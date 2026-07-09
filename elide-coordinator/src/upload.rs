// Segment upload: drain all committed segments from pending/ to the object store.
//
// Object key format: by_id/<volume_ulid>/segments/YYYYMMDD/<ulid>
//
// The date is extracted from the ULID timestamp (creation time, not upload time),
// so keys are stable and deterministic regardless of when drain-pending runs.
//
// Each segment is handled independently. A failure on one segment does not
// prevent the remaining segments from uploading.
//
// Upload commit sequence per segment:
//   1. Read pending/<ulid> into memory
//   2. PUT to object store at the derived key
//   3. IPC → volume: "promote <ulid>"
//      Volume copies pending/<ulid> → cache/<ulid>.body, writes cache/<ulid>.present,
//      and deletes pending/<ulid>.
//   4. On failure at any step: leave pending/<ulid> in place, record error, continue.
//      If volume is not running: leave pending/ in place, retry next tick.
//
// Crash safety:
//   - Crash before step 3: pending/<ulid> still exists; drain re-uploads (idempotent
//     S3 PUT) and re-sends promote on next tick.
//   - Crash after step 3: pending/<ulid> is gone (volume deleted it); done.
//
// Ordering invariant: index/<ulid>.idx present ↔ segment confirmed in S3.
// The volume writes index/<ulid>.idx inside the promote_segment IPC handler,
// which the coordinator calls only after a confirmed S3 PUT. This means every
// .idx file the coordinator sees is safe to fetch from the object store.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use tracing::{info, warn};

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use object_store::path::Path as StorePath;
use object_store::{Attribute, AttributeValue, Attributes, ObjectStore, PutOptions};
use ulid::Ulid;

use crate::portable::MIME_TEXT;

/// Fallback multipart part size when the daemon hasn't initialised
/// [`PART_SIZE_BYTES`] (tests, batch tools that bypass daemon startup).
/// Production reads the configured value via `StoreSection::multipart_part_size_bytes()`
/// and installs it once at daemon boot via [`set_part_size_bytes`].
pub const DEFAULT_PART_SIZE_BYTES: usize = 5 * 1024 * 1024;

/// Process-global multipart part size, set once at daemon startup from
/// `StoreSection::multipart_part_size_bytes()`. Threading this through
/// `daemon → tasks → gc_cycle → drain_pending → SegmentsView` (plus
/// the IPC context chain) is pure ceremony for a value that is constant
/// across the process lifetime and only changes when the operator edits
/// `elide.toml` and restarts.
static PART_SIZE_BYTES: OnceLock<usize> = OnceLock::new();

/// Install the configured part size. Idempotent: a second call after
/// the value is already set is silently ignored. Called by `daemon`
/// during boot.
pub fn set_part_size_bytes(bytes: usize) {
    let _ = PART_SIZE_BYTES.set(bytes);
}

/// Resolve the part size to use for the next multipart upload. Falls
/// back to [`DEFAULT_PART_SIZE_BYTES`] if `set_part_size_bytes` has not
/// been called — the path tests take.
pub(crate) fn part_size_bytes() -> usize {
    PART_SIZE_BYTES
        .get()
        .copied()
        .unwrap_or(DEFAULT_PART_SIZE_BYTES)
}

/// Build `PutOptions` that set `Content-Type` on the uploaded object.
fn put_opts_with_type(content_type: &'static str) -> PutOptions {
    let mut attrs = Attributes::new();
    attrs.insert(Attribute::ContentType, AttributeValue::from(content_type));
    attrs.into()
}

/// PUT a payload with `Content-Type` set. If the backing store returns
/// `NotImplemented` for attribute options (as `LocalFileSystem` does —
/// tests hit this path), retry without attributes. Production S3 always
/// uses the typed path.
pub(crate) async fn put_with_content_type(
    store: &Arc<dyn ObjectStore>,
    key: &StorePath,
    payload: Bytes,
    content_type: &'static str,
) -> std::result::Result<(), object_store::Error> {
    match store
        .put_opts(
            key,
            payload.clone().into(),
            put_opts_with_type(content_type),
        )
        .await
    {
        Ok(_) => Ok(()),
        Err(object_store::Error::NotImplemented) => {
            store.put(key, payload.into()).await.map(|_| ())
        }
        Err(e) => Err(e),
    }
}

/// PUT with `PutMode::Create` and `Content-Type` set. If the backing
/// store returns `NotImplemented` for attribute options (as
/// `LocalFileSystem` does), retry without attributes — the create mode
/// itself is never dropped. `AlreadyExists` surfaces to the caller.
async fn put_create_with_content_type(
    store: &Arc<dyn ObjectStore>,
    key: &StorePath,
    payload: Bytes,
    content_type: &'static str,
) -> std::result::Result<(), object_store::Error> {
    let mut opts = put_opts_with_type(content_type);
    opts.mode = object_store::PutMode::Create;
    match store.put_opts(key, payload.clone().into(), opts).await {
        Ok(_) => Ok(()),
        Err(object_store::Error::NotImplemented) => {
            let opts = PutOptions {
                mode: object_store::PutMode::Create,
                ..Default::default()
            };
            store.put_opts(key, payload.into(), opts).await.map(|_| ())
        }
        Err(e) => Err(e),
    }
}

/// Directory under each volume that holds upload-completion records — one
/// file per S3 object we've confirmed uploaded. For small metadata the file
/// holds a verbatim copy of the uploaded bytes, so `diff uploaded/<f>
/// <source>` works with standard tools and re-upload decisions are taken by
/// exact content comparison rather than mtime. The snapshot pair uses a
/// plain empty sentinel since the S3 marker is empty and the .manifest is
/// inspectable under `snapshots/`.
const UPLOADED_DIR: &str = "uploaded";

fn upload_sentinel(vol_dir: &Path, relative: &str) -> PathBuf {
    vol_dir.join(UPLOADED_DIR).join(relative)
}

/// Return true iff `sentinel` exists and its bytes equal `expected`. A
/// partial-write after a crash fails the equality check and triggers a
/// self-healing re-upload on the next tick.
fn is_already_uploaded(sentinel: &Path, expected: &[u8]) -> bool {
    std::fs::read(sentinel)
        .map(|b| b == expected)
        .unwrap_or(false)
}

fn mark_uploaded(sentinel: &Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = sentinel.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(sentinel, content)?;
    Ok(())
}

/// Like [`mark_uploaded`] but records the sentinel by copying the
/// source file directly — no intermediate userspace buffer. Used when
/// the upload helper just shipped a local file: the sentinel records
/// a byte-equal copy of what S3 now holds, and the next
/// [`is_already_uploaded`] check is a verbatim disk-vs-disk
/// comparison.
fn mark_uploaded_from_file(sentinel: &Path, source: &Path) -> std::io::Result<()> {
    if let Some(parent) = sentinel.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(source, sentinel)?;
    Ok(())
}

/// Write an `uploaded/<relative>` sentinel containing `content`,
/// asserting that S3 already holds these bytes at the matching key.
/// Used by code paths that *downloaded* a skeleton file from S3
/// (notably `pull_readonly_op` and the `claim` hydrate path) so the
/// subsequent drain-loop pass over `upload_volume_metadata` sees a
/// content-equal sentinel and skips a redundant PUT.
///
/// `relative` is the path under `<vol_dir>/uploaded/` — e.g.
/// `"volume.pub"`, `"volume.provenance"`, or
/// `format!("snapshots/{snap_ulid}")` for an empty snapshot
/// sentinel.
pub fn mark_already_uploaded(
    vol_dir: &Path,
    relative: &str,
    content: &[u8],
) -> std::io::Result<()> {
    let sentinel = upload_sentinel(vol_dir, relative);
    mark_uploaded(&sentinel, content)
}

pub struct DrainResult {
    /// Segments observed in `pending/` at the start of the tick.
    pub seen: usize,
    /// Segments whose S3 PUT failed. Likely a persistent store-side issue.
    pub upload_failed: usize,
    /// Segments that uploaded to S3 but whose promote IPC to the volume
    /// process did not succeed. Typically transient (startup/shutdown race);
    /// the pending file stays in place and the next tick retries.
    pub promote_failed: usize,
    /// ULIDs of segments confirmed uploaded *and* promoted this tick.
    /// Fed into the per-volume HEAD's `Added` set by the orchestrator
    /// (`docs/design/segment-index.md`). Excludes upload-failed and
    /// promote-failed segments — those still sit in `pending/` and are
    /// retried next tick, so they are not yet durable from a reader's
    /// perspective. The count of "uploaded this tick" is
    /// `uploaded_ulids.len()`.
    pub uploaded_ulids: Vec<Ulid>,
    /// Highest `User` snapshot manifest newly uploaded this tick, if
    /// any. The caller bumps `names/<name>.latest_snapshot` with it
    /// (`NameClaims::record_latest_snapshot`) — the names write rides
    /// `coord-rw`, which this volume-scoped drain does not hold.
    pub published_user_snapshot: Option<Ulid>,
}

/// Return the volume ULID from a volume directory path.
///
/// In the flat layout every volume lives at `<data_dir>/by_id/<ulid>/`.
/// The directory name is validated as a ULID.
pub fn derive_names(vol_dir: &Path) -> Result<Ulid> {
    let name = vol_dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("vol dir has no name: {}", vol_dir.display()))?;
    ulid::Ulid::from_string(name)
        .map_err(|e| anyhow::anyhow!("vol dir name is not a valid ULID '{name}': {e}"))
}

/// Build the object store key for a segment.
///
/// Format: `by_id/<volume_ulid>/segments/YYYYMMDD/<segment_ulid>`
pub fn segment_key(vol_ulid: Ulid, ulid: Ulid) -> StorePath {
    let dt: DateTime<Utc> = ulid.datetime().into();
    let date = dt.format("%Y%m%d").to_string();
    StorePath::from(format!("by_id/{vol_ulid}/segments/{date}/{ulid}"))
}

/// Upload all committed segments from `pending/` to the object store, then
/// promote each segment to the local cache.
///
/// For writable volumes the promote is done via IPC to the running volume
/// process (`promote <ulid>`), which copies the body to `cache/` and deletes
/// `pending/<ulid>`.  If the volume is not running the segment stays in
/// `pending/` and the coordinator retries on the next tick.
///
/// For readonly volumes no volume process ever runs, so the coordinator
/// performs the promote directly: it writes `index/<ulid>.idx` and
/// `cache/<ulid>.{body,present}` then deletes `pending/<ulid>`.  This is safe
/// because readonly volumes have no concurrent readers or writers — the only
/// `drain_pending` is a one-shot batch command. Metadata (pub key, manifest,
/// name entry) is re-uploaded on every invocation — all are idempotent and tiny.
pub async fn drain_pending(
    vol_dir: &Path,
    vol_ulid: Ulid,
    store: &Arc<dyn ObjectStore>,
    meta_store: &Arc<dyn ObjectStore>,
    head_cache: &crate::HeadCache,
) -> Result<DrainResult> {
    let pending_dir = vol_dir.join("pending");

    // Upload volume metadata before segments so that any host that
    // demand-fetches a segment can immediately verify it and bootstrap the vol.
    let published_user_snapshot =
        upload_volume_metadata(vol_dir, vol_ulid, store, meta_store, head_cache).await;

    // Upload + promote in ULID-ascending order so each promote moves
    // the lowest-ULID pending to committed, preserving
    // `max(committed) < min(pending)` at every boundary. The drain
    // caller has already run repack, so every remaining pending file
    // is upload-ready.

    let mut upload_failed = 0usize;
    let mut promote_failed = 0usize;
    let mut uploaded_ulids: Vec<Ulid> = Vec::new();
    let vd = crate::volume_data::VolumeData::new(Arc::clone(store), vol_ulid);
    let segments = vd.segments();

    let pending_snapshot = elide_core::segment::read_ulid_dir_sorted(&pending_dir)
        .with_context(|| format!("listing pending dir: {}", pending_dir.display()))?;
    let seen = pending_snapshot.len();
    for ulid in pending_snapshot {
        let upload_name = ulid.to_string();
        let segment_path = pending_dir.join(&upload_name);

        let started = Instant::now();
        match segments.put_from_file(ulid, &segment_path).await {
            Ok(()) => {
                info!(
                    "[upload] {} in {:.2?}",
                    segments.segment_key(ulid),
                    started.elapsed()
                );
                // Segment confirmed in S3; promote IPC tells the controlling
                // process (volume or import in serve phase) to write index/ +
                // cache/ and delete pending/<ulid>.
                if crate::control::promote_segment(vol_dir, ulid).await {
                    uploaded_ulids.push(ulid);
                } else {
                    // S3 PUT succeeded but the volume control socket was
                    // unreachable or the IPC reply was an error envelope.
                    // pending/<ulid> stays in place; the next drain
                    // tick re-uploads (idempotent re-PUT) and re-issues
                    // promote.
                    warn!(
                        "promote {upload_name}: uploaded to S3 but volume promote IPC unavailable; \
                         will retry next tick"
                    );
                    promote_failed += 1;
                }
            }
            Err(e) => {
                warn!("upload failed for segment {upload_name}: {e:#}");
                upload_failed += 1;
            }
        }
    }

    Ok(DrainResult {
        seen,
        upload_failed,
        promote_failed,
        uploaded_ulids,
        published_user_snapshot,
    })
}

/// Upload volume metadata: public key, signed provenance, snapshot
/// markers, and signed snapshot manifests.
///
/// All uploads are best-effort — failures are logged but do not abort drain.
/// Each artifact is gated on an `uploaded/<name>` file whose bytes must
/// equal the value we are about to upload; a mismatch (or missing file)
/// triggers upload. For small metadata (volume.pub, provenance) the
/// `uploaded/` entry holds a verbatim copy of the uploaded bytes, so the
/// directory is inspectable with standard tools. The snapshot pair
/// (marker + .manifest) is covered by a single empty sentinel at
/// `uploaded/snapshots/<ulid>`.
///
/// Returns the highest `User` snapshot ULID newly uploaded, if any
/// (see [`upload_snapshot_metadata`]).
async fn upload_volume_metadata(
    vol_dir: &Path,
    vol_ulid: Ulid,
    store: &Arc<dyn ObjectStore>,
    meta_store: &Arc<dyn ObjectStore>,
    head_cache: &crate::HeadCache,
) -> Option<Ulid> {
    let pub_key_path = vol_dir.join("volume.pub");
    match std::fs::read(&pub_key_path) {
        Ok(bytes) => {
            let sentinel = upload_sentinel(vol_dir, "volume.pub");
            if !is_already_uploaded(&sentinel, &bytes) {
                match upload_small_bytes(
                    &bytes,
                    &StorePath::from(elide_core::store_keys::meta_pub_key(vol_ulid)),
                    "volume.pub",
                    MIME_TEXT,
                    meta_store,
                )
                .await
                {
                    Ok(()) => {
                        if let Err(e) = mark_uploaded(&sentinel, &bytes) {
                            warn!("failed to mark volume.pub sentinel: {e}");
                        }
                    }
                    Err(e) => warn!("pub key upload failed: {e:#}"),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("failed to read volume.pub: {e:#}"),
    }

    let provenance_path = vol_dir.join(elide_core::signing::VOLUME_PROVENANCE_FILE);
    match std::fs::read(&provenance_path) {
        Ok(bytes) => {
            let sentinel = upload_sentinel(vol_dir, elide_core::signing::VOLUME_PROVENANCE_FILE);
            if !is_already_uploaded(&sentinel, &bytes) {
                match upload_small_bytes(
                    &bytes,
                    &StorePath::from(elide_core::store_keys::meta_provenance_key(vol_ulid)),
                    elide_core::signing::VOLUME_PROVENANCE_FILE,
                    MIME_TEXT,
                    meta_store,
                )
                .await
                {
                    Ok(()) => {
                        if let Err(e) = mark_uploaded(&sentinel, &bytes) {
                            warn!("failed to mark provenance sentinel: {e}");
                        }
                    }
                    Err(e) => warn!("provenance upload failed: {e:#}"),
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => warn!("failed to read provenance: {e:#}"),
    }

    match upload_snapshot_metadata(vol_dir, vol_ulid, store, head_cache).await {
        Ok(published) => published,
        Err(e) => {
            warn!("snapshot upload failed: {e:#}");
            None
        }
    }
}

/// Upload `by_id/<vol_ulid>/volume.pub` to `meta/<vol_ulid>.pub` on the
/// coordinator-plane meta store and write the local upload sentinel.
///
/// Identity establishment rides `coord-rw`, never `volume-rw`: a
/// volume cannot attest its own first write, because the `volume-rw`
/// possession check reads this very object
/// (`docs/design/mint-volume-attestation.md` § *New-volume bootstrap*).
///
/// Used at create / fork time to establish the invariant
/// "`names/<name>` only ever points at a `vol_ulid` whose `volume.pub` is
/// already in the bucket". If the coordinator dies after this call but
/// before the caller publishes `names/<name>`, the only artefact left in
/// S3 is an orphan `volume.pub` keyed by an unreferenced ULID — harmless,
/// and reclaimable by future GC.
///
/// The sentinel write means the daemon's later `upload_volume_metadata`
/// pass observes a content-equal sentinel and skips the redundant PUT.
pub async fn upload_volume_pub_initial(
    data_dir: &Path,
    vol_ulid: Ulid,
    meta_store: &Arc<dyn ObjectStore>,
) -> Result<()> {
    let vol_dir = crate::volume_state::fork_dir(data_dir, vol_ulid);
    let pub_key_path = vol_dir.join("volume.pub");
    let bytes = std::fs::read(&pub_key_path)
        .with_context(|| format!("reading {}", pub_key_path.display()))?;
    let key = StorePath::from(elide_core::store_keys::meta_pub_key(vol_ulid));
    // Write-once: the pub is the volume's trust anchor and never
    // changes. `AlreadyExists` is success — the content is
    // deterministic for a given keypair, so a crash-resume re-upload
    // finds the identical object.
    match put_create_with_content_type(meta_store, &key, Bytes::from(bytes), MIME_TEXT).await {
        Ok(()) | Err(object_store::Error::AlreadyExists { .. }) => {}
        Err(e) => {
            return Err(e).with_context(|| format!("uploading volume.pub to {key}"));
        }
    }
    let sentinel = upload_sentinel(&vol_dir, "volume.pub");
    mark_uploaded_from_file(&sentinel, &pub_key_path)
        .with_context(|| format!("writing upload sentinel {}", sentinel.display()))?;
    Ok(())
}

/// Upload `by_id/<vol_ulid>/volume.provenance` to
/// `meta/<vol_ulid>.provenance` on the coordinator-plane meta store and
/// write the local upload sentinel.
///
/// Sibling to [`upload_volume_pub_initial`]: extends the same
/// "`names/<name>` only ever points at a `vol_ulid` whose immutable
/// trust artefacts are already in the bucket" invariant from
/// `volume.pub` to `volume.provenance`. Provenance is needed by
/// `pull_readonly` for ancestor materialisation, which fetches
/// `meta/<vol_ulid>.provenance` from S3 to reconstruct ancestry.
/// Without this eager publish, the window between `mark_claimed` and
/// the daemon's later metadata-drain pass is one in which every such
/// request 404s.
///
/// Unlike the pub this is a plain put, not a conditional create: claim
/// and `claim --force` rewrite the provisional lineage once, when the
/// effective basis resolves.
///
/// Crash-safety story matches the `volume.pub` case: if the
/// coordinator dies after this call but before `mark_initial` /
/// `mark_claimed`, the orphan `meta/<vol_ulid>.provenance`
/// has no `names/<name>` referrer and is reclaimed by future GC.
pub async fn upload_volume_provenance_initial(
    data_dir: &Path,
    vol_ulid: Ulid,
    meta_store: &Arc<dyn ObjectStore>,
) -> Result<()> {
    let vol_dir = crate::volume_state::fork_dir(data_dir, vol_ulid);
    let provenance_path = vol_dir.join(elide_core::signing::VOLUME_PROVENANCE_FILE);
    let bytes = std::fs::read(&provenance_path)
        .with_context(|| format!("reading {}", provenance_path.display()))?;
    upload_small_bytes(
        &bytes,
        &StorePath::from(elide_core::store_keys::meta_provenance_key(vol_ulid)),
        elide_core::signing::VOLUME_PROVENANCE_FILE,
        MIME_TEXT,
        meta_store,
    )
    .await?;
    let sentinel = upload_sentinel(&vol_dir, elide_core::signing::VOLUME_PROVENANCE_FILE);
    mark_uploaded_from_file(&sentinel, &provenance_path)
        .with_context(|| format!("writing upload sentinel {}", sentinel.display()))?;
    Ok(())
}

async fn upload_small_bytes(
    data: &[u8],
    key: &StorePath,
    label: &str,
    content_type: &'static str,
    store: &Arc<dyn ObjectStore>,
) -> Result<()> {
    let len = data.len();
    let started = Instant::now();
    put_with_content_type(store, key, Bytes::copy_from_slice(data), content_type)
        .await
        .with_context(|| format!("uploading {label} to {key}"))?;
    info!("[upload] {key} ({len} bytes in {:.2?})", started.elapsed());
    Ok(())
}

/// Write a segment's post-upload local form — `index/<u>.idx` plus
/// `cache/<u>.{body,present}` (and `.delta` when the segment carries a
/// delta section) — from a full segment file at `segment_file`.
///
/// This is the daemon's promote step done coordinator-side, for
/// callers with no running daemon to IPC. Run only after the segment
/// is durable in S3, preserving the idx-presence ↔ segment-in-S3
/// invariant.
pub fn promote_segment_local_form(
    fork_dir: &Path,
    seg_ulid: Ulid,
    segment_file: &Path,
) -> std::io::Result<()> {
    let index_dir = fork_dir.join("index");
    let cache_dir = fork_dir.join("cache");
    std::fs::create_dir_all(&index_dir)?;
    std::fs::create_dir_all(&cache_dir)?;
    elide_core::segment::extract_idx(segment_file, &index_dir.join(format!("{seg_ulid}.idx")))?;
    elide_core::segment::promote_to_cache(
        segment_file,
        &cache_dir.join(format!("{seg_ulid}.body")),
        &cache_dir.join(format!("{seg_ulid}.present")),
    )
}

/// Upload signed snapshot manifests from `vol_dir/snapshots/` to S3.
///
/// Snapshots are recorded as `<ulid>.manifest`; the manifest's
/// existence is the snapshot's existence. Each manifest's upload is
/// gated on a sentinel at `uploaded/snapshots/<ulid>` so re-runs don't
/// re-PUT.
///
/// Returns the highest `User` snapshot ULID newly uploaded by this
/// call, for the caller's `names/<name>.latest_snapshot` bump.
pub async fn upload_snapshot_metadata(
    vol_dir: &Path,
    vol_ulid: Ulid,
    store: &Arc<dyn ObjectStore>,
    head_cache: &crate::HeadCache,
) -> Result<Option<Ulid>> {
    let snap_dir = vol_dir.join("snapshots");
    let entries = match std::fs::read_dir(&snap_dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };

    let mut published_user_snapshot: Option<Ulid> = None;
    let mut sealed: Option<Ulid> = None;
    for entry in entries {
        let entry = entry.context("reading snapshots dir entry")?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some((snap_ulid, kind)) = elide_core::signing::parse_snapshot_filename(name) else {
            continue;
        };

        let sentinel_label = match kind {
            elide_core::signing::SnapshotKind::User => format!("snapshots/{snap_ulid}"),
            elide_core::signing::SnapshotKind::Stop => format!("snapshots/{snap_ulid}-stop"),
        };
        let sentinel = upload_sentinel(vol_dir, &sentinel_label);
        if is_already_uploaded(&sentinel, &[]) {
            continue;
        }

        let manifest_path = snap_dir.join(name);
        let started = Instant::now();

        let vd = crate::volume_data::VolumeData::new(Arc::clone(store), vol_ulid);
        let snapshots = vd.snapshots();

        let key = match kind {
            elide_core::signing::SnapshotKind::User => snapshots.manifest_key(snap_ulid),
            elide_core::signing::SnapshotKind::Stop => snapshots.stop_manifest_key(snap_ulid),
        };
        let put_result = match kind {
            elide_core::signing::SnapshotKind::User => {
                snapshots
                    .put_manifest_from_file(snap_ulid, &manifest_path)
                    .await
            }
            elide_core::signing::SnapshotKind::Stop => {
                snapshots
                    .put_stop_manifest_from_file(snap_ulid, &manifest_path)
                    .await
            }
        };
        match put_result {
            Ok(()) => {
                info!("[upload] {key} in {:.2?}", started.elapsed());
                if let Err(e) = mark_uploaded(&sentinel, &[]) {
                    warn!("failed to mark snapshot {snap_ulid} sentinel: {e}");
                }
                // `snapshots/LATEST` tracks stable user manifests only;
                // stop-snapshots are ephemeral and reachable via the
                // HEAD anchor written below. Failures here must not
                // fail the upload (self-heal on the next publish).
                if kind == elide_core::signing::SnapshotKind::User {
                    published_user_snapshot = published_user_snapshot.max(Some(snap_ulid));
                    if let Err(e) = snapshots.bump_latest_if_newer(snap_ulid).await {
                        warn!("[upload] bumping snapshots/LATEST for {snap_ulid}: {e}");
                    }
                }
                sealed = sealed.max(Some(snap_ulid));
            }
            Err(e) => warn!("snapshot manifest upload failed for {key}: {e:#}"),
        }
    }

    // Truncate the post-snapshot HEAD: the newest manifest uploaded
    // here (either kind) absorbs every live segment, so the delta over
    // it starts empty and the anchor names the seal. For a
    // stop-snapshot the anchor is the only bucket-side pointer to it.
    // Single writer (the seal is the same tick loop / inbound handler
    // that authors HEAD), so a plain unconditional PUT — same pattern
    // as `snapshots/LATEST`. See `docs/design/segment-index.md`
    // *Truncation*.
    //
    // The shared writer cache is updated under its lock around the
    // PUT: the tick loop's next merge must start from the truncated
    // form, never a pre-seal body. On a failed PUT the cache is
    // emptied instead — the next merge re-reads S3.
    if let Some(snap_ulid) = sealed {
        let vd = crate::volume_data::VolumeData::new(Arc::clone(store), vol_ulid);
        let empty = crate::segment_head::SegmentHead::empty(Some(snap_ulid));
        let mut cache = head_cache.lock().await;
        match vd.head().put(&empty).await {
            Ok(()) => *cache = Some(empty),
            Err(e) => {
                *cache = None;
                warn!(
                    "[upload] truncating HEAD for {snap_ulid}: {e}; \
                     self-heals on next active tick"
                );
            }
        }
    }

    Ok(published_user_snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::local::LocalFileSystem;
    use tempfile::TempDir;

    struct MockSocket(tokio::task::JoinHandle<()>);
    impl Drop for MockSocket {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// Spawn a mock volume control socket at `<fork_dir>/control.sock`.
    ///
    /// Replies `Envelope::Ok` to any request. For [`VolumeRequest::Promote`]
    /// also performs the volume's promote behaviour: copies the segment body
    /// from pending/ into cache/ and deletes the pending/ file (drain path).
    async fn spawn_mock_socket(fork_dir: std::path::PathBuf) -> MockSocket {
        use elide_core::ipc::Envelope;
        use elide_core::volume_ipc::VolumeRequest;

        let socket_path = fork_dir.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&socket_path).unwrap();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let dir = fork_dir.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
                    let (r, mut w) = tokio::io::split(stream);
                    let mut buf = BufReader::new(r);
                    let mut line = String::new();
                    let _ = buf.read_line(&mut line).await;
                    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                    if let Ok(VolumeRequest::Promote { segment_ulid }) =
                        serde_json::from_str::<VolumeRequest>(trimmed)
                    {
                        let ulid_str = segment_ulid.to_string();
                        let src = dir.join("pending").join(&ulid_str);
                        if src.exists() {
                            let cache = dir.join("cache");
                            std::fs::create_dir_all(&cache).ok();
                            let body = cache.join(format!("{ulid_str}.body"));
                            let present = cache.join(format!("{ulid_str}.present"));
                            elide_core::segment::promote_to_cache(&src, &body, &present).ok();
                            std::fs::remove_file(&src).ok();
                        }
                    }
                    let reply = Envelope::<()>::ok(());
                    let mut bytes = serde_json::to_vec(&reply).unwrap();
                    bytes.push(b'\n');
                    w.write_all(&bytes).await.ok();
                });
            }
        });
        MockSocket(handle)
    }

    fn make_ulid(ts_ms: u64, random: u128) -> String {
        Ulid::from_parts(ts_ms, random).to_string()
    }

    const VOL_ULID: &str = "01JQAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn derive_names_returns_ulid() {
        let id = derive_names(Path::new(&format!("/data/by_id/{VOL_ULID}"))).unwrap();
        assert_eq!(id.to_string(), VOL_ULID);
    }

    #[test]
    fn derive_names_rejects_non_ulid() {
        assert!(derive_names(Path::new("/data/by_id/not-a-ulid")).is_err());
    }

    #[test]
    fn segment_key_format() {
        let ulid = Ulid::from_parts(1743120000000, 42);
        let ulid_str = ulid.to_string();

        let dt: DateTime<Utc> = ulid.datetime().into();
        let expected_date = dt.format("%Y%m%d").to_string();

        let key = segment_key(VOL_ULID.parse().unwrap(), ulid);
        assert_eq!(
            key.as_ref(),
            format!("by_id/{VOL_ULID}/segments/{expected_date}/{ulid_str}")
        );
    }

    #[tokio::test]
    async fn drain_pending_uploads_and_commits() {
        use elide_core::segment::{SegmentEntry, SegmentFlags, write_segment};
        use elide_core::signing::generate_ephemeral_signer;

        let tmp = TempDir::new().unwrap();
        let vol_dir = tmp.path().join(VOL_ULID);
        let pending_dir = vol_dir.join("pending");
        let cache_dir = vol_dir.join("cache");
        std::fs::create_dir_all(&pending_dir).unwrap();
        elide_core::config::VolumeConfig {
            name: Some("test-vol".into()),
            size: Some(4096),
            ..Default::default()
        }
        .write(&vol_dir)
        .unwrap();

        let (signer, _) = generate_ephemeral_signer();

        let ulid1 = make_ulid(1743120000000, 1);
        let ulid2 = make_ulid(1743120000000, 2);

        let data1 = vec![0xABu8; 4096];
        let h1 = blake3::hash(&data1);
        let mut entries1 = vec![SegmentEntry::new_data(
            h1,
            0,
            1,
            SegmentFlags::empty(),
            data1,
        )];
        write_segment(&pending_dir.join(&ulid1), &mut entries1, signer.as_ref()).unwrap();

        let data2 = vec![0xCDu8; 4096];
        let h2 = blake3::hash(&data2);
        let mut entries2 = vec![SegmentEntry::new_data(
            h2,
            1,
            1,
            SegmentFlags::empty(),
            data2,
        )];
        write_segment(&pending_dir.join(&ulid2), &mut entries2, signer.as_ref()).unwrap();

        // .tmp files must be left in place.
        std::fs::write(pending_dir.join(format!("{ulid1}.tmp")), b"incomplete").unwrap();

        // Mock volume socket: responds "ok" to promote and copies pending → cache.
        let _mock = spawn_mock_socket(vol_dir.clone()).await;

        let store_tmp = TempDir::new().unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(store_tmp.path()).unwrap());

        let result = drain_pending(
            &vol_dir,
            VOL_ULID.parse().unwrap(),
            &store,
            &store,
            &Default::default(),
        )
        .await
        .unwrap();

        assert_eq!(result.uploaded_ulids.len(), 2);
        assert_eq!(result.upload_failed, 0);
        assert_eq!(result.promote_failed, 0);

        // pending/ entries are removed by the volume after promote IPC (mocked here).
        assert!(!pending_dir.join(&ulid1).exists());
        assert!(!pending_dir.join(&ulid2).exists());
        assert!(pending_dir.join(format!("{ulid1}.tmp")).exists());

        // cache/ body + present files are written by the mock volume promote handler.
        assert!(cache_dir.join(format!("{ulid1}.body")).exists());
        assert!(cache_dir.join(format!("{ulid1}.present")).exists());
        assert!(cache_dir.join(format!("{ulid2}.body")).exists());
        assert!(cache_dir.join(format!("{ulid2}.present")).exists());

        let key1 = segment_key(VOL_ULID.parse().unwrap(), ulid1.parse().unwrap());
        let key2 = segment_key(VOL_ULID.parse().unwrap(), ulid2.parse().unwrap());
        store
            .head(&key1)
            .await
            .expect("object 1 should be in store");
        store
            .head(&key2)
            .await
            .expect("object 2 should be in store");
    }

    #[tokio::test]
    async fn drain_pending_uploads_pub_key() {
        let tmp = TempDir::new().unwrap();
        let vol_dir = tmp.path().join(VOL_ULID);
        let pending_dir = vol_dir.join("pending");
        std::fs::create_dir_all(&pending_dir).unwrap();
        elide_core::config::VolumeConfig {
            name: Some("test-vol".into()),
            size: Some(4096),
            ..Default::default()
        }
        .write(&vol_dir)
        .unwrap();

        let fake_pub = b"fakepublickey12345678901234567890";
        std::fs::write(vol_dir.join("volume.pub"), fake_pub).unwrap();

        let store_tmp = TempDir::new().unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(store_tmp.path()).unwrap());

        let result = drain_pending(
            &vol_dir,
            VOL_ULID.parse().unwrap(),
            &store,
            &store,
            &Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(result.uploaded_ulids.len(), 0);
        assert_eq!(result.upload_failed, 0);
        assert_eq!(result.promote_failed, 0);

        let pub_key = StorePath::from(elide_core::store_keys::meta_pub_key(
            ulid::Ulid::from_string(VOL_ULID).expect("VOL_ULID is a valid ULID"),
        ));
        let got = store.get(&pub_key).await.expect("volume.pub not in store");
        let bytes = got.bytes().await.unwrap();
        assert_eq!(bytes.as_ref(), fake_pub);

        // uploaded/volume.pub holds a verbatim copy of the uploaded bytes.
        let sentinel = vol_dir.join("uploaded").join("volume.pub");
        assert_eq!(std::fs::read(&sentinel).unwrap(), fake_pub);
    }

    /// `names/<name>` is owned by the lifecycle verbs (`mark_initial` /
    /// `mark_stopped` / `mark_released` / etc.). The drain path uploads
    /// `volume.pub`, `volume.provenance`, snapshot markers, and segments —
    /// it must not write the name record or it would clobber the populated
    /// claim (overwriting `coordinator_id`, `claimed_at`, `hostname`).
    #[tokio::test]
    async fn drain_pending_does_not_touch_name_record() {
        let tmp = TempDir::new().unwrap();
        let vol_dir = tmp.path().join(VOL_ULID);
        let pending_dir = vol_dir.join("pending");
        std::fs::create_dir_all(&pending_dir).unwrap();
        elide_core::config::VolumeConfig {
            name: Some("my-vol".into()),
            size: Some(8192),
            ..Default::default()
        }
        .write(&vol_dir)
        .unwrap();
        std::fs::write(vol_dir.join("volume.readonly"), "").unwrap();

        let store_tmp = TempDir::new().unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(store_tmp.path()).unwrap());

        drain_pending(
            &vol_dir,
            VOL_ULID.parse().unwrap(),
            &store,
            &store,
            &Default::default(),
        )
        .await
        .unwrap();

        let name_key = StorePath::from("names/my-vol");
        assert!(
            store.head(&name_key).await.is_err(),
            "drain_pending must not write names/<name>; that is owned by mark_initial / lifecycle verbs"
        );
        // No `uploaded/names_<name>` sentinel either — drain doesn't write
        // the record, so it has no sentinel to compare against.
        assert!(!vol_dir.join("uploaded").join("names_my-vol").exists());
    }

    /// Volume-metadata upload is skipped on re-drain when the file bytes
    /// match the existing `uploaded/<f>` entry. Regression guard for the
    /// mtime→content-equal gating switch: re-running drain without changing
    /// any source file must not re-upload.
    #[tokio::test]
    async fn drain_skips_reupload_when_metadata_unchanged() {
        let tmp = TempDir::new().unwrap();
        let vol_dir = tmp.path().join(VOL_ULID);
        std::fs::create_dir_all(vol_dir.join("pending")).unwrap();
        elide_core::config::VolumeConfig {
            name: Some("stable".into()),
            size: Some(4096),
            ..Default::default()
        }
        .write(&vol_dir)
        .unwrap();
        std::fs::write(vol_dir.join("volume.pub"), b"k").unwrap();

        let store_tmp = TempDir::new().unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(store_tmp.path()).unwrap());

        drain_pending(
            &vol_dir,
            VOL_ULID.parse().unwrap(),
            &store,
            &store,
            &Default::default(),
        )
        .await
        .unwrap();

        // Delete the store object behind the coordinator's back. If gating
        // works, re-drain sees a matching `uploaded/volume.pub` and skips —
        // the object remains absent. If gating is broken (e.g. reverted to
        // mtime), the object reappears.
        let pub_key = StorePath::from(elide_core::store_keys::meta_pub_key(
            ulid::Ulid::from_string(VOL_ULID).expect("VOL_ULID is a valid ULID"),
        ));
        store.delete(&pub_key).await.unwrap();

        drain_pending(
            &vol_dir,
            VOL_ULID.parse().unwrap(),
            &store,
            &store,
            &Default::default(),
        )
        .await
        .unwrap();

        assert!(store.head(&pub_key).await.is_err());

        // Now change volume.pub content — re-drain must upload.
        std::fs::write(vol_dir.join("volume.pub"), b"rotated").unwrap();
        drain_pending(
            &vol_dir,
            VOL_ULID.parse().unwrap(),
            &store,
            &store,
            &Default::default(),
        )
        .await
        .unwrap();
        let got = store.get(&pub_key).await.expect("volume.pub re-uploaded");
        assert_eq!(got.bytes().await.unwrap().as_ref(), b"rotated");
    }

    #[tokio::test]
    async fn drain_uploads_signed_manifest_and_skips_local_filemap() {
        use elide_core::signing::generate_ephemeral_signer;

        let tmp = TempDir::new().unwrap();
        let vol_dir = tmp.path().join(VOL_ULID);
        let pending_dir = vol_dir.join("pending");
        let snap_dir = vol_dir.join("snapshots");
        std::fs::create_dir_all(&pending_dir).unwrap();
        std::fs::create_dir_all(&snap_dir).unwrap();
        elide_core::config::VolumeConfig {
            name: Some("test-vol".into()),
            size: Some(4096),
            ..Default::default()
        }
        .write(&vol_dir)
        .unwrap();

        // Sign a real manifest plus a local filemap. The manifest
        // uploads; the filemap stays local-only.
        let snap_ulid = Ulid::from_parts(1743120000000, 77);
        let snap_str = snap_ulid.to_string();
        let (signer, _vk) = generate_ephemeral_signer();
        elide_core::signing::write_snapshot_manifest(&vol_dir, signer.as_ref(), &snap_ulid, &[])
            .unwrap();
        std::fs::write(
            snap_dir.join(format!("{snap_str}.filemap")),
            "# elide-filemap v1\n/etc/hosts\tabcd1234\t128\n",
        )
        .unwrap();

        let store_tmp = TempDir::new().unwrap();
        let store: Arc<dyn ObjectStore> =
            Arc::new(LocalFileSystem::new_with_prefix(store_tmp.path()).unwrap());

        drain_pending(
            &vol_dir,
            VOL_ULID.parse().unwrap(),
            &store,
            &store,
            &Default::default(),
        )
        .await
        .unwrap();

        // Manifest is in store.
        let vol = ulid::Ulid::from_string(VOL_ULID).unwrap();
        let meta = crate::volume_data::VolumeData::new(Arc::clone(&store), vol)
            .snapshots()
            .head_manifest(snap_ulid)
            .await
            .expect("head_manifest succeeds")
            .expect("snapshot manifest not in store");
        assert!(meta.size > 0);

        // No bare-ULID marker in store.
        let dt: DateTime<Utc> = snap_ulid.datetime().into();
        let date = dt.format("%Y%m%d").to_string();
        let bare_key = StorePath::from(format!("by_id/{VOL_ULID}/snapshots/{date}/{snap_str}"));
        assert!(
            store.head(&bare_key).await.is_err(),
            "bare-ULID snapshot marker must not be uploaded to S3",
        );

        // Filemap is NOT in store — it stays local.
        let fm_key = StorePath::from(format!(
            "by_id/{VOL_ULID}/snapshots/{date}/{snap_str}.filemap"
        ));
        assert!(
            store.head(&fm_key).await.is_err(),
            "filemap must not be uploaded to S3",
        );
    }

    #[tokio::test]
    async fn stop_seal_truncates_head_without_bumping_latest() {
        let tmp = TempDir::new().unwrap();
        let vol_dir = tmp.path().join(VOL_ULID);
        std::fs::create_dir_all(vol_dir.join("snapshots")).unwrap();
        let vol: Ulid = VOL_ULID.parse().unwrap();
        let snap = Ulid::from_parts(1743120000000, 78);
        std::fs::write(
            vol_dir
                .join("snapshots")
                .join(elide_core::signing::stop_snapshot_manifest_filename(&snap)),
            b"signed-manifest-bytes",
        )
        .unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let vd = crate::volume_data::VolumeData::new(Arc::clone(&store), vol);
        let mut stale = crate::segment_head::SegmentHead::empty(None);
        stale.added.insert(Ulid::from_parts(1743110000000, 9));
        vd.head().put(&stale).await.unwrap();
        let head_cache: crate::HeadCache = Arc::new(tokio::sync::Mutex::new(Some(stale)));

        let published = upload_snapshot_metadata(&vol_dir, vol, &store, &head_cache)
            .await
            .unwrap();

        assert_eq!(published, None, "stop seals never publish a user snapshot");
        let head = vd.head().read().await.unwrap();
        assert_eq!(
            head,
            crate::segment_head::SegmentHead::empty(Some(snap)),
            "stop seal truncates HEAD anchored at the stop-snapshot"
        );
        assert_eq!(
            *head_cache.lock().await,
            Some(crate::segment_head::SegmentHead::empty(Some(snap))),
            "truncation replaces the shared writer cache with the truncated form"
        );
        assert!(
            vd.snapshots().read_latest().await.unwrap().is_none(),
            "snapshots/LATEST tracks user manifests only"
        );
    }

    #[tokio::test]
    async fn seal_truncation_anchors_at_the_newest_manifest() {
        use elide_core::ulid_mint::UlidMint;
        let tmp = TempDir::new().unwrap();
        let vol_dir = tmp.path().join(VOL_ULID);
        std::fs::create_dir_all(vol_dir.join("snapshots")).unwrap();
        let vol: Ulid = VOL_ULID.parse().unwrap();
        let mut mint = UlidMint::new(Ulid::nil());
        let user_snap = mint.next();
        let stop_snap = mint.next();
        std::fs::write(
            vol_dir
                .join("snapshots")
                .join(elide_core::signing::snapshot_manifest_filename(&user_snap)),
            b"user-manifest-bytes",
        )
        .unwrap();
        std::fs::write(
            vol_dir
                .join("snapshots")
                .join(elide_core::signing::stop_snapshot_manifest_filename(
                    &stop_snap,
                )),
            b"stop-manifest-bytes",
        )
        .unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());

        let published = upload_snapshot_metadata(&vol_dir, vol, &store, &Default::default())
            .await
            .unwrap();

        assert_eq!(published, Some(user_snap));
        let vd = crate::volume_data::VolumeData::new(Arc::clone(&store), vol);
        let head = vd.head().read().await.unwrap();
        assert_eq!(
            head.anchor,
            Some(stop_snap),
            "HEAD anchors at the newest seal regardless of dir order"
        );
        assert!(head.is_empty());
        assert_eq!(
            vd.snapshots().read_latest().await.unwrap().map(|(u, _)| u),
            Some(user_snap),
            "LATEST still points at the user manifest"
        );
    }
}
