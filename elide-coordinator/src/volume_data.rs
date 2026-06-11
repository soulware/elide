//! Domain-typed handle over a single volume's `by_id/<vol>/…` objects.
//!
//! Third slice of the domain-typed store layer
//! (`docs/design-domain-store.md`). [`VolumeData`] is the per-volume
//! handle; it carves the volume's `volume-rw` prefix into
//! object-class sub-accessors that callers name explicitly. The
//! currently-populated sub-accessors are:
//!
//! * [`HeadView`] — the per-volume HEAD object
//!   (`by_id/<vol>/HEAD`, the post-snapshot delta from
//!   `docs/design-segment-index.md`). Single-writer, no CAS.
//! * [`MetadataView`] — the immutable trust artefacts
//!   `meta/<vol>.pub` and `meta/<vol>.provenance`.
//! * [`SnapshotsView`] — signed snapshot manifests under
//!   `by_id/<vol>/snapshots/…` and the `snapshots/LATEST` pointer.
//!   Includes a typed CAS (`advance_latest` / `LatestPointerToken`)
//!   for the LATEST pointer, and a typed
//!   `get_manifest(snap, vk) -> SnapshotManifest` that parses and
//!   verifies in one step (with `get_manifest_bytes` for callers
//!   that verify the raw bytes themselves).
//! * [`SegmentsView`] — segment bodies under
//!   `by_id/<vol>/segments/<YYYYMMDD>/<ulid>`. Multipart PUT for
//!   bodies (via `put_from_file`), range-GET for header+index
//!   verification (`get_range`), and DELETE for the retention reaper.
//!
//! `VolumeData` is a concrete struct, not a trait. There is one
//! impl, no reader/writer split (every op rides one `volume-rw`
//! credential), and no test-only impl (tests substitute an
//! `InMemory` `ObjectStore` underneath). If a second impl becomes
//! useful later, splitting back into a trait is mechanical.

use std::ops::Range;
use std::sync::Arc;

use bytes::Bytes;
use object_store::path::Path as StorePath;
use object_store::{ObjectMeta, ObjectStore, UpdateVersion, WriteMultipart};
use ulid::Ulid;

use elide_core::signing::{self, SnapshotManifest, VerifyingKey};

use crate::portable::{
    ConditionalPutError, MIME_TEXT, put_if_absent_with_type, put_with_match_with_type,
};
use crate::segment_head::{self, ParseHeadError, SegmentHead};

/// Per-volume domain handle, scoped to `by_id/<vol>/…` on the
/// `volume-rw` credential. Acquired via
/// [`crate::stores::ScopedStores::volume_data`]. Cheap to clone (the
/// inner store is `Arc<dyn ObjectStore>`).
#[derive(Clone)]
pub struct VolumeData {
    store: Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
}

impl VolumeData {
    pub fn new(store: Arc<dyn ObjectStore>, vol_ulid: Ulid) -> Self {
        Self { store, vol_ulid }
    }

    pub fn vol_ulid(&self) -> Ulid {
        self.vol_ulid
    }

    /// HEAD operations (`by_id/<vol>/HEAD`).
    pub fn head(&self) -> HeadView<'_> {
        HeadView {
            store: &self.store,
            vol_ulid: self.vol_ulid,
        }
    }

    /// Immutable metadata (`volume.pub`, `volume.provenance`).
    pub fn metadata(&self) -> MetadataView<'_> {
        MetadataView {
            store: &self.store,
            vol_ulid: self.vol_ulid,
        }
    }

    /// Signed snapshot manifests and the `snapshots/LATEST` pointer.
    pub fn snapshots(&self) -> SnapshotsView<'_> {
        SnapshotsView {
            store: &self.store,
            vol_ulid: self.vol_ulid,
        }
    }

    /// Segment bodies under `by_id/<vol>/segments/<date>/<ulid>`.
    pub fn segments(&self) -> SegmentsView<'_> {
        SegmentsView {
            store: &self.store,
            vol_ulid: self.vol_ulid,
        }
    }
}

/// Non-async, zero-cost view bundling the HEAD operations.
pub struct HeadView<'a> {
    store: &'a Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
}

impl HeadView<'_> {
    /// GET `by_id/<vol>/HEAD`. Returns [`SegmentHead::empty`] when
    /// absent or unparseable — HEAD is derived state that self-heals
    /// on the next active tick.
    pub async fn read(&self) -> Result<SegmentHead, HeadError> {
        let key = segment_head::head_key(self.vol_ulid);
        let bytes = match self.store.get(&key).await {
            Ok(g) => g.bytes().await.map_err(HeadError::Get)?,
            Err(object_store::Error::NotFound { .. }) => return Ok(SegmentHead::empty(None)),
            Err(e) => return Err(HeadError::Get(e)),
        };
        let text = std::str::from_utf8(&bytes).map_err(HeadError::NotUtf8)?;
        match segment_head::parse(text) {
            Ok(h) => Ok(h),
            Err(e) => {
                tracing::warn!(
                    "[volume_data] {key} unparseable ({e}); treating as empty (self-heals on next tick)"
                );
                Ok(SegmentHead::empty(None))
            }
        }
    }

    /// PUT `by_id/<vol>/HEAD` with the rendered body. Whole-object
    /// overwrite, no CAS — the per-volume tick loop is the sole
    /// writer (`docs/design-segment-index.md`).
    pub async fn put(&self, head: &SegmentHead) -> Result<(), HeadError> {
        let key = segment_head::head_key(self.vol_ulid);
        let body = segment_head::render(head);
        crate::upload::put_with_content_type(
            self.store,
            &key,
            Bytes::from(body.into_bytes()),
            MIME_TEXT,
        )
        .await
        .map_err(HeadError::Put)
    }

    /// DELETE `by_id/<vol>/HEAD`. Volume teardown only.
    pub async fn delete(&self) -> Result<(), HeadError> {
        let key = segment_head::head_key(self.vol_ulid);
        self.store.delete(&key).await.map_err(HeadError::Delete)
    }
}

/// Non-async, zero-cost view bundling the immutable metadata
/// operations (`volume.pub`, `volume.provenance`).
pub struct MetadataView<'a> {
    store: &'a Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
}

impl MetadataView<'_> {
    /// GET `meta/<vol>.pub` and parse the hex-encoded body
    /// into an Ed25519 [`VerifyingKey`].
    pub async fn read_pubkey(&self) -> Result<VerifyingKey, MetadataError> {
        let key = pubkey_key(self.vol_ulid);
        let result = self.store.get(&key).await.map_err(MetadataError::Get)?;
        let bytes = result.bytes().await.map_err(MetadataError::Get)?;
        let hex = std::str::from_utf8(&bytes).map_err(MetadataError::PubkeyNotUtf8)?;
        parse_hex_pubkey(hex)
    }
}

/// Sibling to [`upload_file_to_store`] for the snapshots surface —
/// same shape, distinct error type so the snapshot view's
/// `Result` stays typed.
async fn upload_file_to_snapshots(
    store: &Arc<dyn ObjectStore>,
    key: &StorePath,
    path: &std::path::Path,
) -> Result<(), SnapshotsError> {
    let bytes = std::fs::read(path).map_err(|e| SnapshotsError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    crate::upload::put_with_content_type(store, key, Bytes::from(bytes), MIME_TEXT)
        .await
        .map_err(SnapshotsError::Put)
}

/// Atomic write: create parent dirs, write through `<dest>.tmp`,
/// rename into place. Used by the `_to_file` snapshot view methods
/// so a crash mid-download never leaves a partial manifest at the
/// final path.
fn write_file_atomic(dest: &std::path::Path, bytes: &[u8]) -> Result<(), SnapshotsError> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SnapshotsError::WriteFile {
            path: parent.to_path_buf(),
            source: e,
        })?;
    }
    let mut tmp = dest.as_os_str().to_os_string();
    tmp.push(".tmp");
    let tmp = std::path::PathBuf::from(tmp);
    std::fs::write(&tmp, bytes).map_err(|e| SnapshotsError::WriteFile {
        path: tmp.clone(),
        source: e,
    })?;
    std::fs::rename(&tmp, dest).map_err(|e| SnapshotsError::WriteFile {
        path: dest.to_path_buf(),
        source: e,
    })?;
    Ok(())
}

/// Non-async, zero-cost view bundling the snapshot-manifest ops and
/// the `snapshots/LATEST` pointer.
pub struct SnapshotsView<'a> {
    store: &'a Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
}

impl SnapshotsView<'_> {
    /// PUT a signed snapshot manifest at
    /// `by_id/<vol>/snapshots/<date>/<snap_ulid>.manifest`. Used by
    /// callers that already hold the canonical bytes in memory
    /// (owner-signed empty handoffs, the `claim --force` basis copy).
    /// The (date, ulid) partitioning makes the key globally unique
    /// by construction, so no CAS.
    pub async fn put_manifest(&self, snap_ulid: Ulid, bytes: Bytes) -> Result<(), SnapshotsError> {
        let key = manifest_key(self.vol_ulid, snap_ulid);
        crate::upload::put_with_content_type(self.store, &key, bytes, MIME_TEXT)
            .await
            .map_err(SnapshotsError::Put)
    }

    /// Upload a signed snapshot manifest from a local file. Reads the
    /// file verbatim and PUTs the body. Used by the regular drain
    /// seal path where the manifest is authored by the volume
    /// process and lives on disk.
    pub async fn put_manifest_from_file(
        &self,
        snap_ulid: Ulid,
        path: &std::path::Path,
    ) -> Result<(), SnapshotsError> {
        upload_file_to_snapshots(self.store, &manifest_key(self.vol_ulid, snap_ulid), path).await
    }

    /// PUT the `-stop.manifest` ephemeral variant written by
    /// `volume stop`. Same path-shape as [`Self::put_manifest`].
    pub async fn put_stop_manifest(
        &self,
        snap_ulid: Ulid,
        bytes: Bytes,
    ) -> Result<(), SnapshotsError> {
        let key = stop_manifest_key(self.vol_ulid, snap_ulid);
        crate::upload::put_with_content_type(self.store, &key, bytes, MIME_TEXT)
            .await
            .map_err(SnapshotsError::Put)
    }

    /// Sibling to [`Self::put_manifest_from_file`] for the
    /// `-stop.manifest` variant.
    pub async fn put_stop_manifest_from_file(
        &self,
        snap_ulid: Ulid,
        path: &std::path::Path,
    ) -> Result<(), SnapshotsError> {
        upload_file_to_snapshots(
            self.store,
            &stop_manifest_key(self.vol_ulid, snap_ulid),
            path,
        )
        .await
    }

    /// Build the canonical manifest key — used by callers that need
    /// to surface it (logging, error paths). Internal writes go
    /// through the typed verbs above.
    pub fn manifest_key(&self, snap_ulid: Ulid) -> StorePath {
        manifest_key(self.vol_ulid, snap_ulid)
    }

    /// Build the `-stop.manifest` variant key.
    pub fn stop_manifest_key(&self, snap_ulid: Ulid) -> StorePath {
        stop_manifest_key(self.vol_ulid, snap_ulid)
    }

    /// GET raw stop-manifest bytes (the `-stop.manifest` variant
    /// written by `volume stop`).
    pub async fn get_stop_manifest_bytes(&self, snap_ulid: Ulid) -> Result<Bytes, SnapshotsError> {
        let key = stop_manifest_key(self.vol_ulid, snap_ulid);
        let got = self.store.get(&key).await.map_err(SnapshotsError::Get)?;
        got.bytes().await.map_err(SnapshotsError::Get)
    }

    /// GET raw manifest bytes. For callers that re-serve or copy the
    /// canonical bytes verbatim. Pure-read sites that know which key
    /// to verify under should call [`Self::get_manifest`] instead so
    /// verification happens at the boundary.
    pub async fn get_manifest_bytes(&self, snap_ulid: Ulid) -> Result<Bytes, SnapshotsError> {
        let key = manifest_key(self.vol_ulid, snap_ulid);
        let got = self.store.get(&key).await.map_err(SnapshotsError::Get)?;
        got.bytes().await.map_err(SnapshotsError::Get)
    }

    /// GET the manifest body and write it atomically to `dest` on
    /// the local filesystem. Creates `dest.parent()` if missing,
    /// writes through `<dest>.tmp`, then renames into place — so a
    /// crash mid-write never leaves a partial manifest at the final
    /// path. Mirrors [`Self::put_manifest_from_file`] but in the
    /// download direction.
    pub async fn get_manifest_to_file(
        &self,
        snap_ulid: Ulid,
        dest: &std::path::Path,
    ) -> Result<(), SnapshotsError> {
        let bytes = self.get_manifest_bytes(snap_ulid).await?;
        write_file_atomic(dest, &bytes)
    }

    /// Sibling to [`Self::get_manifest_to_file`] for the
    /// `-stop.manifest` variant.
    pub async fn get_stop_manifest_to_file(
        &self,
        snap_ulid: Ulid,
        dest: &std::path::Path,
    ) -> Result<(), SnapshotsError> {
        let bytes = self.get_stop_manifest_bytes(snap_ulid).await?;
        write_file_atomic(dest, &bytes)
    }

    /// GET, parse, and verify the snapshot manifest under
    /// `verifying_key` — the volume's own `volume.pub`. One
    /// round-trip.
    pub async fn get_manifest(
        &self,
        snap_ulid: Ulid,
        verifying_key: &VerifyingKey,
    ) -> Result<SnapshotManifest, SnapshotsError> {
        let bytes = self.get_manifest_bytes(snap_ulid).await?;
        signing::read_snapshot_manifest_from_bytes(&bytes, verifying_key, &snap_ulid)
            .map_err(SnapshotsError::Verify)
    }

    /// HEAD on the manifest key. `Ok(None)` for absent. Used by
    /// existence-check fast paths (peer fetch fallback decisions,
    /// reconciliation).
    pub async fn head_manifest(
        &self,
        snap_ulid: Ulid,
    ) -> Result<Option<ObjectMeta>, SnapshotsError> {
        let key = manifest_key(self.vol_ulid, snap_ulid);
        match self.store.head(&key).await {
            Ok(m) => Ok(Some(m)),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(SnapshotsError::Get(e)),
        }
    }

    /// DELETE the manifest. Cleanup / reaper path.
    pub async fn delete_manifest(&self, snap_ulid: Ulid) -> Result<(), SnapshotsError> {
        let key = manifest_key(self.vol_ulid, snap_ulid);
        self.store.delete(&key).await.map_err(SnapshotsError::Put)
    }

    /// Promote a `-stop.manifest` to its `User` counterpart. Server-side
    /// COPY from `<snap>-stop.manifest` → `<snap>.manifest`, then
    /// best-effort DELETE of the `-stop.manifest` original. A leftover
    /// `-stop.manifest` after a failed DELETE is benign — the reader
    /// path prefers `User` on a tie.
    pub async fn promote_stop_to_user(&self, snap_ulid: Ulid) -> Result<(), SnapshotsError> {
        let stop = stop_manifest_key(self.vol_ulid, snap_ulid);
        let user = manifest_key(self.vol_ulid, snap_ulid);
        self.store
            .copy(&stop, &user)
            .await
            .map_err(SnapshotsError::Put)?;
        if let Err(e) = self.store.delete(&stop).await {
            tracing::warn!("[volume_data] promote-stop {snap_ulid}: deleting {stop}: {e}");
        }
        Ok(())
    }

    /// DELETE the `-stop.manifest` variant (e.g. after a failed-resume
    /// reclamation that won't promote).
    pub async fn delete_stop_manifest(&self, snap_ulid: Ulid) -> Result<(), SnapshotsError> {
        let key = stop_manifest_key(self.vol_ulid, snap_ulid);
        self.store.delete(&key).await.map_err(SnapshotsError::Put)
    }

    /// GET `by_id/<vol>/snapshots/LATEST`. Returns the current snap
    /// ULID plus an unforgeable [`LatestPointerToken`] carrying the
    /// `If-Match` ETag for a subsequent [`Self::advance_latest`].
    /// `Ok(None)` when absent (fresh volume / pointer not yet
    /// written).
    ///
    /// An unparseable body is treated as absent and logged — the
    /// pointer is a perf hint, not a correctness datum (the
    /// correctness-sensitive recovery basis lives on the event
    /// spine).
    pub async fn read_latest(&self) -> Result<Option<(Ulid, LatestPointerToken)>, SnapshotsError> {
        let key = latest_key(self.vol_ulid);
        let got = match self.store.get(&key).await {
            Ok(g) => g,
            Err(object_store::Error::NotFound { .. }) => return Ok(None),
            Err(e) => return Err(SnapshotsError::Get(e)),
        };
        let version = UpdateVersion {
            e_tag: got.meta.e_tag.clone(),
            version: got.meta.version.clone(),
        };
        let bytes = got.bytes().await.map_err(SnapshotsError::Get)?;
        let text = std::str::from_utf8(&bytes).map_err(SnapshotsError::NotUtf8)?;
        match Ulid::from_string(text.trim()) {
            Ok(u) => Ok(Some((u, LatestPointerToken { version }))),
            Err(_) => {
                tracing::warn!(
                    "[volume_data] {key} unparseable; treating as absent (self-heals on next publish)"
                );
                Ok(None)
            }
        }
    }

    /// CAS the LATEST pointer to `new_snap`. `prev` is the token
    /// returned by a previous [`Self::read_latest`]; pass `None` to
    /// request `If-None-Match: *` (the first publish). On
    /// [`LatestConflict::Stale`] the caller receives the
    /// then-current pointer ULID so they can decide whether to retry
    /// or bail (a race we lost where the winner advanced past us is
    /// benign for this perf-hint pointer).
    pub async fn advance_latest(
        &self,
        prev: Option<LatestPointerToken>,
        new_snap: Ulid,
    ) -> Result<LatestPointerToken, LatestConflict> {
        let key = latest_key(self.vol_ulid);
        let body = Bytes::from(new_snap.to_string().into_bytes());
        let outcome = match prev {
            Some(tok) => {
                put_with_match_with_type(self.store.as_ref(), &key, body, tok.version, MIME_TEXT)
                    .await
            }
            None => put_if_absent_with_type(self.store.as_ref(), &key, body, MIME_TEXT).await,
        };
        match outcome {
            Ok(result) => Ok(LatestPointerToken {
                version: UpdateVersion::from(result),
            }),
            Err(ConditionalPutError::PreconditionFailed) => {
                // Surface the current value so the caller can decide.
                let current = match self.read_latest().await {
                    Ok(Some((u, _))) => Some(u),
                    _ => None,
                };
                Err(LatestConflict::Stale { current })
            }
            Err(ConditionalPutError::Other(e)) => Err(LatestConflict::Store(e)),
        }
    }

    /// Convenience: ensure LATEST is at least `new_snap`. Reads the
    /// current pointer; if it is already `>= new_snap`, no-ops.
    /// Otherwise CASes once. A `Stale { current >= new_snap }` race
    /// is treated as benign (someone else got there first with a
    /// newer or equal value). Other `Stale` outcomes propagate so
    /// the caller can decide on retry policy.
    pub async fn bump_latest_if_newer(&self, new_snap: Ulid) -> Result<(), SnapshotsError> {
        let cur = self.read_latest().await?;
        if let Some((c, _)) = &cur
            && *c >= new_snap
        {
            return Ok(());
        }
        let tok = cur.map(|(_, t)| t);
        match self.advance_latest(tok, new_snap).await {
            Ok(_) => Ok(()),
            Err(LatestConflict::Stale { current: Some(c) }) if c >= new_snap => Ok(()),
            Err(LatestConflict::Stale { current }) => Err(SnapshotsError::LatestRaceLost {
                attempted: new_snap,
                current,
            }),
            Err(LatestConflict::Store(e)) => Err(SnapshotsError::Put(e)),
        }
    }
}

/// Non-async, zero-cost view bundling the segment-body operations
/// under `by_id/<vol>/segments/<YYYYMMDD>/<ulid>`.
pub struct SegmentsView<'a> {
    store: &'a Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
}

impl SegmentsView<'_> {
    /// Build the canonical segment key. The date partition is
    /// derived from the segment ULID's timestamp, so keys are stable
    /// and reconstructible from the ULID alone.
    pub fn segment_key(&self, seg_ulid: Ulid) -> StorePath {
        segment_key(self.vol_ulid, seg_ulid)
    }

    /// Multipart PUT of a segment body read from `path`.
    ///
    /// Used by the drain path (`pending/<ulid>`) and the GC handoff
    /// cursor (`gc/<ulid>` after `compact`). Multipart is chosen
    /// unconditionally: each part is a separate request with its own
    /// timeout and retry budget, so a stalled part doesn't restart
    /// the whole upload. Small segments still complete in a single
    /// part at roughly the cost of a plain PUT.
    ///
    /// Part size is the process-global value installed at daemon
    /// boot via [`crate::upload::set_part_size_bytes`]. Two parts
    /// in flight is enough to hide one request's handshake latency
    /// without bursting the upload link.
    pub async fn put_from_file(
        &self,
        seg_ulid: Ulid,
        path: &std::path::Path,
    ) -> Result<(), SegmentsError> {
        let data = std::fs::read(path).map_err(|e| SegmentsError::ReadFile {
            path: path.to_path_buf(),
            source: e,
        })?;
        self.put_bytes(seg_ulid, Bytes::from(data)).await
    }

    /// GET the whole segment object. Used by forced-claim tail
    /// re-own, which needs every byte (header + index to verify and
    /// re-sign, body to copy verbatim). Callers verify under the
    /// source volume's pubkey before reusing the bytes.
    pub async fn get_bytes(&self, seg_ulid: Ulid) -> Result<Bytes, SegmentsError> {
        let key = self.segment_key(seg_ulid);
        let got = self.store.get(&key).await.map_err(SegmentsError::Get)?;
        got.bytes().await.map_err(SegmentsError::Get)
    }

    /// Multipart PUT of a fully-formed in-memory segment object. Same
    /// part discipline as [`Self::put_from_file`]; used by
    /// forced-claim tail re-own, which composes the object in memory
    /// (re-signed head + copied body).
    pub async fn put_bytes(&self, seg_ulid: Ulid, mut bytes: Bytes) -> Result<(), SegmentsError> {
        const MAX_CONCURRENT_PARTS: usize = 2;

        let key = self.segment_key(seg_ulid);
        let part_size = crate::upload::part_size_bytes();
        let upload = self
            .store
            .put_multipart(&key)
            .await
            .map_err(SegmentsError::Put)?;
        let mut writer = WriteMultipart::new_with_chunk_size(upload, part_size);
        while !bytes.is_empty() {
            let take = bytes.len().min(part_size);
            let part = bytes.split_to(take);
            writer
                .wait_for_capacity(MAX_CONCURRENT_PARTS)
                .await
                .map_err(SegmentsError::Put)?;
            writer.put(part);
        }
        writer.finish().await.map_err(SegmentsError::Put)?;
        Ok(())
    }

    /// Range-GET the given byte interval. Used by the
    /// header+index-section verify path (recovery + prefetch) which
    /// fetches the fixed header first, then the index extent it
    /// reports. Returns the bytes in memory — callers verify under
    /// the volume's pubkey before persisting.
    pub async fn get_range(
        &self,
        seg_ulid: Ulid,
        range: Range<usize>,
    ) -> Result<Bytes, SegmentsError> {
        let key = self.segment_key(seg_ulid);
        self.store
            .get_range(&key, range)
            .await
            .map_err(SegmentsError::Get)
    }

    /// DELETE the segment object. Used by the per-volume retention
    /// reaper after the `Superseded` edge has aged past retention
    /// (`docs/design-segment-index.md`).
    pub async fn delete(&self, seg_ulid: Ulid) -> Result<(), SegmentsError> {
        let key = self.segment_key(seg_ulid);
        self.store.delete(&key).await.map_err(SegmentsError::Delete)
    }
}

/// Errors from [`SegmentsView`] operations.
#[derive(Debug)]
pub enum SegmentsError {
    Get(object_store::Error),
    Put(object_store::Error),
    Delete(object_store::Error),
    /// Failed to read the on-disk source file for an upload.
    ReadFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for SegmentsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get(e) => write!(f, "getting segment object: {e}"),
            Self::Put(e) => write!(f, "putting segment object: {e}"),
            Self::Delete(e) => write!(f, "deleting segment object: {e}"),
            Self::ReadFile { path, source } => write!(f, "reading {}: {source}", path.display()),
        }
    }
}

impl std::error::Error for SegmentsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Get(e) | Self::Put(e) | Self::Delete(e) => Some(e),
            Self::ReadFile { source, .. } => Some(source),
        }
    }
}

/// Unforgeable read-receipt for `by_id/<vol>/snapshots/LATEST`.
/// Carries the `If-Match` precondition for a subsequent
/// [`SnapshotsView::advance_latest`]. Constructible only inside this
/// module; holding one proves the caller has read LATEST's current
/// state.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct LatestPointerToken {
    version: UpdateVersion,
}

/// Conflict outcomes for [`SnapshotsView::advance_latest`].
#[derive(Debug)]
pub enum LatestConflict {
    /// The pointer changed under us. `current` is the value present
    /// after the failed CAS (best-effort: `None` if a follow-up
    /// `read_latest` could not surface it).
    Stale { current: Option<Ulid> },
    /// Underlying store error unrelated to the CAS condition.
    Store(object_store::Error),
}

impl std::fmt::Display for LatestConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Stale {
                current: Some(c), ..
            } => write!(f, "LATEST advanced under us to {c}"),
            Self::Stale { current: None, .. } => {
                write!(f, "LATEST changed under us (current value unavailable)")
            }
            Self::Store(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for LatestConflict {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(e) => Some(e),
            _ => None,
        }
    }
}

/// Errors from [`SnapshotsView`] operations.
#[derive(Debug)]
pub enum SnapshotsError {
    Get(object_store::Error),
    Put(object_store::Error),
    NotUtf8(std::str::Utf8Error),
    /// Manifest body did not parse or its signature did not verify
    /// under the supplied key.
    Verify(std::io::Error),
    /// Failed to read the on-disk source file for an upload.
    ReadFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// Failed to write or rename the on-disk destination file for a
    /// download (`_to_file` view methods).
    WriteFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// `bump_latest_if_newer` lost a CAS race against an unrelated
    /// (older) value — surface the attempted + current pointer so
    /// the operator can investigate.
    LatestRaceLost {
        attempted: Ulid,
        current: Option<Ulid>,
    },
}

impl std::fmt::Display for SnapshotsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get(e) => write!(f, "getting snapshot object: {e}"),
            Self::Put(e) => write!(f, "writing snapshot object: {e}"),
            Self::NotUtf8(e) => write!(f, "LATEST body not utf-8: {e}"),
            Self::Verify(e) => write!(f, "parsing/verifying manifest: {e}"),
            Self::ReadFile { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::WriteFile { path, source } => write!(f, "writing {}: {source}", path.display()),
            Self::LatestRaceLost { attempted, current } => match current {
                Some(c) => write!(
                    f,
                    "advancing LATEST to {attempted} lost to concurrent writer (now {c})"
                ),
                None => write!(
                    f,
                    "advancing LATEST to {attempted} lost to concurrent writer (now unknown)"
                ),
            },
        }
    }
}

impl std::error::Error for SnapshotsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Get(e) | Self::Put(e) => Some(e),
            Self::NotUtf8(e) => Some(e),
            Self::Verify(e) => Some(e),
            Self::ReadFile { source, .. } => Some(source),
            Self::WriteFile { source, .. } => Some(source),
            Self::LatestRaceLost { .. } => None,
        }
    }
}

/// Errors from [`HeadView`] operations.
#[derive(Debug)]
pub enum HeadError {
    Get(object_store::Error),
    Put(object_store::Error),
    Delete(object_store::Error),
    NotUtf8(std::str::Utf8Error),
    Parse(ParseHeadError),
}

impl std::fmt::Display for HeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get(e) => write!(f, "getting HEAD: {e}"),
            Self::Put(e) => write!(f, "putting HEAD: {e}"),
            Self::Delete(e) => write!(f, "deleting HEAD: {e}"),
            Self::NotUtf8(e) => write!(f, "HEAD body not utf-8: {e}"),
            Self::Parse(e) => write!(f, "parsing HEAD: {e}"),
        }
    }
}

impl std::error::Error for HeadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Get(e) | Self::Put(e) | Self::Delete(e) => Some(e),
            Self::NotUtf8(e) => Some(e),
            Self::Parse(e) => Some(e),
        }
    }
}

/// Errors from [`MetadataView`] operations.
#[derive(Debug)]
pub enum MetadataError {
    Get(object_store::Error),
    Put(object_store::Error),
    /// `volume.pub` body is not valid UTF-8.
    PubkeyNotUtf8(std::str::Utf8Error),
    /// `volume.pub` body did not parse as 64 hex chars + Ed25519 pub.
    InvalidPubkey(String),
    /// Failed to read the on-disk source file for an upload.
    ReadFile {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Get(e) => write!(f, "getting metadata: {e}"),
            Self::Put(e) => write!(f, "putting metadata: {e}"),
            Self::PubkeyNotUtf8(e) => write!(f, "volume.pub not utf-8: {e}"),
            Self::InvalidPubkey(s) => write!(f, "invalid volume.pub: {s}"),
            Self::ReadFile { path, source } => {
                write!(f, "reading {}: {source}", path.display())
            }
        }
    }
}

impl std::error::Error for MetadataError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Get(e) | Self::Put(e) => Some(e),
            Self::PubkeyNotUtf8(e) => Some(e),
            Self::ReadFile { source, .. } => Some(source),
            Self::InvalidPubkey(_) => None,
        }
    }
}

fn pubkey_key(vol: Ulid) -> StorePath {
    StorePath::from(elide_core::store_keys::meta_pub_key(vol))
}

fn manifest_key(vol: Ulid, snap: Ulid) -> StorePath {
    let dt: chrono::DateTime<chrono::Utc> = snap.datetime().into();
    let date = dt.format("%Y%m%d").to_string();
    StorePath::from(format!("by_id/{vol}/snapshots/{date}/{snap}.manifest"))
}

fn segment_key(vol: Ulid, seg: Ulid) -> StorePath {
    let dt: chrono::DateTime<chrono::Utc> = seg.datetime().into();
    let date = dt.format("%Y%m%d").to_string();
    StorePath::from(format!("by_id/{vol}/segments/{date}/{seg}"))
}

fn stop_manifest_key(vol: Ulid, snap: Ulid) -> StorePath {
    let dt: chrono::DateTime<chrono::Utc> = snap.datetime().into();
    let date = dt.format("%Y%m%d").to_string();
    StorePath::from(format!("by_id/{vol}/snapshots/{date}/{snap}-stop.manifest"))
}

fn latest_key(vol: Ulid) -> StorePath {
    StorePath::from(format!("by_id/{vol}/snapshots/LATEST"))
}

fn parse_hex_pubkey(hex: &str) -> Result<VerifyingKey, MetadataError> {
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(MetadataError::InvalidPubkey(format!(
            "expected 64 hex chars for Ed25519 pubkey, got {}",
            hex.len()
        )));
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| {
            MetadataError::InvalidPubkey(format!("invalid hex at position {}", i * 2))
        })?;
    }
    VerifyingKey::from_bytes(&bytes)
        .map_err(|e| MetadataError::InvalidPubkey(format!("invalid Ed25519 pubkey: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_core::ulid_mint::UlidMint;
    use object_store::memory::InMemory;

    fn vd() -> (Arc<dyn ObjectStore>, VolumeData) {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let vol = Ulid::from_string("01J0000000000000000000000V").unwrap();
        (Arc::clone(&store), VolumeData::new(store, vol))
    }

    fn mint() -> UlidMint {
        UlidMint::new(Ulid::nil())
    }

    #[tokio::test]
    async fn head_read_returns_empty_when_absent() {
        let (_s, vd) = vd();
        let h = vd.head().read().await.unwrap();
        assert_eq!(h, SegmentHead::empty(None));
    }

    #[tokio::test]
    async fn head_put_then_read_round_trips() {
        let (_s, vd) = vd();
        let mut m = mint();
        let mut head = SegmentHead::empty(Some(m.next()));
        head.added.insert(m.next());
        vd.head().put(&head).await.unwrap();
        let got = vd.head().read().await.unwrap();
        assert_eq!(got, head);
    }

    #[tokio::test]
    async fn head_delete_removes_object() {
        let (_s, vd) = vd();
        let mut h = SegmentHead::empty(None);
        h.added.insert(mint().next());
        vd.head().put(&h).await.unwrap();
        vd.head().delete().await.unwrap();
        assert_eq!(vd.head().read().await.unwrap(), SegmentHead::empty(None));
    }

    #[tokio::test]
    async fn metadata_pubkey_round_trip() {
        let (store, vd) = vd();
        let (_signer, vk) = elide_core::signing::generate_ephemeral_signer();
        let hex = elide_core::signing::encode_hex(&vk.to_bytes()) + "\n";
        store
            .put(
                &pubkey_key(vd.vol_ulid()),
                bytes::Bytes::from(hex.into_bytes()).into(),
            )
            .await
            .unwrap();
        let got = vd.metadata().read_pubkey().await.unwrap();
        assert_eq!(got.to_bytes(), vk.to_bytes());
    }

    // ── SnapshotsView ───────────────────────────────────────────────

    fn manifest_bytes(signer: &dyn elide_core::segment::SegmentSigner, segments: &[Ulid]) -> Bytes {
        Bytes::from(elide_core::signing::build_snapshot_manifest_bytes(
            signer, segments,
        ))
    }

    #[tokio::test]
    async fn snapshots_put_manifest_round_trips_through_get_manifest() {
        let (_s, vd) = vd();
        let (signer, vk) = elide_core::signing::generate_ephemeral_signer();
        let mut m = mint();
        let s1 = m.next();
        let s2 = m.next();
        let snap = m.next();
        let body = manifest_bytes(&*signer, &[s1, s2]);
        vd.snapshots()
            .put_manifest(snap, body.clone())
            .await
            .unwrap();
        let parsed = vd.snapshots().get_manifest(snap, &vk).await.unwrap();
        assert_eq!(parsed.segment_ulids, vec![s1, s2]);
    }

    #[tokio::test]
    async fn snapshots_get_manifest_rejects_wrong_key() {
        let (_s, vd) = vd();
        let (signer, _vk) = elide_core::signing::generate_ephemeral_signer();
        let (_signer2, wrong_vk) = elide_core::signing::generate_ephemeral_signer();
        let mut m = mint();
        let s1 = m.next();
        let snap = m.next();
        vd.snapshots()
            .put_manifest(snap, manifest_bytes(&*signer, &[s1]))
            .await
            .unwrap();
        assert!(
            vd.snapshots().get_manifest(snap, &wrong_vk).await.is_err(),
            "verification must fail under the wrong key"
        );
    }

    #[tokio::test]
    async fn snapshots_get_manifest_bytes_is_unverified() {
        // Used by the recovery flow that peeks the unauthenticated
        // recovery header before picking a verifying key.
        let (_s, vd) = vd();
        let (signer, _vk) = elide_core::signing::generate_ephemeral_signer();
        let mut m = mint();
        let snap = m.next();
        let body = manifest_bytes(&*signer, &[]);
        vd.snapshots()
            .put_manifest(snap, body.clone())
            .await
            .unwrap();
        let got = vd.snapshots().get_manifest_bytes(snap).await.unwrap();
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn snapshots_get_manifest_to_file_writes_bytes_atomically() {
        let tmp = tempfile::tempdir().unwrap();
        let (_s, vd) = vd();
        let (signer, _vk) = elide_core::signing::generate_ephemeral_signer();
        let mut m = mint();
        let snap = m.next();
        let body = manifest_bytes(&*signer, &[m.next()]);
        vd.snapshots()
            .put_manifest(snap, body.clone())
            .await
            .unwrap();

        // dest is inside a subdirectory that does not exist — view
        // creates parents.
        let dest = tmp
            .path()
            .join("nested")
            .join("snapshots")
            .join("m.manifest");
        vd.snapshots()
            .get_manifest_to_file(snap, &dest)
            .await
            .unwrap();

        let on_disk = std::fs::read(&dest).unwrap();
        assert_eq!(on_disk.as_slice(), body.as_ref());

        // No leftover .tmp at the final path.
        let leftover = {
            let mut p = dest.as_os_str().to_os_string();
            p.push(".tmp");
            std::path::PathBuf::from(p)
        };
        assert!(!leftover.exists(), "atomic rename must consume the .tmp");
    }

    #[tokio::test]
    async fn snapshots_get_manifest_to_file_reports_absent_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let (_s, vd) = vd();
        let snap = mint().next();
        let dest = tmp.path().join("m.manifest");
        let err = vd
            .snapshots()
            .get_manifest_to_file(snap, &dest)
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            SnapshotsError::Get(object_store::Error::NotFound { .. })
        ));
        assert!(!dest.exists(), "no file written when fetch fails");
    }

    #[tokio::test]
    async fn snapshots_head_manifest_reports_absence() {
        let (_s, vd) = vd();
        let snap = mint().next();
        assert!(vd.snapshots().head_manifest(snap).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn snapshots_head_manifest_reports_presence() {
        let (_s, vd) = vd();
        let (signer, _vk) = elide_core::signing::generate_ephemeral_signer();
        let mut m = mint();
        let snap = m.next();
        vd.snapshots()
            .put_manifest(snap, manifest_bytes(&*signer, &[]))
            .await
            .unwrap();
        assert!(vd.snapshots().head_manifest(snap).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn snapshots_delete_manifest_removes_object() {
        let (_s, vd) = vd();
        let (signer, _vk) = elide_core::signing::generate_ephemeral_signer();
        let mut m = mint();
        let snap = m.next();
        vd.snapshots()
            .put_manifest(snap, manifest_bytes(&*signer, &[]))
            .await
            .unwrap();
        vd.snapshots().delete_manifest(snap).await.unwrap();
        assert!(vd.snapshots().head_manifest(snap).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn snapshots_read_latest_absent_is_none() {
        let (_s, vd) = vd();
        assert!(vd.snapshots().read_latest().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn snapshots_advance_latest_then_read_round_trips() {
        let (_s, vd) = vd();
        let snap = mint().next();
        let tok = vd.snapshots().advance_latest(None, snap).await.unwrap();
        let (got, _tok2) = vd.snapshots().read_latest().await.unwrap().unwrap();
        assert_eq!(got, snap);
        // Holding the post-advance token, we can advance again to a
        // newer ULID with a single CAS.
        let mut m = UlidMint::new(snap);
        let _ = m.next(); // skip equal-or-prior
        let newer = m.next();
        vd.snapshots()
            .advance_latest(Some(tok), newer)
            .await
            .unwrap();
        let (got2, _) = vd.snapshots().read_latest().await.unwrap().unwrap();
        assert_eq!(got2, newer);
    }

    #[tokio::test]
    async fn snapshots_advance_latest_with_stale_token_returns_stale() {
        let (_s, vd) = vd();
        let mut m = mint();
        let a = m.next();
        let b = m.next();
        let tok_a = vd.snapshots().advance_latest(None, a).await.unwrap();
        // Bypass our token: another writer advances to `b`.
        vd.snapshots()
            .advance_latest(Some(tok_a.clone()), b)
            .await
            .unwrap();
        // Now `tok_a` is stale. Advancing under it fails.
        let err = vd
            .snapshots()
            .advance_latest(Some(tok_a), a)
            .await
            .unwrap_err();
        match err {
            LatestConflict::Stale { current } => assert_eq!(current, Some(b)),
            other => panic!("expected Stale, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn snapshots_advance_latest_initial_with_some_token_rejects_when_absent() {
        // Passing a (fabricated) token to advance against an absent
        // LATEST should fail — only `None` is valid for the first
        // publish. We exercise this via the symmetric scenario:
        // a None advance succeeds when LATEST is absent, a None
        // advance fails when LATEST exists.
        let (_s, vd) = vd();
        let mut m = mint();
        let a = m.next();
        let b = m.next();
        vd.snapshots().advance_latest(None, a).await.unwrap();
        let err = vd.snapshots().advance_latest(None, b).await.unwrap_err();
        assert!(matches!(err, LatestConflict::Stale { current: Some(_) }));
    }

    #[tokio::test]
    async fn snapshots_bump_latest_if_newer_idempotent_when_equal() {
        let (_s, vd) = vd();
        let snap = mint().next();
        vd.snapshots().bump_latest_if_newer(snap).await.unwrap();
        // Second call is a no-op (cur >= new), no CAS issued.
        vd.snapshots().bump_latest_if_newer(snap).await.unwrap();
        let (got, _) = vd.snapshots().read_latest().await.unwrap().unwrap();
        assert_eq!(got, snap);
    }

    #[tokio::test]
    async fn snapshots_bump_latest_if_newer_skips_when_already_newer() {
        let (_s, vd) = vd();
        let mut m = mint();
        let older = m.next();
        let newer = m.next();
        vd.snapshots().bump_latest_if_newer(newer).await.unwrap();
        // Attempting to bump to `older` is a no-op because cur (newer) >= older.
        vd.snapshots().bump_latest_if_newer(older).await.unwrap();
        let (got, _) = vd.snapshots().read_latest().await.unwrap().unwrap();
        assert_eq!(got, newer, "older bump must not regress LATEST");
    }

    // ── SegmentsView ────────────────────────────────────────────────

    #[tokio::test]
    async fn segments_segment_key_is_date_partitioned_by_ulid_timestamp() {
        let (_s, vd) = vd();
        // Pin a ULID's timestamp so the expected partition is exact.
        let seg = Ulid::from_parts(1_743_120_000_000, 42);
        let key = vd.segments().segment_key(seg);
        let dt: chrono::DateTime<chrono::Utc> = seg.datetime().into();
        let date = dt.format("%Y%m%d").to_string();
        assert_eq!(
            key.as_ref(),
            format!("by_id/{}/segments/{date}/{seg}", vd.vol_ulid()),
        );
    }

    #[tokio::test]
    async fn segments_put_from_file_round_trips_via_get_range() {
        let tmp = tempfile::tempdir().unwrap();
        let (_s, vd) = vd();
        let seg = mint().next();
        // Body larger than the fallback part size would force real
        // multipart; the in-memory store handles either path
        // transparently, but we cover the small-payload case here
        // (one part) since that is the common drain case.
        let body = b"segment body bytes";
        let path = tmp.path().join(seg.to_string());
        std::fs::write(&path, body).unwrap();

        vd.segments().put_from_file(seg, &path).await.unwrap();

        let got = vd.segments().get_range(seg, 0..body.len()).await.unwrap();
        assert_eq!(got.as_ref(), body);
    }

    #[tokio::test]
    async fn segments_put_from_file_reports_missing_source() {
        let (_s, vd) = vd();
        let seg = mint().next();
        let bogus = std::path::Path::new("/does/not/exist/segment");
        let err = vd.segments().put_from_file(seg, bogus).await.unwrap_err();
        assert!(matches!(err, SegmentsError::ReadFile { .. }));
    }

    #[tokio::test]
    async fn segments_get_range_absent_returns_get_error() {
        let (_s, vd) = vd();
        let seg = mint().next();
        let err = vd.segments().get_range(seg, 0..8).await.unwrap_err();
        assert!(matches!(
            err,
            SegmentsError::Get(object_store::Error::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn segments_delete_removes_object() {
        let tmp = tempfile::tempdir().unwrap();
        let (_s, vd) = vd();
        let seg = mint().next();
        let body = b"x";
        let path = tmp.path().join(seg.to_string());
        std::fs::write(&path, body).unwrap();
        vd.segments().put_from_file(seg, &path).await.unwrap();

        vd.segments().delete(seg).await.unwrap();
        let err = vd.segments().get_range(seg, 0..1).await.unwrap_err();
        assert!(matches!(
            err,
            SegmentsError::Get(object_store::Error::NotFound { .. })
        ));
    }
}
