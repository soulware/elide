//! Read-only volume view, ancestor walkers, fork creation, and WAL recovery
//! helpers. Split out of `volume/mod.rs` for legibility — no behaviour change.

use std::cell::RefCell;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ulid::Ulid;

use crate::{
    extentindex::{self, BodySource},
    lbamap, segment, writelog,
};

use super::{
    AncestorLayer, BoxFetcher, FileCache, ZERO_HASH, find_segment_in_dirs, open_delta_body_in_dirs,
    read_extents,
};

/// Read-only view of a volume: rebuilds LBA map and extent index from
/// segments + ancestor chain, no WAL replay, no exclusive lock.
pub struct ReadonlyVolume {
    base_dir: PathBuf,
    ancestor_layers: Vec<AncestorLayer>,
    lbamap: lbamap::LbaMap,
    extent_index: extentindex::ExtentIndex,
    file_cache: RefCell<FileCache>,
    fetcher: Option<BoxFetcher>,
}

impl ReadonlyVolume {
    /// Open a volume directory for read-only access.
    ///
    /// Does not create `wal/`, does not acquire an exclusive lock, and does not
    /// replay the WAL. WAL records from an active writer on the same volume will
    /// not be visible. Intended for the `--readonly` NBD serve path.
    pub fn open(fork_dir: &Path, by_id_dir: &Path) -> io::Result<Self> {
        let (ancestor_layers, lbamap, extent_index) = open_read_state(fork_dir, by_id_dir)?;
        Ok(Self {
            base_dir: fork_dir.to_owned(),
            ancestor_layers,
            lbamap,
            extent_index,
            file_cache: RefCell::new(FileCache::default()),
            fetcher: None,
        })
    }

    /// Read `lba_count` 4KB blocks starting at `start_lba`.
    /// Unwritten blocks are returned as zeros.
    pub fn read(&self, start_lba: u64, lba_count: u32) -> io::Result<Vec<u8>> {
        read_extents(
            start_lba,
            lba_count,
            &self.lbamap,
            &self.extent_index,
            &self.file_cache,
            |id, bss, idx| self.find_segment_file(id, bss, idx),
            |id| {
                open_delta_body_in_dirs(
                    id,
                    &self.base_dir,
                    &self.ancestor_layers,
                    self.fetcher.as_ref(),
                )
            },
        )
    }

    fn find_segment_file(
        &self,
        segment_id: Ulid,
        body_section_start: u64,
        body_source: BodySource,
    ) -> io::Result<PathBuf> {
        find_segment_in_dirs(
            segment_id,
            &self.base_dir,
            &self.ancestor_layers,
            self.fetcher.as_ref(),
            body_section_start,
            body_source,
        )
    }

    /// Attach a `SegmentFetcher` for demand-fetch on segment cache miss.
    pub fn set_fetcher(&mut self, fetcher: BoxFetcher) {
        self.fetcher = Some(fetcher);
    }

    /// Return all fork directories in the ancestry chain, oldest-first,
    /// with the current fork last.
    pub fn fork_dirs(&self) -> Vec<PathBuf> {
        self.ancestor_layers
            .iter()
            .map(|l| l.dir.clone())
            .chain(std::iter::once(self.base_dir.clone()))
            .collect()
    }
}

/// Walk the ancestry chain and rebuild the LBA map and extent index.
///
/// This is the common open-time setup shared by `Volume::open` and
/// `ReadonlyVolume::open`. Returns the ancestor layers (oldest-first, fork
/// parents first then extent-index sources deduped by dir), the rebuilt
/// LBA map, and the rebuilt extent index.
///
/// **Ancestor layer semantics have two jobs** and used to conflate them:
///
/// 1. *LBA-map contribution* — which volumes' segments claim LBAs that
///    should be visible in this volume's read view. This is strictly the
///    fork parent chain (`volume.parent`); extent-index sources never
///    contribute LBA claims.
/// 2. *Body lookup search path* — when an extent resolves via the extent
///    index to a canonical segment, where to find that segment's body on
///    disk (and where to route demand-fetches). **This must include
///    extent-index sources**, because a fork's parent may hold DedupRef
///    entries whose canonical bodies live in an extent-index source.
///    Earlier versions of this function only returned fork parents, which
///    caused silent zero-fill on fork reads through DedupRef — see
///    `docs/architecture.md`.
///
/// The rebuilt `LbaMap` is computed from `lba_chain` (fork-only, correct).
/// The returned `ancestor_layers` is the broader set (fork + extent), used
/// downstream by `find_segment_in_dirs`, `open_delta_body_in_dirs`,
/// `prepare_reclaim`, and `RemoteFetcher`'s search list.
pub(super) fn open_read_state(
    fork_dir: &Path,
    by_id_dir: &Path,
) -> io::Result<(Vec<AncestorLayer>, lbamap::LbaMap, extentindex::ExtentIndex)> {
    // Fail-fast verification: every ancestor in the fork chain must have a
    // signed `.manifest` file whose listed `.idx` files are all present
    // locally. The trust chain is rooted in this volume's own pubkey and
    // walked via the `parent_pubkey` embedded in each child's provenance.
    verify_ancestor_manifests(fork_dir, by_id_dir)?;
    let fork_layers = walk_ancestors(fork_dir, by_id_dir)?;
    let lba_chain: Vec<(PathBuf, Option<String>)> = fork_layers
        .iter()
        .map(|l| (l.dir.clone(), l.branch_ulid.clone()))
        .chain(std::iter::once((fork_dir.to_owned(), None)))
        .collect();
    let lbamap = lbamap::rebuild_segments(&lba_chain)?;

    // Extent-index sources: recursed across the fork chain by
    // `walk_extent_ancestors`. They contribute canonical hashes to the
    // extent index and must also be searchable for body lookups.
    let extent_sources = walk_extent_ancestors(fork_dir, by_id_dir)?;

    // Build the hash chain for extent-index rebuild: fork chain + extent
    // sources (deduped by dir). `extent_index.lookup` returns canonical
    // locations populated from both.
    let mut hash_chain = lba_chain;
    for layer in &extent_sources {
        if !hash_chain.iter().any(|(dir, _)| dir == &layer.dir) {
            hash_chain.push((layer.dir.clone(), layer.branch_ulid.clone()));
        }
    }
    let extent_index = extentindex::rebuild(&hash_chain)?;

    // The returned `ancestor_layers` unifies fork parents and extent
    // sources. Callers use this as the body-lookup search path; the
    // LBA-map-only subset was already consumed above.
    let mut ancestor_layers = fork_layers;
    for layer in extent_sources {
        if !ancestor_layers.iter().any(|l| l.dir == layer.dir) {
            ancestor_layers.push(layer);
        }
    }
    Ok((ancestor_layers, lbamap, extent_index))
}

/// Parse a `<source-ulid>/<snapshot-ulid>` lineage entry, validating
/// both components as ULIDs to prevent path traversal. Returns the source ULID
/// slice (borrowed from `entry`) and the owned snapshot ULID string.
fn parse_lineage_entry<'a>(
    entry: &'a str,
    field: &str,
    fork_dir: &Path,
) -> io::Result<(&'a str, String)> {
    let (source_ulid_str, snapshot_ulid_str) = entry.split_once('/').ok_or_else(|| {
        io::Error::other(format!(
            "malformed {field} entry in {}: {entry}",
            fork_dir.display()
        ))
    })?;
    if snapshot_ulid_str.contains('/') {
        return Err(io::Error::other(format!(
            "malformed {field} entry in {}: {entry} has more than one '/' separator",
            fork_dir.display()
        )));
    }
    let snapshot_ulid = Ulid::from_string(snapshot_ulid_str)
        .map_err(|e| io::Error::other(format!("bad snapshot ULID in {field}: {e}")))?
        .to_string();
    Ulid::from_string(source_ulid_str).map_err(|_| {
        io::Error::other(format!(
            "malformed {field} entry in {}: source '{source_ulid_str}' is not a valid ULID",
            fork_dir.display(),
        ))
    })?;
    Ok((source_ulid_str, snapshot_ulid))
}

/// A volume with no `volume.provenance` is treated as root (empty chain).
/// All other provenance read errors propagate — in particular, a missing
/// or malformed file on a volume that had lineage is a loud failure.
fn load_lineage_or_empty(fork_dir: &Path) -> io::Result<crate::signing::ProvenanceLineage> {
    let provenance_path = fork_dir.join(crate::signing::VOLUME_PROVENANCE_FILE);
    if !provenance_path.exists() {
        return Ok(crate::signing::ProvenanceLineage::default());
    }
    crate::signing::read_lineage_verifying_signature(
        fork_dir,
        crate::signing::VOLUME_PUB_FILE,
        crate::signing::VOLUME_PROVENANCE_FILE,
    )
}

/// Resolve an ancestor volume directory by ULID.
///
/// All ancestors — writable, imported readonly bases, and ancestors pulled
/// from S3 to satisfy a child's lineage — live in `by_id/<ulid>/`. The
/// returned path is deterministic so callers (and tests) can report it in
/// errors even if it does not yet exist.
pub fn resolve_ancestor_dir(by_id_dir: &Path, ulid: &str) -> PathBuf {
    by_id_dir.join(ulid)
}

/// Verify every ancestor of `fork_dir` by walking the fork chain from the
/// current volume, using the `parent_pubkey` embedded in each child's
/// signed provenance as the trust anchor for the next link.
///
/// For each ancestor in the chain:
/// 1. Verify the ancestor's `volume.provenance` under the pubkey the child
///    signed over (NOT the `volume.pub` on disk at the ancestor path).
/// 2. Read the ancestor's `snapshots/<snap_ulid>.manifest` file, also
///    verified under the same pubkey.
/// 3. Assert every segment ULID listed in the manifest is present as
///    `index/<ulid>.idx` in the ancestor directory.
///
/// Fails fast on any missing file, failed signature, or missing `.idx`.
/// Does not perform any demand-fetch — the caller is expected to prefetch
/// ancestor data before opening a fork.
///
/// The trust root is the current volume's own `volume.pub`, which the
/// caller has already validated as the identity of the volume they asked
/// to open.
pub fn verify_ancestor_manifests(fork_dir: &Path, by_id_dir: &Path) -> io::Result<()> {
    // Fast-path: if this volume has no parent, nothing to verify.
    let provenance_path = fork_dir.join(crate::signing::VOLUME_PROVENANCE_FILE);
    if !provenance_path.exists() {
        return Ok(());
    }
    let own_pubkey = crate::signing::load_verifying_key(fork_dir, crate::signing::VOLUME_PUB_FILE)?;
    let own_lineage = crate::signing::read_lineage_with_key(
        fork_dir,
        &own_pubkey,
        crate::signing::VOLUME_PROVENANCE_FILE,
    )?;
    let Some(mut current_parent) = own_lineage.parent else {
        return Ok(());
    };

    loop {
        let parent_dir = resolve_ancestor_dir(by_id_dir, &current_parent.volume_ulid);
        if !parent_dir.exists() {
            return Err(io::Error::other(format!(
                "ancestor {} not found locally (run `elide volume remote pull` first)",
                current_parent.volume_ulid
            )));
        }
        let parent_verifying = crate::signing::VerifyingKey::from_bytes(&current_parent.pubkey)
            .map_err(|e| {
                io::Error::other(format!(
                    "invalid parent pubkey in provenance for {}: {e}",
                    current_parent.volume_ulid
                ))
            })?;
        // For forker-attested "now" pins the `.manifest` is signed by a
        // different (ephemeral) key than the parent's identity. When set,
        // use it for the manifest; fall back to the identity key otherwise.
        let manifest_verifying = match current_parent.manifest_pubkey {
            Some(bytes) => crate::signing::VerifyingKey::from_bytes(&bytes).map_err(|e| {
                io::Error::other(format!(
                    "invalid parent manifest pubkey in provenance for {}: {e}",
                    current_parent.volume_ulid
                ))
            })?,
            None => parent_verifying,
        };

        let snap_ulid = Ulid::from_string(&current_parent.snapshot_ulid).map_err(|e| {
            io::Error::other(format!("invalid snapshot ULID in provenance parent: {e}"))
        })?;
        let segments =
            crate::signing::read_snapshot_manifest(&parent_dir, &manifest_verifying, &snap_ulid)?;

        let index_dir = parent_dir.join("index");
        for seg in &segments {
            let idx_path = index_dir.join(format!("{seg}.idx"));
            if !idx_path.exists() {
                return Err(io::Error::other(format!(
                    "ancestor {} snapshot {}: missing index/{}.idx",
                    current_parent.volume_ulid, snap_ulid, seg
                )));
            }
        }

        // Advance to this ancestor's own parent (if any), verifying its
        // provenance under the identity key we already trust (from the
        // previous child's embedded parent_pubkey).
        let parent_lineage = crate::signing::read_lineage_with_key(
            &parent_dir,
            &parent_verifying,
            crate::signing::VOLUME_PROVENANCE_FILE,
        )?;
        let Some(next) = parent_lineage.parent else {
            return Ok(());
        };
        current_parent = next;
    }
}

/// Walk the fork ancestry chain and return ancestor layers, oldest-first.
/// Public so that `ls.rs` and other read-only tools can build the rebuild chain.
pub fn walk_ancestors(fork_dir: &Path, by_id_dir: &Path) -> io::Result<Vec<AncestorLayer>> {
    let lineage = load_lineage_or_empty(fork_dir)?;
    let Some(parent) = lineage.parent else {
        return Ok(Vec::new());
    };
    let parent_fork_dir = resolve_ancestor_dir(by_id_dir, &parent.volume_ulid);

    // Recurse into the parent's fork chain first (builds oldest-first order).
    let mut ancestors = walk_ancestors(&parent_fork_dir, by_id_dir)?;
    ancestors.push(AncestorLayer {
        dir: parent_fork_dir,
        branch_ulid: Some(parent.snapshot_ulid),
    });
    Ok(ancestors)
}

/// Collect all extent-index source volumes reachable from `fork_dir`,
/// recursing through the fork-parent chain.
///
/// The `extent_index` field of a `volume.provenance` is a flat list of
/// `<source-ulid>/<snapshot-ulid>` entries, each naming a snapshot whose
/// extents populate the volume's `ExtentIndex` for dedup / delta source
/// lookups. At write time these hashes are consulted to decide whether
/// to emit a thin `DedupRef` / `Delta` entry instead of a fresh body.
///
/// **At read time**, every volume in the fork chain may contain thin
/// entries whose canonical bodies live in an extent-index source listed
/// by *that* ancestor. A fork child must therefore see the union of every
/// ancestor's extent-index sources, not just its own (`fork_volume` writes
/// an empty `extent_index` for forks — see `volume.rs::fork_volume_at`).
/// Without this recursion, a fork reading through DedupRef entries in its
/// parent silently zero-fills, because the extent_index rebuild would
/// never scan the source that owns the canonical body.
///
/// The `extent_index` field itself is flat at attach time (the coordinator
/// concatenates + dedupes the sources' own lists during import), so each
/// layer we visit contributes a fully-expanded set. This function's job
/// is the orthogonal recursion across *fork parents*: we walk `lineage.parent`
/// from `fork_dir` upward, unioning each volume's `extent_index`.
///
/// Dedup is by `source_dir`; when multiple ancestors reference the same
/// source at different snapshots, we keep the lexicographically greatest
/// `snapshot_ulid` — that's the cutoff that includes the most data.
pub fn walk_extent_ancestors(fork_dir: &Path, by_id_dir: &Path) -> io::Result<Vec<AncestorLayer>> {
    let mut layers: Vec<AncestorLayer> = Vec::new();
    let mut cursor: Option<PathBuf> = Some(fork_dir.to_owned());
    while let Some(dir) = cursor {
        let lineage = load_lineage_or_empty(&dir)?;
        for entry in &lineage.extent_index {
            let (source_ulid_str, snapshot_ulid) =
                parse_lineage_entry(entry, "extent_index", &dir)?;
            let source_dir = resolve_ancestor_dir(by_id_dir, source_ulid_str);
            match layers.iter_mut().find(|l| l.dir == source_dir) {
                Some(existing) => {
                    if existing
                        .branch_ulid
                        .as_deref()
                        .is_none_or(|prev| snapshot_ulid.as_str() > prev)
                    {
                        existing.branch_ulid = Some(snapshot_ulid);
                    }
                }
                None => {
                    layers.push(AncestorLayer {
                        dir: source_dir,
                        branch_ulid: Some(snapshot_ulid),
                    });
                }
            }
        }
        cursor = lineage
            .parent
            .map(|p| resolve_ancestor_dir(by_id_dir, &p.volume_ulid));
    }
    Ok(layers)
}

/// Return the latest snapshot ULID string for a fork, or `None` if no
/// snapshots exist. Snapshots live as plain files under `fork_dir/snapshots/`.
pub fn latest_snapshot(fork_dir: &Path) -> io::Result<Option<Ulid>> {
    let snapshots_dir = fork_dir.join("snapshots");
    let iter = match fs::read_dir(&snapshots_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let latest = iter
        .filter_map(|e| e.ok())
        .filter_map(|e| Ulid::from_string(e.file_name().to_str()?).ok())
        .max();
    Ok(latest)
}

/// Create a new volume directory, branched from the latest snapshot of the source volume.
///
/// The source volume must have at least one snapshot (written by `snapshot()`).
/// `new_fork_dir` is created with `wal/` and `pending/`, a fresh keypair is
/// generated, and a signed `volume.provenance` is written recording the
/// fork's `parent` field in the form `<source-ulid>/snapshots/<branch-ulid>`.
/// The source ULID is derived from `source_fork_dir`'s directory name.
///
/// Returns `Ok(())` on success; `new_fork_dir` must not already exist.
pub fn fork_volume(new_fork_dir: &Path, source_fork_dir: &Path) -> io::Result<()> {
    let branch_ulid = latest_snapshot(source_fork_dir)?.ok_or_else(|| {
        io::Error::other(format!(
            "source volume '{}' has no snapshots; run snapshot-volume first",
            source_fork_dir.display()
        ))
    })?;
    fork_volume_at(new_fork_dir, source_fork_dir, branch_ulid)
}

/// Like `fork_volume` but pins the fork to an explicit snapshot ULID.
///
/// Used by `volume create --from <vol_ulid>/<snap_ulid>` when the caller
/// wants the branch point to be something other than the source volume's
/// latest snapshot — typically because the source is a pulled readonly
/// ancestor and the caller has a specific snapshot ULID in mind.
///
/// The snapshot is **not** required to exist as a local file: a pulled
/// readonly ancestor may not have its snapshot markers prefetched yet at
/// the time of forking. The snapshot ULID is still recorded in the child's
/// signed provenance and will be resolved at open time once prefetch has
/// populated the ancestor's `snapshots/` directory.
pub fn fork_volume_at(
    new_fork_dir: &Path,
    source_fork_dir: &Path,
    branch_ulid: Ulid,
) -> io::Result<()> {
    fork_volume_at_inner(new_fork_dir, source_fork_dir, branch_ulid, None)
}

/// Like `fork_volume_at` but also records a `manifest_pubkey` override in
/// the child's provenance. The parent's identity key (for verifying the
/// ancestor's own `volume.provenance` and `.idx` signatures) is still
/// loaded from the source's on-disk `volume.pub`; `manifest_pubkey` is
/// used **only** for the pinned snapshot's `.manifest`.
///
/// Used by `volume create --from --force-snapshot` when the forker doesn't hold the
/// source owner's private key and instead signs the synthetic manifest
/// with an ephemeral key. That ephemeral pubkey goes here; the ancestor's
/// own artefacts continue to verify under the owner's key.
pub fn fork_volume_at_with_manifest_key(
    new_fork_dir: &Path,
    source_fork_dir: &Path,
    branch_ulid: Ulid,
    manifest_pubkey: crate::signing::VerifyingKey,
) -> io::Result<()> {
    fork_volume_at_inner(
        new_fork_dir,
        source_fork_dir,
        branch_ulid,
        Some(manifest_pubkey),
    )
}

fn fork_volume_at_inner(
    new_fork_dir: &Path,
    source_fork_dir: &Path,
    branch_ulid: Ulid,
    manifest_pubkey: Option<crate::signing::VerifyingKey>,
) -> io::Result<()> {
    if new_fork_dir.exists() {
        return Err(io::Error::other(format!(
            "fork directory '{}' already exists",
            new_fork_dir.display()
        )));
    }

    // Canonicalize so that symlink paths (e.g. by_name/<name>) resolve to
    // their real by_id/<ulid> directory before we extract the ULID component.
    let source_real = fs::canonicalize(source_fork_dir)?;
    let source_ulid = source_real
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::other("source fork dir has no name"))?;
    // Validate the source directory name really is a ULID before we embed
    // it in the child's provenance as an ancestor reference.
    Ulid::from_string(source_ulid).map_err(|e| {
        io::Error::other(format!(
            "source fork dir name is not a ULID ({}): {e}",
            source_real.display()
        ))
    })?;

    fs::create_dir_all(new_fork_dir.join("wal"))?;
    fs::create_dir_all(new_fork_dir.join("pending"))?;

    // Generate a fresh keypair for the new fork. Every writable volume must have
    // a signing key; the fork gets its own identity independent of its parent.
    // The signing key's in-memory form is reused immediately to write provenance
    // so we never have to re-read it from disk.
    let key = crate::signing::generate_keypair(
        new_fork_dir,
        crate::signing::VOLUME_KEY_FILE,
        crate::signing::VOLUME_PUB_FILE,
    )?;

    // Write signed provenance carrying the fork's parent reference. Extent
    // index is empty for forks — fork ancestry is a read-path relationship
    // tracked in `parent`, not a hash-pool relationship.
    //
    // Embed the parent's identity pubkey (loaded from the source's on-disk
    // `volume.pub`) under the child's signature so the fork's open-time
    // ancestor walk has a trust anchor for the parent's own signed
    // artefacts — see `ParentRef` in signing.rs. If a manifest_pubkey was
    // supplied (force-snapshot path), also embed it as a narrow override
    // for the pinned `.manifest` only.
    let parent_pubkey =
        crate::signing::load_verifying_key(&source_real, crate::signing::VOLUME_PUB_FILE)?;
    let lineage = crate::signing::ProvenanceLineage {
        parent: Some(crate::signing::ParentRef {
            volume_ulid: source_ulid.to_owned(),
            snapshot_ulid: branch_ulid.to_string(),
            pubkey: parent_pubkey.to_bytes(),
            manifest_pubkey: manifest_pubkey.map(|k| k.to_bytes()),
        }),
        extent_index: Vec::new(),
    };
    crate::signing::write_provenance(
        new_fork_dir,
        &key,
        crate::signing::VOLUME_PROVENANCE_FILE,
        &lineage,
    )?;

    Ok(())
}

// --- WAL helpers ---

/// Scan a WAL file and replay its records into `lbamap` + `extent_index`,
/// returning the WAL ULID, the valid (non-partial) tail size, and the
/// reconstructed pending_entries list.
///
/// Shared between:
/// - [`recover_wal`], which also reopens the file for continued appending
///   (latest WAL case).
/// - `Volume::open_impl`'s recovery-time promote loop, which promotes
///   each non-latest WAL to a fresh segment and deletes the WAL file
///   rather than reopening it.
///
/// `writelog::scan` truncates any partial-tail record before returning.
pub(super) fn replay_wal_records(
    path: &Path,
    lbamap: &mut lbamap::LbaMap,
    extent_index: &mut extentindex::ExtentIndex,
) -> io::Result<(Ulid, u64, Vec<segment::SegmentEntry>)> {
    let ulid_str = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::other("bad WAL filename"))?;
    let ulid = Ulid::from_string(ulid_str).map_err(|e| io::Error::other(e.to_string()))?;

    let (records, valid_size) = writelog::scan(path)?;

    let mut pending_entries = Vec::new();
    for record in records {
        match record {
            writelog::LogRecord::Data {
                hash,
                start_lba,
                lba_length,
                flags,
                body_offset,
                data,
            } => {
                let body_length = data.len() as u32;
                let compressed = flags.contains(writelog::WalFlags::COMPRESSED);
                // Translate WalFlags → SegmentFlags: the two namespaces use different
                // bit values (WalFlags::COMPRESSED = 0x01, SegmentFlags::COMPRESSED = 0x04).
                let seg_flags = if compressed {
                    segment::SegmentFlags::COMPRESSED
                } else {
                    segment::SegmentFlags::empty()
                };
                lbamap.insert(start_lba, lba_length, hash);
                // Temporary WAL offset — updated to segment offset on promotion.
                extent_index.insert(
                    hash,
                    extentindex::ExtentLocation {
                        segment_id: ulid,
                        body_offset,
                        body_length,
                        compressed,
                        body_source: BodySource::Local,
                        body_section_start: 0,
                        inline_data: None,
                    },
                );
                pending_entries.push(segment::SegmentEntry::new_data(
                    hash, start_lba, lba_length, seg_flags, data,
                ));
            }
            writelog::LogRecord::Ref {
                hash,
                start_lba,
                lba_length,
            } => {
                lbamap.insert(start_lba, lba_length, hash);
                // REF: no body bytes, no body reservation, no extent_index
                // update. The canonical entry is populated from whichever
                // segment holds the DATA for this hash.
                pending_entries.push(segment::SegmentEntry::new_dedup_ref(
                    hash, start_lba, lba_length,
                ));
            }
            writelog::LogRecord::Zero {
                start_lba,
                lba_length,
            } => {
                lbamap.insert(start_lba, lba_length, ZERO_HASH);
                pending_entries.push(segment::SegmentEntry::new_zero(start_lba, lba_length));
            }
        }
    }

    Ok((ulid, valid_size, pending_entries))
}

/// Scan an existing WAL, replay its records into `lbamap`, rebuild
/// `pending_entries`, and reopen the WAL for continued appending.
///
/// This is the single WAL scan on startup — it both updates the LBA map
/// (WAL is more recent than any segment) and recovers the pending_entries
/// list needed for the next promotion.
pub(super) fn recover_wal(
    path: PathBuf,
    lbamap: &mut lbamap::LbaMap,
    extent_index: &mut extentindex::ExtentIndex,
) -> io::Result<(
    writelog::WriteLog,
    Ulid,
    PathBuf,
    Vec<segment::SegmentEntry>,
)> {
    let (ulid, valid_size, pending_entries) = replay_wal_records(&path, lbamap, extent_index)?;
    let wal = writelog::WriteLog::reopen(&path, valid_size)?;
    Ok((wal, ulid, path, pending_entries))
}

/// Create a new WAL file using the provided `ulid`.
///
/// The caller is responsible for generating a ULID that sorts after all
/// existing segments and WAL files (typically via `Volume::mint`).
pub(super) fn create_fresh_wal(
    wal_dir: &Path,
    ulid: Ulid,
) -> io::Result<(
    writelog::WriteLog,
    Ulid,
    PathBuf,
    Vec<segment::SegmentEntry>,
)> {
    let path = wal_dir.join(ulid.to_string());
    let wal = writelog::WriteLog::create(&path)?;
    log::info!("new WAL {ulid}");
    Ok((wal, ulid, path, Vec::new()))
}
