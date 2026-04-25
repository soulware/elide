//! Sweep / repack / delta-repack data types.
//!
//! `impl Volume` for these (`prepare_*`, `apply_*`, `repack`,
//! `sweep_pending`, `delta_repack_post_snapshot`) lives in `volume/mod.rs`
//! because it touches private fields on `Volume`.

use std::path::PathBuf;
use std::sync::Arc;

use ulid::Ulid;

use crate::{lbamap, segment, segment_cache};

/// Results from a single compaction run.
#[derive(Debug, Default)]
pub struct CompactionStats {
    /// Number of input segments consumed (deleted after compaction).
    pub segments_compacted: usize,
    /// Number of output segments written.
    pub new_segments: usize,
    /// Stored bytes reclaimed from deleted segment bodies.
    pub bytes_freed: u64,
    /// Number of dead extent entries removed from the extent index.
    pub extents_removed: usize,
}

/// Stats from a single `delta_repack_post_snapshot` pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct DeltaRepackStats {
    /// Number of post-snapshot segments inspected.
    pub segments_scanned: usize,
    /// Number of segments actually rewritten (had at least one conversion).
    pub segments_rewritten: usize,
    /// Total Data→Delta conversions across all rewritten segments.
    pub entries_converted: usize,
    /// Sum of original `stored_length` for converted entries.
    pub original_body_bytes: u64,
    /// Sum of delta blob sizes written.
    pub delta_body_bytes: u64,
}

/// Data needed by the worker to compact small / dead-bearing segments in
/// `pending/`. Produced by [`super::Volume::prepare_sweep`] on the actor thread.
///
/// `lbamap` is an `Arc` snapshot used by the worker to make liveness
/// decisions for `DedupRef` entries (`hash_at(lba)` queries). Concurrent
/// writes after prep are not visible to the worker — the apply phase
/// uses CAS on the source `(segment_id, body_offset)` pair, which makes
/// the conservative liveness snapshot safe (we may keep a now-dead hash
/// alive for one more cycle, never the reverse).
pub struct SweepJob {
    pub lbamap: Arc<lbamap::LbaMap>,
    pub floor: Option<Ulid>,
    pub pending_dir: PathBuf,
    pub signer: Arc<dyn segment::SegmentSigner>,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub segment_cache: Arc<segment_cache::SegmentIndexCache>,
}

/// A live entry carried into the swept output, paired with the CAS
/// preconditions from its source segment. Apply uses
/// `replace_if_matches(hash, source_segment_id, source_body_offset, ..)`
/// so a concurrent overwrite leaves the index untouched.
pub struct SweptLiveEntry {
    pub entry: segment::SegmentEntry,
    pub source_segment_id: Ulid,
    pub source_body_offset: u64,
}

/// A dead entry dropped by sweep, paired with the CAS preconditions from
/// its source segment. Apply uses `remove_if_matches`.
///
/// Only Data and Inline entries appear here — Zero, DedupRef, and Delta
/// entries are not in the `inner` extent index.
pub struct SweptDeadEntry {
    pub hash: blake3::Hash,
    pub source_segment_id: Ulid,
    pub source_body_offset: u64,
}

/// Result of a [`SweepJob`]. Consumed by [`super::Volume::apply_sweep_result`]
/// on the actor thread.
///
/// `new_ulid` is `None` when the merged-live set was empty (every input
/// was fully dead) — in that case the apply phase still runs the dead
/// removals and deletes the candidate files. `candidate_paths` lists the
/// inputs to evict from the file cache and unlink. The candidate whose
/// ULID equals `new_ulid` was already replaced atomically by the rename
/// inside the worker; apply must skip its `remove_file` while still
/// evicting its cached fd.
pub struct SweepResult {
    pub stats: CompactionStats,
    pub new_ulid: Option<Ulid>,
    pub new_body_section_start: u64,
    pub merged_live: Vec<SweptLiveEntry>,
    pub dead_entries: Vec<SweptDeadEntry>,
    pub candidate_paths: Vec<PathBuf>,
}

/// Data needed by the worker to repack sparse segments in `pending/`.
/// Produced by [`super::Volume::prepare_repack`] on the actor thread.
///
/// Same shape as [`SweepJob`] plus `min_live_ratio` — the worker iterates
/// every non-floor segment, recomputes liveness against the `lbamap`
/// snapshot, and rewrites (in place, reusing the input ULID) any segment
/// whose live ratio falls below the threshold.
pub struct RepackJob {
    pub lbamap: Arc<lbamap::LbaMap>,
    pub floor: Option<Ulid>,
    pub pending_dir: PathBuf,
    pub signer: Arc<dyn segment::SegmentSigner>,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub segment_cache: Arc<segment_cache::SegmentIndexCache>,
    pub min_live_ratio: f64,
}

/// A live entry carried into the repacked output, paired with the CAS
/// precondition from its source segment. Apply uses
/// `replace_if_matches(hash, seg_id, source_body_offset, ..)` — the
/// output reuses the same ULID, so only `body_offset` changes on success.
pub struct RepackedLiveEntry {
    pub entry: segment::SegmentEntry,
    pub source_body_offset: u64,
}

/// A dead entry dropped by repack, paired with the CAS precondition from
/// its source segment. Apply uses `remove_if_matches`. Only Data and
/// Inline entries appear here — Zero, DedupRef, and Delta are thin
/// entries with no extent-index slot.
pub struct RepackedDeadEntry {
    pub hash: blake3::Hash,
    pub source_body_offset: u64,
}

/// Per-segment payload from a [`RepackJob`]. One of these is produced for
/// every segment the worker rewrote or deleted.
///
/// When `all_dead_deleted` is `true`, the worker has already `remove_file`d
/// the segment; `live` is empty and `new_body_section_start` is 0. When
/// `false`, the worker renamed a fresh `.tmp` over the original file, so
/// `new_body_section_start` and the `live` entries (with post-write
/// offsets) are valid.
pub struct RepackedSegment {
    pub seg_id: Ulid,
    pub new_body_section_start: u64,
    pub live: Vec<RepackedLiveEntry>,
    pub dead: Vec<RepackedDeadEntry>,
    pub all_dead_deleted: bool,
    pub bytes_freed: u64,
}

/// Result of a [`RepackJob`]. Consumed by [`super::Volume::apply_repack_result`]
/// on the actor thread.
pub struct RepackResult {
    pub stats: CompactionStats,
    pub segments: Vec<RepackedSegment>,
}

/// Data needed by the worker to rewrite post-snapshot pending segments
/// with zstd-dictionary deltas against the prior sealed snapshot.
///
/// Produced by [`super::Volume::prepare_delta_repack`] on the actor thread.
///
/// `snap_ulid` is the latest sealed snapshot: only segments with a
/// strictly greater ULID are rewritten; the snapshot itself is frozen.
/// The worker constructs a snapshot-pinned `BlockReader` from
/// `base_dir` + `snap_ulid` — kept off the actor so the manifest /
/// provenance / extent-index rebuild runs on the worker thread.
pub struct DeltaRepackJob {
    pub base_dir: PathBuf,
    pub pending_dir: PathBuf,
    pub snap_ulid: Ulid,
    pub signer: Arc<dyn segment::SegmentSigner>,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub segment_cache: Arc<segment_cache::SegmentIndexCache>,
}

/// Per-segment payload from a [`DeltaRepackJob`]. One of these is
/// produced for every segment the worker actually rewrote
/// (segments that had no convertible entries are skipped).
pub struct DeltaRepackedSegment {
    pub seg_id: Ulid,
    pub rewrite: crate::delta_compute::RewrittenSegment,
}

/// Result of a [`DeltaRepackJob`]. Consumed by
/// [`super::Volume::apply_delta_repack_result`] on the actor thread.
pub struct DeltaRepackResult {
    pub stats: DeltaRepackStats,
    pub segments: Vec<DeltaRepackedSegment>,
}
