//! Extent-reclamation data types and the candidate scanner.
//!
//! `impl Volume` for reclaim (`prepare_reclaim`, `apply_reclaim_result`,
//! `reclaim_alias_merge`) lives in `volume/mod.rs` because it touches
//! private fields on `Volume`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use ulid::Ulid;

use crate::{extentindex, lbamap, segment};

use super::ZERO_HASH;

/// Data needed by the worker to execute extent reclamation off-actor.
///
/// Produced by [`super::Volume::prepare_reclaim`] on the actor thread. The heavy
/// middle phase — reading live bytes for each bloated run, re-hashing,
/// compressing, and assembling one segment file — runs on the worker
/// thread via [`crate::actor::execute_reclaim`]. The actor reclaims no
/// lock during that window; writes continue to flow through the channel.
///
/// `lbamap_snapshot` is kept private on the carried `ReclaimResult`: the
/// pointer identity is the entire precondition check, and exposing it
/// would invite accidental aliasing that weakens the guarantee.
pub struct ReclaimJob {
    pub target_start_lba: u64,
    pub target_lba_length: u32,
    pub entries: Vec<lbamap::ExtentRead>,
    pub lbamap_snapshot: Arc<lbamap::LbaMap>,
    pub extent_index_snapshot: Arc<extentindex::ExtentIndex>,
    pub search_dirs: Vec<PathBuf>,
    pub pending_dir: PathBuf,
    /// Pre-minted on the actor so the worker can write
    /// `pending/<segment_ulid>` without needing access to the mint.
    pub segment_ulid: Ulid,
    pub signer: Arc<dyn segment::SegmentSigner>,
    /// Latest sealed snapshot ULID for this fork at prepare time, or
    /// `None` if no snapshots exist. A hash whose segment is `<=` this
    /// floor lives in a snapshot-pinned segment and cannot be dropped
    /// for the lifetime of the snapshot — reclaim treats that as
    /// indefinite retention and prefers a thin Delta output over a
    /// fresh body (the body is already permanent either way).
    pub snapshot_floor_ulid: Option<Ulid>,
}

/// A rewritten entry placed in the reclaim output segment, paired with
/// the uncompressed byte count it represents (so outcome accounting
/// reflects logical size rather than stored length after compression).
pub struct ReclaimedEntry {
    pub entry: segment::SegmentEntry,
    pub uncompressed_bytes: u64,
}

/// Result of a [`ReclaimJob`]. Consumed by [`super::Volume::apply_reclaim_result`]
/// on the actor thread.
///
/// `segment_written` distinguishes the "nothing to do" case (empty
/// proposal set, no file on disk) from the "worker committed a segment"
/// case. Apply must either splice the entries into the live lbamap +
/// extent index (pointer-equality precondition holds) or delete
/// `pending/<segment_ulid>` as an orphan (precondition failed).
pub struct ReclaimResult {
    pub lbamap_snapshot: Arc<lbamap::LbaMap>,
    pub segment_ulid: Ulid,
    pub body_section_start: u64,
    /// Sum of `stored_length` for body-section entries in the written
    /// segment. Needed by apply to build
    /// [`extentindex::DeltaBodySource::Full`] for any Delta outputs, whose
    /// delta blobs live at `body_section_start + body_length` in the
    /// pending file.
    pub body_length: u64,
    pub entries: Vec<ReclaimedEntry>,
    pub segment_written: bool,
    pub pending_dir: PathBuf,
}

/// Outcome of a complete alias-merge reclaim pass.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReclaimOutcome {
    /// True if the apply precondition failed (the LBA map was mutated
    /// between prepare and apply) and nothing was committed.
    pub discarded: bool,
    /// Number of rewrite entries committed (excluding ones the noop-skip
    /// hash check absorbed because the LBA map already records the rewrite).
    pub runs_rewritten: u32,
    /// Total uncompressed bytes committed to fresh compact entries.
    pub bytes_rewritten: u64,
}

/// Per-hash thresholds controlling which hashes the reclamation scanner
/// proposes as worth rewriting. All defaults are placeholders pending
/// empirical tuning on real aged volumes — see the open questions in
/// `docs/design-extent-reclamation.md § Measurement before mechanism`.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimThresholds {
    /// Minimum number of 4K blocks detectably dead inside a hash's stored
    /// payload before the hash is a candidate. Small waste isn't worth the
    /// rewrite cost.
    pub min_dead_blocks: u32,
    /// Minimum `dead / total` ratio. `payload_block_offset` aliasing
    /// already serves reads without decompress-to-discard below this
    /// ratio, so rewriting is pure write amplification.
    pub min_dead_ratio: f64,
    /// Minimum stored body size. Rewriting a tiny entry amortises badly
    /// over the WAL-append + extent_index-update overhead.
    pub min_stored_bytes: u64,
}

impl Default for ReclaimThresholds {
    fn default() -> Self {
        Self {
            min_dead_blocks: 8,
            min_dead_ratio: 0.3,
            min_stored_bytes: 64 * 1024,
        }
    }
}

/// A single reclamation candidate identified by the scanner. The caller
/// passes `(start_lba, lba_length)` to
/// [`crate::actor::VolumeClient::reclaim_alias_merge`].
///
/// The range is chosen to tightly cover every LBA map run for this
/// hash. The primitive's containment check therefore always succeeds
/// for this hash — but the range may also sweep in other, unrelated
/// hashes that happen to sit between this hash's runs; those are left
/// alone by the primitive's own per-hash containment check.
#[derive(Debug, Clone, Copy)]
pub struct ReclaimCandidate {
    pub start_lba: u64,
    pub lba_length: u32,
    /// Detectable dead block count for this hash's stored payload.
    pub dead_blocks: u32,
    /// Sum of live block lengths across all runs that reference this hash.
    pub live_blocks: u32,
    /// Stored body length in bytes (compressed if the payload was compressed).
    pub stored_bytes: u64,
    /// `true` if the stored payload is compressed and the dead count is
    /// a lower bound rather than exact (we can't know trailing-dead bytes
    /// inside a compressed payload without decompressing).
    pub dead_count_is_lower_bound: bool,
}

/// Walk the LBA map, fold per-hash run lists, and emit reclamation
/// candidates that clear all three thresholds in `ReclaimThresholds`.
///
/// The scanner is read-only and takes `&LbaMap` / `&ExtentIndex` so it
/// can run on a [`crate::actor::VolumeClient`] snapshot without any
/// actor round-trip. Returned candidates are sorted by `dead_blocks`
/// descending (the most wasteful rewrites first).
///
/// **Dead-block detection:** for each hash H we compute `live_blocks =
/// sum(run.length)` and `max_payload_end = max(run.offset + run.length)`
/// across all runs. For uncompressed payloads the exact logical length
/// is `body_length / 4096` and `dead_blocks = logical_length -
/// live_blocks`. For compressed payloads and thin Delta entries the
/// exact logical length is unknown without decompressing, so we use
/// `max_payload_end - live_blocks` — a lower bound that never produces
/// false positives but may miss dead bytes past the last observed run.
///
/// Zero-extents, Inline entries, and hashes absent from both the Data
/// and Delta tables are skipped.
pub fn scan_reclaim_candidates(
    lbamap: &lbamap::LbaMap,
    extent_index: &extentindex::ExtentIndex,
    thresholds: ReclaimThresholds,
) -> Vec<ReclaimCandidate> {
    // Per-hash aggregate: (min_lba, max_lba_end, sum_live_blocks, max_offset_end)
    #[derive(Clone, Copy)]
    struct HashAgg {
        min_lba: u64,
        max_lba_end: u64,
        live_blocks: u64,
        max_offset_end: u64,
    }

    let mut per_hash: HashMap<blake3::Hash, HashAgg> = HashMap::new();
    for (lba, length, hash, offset) in lbamap.iter_entries() {
        if hash == ZERO_HASH {
            continue;
        }
        let lba_end = lba + length as u64;
        let offset_end = offset as u64 + length as u64;
        per_hash
            .entry(hash)
            .and_modify(|agg| {
                if lba < agg.min_lba {
                    agg.min_lba = lba;
                }
                if lba_end > agg.max_lba_end {
                    agg.max_lba_end = lba_end;
                }
                agg.live_blocks += length as u64;
                if offset_end > agg.max_offset_end {
                    agg.max_offset_end = offset_end;
                }
            })
            .or_insert(HashAgg {
                min_lba: lba,
                max_lba_end: lba_end,
                live_blocks: length as u64,
                max_offset_end: offset_end,
            });
    }

    let mut candidates = Vec::new();
    for (hash, agg) in &per_hash {
        // Resolve the hash as either a Data/Inline or Delta entry.
        // Determines how we bound logical body size and what counts as
        // stored bytes for the `min_stored_bytes` threshold.
        //
        // Returns:
        // - `logical_blocks`: upper/exact bound on the payload's
        //   logical size in 4 KiB blocks.
        // - `is_lower_bound`: true when `logical_blocks` is a lower
        //   bound (compressed Data, Delta), false when exact.
        // - `stored_bytes`: bytes on disk that rewriting would
        //   orphan — body_length for Data, decompressed-size estimate
        //   for Delta.
        let (logical_blocks, is_lower_bound, stored_bytes) =
            if let Some(loc) = extent_index.lookup(hash) {
                // Inline entries are small by construction and do not
                // benefit from compaction — their bytes live in the
                // .idx, not the body section.
                if loc.inline_data.is_some() {
                    continue;
                }
                if loc.compressed {
                    (agg.max_offset_end, true, loc.body_length as u64)
                } else {
                    (loc.body_length as u64 / 4096, false, loc.body_length as u64)
                }
            } else if extent_index.lookup_delta(hash).is_some() {
                // Delta-backed: the logical fragment size is not
                // recorded on disk (the Delta entry's stored_length
                // is zero — the delta blob is accessed via the
                // separate delta body section). Use `max_offset_end`
                // as a lower bound and approximate stored_bytes as
                // the implied logical body size. Catches middle
                // splits; misses pure tail overwrites of a Delta
                // fragment (rare — Delta fragments are emitted at
                // import or post-snapshot delta-repack, and partial
                // overwrites of their tail specifically are atypical).
                (agg.max_offset_end, true, agg.max_offset_end * 4096)
            } else {
                continue;
            };

        if logical_blocks < agg.live_blocks {
            // Can happen for compressed/delta payloads when the lower
            // bound underestimates — treat as "no detectable bloat".
            continue;
        }
        let dead_blocks = logical_blocks - agg.live_blocks;
        if dead_blocks < u64::from(thresholds.min_dead_blocks) {
            continue;
        }
        if stored_bytes < thresholds.min_stored_bytes {
            continue;
        }
        let dead_ratio = dead_blocks as f64 / logical_blocks as f64;
        if dead_ratio < thresholds.min_dead_ratio {
            continue;
        }
        let lba_length = agg.max_lba_end - agg.min_lba;
        if lba_length > u32::MAX as u64 {
            // Pathological: wouldn't fit in a single reclaim call. Skip.
            continue;
        }
        candidates.push(ReclaimCandidate {
            start_lba: agg.min_lba,
            lba_length: lba_length as u32,
            dead_blocks: dead_blocks.min(u32::MAX as u64) as u32,
            live_blocks: agg.live_blocks.min(u32::MAX as u64) as u32,
            stored_bytes,
            dead_count_is_lower_bound: is_lower_bound,
        });
    }

    candidates.sort_unstable_by(|a, b| b.dead_blocks.cmp(&a.dead_blocks));
    candidates
}
