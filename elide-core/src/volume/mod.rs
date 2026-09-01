// Volume: top-level I/O interface — owns the LBA map, WAL, and directory layout.
//
// Directory layout:
//   <base>/wal/       — active write-ahead log (at most one file at a time)
//   <base>/pending/   — promoted segments awaiting S3 upload
//   <base>/index/     — coordinator-written LBA index files (*.idx); permanent; never evicted
//   <base>/cache/     — coordinator-written body cache (*.body, *.present); evictable
//   <base>/gc/        — GC handoff files (coordinator-written `.staged`, volume-
//                       applied bare `<ulid>`; see docs/design/gc-self-describing-handoff.md)
//
// Write path:
//   1. Volume::write(lba, data) — hashes data, appends to WAL, updates LBA map
//      and extent index (WAL offset as temporary location)
//   2. When the WAL reaches FLUSH_THRESHOLD, it is promoted to a clean segment
//      in pending/ and the extent index is updated to segment offsets
//
// Read path:
//   1. lbamap.lookup(lba) → (hash, block_offset)
//   2. extent_index.lookup(hash) → ExtentLocation (segment_id, body_offset, body_length)
//   3. find_segment_file (wal/ → pending/ → bare gc/<id> → cache/<id>.body) → open file, seek, read
//
// Recovery:
//   Volume::open() calls lbamap::rebuild_segments() (segments only), then
//   scans the WAL once: that single pass truncates any partial-tail record,
//   replays entries into the LBA map, extent index, and pending writes.
//   Any .tmp files in pending/ are removed (incomplete promotions).

use std::borrow::Cow;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub use segment::BoxFetcher;

use ulid::Ulid;

use crate::{
    blake3_id_hasher::Blake3HashSet,
    extentindex::{self, BodySource},
    lbamap::{self, LbaMap},
    map_layers::{MapLayers, Maps},
    rewrite_plan,
    segment::{self, EntryKind},
    segment_cache,
    ulid_mint::UlidMint,
    writelog,
};

mod ancestry;
mod compress;
mod fork;
mod jobs;
mod open_state;
mod read;
mod readonly;
mod reap;
mod reclaim;
mod repack;
mod wal;

pub use ancestry::{
    latest_snapshot, lineage_ulids, parse_lineage_pair, resolve_ancestor_dir,
    verify_ancestor_manifests, walk_ancestors, walk_extent_ancestors,
};
#[cfg(test)]
pub(in crate::volume) use compress::{MIN_COMPRESSION_RATIO_DEN, MIN_COMPRESSION_RATIO_NUM};
pub(crate) use compress::{compress_body, maybe_compress};
pub use fork::{fork_volume, fork_volume_at};
use jobs::GcCheckpointUlids;
pub use jobs::{
    GcCheckpointPrep, GcPlanApplyJob, GcPlanApplyResult, JournalPartition, JournalSegmentResult,
    PendingPartition, PromoteDeltaPrior, PromoteFailure, PromoteJob, PromoteResult,
    PromoteSegmentJob, PromoteSegmentPrep, PromoteSegmentResult, SignSnapshotManifestJob,
    SignSnapshotManifestResult, WorkerJob, WorkerResult,
};
use open_state::open_read_state;
#[cfg(test)]
pub(in crate::volume) use read::SegmentLayout;
pub use read::{DmatCache, FILE_CACHE_CAPACITY, ReadStats, ReadStatsSnapshot};
pub(crate) use read::{
    SharedFileCache, find_segment_in_dirs, lock_file_cache, open_delta_body_in_dirs, read_extents,
};
pub use readonly::ReadonlyVolume;
pub use reap::{
    BodyBytes, ReapCandidate, ReapSegment, ReapStats, Sweep, list_open_segments,
    parse_reap_candidates, sweep_unreachable,
};
pub use reclaim::{
    ReclaimCandidate, ReclaimJob, ReclaimOutcome, ReclaimPrep, ReclaimResult, ReclaimThresholds,
    ReclaimedEntry, scan_reclaim_candidates,
};
pub use repack::{
    CloseGenerationPrep, CompactionStats, RepackApply, RepackJob, RepackResult, RepackedBucket,
    RepackedInput, RepackedOutput, unlink_consumed_inputs,
};
use wal::{create_fresh_wal, recover_wal, replay_wal_records};

/// WAL size (bytes) at which the log is promoted to a pending segment.
/// This is a soft cap: a single write larger than this threshold will still
/// succeed, producing a segment larger than intended. The block layer
/// (ublk) enforces its own per-request maximum before reaching here.
const FLUSH_THRESHOLD: u64 = 32 * 1024 * 1024;

/// Entry-count cap at which the WAL is promoted, regardless of byte size.
/// Bounds the per-segment index region for workloads that produce many
/// thin entries (DedupRef, Zero, Inline) without advancing the byte cap.
/// Matches a 4 KiB-block 32 MiB segment exactly (32 MiB / 4 KiB = 8192).
const FLUSH_ENTRY_THRESHOLD: usize = 8192;

/// Maximum byte length of a single write. The segment format stores
/// `body_length` as a `u32`, so payloads must fit in 4 GiB. We cap at
/// `u32::MAX` rounded down to a 4 KiB boundary.
const MAX_WRITE_SIZE: usize = (u32::MAX as usize / 4096) * 4096;

/// Reject zero-length, non-block-aligned, and oversize writes early so the
/// rest of the write path can assume a sane payload.
fn validate_write_size(data: &[u8]) -> io::Result<()> {
    if data.is_empty() || !data.len().is_multiple_of(4096) {
        return Err(io::Error::other(
            "data length must be a non-zero multiple of 4096",
        ));
    }
    if data.len() > MAX_WRITE_SIZE {
        return Err(io::Error::other(
            "data length exceeds maximum write size (4 GiB − 4 KiB)",
        ));
    }
    Ok(())
}

/// Sentinel hash used in the LBA map and segment entries to represent an
/// explicitly-zeroed LBA range. All-zero bytes cannot be a valid BLAKE3 output
/// for any non-trivial input; finding a preimage would require breaking 256-bit
/// hash preimage resistance.
pub const ZERO_HASH: blake3::Hash = blake3::Hash::from_bytes([0u8; 32]);

/// Default capacity for the parsed segment-index LRU cache. Each cached
/// entry holds `Vec<SegmentEntry>` for one segment (a few tens of KiB
/// for a 32 MiB segment); 64 entries comfortably covers the working set
/// for sweep/repack/delta_repack/promote passes without unbounded
/// memory growth on large volumes.
const SEGMENT_INDEX_CACHE_CAPACITY: usize = 64;

/// How many diverging LBAs `assert_lbamap_consistent` names before it
/// stops looking. Enough to show whether a drift is one LBA or a whole
/// claimed range, which is the distinction that identifies its cause.
const DIVERGENCE_REPORT_CAP: usize = 8;

/// Replay every WAL's records into `fresh`, lowest ULID first, each
/// record overriding whatever holds its LBA.
///
/// A WAL's ULID is the moment it was created, and it collects records
/// for as long as it stays open, so a record in it can be newer than a
/// segment whose ULID is higher. `prepare_close_generation` mints its
/// output ULIDs above the generation it seals without rotating the WAL,
/// so the running WAL sits below segments holding older content and
/// governs the window until the apply. Ranking the ULIDs hands those
/// LBAs to the segment and loses the writes, so a record overrides
/// unconditionally and the sort orders the WALs among themselves.
///
/// `Volume::open` reaches the same winners by a different construction:
/// it promotes every WAL but the newest into a segment and applies those
/// entries under the segment's own ULID, leaving one WAL to replay. The
/// sort here covers the runtime call sites, where a promote in flight
/// leaves its WAL on disk beside the fresh one taking writes.
fn replay_wals_into(mut wals: Vec<(Ulid, PathBuf)>, fresh: &mut LbaMap) {
    wals.sort_by_key(|(ulid, _)| *ulid);
    for (wal_ulid, path) in wals {
        let Ok((records, _)) = writelog::scan_readonly(&path) else {
            continue;
        };
        for record in records {
            match record {
                writelog::LogRecord::Data {
                    hash,
                    start_lba,
                    lba_length,
                    ..
                }
                | writelog::LogRecord::Ref {
                    hash,
                    start_lba,
                    lba_length,
                } => {
                    fresh.insert(start_lba, lba_length, hash, wal_ulid);
                }
                writelog::LogRecord::Zero {
                    start_lba,
                    lba_length,
                } => {
                    fresh.insert(start_lba, lba_length, ZERO_HASH, wal_ulid);
                }
            }
        }
    }
}

/// One LBA where the in-memory map and the on-disk projection disagree,
/// on the content stored there or on which segment claims it.
struct Diverge {
    lba: u64,
    mem_hash: Option<blake3::Hash>,
    disk_hash: Option<blake3::Hash>,
    mem_claimant: Option<Ulid>,
    disk_claimant: Option<Ulid>,
}

/// A segment entry whose stored bytes are still in the WAL, travelling with the
/// location of those bytes until [`materialise_pending_bodies`] reunites them.
pub struct PendingWrite {
    pub entry: segment::SegmentEntry,
    /// Where the entry's stored bytes live in the WAL, spanning
    /// `off..off + entry.stored_length`. `Some` for the body-bearing kinds
    /// (Data, Inline).
    pub wal_body_offset: Option<u64>,
}

/// Pair each pending write with its stored bytes pread from `wal_path`,
/// producing the build-form [`segment::PendingEntry`]s a segment write
/// consumes. Inline-kind bytes land on `entry.inline`; Data bytes ride
/// as the pending body.
///
/// Formation is where a body changes codec. The WAL holds lz4 because its
/// cost is guest write latency; a segment body holds what
/// [`compress_body`] chooses because its cost is upload bytes. Inline bytes
/// keep the WAL's form: under roughly a kilobyte a zstd frame header costs
/// more than its coding saves.
pub(crate) fn materialise_pending_bodies(
    wal_path: &Path,
    writes: &[PendingWrite],
) -> io::Result<Vec<segment::PendingEntry>> {
    use std::os::unix::fs::FileExt;
    let f = if writes.iter().any(|w| w.wal_body_offset.is_some()) {
        Some(fs::File::open(wal_path)?)
    } else {
        None
    };
    let mut out = Vec::with_capacity(writes.len());
    for write in writes {
        let mut entry = write.entry.clone();
        let mut body = None;
        if let (Some(off), Some(f)) = (write.wal_body_offset, &f) {
            let mut buf = vec![0u8; entry.stored_length as usize];
            f.read_exact_at(&mut buf, off)?;
            if entry.kind.is_inline() {
                entry.inline = Some(buf.into_boxed_slice());
            } else {
                let plain = entry.codec.decode(Cow::Owned(buf))?.into_owned();
                let (codec, stored) = match compress_body(&plain, entry.journal)? {
                    Some(pair) => pair,
                    None => (segment::Codec::None, plain),
                };
                entry.codec = codec;
                entry.stored_length = stored.len() as u32;
                body = Some(stored);
            }
        }
        out.push(segment::PendingEntry { entry, body });
    }
    Ok(out)
}

/// Snapshot the CAS precondition tokens for a promote: the `body_offset`
/// each body-bearing entry currently has in the extent index. These gate
/// the apply loop in [`apply_promoted_entries`] — an entry is only
/// rewritten if it still points at `(wal_ulid, snapshotted_offset)`.
fn snapshot_pre_promote_offsets(
    writes: &[PendingWrite],
    extent_index: &extentindex::ExtentIndex,
) -> Vec<Option<u64>> {
    writes
        .iter()
        .map(|w| match w.entry.kind {
            EntryKind::Data
            | EntryKind::Inline
            | EntryKind::CanonicalData
            | EntryKind::CanonicalInline => extent_index
                .lookup(&w.entry.hash)
                .map(|loc| loc.body_offset),
            EntryKind::DedupRef
            | EntryKind::Zero
            | EntryKind::Delta
            | EntryKind::CanonicalDelta => None,
        })
        .collect()
}

/// Classify pending entries at segment formation: a `Data` or `Inline`
/// entry whose hash resolves in the extent index to a body other than its
/// own WAL record — a canonical in a committed or ancestor segment, or an
/// earlier write of the same bytes in this WAL epoch — becomes a thin
/// `DedupRef`, and its WAL body bytes are dropped at the segment write.
/// Inline-sized duplicates dedup like any other: a DedupRef costs zero
/// bytes where an Inline entry would put its body in the `.idx`.
///
/// Returns the counters for this formation.
fn classify_pending_dedup_entries(
    writes: &mut [PendingWrite],
    extent_index: &extentindex::ExtentIndex,
    wal_ulid: Ulid,
) -> DedupMintStats {
    let mut stats = DedupMintStats::default();
    for write in writes.iter_mut() {
        if !matches!(write.entry.kind, EntryKind::Data | EntryKind::Inline) {
            continue;
        }
        // Journal-tier entries are stored as-is: they stay out of the deduped
        // map, so durable and journal content keep separate bodies and a
        // journal segment reaps whole.
        if write.entry.journal {
            continue;
        }
        let Some(loc) = extent_index.lookup(&write.entry.hash) else {
            continue;
        };
        if loc.segment_id == wal_ulid && Some(loc.body_offset) == write.wal_body_offset {
            continue;
        }
        stats.minted_entries += 1;
        stats.wal_body_bytes += write.entry.stored_length as u64;
        write.entry = segment::SegmentEntry::new_dedup_ref(
            write.entry.hash,
            write.entry.start_lba,
            write.entry.lba_length,
        );
        write.wal_body_offset = None;
    }
    stats
}

/// Stage one WAL epoch's pending writes for promotion: mint dedup refs against
/// the extent index, take the CAS precondition tokens, then split the
/// journal-window share off into its own segment.
///
/// The three steps are ordered. The token snapshot keys off entry kinds, so
/// classification runs first and a converted entry reads as a DedupRef by the
/// time its token is taken; the split then permutes positions, with every token
/// already paired to its write. Taking the tokens here also puts them ahead of
/// `segment::write_and_commit` rewriting `stored_offset` to segment-relative.
///
/// `mint` yields the journal segment's ULID, so callers mint the primary
/// segment's ULID first.
fn stage_pending_for_promote(
    mut writes: Vec<PendingWrite>,
    extent_index: &extentindex::ExtentIndex,
    wal_ulid: Ulid,
    journal_ranges: &crate::journal::JournalRanges,
    mint: &mut UlidMint,
) -> (PendingPartition, Option<JournalPartition>, DedupMintStats) {
    let dedup = classify_pending_dedup_entries(&mut writes, extent_index, wal_ulid);
    let pre_promote_offsets = snapshot_pre_promote_offsets(&writes, extent_index);
    let (primary, journal) =
        PendingPartition::new(writes, pre_promote_offsets).split_journal(journal_ranges);
    let journal = journal.map(|partition| JournalPartition {
        segment_ulid: mint.next(),
        partition,
    });
    (primary, journal, dedup)
}

/// Apply a committed promote to the in-memory maps: CAS each body-bearing
/// entry in the extent index from its WAL-relative location to the new
/// segment (skipping entries a concurrent write or GC handoff has
/// superseded), register formation-minted Delta entries, bump lbamap
/// claimants from the WAL ULID to the segment ULID, and log the entry
/// counts. Applies the primary partition, then the journal segment when
/// present.
fn apply_promoted_entries(
    extent_index: &mut extentindex::ExtentIndex,
    lbamap: &mut lbamap::LbaMap,
    result: &PromoteResult,
) -> io::Result<()> {
    apply_promoted_partition(
        extent_index,
        lbamap,
        result.old_wal_ulid,
        ApplyPartition {
            segment_ulid: result.segment_ulid,
            body_section_start: result.body_section_start,
            delta_region_body_length: result.delta_region_body_length,
            entries: &result.entries,
            pre_promote_offsets: &result.pre_promote_offsets,
            journal_segment: false,
        },
    )?;
    if let Some(j) = &result.journal {
        apply_promoted_partition(
            extent_index,
            lbamap,
            result.old_wal_ulid,
            ApplyPartition {
                segment_ulid: j.segment_ulid,
                body_section_start: j.body_section_start,
                delta_region_body_length: 0,
                entries: &j.entries,
                pre_promote_offsets: &j.pre_promote_offsets,
                journal_segment: true,
            },
        )?;
    }
    Ok(())
}

/// One destination segment's share of a promote apply.
struct ApplyPartition<'a> {
    segment_ulid: Ulid,
    body_section_start: u64,
    delta_region_body_length: u64,
    entries: &'a [segment::SegmentEntry],
    pre_promote_offsets: &'a [Option<u64>],
    /// Marks the journal segment's flush log line.
    journal_segment: bool,
}

fn apply_promoted_partition(
    extent_index: &mut extentindex::ExtentIndex,
    lbamap: &mut lbamap::LbaMap,
    old_wal_ulid: Ulid,
    part: ApplyPartition<'_>,
) -> io::Result<()> {
    let ApplyPartition {
        segment_ulid,
        body_section_start,
        delta_region_body_length,
        entries,
        pre_promote_offsets,
        journal_segment,
    } = part;
    let delta_ctx = extentindex::SegmentRegistrationCtx {
        segment_id: segment_ulid,
        body_section_start,
        body_tier: extentindex::RegistrationBodyTier::Local,
        delta_body_source: Some(extentindex::DeltaBodySource::Full {
            body_section_start,
            body_length: delta_region_body_length,
        }),
        inline: extentindex::InlineSource::EntryInline,
    };
    let consumed: std::collections::HashSet<Ulid> = std::iter::once(old_wal_ulid).collect();
    for (raw_idx, (entry, old_wal_offset)) in entries
        .iter()
        .zip(pre_promote_offsets.iter().copied())
        .enumerate()
    {
        match entry.kind {
            EntryKind::Data
            | EntryKind::Inline
            | EntryKind::CanonicalData
            | EntryKind::CanonicalInline
            | EntryKind::CanonicalDelta => {}
            // A Delta with a CAS token was a Data entry at prep time that
            // the worker's delta tier converted: drop the WAL-pointing
            // DATA location, then register the Delta as the disk rebuild
            // would. The removal is gated on the WAL still owning the
            // hash, and the registration's admission on no other segment
            // having taken it — a concurrent writer wins both. A Delta
            // without a token never had a body location. The delta's
            // source dependency rides the delta-source records:
            // liveness reaches it through
            // `ExtentIndex::named_delta_sources`, keyed by hash, so no
            // per-claim attachment happens here.
            EntryKind::Delta => {
                if let Some(old_wal_offset) = old_wal_offset {
                    extent_index.remove_if_matches(&entry.hash, old_wal_ulid, old_wal_offset);
                    extent_index.register_entry_consuming_inputs(
                        entry,
                        raw_idx as u32,
                        &delta_ctx,
                        &consumed,
                    )?;
                }
                continue;
            }
            EntryKind::DedupRef | EntryKind::Zero => continue,
        }
        let idata = if entry.kind.is_inline() {
            entry.inline.clone()
        } else {
            None
        };
        // Journal-tier entries live in the disjoint `(segment, hash)` map,
        // keyed at write time under the WAL ULID. Move the body to the
        // segment key. No body-offset CAS: the key is specific to this
        // volume's promote, and journal writes are serialised through the WAL.
        if entry.journal {
            extent_index.rekey_journal(
                old_wal_ulid,
                segment_ulid,
                entry.hash,
                extentindex::ExtentLocation {
                    segment_id: segment_ulid,
                    body_offset: entry.stored_offset,
                    body_length: entry.stored_length,
                    codec: entry.codec,
                    body_source: BodySource::Local,
                    body_section_start,
                    inline_data: idata,
                },
            );
            continue;
        }
        let Some(old_wal_offset) = old_wal_offset else {
            // No prior extent index entry for this hash. write_commit
            // always inserts a Data/Inline hash before pushing the
            // SegmentEntry, so this is only possible if something
            // removed the entry out-of-band between the write and the
            // flush — treat it like a failed CAS and leave it alone.
            continue;
        };
        extent_index.replace_if_matches(
            entry.hash,
            old_wal_ulid,
            old_wal_offset,
            extentindex::ExtentLocation {
                segment_id: segment_ulid,
                body_offset: entry.stored_offset,
                body_length: entry.stored_length,
                codec: entry.codec,
                body_source: BodySource::Local,
                body_section_start,
                inline_data: idata,
            },
        );
    }
    // Bump lbamap claimants for every entry that still represents this
    // WAL's claim — every non-canonical entry, including DedupRef and
    // Zero (which have no extent_index entry but do hold an lbamap
    // claim). The strict-newer guard inside `set_claimant_if_matches`
    // skips entries a concurrent writer has already re-claimed at a
    // higher ULID.
    for entry in entries {
        if entry.kind.is_canonical_only() {
            continue;
        }
        let claim_hash = if entry.kind == EntryKind::Zero {
            ZERO_HASH
        } else {
            entry.hash
        };
        lbamap.set_claimant_if_matches(entry.start_lba, entry.lba_length, claim_hash, segment_ulid);
    }
    let (mut data, mut refs, mut zero, mut inline, mut delta, mut canonical) =
        (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    for e in entries {
        match e.kind {
            EntryKind::Data => data += 1,
            EntryKind::DedupRef => refs += 1,
            EntryKind::Zero => zero += 1,
            EntryKind::Inline => inline += 1,
            EntryKind::Delta => delta += 1,
            EntryKind::CanonicalData | EntryKind::CanonicalInline | EntryKind::CanonicalDelta => {
                canonical += 1
            }
        }
    }
    let _ = canonical;
    log::info!(
        "flush {segment_ulid}{} (from WAL {old_wal_ulid}): {data} data, {inline} inline, \
         {refs} dedup-ref, {zero} zero, {delta} delta ({} entries total)",
        if journal_segment { " [journal]" } else { "" },
        entries.len()
    );
    Ok(())
}

/// How many `(lba, hash)` pairs a resolvability refusal names in its log
/// line. The count it reports is separate and unbounded.
pub(in crate::volume) const REFUSAL_SAMPLE_LIMIT: usize = 8;

/// A fold refused because the plan disagreed with the live map about an
/// LBA. `SUPERSEDED_CARRY` is the plan claiming one it should not,
/// `DROPPED_CLAIM` one it should have carried.
const SUPERSEDED_CARRY: &str = "superseded_carry";
const DROPPED_CLAIM: &str = "dropped_claim";

/// Machine-readable identity for a refusal, appended to its ERROR line.
///
/// Two refusals name the same fault iff `refusal`, `held_by` and
/// `anchor_lba` all match, which is what lets recurrence be correlated
/// from the tick log with nothing retained across ticks.
///
/// Reading it: the same three recurring across ticks means the
/// coordinator's disk-derived view and the volume's live map disagree
/// about that LBA in a way that survives re-deriving, so the volume
/// should be run under `ELIDE_VOLUME_INVARIANTS=1` for
/// `assert_lbamap_consistent` to name the divergence. A fresh anchor is a
/// separate fault and starts its own correlation.
///
/// Correlate over a window of ticks. A fold trips this where GC selects a
/// bucket touching that LBA, and `select_buckets` ranks its candidates
/// and caps how many it takes, so a quiet tick is as readily a selection
/// that went elsewhere as a fault that healed.
///
/// `held_by` is the segment holding the disputed claim, which no refused
/// fold can move, so it survives the re-bucketing between passes that
/// makes the input set unstable. `runs` and `blocks` say whether the
/// fault is growing. The plan ULID is minted per pass and identifies
/// nothing across ticks, so it stays in the prose.
///
/// `None` when `runs` is empty, which is the no-refusal case.
fn refusal_identity(kind: &str, runs: &[(u64, u64, Ulid)], inputs: usize) -> Option<String> {
    // Iteration order over `runs` follows the inputs' index order and so
    // shifts with bucket composition. The minimum names the same LBA
    // whatever order they arrive in.
    let (anchor_lba, _, held_by) = runs.iter().min_by_key(|(from, _, _)| *from)?;
    let blocks: u64 = runs.iter().map(|(from, to, _)| to - from).sum();
    Some(format!(
        "refusal={kind} held_by={held_by} anchor_lba={anchor_lba} runs={} blocks={blocks} \
         inputs={inputs}",
        runs.len(),
    ))
}

/// Disjoint half-open LBA ranges, ascending, for coverage queries.
pub(in crate::volume) struct LbaRanges(Vec<(u64, u64)>);

impl LbaRanges {
    /// The union of the LBA ranges `entries` stakes a claim over.
    /// Canonical-only kinds carry a body for dedup resolution and claim
    /// nothing, so they contribute no range.
    pub(in crate::volume) fn from_claims(entries: &[segment::SegmentEntry]) -> Self {
        Self::new(Self::claim_ranges(entries))
    }

    /// The union of the claim ranges of `entries` and the `(start_lba,
    /// lba_length)` pairs in `ranges`.
    pub(in crate::volume) fn from_claims_and_ranges(
        entries: &[segment::SegmentEntry],
        ranges: impl IntoIterator<Item = (u64, u32)>,
    ) -> Self {
        Self::new(
            Self::claim_ranges(entries).chain(ranges.into_iter().map(|(s, l)| (s, s + l as u64))),
        )
    }

    fn claim_ranges(entries: &[segment::SegmentEntry]) -> impl Iterator<Item = (u64, u64)> + '_ {
        entries
            .iter()
            .filter(|e| !e.kind.is_canonical_only())
            .map(|e| (e.start_lba, e.start_lba + e.lba_length as u64))
    }

    /// Sort and coalesce `ranges`. Empty ranges cover nothing and are
    /// dropped, which keeps [`Self::next_start_after`] on a range that
    /// can hold `cursor` back.
    pub(in crate::volume) fn new(ranges: impl IntoIterator<Item = (u64, u64)>) -> Self {
        let mut ranges: Vec<(u64, u64)> = ranges.into_iter().filter(|(s, e)| s < e).collect();
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Self(merged)
    }

    /// The first sub-range of `[start, end)` this set leaves uncovered.
    fn first_gap_in(&self, start: u64, end: u64) -> Option<(u64, u64)> {
        let mut cursor = start;
        // The predecessor is the only range that can cover `cursor` from
        // below, and each subsequent range starts at or after it.
        let from = self.0.partition_point(|(s, _)| *s <= cursor);
        for (s, e) in &self.0[from.saturating_sub(1)..] {
            if *s > cursor {
                break;
            }
            cursor = cursor.max(*e);
            if cursor >= end {
                return None;
            }
        }
        (cursor < end).then_some((
            cursor,
            end.min(self.next_start_after(cursor).unwrap_or(end)),
        ))
    }

    fn next_start_after(&self, lba: u64) -> Option<u64> {
        let i = self.0.partition_point(|(s, _)| *s <= lba);
        self.0.get(i).map(|(s, _)| *s)
    }

    fn iter(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.0.iter().copied()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Unresolvable lbamap claims found by
/// [`Volume::unresolvable_lbamap_hashes`]: how many there are, and the
/// first few for the log line. `total` is the severity signal —
/// `sample.len()` saturates at the caller's limit and so cannot
/// distinguish a handful from thousands.
#[derive(Default)]
pub(in crate::volume) struct UnresolvableHashes {
    pub total: usize,
    pub sample: Vec<(u64, blake3::Hash)>,
}

/// Outcome of [`Volume::mutate_gated_on_resolvability`].
pub(in crate::volume) enum ResolvabilityGate {
    /// The mutation is in place.
    Applied,
    /// The mutation was rolled back: committing it would have left this
    /// many `(lba, hash)` claims unresolvable.
    Refused(UnresolvableHashes),
}

/// Outcome of applying one `.staged` GC handoff via the derive-at-apply path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StagedApply {
    /// The staged segment was applied; extent index updated, body re-signed
    /// and renamed to bare, `.staged` file removed.
    Applied,
    /// The apply was cancelled (e.g. stale-liveness check) and the staged
    /// file was removed. Extent index is unchanged.
    Cancelled,
    /// The plan consumes an input segment this daemon's read state has
    /// never loaded — the served view is a strict subset of the on-disk
    /// own layer (`docs/design/read-state-divergence-check.md`). The
    /// plan file is retained: a fresh open loads the missing segments
    /// and can apply it. The daemon must fail-stop rather than keep
    /// serving.
    Diverged,
}

/// A fork ancestry layer used when rebuilding the LBA map and extent index.
///
/// `branch_ulid` is the latest segment ULID from this fork that belongs to the
/// derived fork's view — segments with a strictly greater ULID were written after
/// the branch point and must not be included. `None` for the live (current) fork,
/// where all segments are always included.
#[derive(Clone)]
pub struct AncestorLayer {
    pub dir: PathBuf,
    pub branch_ulid: Option<String>,
}

/// On-disk WAL state: file handle, ULID, and path. Present iff a WAL file
/// exists under `wal/<ulid>`. Absent between promotes / on idle volumes.
struct OpenWal {
    wal: writelog::WriteLog,
    ulid: Ulid,
    path: PathBuf,
}

/// A writable block-device volume backed by a content-addressable store.
///
/// Owns the in-memory LBA map, the active WAL, and the directory layout.
/// In the Named Forks model, `base_dir` is the fork directory (e.g.
/// `volumes/myvm/default/`), not the volume root.
pub struct Volume {
    pub(in crate::volume) base_dir: PathBuf,
    /// Ancestor fork layers, oldest-first. Does not include the current fork.
    pub(in crate::volume) ancestor_layers: Vec<AncestorLayer>,
    /// Exclusive lock on `base_dir/volume.lock`. Held for the lifetime of the Volume.
    /// The `Flock` releases the lock automatically when dropped.
    #[allow(dead_code)]
    lock_file: nix::fcntl::Flock<fs::File>,
    /// The LBA map and the extent index, as a `base` under the open WAL's
    /// `delta`. A mutation absorbs `delta` first; a read that iterates
    /// takes `materialised()`.
    pub(in crate::volume) maps: MapLayers,
    /// Candidate map for the formation resemblance delta tier, harvested
    /// from the same walk that rebuilt `extent_index` and extended with
    /// each promote's own sketched entries.
    ///
    /// A cache, not index state: every candidate is resolved through
    /// `extent_index` before use, so a posting for a hash that no longer
    /// resolves costs one failed lookup. Nothing rebuilds against it and
    /// nothing persists it.
    pub(in crate::volume) sketch_index: Arc<crate::sketch_index::SketchIndex>,
    /// Whether this volume's promotes run the delta tiers and leave
    /// sketches behind, resolved once at open.
    pub(in crate::volume) delta_policy: jobs::DeltaPolicy,
    /// Lazy WAL state. `None` means no WAL file exists on disk — the next
    /// write opens a fresh one at `mint.next()`. Keeps idle volumes from
    /// churning the WAL on every GC tick.
    pub(in crate::volume) wal: Option<OpenWal>,
    /// DATA and REF extents written since the last promotion, each carrying
    /// where its body bytes sit in the WAL; used to write the clean segment
    /// file on the next promote(). Populated by `write_commit` and by
    /// `recover_wal`, so body bytes live once — in the WAL and its page cache.
    pub(in crate::volume) pending: Vec<PendingWrite>,
    /// Journal-tier ULIDs in `pending/open/`, as the last close pass
    /// left it, with reaped segments removed as they go.
    pub(in crate::volume) pending_journal: std::collections::BTreeSet<Ulid>,
    /// True if at least one segment has been committed since the last snapshot
    /// (or since open, if no snapshot has been taken this session). Used by
    /// `snapshot()` to decide whether a new marker is needed or the latest
    /// existing snapshot can be reused.
    pub(in crate::volume) has_new_segments: bool,
    /// ULID of the most recently committed segment across pending/ and index/,
    /// or `None` if no segments exist. Used by `snapshot()` to name the snapshot
    /// marker with the same ULID as the segment it covers.
    pub(in crate::volume) last_segment_ulid: Option<Ulid>,
    /// Cache of open segment file handles for reads served off the `Volume`.
    ///
    /// Retains recently-opened segment files across `read` calls so that
    /// reads hitting the same segments avoid repeated `open` syscalls.
    /// Reads here run under the volume lock and eviction is explicit
    /// (`evict_cached_segment`), so every op passes layout generation 0.
    pub(in crate::volume) file_cache: SharedFileCache,
    /// Descriptor-cache counters for reads served directly off the `Volume`.
    pub(in crate::volume) read_stats: Arc<read::ReadStats>,
    /// In-memory cache of opened `cache/<ULID>.dmat` sidecars. Populated
    /// lazily on first delta read for each segment; cleared on cache
    /// eviction. See `docs/design/delta-materialisation.md`.
    pub(in crate::volume) dmat_cache: read::DmatCache,
    /// Telemetry counters for the dmat cache. Wrapped in `Arc` so the
    /// stats can be cloned and shared with `VolumeReader`s and IPC.
    pub(in crate::volume) dmat_stats: Arc<crate::dmat::DmatStats>,
    /// Signer for segment promotion. Every segment written by this volume
    /// (at WAL promotion and compaction) is signed with the fork's private key.
    /// See `segment::SegmentSigner`.
    pub(in crate::volume) signer: Arc<dyn segment::SegmentSigner>,
    /// Verifying key derived from `volume.key` at open time. Used to verify
    /// segment signatures when reading during compaction and GC.
    pub(in crate::volume) verifying_key: ed25519_dalek::VerifyingKey,
    /// Optional fetcher for demand-fetch on segment cache miss. When set,
    /// `find_segment_file` fetches missing segments from remote storage and
    /// caches them in `cache/`. See `segment::SegmentFetcher`.
    pub(in crate::volume) fetcher: Option<BoxFetcher>,
    /// Monotonic ULID generator. Seeded from the highest known ULID at open
    /// (WAL filename or max segment). Used for all WAL and compaction outputs
    /// to guarantee strict ordering regardless of host clock behaviour.
    pub(in crate::volume) mint: UlidMint,
    /// Stats for the no-op write skip path (LBA-map hash compare).
    /// See `docs/design/noop-write-skip.md`.
    pub(in crate::volume) noop_stats: NoopSkipStats,
    /// Stats for DedupRef minting at segment formation
    /// (`classify_pending_dedup`).
    pub(in crate::volume) dedup_mint_stats: DedupMintStats,
    /// The guest filesystem's jbd2 journal LBA ranges. Loaded from
    /// `volume.toml` before the extent-index rebuild (which needs them to
    /// route journal entries to the disjoint tier), re-derived from the
    /// filesystem after the maps are built, and persisted back when they
    /// change.
    pub(in crate::volume) journal: crate::journal::JournalRanges,
    /// Whether `volume.toml` holds an authoritative derivation answer.
    /// While `false`, every promote take re-attempts derivation so a
    /// filesystem formatted mid-session gains journal awareness without
    /// a reopen.
    pub(in crate::volume) journal_derived: bool,
    /// Shared LRU of parsed+verified segment indices. Keyed by
    /// `(path, file_len)`. Cloned into worker jobs so the actor thread
    /// and the worker thread hit the same cache. See
    /// `segment_cache::SegmentIndexCache`.
    pub(in crate::volume) segment_cache: Arc<segment_cache::SegmentIndexCache>,
    /// Committed-tier (`gc/` ∪ `index/`) own-layer segments this process
    /// has loaded or created — the daemon's view of its own committed
    /// segment set, against which every GC plan's inputs are checked
    /// (`docs/design/read-state-divergence-check.md`). Populated from
    /// the open-time scan; segments enter at `promote_segment` and at
    /// GC-handoff commit, and leave when their `index/<ulid>.idx` is
    /// deleted by a GC output's promote.
    pub(in crate::volume) own_segments: std::collections::BTreeSet<Ulid>,
}

/// Counters for the no-op write skip path. Reset to zero on `Volume::open`.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSkipStats {
    /// Number of `write()` calls short-circuited because the LBA map
    /// already records the incoming content's hash at the target range.
    pub skipped_writes: u64,
    /// Total bytes of incoming data the skip avoided writing to the WAL.
    pub skipped_bytes: u64,
}

/// Counters for DedupRef minting at segment formation. Counted since
/// `Volume::open`; open-time recovery promotes contribute.
#[derive(Debug, Default, Clone, Copy)]
pub struct DedupMintStats {
    /// Data entries converted to DedupRef by `classify_pending_dedup`.
    pub minted_entries: u64,
    /// Stored WAL body bytes those entries carried — the WAL growth cost
    /// of minting DedupRefs at formation instead of at write time.
    pub wal_body_bytes: u64,
}

impl Volume {
    /// Open (or create) a fork at `base_dir`.
    ///
    /// `base_dir` must be the fork directory (e.g. `volumes/myvm/default/`), not the
    /// volume root. Creates `wal/` and `pending/` if they do not exist.
    /// Rebuilds the LBA map from all committed segments across the ancestry chain
    /// (following `volume.parent` files), then recovers or creates the WAL.
    ///
    /// Loads the signing key from `volume.key` in `base_dir`. Fails hard if the key
    /// is absent — every writable volume must have a signing key. Fork from a snapshot
    /// to create a new writable volume with a fresh keypair.
    pub fn open(base_dir: &Path, by_id_dir: &Path) -> io::Result<Self> {
        let (signer, verifying_key) =
            crate::signing::load_keypair(base_dir, crate::signing::VOLUME_KEY_FILE).map_err(
                |e| {
                    io::Error::other(format!(
                        "{e}; fork from a snapshot to create a writable volume"
                    ))
                },
            )?;
        Self::open_impl(base_dir, signer, verifying_key, by_id_dir)
    }

    fn open_impl(
        base_dir: &Path,
        signer: Arc<dyn segment::SegmentSigner>,
        verifying_key: ed25519_dalek::VerifyingKey,
        by_id_dir: &Path,
    ) -> io::Result<Self> {
        let wal_dir = base_dir.join("wal");
        fs::create_dir_all(&wal_dir)?;

        // Acquire exclusive lock. Fails immediately if another process has this
        // fork open. The lock is released when Volume is dropped.
        let lock_file = acquire_lock(base_dir)?;

        // Generation layout under pending/ — creates open/, adopts any
        // flat pre-generation pending files, and sweeps .tmp leftovers
        // from crashed promotions.
        segment::ensure_pending_layout(base_dir)?;

        // The journal ranges persisted by the previous session. The
        // extent-index rebuild needs them before the filesystem is
        // parseable; a freshly derived window is persisted at the end of
        // open for the next session (`refresh_journal_ranges`).
        let cfg = crate::config::VolumeConfig::read(base_dir)?;
        let journal_derived = cfg.journal.is_some();
        let journal = cfg.journal_ranges();

        // Walk the origin chain and rebuild maps from all committed segments.
        let (ancestor_layers, mut lbamap, mut extent_index, sketch_index) =
            open_read_state(base_dir, by_id_dir)?;

        // Find the in-progress WAL file (there should be at most one).
        let mut wal_files: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&wal_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                wal_files.push(entry.path());
            }
        }
        wal_files.sort_unstable_by(|a, b| a.file_name().cmp(&b.file_name()));

        // Edge case: if pending/<ulid> already exists alongside wal/<ulid>,
        // the promotion completed (rename succeeded) but the WAL delete was
        // interrupted. The segment is authoritative — delete the stale WAL file.
        wal_files.retain(|path| {
            let Some(ulid) = path.file_name().and_then(|s| s.to_str()) else {
                return true; // non-UTF-8 name: leave it alone
            };
            if segment::find_pending_file(base_dir, ulid).is_some() {
                let _ = fs::remove_file(path);
                false
            } else {
                true
            }
        });

        // Scan pending/ and index/ to find the latest committed segment ULID
        // and determine whether any segments postdate the latest snapshot.
        // Cross-session ULID comparison is reliable: those files came from
        // earlier runs at distinct timestamps.
        //
        // Done before WAL recovery so we can compute the mint floor below.
        let latest_snap = latest_snapshot(base_dir)?;
        let mut last_segment_ulid: Option<Ulid> = None;
        // Collect pending/ segment ULIDs (full files, not yet uploaded).
        for p in segment::collect_pending_segment_files(base_dir)? {
            if let Some(ulid) = p
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|s| Ulid::from_string(s).ok())
                && last_segment_ulid < Some(ulid)
            {
                last_segment_ulid = Some(ulid);
            }
        }
        // The committed-tier `own_segments` set (index/*.idx ULIDs plus
        // volume-applied bare gc/ outputs) that the divergence check
        // compares GC plan inputs against. Every member also advances
        // the mint floor: a bare gc/ output carries a ULID minted by the
        // volume's own `UlidMint` via `gc_checkpoint`, so the floor must
        // pass it on restart.
        let own_segments = segment::committed_tier_ulids(base_dir)?;
        if let Some(&max_ulid) = own_segments.last()
            && last_segment_ulid < Some(max_ulid)
        {
            last_segment_ulid = Some(max_ulid);
        }

        // Compute the mint floor: max of the highest segment ULID and the
        // WAL filename ULID (if one exists). This guarantees the first fresh
        // WAL ULID is above all existing local data even when the system clock
        // has drifted backwards.
        let segment_floor = last_segment_ulid.unwrap_or(Ulid::from_parts(0, 0));
        let wal_floor = wal_files
            .last()
            .and_then(|p| p.file_name().and_then(|n| n.to_str()))
            .and_then(|s| Ulid::from_string(s).ok())
            .unwrap_or(Ulid::from_parts(0, 0));
        let mut mint = UlidMint::new(segment_floor.max(wal_floor));

        // Promote every non-latest WAL to a fresh segment so the volume
        // returns to its "one active WAL" invariant before we open the
        // actor. This path fires whenever the previous process ended
        // with promotes in flight or stashed — a crash, or a stop while
        // the worker was mid-promote — leaving multiple WAL files.
        //
        // The freshly-minted segment ULID is strictly > any wal_floor or
        // segment_floor (mint monotonicity), so it never collides with an
        // existing file. Entries use the same CAS apply path as the online
        // `flush_wal_to_pending_as` flow — safe even when an orphan pending
        // segment from the pre-crash worker has already repopulated the
        // same hashes.
        let wal_files_to_promote: Vec<PathBuf> = if wal_files.len() > 1 {
            let split = wal_files.len() - 1;
            let rest = wal_files.split_off(split);
            std::mem::replace(&mut wal_files, rest)
        } else {
            Vec::new()
        };
        let mut recovery_dedup_stats = DedupMintStats::default();
        for wal_path in wal_files_to_promote {
            let wal::WalReplay {
                ulid: old_wal_ulid,
                valid_size: _,
                pending,
            } = replay_wal_records(&wal_path, &mut lbamap, &mut extent_index, &journal)?;
            if pending.is_empty() {
                fs::remove_file(&wal_path)?;
                continue;
            }
            // Primary ULID first: the journal segment must sort above the
            // data segment (see `JournalPartition`).
            let segment_ulid = mint.next();
            let (primary, jpart, dedup) = stage_pending_for_promote(
                pending,
                &extent_index,
                old_wal_ulid,
                &journal,
                &mut mint,
            );
            recovery_dedup_stats.minted_entries += dedup.minted_entries;
            recovery_dedup_stats.wal_body_bytes += dedup.wal_body_bytes;
            let result = crate::actor::execute_promote(
                PromoteJob {
                    segment_ulid,
                    old_wal_ulid,
                    old_wal_path: wal_path.clone(),
                    primary,
                    signer: Arc::clone(&signer),
                    pending_dir: segment::pending_open_dir(base_dir),
                    // Recovery promotes of stale WALs write plain Data
                    // entries. Both delta tiers resolve sources through
                    // Arc'd snapshots, and the open path holds the index
                    // and the candidate map by value at this point, so an
                    // empty spec leaves every entry alone.
                    delta: crate::volume::jobs::PromoteDeltaSpec {
                        policy: crate::volume::jobs::DeltaPolicy::OFF,
                        extent_index: Arc::new(extentindex::ExtentIndex::new()),
                        sketch_index: Arc::new(crate::sketch_index::SketchIndex::new()),
                        search_dirs: Vec::new(),
                        lbamap: Arc::new(crate::lbamap::LbaMap::new()),
                        prior: None,
                    },
                    journal: jpart,
                },
                &mut crate::actor::PriorSourceCache::default(),
            )
            .map_err(|failure| failure.error)?;
            apply_promoted_entries(&mut extent_index, &mut lbamap, &result)?;
            // Bump last_segment_ulid so the first-snapshot pinning invariant
            // (see `Volume::snapshot`) covers the recovery-promoted segments.
            let max_promoted = result
                .journal
                .as_ref()
                .map(|j| j.segment_ulid)
                .unwrap_or(result.segment_ulid)
                .max(result.segment_ulid);
            if last_segment_ulid < Some(max_promoted) {
                last_segment_ulid = Some(max_promoted);
            }
            fs::remove_file(&wal_path)?;
        }

        // recover_wal does the single WAL scan: truncates any partial tail,
        // replays records into the LBA map, and rebuilds the pending writes.
        // When no WAL file is present on disk, leave `wal` as None; the next
        // write lazily opens a fresh WAL. This avoids creating an empty WAL
        // for read-only volumes and idle sessions that never write.
        let (wal, pending) = if let Some(path) = wal_files.into_iter().last() {
            let wal::RecoveredWal {
                wal,
                ulid,
                path,
                pending,
            } = recover_wal(path, &mut lbamap, &mut extent_index, &journal)?;
            (Some(OpenWal { wal, ulid, path }), pending)
        } else {
            (None, Vec::new())
        };

        let has_new_segments = !pending.is_empty()
            || matches!((&latest_snap, &last_segment_ulid), (Some(snap), Some(last)) if last > snap);

        let mut ret = Self {
            base_dir: base_dir.to_owned(),
            ancestor_layers,
            lock_file,
            maps: MapLayers::new(Maps::new(lbamap, extent_index)),
            sketch_index: Arc::new(sketch_index),
            delta_policy: jobs::DeltaPolicy::from_env(),
            wal,
            pending,
            pending_journal: std::collections::BTreeSet::new(),
            has_new_segments,
            last_segment_ulid,
            file_cache: SharedFileCache::default(),
            read_stats: Arc::new(read::ReadStats::default()),
            dmat_cache: read::DmatCache::default(),
            dmat_stats: Arc::new(crate::dmat::DmatStats::default()),
            signer,
            verifying_key,
            fetcher: None,
            mint,
            noop_stats: NoopSkipStats::default(),
            dedup_mint_stats: recovery_dedup_stats,
            journal,
            journal_derived,
            segment_cache: Arc::new(segment_cache::SegmentIndexCache::new(
                SEGMENT_INDEX_CACHE_CAPACITY,
            )),
            own_segments,
        };
        ret.refresh_journal_ranges();
        ret.assert_volume_invariants("Volume::open");
        Ok(ret)
    }

    /// Derive the journal window from the guest filesystem and persist
    /// it to `volume.toml` when it differs from the stored value.
    ///
    /// Never-derived volumes route through `poll_derive_and_flip`: a
    /// successful parse takes effect immediately in this session (the
    /// persisted per-entry `JOURNAL` flag keeps rebuilds consistent). For an
    /// already-derived volume whose window changed (reformat), the
    /// in-memory set stays what this open's rebuild used — the derived
    /// window takes effect at the next open, keeping the live index and
    /// the drift checker on one consistent range set per session. An
    /// affirmative "not ext4" clears the stored section, so a volume
    /// reformatted away from ext4 reverts to never-derived at the next
    /// open instead of keeping a stale window forever. Best-effort: an
    /// unreadable block (e.g. evicted body with no fetcher) or a
    /// config write failure keeps the stored set.
    fn refresh_journal_ranges(&mut self) {
        if !self.journal_derived {
            self.poll_derive_and_flip();
            return;
        }
        // An unwritten superblock block reads as zeros from the void
        // (blank or discarded device) — absence of evidence, not an
        // affirmative "not ext4". Only written content can clear the
        // stored window below.
        let superblock_written = self.maps.materialised().lbamap.lookup(0).is_some();
        let mut reader = read::VolumeExt4Reader { volume: self };
        let derived = match crate::ext4_scan::journal_lba_ranges(&mut reader) {
            // The device read fine and does not parse as ext4: the
            // stored window describes a filesystem that is gone.
            // Clearing reverts to never-derived at the next open;
            // this session keeps the set its rebuild used.
            Ok(None) => {
                if superblock_written {
                    self.clear_stored_window();
                }
                return;
            }
            Ok(Some(r)) => r,
            Err(e) => {
                log::warn!("[journal] window derivation failed, keeping stored set: {e}");
                return;
            }
        };
        if derived == self.journal {
            return;
        }
        let mut cfg = match crate::config::VolumeConfig::read(&self.base_dir) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("[journal] reading volume.toml for window update failed: {e}");
                return;
            }
        };
        cfg.journal = Some(crate::config::JournalConfig {
            ranges: derived.clone(),
        });
        if let Err(e) = cfg.write(&self.base_dir) {
            log::warn!("[journal] persisting window failed: {e}");
            return;
        }
        log::info!(
            "[journal] window changed: {} range(s), {} LBAs (was {} range(s), {} LBAs); effective next open",
            derived.as_slice().len(),
            derived.lba_count(),
            self.journal.as_slice().len(),
            self.journal.lba_count(),
        );
    }

    /// Remove the `[journal]` section from `volume.toml`.
    fn clear_stored_window(&self) {
        let mut cfg = match crate::config::VolumeConfig::read(&self.base_dir) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("[journal] reading volume.toml for window clear failed: {e}");
                return;
            }
        };
        if cfg.journal.take().is_none() {
            return;
        }
        if let Err(e) = cfg.write(&self.base_dir) {
            log::warn!("[journal] clearing stored window failed: {e}");
            return;
        }
        log::info!(
            "[journal] filesystem no longer parses as ext4; cleared stored window ({} range(s), {} LBAs); effective next open",
            self.journal.as_slice().len(),
            self.journal.lba_count(),
        );
    }

    /// While the window has never been derived, attempt derivation and
    /// flip it live on success. Called at the end of open and from
    /// every promote take, so a filesystem formatted mid-session gains
    /// journal awareness within one drain tick. On a blank device the
    /// attempt costs a single read of LBA 0 (the superblock-magic
    /// probe fails before any deeper parsing).
    fn poll_derive_and_flip(&mut self) {
        let mut reader = read::VolumeExt4Reader { volume: self };
        match crate::ext4_scan::journal_lba_ranges(&mut reader) {
            // "No opinion" (not ext4, or not ext4 *yet*): stay
            // never-derived, retry at the next take.
            Ok(None) => {}
            Ok(Some(ranges)) => self.flip_window(ranges),
            Err(e) => {
                // Transient mid-format states can fail past the magic
                // probe (e.g. a superblock restored before its inode
                // table); the next attempt sees more of the image.
                log::debug!("[journal] window derivation failed, will retry: {e}");
            }
        }
    }

    /// Persist a first-ever derivation answer and go live on a non-empty
    /// window in this session.
    ///
    /// Classification is the persisted per-entry `JOURNAL` flag stamped
    /// at formation, so pre-derivation writes stay in the data tier and
    /// this take begins routing window LBAs to the journal tier with no
    /// reclassification of history. The config write comes first; if it
    /// fails the volume stays never-derived so no rebuild can disagree
    /// with the live index.
    fn flip_window(&mut self, ranges: crate::journal::JournalRanges) {
        let mut cfg = match crate::config::VolumeConfig::read(&self.base_dir) {
            Ok(c) => c,
            Err(e) => {
                log::warn!("[journal] reading volume.toml for window flip failed: {e}");
                return;
            }
        };
        cfg.journal = Some(crate::config::JournalConfig {
            ranges: ranges.clone(),
        });
        if let Err(e) = cfg.write(&self.base_dir) {
            log::warn!("[journal] persisting window flip failed: {e}");
            return;
        }
        self.journal_derived = true;
        if ranges.is_empty() {
            log::info!("[journal] derived: filesystem has no internal journal");
        } else {
            log::info!(
                "[journal] window derived live: {} range(s), {} LBAs",
                ranges.as_slice().len(),
                ranges.lba_count(),
            );
            self.journal = ranges;
        }
    }

    /// Write `data` starting at logical block address `lba`.
    ///
    /// `data.len()` must be a non-zero multiple of 4096 and must not exceed
    /// `MAX_WRITE_SIZE` (4 GiB − 4 KiB). The segment format stores `body_length`
    /// as a `u32` byte count, so larger payloads cannot be represented.
    ///
    /// The data is appended to the WAL and the LBA map is updated in memory.
    /// Promotion to a pending segment is triggered after the write if the WAL
    /// reaches `FLUSH_THRESHOLD` (32 MiB). Because the check is post-write, a
    /// single large write may produce a segment larger than the threshold; the
    /// block layer (ublk) is expected to enforce its own per-request cap.
    pub fn write(&mut self, lba: u64, data: &[u8]) -> io::Result<()> {
        validate_write_size(data)?;
        let hash = blake3::hash(data);
        let compressed = maybe_compress(data);
        self.commit_or_skip(lba, data, hash, compressed.as_deref())
            .map(|_| ())
    }

    /// Like [`Volume::write`], but with the BLAKE3 hash *and* the lz4
    /// compression decision precomputed by the caller.
    ///
    /// Used by [`crate::actor::VolumeClient::write`] to keep both passes
    /// off the volume mutex so concurrent writers can hash and compress
    /// in parallel. The caller MUST pass `blake3::hash(data)` for `hash`
    /// and `maybe_compress(data).as_deref()` for `compressed` (i.e.
    /// `Some(lz4_bytes)` iff compression cleared the ratio threshold,
    /// otherwise `None`).
    pub fn write_precomputed(
        &mut self,
        lba: u64,
        data: &[u8],
        hash: blake3::Hash,
        compressed: Option<&[u8]>,
    ) -> io::Result<()> {
        validate_write_size(data)?;
        self.commit_or_skip(lba, data, hash, compressed).map(|_| ())
    }

    /// Run the no-op skip check, then dispatch to [`Self::write_commit`].
    /// Returns `Ok(true)` if the write was committed, `Ok(false)` if it
    /// was a no-op.
    fn commit_or_skip(
        &mut self,
        lba: u64,
        data: &[u8],
        hash: blake3::Hash,
        compressed: Option<&[u8]>,
    ) -> io::Result<bool> {
        let lba_length = (data.len() / 4096) as u32;

        // A write crossing a journal-window boundary commits as
        // boundary-aligned runs, each hashed and compressed on its own,
        // so every WAL record, LBA claim, and segment entry it produces
        // is uniformly journal or stable — the tier purity every
        // downstream consumer (formation's split, drain deferral, repack
        // routing, reap-whole) classifies whole segments by. The
        // caller's hash and compression cover the whole buffer and are
        // recomputed per run; jbd2 confines its I/O to the journal
        // extents, so a crossing write is guest misbehaviour and the
        // recompute cost is irrelevant.
        if self.journal.crosses_boundary(lba, lba_length) {
            let mut committed = false;
            for (run_lba, run_len) in self.journal.split_at_boundaries(lba, lba_length) {
                let offset = ((run_lba - lba) as usize) * 4096;
                let bytes = &data[offset..offset + run_len as usize * 4096];
                let run_hash = blake3::hash(bytes);
                let run_compressed = maybe_compress(bytes);
                committed |=
                    self.commit_or_skip(run_lba, bytes, run_hash, run_compressed.as_deref())?;
            }
            return Ok(committed);
        }

        // No-op skip — pure LBA map lookup, zero body I/O. BLAKE3
        // collision resistance means hash equality implies byte equality,
        // so this is safe regardless of where the body lives (Local,
        // Cached present, Cached absent, or S3-only). See
        // `docs/design/noop-write-skip.md`.
        if self.maps.has_full_match(lba, lba_length, &hash) {
            self.noop_stats.skipped_writes += 1;
            self.noop_stats.skipped_bytes += data.len() as u64;
            if crate::wtrace::enabled() {
                log::info!(
                    "[wtrace] noop-skip lba={lba} blocks={lba_length} hash={}",
                    hash.to_hex()
                );
            }
            return Ok(false);
        }

        self.write_commit(lba, lba_length, data, hash, compressed)?;
        if crate::wtrace::enabled() {
            log::info!(
                "[wtrace] commit lba={lba} blocks={lba_length} hash={}",
                hash.to_hex()
            );
        }
        Ok(true)
    }

    /// Shared tail of the write path after the no-op skip check has
    /// decided the bytes must hit the WAL.
    fn write_commit(
        &mut self,
        lba: u64,
        lba_length: u32,
        data: &[u8],
        hash: blake3::Hash,
        compressed: Option<&[u8]>,
    ) -> io::Result<()> {
        let bytes_to_write: &[u8] = compressed.unwrap_or(data);
        let is_compressed = compressed.is_some();
        let wal_flags = if is_compressed {
            writelog::WalFlags::COMPRESSED
        } else {
            writelog::WalFlags::empty()
        };

        let codec = segment::Codec::from_wal_flags(wal_flags);

        let stored_length = bytes_to_write.len() as u32;
        let (body_offset, wal_ulid) = {
            let open = self.ensure_wal_open()?;
            let offset = open
                .wal
                .append_data(lba, lba_length, &hash, wal_flags, bytes_to_write)?;
            (offset, open.ulid)
        };
        self.maps
            .lbamap_mut()
            .insert(lba, lba_length, hash, wal_ulid);
        // Temporary extent index entry: points into the WAL at the raw
        // payload offset, updated to segment file offsets after promotion.
        // A journal-window write goes to the disjoint journal tier keyed by
        // `(wal_ulid, hash)` — never `inner` — so durable content never
        // dedups against it. A durable write uses `insert_if_absent`: a hash
        // that already resolves (a prior canonical, or an earlier write of
        // the same bytes in this epoch) keeps its owner, and the non-owner is
        // minted as a DedupRef at formation (`classify_pending_dedup`).
        // `commit_or_skip` splits at window boundaries, so the start LBA's
        // classification covers the entry's whole range.
        let is_journal = self.journal.contains(lba);
        let location = extentindex::ExtentLocation {
            segment_id: wal_ulid,
            body_offset,
            body_length: stored_length,
            codec,
            body_source: BodySource::Local,
            body_section_start: 0,
            inline_data: None,
        };
        let ei = self.maps.extent_index_mut();
        if is_journal {
            ei.insert_journal_if_absent(wal_ulid, hash, location);
        } else {
            ei.insert_if_absent(hash, location);
        }
        let mut entry =
            segment::SegmentEntry::new_data_no_body(hash, lba, lba_length, codec, stored_length);
        entry.journal = is_journal;
        self.pending.push(PendingWrite {
            entry,
            wal_body_offset: Some(body_offset),
        });

        Ok(())
    }

    /// Open the WAL if it is currently absent. Mints a fresh ULID from
    /// `self.mint` — always monotonically above any prior segment or
    /// checkpoint ULID, preserving the "new WAL above GC output" invariant
    /// without needing a reserved `u_wal` in `GcCheckpointUlids`.
    fn ensure_wal_open(&mut self) -> io::Result<&mut OpenWal> {
        if self.wal.is_none() {
            let ulid = self.mint.next();
            let (wal, ulid, path) = create_fresh_wal(&self.base_dir.join("wal"), ulid)?;
            self.wal = Some(OpenWal { wal, ulid, path });
        }
        // ensure_wal_open just populated self.wal if it was None.
        Ok(self.wal.as_mut().expect("wal open"))
    }

    /// Zero `lba_count` blocks starting at `lba`.
    ///
    /// Appends a ZERO WAL record per journal-window run — no hashing, no data
    /// payload, no chunking. A range crossing a window boundary commits as
    /// boundary-aligned runs, so every record, LBA claim and segment entry it
    /// produces is uniformly journal or stable, which is the tier purity
    /// `PendingPartition::split_journal` classifies a pending write by. The LBA
    /// map entry uses `ZERO_HASH` as a sentinel, which the read path recognises
    /// and short-circuits to return zeros without any extent index lookup.
    ///
    /// Zero extents explicitly override ancestor data: a ZERO_HASH entry in the
    /// LBA map masks any data at those LBAs in ancestor segments, where an
    /// unwritten LBA range falls through to the ancestor.
    pub fn write_zeroes(&mut self, start_lba: u64, lba_count: u32) -> io::Result<()> {
        if self.journal.crosses_boundary(start_lba, lba_count) {
            for (run_lba, run_len) in self.journal.split_at_boundaries(start_lba, lba_count) {
                self.zero_commit(run_lba, run_len)?;
            }
            return Ok(());
        }
        self.zero_commit(start_lba, lba_count)
    }

    /// Commit one boundary-aligned zero run: one WAL record, one LBA claim,
    /// one pending entry.
    fn zero_commit(&mut self, start_lba: u64, lba_count: u32) -> io::Result<()> {
        let wal_ulid = {
            let open = self.ensure_wal_open()?;
            open.wal.append_zero(start_lba, lba_count)?;
            open.ulid
        };
        self.maps
            .lbamap_mut()
            .insert(start_lba, lba_count, ZERO_HASH, wal_ulid);
        self.pending.push(PendingWrite {
            entry: segment::SegmentEntry::new_zero(start_lba, lba_count),
            wal_body_offset: None,
        });
        Ok(())
    }

    /// Trim (discard) `lba_count` blocks starting at `lba`.
    ///
    /// Implemented via `write_zeroes` — a zero-extent WAL record with no data
    /// payload per journal-window run. The whole-volume TRIM issued by
    /// `mkfs.ext4` runs before any window is derived, so it becomes one
    /// ~40-byte record regardless of volume size.
    pub fn trim(&mut self, start_lba: u64, lba_count: u32) -> io::Result<()> {
        self.write_zeroes(start_lba, lba_count)
    }

    /// Read 4 KiB blocks starting at `lba` into the caller-supplied `buf`.
    ///
    /// `buf.len()` must be a multiple of 4096; it determines the block count.
    /// Blocks that have never been written are returned as zeros (the
    /// block-device convention for unwritten regions). Written blocks are
    /// fetched extent-by-extent: one file open and one read (or decompress)
    /// per extent, regardless of how many blocks within the extent are needed.
    pub fn read_into(&self, lba: u64, buf: &mut [u8]) -> io::Result<()> {
        let cache_dir = self.base_dir.join("cache");
        read_extents(
            lba,
            buf,
            &self.maps,
            0,
            &self.file_cache,
            &self.dmat_cache,
            &self.dmat_stats,
            &self.read_stats,
            &cache_dir,
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

    /// Allocating convenience wrapper around [`Volume::read_into`].
    ///
    /// The hot read path (ublk dispatch) calls `read_into` directly with the
    /// kernel's IO buffer; this allocating form is used by tests and the CLI.
    pub fn read(&self, lba: u64, lba_count: u32) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; lba_count as usize * 4096];
        self.read_into(lba, &mut buf)?;
        Ok(buf)
    }

    /// Snapshot the dmat telemetry counters for this volume.
    pub fn dmat_stats(&self) -> crate::dmat::DmatStatsSnapshot {
        self.dmat_stats.snapshot()
    }

    /// Flush buffered WAL writes and fsync to disk. No-op when no WAL is open.
    pub fn fsync(&mut self) -> io::Result<()> {
        match self.wal.as_mut() {
            Some(open) => open.wal.fsync(),
            None => Ok(()),
        }
    }

    /// No-op skip counters. See `docs/design/noop-write-skip.md`.
    pub fn noop_stats(&self) -> NoopSkipStats {
        self.noop_stats
    }

    /// Counters for DedupRef minting at segment formation since open.
    pub fn dedup_mint_stats(&self) -> DedupMintStats {
        self.dedup_mint_stats
    }

    /// Inline, test-only variant of the GC checkpoint.
    ///
    /// Mints the two ULIDs (`u_gc < u_flush`) and flushes the current WAL
    /// to `pending/<u_flush>` synchronously on the caller's thread.
    /// Returns `u_gc`.  The post-flush WAL is left unopened — the next
    /// write lazily opens a fresh one (see `Volume::wal`).
    ///
    /// **Production uses [`Volume::prepare_gc_checkpoint`] instead**, which
    /// splits mint+rotate (actor thread) from the old-WAL fsync (worker
    /// thread) so writes aren't blocked.  This method keeps both on one
    /// thread for tests that want a synchronous checkpoint without spinning
    /// up the actor machinery.  See [`GcCheckpointUlids`] for why both
    /// ULIDs are minted before any I/O.
    pub fn gc_checkpoint_for_test(&mut self) -> io::Result<Ulid> {
        Ok(self.gc_checkpoint_buckets_for_test(1)?.remove(0))
    }

    /// [`Volume::gc_checkpoint_for_test`] over `max_buckets` buckets, for
    /// tests driving a multi-bucket pass.
    pub fn gc_checkpoint_buckets_for_test(&mut self, max_buckets: usize) -> io::Result<Vec<Ulid>> {
        let GcCheckpointUlids { u_buckets, u_flush } = self.mint_gc_checkpoint_ulids(max_buckets);
        // Flush the current WAL to pending/ under u_flush. If the WAL is
        // empty (or absent), the file is deleted/skipped and u_flush is unused.
        self.flush_wal_to_pending_as(u_flush)?;
        self.assert_volume_invariants("gc_checkpoint_for_test");
        Ok(u_buckets)
    }

    /// `gc_checkpoint_for_test` variant modelling a checkpoint whose WAL
    /// flush promote failed on the worker: the ULIDs are minted and the
    /// WAL is taken, then restored through the promote-failure path.
    pub fn gc_checkpoint_with_failed_flush_for_test(&mut self) -> io::Result<Ulid> {
        let GcCheckpointUlids { u_buckets, u_flush } = self.mint_gc_checkpoint_ulids(1);
        let job = self.take_wal_into_promote_job(u_flush)?;
        self.restore_failed_promote(job)?;
        Ok(u_buckets[0])
    }

    /// Mint the ULIDs for a GC checkpoint, in ordering-invariant order:
    /// `max_buckets` bucket ULIDs followed by `u_flush`.
    ///
    /// See [`GcCheckpointUlids`] for the ordering invariant and why all
    /// are minted before any I/O.
    fn mint_gc_checkpoint_ulids(&mut self, max_buckets: usize) -> GcCheckpointUlids {
        let u_buckets: Vec<Ulid> = (0..max_buckets).map(|_| self.mint.next()).collect();
        let u_flush = self.mint.next();
        GcCheckpointUlids { u_buckets, u_flush }
    }

    /// Apply staged GC handoff files written by the coordinator.
    ///
    /// Under the self-describing handoff protocol, the coordinator writes the
    /// compacted segment to `gc/<new-ulid>.staged` (signed with an ephemeral
    /// key; the `inputs` list is embedded in the segment header). This method
    /// walks `gc/` for `.staged` entries, reads each segment's `inputs`, diffs
    /// those inputs' `.idx` files against the new segment's entries to build
    /// the extent-index updates, re-signs the body with the volume key, and
    /// renames `<ulid>.tmp → <ulid>` (the bare name — an atomic commit point
    /// meaning "volume-applied, awaiting coordinator upload"), then removes
    /// `<ulid>.staged`. The coordinator subsequently uploads the segment to
    /// S3 and sends a `promote <new-ulid>` IPC; `promote_segment` writes
    /// `index/<new-ulid>.idx` and `cache/<new-ulid>.{body,present}` and
    /// deletes `index/<old>.idx` for each consumed input. Input
    /// `cache/<input>.{body,present}` files are deleted by the coordinator
    /// during `apply_done_handoffs`, not here.
    ///
    /// This two-phase approach preserves the invariant: **`index/<ulid>.idx`
    /// present ↔ segment confirmed in S3**. The idx is never written before the
    /// coordinator confirms the upload, so a segment in `gc/` or `pending/` with
    /// no idx is never mistaken for an S3-confirmed segment.
    ///
    /// Returns the number of handoff files processed. Returns `Ok(0)` if
    /// the `gc/` directory does not exist yet.
    pub fn apply_gc_handoffs(&mut self) -> io::Result<usize> {
        let gc_dir = self.base_dir.join("gc");
        self.apply_all_staged_handoffs(&gc_dir)
    }

    /// Walk `gc/` for `.plan` entries and apply each via the
    /// self-describing derive-at-apply path.
    ///
    /// Also handles crash-recovery filename states:
    /// - `<ulid>.tmp` — volume-owned apply scratch from a crashed write.
    ///   Remove on sight. Coordinator-owned `<ulid>.staged.tmp` scratch
    ///   is left alone (the coord may be actively writing it; the coord
    ///   cleans its own stale scratch at the start of each GC pass).
    /// - `<ulid>.staged` alone — apply normally.
    /// - `<ulid>.staged` + bare `<ulid>` — bare wins (previous apply
    ///   committed before cleanup); remove the `.staged`.
    /// - bare `<ulid>` alone — already applied, no action.
    fn apply_all_staged_handoffs(&mut self, gc_dir: &Path) -> io::Result<usize> {
        if !gc_dir.try_exists()? {
            return Ok(0);
        }

        // Pass 1: sweep stale volume-owned `<ulid>.tmp` scratch files
        // (incomplete apply writes). The suffix must be exactly `.tmp`
        // on a valid Ulid stem — this deliberately excludes the
        // coordinator's `<ulid>.staged.tmp` compaction scratch, which
        // the coord may still be writing in a concurrent tick. Deleting
        // it here would race `tokio::fs::rename` to ENOENT and fail the
        // compaction handoff.
        for entry in fs::read_dir(gc_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(stem) = name.strip_suffix(".tmp") else {
                continue;
            };
            if Ulid::from_string(stem).is_ok() {
                let _ = fs::remove_file(entry.path());
            }
        }

        // Pass 2: collect `.plan` files emitted by the coordinator. See
        // docs/design/gc-plan-handoff.md for the protocol.
        let mut plans: Vec<(String, Ulid)> = fs::read_dir(gc_dir)?
            .filter_map(|e| {
                let e = e.ok()?;
                let name = e.file_name().into_string().ok()?;
                let stem = name.strip_suffix(".plan")?;
                let ulid = Ulid::from_string(stem).ok()?;
                Some((name, ulid))
            })
            .collect();
        plans.sort_by(|(a, _), (b, _)| a.cmp(b));

        let mut count = 0usize;
        for (name, new_ulid) in plans {
            let plan_path = gc_dir.join(&name);
            let bare_path = gc_dir.join(new_ulid.to_string());

            // Crash recovery: plan + bare → bare wins, drop plan.
            if bare_path.try_exists()? {
                let _ = fs::remove_file(&plan_path);
                count += 1;
                continue;
            }

            match self.apply_plan_handoff(gc_dir, &plan_path, new_ulid)? {
                StagedApply::Applied => count += 1,
                StagedApply::Cancelled => {
                    // Cancel removes the handoff input file inside.
                }
                // The read state is provably incomplete; every remaining
                // plan is suspect for the same reason. Stop here.
                StagedApply::Diverged => break,
            }
        }

        Ok(count)
    }

    /// Prep phase of GC plan application: snapshot the volume state a
    /// [`GcPlanApplyJob`] needs, around a `plan` that
    /// [`read_plan_for_apply`] has already parsed and ULID-matched.
    pub fn prepare_plan_apply(
        &self,
        plan_path: PathBuf,
        new_ulid: Ulid,
        plan: rewrite_plan::RewritePlan,
    ) -> GcPlanApplyJob {
        GcPlanApplyJob {
            plan_path,
            new_ulid,
            gc_dir: self.base_dir.join("gc"),
            index_dir: self.base_dir.join("index"),
            base_dir: self.base_dir.clone(),
            ancestor_layers: self.ancestor_layers.clone(),
            fetcher: self.fetcher.clone(),
            extent_index: self.maps.materialised().extent_index,
            signer: Arc::clone(&self.signer),
            verifying_key: self.verifying_key,
            plan,
        }
    }

    /// Apply phase for a [`GcPlanApplyResult`] returned by the worker.
    ///
    /// Re-derives the to-remove and stale-cancel sets against the **current**
    /// extent index and lbamap (which may have diverged while the worker was
    /// running), applies the fold to the in-memory extent index and lbamap,
    /// refuses it if that would leave any lbamap-referenced hash without a
    /// body location, then commits via `rename(<tmp>, <bare>)` as the atomic
    /// commit point. Cancelled materialisations skip the commit — the plan
    /// was already removed by the worker and any stale `.tmp` will be swept
    /// on the next apply tick.
    pub fn apply_plan_apply_result(
        &mut self,
        result: GcPlanApplyResult,
    ) -> io::Result<StagedApply> {
        // Cancelled in the worker: plan file already removed; any stale
        // `.tmp` is cleaned up on the next apply pass by the sweep at the
        // top of `apply_all_staged_handoffs`. Nothing more to do here.
        if matches!(result.outcome, StagedApply::Cancelled) {
            return Ok(StagedApply::Cancelled);
        }

        let GcPlanApplyResult {
            new_ulid,
            plan_path,
            gc_dir,
            tmp_path,
            new_bss,
            entries,
            inputs,
            input_old_entries,
            input_claim_ranges,
            carried_hashes,
            entry_hashes,
            handoff_inline,
            outcome: _,
        } = result;
        let tmp_path = match tmp_path {
            Some(p) => p,
            None => return Ok(StagedApply::Cancelled),
        };

        // Divergence check: the stale-liveness loop below only examines
        // hashes the extent index locates *at* an input, so an input
        // this daemon never loaded would sail through it unchecked.
        // The plan file stays on disk — unlike a cancel, the plan is
        // valid against the on-disk layer; it is this daemon that is
        // wrong (`docs/design/read-state-divergence-check.md`).
        let unknown: Vec<Ulid> = inputs
            .iter()
            .filter(|u| !self.own_segments.contains(u))
            .copied()
            .collect();
        if !unknown.is_empty() {
            log::error!(
                "plan {new_ulid}: read-state divergence — {} input segment(s) \
                 unknown to this daemon's read state: [{}]; refusing to fold",
                unknown.len(),
                unknown
                    .iter()
                    .map(Ulid::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
            );
            let _ = fs::remove_file(&tmp_path);
            return Ok(StagedApply::Diverged);
        }

        let derive_start = Instant::now();

        // Liveness for the veto is a claim or any recorded encoding
        // naming the hash as a source: a base body must stay resolvable
        // while an encoding names it, so its extent must cancel a plan
        // that drops it. Both probe maintained counts.
        let mut to_remove: Vec<(blake3::Hash, Ulid)> = Vec::new();
        let mut stale_cancel: Vec<(blake3::Hash, Ulid)> = Vec::new();
        self.maps.absorb();
        let maps = self.maps.materialised();
        for (hash, _kind, input_ulid) in &input_old_entries {
            // Check both `inner` and `deltas` — a Delta entry sits in
            // `extent_index.deltas` and would be missed by `lookup` alone.
            let still_at_input = maps
                .extent_index
                .lookup(hash)
                .is_some_and(|loc| loc.segment_id == *input_ulid)
                || maps
                    .extent_index
                    .lookup_delta(hash)
                    .is_some_and(|loc| loc.segment_id == *input_ulid);
            if !still_at_input {
                continue;
            }
            if carried_hashes.contains(hash) {
                continue;
            }
            if maps.lbamap.is_referenced(hash) || maps.extent_index.is_named_delta_source(hash) {
                stale_cancel.push((*hash, *input_ulid));
            }
            to_remove.push((*hash, *input_ulid));
        }

        if !stale_cancel.is_empty() {
            log::warn!(
                "plan {new_ulid}: stale-liveness cancellation — {} hash(es) live in \
                 volume but absent from materialised output; removing plan [{}]",
                stale_cancel.len(),
                describe_stale_cancel(&stale_cancel, &maps.lbamap),
            );
            // Cancelling is one of the two mechanisms `NoDanglingDeltaSource`
            // needs (docs/testing.md), so it fires whenever a delta increfs
            // its source between plan prep and apply. The warning above
            // reports that from state already in hand; the diagnostic below
            // rebuilds the lbamap from every segment on disk, which belongs
            // with the other drift detectors on the invariants switch.
            if crate::volume_invariants_enabled() {
                diagnose_stale_cancel(
                    &self.base_dir,
                    &self.ancestor_layers,
                    &maps.lbamap,
                    &stale_cancel,
                    &self.base_dir.join("index"),
                );
            }
            let _ = fs::remove_file(&tmp_path);
            let _ = fs::remove_file(&plan_path);
            // No rebuild: cancel means no segment was committed and no
            // lbamap mutation happened. Pre-claimant-tracking we kept a
            // defence-in-depth rebuild here against incremental drift,
            // but every lbamap mutation now records its claimant ULID
            // and the stress invariant `assert_lbamap_consistent`
            // catches divergence at the introducing site.
            self.assert_volume_invariants("apply_plan_apply_result_cancelled");
            return Ok(StagedApply::Cancelled);
        }

        let consumed: std::collections::HashSet<Ulid> = inputs.iter().copied().collect();
        // Every hash whose resolvability this apply can change: the
        // output's entries (registered in the index, merged as claims,
        // seeded into `entry_hashes` by the worker), the input-owned
        // hashes it removes, and the journal-tier hashes of the
        // segments it purges.
        let mut footprint = entry_hashes;
        footprint.extend(to_remove.iter().map(|(hash, _)| *hash));
        for input in &consumed {
            footprint.extend(maps.extent_index.journal_hashes(*input));
        }
        let derive = derive_start.elapsed();

        // Register the output's entries as the disk rebuild would,
        // gated on the current owner being a consumed input. Carried
        // Delta locations are `Full` against the bare `gc/<new_ulid>`
        // file (still at `tmp_path` until the rename below, hence the
        // layout read); the gc-carried promote flips them to `Cached`.
        let header_start = Instant::now();
        let delta_body_source =
            extentindex::DeltaBodySource::full_for_segment(&tmp_path, &entries, new_bss)?;
        let header = header_start.elapsed();
        let ctx = extentindex::SegmentRegistrationCtx {
            segment_id: new_ulid,
            body_section_start: new_bss,
            body_tier: extentindex::RegistrationBodyTier::Cached,
            delta_body_source,
            inline: extentindex::InlineSource::Section(&handoff_inline),
        };

        // `pre_apply_*` back the rename-failure restore below; the
        // resolvability gate keeps its own snapshots for the refusal
        // path.
        let pre_apply = self.maps.materialised();
        let mut merge = Duration::ZERO;
        let mut blocked: Vec<(u64, u32)> = Vec::new();
        let gate_ranges =
            LbaRanges::from_claims_and_ranges(&entries, input_claim_ranges.iter().copied());
        let gate_start = Instant::now();
        let gate = self.mutate_gated_on_resolvability(&footprint, &gate_ranges, |vol| {
            let merge_start = Instant::now();
            {
                let index = vol.maps.extent_index_mut();
                for (i, e) in entries.iter().enumerate() {
                    index.register_entry_consuming_inputs(e, i as u32, &ctx, &consumed)?;
                }
                for (hash, old_ulid) in &to_remove {
                    // `remove_owner_at` covers both `inner` and `deltas`. Plain
                    // `lookup` only checks `inner`, so a Delta-canonical hash
                    // would be left dangling — phantom entry pointing at a
                    // deleted input segment. Caught by
                    // `assert_extent_index_consistent` on
                    // `gc_delta_partial_death_compaction`.
                    index.remove_owner_at(hash, *old_ulid);
                }
                // Journal-tier bodies are keyed by segment, so a consumed
                // input's journal entries are dropped by segment rather than
                // by hash. A journal segment is only ever a bucket input as a
                // whole-dead tombstone, so this drops nothing still live; for
                // a durable input it is a no-op.
                for old_ulid in &consumed {
                    index.purge_journal_segment(*old_ulid);
                    index.purge_segment_delta_sources(*old_ulid);
                }
            }

            // Merge the GC output into the lbamap by per-entry conditional
            // insert. `insert_consuming_inputs` installs on a sub-range
            // whose existing claimant is one of the inputs this apply
            // consumes and tears down, or which holds this entry's hash at
            // a lower ULID (identical bytes — adopting the higher ULID
            // matches the rebuild). A claimant with different content, or a
            // higher ULID, keeps its sub-range: it marks a write the plan
            // did not carry (a WAL whose flush promote failed keeps
            // stamping claims below `new_ulid`). See
            // `docs/design/lbamap-claimant-tracking.md`,
            // `docs/finding-sweep-flush-claimant-bug.md`,
            // `gc_output_loses_to_live_write_applied_after_gc`, and
            // `gc_fold_must_not_resurrect_stale_claim_after_failed_checkpoint_flush`.
            let lbamap = vol.maps.lbamap_mut();
            for e in &entries {
                let took = lbamap.register_entry_consuming_inputs(e, new_ulid, &consumed);
                if !e.kind.is_canonical_only() && took < e.lba_length {
                    blocked.push((e.start_lba, e.lba_length));
                }
            }
            merge = merge_start.elapsed();
            Ok(())
        })?;
        let gate_check = gate_start.elapsed().saturating_sub(merge);

        if let ResolvabilityGate::Refused(orphaned) = gate {
            let detail = orphaned
                .sample
                .iter()
                .map(
                    |(lba, hash)| match to_remove.iter().find(|(h, _)| h == hash) {
                        Some((_, input)) => {
                            format!("lba={lba} hash={} was-at={input}", hash.to_hex())
                        }
                        None => format!("lba={lba} hash={}", hash.to_hex()),
                    },
                )
                .collect::<Vec<_>>()
                .join(", ");
            log::warn!(
                "plan {new_ulid}: refusing fold — {} lbamap-referenced hash(es) would \
                 be unresolvable through the extent index after apply, first {}: \
                 [{detail}]; dropping output and plan",
                orphaned.total,
                orphaned.sample.len(),
            );
            let _ = fs::remove_file(&tmp_path);
            let _ = fs::remove_file(&plan_path);
            self.assert_volume_invariants("apply_plan_apply_result_refused");
            return Ok(StagedApply::Cancelled);
        }

        // A carried entry that took fewer LBA blocks than it covers ran
        // into a claimant this apply does not consume. Above `new_ulid`
        // that is the ordinary plan-then-write race: the rebuild admits
        // by highest claimant ULID, so it prefers the same claimant the
        // merge just did and the two agree.
        //
        // Below `new_ulid` they part. The rebuild hands the range to the
        // fold, so committing buys a volume that reads correctly until
        // its next mount serves content the merge had refused. Reaching
        // that means the plan carried a hash another tier had already
        // superseded, which is what `gc_fork` building liveness from a
        // full rebuild plus a WAL replay exists to prevent. Refusing
        // keeps the two in step and leaves the next pass to re-derive.
        let superseded: Vec<(u64, u64, Ulid)> = blocked
            .iter()
            .flat_map(|(start, length)| {
                pre_apply
                    .lbamap
                    .extents_in_range(*start, start + *length as u64)
            })
            .filter(|x| x.claimant_ulid < new_ulid && !consumed.contains(&x.claimant_ulid))
            .map(|x| (x.range_start, x.range_end, x.claimant_ulid))
            .collect();
        if let Some(identity) = refusal_identity(SUPERSEDED_CARRY, &superseded, inputs.len()) {
            let detail = superseded
                .iter()
                .take(REFUSAL_SAMPLE_LIMIT)
                .map(|(from, to, claimant)| format!("lba={from}..{to} held-by={claimant}"))
                .collect::<Vec<_>>()
                .join(", ");
            log::error!(
                "plan {new_ulid}: refusing fold — {} lba run(s) carried by the plan are held by \
                 a lower-ULID claimant this apply does not consume, so the plan carries a hash \
                 another tier has superseded and a rebuild would prefer the fold, first {}: \
                 [{detail}]; dropping output and plan; {identity}",
                superseded.len(),
                superseded.len().min(REFUSAL_SAMPLE_LIMIT),
            );
            self.maps.restore(pre_apply);
            let _ = fs::remove_file(&tmp_path);
            let _ = fs::remove_file(&plan_path);
            self.assert_volume_invariants("apply_plan_apply_result_superseded");
            return Ok(StagedApply::Cancelled);
        }

        // The mirror of the check above. That one catches a fold claiming
        // an LBA it should not; this one catches a fold dropping an LBA
        // it should have carried. A claim the plan was right to drop
        // cannot still name a consumed input, because dropping it as dead
        // means something else overwrote it and that something is the
        // claimant. So a live claim held by an input over a range the
        // output does not cover says the plan read that LBA as dead while
        // the volume still serves it.
        //
        // The fold consumes its inputs, so on the next open that claim
        // has no segment to come from and the LBA reverts to whatever
        // older layer still holds it, or reads as a hole.
        //
        // Coverage is taken over LBA ranges rather than per entry: two of
        // an input's entries can cover one LBA, the earlier dead on the
        // anchor and dropped, with the later one carried.
        self.assert_claims_within_input_ranges(
            &pre_apply.lbamap,
            &consumed,
            &input_claim_ranges,
            new_ulid,
        );
        let covered = LbaRanges::from_claims(&entries);
        let dropped: Vec<(u64, u64, Ulid)> = input_claim_ranges
            .iter()
            .flat_map(|(start, length)| {
                pre_apply
                    .lbamap
                    .extents_in_range(*start, start + *length as u64)
            })
            .filter(|x| consumed.contains(&x.claimant_ulid))
            .filter_map(|x| {
                covered
                    .first_gap_in(x.range_start, x.range_end)
                    .map(|(from, to)| (from, to, x.claimant_ulid))
            })
            .collect();
        if let Some(identity) = refusal_identity(DROPPED_CLAIM, &dropped, inputs.len()) {
            let detail = dropped
                .iter()
                .take(REFUSAL_SAMPLE_LIMIT)
                .map(|(from, to, claimant)| format!("lba={from}..{to} held-by={claimant}"))
                .collect::<Vec<_>>()
                .join(", ");
            log::error!(
                "plan {new_ulid}: refusing fold — {} lba run(s) are claimed by an input this \
                 apply consumes and are absent from the output, so the plan read them dead while \
                 the volume still serves them, first {}: [{detail}]; dropping output and plan; \
                 {identity}",
                dropped.len(),
                dropped.len().min(REFUSAL_SAMPLE_LIMIT),
            );
            self.maps.restore(pre_apply);
            let _ = fs::remove_file(&tmp_path);
            let _ = fs::remove_file(&plan_path);
            self.assert_volume_invariants("apply_plan_apply_result_dropped_claim");
            return Ok(StagedApply::Cancelled);
        }

        let fs_start = Instant::now();
        for input in &inputs {
            if let Some(p) = segment::find_pending_file(&self.base_dir, &input.to_string()) {
                let _ = fs::remove_file(p);
            }
        }

        // Commit point. On a crash above this rename no fold exists on
        // disk and restart's rebuild never sees the output; the
        // in-memory registrations die with the process. On a crash
        // after it, the rebuild walks the same on-disk segments and
        // produces the same claimant ULIDs as the in-memory merge.
        let bare_path = gc_dir.join(new_ulid.to_string());
        if let Err(e) = fs::rename(&tmp_path, &bare_path) {
            self.maps.restore(pre_apply);
            return Err(e);
        }
        let _ = fs::remove_file(&plan_path);
        log::info!(
            "plan {new_ulid}: apply phases entries={} removed={} inputs={} \
             derive={:.1}ms header={:.1}ms merge={:.1}ms gate={:.1}ms fs={:.1}ms",
            entries.len(),
            to_remove.len(),
            inputs.len(),
            derive.as_secs_f64() * 1e3,
            header.as_secs_f64() * 1e3,
            merge.as_secs_f64() * 1e3,
            gate_check.as_secs_f64() * 1e3,
            fs_start.elapsed().as_secs_f64() * 1e3,
        );
        self.own_segments.insert(new_ulid);
        // Bump last_segment_ulid so a snapshot taken after this apply
        // (with no intervening write) mints its marker at or above the
        // fold output — the first-snapshot pinning invariant in
        // `Volume::snapshot` requires every own-segment extent-index
        // target to sit at or below the marker. The open-time rebuild
        // computes this from its gc/ + index/ scan; the live apply must
        // match it.
        if self.last_segment_ulid < Some(new_ulid) {
            self.last_segment_ulid = Some(new_ulid);
        }

        self.assert_volume_invariants("apply_plan_apply_result_applied");

        Ok(StagedApply::Applied)
    }

    /// Stress-only invariant: every live claim held by a segment this
    /// apply consumes lies inside the union of that segment's entry LBA
    /// ranges.
    ///
    /// It is what makes the bounded walks of the dropped-claim refusal
    /// and the resolvability gate complete rather than merely cheap. Both
    /// query the map over the inputs' own entry ranges, so a claim keyed
    /// to an input from outside them is one they cannot see. A fold that
    /// drops it reports clean, and a purge that strands it passes the
    /// gate.
    ///
    /// A claim reaches the map by registering an entry, and a split only
    /// narrows a range inside the original, so the property holds by
    /// construction. `LbaMap::set_claimant_if_matches` is the one path
    /// that re-keys claims rather than registering them, and it promotes
    /// a predecessor entry whole — including the part below the range it
    /// was handed. Its callers promote WAL writes, whose `insert` has
    /// already split any overlapping predecessor at that boundary, so
    /// the promoted claim is keyed at or above it. This asserts that
    /// rather than resting on it.
    fn assert_claims_within_input_ranges(
        &self,
        pre_apply: &lbamap::LbaMap,
        consumed: &std::collections::HashSet<Ulid>,
        input_claim_ranges: &[(u64, u32)],
        new_ulid: Ulid,
    ) {
        if !crate::volume_invariants_enabled() {
            return;
        }
        let within = LbaRanges::new(
            input_claim_ranges
                .iter()
                .map(|(start, length)| (*start, start + *length as u64)),
        );
        let outside: Vec<(u64, u64, Ulid)> = pre_apply
            .iter_entries_with_claimant()
            .filter(|(_, _, _, _, claimant)| consumed.contains(claimant))
            .filter_map(|(lba, length, _, _, claimant)| {
                within
                    .first_gap_in(lba, lba + length as u64)
                    .map(|(from, to)| (from, to, claimant))
            })
            .collect();
        if !outside.is_empty() {
            let mut msg = format!(
                "claims-within-input-ranges invariant violation during [plan {new_ulid} apply]: \
                 {} claim(s) held by a consumed input sit outside its entry ranges, so the \
                 bounded walks of the dropped-claim refusal and the resolvability gate cannot \
                 see them",
                outside.len()
            );
            for (from, to, claimant) in outside.iter().take(REFUSAL_SAMPLE_LIMIT) {
                msg.push_str(&format!("\n  lba={from}..{to} held-by={claimant}"));
            }
            panic!("{msg}");
        }
    }

    /// Stress-only invariant: rebuild the lbamap from disk + WAL and panic
    /// if the **content** (per-LBA hash) diverges from `self.lbamap`.
    /// Called at the end of every **structural** op (segment-shape
    /// mutations: repack apply, promote, GC plan apply, checkpoint flush,
    /// volume open) so any drift trips at the introducing site, not three
    /// operations later as a stale-cancel or oracle mismatch.
    ///
    /// Panics on any difference from the rebuild, in content or claimant.
    /// Where an apply installs, it stamps the claimant the rebuild would
    /// (a same-hash lower-ULID claim is adopted, not preserved — see
    /// `LbaMap::insert_consuming_inputs`), so a claimant difference is a
    /// real defect rather than a benign ordering hint.
    ///
    /// The admission rules differ. A GC apply keeps the range of any
    /// claimant it does not consume; the rebuild gives it to the highest
    /// ULID. The two reach the same winners while a plan carries no hash
    /// another tier has superseded, and this assert is what catches them
    /// parting.
    ///
    /// Deliberately **not** called from `write` / `write_zeroes` — those
    /// are high-frequency incremental `lbamap.insert` updates that have
    /// been stable for a long time, and any drift they introduced would
    /// be caught at the next structural op anyway. Asserting on every
    /// individual write doubles proptest runtime.
    ///
    /// Answers to [`crate::volume_invariants_enabled`], so the per-op
    /// rebuild costs only the runs that ask for it. `elide-coordinator`'s
    /// `proptest` feature turns it on for the `gc_proptest` suite, and
    /// `ELIDE_VOLUME_INVARIANTS=1` turns it on for a release binary —
    /// which is what catches drift bugs of the class fixed by sorting
    /// drain loops by ULID ascending.
    pub(in crate::volume) fn assert_lbamap_consistent(&self, caller: &'static str) {
        if !crate::volume_invariants_enabled() {
            return;
        }
        self.maps.materialised().lbamap.debug_assert_claim_counts();
        let first = match self.disk_lbamap_projection() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("assert_lbamap_consistent[{caller}]: rebuild failed: {e}");
                return;
            }
        };
        let candidates = self.diverging_lbas(&first);
        if candidates.is_empty() {
            return;
        }
        let second = match self.disk_lbamap_projection() {
            Ok(m) => m,
            Err(e) => {
                eprintln!("assert_lbamap_consistent[{caller}]: confirming rebuild failed: {e}");
                return;
            }
        };
        let confirmed: Vec<Diverge> = candidates
            .iter()
            .filter_map(|d| self.divergence_at(&second, d.lba))
            .collect();
        if confirmed.is_empty() {
            eprintln!(
                "assert_lbamap_consistent[{caller}]: {} LBA(s) diverged on one disk read and \
                 agreed on the next — the tree moved between the two",
                candidates.len()
            );
            return;
        }
        let mut msg = format!(
            "lbamap drift after [{caller}]: {} LBA(s) diverge from the disk rebuild \
             on content or claimant, on two consecutive reads",
            confirmed.len()
        );
        for d in &confirmed {
            msg.push_str(&format!(
                "\n  lba={} in_memory=({:?}, {:?}) disk_rebuild=({:?}, {:?})",
                d.lba,
                d.mem_hash.map(|h| h.to_hex().to_string()),
                d.mem_claimant.map(|u| u.to_string()),
                d.disk_hash.map(|h| h.to_hex().to_string()),
                d.disk_claimant.map(|u| u.to_string()),
            ));
        }
        panic!("{msg}");
    }

    /// The volume's LBA map as the on-disk state projects it: a full
    /// segment rebuild with every WAL replayed on top.
    ///
    /// Read file by file from a tree the worker thread is also writing,
    /// so the result is a composite of the states it passed through
    /// rather than any one of them. A caller comparing against it treats
    /// a single disagreement as a question, not an answer.
    fn disk_lbamap_projection(&self) -> io::Result<LbaMap> {
        let mut chain: Vec<(PathBuf, Option<String>)> = self
            .ancestor_layers
            .iter()
            .map(|l| (l.dir.clone(), l.branch_ulid.clone()))
            .collect();
        chain.push((self.base_dir.clone(), None));
        // Use the unverified rebuild — the signature verify is the dominant
        // per-segment cost and we don't need it for an in-memory consistency
        // check (signatures were already verified at Volume::open time, and
        // on-disk segments are immutable after creation).
        let mut fresh = lbamap::rebuild_segments_unverified(&chain)?;
        let wal_dir = self.base_dir.join("wal");
        if let Ok(entries) = fs::read_dir(&wal_dir) {
            let mut wals: Vec<(Ulid, PathBuf)> = Vec::new();
            for entry in entries.flatten() {
                let path = entry.path();
                if !entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let Some(wal_ulid) = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|s| Ulid::from_string(s).ok())
                else {
                    continue;
                };
                wals.push((wal_ulid, path));
            }
            replay_wals_into(wals, &mut fresh);
        }
        Ok(fresh)
    }

    fn divergence_at(&self, disk: &LbaMap, lba: u64) -> Option<Diverge> {
        let maps = self.maps.materialised();
        let mem_hash = maps.lbamap.hash_at(lba);
        let disk_hash = disk.hash_at(lba);
        let mem_claimant = maps.lbamap.claimant_at(lba);
        let disk_claimant = disk.claimant_at(lba);
        if mem_hash == disk_hash && mem_claimant == disk_claimant {
            return None;
        }
        Some(Diverge {
            lba,
            mem_hash,
            disk_hash,
            mem_claimant,
            disk_claimant,
        })
    }

    /// Up to [`DIVERGENCE_REPORT_CAP`] LBAs where memory and `disk` differ.
    fn diverging_lbas(&self, disk: &LbaMap) -> Vec<Diverge> {
        let mut all_lbas: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        for (lba, _, _, _) in self.maps.materialised().lbamap.iter_entries() {
            all_lbas.insert(lba);
        }
        for (lba, _, _, _) in disk.iter_entries() {
            all_lbas.insert(lba);
        }
        let mut diverging = Vec::new();
        for lba in all_lbas {
            if let Some(d) = self.divergence_at(disk, lba) {
                diverging.push(d);
                if diverging.len() >= DIVERGENCE_REPORT_CAP {
                    break;
                }
            }
        }
        diverging
    }

    /// Stress-only invariant: every *data* pending ULID must be greater
    /// than every promote-tier (`index/`) ULID on disk — the structural
    /// form of the production drain's discipline
    /// (`coordinator/upload.rs`), which uploads and promotes in
    /// ULID-ascending order, halting at the first failure, and defers
    /// pure-journal segments between cuts. A deferred journal segment
    /// therefore sits below committed data by design; for the journal
    /// tier the discipline is instead that journal commits ascending
    /// among themselves, so every *committed journal* ULID must be
    /// below every pending journal ULID. The lbamap rebuild admits
    /// flush claims by claimant ULID and compaction outputs under
    /// their inputs horizon, so rebuild winners are independent of
    /// tier either way; this assert is a canary for the drain ordering
    /// alone, firing structurally with a clearer message than the
    /// lbamap drift a broken drain would eventually cause.
    ///
    /// Compaction outputs are outside this ordering: a GC or repack ULID is
    /// minted at apply time and may legitimately exceed a write that was
    /// already pending when the pass forked. They are identified by the
    /// inputs list every compaction output carries, which is what separates
    /// them from the promoted flushes they share `index/` with.
    ///
    /// Answers to the same runtime switch, so the perf cost only applies
    /// to runs that ask for the checks.
    pub(in crate::volume) fn assert_pending_above_committed(&self, caller: &'static str) {
        if !crate::volume_invariants_enabled() {
            return;
        }
        let mut pending_files: Vec<(Ulid, std::path::PathBuf)> = Vec::new();
        for dir in segment::pending_generation_dirs(&self.base_dir) {
            match segment::read_ulid_dir_sorted(&dir) {
                Ok(us) => {
                    pending_files.extend(us.into_iter().map(|u| (u, dir.join(u.to_string()))))
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    eprintln!("assert_pending_above_committed[{caller}]: read pending failed: {e}");
                    return;
                }
            }
        }
        let pending_ulids: Vec<Ulid> = pending_files.iter().map(|(u, _)| *u).collect();
        if pending_ulids.is_empty() {
            return; // No pending — invariant vacuously holds.
        }

        // Partition pending by tier from each file's own index section.
        // A file whose index cannot be read counts as data, the stricter
        // side. The walk is upload-generation first then open, each
        // ascending — ULID order — so the first of each tier is its min.
        let is_journal = |path: &std::path::Path| -> bool {
            segment::read_segment_index(path)
                .map(|(_, entries, _)| entries.iter().any(|e| e.journal))
                .unwrap_or(false)
        };
        let mut pending_data_min: Option<Ulid> = None;
        let mut pending_journal_min: Option<Ulid> = None;
        for (u, path) in &pending_files {
            let slot = if is_journal(path) {
                &mut pending_journal_min
            } else {
                &mut pending_data_min
            };
            if slot.is_none() {
                *slot = Some(*u);
            }
            if pending_data_min.is_some() && pending_journal_min.is_some() {
                break;
            }
        }

        // A compaction output records the segments it consumed, so an empty
        // inputs list is what marks a segment as having arrived through the
        // drain. That is the property the ordering describes, and `index/`
        // holds both kinds — an applied plan writes its `.idx` there beside
        // the promoted flushes.
        let mut committed: Vec<(Ulid, std::path::PathBuf)> = Vec::new();
        if let Ok(idx_paths) = segment::collect_idx_files(&self.base_dir.join("index")) {
            for p in idx_paths {
                let Some(stem) = p.file_stem().and_then(|s| s.to_str()) else {
                    continue;
                };
                let Ok(u) = Ulid::from_string(stem) else {
                    continue;
                };
                committed.push((u, p));
            }
        }
        // Read only as far as the max: a compaction output is skipped and the
        // next candidate tried, so an ordered volume pays one index read.
        let drained_max = |committed: &[(Ulid, std::path::PathBuf)]| -> Option<Ulid> {
            let mut by_ulid: Vec<&(Ulid, std::path::PathBuf)> = committed.iter().collect();
            by_ulid.sort_by_key(|(u, _)| std::cmp::Reverse(*u));
            by_ulid
                .into_iter()
                .find(|(_, path)| {
                    segment::read_segment_index(path)
                        .map(|(_, _, inputs)| inputs.is_empty())
                        .unwrap_or(true)
                })
                .map(|(u, _)| *u)
        };
        let committed_max = drained_max(&committed);

        // Strict `>`: same-ULID-in-both-tiers (the mid-promote crash recovery
        // state where `pending/<u>` and `index/<u>.idx` coexist briefly) is
        // legitimate and the entries are byte-identical.
        if let (Some(c_max), Some(p_min)) = (committed_max, pending_data_min)
            && c_max > p_min
        {
            panic!(
                "pending-above-committed invariant violation after [{caller}]: \
                 max(promote-tier)={c_max} > min(pending data)={p_min} \
                 (a lower-ULID data segment is pending alongside a higher-ULID \
                 promote-tier segment; the drain promoted out of ULID order)"
            );
        }

        // Journal-tier ordering: a committed journal segment above a
        // pending one means journal uploaded out of ULID order — the
        // shape that would install a stale ring claim on rebuild. Only
        // committed ULIDs above the pending journal min can violate, so
        // only those pay an index read.
        if let Some(j_min) = pending_journal_min {
            for (u, path) in committed.iter().filter(|(u, _)| *u > j_min) {
                // A journal consolidation output carries an inputs list
                // and mints above writes that were pending when its pass
                // forked; only a drained flush violates this ordering.
                let committed_journal = segment::read_segment_index(path)
                    .map(|(_, entries, inputs)| {
                        inputs.is_empty() && entries.iter().any(|e| e.journal)
                    })
                    .unwrap_or(false);
                if committed_journal {
                    panic!(
                        "journal drain-order invariant violation after [{caller}]: \
                         committed journal segment {u} sorts above pending journal \
                         min {j_min} (journal uploaded out of ULID order)"
                    );
                }
            }
        }
    }

    /// Stress-only invariant: every hash in `self.extent_index` must
    /// point at a segment that exists somewhere on disk (in-memory may
    /// disagree with the rebuild on *which* specific segment owns the
    /// hash — see below — but at least one valid owner must exist),
    /// and every in-memory location's `segment_id` must name a segment
    /// the disk walk can still see.
    ///
    /// Catches the bug class "phantom or stale entry in extent_index":
    /// - **Phantom**: an entry whose hash isn't owned by any on-disk
    ///   segment (e.g. inserting a `ZERO_HASH` sentinel into
    ///   extent_index by mistake). Reads through this hash fail.
    /// - **Stale**: an entry pointing at a deleted segment (the segment
    ///   file was unlinked but extent_index wasn't updated). Reads fail
    ///   on file-not-found. Checked per-location against the walk's
    ///   live-segment set — ownership alone can't see it when a live
    ///   segment also owns the hash on disk (the carried-Delta dangle
    ///   shape: disk owner is the rewrite output, in-memory still
    ///   points at the deleted input).
    ///
    /// **Deliberately does NOT enforce specific segment_id agreement**
    /// between in-memory and disk-rebuild. The two representations
    /// legitimately diverge on which segment is named as the owner:
    /// - `extentindex::rebuild` walks segments in ULID-ascending order
    ///   and uses `insert_if_absent` (lowest non-journal ULID wins).
    /// - Several apply paths (reclaim, write-then-flush) use
    ///   unconditional `insert` and override with the newer ULID.
    ///
    /// Both representations are valid for read correctness — the body
    /// is identical across all segments claiming the hash, so any
    /// segment containing it can serve the read. The lowest-vs-newest
    /// distinction matters for downstream invariants (canonicality,
    /// dedup) but not for this check.
    ///
    /// **Also does NOT enforce "disk has more than memory" symmetry**.
    /// After a repack / GC apply prunes a hash from in-memory because
    /// the local segment owned it, an ancestor segment may still own
    /// the hash on disk — leaving in-memory with no entry while disk
    /// does. Reading that hash would then miss the dedup opportunity
    /// and store a duplicate, but doesn't fail outright. Pre-existing
    /// behaviour; out of scope for this invariant.
    ///
    /// Both DATA-canonical (`inner`) and Delta-canonical (`deltas`)
    /// hashes are checked.
    pub(in crate::volume) fn assert_extent_index_consistent(&self, caller: &'static str) {
        if !crate::volume_invariants_enabled() {
            return;
        }
        let mut chain: Vec<(PathBuf, Option<String>)> = self
            .ancestor_layers
            .iter()
            .map(|l| (l.dir.clone(), l.branch_ulid.clone()))
            .collect();
        chain.push((self.base_dir.clone(), None));
        let (disk_inner, disk_deltas, disk_journal, live_segments) =
            match extentindex::rebuild_owners_unverified(&chain, &self.journal) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("assert_extent_index_consistent[{caller}]: rebuild failed: {e}");
                    return;
                }
            };

        let mut diverging: Vec<String> = Vec::new();

        // For each in-memory hash, assert that disk owns it somewhere
        // (see docstring for why we don't compare specific segment_ids)
        // AND that the in-memory location names a segment the walk can
        // still see — a hash can be validly owned on disk while the
        // in-memory location dangles at a deleted file.
        for (hash, loc) in self.maps.materialised().extent_index.iter() {
            if diverging.len() >= 8 {
                break;
            }
            if !disk_inner.contains_key(hash) {
                diverging.push(format!(
                    "  hash={} in_memory_seg={} disk_seg=None (phantom inner)",
                    hash.to_hex(),
                    loc.segment_id,
                ));
            } else if !live_segments.contains(&loc.segment_id) {
                diverging.push(format!(
                    "  hash={} in_memory_seg={} (stale inner: points at deleted segment)",
                    hash.to_hex(),
                    loc.segment_id,
                ));
            }
        }
        for (hash, loc) in self.maps.materialised().extent_index.deltas_iter() {
            if diverging.len() >= 8 {
                break;
            }
            if !disk_deltas.contains_key(hash) {
                diverging.push(format!(
                    "  hash={} in_memory_delta_seg={} disk_delta_seg=None (phantom delta)",
                    hash.to_hex(),
                    loc.segment_id,
                ));
            } else if !live_segments.contains(&loc.segment_id) {
                diverging.push(format!(
                    "  hash={} in_memory_delta_seg={} (stale delta: points at deleted segment)",
                    hash.to_hex(),
                    loc.segment_id,
                ));
            }
        }
        // Journal-tier: every in-memory `(segment, hash)` body must be owned
        // by the disk walk at the same key and name a live segment. A
        // durable rebuild that mistakenly placed a journal hash in `inner`
        // (or vice versa) shows here as a phantom, so this is the executable
        // form of the tier-disjointness invariant.
        for ((seg, hash), _loc) in self.maps.materialised().extent_index.journal_iter() {
            if diverging.len() >= 8 {
                break;
            }
            if !disk_journal.contains(&(seg, hash)) {
                diverging.push(format!(
                    "  journal seg={seg} hash={} disk=None (phantom journal)",
                    hash.to_hex(),
                ));
            } else if !live_segments.contains(&seg) {
                diverging.push(format!(
                    "  journal seg={seg} hash={} (stale journal: points at deleted segment)",
                    hash.to_hex(),
                ));
            }
        }

        if !diverging.is_empty() {
            let mut msg = format!(
                "extent_index drift after [{caller}]: {} hash(es) diverge",
                diverging.len()
            );
            for line in &diverging {
                msg.push('\n');
                msg.push_str(line);
            }
            panic!("{msg}");
        }
    }

    /// Count every lbamap entry whose hash resolves through neither the
    /// extent index's DATA-style map nor its Delta-canonical map — the
    /// two lookups the read path performs — and keep the first
    /// `sample_limit` of them for diagnostics. An unresolvable hash
    /// means a read of that LBA fails at the extent_index lookup.
    ///
    /// Pure in-memory check (no disk rebuild) — linear in lbamap entry
    /// count, two HashMap lookups per entry. Catches the bug class
    /// "lbamap retains a hash claim while extent_index lost the body
    /// location" — typically an apply path that removed from
    /// extent_index without also pruning the lbamap claim. Backs the
    /// stress invariant below; the production gate checks its declared
    /// footprint through [`Self::unresolvable_footprint_hashes`], and
    /// this whole-map walk is the oracle that catches a mutation
    /// reaching outside its declaration.
    ///
    /// The scan runs to completion rather than stopping once the sample
    /// is full: `total` is what separates a handful of stranded claims
    /// from a systemic loss.
    ///
    /// `ZERO_HASH` is a sentinel meaning "this LBA reads as all zeros";
    /// it never resolves through extent_index by design. Skipped here.
    fn unresolvable_lbamap_hashes(&self, sample_limit: usize) -> UnresolvableHashes {
        let mut found = UnresolvableHashes::default();
        let maps = self.maps.materialised();
        for (lba, _len, hash, _anchor, claimant) in maps.lbamap.iter_entries_with_claimant() {
            if hash == ZERO_HASH {
                continue;
            }
            // A journal-tier LBA resolves through the `(claimant, hash)`
            // journal map, exactly as the read path does; a durable LBA
            // resolves through `inner` or the delta map.
            if maps.extent_index.lookup_journal(claimant, &hash).is_some() {
                continue;
            }
            if maps.extent_index.lookup(&hash).is_some() {
                continue;
            }
            // A delta-resolved hash is only readable if at least one of
            // its source options resolves as a DATA/Inline location —
            // exactly the read path's rule (`try_read_delta_extent`
            // consults the DATA map only for sources), so a delta whose
            // every source lacks one is as stranded as a hash with no
            // location.
            if maps.extent_index.lookup_delta(&hash).is_some_and(|loc| {
                loc.options
                    .iter()
                    .any(|opt| maps.extent_index.lookup(&opt.source_hash).is_some())
            }) {
                continue;
            }
            found.total += 1;
            if found.sample.len() < sample_limit {
                found.sample.push((lba, hash));
            }
        }
        found
    }

    /// Resolvability of the hashes in `footprint`, by the same rules as
    /// [`Self::unresolvable_lbamap_hashes`] and counted per stranded
    /// claim like it. An unclaimed hash resolves vacuously; a claimed
    /// one resolves for every claimant at once through `inner` or a
    /// delta with a resolving source, and otherwise per claim through
    /// the claimant's journal map — the one tier whose resolution is
    /// claimant-keyed, which takes a walk over the claims to pair each
    /// with its claimant.
    ///
    /// That walk covers the claims in `claim_ranges`, and it is shared:
    /// every hash the claimant-free tiers leave unresolved settles in
    /// one pass over those claims. A journal consolidation bucket lands
    /// its whole footprint in that residual — journal hashes resolve
    /// only through their claimant — so the walk's cost is per gate
    /// call and proportional to the bucket, with the wholly-durable
    /// footprints of GC folds and close-pass buckets skipping it.
    fn unresolvable_footprint_hashes(
        &self,
        footprint: &Blake3HashSet,
        claim_ranges: &LbaRanges,
        sample_limit: usize,
    ) -> UnresolvableHashes {
        let mut found = UnresolvableHashes::default();
        let maps = self.maps.materialised();
        let mut residual: Blake3HashSet = Blake3HashSet::default();
        for &hash in footprint {
            if hash == ZERO_HASH || maps.lbamap.claim_refcount(&hash) == 0 {
                continue;
            }
            if maps.extent_index.lookup(&hash).is_some() {
                continue;
            }
            if maps.extent_index.lookup_delta(&hash).is_some_and(|loc| {
                loc.options
                    .iter()
                    .any(|opt| maps.extent_index.lookup(&opt.source_hash).is_some())
            }) {
                continue;
            }
            residual.insert(hash);
        }
        if residual.is_empty() {
            return found;
        }
        log::info!(
            "resolvability gate: residual walk over {} journal-tier hash(es) in {} lba range(s)",
            residual.len(),
            claim_ranges.len(),
        );
        for (start, end) in claim_ranges.iter() {
            for x in maps.lbamap.extents_in_range(start, end) {
                if !residual.contains(&x.hash) {
                    continue;
                }
                if maps
                    .extent_index
                    .lookup_journal(x.claimant_ulid, &x.hash)
                    .is_none()
                {
                    found.total += 1;
                    if found.sample.len() < sample_limit {
                        found.sample.push((x.range_start, x.hash));
                    }
                }
            }
        }
        found
    }

    /// Run an in-memory extent-index/lbamap mutation behind the
    /// resolvability gate shared by the structural rewriters (GC fold
    /// apply, repack apply): snapshot both maps, run `mutate`, then
    /// require every claimed hash in `footprint` to resolve through the
    /// extent index — the read path's lookup. A miss means committing
    /// the mutation would strand an LBA claim with no body location
    /// (permanent read EIO that a rebuild reproduces once the inputs
    /// are unlinked), so both maps are restored and the orphans
    /// returned for the caller to log and refuse. Both maps are also
    /// restored when `mutate` itself errors.
    ///
    /// `footprint` is the caller's declaration of every hash whose
    /// resolvability the mutation can change: each hash it removes or
    /// registers in either map, each hash whose lbamap claim it merges,
    /// and each journal-tier hash of a segment it purges. `claim_ranges`
    /// is the matching declaration of every LBA whose claim the mutation
    /// can re-point or whose claimant it can purge, which are the entry
    /// ranges of each input it consumes and of the output it registers. A claim
    /// over an undeclared hash, or outside the declared ranges, can only
    /// strand through a mutation reaching outside its declaration; with
    /// the volume invariants switched on the whole map is re-checked
    /// after every structural op, which is where that class is caught.
    /// Checking the declaration rather than the map is what takes the
    /// gate from O(lbamap) per call to O(footprint + claims in range) —
    /// the difference between millions of lookups under the write mutex
    /// and thousands (#902).
    pub(in crate::volume) fn mutate_gated_on_resolvability(
        &mut self,
        footprint: &Blake3HashSet,
        claim_ranges: &LbaRanges,
        mutate: impl FnOnce(&mut Self) -> io::Result<()>,
    ) -> io::Result<ResolvabilityGate> {
        self.maps.absorb();
        let pre = self.maps.materialised();
        if let Err(e) = mutate(self) {
            self.maps.restore(pre);
            return Err(e);
        }
        let orphaned =
            self.unresolvable_footprint_hashes(footprint, claim_ranges, REFUSAL_SAMPLE_LIMIT);
        if orphaned.total == 0 {
            return Ok(ResolvabilityGate::Applied);
        }
        self.maps.restore(pre);
        Ok(ResolvabilityGate::Refused(orphaned))
    }

    /// Stress-only invariant: panic if [`Self::unresolvable_lbamap_hashes`]
    /// finds any entry after a structural op.
    pub(in crate::volume) fn assert_lbamap_hashes_resolvable(&self, caller: &'static str) {
        if !crate::volume_invariants_enabled() {
            return;
        }
        let unresolved = self.unresolvable_lbamap_hashes(REFUSAL_SAMPLE_LIMIT);
        if unresolved.total > 0 {
            let mut msg = format!(
                "lbamap-hashes-resolvable invariant violation after [{caller}]: \
                 {} hash(es) unresolvable through extent_index",
                unresolved.total
            );
            for (lba, hash) in &unresolved.sample {
                msg.push_str(&format!("\n  lba={lba} hash={}", hash.to_hex()));
            }
            panic!("{msg}");
        }
    }

    /// Stress-only invariant: the in-memory `own_segments` set equals the
    /// committed tier a fresh disk scan produces (`index/*.idx` ∪ bare
    /// `gc/`). A drift here is what trips the coordinator's gc own-segment
    /// divergence check and wedges plan emission.
    ///
    /// Checked at the end of `finalize_gc_handoff` only, not in the
    /// per-mutation umbrella. Equality holds solely when every committed-tier
    /// disk mutation has flowed through this volume: the coordinator's own
    /// divergence check tolerates a transient mismatch across the
    /// volume/coordinator process boundary, and the reproducer harness plants
    /// committed-tier files directly (`populate_cache`,
    /// `simulate_coord_gc_local`), so a fresh scan legitimately diverges
    /// mid-sequence. Finalize is where the leak the fix closes is born — a
    /// zero-entry tombstone dropped from disk but left in the set — so the
    /// check belongs there, matching the per-handoff granularity at which the
    /// coordinator validates the set in production.
    pub(in crate::volume) fn assert_own_segments_match_disk(&self, caller: &'static str) {
        if !crate::volume_invariants_enabled() {
            return;
        }
        let disk = segment::committed_tier_ulids(&self.base_dir)
            .expect("committed_tier_ulids scan for own_segments invariant");
        if self.own_segments != disk {
            let extra: Vec<Ulid> = self.own_segments.difference(&disk).copied().collect();
            let missing: Vec<Ulid> = disk.difference(&self.own_segments).copied().collect();
            panic!(
                "own_segments invariant violation after [{caller}]: in-memory set diverged \
                 from the committed tier on disk; in-memory-only={extra:?} disk-only={missing:?}"
            );
        }
    }

    /// Umbrella over every `assert_*` runtime invariant. Call this at
    /// the end of each structural state-mutating method instead of the
    /// individual asserts — adding a new invariant only requires
    /// extending this function, and every existing call site picks it
    /// up automatically.
    ///
    /// Each member returns immediately unless
    /// [`crate::volume_invariants_enabled`] says otherwise, so this
    /// umbrella costs a handful of loads when the checks are off.
    #[inline]
    pub(in crate::volume) fn assert_volume_invariants(&self, caller: &'static str) {
        self.assert_lbamap_consistent(caller);
        self.assert_pending_above_committed(caller);
        self.assert_extent_index_consistent(caller);
        self.assert_lbamap_hashes_resolvable(caller);
        self.maps
            .materialised()
            .extent_index
            .debug_assert_delta_source_counts();
    }

    /// Synchronous single-shot variant of the plan apply path — runs prep,
    /// execute, and apply inline on the current thread. Used by tests and
    /// any caller that doesn't have an actor behind a worker thread.
    fn apply_plan_handoff(
        &mut self,
        _gc_dir: &Path,
        plan_path: &Path,
        new_ulid: Ulid,
    ) -> io::Result<StagedApply> {
        let Some(plan) = read_plan_for_apply(plan_path, new_ulid) else {
            return Ok(StagedApply::Cancelled);
        };
        let job = self.prepare_plan_apply(plan_path.to_path_buf(), new_ulid, plan);
        let result = crate::actor::execute_gc_plan_apply(job)?;
        self.apply_plan_apply_result(result)
    }

    /// Promote a segment to the local cache after confirmed S3 upload.
    ///
    /// Called in response to the coordinator's `promote <ulid>` IPC, which is
    /// sent only after a confirmed S3 upload.
    ///
    /// Writes `index/<ulid>.idx` first (restoring the invariant that idx presence
    /// ↔ segment confirmed in S3), then `cache/<ulid>.body` and
    /// `cache/<ulid>.present`.
    ///
    /// **Drain path** (`pending/<ulid>` exists): also deletes `pending/<ulid>`.
    /// The coordinator never deletes `pending/` directly.
    ///
    /// **GC path** (bare `gc/<ulid>` exists): also deletes `index/<old>.idx` for
    /// each segment consumed by the GC handoff (read from the bare `gc/<ulid>`
    /// segment header's `inputs` field). This happens after writing the new idx
    /// so there is never a window where no idx covers the affected LBAs.  The
    /// `gc/<ulid>` body file is also deleted here — it has already been copied
    /// into `cache/<ulid>.body`, and deleting it inside the actor (rather than
    /// from the coordinator) keeps every mutation of `gc/` serialised with the
    /// idle-tick `apply_gc_handoffs` path.
    ///
    /// Idempotent: if `cache/<ulid>.body` already exists and no source
    /// remains in `pending/` or `gc/` the function returns `Ok(())` without
    /// re-writing.
    pub fn promote_segment(&mut self, ulid: Ulid) -> io::Result<()> {
        let job = match self.prepare_promote_segment(ulid)? {
            PromoteSegmentPrep::AlreadyPromoted => return Ok(()),
            PromoteSegmentPrep::Job(job) => *job,
        };
        let result = crate::actor::execute_promote_segment(job)?;
        self.apply_promote_segment_result(result)
    }

    /// Prep phase of `promote_segment`. Pure function of the on-disk
    /// layout — runs on the actor thread in microseconds.
    ///
    /// Selects the source segment (`pending/<ulid>` > `gc/<ulid>` >
    /// body-exists early-return) and builds a [`PromoteSegmentJob`] for
    /// the worker. The source-preference ordering is load-bearing: if a
    /// previous promote committed its idx/body but crashed before the
    /// apply phase, `pending/<ulid>` (or `gc/<ulid>`) will still exist
    /// and the retry must take the full path, not the idempotent
    /// early-return. See `promote_segment_recovers_mid_apply_crash`
    /// regression test.
    ///
    /// Ensures `index/` and `cache/` exist so the worker never touches
    /// the directory structure.
    /// Close the open generation and pack what it sealed, on the calling
    /// thread. Returns the segment count of the generation as it was
    /// sealed, which is what the cut reports, `None` when the open
    /// generation was empty and nothing rotated.
    ///
    /// Used by tests and inline callers holding a `&mut Volume`.
    /// Production goes through the actor, where the pass runs on the
    /// worker.
    pub fn close_generation(&mut self) -> io::Result<Option<u32>> {
        let CloseGenerationPrep { rotated, job } = self.prepare_close_generation()?;
        if let Some(job) = job {
            let result = crate::actor::execute_repack(job)?;
            let (_, consumed) = self.apply_repack_result(result)?;
            self.remove_consumed_inputs(&consumed)?;
        }
        Ok(rotated)
    }

    pub fn prepare_promote_segment(&self, ulid: Ulid) -> io::Result<PromoteSegmentPrep> {
        let ulid_str = ulid.to_string();
        let cache_dir = self.base_dir.join("cache");
        let body_path = cache_dir.join(format!("{ulid_str}.body"));
        let present_path = cache_dir.join(format!("{ulid_str}.present"));
        let pending_path = segment::find_pending_file(&self.base_dir, &ulid_str);
        let gc_path = self.base_dir.join("gc").join(&ulid_str);
        let index_dir = self.base_dir.join("index");
        let idx_path = index_dir.join(format!("{ulid_str}.idx"));

        let (src_path, is_drain) = if let Some(pending_path) = pending_path {
            (pending_path, true)
        } else if gc_path.try_exists()? {
            (gc_path, false)
        } else if body_path.try_exists()? {
            return Ok(PromoteSegmentPrep::AlreadyPromoted);
        } else {
            return Err(io::Error::other(format!(
                "promote {ulid_str}: segment not found in pending/ or gc/"
            )));
        };

        fs::create_dir_all(&index_dir)?;
        fs::create_dir_all(&cache_dir)?;

        Ok(PromoteSegmentPrep::Job(Box::new(PromoteSegmentJob {
            ulid,
            src_path,
            is_drain,
            body_path,
            present_path,
            idx_path,
            verifying_key: self.verifying_key,
            segment_cache: Arc::clone(&self.segment_cache),
        })))
    }

    /// Apply phase of `promote_segment`. Consumes the worker's result.
    ///
    /// Drain path: transitions extent-index entries from
    /// `BodySource::Local` (pointing at `pending/<ulid>`) to
    /// `BodySource::Cached(n)` (pointing at the new `cache/<ulid>.body`).
    /// The CAS check (`segment_id == ulid`) makes the rewrite a no-op for
    /// any entry a concurrent write has already superseded. Then evicts
    /// the segment's cached fd, deletes the delta sidecar if present,
    /// and deletes `pending/<ulid>`.
    ///
    /// GC tombstone path: deletes `index/<old>.idx` for every consumed
    /// input. No extent-index updates (tombstones carry no entries).
    ///
    /// GC carried path: same as tombstone plus the extent-index state
    /// stays untouched — the `apply_gc_handoffs` step already rewrote
    /// the extent index to `BodySource::Cached` against the fresh ULID.
    pub fn apply_promote_segment_result(&mut self, result: PromoteSegmentResult) -> io::Result<()> {
        let PromoteSegmentResult {
            ulid,
            is_drain,
            parsed,
            inline,
            tombstone,
        } = result;
        let entries = &parsed.entries;
        let inputs = &parsed.inputs;
        let body_section_start = parsed.body_section_start;
        let index_dir = self.base_dir.join("index");
        self.own_segments.insert(ulid);

        if tombstone {
            for old_ulid in inputs {
                let _ = fs::remove_file(index_dir.join(format!("{old_ulid}.idx")));
                self.own_segments.remove(old_ulid);
            }
            self.assert_volume_invariants("apply_promote_segment_result_tombstone");
            return Ok(());
        }

        if is_drain {
            // Evict before the CAS so readers arriving post-publish
            // open the new cache body, not a stale handle to the
            // soon-to-be-deleted pending file.
            self.evict_cached_segment(ulid);

            // Install the in-memory mirror of the all-bits-set
            // `cache/<ulid>.present` that `promote_to_cache` just
            // wrote. The hot read path uses this for the per-entry
            // presence check on `BodyOnly` cache hits — without it
            // the rebuild-on-startup path would be the only source,
            // which is too late for live drains.
            self.maps.extent_index_mut().set_segment_presence(
                ulid,
                Arc::new(extentindex::SegmentPresence::from_data_kinds(entries)),
            );

            for (i, entry) in entries.iter().enumerate() {
                if !entry.kind.has_body_bytes() || entry.journal {
                    continue;
                }
                // Durable entries only: the CAS is gated on this segment
                // already owning the hash in `inner`. Journal-tier entries
                // are flipped to Cached below via the journal map.
                let owns = self
                    .maps
                    .materialised()
                    .extent_index
                    .lookup(&entry.hash)
                    .is_some_and(|loc| loc.segment_id == ulid);
                if !owns {
                    continue;
                }
                let idata = if entry.kind.is_inline() {
                    let start = entry.stored_offset as usize;
                    let end = start + entry.stored_length as usize;
                    if end <= inline.len() {
                        Some(inline[start..end].into())
                    } else {
                        continue;
                    }
                } else {
                    None
                };
                self.maps.extent_index_mut().insert(
                    entry.hash,
                    extentindex::ExtentLocation {
                        segment_id: ulid,
                        body_offset: entry.stored_offset,
                        body_length: entry.stored_length,
                        codec: entry.codec,
                        body_source: BodySource::Cached(i as u32),
                        body_section_start,
                        inline_data: idata,
                    },
                );
            }
            // Flip journal-tier bodies for this segment from Local to
            // Cached, mirroring the durable loop above. The presence-bitmap
            // index for each hash is its first entry position, resolved
            // through a prebuilt index: blake3::Hash equality is
            // constant-time, so a linear scan per hash costs seconds at
            // full segment size.
            let mut entry_idx = crate::blake3_id_hasher::Blake3HashMap::<u32>::default();
            for (i, e) in entries.iter().enumerate() {
                entry_idx.entry(e.hash).or_insert(i as u32);
            }
            self.maps
                .extent_index_mut()
                .promote_journal_segment_to_cache(ulid, body_section_start, |h| {
                    entry_idx.get(h).copied()
                });

            // Delta entries: the delta blob has moved from inline in
            // the now-deleted pending file to the standalone
            // `cache/<ulid>.delta` sidecar, so flip
            // `DeltaBodySource::Full → Cached`. CAS against
            // `segment_id == ulid` so a concurrent delta-repack or
            // reclaim that re-pointed the hash at a newer segment
            // wins.
            for entry in entries.iter() {
                if !entry.kind.is_delta() {
                    continue;
                }
                self.maps
                    .extent_index_mut()
                    .flip_delta_body_source_to_cached_if_matches(&entry.hash, ulid);
            }

            let ulid_str = ulid.to_string();
            if let Some(delta_path) =
                segment::find_pending_file(&self.base_dir, &format!("{ulid_str}.delta"))
            {
                let _ = fs::remove_file(&delta_path);
            }
            let pending_path = segment::find_pending_file(&self.base_dir, &ulid_str)
                .ok_or_else(|| io::Error::other(format!("pending segment {ulid_str} missing")))?;
            fs::remove_file(&pending_path)?;
        } else {
            // GC carried path: delete each consumed input's idx.
            for old_ulid in inputs {
                let _ = fs::remove_file(index_dir.join(format!("{old_ulid}.idx")));
                self.own_segments.remove(old_ulid);
            }

            // GC carried entries already reference `BodySource::Cached(idx)`
            // against `ulid` (planted by `apply_gc_handoffs`); now that
            // `promote_to_cache` has produced `cache/<ulid>.body` +
            // `cache/<ulid>.present`, install the in-memory presence
            // mirror so reads against the new cache shape succeed
            // without consulting `.present` on disk.
            self.maps.extent_index_mut().set_segment_presence(
                ulid,
                Arc::new(extentindex::SegmentPresence::from_data_kinds(entries)),
            );

            // Carried Delta entries: the delta blob now lives in the
            // `cache/<ulid>.delta` sidecar rather than the bare
            // `gc/<ulid>` file, so flip `DeltaBodySource::Full →
            // Cached`. CAS against `segment_id == ulid` so a
            // concurrent repoint at a newer segment wins.
            for entry in entries.iter() {
                if !entry.kind.is_delta() {
                    continue;
                }
                self.maps
                    .extent_index_mut()
                    .flip_delta_body_source_to_cached_if_matches(&entry.hash, ulid);
            }
        }
        let caller = if is_drain {
            "apply_promote_segment_result_drain"
        } else {
            "apply_promote_segment_result_gc_carried"
        };
        self.assert_volume_invariants(caller);
        Ok(())
    }

    /// Finalize a completed GC handoff by deleting the bare `gc/<ulid>` file.
    ///
    /// Called by the coordinator after the new segment has been uploaded to
    /// S3, `promote_segment` has moved it into the local cache, and the old
    /// segments have been deleted from S3. This is the last step in the
    /// handoff lifecycle and must happen AFTER the S3 delete so that a crash
    /// between the two cannot leak old-segment objects in S3 — the bare file's
    /// presence keeps `apply_done_handoffs` eligible to retry the delete, and
    /// only removing the bare file removes that eligibility.
    ///
    /// Routing through the actor (rather than letting the coordinator unlink
    /// `gc/<ulid>` directly) keeps every mutation of `gc/` serialised with the
    /// idle-tick `apply_gc_handoffs` path, so there is no race between the
    /// coordinator removing a file and the actor reading it.
    pub fn finalize_gc_handoff(&mut self, ulid: Ulid) -> io::Result<()> {
        let gc_dir = self.base_dir.join("gc");
        let bare = gc_dir.join(ulid.to_string());
        match fs::remove_file(&bare) {
            Ok(()) => {}
            // Idempotent: already removed by a previous finalize or a
            // promote that ran before we flipped the protocol.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // Best-effort cleanup of any stray `.plan` sibling left over from
        // a crash between the bare rename and `.plan` removal.
        let _ = fs::remove_file(gc_dir.join(format!("{ulid}.plan")));
        // A zero-entry (tombstone) handoff is never promoted to `index/`
        // (it carries no body to upload), so the bare `gc/<ulid>` deleted
        // above was its only committed-tier file. Its `promote_segment`
        // still inserted it into `own_segments`, so drop it now or the set
        // keeps a member no disk scan can see — the off-by-one that wedges
        // the gc own-segment divergence check. A live output has an
        // `index/<ulid>.idx` from its promote and must stay.
        if !self
            .base_dir
            .join("index")
            .join(format!("{ulid}.idx"))
            .exists()
        {
            self.own_segments.remove(&ulid);
        }
        self.assert_volume_invariants("finalize_gc_handoff");
        self.assert_own_segments_match_disk("finalize_gc_handoff");
        Ok(())
    }

    /// Flush the current WAL to a segment in this node's `pending/`, update
    /// the extent index, and clear `pending`. The WAL file is deleted.
    ///
    /// If `pending` is empty (nothing written since last flush), the
    /// WAL file is deleted directly without writing a segment.
    ///
    /// Evict `segment_id` from the file handle cache.
    ///
    /// The read path (`read_extents`) maintains an LRU cache of open segment
    /// fds keyed by segment ULID, with a `SegmentLayout` that controls how
    /// body offsets are computed (`BodyOnly` files start at offset 0; `Full`
    /// segment files add `body_section_start`).
    ///
    /// Callers must evict whenever a segment's on-disk representation changes
    /// in a way that invalidates the cached fd or layout:
    ///
    /// - **`flush_wal_to_pending`** — WAL file deleted, replaced by a
    ///   pending segment with a different byte layout.
    /// - **`promote_segment`** (drain path) — `pending/<ulid>` deleted,
    ///   replaced by `cache/<ulid>.body` (body-section-relative offsets),
    ///   so `body_section_start` changes from the full-segment value to 0.
    /// - **`apply_gc_handoffs`** (repack) — old segment deleted and
    ///   replaced by a denser segment with reassigned body offsets.
    ///
    /// Without eviction the cached fd silently serves stale data or — worse —
    /// applies `body_section_start` from the new extent index entry against
    /// the old file layout, seeking past the body section.
    pub(in crate::volume) fn evict_cached_segment(&self, segment_id: Ulid) {
        lock_file_cache(&self.file_cache).evict(segment_id);
    }

    /// Flush the current WAL to a fresh `pending/<segment_ulid>` and leave
    /// the volume in a no-WAL state. The next write lazily opens a new WAL.
    fn flush_wal_to_pending(&mut self) -> io::Result<()> {
        // Mint a fresh segment ULID distinct from the old WAL's ULID so
        // `wal/<old_wal_ulid>` and `pending/<segment_ulid>` never collide
        // on the same path. With a shared ULID, a stale cold-cache reader
        // that loaded the pre-promote snapshot could look up the old WAL
        // ULID, fall through to `pending/<same_ulid>`, and read WAL-relative
        // offsets as if they were segment-relative — silent wrong bytes.
        // A distinct segment ULID turns that cold-cache race into NotFound.
        //
        // Wastes one mint when the WAL is empty or absent (the early return
        // below skips the segment write). The mint is cheap and monotonic;
        // the extra advance is harmless.
        let segment_ulid = self.mint.next();
        self.flush_wal_to_pending_as(segment_ulid)
    }

    /// Like `flush_wal_to_pending`, but uses the caller-provided `segment_ulid`
    /// rather than minting a fresh one.
    ///
    /// Used by `gc_checkpoint` to give the flushed WAL segment a ULID that has
    /// been pre-minted above the GC output ULIDs, so that the pending segment
    /// sorts correctly above GC outputs on crash-recovery rebuild.
    ///
    /// The WAL file itself retains its original name (the WAL ULID) — only the
    /// output segment in `pending/` receives `segment_ulid`.
    ///
    /// Leaves `self.wal = None` on success — the next write lazily opens a
    /// fresh WAL. No-op when no WAL is currently open.
    pub(in crate::volume) fn flush_wal_to_pending_as(
        &mut self,
        segment_ulid: Ulid,
    ) -> io::Result<()> {
        if self.wal.is_none() {
            return Ok(());
        }
        if self.pending.is_empty() {
            if let Some(open) = self.wal.take() {
                fs::remove_file(&open.path)?;
            }
            return Ok(());
        }
        let job = self.take_wal_into_promote_job(segment_ulid)?;
        match crate::actor::execute_promote(job, &mut crate::actor::PriorSourceCache::default()) {
            Ok(result) => self.apply_promote(&result),
            Err(failure) => {
                self.restore_failed_promote(*failure.job)?;
                Err(failure.error)
            }
        }
    }

    /// Inverse of `take_wal_into_promote_job`: reopen the WAL for
    /// continued appending and put the entries back, so a failed promote
    /// loses nothing. The WAL file's records were all fully committed, so
    /// its current length is the valid size.
    ///
    /// The reopened WAL gets a **fresh** ULID (file renamed to match, so
    /// crash-recovery replay stamps the same claimant): a checkpoint may
    /// have minted bucket ULIDs above the old one between the take and
    /// the failure, and reusing it would stamp subsequent writes below
    /// those buckets — violating the "new WAL above any prior checkpoint
    /// ULID" invariant `ensure_wal_open` maintains.
    fn restore_failed_promote(&mut self, job: PromoteJob) -> io::Result<()> {
        let new_ulid = self.mint.next();
        let wal_dir = self.base_dir.join("wal");
        let new_path = wal_dir.join(new_ulid.to_string());
        fs::rename(&job.old_wal_path, &new_path)?;
        // Recovery finds the epoch under its new name only once the
        // rename's directory entry is durable.
        crate::segment::fsync_dir(&wal_dir)?;
        let size = fs::metadata(&new_path)?.len();
        let wal = writelog::WriteLog::reopen(&new_path, size)?;

        // The live maps reference the WAL's old identity: extent-index
        // locations point body-bearing hashes at `(old_wal_ulid, offset)`
        // and lbamap claims carry `old_wal_ulid` as claimant. Re-key both
        // to the new identity, mirroring `apply_promoted_entries` — the
        // CAS/hash-match guards leave anything a concurrent writer has
        // superseded untouched.
        {
            let journal_part = job.journal.as_ref().map(|j| &j.partition);
            let partitions = std::iter::once(&job.primary).chain(journal_part);
            let (lbamap, index) = self.maps.base_mut();
            for part in partitions {
                for (write, old_wal_offset) in part.iter() {
                    let entry = &write.entry;
                    match entry.kind {
                        EntryKind::Data
                        | EntryKind::Inline
                        | EntryKind::CanonicalData
                        | EntryKind::CanonicalInline => {}
                        EntryKind::DedupRef
                        | EntryKind::Zero
                        | EntryKind::Delta
                        | EntryKind::CanonicalDelta => continue,
                    }
                    if entry.journal {
                        // Journal bodies live in the disjoint `(segment, hash)`
                        // map keyed under the WAL ULID; re-key them to the
                        // restored WAL identity alongside the lbamap claimant.
                        index.rekey_journal_owner(job.old_wal_ulid, new_ulid, entry.hash);
                    } else if let Some(old_wal_offset) = old_wal_offset {
                        index.rekey_owner(entry.hash, job.old_wal_ulid, old_wal_offset, new_ulid);
                    }
                }
                for write in part.writes() {
                    let entry = &write.entry;
                    if entry.kind.is_canonical_only() {
                        continue;
                    }
                    let claim_hash = if entry.kind == EntryKind::Zero {
                        ZERO_HASH
                    } else {
                        entry.hash
                    };
                    lbamap.set_claimant_if_matches(
                        entry.start_lba,
                        entry.lba_length,
                        claim_hash,
                        new_ulid,
                    );
                }
            }
        }
        self.evict_cached_segment(job.old_wal_ulid);

        self.wal = Some(OpenWal {
            wal,
            ulid: new_ulid,
            path: new_path,
        });
        self.pending = job.primary.into_writes();
        if let Some(j) = job.journal {
            self.pending.extend(j.partition.into_writes());
        }
        Ok(())
    }

    /// Promote the current WAL to a pending segment. The next write lazily
    /// opens a fresh WAL via `ensure_wal_open`.
    fn promote(&mut self) -> io::Result<()> {
        self.flush_wal_to_pending()
    }

    /// Run the delta tiers on this volume's promotes, and persist the
    /// resemblance sketches later promotes select sources by.
    ///
    /// Both follow `ELIDE_ENABLE_DELTA` and `ELIDE_ENABLE_SKETCH` at open.
    /// This sets them for one volume, which is what lets a test exercise
    /// tiers the environment leaves parked.
    pub fn set_delta_policy(&mut self, enabled: bool, persist_sketches: bool) {
        self.delta_policy = jobs::DeltaPolicy {
            enabled,
            persist_sketches,
        };
    }

    /// In-process checkpoint of the fork at the current point in the
    /// segment sequence. **Not** the production path — the coordinator-
    /// driven snapshot flow (see `docs/plans/coordinator-driven-snapshot-plan.md`)
    /// orchestrates flush → S3 drain → signed manifest → upload.
    ///
    /// This in-process variant exists for tests and offline tooling that
    /// need a self-contained snapshot without a running coordinator. It
    /// flushes the WAL to `pending/`, promotes every pending segment so it
    /// appears under `index/`, signs the `.manifest` file over the
    /// resulting full index, then writes the `snapshots/<ulid>` marker.
    ///
    /// Note that promotion writes `cache/<ulid>.body` + `index/<ulid>.idx`
    /// without uploading to S3; in production only the coordinator is
    /// allowed to promote, and only after confirming upload.
    ///
    /// If no new data has been committed since the latest existing snapshot
    /// (nothing in `pending/` or `index/` sorts after it), the existing
    /// snapshot ULID is returned without writing a new marker.
    ///
    /// Returns the snapshot ULID.
    pub fn snapshot(&mut self) -> io::Result<Ulid> {
        // Flush WAL to pending/ first so the snapshot marker sorts after it.
        self.flush_wal_to_pending()?;

        // If no new segments have been committed since the last snapshot, reuse
        // the existing snapshot ULID rather than writing a new marker. The WAL
        // stays closed — the next write lazily opens a fresh one.
        if !self.has_new_segments
            && let Some(latest_str) = latest_snapshot(&self.base_dir)?
        {
            return Ok(latest_str);
        }

        // Write a new snapshot marker, reusing the last segment's ULID so the
        // branch point is self-describing. Falls back to a fresh ULID only when
        // no segments exist (e.g. first snapshot on an empty fork).
        let snap_ulid = self.last_segment_ulid.unwrap_or_else(|| self.mint.next());

        // First-snapshot pinning invariant (see docs/architecture.md § Dedup).
        // Every DedupRef written in this volume resolves through the extent
        // index to a canonical `Data` entry; the entry's segment_id is the
        // DedupRef's target. At snapshot time, every own-volume target must
        // have ULID <= snap_ulid so that advancing the floor pins every live
        // DedupRef atomically. Violation would mean a future write raced the
        // snapshot and leaked an unpinned reference — a correctness bug.
        // Ancestor targets are pinned by their own volume's floor and are
        // excluded from this check.
        #[cfg(debug_assertions)]
        {
            let mut own_segments: std::collections::HashSet<Ulid> =
                std::collections::HashSet::new();
            if let Some(open) = self.wal.as_ref() {
                own_segments.insert(open.ulid);
            }
            for dir in segment::pending_generation_dirs(&self.base_dir) {
                let Ok(entries) = fs::read_dir(&dir) else {
                    continue;
                };
                for entry in entries.flatten() {
                    if let Some(s) = entry.file_name().to_str()
                        && !s.contains('.')
                        && let Ok(u) = Ulid::from_string(s)
                    {
                        own_segments.insert(u);
                    }
                }
            }
            if let Ok(idx_files) = segment::collect_idx_files(&self.base_dir.join("index")) {
                for p in idx_files {
                    if let Some(u) = p
                        .file_stem()
                        .and_then(|n| n.to_str())
                        .and_then(|s| Ulid::from_string(s).ok())
                    {
                        own_segments.insert(u);
                    }
                }
            }
            for (_hash, loc) in self.maps.materialised().extent_index.iter() {
                if own_segments.contains(&loc.segment_id) {
                    debug_assert!(
                        loc.segment_id <= snap_ulid,
                        "first-snapshot pinning invariant violated: extent index \
                         references own segment {} which is > snap_ulid {}",
                        loc.segment_id,
                        snap_ulid,
                    );
                }
            }
        }

        // Promote every pending segment so the signed `.manifest` file
        // can enumerate a complete `index/` rather than a partial view.
        // In production this is driven by the coordinator after confirming
        // S3 upload; the in-process variant skips the upload step.
        let mut pending_ulids: Vec<Ulid> = Vec::new();
        for dir in segment::pending_generation_dirs(&self.base_dir) {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(s) = name.to_str() else { continue };
                if s.contains('.') {
                    continue;
                }
                if let Ok(u) = Ulid::from_string(s) {
                    pending_ulids.push(u);
                }
            }
        }
        pending_ulids.sort();
        for u in pending_ulids {
            self.promote_segment(u)?;
        }

        let snapshots_dir = self.base_dir.join("snapshots");
        fs::create_dir_all(&snapshots_dir)?;

        // Collect every live segment ULID under `index/` for the signed
        // manifest. The shared filter drops any segment whose entries
        // are all dead under the liveness predicate — see
        // [`crate::actor::live_index_segments`]. Reclamation of those
        // segment files is GC's job; this is a manifest-only filter.
        let index_dir = self.base_dir.join("index");
        let maps = self.maps.materialised();
        let index_ulids = crate::actor::live_index_segments(
            &index_dir,
            &maps.extent_index,
            &maps.lbamap,
            &self.verifying_key,
            &self.segment_cache,
        )?;
        // The manifest's existence under `snapshots/` is the
        // snapshot's existence; `write_snapshot_manifest` writes
        // atomically, so a partial sequence leaves no snapshot visible.
        crate::signing::write_snapshot_manifest(
            &self.base_dir,
            self.signer.as_ref(),
            &snap_ulid,
            &index_ulids,
        )?;
        self.has_new_segments = false;

        // The WAL was closed by `flush_wal_to_pending` above. The next write
        // lazily opens a fresh one.
        Ok(snap_ulid)
    }

    /// Sign and write a snapshot manifest under `snapshots/<snap_ulid>.manifest`,
    /// then write the `snapshots/<snap_ulid>` marker.
    ///
    /// Called by the coordinator after a synchronous drain has moved every
    /// in-flight segment out of `pending/` and into `index/`. The volume
    /// enumerates its own `index/` at the moment of the call: the result is a
    /// full list of every segment ULID that belongs to this volume as of the
    /// snapshot, *not* a delta over the previous snapshot. See
    /// `docs/plans/coordinator-driven-snapshot-plan.md` for the rationale.
    ///
    /// The manifest is signed with the volume's private key so ancestor
    /// verification at open time can trust it via the embedded
    /// `parent_pubkey` in the child's `volume.provenance`.
    ///
    /// The caller selects `snap_ulid` — typically the max ULID in `index/`
    /// at the moment the lock is acquired, or a fresh ULID if `index/` is
    /// empty. The volume does not validate the choice.
    /// Synchronous wrapper around the offloadable prep / execute / apply
    /// trio. The actor uses [`Self::prepare_sign_snapshot_manifest`],
    /// [`crate::actor::execute_sign_snapshot_manifest`], and
    /// [`Self::apply_sign_snapshot_manifest_result`] directly so the
    /// worker thread runs the heavy middle — `index/` enumeration,
    /// Ed25519 sign, manifest fsync, marker write — off the request
    /// channel. This wrapper exists for tests and any inline callers.
    pub fn sign_snapshot_manifest(&mut self, snap_ulid: Ulid) -> io::Result<()> {
        self.sign_snapshot_manifest_kind(snap_ulid, crate::signing::SnapshotKind::User)
    }

    /// As [`Self::sign_snapshot_manifest`] but explicitly chooses
    /// between the stable user manifest (`<ulid>.manifest`) and the
    /// ephemeral stop-snapshot variant (`<ulid>-stop.manifest`). The
    /// signed payload is identical for both.
    pub fn sign_snapshot_manifest_kind(
        &mut self,
        snap_ulid: Ulid,
        kind: crate::signing::SnapshotKind,
    ) -> io::Result<()> {
        let job = self.prepare_sign_snapshot_manifest_kind(snap_ulid, kind);
        let result = crate::actor::execute_sign_snapshot_manifest(job)?;
        self.apply_sign_snapshot_manifest_result(result);
        Ok(())
    }

    /// Prep phase of `sign_snapshot_manifest` — runs on the actor
    /// thread. Cheap: clones the signer / index / lbamap / cache `Arc`s
    /// and captures the base dir and target ULID. The worker uses the
    /// extent index and lbamap snapshots to filter fully-dead segments
    /// out of the manifest — see [`crate::actor::execute_sign_snapshot_manifest`].
    pub fn prepare_sign_snapshot_manifest(&self, snap_ulid: Ulid) -> SignSnapshotManifestJob {
        self.prepare_sign_snapshot_manifest_kind(snap_ulid, crate::signing::SnapshotKind::User)
    }

    /// Kind-explicit variant of [`Self::prepare_sign_snapshot_manifest`].
    pub fn prepare_sign_snapshot_manifest_kind(
        &self,
        snap_ulid: Ulid,
        kind: crate::signing::SnapshotKind,
    ) -> SignSnapshotManifestJob {
        let maps = self.maps.materialised();
        SignSnapshotManifestJob {
            snap_ulid,
            base_dir: self.base_dir.clone(),
            signer: Arc::clone(&self.signer),
            extent_index: maps.extent_index,
            lbamap: maps.lbamap,
            verifying_key: self.verifying_key,
            segment_cache: Arc::clone(&self.segment_cache),
            kind,
        }
    }

    /// Apply phase of `sign_snapshot_manifest` — runs on the actor
    /// thread after the worker has written the manifest and marker.
    /// Clears `has_new_segments` so subsequent snapshot attempts with
    /// no new data reuse the marker instead of re-signing.
    pub fn apply_sign_snapshot_manifest_result(&mut self, _result: SignSnapshotManifestResult) {
        self.has_new_segments = false;
    }

    /// Locate the segment body file for `segment_id` within this fork's
    /// ancestry chain.
    ///
    /// Search order:
    ///   1. Current fork: `wal/`, `pending/`, bare `gc/<id>`, `cache/<id>.body`
    ///   2. Ancestor forks (newest first): `pending/`, bare `gc/<id>`, `cache/<id>.body`
    ///   3. Demand-fetch via fetcher (writes three-file format to `cache/`)
    ///
    /// For full segment files (`wal/`, `pending/`, bare `gc/<id>`), body reads
    /// use absolute file offsets (`ExtentLocation.body_offset`). For cached
    /// body files (`cache/<id>.body`), the file IS the body section, so reads
    /// use body-relative offsets — consistent with how `extentindex::rebuild`
    /// stores offsets for cached entries.
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
            &self.maps.base().extent_index,
            body_section_start,
            body_source,
        )
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn ancestor_count(&self) -> usize {
        self.ancestor_layers.len()
    }

    pub fn lbamap_len(&self) -> usize {
        self.maps.materialised().lbamap.len()
    }

    /// Attach a `SegmentFetcher` for demand-fetch on segment cache miss.
    ///
    /// Once set, `find_segment_file` will call the fetcher after all local
    /// directories are checked, caching the result in `cache/`.
    pub fn set_fetcher(&mut self, fetcher: BoxFetcher) {
        self.fetcher = Some(fetcher);
    }

    /// Return all fork directories in the ancestry chain, oldest-first,
    /// with the current fork last.
    ///
    /// Used by callers building a `SegmentFetcher` that needs to know which
    /// forks to search on a cache miss.
    pub fn fork_dirs(&self) -> Vec<PathBuf> {
        self.ancestor_layers
            .iter()
            .map(|l| l.dir.clone())
            .chain(std::iter::once(self.base_dir.clone()))
            .collect()
    }

    /// Return the current LBA map and extent index as shared references.
    ///
    /// Called by `VolumeActor` after every mutation to publish a new `ReadSnapshot`.
    /// The layered maps, for a publish to clone.
    pub fn map_layers(&self) -> &MapLayers {
        &self.maps
    }

    /// One map each, with the open WAL's delta folded in. Two `Arc::clone`
    /// calls when the delta is empty.
    pub fn snapshot_maps(&self) -> (Arc<lbamap::LbaMap>, Arc<extentindex::ExtentIndex>) {
        let maps = self.maps.materialised();
        (maps.lbamap, maps.extent_index)
    }

    /// Shared handle on the volume's dmat cache — the single per-process
    /// instance every reader must use (see [`read::DmatCache`]).
    pub fn dmat_cache_handle(&self) -> read::DmatCache {
        Arc::clone(&self.dmat_cache)
    }

    /// Ancestor layers for this fork, oldest-first.
    pub fn ancestor_layers(&self) -> &[AncestorLayer] {
        &self.ancestor_layers
    }

    /// The attached demand-fetch fetcher, if any.
    pub fn fetcher(&self) -> Option<&BoxFetcher> {
        self.fetcher.as_ref()
    }

    /// Flush the current WAL to a pending segment if it contains any entries.
    /// No-op if the WAL is empty. Called by the idle-flush path in the daemon.
    pub fn flush_wal(&mut self) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        self.promote()
    }

    /// True if the WAL should be promoted to a pending segment.
    ///
    /// Trips on either the byte cap ([`FLUSH_THRESHOLD`]) or the entry-count
    /// cap ([`FLUSH_ENTRY_THRESHOLD`]) — the latter bounds the index region
    /// for workloads (heavy dedup, lots of inline / zero writes) that produce
    /// many thin entries without advancing the byte cap.
    ///
    /// The actor calls this after every write reply and promotes if true.
    /// The check is separated from `write()` so that writes are always fast
    /// (WAL append only) and the promotion cost is never borne by the write caller.
    pub fn needs_promote(&self) -> bool {
        self.wal.as_ref().is_some_and(|o| {
            o.wal.size() >= FLUSH_THRESHOLD || self.pending.len() >= FLUSH_ENTRY_THRESHOLD
        })
    }

    pub fn promote_for_test(&mut self) -> io::Result<()> {
        self.promote()
    }

    // ------------------------------------------------------------------
    // Off-actor promote: prep + apply
    // ------------------------------------------------------------------

    /// The open WAL's file, for a caller that fsyncs it after releasing
    /// the volume lock. `None` when no WAL is open; that state is already
    /// durable.
    ///
    /// Appends landing between this call and the sync ride the same
    /// barrier. Reaching further than the caller asked for still
    /// satisfies the caller.
    pub fn wal_sync_handle(&self) -> Option<Arc<fs::File>> {
        self.wal.as_ref().map(|open| open.wal.sync_handle())
    }

    /// Prep phase of the off-actor promote.  Runs on the actor thread.
    ///
    /// Takes the current WAL, snapshots CAS precondition tokens, takes
    /// ownership of `pending`, and mints a fresh segment ULID.
    /// Returns `None` if the WAL is empty or absent (nothing to promote).
    ///
    /// After this call the volume's `wal` is `None`. The next write will
    /// lazily open a fresh WAL via `ensure_wal_open`; writes resume
    /// immediately. The returned [`PromoteJob`] is sent to the worker
    /// thread for the heavy segment-write work.
    pub fn prepare_promote(&mut self) -> io::Result<Option<PromoteJob>> {
        if self.pending.is_empty() {
            return Ok(None);
        }

        // The old WAL's fsync is deferred to the worker thread (see
        // `execute_promote`), so that the actor returns to the select
        // loop without blocking on disk I/O.  `VolumeActor::Flush`
        // fsyncs rotated WALs itself, so FLUSH's durability contract
        // holds while the promote is still in flight.

        let segment_ulid = self.mint.next();
        Ok(Some(self.take_wal_into_promote_job(segment_ulid)?))
    }

    /// Close the open WAL into a [`PromoteJob`] at `segment_ulid` for the
    /// caller to dispatch. `None` when the WAL held nothing to promote;
    /// an empty WAL file is removed.
    ///
    /// Callers mint `segment_ulid` after every output ULID their operation
    /// reserves, so the promoted segment sorts above them. The WAL that
    /// opens next sits above both — `ensure_wal_open` mints fresh.
    pub(in crate::volume) fn rotate_wal_into_promote(
        &mut self,
        segment_ulid: Ulid,
    ) -> io::Result<Option<PromoteJob>> {
        if self.pending.is_empty() {
            if let Some(open) = self.wal.take() {
                fs::remove_file(&open.path)?;
            }
            return Ok(None);
        }
        Ok(Some(self.take_wal_into_promote_job(segment_ulid)?))
    }

    /// Fold one formation's dedup counters into `self.dedup_mint_stats` and log
    /// the running totals.
    fn record_dedup_mint_stats(&mut self, wal_ulid: Ulid, stats: DedupMintStats) {
        if stats.minted_entries > 0 {
            self.dedup_mint_stats.minted_entries += stats.minted_entries;
            self.dedup_mint_stats.wal_body_bytes += stats.wal_body_bytes;
            log::info!(
                "formation {wal_ulid}: {} dedup-ref minted, {} WAL body bytes dropped \
                 (cumulative {} entries / {} bytes)",
                stats.minted_entries,
                stats.wal_body_bytes,
                self.dedup_mint_stats.minted_entries,
                self.dedup_mint_stats.wal_body_bytes
            );
        }
    }

    /// Take the open WAL and pending writes into a [`PromoteJob`] targeting
    /// `segment_ulid`.
    ///
    /// Errors if no WAL is open — callers check `pending` is non-empty first,
    /// and the write path only ever appends entries after opening the WAL.
    fn take_wal_into_promote_job(&mut self, segment_ulid: Ulid) -> io::Result<PromoteJob> {
        let open = self
            .wal
            .take()
            .ok_or_else(|| io::Error::other("internal: pending writes non-empty but wal absent"))?;
        self.maps.absorb();
        let maps = self.maps.materialised();
        let (primary, jpart, dedup) = stage_pending_for_promote(
            std::mem::take(&mut self.pending),
            &maps.extent_index,
            open.ulid,
            &self.journal,
            &mut self.mint,
        );
        self.record_dedup_mint_stats(open.ulid, dedup);
        let mut search_dirs: Vec<PathBuf> = vec![self.base_dir.clone()];
        for layer in &self.ancestor_layers {
            if !search_dirs.contains(&layer.dir) {
                search_dirs.push(layer.dir.clone());
            }
        }
        let delta = jobs::PromoteDeltaSpec {
            policy: self.delta_policy,
            extent_index: maps.extent_index,
            sketch_index: Arc::clone(&self.sketch_index),
            search_dirs,
            lbamap: maps.lbamap,
            prior: Some(PromoteDeltaPrior {
                base_dir: self.base_dir.clone(),
                journal_ranges: self.journal.clone(),
            }),
        };
        // Poll for a first-ever window derivation while the taken epoch
        // is fully staged, so subsequent takes route window LBAs to the
        // journal tier.
        if !self.journal_derived {
            self.poll_derive_and_flip();
        }
        Ok(PromoteJob {
            segment_ulid,
            old_wal_ulid: open.ulid,
            old_wal_path: open.path,
            primary,
            signer: Arc::clone(&self.signer),
            pending_dir: segment::pending_open_dir(&self.base_dir),
            delta,
            journal: jpart,
        })
    }

    /// Apply phase of the off-actor promote.  Runs on the actor thread
    /// after the worker has written the segment.
    ///
    /// Updates the extent index (CAS), deletes the old WAL, and evicts
    /// the cached file descriptor.  The caller must call `publish_snapshot`
    /// after this to make the changes visible to readers.
    pub fn apply_promote(&mut self, result: &PromoteResult) -> io::Result<()> {
        self.has_new_segments = true;
        // The journal segment ULID is the higher of the pair; the
        // snapshot-pinning invariant needs the max here.
        self.last_segment_ulid = Some(
            result
                .journal
                .as_ref()
                .map(|j| j.segment_ulid)
                .unwrap_or(result.segment_ulid)
                .max(result.segment_ulid),
        );

        let (lbamap, extent_index) = self.maps.base_mut();
        apply_promoted_entries(extent_index, lbamap, result)?;

        // Extend the candidate map with what this promote sketched, so the
        // next formation can source against it. The journal partition
        // carries no sketches, so only the primary share is offered.
        let sketches = Arc::make_mut(&mut self.sketch_index);
        for entry in &result.entries {
            sketches.insert_entry(entry);
        }

        // Delete old WAL — only after the extent index is updated.
        if let Err(e) = fs::remove_file(&result.old_wal_path) {
            log::warn!(
                "failed to delete old WAL {}: {e}",
                result.old_wal_path.display()
            );
        }
        self.evict_cached_segment(result.old_wal_ulid);
        Ok(())
    }

    // ------------------------------------------------------------------
    // Off-actor GC checkpoint: prep + complete
    // ------------------------------------------------------------------

    /// Prep phase of the off-actor GC checkpoint.
    ///
    /// Mints two ULIDs (`u_gc < u_flush`), snapshots CAS
    /// tokens, takes entries, and builds a [`PromoteJob`] using `u_flush`
    /// as the segment ULID. No fresh WAL is opened here — the next write
    /// lazily opens one at `mint.next()`, which is guaranteed >
    /// `u_flush > u_gc` by monotonicity. This avoids churning a new
    /// empty WAL file on every idle GC tick.
    ///
    /// The old WAL's `fsync()` is deferred to the worker thread (see
    /// `execute_promote`), identical to the write-path promote offload.
    /// The parked GC reply only resolves after the worker returns, so
    /// the caller of `GcCheckpoint` still observes a durable old WAL
    /// before acting on `u_gc`.
    ///
    /// Returns `job: None` when the WAL was empty or absent (no segment
    /// to promote). The checkpoint then has no promote of its own to
    /// wait for.
    ///
    /// Always mints ULIDs. An earlier Idle short-circuit (cfcb132) was
    /// reverted because the coordinator's per-tick `promote_wal` IPC
    /// empties `pending` before this call, which would make the
    /// Idle check fire on every tick under active writes and silently
    /// disable GC. We still run GC on every tick; we only stop creating
    /// a new WAL file when there is nothing to promote.
    pub fn prepare_gc_checkpoint(&mut self, max_buckets: usize) -> io::Result<GcCheckpointPrep> {
        let GcCheckpointUlids { u_buckets, u_flush } = self.mint_gc_checkpoint_ulids(max_buckets);
        let job = self.rotate_wal_into_promote(u_flush)?;
        Ok(GcCheckpointPrep {
            u_buckets,
            u_flush,
            job,
        })
    }

    /// Commitment to the current committed-tier `own_segments` set,
    /// carried in the `gc_checkpoint` reply for the coordinator's
    /// divergence check.
    pub fn own_segments_commitment(&self) -> crate::volume_ipc::SegmentSetCommitment {
        crate::volume_ipc::SegmentSetCommitment::from_ulids(self.own_segments.iter().copied())
    }
}

// --- helpers ---

/// Scan `<base_dir>/gc/` for plan handoff files that need processing.
///
/// Sweeps stale volume-owned `<ulid>.tmp` scratch files, applies bare-wins
/// shortcuts for `.plan` + bare co-presence, and returns a list of
/// `(plan_path, new_ulid)` pairs for the caller to dispatch to the worker.
/// Also returns a count of handoffs that were already applied (bare wins).
///
/// Coordinator-owned `<ulid>.plan.tmp` scratch is left alone — the coord
/// may be actively writing it; the coord sweeps its own stale scratch at
/// the start of each GC pass.
///
/// Every decision it makes reads `gc/` alone, so it needs the directory
/// and none of the volume's in-memory state.
pub fn scan_plan_handoffs(base_dir: &Path) -> io::Result<(Vec<(PathBuf, Ulid)>, usize)> {
    let gc_dir = base_dir.join("gc");
    if !gc_dir.try_exists()? {
        return Ok((Vec::new(), 0));
    }

    // Pass 1: sweep stale volume-owned `<ulid>.tmp` scratch files.
    for entry in fs::read_dir(&gc_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_suffix(".tmp") else {
            continue;
        };
        if Ulid::from_string(stem).is_ok() {
            let _ = fs::remove_file(entry.path());
        }
    }

    // Pass 2: collect `.plan` files.
    let mut plans: Vec<(String, Ulid)> = fs::read_dir(&gc_dir)?
        .filter_map(|e| {
            let e = e.ok()?;
            let name = e.file_name().into_string().ok()?;
            let stem = name.strip_suffix(".plan")?;
            let ulid = Ulid::from_string(stem).ok()?;
            Some((name, ulid))
        })
        .collect();
    plans.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut to_process = Vec::new();
    let mut already_applied = 0usize;
    for (plan_name, new_ulid) in plans {
        let plan_path = gc_dir.join(&plan_name);
        let bare_path = gc_dir.join(new_ulid.to_string());

        // Crash recovery: `.plan` + bare → bare wins, drop `.plan`.
        if bare_path.try_exists()? {
            let _ = fs::remove_file(&plan_path);
            already_applied += 1;
            continue;
        }

        to_process.push((plan_path, new_ulid));
    }

    Ok((to_process, already_applied))
}

/// Read and validate `<ulid>.plan`, ready for [`Volume::prepare_plan_apply`].
///
/// `None` means the plan is rejected up front (parse failure, ULID mismatch,
/// empty inputs); the file is removed here and the caller treats it as a
/// cancelled handoff.
pub fn read_plan_for_apply(plan_path: &Path, new_ulid: Ulid) -> Option<rewrite_plan::RewritePlan> {
    let plan = match rewrite_plan::RewritePlan::read(plan_path) {
        Ok(p) => p,
        Err(e) => {
            log::warn!(
                "plan {new_ulid}: parse failed ({e}); removing {}",
                plan_path.display()
            );
            let _ = fs::remove_file(plan_path);
            return None;
        }
    };
    if plan.new_ulid != new_ulid {
        log::warn!(
            "plan ulid mismatch: filename={new_ulid} plan={}; removing",
            plan.new_ulid
        );
        let _ = fs::remove_file(plan_path);
        return None;
    }
    if plan.inputs().is_empty() {
        log::warn!("plan {new_ulid} has no inputs; removing");
        let _ = fs::remove_file(plan_path);
        return None;
    }
    Some(plan)
}

/// Rebuild the lbamap from disk and compare against the live in-memory
/// lbamap at each cancelled LBA. Logs only; never mutates volume state.
///
/// `AGREE` marks a genuine live reference, `DIVERGE` an in-memory lbamap
/// that drifted from what a rebuild produces.
fn diagnose_stale_cancel(
    base_dir: &Path,
    ancestor_layers: &[AncestorLayer],
    in_memory: &lbamap::LbaMap,
    stale: &[(blake3::Hash, Ulid)],
    index_dir: &Path,
) {
    let mut chain: Vec<(PathBuf, Option<String>)> = ancestor_layers
        .iter()
        .map(|l| (l.dir.clone(), l.branch_ulid.clone()))
        .collect();
    chain.push((base_dir.to_path_buf(), None));

    let rebuilt = match lbamap::rebuild_segments(&chain) {
        Ok(m) => m,
        Err(e) => {
            log::warn!("stale-liveness diagnostic rebuild failed: {e}");
            return;
        }
    };

    for (hash, input_ulid) in stale.iter().take(8) {
        let lbas = lbas_for_hash_in_segment(index_dir, input_ulid, hash);
        for (lba, len) in &lbas {
            let mem = in_memory.hash_at(*lba);
            let disk = rebuilt.hash_at(*lba);
            log::warn!(
                "stale-cancel diag: lba={lba}+{len} hash={} input={input_ulid} \
                 in_memory={:?} disk_rebuild={:?} {}",
                hash.to_hex(),
                mem.map(|h| h.to_hex().to_string()),
                disk.map(|h| h.to_hex().to_string()),
                if mem == disk { "AGREE" } else { "DIVERGE" }
            );
        }
    }
}

/// Read `index/<input_ulid>.idx` and return every entry matching `hash`.
fn lbas_for_hash_in_segment(
    index_dir: &Path,
    input_ulid: &Ulid,
    hash: &blake3::Hash,
) -> Vec<(u64, u32)> {
    let idx_path = index_dir.join(format!("{input_ulid}.idx"));
    let Ok((_, entries, _)) = segment::read_segment_index(&idx_path) else {
        return Vec::new();
    };
    entries
        .into_iter()
        .filter(|e| &e.hash == hash)
        .map(|e| (e.start_lba, e.lba_length))
        .collect()
}

/// Render a diagnostic summary of the stale-liveness hashes so the log
/// pinpoints which hash diverged and how it stays live in this volume.
/// Caps at the first 3 entries; trailing `...+N` indicates more.
fn describe_stale_cancel(stale: &[(blake3::Hash, Ulid)], lbamap: &lbamap::LbaMap) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (i, (hash, input_ulid)) in stale.iter().take(3).enumerate() {
        if i > 0 {
            out.push_str("; ");
        }
        let lbas = lbamap.lbas_for_hash(hash);
        let claim_refcount = lbamap.claim_refcount(hash);
        let _ = write!(
            out,
            "hash={} input={input_ulid} lbas={lbas:?} claim_refcount={claim_refcount}{}",
            hash.to_hex(),
            if claim_refcount == 0 {
                " (live as a delta source via the closure)"
            } else {
                ""
            },
        );
    }
    if stale.len() > 3 {
        let _ = write!(out, "; ...+{} more", stale.len() - 3);
    }
    out
}

/// Filename of the per-volume liveness lock within a fork directory.
///
/// A serving process holds an exclusive `flock` on this file for the lifetime
/// of its open [`Volume`] (see [`acquire_lock`]). The kernel releases an flock
/// when its holder exits by any means, including a host reboot, so the lock's
/// held/free state — not a recorded pid — answers "is this volume being
/// served".
pub const VOLUME_LOCK_FILE: &str = "volume.lock";

/// True when a serving process holds the exclusive [`VOLUME_LOCK_FILE`] flock
/// for `dir`.
///
/// Probes with a non-blocking *shared* `flock`: it fails only when the exclusive
/// lock is held, so concurrent probes (also shared) never read each other as a
/// server. Acquiring it (released again immediately) or a missing lock file
/// means it is free. Opens read-only and never creates the file — only a
/// serving process does that.
pub fn lock_is_held(dir: &Path) -> bool {
    let Ok(file) = fs::File::open(dir.join(VOLUME_LOCK_FILE)) else {
        return false;
    };
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockSharedNonblock).is_err()
}

/// Acquire an exclusive non-blocking flock on `<dir>/volume.lock`.
///
/// Creates the lock file if it does not exist. Returns the open `File` — the
/// lock is held for as long as this handle is open and released when dropped.
/// Returns an error immediately if the lock is already held by another process.
fn acquire_lock(dir: &Path) -> io::Result<nix::fcntl::Flock<fs::File>> {
    let file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(false)
        .open(dir.join(VOLUME_LOCK_FILE))?;
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, e)| io::Error::from(e))
}

#[cfg(test)]
mod lock_tests {
    use super::{VOLUME_LOCK_FILE, lock_is_held};

    #[test]
    fn absent_lock_file_is_not_held() {
        let d = tempfile::TempDir::new().unwrap();
        assert!(!lock_is_held(d.path()));
    }

    #[test]
    fn free_lock_is_not_held() {
        let d = tempfile::TempDir::new().unwrap();
        std::fs::write(d.path().join(VOLUME_LOCK_FILE), "").unwrap();
        assert!(!lock_is_held(d.path()));
    }

    #[test]
    fn exclusive_holder_reads_as_held() {
        let d = tempfile::TempDir::new().unwrap();
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(d.path().join(VOLUME_LOCK_FILE))
            .unwrap();
        let _held = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| e)
            .unwrap();
        assert!(lock_is_held(d.path()));
    }

    #[test]
    fn concurrent_shared_probe_is_not_held() {
        // A simultaneous probe also takes a shared lock; it must not read
        // another probe as a live server — only the exclusive lock counts.
        let d = tempfile::TempDir::new().unwrap();
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(d.path().join(VOLUME_LOCK_FILE))
            .unwrap();
        let _probe = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockSharedNonblock)
            .map_err(|(_, e)| e)
            .unwrap();
        assert!(!lock_is_held(d.path()));
    }
}

#[cfg(test)]
pub(in crate::volume) mod test_util;
#[cfg(test)]
mod tests;
