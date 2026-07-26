//! Worker offload types — the jobs the actor hands to worker threads and the
//! results it takes back. Every field is `Send`.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use ulid::Ulid;

use crate::{extentindex, rewrite_plan, segment, segment_cache};

use super::{
    AncestorLayer, BoxFetcher, ReclaimJob, ReclaimResult, RepackJob, RepackResult, StagedApply,
};

/// Data needed by the worker thread to write a pending segment.
pub struct PromoteJob {
    pub segment_ulid: Ulid,
    pub old_wal_ulid: Ulid,
    pub old_wal_path: PathBuf,
    pub entries: Vec<segment::SegmentEntry>,
    /// CAS precondition tokens: the `body_offset` each Data/Inline entry had
    /// in the extent index at prep time.
    pub pre_promote_offsets: Vec<Option<u64>>,
    /// Where each Data/Inline entry's bytes live in the WAL. Bodies stay in
    /// the WAL until the segment is written.
    pub body_offsets: Vec<Option<u64>>,
    pub signer: Arc<dyn segment::SegmentSigner>,
    pub pending_dir: PathBuf,
    pub delta: PromoteDeltaSpec,
    /// The epoch's journal-window share, present when the volume has a
    /// journal window and the epoch touched journal LBAs.
    pub journal: Option<JournalPartition>,
}

/// The journal-window share of one promote: entries whose LBAs fall in the
/// guest filesystem's jbd2 journal window form their own segment, so the whole
/// segment dies together as the journal wraps.
///
/// `segment_ulid` is minted after the primary's, so the journal segment sorts
/// above the data segment. Load-bearing for rebuild: the ownership
/// displacement rule keeps canonicals in the data segment, and a journal entry
/// minted as a DedupRef then points at a lower ULID as required.
pub struct JournalPartition {
    pub segment_ulid: Ulid,
    pub entries: Vec<segment::SegmentEntry>,
    pub pre_promote_offsets: Vec<Option<u64>>,
    pub body_offsets: Vec<Option<u64>>,
}

/// Where a promote's delta tiers find dictionaries.
pub struct PromoteDeltaSpec {
    /// Live extent-index snapshot for resolving source bodies by hash. Any
    /// canonical serving a hash yields identical bytes, so the live index
    /// suffices.
    pub extent_index: Arc<extentindex::ExtentIndex>,
    /// Candidate map over the lineage's persisted sketches, for selecting
    /// sources by content resemblance.
    pub sketch_index: Arc<crate::sketch_index::SketchIndex>,
    /// Body-lookup roots: the fork directory first, then ancestor dirs.
    pub search_dirs: Vec<PathBuf>,
    /// Which hashes were referenced at prep time. An unreferenced source is
    /// declined: deltaing against one pins bytes GC was about to free and gets
    /// the GC plan that omitted them refused on apply.
    pub referenced: crate::lbamap::ReferencedHashes,
    /// The sealed snapshot the same-LBA tier sources from, present for the
    /// volumes that have one. The resemblance tier needs only the candidate
    /// map.
    pub prior: Option<PromoteDeltaPrior>,
}

pub struct PromoteDeltaPrior {
    pub base_dir: PathBuf,
    pub snap_ulid: Ulid,
    /// The volume's journal window, whose LBAs are excluded from the source
    /// map so dictionaries come from filesystem content alone.
    pub journal_ranges: crate::journal::JournalRanges,
}

/// A promote that failed on the worker, carrying the job back intact. The old
/// WAL file on disk remains the durable copy of the epoch, so the job can be
/// re-dispatched as-is once the failure cause (e.g. ENOSPC) clears. Boxed so
/// the error variant stays small.
pub struct PromoteFailure {
    pub error: io::Error,
    pub job: Box<PromoteJob>,
}

impl std::fmt::Debug for PromoteFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PromoteFailure")
            .field("error", &self.error)
            .field("segment_ulid", &self.job.segment_ulid)
            .finish_non_exhaustive()
    }
}

/// Result returned by the worker thread after writing the segment.
pub struct PromoteResult {
    pub segment_ulid: Ulid,
    pub old_wal_ulid: Ulid,
    pub old_wal_path: PathBuf,
    pub body_section_start: u64,
    pub entries: Vec<segment::SegmentEntry>,
    pub pre_promote_offsets: Vec<Option<u64>>,
    /// Byte length of the body region holding Data entries; the delta region
    /// (blobs for entries the worker converted to `Delta`) starts at
    /// `body_section_start + delta_region_body_length`.
    pub delta_region_body_length: u64,
    pub journal: Option<JournalSegmentResult>,
}

/// The journal segment written alongside the primary. Its bodies are all
/// stored whole.
pub struct JournalSegmentResult {
    pub segment_ulid: Ulid,
    pub body_section_start: u64,
    pub entries: Vec<segment::SegmentEntry>,
    pub pre_promote_offsets: Vec<Option<u64>>,
}

/// The ULIDs a GC checkpoint needs, minted atomically in order from the
/// volume's own monotonic mint: every `u_buckets[i] < u_flush`, so rebuild
/// applies all GC outputs before the WAL segment flushed at `u_flush`.
///
/// `u_buckets` holds one ULID per output bucket the coordinator may emit this
/// tick (capped by `max_buckets_per_tick`), and it picks `u_buckets[i]` for the
/// i-th packed bucket. Unused ULIDs are discarded — `UlidMint` is a `u128`
/// counter, so over-reservation is free.
pub(super) struct GcCheckpointUlids {
    pub(super) u_buckets: Vec<Ulid>,
    pub(super) u_flush: Ulid,
}

/// Result of the GC checkpoint prep phase. `job` carries a promote when the
/// WAL held entries; an empty WAL completes the checkpoint outright.
pub struct GcCheckpointPrep {
    /// One pre-minted output ULID per potential bucket. Length equals
    /// `max_buckets_per_tick` from the request.
    pub u_buckets: Vec<Ulid>,
    /// Segment ULID used for the promoted WAL, and the key that identifies
    /// this promote's `PromoteComplete` among other in-flight promotes.
    pub u_flush: Ulid,
    pub job: Option<PromoteJob>,
}

/// Data needed by the worker thread to materialise a coordinator-emitted GC
/// plan (`gc/<ulid>.plan`) into a signed `gc/<ulid>.tmp`.
pub struct GcPlanApplyJob {
    pub plan_path: PathBuf,
    pub new_ulid: Ulid,
    pub gc_dir: PathBuf,
    pub index_dir: PathBuf,
    pub base_dir: PathBuf,
    pub ancestor_layers: Vec<AncestorLayer>,
    pub fetcher: Option<BoxFetcher>,
    /// Merged extent index as of dispatch, for resolving DedupRef /
    /// Delta-base bodies. Apply recomputes updates from a fresh snapshot, so
    /// writes that land while the worker runs survive.
    pub extent_index: Arc<extentindex::ExtentIndex>,
    pub signer: Arc<dyn segment::SegmentSigner>,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    /// Plan parsed and ULID-matched before dispatch.
    pub plan: rewrite_plan::RewritePlan,
}

/// Result returned by the worker after materialising a plan.
pub struct GcPlanApplyResult {
    pub new_ulid: Ulid,
    pub plan_path: PathBuf,
    pub gc_dir: PathBuf,
    /// `gc/<ulid>.tmp` — written and signed, awaiting the rename to bare
    /// `gc/<ulid>`. Present when `outcome` is `Applied`.
    pub tmp_path: Option<PathBuf>,
    pub new_bss: u64,
    pub entries: Vec<segment::SegmentEntry>,
    pub inputs: Vec<Ulid>,
    /// Body-owning entries from each input's `.idx` at dispatch time, as
    /// `(hash, kind, input_ulid)` — the raw material for the to-remove and
    /// stale-cancel sets.
    pub input_old_entries: Vec<(blake3::Hash, segment::EntryKind, Ulid)>,
    /// Inline bytes of the freshly written output segment, for populating
    /// `inline_data` on extent locations.
    pub handoff_inline: Vec<u8>,
    /// `Applied` when materialisation succeeded; `Cancelled` when the worker
    /// bailed out on a missing input or unresolvable hash.
    pub outcome: StagedApply,
}

/// Data needed by the worker thread to promote a confirmed-in-S3 segment from
/// `pending/<ulid>` (drain path) or `gc/<ulid>` (GC path) into
/// `cache/<ulid>.{body,present}` + `index/<ulid>.idx`. Both writes are
/// idempotent on retry.
pub struct PromoteSegmentJob {
    pub ulid: Ulid,
    /// `pending/<ulid>` when `is_drain`, `gc/<ulid>` otherwise.
    pub src_path: PathBuf,
    pub is_drain: bool,
    pub body_path: PathBuf,
    pub present_path: PathBuf,
    pub idx_path: PathBuf,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub segment_cache: Arc<segment_cache::SegmentIndexCache>,
}

/// Result returned by the worker after a `PromoteSegmentJob`.
pub struct PromoteSegmentResult {
    pub ulid: Ulid,
    pub is_drain: bool,
    /// Parsed segment index, shared with the segment-index cache. Carries the
    /// entries, consumed input ULIDs (empty on drain), and
    /// `body_section_start`.
    pub parsed: Arc<segment_cache::ParsedIndex>,
    /// Inline section bytes, populated when the drain path has Inline entries.
    pub inline: Vec<u8>,
    /// True when the worker took the GC tombstone shortcut — a zero-entry
    /// output with a non-empty inputs list, leaving the input idx files to
    /// delete.
    pub tombstone: bool,
}

/// Prep-phase outcome for `promote_segment`. `AlreadyPromoted` reports that an
/// earlier call completed: `cache/<ulid>.body` exists and both source paths
/// have been consumed. `Job` is boxed to keep the enum small.
pub enum PromoteSegmentPrep {
    Job(Box<PromoteSegmentJob>),
    AlreadyPromoted,
}

/// Inputs for signing and writing a `snapshots/<snap_ulid>.manifest` file plus
/// its `snapshots/<snap_ulid>` marker. The worker enumerates `index/` itself,
/// keeping that `read_dir` off the actor.
///
/// `extent_index` and `lbamap` are the snapshots the liveness filter runs
/// against, so the manifest lists the segments holding at least one live entry.
/// Reclaiming the segment files themselves stays GC's job.
pub struct SignSnapshotManifestJob {
    pub snap_ulid: Ulid,
    pub base_dir: PathBuf,
    pub signer: Arc<dyn segment::SegmentSigner>,
    pub extent_index: Arc<extentindex::ExtentIndex>,
    pub lbamap: Arc<crate::lbamap::LbaMap>,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub segment_cache: Arc<segment_cache::SegmentIndexCache>,
    /// Which on-disk filename to write the signed manifest under —
    /// `<ulid>.manifest` for `User`, `<ulid>-stop.manifest` for `Auto`. The
    /// signed payload is identical for both.
    pub kind: crate::signing::SnapshotKind,
}

pub struct SignSnapshotManifestResult {
    pub snap_ulid: Ulid,
}

/// Job dispatched from the actor to the worker thread.
pub enum WorkerJob {
    Promote(PromoteJob),
    GcPlan(GcPlanApplyJob),
    PromoteSegment(PromoteSegmentJob),
    Repack(RepackJob),
    SignSnapshotManifest(SignSnapshotManifestJob),
    Reclaim(ReclaimJob),
    /// Test seam: the worker blocks on the receiver, then returns
    /// [`WorkerResult::Barrier`]. Lets tests hold the worker at a known point
    /// to build full-queue states deterministically.
    #[cfg(test)]
    Barrier(crossbeam_channel::Receiver<()>),
}

/// Result returned by the worker thread to the actor. `PromoteSegment` carries
/// the target ULID out-of-band, so a failed job still matches its parked reply.
pub enum WorkerResult {
    Promote(Result<PromoteResult, PromoteFailure>),
    GcPlan(io::Result<GcPlanApplyResult>),
    PromoteSegment {
        ulid: Ulid,
        result: io::Result<PromoteSegmentResult>,
    },
    Repack(io::Result<RepackResult>),
    SignSnapshotManifest(io::Result<SignSnapshotManifestResult>),
    Reclaim(io::Result<ReclaimResult>),
    /// Test seam: completion of a [`WorkerJob::Barrier`].
    #[cfg(test)]
    Barrier,
}
