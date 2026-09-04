// VolumeActor + VolumeClient/VolumeReader: the intended integration pattern
// for the ublk transport.
//
// VolumeActor owns a Volume exclusively and processes requests from a
// crossbeam-channel in a dedicated thread. VolumeClient is the shareable
// client handle — Send + Sync + Clone — held by ublk queue threads for
// writes, flushes, and control operations. VolumeReader is a per-thread
// handle (Send, !Sync) constructed via VolumeClient::reader(); it owns a
// local file-descriptor cache and serves reads against the current
// ReadSnapshot without any channel round-trip.
//
// Reads bypass the channel entirely: the reader loads the current
// ReadSnapshot via ArcSwap and resolves the read locally. Writes, flushes,
// and compaction go through the channel and block until the actor replies.
//
// The actor publishes a new ReadSnapshot after every write so that reads
// immediately reflect all accepted writes, including those not yet flushed
// to a pending/ segment — matching the read-your-writes guarantee of a
// physical block device.
//
// See docs/architecture.md — "Concurrency model" for rationale and design.

use parking_lot::{Mutex, MutexGuard};
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded, tick};
use log::{debug, error, info, warn};

use ulid::Ulid;

use crate::extentindex::ExtentIndex;
use crate::lbamap::LbaMap;
use crate::lock_stats::{AppendContext, LockSite, LockStats, LockStatsSnapshot, WritePhases};
use crate::segment::{self, BoxFetcher};
use crate::sync_gate::{GateSnapshot, RequestKind, SyncGate};
use crate::volume::{
    AncestorLayer, CompactionStats, GcCheckpointPrep, GcPlanApplyJob, GcPlanApplyResult,
    NoopSkipStats, PromoteFailure, PromoteJob, PromoteResult, PromoteSegmentJob,
    PromoteSegmentPrep, PromoteSegmentResult, ReclaimCandidate, ReclaimJob, ReclaimOutcome,
    ReclaimPrep, ReclaimResult, ReclaimThresholds, ReclaimedEntry, RepackApply, RepackJob,
    RepackResult, SharedFileCache, SignSnapshotManifestJob, SignSnapshotManifestResult, Volume,
    WorkerJob, WorkerResult, find_segment_in_dirs, lock_file_cache, open_delta_body_in_dirs,
    read_extents, read_plan_for_apply, scan_plan_handoffs, scan_reclaim_candidates,
};

// ---------------------------------------------------------------------------
// Static configuration
// ---------------------------------------------------------------------------

/// Static configuration for a volume session.
///
/// Holds the fork directory paths and optional fetcher — data that is fixed
/// for the lifetime of the session. Wrapped in `Arc` and shared across all
/// `VolumeClient` clones (and the `VolumeReader`s they create) without
/// copying.
pub struct VolumeConfig {
    pub base_dir: PathBuf,
    /// Precomputed `base_dir.join("cache")`.  `read_into` runs on every
    /// ublk read; allocating a fresh `PathBuf` per read showed up as
    /// gratuitous churn since `base_dir` is fixed for the session.
    pub cache_dir: PathBuf,
    pub ancestor_layers: Vec<AncestorLayer>,
    pub fetcher: Option<BoxFetcher>,
}

// ---------------------------------------------------------------------------
// Read snapshot
// ---------------------------------------------------------------------------

/// Immutable snapshot of the LBA map and extent index.
///
/// Published by `VolumeActor` after every `write()` and after every WAL
/// promotion.  Readers load the current snapshot via `ArcSwap::load()` —
/// no channel round-trip, no lock.
///
/// Both map fields are `Arc`-wrapped so that publication is O(1): the actor
/// calls `Arc::clone` on its live maps.  If a reader is still holding the
/// previous version when the next write occurs, `Arc::make_mut` in `Volume`
/// performs a copy-on-write clone; in practice reads complete in microseconds
/// so the refcount is almost always 1.
///
/// `flush_gen` counts publications: every write bumps it. A handle compares
/// it against the generation it last resolved through and reloads the
/// snapshot when it differs, which is how a read that raced a repack finds
/// the segment that replaced the one it was looking for.
///
/// `layout_gen` counts the subset of publications that replace or remove
/// segment files — promotion, drain, repack and GC apply, eviction. A handle
/// holding an open descriptor may keep using it while `layout_gen` holds
/// still, because appending WAL bytes grows a file the descriptor already
/// names rather than putting a different inode in its place. Separating the
/// two is what lets a descriptor survive a write: on a read-write volume the
/// publication rate is the write rate, and evicting on it clears the cache
/// between consecutive reads.
///
/// Both generations live inside the snapshot, so a handle always sees a
/// consistent triple: observing a new generation means observing the extent
/// index that goes with it, in the same atomic load.
pub struct ReadSnapshot {
    pub maps: crate::map_layers::MapLayers,
    pub flush_gen: u64,
    pub layout_gen: u64,
}

/// Where a reap pass stops. Production runs every pass to
/// [`ReapStop::Never`]; the crash tests stop one inside the
/// publish-before-unlink discipline and take the crash there, which is
/// the only way those windows are reachable — the phases run back to
/// back under the actor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReapStop {
    /// Run the pass to completion.
    Never,
    /// Stop after the apply. The live maps have dropped the reaped
    /// entries while the published snapshot still resolves readers
    /// through the segments, whose files are still on disk.
    BeforePublish,
    /// Stop after the publish. No published snapshot names the reaped
    /// segments and their files are still on disk, so a rebuild
    /// restores the entries the apply dropped.
    BeforeUnlink,
}

// ---------------------------------------------------------------------------
// Channel message type
// ---------------------------------------------------------------------------

pub(crate) enum VolumeRequest {
    /// Fire-and-forget signal from a direct writer that the WAL may have
    /// crossed the promote threshold.  The actor checks `needs_promote()`
    /// and dispatches a promote if so.  Idempotent; the actor's idle tick
    /// would catch this eventually anyway, so a dropped signal (channel
    /// full) is benign.
    CheckPromote,
    ApplyGcHandoffs {
        reply: Sender<io::Result<usize>>,
    },
    CloseGeneration {
        reply: Sender<io::Result<Option<u32>>>,
    },
    Reap {
        stop: ReapStop,
        reply: Sender<io::Result<crate::volume::ReapStats>>,
    },
    /// Promote the current WAL to a `pending/` segment via the worker
    /// thread.  Reply is sent once `pending/<ulid>` is on disk.
    /// No-op (immediate reply) if the WAL is empty.
    PromoteWal {
        reply: Sender<io::Result<()>>,
    },
    GcCheckpoint {
        /// Number of bucket ULIDs to pre-mint. The coordinator picks
        /// `<= max_buckets` of them for emitted plans; the rest are
        /// discarded. Mint is a free `u128` counter so over-reserving
        /// has no cost.
        max_buckets: usize,
        reply: Sender<io::Result<crate::volume_ipc::GcCheckpointReply>>,
    },
    Promote {
        ulid: Ulid,
        reply: Sender<io::Result<()>>,
    },
    FinalizeGcHandoff {
        ulid: Ulid,
        reply: Sender<io::Result<()>>,
    },
    SignSnapshotManifest {
        snap_ulid: Ulid,
        kind: crate::signing::SnapshotKind,
        reply: Sender<io::Result<()>>,
    },
    NoopStats {
        reply: Sender<NoopSkipStats>,
    },
    /// Alias-merge extent reclamation. Actor preps a `ReclaimJob`,
    /// dispatches to the worker, and parks the reply until
    /// `WorkerResult::Reclaim` returns. Apply runs on the actor:
    /// `Arc::ptr_eq` guard on the captured `Arc<LbaMap>`, splice on
    /// success, orphan cleanup on discard. See
    /// `docs/design/extent-reclamation.md`.
    Reclaim {
        start_lba: u64,
        lba_length: u32,
        reply: Sender<io::Result<ReclaimOutcome>>,
    },
    Shutdown,
    /// Test seam: dispatch a [`WorkerJob::Barrier`] through the normal
    /// worker-dispatch path.
    #[cfg(test)]
    TestDispatchBarrier {
        hold: crossbeam_channel::Receiver<()>,
    },
    /// Test seam: block inside this handler until `park` fires, then
    /// dispatch one [`WorkerJob::Barrier`] per entry of `holds` without
    /// returning to the select loop — so a test can drive a dispatch
    /// while worker results are provably queued undrained.
    #[cfg(test)]
    TestParkThenDispatchBarriers {
        park: crossbeam_channel::Receiver<()>,
        holds: Vec<crossbeam_channel::Receiver<()>>,
    },
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// Owns a `Volume` exclusively and drives the request channel.
///
/// Spawn a thread and call `actor.run()`. The thread exits when the last
/// `VolumeClient` is dropped (channel closes) or when a `Shutdown` message
/// is received.
pub struct VolumeActor {
    /// Shared via `Arc<Mutex<...>>` because the ublk transport acquires the
    /// same lock directly for hot-path writes ([`VolumeClient::write`]),
    /// bypassing the request channel. Every handler below contends with
    /// those writers for as long as it holds the guard.
    volume: Arc<Mutex<Volume>>,
    /// The volume's directory, for control-plane work that reads it directly.
    base_dir: PathBuf,
    /// The fork ancestry, for the GC plan fold's stale-cancel diagnostic.
    ancestor_layers: Vec<AncestorLayer>,
    snapshot: Arc<ArcSwap<ReadSnapshot>>,
    rx: Receiver<VolumeRequest>,
    /// Publication counter.  Bumped under the volume mutex on every snapshot
    /// publish (actor-side state changes and direct writes from the ublk
    /// transport) and embedded into the published `ReadSnapshot` so that
    /// handles see a consistent (generation, extent_index) pair from a
    /// single atomic load.  Shared with `VolumeClient` so direct writers
    /// can publish without an actor round-trip.
    flush_gen: Arc<AtomicU64>,
    /// Counter over the publications that replace or remove segment files.
    /// Bumped under the same mutex, from the same call, and shared the same
    /// way; readers evict cached descriptors when it moves.
    layout_gen: Arc<AtomicU64>,
    /// Sender for dispatching jobs to the worker thread.
    /// `Option` so shutdown can `take()` it, dropping the sender to signal
    /// the worker to exit.
    worker_tx: Option<Sender<QueuedJob>>,
    /// Receiver for results from the worker thread.
    /// Third arm in the `select!` loop.
    worker_rx: Receiver<WorkerResult>,
    /// Join handle for the worker thread, joined on shutdown.
    worker_handle: Option<JoinHandle<()>>,
    /// Fail-stop hook for [`StagedApply::Diverged`]: the daemon binary
    /// installs a process-exit here so a read-state divergence halts
    /// serving instead of continuing on a provably incomplete view
    /// (`docs/design/read-state-divergence-check.md`). `None` (tests,
    /// library callers): the divergence is logged and the plan left on
    /// disk, nothing exits.
    divergence_exit: Option<Box<dyn Fn() + Send>>,
    /// Promote-durability bookkeeping and replies parked on specific
    /// promotes.
    pipeline: PromotePipeline,
    /// Reply slots for the at-most-one-in-flight worker operations.
    parked: ParkedOps,
    /// Volume-mutex occupancy per labelled site, shared with
    /// [`VolumeClient`] so a handle can read it without an actor round
    /// trip.
    lock_stats: Arc<LockStats>,
    /// Counters as the last report left them, so the idle tick reports
    /// the window rather than the volume's whole history.
    lock_stats_reported: LockStatsSnapshot,
    /// When that mark was taken, which is the span the next line covers.
    lock_stats_marked: Instant,
    /// The sync gate the guest's FLUSH and FUA requests run through,
    /// shared with the clients that run them.
    gate: Arc<SyncGate>,
    /// The gate counters as the last `[flush]` line left them.
    gate_reported: GateSnapshot,
    /// When that line last went out, which is the span the next one covers.
    gate_marked: Instant,
    /// When the stashed-promotes warning last went out, so a persistent
    /// failure repeats on the report cadence.
    stash_marked: Instant,
}

/// Promote-pipeline bookkeeping: dispatch/completion generations for
/// the empty-WAL GC checkpoint barrier, plus replies parked on
/// specific promotes.
#[derive(Default)]
struct PromotePipeline {
    /// Number of promote jobs dispatched but not yet applied.
    promotes_in_flight: usize,
    /// Monotonic counter, incremented on every `WorkerJob::Promote`
    /// dispatch (post-write threshold, `PromoteWal`, `GcCheckpoint`).
    /// Used together with `completed_gen` to hold an empty-WAL GC
    /// checkpoint until every promote dispatched *before* it has
    /// applied.
    promote_gen: u64,
    /// Monotonic counter, incremented on every `WorkerResult::Promote`
    /// (success *or* error) received from the worker, after the
    /// success path's apply.  `completed_gen >= needed_gen` means
    /// every promote dispatched at or before `needed_gen` has either
    /// applied or failed and errored its waiters.
    completed_gen: u64,
    /// Parked GC checkpoint: the reply sender and GC ULIDs, waiting
    /// either for the GC promote (`u_flush`) to complete on the worker
    /// or, when the WAL was empty, for every promote dispatched before
    /// the checkpoint to apply.  `None` when no GC checkpoint is in
    /// progress.
    parked_gc: Option<ParkedGc>,
    /// Parked `PromoteWal` replies waiting for their specific promote to
    /// complete.  Multiple can be parked if several `PromoteWal` requests
    /// arrive while the worker is busy.
    parked_promote_wal: Vec<ParkedPromoteWal>,
    /// Parked `Promote` (promote_segment) replies waiting for their
    /// specific segment promote to complete on the worker.
    parked_promote_segments: Vec<ParkedPromoteSegment>,
    /// Number of `promote_segment` jobs dispatched but not yet applied.
    promote_segments_in_flight: usize,
    /// Failed promote jobs awaiting retry, oldest first. Each holds a
    /// closed WAL epoch whose on-disk WAL file is the durable copy of
    /// the data; [`VolumeActor::retry_failed_promote`] re-dispatches one
    /// per promote trigger (write-path threshold, `PromoteWal`,
    /// `GcCheckpoint`).
    failed_promotes: VecDeque<Box<PromoteJob>>,
}

/// Reply slots for worker operations that admit at most one in flight:
/// each holds the parked reply sender while its job runs on the worker,
/// and a concurrent request is rejected while the slot is occupied.
#[derive(Default)]
struct ParkedOps {
    /// In-progress GC plan handoff batch. At most one batch at a time.
    handoffs: Option<ParkedGcHandoffs>,
    /// Whether a GC plan handoff job is on the worker thread, or has
    /// returned a result held in `deferred_handoff`.
    handoff_in_flight: bool,
    /// A finished plan-apply result held back until in-flight promotes
    /// have applied. See [`VolumeActor::apply_or_defer_gc_plan`].
    deferred_handoff: Option<Box<crate::volume::GcPlanApplyResult>>,
    close_generation: Option<ParkedCloseGeneration>,
    /// Reply channel for an in-flight `SignSnapshotManifest` request,
    /// parked while the worker thread enumerates `index/`, signs, and
    /// writes the manifest + marker.  Concurrent requests are rejected
    /// (the coordinator's per-volume snapshot lock already prevents
    /// them in production).
    sign_snapshot_manifest: Option<Sender<io::Result<()>>>,
    /// Reply channel for an in-flight `Reclaim` request, parked while
    /// the worker thread reads live bytes, rehashes, and assembles the
    /// output segment.
    reclaim: Option<Sender<io::Result<ReclaimOutcome>>>,
}

/// State stashed while a `PromoteWal` promote is in flight.
/// Reply for an in-flight close pass, paired with the sealed
/// generation's segment count — the value the reply carries, known at
/// prep and independent of what the pass packs.
struct ParkedCloseGeneration {
    reply: Sender<io::Result<Option<u32>>>,
    rotated: Option<u32>,
}

struct ParkedPromoteWal {
    segment_ulid: Ulid,
    reply: Sender<io::Result<()>>,
}

/// State stashed while a `promote_segment` job is on the worker thread.
struct ParkedPromoteSegment {
    ulid: Ulid,
    reply: Sender<io::Result<()>>,
}

/// A GC checkpoint waiting on the promote pipeline.  `Flush` waits for
/// the checkpoint's own promote (`u_flush`); `Barrier` is the empty-WAL
/// case, waiting for promotes that were already in flight when the
/// checkpoint arrived.  One slot for both phases keeps "at most one
/// checkpoint in progress" a single `is_some` check.
enum ParkedGc {
    Flush(ParkedGcCheckpoint),
    Barrier(ParkedGcBarrier),
}

impl ParkedGc {
    fn into_reply(self) -> Sender<io::Result<crate::volume_ipc::GcCheckpointReply>> {
        match self {
            ParkedGc::Flush(p) => p.reply,
            ParkedGc::Barrier(p) => p.reply,
        }
    }
}

/// State stashed while a GC checkpoint's promote is in flight.
struct ParkedGcCheckpoint {
    u_buckets: Vec<Ulid>,
    u_flush: Ulid,
    reply: Sender<io::Result<crate::volume_ipc::GcCheckpointReply>>,
}

/// State stashed while an empty-WAL GC checkpoint waits for promotes
/// dispatched before it to apply.  Such a promote's claims sit in a
/// WAL file until its apply moves them into a `pending/` segment, and
/// the coordinator builds its liveness view by reading segments first
/// and WALs second — a reply sent mid-flight lets the move land
/// between those two reads, hiding the claims from both (issue #914).
/// Released when `PromotePipeline::completed_gen >= needed_gen`.
struct ParkedGcBarrier {
    needed_gen: u64,
    u_buckets: Vec<Ulid>,
    reply: Sender<io::Result<crate::volume_ipc::GcCheckpointReply>>,
}

/// State for an in-progress batch of GC plan handoff applications.
///
/// The actor dispatches one plan at a time to the worker thread. On each
/// completion it applies the result, then dispatches the next. When the
/// list is exhausted, the reply (if any) is sent.
struct ParkedGcHandoffs {
    remaining: Vec<(PathBuf, Ulid)>,
    reply: Option<Sender<io::Result<usize>>>,
    applied_count: usize,
}

/// Outcome of a single call to [`VolumeActor::dispatch_next_handoff`].
enum HandoffDispatch {
    /// A job was sent to the worker; the caller must retain the parked
    /// batch in `self.parked.handoffs` so the worker result can drive it.
    Dispatched,
    /// The batch is complete — either every entry was skipped, the last
    /// worker result fired the reply, or an error fired the reply. The
    /// caller must drop the parked batch, not store it.
    Finished,
}

/// Idle period after which the actor promotes a non-empty WAL to a pending
/// segment even without an explicit flush request.  10 seconds is a
/// conservative value chosen for observability during development; it can be
/// tightened without any correctness implications.
const IDLE_FLUSH_INTERVAL: Duration = Duration::from_secs(10);

/// Total volume-mutex hold a window must exceed to earn a log line.
///
/// A tick on a volume nobody is writing to still takes the mutex a few
/// times to publish and to check for work, for tens of microseconds all
/// told. At 5ms against a 10s window the mutex is free 99.95% of the
/// time, which is quiet whatever the sites add up to.
const LOCK_REPORT_FLOOR: Duration = Duration::from_millis(5);

/// How often the lock report is due, checked on every pass of the actor
/// loop.
const LOCK_REPORT_INTERVAL: Duration = Duration::from_secs(10);

/// Acquire the volume mutex.
///
/// `parking_lot`'s mutex is the one here because it can release to a
/// waiting thread rather than to whoever wins the next acquisition — see
/// [`TimedGuard::fair`]. It also tracks no poison state, so a caller that
/// panicked mid-mutation leaves the lock takeable; CLAUDE.md's "no panic
/// in library paths" rule is what keeps that from happening.
fn lock_volume(volume: &Arc<Mutex<Volume>>) -> MutexGuard<'_, Volume> {
    volume.lock()
}

/// Acquire the volume mutex for a guest write, timing the wait only when
/// there is one.
///
/// `try_lock` is the same compare-and-swap the blocking acquisition would
/// have made, so a write that finds the mutex free pays one relaxed
/// counter increment beyond what it already paid. A write that does block
/// has parked, and the two clock reads charged to it are far below the
/// wait they measure.
///
/// The returned guard charges what the write held on drop. An actor loop
/// that yields to the queue standing behind it pays that hold once per
/// waiting write, so it is the term that sizes the yield.
/// The clock a guest write runs against. It marks the call, the ask for
/// the mutex, and the return, and turns the marks into [`WritePhases`].
struct WriteClock {
    started: Instant,
}

impl WriteClock {
    fn start() -> Self {
        Self {
            started: Instant::now(),
        }
    }

    /// The instant the write asks for the mutex. Everything before it is
    /// the pre phase.
    fn asked(&self) -> Instant {
        Instant::now()
    }

    /// The phases from the marks: `taken` is the mutex acquisition,
    /// `released` its release, `synced` the FUA round's duration. The post
    /// phase is the remainder of the total.
    fn phases(
        &self,
        bytes: u64,
        asked: Instant,
        taken: Instant,
        released: Instant,
        synced: Option<Duration>,
    ) -> WritePhases {
        let total = self.started.elapsed();
        let pre = asked.duration_since(self.started);
        let wait = taken.duration_since(asked);
        let held = released.duration_since(taken);
        let fua = synced.unwrap_or(Duration::ZERO);
        let post = total.saturating_sub(pre + wait + held + fua);
        WritePhases {
            bytes,
            pre,
            wait,
            held,
            post,
            fua: synced,
            total,
        }
    }
}

fn lock_volume_for_write<'a>(
    volume: &'a Arc<Mutex<Volume>>,
    stats: &'a LockStats,
) -> WriteGuard<'a> {
    if let Some(guard) = volume.try_lock() {
        stats.record_write_uncontended();
        return WriteGuard::new(guard, stats);
    }
    stats.record_write_parking();
    let requested = Instant::now();
    let guard = lock_volume(volume);
    stats.record_write_blocked(requested.elapsed());
    WriteGuard::new(guard, stats)
}

/// A guest write's hold on the volume mutex, charged on drop, with what
/// was in flight when it took the mutex.
pub(crate) struct WriteGuard<'a> {
    guard: MutexGuard<'a, Volume>,
    stats: &'a LockStats,
    acquired: Instant,
    context: AppendContext,
}

impl<'a> WriteGuard<'a> {
    fn new(guard: MutexGuard<'a, Volume>, stats: &'a LockStats) -> Self {
        Self {
            guard,
            stats,
            acquired: Instant::now(),
            context: stats.append_context(),
        }
    }
}

impl std::ops::Deref for WriteGuard<'_> {
    type Target = Volume;

    fn deref(&self) -> &Volume {
        &self.guard
    }
}

impl std::ops::DerefMut for WriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Volume {
        &mut self.guard
    }
}

impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        let depth = self.guard.map_layers().frozen_depth();
        let wal = self.guard.take_wal_time();
        self.stats
            .record_write_hold(self.acquired.elapsed(), depth, wal, self.context);
    }
}

/// Acquire the volume mutex for a labelled site, timing the wait and the
/// hold against it.
fn lock_volume_timed<'a>(
    volume: &'a Arc<Mutex<Volume>>,
    stats: &'a LockStats,
    site: LockSite,
) -> TimedGuard<'a> {
    let requested = Instant::now();
    let guard = lock_volume(volume);
    let acquired = Instant::now();
    TimedGuard {
        guard: Some(guard),
        fair: false,
        stats,
        site,
        wait: acquired.saturating_duration_since(requested),
        acquired,
    }
}

/// A volume-mutex guard that folds its wait and hold into [`LockStats`]
/// when it drops.
///
/// Three clock reads per acquisition, which is why the guest write path
/// acquires through [`lock_volume_for_write`] instead.
pub(crate) struct TimedGuard<'a> {
    /// `Some` for the whole borrow; taken in `drop`, which is the only
    /// place that needs the guard by value, so no deref sees `None`.
    guard: Option<MutexGuard<'a, Volume>>,
    stats: &'a LockStats,
    site: LockSite,
    wait: Duration,
    acquired: Instant,
    fair: bool,
}

impl TimedGuard<'_> {
    /// Release to a thread already waiting rather than to whoever wins
    /// the next acquisition.
    ///
    /// For an actor loop that re-acquires immediately. The mutex hands
    /// the lock back to the running thread by default, so such a loop
    /// holds a guest write off for the sum of its iterations even though
    /// each hold is short — measured at 541.7 ms across twelve holds of
    /// 58 ms or less. A guest write's own hold averages 0.100 ms, so the
    /// queue this lets through costs the loop well under a millisecond
    /// per iteration.
    fn fair(mut self) -> Self {
        self.fair = true;
        self
    }
}

impl std::ops::Deref for TimedGuard<'_> {
    type Target = Volume;

    fn deref(&self) -> &Volume {
        // Taken only by `drop`, which consumes the guard.
        self.guard
            .as_ref()
            .expect("volume guard outlives its borrow")
    }
}

impl std::ops::DerefMut for TimedGuard<'_> {
    fn deref_mut(&mut self) -> &mut Volume {
        // Taken only by `drop`, which consumes the guard.
        self.guard
            .as_mut()
            .expect("volume guard outlives its borrow")
    }
}

impl Drop for TimedGuard<'_> {
    fn drop(&mut self) {
        self.stats
            .record(self.site, self.wait, self.acquired.elapsed());
        // `guard` is a field, so the mutex is still held here.
        self.stats.arm_drain(self.site);
        match (self.guard.take(), self.fair) {
            (Some(guard), true) => MutexGuard::unlock_fair(guard),
            // Releases to whichever thread wins the next acquisition.
            (guard, _) => drop(guard),
        }
    }
}

/// What a publication did to the files on disk, which decides whether a
/// reader's open descriptors survive it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Publication {
    /// Segment files were replaced or removed: WAL promotion, drain, repack
    /// and GC apply, eviction. A descriptor cached for one of them may now
    /// name an unlinked inode, so readers drop what they hold.
    ReplacesFiles,
    /// Bytes were appended to the WAL. Every file a reader has open still
    /// names the same inode at the same path, and the appended bytes are
    /// visible through the descriptor it already holds.
    AppendsToWal,
}

/// What a publication leaves the caller: the snapshot it replaced, and
/// the generation it published under.
#[must_use]
struct Published {
    /// Its drop frees every map node the mutations since the last publish
    /// path-copied, a cost proportional to their count, so the caller
    /// drops it after it releases the mutex.
    previous: Arc<ReadSnapshot>,
    /// The point in the append order this publication holds, which a FUA
    /// write hands the sync gate.
    flush_gen: u64,
}

/// Bump the generations and publish a fresh `ReadSnapshot`.
///
/// Must be called while holding the volume mutex (the `&Volume` argument
/// is the live guard) so the (lbamap, extent_index, generations) tuple
/// observed by the next `snapshot.load()` is internally consistent.
fn publish_snapshot(
    volume: &Volume,
    snapshot: &ArcSwap<ReadSnapshot>,
    flush_gen: &AtomicU64,
    layout_gen: &AtomicU64,
    publication: Publication,
) -> Published {
    let new_flush = flush_gen.fetch_add(1, Ordering::SeqCst) + 1;
    // Read `layout_gen` back when this publication leaves the files alone, so
    // the snapshot carries the generation of the last one that did move them.
    let new_layout = match publication {
        Publication::ReplacesFiles => layout_gen.fetch_add(1, Ordering::SeqCst) + 1,
        Publication::AppendsToWal => layout_gen.load(Ordering::SeqCst),
    };
    let previous = snapshot.swap(Arc::new(ReadSnapshot {
        maps: volume.map_layers().clone(),
        flush_gen: new_flush,
        layout_gen: new_layout,
    }));
    Published {
        previous,
        flush_gen: new_flush,
    }
}

impl VolumeActor {
    /// Acquire the volume mutex, timing the wait and the hold against
    /// `site`. Every actor-side acquisition carries a label, so a site
    /// cannot enter the mutex uncounted.
    fn lock_volume(&self, site: LockSite) -> TimedGuard<'_> {
        lock_volume_timed(&self.volume, &self.lock_stats, site)
    }

    /// Install the fail-stop hook invoked on [`StagedApply::Diverged`].
    /// The daemon binary passes a process-exit; the hook is expected
    /// not to return.
    pub fn set_divergence_exit(&mut self, exit: impl Fn() + Send + 'static) {
        self.divergence_exit = Some(Box::new(exit));
    }

    /// A GC plan named an input this daemon's read state never loaded.
    /// Fail-stop via the installed hook; without one (tests, library
    /// callers) serving continues on the incomplete view and the
    /// retained plan re-arms the check.
    fn on_divergence(&self) {
        error!(
            "read-state divergence: GC plan named input segment(s) unknown to \
             this daemon; failing stop so a fresh open rebuilds from disk \
             (docs/design/read-state-divergence-check.md)"
        );
        if let Some(exit) = &self.divergence_exit {
            exit();
        }
    }

    /// Publish after an actor-side operation. Every one of these runs after a
    /// worker moved, rewrote or unlinked segment files, so they all retire
    /// readers' descriptors.
    fn publish_snapshot(&mut self) {
        let guard = self.lock_volume(LockSite::PublishSnapshot);
        let published = publish_snapshot(
            &guard,
            &self.snapshot,
            &self.flush_gen,
            &self.layout_gen,
            Publication::ReplacesFiles,
        );
        drop(guard);
        drop(published.previous);
    }

    /// Apply a worker's repack result, publish the read snapshot, then
    /// unlink the consumed input files. The publish must come before
    /// the unlinks: publishing first guarantees no published snapshot
    /// ever references a deleted input, and readers still holding an
    /// older snapshot recover via the `NotFound` retry in
    /// [`VolumeReader::read_with_snapshot`]. The unlinks and their
    /// directory fsyncs run with the mutex released; the lock at the
    /// end covers the invariants assertion alone.
    ///
    /// Each bucket folds on this thread with the mutex released, between
    /// two holds that clone and swap handles. Both holds release to a
    /// waiting guest write with the fair handoff, since this loop would
    /// win the lock straight back. The single publish at the end keeps
    /// readers seeing the whole pass at once. The bases the swaps retired
    /// live until after that publish, so this thread frees them.
    fn apply_repack_and_publish(&mut self, result: RepackResult) -> io::Result<CompactionStats> {
        let (mut acc, buckets) = RepackApply::new(result);
        let mut retired = Vec::with_capacity(buckets.len());
        for bucket in &buckets {
            let layers = self
                .lock_volume(LockSite::RepackApply)
                .fair()
                .map_layers()
                .clone();
            if let crate::volume::RepackFold::Landed(landed) =
                crate::volume::fold_repack_bucket(&layers, bucket, &mut acc)?
            {
                retired.extend(
                    self.lock_volume(LockSite::RepackApply)
                        .fair()
                        .swap_repack_bucket(bucket, landed, layers.base(), &mut acc),
                );
            }
        }
        let (stats, consumed_inputs) = self
            .lock_volume(LockSite::RepackApply)
            .finish_repack_apply(acc)?;
        if stats.segments_compacted > 0 || !consumed_inputs.is_empty() {
            self.publish_snapshot();
        }
        drop(retired);
        crate::volume::unlink_consumed_inputs(&consumed_inputs)?;
        self.lock_volume(LockSite::RepackUnlink)
            .assert_consumed_inputs_removed();
        Ok(stats)
    }

    /// Called on each `WorkerResult::Promote` — after the apply for a
    /// success, before the retry stash for a failure.  Bumps
    /// `completed_gen`.
    fn on_promote_result(&mut self) {
        self.pipeline.completed_gen += 1;
    }

    /// Forward the result of a completed `promote_segment` job to the
    /// matching parked reply, if any.  Matched by ULID — callers receive
    /// the apply-phase outcome, not the worker outcome (those only differ
    /// when apply itself fails, which is rare: both success paths imply
    /// the segment is fully promoted and the extent index is up to date).
    fn reply_parked_promote_segment(&mut self, ulid: Ulid, result: io::Result<()>) {
        if let Some(idx) = self
            .pipeline
            .parked_promote_segments
            .iter()
            .position(|p| p.ulid == ulid)
        {
            let parked = self.pipeline.parked_promote_segments.swap_remove(idx);
            let _ = parked.reply.send(result);
        }
    }

    /// Take the parked GC checkpoint if this promote's apply satisfies
    /// it: the checkpoint's own `u_flush`, or — for an empty-WAL
    /// checkpoint — the promote that brings `completed_gen` up to the
    /// barrier's `needed_gen`.  Call after the generation bump in
    /// [`Self::on_promote_result`].
    fn take_satisfied_gc_checkpoint(
        &mut self,
        ulid: Ulid,
    ) -> Option<(
        Vec<Ulid>,
        Sender<io::Result<crate::volume_ipc::GcCheckpointReply>>,
    )> {
        let done = self.pipeline.completed_gen;
        let satisfied = match &self.pipeline.parked_gc {
            Some(ParkedGc::Flush(p)) => p.u_flush == ulid,
            Some(ParkedGc::Barrier(b)) => b.needed_gen <= done,
            None => false,
        };
        if !satisfied {
            return None;
        }
        match self.pipeline.parked_gc.take() {
            Some(ParkedGc::Flush(p)) => Some((p.u_buckets, p.reply)),
            Some(ParkedGc::Barrier(b)) => Some((b.u_buckets, b.reply)),
            None => None,
        }
    }

    /// Dispatch a promote job to the worker thread.
    ///
    /// Calls [`Volume::prepare_promote`] to snapshot the WAL state and open
    /// a fresh WAL, then sends the job to the worker.  No-op if the WAL
    /// is empty.  A failed dispatch logs and leaves the job stashed for
    /// retry.
    fn dispatch_promote(&mut self) {
        self.retry_failed_promote();
        let job = match self.lock_volume(LockSite::PromotePrep).prepare_promote() {
            Ok(Some(job)) => job,
            Ok(None) => return,
            Err(e) => {
                warn!("promote prep failed: {e}");
                return;
            }
        };
        if let Err(e) = self.send_promote_job(job) {
            warn!("promote dispatch failed: {e}; stashed for retry");
        }
    }

    /// Dispatch a promote job to the worker and register it in the
    /// pipeline (in-flight count, generation). A failed dispatch stashes
    /// the job for retry instead; the volume keeps its rotated WAL in the
    /// sync set either way.
    fn send_promote_job(&mut self, job: PromoteJob) -> io::Result<()> {
        match self.send_worker_job(WorkerJob::Promote(job)) {
            Ok(()) => {
                self.pipeline.promotes_in_flight += 1;
                self.pipeline.promote_gen += 1;
                Ok(())
            }
            Err((e, job)) => {
                if let WorkerJob::Promote(job) = *job {
                    self.pipeline.failed_promotes.push_back(Box::new(job));
                }
                Err(e)
            }
        }
    }

    /// Re-dispatch the oldest stashed failed promote, if any. Returns
    /// the job's segment ULID when a retry was dispatched. One job per
    /// call — a job that fails again lands back on the queue, so retries
    /// pace themselves to the promote triggers rather than spinning.
    fn retry_failed_promote(&mut self) -> Option<Ulid> {
        let job = self.pipeline.failed_promotes.pop_front()?;
        let ulid = job.segment_ulid;
        if let Err(e) = self.send_promote_job(*job) {
            warn!("failed-promote retry dispatch failed: {e}");
            return None;
        }
        Some(ulid)
    }

    /// Run the GC checkpoint prep and dispatch the promote to the worker.
    ///
    /// Mints ULIDs, opens the fresh WAL immediately (writes resume),
    /// and dispatches the GC promote.  The reply is parked until every
    /// promote dispatched at or before the checkpoint has applied — the
    /// checkpoint's own `u_flush` when the WAL had entries, and any
    /// promotes already in flight when it was empty — so that each
    /// segment is in `pending/` before the coordinator runs `gc_fork`.
    fn start_gc_checkpoint(
        &mut self,
        max_buckets: usize,
        reply: Sender<io::Result<crate::volume_ipc::GcCheckpointReply>>,
    ) {
        self.retry_failed_promote();
        let prep = match self
            .lock_volume(LockSite::GcCheckpoint)
            .prepare_gc_checkpoint(max_buckets)
        {
            Ok(prep) => prep,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };

        let GcCheckpointPrep {
            u_buckets,
            u_flush,
            job,
        } = prep;

        if let Some(job) = job {
            // Dispatch to worker, park the reply.
            self.pipeline.parked_gc = Some(ParkedGc::Flush(ParkedGcCheckpoint {
                u_buckets,
                u_flush,
                reply,
            }));
            if let Err(e) = self.send_promote_job(job) {
                warn!("gc_checkpoint promote dispatch failed: {e}; stashed for retry");
                if let Some(parked) = self.pipeline.parked_gc.take() {
                    let _ = parked.into_reply().send(Err(e));
                }
            }
        } else if self.pipeline.completed_gen >= self.pipeline.promote_gen {
            // WAL was empty — fresh WAL already opened by prepare_gc_checkpoint.
            self.publish_snapshot();
            let own_segments = Some(
                self.lock_volume(LockSite::OwnSegments)
                    .own_segments_commitment(),
            );
            let _ = reply.send(Ok(crate::volume_ipc::GcCheckpointReply {
                bucket_ulids: u_buckets,
                own_segments,
            }));
        } else {
            // WAL was empty with promotes still in flight (an autonomous
            // threshold flush, or the retry dispatched above).  Their
            // claims reach `pending/` only at apply, so the reply parks
            // until the pipeline drains to the generation observed here.
            self.publish_snapshot();
            self.pipeline.parked_gc = Some(ParkedGc::Barrier(ParkedGcBarrier {
                needed_gen: self.pipeline.promote_gen,
                u_buckets,
                reply,
            }));
        }
    }

    /// Scan for pending GC plan handoffs and dispatch them to the worker.
    ///
    /// The apply path is offloaded because materialising a plan can read
    /// many MiB of body bytes from local cache and/or demand-fetch from S3;
    /// running it on the actor would block concurrent reads/writes. If
    /// `reply` is `Some`, the reply fires once all handoffs in this batch
    /// have been applied (or immediately if there are none).
    ///
    /// At most one batch runs at a time. If a batch is already in flight,
    /// IPC callers are told to retry; internal callers (idle tick) silently
    /// defer — the running batch will cover whatever is on disk.
    fn start_gc_handoffs(&mut self, reply: Option<Sender<io::Result<usize>>>) {
        if self.parked.handoffs.is_some() {
            if let Some(reply) = reply {
                let _ = reply.send(Err(io::Error::other(
                    "apply_gc_handoffs already in progress",
                )));
            }
            return;
        }

        let (to_process, already_applied) = match scan_plan_handoffs(&self.base_dir) {
            Ok(v) => v,
            Err(e) => {
                if let Some(reply) = reply {
                    let _ = reply.send(Err(e));
                } else {
                    warn!("gc plan scan failed: {e}");
                }
                return;
            }
        };

        if to_process.is_empty() {
            if already_applied > 0 {
                self.publish_snapshot();
            }
            if let Some(reply) = reply {
                let _ = reply.send(Ok(already_applied));
            }
            return;
        }

        let mut parked = ParkedGcHandoffs {
            remaining: to_process,
            reply,
            applied_count: already_applied,
        };

        if matches!(
            self.dispatch_next_handoff(&mut parked),
            HandoffDispatch::Dispatched
        ) {
            self.parked.handoffs = Some(parked);
        }
    }

    /// Pop the next plan handoff from the parked batch and dispatch it.
    ///
    /// Returns [`HandoffDispatch::Dispatched`] when a job is on the worker
    /// and the caller should retain `parked` in `self.parked.handoffs`.
    /// Returns [`HandoffDispatch::Finished`] when the batch is done — every
    /// remaining entry was skipped (`read_plan_for_apply` returned `None`)
    /// or a fatal error fired the reply — and the caller must drop `parked`.
    ///
    /// Skips entries whose plan `read_plan_for_apply` rejects (parse failure,
    /// ULID mismatch, empty inputs) — those plans were already removed
    /// inside it, so the batch continues with the next.
    fn dispatch_next_handoff(&mut self, parked: &mut ParkedGcHandoffs) -> HandoffDispatch {
        while let Some((plan_path, new_ulid)) = parked.remaining.pop() {
            let Some(plan) = read_plan_for_apply(&plan_path, new_ulid) else {
                continue;
            };
            let job = self
                .lock_volume(LockSite::GcPlanPrep)
                .prepare_plan_apply(plan_path, new_ulid, plan);
            if let Err((e, _)) = self.send_worker_job(WorkerJob::GcPlan(job)) {
                warn!("gc plan dispatch failed: {e}");
                if let Some(reply) = parked.reply.take() {
                    let _ = reply.send(Err(e));
                }
                return HandoffDispatch::Finished;
            }
            self.parked.handoff_in_flight = true;
            return HandoffDispatch::Dispatched;
        }
        // No more plans — finalise the batch.
        if let Some(reply) = parked.reply.take() {
            let _ = reply.send(Ok(parked.applied_count));
        }
        HandoffDispatch::Finished
    }

    /// One reap pass over `pending/open/`, inline on the actor: sweep
    /// the published snapshot and parse candidate index regions off the
    /// mutex, then revalidate, remove, publish and unlink
    /// (`docs/design/open-generation-reap.md`).
    ///
    /// `stop` is [`ReapStop::Never`] for every production pass; the
    /// crash tests stop one inside the publish-before-unlink discipline
    /// and take the crash there.
    ///
    /// Skipped whole while a promote is in flight: the promote's worker
    /// may be composing a delta against a claim-dead source this pass
    /// would remove, and its source pin is recorded only when its apply
    /// lands — the same ordering that holds a GC plan apply behind
    /// in-flight promotes. The pass runs every tick, so a skip costs one
    /// interval.
    fn handle_reap(&mut self, stop: ReapStop) -> io::Result<crate::volume::ReapStats> {
        if self.pipeline.promotes_in_flight > 0 {
            return Ok(crate::volume::ReapStats::default());
        }
        let open = crate::volume::list_open_segments(&self.base_dir)?;
        if open.is_empty() {
            return Ok(crate::volume::ReapStats::default());
        }
        let floor = crate::volume::latest_snapshot(&self.base_dir)?;
        let maps = self.snapshot.load().maps.materialised();
        let sweep =
            crate::volume::sweep_unreachable(&maps.lbamap, &maps.extent_index, &open, floor);
        let totals = sweep.totals();
        if totals.stored > 0 {
            log::info!(
                "reap sweep: open generation {} segment(s), {} stored body bytes, \
                 {} live, {:.1}% dead",
                sweep.body_bytes.len(),
                totals.stored,
                totals.live,
                100.0 * (totals.stored - totals.live) as f64 / totals.stored as f64,
            );
        }
        if sweep.candidates.is_empty() {
            return Ok(crate::volume::ReapStats::default());
        }
        let parsed = crate::volume::parse_reap_candidates(sweep.candidates);
        if parsed.is_empty() {
            return Ok(crate::volume::ReapStats::default());
        }
        let layers = self.lock_volume(LockSite::ReapApply).map_layers().clone();
        let fold = crate::volume::fold_reap(&layers, parsed);
        let crate::volume::ReapSwap {
            stats,
            unlink,
            retired,
        } = self
            .lock_volume(LockSite::ReapApply)
            .swap_reap(fold, layers.base());
        if unlink.is_empty() || stop == ReapStop::BeforePublish {
            return Ok(stats);
        }
        self.publish_snapshot();
        drop(retired);
        if stop == ReapStop::BeforeUnlink {
            return Ok(stats);
        }
        crate::volume::unlink_consumed_inputs(&unlink)?;
        self.lock_volume(LockSite::ReapUnlink)
            .assert_consumed_inputs_removed();
        Ok(stats)
    }

    /// Seal the open generation on the actor, then dispatch the pass
    /// over it to the worker. The reply is parked until the pass
    /// applies, so a drain of the sealed generation — which the *next*
    /// cut starts — cannot begin before its outputs are in place.
    fn start_close_generation(&mut self, reply: Sender<io::Result<Option<u32>>>) {
        let prep = match self
            .lock_volume(LockSite::ClosePrep)
            .prepare_close_generation()
        {
            Ok(p) => p,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let crate::volume::CloseGenerationPrep { rotated, job } = prep;
        let Some(job) = job else {
            let _ = reply.send(Ok(rotated));
            return;
        };
        // The rotate moved the segments readers resolve through, so
        // republish before the pass starts rewriting them.
        self.publish_snapshot();
        if let Err((e, _)) = self.send_worker_job(WorkerJob::CloseGeneration(job)) {
            warn!("close generation dispatch failed: {e}");
            let _ = reply.send(Err(e));
            return;
        }
        self.parked.close_generation = Some(ParkedCloseGeneration { reply, rotated });
    }

    /// Run the reclaim prep on the actor and dispatch the heavy middle
    /// (body reads + re-hash + re-compress + segment assembly) to the
    /// worker. Reply is parked until [`crate::volume::ReclaimResult`]
    /// arrives and is applied.
    fn start_reclaim(
        &mut self,
        start_lba: u64,
        lba_length: u32,
        reply: Sender<io::Result<ReclaimOutcome>>,
    ) {
        let prep = match self
            .lock_volume(LockSite::ReclaimPrep)
            .prepare_reclaim(start_lba, lba_length)
        {
            Ok(p) => p,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        let ReclaimPrep { flush, job } = prep;
        // The rotated WAL goes first, so `apply_promote` lands before the
        // reclaim's apply. Per-run admission (`register_entry_if_newer`)
        // reads that as an ordinary intervening mutation, which is what
        // lets the two applies stay in dispatch order with no deferral.
        if let Some(flush) = flush
            && let Err(e) = self.send_promote_job(flush)
        {
            warn!("reclaim flush dispatch failed: {e}; stashed for retry");
            let _ = reply.send(Err(e));
            return;
        }
        // Prep took the WAL, so the extent index the readers see still
        // points hashes at it. Republish so a reader picks up the
        // snapshot the promote's apply will move off.
        self.publish_snapshot();
        if let Err((e, _)) = self.send_worker_job(WorkerJob::Reclaim(job)) {
            warn!("reclaim dispatch failed: {e}");
            let _ = reply.send(Err(e));
            return;
        }
        self.parked.reclaim = Some(reply);
    }

    /// Run the snapshot-manifest prep on the actor and dispatch the
    /// heavy middle (`index/` enumeration + signing + manifest/marker
    /// writes) to the worker.  Reply is parked until
    /// [`crate::volume::SignSnapshotManifestResult`] arrives and the
    /// `has_new_segments` flag is flipped on the actor.
    fn start_sign_snapshot_manifest(
        &mut self,
        snap_ulid: Ulid,
        kind: crate::signing::SnapshotKind,
        reply: Sender<io::Result<()>>,
    ) {
        let job = self
            .lock_volume(LockSite::SnapshotPrep)
            .prepare_sign_snapshot_manifest_kind(snap_ulid, kind);
        if let Err((e, _)) = self.send_worker_job(WorkerJob::SignSnapshotManifest(job)) {
            warn!("sign_snapshot_manifest dispatch failed: {e}");
            let _ = reply.send(Err(e));
            return;
        }
        self.parked.sign_snapshot_manifest = Some(reply);
    }

    /// Hand a job to the worker without ever blocking while results back
    /// up. Both worker channels are bounded, so a plain blocking `send`
    /// can deadlock the pair: the worker parks sending a result the
    /// actor isn't draining, and stops taking jobs — the send never
    /// completes and the whole volume (IO + IPC) wedges. When the job
    /// queue is full, drain and apply one result instead, then retry:
    /// the worker frees a job slot right after each result send lands.
    ///
    /// `handle_worker_result` can re-enter this function (a completed GC
    /// plan dispatches the next handoff in its batch). The nesting is
    /// bounded: GC plans are single-flight, so the drained queue can
    /// hold at most one further GcPlan result.
    fn send_worker_job(&mut self, job: WorkerJob) -> Result<(), (io::Error, Box<WorkerJob>)> {
        let Some(tx) = self.worker_tx.clone() else {
            return Err((io::Error::other("worker not running"), Box::new(job)));
        };
        // Stamped ahead of any retry, so the wait covers the whole
        // dispatch.
        let mut job = QueuedJob {
            queued_at: Instant::now(),
            job,
        };
        loop {
            match tx.try_send(job) {
                Ok(()) => return Ok(()),
                Err(crossbeam_channel::TrySendError::Full(j)) => {
                    job = j;
                    let parked = Instant::now();
                    match self.worker_rx.recv() {
                        Ok(result) => self.handle_worker_result(result),
                        Err(_) => {
                            return Err((
                                io::Error::other("worker result channel closed"),
                                Box::new(job.job),
                            ));
                        }
                    }
                    // What the actor waited for a worker slot, before
                    // applying a result under the volume mutex.
                    let waited = parked.elapsed();
                    if waited >= WORKER_QUEUE_WAIT_FLOOR {
                        info!(
                            "worker queue full: {} dispatch waited {:.0}ms for a slot, \
                             applying a result inline",
                            job.job.label(),
                            waited.as_secs_f64() * 1e3,
                        );
                    }
                }
                Err(crossbeam_channel::TrySendError::Disconnected(j)) => {
                    return Err((io::Error::other("worker channel closed"), Box::new(j.job)));
                }
            }
        }
    }

    /// One GC plan apply: the prep and the swap under the volume mutex,
    /// the fold between them on this thread with the mutex released, and
    /// the publish of an applied swap. Plans arrive in batches the actor
    /// folds back to back, so both holds release to a waiting guest write
    /// with the fair handoff, for the same reason the repack bucket loop
    /// does. The base the swap retired lives until after the publish, so
    /// this thread frees it.
    fn apply_gc_plan(
        &mut self,
        result: crate::volume::GcPlanApplyResult,
    ) -> io::Result<crate::volume::StagedApply> {
        use crate::volume::{PlanFold, PlanSwap, PlanSwapPrep, StagedApply};
        let layers = match self
            .lock_volume(LockSite::GcPlanApply)
            .fair()
            .prepare_plan_swap(&result)
        {
            PlanSwapPrep::Skip(outcome) => return Ok(outcome),
            PlanSwapPrep::Layers(layers) => layers,
        };
        let landed = match crate::volume::fold_plan_apply_result(
            &layers,
            result,
            &self.base_dir,
            &self.ancestor_layers,
        )? {
            PlanFold::Cancelled => return Ok(StagedApply::Cancelled),
            PlanFold::Landed(landed) => landed,
        };
        let swap = self
            .lock_volume(LockSite::GcPlanApply)
            .fair()
            .swap_plan_apply(&landed, layers.base())?;
        match swap {
            PlanSwap::Applied(retired) => {
                self.publish_snapshot();
                drop(retired);
                Ok(StagedApply::Applied)
            }
            PlanSwap::Cancelled => {
                landed.remove_output();
                Ok(StagedApply::Cancelled)
            }
        }
    }

    /// Whether any worker job is dispatched but not yet resolved.
    fn work_in_flight(&self) -> bool {
        self.pipeline.promotes_in_flight > 0
            || self.pipeline.promote_segments_in_flight > 0
            || self.parked.handoff_in_flight
            || self.parked.close_generation.is_some()
            || self.parked.sign_snapshot_manifest.is_some()
            || self.parked.reclaim.is_some()
    }

    /// Apply one worker result: bookkeeping, volume apply, snapshot
    /// publish, and resolution of any parked replies.  Called from the
    /// main select loop and the shutdown drain.
    fn handle_worker_result(&mut self, result: WorkerResult) {
        match result {
            WorkerResult::Promote(Ok(result)) => {
                self.pipeline.promotes_in_flight -= 1;
                let ulid = result.segment_ulid;
                // The fold runs on this thread with the mutex released; the
                // two holds around it clone and swap handles.
                let layers = self
                    .lock_volume(LockSite::PromoteApply)
                    .map_layers()
                    .clone();
                let swap = crate::volume::fold_promote_result(&layers, &result).map(|new_base| {
                    self.lock_volume(LockSite::PromoteApply).swap_promote(
                        &result,
                        new_base,
                        layers.base(),
                    )
                });
                let apply: io::Result<()> = match &swap {
                    Ok(_) => Ok(()),
                    Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
                };
                if let Err(e) = &apply {
                    // The segment is committed and the old WAL was kept, so
                    // reads stay resolvable; the in-memory maps are missing
                    // this apply. Parked repliers get the error so the
                    // coordinator aborts its tick.
                    error!("apply of promoted segment {ulid} failed: {e}");
                }
                self.publish_snapshot();
                drop(swap);
                if apply.is_ok() {
                    crate::volume::remove_promoted_wal(&result);
                    if crate::volume_invariants_enabled() {
                        self.lock_volume(LockSite::PromoteApply)
                            .assert_promote_applied();
                    }
                }
                self.on_promote_result();

                let clone_apply = |apply: &io::Result<()>| match apply {
                    Ok(()) => Ok(()),
                    Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
                };
                // Complete any parked operations this apply satisfies.
                // GC checkpoint: its own promote, or the last promote an
                // empty-WAL checkpoint's barrier was waiting out.
                if let Some((u_buckets, reply)) = self.take_satisfied_gc_checkpoint(ulid) {
                    let own_segments = Some(
                        self.lock_volume(LockSite::OwnSegments)
                            .own_segments_commitment(),
                    );
                    let _ = reply.send(clone_apply(&apply).map(|()| {
                        crate::volume_ipc::GcCheckpointReply {
                            bucket_ulids: u_buckets,
                            own_segments,
                        }
                    }));
                }
                // PromoteWal callers.
                let mut i = 0;
                while i < self.pipeline.parked_promote_wal.len() {
                    if self.pipeline.parked_promote_wal[i].segment_ulid == ulid {
                        let parked = self.pipeline.parked_promote_wal.swap_remove(i);
                        let _ = parked.reply.send(clone_apply(&apply));
                    } else {
                        i += 1;
                    }
                }
            }
            WorkerResult::Promote(Err(failure)) => {
                self.pipeline.promotes_in_flight -= 1;
                let ulid = failure.job.segment_ulid;
                warn!(
                    "worker promote of segment {ulid} failed: {}; stashed for retry",
                    failure.error
                );
                self.on_promote_result();
                // Fail parked repliers waiting on this promote promptly —
                // the coordinator retries on its next tick, and by then
                // `retry_failed_promote` will have re-dispatched the job.
                // A parked barrier always covers the failed promote:
                // results arrive in dispatch order, so every result that
                // lands while the barrier holds carries a generation at
                // or below its `needed_gen`.
                let clone_err = |e: &io::Error| io::Error::new(e.kind(), e.to_string());
                let gc_waiting = match &self.pipeline.parked_gc {
                    Some(ParkedGc::Flush(p)) => p.u_flush == ulid,
                    Some(ParkedGc::Barrier(_)) => true,
                    None => false,
                };
                if gc_waiting && let Some(parked) = self.pipeline.parked_gc.take() {
                    let _ = parked.into_reply().send(Err(clone_err(&failure.error)));
                }
                let mut i = 0;
                while i < self.pipeline.parked_promote_wal.len() {
                    if self.pipeline.parked_promote_wal[i].segment_ulid == ulid {
                        let parked = self.pipeline.parked_promote_wal.swap_remove(i);
                        let _ = parked.reply.send(Err(clone_err(&failure.error)));
                    } else {
                        i += 1;
                    }
                }
                self.pipeline.failed_promotes.push_back(failure.job);
            }
            WorkerResult::GcPlan(Ok(result)) => {
                self.apply_or_defer_gc_plan(Box::new(result));
            }
            WorkerResult::GcPlan(Err(e)) => {
                self.parked.handoff_in_flight = false;
                warn!("worker gc plan apply failed: {e}");
                if let Some(parked) = self.parked.handoffs.take()
                    && let Some(reply) = parked.reply
                {
                    let _ = reply.send(Err(e));
                }
            }
            WorkerResult::PromoteSegment { ulid, result } => {
                self.pipeline.promote_segments_in_flight -= 1;
                match result {
                    Ok(r) => {
                        // The fold runs on this thread with the mutex
                        // released; the two holds around it clone and swap
                        // handles.
                        let layers = self
                            .lock_volume(LockSite::PromoteSegmentApply)
                            .map_layers()
                            .clone();
                        let swap = crate::volume::fold_promote_segment_result(&layers, &r).map(
                            |new_base| {
                                self.lock_volume(LockSite::PromoteSegmentApply)
                                    .swap_promote_segment(&r, new_base, layers.base())
                            },
                        );
                        if swap.is_ok() {
                            self.publish_snapshot();
                        }
                        let apply_result = swap.and_then(|retired| {
                            drop(retired);
                            crate::volume::remove_promoted_segment_sources(&self.base_dir, &r)
                        });
                        self.reply_parked_promote_segment(ulid, apply_result);
                    }
                    Err(e) => {
                        warn!("worker promote_segment for {ulid} failed: {e}");
                        self.reply_parked_promote_segment(ulid, Err(e));
                    }
                }
            }
            WorkerResult::CloseGeneration(result) => {
                let parked = self.parked.close_generation.take();
                let outcome = match result {
                    Ok(r) => self.apply_repack_and_publish(r).map(|_| ()),
                    Err(e) => {
                        warn!("worker close generation failed: {e}");
                        Err(e)
                    }
                };
                if let Some(p) = parked {
                    let _ = p.reply.send(outcome.map(|()| p.rotated));
                }
            }
            WorkerResult::SignSnapshotManifest(result) => {
                let reply = self.parked.sign_snapshot_manifest.take();
                let outcome = match result {
                    Ok(r) => {
                        self.lock_volume(LockSite::SnapshotApply)
                            .apply_sign_snapshot_manifest_result(r);
                        Ok(())
                    }
                    Err(e) => {
                        warn!("worker sign_snapshot_manifest failed: {e}");
                        Err(e)
                    }
                };
                if let Some(reply) = reply {
                    let _ = reply.send(outcome);
                }
            }
            WorkerResult::Reclaim(result) => {
                let reply = self.parked.reclaim.take();
                let outcome = match result {
                    Ok(r) => {
                        let layers = self
                            .lock_volume(LockSite::ReclaimApply)
                            .map_layers()
                            .clone();
                        match crate::volume::fold_reclaim_result(&layers, &r) {
                            Ok(crate::volume::ReclaimFold::Landed { new_base, outcome }) => {
                                let retired = self
                                    .lock_volume(LockSite::ReclaimApply)
                                    .swap_reclaim(&r, new_base, layers.base());
                                self.publish_snapshot();
                                drop(retired);
                                Ok(outcome)
                            }
                            Ok(crate::volume::ReclaimFold::NoSwap(outcome)) => Ok(outcome),
                            Err(e) => Err(e),
                        }
                    }
                    Err(e) => {
                        warn!("worker reclaim failed: {e}");
                        Err(e)
                    }
                };
                if let Some(reply) = reply {
                    let _ = reply.send(outcome);
                }
            }
            #[cfg(test)]
            WorkerResult::Barrier => {}
        }
        // A promote applying above may have been the last one a deferred
        // plan was waiting for.
        if self.pipeline.promotes_in_flight == 0
            && let Some(result) = self.parked.deferred_handoff.take()
        {
            self.apply_or_defer_gc_plan(result);
        }
    }

    /// Apply a completed plan-apply result, or hold it until every
    /// in-flight promote has applied.
    ///
    /// A promote captures index snapshots at prep and decides against them
    /// on the worker, off-lock. A plan apply drops the extents GC found
    /// dead, so landing one inside a promote's prep→apply window lets the
    /// promote commit a reference to an extent that no longer exists — a
    /// delta source is the reference that can name a dead extent, since
    /// every other reference a promote makes is to live content, which a
    /// rewrite must carry forward. Ordering the applies removes the
    /// window. Detecting it at apply cannot work: by then the segment is
    /// committed and the old WAL consumed, so there is nothing to roll
    /// back to.
    ///
    /// Only promotes already in flight matter, because one dispatched
    /// after this preps against post-apply state. Nothing starves: the
    /// worker has already finished the plan, and the wait is bounded by
    /// promotes that are running.
    /// Apply a completed repack result, or hold it until every in-flight
    /// promote has applied.
    ///
    /// Same window as [`Self::apply_or_defer_gc_plan`]: a promote can
    /// commit a delta naming an input-owned hash as its source, and that
    /// reference exists nowhere checkable until the promote applies — so
    /// the stale-liveness refusal in `apply_repack_result` can only be
    /// trusted once in-flight promotes have landed. The reap holds the
    /// same rule by skipping its pass while a promote is in flight.
    fn apply_or_defer_gc_plan(&mut self, result: Box<crate::volume::GcPlanApplyResult>) {
        if self.pipeline.promotes_in_flight > 0 {
            debug!(
                "holding gc plan apply behind {} in-flight promote(s)",
                self.pipeline.promotes_in_flight
            );
            self.parked.deferred_handoff = Some(result);
            return;
        }
        self.parked.handoff_in_flight = false;
        let applied = self.apply_gc_plan(*result);
        match applied {
            Ok(crate::volume::StagedApply::Applied) => {
                if let Some(ref mut parked) = self.parked.handoffs {
                    parked.applied_count += 1;
                }
            }
            Ok(crate::volume::StagedApply::Cancelled) => {
                // Cancelled in worker or stale-liveness in
                // apply; plan/tmp already cleaned up inside.
            }
            Ok(crate::volume::StagedApply::Diverged) => {
                self.on_divergence();
                // No hook (tests): drop the rest of the
                // batch — every remaining plan is suspect
                // against the same read state.
                if let Some(parked) = self.parked.handoffs.as_mut() {
                    parked.remaining.clear();
                }
            }
            Err(e) => {
                warn!("gc plan apply failed: {e}");
                if let Some(parked) = self.parked.handoffs.take()
                    && let Some(reply) = parked.reply
                {
                    let _ = reply.send(Err(e));
                }
            }
        }
        // Dispatch next plan in this batch, or complete.
        if let Some(mut parked) = self.parked.handoffs.take() {
            if parked.remaining.is_empty() {
                if let Some(reply) = parked.reply {
                    let _ = reply.send(Ok(parked.applied_count));
                }
            } else if matches!(
                self.dispatch_next_handoff(&mut parked),
                HandoffDispatch::Dispatched
            ) {
                self.parked.handoffs = Some(parked);
            }
        }
    }

    /// Drain in-flight jobs and join the worker thread.
    ///
    /// Called on shutdown (explicit or handle-drop).  Drops the job sender
    /// to signal the worker to exit, then drains all pending results,
    /// applying successful ones so that the extent index is up to date
    /// before the volume is closed.
    fn shutdown_worker(&mut self) {
        // Drop the sender — worker's recv() will return Disconnected.
        self.worker_tx.take();

        // Drain remaining results.
        while self.work_in_flight() {
            match self.worker_rx.recv() {
                Ok(result) => self.handle_worker_result(result),
                Err(_) => {
                    // Channel closed — worker exited unexpectedly.
                    break;
                }
            }
        }
        // Join the worker thread.
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }
    }

    /// Log what the volume mutex was held for since the last report, and
    /// move the mark.
    ///
    /// Every acquisition named here is time a guest write could spend
    /// waiting, so the line is ranked by hold and closes on the longest
    /// hold the volume has seen. A window costing less than
    /// [`LOCK_REPORT_FLOOR`] keeps its counters and rolls into the next
    /// one, so a quiet volume stays silent and the line that does come
    /// out covers everything since the last, over the span it names.
    fn report_lock_stats(&mut self) {
        if self.lock_stats_marked.elapsed() < LOCK_REPORT_INTERVAL {
            return;
        }
        let window = self.lock_stats.snapshot().since(&self.lock_stats_reported);
        if !window.worth_reporting(LOCK_REPORT_FLOOR) {
            return;
        }
        let now = self.lock_stats.take_window();
        if let Some(report) = now.since(&self.lock_stats_reported).report() {
            info!(
                "[lock {}] {}s: {report}",
                self.volume_label(),
                self.lock_stats_marked.elapsed().as_secs(),
            );
        }
        self.lock_stats_reported = now;
        self.lock_stats_marked = Instant::now();
    }

    /// Log which segment of the flush path the window's guest FLUSHes
    /// spent their time in, and move the mark.
    ///
    /// The device boundary times a flush end to end; this line gives the
    /// requests against the rounds that served them, the batching, and
    /// the wait and sync times.
    fn report_gate(&mut self) {
        if self.gate_marked.elapsed() < LOCK_REPORT_INTERVAL {
            return;
        }
        let now = self.gate.take_window();
        if let Some(report) = now.since(&self.gate_reported).report() {
            info!(
                "[flush {}] {}s: {}",
                self.volume_label(),
                self.gate_marked.elapsed().as_secs(),
                report,
            );
        }
        self.gate_reported = now;
        self.gate_marked = Instant::now();
    }

    /// Warn while failed promotes sit stashed for retry, on the report
    /// cadence, so a persistent failure (e.g. disk full) stays visible
    /// beyond the single line each failure logs.  Every stashed epoch
    /// is a wal/ file held on disk until a retry promotes it.
    fn report_stashed_promotes(&mut self) {
        if self.stash_marked.elapsed() < LOCK_REPORT_INTERVAL {
            return;
        }
        self.stash_marked = Instant::now();
        if let Some(oldest) = self.pipeline.failed_promotes.front() {
            warn!(
                "[promote {}] {} promote(s) stashed for retry; oldest segment {} (wal {})",
                self.volume_label(),
                self.pipeline.failed_promotes.len(),
                oldest.segment_ulid,
                oldest.old_wal_ulid,
            );
        }
    }

    /// The volume's directory name, which is its ULID under `by_id/`.
    ///
    /// Every volume server on a host writes to the same log, so the
    /// report carries this the way the coordinator's own lines carry
    /// `[drain <ulid>]`.
    fn volume_label(&self) -> Cow<'_, str> {
        self.base_dir
            .file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or(Cow::Borrowed("volume"))
    }

    pub fn run(mut self) {
        let idle_tick = tick(IDLE_FLUSH_INTERVAL);
        loop {
            self.report_lock_stats();
            self.report_gate();
            self.report_stashed_promotes();
            crossbeam_channel::select! {
                recv(self.rx) -> msg => {
                    let req = match msg {
                        Ok(r) => r,
                        Err(_) => {
                            // All handles dropped — drain and exit.
                            self.shutdown_worker();
                            return;
                        }
                    };
                    match req {
                        VolumeRequest::CheckPromote => {
                            // Direct writers signal here when needs_promote()
                            // is true post-write.  Idempotent — prepare_promote
                            // handles an empty WAL by returning Ok(None).
                            if self.lock_volume(LockSite::CheckPromote).needs_promote() {
                                self.dispatch_promote();
                            }
                        }
                        VolumeRequest::PromoteWal { reply } => {
                            // Promote the WAL to a pending/ segment via the
                            // worker.  Reply once the segment is on disk.
                            let retried = self.retry_failed_promote();
                            let prep = self.lock_volume(LockSite::PromotePrep).prepare_promote();
                            match prep {
                                Ok(Some(job)) => {
                                    let ulid = job.segment_ulid;
                                    match self.send_promote_job(job) {
                                        Ok(()) => {
                                            self.pipeline.parked_promote_wal.push(
                                                ParkedPromoteWal { segment_ulid: ulid, reply },
                                            );
                                        }
                                        Err(e) => {
                                            let _ = reply.send(Err(e));
                                        }
                                    }
                                }
                                Ok(None) => {
                                    // Current WAL empty. If a stashed failed
                                    // promote was just re-dispatched, park the
                                    // reply on it so the caller observes that
                                    // epoch's outcome; otherwise nothing to do.
                                    if let Some(ulid) = retried {
                                        self.pipeline
                                            .parked_promote_wal
                                            .push(ParkedPromoteWal { segment_ulid: ulid, reply });
                                    } else {
                                        let _ = reply.send(Ok(()));
                                    }
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                }
                            }
                        }
                        VolumeRequest::Reap { stop, reply } => {
                            let _ = reply.send(self.handle_reap(stop));
                        }
                        VolumeRequest::ApplyGcHandoffs { reply } => {
                            self.start_gc_handoffs(Some(reply));
                        }
                        VolumeRequest::CloseGeneration { reply } => {
                            if self.parked.close_generation.is_some() {
                                let _ = reply.send(Err(io::Error::other(
                                    "concurrent close_generation not allowed",
                                )));
                            } else {
                                self.start_close_generation(reply);
                            }
                        }
                        VolumeRequest::GcCheckpoint { max_buckets, reply } => {
                            if self.pipeline.parked_gc.is_some() {
                                // Concurrent GC checkpoint is an error.
                                let _ = reply.send(Err(io::Error::other(
                                    "concurrent gc_checkpoint not allowed",
                                )));
                            } else {
                                self.start_gc_checkpoint(max_buckets, reply);
                            }
                        }
                        VolumeRequest::Promote { ulid, reply } => {
                            // Prep on the actor: cheap directory stat +
                            // job build. Dispatch to worker, park reply.
                            let prep = self.lock_volume(LockSite::PromoteSegmentPrep).prepare_promote_segment(ulid);
                            match prep {
                                Ok(PromoteSegmentPrep::AlreadyPromoted) => {
                                    let _ = reply.send(Ok(()));
                                }
                                Ok(PromoteSegmentPrep::Job(job)) => {
                                    match self.send_worker_job(WorkerJob::PromoteSegment(*job)) {
                                        Ok(()) => {
                                            self.pipeline.promote_segments_in_flight += 1;
                                            self.pipeline.parked_promote_segments.push(
                                                ParkedPromoteSegment { ulid, reply },
                                            );
                                        }
                                        Err((e, _)) => {
                                            let _ = reply.send(Err(e));
                                        }
                                    }
                                }
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                }
                            }
                        }
                        VolumeRequest::FinalizeGcHandoff { ulid, reply } => {
                            let _ = reply.send(self.lock_volume(LockSite::GcHandoffFinalize).finalize_gc_handoff(ulid));
                        }
                        VolumeRequest::SignSnapshotManifest {
                            snap_ulid,
                            kind,
                            reply,
                        } => {
                            if self.parked.sign_snapshot_manifest.is_some() {
                                let _ = reply.send(Err(io::Error::other(
                                    "concurrent sign_snapshot_manifest not allowed",
                                )));
                            } else {
                                self.start_sign_snapshot_manifest(snap_ulid, kind, reply);
                            }
                        }
                        VolumeRequest::NoopStats { reply } => {
                            let _ = reply.send(self.lock_volume(LockSite::NoopStats).noop_stats());
                        }
                        VolumeRequest::Reclaim {
                            start_lba,
                            lba_length,
                            reply,
                        } => {
                            if self.parked.reclaim.is_some() {
                                let _ = reply.send(Err(io::Error::other(
                                    "concurrent reclaim not allowed",
                                )));
                            } else {
                                self.start_reclaim(start_lba, lba_length, reply);
                            }
                        }
                        VolumeRequest::Shutdown => {
                            self.shutdown_worker();
                            return;
                        }
                        #[cfg(test)]
                        VolumeRequest::TestDispatchBarrier { hold } => {
                            if let Err((e, _)) = self.send_worker_job(WorkerJob::Barrier(hold)) {
                                warn!("test barrier dispatch failed: {e}");
                            }
                        }
                        #[cfg(test)]
                        VolumeRequest::TestParkThenDispatchBarriers { park, holds } => {
                            let _ = park.recv();
                            for hold in holds {
                                if let Err((e, _)) = self.send_worker_job(WorkerJob::Barrier(hold)) {
                                    warn!("test barrier dispatch failed: {e}");
                                }
                            }
                        }
                    }
                }
                // Worker thread results (promote completions, GC handoffs).
                recv(self.worker_rx) -> msg => {
                    match msg {
                        Ok(result) => self.handle_worker_result(result),
                        Err(_) => {
                            warn!("worker result channel closed unexpectedly");
                        }
                    }
                }
                recv(idle_tick) -> _ => {
                    // Dispatch a promote if the WAL has unflushed data.
                    // prepare_promote handles the empty-WAL case internally.
                    self.dispatch_promote();
                    // Apply any pending GC plan handoffs inline.
                    self.start_gc_handoffs(None);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Client + Reader
// ---------------------------------------------------------------------------

/// Shareable client handle for a volume session.
///
/// `Send + Sync + Clone`. Holds only shared state (mailbox sender, snapshot
/// pointer, immutable config) — no per-thread cache. Suitable for passing
/// directly into transport closures that require `Send + Sync + Clone`
/// (e.g. `libublk` queue handlers).
///
/// Every method except `read` goes through the actor mailbox or an atomic
/// snapshot load. To perform reads, call [`VolumeClient::reader`] to
/// construct a per-thread [`VolumeReader`].
#[derive(Clone)]
pub struct VolumeClient {
    tx: Sender<VolumeRequest>,
    snapshot: Arc<ArcSwap<ReadSnapshot>>,
    config: Arc<VolumeConfig>,
    /// `Weak` so the client side does not extend the `Volume`'s lifetime —
    /// the actor is the sole strong owner. When the actor thread exits, the
    /// `Volume` is dropped (releasing its `volume.lock` flock) even while
    /// `VolumeClient` clones are still held by callers; tests rely on this
    /// to reopen the volume after `handle.shutdown()`.
    ///
    /// Hot-path writes acquire this lock directly (`write`, `write_zeroes`)
    /// rather than going through the request channel, avoiding a thread
    /// hop and a kernel-buffer copy on every I/O.
    volume: Weak<Mutex<Volume>>,
    /// Shared snapshot-generation counter.  Bumped under the volume mutex
    /// on every `publish_snapshot` (actor-side and direct-write paths).
    /// `Weak` would suffice since the actor is the sole strong owner of
    /// the underlying `AtomicU64` lifetime, but `Arc` keeps the load path
    /// to a single deref — bumps only happen under the volume mutex,
    /// which already pins the actor's strong ref while the actor thread
    /// is alive.
    flush_gen: Arc<AtomicU64>,
    /// Shared counter over the publications that replace or remove segment
    /// files, held on the same terms as `flush_gen`.
    layout_gen: Arc<AtomicU64>,
    /// The volume's single per-process dmat cache, handed to every
    /// reader (see `volume::read::DmatCache`).
    dmat_cache: crate::volume::DmatCache,
    /// The volume's single per-process segment-descriptor cache, shared
    /// by every reader (see `volume::read::FileCache` for the layout-
    /// generation discipline that keeps overlapping snapshots safe).
    file_cache: SharedFileCache,
    /// Volume-mutex occupancy per labelled site, shared with the actor
    /// that records it. Read through [`VolumeClient::lock_stats`].
    lock_stats: Arc<LockStats>,
    /// The sync gate FLUSH and FUA requests run through, shared with the
    /// actor that reports it.
    gate: Arc<SyncGate>,
}

/// Per-thread reader for a volume session.
///
/// Reads resolve segment descriptors through the volume's shared
/// `FileCache` (held on the client), keyed by the snapshot's layout
/// generation. `Send` but `!Sync` — each thread serving reads constructs
/// its own reader via [`VolumeClient::reader`].
///
/// Derefs to [`VolumeClient`], so a reader can also issue writes, flushes,
/// and other control operations without requiring a separate client
/// reference.
pub struct VolumeReader {
    client: VolumeClient,
    /// The volume's shared cache of opened `cache/<ULID>.dmat` sidecars —
    /// one instance per volume per process (see `volume::read::DmatCache`).
    /// Cleared whenever the snapshot's `layout_gen` changes, so an
    /// eviction that drops `.dmat` from disk can't leave a stale FD
    /// pointing at a removed inode.
    dmat_cache: crate::volume::DmatCache,
    /// Telemetry counters for the dmat cache. Per-reader; aggregate by
    /// summing snapshots across readers if needed.
    dmat_stats: Arc<crate::dmat::DmatStats>,
    /// Telemetry counters for the descriptor cache, on the same terms.
    read_stats: Arc<crate::volume::ReadStats>,
    /// Generation at which this reader last cleared the shared dmat cache.
    /// Compared against `ReadSnapshot::layout_gen` on every read; on
    /// change the dmat cache is cleared before proceeding. Reading the
    /// generation and the extent index from the same snapshot load means
    /// the two are always in sync — no separate atomic needed.
    last_layout_gen: Cell<u64>,
}

impl std::ops::Deref for VolumeReader {
    type Target = VolumeClient;

    fn deref(&self) -> &VolumeClient {
        &self.client
    }
}

impl VolumeClient {
    /// Construct a per-thread reader. Each thread serving reads should call
    /// this once and keep the returned reader for the thread's lifetime.
    pub fn reader(&self) -> VolumeReader {
        let current_gen = self.snapshot.load().layout_gen;
        VolumeReader {
            dmat_cache: self.dmat_cache.clone(),
            client: self.clone(),
            dmat_stats: Arc::new(crate::dmat::DmatStats::default()),
            read_stats: Arc::new(crate::volume::ReadStats::default()),
            last_layout_gen: Cell::new(current_gen),
        }
    }

    /// Resize the volume's shared segment-descriptor cache to hold
    /// `capacity` files.
    ///
    /// The cache is shared by every reader of this volume, so `capacity`
    /// is the volume's whole descriptor budget for segment bodies. Drops
    /// every cached descriptor; readers re-open files on their next read.
    pub fn set_read_cache_capacity(&self, capacity: usize) {
        lock_file_cache(&self.file_cache).set_capacity(capacity);
    }
}

impl VolumeClient {
    /// Acquire the live `Volume` mutex.  Returns an error if the actor has
    /// already exited (and therefore dropped its strong `Arc`), since the
    /// `Volume` — and the WAL it owns — is gone.
    fn volume(&self) -> io::Result<Arc<Mutex<Volume>>> {
        self.volume
            .upgrade()
            .ok_or_else(|| io::Error::other("volume actor exited"))
    }

    /// Signal the actor that the WAL may have crossed the promote
    /// threshold.
    ///
    /// Try non-blocking first; on `Full`, fall back to a blocking send.
    /// We're past the volume mutex at this point, and the actor handlers
    /// only block on the same mutex — so the actor will drain a slot as
    /// soon as it finishes its current handler, with no deadlock risk.
    /// Skipping a signal here would otherwise let WAL bytes pile up
    /// behind a full mailbox until the 10 s idle tick wakes a promote.
    fn signal_check_promote(&self) {
        match self.tx.try_send(VolumeRequest::CheckPromote) {
            Ok(()) => {}
            Err(TrySendError::Full(req)) => {
                // Blocking send into the same channel; only fails if the
                // actor has exited, which is the same case we already
                // ignore below.
                let _ = self.tx.send(req);
            }
            Err(TrySendError::Disconnected(_)) => {
                // Actor exited.  The next direct write will surface the
                // error via `volume()`; nothing to do here.
            }
        }
    }

    /// Write `data` at `lba` directly into the volume's WAL.
    ///
    /// Acquires the volume mutex on the calling thread — no actor hop,
    /// no per-write allocation.  Republishes the read snapshot under the
    /// lock so reads see the write atomically with `flush_gen`.  If the
    /// write pushed the WAL across the promote threshold, signals the
    /// actor after releasing the lock (fire-and-forget; idempotent).
    ///
    /// BLAKE3 hashing and lz4 compression both run on the calling thread
    /// *before* the lock is taken, so concurrent ublk workers can do
    /// this CPU-bound work in parallel; only the WAL append and map
    /// updates serialise on the volume mutex.  Trade-off: a no-op skip
    /// or a dedup-REF write computes lz4 output it then throws away —
    /// fine for real ublk traffic, where the kernel page cache filters
    /// unchanged pages and dedup hits are a small fraction of writes.
    ///
    /// `fua` runs the write's generation through the sync gate after the
    /// mutex is released, so the write is durable when this returns and
    /// concurrent FUA writers share one round.  See [`Self::sync_through`].
    pub fn write(&self, lba: u64, data: &[u8], fua: bool) -> io::Result<()> {
        let clock = WriteClock::start();
        let hash = blake3::hash(data);
        let compressed = crate::volume::maybe_compress(data);
        let volume = self.volume()?;
        let asked = clock.asked();
        let (needs_promote, published, taken) = {
            let mut guard = lock_volume_for_write(&volume, &self.lock_stats);
            let taken = Instant::now();
            guard.write_precomputed(lba, data, hash, compressed.as_deref())?;
            let published = publish_snapshot(
                &guard,
                &self.snapshot,
                &self.flush_gen,
                &self.layout_gen,
                Publication::AppendsToWal,
            );
            (guard.needs_promote(), published, taken)
        };
        let released = Instant::now();
        drop(published.previous);
        let synced = if fua {
            let began = Instant::now();
            self.sync_through(published.flush_gen, RequestKind::Fua)?;
            Some(began.elapsed())
        } else {
            None
        };
        if needs_promote {
            self.signal_check_promote();
        }
        self.lock_stats.record_write_phases(clock.phases(
            data.len() as u64,
            asked,
            taken,
            released,
            synced,
        ));
        Ok(())
    }

    /// Zero `lba_count` blocks starting at `lba`.  Direct path — see
    /// [`VolumeClient::write`] for the lock/snapshot/signal pattern.
    /// Writes a single zero-extent WAL record — no hashing, no data payload.
    /// See [`Volume::write_zeroes`] for details.
    pub fn write_zeroes(&self, start_lba: u64, lba_count: u32, fua: bool) -> io::Result<()> {
        let clock = WriteClock::start();
        let volume = self.volume()?;
        let asked = clock.asked();
        let (needs_promote, published, taken) = {
            let mut guard = lock_volume_for_write(&volume, &self.lock_stats);
            let taken = Instant::now();
            guard.write_zeroes(start_lba, lba_count)?;
            let published = publish_snapshot(
                &guard,
                &self.snapshot,
                &self.flush_gen,
                &self.layout_gen,
                Publication::AppendsToWal,
            );
            (guard.needs_promote(), published, taken)
        };
        let released = Instant::now();
        drop(published.previous);
        let synced = if fua {
            let began = Instant::now();
            self.sync_through(published.flush_gen, RequestKind::Fua)?;
            Some(began.elapsed())
        } else {
            None
        };
        if needs_promote {
            self.signal_check_promote();
        }
        self.lock_stats.record_write_phases(clock.phases(
            lba_count as u64 * 4096,
            asked,
            taken,
            released,
            synced,
        ));
        Ok(())
    }

    /// Trim (discard) `lba_count` blocks starting at `lba`.
    pub fn trim(&self, start_lba: u64, lba_count: u32, fua: bool) -> io::Result<()> {
        self.write_zeroes(start_lba, lba_count, fua)
    }

    /// Volume-mutex occupancy per labelled site, cumulative since the
    /// volume opened. Read straight off the shared counters, so it needs
    /// no actor round trip and takes no lock — which is what lets it be
    /// sampled while the actor holds the mutex it describes.
    ///
    /// The guest write path contributes what it waited, under
    /// [`LockStatsSnapshot::writes`] rather than a site.
    pub fn lock_stats(&self) -> LockStatsSnapshot {
        self.lock_stats.snapshot()
    }

    /// Fetch the current no-op write skip counters from the actor.
    /// Blocks until the actor replies. See [`NoopSkipStats`].
    pub fn noop_stats(&self) -> io::Result<NoopSkipStats> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::NoopStats { reply: reply_tx })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))
    }

    /// Durability barrier: every write that completed before this call
    /// survives a crash once it returns. The WAL stays where it is.
    pub fn flush(&self) -> io::Result<()> {
        let generation = self.flush_gen.load(Ordering::SeqCst);
        self.sync_through(generation, RequestKind::Flush)
    }

    /// Run a durability request at `generation` through the sync gate.
    ///
    /// A round syncs the open WAL and every rotated WAL the volume holds,
    /// through handles taken under the mutex after the round's start
    /// generation is read, so the round covers every write at or below
    /// that generation. The syncs count as in flight for the writes that
    /// append meanwhile.
    fn sync_through(&self, generation: u64, kind: RequestKind) -> io::Result<()> {
        let volume = self.volume()?;
        self.gate.sync_through(
            generation,
            kind,
            || self.flush_gen.load(Ordering::SeqCst),
            || {
                let handles = lock_volume_timed(&volume, &self.lock_stats, LockSite::FlushHandle)
                    .sync_handles();
                let _in_flight = self.lock_stats.sync_in_flight();
                for file in &handles {
                    file.sync_data()?;
                }
                Ok(handles.len())
            },
        )
    }

    /// The sync gate's counters so far.
    pub fn sync_gate(&self) -> GateSnapshot {
        self.gate.snapshot()
    }

    /// Promote the WAL to a `pending/` segment.  Blocks until the segment
    /// is on disk.  No-op if the WAL is empty.
    pub fn promote_wal(&self) -> io::Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::PromoteWal { reply: reply_tx })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Close the open generation into `pending/upload/`. Errors if the
    /// upload generation still holds files. Returns the closed
    /// generation's segment count, `None` when the open generation was
    /// empty and nothing rotated.
    pub fn close_generation(&self) -> io::Result<Option<u32>> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::CloseGeneration { reply: reply_tx })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Test seam: dispatch a worker barrier job through the normal
    /// dispatch path. Fire-and-forget.
    #[cfg(test)]
    pub(crate) fn test_dispatch_barrier(&self, hold: crossbeam_channel::Receiver<()>) {
        let _ = self.tx.send(VolumeRequest::TestDispatchBarrier { hold });
    }

    /// Test seam: park the actor in-handler until `park` fires, then
    /// dispatch one barrier job per hold without returning to the
    /// select loop. Fire-and-forget.
    #[cfg(test)]
    pub(crate) fn test_park_then_dispatch_barriers(
        &self,
        park: crossbeam_channel::Receiver<()>,
        holds: Vec<crossbeam_channel::Receiver<()>>,
    ) {
        let _ = self
            .tx
            .send(VolumeRequest::TestParkThenDispatchBarriers { park, holds });
    }

    /// One reap pass over `pending/open/`: unlink whatever nothing
    /// references. Blocks until the actor replies. A pass finding
    /// nothing (or skipped behind an in-flight promote) reports zeros,
    /// so the caller may tick as often as it likes.
    pub fn reap(&self) -> io::Result<crate::volume::ReapStats> {
        self.reap_stopping(ReapStop::Never)
    }

    /// [`Self::reap`], stopping the pass at `stop`. A stop leaves the
    /// volume mid-transaction in a way only a crash reaches in
    /// production, where the phases run back to back under the actor,
    /// so the caller must crash (shut the actor down and reopen)
    /// immediately after.
    pub fn reap_stopping(&self, stop: ReapStop) -> io::Result<crate::volume::ReapStats> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::Reap {
                stop,
                reply: reply_tx,
            })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Apply any pending GC handoff files via the actor.  Blocks until the
    /// actor replies.  The actor republishes the snapshot if any handoffs were
    /// applied so that reads immediately reflect the updated extent index.
    pub fn apply_gc_handoffs(&self) -> io::Result<usize> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::ApplyGcHandoffs { reply: reply_tx })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Establish a GC checkpoint: flush the WAL and return `max_buckets`
    /// pre-minted output ULIDs for the GC output segments. Each bucket
    /// ULID is strictly ordered below the fresh WAL's ULID. Blocks until
    /// the actor replies.
    ///
    /// The coordinator picks at most `max_buckets` of the returned ULIDs
    /// for the plans it emits this tick; unused ULIDs are simply
    /// discarded (the volume's mint advances past them anyway).
    pub fn gc_checkpoint(
        &self,
        max_buckets: usize,
    ) -> io::Result<crate::volume_ipc::GcCheckpointReply> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::GcCheckpoint {
                max_buckets,
                reply: reply_tx,
            })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Promote a segment to the local cache after confirmed S3 upload.
    ///
    /// Sends a `promote <ulid>` request to the actor and blocks until it replies.
    pub fn promote_segment(&self, ulid: Ulid) -> io::Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::Promote {
                ulid,
                reply: reply_tx,
            })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Finalize a GC handoff by deleting bare `gc/<ulid>` via the actor.
    /// Routing the delete through the actor keeps every mutation of `gc/`
    /// serialised with the idle-tick apply path, so the coordinator never
    /// races the volume on `gc/` filenames. Blocks until the actor replies.
    pub fn finalize_gc_handoff(&self, ulid: Ulid) -> io::Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::FinalizeGcHandoff {
                ulid,
                reply: reply_tx,
            })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Sign and write a `snapshots/<snap_ulid>.manifest` file plus the
    /// marker file. Called by the coordinator after a synchronous drain has
    /// moved every in-flight segment from `pending/` to `index/`.
    ///
    /// The volume enumerates its own `index/` at handler time — no prior
    /// snapshot is read. The result is a full list of segment ULIDs
    /// belonging to this volume as of the snapshot.
    pub fn sign_snapshot_manifest(&self, snap_ulid: Ulid) -> io::Result<()> {
        self.sign_snapshot_manifest_kind(snap_ulid, crate::signing::SnapshotKind::User)
    }

    /// Kind-explicit variant: choose between `<ulid>.manifest` (User —
    /// the stable user/release snapshot) and `<ulid>-stop.manifest`
    /// (Auto — the ephemeral checkpoint written by `volume stop`).
    pub fn sign_snapshot_manifest_kind(
        &self,
        snap_ulid: Ulid,
        kind: crate::signing::SnapshotKind,
    ) -> io::Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::SignSnapshotManifest {
                snap_ulid,
                kind,
                reply: reply_tx,
            })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }

    /// Signal the actor to shut down and drain remaining requests.
    pub fn shutdown(&self) {
        let _ = self.tx.send(VolumeRequest::Shutdown);
    }

    /// Scan the current LBA map + extent index for hashes worth rewriting.
    ///
    /// Read-only. Runs entirely against the current `ReadSnapshot` with
    /// no actor round-trip and no file I/O. Returned candidates are
    /// sorted by dead-block count descending — feed them to
    /// [`VolumeClient::reclaim_alias_merge`] in order for
    /// "most-wasteful-first" reclamation.
    ///
    /// See [`scan_reclaim_candidates`] for the detection logic.
    pub fn reclaim_candidates(&self, thresholds: ReclaimThresholds) -> Vec<ReclaimCandidate> {
        let maps = self.snapshot.load().maps.materialised();
        scan_reclaim_candidates(&maps.lbamap, &maps.extent_index, thresholds)
    }

    /// Alias-merge extent reclamation over `[lba, lba + lba_length)`.
    ///
    /// Volume-side primitive that rewrites aliased runs of a single
    /// hash inside the target range as fresh compact entries, leaving
    /// the old bloated body orphaned for coordinator GC to eventually
    /// drop. Preserves content boundaries — never merges across
    /// different hashes. Safe on any volume.
    ///
    /// One actor round-trip: the actor preps the job, dispatches the
    /// heavy middle (read + re-hash + re-compress + segment assembly)
    /// to the worker thread, then applies the result under the actor
    /// lock with a pointer-equality precondition on the captured
    /// `Arc<LbaMap>`. A concurrent mutation between prepare and apply
    /// causes a clean discard (the worker's output segment is deleted)
    /// and the caller is free to try again later.
    ///
    /// See `docs/design/extent-reclamation.md`.
    pub fn reclaim_alias_merge(&self, lba: u64, lba_length: u32) -> io::Result<ReclaimOutcome> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::Reclaim {
                start_lba: lba,
                lba_length,
                reply: reply_tx,
            })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
    }
}

impl VolumeReader {
    /// Read 4 KiB blocks starting at `lba` into the caller-supplied `buf`.
    ///
    /// `buf.len()` must be a multiple of 4096. Resolved entirely on the
    /// calling thread using the current `ReadSnapshot` — no channel
    /// round-trip. Reflects all writes that have returned `Ok`, including
    /// those not yet flushed to disk (read-your-writes guarantee).
    pub fn read_into(&self, lba: u64, buf: &mut [u8]) -> io::Result<()> {
        // Load the snapshot first. flush_gen is embedded in the snapshot so
        // the generation and the extent index offsets are always consistent —
        // a single ArcSwap::load() gives both atomically with no window.
        let snap = self.client.snapshot.load();
        self.read_with_snapshot(&snap, lba, buf)
    }

    /// Read through `snap`, upgrading to the currently-published
    /// snapshot on `NotFound`.
    ///
    /// A `NotFound` here means `snap` references a segment file that a
    /// repack consumed and unlinked after `snap` was published. The
    /// actor publishes the post-repack snapshot before unlinking, so
    /// reloading and retrying resolves the same LBA through the
    /// repack's output. Bounded: each retry requires `flush_gen` to
    /// have advanced; if it hasn't, the segment is genuinely missing
    /// and the error propagates.
    fn read_with_snapshot(&self, snap: &ReadSnapshot, lba: u64, buf: &mut [u8]) -> io::Result<()> {
        let mut result = self.read_with_snapshot_once(snap, lba, buf);
        let mut seen_gen = snap.flush_gen;
        for _ in 0..2 {
            match &result {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let fresh = self.client.snapshot.load();
                    if fresh.flush_gen == seen_gen {
                        break;
                    }
                    seen_gen = fresh.flush_gen;
                    result = self.read_with_snapshot_once(&fresh, lba, buf);
                }
                _ => break,
            }
        }
        result
    }

    fn read_with_snapshot_once(
        &self,
        snap: &ReadSnapshot,
        lba: u64,
        buf: &mut [u8],
    ) -> io::Result<()> {
        if snap.layout_gen != self.last_layout_gen.get() {
            self.dmat_cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            self.last_layout_gen.set(snap.layout_gen);
        }
        let config = &self.client.config;
        let extent_index = &snap.maps.base().extent_index;
        read_extents(
            lba,
            buf,
            &snap.maps,
            snap.layout_gen,
            &self.client.file_cache,
            &self.dmat_cache,
            &self.dmat_stats,
            &self.read_stats,
            &config.cache_dir,
            |id, bss, idx| {
                find_segment_in_dirs(
                    id,
                    &config.base_dir,
                    &config.ancestor_layers,
                    config.fetcher.as_ref(),
                    extent_index,
                    bss,
                    idx,
                )
            },
            |id| {
                open_delta_body_in_dirs(
                    id,
                    &config.base_dir,
                    &config.ancestor_layers,
                    config.fetcher.as_ref(),
                )
            },
        )
    }

    /// Allocating convenience wrapper around [`VolumeReader::read_into`].
    ///
    /// The hot read path (ublk dispatch) calls `read_into` directly with the
    /// kernel's IO buffer; this allocating form is used by tests.
    pub fn read(&self, lba: u64, lba_count: u32) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; lba_count as usize * 4096];
        self.read_into(lba, &mut buf)?;
        Ok(buf)
    }

    /// Snapshot the dmat telemetry counters for this reader.
    pub fn dmat_stats(&self) -> crate::dmat::DmatStatsSnapshot {
        self.dmat_stats.snapshot()
    }

    /// Snapshot the descriptor-cache counters for this reader.
    pub fn read_stats(&self) -> crate::volume::ReadStatsSnapshot {
        self.read_stats.snapshot()
    }
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

/// A job with the instant the actor handed it to the channel, which the
/// single worker thread reads back as the wait behind the jobs ahead.
struct QueuedJob {
    queued_at: Instant,
    job: WorkerJob,
}

/// Queue wait a job reports at `info`. A shorter wait reports at `debug`.
const WORKER_QUEUE_WAIT_FLOOR: Duration = Duration::from_millis(50);

/// Long-lived worker thread that processes off-actor jobs (WAL promotes,
/// GC handoff re-signs, etc.).
///
/// Receives jobs via `job_rx`, executes each, and sends the result back on
/// `result_tx`.  Exits when `job_rx` disconnects (actor dropped the sender)
/// or `result_tx` disconnects (actor gone).
fn worker_thread(
    job_rx: Receiver<QueuedJob>,
    result_tx: Sender<WorkerResult>,
    stats: Arc<LockStats>,
) {
    let mut prior_cache = PriorSourceCache::default();
    while let Ok(QueuedJob { queued_at, job }) = job_rx.recv() {
        let label = job.label();
        let waited = queued_at.elapsed();
        let started = Instant::now();
        let running = stats.worker_running();
        let msg = match job {
            WorkerJob::Promote(job) => {
                WorkerResult::Promote(execute_promote(job, &mut prior_cache))
            }
            WorkerJob::GcPlan(job) => WorkerResult::GcPlan(execute_gc_plan_apply(job)),
            WorkerJob::PromoteSegment(job) => {
                let ulid = job.ulid;
                let result = execute_promote_segment(job);
                WorkerResult::PromoteSegment { ulid, result }
            }
            WorkerJob::CloseGeneration(job) => WorkerResult::CloseGeneration(execute_repack(job)),
            WorkerJob::SignSnapshotManifest(job) => {
                WorkerResult::SignSnapshotManifest(execute_sign_snapshot_manifest(job))
            }
            WorkerJob::Reclaim(job) => WorkerResult::Reclaim(execute_reclaim(job)),
            #[cfg(test)]
            WorkerJob::Barrier(hold) => {
                let _ = hold.recv();
                WorkerResult::Barrier
            }
        };
        drop(running);
        let ran = started.elapsed();
        if waited >= WORKER_QUEUE_WAIT_FLOOR {
            info!(
                "worker: {label} waited {:.0}ms for the thread, ran {:.0}ms",
                waited.as_secs_f64() * 1e3,
                ran.as_secs_f64() * 1e3,
            );
        } else {
            debug!(
                "worker: {label} waited {:.0}ms for the thread, ran {:.0}ms",
                waited.as_secs_f64() * 1e3,
                ran.as_secs_f64() * 1e3,
            );
        }
        if result_tx.send(msg).is_err() {
            break;
        }
    }
}

/// Execute a WAL promote job: fsync the old WAL, then write the
/// segment to `pending/`.
///
/// The old-WAL fsync is the durability barrier that `prepare_promote`
/// used to run on the actor thread.  Moving it here off-loads the
/// 10–50 ms fsync cost from the write path: the actor keeps taking
/// new writes onto the fresh WAL while the worker makes the old one
/// durable in parallel — matching the way a real block device keeps
/// accepting commands while a FLUSH is in flight.  `VolumeActor::Flush`
/// parks on a promote-generation counter so FLUSH still replies
/// only after every prior write is durable.
/// Worker: materialise a GC plan end-to-end (read bodies, reconstruct
/// partial-death composites, assemble + sign output segment, write
/// `<ulid>.tmp`). Does not touch the extent index; the actor's
/// [`crate::volume::Volume::apply_plan_apply_result`] phase re-derives
/// updates against the current extent index after the worker returns.
///
/// On soft cancellation (missing input, unresolvable hash, body integrity
/// failure) the worker removes the `.plan` file and returns a result with
/// `outcome = Cancelled`; the actor's apply phase treats this as a no-op.
/// Hard I/O failures propagate as `Err`.
pub fn execute_gc_plan_apply(job: GcPlanApplyJob) -> io::Result<GcPlanApplyResult> {
    use crate::rewrite_apply;

    let GcPlanApplyJob {
        plan_path,
        new_ulid,
        gc_dir,
        index_dir,
        base_dir,
        ancestor_layers,
        fetcher,
        extent_index,
        signer,
        verifying_key,
        plan,
    } = job;

    // Resolver borrows the owned fields for the duration of materialise.
    let resolver = WorkerBodyResolver {
        base_dir: &base_dir,
        ancestor_layers: &ancestor_layers,
        fetcher: fetcher.as_ref(),
        extent_index: &extent_index,
    };
    let inputs = plan.inputs();
    let ctx = match rewrite_apply::MaterialiseCtx::new(&base_dir, &inputs, &extent_index, &resolver)
    {
        Ok(c) => c,
        Err(rewrite_apply::MaterialiseOutcome::Io(e)) => return Err(e),
        Err(rewrite_apply::MaterialiseOutcome::Cancel(e)) => {
            log::warn!("plan {new_ulid}: prepare cancelled ({e}); removing");
            let _ = fs::remove_file(&plan_path);
            return Ok(cancelled_result(new_ulid, plan_path, gc_dir, inputs));
        }
    };
    let materialised = match rewrite_apply::materialise_plan(&plan, &ctx) {
        Ok(m) => m,
        Err(rewrite_apply::MaterialiseOutcome::Io(e)) => return Err(e),
        Err(rewrite_apply::MaterialiseOutcome::Cancel(e)) => {
            log::warn!("plan {new_ulid}: materialise cancelled ({e}); removing");
            let _ = fs::remove_file(&plan_path);
            return Ok(cancelled_result(new_ulid, plan_path, gc_dir, inputs));
        }
    };
    drop(ctx);

    let rewrite_apply::Materialised {
        entries,
        delta_body,
    } = materialised;

    // Collect hash-owning entries from each input's `.idx` for the apply
    // phase's to-remove / stale-cancel derivation: both the inner-map
    // and deltas-map slots need the same to_remove cleanup when the
    // input segment is consumed.
    let mut input_old_entries: Vec<(blake3::Hash, segment::EntryKind, Ulid)> = Vec::new();
    let mut input_claim_ranges: Vec<(u64, u32)> = Vec::new();
    for input_ulid in &inputs {
        let idx_path = index_dir.join(format!("{input_ulid}.idx"));
        let parsed = match segment::read_segment_index(&idx_path) {
            Ok(v) => v,
            // Skipping the input leaves its ranges out of
            // `input_claim_ranges` while `consumed` keeps naming it, so
            // the apply's dropped-claim refusal stops seeing the claims
            // it holds. Say so: the count this narrows by is silent
            // otherwise.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                log::warn!(
                    "plan {new_ulid}: input {input_ulid} has no idx at {}; its claims are \
                     outside the coverage check for this apply",
                    idx_path.display(),
                );
                continue;
            }
            Err(e) => return Err(e),
        };
        let (_, old_entries, _) = parsed;
        for e in &old_entries {
            if e.kind.owns_extent_hash() {
                input_old_entries.push((e.hash, e.kind, *input_ulid));
            }
            if !e.kind.is_canonical_only() {
                input_claim_ranges.push((e.start_lba, e.lba_length));
            }
        }
    }

    // Write the signed output segment to <ulid>.tmp. The actor renames it
    // to bare <ulid> as the commit point.
    let tmp_path = gc_dir.join(format!("{new_ulid}.tmp"));
    segment::write_segment_full(
        &tmp_path,
        entries,
        &delta_body,
        &inputs,
        crate::sketch_enabled(),
        signer.as_ref(),
    )?;

    let (new_bss, written_entries, _) =
        segment::read_and_verify_segment_index(&tmp_path, &verifying_key)?;
    let handoff_inline = segment::read_inline_section(&tmp_path)?;
    let carried_hashes = ExtentIndex::carried_hashes(&written_entries);
    let entry_hashes = written_entries.iter().map(|e| e.hash).collect();

    Ok(GcPlanApplyResult {
        new_ulid,
        plan_path,
        gc_dir,
        tmp_path: Some(tmp_path),
        new_bss,
        entries: written_entries,
        inputs,
        input_old_entries,
        input_claim_ranges,
        carried_hashes,
        entry_hashes,
        handoff_inline,
        outcome: crate::volume::StagedApply::Applied,
    })
}

fn cancelled_result(
    new_ulid: Ulid,
    plan_path: std::path::PathBuf,
    gc_dir: std::path::PathBuf,
    inputs: Vec<Ulid>,
) -> GcPlanApplyResult {
    GcPlanApplyResult {
        new_ulid,
        plan_path,
        gc_dir,
        tmp_path: None,
        new_bss: 0,
        entries: Vec::new(),
        inputs,
        input_old_entries: Vec::new(),
        input_claim_ranges: Vec::new(),
        carried_hashes: Default::default(),
        entry_hashes: Default::default(),
        handoff_inline: Vec::new(),
        outcome: crate::volume::StagedApply::Cancelled,
    }
}

/// `BodyResolver` impl that holds borrowed references to the volume's
/// segment-resolution dependencies. Used both by the worker-thread GC
/// apply path (which doesn't have a live Volume to borrow) and by
/// synchronous, on-actor rewriters (sweep / repack)
/// that hold a `&Volume` and can lend its fields.
pub(crate) struct WorkerBodyResolver<'a> {
    pub(crate) base_dir: &'a std::path::Path,
    pub(crate) ancestor_layers: &'a [AncestorLayer],
    pub(crate) fetcher: Option<&'a BoxFetcher>,
    pub(crate) extent_index: &'a crate::extentindex::ExtentIndex,
}

impl crate::rewrite_apply::BodyResolver for WorkerBodyResolver<'_> {
    fn find_segment(
        &self,
        segment_id: Ulid,
        body_section_start: u64,
        body_source: crate::extentindex::BodySource,
    ) -> io::Result<(std::path::PathBuf, segment::SegmentBodyLayout)> {
        let path = crate::volume::find_segment_in_dirs(
            segment_id,
            self.base_dir,
            self.ancestor_layers,
            self.fetcher,
            self.extent_index,
            body_section_start,
            body_source,
        )?;
        let layout = if path.extension().is_some_and(|e| e == "body") {
            segment::SegmentBodyLayout::BodyOnly
        } else {
            segment::SegmentBodyLayout::FullSegment
        };
        Ok((path, layout))
    }

    fn locate_segment_unchecked(
        &self,
        segment_id: Ulid,
    ) -> Option<(std::path::PathBuf, segment::SegmentBodyLayout)> {
        if let Some(hit) = segment::locate_segment_body(self.base_dir, segment_id) {
            return Some(hit);
        }
        for layer in self.ancestor_layers.iter().rev() {
            if let Some(hit) = segment::locate_segment_body(&layer.dir, segment_id) {
                return Some(hit);
            }
        }
        None
    }

    fn open_delta_body(&self, segment_id: Ulid) -> io::Result<fs::File> {
        crate::volume::open_delta_body_in_dirs(
            segment_id,
            self.base_dir,
            self.ancestor_layers,
            self.fetcher,
        )
    }
}

/// [`SnapshotSourceMap`] reused across promote jobs on one thread, keyed
/// by the sealed snapshot ULID it was built from. The build walks the
/// provenance chain and every `.idx` in the lineage, so paying that once
/// per snapshot rather than once per promote matters under sustained
/// write load; what stays resident between promotes is only the packed
/// `LBA → hash` runs. The worker thread owns one across its job loop;
/// inline promote sites pass a fresh default.
#[derive(Default)]
pub(crate) struct PriorSourceCache {
    cached: Option<(Ulid, crate::block_reader::SnapshotSourceMap)>,
}

impl PriorSourceCache {
    /// Source map for `snap_ulid`, rebuilding when the cached one was
    /// built from a different snapshot.
    fn map_for(
        &mut self,
        base_dir: &std::path::Path,
        snap_ulid: Ulid,
        journal_ranges: &crate::journal::JournalRanges,
    ) -> io::Result<&crate::block_reader::SnapshotSourceMap> {
        if self.cached.as_ref().is_none_or(|(u, _)| *u != snap_ulid) {
            let map = crate::block_reader::SnapshotSourceMap::build(
                base_dir,
                &snap_ulid,
                journal_ranges,
            )?;
            self.cached = Some((snap_ulid, map));
        }
        // The line above just populated the cache on the miss path.
        Ok(&self
            .cached
            .as_ref()
            .expect("prior source cache populated")
            .1)
    }
}

/// Execute a promote job: fsync the old WAL, materialise pending bodies
/// from it, delta-classify against the sealed snapshot, and write +
/// commit the pending segment.
///
/// On failure the job is returned intact inside [`PromoteFailure`] so the
/// caller can retry it — the old WAL on disk stays the durable copy of the
/// epoch, and a retry rewrites the same `pending/<ulid>.tmp` idempotently.
/// The delta conversion mutates only the materialised pendings, never
/// `job.entries`, so a failed promote restores cleanly.
///
/// Also reachable from the inline (on-actor) `Volume::flush_wal_to_pending_as`
/// path and the startup recovery promote in `Volume::open_impl`, so all
/// three execution sites share one write pass.
pub(crate) fn execute_promote(
    mut job: PromoteJob,
    prior_cache: &mut PriorSourceCache,
) -> Result<PromoteResult, PromoteFailure> {
    let maps = job.layers.materialised();
    let (primary, journal, dedup) = crate::volume::stage_pending_for_promote(
        std::mem::take(&mut job.pending),
        &maps.extent_index,
        job.old_wal_ulid,
        &job.journal_ranges,
        job.journal_segment_ulid,
    );
    match write_promote(&job, &maps, &primary, journal.as_ref(), prior_cache) {
        Ok(mut result) => {
            result.dedup = dedup;
            Ok(result)
        }
        Err(error) => {
            job.pending = primary.into_writes();
            if let Some(j) = journal {
                job.pending.extend(j.partition.into_writes());
            }
            Err(PromoteFailure {
                error,
                job: Box::new(job),
            })
        }
    }
}

/// Write the staged partitions as segments. `maps` is the job's layers
/// folded into one map; the delta tiers resolve sources through it.
fn write_promote(
    job: &PromoteJob,
    maps: &crate::map_layers::Maps,
    primary: &crate::volume::PendingPartition,
    journal: Option<&crate::volume::JournalPartition>,
    prior_cache: &mut PriorSourceCache,
) -> io::Result<PromoteResult> {
    std::fs::File::open(&job.old_wal_path).and_then(|f| f.sync_data())?;

    // Body bytes for entries written via `write_commit` live only in the WAL
    // between commit and promote. Pair each pending write back with its bytes
    // for write_and_commit to consume.
    let mut pendings =
        crate::volume::materialise_pending_bodies(&job.old_wal_path, primary.writes())?;

    // Delta tiers, in cascade order. Same-LBA first where the volume has a
    // sealed snapshot, then resemblance over what it left alone. Both are
    // best-effort on source-map construction — a promote must not fail
    // because a delta optimisation's inputs were unavailable — while
    // conversion errors are real corruption and fail the promote.
    let mut delta_body: Vec<u8> = Vec::new();
    let mut reserved_sources = crate::blake3_id_hasher::Blake3HashSet::default();
    if job.delta.policy.enabled {
        // The probe is a delta-optimisation input, so a probe failure
        // skips the tier.
        let prior_snap = match &job.delta.prior {
            Some(spec) => match crate::volume::latest_snapshot(&spec.base_dir) {
                Ok(latest) => latest.map(|snap_ulid| (spec, snap_ulid)),
                Err(e) => {
                    warn!(
                        "formation {}: snapshot probe failed, skipping same-LBA delta tier: {e}",
                        job.segment_ulid
                    );
                    None
                }
            },
            None => None,
        };
        if let Some((prior_spec, snap_ulid)) = prior_snap {
            match prior_cache.map_for(&prior_spec.base_dir, snap_ulid, &prior_spec.journal_ranges) {
                Ok(prior) => {
                    match crate::delta_compute::delta_pendings_against_prior(
                        &mut pendings,
                        prior,
                        &maps.extent_index,
                        &job.delta.search_dirs,
                    ) {
                        Ok((body, stats, reserved)) => {
                            if stats.entries_converted > 0 {
                                log::info!(
                                    "formation {}: {} delta entries vs snapshot {}, {} → {} bytes, {} entries held as sources",
                                    job.segment_ulid,
                                    stats.entries_converted,
                                    snap_ulid,
                                    stats.original_body_bytes,
                                    stats.delta_body_bytes,
                                    stats.entries_reserved_as_sources,
                                );
                            }
                            delta_body = body;
                            reserved_sources = reserved;
                        }
                        Err(e) => return Err(e),
                    }
                }
                Err(e) => {
                    warn!(
                        "formation {}: snapshot {snap_ulid} source map unavailable, skipping same-LBA delta tier: {e}",
                        job.segment_ulid
                    );
                }
            }
        }

        // The resemblance tier's cost filter asks "is this candidate
        // source worth pinning" against claims plus every named delta
        // source — the same liveness definition every deletion decision
        // uses, so the filter never skips a source the GC would keep.
        let referenced = maps
            .lbamap
            .referenced_hashes(maps.extent_index.named_delta_sources());
        let stats = crate::delta_compute::delta_pendings_by_resemblance(
            &mut pendings,
            &job.delta.sketch_index,
            &maps.extent_index,
            &referenced,
            &job.delta.search_dirs,
            &mut delta_body,
            &reserved_sources,
        )?;
        if stats.delta.entries_converted > 0 || stats.targets_probed > 0 {
            log::info!(
                "formation {}: resemblance probed {} target(s), tried {} dictionary(s) over {} bytes ({} cached), skipped {} unreferenced, converted {} entries, {} → {} bytes",
                job.segment_ulid,
                stats.targets_probed,
                stats.candidates_tried,
                stats.dictionary_bytes_read,
                stats.dictionary_cache_hits,
                stats.candidates_unreferenced,
                stats.delta.entries_converted,
                stats.delta.original_body_bytes,
                stats.delta.delta_body_bytes,
            );
        }
    }

    // An all-journal epoch leaves the primary partition empty; no
    // primary segment file is written, and the result carries the
    // primary ULID with no entries (parked-reply matching keys on it).
    let (body_section_start, entries) = if pendings.is_empty() {
        (0, Vec::new())
    } else {
        segment::write_and_commit(
            &job.pending_dir,
            job.segment_ulid,
            pendings,
            &delta_body,
            job.delta.policy.persist_sketches,
            job.signer.as_ref(),
        )?
    };
    let delta_region_body_length: u64 = if delta_body.is_empty() {
        0
    } else {
        entries
            .iter()
            .filter(|e| e.kind == segment::EntryKind::Data)
            .map(|e| e.stored_length as u64)
            .sum()
    };

    // The epoch's journal-window share commits as its own segment, so
    // it dies whole as the journal wraps. Never delta'd.
    let journal = match journal {
        None => None,
        Some(jpart) => {
            let j_pendings = crate::volume::materialise_pending_bodies(
                &job.old_wal_path,
                jpart.partition.writes(),
            )?;
            match segment::write_and_commit(
                &job.pending_dir,
                jpart.segment_ulid,
                j_pendings,
                &[],
                job.delta.policy.persist_sketches,
                job.signer.as_ref(),
            ) {
                Ok((j_bss, j_entries)) => {
                    log::info!(
                        "formation {}: journal segment, {} entries",
                        jpart.segment_ulid,
                        j_entries.len(),
                    );
                    Some(crate::volume::JournalSegmentResult {
                        segment_ulid: jpart.segment_ulid,
                        body_section_start: j_bss,
                        entries: j_entries,
                        pre_promote_offsets: jpart.partition.pre_promote_offsets().to_vec(),
                    })
                }
                Err(e) => return Err(e),
            }
        }
    };

    Ok(PromoteResult {
        segment_ulid: job.segment_ulid,
        old_wal_ulid: job.old_wal_ulid,
        old_wal_path: job.old_wal_path.clone(),
        body_section_start,
        entries,
        pre_promote_offsets: primary.pre_promote_offsets().to_vec(),
        delta_region_body_length,
        journal,
        dedup: crate::volume::DedupMintStats::default(),
    })
}

/// Execute a `promote_segment` job: read + verify the source segment
/// index once, write `index/<ulid>.idx` + `cache/<ulid>.{body,present}`
/// (both idempotent), and return the parsed state the actor's apply
/// phase needs for extent-index updates.
///
/// Also reachable from the inline (on-actor) `Volume::promote_segment`
/// path so that the two execution sites share one parse/verify pass.
pub(crate) fn execute_promote_segment(job: PromoteSegmentJob) -> io::Result<PromoteSegmentResult> {
    let parsed = job
        .segment_cache
        .read_and_verify(&job.src_path, &job.verifying_key)?;

    // Tombstone shortcut: GC output with zero entries + non-empty inputs
    // exists only to acknowledge that the input segments are safe to
    // delete. No idx or body is written; the apply phase handles the
    // input-idx cleanup.
    if !job.is_drain && parsed.entries.is_empty() && !parsed.inputs.is_empty() {
        return Ok(PromoteSegmentResult {
            ulid: job.ulid,
            is_drain: job.is_drain,
            parsed,
            inline: Vec::new(),
            tombstone: true,
        });
    }

    // Both writes are idempotent: extract_idx early-returns when idx_path
    // exists; promote_to_cache early-returns when its cache form is
    // provably complete (not on bare `.body` existence — that may be a
    // partial fetch-created file). This covers the mid-apply crash retry
    // window described in docs/plans/promote-segment-offload-plan.md —
    // the source survives, prep picks it up, the worker re-parses
    // (cheap) and the file writes short-circuit.
    segment::extract_idx(&job.src_path, &job.idx_path)?;
    segment::promote_to_cache(&job.src_path, &job.body_path, &job.present_path)?;

    // Inline section is only needed by the drain-path apply to build
    // `inline_data` for `BodySource::Cached` entries whose kind is
    // `Inline`. The GC apply phase never touches the extent index so
    // the read would be wasted there.
    let inline = if job.is_drain
        && parsed
            .entries
            .iter()
            .any(|e| e.kind == segment::EntryKind::Inline)
    {
        segment::read_inline_section(&job.src_path)?
    } else {
        Vec::new()
    };

    Ok(PromoteSegmentResult {
        ulid: job.ulid,
        is_drain: job.is_drain,
        parsed,
        inline,
        tombstone: false,
    })
}

/// Target output segment size for repack, in **stored** bytes: a
/// bucket's budget is spent against `live_bytes`, the sum of
/// `stored_length`, so it measures the body in the form its codec names
/// and an output lands near this size on disk and on S3. GC's
/// `SWEEP_MATERIALISE_CAP` is the same size in the same unit.
pub(crate) const REPACK_TARGET_LIVE: u64 = 32 * 1024 * 1024;

/// Entry-count cap on a packed output. Mirrors the WAL's
/// `FLUSH_ENTRY_THRESHOLD` so packed outputs sit at the same scale as
/// freshly-flushed segments and the index region stays bounded.
const REPACK_ENTRY_CAP: usize = 8192;

/// Remove any stale promote siblings (`index/<u>.idx`, `cache/<u>.body`,
/// `cache/<u>.present`, `cache/<u>.delta`) that a crashed half-promote may
/// have left alongside a pending segment whose body is about to be
/// rewritten.
///
/// Called by `execute_repack` for every input it consumes, on both the
/// data and the journal bucket. Each file is removed best-effort —
/// `NotFound` is not an error, which is the usual case.
///
/// Reads survive a surviving sibling on their own: the output ULID is
/// minted above every input's, so a resurrected input loses each claim
/// it makes, and bodies are content-addressed. What this holds is that
/// the segment set a rebuild finds is the one the volume believes it
/// has, which the extent index reads as a canonical-owner difference
/// rather than a wrong byte. `repack_half_promote_repro` pins it.
///
/// Fsyncs the parent directories after removal so the absence survives
/// a crash immediately after return.
pub(crate) fn invalidate_promote_siblings(
    index_dir: &std::path::Path,
    cache_dir: &std::path::Path,
    ulid: Ulid,
) -> io::Result<()> {
    let ulid_str = ulid.to_string();
    let idx_path = index_dir.join(format!("{ulid_str}.idx"));
    let body_path = cache_dir.join(format!("{ulid_str}.body"));
    let present_path = cache_dir.join(format!("{ulid_str}.present"));
    let delta_path = cache_dir.join(format!("{ulid_str}.delta"));

    let mut touched_index = false;
    let mut touched_cache = false;
    for path in [&idx_path] {
        match std::fs::remove_file(path) {
            Ok(()) => touched_index = true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    for path in [&body_path, &present_path, &delta_path] {
        match std::fs::remove_file(path) {
            Ok(()) => touched_cache = true,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    if touched_index && index_dir.try_exists()? {
        segment::fsync_dir(&idx_path)?;
    }
    if touched_cache && cache_dir.try_exists()? {
        segment::fsync_dir(&body_path)?;
    }
    Ok(())
}

/// Per-segment scratch state for repack candidate selection +
/// bin-packing. Built during phase 1 and consumed in phases 2/3.
struct RepackCandidate {
    seg_path: PathBuf,
    seg_ulid: Ulid,
    classifications: Vec<crate::segment_classify::EntryClassification>,
    /// Approximate live `Data + Inline` body bytes after classification.
    live_bytes: u64,
    /// Bytes that won't be carried into the rewrite output.
    dead_bytes: u64,
    /// Number of entries that will be emitted into the rewrite output.
    live_entry_count: usize,
    /// Body-bearing entry hashes — used by apply to derive the
    /// to-remove set under per-input CAS.
    owned_hashes: Vec<blake3::Hash>,
    /// `(start_lba, lba_length)` of every claim-making entry, the
    /// apply's resolvability-gate coverage for this input.
    claim_ranges: Vec<(u64, u32)>,
    /// `true` when every classification is `FullyLive` — a single-input
    /// bucket of one of these is a no-op rewrite and is skipped.
    all_live: bool,
}

/// Translate one input segment's per-entry classifications into the
/// `PlanOutput` records for a rewrite plan. Shared by the data bin-pack
/// buckets and the journal-consolidation merge — both keep every live
/// entry (whole, run-sliced, or canonicalised) and drop the dead ones.
/// A repack candidate as the scan measured it, before any entry of it is
/// classified.
struct ScannedSegment {
    seg_path: PathBuf,
    seg_ulid: Ulid,
    stored_bytes: u64,
    journal: bool,
    all_live: bool,
}

/// Where one [`execute_repack`] pass spent, phase by phase.
///
/// `scan`, `reread` and `prep` each read the inputs, and are counted
/// apart: the parse and signature verify before admission, the reread an
/// admitted candidate is classified from, and the per-bucket
/// `MaterialiseCtx`.
#[derive(Default)]
struct PassCost {
    scan: Duration,
    reread: Duration,
    classify: Duration,
    prep: Duration,
    materialise: Duration,
    write: Duration,
    body: crate::rewrite_apply::MaterialiseCost,
}

/// What [`admit_within_budget`] decided, with the counts the pass logs.
struct Admission {
    admitted: Vec<ScannedSegment>,
    spent: u64,
    turned_away: usize,
    turned_away_bytes: u64,
}

/// Split the scanned segments into what the pass takes on and what it
/// leaves for the drain to upload as-is.
///
/// Data is admitted smallest-first while the budget lasts. Each segment
/// admitted folds away the same single object whatever its size, so the
/// smallest buy the most per byte of work; and one too large to share a
/// bucket is skipped at materialise anyway, so passing over it gives up
/// nothing that would have been packed.
///
/// Journal is admitted before the budget is consulted. A pass that
/// repacks data must carry all pending journal above its outputs, so a
/// journal segment left behind is an ordering violation rather than a
/// saving.
fn admit_within_budget(scanned: Vec<ScannedSegment>, budget: u64) -> Admission {
    let (journal, mut data): (Vec<ScannedSegment>, Vec<ScannedSegment>) =
        scanned.into_iter().partition(|s| s.journal);
    data.sort_by_key(|s| s.stored_bytes);

    let mut out = Admission {
        admitted: journal,
        spent: 0,
        turned_away: 0,
        turned_away_bytes: 0,
    };
    for s in data {
        if out.spent + s.stored_bytes <= budget {
            out.spent += s.stored_bytes;
            out.admitted.push(s);
        } else {
            out.turned_away += 1;
            out.turned_away_bytes += s.stored_bytes;
        }
    }
    out
}

fn emit_plan_outputs(
    seg_ulid: Ulid,
    classifications: &[crate::segment_classify::EntryClassification],
    outputs: &mut Vec<crate::rewrite_plan::PlanOutput>,
) {
    use crate::rewrite_plan::PlanOutput;
    use crate::segment_classify::EntryClassification;

    for (entry_idx, action) in classifications.iter().enumerate() {
        let entry_idx = entry_idx as u32;
        match action {
            EntryClassification::FullyLive => outputs.push(PlanOutput::Keep {
                input: seg_ulid,
                entry_idx,
            }),
            EntryClassification::DemoteToCanonical => outputs.push(PlanOutput::Canonical {
                input: seg_ulid,
                entry_idx,
            }),
            EntryClassification::ZeroSubRuns(runs) => {
                for run in runs {
                    outputs.push(PlanOutput::ZeroSplit {
                        input: seg_ulid,
                        entry_idx,
                        start_lba: run.range_start,
                        lba_length: (run.range_end - run.range_start) as u32,
                    });
                }
            }
            EntryClassification::PartialDeath {
                live_runs,
                emit_canonical,
            } => {
                if *emit_canonical {
                    outputs.push(PlanOutput::Canonical {
                        input: seg_ulid,
                        entry_idx,
                    });
                }
                for run in live_runs.iter() {
                    outputs.push(PlanOutput::Run {
                        input: seg_ulid,
                        entry_idx,
                        payload_block_offset: run.payload_block_offset,
                        start_lba: run.range_start,
                        lba_length: (run.range_end - run.range_start) as u32,
                    });
                }
            }
            EntryClassification::DeferUnresolvableDelta => outputs.push(PlanOutput::Keep {
                input: seg_ulid,
                entry_idx,
            }),
            EntryClassification::DropAndRemoveHash | EntryClassification::Drop => {}
        }
    }
}

/// Execute a repack job: classify every non-floor segment in
/// `pending/`, then bin-pack candidates into output buckets sized to
/// [`REPACK_TARGET_LIVE`] and [`REPACK_ENTRY_CAP`]. Each bucket
/// materialises into one rewrite output under a freshly-minted ULID;
/// candidates that don't fit with any peer become solo buckets. The
/// fresh ULIDs close the path-aliasing race against concurrent readers,
/// mirroring GC.
///
/// Every non-floor pending segment becomes a candidate. Single-input
/// buckets whose only input is fully live are skipped at materialise —
/// rewriting would be a byte-identical no-op.
///
/// Journal-tier segments never enter the data bin-pack: they are
/// collected separately and merged into one journal-tagged output at the
/// reserved (highest) ULID, so the merge stays within the disjoint
/// journal tier and sorts above every data output. See
/// `docs/design/journal-pending-consolidation.md`.
pub(crate) fn execute_repack(job: RepackJob) -> io::Result<RepackResult> {
    use crate::rewrite_apply::{self, MaterialiseCtx, MaterialiseOutcome, Materialised};
    use crate::rewrite_plan::{PlanOutput, RewritePlan};
    use crate::segment_classify::{self, ClassifyCtx, EntryClassification};

    let RepackJob {
        base_dir,
        pending_dir,
        floor,
        seg_paths,
        work_budget,
        output_ulids,
        journal_output_ulids,
        layers,
        ancestor_layers,
        fetcher,
        signer,
        verifying_key,
        segment_cache,
    } = job;
    let maps = layers.materialised();
    let lbamap_snapshot = maps.lbamap;
    let extent_index_snapshot = maps.extent_index;

    // Claims plus every named delta source — a base body must stay
    // resolvable while any registered encoding names it, so the
    // classifier counts all of them live.
    let mut live_hashes = lbamap_snapshot.claim_referenced_hashes();
    live_hashes.extend(extent_index_snapshot.named_delta_sources());
    let index_dir = base_dir.join("index");
    let cache_dir = base_dir.join("cache");

    let mut stats = CompactionStats::default();
    let mut cost = PassCost::default();
    // The generation this pass ran over, as its lines name it.
    let generation = pending_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("pending")
        .to_string();

    // Phase 1a — scan: parse + verify every non-floor segment and measure
    // it. Parsing is what identifies the journal tier, so every candidate
    // is read here; classification, the per-entry lbamap probe, waits for
    // the admission below.
    //
    // `seg_paths` is the prep-time listing, so the candidate set and
    // `lbamap_snapshot` describe the same instant. A segment written
    // while this runs belongs to the next pass, which is what keeps the
    // classifier from calling entries the snapshot predates dead and the
    // apply from deleting their files (`docs/finding-cargo-build-stale-read.md`).
    // The `floor` gate excludes segments frozen by the latest snapshot.
    let scan_start = Instant::now();
    let mut scanned: Vec<ScannedSegment> = Vec::new();
    for seg_path in &seg_paths {
        let seg_filename = seg_path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("bad segment filename"))?;
        let seg_ulid =
            Ulid::from_string(seg_filename).map_err(|e| io::Error::other(e.to_string()))?;
        if floor.is_some_and(|f| seg_ulid <= f) {
            continue;
        }

        let parsed = match segment_cache.read_and_verify(seg_path, &verifying_key) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let entries = &parsed.entries;

        let total_bytes: u64 = entries
            .iter()
            .filter(|e| e.kind.has_body_bytes())
            .map(|e| e.stored_length as u64)
            .sum();
        let live_bytes_est: u64 = entries
            .iter()
            .filter(|e| e.kind.has_body_bytes() && live_hashes.contains(&e.hash))
            .map(|e| e.stored_length as u64)
            .sum();
        let all_live = live_bytes_est == total_bytes;

        // Journal-tier segments are collected apart from the data bin-pack
        // and merged into one journal-tagged output below. Pending segments
        // are pure (formation partitions journal content into its own
        // segment), so any journal-flagged entry means the whole segment is
        // journal-tier. Every journal segment (live or fully dead) is routed
        // there so the merge covers all pending journal — the ordering
        // invariant a data repack relies on (a data repack must lift all
        // pending journal above its outputs; see the design doc). That
        // coverage is why the gates below leave journal alone.
        let is_journal_segment = entries.iter().any(|e| e.journal);

        scanned.push(ScannedSegment {
            seg_path: seg_path.clone(),
            seg_ulid,
            stored_bytes: total_bytes,
            journal: is_journal_segment,
            all_live,
        });
    }
    cost.scan = scan_start.elapsed();
    let scanned_count = scanned.len();
    let scanned_bytes: u64 = scanned.iter().map(|s| s.stored_bytes).sum();

    // Admission — a budget on the work the pass takes on, spent
    // smallest-first across the data segments. Each one admitted folds
    // away the same single object whatever its size, so the smallest buy
    // the most per byte of work, and what the budget turns away uploads
    // as its own object. A segment too large to share a bucket is skipped
    // at materialise anyway, so spending the budget on smaller peers
    // gives up nothing that would have been packed.
    //
    // Journal is admitted before the budget is consulted. A pass that
    // repacks data must carry all pending journal above its outputs, so a
    // journal segment left behind is an ordering violation rather than a
    // saving.
    let Admission {
        admitted,
        spent,
        turned_away,
        turned_away_bytes,
    } = admit_within_budget(scanned, work_budget);
    let admitted_count = admitted.len();
    if turned_away > 0 {
        log::info!(
            "repack: {spent} bytes of data segments admitted against a {work_budget} byte \
             budget, {turned_away} segment(s) upload as-is ({turned_away_bytes} bytes)"
        );
    }

    // Phase 1b — classify every entry of each admitted segment, for the
    // live/dead/entry counts the pack and the rewrite plans are built on.
    let mut candidates: Vec<RepackCandidate> = Vec::new();
    let mut journal_candidates: Vec<RepackCandidate> = Vec::new();
    for scan in admitted {
        let reread_start = Instant::now();
        let parsed = match segment_cache.read_and_verify(&scan.seg_path, &verifying_key) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        cost.reread += reread_start.elapsed();
        let entries = &parsed.entries;

        let classify_start = Instant::now();
        let classify_ctx = ClassifyCtx {
            lba_map: &lbamap_snapshot,
            extent_index: &extent_index_snapshot,
            live_hashes: &live_hashes,
            segment_id: scan.seg_ulid,
        };
        let classifications: Vec<EntryClassification> = entries
            .iter()
            .map(|e| segment_classify::classify_entry(e, &classify_ctx))
            .collect();

        let mut live_bytes: u64 = 0;
        let mut dead_bytes: u64 = 0;
        let mut live_entry_count: usize = 0;
        for (entry, action) in entries.iter().zip(classifications.iter()) {
            let is_data_like = matches!(
                entry.kind,
                segment::EntryKind::Data | segment::EntryKind::Inline
            );
            match action {
                EntryClassification::FullyLive | EntryClassification::DeferUnresolvableDelta => {
                    if is_data_like {
                        live_bytes += entry.stored_length as u64;
                    }
                    live_entry_count += 1;
                }
                EntryClassification::DemoteToCanonical => {
                    if is_data_like {
                        live_bytes += entry.stored_length as u64;
                    }
                    live_entry_count += 1;
                }
                EntryClassification::PartialDeath {
                    live_runs,
                    emit_canonical,
                } => {
                    let live_blocks: u64 =
                        live_runs.iter().map(|r| r.range_end - r.range_start).sum();
                    let total = entry.lba_length as u64;
                    if is_data_like && total > 0 {
                        let kept = entry.stored_length as u64 * live_blocks / total;
                        live_bytes += kept;
                        dead_bytes += entry.stored_length as u64 - kept;
                    }
                    live_entry_count += live_runs.len() + if *emit_canonical { 1 } else { 0 };
                }
                EntryClassification::ZeroSubRuns(runs) => {
                    live_entry_count += runs.len();
                }
                EntryClassification::DropAndRemoveHash | EntryClassification::Drop => {
                    dead_bytes += entry.stored_length as u64;
                }
            }
        }

        let owned_hashes: Vec<blake3::Hash> = entries
            .iter()
            .filter(|e| e.kind.owns_extent_hash())
            .map(|e| e.hash)
            .collect();
        let claim_ranges: Vec<(u64, u32)> = entries
            .iter()
            .filter(|e| !e.kind.is_canonical_only())
            .map(|e| (e.start_lba, e.lba_length))
            .collect();
        cost.classify += classify_start.elapsed();

        let candidate = RepackCandidate {
            seg_path: scan.seg_path,
            seg_ulid: scan.seg_ulid,
            classifications,
            live_bytes,
            dead_bytes,
            live_entry_count,
            owned_hashes,
            claim_ranges,
            all_live: scan.all_live,
        };
        if scan.journal {
            journal_candidates.push(candidate);
        } else {
            candidates.push(candidate);
        }
    }

    let mut result_buckets: Vec<crate::volume::RepackedBucket> = Vec::new();

    // Phase 2 — bin-pack: first-fit-decreasing into buckets sized to
    // (REPACK_TARGET_LIVE, REPACK_ENTRY_CAP). Sorting by live_bytes
    // descending places the largest candidates in their own buckets
    // first; smaller candidates fill remaining headroom or start fresh
    // buckets.
    //
    // The pack is pure, and it runs before the journal consolidation
    // writes anything because whether this pass emits a data output is
    // what decides whether the journal has to move (see below). Phase 3
    // materialises these buckets after the journal segment is on disk.
    candidates.sort_by_key(|c| std::cmp::Reverse(c.live_bytes));

    struct Bucket {
        candidate_idxs: Vec<usize>,
        used_bytes: u64,
        used_entries: usize,
    }
    let mut buckets: Vec<Bucket> = Vec::new();
    for (i, c) in candidates.iter().enumerate() {
        let mut placed = false;
        for b in buckets.iter_mut() {
            if c.live_bytes + b.used_bytes <= REPACK_TARGET_LIVE
                && c.live_entry_count + b.used_entries <= REPACK_ENTRY_CAP
            {
                b.candidate_idxs.push(i);
                b.used_bytes += c.live_bytes;
                b.used_entries += c.live_entry_count;
                placed = true;
                break;
            }
        }
        if !placed {
            buckets.push(Bucket {
                candidate_idxs: vec![i],
                used_bytes: c.live_bytes,
                used_entries: c.live_entry_count,
            });
        }
    }
    // A bucket of one fully-live candidate is a byte-identical no-op that
    // phase 3 skips, so it emits nothing.
    let emits_data_output = buckets
        .iter()
        .any(|b| b.candidate_idxs.len() > 1 || !candidates[b.candidate_idxs[0]].all_live);

    // Journal consolidation — merge every pending journal segment's live
    // entries into one journal-tagged output at the reserved (highest)
    // ULID. Runs before the data bin-pack materialises so its segment is
    // written first and, minted above every data output, sorts above
    // them: data-before-journal on disk and on upload. The whole live set
    // is at most one jbd2 ring, so it merges into one uncapped output;
    // there is deliberately no size or entry cap here.
    //
    // A lone all-live journal segment merges into nothing and frees no
    // bytes, so the 1→1 rewrite exists only to carry it above this pass's
    // data outputs. Where the pass emits one it is mandatory: data
    // outputs mint above everything pending, so a journal segment left at
    // its own ULID lands below the data it commits — the inverted state
    // uploads make unsafe, since a journal segment reaching S3 would no
    // longer imply its data did (`journal-pending-consolidation.md`).
    // Where the pass emits no data output there is nothing to stay above.
    let journal_carries_itself = journal_candidates.len() == 1 && journal_candidates[0].all_live;
    let journal_lifted =
        !journal_candidates.is_empty() && (!journal_carries_itself || emits_data_output);
    // What the pass leaves where it is, which the apply folds into
    // `Volume::pending_journal` so the next sweep exempts it by name
    // rather than by parsing its index.
    let journal_untouched: Vec<Ulid> = if journal_lifted {
        Vec::new()
    } else {
        journal_candidates.iter().map(|c| c.seg_ulid).collect()
    };
    if journal_lifted {
        journal_candidates.sort_by_key(|c| c.seg_ulid);

        let mut outputs: Vec<PlanOutput> = Vec::new();
        let mut journal_inputs: Vec<crate::volume::RepackedInput> =
            Vec::with_capacity(journal_candidates.len());
        let mut journal_bytes_freed: u64 = 0;
        for c in &mut journal_candidates {
            emit_plan_outputs(c.seg_ulid, &c.classifications, &mut outputs);
            journal_inputs.push(crate::volume::RepackedInput {
                input_ulid: c.seg_ulid,
                input_path: std::mem::take(&mut c.seg_path),
                owned_hashes: std::mem::take(&mut c.owned_hashes),
                claim_ranges: std::mem::take(&mut c.claim_ranges),
            });
            journal_bytes_freed += c.dead_bytes;
            stats.segments_compacted += 1;
        }

        for input in &journal_inputs {
            invalidate_promote_siblings(&index_dir, &cache_dir, input.input_ulid)?;
        }

        let output = if outputs.is_empty() {
            // Every journal input classified fully dead: no output segment,
            // the inputs reap as an all-Drop bucket (apply purges their
            // journal-map entries and queues the files for unlink).
            None
        } else {
            let new_ulid = *journal_output_ulids
                .first()
                .ok_or_else(|| io::Error::other("repack: no reserved journal output ulid"))?;
            let final_path = pending_dir.join(new_ulid.to_string());

            let (new_body_section_start, out_entries) = {
                let plan = RewritePlan { new_ulid, outputs };
                let resolver = WorkerBodyResolver {
                    base_dir: &base_dir,
                    ancestor_layers: &ancestor_layers,
                    fetcher: fetcher.as_ref(),
                    extent_index: &extent_index_snapshot,
                };
                let plan_inputs = plan.inputs();
                let prep_start = Instant::now();
                let ctx = match MaterialiseCtx::new_for_pending(
                    &base_dir,
                    &pending_dir,
                    &plan_inputs,
                    &extent_index_snapshot,
                    &resolver,
                ) {
                    Ok(c) => c.allowing_journal(),
                    Err(MaterialiseOutcome::Io(e)) => return Err(e),
                    Err(MaterialiseOutcome::Cancel(e)) => {
                        return Err(io::Error::other(format!(
                            "journal consolidation {new_ulid}: materialise prep cancelled: {e}"
                        )));
                    }
                };
                cost.prep += prep_start.elapsed();
                let materialise_start = Instant::now();
                let materialised = match rewrite_apply::materialise_plan(&plan, &ctx) {
                    Ok(m) => m,
                    Err(MaterialiseOutcome::Io(e)) => return Err(e),
                    Err(MaterialiseOutcome::Cancel(e)) => {
                        return Err(io::Error::other(format!(
                            "journal consolidation {new_ulid}: materialise cancelled: {e}"
                        )));
                    }
                };
                cost.materialise += materialise_start.elapsed();
                cost.body += ctx.cost();
                drop(ctx);

                let Materialised {
                    mut entries,
                    delta_body,
                } = materialised;
                // Re-tag every merged entry journal so the output registers
                // into the disjoint `(segment, hash)` journal map, never
                // `inner`, and reaps whole. The journal tier carries no deltas.
                for pe in &mut entries {
                    pe.entry.journal = true;
                }
                debug_assert!(
                    delta_body.is_empty(),
                    "journal consolidation output must carry no delta body"
                );

                let input_ulids: Vec<Ulid> = journal_inputs.iter().map(|i| i.input_ulid).collect();
                let tmp_path = pending_dir.join(format!("{new_ulid}.tmp"));
                let _ = std::fs::remove_file(&tmp_path);
                let write_start = Instant::now();
                let written = segment::write_segment_full(
                    &tmp_path,
                    entries,
                    &delta_body,
                    &input_ulids,
                    crate::sketch_enabled(),
                    signer.as_ref(),
                )?;
                std::fs::rename(&tmp_path, &final_path)?;
                segment::fsync_dir(&final_path)?;
                cost.write += write_start.elapsed();
                written
            };
            stats.new_segments += 1;
            stats.bytes_freed += journal_bytes_freed;

            Some(crate::volume::RepackedOutput {
                new_ulid,
                new_body_section_start,
                out_entries,
            })
        };

        result_buckets.push(crate::volume::RepackedBucket {
            inputs: journal_inputs,
            output,
            bytes_freed: journal_bytes_freed,
            journal: true,
        });
    }

    // Phase 3 — materialise each bucket. A bucket of one fully-live
    // candidate is a byte-identical no-op; skip it. Data buckets append
    // after the journal bucket already pushed above.
    let mut next_output_idx: usize = 0;
    for bucket in buckets {
        let solo_no_op =
            bucket.candidate_idxs.len() == 1 && candidates[bucket.candidate_idxs[0]].all_live;
        if solo_no_op {
            continue;
        }

        // Sort the bucket's candidates by ULID ascending so PlanOutput
        // records emit input entries in write order.
        let mut bucket_idxs = bucket.candidate_idxs;
        bucket_idxs.sort_by_key(|&i| candidates[i].seg_ulid);

        let mut outputs: Vec<PlanOutput> = Vec::new();
        let mut bucket_inputs: Vec<crate::volume::RepackedInput> =
            Vec::with_capacity(bucket_idxs.len());
        let mut bucket_bytes_freed: u64 = 0;
        for &i in &bucket_idxs {
            let c = &candidates[i];
            emit_plan_outputs(c.seg_ulid, &c.classifications, &mut outputs);
            let c = &mut candidates[i];
            bucket_inputs.push(crate::volume::RepackedInput {
                input_ulid: c.seg_ulid,
                input_path: std::mem::take(&mut c.seg_path),
                owned_hashes: std::mem::take(&mut c.owned_hashes),
                claim_ranges: std::mem::take(&mut c.claim_ranges),
            });
            bucket_bytes_freed += c.dead_bytes;
            stats.segments_compacted += 1;
        }

        // Invalidate sibling promote files for each input before
        // writing — half-crashed promotes can leave stale .idx/.body
        // peers that would otherwise shadow the rewrite.
        for input in &bucket_inputs {
            invalidate_promote_siblings(&index_dir, &cache_dir, input.input_ulid)?;
        }

        if outputs.is_empty() {
            // Every entry in every input classified Drop — no rewrite
            // output. The inputs are handed to the apply phase
            // (`output: None`), which gates the hash removals on
            // current-lbamap resolvability and queues the files for
            // the post-publish unlink.
            result_buckets.push(crate::volume::RepackedBucket {
                inputs: bucket_inputs,
                output: None,
                bytes_freed: bucket_bytes_freed,
                journal: false,
            });
            continue;
        }

        let new_ulid = *output_ulids
            .get(next_output_idx)
            .ok_or_else(|| io::Error::other("repack: ran out of pre-minted output ULIDs"))?;
        next_output_idx += 1;

        let plan = RewritePlan { new_ulid, outputs };
        let resolver = WorkerBodyResolver {
            base_dir: &base_dir,
            ancestor_layers: &ancestor_layers,
            fetcher: fetcher.as_ref(),
            extent_index: &extent_index_snapshot,
        };
        let plan_inputs = plan.inputs();
        let prep_start = Instant::now();
        let ctx = match MaterialiseCtx::new_for_pending(
            &base_dir,
            &pending_dir,
            &plan_inputs,
            &extent_index_snapshot,
            &resolver,
        ) {
            Ok(c) => c,
            Err(MaterialiseOutcome::Io(e)) => return Err(e),
            Err(MaterialiseOutcome::Cancel(e)) => {
                return Err(io::Error::other(format!(
                    "repack {new_ulid}: materialise prep cancelled: {e}"
                )));
            }
        };
        cost.prep += prep_start.elapsed();
        let materialise_start = Instant::now();
        let materialised = match rewrite_apply::materialise_plan(&plan, &ctx) {
            Ok(m) => m,
            Err(MaterialiseOutcome::Io(e)) => return Err(e),
            Err(MaterialiseOutcome::Cancel(e)) => {
                return Err(io::Error::other(format!(
                    "repack {new_ulid}: materialise cancelled: {e}"
                )));
            }
        };
        cost.materialise += materialise_start.elapsed();
        cost.body += ctx.cost();
        drop(ctx);

        let Materialised {
            entries: out_entries,
            delta_body,
        } = materialised;

        let input_ulids: Vec<Ulid> = bucket_inputs.iter().map(|i| i.input_ulid).collect();
        let new_ulid_str = new_ulid.to_string();
        let final_path = pending_dir.join(&new_ulid_str);
        let tmp_path = pending_dir.join(format!("{new_ulid_str}.tmp"));
        let _ = std::fs::remove_file(&tmp_path);
        let write_start = Instant::now();
        let (new_body_section_start, out_entries) = segment::write_segment_full(
            &tmp_path,
            out_entries,
            &delta_body,
            &input_ulids,
            crate::sketch_enabled(),
            signer.as_ref(),
        )?;
        std::fs::rename(&tmp_path, &final_path)?;
        segment::fsync_dir(&final_path)?;
        cost.write += write_start.elapsed();
        stats.new_segments += 1;
        stats.bytes_freed += bucket_bytes_freed;

        result_buckets.push(crate::volume::RepackedBucket {
            inputs: bucket_inputs,
            output: Some(crate::volume::RepackedOutput {
                new_ulid,
                new_body_section_start,
                out_entries,
            }),
            bytes_freed: bucket_bytes_freed,
            journal: false,
        });
    }

    let ms = |d: Duration| d.as_secs_f64() * 1e3;
    log::info!(
        "repack {generation}: scanned {scanned_count} segment(s) / {scanned_bytes} stored bytes \
         in {:.1}ms, admitted {admitted_count}, reread={:.1}ms classify={:.1}ms",
        ms(cost.scan),
        ms(cost.reread),
        ms(cost.classify),
    );
    log::info!(
        "repack {generation}: {} output(s) prep={:.1}ms materialise={:.1}ms write={:.1}ms; \
         bodies read={:.1}ms/{}B verify={:.1}ms/{}B decode={:.1}ms/{}B recompress={:.1}ms/{}B",
        stats.new_segments,
        ms(cost.prep),
        ms(cost.materialise),
        ms(cost.write),
        ms(cost.body.read),
        cost.body.read_bytes,
        ms(cost.body.verify),
        cost.body.verify_bytes,
        ms(cost.body.decode),
        cost.body.decode_bytes,
        ms(cost.body.recompress),
        cost.body.recompress_bytes,
    );

    Ok(RepackResult {
        stats,
        buckets: result_buckets,
        pending_dir,
        journal_untouched,
    })
}

/// Execute a snapshot-manifest sign job: enumerate `index/`, drop
/// fully-dead segments, Ed25519 sign the manifest, atomic-write it,
/// write the marker last.
///
/// `snapshots/` is created on demand. A `NotFound` on `index/` is
/// treated as an empty list — matches the inline behaviour.
pub(crate) fn execute_sign_snapshot_manifest(
    job: SignSnapshotManifestJob,
) -> io::Result<SignSnapshotManifestResult> {
    let SignSnapshotManifestJob {
        snap_ulid,
        base_dir,
        signer,
        extent_index,
        lbamap,
        verifying_key,
        segment_cache,
        kind,
    } = job;

    let index_dir = base_dir.join("index");
    let seg_ulids = live_index_segments(
        &index_dir,
        &extent_index,
        &lbamap,
        &verifying_key,
        &segment_cache,
    )?;

    let snapshots_dir = base_dir.join("snapshots");
    std::fs::create_dir_all(&snapshots_dir)?;

    // The manifest's existence under `snapshots/` is the snapshot's
    // existence; both writers go through `write_file_atomic` internally.
    match kind {
        crate::signing::SnapshotKind::User => crate::signing::write_snapshot_manifest(
            &base_dir,
            signer.as_ref(),
            &snap_ulid,
            &seg_ulids,
        )?,
        crate::signing::SnapshotKind::Stop => crate::signing::write_stop_snapshot_manifest(
            &base_dir,
            signer.as_ref(),
            &snap_ulid,
            &seg_ulids,
        )?,
    };

    Ok(SignSnapshotManifestResult { snap_ulid })
}

/// Enumerate `index/<u>.idx`, drop fully-dead segments, and return the
/// surviving ULIDs. Used by both [`execute_sign_snapshot_manifest`] and
/// the in-process [`crate::volume::Volume::snapshot`] path.
///
/// A segment is fully dead when no entry in its `.idx` passes the
/// liveness predicate ([`is_index_entry_live`]). Files are not
/// removed; reclamation is GC's job. Unparseable filenames are
/// skipped silently to match the prior enumeration behaviour.
///
/// Two passes over the cached `.idx` set:
/// 1. Build `live_hashes` — `lbamap.claim_referenced_hashes()` unioned
///    with `ExtentIndex::named_delta_sources`. A body whose hash is
///    not in this set has nothing reading it, even if the extent
///    index still points at it.
/// 2. Apply the predicate with `live_hashes` as the body-reachability
///    side condition.
///
/// Returns `Ok(Vec::new())` if `index_dir` does not exist.
pub(crate) fn live_index_segments(
    index_dir: &std::path::Path,
    extent_index: &ExtentIndex,
    lbamap: &LbaMap,
    verifying_key: &ed25519_dalek::VerifyingKey,
    segment_cache: &crate::segment_cache::SegmentIndexCache,
) -> io::Result<Vec<Ulid>> {
    let read_dir = match std::fs::read_dir(index_dir) {
        Ok(d) => d,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    // Collect (ulid, parsed) once. The `Arc` clone keeps memory cost flat
    // (we hold the cache's slot, not a copy).
    let mut parsed_segments: Vec<(Ulid, Arc<crate::segment_cache::ParsedIndex>)> = Vec::new();
    for entry in read_dir.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else { continue };
        let Some(stem) = s.strip_suffix(".idx") else {
            continue;
        };
        let Ok(seg_ulid) = Ulid::from_string(stem) else {
            continue;
        };
        let parsed = segment_cache.read_and_verify(&entry.path(), verifying_key)?;
        parsed_segments.push((seg_ulid, parsed));
    }

    // Pass 1: live_hashes = claim-referenced hashes ∪ every named delta
    // source. A source body must stay resolvable while any registered
    // encoding names it, so all of them count as live even when no LBA
    // references the source directly.
    let mut live_hashes = lbamap.claim_referenced_hashes();
    live_hashes.extend(extent_index.named_delta_sources());

    // Pass 2: apply predicate.
    let mut live: Vec<Ulid> = Vec::with_capacity(parsed_segments.len());
    for (seg_ulid, parsed) in &parsed_segments {
        let any_live = parsed
            .entries
            .iter()
            .any(|e| is_index_entry_live(*seg_ulid, e, extent_index, lbamap, &live_hashes));
        if any_live {
            live.push(*seg_ulid);
        }
    }
    Ok(live)
}

/// Liveness predicate for one entry in an `index/<seg_ulid>.idx`.
///
/// - Body-bearing kinds (`Data`, `Inline`, `CanonicalData`,
///   `CanonicalInline`): live iff the extent index points the entry's
///   hash at this `(seg_ulid, stored_offset)` **and** the hash is in
///   `live_hashes`. The first conjunct rules out duplicate copies the
///   lowest-ULID rule has displaced; the second rules out orphan
///   bodies whose hash is no longer referenced anywhere.
/// - `DedupRef` and `Delta`: live iff some LBA in
///   `[start_lba, start_lba + lba_length)` still maps to `entry.hash`
///   in the lbamap. (When live, a `Delta`'s source hash is already in
///   `live_hashes` via the pass-1 augmentation.)
/// - `Zero`: live iff some LBA in range still maps to `ZERO_HASH`.
fn is_index_entry_live(
    seg_ulid: Ulid,
    entry: &segment::SegmentEntry,
    extent_index: &ExtentIndex,
    lbamap: &LbaMap,
    live_hashes: &crate::blake3_id_hasher::Blake3HashSet,
) -> bool {
    use segment::EntryKind;
    match entry.kind {
        EntryKind::Zero => {
            let end = entry.start_lba + entry.lba_length as u64;
            lbamap
                .extents_in_range(entry.start_lba, end)
                .any(|r| r.hash == crate::volume::ZERO_HASH)
        }
        EntryKind::DedupRef | EntryKind::Delta => {
            let end = entry.start_lba + entry.lba_length as u64;
            lbamap
                .extents_in_range(entry.start_lba, end)
                .any(|r| r.hash == entry.hash)
        }
        EntryKind::CanonicalDelta => {
            live_hashes.contains(&entry.hash)
                && extent_index
                    .lookup_delta(&entry.hash)
                    .is_some_and(|loc| loc.segment_id == seg_ulid)
        }
        EntryKind::Data
        | EntryKind::Inline
        | EntryKind::CanonicalData
        | EntryKind::CanonicalInline => {
            // Journal-tier bodies own a `(segment, hash)` slot in the
            // disjoint journal map, never `inner`; a journal segment with a
            // live journal LBA must stay in the manifest so a rebuild from
            // the snapshot reproduces its journal map. Durable bodies own
            // `inner`.
            if entry.journal {
                live_hashes.contains(&entry.hash)
                    && extent_index
                        .lookup_journal(seg_ulid, &entry.hash)
                        .is_some_and(|loc| loc.body_offset == entry.stored_offset)
            } else {
                live_hashes.contains(&entry.hash)
                    && extent_index.lookup(&entry.hash).is_some_and(|loc| {
                        loc.segment_id == seg_ulid && loc.body_offset == entry.stored_offset
                    })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

/// Create a `VolumeActor` / `VolumeClient` pair from an opened `Volume`.
///
/// The caller must spawn a thread and call `actor.run()` on it. The
/// `VolumeClient` can be cloned freely (it is `Send + Sync + Clone`); per-
/// thread reads are served via `client.reader()`.
///
/// Also spawns a worker thread for off-actor I/O (WAL promotion, etc.).
/// The worker exits when the actor shuts down and drops its job sender.
pub fn spawn(volume: Volume) -> (VolumeActor, VolumeClient) {
    let initial = Arc::new(ReadSnapshot {
        maps: volume.map_layers().clone(),
        flush_gen: 0,
        layout_gen: 0,
    });
    let snapshot = Arc::new(ArcSwap::new(initial));

    let base_dir = volume.base_dir().to_owned();
    let cache_dir = base_dir.join("cache");
    let config = Arc::new(VolumeConfig {
        base_dir,
        cache_dir,
        ancestor_layers: volume.ancestor_layers().to_vec(),
        fetcher: volume.fetcher().cloned(),
    });

    let volume = Arc::new(Mutex::new(volume));
    let flush_gen = Arc::new(AtomicU64::new(0));
    let layout_gen = Arc::new(AtomicU64::new(0));
    let lock_stats = Arc::new(LockStats::default());
    let gate = Arc::new(SyncGate::default());

    // Channel depth of 64: enough to absorb bursts without blocking callers
    // while still providing backpressure if the actor falls behind.
    let (tx, rx) = bounded(64);

    // Worker channels: job channel bounded at 4, result channel matched.
    let (worker_job_tx, worker_job_rx) = bounded::<QueuedJob>(4);
    let (worker_result_tx, worker_result_rx) = bounded::<WorkerResult>(4);
    let worker_stats = Arc::clone(&lock_stats);
    let worker_handle = std::thread::Builder::new()
        .name("volume-worker".into())
        .spawn(move || worker_thread(worker_job_rx, worker_result_tx, worker_stats))
        .expect("failed to spawn worker thread");

    let actor = VolumeActor {
        volume: Arc::clone(&volume),
        base_dir: config.base_dir.clone(),
        ancestor_layers: config.ancestor_layers.clone(),
        snapshot: Arc::clone(&snapshot),
        rx,
        flush_gen: Arc::clone(&flush_gen),
        layout_gen: Arc::clone(&layout_gen),
        worker_tx: Some(worker_job_tx),
        worker_rx: worker_result_rx,
        worker_handle: Some(worker_handle),
        divergence_exit: None,
        pipeline: PromotePipeline::default(),
        parked: ParkedOps::default(),
        lock_stats: Arc::clone(&lock_stats),
        lock_stats_reported: LockStatsSnapshot::default(),
        lock_stats_marked: Instant::now(),
        gate: Arc::clone(&gate),
        gate_reported: GateSnapshot::default(),
        gate_marked: Instant::now(),
        stash_marked: Instant::now(),
    };

    let client = VolumeClient {
        tx,
        snapshot,
        config,
        dmat_cache: lock_volume(&volume).dmat_cache_handle(),
        file_cache: SharedFileCache::default(),
        volume: Arc::downgrade(&volume),
        flush_gen,
        layout_gen,
        lock_stats,
        gate,
    };

    (actor, client)
}

// ---------------------------------------------------------------------------
// Reclaim worker execution
// ---------------------------------------------------------------------------

/// What the reclaim worker has to work with for a single hash sitting
/// inside the target range.
enum ReclaimBody {
    /// Rematerialised bytes for a Data or Inline hash. Slice the live
    /// sub-range, rehash, compress, emit `Data`/`Inline`/`DedupRef`.
    Data(Vec<u8>),
    /// A Delta hash the worker was able to decompress locally. The
    /// live sub-range is re-compressed against `source_plain` (zstd
    /// dictionary) to produce a smaller delta blob and emitted as a
    /// fresh `Delta` entry carrying one option for `source_hash`.
    Delta {
        source_hash: blake3::Hash,
        source_plain: Vec<u8>,
        fragment: Vec<u8>,
    },
    /// No locally-resolvable body or source — skip this entry. For a
    /// Delta hash this happens when no option's source resolves in the
    /// local extent index, or the source body / delta blob is missing
    /// from all search dirs. Reclaim is best-effort; we never
    /// demand-fetch and never rehydrate a Delta as Data.
    Skip,
}

/// Read the full stored bytes (fully decompressed) for a Data or Inline
/// hash via the extent index snapshot.
fn read_full_extent_body(
    loc: &crate::extentindex::ExtentLocation,
    search_dirs: &[PathBuf],
) -> io::Result<Vec<u8>> {
    if let Some(ref idata) = loc.inline_data {
        return Ok(loc.codec.decode(Cow::Borrowed(idata))?.into_owned());
    }
    let home = loc.body_source.home();
    let mut found = None;
    for dir in search_dirs {
        if let Some(hit) = segment::locate_segment_body_from(dir, loc.segment_id, home) {
            found = Some(hit);
            break;
        }
    }
    let (path, layout) = found.ok_or_else(|| {
        io::Error::other(format!(
            "reclaim: segment {} not found in search dirs",
            loc.segment_id
        ))
    })?;
    let seek = layout.body_seek(loc);
    use std::os::unix::fs::FileExt;
    let f = std::fs::File::open(&path)?;
    let mut buf = vec![0u8; loc.body_length as usize];
    f.read_exact_at(&mut buf, seek)?;
    Ok(loc.codec.decode(Cow::Owned(buf))?.into_owned())
}

/// Read a delta blob from the segment identified by `loc`.
///
/// Returns `Ok(None)` if the delta body file cannot be located in any
/// of `search_dirs` — the worker has no fetcher attached and must not
/// reach out to S3 just to seed a dictionary rewrite.
fn read_delta_blob(
    loc: &crate::extentindex::DeltaLocation,
    option: &segment::DeltaOption,
    search_dirs: &[PathBuf],
) -> io::Result<Option<Vec<u8>>> {
    use std::os::unix::fs::FileExt;
    match loc.body_source {
        crate::extentindex::DeltaBodySource::Full {
            body_section_start,
            body_length,
        } => {
            let mut found = None;
            for dir in search_dirs {
                if let Some(hit) = segment::locate_segment_body(dir, loc.segment_id) {
                    found = Some(hit);
                    break;
                }
            }
            let Some((path, _layout)) = found else {
                return Ok(None);
            };
            let f = std::fs::File::open(&path)?;
            let seek = body_section_start + body_length + option.delta_offset;
            let mut buf = vec![0u8; option.delta_length as usize];
            f.read_exact_at(&mut buf, seek)?;
            Ok(Some(buf))
        }
        crate::extentindex::DeltaBodySource::Cached => {
            let sid = loc.segment_id.to_string();
            for dir in search_dirs {
                let delta_path = dir.join("cache").join(format!("{sid}.delta"));
                if delta_path.exists() {
                    let f = std::fs::File::open(&delta_path)?;
                    let mut buf = vec![0u8; option.delta_length as usize];
                    f.read_exact_at(&mut buf, option.delta_offset)?;
                    return Ok(Some(buf));
                }
            }
            Ok(None)
        }
    }
}

/// Resolve what reclaim can do with `hash` locally.
///
/// - Data/Inline hash in the extent index → `ReclaimBody::Data(bytes)`.
/// - Delta hash with at least one option whose `source_hash` resolves
///   as Data/Inline locally and whose delta blob file is findable →
///   `ReclaimBody::Delta { .. }`.
/// - Delta hash with no resolvable source/blob → `ReclaimBody::Skip`.
/// - Hash absent from the extent index entirely → `Err`.
fn read_reclaim_extent_body(
    extent_index: &ExtentIndex,
    search_dirs: &[PathBuf],
    hash: &blake3::Hash,
) -> io::Result<ReclaimBody> {
    if let Some(loc) = extent_index.lookup(hash) {
        return Ok(ReclaimBody::Data(read_full_extent_body(loc, search_dirs)?));
    }
    if let Some(delta_loc) = extent_index.lookup_delta(hash) {
        // Source selection: first option whose `source_hash` resolves
        // as Data/Inline and whose source body + delta blob are both
        // locally readable. Mirrors `try_read_delta_extent`'s "first
        // resolved option wins" rule — keeps the output delta shape
        // aligned with the shape a concurrent reader would pick.
        for option in &delta_loc.options {
            let Some(source_loc) = extent_index.lookup(&option.source_hash) else {
                continue;
            };
            let source_plain = read_full_extent_body(source_loc, search_dirs)?;
            let Some(delta_blob) = read_delta_blob(delta_loc, option, search_dirs)? else {
                // Delta blob file missing locally — try the next option.
                continue;
            };
            let fragment = crate::delta_compute::apply_delta(&source_plain, &delta_blob)?;
            // The zstd-dict decompress carries no content checksum: a
            // wrong source dictionary yields plausible-length garbage,
            // not an error — and reclaim would write it into a durable
            // segment. The entry's content hash is the integrity anchor.
            let got = blake3::hash(&fragment);
            if got != *hash {
                return Err(io::Error::other(format!(
                    "reclaim delta materialisation for segment {} hashed {} \
                     instead of {} (source {})",
                    delta_loc.segment_id,
                    got.to_hex(),
                    hash.to_hex(),
                    option.source_hash.to_hex(),
                )));
            }
            return Ok(ReclaimBody::Delta {
                source_hash: option.source_hash,
                source_plain,
                fragment,
            });
        }
        return Ok(ReclaimBody::Skip);
    }
    Err(io::Error::other(format!(
        "reclaim: hash {} not in extent index (data, inline, or delta)",
        hash.to_hex()
    )))
}

/// Execute an extent reclamation job on the worker thread.
///
/// Walks the range entries captured at prepare time, applies the
/// containment + bloat gates against the lbamap snapshot, reads each
/// bloated hash's full body via the extent index snapshot, slices out
/// the live sub-range, re-hashes, compresses, and assembles one
/// pending segment. The segment rename is the durability commit point.
///
/// Apply on the actor checks `Arc::ptr_eq` against the live lbamap; on
/// mismatch the segment is deleted as an orphan.
pub(crate) fn execute_reclaim(job: ReclaimJob) -> io::Result<ReclaimResult> {
    let target_start = job.target_start_lba;
    let target_end = target_start + job.target_lba_length as u64;
    let maps = job.layers.materialised();
    let lbamap_snapshot = maps.lbamap;
    let extent_index_snapshot = maps.extent_index;

    // Cache containment/bloat decisions per hash so repeated runs of
    // the same hash inside the target share one full-map walk.
    let mut decision: std::collections::HashMap<blake3::Hash, bool> =
        std::collections::HashMap::new();
    // Cache per-hash resolved bodies so multiple in-range runs of the
    // same hash share one file read + decompress. Skip entries are
    // cached via the `Skip` variant to avoid retrying the resolve.
    let mut body_cache: std::collections::HashMap<blake3::Hash, ReclaimBody> =
        std::collections::HashMap::new();

    let mut entries: Vec<segment::PendingEntry> = Vec::new();
    let mut uncompressed_bytes: Vec<u64> = Vec::new();
    // Delta blobs, concatenated in emission order. Offsets recorded on
    // each emitted Delta entry are into this buffer; it becomes the
    // segment's delta body section at write time.
    let mut delta_body: Vec<u8> = Vec::new();

    // Sources already pinned by a registered delta encoding: the "H
    // will stick around" signal the delta-emission decision below
    // consults.
    let delta_source_pins = extent_index_snapshot.named_delta_sources();

    for er in &job.entries {
        if er.hash == crate::volume::ZERO_HASH {
            continue;
        }
        let should_rewrite = *decision.entry(er.hash).or_insert_with(|| {
            let runs = lbamap_snapshot.runs_for_hash(&er.hash);
            let contained = runs.iter().all(|(lba, length, _)| {
                *lba >= target_start && *lba + *length as u64 <= target_end
            });
            if !contained {
                return false;
            }
            // Bloat: at least one block inside the hash's logical body is
            // no longer referenced by any live LBA. Mirror the scanner's
            // criterion (`scan_reclaim_candidates`) so the two agree on
            // "worth rewriting" — the previous `any run with
            // payload_block_offset != 0` gate only caught middle
            // overwrites and silently rejected tail overwrites that the
            // scanner flagged.
            let live_blocks: u64 = runs.iter().map(|(_, len, _)| *len as u64).sum();
            let max_offset_end: u64 = runs
                .iter()
                .map(|(_, len, off)| *off as u64 + *len as u64)
                .max()
                .unwrap_or(0);
            let logical_blocks = match extent_index_snapshot.lookup(&er.hash) {
                Some(loc) if loc.inline_data.is_none() && loc.codec == segment::Codec::None => {
                    // Plaintext Data: body_length is the exact logical
                    // size in bytes. Divide to get blocks. Catches tail
                    // overwrites where max_offset_end == live_blocks.
                    loc.body_length as u64 / 4096
                }
                // Compressed Data, Inline, Delta-backed, or missing from
                // the index: we don't have an exact logical-size signal,
                // so max_offset_end is a conservative lower bound.
                // Catches middle splits; misses pure tail overwrites of
                // these shapes (rare in practice).
                _ => max_offset_end,
            };
            live_blocks < logical_blocks
        });
        if !should_rewrite {
            continue;
        }

        // Resolve the body / delta-source context for this hash (cached).
        use std::collections::hash_map::Entry;
        let resolved = match body_cache.entry(er.hash) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(v) => {
                let fetched =
                    read_reclaim_extent_body(&extent_index_snapshot, &job.search_dirs, &er.hash)?;
                v.insert(fetched)
            }
        };

        let length_blocks = (er.range_end - er.range_start) as u32;
        let start = er.payload_block_offset as usize * 4096;
        let end = start + length_blocks as usize * 4096;

        match resolved {
            ReclaimBody::Skip => continue,
            ReclaimBody::Data(body) => {
                if body.len() < end {
                    return Err(io::Error::other(format!(
                        "reclaim: body for hash {} too short ({} < {end})",
                        er.hash.to_hex(),
                        body.len()
                    )));
                }
                let bytes = &body[start..end];
                let new_hash = blake3::hash(bytes);

                // If the new hash is already canonical somewhere, emit a thin
                // DedupRef — cheapest possible output, strictly beats any Delta.
                if extent_index_snapshot.lookup(&new_hash).is_some() {
                    entries.push(segment::PendingEntry::from_entry(
                        segment::SegmentEntry::new_dedup_ref(
                            new_hash,
                            er.range_start,
                            length_blocks,
                        ),
                    ));
                    uncompressed_bytes.push(bytes.len() as u64);
                    continue;
                }

                // When H's body is going to stick around regardless of
                // this reclaim, emitting a thin Delta against H is a
                // strict win over a fresh body: the sliced sub-range is
                // a literal substring of H, so `zstd_compress(sub, dict=H)`
                // is typically a few hundred bytes (a dict reference)
                // versus a few KB for a fresh lz4'd body.
                //
                // Two independent signals that H will stick around:
                // 1. H's segment is pinned by the current snapshot
                //    (segment_id <= snapshot_floor_ulid). Snapshot-
                //    referenced segments cannot be rewritten or dropped
                //    for the lifetime of the snapshot — a much stickier
                //    pin than a delta-source pin, which lasts only while
                //    some delta canonical stays live.
                // 2. H is already serving as a delta source for a live
                //    delta canonical (`delta_source_pins`). The liveness
                //    closure keeps H alive as long as any such Delta
                //    remains on the volume.
                //
                // If neither holds, H would be orphaned by this reclaim
                // and GC would drop its body on the next pass; pinning
                // H via our own Delta would trade "drop H's body" for
                // "keep it forever" — net loss.
                //
                // Size guard: if zstd isn't smaller than the raw sub-range,
                // fall through to Data. The guard also protects against
                // pathological inputs where the sub-range and H's body
                // happen to be the same bytes (zero bloat, no reclaim
                // should have been attempted).
                let pre_snapshot_h = match (
                    job.snapshot_floor_ulid,
                    extent_index_snapshot.lookup(&er.hash),
                ) {
                    (Some(floor), Some(loc)) => loc.segment_id <= floor,
                    _ => false,
                };
                let source_pinned = pre_snapshot_h || delta_source_pins.contains(&er.hash);
                if source_pinned {
                    let delta_blob = zstd::bulk::Compressor::with_dictionary(
                        crate::delta_compute::ZSTD_LEVEL,
                        body,
                    )
                    .map_err(|e| io::Error::other(format!("reclaim zstd compressor init: {e}")))?
                    .compress(bytes)
                    .map_err(|e| io::Error::other(format!("reclaim zstd compress: {e}")))?;
                    if delta_blob.len() < bytes.len() {
                        let delta_offset = delta_body.len() as u64;
                        let delta_length = delta_blob.len() as u32;
                        let delta_hash = segment::stored_hash(&delta_blob);
                        delta_body.extend_from_slice(&delta_blob);

                        entries.push(segment::PendingEntry::from_entry(
                            segment::SegmentEntry::new_delta(
                                new_hash,
                                er.range_start,
                                length_blocks,
                                vec![segment::DeltaOption {
                                    source_hash: er.hash,
                                    delta_offset,
                                    delta_length,
                                    delta_hash,
                                }],
                            ),
                        ));
                        uncompressed_bytes.push(bytes.len() as u64);
                        continue;
                    }
                    // delta_blob wasn't smaller — fall through to Data.
                }

                let (codec, stored_body) = match crate::volume::compress_body(bytes, false)? {
                    Some(pair) => pair,
                    None => (segment::Codec::None, bytes.to_vec()),
                };
                entries.push(segment::SegmentEntry::new_data(
                    new_hash,
                    er.range_start,
                    length_blocks,
                    codec,
                    stored_body,
                ));
                uncompressed_bytes.push(bytes.len() as u64);
            }
            ReclaimBody::Delta {
                source_hash,
                source_plain,
                fragment,
            } => {
                if fragment.len() < end {
                    return Err(io::Error::other(format!(
                        "reclaim: delta fragment for hash {} too short ({} < {end})",
                        er.hash.to_hex(),
                        fragment.len()
                    )));
                }
                let bytes = &fragment[start..end];
                let new_hash = blake3::hash(bytes);

                // If the new hash is already canonical somewhere, prefer a
                // thin DedupRef — a DATA entry is cheaper to read than a
                // Delta when the body exists.
                if extent_index_snapshot.lookup(&new_hash).is_some() {
                    entries.push(segment::PendingEntry::from_entry(
                        segment::SegmentEntry::new_dedup_ref(
                            new_hash,
                            er.range_start,
                            length_blocks,
                        ),
                    ));
                    uncompressed_bytes.push(bytes.len() as u64);
                    continue;
                }

                // Re-delta the sliced sub-range against the same source
                // we just used to decompress. If the resulting blob
                // isn't smaller than the raw sub-range bytes, skip — a
                // bigger-delta entry would be a net loss on every read
                // path.
                let delta_blob = zstd::bulk::Compressor::with_dictionary(
                    crate::delta_compute::ZSTD_LEVEL,
                    source_plain,
                )
                .map_err(|e| io::Error::other(format!("reclaim zstd compressor init: {e}")))?
                .compress(bytes)
                .map_err(|e| io::Error::other(format!("reclaim zstd compress: {e}")))?;
                if delta_blob.len() >= bytes.len() {
                    continue;
                }

                let delta_offset = delta_body.len() as u64;
                let delta_length = delta_blob.len() as u32;
                let delta_hash = segment::stored_hash(&delta_blob);
                delta_body.extend_from_slice(&delta_blob);

                entries.push(segment::PendingEntry::from_entry(
                    segment::SegmentEntry::new_delta(
                        new_hash,
                        er.range_start,
                        length_blocks,
                        vec![segment::DeltaOption {
                            source_hash: *source_hash,
                            delta_offset,
                            delta_length,
                            delta_hash,
                        }],
                    ),
                ));
                uncompressed_bytes.push(bytes.len() as u64);
            }
        }
    }

    if entries.is_empty() {
        return Ok(ReclaimResult {
            segment_ulid: job.segment_ulid,
            body_section_start: 0,
            body_length: 0,
            entries: Vec::new(),
            segment_written: false,
            pending_dir: job.pending_dir,
        });
    }

    // Write the segment. Tmp + rename gives us the same commit point
    // `segment::write_and_commit` provides for delta-free reclaim.
    let ulid_str = job.segment_ulid.to_string();
    let tmp_path = job.pending_dir.join(format!("{ulid_str}.tmp"));
    let final_path = job.pending_dir.join(&ulid_str);
    let (body_section_start, entries) = segment::write_segment_full(
        &tmp_path,
        entries,
        &delta_body,
        &[],
        crate::sketch_enabled(),
        job.signer.as_ref(),
    )?;
    fs::rename(&tmp_path, &final_path)?;
    segment::fsync_dir(&final_path)?;

    // body_length = sum of stored_length over entries that contribute
    // to the body section (Data + CanonicalData). Delta, DedupRef, and
    // Inline entries do not.
    let body_length: u64 = entries
        .iter()
        .filter(|e| e.kind.is_data())
        .map(|e| e.stored_length as u64)
        .sum();

    let reclaimed: Vec<ReclaimedEntry> = entries
        .into_iter()
        .zip(uncompressed_bytes)
        .map(|(entry, uncompressed_bytes)| ReclaimedEntry {
            entry,
            uncompressed_bytes,
        })
        .collect();

    Ok(ReclaimResult {
        segment_ulid: job.segment_ulid,
        body_section_start,
        body_length,
        entries: reclaimed,
        segment_written: true,
        pending_dir: job.pending_dir,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::volume::Volume;

    fn scanned(stored_bytes: u64, journal: bool) -> ScannedSegment {
        ScannedSegment {
            seg_path: PathBuf::from(format!("seg-{stored_bytes}-{journal}")),
            seg_ulid: Ulid::new(),
            stored_bytes,
            journal,
            all_live: false,
        }
    }

    fn admitted_bytes(a: &Admission) -> Vec<u64> {
        a.admitted.iter().map(|s| s.stored_bytes).collect()
    }

    #[test]
    fn admission_spends_the_budget_on_the_smallest_segments() {
        // A budget of 10 over 8, 3 and 2: smallest-first fits two segments
        // and folds two objects away, where taking them in the order given
        // would fit 8 and 2 and fold one.
        let a = admit_within_budget(
            vec![scanned(8, false), scanned(3, false), scanned(2, false)],
            10,
        );
        assert_eq!(admitted_bytes(&a), vec![2, 3]);
        assert_eq!(a.spent, 5);
        assert_eq!(a.turned_away, 1);
        assert_eq!(a.turned_away_bytes, 8);
    }

    #[test]
    fn admission_takes_journal_whatever_the_budget() {
        // The lift has to carry all pending journal above the pass's data
        // outputs, so the budget governs data alone.
        let a = admit_within_budget(
            vec![scanned(64, true), scanned(32, true), scanned(4, false)],
            1,
        );
        assert_eq!(admitted_bytes(&a), vec![64, 32]);
        assert_eq!(a.spent, 0, "journal spends none of the budget");
        assert_eq!(a.turned_away, 1);
        assert_eq!(a.turned_away_bytes, 4);
    }

    fn temp_dir() -> std::path::PathBuf {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("elide-actor-test-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        crate::signing::generate_keypair(
            &p,
            crate::signing::VOLUME_KEY_FILE,
            crate::signing::VOLUME_PUB_FILE,
        )
        .unwrap();
        p
    }

    /// Distinct, incompressible 4 KiB block per seed (splitmix64 stream)
    /// so entries land as body extents — compressible data goes inline in
    /// the extent index and reads of it never resolve a segment file.
    fn unique_block(seed: u32) -> Vec<u8> {
        let mut x = (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut out = Vec::with_capacity(4096);
        for _ in 0..512 {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            out.extend_from_slice(&z.to_le_bytes());
        }
        out
    }

    /// A fair release frees the mutex and still charges the hold.
    ///
    /// The guard keeps its lock in an `Option` so `drop` can hand it over
    /// by value; a release that failed to take it would leave the mutex
    /// held for the rest of the process.
    #[test]
    fn a_fair_release_frees_the_mutex_and_charges_the_hold() {
        let dir = temp_dir();
        let volume = Arc::new(Mutex::new(Volume::open(&dir, &dir).unwrap()));
        let stats = LockStats::default();

        drop(TimedGuard {
            guard: Some(lock_volume(&volume)),
            stats: &stats,
            site: LockSite::RepackApply,
            wait: Duration::ZERO,
            acquired: Instant::now(),
            fair: true,
        });

        assert!(
            volume.try_lock().is_some(),
            "a fair release left the mutex held"
        );
        assert_eq!(stats.snapshot().site(LockSite::RepackApply).acquisitions, 1);
    }

    /// Writes publish a snapshot, so `flush_gen` moves and a reader
    /// re-resolves through the new extent index. They append to a file every
    /// open descriptor already names, so `layout_gen` holds and the
    /// descriptors survive.
    #[test]
    fn writes_advance_flush_gen_and_hold_layout_gen() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        let before = client.snapshot.load();
        for lba in 0..8u64 {
            client.write(lba, &unique_block(lba as u32), false).unwrap();
        }
        let after = client.snapshot.load();

        assert!(
            after.flush_gen > before.flush_gen,
            "each write publishes a snapshot"
        );
        assert_eq!(
            after.layout_gen, before.layout_gen,
            "appending WAL bytes leaves every open descriptor valid"
        );

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Promotion rewrites the WAL into `pending/` and unlinks it, so a
    /// descriptor cached for the WAL names an inode that is gone. That
    /// advances `layout_gen` and retires the descriptor.
    #[test]
    fn promotion_advances_layout_gen() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        client.write(0, &unique_block(1), false).unwrap();
        let before = client.snapshot.load().layout_gen;
        client.promote_wal().unwrap();
        let after = client.snapshot.load().layout_gen;

        assert!(
            after > before,
            "promotion replaces segment files: {before} -> {after}"
        );

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The read-your-writes guarantee across the descriptor cache: the first
    /// read caches an open WAL descriptor, and the second read has to serve
    /// bytes that were appended to that file afterwards.
    #[test]
    fn a_cached_descriptor_serves_bytes_appended_after_it_was_opened() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());
        let reader = client.reader();

        let mut buf = vec![0u8; 4096];
        for seed in 1..=4u32 {
            let block = unique_block(seed);
            client.write(0, &block, false).unwrap();
            reader.read_into(0, &mut buf).unwrap();
            assert_eq!(
                buf, block,
                "read {seed} must see the write that preceded it"
            );
        }

        // The same holds across a promotion, which does retire the cached
        // descriptor.
        client.promote_wal().unwrap();
        let block = unique_block(5);
        client.write(0, &block, false).unwrap();
        reader.read_into(0, &mut buf).unwrap();
        assert_eq!(buf, block);

        drop(reader);
        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The descriptor-cache counters follow the cache: the first read of a
    /// segment opens a file, and a second read of the same segment reuses the
    /// descriptor. A cache sized to hold one file evicts on the second
    /// segment, so returning to the first opens it again.
    #[test]
    fn read_stats_count_descriptor_hits_and_misses() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        client.write(0, &unique_block(1), false).unwrap();
        client.promote_wal().unwrap();
        client.write(1, &unique_block(2), false).unwrap();
        client.promote_wal().unwrap();

        client.set_read_cache_capacity(1);
        let reader = client.reader();
        let mut buf = vec![0u8; 4096];

        reader.read_into(0, &mut buf).unwrap();
        let first = reader.read_stats();
        assert_eq!(first.extents_total, 1);
        assert_eq!(
            first.fd_miss_total, 1,
            "the first read has to open the file"
        );
        assert_eq!(first.fd_hit_total, 0);

        reader.read_into(0, &mut buf).unwrap();
        let second = reader.read_stats().since(&first);
        assert_eq!(second.fd_hit_total, 1, "the descriptor is still cached");
        assert_eq!(second.fd_miss_total, 0);

        // A second segment takes the only slot, so the first is evicted.
        reader.read_into(1, &mut buf).unwrap();
        let mark = reader.read_stats();
        reader.read_into(0, &mut buf).unwrap();
        let evicted = reader.read_stats().since(&mark);
        assert_eq!(evicted.fd_miss_total, 1, "one slot cannot hold both");

        let total = reader.read_stats();
        assert_eq!(total.extents_total, 4);
        assert!((total.fd_miss_rate() - 0.75).abs() < f64::EPSILON);

        drop(reader);
        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The descriptor cache is per volume: a segment opened through one
    /// reader serves the next reader's read of the same segment.
    #[test]
    fn readers_share_the_descriptor_cache() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        client.write(0, &unique_block(1), false).unwrap();
        client.promote_wal().unwrap();

        let warmer = client.reader();
        let sharer = client.reader();
        let mut buf = vec![0u8; 4096];

        warmer.read_into(0, &mut buf).unwrap();
        assert_eq!(warmer.read_stats().fd_miss_total, 1);

        sharer.read_into(0, &mut buf).unwrap();
        let stats = sharer.read_stats();
        assert_eq!(stats.fd_hit_total, 1, "the warmed descriptor is shared");
        assert_eq!(stats.fd_miss_total, 0);

        drop(warmer);
        drop(sharer);
        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A promote takes the WAL out from under a sync round's feet. The
    /// volume keeps the taken WAL's handle until the promote's segment is
    /// committed, so a round that starts after the rotation syncs the
    /// epoch's bytes, and a sync through the handle after the unlink is
    /// harmless because the segment carrying those bytes is committed.
    #[test]
    fn a_sync_round_covers_a_rotated_wal_until_its_segment_commits() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        let block = unique_block(21);
        client.write(9, &block, false).unwrap();
        let handles = lock_volume(&client.volume().unwrap()).sync_handles();
        assert_eq!(handles.len(), 1, "the write left a WAL open");

        client.promote_wal().unwrap();
        assert!(
            lock_volume(&client.volume().unwrap())
                .sync_handles()
                .is_empty(),
            "the committed promote released its WAL from the sync set"
        );
        for file in handles {
            file.sync_data().unwrap();
        }

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();

        let recovered = Volume::open(&dir, &dir).unwrap();
        assert_eq!(recovered.read(9, 1).unwrap(), block);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// Concurrent FUA writers each sync off the lock, so their syncs
    /// overlap.  Every write is durable when its own call returns, which a
    /// recovery open with no flush or promote in between confirms.
    #[test]
    fn concurrent_fua_writes_are_each_durable() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        let blocks: Vec<Vec<u8>> = (0..8).map(unique_block).collect();
        std::thread::scope(|s| {
            for (i, block) in blocks.iter().enumerate() {
                let client = &client;
                s.spawn(move || client.write(i as u64, block, true).unwrap());
            }
        });

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();

        let recovered = Volume::open(&dir, &dir).unwrap();
        for (i, block) in blocks.iter().enumerate() {
            assert_eq!(&recovered.read(i as u64, 1).unwrap(), block);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A FUA write syncs the WAL before returning, so a recovery open of
    /// the same directory sees the data with no flush or promote in
    /// between.
    #[test]
    fn fua_write_is_durable_without_flush() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        let block = unique_block(7);
        client.write(3, &block, true).unwrap();

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();

        let recovered = Volume::open(&dir, &dir).unwrap();
        assert_eq!(recovered.read(3, 1).unwrap(), block);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A sync round takes the WAL handles under the volume lock and syncs
    /// them after releasing, so it has an open-WAL arm and a no-WAL arm.
    /// Exercise both, plus the rotation that moves one to the other:
    /// `promote_wal` leaves the volume WAL-less, and the flush that
    /// follows finds an empty sync set.
    #[test]
    fn flush_spans_wal_open_and_wal_absent() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        // No WAL has ever been opened.
        client.flush().unwrap();

        let block = unique_block(11);
        client.write(5, &block, false).unwrap();
        client.flush().unwrap();

        // Promote takes the WAL, so the next flush finds none open.
        client.promote_wal().unwrap();
        client.flush().unwrap();

        // A fresh WAL opens lazily under the next write.
        let after = unique_block(12);
        client.write(6, &after, false).unwrap();
        client.flush().unwrap();

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();

        let recovered = Volume::open(&dir, &dir).unwrap();
        assert_eq!(recovered.read(5, 1).unwrap(), block);
        assert_eq!(recovered.read(6, 1).unwrap(), after);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A flush with a promote in flight syncs the rotated WAL itself and
    /// acks while the promote waits on the worker; the gate counts that
    /// round as rotated.
    #[test]
    fn flush_syncs_rotated_wal_without_waiting_on_promote() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        client.write(0, &unique_block(1), false).unwrap();
        client.flush().unwrap();

        let quiet = client.sync_gate();
        assert_eq!(quiet.flush_requests, 1, "setup: the flush was counted");
        assert_eq!(quiet.rounds, 1, "setup: the flush led a round");
        assert_eq!(quiet.rotated_rounds, 0, "no rotated WALs existed yet");

        // Occupy the worker so a promote dispatches but cannot run.
        let (hold_tx, hold_rx) = bounded::<()>(1);
        client.test_dispatch_barrier(hold_rx);

        let baseline = client.lock_stats();
        let promote_done = {
            let c = client.clone();
            let (tx, rx) = bounded(1);
            std::thread::spawn(move || {
                let _ = tx.send(c.promote_wal());
            });
            rx
        };

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while client
            .lock_stats()
            .since(&baseline)
            .site(LockSite::PromotePrep)
            .acquisitions
            == 0
        {
            assert!(
                std::time::Instant::now() < deadline,
                "setup: promote prep never ran"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // The promote is queued behind the barrier. The round covers
        // its rotated WAL through the volume's sync set, so this call
        // returns while the barrier still holds the worker.
        client.write(1, &unique_block(2), false).unwrap();
        client.flush().unwrap();

        let after = client.sync_gate();
        assert_eq!(after.rounds, 2, "the flush led a second round");
        assert_eq!(after.rotated_rounds, 1, "the round found a rotated WAL");

        hold_tx.send(()).unwrap();
        promote_done.recv().unwrap().unwrap();

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The flush handle is taken under the lock and synced off it, so a
    /// write can land in between. That write rides the same sync — the
    /// flush covers more than its caller asked for, and both records
    /// replay.
    #[test]
    fn write_concurrent_with_flush_replays() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        let first = unique_block(21);
        client.write(0, &first, false).unwrap();

        let writer = {
            let client = client.clone();
            let block = unique_block(22);
            std::thread::spawn(move || {
                client.write(1, &block, false).unwrap();
                block
            })
        };
        client.flush().unwrap();
        let second = writer.join().unwrap();

        client.shutdown();
        drop(client);
        actor_thread.join().unwrap();

        let recovered = Volume::open(&dir, &dir).unwrap();
        assert_eq!(recovered.read(0, 1).unwrap(), first);
        assert_eq!(recovered.read(1, 1).unwrap(), second);
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// The sites describe what the actor does to writers, so an
    /// actor-side operation must land against its own site and a guest
    /// write against none of them — a write lands in the separate write
    /// counters, which measure what it waited rather than what it held.
    #[test]
    fn actor_operations_record_against_their_site() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        std::thread::Builder::new()
            .name("volume-actor".into())
            .spawn(move || actor.run())
            .unwrap();

        // Every write publishes a snapshot under the mutex, so counting
        // the write path would show up here and nowhere else.
        for lba in 0..3u64 {
            client
                .write(lba, &unique_block(lba as u32 + 1), false)
                .unwrap();
        }
        let after_writes = client.lock_stats();
        assert_eq!(
            after_writes.site(LockSite::PublishSnapshot).acquisitions,
            0,
            "the guest write path must not be attributed to a site"
        );
        assert_eq!(
            after_writes.writes().acquisitions,
            3,
            "every guest write counts its acquisition"
        );
        assert!(
            after_writes.writes().blocked <= after_writes.writes().acquisitions,
            "a write can only block on an acquisition it made"
        );

        client.promote_wal().unwrap();
        let after_promote = client.lock_stats().since(&after_writes);
        assert!(
            after_promote.site(LockSite::PromotePrep).acquisitions > 0,
            "promote prep acquires the mutex"
        );
        assert!(
            after_promote.site(LockSite::PromoteApply).acquisitions > 0,
            "promote apply acquires the mutex"
        );
        assert!(
            after_promote.site(LockSite::ClosePrep).acquisitions == 0,
            "a promote must not be attributed to the close pass"
        );

        // Overwrite everything the promoted segment claims, so the reap
        // finds it whole-dead and its apply acquires the mutex.
        for lba in 0..3u64 {
            client
                .write(lba, &unique_block(10 + lba as u32), false)
                .unwrap();
        }
        let stats = client.reap().unwrap();
        assert!(stats.segments_reaped > 0, "setup: nothing reaped");
        let after_reap = client.lock_stats().since(&after_promote);
        assert!(
            after_reap.site(LockSite::ReapApply).acquisitions > 0,
            "the reap's apply acquires the mutex"
        );
        assert!(
            client.lock_stats().report().is_some(),
            "a window with acquisitions reports a line"
        );
    }

    /// A reader whose snapshot predates the close pass must still resolve
    /// reads after the pass unlinks its input segments — the data is
    /// live, only its location changed. Reproduces the 2026-07-11 field
    /// EIO ("segment not found" during the rewrite swap window).
    #[test]
    fn stale_snapshot_read_survives_the_close_pass() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        std::thread::Builder::new()
            .name("volume-actor".into())
            .spawn(move || actor.run())
            .unwrap();

        let block_a = unique_block(1);
        client.write(0, &block_a, false).unwrap();
        client.write(1, &unique_block(2), false).unwrap();
        client.write(2, &unique_block(3), false).unwrap();
        client.promote_wal().unwrap();

        // Overwrite one LBA in a second segment so the first has dead
        // bytes and is a repack candidate.
        client.write(1, &unique_block(4), false).unwrap();
        client.promote_wal().unwrap();

        // A reader's view captured before the close pass.
        let stale = client.snapshot.load_full();

        let closed = client.close_generation().unwrap();
        assert_eq!(
            closed,
            Some(2),
            "setup: the close sealed no segments, race not exercised"
        );

        let reader = client.reader();
        let mut buf = vec![0u8; 4096];
        reader
            .read_with_snapshot(&stale, 0, &mut buf)
            .expect("read of live data through a pre-close snapshot");
        assert_eq!(buf, block_a, "read must return the live block contents");
    }

    /// Deterministic reconstruction of the 2026-07-13 field wedge: the
    /// worker blocked sending into a full result queue while the actor
    /// dispatched into a full job queue. A blocking dispatch deadlocks
    /// here — the volume stops serving IO and IPC permanently. The
    /// drain-and-retry dispatch must complete and leave the volume
    /// responsive.
    ///
    /// The sleeps only give threads time to reach states they are
    /// already committed to (a dequeue, a blocked send); no ordering
    /// depends on winning a race.
    #[test]
    fn dispatch_into_full_queues_stays_live() {
        let dir = temp_dir();
        let vol = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(vol);
        let actor_thread = std::thread::spawn(move || actor.run());

        // B1 occupies the worker; give it time to dequeue before
        // filling the job queue exactly to capacity with B2..B5.
        let (h1_tx, h1_rx) = bounded::<()>(1);
        client.test_dispatch_barrier(h1_rx);
        std::thread::sleep(Duration::from_millis(300));
        let mut early = vec![h1_tx];
        for _ in 0..4 {
            let (tx, rx) = bounded::<()>(1);
            client.test_dispatch_barrier(rx);
            early.push(tx);
        }

        // The next request parks the actor in-handler, then dispatches
        // five more barriers without returning to the select loop — so
        // nothing can drain worker results between those dispatches.
        let (park_tx, park_rx) = bounded::<()>(1);
        let mut late = Vec::new();
        let mut late_holds = Vec::new();
        for _ in 0..5 {
            let (tx, rx) = bounded::<()>(1);
            // Pre-fire the hold so the job completes the moment the
            // worker dequeues it — the deadlock under test lives in the
            // queues, not in job execution time.
            tx.send(()).unwrap();
            late.push(tx);
            late_holds.push(rx);
        }
        client.test_park_then_dispatch_barriers(park_rx, late_holds);
        std::thread::sleep(Duration::from_millis(200));

        // With the actor parked, complete all five early jobs: results
        // 1-4 fill the result queue and the worker blocks sending the
        // fifth.
        for h in &early {
            let _ = h.send(());
        }
        std::thread::sleep(Duration::from_millis(500));

        // Unpark. The handler now dispatches five jobs back to back;
        // the fifth lands on a full job queue while the worker is still
        // wedged on the result queue — the field deadlock shape.
        park_tx.send(()).unwrap();

        // Liveness probe: flush answers only once the actor has made it
        // through all five dispatches.
        let (done_tx, done_rx) = bounded(1);
        {
            let c = client.clone();
            std::thread::spawn(move || {
                let _ = done_tx.send(c.flush());
            });
        }
        done_rx
            .recv_timeout(Duration::from_secs(30))
            .expect("actor wedged dispatching into full worker queues")
            .expect("flush after dispatch flood");
        drop(late);

        // Let the actor drain the late results before shutdown joins
        // the worker.
        std::thread::sleep(Duration::from_millis(500));
        client.shutdown();
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A lone all-live journal segment consolidates through the same
    /// rewrite as every other close pass, and each inline entry reaches
    /// the apply's registration carrying its bytes — a location without
    /// them survives reads only until the drain-promote flips it to
    /// `Cached`, after which the demand-fetch path rejects the inline
    /// kind. Reconstructs the 2026-08-13 pg28 spurious EIO on a jbd2
    /// commit block (issue #950).
    #[test]
    fn journal_inline_read_survives_solo_consolidation() {
        let dir = temp_dir();
        drop(Volume::open(&dir, &dir).unwrap());
        let mut cfg = crate::config::VolumeConfig::read(&dir).unwrap();
        cfg.journal = Some(crate::config::JournalConfig {
            ranges: crate::journal::JournalRanges::new(vec![(1024, 64)]),
        });
        cfg.write(&dir).unwrap();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        // One journal epoch, fully live: compressible window content
        // forms as an inline entry. Data blocks ride along so the close
        // pass has data outputs and carries the journal above them.
        let jblock = vec![0xAB_u8; 4096];
        client.write(1024, &jblock, false).unwrap();
        client.write(0, &unique_block(11), false).unwrap();
        client.promote_wal().unwrap();
        client.write(1, &unique_block(12), false).unwrap();
        client.promote_wal().unwrap();

        let closed = client.close_generation().unwrap();
        assert!(closed.is_some(), "setup: the close pass sealed nothing");

        let upload_dir = crate::segment::pending_upload_dir(&dir);
        let mut segs: Vec<Ulid> = std::fs::read_dir(&upload_dir)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                Ulid::from_string(&name).ok()
            })
            .collect();
        segs.sort();
        assert!(!segs.is_empty(), "setup: nothing packed to upload");
        for u in &segs {
            let (_, _, inputs) =
                crate::segment::read_segment_index(&upload_dir.join(u.to_string())).unwrap();
            assert!(
                !inputs.is_empty(),
                "close pass output {u} must record its consumed inputs"
            );
            client.promote_segment(*u).unwrap();
        }

        let reader = client.reader();
        let mut buf = vec![0u8; 4096];
        reader
            .read_with_snapshot(&client.snapshot.load_full(), 1024, &mut buf)
            .expect("journal inline read after solo consolidation and drain promote");
        assert_eq!(buf, jblock, "journal inline read content");

        client.shutdown();
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A journal-window write that forms as an inline entry stays
    /// readable after the close pass's consolidation merge and the
    /// drain-promote into the cache (the multi-epoch sibling of the
    /// solo consolidation above; issue #950).
    #[test]
    fn journal_inline_read_survives_cache_promote() {
        let dir = temp_dir();
        drop(Volume::open(&dir, &dir).unwrap());
        let mut cfg = crate::config::VolumeConfig::read(&dir).unwrap();
        cfg.journal = Some(crate::config::JournalConfig {
            ranges: crate::journal::JournalRanges::new(vec![(1024, 64)]),
        });
        cfg.write(&dir).unwrap();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        // Two epochs of journal-window writes: compressible content
        // forms as inline entries (jbd2 commit blocks in the field), a
        // data block rides along in each flush. Epoch 2 overwrites one
        // of epoch 1's window LBAs — the ring-wrap shape — so the close
        // pass has dead journal bytes and runs a real consolidation
        // merge that must carry epoch 1's surviving inline entry.
        let jblock_a = vec![0xAB_u8; 4096];
        let jblock_b = vec![0xCD_u8; 4096];
        let jblock_c = vec![0xEF_u8; 4096];
        client.write(1024, &jblock_a, false).unwrap();
        client.write(1030, &jblock_c, false).unwrap();
        client.write(0, &unique_block(9), false).unwrap();
        client.promote_wal().unwrap();
        client.write(1024, &jblock_b, false).unwrap();
        client.write(1, &unique_block(10), false).unwrap();
        client.promote_wal().unwrap();

        let reader = client.reader();
        let mut buf = vec![0u8; 4096];
        reader
            .read_with_snapshot(&client.snapshot.load_full(), 1030, &mut buf)
            .expect("pre-close journal read");
        assert_eq!(buf, jblock_c, "pre-close journal read content");

        // The close pass packs the generation; the journal segments
        // merge into one consolidation output.
        let closed = client.close_generation().unwrap();
        assert!(closed.is_some(), "setup: the close pass sealed nothing");

        // Drain: promote every packed segment into the cache, ULID order.
        let upload_dir = crate::segment::pending_upload_dir(&dir);
        let mut segs: Vec<Ulid> = std::fs::read_dir(&upload_dir)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().into_string().ok()?;
                Ulid::from_string(&name).ok()
            })
            .collect();
        segs.sort();
        assert!(!segs.is_empty(), "setup: nothing packed to upload");
        for u in &segs {
            client.promote_segment(*u).unwrap();
        }

        for (lba, want, label) in [
            (1024u64, &jblock_b, "jblock_b"),
            (1030u64, &jblock_c, "jblock_c carried through the merge"),
        ] {
            let mut buf = vec![0u8; 4096];
            reader
                .read_with_snapshot(&client.snapshot.load_full(), lba, &mut buf)
                .unwrap_or_else(|e| panic!("journal read {label} after drain promote: {e}"));
            assert_eq!(&buf, want, "journal read {label} content");
        }

        client.shutdown();
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A GC checkpoint that finds an empty WAL still waits for promotes
    /// already in flight. Their claims sit in a WAL file until the apply
    /// moves them into `pending/`, and the coordinator reads segments
    /// before WALs when it builds the pass's liveness view — a reply
    /// sent mid-flight lets the move land between those two reads and
    /// the claims vanish from both. Reconstructs the 2026-08-12 pg28
    /// `superseded_carry` interleaving (issue #914).
    #[test]
    fn empty_wal_gc_checkpoint_waits_for_inflight_promote() {
        let dir = temp_dir();
        let volume = Volume::open(&dir, &dir).unwrap();
        let (actor, client) = spawn(volume);
        let actor_thread = std::thread::spawn(move || actor.run());

        client.write(0, &unique_block(1), false).unwrap();
        let wal_files = |dir: &std::path::Path| -> usize {
            std::fs::read_dir(dir.join("wal"))
                .map(|d| d.filter_map(|e| e.ok()).count())
                .unwrap_or(0)
        };
        assert_eq!(wal_files(&dir), 1, "setup: the write opened a WAL");

        // Occupy the worker so the promote dispatches but cannot apply.
        let (hold_tx, hold_rx) = bounded::<()>(1);
        client.test_dispatch_barrier(hold_rx);

        // Promote the WAL behind the barrier; the reply parks on the
        // apply, so it runs on its own thread.
        let baseline = client.lock_stats();
        let promote_done = {
            let c = client.clone();
            let (tx, rx) = bounded(1);
            std::thread::spawn(move || {
                let _ = tx.send(c.promote_wal());
            });
            rx
        };

        // Prep and dispatch run inside one handler invocation, so once
        // a `PromotePrep` acquisition lands, the promote job is queued
        // behind the barrier ahead of any request sent from here on.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while client
            .lock_stats()
            .since(&baseline)
            .site(LockSite::PromotePrep)
            .acquisitions
            == 0
        {
            assert!(
                std::time::Instant::now() < deadline,
                "setup: promote prep never ran"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // The checkpoint sees an empty (fresh) WAL. Its reply must wait
        // out the promote parked behind the barrier.
        let checkpoint_done = {
            let c = client.clone();
            let (tx, rx) = bounded(1);
            std::thread::spawn(move || {
                let _ = tx.send(c.gc_checkpoint(4));
            });
            rx
        };
        assert!(
            checkpoint_done
                .recv_timeout(Duration::from_millis(500))
                .is_err(),
            "gc_checkpoint replied while the promote's claims were still WAL-only"
        );

        hold_tx.send(()).unwrap();
        let reply = checkpoint_done
            .recv_timeout(Duration::from_secs(30))
            .expect("checkpoint reply after the barrier released")
            .expect("gc_checkpoint");
        assert!(!reply.bucket_ulids.is_empty());
        promote_done
            .recv_timeout(Duration::from_secs(30))
            .expect("promote reply after the barrier released")
            .expect("promote_wal");

        // The reply implies the apply ran: the promoted WAL is unlinked,
        // and with nothing written since, `wal/` is empty.
        assert_eq!(
            wal_files(&dir),
            0,
            "the checkpoint reply must observe the promote's apply"
        );

        client.shutdown();
        actor_thread.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
