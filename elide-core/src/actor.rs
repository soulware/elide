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

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::thread::JoinHandle;
use std::time::Duration;

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded, tick};
use log::{error, warn};

use ulid::Ulid;

use crate::extentindex::ExtentIndex;
use crate::lbamap::LbaMap;
use crate::segment::{self, BoxFetcher};
use crate::volume::{
    AncestorLayer, CompactionStats, FileCache, GcCheckpointPrep, GcPlanApplyJob, GcPlanApplyResult,
    NoopSkipStats, PromoteFailure, PromoteJob, PromoteResult, PromoteSegmentJob,
    PromoteSegmentPrep, PromoteSegmentResult, ReclaimCandidate, ReclaimJob, ReclaimOutcome,
    ReclaimResult, ReclaimThresholds, ReclaimedEntry, RepackJob, RepackResult,
    SignSnapshotManifestJob, SignSnapshotManifestResult, Volume, WorkerJob, WorkerResult,
    find_segment_in_dirs, open_delta_body_in_dirs, read_extents, scan_reclaim_candidates,
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
/// `flush_gen` is incremented by the actor on every WAL promotion.  Handles
/// compare it against their cached value; a change means the extent index now
/// contains post-promote (segment-format) body offsets and any cached WAL file
/// descriptor must be evicted.  Because `flush_gen` is stored inside the
/// snapshot, a handle always sees a consistent pair: if it observes a new
/// generation it also observes the updated extent index in the same atomic
/// load — there is no window between the two.
pub struct ReadSnapshot {
    pub lbamap: Arc<LbaMap>,
    pub extent_index: Arc<ExtentIndex>,
    pub flush_gen: u64,
}

// ---------------------------------------------------------------------------
// Channel message type
// ---------------------------------------------------------------------------

pub(crate) enum VolumeRequest {
    Flush {
        reply: Sender<io::Result<()>>,
    },
    /// Fire-and-forget signal from a direct writer that the WAL may have
    /// crossed the promote threshold.  The actor checks `needs_promote()`
    /// and dispatches a promote if so.  Idempotent; the actor's idle tick
    /// would catch this eventually anyway, so a dropped signal (channel
    /// full) is benign.
    CheckPromote,
    ApplyGcHandoffs {
        reply: Sender<io::Result<usize>>,
    },
    Repack {
        reply: Sender<io::Result<CompactionStats>>,
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
    /// Shared via `Arc<Mutex<...>>` rather than owned exclusively so a
    /// future PR can let the ublk transport bypass the request channel
    /// for hot-path writes by acquiring the same lock directly. Today
    /// the actor is still the only writer; the lock is uncontended.
    volume: Arc<Mutex<Volume>>,
    snapshot: Arc<ArcSwap<ReadSnapshot>>,
    rx: Receiver<VolumeRequest>,
    /// Promotion counter.  Bumped under the volume mutex on every snapshot
    /// publish (actor-side state changes and direct writes from the ublk
    /// transport) and embedded into the published `ReadSnapshot` so that
    /// handles see a consistent (generation, extent_index) pair from a
    /// single atomic load.  Shared with `VolumeClient` so direct writers
    /// can publish without an actor round-trip.
    flush_gen: Arc<AtomicU64>,
    /// Sender for dispatching jobs to the worker thread.
    /// `Option` so shutdown can `take()` it, dropping the sender to signal
    /// the worker to exit.
    worker_tx: Option<Sender<WorkerJob>>,
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
}

/// Promote-pipeline bookkeeping: dispatch/completion generations for
/// the flush-durability barrier, plus replies parked on specific
/// promotes.
#[derive(Default)]
struct PromotePipeline {
    /// Number of promote jobs dispatched but not yet applied.
    promotes_in_flight: usize,
    /// Monotonic counter, incremented on every `WorkerJob::Promote`
    /// dispatch (post-write threshold, `PromoteWal`, `GcCheckpoint`).
    /// Used together with `completed_gen` to park `Flush` replies
    /// until every promote dispatched *before* the flush has had its
    /// old-WAL fsync completed by the worker.
    promote_gen: u64,
    /// Monotonic counter, incremented on every `WorkerResult::Promote`
    /// (success *or* error) received from the worker.  For errors the
    /// actor performs a fallback fsync itself before bumping the
    /// counter, so `completed_gen >= needed_gen` always implies every
    /// promote dispatched at or before `needed_gen` has had its old
    /// WAL made durable.
    completed_gen: u64,
    /// FIFO queue of old WAL paths for promotes currently dispatched
    /// but not yet completed.  Matches the worker's strict dispatch
    /// order (single thread, bounded FIFO channel).  Popped on every
    /// worker result; the error path re-fsyncs the popped path on the
    /// actor thread as a fallback before bumping `completed_gen`.
    inflight_old_wals: VecDeque<PathBuf>,
    /// `Flush` replies parked until `completed_gen >= needed_gen`.
    /// Each entry records the `promote_gen` snapshot at the time the
    /// flush arrived; as worker results come in the actor resolves any
    /// entries whose precondition now holds.
    parked_flushes: Vec<ParkedFlush>,
    /// Parked GC checkpoint: the reply sender and GC ULIDs, waiting for
    /// the GC promote (`u_flush`) to complete on the worker.  `None`
    /// when no GC checkpoint is in progress.
    parked_gc: Option<ParkedGcCheckpoint>,
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
    /// Whether a GC plan handoff job is currently on the worker thread.
    handoff_in_flight: bool,
    /// Reply channel for an in-flight `Repack` request, parked while
    /// the worker thread executes the repack.
    repack: Option<Sender<io::Result<CompactionStats>>>,
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
struct ParkedPromoteWal {
    segment_ulid: Ulid,
    reply: Sender<io::Result<()>>,
}

/// State stashed while a `Flush` waits for an in-flight promote's
/// old-WAL fsync to complete on the worker.  Released when
/// `PromotePipeline::completed_gen >= needed_gen`.
struct ParkedFlush {
    needed_gen: u64,
    reply: Sender<io::Result<()>>,
}

/// State stashed while a `promote_segment` job is on the worker thread.
struct ParkedPromoteSegment {
    ulid: Ulid,
    reply: Sender<io::Result<()>>,
}

/// State stashed while a GC checkpoint's promote is in flight.
struct ParkedGcCheckpoint {
    u_buckets: Vec<Ulid>,
    u_flush: Ulid,
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

/// Acquire the volume mutex.
///
/// Poisoning would mean library code panicked while holding the lock —
/// forbidden by CLAUDE.md's "no panic in library paths" rule.  Once
/// poisoned, the volume's in-memory state is mid-mutation and the
/// caller's thread is already doomed; we surface that with a clear
/// message rather than continuing on broken state.
fn lock_volume(volume: &Arc<Mutex<Volume>>) -> MutexGuard<'_, Volume> {
    volume.lock().expect("volume mutex poisoned")
}

/// Bump `flush_gen` and publish a fresh `ReadSnapshot`.
///
/// Must be called while holding the volume mutex (the `&Volume` argument
/// is the live guard) so the (lbamap, extent_index, flush_gen) tuple
/// observed by the next `snapshot.load()` is internally consistent.
fn publish_snapshot(volume: &Volume, snapshot: &ArcSwap<ReadSnapshot>, flush_gen: &AtomicU64) {
    let new_gen = flush_gen.fetch_add(1, Ordering::SeqCst) + 1;
    let (lbamap, extent_index) = volume.snapshot_maps();
    snapshot.store(Arc::new(ReadSnapshot {
        lbamap,
        extent_index,
        flush_gen: new_gen,
    }));
}

impl VolumeActor {
    fn lock_volume(&self) -> MutexGuard<'_, Volume> {
        lock_volume(&self.volume)
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

    fn publish_snapshot(&mut self) {
        let guard = self.lock_volume();
        publish_snapshot(&guard, &self.snapshot, &self.flush_gen);
    }

    /// Apply a worker's repack result, publish the read snapshot, then
    /// unlink the consumed input files. The publish must come before
    /// the unlinks: publishing first guarantees no published snapshot
    /// ever references a deleted input, and readers still holding an
    /// older snapshot recover via the `NotFound` retry in
    /// [`VolumeReader::read_with_snapshot`].
    fn apply_repack_and_publish(&mut self, result: RepackResult) -> io::Result<CompactionStats> {
        let (stats, consumed_inputs) = self.lock_volume().apply_repack_result(result)?;
        if stats.segments_compacted > 0 || !consumed_inputs.is_empty() {
            self.publish_snapshot();
        }
        self.lock_volume()
            .remove_consumed_inputs(&consumed_inputs)?;
        Ok(stats)
    }

    /// `Flush` arrives.  The current WAL has already been fsynced
    /// by the caller; here we decide whether the reply can go out
    /// immediately or must wait for an in-flight promote's old-WAL
    /// fsync on the worker.
    fn park_or_resolve_flush(&mut self, reply: Sender<io::Result<()>>) {
        if self.pipeline.completed_gen >= self.pipeline.promote_gen {
            let _ = reply.send(Ok(()));
        } else {
            self.pipeline.parked_flushes.push(ParkedFlush {
                needed_gen: self.pipeline.promote_gen,
                reply,
            });
        }
    }

    /// Called after the actor has finished applying a successful
    /// `Promote(Ok(..))` result — extent index CAS'd, old WAL deleted,
    /// snapshot republished.  Pops the FIFO head of
    /// `inflight_old_wals` (matching the worker's dispatch order),
    /// bumps `completed_gen`, and resolves any parked flushes whose
    /// precondition now holds.  The worker already fsynced the old
    /// WAL, so no extra I/O is needed here.  Resolving *after*
    /// `apply_promote` ensures callers of `Flush` observe the
    /// housekeeping state (old WAL deleted, new snapshot published)
    /// and not just the durability barrier.
    fn on_promote_success(&mut self) {
        self.pipeline.inflight_old_wals.pop_front();
        self.pipeline.completed_gen += 1;
        self.resolve_parked_flushes(Ok(()));
    }

    /// Called after each worker-result `Promote(Err(..))`.  The
    /// worker may or may not have fsynced the old WAL before failing,
    /// so we perform a best-effort fallback fsync on the actor thread
    /// to guarantee that `completed_gen` advancing implies durability
    /// of every write that was in the old WAL at dispatch time.
    fn on_promote_failure(&mut self) {
        let outcome = if let Some(path) = self.pipeline.inflight_old_wals.pop_front() {
            match std::fs::File::open(&path).and_then(|f| f.sync_data()) {
                Ok(()) => Ok(()),
                Err(e) => {
                    warn!("fallback fsync of {} failed: {e}", path.display());
                    Err(io::Error::other(format!(
                        "promote failed and fallback WAL fsync failed: {e}"
                    )))
                }
            }
        } else {
            // Shouldn't happen — every dispatch pushes a path — but
            // don't panic in library code.  Treat as "nothing to
            // fsync" which is vacuously durable.
            Ok(())
        };
        self.pipeline.completed_gen += 1;
        self.resolve_parked_flushes(outcome);
    }

    /// Drain `parked_flushes` of any entry whose `needed_gen` is now
    /// satisfied by `completed_gen`, delivering `outcome` to each.
    /// Entries whose `needed_gen` is still in the future stay parked.
    fn resolve_parked_flushes(&mut self, outcome: io::Result<()>) {
        let done = self.pipeline.completed_gen;
        let mut i = 0;
        while i < self.pipeline.parked_flushes.len() {
            if self.pipeline.parked_flushes[i].needed_gen <= done {
                let parked = self.pipeline.parked_flushes.swap_remove(i);
                let reply_outcome = match &outcome {
                    Ok(()) => Ok(()),
                    Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
                };
                let _ = parked.reply.send(reply_outcome);
            } else {
                i += 1;
            }
        }
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

    /// Dispatch a promote job to the worker thread.
    ///
    /// Calls [`Volume::prepare_promote`] to snapshot the WAL state and open
    /// a fresh WAL, then sends the job to the worker.  No-op if the WAL
    /// is empty.  Logs and returns on error.
    fn dispatch_promote(&mut self) {
        self.retry_failed_promote();
        let job = match self.lock_volume().prepare_promote() {
            Ok(Some(job)) => job,
            Ok(None) => return,
            Err(e) => {
                warn!("promote prep failed: {e}");
                return;
            }
        };
        let old_wal_path = job.old_wal_path.clone();
        if let Err(e) = self.send_worker_job(WorkerJob::Promote(job)) {
            warn!("promote dispatch failed: {e}");
            return;
        }
        self.pipeline.promotes_in_flight += 1;
        self.pipeline.promote_gen += 1;
        self.pipeline.inflight_old_wals.push_back(old_wal_path);
    }

    /// Re-dispatch the oldest stashed failed promote, if any. Returns
    /// the job's segment ULID when a retry was dispatched. One job per
    /// call — a job that fails again lands back on the queue, so retries
    /// pace themselves to the promote triggers rather than spinning.
    fn retry_failed_promote(&mut self) -> Option<Ulid> {
        let job = self.pipeline.failed_promotes.pop_front()?;
        let ulid = job.segment_ulid;
        let old_wal_path = job.old_wal_path.clone();
        if let Err(e) = self.send_worker_job(WorkerJob::Promote(*job)) {
            warn!("failed-promote retry dispatch failed: {e}");
            return None;
        }
        self.pipeline.promotes_in_flight += 1;
        self.pipeline.promote_gen += 1;
        self.pipeline.inflight_old_wals.push_back(old_wal_path);
        Some(ulid)
    }

    /// Run the GC checkpoint prep and dispatch the promote to the worker.
    ///
    /// Mints ULIDs, opens the fresh WAL immediately (writes resume),
    /// and dispatches the GC promote.  If the WAL is empty, completes
    /// immediately.  The reply is parked until `PromoteComplete` for
    /// `u_flush` arrives so that `pending/<u_flush>` is on disk before
    /// the coordinator runs `gc_fork`.
    fn start_gc_checkpoint(
        &mut self,
        max_buckets: usize,
        reply: Sender<io::Result<crate::volume_ipc::GcCheckpointReply>>,
    ) {
        self.retry_failed_promote();
        let prep = match self.lock_volume().prepare_gc_checkpoint(max_buckets) {
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
            self.pipeline.parked_gc = Some(ParkedGcCheckpoint {
                u_buckets,
                u_flush,
                reply,
            });
            let old_wal_path = job.old_wal_path.clone();
            if let Err(e) = self.send_worker_job(WorkerJob::Promote(job)) {
                warn!("gc_checkpoint promote dispatch failed: {e}");
                if let Some(parked) = self.pipeline.parked_gc.take() {
                    let _ = parked.reply.send(Err(e));
                }
                return;
            }
            self.pipeline.promotes_in_flight += 1;
            self.pipeline.promote_gen += 1;
            self.pipeline.inflight_old_wals.push_back(old_wal_path);
        } else {
            // WAL was empty — fresh WAL already opened by prepare_gc_checkpoint.
            self.publish_snapshot();
            let own_segments = Some(self.lock_volume().own_segments_commitment());
            let _ = reply.send(Ok(crate::volume_ipc::GcCheckpointReply {
                bucket_ulids: u_buckets,
                own_segments,
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

        let (to_process, already_applied) = match self.lock_volume().scan_plan_handoffs() {
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
    /// remaining entry was skipped (`prepare_plan_apply` returned `None`)
    /// or a fatal error fired the reply — and the caller must drop `parked`.
    ///
    /// Skips entries whose `prepare_plan_apply` rejects them (parse failure,
    /// ULID mismatch, empty inputs) — those plans were already removed
    /// inside `prepare_plan_apply`, so the batch continues with the next.
    fn dispatch_next_handoff(&mut self, parked: &mut ParkedGcHandoffs) -> HandoffDispatch {
        while let Some((plan_path, new_ulid)) = parked.remaining.pop() {
            let job = match self.lock_volume().prepare_plan_apply(plan_path, new_ulid) {
                Ok(Some(job)) => job,
                Ok(None) => continue,
                Err(e) => {
                    warn!("gc plan prepare failed for {new_ulid}: {e}");
                    if let Some(reply) = parked.reply.take() {
                        let _ = reply.send(Err(e));
                    }
                    return HandoffDispatch::Finished;
                }
            };
            if let Err(e) = self.send_worker_job(WorkerJob::GcPlan(job)) {
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

    /// Run the repack prep on the actor and dispatch the heavy middle
    /// to the worker.  Reply is parked until
    /// [`crate::volume::RepackResult`] arrives and is applied.
    fn start_repack(&mut self, reply: Sender<io::Result<CompactionStats>>) {
        let job = match self.lock_volume().prepare_repack() {
            Ok(Some(j)) => j,
            Ok(None) => {
                let _ = reply.send(Ok(CompactionStats::default()));
                return;
            }
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        // `prepare_repack` flushes the WAL before pre-minting output
        // ULIDs (mirrors `start_sweep`). The flush
        // mutates the extent index and may delete the old WAL file —
        // republish so readers don't resolve hashes through the
        // pre-flush snapshot into a deleted WAL.
        self.publish_snapshot();
        if let Err(e) = self.send_worker_job(WorkerJob::Repack(job)) {
            warn!("repack dispatch failed: {e}");
            let _ = reply.send(Err(e));
            return;
        }
        self.parked.repack = Some(reply);
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
        let job = match self.lock_volume().prepare_reclaim(start_lba, lba_length) {
            Ok(j) => j,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        // `prepare_reclaim` flushes the WAL before minting the reclaim
        // output ULID (see the `u_flush < u_reclaim` invariant on
        // `Volume::prepare_reclaim`). That mutates the extent index
        // (WAL-relative offsets → segment-relative) and deletes the old
        // WAL file. Republish so readers don't resolve hashes through
        // the pre-flush snapshot into a deleted WAL.
        self.publish_snapshot();
        if let Err(e) = self.send_worker_job(WorkerJob::Reclaim(job)) {
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
            .lock_volume()
            .prepare_sign_snapshot_manifest_kind(snap_ulid, kind);
        if let Err(e) = self.send_worker_job(WorkerJob::SignSnapshotManifest(job)) {
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
    fn send_worker_job(&mut self, job: WorkerJob) -> io::Result<()> {
        let Some(tx) = self.worker_tx.clone() else {
            return Err(io::Error::other("worker not running"));
        };
        let mut job = job;
        loop {
            match tx.try_send(job) {
                Ok(()) => return Ok(()),
                Err(crossbeam_channel::TrySendError::Full(j)) => {
                    job = j;
                    match self.worker_rx.recv() {
                        Ok(result) => self.handle_worker_result(result),
                        Err(_) => {
                            return Err(io::Error::other("worker result channel closed"));
                        }
                    }
                }
                Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                    return Err(io::Error::other("worker channel closed"));
                }
            }
        }
    }

    /// Whether any worker job is dispatched but not yet resolved.
    fn work_in_flight(&self) -> bool {
        self.pipeline.promotes_in_flight > 0
            || self.pipeline.promote_segments_in_flight > 0
            || self.parked.handoff_in_flight
            || self.parked.repack.is_some()
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
                let apply = self.lock_volume().apply_promote(&result);
                if let Err(e) = &apply {
                    // The segment is committed and the old WAL was kept, so
                    // reads stay resolvable; the in-memory maps are missing
                    // this apply. Parked repliers get the error so the
                    // coordinator aborts its tick.
                    error!("apply of promoted segment {ulid} failed: {e}");
                }
                self.publish_snapshot();
                // Resolve parked flushes only after apply + publish
                // so the caller observes the old WAL deleted and the
                // new snapshot visible — not just the durability barrier.
                self.on_promote_success();

                let clone_apply = |apply: &io::Result<()>| match apply {
                    Ok(()) => Ok(()),
                    Err(e) => Err(io::Error::new(e.kind(), e.to_string())),
                };
                // Complete any parked operations waiting for this ULID.
                // GC checkpoint.
                if let Some(parked) = self.pipeline.parked_gc.take_if(|p| ulid == p.u_flush) {
                    let own_segments = Some(self.lock_volume().own_segments_commitment());
                    let _ = parked.reply.send(clone_apply(&apply).map(|()| {
                        crate::volume_ipc::GcCheckpointReply {
                            bucket_ulids: parked.u_buckets,
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
                self.on_promote_failure();
                // Fail parked repliers waiting on this ULID promptly —
                // the coordinator retries on its next tick, and by then
                // `retry_failed_promote` will have re-dispatched the job.
                let clone_err = |e: &io::Error| io::Error::new(e.kind(), e.to_string());
                if let Some(parked) = self.pipeline.parked_gc.take_if(|p| ulid == p.u_flush) {
                    let _ = parked.reply.send(Err(clone_err(&failure.error)));
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
                self.parked.handoff_in_flight = false;
                let applied = self.lock_volume().apply_plan_apply_result(result);
                match applied {
                    Ok(crate::volume::StagedApply::Applied) => {
                        self.publish_snapshot();
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
                        let apply_result = self.lock_volume().apply_promote_segment_result(r);
                        if apply_result.is_ok() {
                            self.publish_snapshot();
                        }
                        self.reply_parked_promote_segment(ulid, apply_result);
                    }
                    Err(e) => {
                        warn!("worker promote_segment for {ulid} failed: {e}");
                        self.reply_parked_promote_segment(ulid, Err(e));
                    }
                }
            }
            WorkerResult::Repack(result) => {
                let reply = self.parked.repack.take();
                let outcome = match result {
                    Ok(r) => self.apply_repack_and_publish(r),
                    Err(e) => {
                        warn!("worker repack failed: {e}");
                        Err(e)
                    }
                };
                if let Some(reply) = reply {
                    let _ = reply.send(outcome);
                }
            }
            WorkerResult::SignSnapshotManifest(result) => {
                let reply = self.parked.sign_snapshot_manifest.take();
                let outcome = match result {
                    Ok(r) => {
                        self.lock_volume().apply_sign_snapshot_manifest_result(r);
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
                        let apply_result = self.lock_volume().apply_reclaim_result(r);
                        if matches!(&apply_result, Ok(o) if !o.discarded && o.runs_rewritten > 0) {
                            self.publish_snapshot();
                        }
                        apply_result
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

    pub fn run(mut self) {
        let idle_tick = tick(IDLE_FLUSH_INTERVAL);
        loop {
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
                            if self.lock_volume().needs_promote() {
                                self.dispatch_promote();
                            }
                        }
                        VolumeRequest::Flush { reply } => {
                            // Flush = WAL fsync + wait for any in-flight
                            // promote's old-WAL fsync to complete on the
                            // worker.  The actor stays on the select loop
                            // during the wait — new writes continue to flow
                            // onto the fresh WAL, matching how a real block
                            // device keeps accepting commands while a FLUSH
                            // is in flight at the controller.
                            let fsync_result = self.lock_volume().wal_fsync();
                            match fsync_result {
                                Ok(()) => self.park_or_resolve_flush(reply),
                                Err(e) => {
                                    let _ = reply.send(Err(e));
                                }
                            }
                        }
                        VolumeRequest::PromoteWal { reply } => {
                            // Promote the WAL to a pending/ segment via the
                            // worker.  Reply once the segment is on disk.
                            let retried = self.retry_failed_promote();
                            let prep = self.lock_volume().prepare_promote();
                            match prep {
                                Ok(Some(job)) => {
                                    let ulid = job.segment_ulid;
                                    let old_wal_path = job.old_wal_path.clone();
                                    match self.send_worker_job(WorkerJob::Promote(job)) {
                                        Ok(()) => {
                                            self.pipeline.promotes_in_flight += 1;
                                            self.pipeline.promote_gen += 1;
                                            self.pipeline.inflight_old_wals.push_back(old_wal_path);
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
                        VolumeRequest::Repack { reply } => {
                            if self.parked.repack.is_some() {
                                let _ = reply
                                    .send(Err(io::Error::other("concurrent repack not allowed")));
                            } else {
                                self.start_repack(reply);
                            }
                        }
                        VolumeRequest::ApplyGcHandoffs { reply } => {
                            self.start_gc_handoffs(Some(reply));
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
                            let prep = self.lock_volume().prepare_promote_segment(ulid);
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
                                        Err(e) => {
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
                            let _ = reply.send(self.lock_volume().finalize_gc_handoff(ulid));
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
                            let _ = reply.send(self.lock_volume().noop_stats());
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
                            if let Err(e) = self.send_worker_job(WorkerJob::Barrier(hold)) {
                                warn!("test barrier dispatch failed: {e}");
                            }
                        }
                        #[cfg(test)]
                        VolumeRequest::TestParkThenDispatchBarriers { park, holds } => {
                            let _ = park.recv();
                            for hold in holds {
                                if let Err(e) = self.send_worker_job(WorkerJob::Barrier(hold)) {
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
}

/// Per-thread reader for a volume session.
///
/// Owns the file-descriptor cache for segment bodies and the generation
/// counter used to evict that cache when the extent index changes. `Send`
/// but `!Sync` — each thread serving reads constructs its own reader via
/// [`VolumeClient::reader`].
///
/// Derefs to [`VolumeClient`], so a reader can also issue writes, flushes,
/// and other control operations without requiring a separate client
/// reference.
pub struct VolumeReader {
    client: VolumeClient,
    /// Per-reader LRU cache of open segment file handles. Never contended:
    /// each transport thread holds its own reader. `RefCell` is sufficient;
    /// `Mutex` is not needed.
    file_cache: RefCell<FileCache>,
    /// Per-reader cache of opened `cache/<ULID>.dmat` sidecars. Cleared
    /// alongside `file_cache` whenever the snapshot's `flush_gen` changes,
    /// so an eviction that drops `.dmat` from disk can't leave a stale FD
    /// pointing at a removed inode.
    dmat_cache: crate::volume::DmatCache,
    /// Telemetry counters for the dmat cache. Per-reader; aggregate by
    /// summing snapshots across readers if needed.
    dmat_stats: Arc<crate::dmat::DmatStats>,
    /// Generation of the last snapshot whose extent index offsets were used
    /// to populate `file_cache`. Compared against `ReadSnapshot::flush_gen`
    /// on every read; if they differ the cache is evicted before proceeding.
    /// Reading both the generation and the extent index from the same
    /// snapshot load means the two are always in sync — no separate atomic
    /// needed.
    last_flush_gen: Cell<u64>,
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
        let current_gen = self.snapshot.load().flush_gen;
        VolumeReader {
            client: self.clone(),
            file_cache: RefCell::new(FileCache::default()),
            dmat_cache: RefCell::new(std::collections::HashMap::new()),
            dmat_stats: Arc::new(crate::dmat::DmatStats::default()),
            last_flush_gen: Cell::new(current_gen),
        }
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
    /// `fua` fsyncs the WAL inside the same critical section as the
    /// append, so a concurrent promote can't rotate the WAL between the
    /// two — the write is durable when this returns.
    pub fn write(&self, lba: u64, data: &[u8], fua: bool) -> io::Result<()> {
        let hash = blake3::hash(data);
        let compressed = crate::volume::maybe_compress(data);
        let volume = self.volume()?;
        let needs_promote = {
            let mut guard = lock_volume(&volume);
            guard.write_precomputed(lba, data, hash, compressed.as_deref())?;
            publish_snapshot(&guard, &self.snapshot, &self.flush_gen);
            if fua {
                guard.wal_fsync()?;
            }
            guard.needs_promote()
        };
        if needs_promote {
            self.signal_check_promote();
        }
        Ok(())
    }

    /// Zero `lba_count` blocks starting at `lba`.  Direct path — see
    /// [`VolumeClient::write`] for the lock/snapshot/signal pattern.
    /// Writes a single zero-extent WAL record — no hashing, no data payload.
    /// See [`Volume::write_zeroes`] for details.
    pub fn write_zeroes(&self, start_lba: u64, lba_count: u32, fua: bool) -> io::Result<()> {
        let volume = self.volume()?;
        let needs_promote = {
            let mut guard = lock_volume(&volume);
            guard.write_zeroes(start_lba, lba_count)?;
            publish_snapshot(&guard, &self.snapshot, &self.flush_gen);
            if fua {
                guard.wal_fsync()?;
            }
            guard.needs_promote()
        };
        if needs_promote {
            self.signal_check_promote();
        }
        Ok(())
    }

    /// Trim (discard) `lba_count` blocks starting at `lba`.
    pub fn trim(&self, start_lba: u64, lba_count: u32, fua: bool) -> io::Result<()> {
        self.write_zeroes(start_lba, lba_count, fua)
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

    /// Fsync the WAL.  Durability barrier — data survives a crash after
    /// this returns.  Does not promote the WAL to a segment.
    pub fn flush(&self) -> io::Result<()> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::Flush { reply: reply_tx })
            .map_err(|_| io::Error::other("volume actor channel closed"))?;
        reply_rx
            .recv()
            .map_err(|_| io::Error::other("volume actor reply channel closed"))?
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

    /// Rewrite every pending segment with any hash-dead body bytes.
    /// Blocks until the actor replies.
    pub fn repack(&self) -> io::Result<CompactionStats> {
        let (reply_tx, reply_rx) = bounded(1);
        self.tx
            .send(VolumeRequest::Repack { reply: reply_tx })
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
        let snap = self.snapshot.load();
        scan_reclaim_candidates(&snap.lbamap, &snap.extent_index, thresholds)
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
        if snap.flush_gen != self.last_flush_gen.get() {
            self.file_cache.borrow_mut().clear();
            self.dmat_cache.borrow_mut().clear();
            self.last_flush_gen.set(snap.flush_gen);
        }
        let config = &self.client.config;
        let extent_index = &snap.extent_index;
        read_extents(
            lba,
            buf,
            &snap.lbamap,
            extent_index,
            &self.file_cache,
            &self.dmat_cache,
            &self.dmat_stats,
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
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

/// Long-lived worker thread that processes off-actor jobs (WAL promotes,
/// GC handoff re-signs, etc.).
///
/// Receives jobs via `job_rx`, executes each, and sends the result back on
/// `result_tx`.  Exits when `job_rx` disconnects (actor dropped the sender)
/// or `result_tx` disconnects (actor gone).
fn worker_thread(job_rx: Receiver<WorkerJob>, result_tx: Sender<WorkerResult>) {
    let mut prior_cache = PriorSourceCache::default();
    while let Ok(job) = job_rx.recv() {
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
            WorkerJob::Repack(job) => WorkerResult::Repack(execute_repack(job)),
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
    for input_ulid in &inputs {
        let idx_path = index_dir.join(format!("{input_ulid}.idx"));
        let parsed = match segment::read_segment_index(&idx_path) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e),
        };
        let (_, old_entries, _) = parsed;
        for e in &old_entries {
            if e.kind.owns_extent_hash() {
                input_old_entries.push((e.hash, e.kind, *input_ulid));
            }
        }
    }

    // Write the signed output segment to <ulid>.tmp. The actor renames it
    // to bare <ulid> as the commit point.
    let tmp_path = gc_dir.join(format!("{new_ulid}.tmp"));
    segment::write_segment_full(&tmp_path, entries, &delta_body, &inputs, signer.as_ref())?;

    let (new_bss, written_entries, _) =
        segment::read_and_verify_segment_index(&tmp_path, &verifying_key)?;
    let handoff_inline = segment::read_inline_section(&tmp_path)?;

    Ok(GcPlanApplyResult {
        new_ulid,
        plan_path,
        gc_dir,
        tmp_path: Some(tmp_path),
        new_bss,
        entries: written_entries,
        inputs,
        input_old_entries,
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
    job: PromoteJob,
    prior_cache: &mut PriorSourceCache,
) -> Result<PromoteResult, PromoteFailure> {
    fn fail(error: io::Error, job: PromoteJob) -> PromoteFailure {
        PromoteFailure {
            error,
            job: Box::new(job),
        }
    }

    if let Err(e) = std::fs::File::open(&job.old_wal_path).and_then(|f| f.sync_data()) {
        return Err(fail(e, job));
    }

    // Body bytes for entries written via `write_commit` live only in the
    // WAL between commit and promote. Pair them with their WAL bytes via
    // `body_offsets` for write_and_commit to consume.
    let mut pendings = match crate::volume::materialise_pending_bodies(
        &job.old_wal_path,
        &job.entries,
        &job.body_offsets,
    ) {
        Ok(p) => p,
        Err(e) => return Err(fail(e, job)),
    };

    // Delta tier: convert single-block Data entries whose same-LBA prior
    // extent beats the stored size as a zstd dictionary. Best-effort on
    // map construction (a promote must not fail because the delta
    // optimisation's source map broke); conversion errors are real
    // corruption and fail the promote.
    let mut delta_body: Vec<u8> = Vec::new();
    if let Some(prior_spec) = &job.delta_prior {
        match prior_cache.map_for(
            &prior_spec.base_dir,
            prior_spec.snap_ulid,
            &prior_spec.journal_ranges,
        ) {
            Ok(prior) => {
                match crate::delta_compute::delta_pendings_against_prior(
                    &mut pendings,
                    prior,
                    &prior_spec.extent_index,
                    &prior_spec.search_dirs,
                ) {
                    Ok((body, stats)) => {
                        if stats.entries_converted > 0 {
                            log::info!(
                                "formation {}: {} delta entries vs snapshot {}, {} → {} bytes",
                                job.segment_ulid,
                                stats.entries_converted,
                                prior_spec.snap_ulid,
                                stats.original_body_bytes,
                                stats.delta_body_bytes,
                            );
                        }
                        delta_body = body;
                    }
                    Err(e) => return Err(fail(e, job)),
                }
            }
            Err(e) => {
                warn!(
                    "formation {}: snapshot {} source map unavailable, skipping delta tier: {e}",
                    job.segment_ulid, prior_spec.snap_ulid
                );
            }
        }
    }

    // An all-journal epoch leaves the primary partition empty; no
    // primary segment file is written, and the result carries the
    // primary ULID with no entries (parked-reply matching keys on it).
    let (body_section_start, entries) = if pendings.is_empty() {
        (0, Vec::new())
    } else {
        match segment::write_and_commit(
            &job.pending_dir,
            job.segment_ulid,
            pendings,
            &delta_body,
            job.signer.as_ref(),
        ) {
            Ok(v) => v,
            Err(e) => return Err(fail(e, job)),
        }
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
    let journal = match &job.journal {
        None => None,
        Some(jpart) => {
            let j_pendings = match crate::volume::materialise_pending_bodies(
                &job.old_wal_path,
                &jpart.entries,
                &jpart.body_offsets,
            ) {
                Ok(p) => p,
                Err(e) => return Err(fail(e, job)),
            };
            match segment::write_and_commit(
                &job.pending_dir,
                jpart.segment_ulid,
                j_pendings,
                &[],
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
                        pre_promote_offsets: jpart.pre_promote_offsets.clone(),
                    })
                }
                Err(e) => return Err(fail(e, job)),
            }
        }
    };

    Ok(PromoteResult {
        segment_ulid: job.segment_ulid,
        old_wal_ulid: job.old_wal_ulid,
        old_wal_path: job.old_wal_path,
        body_section_start,
        entries,
        pre_promote_offsets: job.pre_promote_offsets,
        delta_region_body_length,
        journal,
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

/// Target output segment size for repack, in live bytes. Matches the
/// WAL `FLUSH_THRESHOLD` so repack outputs sit at the same scale as
/// freshly-flushed segments.
const REPACK_TARGET_LIVE: u64 = 32 * 1024 * 1024;

/// Entry-count cap on a packed output. Mirrors the WAL's
/// `FLUSH_ENTRY_THRESHOLD` so packed outputs sit at the same scale as
/// freshly-flushed segments and the index region stays bounded.
const REPACK_ENTRY_CAP: usize = 8192;

/// Remove any stale promote siblings (`index/<u>.idx`, `cache/<u>.body`,
/// `cache/<u>.present`, `cache/<u>.delta`) that a crashed half-promote may
/// have left alongside a pending segment whose body is about to be
/// rewritten.
///
/// Called by `execute_repack` before rewriting or deleting a pending
/// segment, and by `execute_promote_segment` as a no-op (siblings don't
/// normally coexist with a committed pending segment). Each file is
/// removed best-effort — `NotFound` is not an error.
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
    /// Parsed segment index, shared with the segment-index cache.
    parsed: Arc<crate::segment_cache::ParsedIndex>,
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
    /// `true` when every classification is `FullyLive` — a single-input
    /// bucket of one of these is a no-op rewrite and is skipped.
    all_live: bool,
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
pub(crate) fn execute_repack(job: RepackJob) -> io::Result<RepackResult> {
    use crate::rewrite_apply::{self, MaterialiseCtx, MaterialiseOutcome, Materialised};
    use crate::rewrite_plan::{PlanOutput, RewritePlan};
    use crate::segment_classify::{self, ClassifyCtx, EntryClassification};

    let RepackJob {
        base_dir,
        pending_dir,
        floor,
        ceiling,
        output_ulids,
        lbamap_snapshot,
        extent_index_snapshot,
        ancestor_layers,
        fetcher,
        signer,
        verifying_key,
        segment_cache,
    } = job;

    let seg_paths = segment::collect_segment_files(&pending_dir)?;
    let live_hashes = lbamap_snapshot.lba_referenced_hashes();
    let index_dir = base_dir.join("index");
    let cache_dir = base_dir.join("cache");

    let mut stats = CompactionStats::default();

    // Phase 1 — scan: parse + verify every non-floor segment, classify
    // every entry, compute live/dead/entry counts. Skip fully-live
    // segments larger than the small threshold (no rewrite, no peer to
    // pack with).
    //
    // Two ULID gates filter the candidate set:
    //   - `floor` (snapshot floor) excludes segments frozen by the
    //     latest snapshot.
    //   - `ceiling` (= prep-time `u_flush`) excludes segments minted
    //     after prep — those exist on disk but the prep-time
    //     `lbamap_snapshot` knows nothing about their entries, so the
    //     classifier would call them all dead and the apply would
    //     delete the files plus clobber any lbamap claims they made.
    //     See `docs/finding-cargo-build-stale-read.md`.
    let mut candidates: Vec<RepackCandidate> = Vec::new();
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
        if seg_ulid > ceiling {
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

        let classify_ctx = ClassifyCtx {
            lba_map: &lbamap_snapshot,
            extent_index: &extent_index_snapshot,
            live_hashes: &live_hashes,
            segment_id: seg_ulid,
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

        candidates.push(RepackCandidate {
            seg_path: seg_path.clone(),
            seg_ulid,
            parsed,
            classifications,
            live_bytes,
            dead_bytes,
            live_entry_count,
            owned_hashes,
            all_live,
        });
    }

    // Phase 2 — bin-pack: first-fit-decreasing into buckets sized to
    // (REPACK_TARGET_LIVE, REPACK_ENTRY_CAP). Sorting by live_bytes
    // descending places the largest candidates in their own buckets
    // first; smaller candidates fill remaining headroom or start fresh
    // buckets.
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

    // Phase 3 — materialise each bucket. A bucket of one fully-live
    // candidate is a byte-identical no-op; skip it.
    let mut result_buckets: Vec<crate::volume::RepackedBucket> = Vec::new();
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
            for (entry_idx, (_entry, action)) in c
                .parsed
                .entries
                .iter()
                .zip(c.classifications.iter())
                .enumerate()
            {
                let entry_idx = entry_idx as u32;
                match action {
                    EntryClassification::FullyLive => outputs.push(PlanOutput::Keep {
                        input: c.seg_ulid,
                        entry_idx,
                    }),
                    EntryClassification::DemoteToCanonical => outputs.push(PlanOutput::Canonical {
                        input: c.seg_ulid,
                        entry_idx,
                    }),
                    EntryClassification::ZeroSubRuns(runs) => {
                        for run in runs {
                            outputs.push(PlanOutput::ZeroSplit {
                                input: c.seg_ulid,
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
                                input: c.seg_ulid,
                                entry_idx,
                            });
                        }
                        for run in live_runs.iter() {
                            outputs.push(PlanOutput::Run {
                                input: c.seg_ulid,
                                entry_idx,
                                payload_block_offset: run.payload_block_offset,
                                start_lba: run.range_start,
                                lba_length: (run.range_end - run.range_start) as u32,
                            });
                        }
                    }
                    EntryClassification::DeferUnresolvableDelta => outputs.push(PlanOutput::Keep {
                        input: c.seg_ulid,
                        entry_idx,
                    }),
                    EntryClassification::DropAndRemoveHash | EntryClassification::Drop => {}
                }
            }
            let c = &mut candidates[i];
            bucket_inputs.push(crate::volume::RepackedInput {
                input_ulid: c.seg_ulid,
                input_path: std::mem::take(&mut c.seg_path),
                owned_hashes: std::mem::take(&mut c.owned_hashes),
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
        let ctx = match MaterialiseCtx::new_for_pending(
            &base_dir,
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
        let materialised = match rewrite_apply::materialise_plan(&plan, &ctx) {
            Ok(m) => m,
            Err(MaterialiseOutcome::Io(e)) => return Err(e),
            Err(MaterialiseOutcome::Cancel(e)) => {
                return Err(io::Error::other(format!(
                    "repack {new_ulid}: materialise cancelled: {e}"
                )));
            }
        };
        drop(ctx);

        let Materialised {
            entries: out_entries,
            delta_body,
        } = materialised;

        let new_ulid_str = new_ulid.to_string();
        let final_path = pending_dir.join(&new_ulid_str);
        let tmp_path = pending_dir.join(format!("{new_ulid_str}.tmp"));
        let _ = std::fs::remove_file(&tmp_path);
        let (new_body_section_start, out_entries) =
            segment::write_segment_full(&tmp_path, out_entries, &delta_body, &[], signer.as_ref())?;
        std::fs::rename(&tmp_path, &final_path)?;
        segment::fsync_dir(&final_path)?;
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
        });
    }

    Ok(RepackResult {
        stats,
        buckets: result_buckets,
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
/// 1. Build `live_hashes` — the union of `lbamap.lba_referenced_hashes()`
///    with every live `Delta`'s `source_hash`. A body whose hash is not
///    in this set has nothing reading it, even if the extent index still
///    points at it.
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

    // Pass 1: live_hashes = LBA-referenced hashes ∪ live-delta source hashes.
    //
    // A `Delta` entry is live when some LBA in its range still maps to
    // `entry.hash`; a claim-less `CanonicalDelta` is live when its hash is
    // LBA-referenced through a DedupRef. Either way its `source_hash` body
    // is needed to reconstruct the delta, so the source must be carried
    // into `live_hashes` even if no LBA references the source directly.
    let mut live_hashes: std::collections::HashSet<blake3::Hash> = lbamap.lba_referenced_hashes();
    for (_seg_ulid, parsed) in &parsed_segments {
        for entry in &parsed.entries {
            if !entry.kind.is_delta() {
                continue;
            }
            let live = if entry.kind.is_canonical_only() {
                live_hashes.contains(&entry.hash)
            } else {
                let end = entry.start_lba + entry.lba_length as u64;
                lbamap
                    .extents_in_range(entry.start_lba, end)
                    .any(|r| r.hash == entry.hash)
            };
            if !live {
                continue;
            }
            for opt in &entry.delta_options {
                live_hashes.insert(opt.source_hash);
            }
        }
    }

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
    live_hashes: &std::collections::HashSet<blake3::Hash>,
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
    let (lbamap, extent_index) = volume.snapshot_maps();
    let initial = Arc::new(ReadSnapshot {
        lbamap,
        extent_index,
        flush_gen: 0,
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

    // Channel depth of 64: enough to absorb bursts without blocking callers
    // while still providing backpressure if the actor falls behind.
    let (tx, rx) = bounded(64);

    // Worker channels: job channel bounded at 4, result channel matched.
    let (worker_job_tx, worker_job_rx) = bounded::<WorkerJob>(4);
    let (worker_result_tx, worker_result_rx) = bounded::<WorkerResult>(4);
    let worker_handle = std::thread::Builder::new()
        .name("volume-worker".into())
        .spawn(move || worker_thread(worker_job_rx, worker_result_tx))
        .expect("failed to spawn worker thread");

    let actor = VolumeActor {
        volume: Arc::clone(&volume),
        snapshot: Arc::clone(&snapshot),
        rx,
        flush_gen: Arc::clone(&flush_gen),
        worker_tx: Some(worker_job_tx),
        worker_rx: worker_result_rx,
        worker_handle: Some(worker_handle),
        divergence_exit: None,
        pipeline: PromotePipeline::default(),
        parked: ParkedOps::default(),
    };

    let client = VolumeClient {
        tx,
        snapshot,
        config,
        volume: Arc::downgrade(&volume),
        flush_gen,
    };

    (actor, client)
}

// ---------------------------------------------------------------------------
// Reclaim worker execution
// ---------------------------------------------------------------------------

/// zstd level for re-delta'd reclaim outputs. Mirrors the import-time
/// `delta_compute::ZSTD_LEVEL`; reclaim runs off-actor and the blob is
/// fetched infrequently, so a middling level keeps compression time
/// bounded without sacrificing ratio.
const RECLAIM_ZSTD_LEVEL: i32 = 3;

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
        return if loc.compressed {
            lz4_flex::decompress_size_prepended(idata).map_err(io::Error::other)
        } else {
            Ok(idata.to_vec())
        };
    }
    let mut found = None;
    for dir in search_dirs {
        if let Some(hit) = segment::locate_segment_body(dir, loc.segment_id) {
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
    if loc.compressed {
        lz4_flex::decompress_size_prepended(&buf).map_err(io::Error::other)
    } else {
        Ok(buf)
    }
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

    for er in &job.entries {
        if er.hash == crate::volume::ZERO_HASH {
            continue;
        }
        let should_rewrite = *decision.entry(er.hash).or_insert_with(|| {
            let runs = job.lbamap_snapshot.runs_for_hash(&er.hash);
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
            let logical_blocks = match job.extent_index_snapshot.lookup(&er.hash) {
                Some(loc) if loc.inline_data.is_none() && !loc.compressed => {
                    // Uncompressed Data: body_length is the exact logical
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
                let fetched = read_reclaim_extent_body(
                    &job.extent_index_snapshot,
                    &job.search_dirs,
                    &er.hash,
                )?;
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
                if job.extent_index_snapshot.lookup(&new_hash).is_some() {
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
                //    pin than delta-source refcount, which dynamically
                //    tracks live Delta LBAs.
                // 2. H is already serving as a delta source for some
                //    other live entry (delta_source_refcount > 0).
                //    `lba_referenced_hashes` keeps H alive as long as
                //    any such Delta remains on the volume.
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
                    job.extent_index_snapshot.lookup(&er.hash),
                ) {
                    (Some(floor), Some(loc)) => loc.segment_id <= floor,
                    _ => false,
                };
                let source_pinned =
                    pre_snapshot_h || job.lbamap_snapshot.delta_source_refcount(&er.hash) > 0;
                if source_pinned {
                    let delta_blob =
                        zstd::bulk::Compressor::with_dictionary(RECLAIM_ZSTD_LEVEL, body)
                            .map_err(|e| {
                                io::Error::other(format!("reclaim zstd compressor init: {e}"))
                            })?
                            .compress(bytes)
                            .map_err(|e| io::Error::other(format!("reclaim zstd compress: {e}")))?;
                    if delta_blob.len() < bytes.len() {
                        let delta_offset = delta_body.len() as u64;
                        let delta_length = delta_blob.len() as u32;
                        let delta_hash = blake3::hash(&delta_blob);
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

                let (stored_body, flags) = match crate::volume::maybe_compress(bytes) {
                    Some(c) => (c, segment::SegmentFlags::COMPRESSED),
                    None => (bytes.to_vec(), segment::SegmentFlags::empty()),
                };
                entries.push(segment::SegmentEntry::new_data(
                    new_hash,
                    er.range_start,
                    length_blocks,
                    flags,
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
                if job.extent_index_snapshot.lookup(&new_hash).is_some() {
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
                let delta_blob =
                    zstd::bulk::Compressor::with_dictionary(RECLAIM_ZSTD_LEVEL, source_plain)
                        .map_err(|e| {
                            io::Error::other(format!("reclaim zstd compressor init: {e}"))
                        })?
                        .compress(bytes)
                        .map_err(|e| io::Error::other(format!("reclaim zstd compress: {e}")))?;
                if delta_blob.len() >= bytes.len() {
                    continue;
                }

                let delta_offset = delta_body.len() as u64;
                let delta_length = delta_blob.len() as u32;
                let delta_hash = blake3::hash(&delta_blob);
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
            lbamap_snapshot: job.lbamap_snapshot,
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
    let (body_section_start, entries) = if delta_body.is_empty() {
        segment::write_segment(&tmp_path, entries, job.signer.as_ref())?
    } else {
        segment::write_segment_with_delta_body(
            &tmp_path,
            entries,
            &delta_body,
            job.signer.as_ref(),
        )?
    };
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
        lbamap_snapshot: job.lbamap_snapshot,
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

    /// A FUA write fsyncs the WAL in the same critical section as the
    /// append: the WAL bytes are on disk when `write` returns, so a
    /// recovery open of the same directory sees the data with no flush
    /// or promote in between.
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

    /// A reader whose snapshot predates a repack must still resolve reads
    /// after the repack unlinks its input segments — the data is live, only
    /// its location changed. Reproduces the 2026-07-11 field EIO ("segment
    /// not found" during the repack swap window).
    #[test]
    fn stale_snapshot_read_survives_repack() {
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

        // A reader's view captured before the repack.
        let stale = client.snapshot.load_full();

        let stats = client.repack().unwrap();
        assert!(
            stats.segments_compacted > 0,
            "setup: repack consumed no segments, race not exercised"
        );

        let reader = client.reader();
        let mut buf = vec![0u8; 4096];
        reader
            .read_with_snapshot(&stale, 0, &mut buf)
            .expect("read of live data through a pre-repack snapshot");
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
}
