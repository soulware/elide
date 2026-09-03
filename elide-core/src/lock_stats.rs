//! Per-site occupancy of the volume mutex.
//!
//! A read resolves off a published snapshot and takes no volume lock; a
//! write takes the volume mutex directly on the ublk queue thread. So
//! every acquisition counted here is time a guest write can spend waiting
//! (`docs/architecture.md` *Concurrency and locking*).
//!
//! Hold time is what blocks a writer, and it is not the same quantity as
//! CPU time: a section that blocks on `fsync_dir` holds the mutex for the
//! whole commit while consuming almost nothing, so per-thread CPU sampling
//! cannot see it.
//!
//! The write path measures the other end of the same story. It records
//! what it waits and leaves what it holds alone, which is why its counters
//! sit apart from the labelled sites. A guest write pays one relaxed
//! increment when the mutex is free, and reads the clock only on the
//! acquisitions that actually blocked.
//!
//! The drain counters measure how long a queue of parked writers takes
//! to clear once the hold releases.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// A labelled acquisition of the volume mutex.
///
/// One variant per site so a report names the operation rather than a
/// line number. Sites that acquire more than once (a prep and an apply
/// either side of a worker job) carry a variant each, since the two hold
/// the lock for unrelated reasons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockSite {
    PublishSnapshot,
    CheckPromote,
    FlushHandle,
    PromotePrep,
    PromoteApply,
    PromoteSegmentPrep,
    PromoteSegmentApply,
    RepackPrep,
    RepackApply,
    RepackUnlink,
    ReapApply,
    ReapUnlink,
    ClosePrep,
    ReclaimPrep,
    ReclaimApply,
    GcCheckpoint,
    GcPlanPrep,
    GcPlanApply,
    GcHandoffFinalize,
    OwnSegments,
    SnapshotPrep,
    SnapshotApply,
    NoopStats,
}

impl LockSite {
    /// Every variant, in report order. Kept beside the enum rather than
    /// derived, so adding a variant without listing it here fails
    /// `all_sites_are_listed_once`.
    pub const ALL: &'static [LockSite] = &[
        LockSite::PublishSnapshot,
        LockSite::CheckPromote,
        LockSite::FlushHandle,
        LockSite::PromotePrep,
        LockSite::PromoteApply,
        LockSite::PromoteSegmentPrep,
        LockSite::PromoteSegmentApply,
        LockSite::RepackPrep,
        LockSite::RepackApply,
        LockSite::RepackUnlink,
        LockSite::ReapApply,
        LockSite::ReapUnlink,
        LockSite::ClosePrep,
        LockSite::ReclaimPrep,
        LockSite::ReclaimApply,
        LockSite::GcCheckpoint,
        LockSite::GcPlanPrep,
        LockSite::GcPlanApply,
        LockSite::GcHandoffFinalize,
        LockSite::OwnSegments,
        LockSite::SnapshotPrep,
        LockSite::SnapshotApply,
        LockSite::NoopStats,
    ];

    pub const COUNT: usize = LockSite::ALL.len();

    /// Position in [`LockStats::sites`].
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Name used in the periodic report.
    pub const fn label(self) -> &'static str {
        match self {
            LockSite::PublishSnapshot => "publish",
            LockSite::CheckPromote => "check-promote",
            LockSite::FlushHandle => "flush-handle",
            LockSite::PromotePrep => "promote-prep",
            LockSite::PromoteApply => "promote-apply",
            LockSite::PromoteSegmentPrep => "promote-segment-prep",
            LockSite::PromoteSegmentApply => "promote-segment-apply",
            LockSite::RepackPrep => "repack-prep",
            LockSite::RepackApply => "repack-apply",
            LockSite::RepackUnlink => "repack-unlink",
            LockSite::ReapApply => "reap-apply",
            LockSite::ReapUnlink => "reap-unlink",
            LockSite::ClosePrep => "close-prep",
            LockSite::ReclaimPrep => "reclaim-prep",
            LockSite::ReclaimApply => "reclaim-apply",
            LockSite::GcCheckpoint => "gc-checkpoint",
            LockSite::GcPlanPrep => "gc-plan-prep",
            LockSite::GcPlanApply => "gc-plan-apply",
            LockSite::GcHandoffFinalize => "gc-handoff-finalize",
            LockSite::OwnSegments => "own-segments",
            LockSite::SnapshotPrep => "snapshot-prep",
            LockSite::SnapshotApply => "snapshot-apply",
            LockSite::NoopStats => "noop-stats",
        }
    }
}

#[derive(Default)]
struct SiteCounters {
    acquisitions: AtomicU64,
    wait_nanos: AtomicU64,
    hold_nanos: AtomicU64,
    /// Longest hold since the last [`LockStats::take_window`], which the
    /// reporter swaps to zero as it reads. A maximum cannot be recovered
    /// by subtraction, so a windowed one has to be reset rather than
    /// differenced.
    window_max_hold_nanos: AtomicU64,
    /// Longest hold since the volume opened, never reset, so a spike
    /// survives the window it happened in.
    peak_hold_nanos: AtomicU64,
    /// Holds of this site that released with writers parked behind them.
    arms: AtomicU64,
    /// Those arms an emptied queue closed out; the drain figures below
    /// cover these.
    drains: AtomicU64,
    /// Writers parked when those holds released.
    drain_queued: AtomicU64,
    /// Writers that parked between release and the queue emptying.
    drain_joined: AtomicU64,
    /// Time those queues took to clear after release.
    drain_nanos: AtomicU64,
    window_max_drain_nanos: AtomicU64,
    peak_drain_nanos: AtomicU64,
}

/// The hold whose queue is still draining.
///
/// One slot, replaced by any hold that releases into a queue while it is
/// outstanding. `arms` against `drains` counts the replacements.
#[derive(Default)]
struct ArmedDrain {
    /// Index into [`LockStats::sites`] of the site that released.
    site: AtomicUsize,
    /// Nanos since [`LockStats::base`] at release, zero when no queue is
    /// outstanding.
    release_nanos: AtomicU64,
    /// Writers parked at that moment.
    queued: AtomicU64,
    /// Writers that have parked since.
    joined: AtomicU64,
}

/// Upper edges of the guest write-wait histogram, in milliseconds. A wait
/// past the last edge lands in an overflow bucket.
const WAIT_BUCKET_EDGES_MS: [u64; 5] = [1, 10, 100, 1_000, 10_000];

/// One bucket per edge, plus the overflow.
const WAIT_BUCKETS: usize = WAIT_BUCKET_EDGES_MS.len() + 1;

/// Which bucket a wait falls in.
/// Frozen depths a write hold is charged to: 0 to 4, and 5 or more.
pub const DEPTH_BUCKETS: usize = 6;

fn depth_bucket(depth: usize) -> usize {
    depth.min(DEPTH_BUCKETS - 1)
}

fn depth_bucket_label(i: usize) -> String {
    if i == DEPTH_BUCKETS - 1 {
        format!("d{i}+")
    } else {
        format!("d{i}")
    }
}

fn wait_bucket(wait: Duration) -> usize {
    let ms = wait.as_millis() as u64;
    WAIT_BUCKET_EDGES_MS
        .iter()
        .position(|edge| ms < *edge)
        .unwrap_or(WAIT_BUCKETS - 1)
}

/// Label for bucket `i`, as the report prints it.
fn wait_bucket_label(i: usize) -> String {
    match i {
        0 => format!("<{}ms", WAIT_BUCKET_EDGES_MS[0]),
        i if i < WAIT_BUCKETS - 1 => format!("<{}ms", WAIT_BUCKET_EDGES_MS[i]),
        _ => format!(
            ">={}ms",
            WAIT_BUCKET_EDGES_MS[WAIT_BUCKET_EDGES_MS.len() - 1]
        ),
    }
}

/// The guest write path's acquisitions, kept apart from the labelled
/// sites because a different quantity is measured.
///
/// A write is ranked by what it waited rather than what it held: the
/// waits are what the guest sees. The hold is summed and its window
/// maximum kept, which is what sizes the cost of yielding an actor loop
/// to the queue standing behind it.
#[derive(Default)]
struct WriteCounters {
    acquisitions: AtomicU64,
    /// How many of those acquisitions found the mutex taken. The rest
    /// went straight through, so this is the fraction of guest writes an
    /// actor-side section was in a position to delay.
    blocked: AtomicU64,
    wait_nanos: AtomicU64,
    window_max_wait_nanos: AtomicU64,
    peak_wait_nanos: AtomicU64,
    /// What the guest held across all of those acquisitions. This is what
    /// an actor loop pays to let the queue through between two units of
    /// its own work.
    hold_nanos: AtomicU64,
    window_max_hold_nanos: AtomicU64,
    /// Writes parked on the mutex right now.
    waiting: AtomicU64,
    /// Deepest that queue got. Its ceiling is the number of threads that
    /// can be inside a write at once, so a `queued` figure sitting at
    /// this high-water mark is a bound on the measurement rather than a
    /// property of the hold.
    window_max_waiting: AtomicU64,
    peak_waiting: AtomicU64,
    /// Distribution of the waits, by [`wait_bucket`].
    wait_buckets: [AtomicU64; WAIT_BUCKETS],
    /// The holds by the frozen depth the write ran under, by
    /// [`depth_bucket`]. Each layer adds one descent to every lookup the
    /// write makes, so the per-depth means give the cost of a layer.
    by_depth: [HoldCounters; DEPTH_BUCKETS],
    window_max_depth: AtomicU64,
    peak_depth: AtomicU64,
    /// The hold split into the WAL file calls and the rest, which is the
    /// map commit and the snapshot publish, so a long hold reads as one
    /// or the other.
    wal_nanos: AtomicU64,
    window_max_wal_nanos: AtomicU64,
    map_nanos: AtomicU64,
    window_max_map_nanos: AtomicU64,
    /// The WAL time by what was in flight at the append, by
    /// [`append_bucket`], so a long append reads as blocked behind a sync,
    /// behind the worker's disk traffic, or behind neither.
    by_append: [HoldCounters; APPEND_BUCKETS],
}

/// The write holds charged to one bucket: a frozen depth, or what was in
/// flight at the append.
#[derive(Default)]
struct HoldCounters {
    writes: AtomicU64,
    hold_nanos: AtomicU64,
    window_max_hold_nanos: AtomicU64,
}

/// What was in flight when a write began its WAL append: a sync on the
/// WAL inode, a worker job, both, or neither.
pub const APPEND_BUCKETS: usize = 4;

const APPEND_BUCKET_LABELS: [&str; APPEND_BUCKETS] = ["idle", "sync", "worker", "both"];

fn append_bucket(context: AppendContext) -> usize {
    (context.sync_in_flight as usize) | ((context.worker_running as usize) << 1)
}

/// What a write found in flight when it took the mutex, read through
/// [`LockStats::append_context`] and charged with its WAL time.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AppendContext {
    pub sync_in_flight: bool,
    pub worker_running: bool,
}

/// One sync or worker job in flight, counted while this is held.
pub struct InFlight<'a>(&'a AtomicU64);

impl<'a> InFlight<'a> {
    fn new(count: &'a AtomicU64) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count)
    }
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Counters for every labelled acquisition of one volume's mutex.
///
/// Shared between the actor and any handle that reports them, so the
/// counters are atomics rather than a locked struct — taking a lock to
/// record lock occupancy would defeat the measurement.
pub struct LockStats {
    sites: [SiteCounters; LockSite::COUNT],
    writes: WriteCounters,
    armed: ArmedDrain,
    /// Origin for the nanosecond stamps in [`ArmedDrain`].
    base: Instant,
    /// Syncs of the WAL inode and worker jobs in flight right now, read
    /// by a write at its append.
    syncs_in_flight: AtomicU64,
    worker_jobs_running: AtomicU64,
}

impl Default for LockStats {
    fn default() -> Self {
        Self {
            sites: std::array::from_fn(|_| SiteCounters::default()),
            writes: WriteCounters::default(),
            armed: ArmedDrain::default(),
            base: Instant::now(),
            syncs_in_flight: AtomicU64::new(0),
            worker_jobs_running: AtomicU64::new(0),
        }
    }
}

impl LockStats {
    /// Count a `sync_data` of the WAL as in flight while the guard lives.
    pub fn sync_in_flight(&self) -> InFlight<'_> {
        InFlight::new(&self.syncs_in_flight)
    }

    /// Count a worker job as running while the guard lives.
    pub fn worker_running(&self) -> InFlight<'_> {
        InFlight::new(&self.worker_jobs_running)
    }

    /// What is in flight now, for a write to charge its WAL time against.
    pub fn append_context(&self) -> AppendContext {
        AppendContext {
            sync_in_flight: self.syncs_in_flight.load(Ordering::Relaxed) > 0,
            worker_running: self.worker_jobs_running.load(Ordering::Relaxed) > 0,
        }
    }

    /// Fold one completed acquisition in.
    pub fn record(&self, site: LockSite, wait: Duration, hold: Duration) {
        let counters = &self.sites[site.index()];
        let hold_nanos = hold.as_nanos() as u64;
        counters.acquisitions.fetch_add(1, Ordering::Relaxed);
        counters
            .wait_nanos
            .fetch_add(wait.as_nanos() as u64, Ordering::Relaxed);
        counters.hold_nanos.fetch_add(hold_nanos, Ordering::Relaxed);
        counters
            .window_max_hold_nanos
            .fetch_max(hold_nanos, Ordering::Relaxed);
        counters
            .peak_hold_nanos
            .fetch_max(hold_nanos, Ordering::Relaxed);
    }

    /// Arm the drain for a hold about to release, sized by the writers
    /// parked now. Must be called with the mutex still held. An empty
    /// queue arms nothing.
    pub fn arm_drain(&self, site: LockSite) {
        let queued = self.writes.waiting.load(Ordering::Acquire);
        if queued == 0 {
            return;
        }
        self.sites[site.index()]
            .arms
            .fetch_add(1, Ordering::Relaxed);
        self.armed.site.store(site.index(), Ordering::Relaxed);
        self.armed.queued.store(queued, Ordering::Relaxed);
        self.armed.joined.store(0, Ordering::Relaxed);
        // Zero is the unarmed sentinel, and the first clock tick after
        // `base` reads as zero.
        self.armed
            .release_nanos
            .store(self.now_nanos().max(1), Ordering::Release);
    }

    /// Count a guest write that took the mutex without blocking.
    ///
    /// One relaxed increment, no clock read, which is what keeps this
    /// affordable on a path that runs per device write.
    pub fn record_write_uncontended(&self) {
        self.writes.acquisitions.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a guest write about to park on the mutex, and its arrival
    /// into any queue already standing. Paired with the
    /// [`Self::record_write_blocked`] that follows it, so the gauge
    /// between the two is the queue a holder sees.
    pub fn record_write_parking(&self) {
        let depth = self.writes.waiting.fetch_add(1, Ordering::Release) + 1;
        self.writes
            .window_max_waiting
            .fetch_max(depth, Ordering::Relaxed);
        self.writes.peak_waiting.fetch_max(depth, Ordering::Relaxed);
        if self.armed.release_nanos.load(Ordering::Acquire) != 0 {
            self.armed.joined.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count a guest write that blocked, and for how long it did.
    ///
    /// A write reaching here has already parked, so the clock reads that
    /// produced `wait` are orders below what it is being charged.
    ///
    /// The write that leaves the queue empty closes out the armed drain.
    pub fn record_write_blocked(&self, wait: Duration) {
        let nanos = wait.as_nanos() as u64;
        self.writes.acquisitions.fetch_add(1, Ordering::Relaxed);
        self.writes.blocked.fetch_add(1, Ordering::Relaxed);
        self.writes.wait_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.writes
            .window_max_wait_nanos
            .fetch_max(nanos, Ordering::Relaxed);
        self.writes
            .peak_wait_nanos
            .fetch_max(nanos, Ordering::Relaxed);
        self.writes.wait_buckets[wait_bucket(wait)].fetch_add(1, Ordering::Relaxed);

        if self.writes.waiting.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.close_drain();
        }
    }

    /// Record what one guest write held the mutex for, on its release,
    /// the frozen depth it ran under, the part of the hold spent inside
    /// the WAL file calls, and what was in flight when it took the mutex.
    ///
    /// Charged by every write, contended or not, so the mean covers the
    /// uncontended holds an actor loop would be waiting on too.
    pub fn record_write_hold(
        &self,
        hold: Duration,
        depth: usize,
        wal: Duration,
        context: AppendContext,
    ) {
        let nanos = hold.as_nanos() as u64;
        let wal_nanos = wal.as_nanos() as u64;
        let map_nanos = nanos.saturating_sub(wal_nanos);
        let by = &self.writes.by_append[append_bucket(context)];
        by.writes.fetch_add(1, Ordering::Relaxed);
        by.hold_nanos.fetch_add(wal_nanos, Ordering::Relaxed);
        by.window_max_hold_nanos
            .fetch_max(wal_nanos, Ordering::Relaxed);
        self.writes
            .wal_nanos
            .fetch_add(wal_nanos, Ordering::Relaxed);
        self.writes
            .window_max_wal_nanos
            .fetch_max(wal_nanos, Ordering::Relaxed);
        self.writes
            .map_nanos
            .fetch_add(map_nanos, Ordering::Relaxed);
        self.writes
            .window_max_map_nanos
            .fetch_max(map_nanos, Ordering::Relaxed);
        self.writes.hold_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.writes
            .window_max_hold_nanos
            .fetch_max(nanos, Ordering::Relaxed);
        let at = &self.writes.by_depth[depth_bucket(depth)];
        at.writes.fetch_add(1, Ordering::Relaxed);
        at.hold_nanos.fetch_add(nanos, Ordering::Relaxed);
        at.window_max_hold_nanos.fetch_max(nanos, Ordering::Relaxed);
        let depth = depth as u64;
        self.writes
            .window_max_depth
            .fetch_max(depth, Ordering::Relaxed);
        self.writes.peak_depth.fetch_max(depth, Ordering::Relaxed);
    }

    /// Fold the armed drain in, called by the write that emptied the
    /// queue. The swap leaves a later arm for the next such write.
    fn close_drain(&self) {
        let release = self.armed.release_nanos.swap(0, Ordering::AcqRel);
        if release == 0 {
            return;
        }
        // A drain inside one clock tick still counts, so its window max
        // and peak stay nonzero alongside its `drains` increment.
        let tail = self.now_nanos().saturating_sub(release).max(1);
        let queued = self.armed.queued.load(Ordering::Relaxed);
        let joined = self.armed.joined.load(Ordering::Relaxed);
        let site = self.armed.site.load(Ordering::Relaxed);
        let counters = &self.sites[site];
        counters.drains.fetch_add(1, Ordering::Relaxed);
        counters.drain_queued.fetch_add(queued, Ordering::Relaxed);
        counters.drain_joined.fetch_add(joined, Ordering::Relaxed);
        counters.drain_nanos.fetch_add(tail, Ordering::Relaxed);
        counters
            .window_max_drain_nanos
            .fetch_max(tail, Ordering::Relaxed);
        counters.peak_drain_nanos.fetch_max(tail, Ordering::Relaxed);
    }

    fn now_nanos(&self) -> u64 {
        self.base.elapsed().as_nanos() as u64
    }

    /// Read the counters without disturbing them. `max_hold_nanos`
    /// covers whatever has accumulated since the last
    /// [`Self::take_window`], so a caller sampling between reports sees a
    /// partial window.
    pub fn snapshot(&self) -> LockStatsSnapshot {
        self.read(false)
    }

    /// Read the counters and start a fresh window, returning the maxima
    /// the closing one held. One reporter calls this; anything else
    /// wanting a look uses [`Self::snapshot`].
    pub fn take_window(&self) -> LockStatsSnapshot {
        self.read(true)
    }

    fn read(&self, close_window: bool) -> LockStatsSnapshot {
        LockStatsSnapshot {
            sites: std::array::from_fn(|i| SiteSnapshot {
                acquisitions: self.sites[i].acquisitions.load(Ordering::Relaxed),
                wait_nanos: self.sites[i].wait_nanos.load(Ordering::Relaxed),
                hold_nanos: self.sites[i].hold_nanos.load(Ordering::Relaxed),
                max_hold_nanos: if close_window {
                    self.sites[i]
                        .window_max_hold_nanos
                        .swap(0, Ordering::Relaxed)
                } else {
                    self.sites[i].window_max_hold_nanos.load(Ordering::Relaxed)
                },
                peak_hold_nanos: self.sites[i].peak_hold_nanos.load(Ordering::Relaxed),
                arms: self.sites[i].arms.load(Ordering::Relaxed),
                drains: self.sites[i].drains.load(Ordering::Relaxed),
                drain_joined: self.sites[i].drain_joined.load(Ordering::Relaxed),
                drain_queued: self.sites[i].drain_queued.load(Ordering::Relaxed),
                drain_nanos: self.sites[i].drain_nanos.load(Ordering::Relaxed),
                max_drain_nanos: if close_window {
                    self.sites[i]
                        .window_max_drain_nanos
                        .swap(0, Ordering::Relaxed)
                } else {
                    self.sites[i].window_max_drain_nanos.load(Ordering::Relaxed)
                },
                peak_drain_nanos: self.sites[i].peak_drain_nanos.load(Ordering::Relaxed),
            }),
            writes: WriteSnapshot {
                acquisitions: self.writes.acquisitions.load(Ordering::Relaxed),
                blocked: self.writes.blocked.load(Ordering::Relaxed),
                wait_nanos: self.writes.wait_nanos.load(Ordering::Relaxed),
                max_wait_nanos: if close_window {
                    self.writes.window_max_wait_nanos.swap(0, Ordering::Relaxed)
                } else {
                    self.writes.window_max_wait_nanos.load(Ordering::Relaxed)
                },
                peak_wait_nanos: self.writes.peak_wait_nanos.load(Ordering::Relaxed),
                hold_nanos: self.writes.hold_nanos.load(Ordering::Relaxed),
                max_hold_nanos: if close_window {
                    self.writes.window_max_hold_nanos.swap(0, Ordering::Relaxed)
                } else {
                    self.writes.window_max_hold_nanos.load(Ordering::Relaxed)
                },
                max_waiting: if close_window {
                    self.writes.window_max_waiting.swap(0, Ordering::Relaxed)
                } else {
                    self.writes.window_max_waiting.load(Ordering::Relaxed)
                },
                peak_waiting: self.writes.peak_waiting.load(Ordering::Relaxed),
                wait_buckets: std::array::from_fn(|i| {
                    self.writes.wait_buckets[i].load(Ordering::Relaxed)
                }),
                by_depth: std::array::from_fn(|i| {
                    let at = &self.writes.by_depth[i];
                    HoldSnapshot {
                        writes: at.writes.load(Ordering::Relaxed),
                        hold_nanos: at.hold_nanos.load(Ordering::Relaxed),
                        max_hold_nanos: if close_window {
                            at.window_max_hold_nanos.swap(0, Ordering::Relaxed)
                        } else {
                            at.window_max_hold_nanos.load(Ordering::Relaxed)
                        },
                    }
                }),
                max_depth: if close_window {
                    self.writes.window_max_depth.swap(0, Ordering::Relaxed)
                } else {
                    self.writes.window_max_depth.load(Ordering::Relaxed)
                },
                peak_depth: self.writes.peak_depth.load(Ordering::Relaxed),
                wal_nanos: self.writes.wal_nanos.load(Ordering::Relaxed),
                max_wal_nanos: if close_window {
                    self.writes.window_max_wal_nanos.swap(0, Ordering::Relaxed)
                } else {
                    self.writes.window_max_wal_nanos.load(Ordering::Relaxed)
                },
                map_nanos: self.writes.map_nanos.load(Ordering::Relaxed),
                max_map_nanos: if close_window {
                    self.writes.window_max_map_nanos.swap(0, Ordering::Relaxed)
                } else {
                    self.writes.window_max_map_nanos.load(Ordering::Relaxed)
                },
                by_append: std::array::from_fn(|i| {
                    let at = &self.writes.by_append[i];
                    HoldSnapshot {
                        writes: at.writes.load(Ordering::Relaxed),
                        hold_nanos: at.hold_nanos.load(Ordering::Relaxed),
                        max_hold_nanos: if close_window {
                            at.window_max_hold_nanos.swap(0, Ordering::Relaxed)
                        } else {
                            at.window_max_hold_nanos.load(Ordering::Relaxed)
                        },
                    }
                }),
            },
        }
    }
}

/// One site's counters read at an instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiteSnapshot {
    pub acquisitions: u64,
    pub wait_nanos: u64,
    pub hold_nanos: u64,
    /// Longest single hold within the window this snapshot covers.
    pub max_hold_nanos: u64,
    /// Longest single hold since the volume opened.
    pub peak_hold_nanos: u64,
    /// Holds that released with guest writes parked behind them.
    pub arms: u64,
    /// Those arms an emptied queue closed out; the drain figures below
    /// cover these.
    pub drains: u64,
    /// Writes parked when those holds released.
    pub drain_queued: u64,
    /// Writes that parked between release and the queue emptying.
    pub drain_joined: u64,
    /// Time those queues took to clear once the mutex was free.
    pub drain_nanos: u64,
    /// Longest single drain within the window this snapshot covers.
    pub max_drain_nanos: u64,
    /// Longest single drain since the volume opened.
    pub peak_drain_nanos: u64,
}

/// The guest write path's counters read at an instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WriteSnapshot {
    pub acquisitions: u64,
    pub blocked: u64,
    pub wait_nanos: u64,
    /// Longest single wait within the window this snapshot covers.
    pub max_wait_nanos: u64,
    /// Longest single wait since the volume opened.
    pub peak_wait_nanos: u64,
    /// What the guest held across `acquisitions`, and the longest single
    /// hold within the window.
    pub hold_nanos: u64,
    pub max_hold_nanos: u64,
    /// Deepest the parked-write queue got within the window.
    pub max_waiting: u64,
    /// Deepest it has got since the volume opened.
    pub peak_waiting: u64,
    /// Waits by magnitude, bucketed on [`WAIT_BUCKET_EDGES_MS`].
    pub wait_buckets: [u64; WAIT_BUCKETS],
    /// Holds by the frozen depth the write ran under.
    pub by_depth: [HoldSnapshot; DEPTH_BUCKETS],
    /// Deepest the frozen layers stood under a write within the window,
    /// and since the volume opened.
    pub max_depth: u64,
    pub peak_depth: u64,
    /// The hold split into the WAL file calls and the map commit, summed
    /// and with the longest single one within the window.
    pub wal_nanos: u64,
    pub max_wal_nanos: u64,
    pub map_nanos: u64,
    pub max_map_nanos: u64,
    /// The WAL time by what was in flight at the append.
    pub by_append: [HoldSnapshot; APPEND_BUCKETS],
}

/// The write holds charged at one frozen depth, read at an instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HoldSnapshot {
    pub writes: u64,
    pub hold_nanos: u64,
    pub max_hold_nanos: u64,
}

/// Every site's counters read at one instant.
#[derive(Debug, Clone, Copy)]
pub struct LockStatsSnapshot {
    sites: [SiteSnapshot; LockSite::COUNT],
    writes: WriteSnapshot,
}

impl Default for LockStatsSnapshot {
    fn default() -> Self {
        Self {
            sites: [SiteSnapshot::default(); LockSite::COUNT],
            writes: WriteSnapshot::default(),
        }
    }
}

impl LockStatsSnapshot {
    pub fn site(&self, site: LockSite) -> SiteSnapshot {
        self.sites[site.index()]
    }

    /// What the guest write path waited for the same mutex.
    pub fn writes(&self) -> WriteSnapshot {
        self.writes
    }

    /// What accumulated between `earlier` and this snapshot.
    ///
    /// Counts and totals subtract. The two maxima are carried through:
    /// `max_hold_nanos` is already scoped to the window by the reset in
    /// [`LockStats::take_window`], and `peak_hold_nanos` is meant to
    /// outlive its window.
    pub fn since(&self, earlier: &LockStatsSnapshot) -> LockStatsSnapshot {
        LockStatsSnapshot {
            sites: std::array::from_fn(|i| SiteSnapshot {
                acquisitions: self.sites[i]
                    .acquisitions
                    .saturating_sub(earlier.sites[i].acquisitions),
                wait_nanos: self.sites[i]
                    .wait_nanos
                    .saturating_sub(earlier.sites[i].wait_nanos),
                hold_nanos: self.sites[i]
                    .hold_nanos
                    .saturating_sub(earlier.sites[i].hold_nanos),
                max_hold_nanos: self.sites[i].max_hold_nanos,
                peak_hold_nanos: self.sites[i].peak_hold_nanos,
                arms: self.sites[i].arms.saturating_sub(earlier.sites[i].arms),
                drains: self.sites[i].drains.saturating_sub(earlier.sites[i].drains),
                drain_queued: self.sites[i]
                    .drain_queued
                    .saturating_sub(earlier.sites[i].drain_queued),
                drain_joined: self.sites[i]
                    .drain_joined
                    .saturating_sub(earlier.sites[i].drain_joined),
                drain_nanos: self.sites[i]
                    .drain_nanos
                    .saturating_sub(earlier.sites[i].drain_nanos),
                max_drain_nanos: self.sites[i].max_drain_nanos,
                peak_drain_nanos: self.sites[i].peak_drain_nanos,
            }),
            writes: WriteSnapshot {
                acquisitions: self
                    .writes
                    .acquisitions
                    .saturating_sub(earlier.writes.acquisitions),
                blocked: self.writes.blocked.saturating_sub(earlier.writes.blocked),
                wait_nanos: self
                    .writes
                    .wait_nanos
                    .saturating_sub(earlier.writes.wait_nanos),
                max_wait_nanos: self.writes.max_wait_nanos,
                peak_wait_nanos: self.writes.peak_wait_nanos,
                hold_nanos: self
                    .writes
                    .hold_nanos
                    .saturating_sub(earlier.writes.hold_nanos),
                max_hold_nanos: self.writes.max_hold_nanos,
                max_waiting: self.writes.max_waiting,
                peak_waiting: self.writes.peak_waiting,
                wait_buckets: std::array::from_fn(|i| {
                    self.writes.wait_buckets[i].saturating_sub(earlier.writes.wait_buckets[i])
                }),
                by_depth: std::array::from_fn(|i| HoldSnapshot {
                    writes: self.writes.by_depth[i]
                        .writes
                        .saturating_sub(earlier.writes.by_depth[i].writes),
                    hold_nanos: self.writes.by_depth[i]
                        .hold_nanos
                        .saturating_sub(earlier.writes.by_depth[i].hold_nanos),
                    max_hold_nanos: self.writes.by_depth[i].max_hold_nanos,
                }),
                max_depth: self.writes.max_depth,
                peak_depth: self.writes.peak_depth,
                wal_nanos: self
                    .writes
                    .wal_nanos
                    .saturating_sub(earlier.writes.wal_nanos),
                max_wal_nanos: self.writes.max_wal_nanos,
                map_nanos: self
                    .writes
                    .map_nanos
                    .saturating_sub(earlier.writes.map_nanos),
                max_map_nanos: self.writes.max_map_nanos,
                by_append: std::array::from_fn(|i| HoldSnapshot {
                    writes: self.writes.by_append[i]
                        .writes
                        .saturating_sub(earlier.writes.by_append[i].writes),
                    hold_nanos: self.writes.by_append[i]
                        .hold_nanos
                        .saturating_sub(earlier.writes.by_append[i].hold_nanos),
                    max_hold_nanos: self.writes.by_append[i].max_hold_nanos,
                }),
            },
        }
    }

    /// The site holding the mutex longest since the volume opened, and
    /// for how long.
    pub fn peak(&self) -> Option<(LockSite, Duration)> {
        LockSite::ALL
            .iter()
            .map(|&site| (site, self.site(site).peak_hold_nanos))
            .filter(|(_, peak)| *peak > 0)
            .max_by_key(|(_, peak)| *peak)
            .map(|(site, peak)| (site, Duration::from_nanos(peak)))
    }

    /// Total hold across every site.
    pub fn total_hold(&self) -> Duration {
        Duration::from_nanos(self.sites.iter().map(|s| s.hold_nanos).sum())
    }

    /// Whether this window cost a writer enough to be worth a line: the
    /// mutex held past `floor`, or a guest write that blocked on it.
    ///
    /// A blocked write qualifies on its own however short it waited,
    /// since a guest stalling on the mutex is the quantity the whole
    /// measurement exists to surface.
    pub fn worth_reporting(&self, floor: Duration) -> bool {
        self.total_hold() > floor || self.writes.blocked > 0
    }

    /// One line naming every site that acquired in this window, ordered
    /// by hold time descending, then the longest hold the volume has seen
    /// and what the guest writes waited. `None` when nothing acquired,
    /// which is what keeps an idle volume silent.
    pub fn report(&self) -> Option<String> {
        let mut active: Vec<(LockSite, SiteSnapshot)> = LockSite::ALL
            .iter()
            .map(|&site| (site, self.site(site)))
            .filter(|(_, s)| s.acquisitions > 0)
            .collect();
        if active.is_empty() && self.writes.acquisitions == 0 {
            return None;
        }
        active.sort_by_key(|(_, s)| std::cmp::Reverse(s.hold_nanos));

        let mut out = format!(
            "held {:.1}ms total",
            millis(self.total_hold().as_nanos() as u64)
        );
        for (site, s) in active {
            out.push_str(&format!(
                "; {} n={} hold={:.1}ms max={:.1}ms wait={:.1}ms",
                site.label(),
                s.acquisitions,
                millis(s.hold_nanos),
                millis(s.max_hold_nanos),
                millis(s.wait_nanos),
            ));
            if s.arms > 0 {
                out.push_str(&format!(
                    " arms={} drains={} queued={} joined={} drained={:.1}ms max={:.1}ms",
                    s.arms,
                    s.drains,
                    s.drain_queued,
                    s.drain_joined,
                    millis(s.drain_nanos),
                    millis(s.max_drain_nanos),
                ));
            }
        }
        if let Some((site, peak)) = self.peak() {
            out.push_str(&format!(
                "; peak {} {:.1}ms",
                site.label(),
                millis(peak.as_nanos() as u64)
            ));
        }
        if self.writes.acquisitions > 0 {
            out.push_str(&format!(
                "; writes n={} blocked={} wait={:.1}ms max={:.1}ms peak={:.1}ms \
                 held={:.1}ms maxheld={:.1}ms maxq={} peakq={}",
                self.writes.acquisitions,
                self.writes.blocked,
                millis(self.writes.wait_nanos),
                millis(self.writes.max_wait_nanos),
                millis(self.writes.peak_wait_nanos),
                millis(self.writes.hold_nanos),
                millis(self.writes.max_hold_nanos),
                self.writes.max_waiting,
                self.writes.peak_waiting,
            ));
            let spread: Vec<String> = self
                .writes
                .wait_buckets
                .iter()
                .enumerate()
                .filter(|(_, n)| **n > 0)
                .map(|(i, n)| format!("{}={n}", wait_bucket_label(i)))
                .collect();
            if !spread.is_empty() {
                out.push_str(&format!(" [{}]", spread.join(" ")));
            }
            out.push_str(&format!(
                "; depth max={} peak={}",
                self.writes.max_depth, self.writes.peak_depth
            ));
            for (i, d) in self
                .writes
                .by_depth
                .iter()
                .enumerate()
                .filter(|(_, d)| d.writes > 0)
            {
                out.push_str(&format!(
                    " {} n={} held={:.1}ms maxheld={:.1}ms",
                    depth_bucket_label(i),
                    d.writes,
                    millis(d.hold_nanos),
                    millis(d.max_hold_nanos),
                ));
            }
            out.push_str(&format!(
                "; wal held={:.1}ms maxheld={:.1}ms map held={:.1}ms maxheld={:.1}ms",
                millis(self.writes.wal_nanos),
                millis(self.writes.max_wal_nanos),
                millis(self.writes.map_nanos),
                millis(self.writes.max_map_nanos),
            ));
            out.push_str("; append");
            for (i, d) in self
                .writes
                .by_append
                .iter()
                .enumerate()
                .filter(|(_, d)| d.writes > 0)
            {
                out.push_str(&format!(
                    " {} n={} held={:.1}ms maxheld={:.1}ms",
                    APPEND_BUCKET_LABELS[i],
                    d.writes,
                    millis(d.hold_nanos),
                    millis(d.max_hold_nanos),
                ));
            }
        }
        Some(out)
    }
}

fn millis(nanos: u64) -> f64 {
    nanos as f64 / 1_000_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ALL` drives `COUNT`, the report order and the index space, so a
    /// variant missing from it would silently never be reported and would
    /// alias another site's counters.
    #[test]
    fn all_sites_are_listed_once() {
        let mut seen = [false; LockSite::COUNT];
        for &site in LockSite::ALL {
            let i = site.index();
            assert!(
                i < LockSite::COUNT,
                "{} indexes outside the counter array",
                site.label()
            );
            assert!(!seen[i], "{} listed twice", site.label());
            seen[i] = true;
        }
        assert!(
            seen.iter().all(|s| *s),
            "a LockSite variant is missing from LockSite::ALL"
        );
    }

    #[test]
    fn labels_are_distinct() {
        let mut labels: Vec<&str> = LockSite::ALL.iter().map(|s| s.label()).collect();
        labels.sort_unstable();
        let before = labels.len();
        labels.dedup();
        assert_eq!(before, labels.len(), "two sites share a label");
    }

    #[test]
    fn record_accumulates_per_site() {
        let stats = LockStats::default();
        stats.record(
            LockSite::RepackApply,
            Duration::from_millis(1),
            Duration::from_millis(10),
        );
        stats.record(
            LockSite::RepackApply,
            Duration::from_millis(2),
            Duration::from_millis(4),
        );
        stats.record(
            LockSite::PromotePrep,
            Duration::ZERO,
            Duration::from_millis(3),
        );

        let snap = stats.snapshot();
        let repack = snap.site(LockSite::RepackApply);
        assert_eq!(repack.acquisitions, 2);
        assert_eq!(
            repack.hold_nanos,
            Duration::from_millis(14).as_nanos() as u64
        );
        assert_eq!(
            repack.wait_nanos,
            Duration::from_millis(3).as_nanos() as u64
        );
        assert_eq!(
            repack.max_hold_nanos,
            Duration::from_millis(10).as_nanos() as u64,
            "max is the longest single hold, not the total"
        );
        assert_eq!(snap.site(LockSite::PromotePrep).acquisitions, 1);
        assert_eq!(snap.site(LockSite::ClosePrep).acquisitions, 0);
    }

    /// A window reports what accumulated in it, maximum included. A
    /// maximum cannot subtract, so `take_window` resets it; carrying the
    /// cumulative one instead would repeat an old spike in every window
    /// and leave no way to tell when it happened.
    #[test]
    fn a_window_maximum_covers_only_that_window() {
        let stats = LockStats::default();
        stats.record(
            LockSite::GcPlanApply,
            Duration::ZERO,
            Duration::from_millis(20),
        );
        let mark = stats.take_window();
        stats.record(
            LockSite::GcPlanApply,
            Duration::ZERO,
            Duration::from_millis(5),
        );

        let window = stats.take_window().since(&mark);
        let site = window.site(LockSite::GcPlanApply);
        assert_eq!(site.acquisitions, 1);
        assert_eq!(site.hold_nanos, Duration::from_millis(5).as_nanos() as u64);
        assert_eq!(
            site.max_hold_nanos,
            Duration::from_millis(5).as_nanos() as u64,
            "the 20ms hold belongs to the window before this one"
        );
    }

    /// The peak outlives its window, so a spike stays visible in every
    /// later report rather than scrolling away with the window it
    /// happened in.
    #[test]
    fn the_peak_survives_the_window_it_happened_in() {
        let stats = LockStats::default();
        stats.record(
            LockSite::RepackApply,
            Duration::ZERO,
            Duration::from_millis(1700),
        );
        stats.take_window();
        stats.record(
            LockSite::PromoteApply,
            Duration::ZERO,
            Duration::from_millis(2),
        );

        let window = stats.take_window();
        assert_eq!(
            window.site(LockSite::RepackApply).max_hold_nanos,
            0,
            "the spike is not in this window"
        );
        let (site, peak) = window.peak().expect("a peak was recorded");
        assert_eq!(site, LockSite::RepackApply);
        assert_eq!(peak, Duration::from_millis(1700));
        assert!(
            window
                .report()
                .expect("sites acquired")
                .contains("peak repack-apply"),
            "the report names the all-time peak"
        );
    }

    /// A plain read must not disturb the window the reporter is
    /// accumulating, or a handle sampling the counters would silently
    /// truncate the next log line's maximum.
    #[test]
    fn snapshot_leaves_the_window_intact() {
        let stats = LockStats::default();
        stats.record(
            LockSite::ClosePrep,
            Duration::ZERO,
            Duration::from_millis(7),
        );
        let peeked = stats.snapshot();
        assert_eq!(
            peeked.site(LockSite::ClosePrep).max_hold_nanos,
            Duration::from_millis(7).as_nanos() as u64
        );
        assert_eq!(
            stats.take_window().site(LockSite::ClosePrep).max_hold_nanos,
            Duration::from_millis(7).as_nanos() as u64,
            "the peek consumed the window"
        );
    }

    #[test]
    fn an_idle_window_reports_nothing() {
        assert!(LockStatsSnapshot::default().report().is_none());
    }

    /// A volume nobody is writing to still runs its tick, which takes the
    /// mutex a handful of times for microseconds. Those acquisitions are
    /// what the floor is for.
    #[test]
    fn a_tick_on_a_quiet_volume_falls_under_the_floor() {
        let stats = LockStats::default();
        for site in [
            LockSite::OwnSegments,
            LockSite::PublishSnapshot,
            LockSite::GcCheckpoint,
            LockSite::PromotePrep,
        ] {
            stats.record(site, Duration::ZERO, Duration::from_micros(20));
        }
        stats.record_write_uncontended();

        let window = stats.snapshot();
        assert!(
            window.report().is_some(),
            "the sites acquired, so there is a line to suppress"
        );
        assert!(!window.worth_reporting(Duration::from_millis(1)));
    }

    /// Held time accumulates across suppressed windows, so a volume
    /// sitting just under the floor surfaces once the holds add up
    /// rather than never.
    #[test]
    fn holds_under_the_floor_add_up_to_a_report() {
        let stats = LockStats::default();
        let floor = Duration::from_millis(1);
        stats.record(
            LockSite::GcPlanApply,
            Duration::ZERO,
            Duration::from_micros(600),
        );
        assert!(!stats.snapshot().worth_reporting(floor));
        stats.record(
            LockSite::GcPlanApply,
            Duration::ZERO,
            Duration::from_micros(600),
        );
        assert!(stats.snapshot().worth_reporting(floor));
    }

    /// A guest that stalled is the measurement's whole point, so it earns
    /// a line however little the actor side held.
    #[test]
    fn a_blocked_write_reports_under_any_floor() {
        let stats = LockStats::default();
        stats.record_write_blocked(Duration::from_micros(30));
        assert!(stats.snapshot().worth_reporting(Duration::from_secs(1)));
    }

    /// Every guest write counts, but only the ones that blocked carry a
    /// wait — an uncontended write reads no clock, so a zero wait would
    /// be indistinguishable from an unmeasured one without `blocked`.
    #[test]
    fn writes_count_always_and_time_only_when_blocked() {
        let stats = LockStats::default();
        stats.record_write_uncontended();
        stats.record_write_uncontended();
        stats.record_write_blocked(Duration::from_millis(12));

        let writes = stats.snapshot().writes();
        assert_eq!(writes.acquisitions, 3);
        assert_eq!(writes.blocked, 1);
        assert_eq!(
            writes.wait_nanos,
            Duration::from_millis(12).as_nanos() as u64
        );
        assert_eq!(
            writes.max_wait_nanos,
            Duration::from_millis(12).as_nanos() as u64
        );
    }

    /// The write maxima window and survive on the same terms as a site's
    /// hold: the worst stall a guest saw is the number worth keeping, and
    /// it cannot be recovered by subtracting two totals.
    #[test]
    fn the_worst_write_stall_outlives_its_window() {
        let stats = LockStats::default();
        stats.record_write_blocked(Duration::from_millis(1700));
        let mark = stats.take_window();
        stats.record_write_blocked(Duration::from_millis(3));

        let window = stats.take_window().since(&mark);
        assert_eq!(window.writes().blocked, 1);
        assert_eq!(
            window.writes().max_wait_nanos,
            Duration::from_millis(3).as_nanos() as u64,
            "the 1700ms stall belongs to the window before this one"
        );
        assert_eq!(
            window.writes().peak_wait_nanos,
            Duration::from_millis(1700).as_nanos() as u64,
            "the worst stall stays visible after its window closes"
        );
    }

    /// A window in which only the guest wrote still reports, so write
    /// waits cannot go unlogged for want of an actor-side acquisition.
    #[test]
    fn a_write_only_window_still_reports() {
        let stats = LockStats::default();
        stats.record_write_blocked(Duration::from_millis(4));
        let report = stats.snapshot().report().expect("the writes acquired");
        assert!(report.contains("writes n=1 blocked=1"), "got: {report}");
    }

    /// Every write charges its hold, whether or not it waited: an actor
    /// loop yielding to the queue pays the uncontended holds too, so a
    /// sum over the blocked ones alone would under-size the yield.
    #[test]
    fn a_write_charges_its_hold_whether_or_not_it_waited() {
        let stats = LockStats::default();
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(2),
            0,
            Duration::ZERO,
            AppendContext::default(),
        );
        stats.record_write_parking();
        stats.record_write_blocked(Duration::from_millis(9));
        stats.record_write_hold(
            Duration::from_millis(5),
            0,
            Duration::ZERO,
            AppendContext::default(),
        );

        let snap = stats.snapshot();
        assert_eq!(snap.writes.hold_nanos, 7_000_000);
        assert_eq!(snap.writes.max_hold_nanos, 5_000_000);
        let report = snap.report().expect("the writes acquired");
        assert!(report.contains("held=7.0ms maxheld=5.0ms"), "got: {report}");
    }

    /// The window maximum resets with the window while the sum keeps
    /// running, matching how the wait figures either side of it read.
    #[test]
    fn the_window_hold_maximum_resets_and_the_sum_does_not() {
        let stats = LockStats::default();
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(6),
            0,
            Duration::ZERO,
            AppendContext::default(),
        );
        assert_eq!(stats.take_window().writes.max_hold_nanos, 6_000_000);

        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(1),
            0,
            Duration::ZERO,
            AppendContext::default(),
        );
        let snap = stats.snapshot();
        assert_eq!(snap.writes.max_hold_nanos, 1_000_000);
        assert_eq!(snap.writes.hold_nanos, 7_000_000);
    }

    /// A write's WAL time is charged to what was in flight when it took
    /// the mutex: a sync on the WAL inode, a worker job, both, or neither,
    /// so a long append reads as blocked behind one or the other.
    #[test]
    fn a_wal_append_is_charged_to_what_was_in_flight() {
        let stats = LockStats::default();
        assert_eq!(stats.append_context(), AppendContext::default());
        {
            let _sync = stats.sync_in_flight();
            let context = stats.append_context();
            assert!(context.sync_in_flight);
            assert!(!context.worker_running);
            stats.record_write_uncontended();
            stats.record_write_hold(
                Duration::from_millis(3),
                0,
                Duration::from_millis(2),
                context,
            );
            let _worker = stats.worker_running();
            let context = stats.append_context();
            assert!(context.sync_in_flight);
            assert!(context.worker_running);
            stats.record_write_uncontended();
            stats.record_write_hold(
                Duration::from_millis(5),
                0,
                Duration::from_millis(4),
                context,
            );
        }
        assert_eq!(stats.append_context(), AppendContext::default());
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(1),
            0,
            Duration::from_millis(1),
            stats.append_context(),
        );

        let snap = stats.take_window();
        assert_eq!(snap.writes.by_append[0].writes, 1);
        assert_eq!(snap.writes.by_append[1].hold_nanos, 2_000_000);
        assert_eq!(snap.writes.by_append[3].max_hold_nanos, 4_000_000);
        let report = snap.report().expect("the writes acquired");
        assert!(
            report.contains(
                "; append idle n=1 held=1.0ms maxheld=1.0ms \
                 sync n=1 held=2.0ms maxheld=2.0ms both n=1 held=4.0ms maxheld=4.0ms"
            ),
            "got: {report}"
        );
    }

    /// The hold splits into the WAL file calls and the map commit, each
    /// summed and with its window maximum, so a long hold reads as one
    /// or the other. The window maxima reset with the window.
    #[test]
    fn a_write_hold_splits_into_wal_time_and_map_time() {
        let stats = LockStats::default();
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(5),
            0,
            Duration::from_millis(4),
            AppendContext::default(),
        );
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(3),
            0,
            Duration::from_millis(1),
            AppendContext::default(),
        );

        let snap = stats.take_window();
        assert_eq!(snap.writes.wal_nanos, 5_000_000);
        assert_eq!(snap.writes.max_wal_nanos, 4_000_000);
        assert_eq!(snap.writes.map_nanos, 3_000_000);
        assert_eq!(snap.writes.max_map_nanos, 2_000_000);
        let report = snap.report().expect("the writes acquired");
        assert!(
            report.contains("; wal held=5.0ms maxheld=4.0ms map held=3.0ms maxheld=2.0ms"),
            "got: {report}"
        );

        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(1),
            0,
            Duration::from_millis(1),
            AppendContext::default(),
        );
        let next = stats.snapshot();
        assert_eq!(next.writes.max_wal_nanos, 1_000_000);
        assert_eq!(next.writes.max_map_nanos, 0);
        assert_eq!(next.writes.wal_nanos, 6_000_000);
    }

    /// A write's hold is charged to the frozen depth it ran under, so
    /// the cost of one more layer reads off the per-depth means. Depths
    /// past the last bucket land in it, and the window maximum resets
    /// while the peak stands.
    #[test]
    fn a_write_hold_is_charged_to_its_frozen_depth() {
        let stats = LockStats::default();
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(1),
            0,
            Duration::ZERO,
            AppendContext::default(),
        );
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(3),
            2,
            Duration::ZERO,
            AppendContext::default(),
        );
        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(2),
            7,
            Duration::ZERO,
            AppendContext::default(),
        );

        let snap = stats.take_window();
        assert_eq!(snap.writes.by_depth[0].writes, 1);
        assert_eq!(snap.writes.by_depth[2].hold_nanos, 3_000_000);
        assert_eq!(snap.writes.by_depth[DEPTH_BUCKETS - 1].writes, 1);
        assert_eq!(snap.writes.max_depth, 7);
        let report = snap.report().expect("the writes acquired");
        assert!(
            report.contains(
                "depth max=7 peak=7 d0 n=1 held=1.0ms maxheld=1.0ms \
                 d2 n=1 held=3.0ms maxheld=3.0ms d5+ n=1 held=2.0ms maxheld=2.0ms"
            ),
            "got: {report}"
        );

        stats.record_write_uncontended();
        stats.record_write_hold(
            Duration::from_millis(1),
            1,
            Duration::ZERO,
            AppendContext::default(),
        );
        let next = stats.snapshot();
        assert_eq!(next.writes.max_depth, 1);
        assert_eq!(next.writes.peak_depth, 7);
        assert_eq!(next.writes.by_depth[2].max_hold_nanos, 0);
        assert_eq!(next.writes.by_depth[2].hold_nanos, 3_000_000);
    }

    /// A drain is attributed to the site that released, sized by the
    /// queue standing at that moment, and timed from the release.
    #[test]
    fn a_drain_is_timed_from_the_release_that_left_the_queue() {
        let stats = LockStats::default();
        stats.record_write_parking();
        stats.record_write_parking();

        stats.record(
            LockSite::RepackApply,
            Duration::ZERO,
            Duration::from_millis(600),
        );
        stats.arm_drain(LockSite::RepackApply);

        std::thread::sleep(Duration::from_millis(2));
        stats.record_write_blocked(Duration::from_millis(600));
        let mid = stats.snapshot().site(LockSite::RepackApply);
        assert_eq!(mid.drains, 0, "one writer is still queued");

        stats.record_write_blocked(Duration::from_millis(602));

        let site = stats.snapshot().site(LockSite::RepackApply);
        assert_eq!(site.drains, 1);
        assert_eq!(site.drain_queued, 2, "both writers stood behind the hold");
        assert!(
            site.drain_nanos >= Duration::from_millis(2).as_nanos() as u64,
            "the tail covers the time after release, got {}ns",
            site.drain_nanos
        );
        assert!(
            site.drain_nanos < Duration::from_millis(600).as_nanos() as u64,
            "the tail is not the hold, got {}ns",
            site.drain_nanos
        );
    }

    /// A hold releasing into a queue that already stands replaces the
    /// arm holding it, and the arms-to-drains shortfall counts that.
    #[test]
    fn an_arm_over_a_standing_queue_shows_as_a_shortfall() {
        let stats = LockStats::default();
        stats.record_write_parking();
        stats.record_write_parking();

        stats.record(
            LockSite::RepackApply,
            Duration::ZERO,
            Duration::from_millis(600),
        );
        stats.arm_drain(LockSite::RepackApply);
        stats.record(
            LockSite::PublishSnapshot,
            Duration::ZERO,
            Duration::from_micros(50),
        );
        stats.arm_drain(LockSite::PublishSnapshot);

        stats.record_write_blocked(Duration::from_millis(600));
        stats.record_write_blocked(Duration::from_millis(601));

        let snap = stats.snapshot();
        let repack = snap.site(LockSite::RepackApply);
        let publish = snap.site(LockSite::PublishSnapshot);
        assert_eq!(repack.arms, 1);
        assert_eq!(repack.drains, 0, "its arm was replaced");
        assert_eq!(publish.arms, 1);
        assert_eq!(publish.drains, 1, "the surviving arm closed");

        let report = snap.report().expect("sites acquired");
        assert!(
            report.contains("arms=1 drains=0"),
            "the replaced arm is visible: {report}"
        );
    }

    /// The queue's high-water mark bounds every `queued` figure, so a
    /// window reports it beside them.
    #[test]
    fn the_queue_depth_high_water_mark_is_reported() {
        let stats = LockStats::default();
        stats.record_write_parking();
        stats.record_write_parking();
        stats.record_write_parking();
        stats.record_write_blocked(Duration::from_millis(1));
        stats.record_write_blocked(Duration::from_millis(1));
        stats.record_write_parking();
        stats.record_write_blocked(Duration::from_millis(1));
        stats.record_write_blocked(Duration::from_millis(1));

        let writes = stats.snapshot().writes();
        assert_eq!(writes.max_waiting, 3);
        assert_eq!(writes.peak_waiting, 3);
        let report = stats.snapshot().report().expect("the writes acquired");
        assert!(report.contains("maxq=3 peakq=3"), "got: {report}");
    }

    /// `queued` samples once at the release, so writes arriving during
    /// the tail count as joined.
    #[test]
    fn writes_joining_a_standing_queue_are_counted() {
        let stats = LockStats::default();
        stats.record_write_parking();
        stats.arm_drain(LockSite::RepackApply);

        stats.record_write_parking();
        stats.record_write_parking();
        stats.record_write_blocked(Duration::from_millis(5));
        stats.record_write_blocked(Duration::from_millis(4));
        stats.record_write_blocked(Duration::from_millis(3));

        let site = stats.snapshot().site(LockSite::RepackApply);
        assert_eq!(site.drains, 1);
        assert_eq!(site.drain_queued, 1, "one writer stood at the release");
        assert_eq!(site.drain_joined, 2, "two more joined before it cleared");
    }

    /// A hold nobody waited on leaves no queue and no tail to time.
    #[test]
    fn a_hold_with_an_empty_queue_arms_nothing() {
        let stats = LockStats::default();
        stats.record(
            LockSite::GcPlanApply,
            Duration::ZERO,
            Duration::from_millis(400),
        );
        stats.arm_drain(LockSite::GcPlanApply);

        stats.record_write_parking();
        stats.record_write_blocked(Duration::from_millis(1));

        assert_eq!(stats.snapshot().site(LockSite::GcPlanApply).drains, 0);
    }

    /// A drain windows and peaks on the same terms as a hold.
    #[test]
    fn a_drain_windows_like_a_hold() {
        let stats = LockStats::default();
        stats.record_write_parking();
        stats.arm_drain(LockSite::RepackApply);
        stats.record_write_blocked(Duration::from_millis(9));
        let mark = stats.take_window();
        assert!(mark.site(LockSite::RepackApply).max_drain_nanos > 0);

        let window = stats.take_window().since(&mark);
        assert_eq!(window.site(LockSite::RepackApply).drains, 0);
        assert_eq!(
            window.site(LockSite::RepackApply).max_drain_nanos,
            0,
            "the drain belongs to the window before this one"
        );
        assert!(
            window.site(LockSite::RepackApply).peak_drain_nanos > 0,
            "the worst drain stays visible after its window closes"
        );
    }

    /// The spread separates one long wait from many.
    #[test]
    fn the_wait_spread_separates_one_stall_from_many() {
        let stats = LockStats::default();
        stats.record_write_blocked(Duration::from_millis(111));
        for _ in 0..1000 {
            stats.record_write_blocked(Duration::from_micros(200));
        }

        let writes = stats.snapshot().writes();
        assert_eq!(writes.wait_buckets[0], 1000, "sub-millisecond waits");
        assert_eq!(
            writes.wait_buckets[wait_bucket(Duration::from_millis(111))],
            1
        );
        let report = stats.snapshot().report().expect("the writes acquired");
        assert!(report.contains("<1ms=1000"), "got: {report}");
        assert!(report.contains("<1000ms=1"), "got: {report}");
    }

    /// Every wait lands in exactly one bucket, including one past the
    /// last edge.
    #[test]
    fn every_wait_falls_in_one_bucket() {
        assert_eq!(wait_bucket(Duration::ZERO), 0);
        assert_eq!(wait_bucket(Duration::from_micros(999)), 0);
        assert_eq!(wait_bucket(Duration::from_millis(1)), 1);
        assert_eq!(wait_bucket(Duration::from_millis(9)), 1);
        assert_eq!(wait_bucket(Duration::from_millis(10)), 2);
        assert_eq!(wait_bucket(Duration::from_millis(999)), 3);
        assert_eq!(wait_bucket(Duration::from_millis(1_000)), 4);
        assert_eq!(wait_bucket(Duration::from_secs(60)), WAIT_BUCKETS - 1);
    }

    /// The report is ranked by hold, so the site costing writers the most
    /// reads first whatever order the sites were declared in.
    #[test]
    fn report_ranks_by_hold_descending() {
        let stats = LockStats::default();
        stats.record(
            LockSite::PublishSnapshot,
            Duration::ZERO,
            Duration::from_millis(1),
        );
        stats.record(
            LockSite::RepackApply,
            Duration::ZERO,
            Duration::from_millis(50),
        );
        let report = stats.snapshot().report().expect("sites acquired");
        let repack = report.find("repack-apply").expect("repack-apply named");
        let publish = report.find("publish").expect("publish named");
        assert!(
            repack < publish,
            "expected hold-ranked order, got: {report}"
        );
    }
}
