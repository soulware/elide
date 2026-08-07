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
//! sit apart from the labelled sites: a guest write pays one relaxed
//! increment when the mutex is free, and reads the clock only on the
//! acquisitions that actually blocked.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
}

/// The guest write path's acquisitions, kept apart from the labelled
/// sites because a different quantity is measured.
///
/// A write records what it waited and nothing about what it held, so
/// there is no hold to rank it by and no hold column that would read as
/// zero when it means unmeasured.
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
}

/// Counters for every labelled acquisition of one volume's mutex.
///
/// Shared between the actor and any handle that reports them, so the
/// counters are atomics rather than a locked struct — taking a lock to
/// record lock occupancy would defeat the measurement.
pub struct LockStats {
    sites: [SiteCounters; LockSite::COUNT],
    writes: WriteCounters,
}

impl Default for LockStats {
    fn default() -> Self {
        Self {
            sites: std::array::from_fn(|_| SiteCounters::default()),
            writes: WriteCounters::default(),
        }
    }
}

impl LockStats {
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

    /// Count a guest write that took the mutex without blocking.
    ///
    /// One relaxed increment, no clock read, which is what keeps this
    /// affordable on a path that runs per device write.
    pub fn record_write_uncontended(&self) {
        self.writes.acquisitions.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a guest write that blocked, and for how long it did.
    ///
    /// A write reaching here has already parked, so the clock reads that
    /// produced `wait` are orders below what it is being charged.
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
                "; writes n={} blocked={} wait={:.1}ms max={:.1}ms peak={:.1}ms",
                self.writes.acquisitions,
                self.writes.blocked,
                millis(self.writes.wait_nanos),
                millis(self.writes.max_wait_nanos),
                millis(self.writes.peak_wait_nanos),
            ));
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
