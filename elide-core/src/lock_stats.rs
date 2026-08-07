//! Per-site occupancy of the volume mutex.
//!
//! A read resolves off a published snapshot and takes no volume lock; a
//! write takes the volume mutex directly on the ublk queue thread. So
//! every acquisition counted here is time a guest write can spend waiting
//! (`docs/architecture.md` *Concurrency and locking*).
//!
//! The write path itself is uncounted. It acquires through the untimed
//! primitive, which keeps two clock reads off the hot path and leaves the
//! counters describing what the actor does to writers.
//!
//! Hold time is what blocks a writer, and it is not the same quantity as
//! CPU time: a section that blocks on `fsync_dir` holds the mutex for the
//! whole commit while consuming almost nothing, so per-thread CPU sampling
//! cannot see it.

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
    max_hold_nanos: AtomicU64,
}

/// Counters for every labelled acquisition of one volume's mutex.
///
/// Shared between the actor and any handle that reports them, so the
/// counters are atomics rather than a locked struct — taking a lock to
/// record lock occupancy would defeat the measurement.
pub struct LockStats {
    sites: [SiteCounters; LockSite::COUNT],
}

impl Default for LockStats {
    fn default() -> Self {
        Self {
            sites: std::array::from_fn(|_| SiteCounters::default()),
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
            .max_hold_nanos
            .fetch_max(hold_nanos, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> LockStatsSnapshot {
        LockStatsSnapshot {
            sites: std::array::from_fn(|i| SiteSnapshot {
                acquisitions: self.sites[i].acquisitions.load(Ordering::Relaxed),
                wait_nanos: self.sites[i].wait_nanos.load(Ordering::Relaxed),
                hold_nanos: self.sites[i].hold_nanos.load(Ordering::Relaxed),
                max_hold_nanos: self.sites[i].max_hold_nanos.load(Ordering::Relaxed),
            }),
        }
    }
}

/// One site's counters read at an instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SiteSnapshot {
    pub acquisitions: u64,
    pub wait_nanos: u64,
    pub hold_nanos: u64,
    /// Longest single hold. A `since` window reports the running maximum
    /// rather than the window's own, because a maximum does not subtract.
    pub max_hold_nanos: u64,
}

/// Every site's counters read at one instant.
#[derive(Debug, Clone, Copy)]
pub struct LockStatsSnapshot {
    sites: [SiteSnapshot; LockSite::COUNT],
}

impl Default for LockStatsSnapshot {
    fn default() -> Self {
        Self {
            sites: [SiteSnapshot::default(); LockSite::COUNT],
        }
    }
}

impl LockStatsSnapshot {
    pub fn site(&self, site: LockSite) -> SiteSnapshot {
        self.sites[site.index()]
    }

    /// What accumulated between `earlier` and this snapshot.
    ///
    /// Counts and totals subtract. `max_hold_nanos` carries this
    /// snapshot's running maximum, so a window reports the largest hold
    /// the volume has seen rather than the largest within the window.
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
            }),
        }
    }

    /// Total hold across every site.
    pub fn total_hold(&self) -> Duration {
        Duration::from_nanos(self.sites.iter().map(|s| s.hold_nanos).sum())
    }

    /// One line naming every site that acquired, ordered by hold time
    /// descending. `None` when nothing acquired, which is what keeps an
    /// idle volume silent.
    pub fn report(&self) -> Option<String> {
        let mut active: Vec<(LockSite, SiteSnapshot)> = LockSite::ALL
            .iter()
            .map(|&site| (site, self.site(site)))
            .filter(|(_, s)| s.acquisitions > 0)
            .collect();
        if active.is_empty() {
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

    /// A window reports what accumulated in it. The maximum is the one
    /// quantity that cannot subtract, so it stays cumulative.
    #[test]
    fn since_subtracts_totals_and_carries_the_maximum() {
        let stats = LockStats::default();
        stats.record(
            LockSite::GcPlanApply,
            Duration::ZERO,
            Duration::from_millis(20),
        );
        let mark = stats.snapshot();
        stats.record(
            LockSite::GcPlanApply,
            Duration::ZERO,
            Duration::from_millis(5),
        );

        let window = stats.snapshot().since(&mark);
        let site = window.site(LockSite::GcPlanApply);
        assert_eq!(site.acquisitions, 1);
        assert_eq!(site.hold_nanos, Duration::from_millis(5).as_nanos() as u64);
        assert_eq!(
            site.max_hold_nanos,
            Duration::from_millis(20).as_nanos() as u64
        );
    }

    #[test]
    fn an_idle_window_reports_nothing() {
        assert!(LockStatsSnapshot::default().report().is_none());
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
