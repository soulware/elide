// The ext4 jbd2 journal occupies a fixed set of LBA ranges (inode 8's
// extents). Writes in that window are cyclically overwritten copies of
// metadata blocks, the shortest-lived data on the device. The extent
// index stores them in a disjoint per-segment tier so journal content
// never dedups and each journal segment reaps whole.

use serde::{Deserialize, Serialize};

/// Sorted, coalesced set of journal LBA ranges. Empty means no journal
/// awareness: unknown filesystem, external journal, or parse failure.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct JournalRanges {
    ranges: Vec<(u64, u64)>,
}

/// The empty window, for contexts with no journal awareness. A
/// `static` (not an associated const) so `&EMPTY` has a `'static`
/// lifetime.
pub static EMPTY: JournalRanges = JournalRanges { ranges: Vec::new() };

impl JournalRanges {
    /// Normalise `(start_lba, lba_count)` pairs: drop empties, sort,
    /// coalesce adjacent and overlapping ranges.
    pub fn new(mut ranges: Vec<(u64, u64)>) -> Self {
        ranges.retain(|&(_, len)| len > 0);
        ranges.sort_unstable();
        let mut coalesced: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, len) in ranges {
            match coalesced.last_mut() {
                Some((prev_start, prev_len)) if start <= *prev_start + *prev_len => {
                    *prev_len = (*prev_len).max(start + len - *prev_start);
                }
                _ => coalesced.push((start, len)),
            }
        }
        Self { ranges: coalesced }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Whether `lba` falls inside a journal range.
    pub fn contains(&self, lba: u64) -> bool {
        let i = self.ranges.partition_point(|&(start, _)| start <= lba);
        i > 0 && {
            let (start, len) = self.ranges[i - 1];
            lba < start + len
        }
    }

    pub fn as_slice(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    /// Total LBAs covered.
    pub fn lba_count(&self) -> u64 {
        self.ranges.iter().map(|&(_, len)| len).sum()
    }

    /// Whether `[start_lba, start_lba + lba_count)` crosses a window
    /// boundary — a run that is neither fully inside one journal range
    /// nor fully outside all of them. The ranges are few (jbd2 journals
    /// are one or two extents), so a linear scan beats building anything.
    pub fn crosses_boundary(&self, start_lba: u64, lba_count: u32) -> bool {
        let end = start_lba + lba_count as u64;
        self.ranges.iter().any(|&(s, l)| {
            let range_end = s + l;
            (s > start_lba && s < end) || (range_end > start_lba && range_end < end)
        })
    }

    /// Split `[start_lba, start_lba + lba_count)` at every window
    /// boundary it crosses. Each returned `(start, len)` run lies fully
    /// inside one journal range or fully outside all of them, in LBA
    /// order; a run that crosses nothing comes back whole.
    pub fn split_at_boundaries(&self, start_lba: u64, lba_count: u32) -> Vec<(u64, u32)> {
        let end = start_lba + lba_count as u64;
        // Ranges are sorted and disjoint, so their starts and ends form
        // an ascending boundary sequence; keep the cuts interior to the
        // run.
        let cuts = self
            .ranges
            .iter()
            .flat_map(|&(s, l)| [s, s + l])
            .filter(|&b| b > start_lba && b < end);
        let mut runs = Vec::new();
        let mut cursor = start_lba;
        for cut in cuts {
            runs.push((cursor, (cut - cursor) as u32));
            cursor = cut;
        }
        runs.push((cursor, (end - cursor) as u32));
        runs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_hits_inside_and_misses_outside() {
        let r = JournalRanges::new(vec![(100, 10), (200, 5)]);
        assert!(!r.contains(99));
        assert!(r.contains(100));
        assert!(r.contains(109));
        assert!(!r.contains(110));
        assert!(r.contains(204));
        assert!(!r.contains(205));
    }

    #[test]
    fn new_sorts_coalesces_and_drops_empty() {
        let r = JournalRanges::new(vec![(200, 5), (0, 0), (100, 10), (110, 4), (108, 3)]);
        assert_eq!(r.as_slice(), &[(100, 14), (200, 5)]);
        assert_eq!(r.lba_count(), 19);
    }

    #[test]
    fn empty_contains_nothing() {
        let r = JournalRanges::default();
        assert!(!r.contains(0));
        assert!(r.is_empty());
    }

    #[test]
    fn crosses_boundary_detects_entering_and_leaving_runs() {
        let r = JournalRanges::new(vec![(100, 10)]);
        assert!(
            !r.crosses_boundary(90, 10),
            "ends exactly at the window start"
        );
        assert!(r.crosses_boundary(95, 10), "enters the window mid-run");
        assert!(!r.crosses_boundary(100, 10), "exactly the window");
        assert!(!r.crosses_boundary(102, 4), "fully inside");
        assert!(r.crosses_boundary(105, 10), "leaves the window mid-run");
        assert!(
            !r.crosses_boundary(110, 5),
            "starts exactly at the window end"
        );
        assert!(r.crosses_boundary(95, 20), "spans the whole window");
        assert!(!JournalRanges::default().crosses_boundary(0, 100));
    }

    #[test]
    fn split_at_boundaries_yields_uniform_runs() {
        let r = JournalRanges::new(vec![(100, 10), (200, 5)]);
        assert_eq!(r.split_at_boundaries(102, 4), vec![(102, 4)]);
        assert_eq!(r.split_at_boundaries(95, 10), vec![(95, 5), (100, 5)]);
        assert_eq!(
            r.split_at_boundaries(95, 20),
            vec![(95, 5), (100, 10), (110, 5)]
        );
        assert_eq!(
            r.split_at_boundaries(90, 120),
            vec![(90, 10), (100, 10), (110, 90), (200, 5), (205, 5)]
        );
        for (start, len) in r.split_at_boundaries(90, 120) {
            let inside = r.contains(start);
            for lba in start..start + len as u64 {
                assert_eq!(r.contains(lba), inside, "run [{start},+{len}) mixes tiers");
            }
        }
    }
}
