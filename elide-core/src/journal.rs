// The ext4 jbd2 journal occupies a fixed set of LBA ranges (inode 8's
// extents). Writes in that window are cyclically overwritten copies of
// metadata blocks, the shortest-lived data on the device, and the
// extent index refuses to keep them as dedup canonicals when a copy at
// a stable LBA exists (`ExtentIndex::insert_if_absent`).

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
}
