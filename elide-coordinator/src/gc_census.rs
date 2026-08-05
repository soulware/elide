//! Density-versus-age census over the segments a GC pass classified.
//!
//! `collect_stats` already walks every committed segment entry by entry, so
//! the density of each one is known once per pass. This groups those
//! densities by segment age and pool and logs the distribution, which is
//! what shows whether old segments converge toward fully dead or plateau
//! with a live residue.

use crate::gc::SegmentPool;
use chrono::Utc;
use tracing::info;
use ulid::Ulid;

/// Upper bound in milliseconds for each age bucket, ordered ascending.
const AGE_BUCKETS: [(&str, u64); 7] = [
    ("<1m", 60_000),
    ("1-5m", 300_000),
    ("5-15m", 900_000),
    ("15-60m", 3_600_000),
    ("1-6h", 21_600_000),
    ("6-24h", 86_400_000),
    (">24h", u64::MAX),
];

const POOL_LABELS: [&str; 3] = ["stable", "journal", "tombstone"];

fn pool_index(pool: SegmentPool) -> usize {
    match pool {
        SegmentPool::Stable => 0,
        SegmentPool::Journal => 1,
        SegmentPool::Tombstone => 2,
    }
}

#[derive(Clone, Copy)]
struct Cell {
    count: usize,
    fully_dead: usize,
    stored_bytes: u64,
    density_sum: f64,
    density_min: f64,
}

impl Cell {
    const fn new() -> Self {
        Self {
            count: 0,
            fully_dead: 0,
            stored_bytes: 0,
            density_sum: 0.0,
            density_min: f64::INFINITY,
        }
    }

    fn mean_density(&self) -> f64 {
        if self.count > 0 {
            self.density_sum / self.count as f64
        } else {
            0.0
        }
    }
}

pub struct DensityCensus {
    now_ms: u64,
    cells: [[Cell; AGE_BUCKETS.len()]; POOL_LABELS.len()],
}

impl DensityCensus {
    pub fn now() -> Self {
        Self::at(Utc::now().timestamp_millis().max(0) as u64)
    }

    fn at(now_ms: u64) -> Self {
        Self {
            now_ms,
            cells: [[Cell::new(); AGE_BUCKETS.len()]; POOL_LABELS.len()],
        }
    }

    /// Age comes from the ULID's own timestamp, so a GC output reports the
    /// age of the content it carries rather than the moment it was written
    /// (`max(inputs).increment()` is history-derived). Content age is what
    /// the convergence question asks about.
    pub fn record(&mut self, ulid: Ulid, pool: SegmentPool, density: f64, stored_bytes: u64) {
        let age_ms = self.now_ms.saturating_sub(ulid.timestamp_ms());
        let age_idx = AGE_BUCKETS
            .iter()
            .position(|(_, upper)| age_ms < *upper)
            .unwrap_or(AGE_BUCKETS.len() - 1);

        let cell = &mut self.cells[pool_index(pool)][age_idx];
        cell.count += 1;
        cell.stored_bytes += stored_bytes;
        cell.density_sum += density;
        cell.density_min = cell.density_min.min(density);
        if density == 0.0 {
            cell.fully_dead += 1;
        }
    }

    /// One line per populated pool, age buckets inline oldest-last.
    pub fn log(&self, vol_ulid: Ulid) {
        for (pool_idx, label) in POOL_LABELS.iter().enumerate() {
            let row = &self.cells[pool_idx];
            let total: usize = row.iter().map(|c| c.count).sum();
            if total == 0 {
                continue;
            }
            let bytes: u64 = row.iter().map(|c| c.stored_bytes).sum();
            let dead: usize = row.iter().map(|c| c.fully_dead).sum();

            let mut buf = String::new();
            for (age_idx, (age_label, _)) in AGE_BUCKETS.iter().enumerate() {
                let cell = &row[age_idx];
                if cell.count == 0 {
                    continue;
                }
                buf.push_str(&format!(
                    " | {age_label} n={} dead={} mean={:.2} min={:.2}",
                    cell.count,
                    cell.fully_dead,
                    cell.mean_density(),
                    cell.density_min,
                ));
            }
            info!("[gc census {vol_ulid}] pool={label} n={total} dead={dead} bytes={bytes}{buf}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: u64 = 60_000;

    fn ulid_at(ms: u64) -> Ulid {
        Ulid::from_parts(ms, 0)
    }

    fn census_at(now_ms: u64) -> DensityCensus {
        DensityCensus::at(now_ms)
    }

    #[test]
    fn records_land_in_the_bucket_matching_their_age() {
        let now = 100 * MINUTE;
        let mut c = census_at(now);
        // One segment per bucket boundary, youngest first.
        c.record(ulid_at(now - 30_000), SegmentPool::Stable, 1.0, 10);
        c.record(ulid_at(now - 3 * MINUTE), SegmentPool::Stable, 0.8, 20);
        c.record(ulid_at(now - 10 * MINUTE), SegmentPool::Stable, 0.5, 30);
        c.record(ulid_at(now - 30 * MINUTE), SegmentPool::Stable, 0.0, 40);

        let row = &c.cells[pool_index(SegmentPool::Stable)];
        assert_eq!(row[0].count, 1, "<1m");
        assert_eq!(row[1].count, 1, "1-5m");
        assert_eq!(row[2].count, 1, "5-15m");
        assert_eq!(row[3].count, 1, "15-60m");
        assert_eq!(row[3].fully_dead, 1, "a zero-density segment counts dead");
        assert_eq!(row[4].count, 0, "1-6h stays empty");
    }

    #[test]
    fn a_segment_older_than_every_bound_lands_in_the_last_bucket() {
        let now = 400 * 24 * MINUTE * 60;
        let mut c = census_at(now);
        c.record(ulid_at(0), SegmentPool::Stable, 0.3, 7);
        let row = &c.cells[pool_index(SegmentPool::Stable)];
        assert_eq!(row[AGE_BUCKETS.len() - 1].count, 1, ">24h");
    }

    #[test]
    fn a_ulid_ahead_of_now_lands_in_the_youngest_bucket() {
        let mut c = census_at(MINUTE);
        c.record(ulid_at(10 * MINUTE), SegmentPool::Stable, 1.0, 1);
        let row = &c.cells[pool_index(SegmentPool::Stable)];
        assert_eq!(row[0].count, 1, "saturating age puts it at zero");
    }

    #[test]
    fn each_pool_accumulates_separately() {
        let now = 100 * MINUTE;
        let mut c = census_at(now);
        c.record(ulid_at(now), SegmentPool::Stable, 1.0, 10);
        c.record(ulid_at(now), SegmentPool::Journal, 0.5, 20);
        c.record(ulid_at(now), SegmentPool::Tombstone, 0.0, 30);

        for pool in [
            SegmentPool::Stable,
            SegmentPool::Journal,
            SegmentPool::Tombstone,
        ] {
            assert_eq!(c.cells[pool_index(pool)][0].count, 1, "{pool:?}");
        }
        assert_eq!(c.cells[pool_index(SegmentPool::Tombstone)][0].fully_dead, 1);
    }

    #[test]
    fn mean_and_min_track_the_recorded_densities() {
        let now = 100 * MINUTE;
        let mut c = census_at(now);
        c.record(ulid_at(now), SegmentPool::Stable, 1.0, 1);
        c.record(ulid_at(now), SegmentPool::Stable, 0.4, 1);
        let cell = &c.cells[pool_index(SegmentPool::Stable)][0];
        assert!((cell.mean_density() - 0.7).abs() < 1e-9);
        assert!((cell.density_min - 0.4).abs() < 1e-9);
    }
}
