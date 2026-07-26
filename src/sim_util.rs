// Formatting and compression helpers shared by the offline measurement
// harnesses.

use std::io;

/// Compressed size of `target` under plain zstd at `level`, the baseline a
/// dictionary has to beat before it has earned anything.
pub fn zstd_len(level: i32, target: &[u8]) -> io::Result<usize> {
    zstd::bulk::compress(target, level)
        .map(|blob| blob.len())
        .map_err(|e| io::Error::other(format!("zstd compression failed: {e}")))
}

pub fn mib(v: u64) -> f64 {
    v as f64 / (1 << 20) as f64
}

pub fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}
