//! Process-wide glibc malloc policy, installed at binary startup.
//!
//! glibc's mmap threshold is dynamic: freeing a large block raises the
//! threshold (up to 32 MiB) so subsequent large allocations land on
//! heap arenas, and the trim threshold rises in lockstep — after which
//! freed large transients are retained as process RSS instead of
//! returning to the OS. Pinning the threshold keeps every allocation
//! ≥ 1 MiB on the mmap path (freed = unmapped) and, as a side effect
//! of setting any mallopt parameter, disables the dynamic adjustment
//! entirely, so the trim threshold stays at its default and
//! top-of-heap trimming keeps working for the sub-threshold sizes.
//!
//! No-op on non-glibc targets.

#[cfg(all(unix, target_env = "gnu"))]
pub fn pin_mmap_threshold() {
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, 1 << 20);
    }
}

#[cfg(not(all(unix, target_env = "gnu")))]
pub fn pin_mmap_threshold() {}
