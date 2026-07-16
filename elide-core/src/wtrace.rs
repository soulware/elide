//! Diagnostic write-path tracing, enabled by setting `ELIDE_WRITE_TRACE`
//! in the daemon environment (any value except `0`).
//!
//! Two trace points bracket a guest write: the ublk ingress hash
//! (`src/ublk.rs`, taken the moment the kernel hands over the request)
//! and the WAL decision (`Volume::commit_or_skip`, logging the hash the
//! write path committed or no-op-skipped). Comparing the two streams
//! localises a lost or substituted write: an ingress hash with no
//! matching WAL line died in dispatch; differing hashes for the same
//! request mean the buffer changed between kernel handoff and commit.
//!
//! Diagnostic only: two extra BLAKE3 passes per write plus one log line
//! each. Leave unset in normal operation.

use std::sync::OnceLock;

/// True when `ELIDE_WRITE_TRACE` is set (any value except `0`).
/// Read once per process.
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var_os("ELIDE_WRITE_TRACE").is_some_and(|v| v != "0"))
}
