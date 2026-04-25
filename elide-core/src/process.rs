//! Process-introspection helpers shared across the workspace.

use nix::errno::Errno;
use nix::sys::signal::kill;
use nix::unistd::Pid;

/// Returns true if `pid` names a process that currently exists on this host.
///
/// Sends signal 0, which performs the kernel's existence/permission check
/// without delivering anything. `EPERM` is treated as alive — the process
/// exists, the caller just lacks permission to signal it (common when the
/// CLI runs unprivileged and the target was started by the root-owned
/// coordinator). Only `ESRCH` (and a `u32 → i32` overflow on absurd pids)
/// means the process is gone.
pub fn pid_is_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    match kill(Pid::from_raw(raw), None) {
        Ok(()) => true,
        Err(Errno::EPERM) => true,
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_process_is_alive() {
        assert!(pid_is_alive(std::process::id()));
    }

    #[test]
    fn nonexistent_pid_is_not_alive() {
        // u32::MAX is far above any plausible system pid_max, so the kernel
        // returns ESRCH rather than EPERM.
        assert!(!pid_is_alive(u32::MAX));
    }
}
