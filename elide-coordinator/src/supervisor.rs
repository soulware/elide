// Volume process supervision.
//
// The supervisor spawns `elide serve-volume` for every discovered fork and
// restarts it if it exits. The spawned process is placed in a new session
// (setsid) so it is not affected by the coordinator's lifetime — the volume
// keeps serving if the coordinator is restarted or upgraded.
//
// Transport binding:
//   The supervisor passes `--ublk` when `volume.toml` has a `[ublk]` section;
//   without one the volume is IPC-only. Create/claim write the section by
//   default when the host can serve ublk (root with /dev/ublk-control
//   present), and `volume update --ublk/--no-ublk` flips it. The bound
//   dev_id is read by serve-volume from volume.toml itself, and the kernel
//   auto-allocates on first serve.
//
// State files written to the fork directory:
//   volume.pid  — PID of the running volume process, for display; absent when
//                 not running
//
// Re-adoption on coordinator restart:
//   The serving process holds an exclusive flock on volume.lock for its
//   lifetime. If the lock is held the supervisor waits for it to free rather
//   than double-spawning; otherwise it spawns a fresh process. The kernel
//   releases the lock on process death or host reboot, so a recycled pid can
//   never read as a live server.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tracing::{error, info, warn};

use tokio::process::Command;

use elide_coordinator::volume_state::{PID_FILE, STOPPED_FILE};
use elide_core::volume::lock_is_held;

/// Env vars the coordinator exports into each volume subprocess so the
/// volume's fetcher inherits store config without operator-level env or a
/// per-volume `fetch.toml`. Built by [`crate::config::StoreSection::child_env`].
pub type ChildEnv = Arc<Vec<(&'static str, String)>>;

const RESTART_DELAY: Duration = Duration::from_secs(1);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// A process that exits within this many seconds is considered a fast failure.
const FAST_EXIT_THRESHOLD_SECS: u64 = 5;
/// Maximum backoff delay after repeated fast failures.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Volume process exit code signalling "permanent misconfiguration — do not
/// respawn me". Mirrors `EXIT_CONFIG` in `src/ublk.rs` (BSD `EX_CONFIG`).
const EXIT_CONFIG: i32 = 78;

/// Supervise a single fork: spawn `elide serve-volume`, restart on exit.
/// Runs indefinitely; cancel the task to stop supervision.
pub async fn supervise(fork_dir: PathBuf, data_dir: PathBuf, child_env: ChildEnv) {
    let label = fork_dir.display().to_string();
    let mut fast_failures: u32 = 0;

    loop {
        // Exit if the fork directory has been removed (e.g. by `volume delete`).
        if !fork_dir.exists() {
            info!("[supervisor {label}] fork directory removed, stopping");
            break;
        }

        // Park if any park marker is present (volume.stopped or volume.released).
        if elide_coordinator::park::is_parked(&fork_dir).is_some() {
            tokio::time::sleep(POLL_INTERVAL).await;
            continue;
        }

        // ublk dev-id conflict: lowest-ULID-wins rule by dev_id.
        // Auto-allocated devices (dev_id absent) skip this
        // check — the kernel resolves them at start time.
        match elide_core::config::find_ublk_conflict(&fork_dir, &data_dir) {
            Ok(Some(conflict)) => {
                let self_name = fork_dir.file_name().and_then(|n| n.to_str());
                let other_name = conflict.dir.file_name().and_then(|n| n.to_str());
                let dominated = match (self_name, other_name) {
                    (Some(s), Some(o)) => s > o,
                    _ => true,
                };
                if dominated {
                    error!(
                        "[supervisor {label}] ublk dev id {} conflicts with '{}'; \
                         volume stopped (lower ULID wins)",
                        conflict.dev_id, conflict.name,
                    );
                    let _ = std::fs::write(fork_dir.join(STOPPED_FILE), "");
                    break;
                }
            }
            Ok(None) => {}
            Err(e) => {
                warn!("[supervisor {label}] ublk conflict check failed: {e}");
            }
        }

        // ublk requires CAP_SYS_ADMIN; without it the volume process fails to
        // open /dev/ublk-control and exits in a tight respawn loop. Catch this
        // before spawning so the user sees a single, actionable log line and
        // the volume is parked under volume.stopped.
        if requires_ublk(&fork_dir) && !is_root() {
            error!(
                "[supervisor {label}] volume requires --ublk but coordinator is not running as root. \
                 Rerun the coordinator under sudo (or grant it CAP_SYS_ADMIN), \
                 or run `elide volume update <name> --no-ublk`. Marking volume.stopped."
            );
            let _ = std::fs::write(fork_dir.join(STOPPED_FILE), "");
            continue;
        }

        // A serve-volume from a previous coordinator session (within this
        // boot) still holds the volume lock. Wait for it to exit rather than
        // double-spawning. The kernel drops the lock on process death or host
        // reboot, so after a reboot the lock is simply free and we spawn fresh.
        if lock_is_held(&fork_dir) {
            info!("[supervisor {label}] volume already being served; waiting for it to exit");
            poll_until_unlocked(&fork_dir).await;
            info!("[supervisor {label}] previous server exited");
            remove_pid(&fork_dir);
            tokio::time::sleep(RESTART_DELAY).await;
            continue;
        }

        match spawn_volume(&fork_dir, &child_env) {
            Ok(mut child) => {
                let pid = child.id().unwrap_or(0);
                info!("[supervisor {label}] started pid {pid}");
                write_pid(&fork_dir, pid);
                let started = std::time::Instant::now();
                let mut config_exit = false;
                match child.wait().await {
                    Ok(status) => {
                        info!("[supervisor {label}] pid {pid} exited: {status}");
                        if status.code() == Some(EXIT_CONFIG) {
                            config_exit = true;
                        }
                    }
                    Err(e) => warn!("[supervisor {label}] wait error: {e}"),
                }
                remove_pid(&fork_dir);
                if config_exit {
                    error!(
                        "[supervisor {label}] volume reported permanent misconfiguration; \
                         marking volume.stopped (see preceding line for cause)"
                    );
                    let _ = std::fs::write(fork_dir.join(STOPPED_FILE), "");
                    continue;
                }
                if started.elapsed().as_secs() < FAST_EXIT_THRESHOLD_SECS {
                    fast_failures = fast_failures.saturating_add(1);
                    let delay = MAX_BACKOFF.min(Duration::from_secs(1u64 << fast_failures.min(6)));
                    warn!("[supervisor {label}] fast exit #{fast_failures}, backing off {delay:?}");
                    tokio::time::sleep(delay).await;
                } else {
                    fast_failures = 0;
                    tokio::time::sleep(RESTART_DELAY).await;
                }
            }
            Err(e) => {
                error!("[supervisor {label}] failed to spawn: {e:#}");
                tokio::time::sleep(RESTART_DELAY).await;
            }
        }
    }
}

fn spawn_volume(
    fork_dir: &Path,
    child_env: &[(&'static str, String)],
) -> std::io::Result<tokio::process::Child> {
    let mut cmd = Command::new(elide_coordinator::bins::elide_bin());
    cmd.arg("serve-volume").arg(fork_dir);

    // Scrub the coordinator's S3 secrets from the spawned volume's env.
    // Volumes obtain credentials over the macaroon-authenticated IPC
    // handshake (`Register` + `Credentials`); inheriting the
    // coordinator's unscoped key via fork() would defeat per-volume
    // scoping the moment per-volume IAM lands, and is unnecessary
    // today.
    cmd.env_remove("AWS_ACCESS_KEY_ID");
    cmd.env_remove("AWS_SECRET_ACCESS_KEY");
    cmd.env_remove("AWS_SESSION_TOKEN");

    for (k, v) in child_env {
        cmd.env(k, v);
    }

    if let Ok(cfg) = elide_core::config::VolumeConfig::read(fork_dir)
        && cfg.ublk.is_some()
    {
        cmd.arg("--ublk");
    }

    // Place the child in a new session so it is not signalled when the
    // coordinator's process group receives SIGHUP or is terminated.
    // pre_exec is unsafe because the callback runs between fork() and exec()
    // where only async-signal-safe functions may be called. setsid() is
    // async-signal-safe.
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| nix::unistd::setsid().map(|_| ()).map_err(io::Error::from));
    }

    cmd.spawn()
}

/// Poll every POLL_INTERVAL until the volume lock is free.
async fn poll_until_unlocked(fork_dir: &Path) {
    loop {
        tokio::time::sleep(POLL_INTERVAL).await;
        if !lock_is_held(fork_dir) {
            break;
        }
    }
}

fn write_pid(fork_dir: &Path, pid: u32) {
    if let Err(e) = std::fs::write(fork_dir.join(PID_FILE), pid.to_string()) {
        warn!("[supervisor] failed to write pid file: {e}");
    }
}

fn remove_pid(fork_dir: &Path) {
    let _ = std::fs::remove_file(fork_dir.join(PID_FILE));
}

/// Returns true if the volume's `volume.toml` declares a `[ublk]` transport.
/// Missing or unreadable config returns false (no transport configured).
fn requires_ublk(fork_dir: &Path) -> bool {
    elide_core::config::VolumeConfig::read(fork_dir)
        .ok()
        .and_then(|cfg| cfg.ublk)
        .is_some()
}

#[cfg(unix)]
fn is_root() -> bool {
    nix::unistd::Uid::effective().is_root()
}

#[cfg(not(unix))]
fn is_root() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn pid_file_write_and_remove() {
        let tmp = TempDir::new().unwrap();
        write_pid(tmp.path(), 4242);
        assert_eq!(
            std::fs::read_to_string(tmp.path().join(PID_FILE)).unwrap(),
            "4242"
        );
        remove_pid(tmp.path());
        assert!(!tmp.path().join(PID_FILE).exists());
    }

    #[test]
    fn requires_ublk_missing_config() {
        let tmp = TempDir::new().unwrap();
        assert!(!requires_ublk(tmp.path()));
    }

    #[test]
    fn requires_ublk_empty_config() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("volume.toml"), "size = 4096\n").unwrap();
        assert!(!requires_ublk(tmp.path()));
    }

    #[test]
    fn requires_ublk_with_section() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("volume.toml"), "[ublk]\n").unwrap();
        assert!(requires_ublk(tmp.path()));
    }

    #[test]
    fn requires_ublk_with_dev_id() {
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("volume.toml"), "[ublk]\ndev_id = 7\n").unwrap();
        assert!(requires_ublk(tmp.path()));
    }
}
