// Coordinator inbound socket.
//
// Listens on coordinator.sock for commands from the elide CLI.
// Protocol: one request line per connection, one response line, then close.
//
// Unauthenticated operations (any caller):
//   rescan              — trigger an immediate fork discovery pass
//   status <volume>     — report running state of a named volume
//
// Volume-process operations (macaroon required — not yet implemented):
//   register <volume> <fork>   — mint a per-fork macaroon (PID-bound)
//   credentials <macaroon>     — exchange macaroon for short-lived S3 creds
//
// Operator operations (operator macaroon required — not yet implemented):
//   delete <volume> <fork> <macaroon>  — stop and remove a volume

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Notify;
use tracing::{info, warn};

pub async fn serve(socket_path: &Path, roots: Arc<Vec<PathBuf>>, rescan: Arc<Notify>) {
    // Remove any stale socket file from a previous run.
    let _ = std::fs::remove_file(socket_path);

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            warn!("[inbound] failed to bind {}: {e}", socket_path.display());
            return;
        }
    };

    info!("[inbound] listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let roots = roots.clone();
                let rescan = rescan.clone();
                tokio::spawn(handle(stream, roots, rescan));
            }
            Err(e) => warn!("[inbound] accept error: {e}"),
        }
    }
}

async fn handle(stream: tokio::net::UnixStream, roots: Arc<Vec<PathBuf>>, rescan: Arc<Notify>) {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    // One request per connection: read one line, write one response, close.
    let response = match lines.next_line().await {
        Ok(Some(line)) => dispatch(line.trim(), &roots, &rescan),
        Ok(None) => return, // caller disconnected without sending a request
        Err(e) => {
            warn!("[inbound] read error: {e}");
            return;
        }
    };
    let _ = writer.write_all(format!("{response}\n").as_bytes()).await;
}

fn dispatch(line: &str, roots: &[PathBuf], rescan: &Notify) -> String {
    if line.is_empty() {
        return "err empty request".to_string();
    }

    let (op, args) = match line.split_once(' ') {
        Some((op, args)) => (op, args.trim()),
        None => (line, ""),
    };

    match op {
        "rescan" => {
            rescan.notify_one();
            "ok".to_string()
        }
        "status" => {
            if args.is_empty() {
                return "err usage: status <volume>".to_string();
            }
            volume_status(args, roots)
        }
        _ => {
            warn!("[inbound] unexpected op: {op:?}");
            format!("err unknown op: {op}")
        }
    }
}

fn volume_status(volume_name: &str, roots: &[PathBuf]) -> String {
    for root in roots {
        let vol_dir = root.join(volume_name);
        if !vol_dir.is_dir() {
            continue;
        }

        let mut running_forks = Vec::new();
        let forks_dir = vol_dir.join("forks");
        if let Ok(entries) = std::fs::read_dir(&forks_dir) {
            for entry in entries.flatten() {
                let fork_path = entry.path();
                if !fork_path.is_dir() {
                    continue;
                }
                if let Ok(text) = std::fs::read_to_string(fork_path.join("volume.pid")) {
                    if let Ok(pid) = text.trim().parse::<u32>() {
                        if pid_is_alive(pid) {
                            if let Some(name) = fork_path.file_name().and_then(|n| n.to_str()) {
                                running_forks.push(name.to_owned());
                            }
                        }
                    }
                }
            }
        }

        return if running_forks.is_empty() {
            "ok stopped".to_string()
        } else {
            running_forks.sort();
            format!("ok running {}", running_forks.join(","))
        };
    }

    format!("err volume not found: {volume_name}")
}

fn pid_is_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), None).is_ok()
}
