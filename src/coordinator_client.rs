// Client for the coordinator inbound socket.
//
// Connects to coordinator.sock, sends one command, reads one response line.
// A new connection is made per call — the protocol is request-response-close.

use std::io::{self, BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

fn call(socket_path: &Path, cmd: &str) -> io::Result<String> {
    let mut stream = UnixStream::connect(socket_path).map_err(|e| {
        io::Error::other(format!(
            "coordinator not running ({}): {e}",
            socket_path.display()
        ))
    })?;
    writeln!(stream, "{cmd}")?;
    stream.flush()?;
    stream.shutdown(std::net::Shutdown::Write)?;
    let mut reader = io::BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

/// Trigger an immediate fork discovery pass.
/// Returns `Ok(())` on success, or an error if the coordinator is not running.
pub fn rescan(socket_path: &Path) -> io::Result<()> {
    let resp = call(socket_path, "rescan")?;
    if resp == "ok" {
        Ok(())
    } else {
        Err(io::Error::other(format!("unexpected response: {resp}")))
    }
}

/// Query the running state of a named volume.
pub fn status(socket_path: &Path, volume: &str) -> io::Result<String> {
    call(socket_path, &format!("status {volume}"))
}
