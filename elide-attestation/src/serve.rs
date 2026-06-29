//! Bind the discharge router on a TCP or Unix-domain socket. coord B is a
//! separate mode from peer fetch with its own listener, so it carries its
//! own (tiny) serve helpers rather than sharing peer-fetch's. A UDS keeps
//! the discharge endpoint off the network, reachable only by a co-located
//! coord A (`docs/design/mint-volume-attestation.md` § *Proposed:
//! per-endpoint transport*).

use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use tokio::net::{TcpListener, UnixListener};

/// Bind a TCP listener at `addr` and serve `router` until it stops.
pub async fn serve_tcp(addr: SocketAddr, router: Router) -> io::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, router)
        .await
        .map_err(io::Error::other)
}

/// Bind a Unix-domain-socket listener at `path` and serve `router`. Removes
/// a stale socket file first so a restart rebinds cleanly.
pub async fn serve_uds(path: PathBuf, router: Router) -> io::Result<()> {
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    axum::serve(listener, router)
        .await
        .map_err(io::Error::other)
}
