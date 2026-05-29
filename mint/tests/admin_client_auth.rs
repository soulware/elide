//! The operator admin CLI must present an admin macaroon: the
//! `/v1/admin/*` endpoints are macaroon-gated, so the admin client
//! attaches `AdminTarget.auth` as `Authorization: MintV1 …`. Without
//! it the gate answers 401 (the bug that broke `mint invite`). Drives
//! the real client (`mint::admin::get_invite`) over a live UDS.

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use mint::admin::{self, AdminTarget, AdminTransport};
use mint::audit::AuditLog;
use mint::config::Config;
use mint::http::AppState;
use mint::iam::FakeMinter;
use mint::keyring::Keyring;
use mint::state::Store;

mod common;

const ROOT: [u8; 32] = [42u8; 32];

#[derive(Clone)]
struct AuditSink(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for AuditSink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("poisoned"))?
            .extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn config() -> Config {
    common::parse_config("audience = \"mint\"\n[tenant]\nbucket = \"demo\"\n", &[])
}

async fn state() -> AppState {
    let store = Arc::new(Store::open_in_memory(ROOT).await.expect("store"));
    AppState {
        config: Arc::new(config()),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(Arc::new(Mutex::new(
            Vec::new(),
        )))))),
        store,
    }
}

fn serve(app: axum::Router, path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path).expect("bind");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
}

/// A super-admin macaroon under the server's keyring — the same shape
/// `serve` writes to `admin.bootstrap`.
fn super_admin_token() -> String {
    mint::issuance::mint_admin_token(&Keyring::single(ROOT), "mint", "human", None, None).encode()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admin_invite_requires_the_admin_macaroon() {
    let dir = tempfile::tempdir().expect("dir");
    let sock = dir.path().join("mint.sock");
    serve(admin::router(state().await), &sock);

    // No admin macaroon → the gate rejects (this is what 401'd `mint
    // invite` before the client attached one).
    let unauthenticated = admin::get_invite(AdminTarget {
        transport: AdminTransport::Uds(&sock),
        auth: None,
    })
    .await;
    assert!(
        unauthenticated.is_err(),
        "an unauthenticated admin request must be rejected"
    );

    // With the bootstrap-style super-admin token → succeeds.
    let resp = admin::get_invite(AdminTarget {
        transport: AdminTransport::Uds(&sock),
        auth: Some(super_admin_token()),
    })
    .await
    .expect("an admin macaroon must be accepted");
    assert!(
        !resp.macaroon.is_empty(),
        "the invite macaroon is returned on success"
    );
}
