//! End-to-end operator-write loop: the mint CLI is the client of mint.
//!
//! A `write` role configured with `issues_with_tpc = true` produces a
//! credential bearing a third-party caveat. `assume-role` on that
//! credential is refused until the client fetches a discharge from the
//! authority and attaches it to the bundle. This drives the real client
//! (`mint::client::assume_role`) over two live UDS listeners — the mint
//! router and the colocated demo-auth router. The client logs in at the
//! auth role (`/v1/login`) and presents the session on `/v1/discharge`,
//! which is session-gated (`design-auth-service.md` § *Login flow*).

use std::os::unix::fs::PermissionsExt;
use std::sync::{Arc, Mutex};

use mint::audit::AuditLog;
use mint::caveat::Caveat;
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::keyring::Keyring;
use mint::macaroon::Macaroon;
use mint::state::Store;
use mint::{client, issuance, pop, tpc};

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const K_M_A: [u8; 32] = [13u8; 32];
const CLIENT_SEED: [u8; 32] = [7u8; 32];
const CLIENT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ORG_ID: &str = "demo";

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
    let toml = r#"
audience = "mint"
[tenant]
bucket = "demo-bucket"
[auth]
endpoint = "unix:/unused-in-this-test"
demo_enabled = true
[[role]]
name = "write"
required_caveats = ["sub", "aud", "exp"]
min_ttl_seconds = 60
max_ttl_seconds = 900
default_ttl_seconds = 300
policy_file = "write.json"
issues_with_tpc = true
"#;
    common::parse_config(toml, &[("write.json", r#"{"Version":"2012-10-17"}"#)])
}

async fn state(dir: &std::path::Path) -> AppState {
    let root_hex: String = ROOT.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("root_key"), root_hex).expect("root_key");
    let k_m_a_hex: String = K_M_A.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.join("k_m_a"), k_m_a_hex).expect("k_m_a");
    let mut store = Store::open_local(dir).await.expect("store");
    store.init_k_m_a(dir, true).expect("init_k_m_a");
    store.init_k_session(dir).expect("init_k_session");
    AppState {
        config: Arc::new(config()),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(Arc::new(Mutex::new(
            Vec::new(),
        )))))),
        store: Arc::new(store),
    }
}

/// Bind a router on `path` and serve it on a background task. The
/// listen backlog accepts the client's connection even before the
/// spawned accept loop is scheduled, so no readiness wait is needed.
fn serve(app: axum::Router, path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let listener = tokio::net::UnixListener::bind(path).expect("bind");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
}

/// Build the TPC-bearing `write` credential the way mint's
/// `enroll-exchange` would, pointing its third-party caveat at
/// `auth_location` so the client knows where to fetch the discharge.
fn write_credential(auth_location: &str) -> Macaroon {
    let ring = Keyring::single(ROOT);
    let cnf = pop::cnf_value(&CLIENT_SEED);
    let cred = issuance::mint_credential(&ring, "mint", CLIENT_ID, &cnf, "write");
    let r = tpc::derive_r(&ROOT, CLIENT_ID, 0);
    let tpc_cv = tpc::build_caveat(cred.tail(), &r, &K_M_A, CLIENT_ID, ORG_ID, auth_location);
    cred.attenuate(tpc_cv)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn write_credential_assumes_role_only_after_fetching_a_discharge() {
    let server_dir = tempfile::tempdir().expect("server dir");
    let client_dir = tempfile::tempdir().expect("client dir");

    let mint_sock = server_dir.path().join("mint.sock");
    let auth_sock = server_dir.path().join("auth.sock");
    let auth_location = format!("unix:{}", auth_sock.display());

    // Bring up the mint router and the colocated demo-auth router on
    // their own sockets, sharing one AppState.
    let st = state(server_dir.path()).await;
    serve(router(st.clone()), &mint_sock);
    serve(mint::auth::router(st.clone()), &auth_sock);

    // Lay down the client identity + the TPC-bearing credential.
    let seed_hex: String = CLIENT_SEED.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(client_dir.path().join("client.key"), seed_hex).expect("client.key");
    std::fs::create_dir_all(client_dir.path().join("credentials")).expect("creds dir");
    let cred = write_credential(&auth_location);
    std::fs::write(
        client_dir.path().join(client::credential_path("write")),
        cred.encode(),
    )
    .expect("write credential");

    // Sanity: the credential really does carry a third-party caveat
    // pointing at the auth socket — otherwise the loop below would pass
    // for the wrong reason (a TPC-free assume-role).
    assert!(
        cred.caveats().iter().any(
            |c| matches!(c, Caveat::ThirdParty { location, .. } if location == &auth_location)
        ),
        "credential should carry a third-party caveat at {auth_location}"
    );

    // The client logs in at the auth role first (`mint client login`);
    // assume_role on a TPC-bearing credential reads that saved session
    // and presents it on the session-gated `/v1/discharge`.
    client::login_cmd(client_dir.path(), &auth_location, "operator")
        .await
        .expect("client login");

    // The full loop: assume_role reads the TPC, fetches a discharge from
    // the auth socket, attaches it, and mint vends a scoped keypair.
    let mint_url = format!("unix:{}", mint_sock.display());
    let out = client::assume_role(
        client_dir.path(),
        &mint_url,
        "write",
        None,
        &[],
        300,
        &client::credential_path("write"),
    )
    .await
    .expect("assume-role with discharge should succeed");

    assert!(
        out.contains("tid_fake_"),
        "expected a minted Tigris keypair, got: {out}"
    );
}
