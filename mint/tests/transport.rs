//! UDS transport end-to-end (`docs/design-mint.md` § *Transport*): the
//! bundled single-host dev shape. Every other test drives the router
//! in-process via `tower::oneshot`; this one binds a real
//! `UnixListener`, serves the router with `axum::serve`, and runs the
//! reference client over `--socket <path>` — exercising the server
//! bind+chmod path, the `unix:` scheme parse, and the `hyperlocal`
//! client leg that `reqwest` cannot do. The macaroon + Ed25519 PoP is
//! identical to the TCP path, so a green full flow here proves the
//! transport seam, not the auth.

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use mint::audit::AuditLog;
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::mint_invite;
use mint::keyring::Keyring;
use mint::state::{K_M_A_FILE, Store};

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const K_M_A: [u8; 32] = [13u8; 32];
const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ORG_ID: &str = "demo";
const AUTH_URL: &str = "https://auth.example/v1/discharge";

const TOML: &str = r#"
audience = "mint"
[store]
bucket = "demo-bucket"
[auth]
location = "https://auth.example/v1/discharge"
[auth.demo]
enabled = true
[attestation]
location = "https://attest.example/v1/discharge"
[attestation.demo]
enabled = true
[[role]]
name = "writer"
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 900
policy_file = "writer.json"
[role.template]
attested = ["project"]
[role.attestation]
"#;

fn config() -> Config {
    common::parse_config(
        TOML,
        &[(
            "writer.json",
            r#"{"Version":"2012-10-17","Statement":[{"Resource":["arn:aws:s3:::demo-bucket/{{attested.project}}/*"]}]}"#,
        )],
    )
}

#[tokio::test]
async fn full_flow_over_unix_socket() {
    // Server state with a seeded root key so client-side invite
    // macaroons minted from ROOT verify.
    let srv_dir = tempfile::tempdir().expect("srv tempdir");
    let k_m_a_hex: String = K_M_A.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(srv_dir.path().join(K_M_A_FILE), k_m_a_hex).expect("seed k_m_a");
    let mut store_inner = Store::open_local_with_initial_key(srv_dir.path(), Some(ROOT))
        .await
        .expect("store");
    // Colocated demo auth: K_M-A keys the gate TPCs, K_session the
    // operator login the client performs before enrolling.
    store_inner
        .init_k_m_a(srv_dir.path(), true)
        .expect("init k_m_a");
    store_inner
        .init_k_session(srv_dir.path())
        .expect("init k_session");
    // K_M-B keys the attested TPC the exchange stamps onto the `writer`
    // credential, and the demo attestation authority's discharge route.
    store_inner
        .init_k_m_b(srv_dir.path(), true)
        .expect("init k_m_b");
    let store = Arc::new(store_inner);
    let nonce = store.current_invite().await.expect("nonce");
    let cfg = config();
    let seal = Arc::new(arc_swap::ArcSwap::from_pointee(
        mint::sealed_cache::serving_from_config(&cfg),
    ));
    let state = AppState {
        config: Arc::new(cfg),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(std::io::sink()))),
        store: store.clone(),
        seal,
    };

    // Bind the socket (listening immediately, so client connects queue
    // in the backlog even before the accept task is scheduled), chmod
    // 0o666 as the server does, then serve in the background.
    let sock = srv_dir.path().join("mint.sock");
    let listener = tokio::net::UnixListener::bind(&sock).expect("bind uds");
    std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    assert_eq!(
        std::fs::metadata(&sock).expect("stat").permissions().mode() & 0o777,
        0o666,
    );
    // The demo auth role on its own UDS, also over the transport seam:
    // the client fetches its enroll/exchange discharges here.
    let auth_sock = srv_dir.path().join("auth.sock");
    let auth_listener = tokio::net::UnixListener::bind(&auth_sock).expect("bind auth uds");
    std::fs::set_permissions(&auth_sock, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    // The demo attestation authority on a third UDS: the client fetches
    // the `writer` credential's attestation discharge here.
    let attest_sock = srv_dir.path().join("attest.sock");
    let attest_listener = tokio::net::UnixListener::bind(&attest_sock).expect("bind attest uds");
    std::fs::set_permissions(&attest_sock, std::fs::Permissions::from_mode(0o666)).expect("chmod");
    let auth_state = state.clone();
    let attest_state = state.clone();
    tokio::spawn(async move {
        axum::serve(listener, router(state)).await.expect("serve");
    });
    tokio::spawn(async move {
        axum::serve(auth_listener, mint::auth::router(auth_state))
            .await
            .expect("serve auth");
    });
    tokio::spawn(async move {
        axum::serve(attest_listener, mint::attest::router(attest_state))
            .await
            .expect("serve attest");
    });

    let url = format!("unix:{}", sock.display());
    let cdir = tempfile::tempdir().expect("client tempdir");
    // No explicit keygen — the client mints its identity lazily on the
    // first operation that needs it (enroll, below).
    // Point per-user config at a tempdir, then log in at the auth socket so
    // enroll/exchange can fetch their gate discharges. `mint login` now
    // persists the shared session + transport under `XDG_CONFIG_HOME/mint`.
    let cfg_home = tempfile::tempdir().expect("config tempdir");
    // SAFETY: single-threaded test binary; no other thread reads the env.
    unsafe { std::env::set_var("XDG_CONFIG_HOME", cfg_home.path()) };
    let auth_transport = format!("unix:{}", auth_sock.display());
    let session = mint::session::login(&auth_transport, "operator")
        .await
        .expect("shared login over uds");
    mint::session::save(&session, &auth_transport).expect("persist session");
    // As `mint login --config` does when the config colocates the demo
    // attestation authority.
    mint::session::save_attest_transport(&format!("unix:{}", attest_sock.display()))
        .expect("persist attest transport");
    let invite = mint_invite(
        &Keyring::single(ROOT),
        &K_M_A,
        "mint",
        &nonce,
        ORG_ID,
        AUTH_URL,
    )
    .encode();

    // enroll → credential ticket persisted client-side.
    mint::client::enroll(
        cdir.path(),
        &url,
        &invite,
        SUB,
        mint::client::CREDENTIAL_TICKET_FILE,
    )
    .await
    .expect("enroll over uds");

    // exchange before approval: not a failure, just not yet approved.
    let role = "writer";
    let cred = mint::client::credential_path(role);
    assert!(
        !mint::client::exchange(
            cdir.path(),
            &url,
            mint::client::CREDENTIAL_TICKET_FILE,
            role,
            &cred,
        )
        .await
        .expect("exchange call over uds"),
        "unapproved exchange must report not-yet-approved, not error",
    );

    // Operator approves, then exchange yields the credential.
    let (cnf, _fp) = mint::client::identity(cdir.path()).expect("client identity");
    let now_iso = chrono::Utc::now().to_rfc3339();
    store
        .approve(SUB, &cnf, "usr_op", &now_iso)
        .await
        .expect("approve");
    assert!(
        mint::client::exchange(
            cdir.path(),
            &url,
            mint::client::CREDENTIAL_TICKET_FILE,
            role,
            &cred,
        )
        .await
        .expect("post-approval exchange over uds"),
    );

    // assume-role returns the (fake) keypair JSON — the full chain
    // verified and a scoped credential minted, all over the sockets:
    // the client detects the credential's attested TPC, fetches the
    // discharge from the attest socket, and presents the bundle.
    let attest = ["project=apollo".to_string()];
    let kp = mint::client::assume_role(cdir.path(), &url, role, None, &[], &attest, 900, &cred)
        .await
        .expect("assume-role over uds");
    let v: serde_json::Value = serde_json::from_str(&kp).expect("keypair json");
    assert!(
        v.get("access_key_id").is_some(),
        "expected a keypair, got: {kp}"
    );
}
