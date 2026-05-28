//! End-to-end demo-auth flow: operator CLI gets a discharge from
//! `/v1/discharge` (mint-as-auth), then uses it to hit
//! `POST /v1/admin/invite` (the migrated admin endpoint). Exercises
//! the full bundle-in-Authorization + cnf+PoP + discharge-as-primary
//! verifier path.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use mint::audit::AuditLog;
use mint::auth;
use mint::caveat::{Caveat, name};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::macaroon::{self, DISCHARGE_KID, Macaroon};
use mint::pop;
use mint::state::Store;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const K_M_A: [u8; 32] = [13u8; 32];
const OPERATOR_SEED: [u8; 32] = [55u8; 32];

const TOML: &str = r#"
audience = "mint"
[tenant]
bucket = "demo-bucket"
[auth]
endpoint = "https://auth.example/"
demo_enabled = true
[[role]]
name = "volume-rw"
required_caveats = []
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 900
policy_file = "volume-rw.json"
issues_with_tpc = true
"#;

fn config() -> Config {
    common::parse_config(TOML, &[("volume-rw.json", r#"{"Version":"2012-10-17"}"#)])
}

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

async fn app() -> (Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root_hex: String = ROOT.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join("root_key"), root_hex).expect("root_key");
    let k_m_a_hex: String = K_M_A.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join("k_m_a"), k_m_a_hex).expect("k_m_a");
    let mut store = Store::open_local(dir.path()).await.expect("store");
    store.init_k_m_a(dir.path(), true).expect("init_k_m_a");
    let state = AppState {
        config: Arc::new(config()),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(Arc::new(Mutex::new(
            Vec::new(),
        )))))),
        store: Arc::new(store),
    };
    let app = auth::mount(router(state.clone()), state.clone());
    let app = mint::admin::mount(app, state);
    (app, dir)
}

async fn body_string(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

/// Request a discharge from mint-as-auth for the given action,
/// bound to the operator's pubkey.
async fn fetch_discharge(app: Router, action: &str) -> Macaroon {
    let req_body = serde_json::json!({
        "ts": now(),
        "action": action,
        "cnf": pop::cnf_value(&OPERATOR_SEED),
    })
    .to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/discharge")
        .header("content-type", "application/json")
        .body(Body::from(req_body))
        .unwrap();
    let (status, body) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "discharge body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    Macaroon::decode(v["discharge"].as_str().expect("discharge field")).expect("decode")
}

#[tokio::test]
async fn happy_path_discharge_then_invite_read() {
    let (app, _dir) = app().await;
    let discharge = fetch_discharge(app.clone(), "admin:invite-read").await;
    assert_eq!(discharge.kid(), DISCHARGE_KID);

    // Now POST /v1/admin/invite with the discharge + PoP.
    let body = format!(r#"{{"ts":{}}}"#, now());
    let sig = pop::client_signature(&OPERATOR_SEED, discharge.tail(), body.as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/invite")
        .header("authorization", format!("MintV1 {}", discharge.encode()))
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, body) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "invite body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["macaroon"].as_str().is_some(), "no macaroon in {body}");
    assert!(v["nonce"].as_str().is_some(), "no nonce in {body}");
}

#[tokio::test]
async fn wrong_action_discharge_rejected() {
    // Discharge minted for a different action — verify+clear should
    // reject because the endpoint clears op=admin:invite-read.
    let (app, _dir) = app().await;
    let discharge = fetch_discharge(app.clone(), "admin:enroll-approve").await;
    let body = format!(r#"{{"ts":{}}}"#, now());
    let sig = pop::client_signature(&OPERATOR_SEED, discharge.tail(), body.as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/invite")
        .header("authorization", format!("MintV1 {}", discharge.encode()))
        .header("x-mint-pop", sig)
        .body(Body::from(body))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pop_signed_by_wrong_key_rejected() {
    let (app, _dir) = app().await;
    let discharge = fetch_discharge(app.clone(), "admin:invite-read").await;
    let body = format!(r#"{{"ts":{}}}"#, now());
    // Sign with a key that doesn't match the cnf in the discharge.
    let other_seed = [99u8; 32];
    let sig = pop::client_signature(&other_seed, discharge.tail(), body.as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/invite")
        .header("authorization", format!("MintV1 {}", discharge.encode()))
        .header("x-mint-pop", sig)
        .body(Body::from(body))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_discharge_under_wrong_kma_rejected() {
    // An attacker tries to forge a discharge by minting one under
    // wrong K_M-A. verify_and_clear's resolve_primary_key recovers `r`
    // from the (correct) K_M-A and the chain MAC fails.
    let (app, _dir) = app().await;
    let wrong_k_m_a = [99u8; 32];
    let mut nonce = [0u8; 16];
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(&mut nonce);
    let r = auth::derive_discharge_r(&wrong_k_m_a, &nonce);
    let forged = macaroon::mint_under_key_with_nonce(
        &r,
        DISCHARGE_KID,
        nonce,
        vec![
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::OP, "admin:invite-read"),
            Caveat::scalar(name::CNF, pop::cnf_value(&OPERATOR_SEED)),
            Caveat::scalar(name::EXP, (now() + 300).to_string()),
        ],
    );
    let body = format!(r#"{{"ts":{}}}"#, now());
    let sig = pop::client_signature(&OPERATOR_SEED, forged.tail(), body.as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/invite")
        .header("authorization", format!("MintV1 {}", forged.encode()))
        .header("x-mint-pop", sig)
        .body(Body::from(body))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn old_get_path_still_works_with_admin_macaroon() {
    // Sanity: the migration is additive — the existing
    // `GET /v1/admin/invite` path still works with an admin macaroon
    // until the follow-up PR removes it.
    let (app, _dir) = app().await;
    let admin = mint::issuance::mint_admin_token(
        &mint::keyring::Keyring::single(ROOT),
        "mint",
        "alice",
        None,
        None,
    );
    let req = Request::builder()
        .method("GET")
        .uri("/v1/admin/invite")
        .header("authorization", format!("MintV1 {}", admin.encode()))
        .body(Body::empty())
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK);
}
