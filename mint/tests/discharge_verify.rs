//! `/v1/verify`: mint walks a `(primary, discharges)` bundle,
//! recovers `r` for each TPC, verifies the matched discharge's chain
//! under `r`, returns aggregated caveats. End-to-end through the HTTP
//! handler.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mint::audit::AuditLog;
use mint::caveat::Caveat;
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::keyring::Keyring;
use mint::macaroon::{self, DISCHARGE_KID, Macaroon};
use mint::state::Store;
use mint::tpc;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const K_M_A: [u8; 32] = [13u8; 32];
const CLIENT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ORG_ID: &str = "demo";
const AUTH_URL: &str = "https://auth.example/";

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
    common::parse_config(TOML, &[("volume-rw.json", r#"{"Version":"2012-10-17"}"#)])
}

/// (router, store-handle, tempdir). Store has K_M-A pre-seeded so the
/// verifier-side handler doesn't need to materialise it itself.
async fn app() -> (axum::Router, tempfile::TempDir) {
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
    (router(state), dir)
}

/// Build a TPC-bearing primary the way mint's issuance path would,
/// using the public APIs.
fn build_primary(r_epoch: u32) -> Macaroon {
    let ring = Keyring::single(ROOT);
    let cred = macaroon::mint(
        &ring,
        vec![
            Caveat::scalar("aud", "mint"),
            Caveat::scalar("sub", CLIENT_ID),
            Caveat::scalar("role", "volume-rw"),
        ],
    );
    let r = tpc::derive_r(&ROOT, CLIENT_ID, r_epoch);
    let tpc_cv = tpc::build_caveat(cred.tail(), &r, &K_M_A, CLIENT_ID, ORG_ID, AUTH_URL);
    cred.attenuate(tpc_cv)
}

/// Build a discharge the way mint-as-auth (or a separate auth
/// service) would mint one — keyring-less mint under `r`. Verifier
/// expects this exact construction.
fn build_discharge(r: [u8; 32]) -> Macaroon {
    macaroon::mint_under_key(
        &r,
        DISCHARGE_KID,
        vec![
            Caveat::scalar("Subject", "usr_demo"),
            Caveat::scalar("NotAfter", "2099999999"),
        ],
    )
}

async fn verify_request(
    app: axum::Router,
    primary: &str,
    discharges: &[&str],
) -> (StatusCode, String) {
    let body = serde_json::json!({
        "primary": primary,
        "discharges": discharges,
    })
    .to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

#[tokio::test]
async fn verifies_matching_primary_and_discharge() {
    let (app, _dir) = app().await;
    let primary = build_primary(0);
    let r = tpc::derive_r(&ROOT, CLIENT_ID, 0);
    let discharge = build_discharge(r);

    let (status, body) = verify_request(app, &primary.encode(), &[&discharge.encode()]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(true), "body: {body}");
    // Aggregated caveats include both first-party sets.
    let caveats = v["caveats"].as_array().unwrap();
    let names: Vec<&str> = caveats
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"sub"), "got: {names:?}");
    assert!(names.contains(&"Subject"), "got: {names:?}");
}

#[tokio::test]
async fn rejects_discharge_under_wrong_r() {
    // Discharge minted under a *different* r — wrong r_epoch.
    let (app, _dir) = app().await;
    let primary = build_primary(0); // primary uses r_epoch = 0
    let wrong_r = tpc::derive_r(&ROOT, CLIENT_ID, 1);
    let discharge = build_discharge(wrong_r);

    let (_status, body) = verify_request(app, &primary.encode(), &[&discharge.encode()]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false), "body: {body}");
    assert_eq!(v["reason"], "mac_mismatch");
}

#[tokio::test]
async fn rejects_when_discharge_missing() {
    let (app, _dir) = app().await;
    let primary = build_primary(0);

    let (_status, body) = verify_request(app, &primary.encode(), &[]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false));
    assert_eq!(v["reason"], "tpc_undischarged");
}

#[tokio::test]
async fn rejects_excess_discharges() {
    let (app, _dir) = app().await;
    let primary = build_primary(0);
    let r = tpc::derive_r(&ROOT, CLIENT_ID, 0);
    let discharge = build_discharge(r);
    // Pass two discharges for a one-TPC primary.
    let d_enc = discharge.encode();

    let (_status, body) = verify_request(app, &primary.encode(), &[&d_enc, &d_enc]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false));
    assert_eq!(v["reason"], "excess_discharges");
}

#[tokio::test]
async fn verifies_tpc_free_chain_with_no_discharges() {
    // A primary with no TPCs (e.g. a background-role credential)
    // verifies cleanly when no discharges are presented.
    let (app, _dir) = app().await;
    let ring = Keyring::single(ROOT);
    let plain = macaroon::mint(
        &ring,
        vec![
            Caveat::scalar("aud", "mint"),
            Caveat::scalar("sub", CLIENT_ID),
            Caveat::scalar("role", "volume-rw-background"),
        ],
    );
    let (status, body) = verify_request(app, &plain.encode(), &[]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(true), "body: {body}");
}

#[tokio::test]
async fn rejects_tampered_primary() {
    let (app, _dir) = app().await;
    let primary = build_primary(0);
    let r = tpc::derive_r(&ROOT, CLIENT_ID, 0);
    let discharge = build_discharge(r);

    // Decode → tamper a caveat → re-encode without re-MACing.
    let mut bad = Macaroon::decode(&primary.encode()).unwrap();
    // SAFETY: tests live in the same workspace; we mutate via the
    // wire round-trip to avoid touching internals.
    let bad_enc = {
        let dec = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, bad.encode())
            .unwrap();
        let _ = &mut bad;
        // Flip a byte in the body (not at MAC offset).
        let mut bytes = dec;
        // Last byte sits in a caveat value; flipping it breaks the chain.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    };

    let (_status, body) = verify_request(app, &bad_enc, &[&discharge.encode()]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false));
}
