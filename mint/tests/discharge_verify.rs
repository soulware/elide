//! `/v1/verify`: mint walks a `(primary, discharges)` bundle,
//! recovers `r` for each TPC, verifies the matched discharge's chain
//! under `r`, returns aggregated caveats. End-to-end through the HTTP
//! handler.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use mint::audit::AuditLog;
use mint::caveat::{Caveat, name, op};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::keyring::Keyring;
use mint::macaroon::{self, DISCHARGE_KID, Macaroon};
use mint::pop;
use mint::state::Store;
use mint::tpc;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const K_M_A: [u8; 32] = [13u8; 32];
const CLIENT_SEED: [u8; 32] = [7u8; 32];
const CLIENT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ORG_ID: &str = "demo";
const AUTH_URL: &str = "https://auth.example/";

const TOML: &str = r#"
audience = "mint"
auth_location = "https://auth.example/"
[store]
bucket = "demo-bucket"
[demo_auth]
enabled = true
[[role]]
name = "volume-rw"
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 900
policy_file = "volume-rw.json"
tpc = { location = "https://auth.example/" }
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
    let k_m_a_hex: String = K_M_A.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join(mint::state::K_M_A_FILE), k_m_a_hex).expect("k_m_a");
    let mut store = Store::open_local_with_initial_key(dir.path(), Some(ROOT))
        .await
        .expect("store");
    store.init_k_m_a(dir.path(), true).expect("init_k_m_a");
    let cfg = config();
    let seal = Arc::new(arc_swap::ArcSwap::from_pointee(
        mint::sealed_cache::serving_from_config(&cfg),
    ));
    let state = AppState {
        config: Arc::new(cfg),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(Arc::new(Mutex::new(
            Vec::new(),
        )))))),
        store: Arc::new(store),
        seal,
    };
    (router(state), dir)
}

/// Build a TPC-bearing primary the way mint's issuance path would,
/// using the public APIs. Includes the universal caveats verify+clear
/// requires: `op=assume-role`, `aud`, `cnf` for the test client.
fn build_primary(r_epoch: u32) -> Macaroon {
    let ring = Keyring::single(ROOT);
    let cred = macaroon::mint(
        &ring,
        vec![
            Caveat::scalar(name::OP, op::ASSUME_ROLE),
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::SUB, CLIENT_ID),
            Caveat::scalar(name::CNF, pop::cnf_value(&CLIENT_SEED)),
            Caveat::scalar(name::ROLE, "volume-rw"),
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
            Caveat::scalar(name::EXP, "2099999999"),
        ],
    )
}

/// Send a verify request with the bundle in `Authorization: MintV1
/// <primary>[,<discharge>...]` and `{ts}` in the body, PoP-signed
/// under the test client seed against the primary's tail.
async fn verify_request(
    app: axum::Router,
    primary: &str,
    discharges: &[&str],
) -> (StatusCode, String) {
    verify_request_pop_seed(app, primary, discharges, &CLIENT_SEED).await
}

async fn verify_request_pop_seed(
    app: axum::Router,
    primary: &str,
    discharges: &[&str],
    pop_seed: &[u8; 32],
) -> (StatusCode, String) {
    let ts = chrono::Utc::now().timestamp() as u64;
    let body = format!("{{\"ts\":{ts}}}");
    let primary_mac = Macaroon::decode(primary).expect("decode primary for tail");
    let sig = pop::client_signature(pop_seed, primary_mac.tail(), body.as_bytes());
    let mut auth = String::from("MintV1 ");
    auth.push_str(primary);
    for d in discharges {
        auth.push(',');
        auth.push_str(d);
    }
    let req = Request::builder()
        .method("POST")
        .uri("/v1/verify")
        .header("authorization", auth)
        .header("x-mint-pop", sig)
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
            Caveat::scalar(name::OP, op::ASSUME_ROLE),
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::SUB, CLIENT_ID),
            Caveat::scalar(name::CNF, pop::cnf_value(&CLIENT_SEED)),
            Caveat::scalar(name::ROLE, "volume-rw-background"),
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

    // Tamper a byte in the wire-encoded primary without re-MACing.
    let bad_enc = {
        let wire = primary.encode();
        let body = wire.strip_prefix(macaroon::WIRE_PREFIX).unwrap();
        let mut bytes =
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, body)
                .unwrap();
        // Last byte sits in a caveat value; flipping it breaks the chain.
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        format!(
            "{}{}",
            macaroon::WIRE_PREFIX,
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes,)
        )
    };

    let (_status, body) = verify_request(app, &bad_enc, &[&discharge.encode()]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false));
}
