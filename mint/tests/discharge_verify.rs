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
const K_M_B: [u8; 32] = [21u8; 32];
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
fn build_primary() -> Macaroon {
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
    let tpc_cv = tpc::build_caveat(cred.tail(), &K_M_A, CLIENT_ID, ORG_ID, AUTH_URL);
    cred.attenuate(tpc_cv)
}

/// Recover the auth TPC's `r` the way the auth service would: decrypt
/// the CID under `K_M-A`. `r` is fresh per TPC, so it can only come
/// from the primary itself.
fn recover_r(primary: &Macaroon) -> [u8; 32] {
    let cid = primary
        .caveats()
        .iter()
        .find_map(|c| match c {
            Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
            _ => None,
        })
        .expect("TPC present");
    tpc::decrypt_cid(&K_M_A, &cid)
        .expect("recover r from cid")
        .r
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

/// A primary carrying the **attested** TPC (the volume-attestation
/// variant), built via the public issuance APIs. Same universal caveats
/// as [`build_primary`]; the TPC's CID is sealed under `K_M-B` and
/// carries an opaque `mode`.
fn build_attested_primary(mode: &str) -> Macaroon {
    let ring = Keyring::single(ROOT);
    let cred = macaroon::mint(
        &ring,
        vec![
            Caveat::scalar(name::OP, op::ASSUME_ROLE),
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::SUB, CLIENT_ID),
            Caveat::scalar(name::CNF, pop::cnf_value(&CLIENT_SEED)),
            Caveat::scalar(name::ROLE, "volume-ro"),
        ],
    );
    let tpc_cv = tpc::build_caveat_attested(cred.tail(), &K_M_B, CLIENT_ID, ORG_ID, mode, AUTH_URL);
    cred.attenuate(tpc_cv)
}

/// Mint a discharge the way the attestation coordinator would: recover
/// `r` from the attested TPC's CID under `K_M-B` (coord B has no `K_M`,
/// so it cannot re-derive `r` — it must decrypt the CID), then mint
/// rooted at that `r`. Proves the verifier's VID-side `r` and coord B's
/// CID-side `r` agree end-to-end through the HTTP handler.
fn coord_b_discharge(primary: &Macaroon) -> Macaroon {
    let cid = primary
        .caveats()
        .iter()
        .find_map(|c| match c {
            Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
            _ => None,
        })
        .expect("attested TPC present");
    let pt = tpc::decrypt_cid_attested(&K_M_B, &cid).expect("recover r from attested cid");
    macaroon::mint_under_key(
        &pt.r,
        DISCHARGE_KID,
        vec![Caveat::scalar(name::EXP, "2099999999")],
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
    let primary = build_primary();
    let discharge = build_discharge(recover_r(&primary));

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
async fn rejects_discharge_transplanted_from_another_primary() {
    // `r` is fresh per TPC: a discharge minted for one primary's caveat
    // is not MAC-valid against another primary — same client, same
    // role, same gate.
    let (app, _dir) = app().await;
    let primary = build_primary();
    let other = build_primary();
    let discharge = build_discharge(recover_r(&other));

    let (_status, body) = verify_request(app, &primary.encode(), &[&discharge.encode()]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false), "body: {body}");
    assert_eq!(v["reason"], "mac_mismatch");
}

#[tokio::test]
async fn rejects_when_discharge_missing() {
    let (app, _dir) = app().await;
    let primary = build_primary();

    let (_status, body) = verify_request(app, &primary.encode(), &[]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false));
    assert_eq!(v["reason"], "tpc_undischarged");
}

#[tokio::test]
async fn rejects_excess_discharges() {
    let (app, _dir) = app().await;
    let primary = build_primary();
    let discharge = build_discharge(recover_r(&primary));
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
async fn verifies_attested_primary_and_coord_b_discharge() {
    // The volume-attestation TPC rides the same generic discharge walk
    // as the auth TPC: mint recovers `r` from the TPC's VID, coord B
    // recovered the same `r` from the CID under K_M-B, and the discharge
    // minted under it verifies. mint needs no K_M-B to verify (VID is
    // key-agnostic) — the store here holds only K_M-A.
    let (app, _dir) = app().await;
    let primary = build_attested_primary("volume-ro");
    let discharge = coord_b_discharge(&primary);

    let (status, body) = verify_request(app, &primary.encode(), &[&discharge.encode()]).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(true), "body: {body}");
}

#[tokio::test]
async fn rejects_attested_discharge_transplanted_across_modes() {
    // The cross-mode transplant: the same coordinator holds a volume-ro
    // and a volume-rw credential. A discharge coord B mints for the
    // volume-ro caveat (whose predicate admits ancestors) must not
    // MAC-verify against the volume-rw credential — fresh per-TPC `r`
    // is what binds each discharge to the caveat it was minted for.
    let (app, _dir) = app().await;
    let primary_ro = build_attested_primary("volume-ro");
    let primary_rw = build_attested_primary("volume-rw");
    let discharge = coord_b_discharge(&primary_ro);

    let (_status, body) = verify_request(app, &primary_rw.encode(), &[&discharge.encode()]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false), "body: {body}");
    assert_eq!(v["reason"], "mac_mismatch");
}

#[tokio::test]
async fn rejects_attested_primary_when_discharge_missing() {
    // The load-bearing invariant: a credential carrying the attested TPC
    // is inert without a discharge — it cannot clear at assume-role.
    let (app, _dir) = app().await;
    let primary = build_attested_primary("volume-rw");

    let (_status, body) = verify_request(app, &primary.encode(), &[]).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(v["valid"], serde_json::Value::Bool(false));
    assert_eq!(v["reason"], "tpc_undischarged");
}

#[tokio::test]
async fn rejects_tampered_primary() {
    let (app, _dir) = app().await;
    let primary = build_primary();
    let discharge = build_discharge(recover_r(&primary));

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
