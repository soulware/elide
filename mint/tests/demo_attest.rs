//! End-to-end through the colocated demo attestation authority: login at
//! the demo auth role → fetch an attestation discharge from the demo
//! verifier → assume-role renders a policy substituting **all four**
//! template namespaces (`env`, `mint`, `caveat`, `attested`). The whole
//! mint-as-verifier loop without a live Tigris or a real coordinator.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use mint::audit::AuditLog;
use mint::caveat::{Caveat, name};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::{AttestedTpc, mint_credential};
use mint::keyring::Keyring;
use mint::macaroon::Macaroon;
use mint::pop;
use mint::state::Store;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const CLIENT_SEED: [u8; 32] = [7u8; 32];
const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ATTEST_LOCATION: &str = "https://attest.elide.internal/v1/discharge";
/// The project the demo verifier attests, session-gated; the policy
/// substitutes it as `{{attested.project}}`.
const PROJECT: &str = "apollo";

const TOML_TEMPLATE: &str = r#"
audience = "mint"
[store]
bucket = "mint-demo"
[attestation]
location = "https://attest.elide.internal/v1/discharge"
[env]
bucket = "mint-demo"
prefix = "demo"
[[role]]
name = "attested-write"
min_ttl_seconds = 60
max_ttl_seconds = 900
default_ttl_seconds = 300
policy_file = "attested-write.json"
[role.template]
caveat = ["sub"]
attested = ["project"]
[role.attestation]
"#;

/// The shipped demo template: one policy substituting every namespace.
const POLICY: &str = r#"
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
    "Resource": ["arn:aws:s3:::{{env.bucket}}/{{env.prefix}}/{{caveat.sub}}/{{attested.project}}/*"],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}
"#;

fn config() -> Config {
    common::parse_config(TOML_TEMPLATE, &[("attested-write.json", POLICY)])
}

/// AppState with demo keys provisioned the way `mint serve` does under
/// `[auth.demo]` + `[attestation.demo]`: K_M-A (settling org = "demo"),
/// K_session (the login-session root), and K_M-B (the attestation
/// wrapping key). Returns the generated K_M-B so the test can stamp the
/// credential's attested TPC the way issuance does.
async fn demo_state() -> (AppState, Arc<FakeMinter>, [u8; 32], tempfile::TempDir) {
    let minter = Arc::new(FakeMinter::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config();
    let seal = Arc::new(arc_swap::ArcSwap::from_pointee(
        mint::sealed_cache::serving_from_config(&cfg),
    ));
    let mut store = Store::open_local_with_initial_key(dir.path(), Some(ROOT))
        .await
        .expect("store");
    store.init_k_m_a(dir.path(), true).expect("k_m_a");
    store.init_k_session(dir.path()).expect("k_session");
    store.init_k_m_b(dir.path(), true).expect("k_m_b");
    let k_m_b = *store.k_m_b().expect("k_m_b generated");
    store
        .approve(
            SUB,
            &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            "usr_test",
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .expect("approve");
    let state = AppState {
        config: Arc::new(cfg),
        minter: minter.clone(),
        audit: Arc::new(AuditLog::new(Box::new(std::io::sink()))),
        store: Arc::new(store),
        seal,
    };
    (state, minter, k_m_b, dir)
}

fn far_future() -> u64 {
    (chrono::Utc::now().timestamp() as u64) + 365 * 24 * 3600
}

/// The held `attested-write` credential, carrying the attested TPC its
/// role declares.
fn credential(k_m_b: &[u8; 32]) -> Macaroon {
    mint_credential(
        &Keyring::single(ROOT),
        "mint",
        SUB,
        &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
        "attested-write",
        0,
        Some(AttestedTpc {
            k_m_b,
            org_id: "demo",
            mode: "attested-write",
            location: ATTEST_LOCATION,
        }),
    )
    .attenuate(Caveat::scalar(name::EXP, far_future().to_string()))
}

fn tpc_cid(m: &Macaroon) -> Vec<u8> {
    m.caveats()
        .iter()
        .find_map(|c| match c {
            Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
            _ => None,
        })
        .expect("credential carries the attested TPC")
}

async fn body_string(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

/// `POST /v1/login` at the demo auth role, as `mint login` does.
async fn login(state: &AppState) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/v1/login")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"subject":"demo-operator"}"#))
        .unwrap();
    let app = mint::auth::router(state.clone());
    let (status, body) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "login: {body}");
    json_str(&body, "session")
}

/// `POST /v1/discharge` at the demo attestation authority.
async fn attest_request(
    state: &AppState,
    session: Option<&str>,
    body: serde_json::Value,
) -> (StatusCode, String) {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/v1/discharge")
        .header("content-type", "application/json");
    if let Some(s) = session {
        builder = builder.header("authorization", format!("Bearer {s}"));
    }
    let req = builder.body(Body::from(body.to_string())).unwrap();
    let app = mint::attest::router(state.clone());
    body_string(app.oneshot(req).await.unwrap()).await
}

fn json_str(body: &str, key: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(key).and_then(|s| s.as_str()).map(str::to_string))
        .unwrap_or_else(|| panic!("no {key:?} in: {body}"))
}

fn b64(cid: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cid)
}

#[tokio::test]
async fn demo_attest_loop_renders_all_four_namespaces() {
    let (state, minter, k_m_b, _dir) = demo_state().await;
    let m = credential(&k_m_b);

    // login → session-gated attestation discharge.
    let session = login(&state).await;
    let (status, body) = attest_request(
        &state,
        Some(&session),
        serde_json::json!({"cid": b64(&tpc_cid(&m)), "attested": {"project": PROJECT}}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "discharge: {body}");
    let discharge = Macaroon::decode(&json_str(&body, "discharge")).expect("discharge decodes");

    // assume-role with the bundle.
    let ts = chrono::Utc::now().timestamp() as u64;
    let body = format!("{{\"ts\":{ts},\"role\":\"attested-write\",\"ttl_seconds\":600}}");
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        m.tail(),
        body.as_bytes(),
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header(
            "authorization",
            format!("MintV1 {},{}", m.encode(), discharge.encode()),
        )
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, body) = body_string(router(state).oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "assume-role: {body}");

    // One rendered policy, every namespace in its slot: env.bucket /
    // env.prefix (sealed config), caveat.sub (primary MAC), attested
    // .project (discharge MAC), mint.expiry (computed).
    let calls = minter.calls();
    assert_eq!(calls.len(), 1);
    let policy = &calls[0].policy_json;
    assert!(
        policy.contains(&format!("arn:aws:s3:::mint-demo/demo/{SUB}/{PROJECT}/*")),
        "policy: {policy}"
    );
    assert!(policy.contains("aws:CurrentTime"), "policy: {policy}");
    // The IAM policy name's scope segment is the attested value.
    assert!(
        calls[0].policy_name.contains(PROJECT),
        "policy name: {}",
        calls[0].policy_name
    );
}

#[tokio::test]
async fn discharge_requires_a_session() {
    let (state, _minter, k_m_b, _dir) = demo_state().await;
    let m = credential(&k_m_b);
    let (status, _) = attest_request(
        &state,
        None,
        serde_json::json!({"cid": b64(&tpc_cid(&m)), "attested": {"project": PROJECT}}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discharge_refuses_reserved_attested_names() {
    // Each authority emits only its own vocabulary: the demo verifier
    // must refuse to attest a reserved control-caveat name, so its
    // discharge can never carry `sub`/`exp`/… as attested data.
    let (state, _minter, k_m_b, _dir) = demo_state().await;
    let m = credential(&k_m_b);
    let session = login(&state).await;
    for reserved in name::RESERVED {
        let (status, body) = attest_request(
            &state,
            Some(&session),
            serde_json::json!({"cid": b64(&tpc_cid(&m)), "attested": {*reserved: "forged"}}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "reserved name {reserved:?} must be refused: {body}"
        );
    }
}

#[tokio::test]
async fn discharge_refuses_an_empty_attested_set() {
    let (state, _minter, k_m_b, _dir) = demo_state().await;
    let m = credential(&k_m_b);
    let session = login(&state).await;
    let (status, _) = attest_request(
        &state,
        Some(&session),
        serde_json::json!({"cid": b64(&tpc_cid(&m)), "attested": {}}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn assume_role_without_the_discharge_is_refused() {
    // The credential carries the attested TPC; presenting it bare must
    // fail verification — the discharge is not optional.
    let (state, minter, k_m_b, _dir) = demo_state().await;
    let m = credential(&k_m_b);
    let ts = chrono::Utc::now().timestamp() as u64;
    let body = format!("{{\"ts\":{ts},\"role\":\"attested-write\",\"ttl_seconds\":600}}");
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        m.tail(),
        body.as_bytes(),
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header("authorization", format!("MintV1 {}", m.encode()))
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, _) = body_string(router(state).oneshot(req).await.unwrap()).await;
    assert_ne!(status, StatusCode::OK);
    assert!(minter.calls().is_empty(), "no keypair may be minted");
}
