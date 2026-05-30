//! End-to-end demo-auth flow for the admin surface. The operator holds
//! the deployment's **cli-token** (a mint-issued primary with a machine
//! `cnf` and a third-party caveat), logs in at the demo auth role
//! (`POST /v1/login`), fetches a **wide** discharge for that token's TPC
//! (`POST /v1/discharge`), then per call attenuates `op=admin:<verb>`
//! onto the cli-token and presents `[cli-token, discharge]` as a
//! `MintV1` bundle with a proof-of-possession over the attenuated tail.
//!
//! Exercises the full bundle verifier path the migrated `/v1/admin/*`
//! endpoints run: chain MAC under `K_M`, TPC satisfied by the discharge
//! under the `r` recovered from its `VID`, `aud`/`op` clearing, `exp`,
//! and cnf+PoP.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use mint::audit::AuditLog;
use mint::auth;
use mint::caveat::{Caveat, name};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::keyring::Keyring;
use mint::macaroon::{DISCHARGE_KID, Macaroon, mint_under_key};
use mint::pop;
use mint::state::Store;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const K_M_A: [u8; 32] = [13u8; 32];
/// The cli-token's machine key — mint-generated at first start, the
/// `cnf` the operator CLI signs PoP with. Fixed here so the test can
/// re-mint the same cli-token and sign for it.
const MACHINE_SEED: [u8; 32] = [55u8; 32];
/// The org the demo store serves (`Store::init_k_m_a` assigns `"demo"`).
/// The cli-token's TPC binds this; `/v1/discharge` cross-checks it.
const ORG: &str = "demo";
/// The TPC location — where the cli-token says to fetch a discharge. The
/// verifier recovers `r` from the `VID` regardless of location, so the
/// exact string is immaterial to verification; the test calls the auth
/// router directly.
const AUTH_LOCATION: &str = "https://auth.example/";

// The admin action vocabulary mirrors the private `ADMIN_*` consts in
// `mint::admin`: each endpoint clears exactly its own value, so the
// operator must attenuate the matching `op` onto the cli-token.
const OP_INVITE_READ: &str = "admin:invite-read";
const OP_INVITE_ROTATE: &str = "admin:invite-rotate";
const OP_ENROLL_LIST: &str = "admin:enroll-list";
const OP_ENROLL_APPROVE: &str = "admin:enroll-approve";
const OP_ENROLL_REVOKE: &str = "admin:enroll-revoke";

/// A valid ULID — `approve`/`revoke` require a `safe_sub`.
const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

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

/// (mint_router, auth_router, tempdir). The two routers live on
/// *different* listeners in production (`main.rs` binds the auth role
/// to its own UDS); the tests preserve that boundary by routing
/// `/v1/login` and `/v1/discharge` to `auth_router` and everything else
/// to `mint_router`. State is shared because `K_M-A` and `K_session`
/// are the same values at both roles — the boundary is the listener /
/// router, not the underlying secret material.
async fn app() -> (Router, Router, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let root_hex: String = ROOT.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join("root_key"), root_hex).expect("root_key");
    let k_m_a_hex: String = K_M_A.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join("k_m_a"), k_m_a_hex).expect("k_m_a");
    let mut store = Store::open_local(dir.path()).await.expect("store");
    store.init_k_m_a(dir.path(), true).expect("init_k_m_a");
    store.init_k_session(dir.path()).expect("init_k_session");
    let state = AppState {
        config: Arc::new(config()),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(Arc::new(Mutex::new(
            Vec::new(),
        )))))),
        store: Arc::new(store),
    };
    let mint_router = mint::admin::mount(router(state.clone()), state.clone());
    let auth_router = auth::router(state);
    (mint_router, auth_router, dir)
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

/// Mint the deployment's cli-token exactly as `main.rs` does at first
/// start: a mint-issued chain carrying `aud` + the machine `cnf`, plus
/// the auth-location TPC. Keyed by the store's root (`kid=0`).
fn cli_token() -> Macaroon {
    let kr = Keyring::single(ROOT);
    let cnf = pop::cnf_value(&MACHINE_SEED);
    mint::issuance::mint_cli_token(&kr, &K_M_A, "mint", &cnf, ORG, AUTH_LOCATION)
}

/// Read the base64 `CID` off the cli-token's third-party caveat — what
/// the operator CLI POSTs to `/v1/discharge` to ask the auth role for a
/// discharge satisfying that caveat.
fn cli_token_cid(token: &Macaroon) -> String {
    for c in token.caveats() {
        if let Caveat::ThirdParty { cid, .. } = c {
            return BASE64.encode(cid);
        }
    }
    panic!("cli-token has no third-party caveat");
}

/// Trivially log in at the demo auth role (`POST /v1/login`), returning
/// the session bearer. The demo accepts any subject with no password —
/// the session is the gate on discharge issuance, not an identity.
async fn login(auth_router: Router, subject: &str) -> String {
    let body = serde_json::json!({ "subject": subject }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/login")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, body) = body_string(auth_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "login body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    v["session"].as_str().expect("session field").to_string()
}

/// Fetch a wide discharge for the cli-token's CID from the auth role on
/// its dedicated router. In production this hits a separate UDS socket;
/// the test preserves the boundary by routing it to `auth_router`
/// exclusively. `/v1/discharge` requires a session bearer, so we log in
/// first.
async fn fetch_discharge(auth_router: Router, cid_b64: &str) -> Macaroon {
    let session = login(auth_router.clone(), "operator-alice").await;
    let req_body = serde_json::json!({ "cid": cid_b64 }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/discharge")
        .header("authorization", format!("Bearer {session}"))
        .header("content-type", "application/json")
        .body(Body::from(req_body))
        .unwrap();
    let (status, body) = body_string(auth_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "discharge body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    Macaroon::decode(v["discharge"].as_str().expect("discharge field")).expect("decode")
}

/// Assemble the per-call admin request: attenuate `op` onto the
/// cli-token, build the `MintV1 <cli-token>,<discharge>` bundle, and
/// PoP-sign the attenuated tail with the machine key over `body`.
fn admin_request(
    token: &Macaroon,
    discharge: &Macaroon,
    op_value: &str,
    method: &str,
    uri: &str,
    body: &str,
) -> Request<Body> {
    let attenuated = token.clone().attenuate(Caveat::scalar(name::OP, op_value));
    let sig = pop::client_signature(&MACHINE_SEED, attenuated.tail(), body.as_bytes());
    let bundle = format!("MintV1 {},{}", attenuated.encode(), discharge.encode());
    Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", bundle)
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn happy_path_discharge_then_invite_read() {
    let (mint_router, auth_router, _dir) = app().await;
    let token = cli_token();
    let discharge = fetch_discharge(auth_router, &cli_token_cid(&token)).await;
    assert_eq!(discharge.kid(), DISCHARGE_KID);

    let body = format!(r#"{{"ts":{}}}"#, now());
    let req = admin_request(
        &token,
        &discharge,
        OP_INVITE_READ,
        "POST",
        "/v1/admin/invite",
        &body,
    );
    let (status, body) = body_string(mint_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "invite body: {body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("json");
    assert!(v["macaroon"].as_str().is_some(), "no macaroon in {body}");
    assert!(v["nonce"].as_str().is_some(), "no nonce in {body}");
}

#[tokio::test]
async fn one_wide_discharge_satisfies_every_verb() {
    // The discharge carries no `op` — per-verb narrowing is the
    // operator's attenuation onto the cli-token. So a single fetched
    // discharge serves every admin endpoint; only the attenuated `op`
    // (and the route) changes.
    let (mint_router, auth_router, _dir) = app().await;
    let token = cli_token();
    let discharge = fetch_discharge(auth_router, &cli_token_cid(&token)).await;

    let cases: &[(&str, &str, &str, String)] = &[
        (
            OP_INVITE_READ,
            "POST",
            "/v1/admin/invite",
            format!(r#"{{"ts":{}}}"#, now()),
        ),
        (
            OP_INVITE_ROTATE,
            "POST",
            "/v1/admin/invite/rotate",
            format!(r#"{{"ts":{}}}"#, now()),
        ),
        (
            OP_ENROLL_LIST,
            "POST",
            "/v1/admin/enrollments",
            format!(r#"{{"ts":{}}}"#, now()),
        ),
        (
            OP_ENROLL_APPROVE,
            "POST",
            "/v1/admin/enroll/approve",
            serde_json::json!({ "ts": now(), "sub": SUB, "pubkey": pop::cnf_value(&[1u8; 32]) })
                .to_string(),
        ),
        (
            OP_ENROLL_REVOKE,
            "POST",
            "/v1/admin/enroll/revoke",
            serde_json::json!({ "ts": now(), "sub": SUB }).to_string(),
        ),
    ];

    for (op_value, method, uri, body) in cases {
        let req = admin_request(&token, &discharge, op_value, method, uri, body);
        let (status, resp) = body_string(mint_router.clone().oneshot(req).await.unwrap()).await;
        assert_eq!(status, StatusCode::OK, "{uri} ({op_value}) body: {resp}");
    }
}

#[tokio::test]
async fn operator_client_assembles_accepted_request() {
    // Drive the *real* operator client header-assembly
    // (`Operator::authorize`) against the real verifier, closing the gap
    // between what `mint invite` produces and what the server accepts.
    // The literal UDS transport leg is exercised by the e2e walkthrough,
    // not here (the sandbox forbids socket binds).
    let (mint_router, auth_router, _dir) = app().await;

    // Persist the cli-token + machine key exactly as `mint serve` does,
    // then load the operator identity from disk.
    let op_dir = tempfile::tempdir().expect("op tempdir");
    let token = cli_token();
    std::fs::write(op_dir.path().join("cli-token"), token.encode()).expect("write cli-token");
    let seed_hex: String = MACHINE_SEED.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(op_dir.path().join("cli-token.key"), seed_hex).expect("write key");
    let operator = mint::operator::Operator::load(op_dir.path()).expect("load operator");

    let discharge = fetch_discharge(auth_router, &operator.cid_b64().expect("cid")).await;
    let body = format!(r#"{{"ts":{}}}"#, now());
    let (auth, pop) = operator.authorize(&discharge, OP_INVITE_READ, body.as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/invite")
        .header("authorization", auth)
        .header("x-mint-pop", pop)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, resp) = body_string(mint_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "invite body: {resp}");
    let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
    assert!(v["macaroon"].as_str().is_some(), "no macaroon in {resp}");
}

#[tokio::test]
async fn discharge_without_session_rejected() {
    // The gate: /v1/discharge requires a session bearer. A request with
    // a well-formed CID but no Authorization is refused before any
    // discharge is minted.
    let (_mint_router, auth_router, _dir) = app().await;
    let token = cli_token();
    let req_body = serde_json::json!({ "cid": cli_token_cid(&token) }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/discharge")
        .header("content-type", "application/json")
        .body(Body::from(req_body))
        .unwrap();
    let (status, _) = body_string(auth_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discharge_with_foreign_session_rejected() {
    // A session that verifies under a *different* K_session must not
    // open the gate — the bearer is checked, not merely parsed.
    let (_mint_router, auth_router, _dir) = app().await;
    let token = cli_token();
    let foreign = mint_under_key(
        &[0xAAu8; 32],
        mint::macaroon::SESSION_KID,
        vec![
            Caveat::scalar(name::OP, mint::caveat::op::SESSION),
            Caveat::scalar(name::SUB, "intruder"),
        ],
    );
    let req_body = serde_json::json!({ "cid": cli_token_cid(&token) }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/discharge")
        .header("authorization", format!("Bearer {}", foreign.encode()))
        .header("content-type", "application/json")
        .body(Body::from(req_body))
        .unwrap();
    let (status, _) = body_string(auth_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_op_attenuation_rejected() {
    // The cli-token attenuated for one verb cannot exercise another:
    // the endpoint clears its own `op`, so presenting an
    // `admin:enroll-approve` attenuation at `/v1/admin/invite` fails
    // op-clearing.
    let (mint_router, auth_router, _dir) = app().await;
    let token = cli_token();
    let discharge = fetch_discharge(auth_router, &cli_token_cid(&token)).await;
    let body = format!(r#"{{"ts":{}}}"#, now());
    let req = admin_request(
        &token,
        &discharge,
        OP_ENROLL_APPROVE,
        "POST",
        "/v1/admin/invite",
        &body,
    );
    let (status, _) = body_string(mint_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pop_signed_by_wrong_key_rejected() {
    // The PoP must be over the cli-token's `cnf` (the machine key).
    // Signing the attenuated tail with a different key fails cnf+PoP.
    let (mint_router, auth_router, _dir) = app().await;
    let token = cli_token();
    let discharge = fetch_discharge(auth_router, &cli_token_cid(&token)).await;
    let body = format!(r#"{{"ts":{}}}"#, now());
    let attenuated = token.attenuate(Caveat::scalar(name::OP, OP_INVITE_READ));
    let sig = pop::client_signature(&[99u8; 32], attenuated.tail(), body.as_bytes());
    let bundle = format!("MintV1 {},{}", attenuated.encode(), discharge.encode());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/invite")
        .header("authorization", bundle)
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, _) = body_string(mint_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn forged_discharge_under_wrong_r_rejected() {
    // An attacker mints a discharge under a key of their own choosing
    // (they don't hold K_M-A, so they can't recover the cli-token's
    // real `r`). verify_and_clear recovers `r` from the TPC's `VID` and
    // the forged discharge fails its chain MAC under that `r`.
    let (mint_router, _auth_router, _dir) = app().await;
    let token = cli_token();
    let forged = mint_under_key(
        &[0x11u8; 32],
        DISCHARGE_KID,
        vec![
            Caveat::scalar(name::SUB, "operator-alice"),
            Caveat::scalar(name::EXP, (now() + 300).to_string()),
        ],
    );
    let body = format!(r#"{{"ts":{}}}"#, now());
    let req = admin_request(
        &token,
        &forged,
        OP_INVITE_READ,
        "POST",
        "/v1/admin/invite",
        &body,
    );
    let (status, _) = body_string(mint_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn cli_token_without_discharge_rejected() {
    // The cli-token is inert on its own: its third-party caveat is
    // undischarged, so the bundle fails before any clearing.
    let (mint_router, _auth_router, _dir) = app().await;
    let token = cli_token();
    let body = format!(r#"{{"ts":{}}}"#, now());
    let attenuated = token.attenuate(Caveat::scalar(name::OP, OP_INVITE_READ));
    let sig = pop::client_signature(&MACHINE_SEED, attenuated.tail(), body.as_bytes());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/admin/invite")
        .header("authorization", format!("MintV1 {}", attenuated.encode()))
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, _) = body_string(mint_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn discharge_route_not_on_mint_router() {
    // Structural guard: the mint router must not expose /v1/discharge.
    // If a request to /v1/discharge hits the mint router, mint-as-auth
    // and mint roles are sharing a listener — exactly what the
    // separate-socket design prevents.
    let (mint_router, _auth_router, _dir) = app().await;
    let token = cli_token();
    let req_body = serde_json::json!({ "cid": cli_token_cid(&token) }).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/discharge")
        .header("content-type", "application/json")
        .body(Body::from(req_body))
        .unwrap();
    let (status, _) = body_string(mint_router.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
