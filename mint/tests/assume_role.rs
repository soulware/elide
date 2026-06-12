//! End-to-end: a credential (op=assume-role) + holder-of-key PoP -> HTTP
//! -> op gate -> role gate -> policy render -> faked keypair. The whole
//! vertical slice without a live Tigris.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use mint::audit::AuditLog;
use mint::caveat::{Caveat, name, op};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::{AttestedTpc, mint_credential};
use mint::keyring::Keyring;
use mint::macaroon::{KeyRef, Macaroon, mint, mint_under_key_with_nonce};
use mint::pop;
use mint::state::Store;
use mint::tpc;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
/// Stands in for the client's Ed25519 identity-key seed.
const CLIENT_SEED: [u8; 32] = [7u8; 32];
const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
/// The attestation-coordinator wrapping key, shared mint↔coord B. The
/// test plays coord B to mint the discharge.
const K_M_B: [u8; 32] = [21u8; 32];
const ORG_ID: &str = "demo";
const ATTEST_LOCATION: &str = "https://coord-b.example/v1/discharge";
/// The target volume. It is **attested by the discharge**, not
/// self-asserted: the test's coord B stamps it as the discharge's
/// `volume` caveat, which the policy substitutes as `{{attested.volume}}`.
const VOLUME: &str = "01JQAAAAAAAAAAAAAAAAAAAAAA";

fn config() -> Config {
    common::parse_config(TOML_TEMPLATE, &[("volume-ro.json", POLICY)])
}

const TOML_TEMPLATE: &str = r#"
audience = "mint"
attestation_location = "https://coord-b.example/v1/discharge"
[store]
bucket = "demo-bucket"
[env]
bucket = "demo-bucket"
[[role]]
name = "volume-ro"
min_ttl_seconds = 60
max_ttl_seconds = 2592000
default_ttl_seconds = 2592000
policy_file = "volume-ro.json"
[role.template]
attested = ["volume"]
[role.attestation]
"#;

const POLICY: &str = r#"
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": [
      "arn:aws:s3:::{{env.bucket}}/by_id/{{attested.volume}}/*"
    ],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}
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

async fn state_with_audit() -> (
    AppState,
    Arc<Mutex<Vec<u8>>>,
    Arc<FakeMinter>,
    tempfile::TempDir,
) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let minter = Arc::new(FakeMinter::new());
    let dir = tempfile::tempdir().expect("tempdir");
    let cfg = config();
    let seal = Arc::new(arc_swap::ArcSwap::from_pointee(
        mint::sealed_cache::serving_from_config(&cfg),
    ));
    // assume-role clears the credential against a present enrolled
    // record (§ *Revocation*). Approve SUB at the implicit epoch 0 so a
    // credential minted at epoch 0 with this cnf clears.
    let store = Store::open_local_with_initial_key(dir.path(), Some(ROOT))
        .await
        .expect("store");
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
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(buf.clone())))),
        store: Arc::new(store),
        seal,
    };
    (state, buf, minter, dir)
}

fn far_future() -> u64 {
    (chrono::Utc::now().timestamp() as u64) + 365 * 24 * 3600
}

/// A held `volume-ro` credential (op=assume-role, aud, sub, cnf, role)
/// carrying the attested third-party caveat its role declares, attenuated
/// per request with a tighter `exp`. The target volume is not on the
/// credential at all — it is attested by a discharge at request time.
fn request_macaroon() -> Macaroon {
    request_macaroon_at_epoch(0)
}

fn request_macaroon_at_epoch(rev_epoch: u64) -> Macaroon {
    mint_credential(
        &Keyring::single(ROOT),
        "mint",
        SUB,
        &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
        "volume-ro",
        rev_epoch,
        Some(AttestedTpc {
            k_m_b: &K_M_B,
            org_id: ORG_ID,
            mode: "volume-ro",
            location: ATTEST_LOCATION,
        }),
    )
    .attenuate(Caveat::scalar(name::EXP, far_future().to_string()))
}

/// Mint the discharge for `primary`'s attested TPC the way coord B would:
/// recover `r` from the CID under `K_M-B`, then mint a discharge rooted at
/// it attesting `volume = VOLUME`. Returns `None` if `primary` carries no
/// TPC (a hand-built credential in a negative test).
fn discharge_for(primary: &Macaroon) -> Option<Macaroon> {
    let cid = primary.caveats().iter().find_map(|c| match c {
        Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
        _ => None,
    })?;
    let pt = tpc::decrypt_cid_attested(&K_M_B, &cid).expect("recover r from attested cid");
    Some(mint_under_key_with_nonce(
        &pt.r,
        KeyRef::Discharge,
        tpc::ticket_id(&cid),
        vec![
            Caveat::scalar("volume", VOLUME),
            Caveat::scalar(name::EXP, far_future().to_string()),
        ],
    ))
}

/// Sign and send an assume-role request, auto-attaching the coord-B
/// discharge whenever the primary carries an attested TPC.
fn signed_request(m: &Macaroon, inner_fields: &str) -> Request<Body> {
    signed_request_with_discharge(m, discharge_for(m).as_ref(), inner_fields)
}

fn signed_request_with_discharge(
    m: &Macaroon,
    discharge: Option<&Macaroon>,
    inner_fields: &str,
) -> Request<Body> {
    let ts = chrono::Utc::now().timestamp() as u64;
    let body = format!("{{\"ts\":{ts},{inner_fields}}}");
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        m.tail(),
        body.as_bytes(),
    );
    let mut auth = format!("MintV1 {}", m.encode());
    if let Some(d) = discharge {
        auth.push(',');
        auth.push_str(&d.encode());
    }
    Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header("authorization", auth)
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn body_string(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

#[tokio::test]
async fn happy_path_mints_scoped_keypair() {
    let (state, audit_buf, minter, _dir) = state_with_audit().await;
    let app = router(state);
    let m = request_macaroon();

    let req = signed_request(&m, r#""role":"volume-ro","ttl_seconds":3600"#);
    let (status, body) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.contains("tid_fake_00000000"), "body: {body}");

    // The rendered policy scopes to the discharge's **attested** volume,
    // substituted verbatim into the by_id prefix.
    let calls = minter.calls();
    assert_eq!(calls.len(), 1);
    assert!(
        calls[0]
            .policy_json
            .contains(&format!("demo-bucket/by_id/{VOLUME}/*")),
        "policy: {}",
        calls[0].policy_json
    );

    let audit = String::from_utf8(audit_buf.lock().unwrap().clone()).unwrap();
    assert!(audit.contains("\"outcome\":\"granted\""), "audit: {audit}");
}

#[tokio::test]
async fn missing_attested_value_is_rejected_before_render() {
    // A fully authorized request (gate passes) presenting a discharge that
    // verifies but omits the `volume` the role declares in its sealed
    // `attested` contract. The request-time contract check rejects it with
    // a clean 400 before render — no unscoped credential is ever minted.
    // This pins the fail-closed property now that scoping is attested.
    let (state, audit_buf, minter, _dir) = state_with_audit().await;
    let app = router(state);
    let m = request_macaroon();

    // A discharge rooted at the right `r` but attesting no `volume`.
    let cid = m
        .caveats()
        .iter()
        .find_map(|c| match c {
            Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
            _ => None,
        })
        .expect("attested TPC present");
    let r = tpc::decrypt_cid_attested(&K_M_B, &cid)
        .expect("recover r")
        .r;
    let bare_discharge = mint_under_key_with_nonce(
        &r,
        KeyRef::Discharge,
        tpc::ticket_id(&cid),
        vec![Caveat::scalar(name::EXP, far_future().to_string())],
    );

    let req = signed_request_with_discharge(
        &m,
        Some(&bare_discharge),
        r#""role":"volume-ro","ttl_seconds":3600"#,
    );
    let (status, body) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "body: {body}");
    // Nothing was minted, and the contract check (not render) is what
    // fired — the request never reached the renderer.
    assert!(minter.calls().is_empty(), "no keypair should be minted");
    let audit = String::from_utf8(audit_buf.lock().unwrap().clone()).unwrap();
    assert!(
        audit.contains("\"outcome\":\"denied:missing_attested\""),
        "audit: {audit}"
    );
}

#[tokio::test]
async fn wrong_op_is_opaque_401() {
    // A correctly key-bound, role-shaped macaroon but op=enroll instead
    // of assume-role: the positive op gate refuses it.
    let (state, _, _, _dir) = state_with_audit().await;
    let app = router(state);
    let m = mint(
        &Keyring::single(ROOT),
        vec![
            Caveat::scalar(name::OP, op::ENROLL),
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::EXP, far_future().to_string()),
            Caveat::scalar(
                name::CNF,
                pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            ),
        ],
    );
    let (status, _) = body_string(
        app.oneshot(signed_request(&m, r#""role":"volume-ro""#))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn key_bound_without_pop_is_opaque_401() {
    let (state, _, _, _dir) = state_with_audit().await;
    let app = router(state);
    let m = request_macaroon();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header("authorization", format!("MintV1 {}", m.encode()))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"role":"volume-ro"}"#))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn pop_over_a_different_body_is_401() {
    let (state, _, _, _dir) = state_with_audit().await;
    let app = router(state);
    let m = request_macaroon();
    let ts = chrono::Utc::now().timestamp() as u64;
    let signed = format!(r#"{{"ts":{ts},"role":"volume-ro","volume":"{VOLUME}"}}"#);
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        m.tail(),
        signed.as_bytes(),
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header("authorization", format!("MintV1 {}", m.encode()))
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"ts":{ts},"role":"volume-ro","volume":"01JQBBBBBBBBBBBBBBBBBBBBBB"}}"#
        )))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn contradictory_cnf_fails_closed_not_bearer() {
    let (state, _, _, _dir) = state_with_audit().await;
    let app = router(state);
    let m = request_macaroon().attenuate(Caveat::scalar(name::CNF, "ed25519:AAAA"));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header("authorization", format!("MintV1 {}", m.encode()))
        .header("content-type", "application/json")
        .body(Body::from(r#"{"role":"volume-ro"}"#))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_mac_is_opaque_401() {
    let (state, _, _, _dir) = state_with_audit().await;
    let app = router(state);
    let forged = mint(
        &Keyring::single([1u8; 32]),
        vec![Caveat::scalar(name::OP, op::ASSUME_ROLE)],
    )
    .encode();
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .header("authorization", format!("Macaroon {forged}"))
        .body(Body::from(r#"{"role":"volume-ro"}"#))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_role_caveat_is_400() {
    // A cnf-bound, PoP-signed macaroon that clears the MAC stage
    // (aud/op/cnf/exp) and the revocation gate (present enrolled record,
    // matching sub + cnf + epoch) but carries no `Role` caveat → the
    // role gate denies with 400 before any policy render.
    let (state, _, _, _dir) = state_with_audit().await;
    let app = router(state);
    let m = mint(
        &Keyring::single(ROOT),
        vec![
            Caveat::scalar(name::OP, op::ASSUME_ROLE),
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::SUB, SUB),
            Caveat::scalar(
                name::CNF,
                pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            ),
            Caveat::scalar(name::EPOCH, "0"),
            Caveat::scalar(name::EXP, far_future().to_string()),
        ],
    );
    let req = signed_request(&m, &format!(r#""role":"volume-ro","volume":"{VOLUME}""#));
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn no_auth_header_is_401() {
    let (state, _, _, _dir) = state_with_audit().await;
    let app = router(state);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/assume-role")
        .body(Body::from(r#"{"role":"volume-ro"}"#))
        .unwrap();
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_credential_is_401() {
    // A credential that minted fine stops clearing once its sub is
    // revoked: the enrolled record is gone, so the revocation gate denies
    // and no second keypair is minted.
    let (state, _, minter, _dir) = state_with_audit().await;
    let store = state.store.clone();
    let app = router(state);
    let m = request_macaroon();

    let req = signed_request(
        &m,
        &format!(r#""role":"volume-ro","ttl_seconds":3600,"volume":"{VOLUME}""#),
    );
    let (status, body) = body_string(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::OK, "body: {body}");

    store
        .revoke(SUB, "usr_test", &chrono::Utc::now().to_rfc3339())
        .await
        .expect("revoke");

    let req = signed_request(
        &m,
        &format!(r#""role":"volume-ro","ttl_seconds":3600,"volume":"{VOLUME}""#),
    );
    let (status, _) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "revoked credential denied"
    );
    assert_eq!(minter.calls().len(), 1, "no keypair minted after revoke");
}

#[tokio::test]
async fn re_approval_after_revoke_does_not_revive_old_credential() {
    // The epoch is what presence alone cannot enforce: after revoke +
    // re-approve, the enrolled record's rev_epoch advances, so a
    // credential minted before the revocation (epoch 0) stays dead while
    // a freshly minted one (epoch 1) clears.
    let (state, _, _minter, _dir) = state_with_audit().await;
    let store = state.store.clone();
    let app = router(state);
    let old = request_macaroon();

    store
        .revoke(SUB, "usr_test", &chrono::Utc::now().to_rfc3339())
        .await
        .expect("revoke");
    store
        .approve(
            SUB,
            &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            "usr_test",
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
        .expect("re-approve");

    let req = signed_request(
        &old,
        &format!(r#""role":"volume-ro","ttl_seconds":3600,"volume":"{VOLUME}""#),
    );
    let (status, _) = body_string(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "old-epoch credential stays dead after re-approval"
    );

    let fresh = request_macaroon_at_epoch(1);
    let req = signed_request(&fresh, r#""role":"volume-ro","ttl_seconds":3600"#);
    let (status, body) = body_string(app.oneshot(req).await.unwrap()).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "new-epoch credential clears; body: {body}"
    );
}

#[tokio::test]
async fn dormant_closes_assume_role_and_readiness() {
    // A mint that came up without a verifiable seal closes the
    // role-rendering plane and reports not-ready, while liveness stays up.
    let dir = tempfile::tempdir().expect("tempdir");
    let state = AppState {
        config: Arc::new(config()),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(std::io::sink()))),
        store: Arc::new(
            Store::open_local_with_initial_key(dir.path(), Some(ROOT))
                .await
                .expect("store"),
        ),
        seal: Arc::new(arc_swap::ArcSwap::from_pointee(
            mint::sealed_cache::SealState::Dormant,
        )),
    };
    let app = router(state);

    // assume-role: the seal gate fires before authentication, so even an
    // otherwise-valid request gets 503 not-sealed (never mints a keypair).
    let m = request_macaroon();
    let req = signed_request(&m, r#""role":"volume-ro","ttl_seconds":3600"#);
    let (status, body) = body_string(app.clone().oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {body}");
    assert!(body.contains("not sealed"), "body: {body}");

    // /readyz not-ready, /healthz still ok.
    let ready = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready.status(), StatusCode::SERVICE_UNAVAILABLE);
    let live = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live.status(), StatusCode::OK);
}
