//! End-to-end enrollment (`docs/design-mint.md` § *Enrollment*):
//! reusable invite macaroon → client self-asserts `sub`/`cnf` at
//! `POST /v1/enroll` (pending record + credential ticket) → operator
//! approval → `POST /v1/enroll-exchange` (403 until approved, then the
//! non-expiring credential) → the credential attenuates and assumes a role.
//! Plus the refusals that matter: stale invite, wrong-key PoP,
//! bearer (no cnf), no pending record, conflicting key for a `sub`.

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::SigningKey;
use mint::audit::AuditLog;
use mint::caveat::{Caveat, EffectiveCaveats, Resolved, name, op, scope};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::{mint_credential_ticket, mint_invite};
use mint::keyring::Keyring;
use mint::macaroon::{KeyRef, Macaroon, mint_under_key_with_nonce};
use mint::pop;
use mint::state::{K_M_A_FILE, K_M_B_FILE, Store};
use mint::tpc;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
/// The mint↔auth wrapping key. Pre-seeded on the store so the enroll
/// handler can stamp the gate TPCs, and reused by [`signed`] to mint the
/// operator discharge each gate clears.
const K_M_A: [u8; 32] = [13u8; 32];
/// The mint↔attestation-coordinator wrapping key. Pre-seeded so the
/// exchange handler can stamp the volume role's attested TPC, and reused
/// by [`signed`] to mint the attestation discharge it clears.
const K_M_B: [u8; 32] = [21u8; 32];
const CLIENT_SEED: [u8; 32] = [7u8; 32];
const OTHER_SEED: [u8; 32] = [9u8; 32];
const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const ORG_ID: &str = "demo";
/// Discharge location stamped into the invite/ticket gate TPCs.
const AUTH_URL: &str = "https://auth.example/v1/discharge";
/// The volume the attestation discharge attests for the `volume-ro` role.
const VOLUME: &str = "01JQAAAAAAAAAAAAAAAAAAAAAA";

const TOML_TEMPLATE: &str = r#"
audience = "mint"
auth_location = "https://auth.example/v1/discharge"
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
[[role]]
name = "volume-rw"
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 900
policy_file = "volume-rw.json"
"#;

const VOLUME_RW_POLICY: &str = r#"{"Version":"2012-10-17","Statement":[]}"#;

const POLICY: &str = r#"
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["s3:GetObject"],
    "Resource": ["arn:aws:s3:::{{env.bucket}}/by_id/{{attested.volume}}/*"],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{mint.expiry}}"}}
  }]
}
"#;

fn config() -> Config {
    common::parse_config(
        TOML_TEMPLATE,
        &[
            ("volume-ro.json", POLICY),
            ("volume-rw.json", VOLUME_RW_POLICY),
        ],
    )
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

/// (router, audit-buffer, store handle, tempdir guard). The store
/// handle lets a test play the operator (`approve`); the tempdir must
/// outlive the app.
async fn app() -> (
    axum::Router,
    Arc<Mutex<Vec<u8>>>,
    Arc<Store>,
    tempfile::TempDir,
) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let dir = tempfile::tempdir().expect("tempdir");
    // Seed the keyring's kid=0 with the known ROOT so the macaroons
    // minted with ROOT verify.
    let k_m_a_hex: String = K_M_A.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join(K_M_A_FILE), k_m_a_hex).expect("seed k_m_a");
    let k_m_b_hex: String = K_M_B.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join(K_M_B_FILE), k_m_b_hex).expect("seed k_m_b");
    let mut store_inner = Store::open_local_with_initial_key(dir.path(), Some(ROOT))
        .await
        .expect("store");
    store_inner
        .init_k_m_a(dir.path(), true)
        .expect("init k_m_a");
    store_inner
        .init_k_m_b(dir.path(), true)
        .expect("init k_m_b");
    let store = Arc::new(store_inner);
    let cfg = config();
    let seal = Arc::new(arc_swap::ArcSwap::from_pointee(
        mint::sealed_cache::serving_from_config(&cfg),
    ));
    let state = AppState {
        config: Arc::new(cfg),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(buf.clone())))),
        store: store.clone(),
        seal,
    };
    (router(state), buf, store, dir)
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn now() -> u64 {
    chrono::Utc::now().timestamp().max(0) as u64
}

fn far_future() -> u64 {
    now() + 365 * 24 * 3600
}

/// The operator-discharge scope a gate-bearing primary needs, inferred
/// from its `op`. `assume-role` (a TPC-free credential) needs none.
fn gate_scope(m: &Macaroon) -> Option<&'static str> {
    match EffectiveCaveats::new(m.caveats()).resolve(name::OP) {
        Resolved::Value(v) if v == op::ENROLL => Some(scope::MINT_ENROLL),
        Resolved::Value(v) if v == op::ENROLL_EXCHANGE => Some(scope::MINT_EXCHANGE),
        _ => None,
    }
}

/// Mint the operator discharge a gate clears, the way auth (or the
/// colocated demo) would: recover `r` from the anchor's TPC `CID` under
/// `K_M-A` and chain-MAC a discharge carrying `(aud, sub, Scope, exp)`
/// under it. `sub` is the authenticated human in the
/// discharge's own context; `aud` clears per-macaroon like the primary's.
fn gate_discharge(cid: &[u8], scope: &str) -> Macaroon {
    let pt = tpc::decrypt_cid(&K_M_A, cid).expect("cid decrypts under K_M-A");
    mint_under_key_with_nonce(
        &pt.r,
        KeyRef::Discharge,
        tpc::ticket_id(cid),
        vec![
            Caveat::scalar(name::AUD, "mint"),
            Caveat::scalar(name::SUB, "usr_test"),
            Caveat::scalar(name::SCOPE, scope),
            Caveat::scalar(name::EXP, far_future().to_string()),
        ],
    )
}

/// Mint the attestation discharge for the volume role's attested TPC the
/// way coord B would: recover `r` from the CID under `K_M-B`, then mint a
/// discharge rooted at it attesting `volume = VOLUME`.
fn volume_discharge(cid: &[u8]) -> Macaroon {
    let pt = tpc::decrypt_cid_attested(&K_M_B, cid).expect("cid decrypts under K_M-B");
    mint_under_key_with_nonce(
        &pt.r,
        KeyRef::Discharge,
        tpc::ticket_id(cid),
        vec![
            Caveat::scalar("volume", VOLUME),
            Caveat::scalar(name::EXP, far_future().to_string()),
        ],
    )
}

/// Build a signed request, presenting the primary plus a fresh discharge
/// for each TPC the primary carries — an operator discharge for the
/// enroll/exchange gates, an attestation discharge for an assume-role
/// credential's volume TPC. The PoP signs the body under the *primary's*
/// tail, as the client does.
fn signed(uri: &str, m: &Macaroon, seed: &[u8; 32], extra: &str) -> Request<Body> {
    let body = format!("{{\"ts\":{}{extra}}}", now());
    let sig = pop::client_signature(&SigningKey::from_bytes(seed), m.tail(), body.as_bytes());
    let mut auth = format!("MintV1 {}", m.encode());
    for c in m.caveats() {
        if let Caveat::ThirdParty { cid, .. } = c {
            // An enroll/exchange anchor carries a gate TPC the operator
            // discharges; an assume-role credential carries the volume
            // role's attested TPC the attestation coordinator discharges.
            let discharge = match gate_scope(m) {
                Some(scope) => gate_discharge(cid, scope),
                None => volume_discharge(cid),
            };
            auth.push(',');
            auth.push_str(&discharge.encode());
        }
    }
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", auth)
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap()
}

async fn parts(resp: axum::response::Response) -> (StatusCode, String) {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("collect body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

fn field(body: &str, key: &str) -> Macaroon {
    let v: serde_json::Value = serde_json::from_str(body).expect("json");
    Macaroon::decode(v[key].as_str().expect("field present")).expect("decode")
}

/// The client's self-asserted invite: the reusable invite
/// macaroon with `sub`/`cnf` appended for `seed`.
fn client_invite(nonce: &str, seed: &[u8; 32]) -> Macaroon {
    mint_invite(
        &Keyring::single(ROOT),
        &K_M_A,
        "mint",
        nonce,
        ORG_ID,
        AUTH_URL,
    )
    .attenuate(Caveat::scalar(name::SUB, SUB))
    .attenuate(Caveat::scalar(
        name::CNF,
        pop::cnf_value(&SigningKey::from_bytes(seed)),
    ))
}

#[tokio::test]
async fn full_flow_enroll_approve_exchange_then_assume_role() {
    let (app, audit, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &CLIENT_SEED);

    // (1) enroll → pending + ticket
    let (status, body) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &CLIENT_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let ticket = field(&body, "credential.ticket");
    assert!(ticket.verify(&Keyring::single(ROOT)));

    // (2) exchange before approval → 403 (awaited, not a failure)
    let (status, _) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &CLIENT_SEED,
                r#","role":"volume-ro""#,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // (3) operator approves the displayed sub
    store
        .approve(
            SUB,
            &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            "usr_op",
            &now_iso(),
        )
        .await
        .unwrap();

    // (4) exchange → non-expiring, role-stamped credential
    let (status, body) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &CLIENT_SEED,
                r#","role":"volume-ro""#,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let credential = field(&body, "credential");
    assert!(credential.verify(&Keyring::single(ROOT)));
    let eff = EffectiveCaveats::new(credential.caveats());
    assert_eq!(
        eff.resolve(name::OP),
        Resolved::Value(op::ASSUME_ROLE.into())
    );
    assert_eq!(eff.resolve(name::SUB), Resolved::Value(SUB.into()));
    assert_eq!(
        eff.resolve(name::CNF),
        Resolved::Value(pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)))
    );
    assert_eq!(eff.resolve(name::ROLE), Resolved::Value("volume-ro".into()));
    assert_eq!(eff.min_bound(name::EXP), None, "credential does not expire");

    // ticket is multi-use: the SAME ticket, same approval, exchanged
    // again for a different role yields a second single-role credential
    // (record not consumed).
    let (status, body) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &CLIENT_SEED,
                r#","role":"volume-rw""#,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "second exchange body: {body}");
    let cd = field(&body, "credential");
    assert_eq!(
        EffectiveCaveats::new(cd.caveats()).resolve(name::ROLE),
        Resolved::Value("volume-rw".into())
    );

    // floor gate: a role not in the mint config is the same opaque 401.
    let (status, _) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &CLIENT_SEED,
                r#","role":"nope""#,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // (5) attenuate the credential and assume a role with it. The
    // credential carries the volume role's attested TPC (stamped at
    // exchange); `signed` attaches the attestation discharge that vouches
    // the target volume, which the policy renders as `{{attested.volume}}`.
    let req = credential.attenuate(Caveat::scalar(name::EXP, far_future().to_string()));
    let (status, body) = parts(
        app.oneshot(signed(
            "/v1/assume-role",
            &req,
            &CLIENT_SEED,
            r#","role":"volume-ro","ttl_seconds":3600"#,
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "assume-role body: {body}");
    assert!(body.contains("tid_fake_00000000"), "body: {body}");

    let a = String::from_utf8(audit.lock().unwrap().clone()).unwrap();
    assert!(a.contains("\"outcome\":\"exchange:granted\""), "audit: {a}");
}

/// Build an InMemory-backed test app so we can exercise `PutMode::Update`
/// (LocalFileSystem returns `NotImplemented` for it). Mirrors `app()`
/// otherwise, with a single-kid keyring seeded to `ROOT`.
async fn app_in_memory() -> (axum::Router, Arc<Mutex<Vec<u8>>>, Arc<Store>) {
    let buf = Arc::new(Mutex::new(Vec::new()));
    let mut store_inner = Store::open_in_memory(ROOT).await.expect("store");
    // The in-memory store still needs K_M-A to stamp the gate TPCs;
    // load the known key off a scratch dir (the bytes live in memory
    // after init, so the dir need not outlive this call).
    let kdir = tempfile::tempdir().expect("tempdir");
    let k_m_a_hex: String = K_M_A.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(kdir.path().join(K_M_A_FILE), k_m_a_hex).expect("seed k_m_a");
    store_inner
        .init_k_m_a(kdir.path(), true)
        .expect("init k_m_a");
    let store = Arc::new(store_inner);
    let cfg = config();
    let seal = Arc::new(arc_swap::ArcSwap::from_pointee(
        mint::sealed_cache::serving_from_config(&cfg),
    ));
    let state = AppState {
        config: Arc::new(cfg),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(buf.clone())))),
        store: store.clone(),
        seal,
    };
    (router(state), buf, store)
}

#[tokio::test]
async fn re_enroll_after_keyring_rotation_lazily_migrates_approval() {
    // Rotation procedure: kid=0 approves; operator rotates keyring;
    // coordinator restarts → next /v1/enroll fast-path drifts the
    // record forward to the new current kid, with no operator
    // intervention. Verifies the runtime path of the retain-keychain
    // + lazy-migration design (`docs/design-mint.md` § *Root-key
    // rotation*).
    let (app, _audit, store) = app_in_memory().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &CLIENT_SEED);

    // (1) initial enroll + operator approval under kid=0
    let (status, _) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &CLIENT_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    store
        .approve(
            SUB,
            &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            "usr_op",
            &now_iso(),
        )
        .await
        .unwrap();
    assert_eq!(
        store.get_enrolled(SUB).await.unwrap().unwrap().kid,
        0,
        "approval starts under kid=0"
    );

    // (2) operator rotates the keyring: a second key joins as
    // current. (In production this is `mint admin keyring rekey-add`;
    // here we swap directly.)
    use std::collections::BTreeMap;
    let mut ring = BTreeMap::new();
    ring.insert(0, ROOT);
    ring.insert(1, [99u8; 32]);
    store
        .set_keyring(Keyring::from_parts(ring, 1).unwrap())
        .await;
    // The record is still trustable — kid=0 is still in the ring.
    assert_eq!(
        store.get_enrolled(SUB).await.unwrap().unwrap().kid,
        0,
        "record stays on its issuing kid until migrated",
    );

    // (3) coordinator restarts → re-runs /v1/enroll. Fast path matches
    // (same sub/cnf) and the handler opportunistically re-MACs.
    let (status, _) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &CLIENT_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        store.get_enrolled(SUB).await.unwrap().unwrap().kid,
        1,
        "lazy migration drifted the record to the current kid",
    );

    // (4) operator can now safely retire kid=0; nothing of value is
    // still under it. A second enroll is a no-op for the kid.
    let mut ring = BTreeMap::new();
    ring.insert(1, [99u8; 32]);
    store
        .set_keyring(Keyring::from_parts(ring, 1).unwrap())
        .await;
    assert!(store.get_enrolled(SUB).await.unwrap().is_some());
}

#[tokio::test]
async fn idempotent_reenroll_same_pair() {
    let (app, _a, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &CLIENT_SEED);
    for _ in 0..2 {
        let (status, _) = parts(
            app.clone()
                .oneshot(signed("/v1/enroll", &cb, &CLIENT_SEED, ""))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}

#[tokio::test]
async fn conflicting_key_for_same_sub_is_opaque_401() {
    let (app, audit, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let (s, _) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll",
                &client_invite(&nonce, &CLIENT_SEED),
                &CLIENT_SEED,
                "",
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::OK);
    // Same sub, a different key — must not overwrite or auto-resolve.
    let (s, _) = parts(
        app.oneshot(signed(
            "/v1/enroll",
            &client_invite(&nonce, &OTHER_SEED),
            &OTHER_SEED,
            "",
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    // Genuine conflict — the audit tag stays `enroll:denied:conflict`
    // (the operator-facing distinction the audit log preserves while
    // the client sees the same opaque 401 as any other failure).
    let a = String::from_utf8(audit.lock().unwrap().clone()).unwrap();
    assert!(
        a.contains("\"outcome\":\"enroll:denied:conflict\""),
        "audit must tag a genuine pending-conflict as 'enroll:denied:conflict': {a}",
    );
}

#[tokio::test]
async fn re_enroll_over_legacy_unsigned_approved_takes_slow_path() {
    // The fix for the post-#454 upgrade footgun: a pre-existing
    // enrolled record from before the keyring + MAC landed cannot
    // be deserialised by the current `Enrolled` struct (missing
    // kid + mac fields). Before this fix, `record_pending` propagated
    // `StateError::Corrupt` and the handler tagged it
    // `enroll:denied:conflict` — opaque 401 with a misleading audit
    // line, blocking re-enrollment behind a state only inspection of
    // the bucket could reveal.
    //
    // After: a corrupt enrolled record is treated as "no approved
    // record" for the fast-path check, the slow path writes a fresh
    // pending, and the operator can re-approve normally.
    let (app, audit, store) = app_in_memory().await;
    let nonce = store.current_invite().await.unwrap();

    // Inject a pre-#454-shaped record at `_mint/clients/enrolled/<SUB>` —
    // the body lacks `kid` and `mac`, so deserialising it as the
    // current `Enrolled` struct fails.
    let legacy = serde_json::json!({
        "pubkey": pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
        "approved_at": now_iso(),
        "fingerprint_shown": "deadbeef00112233",
    });
    let body = serde_json::to_vec(&legacy).unwrap();
    store
        .objects()
        .put_opts(
            &object_store::path::Path::from(format!("_mint/clients/enrolled/{SUB}")),
            object_store::PutPayload::from(axum::body::Bytes::from(body)),
            object_store::PutOptions::default(),
        )
        .await
        .expect("seed legacy approved");

    let (status, _body) = parts(
        app.oneshot(signed(
            "/v1/enroll",
            &client_invite(&nonce, &CLIENT_SEED),
            &CLIENT_SEED,
            "",
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "re-enroll over a corrupt approved must take the slow path, not 401",
    );
    let a = String::from_utf8(audit.lock().unwrap().clone()).unwrap();
    assert!(
        a.contains("\"outcome\":\"enroll:pending\""),
        "audit must show the slow path was taken (enroll:pending), not denied:conflict: {a}",
    );
    assert!(
        !a.contains("\"outcome\":\"enroll:denied:conflict\""),
        "audit must NOT misreport a corrupt approved as a key conflict: {a}",
    );
}

#[tokio::test]
async fn stale_invite_nonce_is_opaque_401() {
    let (app, _a, store, _dir) = app().await;
    let stale = store.current_invite().await.unwrap();
    let cb = client_invite(&stale, &CLIENT_SEED);
    store.rotate_invite().await.unwrap(); // current nonce moves on
    let (status, _) = parts(
        app.oneshot(signed("/v1/enroll", &cb, &CLIENT_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enroll_pop_by_wrong_key_is_opaque_401() {
    let (app, _a, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    // cnf bound to CLIENT_SEED, but the request is signed by OTHER_SEED.
    let cb = client_invite(&nonce, &CLIENT_SEED);
    let (status, _) = parts(
        app.oneshot(signed("/v1/enroll", &cb, &OTHER_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_invite_without_cnf_is_opaque_401() {
    let (app, _a, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    // sub but no cnf, and no PoP header: a captured invite copy must
    // not enrol.
    let cb = mint_invite(
        &Keyring::single(ROOT),
        &K_M_A,
        "mint",
        &nonce,
        ORG_ID,
        AUTH_URL,
    )
    .attenuate(Caveat::scalar(name::SUB, SUB));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/enroll")
        .header("authorization", format!("MintV1 {}", cb.encode()))
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"ts":{}}}"#, now())))
        .unwrap();
    let (status, _) = parts(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The new invariant: operator authority rides the enroll/exchange
/// gates, not the credential. The invite and the ticket each carry a
/// third-party caveat; the exchanged credential carries none.
#[tokio::test]
async fn gates_carry_tpc_but_credential_does_not() {
    let (app, _audit, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &CLIENT_SEED);

    // The invite (enroll gate) carries exactly one third-party caveat.
    assert_eq!(tpc_count(&cb), 1, "invite carries the enroll-gate TPC");

    // enroll → ticket, which carries its own (exchange-gate) TPC.
    let (status, body) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &CLIENT_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let ticket = field(&body, "credential.ticket");
    assert_eq!(
        tpc_count(&ticket),
        1,
        "ticket carries the exchange-gate TPC"
    );

    // approve, then exchange. A non-attested role (`volume-rw` here
    // declares no `[role.attestation]`) yields a TPC-free credential —
    // operator authority lives at the gates, not at assume-role.
    store
        .approve(
            SUB,
            &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
            "usr_op",
            &now_iso(),
        )
        .await
        .unwrap();
    let (status, body) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &CLIENT_SEED,
                r#","role":"volume-rw""#,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let credential = field(&body, "credential");
    assert_eq!(
        tpc_count(&credential),
        0,
        "non-attested role: credential carries no TPC"
    );

    // An attested role (`volume-ro`) instead yields a credential carrying
    // exactly the volume attested TPC the attestation coordinator clears.
    let (status, body) = parts(
        app.oneshot(signed(
            "/v1/enroll-exchange",
            &ticket,
            &CLIENT_SEED,
            r#","role":"volume-ro""#,
        ))
        .await
        .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let attested_credential = field(&body, "credential");
    assert_eq!(
        tpc_count(&attested_credential),
        1,
        "attested role: credential carries the volume TPC"
    );
}

/// Count third-party caveats on a macaroon.
fn tpc_count(m: &Macaroon) -> usize {
    m.caveats()
        .iter()
        .filter(|c| matches!(c, Caveat::ThirdParty { .. }))
        .count()
}

/// The enroll gate bites: a bare invite with no operator discharge
/// cannot open an enrollment, even with a valid PoP.
#[tokio::test]
async fn enroll_without_operator_discharge_is_opaque_401() {
    let (app, _a, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &CLIENT_SEED);
    let body = format!(r#"{{"ts":{}}}"#, now());
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        cb.tail(),
        body.as_bytes(),
    );
    let req = Request::builder()
        .method("POST")
        .uri("/v1/enroll")
        .header("authorization", format!("MintV1 {}", cb.encode()))
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, _) = parts(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The scope clear bites: a discharge for the invite's TPC carrying the
/// wrong scope (`mint:exchange`, not `mint:enroll`) does not clear the
/// enroll gate.
#[tokio::test]
async fn enroll_with_wrong_scope_discharge_is_opaque_401() {
    let (app, _a, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &CLIENT_SEED);
    let cid = cb
        .caveats()
        .iter()
        .find_map(|c| match c {
            Caveat::ThirdParty { cid, .. } => Some(cid.clone()),
            _ => None,
        })
        .expect("invite carries a TPC");
    let wrong = gate_discharge(&cid, scope::MINT_EXCHANGE);
    let body = format!(r#"{{"ts":{}}}"#, now());
    let sig = pop::client_signature(
        &SigningKey::from_bytes(&CLIENT_SEED),
        cb.tail(),
        body.as_bytes(),
    );
    let auth = format!("MintV1 {},{}", cb.encode(), wrong.encode());
    let req = Request::builder()
        .method("POST")
        .uri("/v1/enroll")
        .header("authorization", auth)
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap();
    let (status, _) = parts(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn exchange_without_approval_returns_403_awaiting() {
    let (app, _a, _store, _dir) = app().await;
    // A perfectly well-formed ticket (minted from root) for a sub
    // that was never approved: the exchange-time check is
    // `_mint/clients/enrolled/<sub>` exists and its pub matches the cnf, so
    // an unrecorded sub is indistinguishable from "operator hasn't
    // approved yet" — both are the 403-awaited outcome.
    let inter = mint_credential_ticket(
        &Keyring::single(ROOT),
        &K_M_A,
        "mint",
        SUB,
        &pop::cnf_value(&SigningKey::from_bytes(&CLIENT_SEED)),
        now() + 600,
        ORG_ID,
        AUTH_URL,
    );
    let (status, _) = parts(
        app.oneshot(signed("/v1/enroll-exchange", &inter, &CLIENT_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
