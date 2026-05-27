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
use mint::audit::AuditLog;
use mint::caveat::{Caveat, EffectiveCaveats, Resolved, name, op};
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::{mint_credential_ticket, mint_invite};
use mint::keyring::Keyring;
use mint::macaroon::Macaroon;
use mint::pop;
use mint::state::Store;
use tower::ServiceExt;

mod common;

const ROOT: [u8; 32] = [42u8; 32];
const COORD_SEED: [u8; 32] = [7u8; 32];
const OTHER_SEED: [u8; 32] = [9u8; 32];
const SUB: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

const TOML_TEMPLATE: &str = r#"
audience = "mint"
[tenant]
bucket = "demo-bucket"
[[role]]
name = "volume-ro"
required_caveats = ["elide:Volume", "aud", "exp"]
min_ttl_seconds = 60
max_ttl_seconds = 2592000
default_ttl_seconds = 2592000
policy_file = "volume-ro.json"
[[role]]
name = "volume-rw"
required_caveats = ["aud"]
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
    "Resource": ["arn:aws:s3:::{{tenant.bucket}}/by_id/{{caveat "elide:Volume"}}/*"],
    "Condition": {"DateLessThan": {"aws:CurrentTime": "{{system.expiry_iso8601}}"}}
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
    // Seed the known root key (hex) so Store::open_local loads it (vs
    // generating one) and the macaroons minted with ROOT verify.
    let root_hex: String = ROOT.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join("root_key"), root_hex).expect("seed root_key");
    let store = Arc::new(Store::open_local(dir.path()).await.expect("store"));
    let state = AppState {
        config: Arc::new(config()),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(buf.clone())))),
        store: store.clone(),
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

fn signed(uri: &str, m: &Macaroon, seed: &[u8; 32], extra: &str) -> Request<Body> {
    let body = format!("{{\"ts\":{}{extra}}}", now());
    let sig = pop::client_signature(seed, m.tail(), body.as_bytes());
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("authorization", format!("Macaroon {}", m.encode()))
        .header("x-mint-coord-pop", sig)
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
    mint_invite(&Keyring::single(ROOT), "mint", nonce)
        .attenuate(Caveat::scalar(name::SUB, SUB))
        .attenuate(Caveat::scalar(name::CNF, pop::cnf_value(seed)))
}

#[tokio::test]
async fn full_flow_enroll_approve_exchange_then_assume_role() {
    let (app, audit, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &COORD_SEED);

    // (1) enroll → pending + ticket
    let (status, body) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &COORD_SEED, ""))
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
                &COORD_SEED,
                r#","role":"volume-ro""#,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // (3) operator approves the displayed sub
    store
        .approve(SUB, &pop::cnf_value(&COORD_SEED), &now_iso())
        .await
        .unwrap();

    // (4) exchange → non-expiring, role-stamped credential
    let (status, body) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &COORD_SEED,
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
        Resolved::Value(pop::cnf_value(&COORD_SEED))
    );
    assert_eq!(eff.resolve(name::ROLE), Resolved::Value("volume-ro".into()));
    assert_eq!(eff.not_after(name::EXP), None, "credential does not expire");

    // ticket is multi-use: the SAME ticket, same approval, exchanged
    // again for a different role yields a second single-role credential
    // (record not consumed).
    let (status, body) = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &COORD_SEED,
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
                &COORD_SEED,
                r#","role":"nope""#,
            ))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // (5) attenuate the credential and assume a role with it
    let req = credential
        .attenuate(Caveat::scalar(name::EXP, far_future().to_string()))
        .attenuate(Caveat::scalar("elide:Volume", "VOL1"));
    let (status, body) = parts(
        app.oneshot(signed(
            "/v1/assume-role",
            &req,
            &COORD_SEED,
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
    let store = Arc::new(Store::open_in_memory(ROOT).await.expect("store"));
    let state = AppState {
        config: Arc::new(config()),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(buf.clone())))),
        store: store.clone(),
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
    let cb = client_invite(&nonce, &COORD_SEED);

    // (1) initial enroll + operator approval under kid=0
    let (status, _) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &COORD_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    store
        .approve(SUB, &pop::cnf_value(&COORD_SEED), &now_iso())
        .await
        .unwrap();
    assert_eq!(
        store.get_approved(SUB).await.unwrap().unwrap().kid,
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
        store.get_approved(SUB).await.unwrap().unwrap().kid,
        0,
        "record stays on its issuing kid until migrated",
    );

    // (3) coordinator restarts → re-runs /v1/enroll. Fast path matches
    // (same sub/cnf) and the handler opportunistically re-MACs.
    let (status, _) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &COORD_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        store.get_approved(SUB).await.unwrap().unwrap().kid,
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
    assert!(store.get_approved(SUB).await.unwrap().is_some());
}

#[tokio::test]
async fn idempotent_reenroll_same_pair() {
    let (app, _a, store, _dir) = app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &COORD_SEED);
    for _ in 0..2 {
        let (status, _) = parts(
            app.clone()
                .oneshot(signed("/v1/enroll", &cb, &COORD_SEED, ""))
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
                &client_invite(&nonce, &COORD_SEED),
                &COORD_SEED,
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
    // approved record from before the keyring + MAC landed cannot
    // be deserialised by the current `Approved` struct (missing
    // kid + mac fields). Before this fix, `record_pending` propagated
    // `StateError::Corrupt` and the handler tagged it
    // `enroll:denied:conflict` — opaque 401 with a misleading audit
    // line, blocking re-enrollment behind a state only inspection of
    // the bucket could reveal.
    //
    // After: a corrupt approved record is treated as "no approved
    // record" for the fast-path check, the slow path writes a fresh
    // pending, and the operator can re-approve normally.
    let (app, audit, store) = app_in_memory().await;
    let nonce = store.current_invite().await.unwrap();

    // Inject a pre-#454-shaped record at `_mint/approved/<SUB>` —
    // the body lacks `kid` and `mac`, so deserialising it as the
    // current `Approved` struct fails.
    let legacy = serde_json::json!({
        "pubkey": pop::cnf_value(&COORD_SEED),
        "approved_at": now_iso(),
        "fingerprint_shown": "deadbeef00112233",
    });
    let body = serde_json::to_vec(&legacy).unwrap();
    store
        .objects()
        .put_opts(
            &object_store::path::Path::from(format!("_mint/approved/{SUB}")),
            object_store::PutPayload::from(axum::body::Bytes::from(body)),
            object_store::PutOptions::default(),
        )
        .await
        .expect("seed legacy approved");

    let (status, _body) = parts(
        app.oneshot(signed(
            "/v1/enroll",
            &client_invite(&nonce, &COORD_SEED),
            &COORD_SEED,
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
    let cb = client_invite(&stale, &COORD_SEED);
    store.rotate_invite().await.unwrap(); // current nonce moves on
    let (status, _) = parts(
        app.oneshot(signed("/v1/enroll", &cb, &COORD_SEED, ""))
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
    // cnf bound to COORD_SEED, but the request is signed by OTHER_SEED.
    let cb = client_invite(&nonce, &COORD_SEED);
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
    // not enrol. NotKeyBound is a refusal here.
    let cb = mint_invite(&Keyring::single(ROOT), "mint", &nonce)
        .attenuate(Caveat::scalar(name::SUB, SUB));
    let req = Request::builder()
        .method("POST")
        .uri("/v1/enroll")
        .header("authorization", format!("Macaroon {}", cb.encode()))
        .header("content-type", "application/json")
        .body(Body::from(format!(r#"{{"ts":{}}}"#, now())))
        .unwrap();
    let (status, _) = parts(app.oneshot(req).await.unwrap()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// A separate harness with `[auth]` configured and two operator-write
/// roles, so the exchange path stamps a TPC. Mirrors `app()` but
/// builds Store with `init_k_m_a` and a config that includes the
/// `[auth]` block.
async fn tpc_app() -> (axum::Router, Arc<Store>, tempfile::TempDir) {
    const TOML_TPC: &str = r#"
audience = "mint"
[tenant]
bucket = "demo-bucket"
[auth]
endpoint = "https://auth.example/"
demo_enabled = true
[[role]]
name = "coord-rw"
required_caveats = ["aud"]
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 900
policy_file = "rw.json"
issues_with_tpc = true
[[role]]
name = "volume-rw"
required_caveats = ["aud"]
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 900
policy_file = "rw.json"
issues_with_tpc = true
"#;
    let cfg = common::parse_config(TOML_TPC, &[("rw.json", VOLUME_RW_POLICY)]);
    let buf = Arc::new(Mutex::new(Vec::new()));
    let dir = tempfile::tempdir().expect("tempdir");
    let root_hex: String = ROOT.iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(dir.path().join("root_key"), root_hex).expect("seed root_key");
    let mut store_inner = Store::open_local(dir.path()).await.expect("store");
    store_inner
        .init_k_m_a(dir.path(), true)
        .expect("init k_m_a");
    let store = Arc::new(store_inner);
    let state = AppState {
        config: Arc::new(cfg),
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(AuditSink(buf)))),
        store: store.clone(),
    };
    (router(state), store, dir)
}

#[tokio::test]
async fn tpc_role_credential_carries_third_party_caveat() {
    let (app, store, _dir) = tpc_app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &COORD_SEED);

    // enroll
    let (status, body) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &COORD_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let ticket = field(&body, "credential.ticket");

    // approve
    store
        .approve(SUB, &pop::cnf_value(&COORD_SEED), &now_iso())
        .await
        .unwrap();

    // exchange both operator-write roles
    let exchange = |role: &str| {
        let app = app.clone();
        let ticket = ticket.clone();
        let extra = format!(r#","role":"{role}""#);
        async move {
            let (status, body) = parts(
                app.oneshot(signed("/v1/enroll-exchange", &ticket, &COORD_SEED, &extra))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "body: {body}");
            field(&body, "credential")
        }
    };
    let coord_rw = exchange("coord-rw").await;
    let volume_rw = exchange("volume-rw").await;

    // Both verify under the same root: chain MAC includes the TPC.
    let ring = Keyring::single(ROOT);
    assert!(coord_rw.verify(&ring));
    assert!(volume_rw.verify(&ring));

    // Last caveat in each is a ThirdParty with the configured location.
    let coord_tpc = coord_rw.caveats().last().expect("at least one caveat");
    let volume_tpc = volume_rw.caveats().last().expect("at least one caveat");
    match (coord_tpc, volume_tpc) {
        (
            Caveat::ThirdParty {
                location: loc_a,
                vid: vid_a,
                cid: cid_a,
            },
            Caveat::ThirdParty {
                location: loc_b,
                vid: vid_b,
                cid: cid_b,
            },
        ) => {
            assert_eq!(loc_a, "https://auth.example/");
            assert_eq!(loc_a, loc_b);
            // One discharge serves both: CID is identical across the
            // operator-write credentials because both share the same
            // `r`, `coord_ulid`, and `org_id` plaintext under the same
            // `K_M-A`.
            assert_eq!(cid_a, cid_b, "CID must match across operator-write creds");
            // But VID differs: each chain reaches a different tag at
            // the TPC position (different first-party caveats =
            // different T_{n-1}), so the AEAD output differs even
            // though `r` is the same.
            assert_ne!(
                vid_a, vid_b,
                "VID must differ across chains with different first-party caveats"
            );
        }
        (a, b) => panic!("expected ThirdParty caveats; got {a:?} and {b:?}"),
    }
}

#[tokio::test]
async fn tpc_credential_is_deterministic_for_same_coord() {
    // Re-minting (e.g. on a fresh exchange of the same ticket) must
    // produce the same CID — that's the property mint_credential
    // depends on for "one discharge serves both" to hold across
    // restarts.
    let (app, store, _dir) = tpc_app().await;
    let nonce = store.current_invite().await.unwrap();
    let cb = client_invite(&nonce, &COORD_SEED);
    let (_, body) = parts(
        app.clone()
            .oneshot(signed("/v1/enroll", &cb, &COORD_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    let ticket = field(&body, "credential.ticket");
    store
        .approve(SUB, &pop::cnf_value(&COORD_SEED), &now_iso())
        .await
        .unwrap();

    let one = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &COORD_SEED,
                r#","role":"coord-rw""#,
            ))
            .await
            .unwrap(),
    )
    .await
    .1;
    let two = parts(
        app.clone()
            .oneshot(signed(
                "/v1/enroll-exchange",
                &ticket,
                &COORD_SEED,
                r#","role":"coord-rw""#,
            ))
            .await
            .unwrap(),
    )
    .await
    .1;
    let cred1 = field(&one, "credential");
    let cred2 = field(&two, "credential");
    match (cred1.caveats().last(), cred2.caveats().last()) {
        (
            Some(Caveat::ThirdParty { cid: cid1, .. }),
            Some(Caveat::ThirdParty { cid: cid2, .. }),
        ) => {
            assert_eq!(cid1, cid2, "CID must be deterministic across re-mints");
        }
        other => panic!("expected ThirdParty tails; got {other:?}"),
    }
}

#[tokio::test]
async fn exchange_without_approval_returns_403_awaiting() {
    let (app, _a, _store, _dir) = app().await;
    // A perfectly well-formed ticket (minted from root) for a sub
    // that was never approved: the exchange-time check is
    // `_mint/approved/<sub>` exists and its pub matches the cnf, so
    // an unrecorded sub is indistinguishable from "operator hasn't
    // approved yet" — both are the 403-awaited outcome.
    let inter = mint_credential_ticket(
        &Keyring::single(ROOT),
        "mint",
        SUB,
        &pop::cnf_value(&COORD_SEED),
        now() + 600,
    );
    let (status, _) = parts(
        app.oneshot(signed("/v1/enroll-exchange", &inter, &COORD_SEED, ""))
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
