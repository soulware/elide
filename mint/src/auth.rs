//! mint-as-auth role — demo-only discharge issuer.
//!
//! Structurally separate from the mint role. The discharge route
//! mounts only when `[auth].demo_enabled = true`; production deploys
//! run a standalone auth-service binary that issues discharges over
//! its own wire and shares `K_M-A` with mint. Mint's
//! [`verify_and_clear`](crate::http::verify_and_clear) verifies any
//! discharge by recovering `r` from `K_M-A` regardless of where the
//! discharge was minted, so this module can later move out of the mint
//! binary without disturbing the verifier.
//!
//! Session gate (`docs/design-auth-service.md` § *Login flow*): every
//! `/v1/discharge` request must carry `Authorization: Bearer
//! <session>` — a session macaroon minted by `POST /v1/login` under
//! `K_session`. The demo accepts any subject at login (no password);
//! the session is the *gate* on discharge issuance, and its `Subject`
//! is what each discharge attests. Production auth-service authenticates
//! login for real and issues sessions over its own wire; the gate shape
//! is the same.
//!
//! Wire (`POST /v1/login`):
//!
//! ```text
//! request body:  { "subject": "<opaque>" }
//! 200 OK:        { "session": "mnt1_<base64url>" }
//! ```
//!
//! Wire (`POST /v1/discharge`):
//!
//! ```text
//! Authorization: Bearer mnt1_<session>
//! request body:  { "cid": "<base64url of the anchor's TPC CID>",
//!                  "scope": "mint:enroll" | "mint:exchange" | "mint:admin" }
//! 200 OK:        { "discharge": "mnt1_<base64url>" }
//! 403:           session valid but does not grant the requested scope
//! ```
//!
//! Discharge construction: require `scope ∈ session.scopes` (the
//! authorization decision; `403` otherwise), then decrypt `cid` under
//! `K_M-A` ([`tpc::decrypt_cid`]) to recover `(r, client_id, org_id)` —
//! no `K_M`, no per-client state — and reject if `org_id` is not the org
//! this role serves. Mint a macaroon at `kid = DISCHARGE_KID`, chain
//! MAC'd under that `r`, caveats `Subject` (the session subject),
//! `OrgId`, `ClientId`, `Scope` (the requested class, cleared by the
//! gate), `NotAfter`. No `op`: per-op narrowing is the caller's
//! attenuation onto the primary (the PoP'd anchor), so one discharge
//! satisfies every op that primary is attenuated for. Mint's verifier
//! recovers the same `r` from the primary's `vid`
//! ([`tpc::decrypt_vid`]) — the two recover identical keys by
//! construction.
//!
//! Demo gate: `[auth].demo_enabled` must be true *and* the request must
//! have arrived over the UDS listener (we never expose discharge
//! issuance on TCP). The router-mount in `main.rs` enforces the first
//! gate; defence-in-depth for the second.

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::caveat::{Caveat, EffectiveCaveats, Resolved, name, op, scope};
use crate::http::AppState;
use crate::macaroon::{DISCHARGE_KID, Macaroon, NONCE_LEN, SESSION_KID, mint_under_key};
use crate::tpc;

/// BLAKE3 derive-key context for the per-discharge MAC key. The
/// context string is the domain separator — bumping it rotates every
/// outstanding demo discharge.
const R_KDF_CONTEXT: &str = "mint discharge r-key v1";

/// Demo discharge lifetime. Long enough for a CLI command to round-trip
/// from auth to mint, short enough that a leaked discharge has minimal
/// window. Demo only — production auth-service controls this per its
/// own policy.
const DISCHARGE_EXP_SECONDS: u64 = 300;

/// Demo session lifetime — `~7 days` per `docs/design-auth-service.md`
/// § *Cadence*. The operator re-runs `mint login` when it lapses.
const SESSION_EXP_SECONDS: u64 = 7 * 24 * 60 * 60;

/// Derive the per-discharge MAC key from `K_M-A` and a discharge's
/// nonce. The discharge-as-primary verification path
/// ([`crate::http`] `resolve_primary_key`) recovers `r` this way for a
/// standalone discharge; the CID-arm discharge below is keyed by the
/// CID's `r` instead.
pub fn derive_discharge_r(k_m_a: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut km = Vec::with_capacity(32 + NONCE_LEN);
    km.extend_from_slice(k_m_a);
    km.extend_from_slice(nonce);
    blake3::derive_key(R_KDF_CONTEXT, &km)
}

/// The `/v1/discharge` request body. Shared with the client side
/// (`crate::operator`) so the bytes a caller serialises and the bytes
/// the handler deserialises are one type — a missing or misnamed field
/// is a compile error, not a runtime 400.
#[derive(Deserialize, Serialize)]
pub(crate) struct DischargeRequest {
    /// Base64url of the anchor's third-party-caveat `CID` (the invite's,
    /// the ticket's, or the cli-token's). The auth role decrypts it under
    /// `K_M-A` to recover the discharge key `r` and the bound
    /// `(client_id, org_id)`.
    pub(crate) cid: String,
    /// The authority class the caller needs — `mint:enroll`,
    /// `mint:exchange`, or `mint:admin`. Auth issues only if the session
    /// grants it, and stamps it as the discharge's `Scope` caveat for the
    /// gate to clear (`docs/design-auth-service.md` § *Discharge flows*).
    pub(crate) scope: String,
}

/// A verified session's claims: the `Subject` the discharge attests and
/// the granted `Scope` set the issuance check is made against.
pub struct SessionClaims {
    pub subject: String,
    pub scopes: Vec<String>,
}

#[derive(Deserialize)]
struct LoginRequest {
    subject: String,
}

/// Build the auth-role router. The caller binds it to its own
/// listener — the auth role lives on a *separate* socket from the
/// mint role, never sharing a router with `/v1/assume-role`,
/// `/v1/admin/*`, or any mint-issued-credential endpoint. Demo
/// callers reach it at the path in `[auth].socket`
/// (defaults to `<data_dir>/auth.sock`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/login", post(issue_session))
        .route("/v1/discharge", post(issue_discharge))
        .with_state(state)
}

/// Mint a demo session macaroon under `K_session`: caveats
/// `op=session`, `Subject=<subject>`, the granted `Scope` set, and
/// `NotAfter=now+7d`. A fresh chain (not an attenuation), keyed by
/// `K_session`, so it is structurally distinct from every mint-issued
/// macaroon and verifiable only by this role. The demo grants **every**
/// scope to every subject — login stays wide-open, but the grant is
/// explicit on the session (`docs/design-auth-service.md` § *Scope
/// tier*); production auth-service decides the grant per its own policy.
fn mint_session(k_session: &[u8; 32], subject: &str, now_unix: u64) -> Macaroon {
    let not_after = now_unix + SESSION_EXP_SECONDS;
    mint_under_key(
        k_session,
        SESSION_KID,
        vec![
            Caveat::scalar(name::OP, op::SESSION),
            Caveat::scalar("Subject", subject),
            Caveat::scalar(name::SCOPE, scope::MINT_ENROLL),
            Caveat::scalar(name::SCOPE, scope::MINT_EXCHANGE),
            Caveat::scalar(name::SCOPE, scope::MINT_ADMIN),
            Caveat::scalar(name::NOT_AFTER, not_after.to_string()),
        ],
    )
}

/// Verify a session presented in `Authorization: Bearer <session>`:
/// chain MAC under `K_session`, `op=session`, and a non-expired
/// `NotAfter`. Returns the session's `Subject` and granted `Scope` set
/// on success. Every failure is the opaque `()` the caller maps to
/// `401`.
#[allow(clippy::result_unit_err)]
pub fn verify_session(
    k_session: &[u8; 32],
    headers: &HeaderMap,
    now_unix: u64,
) -> Result<SessionClaims, ()> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or(())?;
    let mac = Macaroon::decode(token.trim()).map_err(|_| ())?;
    if !mac.verify_under_key(k_session) {
        return Err(());
    }
    let eff = EffectiveCaveats::new(mac.caveats());
    if !matches!(eff.resolve(name::OP), Resolved::Value(v) if v == op::SESSION) {
        return Err(());
    }
    if let Some(not_after) = eff.not_after(name::NOT_AFTER)
        && not_after <= now_unix
    {
        return Err(());
    }
    let scopes = mac
        .caveats()
        .iter()
        .filter_map(|c| match c {
            Caveat::FirstParty { name: n, value } if n == name::SCOPE => Some(value.clone()),
            _ => None,
        })
        .collect();
    match eff.resolve("Subject") {
        Resolved::Value(subject) => Ok(SessionClaims { subject, scopes }),
        _ => Err(()),
    }
}

/// `POST /v1/login` — the demo login. Accepts any `subject` with no
/// password (the demo does not authenticate the human); production
/// auth-service runs a real login here (device-code / API-key, see
/// `docs/design-auth-service.md` § *Login flow*) and issues the same
/// session shape.
async fn issue_session(State(state): State<AppState>, body: Bytes) -> Response {
    let Some(k_session) = state.store.k_session().copied() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "k_session unavailable");
    };
    let req: LoginRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad request"),
    };
    if req.subject.is_empty() {
        return error(StatusCode::BAD_REQUEST, "empty subject");
    }
    let now_unix = Utc::now().timestamp().max(0) as u64;
    let session = mint_session(&k_session, &req.subject, now_unix);
    (
        StatusCode::OK,
        axum::Json(json!({"session": session.encode()})),
    )
        .into_response()
}

/// `POST /v1/discharge` — session-gated wide discharge for a credential's
/// third-party caveat. The session's `Subject` is what the discharge
/// attests; the `cid` recovers `(r, client_id, org_id)` under `K_M-A`,
/// cross-checked against the org this role serves.
async fn issue_discharge(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(k_m_a) = state.store.k_m_a().copied() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "k_m_a unavailable");
    };
    let Some(k_session) = state.store.k_session().copied() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "k_session unavailable");
    };

    let now_unix = Utc::now().timestamp().max(0) as u64;
    let claims = match verify_session(&k_session, &headers, now_unix) {
        Ok(c) => c,
        Err(()) => return error(StatusCode::UNAUTHORIZED, "session required"),
    };

    let req: DischargeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad request"),
    };
    // The authorization decision `/v1/discharge` makes: the session must
    // grant the requested scope. Distinct from the liveness gate above —
    // a valid session that lacks the scope is `403`, not `401`.
    if !claims.scopes.iter().any(|s| s == &req.scope) {
        return error(StatusCode::FORBIDDEN, "scope not granted");
    }
    let cid = match BASE64.decode(req.cid.trim()) {
        Ok(b) => b,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad cid"),
    };
    // Recover `r` and the bound identity from the CID under K_M-A — the
    // dual of the verifier's VID path. A `cid` that fails to decrypt
    // signals a `K_M-A` rotation (422), distinct from a malformed
    // request (400).
    let pt = match tpc::decrypt_cid(&k_m_a, &cid) {
        Ok(pt) => pt,
        Err(_) => return error(StatusCode::UNPROCESSABLE_ENTITY, "cid decrypt"),
    };
    if state.store.org_id() != Some(pt.org_id.as_str()) {
        return error(StatusCode::FORBIDDEN, "org mismatch");
    }

    let not_after = now_unix + DISCHARGE_EXP_SECONDS;
    let discharge = mint_under_key(
        &pt.r,
        DISCHARGE_KID,
        vec![
            Caveat::scalar("Subject", &claims.subject),
            Caveat::scalar("OrgId", pt.org_id),
            Caveat::scalar("ClientId", pt.client_id),
            Caveat::scalar(name::SCOPE, &req.scope),
            Caveat::scalar(name::NOT_AFTER, not_after.to_string()),
        ],
    );

    (
        StatusCode::OK,
        axum::Json(json!({"discharge": discharge.encode()})),
    )
        .into_response()
}

fn error(status: StatusCode, msg: &'static str) -> Response {
    (status, axum::Json(json!({"error": msg}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macaroon::mint_under_key_with_nonce;
    use rand_core::{OsRng, RngCore};

    fn bearer(session: &Macaroon) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", session.encode()).parse().unwrap(),
        );
        h
    }

    #[test]
    fn session_round_trips_and_returns_subject_and_scopes() {
        let k = [21u8; 32];
        let s = mint_session(&k, "operator-alice", 1_000);
        let claims = verify_session(&k, &bearer(&s), 1_000).expect("valid session");
        assert_eq!(claims.subject, "operator-alice");
        // The demo grants every scope.
        assert!(claims.scopes.iter().any(|s| s == scope::MINT_ENROLL));
        assert!(claims.scopes.iter().any(|s| s == scope::MINT_EXCHANGE));
        assert!(claims.scopes.iter().any(|s| s == scope::MINT_ADMIN));
    }

    #[test]
    fn session_under_wrong_key_rejected() {
        let s = mint_session(&[21u8; 32], "alice", 1_000);
        assert!(verify_session(&[22u8; 32], &bearer(&s), 1_000).is_err());
    }

    #[test]
    fn expired_session_rejected() {
        let s = mint_session(&[21u8; 32], "alice", 1_000);
        let later = 1_000 + SESSION_EXP_SECONDS + 1;
        assert!(verify_session(&[21u8; 32], &bearer(&s), later).is_err());
    }

    #[test]
    fn missing_bearer_rejected() {
        assert!(verify_session(&[21u8; 32], &HeaderMap::new(), 1_000).is_err());
    }

    #[test]
    fn non_session_op_rejected() {
        let m = mint_under_key(
            &[21u8; 32],
            SESSION_KID,
            vec![
                Caveat::scalar(name::OP, "not-session"),
                Caveat::scalar("Subject", "alice"),
            ],
        );
        assert!(verify_session(&[21u8; 32], &bearer(&m), 1_000).is_err());
    }

    #[test]
    fn r_is_deterministic_in_nonce_and_kma() {
        let k = [3u8; 32];
        let n = [7u8; NONCE_LEN];
        assert_eq!(derive_discharge_r(&k, &n), derive_discharge_r(&k, &n));
    }

    #[test]
    fn r_differs_per_nonce_and_per_kma() {
        let k0 = [3u8; 32];
        let mut k1 = k0;
        k1[0] ^= 0x80;
        let n0 = [7u8; NONCE_LEN];
        let mut n1 = n0;
        n1[0] ^= 0x01;
        let base = derive_discharge_r(&k0, &n0);
        assert_ne!(base, derive_discharge_r(&k1, &n0));
        assert_ne!(base, derive_discharge_r(&k0, &n1));
    }

    #[test]
    fn issued_discharge_round_trips_under_recovered_r() {
        // The discharge-as-primary property the verifier's
        // resolve_primary_key path relies on: recover `r` from
        // (K_M-A, nonce) and confirm the chain MAC verifies.
        let k_m_a = [3u8; 32];
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let r = derive_discharge_r(&k_m_a, &nonce);
        let discharge = mint_under_key_with_nonce(
            &r,
            DISCHARGE_KID,
            nonce,
            vec![
                Caveat::scalar(name::AUD, "mint"),
                Caveat::scalar(name::OP, "admin:invite-read"),
                Caveat::scalar(name::CNF, "ed25519:AAAA"),
                Caveat::scalar(name::NOT_AFTER, "1700000000"),
            ],
        );
        let wire = discharge.encode();
        let decoded = Macaroon::decode(&wire).expect("decode");
        let recovered = derive_discharge_r(&k_m_a, decoded.nonce());
        assert!(decoded.verify_under_key(&recovered));
        let mut wrong = k_m_a;
        wrong[31] ^= 0x01;
        let bad = derive_discharge_r(&wrong, decoded.nonce());
        assert!(!decoded.verify_under_key(&bad));
    }
}
