//! mint-as-auth role — demo-only discharge issuer.
//!
//! Structurally separate from the mint role. The discharge route
//! mounts only when `[auth].demo_enabled = true`; production deploys
//! run a standalone auth-service binary that issues discharges over
//! its own wire and shares `K_M-A` with mint. Mint's
//! [`verify_and_clear`](crate::http::verify_and_clear) verifies any
//! discharge by recovering `r` from the anchor's `vid` regardless of
//! where the discharge was minted, so this module can later move out
//! of the mint binary without disturbing the verifier.
//!
//! Session gate (`docs/design-auth-service.md` § *Login flow*): every
//! `/v1/discharge` request must carry `Authorization: Bearer
//! <session>` — a session macaroon minted by `POST /v1/login` under
//! `K_session`. The demo accepts any subject at login (no password);
//! the session is the *gate* on discharge issuance, and its `sub`
//! is what each discharge attests. Production auth-service authenticates
//! login for real and issues sessions over its own wire; the gate shape
//! is the same.
//!
//! Wire (`POST /v1/login`):
//!
//! ```text
//! request body:  { "subject": "<opaque>" }
//! 200 OK:        { "session": "mnt2_<base64url>" }
//! ```
//!
//! Wire (`POST /v1/discharge`):
//!
//! ```text
//! Authorization: Bearer mnt2_<session>
//! request body:  { "cid": "<base64url of the anchor's TPC CID>",
//!                  "scope": "mint:enroll" | "mint:exchange" | "mint:admin" }
//! 200 OK:        { "discharge": "mnt2_<base64url>" }
//! 403:           session valid but does not grant the requested scope
//! ```
//!
//! Discharge construction: require `scope ∈ session.scopes` (the
//! authorization decision; `403` otherwise), then decrypt `cid` under
//! `K_M-A` ([`tpc::decrypt_cid`]) to recover `(r, client_id, org_id)` —
//! no `K_M`, no per-client state — and reject if `org_id` is not the org
//! this role serves. Mint a discharge macaroon chain-MAC'd under that
//! `r`, caveats `aud`, `sub` (the session subject — the
//! authenticated human, in the discharge's own context), `Scope` (the
//! requested class, cleared by the gate), `exp`. `org_id`/`client_id` are
//! not stamped as caveats — nothing reads them; the org is checked
//! here. No `op`: per-op narrowing is the
//! caller's attenuation onto the primary (the PoP'd anchor), so one
//! discharge satisfies every op that primary is attenuated for. Mint's verifier
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
use crate::macaroon::{KeyRef, Macaroon, mint_under_key, mint_under_key_with_nonce};
use crate::tpc;

/// Demo discharge lifetime. Long enough for a CLI command to round-trip
/// from auth to mint, short enough that a leaked discharge has minimal
/// window. Demo only — production auth-service controls this per its
/// own policy.
const DISCHARGE_EXP_SECONDS: u64 = 300;

/// Demo session lifetime — `~7 days` per `docs/design-auth-service.md`
/// § *Cadence*. The operator re-runs `mint login` when it lapses.
const SESSION_EXP_SECONDS: u64 = 7 * 24 * 60 * 60;

/// The `/v1/discharge` request body. Shared with the client side
/// (`crate::operator`) so the bytes a caller serialises and the bytes
/// the handler deserialises are one type — a missing or misnamed field
/// is a compile error, not a runtime 400.
#[derive(Deserialize, Serialize)]
pub(crate) struct DischargeRequest {
    /// Base64url of the anchor's third-party-caveat `CID` (the invite's,
    /// the ticket's, or the admin-service's). The auth role decrypts it under
    /// `K_M-A` to recover the discharge key `r` and the bound
    /// `(client_id, org_id)`.
    pub(crate) cid: String,
    /// The authority class the caller needs — `mint:enroll`,
    /// `mint:exchange`, or `mint:admin`. Auth issues only if the session
    /// grants it, and stamps it as the discharge's `Scope` caveat for the
    /// gate to clear (`docs/design-auth-service.md` § *Discharge flows*).
    pub(crate) scope: String,
}

/// The set of scopes a session grants, parsed from the session's
/// **single** canonical `scope` caveat. Carrying the grant as one
/// scalar — not one caveat per scope — is what keeps it append-safe: a
/// holder cannot append a `scope` caveat to add a scope, because two
/// `scope` caveats resolve to `Unsatisfiable` (→ empty grant), exactly
/// like every other scalar. The set is private so no caller can iterate
/// it and ask a membership question over loose, separately-appendable
/// values; the only question is [`grants`](Self::grants), answered
/// against this one tamper-evident value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantedScopes(std::collections::BTreeSet<String>);

impl GrantedScopes {
    /// The canonical wire value for a set of scopes: sorted and
    /// space-joined into one string. Scope tokens never contain
    /// whitespace, so the separator is unambiguous. This is what
    /// [`mint_session`] stamps as the lone `scope` caveat value.
    pub fn canonical(scopes: &[&str]) -> String {
        let set: std::collections::BTreeSet<&str> = scopes.iter().copied().collect();
        set.into_iter().collect::<Vec<_>>().join(" ")
    }

    /// Parse a resolved canonical `scope` value back into a set.
    fn parse(value: &str) -> Self {
        GrantedScopes(value.split_whitespace().map(str::to_owned).collect())
    }

    /// Whether `scope` is in the granted set. Membership over a value
    /// recovered from a single caveat — not over an appendable list — so
    /// it cannot be widened by a holder.
    pub fn grants(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }
}

/// A verified session's claims: the `sub` the discharge attests and
/// the granted scopes the issuance check is made against.
pub struct SessionClaims {
    pub subject: String,
    pub scopes: GrantedScopes,
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
/// `op=session`, `sub=<subject>`, the granted scopes as one canonical
/// `scope` caveat, and `exp=now+7d`. A fresh chain (not an attenuation),
/// keyed by `K_session`, so it is structurally distinct from every
/// mint-issued macaroon and verifiable only by this role. The granted
/// scopes are a **single** scalar caveat ([`GrantedScopes::canonical`]),
/// not one caveat each — appending a second `scope` caveat makes the set
/// `Unsatisfiable` (→ empty grant), so a holder cannot widen the grant.
/// The demo grants **every** scope to every subject — login stays
/// wide-open, but the grant is explicit on the session
/// (`docs/design-auth-service.md` § *Scope tier*); production
/// auth-service decides the grant per its own policy.
fn mint_session(k_session: &[u8; 32], subject: &str, now_unix: u64) -> Macaroon {
    let exp = now_unix + SESSION_EXP_SECONDS;
    let scopes =
        GrantedScopes::canonical(&[scope::MINT_ENROLL, scope::MINT_EXCHANGE, scope::MINT_ADMIN]);
    mint_under_key(
        k_session,
        KeyRef::Session,
        vec![
            Caveat::scalar(name::OP, op::SESSION),
            Caveat::scalar(name::SUB, subject),
            Caveat::scalar(name::SCOPE, scopes),
            Caveat::scalar(name::EXP, exp.to_string()),
        ],
    )
}

/// Verify a session presented in `Authorization: Bearer <session>`:
/// chain MAC under `K_session`, `op=session`, and a non-expired
/// `exp`. Returns the session's `sub` and granted `Scope` set
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
    if mac.key_ref() != KeyRef::Session {
        return Err(());
    }
    if !mac.verify_under_key(k_session) {
        return Err(());
    }
    let eff = EffectiveCaveats::new(mac.caveats());
    if !matches!(eff.resolve(name::OP), Resolved::Value(v) if v == op::SESSION) {
        return Err(());
    }
    if let Some(exp) = eff.min_bound(name::EXP)
        && exp <= now_unix
    {
        return Err(());
    }
    // Scopes clear like every other scalar: the grant is a single
    // canonical `scope` caveat, read through `resolve`. Absent → no
    // grant; a second, disagreeing `scope` caveat → `Unsatisfiable` →
    // no grant. A holder cannot append a `scope` caveat to widen the
    // set — the same tri-state that protects `aud`/`role`/`exp`.
    let scopes = match eff.resolve(name::SCOPE) {
        Resolved::Value(v) => GrantedScopes::parse(&v),
        Resolved::Absent | Resolved::Unsatisfiable => GrantedScopes::default(),
    };
    match eff.resolve(name::SUB) {
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
/// third-party caveat. The session's `sub` is what the discharge
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
    if !claims.scopes.grants(&req.scope) {
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

    let exp = now_unix + DISCHARGE_EXP_SECONDS;
    // The discharge names the third-party caveat it answers by stamping
    // the ticket id (derived from this CID) into its nonce. The verifier
    // pairs discharges to TPCs by that id, never by presentation order.
    let discharge = mint_under_key_with_nonce(
        &pt.r,
        KeyRef::Discharge,
        tpc::ticket_id(&cid),
        vec![
            // The discharge declares its own audience and clears it
            // per-macaroon at the bundle, like the primary.
            Caveat::scalar(name::AUD, &state.config.audience),
            // The authenticated human the discharge attests — `sub` in the
            // discharge's own context, never reconciled with the primary's
            // `sub` (the machine). `org_id`/`client_id` from the CID are
            // not re-stamped as caveats: nothing reads them, the org is
            // already checked above.
            Caveat::scalar(name::SUB, &claims.subject),
            Caveat::scalar(name::SCOPE, &req.scope),
            Caveat::scalar(name::EXP, exp.to_string()),
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
        assert!(claims.scopes.grants(scope::MINT_ENROLL));
        assert!(claims.scopes.grants(scope::MINT_EXCHANGE));
        assert!(claims.scopes.grants(scope::MINT_ADMIN));
    }

    #[test]
    fn session_under_wrong_key_rejected() {
        let s = mint_session(&[21u8; 32], "alice", 1_000);
        assert!(verify_session(&[22u8; 32], &bearer(&s), 1_000).is_err());
    }

    /// A holder cannot widen their granted scopes by appending a `scope`
    /// caveat. The session grant is a single canonical `scope` caveat;
    /// appending a second one makes it `Unsatisfiable` → empty grant, so
    /// every scope is denied — not just the one not originally granted.
    /// This is the regression for the membership-read escalation
    /// (`docs/finding-membership-caveat-read.md`).
    #[test]
    fn appended_scope_caveat_cannot_widen_the_grant() {
        let k = [21u8; 32];
        // A narrow session: enroll only (the production shape — the demo
        // grants all three, leaving nothing to escalate to).
        let narrow = mint_under_key(
            &k,
            KeyRef::Session,
            vec![
                Caveat::scalar(name::OP, op::SESSION),
                Caveat::scalar(name::SUB, "alice"),
                Caveat::scalar(name::SCOPE, GrantedScopes::canonical(&[scope::MINT_ENROLL])),
                Caveat::scalar(name::EXP, "2000"),
            ],
        );
        // Sanity: the un-tampered narrow session grants exactly enroll.
        let claims = verify_session(&k, &bearer(&narrow), 1_000).expect("valid");
        assert!(claims.scopes.grants(scope::MINT_ENROLL));
        assert!(!claims.scopes.grants(scope::MINT_ADMIN));

        // The holder appends `scope=mint:admin` with only the trailing
        // MAC — a legal chain extension, so the MAC still verifies.
        let tampered = narrow.attenuate(Caveat::scalar(name::SCOPE, scope::MINT_ADMIN));
        let claims = verify_session(&k, &bearer(&tampered), 1_000).expect("mac still valid");
        // Two disagreeing `scope` caveats → Unsatisfiable → empty grant.
        assert!(
            !claims.scopes.grants(scope::MINT_ADMIN),
            "must not gain admin"
        );
        assert!(
            !claims.scopes.grants(scope::MINT_ENROLL),
            "the grant collapses entirely — fail closed, never widen"
        );
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
            KeyRef::Session,
            vec![
                Caveat::scalar(name::OP, "not-session"),
                Caveat::scalar(name::SUB, "alice"),
            ],
        );
        assert!(verify_session(&[21u8; 32], &bearer(&m), 1_000).is_err());
    }
}
