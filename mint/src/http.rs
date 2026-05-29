//! HTTP surface (`docs/design-mint.md` § *Protocol*).
//!
//! ```text
//! POST /v1/assume-role      op=assume-role   (per request)
//! POST /v1/enroll           op=enroll        (creates a pending record)
//! POST /v1/enroll-exchange  op=enroll-exchange (403 until approved)
//! GET  /healthz
//! ```
//!
//! Authentication is identical across all three operations: MAC against
//! the root, the positively-required `op` for the endpoint, `aud`, and
//! the holder-of-key PoP over `tail ‖ BLAKE3(body)` (the body is the
//! freshness `ts` for the enrollment endpoints, the full exercise body
//! for `assume-role`). Every failure is an opaque `401` with no detail
//! so an attacker can't distinguish causes; role/caveat denial is
//! `400`; backend failure `503`. The **sole** non-`401` authorization
//! outcome is `/v1/enroll-exchange` returning `403` for a
//! not-yet-approved pending record — an awaited state, not a failure.

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::audit::{AuditEntry, AuditLog, sanitise_caveats};
use crate::caveat::{Caveat, EffectiveCaveats, Resolved, name, op};
use crate::config::Config;
use crate::iam::{self, KeypairMinter};
use crate::issuance;
use crate::macaroon::Macaroon;
use crate::pop;
use crate::role::{self, Denied};
use crate::state::{Recorded, StateError, Store};
use crate::template::render_policy;

/// Credential-ticket lifetime. The ticket is multi-use within this
/// window: one operator approval, then the client exchanges it once
/// per role it needs (§ *Enrollment*). 10 min is a deliberate choice
/// — comfortably enough to mint the handful (3–4) of per-role
/// credentials a client holds, while keeping the pending record (and
/// so the approval) short-lived. If it lapses the client just
/// re-enrols (idempotent for the same `(sub, pub)` → fresh ticket);
/// a *new* role after expiry needs a fresh approval, by design.
const CREDENTIAL_TICKET_TTL_SECONDS: u64 = 600;
/// Unapproved pending records age out past this (≥ the credential
/// ticket `exp`, so a still-usable ticket always has its record).
const PENDING_MAX_AGE_SECONDS: u64 = 3600;

#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub minter: Arc<dyn KeypairMinter>,
    pub audit: Arc<AuditLog>,
    pub store: Arc<Store>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/assume-role", post(assume_role))
        .route("/v1/enroll", post(enroll))
        .route("/v1/enroll-exchange", post(enroll_exchange))
        .route("/v1/verify", post(discharge_verify))
        .with_state(state)
}

#[derive(Deserialize)]
struct AssumeRoleBody {
    role: String,
    ttl_seconds: Option<u64>,
}

/// `/v1/enroll-exchange` body — `{ts, role}`. `ts` is handled by the
/// PoP machinery (it signs the whole body); `role` is the role this
/// exchange mints a credential for, authenticated by that same
/// signature.
#[derive(Deserialize)]
struct ExchangeBody {
    role: String,
}

fn respond(request_id: &str, status: StatusCode, body: serde_json::Value) -> Response {
    let mut resp = (status, axum::Json(body)).into_response();
    if let Ok(v) = request_id.parse() {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

fn unauthorized(request_id: &str) -> Response {
    respond(
        request_id,
        StatusCode::UNAUTHORIZED,
        json!({"error": "unauthorized"}),
    )
}

/// A `(primary, discharges)` bundle parsed from
/// `Authorization: MintV1 mnt1_<b64url>[,mnt1_<b64url>...]`. Primary is
/// positionally first; discharges follow in the order they
/// position-match the primary's TPCs. Used at the verify+clear
/// endpoints.
pub struct Bundle {
    pub primary: Macaroon,
    pub discharges: Vec<Macaroon>,
}

/// Parse `Authorization: MintV1 <m>[,<m>...]` into a bundle. Single
/// macaroon → bundle with empty discharges. The scheme name is
/// `MintV1` at every macaroon-bearing endpoint; the payload's
/// per-macaroon `mnt1_` prefix keeps individual macaroons greppable
/// in logs even when concatenated.
pub fn extract_bundle(headers: &HeaderMap) -> Option<Bundle> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let payload = raw.strip_prefix("MintV1 ")?;
    let mut parts = payload.split(',').map(|s| s.trim());
    let primary = Macaroon::decode(parts.next()?).ok()?;
    let mut discharges = Vec::new();
    for p in parts {
        discharges.push(Macaroon::decode(p).ok()?);
    }
    Some(Bundle {
        primary,
        discharges,
    })
}

/// Pull a single bearer macaroon out of `Authorization: MintV1 <m>`.
/// Used at single-credential endpoints (enrollment, admin); rejects
/// a comma-separated bundle.
fn extract_macaroon(headers: &HeaderMap) -> Option<Macaroon> {
    let bundle = extract_bundle(headers)?;
    if !bundle.discharges.is_empty() {
        return None;
    }
    Some(bundle.primary)
}

fn peer_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
}

/// A scalar caveat must be present and equal to `expected` — the
/// positive-value gate (`op`/`aud`). Absent, contradictory, or any
/// other value all fail closed; no path tests for absence.
fn scalar_is(caveats: &[Caveat], n: &str, expected: &str) -> bool {
    matches!(
        EffectiveCaveats::new(caveats).resolve(n),
        Resolved::Value(v) if v == expected
    )
}

/// The detached PoP from `X-Mint-Pop`, if syntactically present.
/// A malformed header is a hard `Err` (caller maps to 401); absence is
/// `Ok(None)` (caller decides whether key-binding is required).
// The error variant carries no information by design — every PoP
// failure collapses to opaque 401 at the HTTP layer (audit log is
// where the variant lives, not the wire). The unit error type makes
// the call-site shape unambiguous.
#[allow(clippy::result_unit_err)]
pub fn pop_proof(headers: &HeaderMap) -> Result<Option<pop::Proof>, ()> {
    match headers.get("x-mint-pop").and_then(|v| v.to_str().ok()) {
        Some(sig) => pop::Proof::from_b64(sig).map(Some).map_err(|_| ()),
        None => Ok(None),
    }
}

/// Output of [`verify_and_clear`]: the primary, the union of verified
/// caveats across the bundle, and the bundle-wide minimum `NotAfter`.
pub struct ClearedBundle {
    pub primary: Macaroon,
    pub aggregated_caveats: Vec<Caveat>,
    /// Minimum `exp` across the primary and every verified discharge,
    /// if any are present. `None` means the bundle carries no `exp`.
    pub expires_at: Option<u64>,
}

/// Why verify+clear refused a bundle. The HTTP layer translates each
/// variant per endpoint — `/v1/verify` returns `{valid:false, reason}`,
/// `/v1/assume-role` returns an opaque `401`. The `reason` strings
/// are stable identifiers for audit / forensics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyClearError {
    Auth(&'static str),
    Pop,
    AudClear,
    OpClear,
    Expired,
}

impl VerifyClearError {
    pub fn reason(&self) -> &'static str {
        match self {
            VerifyClearError::Auth(r) => r,
            VerifyClearError::Pop => "pop",
            VerifyClearError::AudClear => "aud_clear",
            VerifyClearError::OpClear => "op_clear",
            VerifyClearError::Expired => "expired",
        }
    }
}

/// Walk the bundle's chain MACs (primary first, then each discharge
/// under the `r` recovered from its matched TPC's `VID`, recursing to
/// fixpoint on nested TPCs), then clear the universal first-party
/// caveats — `aud` ≡ `expected_aud`, `op` ≡ `expected_op`, `cnf`+PoP
/// against the primary's tail and the raw request body, and `exp` (if
/// present) in the future. Both bundle endpoints
/// (`/v1/assume-role`, `/v1/verify`) invoke this; assume-role layers
/// role-specific clearing and IAM issuance on top of the result.
///
/// The bundle's *primary* may be either:
///
/// 1. **Mint-issued** — `kid` matches a generation in mint's keyring;
///    the chain seed verifies under `K_M`. This is the long-lived
///    credential path (coord-side `assume-role`, `enroll-exchange`).
/// 2. **Auth-issued discharge** — `kid == DISCHARGE_KID`; the chain
///    seed verifies under `r` derived from `(K_M-A, nonce)`. This is
///    the per-action operator-authority path (`admin:*` endpoints under
///    the consolidation, or any future verifier of standalone
///    discharges).
///
/// The two paths use *different* key sources (`K_M` vs. `K_M-A`-derived
/// `r`) — no code path conflates them; an attacker without `K_M-A`
/// cannot produce a discharge that verifies, and an attacker without
/// `K_M` cannot produce a mint-issued primary that verifies.
///
/// Returns the union of caveats across the bundle and the
/// bundle-wide minimum `NotAfter` — the verify endpoint returns
/// these verbatim; assume-role hands the caveats to [`role::authorize`]
/// for the role-specific gate.
// Each input is independently meaningful at every call site (keyring +
// K_M-A + body + expected caveats are all separate concerns). A
// builder/struct wrapper would obscure that without removing any
// coupling.
#[allow(clippy::too_many_arguments)]
pub fn verify_and_clear(
    bundle: &Bundle,
    keyring: &crate::keyring::Keyring,
    k_m_a: Option<&[u8; 32]>,
    proof: Option<pop::Proof>,
    body: &[u8],
    now_unix: u64,
    expected_aud: &str,
    expected_op: &str,
) -> Result<ClearedBundle, VerifyClearError> {
    let primary_key = resolve_primary_key(&bundle.primary, keyring, k_m_a)?;

    let mut aggregated: Vec<Caveat> = Vec::new();
    let mut discharge_cursor = 0usize;
    let mut work: std::collections::VecDeque<(Macaroon, [u8; 32])> =
        std::collections::VecDeque::new();
    work.push_back((bundle.primary.clone(), primary_key));

    while let Some((mac, key)) = work.pop_front() {
        let sites = mac
            .verify_collecting_tpcs(&key)
            .ok_or(VerifyClearError::Auth("mac_mismatch"))?;
        for site in sites {
            let r = crate::tpc::decrypt_vid(&site.t_n_minus_1, site.vid)
                .map_err(|_| VerifyClearError::Auth("vid_decrypt"))?;
            let discharge = bundle
                .discharges
                .get(discharge_cursor)
                .ok_or(VerifyClearError::Auth("tpc_undischarged"))?;
            discharge_cursor += 1;
            work.push_back((discharge.clone(), r));
        }
        aggregated.extend(mac.caveats().iter().cloned());
    }
    if discharge_cursor != bundle.discharges.len() {
        return Err(VerifyClearError::Auth("excess_discharges"));
    }

    // PoP is checked against the primary's caveats with the primary's
    // tail — the principal whose chain is being exercised. Discharges
    // carry their own `cnf` caveats but they are not request-time
    // PoP'd (the per-forward freshness is the primary's per-forward
    // `NotAfter` attenuation).
    pop::check(
        bundle.primary.caveats(),
        bundle.primary.tail(),
        body,
        proof,
        now_unix,
    )
    .map_err(|_| VerifyClearError::Pop)?;

    let eff = EffectiveCaveats::new(&aggregated);
    if !matches!(eff.resolve(name::AUD), Resolved::Value(v) if v == expected_aud) {
        return Err(VerifyClearError::AudClear);
    }
    if !matches!(eff.resolve(name::OP), Resolved::Value(v) if v == expected_op) {
        return Err(VerifyClearError::OpClear);
    }
    // Two deadline names bind: `exp` (the credential's own expiry) and
    // `NotAfter` (borne by discharges and by per-IPC / per-forward
    // attenuations). The minimum across both is the bundle's effective
    // deadline — the tightest attenuation wins.
    let expires_at = match (eff.not_after(name::EXP), eff.not_after(name::NOT_AFTER)) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    if let Some(deadline) = expires_at
        && deadline <= now_unix
    {
        return Err(VerifyClearError::Expired);
    }

    Ok(ClearedBundle {
        primary: bundle.primary.clone(),
        aggregated_caveats: aggregated,
        expires_at,
    })
}

/// Resolve the chain-MAC seed key for the bundle's primary. Two
/// disjoint paths, distinguished structurally:
///
/// - **Mint-issued primary**: `primary.kid()` matches a generation in
///   the keyring → seed key is `keyring.get(kid)`. The chain MAC then
///   verifies under `K_M`.
/// - **Auth-issued discharge**: `primary.kid() == DISCHARGE_KID` →
///   seed key is `auth::derive_discharge_r(K_M-A, primary.nonce())`.
///   The chain MAC then verifies under `r` recovered from `K_M-A`.
///
/// Anything else (unknown kid, or `DISCHARGE_KID` with no `K_M-A`
/// available) is `Auth("unknown_kid")`. The two paths use *different*
/// key sources by construction — there is no code path that admits
/// one's bytes under the other's key.
fn resolve_primary_key(
    primary: &Macaroon,
    keyring: &crate::keyring::Keyring,
    k_m_a: Option<&[u8; 32]>,
) -> Result<[u8; 32], VerifyClearError> {
    // Dispatch on the kid sentinel first: discharges use the reserved
    // `DISCHARGE_KID` and never appear in the keyring. Checking this
    // before the keyring lookup keeps the two paths cleanly disjoint
    // even if the keyring were ever extended past the sentinel.
    if primary.kid() == crate::macaroon::DISCHARGE_KID {
        let Some(k_m_a) = k_m_a else {
            return Err(VerifyClearError::Auth("unknown_kid"));
        };
        return Ok(crate::auth::derive_discharge_r(k_m_a, primary.nonce()));
    }
    keyring
        .get(primary.kid())
        .copied()
        .ok_or(VerifyClearError::Auth("unknown_kid"))
}

async fn assume_role(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let caller = peer_ip(&headers);
    let audit = |entry: AuditEntry| state.audit.record(&entry);
    let now = Utc::now();
    let now_unix = now.timestamp().max(0) as u64;
    let base_entry = |outcome: &str| AuditEntry {
        timestamp: now.to_rfc3339(),
        request_id: request_id.clone(),
        caller_address: caller.clone(),
        macaroon_nonce: None,
        macaroon_caveats: Vec::new(),
        role: String::new(),
        granted_ttl_seconds: None,
        outcome: outcome.to_string(),
        tigris_access_key_id: None,
    };

    // --- Bundle + PoP extraction. ---
    let Some(bundle) = extract_bundle(&headers) else {
        audit(base_entry("denied:unauthenticated"));
        return unauthorized(&request_id);
    };
    let proof = match pop_proof(&headers) {
        Ok(p) => p,
        Err(()) => {
            audit(base_entry("denied:pop"));
            return unauthorized(&request_id);
        }
    };

    // --- Verify+clear: shared with /v1/verify. Walks chain MACs,
    // resolves discharges, clears aud/op/cnf+PoP/exp. ---
    let keyring = state.store.keyring().await;
    let cleared = match verify_and_clear(
        &bundle,
        &keyring,
        state.store.k_m_a(),
        proof,
        &body,
        now_unix,
        &state.config.audience,
        op::ASSUME_ROLE,
    ) {
        Ok(c) => c,
        Err(e) => {
            audit(base_entry(&format!("denied:{}", e.reason())));
            return unauthorized(&request_id);
        }
    };
    let caveats = cleared.aggregated_caveats;
    let nonce_hex = cleared.primary.nonce_hex();
    let entry = |outcome: &str, role: &str, ttl: Option<u64>, key: Option<String>| AuditEntry {
        timestamp: now.to_rfc3339(),
        request_id: request_id.clone(),
        caller_address: caller.clone(),
        macaroon_nonce: Some(nonce_hex.clone()),
        macaroon_caveats: sanitise_caveats(&caveats),
        role: role.to_string(),
        granted_ttl_seconds: ttl,
        outcome: outcome.to_string(),
        tigris_access_key_id: key,
    };

    // --- Request body (the exact bytes the PoP already covered). ---
    let Ok(req) = serde_json::from_slice::<AssumeRoleBody>(&body) else {
        audit(entry("denied:bad_request", "", None, None));
        return respond(
            &request_id,
            StatusCode::BAD_REQUEST,
            json!({"error": "bad request"}),
        );
    };
    let request_json: serde_json::Value =
        serde_json::from_slice(&body).unwrap_or(serde_json::Value::Null);

    let requested_ttl = match req.ttl_seconds {
        Some(t) => t,
        None => match state.config.roles.get(&req.role) {
            Some(r) => r.default_ttl_seconds,
            None => {
                audit(entry("denied:unknown_role", &req.role, None, None));
                return respond(
                    &request_id,
                    StatusCode::BAD_REQUEST,
                    json!({"error": "bad request"}),
                );
            }
        },
    };

    let granted = match role::authorize(&state.config, &caveats, &req.role, requested_ttl, now_unix)
    {
        Ok(g) => g,
        Err(d) => {
            audit(entry(
                &format!("denied:{}", denied_tag(&d)),
                &req.role,
                None,
                None,
            ));
            return respond(
                &request_id,
                StatusCode::BAD_REQUEST,
                json!({"error": "bad request"}),
            );
        }
    };

    let expiry = now + chrono::Duration::seconds(granted.ttl_seconds as i64);
    let expiry_iso = expiry.to_rfc3339();
    let policy = match render_policy(
        &granted.role.policy,
        &state.config.tenant,
        &caveats,
        &request_json,
        &expiry_iso,
        &granted.role.name,
    ) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, role = %req.role, "policy render failed");
            audit(entry("denied:policy_render", &req.role, None, None));
            return respond(
                &request_id,
                StatusCode::BAD_REQUEST,
                json!({"error": "bad request"}),
            );
        }
    };

    let scope = match EffectiveCaveats::new(&caveats).resolve("elide:Volume") {
        Resolved::Value(v) => Some(v),
        Resolved::Absent | Resolved::Unsatisfiable => None,
    };
    let policy_name = iam::policy_name(&granted.role.name, scope.as_deref(), expiry);

    match state
        .minter
        .mint_keypair(
            &policy_name,
            &policy,
            Duration::from_secs(granted.ttl_seconds),
        )
        .await
    {
        Ok(kp) => {
            audit(entry(
                "granted",
                &req.role,
                Some(granted.ttl_seconds),
                Some(kp.access_key_id.clone()),
            ));
            respond(
                &request_id,
                StatusCode::OK,
                json!({
                    "access_key_id": kp.access_key_id,
                    "secret_access_key": kp.secret_access_key,
                    "expiration": kp.expiration.to_rfc3339(),
                }),
            )
        }
        Err(e) => {
            tracing::error!(error = %e, "keypair mint failed");
            audit(entry(
                "tigris_error",
                &req.role,
                Some(granted.ttl_seconds),
                None,
            ));
            let mut resp = respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
            if let Ok(v) = "5".parse() {
                resp.headers_mut().insert("retry-after", v);
            }
            resp
        }
    }
}

/// `POST /v1/enroll` (`docs/design-mint.md` § *Enrollment* (1)). The
/// client presents the client-attenuated invite macaroon
/// (`op=enroll`, current `invite`, self-asserted `sub`/`cnf`) and a
/// PoP. Mint records a **pending** record keyed by `sub` and returns a
/// short-lived credential ticket. Always `200` for an accepted
/// (new or idempotent) `(sub, pub)`; conflicts and auth failures are
/// the opaque `401`.
async fn enroll(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let caller = peer_ip(&headers);
    let now_unix = Utc::now().timestamp().max(0) as u64;
    let audit = |outcome: &str, caveats: &[Caveat]| {
        state.audit.record(&AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            request_id: request_id.clone(),
            caller_address: caller.clone(),
            macaroon_nonce: None,
            macaroon_caveats: sanitise_caveats(caveats),
            role: String::new(),
            granted_ttl_seconds: None,
            outcome: format!("enroll:{outcome}"),
            tigris_access_key_id: None,
        });
    };

    // Opportunistic GC keeps the pending table transient.
    if let Err(e) = state.store.gc(now_unix, PENDING_MAX_AGE_SECONDS).await {
        tracing::warn!(error = %e, "pending gc failed");
    }

    let Some(mac) = extract_macaroon(&headers) else {
        audit("denied:unauthenticated", &[]);
        return unauthorized(&request_id);
    };
    let keyring = state.store.keyring().await;
    if !mac.verify(&keyring) {
        audit("denied:bad_mac", &[]);
        return unauthorized(&request_id);
    }
    let caveats = mac.caveats().to_vec();

    if !scalar_is(&caveats, name::OP, op::ENROLL)
        || !scalar_is(&caveats, name::AUD, &state.config.audience)
    {
        audit("denied:wrong_op", &caveats);
        return unauthorized(&request_id);
    }
    let current = match state.store.current_invite().await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "read invite nonce");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        }
    };
    if !scalar_is(&caveats, name::INVITE, &current) {
        audit("denied:stale_invite", &caveats);
        return unauthorized(&request_id);
    }

    // Body is the freshness ts only.
    let proof = match pop_proof(&headers) {
        Ok(p) => p,
        Err(()) => {
            audit("denied:pop", &caveats);
            return unauthorized(&request_id);
        }
    };
    if pop::check(&caveats, mac.tail(), &body, proof, now_unix).is_err() {
        audit("denied:pop", &caveats);
        return unauthorized(&request_id);
    }

    let (sub, cnf) = match issuance::bound_identity(&mac) {
        Ok(v) => v,
        Err(_) => {
            audit("denied:identity", &caveats);
            return unauthorized(&request_id);
        }
    };

    // Every Err branch returns the same opaque 401 to the client —
    // the audit tag is the only place we distinguish, so operators
    // reading mint's log can tell `denied:conflict` (genuine
    // key-rotation collision against an existing pending) from
    // `denied:bad_sub` (malformed sub at the boundary) from
    // `denied:state_error` (something we didn't anticipate). The
    // client signal is unchanged.
    let recorded = match state
        .store
        .record_pending(&sub, &cnf, &current, &caller, now_unix)
        .await
    {
        Ok(r) => r,
        Err(StateError::Io(e)) => {
            tracing::error!(error = %e, "record pending");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        }
        Err(StateError::Store(msg)) => {
            tracing::error!(error = %msg, "record pending (object store)");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        }
        Err(StateError::Conflict) => {
            audit("denied:conflict", &caveats);
            return unauthorized(&request_id);
        }
        Err(StateError::BadSub) => {
            audit("denied:bad_sub", &caveats);
            return unauthorized(&request_id);
        }
        Err(e) => {
            // Corrupt / Forged are handled inside `record_pending` by
            // falling through to the slow path, so reaching this arm
            // means a state-error variant we didn't expect to surface
            // here. Log loudly server-side; client still gets 401.
            tracing::warn!(error = %e, sub = %sub, "unexpected state error during record_pending");
            audit("denied:state_error", &caveats);
            return unauthorized(&request_id);
        }
    };

    let ticket = issuance::mint_credential_ticket(
        &keyring,
        &state.config.audience,
        &sub,
        &cnf,
        now_unix.saturating_add(CREDENTIAL_TICKET_TTL_SECONDS),
    );
    // Fast path (an existing `approved/<sub>` matches the presented
    // `cnf`) means /v1/enroll-exchange will succeed immediately on the
    // returned ticket without any operator action; the slow path
    // requires `mint enroll approve <sub>` to fire first.
    //
    // Lazy migration: every client restart pings /v1/enroll, so
    // this is the natural place to drift `_mint/approved/<sub>`
    // forward to the keyring's current kid (`docs/design-mint.md` §
    // *Root-key rotation*). Best-effort and untimed; failures are
    // logged, never blocking — the MAC check in `get_approved` is
    // what makes correctness load-bearing, not this write.
    if matches!(recorded, Recorded::AlreadyApproved) {
        match state.store.migrate_approval_to_current_kid(&sub).await {
            Ok(true) => tracing::info!(
                target: "mint::http",
                sub = %sub,
                kid = keyring.current_kid(),
                "approval lazily migrated to current kid",
            ),
            Ok(false) => {}
            Err(e) => tracing::warn!(
                target: "mint::http",
                sub = %sub,
                error = %e,
                "approval lazy migration failed; record still valid under prior kid",
            ),
        }
    }
    audit(
        match recorded {
            Recorded::AlreadyApproved => "fast_path",
            Recorded::Created | Recorded::Idempotent => "pending",
        },
        &caveats,
    );
    respond(
        &request_id,
        StatusCode::OK,
        json!({ "credential.ticket": ticket.encode() }),
    )
}

/// `POST /v1/enroll-exchange` (`docs/design-mint.md` § *Enrollment*
/// (3)) — the role-authorization point. The client presents the
/// credential ticket (`op=enroll-exchange`, unexpired `exp`), a PoP,
/// and a requested `role` in the PoP-signed body. If the pending
/// record is approved and `role` is a configured role, mint re-mints
/// a non-expiring, single-role credential from root. The record is
/// **not** consumed — the ticket is multi-use until its `exp` (one
/// approval, one credential per role); GC reclaims the record at that
/// bound. `403` (not `401`) while approval is still pending — the one
/// awaited, non-failure outcome.
async fn enroll_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let caller = peer_ip(&headers);
    let now_unix = Utc::now().timestamp().max(0) as u64;
    let audit = |outcome: &str, caveats: &[Caveat]| {
        state.audit.record(&AuditEntry {
            timestamp: Utc::now().to_rfc3339(),
            request_id: request_id.clone(),
            caller_address: caller.clone(),
            macaroon_nonce: None,
            macaroon_caveats: sanitise_caveats(caveats),
            role: String::new(),
            granted_ttl_seconds: None,
            outcome: format!("exchange:{outcome}"),
            tigris_access_key_id: None,
        });
    };

    let Some(mac) = extract_macaroon(&headers) else {
        audit("denied:unauthenticated", &[]);
        return unauthorized(&request_id);
    };
    let keyring = state.store.keyring().await;
    if !mac.verify(&keyring) {
        audit("denied:bad_mac", &[]);
        return unauthorized(&request_id);
    }
    let caveats = mac.caveats().to_vec();

    if !scalar_is(&caveats, name::OP, op::ENROLL_EXCHANGE)
        || !scalar_is(&caveats, name::AUD, &state.config.audience)
    {
        audit("denied:wrong_op", &caveats);
        return unauthorized(&request_id);
    }
    match EffectiveCaveats::new(&caveats).not_after(name::EXP) {
        Some(exp) if exp > now_unix => {}
        _ => {
            audit("denied:expired", &caveats);
            return unauthorized(&request_id);
        }
    }

    let proof = match pop_proof(&headers) {
        Ok(p) => p,
        Err(()) => {
            audit("denied:pop", &caveats);
            return unauthorized(&request_id);
        }
    };
    if pop::check(&caveats, mac.tail(), &body, proof, now_unix).is_err() {
        audit("denied:pop", &caveats);
        return unauthorized(&request_id);
    }

    let (sub, cnf) = match issuance::bound_identity(&mac) {
        Ok(v) => v,
        Err(_) => {
            audit("denied:identity", &caveats);
            return unauthorized(&request_id);
        }
    };

    // The approved-registry entry for this sub must exist and its
    // pinned pub must match the presented cnf — the operator approved
    // *this* (sub, pub) pair (`docs/design-mint.md` § *Enrollment* (3)).
    // The record also carries `r_epoch`, the input to TPC `r`
    // derivation for credentials that carry a TPC.
    let r_epoch = match state.store.get_approved(&sub).await {
        Ok(Some(a)) if a.pubkey == cnf => a.r_epoch,
        // The one non-401 authorization outcome: awaited, not a
        // failure. Includes both "never approved" and "approved
        // under a different pub" (pending key-rotation re-approval).
        // A `Forged` record (bucket-level tamper, or a record left
        // behind by a retired kid) is folded in here too: the client
        // gets no signal that distinguishes it from a missing record,
        // while the audit tag and `Store::get_approved`'s warn-log
        // give operators a forensic trail.
        // `Corrupt` joins `Forged` here for the same reason:
        // operationally it means "no record we can trust" — a
        // pre-#454 unsigned body, a partial overwrite, or anything
        // else that breaks deserialisation. The fix is operator
        // re-approval, identical to the Forged path.
        Ok(_) | Err(StateError::Forged | StateError::Corrupt) => {
            audit("awaiting_approval", &caveats);
            return respond(
                &request_id,
                StatusCode::FORBIDDEN,
                json!({"error": "awaiting operator approval"}),
            );
        }
        Err(StateError::Io(e)) => {
            tracing::error!(error = %e, "read approved");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        }
        Err(StateError::Store(msg)) => {
            tracing::error!(error = %msg, "read approved (object store)");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        }
        Err(StateError::BadSub) => {
            audit("denied:bad_sub", &caveats);
            return unauthorized(&request_id);
        }
        Err(e) => {
            // Conflict shouldn't reach `get_approved` (it's a
            // pending-side error); reaching this arm is the
            // unforeseen-state case. Log loudly, opaque 401 to client.
            tracing::warn!(error = %e, sub = %sub, "unexpected state error during get_approved");
            audit("denied:state_error", &caveats);
            return unauthorized(&request_id);
        }
    };

    // The requested role rides the PoP-signed body (already verified
    // above), so it is authenticated. Floor authorization (§
    // *Enrollment* (3), option (a)): it must name a configured role —
    // per-`sub` scoping lives in the role policy, not here. Failure is
    // the same opaque 401 as any other (a role this `sub` may not have
    // must not be distinguishable from a bad token).
    let role = match serde_json::from_slice::<ExchangeBody>(&body) {
        Ok(b) if state.config.roles.contains_key(&b.role) => b.role,
        _ => {
            audit("denied:unknown_role", &caveats);
            return unauthorized(&request_id);
        }
    };

    let mut credential =
        issuance::mint_credential(&keyring, &state.config.audience, &sub, &cnf, &role);

    // Operator-write roles carry a third-party caveat. Append it as a
    // chain extension off the just-minted credential's tail — the
    // chain MAC is incremental, so this is byte-identical to having
    // stamped the TPC inline at issuance. Config and Store invariants
    // guarantee the inputs are present when the role flag is set.
    if state.config.roles[&role].issues_with_tpc {
        let Some(auth) = state.config.auth.as_ref() else {
            tracing::error!("TPC-bearing role without [auth] reached issuance");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        };
        let Some(k_m_a) = state.store.k_m_a() else {
            tracing::error!("TPC-bearing role minted but K_M-A not loaded");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        };
        let Some(org_id) = state.store.org_id() else {
            tracing::error!("TPC-bearing role minted but OrgId not set");
            return respond(
                &request_id,
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "service unavailable"}),
            );
        };
        let r = crate::tpc::derive_r(keyring.current_key(), &sub, r_epoch);
        let tpc_caveat =
            crate::tpc::build_caveat(credential.tail(), &r, k_m_a, &sub, org_id, &auth.endpoint);
        credential = credential.attenuate(tpc_caveat);
    }
    // The approved-registry entry is not consumed: the ticket is
    // multi-use until its `exp` and the entry powers the re-enrollment
    // fast path beyond that.
    audit("granted", &caveats);
    respond(
        &request_id,
        StatusCode::OK,
        json!({ "credential": credential.encode() }),
    )
}

fn denied_tag(d: &Denied) -> &'static str {
    match d {
        Denied::UnknownRole => "unknown_role",
        Denied::WrongAudience => "wrong_audience",
        Denied::RoleNotPermitted => "role_not_permitted",
        Denied::MissingRequiredCaveat(_) => "missing_required_caveat",
        Denied::UnsatisfiableCaveat(_) => "unsatisfiable_caveat",
        Denied::Expired => "expired",
        Denied::TtlTooShort => "ttl_too_short",
    }
}

/// `POST /v1/verify`. The bundle (`primary` + any discharges) is in
/// `Authorization: MintV1 mnt1_<…>,mnt1_<…>`; the body is `{ts}` only —
/// PoP freshness, signed under the primary's `cnf` over the request
/// bytes. Runs the shared [`verify_and_clear`] core (chain MACs +
/// `aud`/`op`/`cnf`+PoP/`exp` clears) and returns the verdict + the
/// aggregated cleared caveats + the bundle-wide minimum `NotAfter`.
/// The caller (coord) caches the verdict by the bundle's wire bytes
/// for the lifetime of `expires_at`.
async fn discharge_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let now_unix = Utc::now().timestamp().max(0) as u64;

    let Some(bundle) = extract_bundle(&headers) else {
        return verify_failure(&request_id, "bundle_decode");
    };
    let proof = match pop_proof(&headers) {
        Ok(p) => p,
        Err(()) => return verify_failure(&request_id, "pop_header"),
    };
    let keyring = state.store.keyring().await;
    let cleared = match verify_and_clear(
        &bundle,
        &keyring,
        state.store.k_m_a(),
        proof,
        &body,
        now_unix,
        &state.config.audience,
        op::ASSUME_ROLE,
    ) {
        Ok(c) => c,
        Err(e) => return verify_failure(&request_id, e.reason()),
    };

    // Aggregated first-party caveats — mint is caveat-vocabulary-
    // agnostic and hands the raw set back to the caller for live
    // context clearing (CoordId, Volume, op-attenuation, etc.).
    let aggregated: Vec<serde_json::Value> = cleared
        .aggregated_caveats
        .iter()
        .filter_map(|c| match c {
            Caveat::FirstParty { name, value } => Some(json!({"name": name, "value": value})),
            Caveat::ThirdParty { .. } => None,
        })
        .collect();

    respond(
        &request_id,
        StatusCode::OK,
        json!({
            "valid": true,
            "expires_at": cleared.expires_at,
            "caveats": aggregated,
        }),
    )
}

fn verify_failure(request_id: &str, reason: &'static str) -> Response {
    respond(
        request_id,
        StatusCode::OK,
        json!({"valid": false, "reason": reason}),
    )
}
