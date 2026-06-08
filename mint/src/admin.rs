//! Admin-side HTTP surface — what `mint invite` and `mint enroll …`
//! call so the CLI does not need its own Tigris admin credential or
//! vend a fresh `mint-rw` keypair per invocation. These endpoints
//! proxy directly to the running daemon's [`crate::state::Store`]
//! and macaroon root, never touching IAM.
//!
//! Auth: every admin request carries the same `MintV1` bundle as the
//! rest of the surface — the **admin service token** primary
//! (`docs/design-mint.md` § *Admin service token*) plus a fresh
//! auth-service discharge satisfying its third-party caveat, with the
//! operator's per-call proof-of-possession over the admin-service tail.
//! The operator attenuates the admin-service with `op=admin:<verb>` per
//! call, so each endpoint clears its own specific action
//! ([`verify_discharge`]). There is no bearer path and no per-human
//! admin token: the human's authority is the discharge (gated at the
//! auth service behind `mint login`), the machine identity is the
//! admin-service's `cnf`.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::caveat::{EffectiveCaveats, Resolved, name, scope};
use crate::http::{AppState, verify_and_clear};
use crate::issuance::mint_invite;
use crate::macaroon::Macaroon;
use crate::operator::Operator;
use crate::seal::Seal;
use crate::sealed_cache::{SealState, ServedSurface};
use crate::state::{EnrollmentState, EnrollmentView, Store};

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&json!({"error": "unauthorized"})).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}

/// Admin routes. Every route is a `POST` gated by [`verify_discharge`]
/// — the admin-service bundle + a discharge attenuated to that route's
/// `op=admin:<verb>`. POST (not GET) even for reads, because the
/// proof-of-possession signs over the request body and every call
/// carries one.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/invite", post(handle_invite))
        .route("/v1/admin/invite/rotate", post(handle_rotate_invite))
        .route("/v1/admin/enrollments", post(handle_list_enrollments))
        .route("/v1/admin/enroll/approve", post(handle_approve))
        .route("/v1/admin/enroll/revoke", post(handle_revoke))
        .route("/v1/admin/seal", post(handle_seal))
        .with_state(state)
}

/// Per-endpoint admin action vocabulary. The operator attenuates the
/// admin-service with the matching `op=admin:<verb>` before presenting it;
/// each handler clears exactly its own value, so a discharge fetched
/// (and admin-service attenuated) for one verb cannot exercise another.
const ADMIN_INVITE_READ: &str = "admin:invite-read";
const ADMIN_INVITE_ROTATE: &str = "admin:invite-rotate";
const ADMIN_ENROLL_LIST: &str = "admin:enroll-list";
const ADMIN_ENROLL_APPROVE: &str = "admin:enroll-approve";
const ADMIN_ENROLL_REVOKE: &str = "admin:enroll-revoke";
const ADMIN_SEAL: &str = "admin:seal";

#[derive(Serialize, Deserialize)]
pub struct InviteResponse {
    /// Base64-encoded invite macaroon — the bytes a client presents
    /// at `/v1/enroll`.
    pub macaroon: String,
    /// The underlying nonce, for human-readable diagnostics
    /// (`mint invite` prints it alongside the macaroon).
    pub nonce: String,
}

/// Read the current invite. Body is just the PoP freshness `{ts}`.
async fn handle_invite(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    if let Err(r) = verify_discharge(&state, &headers, &body, ADMIN_INVITE_READ).await {
        return r;
    }
    match build_invite(&state).await {
        Ok(r) => json_ok(r),
        Err(s) => s,
    }
}

/// Run verify+clear against the request bundle in
/// `Authorization: MintV1 mnt1_<admin-service>,mnt1_<discharge>`. The
/// admin-service primary must verify under `K_M`, its third-party caveat
/// must be satisfied by the accompanying discharge (under the `r`
/// recovered from the TPC's `VID`), the aggregated caveats must clear
/// `op == expected_op` (the operator's per-call attenuation) and
/// `aud`, any `exp` must be in the future, and the operator's
/// `X-Mint-Pop` must sign `tail ‖ BLAKE3(body)` under the admin-service's
/// `cnf`. Every failure collapses to opaque 401.
async fn verify_discharge(
    state: &AppState,
    headers: &HeaderMap,
    body: &[u8],
    expected_op: &str,
) -> Result<String, Response> {
    let Some(bundle) = crate::http::extract_bundle(headers) else {
        return Err(unauthorized_response());
    };
    let proof = match crate::http::pop_proof(headers) {
        Ok(p) => p,
        Err(()) => return Err(unauthorized_response()),
    };
    let keyring = state.store.keyring().await;
    let now_unix = chrono::Utc::now().timestamp().max(0) as u64;
    let cleared = verify_and_clear(
        &bundle,
        &keyring,
        state.store.k_m_a(),
        proof,
        body,
        now_unix,
        &state.config.audience,
        expected_op,
    )
    .map_err(|_| unauthorized_response())?;
    // The admin plane clears the discharge's `Scope` against
    // `mint:admin` (`docs/design-auth-service.md` § *Scope tier*): a
    // session that obtained only an enroll- or exchange-scope discharge
    // cannot drive an admin verb, even though the verb itself rides the
    // admin-service's per-call `op=admin:<verb>` attenuation.
    if !matches!(
        EffectiveCaveats::new(&cleared.discharge_caveats).resolve(name::SCOPE),
        Resolved::Value(v) if v == scope::MINT_ADMIN
    ) {
        return Err(unauthorized_response());
    }
    // The operator's `sub` from the discharge — the audit-bearing identity
    // each admin verb records (e.g. `approved_by` on approve). Read from
    // the discharge's context, distinct from the admin-service primary's
    // own `sub` (the machine identity).
    match EffectiveCaveats::new(&cleared.discharge_caveats).resolve(name::SUB) {
        Resolved::Value(s) => Ok(s),
        _ => Err(unauthorized_response()),
    }
}

async fn handle_rotate_invite(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = verify_discharge(&state, &headers, &body, ADMIN_INVITE_ROTATE).await {
        return r;
    }
    if let Err(e) = state.store.rotate_invite().await {
        return service_unavailable(&format!("rotate invite: {e}"));
    }
    match build_invite(&state).await {
        Ok(r) => json_ok(r),
        Err(s) => s,
    }
}

async fn build_invite(state: &AppState) -> Result<InviteResponse, Response> {
    let nonce = state
        .store
        .current_invite()
        .await
        .map_err(|e| service_unavailable(&format!("read invite: {e}")))?;
    // The invite carries the enroll gate, so minting one requires the
    // auth integration that stamps its TPC. A mint with no auth has no
    // enrollment plane — there is no PoP-only fallback, by design
    // (`docs/design-mint.md` § *Enrollment*).
    let k_m_a = state.store.k_m_a().copied().ok_or_else(|| {
        service_unavailable("invite requires an auth integration (K_M-A) for its enroll gate")
    })?;
    let location = state.config.auth_location.as_deref().ok_or_else(|| {
        service_unavailable("invite requires auth_location for its discharge location")
    })?;
    let org_id = state.store.org_id().unwrap_or("demo").to_string();
    let keyring = state.store.keyring().await;
    let mac = mint_invite(
        &keyring,
        &k_m_a,
        &state.config.audience,
        &nonce,
        &org_id,
        location,
    );
    Ok(InviteResponse {
        macaroon: mac.encode(),
        nonce,
    })
}

#[derive(Serialize, Deserialize)]
pub struct EnrollmentRow {
    pub sub: String,
    /// `"pending"` or `"enrolled"`.
    pub state: String,
    pub pubkey: String,
    pub fingerprint: String,
    pub peer_ip: Option<String>,
    pub age_seconds: u64,
    pub anomalous_pub: bool,
}

impl From<EnrollmentView> for EnrollmentRow {
    fn from(v: EnrollmentView) -> Self {
        Self {
            sub: v.sub,
            state: match v.state {
                EnrollmentState::Pending => "pending".into(),
                EnrollmentState::Enrolled => "enrolled".into(),
                EnrollmentState::Revoked => "revoked".into(),
            },
            pubkey: v.pubkey,
            fingerprint: v.fingerprint,
            peer_ip: v.peer_ip,
            age_seconds: v.age_seconds,
            anomalous_pub: v.anomalous_pub,
        }
    }
}

async fn handle_list_enrollments(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(r) = verify_discharge(&state, &headers, &body, ADMIN_ENROLL_LIST).await {
        return r;
    }
    let now = Utc::now().timestamp().max(0) as u64;
    match state.store.list(now).await {
        Ok(rows) => json_ok(
            rows.into_iter()
                .map(EnrollmentRow::from)
                .collect::<Vec<_>>(),
        ),
        Err(e) => service_unavailable(&format!("list: {e}")),
    }
}

#[derive(Serialize, Deserialize)]
pub struct ApproveRequest {
    pub sub: String,
    pub pubkey: String,
}

#[derive(Serialize, Deserialize)]
pub struct ApproveResponse {
    pub approved_at: String,
}

async fn handle_approve(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let approved_by = match verify_discharge(&state, &headers, &body, ADMIN_ENROLL_APPROVE).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: ApproveRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return unauthorized_response(),
    };
    let approved_at = Utc::now().to_rfc3339();
    match state
        .store
        .approve(&req.sub, &req.pubkey, &approved_by, &approved_at)
        .await
    {
        Ok(()) => json_ok(ApproveResponse { approved_at }),
        Err(e) => service_unavailable(&format!("approve: {e}")),
    }
}

#[derive(Serialize, Deserialize)]
pub struct RevokeRequest {
    pub sub: String,
}

#[derive(Serialize, Deserialize)]
pub struct RevokeResponse {
    pub revoked_at: String,
    /// High-water revocation epoch written to the tombstone.
    pub rev_epoch: u64,
    /// Whether a live enrolled record was present (false when the `sub`
    /// was already revoked or never enrolled — the tombstone is still
    /// written/kept, so the call is idempotent and fail-safe).
    pub was_enrolled: bool,
}

/// Revoke a coordinator by `sub` — delete its enrolled record and write
/// the revocation tombstone (`docs/design-mint.md` § *Revocation*).
async fn handle_revoke(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    let revoked_by = match verify_discharge(&state, &headers, &body, ADMIN_ENROLL_REVOKE).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let req: RevokeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return unauthorized_response(),
    };
    let revoked_at = Utc::now().to_rfc3339();
    match state.store.revoke(&req.sub, &revoked_by, &revoked_at).await {
        Ok(outcome) => json_ok(RevokeResponse {
            revoked_at,
            rev_epoch: outcome.rev_epoch,
            was_enrolled: outcome.was_enrolled,
        }),
        Err(e) => service_unavailable(&format!("revoke: {e}")),
    }
}

#[derive(Serialize, Deserialize)]
pub struct SealResponse {
    /// Keyring generation that MAC'd the published seal.
    pub kid: crate::keyring::Kid,
    /// RFC 3339 timestamp the seal was authored.
    pub sealed_at: String,
    /// role → `policy_blake3` (hex) — the per-role hashes the CLI prints
    /// so the operator can eyeball what was committed.
    pub roles: std::collections::BTreeMap<String, String>,
}

/// `POST /v1/admin/seal` — author and publish the template seal from the
/// daemon's **own local** config (`docs/design-mint-template-seal.md` §
/// *The `mint seal` command*). The request carries only authorisation
/// (an empty PoP-freshness body); the daemon hashes its already-loaded
/// `roles_dir/`, MACs the manifest under the keyring, PUTs `seal.json`,
/// and writes its local sealed cache so it holds a cache for the seal it
/// just published. It then hot-swaps this host's served surface to the
/// seal it authored, so the new content goes live immediately — no
/// restart. In-flight requests finish against the surface they loaded.
async fn handle_seal(State(state): State<AppState>, headers: HeaderMap, body: Bytes) -> Response {
    // verify+clear directly (rather than via `verify_discharge`) so we
    // can name the operator subject — carried in the discharge — in the
    // seal log.
    let Some(bundle) = crate::http::extract_bundle(&headers) else {
        return unauthorized_response();
    };
    let proof = match crate::http::pop_proof(&headers) {
        Ok(p) => p,
        Err(()) => return unauthorized_response(),
    };
    let keyring = state.store.keyring().await;
    let now_unix = Utc::now().timestamp().max(0) as u64;
    let cleared = match verify_and_clear(
        &bundle,
        &keyring,
        state.store.k_m_a(),
        proof,
        &body,
        now_unix,
        &state.config.audience,
        ADMIN_SEAL,
    ) {
        Ok(c) => c,
        Err(_) => return unauthorized_response(),
    };
    let operator = match EffectiveCaveats::new(&cleared.discharge_caveats).resolve(name::SUB) {
        Resolved::Value(s) => s.to_string(),
        Resolved::Absent | Resolved::Unsatisfiable => "unknown".to_string(),
    };

    // A seal must not pin templates that reference undefined `[env]`
    // values — refuse to publish one (the host keeps serving whatever it
    // serves now). Not enforced at config load: serving is decoupled from
    // the live config, so this is the right gate.
    if let Err(e) = state.config.validate_policy_surface() {
        return unprocessable(&e.to_string());
    }

    let sealed_at = Utc::now().to_rfc3339();
    let seal = Seal::build_from_config(&state.config, &keyring, &sealed_at);
    if let Err(e) = state.store.put_template_seal(&seal).await {
        return service_unavailable(&format!("publish seal: {e}"));
    }
    // Cache what we just published so this host serves it after a restart
    // without re-deriving from `roles_dir/`, and take the surface to swap
    // in below.
    let surface = match ServedSurface::materialize(&state.config, &seal, &state.config.data_dir) {
        Ok(s) => s,
        Err(e) => return service_unavailable(&format!("write sealed cache: {e}")),
    };

    let roles: std::collections::BTreeMap<String, String> = seal
        .roles
        .iter()
        .map(|(n, r)| (n.clone(), r.policy_blake3.clone()))
        .collect();

    // Swap this host's served surface to the seal it just authored. The
    // surface satisfies that seal by construction (it is built from the
    // same config), so the new content goes live here immediately —
    // dormant or not — without a restart. In-flight requests finish
    // against the surface they loaded (`docs/design-mint-template-seal.md`
    // § *Dormant until sealed*).
    state.seal.store(Arc::new(SealState::Serving(surface)));

    crate::seal::log_now_serving(&seal, Some(&operator));
    json_ok(SealResponse {
        kid: seal.kid,
        sealed_at,
        roles,
    })
}

fn json_ok<T: Serialize>(body: T) -> Response {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        bytes,
    )
        .into_response()
}

fn service_unavailable(reason: &str) -> Response {
    tracing::error!(target: "mint::admin", reason, "admin request failed");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&json!({"error": "service unavailable"}))
            .unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}

/// `422` for an operator config defect surfaced at seal authoring (e.g. a
/// template referencing an undefined `[env]` key). The `reason` is
/// operator-facing — this is the authenticated admin plane.
fn unprocessable(reason: &str) -> Response {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&json!({ "error": reason })).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}

/// Mount the admin routes onto a base router. The caller decides
/// whether to mount them (only when the listener is UDS — TCP
/// deployments must not expose admin paths).
pub fn mount(base: Router, state: AppState) -> Router {
    base.merge(router(state))
}

#[allow(dead_code)] // signature placeholder for the future multi-host story
pub fn _store_handle(state: &AppState) -> &Arc<Store> {
    &state.store
}

// --- Client-side HTTP helpers ------------------------------------------------
//
// Operator CLI (`mint invite`, `mint enroll …`) reaches the running
// `serve` over the UDS socket it is bound to and calls the routes
// above. Every call carries the operator bundle: the admin-service
// attenuated with this verb's `op=admin:<verb>`, a fresh auth-service
// discharge, and a PoP over the attenuated tail — assembled by
// [`Operator::authorize`]. Living next to the handlers keeps the
// request/response shapes one-edit away from each other.

#[derive(Debug, thiserror::Error)]
pub enum AdminClientError {
    #[error("transport: {0}")]
    Transport(String),
    #[error("server returned {status}: {body}")]
    Status { status: u16, body: String },
    #[error("malformed response: {0}")]
    Malformed(String),
}

/// Reach the running mint over the same listener `serve` is bound to.
/// The admin authority rides in the `MintV1` bundle + PoP that
/// [`authed_post`] assembles from the [`Operator`] and discharge, not in
/// the target — so there is no bearer field here.
pub enum AdminTarget<'a> {
    /// Unix-domain socket — the production operator path.
    Uds(&'a std::path::Path),
    /// TCP base URL — convenience for tests / dev where the operator
    /// and serve share localhost. Admin routes are only registered on
    /// the UDS side of a real deployment, so a real TCP-only `serve`
    /// will return 404.
    Tcp(&'a str),
}

pub async fn get_invite(
    target: AdminTarget<'_>,
    op: &Operator,
    discharge: &Macaroon,
) -> Result<InviteResponse, AdminClientError> {
    let body = ts_body();
    let (status, resp) = authed_post(
        target,
        "/v1/admin/invite",
        op,
        discharge,
        ADMIN_INVITE_READ,
        body,
    )
    .await?;
    ok_json(status, &resp)
}

pub async fn rotate_invite(
    target: AdminTarget<'_>,
    op: &Operator,
    discharge: &Macaroon,
) -> Result<InviteResponse, AdminClientError> {
    let body = ts_body();
    let (status, resp) = authed_post(
        target,
        "/v1/admin/invite/rotate",
        op,
        discharge,
        ADMIN_INVITE_ROTATE,
        body,
    )
    .await?;
    ok_json(status, &resp)
}

pub async fn list_enrollments(
    target: AdminTarget<'_>,
    op: &Operator,
    discharge: &Macaroon,
) -> Result<Vec<EnrollmentRow>, AdminClientError> {
    let body = ts_body();
    let (status, resp) = authed_post(
        target,
        "/v1/admin/enrollments",
        op,
        discharge,
        ADMIN_ENROLL_LIST,
        body,
    )
    .await?;
    ok_json(status, &resp)
}

pub async fn approve_enrollment(
    target: AdminTarget<'_>,
    op: &Operator,
    discharge: &Macaroon,
    req: &ApproveRequest,
) -> Result<ApproveResponse, AdminClientError> {
    let body = body_with_ts(req)?;
    let (status, resp) = authed_post(
        target,
        "/v1/admin/enroll/approve",
        op,
        discharge,
        ADMIN_ENROLL_APPROVE,
        body,
    )
    .await?;
    ok_json(status, &resp)
}

pub async fn revoke_enrollment(
    target: AdminTarget<'_>,
    op: &Operator,
    discharge: &Macaroon,
    req: &RevokeRequest,
) -> Result<RevokeResponse, AdminClientError> {
    let body = body_with_ts(req)?;
    let (status, resp) = authed_post(
        target,
        "/v1/admin/enroll/revoke",
        op,
        discharge,
        ADMIN_ENROLL_REVOKE,
        body,
    )
    .await?;
    ok_json(status, &resp)
}

pub async fn seal(
    target: AdminTarget<'_>,
    op: &Operator,
    discharge: &Macaroon,
) -> Result<SealResponse, AdminClientError> {
    let body = ts_body();
    let (status, resp) =
        authed_post(target, "/v1/admin/seal", op, discharge, ADMIN_SEAL, body).await?;
    ok_json(status, &resp)
}

fn now_unix() -> u64 {
    Utc::now().timestamp().max(0) as u64
}

/// The PoP freshness body for a read — just `{"ts":<now>}`.
fn ts_body() -> String {
    format!(r#"{{"ts":{}}}"#, now_unix())
}

/// Serialize a request struct and inject the PoP freshness `ts`. The
/// admin handlers parse only their domain fields (`sub`/`pubkey`), so
/// the extra `ts` rides along covered by the signature and ignored on
/// the server.
fn body_with_ts<T: Serialize>(req: &T) -> Result<String, AdminClientError> {
    let mut v =
        serde_json::to_value(req).map_err(|e| AdminClientError::Malformed(e.to_string()))?;
    if let serde_json::Value::Object(map) = &mut v {
        map.insert("ts".into(), serde_json::json!(now_unix()));
    }
    serde_json::to_string(&v).map_err(|e| AdminClientError::Malformed(e.to_string()))
}

/// POST `body` to `endpoint`, attaching the operator bundle (admin-service
/// attenuated with `op_value` + `discharge`) and the PoP over the
/// attenuated tail.
async fn authed_post(
    target: AdminTarget<'_>,
    endpoint: &str,
    op: &Operator,
    discharge: &Macaroon,
    op_value: &str,
    body: String,
) -> Result<(u16, String), AdminClientError> {
    let (auth, pop) = op.authorize(discharge, op_value, body.as_bytes());
    let headers = [("authorization", auth), ("x-mint-pop", pop)];
    match target {
        AdminTarget::Tcp(base) => request_tcp(base, endpoint, &headers, body).await,
        AdminTarget::Uds(socket) => request_uds(socket, endpoint, &headers, body).await,
    }
}

async fn request_tcp(
    base: &str,
    endpoint: &str,
    headers: &[(&str, String)],
    body: String,
) -> Result<(u16, String), AdminClientError> {
    let mut rb = reqwest::Client::new()
        .post(format!("{base}{endpoint}"))
        .header("content-type", "application/json")
        .body(body);
    for (k, v) in headers {
        rb = rb.header(*k, v);
    }
    let resp = rb
        .send()
        .await
        .map_err(|e| AdminClientError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    let text = resp
        .text()
        .await
        .map_err(|e| AdminClientError::Transport(e.to_string()))?;
    Ok((status, text))
}

async fn request_uds(
    socket: &std::path::Path,
    endpoint: &str,
    headers: &[(&str, String)],
    body: String,
) -> Result<(u16, String), AdminClientError> {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<_, Full<bytes::Bytes>> =
        Client::builder(TokioExecutor::new()).build(hyperlocal::UnixConnector);
    let uri: hyper::Uri = hyperlocal::Uri::new(socket, endpoint).into();
    let mut builder = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("content-type", "application/json");
    for (k, v) in headers {
        builder = builder.header(*k, v);
    }
    let req = builder
        .body(Full::new(bytes::Bytes::from(body)))
        .map_err(|e| AdminClientError::Transport(e.to_string()))?;
    let resp = client
        .request(req)
        .await
        .map_err(|e| AdminClientError::Transport(e.to_string()))?;
    let status = resp.status().as_u16();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| AdminClientError::Transport(e.to_string()))?
        .to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

fn ok_json<T: for<'de> Deserialize<'de>>(status: u16, body: &str) -> Result<T, AdminClientError> {
    if status != 200 {
        return Err(AdminClientError::Status {
            status,
            body: body.to_owned(),
        });
    }
    serde_json::from_str(body).map_err(|e| AdminClientError::Malformed(e.to_string()))
}
