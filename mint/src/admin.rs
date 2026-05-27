//! Admin-side HTTP surface — what `mint invite` and `mint enroll …`
//! call so the CLI does not need its own Tigris admin credential or
//! vend a fresh `mint-rw` keypair per invocation. These endpoints
//! proxy directly to the running daemon's [`crate::state::Store`]
//! and macaroon root, never touching IAM.
//!
//! Auth: every admin request carries `Authorization: Macaroon <b64>`
//! holding a mint-issued **admin macaroon** (`op=admin`). The
//! bootstrap admin macaroon is written to `<data_dir>/admin.bootstrap`
//! on first start — the human operator captures it out of band, then
//! immediately mints per-human admin tokens via
//! `/v1/admin/token/mint`. Per-human tokens are scoped via the
//! optional `scope` caveat to specific admin verb tags
//! ([`crate::caveat::admin_scope`]); an absent `scope` is super-admin.
//!
//! Admin macaroons are bearer (no PoP). Identity for audit comes
//! from the `sub` caveat the issuer stamped in. Revocation is via
//! keyring kid rotation in v1; a per-nonce revocation list lands
//! when there's a need to revoke a single token without burning the
//! whole kid.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::caveat::{EffectiveCaveats, Resolved, SCOPE, admin_scope, name, op as op_value};
use crate::http::AppState;
use crate::issuance::{mint_admin_token, mint_invite};
use crate::macaroon::Macaroon;
use crate::state::{EnrollmentState, EnrollmentView, Store};

/// Result of a successful admin-macaroon verification — the bound
/// `sub` for audit and any further scope checks the handler wants
/// to do.
struct AdminContext {
    #[allow(dead_code)] // logged via the audit-todo path; reserved for future per-sub policy
    sub: String,
}

/// Verify the admin macaroon on the request and check it covers
/// `required_scope`. Returns the verified `AdminContext` on success,
/// or a ready-to-return 401 response on any failure (the coarse
/// "every failure is opaque 401" convention shared with the rest of
/// the HTTP surface). `required_scope` is one of
/// [`crate::caveat::admin_scope`].
async fn verify_admin(
    state: &AppState,
    headers: &HeaderMap,
    required_scope: &str,
) -> Result<AdminContext, Response> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Macaroon "))
        .ok_or_else(unauthorized_response)?;
    let mac = Macaroon::decode(token).map_err(|_| unauthorized_response())?;

    let keyring = state.store.keyring().await;
    if !mac.verify(&keyring) {
        return Err(unauthorized_response());
    }

    let caveats = mac.caveats();
    let eff = EffectiveCaveats::new(caveats);
    if !is_value(&eff.resolve(name::OP), op_value::ADMIN) {
        return Err(unauthorized_response());
    }
    if !is_value(&eff.resolve(name::AUD), &state.config.audience) {
        return Err(unauthorized_response());
    }
    if let Some(exp) = eff.not_after(name::EXP) {
        let now = Utc::now().timestamp().max(0) as u64;
        if exp <= now {
            return Err(unauthorized_response());
        }
    }
    let sub = match eff.resolve(name::SUB) {
        Resolved::Value(s) => s,
        _ => return Err(unauthorized_response()),
    };
    // Scope check: absent caveat = super-admin (all verbs). Present
    // caveat = comma-list; the required tag must appear in the list.
    // `Unsatisfiable` (two disagreeing scope copies the holder
    // appended) fails closed — never silently read as absent.
    match eff.resolve(SCOPE) {
        Resolved::Absent => {} // super-admin
        Resolved::Value(s) => {
            if !scope_covers(&s, required_scope) {
                return Err(unauthorized_response());
            }
        }
        Resolved::Unsatisfiable => return Err(unauthorized_response()),
    }

    Ok(AdminContext { sub })
}

fn is_value(r: &Resolved, expected: &str) -> bool {
    matches!(r, Resolved::Value(v) if v == expected)
}

fn scope_covers(scope_list: &str, required: &str) -> bool {
    scope_list.split(',').any(|s| s.trim() == required)
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::to_vec(&json!({"error": "unauthorized"})).unwrap_or_else(|_| b"{}".to_vec()),
    )
        .into_response()
}

/// Admin routes. Every route gates on an admin macaroon (see module
/// docs); routes are now safe to mount on any listener.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/invite", get(handle_get_invite))
        .route("/v1/admin/invite/rotate", post(handle_rotate_invite))
        .route("/v1/admin/enrollments", get(handle_list_enrollments))
        .route("/v1/admin/enroll/approve", post(handle_approve))
        .route("/v1/admin/enroll/revoke", post(handle_revoke))
        .route("/v1/admin/token/mint", post(handle_mint_admin_token))
        .with_state(state)
}

#[derive(Serialize, Deserialize)]
pub struct AdminTokenMintRequest {
    /// Human identifier — stamped into the new token's `sub` for
    /// audit. Free-text; mint treats it as opaque.
    pub sub: String,
    /// Optional comma-list of scope tags
    /// ([`crate::caveat::admin_scope`]) the new token may exercise.
    /// `None` = super-admin (all verbs).
    #[serde(default)]
    pub scope: Option<String>,
    /// Optional unix-seconds expiry. `None` = non-expiring.
    #[serde(default)]
    pub exp: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct AdminTokenMintResponse {
    pub macaroon: String,
}

async fn handle_mint_admin_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<AdminTokenMintRequest>,
) -> Response {
    if let Err(r) = verify_admin(&state, &headers, admin_scope::TOKEN_MINT).await {
        return r;
    }
    // The caller's authority is exactly the scope they hold. If the
    // caller is super-admin they may mint anything; if they have a
    // scoped token, they can only mint at-or-narrower than their own
    // scope. This is plain macaroon attenuation semantics applied to
    // the issuance call: a holder can only narrow.
    if let Some(requested) = req.scope.as_deref()
        && !caller_can_grant(&state, &headers, requested).await
    {
        return unauthorized_response();
    }
    let keyring = state.store.keyring().await;
    let mac = mint_admin_token(
        &keyring,
        &state.config.audience,
        &req.sub,
        req.scope.as_deref(),
        req.exp,
    );
    json_ok(AdminTokenMintResponse {
        macaroon: mac.encode(),
    })
}

/// Re-verify the caller's macaroon to inspect its scope, returning
/// whether every tag in `requested_scope` is covered. Super-admin
/// callers (no scope caveat) cover any request.
async fn caller_can_grant(_state: &AppState, headers: &HeaderMap, requested_scope: &str) -> bool {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Macaroon "))
    else {
        return false;
    };
    let Ok(mac) = Macaroon::decode(token) else {
        return false;
    };
    let eff = EffectiveCaveats::new(mac.caveats());
    match eff.resolve(SCOPE) {
        Resolved::Absent => true, // super-admin grants anything
        Resolved::Value(caller_scope) => requested_scope.split(',').all(|tag| {
            let tag = tag.trim();
            caller_scope.split(',').any(|t| t.trim() == tag)
        }),
        Resolved::Unsatisfiable => false,
    }
}

#[derive(Serialize, Deserialize)]
pub struct InviteResponse {
    /// Base64-encoded invite macaroon — the bytes a client presents
    /// at `/v1/enroll`.
    pub macaroon: String,
    /// The underlying nonce, for human-readable diagnostics
    /// (`mint invite` prints it alongside the macaroon).
    pub nonce: String,
}

async fn handle_get_invite(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin(&state, &headers, admin_scope::INVITE_READ).await {
        return r;
    }
    match build_invite(&state).await {
        Ok(r) => json_ok(r),
        Err(s) => s,
    }
}

async fn handle_rotate_invite(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin(&state, &headers, admin_scope::INVITE_ROTATE).await {
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
    let keyring = state.store.keyring().await;
    let mac = mint_invite(&keyring, &state.config.audience, &nonce);
    Ok(InviteResponse {
        macaroon: mac.encode(),
        nonce,
    })
}

#[derive(Serialize, Deserialize)]
pub struct EnrollmentRow {
    pub sub: String,
    /// `"pending"` or `"approved"`.
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
                EnrollmentState::Approved => "approved".into(),
            },
            pubkey: v.pubkey,
            fingerprint: v.fingerprint,
            peer_ip: v.peer_ip,
            age_seconds: v.age_seconds,
            anomalous_pub: v.anomalous_pub,
        }
    }
}

async fn handle_list_enrollments(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(r) = verify_admin(&state, &headers, admin_scope::ENROLL_LIST).await {
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
    axum::Json(req): axum::Json<ApproveRequest>,
) -> Response {
    if let Err(r) = verify_admin(&state, &headers, admin_scope::ENROLL_APPROVE).await {
        return r;
    }
    let approved_at = Utc::now().to_rfc3339();
    match state
        .store
        .approve(&req.sub, &req.pubkey, &approved_at)
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
    pub revoked: bool,
}

async fn handle_revoke(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(req): axum::Json<RevokeRequest>,
) -> Response {
    if let Err(r) = verify_admin(&state, &headers, admin_scope::ENROLL_REVOKE).await {
        return r;
    }
    match state.store.revoke(&req.sub).await {
        Ok(revoked) => json_ok(RevokeResponse { revoked }),
        Err(e) => service_unavailable(&format!("revoke: {e}")),
    }
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
// above. Living next to the handlers keeps the request/response
// shapes one-edit away from each other.

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
pub enum AdminTarget<'a> {
    /// Unix-domain socket — the production operator path.
    Uds(&'a std::path::Path),
    /// TCP base URL — convenience for tests / dev where the operator
    /// and serve share localhost. Admin routes are only registered on
    /// the UDS side of a real deployment, so a real TCP-only `serve`
    /// will return 404.
    Tcp(&'a str),
}

pub async fn get_invite(target: AdminTarget<'_>) -> Result<InviteResponse, AdminClientError> {
    let (status, body) = request(target, "GET", "/v1/admin/invite", None).await?;
    ok_json(status, &body)
}

pub async fn rotate_invite(target: AdminTarget<'_>) -> Result<InviteResponse, AdminClientError> {
    let (status, body) = request(target, "POST", "/v1/admin/invite/rotate", None).await?;
    ok_json(status, &body)
}

pub async fn list_enrollments(
    target: AdminTarget<'_>,
) -> Result<Vec<EnrollmentRow>, AdminClientError> {
    let (status, body) = request(target, "GET", "/v1/admin/enrollments", None).await?;
    ok_json(status, &body)
}

pub async fn approve_enrollment(
    target: AdminTarget<'_>,
    req: &ApproveRequest,
) -> Result<ApproveResponse, AdminClientError> {
    let body =
        serde_json::to_string(req).map_err(|e| AdminClientError::Malformed(e.to_string()))?;
    let (status, body) = request(target, "POST", "/v1/admin/enroll/approve", Some(body)).await?;
    ok_json(status, &body)
}

pub async fn revoke_enrollment(
    target: AdminTarget<'_>,
    req: &RevokeRequest,
) -> Result<RevokeResponse, AdminClientError> {
    let body =
        serde_json::to_string(req).map_err(|e| AdminClientError::Malformed(e.to_string()))?;
    let (status, body) = request(target, "POST", "/v1/admin/enroll/revoke", Some(body)).await?;
    ok_json(status, &body)
}

async fn request(
    target: AdminTarget<'_>,
    method: &str,
    endpoint: &str,
    body: Option<String>,
) -> Result<(u16, String), AdminClientError> {
    match target {
        AdminTarget::Tcp(base) => request_tcp(base, method, endpoint, body).await,
        AdminTarget::Uds(socket) => request_uds(socket, method, endpoint, body).await,
    }
}

async fn request_tcp(
    base: &str,
    method: &str,
    endpoint: &str,
    body: Option<String>,
) -> Result<(u16, String), AdminClientError> {
    let client = reqwest::Client::new();
    let mut rb = match method {
        "GET" => client.get(format!("{base}{endpoint}")),
        "POST" => client.post(format!("{base}{endpoint}")),
        m => return Err(AdminClientError::Transport(format!("bad method {m}"))),
    };
    if let Some(b) = body {
        rb = rb.header("content-type", "application/json").body(b);
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
    method: &str,
    endpoint: &str,
    body: Option<String>,
) -> Result<(u16, String), AdminClientError> {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<_, Full<bytes::Bytes>> =
        Client::builder(TokioExecutor::new()).build(hyperlocal::UnixConnector);
    let uri: hyper::Uri = hyperlocal::Uri::new(socket, endpoint).into();
    let mut builder = hyper::Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let req = builder
        .body(Full::new(bytes::Bytes::from(body.unwrap_or_default())))
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::Arc;
    use tower::ServiceExt;

    use crate::audit::AuditLog;
    use crate::config::Config;
    use crate::iam::FakeMinter;
    use crate::state::Store;

    fn make_state(store: Arc<Store>) -> AppState {
        AppState {
            config: Arc::new(Config {
                audience: "mint".into(),
                data_dir: std::path::PathBuf::from("/tmp/unused"),
                roles_dir: std::path::PathBuf::from("/tmp/unused"),
                listener: crate::config::Listener::Uds(std::path::PathBuf::from(
                    "/tmp/unused.sock",
                )),
                tenant: crate::config::Tenant {
                    bucket: "test".into(),
                    endpoint: None,
                    region: None,
                },
                admin: None,
                auth: None,
                roles: Default::default(),
            }),
            minter: Arc::new(FakeMinter::new()),
            audit: Arc::new(AuditLog::new(Box::new(std::io::sink()))),
            store,
        }
    }

    async fn body_string(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8(bytes.to_vec()).expect("utf8")
    }

    /// A super-admin macaroon for the test keyring (always `[7u8;
    /// 32]` in these tests). Most tests use this; the
    /// scope-checking tests mint scoped tokens directly.
    fn super_admin_token() -> String {
        let mac = crate::issuance::mint_admin_token(
            &crate::keyring::Keyring::single([7u8; 32]),
            "mint",
            "test-super",
            None,
            None,
        );
        format!("Macaroon {}", mac.encode())
    }

    fn scoped_token(scope: &str) -> String {
        let mac = crate::issuance::mint_admin_token(
            &crate::keyring::Keyring::single([7u8; 32]),
            "mint",
            "test-scoped",
            Some(scope),
            None,
        );
        format!("Macaroon {}", mac.encode())
    }

    #[tokio::test]
    async fn get_invite_returns_macaroon_and_nonce() {
        let store = Arc::new(Store::open_in_memory([7u8; 32]).await.unwrap());
        let app = router(make_state(store));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/invite")
                    .header("authorization", super_admin_token())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let encoded = v["macaroon"].as_str().unwrap();
        let decoded = crate::macaroon::Macaroon::decode(encoded).expect("decode");
        assert!(decoded.verify(&crate::keyring::Keyring::single([7u8; 32])));
        assert!(!v["nonce"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rotate_invite_changes_the_nonce() {
        let store = Arc::new(Store::open_in_memory([7u8; 32]).await.unwrap());
        let app = router(make_state(store.clone()));
        let before = store.current_invite().await.unwrap();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/invite/rotate")
                    .header("authorization", super_admin_token())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let after = v["nonce"].as_str().unwrap().to_string();
        assert_ne!(before, after);
        assert_eq!(store.current_invite().await.unwrap(), after);
    }

    #[tokio::test]
    async fn approve_and_revoke_round_trip() {
        let store = Arc::new(Store::open_in_memory([7u8; 32]).await.unwrap());
        let nonce = store.current_invite().await.unwrap();
        store
            .record_pending("01ARZ", "ed25519:AAA", &nonce, "ip", 1)
            .await
            .unwrap();
        let app = router(make_state(store.clone()));
        // approve
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enroll/approve")
                    .header("content-type", "application/json")
                    .header("authorization", super_admin_token())
                    .body(Body::from(r#"{"sub":"01ARZ","pubkey":"ed25519:AAA"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(store.get_approved("01ARZ").await.unwrap().is_some());
        assert!(store.get_pending("01ARZ").await.unwrap().is_none());
        // revoke
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/admin/enroll/revoke")
                    .header("content-type", "application/json")
                    .header("authorization", super_admin_token())
                    .body(Body::from(r#"{"sub":"01ARZ"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["revoked"], true);
        assert!(store.get_approved("01ARZ").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn list_enrollments_returns_state_column() {
        let store = Arc::new(Store::open_in_memory([7u8; 32]).await.unwrap());
        let nonce = store.current_invite().await.unwrap();
        store
            .record_pending("subP", "ed25519:P", &nonce, "ip", 1)
            .await
            .unwrap();
        store
            .record_pending("subQ", "ed25519:Q", &nonce, "ip", 1)
            .await
            .unwrap();
        store.approve("subQ", "ed25519:Q", "now").await.unwrap();
        let app = router(make_state(store));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/enrollments")
                    .header("authorization", super_admin_token())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        let rows: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
        assert_eq!(rows.len(), 2);
        let by_sub: std::collections::HashMap<_, _> = rows
            .iter()
            .map(|r| (r["sub"].as_str().unwrap(), r["state"].as_str().unwrap()))
            .collect();
        assert_eq!(by_sub.get("subP"), Some(&"pending"));
        assert_eq!(by_sub.get("subQ"), Some(&"approved"));
    }

    // ── Macaroon gating ────────────────────────────────────────────

    async fn make_app() -> axum::Router {
        let store = Arc::new(Store::open_in_memory([7u8; 32]).await.unwrap());
        router(make_state(store))
    }

    fn invite_get(auth: Option<&str>) -> Request<Body> {
        let mut req = Request::builder().method("GET").uri("/v1/admin/invite");
        if let Some(a) = auth {
            req = req.header("authorization", a);
        }
        req.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn missing_authorization_rejected() {
        let app = make_app().await;
        let resp = app.oneshot(invite_get(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_authorization_rejected() {
        let app = make_app().await;
        let resp = app
            .oneshot(invite_get(Some("Macaroon not-base64!!")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn token_signed_by_wrong_root_rejected() {
        let app = make_app().await;
        // App's keyring is [7u8; 32]; mint a "super-admin" under a
        // different root and present it.
        let mac = crate::issuance::mint_admin_token(
            &crate::keyring::Keyring::single([9u8; 32]),
            "mint",
            "imposter",
            None,
            None,
        );
        let auth = format!("Macaroon {}", mac.encode());
        let resp = app.oneshot(invite_get(Some(&auth))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_op_rejected() {
        // A credential-shaped macaroon (op=assume-role) cannot be
        // used as an admin token — even when MAC'd under the same
        // root.
        let app = make_app().await;
        let mac = crate::issuance::mint_credential(
            &crate::keyring::Keyring::single([7u8; 32]),
            "mint",
            "01ARZ",
            "ed25519:AAA",
            "volume-rw",
        );
        let auth = format!("Macaroon {}", mac.encode());
        let resp = app.oneshot(invite_get(Some(&auth))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_audience_rejected() {
        let app = make_app().await;
        let mac = crate::issuance::mint_admin_token(
            &crate::keyring::Keyring::single([7u8; 32]),
            "other-mint", // app's audience is "mint"
            "alice",
            None,
            None,
        );
        let auth = format!("Macaroon {}", mac.encode());
        let resp = app.oneshot(invite_get(Some(&auth))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn expired_token_rejected() {
        let app = make_app().await;
        let mac = crate::issuance::mint_admin_token(
            &crate::keyring::Keyring::single([7u8; 32]),
            "mint",
            "alice",
            None,
            Some(1), // unix-epoch second 1 — long past
        );
        let auth = format!("Macaroon {}", mac.encode());
        let resp = app.oneshot(invite_get(Some(&auth))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn scoped_token_covering_verb_accepted() {
        let app = make_app().await;
        let auth = scoped_token(admin_scope::INVITE_READ);
        let resp = app.oneshot(invite_get(Some(&auth))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn scoped_token_not_covering_verb_rejected() {
        let app = make_app().await;
        // Token only allows enroll-approve; the request is for
        // invite-read.
        let auth = scoped_token(admin_scope::ENROLL_APPROVE);
        let resp = app.oneshot(invite_get(Some(&auth))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn multi_scope_token_accepted_for_any_listed_verb() {
        let app = make_app().await;
        let auth = scoped_token(&format!(
            "{},{}",
            admin_scope::INVITE_READ,
            admin_scope::ENROLL_APPROVE
        ));
        let resp = app.oneshot(invite_get(Some(&auth))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn token_mint_endpoint_attenuates() {
        // A scoped caller can only mint a token at or narrower than
        // their own scope: macaroon-style attenuation enforced at
        // the endpoint.
        let app = make_app().await;
        let scoped_auth = scoped_token(&format!(
            "{},{}",
            admin_scope::TOKEN_MINT,
            admin_scope::INVITE_READ
        ));
        // Allowed: minting a token with a strictly-narrower scope.
        let req = Request::builder()
            .method("POST")
            .uri("/v1/admin/token/mint")
            .header("authorization", &scoped_auth)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"sub":"bob","scope":"{}"}}"#,
                admin_scope::INVITE_READ
            )))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // Refused: minting a token with a wider scope the caller
        // doesn't hold.
        let req = Request::builder()
            .method("POST")
            .uri("/v1/admin/token/mint")
            .header("authorization", &scoped_auth)
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"sub":"bob","scope":"{}"}}"#,
                admin_scope::ENROLL_REVOKE
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
