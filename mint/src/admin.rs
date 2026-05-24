//! Operator-side HTTP surface — what `mint invite` and `mint enroll …`
//! call so the CLI does not need its own Tigris admin credential or
//! vend a fresh `mint-rw` keypair per invocation. These endpoints
//! proxy directly to the running daemon's [`crate::state::Store`]
//! and macaroon root, never touching IAM.
//!
//! Reachability is **UDS-only** by construction: [`router`] is mounted
//! only when `serve` is bound to a Unix-domain socket
//! (`docs/design-mint.md` § *Transport*). Filesystem permission on the
//! socket file is the auth gate — operators on the host can call;
//! anyone reaching the bucket-facing TCP listener cannot, because the
//! routes are not registered there. A request to one of these paths
//! against a TCP-only deployment returns the usual `404 Not Found`.
//!
//! The auth simplification — UDS only, no per-request macaroon — is
//! deliberate. The operator role is "the principal that can write the
//! mint root key's filesystem". A second cryptographic gate above
//! that would be redundant; a second non-cryptographic gate that
//! could be bypassed by a leaked admin token would be worse than what
//! we have. Multi-host operator access (a real future need) calls for
//! an explicit admin macaroon, not a bolt-on token; that work is
//! tracked separately.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::http::AppState;
use crate::issuance::mint_invite;
use crate::state::{EnrollmentState, EnrollmentView, Store};

/// Admin routes mounted only on UDS — see module docs.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/admin/invite", get(handle_get_invite))
        .route("/v1/admin/invite/rotate", post(handle_rotate_invite))
        .route("/v1/admin/enrollments", get(handle_list_enrollments))
        .route("/v1/admin/enroll/approve", post(handle_approve))
        .route("/v1/admin/enroll/revoke", post(handle_revoke))
        .with_state(state)
}

#[derive(Serialize, Deserialize)]
pub struct InviteResponse {
    /// Base64-encoded invite macaroon — the `mcrn1`-prefixed bytes the
    /// coordinator presents at `/v1/enroll`.
    pub macaroon: String,
    /// The underlying nonce, for human-readable diagnostics
    /// (`mint invite` prints it alongside the macaroon).
    pub nonce: String,
}

async fn handle_get_invite(State(state): State<AppState>) -> Response {
    match build_invite(&state).await {
        Ok(r) => json_ok(r),
        Err(s) => s,
    }
}

async fn handle_rotate_invite(State(state): State<AppState>) -> Response {
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

async fn handle_list_enrollments(State(state): State<AppState>) -> Response {
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
    axum::Json(req): axum::Json<ApproveRequest>,
) -> Response {
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
    axum::Json(req): axum::Json<RevokeRequest>,
) -> Response {
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

    #[tokio::test]
    async fn get_invite_returns_macaroon_and_nonce() {
        let store = Arc::new(Store::open_in_memory([7u8; 32]).await.unwrap());
        let app = router(make_state(store));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/v1/admin/invite")
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
}
