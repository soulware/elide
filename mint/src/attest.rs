//! mint-as-verifier role — demo-only attestation-discharge issuer.
//!
//! Structurally separate from the mint role, exactly like the demo auth
//! role (`crate::auth`): its discharge route mounts on its own UDS only
//! when `[demo_attestation].enabled = true`. Production deploys run a
//! real attestation authority (for Elide, the attestation coordinator —
//! `elide-attestation`) that shares `K_M-B` with mint and runs a real
//! ownership predicate. Mint's verifier recovers `r` from the attested
//! TPC's `VID` regardless of where the discharge was minted, so this
//! module can move out of the mint binary without disturbing it.
//!
//! Session gate: every `/v1/discharge` request must carry
//! `Authorization: Bearer <session>` — the same login session the demo
//! auth role mints under `K_session` (`mint login`). The session is the
//! *whole* predicate: the issuer attests whatever named values the
//! logged-in caller asks for. A real authority replaces that with its
//! own check (coord B: possession proof + liveness + lineage); the
//! discharge it returns has the same shape.
//!
//! Wire (`POST /v1/discharge`):
//!
//! ```text
//! Authorization: Bearer mnt2_<session>
//! request body:  { "cid": "<base64url of the attested TPC CID>",
//!                  "attested": { "<name>": "<value>", … } }
//! 200 OK:        { "discharge": "mnt2_<base64url>" }
//! ```
//!
//! Discharge construction: decrypt `cid` under `K_M-B`
//! ([`tpc::decrypt_cid_attested`]) to recover `(r, client_id, org_id,
//! mode)`, reject if `org_id` is not the org this role serves, then mint
//! a discharge macaroon chain-MAC'd under `r`, carrying
//! each requested `(name, value)` as a scalar caveat plus `exp` — the
//! same caveat shape the attestation coordinator emits. A requested name
//! that collides with a reserved control-caveat name is rejected: each
//! authority emits only its own vocabulary, never the primary's control
//! set. The CID's `mode` is recovered but not dispatched on — this
//! issuer has a single predicate (the session gate).

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;

use crate::auth::verify_session;
use crate::caveat::{Caveat, name};
use crate::http::AppState;
use crate::macaroon::{KeyRef, mint_under_key};
use crate::tpc;

/// Demo attestation-discharge lifetime. Long enough for the client to
/// round-trip it to `assume-role`, short enough that a leaked discharge
/// has minimal window. Demo only — a real authority sets its own per
/// its staleness model.
const DISCHARGE_EXP_SECONDS: u64 = 300;

/// The `/v1/discharge` request body. Shared with the client side
/// (`crate::client`) so the bytes a caller serialises and the bytes the
/// handler deserialises are one type.
#[derive(Deserialize, Serialize)]
pub(crate) struct AttestRequest {
    /// Base64url of the credential's attested third-party-caveat `CID`.
    /// Decrypted under `K_M-B` to recover the discharge key `r` and the
    /// bound `(client_id, org_id, mode)`.
    pub(crate) cid: String,
    /// The `(name, value)` pairs the discharge is to attest — the names
    /// the role's policy template substitutes as `{{attested.X}}`.
    pub(crate) attested: BTreeMap<String, String>,
}

/// Build the attestation-authority router. The caller binds it to its
/// own listener — a *separate* socket from both the mint role and the
/// demo auth role, mirroring the per-endpoint listener split the
/// attestation coordinator uses.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/discharge", post(issue_discharge))
        .with_state(state)
}

/// `POST /v1/discharge` — session-gated attestation discharge for a
/// credential's attested third-party caveat.
async fn issue_discharge(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(k_m_b) = state.store.k_m_b().copied() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "k_m_b unavailable");
    };
    let Some(k_session) = state.store.k_session().copied() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "k_session unavailable");
    };

    let now_unix = Utc::now().timestamp().max(0) as u64;
    if verify_session(&k_session, &headers, now_unix).is_err() {
        return error(StatusCode::UNAUTHORIZED, "session required");
    }

    let req: AttestRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad request"),
    };
    if req.attested.is_empty() {
        return error(StatusCode::BAD_REQUEST, "nothing to attest");
    }
    // Each authority emits only its own vocabulary: a requested name
    // that collides with a reserved control-caveat name is refused, so
    // an attestation discharge can never carry the primary's control
    // set (`sub`, `exp`, …) as attested data.
    if req
        .attested
        .keys()
        .any(|n| name::RESERVED.contains(&n.as_str()))
    {
        return error(StatusCode::BAD_REQUEST, "reserved attested name");
    }
    let cid = match BASE64.decode(req.cid.trim()) {
        Ok(b) => b,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad cid"),
    };
    // Recover `r` and the bound identity from the CID under K_M-B. A
    // `cid` that fails to decrypt signals a `K_M-B` rotation (422),
    // distinct from a malformed request (400).
    let pt = match tpc::decrypt_cid_attested(&k_m_b, &cid) {
        Ok(pt) => pt,
        Err(_) => return error(StatusCode::UNPROCESSABLE_ENTITY, "cid decrypt"),
    };
    if state.store.org_id() != Some(pt.org_id.as_str()) {
        return error(StatusCode::FORBIDDEN, "org mismatch");
    }

    let exp = now_unix + DISCHARGE_EXP_SECONDS;
    let mut caveats: Vec<Caveat> = req
        .attested
        .iter()
        .map(|(n, v)| Caveat::scalar(n.as_str(), v.as_str()))
        .collect();
    caveats.push(Caveat::scalar(name::EXP, exp.to_string()));
    let discharge = mint_under_key(&pt.r, KeyRef::Discharge, caveats);

    (
        StatusCode::OK,
        axum::Json(json!({"discharge": discharge.encode()})),
    )
        .into_response()
}

fn error(status: StatusCode, msg: &'static str) -> Response {
    (status, axum::Json(json!({"error": msg}))).into_response()
}
