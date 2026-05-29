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
//! Wire (`POST /v1/discharge`) — two request shapes, two discharge
//! kinds, distinguished structurally by their fields:
//!
//! ```text
//! 200 OK (either shape):
//!   { "discharge": "mnt1_<base64url>" }
//!
//! (a) Third-party-caveat discharge — operator-write credentials:
//!   { "cid": "<base64url>" }
//! (b) Standalone admin bearer — the /v1/admin/* authority path:
//!   { "ts": <unix>,
//!     "action": "admin:invite-read" | "admin:enroll-approve" | ...,
//!     "cnf":    "ed25519:<base64 pubkey>" }
//! ```
//!
//! Discharge construction:
//!
//! - **(a) TPC discharge.** `r`, the bound `client_id` and `org_id` are
//!   recovered from `cid` under `K_M-A` (`tpc::decrypt_cid`) — no `K_M`,
//!   no per-client state. Macaroon at `kid = DISCHARGE_KID`, chain MAC'd
//!   under that `r`, caveats `Subject`, `OrgId`, `ClientId`, `NotAfter`.
//!   Mint's verifier recovers the same `r` from the matching primary's
//!   `vid` (`tpc::decrypt_vid`) — the two recover identical keys by
//!   construction.
//! - **(b) Admin bearer.** Fresh 16-byte nonce; `r =
//!   BLAKE3-derive-key("mint discharge r-key v1", K_M-A || nonce)`.
//!   Macaroon at `kid = DISCHARGE_KID`, chain MAC'd under `r`, caveats
//!   `aud=mint`, `op=<action>`, `cnf=<requester pub>`, `exp=now + 5 min`.
//!   Mint's verifier reconstructs `r` from the same `(K_M-A, nonce)`
//!   when this discharge is presented as the bundle primary — cheap,
//!   stateless, no per-discharge ledger.
//!
//! Demo gate: `[auth].demo_enabled` must be true *and* the request must
//! have arrived over the UDS listener (we never expose discharge
//! issuance on TCP). The router-mount in `main.rs` enforces the first
//! gate; defence-in-depth for the second.

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64;
use chrono::Utc;
use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;

use crate::caveat::{Caveat, name};
use crate::http::AppState;
use crate::macaroon::{
    DISCHARGE_KID, Macaroon, NONCE_LEN, mint_under_key, mint_under_key_with_nonce,
};
use crate::pop;
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

/// Freshness window on the request's in-body `ts`.
const TS_SKEW_SECONDS: u64 = 60;

/// Required prefix for the `action` body field in the initial cut. Real
/// auth-service may issue discharges for non-`admin:*` ops too;
/// demo-mint only mints discharges for admin actions until a clear use
/// case emerges otherwise.
const ACTION_PREFIX: &str = "admin:";

/// Demo subject stamped on operator-write discharges. The production
/// auth service derives `Subject` from the authenticated operator
/// session; demo-mint has no session layer (see
/// `design-auth-service.md` § *Mint as auth*), so every demo discharge
/// is attributed to this placeholder.
const DEMO_SUBJECT: &str = "usr_demo";

/// Derive the per-discharge MAC key from `K_M-A` and the discharge's
/// nonce. Verifier and issuer compute the same function, so no shared
/// state — same input → same `r`.
pub fn derive_discharge_r(k_m_a: &[u8; 32], nonce: &[u8; NONCE_LEN]) -> [u8; 32] {
    let mut km = Vec::with_capacity(32 + NONCE_LEN);
    km.extend_from_slice(k_m_a);
    km.extend_from_slice(nonce);
    blake3::derive_key(R_KDF_CONTEXT, &km)
}

/// The two discharge-request shapes, disjoint in their required fields
/// so serde routes by structure alone. A TPC discharge satisfies a
/// third-party caveat on an operator-write credential; an admin bearer
/// is the standalone authority a human presents on `/v1/admin/*`. The
/// verifier stays unconditional — only issuance forks here.
#[derive(Deserialize)]
#[serde(untagged)]
enum DischargeRequest {
    /// Operator-write: discharge the third-party caveat named by `cid`.
    Tpc { cid: String },
    /// Standalone admin bearer.
    Admin {
        ts: u64,
        action: String,
        cnf: String,
    },
}

/// Build the auth-role router. The caller binds it to its own
/// listener — the auth role lives on a *separate* socket from the
/// mint role, never sharing a router with `/v1/assume-role`,
/// `/v1/admin/*`, or any mint-issued-credential endpoint. Demo
/// callers reach it at the path in `[auth].socket`
/// (defaults to `<data_dir>/auth.sock`).
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/discharge", post(issue_discharge))
        .with_state(state)
}

async fn issue_discharge(State(state): State<AppState>, body: Bytes) -> Response {
    let Some(k_m_a) = state.store.k_m_a().copied() else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "k_m_a unavailable");
    };

    let req: DischargeRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "bad request"),
    };

    let now_unix = Utc::now().timestamp().max(0) as u64;
    let minted = match req {
        DischargeRequest::Tpc { cid } => issue_tpc_discharge(&k_m_a, &cid, now_unix),
        DischargeRequest::Admin { ts, action, cnf } => {
            issue_admin_discharge(&state, &k_m_a, ts, &action, &cnf, now_unix)
        }
    };
    let discharge = match minted {
        Ok(d) => d,
        Err((status, msg)) => return error(status, msg),
    };

    (
        StatusCode::OK,
        axum::Json(json!({"discharge": discharge.encode()})),
    )
        .into_response()
}

/// (a) Operator-write TPC discharge. The `cid` recovers `(r, client_id,
/// org_id)` under `K_M-A`; the discharge is MAC'd under that `r` and
/// carries the bound identity plus a fresh `NotAfter`. A `cid` that
/// fails to decrypt signals a `K_M-A` rotation to the caller (422) —
/// distinct from a malformed request (400).
fn issue_tpc_discharge(
    k_m_a: &[u8; 32],
    cid_b64: &str,
    now_unix: u64,
) -> Result<Macaroon, (StatusCode, &'static str)> {
    let cid = BASE64
        .decode(cid_b64)
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad cid"))?;
    let pt = tpc::decrypt_cid(k_m_a, &cid)
        .map_err(|_| (StatusCode::UNPROCESSABLE_ENTITY, "cid decrypt"))?;

    let not_after = now_unix + DISCHARGE_EXP_SECONDS;
    Ok(mint_under_key(
        &pt.r,
        DISCHARGE_KID,
        vec![
            Caveat::scalar("Subject", DEMO_SUBJECT),
            Caveat::scalar("OrgId", pt.org_id),
            Caveat::scalar("ClientId", pt.client_id),
            Caveat::scalar(name::NOT_AFTER, not_after.to_string()),
        ],
    ))
}

/// (b) Standalone admin bearer. Self-describing: a fresh nonce derives
/// `r` under `K_M-A`, and the discharge is presented as the bundle
/// primary on `/v1/admin/*`.
fn issue_admin_discharge(
    state: &AppState,
    k_m_a: &[u8; 32],
    ts: u64,
    action: &str,
    cnf: &str,
    now_unix: u64,
) -> Result<Macaroon, (StatusCode, &'static str)> {
    if now_unix.abs_diff(ts) > TS_SKEW_SECONDS {
        return Err((StatusCode::BAD_REQUEST, "stale ts"));
    }
    if !action.starts_with(ACTION_PREFIX) {
        return Err((StatusCode::BAD_REQUEST, "unsupported action"));
    }
    if pop::validate_cnf(cnf).is_err() {
        return Err((StatusCode::BAD_REQUEST, "bad cnf"));
    }

    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);
    let r = derive_discharge_r(k_m_a, &nonce);

    let exp = now_unix + DISCHARGE_EXP_SECONDS;
    Ok(mint_under_key_with_nonce(
        &r,
        DISCHARGE_KID,
        nonce,
        vec![
            Caveat::scalar(name::AUD, &state.config.audience),
            Caveat::scalar(name::OP, action),
            Caveat::scalar(name::CNF, cnf),
            Caveat::scalar(name::EXP, exp.to_string()),
        ],
    ))
}

fn error(status: StatusCode, msg: &'static str) -> Response {
    (status, axum::Json(json!({"error": msg}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macaroon::Macaroon;

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
        // Mint a discharge as the auth role would, then recover `r`
        // from the nonce + K_M-A as the mint role's verifier will and
        // confirm the chain MAC verifies. This is the core property
        // the demo issuer relies on.
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
                Caveat::scalar(name::EXP, "1700000000"),
            ],
        );
        let wire = discharge.encode();
        let decoded = Macaroon::decode(&wire).expect("decode");
        let recovered = derive_discharge_r(&k_m_a, decoded.nonce());
        assert!(decoded.verify_under_key(&recovered));
        // Wrong K_M-A: cannot recover the matching r.
        let mut wrong = k_m_a;
        wrong[31] ^= 0x01;
        let bad = derive_discharge_r(&wrong, decoded.nonce());
        assert!(!decoded.verify_under_key(&bad));
    }
}
