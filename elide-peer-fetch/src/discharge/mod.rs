//! The attestation-coordinator (coord B) discharge endpoint.
//!
//! coord B is mint's volume-attestation discharge authority
//! (`docs/design-mint-volume-attestation.md`). It serves `POST /v1/discharge`
//! on this peer-fetch server — the structural twin that already holds
//! `coord-ro` and verifies signed metadata — recovering `r` from an attested
//! TPC's CID, verifying a possession proof of the volume's signing key over
//! public signed state, and minting a discharge that attests the scoped
//! volume.
//!
//! This slice implements the **`rw-self`** mode: the requester proves
//! possession of a live volume's key and is vouched for *that same* volume.
//! The `ro-ancestor` mode (which needs the signed-lineage walk) is rejected
//! as unimplemented rather than silently mishandled.

pub mod crypto;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use object_store::path::Path as StorePath;
use object_store::{ObjectStore, PutPayload};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use elide_core::name_record::{NameRecord, NameState};
use elide_core::signing::{self, VerifyingKey};
use elide_core::store_keys::meta_pub_key;

/// Possession-proof freshness window, seconds. Bounds replay of a single
/// proof; the seen-cache (below) makes it single-use within `2 × skew`.
const DEFAULT_SKEW_SECS: u64 = 30;
/// `rw-self` discharge lifetime, seconds. RW ownership is revocable
/// (force-release/handoff), so the discharge is the liveness-staleness
/// bound and is kept short — roughly the Tigris keypair lifetime
/// (`docs/design-mint-volume-attestation.md` § *One liveness check*).
const RW_SELF_DISCHARGE_TTL_SECS: u64 = 300;

/// The opaque `mode` mint sealed into the attested TPC's CID for the
/// `volume-rw` role. coord B — not mint — assigns it meaning.
const MODE_RW_SELF: &str = "rw-self";
/// The `volume-ro` mode, recognised but not yet served by this slice.
const MODE_RO_ANCESTOR: &str = "ro-ancestor";

/// `POST /v1/discharge` request. `cid`, `nonce`, and `proof` are hex; `cid`
/// is opaque to the requester (coord A), decrypted here under `K_M-B`.
#[derive(Debug, Clone, Deserialize)]
pub struct DischargeRequest {
    /// The attested TPC's CID, hex — sealed by mint under `K_M-B`.
    pub cid: String,
    /// Volume name, for the liveness lookup (`names/<name>`).
    pub name: String,
    /// ULID of the live volume coord A proves possession of.
    pub owned: String,
    /// ULID of the volume to vouch for. `== owned` in `rw-self`.
    pub target: String,
    /// Possession-proof timestamp, unix seconds.
    pub ts: u64,
    /// Possession-proof nonce, hex.
    pub nonce: String,
    /// Ed25519 possession proof over the canonical payload, hex (64 bytes).
    pub proof: String,
}

/// `POST /v1/discharge` response: the `mnt1_` discharge macaroon.
#[derive(Debug, Clone, Serialize)]
pub struct DischargeResponse {
    pub discharge: String,
}

/// Why a discharge request was refused. Verification failures collapse to
/// one opaque `403` at the HTTP layer so coord B is not a discriminating
/// oracle; the variants drive logging and tests.
#[derive(Debug, thiserror::Error)]
pub enum DischargeError {
    #[error("malformed request: {0}")]
    Malformed(&'static str),
    #[error("discharge denied")]
    Denied(&'static str),
    #[error("unsupported attestation mode")]
    UnsupportedMode,
    #[error("metadata backend: {0}")]
    Backend(std::io::Error),
}

impl DischargeError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Malformed(_) => StatusCode::BAD_REQUEST,
            // Every verification failure looks identical to a caller.
            Self::Denied(_) => StatusCode::FORBIDDEN,
            Self::UnsupportedMode => StatusCode::NOT_IMPLEMENTED,
            Self::Backend(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl IntoResponse for DischargeError {
    fn into_response(self) -> Response {
        let body = match &self {
            // `Denied` never reveals which check failed.
            Self::Denied(_) => "discharge denied".to_string(),
            other => other.to_string(),
        };
        (self.status(), body).into_response()
    }
}

/// (owned, nonce) → server-clock insertion time. Makes a possession proof
/// single-use within its freshness window; pruned on every insert so it
/// stays bounded by `2 × skew`.
type SeenCache = HashMap<(String, String), u64>;

/// coord B's discharge-authority state, threaded onto the peer-fetch
/// [`crate::server::ServerContext`]. Present only on a coordinator enrolled
/// as a discharge authority (holds `K_M-B`); absent otherwise, so the
/// route fails closed with `404`.
#[derive(Clone)]
pub struct DischargeState {
    inner: Arc<DischargeInner>,
}

struct DischargeInner {
    /// The symmetric key mint shares with this authority; recovers `r` and
    /// the opaque `mode` from an attested TPC's CID.
    k_m_b: [u8; 32],
    /// Coord-ro S3 store: `meta/<owned>.pub` (possession) and
    /// `names/<name>` (liveness). No `by_id/` access.
    store: Arc<dyn ObjectStore>,
    skew_secs: u64,
    seen: Mutex<SeenCache>,
}

impl DischargeState {
    /// Build a discharge authority over `store` (coord-ro) keyed by `k_m_b`.
    pub fn new(k_m_b: [u8; 32], store: Arc<dyn ObjectStore>) -> Self {
        Self {
            inner: Arc::new(DischargeInner {
                k_m_b,
                store,
                skew_secs: DEFAULT_SKEW_SECS,
                seen: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Run the `rw-self` discharge predicate and mint the discharge.
    ///
    /// Order follows `docs/design-mint-volume-attestation.md` § *coord B
    /// verification*: recover the CID, check freshness + anti-replay, verify
    /// possession against `meta/<owned>.pub`, confirm liveness via
    /// `names/<name>`, enforce the mode, then mint.
    pub async fn discharge(&self, req: DischargeRequest) -> Result<String, DischargeError> {
        let cid = decode_hex(&req.cid).map_err(|_| DischargeError::Malformed("cid not hex"))?;
        let nonce =
            decode_hex(&req.nonce).map_err(|_| DischargeError::Malformed("nonce not hex"))?;
        let proof_bytes =
            decode_hex(&req.proof).map_err(|_| DischargeError::Malformed("proof not hex"))?;
        let proof: [u8; 64] = proof_bytes
            .try_into()
            .map_err(|_| DischargeError::Malformed("proof not 64 bytes"))?;
        let owned = Ulid::from_string(&req.owned)
            .map_err(|_| DischargeError::Malformed("owned not a ulid"))?;
        let target = Ulid::from_string(&req.target)
            .map_err(|_| DischargeError::Malformed("target not a ulid"))?;

        // 1. Recover `r` and `mode` from the CID under `K_M-B`. A bad CID is
        //    a denial, not a distinguishable error.
        let recovered = crypto::decrypt_cid_attested(&self.inner.k_m_b, &cid)
            .map_err(|_| DischargeError::Denied("cid"))?;

        // 2. Freshness + single-use anti-replay, before any S3 read so coord
        //    B is not a free discharge oracle.
        let now = now_unix();
        if now.abs_diff(req.ts) > self.inner.skew_secs {
            return Err(DischargeError::Denied("stale"));
        }
        self.check_and_record_nonce(&req.owned, &req.nonce, now)?;

        // 3. Mode. rw-self ⟹ target == owned; ro-ancestor is recognised but
        //    not served by this slice; anything else is unknown.
        match recovered.mode.as_str() {
            MODE_RW_SELF => {
                if target != owned {
                    return Err(DischargeError::Denied("target != owned"));
                }
            }
            MODE_RO_ANCESTOR => return Err(DischargeError::UnsupportedMode),
            _ => return Err(DischargeError::Denied("unknown mode")),
        }

        // 4. Possession: the proof must verify under `owned`'s public key.
        let owned_pub = self.fetch_volume_pub(&owned).await?;
        signing::verify_volume_possession(
            &owned_pub, &owned, &target, &cid, req.ts, &nonce, &proof,
        )
        .map_err(|_| DischargeError::Denied("possession"))?;

        // 5. Liveness: `names/<name>` must resolve to `owned`, Live.
        let record = self.fetch_name_record(&req.name).await?;
        if record.vol_ulid != owned || record.state != NameState::Live {
            return Err(DischargeError::Denied("liveness"));
        }

        // 6. Mint the discharge attesting `volume = target`.
        let exp = now + RW_SELF_DISCHARGE_TTL_SECS;
        let exp_s = exp.to_string();
        let target_s = target.to_string();
        Ok(crypto::mint_discharge(
            &recovered.r,
            &[("volume", &target_s), ("exp", &exp_s)],
        ))
    }

    fn check_and_record_nonce(
        &self,
        owned: &str,
        nonce: &str,
        now: u64,
    ) -> Result<(), DischargeError> {
        let bound = self.inner.skew_secs.saturating_mul(2);
        let mut seen =
            self.inner.seen.lock().map_err(|_| {
                DischargeError::Backend(std::io::Error::other("seen-cache poisoned"))
            })?;
        seen.retain(|_, &mut inserted| now.saturating_sub(inserted) <= bound);
        let key = (owned.to_owned(), nonce.to_owned());
        if seen.contains_key(&key) {
            return Err(DischargeError::Denied("replay"));
        }
        seen.insert(key, now);
        Ok(())
    }

    async fn fetch_volume_pub(&self, owned: &Ulid) -> Result<VerifyingKey, DischargeError> {
        let key = StorePath::from(meta_pub_key(*owned));
        let bytes = self.get_bytes(&key).await?;
        let text = std::str::from_utf8(&bytes).map_err(|_| DischargeError::Denied("pub utf8"))?;
        parse_pub_hex(text.trim()).map_err(|_| DischargeError::Denied("pub parse"))
    }

    async fn fetch_name_record(&self, name: &str) -> Result<NameRecord, DischargeError> {
        let key = StorePath::from(format!("names/{name}"));
        let bytes = self.get_bytes(&key).await?;
        let text = std::str::from_utf8(&bytes).map_err(|_| DischargeError::Denied("name utf8"))?;
        NameRecord::from_toml(text).map_err(|_| DischargeError::Denied("name parse"))
    }

    /// GET a coord-ro object. A missing object is a denial (the requester
    /// proved nothing about a volume with no published key / claim); other
    /// errors are backend faults.
    async fn get_bytes(&self, key: &StorePath) -> Result<bytes::Bytes, DischargeError> {
        match self.inner.store.get(key).await {
            Ok(r) => r
                .bytes()
                .await
                .map_err(|e| DischargeError::Backend(std::io::Error::other(e))),
            Err(object_store::Error::NotFound { .. }) => Err(DischargeError::Denied("absent")),
            Err(e) => Err(DischargeError::Backend(std::io::Error::other(e))),
        }
    }
}

/// Axum handler for `POST /v1/discharge`. Fails closed with `404` when this
/// coordinator is not a discharge authority.
pub async fn handle_discharge(
    State(ctx): State<crate::server::ServerContext>,
    Json(req): Json<DischargeRequest>,
) -> Response {
    let Some(state) = ctx.discharge.as_ref() else {
        return (StatusCode::NOT_FOUND, "discharge authority not enabled").into_response();
    };
    match state.discharge(req).await {
        Ok(discharge) => Json(DischargeResponse { discharge }).into_response(),
        Err(e) => {
            tracing::info!("[discharge] denied: {e}");
            e.into_response()
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    elide_core::signing::decode_hex(s).map_err(|_| ())
}

fn parse_pub_hex(s: &str) -> Result<VerifyingKey, ()> {
    let bytes: [u8; 32] = elide_core::signing::decode_hex(s)
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| ())
}

/// Put a coord-ro object — used by the daemon to seed test fixtures and by
/// callers that need to publish public metadata through the same handle.
pub async fn put_object(
    store: &dyn ObjectStore,
    key: &str,
    bytes: Vec<u8>,
) -> object_store::Result<()> {
    store
        .put(&StorePath::from(key), PutPayload::from(bytes))
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_core::signing::{encode_hex, generate_ephemeral_signer, sign_volume_possession};
    use object_store::memory::InMemory;

    /// The shared fixture's CID is sealed under a known `K_M-B` and carries
    /// `mode = "rw-self"` — exactly the rw-self input, so the test needs no
    /// CID re-encryption.
    fn vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/mint-discharge-vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    struct Fixture {
        state: DischargeState,
        owned: Ulid,
        cid_hex: String,
        name: String,
        nonce: [u8; 16],
        proof: [u8; 64],
        ts: u64,
    }

    /// A coordinator that owns a live volume, with its pub key and a Live
    /// name record published to an in-memory coord-ro store, and a valid
    /// rw-self possession proof over the fixture CID.
    async fn live_rw_self() -> Fixture {
        let v = vectors();
        let k_m_b: [u8; 32] = elide_core::signing::decode_hex(v["k_m_b"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let cid = elide_core::signing::decode_hex(v["cid"].as_str().unwrap()).unwrap();

        let owned = Ulid::from_string("01BX5ZZKBKACTAV9WEVGEMMVRZ").unwrap();
        let name = "demo-vol".to_string();
        let (signer, vk) = generate_ephemeral_signer();

        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        put_object(
            store.as_ref(),
            &meta_pub_key(owned),
            encode_hex(vk.as_bytes()).into_bytes(),
        )
        .await
        .unwrap();
        let record = NameRecord::live_minimal(owned, 4 * 1024 * 1024 * 1024);
        put_object(
            store.as_ref(),
            &format!("names/{name}"),
            record.to_toml().unwrap().into_bytes(),
        )
        .await
        .unwrap();

        let ts = now_unix();
        let nonce = [0x55u8; 16];
        let proof = sign_volume_possession(signer.as_ref(), &owned, &owned, &cid, ts, &nonce);
        Fixture {
            state: DischargeState::new(k_m_b, store),
            owned,
            cid_hex: v["cid"].as_str().unwrap().to_string(),
            name,
            nonce,
            proof,
            ts,
        }
    }

    impl Fixture {
        fn request(&self) -> DischargeRequest {
            DischargeRequest {
                cid: self.cid_hex.clone(),
                name: self.name.clone(),
                owned: self.owned.to_string(),
                target: self.owned.to_string(),
                ts: self.ts,
                nonce: encode_hex(&self.nonce),
                proof: encode_hex(&self.proof),
            }
        }
    }

    #[tokio::test]
    async fn rw_self_discharge_succeeds_and_returns_a_macaroon() {
        let f = live_rw_self().await;
        let wire = f.state.discharge(f.request()).await.expect("discharge");
        assert!(wire.starts_with("mnt1_"), "wire was {wire}");
    }

    #[tokio::test]
    async fn rejects_tampered_possession_proof() {
        let f = live_rw_self().await;
        let mut req = f.request();
        let mut proof = f.proof;
        proof[0] ^= 0x80;
        req.proof = encode_hex(&proof);
        assert!(matches!(
            f.state.discharge(req).await,
            Err(DischargeError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn rejects_when_name_owner_differs() {
        let f = live_rw_self().await;
        // Rebind the name to a different live volume.
        let other = Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").unwrap();
        let record = NameRecord::live_minimal(other, 4 * 1024 * 1024 * 1024);
        put_object(
            f.state.inner.store.as_ref(),
            &format!("names/{}", f.name),
            record.to_toml().unwrap().into_bytes(),
        )
        .await
        .unwrap();
        assert!(matches!(
            f.state.discharge(f.request()).await,
            Err(DischargeError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn rejects_stale_timestamp() {
        let f = live_rw_self().await;
        let mut req = f.request();
        req.ts = f.ts.saturating_sub(DEFAULT_SKEW_SECS + 5);
        // The proof was signed over the original ts, but freshness fails
        // first regardless.
        assert!(matches!(
            f.state.discharge(req).await,
            Err(DischargeError::Denied(_))
        ));
    }

    #[tokio::test]
    async fn rejects_replayed_nonce() {
        let f = live_rw_self().await;
        f.state.discharge(f.request()).await.expect("first ok");
        assert!(
            matches!(
                f.state.discharge(f.request()).await,
                Err(DischargeError::Denied(_))
            ),
            "second use of the same (owned, nonce) must be rejected"
        );
    }

    #[tokio::test]
    async fn rejects_target_not_owned_in_rw_self() {
        let f = live_rw_self().await;
        let mut req = f.request();
        req.target = "01ARZ3NDEKTSV4RRFFQ69G5FAV".to_string();
        assert!(matches!(
            f.state.discharge(req).await,
            Err(DischargeError::Denied(_))
        ));
    }
}
