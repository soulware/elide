//! mint credential-service client (`docs/design-mint.md`
//! § "Coordinator configuration").
//!
//! The coordinator holds a per-role capability macaroon under
//! `<data_dir>/credentials/<role>` (provisioned by enrollment — out of
//! scope here) and exercises it against mint's `assume-role`. Per
//! request it attenuates the stored macaroon with the bounding `exp`
//! and the per-volume `elide:Volume` caveat, proves possession with an
//! Ed25519 signature by `coordinator.key` over
//! `BLAKE3(macaroon-tail ‖ BLAKE3(request-body))`, and POSTs it.
//!
//! The macaroon wire format and PoP construction are reimplemented
//! here against the spec rather than shared: mint is a standalone
//! workspace with no `elide-*` dependency and Elide cannot depend on
//! it, the same deliberate duplication `mint/src/tigris.rs` makes.
//! The coordinator never mints or verifies — it only decodes,
//! attenuates (trailing-MAC only), and re-encodes — so the mint root
//! key never enters this path.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine as _;
// STANDARD base64 carries the PoP signature in `X-Mint-Pop` — mint's
// `pop::Proof::from_b64` expects it. Macaroon-wire base64 lives on
// [`WireMacaroon::encode`] / `decode` and uses base64url-no-pad.
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL;
use rand_core::{OsRng, RngCore};
use tracing::{debug, warn};
use ulid::Ulid;

/// Coordinator-side 503 retry budget for `assume-role`. Three attempts
/// total — mint already absorbs short Tigris throttle bursts with its
/// own per-IAM-call retry, so a 503 reaching here implies a sustained
/// condition; a tight outer budget keeps a stuck control-plane op from
/// blocking for tens of seconds.
const MAX_503_RETRIES: u32 = 3;
/// Floor / ceiling applied to the mint-supplied `Retry-After`. The
/// floor prevents tight loops if mint ever emits `0`; the ceiling
/// keeps total wait bounded even if mint asks for a long pause.
const RETRY_AFTER_FLOOR: Duration = Duration::from_secs(1);
const RETRY_AFTER_CEILING: Duration = Duration::from_secs(8);
const RETRY_AFTER_FALLBACK: Duration = Duration::from_secs(2);

/// Clamp the mint-supplied `Retry-After` (seconds) to a sane band, or
/// fall back to a small default when the header was absent or zero.
fn retry_after_delay(retry_after_secs: Option<u64>) -> Duration {
    match retry_after_secs {
        Some(0) | None => RETRY_AFTER_FALLBACK,
        Some(s) => Duration::from_secs(s)
            .max(RETRY_AFTER_FLOOR)
            .min(RETRY_AFTER_CEILING),
    }
}

use elide_coordinator::config::MintConfig;
use elide_coordinator::identity::CoordinatorIdentity;

use crate::credential::{AuthorizedTarget, CredentialIssuer, Credentialer, IssuedCredentials};

/// Wire prefix for a base64url-encoded mint macaroon — must match
/// `mint::macaroon::WIRE_PREFIX`. `mnt1` = mint macaroon, wire
/// generation 1.
const WIRE_PREFIX: &str = "mnt1_";
const NONCE_LEN: usize = 16;

/// Per-step type tag in the canonical MsgPack encoding (first element
/// of every caveat array). Must match `mint/src/macaroon.rs`.
const TYPE_FIRST_PARTY: u64 = 0;
const TYPE_THIRD_PARTY: u64 = 1;

/// Canonical mint role inventory — the single source of truth shared by
/// the enrollment fan-out (`crate::enroll`), the `[mint]` startup gate,
/// and the scoped stores (`crate::mint_stores`), so the three can never
/// drift. `volume-rw` is per-volume only at `assume-role` time (the
/// `elide:Volume` narrowing caveat); enrollment still mints exactly one
/// `credentials/volume-rw`.
pub(crate) const ROLE_COORD_RO: &str = "coord-ro";
pub(crate) const ROLE_COORD_RW: &str = "coord-rw";
pub(crate) const ROLE_VOLUME_RW: &str = "volume-rw";
pub(crate) const ROLE_VOLUME_RO: &str = "volume-ro";

/// Every role the coordinator enrols for, in fan-out order.
pub(crate) const COORD_ENROLL_ROLES: &[&str] =
    &[ROLE_COORD_RO, ROLE_COORD_RW, ROLE_VOLUME_RW, ROLE_VOLUME_RO];

const CAVEAT_EXP: &str = "exp";

/// What an `assume-role` is for — the `req.volume` target plus the
/// attestation anchor, made structural so the discharge decision is a
/// property of the variant, not a role-string comparison at the call
/// site.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AssumeTarget {
    /// Coordinator-wide roles (`coord-ro` / `coord-rw`): no
    /// `req.volume`, no attestation discharge.
    Coord,
    /// `volume-rw`: the volume is both the possession-proven anchor
    /// and the vouched target (`rw-self`).
    RwSelf(Ulid),
    /// `volume-ro`: read `target`'s prefix, anchored on the live,
    /// locally-keyed `owned` whose key signs the possession proof
    /// (`ro-ancestor`; `target == owned` is the leaf reading its own
    /// prefix).
    RoAncestor { owned: Ulid, target: Ulid },
}

impl AssumeTarget {
    /// The `req.volume` value for the assume-role body.
    fn volume(&self) -> Option<Ulid> {
        match self {
            AssumeTarget::Coord => None,
            AssumeTarget::RwSelf(v) => Some(*v),
            AssumeTarget::RoAncestor { target, .. } => Some(*target),
        }
    }

    /// The `(owned, target)` pair a discharge attests, when this
    /// assume carries an attestation TPC.
    fn attestation(&self) -> Option<(Ulid, Ulid)> {
        match self {
            AssumeTarget::Coord => None,
            AssumeTarget::RwSelf(v) => Some((*v, *v)),
            AssumeTarget::RoAncestor { owned, target } => Some((*owned, *target)),
        }
    }
}

/// Lifetime requested for a `volume-ro` credential. Set to 1h: the
/// non-lazy fetch episode completes in seconds, and the lazy-volume
/// cache refreshes proactively at half-life (`docs/design-mint.md`
/// § "Keypair freshness — split by volume mode"). Read keys on the
/// narrowest scope still benefit from the tightest revocation window
/// that doesn't put the refresh path on the hot path.
pub(crate) const VOLUME_RO_TTL_SECS: u64 = 60 * 60;

pub(crate) fn now_unix() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| io::Error::other(format!("system clock before unix epoch: {e}")))
}

/// One step in the macaroon's caveat chain. Mirrors
/// `mint/src/caveat.rs::Caveat`. The coordinator only ever appends
/// first-party caveats; third-party caveats are preserved opaquely
/// through the decode → attenuate → encode round-trip so re-encoded
/// bytes match what mint will accept.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Caveat {
    FirstParty {
        name: String,
        value: String,
    },
    ThirdParty {
        location: String,
        vid: Vec<u8>,
        cid: Vec<u8>,
    },
}

/// Canonical per-caveat MsgPack encoding — first-party: `[0, name,
/// value]`; third-party: `[1, location, vid, cid]`. The same bytes
/// appear in the wire envelope and as the BLAKE3-keyed-hash input to
/// each chain step, so a decoded macaroon re-MACs identically. Must
/// match `mint/src/macaroon.rs::serialize_one`.
fn serialize_one(c: &Caveat) -> Vec<u8> {
    let mut out = Vec::new();
    match c {
        Caveat::FirstParty { name, value } => {
            rmp::encode::write_array_len(&mut out, 3).expect("vec writer");
            rmp::encode::write_uint(&mut out, TYPE_FIRST_PARTY).expect("vec writer");
            rmp::encode::write_str(&mut out, name).expect("vec writer");
            rmp::encode::write_str(&mut out, value).expect("vec writer");
        }
        Caveat::ThirdParty { location, vid, cid } => {
            rmp::encode::write_array_len(&mut out, 4).expect("vec writer");
            rmp::encode::write_uint(&mut out, TYPE_THIRD_PARTY).expect("vec writer");
            rmp::encode::write_str(&mut out, location).expect("vec writer");
            rmp::encode::write_bin(&mut out, vid).expect("vec writer");
            rmp::encode::write_bin(&mut out, cid).expect("vec writer");
        }
    }
    out
}

/// Build the first-party caveat shape, the only kind the coordinator
/// ever appends via attenuation.
fn first_party(name: impl Into<String>, value: impl Into<String>) -> Caveat {
    Caveat::FirstParty {
        name: name.into(),
        value: value.into(),
    }
}

/// A decoded mint macaroon. The coordinator only ever decodes one mint
/// gave it, appends narrowing caveats, and re-encodes — it has no root
/// key, so it neither mints nor verifies. The `kid` is preserved
/// opaquely through the round-trip so re-encoded bytes match what mint
/// will accept (kid is part of the MAC seed, not the wire-level chain
/// extension — so attenuation doesn't touch it).
pub(crate) struct WireMacaroon {
    kid: u16,
    nonce: [u8; NONCE_LEN],
    caveats: Vec<Caveat>,
    mac: [u8; 32],
}

impl WireMacaroon {
    pub(crate) fn decode(s: &str) -> io::Result<Self> {
        let body = s
            .trim()
            .strip_prefix(WIRE_PREFIX)
            .ok_or_else(|| io::Error::other("credential macaroon: missing mnt1_ prefix"))?;
        let buf = BASE64_URL
            .decode(body)
            .map_err(|_| io::Error::other("credential macaroon: base64url decode failed"))?;
        let mut r: &[u8] = &buf;

        let env_len = rmp::decode::read_array_len(&mut r)
            .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
        if env_len != 4 {
            return Err(io::Error::other("credential macaroon: envelope shape"));
        }
        let kid_u64: u64 = rmp::decode::read_int(&mut r)
            .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
        let kid: u16 = kid_u64
            .try_into()
            .map_err(|_| io::Error::other("credential macaroon: kid overflow"))?;
        let nonce = read_bin_fixed::<NONCE_LEN>(&mut r)?;
        let mac = read_bin_fixed::<32>(&mut r)?;
        let count = rmp::decode::read_array_len(&mut r)
            .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
        let mut caveats = Vec::with_capacity(count as usize);
        for _ in 0..count {
            caveats.push(decode_caveat(&mut r)?);
        }
        if !r.is_empty() {
            return Err(io::Error::other("credential macaroon: trailing bytes"));
        }
        Ok(Self {
            kid,
            nonce,
            caveats,
            mac,
        })
    }

    /// Append `(name, value)` as a first-party caveat, extending the
    /// chain with only the trailing MAC. Caveats are AND-evaluated,
    /// so this can only restrict authority — the additive-restriction
    /// property that lets a non-root holder attenuate. The coordinator
    /// never appends third-party caveats; only mint at issuance
    /// constructs those.
    pub(crate) fn attenuate(&mut self, name: &str, value: &str) {
        let c = first_party(name, value);
        let step = serialize_one(&c);
        self.mac = *blake3::keyed_hash(&self.mac, &step).as_bytes();
        self.caveats.push(c);
    }

    pub(crate) fn tail(&self) -> &[u8; 32] {
        &self.mac
    }

    /// The `cid` of the third-party caveat at `location`, if the macaroon
    /// carries one. Used to find the attestation caveat coord B discharges;
    /// other third-party caveats (e.g. operator-authorisation) sit at
    /// different locations and are discharged by their own authorities.
    pub(crate) fn third_party_cid_at(&self, location: &str) -> Option<&[u8]> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::ThirdParty {
                location: l, cid, ..
            } if l == location => Some(cid.as_slice()),
            _ => None,
        })
    }

    pub(crate) fn encode(&self) -> String {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 4).expect("vec writer");
        rmp::encode::write_uint(&mut buf, self.kid as u64).expect("vec writer");
        rmp::encode::write_bin(&mut buf, &self.nonce).expect("vec writer");
        rmp::encode::write_bin(&mut buf, &self.mac).expect("vec writer");
        let count: u32 = self
            .caveats
            .len()
            .try_into()
            .expect("caveat count fits u32");
        rmp::encode::write_array_len(&mut buf, count).expect("vec writer");
        for c in &self.caveats {
            buf.extend_from_slice(&serialize_one(c));
        }
        let mut out = String::with_capacity(WIRE_PREFIX.len() + (buf.len() * 4 / 3 + 4));
        out.push_str(WIRE_PREFIX);
        BASE64_URL.encode_string(&buf, &mut out);
        out
    }
}

fn read_bin_fixed<const N: usize>(r: &mut &[u8]) -> io::Result<[u8; N]> {
    let len = rmp::decode::read_bin_len(r)
        .map_err(|_| io::Error::other("credential macaroon: truncated"))? as usize;
    if len != N {
        return Err(io::Error::other("credential macaroon: bin length"));
    }
    let (head, tail) = r
        .split_at_checked(N)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
    let arr: [u8; N] = head
        .try_into()
        .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
    *r = tail;
    Ok(arr)
}

fn read_str_owned(r: &mut &[u8]) -> io::Result<String> {
    let len = rmp::decode::read_str_len(r)
        .map_err(|_| io::Error::other("credential macaroon: truncated"))? as usize;
    let (head, tail) = r
        .split_at_checked(len)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
    *r = tail;
    String::from_utf8(head.to_vec())
        .map_err(|_| io::Error::other("credential macaroon: caveat not utf-8"))
}

fn read_bin_owned(r: &mut &[u8]) -> io::Result<Vec<u8>> {
    let len = rmp::decode::read_bin_len(r)
        .map_err(|_| io::Error::other("credential macaroon: truncated"))? as usize;
    let (head, tail) = r
        .split_at_checked(len)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
    *r = tail;
    Ok(head.to_vec())
}

fn decode_caveat(r: &mut &[u8]) -> io::Result<Caveat> {
    let arr_len = rmp::decode::read_array_len(r)
        .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
    let tag: u64 =
        rmp::decode::read_int(r).map_err(|_| io::Error::other("credential macaroon: truncated"))?;
    match (tag, arr_len) {
        (0, 3) => {
            let name = read_str_owned(r)?;
            let value = read_str_owned(r)?;
            Ok(Caveat::FirstParty { name, value })
        }
        (1, 4) => {
            let location = read_str_owned(r)?;
            let vid = read_bin_owned(r)?;
            let cid = read_bin_owned(r)?;
            Ok(Caveat::ThirdParty { location, vid, cid })
        }
        _ => Err(io::Error::other(
            "credential macaroon: unknown caveat type tag",
        )),
    }
}

/// `BLAKE3(tail ‖ BLAKE3(body))` — the digest the PoP signature
/// covers. Body is hashed as the exact bytes sent (`mint/src/pop.rs`).
pub(crate) fn pop_digest(tail: &[u8; 32], body: &[u8]) -> [u8; 32] {
    let body_hash = blake3::hash(body);
    let mut h = blake3::Hasher::new();
    h.update(tail);
    h.update(body_hash.as_bytes());
    *h.finalize().as_bytes()
}

/// `unix:<path>` selects the UDS leg; anything else is the TCP base
/// URL. Scheme validation already happened in `MintConfig::validate`.
fn uds_socket(url: &str) -> Option<&str> {
    url.trim().strip_prefix("unix:")
}

/// Returns `(status, body, retry_after_secs)`. The retry-after value
/// is parsed from the response `Retry-After` header when present and
/// expressed in seconds (mint always emits seconds —
/// `docs/design-mint.md` § *Failure modes*); the HTTP-date form is
/// not parsed.
pub(crate) async fn post(
    cfg_url: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
    endpoint: &str,
    auth: &str,
    sig: &str,
    body: String,
) -> io::Result<(u16, String, Option<u64>)> {
    match uds_socket(cfg_url) {
        Some(socket) => post_uds(socket, request_timeout, endpoint, auth, sig, body).await,
        None => {
            post_tcp(
                cfg_url,
                connect_timeout,
                request_timeout,
                endpoint,
                auth,
                sig,
                body,
            )
            .await
        }
    }
}

async fn post_tcp(
    base: &str,
    connect_timeout: Duration,
    request_timeout: Duration,
    endpoint: &str,
    auth: &str,
    sig: &str,
    body: String,
) -> io::Result<(u16, String, Option<u64>)> {
    let client = reqwest::Client::builder()
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .build()
        .map_err(|e| io::Error::other(format!("building mint http client: {e}")))?;
    let resp = client
        .post(format!("{}{endpoint}", base.trim_end_matches('/')))
        .header("authorization", auth)
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| {
            // Tag connect/timeout failures with a specific `ErrorKind` so
            // `wait_for_ready` can distinguish "mint not up yet" from a
            // real protocol-level error.
            if e.is_connect() {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("mint request failed: {e}"),
                )
            } else if e.is_timeout() {
                io::Error::new(io::ErrorKind::TimedOut, format!("mint request failed: {e}"))
            } else {
                io::Error::other(format!("mint request failed: {e}"))
            }
        })?;
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let text = resp
        .text()
        .await
        .map_err(|e| io::Error::other(format!("reading mint response: {e}")))?;
    Ok((status, text, retry_after))
}

/// HTTP-over-UDS leg — `reqwest` has no UDS support, so this drops to
/// `hyper` dialed through `hyperlocal`, the same split mint's
/// reference client makes (`docs/design-mint.md` § "Transport").
async fn post_uds(
    socket: &str,
    request_timeout: Duration,
    endpoint: &str,
    auth: &str,
    sig: &str,
    body: String,
) -> io::Result<(u16, String, Option<u64>)> {
    use http_body_util::{BodyExt, Full};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let client: Client<_, Full<bytes::Bytes>> =
        Client::builder(TokioExecutor::new()).build(hyperlocal::UnixConnector);
    let uri: hyper::Uri = hyperlocal::Uri::new(socket, endpoint).into();
    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(uri)
        .header("authorization", auth)
        .header("x-mint-pop", sig)
        .header("content-type", "application/json")
        .body(Full::new(bytes::Bytes::from(body)))
        .map_err(|e| io::Error::other(format!("building mint uds request: {e}")))?;
    let resp = tokio::time::timeout(request_timeout, client.request(req))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "mint uds request timed out"))?
        .map_err(|e| {
            // Tag connect-class failures so `wait_for_ready` can
            // distinguish "mint not up yet" from a real protocol error.
            // hyperlocal's connector raises an `io::Error::NotFound`
            // when the socket is missing entirely — surface that as
            // `ConnectionRefused` too.
            if e.is_connect() {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("mint uds request failed: {e}"),
                )
            } else {
                io::Error::other(format!("mint uds request failed: {e}"))
            }
        })?;
    let status = resp.status().as_u16();
    let retry_after = resp
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());
    let bytes = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| io::Error::other(format!("reading mint uds response: {e}")))?
        .to_bytes();
    Ok((
        status,
        String::from_utf8_lossy(&bytes).into_owned(),
        retry_after,
    ))
}

pub(crate) fn json_str_field(body: &str, key: &str) -> io::Result<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(key).and_then(|s| s.as_str()).map(str::to_owned))
        .ok_or_else(|| io::Error::other(format!("mint response missing `{key}` field")))
}

/// A configured mint endpoint plus the coordinator identity that
/// proves possession. Shared by every role the coordinator assumes —
/// `volume-ro` (vended to volumes, [`MintCredentialer`]) and the
/// `coord-*` roles (held by the coordinator, `crate::mint_stores`).
#[derive(Clone)]
pub struct MintEndpoint {
    url: String,
    connect_timeout: Duration,
    request_timeout: Duration,
    data_dir: PathBuf,
    identity: Arc<CoordinatorIdentity>,
    /// coord B's discharge URL, when this deployment uses volume
    /// attestation. A primary whose third-party caveat sits at this exact
    /// location is discharged before `assume-role`; see
    /// [`MintEndpoint::fetch_rw_self_discharge`].
    attestation_location: Option<String>,
}

impl MintEndpoint {
    pub fn new(cfg: &MintConfig, data_dir: PathBuf, identity: Arc<CoordinatorIdentity>) -> Self {
        Self {
            url: cfg.url.clone(),
            connect_timeout: cfg.connect_timeout,
            request_timeout: cfg.request_timeout,
            data_dir,
            identity,
            attestation_location: cfg.attestation_location.clone(),
        }
    }

    /// Load `credentials/<role>`, bound it to `ttl_secs` (`exp`
    /// caveat) plus any role-specific narrowing caveats, exercise it
    /// at `/v1/assume-role` with the `coordinator.key` PoP, and return
    /// the vended Tigris keypair. `extra_body` carries role-specific
    /// PoP-signed request fields (e.g. `volume-ro`'s `ancestors`).
    ///
    /// Transient `503` responses (mint's signal for Tigris-side
    /// throttling or backend unavailability, `docs/design-mint.md`
    /// § *Failure modes*) are retried a bounded number of times,
    /// honouring `Retry-After` clamped to a sane band. Mint also
    /// performs its own per-IAM-call retry before surfacing 503, so
    /// reaching this loop already implies a sustained backend
    /// condition, not a one-shot burst.
    /// Fetch an attestation discharge from coord B vouching `target`,
    /// anchored on `owned`.
    ///
    /// Proves possession of `owned`'s `volume.key` over a fresh
    /// `(ts, nonce)` bound to the opaque `cid`, names the volume for coord
    /// B's liveness lookup (`read_volume_name` reads it from the volume's
    /// own dir), and returns the `mnt1_` discharge to attach to the
    /// `assume-role` bundle. coord B authenticates the request by the
    /// possession proof in the body, not the mint PoP headers. Which
    /// `(owned, target)` shapes coord B accepts is the CID's baked
    /// `mode`: `rw-self` requires `target == owned`; `ro-ancestor`
    /// requires `target` in `owned`'s read set.
    async fn fetch_attestation_discharge(
        &self,
        owned: Ulid,
        target: Ulid,
        cid: &[u8],
        location: &str,
    ) -> io::Result<String> {
        let body = self.build_discharge_request(owned, target, cid)?;

        // The discharge URL carries its own path, so the endpoint suffix is
        // empty; auth/PoP headers are unused by coord B and sent empty.
        let (status, text, _) = post(
            location,
            self.connect_timeout,
            self.request_timeout,
            "",
            "",
            "",
            body,
        )
        .await?;
        if status != 200 {
            let snippet: String = text.chars().take(200).collect();
            return Err(io::Error::other(format!(
                "coord B discharge for {target} (anchor {owned}) returned {status}: {snippet}"
            )));
        }
        json_str_field(&text, "discharge")
    }

    /// Build coord B's `POST /v1/discharge` request body attesting
    /// `target` anchored on `owned`: load the anchor's volume name and
    /// `volume.key`, sign an Ed25519 possession proof over a fresh
    /// `(ts, nonce)` bound to `cid`, and serialise the JSON coord B's
    /// `DischargeRequest` expects. Separated from the POST so the
    /// request/response contract with coord B is testable without a
    /// live server.
    fn build_discharge_request(&self, owned: Ulid, target: Ulid, cid: &[u8]) -> io::Result<String> {
        let fork_dir = self.data_dir.join("by_id").join(owned.to_string());
        let name = elide_coordinator::tasks::read_volume_name(&fork_dir).ok_or_else(|| {
            io::Error::other(format!(
                "cannot anchor on {owned}: no local volume name (not a live named volume)"
            ))
        })?;
        let signer =
            elide_core::signing::load_signer(&fork_dir, elide_core::signing::VOLUME_KEY_FILE)?;

        let ts = now_unix()?;
        let mut nonce = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        let proof = elide_core::signing::sign_volume_possession(
            signer.as_ref(),
            &owned,
            &target,
            cid,
            ts,
            &nonce,
        );

        let mut obj = serde_json::Map::new();
        obj.insert("cid".into(), elide_core::signing::encode_hex(cid).into());
        obj.insert("name".into(), name.into());
        obj.insert("owned".into(), owned.to_string().into());
        obj.insert("target".into(), target.to_string().into());
        obj.insert("ts".into(), ts.into());
        obj.insert(
            "nonce".into(),
            elide_core::signing::encode_hex(&nonce).into(),
        );
        obj.insert(
            "proof".into(),
            elide_core::signing::encode_hex(&proof).into(),
        );
        Ok(serde_json::Value::Object(obj).to_string())
    }

    pub async fn assume_role(
        &self,
        role: &str,
        ttl_secs: u64,
        target: AssumeTarget,
    ) -> io::Result<IssuedCredentials> {
        let cred_path = self.data_dir.join("credentials").join(role);
        let stored = std::fs::read_to_string(&cred_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "reading {role} credential at {}: {e} (run enrollment for this role)",
                    cred_path.display()
                ),
            )
        })?;

        // If this credential carries an attestation third-party caveat at
        // the configured coord B location, discharge it once and attach the
        // discharge to every attempt's bundle. The `(owned, target)` the
        // discharge attests is a property of the assume's variant — rw-self
        // for `volume-rw`, ro-ancestor for `volume-ro`.
        let discharge = match (&self.attestation_location, target.attestation()) {
            (Some(loc), Some((owned, tgt))) => {
                let cid = WireMacaroon::decode(&stored)?
                    .third_party_cid_at(loc)
                    .map(<[u8]>::to_vec);
                match cid {
                    Some(cid) => Some(
                        self.fetch_attestation_discharge(owned, tgt, &cid, loc)
                            .await?,
                    ),
                    None => None,
                }
            }
            _ => None,
        };
        let volume = target.volume();

        let mut attempt: u32 = 0;
        let (text, exp) = loop {
            attempt += 1;
            // Each attempt re-attenuates from the stored macaroon and
            // signs a fresh body — `exp` and `ts` shift with the
            // current clock so the issued credential's lifetime is
            // measured from the successful attempt, not the first try.
            let mut mac = WireMacaroon::decode(&stored)?;
            let now = now_unix()?;
            let exp = now.saturating_add(ttl_secs);
            // The credential does not expire; the role gate requires
            // `exp`. Bound it via a caveat (the gate clears it).
            mac.attenuate(CAVEAT_EXP, &exp.to_string());

            // Build the exact body bytes once: they are both signed
            // (via BLAKE3(body)) and sent. Mint hashes the raw bytes
            // before parsing, so no canonicalization step may sit
            // between. The per-volume target rides the PoP-signed body as
            // `req.volume`; the policy template substitutes it.
            let mut obj = serde_json::Map::new();
            obj.insert("ts".into(), now.into());
            obj.insert("role".into(), role.into());
            obj.insert("ttl_seconds".into(), ttl_secs.into());
            if let Some(v) = volume {
                obj.insert("volume".into(), v.to_string().into());
            }
            let body = serde_json::Value::Object(obj).to_string();

            let sig = BASE64.encode(self.identity.sign(&pop_digest(mac.tail(), body.as_bytes())));
            // Attach the attestation discharge (if any) as the second
            // macaroon in the bundle; mint parses `MintV1 <primary>,<dis>`.
            let auth = match &discharge {
                Some(d) => format!("MintV1 {},{}", mac.encode(), d),
                None => format!("MintV1 {}", mac.encode()),
            };

            let (status, text, retry_after) = post(
                &self.url,
                self.connect_timeout,
                self.request_timeout,
                "/v1/assume-role",
                &auth,
                &sig,
                body,
            )
            .await?;

            if status == 200 {
                break (text, exp);
            }

            // mint's error model is deliberately coarse (401/400/503);
            // surface status + a short body for the operator log.
            let snippet: String = text.chars().take(200).collect();
            if status == 503 && attempt < MAX_503_RETRIES {
                let delay = retry_after_delay(retry_after);
                warn!(
                    "[coordinator] mint assume-role for {role} returned 503 \
                     (retry-after={}s, body={snippet:?}); retrying in {:?} (attempt {attempt}/{MAX_503_RETRIES})",
                    retry_after
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "<absent>".into()),
                    delay,
                );
                tokio::time::sleep(delay).await;
                continue;
            }
            if status == 503 {
                warn!(
                    "[coordinator] mint assume-role for {role} exhausted 503 retries \
                     (retry-after={}s, body={snippet:?})",
                    retry_after
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "<absent>".into()),
                );
            }
            return Err(io::Error::other(format!(
                "mint assume-role for {role} returned {status}: {snippet}"
            )));
        };

        let access_key_id = json_str_field(&text, "access_key_id")?;
        let secret_access_key = json_str_field(&text, "secret_access_key")?;
        // mint may clamp to the role max; its `expiration` is
        // authoritative. If it is unparseable, the `exp` we attenuated
        // to is a valid upper bound — fall back to it rather than fail
        // a credential mint that otherwise succeeded.
        let expiry_unix = json_str_field(&text, "expiration")
            .ok()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s.trim()).ok())
            .map(|dt| dt.timestamp().max(0) as u64)
            .unwrap_or_else(|| {
                warn!("[coordinator] mint {role} expiration unparseable; using attenuated exp");
                exp
            });

        Ok(IssuedCredentials {
            access_key_id,
            secret_access_key,
            session_token: None,
            expiry_unix: Some(expiry_unix),
        })
    }

    /// Block until the mint endpoint accepts an `assume-role` for
    /// `role`. Retries indefinitely on connect/timeout failures with
    /// exponential backoff (100ms → 5s cap); any other error
    /// (HTTP status, missing credential file, decode failure, etc.)
    /// is fatal. The vended credentials are discarded — this is a
    /// readiness probe; the real first use during normal operation
    /// will re-assume and cache.
    pub async fn wait_for_ready(&self, role: &str, ttl_secs: u64) -> io::Result<()> {
        let mut delay = Duration::from_millis(100);
        let cap = Duration::from_secs(5);
        let mut attempt: u64 = 0;
        loop {
            attempt += 1;
            match self.assume_role(role, ttl_secs, AssumeTarget::Coord).await {
                Ok(_) => {
                    if attempt > 1 {
                        tracing::info!("[coordinator] mint reachable after {attempt} attempts");
                    }
                    return Ok(());
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::TimedOut
                    ) =>
                {
                    if attempt == 1 || attempt.is_multiple_of(10) {
                        warn!(
                            "[coordinator] mint not reachable yet ({e}); \
                             retrying (attempt {attempt})"
                        );
                    }
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(cap);
                }
                Err(e) => return Err(e),
            }
        }
    }
}

/// Per-volume RO credentialer backed by the external mint service.
/// Sees only ULIDs — ancestor resolution happens upstream in
/// [`MintCredentialIssuer`], the same split the in-process iam path
/// makes, so the seam is transport-agnostic.
pub struct MintCredentialer {
    endpoint: MintEndpoint,
}

impl MintCredentialer {
    pub fn new(cfg: &MintConfig, data_dir: PathBuf, identity: Arc<CoordinatorIdentity>) -> Self {
        Self {
            endpoint: MintEndpoint::new(cfg, data_dir, identity),
        }
    }
}

#[async_trait]
impl Credentialer for MintCredentialer {
    async fn provision_volume_ro(
        &self,
        owned: Ulid,
        target: Ulid,
    ) -> io::Result<IssuedCredentials> {
        self.endpoint
            .assume_role(
                ROLE_VOLUME_RO,
                VOLUME_RO_TTL_SECS,
                AssumeTarget::RoAncestor { owned, target },
            )
            .await
    }

    async fn release_volume_ro(&self, vol_ulid: Ulid) {
        // Nothing to release. mint vends self-expiring ephemeral
        // keypairs; the IAM key lifecycle is mint's concern and the
        // coordinator holds no server-side handle to tear down. (The
        // in-process iam path deleted the key+policy because it minted
        // them itself — mint does not delegate that.)
        debug!("[coordinator] mint volume-ro release for {vol_ulid}: no-op (self-expiring)");
    }
}

/// `CredentialIssuer` wrapper that delegates to a [`Credentialer`].
/// Mirrors the in-process iam issuer so the inbound `credentials`
/// handshake is identical regardless of backend. Lineage authorization
/// happens at the IPC boundary (`inbound::issue_credentials`), so this
/// issuer provisions exactly the one authorized `target` prefix.
pub struct MintCredentialIssuer {
    credentialer: Arc<dyn Credentialer>,
}

impl MintCredentialIssuer {
    pub fn new(credentialer: Arc<dyn Credentialer>) -> Self {
        Self { credentialer }
    }
}

#[async_trait]
impl CredentialIssuer for MintCredentialIssuer {
    async fn issue(&self, authorized: AuthorizedTarget) -> io::Result<IssuedCredentials> {
        // A single volume the requester is authorized to read (the
        // `AuthorizedTarget` proof); grant its `by_id/<target>/*`
        // prefix, anchored on the requester.
        self.credentialer
            .provision_volume_ro(authorized.owned(), authorized.target())
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a wire macaroon the way `mint/src/macaroon.rs` does, so
    /// the coordinator's decode/attenuate/encode is checked against the
    /// real construction without depending on the mint crate. Mirrors
    /// the v4 wire format: canonical MsgPack envelope, base64url-no-pad
    /// encoded, `mnt1_` prefix.
    fn mint_like(
        root: &[u8; 32],
        kid: u16,
        nonce: [u8; NONCE_LEN],
        caveats: &[(&str, &str)],
    ) -> String {
        let cs: Vec<Caveat> = caveats.iter().map(|(n, v)| first_party(*n, *v)).collect();
        const DOMAIN: &[u8] = b"mint-macaroon-v4";
        let mut seed_msg = Vec::new();
        seed_msg.extend_from_slice(DOMAIN);
        seed_msg.extend_from_slice(&kid.to_be_bytes());
        seed_msg.extend_from_slice(&nonce);
        let mut key = *blake3::keyed_hash(root, &seed_msg).as_bytes();
        for c in &cs {
            key = *blake3::keyed_hash(&key, &serialize_one(c)).as_bytes();
        }
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 4).unwrap();
        rmp::encode::write_uint(&mut buf, kid as u64).unwrap();
        rmp::encode::write_bin(&mut buf, &nonce).unwrap();
        rmp::encode::write_bin(&mut buf, &key).unwrap();
        rmp::encode::write_array_len(&mut buf, cs.len() as u32).unwrap();
        for c in &cs {
            buf.extend_from_slice(&serialize_one(c));
        }
        format!("{WIRE_PREFIX}{}", BASE64_URL.encode(buf))
    }

    #[test]
    fn decode_then_encode_roundtrips() {
        let wire = mint_like(
            &[7u8; 32],
            0,
            [3u8; NONCE_LEN],
            &[("aud", "mint"), ("role", "volume-ro")],
        );
        let m = WireMacaroon::decode(&wire).expect("decode");
        assert_eq!(m.caveats.len(), 2);
        assert_eq!(m.kid, 0);
        assert_eq!(m.encode(), wire);
    }

    #[test]
    fn kid_is_preserved_through_roundtrip() {
        // Coordinator never minted, never verifies, never rotates —
        // its only obligation is to hand back the kid bytes it
        // received so mint's verifier picks the same generation.
        let wire = mint_like(&[7u8; 32], 5, [3u8; NONCE_LEN], &[("aud", "mint")]);
        let m = WireMacaroon::decode(&wire).expect("decode");
        assert_eq!(m.kid, 5);
        assert_eq!(m.encode(), wire);
    }

    #[test]
    fn attenuate_extends_chain_like_mint() {
        let root = [9u8; 32];
        let nonce = [1u8; NONCE_LEN];
        let base = mint_like(&root, 0, nonce, &[("aud", "mint")]);
        let mut m = WireMacaroon::decode(&base).expect("decode");
        m.attenuate(CAVEAT_EXP, "1700000000");

        // The attenuated wire must equal a mint-side macaroon minted
        // with the same caveat appended — proves the trailing-MAC
        // extension is byte-identical.
        let expected = mint_like(&root, 0, nonce, &[("aud", "mint"), ("exp", "1700000000")]);
        assert_eq!(m.encode(), expected);
        assert_eq!(m.caveats.len(), 2);
    }

    #[test]
    fn pop_digest_is_tail_then_body_hash() {
        let tail = [4u8; 32];
        let body = br#"{"ts":1,"role":"volume-ro"}"#;
        let bh = blake3::hash(body);
        let mut h = blake3::Hasher::new();
        h.update(&tail);
        h.update(bh.as_bytes());
        assert_eq!(pop_digest(&tail, body), *h.finalize().as_bytes());
    }

    #[test]
    fn decode_rejects_garbage_without_panicking() {
        assert!(WireMacaroon::decode("not base64!!!").is_err());
        assert!(WireMacaroon::decode(&BASE64.encode([0u8; 3])).is_err());
    }

    #[test]
    fn uds_scheme_detected() {
        assert_eq!(
            uds_socket("unix:mint/mint_data/mint.sock"),
            Some("mint/mint_data/mint.sock")
        );
        assert_eq!(uds_socket("https://mint.host:8085"), None);
    }

    #[test]
    fn retry_after_delay_clamps() {
        // Absent or zero header → fallback, not a tight loop.
        assert_eq!(retry_after_delay(None), RETRY_AFTER_FALLBACK);
        assert_eq!(retry_after_delay(Some(0)), RETRY_AFTER_FALLBACK);
        // Values inside the band pass through unchanged.
        assert_eq!(retry_after_delay(Some(3)), Duration::from_secs(3));
        // Below floor → floor.
        assert_eq!(retry_after_delay(Some(1)), RETRY_AFTER_FLOOR);
        // Above ceiling → ceiling (mint asking for a long pause does
        // not block control-plane ops for that long).
        assert_eq!(retry_after_delay(Some(60)), RETRY_AFTER_CEILING);
    }

    #[test]
    fn third_party_cid_at_selects_the_caveat_for_a_location() {
        // A credential can carry several third-party caveats discharged by
        // different authorities; coord A must pick the attestation one by
        // its location, not by position.
        let m = WireMacaroon {
            kid: 0,
            nonce: [0u8; NONCE_LEN],
            mac: [0u8; 32],
            caveats: vec![
                first_party("aud", "mint"),
                Caveat::ThirdParty {
                    location: "https://auth.example/v1/discharge".into(),
                    vid: vec![3, 3],
                    cid: vec![7, 7, 7],
                },
                Caveat::ThirdParty {
                    location: "https://coord-b.example/v1/discharge".into(),
                    vid: vec![1, 1],
                    cid: vec![9, 9, 9, 9],
                },
            ],
        };
        assert_eq!(
            m.third_party_cid_at("https://coord-b.example/v1/discharge"),
            Some(&[9u8, 9, 9, 9][..])
        );
        assert_eq!(
            m.third_party_cid_at("https://auth.example/v1/discharge"),
            Some(&[7u8, 7, 7][..])
        );
        assert_eq!(m.third_party_cid_at("https://nowhere.example"), None);
    }

    /// The shared cross-implementation fixture (canonical rw-self CID under
    /// a known `K_M-B`), the same file `elide-peer-fetch`'s discharge tests
    /// pin against.
    fn discharge_vectors() -> serde_json::Value {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/mint-discharge-vectors.json"
        );
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn rw_self_discharge_request_is_accepted_by_coord_b() {
        use ed25519_dalek::SigningKey;
        use elide_attestation::{DischargeRequest, DischargeState, put_object};
        use elide_core::config::VolumeConfig;
        use elide_core::name_record::NameRecord;
        use elide_core::signing::encode_hex;
        use elide_core::store_keys::meta_pub_key;
        use object_store::ObjectStore;
        use object_store::memory::InMemory;

        let v = discharge_vectors();
        let k_m_b: [u8; 32] = elide_core::signing::decode_hex(v["k_m_b"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let cid = elide_core::signing::decode_hex(v["cid"].as_str().unwrap()).unwrap();

        // --- coord A: own a live named volume with its volume.key on disk.
        let data_dir = tempfile::TempDir::new().unwrap();
        let owned = Ulid::new();
        let owned_sk = SigningKey::generate(&mut OsRng);
        let fork_dir = data_dir.path().join("by_id").join(owned.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        std::fs::write(
            fork_dir.join(elide_core::signing::VOLUME_KEY_FILE),
            owned_sk.to_bytes(),
        )
        .unwrap();
        VolumeConfig {
            name: Some("rw-vol".into()),
            ..Default::default()
        }
        .write(&fork_dir)
        .unwrap();

        let identity_dir = tempfile::TempDir::new().unwrap();
        let identity =
            Arc::new(CoordinatorIdentity::load_or_generate(identity_dir.path()).unwrap());
        let cfg = MintConfig {
            url: "unix:/tmp/unused.sock".into(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            attestation_location: Some("https://coord-b.example/v1/discharge".into()),
        };
        let endpoint = MintEndpoint::new(&cfg, data_dir.path().to_path_buf(), identity);

        // coord A builds exactly the JSON it would POST.
        let body = endpoint
            .build_discharge_request(owned, owned, &cid)
            .expect("build request");
        // Field-name / hex contract: coord A's body parses into coord B's
        // request struct with no remapping.
        let req: DischargeRequest = serde_json::from_str(&body).expect("contract: body shape");

        // --- coord B: a coord-ro store with owned's pub + a Live name claim.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        put_object(
            store.as_ref(),
            &meta_pub_key(owned),
            encode_hex(owned_sk.verifying_key().as_bytes()).into_bytes(),
        )
        .await
        .unwrap();
        let record = NameRecord::live_minimal(owned, 4 * 1024 * 1024 * 1024);
        put_object(
            store.as_ref(),
            "names/rw-vol",
            record.to_toml().unwrap().into_bytes(),
        )
        .await
        .unwrap();
        let state = DischargeState::new(k_m_b, store);

        let wire = state
            .discharge(req)
            .await
            .expect("coord B accepts coord A's rw-self request");
        assert!(wire.starts_with("mnt1_"), "discharge wire was {wire}");
    }

    #[tokio::test]
    async fn ro_ancestor_discharge_request_is_accepted_by_coord_b() {
        use ed25519_dalek::SigningKey;
        use elide_attestation::{DischargeRequest, DischargeState, put_object};
        use elide_core::config::VolumeConfig;
        use elide_core::name_record::NameRecord;
        use elide_core::signing::{
            ParentRef, ProvenanceLineage, VOLUME_PROVENANCE_FILE, encode_hex, write_provenance,
        };
        use elide_core::store_keys::{meta_provenance_key, meta_pub_key};
        use object_store::ObjectStore;
        use object_store::memory::InMemory;

        let v = discharge_vectors();
        let k_m_b: [u8; 32] = elide_core::signing::decode_hex(v["k_m_b"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let cid = elide_core::signing::decode_hex(v["cid_ro_ancestor"].as_str().unwrap()).unwrap();

        // --- coord A: own a live named fork of `parent`, key + name on disk.
        let data_dir = tempfile::TempDir::new().unwrap();
        let owned = Ulid::new();
        let parent = Ulid::new();
        let owned_sk = SigningKey::generate(&mut OsRng);
        let parent_sk = SigningKey::generate(&mut OsRng);
        let fork_dir = data_dir.path().join("by_id").join(owned.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        std::fs::write(
            fork_dir.join(elide_core::signing::VOLUME_KEY_FILE),
            owned_sk.to_bytes(),
        )
        .unwrap();
        VolumeConfig {
            name: Some("ro-vol".into()),
            ..Default::default()
        }
        .write(&fork_dir)
        .unwrap();

        let identity_dir = tempfile::TempDir::new().unwrap();
        let identity =
            Arc::new(CoordinatorIdentity::load_or_generate(identity_dir.path()).unwrap());
        let cfg = MintConfig {
            url: "unix:/tmp/unused.sock".into(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            attestation_location: Some("https://coord-b.example/v1/discharge".into()),
        };
        let endpoint = MintEndpoint::new(&cfg, data_dir.path().to_path_buf(), identity);

        // coord A builds exactly the JSON it would POST: target = the
        // fork's parent, anchored on owned.
        let body = endpoint
            .build_discharge_request(owned, parent, &cid)
            .expect("build request");
        let req: DischargeRequest = serde_json::from_str(&body).expect("contract: body shape");

        // --- coord B: owned's signed lineage (parent ref) + both pubs +
        // a Live name claim on a coord-ro store, so the read-set walk
        // resolves `parent` from `meta/*`.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let prov_dir = tempfile::TempDir::new().unwrap();
        write_provenance(
            prov_dir.path(),
            &owned_sk,
            VOLUME_PROVENANCE_FILE,
            &ProvenanceLineage {
                parent: Some(ParentRef {
                    volume_ulid: parent.to_string(),
                    snapshot_ulid: Ulid::new().to_string(),
                    pubkey: parent_sk.verifying_key().to_bytes(),
                }),
                extent_index: Vec::new(),
                oci_source: None,
            },
        )
        .unwrap();
        let prov = std::fs::read(prov_dir.path().join(VOLUME_PROVENANCE_FILE)).unwrap();
        put_object(store.as_ref(), &meta_provenance_key(owned), prov)
            .await
            .unwrap();
        put_object(
            store.as_ref(),
            &meta_pub_key(owned),
            encode_hex(owned_sk.verifying_key().as_bytes()).into_bytes(),
        )
        .await
        .unwrap();
        let parent_prov_dir = tempfile::TempDir::new().unwrap();
        write_provenance(
            parent_prov_dir.path(),
            &parent_sk,
            VOLUME_PROVENANCE_FILE,
            &ProvenanceLineage::default(),
        )
        .unwrap();
        let parent_prov =
            std::fs::read(parent_prov_dir.path().join(VOLUME_PROVENANCE_FILE)).unwrap();
        put_object(store.as_ref(), &meta_provenance_key(parent), parent_prov)
            .await
            .unwrap();
        put_object(
            store.as_ref(),
            &meta_pub_key(parent),
            encode_hex(parent_sk.verifying_key().as_bytes()).into_bytes(),
        )
        .await
        .unwrap();
        let record = NameRecord::live_minimal(owned, 4 * 1024 * 1024 * 1024);
        put_object(
            store.as_ref(),
            "names/ro-vol",
            record.to_toml().unwrap().into_bytes(),
        )
        .await
        .unwrap();
        let state = DischargeState::new(k_m_b, store);

        let wire = state
            .discharge(req)
            .await
            .expect("coord B accepts coord A's ro-ancestor request");
        assert!(wire.starts_with("mnt1_"), "discharge wire was {wire}");
    }
}
