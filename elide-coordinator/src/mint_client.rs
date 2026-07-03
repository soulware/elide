//! mint credential-service client (`docs/design/mint.md`
//! § "Coordinator configuration").
//!
//! The coordinator holds a capability macaroon under
//! `<data_dir>/credentials/<role>` for coordinator roles, or
//! `<data_dir>/credentials/<role>/<volume>` for attested volume roles —
//! the volume is baked into the credential as `caveat.volume` at
//! `exchange-finalize`, so a volume credential is per-volume.
//! `assume-role` is a pure render: it attenuates the stored macaroon
//! with the bounding `exp`, proves possession with an Ed25519 signature
//! by `coordinator.key` over `BLAKE3(macaroon-tail ‖ BLAKE3(request-body))`,
//! and POSTs it. Scoping rides the credential's baked caveats, not the
//! request body or an attached discharge.
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
/// `mint::macaroon::WIRE_PREFIX`. `mnt2` = mint macaroon, wire
/// generation 2.
const WIRE_PREFIX: &str = "mnt2_";
const NONCE_LEN: usize = 16;

/// Per-step type tag in the canonical MsgPack encoding (first element
/// of every caveat array). Must match `mint/src/macaroon.rs`.
const TYPE_FIRST_PARTY: u64 = 0;
const TYPE_THIRD_PARTY: u64 = 1;

/// Canonical mint role inventory — the single source of truth shared by
/// the enrollment fan-out (`crate::enroll`), the `[mint]` startup gate,
/// and the scoped stores (`crate::mint_stores`), so the three can never
/// drift. The volume roles are attested: their credentials are minted
/// per-volume at `exchange-finalize` (the volume baked in as
/// `caveat.volume`), not once at enrollment.
pub(crate) const ROLE_COORD_RO: &str = "coord-ro";
pub(crate) const ROLE_COORD_RW: &str = "coord-rw";
pub(crate) const ROLE_VOLUME_RW: &str = "volume-rw";
pub(crate) const ROLE_VOLUME_RO: &str = "volume-ro";
/// The read-only attestation authority's role — `coord-ro` narrowed to the
/// discharge predicate's exact read set (`GetObject` on `meta/*` + `names/*`).
pub(crate) const ROLE_ATTEST_RO: &str = "attest-ro";

/// Filename of the durable, volume-parametric enrollment *intermediate*
/// stored under an attested role's directory
/// (`credentials/<role>/_intermediate`). It is the `op=exchange-finalize`
/// token exchanged once at enrollment (operator-gated) and finalized
/// per-volume at runtime ([`MintEndpoint::assume_role`]'s finalize-on-miss),
/// which writes the rendered per-volume credential alongside it at
/// `credentials/<role>/<volume>`. Lowercase, so it can never collide with a
/// volume ULID (uppercase Crockford base32).
pub(crate) const INTERMEDIATE_FILE: &str = "_intermediate";

const CAVEAT_EXP: &str = "exp";

/// What an `assume-role` is for — the volume the credential is scoped to
/// plus the attestation anchor, made structural so the per-volume mint
/// decision is a property of the variant, not a role-string comparison
/// at the call site.
#[derive(Clone, Copy, Debug)]
pub(crate) enum AssumeTarget {
    /// Coordinator-wide roles (`coord-ro` / `coord-rw`): no volume, no
    /// attestation.
    Coord,
    /// `volume-rw`: the volume is both the possession-proven anchor
    /// and the vouched target (`volume-rw`).
    VolumeRw(Ulid),
    /// `volume-ro`: read `target`'s prefix, anchored on the live,
    /// locally-keyed `owned` whose key signs the possession proof
    /// (`volume-ro`; `target == owned` is the leaf reading its own
    /// prefix). `owned` is read only when minting a credential (via
    /// [`AssumeTarget::attestation`]), not when rendering one.
    VolumeRo { owned: Ulid, target: Ulid },
}

impl AssumeTarget {
    /// The volume a credential for this target is scoped to — the value
    /// mint bakes in as `caveat.volume` at `exchange-finalize`. Keys the
    /// per-volume credential on disk; `None` for coord roles, which are
    /// one credential per role.
    pub(crate) fn volume(&self) -> Option<Ulid> {
        match self {
            AssumeTarget::Coord => None,
            AssumeTarget::VolumeRw(v) => Some(*v),
            AssumeTarget::VolumeRo { target, .. } => Some(*target),
        }
    }

    /// The `(owned, target)` pair a discharge attests, when this target
    /// carries an attestation TPC. `owned` anchors the possession proof;
    /// `target` is the vouched volume baked into the credential.
    pub(crate) fn attestation(&self) -> Option<(Ulid, Ulid)> {
        match self {
            AssumeTarget::Coord => None,
            AssumeTarget::VolumeRw(v) => Some((*v, *v)),
            AssumeTarget::VolumeRo { owned, target } => Some((*owned, *target)),
        }
    }
}

/// Lifetime requested for a `volume-ro` credential. Set to 1h: the
/// non-lazy fetch episode completes in seconds, and the lazy-volume
/// cache refreshes proactively at half-life (`docs/design/mint.md`
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
/// key, so it neither mints nor verifies. The keyref (which key roots
/// the chain — `[0, kid]` for a keyring credential, `[1]` for a
/// discharge) is preserved opaquely through the round-trip so
/// re-encoded bytes match what mint will accept (the keyref is part of
/// the MAC seed, not the wire-level chain extension — so attenuation
/// doesn't touch it).
pub(crate) struct WireMacaroon {
    key_ref: Vec<u64>,
    nonce: [u8; NONCE_LEN],
    caveats: Vec<Caveat>,
    // Held as blake3::Hash so tag comparison (`==`) is constant-time.
    mac: blake3::Hash,
}

impl WireMacaroon {
    pub(crate) fn decode(s: &str) -> io::Result<Self> {
        let body = s
            .trim()
            .strip_prefix(WIRE_PREFIX)
            .ok_or_else(|| io::Error::other("credential macaroon: missing mnt2_ prefix"))?;
        let buf = BASE64_URL
            .decode(body)
            .map_err(|_| io::Error::other("credential macaroon: base64url decode failed"))?;
        let mut r: &[u8] = &buf;

        let env_len = rmp::decode::read_array_len(&mut r)
            .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
        if env_len != 4 {
            return Err(io::Error::other("credential macaroon: envelope shape"));
        }
        let kr_len = rmp::decode::read_array_len(&mut r)
            .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
        if kr_len == 0 || kr_len > 8 {
            return Err(io::Error::other("credential macaroon: keyref shape"));
        }
        let mut key_ref = Vec::with_capacity(kr_len as usize);
        for _ in 0..kr_len {
            let v: u64 = rmp::decode::read_int(&mut r)
                .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
            key_ref.push(v);
        }
        let nonce = read_bin_fixed::<NONCE_LEN>(&mut r)?;
        let mac = blake3::Hash::from_bytes(read_bin_fixed::<32>(&mut r)?);
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
            key_ref,
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
        self.mac = blake3::keyed_hash(self.mac.as_bytes(), &step);
        self.caveats.push(c);
    }

    pub(crate) fn tail(&self) -> &[u8; 32] {
        self.mac.as_bytes()
    }

    /// The `(location, cid)` of the credential's sole third-party caveat —
    /// the attestation TPC coord B discharges. An attested role's
    /// `exchange-finalize` intermediate carries exactly one TPC (mint's
    /// `issuance::mint_intermediate`), so the discharge route is read from
    /// the caveat's own `location`, never from config. Fails closed unless
    /// exactly one is present, so a malformed intermediate cannot silently
    /// route the wrong caveat or skip attestation.
    pub(crate) fn attestation_third_party(&self) -> io::Result<(&str, &[u8])> {
        let mut tpcs = self.third_party_caveats();
        let first = tpcs
            .next()
            .ok_or_else(|| io::Error::other("intermediate carries no attestation caveat"))?;
        if tpcs.next().is_some() {
            return Err(io::Error::other(
                "intermediate carries multiple third-party caveats; expected exactly one",
            ));
        }
        Ok(first)
    }

    /// Every third-party caveat as `(location, cid)` — what a gate
    /// discharge fetch iterates (`crate::enroll`).
    pub(crate) fn third_party_caveats(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.caveats.iter().filter_map(|c| match c {
            Caveat::ThirdParty { location, cid, .. } => Some((location.as_str(), cid.as_slice())),
            _ => None,
        })
    }

    /// Every first-party caveat as `(name, value)`.
    pub(crate) fn first_party_caveats(&self) -> impl Iterator<Item = (&str, &str)> {
        self.caveats.iter().filter_map(|c| match c {
            Caveat::FirstParty { name, value } => Some((name.as_str(), value.as_str())),
            _ => None,
        })
    }

    /// The value of the first-party caveat named `name`, if present. Used
    /// to read the anchor's `aud` so a self-issued discharge declares the
    /// same audience the primary clears under (`crate::enroll`).
    pub(crate) fn first_party_value(&self, name: &str) -> Option<&str> {
        self.caveats.iter().find_map(|c| match c {
            Caveat::FirstParty { name: n, value } if n == name => Some(value.as_str()),
            _ => None,
        })
    }

    pub(crate) fn encode(&self) -> String {
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 4).expect("vec writer");
        let kr_len: u32 = self
            .key_ref
            .len()
            .try_into()
            .expect("keyref length fits u32");
        rmp::encode::write_array_len(&mut buf, kr_len).expect("vec writer");
        for v in &self.key_ref {
            rmp::encode::write_uint(&mut buf, *v).expect("vec writer");
        }
        rmp::encode::write_bin(&mut buf, &self.nonce).expect("vec writer");
        rmp::encode::write_bin(&mut buf, self.mac.as_bytes()).expect("vec writer");
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
/// `docs/design/mint.md` § *Failure modes*); the HTTP-date form is
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
/// reference client makes (`docs/design/mint.md` § "Transport").
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

/// Map an `assume-role` HTTP status to an `io::ErrorKind`. A 401 is mint's
/// opaque "not validly enrolled" (de-authorized, revoked, cnf mismatch,
/// schema-stale record); `PermissionDenied` lets the readiness path stay
/// pending for a manual re-enroll instead of treating it as fatal. Every other
/// non-200 is an ordinary error.
fn assume_role_error_kind(status: u16) -> io::ErrorKind {
    if status == 401 {
        io::ErrorKind::PermissionDenied
    } else {
        io::ErrorKind::Other
    }
}

/// Whether a 503 body is mint's dormant `{"error":"not sealed"}` (as opposed to
/// a transient backend 503). The dormant case is waited out; a backend 503 is
/// retried then surfaced.
fn is_not_sealed(body: &str) -> bool {
    json_str_field(body, "error").is_ok_and(|e| e == "not sealed")
}

pub(crate) fn json_str_field(body: &str, key: &str) -> io::Result<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get(key).and_then(|s| s.as_str()).map(str::to_owned))
        .ok_or_else(|| io::Error::other(format!("mint response missing `{key}` field")))
}

/// Validate `credential` decodes, then write it `0600` to `path` (atomic
/// temp + rename), creating the parent directory if absent. Shared by
/// enrollment (`crate::enroll`) and the finalize-on-miss path.
pub(crate) fn write_credential_file(
    path: &std::path::Path,
    role: &str,
    credential: &str,
) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    WireMacaroon::decode(credential).map_err(|e| {
        io::Error::other(format!(
            "mint returned an undecodable {role} credential: {e}"
        ))
    })?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, credential.as_bytes())?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
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
    /// How to dial coord B when its sealed location is not the connection
    /// (`[mint] attestation_transport`); `None` dials the caveat's location.
    attestation_transport: Option<String>,
}

/// Resolve where a discharge POST goes: the route is always the
/// location's URL path (the location is the authority's *identity*);
/// the connection is `transport` when given — coord B off-network on a
/// UDS, or any dial target differing from the identity — else the
/// location minus its path.
fn discharge_dial<'a>(
    location: &'a str,
    transport: Option<&'a str>,
) -> io::Result<(&'a str, &'a str)> {
    let path = elide_coordinator::config::location_path(location).ok_or_else(|| {
        io::Error::other(format!(
            "attestation location carries no discharge route: {location}"
        ))
    })?;
    let base = match transport {
        Some(t) => t,
        None => &location[..location.len() - path.len()],
    };
    Ok((base, path))
}

impl MintEndpoint {
    pub fn new(cfg: &MintConfig, data_dir: PathBuf, identity: Arc<CoordinatorIdentity>) -> Self {
        Self {
            url: cfg.url.clone(),
            connect_timeout: cfg.connect_timeout,
            request_timeout: cfg.request_timeout,
            data_dir,
            identity,
            attestation_transport: cfg.attestation_transport.clone(),
        }
    }

    /// Load `credentials/<role>`, bound it to `ttl_secs` (`exp`
    /// caveat) plus any role-specific narrowing caveats, exercise it
    /// at `/v1/assume-role` with the `coordinator.key` PoP, and return
    /// the vended Tigris keypair. `extra_body` carries role-specific
    /// PoP-signed request fields (e.g. `volume-ro`'s `ancestors`).
    ///
    /// Transient `503` responses (mint's signal for Tigris-side
    /// throttling or backend unavailability, `docs/design/mint.md`
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
    /// own dir), and returns the `mnt2_` discharge to attach to the
    /// `assume-role` bundle. coord B authenticates the request by the
    /// possession proof in the body, not the mint PoP headers. Which
    /// `(owned, target)` shapes coord B accepts is the CID's baked
    /// `mode`: `volume-rw` requires `target == owned`; `volume-ro`
    /// requires `target` in `owned`'s read set.
    async fn fetch_attestation_discharge(
        &self,
        owned: Ulid,
        target: Ulid,
        cid: &[u8],
        location: &str,
    ) -> io::Result<String> {
        let body = self.build_discharge_request(owned, target, cid)?;

        // Route from the location, connection from the transport when
        // set; auth/PoP headers are unused by coord B and sent empty.
        let (base, path) = discharge_dial(location, self.attestation_transport.as_deref())?;
        let (status, text, _) = post(
            base,
            self.connect_timeout,
            self.request_timeout,
            path,
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
        let fork_dir = elide_coordinator::volume_state::fork_dir(&self.data_dir, owned);
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

    /// Finalize an attested role's short-lived `op=exchange-finalize`
    /// intermediate into the long-lived credential. The intermediate
    /// carries an undischarged attestation third-party caveat; this
    /// discharges it via coord B (vouching `target`, anchored on
    /// `owned`) and presents `intermediate,discharge` to
    /// `POST /v1/exchange-finalize`, which bakes the attested volume into
    /// the returned credential as an ordinary `caveat.volume`. The result
    /// is a bare primary — `assume-role` over it is a pure render.
    pub(crate) async fn finalize_volume(
        &self,
        owned: Ulid,
        target: Ulid,
        intermediate: &str,
    ) -> io::Result<String> {
        let mac = WireMacaroon::decode(intermediate)?;
        let (location, cid) = {
            let (loc, cid) = mac.attestation_third_party()?;
            (loc.to_owned(), cid.to_vec())
        };
        let discharge = self
            .fetch_attestation_discharge(owned, target, &cid, &location)
            .await?;

        let body = format!(r#"{{"ts":{}}}"#, now_unix()?);
        let sig = BASE64.encode(self.identity.sign(&pop_digest(mac.tail(), body.as_bytes())));
        let auth = format!("MintV1 {},{}", mac.encode(), discharge);
        let (status, text, _) = post(
            &self.url,
            self.connect_timeout,
            self.request_timeout,
            "/v1/exchange-finalize",
            &auth,
            &sig,
            body,
        )
        .await?;
        if status != 200 {
            let snippet: String = text.chars().take(200).collect();
            return Err(io::Error::other(format!(
                "mint /v1/exchange-finalize returned {status}: {snippet}"
            )));
        }
        json_str_field(&text, "credential")
    }

    /// Finalize the per-volume credential for an attested `target` from the
    /// durable enrollment intermediate (`credentials/<role>/_intermediate`)
    /// and persist it `0600` at `cred_path`, returning the rendered
    /// credential string.
    ///
    /// The intermediate is the `op=exchange-finalize` token exchanged once at
    /// enrollment; [`Self::finalize_volume`] discharges its attestation TPC
    /// via coord B (vouching the volume, anchored on `owned`) and bakes the
    /// volume in. Called on the first `assume-role` for a volume that has no
    /// stored credential yet; every later `assume-role` reads the file this
    /// writes and is a pure render.
    async fn finalize_volume_credential(
        &self,
        role: &str,
        target: AssumeTarget,
        cred_path: &std::path::Path,
    ) -> io::Result<String> {
        let (owned, vouched) = target
            .attestation()
            .ok_or_else(|| io::Error::other(format!("{role} is not an attested volume role")))?;
        let intermediate_path = self
            .data_dir
            .join("credentials")
            .join(role)
            .join(INTERMEDIATE_FILE);
        let intermediate = std::fs::read_to_string(&intermediate_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "reading {role} enrollment intermediate at {}: {e} (run `elide coord enroll`)",
                    intermediate_path.display()
                ),
            )
        })?;
        let credential = self
            .finalize_volume(owned, vouched, intermediate.trim())
            .await?;
        write_credential_file(cred_path, role, &credential)?;
        Ok(credential)
    }

    /// On-disk location of the stored credential for `(role, target)`.
    /// Coord roles store one credential per role; attested roles store
    /// one per baked volume (the volume is finalized into the credential
    /// at `exchange-finalize`, so a credential is per-volume).
    fn credential_path(&self, role: &str, target: AssumeTarget) -> std::path::PathBuf {
        let base = self.data_dir.join("credentials").join(role);
        match target.volume() {
            Some(v) => base.join(v.to_string()),
            None => base,
        }
    }

    /// The stored credential's first-party caveats rendered as
    /// space-separated `name=value` pairs — the scope mint baked in at
    /// enrollment/finalize (`sub`, `aud`, `volume`, …), for the assume
    /// log line. `cnf` is skipped (a base64 key-confirmation blob).
    /// `None` when the credential is absent or undecodable.
    pub(crate) fn credential_scope(&self, role: &str, target: AssumeTarget) -> Option<String> {
        let stored = std::fs::read_to_string(self.credential_path(role, target)).ok()?;
        let mac = WireMacaroon::decode(&stored).ok()?;
        let parts: Vec<String> = mac
            .first_party_caveats()
            .filter(|(name, _)| *name != "cnf")
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        (!parts.is_empty()).then(|| parts.join(" "))
    }

    pub async fn assume_role(
        &self,
        role: &str,
        ttl_secs: u64,
        target: AssumeTarget,
    ) -> io::Result<IssuedCredentials> {
        let cred_path = self.credential_path(role, target);
        let stored = match std::fs::read_to_string(&cred_path) {
            Ok(s) => s,
            // An attested volume role's per-volume credential is finalized
            // on first use from the durable enrollment intermediate, then
            // stored so every later assume-role is a pure render. A coord
            // role has no intermediate, so a missing file there is an
            // un-enrolled coordinator, not a finalize trigger.
            Err(e) if e.kind() == io::ErrorKind::NotFound && target.attestation().is_some() => {
                self.finalize_volume_credential(role, target, &cred_path)
                    .await?
            }
            Err(e) => {
                return Err(io::Error::new(
                    e.kind(),
                    format!(
                        "reading {role} credential at {}: {e} (run enrollment for this role)",
                        cred_path.display()
                    ),
                ));
            }
        };

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
            // between. Scoping is baked into the credential's caveats at
            // exchange-finalize and the lifetime is the role's sealed
            // `ttl_seconds` clamped to the `exp` attenuated above, so the
            // body carries only `ts`/`role` — the only fields mint reads.
            let mut obj = serde_json::Map::new();
            obj.insert("ts".into(), now.into());
            obj.insert("role".into(), role.into());
            let body = serde_json::Value::Object(obj).to_string();

            let sig = BASE64.encode(self.identity.sign(&pop_digest(mac.tail(), body.as_bytes())));
            // The credential is a bare primary — any attestation was
            // discharged and baked in at exchange-finalize, so assume-role
            // is a pure render with no discharge attached.
            let auth = format!("MintV1 {}", mac.encode());

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
            // A 503 "not sealed" means mint is up but dormant (no template
            // seal). That clears only when an operator seals, not on its own,
            // so don't spend the bounded backend-retry budget — surface it as
            // `WouldBlock` so the readiness probe waits it out. A sustained
            // *backend* 503 still exhausts the budget below and stays fatal.
            if status == 503 && is_not_sealed(&text) {
                let msg = format!("mint assume-role for {role} returned 503: {snippet}");
                return Err(io::Error::new(io::ErrorKind::WouldBlock, msg));
            }
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
            let msg = format!("mint assume-role for {role} returned {status}: {snippet}");
            return Err(io::Error::new(assume_role_error_kind(status), msg));
        };

        let access_key_id = json_str_field(&text, "access_key_id")?;
        let secret_access_key = json_str_field(&text, "secret_access_key")?;
        // The credential's lifetime is the `exp` we attenuated onto the
        // macaroon: mint clamps the issued key to it (and to the role's
        // sealed ceiling), so it is the authoritative upper bound.
        Ok(IssuedCredentials {
            access_key_id,
            secret_access_key,
            session_token: None,
            expiry_unix: Some(exp),
        })
    }

    /// Block until the mint endpoint accepts an `assume-role` for
    /// `role`. Retries indefinitely with exponential backoff (100ms →
    /// 5s cap) while mint is unreachable (connect/timeout) or dormant
    /// (503 "not sealed"). A 401 surfaces as `PermissionDenied` for the
    /// caller to handle (the held enrollment is invalid); any other
    /// error (sustained backend 503, missing credential file, decode
    /// failure, etc.) is fatal. The vended credentials are discarded —
    /// this is a readiness probe; the real first use during normal
    /// operation will re-assume and cache.
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
                // 503 "not sealed": mint is up but dormant. It becomes ready
                // only when an operator seals, so wait it out like a not-yet-up
                // mint rather than fail (a sustained backend 503 surfaces as a
                // fatal error instead, having exhausted `assume_role`'s budget).
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if attempt == 1 || attempt.is_multiple_of(10) {
                        warn!(
                            "[coordinator] mint is dormant (not sealed); \
                             waiting for `mint seal` (attempt {attempt})"
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
                AssumeTarget::VolumeRo { owned, target },
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

    #[test]
    fn assume_role_401_is_permission_denied_others_are_other() {
        assert_eq!(
            assume_role_error_kind(401),
            io::ErrorKind::PermissionDenied,
            "401 must be PermissionDenied so the readiness loop stays pending for re-enroll"
        );
        for status in [400, 403, 500, 503] {
            assert_eq!(
                assume_role_error_kind(status),
                io::ErrorKind::Other,
                "{status} must stay an ordinary error, not trip the re-enroll path"
            );
        }
    }

    #[test]
    fn is_not_sealed_only_matches_the_dormant_body() {
        assert!(is_not_sealed(r#"{"error":"not sealed"}"#));
        assert!(!is_not_sealed(r#"{"error":"unavailable"}"#));
        assert!(!is_not_sealed(r#"{"error":"unauthorized"}"#));
        assert!(!is_not_sealed("Service Unavailable"));
        assert!(!is_not_sealed(""));
    }

    /// Build a wire macaroon the way `mint/src/macaroon.rs` does, so
    /// the coordinator's decode/attenuate/encode is checked against the
    /// real construction without depending on the mint crate. Mirrors
    /// the v6 wire format: canonical MsgPack envelope with a keyring
    /// keyref, base64url-no-pad encoded, `mnt2_` prefix.
    fn mint_like(
        root: &[u8; 32],
        kid: u16,
        nonce: [u8; NONCE_LEN],
        caveats: &[(&str, &str)],
    ) -> String {
        let cs: Vec<Caveat> = caveats.iter().map(|(n, v)| first_party(*n, *v)).collect();
        const DOMAIN: &[u8] = b"mint-macaroon-v6";
        let mut kr_bytes = Vec::new();
        rmp::encode::write_array_len(&mut kr_bytes, 2).unwrap();
        rmp::encode::write_uint(&mut kr_bytes, 0).unwrap();
        rmp::encode::write_uint(&mut kr_bytes, kid as u64).unwrap();
        let mut seed_msg = Vec::new();
        seed_msg.extend_from_slice(DOMAIN);
        seed_msg.extend_from_slice(&kr_bytes);
        seed_msg.extend_from_slice(&nonce);
        let mut key = blake3::keyed_hash(root, &seed_msg);
        for c in &cs {
            key = blake3::keyed_hash(key.as_bytes(), &serialize_one(c));
        }
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 4).unwrap();
        buf.extend_from_slice(&kr_bytes);
        rmp::encode::write_bin(&mut buf, &nonce).unwrap();
        rmp::encode::write_bin(&mut buf, key.as_bytes()).unwrap();
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
        assert_eq!(m.key_ref, vec![0, 0]);
        assert_eq!(m.encode(), wire);
    }

    #[test]
    fn key_ref_is_preserved_through_roundtrip() {
        // Coordinator never minted, never verifies, never rotates —
        // its only obligation is to hand back the keyref bytes it
        // received so mint's verifier picks the same key.
        let wire = mint_like(&[7u8; 32], 5, [3u8; NONCE_LEN], &[("aud", "mint")]);
        let m = WireMacaroon::decode(&wire).expect("decode");
        assert_eq!(m.key_ref, vec![0, 5]);
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
    fn credential_scope_renders_first_party_caveats_skipping_cnf() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let identity = Arc::new(
            CoordinatorIdentity::load_or_generate(tmp.path()).expect("identity load_or_generate"),
        );
        let cfg = MintConfig {
            url: "unix:/tmp/elide-mint-test.sock".to_owned(),
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
            attestation_transport: None,
        };
        let endpoint = MintEndpoint::new(&cfg, tmp.path().to_path_buf(), identity);

        let wire = mint_like(
            &[7u8; 32],
            0,
            [3u8; NONCE_LEN],
            &[
                ("sub", "01ARZ3NDEKTSV4RRFFQ69G5FAV"),
                ("cnf", "a2V5YmxvYg"),
                ("aud", "mint"),
            ],
        );
        let creds_dir = tmp.path().join("credentials");
        std::fs::create_dir_all(&creds_dir).expect("mkdir credentials");
        std::fs::write(creds_dir.join("attest-ro"), wire).expect("write credential");

        assert_eq!(
            endpoint
                .credential_scope("attest-ro", AssumeTarget::Coord)
                .as_deref(),
            Some("sub=01ARZ3NDEKTSV4RRFFQ69G5FAV aud=mint"),
            "caveats render in chain order with cnf elided"
        );
        assert_eq!(
            endpoint.credential_scope("coord-ro", AssumeTarget::Coord),
            None,
            "absent credential renders no scope"
        );
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
    fn discharge_dial_routes_from_the_location() {
        // No transport: the location is the connection, split into the
        // base post() re-joins with the path.
        assert_eq!(
            discharge_dial("https://coord-b.example/v1/discharge", None).unwrap(),
            ("https://coord-b.example", "/v1/discharge")
        );
        // Transport set: the location is identity only; the connection
        // is whatever the transport says — the off-network UDS shape.
        assert_eq!(
            discharge_dial(
                "https://coord-b.example/v1/discharge",
                Some("unix:/run/elide/coord-b.sock")
            )
            .unwrap(),
            ("unix:/run/elide/coord-b.sock", "/v1/discharge")
        );
        // A routeless location cannot be dialled under any transport.
        assert!(discharge_dial("https://coord-b.example", None).is_err());
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
    fn attestation_third_party_takes_the_sole_caveat() {
        // An attested role's exchange-finalize intermediate carries exactly
        // one third-party caveat — the attestation TPC — so coord A reads its
        // location from the caveat, never from config.
        let mac = |caveats| WireMacaroon {
            key_ref: vec![0, 0],
            nonce: [0u8; NONCE_LEN],
            mac: blake3::Hash::from_bytes([0u8; 32]),
            caveats,
        };
        let coord_b = || Caveat::ThirdParty {
            location: "https://coord-b.example/v1/discharge".into(),
            vid: vec![1, 1],
            cid: vec![9, 9, 9, 9],
        };

        assert_eq!(
            mac(vec![first_party("aud", "mint"), coord_b()])
                .attestation_third_party()
                .unwrap(),
            ("https://coord-b.example/v1/discharge", &[9u8, 9, 9, 9][..])
        );

        // Zero or several TPCs fail closed rather than guess which to route.
        assert!(
            mac(vec![first_party("aud", "mint")])
                .attestation_third_party()
                .is_err()
        );
        let auth = Caveat::ThirdParty {
            location: "https://auth.example/v1/discharge".into(),
            vid: vec![3, 3],
            cid: vec![7, 7, 7],
        };
        assert!(
            mac(vec![auth, coord_b()])
                .attestation_third_party()
                .is_err()
        );
    }

    /// The shared cross-implementation fixture (canonical volume-rw CID under
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
    async fn volume_rw_discharge_request_is_accepted_by_coord_b() {
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
            attestation_transport: None,
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
            .expect("coord B accepts coord A's volume-rw request");
        assert!(wire.starts_with("mnt2_"), "discharge wire was {wire}");
    }

    #[tokio::test]
    async fn volume_ro_discharge_request_is_accepted_by_coord_b() {
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
        let cid = elide_core::signing::decode_hex(v["cid_volume_ro"].as_str().unwrap()).unwrap();

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
            attestation_transport: None,
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
            &ProvenanceLineage::fork(ParentRef {
                volume_ulid: parent.to_string(),
                snapshot_ulid: Ulid::new().to_string(),
                pubkey: parent_sk.verifying_key().to_bytes(),
            }),
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
            .expect("coord B accepts coord A's volume-ro request");
        assert!(wire.starts_with("mnt2_"), "discharge wire was {wire}");
    }
}
