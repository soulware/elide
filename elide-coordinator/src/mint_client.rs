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
use base64::engine::general_purpose::STANDARD as BASE64;
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

use crate::credential::{CredentialIssuer, Credentialer, IssuedCredentials};

/// Wire-format magic. v3 added a per-caveat type byte to the
/// serialised chain step so third-party caveats (carrying
/// `(location, VID, CID)`) can ride alongside first-party scalar
/// caveats (`mint/src/macaroon.rs`). The coordinator preserves
/// third-party caveats opaquely through decode → attenuate → encode;
/// it only ever appends first-party narrowing caveats, never TPCs
/// (only mint at issuance constructs those).
const MAGIC: &[u8; 5] = b"mcrn3";
const NONCE_LEN: usize = 16;

/// Per-step type tag in the wire format. Must match
/// `mint/src/macaroon.rs`.
const TYPE_FIRST_PARTY: u8 = 0;
const TYPE_THIRD_PARTY: u8 = 1;

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
const CAVEAT_VOLUME: &str = "elide:Volume";

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

/// Canonical per-caveat encoding fed into the MAC chain; the same
/// bytes appear on the wire so a decoded macaroon re-MACs identically
/// (`mint/src/macaroon.rs`).
fn serialize_one(c: &Caveat) -> Vec<u8> {
    match c {
        Caveat::FirstParty { name, value } => {
            let n = name.as_bytes();
            let v = value.as_bytes();
            let mut out = Vec::with_capacity(1 + 8 + n.len() + v.len());
            out.push(TYPE_FIRST_PARTY);
            out.extend_from_slice(&(n.len() as u32).to_be_bytes());
            out.extend_from_slice(n);
            out.extend_from_slice(&(v.len() as u32).to_be_bytes());
            out.extend_from_slice(v);
            out
        }
        Caveat::ThirdParty { location, vid, cid } => {
            let loc = location.as_bytes();
            let mut out = Vec::with_capacity(1 + 12 + loc.len() + vid.len() + cid.len());
            out.push(TYPE_THIRD_PARTY);
            out.extend_from_slice(&(loc.len() as u32).to_be_bytes());
            out.extend_from_slice(loc);
            out.extend_from_slice(&(vid.len() as u32).to_be_bytes());
            out.extend_from_slice(vid);
            out.extend_from_slice(&(cid.len() as u32).to_be_bytes());
            out.extend_from_slice(cid);
            out
        }
    }
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
        let buf = BASE64
            .decode(s.trim())
            .map_err(|_| io::Error::other("credential macaroon: base64 decode failed"))?;
        let mut pos = 0usize;
        let mut take = |n: usize| -> io::Result<&[u8]> {
            let end = pos
                .checked_add(n)
                .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
            let slice = buf
                .get(pos..end)
                .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
            pos = end;
            Ok(slice)
        };
        if take(MAGIC.len())? != MAGIC {
            return Err(io::Error::other("credential macaroon: bad magic"));
        }
        let kid = u16::from_be_bytes(
            take(2)?
                .try_into()
                .map_err(|_| io::Error::other("credential macaroon: truncated"))?,
        );
        let nonce: [u8; NONCE_LEN] = take(NONCE_LEN)?
            .try_into()
            .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
        let mac: [u8; 32] = take(32)?
            .try_into()
            .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
        let count = u16::from_be_bytes(
            take(2)?
                .try_into()
                .map_err(|_| io::Error::other("credential macaroon: truncated"))?,
        );
        let mut caveats = Vec::with_capacity(count as usize);
        for _ in 0..count {
            caveats.push(read_caveat(&buf, &mut pos)?);
        }
        if pos != buf.len() {
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

    pub(crate) fn encode(&self) -> String {
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&self.kid.to_be_bytes());
        buf.extend_from_slice(&self.nonce);
        buf.extend_from_slice(&self.mac);
        buf.extend_from_slice(&(self.caveats.len() as u16).to_be_bytes());
        for c in &self.caveats {
            buf.extend_from_slice(&serialize_one(c));
        }
        BASE64.encode(buf)
    }
}

fn read_bytes<'a>(buf: &'a [u8], pos: &mut usize) -> io::Result<&'a [u8]> {
    let lead = pos
        .checked_add(4)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
    let len_bytes: [u8; 4] = buf
        .get(*pos..lead)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?
        .try_into()
        .map_err(|_| io::Error::other("credential macaroon: truncated"))?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let end = lead
        .checked_add(len)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
    let out = buf
        .get(lead..end)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
    *pos = end;
    Ok(out)
}

fn read_string(buf: &[u8], pos: &mut usize) -> io::Result<String> {
    String::from_utf8(read_bytes(buf, pos)?.to_vec())
        .map_err(|_| io::Error::other("credential macaroon: caveat not utf-8"))
}

fn read_caveat(buf: &[u8], pos: &mut usize) -> io::Result<Caveat> {
    let tag = *buf
        .get(*pos)
        .ok_or_else(|| io::Error::other("credential macaroon: truncated"))?;
    *pos += 1;
    match tag {
        TYPE_FIRST_PARTY => {
            let name = read_string(buf, pos)?;
            let value = read_string(buf, pos)?;
            Ok(Caveat::FirstParty { name, value })
        }
        TYPE_THIRD_PARTY => {
            let location = read_string(buf, pos)?;
            let vid = read_bytes(buf, pos)?.to_vec();
            let cid = read_bytes(buf, pos)?.to_vec();
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
}

impl MintEndpoint {
    pub fn new(cfg: &MintConfig, data_dir: PathBuf, identity: Arc<CoordinatorIdentity>) -> Self {
        Self {
            url: cfg.url.clone(),
            connect_timeout: cfg.connect_timeout,
            request_timeout: cfg.request_timeout,
            data_dir,
            identity,
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
    pub async fn assume_role(
        &self,
        role: &str,
        ttl_secs: u64,
        narrowing: &[(&str, &str)],
        extra_body: &[(&str, serde_json::Value)],
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
            // `exp`. Bound it, then apply any role-specific narrowing.
            mac.attenuate(CAVEAT_EXP, &exp.to_string());
            for (n, v) in narrowing {
                mac.attenuate(n, v);
            }

            // Build the exact body bytes once: they are both signed
            // (via BLAKE3(body)) and sent. Mint hashes the raw bytes
            // before parsing, so no canonicalization step may sit
            // between.
            let mut obj = serde_json::Map::new();
            obj.insert("ts".into(), now.into());
            obj.insert("role".into(), role.into());
            obj.insert("ttl_seconds".into(), ttl_secs.into());
            for (k, v) in extra_body {
                obj.insert((*k).to_owned(), v.clone());
            }
            let body = serde_json::Value::Object(obj).to_string();

            let sig = BASE64.encode(self.identity.sign(&pop_digest(mac.tail(), body.as_bytes())));
            let auth = format!("Macaroon {}", mac.encode());

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
            match self.assume_role(role, ttl_secs, &[], &[]).await {
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
        vol_ulid: Ulid,
        ancestors: &[Ulid],
    ) -> io::Result<IssuedCredentials> {
        let ancestor_strs: Vec<String> = ancestors.iter().map(Ulid::to_string).collect();
        self.endpoint
            .assume_role(
                ROLE_VOLUME_RO,
                VOLUME_RO_TTL_SECS,
                &[(CAVEAT_VOLUME, &vol_ulid.to_string())],
                &[("ancestors", serde_json::json!(ancestor_strs))],
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

/// `CredentialIssuer` wrapper that resolves the volume's ancestor
/// chain from local provenance and delegates to a [`Credentialer`].
/// Mirrors the in-process iam issuer so the inbound `credentials`
/// handshake is identical regardless of backend.
pub struct MintCredentialIssuer {
    credentialer: Arc<dyn Credentialer>,
    data_dir: PathBuf,
}

impl MintCredentialIssuer {
    pub fn new(credentialer: Arc<dyn Credentialer>, data_dir: PathBuf) -> Self {
        Self {
            credentialer,
            data_dir,
        }
    }
}

#[async_trait]
impl CredentialIssuer for MintCredentialIssuer {
    async fn issue(
        &self,
        volume_id: elide_coordinator::macaroon::Verified<Ulid>,
    ) -> io::Result<IssuedCredentials> {
        let vol_ulid = volume_id.copy_inner();
        let by_id_dir = self.data_dir.join("by_id");
        let fork_dir = by_id_dir.join(vol_ulid.to_string());
        let ancestors = elide_core::volume::lineage_ulids(&fork_dir, &by_id_dir)
            .map_err(|e| io::Error::other(format!("loading ancestor chain: {e}")))?;
        self.credentialer
            .provision_volume_ro(vol_ulid, &ancestors)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a wire macaroon the way `mint/src/macaroon.rs` does, so
    /// the coordinator's decode/attenuate/encode is checked against the
    /// real construction without depending on the mint crate. Mirrors
    /// the v3 wire format: per-caveat type byte + length-prefixed
    /// fields, kid bound into the MAC seed.
    fn mint_like(
        root: &[u8; 32],
        kid: u16,
        nonce: [u8; NONCE_LEN],
        caveats: &[(&str, &str)],
    ) -> String {
        let cs: Vec<Caveat> = caveats.iter().map(|(n, v)| first_party(*n, *v)).collect();
        const DOMAIN: &[u8] = b"mint-macaroon-v3";
        let mut seed_msg = Vec::new();
        seed_msg.extend_from_slice(DOMAIN);
        seed_msg.extend_from_slice(&kid.to_be_bytes());
        seed_msg.extend_from_slice(&nonce);
        let mut key = *blake3::keyed_hash(root, &seed_msg).as_bytes();
        for c in &cs {
            key = *blake3::keyed_hash(&key, &serialize_one(c)).as_bytes();
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(MAGIC);
        buf.extend_from_slice(&kid.to_be_bytes());
        buf.extend_from_slice(&nonce);
        buf.extend_from_slice(&key);
        buf.extend_from_slice(&(cs.len() as u16).to_be_bytes());
        for c in &cs {
            buf.extend_from_slice(&serialize_one(c));
        }
        BASE64.encode(buf)
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
}
