//! Coordinator-side mint enrollment
//! (`docs/plans/coordinator-mint-enrollment-plan-v2.md`).
//!
//! One blocking operator command: `POST /v1/enroll` (A), wait while the
//! operator approves out of band (B), then exchange the ticket once per
//! role (C). A coord role's credential is written to
//! `<data_dir>/credentials/<role>`; an attested volume role's durable,
//! volume-parametric intermediate to
//! `<data_dir>/credentials/<role>/_intermediate` (finalized per-volume at
//! runtime — `crate::mint_client`). The credential ticket lives in memory
//! for the command's duration and never touches disk — those files are the
//! only durable enrollment artifacts.
//!
//! A and C are operator-gated: the invite and the ticket each carry a
//! third-party caveat keyed by the auth service, so the command fetches
//! an operator discharge for each presentation (`mint:enroll` /
//! `mint:exchange` scope) using the logged-in operator's session and
//! bundles it after the primary. Discharges are short-lived and held
//! only in memory; one exchange discharge covers every role in a pass.
//!
//! Because the command holds the invite macaroon for its whole
//! duration it self-heals the ticket-expiry race: if the short-lived
//! ticket expires before approval lands it transparently re-enrolls
//! (the operator must then re-approve, since mint GC's the pending
//! record at the ticket `exp`).
//!
//! The macaroon / PoP / transport primitives are reused from
//! `crate::mint_client` (reimplemented there against the spec, no mint
//! dependency — the same deliberate duplication).

use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use tracing::{info, warn};

use elide_attestation::crypto::{decrypt_cid, mint_discharge_with_nonce, ticket_id};
use elide_coordinator::config::MintConfig;
use elide_coordinator::identity::CoordinatorIdentity;

use crate::mint_client::{
    AssumeTarget, INTERMEDIATE_FILE, MintEndpoint, ROLE_ATTEST_RO, ROLE_COORD_RO, ROLE_COORD_RW,
    ROLE_VOLUME_RO, ROLE_VOLUME_RW, WireMacaroon, json_str_field, now_unix, pop_digest, post,
    write_credential_file,
};

const CAVEAT_SUB: &str = "sub";
const CAVEAT_CNF: &str = "cnf";

/// Operator-discharge scopes for the two coordinator-presented
/// enrollment gates (`mint/src/caveat.rs::scope` — reimplemented
/// constants, same deliberate duplication as the wire format).
const SCOPE_ENROLL: &str = "mint:enroll";
const SCOPE_EXCHANGE: &str = "mint:exchange";

/// How often to re-attempt the exchange while awaiting operator
/// approval. Foreground operator command — a short, predictable cadence
/// the operator can watch, not a cache-driven one.
const POLL_INTERVAL: Duration = Duration::from_secs(3);

/// TTL for the validity probe assume-role taken when all artifacts are
/// already present. The vended credential is discarded, so the value only
/// has to clear mint's lower bound.
const ENROLL_PROBE_TTL_SECS: u64 = 300;

/// `ed25519:<base64 pub>` — the `cnf` value mint seals into the ticket
/// and verifies the PoP against (`mint/src/pop.rs::cnf_value`).
fn cnf_value(identity: &CoordinatorIdentity) -> String {
    format!(
        "ed25519:{}",
        BASE64.encode(identity.verifying_key().to_bytes())
    )
}

/// Stable short fingerprint of a `cnf` value: BLAKE3 of the raw string,
/// first 8 bytes hex. Byte-identical to what `mint enroll list` prints
/// (`mint/src/state.rs::fingerprint`), so the operator can compare the
/// two out of band before approving.
fn fingerprint(cnf: &str) -> String {
    blake3::hash(cnf.as_bytes()).as_bytes()[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn credentials_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("credentials")
}

/// What enrollment provisions, in fan-out order. Every entry is exchanged
/// the same way at `/v1/enroll-exchange` (operator-gated); only where the
/// result is stored differs, driven by the role's own attestation contract.
struct EnrollRole {
    name: &'static str,
    /// `true` for an attested volume role: the exchange yields a durable,
    /// volume-parametric *intermediate* stored at
    /// `credentials/<role>/_intermediate` and finalized per-volume at
    /// runtime. `false` for a coord role: a directly-assumable credential at
    /// `credentials/<role>`.
    intermediate: bool,
}

const COORDINATOR_ROLES: &[EnrollRole] = &[
    EnrollRole {
        name: ROLE_COORD_RO,
        intermediate: false,
    },
    EnrollRole {
        name: ROLE_COORD_RW,
        intermediate: false,
    },
    EnrollRole {
        name: ROLE_VOLUME_RW,
        intermediate: true,
    },
    EnrollRole {
        name: ROLE_VOLUME_RO,
        intermediate: true,
    },
];

/// A read-only attestation authority (coord B) holds only `attest-ro`, the
/// discharge predicate's exact read set (`docs/design/mint-volume-attestation.md`
/// § *Attestation-profile enrollment*).
const ATTESTATION_ROLES: &[EnrollRole] = &[EnrollRole {
    name: ROLE_ATTEST_RO,
    intermediate: false,
}];

/// The enrollment profile, declared by the enrollee in the `/v1/enroll`
/// body and bounding the role set it may exchange. mint maps the profile to
/// the same grant and enforces `role ∈ grant` at `enroll-exchange`
/// (`docs/attestation-readonly-enrollment-spec.md`).
#[derive(Clone, Copy)]
pub(crate) enum EnrollProfile {
    /// A full coordinator: the four coordinator roles.
    Coordinator,
    /// A read-only attestation authority: `attest-ro` only.
    Attestation,
}

impl EnrollProfile {
    /// The wire value for the `profile` field of the `/v1/enroll` body.
    fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Attestation => "attestation",
        }
    }

    /// The roles this profile provisions.
    fn roles(self) -> &'static [EnrollRole] {
        match self {
            Self::Coordinator => COORDINATOR_ROLES,
            Self::Attestation => ATTESTATION_ROLES,
        }
    }

    /// The directly-assumable read role used to probe enrollment validity:
    /// the first non-intermediate role (a coord role renders with no
    /// discharge; an intermediate can't be assumed without a volume target).
    fn probe_role(self) -> &'static str {
        self.roles()
            .iter()
            .find(|r| !r.intermediate)
            .map_or(ROLE_COORD_RO, |r| r.name)
    }
}

/// The behaviour knobs for an enrollment pass.
pub(crate) struct EnrollOptions {
    /// Overall bound on waiting for operator approval.
    pub wait: Duration,
    /// Re-exchange and overwrite every role, not just the missing ones.
    pub force: bool,
    /// The enrollment profile, bounding the role set.
    pub profile: EnrollProfile,
}

impl EnrollRole {
    /// Where this role's enrollment artifact lands. A coord role is the file
    /// `credentials/<role>`; an attested role's intermediate is
    /// `credentials/<role>/_intermediate` (the same directory the per-volume
    /// credentials finalize into).
    fn path(&self, data_dir: &Path) -> PathBuf {
        let base = credentials_dir(data_dir).join(self.name);
        if self.intermediate {
            base.join(INTERMEDIATE_FILE)
        } else {
            base
        }
    }
}

/// An enrollment artifact is present if it exists and decodes as a macaroon.
fn credential_present_at(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .ok()
        .is_some_and(|s| WireMacaroon::decode(s.trim()).is_ok())
}

/// Resolve the invite argument: `-` reads stdin, an inline macaroon
/// is used verbatim, anything else is a file path. Validated by a
/// decode at the boundary so a bad source fails here, not at the PoP.
fn resolve_invite(src: &str) -> io::Result<String> {
    let raw = if src == "-" {
        let mut s = String::new();
        io::stdin().read_to_string(&mut s)?;
        s
    } else if WireMacaroon::decode(src).is_ok() {
        src.to_owned()
    } else {
        std::fs::read_to_string(src).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "invite macaroon: {src:?} is neither an inline macaroon nor a readable file: {e}"
                ),
            )
        })?
    };
    let trimmed = raw.trim().to_owned();
    WireMacaroon::decode(&trimmed)
        .map_err(|e| io::Error::other(format!("invite macaroon failed to decode: {e}")))?;
    Ok(trimmed)
}

/// Discharge lifetime, matching mint's demo issuer
/// (`mint/src/auth.rs::DISCHARGE_EXP_SECONDS`).
const DISCHARGE_EXP_SECONDS: u64 = 300;

/// How enrollment acquires the operator discharge for a gate. Selected once
/// at config time, so [`run`]'s call site is identical regardless: the
/// shared-key demo self-issues ([`SelfMint`]); a standalone auth service
/// will fetch (a future `Fetch { url, session }` impl POSTing `(cid,
/// session)` to it). See `docs/design/auth-service.md` § *Proposed:
/// distributed demo — shared K_M-A*.
pub(crate) trait DischargeSource {
    /// The operator discharges for every third-party caveat on `anchor`, at
    /// gate `scope`, to bundle after the primary.
    async fn discharges(&self, anchor: &WireMacaroon, scope: &str) -> io::Result<Vec<String>>;
}

/// The shared-key demo source: hold the same `K_M-A` as mint and self-mint
/// the enroll/exchange-gate discharges, stamping the logged-in operator as
/// `sub` — no auth-service round-trip, the shared `K_M-A` is the trust
/// anchor. mint's verifier recovers `r` from the VID (not `K_M-A`), so a
/// coordinator-minted discharge is indistinguishable from a mint-as-auth one.
pub(crate) struct SelfMint {
    /// `K_M-A`, from `coordinator.toml [auth.demo]` — identical to mint's.
    pub k_m_a: [u8; 32],
    /// The logged-in operator subject (`elide login`), stamped as `sub`.
    pub subject: String,
}

impl DischargeSource for SelfMint {
    /// For each CID, recover `r` under the shared `K_M-A` and mint a
    /// discharge keyed by `r` carrying `(aud, sub, scope, exp)` —
    /// byte-for-byte what mint-as-auth would have issued.
    async fn discharges(&self, anchor: &WireMacaroon, scope: &str) -> io::Result<Vec<String>> {
        // The discharge declares the same audience the primary clears under.
        let aud = anchor.first_party_value("aud").ok_or_else(|| {
            io::Error::other(
                "enrollment anchor carries no `aud` caveat to mirror into the discharge",
            )
        })?;
        let exp = (now_unix()? + DISCHARGE_EXP_SECONDS).to_string();
        let mut discharges = Vec::new();
        for (_location, cid) in anchor.third_party_caveats() {
            let pt = decrypt_cid(&self.k_m_a, cid).map_err(|e| {
                io::Error::other(format!(
                    "{scope} gate CID failed to decrypt under [auth.demo].k_m_a — the \
                     coordinator's shared key does not match mint's: {e}"
                ))
            })?;
            discharges.push(mint_discharge_with_nonce(
                &pt.r,
                &ticket_id(cid),
                &[
                    ("aud", aud),
                    ("sub", self.subject.as_str()),
                    ("scope", scope),
                    ("exp", exp.as_str()),
                ],
            ));
        }
        Ok(discharges)
    }
}

/// `MintV1 <primary>[,<discharge>…]` — the bundle wire mint parses.
fn bundle_auth(primary: &WireMacaroon, discharges: &[String]) -> String {
    let mut auth = format!("MintV1 {}", primary.encode());
    for d in discharges {
        auth.push(',');
        auth.push_str(d);
    }
    auth
}

/// A — `POST /v1/enroll`. Attenuate the invite with `sub`/`cnf`,
/// discharge its enroll gate, PoP over `{ts, profile}`, return the
/// credential-ticket macaroon string. `profile` rides the PoP-signed body,
/// so the declared grant is bound to the enrollee.
async fn enroll_request(
    cfg: &MintConfig,
    identity: &CoordinatorIdentity,
    invite: &str,
    profile: EnrollProfile,
    source: &impl DischargeSource,
) -> io::Result<String> {
    let mut mac = WireMacaroon::decode(invite)?;
    mac.attenuate(CAVEAT_SUB, identity.coordinator_id_str());
    mac.attenuate(CAVEAT_CNF, &cnf_value(identity));
    let discharges = source.discharges(&mac, SCOPE_ENROLL).await?;

    let body = format!(
        r#"{{"ts":{},"profile":{}}}"#,
        now_unix()?,
        serde_json::Value::from(profile.as_str())
    );
    let sig = BASE64.encode(identity.sign(&pop_digest(mac.tail(), body.as_bytes())));
    let auth = bundle_auth(&mac, &discharges);

    let (status, text, _retry_after) = post(
        &cfg.url,
        cfg.connect_timeout,
        cfg.request_timeout,
        "/v1/enroll",
        &auth,
        &sig,
        body,
    )
    .await?;
    if status != 200 {
        let snippet: String = text.chars().take(200).collect();
        return Err(io::Error::other(format!(
            "mint /v1/enroll returned {status}: {snippet}"
        )));
    }
    json_str_field(&text, "credential.ticket")
}

enum ExchangeOutcome {
    Granted(String),
    AwaitingApproval,
    TicketExpired,
}

/// C (one role) — `POST /v1/enroll-exchange`, body `{ts, role}`, PoP
/// over it, the pass's exchange-gate discharges bundled after the
/// ticket. `200` → the credential; `403` → not yet approved; `401` →
/// ticket expired (the single command re-enrolls); anything else fails.
async fn exchange_request(
    cfg: &MintConfig,
    identity: &CoordinatorIdentity,
    ticket: &str,
    role: &str,
    discharges: &[String],
) -> io::Result<ExchangeOutcome> {
    let mac = WireMacaroon::decode(ticket)?;
    let body = format!(
        r#"{{"ts":{},"role":{}}}"#,
        now_unix()?,
        serde_json::Value::from(role)
    );
    let sig = BASE64.encode(identity.sign(&pop_digest(mac.tail(), body.as_bytes())));
    let auth = bundle_auth(&mac, discharges);

    let (status, text, _retry_after) = post(
        &cfg.url,
        cfg.connect_timeout,
        cfg.request_timeout,
        "/v1/enroll-exchange",
        &auth,
        &sig,
        body,
    )
    .await?;
    match status {
        200 => Ok(ExchangeOutcome::Granted(json_str_field(
            &text,
            "credential",
        )?)),
        403 => Ok(ExchangeOutcome::AwaitingApproval),
        401 => Ok(ExchangeOutcome::TicketExpired),
        s => {
            let snippet: String = text.chars().take(200).collect();
            Err(io::Error::other(format!(
                "mint /v1/enroll-exchange ({role}) returned {s}: {snippet}"
            )))
        }
    }
}

/// `[mint]` startup gate. Every enrollment artifact — each coord credential
/// and each attested role's volume intermediate — must exist and decode;
/// otherwise the daemon refuses to start half-enrolled. The intermediates are
/// required
/// because the mint-backed store finalizes per-volume credentials from them
/// at runtime; without them no `by_id/<vol>` op can proceed.
pub(crate) fn assert_enrolled(data_dir: &Path, profile: EnrollProfile) -> io::Result<()> {
    let missing: Vec<&str> = profile
        .roles()
        .iter()
        .filter(|r| !credential_present_at(&r.path(data_dir)))
        .map(|r| r.name)
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "[mint] is configured but enrollment artifact(s) for [{}] are missing or unreadable \
         under {}",
        missing.join(", "),
        credentials_dir(data_dir).display()
    )))
}

/// The single blocking operator command: A → wait for approval → C
/// fan-out over the kind's role set. Idempotent — only roles whose artifact is
/// absent (or all, under `force`) are (re-)exchanged; an already-complete
/// enrollment is a no-op. The ticket is held only for the command's duration
/// (the attested-role intermediates it mints are durable, so nothing needs it
/// after this returns).
pub(crate) async fn run<S: DischargeSource>(
    cfg: &MintConfig,
    identity: &Arc<CoordinatorIdentity>,
    data_dir: &Path,
    invite_src: &str,
    opts: EnrollOptions,
    source: &S,
) -> io::Result<()> {
    let mut remaining: Vec<&EnrollRole> = opts
        .profile
        .roles()
        .iter()
        .filter(|r| opts.force || !credential_present_at(&r.path(data_dir)))
        .collect();
    if remaining.is_empty() {
        // Presence isn't validity: a de-authorized enrollment leaves the
        // local artifacts in place but mint answers 401. Probe one
        // assume-role so this reports the truth instead of a false "nothing
        // to do" — on a 401 the operator must re-run with `--force`.
        let endpoint = MintEndpoint::new(cfg, data_dir.to_path_buf(), identity.clone());
        let count = opts.profile.roles().len();
        let dir = credentials_dir(data_dir);
        match endpoint
            .assume_role(
                opts.profile.probe_role(),
                ENROLL_PROBE_TTL_SECS,
                AssumeTarget::Coord,
            )
            .await
        {
            Ok(_) => {
                info!(
                    "[enroll] all {count} enrollment artifact(s) present under {} and accepted by mint; nothing to do",
                    dir.display()
                );
                return Ok(());
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "enrollment artifact(s) present under {} but mint rejected them as \
                         unauthorized ({e}); the enrollment was de-authorized — re-run with \
                         `--force` to re-enroll",
                        dir.display()
                    ),
                ));
            }
            Err(e) => {
                warn!(
                    "[enroll] all {count} artifact(s) present under {}, but could not verify with \
                     mint ({e}); leaving them in place",
                    dir.display()
                );
                return Ok(());
            }
        }
    }

    let invite = resolve_invite(invite_src)?;
    let sub = identity.coordinator_id_str();
    let cnf = cnf_value(identity);

    let mut ticket = enroll_request(cfg, identity, &invite, opts.profile, source).await?;
    info!(
        "[enroll] enrolled sub={sub} cnf-fingerprint={} — now run `mint enroll approve {sub}` \
         on the mint host (match that fingerprint out of band first)",
        fingerprint(&cnf)
    );
    info!(
        "[enroll] waiting for approval, exchanging {} role(s): [{}]",
        remaining.len(),
        remaining
            .iter()
            .map(|r| r.name)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let deadline = Instant::now() + opts.wait;
    loop {
        // One approval covers every role; the ticket is multi-use until
        // its `exp`, so on AwaitingApproval there is no point trying the
        // other roles this pass.
        let mut awaiting = false;
        // One exchange-gate discharge covers every role in the pass
        // (the auth scope is per-operation, not per-role); fetched per
        // pass so a long approval wait never presents a stale one.
        let ticket_mac = WireMacaroon::decode(&ticket)?;
        let discharges = source.discharges(&ticket_mac, SCOPE_EXCHANGE).await?;
        // Always process from the front: Granted removes the head;
        // AwaitingApproval / TicketExpired break the pass.
        let idx = 0;
        while idx < remaining.len() {
            let role = remaining[idx];
            match exchange_request(cfg, identity, &ticket, role.name, &discharges).await? {
                ExchangeOutcome::Granted(credential) => {
                    // A coord role's credential is directly assumable; an
                    // attested role's is the durable, volume-parametric
                    // intermediate finalized per-volume at runtime.
                    write_credential_file(&role.path(data_dir), role.name, &credential)?;
                    info!(
                        "[enroll] {}: {} written",
                        role.name,
                        if role.intermediate {
                            "volume intermediate"
                        } else {
                            "credential"
                        }
                    );
                    remaining.remove(idx);
                }
                ExchangeOutcome::AwaitingApproval => {
                    awaiting = true;
                    break;
                }
                ExchangeOutcome::TicketExpired => {
                    warn!(
                        "[enroll] credential ticket expired before approval; re-enrolling — \
                         the operator must re-run `mint enroll approve {sub}`"
                    );
                    ticket = enroll_request(cfg, identity, &invite, opts.profile, source).await?;
                    awaiting = true;
                    break;
                }
            }
        }

        if remaining.is_empty() {
            info!(
                "[enroll] complete: {} enrollment artifact(s) under {}",
                opts.profile.roles().len(),
                credentials_dir(data_dir).display()
            );
            return Ok(());
        }
        if !awaiting {
            continue;
        }
        if Instant::now() >= deadline {
            return Err(io::Error::other(format!(
                "timed out waiting for operator approval; [{}] still unenrolled. \
                 Approval persists — re-run `elide coord enroll` to resume",
                remaining
                    .iter()
                    .map(|r| r.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_matches_mint_algorithm() {
        // BLAKE3 of the raw cnf string, first 8 bytes hex.
        let cnf = "ed25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let expect: String = blake3::hash(cnf.as_bytes()).as_bytes()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(fingerprint(cnf), expect);
        assert_eq!(fingerprint(cnf).len(), 16);
    }

    #[test]
    fn resolve_invite_distinguishes_inline_file_and_garbage() {
        // A real wire macaroon, built the way mint mints one. v6
        // format: canonical-MsgPack envelope with a keyring keyref,
        // base64url-no-pad, mnt2_ prefix (`mint/src/macaroon.rs`).
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        let nonce = [5u8; 16];
        let root = [2u8; 32];
        let kid: u16 = 0;
        const DOMAIN: &[u8] = b"mint-macaroon-v6";
        let mut kr_bytes = Vec::new();
        rmp::encode::write_array_len(&mut kr_bytes, 2).unwrap();
        rmp::encode::write_uint(&mut kr_bytes, 0).unwrap();
        rmp::encode::write_uint(&mut kr_bytes, kid as u64).unwrap();
        let mut seed = Vec::new();
        seed.extend_from_slice(DOMAIN);
        seed.extend_from_slice(&kr_bytes);
        seed.extend_from_slice(&nonce);
        let mut key = *blake3::keyed_hash(&root, &seed).as_bytes();
        let mut ser = Vec::new();
        rmp::encode::write_array_len(&mut ser, 3).unwrap();
        rmp::encode::write_uint(&mut ser, 0).unwrap();
        rmp::encode::write_str(&mut ser, "aud").unwrap();
        rmp::encode::write_str(&mut ser, "mint").unwrap();
        key = *blake3::keyed_hash(&key, &ser).as_bytes();
        let mut buf = Vec::new();
        rmp::encode::write_array_len(&mut buf, 4).unwrap();
        buf.extend_from_slice(&kr_bytes);
        rmp::encode::write_bin(&mut buf, &nonce).unwrap();
        rmp::encode::write_bin(&mut buf, &key).unwrap();
        rmp::encode::write_array_len(&mut buf, 1).unwrap();
        buf.extend_from_slice(&ser);
        let inline = format!("mnt2_{}", B64URL.encode(buf));

        assert_eq!(resolve_invite(&inline).expect("inline"), inline);

        let dir = tempfile::tempdir().expect("tempdir");
        let f = dir.path().join("invite.mac");
        std::fs::write(&f, format!("  {inline}\n")).expect("write");
        assert_eq!(
            resolve_invite(f.to_str().expect("utf8")).expect("file"),
            inline
        );

        assert!(resolve_invite("not-a-macaroon-and-not-a-path").is_err());
    }

    #[test]
    fn assert_enrolled_reports_missing_roles() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err =
            assert_enrolled(dir.path(), EnrollProfile::Coordinator).expect_err("none present");
        let msg = err.to_string();
        for r in EnrollProfile::Coordinator.roles() {
            assert!(
                msg.contains(r.name),
                "missing list should name {}: {msg}",
                r.name
            );
        }
    }

    #[test]
    fn enroll_profiles_map_to_expected_role_sets() {
        let names =
            |p: EnrollProfile| -> Vec<&'static str> { p.roles().iter().map(|r| r.name).collect() };
        assert_eq!(
            names(EnrollProfile::Coordinator),
            vec![ROLE_COORD_RO, ROLE_COORD_RW, ROLE_VOLUME_RW, ROLE_VOLUME_RO]
        );
        assert_eq!(names(EnrollProfile::Attestation), vec![ROLE_ATTEST_RO]);
        assert_eq!(EnrollProfile::Coordinator.as_str(), "coordinator");
        assert_eq!(EnrollProfile::Attestation.as_str(), "attestation");
    }

    #[test]
    fn probe_role_is_the_base_read_role() {
        // The validity probe must use a directly-assumable (non-intermediate)
        // coord role, not a volume intermediate.
        assert_eq!(EnrollProfile::Coordinator.probe_role(), ROLE_COORD_RO);
        assert_eq!(EnrollProfile::Attestation.probe_role(), ROLE_ATTEST_RO);
    }

    #[test]
    fn attestation_assert_enrolled_wants_only_attest_ro() {
        let dir = tempfile::tempdir().expect("tempdir");
        let msg = assert_enrolled(dir.path(), EnrollProfile::Attestation)
            .expect_err("none present")
            .to_string();
        assert!(msg.contains(ROLE_ATTEST_RO), "should name attest-ro: {msg}");
        for absent in [ROLE_COORD_RO, ROLE_COORD_RW, ROLE_VOLUME_RW, ROLE_VOLUME_RO] {
            assert!(
                !msg.contains(absent),
                "attestation enrollment must not require {absent}: {msg}"
            );
        }
    }

    #[test]
    fn shipped_mint_catalog_matches_enroll_profiles() {
        // deploy/mint/catalog.toml is mint's authoritative profile → role-set
        // map; this binary fans each profile out to a fixed role set at
        // exchange. The two must agree, or an enrolment requests a role its
        // profile's grant omits. Nothing else reads that file, so guard it here.
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../deploy/mint/catalog.toml"
        ))
        .expect("read catalog.toml");
        let catalog: toml::Value = toml::from_str(&text).expect("catalog.toml parses");
        let profiles = catalog
            .get("profile")
            .and_then(|p| p.as_array())
            .expect("[[profile]] present");
        let granted = |name: &str| -> Vec<&str> {
            let mut roles: Vec<&str> = profiles
                .iter()
                .find(|p| p.get("name").and_then(toml::Value::as_str) == Some(name))
                .and_then(|p| p.get("roles"))
                .and_then(toml::Value::as_array)
                .unwrap_or_else(|| panic!("profile {name} with roles"))
                .iter()
                .map(|r| r.as_str().expect("role is a string"))
                .collect();
            roles.sort_unstable();
            roles
        };
        let fanned = |roles: &[EnrollRole]| -> Vec<&str> {
            let mut names: Vec<&str> = roles.iter().map(|r| r.name).collect();
            names.sort_unstable();
            names
        };
        assert_eq!(
            granted("attestation"),
            fanned(ATTESTATION_ROLES),
            "attestation profile vs ATTESTATION_ROLES"
        );
        assert_eq!(
            granted("coordinator"),
            fanned(COORDINATOR_ROLES),
            "coordinator profile vs COORDINATOR_ROLES"
        );

        // Every role a profile grants must be a defined `[[role]]` (mint
        // rejects the config otherwise); guard it before mint ever sees it.
        let defined: Vec<&str> = catalog
            .get("role")
            .and_then(toml::Value::as_array)
            .expect("[[role]] present")
            .iter()
            .filter_map(|r| r.get("name").and_then(toml::Value::as_str))
            .collect();
        for profile in ["coordinator", "attestation"] {
            for role in granted(profile) {
                assert!(
                    defined.contains(&role),
                    "profile {profile} grants {role}, absent from [[role]]"
                );
            }
        }
    }
}
