//! Template seal — the operator-signed manifest pinning every role's
//! authority surface against tamper between provisioning and render
//! time (`docs/design-mint-template-seal.md`).
//!
//! The seal MACs the substrate that drives `/v1/assume-role`'s policy
//! output: each role's TTL bounds, required-caveat set, TPC-issuance
//! flag, and the BLAKE3 hash of its policy template's content. A
//! bucket-credential
//! holder cannot forge a seal — only a process holding the macaroon
//! keyring can produce a valid MAC, the same trust anchor that signs
//! `_mint/approved/<sub>` (PR #454).
//!
//! Authoring is purely local: [`Seal::build_from_config`] takes the
//! already-loaded [`Config`] (whose roles carry their policy bytes)
//! and a [`Keyring`], and produces a self-contained, self-verifying
//! object. The CLI writes it to `<data_dir>/pending-seal.json` via
//! [`write_pending`]; [`resolve_startup`] picks it up on the next start
//! and either publishes it (`Store::put_template_seal`) or, if the
//! bucket already represents the same intent, discards it via
//! [`Seal::semantically_equal`].
//!
//! [`resolve_startup`] then resolves what the daemon serves: a verified
//! bucket seal yields a [`SealState::Serving`] surface drawn from the
//! local sealed cache (or adopted from `roles_dir/`); a missing or
//! unsatisfiable seal yields [`SealState::Dormant`]. The served policy
//! bytes live in the immutable [`crate::sealed_cache::TemplateSet`] for
//! the process lifetime — the request path never re-reads disk.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::config::Config;
use crate::keyring::{Keyring, Kid};
use crate::sealed_cache::{SealState, ServedSurface};

/// Domain separator for seal MACs. Distinct from the macaroon and
/// approval domains so the same key cannot be tricked into producing
/// a seal MAC that doubles as a credential MAC, an approval MAC, or
/// vice versa.
const SEAL_DOMAIN: &[u8] = b"mint-templates-seal-v1";

/// Sealed view of one role: every field of the `[[role]]` block that
/// bears on what mint will render or grant — TTL bounds, required-caveat
/// set, the TPC section (`tpc`: present ⇒ the role issues a third-party
/// caveat at `tpc.location`, the operator-consent gate on writes), and
/// the policy template's content hash. The only role-block field
/// deliberately left unsealed is `policy_file` (the filename): what
/// matters is the bytes it currently contains — hashed into
/// `policy_blake3` — not where the operator put them.
///
/// [`Seal::build_from_config`] destructures the role exhaustively, so
/// adding a field to the role config is a compile error until it is
/// consciously sealed here or skipped with a reason — the seal cannot
/// silently fall behind the role surface.
///
/// Field order is fixed (alphabetical via serde's struct serializer)
/// so JSON serialisation is stable across hosts authoring the same
/// intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedRole {
    pub default_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub min_ttl_seconds: u64,
    /// BLAKE3 of the role's policy template file content, hex-encoded.
    pub policy_blake3: String,
    pub required_caveats: Vec<String>,
    pub tpc: Option<crate::config::Tpc>,
}

/// The complete seal: every role, plus the audience. MAC'd under one
/// keyring generation so a single object covers the whole deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    pub audience: String,
    pub roles: BTreeMap<String, SealedRole>,
    /// RFC 3339 timestamp the seal was authored. Diagnostic only — not
    /// part of the *intent* checked by [`Self::semantically_equal`], so
    /// two hosts signing identical templates seconds apart produce
    /// seals that reconcile cleanly at publish time.
    pub sealed_at: String,
    pub kid: Kid,
    /// `blake3_keyed(keyring[kid], SEAL_DOMAIN || canonical_body)` where
    /// `canonical_body` is the seal serialised with `mac` omitted —
    /// see [`Self::compute_mac`].
    pub mac: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("decode seal: {0}")]
    Decode(String),
    #[error("encode seal: {0}")]
    Encode(String),
    /// The seal's `kid` is not in the keyring (retired or unknown).
    #[error("seal kid {0} is not in the keyring")]
    UnknownKid(Kid),
    /// MAC mismatch under the named kid — body tampered with, or
    /// authored by something that didn't hold the keyring.
    #[error("seal MAC verification failed")]
    BadMac,
}

impl Seal {
    /// Build a seal from a loaded [`Config`] (which already holds each
    /// role's `policy` bytes in memory) and a [`Keyring`]. MAC'd under
    /// the keyring's current kid.
    ///
    /// `sealed_at` is RFC 3339; the caller passes it so tests can use
    /// fixed timestamps and production uses `Utc::now().to_rfc3339()`.
    pub fn build_from_config(config: &Config, keyring: &Keyring, sealed_at: &str) -> Self {
        let mut roles = BTreeMap::new();
        for (name, role) in &config.roles {
            // Exhaustive on purpose: a new role field must be
            // consciously sealed (added to SealedRole) or skipped (bound
            // to `_` with a reason) right here. Never add `..` — that is
            // how an authority-bearing field silently escapes the seal.
            let crate::config::Role {
                name: _,
                required_caveats,
                min_ttl_seconds,
                max_ttl_seconds,
                default_ttl_seconds,
                policy_path: _, // location, not authority — bytes hashed below
                policy,
                tpc,
            } = role;
            roles.insert(
                name.clone(),
                SealedRole {
                    default_ttl_seconds: *default_ttl_seconds,
                    max_ttl_seconds: *max_ttl_seconds,
                    min_ttl_seconds: *min_ttl_seconds,
                    policy_blake3: hash_hex(policy.as_bytes()),
                    required_caveats: required_caveats.clone(),
                    tpc: tpc.clone(),
                },
            );
        }
        let kid = keyring.current_kid();
        let mut seal = Seal {
            audience: config.audience.clone(),
            roles,
            sealed_at: sealed_at.to_string(),
            kid,
            mac: String::new(),
        };
        let mac = seal.compute_mac(keyring.current_key());
        seal.mac = hex32(&mac);
        seal
    }

    /// Verify the seal's MAC against `keyring`. Returns the verified
    /// seal on success, or a `SealError` naming the failure mode.
    /// The seal's `kid` selects which generation to verify under; a
    /// kid that is not in the ring fails with [`SealError::UnknownKid`].
    pub fn verify(&self, keyring: &Keyring) -> Result<(), SealError> {
        let key = keyring
            .get(self.kid)
            .ok_or(SealError::UnknownKid(self.kid))?;
        let expected = self.compute_mac(key);
        let actual = unhex32(&self.mac).ok_or(SealError::BadMac)?;
        if bool::from(expected.ct_eq(&actual)) {
            Ok(())
        } else {
            Err(SealError::BadMac)
        }
    }

    /// Two seals are *semantically* equal when they pin the same
    /// intent — audience + per-role required_caveats, TTL bounds, and
    /// policy hash. `sealed_at`, `kid`, and `mac` are explicitly
    /// ignored so two hosts signing identical templates produce
    /// reconciliation-equal seals.
    pub fn semantically_equal(&self, other: &Seal) -> bool {
        self.audience == other.audience && self.roles == other.roles
    }

    /// Compute the MAC under `key`. The MAC input is the seal
    /// serialised by `serde_json::to_vec` with `mac` cleared to the
    /// empty string — deterministic for the field set used (small
    /// object, no floats, BTreeMap ordering is stable).
    fn compute_mac(&self, key: &[u8; 32]) -> [u8; 32] {
        let canonical = Seal {
            audience: self.audience.clone(),
            roles: self.roles.clone(),
            sealed_at: self.sealed_at.clone(),
            kid: self.kid,
            mac: String::new(),
        };
        let body = serde_json::to_vec(&canonical).expect("serialise seal");
        let mut msg = Vec::with_capacity(SEAL_DOMAIN.len() + body.len());
        msg.extend_from_slice(SEAL_DOMAIN);
        msg.extend_from_slice(&body);
        *blake3::keyed_hash(key, &msg).as_bytes()
    }

    /// Verify the seal pins exactly the role surface `config` carries
    /// locally. Returns the per-role diff (one line per divergence)
    /// on mismatch — the seal does not equal the local config, and
    /// the operator needs to know which side to bring into agreement.
    /// Empty Vec means "agree."
    pub fn diff_against_config(&self, config: &Config) -> Vec<String> {
        let mut diffs = Vec::new();
        if self.audience != config.audience {
            diffs.push(format!(
                "audience: sealed as {:?}, local config has {:?}",
                self.audience, config.audience
            ));
        }
        // Roles present locally but not in the seal, or where the
        // sealed view disagrees.
        for (name, role) in &config.roles {
            let Some(sealed) = self.roles.get(name) else {
                diffs.push(format!("role {name}: not in seal"));
                continue;
            };
            if sealed.required_caveats != role.required_caveats {
                diffs.push(format!(
                    "role {name}: required_caveats sealed as {:?}, local has {:?}",
                    sealed.required_caveats, role.required_caveats
                ));
            }
            if sealed.tpc != role.tpc {
                diffs.push(format!(
                    "role {name}: tpc sealed as {:?}, local has {:?}",
                    sealed.tpc, role.tpc
                ));
            }
            if sealed.min_ttl_seconds != role.min_ttl_seconds
                || sealed.max_ttl_seconds != role.max_ttl_seconds
                || sealed.default_ttl_seconds != role.default_ttl_seconds
            {
                diffs.push(format!(
                    "role {name}: TTL bounds sealed as ({}, {}, {}), local has ({}, {}, {})",
                    sealed.min_ttl_seconds,
                    sealed.default_ttl_seconds,
                    sealed.max_ttl_seconds,
                    role.min_ttl_seconds,
                    role.default_ttl_seconds,
                    role.max_ttl_seconds,
                ));
            }
            let local_hash = hash_hex(role.policy.as_bytes());
            if sealed.policy_blake3 != local_hash {
                diffs.push(format!(
                    "role {name}: policy_blake3 sealed as {}, local file hashes to {}",
                    sealed.policy_blake3, local_hash,
                ));
            }
        }
        // Roles in the seal that are absent from the local config.
        for name in self.roles.keys() {
            if !config.roles.contains_key(name) {
                diffs.push(format!("role {name}: in seal but absent from local config"));
            }
        }
        diffs
    }
}

/// BLAKE3 of `bytes`, hex-encoded — the encoding used for every
/// `policy_blake3` in the seal, so the sealed cache must hash with this
/// to compare cached bytes against the seal.
pub(crate) fn hash_hex(bytes: &[u8]) -> String {
    let h = blake3::hash(bytes);
    hex32(h.as_bytes())
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Read a pending seal from disk, JSON-decoding the body. Returns
/// `Ok(None)` if the file does not exist; any other I/O or decode
/// failure surfaces as [`SealError`].
pub fn read_pending(path: &Path) -> Result<Option<Seal>, SealError> {
    match fs::read(path) {
        Ok(bytes) => {
            let seal: Seal =
                serde_json::from_slice(&bytes).map_err(|e| SealError::Decode(e.to_string()))?;
            Ok(Some(seal))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(SealError::Io(e)),
    }
}

/// Write a pending seal to disk atomically (tmp + rename, mode 0600).
/// The pending file is no more sensitive than the keyring it was
/// signed under; both share the `<data_dir>/` trust boundary.
pub fn write_pending(path: &Path, seal: &Seal) -> Result<(), SealError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(seal).map_err(|e| SealError::Encode(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, &bytes)?;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp, path)?;
    Ok(())
}

/// Remove a pending seal — the daemon calls this after a successful
/// publish (or after observing the bucket already represents the same
/// intent). Treats `NotFound` as success.
pub fn remove_pending(path: &Path) -> Result<(), SealError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(SealError::Io(e)),
    }
}

/// `mint serve` startup: resolve the template-seal state
/// (`docs/design-mint-template-seal.md` § *Startup*).
///
/// 1. Publish any staged `<data_dir>/pending-seal.json` (the local
///    authoring path) to the bucket, then remove it.
/// 2. Load the bucket seal. Missing, or unverifiable under the current
///    keyring → **dormant** (logged loudly): the auth/admin planes still
///    run, so an operator can publish a seal that lifts dormancy on the
///    next restart. This replaces the old auto-seal-on-first-start and
///    refuse-on-mismatch — mint never commits on-disk bytes as canonical
///    on its own.
/// 3. Resolve the served surface from the verified seal: serve the local
///    sealed cache if it satisfies that seal, else adopt the seal from
///    `roles_dir/` (writing the cache). A host whose templates can't
///    produce the sealed content comes up dormant with the diff.
/// 4. Drift check (informational): if `roles_dir/` has changed away from
///    what is served, log loudly — staged-but-unsealed — and serve.
///
/// Only genuine infrastructure failures (bucket unreachable) are `Err`;
/// every no-seal / mismatch path is a logged `Ok(SealState::Dormant)`.
pub async fn resolve_startup(
    config: &Config,
    store: &crate::state::Store,
) -> Result<SealState, String> {
    let keyring = store.keyring().await;
    let pending_path = config.data_dir.join("pending-seal.json");

    // (1) Publish any staged pending seal, then drop it.
    if let Some(pending) = read_pending(&pending_path).map_err(|e| e.to_string())? {
        pending.verify(&keyring).map_err(|e| {
            format!(
                "{} is signed under a kid that is no longer in the keyring \
                 (or its MAC is invalid): {e}. Inspect the file, then either \
                 re-run `mint seal` to re-sign under the current kid or \
                 remove the file to discard the staged intent.",
                pending_path.display(),
            )
        })?;
        let existing = store
            .get_template_seal()
            .await
            .map_err(|e| format!("read bucket seal: {e}"))?;
        match existing {
            Some(existing) if existing.semantically_equal(&pending) => {
                tracing::info!(
                    pending = %pending_path.display(),
                    "bucket seal already represents this intent; discarding pending without PUT",
                );
            }
            _ => {
                store
                    .put_template_seal(&pending)
                    .await
                    .map_err(|e| format!("PUT bucket seal: {e}"))?;
                tracing::info!(
                    pending = %pending_path.display(),
                    kid = pending.kid,
                    sealed_at = %pending.sealed_at,
                    roles = pending.roles.len(),
                    "published staged template seal",
                );
            }
        }
        remove_pending(&pending_path).map_err(|e| e.to_string())?;
    }

    // (2) Load + verify the bucket seal. No seal, or one we can't verify
    //     under the current keyring → dormant.
    let bucket_seal = match store
        .get_template_seal()
        .await
        .map_err(|e| format!("read bucket seal: {e}"))?
    {
        Some(seal) => seal,
        None => {
            tracing::warn!(
                "no template seal in the bucket — running DORMANT: /v1/assume-role \
                 and /v1/enroll-exchange are closed and /readyz is not-ready until \
                 an operator runs `mint seal` and the daemon restarts"
            );
            return Ok(SealState::Dormant);
        }
    };
    if let Err(e) = bucket_seal.verify(&keyring) {
        tracing::warn!(
            error = %e,
            kid = bucket_seal.kid,
            "bucket template seal does not verify under the current keyring — \
             running DORMANT; re-seal under a current kid via `mint seal`, then restart"
        );
        return Ok(SealState::Dormant);
    }

    // (3) Resolve the served surface; None → this host can't produce the
    //     sealed content, so dormant.
    let Some(surface) = resolve_surface(config, &keyring, &bucket_seal)? else {
        return Ok(SealState::Dormant);
    };

    // (4) Drift check: what is staged on disk vs what we serve.
    let staged = Seal::build_from_config(config, &keyring, &bucket_seal.sealed_at);
    if staged.semantically_equal(&surface.seal) {
        tracing::info!(
            kid = surface.seal.kid,
            sealed_at = %surface.seal.sealed_at,
            roles = surface.seal.roles.len(),
            "template seal verified — serving",
        );
    } else {
        tracing::warn!(
            "staged template changes in roles_dir/ are not sealed — serving the \
             sealed content; run `mint seal` to commit:\n  {}",
            surface.seal.diff_against_config(config).join("\n  "),
        );
    }
    Ok(SealState::Serving(surface))
}

/// Build the served surface for a verified `bucket_seal`: prefer the
/// local sealed cache when it satisfies the seal, else adopt the seal
/// from the on-disk templates (writing the cache). `Ok(None)` means this
/// host cannot produce the sealed content — the caller goes dormant.
fn resolve_surface(
    config: &Config,
    keyring: &Keyring,
    bucket_seal: &Seal,
) -> Result<Option<ServedSurface>, String> {
    use crate::sealed_cache::{self, CacheState};
    let data_dir = &config.data_dir;

    // Serve the cache if it satisfies this seal (its bytes were already
    // re-hashed against their pins by `load`).
    match sealed_cache::load(data_dir).map_err(|e| format!("load sealed cache: {e}"))? {
        CacheState::Loaded { seal, templates } if seal.semantically_equal(bucket_seal) => {
            return Ok(Some(ServedSurface {
                seal: bucket_seal.clone(),
                templates,
            }));
        }
        CacheState::Corrupt { reason } => {
            tracing::warn!(
                reason,
                "sealed cache is corrupt — re-deriving from roles_dir/"
            );
        }
        // Absent, or a cache that satisfies a different (older) seal:
        // fall through to adopt from disk.
        _ => {}
    }

    // Adopt: the on-disk templates must hash to exactly the sealed
    // surface, in which case we write the cache and serve.
    let staged = Seal::build_from_config(config, keyring, &bucket_seal.sealed_at);
    if staged.semantically_equal(bucket_seal) {
        let templates = sealed_cache::policies_from_config(config);
        sealed_cache::write(data_dir, bucket_seal, &templates)
            .map_err(|e| format!("write sealed cache: {e}"))?;
        return Ok(Some(ServedSurface {
            seal: bucket_seal.clone(),
            templates,
        }));
    }

    tracing::warn!(
        "local templates do not match the bucket seal — running DORMANT:\n  {}\n\
         deliver the sealed templates to this host and restart, or re-seal.",
        bucket_seal.diff_against_config(config).join("\n  "),
    );
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_for_test;
    use crate::sealed_cache::SealState;

    const SAMPLE_TOML: &str = r#"
audience = "mint"

[tenant]
bucket = "demo-bucket"

[[role]]
name = "volume-ro"
required_caveats = ["elide:Volume", "Audience", "NotAfter"]
min_ttl_seconds = 60
max_ttl_seconds = 2592000
default_ttl_seconds = 2592000
policy_file = "volume-ro.json"
"#;

    fn config() -> Config {
        parse_for_test(SAMPLE_TOML, &[("volume-ro.json", "{\"Statement\":[]}")]).expect("parse")
    }

    #[tokio::test]
    async fn dormant_until_pending_published_then_serves_from_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut cfg = config();
        cfg.data_dir = tmp.path().to_path_buf();
        let store = crate::state::Store::open_in_memory([9u8; 32])
            .await
            .expect("store");

        // First start: no pending, no bucket seal — DORMANT, and mint
        // never commits the on-disk bytes on its own (no auto-seal).
        assert!(matches!(
            resolve_startup(&cfg, &store).await.expect("startup"),
            SealState::Dormant
        ));
        assert!(
            store.get_template_seal().await.expect("read").is_none(),
            "dormant start must not write a seal"
        );

        // Operator stages a seal (the local authoring path), then a
        // restart publishes it, adopts it from roles_dir/, and serves.
        let keyring = store.keyring().await;
        let seal = Seal::build_from_config(&cfg, &keyring, "2026-05-31T00:00:00Z");
        write_pending(&cfg.data_dir.join("pending-seal.json"), &seal).expect("stage");
        match resolve_startup(&cfg, &store).await.expect("startup") {
            SealState::Serving(surface) => {
                assert_eq!(surface.seal.roles.len(), cfg.roles.len());
                assert_eq!(surface.policy("volume-ro").unwrap(), "{\"Statement\":[]}");
            }
            SealState::Dormant => panic!("should be serving after publish"),
        }
        assert!(store.get_template_seal().await.expect("read").is_some());

        // Idempotent restart: the bucket seal is unchanged, so it serves
        // straight from the local cache.
        assert!(matches!(
            resolve_startup(&cfg, &store).await.expect("startup"),
            SealState::Serving(_)
        ));
    }

    #[tokio::test]
    async fn unverifiable_bucket_seal_runs_dormant() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut cfg = config();
        cfg.data_dir = tmp.path().to_path_buf();
        let store = crate::state::Store::open_in_memory([9u8; 32])
            .await
            .expect("store");

        // A seal MAC'd under a key the store's keyring does not hold:
        // can't verify → dormant, not a hard error.
        let foreign = Seal::build_from_config(&cfg, &Keyring::single([0xAB; 32]), "t");
        store.put_template_seal(&foreign).await.expect("put");
        assert!(matches!(
            resolve_startup(&cfg, &store).await.expect("startup"),
            SealState::Dormant
        ));
    }

    #[test]
    fn build_and_verify_roundtrip() {
        let kr = Keyring::single([7u8; 32]);
        let seal = Seal::build_from_config(&config(), &kr, "2026-05-24T12:00:00Z");
        assert_eq!(seal.audience, "mint");
        assert_eq!(seal.kid, 0);
        assert_eq!(seal.mac.len(), 64);
        assert_eq!(seal.roles.len(), 1);
        let role = &seal.roles["volume-ro"];
        assert_eq!(role.policy_blake3.len(), 64);
        seal.verify(&kr)
            .expect("MAC verifies under issuing keyring");
    }

    #[test]
    fn verify_fails_under_different_key() {
        let kr_a = Keyring::single([7u8; 32]);
        let kr_b = Keyring::single([9u8; 32]);
        let seal = Seal::build_from_config(&config(), &kr_a, "t");
        assert!(matches!(seal.verify(&kr_b), Err(SealError::BadMac)));
    }

    #[test]
    fn verify_fails_with_tampered_role() {
        // Tampering with required_caveats invalidates the MAC.
        let kr = Keyring::single([7u8; 32]);
        let mut seal = Seal::build_from_config(&config(), &kr, "t");
        seal.roles
            .get_mut("volume-ro")
            .unwrap()
            .required_caveats
            .clear();
        assert!(matches!(seal.verify(&kr), Err(SealError::BadMac)));
    }

    #[test]
    fn tpc_is_sealed() {
        // The TPC section is the operator-consent gate on writes:
        // adding/removing it (or repointing its location) changes whether
        // a role's credentials require a discharge, and from where. It
        // must be inside both the MAC body and the config diff, or it
        // could be mutated without a re-seal.
        use crate::config::Tpc;
        let tpc = || {
            Some(Tpc {
                location: "https://auth.example/v1/discharge".to_string(),
            })
        };
        let kr = Keyring::single([7u8; 32]);
        let mut seal = Seal::build_from_config(&config(), &kr, "t");
        assert!(seal.roles["volume-ro"].tpc.is_none());

        // Part of the MAC body: adding a TPC invalidates the seal.
        seal.roles.get_mut("volume-ro").unwrap().tpc = tpc();
        assert!(matches!(seal.verify(&kr), Err(SealError::BadMac)));

        // Part of the intent: a seal pinning a different TPC than the
        // local config is reported by the diff (re-MAC first so we
        // exercise the diff, not the MAC check).
        let mac = seal.compute_mac(kr.current_key());
        seal.mac = hex32(&mac);
        let diffs = seal.diff_against_config(&config());
        assert_eq!(diffs.len(), 1, "diff: {diffs:?}");
        assert!(diffs[0].contains("tpc"), "diff: {diffs:?}");

        // Part of semantic equality: it gates the "serve cache" decision,
        // so two seals differing only in the TPC must not reconcile.
        let a = Seal::build_from_config(&config(), &kr, "t");
        let mut b = a.clone();
        b.roles.get_mut("volume-ro").unwrap().tpc = tpc();
        assert!(!a.semantically_equal(&b));
    }

    #[test]
    fn verify_fails_with_unknown_kid() {
        // A retired or unknown kid is a hard failure, not a silent
        // pass.
        let kr = Keyring::single([7u8; 32]);
        let mut seal = Seal::build_from_config(&config(), &kr, "t");
        seal.kid = 99;
        // Re-MAC under the (still in-ring) key 0 so we don't trip
        // BadMac before UnknownKid: we want to confirm kid-lookup
        // fires first.
        let mac = seal.compute_mac(kr.current_key());
        seal.mac = hex32(&mac);
        assert!(matches!(seal.verify(&kr), Err(SealError::UnknownKid(99))));
    }

    #[test]
    fn semantic_equality_ignores_sealed_at_kid_mac() {
        // Two hosts signing identical templates at different times
        // (and potentially under different kids) produce seals that
        // reconcile equal — the basis for "every host signs,
        // first-restart wins."
        let kr = Keyring::single([7u8; 32]);
        let a = Seal::build_from_config(&config(), &kr, "2026-05-24T12:00:00Z");
        let b = Seal::build_from_config(&config(), &kr, "2026-05-24T13:00:00Z");
        assert_ne!(a.sealed_at, b.sealed_at);
        assert_ne!(a.mac, b.mac); // sealed_at is in the MAC body
        assert!(a.semantically_equal(&b));
    }

    #[test]
    fn semantic_equality_diverges_on_intent() {
        // A change to any sealed field — TTL bounds here — breaks
        // semantic equality, so the second host's startup
        // recognises conflicting intent and publishes its own seal
        // (the operator-driven "rolling restart updates the seal"
        // flow).
        let kr = Keyring::single([7u8; 32]);
        let a = Seal::build_from_config(&config(), &kr, "t1");
        let mut b = a.clone();
        b.roles.get_mut("volume-ro").unwrap().max_ttl_seconds += 1;
        assert!(!a.semantically_equal(&b));
    }

    #[test]
    fn diff_against_config_empty_when_match() {
        let kr = Keyring::single([7u8; 32]);
        let cfg = config();
        let seal = Seal::build_from_config(&cfg, &kr, "t");
        assert!(seal.diff_against_config(&cfg).is_empty());
    }

    #[test]
    fn diff_reports_template_hash_mismatch() {
        // The render-time integrity check: a sealed hash that
        // doesn't match the on-disk file is the operator's signal
        // that the templates were tampered with (or that the
        // operator forgot to re-seal after editing them).
        let kr = Keyring::single([7u8; 32]);
        let seal = Seal::build_from_config(&config(), &kr, "t");
        let cfg2 = parse_for_test(
            SAMPLE_TOML,
            &[("volume-ro.json", "{\"Statement\":[\"DIFFERENT\"]}")],
        )
        .expect("parse");
        let diffs = seal.diff_against_config(&cfg2);
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("policy_blake3"), "diff: {:?}", diffs);
    }

    #[test]
    fn diff_reports_role_present_only_in_seal() {
        let kr = Keyring::single([7u8; 32]);
        let mut seal = Seal::build_from_config(&config(), &kr, "t");
        let role = seal.roles["volume-ro"].clone();
        seal.roles.insert("ghost-role".into(), role);
        let diffs = seal.diff_against_config(&config());
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("ghost-role"));
        assert!(diffs[0].contains("absent from local config"));
    }

    #[test]
    fn diff_reports_role_present_only_locally() {
        let kr = Keyring::single([7u8; 32]);
        let mut seal = Seal::build_from_config(&config(), &kr, "t");
        seal.roles.clear();
        let diffs = seal.diff_against_config(&config());
        assert_eq!(diffs.len(), 1);
        assert!(diffs[0].contains("volume-ro"));
        assert!(diffs[0].contains("not in seal"));
    }

    #[test]
    fn pending_file_roundtrip_atomic_with_0600() {
        let kr = Keyring::single([7u8; 32]);
        let seal = Seal::build_from_config(&config(), &kr, "t");
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pending-seal.json");
        write_pending(&p, &seal).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "pending file mode");
        let loaded = read_pending(&p).unwrap().expect("present");
        assert_eq!(loaded, seal);
        loaded.verify(&kr).expect("loaded seal still verifies");
    }

    #[test]
    fn read_pending_missing_is_ok_none() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pending-seal.json");
        assert!(read_pending(&p).unwrap().is_none());
    }

    #[test]
    fn remove_pending_is_idempotent() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pending-seal.json");
        // missing → ok
        remove_pending(&p).unwrap();
        // present → ok
        fs::write(&p, b"junk").unwrap();
        remove_pending(&p).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn forged_bucket_put_cannot_be_verified() {
        // Simulates the bucket-credential attacker: they write
        // arbitrary JSON into _mint/templates/seal.json. Without
        // the keyring they cannot produce a valid MAC, so no
        // recovered Seal verifies.
        let kr = Keyring::single([7u8; 32]);
        let forged = Seal {
            audience: "mint".into(),
            roles: BTreeMap::new(),
            sealed_at: "t".into(),
            kid: 0,
            mac: "00".repeat(32),
        };
        assert!(matches!(forged.verify(&kr), Err(SealError::BadMac)));
    }
}
