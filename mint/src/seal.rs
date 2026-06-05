//! Template seal — the operator-signed manifest pinning every role's
//! authority surface against tamper between provisioning and render
//! time (`docs/design-mint-template-seal.md`).
//!
//! The seal MACs the substrate that drives `/v1/assume-role`'s policy
//! output: each role's TTL bounds and the BLAKE3 hash of its policy
//! template's content. A bucket-credential
//! holder cannot forge a seal — only a process holding the macaroon
//! keyring can produce a valid MAC, the same trust anchor that signs
//! `_mint/approved/<sub>` (PR #454).
//!
//! Authoring is an authenticated call to a running daemon:
//! `POST /v1/admin/seal` ([`crate::admin`]) hashes the daemon's own
//! already-loaded [`Config`] via [`Seal::build_from_config`], MACs it
//! under the keyring, PUTs `seal.json`, and writes the local sealed
//! cache. There is no local staging file.
//!
//! [`resolve_startup`] resolves what the daemon serves: a verified bucket
//! seal yields a [`SealState::Serving`] surface drawn from the local
//! sealed cache (or adopted from `roles_dir/`); a missing or unsatisfiable
//! seal yields [`SealState::Dormant`]. The served policy bytes live in the
//! immutable [`crate::sealed_cache::TemplateSet`] for the process
//! lifetime — the request path never re-reads disk.

use std::collections::BTreeMap;
use std::io;

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
/// bears on what mint will render or grant — TTL bounds and the policy
/// template's content hash. The only role-block
/// field deliberately left unsealed is `policy_file` (the filename):
/// what matters is the bytes it currently contains — hashed into
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
}

/// The complete seal: every role, plus the audience. MAC'd under one
/// keyring generation so a single object covers the whole deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seal {
    pub audience: String,
    pub roles: BTreeMap<String, SealedRole>,
    /// BLAKE3 of the canonical `[env]` serialisation (see
    /// [`canonical_env_bytes`]), hex-encoded — the pin for the materialised
    /// `sealed/env.json`. Binds the operator-defined template values into
    /// the attested surface: a host serves the env it can reproduce to this
    /// hash, never the live config, so granted resource names are sealed.
    pub env_blake3: String,
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
                min_ttl_seconds,
                max_ttl_seconds,
                default_ttl_seconds,
                policy_path: _, // location, not authority — bytes hashed below
                policy,
            } = role;
            roles.insert(
                name.clone(),
                SealedRole {
                    default_ttl_seconds: *default_ttl_seconds,
                    max_ttl_seconds: *max_ttl_seconds,
                    min_ttl_seconds: *min_ttl_seconds,
                    policy_blake3: hash_hex(policy.as_bytes()),
                },
            );
        }
        let kid = keyring.current_kid();
        let mut seal = Seal {
            audience: config.audience.clone(),
            roles,
            env_blake3: hash_hex(&canonical_env_bytes(&config.env)),
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
    /// intent — audience + per-role TTL bounds and policy hash.
    /// `sealed_at`, `kid`, and `mac` are explicitly
    /// ignored so two hosts signing identical templates produce
    /// reconciliation-equal seals.
    pub fn semantically_equal(&self, other: &Seal) -> bool {
        self.audience == other.audience
            && self.roles == other.roles
            && self.env_blake3 == other.env_blake3
    }

    /// Compute the MAC under `key`. The MAC input is the seal
    /// serialised by `serde_json::to_vec` with `mac` cleared to the
    /// empty string — deterministic for the field set used (small
    /// object, no floats, BTreeMap ordering is stable).
    fn compute_mac(&self, key: &[u8; 32]) -> [u8; 32] {
        let canonical = Seal {
            audience: self.audience.clone(),
            roles: self.roles.clone(),
            env_blake3: self.env_blake3.clone(),
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
        let local_env_hash = hash_hex(&canonical_env_bytes(&config.env));
        if self.env_blake3 != local_env_hash {
            diffs.push(format!(
                "env: sealed as {}, local [env] hashes to {}",
                self.env_blake3, local_env_hash
            ));
        }
        // Roles present locally but not in the seal, or where the
        // sealed view disagrees.
        for (name, role) in &config.roles {
            let Some(sealed) = self.roles.get(name) else {
                diffs.push(format!("role {name}: not in seal"));
                continue;
            };
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

/// Canonical serialisation of the `[env]` map — the bytes hashed into
/// [`Seal::env_blake3`] and written to `sealed/env.json`. Deterministic
/// (BTreeMap key order, all-string values), so every host materialising
/// the same `[env]` produces identical bytes and hash.
pub(crate) fn canonical_env_bytes(env: &BTreeMap<String, String>) -> Vec<u8> {
    // A String→String map cannot fail to serialise.
    serde_json::to_vec_pretty(env).expect("serialise env map")
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

/// `mint serve` startup: resolve the template-seal state
/// (`docs/design-mint-template-seal.md` § *Startup*).
///
/// 1. Load the bucket seal. Missing, or unverifiable under the current
///    keyring → **dormant** (logged loudly): the auth/admin planes still
///    run, so an operator can publish a seal (`POST /v1/admin/seal`) that
///    lifts dormancy on this host immediately. Mint never commits on-disk
///    bytes as canonical on its own.
/// 2. Resolve the served surface from the verified seal: serve the local
///    sealed cache if it satisfies that seal, else adopt the seal from
///    `roles_dir/` (writing the cache). A host whose templates can't
///    produce the sealed content comes up dormant with the diff.
/// 3. Drift check (informational): if `roles_dir/` has changed away from
///    what is served, log loudly — staged-but-unsealed — and serve.
///
/// Only genuine infrastructure failures (bucket unreachable) are `Err`;
/// every no-seal / mismatch path is a logged `Ok(SealState::Dormant)`.
pub async fn resolve_startup(
    config: &Config,
    store: &crate::state::Store,
) -> Result<SealState, String> {
    let keyring = store.keyring().await;

    // (1) Load + verify the bucket seal. No seal, or one we can't verify
    //     under the current keyring → dormant.
    let bucket_seal = match store
        .get_template_seal()
        .await
        .map_err(|e| format!("read bucket seal: {e}"))?
    {
        Some(seal) => seal,
        None => {
            tracing::warn!("no roles available until `mint seal` is run");
            return Ok(SealState::Dormant);
        }
    };
    if let Err(e) = bucket_seal.verify(&keyring) {
        tracing::warn!(
            error = %e,
            kid = bucket_seal.kid,
            "seal does not verify under the current keyring — rerun `mint seal` to update"
        );
        return Ok(SealState::Dormant);
    }

    // (2) Resolve the served surface; None → this host can't produce the
    //     sealed content, so dormant.
    let Some(surface) = resolve_surface(config, &keyring, &bucket_seal)? else {
        return Ok(SealState::Dormant);
    };

    // (3) Drift check: what is staged on disk vs what we serve.
    let staged = Seal::build_from_config(config, &keyring, &bucket_seal.sealed_at);
    if staged.semantically_equal(&surface.seal) {
        log_now_serving(&surface.seal, None);
    } else {
        tracing::warn!(
            "staged template changes in roles_dir/ are not sealed — serving the \
             sealed content; run `mint seal` to commit:\n  {}",
            surface.seal.diff_against_config(config).join("\n  "),
        );
    }
    Ok(SealState::Serving(surface))
}

/// Emit the canonical "now serving" line whenever a verified seal becomes
/// this host's served surface — at startup (`operator` is `None`) and after
/// an in-process reseal (`operator` names who authored it). Same message
/// string in both, so an operator watching the log sees one consistent
/// confirmation that a seal is live whether mint was just restarted or
/// resealed while running.
pub fn log_now_serving(seal: &Seal, operator: Option<&str>) {
    match operator {
        Some(op) => tracing::info!(
            target: "mint::seal",
            operator = op,
            kid = seal.kid,
            sealed_at = %seal.sealed_at,
            roles = seal.roles.len(),
            "template seal verified — serving",
        ),
        None => tracing::info!(
            target: "mint::seal",
            kid = seal.kid,
            sealed_at = %seal.sealed_at,
            roles = seal.roles.len(),
            "template seal verified — serving",
        ),
    }
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
        CacheState::Loaded {
            seal,
            templates,
            env,
        } if seal.semantically_equal(bucket_seal) => {
            return Ok(Some(ServedSurface {
                seal: bucket_seal.clone(),
                templates,
                env,
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
        let surface = ServedSurface::materialize(config, bucket_seal, data_dir)
            .map_err(|e| format!("write sealed cache: {e}"))?;
        return Ok(Some(surface));
    }

    tracing::warn!(
        "local templates do not match the published seal:\n  {}",
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

[store]
bucket = "demo-bucket"

[[role]]
name = "volume-ro"
min_ttl_seconds = 60
max_ttl_seconds = 2592000
default_ttl_seconds = 2592000
policy_file = "volume-ro.json"
"#;

    fn config() -> Config {
        parse_for_test(SAMPLE_TOML, &[("volume-ro.json", "{\"Statement\":[]}")]).expect("parse")
    }

    #[tokio::test]
    async fn dormant_until_sealed_then_adopts_then_serves_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mut cfg = config();
        cfg.data_dir = tmp.path().to_path_buf();
        let store = crate::state::Store::open_in_memory([9u8; 32])
            .await
            .expect("store");

        // First start: no bucket seal — DORMANT, and mint never commits
        // the on-disk bytes on its own.
        assert!(matches!(
            resolve_startup(&cfg, &store).await.expect("startup"),
            SealState::Dormant
        ));
        assert!(
            store.get_template_seal().await.expect("read").is_none(),
            "dormant start must not write a seal"
        );

        // A seal is published — what `POST /v1/admin/seal` does: build it
        // from the daemon's config and PUT it to the bucket.
        let keyring = store.keyring().await;
        let seal = Seal::build_from_config(&cfg, &keyring, "2026-05-31T00:00:00Z");
        store.put_template_seal(&seal).await.expect("publish");

        // First start after sealing: no local cache yet → adopt from
        // roles_dir/, write the cache, serve.
        match resolve_startup(&cfg, &store).await.expect("startup") {
            SealState::Serving(surface) => {
                assert_eq!(surface.seal.roles.len(), cfg.roles.len());
                assert_eq!(surface.policy("volume-ro").unwrap(), "{\"Statement\":[]}");
            }
            SealState::Dormant => panic!("should adopt + serve once a seal exists"),
        }

        // Restart: the bucket seal is unchanged, so it serves straight
        // from the local cache.
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
        // Tampering with a sealed role field invalidates the MAC.
        let kr = Keyring::single([7u8; 32]);
        let mut seal = Seal::build_from_config(&config(), &kr, "t");
        seal.roles.get_mut("volume-ro").unwrap().max_ttl_seconds += 1;
        assert!(matches!(seal.verify(&kr), Err(SealError::BadMac)));
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
    fn forged_bucket_put_cannot_be_verified() {
        // Simulates the bucket-credential attacker: they write
        // arbitrary JSON into _mint/templates/seal.json. Without
        // the keyring they cannot produce a valid MAC, so no
        // recovered Seal verifies.
        let kr = Keyring::single([7u8; 32]);
        let forged = Seal {
            audience: "mint".into(),
            roles: BTreeMap::new(),
            env_blake3: "00".repeat(32),
            sealed_at: "t".into(),
            kid: 0,
            mac: "00".repeat(32),
        };
        assert!(matches!(forged.verify(&kr), Err(SealError::BadMac)));
    }
}
