//! The local **sealed cache** (`docs/design-mint-template-seal.md` §
//! *The sealed cache*): a host's last-verified sealed template state,
//! the bytes mint actually serves from.
//!
//! ```text
//! <data_dir>/sealed/
//!   seal.json            # copy of the canonical seal this cache satisfies
//!   policies/<blake3>    # one file per policy template, content-addressed
//!   env.json             # materialised [env] values, pinned by env_blake3
//! ```
//!
//! The cache exists so a restarting host can serve last-sealed content
//! after `roles_dir/` has drifted (templates updated fleet-wide but not
//! yet re-sealed) — the seal holds only hashes, so the bytes must live
//! somewhere a restart can reach. It is a *derived* artefact, always
//! reconstructable from `roles_dir/` + `[env]` + a canonical `seal.json`,
//! so it is content-addressed and `ls`/`cat`-inspectable; nothing here is
//! precious or authoritative on its own.
//!
//! This module is the cache's read/write primitives plus the in-memory
//! [`TemplateSet`] loaded from it. The *policy* of when to write, adopt,
//! or fall through lives in `mint serve` startup; the cache module only
//! knows how to persist a verified set and how to load one back while
//! re-checking each policy's bytes (and `env.json`) against the hashes the
//! cache's own `seal.json` pins.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::keyring::Keyring;
use crate::seal::{Seal, SealError, SealedRole, canonical_env_bytes, hash_hex};

/// Subdirectory of `data_dir` holding the cache.
const SEALED_DIR: &str = "sealed";
/// Content-addressed policy templates live under `sealed/policies/`.
const POLICIES_DIR: &str = "policies";
/// The cached copy of the canonical seal the policy files satisfy.
const SEAL_FILE: &str = "seal.json";
/// The materialised `[env]` values the seal's `env_blake3` pins.
const ENV_FILE: &str = "env.json";

/// The immutable, verified set of policy templates mint renders from —
/// role name → template bytes. Built once at startup (from the cache, or
/// adopted from `roles_dir/` against the canonical seal) and never
/// mutated for the process lifetime: the request path reads it without
/// locking and consults nothing on disk
/// (`docs/design-mint-template-seal.md` § *Runtime behaviour*).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateSet {
    policies: BTreeMap<String, String>,
}

impl TemplateSet {
    /// Wrap a role → template-bytes map. The caller is responsible for
    /// having verified the bytes against a canonical seal first.
    pub fn from_policies(policies: BTreeMap<String, String>) -> Self {
        TemplateSet { policies }
    }

    /// The policy template for `role`, or `None` if the role is not in
    /// the sealed set.
    pub fn get(&self, role: &str) -> Option<&str> {
        self.policies.get(role).map(String::as_str)
    }

    /// Role names in the set, ascending. Diagnostic / test use.
    pub fn roles(&self) -> impl Iterator<Item = &str> {
        self.policies.keys().map(String::as_str)
    }
}

/// Collect a config's already-loaded role policy templates into a
/// [`TemplateSet`] — the bytes `mint seal` hashes and the cache stores.
/// Used by startup's adopt path and by tests.
pub fn policies_from_config(config: &Config) -> TemplateSet {
    TemplateSet::from_policies(
        config
            .roles
            .iter()
            .map(|(name, r)| (name.clone(), r.policy.clone()))
            .collect(),
    )
}

/// The complete role surface mint serves from once startup has resolved
/// a canonical seal: the seal itself (audience + the per-role authority
/// fields) paired with the verified policy bytes. The request path reads
/// *only* this — never the live [`Config`], which is staging input to
/// `mint seal` and may have drifted (`docs/design-mint-template-seal.md`
/// § *The sealed cache*).
#[derive(Debug, Clone)]
pub struct ServedSurface {
    /// The canonical seal — its `audience` and `roles` (each a
    /// [`SealedRole`]: required caveats, TTL bounds) are the
    /// authority surface; the policy *bytes* live in `templates`.
    pub seal: Seal,
    /// Verified policy templates, role → bytes.
    pub templates: TemplateSet,
    /// The sealed `[env]` values (`{{env.X}}`), reproduced from local
    /// `config.env` and verified against the seal's `env_blake3`. Rendered
    /// into every policy; the request path reads these, never live config.
    pub env: BTreeMap<String, String>,
}

impl ServedSurface {
    /// Build the surface straight from a loaded config — the shape
    /// startup's adopt path produces and tests use. The seal is MAC'd
    /// under `keyring`; serving itself reads only `audience`, `roles`,
    /// and the templates.
    pub fn from_config(config: &Config, keyring: &Keyring, sealed_at: &str) -> Self {
        ServedSurface {
            seal: Seal::build_from_config(config, keyring, sealed_at),
            templates: policies_from_config(config),
            env: config.env.clone(),
        }
    }

    /// Persist `seal`'s surface to the sealed cache under `data_dir` and
    /// return the `ServedSurface` to serve. The policy bytes and `[env]`
    /// values are taken from `config`, which the caller has already
    /// established satisfies `seal` — the startup adopt path (templates and
    /// env hash-match a verified bucket seal) or the seal handler (the seal
    /// was just authored from this same config). This is the tail both
    /// share once they hold a known-good seal: write the cache, hand back
    /// the surface.
    pub fn materialize(config: &Config, seal: &Seal, data_dir: &Path) -> Result<Self, SealError> {
        let templates = policies_from_config(config);
        write(data_dir, seal, &templates, &config.env)?;
        Ok(ServedSurface {
            seal: seal.clone(),
            templates,
            env: config.env.clone(),
        })
    }

    /// The sealed audience every served credential is stamped with and
    /// checked against.
    pub fn audience(&self) -> &str {
        &self.seal.audience
    }

    /// The sealed authority fields for `role`, or `None` if the role is
    /// not in the sealed surface.
    pub fn role(&self, role: &str) -> Option<&SealedRole> {
        self.seal.roles.get(role)
    }

    /// The sealed policy template for `role`.
    pub fn policy(&self, role: &str) -> Option<&str> {
        self.templates.get(role)
    }

    /// The sealed `[env]` values rendered into every policy (`{{env.X}}`).
    pub fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }
}

/// A `Serving` state built directly from a loaded config — bypassing the
/// bucket-seal verification `seal::resolve_startup` performs. Hidden from
/// docs because production serving must go through `resolve_startup`;
/// this exists for tests and in-process callers that already trust the
/// config. The seal is MAC'd under a throwaway keyring (serving reads
/// only audience/roles/policy).
#[doc(hidden)]
pub fn serving_from_config(config: &Config) -> SealState {
    SealState::Serving(ServedSurface::from_config(
        config,
        &Keyring::single([0u8; 32]),
        "unsealed",
    ))
}

/// Whether `mint serve` resolved a canonical seal at startup, and if so
/// the surface it serves. `Dormant` closes the role-rendering and
/// issuance planes (`/v1/assume-role`, `/v1/enroll-exchange`) and reports
/// not-ready, while the auth/admin planes stay live so an operator can
/// publish the seal that lifts dormancy
/// (`docs/design-mint-template-seal.md` § *Dormant until sealed*).
#[derive(Debug, Clone)]
pub enum SealState {
    /// No verifiable seal — role-rendering closed, not-ready.
    Dormant,
    /// Serving the resolved sealed surface.
    Serving(ServedSurface),
}

/// What [`load`] found in `<data_dir>/sealed/`.
///
/// `Absent` and `Corrupt` are both recoverable at startup — the host
/// falls through to adopting the bucket seal from `roles_dir/`
/// (`docs/design-mint-template-seal.md` § *Startup*); only genuine
/// infrastructure I/O fails as [`SealError`].
#[derive(Debug)]
pub enum CacheState {
    /// No cache on disk — `sealed/seal.json` does not exist.
    Absent,
    /// A cache whose `seal.json` parsed and whose every policy file's
    /// bytes hash to the `policy_blake3` that seal pins.
    Loaded {
        /// The canonical seal this cache claims to satisfy. Startup
        /// compares it (semantically) to the bucket seal.
        seal: Seal,
        /// The verified templates, ready to serve.
        templates: TemplateSet,
        /// The verified `[env]` values, ready to serve.
        env: BTreeMap<String, String>,
    },
    /// The cache exists but does not hold up: `seal.json` is unparseable,
    /// a referenced policy file is missing, or a policy file's bytes do
    /// not match the hash the cache pins. The reason is for a loud log;
    /// the bytes are never served.
    Corrupt {
        /// Human-readable divergence, for the startup log.
        reason: String,
    },
}

fn sealed_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(SEALED_DIR)
}

/// Write the sealed cache atomically-per-file: the canonical `seal`
/// plus one content-addressed file per template in `templates`. Every
/// byte written has already been verified against `seal` by the caller
/// (the seal handler or the startup adopt path), so this only persists —
/// it does not re-decide.
///
/// `policies/` is pruned to exactly the hashes `seal` references, so
/// `ls sealed/policies/` always reflects the current seal and no orphan
/// blobs accumulate across re-seals.
pub fn write(
    data_dir: &Path,
    seal: &Seal,
    templates: &TemplateSet,
    env: &BTreeMap<String, String>,
) -> Result<(), SealError> {
    let dir = sealed_dir(data_dir);
    let policies = dir.join(POLICIES_DIR);
    std::fs::create_dir_all(&policies)?;

    // Materialise the env beside the policies, pinned the same way: its
    // bytes must hash to the seal's `env_blake3`, else this is a caller bug.
    let env_bytes = canonical_env_bytes(env);
    if hash_hex(&env_bytes) != seal.env_blake3 {
        return Err(SealError::Encode(
            "env bytes do not match the seal's env_blake3".into(),
        ));
    }
    write_atomic(&dir.join(ENV_FILE), &env_bytes)?;

    let mut keep = std::collections::BTreeSet::new();
    for (role, body) in &templates.policies {
        let hash = hash_hex(body.as_bytes());
        // The seal was built from these same bytes; a mismatch here is a
        // caller bug, not a tamper, so surface it loudly rather than
        // writing a cache that load() would reject.
        match seal.roles.get(role) {
            Some(sealed) if sealed.policy_blake3 == hash => {}
            _ => {
                return Err(SealError::Encode(format!(
                    "role {role}: template bytes do not match the seal's policy_blake3"
                )));
            }
        }
        write_atomic(&policies.join(&hash), body.as_bytes())?;
        keep.insert(hash);
    }
    prune_policies(&policies, &keep)?;

    let body = serde_json::to_vec_pretty(seal).map_err(|e| SealError::Encode(e.to_string()))?;
    write_atomic(&dir.join(SEAL_FILE), &body)
}

/// Load and self-verify the sealed cache. Reads `sealed/seal.json`, then
/// for every role it names reads `policies/<policy_blake3>` and re-hashes
/// the bytes against that pin. Internal consistency only — the seal's MAC
/// and its agreement with the bucket seal are startup's concern.
pub fn load(data_dir: &Path) -> Result<CacheState, SealError> {
    let dir = sealed_dir(data_dir);
    let seal_bytes = match std::fs::read(dir.join(SEAL_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(CacheState::Absent),
        Err(e) => return Err(SealError::Io(e)),
    };
    let seal: Seal = match serde_json::from_slice(&seal_bytes) {
        Ok(s) => s,
        Err(e) => {
            return Ok(CacheState::Corrupt {
                reason: format!("sealed/{SEAL_FILE} is unparseable: {e}"),
            });
        }
    };

    let policies = dir.join(POLICIES_DIR);
    let mut loaded = BTreeMap::new();
    for (role, sealed) in &seal.roles {
        let path = policies.join(&sealed.policy_blake3);
        let body = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(CacheState::Corrupt {
                    reason: format!(
                        "role {role}: cached policy {} is missing",
                        sealed.policy_blake3
                    ),
                });
            }
            Err(e) => return Err(SealError::Io(e)),
        };
        if hash_hex(&body) != sealed.policy_blake3 {
            return Ok(CacheState::Corrupt {
                reason: format!(
                    "role {role}: cached policy bytes do not match pinned hash {}",
                    sealed.policy_blake3
                ),
            });
        }
        let text = match String::from_utf8(body) {
            Ok(t) => t,
            Err(_) => {
                return Ok(CacheState::Corrupt {
                    reason: format!("role {role}: cached policy is not valid UTF-8"),
                });
            }
        };
        loaded.insert(role.clone(), text);
    }

    let env_bytes = match std::fs::read(dir.join(ENV_FILE)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(CacheState::Corrupt {
                reason: format!("cached {ENV_FILE} is missing"),
            });
        }
        Err(e) => return Err(SealError::Io(e)),
    };
    if hash_hex(&env_bytes) != seal.env_blake3 {
        return Ok(CacheState::Corrupt {
            reason: format!(
                "cached {ENV_FILE} bytes do not match pinned env_blake3 {}",
                seal.env_blake3
            ),
        });
    }
    let env: BTreeMap<String, String> = match serde_json::from_slice(&env_bytes) {
        Ok(m) => m,
        Err(e) => {
            return Ok(CacheState::Corrupt {
                reason: format!("cached {ENV_FILE} is not a string map: {e}"),
            });
        }
    };

    Ok(CacheState::Loaded {
        seal,
        templates: TemplateSet::from_policies(loaded),
        env,
    })
}

/// Remove any `policies/<name>` whose name is not in `keep`, so the
/// directory holds exactly the current seal's templates.
fn prune_policies(
    policies: &Path,
    keep: &std::collections::BTreeSet<String>,
) -> Result<(), SealError> {
    for entry in std::fs::read_dir(policies)? {
        let entry = entry?;
        if let Some(name) = entry.file_name().to_str()
            && !keep.contains(name)
        {
            std::fs::remove_file(entry.path())?;
        }
    }
    Ok(())
}

/// Atomic write within the same directory: write a temp sibling, then
/// rename over the target.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), SealError> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::keyring::Keyring;

    const ROOT: [u8; 32] = [42u8; 32];

    /// A config with two roles whose policy bytes differ, so the cache
    /// must keep them apart by content hash.
    fn config() -> Config {
        let toml = r#"
audience = "mint"
[store]
bucket = "demo-bucket"
[env]
bucket = "demo-bucket"
[[role]]
name = "volume-ro"
required_caveats = ["elide:Volume", "aud", "exp"]
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 3600
policy_file = "volume-ro.json"
[[role]]
name = "volume-rw"
required_caveats = ["sub", "elide:Volume", "aud", "exp"]
min_ttl_seconds = 60
max_ttl_seconds = 3600
default_ttl_seconds = 3600
policy_file = "volume-rw.json"
"#;
        crate::config::parse_for_test(
            toml,
            &[
                ("volume-ro.json", r#"{"ro":"{{env.bucket}}"}"#),
                ("volume-rw.json", r#"{"rw":"{{env.bucket}}"}"#),
            ],
        )
        .expect("parse")
    }

    /// Build a seal + the matching TemplateSet straight from a config —
    /// the shape startup and the seal handler will produce.
    fn seal_and_templates(config: &Config) -> (Seal, TemplateSet) {
        let keyring = Keyring::single(ROOT);
        let seal = Seal::build_from_config(config, &keyring, "2026-05-31T00:00:00Z");
        let policies = config
            .roles
            .iter()
            .map(|(name, r)| (name.clone(), r.policy.clone()))
            .collect();
        (seal, TemplateSet::from_policies(policies))
    }

    #[test]
    fn load_absent_when_no_cache() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(load(dir.path()).unwrap(), CacheState::Absent));
    }

    #[test]
    fn write_then_load_round_trips_every_policy() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config();
        let (seal, templates) = seal_and_templates(&cfg);
        write(dir.path(), &seal, &templates, &cfg.env).expect("write");

        match load(dir.path()).expect("load") {
            CacheState::Loaded {
                seal: got_seal,
                templates: got,
                env: got_env,
            } => {
                assert!(got_seal.semantically_equal(&seal));
                assert_eq!(got.get("volume-ro").unwrap(), r#"{"ro":"{{env.bucket}}"}"#);
                assert_eq!(got.get("volume-rw").unwrap(), r#"{"rw":"{{env.bucket}}"}"#);
                assert_eq!(
                    got_env.get("bucket").map(String::as_str),
                    Some("demo-bucket")
                );
            }
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn policies_are_content_addressed_and_pruned() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config();
        let (seal, templates) = seal_and_templates(&cfg);
        write(dir.path(), &seal, &templates, &cfg.env).expect("write");

        // Two distinct policies → two content-addressed files, each named
        // by its hash.
        let policies = sealed_dir(dir.path()).join(POLICIES_DIR);
        let names: std::collections::BTreeSet<String> = std::fs::read_dir(&policies)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names.len(), 2);
        for sealed in seal.roles.values() {
            assert!(names.contains(&sealed.policy_blake3));
        }

        // Drop a stale blob in; a re-write must prune it.
        std::fs::write(policies.join("deadbeef"), b"orphan").unwrap();
        write(dir.path(), &seal, &templates, &cfg.env).expect("rewrite");
        assert!(!policies.join("deadbeef").exists(), "stale blob not pruned");
    }

    #[test]
    fn tampered_policy_bytes_are_corrupt_not_loaded() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config();
        let (seal, templates) = seal_and_templates(&cfg);
        write(dir.path(), &seal, &templates, &cfg.env).expect("write");

        // Overwrite one content-addressed file with bytes that no longer
        // hash to its name — the cache's own integrity check must reject.
        let ro_hash = &seal.roles["volume-ro"].policy_blake3;
        let path = sealed_dir(dir.path()).join(POLICIES_DIR).join(ro_hash);
        std::fs::write(&path, b"{\"ro\":\"tampered\"}").unwrap();

        match load(dir.path()).expect("load") {
            CacheState::Corrupt { reason } => assert!(reason.contains("do not match")),
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn missing_policy_file_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config();
        let (seal, templates) = seal_and_templates(&cfg);
        write(dir.path(), &seal, &templates, &cfg.env).expect("write");

        let ro_hash = &seal.roles["volume-ro"].policy_blake3;
        std::fs::remove_file(sealed_dir(dir.path()).join(POLICIES_DIR).join(ro_hash)).unwrap();

        match load(dir.path()).expect("load") {
            CacheState::Corrupt { reason } => assert!(reason.contains("missing")),
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_seal_json_is_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(sealed_dir(dir.path())).unwrap();
        std::fs::write(sealed_dir(dir.path()).join(SEAL_FILE), b"not json").unwrap();
        match load(dir.path()).expect("load") {
            CacheState::Corrupt { reason } => assert!(reason.contains("unparseable")),
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }

    #[test]
    fn write_rejects_templates_that_disagree_with_seal() {
        // A caller bug: the TemplateSet bytes don't match the seal's
        // hashes. write must refuse rather than persist an
        // already-inconsistent cache.
        let dir = tempfile::tempdir().unwrap();
        let cfg = config();
        let (seal, _) = seal_and_templates(&cfg);
        let wrong = TemplateSet::from_policies(
            [
                (
                    "volume-ro".to_string(),
                    "{\"ro\":\"different\"}".to_string(),
                ),
                (
                    "volume-rw".to_string(),
                    r#"{"rw":"{{env.bucket}}"}"#.to_string(),
                ),
            ]
            .into_iter()
            .collect(),
        );
        assert!(matches!(
            write(dir.path(), &seal, &wrong, &cfg.env),
            Err(SealError::Encode(_))
        ));
    }

    #[test]
    fn tampered_env_bytes_are_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = config();
        let (seal, templates) = seal_and_templates(&cfg);
        write(dir.path(), &seal, &templates, &cfg.env).expect("write");

        // Rewrite env.json with bytes that no longer hash to env_blake3 —
        // the same integrity check policies get, applied to the env.
        std::fs::write(
            sealed_dir(dir.path()).join(ENV_FILE),
            br#"{"bucket":"attacker"}"#,
        )
        .unwrap();
        match load(dir.path()).expect("load") {
            CacheState::Corrupt { reason } => assert!(reason.contains("env_blake3")),
            other => panic!("expected Corrupt, got {other:?}"),
        }
    }
}
