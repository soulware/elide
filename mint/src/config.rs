//! Configuration (`docs/design-mint.md` § *Mint configuration*). v1 is
//! single-tenant, single-root-key.
//!
//! Audience, store, env, and role metadata are file-backed (TOML); the
//! macaroon keyring is not config (loaded by [`crate::state::Store`]
//! from `<data_dir>/root_keys/`). Each role's IAM-policy template lives in
//! its own file under
//! `roles_dir`, named by the role's `policy_file` (a single normal path
//! component — see [`read_policy`]). The Tigris admin credential is the
//! one input that comes from the environment — `AWS_*`, resolved by
//! [`AdminCredential::from_env`] at load — never the TOML, so secrets
//! and role definitions stay on separate management planes.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("read config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("duplicate role name: {0}")]
    DuplicateRole(String),
    #[error("role {role}: {field} must be > 0 and min <= default <= max")]
    BadTtlBounds { role: String, field: String },
    #[error(
        "role {role}: policy_file {value:?} must be a single filename \
         (no path separators, no '.' or '..', not absolute)"
    )]
    BadPolicyFileName { role: String, value: String },
    #[error(
        "role {role}: derived policy filename {value:?} is not a single \
         filename — set an explicit policy_file or rename the role"
    )]
    BadDerivedPolicyName { role: String, value: String },
    #[error("role {role}: read policy_file {path}: {source}")]
    ReadPolicyFile {
        role: String,
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "bind and socket are mutually exclusive — set one (TCP) or the \
         other (UDS), not both"
    )]
    ConflictingListener,
    #[error("bind {value:?} is not a valid host:port: {source}")]
    BadBindAddr {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
    #[error("[env] key {key:?} is not a scalar (string, integer, float, or boolean)")]
    NonScalarEnv { key: String },
    #[error(
        "role {role}: declares [role.attestation] but no attestation_location \
         is configured to discharge it"
    )]
    AttestationWithoutLocation { role: String },
    #[error("role {role}: template references env.{key} but [env] has no such key")]
    UndefinedEnvKey { role: String, key: String },
    #[error("role {role}: policy template is not valid JSON: {source}")]
    PolicyNotJson {
        role: String,
        source: serde_json::Error,
    },
    #[error("role {role}: policy template has a malformed substitution {token}")]
    MalformedPolicyToken { role: String, token: String },
    #[error(
        "role {role}: template references mint.{key}, which is not a \
         mint-computed value"
    )]
    UnknownMintKey { role: String, key: String },
    #[error(
        "role {role}: declared attested names {declared:?} do not match the \
         template's {{{{attested.X}}}} tokens {used:?}"
    )]
    AttestedContractMismatch {
        role: String,
        declared: Vec<String>,
        used: Vec<String>,
    },
    #[error(
        "role {role}: declared attested name {key:?} is not in the attestable \
         registry"
    )]
    UnknownAttestedKey { role: String, key: String },
    #[error(
        "role {role}: declared caveat names {declared:?} do not match the \
         template's {{{{caveat.X}}}} tokens {used:?}"
    )]
    CaveatContractMismatch {
        role: String,
        declared: Vec<String>,
        used: Vec<String>,
    },
}

/// Normalise a declared field set (`attested`/`caveat`) to a canonical sorted,
/// de-duplicated form so the sealed contract is independent of authoring
/// order and the seal-time exact-match is a plain `Vec` equality against
/// the equally-canonical [`crate::template::template_surface`] output.
fn canonical_field_set(mut fields: Vec<String>) -> Vec<String> {
    fields.sort();
    fields.dedup();
    fields
}

/// Strip a namespace prefix (`attested.`/`caveat.`) off each
/// [`crate::template::template_surface`] entry, yielding the bare keys to
/// compare against a role's declared contract. The surface is already
/// sorted+deduped, so the result is too.
fn strip_ns(paths: &[String], prefix: &str) -> Vec<String> {
    paths
        .iter()
        .map(|p| p.strip_prefix(prefix).unwrap_or(p).to_string())
        .collect()
}

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    /// The audience name this mint answers to. A macaroon whose
    /// `Audience` caveat differs is rejected (cross-service replay
    /// defence).
    pub audience: String,
    /// Directory for mint's persisted state — the macaroon keyring
    /// (`root_keys/`), the current invite nonce, and the transient
    /// pending-enrollment table, all under one custody
    /// (`docs/design-mint.md` § *Enrollment*, § *Mint configuration*). A
    /// relative value (including the default
    /// `mint_data`) resolves against the current working directory,
    /// not the config file's parent; an absolute path is used verbatim.
    #[serde(default)]
    pub data_dir: Option<String>,
    /// Directory holding role policy-template files, one per role
    /// (referenced by each role's `policy_file`). Same resolution rule
    /// as `data_dir`; defaults to `mint_roles`.
    #[serde(default)]
    pub roles_dir: Option<String>,
    /// TCP listener address (`host:port`). The network deployment
    /// shapes — self-hosted on a separate trusted machine, central
    /// custodial/proxy — all use this; TLS is terminated ahead of or by
    /// mint. Mutually exclusive with `socket`. When neither is set the
    /// listener defaults to TCP `127.0.0.1:8085`.
    #[serde(default)]
    pub bind: Option<String>,
    /// Unix-domain-socket listener path — the bundled single-host dev
    /// shape (client + mint co-resident). Selecting it is what makes a
    /// mint instance local-only: no port, no accidental network
    /// exposure, no same-host TLS, filesystem-permission scoped.
    /// Mutually exclusive with `bind`. Same resolution rule as
    /// `data_dir` (relative against cwd, absolute verbatim); an empty
    /// value selects UDS at the default `<data_dir>/mint.sock`.
    #[serde(default)]
    pub socket: Option<String>,
    pub store: Store,
    /// Flat table of operator-defined scalar values surfaced to role
    /// policy templates as `{{env.X}}` (`docs/design-mint.md` §
    /// *Templating*). Values must be scalars; nested tables/arrays are
    /// rejected at load. Empty when the config omits `[env]`.
    #[serde(default)]
    pub env: BTreeMap<String, toml::Value>,
    /// Colocated demo auth role (`docs/design-auth-service.md`). Demo /
    /// single-host only; absent in production.
    #[serde(default)]
    pub demo_auth: Option<RawDemoAuth>,
    /// The discharge URL stamped into the enroll-gate (invite),
    /// exchange-gate (ticket), and admin-gate (admin-service) third-party
    /// caveats — where a client/operator fetches the discharge. A mint
    /// without `auth_location` (and without `[demo_auth].enabled`) cannot
    /// stamp those caveats, so it has no enrollment plane — `/v1/enroll`
    /// fails closed. The path is the discharge route; the transport it is
    /// dialed over is resolved separately (`[demo_auth]` socket in the
    /// colocated demo, the remembered `auth-transport` otherwise).
    #[serde(default)]
    pub auth_location: Option<String>,
    /// The discharge URL stamped into the attested third-party caveat
    /// of every role that declares `[role.attestation]` — where the
    /// holder fetches the attestation discharge. A single fixed
    /// authority (the attestation coordinator) for the deployment;
    /// absent means no role may declare attestation. The transport it is
    /// dialed over is resolved separately, like `auth_location`.
    #[serde(default)]
    pub attestation_location: Option<String>,
    #[serde(rename = "role", default)]
    pub roles: Vec<RawRole>,
}

/// `[demo_auth]` block: whether mint colocates the auth-service role and
/// the UDS it binds. Demo / single-host only; production runs a separate
/// auth-service binary.
#[derive(Debug, Clone, Deserialize)]
pub struct RawDemoAuth {
    /// When `true`, mint colocates the auth-service role and binds its
    /// own UDS for `/v1/login` + `/v1/discharge`. Generates `K_M-A` and
    /// `K_session` on first start. Mint refuses to start with
    /// `enabled = true` unless mint itself is bound to loopback or UDS —
    /// see `docs/design-auth-service.md` § *Mint as auth (demo only)*.
    #[serde(default)]
    pub enabled: bool,
    /// UDS path the colocated auth role binds, and the transport the
    /// operator/client dial to reach it. Path-only (UDS-only). Defaults
    /// to `<data_dir>/auth.sock` when omitted; ignored when
    /// `enabled = false`.
    #[serde(default)]
    pub socket: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Store {
    /// Bucket holding mint's own `_mint/*` state (the store bucket).
    /// Operational only — **not** a template surface; roles name the
    /// bucket(s) they grant on via `[env]`.
    pub bucket: String,
    /// S3 endpoint URL. Used by `serve --tigris` to build the
    /// data-plane client that reads and writes `_mint/*` under
    /// [self-vended `mint-rw` credentials][mint-rw], distinct from
    /// the IAM endpoint that `tigris.rs` calls. Omit to use Tigris's
    /// default S3 endpoint
    /// ([`crate::mint_rw::DEFAULT_TIGRIS_S3_ENDPOINT`]); set
    /// explicitly only for a non-Tigris S3-compatible target
    /// (custom AWS region, MinIO, etc.).
    ///
    /// [mint-rw]: crate::state::Store
    #[serde(default)]
    pub endpoint: Option<String>,
    /// S3 region; defaults to `us-east-1` (which Tigris accepts as a
    /// no-op). Override only for non-Tigris S3-compatible backends that
    /// reject the default.
    #[serde(default)]
    pub region: Option<String>,
}

/// Tigris admin credential, read from the standard AWS environment
/// variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
/// optional `AWS_SESSION_TOKEN`). Deliberately **not** in the TOML
/// config: the credential is a secret delivered by the environment
/// (systemd `LoadCredential=`, a secrets manager, …), never committed
/// alongside role definitions.
#[derive(Clone)]
pub struct AdminCredential {
    pub access_key_id: String,
    pub secret_access_key: String,
    /// `AWS_SESSION_TOKEN` if present (STS-style temporary creds).
    pub session_token: Option<String>,
}

impl std::fmt::Debug for AdminCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret — only that a credential is present.
        f.debug_struct("AdminCredential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"<redacted>")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl AdminCredential {
    /// Resolve from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
    /// (+ optional `AWS_SESSION_TOKEN`). `None` if either required var
    /// is unset or empty — the prototype's faked minter does not need
    /// it, so absence is a warning at startup, not a hard error.
    pub fn from_env() -> Option<Self> {
        let access_key_id = non_empty_env("AWS_ACCESS_KEY_ID")?;
        let secret_access_key = non_empty_env("AWS_SECRET_ACCESS_KEY")?;
        Some(Self {
            access_key_id,
            secret_access_key,
            session_token: non_empty_env("AWS_SESSION_TOKEN"),
        })
    }
}

fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|v| !v.is_empty())
}

/// Coerce an `[env]` value to its template string form. `[env]` is a
/// flat key→scalar table (`docs/design-mint.md` § *Templating*); arrays
/// and nested tables are a config error.
fn env_scalar_to_string(key: &str, value: &toml::Value) -> Result<String, ConfigError> {
    match value {
        toml::Value::String(s) => Ok(s.clone()),
        toml::Value::Integer(i) => Ok(i.to_string()),
        toml::Value::Float(f) => Ok(f.to_string()),
        toml::Value::Boolean(b) => Ok(b.to_string()),
        _ => Err(ConfigError::NonScalarEnv {
            key: key.to_string(),
        }),
    }
}

#[derive(Debug, Deserialize)]
pub struct RawRole {
    pub name: String,
    pub min_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub default_ttl_seconds: u64,
    /// Filename of the IAM-policy JSON template (see
    /// [`crate::template`]), resolved against `roles_dir`. Optional;
    /// defaults to `<name>.json`. Whether explicit or derived it must
    /// be a single normal path component — validated by [`read_policy`]
    /// (so a role `name` with a path separator is rejected too).
    #[serde(default)]
    pub policy_file: Option<String>,
    /// The role's substitution contract — the `[role.template]` subtable
    /// declaring which `attested.*` and `caveat.*` namespaces the policy
    /// template consumes. Absent = the empty contract.
    #[serde(default)]
    pub template: RawTemplate,
    /// The `[role.attestation]` subtable. Present ⟹ a credential for
    /// this role carries an attested third-party caveat that the
    /// attestation authority (`attestation_location`) must discharge.
    /// Absent ⟹ no attested caveat (the uniform key-bound credential).
    #[serde(default)]
    pub attestation: Option<RawAttestation>,
}

/// The `[role.attestation]` subtable: a role's attested-caveat contract.
#[derive(Debug, Deserialize)]
pub struct RawAttestation {
    /// Opaque context sealed verbatim into the attested caveat's CID and
    /// interpreted by the attestation authority alone. mint never
    /// inspects it — it carries whatever the authority's vocabulary
    /// needs (e.g. `rw-self` / `ro-ancestor` for volume attestation).
    pub mode: String,
}

/// The `[role.template]` subtable: the namespaces a role's policy template
/// substitutes (`docs/design-mint.md` § *Templating*). Declared here,
/// cross-checked at seal authoring against the template's actual
/// `{{attested.X}}` / `{{caveat.X}}` tokens (exact match), sealed into
/// [`crate::seal::SealedRole`], and enforced at request time before render.
#[derive(Debug, Default, Deserialize)]
pub struct RawTemplate {
    /// The `attested.*` names the template substitutes — the keys it
    /// expects a discharge to attest. Each must be in the closed
    /// [`crate::template::ATTESTABLE`] registry. Absent = the empty set
    /// (the template must reference no `attested.*`).
    #[serde(default)]
    pub attested: Vec<String>,
    /// The `caveat.*` MAC-verified names the template binds (e.g. `sub`).
    /// Absent = the empty set.
    #[serde(default)]
    pub caveat: Vec<String>,
}

/// Resolved listener transport — a per-deployment-shape choice, not a
/// global default (`docs/design-mint.md` § *Transport*). The macaroon +
/// Ed25519 PoP auth is identical over either; the socket neither
/// weakens nor substitutes for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Listener {
    /// The network shapes. TLS terminated ahead of or by mint.
    Tcp(SocketAddr),
    /// The single-host dev shape. Recreated on bind (stale dentry
    /// removed first), chmod `0o666` so a non-root client can
    /// connect.
    Uds(PathBuf),
}

impl Listener {
    /// The transport string a same-host client dials this listener at:
    /// `unix:<path>` for UDS, `http://<host>:<port>` for TCP. A wildcard
    /// bind (`0.0.0.0`/`::`) is rewritten to loopback — it is a bind
    /// address, not a dialable one.
    pub fn dial_url(&self) -> String {
        match self {
            Listener::Uds(path) => format!("unix:{}", path.display()),
            Listener::Tcp(addr) if addr.ip().is_unspecified() => {
                let loopback = if addr.is_ipv4() {
                    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                } else {
                    std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
                };
                format!("http://{}", SocketAddr::new(loopback, addr.port()))
            }
            Listener::Tcp(addr) => format!("http://{addr}"),
        }
    }
}

/// Default TCP listener when neither `bind` nor `socket` is configured.
pub const DEFAULT_BIND: &str = "127.0.0.1:8085";
/// Socket filename under `data_dir` when `socket` is selected without
/// an explicit path.
pub const DEFAULT_SOCKET_NAME: &str = "mint.sock";
/// Persisted-state directory when the config omits `data_dir`.
pub const DEFAULT_DATA_DIR: &str = "mint_data";

/// The default UDS path `mint serve` binds and `mint client` dials when
/// no config selects another: `<DEFAULT_DATA_DIR>/<DEFAULT_SOCKET_NAME>`.
pub fn default_mint_socket() -> PathBuf {
    PathBuf::from(DEFAULT_DATA_DIR).join(DEFAULT_SOCKET_NAME)
}

/// Colocated demo auth role, post-validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DemoAuth {
    pub enabled: bool,
    /// UDS the demo auth role binds, and the transport the
    /// operator/client dial to reach it. Resolved from
    /// `[demo_auth].socket` (explicit) or `<data_dir>/auth.sock`
    /// (default). `None` when `enabled = false`.
    pub socket: Option<PathBuf>,
}

/// Validated configuration, ready to serve.
#[derive(Debug)]
pub struct Config {
    pub audience: String,
    /// Persisted-state directory: the root key (generated on first
    /// start), invite nonce, and pending table all share this
    /// custody. Defaults to `mint_data` when the config omits
    /// `data_dir`. The root key itself is owned by
    /// [`crate::state::Store`], not parsed from config.
    pub data_dir: PathBuf,
    /// Directory the role `policy_file`s were read from. Defaults to
    /// `mint_roles`. Retained for diagnostics; policies are already
    /// resolved into [`Role::policy`].
    pub roles_dir: PathBuf,
    /// The resolved listener transport. The CLI may still override this
    /// with an explicit `--bind` (the TCP single-host override).
    pub listener: Listener,
    pub store: Store,
    /// Validated `[env]` values (`docs/design-mint.md` § *Templating*):
    /// operator-defined scalars surfaced to role policies as `{{env.X}}`,
    /// coerced to their string form. The only server-side substitution a
    /// role policy reads.
    pub env: BTreeMap<String, String>,
    /// Resolved from the AWS environment at load time. `None` when the
    /// env is unset. `mint serve` requires `Some`; tests that
    /// construct `Config` directly (and use `Store::open_local` /
    /// `Store::open_in_memory` instead of the Tigris backend) can
    /// leave it `None`.
    pub admin: Option<AdminCredential>,
    /// Colocated demo auth role — `None` if the config omits
    /// `[demo_auth]`.
    pub demo_auth: Option<DemoAuth>,
    /// The discharge URL stamped into the enroll/exchange/admin gates —
    /// `None` if the config omits `auth_location`. A mint without it (and
    /// without a demo auth role) cannot stamp those gates, so enrollment
    /// and the admin plane fail closed.
    pub auth_location: Option<String>,
    /// The discharge URL for the attested third-party caveat — `None`
    /// if the config omits `attestation_location`. A role that declares
    /// `[role.attestation]` without it is rejected at load.
    pub attestation_location: Option<String>,
    pub roles: BTreeMap<String, Role>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub name: String,
    pub min_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub default_ttl_seconds: u64,
    /// The resolved source of [`policy`](Role::policy):
    /// `<roles_dir>/<policy_file>`, or `<roles_dir>/<name>.json` when no
    /// explicit `policy_file` was set. Retained for diagnostics
    /// (`mint role inspect`); the template itself is already resolved.
    pub policy_path: PathBuf,
    /// The role's IAM-policy JSON template, read from
    /// [`policy_path`](Role::policy_path) at load.
    pub policy: String,
    /// The role's declared substitution contract: the `attested.*` and
    /// `caveat.*` names its template substitutes. Sorted and de-duplicated
    /// at load so the sealed form is canonical regardless of authoring
    /// order. Cross-checked against the template at seal authoring
    /// ([`Config::validate_policy_surface`]) and enforced at request time.
    pub attested: Vec<String>,
    pub caveat: Vec<String>,
    /// The role's opaque attestation `mode`, from `[role.attestation]` —
    /// `None` when the role declares no attestation. When `Some`, mint
    /// stamps an attested third-party caveat onto the credential at
    /// issuance, carrying this string verbatim for the attestation
    /// authority (`docs/design-mint-volume-attestation.md`).
    pub attestation_mode: Option<String>,
}

impl Config {
    pub fn from_toml_str(s: &str) -> Result<Config, ConfigError> {
        Self::from_raw(toml::from_str(s)?)
    }

    /// Resolve only the listener from a config file, skipping role and
    /// policy loading. `mint client` uses this to locate the local
    /// daemon socket without needing the server's `roles_dir` present.
    pub fn load_listener(path: &Path) -> Result<Listener, ConfigError> {
        let raw: RawConfig = toml::from_str(&std::fs::read_to_string(path)?)?;
        let data_dir = raw
            .data_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
        resolve_listener(raw.bind.as_deref(), raw.socket.as_deref(), &data_dir)
    }

    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        Self::from_toml_str(&std::fs::read_to_string(path)?)
    }

    fn from_raw(raw: RawConfig) -> Result<Config, ConfigError> {
        let roles_dir = raw
            .roles_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("mint_roles"));
        let mut roles = BTreeMap::new();
        for r in raw.roles {
            if r.min_ttl_seconds == 0
                || r.min_ttl_seconds > r.default_ttl_seconds
                || r.default_ttl_seconds > r.max_ttl_seconds
            {
                return Err(ConfigError::BadTtlBounds {
                    role: r.name.clone(),
                    field: "ttl_seconds".into(),
                });
            }
            let (policy_path, policy) = match r.policy_file {
                Some(ref f) => read_policy(&roles_dir, &r.name, f, true)?,
                None => read_policy(&roles_dir, &r.name, &format!("{}.json", r.name), false)?,
            };
            // A role that asks for an attested caveat needs an authority
            // to discharge it; minting an undischargeable credential
            // would be a silent dead-credential trap, so reject at load.
            if r.attestation.is_some() && raw.attestation_location.is_none() {
                return Err(ConfigError::AttestationWithoutLocation { role: r.name });
            }
            let role = Role {
                name: r.name.clone(),
                min_ttl_seconds: r.min_ttl_seconds,
                max_ttl_seconds: r.max_ttl_seconds,
                default_ttl_seconds: r.default_ttl_seconds,
                policy_path,
                policy,
                attested: canonical_field_set(r.template.attested),
                caveat: canonical_field_set(r.template.caveat),
                attestation_mode: r.attestation.map(|a| a.mode),
            };
            if roles.insert(r.name.clone(), role).is_some() {
                return Err(ConfigError::DuplicateRole(r.name));
            }
        }
        let data_dir = raw
            .data_dir
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_DATA_DIR));
        let listener = resolve_listener(raw.bind.as_deref(), raw.socket.as_deref(), &data_dir)?;
        let demo_auth = raw.demo_auth.map(|d| {
            let socket = d.enabled.then(|| {
                d.socket
                    .map(PathBuf::from)
                    .unwrap_or_else(|| data_dir.join("auth.sock"))
            });
            DemoAuth {
                enabled: d.enabled,
                socket,
            }
        });
        // `[env]` values must be scalars; the env-key *surface* check
        // (every `{{env.X}}` names a defined key) is deliberately **not**
        // run here — it gates seal authoring, not config load, so a
        // drifted local template never blocks a host from serving its
        // already-sealed surface. See [`Config::validate_policy_surface`].
        let mut env = BTreeMap::new();
        for (key, value) in raw.env {
            let scalar = env_scalar_to_string(&key, &value)?;
            env.insert(key, scalar);
        }
        Ok(Config {
            audience: raw.audience,
            data_dir,
            roles_dir,
            listener,
            store: raw.store,
            env,
            admin: AdminCredential::from_env(),
            demo_auth,
            auth_location: raw.auth_location,
            attestation_location: raw.attestation_location,
            roles,
        })
    }

    /// Gate **seal authoring** (`POST /v1/admin/seal`) by validating every
    /// template's substitution surface against an authoritative set per
    /// namespace, so a sealed template is one the renderer can render and
    /// the request path can enforce:
    ///
    /// 1. The template parses as JSON. A `{{…}}` token may sit only inside
    ///    a JSON string value; one that escaped (array, key, bare position)
    ///    makes the template invalid JSON and is caught here, not at first
    ///    render. The renderer relies on this — it substitutes into the
    ///    parsed string leaves and re-serialises, so a valid-JSON template
    ///    is the precondition for injection-proof rendering
    ///    (`crate::template`).
    /// 2. Every `{{…}}` token is a well-formed `namespace.key` scalar path.
    ///    An engine-ism (`{{#each}}`), a namespace-less or empty token, or
    ///    an unterminated `{{` would fail the render closed; the lint
    ///    surfaces it at publish instead.
    /// 3. Every `{{env.X}}` names a key present in `[env]`, every
    ///    `{{mint.X}}` names a [`crate::template::MINT_KEYS`] value, and
    ///    every declared `{{attested.X}}` names a key in
    ///    [`crate::template::ATTESTABLE`] — the closed-to-a-known-set
    ///    namespaces.
    /// 4. The template's `{{attested.X}}` and `{{caveat.X}}` tokens match
    ///    the role's declared `attested`/`caveat` contract exactly. A typo
    ///    (`{{attested.volm}}` vs declared `volume`) or a dropped binding
    ///    (a `coord-rw` template forgetting `{{caveat.sub}}`) fails at
    ///    publish instead of silently mis-scoping a live credential. The
    ///    declared set is what gets sealed and enforced at request time.
    ///
    /// None is run at config load: the request path renders the sealed
    /// surface, decoupled from the live config, so a drifted local
    /// template must never block a host from serving its already-sealed
    /// roles. Render-time strict mode is the final backstop if `[env]` is
    /// later mutated to drop a key a sealed template uses.
    pub fn validate_policy_surface(&self) -> Result<(), ConfigError> {
        for role in self.roles.values() {
            let doc =
                serde_json::from_str::<serde_json::Value>(&role.policy).map_err(|source| {
                    ConfigError::PolicyNotJson {
                        role: role.name.clone(),
                        source,
                    }
                })?;
            if let Some(token) = crate::template::malformed_tokens(&doc).into_iter().next() {
                return Err(ConfigError::MalformedPolicyToken {
                    role: role.name.clone(),
                    token,
                });
            }
            let surface = crate::template::template_surface(&role.policy);
            for path in &surface.env {
                if let Some(key) = path.strip_prefix("env.")
                    && !self.env.contains_key(key)
                {
                    return Err(ConfigError::UndefinedEnvKey {
                        role: role.name.clone(),
                        key: key.to_string(),
                    });
                }
            }
            for path in &surface.mint {
                let key = path.strip_prefix("mint.").unwrap_or(path);
                if !crate::template::MINT_KEYS.contains(&key) {
                    return Err(ConfigError::UnknownMintKey {
                        role: role.name.clone(),
                        key: key.to_string(),
                    });
                }
            }
            // Every declared attested name must be in the closed attestable
            // registry — `declared ⊆ authoritative`, the same shape as the
            // `env`/`mint` checks above.
            for key in &role.attested {
                if !crate::template::ATTESTABLE.contains(&key.as_str()) {
                    return Err(ConfigError::UnknownAttestedKey {
                        role: role.name.clone(),
                        key: key.clone(),
                    });
                }
            }
            // `template_surface` returns each bucket sorted+deduped, and
            // the declared sets are canonicalised the same way at load, so
            // the contract check is a plain Vec equality of the bare keys.
            let used_attested = strip_ns(&surface.attested, "attested.");
            if used_attested != role.attested {
                return Err(ConfigError::AttestedContractMismatch {
                    role: role.name.clone(),
                    declared: role.attested.clone(),
                    used: used_attested,
                });
            }
            let used_caveat = strip_ns(&surface.caveat, "caveat.");
            if used_caveat != role.caveat {
                return Err(ConfigError::CaveatContractMismatch {
                    role: role.name.clone(),
                    declared: role.caveat.clone(),
                    used: used_caveat,
                });
            }
        }
        Ok(())
    }
}

/// Resolve the listener transport from the mutually-exclusive `bind` /
/// `socket` keys (`docs/design-mint.md` § *Transport*):
///
/// - both set → [`ConfigError::ConflictingListener`];
/// - `socket` non-empty → UDS at that path (relative against cwd,
///   absolute verbatim — the `data_dir` rule);
/// - `socket` present but empty → UDS at `<data_dir>/mint.sock`;
/// - `bind` set → TCP at that parsed address;
/// - neither → TCP at [`DEFAULT_BIND`] (the production default;
///   selecting the socket is the deliberate act that makes an instance
///   local-only).
fn resolve_listener(
    bind: Option<&str>,
    socket: Option<&str>,
    data_dir: &Path,
) -> Result<Listener, ConfigError> {
    match (bind, socket) {
        (Some(_), Some(_)) => Err(ConfigError::ConflictingListener),
        (None, Some(s)) => Ok(Listener::Uds(if s.is_empty() {
            data_dir.join(DEFAULT_SOCKET_NAME)
        } else {
            PathBuf::from(s)
        })),
        (Some(b), None) => parse_bind(b).map(Listener::Tcp),
        (None, None) => parse_bind(DEFAULT_BIND).map(Listener::Tcp),
    }
}

fn parse_bind(value: &str) -> Result<SocketAddr, ConfigError> {
    value.parse().map_err(|source| ConfigError::BadBindAddr {
        value: value.to_owned(),
        source,
    })
}

/// Read a role's policy template from `<roles_dir>/<policy_file>`.
///
/// `policy_file` is parsed, not substring-checked: `Path::new` of it
/// must yield exactly one [`Component::Normal`]. That rejects path
/// separators, absolute paths, `.`, `..`, parent traversal, and the
/// empty string in one predicate, so a role name cannot reach outside
/// `roles_dir`. The guarantee is name-level — a symlink *inside*
/// `roles_dir` is still followed, but `roles_dir` shares the config's
/// custody, so its contents are the operator's own.
///
/// `explicit` selects the diagnostic: a bad *explicit* `policy_file` is
/// [`ConfigError::BadPolicyFileName`]; a bad *derived* `<name>.json`
/// (i.e. an unsafe role name) is [`ConfigError::BadDerivedPolicyName`].
fn read_policy(
    roles_dir: &Path,
    role: &str,
    policy_file: &str,
    explicit: bool,
) -> Result<(PathBuf, String), ConfigError> {
    let mut comps = Path::new(policy_file).components();
    let only = comps.next();
    if comps.next().is_some() || !matches!(only, Some(Component::Normal(_))) {
        let (role, value) = (role.to_owned(), policy_file.to_owned());
        return Err(if explicit {
            ConfigError::BadPolicyFileName { role, value }
        } else {
            ConfigError::BadDerivedPolicyName { role, value }
        });
    }
    let path = roles_dir.join(policy_file);
    let contents =
        std::fs::read_to_string(&path).map_err(|source| ConfigError::ReadPolicyFile {
            role: role.to_owned(),
            path: path.display().to_string(),
            source,
        })?;
    Ok((path, contents))
}

/// Path-A test harness (shared with `role.rs`'s unit tests): write each
/// role policy into a tempdir, splice an absolute `roles_dir` into the
/// TOML, then exercise the real [`Config::from_toml_str`] file-read
/// path. The tempdir only needs to outlive the parse — `policy` is read
/// eagerly — so it is dropped on return.
#[cfg(test)]
pub(crate) fn parse_for_test(toml: &str, roles: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let dir = tempfile::tempdir().expect("tempdir");
    for (name, body) in roles {
        std::fs::write(dir.path().join(name), body).expect("write role file");
    }
    let injected = toml.replacen(
        "[store]",
        &format!(
            "roles_dir = {:?}\n[store]",
            dir.path().display().to_string()
        ),
        1,
    );
    Config::from_toml_str(&injected)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
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

    #[test]
    fn parses_sample() {
        let c = parse_for_test(SAMPLE, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.audience, "mint");
        assert_eq!(c.store.bucket, "demo-bucket");
        assert_eq!(c.roles["volume-ro"].policy, "{}");
    }

    const ATTESTATION_SAMPLE: &str = r#"
audience = "mint"
attestation_location = "https://coord-b.example/v1/discharge"
[store]
bucket = "demo-bucket"
[[role]]
name = "volume-rw"
min_ttl_seconds = 60
max_ttl_seconds = 100
default_ttl_seconds = 100
policy_file = "volume-rw.json"
[role.attestation]
mode = "rw-self"
[[role]]
name = "coord-base"
min_ttl_seconds = 60
max_ttl_seconds = 100
default_ttl_seconds = 100
policy_file = "coord-base.json"
"#;

    #[test]
    fn attestation_mode_and_location_resolve_per_role() {
        let c = parse_for_test(
            ATTESTATION_SAMPLE,
            &[("volume-rw.json", "{}"), ("coord-base.json", "{}")],
        )
        .expect("parse");
        assert_eq!(
            c.attestation_location.as_deref(),
            Some("https://coord-b.example/v1/discharge")
        );
        // The declaring role carries its opaque mode; a role with no
        // [role.attestation] carries none.
        assert_eq!(
            c.roles["volume-rw"].attestation_mode.as_deref(),
            Some("rw-self")
        );
        assert_eq!(c.roles["coord-base"].attestation_mode, None);
    }

    #[test]
    fn attestation_role_without_location_is_rejected_at_load() {
        // A role asking for a discharge mint cannot stamp (no authority
        // location) would mint a dead credential; load fails closed.
        let toml = ATTESTATION_SAMPLE.replace(
            "attestation_location = \"https://coord-b.example/v1/discharge\"\n",
            "",
        );
        assert!(matches!(
            parse_for_test(&toml, &[("volume-rw.json", "{}"), ("coord-base.json", "{}")]),
            Err(ConfigError::AttestationWithoutLocation { role }) if role == "volume-rw"
        ));
    }

    /// `[env]` block — env-table parsing, the scalar guard (load-time),
    /// and the env-key surface check (seal-authoring gate).
    const ENV_SAMPLE: &str = r#"
audience = "mint"
[store]
bucket = "state-bucket"
[env]
bucket = "data-bucket"
[[role]]
name = "r"
min_ttl_seconds = 60
max_ttl_seconds = 100
default_ttl_seconds = 100
policy_file = "r.json"
"#;

    #[test]
    fn env_values_are_parsed_and_separate_from_store() {
        let c =
            parse_for_test(ENV_SAMPLE, &[("r.json", r#"{"b":"{{env.bucket}}"}"#)]).expect("parse");
        // The store bucket and the template-facing env bucket are
        // independent values, even when set to the same string elsewhere.
        assert_eq!(c.store.bucket, "state-bucket");
        assert_eq!(c.env["bucket"], "data-bucket");
        // A template referencing a defined key satisfies the seal gate.
        assert!(c.validate_policy_surface().is_ok());
    }

    #[test]
    fn undefined_env_key_passes_load_but_fails_seal_validation() {
        // Config load tolerates a template referencing an undefined env
        // key — serving renders the sealed surface, decoupled from the
        // live config, so this must not block startup. The surface check
        // that gates seal authoring is what rejects it.
        let cfg = parse_for_test(ENV_SAMPLE, &[("r.json", r#"{"r":"{{env.region}}"}"#)])
            .expect("load tolerates an undefined env-key reference");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::UndefinedEnvKey { key, .. }) if key == "region"
        ));
    }

    #[test]
    fn malformed_token_passes_load_but_fails_seal_validation() {
        // An engine-ism the renderer would fail closed on is caught at
        // seal authoring, not deferred to first render. Like the env-key
        // check, config load tolerates it (serving is decoupled).
        let cfg = parse_for_test(ENV_SAMPLE, &[("r.json", r#"{"r":"{{#each items}}"}"#)])
            .expect("load tolerates a malformed token");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::MalformedPolicyToken { token, .. }) if token == "{{#each items}}"
        ));
    }

    #[test]
    fn non_json_template_passes_load_but_fails_seal_validation() {
        // A token that escaped its string slot makes the template invalid
        // JSON; the seal gate rejects it before it can ever be rendered.
        let cfg = parse_for_test(ENV_SAMPLE, &[("r.json", r#"{"r":[{{attested.volume}}]}"#)])
            .expect("load tolerates a non-JSON template");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::PolicyNotJson { role, .. }) if role == "r"
        ));
    }

    /// A single-role config whose `[role.template]` contract lines (and
    /// policy template body) the test supplies, for the contract-surface
    /// checks. An empty `contract` omits the subtable entirely.
    fn contract_toml(contract: &str) -> String {
        let block = if contract.is_empty() {
            String::new()
        } else {
            format!("[role.template]\n{contract}\n")
        };
        format!(
            r#"
audience = "mint"
[store]
bucket = "state-bucket"
[env]
bucket = "data-bucket"
[[role]]
name = "r"
min_ttl_seconds = 60
max_ttl_seconds = 100
default_ttl_seconds = 100
policy_file = "r.json"
{block}"#
        )
    }

    #[test]
    fn declared_contract_matching_template_passes_seal() {
        let cfg = parse_for_test(
            &contract_toml(
                r#"attested = ["volume"]
caveat = ["sub"]"#,
            ),
            &[("r.json", r#"{"r":"{{attested.volume}}/{{caveat.sub}}"}"#)],
        )
        .expect("parse");
        assert!(cfg.validate_policy_surface().is_ok());
        // The declaration is canonicalised (sorted+deduped) at load.
        assert_eq!(cfg.roles["r"].attested, vec!["volume".to_string()]);
        assert_eq!(cfg.roles["r"].caveat, vec!["sub".to_string()]);
    }

    #[test]
    fn attested_token_typo_fails_seal_against_declaration() {
        // The declared name is `volume`; the template typos it as `volm`.
        // Caught at publish, not at the first request's render-time 500.
        let cfg = parse_for_test(
            &contract_toml(r#"attested = ["volume"]"#),
            &[("r.json", r#"{"r":"{{attested.volm}}"}"#)],
        )
        .expect("load tolerates a contract mismatch");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::AttestedContractMismatch { declared, used, .. })
                if declared == ["volume"] && used == ["volm"]
        ));
    }

    #[test]
    fn undeclared_attested_token_fails_seal() {
        // A template that substitutes an `attested` name the role never
        // declared is rejected — the declaration is the authoritative set.
        let cfg = parse_for_test(
            &contract_toml(""),
            &[("r.json", r#"{"r":"{{attested.volume}}"}"#)],
        )
        .expect("load tolerates a contract mismatch");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::AttestedContractMismatch { declared, used, .. })
                if declared.is_empty() && used == ["volume"]
        ));
    }

    #[test]
    fn declared_attested_name_outside_registry_fails_seal() {
        // `declared ⊆ authoritative`: a declared attested name not in the
        // closed ATTESTABLE registry is rejected at publish.
        let cfg = parse_for_test(
            &contract_toml(r#"attested = ["region"]"#),
            &[("r.json", r#"{"r":"{{attested.region}}"}"#)],
        )
        .expect("load tolerates a contract that fails the surface check");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::UnknownAttestedKey { key, .. }) if key == "region"
        ));
    }

    #[test]
    fn dropped_caveat_binding_fails_seal() {
        // The security-relevant omission: a role declares it must scope by
        // the MAC-verified `sub`, but the template forgets `{{caveat.sub}}`.
        // The seal refuses to pin a template that drops the binding.
        let cfg = parse_for_test(
            &contract_toml(r#"caveat = ["sub"]"#),
            &[("r.json", r#"{"r":"{{env.bucket}}/*"}"#)],
        )
        .expect("load tolerates a contract mismatch");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::CaveatContractMismatch { declared, used, .. })
                if declared == ["sub"] && used.is_empty()
        ));
    }

    #[test]
    fn unknown_mint_key_fails_seal() {
        // `mint.*` is closed to the server-computed set; an unknown key
        // fails at publish rather than at render.
        let cfg = parse_for_test(
            &contract_toml(""),
            &[("r.json", r#"{"r":"{{mint.bogus}}"}"#)],
        )
        .expect("load tolerates an unknown mint key");
        assert!(matches!(
            cfg.validate_policy_surface(),
            Err(ConfigError::UnknownMintKey { key, .. }) if key == "bogus"
        ));
    }

    #[test]
    fn non_scalar_env_value_is_rejected() {
        let bad = ENV_SAMPLE.replace(r#"bucket = "data-bucket""#, r#"bucket = ["a", "b"]"#);
        let err = parse_for_test(&bad, &[("r.json", "{}")]);
        assert!(matches!(
            err,
            Err(ConfigError::NonScalarEnv { key }) if key == "bucket"
        ));
    }

    #[test]
    fn rejects_inverted_ttl_bounds() {
        let bad = SAMPLE.replace("max_ttl_seconds = 2592000", "max_ttl_seconds = 10");
        assert!(matches!(
            parse_for_test(&bad, &[("volume-ro.json", "{}")]),
            Err(ConfigError::BadTtlBounds { .. })
        ));
    }

    #[test]
    fn rejects_policy_file_traversal() {
        // Name validation fires before any read, so roles_dir is never
        // touched — no file is written.
        for evil in ["../escape.json", "/etc/passwd", "a/b.json", "..", "."] {
            let toml = SAMPLE
                .replace("[store]", "roles_dir = \"mint_roles\"\n[store]")
                .replace("volume-ro.json", evil);
            assert!(
                matches!(
                    Config::from_toml_str(&toml),
                    Err(ConfigError::BadPolicyFileName { .. })
                ),
                "expected BadPolicyFileName for {evil:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_policy_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let toml = SAMPLE.replace(
            "[store]",
            &format!(
                "roles_dir = {:?}\n[store]",
                dir.path().display().to_string()
            ),
        );
        assert!(matches!(
            Config::from_toml_str(&toml),
            Err(ConfigError::ReadPolicyFile { .. })
        ));
    }

    /// Inject a config block (e.g. `[demo_auth]`) before the first
    /// `[[role]]` in SAMPLE. Injecting at `[store]` would land
    /// `parse_for_test`'s `roles_dir = ...` line inside the injected
    /// table; injecting at `[[role]]` keeps every key in the right table.
    fn with_block(s: &str, block: &str) -> String {
        s.replacen("[[role]]", &format!("{block}\n\n[[role]]"), 1)
    }

    #[test]
    fn demo_auth_block_and_auth_location_are_parsed() {
        // `auth_location` is a top-level scalar, so it must precede the
        // first `[table]` header; `[demo_auth]` injects before `[[role]]`.
        let toml = with_block(SAMPLE, "[demo_auth]\nenabled = true").replacen(
            "audience = \"mint\"",
            "audience = \"mint\"\nauth_location = \"https://auth.example/v1/discharge\"",
            1,
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        let demo = c.demo_auth.expect("demo_auth present");
        assert!(demo.enabled);
        assert!(demo.socket.is_some(), "socket resolves when enabled");
        assert_eq!(
            c.auth_location.expect("auth_location present"),
            "https://auth.example/v1/discharge"
        );
    }

    #[test]
    fn demo_auth_enabled_defaults_to_false() {
        let toml = with_block(SAMPLE, "[demo_auth]\nsocket = \"x.sock\"");
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        let demo = c.demo_auth.expect("demo_auth present");
        assert!(!demo.enabled);
        assert!(demo.socket.is_none(), "socket ignored when disabled");
    }

    #[test]
    fn policy_file_defaults_to_name_json() {
        // Drop the explicit policy_file: it must derive `<name>.json`.
        let toml = SAMPLE.replace("policy_file = \"volume-ro.json\"\n", "");
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.roles["volume-ro"].policy, "{}");
    }

    #[test]
    fn listener_defaults_to_tcp_8085() {
        let c = parse_for_test(SAMPLE, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.listener, Listener::Tcp("127.0.0.1:8085".parse().unwrap()));
    }

    #[test]
    fn explicit_bind_is_parsed() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nbind = \"0.0.0.0:9000\"",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.listener, Listener::Tcp("0.0.0.0:9000".parse().unwrap()));
    }

    #[test]
    fn bad_bind_is_rejected() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nbind = \"not-an-addr\"",
        );
        assert!(matches!(
            parse_for_test(&toml, &[("volume-ro.json", "{}")]),
            Err(ConfigError::BadBindAddr { .. })
        ));
    }

    #[test]
    fn socket_path_selects_uds_verbatim() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nsocket = \"/run/mint.sock\"",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(c.listener, Listener::Uds(PathBuf::from("/run/mint.sock")));
    }

    #[test]
    fn dial_url_maps_each_listener_shape() {
        assert_eq!(
            Listener::Uds(PathBuf::from("/run/mint.sock")).dial_url(),
            "unix:/run/mint.sock"
        );
        // An explicit address dials verbatim.
        assert_eq!(
            Listener::Tcp("10.0.0.5:9000".parse().unwrap()).dial_url(),
            "http://10.0.0.5:9000"
        );
        // A wildcard bind is rewritten to loopback — it is not dialable.
        assert_eq!(
            Listener::Tcp("0.0.0.0:9000".parse().unwrap()).dial_url(),
            "http://127.0.0.1:9000"
        );
        assert_eq!(
            Listener::Tcp("[::]:9000".parse().unwrap()).dial_url(),
            "http://[::1]:9000"
        );
    }

    #[test]
    fn default_mint_socket_is_under_default_data_dir() {
        assert_eq!(default_mint_socket(), PathBuf::from("mint_data/mint.sock"));
    }

    #[test]
    fn empty_socket_selects_uds_at_default_under_data_dir() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\ndata_dir = \"/var/lib/mint\"\nsocket = \"\"",
        );
        let c = parse_for_test(&toml, &[("volume-ro.json", "{}")]).expect("parse");
        assert_eq!(
            c.listener,
            Listener::Uds(PathBuf::from("/var/lib/mint/mint.sock"))
        );
    }

    #[test]
    fn bind_and_socket_together_are_rejected() {
        let toml = SAMPLE.replace(
            "audience = \"mint\"",
            "audience = \"mint\"\nbind = \"127.0.0.1:8085\"\nsocket = \"/run/mint.sock\"",
        );
        assert!(matches!(
            parse_for_test(&toml, &[("volume-ro.json", "{}")]),
            Err(ConfigError::ConflictingListener)
        ));
    }

    #[test]
    fn unsafe_role_name_rejected_when_derived() {
        // No explicit policy_file, so the unsafe name flows into the
        // derived filename and must be caught — distinctly from an
        // explicit bad policy_file.
        let toml = SAMPLE
            .replace("policy_file = \"volume-ro.json\"\n", "")
            .replace("[store]", "roles_dir = \"mint_roles\"\n[store]")
            .replace("name = \"volume-ro\"", "name = \"../escape\"");
        assert!(matches!(
            Config::from_toml_str(&toml),
            Err(ConfigError::BadDerivedPolicyName { .. })
        ));
    }
}
