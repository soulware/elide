//! mint entry point (`docs/design-mint.md` § *Reference client &
//! demo*). clap-derived CLI.
//!
//! `serve` runs the verification/vending HTTP surface against Tigris:
//! self-vended `mint-rw` keypair for `_mint/*` data-plane I/O and a
//! real `TigrisMinter` for `/v1/assume-role`. There is no in-process
//! dev backend; test code that needs a Store without a cloud
//! dependency uses `Store::open_in_memory` / `Store::open_local`
//! directly, outside the `serve` path.
//!
//! `invite` / `enroll` are the operator side. The networked
//! `mint client` (the caller's half of the flow) is the staged tail.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use rand_core::{OsRng, RngCore};

use mint::audit::AuditLog;
use mint::config::{Config, Listener};
use mint::http::{AppState, router};
use mint::iam::KeypairMinter;
use mint::state::Store;
use mint::tigris::TigrisMinter;

#[derive(Parser)]
#[command(about = "mint: macaroon-authenticated scoped-credential vending for Tigris")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the verification/vending HTTP service.
    Serve {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// TCP `host:port` override. Forces the TCP transport, taking
        /// precedence over the config's `bind`/`socket`. Omit to use
        /// the listener the config resolves to.
        #[arg(long)]
        bind: Option<SocketAddr>,
    },
    /// Operator: log in at the auth service, storing the session that
    /// gates discharge issuance (`<data_dir>/cli-session`).
    ///
    /// The demo auth role accepts any subject with no password; the
    /// session it returns is the gate on `/v1/discharge`, not an
    /// identity. Re-run when the session lapses (~7 days).
    Login {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// Opaque operator subject, stamped into issued discharges for
        /// audit. Any value is accepted in the demo.
        #[arg(long, default_value = "operator")]
        subject: String,
    },
    /// Print the invite macaroon (reusable, non-expiring).
    ///
    /// The macaroon goes to stdout for piping; diagnostics to stderr.
    Invite {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// Draw a new invite nonce first, cancelling in-flight
        /// enrollments (outstanding credentials are unaffected).
        #[arg(long)]
        rotate: bool,
    },
    /// Operator: inspect and approve pending enrollments.
    Enroll {
        #[command(subcommand)]
        cmd: EnrollCmd,
    },
    /// Operator: inspect the configured role inventory (read-only).
    Role {
        #[command(subcommand)]
        cmd: RoleCmd,
    },
    /// Operator: stage a new template seal under the current keyring,
    /// to be published on the next `mint serve` startup.
    ///
    /// Reads `roles_dir/` + `mint.toml`, hashes each role's policy
    /// template, signs the manifest under
    /// `<data_dir>/root_keys/current`, and writes the result to
    /// `<data_dir>/pending-seal.json` (mode 0600, atomic). No bucket
    /// I/O — `mint serve` performs the PUT on its next start, with
    /// semantic-equality reconcile against whatever is already in
    /// `_mint/templates/seal.json`.
    Seal {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
    },
    /// Reference client — the caller's half of the flow.
    Client {
        /// Identity + received-macaroon directory (default
        /// `./mint_client`, analogous to the server's `./mint_data`).
        #[arg(long)]
        client_dir: Option<PathBuf>,
        #[command(subcommand)]
        cmd: ClientCmd,
    },
}

#[derive(Subcommand)]
enum ClientCmd {
    /// Generate a fresh `client.key` / `client.pub` identity pair.
    Keygen {
        /// Overwrite an existing identity (a key is an identity —
        /// off by default).
        #[arg(long)]
        force: bool,
    },
    /// Print this identity's `cnf` value + fingerprint (what the
    /// operator compares out of band before `enroll approve`).
    Fingerprint,
    /// Attenuate the invite macaroon with `sub`/`cnf`, enrol, and
    /// save the returned credential ticket.
    Enroll {
        /// mint endpoint: `http(s)://host:port` (TCP) or
        /// `unix:<socket-path>` (the single-host UDS shape).
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        url: String,
        /// Opaque principal id — the `sub` (typically a ULID).
        #[arg(long)]
        id: String,
        /// Filename (under the client dir) to write the credential
        /// ticket to.
        #[arg(long, default_value_t = mint::client::CREDENTIAL_TICKET_FILE.to_string())]
        out: String,
        /// Invite macaroon: the macaroon text inline, a file path,
        /// or `-` for stdin.
        #[arg(value_name = "INVITE")]
        invite: String,
    },
    /// Exchange the credential ticket for the credential (after
    /// approval). Exits 2 while still awaiting operator approval.
    Exchange {
        /// mint endpoint: `http(s)://host:port` (TCP) or
        /// `unix:<socket-path>` (the single-host UDS shape).
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        url: String,
        /// Role to exchange the ticket for. One credential per role —
        /// run `exchange` once per role you are authorized for.
        #[arg(long)]
        role: String,
        /// Credential-ticket filename (under the client dir) to present.
        #[arg(long = "in", default_value_t = mint::client::CREDENTIAL_TICKET_FILE.to_string())]
        in_file: String,
        /// Filename (under the client dir) to write the credential to.
        /// Defaults to `credentials/<role>`.
        #[arg(long)]
        out: Option<String>,
    },
    /// Inspect the per-role credentials held on disk (local-only).
    Credential {
        #[command(subcommand)]
        cmd: CredentialCmd,
    },
    /// Assume a role with the held credential; prints the keypair JSON.
    AssumeRole {
        /// mint endpoint: `http(s)://host:port` (TCP) or
        /// `unix:<socket-path>` (the single-host UDS shape).
        #[arg(long, default_value = "http://127.0.0.1:8085")]
        url: String,
        /// Credential filename (under the client dir) to exercise.
        /// Defaults to `credentials/<role>`.
        #[arg(long = "in")]
        in_file: Option<String>,
        /// PoP-signed request body as a JSON object: inline, `@file`,
        /// or `-` for stdin. Opaque pass-through into `request.*` —
        /// `ts`/`role`/`ttl_seconds` are client-owned and ignored here.
        #[arg(long, value_name = "JSON|@FILE|-")]
        request: Option<String>,
        /// Narrowing caveat to attenuate the credential with (repeatable).
        /// Vocabulary-agnostic — e.g. `--caveat elide:Volume=01VOL`.
        #[arg(long = "caveat", value_name = "NAME=VALUE")]
        caveat: Vec<String>,
        #[arg(long, default_value_t = 900)]
        ttl: u64,
        /// Role name from the mint config.
        #[arg(value_name = "ROLE")]
        role: String,
    },
}

#[derive(Subcommand)]
enum CredentialCmd {
    /// List held per-role credentials: role, role caveat, caveat count, sub.
    List,
    /// Narrate one role credential's caveat chain.
    Inspect {
        /// Role whose credential to inspect (`credentials/<role>`).
        #[arg(value_name = "ROLE")]
        role: String,
    },
}

#[derive(Subcommand)]
enum RoleCmd {
    /// List configured roles: name, required caveats, TTL bounds.
    List {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
    },
    /// Show one role: TTL bounds, required caveats, policy source, and
    /// the raw policy template + the substitution surface it references.
    Inspect {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// Role name from the mint config.
        #[arg(value_name = "ROLE")]
        name: String,
    },
}

#[derive(Subcommand)]
enum EnrollCmd {
    /// List enrollments — pending and approved — with state as a
    /// column (`docs/design-mint.md` § *Reference client & demo*).
    List {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
    },
    /// Approve a pending record by its `sub`.
    ///
    /// Prints the record's `cnf` fingerprint and asks for an
    /// interactive y/N confirmation: confirming **is** the trust anchor
    /// (it must match what the client reports via
    /// `mint client fingerprint`). `--yes` skips the prompt for
    /// automation.
    Approve {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// The opaque principal id (typically a ULID).
        sub: String,
        /// Skip the interactive confirmation (automation only — you are
        /// asserting the fingerprint was verified out of band).
        #[arg(long)]
        yes: bool,
    },
    /// Revoke an approved-client registry entry.
    ///
    /// After this, the next `/v1/enroll` for `<sub>` falls back to the
    /// slow path: a fresh pending record requiring a fresh operator
    /// approval. Outstanding credentials are unaffected.
    Revoke {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// The opaque principal id whose registry entry to delete.
        sub: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Command::Serve { config, bind } => serve(&config, bind).await,
        Command::Login { config, subject } => login(&config, &subject).await,
        Command::Invite { config, rotate } => invite(&config, rotate).await,
        Command::Enroll { cmd } => match cmd {
            EnrollCmd::List { config } => enroll_list(&config).await,
            EnrollCmd::Approve { config, sub, yes } => enroll_approve(&config, &sub, yes).await,
            EnrollCmd::Revoke { config, sub } => enroll_revoke(&config, &sub).await,
        },
        Command::Seal { config } => seal(&config).await,
        Command::Role { cmd } => match cmd {
            RoleCmd::List { config } => role_list(&config),
            RoleCmd::Inspect { config, name } => role_inspect(&config, &name),
        },
        Command::Client { client_dir, cmd } => client_cmd(client_dir, cmd).await,
    }
}

async fn client_cmd(
    client_dir: Option<PathBuf>,
    cmd: ClientCmd,
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = mint::client::client_dir(client_dir);
    match cmd {
        ClientCmd::Keygen { force } => {
            let (cnf, fp) = mint::client::keygen(&dir, force)?;
            eprintln!("wrote {}/client.key (0600) + client.pub", dir.display());
            println!("cnf={cnf}");
            println!("fingerprint={fp}");
            Ok(())
        }
        ClientCmd::Fingerprint => {
            let (cnf, fp) = mint::client::identity(&dir)?;
            println!("cnf={cnf}");
            println!("fingerprint={fp}");
            Ok(())
        }
        ClientCmd::Enroll {
            url,
            invite,
            id,
            out,
        } => {
            mint::client::enroll(&dir, &url, &invite, &id, &out).await?;
            eprintln!("  (compare the fingerprint out of band before approving)");
            Ok(())
        }
        ClientCmd::Exchange {
            url,
            role,
            in_file,
            out,
        } => {
            let out = out.unwrap_or_else(|| mint::client::credential_path(&role));
            if mint::client::exchange(&dir, &url, &in_file, &role, &out).await? {
                Ok(())
            } else {
                eprintln!(
                    "  re-run `mint client exchange --role {role}` once the operator approves"
                );
                std::process::exit(2);
            }
        }
        ClientCmd::Credential { cmd } => match cmd {
            CredentialCmd::List => Ok(mint::client::credential_list(&dir)?),
            CredentialCmd::Inspect { role } => Ok(mint::client::credential_inspect(&dir, &role)?),
        },
        ClientCmd::AssumeRole {
            url,
            in_file,
            request,
            caveat,
            ttl,
            role,
        } => {
            let in_file = in_file.unwrap_or_else(|| mint::client::credential_path(&role));
            let kp = mint::client::assume_role(
                &dir,
                &url,
                &role,
                request.as_deref(),
                &caveat,
                ttl,
                &in_file,
            )
            .await?;
            println!("{kp}");
            Ok(())
        }
    }
}

fn load(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    Ok(Config::load(path)?)
}

/// Bits a long-running `serve` against the Tigris backend needs to
/// keep the bucket-backed store alive past the initial `mint-rw`
/// keypair's `DateLessThan`. Operator one-shots drop this and let
/// their keypair expire by itself.
struct TigrisHandles {
    minter: Arc<dyn KeypairMinter>,
    provider: Arc<mint::mint_rw::SwappableAwsProvider>,
    expiration: chrono::DateTime<chrono::Utc>,
}

/// Open the Tigris-backed persisted-state store: self-vend a
/// `mint-rw` keypair, route `_mint/*` I/O through it, load the
/// keyring from `<data_dir>/root_keys/` (migrating any legacy
/// singleton). Requires an `AWS_*` admin credential in the
/// environment. The returned [`TigrisHandles`] lets `serve` spawn a
/// background refresh of the `mint-rw` keypair before its
/// `DateLessThan`.
///
/// There is no in-process "local" alternative: dev shapes point at a
/// real S3-compatible target (Tigris free tier, MinIO). Test code
/// constructs `Store::open_in_memory` / `Store::open_local` directly,
/// outside this path.
/// Mint the **CLI service token** and its machine keypair at first
/// start, writing `<data_dir>/cli-token` + `<data_dir>/cli-token.key`
/// (`docs/design-mint.md` § *CLI service token*). The operator CLI on
/// the same host reads both: the token is the admin-plane primary, the
/// key is what it signs proof-of-possession with. Mint generates the
/// keypair here because the token is minted before any operator key
/// exists.
///
/// Requires `[auth]` (so `K_M-A` is present): admin endpoints are
/// discharge-gated, so a mint with no auth service has no admin plane
/// and no cli-token to mint — that case returns `Ok(())` and writes
/// nothing. Refuses to overwrite; first-start detection is the
/// caller's job.
async fn write_cli_token(cfg: &Config, store: &Store) -> Result<(), Box<dyn std::error::Error>> {
    let Some(k_m_a) = store.k_m_a().copied() else {
        return Ok(()); // no auth → no admin plane → no cli-token
    };
    let auth = cfg
        .auth
        .as_ref()
        .ok_or("cli-token: K_M-A present without an [auth] block")?;
    let org_id = store.org_id().unwrap_or("demo").to_string();

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let cnf = mint::pop::cnf_value(&seed);

    let keyring = store.keyring().await;
    let mac = mint::issuance::mint_cli_token(
        &keyring,
        &k_m_a,
        &cfg.audience,
        &cnf,
        &org_id,
        &auth.endpoint,
    );

    write_0600(&cfg.data_dir.join("cli-token"), mac.encode().as_bytes())?;
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    write_0600(&cfg.data_dir.join("cli-token.key"), seed_hex.as_bytes())?;
    tracing::info!(
        data_dir = %cfg.data_dir.display(),
        "wrote cli-token + cli-token.key (admin-plane identity for the local operator CLI)"
    );
    Ok(())
}

/// Atomic 0600 write — tmp file, chmod, rename.
fn write_0600(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

async fn open_store(cfg: &Config) -> Result<(Store, TigrisHandles), Box<dyn std::error::Error>> {
    let admin = cfg.admin.as_ref().ok_or(
        "mint serve requires a Tigris admin credential in the environment \
         (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)",
    )?;
    let minter: Arc<dyn KeypairMinter> = Arc::new(TigrisMinter::new(admin)?);
    let (s3, provider, expiration) = mint::mint_rw::build_s3_with_mint_rw(
        &minter,
        &cfg.tenant.bucket,
        cfg.tenant.endpoint.as_deref(),
        cfg.tenant.region.as_deref(),
    )
    .await?;
    std::fs::create_dir_all(&cfg.data_dir)?;
    let legacy = cfg.data_dir.join("root_key");
    let mut store =
        Store::open_remote(s3, &cfg.data_dir.join("root_keys"), Some(&legacy), None).await?;
    // K_M-A is needed wherever `[auth]` is configured (TPC verification
    // and demo discharge issuance). Demo mode generates it locally;
    // production loads what auth-service enrollment provisioned.
    // K_session is purely the colocated demo auth role's session root —
    // generated only under `demo_enabled`.
    if let Some(auth) = &cfg.auth {
        store.init_k_m_a(&cfg.data_dir, auth.demo_enabled)?;
        if auth.demo_enabled {
            store.init_k_session(&cfg.data_dir)?;
        }
    }
    Ok((
        store,
        TigrisHandles {
            minter,
            provider,
            expiration,
        },
    ))
}

async fn serve(
    config: &Path,
    bind_override: Option<SocketAddr>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Arc::new(load(config)?);

    // First start = keyring directory empty before open_store.
    // open_store generates `root_keys/0000` if absent, so checking
    // before is the only reliable signal. The cli-token is minted
    // exactly once, on this transition; later starts never re-create
    // it (the existing file is left in place).
    let is_first_start = !config.data_dir.join("root_keys").join("0000").exists()
        && !config.data_dir.join("root_key").exists();

    let (store, tigris) = open_store(&config).await?;
    let store = Arc::new(store);

    // CLI service token (`docs/design-mint.md` § *CLI service token*):
    // the admin-plane primary + machine key the local operator CLI
    // reads. Written once on first start when an auth service is
    // configured.
    if is_first_start && !config.data_dir.join("cli-token").exists() {
        write_cli_token(&config, &store).await?;
    }

    // Template seal: publish any pending file on disk, then verify
    // the canonical seal matches local config + template hashes.
    // Refuse-closed on any divergence (`docs/design-mint-template-seal.md`).
    mint::seal::publish_pending_and_verify(&config, &store)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // `assume-role` reuses the `TigrisMinter` we already built for
    // `mint-rw` vending. Long-running serve also spawns a background
    // task that re-mints `mint-rw` before its `DateLessThan` and the
    // invite-cache refresher.
    let _refresh = mint::mint_rw::spawn_refresh(
        tigris.minter.clone(),
        config.tenant.bucket.clone(),
        tigris.provider,
        tigris.expiration,
    );
    let minter: Arc<dyn KeypairMinter> = tigris.minter;
    // Steady-state /v1/enroll reads the invite from a local cache that
    // a background task keeps fresh with `If-None-Match` (~30 s, cheap
    // 304 on the common path). Rotation by this process updates the
    // cache eagerly; this task picks up rotations by any other instance.
    let _invite_refresh = store.spawn_invite_refresh(mint::state::INVITE_REFRESH_INTERVAL);
    tracing::info!(
        audience = %config.audience,
        roles = config.roles.len(),
        data_dir = %config.data_dir.display(),
        roles_dir = %config.roles_dir.display(),
        "loaded config"
    );

    // An explicit --bind forces TCP, overriding the config's resolved
    // listener (the single-host TCP override). Otherwise the config's
    // bind/socket choice stands. Resolved before `config` moves into
    // the app state.
    let transport = match bind_override {
        Some(addr) => Listener::Tcp(addr),
        None => config.listener.clone(),
    };

    let state = AppState {
        config,
        minter,
        audit: Arc::new(AuditLog::new(Box::new(std::io::stdout()))),
        store,
    };

    // The mint role's app (admin routes are merged onto the same router
    // because they share the mint-listener; admin is a mint-internal
    // operator surface, not an auth-role concern).
    let mint_app = mint::admin::mount(router(state.clone()), state.clone());

    // The auth role lives on its own UDS when `[auth].demo_enabled =
    // true`. mint-as-auth is structurally not mint: separate listener,
    // separate router, no shared HTTP path. Production deploys run a
    // standalone auth-service binary instead — mint never opens this
    // socket without `demo_enabled`.
    let auth_socket = state
        .config
        .auth
        .as_ref()
        .and_then(|a| a.socket.clone())
        .filter(|_| state.config.auth.as_ref().is_some_and(|a| a.demo_enabled));

    let mint_listener: Pin<Box<dyn Future<Output = io::Result<()>> + Send>> = match transport {
        Listener::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(%addr, "mint listening (tcp)");
            Box::pin(async move { axum::serve(listener, mint_app).await })
        }
        Listener::Uds(path) => {
            // UDS idiom: clear the stale dentry, bind, then chmod
            // 0o666 so a non-root client can connect (the socket
            // inherits the binding process's umask otherwise).
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
            tracing::info!(path = %path.display(), "mint listening (uds)");
            Box::pin(async move { axum::serve(listener, mint_app).await })
        }
    };

    match auth_socket {
        Some(path) => {
            let auth_app = mint::auth::router(state);
            let _ = std::fs::remove_file(&path);
            let auth_listener = tokio::net::UnixListener::bind(&path)?;
            // Tighter mode than mint's listener: only the binding user
            // and group can fetch discharges. Demo-only; production
            // auth-service binds its own socket with its own policy.
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))?;
            tracing::info!(path = %path.display(), "auth listening (uds)");
            let auth_fut = async move { axum::serve(auth_listener, auth_app).await };
            // `try_join!` fails-fast: a fault on either listener
            // brings the process down. Both listeners are required for
            // a working demo, so partial-up is never the right state.
            tokio::try_join!(mint_listener, auth_fut)?;
        }
        None => {
            mint_listener.await?;
        }
    }
    Ok(())
}

/// Resolve the operator-side admin target from the config's listener.
/// `Listener::Uds(path)` is the production operator path; `Tcp` is
/// accepted for local-only setups (the admin routes are only mounted
/// when serve is bound to UDS, so a TCP-only deployment returns 404
/// and the command surfaces a clean error).
fn admin_target(cfg: &Config) -> mint::admin::AdminTarget<'_> {
    match &cfg.listener {
        Listener::Uds(p) => mint::admin::AdminTarget::Uds(p),
        Listener::Tcp(addr) => {
            // Construct a leaked &str for the lifetime of this CLI process —
            // safe because clap-parsed Config lives until main returns.
            let url: &'static str = Box::leak(format!("http://{addr}").into_boxed_str());
            mint::admin::AdminTarget::Tcp(url)
        }
    }
}

/// The demo auth socket the operator logs in / fetches discharges over.
/// Present only when `[auth].demo_enabled = true` — the only auth
/// backend that exists in-tree. Production runs a separate auth-service
/// binary; wiring the operator to that endpoint is out of scope here.
fn auth_socket(cfg: &Config) -> Result<PathBuf, Box<dyn std::error::Error>> {
    cfg.auth
        .as_ref()
        .and_then(|a| a.socket.clone())
        .ok_or_else(|| {
            "operator plane requires a colocated demo auth role \
             ([auth].demo_enabled = true); no auth socket is configured"
                .into()
        })
}

/// `mint login` — trivially authenticate at the demo auth role and
/// persist the session that gates discharge issuance.
async fn login(config: &Path, subject: &str) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load(config)?;
    let socket = auth_socket(&cfg)?;
    let session = mint::operator::login(&socket, subject).await?;
    mint::operator::save_session(&cfg.data_dir, &session)?;
    eprintln!(
        "logged in as {subject}; session saved to {}",
        cfg.data_dir.join(mint::operator::SESSION_FILE).display()
    );
    Ok(())
}

/// Assemble the operator's admin-plane authority for one CLI
/// invocation: load the cli-token + machine key, load the session
/// (`mint login`), and fetch a fresh wide discharge over the auth
/// socket. The returned discharge satisfies every admin verb; each
/// admin call attenuates its own `op` onto the cli-token.
async fn operator_session(
    cfg: &Config,
) -> Result<(mint::operator::Operator, mint::Macaroon), Box<dyn std::error::Error>> {
    let operator = mint::operator::Operator::load(&cfg.data_dir)?;
    let session = mint::operator::load_session(&cfg.data_dir)?;
    let socket = auth_socket(cfg)?;
    let discharge =
        mint::operator::fetch_discharge(&socket, &session, &operator.cid_b64()?).await?;
    Ok((operator, discharge))
}

async fn invite(config: &Path, rotate: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let (op, discharge) = operator_session(&config).await?;
    let target = admin_target(&config);
    let resp = if rotate {
        eprintln!("rotating invite nonce; in-flight enrollments cancelled");
        mint::admin::rotate_invite(target, &op, &discharge).await?
    } else {
        mint::admin::get_invite(target, &op, &discharge).await?
    };
    eprintln!(
        "invite macaroon for audience={} (non-expiring, reusable)",
        config.audience
    );
    println!("{}", resp.macaroon);
    Ok(())
}

async fn enroll_list(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let (op, discharge) = operator_session(&config).await?;
    let rows = mint::admin::list_enrollments(admin_target(&config), &op, &discharge).await?;
    if rows.is_empty() {
        eprintln!("no enrollments");
        return Ok(());
    }
    println!(
        "{:<28} {:<9} {:<18} {:<16} {:>7} FLAGS",
        "SUB", "STATE", "FINGERPRINT", "PEER", "AGE(s)"
    );
    for r in rows {
        println!(
            "{:<28} {:<9} {:<18} {:<16} {:>7} {}",
            r.sub,
            r.state,
            r.fingerprint,
            r.peer_ip.as_deref().unwrap_or("-"),
            r.age_seconds,
            if r.anomalous_pub { "ANOMALOUS-PUB" } else { "" }
        );
    }
    Ok(())
}

async fn enroll_approve(
    config: &Path,
    sub: &str,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let config = load(config)?;
    let (op, discharge) = operator_session(&config).await?;
    let target = admin_target(&config);
    // Read the pending row from the daemon so the operator's
    // fingerprint check matches what's on the server side, not what
    // the CLI thinks should be there.
    let rows = mint::admin::list_enrollments(target, &op, &discharge).await?;
    let pending = rows
        .into_iter()
        .find(|r| r.sub == sub && r.state == "pending")
        .ok_or_else(|| format!("no pending enrollment for sub {sub}"))?;

    eprintln!("pending enrollment:");
    eprintln!("  sub:         {sub}");
    eprintln!("  fingerprint: {}", pending.fingerprint);
    eprintln!(
        "  peer:        {}",
        pending.peer_ip.as_deref().unwrap_or("-")
    );
    eprintln!("  age:         {}s", pending.age_seconds);

    if !yes {
        eprint!(
            "Approve? This authorises the binding — the fingerprint must \
             match what the client reports (`mint client fingerprint`). [y/N] "
        );
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("not approved");
            std::process::exit(1);
        }
    }

    let req = mint::admin::ApproveRequest {
        sub: sub.to_owned(),
        pubkey: pending.pubkey,
    };
    let resp =
        mint::admin::approve_enrollment(admin_target(&config), &op, &discharge, &req).await?;
    eprintln!(
        "approved {sub} (registry entry written at {}; pending record deleted)",
        resp.approved_at
    );
    Ok(())
}

async fn enroll_revoke(config: &Path, sub: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let (op, discharge) = operator_session(&config).await?;
    let req = mint::admin::RevokeRequest {
        sub: sub.to_owned(),
    };
    let resp = mint::admin::revoke_enrollment(admin_target(&config), &op, &discharge, &req).await?;
    if resp.revoked {
        eprintln!("revoked approved/{sub}; next enroll requires fresh approval");
        Ok(())
    } else {
        Err(format!("no approved entry for sub {sub}").into())
    }
}

/// `mint seal` — stage a pending template seal at
/// `<data_dir>/pending-seal.json` to be published on the next
/// `mint serve` startup. Purely local: opens the keyring directly,
/// hashes each role's already-loaded policy bytes, MACs under the
/// current kid. No bucket I/O, no daemon dependency.
async fn seal(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let cfg = load(config_path)?;
    let keyring_dir = cfg.data_dir.join("root_keys");
    let legacy_singleton = cfg.data_dir.join("root_key");
    std::fs::create_dir_all(&cfg.data_dir)?;
    let keyring = mint::keyring::Keyring::open(&keyring_dir, Some(&legacy_singleton), None)
        .map_err(|e| -> Box<dyn std::error::Error> {
            format!("open keyring at {}: {e}", keyring_dir.display()).into()
        })?;
    let sealed_at = chrono::Utc::now().to_rfc3339();
    let seal = mint::seal::Seal::build_from_config(&cfg, &keyring, &sealed_at);
    let pending_path = cfg.data_dir.join("pending-seal.json");
    mint::seal::write_pending(&pending_path, &seal)?;
    eprintln!(
        "staged seal: kid={} sealed_at={} roles=[{}] → {}",
        seal.kid,
        seal.sealed_at,
        seal.roles
            .iter()
            .map(|(name, r)| format!("{name}:{}", &r.policy_blake3[..12]))
            .collect::<Vec<_>>()
            .join(", "),
        pending_path.display(),
    );
    eprintln!("publish via the next `mint serve` startup");
    Ok(())
}

fn role_list(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    if config.roles.is_empty() {
        eprintln!("no roles configured");
        return Ok(());
    }
    println!(
        "{:<24} {:>5} {:>7} {:>7} {:>7}  REQUIRED-CAVEATS",
        "NAME", "TPC", "MIN", "DEF", "MAX"
    );
    // config.roles is a BTreeMap, so iteration is name-sorted.
    for r in config.roles.values() {
        println!(
            "{:<24} {:>5} {:>7} {:>7} {:>7}  {}",
            r.name,
            if r.issues_with_tpc { "yes" } else { "no" },
            r.min_ttl_seconds,
            r.default_ttl_seconds,
            r.max_ttl_seconds,
            if r.required_caveats.is_empty() {
                "(none)".to_string()
            } else {
                r.required_caveats.join(", ")
            }
        );
    }
    Ok(())
}

fn role_inspect(config: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let role = config
        .roles
        .get(name)
        .ok_or_else(|| format!("no role {name} in config (see `mint role list`)"))?;
    eprintln!("role: {}", role.name);
    eprintln!(
        "  ttl_seconds:      min={} default={} max={}",
        role.min_ttl_seconds, role.default_ttl_seconds, role.max_ttl_seconds
    );
    eprintln!(
        "  required_caveats: {}",
        if role.required_caveats.is_empty() {
            "(none)".to_string()
        } else {
            role.required_caveats.join(", ")
        }
    );
    eprintln!(
        "  issues_with_tpc:  {}",
        if role.issues_with_tpc { "yes" } else { "no" }
    );
    eprintln!("  audience:         {}", config.audience);
    eprintln!("  tenant.bucket:    {}", config.tenant.bucket);
    eprintln!("  policy source:    {}", role.policy_path.display());

    // The policy is a request-parameterised template: there is no
    // single concrete grant to print, so show the substitution surface
    // (by trust provenance) + the raw template, not a rendering.
    let surface = mint::template::template_surface(&role.policy);
    eprintln!("  policy references:");
    for (label, vals) in [
        ("caveat (MAC-bound)", &surface.caveats),
        ("request (PoP-bound)", &surface.request),
        ("tenant (config)", &surface.tenant),
        ("system (mint-computed)", &surface.system),
    ] {
        if !vals.is_empty() {
            eprintln!("    {label}: {}", vals.join(", "));
        }
    }
    eprintln!("  policy template:");
    println!("{}", role.policy);
    Ok(())
}
