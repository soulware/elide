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
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
        config: PathBuf,
        /// TCP `host:port` to bind.
        #[arg(long)]
        bind: Option<SocketAddr>,
    },
    /// Log in at the auth service; store the session gating `/v1/discharge`.
    Login {
        /// Auth-service endpoint: `unix:<socket-path>` or
        /// `http(s)://host:port`.
        #[arg(long)]
        url: Option<String>,
        /// Derive the auth transport from a mint config's auth-role
        /// socket.
        #[arg(long, env = "MINT_CONFIG")]
        config: Option<PathBuf>,
        /// Opaque subject, stamped into issued discharges for audit.
        #[arg(long, default_value = "operator")]
        subject: String,
    },
    /// Log out, removing the per-user session.
    Logout,
    /// Print the invite macaroon (reusable, non-expiring).
    ///
    /// The macaroon goes to stdout for piping; diagnostics to stderr.
    Invite {
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
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
    /// Operator: seal the current role configuration.
    Seal {
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
        config: PathBuf,
    },
    /// Reference client — the caller's half of the flow.
    Client {
        /// Identity + received-macaroon directory (default `./mint_client`).
        #[arg(long)]
        client_dir: Option<PathBuf>,
        #[command(subcommand)]
        cmd: ClientCmd,
    },
}

#[derive(Subcommand)]
enum ClientCmd {
    /// Print this identity's `cnf` value + fingerprint.
    ///
    /// The operator compares this out of band before `enroll approve`. The
    /// identity is minted on first use, so this also creates it.
    Fingerprint,
    /// Attenuate the invite, enrol, and save the credential ticket.
    ///
    /// Attenuates the invite macaroon with `sub`/`cnf`.
    Enroll {
        /// UDS path of the local mint daemon.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Opaque principal id — the `sub`. Any path-safe string
        /// (`[A-Za-z0-9._-]`, ≤256 chars); not required to be a ULID.
        #[arg(value_name = "ID")]
        id: String,
        /// Filename (under the client dir) to write the credential
        /// ticket to.
        #[arg(long, default_value_t = mint::client::CREDENTIAL_TICKET_FILE.to_string())]
        out: String,
        /// Invite macaroon — the encoded string the operator gave you,
        /// passed inline.
        #[arg(value_name = "INVITE")]
        invite: String,
    },
    /// Exchange the credential ticket for the credential.
    ///
    /// Run after approval; exits 2 while still awaiting operator approval.
    Exchange {
        /// UDS path of the local mint daemon.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Credential-ticket filename (under the client dir) to present.
        #[arg(long = "in", default_value_t = mint::client::CREDENTIAL_TICKET_FILE.to_string())]
        in_file: String,
        /// Filename (under the client dir) to write the credential to.
        /// Defaults to `credentials/<role>`.
        #[arg(long)]
        out: Option<String>,
        /// Role to exchange the ticket for. One credential per role —
        /// run `exchange` once per role you are authorized for.
        #[arg(value_name = "ROLE")]
        role: String,
    },
    /// Inspect the per-role credentials held on disk (local-only).
    Credential {
        #[command(subcommand)]
        cmd: CredentialCmd,
    },
    /// Assume a role with the held credential; prints the keypair JSON.
    AssumeRole {
        /// UDS path of the local mint daemon.
        #[arg(long)]
        socket: Option<PathBuf>,
        /// Credential filename (under the client dir) to exercise.
        /// Defaults to `credentials/<role>`.
        #[arg(long = "in")]
        in_file: Option<String>,
        /// PoP-signed request body as an inline JSON object. Opaque
        /// pass-through into `req.*` — `ts`/`role`/`ttl_seconds` are
        /// client-owned and ignored here.
        #[arg(long, value_name = "JSON")]
        req: Option<String>,
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
    /// List roles: name, TTL bounds, and each role's state relative to
    /// the served seal (served / drifted / unsealed).
    List {
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
        config: PathBuf,
    },
    /// Show one role from the served seal: TTL bounds, policy source, the
    /// served policy template + its substitution surface, and any drift of
    /// the local config from the seal.
    Inspect {
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
        config: PathBuf,
        /// Role name from the mint config.
        #[arg(value_name = "ROLE")]
        name: String,
    },
}

#[derive(Subcommand)]
enum EnrollCmd {
    /// List enrollments — pending and enrolled — with state as a column.
    List {
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
        config: PathBuf,
    },
    /// Approve a pending record by its `sub`.
    Approve {
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
        config: PathBuf,
        /// The opaque principal id (any path-safe string; not required
        /// to be a ULID).
        sub: String,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Revoke a coordinator by its `sub` — kills every credential it
    /// holds and drops it to the operator-gated slow path.
    Revoke {
        #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
        config: PathBuf,
        /// The opaque principal id of the coordinator to revoke.
        sub: String,
        /// Skip the interactive confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Command::Serve { config, bind } => serve(&config, bind).await,
        Command::Login {
            url,
            config,
            subject,
        } => login(url, config, &subject).await,
        Command::Logout => logout(),
        Command::Invite { config, rotate } => invite(&config, rotate).await,
        Command::Enroll { cmd } => match cmd {
            EnrollCmd::List { config } => enroll_list(&config).await,
            EnrollCmd::Approve { config, sub, yes } => enroll_approve(&config, &sub, yes).await,
            EnrollCmd::Revoke { config, sub, yes } => enroll_revoke(&config, &sub, yes).await,
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
        ClientCmd::Fingerprint => {
            let (cnf, fp) = mint::client::identity(&dir)?;
            println!("cnf={cnf}");
            println!("fingerprint={fp}");
            Ok(())
        }
        ClientCmd::Enroll {
            socket,
            invite,
            id,
            out,
        } => {
            let transport = client_transport(socket)?;
            mint::client::enroll(&dir, &transport, &invite, &id, &out).await?;
            eprintln!("  (compare the fingerprint out of band before approving)");
            Ok(())
        }
        ClientCmd::Exchange {
            socket,
            role,
            in_file,
            out,
        } => {
            let transport = client_transport(socket)?;
            let out = out.unwrap_or_else(|| mint::client::credential_path(&role));
            if mint::client::exchange(&dir, &transport, &in_file, &role, &out).await? {
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
            socket,
            in_file,
            req,
            caveat,
            ttl,
            role,
        } => {
            let transport = client_transport(socket)?;
            let in_file = in_file.unwrap_or_else(|| mint::client::credential_path(&role));
            let kp = mint::client::assume_role(
                &dir,
                &transport,
                &role,
                req.as_deref(),
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

/// Resolve the UDS transport `mint client` dials. `--socket <path>`
/// wins; else the `MINT_CONFIG` listener socket (the client is
/// UDS-only, so a TCP-bound config is an error); else the default
/// `<data_dir>/mint.sock`.
fn client_transport(socket: Option<PathBuf>) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = socket {
        return Ok(Listener::Uds(path).dial_url());
    }
    if let Ok(cfg_path) = std::env::var("MINT_CONFIG") {
        return match Config::load_listener(Path::new(&cfg_path))? {
            uds @ Listener::Uds(_) => Ok(uds.dial_url()),
            Listener::Tcp(_) => Err(format!(
                "mint client is UDS-only but MINT_CONFIG ({cfg_path}) selects a TCP \
                 listener; pass --socket <path>"
            )
            .into()),
        };
    }
    Ok(Listener::Uds(mint::config::default_mint_socket()).dial_url())
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
/// Mint the **admin service token** and its machine keypair, writing
/// `<data_dir>/admin-service` + `<data_dir>/admin-service.key`
/// (`docs/design-mint.md` § *Admin service token*). The operator CLI on
/// the same host reads both: the token is the admin-plane primary, the
/// key is what it signs proof-of-possession with. Mint generates the
/// keypair here because the token is minted before any operator key
/// exists.
///
/// Requires `[auth]` (so `K_M-A` is present): admin endpoints are
/// discharge-gated, so a mint with no auth service has no admin plane
/// and no admin-service to mint — that case returns `Ok(())` and writes
/// nothing. The caller invokes this when either file is absent; both are
/// (re)written, so a partial pair (e.g. a crash mid-write) is repaired
/// with a fresh keypair.
async fn write_admin_service(
    cfg: &Config,
    store: &Store,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(k_m_a) = store.k_m_a().copied() else {
        return Ok(()); // no auth → no admin plane → no admin-service
    };
    let location = cfg
        .auth_location
        .as_deref()
        .ok_or("admin-service: K_M-A present without auth_location")?;
    let org_id = store.org_id().unwrap_or("demo").to_string();

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let cnf = mint::pop::cnf_value(&seed);

    let keyring = store.keyring().await;
    let mac = mint::issuance::mint_admin_service_token(
        &keyring,
        &k_m_a,
        &cfg.audience,
        &cnf,
        &org_id,
        location,
    );

    write_0600(&cfg.data_dir.join("admin-service"), mac.encode().as_bytes())?;
    let seed_hex: String = seed.iter().map(|b| format!("{b:02x}")).collect();
    write_0600(&cfg.data_dir.join("admin-service.key"), seed_hex.as_bytes())?;
    tracing::info!(
        data_dir = %cfg.data_dir.display(),
        "wrote admin-service + admin-service.key (admin-plane identity for the local operator CLI)"
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
        &cfg.store.bucket,
        cfg.store.endpoint.as_deref(),
        cfg.store.region.as_deref(),
    )
    .await?;
    std::fs::create_dir_all(&cfg.data_dir)?;
    // Auto-generation of secret material is gated on demo mode. A
    // production instance must have its keyring (and K_M-A) provisioned
    // out-of-band and fails closed if absent; only a demo instance mints
    // a fresh master key.
    let demo_enabled = cfg.demo_auth.as_ref().is_some_and(|d| d.enabled);
    let mut store =
        Store::open_remote(s3, &cfg.data_dir.join("root_keys"), None, demo_enabled).await?;
    // K_M-A is needed wherever an auth integration is configured (TPC
    // verification and demo discharge issuance): a colocated demo auth
    // role generates it locally, otherwise `auth_location` signals that the
    // auth-service binary provisioned it. K_session is purely the demo
    // auth role's session root — generated only under `[demo_auth]`.
    if demo_enabled || cfg.auth_location.is_some() {
        store.init_k_m_a(&cfg.data_dir, demo_enabled)?;
        if demo_enabled {
            store.init_k_session(&cfg.data_dir)?;
        }
    }
    // K_M-B is needed only when a role carries an attested third-party
    // caveat to stamp. A colocated coordinator playing the attestation
    // role generates it locally under demo; otherwise the attestation
    // coordinator provisioned it out-of-band.
    if cfg.roles.values().any(|r| r.attestation_mode.is_some()) {
        store.init_k_m_b(&cfg.data_dir, demo_enabled)?;
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
    tracing::info!(data_dir = %config.data_dir.display(), "loaded config");

    let (store, tigris) = open_store(&config).await?;
    let store = Arc::new(store);

    // admin service token (`docs/design-mint.md` § *Admin service token*):
    // the admin-plane primary + machine key the local operator CLI reads.
    // (Re)minted whenever either file is absent and an auth service is
    // configured — so a fresh deployment provisions it, a lost or partial
    // pair self-heals on restart, and enabling [auth] on an existing
    // deployment picks it up.
    let have_admin_service = config.data_dir.join("admin-service").exists()
        && config.data_dir.join("admin-service.key").exists();
    if !have_admin_service {
        write_admin_service(&config, &store).await?;
    }

    // Template seal: publish any staged pending file, then resolve the
    // served surface from the canonical bucket seal — serving from the
    // local sealed cache (or adopting it from roles_dir/), or running
    // dormant if there is no verifiable seal this host can satisfy
    // (`docs/design-mint-template-seal.md` § *Startup*).
    let seal_state = mint::seal::resolve_startup(&config, &store)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    // `assume-role` reuses the `TigrisMinter` we already built for
    // `mint-rw` vending. Long-running serve also spawns a background
    // task that re-mints `mint-rw` before its `DateLessThan` and the
    // invite-cache refresher.
    let _refresh = mint::mint_rw::spawn_refresh(
        tigris.minter.clone(),
        config.store.bucket.clone(),
        tigris.provider,
        tigris.expiration,
    );
    let minter: Arc<dyn KeypairMinter> = tigris.minter;
    // Steady-state /v1/enroll reads the invite from a local cache that
    // a background task keeps fresh with `If-None-Match` (~30 s, cheap
    // 304 on the common path). Rotation by this process updates the
    // cache eagerly; this task picks up rotations by any other instance.
    let _invite_refresh = store.spawn_invite_refresh(mint::state::INVITE_REFRESH_INTERVAL);

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
        seal: Arc::new(arc_swap::ArcSwap::from_pointee(seal_state)),
    };

    // The mint role's app (admin routes are merged onto the same router
    // because they share the mint-listener; admin is a mint-internal
    // operator surface, not an auth-role concern).
    let mint_app = mint::admin::mount(router(state.clone()), state.clone());

    // The auth role lives on its own UDS when `[demo_auth].enabled =
    // true`. mint-as-auth is structurally not mint: separate listener,
    // separate router, no shared HTTP path. Production deploys run a
    // standalone auth-service binary instead — mint never opens this
    // socket without `[demo_auth]`. (`socket` is `Some` only when
    // `enabled`, resolved in `Config::from_raw`.)
    let auth_socket = state
        .config
        .demo_auth
        .as_ref()
        .and_then(|d| d.socket.clone());

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
        Listener::Tcp(_) => {
            // Construct a leaked &str for the lifetime of this CLI process —
            // safe because clap-parsed Config lives until main returns.
            let url: &'static str = Box::leak(cfg.listener.dial_url().into_boxed_str());
            mint::admin::AdminTarget::Tcp(url)
        }
    }
}

/// Derive the auth transport from a mint config's colocated demo auth
/// role: `unix:<[demo_auth].socket>`. Present only when
/// `[demo_auth].enabled = true` — the only auth backend that exists
/// in-tree. Production runs a separate auth-service binary, reached via
/// `mint login --url`.
fn config_auth_transport(cfg: &Config) -> Result<String, Box<dyn std::error::Error>> {
    let socket = cfg
        .demo_auth
        .as_ref()
        .and_then(|d| d.socket.clone())
        .ok_or(
            "config has no colocated demo auth role \
             ([demo_auth].enabled = true); pass --url instead",
        )?;
    Ok(format!("unix:{}", socket.display()))
}

/// Resolve the auth transport for `mint login`: `--url`, else `--config`'s
/// `[demo_auth]` socket, else the transport remembered from a prior login.
fn resolve_login_transport(
    url: Option<String>,
    config: Option<PathBuf>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(url) = url {
        return Ok(url);
    }
    if let Some(config) = config {
        return config_auth_transport(&load(&config)?);
    }
    Ok(mint::session::load_transport()?)
}

/// `mint login` — authenticate at the auth role and persist the per-user
/// session + transport that gate `/v1/discharge` for both planes.
async fn login(
    url: Option<String>,
    config: Option<PathBuf>,
    subject: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let transport = resolve_login_transport(url, config)?;
    let session = mint::session::login(&transport, subject).await?;
    mint::session::save(&session, &transport)?;
    eprintln!(
        "logged in as {subject} at {transport}; session saved to {}",
        mint::session::dir()?.display()
    );
    Ok(())
}

/// `mint logout` — remove the per-user session, leaving the remembered
/// auth transport in place.
fn logout() -> Result<(), Box<dyn std::error::Error>> {
    if mint::session::clear_session()? {
        eprintln!("logged out; removed the session (auth transport kept)");
    } else {
        eprintln!(
            "not logged in (no session at {})",
            mint::session::dir()?.display()
        );
    }
    Ok(())
}

/// Assemble the operator's admin-plane authority for one CLI invocation:
/// load the admin-service + machine key (from `data_dir`), load the per-user
/// session + transport (`mint login`), and fetch a fresh wide discharge.
/// The returned discharge satisfies every admin verb; each admin call
/// attenuates its own `op` onto the admin-service.
async fn operator_session(
    cfg: &Config,
) -> Result<(mint::operator::Operator, mint::Macaroon), Box<dyn std::error::Error>> {
    let operator = mint::operator::Operator::load(&cfg.data_dir)?;
    let session = mint::session::load_session()?;
    let transport = mint::session::load_transport()?;
    let discharge = operator.fetch_discharge(&transport, &session).await?;
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
            if r.fingerprint.is_empty() {
                "-"
            } else {
                &r.fingerprint
            },
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

async fn enroll_revoke(
    config: &Path,
    sub: &str,
    yes: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let config = load(config)?;
    let (op, discharge) = operator_session(&config).await?;

    if !yes {
        eprintln!("revoke enrollment:");
        eprintln!("  sub: {sub}");
        eprint!(
            "Revoke? This kills every credential this coordinator holds \
             and drops it to the operator-gated slow path; live S3 access \
             dies within one keypair TTL. [y/N] "
        );
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if !matches!(line.trim(), "y" | "Y" | "yes" | "YES") {
            eprintln!("not revoked");
            std::process::exit(1);
        }
    }

    let req = mint::admin::RevokeRequest {
        sub: sub.to_owned(),
    };
    let resp = mint::admin::revoke_enrollment(admin_target(&config), &op, &discharge, &req).await?;
    if resp.was_enrolled {
        eprintln!(
            "revoked {sub} at {} (epoch {}; enrolled record deleted, tombstone written)",
            resp.revoked_at, resp.rev_epoch
        );
    } else {
        eprintln!(
            "revoked {sub} at {} (epoch {}; no live enrolled record — tombstone written/kept)",
            resp.revoked_at, resp.rev_epoch
        );
    }
    Ok(())
}

/// `mint seal` — author and publish the template seal by calling the
/// running daemon's `POST /v1/admin/seal`, structurally identical to
/// `mint invite`: an `op=admin:seal` discharge over the operator session.
/// The daemon hashes its **own local** `roles_dir/`, MACs under the
/// keyring, PUTs `seal.json`, and caches it. The new content goes live
/// immediately — no restart.
async fn seal(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config_path)?;
    let (op, discharge) = operator_session(&config).await?;
    let resp = mint::admin::seal(admin_target(&config), &op, &discharge).await?;
    eprintln!(
        "published seal: kid={} sealed_at={} roles=[{}]",
        resp.kid,
        resp.sealed_at,
        resp.roles
            .iter()
            .map(|(name, hash)| format!("{name}:{}", &hash[..12.min(hash.len())]))
            .collect::<Vec<_>>()
            .join(", "),
    );
    Ok(())
}

fn role_list(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    if config.roles.is_empty() {
        eprintln!("no roles configured");
        return Ok(());
    }

    // The served seal (if any) is authoritative; the STATE column reports
    // each role's relationship to it, mirroring `mint role inspect`.
    use mint::sealed_cache::CacheState;
    let cache = mint::sealed_cache::load(&config.data_dir)?;
    if let CacheState::Corrupt { reason } = &cache {
        eprintln!("warning: sealed cache is corrupt and will not be served: {reason}");
    }
    let served = match &cache {
        CacheState::Loaded {
            seal, templates, ..
        } => Some((seal, templates)),
        _ => None,
    };
    // env/audience drift is deployment-wide: it marks every served role
    // drifted, since it changes the resources each grant renders to.
    let global_drift =
        served.is_some_and(|(s, _)| !s.env_matches(&config.env) || s.audience != config.audience);

    println!(
        "{:<24} {:>7} {:>7} {:>7}  STATE",
        "NAME", "MIN", "DEF", "MAX"
    );
    // config.roles is a BTreeMap, so iteration is name-sorted.
    for r in config.roles.values() {
        let row = served
            .and_then(|(seal, templates)| {
                let sealed = seal.roles.get(&r.name)?;
                templates.get(&r.name)?;
                let drifted = global_drift
                    || sealed.min_ttl_seconds != r.min_ttl_seconds
                    || sealed.default_ttl_seconds != r.default_ttl_seconds
                    || sealed.max_ttl_seconds != r.max_ttl_seconds
                    || sealed.policy_blake3 != mint::seal::hash_hex(r.policy.as_bytes());
                let state = if drifted { "drifted" } else { "served" };
                Some((
                    sealed.min_ttl_seconds,
                    sealed.default_ttl_seconds,
                    sealed.max_ttl_seconds,
                    state,
                ))
            })
            .unwrap_or((
                r.min_ttl_seconds,
                r.default_ttl_seconds,
                r.max_ttl_seconds,
                "unsealed",
            ));
        let (min, def, max, state) = row;
        println!("{:<24} {min:>7} {def:>7} {max:>7}  {state}", r.name);
    }
    Ok(())
}

fn role_inspect(config: &Path, name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let role = config
        .roles
        .get(name)
        .ok_or_else(|| format!("no role {name} in config (see `mint role list`)"))?;

    // Two surfaces hold a role: the live authoring template in roles_dir/
    // (what the operator edits) and the sealed surface in <data_dir>/sealed/
    // (what mint mints from — never the live config). Report the served
    // surface as authoritative and flag where the live config has drifted.
    let cache = mint::sealed_cache::load(&config.data_dir)?;

    eprintln!("role: {}", role.name);
    eprintln!("  store.bucket:     {}", config.store.bucket);
    eprintln!("  policy source:    {}", role.policy_path.display());

    use mint::sealed_cache::CacheState;
    match cache {
        CacheState::Loaded {
            seal, templates, ..
        } => match (seal.roles.get(name), templates.get(name)) {
            (Some(sealed), Some(sealed_policy)) => {
                eprintln!("  surface:          served (sealed at {})", seal.sealed_at);

                // Sealed value is authoritative; show the live value only
                // where the config has drifted from it.
                let drift = |s: u64, l: u64| {
                    if s == l {
                        String::new()
                    } else {
                        format!(" (local={l})")
                    }
                };
                eprintln!(
                    "  ttl_seconds:      min={}{} default={}{} max={}{}",
                    sealed.min_ttl_seconds,
                    drift(sealed.min_ttl_seconds, role.min_ttl_seconds),
                    sealed.default_ttl_seconds,
                    drift(sealed.default_ttl_seconds, role.default_ttl_seconds),
                    sealed.max_ttl_seconds,
                    drift(sealed.max_ttl_seconds, role.max_ttl_seconds),
                );
                if seal.audience == config.audience {
                    eprintln!("  audience:         {}", seal.audience);
                } else {
                    eprintln!(
                        "  audience:         {} (local={})",
                        seal.audience, config.audience
                    );
                }
                // env is deployment-wide; drift changes the resources every
                // {{env.X}} in this template renders to.
                if !seal.env_matches(&config.env) {
                    eprintln!("  \u{26a0} local [env] has drifted from the seal");
                }

                // Surface + template come from the sealed bytes.
                print_policy_surface(sealed_policy);
                // The request contract (`[role.template]`) is sealed too;
                // flag a local declaration that has drifted from it.
                if sealed.req != role.req || sealed.caveat != role.caveat {
                    eprintln!("  \u{26a0} local [role.template] has drifted from the seal:");
                    eprintln!(
                        "      sealed: req={:?} caveat={:?}",
                        sealed.req, sealed.caveat
                    );
                    eprintln!("      local:  req={:?} caveat={:?}", role.req, role.caveat);
                }
                let local_blake3 = mint::seal::hash_hex(role.policy.as_bytes());
                if local_blake3 != sealed.policy_blake3 {
                    eprintln!("  \u{26a0} local roles_dir/ has drifted from the seal:");
                    eprintln!("      sealed policy_blake3: {}", sealed.policy_blake3);
                    eprintln!("      local  policy_blake3: {local_blake3}");
                    eprintln!("      (run `mint seal` to publish the local template)");
                }
                eprintln!("  policy template (served):");
                println!("{sealed_policy}");
            }
            // In the config but not the seal: added since the last seal,
            // so it cannot be minted yet.
            _ => print_unsealed_role(
                role,
                "role absent from the served seal; will not be minted until `mint seal`",
            ),
        },
        CacheState::Absent => print_unsealed_role(
            role,
            "no sealed cache on this host; the local template is not served",
        ),
        CacheState::Corrupt { reason } => {
            eprintln!(
                "  surface:          CORRUPT \u{2014} sealed cache will not be served: {reason}"
            );
            print_unsealed_role(role, "showing local authoring template");
        }
    }
    Ok(())
}

/// The substitution surface of a policy template, grouped by trust
/// provenance. A role policy is a request-parameterised template — there
/// is no single concrete grant to print — so this shows where each
/// substituted value comes from, not a rendering.
fn print_policy_surface(template: &str) {
    let surface = mint::template::template_surface(template);
    eprintln!("  policy references:");
    for (label, vals) in [
        ("req (PoP-bound)", &surface.req),
        ("env (config)", &surface.env),
        ("mint (mint-computed)", &surface.mint),
        ("caveat (MAC-verified)", &surface.caveat),
    ] {
        if !vals.is_empty() {
            eprintln!("    {label}: {}", vals.join(", "));
        }
    }
}

/// No sealed surface backs this role — print the live authoring template,
/// labelled so it is never mistaken for what mint serves.
fn print_unsealed_role(role: &mint::config::Role, why: &str) {
    eprintln!("  surface:          NOT SEALED \u{2014} {why}");
    eprintln!(
        "  ttl_seconds:      min={} default={} max={}  (local, unsealed)",
        role.min_ttl_seconds, role.default_ttl_seconds, role.max_ttl_seconds
    );
    print_policy_surface(&role.policy);
    eprintln!("  policy template (local draft):");
    println!("{}", role.policy);
}
