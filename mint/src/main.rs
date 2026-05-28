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

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
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
/// Mint a super-admin bootstrap macaroon and write it to
/// `<data_dir>/admin.bootstrap` (mode 0600). The first-start hook
/// for `serve`; the operator captures the file out of band, mints
/// per-human admin tokens via `/v1/admin/token/mint`, and then
/// rotates the keyring to retire this one. Mint refuses to overwrite
/// an existing file — first-start detection is the caller's job.
async fn write_bootstrap_admin(
    cfg: &Config,
    store: &Store,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = cfg.data_dir.join("admin.bootstrap");
    let keyring = store.keyring().await;
    let mac = mint::issuance::mint_admin_token(
        &keyring,
        &cfg.audience,
        "bootstrap",
        None, // super-admin
        None, // non-expiring
    );
    let bytes = mac.encode();
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, &path)?;
    tracing::warn!(
        path = %path.display(),
        "wrote bootstrap admin macaroon — capture out of band, mint per-human tokens via /v1/admin/token/mint, then rotate the keyring to retire this one"
    );
    Ok(())
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
    let store =
        Store::open_remote(s3, &cfg.data_dir.join("root_keys"), Some(&legacy), None).await?;
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
    // before is the only reliable signal. The bootstrap admin
    // macaroon is written exactly once, on this transition; later
    // starts never re-create it, so an operator who has captured
    // and removed it never sees it re-appear.
    let is_first_start = !config.data_dir.join("root_keys").join("0000").exists()
        && !config.data_dir.join("root_key").exists();

    let (store, tigris) = open_store(&config).await?;
    let store = Arc::new(store);

    // Bootstrap admin macaroon (`docs/design-mint.md` § *Admin
    // macaroon*). Super-admin, non-expiring, `sub=bootstrap` —
    // captured out of band by the operator who runs `mint serve`
    // for the first time, then revoked (by minting per-human tokens
    // and rotating the keyring) so production never relies on this
    // one-shot artefact.
    if is_first_start && !config.data_dir.join("admin.bootstrap").exists() {
        write_bootstrap_admin(&config, &store).await?;
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
    let demo_auth = state.config.auth.as_ref().is_some_and(|a| a.demo_enabled);
    let mut app = mint::admin::mount(router(state.clone()), state.clone());
    if demo_auth {
        app = mint::auth::mount(app, state);
    }
    match transport {
        Listener::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(%addr, "mint listening (tcp)");
            axum::serve(listener, app).await?;
        }
        Listener::Uds(path) => {
            // UDS idiom: clear the stale dentry, bind, then chmod
            // 0o666 so a non-root client can connect (the socket
            // inherits the binding process's umask otherwise).
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
            tracing::info!(path = %path.display(), "mint listening (uds)");
            axum::serve(listener, app).await?;
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

async fn invite(config: &Path, rotate: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let target = admin_target(&config);
    let resp = if rotate {
        eprintln!("rotating invite nonce; in-flight enrollments cancelled");
        mint::admin::rotate_invite(target).await?
    } else {
        mint::admin::get_invite(target).await?
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
    let rows = mint::admin::list_enrollments(admin_target(&config)).await?;
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
    let target = admin_target(&config);
    // Read the pending row from the daemon so the operator's
    // fingerprint check matches what's on the server side, not what
    // the CLI thinks should be there.
    let rows = mint::admin::list_enrollments(target).await?;
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
    let resp = mint::admin::approve_enrollment(admin_target(&config), &req).await?;
    eprintln!(
        "approved {sub} (registry entry written at {}; pending record deleted)",
        resp.approved_at
    );
    Ok(())
}

async fn enroll_revoke(config: &Path, sub: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let req = mint::admin::RevokeRequest {
        sub: sub.to_owned(),
    };
    let resp = mint::admin::revoke_enrollment(admin_target(&config), &req).await?;
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
