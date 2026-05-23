//! mint entry point (`docs/design-mint.md` § *Reference client &
//! demo*). clap-derived CLI, matching the elide coordinator's shape.
//!
//! `serve` runs the verification/vending HTTP surface. Until the live
//! Tigris SigV4 minter lands this binary wires [`FakeMinter`] and warns
//! loudly on every start: the enroll/exchange flow is real, but
//! `assume-role` returns a **deterministic fake keypair**. This is an
//! explicit, temporary interim — not a silent optional path — removed
//! when the real minter is wired (`docs/design-mint.md` § *Reference
//! client & demo*: "no stub backend").
//!
//! `invite` / `enroll` are the operator side. The networked
//! `mint client` (the coordinator's half) is the staged tail.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mint::audit::AuditLog;
use mint::config::{Config, Listener};
use mint::http::{AppState, router};
use mint::iam::{FakeMinter, KeypairMinter};
use mint::issuance::mint_invite;
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
        /// Use the real Tigris IAM minter (requires a Tigris admin
        /// credential in the environment). Without it, assume-role
        /// returns a deterministic fake keypair.
        #[arg(long)]
        tigris: bool,
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
    /// Reference client — the coordinator's half of the flow.
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
        /// Opaque principal id — the `sub` (Elide: coordinator ULID).
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
        /// The opaque principal id (Elide: the coordinator ULID).
        sub: String,
        /// Skip the interactive confirmation (automation only — you are
        /// asserting the fingerprint was verified out of band).
        #[arg(long)]
        yes: bool,
    },
    /// Revoke an approved-coordinator registry entry.
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
        Command::Serve {
            config,
            bind,
            tigris,
        } => serve(&config, bind, tigris).await,
        Command::Invite { config, rotate } => invite(&config, rotate).await,
        Command::Enroll { cmd } => match cmd {
            EnrollCmd::List { config } => enroll_list(&config).await,
            EnrollCmd::Approve { config, sub, yes } => enroll_approve(&config, &sub, yes).await,
            EnrollCmd::Revoke { config, sub } => enroll_revoke(&config, &sub).await,
        },
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

/// Open the persisted state store from the config's `data_dir`. In
/// the local-filesystem shape (the dev / co-resident default), this is
/// where `root_key` is read from / generated and the `_mint/` subtree
/// is rooted. The S3-backed variant (`serve --tigris`) constructs its
/// `Store` directly in [`serve`] using a self-vended `mint-rw` key.
async fn open_store_local(cfg: &Config) -> Result<Store, Box<dyn std::error::Error>> {
    Ok(Store::open_local(&cfg.data_dir).await?)
}

async fn serve(
    config: &Path,
    bind_override: Option<SocketAddr>,
    tigris: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Arc::new(load(config)?);

    // Pick the minter before binding so a misconfigured --tigris fails
    // fast rather than at the first request.
    let minter: Arc<dyn KeypairMinter> = if tigris {
        let admin = config.admin.as_ref().ok_or(
            "--tigris requires a Tigris admin credential in the environment \
             (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)",
        )?;
        Arc::new(TigrisMinter::new(admin)?)
    } else {
        tracing::warn!(
            "INTERIM: assume-role uses the FAKE keypair minter — it returns a \
             deterministic non-production keypair. Pass --tigris for real \
             Tigris keys. The enroll/exchange flow is real either way."
        );
        Arc::new(FakeMinter::new())
    };

    // State backing:
    // - `--tigris`: self-vend a `mint-rw` keypair scoped to `_mint/*`
    //   in the tenant bucket, use it for all data-plane I/O. The admin
    //   credential never signs an `s3:*` call. A background task
    //   refreshes the keypair before its `DateLessThan`.
    // - default: LocalFileSystem under `<data_dir>/_mint/`, matching the
    //   bucket key layout so an operator can `ls` either and see the
    //   same shape.
    let store = if tigris {
        let (s3, provider, expiration) = mint::mint_rw::build_s3_with_mint_rw(
            &minter,
            &config.tenant.bucket,
            config.tenant.endpoint.as_deref(),
            config.tenant.region.as_deref(),
        )
        .await?;
        let _refresh = mint::mint_rw::spawn_refresh(
            minter.clone(),
            config.tenant.bucket.clone(),
            provider,
            expiration,
        );
        let root_key_path = config.data_dir.join("root_key");
        std::fs::create_dir_all(&config.data_dir)?;
        Arc::new(Store::open_remote(s3, &root_key_path).await?)
    } else {
        Arc::new(open_store_local(&config).await?)
    };
    // Steady-state /v1/enroll reads the invite from a local cache that
    // a background task keeps fresh with `If-None-Match` (~30 s, cheap
    // 304 on the common path). Rotation by this process updates the
    // cache eagerly; this task picks up rotations by any other instance.
    let _invite_refresh = store.spawn_invite_refresh(mint::state::INVITE_REFRESH_INTERVAL);
    tracing::info!(
        audience = %config.audience,
        roles = config.roles.len(),
        admin_credential = config.admin.is_some(),
        data_dir = %config.data_dir.display(),
        roles_dir = %config.roles_dir.display(),
        minter = if tigris { "tigris" } else { "fake" },
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
    match transport {
        Listener::Tcp(addr) => {
            let listener = tokio::net::TcpListener::bind(addr).await?;
            tracing::info!(%addr, "mint listening (tcp)");
            axum::serve(listener, router(state)).await?;
        }
        Listener::Uds(path) => {
            // Coordinator UDS idiom: clear the stale dentry, bind, then
            // chmod 0o666 so a non-root coordinator can connect (the
            // socket inherits the binding process's umask otherwise).
            let _ = std::fs::remove_file(&path);
            let listener = tokio::net::UnixListener::bind(&path)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666))?;
            tracing::info!(path = %path.display(), "mint listening (uds)");
            axum::serve(listener, router(state)).await?;
        }
    }
    Ok(())
}

async fn invite(config: &Path, rotate: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let store = open_store_local(&config).await?;
    let nonce = if rotate {
        let n = store.rotate_invite().await?;
        eprintln!("rotated invite nonce; in-flight enrollments cancelled");
        n
    } else {
        store.current_invite().await?
    };
    let mac = mint_invite(&store.root_key(), &config.audience, &nonce);
    eprintln!(
        "invite macaroon for audience={} (non-expiring, reusable)",
        config.audience
    );
    println!("{}", mac.encode());
    Ok(())
}

async fn enroll_list(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    use mint::state::EnrollmentState;
    let config = load(config)?;
    let store = open_store_local(&config).await?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let rows = store.list(now).await?;
    if rows.is_empty() {
        eprintln!("no enrollments");
        return Ok(());
    }
    println!(
        "{:<28} {:<9} {:<18} {:<16} {:>7} FLAGS",
        "SUB", "STATE", "FINGERPRINT", "PEER", "AGE(s)"
    );
    for r in rows {
        let state = match r.state {
            EnrollmentState::Pending => "pending",
            EnrollmentState::Approved => "approved",
        };
        println!(
            "{:<28} {:<9} {:<18} {:<16} {:>7} {}",
            r.sub,
            state,
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
    let store = open_store_local(&config).await?;
    let pending = store
        .get_pending(sub)
        .await?
        .ok_or_else(|| format!("no pending enrollment for sub {sub}"))?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let fp = mint::state::fingerprint(&pending.pubkey);

    eprintln!("pending enrollment:");
    eprintln!("  sub:         {sub}");
    eprintln!("  fingerprint: {fp}");
    eprintln!("  peer:        {}", pending.peer_ip);
    eprintln!("  age:         {}s", now.saturating_sub(pending.first_seen));

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

    let now_iso = chrono::Utc::now().to_rfc3339();
    store.approve(sub, &pending.pubkey, &now_iso).await?;
    eprintln!("approved {sub} (registry entry written; pending record deleted)");
    Ok(())
}

async fn enroll_revoke(config: &Path, sub: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let store = open_store_local(&config).await?;
    if store.revoke(sub).await? {
        eprintln!("revoked approved/{sub}; next enroll requires fresh approval");
        Ok(())
    } else {
        Err(format!("no approved entry for sub {sub}").into())
    }
}

fn role_list(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    if config.roles.is_empty() {
        eprintln!("no roles configured");
        return Ok(());
    }
    println!(
        "{:<16} {:>7} {:>7} {:>7}  REQUIRED-CAVEATS",
        "NAME", "MIN", "DEF", "MAX"
    );
    // config.roles is a BTreeMap, so iteration is name-sorted.
    for r in config.roles.values() {
        println!(
            "{:<16} {:>7} {:>7} {:>7}  {}",
            r.name,
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
