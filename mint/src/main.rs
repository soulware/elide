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
//! `bootstrap` / `enroll` are the operator side. The networked
//! `mint client` (the coordinator's half) is the staged tail.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand};
use mint::audit::AuditLog;
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::mint_bootstrap;
use mint::state::Store;

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
        #[arg(long, default_value = "127.0.0.1:8085")]
        bind: SocketAddr,
    },
    /// Print the bootstrap macaroon (reusable, non-expiring).
    ///
    /// The macaroon goes to stdout for piping; diagnostics to stderr.
    Bootstrap {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// Draw a new bootstrap nonce first, cancelling in-flight
        /// enrollments (outstanding primaries are unaffected).
        #[arg(long)]
        rotate: bool,
    },
    /// Operator: inspect and approve pending enrollments.
    Enroll {
        #[command(subcommand)]
        cmd: EnrollCmd,
    },
}

#[derive(Subcommand)]
enum EnrollCmd {
    /// List pending enrollment records.
    List {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
    },
    /// Approve a pending record by its `sub`.
    ///
    /// Verify the displayed `cnf` fingerprint matches the client out of
    /// band *before* approving — that confirmation is the trust anchor.
    Approve {
        #[arg(long, default_value = "mint.toml")]
        config: PathBuf,
        /// The opaque principal id (Elide: the coordinator ULID).
        sub: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Args::parse().command {
        Command::Serve { config, bind } => serve(&config, bind).await,
        Command::Bootstrap { config, rotate } => bootstrap(&config, rotate),
        Command::Enroll { cmd } => match cmd {
            EnrollCmd::List { config } => enroll_list(&config),
            EnrollCmd::Approve { config, sub } => enroll_approve(&config, &sub),
        },
    }
}

fn load(path: &Path) -> Result<Config, Box<dyn std::error::Error>> {
    Ok(Config::load(path)?)
}

/// Open the persisted state store from the config's `state_dir`
/// (defaults to `./mint_data` when the config omits it).
fn open_store(cfg: &Config) -> Result<Store, Box<dyn std::error::Error>> {
    Ok(Store::open(&cfg.state_dir)?)
}

async fn serve(config: &Path, bind: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let config = Arc::new(load(config)?);
    let store = Arc::new(open_store(&config)?);
    tracing::warn!(
        "INTERIM: assume-role uses the FAKE keypair minter — it returns a \
         deterministic non-production keypair. The enroll/exchange flow is \
         real. Remove when the live Tigris SigV4 minter is wired."
    );
    tracing::info!(
        audience = %config.audience,
        roles = config.roles.len(),
        admin_credential = config.admin.is_some(),
        state_dir = %config.state_dir.display(),
        "loaded config"
    );

    let state = AppState {
        config,
        minter: Arc::new(FakeMinter::new()),
        audit: Arc::new(AuditLog::new(Box::new(std::io::stdout()))),
        store,
    };

    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, "mint listening");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn bootstrap(config: &Path, rotate: bool) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let store = open_store(&config)?;
    let nonce = if rotate {
        let n = store.rotate_bootstrap()?;
        eprintln!("rotated bootstrap nonce; in-flight enrollments cancelled");
        n
    } else {
        store.current_bootstrap()?
    };
    let mac = mint_bootstrap(&config.trust_root, &config.audience, &nonce);
    eprintln!(
        "bootstrap macaroon for audience={} (non-expiring, reusable)",
        config.audience
    );
    println!("{}", mac.encode());
    Ok(())
}

fn enroll_list(config: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let store = open_store(&config)?;
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    let rows = store.list(now)?;
    if rows.is_empty() {
        eprintln!("no pending enrollments");
        return Ok(());
    }
    println!(
        "{:<28} {:<18} {:<16} {:>7} {:<9} FLAGS",
        "SUB", "FINGERPRINT", "PEER", "AGE(s)", "APPROVED"
    );
    for r in rows {
        println!(
            "{:<28} {:<18} {:<16} {:>7} {:<9} {}",
            r.sub,
            r.fingerprint,
            r.peer_ip,
            r.age_seconds,
            if r.approved { "yes" } else { "no" },
            if r.anomalous_pub { "ANOMALOUS-PUB" } else { "" }
        );
    }
    Ok(())
}

fn enroll_approve(config: &Path, sub: &str) -> Result<(), Box<dyn std::error::Error>> {
    let config = load(config)?;
    let store = open_store(&config)?;
    if store.approve(sub)? {
        eprintln!(
            "approved {sub} — verify its fingerprint matches the client out \
             of band before it exchanges"
        );
        Ok(())
    } else {
        Err(format!("no pending enrollment for sub {sub}").into())
    }
}
