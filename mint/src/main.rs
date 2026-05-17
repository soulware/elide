//! mint entry point (`docs/design-mint.md` § *Reference client &
//! demo*).
//!
//! ```text
//! mint serve <config.toml> [bind-addr]      # default 127.0.0.1:8085
//! mint bootstrap <config.toml>              # print the current bootstrap macaroon
//! mint bootstrap rotate <config.toml>       # new nonce, then print it
//! mint enroll list <config.toml>            # pending records
//! mint enroll approve <config.toml> <sub>   # approve a pending record
//! ```
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
use std::path::Path;
use std::sync::Arc;

use mint::audit::AuditLog;
use mint::config::Config;
use mint::http::{AppState, router};
use mint::iam::FakeMinter;
use mint::issuance::mint_bootstrap;
use mint::state::Store;

const USAGE: &str = "usage:\n  \
    mint serve <config.toml> [bind-addr]\n  \
    mint bootstrap <config.toml>\n  \
    mint bootstrap rotate <config.toml>\n  \
    mint enroll list <config.toml>\n  \
    mint enroll approve <config.toml> <sub>";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let cmd = args.next().ok_or(USAGE)?;
    let rest: Vec<String> = args.collect();
    match cmd.as_str() {
        "serve" => serve(rest).await,
        "bootstrap" => bootstrap(rest),
        "enroll" => enroll(rest),
        _ => Err(USAGE.into()),
    }
}

/// Open the persisted state store from the config's `state_dir`,
/// erroring if it is unset (required for every subcommand here).
fn open_store(cfg: &Config) -> Result<Store, Box<dyn std::error::Error>> {
    let dir = cfg
        .state_dir
        .as_ref()
        .ok_or("config is missing state_dir (required for serve/bootstrap/enroll)")?;
    Ok(Store::open(dir)?)
}

fn load(path: &str) -> Result<Config, Box<dyn std::error::Error>> {
    Ok(Config::load(Path::new(path))?)
}

async fn serve(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let mut a = args.into_iter();
    let config_path = a.next().ok_or(USAGE)?;
    let bind: SocketAddr = a
        .next()
        .unwrap_or_else(|| "127.0.0.1:8085".into())
        .parse()?;

    let config = Arc::new(load(&config_path)?);
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

/// `mint bootstrap [rotate] <config.toml>` — emit the bootstrap
/// macaroon (root + op=enroll + aud + the current nonce). `rotate`
/// draws a new nonce first (cancelling in-flight enrollments), then
/// emits the macaroon carrying it. The macaroon goes to stdout for
/// piping; diagnostics to stderr.
fn bootstrap(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut a = args.into_iter();
    let first = a.next().ok_or(USAGE)?;
    let (rotate, config_path) = if first == "rotate" {
        (true, a.next().ok_or(USAGE)?)
    } else {
        (false, first)
    };
    let config = load(&config_path)?;
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

fn enroll(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut a = args.into_iter();
    let sub = a.next().ok_or(USAGE)?;
    match sub.as_str() {
        "list" => {
            let config = load(&a.next().ok_or(USAGE)?)?;
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
        "approve" => {
            let config = load(&a.next().ok_or(USAGE)?)?;
            let target = a.next().ok_or("enroll approve needs a <sub>")?;
            let store = open_store(&config)?;
            if store.approve(&target)? {
                eprintln!(
                    "approved {target} — verify its fingerprint matches the client \
                     out of band before it exchanges"
                );
                Ok(())
            } else {
                Err(format!("no pending enrollment for sub {target}").into())
            }
        }
        other => Err(format!("unknown enroll subcommand {other}\n{USAGE}").into()),
    }
}
