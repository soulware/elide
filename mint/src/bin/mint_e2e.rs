//! `mint-e2e` — hermetic mint daemon for end-to-end tests (feature
//! `e2e-harness`). Runs the production serve loop (`mint::serve::run`)
//! over `Store::open_local` + `FakeMinter`, so the full enroll → seal →
//! assume-role flow works without Tigris. Spawned as a process by tests
//! that cannot link mint as a library (the elide workspace excludes it);
//! every credential it vends is fake by construction.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;

use mint::config::Config;
use mint::iam::{FakeMinter, KeypairMinter};
use mint::state::Store;

#[derive(Parser)]
#[command(about = "hermetic mint daemon for end-to-end tests (FakeMinter + local store)")]
struct Args {
    #[arg(long, env = "MINT_CONFIG", default_value = "mint.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let config = Arc::new(Config::load(&args.config)?);
    tracing::warn!(
        data_dir = %config.data_dir.display(),
        "mint-e2e harness: FakeMinter + local store — every vended credential is fake"
    );

    // Key provisioning mirrors `mint serve`'s `open_store`, over the
    // local backend.
    let demo_enabled = config.demo_auth.as_ref().is_some_and(|d| d.enabled);
    let mut store = Store::open_local(&config.data_dir).await?;
    if demo_enabled || config.auth_location.is_some() {
        store.init_k_m_a(&config.data_dir, demo_enabled)?;
        if demo_enabled {
            store.init_k_session(&config.data_dir)?;
        }
    }
    let attest_demo = config.demo_attestation.as_ref().is_some_and(|d| d.enabled);
    if config.roles.values().any(|r| r.attestation_mode.is_some()) || attest_demo {
        store.init_k_m_b(&config.data_dir, demo_enabled)?;
    }

    let minter: Arc<dyn KeypairMinter> = Arc::new(FakeMinter::new());
    mint::serve::run(config, Arc::new(store), minter, None).await?;
    Ok(())
}
