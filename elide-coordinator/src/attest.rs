//! Dedicated attestation authority (coord B) serve loop.
//!
//! `elide-coordinator attest`: assume `coord-ro`, open attested CIDs under
//! `K_M-B`, and serve `POST /v1/discharge` on the `[attestation] listen`
//! address — none of the supervisor, GC, IPC, or volume scan
//! `daemon::run` runs (`docs/design/mint-volume-attestation.md` § *A
//! dedicated attestation instance*, shape 2).

use std::sync::Arc;

use anyhow::{Context, Result};
use tracing::info;

use crate::config::{CoordinatorConfig, ListenAddr};
use crate::{enroll, mint_stores};
use elide_coordinator::identity::CoordinatorIdentity;
use elide_coordinator::stores::ScopedStores;

pub async fn run(config: CoordinatorConfig) -> Result<()> {
    let mint_cfg = config
        .mint
        .as_ref()
        .context("`attest` requires a [mint] section: coord B assumes coord-ro through mint")?;
    mint_cfg.validate()?;

    let attestation = config
        .attestation
        .as_ref()
        .context("`attest` requires an [attestation] section (K_M-B + listen)")?;
    let listen = attestation
        .listen_addr()?
        .context("[attestation] requires `listen` to serve the discharge authority")?;
    let k_m_b = attestation.load_discharge_key()?;

    let identity = Arc::new(
        CoordinatorIdentity::load_or_generate(&config.data_dir)
            .map_err(|e| anyhow::anyhow!("loading coordinator identity: {e}"))?,
    );
    info!("[attest] coordinator_id: {}", identity.coordinator_id_str());

    // Wait for the read-only attestation enrollment rather than failing
    // closed: a fresh deploy comes up before the operator runs `enroll
    // --attestation`, and we block on mint just below anyway.
    while let Err(missing) =
        enroll::assert_enrolled(&config.data_dir, enroll::EnrollProfile::Attestation)
    {
        info!("[attest] awaiting enrollment: {missing}; run `elide coord enroll --attestation`");
        tokio::time::sleep(std::time::Duration::from_secs(15)).await;
    }

    let scoped = mint_stores::MintScopedStores::new(
        mint_cfg,
        config.store.clone(),
        config.data_dir.clone(),
        identity.clone(),
    );
    // Block until mint accepts a coord-ro assume-role, so coord B survives
    // mint coming up after it instead of failing on the first S3 read.
    scoped
        .wait_for_ready()
        .await
        .map_err(|e| anyhow::anyhow!("waiting for mint to become ready: {e}"))?;

    let state = elide_attestation::DischargeState::new(k_m_b, scoped.base_object_store());
    info!("[attest] discharge authority (coord B) serving on {listen:?}");
    let router = elide_attestation::discharge_router(state);
    let serve = async move {
        match listen {
            ListenAddr::Tcp(addr) => elide_attestation::serve::serve_tcp(addr, router).await,
            ListenAddr::Uds(path) => elide_attestation::serve::serve_uds(path, router).await,
        }
    };

    use tokio::signal::unix::{SignalKind, signal};
    let mut sigint = signal(SignalKind::interrupt()).context("install SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("install SIGTERM handler")?;
    tokio::select! {
        res = serve => res.map_err(|e| anyhow::anyhow!("discharge server exited: {e}")),
        _ = sigint.recv() => { info!("[attest] SIGINT; shutting down"); Ok(()) }
        _ = sigterm.recv() => { info!("[attest] SIGTERM; shutting down"); Ok(()) }
    }
}
