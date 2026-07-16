// elide-coordinator: manages segment upload, GC, and volume process supervision.
//
// Subcommands:
//   serve [--config <path>]
//     Start the coordinator daemon. Watches configured volume roots, discovers
//     forks, supervises volume processes, drains pending segments to S3, and
//     runs segment GC. Configuration comes from coordinator.toml.
//   init [--config <path>] [--force]
//     Write a default coordinator.toml (commented template) to the given path.

// Binary-only modules (process supervision, IPC, import jobs).
mod attest;
mod claim;
mod credential;
mod daemon;
mod enroll;
mod force_claim;
mod fork;
mod import;
mod inbound;
#[cfg(test)]
mod mint_attested_e2e;
mod mint_client;
mod mint_stores;
mod pidfile;
mod rescan;
mod shutdown;
mod supervisor;

// Re-use the library's shared modules so types are identical across the
// lib and bin compilation units.
use elide_coordinator::{bench, config, portable};

use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    version = elide_core::VERSION,
    about = "Elide coordinator: manages volumes, segment upload, and GC"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Start the coordinator daemon
    Serve {
        #[arg(long, default_value = "coordinator.toml", env = "ELIDE_COORD_CONFIG")]
        config: PathBuf,
        /// Override the data_dir from the config file
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Override [peer_fetch].listen from the config file; setting a
        /// listen address (here or in config) enables peer fetch
        #[arg(long)]
        peer_fetch_listen: Option<String>,
        /// Override [peer_fetch].host from the config file (the hostname
        /// advertised for other coordinators to dial)
        #[arg(long)]
        peer_fetch_host: Option<String>,
    },

    /// Write a default coordinator.toml template (all fields commented out)
    Init {
        #[arg(long, default_value = "coordinator.toml", env = "ELIDE_COORD_CONFIG")]
        config: PathBuf,
        /// Overwrite the file if it already exists
        #[arg(long)]
        force: bool,
    },

    /// Enrol with the configured mint and provision per-role credentials
    Enroll {
        #[arg(long, default_value = "coordinator.toml", env = "ELIDE_COORD_CONFIG")]
        config: PathBuf,
        /// Override the data_dir from the config file
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Invite macaroon: inline text, a file path, or `-` for stdin
        invite: String,
        /// Bound on waiting for operator approval (humantime)
        #[arg(long, default_value = "30m", value_parser = parse_humantime)]
        timeout: std::time::Duration,
        /// Re-exchange and overwrite every role credential, not just missing ones
        #[arg(long)]
        force: bool,
        /// Enrol as a read-only attestation authority (attest-ro role only)
        #[arg(long)]
        attestation: bool,
    },

    /// Serve only the volume-attestation discharge authority (coord B)
    Attest {
        #[arg(long, default_value = "coordinator.toml", env = "ELIDE_COORD_CONFIG")]
        config: PathBuf,
        /// Override the data_dir from the config file
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },

    /// Micro-benchmark the segment upload path against the configured
    /// object store, in isolation from the daemon (diagnostic).
    #[command(hide = true)]
    Bench {
        #[arg(long, default_value = "coordinator.toml", env = "ELIDE_COORD_CONFIG")]
        config: PathBuf,
        /// Override the data_dir from the config file (source file is
        /// written here)
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Object size in MiB
        #[arg(long, default_value_t = 32)]
        size_mb: usize,
        /// Timed iterations; the report is their median
        #[arg(long, default_value_t = 3)]
        iters: usize,
        /// Concurrent uploads per iteration (reproduces N volumes
        /// draining at once on one runtime)
        #[arg(long, default_value_t = 1)]
        parallel: usize,
        /// Worker threads for the benchmark runtime (0 = tokio default,
        /// one per CPU — the coordinator's setting)
        #[arg(long, default_value_t = 0)]
        worker_threads: usize,
        /// Leave uploaded objects in place instead of deleting them
        #[arg(long)]
        keep: bool,
        /// Object-key prefix confining probe objects in a shared bucket
        #[arg(long, default_value = "elide-throughput-probe/s3bench")]
        key_prefix: String,
    },
}

fn parse_humantime(s: &str) -> Result<std::time::Duration, String> {
    humantime::parse_duration(s).map_err(|e| format!("invalid duration {s:?}: {e}"))
}

fn main() {
    elide_core::malloc_policy::pin_mmap_threshold();
    // Must precede runtime construction: the hook blocks SIGUSR1
    // process-wide, and every thread spawned afterwards (including
    // tokio workers) inherits the mask.
    elide_core::malloc_debug::install_sigusr1_dump();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");
    if let Err(e) = rt.block_on(run()) {
        tracing::error!("{e:#}");
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Serve {
            config,
            data_dir,
            peer_fetch_listen,
            peer_fetch_host,
        } => {
            let mut config = config::load(&config)?;
            if let Some(dir) = data_dir {
                config.data_dir = dir;
            }
            if let Some(listen) = peer_fetch_listen {
                config.peer_fetch.listen = Some(listen);
            }
            if let Some(host) = peer_fetch_host {
                config.peer_fetch.host = Some(host);
            }
            // Initialise tracing now that we know the resolved data_dir.
            // Coordinator + every volume share `<data_dir>/elide.log`,
            // each opening it independently. When stderr already points
            // at the same file (e.g. `elide coord start` redirected the
            // daemon's stdio there), the tee is suppressed.
            elide_coordinator::log_init::init_for_coord(&config.data_dir).with_context(|| {
                format!("initialising tracing in {}", config.data_dir.display())
            })?;
            // Start the volume → coord log relay server so volumes
            // tee their output through whichever coord is currently
            // attached to the operator's terminal. No-op when stderr
            // already routes to elide.log (daemon mode). Best-effort:
            // a failure here just means volumes lose the live-tee
            // path and fall back to file-only — coord itself is
            // unaffected, so we log and continue rather than refuse
            // to start.
            if let Err(e) = elide_coordinator::log_relay::start(&config.data_dir) {
                tracing::warn!(
                    "[log-relay] failed to start ({e}); volumes will log to elide.log only"
                );
            }
            // Single-instance guard: an exclusive flock on the pidfile held for
            // the whole process lifetime (see `pidfile::lock_instance`). The
            // kernel releases it on any exit — crash, kill, or reboot — so it
            // never goes stale, which a pid-liveness check can't guarantee for a
            // data dir on a durable volume. Held until the end of this arm,
            // across `daemon::run`.
            std::fs::create_dir_all(&config.data_dir)
                .with_context(|| format!("creating data dir: {}", config.data_dir.display()))?;
            let _coord_lock = pidfile::lock_instance(&config.data_dir)?;

            // Loaded here so the coord-id is in scope for the
            // mint-stores wiring and the per-coordinator caps-probe key
            // below; daemon::run also calls load_or_generate, but it's
            // idempotent.
            let identity = std::sync::Arc::new(
                elide_coordinator::identity::CoordinatorIdentity::load_or_generate(
                    &config.data_dir,
                )
                .map_err(|e| anyhow::anyhow!("loading coordinator identity: {e}"))?,
            );

            if let Some(mint_cfg) = &config.mint {
                mint_cfg.validate()?;
                // Wait for enrollment rather than failing closed: a fresh
                // deploy comes up before the operator runs `elide coord
                // enroll`, and the daemon already blocks for mint just below
                // (`wait_for_ready`). `assert_enrolled` is all-or-nothing, so
                // this proceeds only once every role's credential is present.
                while let Err(missing) =
                    enroll::assert_enrolled(&config.data_dir, enroll::EnrollProfile::Coordinator)
                {
                    tracing::info!(
                        "[coordinator] awaiting enrollment: {missing}; run `elide coord enroll`"
                    );
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                }
                tracing::info!(
                    "[coordinator] store: mint-backed scoped \
                     (coord-ro / coord-rw / volume-rw); reachability \
                     and conditional-PUT are validated lazily on first \
                     assume-role per role"
                );
                let scoped = mint_stores::MintScopedStores::new(
                    mint_cfg,
                    config.store.clone(),
                    config.data_dir.clone(),
                    identity.clone(),
                );
                // Block here until mint accepts a `coord-ro` assume-role,
                // so the coordinator survives mint coming up after it
                // (systemd ordering, fresh box) instead of failing on the
                // first S3 op (publish coordinator.pub) with a connect
                // error.
                // A 401 means the held primary is no longer validly enrolled
                // (de-authorized, revoked, schema-stale). Re-enrollment is a
                // manual operator action, so stay pending and keep probing
                // instead of exiting into an orchestrator crash-loop; a
                // `elide coord enroll --force` is picked up on a later probe.
                // Connect/timeout/503 are absorbed inside `wait_for_ready`; any
                // other error remains fatal.
                loop {
                    match scoped.wait_for_ready().await {
                        Ok(()) => break,
                        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                            tracing::warn!(
                                "[coordinator] mint rejected the held enrollment as \
                                 unauthorized ({e}); re-enroll with `elide coord enroll \
                                 --force` then `mint enroll approve` — staying pending"
                            );
                            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!("waiting for mint to become ready: {e}"));
                        }
                    }
                }
                let stores: std::sync::Arc<dyn elide_coordinator::stores::ScopedStores> =
                    std::sync::Arc::new(scoped);
                return daemon::run(config, stores).await;
            }

            let store = config.store.build()?;
            tracing::info!("[coordinator] store: {}", config.store.describe());
            tracing::info!(
                "[coordinator] store scoping: shared-key passthrough \
                 (single AWS_* key for every op; no per-volume scoping)"
            );
            config.store.precheck_env()?;

            // Verify conditional-PUT support up front: the lifecycle
            // verbs (`mark_stopped`, `mark_released`,
            // `claim_started_from_released`) all rely on `If-Match`
            // ETag updates against `names/<name>`. Failing here is far
            // clearer than warning on every `volume stop` later.
            // Probe key is per-coordinator so concurrent startups against
            // the same bucket don't race on a shared key. Placed under
            // `by_id/` — the prefix the probe's Put+Delete is always
            // permitted on.
            let probe_key = object_store::path::Path::from(format!(
                "by_id/__elide_caps_probe_{}__",
                identity.coordinator_id_str()
            ));
            let caps = portable::probe_capabilities(store.as_ref(), &probe_key)
                .await
                .context("probing bucket capabilities")?;
            if !caps.conditional_put {
                bail!(
                    "object store ({}) does not support conditional PUT \
                     (If-Match / If-None-Match); portable-live-volume \
                     lifecycle verbs cannot run safely against this \
                     backend. For S3/Tigris this typically means \
                     `with_conditional_put(S3ConditionalPut::ETagMatch)` \
                     was not set on the client",
                    config.store.describe()
                );
            }
            tracing::info!("[coordinator] store: conditional PUT supported");

            let stores: std::sync::Arc<dyn elide_coordinator::stores::ScopedStores> =
                std::sync::Arc::new(elide_coordinator::stores::PassthroughStores::new(store));
            daemon::run(config, stores).await
        }
        Command::Init { config, force } => {
            elide_coordinator::log_init::init_stderr();
            init_config(&config, force)
        }
        Command::Enroll {
            config,
            data_dir,
            invite,
            timeout,
            force,
            attestation,
        } => {
            elide_coordinator::log_init::init_stderr();
            let mut config = config::load(&config)?;
            if let Some(dir) = data_dir {
                config.data_dir = dir;
            }
            let mint_cfg = config.mint.as_ref().with_context(|| {
                "`elide coord enroll` requires a [mint] section in coordinator.toml \
                 (without it the coordinator uses the shared-key downgrade and has \
                 nothing to enrol)"
            })?;
            mint_cfg.validate()?;
            std::fs::create_dir_all(&config.data_dir)
                .with_context(|| format!("creating data dir: {}", config.data_dir.display()))?;
            let identity = std::sync::Arc::new(
                elide_coordinator::identity::CoordinatorIdentity::load_or_generate(
                    &config.data_dir,
                )
                .with_context(|| "loading coordinator identity")?,
            );
            // The enroll/exchange gates are operator-discharged. In the
            // shared-key demo the coordinator self-issues them from the
            // `K_M-A` it shares with mint (`[auth.demo]`), stamped with the
            // logged-in operator subject.
            let k_m_a = config.demo_k_m_a()?.with_context(|| {
                "`elide coord enroll` needs an operator-auth source: set [auth.demo].k_m_a \
                 in coordinator.toml (the same value mint is deployed with)"
            })?;
            let subject = elide_core::operator_session::load_subject()
                .with_context(|| "loading the operator login for the enrollment gates")?;
            let issuer = enroll::SelfMint { k_m_a, subject };
            let profile = if attestation {
                enroll::EnrollProfile::Attestation
            } else {
                enroll::EnrollProfile::Coordinator
            };
            enroll::run(
                mint_cfg,
                &identity,
                &config.data_dir,
                &invite,
                enroll::EnrollOptions {
                    wait: timeout,
                    force,
                    profile,
                },
                &issuer,
            )
            .await
            .map_err(anyhow::Error::from)
        }
        Command::Attest { config, data_dir } => {
            let mut config = config::load(&config)?;
            if let Some(dir) = data_dir {
                config.data_dir = dir;
            }
            elide_coordinator::log_init::init_for_coord(&config.data_dir).with_context(|| {
                format!("initialising tracing in {}", config.data_dir.display())
            })?;
            std::fs::create_dir_all(&config.data_dir)
                .with_context(|| format!("creating data dir: {}", config.data_dir.display()))?;
            let _coord_lock = pidfile::lock_instance(&config.data_dir)?;
            attest::run(config).await
        }
        Command::Bench {
            config,
            data_dir,
            size_mb,
            iters,
            parallel,
            worker_threads,
            keep,
            key_prefix,
        } => {
            let mut config = config::load(&config)?;
            if let Some(dir) = data_dir {
                config.data_dir = dir;
            }
            let opts = bench::BenchOpts {
                size_mb,
                iters,
                parallel,
                worker_threads,
                keep,
                key_prefix,
            };
            // run_blocking owns its own runtime; keep it off this async
            // worker so its block_on doesn't nest inside the outer runtime.
            tokio::task::spawn_blocking(move || bench::run_blocking(config, opts))
                .await
                .context("benchmark task panicked")?
        }
    }
}

fn init_config(path: &std::path::Path, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite",
            path.display()
        );
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating parent directory: {}", parent.display()))?;
    }
    std::fs::write(path, config::DEFAULT_CONFIG_TEMPLATE)
        .with_context(|| format!("writing config: {}", path.display()))?;
    println!("wrote default config to {}", path.display());
    Ok(())
}
