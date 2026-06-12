//! The serve loop shared by every mint daemon shape: admin-service
//! provisioning, template-seal startup, the mint/admin router on the
//! configured listener, and the colocated demo-auth / demo-attestation
//! listeners when `[demo_auth]` / `[demo_attestation]` are enabled.
//!
//! Callers construct the store and minter for their backend and hand
//! them in: `mint serve` opens the Tigris-backed store with a real
//! `TigrisMinter`; the `mint-e2e` harness bin (feature `e2e-harness`)
//! wires `Store::open_local` + `FakeMinter` for hermetic end-to-end
//! tests.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;

use axum::Router;
use rand_core::{OsRng, RngCore};

use crate::audit::AuditLog;
use crate::config::{Config, Listener};
use crate::http::{AppState, router};
use crate::iam::KeypairMinter;
use crate::state::Store;

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
async fn write_admin_service(cfg: &Config, store: &Store) -> io::Result<()> {
    let Some(k_m_a) = store.k_m_a().copied() else {
        return Ok(()); // no auth → no admin plane → no admin-service
    };
    let location = cfg
        .auth_location
        .as_deref()
        .ok_or_else(|| io::Error::other("admin-service: K_M-A present without auth_location"))?;
    let org_id = store.org_id().unwrap_or("demo").to_string();

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let cnf = crate::pop::cnf_value(&seed);

    let keyring = store.keyring().await;
    let mac = crate::issuance::mint_admin_service_token(
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
fn write_0600(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
    std::fs::rename(&tmp, path)
}

/// Run the daemon over an opened store and minter until a listener
/// faults. `bind_override` forces a TCP listener regardless of the
/// config's bind/socket choice.
pub async fn run(
    config: Arc<Config>,
    store: Arc<Store>,
    minter: Arc<dyn KeypairMinter>,
    bind_override: Option<SocketAddr>,
) -> io::Result<()> {
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
    let seal_state = crate::seal::resolve_startup(&config, &store)
        .await
        .map_err(io::Error::other)?;

    // Steady-state /v1/enroll reads the invite from a local cache that
    // a background task keeps fresh with `If-None-Match` (~30 s, cheap
    // 304 on the common path). Rotation by this process updates the
    // cache eagerly; this task picks up rotations by any other instance.
    let _invite_refresh = store.spawn_invite_refresh(crate::state::INVITE_REFRESH_INTERVAL);

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
    let mint_app = crate::admin::mount(router(state.clone()), state.clone());

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
    // Same shape for the demo attestation authority: its own UDS, its
    // own router, only under `[demo_attestation].enabled = true`.
    let attest_socket = state
        .config
        .demo_attestation
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

    let auth_fut = match auth_socket {
        Some(path) => serve_role_uds(&path, crate::auth::router(state.clone()), "auth")?,
        None => Box::pin(std::future::ready(Ok(()))),
    };
    let attest_fut = match attest_socket {
        Some(path) => serve_role_uds(&path, crate::attest::router(state), "attest")?,
        None => Box::pin(std::future::ready(Ok(()))),
    };
    // `try_join!` fails-fast: a fault on any listener brings the
    // process down. Every enabled listener is required for a working
    // demo, so partial-up is never the right state. (A disabled role's
    // arm is an immediately-ready `Ok`, which `try_join!` ignores while
    // the live listeners run.)
    tokio::try_join!(mint_listener, auth_fut, attest_fut)?;
    Ok(())
}

/// Bind one colocated demo role's UDS and serve its router. Tighter
/// mode than mint's listener: only the binding user and group can fetch
/// discharges. Demo-only; a production authority binds its own socket
/// with its own policy.
fn serve_role_uds(
    path: &Path,
    app: Router,
    label: &'static str,
) -> io::Result<Pin<Box<dyn Future<Output = io::Result<()>> + Send>>> {
    let _ = std::fs::remove_file(path);
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    let listener = tokio::net::UnixListener::from_std(listener)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    tracing::info!(path = %path.display(), "{label} listening (uds)");
    Ok(Box::pin(async move { axum::serve(listener, app).await }))
}
