//! The serve loop shared by every mint daemon shape: admin-service
//! provisioning, template-seal startup, the mint/admin router on the
//! configured listener, and the colocated demo-auth listener when
//! `[demo_auth]` is enabled.
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
            let auth_app = crate::auth::router(state);
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
