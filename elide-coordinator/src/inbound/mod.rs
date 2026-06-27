// Coordinator inbound socket — top-level dispatch.
//
// Submodules:
//   - `lifecycle`: start, stop, release, hydrate.
//
// Listens on control.sock for commands from the elide CLI.
// Protocol: one request line per connection, one response line, then close.
// Exception: `import attach` streams multiple response lines until done.
//
// Unauthenticated operations (any caller):
//   rescan                    — trigger an immediate fork discovery pass
//   status <volume>           — report running state of a named volume
//   import <name> <ref>       — spawn an OCI import
//   import status <name>      — poll import state by volume name (running / done / failed)
//   import attach <name>      — stream import output by volume name until completion
//   delete <volume>           — stop all processes and remove the volume directory
//   evict <volume> [<ulid>]   — evict all (or one) S3-confirmed segment body from cache/
//
// Volume-process operations (macaroon-authenticated):
//   register <volume-ulid>     — mint a per-volume macaroon, PID-bound via SO_PEERCRED
//   credentials <macaroon>     — exchange macaroon for short-lived S3 creds (PID re-checked)

mod lifecycle;

// Re-exports used by sibling modules (claim.rs, fork.rs) under the
// previous flat `crate::inbound::*` shape.
pub(crate) use lifecycle::{
    FastPathDisposition, local_daemon_running, promote_stop_snapshot, release_fast_path_handoff,
};
// Reached by `claim.rs`'s crash-recovery test (#428), which drives the
// real force-release op against a partial-fork shape.
#[cfg(test)]
// Shared test fixtures used by both `mod.rs::tests` and
// `lifecycle.rs::tests`. Keeping them at the module level (rather
// than inside one of the `tests` modules) lets the sibling test
// module reach them without cross-cfg(test)-private gymnastics.
#[cfg(test)]
pub(super) mod test_helpers {
    use std::sync::Arc;

    use object_store::ObjectStore;

    pub fn mem_store() -> Arc<dyn ObjectStore> {
        Arc::new(object_store::memory::InMemory::new())
    }

    pub fn sample_ulid() -> ulid::Ulid {
        ulid::Ulid::from_string("01J0000000000000000000000V").unwrap()
    }

    pub const SAMPLE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
}

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use elide_peer_fetch::PeerEndpoint;
use object_store::ObjectStore;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UnixListener;
use tokio::net::unix::OwnedWriteHalf;
use tracing::{info, warn};

use crate::claim::{ClaimJobState, ClaimRegistry};
use crate::credential::{CredentialIssuer, Credentialer, credential_issuer};
use crate::fork::{ForkJobState, ForkRegistry};
use crate::import::{self, ImportRegistry, ImportState};
use elide_coordinator::config::{StoreSection, store_config};
use elide_coordinator::ipc::{
    self, ClaimAttachEvent, ClaimStartReply, CreateReply, Envelope, EvictReply, ForkAttachEvent,
    ForkStartReply, GenerateFilemapReply, ImportAttachEvent, ImportStartReply, ImportStatusReply,
    IpcError, PeerClaimerTokenReply, PullReadonlyReply, RegisterReply, ReleaseReply, Request,
    SnapshotReply, StatusRemoteReply, StatusReply, StoreConfigReply, StoreCredsReply, UpdateReply,
    VolumeEventsReply,
};
use elide_coordinator::macaroon::{self, Caveat, Macaroon, Scope, VerifyCtx};
use elide_coordinator::volume_state::{IMPORTING_FILE, PID_FILE, write_released_marker};
use elide_coordinator::{
    EvictRegistry, PrefetchTracker, ReadinessTracker, SnapshotLockRegistry, subscribe_prefetch,
};
use elide_core::process::pid_is_alive;

/// Shared coordinator state threaded through every inbound op.
///
/// All fields are cheap to clone (Arc-wrapped or Copy), so per-connection
/// fan-out in `serve` is a flat clone rather than a long argument list.
///
/// The dispatcher legitimately needs every field (it routes to handlers
/// touching different subsets); orchestrators and per-domain helpers do
/// not. They take narrower context structs ([`crate::claim::ClaimContext`],
/// [`crate::fork::ForkContext`], [`crate::import::ImportContext`]) that
/// hold the [`CoordinatorCore`] plus the registries they actually use.
#[derive(Clone)]
pub struct IpcContext {
    pub data_dir: Arc<PathBuf>,
    pub registry: ImportRegistry,
    pub fork_registry: ForkRegistry,
    pub claim_registry: ClaimRegistry,
    pub evict_registry: EvictRegistry,
    pub snapshot_locks: SnapshotLockRegistry,
    pub prefetch_tracker: PrefetchTracker,
    pub readiness_tracker: ReadinessTracker,
    pub stores: Arc<dyn elide_coordinator::stores::ScopedStores>,
    /// The coordinator's identity bundle: the source of the
    /// coordinator id (`identity.coordinator_id_str()`) and the
    /// 32-byte macaroon MAC root (`identity.macaroon_root()`).
    /// Arc-shared so per-connection clones stay cheap.
    pub identity: Arc<elide_coordinator::identity::CoordinatorIdentity>,
    /// Credentialer, present only when the `[iam]` config section is set.
    /// Used by the volume-delete path to tear down the per-volume RO
    /// key + policy. Absent in the shared-key downgrade — that path
    /// has no IAM state to clean up.
    pub credentialer: Option<Arc<dyn Credentialer>>,
}

/// Universal coordinator state — every IPC handler and every domain
/// orchestrator needs these four fields. Carried inside the per-domain
/// context structs so they don't have to embed `IpcContext`'s full bag
/// when most of it would be unused.
#[derive(Clone)]
pub struct CoordinatorCore {
    pub data_dir: Arc<PathBuf>,
    pub stores: Arc<dyn elide_coordinator::stores::ScopedStores>,
    pub identity: Arc<elide_coordinator::identity::CoordinatorIdentity>,
}

impl IpcContext {
    /// Snapshot the universal hot-core fields. Cheap (Arc clones).
    pub(crate) fn core(&self) -> CoordinatorCore {
        CoordinatorCore {
            data_dir: self.data_dir.clone(),
            stores: self.stores.clone(),
            identity: self.identity.clone(),
        }
    }

    /// Construct a [`crate::claim::ClaimContext`] — the hot core plus
    /// the claim-domain registries (claim_registry, prefetch_tracker).
    pub(crate) fn for_claim(&self) -> crate::claim::ClaimContext {
        crate::claim::ClaimContext {
            core: self.core(),
            claim_registry: self.claim_registry.clone(),
            prefetch_tracker: self.prefetch_tracker.clone(),
        }
    }

    /// Construct a [`crate::fork::ForkContext`] — the hot core plus the
    /// fork-domain registries (fork_registry, prefetch_tracker,
    /// snapshot_locks).
    pub(crate) fn for_fork(&self) -> crate::fork::ForkContext {
        crate::fork::ForkContext {
            core: self.core(),
            fork_registry: self.fork_registry.clone(),
            prefetch_tracker: self.prefetch_tracker.clone(),
            snapshot_locks: self.snapshot_locks.clone(),
        }
    }

    /// Construct a [`crate::import::ImportContext`] — the hot core plus
    /// the import registry.
    pub(crate) fn for_import(&self) -> crate::import::ImportContext {
        crate::import::ImportContext {
            core: self.core(),
            registry: self.registry.clone(),
        }
    }
}

pub async fn serve(socket_path: &Path, ctx: IpcContext) {
    let _ = std::fs::remove_file(socket_path);

    let listener = match UnixListener::bind(socket_path) {
        Ok(l) => l,
        Err(e) => {
            warn!("[inbound] failed to bind {}: {e}", socket_path.display());
            return;
        }
    };

    // The socket inherits the binding process's umask (typically 0022 → 0755),
    // which on Linux blocks non-root from `connect()` (write perm is required).
    // A coordinator running under sudo would otherwise leave a CLI in the user's
    // session unable to talk to it. Relax to 0666 so any local user can issue
    // unprivileged ops; permission-sensitive ops still go through coordinator
    // logic, not raw filesystem access.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) =
            std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o666))
        {
            warn!(
                "[inbound] chmod 0666 on {} failed: {e} (non-root CLI may be unable to connect)",
                socket_path.display()
            );
        }
    }

    info!("[inbound] listening on {}", socket_path.display());

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                tokio::spawn(handle(stream, ctx.clone()));
            }
            Err(e) => warn!("[inbound] accept error: {e}"),
        }
    }
}

async fn handle(stream: tokio::net::UnixStream, ctx: IpcContext) {
    // Capture peer credentials before splitting the stream — needed for
    // SO_PEERCRED on the `register` and `credentials` verbs. Other
    // verbs ignore the peer pid; capturing once here keeps the code
    // symmetric and avoids a second syscall later.
    let peer_pid = stream.peer_cred().ok().and_then(|c| c.pid());

    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();

    let line = match lines.next_line().await {
        Ok(Some(line)) => line,
        Ok(None) => return,
        Err(e) => {
            warn!("[inbound] read error: {e}");
            return;
        }
    };
    let line = line.trim().to_owned();

    dispatch_json(&line, &ctx, peer_pid, &mut writer).await;
}

/// Typed JSON dispatch. Each match arm runs the verb-specific
/// handler, wraps the result in an [`Envelope`], and writes one or
/// more reply messages back. Most verbs reply with a single
/// envelope; the streaming variant (`ImportAttach`) writes a
/// sequence terminated by either an `Ok(Done)` or `Err`. Unknown
/// verbs fail at the `serde_json::from_str` step — `serde` rejects
/// unrecognised variants by default for internally-tagged enums.
///
/// The `[store]` section and the credential issuer are both
/// process-global (set in `daemon::run`) and read directly inside
/// the `GetStoreConfig` and `Credentials` arms — they don't need to
/// be threaded through `ctx`.
async fn dispatch_json(
    line: &str,
    ctx: &IpcContext,
    peer_pid: Option<i32>,
    writer: &mut OwnedWriteHalf,
) {
    let request: Request = match serde_json::from_str(line) {
        Ok(r) => r,
        Err(e) => {
            let env: Envelope<()> =
                Envelope::err(IpcError::bad_request(format!("parse request: {e}")));
            let _ = ipc::write_message(writer, &env).await;
            return;
        }
    };

    match request {
        Request::Rescan => {
            crate::rescan::trigger();
            let env: Envelope<()> = Envelope::ok(());
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Status { volume } => {
            let env: Envelope<StatusReply> = volume_status_typed(&volume, &ctx.data_dir).into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::StatusRemote { volume } => {
            // Reads names/<volume> only — the read-only coord-ro
            // credential.
            let store = ctx.stores.base_ro();
            let result = volume_status_remote_typed(
                &volume,
                store.as_ref(),
                ctx.identity.coordinator_id_str(),
            )
            .await;
            let env: Envelope<StatusRemoteReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Stop { volume, force } => {
            // Conditional PUT on names/<volume>: coordinator-wide.
            let result = lifecycle::stop_volume_op(
                &volume,
                force,
                &ctx.core(),
                &ctx.snapshot_locks,
                ctx.identity.coordinator_id_str(),
                ctx.identity.hostname(),
            )
            .await;
            let env: Envelope<()> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Release { volume } => {
            // `release_volume_op` straddles two role scopes (coord-rw
            // for names/<name> + per-vol volume-rw for
            // by_id/<vol>/snapshots/). It picks the right credential
            // for each step internally; just hand it the IpcContext.
            let result = lifecycle::release_volume_op(&volume, ctx).await;
            let env: Envelope<ReleaseReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Start { volume } => {
            // Conditional PUT on names/<volume>: coordinator-wide.
            let result =
                lifecycle::start_volume_op(&volume, &ctx.core(), &ctx.readiness_tracker).await;
            let env: Envelope<()> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Create {
            volume,
            size_bytes,
            flags,
        } => {
            // Mixed: names/<volume> claim + per-volume artefacts.
            let result = create_volume_op(&volume, size_bytes, &flags, &ctx.core()).await;
            let env: Envelope<CreateReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Update { volume, flags } => {
            let result = update_volume_op(&volume, &flags, &ctx.data_dir).await;
            let env: Envelope<UpdateReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::ImportStart {
            volume,
            oci_ref,
            extents_from,
        } => {
            // Mixed: names/<volume> mark_initial; the spawned import
            // subprocess writes locally only.
            let import_ctx = ctx.for_import();
            let result = start_import(&volume, &oci_ref, &extents_from, &import_ctx).await;
            let env: Envelope<ImportStartReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::ImportStatus { volume } => {
            let result = import_status_by_name(&volume, &ctx.data_dir, &ctx.registry).await;
            let env: Envelope<ImportStatusReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::ImportAttach { volume } => {
            stream_import_by_name(&volume, &ctx.data_dir, writer, &ctx.registry).await;
        }
        Request::Snapshot { volume } => {
            // Per-volume artefact upload + events/<volume>/ emit.
            // Coordinator-wide today; future Tigris work splits the
            // upload from the event emit.
            let result = snapshot_volume(&volume, &ctx.core(), &ctx.snapshot_locks).await;
            let env: Envelope<SnapshotReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Evict {
            volume,
            segment_ulid,
        } => {
            let result =
                evict_volume(&volume, segment_ulid, &ctx.data_dir, &ctx.evict_registry).await;
            let env: Envelope<EvictReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::GenerateFilemap { volume, snap_ulid } => {
            // Demand-fetches segment bodies from the leaf + ancestor
            // chain. The minted store needs `by_id/<leaf>/*` plus one
            // `by_id/<ancestor>/*` per provenance entry — that's the
            // `volume-ro` head-with-ancestors scope. `generate_filemap_op`
            // mints it internally once vol_ulid is resolved from the
            // by_name symlink.
            let result = generate_filemap_op(&volume, snap_ulid, &ctx.data_dir, &ctx.stores).await;
            let env: Envelope<GenerateFilemapReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::AwaitPrefetch { vol_ulid } => {
            let result = await_prefetch_op(vol_ulid, &ctx.prefetch_tracker).await;
            let env: Envelope<()> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::NotifyVolumeReady { vol_ulid } => {
            // Deletes under `by_id/<vol>/snapshots/` — needs volume-rw
            // per-vol, not coord-rw. The op picks the cred via
            // `ScopedStores::volume_data(&vol_ulid)` internally.
            let result = lifecycle::notify_volume_ready_op(
                vol_ulid,
                &ctx.data_dir,
                &ctx.stores,
                &ctx.readiness_tracker,
            )
            .await;
            let env: Envelope<()> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Remove { volume_ulid, force } => {
            let store = ctx.stores.writer();
            let result = remove_volume(
                volume_ulid,
                force,
                &ctx.data_dir,
                Some(&store),
                Some(ctx.identity.coordinator_id_str()),
            )
            .await;
            // After local removal, tear down the per-volume IAM key +
            // policy. Best-effort: any IAM error is logged inside
            // `release` and does not block the IPC reply.
            if let (Ok(Some(vol_ulid)), Some(credentialer)) = (&result, ctx.credentialer.as_ref()) {
                credentialer.release_volume_ro(*vol_ulid).await;
            }
            let env: Envelope<()> = result.map(|_| ()).into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::VolumeEvents { volume, num } => {
            // Pure-read IPC: read-only journal handle (coord-ro) — the
            // type system rules out an accidental emit on the IPC perimeter.
            let journal = ctx.stores.event_journal_ro();
            let result = volume_events_typed(&volume, journal.as_ref(), num).await;
            let env: Envelope<VolumeEventsReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::GetStoreConfig => {
            let reply = render_store_config(store_config());
            let env: Envelope<StoreConfigReply> = Envelope::ok(reply);
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Register { volume_ulid } => {
            let mut result = register_volume(
                volume_ulid,
                &ctx.data_dir,
                peer_pid,
                ctx.identity.macaroon_root(),
            );
            if let Ok(reply) = &mut result {
                reply.peer_endpoint =
                    resolve_peer_endpoint_for_volume(volume_ulid, &ctx.data_dir, &ctx.stores).await;
            }
            let env: Envelope<RegisterReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::Credentials { macaroon, target } => {
            let result = issue_credentials(
                &macaroon,
                target,
                &ctx.data_dir,
                peer_pid,
                ctx.identity.macaroon_root(),
                credential_issuer(),
            )
            .await;
            let env: Envelope<StoreCredsReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::PeerClaimerToken { macaroon } => {
            let result =
                mint_peer_claimer_token(&macaroon, &ctx.data_dir, peer_pid, &ctx.identity).await;
            let env: Envelope<PeerClaimerTokenReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }

        // ── Iteration 5: consolidated fork / claim flows ─────────────
        Request::ForkStart {
            new_name,
            from,
            flags,
        } => {
            let result = crate::fork::start_fork(new_name, from, flags, ctx.for_fork());
            let env: Envelope<ForkStartReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::ForkAttach { new_name } => {
            stream_fork_by_name(&new_name, writer, &ctx.fork_registry).await;
        }
        Request::ClaimStart { volume, force } => {
            let result = if force {
                crate::force_claim::start_force_claim(volume, ctx.for_claim()).await
            } else {
                crate::claim::start_claim(volume, ctx.for_claim()).await
            };
            let env: Envelope<ClaimStartReply> = result.into();
            let _ = ipc::write_message(writer, &env).await;
        }
        Request::ClaimAttach { volume } => {
            stream_claim_by_name(&volume, writer, &ctx.claim_registry).await;
        }
        Request::Shutdown { keep_volumes } => {
            // Reply ok first, then trigger the signal: the daemon's
            // main-loop teardown aborts the inbound listener task, but
            // the per-connection handler running this code is detached
            // and gets to flush its reply before the runtime stops.
            let env: Envelope<()> = Envelope::ok(());
            let _ = ipc::write_message(writer, &env).await;
            crate::shutdown::trigger(keep_volumes);
        }
    }
}

// ── Store config / creds vending ──────────────────────────────────────────────

/// Resolve the store config the CLI should see. If neither a local
/// path nor a bucket is configured, falls back to `./elide_store` to
/// match the coordinator's own default — the CLI builds an
/// object_store from this and must agree with the coordinator on
/// where the bytes live.
fn render_store_config(store: &StoreSection) -> StoreConfigReply {
    if let Some(path) = &store.local_path {
        return StoreConfigReply {
            local_path: Some(path.display().to_string()),
            ..Default::default()
        };
    }
    if let Some(bucket) = &store.bucket {
        return StoreConfigReply {
            bucket: Some(bucket.clone()),
            endpoint: store.endpoint.clone(),
            region: store.region.clone(),
            ..Default::default()
        };
    }
    StoreConfigReply {
        local_path: Some("elide_store".to_owned()),
        ..Default::default()
    }
}

// ── Import operations ─────────────────────────────────────────────────────────

async fn start_import(
    volume: &str,
    oci_ref: &str,
    extents_from: &[String],
    ctx: &crate::import::ImportContext,
) -> Result<ImportStartReply, IpcError> {
    let req = import::ImportRequest {
        vol_name: volume,
        oci_ref,
        extents_from,
    };
    let ulid_str = import::spawn_import(req, ctx)
        .await
        .map_err(|e| IpcError::internal(format!("{e}")))?;
    let import_ulid = ulid::Ulid::from_string(&ulid_str)
        .map_err(|e| IpcError::internal(format!("import ulid {ulid_str:?}: {e}")))?;
    Ok(ImportStartReply { import_ulid })
}

/// Resolve a volume name to its import ULID via `volume.importing`, if present.
fn import_ulid_for_volume(name: &str, data_dir: &Path) -> Option<String> {
    let lock_path = data_dir.join("by_name").join(name).join(IMPORTING_FILE);
    std::fs::read_to_string(lock_path)
        .ok()
        .map(|s| s.trim().to_owned())
}

async fn import_status_by_name(
    name: &str,
    data_dir: &Path,
    registry: &ImportRegistry,
) -> Result<ImportStatusReply, IpcError> {
    let vol_dir = data_dir.join("by_name").join(name);
    if !vol_dir.exists() {
        return Err(IpcError::not_found(format!("volume not found: {name}")));
    }
    let Some(ulid) = import_ulid_for_volume(name, data_dir) else {
        // No active import lock — if volume is readonly the import completed.
        if vol_dir.join("volume.readonly").exists() {
            return Ok(ImportStatusReply::Done);
        }
        return Err(IpcError::not_found(format!("no active import for: {name}")));
    };
    let job = registry
        .lock()
        .expect("import registry poisoned")
        .get(&ulid)
        .cloned();
    match job {
        // volume.importing exists but not in registry (coordinator restarted mid-import)
        None => Ok(ImportStatusReply::Running),
        Some(job) => match job.state() {
            ImportState::Running => Ok(ImportStatusReply::Running),
            ImportState::Done => Ok(ImportStatusReply::Done),
            ImportState::Failed(msg) => Err(IpcError::internal(format!("import failed: {msg}"))),
        },
    }
}

/// Stream buffered and live import output to `writer` as a sequence of
/// [`Envelope<ImportAttachEvent>`] messages, terminating with either
/// `ImportAttachEvent::Done` (success) or `Envelope::Err` (failure).
async fn stream_import_by_name(
    name: &str,
    data_dir: &Path,
    writer: &mut OwnedWriteHalf,
    registry: &ImportRegistry,
) {
    async fn write_err(writer: &mut OwnedWriteHalf, error: IpcError) {
        let env: Envelope<ImportAttachEvent> = Envelope::err(error);
        let _ = ipc::write_message(writer, &env).await;
    }

    let vol_dir = data_dir.join("by_name").join(name);
    if !vol_dir.exists() {
        write_err(
            writer,
            IpcError::not_found(format!("volume not found: {name}")),
        )
        .await;
        return;
    }
    let Some(ulid) = import_ulid_for_volume(name, data_dir) else {
        // No active import — if volume is readonly the import already completed.
        if vol_dir.join("volume.readonly").exists() {
            let env: Envelope<ImportAttachEvent> = Envelope::ok(ImportAttachEvent::Done);
            let _ = ipc::write_message(writer, &env).await;
        } else {
            write_err(
                writer,
                IpcError::not_found(format!("no active import for: {name}")),
            )
            .await;
        }
        return;
    };

    let job = registry
        .lock()
        .expect("import registry poisoned")
        .get(&ulid)
        .cloned();
    let Some(job) = job else {
        // volume.importing exists but not in registry (coordinator restarted mid-import).
        // We can't stream output we never buffered.
        write_err(
            writer,
            IpcError::internal("import output unavailable (coordinator restarted)"),
        )
        .await;
        return;
    };

    let mut offset = 0;
    loop {
        let lines = job.read_from(offset);
        for line in &lines {
            let env: Envelope<ImportAttachEvent> = Envelope::ok(ImportAttachEvent::Line {
                content: line.clone(),
            });
            if ipc::write_message(writer, &env).await.is_err() {
                return; // client disconnected
            }
        }
        offset += lines.len();

        match job.state() {
            ImportState::Done => {
                let env: Envelope<ImportAttachEvent> = Envelope::ok(ImportAttachEvent::Done);
                let _ = ipc::write_message(writer, &env).await;
                return;
            }
            ImportState::Failed(msg) => {
                write_err(writer, IpcError::internal(format!("import failed: {msg}"))).await;
                return;
            }
            ImportState::Running => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// ── Volume evict ─────────────────────────────────────────────────────────────

/// Route an eviction request to the fork's task loop.
///
/// The fork task processes the request between drain/GC ticks, ensuring it
/// never races with the GC pass's collect_stats → compact_segments window.
async fn evict_volume(
    vol_name: &str,
    segment_ulid: Option<ulid::Ulid>,
    data_dir: &Path,
    evict_registry: &EvictRegistry,
) -> Result<EvictReply, IpcError> {
    let vol_ulid = elide_coordinator::volume_state::resolve_volume_ulid(data_dir, vol_name)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                IpcError::not_found(format!("volume not found: {vol_name}"))
            }
            _ => IpcError::internal(format!("resolving volume '{vol_name}': {e}")),
        })?;
    // The EvictRegistry key is built from `data_dir` (daemon.rs), so the
    // fork dir must be reconstructed the same way — a canonicalised path
    // would not match when `data_dir` is relative.
    let fork_dir = elide_coordinator::volume_state::fork_dir(data_dir, vol_ulid);

    // Look up the fork's evict sender.
    let sender = evict_registry
        .lock()
        .expect("evict registry poisoned")
        .get(&fork_dir)
        .cloned();
    let sender = sender.ok_or_else(|| {
        IpcError::conflict(format!("volume not managed by coordinator: {vol_name}"))
    })?;

    // Send the request and wait for the result. The fork task accepts an
    // owned ULID string for legacy reasons; encode the typed `Ulid` back.
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let ulid_str = segment_ulid.map(|u| u.to_string());
    if sender.send((ulid_str, reply_tx)).await.is_err() {
        return Err(IpcError::internal("fork task no longer running"));
    }
    match reply_rx.await {
        Ok(Ok(n)) => Ok(EvictReply { evicted: n }),
        Ok(Err(e)) => Err(IpcError::internal(format!("{e}"))),
        Err(_) => Err(IpcError::internal("fork task dropped reply")),
    }
}

// ── Volume snapshot ──────────────────────────────────────────────────────────

/// Coordinator-orchestrated snapshot handler.
///
/// Sequence for the named volume:
///   1. Acquire per-volume snapshot lock (blocks the tick loop for this volume).
///   2. `flush` IPC to the volume → WAL into `pending/`.
///   3. Inline drain of `pending/` via `upload::drain_pending` (uploads to S3
///      and triggers `promote` IPCs that move bodies into `cache/` and
///      materialise `index/<ulid>.idx`).
///   4. Pick `snap_ulid` as the max ULID in `index/` after drain, or a fresh
///      ULID if `index/` is empty.
///   5. `snapshot_manifest <snap_ulid>` IPC → volume writes the signed
///      `snapshots/<snap_ulid>.manifest` file and marker.
///   6. Upload the just-written snapshot files to S3 via
///      `upload::upload_snapshot_metadata`.
///
/// Lock is released when this function returns (via the `Drop` guard on
/// the returned `MutexGuard`).
pub(crate) async fn snapshot_volume(
    vol_name: &str,
    core: &CoordinatorCore,
    snapshot_locks: &SnapshotLockRegistry,
) -> Result<SnapshotReply, IpcError> {
    snapshot_volume_kind(
        vol_name,
        core,
        snapshot_locks,
        elide_core::signing::SnapshotKind::User,
    )
    .await
}

/// As [`snapshot_volume`] but lets the caller choose between the stable
/// user manifest (`<ulid>.manifest`) and the ephemeral stop-snapshot
/// (`<ulid>-stop.manifest`). The auto variant is what `volume stop`
/// publishes so that a future `start` (this host or another via
/// `claim`) has a basis to hydrate from. See `docs/architecture.md`
/// *Auto-snapshot lifecycle*.
pub(crate) async fn snapshot_volume_kind(
    vol_name: &str,
    core: &CoordinatorCore,
    snapshot_locks: &SnapshotLockRegistry,
    kind: elide_core::signing::SnapshotKind,
) -> Result<SnapshotReply, IpcError> {
    let link = core.data_dir.join("by_name").join(vol_name);
    let fork_dir = std::fs::canonicalize(&link)
        .map_err(|_| IpcError::not_found(format!("volume not found: {vol_name}")))?;
    // PID liveness, not raw control.sock existence — a `process::exit`
    // shutdown or crash leaves the socket file behind, and that would
    // false-positive this gate (see #432).
    if !elide_coordinator::volume_state::VolumeLifecycle::from_dir(&fork_dir).is_running() {
        return Err(IpcError::conflict(format!(
            "volume '{vol_name}' is not running — start it first"
        )));
    }
    if fork_dir.join("volume.readonly").exists() {
        return Err(IpcError::conflict(format!(
            "volume '{vol_name}' is readonly"
        )));
    }

    // Every store op below writes under `by_id/<vol>/` (segment drain,
    // GC handoff apply, snapshot manifest publish). That prefix is
    // owned by `volume-rw`; `coord-rw` is `names/*` + `events/*`
    // + `coordinators/<sub>/*` only and would 403 on the snapshot PUT.
    // Mirrors the same fix in `release_volume_op` (commit 4e6950f).
    let vol_ulid = elide_coordinator::upload::derive_names(&fork_dir)
        .map_err(|e| IpcError::internal(format!("deriving volume id: {e}")))?;
    let store = core.stores.volume_rw(&vol_ulid);

    let lock = elide_coordinator::snapshot_lock_for(snapshot_locks, &fork_dir);
    let _guard = lock.lock_owned().await;

    if !elide_coordinator::control::promote_wal(&fork_dir).await {
        return Err(IpcError::internal(
            "promote_wal failed or volume unreachable",
        ));
    }

    let meta_store = core.stores.writer();
    let drained_user_snapshot =
        match elide_coordinator::upload::drain_pending(&fork_dir, vol_ulid, &store, &meta_store)
            .await
        {
            Ok(r) if r.upload_failed > 0 || r.promote_failed > 0 => {
                return Err(IpcError::store(format!(
                    "drain reported {} S3-upload failure(s), {} volume-promote failure(s)",
                    r.upload_failed, r.promote_failed
                )));
            }
            Ok(r) => r.published_user_snapshot,
            Err(e) => return Err(IpcError::store(format!("drain: {e:#}"))),
        };

    let _ = elide_coordinator::control::apply_gc_handoffs(&fork_dir).await;
    // Outcomes from handoffs draining during a snapshot seal are folded
    // into the manifest itself (the consumed inputs are excluded from
    // the manifest's segment_ulids) and HEAD is truncated to empty
    // post-seal, so the orchestrator doesn't need them — drop on the
    // floor here. See `docs/design-segment-index.md` *Truncation*.
    elide_coordinator::gc::apply_done_handoffs(&fork_dir, vol_ulid, &store)
        .await
        .map_err(|e| IpcError::store(format!("draining gc handoffs: {e:#}")))?;

    let snap_ulid = pick_snapshot_ulid(&fork_dir)
        .map_err(|e| IpcError::internal(format!("picking snap_ulid: {e}")))?;

    // Auto-snapshot skip-if-covered: if a manifest (user OR auto) at
    // this exact ULID already exists locally, the basis is already
    // published — `volume snapshot` was run with no further writes,
    // or a previous stop on the same index/ state already covered.
    // Republishing would write the same signed bytes at the same key,
    // wasting work and (for the user-manifest case) producing a
    // redundant `-stop.manifest` sibling that NotifyVolumeReady would
    // clean up on the next start anyway.
    //
    // User snapshots take this same path through `volume snapshot`,
    // but that verb is an explicit operator request — surprise no-op
    // there would be confusing — so the skip is gated on Auto only.
    if kind == elide_core::signing::SnapshotKind::Stop
        && let Some(existing_kind) = covering_local_snapshot(&fork_dir, snap_ulid)
    {
        let label = match existing_kind {
            elide_core::signing::SnapshotKind::User => "user snapshot",
            elide_core::signing::SnapshotKind::Stop => "stop-snapshot",
        };
        info!(
            "[stop-snapshot {vol_ulid}] skipping: {label} {snap_ulid} \
             already covers current state"
        );
        return Ok(SnapshotReply { snap_ulid });
    }

    let signed = match kind {
        elide_core::signing::SnapshotKind::User => {
            elide_coordinator::control::sign_snapshot_manifest(&fork_dir, snap_ulid).await
        }
        elide_core::signing::SnapshotKind::Stop => {
            elide_coordinator::control::sign_stop_snapshot_manifest(&fork_dir, snap_ulid).await
        }
    };
    if !signed {
        return Err(IpcError::internal(format!(
            "sign_snapshot_manifest {snap_ulid} failed"
        )));
    }

    let uploaded_user_snapshot =
        elide_coordinator::upload::upload_snapshot_metadata(&fork_dir, vol_ulid, &store)
            .await
            .map_err(|e| IpcError::store(format!("uploading snapshot files: {e:#}")))?;

    // Best-effort `names/<name>.latest_snapshot` bump (`coord-rw` —
    // the volume-rw drain above cannot write it). Mirrors the
    // `snapshots/LATEST` bump inside the upload: monotonic,
    // self-heals on the next publish.
    if let Some(snap) = drained_user_snapshot.max(uploaded_user_snapshot)
        && let Err(e) = core
            .stores
            .name_claims()
            .record_latest_snapshot(vol_name, vol_ulid, snap)
            .await
    {
        warn!("[snapshot {vol_ulid}] recording latest_snapshot {snap} on names/{vol_name}: {e}");
    }

    let label = match kind {
        elide_core::signing::SnapshotKind::User => "snapshot",
        elide_core::signing::SnapshotKind::Stop => "stop-snapshot",
    };
    info!("[{label} {vol_ulid}] committed {snap_ulid}");
    Ok(SnapshotReply { snap_ulid })
}

/// Returns the kind of a local manifest at `<vol_dir>/snapshots/<ulid>.{,auto.}manifest`,
/// or `None` if neither exists. Used by stop's stop-snapshot publish path
/// to skip the redundant sign+upload when a covering manifest is already
/// present.
fn covering_local_snapshot(
    vol_dir: &Path,
    snap_ulid: ulid::Ulid,
) -> Option<elide_core::signing::SnapshotKind> {
    let snap_dir = vol_dir.join("snapshots");
    if snap_dir
        .join(elide_core::signing::snapshot_manifest_filename(&snap_ulid))
        .exists()
    {
        return Some(elide_core::signing::SnapshotKind::User);
    }
    if snap_dir
        .join(elide_core::signing::stop_snapshot_manifest_filename(
            &snap_ulid,
        ))
        .exists()
    {
        return Some(elide_core::signing::SnapshotKind::Stop);
    }
    None
}

/// Pick the ULID to tag a snapshot with: the max segment ULID in
/// `fork_dir/index/` if any are present, else a fresh `Ulid::new()`,
/// so empty volumes still get a valid snapshot tag.
fn pick_snapshot_ulid(fork_dir: &Path) -> std::io::Result<ulid::Ulid> {
    let index_dir = fork_dir.join("index");
    let mut latest: Option<ulid::Ulid> = None;
    match std::fs::read_dir(&index_dir) {
        Ok(entries) => {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(s) = name.to_str() else { continue };
                let Some(stem) = s.strip_suffix(".idx") else {
                    continue;
                };
                if let Ok(u) = ulid::Ulid::from_string(stem)
                    && latest.is_none_or(|cur| u > cur)
                {
                    latest = Some(u);
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // `Ulid::default()` is the nil ULID, not a fresh one — we explicitly
    // want a freshly minted ULID when the index is empty.
    #[allow(clippy::unwrap_or_default)]
    Ok(latest.unwrap_or_else(ulid::Ulid::new))
}

// ── Snapshot filemap generation ───────────────────────────────────────────────

/// Handle the `generate-filemap <vol> [<snap_ulid>]` IPC verb.
///
/// Looks up the volume by name, defaults `snap_ulid` to the latest local
/// snapshot when omitted, and runs `filemap::generate_from_snapshot` against
/// it with a coordinator-vended `RemoteFetcher` so demand-fetch works for
/// evicted segments.
///
/// The filemap is the only piece of snapshot metadata that is expensive to
/// produce (ext4 layout walk + per-fragment hash lookup). Used to be inline
/// in `snapshot_volume` but the cost was wasted on the user-visible release
/// path because the only consumer is `elide volume import --extents-from`.
/// Operators wanting to seed a delta source now invoke this verb explicitly.
async fn generate_filemap_op(
    vol_name: &str,
    snap_arg: Option<ulid::Ulid>,
    data_dir: &Path,
    stores: &Arc<dyn elide_coordinator::stores::ScopedStores>,
) -> Result<GenerateFilemapReply, IpcError> {
    let leaf_ulid = elide_coordinator::volume_state::resolve_volume_ulid(data_dir, vol_name)
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                IpcError::not_found(format!("volume not found: {vol_name}"))
            }
            _ => IpcError::internal(format!("resolving volume '{vol_name}': {e}")),
        })?;
    let fork_dir = elide_coordinator::volume_state::fork_dir(data_dir, leaf_ulid);

    let snap_ulid = match snap_arg {
        Some(u) => u,
        None => match elide_core::volume::latest_snapshot(&fork_dir) {
            Ok(Some(u)) => u,
            Ok(None) => {
                return Err(IpcError::not_found(format!(
                    "volume '{vol_name}' has no local snapshot; \
                     publish one first with `volume snapshot`"
                )));
            }
            Err(e) => return Err(IpcError::internal(format!("reading snapshots dir: {e}"))),
        },
    };

    // Pre-check that the snapshot the caller asked for is actually
    // sealed on disk. `BlockReader::open_snapshot` would surface a
    // generic NotFound otherwise; a verb-level check makes the error
    // reflect the user's intent ("you named a snapshot that doesn't
    // exist locally" vs. "something deep in the reader failed").
    let manifest_path = fork_dir
        .join("snapshots")
        .join(format!("{snap_ulid}.manifest"));
    if !manifest_path.exists() {
        return Err(IpcError::not_found(format!(
            "snapshot {snap_ulid} not found locally for volume '{vol_name}' \
             (no snapshots/{snap_ulid}.manifest); pull or snapshot first"
        )));
    }

    let started = std::time::Instant::now();
    generate_snapshot_filemap(data_dir, leaf_ulid, snap_ulid, Arc::clone(stores))
        .await
        .map_err(|e| {
            IpcError::internal(format!("filemap generation failed for {snap_ulid}: {e:#}"))
        })?;
    info!(
        "[generate-filemap {vol_name}] snapshot {snap_ulid} written in {:.2?}",
        started.elapsed()
    );
    Ok(GenerateFilemapReply { snap_ulid })
}

/// Open a sealed snapshot, walk its ext4 layout, and write
/// `snapshots/<snap_ulid>.filemap`. Runs on a worker thread so the tokio
/// reactor stays responsive.
///
/// Wires a `RemoteFetcher` so demand-fetch works for evicted segments —
/// freshly-pulled forks have no local segment bodies, so the ext4 inode
/// table reads must reach S3. The fetcher is constructed inside the
/// closure (after the search-dir list is known) because each fetcher
/// binds to a fork chain.
async fn generate_snapshot_filemap(
    data_dir: &Path,
    leaf_ulid: ulid::Ulid,
    snap_ulid: ulid::Ulid,
    stores: Arc<dyn elide_coordinator::stores::ScopedStores>,
) -> std::io::Result<()> {
    let fork_dir = elide_coordinator::volume_state::fork_dir(data_dir, leaf_ulid);
    // Reads route per owning volume — each segment body lives under the
    // leaf's prefix or an ancestor's, and the owner is taken from the
    // `by_id/<owner>/…` key, so each gets its own single-prefix
    // `volume-ro` store anchored on the leaf.
    let range_fetcher: Arc<dyn elide_fetch::RangeFetcher> = Arc::new(
        elide_coordinator::range_fetcher::PerOwnerObjectStoreFetcher::new(stores, leaf_ulid),
    );
    tokio::task::spawn_blocking(move || {
        let range_fetcher_for_factory = range_fetcher.clone();
        let mk_fetcher: Box<elide_core::block_reader::FetcherFactory<'_>> =
            Box::new(move |_search_dirs: &[PathBuf]| {
                let f = elide_fetch::RemoteFetcher::from_store(
                    range_fetcher_for_factory,
                    elide_fetch::DEFAULT_FETCH_BATCH_BYTES,
                );
                Some(Box::new(f) as Box<dyn elide_core::segment::SegmentFetcher>)
            });
        let _wrote =
            elide_core::filemap::generate_from_snapshot(&fork_dir, &snap_ulid, mk_fetcher)?;
        Ok::<_, std::io::Error>(())
    })
    .await
    .map_err(|e| std::io::Error::other(format!("filemap join: {e}")))?
}

// ── Volume status ─────────────────────────────────────────────────────────────

/// Typed implementation of the `status` verb. Returned to the JSON
/// dispatcher as-is; legacy callers exist as a separate adapter.
fn volume_status_typed(volume_name: &str, data_dir: &Path) -> Result<StatusReply, IpcError> {
    let link = data_dir.join("by_name").join(volume_name);
    if !link.exists() {
        return Err(IpcError::not_found(format!(
            "volume not found: {volume_name}"
        )));
    }
    // The OS follows the symlink transparently for all path ops below.
    let lifecycle = elide_coordinator::volume_state::VolumeLifecycle::from_dir(&link);
    Ok(StatusReply { lifecycle })
}

/// Typed implementation of the `status-remote` verb. Reads
/// `names/<volume>` from the bucket and classifies this coordinator's
/// eligibility against it.
async fn volume_status_remote_typed(
    volume_name: &str,
    store: &dyn elide_coordinator::stores::ReadStore,
    coord_id: &str,
) -> Result<StatusRemoteReply, IpcError> {
    use elide_coordinator::bucket_position::fetch_position;

    let (position, record) = fetch_position(store, volume_name, coord_id)
        .await
        .map_err(|e| IpcError::store(format!("reading names/{volume_name}: {e}")))?;
    let record = record
        .ok_or_else(|| IpcError::not_found(format!("name '{volume_name}' has no S3 record")))?
        .0;
    // `position` is non-Absent here (record is Some).
    let eligibility = position
        .to_eligibility()
        .expect("non-Absent position has an Eligibility");

    Ok(StatusRemoteReply {
        state: record.state,
        vol_ulid: record.vol_ulid,
        coordinator_id: record.coordinator_id,
        hostname: record.hostname,
        claimed_at: record.claimed_at,
        parent: record.parent,
        handoff_snapshot: record.handoff_snapshot,
        eligibility,
    })
}

/// Typed implementation of the `volume-events` verb. Reads the
/// `num` most-recent events for `volume` (default: the HEAD window)
/// from `events/<volume>/HEAD`, parsed and signature-verified. An
/// absent log returns an empty list — every name has a journal even
/// if no events have been emitted yet, so "empty log" is not the
/// same as "name doesn't exist".
async fn volume_events_typed(
    volume_name: &str,
    journal: &dyn elide_coordinator::event_journal::EventJournalReader,
    num: Option<usize>,
) -> Result<VolumeEventsReply, IpcError> {
    let limit = num.unwrap_or(elide_coordinator::event_journal::DEFAULT_EVENTS_LIMIT);
    let entries = journal
        .list_and_verify(volume_name, limit)
        .await
        .map_err(|e| IpcError::store(format!("listing events for {volume_name}: {e}")))?;
    Ok(VolumeEventsReply { events: entries })
}

// ── Volume remove ─────────────────────────────────────────────────────────────

/// Remove the local instance of a volume.
///
/// Removes the on-disk fork (`by_id/<ulid>/`) and its `by_name/<name>`
/// symlink. Does not delete bucket-side records or segments — this is a
/// local-instance verb, not a `purge`.
///
/// Preconditions (without `force`):
///  - `volume.stopped` must be present (the local daemon is halted)
///  - `pending/` and `wal/` must be empty (all writes are durable in S3)
///
/// `force = true` skips the second check, accepting that any local-only
/// pending segments or unflushed WAL records will be discarded.
async fn remove_volume(
    volume_ulid: ulid::Ulid,
    force: bool,
    data_dir: &Path,
    store: Option<&Arc<dyn ObjectStore>>,
    coord_id: Option<&str>,
) -> Result<Option<ulid::Ulid>, IpcError> {
    use elide_coordinator::volume_state::VolumeLifecycle;
    let volume_ulid_str = volume_ulid.to_string();
    let vol_dir_path = elide_coordinator::volume_state::fork_dir(data_dir, volume_ulid);
    let (vol_dir, shape) = VolumeLifecycle::resolve(&vol_dir_path)
        .map_err(|e| IpcError::internal(format!("resolving by_id/{volume_ulid_str}: {e}")))?;
    let vol_dir = vol_dir
        .ok_or_else(|| IpcError::not_found(format!("volume not found: {volume_ulid_str}")))?;
    // ULID is the input; carry it through to the caller for the
    // post-delete IAM cleanup hook.
    let vol_ulid = Some(volume_ulid);

    // Best-effort reverse-resolve of the local name claim, used for
    // the `data_dir/remote/<name>` breadcrumb, the by_name symlink
    // cleanup, and human-readable log lines. `None` is fine — a
    // `Fetched` or `ReadonlyImported` volume might never have had a
    // by_name entry.
    let local_name = find_local_name_for_ulid(data_dir, volume_ulid);

    // Remove accepts any shape where no process is actively touching
    // the fork:
    //   - `StoppedManual`: daemon halted via `volume stop`.
    //   - `Released { .. }`: ownership handed off; local fork is sticky
    //     display-only state. Release requires Owner{Stopped} per the
    //     #337 tightening, so the daemon is provably down.
    //   - `ReadonlyImported`: readonly local cache. The supervisor
    //     refuses to spawn a daemon for it, so there is nothing live to
    //     stop — removing it just drops the bytes.
    //
    // Refuses on `Running` (daemon alive), `Stopped` (no manual marker;
    // supervisor may still respawn), and `Importing` (subprocess is
    // actively writing). Error strings name the actual state so the
    // operator isn't told "running" for an imported volume.
    match &shape {
        VolumeLifecycle::StoppedManual
        | VolumeLifecycle::Released { .. }
        | VolumeLifecycle::ReadonlyImported => {}
        VolumeLifecycle::Running { .. } | VolumeLifecycle::Stopped => {
            return Err(IpcError::conflict(
                "volume is running; stop it first with: elide volume stop <name>",
            ));
        }
        VolumeLifecycle::Importing { .. } => {
            return Err(IpcError::conflict(
                "volume import is in progress; wait for it to finish or cancel it before remove",
            ));
        }
        VolumeLifecycle::Absent => unreachable!("vol_dir was Some above"),
    }

    if !force && let Some(reason) = unflushed_state_reason(&vol_dir) {
        return Err(IpcError::conflict(format!(
            "{reason}; take a snapshot first with: elide volume snapshot <name> \
             — or pass --force to discard the unflushed local state"
        )));
    }

    // Capture any bound ublk dev_id before removing the volume directory.
    // The daemon is already stopped (STOPPED_FILE check above), so the
    // kernel device is QUIESCED and ready for del_dev. Leaving it in
    // place would orphan a kernel device whose stamped owner points at
    // a now-deleted vol_dir.
    let teardown_id: Option<i32> = bound_ublk_id(&vol_dir);
    // Capture the pid alongside, before `remove_dir_all` takes the file
    // with it. `stop`'s IPC ack returns before the daemon's `exit(0)`
    // fires, so a quick stop → remove sequence can still race the ublk
    // queue io_uring fds being released.
    let prev_pid: Option<u32> = crate::ublk_sweep::read_volume_pid(&vol_dir);

    import::kill_all_for_volume(&vol_dir);

    // Write the breadcrumb before tearing down local state. Best-effort:
    // a transient bucket-read error logs and skips rather than blocking
    // the operator's removal. A volume without a current local name
    // claim has nothing to breadcrumb under — skip silently.
    //
    // The signing key shadow at `data_dir/keys/<vol_ulid>.key` was
    // written eagerly at volume creation time (and self-heals on every
    // `volume start`), so `remove` does not need to touch it — the
    // shadow already exists and survives `remove_dir_all` because it
    // lives outside `vol_dir`.
    if let (Some(store), Some(coord_id), Some(name)) = (store, coord_id, local_name.as_deref())
        && let Err(e) =
            maybe_write_remote_breadcrumb(data_dir, name, volume_ulid, store, coord_id).await
    {
        warn!(
            "[inbound] remove {name} ({volume_ulid_str}): skipping remote breadcrumb ({e}); \
             use `elide volume claim {name}` to recover the name later"
        );
    }

    if let Some(name) = local_name.as_deref() {
        let _ = std::fs::remove_file(data_dir.join("by_name").join(name));
    }

    std::fs::remove_dir_all(&vol_dir)
        .map_err(|e| IpcError::internal(format!("remove failed: {e}")))?;

    if let Some(id) = teardown_id {
        if let Some(pid) = prev_pid {
            crate::ublk_sweep::wait_for_pid_exit(pid).await;
        }
        crate::ublk_sweep::teardown_bound_device(&vol_dir, id).await;
    }

    match local_name.as_deref() {
        Some(name) => info!("[inbound] removed volume {name} ({volume_ulid_str})"),
        None => info!("[inbound] removed volume {volume_ulid_str}"),
    }
    Ok(vol_ulid)
}

/// Best-effort reverse-resolve from `volume_ulid` to the current local
/// name claim (the by_name symlink that points at this ULID's vol_dir).
/// Returns `None` when no by_name entry exists or the directory is
/// missing — the caller treats absence as informational, not an error.
fn find_local_name_for_ulid(data_dir: &Path, volume_ulid: ulid::Ulid) -> Option<String> {
    let target_ulid_str = volume_ulid.to_string();
    let by_name = data_dir.join("by_name");
    let entries = std::fs::read_dir(&by_name).ok()?;
    for entry in entries.flatten() {
        let link = entry.path();
        if !link.is_symlink() {
            continue;
        }
        let Ok(target) = std::fs::canonicalize(&link) else {
            continue;
        };
        if target.file_name().and_then(|n| n.to_str()) == Some(target_ulid_str.as_str())
            && let Some(name) = entry.file_name().to_str()
        {
            return Some(name.to_owned());
        }
    }
    None
}

/// Read `names/<volume_name>` and, if the bucket record exists, is in a
/// state that retains ownership (`Live` or `Stopped`), and names this
/// coordinator as owner, write a `data_dir/remote/<volume_name>`
/// breadcrumb. Surfaced by `volume list` so the user can see remotely-
/// owned volumes that have no local fork.
async fn maybe_write_remote_breadcrumb(
    data_dir: &Path,
    volume_name: &str,
    vol_ulid: ulid::Ulid,
    store: &Arc<dyn ObjectStore>,
    coord_id: &str,
) -> Result<(), String> {
    use elide_coordinator::bucket_position::{OwnershipPosition, fetch_position};

    let (position, _) = fetch_position(store, volume_name, coord_id)
        .await
        .map_err(|e| e.to_string())?;
    let owned_state = match position {
        OwnershipPosition::OwnedByUs { state, .. } => state,
        _ => return Ok(()),
    };

    elide_coordinator::remote_breadcrumb::write(data_dir, volume_name, vol_ulid)
        .map_err(|e| format!("write remote breadcrumb: {e}"))?;
    info!(
        "[inbound] remove {volume_name}: wrote remote breadcrumb (vol {vol_ulid}, owned_state={:?})",
        owned_state
    );
    Ok(())
}

/// Read the bound ublk `dev_id` from `vol_dir/volume.toml`, if any.
///
/// Returns `None` when the config is missing/unreadable, has no `[ublk]`
/// section, or the section has no `dev_id` (volume was never started, so
/// there's no kernel device to tear down).
fn bound_ublk_id(vol_dir: &Path) -> Option<i32> {
    elide_core::config::VolumeConfig::read(vol_dir)
        .ok()
        .and_then(|cfg| cfg.ublk.and_then(|u| u.dev_id))
}

/// Returns a human-readable reason if the fork has on-disk state that
/// has not been flushed and uploaded to S3, or `None` if the fork is
/// fully durable. Used to gate `remove` and decide whether `--force` is
/// required.
///
/// "Fully durable" means: no segments awaiting upload (`pending/` empty)
/// and no unflushed WAL records (`wal/` empty). Both directories are
/// populated by writes and emptied by the drain pipeline.
/// Post-flip best-effort housekeeping shared by `volume release` and
/// the breadcrumb-only release path. Each successful bucket flip
/// (`mark_released` returning `Updated`) wants to do the same three
/// things in the same order:
///
///   1. If we have a local fork: write `volume.released` so
///      `volume list` reflects the new state without a bucket
///      round-trip. Failure is logged but non-fatal — the bucket
///      record is authoritative.
///   2. Emit a journal entry recording the transition. Best-effort.
///   3. If a remote breadcrumb existed for this name, clear it.
///      Some paths don't have a breadcrumb to clear (the standard
///      local-fork release); a missing breadcrumb is a no-op.
///
/// Allow `too_many_arguments`: every parameter here is genuine
/// plumbing — the alternative struct-of-options just shifts the
/// same parameter list one indirection deeper without simplifying
/// any caller.
#[allow(clippy::too_many_arguments)]
async fn emit_release_aftermath(
    data_dir: &Path,
    journal: &dyn elide_coordinator::event_journal::EventJournal,
    identity: &Arc<elide_coordinator::identity::CoordinatorIdentity>,
    volume_name: &str,
    vol_dir_for_marker: Option<&Path>,
    handoff_snapshot: ulid::Ulid,
    vol_ulid: ulid::Ulid,
    event: elide_core::volume_event::EventKind,
    clear_breadcrumb: bool,
    log_prefix: &str,
) {
    if let Some(vol_dir) = vol_dir_for_marker
        && let Err(e) = write_released_marker(vol_dir, handoff_snapshot)
    {
        warn!(
            "[{log_prefix} {volume_name}] writing volume.released \
             marker: {e} (display-only; bucket state authoritative)"
        );
    }
    journal
        .emit_best_effort(identity.as_ref(), volume_name, event, vol_ulid)
        .await;
    if clear_breadcrumb
        && let Err(e) = elide_coordinator::remote_breadcrumb::remove(data_dir, volume_name)
    {
        warn!("[{log_prefix} {volume_name}] clearing breadcrumb: {e}");
    }
}

/// Guard run early in every `volume release` variant (local fork
/// and breadcrumb-only): pass through on `OwnedByUs`; refuse on
/// foreign-owned (point at `claim --force`), already-released,
/// or readonly records; surface the caller-supplied `absent_msg`
/// as the `not_found` reason. The error strings are
/// operator-facing and load-bearing for discoverability — keep
/// them verbatim.
fn ensure_release_eligible(
    position: &elide_coordinator::bucket_position::OwnershipPosition,
    volume_name: &str,
    absent_msg: String,
) -> Result<(), IpcError> {
    use elide_coordinator::bucket_position::OwnershipPosition;
    match position {
        OwnershipPosition::OwnedByUs { .. } => Ok(()),
        OwnershipPosition::OwnedByOther { coord_id, .. } => Err(IpcError::conflict(format!(
            "name '{volume_name}' is owned by coordinator {coord_id}; \
             if that owner is dead, run `volume claim --force` to take over"
        ))),
        OwnershipPosition::Released { .. } => Err(IpcError::conflict(format!(
            "name '{volume_name}' is already released"
        ))),
        OwnershipPosition::Readonly { .. } => Err(IpcError::conflict(format!(
            "name '{volume_name}' is readonly; nothing to release"
        ))),
        OwnershipPosition::Importing { coord_id, .. } => Err(IpcError::conflict(format!(
            "name '{volume_name}' is being imported on coordinator {coord_id}; \
             nothing to release"
        ))),
        OwnershipPosition::Absent => Err(IpcError::not_found(absent_msg)),
    }
}

/// User-wins-on-tie precedence for snapshot enumeration. Given a
/// candidate `(ulid, kind)` and the current best, returns `true`
/// when the candidate should replace it: strictly newer ULID, or
/// same ULID with `User` kind (which beats `Auto` to handle the
/// transient state of an in-flight auto→user promotion that crashed
/// between PUT and DELETE).
pub(super) fn snapshot_take_new(
    new: (ulid::Ulid, elide_core::signing::SnapshotKind),
    current: (ulid::Ulid, elide_core::signing::SnapshotKind),
) -> bool {
    new.0 > current.0 || (new.0 == current.0 && new.1 == elide_core::signing::SnapshotKind::User)
}

fn unflushed_state_reason(vol_dir: &Path) -> Option<String> {
    let dir_has_entries = |sub: &str| {
        std::fs::read_dir(vol_dir.join(sub))
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    };
    if dir_has_entries("pending") {
        return Some("local segments are pending upload to S3".to_string());
    }
    if dir_has_entries("wal") {
        return Some("local WAL has unflushed writes".to_string());
    }
    None
}

// ── Volume create / update ────────────────────────────────────────────────────

/// Parsed transport flags from the `create`/`update` IPC argument string.
/// Each `Some` field is an explicit set request; the corresponding `no_*`
/// boolean is an explicit clear. Mutually-exclusive flags are validated by
/// the consumer (different rules for create vs update).
#[derive(Default)]
pub(crate) struct TransportPatch {
    pub(crate) ublk: bool,
    pub(crate) no_ublk: bool,
}

/// Parse a flat space-separated flag list. Recognised tokens: `ublk`,
/// `no-ublk`.
///
/// Unknown tokens produce an error so silent typos don't get accepted.
/// There is no `ublk-id=<n>` token: the kernel auto-allocates on first
/// ADD and the chosen id is sticky across restarts (recorded in
/// `volume.toml`). Direct `elide serve-volume --ublk-id <n>` invocations
/// still allow pinning at the lowest layer for tests / emergency
/// override; that path bypasses this parser.
pub(crate) fn parse_transport_flags(args: &str) -> Result<TransportPatch, String> {
    let mut patch = TransportPatch::default();
    for tok in args.split_whitespace() {
        let (key, val) = match tok.split_once('=') {
            Some((k, v)) => (k, Some(v)),
            None => (tok, None),
        };
        match (key, val) {
            ("ublk", None) => patch.ublk = true,
            ("no-ublk", None) => patch.no_ublk = true,
            _ => return Err(format!("unknown flag: {tok}")),
        }
    }
    Ok(patch)
}

pub(crate) fn validate_volume_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("volume name must not be empty".to_owned());
    }
    if let Some(c) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_' && *c != '.')
    {
        return Err(format!(
            "invalid character {c:?} in volume name {name:?}: only [a-zA-Z0-9._-] allowed"
        ));
    }
    if matches!(name, "status" | "attach") {
        return Err(format!("'{name}' is a reserved name"));
    }
    Ok(())
}

async fn create_volume_op(
    name: &str,
    size_bytes: u64,
    flags: &[String],
    core: &CoordinatorCore,
) -> Result<CreateReply, IpcError> {
    let identity = &core.identity;
    // `coord-rw` for the names/<name> rollback on Phase-4 failure
    // (see end of function); the by_id/<vol>/{volume.pub,.provenance}
    // uploads go through the per-volume `volume-rw` handle vended by
    // `core.stores.volume_data(&vol_ulid)`.
    let store = core.stores.writer();
    let data_dir: &Path = &core.data_dir;
    let coord_id = identity.coordinator_id_str();

    validate_volume_name(name).map_err(IpcError::bad_request)?;
    if size_bytes == 0 {
        return Err(IpcError::bad_request("size must be non-zero"));
    }

    let patch = parse_transport_flags(&flags.join(" ")).map_err(IpcError::bad_request)?;
    if patch.no_ublk {
        return Err(IpcError::bad_request(
            "no-ublk is not valid on create (volume starts without transport)",
        ));
    }

    let ublk_cfg = if patch.ublk {
        Some(elide_core::config::UblkConfig::default())
    } else {
        None
    };

    let by_name_dir = data_dir.join("by_name");
    if by_name_dir.join(name).exists() {
        return Err(IpcError::conflict(format!("volume already exists: {name}")));
    }

    let vol_ulid = ulid::Ulid::new();
    let vol_ulid_str = vol_ulid.to_string();
    let vol_dir = elide_coordinator::volume_state::fork_dir(data_dir, vol_ulid);

    // Phase 1: create the local volume directory, signing key, and
    // signed empty-lineage `volume.provenance`. Both immutable trust
    // artefacts must exist on disk before Phase 2 uploads them, and
    // both must land in S3 *before* `names/<name>` so the invariant
    // "every named vol_ulid has volume.pub *and* volume.provenance in
    // the bucket" holds across crashes. A SIGINT before the upload
    // leaves only local-disk state, which `cleanup_local` rolls back.
    let cleanup_local = || {
        let _ = std::fs::remove_file(by_name_dir.join(name));
        let _ = std::fs::remove_dir_all(&vol_dir);
    };
    if let Err(e) = (|| {
        std::fs::create_dir_all(&vol_dir)?;
        std::fs::create_dir_all(vol_dir.join("pending"))?;
        std::fs::create_dir_all(vol_dir.join("index"))?;
        std::fs::create_dir_all(vol_dir.join("cache"))?;
        let key = elide_core::signing::generate_keypair(
            &vol_dir,
            elide_core::signing::VOLUME_KEY_FILE,
            elide_core::signing::VOLUME_PUB_FILE,
        )?;
        // Shadow the signing key under `data_dir/keys/<vol_ulid>.key`
        // immediately. The shadow is `start`'s possession proof after
        // a `remove` — the private key is never uploaded, and a
        // future `start` fails without it.
        elide_coordinator::key_shadow::write(data_dir, vol_ulid, &key.to_bytes())?;
        elide_core::signing::write_provenance(
            &vol_dir,
            &key,
            elide_core::signing::VOLUME_PROVENANCE_FILE,
            &elide_core::signing::ProvenanceLineage::default(),
        )?;
        Ok::<_, std::io::Error>(())
    })() {
        cleanup_local();
        // Best-effort shadow cleanup if create rolls back partway.
        let _ = elide_coordinator::key_shadow::remove(data_dir, vol_ulid);
        return Err(IpcError::internal(format!("create failed: {e}")));
    }

    // Phase 2: publish volume.pub *and* volume.provenance to S3
    // *before* claiming the name. Both files are immutable. A SIGINT
    // here at worst leaves orphan
    // `by_id/<vol_ulid>/{volume.pub, volume.provenance}` (no
    // names/<name> references them, so they're harmless and
    // GC-reclaimable).
    let meta_store = core.stores.writer();
    if let Err(e) =
        elide_coordinator::upload::upload_volume_pub_initial(&core.data_dir, vol_ulid, &meta_store)
            .await
    {
        cleanup_local();
        return Err(IpcError::store(format!("uploading volume.pub: {e:#}")));
    }
    if let Err(e) = elide_coordinator::upload::upload_volume_provenance_initial(
        &core.data_dir,
        vol_ulid,
        &meta_store,
    )
    .await
    {
        cleanup_local();
        return Err(IpcError::store(format!(
            "uploading volume.provenance: {e:#}"
        )));
    }

    // Phase 3: claim the name in S3. After this point the names/<name>
    // record exists in the bucket and references a vol_ulid whose
    // volume.pub is already uploaded — recovery via `claim --force`
    // is always possible from here on.
    use elide_coordinator::lifecycle::{LifecycleError, MarkInitialOutcome};
    match core
        .stores
        .name_claims()
        .mark_initial(name, coord_id, identity.hostname(), vol_ulid, size_bytes)
        .await
    {
        Ok(MarkInitialOutcome::Claimed) => {
            core.stores
                .event_journal()
                .emit_best_effort(
                    identity.as_ref(),
                    name,
                    elide_core::volume_event::EventKind::Created,
                    vol_ulid,
                )
                .await;
        }
        Ok(MarkInitialOutcome::AlreadyExists {
            existing_vol_ulid,
            existing_state,
            existing_owner,
        }) => {
            cleanup_local();
            let owner = existing_owner.as_deref().unwrap_or("<unowned>");
            return Err(IpcError::conflict(format!(
                "name '{name}' already exists in bucket \
                 (vol_ulid={existing_vol_ulid}, state={existing_state:?}, \
                 owner={owner})"
            )));
        }
        Err(LifecycleError::Store(e)) => {
            cleanup_local();
            return Err(IpcError::store(format!("claiming name in bucket: {e}")));
        }
        Err(LifecycleError::OwnershipConflict { held_by }) => {
            // mark_initial doesn't currently surface this, but match
            // exhaustively so a future refactor doesn't silently drop it.
            cleanup_local();
            return Err(IpcError::conflict(format!(
                "name held by another coordinator: {held_by}"
            )));
        }
        Err(LifecycleError::InvalidTransition { from, .. }) => {
            cleanup_local();
            return Err(IpcError::conflict(format!(
                "names/<name> is in unexpected state {from:?}"
            )));
        }
    }

    // Phase 4: finish local state (config + by_name symlink).
    // Provenance was already written in Phase 1 so it could be
    // uploaded in Phase 2 ahead of the names/<name> claim.
    let result: std::io::Result<()> = (|| {
        elide_core::config::VolumeConfig {
            name: Some(name.to_owned()),
            size: Some(size_bytes),
            ublk: ublk_cfg,
            lazy: None,
        }
        .write(&vol_dir)?;
        std::fs::create_dir_all(&by_name_dir)?;
        std::os::unix::fs::symlink(format!("../by_id/{vol_ulid_str}"), by_name_dir.join(name))?;
        Ok(())
    })();

    if let Err(e) = result {
        // Phase-4 failure: roll back local artefacts *and* the bucket-side
        // claim so the name is free to retry. The orphan volume.pub stays
        // in S3 — it's not pointed to by anything and will be reclaimed
        // by future GC.
        cleanup_local();
        let name_key = object_store::path::Path::from(format!("names/{name}"));
        if let Err(del_err) = store.delete(&name_key).await {
            warn!(
                "[inbound] create {name}: local setup failed and rollback \
                 of names/<name> also failed: {del_err}"
            );
        }
        return Err(IpcError::internal(format!("create failed: {e}")));
    }

    crate::rescan::trigger();
    info!("[inbound] created volume {name} ({vol_ulid_str})");
    Ok(CreateReply { vol_ulid })
}

async fn update_volume_op(
    name: &str,
    flags: &[String],
    data_dir: &Path,
) -> Result<UpdateReply, IpcError> {
    if name.is_empty() {
        return Err(IpcError::bad_request("usage: update <volume> [flags...]"));
    }
    let link = data_dir.join("by_name").join(name);
    if !link.exists() {
        return Err(IpcError::not_found(format!("volume not found: {name}")));
    }
    let vol_dir = std::fs::canonicalize(&link)
        .map_err(|e| IpcError::internal(format!("resolving volume dir: {e}")))?;

    let patch = parse_transport_flags(&flags.join(" ")).map_err(IpcError::bad_request)?;

    let mut cfg = elide_core::config::VolumeConfig::read(&vol_dir)
        .map_err(|e| IpcError::internal(format!("reading volume.toml: {e}")))?;
    // Capture the previously-bound dev_id before mutating cfg, so we can
    // tear the kernel device down after the new config takes effect.
    let prev_bound_id = cfg.ublk.as_ref().and_then(|u| u.dev_id);

    if patch.no_ublk {
        cfg.ublk = None;
    } else if patch.ublk {
        // Enable ublk. The kernel auto-allocates a dev_id on first ADD;
        // any existing binding is preserved (clobbering it with `None`
        // would silently invalidate the kernel-stamped recovery path on
        // the next serve).
        if cfg.ublk.is_none() {
            cfg.ublk = Some(elide_core::config::UblkConfig::default());
        }
    }

    // Decide which previously-bound kernel device (if any) to tear
    // down *after* writing the new config. With `--ublk-id` removed
    // from the user CLI, the only path that requires teardown here is
    // transport disabled / switched: the volume previously had a bound
    // id and the new cfg has no `[ublk]` section. The kernel device
    // must go — leaving it QUIESCED contradicts the new transport
    // policy and leaves an orphan whose stamped owner can take down
    // the daemon on the next `elide ublk delete`.
    //
    // Plain `volume stop` / restart with no transport change does NOT
    // take this path — that's the maintenance bounce, where QUIESCED +
    // recover is the desired behaviour.
    let teardown_id: Option<i32> = match (prev_bound_id, cfg.ublk.is_some()) {
        (Some(prev), false) => Some(prev),
        _ => None,
    };

    // Snapshot the live daemon's pid before the supervisor respawns it
    // under the new cfg. Used after `shutdown` returns `Acknowledged` to
    // wait for the OLD process to actually exit (releasing its ublk
    // queue io_uring fds) before issuing `del_dev`.
    let prev_pid: Option<u32> =
        teardown_id.and_then(|_| crate::ublk_sweep::read_volume_pid(&vol_dir));

    cfg.write(&vol_dir)
        .map_err(|e| IpcError::internal(format!("writing volume.toml: {e}")))?;

    // Restart the volume process so it picks up the new config. ECONNREFUSED /
    // ENOENT mean the volume isn't running — fine, the new config takes effect
    // on next start.
    use elide_coordinator::control::ShutdownOutcome;
    let restarted = match elide_coordinator::control::shutdown(&vol_dir).await {
        ShutdownOutcome::Acknowledged => {
            info!("[inbound] updated volume {name}; restart triggered");
            true
        }
        ShutdownOutcome::Failed(msg) => {
            return Err(IpcError::internal(format!("shutdown failed: {msg}")));
        }
        ShutdownOutcome::NotRunning => {
            info!("[inbound] updated volume {name}; not running");
            false
        }
    };

    // Tear down after shutdown so the kernel's queue io_uring fds are
    // released before del_dev waits on refcounts. `shutdown` returns
    // when the daemon's IPC reply lands, which is *before* its
    // `exit(0)` — wait for the pid to actually exit so the kernel's
    // refcount on the ublk_device drops. The supervisor's respawn is
    // racing us, but the new daemon reads the new cfg — either no
    // ublk, or a different bound id — and never touches the old kernel
    // device, so there is no conflict.
    if let Some(id) = teardown_id {
        if let Some(pid) = prev_pid {
            crate::ublk_sweep::wait_for_pid_exit(pid).await;
        }
        crate::ublk_sweep::teardown_bound_device(&vol_dir, id).await;
    }

    Ok(UpdateReply { restarted })
}

// ── Volume fork (create --from) plumbing ──────────────────────────────────────

/// Pull one readonly ancestor from the store.
///
/// Downloads `volume.pub` and `volume.provenance` and writes the ancestor
/// skeleton under `data_dir/by_id/<vol_ulid>/`. Returns the parent ULID
/// parsed from the (signature-verified) provenance, or `None` if this is a
/// root volume. Ancestors carry no `volume.toml` and no size: per
/// `docs/design-volume-size-ownership.md`, size lives only on the live
/// `names/<name>` record.
///
/// `peer` is best-effort: when `Some` and the peer's auth pipeline
/// accepts the request (i.e. `names/<volume>` already points at our
/// coordinator id), each of the two GETs is tried at the peer first
/// and falls through to S3 on miss. Provenance signatures are still
/// checked against the just-downloaded `volume.pub`, but that check
/// is self-consistent — a peer that forges both files passes here.
/// The caller is responsible for downstream verification against an
/// S3-rooted artifact (see [`PulledAncestorsGuard`]).
pub(crate) async fn pull_readonly_op(
    vol_ulid: ulid::Ulid,
    data_dir: &Path,
    store: &Arc<dyn ObjectStore>,
    peer: Option<&elide_coordinator::prefetch::PeerFetchContext>,
) -> Result<PullReadonlyReply, IpcError> {
    let volume_id = vol_ulid.to_string();
    let vol_dir = elide_coordinator::volume_state::fork_dir(data_dir, vol_ulid);
    if vol_dir.exists() {
        return Err(IpcError::conflict(format!(
            "volume already present locally: {volume_id}"
        )));
    }

    let pull_started = std::time::Instant::now();

    // Steps 1-3: fetch volume.pub + volume.provenance and write the
    // ancestor skeleton via `pull_volume_skeleton`. The two GETs run
    // in parallel so per-ancestor latency is bounded by the slowest
    // leg rather than the sum; peer-first when a context is supplied.
    elide_coordinator::pull::pull_volume_skeleton(store, data_dir, vol_ulid, peer)
        .await
        .map_err(|e| IpcError::store(format!("pulling skeleton for {volume_id}: {e}")))?;
    let fetch_elapsed = pull_started.elapsed();

    // Step 4: parse and verify provenance to find the parent. Verification
    // is self-consistent (provenance signature checked against the
    // just-downloaded volume.pub) — peer-served forgery isn't caught here
    // and is the caller's responsibility to detect downstream (typically
    // by failing to verify a real S3-rooted artifact, e.g. the handoff
    // manifest fetched in `skip_empty_intermediates`). The
    // [`PulledAncestorsGuard`] in `run_claim_job` cleans up on that
    // downstream failure.
    let verify_started = std::time::Instant::now();
    let parent = match elide_core::signing::read_lineage_verifying_signature(
        &vol_dir,
        elide_core::signing::VOLUME_PUB_FILE,
        elide_core::signing::VOLUME_PROVENANCE_FILE,
    ) {
        Ok(lineage) => lineage
            .parent
            .map(|p| {
                ulid::Ulid::from_string(&p.volume_ulid).map_err(|e| {
                    IpcError::internal(format!("malformed parent ULID {:?}: {e}", p.volume_ulid))
                })
            })
            .transpose()?,
        Err(e) => {
            let _ = std::fs::remove_dir_all(&vol_dir);
            return Err(IpcError::internal(format!(
                "verifying provenance for {volume_id}: {e}"
            )));
        }
    };
    let verify_elapsed = verify_started.elapsed();

    info!(
        "[inbound] pulled ancestor {volume_id} in {:.2?} (fetch {:.2?}, verify {:.2?})",
        pull_started.elapsed(),
        fetch_elapsed,
        verify_elapsed,
    );
    Ok(PullReadonlyReply { parent })
}

/// Wait for the per-fork prefetch result and echo it.
///
/// The IPC has no internal timeout — the volume-side caller bounds it. If
/// the per-fork task disappears (channel closed without a final value, e.g.
/// the volume directory was removed) we report that as an error rather than
/// silently returning ok, so the caller can act on it.
pub(crate) async fn await_prefetch_op(
    vol_ulid: ulid::Ulid,
    tracker: &PrefetchTracker,
) -> Result<(), IpcError> {
    let mut rx = match subscribe_prefetch(tracker, &vol_ulid) {
        Some(rx) => rx,
        // Untracked: either already prefetched on a previous coordinator run,
        // or this coordinator hasn't discovered the fork yet. Both cases are
        // safe to treat as ready — Volume::open's own retry helper still
        // absorbs the rare "fork not yet on disk" sub-race.
        None => return Ok(()),
    };

    loop {
        // `borrow()` returns the most recently published value; if a value
        // was already sent before we subscribed it is visible immediately.
        if let Some(result) = rx.borrow().clone() {
            return match result {
                Ok(()) => Ok(()),
                Err(msg) => Err(IpcError::internal(format!("prefetch failed: {msg}"))),
            };
        }
        if rx.changed().await.is_err() {
            // Sender was dropped before publishing — the per-fork task exited
            // abnormally (volume removed mid-prefetch, panic, etc.).
            return Err(IpcError::internal(
                "prefetch task exited without publishing a result",
            ));
        }
    }
}

// ── Macaroon-authenticated credential vending ────────────────────────────────

/// Verify the connecting peer matches the volume's recorded `volume.pid`.
///
/// Returns `Ok(pid)` on a clean match. Returns `Err(<wire-error-line>)` ready
/// to send back to the volume — the messages are intentionally generic so a
/// hostile caller can't tell apart "no such volume", "pid not yet recorded"
/// (the spawn-write race), or "pid mismatch".
fn check_peer_pid(vol_dir: &Path, peer_pid: Option<i32>) -> Result<i32, String> {
    check_peer_pid_against(vol_dir, peer_pid, PID_FILE)
}

/// Generalized PID handshake: read `<vol_dir>/<pid_filename>`, check
/// it parses as an integer, and verify it matches `peer_pid` (the
/// `SO_PEERCRED` value supplied by the IPC layer). Used by
/// [`register_volume`] (against `volume.pid`).
fn check_peer_pid_against(
    vol_dir: &Path,
    peer_pid: Option<i32>,
    pid_filename: &str,
) -> Result<i32, String> {
    let peer_pid = peer_pid.ok_or_else(|| "err peer pid unavailable".to_string())?;
    let pid_path = vol_dir.join(pid_filename);
    let recorded: i32 = match std::fs::read_to_string(&pid_path) {
        Ok(s) => s
            .trim()
            .parse()
            .map_err(|_| format!("err {pid_filename} is not numeric"))?,
        // Brief window between spawn and parent writing the pidfile:
        // a fast-starting child can dial the socket before the parent
        // has written the file — caller retries on this error class.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err("err volume not registered".to_string());
        }
        Err(e) => return Err(format!("err reading {pid_filename}: {e}")),
    };
    if recorded != peer_pid {
        return Err(format!("err peer pid does not match {pid_filename}"));
    }
    Ok(peer_pid)
}

fn register_volume(
    volume_ulid: ulid::Ulid,
    data_dir: &Path,
    peer_pid: Option<i32>,
    macaroon_root: &[u8; 32],
) -> Result<RegisterReply, IpcError> {
    let ulid_str = volume_ulid.to_string();
    let vol_dir = elide_coordinator::volume_state::fork_dir(data_dir, volume_ulid);
    if !vol_dir.exists() {
        return Err(IpcError::not_found("unknown volume"));
    }
    let pid = check_peer_pid_against(&vol_dir, peer_pid, PID_FILE).map_err(IpcError::forbidden)?;
    let m = macaroon::mint(
        macaroon_root,
        vec![
            Caveat::Volume(ulid_str.clone()),
            Caveat::Scope(Scope::Credentials),
            Caveat::Pid(pid),
        ],
    );
    info!(
        target: "creds::issuance",
        volume_ulid = %ulid_str,
        peer_pid = pid,
        scope = "credentials",
        macaroon_nonce = %m.nonce_hex(),
        "minted macaroon for volume daemon",
    );
    Ok(RegisterReply {
        macaroon: m.encode(),
        peer_endpoint: None,
    })
}

/// Resolve the previous claimer's peer-fetch endpoint for `volume_ulid`.
///
/// `Some(endpoint)` only when peer-fetch is locally configured, the
/// volume name is readable from the fork dir, and discovery resolves
/// a clean handoff. Every other path collapses to `None` — the volume
/// runs S3-only.
async fn resolve_peer_endpoint_for_volume(
    volume_ulid: ulid::Ulid,
    data_dir: &Path,
    stores: &Arc<dyn elide_coordinator::stores::ScopedStores>,
) -> Option<PeerEndpoint> {
    elide_coordinator::tasks::peer_fetch_handle()?;
    let vol_dir = elide_coordinator::volume_state::fork_dir(data_dir, volume_ulid);
    let volume_name = elide_coordinator::tasks::read_volume_name(&vol_dir)?;
    // Cross-coordinator RO reads: events/<name>/HEAD + coordinators/<other>/* —
    // coord-ro scope. The read-only journal carries that.
    let store = stores.base_object_store();
    let journal = stores.event_journal_ro();
    elide_coordinator::peer_discovery::discover_peer_for_claim(
        &store,
        journal.as_ref(),
        &volume_name,
    )
    .await
    .map(|d| d.endpoint)
}

/// Shared authentication preamble for the macaroon-bound volume-daemon
/// IPC ops (`Credentials`, `PeerClaimerToken`): MAC verify, volume
/// caveat extraction, scope + caveat checks, and a fresh SO_PEERCRED /
/// `volume.pid` / liveness re-check. Returns the parsed macaroon (for
/// audit-log fields) and the bound `volume_ulid`. One copy so the two
/// ops can never drift on the security checks.
async fn authenticate_volume_macaroon(
    macaroon_str: &str,
    data_dir: &Path,
    peer_pid: Option<i32>,
    macaroon_root: &[u8; 32],
) -> Result<(Macaroon, macaroon::Verified), IpcError> {
    let m = Macaroon::parse(macaroon_str)
        .map_err(|e| IpcError::bad_request(format!("parse macaroon: {e}")))?;
    if !macaroon::verify(macaroon_root, &m) {
        // Generic message — don't help an attacker distinguish "wrong key"
        // from "tampered caveats".
        return Err(IpcError::forbidden("invalid macaroon"));
    }
    let peer_pid = peer_pid.ok_or_else(|| IpcError::forbidden("peer pid unavailable"))?;
    let volume_ulid = m
        .volume()
        .ok_or_else(|| IpcError::forbidden("macaroon missing volume caveat"))?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verified = macaroon::check_caveats(
        &m,
        &VerifyCtx {
            volume: volume_ulid,
            peer_pid,
            now_unix,
            accepted_scopes: &[Scope::Credentials],
        },
    )
    .map_err(IpcError::forbidden)?;
    // Re-validate that volume.pid still matches — covers the case where the
    // original process has exited and the PID was reused.
    let vol_dir = elide_coordinator::volume_state::fork_dir(data_dir, volume_ulid);
    check_peer_pid(&vol_dir, Some(peer_pid)).map_err(IpcError::forbidden)?;
    if !pid_is_alive(peer_pid as u32) {
        return Err(IpcError::forbidden("peer pid not alive"));
    }
    Ok((m, verified))
}

/// Resolve a claimed volume's current name from its ULID via the
/// authoritative local `by_name/<name>` → `by_id/<ulid>` symlinks.
/// This is the same name the serving peer's step 3 resolves through
/// `names/<name>`; a coordinator with no local `by_name` entry for the
/// volume is not its current local claimer and cannot mint a passing
/// claimer token.
fn resolve_volume_name(data_dir: &Path, verified: &macaroon::Verified) -> Result<String, IpcError> {
    let by_name = data_dir.join("by_name");
    let entries = std::fs::read_dir(&by_name)
        .map_err(|e| IpcError::internal(format!("read by_name: {e}")))?;
    let target_ulid_str = verified.copy_inner().to_string();
    for entry in entries.flatten() {
        let link = entry.path();
        if !link.is_symlink() {
            continue;
        }
        let Ok(target) = std::fs::canonicalize(&link) else {
            continue;
        };
        if target.file_name().and_then(|n| n.to_str()) == Some(target_ulid_str.as_str())
            && let Some(name) = entry.file_name().to_str()
        {
            return Ok(name.to_owned());
        }
    }
    Err(IpcError::forbidden(
        "no local name claim for volume; not the current claimer",
    ))
}

async fn issue_credentials(
    macaroon_str: &str,
    target: ulid::Ulid,
    data_dir: &Path,
    peer_pid: Option<i32>,
    macaroon_root: &[u8; 32],
    issuer: &dyn CredentialIssuer,
) -> Result<StoreCredsReply, IpcError> {
    let (m, verified) =
        authenticate_volume_macaroon(macaroon_str, data_dir, peer_pid, macaroon_root).await?;
    let requester = verified.copy_inner();

    // Authorize the requested target against the requester's lineage. The
    // macaroon authenticates the requester; `target` is the single
    // `by_id/<target>/*` prefix it wants to read. The resulting
    // `AuthorizedTarget` is a proof the check passed — `issue` cannot be
    // reached without one (`docs/design-mint.md` § per-volume read creds).
    let authorized = crate::credential::authorize_target(&verified, target, data_dir)?;

    let creds = issuer
        .issue(authorized)
        .await
        .map_err(|e| IpcError::internal(format!("issue: {e}")))?;
    info!(
        target: "creds::issuance",
        requester = %requester,
        target = %target,
        peer_pid,
        macaroon_nonce = %m.nonce_hex(),
        macaroon_not_after = ?m.narrowest_not_after(),
        expiry_unix = creds.expiry_unix,
        "issued S3 credentials to volume",
    );
    Ok(StoreCredsReply {
        access_key_id: creds.access_key_id,
        secret_access_key: creds.secret_access_key,
        session_token: creds.session_token,
        expiry_unix: creds.expiry_unix,
    })
}

/// Mint a coordinator-signed `PeerFetchToken` claimer credential for
/// the requesting volume daemon. Same authentication as
/// `issue_credentials`; the token is scoped to the volume's current
/// name claim and signed with `coordinator.key`, so the serving peer's
/// steps 1–3 confirm the requester is this volume's current claimer
/// before serving body bytes.
async fn mint_peer_claimer_token(
    macaroon_str: &str,
    data_dir: &Path,
    peer_pid: Option<i32>,
    identity: &elide_coordinator::identity::CoordinatorIdentity,
) -> Result<PeerClaimerTokenReply, IpcError> {
    let (m, verified) =
        authenticate_volume_macaroon(macaroon_str, data_dir, peer_pid, identity.macaroon_root())
            .await?;
    let volume_ulid = verified.copy_inner();
    let name = resolve_volume_name(data_dir, &verified)?;
    let coordinator_id = identity.coordinator_id_str().to_owned();
    let issued_at = elide_peer_fetch::PeerFetchToken::now_unix_seconds();
    let payload =
        elide_peer_fetch::PeerFetchToken::signing_payload(&name, &coordinator_id, issued_at);
    let signature =
        <elide_coordinator::identity::CoordinatorIdentity as elide_peer_fetch::TokenSigner>::sign(
            identity, &payload,
        );
    let token = elide_peer_fetch::PeerFetchToken {
        volume_name: name.clone(),
        coordinator_id,
        issued_at,
        signature,
    };
    info!(
        target: "creds::issuance",
        volume_ulid = %volume_ulid,
        volume_name = %name,
        macaroon_nonce = %m.nonce_hex(),
        "minted peer-fetch claimer token for volume daemon",
    );
    Ok(PeerClaimerTokenReply {
        token: token.encode(),
        issued_at,
    })
}

async fn stream_fork_by_name(new_name: &str, writer: &mut OwnedWriteHalf, registry: &ForkRegistry) {
    async fn write_err(writer: &mut OwnedWriteHalf, error: IpcError) {
        let env: Envelope<ForkAttachEvent> = Envelope::err(error);
        let _ = ipc::write_message(writer, &env).await;
    }

    let job = {
        let reg = registry.lock().expect("fork registry poisoned");
        reg.get(new_name).cloned()
    };
    let Some(job) = job else {
        write_err(
            writer,
            IpcError::not_found(format!("no active fork for: {new_name}")),
        )
        .await;
        return;
    };

    let mut offset = 0;
    loop {
        let events = job.read_from(offset);
        for event in &events {
            let env: Envelope<ForkAttachEvent> = Envelope::ok(event.clone());
            if ipc::write_message(writer, &env).await.is_err() {
                return;
            }
        }
        offset += events.len();

        match job.state() {
            ForkJobState::Done => return,
            ForkJobState::Failed(err) => {
                write_err(writer, err).await;
                return;
            }
            ForkJobState::Running => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// Stream buffered + live claim events to `writer`, terminating with
/// `Done` (success) or `Envelope::Err` (failure).
async fn stream_claim_by_name(volume: &str, writer: &mut OwnedWriteHalf, registry: &ClaimRegistry) {
    async fn write_err(writer: &mut OwnedWriteHalf, error: IpcError) {
        let env: Envelope<ClaimAttachEvent> = Envelope::err(error);
        let _ = ipc::write_message(writer, &env).await;
    }

    let job = {
        let reg = registry.lock().expect("claim registry poisoned");
        reg.get(volume).cloned()
    };
    let Some(job) = job else {
        write_err(
            writer,
            IpcError::not_found(format!("no active claim for: {volume}")),
        )
        .await;
        return;
    };

    let mut offset = 0;
    loop {
        let events = job.read_from(offset);
        for event in &events {
            let env: Envelope<ClaimAttachEvent> = Envelope::ok(event.clone());
            if ipc::write_message(writer, &env).await.is_err() {
                return;
            }
        }
        offset += events.len();

        match job.state() {
            ClaimJobState::Done => return,
            ClaimJobState::Failed(err) => {
                write_err(writer, err).await;
                return;
            }
            ClaimJobState::Running => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_helpers::*;
    use super::*;
    use crate::credential::IssuedCredentials;
    use elide_coordinator::eligibility::Eligibility;
    use elide_coordinator::ipc::IpcErrorKind;
    use elide_coordinator::volume_state::STOPPED_FILE;
    use tempfile::TempDir;

    struct FixedIssuer;
    #[async_trait::async_trait]
    impl CredentialIssuer for FixedIssuer {
        async fn issue(
            &self,
            _target: crate::credential::AuthorizedTarget,
        ) -> std::io::Result<IssuedCredentials> {
            Ok(IssuedCredentials {
                access_key_id: "AK".into(),
                secret_access_key: "SK".into(),
                session_token: None,
                expiry_unix: None,
            })
        }
    }

    fn setup_volume(data_dir: &Path, ulid: &str, pid: i32) {
        let dir = data_dir.join("by_id").join(ulid);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(PID_FILE), pid.to_string()).unwrap();
    }

    fn key() -> [u8; 32] {
        [0x42; 32]
    }

    fn ulid_from(s: &str) -> ulid::Ulid {
        ulid::Ulid::from_string(s).unwrap()
    }

    #[test]
    fn register_succeeds_when_peer_pid_matches_volume_pid() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        setup_volume(tmp.path(), ulid_str, 4242);
        let reply = register_volume(ulid_from(ulid_str), tmp.path(), Some(4242), &key())
            .expect("matching pid → ok");
        assert!(!reply.macaroon.is_empty());
    }

    #[test]
    fn register_rejects_pid_mismatch() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        setup_volume(tmp.path(), ulid_str, 4242);
        let err = register_volume(ulid_from(ulid_str), tmp.path(), Some(9999), &key())
            .expect_err("mismatched pid should error");
        assert_eq!(err.kind, IpcErrorKind::Forbidden);
        assert!(err.message.contains("does not match"), "{err}");
    }

    #[test]
    fn register_rejects_when_volume_pid_missing() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        // Create the volume dir but no volume.pid yet — this is the spawn-write
        // race the volume-side retry absorbs.
        std::fs::create_dir_all(tmp.path().join("by_id").join(ulid_str)).unwrap();
        let err = register_volume(ulid_from(ulid_str), tmp.path(), Some(4242), &key())
            .expect_err("missing pid file should error");
        assert!(err.message.contains("not registered"), "{err}");
    }

    #[test]
    fn register_rejects_unknown_volume() {
        let tmp = TempDir::new().unwrap();
        let err = register_volume(
            ulid_from("01JQAAAAAAAAAAAAAAAAAAAAAA"),
            tmp.path(),
            Some(4242),
            &key(),
        )
        .expect_err("unknown volume should error");
        assert_eq!(err.kind, IpcErrorKind::NotFound);
        assert!(err.message.contains("unknown volume"), "{err}");
    }

    #[tokio::test]
    async fn credentials_round_trip_with_live_pid() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        // Use our own pid so the pid_is_alive check passes inside the handler.
        let my_pid = std::process::id() as i32;
        setup_volume(tmp.path(), ulid_str, my_pid);
        let mint_reply = register_volume(ulid_from(ulid_str), tmp.path(), Some(my_pid), &key())
            .expect("register should succeed");
        let issuer = FixedIssuer;
        let creds = issue_credentials(
            &mint_reply.macaroon,
            ulid_from(ulid_str),
            tmp.path(),
            Some(my_pid),
            &key(),
            &issuer,
        )
        .await
        .expect("credentials should succeed");
        assert_eq!(creds.access_key_id, "AK");
        assert_eq!(creds.secret_access_key, "SK");
    }

    #[tokio::test]
    async fn credentials_rejects_wrong_root_key() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let my_pid = std::process::id() as i32;
        setup_volume(tmp.path(), ulid_str, my_pid);
        let mint_reply = register_volume(ulid_from(ulid_str), tmp.path(), Some(my_pid), &key())
            .expect("register should succeed");
        let mut other = key();
        other[0] ^= 0xFF;
        let issuer = FixedIssuer;
        let err = issue_credentials(
            &mint_reply.macaroon,
            ulid_from(ulid_str),
            tmp.path(),
            Some(my_pid),
            &other,
            &issuer,
        )
        .await
        .expect_err("wrong root key should fail");
        assert_eq!(err.kind, IpcErrorKind::Forbidden);
        assert!(err.message.contains("invalid macaroon"), "{err}");
    }

    #[tokio::test]
    async fn credentials_rejects_pid_mismatch() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let my_pid = std::process::id() as i32;
        setup_volume(tmp.path(), ulid_str, my_pid);
        let mint_reply = register_volume(ulid_from(ulid_str), tmp.path(), Some(my_pid), &key())
            .expect("register should succeed");
        let issuer = FixedIssuer;
        // Present a different peer pid than the macaroon was minted for.
        let err = issue_credentials(
            &mint_reply.macaroon,
            ulid_from(ulid_str),
            tmp.path(),
            Some(my_pid + 1),
            &key(),
            &issuer,
        )
        .await
        .expect_err("pid mismatch should fail");
        assert_eq!(err.kind, IpcErrorKind::Forbidden);
        assert!(
            err.message.contains("does not match macaroon")
                || err.message.contains("does not match volume.pid"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn credentials_rejects_tampered_caveat() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let my_pid = std::process::id() as i32;
        setup_volume(tmp.path(), ulid_str, my_pid);
        // Mint a macaroon for a different volume — the verify call rejects
        // because the volume caveat is wrong even though MAC matches.
        let other_ulid_str = "01JQBBBBBBBBBBBBBBBBBBBBBB";
        setup_volume(tmp.path(), other_ulid_str, my_pid);
        let mint_reply =
            register_volume(ulid_from(other_ulid_str), tmp.path(), Some(my_pid), &key())
                .expect("register should succeed");
        let parsed = Macaroon::parse(&mint_reply.macaroon).unwrap();
        let mut caveats: Vec<Caveat> = parsed.caveats().to_vec();
        for c in &mut caveats {
            if let Caveat::Volume(v) = c {
                *v = ulid_str.to_owned();
            }
        }
        // Construct a forged macaroon with rewritten caveats under a wrong
        // key — verify must fail.
        let forged = macaroon::mint(&[0u8; 32], caveats);
        let issuer = FixedIssuer;
        let err = issue_credentials(
            &forged.encode(),
            ulid_from(ulid_str),
            tmp.path(),
            Some(my_pid),
            &key(),
            &issuer,
        )
        .await
        .expect_err("tampered caveat should fail");
        assert_eq!(err.kind, IpcErrorKind::Forbidden);
        assert!(err.message.contains("invalid macaroon"), "{err}");
    }

    #[tokio::test]
    async fn credentials_rejects_expired_macaroon() {
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let my_pid = std::process::id() as i32;
        setup_volume(tmp.path(), ulid_str, my_pid);
        let m = macaroon::mint(
            &key(),
            vec![
                Caveat::Volume(ulid_str.to_owned()),
                Caveat::Scope(macaroon::Scope::Credentials),
                Caveat::Pid(my_pid),
                Caveat::NotAfter(1), // unix second 1 — long ago
            ],
        );
        let issuer = FixedIssuer;
        let err = issue_credentials(
            &m.encode(),
            ulid_from(ulid_str),
            tmp.path(),
            Some(my_pid),
            &key(),
            &issuer,
        )
        .await
        .expect_err("expired macaroon should fail");
        assert_eq!(err.kind, IpcErrorKind::Forbidden);
        assert!(err.message.contains("expired"), "{err}");
    }

    #[tokio::test]
    async fn credentials_target_unrelated_volume_is_forbidden() {
        // The macaroon authenticates the requester; `target` is the
        // prefix it wants to read. A volume with no lineage may obtain
        // creds only for itself — any other target is refused, so a
        // volume cannot mint another volume's read credential.
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let my_pid = std::process::id() as i32;
        setup_volume(tmp.path(), ulid_str, my_pid);
        let mint_reply = register_volume(ulid_from(ulid_str), tmp.path(), Some(my_pid), &key())
            .expect("register should succeed");
        let issuer = FixedIssuer;
        let unrelated = ulid_from("01JQZZZZZZZZZZZZZZZZZZZZZZ");
        let err = issue_credentials(
            &mint_reply.macaroon,
            unrelated,
            tmp.path(),
            Some(my_pid),
            &key(),
            &issuer,
        )
        .await
        .expect_err("unrelated target must be forbidden");
        assert_eq!(err.kind, IpcErrorKind::Forbidden);
        assert!(err.message.contains("ancestor"), "{err}");
    }

    #[tokio::test]
    async fn credentials_target_ancestor_is_allowed() {
        // A volume whose signed provenance names a parent may obtain
        // read creds for that ancestor's prefix.
        let tmp = TempDir::new().unwrap();
        let ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let parent_str = "01JQBBBBBBBBBBBBBBBBBBBBBB";
        let my_pid = std::process::id() as i32;
        setup_volume(tmp.path(), ulid_str, my_pid);
        // Sign self's provenance with a parent ref so lineage resolves.
        let self_dir = tmp.path().join("by_id").join(ulid_str);
        let self_key = elide_core::signing::generate_keypair(
            &self_dir,
            elide_core::signing::VOLUME_KEY_FILE,
            elide_core::signing::VOLUME_PUB_FILE,
        )
        .unwrap();
        elide_core::signing::write_provenance(
            &self_dir,
            &self_key,
            elide_core::signing::VOLUME_PROVENANCE_FILE,
            &elide_core::signing::ProvenanceLineage {
                parent: Some(elide_core::signing::ParentRef {
                    volume_ulid: parent_str.to_owned(),
                    snapshot_ulid: "01JQCCCCCCCCCCCCCCCCCCCCCC".to_owned(),
                    pubkey: self_key.verifying_key().to_bytes(),
                }),
                extent_index: Vec::new(),
                oci_source: None,
            },
        )
        .unwrap();
        let mint_reply = register_volume(ulid_from(ulid_str), tmp.path(), Some(my_pid), &key())
            .expect("register should succeed");
        let issuer = FixedIssuer;
        let creds = issue_credentials(
            &mint_reply.macaroon,
            ulid_from(parent_str),
            tmp.path(),
            Some(my_pid),
            &key(),
            &issuer,
        )
        .await
        .expect("ancestor target must be allowed");
        assert_eq!(creds.access_key_id, "AK");
    }

    #[test]
    fn parse_flags_empty() {
        let p = parse_transport_flags("").unwrap();
        assert!(!p.ublk && !p.no_ublk);
    }

    #[test]
    fn parse_flags_ublk() {
        let p = parse_transport_flags("ublk").unwrap();
        assert!(p.ublk);
    }

    #[test]
    fn parse_flags_ublk_id_no_longer_recognised() {
        // `ublk-id=N` was the user-facing pin token; removed in the
        // collapse follow-up. Operator pinning happens via direct
        // `elide serve-volume --ublk-id <n>` (the internal CLI), not
        // via the coordinator IPC parser.
        let err = match parse_transport_flags("ublk-id=7") {
            Ok(_) => panic!("ublk-id=7 should be rejected"),
            Err(e) => e,
        };
        assert!(err.contains("unknown flag"), "got {err:?}");
    }

    #[test]
    fn parse_flags_clearing() {
        let p = parse_transport_flags("no-ublk").unwrap();
        assert!(p.no_ublk);
    }

    #[test]
    fn parse_flags_unknown_rejected() {
        assert!(parse_transport_flags("ublk unknown=1").is_err());
        assert!(parse_transport_flags("not-a-flag").is_err());
    }

    #[test]
    fn parse_flags_bad_value() {
        assert!(parse_transport_flags("ublk-id=").is_err());
    }

    #[test]
    fn validate_name_accepts() {
        for n in &["foo", "vol-1", "my_vol", "ubuntu.22.04"] {
            assert!(validate_volume_name(n).is_ok(), "expected ok for {n}");
        }
    }

    #[test]
    fn validate_name_rejects() {
        assert!(validate_volume_name("").is_err());
        assert!(validate_volume_name("foo:bar").is_err());
        assert!(validate_volume_name("foo/bar").is_err());
        assert!(validate_volume_name("status").is_err());
        assert!(validate_volume_name("attach").is_err());
    }

    // ── status-remote ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn status_remote_absent_name_returns_err() {
        let store = mem_store();
        let err = volume_status_remote_typed("ghost", &store, "coord-self")
            .await
            .expect_err("absent name should return an error");
        assert_eq!(err.kind, elide_coordinator::ipc::IpcErrorKind::NotFound);
        assert!(err.message.contains("no S3 record"), "{}", err.message);
    }

    #[tokio::test]
    async fn status_remote_owned_live_record() {
        let store = mem_store();
        let mut rec = elide_core::name_record::NameRecord::live_minimal(sample_ulid(), SAMPLE_SIZE);
        rec.coordinator_id = Some("coord-self".into());
        rec.hostname = Some("host-A".into());
        rec.claimed_at = Some("2026-04-28T00:00:00Z".into());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let reply = volume_status_remote_typed("vol", &store, "coord-self")
            .await
            .unwrap();
        assert_eq!(reply.state, elide_core::name_record::NameState::Live);
        assert_eq!(reply.vol_ulid, sample_ulid());
        assert_eq!(reply.coordinator_id.as_deref(), Some("coord-self"));
        assert_eq!(reply.hostname.as_deref(), Some("host-A"));
        assert_eq!(reply.claimed_at.as_deref(), Some("2026-04-28T00:00:00Z"));
        assert_eq!(reply.eligibility, Eligibility::Owned);
    }

    #[tokio::test]
    async fn status_remote_foreign_live_record() {
        let store = mem_store();
        let mut rec = elide_core::name_record::NameRecord::live_minimal(sample_ulid(), SAMPLE_SIZE);
        rec.coordinator_id = Some("coord-other".into());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let reply = volume_status_remote_typed("vol", &store, "coord-self")
            .await
            .unwrap();
        assert_eq!(reply.state, elide_core::name_record::NameState::Live);
        assert_eq!(reply.eligibility, Eligibility::Foreign);
    }

    #[tokio::test]
    async fn status_remote_released_is_claimable() {
        let store = mem_store();
        let mut rec = elide_core::name_record::NameRecord::live_minimal(sample_ulid(), SAMPLE_SIZE);
        rec.state = elide_core::name_record::NameState::Released;
        rec.handoff_snapshot = Some(sample_ulid());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let reply = volume_status_remote_typed("vol", &store, "coord-self")
            .await
            .unwrap();
        assert_eq!(reply.state, elide_core::name_record::NameState::Released);
        assert_eq!(reply.eligibility, Eligibility::ReleasedClaimable);
        assert_eq!(reply.handoff_snapshot, Some(sample_ulid()));
    }

    #[tokio::test]
    async fn status_remote_readonly() {
        let store = mem_store();
        let mut rec = elide_core::name_record::NameRecord::live_minimal(sample_ulid(), SAMPLE_SIZE);
        rec.state = elide_core::name_record::NameState::Readonly;
        elide_coordinator::name_store::create_name_record(&store, "img", &rec)
            .await
            .unwrap();

        let reply = volume_status_remote_typed("img", &store, "coord-self")
            .await
            .unwrap();
        assert_eq!(reply.state, elide_core::name_record::NameState::Readonly);
        assert_eq!(reply.eligibility, Eligibility::Readonly);
    }

    /// `covering_local_snapshot` is the gate that suppresses the
    /// redundant stop-snapshot publish at `stop` time when a manifest
    /// at the target ULID already exists locally.
    #[test]
    fn covering_local_snapshot_finds_user_manifest() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();
        let snap = ulid::Ulid::new();
        std::fs::write(
            tmp.path()
                .join("snapshots")
                .join(format!("{snap}.manifest")),
            "x",
        )
        .unwrap();
        assert_eq!(
            covering_local_snapshot(tmp.path(), snap),
            Some(elide_core::signing::SnapshotKind::User)
        );
    }

    #[test]
    fn covering_local_snapshot_finds_stop_manifest() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();
        let snap = ulid::Ulid::new();
        std::fs::write(
            tmp.path()
                .join("snapshots")
                .join(format!("{snap}-stop.manifest")),
            "x",
        )
        .unwrap();
        assert_eq!(
            covering_local_snapshot(tmp.path(), snap),
            Some(elide_core::signing::SnapshotKind::Stop)
        );
    }

    #[test]
    fn covering_local_snapshot_returns_none_when_absent() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();
        let snap = ulid::Ulid::new();
        assert_eq!(covering_local_snapshot(tmp.path(), snap), None);
    }

    #[test]
    fn covering_local_snapshot_prefers_user_over_auto() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("snapshots")).unwrap();
        let snap = ulid::Ulid::new();
        std::fs::write(
            tmp.path()
                .join("snapshots")
                .join(format!("{snap}.manifest")),
            "x",
        )
        .unwrap();
        std::fs::write(
            tmp.path()
                .join("snapshots")
                .join(format!("{snap}-stop.manifest")),
            "x",
        )
        .unwrap();
        assert_eq!(
            covering_local_snapshot(tmp.path(), snap),
            Some(elide_core::signing::SnapshotKind::User),
            "User wins so an in-flight promotion is treated as already-done"
        );
    }

    // ----- await-prefetch -----

    /// Untracked volume → ok. Used for volumes already-prefetched on a previous
    /// coordinator run (no entry in the tracker yet) or running without
    /// coordinator-managed prefetch at all.
    #[tokio::test]
    async fn await_prefetch_returns_ok_for_untracked_volume() {
        let tracker = elide_coordinator::new_prefetch_tracker();
        let vol = ulid::Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        await_prefetch_op(vol, &tracker)
            .await
            .expect("untracked → ok");
    }

    /// Tracker already has a Done(Ok) entry → returns immediately, no blocking.
    #[tokio::test]
    async fn await_prefetch_returns_ok_when_already_done_success() {
        let tracker = elide_coordinator::new_prefetch_tracker();
        let vol = ulid::Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let tx = elide_coordinator::register_prefetch_or_get(&tracker, vol);
        tx.send_replace(Some(Ok(())));
        // Don't await with a timeout: if this blocks, the test blocks — that's
        // a clearer failure than a timeout.
        await_prefetch_op(vol, &tracker)
            .await
            .expect("already-done → ok");
    }

    /// Tracker has Done(Err) → surfaces the message, doesn't return ok.
    #[tokio::test]
    async fn await_prefetch_returns_err_when_already_done_failed() {
        let tracker = elide_coordinator::new_prefetch_tracker();
        let vol = ulid::Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let tx = elide_coordinator::register_prefetch_or_get(&tracker, vol);
        tx.send_replace(Some(Err("S3 timeout".into())));
        let err = await_prefetch_op(vol, &tracker)
            .await
            .expect_err("done(err) should surface");
        assert!(err.message.contains("S3 timeout"), "{err}");
    }

    /// In-progress entry: caller blocks; producer publishes Ok mid-wait;
    /// caller unblocks with ok.
    #[tokio::test]
    async fn await_prefetch_blocks_until_publisher_sends_ok() {
        let tracker = elide_coordinator::new_prefetch_tracker();
        let vol = ulid::Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let tx = elide_coordinator::register_prefetch_or_get(&tracker, vol);

        let tracker_clone = tracker.clone();
        let waiter = tokio::spawn(async move { await_prefetch_op(vol, &tracker_clone).await });

        // Give the waiter a moment to subscribe before the publisher fires.
        // Without this, the publisher might send before the waiter is even
        // running; the test would still pass via initial-borrow, so this
        // sleep specifically exercises the rx.changed() path.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        tx.send_replace(Some(Ok(())));

        waiter.await.unwrap().expect("publisher → ok");
    }

    /// In-progress entry, sender dropped (per-fork task panicked / volume
    /// removed mid-prefetch) → IPC returns a clear error rather than hanging
    /// or silently saying ok.
    #[tokio::test]
    async fn await_prefetch_returns_err_when_sender_dropped_without_value() {
        let tracker = elide_coordinator::new_prefetch_tracker();
        let vol = ulid::Ulid::from_string("01JQAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let tx = elide_coordinator::register_prefetch_or_get(&tracker, vol);

        let tracker_clone = tracker.clone();
        let waiter = tokio::spawn(async move { await_prefetch_op(vol, &tracker_clone).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        // Simulate the per-fork task exiting: drop the task's local
        // Arc<Sender> AND remove the tracker entry (the Drop guard in
        // run_volume_tasks does this on real exit). With both gone, the
        // underlying watch channel has no more senders and the waiter
        // unblocks with Err.
        drop(tx);
        elide_coordinator::unregister_prefetch(&tracker, &vol);

        let err = waiter
            .await
            .unwrap()
            .expect_err("dropped sender should error");
        assert!(
            err.message.contains("prefetch task exited"),
            "expected 'prefetch task exited...', got: {err}"
        );
    }

    // ── generate-filemap argument validation ─────────────────────────────

    #[tokio::test]
    async fn generate_filemap_unknown_volume_returns_err() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("by_name")).unwrap();
        let stores: Arc<dyn elide_coordinator::stores::ScopedStores> = Arc::new(
            elide_coordinator::stores::PassthroughStores::new(mem_store()),
        );
        let err = generate_filemap_op("ghost", None, tmp.path(), &stores)
            .await
            .expect_err("ghost volume should error");
        assert_eq!(err.kind, IpcErrorKind::NotFound);
        assert!(err.message.contains("volume not found"), "{err}");
    }

    #[tokio::test]
    async fn generate_filemap_no_snapshot_returns_err() {
        let tmp = TempDir::new().unwrap();
        let vol_ulid = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let vol_dir = tmp.path().join("by_id").join(vol_ulid);
        std::fs::create_dir_all(&vol_dir).unwrap();
        let by_name = tmp.path().join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        std::os::unix::fs::symlink(&vol_dir, by_name.join("vol")).unwrap();
        let stores: Arc<dyn elide_coordinator::stores::ScopedStores> = Arc::new(
            elide_coordinator::stores::PassthroughStores::new(mem_store()),
        );
        let err = generate_filemap_op("vol", None, tmp.path(), &stores)
            .await
            .expect_err("no snapshot should error");
        assert_eq!(err.kind, IpcErrorKind::NotFound);
        assert!(err.message.contains("no local snapshot"), "{err}");
    }

    #[tokio::test]
    async fn generate_filemap_explicit_unknown_snapshot_returns_err() {
        let tmp = TempDir::new().unwrap();
        let vol_ulid = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let vol_dir = tmp.path().join("by_id").join(vol_ulid);
        std::fs::create_dir_all(&vol_dir).unwrap();
        let by_name = tmp.path().join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        std::os::unix::fs::symlink(&vol_dir, by_name.join("vol")).unwrap();
        let stores: Arc<dyn elide_coordinator::stores::ScopedStores> = Arc::new(
            elide_coordinator::stores::PassthroughStores::new(mem_store()),
        );
        // Valid ULID, but no matching snapshots/<ulid>.manifest on disk.
        let bogus = ulid::Ulid::from_string("01J0000000000000000000000V").unwrap();
        let err = generate_filemap_op("vol", Some(bogus), tmp.path(), &stores)
            .await
            .expect_err("missing manifest should error");
        assert_eq!(err.kind, IpcErrorKind::NotFound);
        assert!(
            err.message.contains("not found locally") && err.message.contains(&bogus.to_string()),
            "{err}"
        );
    }

    // ── credential-routing regressions ────────────────────────────────────
    //
    // Each verb has exactly one defensible role for each store op it
    // performs. A misrouting (e.g. `writer()` for a `by_id/` write)
    // gets a 403 from Tigris and a silent half-published state.
    // These tests pin down the choice via [`RecordingStores`] so the
    // routing can't quietly regress.

    #[tokio::test]
    async fn snapshot_volume_kind_routes_through_volume_rw() {
        // Regression for the user-visible 2026-05-21 bug: stop's
        // snapshot publish (and the GC handoff apply + drain) write
        // under `by_id/<vol>/`, which needs per-vol `volume-rw`. Using
        // `writer()` (coord-rw) produced silent 403s on Tigris.
        //
        // We can't run the full snapshot through this unit test (it
        // needs a live volume daemon for the `promote_wal` IPC), but
        // the credential pick happens BEFORE that IPC: pass-through
        // until promote_wal fails, then inspect the spy.
        use elide_coordinator::stores::{
            PassthroughStores, RecordingStores, RoleCall, ScopedStores,
        };

        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let vol_ulid = ulid::Ulid::new();
        let vol_dir = data_dir.join("by_id").join(vol_ulid.to_string());
        std::fs::create_dir_all(&vol_dir).unwrap();
        let by_name = data_dir.join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        std::os::unix::fs::symlink(&vol_dir, by_name.join("vol")).unwrap();
        // Fake a running daemon by holding the volume lock — passes the
        // is_running() gate without a real subprocess.
        let f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(vol_dir.join(elide_core::volume::VOLUME_LOCK_FILE))
            .unwrap();
        let _held = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock)
            .map_err(|(_, e)| e)
            .unwrap();

        let identity = std::sync::Arc::new(
            elide_coordinator::identity::CoordinatorIdentity::load_or_generate(data_dir).unwrap(),
        );
        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let passthrough: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&mem)));
        let recording = RecordingStores::wrap(passthrough);

        let core = CoordinatorCore {
            data_dir: Arc::new(data_dir.to_path_buf()),
            stores: recording.clone(),
            identity,
        };
        let locks = SnapshotLockRegistry::default();

        // promote_wal will fail (no control.sock) — that's after the
        // credential pick at the top of the function.
        let _ = snapshot_volume_kind(
            "vol",
            &core,
            &locks,
            elide_core::signing::SnapshotKind::Stop,
        )
        .await;

        let calls = recording.calls();
        assert_eq!(
            calls,
            vec![RoleCall::VolumeRw(vol_ulid)],
            "stop's snapshot publish must mint volume-rw for the vol_ulid; \
             got {calls:?}"
        );
    }

    #[tokio::test]
    async fn generate_filemap_routes_through_read_volume() {
        // `generate_filemap_op` demand-fetches segment bodies per owner:
        // each `by_id/<owner>/…` key is read under that owner's
        // single-prefix `volume-ro` credential (`read_volume`), never a
        // `writer` or `volume-rw` mint. The per-owner read store is built
        // lazily inside the range fetcher when a body is actually
        // fetched, so any role mint this op makes must be a `read_volume`.
        // (End-to-end per-owner `read_volume` routing through the same
        // fetcher is exercised by
        // `prefetch::tests::prefetch_indexes_downloads_ancestor_idx`.)
        use elide_coordinator::stores::{
            PassthroughStores, RecordingStores, RoleCall, ScopedStores,
        };

        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let vol_dir = tmp.path().join("by_id").join(vol_ulid_str);
        std::fs::create_dir_all(&vol_dir).unwrap();
        let by_name = tmp.path().join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        std::os::unix::fs::symlink(&vol_dir, by_name.join("vol")).unwrap();

        let inner: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(mem_store()));
        let recording = RecordingStores::wrap(inner);
        let stores: Arc<dyn ScopedStores> = recording.clone();

        let _ = generate_filemap_op("vol", None, tmp.path(), &stores).await;

        let calls = recording.calls();
        assert!(
            calls
                .iter()
                .all(|c| matches!(c, RoleCall::ReadVolume { .. })),
            "generate-filemap may only mint per-owner read_volume credentials; got {calls:?}"
        );
    }

    #[tokio::test]
    async fn create_volume_op_routes_everything_through_writer() {
        // `create_volume_op` runs three S3-touching phases (volume.pub
        // upload, volume.provenance upload, names/<name> claim) and all
        // of them are coordinator-plane (coord-rw): identity
        // establishment cannot ride volume-rw — a volume cannot attest
        // its own first write (`design-mint-volume-attestation.md`
        // § *New-volume bootstrap*) — and names/events always were
        // coord-rw. No per-volume credential of either direction may
        // be minted at create time.
        use elide_coordinator::stores::{
            PassthroughStores, RecordingStores, RoleCall, ScopedStores,
        };

        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let identity = std::sync::Arc::new(
            elide_coordinator::identity::CoordinatorIdentity::load_or_generate(data_dir).unwrap(),
        );
        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let passthrough: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&mem)));
        let recording = RecordingStores::wrap(passthrough);

        let core = CoordinatorCore {
            data_dir: Arc::new(data_dir.to_path_buf()),
            stores: recording.clone(),
            identity,
        };

        let reply = create_volume_op("vol", 4 * 1024 * 1024 * 1024, &[], &core)
            .await
            .expect("create must succeed in this fixture");
        let vol_ulid = reply.vol_ulid;

        let calls = recording.calls();
        // Coordinator-plane writes (meta identity, names/<vol>,
        // events/<vol>/) mint coord-rw plus coord-ro reads (the
        // name_claims + event_journal facades wrap both).
        assert!(
            calls.contains(&RoleCall::Writer),
            "create must mint coord-rw for meta identity + names/events; got {calls:?}"
        );
        // No per-volume credential in either direction: create-time
        // reads are local disk, and every S3 write is
        // coordinator-plane.
        for call in &calls {
            assert!(
                !matches!(call, RoleCall::ReadVolume { .. }),
                "create must not mint per-vol read credentials; saw {call:?} in {calls:?}"
            );
            assert!(
                !matches!(call, RoleCall::VolumeRw(_)),
                "create must not mint volume-rw — identity uploads are \
                 coordinator-plane; saw {call:?} (vol {vol_ulid}) in {calls:?}"
            );
        }
    }

    // ── bound_ublk_id / remove_volume ─────────────────────────────────────

    /// Build `data_dir/{by_id/<ulid>, by_name/<name>}` for a removable
    /// volume. Optionally writes `[ublk] dev_id` and the STOPPED_FILE
    /// marker. Returns `(vol_dir, by_name_link)`.
    fn setup_removable_volume(
        data_dir: &Path,
        name: &str,
        vol_ulid: &str,
        ublk_dev_id: Option<i32>,
        stopped: bool,
    ) -> (PathBuf, PathBuf) {
        let vol_dir = data_dir.join("by_id").join(vol_ulid);
        std::fs::create_dir_all(&vol_dir).unwrap();
        elide_core::config::VolumeConfig {
            name: Some(name.to_owned()),
            size: Some(SAMPLE_SIZE),
            ublk: ublk_dev_id.map(|id| elide_core::config::UblkConfig { dev_id: Some(id) }),
            lazy: None,
        }
        .write(&vol_dir)
        .unwrap();
        if stopped {
            std::fs::write(vol_dir.join(STOPPED_FILE), "").unwrap();
        }
        let by_name = data_dir.join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        let link = by_name.join(name);
        std::os::unix::fs::symlink(&vol_dir, &link).unwrap();
        (vol_dir, link)
    }

    #[test]
    fn resolve_volume_name_maps_ulid_via_by_name_symlink() {
        let tmp = TempDir::new().unwrap();
        let ulid = ulid::Ulid::new();
        let vol_dir = tmp.path().join("by_id").join(ulid.to_string());
        std::fs::create_dir_all(&vol_dir).unwrap();
        let by_name = tmp.path().join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        std::os::unix::fs::symlink(&vol_dir, by_name.join("myvol")).unwrap();

        assert_eq!(
            resolve_volume_name(tmp.path(), &macaroon::Verified::for_test(ulid)).unwrap(),
            "myvol".to_owned()
        );
    }

    #[test]
    fn resolve_volume_name_unclaimed_volume_is_forbidden() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("by_name")).unwrap();
        // by_name has no symlink pointing at this ulid → not the
        // current local claimer → forbidden (403-class).
        let err = resolve_volume_name(tmp.path(), &macaroon::Verified::for_test(ulid::Ulid::new()))
            .expect_err("no claim → reject");
        assert_eq!(err.kind, IpcErrorKind::Forbidden);
    }

    #[test]
    fn bound_ublk_id_missing_config_returns_none() {
        let tmp = TempDir::new().unwrap();
        assert_eq!(bound_ublk_id(tmp.path()), None);
    }

    #[test]
    fn bound_ublk_id_no_ublk_section_returns_none() {
        let tmp = TempDir::new().unwrap();
        elide_core::config::VolumeConfig {
            size: Some(SAMPLE_SIZE),
            ..Default::default()
        }
        .write(tmp.path())
        .unwrap();
        assert_eq!(bound_ublk_id(tmp.path()), None);
    }

    #[test]
    fn bound_ublk_id_section_without_dev_id_returns_none() {
        let tmp = TempDir::new().unwrap();
        elide_core::config::VolumeConfig {
            size: Some(SAMPLE_SIZE),
            ublk: Some(elide_core::config::UblkConfig { dev_id: None }),
            ..Default::default()
        }
        .write(tmp.path())
        .unwrap();
        assert_eq!(bound_ublk_id(tmp.path()), None);
    }

    #[test]
    fn bound_ublk_id_returns_dev_id() {
        let tmp = TempDir::new().unwrap();
        elide_core::config::VolumeConfig {
            size: Some(SAMPLE_SIZE),
            ublk: Some(elide_core::config::UblkConfig { dev_id: Some(7) }),
            ..Default::default()
        }
        .write(tmp.path())
        .unwrap();
        assert_eq!(bound_ublk_id(tmp.path()), Some(7));
    }

    #[tokio::test]
    async fn remove_volume_without_ublk_succeeds() {
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let (vol_dir, link) = setup_removable_volume(tmp.path(), "vol", vol_ulid_str, None, true);
        remove_volume(ulid_from(vol_ulid_str), false, tmp.path(), None, None)
            .await
            .unwrap();
        assert!(!vol_dir.exists(), "by_id dir should be removed");
        assert!(
            std::fs::symlink_metadata(&link).is_err(),
            "by_name link should be removed"
        );
    }

    #[tokio::test]
    async fn remove_volume_with_ublk_dev_id_succeeds() {
        // teardown_bound_device best-effort logs a warn when the kernel
        // device doesn't exist; remove_volume must still succeed and
        // clean up local state. Verifies the cfg is read *before*
        // remove_dir_all runs (otherwise read would fail and we'd still
        // be in this branch — but the dir wouldn't be gone).
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAB";
        let (vol_dir, link) =
            setup_removable_volume(tmp.path(), "vol", vol_ulid_str, Some(99), true);
        remove_volume(ulid_from(vol_ulid_str), false, tmp.path(), None, None)
            .await
            .unwrap();
        assert!(!vol_dir.exists());
        assert!(std::fs::symlink_metadata(&link).is_err());
    }

    #[tokio::test]
    async fn remove_volume_rejects_running() {
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAC";
        let (vol_dir, _link) = setup_removable_volume(
            tmp.path(),
            "vol",
            vol_ulid_str,
            Some(5),
            false, // no STOPPED_FILE
        );
        let err = remove_volume(ulid_from(vol_ulid_str), false, tmp.path(), None, None)
            .await
            .expect_err("running volume should be rejected");
        assert_eq!(err.kind, IpcErrorKind::Conflict);
        assert!(vol_dir.exists(), "dir must be preserved on conflict");
    }

    #[tokio::test]
    async fn remove_volume_succeeds_when_released() {
        // After `volume release`, the fork carries both
        // `volume.stopped` (release requires Owner{Stopped}) and
        // `volume.released`. `VolumeLifecycle::from_dir` returns
        // `Released { .. }` because that marker takes precedence —
        // but the daemon is provably halted, so remove must proceed.
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAD";
        let (vol_dir, link) = setup_removable_volume(tmp.path(), "vol", vol_ulid_str, None, true);
        write_released_marker(&vol_dir, ulid::Ulid::new()).unwrap();
        remove_volume(ulid_from(vol_ulid_str), false, tmp.path(), None, None)
            .await
            .unwrap();
        assert!(!vol_dir.exists(), "by_id dir should be removed");
        assert!(std::fs::symlink_metadata(&link).is_err());
    }

    #[tokio::test]
    async fn remove_volume_succeeds_when_readonly_imported() {
        // OCI base or readonly skeleton — no signing key, no daemon.
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAF";
        let (vol_dir, link) = setup_removable_volume(tmp.path(), "vol", vol_ulid_str, None, false);
        std::fs::write(vol_dir.join("volume.readonly"), "").unwrap();
        remove_volume(ulid_from(vol_ulid_str), false, tmp.path(), None, None)
            .await
            .unwrap();
        assert!(!vol_dir.exists());
        assert!(std::fs::symlink_metadata(&link).is_err());
    }

    #[tokio::test]
    async fn remove_volume_unknown_returns_not_found() {
        let tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join("by_name")).unwrap();
        // ULID with no `by_id/<ulid>` directory → not_found.
        let err = remove_volume(ulid::Ulid::new(), false, tmp.path(), None, None)
            .await
            .expect_err("absent volume should be NotFound");
        assert_eq!(err.kind, IpcErrorKind::NotFound);
    }

    #[tokio::test]
    async fn remove_volume_writes_breadcrumb_when_owned() {
        use elide_coordinator::name_store::create_name_record;
        use elide_core::name_record::{NameRecord, NameState};
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAA";
        let (_vol_dir, _link) = setup_removable_volume(tmp.path(), "vol", vol_ulid_str, None, true);

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut record = NameRecord::live_minimal(ulid_from(vol_ulid_str), SAMPLE_SIZE);
        record.state = NameState::Stopped;
        record.coordinator_id = Some("coord-A".to_owned());
        create_name_record(&store, "vol", &record).await.unwrap();

        remove_volume(
            ulid_from(vol_ulid_str),
            false,
            tmp.path(),
            Some(&store),
            Some("coord-A"),
        )
        .await
        .unwrap();

        let crumb = elide_coordinator::remote_breadcrumb::read(tmp.path(), "vol")
            .unwrap()
            .expect("breadcrumb should exist");
        assert_eq!(crumb.volume_id.to_string(), vol_ulid_str);
    }

    #[tokio::test]
    async fn remove_volume_skips_breadcrumb_when_record_absent() {
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAB";
        let (_vol_dir, _link) = setup_removable_volume(tmp.path(), "vol", vol_ulid_str, None, true);
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());

        remove_volume(
            ulid_from(vol_ulid_str),
            false,
            tmp.path(),
            Some(&store),
            Some("coord-A"),
        )
        .await
        .unwrap();

        assert!(
            elide_coordinator::remote_breadcrumb::read(tmp.path(), "vol")
                .unwrap()
                .is_none(),
            "no breadcrumb when bucket has no record"
        );
    }

    #[tokio::test]
    async fn remove_volume_skips_breadcrumb_when_owned_by_other() {
        use elide_coordinator::name_store::create_name_record;
        use elide_core::name_record::{NameRecord, NameState};
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAC";
        let (_vol_dir, _link) = setup_removable_volume(tmp.path(), "vol", vol_ulid_str, None, true);

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut record = NameRecord::live_minimal(ulid_from(vol_ulid_str), SAMPLE_SIZE);
        record.state = NameState::Stopped;
        record.coordinator_id = Some("coord-OTHER".to_owned());
        create_name_record(&store, "vol", &record).await.unwrap();

        remove_volume(
            ulid_from(vol_ulid_str),
            false,
            tmp.path(),
            Some(&store),
            Some("coord-A"),
        )
        .await
        .unwrap();

        assert!(
            elide_coordinator::remote_breadcrumb::read(tmp.path(), "vol")
                .unwrap()
                .is_none(),
            "no breadcrumb when bucket says different owner"
        );
    }

    #[tokio::test]
    async fn remove_volume_skips_breadcrumb_when_released() {
        use elide_coordinator::name_store::create_name_record;
        use elide_core::name_record::{NameRecord, NameState};
        let tmp = TempDir::new().unwrap();
        let vol_ulid_str = "01JQAAAAAAAAAAAAAAAAAAAAAD";
        let (_vol_dir, _link) = setup_removable_volume(tmp.path(), "vol", vol_ulid_str, None, true);

        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut record = NameRecord::live_minimal(ulid_from(vol_ulid_str), SAMPLE_SIZE);
        record.state = NameState::Released;
        record.coordinator_id = Some("coord-A".to_owned());
        create_name_record(&store, "vol", &record).await.unwrap();

        remove_volume(
            ulid_from(vol_ulid_str),
            false,
            tmp.path(),
            Some(&store),
            Some("coord-A"),
        )
        .await
        .unwrap();

        assert!(
            elide_coordinator::remote_breadcrumb::read(tmp.path(), "vol")
                .unwrap()
                .is_none(),
            "no breadcrumb when bucket state is Released"
        );
    }
}
