//! Fork flow: registry, orchestrator, and the start-fork entry point.
//!
//! Mirrors the structure of [`crate::claim`]:
//!
//! - [`ForkJob`] / [`ForkRegistry`] — buffered events + state for one
//!   in-flight fork. Polled by `fork-attach` IPC subscribers.
//! - [`start_fork`] — synchronous entry point invoked by the
//!   `Request::ForkStart` dispatch arm. Registers the job, spawns the
//!   orchestrator, and returns immediately.
//! - [`ForkOrchestrator`] — the four-stage pipeline (resolve-source →
//!   pull-chain → resolve-snapshot → mint-fork → surface-prefetch),
//!   each stage `&mut self` so per-job state lives on the struct rather
//!   than threading through helper-function arguments.
//!
//! Job state is in-memory: unlike imports there is no long-lived child
//! process to outlive the coordinator, so a coordinator restart simply
//! means the caller gets "no active fork" and re-runs `volume create
//! --from`. [`fork_create_op`] already handles cleaning up the kind of
//! partial `by_name/<name>` symlinks a mid-flight crash can leave behind.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use object_store::ObjectStore;
use tracing::{info, warn};
use ulid::Ulid;

use crate::inbound::{
    CoordinatorCore, await_prefetch_op, parse_transport_flags, pull_readonly_op, snapshot_volume,
    validate_volume_name,
};
use elide_coordinator::ipc::{
    ForkAttachEvent, ForkCreateReply, ForkSource, ForkStartReply, IpcError,
};
use elide_coordinator::register_prefetch_or_get;
use elide_coordinator::volume_state::{IMPORTING_FILE, STOPPED_FILE};

// ── Per-domain context ───────────────────────────────────────────────────────

/// Coordinator state needed by the fork flow: the universal hot core
/// plus the fork-domain registries and config. Constructed via
/// [`crate::inbound::IpcContext::for_fork`].
#[derive(Clone)]
pub(crate) struct ForkContext {
    pub core: CoordinatorCore,
    pub fork_registry: ForkRegistry,
    pub prefetch_tracker: elide_coordinator::PrefetchTracker,
    pub fork_sync: elide_coordinator::ForkSyncRegistry,
}

// ── Job + registry ────────────────────────────────────────────────────────────

/// Terminal state of a fork job. `Failed` carries the error that the
/// orchestrator surfaced; `attach_fork` translates it back into an
/// `Envelope::Err` for the wire.
#[derive(Clone, Debug)]
pub enum ForkJobState {
    Running,
    Done,
    Failed(IpcError),
}

/// In-memory record for one in-flight fork. The orchestrator pushes
/// `ForkAttachEvent` values into `events` as the flow progresses;
/// `attach_fork` polls and replays them to the subscriber.
pub struct ForkJob {
    /// Buffered progress events. The orchestrator only ever appends;
    /// `attach_fork` reads from a per-subscriber offset.
    events: Mutex<Vec<ForkAttachEvent>>,
    /// Current job state. The orchestrator flips it to `Done` /
    /// `Failed` exactly once at the end of the flow.
    state: RwLock<ForkJobState>,
}

impl ForkJob {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            state: RwLock::new(ForkJobState::Running),
        })
    }

    /// Append one event to the job's buffer. Cheap (single mutex lock,
    /// no I/O); safe to call from the orchestrator task.
    pub fn append(&self, event: ForkAttachEvent) {
        self.events
            .lock()
            .expect("fork job events poisoned")
            .push(event);
    }

    /// Mark the job terminal. Called once by the orchestrator.
    pub fn finish(&self, state: ForkJobState) {
        *self.state.write().expect("fork job state poisoned") = state;
    }

    /// Snapshot the events appended at or after `offset`. Used by
    /// `attach_fork` for its polling loop.
    pub fn read_from(&self, offset: usize) -> Vec<ForkAttachEvent> {
        self.events.lock().expect("fork job events poisoned")[offset..].to_vec()
    }

    pub fn state(&self) -> ForkJobState {
        self.state.read().expect("fork job state poisoned").clone()
    }
}

/// Registry of in-flight fork jobs keyed by the new fork's name. The
/// name uniquely identifies a fork in flight: [`fork_create_op`] rejects
/// a second concurrent attempt for the same `by_name/<name>` symlink, so
/// two `fork-start` calls for the same name cannot both be live.
pub type ForkRegistry = Arc<Mutex<HashMap<String, Arc<ForkJob>>>>;

pub fn new_registry() -> ForkRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Register a fork job and spawn the orchestrator task.
///
/// Returns immediately once the job is in the registry; the actual
/// chain-pull / snapshot / fork-create / prefetch flow runs in the
/// background. Errors here are synchronous validation failures
/// (duplicate name in flight, bad inputs); orchestrator errors are
/// surfaced via `attach_fork` instead.
pub(crate) fn start_fork(
    new_name: String,
    from: ForkSource,
    flags: Vec<String>,
    ctx: ForkContext,
) -> Result<ForkStartReply, IpcError> {
    {
        let mut reg = ctx.fork_registry.lock().expect("fork registry poisoned");
        if let Some(job) = reg.get(&new_name)
            && matches!(job.state(), ForkJobState::Running)
        {
            return Err(IpcError::conflict(format!(
                "fork '{new_name}' is already in progress"
            )));
        }
        reg.insert(new_name.clone(), ForkJob::new());
    }

    let job = {
        let reg = ctx.fork_registry.lock().expect("fork registry poisoned");
        reg.get(&new_name).cloned().expect("just inserted")
    };

    tokio::spawn(async move {
        let orch = ForkOrchestrator::new(job.clone(), new_name, from, flags, ctx);
        match orch.run().await {
            Ok(()) => {
                job.append(ForkAttachEvent::Done);
                job.finish(ForkJobState::Done);
            }
            Err(e) => job.finish(ForkJobState::Failed(e)),
        }
    });

    Ok(ForkStartReply::default())
}

// ── Orchestrator ─────────────────────────────────────────────────────────────

/// Source resolved in stage 1. `name` is `Some` for name-addressed
/// sources (`Name` / `PinnedName`); `snap_hint` is `Some` for the
/// pinned forms; `record_latest` carries the `names/<name>` record's
/// `latest_snapshot` when the name was resolved through the bucket.
struct ResolvedSource {
    vol_ulid: Ulid,
    name: Option<String>,
    snap_hint: Option<Ulid>,
    record_latest: Option<Ulid>,
}

/// Drive one fork job to completion.
///
/// The flow is a five-stage pipeline; each stage consumes earlier outputs
/// from `self` and writes its own. See [`Self::run`] for the linear
/// sequence.
pub(crate) struct ForkOrchestrator {
    job: Arc<ForkJob>,
    new_name: String,
    from: ForkSource,
    flags: Vec<String>,
    ctx: ForkContext,
    by_id_dir: PathBuf,

    // Stage outputs.
    source: Option<ResolvedSource>,
    /// Snapshot the new fork pins to. Set during `resolve_snapshot`. The
    /// `Option` mirrors what [`fork_create_op`] accepts; in practice every
    /// success path sets `Some(_)`.
    snap_ulid: Option<Ulid>,
    /// Set by `mint_fork` so `surface_prefetch` knows which volume to
    /// await.
    new_vol_ulid: Option<Ulid>,
}

impl ForkOrchestrator {
    pub(crate) fn new(
        job: Arc<ForkJob>,
        new_name: String,
        from: ForkSource,
        flags: Vec<String>,
        ctx: ForkContext,
    ) -> Self {
        let by_id_dir = ctx.core.data_dir.join("by_id");
        Self {
            job,
            new_name,
            from,
            flags,
            ctx,
            by_id_dir,
            source: None,
            snap_ulid: None,
            new_vol_ulid: None,
        }
    }

    pub(crate) async fn run(mut self) -> Result<(), IpcError> {
        self.resolve_source().await?;
        self.pull_chain().await?;
        self.resolve_snapshot().await?;
        self.mint_fork().await?;
        self.surface_prefetch().await;
        Ok(())
    }

    /// Stage 1. Resolve `from` to `(source_vol_ulid, source_name,
    /// snap_hint, record_latest)`. Name-addressed sources look up the
    /// local symlink first and fall back to `names/<name>` in the
    /// bucket (`coord-ro`), capturing the record's `latest_snapshot`
    /// alongside the binding.
    async fn resolve_source(&mut self) -> Result<(), IpcError> {
        let resolved = match &self.from {
            ForkSource::Pinned {
                vol_ulid,
                snap_ulid,
            } => ResolvedSource {
                vol_ulid: *vol_ulid,
                name: None,
                snap_hint: Some(*snap_ulid),
                record_latest: None,
            },
            ForkSource::PinnedName { name, snap_ulid } => {
                let snap_ulid = *snap_ulid;
                let name = name.clone();
                let (vol_ulid, record_latest) = self.resolve_by_name(&name).await?;
                ResolvedSource {
                    vol_ulid,
                    name: Some(name),
                    snap_hint: Some(snap_ulid),
                    record_latest,
                }
            }
            ForkSource::Name { name } => {
                let name = name.clone();
                let (vol_ulid, record_latest) = self.resolve_by_name(&name).await?;
                ResolvedSource {
                    vol_ulid,
                    name: Some(name),
                    snap_hint: None,
                    record_latest,
                }
            }
        };
        self.source = Some(resolved);
        Ok(())
    }

    /// Resolve a name-addressed source: `by_name/<name>` locally
    /// first, else the `names/<name>` record in the bucket. Returns
    /// the bound `vol_ulid` plus the record's `latest_snapshot` when
    /// the bucket record was consulted.
    async fn resolve_by_name(&self, name: &str) -> Result<(Ulid, Option<Ulid>), IpcError> {
        validate_volume_name(name).map_err(IpcError::bad_request)?;
        match elide_coordinator::volume_state::resolve_volume_ulid(&self.ctx.core.data_dir, name) {
            Ok(vol_ulid) => return Ok((vol_ulid, None)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(IpcError::internal(format!("resolving by_name/{name}: {e}")));
            }
        }
        self.job.append(ForkAttachEvent::ResolvingName {
            name: name.to_owned(),
        });
        let claims = self.ctx.core.stores.name_claims_ro();
        match claims.read(name).await {
            Ok(Some(rec)) => Ok((rec.vol_ulid, rec.latest_snapshot)),
            Ok(None) => Err(IpcError::not_found(format!(
                "volume '{name}' not found in store"
            ))),
            Err(e) => Err(IpcError::store(format!("reading names/{name}: {e}"))),
        }
    }

    /// Stage 2. Walk the ancestor chain, pulling each missing entry.
    /// S3-only — fork is the `volume create --from` path with no released
    /// ancestor to claim, so peer-fetch can't authenticate (no
    /// `names/<volume>` rebind to anchor against).
    async fn pull_chain(&mut self) -> Result<(), IpcError> {
        use elide_core::volume::resolve_ancestor_dir;

        let source = self
            .source
            .as_ref()
            .expect("resolve_source must run before pull_chain");
        let source_vol_ulid = source.vol_ulid;

        let mut next: Option<Ulid> = Some(source_vol_ulid);
        while let Some(vol_ulid) = next.take() {
            let dir = resolve_ancestor_dir(&self.by_id_dir, &vol_ulid.to_string());
            if dir.exists() {
                break;
            }
            self.job
                .append(ForkAttachEvent::PullingAncestor { vol_ulid });
            // Skeleton pull reads only `meta/<ulid>.{provenance,pub}` —
            // bucket-wide objects on the warm `coord-ro` credential.
            let store = self.ctx.core.stores.base_object_store();
            let reply = pull_readonly_op(vol_ulid, &self.ctx.core.data_dir, &store, None).await?;
            next = reply.parent;
        }

        let source_ulid_str = source_vol_ulid.to_string();
        let source_dir = resolve_ancestor_dir(&self.by_id_dir, &source_ulid_str);
        if !source_dir.exists() {
            return Err(IpcError::not_found(format!(
                "source volume {source_ulid_str} not found in remote store"
            )));
        }
        if source_dir.join(IMPORTING_FILE).exists() {
            return Err(IpcError::conflict(format!(
                "source '{source_ulid_str}' is still importing; wait for import to complete"
            )));
        }
        Ok(())
    }

    /// Stage 3. Decide which snapshot the fork pins to.
    ///
    /// Resolution order:
    ///   - Pinned source (`Pinned` / `PinnedName`): use the explicit
    ///     `snap_hint`.
    ///   - Readonly source: use the latest local snapshot, falling back
    ///     to the `names/<name>` record's `latest_snapshot`.
    ///   - Writable source: take an implicit snapshot. If the source
    ///     daemon is stopped, transparently bring it up in
    ///     transport-suppressed mode for the drain, then halt and
    ///     restore `volume.stopped`.
    async fn resolve_snapshot(&mut self) -> Result<(), IpcError> {
        use elide_core::volume::resolve_ancestor_dir;

        let source = self
            .source
            .as_ref()
            .expect("resolve_source must run before resolve_snapshot");
        let source_vol_ulid = source.vol_ulid;
        let source_ulid_str = source_vol_ulid.to_string();
        let source_dir = resolve_ancestor_dir(&self.by_id_dir, &source_ulid_str);

        if let Some(snap) = source.snap_hint {
            // Pinned source already names the snapshot.
            self.snap_ulid = Some(snap);
            return Ok(());
        }

        if source_dir.join("volume.readonly").exists() {
            let snap_ulid = if let Some(snap) = elide_core::volume::latest_snapshot(&source_dir)
                .map_err(|e| IpcError::internal(format!("reading local snapshots: {e}")))?
            {
                snap
            } else {
                // Basis discovery through the `names/<name>` record
                // (`coord-ro`). `by_id/<vol>/snapshots/LATEST` is
                // owner-anchored; strangers discover a basis via the
                // record's `latest_snapshot`
                // (`docs/design/mint-volume-attestation.md` § *Basis
                // resolution per `--from` form*). Guarded on the record
                // still binding this vol_ulid so a rebound name never
                // supplies a previous binding's snapshot.
                let record_latest = if source.record_latest.is_some() {
                    source.record_latest
                } else if let Some(name) = &source.name {
                    let claims = self.ctx.core.stores.name_claims_ro();
                    match claims.read(name).await {
                        Ok(Some(rec)) if rec.vol_ulid == source_vol_ulid => rec.latest_snapshot,
                        Ok(_) => None,
                        Err(e) => {
                            return Err(IpcError::store(format!("reading names/{name}: {e}")));
                        }
                    }
                } else {
                    None
                };
                match record_latest {
                    Some(snap) => snap,
                    None => {
                        return Err(IpcError::not_found(format!(
                            "source volume {source_ulid_str} has no published snapshot \
                             recorded; pin one explicitly with \
                             --from {source_ulid_str}/<snap_ulid>"
                        )));
                    }
                }
            };
            self.snap_ulid = Some(snap_ulid);
            return Ok(());
        }

        // Writable source: need a snapshot covering the source's current
        // durable state. Two paths:
        //
        //   - Source is stopped: the latest published snapshot must
        //     cover everything (no work post-dating it). Reuse it as
        //     the fork basis, promoting an Auto to a stable User
        //     manifest first if needed (parent refs point at the
        //     stable filename). Refuses if the previous stop was
        //     unclean — the operator's recovery is start → stop →
        //     refork.
        //
        //   - Source is live: drive a fresh snapshot via IPC through
        //     the running daemon's actor. The daemon stays up.
        //
        // No transparent bring-up of a stopped source. Forking should
        // not have the side effect of starting a daemon.
        let name = if let Some(n) = source.name.clone() {
            n
        } else {
            elide_core::config::VolumeConfig::read(&source_dir)
                .map_err(|e| IpcError::internal(format!("read volume.toml: {e}")))?
                .name
                .ok_or_else(|| IpcError::internal("source volume has no name in volume.toml"))?
        };

        if source_dir.join(STOPPED_FILE).exists() {
            // Stopped source: reuse the latest snapshot if it covers
            // all durable state.
            let cover = match crate::inbound::release_fast_path_handoff(&source_dir) {
                Ok(crate::inbound::FastPathDisposition::Cover(cover)) => cover,
                Ok(_) => {
                    return Err(IpcError::conflict(format!(
                        "source '{name}' has durable state past the last snapshot \
                         (WAL/pending uploads not yet drained); the previous stop \
                         did not complete a clean drain. Recover with: \
                         `elide volume start {name}` then `elide volume stop {name}`, \
                         then re-run fork"
                    )));
                }
                Err(e) => {
                    return Err(IpcError::internal(format!(
                        "fork fast-path inspection for '{name}': {e}"
                    )));
                }
            };
            if cover.kind == elide_core::signing::SnapshotKind::Stop {
                let vd = self.ctx.core.stores.volume_data(&source_vol_ulid);
                if let Err(e) =
                    crate::inbound::promote_stop_snapshot(&source_dir, &vd, cover.snap_ulid).await
                {
                    return Err(IpcError::internal(format!(
                        "promoting stop-snapshot {} for fork of '{name}': {e}",
                        cover.snap_ulid
                    )));
                }
            }
            self.job.append(ForkAttachEvent::SnapshotTaken {
                snap_ulid: cover.snap_ulid,
            });
            self.snap_ulid = Some(cover.snap_ulid);
            return Ok(());
        }

        // Live source: drive a fresh snapshot via the running daemon.
        let reply = snapshot_volume(&name, &self.ctx.core, &self.ctx.fork_sync).await?;
        self.job.append(ForkAttachEvent::SnapshotTaken {
            snap_ulid: reply.snap_ulid,
        });
        self.snap_ulid = Some(reply.snap_ulid);
        Ok(())
    }

    /// Stage 4. Mint the fork.
    ///
    /// For a name-addressed source the orchestrator already knows the
    /// user-facing name; pass it as `source_name_hint` so a pulled
    /// source (whose `volume.toml` lacks `name`) still produces a
    /// `ForkedFrom` journal event instead of falling back to `Created`.
    /// `Pinned` sources have no orchestrator-known name and rely on
    /// `src_cfg.name`.
    async fn mint_fork(&mut self) -> Result<(), IpcError> {
        let source = self
            .source
            .as_ref()
            .expect("resolve_source must run before mint_fork");
        let source_vol_ulid = source.vol_ulid;
        let source_name = source.name.clone();
        let snap_ulid = self.snap_ulid;

        self.job.append(ForkAttachEvent::ForkingFrom {
            source_vol_ulid,
            snap_ulid,
        });
        let store = self.ctx.core.stores.writer();
        let reply = fork_create_op(
            &self.new_name,
            source_vol_ulid,
            snap_ulid,
            &self.flags,
            source_name.as_deref(),
            &store,
            &self.ctx,
        )
        .await?;
        self.new_vol_ulid = Some(reply.new_vol_ulid);
        self.job.append(ForkAttachEvent::ForkCreated {
            new_vol_ulid: reply.new_vol_ulid,
        });
        Ok(())
    }

    /// Stage 5. Surface the coordinator's background prefetch. The fork
    /// is already durable; prefetch failure here is non-fatal — the
    /// volume opens regardless and `volume start` re-awaits.
    async fn surface_prefetch(&self) {
        let new_vol_ulid = self
            .new_vol_ulid
            .expect("mint_fork must run before surface_prefetch");
        self.job.append(ForkAttachEvent::PrefetchStarted);
        let _ = await_prefetch_op(new_vol_ulid, &self.ctx.prefetch_tracker).await;
        self.job.append(ForkAttachEvent::PrefetchDone);
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Fork an existing source volume into a new writable volume.
///
/// Mirrors the CLI's `fork_volume_at*` + by_name symlink + volume.toml
/// write. `source_vol_ulid` resolves to any volume in `by_id/<ulid>/` —
/// writable, imported readonly base, or pulled ancestor. `snap` is
/// optional: if omitted, falls back to `volume::fork_volume` (latest
/// local snapshot). `source_name_hint` is the orchestrator-supplied
/// source name, used as a fallback when the source's on-disk
/// `volume.toml` has no `name` field — typically because the source was
/// pulled from S3 (`pull.rs` writes `name: None` for pulled ancestors).
/// Without this hint, forks from a pulled source emit a `Created`
/// journal event instead of the more useful
/// `ForkedFrom { source_name, ... }`.
#[allow(clippy::too_many_arguments)]
async fn fork_create_op(
    new_name: &str,
    source_vol_ulid: Ulid,
    snap: Option<Ulid>,
    flags: &[String],
    source_name_hint: Option<&str>,
    store: &Arc<dyn ObjectStore>,
    ctx: &ForkContext,
) -> Result<ForkCreateReply, IpcError> {
    let identity = &ctx.core.identity;
    let data_dir: &Path = &ctx.core.data_dir;
    let prefetch_tracker = &ctx.prefetch_tracker;
    let coord_id = identity.coordinator_id_str();
    validate_volume_name(new_name).map_err(IpcError::bad_request)?;
    let source_ulid_str = source_vol_ulid.to_string();

    let patch = parse_transport_flags(&flags.join(" ")).map_err(IpcError::bad_request)?;
    let ublk_cfg = patch.ublk_cfg_or_default();

    let by_name_dir = data_dir.join("by_name");
    let symlink_path = by_name_dir.join(new_name);
    let by_id_dir = data_dir.join("by_id");
    let source_dir = elide_core::volume::resolve_ancestor_dir(&by_id_dir, &source_ulid_str);
    if !source_dir.exists() {
        return Err(IpcError::not_found(format!(
            "source volume {source_ulid_str} not found locally"
        )));
    }
    if symlink_path.exists() {
        return Err(IpcError::conflict(format!(
            "volume already exists: {new_name}"
        )));
    }

    let new_vol_ulid_value = Ulid::new();
    let new_vol_ulid = new_vol_ulid_value.to_string();
    let new_fork_dir = by_id_dir.join(&new_vol_ulid);

    // Local rollback helpers. `cleanup` undoes the on-disk fork dir +
    // symlink; `rollback_claim` deletes `names/<name>` from the bucket
    // and is only called after `mark_initial` has succeeded, so it
    // always actually rolls back.
    let cleanup = |fork_dir: &Path, link: &Path| {
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_dir_all(fork_dir);
    };
    let rollback_claim = async || {
        let key = object_store::path::Path::from(format!("names/{new_name}"));
        if let Err(e) = store.delete(&key).await {
            warn!(
                "[inbound] fork-create {new_name}: local fork failed and \
                 rollback of names/<name> also failed: {e}"
            );
        }
    };

    // Phase 1: materialise the fork locally. This generates the new
    // fork's keypair on disk so we can upload `volume.pub` before
    // touching `names/<name>`.
    let fork_result: std::io::Result<()> = match snap {
        Some(snap) => elide_core::volume::fork_volume_at(&new_fork_dir, &source_dir, snap),
        None => elide_core::volume::fork_volume(&new_fork_dir, &source_dir),
    };
    if let Err(e) = fork_result {
        cleanup(&new_fork_dir, &symlink_path);
        return Err(IpcError::internal(format!("fork failed: {e}")));
    }

    // Shadow the freshly-minted `volume.key` under
    // `data_dir/keys/<vol_ulid>.key`. The shadow is `start`'s
    // possession proof after a `remove` — minting an owned volume
    // without one would leave it unrestartable on this host, so the
    // write is load-bearing. The fork path generates the key inside
    // `new_fork_dir/volume.key`; read it back and copy.
    let shadow_result = std::fs::read(new_fork_dir.join(elide_core::signing::VOLUME_KEY_FILE))
        .and_then(|bytes| {
            elide_coordinator::key_shadow::write(data_dir, new_vol_ulid_value, &bytes)
        });
    if let Err(e) = shadow_result {
        cleanup(&new_fork_dir, &symlink_path);
        return Err(IpcError::internal(format!("writing key shadow: {e}")));
    }

    // Phase 2: publish volume.pub *and* volume.provenance to S3 *before*
    // claiming the name. Both files are immutable from fork creation
    // onward and self-signed by the new fork's keypair. A SIGINT here
    // at worst leaves orphan
    // `by_id/<new_vol_ulid>/{volume.pub, volume.provenance}` (no
    // names/<name> references them, so they're harmless and reclaimable
    // by future GC). Without this ordering, a crash between
    // mark_initial and the daemon's first metadata-drain leaves
    // `names/<name>` pointing at a vol_ulid whose immutable trust
    // artefacts are missing — which breaks both the normal claim path
    // and the peer-fetch auth pipeline (lineage walk 404s on
    // volume.provenance).
    let meta_store = ctx.core.stores.writer();
    if let Err(e) = elide_coordinator::upload::upload_volume_pub_initial(
        &ctx.core.data_dir,
        new_vol_ulid_value,
        &meta_store,
    )
    .await
    {
        cleanup(&new_fork_dir, &symlink_path);
        return Err(IpcError::store(format!("uploading volume.pub: {e:#}")));
    }
    if let Err(e) = elide_coordinator::upload::upload_volume_provenance_initial(
        &ctx.core.data_dir,
        new_vol_ulid_value,
        &meta_store,
    )
    .await
    {
        cleanup(&new_fork_dir, &symlink_path);
        return Err(IpcError::store(format!(
            "uploading volume.provenance: {e:#}"
        )));
    }

    // Read source volume config for `src_cfg.name` (feeds the
    // `ForkedFrom` journal entry). Done before the bucket claim so a
    // malformed source fails cleanly without leaving a half-claimed
    // name. Size for the new fork's local `volume.toml` comes from the
    // source's cached `volume.toml.size` — the source is always a live
    // volume on this host, so its config is authoritative.
    let src_cfg = match elide_core::config::VolumeConfig::read(&source_dir) {
        Ok(c) => c,
        Err(e) => {
            cleanup(&new_fork_dir, &symlink_path);
            return Err(IpcError::internal(format!(
                "reading source volume config: {e}"
            )));
        }
    };
    let size = match src_cfg.size {
        Some(s) => s,
        None => {
            cleanup(&new_fork_dir, &symlink_path);
            return Err(IpcError::conflict(
                "source volume has no size (import may not have completed)",
            ));
        }
    };

    // Snap actually used for the fork. `snap.is_some()` matches the
    // explicit-pin call sites; otherwise `fork_volume` above resolved
    // `latest_snapshot(&source_dir)` internally and we recompute it
    // here so the journal records the same value. Resolution failure
    // here only suppresses the `ForkedFrom` event; the lifecycle
    // proceeds with `Created` as a fallback.
    let resolved_snap = snap.or_else(|| {
        elide_core::volume::latest_snapshot(&source_dir)
            .ok()
            .flatten()
    });

    // Phase 4 prep: write the local volume.toml alongside the symlink
    // creation below. Doing it here keeps the cleanup semantics
    // symmetric with the upload failures above.
    if let Err(e) = (elide_core::config::VolumeConfig {
        ulid: Some(new_vol_ulid_value),
        name: Some(new_name.to_owned()),
        size: Some(size),
        ublk: ublk_cfg,
        lazy: None,
    }
    .write(&new_fork_dir))
    {
        cleanup(&new_fork_dir, &symlink_path);
        return Err(IpcError::internal(format!("writing volume config: {e}")));
    }

    let src_name = src_cfg.name.or_else(|| source_name_hint.map(str::to_owned));

    // Phase 3: claim `names/<name>` in S3.
    use elide_coordinator::lifecycle::{LifecycleError, MarkInitialOutcome};
    match ctx
        .core
        .stores
        .name_claims()
        .mark_initial(
            new_name,
            coord_id,
            identity.hostname(),
            new_vol_ulid_value,
            size,
        )
        .await
    {
        Ok(MarkInitialOutcome::Claimed) => {
            // `volume create --from` mints a fork, so the opening
            // journal entry on the new name is `ForkedFrom` (not
            // `Created`). Falls back to `Created` only when fork context
            // cannot be reconstructed — typically a ULID-only ancestor
            // with no `name` in its `volume.toml`. Both the source name
            // and snap have to be present; a partial `ForkedFrom` would
            // publish a less useful record than just stating "this name
            // appeared".
            let kind = match (resolved_snap, src_name.clone()) {
                (Some(source_snap_ulid), Some(source_name)) => {
                    elide_core::volume_event::EventKind::ForkedFrom {
                        source_name,
                        source_vol_ulid,
                        source_snap_ulid,
                    }
                }
                _ => {
                    warn!(
                        "[inbound] fork-create {new_name}: source \
                         {source_ulid_str} missing name or snap; emitting \
                         Created in lieu of ForkedFrom"
                    );
                    elide_core::volume_event::EventKind::Created
                }
            };
            ctx.core
                .stores
                .event_journal()
                .emit_best_effort(identity.as_ref(), new_name, kind, new_vol_ulid_value)
                .await;
        }
        Ok(MarkInitialOutcome::AlreadyExists {
            existing_vol_ulid,
            existing_state,
            existing_owner,
        }) => {
            cleanup(&new_fork_dir, &symlink_path);
            let owner = existing_owner.as_deref().unwrap_or("<unowned>");
            return Err(IpcError::conflict(format!(
                "name '{new_name}' already exists in bucket \
                 (vol_ulid={existing_vol_ulid}, state={existing_state:?}, \
                 owner={owner})"
            )));
        }
        Err(LifecycleError::Store(e)) => {
            cleanup(&new_fork_dir, &symlink_path);
            return Err(IpcError::store(format!("claiming name in bucket: {e}")));
        }
        Err(LifecycleError::OwnershipConflict { held_by }) => {
            cleanup(&new_fork_dir, &symlink_path);
            return Err(IpcError::conflict(format!(
                "name held by another coordinator: {held_by}"
            )));
        }
        Err(LifecycleError::InvalidTransition { from, .. }) => {
            cleanup(&new_fork_dir, &symlink_path);
            return Err(IpcError::conflict(format!(
                "names/<name> is in unexpected state {from:?}"
            )));
        }
    }

    // Phase 4: by_name/<name> symlink. volume.toml was written above
    // before mark_initial, so a Phase-3 failure didn't leave a
    // half-written config.
    if let Err(e) = std::fs::create_dir_all(&by_name_dir) {
        cleanup(&new_fork_dir, &symlink_path);
        rollback_claim().await;
        return Err(IpcError::internal(format!("creating by_name dir: {e}")));
    }
    if let Err(e) = std::os::unix::fs::symlink(format!("../by_id/{new_vol_ulid}"), &symlink_path) {
        cleanup(&new_fork_dir, &symlink_path);
        rollback_claim().await;
        return Err(IpcError::internal(format!("creating by_name symlink: {e}")));
    }

    // Pre-register the prefetch tracker entry before notifying the
    // daemon's discovery loop. This closes the race where the CLI's
    // `await-prefetch <new_vol_ulid>` (called immediately after this IPC
    // returns) could land before the daemon has discovered the new fork
    // and registered the entry — in which case `await-prefetch` would
    // hit the "untracked → ok" path and falsely report prefetch
    // complete. `register_prefetch_or_get` is idempotent: when discovery
    // later runs, it gets back the same `Arc<Sender>` and passes it to
    // `run_volume_tasks`. Drop the local Arc immediately; the tracker
    // holds the entry until the per-fork task's Drop guard removes it.
    let _ = register_prefetch_or_get(prefetch_tracker, new_vol_ulid_value);

    crate::rescan::trigger();
    info!("[inbound] forked volume {new_name} ({new_vol_ulid}) from {source_ulid_str}");
    Ok(ForkCreateReply {
        new_vol_ulid: new_vol_ulid_value,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use elide_coordinator::identity::CoordinatorIdentity;
    use elide_coordinator::ipc::IpcErrorKind;
    use elide_coordinator::stores::{PassthroughStores, ScopedStores};
    use elide_core::name_record::{NameRecord, NameState};
    use elide_core::signing::{ProvenanceLineage, VOLUME_PROVENANCE_FILE, write_provenance};
    use object_store::PutPayload;
    use object_store::path::Path as StorePath;
    use rand_core::OsRng;
    use tempfile::TempDir;

    /// Upload a root-shape `volume.pub` + `volume.provenance` for
    /// `vol_ulid` so `pull_chain` can pull + verify the skeleton.
    async fn upload_root_skeleton(store: &Arc<dyn ObjectStore>, vol_ulid: Ulid) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let vk = signing_key.verifying_key();

        let pub_key = StorePath::from(elide_core::store_keys::meta_pub_key(vol_ulid));
        let pub_hex: String = vk.to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        store
            .put(
                &pub_key,
                PutPayload::from(format!("{pub_hex}\n").into_bytes()),
            )
            .await
            .unwrap();

        let tmp = TempDir::new().unwrap();
        write_provenance(
            tmp.path(),
            &signing_key,
            VOLUME_PROVENANCE_FILE,
            &ProvenanceLineage::default(),
        )
        .unwrap();
        let body = std::fs::read(tmp.path().join(VOLUME_PROVENANCE_FILE)).unwrap();
        let prov_key = StorePath::from(elide_core::store_keys::meta_provenance_key(vol_ulid));
        store.put(&prov_key, PutPayload::from(body)).await.unwrap();
    }

    async fn put_name_record(store: &Arc<dyn ObjectStore>, name: &str, rec: &NameRecord) {
        let key = StorePath::from(format!("names/{name}"));
        let body = rec.to_toml().unwrap();
        store
            .put(&key, PutPayload::from(body.into_bytes()))
            .await
            .unwrap();
    }

    fn fixture(store: Arc<dyn ObjectStore>) -> (ForkContext, TempDir) {
        let coord_dir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let identity = Arc::new(CoordinatorIdentity::load_or_generate(coord_dir.path()).unwrap());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(store));
        let ctx = ForkContext {
            core: CoordinatorCore {
                data_dir: Arc::new(data_dir.path().to_path_buf()),
                stores,
                identity,
            },
            fork_registry: new_registry(),
            prefetch_tracker: elide_coordinator::new_prefetch_tracker(),
            fork_sync: elide_coordinator::new_fork_sync_registry(),
        };
        (ctx, data_dir)
    }

    fn orchestrator(ctx: ForkContext, from: ForkSource) -> ForkOrchestrator {
        ForkOrchestrator::new(ForkJob::new(), "child".to_owned(), from, Vec::new(), ctx)
    }

    fn snap() -> Ulid {
        Ulid::from_string("01J1111111111111111111111V").unwrap()
    }

    #[tokio::test]
    async fn remote_name_basis_comes_from_record_latest_snapshot() {
        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let source = Ulid::new();
        upload_root_skeleton(&mem, source).await;
        let mut rec = NameRecord::live_minimal(source, 4096);
        rec.state = NameState::Readonly;
        rec.latest_snapshot = Some(snap());
        put_name_record(&mem, "base", &rec).await;

        let (ctx, _data_dir) = fixture(Arc::clone(&mem));
        let mut orch = orchestrator(
            ctx,
            ForkSource::Name {
                name: "base".to_owned(),
            },
        );
        orch.resolve_source().await.unwrap();
        orch.pull_chain().await.unwrap();
        orch.resolve_snapshot().await.unwrap();
        assert_eq!(orch.snap_ulid, Some(snap()));
    }

    #[tokio::test]
    async fn remote_name_without_recorded_snapshot_refuses() {
        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let source = Ulid::new();
        upload_root_skeleton(&mem, source).await;
        let mut rec = NameRecord::live_minimal(source, 4096);
        rec.state = NameState::Readonly;
        put_name_record(&mem, "base", &rec).await;

        let (ctx, _data_dir) = fixture(Arc::clone(&mem));
        let mut orch = orchestrator(
            ctx,
            ForkSource::Name {
                name: "base".to_owned(),
            },
        );
        orch.resolve_source().await.unwrap();
        orch.pull_chain().await.unwrap();
        let err = orch
            .resolve_snapshot()
            .await
            .expect_err("no basis anywhere must refuse");
        assert_eq!(err.kind, IpcErrorKind::NotFound);
        assert!(err.message.contains("no published snapshot"), "{err}");
    }

    #[tokio::test]
    async fn pinned_name_uses_explicit_snapshot() {
        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let source = Ulid::new();
        upload_root_skeleton(&mem, source).await;
        let mut rec = NameRecord::live_minimal(source, 4096);
        rec.state = NameState::Readonly;
        rec.latest_snapshot = Some(snap());
        put_name_record(&mem, "base", &rec).await;

        let pinned = Ulid::from_string("01J2222222222222222222222V").unwrap();
        let (ctx, _data_dir) = fixture(Arc::clone(&mem));
        let mut orch = orchestrator(
            ctx,
            ForkSource::PinnedName {
                name: "base".to_owned(),
                snap_ulid: pinned,
            },
        );
        orch.resolve_source().await.unwrap();
        orch.pull_chain().await.unwrap();
        orch.resolve_snapshot().await.unwrap();
        assert_eq!(orch.snap_ulid, Some(pinned), "pin wins over record latest");
    }

    #[tokio::test]
    async fn rebound_record_never_supplies_basis_for_local_name() {
        // Local symlink binds the name to fork A (readonly, no local
        // manifest); the bucket record has been rebound to fork B with
        // a latest_snapshot. The fallback must not pair B's snapshot
        // with A.
        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let local_vol = Ulid::new();
        let (ctx, data_dir) = fixture(Arc::clone(&mem));

        let vol_dir = data_dir.path().join("by_id").join(local_vol.to_string());
        std::fs::create_dir_all(&vol_dir).unwrap();
        std::fs::write(vol_dir.join("volume.readonly"), "").unwrap();
        let by_name = data_dir.path().join("by_name");
        std::fs::create_dir_all(&by_name).unwrap();
        std::os::unix::fs::symlink(&vol_dir, by_name.join("base")).unwrap();

        let mut rec = NameRecord::live_minimal(Ulid::new(), 4096);
        rec.latest_snapshot = Some(snap());
        put_name_record(&mem, "base", &rec).await;

        let mut orch = orchestrator(
            ctx,
            ForkSource::Name {
                name: "base".to_owned(),
            },
        );
        orch.resolve_source().await.unwrap();
        orch.pull_chain().await.unwrap();
        let err = orch
            .resolve_snapshot()
            .await
            .expect_err("rebound record must not supply a basis");
        assert_eq!(err.kind, IpcErrorKind::NotFound);
    }
    #[tokio::test]
    async fn setup_stages_are_control_plane_only() {
        // Claim-first ordering: stages 1-3 (resolve-source, pull-chain,
        // resolve-snapshot) run before the new fork exists, so they may
        // touch only control-plane state -- names/<name> + meta/* on
        // coord-ro. The first by_id credential is minted post-rebind
        // (prefetch, anchored on the new fork).
        use elide_coordinator::stores::{RecordingStores, RoleCall};

        let mem: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let source = Ulid::new();
        upload_root_skeleton(&mem, source).await;
        let mut rec = NameRecord::live_minimal(source, 4096);
        rec.state = NameState::Readonly;
        rec.latest_snapshot = Some(snap());
        put_name_record(&mem, "base", &rec).await;

        let coord_dir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let identity = Arc::new(CoordinatorIdentity::load_or_generate(coord_dir.path()).unwrap());
        let recording = RecordingStores::wrap(Arc::new(PassthroughStores::new(mem)));
        let ctx = ForkContext {
            core: CoordinatorCore {
                data_dir: Arc::new(data_dir.path().to_path_buf()),
                stores: recording.clone(),
                identity,
            },
            fork_registry: new_registry(),
            prefetch_tracker: elide_coordinator::new_prefetch_tracker(),
            fork_sync: elide_coordinator::new_fork_sync_registry(),
        };
        let mut orch = orchestrator(
            ctx,
            ForkSource::Name {
                name: "base".to_owned(),
            },
        );
        orch.resolve_source().await.unwrap();
        orch.pull_chain().await.unwrap();
        orch.resolve_snapshot().await.unwrap();

        let calls = recording.calls();
        assert!(!calls.is_empty(), "expected role acquisitions");
        for call in &calls {
            assert!(
                matches!(call, RoleCall::BaseObjectStore),
                "fork setup stages must ride coord-ro only; saw {call:?} in {calls:?}"
            );
        }
    }
}
