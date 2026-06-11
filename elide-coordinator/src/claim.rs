//! Claim flow: registry, orchestrator, and the bucket-side entry point.
//!
//! The claim flow runs in two halves:
//!
//! 1. **Bucket-side claim** ([`claim_volume_bucket_op`]). Synchronous; returns
//!    [`ClaimReply::Reclaimed`] when this host already holds a matching local
//!    fork (in-place reclaim, nothing more to do), or
//!    [`ClaimReply::MustClaimFresh`] when foreign content needs to be pulled
//!    and a fresh fork minted.
//!
//! 2. **Orchestrator** ([`ClaimOrchestrator`]). Spawned in a background tokio
//!    task by [`start_claim`] for the `MustClaimFresh` branch; streams
//!    progress events into a [`ClaimJob`] which `claim-attach` subscribers
//!    consume.
//!
//! The orchestrator owns the per-job state (new-fork skeleton, peer-fetch
//! context, pulled ancestor guard, effective ancestor) so each stage method
//! reads/writes via `&mut self` instead of threading the state through
//! function arguments. Stage outputs that downstream stages consume live as
//! `Option<...>` fields and are unwrapped with explicit `expect()` messages
//! that document which earlier stage was supposed to populate them.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use ed25519_dalek::SigningKey;
use object_store::ObjectStore;
use tracing::{info, warn};
use ulid::Ulid;

use crate::inbound::{CoordinatorCore, await_prefetch_op, local_daemon_running, pull_readonly_op};
use elide_coordinator::ipc::{ClaimAttachEvent, ClaimReply, ClaimStartReply, IpcError};
use elide_coordinator::prefetch::PeerFetchContext;
use elide_coordinator::register_prefetch_or_get;
use elide_coordinator::volume_state::STOPPED_FILE;

// ── Per-domain context ───────────────────────────────────────────────────────

/// Coordinator state needed by the claim flow: the universal hot core
/// plus the claim-domain registries. Constructed via
/// [`crate::inbound::IpcContext::for_claim`]. The peer-fetch handle is
/// a process-global; the orchestrator reads it on demand inside
/// `discover_peer` rather than carrying it on the context.
#[derive(Clone)]
pub(crate) struct ClaimContext {
    pub core: CoordinatorCore,
    pub claim_registry: ClaimRegistry,
    pub prefetch_tracker: elide_coordinator::PrefetchTracker,
}

// ── Job + registry ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum ClaimJobState {
    Running,
    Done,
    Failed(IpcError),
}

pub struct ClaimJob {
    events: Mutex<Vec<ClaimAttachEvent>>,
    state: RwLock<ClaimJobState>,
}

impl ClaimJob {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            events: Mutex::new(Vec::new()),
            state: RwLock::new(ClaimJobState::Running),
        })
    }

    pub fn append(&self, event: ClaimAttachEvent) {
        self.events
            .lock()
            .expect("claim job events poisoned")
            .push(event);
    }

    pub fn finish(&self, state: ClaimJobState) {
        *self.state.write().expect("claim job state poisoned") = state;
    }

    pub fn read_from(&self, offset: usize) -> Vec<ClaimAttachEvent> {
        self.events.lock().expect("claim job events poisoned")[offset..].to_vec()
    }

    pub fn state(&self) -> ClaimJobState {
        self.state.read().expect("claim job state poisoned").clone()
    }
}

/// Registry of in-flight claim jobs keyed by volume name. The bucket-side
/// `claim-start` op already serialises concurrent claims for the same name
/// (the conditional PUT inside `mark_claimed` will lose), so two claim jobs
/// for the same name cannot both be in their post-claim phase.
pub type ClaimRegistry = Arc<Mutex<HashMap<String, Arc<ClaimJob>>>>;

pub fn new_registry() -> ClaimRegistry {
    Arc::new(Mutex::new(HashMap::new()))
}

// ── Pulled-ancestor cleanup guard ─────────────────────────────────────────────

/// Tracks ancestor skeletons pulled during one claim attempt and removes them
/// from disk on drop unless [`Self::commit`] was called.
///
/// Why: [`pull_readonly_op`] verifies provenance against the just-downloaded
/// `volume.pub` — a self-consistent check that does not catch a peer (or
/// store) supplying matched-but-forged `volume.pub` + `volume.provenance`
/// bytes. The forgery only fails later, when the released volume's signed
/// handoff manifest from S3 is checked against that pubkey. Without this
/// guard a failed claim leaves the bogus skeleton in `data_dir/by_id/<id>/`;
/// the next retry sees the directory exists and reuses the lie. The guard
/// ensures every ancestor pulled in a failing attempt is torn down before
/// the error propagates.
///
/// Removal is cheap blocking I/O (`std::fs::remove_dir_all`), safe to run
/// from `Drop`. Failures are logged but not propagated — at worst a leftover
/// dir survives, the same outcome as today's behaviour.
pub(crate) struct PulledAncestorsGuard {
    by_id_dir: PathBuf,
    pulled: Vec<Ulid>,
    committed: bool,
}

impl PulledAncestorsGuard {
    pub(crate) fn new(by_id_dir: PathBuf) -> Self {
        Self {
            by_id_dir,
            pulled: Vec::new(),
            committed: false,
        }
    }

    pub(crate) fn record(&mut self, vol_ulid: Ulid) {
        self.pulled.push(vol_ulid);
    }

    /// Mark the pulled set as kept. Call after every downstream verification
    /// step that could reject a peer-served forgery has passed — typically
    /// right before [`ClaimOrchestrator::finalize`].
    pub(crate) fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PulledAncestorsGuard {
    fn drop(&mut self) {
        if self.committed || self.pulled.is_empty() {
            return;
        }
        for vol_ulid in &self.pulled {
            let dir = self.by_id_dir.join(vol_ulid.to_string());
            if let Err(e) = std::fs::remove_dir_all(&dir) {
                warn!(
                    "[claim cleanup] failed to remove pulled ancestor {}: {e}",
                    dir.display()
                );
            } else {
                info!("[claim cleanup] removed unverified ancestor {vol_ulid}");
            }
        }
    }
}

// ── Entry point ──────────────────────────────────────────────────────────────

/// Run the bucket-side claim synchronously and either return `Reclaimed` (no
/// further work) or register a job and spawn the foreign-claim orchestrator.
/// Returns immediately in both branches — `Claiming` callers subscribe via
/// `claim-attach` to stream progress.
pub(crate) async fn start_claim(
    volume: String,
    ctx: ClaimContext,
) -> Result<ClaimStartReply, IpcError> {
    let store = ctx.core.stores.writer();
    let journal = ctx.core.stores.event_journal();
    let claims = ctx.core.stores.name_claims();
    let bucket_started = std::time::Instant::now();
    let bucket = claim_volume_bucket_op(
        &volume,
        &ctx.core.data_dir,
        &store,
        journal.as_ref(),
        claims.as_ref(),
        &ctx.core.identity,
    )
    .await?;
    info!(
        "[claim {volume}] bucket-side claim resolved in {:.2?}",
        bucket_started.elapsed()
    );
    match bucket {
        ClaimReply::Reclaimed => Ok(ClaimStartReply::Reclaimed),
        ClaimReply::MustClaimFresh {
            released_vol_ulid,
            handoff_snapshot,
        } => {
            let snap = handoff_snapshot.ok_or_else(|| {
                IpcError::not_found(format!(
                    "name '{volume}' is Released but has no handoff snapshot — \
                     manual recovery required (see docs/operations.md)"
                ))
            })?;

            {
                let mut reg = ctx.claim_registry.lock().expect("claim registry poisoned");
                if let Some(job) = reg.get(&volume)
                    && matches!(job.state(), ClaimJobState::Running)
                {
                    return Err(IpcError::conflict(format!(
                        "claim for '{volume}' is already in progress"
                    )));
                }
                reg.insert(volume.clone(), ClaimJob::new());
            }
            let job = ctx
                .claim_registry
                .lock()
                .expect("claim registry poisoned")
                .get(&volume)
                .cloned()
                .expect("just inserted");

            tokio::spawn(async move {
                let orch =
                    ClaimOrchestrator::new(job.clone(), volume, released_vol_ulid, snap, ctx);
                match orch.run().await {
                    Ok(()) => {
                        job.append(ClaimAttachEvent::Done);
                        job.finish(ClaimJobState::Done);
                    }
                    Err(e) => job.finish(ClaimJobState::Failed(e)),
                }
            });

            Ok(ClaimStartReply::Claiming { released_vol_ulid })
        }
    }
}

// ── Bucket-side claim ─────────────────────────────────────────────────────────

async fn claim_volume_bucket_op(
    volume_name: &str,
    data_dir: &std::path::Path,
    store: &Arc<dyn ObjectStore>,
    journal: &dyn elide_coordinator::event_journal::EventJournal,
    claims: &dyn elide_coordinator::name_claims::NameClaims,
    identity: &Arc<elide_coordinator::identity::CoordinatorIdentity>,
) -> Result<ClaimReply, IpcError> {
    use elide_coordinator::bucket_position::fetch_position;
    use elide_coordinator::role::{ObserverKind, Role};
    use elide_coordinator::volume_state::{VolumeLifecycle, clear_released_marker};
    use elide_core::name_record::NameState;

    let coord_id = identity.coordinator_id_str();

    // Claim always lands the volume in `Stopped`. A running local daemon
    // contradicts that — refuse and point the operator at `volume stop` first.
    if local_daemon_running(data_dir, volume_name) {
        return Err(IpcError::conflict(format!(
            "volume '{volume_name}' is running on this host; \
             stop it first with: elide volume stop {volume_name}"
        )));
    }

    // Resolve local fork once up front; both bucket-state branches
    // (Released → reclaim-vs-MustClaimFresh, OwnedByUs → reconcile)
    // need the vol_dir / vol_ulid to discriminate.
    let (local_vol_dir, _shape) =
        VolumeLifecycle::resolve(&data_dir.join("by_name").join(volume_name))
            .map_err(|e| IpcError::internal(format!("resolving local fork: {e}")))?;
    let local_vol_ulid = local_vol_dir
        .as_deref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .and_then(|s| Ulid::from_string(s).ok());

    let (position, _record) = fetch_position(store, volume_name, coord_id)
        .await
        .map_err(|e| IpcError::store(format!("reading names/{volume_name}: {e}")))?;

    match Role::from_position(&position) {
        Role::None => Err(IpcError::not_found(format!(
            "name '{volume_name}' has no S3 record; nothing to claim"
        ))),
        Role::Observer {
            kind: ObserverKind::Released {
                handoff: handoff_snapshot,
            },
        } => {
            let released_vol_ulid = position
                .vol_ulid()
                .expect("Released role implies non-Absent position");
            if local_vol_ulid != Some(released_vol_ulid) {
                // Foreign content — CLI must orchestrate the claim.
                return Ok(ClaimReply::MustClaimFresh {
                    released_vol_ulid,
                    handoff_snapshot,
                });
            }
            // In-place reclaim of a Released name we still hold
            // locally. Three shapes for the matching `vol_ulid`:
            //
            //   (a) Original writable fork (has `volume.key`):
            //       reconcile is a no-op on the local side; just
            //       flip the bucket to Stopped.
            //
            //   (b) Readonly copy of our own lineage (no
            //       `volume.key`, but a key shadow exists):
            //       reconcile restores the key and strips the
            //       readonly marker, then the bucket flip proceeds.
            //
            //   (c) Readonly copy of a foreign lineage (no
            //       `volume.key`, no shadow): reconcile refuses
            //       with `NoKeyShadow` and we surface a hint to
            //       fork via `volume create --from`.
            let vol_dir = local_vol_dir
                .clone()
                .expect("local_vol_ulid matched bucket => fork dir resolved");
            use elide_coordinator::volume_state::{
                ReconcileError, reconcile_owned_local_to_stopped,
            };
            if let Err(e) = reconcile_owned_local_to_stopped(&vol_dir, data_dir, released_vol_ulid)
            {
                return Err(match e {
                    ReconcileError::NoKeyShadow => IpcError::conflict(format!(
                        "volume '{volume_name}' is a readonly copy with no \
                         local signing key. To use it as a writable fork run: \
                         elide volume create --from {volume_name} <new-name>"
                    )),
                    ReconcileError::DaemonRunning => IpcError::conflict(format!(
                        "volume '{volume_name}' is running on this host; \
                         stop it first with: elide volume stop {volume_name}"
                    )),
                    ReconcileError::Io(e) => {
                        IpcError::internal(format!("reconciling local fork: {e}"))
                    }
                });
            }
            use elide_coordinator::lifecycle::{LifecycleError, MarkReclaimedLocalOutcome};
            match claims
                .mark_reclaimed_local(
                    volume_name,
                    coord_id,
                    identity.hostname(),
                    released_vol_ulid,
                    NameState::Stopped,
                )
                .await
            {
                Ok(MarkReclaimedLocalOutcome::Reclaimed) => {
                    info!(
                        "[inbound] reclaimed {volume_name} in place (vol_ulid {released_vol_ulid})"
                    );
                    if let Err(e) =
                        elide_coordinator::remote_breadcrumb::remove(data_dir, volume_name)
                    {
                        warn!("[inbound] reclaim {volume_name}: clearing breadcrumb: {e}");
                    }
                    // Best-effort: drop the display-only marker now that
                    // the bucket record is no longer Released.
                    if let Err(e) = clear_released_marker(&vol_dir) {
                        warn!(
                            "[inbound] reclaim {volume_name}: clearing \
                             volume.released marker: {e}"
                        );
                    }
                    journal
                        .emit_best_effort(
                            identity.as_ref(),
                            volume_name,
                            elide_core::volume_event::EventKind::Claimed,
                            released_vol_ulid,
                        )
                        .await;
                    Ok(ClaimReply::Reclaimed)
                }
                Ok(MarkReclaimedLocalOutcome::Absent) => Err(IpcError::precondition_failed(
                    format!("names/{volume_name} vanished between read and reclaim"),
                )),
                Ok(MarkReclaimedLocalOutcome::NotReleased { observed_state, .. }) => {
                    Err(IpcError::precondition_failed(format!(
                        "names/{volume_name} changed underneath us; now in state \
                         {observed_state:?}"
                    )))
                }
                Ok(MarkReclaimedLocalOutcome::ForkMismatch {
                    released_vol_ulid: raced_vol_ulid,
                    ..
                }) => {
                    // Race: someone rebound between our read and write.
                    // Surface as MustClaimFresh routing — same shape as the
                    // foreign-content path above.
                    Ok(ClaimReply::MustClaimFresh {
                        released_vol_ulid: raced_vol_ulid,
                        handoff_snapshot,
                    })
                }
                Err(LifecycleError::Store(e)) => {
                    Err(IpcError::store(format!("reclaim failed: {e}")))
                }
                Err(LifecycleError::OwnershipConflict { .. })
                | Err(LifecycleError::InvalidTransition { .. }) => Err(IpcError::conflict(
                    format!("in-place reclaim of {volume_name} refused"),
                )),
            }
        }
        Role::Owner { .. } => {
            let vol_ulid = position
                .vol_ulid()
                .expect("Role::Owner implies non-Absent position");
            // Idempotent: we already own this name in the bucket.
            // Reconcile the local fork to the canonical Stopped+
            // writable shape so a subsequent `volume start` works
            // immediately. Handles the readonly-local case: `volume.key`
            // missing, `volume.readonly` present.
            //
            // If no local fork exists at all (e.g. post-stop+remove,
            // breadcrumb retained), `claim` doesn't hydrate — the
            // operator should use `volume start`, which has the
            // full hydrate-from-bucket pipeline.
            use elide_coordinator::volume_state::{
                ReconcileError, ReconcileOutcome, reconcile_owned_local_to_stopped,
            };
            let vol_dir = match local_vol_dir.clone() {
                Some(d) => d,
                None => {
                    return Err(IpcError::conflict(format!(
                        "name '{volume_name}' is owned by this coordinator but has no \
                         local fork; use `volume start {volume_name}` to hydrate"
                    )));
                }
            };
            match reconcile_owned_local_to_stopped(&vol_dir, data_dir, vol_ulid) {
                Ok(ReconcileOutcome::AlreadyStopped) => {
                    info!("[inbound] claim {volume_name}: already owned + stopped — no-op");
                    Ok(ClaimReply::Reclaimed)
                }
                Ok(ReconcileOutcome::Reconciled) => {
                    info!(
                        "[inbound] claim {volume_name}: reconciled local fork to stopped+writable"
                    );
                    Ok(ClaimReply::Reclaimed)
                }
                Err(ReconcileError::NoKeyShadow) => Err(IpcError::conflict(format!(
                    "volume '{volume_name}' is a readonly copy with no \
                     local signing key. To use it as a writable fork run: \
                     elide volume create --from {volume_name} <new-name>"
                ))),
                Err(ReconcileError::DaemonRunning) => Err(IpcError::conflict(format!(
                    "volume '{volume_name}' is running on this host; \
                     stop it first with: elide volume stop {volume_name}"
                ))),
                Err(ReconcileError::Io(e)) => {
                    Err(IpcError::internal(format!("reconciling local fork: {e}")))
                }
            }
        }
        Role::Observer {
            kind: ObserverKind::Foreign { coord_id: owner },
        } => Err(IpcError::conflict(format!(
            "name '{volume_name}' is held by coordinator {owner}"
        ))),
        Role::Observer {
            kind: ObserverKind::Readonly,
        } => Err(IpcError::conflict(format!(
            "name '{volume_name}' is readonly (immutable handle); \
             pull it with `volume pull` to serve locally"
        ))),
    }
}

// ── Orchestrator ─────────────────────────────────────────────────────────────

/// Skeleton minted in stage 1 (`early_rebind`) and consumed in stage 6
/// (`finalize`). The fork dir on disk holds `volume.{key,pub}` only — no
/// `wal/`, no `pending/`, no `index/` — until `finalize` writes them.
struct NewForkSkeleton {
    vol_ulid: Ulid,
    dir: PathBuf,
    signing_key: SigningKey,
}

/// The ancestor chosen as the new fork's parent after stage 4b
/// (`skip_empty_intermediates`).
struct EffectiveAncestor {
    vol: Ulid,
    snap: Ulid,
}

/// Drive one claim job to completion.
///
/// The flow is a six-stage pipeline; each stage consumes earlier outputs from
/// `self` and writes its own. See [`Self::run`] for the linear sequence.
pub(crate) struct ClaimOrchestrator {
    job: Arc<ClaimJob>,
    volume: String,
    released_vol_ulid: Ulid,
    handoff_snap: Ulid,
    ctx: ClaimContext,
    by_id_dir: PathBuf,
    pulled_guard: PulledAncestorsGuard,

    // Stage outputs.
    new_fork: Option<NewForkSkeleton>,
    peer_ctx: Option<PeerFetchContext>,
    effective: Option<EffectiveAncestor>,
}

impl ClaimOrchestrator {
    pub(crate) fn new(
        job: Arc<ClaimJob>,
        volume: String,
        released_vol_ulid: Ulid,
        handoff_snap: Ulid,
        ctx: ClaimContext,
    ) -> Self {
        let by_id_dir = ctx.core.data_dir.join("by_id");
        let pulled_guard = PulledAncestorsGuard::new(by_id_dir.clone());
        Self {
            job,
            volume,
            released_vol_ulid,
            handoff_snap,
            ctx,
            by_id_dir,
            pulled_guard,
            new_fork: None,
            peer_ctx: None,
            effective: None,
        }
    }

    pub(crate) async fn run(mut self) -> Result<(), IpcError> {
        self.early_rebind().await?;
        self.discover_peer().await;
        self.pull_chain().await?;
        self.skip_empty_intermediates().await?;
        // All signature checks against S3-rooted artifacts have passed.
        // Commit so the pulled skeletons survive the rest of this job.
        self.pulled_guard.commit();
        self.finalize().await?;
        self.surface_prefetch().await;
        Ok(())
    }

    /// Stage 1. Mint a fresh fork ULID + keypair, upload `volume.{pub,
    /// provenance}` to S3, and `mark_claimed` to rebind `names/<volume>` to
    /// this coordinator. After this returns the bucket says we own the name,
    /// peer-fetch auth accepts our coord_id for the chain walk that follows,
    /// and the local fork dir holds `volume.{key,pub,provenance}` only —
    /// crucially **no `wal/`, no `pending/`, no `index/`**, so the daemon's
    /// discovery loop won't pick the partial fork up and try to open it
    /// before [`Self::finalize`] materialises those dirs.
    ///
    /// The provenance written here is provisional: its `ParentRef` points at
    /// the immediate released volume, not yet the effective (deepest
    /// non-empty) ancestor that `skip_empty_intermediates` resolves.
    /// `finalize` overwrites it once `effective` is known.
    ///
    /// Crash semantics. If the coordinator dies between this returning and
    /// `finalize`'s rewrite, the bucket points at an empty fork whose
    /// provenance already names the released volume as its parent. It is
    /// recoverable: `volume claim --force` over the partial fork takes over
    /// that `ParentRef`, anchoring the new fork on the released volume's
    /// data. (A root-shape `parent: None` provenance would instead strand
    /// the released volume's data behind an empty root the takeover could
    /// never reach.)
    async fn early_rebind(&mut self) -> Result<(), IpcError> {
        use elide_coordinator::lifecycle::{LifecycleError, MarkClaimedOutcome};
        use elide_core::name_record::NameState;
        use elide_core::signing::{
            ParentRef, ProvenanceLineage, VOLUME_KEY_FILE, VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE,
            generate_keypair, write_provenance,
        };

        let early_started = std::time::Instant::now();

        let new_vol_ulid = Ulid::new();
        let new_vol_ulid_str = new_vol_ulid.to_string();
        let new_fork_dir = self.ctx.core.data_dir.join("by_id").join(&new_vol_ulid_str);

        // Bare dir + keypair only. No wal/, no pending/, no index/ — daemon
        // discovery requires one of those to consider a dir a volume, so this
        // skeleton stays invisible to the supervisor until `finalize` adds them.
        std::fs::create_dir_all(&new_fork_dir)
            .map_err(|e| IpcError::internal(format!("creating fork dir: {e}")))?;
        let signing_key = generate_keypair(&new_fork_dir, VOLUME_KEY_FILE, VOLUME_PUB_FILE)
            .map_err(|e| IpcError::internal(format!("generating keypair: {e}")))?;

        // Shadow the freshly-minted key under
        // `data_dir/keys/<vol_ulid>.key` so a future
        // `stop`→`remove`→`start` round-trip on this host preserves
        // writability — see `elide_coordinator::key_shadow`.
        if let Err(e) = elide_coordinator::key_shadow::write(
            &self.ctx.core.data_dir,
            new_vol_ulid,
            &signing_key.to_bytes(),
        ) {
            warn!("[claim {new_vol_ulid_str}] writing key shadow failed: {e}");
        }

        // Sign a provisional `volume.provenance` whose `ParentRef` points at
        // the immediate released volume, alongside `volume.pub`. The
        // *effective* (deepest non-empty) ancestor isn't known yet — that
        // comes from `skip_empty_intermediates` after the chain walk — but
        // every published fork in the bucket must carry a complete provenance
        // so readers don't special-case the "pub-exists-but-no-provenance"
        // shape. `finalize` overwrites this with the effective `ParentRef`
        // once `effective` is resolved.
        //
        // Claim-first ordering (`design-mint-volume-attestation.md`
        // § *Setup reads*): everything before `mark_claimed` below is
        // control-plane only. Both provisional trust anchors come from
        // there — the basis (`handoff_snap`) from the Released record,
        // the parent identity key from `meta/<released>.pub` on
        // `coord-ro`.
        let base_ro = self.ctx.core.stores.base_object_store();
        let released_meta =
            elide_coordinator::volume_data::VolumeData::new(base_ro, self.released_vol_ulid);
        let parent_pubkey = released_meta.metadata().read_pubkey().await.map_err(|e| {
            IpcError::store(format!(
                "reading meta/{}.pub for released volume: {e}",
                self.released_vol_ulid
            ))
        })?;
        let provisional_lineage = ProvenanceLineage {
            parent: Some(ParentRef {
                volume_ulid: self.released_vol_ulid.to_string(),
                snapshot_ulid: self.handoff_snap.to_string(),
                pubkey: parent_pubkey.to_bytes(),
            }),
            extent_index: Vec::new(),
            oci_source: None,
        };
        write_provenance(
            &new_fork_dir,
            &signing_key,
            VOLUME_PROVENANCE_FILE,
            &provisional_lineage,
        )
        .map_err(|e| IpcError::internal(format!("writing provisional provenance: {e}")))?;

        // Upload volume.pub and volume.provenance to S3 in parallel so
        // peer-fetch ancestry walks (which read both) and future claimants
        // doing `claim --force` see a complete fork in the bucket. Both
        // are self-signed by the fresh keypair generated above. The
        // invariant "names/<name> only points at vol_ulids with both
        // immutable trust artefacts in the bucket" is restored at
        // `mark_claimed` below.
        let new_vd = self.ctx.core.stores.volume_data(&new_vol_ulid);
        let (pub_result, prov_result) = tokio::join!(
            elide_coordinator::upload::upload_volume_pub_initial(&new_fork_dir, &new_vd),
            elide_coordinator::upload::upload_volume_provenance_initial(&new_fork_dir, &new_vd),
        );
        pub_result.map_err(|e| IpcError::store(format!("uploading volume.pub: {e:#}")))?;
        prov_result
            .map_err(|e| IpcError::store(format!("uploading provisional provenance: {e:#}")))?;

        // Bucket rebind. Peer-fetch auth accepts our coord_id from this point
        // onward.
        match self
            .ctx
            .core
            .stores
            .name_claims()
            .mark_claimed(
                &self.volume,
                self.ctx.core.identity.coordinator_id_str(),
                self.ctx.core.identity.hostname(),
                new_vol_ulid,
                NameState::Stopped,
            )
            .await
        {
            Ok(MarkClaimedOutcome::Claimed) => {
                let vol = &self.volume;
                info!(
                    "[claim {vol}] early-rebind: bucket → {new_vol_ulid_str} \
                     (provenance pending)"
                );
                self.ctx
                    .core
                    .stores
                    .event_journal()
                    .emit_best_effort(
                        self.ctx.core.identity.as_ref(),
                        &self.volume,
                        elide_core::volume_event::EventKind::Claimed,
                        new_vol_ulid,
                    )
                    .await;
                self.new_fork = Some(NewForkSkeleton {
                    vol_ulid: new_vol_ulid,
                    dir: new_fork_dir,
                    signing_key,
                });
                info!(
                    "[claim {}] early-rebind completed in {:.2?}",
                    self.volume,
                    early_started.elapsed()
                );
                Ok(())
            }
            Ok(MarkClaimedOutcome::Absent) => Err(IpcError::not_found(format!(
                "names/{} disappeared between bucket-side claim and rebind",
                self.volume
            ))),
            Ok(MarkClaimedOutcome::NotReleased { observed }) => Err(IpcError::conflict(format!(
                "names/{} changed underneath us; now in state {observed:?}",
                self.volume
            ))),
            Err(LifecycleError::Store(e)) => Err(IpcError::store(format!("rebind failed: {e}"))),
            Err(LifecycleError::OwnershipConflict { held_by }) => {
                Err(IpcError::precondition_failed(format!(
                    "name '{}' raced with another claim ({held_by} won)",
                    self.volume
                )))
            }
            Err(LifecycleError::InvalidTransition { from, .. }) => Err(IpcError::conflict(
                format!("names/{} is in unexpected state {from:?}", self.volume),
            )),
        }
    }

    /// Stage 2. Discover the previous claimer's peer-fetch endpoint.
    ///
    /// Best-effort — `peer_ctx` is set only when `[peer_fetch].port` is
    /// configured, the event log yields a clean Released, and the previous
    /// claimer published a peer endpoint. Peer auth now accepts our coord_id
    /// (we `mark_claimed` in stage 1), so peer requests will succeed.
    async fn discover_peer(&mut self) {
        let Some(handle) = elide_coordinator::tasks::peer_fetch_handle() else {
            return;
        };
        // Discovery reads events/<name>/HEAD, coordinators/<other>/coordinator.pub,
        // and coordinators/<other>/peer-endpoint.toml — all RO and all cross-
        // coordinator, so the correct credential is coord-ro.
        let store_base = self.ctx.core.stores.base_object_store();
        let journal = self.ctx.core.stores.event_journal_ro();
        if let Some(discovered) = elide_coordinator::peer_discovery::discover_peer_for_claim(
            &store_base,
            journal.as_ref(),
            &self.volume,
        )
        .await
        {
            self.peer_ctx = Some(PeerFetchContext {
                client: handle.client.clone(),
                endpoint: discovered.endpoint,
                volume_name: self.volume.clone(),
            });
        }
    }

    /// Stage 3. Pull the released chain locally if absent. Peer-first when a
    /// context is available — auth now accepts our coord_id.
    async fn pull_chain(&mut self) -> Result<(), IpcError> {
        use elide_core::volume::resolve_ancestor_dir;

        let chain_started = std::time::Instant::now();
        let mut chain_pulled = 0usize;
        let mut next: Option<Ulid> = Some(self.released_vol_ulid);
        while let Some(vol_ulid) = next.take() {
            let dir = resolve_ancestor_dir(&self.by_id_dir, &vol_ulid.to_string());
            if dir.exists() {
                break;
            }
            self.job
                .append(ClaimAttachEvent::PullingAncestor { vol_ulid });
            // Skeleton pull reads only `meta/<ulid>.{provenance,pub}` —
            // bucket-wide objects covered by the warm `coord-ro`
            // credential, so chain discovery costs no per-hop mint.
            let store = self.ctx.core.stores.base_object_store();
            self.pulled_guard.record(vol_ulid);
            let reply = pull_readonly_op(
                vol_ulid,
                &self.ctx.core.data_dir,
                &store,
                self.peer_ctx.as_ref(),
            )
            .await?;
            chain_pulled += 1;
            next = reply.parent;
        }
        info!(
            "[claim {}] ancestor chain pulled: {chain_pulled} in {:.2?}",
            self.volume,
            chain_started.elapsed()
        );

        let source_dir = resolve_ancestor_dir(&self.by_id_dir, &self.released_vol_ulid.to_string());
        if !source_dir.exists() {
            return Err(IpcError::not_found(format!(
                "source volume {} not found in remote store",
                self.released_vol_ulid
            )));
        }
        Ok(())
    }

    /// Stage 4b. Skip empty intermediate forks.
    ///
    /// A fork that produced no writes between claim and release leaves a
    /// handoff snapshot whose segment list is identical to its parent's —
    /// every segment was inherited, none minted under this fork. Forking from
    /// such a no-op intermediate just bloats the chain by one link per cycle.
    /// Detect it and rewrite `effective` to point at the deepest non-empty
    /// ancestor.
    async fn skip_empty_intermediates(&mut self) -> Result<(), IpcError> {
        let (vol, snap) = skip_empty_intermediates_impl(
            &self.job,
            &self.volume,
            self.released_vol_ulid,
            self.handoff_snap,
            &self.ctx.core.data_dir,
            &self.ctx.core.stores,
            self.peer_ctx.as_ref(),
            &mut self.pulled_guard,
        )
        .await?;
        self.effective = Some(EffectiveAncestor { vol, snap });
        Ok(())
    }

    /// Stage 5. Now that ancestor verification has passed and `effective` is
    /// known, sign and upload `volume.provenance`, write the local config +
    /// `wal/` + `pending/`, link `by_name/<volume>`, drop the
    /// `volume.stopped` marker, and emit the journal event. Once this returns
    /// the fork is fully materialised and the daemon's next discovery tick
    /// will find and supervise it.
    async fn finalize(&mut self) -> Result<(), IpcError> {
        use elide_core::signing::{
            ParentRef, ProvenanceLineage, VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE,
            load_verifying_key, write_provenance,
        };
        use elide_core::volume::resolve_ancestor_dir;

        let fork_create_started = std::time::Instant::now();
        let new_fork = self
            .new_fork
            .as_ref()
            .expect("early_rebind must run before finalize");
        let effective = self
            .effective
            .as_ref()
            .expect("skip_empty_intermediates must run before finalize");
        let new_vol_ulid_str = new_fork.vol_ulid.to_string();

        // Ancestor's identity pubkey for the embedded `ParentRef.pubkey` trust
        // anchor. Loaded from the just-pulled (and verified) ancestor skeleton.
        let parent_dir = resolve_ancestor_dir(&self.by_id_dir, &effective.vol.to_string());
        let parent_pubkey = load_verifying_key(&parent_dir, VOLUME_PUB_FILE)
            .map_err(|e| IpcError::internal(format!("loading parent volume.pub: {e}")))?;

        let lineage = ProvenanceLineage {
            parent: Some(ParentRef {
                volume_ulid: effective.vol.to_string(),
                snapshot_ulid: effective.snap.to_string(),
                pubkey: parent_pubkey.to_bytes(),
            }),
            extent_index: Vec::new(),
            oci_source: None,
        };
        write_provenance(
            &new_fork.dir,
            &new_fork.signing_key,
            VOLUME_PROVENANCE_FILE,
            &lineage,
        )
        .map_err(|e| IpcError::internal(format!("writing provenance: {e}")))?;

        let prov_vd = self.ctx.core.stores.volume_data(&new_fork.vol_ulid);
        elide_coordinator::upload::upload_volume_provenance_initial(&new_fork.dir, &prov_vd)
            .await
            .map_err(|e| IpcError::store(format!("uploading volume.provenance: {e:#}")))?;

        // wal/ and pending/ now — daemon discovery becomes interested only
        // after these exist, by which point the provenance is on S3 and the
        // volume is fully openable.
        std::fs::create_dir_all(new_fork.dir.join("wal"))
            .map_err(|e| IpcError::internal(format!("creating wal/: {e}")))?;
        std::fs::create_dir_all(new_fork.dir.join("pending"))
            .map_err(|e| IpcError::internal(format!("creating pending/: {e}")))?;

        // Local volume.toml: size from the released NameRecord (claim is a
        // continuation of the same logical volume identity, not a resize).
        let claims = self.ctx.core.stores.name_claims_ro();
        let size = match claims.read(&self.volume).await {
            Ok(Some(rec)) => rec.size,
            Ok(None) => {
                return Err(IpcError::not_found(format!(
                    "names/{} disappeared during finalize",
                    self.volume
                )));
            }
            Err(e) => {
                return Err(IpcError::store(format!(
                    "reading names/{}: {e}",
                    self.volume
                )));
            }
        };
        elide_core::config::VolumeConfig {
            name: Some(self.volume.clone()),
            size: Some(size),
            ublk: None,
            lazy: None,
        }
        .write(&new_fork.dir)
        .map_err(|e| IpcError::internal(format!("writing volume.toml: {e}")))?;

        // by_name symlink + volume.stopped marker.
        let by_name_dir = self.ctx.core.data_dir.join("by_name");
        let symlink_path = by_name_dir.join(&self.volume);
        std::fs::create_dir_all(&by_name_dir)
            .map_err(|e| IpcError::internal(format!("creating by_name dir: {e}")))?;
        if symlink_path.exists() || symlink_path.is_symlink() {
            std::fs::remove_file(&symlink_path)
                .map_err(|e| IpcError::internal(format!("removing stale by_name link: {e}")))?;
        }
        std::os::unix::fs::symlink(format!("../by_id/{new_vol_ulid_str}"), &symlink_path)
            .map_err(|e| IpcError::internal(format!("creating by_name symlink: {e}")))?;
        std::fs::write(new_fork.dir.join(STOPPED_FILE), "")
            .map_err(|e| IpcError::internal(format!("writing volume.stopped: {e}")))?;

        if let Err(e) =
            elide_coordinator::remote_breadcrumb::remove(&self.ctx.core.data_dir, &self.volume)
        {
            warn!("[claim {}] clearing remote breadcrumb: {e}", self.volume);
        }

        register_prefetch_or_get(&self.ctx.prefetch_tracker, new_fork.vol_ulid);
        crate::rescan::trigger();
        self.job.append(ClaimAttachEvent::ForkCreated {
            new_vol_ulid: new_fork.vol_ulid,
        });
        info!(
            "[claim {}] finalized fork {new_vol_ulid_str} (parent {}/{})",
            self.volume, effective.vol, effective.snap
        );
        info!(
            "[claim {}] fork finalized in {:.2?}",
            self.volume,
            fork_create_started.elapsed()
        );
        Ok(())
    }

    /// Stage 6. Surface prefetch warm-up. Non-fatal: the bucket-side claim
    /// and local fork are durable by this point.
    async fn surface_prefetch(&self) {
        let new_fork = self
            .new_fork
            .as_ref()
            .expect("early_rebind must run before surface_prefetch");
        let prefetch_wait_started = std::time::Instant::now();
        self.job.append(ClaimAttachEvent::PrefetchStarted);
        let _ = await_prefetch_op(new_fork.vol_ulid, &self.ctx.prefetch_tracker).await;
        self.job.append(ClaimAttachEvent::PrefetchDone);
        info!(
            "[claim {}] prefetch awaited in {:.2?}",
            self.volume,
            prefetch_wait_started.elapsed()
        );
    }
}

// ── Private helpers ──────────────────────────────────────────────────────────

/// Walk back through empty intermediate forks and return the deepest non-empty
/// ancestor as the source the new fork should pin to.
///
/// Each iteration:
///   1. Read the current effective fork's signed `volume.provenance` to find
///      its `parent` ref (if any).
///   2. Fetch and verify its handoff manifest from S3.
///   3. Decide emptiness:
///      * Non-root: empty if `max(segment_ulids) < parent.snapshot_ulid` —
///        every segment was inherited from the parent.
///      * Root: empty if `segment_ulids` is empty — the fork has no content
///        and no ancestor to fall back to.
///   4. If non-root and empty, advance to the parent and loop. If non-root
///      and non-empty, return this fork. If root and non-empty, return this
///      fork. If root and empty, error: the entire chain is empty, so pinning
///      a new fork here would produce a volume that can never serve a read.
///
/// On loop advance, also pulls the parent's directory locally if not already
/// present — chain-pull in stage 3 stops at the first existing dir, but the
/// skip walk may need to reach further back.
///
/// Returns `(source_vol_ulid, snapshot_ulid)`.
///
/// Kept as a free fn (rather than folded into the `&mut self` method above)
/// so the existing test suite can drive it directly without needing to
/// construct a full [`IpcContext`] / [`ClaimOrchestrator`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn skip_empty_intermediates_impl(
    job: &Arc<ClaimJob>,
    volume: &str,
    released_vol_ulid: Ulid,
    handoff_snap: Ulid,
    data_dir: &std::path::Path,
    stores: &Arc<dyn elide_coordinator::stores::ScopedStores>,
    peer: Option<&PeerFetchContext>,
    guard: &mut PulledAncestorsGuard,
) -> Result<(Ulid, Ulid), IpcError> {
    use elide_core::signing::{
        VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE, load_verifying_key,
        read_lineage_verifying_signature,
    };
    use elide_core::volume;

    let by_id_dir = data_dir.join("by_id");

    let mut effective_vol = released_vol_ulid;
    let mut effective_snap = handoff_snap;

    loop {
        let dir = volume::resolve_ancestor_dir(&by_id_dir, &effective_vol.to_string());
        let lineage =
            read_lineage_verifying_signature(&dir, VOLUME_PUB_FILE, VOLUME_PROVENANCE_FILE)
                .map_err(|e| {
                    IpcError::internal(format!("reading provenance for {effective_vol}: {e}"))
                })?;

        // Verify and read this fork's handoff manifest under the
        // fork's own `volume.pub` from the just-pulled (and verified)
        // skeleton. This is the first step that verifies a
        // peer-served pubkey against an S3-rooted artifact: a
        // tampering peer is detected here, and on `?` propagation the
        // caller's guard tears down the bogus skeletons.
        let fork_pubkey = load_verifying_key(&dir, VOLUME_PUB_FILE).map_err(|e| {
            IpcError::internal(format!("loading volume.pub for {effective_vol}: {e}"))
        })?;

        // Pure-read manifest fetch — `volume-ro` is the right scope.
        let store = stores.read_volume(&effective_vol);
        let manifest =
            fetch_handoff_manifest(&store, effective_vol, effective_snap, &fork_pubkey, peer)
                .await?;

        let Some(parent) = lineage.parent else {
            // Root volume. The function's contract is "deepest non-empty
            // ancestor", so a root with zero segments is a contract
            // violation — pinning a new fork here would yield a volume
            // whose every read demand-fetches NotFound.
            if manifest.segment_ulids.is_empty() {
                return Err(IpcError::conflict(format!(
                    "empty ancestor chain: claim source walked to root \
                     {effective_vol}/{effective_snap} with no segments; \
                     cannot pin a new fork to a chain with no data"
                )));
            }
            break;
        };

        let parent_vol_ulid = Ulid::from_string(&parent.volume_ulid).map_err(|e| {
            IpcError::internal(format!(
                "malformed parent volume_ulid in {effective_vol}: {e}"
            ))
        })?;
        let parent_snap_ulid = Ulid::from_string(&parent.snapshot_ulid).map_err(|e| {
            IpcError::internal(format!(
                "malformed parent snapshot_ulid in {effective_vol}: {e}"
            ))
        })?;

        let is_empty = manifest
            .segment_ulids
            .last()
            .is_none_or(|m| *m < parent_snap_ulid);
        if !is_empty {
            break;
        }

        // Advance to parent. Pull it locally if not already there — stage 3
        // may not have reached this far back. Register the pull with the
        // guard so a downstream verification failure cleans it up.
        let parent_dir = volume::resolve_ancestor_dir(&by_id_dir, &parent.volume_ulid);
        if !parent_dir.exists() {
            job.append(ClaimAttachEvent::PullingAncestor {
                vol_ulid: parent_vol_ulid,
            });
            // Skeleton pull reads only `meta/<ulid>.{provenance,pub}` —
            // bucket-wide objects on the warm `coord-ro` credential.
            let parent_store = stores.base_object_store();
            guard.record(parent_vol_ulid);
            let _ = pull_readonly_op(parent_vol_ulid, data_dir, &parent_store, peer).await?;
        }

        info!(
            "[claim {volume}] skipping empty intermediate {effective_vol}; \
             using {parent_vol_ulid}/{parent_snap_ulid}"
        );

        effective_vol = parent_vol_ulid;
        effective_snap = parent_snap_ulid;
    }

    Ok((effective_vol, effective_snap))
}

/// Fetch a handoff snapshot manifest — peer-fetch first when
/// available, S3 otherwise — and verify it under the volume's own
/// key. The signature is checked the same way regardless of which
/// tier served the bytes, so a tampering peer surfaces as a
/// verification error rather than a silent acceptance.
async fn fetch_handoff_manifest(
    data_store: &Arc<dyn ObjectStore>,
    vol_ulid: Ulid,
    snap_ulid: Ulid,
    pubkey: &ed25519_dalek::VerifyingKey,
    peer: Option<&PeerFetchContext>,
) -> Result<elide_core::signing::SnapshotManifest, IpcError> {
    let from_peer = match peer {
        Some(peer_ctx) => {
            peer_ctx
                .client
                .fetch_snapshot_manifest(
                    &peer_ctx.endpoint,
                    &peer_ctx.volume_name,
                    vol_ulid,
                    snap_ulid,
                )
                .await
        }
        None => None,
    };
    let bytes = match from_peer {
        Some(b) => b,
        None => {
            let vd =
                elide_coordinator::volume_data::VolumeData::new(Arc::clone(data_store), vol_ulid);
            vd.snapshots()
                .get_manifest_bytes(snap_ulid)
                .await
                .map_err(|e| {
                    IpcError::store(format!(
                        "fetching snapshot manifest for {vol_ulid}/{snap_ulid}: {e}"
                    ))
                })?
        }
    };
    elide_core::signing::read_snapshot_manifest_from_bytes(&bytes, pubkey, &snap_ulid).map_err(
        |e| {
            IpcError::internal(format!(
                "verifying snapshot manifest {vol_ulid}/{snap_ulid}: {e}"
            ))
        },
    )
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use elide_coordinator::stores::PassthroughStores;
    use elide_core::signing::{
        ParentRef, ProvenanceLineage, VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE,
        build_snapshot_manifest_bytes, encode_hex, load_verifying_key, setup_readonly_identity,
    };
    use elide_core::ulid_mint::UlidMint;
    use object_store::{ObjectStore, memory::InMemory};
    use tempfile::TempDir;

    struct Fork {
        vol: Ulid,
        snap: Ulid,
        signer: Arc<dyn elide_core::segment::SegmentSigner>,
        verifying_key: ed25519_dalek::VerifyingKey,
    }

    fn build_fork(
        data_dir: &std::path::Path,
        vol: Ulid,
        snap: Ulid,
        parent: Option<&Fork>,
    ) -> Fork {
        let dir = data_dir.join("by_id").join(vol.to_string());
        std::fs::create_dir_all(&dir).unwrap();

        let lineage = match parent {
            None => ProvenanceLineage::default(),
            Some(p) => ProvenanceLineage {
                parent: Some(ParentRef {
                    volume_ulid: p.vol.to_string(),
                    snapshot_ulid: p.snap.to_string(),
                    pubkey: p.verifying_key.to_bytes(),
                }),
                extent_index: vec![],
                oci_source: None,
            },
        };

        let signer =
            setup_readonly_identity(&dir, VOLUME_PUB_FILE, VOLUME_PROVENANCE_FILE, &lineage)
                .unwrap();
        let verifying_key = load_verifying_key(&dir, VOLUME_PUB_FILE).unwrap();
        Fork {
            vol,
            snap,
            signer,
            verifying_key,
        }
    }

    async fn upload_handoff_manifest(
        store: &Arc<dyn ObjectStore>,
        fork: &Fork,
        segment_ulids: &[Ulid],
    ) {
        let bytes = build_snapshot_manifest_bytes(fork.signer.as_ref(), segment_ulids);
        elide_coordinator::volume_data::VolumeData::new(Arc::clone(store), fork.vol)
            .snapshots()
            .put_manifest(fork.snap, bytes::Bytes::from(bytes))
            .await
            .unwrap();
    }

    fn passthrough(
        store: Arc<dyn ObjectStore>,
    ) -> Arc<dyn elide_coordinator::stores::ScopedStores> {
        Arc::new(PassthroughStores::new(store))
    }

    #[tokio::test]
    async fn empty_fork_is_skipped() {
        // R(writes) → F1(empty, released). Claim should fork from R, not F1.
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let seg_a = mint.next();
        let seg_b = mint.next();
        let r_snap = mint.next(); // > seg_a, seg_b
        let f1_snap = mint.next(); // > r_snap

        let r = build_fork(data_dir, mint.next(), r_snap, None);
        let f1 = build_fork(data_dir, mint.next(), f1_snap, Some(&r));

        // R's handoff manifest = [seg_a, seg_b].
        upload_handoff_manifest(&store, &r, &[seg_a, seg_b]).await;
        // F1 wrote nothing → manifest inherits R's segments verbatim.
        upload_handoff_manifest(&store, &f1, &[seg_a, seg_b]).await;

        let job = ClaimJob::new();
        let stores = passthrough(store);
        let (vol, snap) = skip_empty_intermediates_impl(
            &job,
            "vol",
            f1.vol,
            f1.snap,
            data_dir,
            &stores,
            None,
            &mut PulledAncestorsGuard::new(data_dir.join("by_id")),
        )
        .await
        .unwrap();
        assert_eq!(vol, r.vol);
        assert_eq!(snap, r.snap);
    }

    #[tokio::test]
    async fn chained_empties_collapse_to_deepest_non_empty() {
        // R(writes) → F1(empty) → F2(empty, released). Claim → R.
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let seg_a = mint.next();
        let r_snap = mint.next();
        let f1_snap = mint.next();
        let f2_snap = mint.next();

        let r = build_fork(data_dir, mint.next(), r_snap, None);
        let f1 = build_fork(data_dir, mint.next(), f1_snap, Some(&r));
        let f2 = build_fork(data_dir, mint.next(), f2_snap, Some(&f1));

        upload_handoff_manifest(&store, &r, &[seg_a]).await;
        upload_handoff_manifest(&store, &f1, &[seg_a]).await;
        upload_handoff_manifest(&store, &f2, &[seg_a]).await;

        let job = ClaimJob::new();
        let stores = passthrough(store);
        let (vol, snap) = skip_empty_intermediates_impl(
            &job,
            "vol",
            f2.vol,
            f2.snap,
            data_dir,
            &stores,
            None,
            &mut PulledAncestorsGuard::new(data_dir.join("by_id")),
        )
        .await
        .unwrap();
        assert_eq!(vol, r.vol);
        assert_eq!(snap, r.snap);
    }

    #[tokio::test]
    async fn non_empty_fork_is_not_skipped() {
        // R(writes) → F1(writes, released). Claim should fork from F1.
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let seg_a = mint.next();
        let r_snap = mint.next();
        let seg_b = mint.next(); // > r_snap → owned by F1
        let f1_snap = mint.next();

        let r = build_fork(data_dir, mint.next(), r_snap, None);
        let f1 = build_fork(data_dir, mint.next(), f1_snap, Some(&r));

        upload_handoff_manifest(&store, &r, &[seg_a]).await;
        upload_handoff_manifest(&store, &f1, &[seg_a, seg_b]).await;

        let job = ClaimJob::new();
        let stores = passthrough(store);
        let (vol, snap) = skip_empty_intermediates_impl(
            &job,
            "vol",
            f1.vol,
            f1.snap,
            data_dir,
            &stores,
            None,
            &mut PulledAncestorsGuard::new(data_dir.join("by_id")),
        )
        .await
        .unwrap();
        assert_eq!(vol, f1.vol);
        assert_eq!(snap, f1.snap);
    }

    #[tokio::test]
    async fn missing_provenance_now_errors_loud() {
        // Inverse of the old (#426) tolerance test. `early_rebind`
        // publishes `volume.provenance` alongside `volume.pub` *before*
        // `mark_claimed`, so the on-disk shape "volume.pub present,
        // volume.provenance absent" can no longer be produced by any
        // normal flow. If a reader hits it, the bytes have been corrupted
        // or hand-edited — fail loud rather than silently treating it as a
        // root volume (which would lose ancestor data).
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let corrupt_vol = mint.next();
        let snap = mint.next();
        let dir = data_dir.join("by_id").join(corrupt_vol.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        elide_core::signing::generate_keypair(
            &dir,
            elide_core::signing::VOLUME_KEY_FILE,
            VOLUME_PUB_FILE,
        )
        .unwrap();
        // Note: deliberately *no* volume.provenance — simulates corruption.

        let job = ClaimJob::new();
        let stores = passthrough(store);
        let err = skip_empty_intermediates_impl(
            &job,
            "vol",
            corrupt_vol,
            snap,
            data_dir,
            &stores,
            None,
            &mut PulledAncestorsGuard::new(data_dir.join("by_id")),
        )
        .await
        .expect_err("post-(C) invariant: every fork has provenance; absence is corruption");
        assert!(
            err.message.contains("provenance"),
            "error should point at the missing provenance: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn crashed_claim_leaves_non_root_provisional_provenance() {
        // #428 crash window. Drive the real `early_rebind` (stage 1 of a
        // claim) and simulate a crash by *not* running `finalize`.
        //
        // The invariant under test: `early_rebind` writes a provisional
        // provenance whose `ParentRef` points at the released volume. A
        // crash here leaves an *empty fork with a real parent*, not an
        // empty root, so the documented recovery — `claim --force` over
        // the partial fork, which takes over its `ParentRef` — lands on
        // the released volume's data. The takeover itself is covered in
        // `force_claim::tests`.
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        // ── Released volume with real data: `vol_x` (a root) holding one
        // segment, published to S3, with `names/vol` Released and pointing
        // at it via a normal handoff snapshot.
        let mut mint = UlidMint::new(Ulid::nil());
        let seg_a = mint.next();
        let snap_x = mint.next();
        let vol_x = mint.next();
        let fork_x = build_fork(data_dir, vol_x, snap_x, None);
        let vx_dir = data_dir.join("by_id").join(vol_x.to_string());
        let vx_vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), vol_x);
        elide_coordinator::upload::upload_volume_pub_initial(&vx_dir, &vx_vd)
            .await
            .unwrap();
        elide_coordinator::upload::upload_volume_provenance_initial(&vx_dir, &vx_vd)
            .await
            .unwrap();
        upload_handoff_manifest(&store, &fork_x, &[seg_a]).await;

        let mut rec = elide_core::name_record::NameRecord::live_minimal(vol_x, 4096);
        rec.state = elide_core::name_record::NameState::Released;
        rec.coordinator_id = None;
        rec.handoff_snapshot = Some(snap_x);
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        // ── Claiming coordinator.
        let coord_b_dir = TempDir::new().unwrap();
        let identity = Arc::new(
            elide_coordinator::identity::CoordinatorIdentity::load_or_generate(coord_b_dir.path())
                .unwrap(),
        );
        let stores = passthrough(Arc::clone(&store));

        // ── Stage 1 of the claim, for real. `early_rebind` mints the fork,
        // writes the provisional provenance, uploads it, and rebinds the
        // name. Then we *stop* — the crash is the absence of `finalize`.
        let ctx = ClaimContext {
            core: crate::inbound::CoordinatorCore {
                data_dir: Arc::new(data_dir.to_path_buf()),
                stores: Arc::clone(&stores),
                identity: Arc::clone(&identity),
            },
            claim_registry: new_registry(),
            prefetch_tracker: elide_coordinator::new_prefetch_tracker(),
        };
        let mut orch = ClaimOrchestrator::new(ClaimJob::new(), "vol".into(), vol_x, snap_x, ctx);
        orch.early_rebind().await.expect("early_rebind succeeds");
        let partial_vol = orch
            .new_fork
            .as_ref()
            .expect("early_rebind set the new fork skeleton")
            .vol_ulid;
        drop(orch); // simulate the crash: `finalize` never runs.

        // Structural invariant: the partial fork's provenance is NOT a
        // root — it already names the released volume as its parent.
        let partial_dir = data_dir.join("by_id").join(partial_vol.to_string());
        let lineage = elide_core::signing::read_lineage_verifying_signature(
            &partial_dir,
            VOLUME_PUB_FILE,
            VOLUME_PROVENANCE_FILE,
        )
        .unwrap();
        let parent = lineage
            .parent
            .expect("provisional provenance must carry a ParentRef, not be root-shape");
        assert_eq!(parent.volume_ulid, vol_x.to_string());
        assert_eq!(parent.snapshot_ulid, snap_x.to_string());
    }

    #[tokio::test]
    async fn root_fork_with_segments_is_returned() {
        // Released name points at a non-empty root (no parent). Returns
        // the root as-is — no ancestor to skip to, contract satisfied.
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let seg_a = mint.next();
        let r_snap = mint.next();
        let r = build_fork(data_dir, mint.next(), r_snap, None);
        upload_handoff_manifest(&store, &r, &[seg_a]).await;

        let job = ClaimJob::new();
        let stores = passthrough(store);
        let (vol, snap) = skip_empty_intermediates_impl(
            &job,
            "vol",
            r.vol,
            r.snap,
            data_dir,
            &stores,
            None,
            &mut PulledAncestorsGuard::new(data_dir.join("by_id")),
        )
        .await
        .unwrap();
        assert_eq!(vol, r.vol);
        assert_eq!(snap, r.snap);
    }

    #[tokio::test]
    async fn empty_root_with_no_parent_errors() {
        // Released name points at a root volume that has no segments and
        // no parent — pinning a new fork here would produce a volume
        // whose every read demand-fetches NotFound. The contract is
        // "non-empty ancestor", so this is rejected at the claim layer.
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let r_snap = mint.next();
        let r = build_fork(data_dir, mint.next(), r_snap, None);
        upload_handoff_manifest(&store, &r, &[]).await;

        let job = ClaimJob::new();
        let stores = passthrough(store);
        let err = skip_empty_intermediates_impl(
            &job,
            "vol",
            r.vol,
            r.snap,
            data_dir,
            &stores,
            None,
            &mut PulledAncestorsGuard::new(data_dir.join("by_id")),
        )
        .await
        .expect_err("empty root violates the non-empty-ancestor contract");
        assert_eq!(err.kind, elide_core::ipc::IpcErrorKind::Conflict);
        assert!(
            err.message.contains("empty ancestor chain"),
            "error should name the empty-chain condition: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn chain_of_empties_to_empty_root_errors() {
        // R(empty) → F1(empty) → F2(empty, released). The walk skips
        // F2 → F1 → R, then finds R itself has no segments. Reject
        // rather than silently pin the new fork to a dead chain.
        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let r_snap = mint.next();
        let f1_snap = mint.next();
        let f2_snap = mint.next();

        let r = build_fork(data_dir, mint.next(), r_snap, None);
        let f1 = build_fork(data_dir, mint.next(), f1_snap, Some(&r));
        let f2 = build_fork(data_dir, mint.next(), f2_snap, Some(&f1));

        upload_handoff_manifest(&store, &r, &[]).await;
        upload_handoff_manifest(&store, &f1, &[]).await;
        upload_handoff_manifest(&store, &f2, &[]).await;

        let job = ClaimJob::new();
        let stores = passthrough(store);
        let err = skip_empty_intermediates_impl(
            &job,
            "vol",
            f2.vol,
            f2.snap,
            data_dir,
            &stores,
            None,
            &mut PulledAncestorsGuard::new(data_dir.join("by_id")),
        )
        .await
        .expect_err("chain of empties terminating in empty root must error");
        assert_eq!(err.kind, elide_core::ipc::IpcErrorKind::Conflict);
        assert!(
            err.message.contains("empty ancestor chain"),
            "error should name the empty-chain condition: {}",
            err.message
        );
        // The error should name the root we reached, not the released vol.
        assert!(
            err.message.contains(&r.vol.to_string()),
            "error should identify the empty root: {}",
            err.message
        );
    }

    #[tokio::test]
    async fn claim_bucket_op_routes_only_through_writer_and_base_ro() {
        // The bucket-side claim never touches `by_id/`. It reads
        // names/<name> (coord-ro via name_claims_ro-equivalent
        // reads), writes the name flip (coord-rw), and emits an
        // event (coord-rw + coord-ro reads). Mirror what
        // `start_claim` does at its store-pick site (`stores.writer()`
        // + `stores.event_journal()` + `stores.name_claims()`) and
        // assert the recorded role set is exactly `{Writer,
        // BaseObjectStore}` — never volume-rw/volume-ro/etc, which
        // would silently 403 against names/<name>.
        use elide_coordinator::stores::{RecordingStores, RoleCall, ScopedStores};

        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        // names/vol = Released, no local fork → claim_volume_bucket_op
        // takes the MustClaimFresh path (no key shadow / reconcile
        // setup needed).
        let mut rec = elide_core::name_record::NameRecord::live_minimal(Ulid::new(), 1 << 30);
        rec.state = elide_core::name_record::NameState::Released;
        rec.coordinator_id = None;
        rec.handoff_snapshot = Some(Ulid::new());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let coord_dir = TempDir::new().unwrap();
        let identity = Arc::new(
            elide_coordinator::identity::CoordinatorIdentity::load_or_generate(coord_dir.path())
                .unwrap(),
        );

        let inner: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(Arc::clone(&store)));
        let recording = RecordingStores::wrap(inner);
        // Mirror start_claim's three picks.
        let writer = recording.writer();
        let journal = recording.event_journal();
        let claims = recording.name_claims();

        let reply = claim_volume_bucket_op(
            "vol",
            data_dir,
            &writer,
            journal.as_ref(),
            claims.as_ref(),
            &identity,
        )
        .await
        .expect("claim must surface MustClaimFresh, not error");
        assert!(
            matches!(reply, ClaimReply::MustClaimFresh { .. }),
            "no local fork → MustClaimFresh; got {reply:?}"
        );

        let calls = recording.calls();
        assert!(!calls.is_empty(), "expected at least one role call");
        for call in &calls {
            assert!(
                matches!(call, RoleCall::Writer | RoleCall::BaseObjectStore),
                "claim's bucket side must only mint coord-rw / coord-ro; \
                 saw {call:?} in {calls:?}"
            );
        }
    }
    #[tokio::test]
    async fn early_rebind_is_control_plane_only() {
        // Claim-first ordering: everything `early_rebind` does before
        // `mark_claimed` must be control-plane (`coord-ro` / `coord-rw`)
        // plus the new fork's own uploads. In particular the released
        // volume's identity key comes from `meta/<released>.pub`, never
        // a `by_id/<released>/` read — no volume-ro/volume-rw credential
        // may be minted for the released (foreign) volume.
        use elide_coordinator::stores::{RecordingStores, RoleCall};

        let tmp = TempDir::new().unwrap();
        let data_dir = tmp.path();
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());

        let mut mint = UlidMint::new(Ulid::nil());
        let handoff = mint.next();
        let released = mint.next();

        // Released volume's identity key, published at meta/<released>.pub.
        let released_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let pub_hex = encode_hex(&released_key.verifying_key().to_bytes());
        store
            .put(
                &object_store::path::Path::from(elide_core::store_keys::meta_pub_key(released)),
                object_store::PutPayload::from(format!("{pub_hex}\n").into_bytes()),
            )
            .await
            .unwrap();

        // names/vol: Released with a handoff pin, claimable.
        let mut rec = elide_core::name_record::NameRecord::live_minimal(released, 1 << 30);
        rec.state = elide_core::name_record::NameState::Released;
        rec.coordinator_id = None;
        rec.handoff_snapshot = Some(handoff);
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let coord_dir = TempDir::new().unwrap();
        let identity = Arc::new(
            elide_coordinator::identity::CoordinatorIdentity::load_or_generate(coord_dir.path())
                .unwrap(),
        );
        let recording = RecordingStores::wrap(passthrough(Arc::clone(&store)));
        let ctx = ClaimContext {
            core: crate::inbound::CoordinatorCore {
                data_dir: Arc::new(data_dir.to_path_buf()),
                stores: recording.clone(),
                identity,
            },
            claim_registry: new_registry(),
            prefetch_tracker: elide_coordinator::new_prefetch_tracker(),
        };
        let mut orch =
            ClaimOrchestrator::new(ClaimJob::new(), "vol".to_owned(), released, handoff, ctx);
        orch.early_rebind().await.expect("early rebind succeeds");

        // No by_id credential for the released volume; no volume-ro at all.
        let calls = recording.calls();
        for call in &calls {
            assert!(
                !matches!(call, RoleCall::ReadVolume(_)),
                "early_rebind must not mint volume-ro; saw {call:?} in {calls:?}"
            );
            assert!(
                !matches!(call, RoleCall::VolumeRw(v) if *v == released),
                "early_rebind must not mint volume-rw for the released \
                 volume; saw {call:?} in {calls:?}"
            );
        }

        // The name is rebound to the new fork...
        let (rebound, _) = elide_coordinator::name_store::read_name_record(&store, "vol")
            .await
            .unwrap()
            .unwrap();
        assert_ne!(rebound.vol_ulid, released);
        assert_eq!(rebound.state, elide_core::name_record::NameState::Stopped);

        // ...and the provisional provenance carries the control-plane
        // anchors: parent pubkey from meta/.
        let new_dir = data_dir.join("by_id").join(rebound.vol_ulid.to_string());
        let lineage = elide_core::signing::read_lineage_verifying_signature(
            &new_dir,
            VOLUME_PUB_FILE,
            VOLUME_PROVENANCE_FILE,
        )
        .unwrap();
        let parent = lineage.parent.expect("provisional parent ref");
        assert_eq!(parent.volume_ulid, released.to_string());
        assert_eq!(parent.snapshot_ulid, handoff.to_string());
        assert_eq!(parent.pubkey, released_key.verifying_key().to_bytes());
    }
}
