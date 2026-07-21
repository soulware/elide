//! `volume claim --force`: ownership-first recovery of a name whose
//! owner is unreachable.
//!
//! Design: `docs/design/mint-volume-attestation.md` § *Recovery is a
//! claim* and `docs/design/force-release-fencing.md`. The forced CAS
//! on `names/<name>` is the fence point; everything the claimant
//! reads from the dead fork's prefix happens after it, anchored on
//! the now-live new fork. The dead fork's prefix is never written:
//! the head delta (live segments above the basis manifest) is
//! *re-owned* — each segment's index verified under the dead fork's
//! key, re-signed with the new fork's key, copied under the new
//! fork's prefix with its ULID retained, and written into the fork's
//! local read state (`index/<u>.idx` + `cache/<u>.{body,present}`).
//!
//! Mirrors the structure of [`crate::claim`]: a [`ClaimJob`] in the
//! shared registry, a staged orchestrator, progress via
//! `ClaimAttachEvent`.
//!
//! Crash recovery: the provisional provenance and the new fork's
//! HEAD (written before any body copy) make the flow resumable. A
//! re-run on the same host detects the partial fork and continues; a
//! claimant on another host falls back to the `events/<name>`
//! journal's prior bindings to source head-delta segments a crashed
//! intermediate never finished copying.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ed25519_dalek::{SigningKey, VerifyingKey};
use tracing::{error, info, warn};
use ulid::Ulid;

use crate::claim::{ClaimContext, ClaimJob, ClaimJobState};
use crate::inbound::{await_prefetch_op, pull_readonly_op};
use elide_coordinator::ipc::{ClaimAttachEvent, ClaimStartReply, IpcError};
use elide_coordinator::lifecycle::ObservedRecord;
use elide_coordinator::register_prefetch_or_get;
use elide_coordinator::segment_head::{SegmentHead, live_set};
use elide_coordinator::volume_state::{CLAIMING_FILE, STOPPED_FILE};
use elide_core::name_record::{Lifecycle, TransitionCheck};
use elide_core::signing::{
    ParentRef, ProvenanceLineage, VOLUME_KEY_FILE, VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE,
    generate_keypair, load_verifying_key, read_lineage_verifying_signature, write_provenance,
};

/// How many prior bindings of the name to consider when sourcing
/// head-delta segments a crashed intermediate claimant never finished
/// copying.
const JOURNAL_SOURCE_LIMIT: usize = 8;

/// Synchronous entry point for `Request::ClaimStart { force: true }`.
///
/// Observes `names/<name>`, validates the record is force-claimable,
/// registers a [`ClaimJob`], and spawns the orchestrator. Returns
/// `Claiming { released_vol_ulid }` carrying the dead fork's ULID (or
/// the partial fork's, when resuming).
pub(crate) async fn start_force_claim(
    volume: String,
    ctx: ClaimContext,
) -> Result<ClaimStartReply, IpcError> {
    let base_ro = ctx.core.stores.base_object_store();
    let observed = elide_coordinator::name_store::read_name_record(&base_ro, &volume)
        .await
        .map_err(|e| IpcError::store(format!("reading names/{volume}: {e}")))?;
    let Some((record, version)) = observed else {
        return Err(IpcError::not_found(format!(
            "volume '{volume}' not found in store"
        )));
    };
    let observed = ObservedRecord { record, version };

    match observed
        .record
        .state
        .check_transition(Lifecycle::ForceClaim)
    {
        TransitionCheck::Proceed => {}
        TransitionCheck::Reroute => {
            return Err(IpcError::conflict(format!(
                "name '{volume}' is released — no owner to override; claim it \
                 normally: elide volume claim {volume}"
            )));
        }
        TransitionCheck::Idempotent | TransitionCheck::Refuse => {
            return Err(IpcError::conflict(format!(
                "name '{volume}' is readonly; nothing to claim"
            )));
        }
    }

    // Self-owned records: a forced claim is for a *dead other* owner.
    // The one exception is our own partial force-claim fork (forced
    // CAS landed, re-own/finalize did not) — resume it.
    let ours =
        observed.record.coordinator_id.as_deref() == Some(ctx.core.identity.coordinator_id_str());
    let bound_dir =
        elide_coordinator::volume_state::fork_dir(&ctx.core.data_dir, observed.record.vol_ulid);
    let resume =
        ours && bound_dir.join(VOLUME_KEY_FILE).exists() && !bound_dir.join("wal").exists();
    if ours && !resume {
        return Err(IpcError::conflict(format!(
            "name '{volume}' is already owned by this coordinator; \
             use: elide volume start {volume}"
        )));
    }

    let reply_vol = observed.record.vol_ulid;
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
        let orch = ForceClaimOrchestrator::new(job.clone(), volume, observed, resume, ctx);
        match orch.run().await {
            Ok(()) => {
                job.append(ClaimAttachEvent::Done);
                job.finish(ClaimJobState::Done);
            }
            Err(e) => job.finish(ClaimJobState::Failed(e)),
        }
    });

    Ok(ClaimStartReply::Claiming {
        released_vol_ulid: reply_vol,
    })
}

/// The new fork being established (or resumed).
struct ForkSkeleton {
    vol_ulid: Ulid,
    dir: PathBuf,
    signing_key: SigningKey,
}

impl ForkSkeleton {
    /// Segment-signer view of the fork key (the trait object
    /// `resign_segment_head` takes).
    fn signer(&self) -> Result<Arc<dyn elide_core::segment::SegmentSigner>, IpcError> {
        let (signer, _) = elide_core::signing::signer_from_bytes(&self.signing_key.to_bytes())
            .map_err(|e| IpcError::internal(format!("deriving segment signer: {e}")))?;
        Ok(signer)
    }
}

/// Drive one forced claim to completion. Stages run in order from
/// [`Self::run`]; each consumes earlier outputs from `self`.
struct ForceClaimOrchestrator {
    job: Arc<ClaimJob>,
    volume: String,
    /// The record + version observed at start: the dead fork's
    /// binding (fresh) or our own partial fork's (resume).
    observed: ObservedRecord,
    resume: bool,
    ctx: ClaimContext,
    by_id_dir: PathBuf,

    // Stage outputs.
    /// The dead fork whose head delta is being re-owned. Fresh: the
    /// observed binding. Resume: the newest prior binding from the
    /// `events/<name>` journal.
    source_vol: Option<Ulid>,
    fork: Option<ForkSkeleton>,
    /// Effective basis resolved from the dead fork's data plane
    /// (`snapshots/LATEST`), or the record-hint basis on resume.
    /// `None` = the dead fork never published a `User` manifest.
    basis: Option<Option<Ulid>>,
    /// Head-delta segments re-owned into the new fork.
    reowned: usize,
}

impl ForceClaimOrchestrator {
    fn new(
        job: Arc<ClaimJob>,
        volume: String,
        observed: ObservedRecord,
        resume: bool,
        ctx: ClaimContext,
    ) -> Self {
        let by_id_dir = ctx.core.data_dir.join("by_id");
        Self {
            job,
            volume,
            observed,
            resume,
            ctx,
            by_id_dir,
            source_vol: None,
            fork: None,
            basis: None,
            reowned: 0,
        }
    }

    async fn run(mut self) -> Result<(), IpcError> {
        self.resolve_source().await?;
        self.pull_chain().await?;
        self.rebind().await?;
        self.re_own().await?;
        self.finalize().await?;
        self.surface_prefetch().await;
        Ok(())
    }

    /// Stage 1. Resolve the dead fork. Fresh claims take it straight
    /// from the observed record. Resumes recover it from the
    /// `events/<name>` journal: the newest binding that is not the
    /// partial fork itself.
    async fn resolve_source(&mut self) -> Result<(), IpcError> {
        if !self.resume {
            self.source_vol = Some(self.observed.record.vol_ulid);
            return Ok(());
        }
        let prior = self.prior_bindings().await?;
        let Some(dead) = prior.first().copied() else {
            return Err(IpcError::not_found(format!(
                "resuming forced claim of '{}': no prior binding in \
                 events/{} to re-own from",
                self.volume, self.volume
            )));
        };
        self.source_vol = Some(dead);
        Ok(())
    }

    /// Prior bindings of this name, newest first, excluding the
    /// observed (current) binding. Source of truth for "which fork
    /// held this name before" — survives any chain of crashed
    /// claimants because every claim/force-claim appends here.
    async fn prior_bindings(&self) -> Result<Vec<Ulid>, IpcError> {
        let journal = self.ctx.core.stores.event_journal_ro();
        let events = journal
            .recent(&self.volume, JOURNAL_SOURCE_LIMIT * 2)
            .await
            .map_err(|e| IpcError::store(format!("reading events/{}: {e}", self.volume)))?;
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for ev in events {
            // `recent` is newest-first.
            if ev.vol_ulid != self.observed.record.vol_ulid && seen.insert(ev.vol_ulid) {
                out.push(ev.vol_ulid);
                if out.len() >= JOURNAL_SOURCE_LIMIT {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Stage 2. Pull the dead fork's skeleton chain (`meta/*`,
    /// `coord-ro` — control-plane, allowed before the rebind).
    async fn pull_chain(&mut self) -> Result<(), IpcError> {
        use elide_core::volume::resolve_ancestor_dir;

        let source = self.source_vol.expect("resolve_source ran");
        let mut next: Option<Ulid> = Some(source);
        while let Some(vol_ulid) = next.take() {
            let dir = resolve_ancestor_dir(&self.by_id_dir, &vol_ulid.to_string());
            if dir.exists() {
                break;
            }
            self.job
                .append(ClaimAttachEvent::PullingAncestor { vol_ulid });
            let store = self.ctx.core.stores.base_object_store();
            let reply = pull_readonly_op(vol_ulid, &self.ctx.core.data_dir, &store, None).await?;
            next = reply.parent;
        }
        Ok(())
    }

    /// Stage 3. Establish the new fork and force the rebind — the
    /// fence point.
    ///
    /// Fresh: mint a keypair, sign a provisional provenance whose
    /// trust anchors are control-plane only (basis hint from the
    /// record's `latest_snapshot`, parent identity from the pulled
    /// skeleton — itself sourced from `meta/`), upload
    /// `volume.{pub,provenance}`, then CAS the record conditioned on
    /// the version observed at start. Resume: load the partial fork
    /// from disk; the record already points at it.
    async fn rebind(&mut self) -> Result<(), IpcError> {
        if self.resume {
            let vol_ulid = self.observed.record.vol_ulid;
            let dir = self.by_id_dir.join(vol_ulid.to_string());
            let key_bytes = std::fs::read(dir.join(VOLUME_KEY_FILE))
                .map_err(|e| IpcError::internal(format!("reading partial fork key: {e}")))?;
            let arr: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
                IpcError::internal("partial fork volume.key is not a 32-byte Ed25519 key")
            })?;
            let signing_key = SigningKey::from_bytes(&arr);
            info!(
                "[force-claim {}] resuming partial fork {vol_ulid}",
                self.volume
            );
            std::fs::write(dir.join(CLAIMING_FILE), "")
                .map_err(|e| IpcError::internal(format!("writing volume.claiming: {e}")))?;
            self.write_volume_toml(&dir, vol_ulid)?;
            self.fork = Some(ForkSkeleton {
                vol_ulid,
                dir,
                signing_key,
            });
            return Ok(());
        }

        let source = self.source_vol.expect("resolve_source ran");
        let source_dir =
            elide_core::volume::resolve_ancestor_dir(&self.by_id_dir, &source.to_string());
        let source_lineage =
            read_lineage_verifying_signature(&source_dir, VOLUME_PUB_FILE, VOLUME_PROVENANCE_FILE)
                .map_err(|e| IpcError::internal(format!("reading provenance for {source}: {e}")))?;
        let source_pubkey = load_verifying_key(&source_dir, VOLUME_PUB_FILE)
            .map_err(|e| IpcError::internal(format!("loading volume.pub for {source}: {e}")))?;

        let new_vol_ulid = Ulid::new();
        let new_dir = self.by_id_dir.join(new_vol_ulid.to_string());
        // Marker before keypair: discovery admits any dir carrying
        // `volume.key`, and `volume.claiming` is what keeps this
        // half-built skeleton out of supervision until `finalize`
        // removes it — so no discoverable instant exists without it.
        std::fs::create_dir_all(&new_dir)
            .map_err(|e| IpcError::internal(format!("creating fork dir: {e}")))?;
        std::fs::write(new_dir.join(CLAIMING_FILE), "")
            .map_err(|e| IpcError::internal(format!("writing volume.claiming: {e}")))?;
        let signing_key = generate_keypair(&new_dir, VOLUME_KEY_FILE, VOLUME_PUB_FILE)
            .map_err(|e| IpcError::internal(format!("generating keypair: {e}")))?;
        elide_coordinator::key_shadow::write(
            &self.ctx.core.data_dir,
            new_vol_ulid,
            &signing_key.to_bytes(),
        )
        .map_err(|e| IpcError::internal(format!("writing key shadow: {e}")))?;

        // Provisional ParentRef, control-plane anchors only
        // (claim-first). With a basis hint the new fork is a child of
        // the dead fork at that snapshot. Without one the dead fork
        // has no manifest to reference: the new fork takes over the
        // dead fork's own ParentRef and extent sources, and the dead
        // fork's content arrives via the head-delta re-own instead.
        let parent_pin = self
            .observed
            .record
            .latest_snapshot
            .map(|snap| format!("{source}/{snap}"));
        let provisional = match self.observed.record.latest_snapshot {
            Some(basis) => ProvenanceLineage::fork(ParentRef {
                volume_ulid: source.to_string(),
                snapshot_ulid: basis.to_string(),
                pubkey: source_pubkey.to_bytes(),
            }),
            // Source is read transiently during re_own to recover its
            // unsnapshotted tail but is not F's content parent (P is, or
            // none); the grant authorises the read, finalize collapses the
            // `Recovering` lineage to its steady-state shape.
            None => ProvenanceLineage::from_parts(
                source_lineage.parent().cloned(),
                source_lineage.extent_index().to_vec(),
                vec![source],
            ),
        };
        write_provenance(&new_dir, &signing_key, VOLUME_PROVENANCE_FILE, &provisional)
            .map_err(|e| IpcError::internal(format!("writing provisional provenance: {e}")))?;

        let meta_store = self.ctx.core.stores.writer();
        let (pub_result, prov_result) = tokio::join!(
            elide_coordinator::upload::upload_volume_pub_initial(
                &self.ctx.core.data_dir,
                new_vol_ulid,
                &meta_store
            ),
            elide_coordinator::upload::upload_volume_provenance_initial(
                &self.ctx.core.data_dir,
                new_vol_ulid,
                &meta_store
            ),
        );
        pub_result.map_err(|e| IpcError::store(format!("uploading volume.pub: {e:#}")))?;
        prov_result
            .map_err(|e| IpcError::store(format!("uploading provisional provenance: {e:#}")))?;

        // The fence: forced CAS conditioned on the record observed at
        // start. "Force" skips the ownership refusal, not the
        // precondition — concurrent forced claims arbitrate here.
        use elide_coordinator::lifecycle::MarkClaimedForceOutcome;
        let outcome = self
            .ctx
            .core
            .stores
            .name_claims()
            .mark_claimed_force(
                &self.volume,
                self.ctx.core.identity.coordinator_id_str(),
                self.ctx.core.identity.hostname(),
                new_vol_ulid,
                parent_pin,
                &self.observed,
            )
            .await
            .map_err(|e| IpcError::store(format!("forced rebind of names/{}: {e}", self.volume)))?;
        let displaced = match outcome {
            MarkClaimedForceOutcome::Claimed {
                displaced_coordinator_id,
            } => displaced_coordinator_id,
            MarkClaimedForceOutcome::Raced => {
                let _ = std::fs::remove_dir_all(&new_dir);
                return Err(IpcError::conflict(format!(
                    "names/{} changed since it was observed — either a \
                     concurrent forced claim won or the owner is alive; \
                     re-check and retry",
                    self.volume
                )));
            }
        };
        info!(
            "[force-claim {}] fence: names/{} -> {new_vol_ulid} (displaced {})",
            self.volume,
            self.volume,
            displaced.as_deref().unwrap_or("<unowned>")
        );
        self.ctx
            .core
            .stores
            .event_journal()
            .emit_best_effort(
                self.ctx.core.identity.as_ref(),
                &self.volume,
                elide_core::volume_event::EventKind::ForceClaimed {
                    source_vol_ulid: source,
                    displaced_coordinator_id: displaced,
                },
                new_vol_ulid,
            )
            .await;

        // The new fork is the `owned` anchor for the re-own reads that
        // follow; the discharge possession proof loads the anchor's
        // name and key from its dir, so volume.toml lands before the
        // first anchored read.
        self.write_volume_toml(&new_dir, new_vol_ulid)?;
        self.fork = Some(ForkSkeleton {
            vol_ulid: new_vol_ulid,
            dir: new_dir,
            signing_key,
        });
        Ok(())
    }

    /// Write the fork's `volume.toml` (name + size from the observed
    /// record — a forced claim continues the same logical volume
    /// identity).
    fn write_volume_toml(&self, dir: &Path, vol_ulid: Ulid) -> Result<(), IpcError> {
        elide_core::config::VolumeConfig {
            ulid: Some(vol_ulid),
            name: Some(self.volume.clone()),
            size: Some(self.observed.record.size),
            ublk: elide_coordinator::ublk_sweep::ublk_capable()
                .then(elide_core::config::UblkConfig::default),
            lazy: None,
        }
        .write(dir)
        .map_err(|e| IpcError::internal(format!("writing volume.toml: {e}")))
    }

    /// Stage 4. Re-own the dead fork's head delta.
    ///
    /// Resolves the pin basis from the dead fork's data plane
    /// (`snapshots/LATEST` → manifest), then reads the dead fork's
    /// HEAD **once**: the forced CAS is the cut, and this single read
    /// defines the claim set — `delta = live(frontier, HEAD) −
    /// basis`, where the frontier is the newest seal of either kind
    /// (HEAD's anchor names the stop-snapshot a clean `stop` leaves
    /// behind, which `LATEST` — user manifests only — does not).
    /// The pin stays on the stable user manifest: stop-snapshots are
    /// ephemeral, so segments they cover are copied, not referenced
    /// through lineage. Anything the displaced owner publishes after
    /// the cut is a post-displacement write and is excluded, the same
    /// policy as its undrained WAL. Writes the new fork's HEAD
    /// *first* (the durable intent a resumer reads), then copies each
    /// segment: GET, verify under the source's key, re-sign the
    /// header with the new fork's key, PUT under the new prefix with
    /// the ULID retained. A final advisory re-read of the dead HEAD
    /// detects an owner that was alive all along — logged loudly; the
    /// claim proceeds, since the fence has already landed. Each copied
    /// segment is also written into the fork's local read state
    /// (`index/`, `cache/`) so the daemon's lbamap rebuild sees it.
    async fn re_own(&mut self) -> Result<(), IpcError> {
        let source = self.source_vol.expect("resolve_source ran");
        let fork_vol = self.fork.as_ref().expect("rebind ran").vol_ulid;

        let source_ro = self.ctx.core.stores.read_volume(&fork_vol, &source);
        let source_vd =
            elide_coordinator::volume_data::VolumeData::new(Arc::clone(&source_ro), source);
        let source_dir =
            elide_core::volume::resolve_ancestor_dir(&self.by_id_dir, &source.to_string());
        let source_pubkey = load_verifying_key(&source_dir, VOLUME_PUB_FILE)
            .map_err(|e| IpcError::internal(format!("loading volume.pub for {source}: {e}")))?;

        // Effective basis from the data plane. The record's
        // `latest_snapshot` hint is best-effort and may lag the
        // owner's last published manifest; LATEST is authoritative.
        let basis = match source_vd.snapshots().read_latest().await {
            Ok(opt) => opt.map(|(u, _)| u),
            Err(e) => {
                return Err(IpcError::store(format!(
                    "reading snapshots/LATEST for {source}: {e}"
                )));
            }
        };
        let manifest_segments: BTreeSet<Ulid> = match basis {
            Some(snap) => match source_vd
                .snapshots()
                .get_manifest(snap, &source_pubkey)
                .await
            {
                Ok(m) => m.segment_ulids.into_iter().collect(),
                Err(elide_coordinator::volume_data::SnapshotsError::Get(
                    object_store::Error::NotFound { .. },
                )) => BTreeSet::new(),
                Err(e) => {
                    return Err(IpcError::store(format!(
                        "reading basis manifest {source}/{snap}: {e}"
                    )));
                }
            },
            None => BTreeSet::new(),
        };
        self.basis = Some(basis);

        // The cut: one post-fence read of the dead fork's HEAD
        // defines the claim set.
        let source_head = source_vd
            .head()
            .read()
            .await
            .map_err(|e| IpcError::store(format!("reading HEAD for {source}: {e}")))?;

        // Frontier: the newest seal of either kind. A clean `stop`
        // truncates HEAD to empty anchored at its stop-snapshot;
        // computing the claim set over the basis manifest alone would
        // drop everything that seal covered.
        let frontier_segments: BTreeSet<Ulid> = match source_head.anchor {
            Some(anchor) if basis.is_none_or(|b| anchor > b) => {
                match fetch_manifest_any_kind(&source_vd, anchor, &source_pubkey).await? {
                    Some(m) => m.segment_ulids.into_iter().collect(),
                    None => {
                        warn!(
                            "[force-claim {}] HEAD anchor {anchor} has no manifest \
                             under {source}; claim set falls back to the basis",
                            self.volume
                        );
                        manifest_segments.clone()
                    }
                }
            }
            _ => manifest_segments.clone(),
        };
        let head_delta: BTreeSet<Ulid> = live_set(&frontier_segments, &source_head)
            .into_iter()
            .filter(|u| !manifest_segments.contains(u))
            .collect();

        if !head_delta.is_empty() {
            // Durable intent first: a resumer reads the new fork's
            // HEAD to learn which ULIDs must exist under it. It is
            // written before the copies, so it cannot serve as the
            // done-set — per-object existence inside `re_own_segment`
            // is what makes a resume skip work.
            let fork_vd = self.ctx.core.stores.volume_data(&fork_vol);
            let mut intent = SegmentHead::empty(basis);
            intent.added = head_delta.clone();
            fork_vd
                .head()
                .put(&intent)
                .await
                .map_err(|e| IpcError::store(format!("writing HEAD for {fork_vol}: {e}")))?;

            for seg_ulid in &head_delta {
                self.re_own_segment(*seg_ulid, source, &source_pubkey)
                    .await?;
            }
        }

        // Advisory liveness check: a dead owner's HEAD cannot move.
        match source_vd.head().read().await {
            Ok(h) if h != source_head => {
                error!(
                    "[force-claim {}] HEAD of {source} changed during the \
                     claim — the displaced owner appears to be alive; its \
                     post-displacement writes are lost",
                    self.volume
                );
            }
            Ok(_) => {}
            Err(e) => {
                warn!(
                    "[force-claim {}] re-reading HEAD for {source}: {e}; \
                     skipping liveness check",
                    self.volume
                );
            }
        }

        info!(
            "[force-claim {}] re-owned {} head-delta segment(s) into \
             {fork_vol} (basis {})",
            self.volume,
            head_delta.len(),
            basis.map(|b| b.to_string()).as_deref().unwrap_or("<none>")
        );
        self.reowned = head_delta.len();
        Ok(())
    }

    /// Copy one head-delta segment under the new fork's prefix and
    /// materialise its local read-state form. Sources the bytes from
    /// the dead fork, falling back to the name's prior bindings
    /// (journal) for chains of crashed claimants. Verifies under the
    /// source's key before re-signing — re-signing unverified bytes
    /// would launder them under the new key.
    ///
    /// The local form (`index/<u>.idx` + `cache/<u>.{body,present}`) is
    /// what `open_read_state` builds the fork's lbamap from: without it
    /// a re-owned segment is durable but invisible to reads. It is
    /// written only after the segment is durable under the fork's
    /// prefix, preserving the idx-presence ↔ segment-in-S3 invariant.
    async fn re_own_segment(
        &self,
        seg_ulid: Ulid,
        primary_source: Ulid,
        primary_pubkey: &VerifyingKey,
    ) -> Result<(), IpcError> {
        let fork = self.fork.as_ref().expect("rebind ran");
        let idx_path = fork.dir.join("index").join(format!("{seg_ulid}.idx"));

        // Resume skips are per-artefact: the S3 copy and the local form
        // are checked independently so a crash between them heals here.
        let fork_ro = self
            .ctx
            .core
            .stores
            .read_volume(&fork.vol_ulid, &fork.vol_ulid);
        let fork_ro_vd = elide_coordinator::volume_data::VolumeData::new(fork_ro, fork.vol_ulid);
        let copied = fork_ro_vd
            .segments()
            .get_range(seg_ulid, 0..1)
            .await
            .is_ok();
        if copied && idx_path.exists() {
            return Ok(());
        }

        let staged = fork.dir.join(format!("{seg_ulid}.re-own"));
        if copied {
            // A prior run copied the segment but crashed before writing
            // the local form: fetch our copy back, verified under the
            // fork's own key.
            let bytes = fork_ro_vd
                .segments()
                .get_bytes(seg_ulid)
                .await
                .map_err(|e| {
                    IpcError::store(format!(
                        "fetching re-owned segment {seg_ulid} from {}: {e}",
                        fork.vol_ulid
                    ))
                })?;
            elide_core::segment::verify_segment_bytes(
                &bytes,
                &seg_ulid.to_string(),
                &fork.signing_key.verifying_key(),
            )
            .map_err(|e| IpcError::internal(format!("verifying {seg_ulid}: {e}")))?;
            std::fs::write(&staged, &bytes)
                .map_err(|e| IpcError::internal(format!("staging segment {seg_ulid}: {e}")))?;
        } else {
            let mut bytes = match self
                .fetch_delta_segment(seg_ulid, primary_source, primary_pubkey)
                .await?
            {
                Some(b) => b,
                None => {
                    return Err(IpcError::not_found(format!(
                        "segment {seg_ulid} not found under {primary_source} \
                         or any prior binding of '{}' — originals may have been \
                         reaped; manual recovery required",
                        self.volume
                    )));
                }
            };

            let signer = fork.signer()?;
            elide_core::segment::resign_segment_head(&mut bytes, signer.as_ref())
                .map_err(|e| IpcError::internal(format!("re-signing segment {seg_ulid}: {e}")))?;
            std::fs::write(&staged, &bytes)
                .map_err(|e| IpcError::internal(format!("staging segment {seg_ulid}: {e}")))?;

            let fork_vd = self.ctx.core.stores.volume_data(&fork.vol_ulid);
            fork_vd
                .segments()
                .put_bytes(seg_ulid, bytes::Bytes::from(bytes))
                .await
                .map_err(|e| {
                    IpcError::store(format!("uploading re-owned segment {seg_ulid}: {e}"))
                })?;
        }

        let materialised =
            elide_coordinator::upload::promote_segment_local_form(&fork.dir, seg_ulid, &staged);
        let _ = std::fs::remove_file(&staged);
        materialised.map_err(|e| {
            IpcError::internal(format!(
                "materialising re-owned segment {seg_ulid} locally: {e}"
            ))
        })?;
        info!(
            "[force-claim {}] re-owned segment {seg_ulid} from {primary_source}",
            self.volume
        );
        Ok(())
    }

    /// Fetch + verify a head-delta segment's bytes from the dead
    /// fork, then from each prior binding of the name (newest first).
    /// Each candidate's bytes are verified under *that* volume's key
    /// (its skeleton is pulled on demand, which verifies the key
    /// against `meta/`).
    async fn fetch_delta_segment(
        &self,
        seg_ulid: Ulid,
        primary_source: Ulid,
        primary_pubkey: &VerifyingKey,
    ) -> Result<Option<Vec<u8>>, IpcError> {
        let seg_id = seg_ulid.to_string();
        let owned = self.fork.as_ref().expect("rebind ran").vol_ulid;
        let primary_ro = self.ctx.core.stores.read_volume(&owned, &primary_source);
        let primary_vd =
            elide_coordinator::volume_data::VolumeData::new(primary_ro, primary_source);
        match primary_vd.segments().get_bytes(seg_ulid).await {
            Ok(b) => {
                let bytes = b.to_vec();
                elide_core::segment::verify_segment_bytes(&bytes, &seg_id, primary_pubkey)
                    .map_err(|e| IpcError::internal(format!("verifying {seg_ulid}: {e}")))?;
                return Ok(Some(bytes));
            }
            Err(elide_coordinator::volume_data::SegmentsError::Get(
                object_store::Error::NotFound { .. },
            )) => {}
            Err(e) => {
                return Err(IpcError::store(format!(
                    "fetching segment {seg_ulid} from {primary_source}: {e}"
                )));
            }
        }

        for candidate in self.prior_bindings().await? {
            if candidate == primary_source {
                continue;
            }
            let dir =
                elide_core::volume::resolve_ancestor_dir(&self.by_id_dir, &candidate.to_string());
            if !dir.exists() {
                let store = self.ctx.core.stores.base_object_store();
                if let Err(e) =
                    pull_readonly_op(candidate, &self.ctx.core.data_dir, &store, None).await
                {
                    warn!(
                        "[force-claim {}] pulling prior binding {candidate}: {e}",
                        self.volume
                    );
                    continue;
                }
            }
            let Ok(vk) = load_verifying_key(&dir, VOLUME_PUB_FILE) else {
                continue;
            };
            let ro = self.ctx.core.stores.read_volume(&owned, &candidate);
            let vd = elide_coordinator::volume_data::VolumeData::new(ro, candidate);
            match vd.segments().get_bytes(seg_ulid).await {
                Ok(b) => {
                    let bytes = b.to_vec();
                    elide_core::segment::verify_segment_bytes(&bytes, &seg_id, &vk)
                        .map_err(|e| IpcError::internal(format!("verifying {seg_ulid}: {e}")))?;
                    info!(
                        "[force-claim {}] segment {seg_ulid} sourced from prior \
                         binding {candidate}",
                        self.volume
                    );
                    return Ok(Some(bytes));
                }
                Err(elide_coordinator::volume_data::SegmentsError::Get(
                    object_store::Error::NotFound { .. },
                )) => continue,
                Err(e) => {
                    return Err(IpcError::store(format!(
                        "fetching segment {seg_ulid} from {candidate}: {e}"
                    )));
                }
            }
        }
        Ok(None)
    }

    /// Stage 5. Rewrite the provisional provenance into its steady-state
    /// shape — fold in a basis the record hint missed, and always drop the
    /// transient `recovery_sources` grant the rebind may have set — then
    /// materialise the local fork (config, `wal/`, `pending/`, symlink,
    /// stopped marker) so the daemon can supervise it.
    async fn finalize(&mut self) -> Result<(), IpcError> {
        let fork = self.fork.as_ref().expect("rebind ran");
        let source = self.source_vol.expect("resolve_source ran");
        let basis = self.basis.expect("re_own ran");

        let provisional =
            read_lineage_verifying_signature(&fork.dir, VOLUME_PUB_FILE, VOLUME_PROVENANCE_FILE)
                .map_err(|e| IpcError::internal(format!("reading provisional provenance: {e}")))?;

        // Rewrite when the data plane revealed a basis the record hint did
        // not name, and/or the rebind left a `recovery_sources` grant: the
        // grant authorises re_own's reads but must never persist past them.
        let rewrite = match basis {
            Some(effective_basis) => {
                let pin = provisional
                    .parent()
                    .filter(|p| p.volume_ulid == source.to_string())
                    .map(|p| p.snapshot_ulid.clone());
                if pin.as_deref() != Some(effective_basis.to_string().as_str()) {
                    let source_dir = elide_core::volume::resolve_ancestor_dir(
                        &self.by_id_dir,
                        &source.to_string(),
                    );
                    let source_pubkey =
                        load_verifying_key(&source_dir, VOLUME_PUB_FILE).map_err(|e| {
                            IpcError::internal(format!("loading volume.pub for {source}: {e}"))
                        })?;
                    Some(ProvenanceLineage::fork(ParentRef {
                        volume_ulid: source.to_string(),
                        snapshot_ulid: effective_basis.to_string(),
                        pubkey: source_pubkey.to_bytes(),
                    }))
                } else if provisional.recovery_sources().is_empty() {
                    None
                } else {
                    Some(provisional.cleared_recovery())
                }
            }
            None if provisional.recovery_sources().is_empty() => None,
            None => Some(provisional.cleared_recovery()),
        };

        if let Some(lineage) = rewrite {
            write_provenance(
                &fork.dir,
                &fork.signing_key,
                VOLUME_PROVENANCE_FILE,
                &lineage,
            )
            .map_err(|e| IpcError::internal(format!("writing provenance: {e}")))?;
            let meta_store = self.ctx.core.stores.writer();
            elide_coordinator::upload::upload_volume_provenance_initial(
                &self.ctx.core.data_dir,
                fork.vol_ulid,
                &meta_store,
            )
            .await
            .map_err(|e| IpcError::store(format!("uploading volume.provenance: {e:#}")))?;
        }

        std::fs::create_dir_all(fork.dir.join("wal"))
            .map_err(|e| IpcError::internal(format!("creating wal/: {e}")))?;
        std::fs::create_dir_all(fork.dir.join("pending"))
            .map_err(|e| IpcError::internal(format!("creating pending/: {e}")))?;

        let by_name_dir = self.ctx.core.data_dir.join("by_name");
        let symlink_path = by_name_dir.join(&self.volume);
        std::fs::create_dir_all(&by_name_dir)
            .map_err(|e| IpcError::internal(format!("creating by_name dir: {e}")))?;
        if symlink_path.exists() || symlink_path.is_symlink() {
            // Preserve the fork we're displacing: rehome it under
            // <name>-<suffix> instead of orphaning it
            // (docs/design/displaced-fork-rehome.md). Best-effort — a
            // rehome failure must not fail the force-claim itself.
            elide_coordinator::rehome::rehome_existing_local_fork(
                self.ctx.core.identity.as_ref(),
                self.ctx.core.stores.as_ref(),
                &self.ctx.core.data_dir,
                &self.volume,
            )
            .await;
            std::fs::remove_file(&symlink_path)
                .map_err(|e| IpcError::internal(format!("removing stale by_name link: {e}")))?;
        }
        std::os::unix::fs::symlink(format!("../by_id/{}", fork.vol_ulid), &symlink_path)
            .map_err(|e| IpcError::internal(format!("creating by_name symlink: {e}")))?;
        std::fs::write(fork.dir.join(STOPPED_FILE), "")
            .map_err(|e| IpcError::internal(format!("writing volume.stopped: {e}")))?;

        // Park marker down first, claiming marker off second: no
        // instant where the dir is discoverable without one of them.
        elide_coordinator::volume_state::clear_claiming_marker(&fork.dir)
            .map_err(|e| IpcError::internal(format!("removing volume.claiming: {e}")))?;

        register_prefetch_or_get(&self.ctx.prefetch_tracker, fork.vol_ulid);
        crate::rescan::trigger();
        self.job.append(ClaimAttachEvent::ForkCreated {
            new_vol_ulid: fork.vol_ulid,
        });
        // Appended after ForkCreated so a CLI that predates the
        // variant fails its stream parse only past the point
        // `finalize_or_err` treats as success.
        self.job.append(ClaimAttachEvent::ReOwned {
            segments: self.reowned as u64,
            basis,
        });
        info!(
            "[force-claim {}] finalized fork {} (source {source})",
            self.volume, fork.vol_ulid
        );
        Ok(())
    }

    /// Stage 6. Surface the daemon-side prefetch (ancestor + own
    /// index hydration). Failure is non-fatal — `volume start`
    /// re-awaits.
    async fn surface_prefetch(&self) {
        let fork_vol = self.fork.as_ref().expect("rebind ran").vol_ulid;
        self.job.append(ClaimAttachEvent::PrefetchStarted);
        let _ = await_prefetch_op(fork_vol, &self.ctx.prefetch_tracker).await;
        self.job.append(ClaimAttachEvent::PrefetchDone);
    }
}

/// Fetch and verify `<vol>/snapshots/<snap>` in either form — the
/// stable user manifest first, the ephemeral stop-snapshot second.
/// `Ok(None)` when neither key exists.
async fn fetch_manifest_any_kind(
    vd: &elide_coordinator::volume_data::VolumeData,
    snap_ulid: Ulid,
    pubkey: &VerifyingKey,
) -> Result<Option<elide_core::signing::SnapshotManifest>, IpcError> {
    use elide_coordinator::volume_data::SnapshotsError;
    let vol = vd.vol_ulid();
    let bytes = match vd.snapshots().get_manifest_bytes(snap_ulid).await {
        Ok(b) => b,
        Err(SnapshotsError::Get(object_store::Error::NotFound { .. })) => {
            match vd.snapshots().get_stop_manifest_bytes(snap_ulid).await {
                Ok(b) => b,
                Err(SnapshotsError::Get(object_store::Error::NotFound { .. })) => {
                    return Ok(None);
                }
                Err(e) => {
                    return Err(IpcError::store(format!(
                        "fetching stop manifest {vol}/{snap_ulid}: {e}"
                    )));
                }
            }
        }
        Err(e) => {
            return Err(IpcError::store(format!(
                "fetching manifest {vol}/{snap_ulid}: {e}"
            )));
        }
    };
    elide_core::signing::read_snapshot_manifest_from_bytes(&bytes, pubkey, &snap_ulid)
        .map(Some)
        .map_err(|e| IpcError::internal(format!("verifying manifest {vol}/{snap_ulid}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_coordinator::identity::CoordinatorIdentity;
    use elide_coordinator::stores::{PassthroughStores, ScopedStores};
    use elide_core::name_record::NameRecord;
    use elide_core::segment::{SegmentEntry, SegmentFlags, SegmentSigner};
    use elide_core::signing::encode_hex;
    use elide_core::ulid_mint::UlidMint;
    use object_store::path::Path as StorePath;
    use object_store::{ObjectStore, PutPayload};
    use tempfile::TempDir;

    /// A dead volume seeded directly into the in-memory bucket.
    struct DeadVol {
        vol: Ulid,
        signer: Arc<dyn SegmentSigner>,
        vk: ed25519_dalek::VerifyingKey,
    }

    /// Mint a keypair and publish the root-shape `meta/<vol>.{pub,
    /// provenance}` skeleton for it.
    async fn make_dead_volume(store: &Arc<dyn ObjectStore>, vol: Ulid) -> DeadVol {
        make_dead_volume_with_lineage(store, vol, &ProvenanceLineage::default()).await
    }

    /// Like [`make_dead_volume`] but with a caller-supplied lineage
    /// (e.g. a partial fork that carries a `ParentRef`).
    async fn make_dead_volume_with_lineage(
        store: &Arc<dyn ObjectStore>,
        vol: Ulid,
        lineage: &ProvenanceLineage,
    ) -> DeadVol {
        let tmp = TempDir::new().unwrap();
        let key = generate_keypair(tmp.path(), VOLUME_KEY_FILE, VOLUME_PUB_FILE).unwrap();
        write_provenance(tmp.path(), &key, VOLUME_PROVENANCE_FILE, lineage).unwrap();
        let vk = key.verifying_key();
        let pub_key = StorePath::from(elide_core::store_keys::meta_pub_key(vol));
        let pub_body = format!("{}\n", encode_hex(&vk.to_bytes()));
        store
            .put(&pub_key, PutPayload::from(pub_body.into_bytes()))
            .await
            .unwrap();
        let prov_body = std::fs::read(tmp.path().join(VOLUME_PROVENANCE_FILE)).unwrap();
        let prov_key = StorePath::from(elide_core::store_keys::meta_provenance_key(vol));
        store
            .put(&prov_key, PutPayload::from(prov_body))
            .await
            .unwrap();
        let (signer, _) = elide_core::signing::signer_from_bytes(&key.to_bytes()).unwrap();
        DeadVol { vol, signer, vk }
    }

    fn build_segment_bytes(signer: &dyn SegmentSigner, fill: u8) -> Vec<u8> {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("seg");
        let body = vec![fill; 4096];
        let hash = blake3::hash(&body);
        let entries = vec![SegmentEntry::new_data(
            hash,
            0,
            1,
            SegmentFlags::empty(),
            body,
        )];
        elide_core::segment::write_segment(&path, entries, signer).unwrap();
        std::fs::read(&path).unwrap()
    }

    async fn put_segment(store: &Arc<dyn ObjectStore>, vol: Ulid, seg: Ulid, bytes: Vec<u8>) {
        let key = elide_coordinator::upload::segment_key(vol, seg);
        store.put(&key, PutPayload::from(bytes)).await.unwrap();
    }

    async fn put_head(
        store: &Arc<dyn ObjectStore>,
        vol: Ulid,
        anchor: Option<Ulid>,
        segs: &[Ulid],
    ) {
        let mut head = SegmentHead::empty(anchor);
        for s in segs {
            head.added.insert(*s);
        }
        elide_coordinator::volume_data::VolumeData::new(Arc::clone(store), vol)
            .head()
            .put(&head)
            .await
            .unwrap();
    }

    fn fixture(store: Arc<dyn ObjectStore>) -> (ClaimContext, TempDir) {
        let coord_dir = TempDir::new().unwrap();
        let data_dir = TempDir::new().unwrap();
        let identity = Arc::new(CoordinatorIdentity::load_or_generate(coord_dir.path()).unwrap());
        let stores: Arc<dyn ScopedStores> = Arc::new(PassthroughStores::new(store));
        let ctx = ClaimContext {
            core: crate::inbound::CoordinatorCore {
                data_dir: Arc::new(data_dir.path().to_path_buf()),
                stores,
                identity,
            },
            claim_registry: crate::claim::new_registry(),
            prefetch_tracker: elide_coordinator::new_prefetch_tracker(),
        };
        (ctx, data_dir)
    }

    /// Run a forced claim to terminal state. Returns the new fork's
    /// ULID from the rebound record.
    async fn run_force_claim(ctx: &ClaimContext, store: &Arc<dyn ObjectStore>) -> Ulid {
        let reply = start_force_claim("vol".to_owned(), ctx.clone())
            .await
            .unwrap();
        assert!(matches!(reply, ClaimStartReply::Claiming { .. }));
        let job = ctx
            .claim_registry
            .lock()
            .unwrap()
            .get("vol")
            .cloned()
            .unwrap();
        // No daemon runs in tests: once the orchestrator reports
        // `ForkCreated`, publish the prefetch result the daemon side
        // would normally send, so `surface_prefetch` unblocks.
        let mut prefetch_published = false;
        for _ in 0..500 {
            if !prefetch_published
                && let Some(fork) = job.read_from(0).iter().find_map(|e| match e {
                    ClaimAttachEvent::ForkCreated { new_vol_ulid } => Some(*new_vol_ulid),
                    _ => None,
                })
            {
                register_prefetch_or_get(&ctx.prefetch_tracker, fork).send_replace(Some(Ok(())));
                prefetch_published = true;
            }
            match job.state() {
                ClaimJobState::Running => {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await
                }
                ClaimJobState::Done => break,
                ClaimJobState::Failed(e) => panic!("forced claim failed: {e}"),
            }
        }
        assert!(matches!(job.state(), ClaimJobState::Done), "timed out");
        let (rec, _) = elide_coordinator::name_store::read_name_record(store, "vol")
            .await
            .unwrap()
            .unwrap();
        rec.vol_ulid
    }

    async fn assert_reowned(
        store: &Arc<dyn ObjectStore>,
        data_dir: &std::path::Path,
        fork: Ulid,
        seg: Ulid,
    ) {
        let fork_vk = load_verifying_key(
            &data_dir.join("by_id").join(fork.to_string()),
            VOLUME_PUB_FILE,
        )
        .unwrap();
        let vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(store), fork);
        let bytes = vd.segments().get_bytes(seg).await.unwrap();
        elide_core::segment::verify_segment_bytes(&bytes, &seg.to_string(), &fork_vk)
            .expect("re-owned segment verifies under the new fork's key");
    }

    /// The re-owned segment's local read-state form is in place and the
    /// fork's own lbamap layer rebuilds over it (signature-verifying, so
    /// this also proves the idx carries the fork's re-signed header).
    fn assert_materialised(data_dir: &std::path::Path, fork: Ulid, seg: Ulid) {
        let fork_dir = data_dir.join("by_id").join(fork.to_string());
        for rel in [
            format!("index/{seg}.idx"),
            format!("cache/{seg}.body"),
            format!("cache/{seg}.present"),
        ] {
            assert!(
                fork_dir.join(&rel).is_file(),
                "re-owned segment {seg} missing local form: {rel}"
            );
        }
        assert!(
            !fork_dir.join(format!("{seg}.re-own")).exists(),
            "staging file for {seg} must not outlive the re-own"
        );
        let map = elide_core::lbamap::rebuild_segments(&[(fork_dir, None)])
            .expect("fork's own lbamap layer rebuilds over the re-owned idx");
        assert!(
            map.lookup(0).is_some(),
            "re-owned segment {seg} claims its LBAs in the rebuilt lbamap"
        );
    }

    fn dead_owner_id() -> String {
        elide_coordinator::portable::format_coordinator_id(
            &elide_coordinator::portable::coordinator_id(&[0xEEu8; 32]),
        )
    }

    #[tokio::test]
    async fn fresh_claim_reowns_post_snapshot_head_delta() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s1 = mint.next();
        let basis = mint.next();
        let s2 = mint.next();
        let s3 = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;

        for (seg, fill) in [(s1, 1u8), (s2, 2), (s3, 3)] {
            put_segment(
                &store,
                dead.vol,
                seg,
                build_segment_bytes(dead.signer.as_ref(), fill),
            )
            .await;
        }
        // Basis manifest covers s1; HEAD carries the post-basis delta.
        let manifest =
            elide_core::signing::build_snapshot_manifest_bytes(dead.signer.as_ref(), &[s1]);
        let vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), dead.vol);
        vd.snapshots()
            .put_manifest(basis, bytes::Bytes::from(manifest))
            .await
            .unwrap();
        vd.snapshots().bump_latest_if_newer(basis).await.unwrap();
        put_head(&store, dead.vol, Some(basis), &[s2, s3]).await;

        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        rec.latest_snapshot = Some(basis);
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        // Record: rebound to the new fork under us, Stopped, pinned.
        let (rec, _) = elide_coordinator::name_store::read_name_record(&store, "vol")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.state, elide_core::name_record::NameState::Stopped);
        assert_eq!(
            rec.coordinator_id.as_deref(),
            Some(ctx.core.identity.coordinator_id_str())
        );
        assert_eq!(
            rec.parent.as_deref(),
            Some(format!("{}/{basis}", dead.vol).as_str())
        );

        // Head delta re-owned under the new prefix, ULIDs retained;
        // the basis-covered segment is not copied.
        assert_reowned(&store, data_dir.path(), fork, s2).await;
        assert_reowned(&store, data_dir.path(), fork, s3).await;
        assert_materialised(data_dir.path(), fork, s2);
        assert_materialised(data_dir.path(), fork, s3);
        let fork_vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), fork);
        assert!(fork_vd.segments().get_bytes(s1).await.is_err());
        assert!(
            !data_dir
                .path()
                .join("by_id")
                .join(fork.to_string())
                .join(format!("index/{s1}.idx"))
                .exists(),
            "basis-covered segment gets no local idx"
        );

        // New fork's HEAD: anchored at the basis, listing the delta.
        let head = fork_vd.head().read().await.unwrap();
        assert_eq!(head.anchor, Some(basis));
        assert_eq!(head.added, [s2, s3].into_iter().collect());

        // The attach stream reports the re-own summary to the CLI.
        let job = ctx
            .claim_registry
            .lock()
            .unwrap()
            .get("vol")
            .cloned()
            .unwrap();
        assert!(
            job.read_from(0).contains(&ClaimAttachEvent::ReOwned {
                segments: 2,
                basis: Some(basis),
            }),
            "attach stream must carry the re-own summary"
        );

        // Provenance: pinned at (dead, basis).
        let lineage = read_lineage_verifying_signature(
            &data_dir.path().join("by_id").join(fork.to_string()),
            VOLUME_PUB_FILE,
            VOLUME_PROVENANCE_FILE,
        )
        .unwrap();
        let parent = lineage.parent().expect("parent pin");
        assert_eq!(parent.volume_ulid, dead.vol.to_string());
        assert_eq!(parent.snapshot_ulid, basis.to_string());
        assert_eq!(parent.pubkey, dead.vk.to_bytes());

        // Local fork is finalized: parked, discovery unblocked.
        let fork_dir = data_dir.path().join("by_id").join(fork.to_string());
        assert!(fork_dir.join("wal").is_dir());
        assert!(fork_dir.join(STOPPED_FILE).exists());
        assert!(
            !fork_dir.join(CLAIMING_FILE).exists(),
            "finalize removes the claim-in-progress marker"
        );

        // The journal records the forced claim against the new fork.
        let events = ctx
            .core
            .stores
            .event_journal_ro()
            .recent("vol", 4)
            .await
            .unwrap();
        let fc = events
            .iter()
            .find(|e| {
                matches!(
                    e.kind,
                    elide_core::volume_event::EventKind::ForceClaimed { .. }
                )
            })
            .expect("force_claimed event present");
        assert_eq!(fc.vol_ulid, fork);
        assert!(
            matches!(
                fc.kind,
                elide_core::volume_event::EventKind::ForceClaimed { source_vol_ulid, .. }
                    if source_vol_ulid == dead.vol
            ),
            "the force-claim event records the re-owned dead fork as its source"
        );
    }

    /// Mirror of the 2026-07-06 quickstart incident: the dead owner's
    /// head delta carries a `Delta` entry (minted by the formation delta tier) whose
    /// source extent lives in a sealed segment, the handoff manifest
    /// exists as a user-kind object but `snapshots/LATEST` is absent,
    /// and the name record still hints the handoff snapshot. After the
    /// forced claim, opening the fork the way the volume daemon does
    /// and reading the delta LBA must materialise the post-delta bytes.
    #[tokio::test]
    async fn force_claimed_fork_serves_delta_entries() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s_src = mint.next();
        let anchor = mint.next();
        let s_delta = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;

        // v2 = v1 with a small edit, so the zstd-dict delta is tiny.
        let v1 = vec![0x11u8; 4096];
        let mut v2 = v1.clone();
        v2[100..140].copy_from_slice(&[0xAB; 40]);
        let h1 = blake3::hash(&v1);
        let h2 = blake3::hash(&v2);

        let src_bytes = {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("seg");
            let entries = vec![SegmentEntry::new_data(
                h1,
                0,
                1,
                SegmentFlags::empty(),
                v1.clone(),
            )];
            elide_core::segment::write_segment(&path, entries, dead.signer.as_ref()).unwrap();
            std::fs::read(&path).unwrap()
        };

        let blob = zstd::bulk::Compressor::with_dictionary(3, &v1)
            .unwrap()
            .compress(&v2)
            .unwrap();
        let delta_bytes = {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("seg");
            let entries = vec![elide_core::segment::PendingEntry::from_entry(
                elide_core::segment::SegmentEntry::new_delta(
                    h2,
                    0,
                    1,
                    vec![elide_core::segment::DeltaOption {
                        source_hash: h1,
                        delta_offset: 0,
                        delta_length: blob.len() as u32,
                        delta_hash: blake3::hash(&blob),
                    }],
                ),
            )];
            elide_core::segment::write_segment_with_delta_body(
                &path,
                entries,
                &blob,
                dead.signer.as_ref(),
            )
            .unwrap();
            std::fs::read(&path).unwrap()
        };

        put_segment(&store, dead.vol, s_src, src_bytes.clone()).await;
        put_segment(&store, dead.vol, s_delta, delta_bytes).await;

        // Handoff-shaped data plane: user-kind manifest at `anchor`
        // covering the source segment, no `snapshots/LATEST`, HEAD
        // anchored at the seal with the delta segment as head delta.
        let manifest =
            elide_core::signing::build_snapshot_manifest_bytes(dead.signer.as_ref(), &[s_src]);
        let vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), dead.vol);
        vd.snapshots()
            .put_manifest(anchor, bytes::Bytes::from(manifest.clone()))
            .await
            .unwrap();
        put_head(&store, dead.vol, Some(anchor), &[s_delta]).await;

        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        rec.latest_snapshot = Some(anchor);
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        // LATEST absent → data-plane basis none → both segments copied.
        assert_materialised(data_dir.path(), fork, s_src);
        assert_materialised(data_dir.path(), fork, s_delta);

        // Populate the pulled ancestor's read state the way the
        // prefetch/heal pass does before the daemon opens: the pinned
        // manifest plus the idx of every manifest-covered segment.
        let dead_dir = data_dir.path().join("by_id").join(dead.vol.to_string());
        std::fs::create_dir_all(dead_dir.join("snapshots")).unwrap();
        std::fs::write(
            dead_dir
                .join("snapshots")
                .join(format!("{anchor}.manifest")),
            &manifest,
        )
        .unwrap();
        std::fs::create_dir_all(dead_dir.join("index")).unwrap();
        let tmp = TempDir::new().unwrap();
        let segf = tmp.path().join(s_src.to_string());
        std::fs::write(&segf, &src_bytes).unwrap();
        elide_core::segment::extract_idx(
            &segf,
            &dead_dir.join("index").join(format!("{s_src}.idx")),
        )
        .unwrap();

        // Open the fork the way the volume daemon does and read the
        // delta LBA.
        let fork_dir = data_dir.path().join("by_id").join(fork.to_string());
        let vol =
            elide_core::volume::Volume::open(&fork_dir, &data_dir.path().join("by_id")).unwrap();
        let got = vol.read(0, 1).unwrap();
        assert_eq!(
            got.as_slice(),
            v2.as_slice(),
            "delta LBA must materialise the post-delta bytes on the claimed fork"
        );
    }

    /// A forced claim of a volume with no basis snapshot and nothing
    /// drained recovers an empty fork — the attach stream must say so
    /// (the CLI renders `segments: 0, basis: None` as a warning).
    #[tokio::test]
    async fn empty_recovery_reports_zero_segments() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let dead = make_dead_volume(&store, Ulid::new()).await;
        put_head(&store, dead.vol, None, &[]).await;

        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, _data_dir) = fixture(Arc::clone(&store));
        run_force_claim(&ctx, &store).await;

        let job = ctx
            .claim_registry
            .lock()
            .unwrap()
            .get("vol")
            .cloned()
            .unwrap();
        assert!(
            job.read_from(0).contains(&ClaimAttachEvent::ReOwned {
                segments: 0,
                basis: None,
            }),
            "attach stream must report the empty recovery"
        );
    }

    #[tokio::test]
    async fn never_snapshotted_root_reowns_everything() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s1 = mint.next();
        let s2 = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;
        for (seg, fill) in [(s1, 1u8), (s2, 2)] {
            put_segment(
                &store,
                dead.vol,
                seg,
                build_segment_bytes(dead.signer.as_ref(), fill),
            )
            .await;
        }
        put_head(&store, dead.vol, None, &[s1, s2]).await;

        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        assert_reowned(&store, data_dir.path(), fork, s1).await;
        assert_reowned(&store, data_dir.path(), fork, s2).await;
        assert_materialised(data_dir.path(), fork, s1);
        assert_materialised(data_dir.path(), fork, s2);

        // The dead fork was a root with no manifest: the new fork
        // takes over its (empty) ParentRef — a root itself.
        let lineage = read_lineage_verifying_signature(
            &data_dir.path().join("by_id").join(fork.to_string()),
            VOLUME_PUB_FILE,
            VOLUME_PROVENANCE_FILE,
        )
        .unwrap();
        assert!(lineage.parent().is_none(), "root continuation stays a root");
        assert!(
            lineage.recovery_sources().is_empty(),
            "finalize must clear the transient recovery-source grant the rebind set"
        );
        let head = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), fork)
            .head()
            .read()
            .await
            .unwrap();
        assert_eq!(head.anchor, None);
        assert_eq!(head.added, [s1, s2].into_iter().collect());
    }

    /// A clean `stop` on a never-user-snapshotted fork truncates HEAD
    /// to empty anchored at the stop-snapshot. The claim set must come
    /// from that manifest (the frontier), not the absent `LATEST` —
    /// otherwise the claim would compute an empty live set and re-own
    /// nothing.
    #[tokio::test]
    async fn clean_stop_frontier_reowns_stop_covered_segments() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s1 = mint.next();
        let s2 = mint.next();
        let stop_snap = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;
        for (seg, fill) in [(s1, 1u8), (s2, 2)] {
            put_segment(
                &store,
                dead.vol,
                seg,
                build_segment_bytes(dead.signer.as_ref(), fill),
            )
            .await;
        }
        let manifest =
            elide_core::signing::build_snapshot_manifest_bytes(dead.signer.as_ref(), &[s1, s2]);
        elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), dead.vol)
            .snapshots()
            .put_stop_manifest(stop_snap, bytes::Bytes::from(manifest))
            .await
            .unwrap();
        put_head(&store, dead.vol, Some(stop_snap), &[]).await;

        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        assert_reowned(&store, data_dir.path(), fork, s1).await;
        assert_reowned(&store, data_dir.path(), fork, s2).await;
        assert_materialised(data_dir.path(), fork, s1);
        assert_materialised(data_dir.path(), fork, s2);

        // No user manifest to pin at: root continuation, data carried
        // by the copies.
        let lineage = read_lineage_verifying_signature(
            &data_dir.path().join("by_id").join(fork.to_string()),
            VOLUME_PUB_FILE,
            VOLUME_PROVENANCE_FILE,
        )
        .unwrap();
        assert!(lineage.parent().is_none());
    }

    /// User snapshot at `basis` covering s1, then further writes and a
    /// clean stop sealing {s1, s2}. The pin lands on the stable user
    /// basis; only the stop-covered delta above it is copied.
    #[tokio::test]
    async fn stop_frontier_above_user_basis_copies_only_the_delta() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s1 = mint.next();
        let basis = mint.next();
        let s2 = mint.next();
        let stop_snap = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;
        for (seg, fill) in [(s1, 1u8), (s2, 2)] {
            put_segment(
                &store,
                dead.vol,
                seg,
                build_segment_bytes(dead.signer.as_ref(), fill),
            )
            .await;
        }
        let vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), dead.vol);
        let user_manifest =
            elide_core::signing::build_snapshot_manifest_bytes(dead.signer.as_ref(), &[s1]);
        vd.snapshots()
            .put_manifest(basis, bytes::Bytes::from(user_manifest))
            .await
            .unwrap();
        vd.snapshots().bump_latest_if_newer(basis).await.unwrap();
        let stop_manifest =
            elide_core::signing::build_snapshot_manifest_bytes(dead.signer.as_ref(), &[s1, s2]);
        vd.snapshots()
            .put_stop_manifest(stop_snap, bytes::Bytes::from(stop_manifest))
            .await
            .unwrap();
        put_head(&store, dead.vol, Some(stop_snap), &[]).await;

        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        rec.latest_snapshot = Some(basis);
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        assert_reowned(&store, data_dir.path(), fork, s2).await;
        assert_materialised(data_dir.path(), fork, s2);
        let fork_vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), fork);
        assert!(
            fork_vd.segments().get_bytes(s1).await.is_err(),
            "basis-covered segment is served through the pin, not copied"
        );

        let (rec, _) = elide_coordinator::name_store::read_name_record(&store, "vol")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            rec.parent.as_deref(),
            Some(format!("{}/{basis}", dead.vol).as_str())
        );
        let head = fork_vd.head().read().await.unwrap();
        assert_eq!(head.anchor, Some(basis));
        assert_eq!(head.added, [s2].into_iter().collect());
    }

    /// HEAD anchored at a manifest that no longer exists (e.g. a
    /// reaped stop-snapshot): the claim set falls back to the basis
    /// manifest plus HEAD's own delta.
    #[tokio::test]
    async fn missing_frontier_manifest_falls_back_to_basis() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s1 = mint.next();
        let s2 = mint.next();
        let gone_snap = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;
        for (seg, fill) in [(s1, 1u8), (s2, 2)] {
            put_segment(
                &store,
                dead.vol,
                seg,
                build_segment_bytes(dead.signer.as_ref(), fill),
            )
            .await;
        }
        put_head(&store, dead.vol, Some(gone_snap), &[s1, s2]).await;

        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        assert_reowned(&store, data_dir.path(), fork, s1).await;
        assert_reowned(&store, data_dir.path(), fork, s2).await;
    }

    /// A claim that crashed after `early_rebind` leaves a partial fork
    /// bound to the name: meta artifacts only, a `ParentRef` to the
    /// real parent, no manifest, no HEAD. `claim --force` over it must
    /// take over that `ParentRef` so the new fork rejoins the lineage
    /// at the same branch point.
    #[tokio::test]
    async fn crashed_claim_fork_takeover_carries_parent_ref() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let gsnap = mint.next();
        let grandparent = make_dead_volume(&store, mint.next()).await;
        // Grandparent's handoff manifest at the branch point — the
        // chain pull and later hydration anchor on it.
        let manifest =
            elide_core::signing::build_snapshot_manifest_bytes(grandparent.signer.as_ref(), &[]);
        elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), grandparent.vol)
            .snapshots()
            .put_manifest(gsnap, bytes::Bytes::from(manifest))
            .await
            .unwrap();

        let partial = make_dead_volume_with_lineage(
            &store,
            mint.next(),
            &ProvenanceLineage::fork(ParentRef {
                volume_ulid: grandparent.vol.to_string(),
                snapshot_ulid: gsnap.to_string(),
                pubkey: grandparent.vk.to_bytes(),
            }),
        )
        .await;

        let mut rec = NameRecord::live_minimal(partial.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        // The partial fork had no manifest: the new fork takes over
        // its ParentRef, rejoining the lineage at the grandparent's
        // branch point.
        let lineage = read_lineage_verifying_signature(
            &data_dir.path().join("by_id").join(fork.to_string()),
            VOLUME_PUB_FILE,
            VOLUME_PROVENANCE_FILE,
        )
        .unwrap();
        let parent = lineage.parent().expect("takeover carries the ParentRef");
        assert_eq!(parent.volume_ulid, grandparent.vol.to_string());
        assert_eq!(parent.snapshot_ulid, gsnap.to_string());
        assert_eq!(parent.pubkey, grandparent.vk.to_bytes());

        // Record rebound to the new fork; no basis pin (the partial
        // fork never published a snapshot).
        let (rec, _) = elide_coordinator::name_store::read_name_record(&store, "vol")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rec.vol_ulid, fork);
        assert!(rec.parent.is_none());
    }

    #[tokio::test]
    async fn same_host_resume_completes_partial_fork() {
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s1 = mint.next();
        let s2 = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;
        for (seg, fill) in [(s1, 1u8), (s2, 2)] {
            put_segment(
                &store,
                dead.vol,
                seg,
                build_segment_bytes(dead.signer.as_ref(), fill),
            )
            .await;
        }
        put_head(&store, dead.vol, None, &[s1, s2]).await;
        let mut rec = NameRecord::live_minimal(dead.vol, 1 << 30);
        rec.coordinator_id = Some(dead_owner_id());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();
        // The dead binding's journal history — every real name has
        // one from creation; the resume path resolves its re-own
        // source from it.
        let owner_dir = TempDir::new().unwrap();
        let owner = Arc::new(CoordinatorIdentity::load_or_generate(owner_dir.path()).unwrap());
        owner.publish_pub(store.as_ref()).await.unwrap();
        use elide_coordinator::event_journal::EventJournal;
        elide_coordinator::event_journal::BucketEventJournal::new(
            Arc::clone(&store),
            Arc::clone(&store),
        )
        .emit(
            owner.as_ref(),
            "vol",
            elide_core::volume_event::EventKind::Created,
            dead.vol,
        )
        .await
        .unwrap();

        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        // Simulate a crash between the forced CAS and completion:
        // local materialisation gone (both segments), one re-owned
        // object missing from S3. Resume must re-copy s2 and
        // re-materialise both — s1 through the copied-but-unmaterialised
        // branch, s2 through the full copy path.
        let fork_dir = data_dir.path().join("by_id").join(fork.to_string());
        std::fs::remove_dir_all(fork_dir.join("wal")).unwrap();
        std::fs::remove_dir_all(fork_dir.join("pending")).unwrap();
        std::fs::remove_dir_all(fork_dir.join("index")).unwrap();
        std::fs::remove_dir_all(fork_dir.join("cache")).unwrap();
        std::fs::remove_file(data_dir.path().join("by_name").join("vol")).unwrap();
        store
            .delete(&elide_coordinator::upload::segment_key(fork, s2))
            .await
            .unwrap();

        let resumed = run_force_claim(&ctx, &store).await;
        assert_eq!(resumed, fork, "resume continues the same fork");
        assert_reowned(&store, data_dir.path(), fork, s2).await;
        assert_materialised(data_dir.path(), fork, s1);
        assert_materialised(data_dir.path(), fork, s2);
        assert!(fork_dir.join("wal").is_dir(), "finalize re-ran");
    }

    #[tokio::test]
    async fn cross_host_resume_sources_via_journal() {
        // D (never-snapshotted root, dead) was force-claimed by host A,
        // which crashed mid-copy: F1 has the HEAD intent and one of two
        // segments. Host B force-claims the name; the missing segment
        // is unreachable through F1's provenance (a root) and must be
        // sourced from D via the events/<name> journal.
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let mut mint = UlidMint::new(Ulid::nil());
        let s1 = mint.next();
        let s2 = mint.next();
        let dead = make_dead_volume(&store, mint.next()).await;
        for (seg, fill) in [(s1, 1u8), (s2, 2)] {
            put_segment(
                &store,
                dead.vol,
                seg,
                build_segment_bytes(dead.signer.as_ref(), fill),
            )
            .await;
        }
        put_head(&store, dead.vol, None, &[s1, s2]).await;

        // Journal history: D's owner created the name.
        let owner_dir = TempDir::new().unwrap();
        let owner = Arc::new(CoordinatorIdentity::load_or_generate(owner_dir.path()).unwrap());
        let journal = elide_coordinator::event_journal::BucketEventJournal::new(
            Arc::clone(&store),
            Arc::clone(&store),
        );
        owner.publish_pub(store.as_ref()).await.unwrap();
        use elide_coordinator::event_journal::EventJournal;
        journal
            .emit(
                owner.as_ref(),
                "vol",
                elide_core::volume_event::EventKind::Created,
                dead.vol,
            )
            .await
            .unwrap();

        // Host A's partial fork F1: meta skeleton (root, like D), HEAD
        // intent for both segments, but only s1 copied. The journal
        // records A's forced claim.
        let f1 = make_dead_volume(&store, mint.next()).await;
        let mut s1_bytes = {
            let vd = elide_coordinator::volume_data::VolumeData::new(Arc::clone(&store), dead.vol);
            vd.segments().get_bytes(s1).await.unwrap().to_vec()
        };
        elide_core::segment::resign_segment_head(&mut s1_bytes, f1.signer.as_ref()).unwrap();
        put_segment(&store, f1.vol, s1, s1_bytes).await;
        put_head(&store, f1.vol, None, &[s1, s2]).await;
        let host_a_dir = TempDir::new().unwrap();
        let host_a = Arc::new(CoordinatorIdentity::load_or_generate(host_a_dir.path()).unwrap());
        host_a.publish_pub(store.as_ref()).await.unwrap();
        journal
            .emit(
                host_a.as_ref(),
                "vol",
                elide_core::volume_event::EventKind::ForceClaimed {
                    source_vol_ulid: dead.vol,
                    displaced_coordinator_id: Some(dead_owner_id()),
                },
                f1.vol,
            )
            .await
            .unwrap();
        let mut rec = NameRecord::live_minimal(f1.vol, 1 << 30);
        rec.coordinator_id = Some(host_a.coordinator_id_str().to_owned());
        elide_coordinator::name_store::create_name_record(&store, "vol", &rec)
            .await
            .unwrap();

        // Host B forces the claim.
        let (ctx, data_dir) = fixture(Arc::clone(&store));
        let fork = run_force_claim(&ctx, &store).await;

        // Both segments re-owned: s1 sourced from F1's copy, s2 from D
        // via the journal fallback.
        assert_reowned(&store, data_dir.path(), fork, s1).await;
        assert_reowned(&store, data_dir.path(), fork, s2).await;
        assert_materialised(data_dir.path(), fork, s1);
        assert_materialised(data_dir.path(), fork, s2);
    }
}
