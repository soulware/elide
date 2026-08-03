// Per-volume drain + GC tick orchestrator.
//
// Mechanical extraction of the tick body that used to live inline in
// `run_volume_tasks` (see `tasks.rs`). One `run_tick()` call performs the
// pre-flight checks, volume-side IPC compactions, S3 drain, and the
// rate-limited GC pass — same call order, same logs, same behaviour.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use object_store::ObjectStore;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{error, info, warn};
use ulid::Ulid;

use crate::config::GcConfig;
use crate::segment_head;
use crate::volume_data::VolumeData;
use crate::volume_state::{IMPORTING_FILE, STOPPED_FILE};
use crate::{ForkSyncRegistry, control, gc, snapshot_lock_for, upload};

/// Outcome of a single tick. `Stop` is returned when the fork directory has
/// disappeared and the per-volume task should exit.
pub enum TickOutcome {
    Continue,
    Stop,
}

/// How long an idle fork may go between displacement-fence checks. An
/// active tick (pending segments to drain) always re-checks; this bounds
/// how long a displaced-but-idle fork keeps its device up before the
/// fence halts and rehomes it.
const FENCE_HEARTBEAT: Duration = Duration::from_secs(60);

/// Result of re-reading `names/<name>` against this fork's ULID. The
/// two consumers dispose of the non-`Bound` cases differently — the
/// tick-top fence stays conservative (only `Displaced` fences), the
/// reap gate fails safe (anything but `Bound` skips the DELETEs) — so
/// the variants carry the facts and the call sites choose.
enum NameBinding {
    Bound,
    Displaced(elide_core::name_record::NameRecord),
    Missing,
    Unreadable(crate::name_store::NameStoreError),
}

/// Drives one drain + GC cycle per `run_tick()` call. Constructed once per
/// volume task; cross-tick state (`last_gc`, `gc_was_active`) lives on
/// `&mut self`.
pub struct GcCycleOrchestrator {
    fork_dir: PathBuf,
    by_id_dir: PathBuf,
    vol_ulid: Ulid,
    store: Arc<dyn ObjectStore>,
    /// `coord-rw` store for the drain's `meta/<vol>.{pub,provenance}`
    /// self-heal uploads — identity writes are coordinator-plane
    /// (`docs/design/mint-volume-attestation.md` § *New-volume bootstrap*).
    meta_store: Arc<dyn ObjectStore>,
    /// Typed handle for the per-volume `by_id/<vol>/…` objects. Used
    /// for HEAD ops; raw `store` is still used for object classes the
    /// domain layer doesn't yet vend (segments, snapshot manifests).
    volume_data: VolumeData,
    gc_config: GcConfig,
    snap_lock: Arc<AsyncMutex<()>>,
    last_gc: Instant,
    gc_was_active: bool,
    /// Cross-tick: last time the reap step fired. Gated on
    /// `gc_config.reaper_cadence()` (= `max(retention/10, 1s)`,
    /// unchanged from the old standalone reaper); see
    /// `docs/design/segment-index.md` *Reaper fold*.
    last_reap: Instant,
    /// Cross-tick: last time a cut landed in HEAD. The publish runs
    /// on `gc_config.cut_interval`, not per tick; bumped only when a
    /// cut actually publishes (or confirms nothing changed), so an
    /// idle stretch costs no latency once activity resumes.
    /// Constructed backdated so a fresh process cuts on its first
    /// active tick.
    last_cut: Instant,
    /// Cross-tick: last time the displacement fence completed a
    /// name-binding check. Constructed backdated so the first tick
    /// always checks; not bumped when the fence returns an outcome,
    /// so a failed halt retries on the very next tick.
    last_fence: Instant,
    /// Publish scratch: ULIDs uploaded (drain) or produced (GC output)
    /// since the last published cut — the signal that S3 segment state
    /// changed and a HEAD PUT is due. Kept across ticks until a publish
    /// lands, so a held or failed cut retries on the next complete
    /// drain.
    tick_added: Vec<Ulid>,
    /// Publish scratch: GC supersession edges — `(input, output,
    /// since)` — awaiting their cut. `since` is captured at handoff
    /// completion time per `docs/design/segment-index.md` (the GC
    /// output ULID is history-derived, not wall-clock). Kept across
    /// ticks until a publish lands them in HEAD's `Superseded` set.
    tick_superseded: Vec<(Ulid, Ulid, DateTime<Utc>)>,
    /// Monotonic tick counter, the clock for the supersession barrier
    /// below.
    tick_seq: u64,
    /// Tick of the last confirmed WAL flush — a successful
    /// `promote_wal` round trip, including the empty-WAL reply.
    last_flush_seq: u64,
    /// Tick of the last GC pass that could have emitted plans.
    /// Supersession edges publish only when a confirmed flush
    /// postdates it (`docs/design/durable-cut.md` *GC supersession
    /// waits for its killers*): the pass classifies liveness against
    /// the live WAL, so an input's block can be dead only to an
    /// uncommitted write. The post-pass flush seals every write the
    /// pass could have seen into `pending/`, and the complete-drain
    /// publish gate puts that flush segment inside any cut that
    /// carries the edges. Both counters start at zero, so a fresh
    /// process holds edges until its first confirmed flush covers
    /// whatever a pre-crash pass saw.
    last_plan_pass_seq: u64,
    /// One-shot per process: fold supersession edges missing from
    /// HEAD back in from the confirmed outputs' signed `inputs`
    /// tables, at the first edge-eligible publish. Held edges live in
    /// `tick_superseded` between cleanup and publish, so a crash in
    /// that window loses them from memory; the signed tables are the
    /// durable authority they re-derive from.
    reconcile_edges: bool,
    /// `coord-rw` handle for the `names/<name>.latest_snapshot` bump
    /// after a drain uploads a `User` manifest (the retry path for a
    /// manifest whose inline snapshot-op upload failed, and the import
    /// drain). The volume-rw `store` cannot write `names/*`.
    name_claims: Arc<dyn crate::name_claims::NameClaims>,
    /// Shared per-fork HEAD writer cache: the body of the last
    /// successful HEAD GET or PUT in this process. Shared with the
    /// seal-time truncation in `upload.rs`, which resets it to the
    /// truncated form. A warm cache lets the merge and the reap gate
    /// run without a per-pass HEAD GET.
    head_cache: crate::HeadCache,
    /// Name bound to this fork, if it has one. Nameless forks (pulled
    /// ancestors) have no `names/<name>` record to bump.
    volume_name: Option<String>,
    /// Coordinator identity — signs the `Displaced` event and stamps the
    /// rehomed name record when a displaced fork is fenced
    /// (`fence_if_displaced`).
    identity: Arc<crate::identity::CoordinatorIdentity>,
    /// Scoped stores — the rehome mints `names/<name>-<suffix>`
    /// and emits its `Displaced` event through these.
    stores: Arc<dyn crate::stores::ScopedStores>,
}

impl GcCycleOrchestrator {
    // A per-volume orchestrator is assembled from its collaborators (data
    // store, scoped stores, identity, config, locks); folding them into an
    // args struct would add ceremony without clarity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        fork_dir: PathBuf,
        vol_ulid: Ulid,
        store: Arc<dyn ObjectStore>,
        stores: &Arc<dyn crate::stores::ScopedStores>,
        gc_config: GcConfig,
        fork_sync: &ForkSyncRegistry,
        volume_name: Option<String>,
        identity: Arc<crate::identity::CoordinatorIdentity>,
    ) -> Self {
        let meta_store = stores.writer();
        let name_claims = stores.name_claims();
        let by_id_dir = fork_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| fork_dir.clone());
        let snap_lock = snapshot_lock_for(fork_sync, &fork_dir);
        let head_cache = crate::head_cache_for(fork_sync, &fork_dir);
        // Force GC and reap on the first tick only when local-fs
        // markers show work a previous run left mid-stream. A
        // quiescent fork starts both clocks at their natural cadence:
        // the forced reap's HEAD read is the first op on the volume's
        // `coord-data` facade, so an unconditional backdate costs one
        // mint round-trip per live volume on every coordinator start.
        let backdate = fork_has_local_backlog(&fork_dir);
        let now = Instant::now();
        let last_gc = if backdate {
            now.checked_sub(gc_config.interval).unwrap_or(now)
        } else {
            now
        };
        let last_reap = if backdate {
            now.checked_sub(gc_config.reaper_cadence()).unwrap_or(now)
        } else {
            now
        };
        let last_fence = now.checked_sub(FENCE_HEARTBEAT).unwrap_or(now);
        let last_cut = now.checked_sub(gc_config.cut_interval).unwrap_or(now);
        let volume_data = VolumeData::new(Arc::clone(&store), vol_ulid);
        Self {
            fork_dir,
            by_id_dir,
            vol_ulid,
            store,
            meta_store,
            volume_data,
            gc_config,
            snap_lock,
            last_gc,
            gc_was_active: true,
            last_reap,
            last_fence,
            last_cut,
            tick_added: Vec::new(),
            tick_superseded: Vec::new(),
            tick_seq: 0,
            last_flush_seq: 0,
            last_plan_pass_seq: 0,
            reconcile_edges: true,
            name_claims,
            head_cache,
            volume_name,
            identity,
            stores: Arc::clone(stores),
        }
    }

    pub fn fork_dir(&self) -> &Path {
        &self.fork_dir
    }

    /// Fence this fork if it has been displaced — another coordinator has
    /// force-claimed the name and `names/<name>` now binds a different fork.
    ///
    /// This is the previous-owner half of forced-claim fencing
    /// (`docs/design/displaced-fork-rehome.md`). The credential-liveness
    /// fence (`docs/design/force-release-fencing.md`) is the load-bearing
    /// safety for the *claimant*; this stops the *guest* writing into a WAL
    /// that can no longer drain. It is conservative: only a definite
    /// mismatch fences — a missing record or a read error leaves the fork
    /// alone and lets the credential fence backstop.
    ///
    /// Halts the device, then rehomes the fork under
    /// `<name>-<suffix>` (a first-class released volume,
    /// recovered by reclaim-then-start) and drops the stale local name
    /// binding. Returns `Some(Stop)` once halted (the per-volume task then
    /// exits), `Some(Continue)` to retry a failed halt next tick, or `None`
    /// when the fork is still the bound owner.
    /// One `names/<name>` GET, compared against this fork's ULID. Every
    /// claim episode mints a fresh fork ULID, so a matching ULID means
    /// the binding is still this episode's.
    async fn read_binding(&self, name: &str) -> NameBinding {
        match self.name_claims.read(name).await {
            Ok(Some(rec)) if rec.vol_ulid == self.vol_ulid => NameBinding::Bound,
            Ok(Some(rec)) => NameBinding::Displaced(rec),
            Ok(None) => NameBinding::Missing,
            Err(e) => NameBinding::Unreadable(e),
        }
    }

    async fn fence_if_displaced(&self) -> Option<TickOutcome> {
        let name = self.volume_name.as_ref()?;
        let rec = match self.read_binding(name).await {
            NameBinding::Bound => return None,
            NameBinding::Displaced(rec) => rec,
            NameBinding::Missing => {
                warn!(
                    "[fence {}] names/{name} record is gone; not fencing",
                    self.vol_ulid
                );
                return None;
            }
            NameBinding::Unreadable(e) => {
                warn!(
                    "[fence {}] reading names/{name}: {e}; not fencing",
                    self.vol_ulid
                );
                return None;
            }
        };

        warn!(
            "[fence {}] names/{name} now binds {} (coordinator {}); \
             fencing + rehoming",
            self.vol_ulid,
            rec.vol_ulid,
            rec.coordinator_id.as_deref().unwrap_or("?")
        );

        // Stop the device first: the guest must stop writing into a WAL
        // that can no longer drain.
        let bound_id = crate::ublk_sweep::bound_ublk_id(&self.fork_dir);
        let prev_pid = crate::ublk_sweep::read_volume_pid(&self.fork_dir);
        match control::shutdown(&self.fork_dir).await {
            control::ShutdownOutcome::Acknowledged | control::ShutdownOutcome::NotRunning => {}
            control::ShutdownOutcome::Failed(msg) => {
                warn!(
                    "[fence {}] shutdown failed: {msg}; retrying next tick",
                    self.vol_ulid
                );
                return Some(TickOutcome::Continue);
            }
        }

        // The daemon parks its kernel device QUIESCED for a fast re-serve;
        // a displaced fork won't serve here again without an explicit
        // `start` (which re-ADDs at the persisted id), so del_dev it now.
        if let Some(id) = bound_id {
            if let Some(pid) = prev_pid {
                crate::ublk_sweep::wait_for_pid_exit(pid).await;
            }
            crate::ublk_sweep::teardown_bound_device(&self.fork_dir, id).await;
        }

        // Rehome the fork under <name>-<suffix> so it survives
        // as a first-class released volume, then drop our stale local binding.
        let data_dir = self.by_id_dir.parent().unwrap_or(&self.by_id_dir);
        match crate::rehome::rehome_displaced_fork(
            self.identity.as_ref(),
            self.stores.as_ref(),
            data_dir,
            &self.fork_dir,
            name,
            self.vol_ulid,
        )
        .await
        {
            Ok(new_name) => {
                let _ = std::fs::remove_file(data_dir.join("by_name").join(name));
                info!(
                    "[fence {}] rehomed as {new_name}; displaced by {}",
                    self.vol_ulid, rec.vol_ulid
                );
            }
            Err(e) => {
                // Fall back to stopped-but-not-rehomed; a later start
                // rehomes it via the start-refusal path.
                let _ = std::fs::write(self.fork_dir.join(STOPPED_FILE), "");
                warn!(
                    "[fence {}] rehoming displaced fork: {e}; left stopped",
                    self.vol_ulid
                );
            }
        }
        Some(TickOutcome::Stop)
    }

    pub async fn run_tick(&mut self) -> TickOutcome {
        if !self.fork_dir.exists() {
            info!(
                "[coordinator] fork removed, stopping: {}",
                self.fork_dir.display()
            );
            return TickOutcome::Stop;
        }

        // Fence and stop before any drain/GC if this fork has been
        // displaced — another coordinator now owns the name. The check
        // is one `names/<name>` GET per run, so it fires only when this
        // tick has segments to drain (guest writes are the risk the
        // fence exists for) or the idle heartbeat has elapsed — not on
        // every 5s tick of a quiescent fork.
        if pending_has_files(&self.fork_dir) || self.last_fence.elapsed() >= FENCE_HEARTBEAT {
            if let Some(outcome) = self.fence_if_displaced().await {
                return outcome;
            }
            self.last_fence = Instant::now();
        }

        // Skip drain/GC while an import is in its write phase (volume.importing
        // present but no control.sock yet). When both are present the import
        // is in its serve phase and is ready to handle promote IPC — fall
        // through to the normal drain path.
        if self.fork_dir.join(IMPORTING_FILE).exists()
            && !self.fork_dir.join("control.sock").exists()
        {
            return TickOutcome::Continue;
        }

        // Skip drain/GC while a snapshot is in flight for this volume. The
        // snapshot handler holds this lock for its full sequence (flush →
        // drain → sign manifest → upload); racing the tick loop against it
        // would reorder pending/ uploads against the manifest's index view.
        //
        // Cloning the Arc gives the guard an owner that is not borrowed
        // from `self`, so subsequent `&mut self` calls (e.g. `run_gc_pass`)
        // don't conflict with the live guard.
        let snap_lock = self.snap_lock.clone();
        let _snap_guard = match snap_lock.try_lock() {
            Ok(g) => g,
            Err(_) => {
                info!("[tick {}] skipped: snapshot lock held", self.vol_ulid);
                return TickOutcome::Continue;
            }
        };

        self.tick_seq += 1;
        if self.run_volume_compactions().await {
            self.last_flush_seq = self.tick_seq;
        }

        // GC preparation runs before the drain so the checkpoint's WAL
        // flush lands in `pending/` in time to drain — and so commit —
        // this same tick: the tick's cut then covers the frontier the
        // pass was checkpointed at (`docs/design/durable-cut.md` *The
        // tick anchors at one frontier*).
        let gc_due = self.last_gc.elapsed() >= self.gc_config.interval;
        let mut gc_buckets = None;
        if gc_due {
            // Finalize outstanding bare `gc/<ulid>` files first, independent
            // of `gc_checkpoint` and the drain outcome. A bare file is a
            // handoff the volume already committed (`.staged` → bare) but
            // which the coordinator has not yet uploaded + promoted. If the
            // coordinator crashes between those steps on a quiescent volume,
            // the next `gc_checkpoint` returns `Idle` (WAL empty + no
            // `.staged`), and gating cleanup behind the checkpoint would
            // strand the bare file indefinitely — `has_pending_results`
            // would then also block every future `gc_fork` pass. Always
            // run this.
            self.run_handoff_cleanup().await;
            gc_buckets = self.prepare_gc_pass().await;
        }

        let drain_ok = self.run_drain().await;

        if gc_due && drain_ok {
            if let Some(bucket_ulids) = gc_buckets {
                self.run_gc_pass(bucket_ulids).await;
            }
            self.last_gc = Instant::now();
        }
        // If !drain_ok: the pass is skipped and last_gc is not bumped, so
        // the next tick retries GC immediately once drain recovers.

        // Publish this tick's cut. All S3 segment operations for this
        // tick are durable before the HEAD overwrite — segments-before-
        // HEAD crash ordering (design *Writers and crash ordering*). An
        // idle tick (no drain, no GC outputs) is a no-op; only ticks
        // that actually changed S3 segment state pay the HEAD PUT.
        self.publish_head_delta(drain_ok).await;

        TickOutcome::Continue
    }

    /// Volume-side compactions (best-effort; skipped silently if the control
    /// socket is absent so that drain still runs for forks without a live
    /// volume process). Skipped for readonly volumes: flush/sweep/repack are
    /// WAL and compaction operations that only make sense for writable
    /// volumes. During an import serve phase, control.sock is bound by the
    /// import process which only handles promote IPC.
    ///
    /// Returns whether the WAL flush was confirmed — a successful
    /// `promote_wal` round trip, which replies only once the flush
    /// segment is in `pending/` (or the WAL was empty). The tick loop
    /// feeds this into the supersession barrier.
    async fn run_volume_compactions(&self) -> bool {
        if !self.fork_dir.join("control.sock").exists()
            || self.fork_dir.join("volume.readonly").exists()
        {
            return false;
        }

        let vol_ulid = self.vol_ulid;
        let flushed = control::promote_wal(&self.fork_dir).await;

        if let Some(s) = control::repack(&self.fork_dir).await
            && s.segments_compacted > 0
        {
            info!(
                "[drain {vol_ulid}] repack: {} segment(s), ~{} bytes freed",
                s.segments_compacted, s.bytes_freed
            );
        }

        // Alias-merge extent reclamation: rewrites LBA sub-ranges of bloated
        // hashes (partial-overwrite survivors) into fresh compact entries.
        // One candidate per tick caps per-tick latency; the scanner sorts
        // most-wasteful-first, so sustained bloat converges across ticks.
        // Default scanner thresholds gate tiny / weakly-bloated hashes out.
        if let Some(s) = control::reclaim(&self.fork_dir, Some(1)).await
            && s.runs_rewritten > 0
        {
            info!(
                "[drain {vol_ulid}] reclaim: scanned={} runs={} bytes={} discarded={}",
                s.candidates_scanned, s.runs_rewritten, s.bytes_rewritten, s.discarded,
            );
        }
        flushed
    }

    /// Drain pending segments to S3. Returns whether the drain completed —
    /// the gate for both this tick's GC pass and its cut publish. A drain
    /// failure forces the GC skip because pending segments that failed to
    /// promote still have no `cache/<ulid>.body` and would not appear in
    /// the GC candidate set, while their LBAs would be invisible to
    /// `collect_stats`; it holds the cut because a partial batch must
    /// never become visible (`docs/design/durable-cut.md`).
    async fn run_drain(&mut self) -> bool {
        if !self.fork_dir.join("pending").exists() {
            return true;
        }
        let vol_ulid = self.vol_ulid;
        match upload::drain_pending(
            &self.fork_dir,
            vol_ulid,
            &self.store,
            &self.meta_store,
            &self.head_cache,
        )
        .await
        {
            Ok(r) => {
                if r.seen > 0 {
                    info!(
                        "[drain {vol_ulid}] pending={} uploaded={} upload_failed={} promote_failed={}",
                        r.seen,
                        r.uploaded_ulids.len(),
                        r.upload_failed,
                        r.promote_failed,
                    );
                }
                if r.upload_failed > 0 {
                    error!(
                        "[drain {vol_ulid}] {} segment(s) failed to upload to S3; \
                         skipping GC this tick to preserve ULID ordering invariant",
                        r.upload_failed
                    );
                }
                if r.promote_failed > 0 {
                    warn!(
                        "[drain {vol_ulid}] {} segment(s) uploaded to S3 but volume \
                         promote IPC unavailable; skipping GC this tick to preserve \
                         ULID ordering invariant",
                        r.promote_failed
                    );
                }
                if let Some(snap) = r.published_user_snapshot
                    && let Some(name) = &self.volume_name
                    && let Err(e) = self
                        .name_claims
                        .record_latest_snapshot(name, vol_ulid, snap)
                        .await
                {
                    warn!(
                        "[drain {vol_ulid}] recording latest_snapshot {snap} \
                         on names/{name}: {e}"
                    );
                }
                self.tick_added.extend(r.uploaded_ulids);
                r.upload_failed == 0 && r.promote_failed == 0
            }
            Err(e) => {
                error!(
                    "[drain {vol_ulid}] drain error: {e:#}; \
                     skipping GC this tick to preserve ULID ordering invariant"
                );
                false
            }
        }
    }

    async fn run_handoff_cleanup(&mut self) {
        let vol_ulid = self.vol_ulid;
        match gc::apply_done_handoffs(&self.fork_dir, vol_ulid, &self.store).await {
            Ok(outcomes) => {
                if !outcomes.is_empty() {
                    info!("[gc {vol_ulid}] completed {} GC handoff(s)", outcomes.len());
                }
                // Stamp `since` once for the whole tick. The reaper
                // checks `since + retention_window <= now`; one-tick
                // precision is well inside the retention window's 10×
                // slack.
                let since = Utc::now();
                for outcome in outcomes {
                    if outcome.uploaded {
                        self.tick_added.push(outcome.output);
                    }
                    for input in outcome.inputs {
                        self.tick_superseded.push((input, outcome.output, since));
                    }
                }
            }
            Err(e) => error!("[gc {vol_ulid}] handoff cleanup error: {e:#}"),
        }
    }

    /// Publish this tick's cut: apply drain/GC/reap deltas to HEAD and
    /// overwrite. Runs only after a complete drain (`drain_ok`) — a
    /// partial drain publishes nothing, so HEAD only ever names whole
    /// cuts (`docs/design/durable-cut.md` *HEAD publishes complete
    /// drains only*); scratch and reap wait for the next complete tick.
    /// The reap step is folded in here (`docs/design/segment-index.md`
    /// *Reaper fold*) so a tick that fires drain + GC + reap still
    /// pays exactly one HEAD PUT.
    ///
    /// Single-writer-per-vol-epoch is structural (the per-volume tick
    /// loop is the sole writer for this volume); a plain merge + PUT,
    /// no CAS. The merge basis is the shared `head_cache` — the body
    /// of this process's last successful HEAD GET or PUT — so a warm
    /// cache costs no GET; the cache is seeded with one GET on the
    /// first pass after start, and re-seeded after a failed PUT or a
    /// failed seal-time truncation (`upload.rs` empties the cache on
    /// its failure paths). A lost HEAD self-heals on the next active
    /// tick's seed: `read` treats a 404 or unparseable body as empty,
    /// and we rewrite from the current truth.
    /// The cut's `added` universe: every confirmed segment
    /// (`index/<ulid>.idx`) with a ULID beyond `anchor`.
    fn confirmed_beyond(&self, anchor: Option<Ulid>) -> std::io::Result<Vec<Ulid>> {
        Ok(segment_head::confirmed_segments(&self.fork_dir, anchor)?
            .into_iter()
            .map(|(ulid, _)| ulid)
            .collect())
    }

    /// `true` when every confirmed segment (`index/<ulid>.idx`) above
    /// `anchor` is in the publish scratch and no supersession edges
    /// are in hand — the shape a legitimately empty HEAD has on a
    /// fresh volume or right after a seal. A confirmed segment beyond
    /// the scratch means the empty body lost committed entries; a
    /// held edge means a handoff just consumed inputs whose idx
    /// markers are gone, so the idx listing undercounts the cut and
    /// only regeneration (which re-adds consumed inputs from the
    /// outputs' signed tables) accounts for them. A listing error
    /// returns `false`, routing the caller to
    /// `segment_head::regenerate`, which reports it.
    fn empty_head_is_legitimate(&self, anchor: Option<Ulid>) -> bool {
        if !self.tick_superseded.is_empty() {
            return false;
        }
        let confirmed = match self.confirmed_beyond(anchor) {
            Ok(v) => v,
            Err(_) => return false,
        };
        let scratch: std::collections::HashSet<Ulid> = self.tick_added.iter().copied().collect();
        confirmed.iter().all(|u| scratch.contains(u))
    }

    async fn publish_head_delta(&mut self, drain_ok: bool) {
        let reap_due = self.last_reap.elapsed() >= self.gc_config.reaper_cadence();
        let has_scratch = !self.tick_added.is_empty() || !self.tick_superseded.is_empty();
        if !reap_due && !has_scratch {
            return;
        }
        // The cut cadence (`docs/design/durable-cut.md` *Relation to
        // the loss-window work*): a cut publishes on `cut_interval`,
        // not per tick. Between cuts the scratch and the reap wait,
        // and drained segments stay durable but invisible until the
        // next cut names them.
        if self.last_cut.elapsed() < self.gc_config.cut_interval {
            return;
        }
        if !drain_ok {
            info!(
                "[head {}] drain incomplete; holding this tick's cut",
                self.vol_ulid
            );
            return;
        }
        // Supersession barrier (`docs/design/durable-cut.md` *GC
        // supersession waits for its killers*): edges join a cut only
        // once a confirmed WAL flush postdates the last plan-emitting
        // pass. The pass classifies liveness against the live WAL, so
        // an input's block can be dead only to an uncommitted write;
        // the post-pass flush seals every write the pass could have
        // seen into `pending/`, and the complete-drain gate above puts
        // that flush segment inside any cut that carries the edges.
        // Until then the inputs stay in the live set and force-claim
        // resolves through them; an output alongside its still-live
        // inputs is harmless duplication.
        let edges_eligible = self.last_flush_seq > self.last_plan_pass_seq;

        // Cloning the Arc gives the guard an owner that is not
        // borrowed from `self`, so `reap_expired(&mut self, ..)` below
        // doesn't conflict with the live guard.
        let cell = Arc::clone(&self.head_cache);
        let mut cache = cell.lock().await;
        // The cache holds the last successfully read or PUT body, so a
        // cached value — including the empty-at-anchor form the seal
        // writes — is trusted as-is. A body from S3 is trusted when it
        // has entries, or when its emptiness is the legitimate shape
        // (every confirmed segment beyond its anchor is in this tick's
        // scratch). Anything else — a failed GET, or an empty body
        // that lost committed entries — is repaired by regenerating
        // the full delta from the fork directory, the authority HEAD
        // derives from. Merging the tick's scratch into an
        // assumed-empty HEAD would instead overwrite the object with
        // one tick's delta.
        let (mut head, repaired) = match cache.take() {
            Some(h) => (h, false),
            None => {
                let seed = match self.volume_data.head().read().await {
                    Ok(h) => Some(h),
                    Err(e) => {
                        warn!(
                            "[head {}] read failed: {e}; regenerating from local state",
                            self.vol_ulid
                        );
                        None
                    }
                };
                match seed {
                    Some(h) if !h.is_empty() => (h, false),
                    Some(h) if self.empty_head_is_legitimate(h.anchor) => (h, false),
                    _ => match segment_head::regenerate(&self.fork_dir) {
                        Ok(mut r) => {
                            // A regenerated body carries every edge the
                            // signed inputs tables record, so those
                            // edges ride the same barrier: eligible,
                            // they publish here; otherwise they wait
                            // for the reconcile at the first eligible
                            // publish. Stripping is safe because the
                            // regenerated `added` keeps the consumed
                            // inputs, so their claims stay visible
                            // until the edges commit.
                            if edges_eligible {
                                self.reconcile_edges = false;
                            } else {
                                r.superseded.clear();
                            }
                            let repaired = !r.is_empty();
                            (r, repaired)
                        }
                        Err(e) => {
                            warn!(
                                "[head {}] regenerate failed: {e}; retrying next tick",
                                self.vol_ulid
                            );
                            return;
                        }
                    },
                }
            }
        };

        let mut mutated = repaired;
        if reap_due {
            if self.reap_expired(&mut head).await {
                mutated = true;
            }
            self.last_reap = Instant::now();
        }

        // The cut's `added` set is derived at publish time: every
        // confirmed segment beyond the anchor is in it. Segments
        // confirmed by an earlier held tick, or by an upload whose
        // process died before publishing, join the cut here
        // (`docs/design/durable-cut.md` *HEAD publishes complete
        // drains only*).
        match self.confirmed_beyond(head.anchor) {
            Ok(confirmed) => {
                for u in confirmed {
                    if head.added.insert(u) {
                        mutated = true;
                    }
                }
            }
            Err(e) => {
                warn!(
                    "[head {}] index scan failed: {e}; holding this tick's cut",
                    self.vol_ulid
                );
                return;
            }
        }
        if edges_eligible {
            if self.reconcile_edges {
                match segment_head::confirmed_edges(&self.fork_dir, head.anchor) {
                    Ok(edges) => {
                        let now = Utc::now();
                        for (input, output) in edges {
                            if head.tombstoned.contains(&input)
                                || head.superseded.contains_key(&input)
                            {
                                continue;
                            }
                            head.superseded
                                .insert(input, segment_head::Supersession { output, since: now });
                            mutated = true;
                        }
                        self.reconcile_edges = false;
                    }
                    Err(e) => warn!(
                        "[head {}] edge reconcile failed: {e}; retrying next publish",
                        self.vol_ulid
                    ),
                }
            }
            // An edge is publishable only when its output sits above
            // the anchor. A handoff that straddled a seal has an
            // output at or below the new anchor — permanently
            // invisible, since the anchor only grows — while the
            // manifest may still cover its input; the edge would
            // remove the input from the live set with nothing visible
            // carrying its claims. Dropped edges leave the input to
            // the manifest and the objects to reconcile-reap.
            let mut straddled = 0usize;
            self.tick_superseded
                .retain(|(_, output, _)| match head.anchor {
                    Some(a) if *output <= a => {
                        straddled += 1;
                        false
                    }
                    _ => true,
                });
            if straddled > 0 {
                info!(
                    "[head {}] dropped {straddled} supersession edge(s) whose \
                     output a seal left below the anchor",
                    self.vol_ulid
                );
            }
            for (input, output, since) in &self.tick_superseded {
                let edge = segment_head::Supersession {
                    output: *output,
                    since: *since,
                };
                if head.superseded.insert(*input, edge) != Some(edge) {
                    mutated = true;
                }
            }
        } else if !self.tick_superseded.is_empty() {
            info!(
                "[head {}] holding {} supersession edge(s) for a post-pass WAL flush",
                self.vol_ulid,
                self.tick_superseded.len()
            );
        }

        if !mutated {
            self.tick_added.clear();
            if edges_eligible {
                self.tick_superseded.clear();
            }
            self.last_cut = Instant::now();
            *cache = Some(head);
            return;
        }
        match self.volume_data.head().put(&head).await {
            Ok(()) => {
                self.tick_added.clear();
                if edges_eligible {
                    self.tick_superseded.clear();
                }
                self.last_cut = Instant::now();
                *cache = Some(head);
            }
            // Cache stays empty and the scratch is kept: the next
            // pass re-reads S3 and re-merges the same deltas, which
            // heals the lost overwrite.
            Err(e) => warn!(
                "[head {}] put failed: {e}; \
                 self-heals on the next active tick",
                self.vol_ulid
            ),
        }
    }

    /// Reap step: walk HEAD's `Superseded` edges, DELETE the input
    /// objects whose `since + retention_window <= now`, and update
    /// `head` via `apply_reap`. Returns `true` if any input was
    /// reaped (the caller PUTs HEAD only when mutated). An expired
    /// input still present in the local committed tier is excluded
    /// and logged instead of deleted.
    ///
    /// Crash ordering (`docs/design/segment-index.md` *Writers and
    /// crash ordering*): DELETE the object first, *then* PUT HEAD
    /// dropping the `Superseded` edge / adding `Tombstoned`. A crash
    /// between leaves HEAD listing a gone object — readers tolerate
    /// the 404. The reverse order would leak the entry by dropping
    /// the tombstone record before the object delete succeeded.
    async fn reap_expired(&mut self, head: &mut segment_head::SegmentHead) -> bool {
        let now = Utc::now();
        let retention = match chrono::Duration::from_std(self.gc_config.retention_window) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "[reap {}] retention_window {:?} out of chrono::Duration range: {e}; \
                     skipping reap pass",
                    self.vol_ulid, self.gc_config.retention_window
                );
                return false;
            }
        };
        let expired: Vec<Ulid> = head
            .superseded
            .iter()
            .filter(|(_, edge)| edge.since + retention <= now)
            .map(|(input, _)| *input)
            .collect();
        if expired.is_empty() {
            // Nothing reapable yet, but superseded inputs may still be
            // inside their retention window — say so, or a segment
            // count read next to a "[gc] idle" line looks inexplicably
            // high while this queue drains.
            let waiting = head.superseded.len();
            if waiting > 0 {
                info!(
                    "[reap {}] {waiting} superseded segment(s) in retention window",
                    self.vol_ulid
                );
            }
            return false;
        }

        // Liveness backstop: never DELETE an object the local committed
        // tier still contains. A `Superseded` edge normally outlives the
        // input's `index/<ulid>.idx` by the whole retention window, so a
        // still-present member here means the fold's supersede was
        // recorded while the volume still serves from the input —
        // deleting the bytes would turn that divergence into permanent
        // loss. Skip the member (the edge stays, so it is re-examined
        // next tick) and say so loudly.
        let local_tier = match elide_core::segment::committed_tier_ulids(&self.fork_dir) {
            Ok(set) => set,
            Err(e) => {
                warn!(
                    "[reap {}] committed-tier scan failed: {e}; skipping reap pass",
                    self.vol_ulid
                );
                return false;
            }
        };
        let (still_local, to_reap): (Vec<Ulid>, Vec<Ulid>) =
            expired.into_iter().partition(|u| local_tier.contains(u));
        for input in &still_local {
            error!(
                "[reap {}] {input} is past retention in HEAD but present in the \
                 local committed tier; refusing to delete it",
                self.vol_ulid
            );
        }
        if to_reap.is_empty() {
            return false;
        }

        // Reap is the only destructive tick op: a `claim --force` on
        // another host may be copying these very objects, so re-check
        // `names/<name>` still binds this fork before DELETEing. Best
        // effort (check-then-act, one-tick window) — the claimant's
        // per-pass HEAD re-read remains the correctness backstop.
        if let Some(name) = &self.volume_name {
            match self.read_binding(name).await {
                NameBinding::Bound => {}
                NameBinding::Displaced(rec) => {
                    error!(
                        "[reap {}] names/{name} now binds {}; this fork has been \
                         displaced — skipping reap",
                        self.vol_ulid, rec.vol_ulid
                    );
                    return false;
                }
                NameBinding::Missing => {
                    error!(
                        "[reap {}] names/{name} record is gone; skipping reap",
                        self.vol_ulid
                    );
                    return false;
                }
                NameBinding::Unreadable(e) => {
                    warn!(
                        "[reap {}] reading names/{name}: {e}; skipping reap",
                        self.vol_ulid
                    );
                    return false;
                }
            }
        }

        // Fan the DELETEs out concurrently so the per-vol tick isn't
        // blocked on N sequential round-trips when retention expires
        // for a large batch at once. Concurrency cap matches the
        // peer-fetch / drain idiom — high enough to overlap latency,
        // low enough not to burst the bucket.
        use futures::stream::{self, StreamExt};
        const REAP_CONCURRENCY: usize = 16;
        let vol_ulid = self.vol_ulid;
        let vd = self.volume_data.clone();
        stream::iter(to_reap.iter().copied())
            .for_each_concurrent(REAP_CONCURRENCY, |input| {
                let segments = vd.segments();
                async move {
                    match segments.delete(input).await {
                        Ok(_) => {}
                        Err(crate::volume_data::SegmentsError::Delete(
                            object_store::Error::NotFound { .. },
                        )) => {}
                        Err(e) => {
                            // A failed DELETE is logged and retried
                            // on the next reap tick. The HEAD-after-
                            // object rule means a stale `Superseded`
                            // entry is harmless: readers tolerate the
                            // 404. `apply_reap` is still called
                            // unconditionally below because the
                            // tombstone is only over-recorded by one
                            // tick if it turns out the delete didn't
                            // land (benign).
                            warn!(
                                "[reap {vol_ulid}] delete {}: {e}; will retry",
                                segments.segment_key(input)
                            );
                        }
                    }
                }
            })
            .await;
        head.apply_reap(&to_reap);
        info!(
            "[reap {vol_ulid}] reaped {} input segment(s) past retention; \
             {} in retention window",
            to_reap.len(),
            head.superseded.len()
        );
        true
    }

    /// Checkpoint the volume for this tick's GC pass: flush the WAL
    /// (the flush segment joins `pending/` and drains with this tick's
    /// cut), run the own-segment divergence check, and apply staged
    /// handoffs. Returns the pre-minted bucket ULIDs when the pass may
    /// emit plans this tick.
    async fn prepare_gc_pass(&mut self) -> Option<Vec<Ulid>> {
        let vol_ulid = self.vol_ulid;
        let max_buckets = self.gc_config.max_buckets_per_tick.max(1);
        let checkpoint = control::gc_checkpoint(&self.fork_dir, max_buckets).await?;
        let bucket_ulids = checkpoint.bucket_ulids;

        // Divergence check (docs/design/read-state-divergence-check.md):
        // the daemon's committed-tier commitment must match this
        // coordinator's disk scan before a new plan is drawn against
        // that disk. Compared here, before the handoff apply below,
        // because an apply moves both views. A mismatch can be a benign
        // race with a concurrent drain promote, so the response is to
        // skip plan emission for this tick — staged handoffs still
        // apply (the volume revalidates every plan at its commit
        // point), and the next tick re-asks.
        let diverged = match &checkpoint.own_segments {
            None => false,
            Some(daemon) => match own_segments_commitment_from_disk(&self.fork_dir) {
                Ok(ref disk) if disk == daemon => false,
                Ok(disk) => {
                    warn!(
                        "[gc {vol_ulid}] own-segment divergence: daemon commits \
                         count={} xor={}, disk scan count={} xor={}; skipping \
                         plan emission this tick",
                        daemon.count, daemon.xor, disk.count, disk.xor
                    );
                    true
                }
                Err(e) => {
                    warn!(
                        "[gc {vol_ulid}] own-segment disk scan failed: {e}; \
                         skipping plan emission this tick"
                    );
                    true
                }
            },
        };

        // An apply whose outcome is unknown (timeout, error reply) may
        // still be running volume-side; emitting a plan now would race
        // it against state the plan has not seen. Defer to a later tick,
        // which re-asks and only plans after a confirmed apply pass.
        let handoffs_applied = match control::apply_gc_handoffs(&self.fork_dir).await {
            Some(n) => n,
            None => {
                warn!(
                    "[gc {vol_ulid}] apply-gc-handoffs outcome unknown; \
                     skipping plan emission this tick"
                );
                return None;
            }
        };
        if handoffs_applied > 0 {
            info!("[gc {vol_ulid}] volume applied {handoffs_applied} GC handoff(s)");
        }

        if diverged {
            return None;
        }
        Some(bucket_ulids)
    }

    async fn run_gc_pass(&mut self, bucket_ulids: Vec<Ulid>) {
        let vol_ulid = self.vol_ulid;
        let gc_result = {
            let fork_dir = self.fork_dir.clone();
            let by_id_dir = self.by_id_dir.clone();
            let gc_config = self.gc_config.clone();
            tokio::task::spawn_blocking(move || {
                gc::gc_fork(&fork_dir, &by_id_dir, &gc_config, bucket_ulids)
            })
            .await
            .unwrap_or_else(|e| Err(anyhow::anyhow!("gc task panicked: {e}")))
        };
        match gc_result {
            Ok(gc::GcStats {
                strategy: gc::GcStrategy::Compact,
                candidates,
                bytes_freed,
                dead_cleaned,
                buckets_emitted,
                deferred_cold,
                ..
            }) => {
                self.gc_was_active = true;
                self.last_plan_pass_seq = self.tick_seq;
                let cold_note = if deferred_cold > 0 {
                    format!(", {deferred_cold} cold-deferred")
                } else {
                    String::new()
                };
                info!(
                    "[gc {vol_ulid}] compact: {buckets_emitted} bucket(s), \
                     {candidates} input(s) ({dead_cleaned} dead{cold_note}), \
                     ~{bytes_freed} bytes freed"
                );
            }
            Ok(gc::GcStats {
                strategy: gc::GcStrategy::None(reason),
                total_segments,
                ..
            }) => {
                // Only the NoCandidates reason reflects a real idle-pass
                // result. NoIndex and PendingHandoffs are transient bail-outs
                // that do not advance the active→idle state — another tick
                // will re-evaluate once the bail condition clears. The
                // "volume applied" / "completed N handoff(s)" logs already
                // cover PendingHandoffs visibility.
                if matches!(reason, gc::NoneReason::NoCandidates) && self.gc_was_active {
                    info!(
                        "[gc {vol_ulid}] idle — {total_segments} segment(s), \
                         nothing eligible (threshold {:.2})",
                        self.gc_config.density_threshold
                    );
                    self.gc_was_active = false;
                }
            }
            Err(e) => {
                // A failed pass may have staged plans before erroring;
                // treat it as plan-emitting for the barrier.
                self.last_plan_pass_seq = self.tick_seq;
                error!("[gc {vol_ulid}] error: {e:#}");
            }
        }
    }
}

/// Commitment over the committed-tier segment set as this coordinator
/// sees it on disk, from the same `segment::committed_tier_ulids` scan
/// that seeds the daemon's `own_segments` at open — the two sides of
/// the divergence check share one set definition.
fn own_segments_commitment_from_disk(
    fork_dir: &Path,
) -> std::io::Result<elide_core::volume_ipc::SegmentSetCommitment> {
    Ok(elide_core::volume_ipc::SegmentSetCommitment::from_ulids(
        elide_core::segment::committed_tier_ulids(fork_dir)?,
    ))
}

/// Local-fs preflight: does this fork hold work a previous run left
/// mid-stream? True when `pending/` contains any file (segments not
/// yet promoted to S3) or `gc/` holds a bare volume-applied handoff
/// awaiting upload. Best-effort: an unreadable dir counts as no
/// backlog — a false negative defers the forced first-tick pass to
/// the natural cadence, with no correctness consequence.
fn fork_has_local_backlog(fork_dir: &Path) -> bool {
    if pending_has_files(fork_dir) {
        return true;
    }
    let gc_dir = fork_dir.join("gc");
    if !gc_dir.is_dir() {
        return false;
    }
    gc::collect_bare_handoffs(&gc_dir)
        .map(|bare| !bare.is_empty())
        .unwrap_or(false)
}

/// `pending/` holds segments the volume flushed but the drain has not
/// yet promoted to S3 — the signal that this fork has guest writes in
/// flight. An absent or unreadable dir counts as empty.
fn pending_has_files(fork_dir: &Path) -> bool {
    std::fs::read_dir(fork_dir.join("pending"))
        .map(|mut entries| entries.next().is_some())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    //! HEAD-merge integration for the per-volume tick loop.
    //!
    //! `publish_head_delta` is the only path that writes
    //! `by_id/<vol>/HEAD` outside the seal-time truncation in
    //! `upload.rs`. These tests construct a minimal orchestrator
    //! against an in-memory `ObjectStore` and exercise it through the
    //! same scratch-buffer interface the production tick uses.
    use super::*;
    use crate::segment_head::{self, Supersession};
    use elide_core::ulid_mint::UlidMint;
    use object_store::memory::InMemory;
    use tempfile::TempDir;

    fn vol_ulid() -> Ulid {
        Ulid::from_string("01J0000000000000000000000V").unwrap()
    }

    fn vd_for(store: Arc<dyn ObjectStore>) -> VolumeData {
        VolumeData::new(store, vol_ulid())
    }

    async fn read_head_via(store: &Arc<dyn ObjectStore>) -> segment_head::SegmentHead {
        vd_for(Arc::clone(store)).head().read().await.unwrap()
    }

    async fn put_head_via(store: &Arc<dyn ObjectStore>, head: &segment_head::SegmentHead) {
        vd_for(Arc::clone(store)).head().put(head).await.unwrap();
    }

    fn orchestrator(store: Arc<dyn ObjectStore>) -> (GcCycleOrchestrator, TempDir) {
        orchestrator_named(store, None)
    }

    fn orchestrator_named(
        store: Arc<dyn ObjectStore>,
        volume_name: Option<&str>,
    ) -> (GcCycleOrchestrator, TempDir) {
        orchestrator_prepped(store, volume_name, |_| {})
    }

    /// `prep` runs against the fork dir before the orchestrator is
    /// constructed, so tests can plant backlog markers the constructor
    /// preflight must see.
    fn orchestrator_prepped(
        store: Arc<dyn ObjectStore>,
        volume_name: Option<&str>,
        prep: impl FnOnce(&Path),
    ) -> (GcCycleOrchestrator, TempDir) {
        let tmp = TempDir::new().unwrap();
        // Build `<tmp>/by_id/<vol>/` so by_id_dir resolves to a real
        // path; the orchestrator's tick logic exists() checks the fork
        // dir but the publish_head_delta path does not touch the fs.
        let by_id = tmp.path().join("by_id");
        std::fs::create_dir_all(&by_id).unwrap();
        let vol = vol_ulid();
        let fork_dir = by_id.join(vol.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        prep(&fork_dir);
        let locks = crate::new_fork_sync_registry();
        let stores: Arc<dyn crate::stores::ScopedStores> =
            Arc::new(crate::stores::PassthroughStores::new(Arc::clone(&store)));
        let identity =
            Arc::new(crate::identity::CoordinatorIdentity::load_or_generate(tmp.path()).unwrap());
        // Zero cut interval: these tests exercise the publish body,
        // not the cadence; the cadence tests set a real interval.
        let gc_config = crate::config::GcConfig {
            cut_interval: Duration::ZERO,
            ..crate::config::GcConfig::default()
        };
        let orch = GcCycleOrchestrator::new(
            fork_dir,
            vol,
            store,
            &stores,
            gc_config,
            &locks,
            volume_name.map(String::from),
            identity,
        );
        (orch, tmp)
    }

    #[tokio::test]
    async fn idle_tick_writes_nothing() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator(store.clone());
        orch.publish_head_delta(true).await;
        // Empty scratch ⇒ no PUT ⇒ no HEAD object in the store.
        let res = store.get(&segment_head::head_key(vol_ulid())).await;
        assert!(
            matches!(res, Err(object_store::Error::NotFound { .. })),
            "idle tick must not create HEAD"
        );
    }

    #[tokio::test]
    async fn drain_only_tick_publishes_added() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let a2 = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, a1, &[]);
            plant_confirmed_segment(fork, a2, &[]);
        });
        orch.tick_added.push(a1);
        orch.tick_added.push(a2);

        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&a1));
        assert!(head.added.contains(&a2));
        assert!(head.superseded.is_empty());
        assert!(head.tombstoned.is_empty());
        // Scratch must drain so the next tick starts fresh.
        assert!(orch.tick_added.is_empty());
    }

    #[tokio::test]
    async fn handoff_tick_publishes_added_output_and_superseded_inputs() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let input_a = m.next();
        let input_b = m.next();
        let output = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, output, &[input_a, input_b]);
        });
        orch.last_flush_seq = 1;
        orch.reconcile_edges = false;
        let since = Utc::now();
        orch.tick_added.push(output);
        orch.tick_superseded.push((input_a, output, since));
        orch.tick_superseded.push((input_b, output, since));

        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&output));
        assert_eq!(
            head.superseded.get(&input_a),
            Some(&Supersession { output, since })
        );
        assert_eq!(
            head.superseded.get(&input_b),
            Some(&Supersession { output, since })
        );
    }

    /// Plant `volume.pub` plus a signed, extracted `index/<seg>.idx`
    /// (with `inputs`) in the fork dir.
    fn plant_confirmed_segment(fork_dir: &Path, seg: Ulid, inputs: &[Ulid]) {
        use elide_core::signing;
        let key = match std::fs::read(fork_dir.join(signing::VOLUME_KEY_FILE)) {
            Ok(bytes) => {
                let arr: [u8; 32] = bytes.as_slice().try_into().unwrap();
                ed25519_dalek::SigningKey::from_bytes(&arr)
            }
            Err(_) => signing::generate_keypair(
                fork_dir,
                signing::VOLUME_KEY_FILE,
                signing::VOLUME_PUB_FILE,
            )
            .unwrap(),
        };
        let (signer, _) = signing::signer_from_bytes(&key.to_bytes()).unwrap();
        let index_dir = fork_dir.join("index");
        std::fs::create_dir_all(&index_dir).unwrap();
        let scratch = fork_dir.join(format!("{seg}.seg"));
        let body = vec![0xCD; 4096];
        let entries = vec![elide_core::segment::SegmentEntry::new_data(
            blake3::hash(&body),
            0,
            1,
            elide_core::segment::Codec::None,
            body,
        )];
        elide_core::segment::write_segment_full(&scratch, entries, &[], inputs, signer.as_ref())
            .unwrap();
        elide_core::segment::extract_idx(&scratch, &index_dir.join(format!("{seg}.idx"))).unwrap();
        std::fs::remove_file(&scratch).unwrap();
    }

    #[tokio::test]
    async fn missing_head_regenerates_prior_ticks_from_local_state() {
        // Regression: HEAD object gone (lost, or never readable) while
        // index/ records prior confirmed segments. The publish must
        // carry those segments, never overwrite HEAD with only the
        // current tick's scratch.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let prior = m.next();
        let gc_input = m.next();
        let gc_out = m.next();
        let fresh = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, prior, &[]);
            plant_confirmed_segment(fork, gc_out, &[gc_input]);
            plant_confirmed_segment(fork, fresh, &[]);
        });
        orch.last_flush_seq = 1;
        orch.tick_added.push(fresh);

        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&prior), "lost prior tick's segment");
        assert!(head.added.contains(&gc_out));
        assert!(head.added.contains(&fresh));
        assert_eq!(head.superseded[&gc_input].output, gc_out);
    }

    #[tokio::test]
    async fn held_cut_publishes_whole_on_next_complete_drain() {
        // A tick whose drain came up short publishes nothing — HEAD
        // only ever names whole cuts. The scratch survives the held
        // tick, and the next complete drain publishes everything.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let a2 = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, a1, &[]);
        });
        orch.tick_added.push(a1);

        orch.publish_head_delta(false).await;

        let res = store.get(&segment_head::head_key(vol_ulid())).await;
        assert!(
            matches!(res, Err(object_store::Error::NotFound { .. })),
            "a held cut must not touch HEAD"
        );
        assert!(!orch.tick_added.is_empty(), "scratch survives a held cut");

        plant_confirmed_segment(orch.fork_dir(), a2, &[]);
        orch.tick_added.push(a2);
        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&a1));
        assert!(head.added.contains(&a2));
    }

    #[tokio::test]
    async fn confirmed_segments_beyond_scratch_join_the_cut() {
        // A segment confirmed by a process that died between upload
        // and publish is in `index/` but in no scratch and no HEAD.
        // The cut's `added` set is derived from `index/` at publish
        // time, so the segment joins the next published cut.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let prior = m.next();
        let orphan = m.next();
        let fresh = m.next();

        let mut seed = segment_head::SegmentHead::empty(None);
        seed.added.insert(prior);
        put_head_via(&store, &seed).await;

        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, prior, &[]);
            plant_confirmed_segment(fork, orphan, &[]);
            plant_confirmed_segment(fork, fresh, &[]);
        });
        orch.tick_added.push(fresh);
        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(
            head.added.contains(&orphan),
            "confirmed but unpublished segment joins the cut"
        );
        assert!(head.added.contains(&fresh));
    }

    #[tokio::test]
    async fn superseded_edges_wait_for_a_post_pass_flush() {
        // Edges publish only once a confirmed WAL flush postdates the
        // last plan-emitting pass; the output's Added entry commits
        // immediately. Both counters start equal, so a fresh process
        // holds edges until its first confirmed flush.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let input = m.next();
        let output = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, output, &[input]);
        });
        orch.reconcile_edges = false;
        let since = Utc::now();
        orch.tick_added.push(output);
        orch.tick_superseded.push((input, output, since));

        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&output), "Added commits with the cut");
        assert!(
            head.superseded.is_empty(),
            "edges wait for a post-pass flush"
        );
        assert!(
            !orch.tick_superseded.is_empty(),
            "held edges stay in the scratch"
        );

        orch.last_flush_seq = 1;
        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert_eq!(head.superseded[&input].output, output);
        assert!(orch.tick_superseded.is_empty());
    }

    #[tokio::test]
    async fn crash_lost_edges_reconcile_from_signed_inputs() {
        // A crash between handoff cleanup and publish loses held edges
        // from memory. The first edge-eligible publish of a fresh
        // process re-derives them from the confirmed outputs' signed
        // inputs tables; tombstoned inputs stay tombstoned.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let reaped = m.next();
        let lost = m.next();
        let output = m.next();

        let mut seed = segment_head::SegmentHead::empty(None);
        seed.added.insert(output);
        seed.tombstoned.insert(reaped);
        put_head_via(&store, &seed).await;

        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, output, &[reaped, lost]);
        });
        orch.last_flush_seq = 1;
        orch.tick_added.push(output);

        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert_eq!(
            head.superseded[&lost].output, output,
            "lost edge re-derived from the output's signed inputs"
        );
        assert!(
            !head.superseded.contains_key(&reaped),
            "tombstoned inputs are not resurrected"
        );
        assert!(head.tombstoned.contains(&reaped));
    }

    #[tokio::test]
    async fn run_tick_without_volume_flush_holds_edges() {
        // With no volume process there is no flush confirmation, so a
        // tick publishes Added but keeps supersession edges in hand —
        // whether they arrive via the scratch or via regeneration.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let input = m.next();
        let output = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, output, &[input]);
        });
        orch.tick_superseded.push((input, output, Utc::now()));

        orch.run_tick().await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&output));
        assert!(head.superseded.is_empty());
        assert!(!orch.tick_superseded.is_empty());
    }

    #[tokio::test]
    async fn reap_held_when_drain_incomplete() {
        // Reap is destructive and rides the cut publish, so it too
        // waits for a complete drain.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator(store.clone());
        let mut m = UlidMint::new(Ulid::nil());
        let input = m.next();
        let output = m.next();
        let key = seed_expired_input(&store, &mut orch, input, output).await;

        orch.publish_head_delta(false).await;

        assert!(store.head(&key).await.is_ok(), "no DELETE on a held tick");
        let head = read_head_via(&store).await;
        assert!(head.superseded.contains_key(&input));
        assert!(head.tombstoned.is_empty());
    }

    #[tokio::test]
    async fn read_modify_write_unions_with_existing_head() {
        // Crash-recovery / restart equivalent: HEAD already carries
        // entries from a prior tick (or a prior coordinator), and this
        // tick merges *into* that state — never overwrites with only
        // the current scratch. Matches the design's *Writer state* rule:
        // "read-modify-write from S3 each active tick".
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let prior = m.next();
        let new = m.next();

        let mut seed = segment_head::SegmentHead::empty(None);
        seed.added.insert(prior);
        put_head_via(&store, &seed).await;

        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, new, &[]);
        });
        orch.tick_added.push(new);
        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&prior), "prior entry retained");
        assert!(head.added.contains(&new), "this tick's entry merged");
    }

    #[tokio::test]
    async fn reap_step_deletes_expired_inputs_and_tombstones_in_head() {
        // Seed HEAD with a Superseded edge whose `since` is well in
        // the past, plus an unrelated one inside the retention window.
        // The reap step deletes the expired input from S3 and tombstones
        // it in HEAD; the un-expired edge is left alone.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator(store.clone());
        // Speed the reap gate so it fires on the next publish.
        orch.last_reap = std::time::Instant::now()
            - orch.gc_config.reaper_cadence()
            - std::time::Duration::from_secs(1);

        let mut m = UlidMint::new(Ulid::nil());
        let input_expired = m.next();
        let input_fresh = m.next();
        let output = m.next();

        // Put the input segment objects in S3 (the reap step DELETEs by
        // key).
        let expired_key = crate::upload::segment_key(vol_ulid(), input_expired);
        let fresh_key = crate::upload::segment_key(vol_ulid(), input_fresh);
        store
            .put(&expired_key, bytes::Bytes::from_static(b"body").into())
            .await
            .unwrap();
        store
            .put(&fresh_key, bytes::Bytes::from_static(b"body").into())
            .await
            .unwrap();

        let mut head = segment_head::SegmentHead::empty(None);
        head.added.insert(output);
        let retention = orch.gc_config.retention_window;
        let expired_since = Utc::now()
            - chrono::Duration::from_std(retention).unwrap()
            - chrono::Duration::seconds(1);
        head.superseded.insert(
            input_expired,
            Supersession {
                output,
                since: expired_since,
            },
        );
        head.superseded.insert(
            input_fresh,
            Supersession {
                output,
                since: Utc::now(),
            },
        );
        put_head_via(&store, &head).await;

        orch.publish_head_delta(true).await;

        // Expired input: S3 object gone, HEAD edge replaced with
        // Tombstoned. Fresh input: untouched on both sides.
        assert!(
            matches!(
                store.head(&expired_key).await,
                Err(object_store::Error::NotFound { .. })
            ),
            "expired input segment must be deleted from S3"
        );
        assert!(
            store.head(&fresh_key).await.is_ok(),
            "fresh input segment must be retained"
        );

        let head = read_head_via(&store).await;
        assert!(!head.superseded.contains_key(&input_expired));
        assert!(head.tombstoned.contains(&input_expired));
        assert!(
            head.superseded.contains_key(&input_fresh),
            "fresh edge retained until its retention window elapses"
        );
        assert!(!head.tombstoned.contains(&input_fresh));
    }

    #[tokio::test]
    async fn reap_refuses_input_still_in_local_committed_tier() {
        // Two expired Superseded edges; one input's `index/<ulid>.idx`
        // is still present in the fork dir. The backstop must exclude
        // that input — S3 object retained, edge kept, no tombstone —
        // while the other input reaps normally.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let input_local = m.next();
        let input_gone = m.next();
        let output = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            let index = fork.join("index");
            std::fs::create_dir_all(&index).unwrap();
            std::fs::write(index.join(format!("{input_local}.idx")), b"idx").unwrap();
        });
        orch.last_reap = std::time::Instant::now()
            - orch.gc_config.reaper_cadence()
            - std::time::Duration::from_secs(1);

        let local_key = crate::upload::segment_key(vol_ulid(), input_local);
        let gone_key = crate::upload::segment_key(vol_ulid(), input_gone);
        for key in [&local_key, &gone_key] {
            store
                .put(key, bytes::Bytes::from_static(b"body").into())
                .await
                .unwrap();
        }

        let mut head = segment_head::SegmentHead::empty(None);
        head.added.insert(output);
        let expired_since = Utc::now()
            - chrono::Duration::from_std(orch.gc_config.retention_window).unwrap()
            - chrono::Duration::seconds(1);
        for input in [input_local, input_gone] {
            head.superseded.insert(
                input,
                Supersession {
                    output,
                    since: expired_since,
                },
            );
        }
        put_head_via(&store, &head).await;

        orch.publish_head_delta(true).await;

        assert!(
            store.head(&local_key).await.is_ok(),
            "input in the local committed tier must not be deleted"
        );
        assert!(
            matches!(
                store.head(&gone_key).await,
                Err(object_store::Error::NotFound { .. })
            ),
            "input absent from the local tier reaps normally"
        );
        let head = read_head_via(&store).await;
        assert!(
            head.superseded.contains_key(&input_local),
            "refused input keeps its edge for the next pass"
        );
        assert!(!head.tombstoned.contains(&input_local));
        assert!(head.tombstoned.contains(&input_gone));
    }

    #[tokio::test]
    async fn reap_skipped_when_no_superseded_entries() {
        // The reap step gate fires by time, but if HEAD has no
        // Superseded entries there's nothing to reap and HEAD is left
        // alone. We verify no PUT occurred by writing a marker body
        // and checking it survived.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator(store.clone());
        orch.last_reap = std::time::Instant::now()
            - orch.gc_config.reaper_cadence()
            - std::time::Duration::from_secs(1);

        // Seed an empty HEAD so reap finds nothing.
        let seed = segment_head::SegmentHead::empty(None);
        put_head_via(&store, &seed).await;

        // Replace HEAD with a known marker after seeding — we want to
        // confirm publish_head_delta does NOT overwrite when nothing
        // changed.
        let key = segment_head::head_key(vol_ulid());
        store
            .put(&key, bytes::Bytes::from_static(b"sentinel").into())
            .await
            .unwrap();

        orch.publish_head_delta(true).await;

        let got = store.get(&key).await.unwrap().bytes().await.unwrap();
        assert_eq!(
            got.as_ref(),
            b"sentinel",
            "publish must not PUT when no work was done"
        );
    }

    #[tokio::test]
    async fn warm_cache_is_the_merge_basis_not_s3() {
        // First publish seeds the cache (GET + PUT). A body written to
        // S3 behind the writer's back must not leak into the second
        // publish's merge: the sole-writer invariant means the cache
        // is the basis, and no per-pass GET happens once it is warm.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let foreign = m.next();
        let a2 = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, a1, &[]);
        });

        orch.tick_added.push(a1);
        orch.publish_head_delta(true).await;

        let mut planted = segment_head::SegmentHead::empty(None);
        planted.added.insert(foreign);
        put_head_via(&store, &planted).await;

        plant_confirmed_segment(orch.fork_dir(), a2, &[]);
        orch.tick_added.push(a2);
        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&a1));
        assert!(head.added.contains(&a2));
        assert!(
            !head.added.contains(&foreign),
            "a warm cache must be the merge basis; a per-pass GET would have absorbed the planted entry"
        );
    }

    #[tokio::test]
    async fn warm_cache_reap_gate_evaluates_locally() {
        // With a warm cache showing no Superseded edges, a due reap
        // pass issues no S3 ops at all. An expired edge planted in S3
        // behind the writer's back is the tripwire: a per-pass GET
        // would see it and DELETE the input object.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let input = m.next();
        let output = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, a1, &[]);
        });

        orch.tick_added.push(a1);
        orch.publish_head_delta(true).await;

        let key = seed_expired_input(&store, &mut orch, input, output).await;
        let planted = read_head_via(&store).await;

        orch.publish_head_delta(true).await;

        assert!(
            store.head(&key).await.is_ok(),
            "reap gate must evaluate the cached edge set, not re-read S3"
        );
        assert_eq!(
            read_head_via(&store).await,
            planted,
            "an idle reap pass with a warm cache must not PUT"
        );
    }

    /// Delegates to an inner store but fails `put_opts` while armed.
    #[derive(Debug)]
    struct PutFailOnce {
        inner: Arc<dyn ObjectStore>,
        armed: std::sync::atomic::AtomicBool,
    }

    impl std::fmt::Display for PutFailOnce {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "PutFailOnce")
        }
    }

    #[async_trait::async_trait]
    impl ObjectStore for PutFailOnce {
        async fn put_opts(
            &self,
            location: &object_store::path::Path,
            payload: object_store::PutPayload,
            opts: object_store::PutOptions,
        ) -> object_store::Result<object_store::PutResult> {
            if self.armed.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(object_store::Error::Generic {
                    store: "PutFailOnce",
                    source: "simulated put failure".into(),
                });
            }
            self.inner.put_opts(location, payload, opts).await
        }

        async fn put_multipart_opts(
            &self,
            location: &object_store::path::Path,
            opts: object_store::PutMultipartOpts,
        ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
            self.inner.put_multipart_opts(location, opts).await
        }

        async fn get_opts(
            &self,
            location: &object_store::path::Path,
            options: object_store::GetOptions,
        ) -> object_store::Result<object_store::GetResult> {
            self.inner.get_opts(location, options).await
        }

        async fn delete(&self, location: &object_store::path::Path) -> object_store::Result<()> {
            self.inner.delete(location).await
        }

        fn list(
            &self,
            prefix: Option<&object_store::path::Path>,
        ) -> futures::stream::BoxStream<'_, object_store::Result<object_store::ObjectMeta>>
        {
            self.inner.list(prefix)
        }

        async fn list_with_delimiter(
            &self,
            prefix: Option<&object_store::path::Path>,
        ) -> object_store::Result<object_store::ListResult> {
            self.inner.list_with_delimiter(prefix).await
        }

        async fn copy(
            &self,
            from: &object_store::path::Path,
            to: &object_store::path::Path,
        ) -> object_store::Result<()> {
            self.inner.copy(from, to).await
        }

        async fn copy_if_not_exists(
            &self,
            from: &object_store::path::Path,
            to: &object_store::path::Path,
        ) -> object_store::Result<()> {
            self.inner.copy_if_not_exists(from, to).await
        }
    }

    #[tokio::test]
    async fn failed_put_empties_cache_and_next_pass_reseeds() {
        // A failed HEAD PUT must leave the cache empty so the next
        // pass re-reads S3 before merging, and must keep the publish
        // scratch so the same deltas re-merge. The reseed is observable
        // because a body planted in S3 after the failure IS absorbed
        // by the next merge — the opposite of the warm-cache case.
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store: Arc<dyn ObjectStore> = Arc::new(PutFailOnce {
            inner: Arc::clone(&inner),
            armed: std::sync::atomic::AtomicBool::new(true),
        });
        let mut m = UlidMint::new(Ulid::nil());
        let input = m.next();
        let a1 = m.next();
        let planted_ulid = m.next();
        let a2 = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, a1, &[input]);
            plant_confirmed_segment(fork, a2, &[]);
        });
        orch.last_flush_seq = 1;
        orch.reconcile_edges = false;

        orch.tick_added.push(a1);
        orch.tick_superseded.push((input, a1, Utc::now()));
        orch.publish_head_delta(true).await;
        assert!(
            !orch.tick_superseded.is_empty(),
            "a failed PUT must keep the scratch for the retry"
        );

        let mut planted = segment_head::SegmentHead::empty(None);
        planted.added.insert(planted_ulid);
        vd_for(Arc::clone(&inner))
            .head()
            .put(&planted)
            .await
            .unwrap();

        orch.tick_added.push(a2);
        orch.publish_head_delta(true).await;

        let head = read_head_via(&inner).await;
        assert!(
            head.added.contains(&planted_ulid),
            "the pass after a failed PUT must reseed from S3"
        );
        assert!(head.added.contains(&a1), "kept scratch re-merges");
        assert!(head.added.contains(&a2));
        assert_eq!(
            head.superseded[&input].output, a1,
            "kept supersession edges re-merge after a failed PUT"
        );
    }

    /// Seed an expired Superseded edge for `input` (object body
    /// included) so the next reap pass would delete it.
    async fn seed_expired_input(
        store: &Arc<dyn ObjectStore>,
        orch: &mut GcCycleOrchestrator,
        input: Ulid,
        output: Ulid,
    ) -> object_store::path::Path {
        orch.last_reap = std::time::Instant::now()
            - orch.gc_config.reaper_cadence()
            - std::time::Duration::from_secs(1);
        let key = crate::upload::segment_key(vol_ulid(), input);
        store
            .put(&key, bytes::Bytes::from_static(b"body").into())
            .await
            .unwrap();
        let mut head = segment_head::SegmentHead::empty(None);
        head.added.insert(output);
        let since = Utc::now()
            - chrono::Duration::from_std(orch.gc_config.retention_window).unwrap()
            - chrono::Duration::seconds(1);
        head.superseded
            .insert(input, Supersession { output, since });
        put_head_via(store, &head).await;
        key
    }

    #[tokio::test]
    async fn reap_skipped_when_name_binds_another_fork() {
        // names/<name> has been rebound to another fork (a forced
        // claim displaced us). The ownership check must refuse the
        // DELETE and leave HEAD untouched.
        use crate::name_claims::NameClaims as _;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator_named(store.clone(), Some("vol"));
        let mut m = UlidMint::new(Ulid::nil());
        let input = m.next();
        let output = m.next();
        let usurper = m.next();

        let claims =
            crate::name_claims::BucketNameClaims::new(Arc::clone(&store), Arc::clone(&store));
        claims
            .mark_initial("vol", "other-coord", None, usurper, 1024)
            .await
            .unwrap();
        let key = seed_expired_input(&store, &mut orch, input, output).await;

        orch.publish_head_delta(true).await;

        assert!(
            store.head(&key).await.is_ok(),
            "a displaced fork must not delete segment objects"
        );
        let head = read_head_via(&store).await;
        assert!(head.superseded.contains_key(&input));
        assert!(head.tombstoned.is_empty());
    }

    #[tokio::test]
    async fn reap_proceeds_when_name_binds_this_fork() {
        use crate::name_claims::NameClaims as _;
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator_named(store.clone(), Some("vol"));
        let mut m = UlidMint::new(Ulid::nil());
        let input = m.next();
        let output = m.next();

        let claims =
            crate::name_claims::BucketNameClaims::new(Arc::clone(&store), Arc::clone(&store));
        claims
            .mark_initial("vol", "this-coord", None, vol_ulid(), 1024)
            .await
            .unwrap();
        let key = seed_expired_input(&store, &mut orch, input, output).await;

        orch.publish_head_delta(true).await;

        assert!(
            matches!(
                store.head(&key).await,
                Err(object_store::Error::NotFound { .. })
            ),
            "owner-bound fork reaps normally"
        );
        let head = read_head_via(&store).await;
        assert!(head.tombstoned.contains(&input));
    }

    #[tokio::test]
    async fn reap_skipped_when_name_record_missing() {
        // A named fork whose names/<name> record cannot be found must
        // fail safe: no record means ownership cannot be confirmed.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator_named(store.clone(), Some("vol"));
        let mut m = UlidMint::new(Ulid::nil());
        let input = m.next();
        let output = m.next();
        let key = seed_expired_input(&store, &mut orch, input, output).await;

        orch.publish_head_delta(true).await;

        assert!(store.head(&key).await.is_ok());
        let head = read_head_via(&store).await;
        assert!(head.superseded.contains_key(&input));
        assert!(head.tombstoned.is_empty());
    }

    #[tokio::test]
    async fn drain_followed_by_handoff_in_same_tick_publishes_once() {
        // The orchestrator's contract: at most one HEAD PUT per active
        // tick, regardless of how many sub-steps fired. Verified by
        // staging both drain *and* handoff scratch before calling
        // publish_head_delta and checking the resulting body reflects
        // both.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let drained = m.next();
        let input = m.next();
        let output = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, drained, &[]);
            plant_confirmed_segment(fork, output, &[input]);
        });
        orch.last_flush_seq = 1;
        orch.reconcile_edges = false;
        let since = Utc::now();
        orch.tick_added.push(drained);
        orch.tick_added.push(output);
        orch.tick_superseded.push((input, output, since));

        orch.publish_head_delta(true).await;

        let head = read_head_via(&store).await;
        assert!(head.added.contains(&drained));
        assert!(head.added.contains(&output));
        assert!(head.superseded.contains_key(&input));
    }

    #[tokio::test]
    async fn fence_skips_when_still_owner() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (orch, _tmp) = orchestrator_named(store.clone(), Some("vol2"));
        let rec = elide_core::name_record::NameRecord::live_minimal(vol_ulid(), 0);
        crate::name_store::create_name_record(&store, "vol2", &rec)
            .await
            .unwrap();
        assert!(orch.fence_if_displaced().await.is_none());
    }

    #[tokio::test]
    async fn fence_stops_and_rehomes_when_displaced() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (orch, tmp) = orchestrator_named(store.clone(), Some("vol2"));
        // names/vol2 now binds a different fork — this one is displaced.
        let other = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let rec = elide_core::name_record::NameRecord::live_minimal(other, 0);
        crate::name_store::create_name_record(&store, "vol2", &rec)
            .await
            .unwrap();

        assert!(matches!(
            orch.fence_if_displaced().await,
            Some(TickOutcome::Stop)
        ));

        // The displaced fork is rehomed as a Released volume under its
        // episode's derived name.
        let our = vol_ulid();
        let new_name = format!("vol2-{}", crate::rehome::rehome_suffix("vol2", our, 0));
        let rehomed = orch
            .name_claims
            .read(&new_name)
            .await
            .unwrap()
            .expect("displaced fork must be rehomed");
        assert_eq!(rehomed.vol_ulid, our);
        assert_eq!(rehomed.state, elide_core::name_record::NameState::Released);
        let fork_dir = tmp.path().join("by_id").join(our.to_string());
        assert!(fork_dir.join(crate::volume_state::RELEASED_FILE).exists());
        assert!(tmp.path().join("by_name").join(&new_name).exists());
    }

    #[tokio::test]
    async fn fence_skips_when_record_absent() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (orch, _tmp) = orchestrator_named(store, Some("vol2"));
        assert!(orch.fence_if_displaced().await.is_none());
    }

    #[tokio::test]
    async fn fence_skips_nameless_fork() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (orch, _tmp) = orchestrator(store);
        assert!(orch.fence_if_displaced().await.is_none());
    }

    /// Plant a `names/vol2` record binding a different fork, so any
    /// fence check that actually runs will fence this orchestrator.
    async fn displace(store: &Arc<dyn ObjectStore>) {
        let other = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let rec = elide_core::name_record::NameRecord::live_minimal(other, 0);
        crate::name_store::create_name_record(store, "vol2", &rec)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn fence_skipped_on_idle_tick_within_heartbeat() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, tmp) = orchestrator_named(store.clone(), Some("vol2"));
        displace(&store).await;
        orch.last_fence = std::time::Instant::now();

        assert!(matches!(orch.run_tick().await, TickOutcome::Continue));

        let new_name = format!(
            "vol2-{}",
            crate::rehome::rehome_suffix("vol2", vol_ulid(), 0)
        );
        assert!(
            orch.name_claims.read(&new_name).await.unwrap().is_none(),
            "idle tick inside the heartbeat must not run the fence"
        );
        assert!(!tmp.path().join("by_name").join(&new_name).exists());
    }

    #[tokio::test]
    async fn fence_runs_on_idle_tick_after_heartbeat() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator_named(store.clone(), Some("vol2"));
        displace(&store).await;
        orch.last_fence =
            std::time::Instant::now() - super::FENCE_HEARTBEAT - std::time::Duration::from_secs(1);

        assert!(matches!(orch.run_tick().await, TickOutcome::Stop));

        let new_name = format!(
            "vol2-{}",
            crate::rehome::rehome_suffix("vol2", vol_ulid(), 0)
        );
        assert!(
            orch.name_claims.read(&new_name).await.unwrap().is_some(),
            "heartbeat-due tick must fence and rehome"
        );
    }

    #[tokio::test]
    async fn fence_runs_on_active_tick_within_heartbeat() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (mut orch, _tmp) = orchestrator_named(store.clone(), Some("vol2"));
        displace(&store).await;
        orch.last_fence = std::time::Instant::now();
        let pending = orch.fork_dir().join("pending");
        std::fs::create_dir_all(&pending).unwrap();
        std::fs::write(pending.join("01ARZ3NDEKTSV4RRFFQ69G5FAV"), b"").unwrap();

        assert!(
            matches!(orch.run_tick().await, TickOutcome::Stop),
            "pending segments make the tick active; the fence must run"
        );
    }

    #[test]
    fn fork_quiescent_when_no_pending_or_gc_dir() {
        let tmp = TempDir::new().unwrap();
        assert!(!super::fork_has_local_backlog(tmp.path()));
        std::fs::create_dir_all(tmp.path().join("pending")).unwrap();
        std::fs::create_dir_all(tmp.path().join("gc")).unwrap();
        assert!(!super::fork_has_local_backlog(tmp.path()));
    }

    #[test]
    fn fork_has_backlog_when_pending_has_files() {
        let tmp = TempDir::new().unwrap();
        let pending = tmp.path().join("pending");
        std::fs::create_dir_all(&pending).unwrap();
        std::fs::write(pending.join("01ARZ3NDEKTSV4RRFFQ69G5FAV"), b"").unwrap();
        assert!(super::fork_has_local_backlog(tmp.path()));
    }

    #[test]
    fn fork_has_backlog_for_bare_gc_handoff() {
        let tmp = TempDir::new().unwrap();
        let gc = tmp.path().join("gc");
        std::fs::create_dir_all(&gc).unwrap();
        std::fs::write(gc.join("01ARZ3NDEKTSV4RRFFQ69G5FAV"), b"").unwrap();
        assert!(super::fork_has_local_backlog(tmp.path()));
    }

    #[test]
    fn fork_quiescent_when_gc_only_holds_staged_or_planned() {
        // A `.staged` file and a bare ULID with a `.plan` sibling are
        // mid-apply states the volume resolves on its next apply tick,
        // not coordinator backlog.
        let tmp = TempDir::new().unwrap();
        let gc = tmp.path().join("gc");
        std::fs::create_dir_all(&gc).unwrap();
        std::fs::write(gc.join("01ARZ3NDEKTSV4RRFFQ69G5FAV.staged"), b"").unwrap();
        std::fs::write(gc.join("01BX5ZZKBKACTAV9WEVGEMMVRZ.plan"), b"").unwrap();
        std::fs::write(gc.join("01BX5ZZKBKACTAV9WEVGEMMVRZ"), b"").unwrap();
        assert!(!super::fork_has_local_backlog(tmp.path()));
    }

    #[test]
    fn fork_quiescent_when_gc_holds_non_ulid_names() {
        let tmp = TempDir::new().unwrap();
        let gc = tmp.path().join("gc");
        std::fs::create_dir_all(&gc).unwrap();
        std::fs::write(gc.join("notaulid"), b"").unwrap();
        assert!(!super::fork_has_local_backlog(tmp.path()));
    }

    #[tokio::test]
    async fn constructor_defers_first_tick_on_quiescent_fork() {
        // orchestrator() builds an empty fork dir, so neither clock is
        // backdated: the first tick fires GC and reap on their natural
        // cadence, not immediately.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (orch, _tmp) = orchestrator(store);
        assert!(orch.last_gc.elapsed() < orch.gc_config.interval);
        assert!(orch.last_reap.elapsed() < orch.gc_config.reaper_cadence());
    }

    #[tokio::test]
    async fn constructor_forces_first_tick_on_backlogged_fork() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let (orch, _tmp) = orchestrator_prepped(store, None, |fork_dir| {
            let pending = fork_dir.join("pending");
            std::fs::create_dir_all(&pending).unwrap();
            std::fs::write(pending.join("01ARZ3NDEKTSV4RRFFQ69G5FAV"), b"").unwrap();
        });
        assert!(orch.last_gc.elapsed() >= orch.gc_config.interval);
        assert!(orch.last_reap.elapsed() >= orch.gc_config.reaper_cadence());
    }

    #[tokio::test]
    async fn cut_interval_holds_publish_between_cuts() {
        // A cut publishes on `cut_interval`, not per tick: after one
        // cut lands, further scratch — and a due reap — wait out the
        // window; an elapsed clock releases them. The clock starts
        // backdated by the interval (the constructor's init, redone
        // here because the fixture builds with a zero interval), so
        // the first active publish fires.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let a2 = m.next();
        let (mut orch, _tmp) = orchestrator_prepped(store.clone(), None, |fork| {
            plant_confirmed_segment(fork, a1, &[]);
        });
        orch.gc_config.cut_interval = Duration::from_secs(3600);
        orch.last_cut = std::time::Instant::now() - orch.gc_config.cut_interval;
        orch.tick_added.push(a1);
        orch.publish_head_delta(true).await;
        assert!(
            read_head_via(&store).await.added.contains(&a1),
            "first active publish cuts immediately (backdated clock)"
        );

        plant_confirmed_segment(orch.fork_dir(), a2, &[]);
        orch.tick_added.push(a2);
        orch.last_reap =
            std::time::Instant::now() - orch.gc_config.reaper_cadence() - Duration::from_secs(1);
        orch.publish_head_delta(true).await;
        let head = read_head_via(&store).await;
        assert!(
            !head.added.contains(&a2),
            "scratch waits inside the cut window"
        );
        assert!(
            !orch.tick_added.is_empty(),
            "held scratch survives for the next cut"
        );

        orch.last_cut =
            std::time::Instant::now() - orch.gc_config.cut_interval - Duration::from_secs(1);
        orch.publish_head_delta(true).await;
        assert!(
            read_head_via(&store).await.added.contains(&a2),
            "elapsed window releases the cut"
        );
    }

    /// Cut consistency oracle (`docs/design/durable-cut.md` *Testing*).
    ///
    /// A simulated guest writes an ordered history of 4 KiB blocks;
    /// the simulation seals, repacks (with elision and arbitrary
    /// output regrouping), drains with injected partial failures, runs
    /// GC passes classified against the full write frontier, seals
    /// snapshots, crashes the coordinator, damages HEAD, and fails
    /// HEAD GETs/PUTs — driving the real `publish_head_delta` and its
    /// scratch/barrier state throughout. After every remote mutation
    /// the oracle materialises the image exactly as force-claim's
    /// reader would (`read_status`, newest-seal fallback, `live_set`,
    /// highest-ULID resolution) and asserts it is a state the write
    /// history could have produced: some prefix of the acked writes,
    /// with every visible write preceded by all writes acked before
    /// it.
    mod cut_oracle {
        use super::*;
        use elide_core::segment::{Codec, SegmentEntry, SegmentSigner};
        use proptest::prelude::*;
        use std::collections::{BTreeMap, BTreeSet};
        use std::sync::atomic::{AtomicBool, Ordering};

        #[derive(Clone, Debug)]
        enum Op {
            Write {
                lba: u8,
            },
            Seal,
            Repack {
                bits: u8,
            },
            Tick {
                fail_after: Option<u8>,
                /// `promote_wal` confirmation: `false` models the
                /// volume process down or the IPC failing, so the tick
                /// runs with no flush and the WAL keeps its writes.
                flush_ok: bool,
                /// Whether `cut_interval` has elapsed by this tick's
                /// publish; `false` models the ticks inside a cut
                /// window, where everything waits.
                cut_due: bool,
            },
            GcPass,
            Snapshot,
            CrashCoordinator,
            DamageHead {
                delete: bool,
            },
            FailNextHeadPut,
            FailNextSeedGet,
            Reap,
        }

        fn arb_op() -> impl Strategy<Value = Op> {
            prop_oneof![
                8 => (0u8..6).prop_map(|lba| Op::Write { lba }),
                3 => Just(Op::Seal),
                2 => any::<u8>().prop_map(|bits| Op::Repack { bits }),
                6 => (
                    proptest::option::weighted(0.35, 0u8..3),
                    proptest::bool::weighted(0.85),
                    proptest::bool::weighted(0.7),
                )
                    .prop_map(|(fail_after, flush_ok, cut_due)| Op::Tick {
                        fail_after,
                        flush_ok,
                        cut_due,
                    }),
                2 => Just(Op::GcPass),
                1 => Just(Op::Snapshot),
                1 => Just(Op::CrashCoordinator),
                1 => proptest::bool::ANY.prop_map(|delete| Op::DamageHead { delete }),
                1 => Just(Op::FailNextHeadPut),
                1 => Just(Op::FailNextSeedGet),
                1 => Just(Op::Reap),
            ]
        }

        /// Delegates to an inner store; each armed flag fails exactly
        /// one HEAD operation. Faults are owner-side only — the
        /// oracle's reader materialises through the inner store, the
        /// way a claimant on another host would.
        #[derive(Debug)]
        struct FaultStore {
            inner: Arc<dyn ObjectStore>,
            fail_head_put: AtomicBool,
            fail_head_get: AtomicBool,
        }

        impl std::fmt::Display for FaultStore {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "FaultStore")
            }
        }

        fn is_head(location: &object_store::path::Path) -> bool {
            location.as_ref().ends_with("/HEAD")
        }

        fn fault() -> object_store::Error {
            object_store::Error::Generic {
                store: "FaultStore",
                source: "injected fault".into(),
            }
        }

        #[async_trait::async_trait]
        impl ObjectStore for FaultStore {
            async fn put_opts(
                &self,
                location: &object_store::path::Path,
                payload: object_store::PutPayload,
                opts: object_store::PutOptions,
            ) -> object_store::Result<object_store::PutResult> {
                if is_head(location) && self.fail_head_put.swap(false, Ordering::SeqCst) {
                    return Err(fault());
                }
                self.inner.put_opts(location, payload, opts).await
            }

            async fn put_multipart_opts(
                &self,
                location: &object_store::path::Path,
                opts: object_store::PutMultipartOpts,
            ) -> object_store::Result<Box<dyn object_store::MultipartUpload>> {
                self.inner.put_multipart_opts(location, opts).await
            }

            async fn get_opts(
                &self,
                location: &object_store::path::Path,
                options: object_store::GetOptions,
            ) -> object_store::Result<object_store::GetResult> {
                if is_head(location) && self.fail_head_get.swap(false, Ordering::SeqCst) {
                    return Err(fault());
                }
                self.inner.get_opts(location, options).await
            }

            async fn delete(
                &self,
                location: &object_store::path::Path,
            ) -> object_store::Result<()> {
                self.inner.delete(location).await
            }

            fn list(
                &self,
                prefix: Option<&object_store::path::Path>,
            ) -> futures::stream::BoxStream<'_, object_store::Result<object_store::ObjectMeta>>
            {
                self.inner.list(prefix)
            }

            async fn list_with_delimiter(
                &self,
                prefix: Option<&object_store::path::Path>,
            ) -> object_store::Result<object_store::ListResult> {
                self.inner.list_with_delimiter(prefix).await
            }

            async fn copy(
                &self,
                from: &object_store::path::Path,
                to: &object_store::path::Path,
            ) -> object_store::Result<()> {
                self.inner.copy(from, to).await
            }

            async fn copy_if_not_exists(
                &self,
                from: &object_store::path::Path,
                to: &object_store::path::Path,
            ) -> object_store::Result<()> {
                self.inner.copy_if_not_exists(from, to).await
            }
        }

        /// One simulated segment: entries map `lba → version`, where
        /// version is the 1-based index of the write in the history.
        #[derive(Clone, Debug)]
        struct Seg {
            ulid: Ulid,
            entries: BTreeMap<u8, usize>,
            inputs: Vec<Ulid>,
        }

        struct World {
            history: Vec<u8>,
            wal: Vec<usize>,
            pending: Vec<Seg>,
            handoff: Vec<Seg>,
            committed: Vec<Seg>,
            /// Every segment ever uploaded: the resolution table the
            /// oracle uses to turn a visible ULID set into an image.
            catalog: BTreeMap<Ulid, BTreeMap<u8, usize>>,
            mint: UlidMint,
            faults: Arc<FaultStore>,
            inner: Arc<dyn ObjectStore>,
            orch: GcCycleOrchestrator,
            fork_dir: std::path::PathBuf,
            signer: Arc<dyn SegmentSigner>,
            vk: ed25519_dalek::VerifyingKey,
            _tmp: TempDir,
        }

        fn body_for(lba: u8, version: usize) -> Vec<u8> {
            let mut body = vec![lba; 4096];
            body[..8].copy_from_slice(&(version as u64).to_le_bytes());
            body
        }

        impl World {
            fn new() -> Self {
                let tmp = TempDir::new().unwrap();
                let by_id = tmp.path().join("by_id");
                let fork_dir = by_id.join(vol_ulid().to_string());
                std::fs::create_dir_all(&fork_dir).unwrap();
                let key = elide_core::signing::generate_keypair(
                    &fork_dir,
                    elide_core::signing::VOLUME_KEY_FILE,
                    elide_core::signing::VOLUME_PUB_FILE,
                )
                .unwrap();
                let vk = key.verifying_key();
                let (signer, _) = elide_core::signing::signer_from_bytes(&key.to_bytes()).unwrap();
                let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
                let faults = Arc::new(FaultStore {
                    inner: Arc::clone(&inner),
                    fail_head_put: AtomicBool::new(false),
                    fail_head_get: AtomicBool::new(false),
                });
                let orch = Self::build_orch(&fork_dir, &faults, tmp.path());
                World {
                    history: Vec::new(),
                    wal: Vec::new(),
                    pending: Vec::new(),
                    handoff: Vec::new(),
                    committed: Vec::new(),
                    catalog: BTreeMap::new(),
                    mint: UlidMint::new(Ulid::nil()),
                    faults,
                    inner,
                    orch,
                    fork_dir,
                    signer,
                    vk,
                    _tmp: tmp,
                }
            }

            fn build_orch(
                fork_dir: &Path,
                faults: &Arc<FaultStore>,
                root: &Path,
            ) -> GcCycleOrchestrator {
                let store: Arc<dyn ObjectStore> = Arc::clone(faults) as Arc<dyn ObjectStore>;
                let locks = crate::new_fork_sync_registry();
                let stores: Arc<dyn crate::stores::ScopedStores> =
                    Arc::new(crate::stores::PassthroughStores::new(Arc::clone(&store)));
                let identity =
                    Arc::new(crate::identity::CoordinatorIdentity::load_or_generate(root).unwrap());
                GcCycleOrchestrator::new(
                    fork_dir.to_path_buf(),
                    vol_ulid(),
                    store,
                    &stores,
                    crate::config::GcConfig::default(),
                    &locks,
                    None,
                    identity,
                )
            }

            fn last_write(&self, lba: u8) -> Option<usize> {
                self.history.iter().rposition(|l| *l == lba).map(|i| i + 1)
            }

            fn seal(&mut self) {
                if self.wal.is_empty() {
                    return;
                }
                let mut entries = BTreeMap::new();
                for version in self.wal.drain(..) {
                    entries.insert(self.history[version - 1], version);
                }
                self.pending.push(Seg {
                    ulid: self.mint.next(),
                    entries,
                    inputs: Vec::new(),
                });
            }

            fn repack(&mut self, bits: u8) {
                if self.pending.is_empty() {
                    return;
                }
                let mut best: BTreeMap<u8, usize> = BTreeMap::new();
                for seg in &self.pending {
                    for (lba, v) in &seg.entries {
                        let e = best.entry(*lba).or_insert(*v);
                        *e = (*e).max(*v);
                    }
                }
                let mut groups: [BTreeMap<u8, usize>; 2] = Default::default();
                for (i, (lba, v)) in best.into_iter().enumerate() {
                    groups[usize::from((bits >> (i % 8)) & 1)].insert(lba, v);
                }
                self.pending.clear();
                for entries in groups.into_iter().filter(|g| !g.is_empty()) {
                    self.pending.push(Seg {
                        ulid: self.mint.next(),
                        entries,
                        inputs: Vec::new(),
                    });
                }
            }

            /// Write the signed, extracted `index/<ulid>.idx` marker a
            /// promote leaves behind.
            fn plant_idx(&self, seg: &Seg) {
                let index_dir = self.fork_dir.join("index");
                std::fs::create_dir_all(&index_dir).unwrap();
                let scratch = self.fork_dir.join(format!("{}.seg", seg.ulid));
                let entries: Vec<_> = seg
                    .entries
                    .iter()
                    .map(|(lba, v)| {
                        let body = body_for(*lba, *v);
                        SegmentEntry::new_data(
                            blake3::hash(&body),
                            u64::from(*lba),
                            1,
                            Codec::None,
                            body,
                        )
                    })
                    .collect();
                elide_core::segment::write_segment_full(
                    &scratch,
                    entries,
                    &[],
                    &seg.inputs,
                    self.signer.as_ref(),
                )
                .unwrap();
                elide_core::segment::extract_idx(
                    &scratch,
                    &index_dir.join(format!("{}.idx", seg.ulid)),
                )
                .unwrap();
                std::fs::remove_file(&scratch).unwrap();
            }

            async fn upload(&mut self, seg: Seg) {
                let key = crate::upload::segment_key(vol_ulid(), seg.ulid);
                self.inner
                    .put(&key, bytes::Bytes::from_static(b"seg").into())
                    .await
                    .unwrap();
                self.plant_idx(&seg);
                self.catalog.insert(seg.ulid, seg.entries.clone());
                self.orch.tick_added.push(seg.ulid);
                self.committed.push(seg);
            }

            async fn tick(&mut self, fail_after: Option<u8>, flush_ok: bool, cut_due: bool) {
                self.orch.tick_seq += 1;
                self.orch.last_cut = if cut_due {
                    Instant::now() - self.orch.gc_config.cut_interval - Duration::from_secs(1)
                } else {
                    Instant::now()
                };
                if flush_ok {
                    self.seal();
                    self.orch.last_flush_seq = self.orch.tick_seq;
                }

                // Handoff cleanup: upload prior GC outputs, record
                // their edges, retire the consumed inputs' idx — the
                // promote-apply shape (`volume/mod.rs`
                // `apply_promote_segment_result`).
                let expired = Utc::now()
                    - chrono::Duration::from_std(self.orch.gc_config.retention_window).unwrap()
                    - chrono::Duration::seconds(60);
                for out in std::mem::take(&mut self.handoff) {
                    for input in &out.inputs {
                        let _ = std::fs::remove_file(
                            self.fork_dir.join("index").join(format!("{input}.idx")),
                        );
                        self.committed.retain(|s| s.ulid != *input);
                        self.orch.tick_superseded.push((*input, out.ulid, expired));
                    }
                    if !out.entries.is_empty() {
                        self.upload(out).await;
                        self.check().await;
                    }
                }

                let take = fail_after.map_or(self.pending.len(), |k| {
                    usize::from(k).min(self.pending.len())
                });
                let drain_ok = take == self.pending.len();
                let batch: Vec<Seg> = self.pending.drain(..take).collect();
                for seg in batch {
                    self.upload(seg).await;
                    self.check().await;
                }

                self.orch.publish_head_delta(drain_ok).await;
                self.check().await;
            }

            fn gc_pass(&mut self) {
                if self.committed.is_empty() || !self.handoff.is_empty() {
                    return;
                }
                let inputs: Vec<Seg> = self.committed.iter().take(2).cloned().collect();
                let mut entries = BTreeMap::new();
                for seg in &inputs {
                    for (lba, v) in &seg.entries {
                        // The pass classifies against everything the
                        // volume knows, live WAL included: an entry is
                        // live only if it is the newest write to its
                        // block.
                        if self.last_write(*lba) == Some(*v) {
                            entries.insert(*lba, *v);
                        }
                    }
                }
                self.handoff.push(Seg {
                    ulid: self.mint.next(),
                    entries,
                    inputs: inputs.iter().map(|s| s.ulid).collect(),
                });
                self.orch.last_plan_pass_seq = self.orch.tick_seq;
            }

            async fn snapshot(&mut self) {
                self.seal();
                let batch: Vec<Seg> = self.pending.drain(..).collect();
                for seg in batch {
                    self.upload(seg).await;
                    self.check().await;
                }
                let snap = self.mint.next();
                let ulids: Vec<Ulid> = self.committed.iter().map(|s| s.ulid).collect();
                let manifest = elide_core::signing::build_snapshot_manifest_bytes(
                    self.signer.as_ref(),
                    &ulids,
                );
                let vd = crate::volume_data::VolumeData::new(Arc::clone(&self.inner), vol_ulid());
                vd.snapshots()
                    .put_manifest(snap, bytes::Bytes::from(manifest.clone()))
                    .await
                    .unwrap();
                vd.snapshots().bump_latest_if_newer(snap).await.unwrap();
                let snap_dir = self.fork_dir.join("snapshots");
                std::fs::create_dir_all(&snap_dir).unwrap();
                std::fs::write(snap_dir.join(format!("{snap}.manifest")), &manifest).unwrap();
                let truncated = segment_head::SegmentHead::empty(Some(snap));
                vd.head().put(&truncated).await.unwrap();
                *self.orch.head_cache.lock().await = Some(truncated);
                self.check().await;
            }

            async fn damage_head(&mut self, delete: bool) {
                let key = segment_head::head_key(vol_ulid());
                if delete {
                    match self.inner.delete(&key).await {
                        Ok(()) | Err(object_store::Error::NotFound { .. }) => {}
                        Err(e) => panic!("deleting HEAD: {e}"),
                    }
                } else {
                    self.inner
                        .put(&key, bytes::Bytes::from_static(b"damaged").into())
                        .await
                        .unwrap();
                }
                // The owner's cache no longer reflects the object;
                // model the next seed read hitting S3.
                *self.orch.head_cache.lock().await = None;
                self.check().await;
            }

            fn crash_coordinator(&mut self) {
                self.orch = Self::build_orch(&self.fork_dir, &self.faults, self._tmp.path());
            }

            /// Materialise the remote image exactly as force-claim's
            /// reader would (`force_claim.rs::re_own`): basis from
            /// LATEST, HEAD via `read_status`, damage anchored at the
            /// newest seal, frontier from the anchor manifest, then
            /// `live_set` and highest-ULID resolution. Assert the
            /// image is a prefix-consistent state of the write
            /// history.
            async fn check(&self) {
                let vd = crate::volume_data::VolumeData::new(Arc::clone(&self.inner), vol_ulid());
                let basis = vd.snapshots().read_latest().await.unwrap().map(|(u, _)| u);
                let manifest_for = |snap: Ulid| async move {
                    let vd =
                        crate::volume_data::VolumeData::new(Arc::clone(&self.inner), vol_ulid());
                    let m = vd.snapshots().get_manifest(snap, &self.vk).await.unwrap();
                    m.segment_ulids.into_iter().collect::<BTreeSet<Ulid>>()
                };
                let basis_segments = match basis {
                    Some(snap) => manifest_for(snap).await,
                    None => BTreeSet::new(),
                };
                let (frontier, head) = match vd.head().read_status().await.unwrap() {
                    Ok(h) => {
                        let frontier = match h.anchor {
                            Some(a) if basis.is_none_or(|b| a > b) => manifest_for(a).await,
                            _ => basis_segments,
                        };
                        (frontier, h)
                    }
                    Err(_) => {
                        let newest = vd.snapshots().newest_seal().await.unwrap();
                        let frontier = match newest {
                            Some(snap) => manifest_for(snap).await,
                            None => BTreeSet::new(),
                        };
                        (frontier, segment_head::SegmentHead::empty(newest))
                    }
                };
                let visible = segment_head::live_set(&frontier, &head);

                let mut image: BTreeMap<u8, usize> = BTreeMap::new();
                for ulid in &visible {
                    let entries = self
                        .catalog
                        .get(ulid)
                        .unwrap_or_else(|| panic!("visible segment {ulid} never uploaded"));
                    for (lba, v) in entries {
                        image.insert(*lba, *v);
                    }
                }

                let legal = (0..=self.history.len()).rev().any(|t| {
                    (0u8..8).all(|lba| {
                        let want = self.history[..t]
                            .iter()
                            .rposition(|l| *l == lba)
                            .map(|i| i + 1);
                        image.get(&lba).copied() == want
                    })
                });
                assert!(
                    legal,
                    "remote image is not a prefix of the write history\n\
                     history: {:?}\nimage: {image:?}\nvisible: {visible:?}\nhead: {head:?}",
                    self.history
                );
            }

            async fn step(&mut self, op: &Op) {
                match op {
                    Op::Write { lba } => {
                        self.history.push(*lba);
                        self.wal.push(self.history.len());
                    }
                    Op::Seal => self.seal(),
                    Op::Repack { bits } => self.repack(*bits),
                    Op::Tick {
                        fail_after,
                        flush_ok,
                        cut_due,
                    } => self.tick(*fail_after, *flush_ok, *cut_due).await,
                    Op::GcPass => self.gc_pass(),
                    Op::Snapshot => self.snapshot().await,
                    Op::CrashCoordinator => self.crash_coordinator(),
                    Op::DamageHead { delete } => self.damage_head(*delete).await,
                    Op::FailNextHeadPut => {
                        self.faults.fail_head_put.store(true, Ordering::SeqCst);
                    }
                    Op::FailNextSeedGet => {
                        self.faults.fail_head_get.store(true, Ordering::SeqCst);
                    }
                    Op::Reap => {
                        self.orch.last_reap = Instant::now()
                            - self.orch.gc_config.reaper_cadence()
                            - Duration::from_secs(1);
                    }
                }
            }
        }

        async fn run_case(ops: Vec<Op>) {
            let mut world = World::new();
            for op in &ops {
                world.step(op).await;
            }
            // Close out: a final complete tick, then one more so held
            // supersession edges get their post-pass flush and publish.
            world.tick(None, true, true).await;
            world.tick(None, true, true).await;
        }

        /// The oracle's first find, materialised: a GC handoff
        /// straddles a seal. The pass pre-mints its output ULID, the
        /// snapshot seals with the input still in the manifest and an
        /// anchor above the output, then handoff cleanup publishes the
        /// supersession edge — which would remove the manifest-covered
        /// input from the live set while the output stays permanently
        /// invisible below the anchor. The publish must drop that edge
        /// and leave the input to the manifest.
        #[tokio::test]
        async fn gc_handoff_straddling_a_seal_keeps_the_manifest_input_live() {
            let mut world = World::new();
            for op in [
                Op::Write { lba: 0 },
                Op::Tick {
                    fail_after: None,
                    flush_ok: true,
                    cut_due: true,
                },
                Op::GcPass,
                Op::Snapshot,
                Op::Write { lba: 1 },
                Op::Write { lba: 1 },
                Op::Tick {
                    fail_after: None,
                    flush_ok: true,
                    cut_due: true,
                },
                Op::Tick {
                    fail_after: None,
                    flush_ok: true,
                    cut_due: true,
                },
            ] {
                world.step(&op).await;
            }
            world.check().await;
        }

        /// The oracle's second find: HEAD damaged while a GC handoff
        /// is in flight and the killer write still in the WAL. The
        /// legitimacy gate must refuse the damaged-empty body (held
        /// edges mean the idx listing undercounts the cut), and
        /// regeneration must re-add the consumed inputs from the
        /// outputs' signed tables — dropping either leaves the input's
        /// claims out of the cut while its killer is uncommitted.
        #[tokio::test]
        async fn damaged_head_with_in_flight_handoff_keeps_consumed_inputs() {
            let mut world = World::new();
            for op in [
                Op::Write { lba: 2 },
                Op::Write { lba: 0 },
                Op::Tick {
                    fail_after: None,
                    flush_ok: true,
                    cut_due: true,
                },
                Op::DamageHead { delete: false },
                Op::Write { lba: 2 },
                Op::GcPass,
                Op::Tick {
                    fail_after: None,
                    flush_ok: false,
                    cut_due: true,
                },
            ] {
                world.step(&op).await;
            }
            let vd = crate::volume_data::VolumeData::new(Arc::clone(&world.inner), vol_ulid());
            let head = vd.head().read().await.unwrap();
            let ulids: Vec<Ulid> = world.catalog.keys().copied().collect();
            let [input, output] = ulids[..] else {
                panic!("expected exactly the input and the GC output uploaded")
            };
            assert!(
                head.added.contains(&input),
                "consumed input stays in the regenerated cut"
            );
            assert!(head.added.contains(&output));
        }

        proptest! {
            #![proptest_config(ProptestConfig {
                cases: std::env::var("PROPTEST_CASES")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(64),
                ..ProptestConfig::default()
            })]

            #[test]
            fn cut_consistency_oracle(ops in proptest::collection::vec(arb_op(), 1..35)) {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(run_case(ops));
            }
        }
    }
}
