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
    /// Cross-tick: last time the displacement fence completed a
    /// name-binding check. Constructed backdated so the first tick
    /// always checks; not bumped when the fence returns an outcome,
    /// so a failed halt retries on the very next tick.
    last_fence: Instant,
    /// Per-tick scratch: ULIDs uploaded (drain) or produced (GC output)
    /// that must land in HEAD's `Added` set before this tick reports
    /// success. Cleared at the start of every `run_tick`.
    tick_added: Vec<Ulid>,
    /// Per-tick scratch: GC supersession edges produced this tick —
    /// `(input, output, since)` — that must land in HEAD's `Superseded`
    /// set. `since` is captured at handoff completion time per
    /// `docs/design/segment-index.md` (the GC output ULID is
    /// history-derived, not wall-clock).
    tick_superseded: Vec<(Ulid, Ulid, DateTime<Utc>)>,
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
            tick_added: Vec::new(),
            tick_superseded: Vec::new(),
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

        // Fresh scratch every tick — entries land in HEAD via this
        // tick's merge-and-publish (`docs/design/segment-index.md`
        // *Writer state*).
        self.tick_added.clear();
        self.tick_superseded.clear();

        self.run_volume_compactions().await;
        let drain_ok = self.run_drain().await;

        if self.last_gc.elapsed() >= self.gc_config.interval {
            // Finalize outstanding bare `gc/<ulid>` files first, independent
            // of `gc_checkpoint` and `drain_ok`. A bare file is a handoff the
            // volume already committed (`.staged` → bare) but which the
            // coordinator has not yet uploaded + promoted. If the coordinator
            // crashes between those steps on a quiescent volume, the next
            // `gc_checkpoint` returns `Idle` (WAL empty + no `.staged`), and
            // gating cleanup behind the checkpoint would strand the bare file
            // indefinitely — `has_pending_results` would then also block
            // every future `gc_fork` pass. Always run this.
            self.run_handoff_cleanup().await;

            if drain_ok {
                self.run_gc_pass().await;
                self.last_gc = Instant::now();
            }
            // If !drain_ok: gc_pass is skipped and last_gc is not bumped, so
            // the next tick retries GC immediately once drain recovers.
        }

        // Publish the post-snapshot delta. All S3 segment operations
        // for this tick are durable before the HEAD overwrite —
        // segments-before-HEAD crash ordering (design *Writers and
        // crash ordering*). An idle tick (no drain, no GC outputs) is
        // a no-op; only ticks that actually changed S3 segment state
        // pay the HEAD PUT. A partial drain still publishes the
        // segments that did upload — they're durable in S3 and would
        // otherwise be invisible to readers until the next active tick.
        self.publish_head_delta().await;

        TickOutcome::Continue
    }

    /// Volume-side compactions (best-effort; skipped silently if the control
    /// socket is absent so that drain still runs for forks without a live
    /// volume process). Skipped for readonly volumes: flush/sweep/repack are
    /// WAL and compaction operations that only make sense for writable
    /// volumes. During an import serve phase, control.sock is bound by the
    /// import process which only handles promote IPC.
    async fn run_volume_compactions(&self) {
        if !self.fork_dir.join("control.sock").exists()
            || self.fork_dir.join("volume.readonly").exists()
        {
            return;
        }

        let vol_ulid = self.vol_ulid;
        control::promote_wal(&self.fork_dir).await;

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
    }

    /// Drain pending segments to S3. Returns whether GC may proceed: a drain
    /// failure forces this tick's GC to be skipped, since pending segments
    /// that failed to promote still have no `cache/<ulid>.body` and would
    /// not appear in the GC candidate set, while their LBAs would be
    /// invisible to `collect_stats`.
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
                    self.tick_added.push(outcome.output);
                    for input in outcome.inputs {
                        self.tick_superseded.push((input, outcome.output, since));
                    }
                }
            }
            Err(e) => error!("[gc {vol_ulid}] handoff cleanup error: {e:#}"),
        }
    }

    /// Apply this tick's drain/GC/reap deltas to HEAD and overwrite.
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
    async fn publish_head_delta(&mut self) {
        let reap_due = self.last_reap.elapsed() >= self.gc_config.reaper_cadence();
        let has_scratch = !self.tick_added.is_empty() || !self.tick_superseded.is_empty();
        if !reap_due && !has_scratch {
            return;
        }

        // Cloning the Arc gives the guard an owner that is not
        // borrowed from `self`, so `reap_expired(&mut self, ..)` below
        // doesn't conflict with the live guard.
        let cell = Arc::clone(&self.head_cache);
        let mut cache = cell.lock().await;
        // `trusted` is false only when the seed GET failed: the merge
        // proceeds against an assumed-empty HEAD (self-heal
        // semantics), but that fabricated value must not populate the
        // cache unless the PUT lands it in S3.
        let (mut head, trusted) = match cache.take() {
            Some(h) => (h, true),
            None => match self.volume_data.head().read().await {
                Ok(h) => (h, true),
                Err(e) => {
                    warn!(
                        "[head {}] read failed: {e}; treating as empty",
                        self.vol_ulid
                    );
                    (segment_head::SegmentHead::empty(None), false)
                }
            },
        };

        let mut mutated = has_scratch;
        if reap_due {
            if self.reap_expired(&mut head).await {
                mutated = true;
            }
            self.last_reap = Instant::now();
        }

        for u in self.tick_added.drain(..) {
            head.added.insert(u);
        }
        for (input, output, since) in self.tick_superseded.drain(..) {
            head.superseded
                .insert(input, segment_head::Supersession { output, since });
        }

        if !mutated {
            if trusted {
                *cache = Some(head);
            }
            return;
        }
        match self.volume_data.head().put(&head).await {
            Ok(()) => *cache = Some(head),
            // Cache stays empty: the next pass re-reads S3 before
            // merging, which is what heals the lost overwrite.
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

    async fn run_gc_pass(&mut self) {
        let vol_ulid = self.vol_ulid;
        let max_buckets = self.gc_config.max_buckets_per_tick.max(1);
        let Some(checkpoint) = control::gc_checkpoint(&self.fork_dir, max_buckets).await else {
            return;
        };
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
                return;
            }
        };
        if handoffs_applied > 0 {
            info!("[gc {vol_ulid}] volume applied {handoffs_applied} GC handoff(s)");
        }

        if diverged {
            return;
        }

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
            Err(e) => error!("[gc {vol_ulid}] error: {e:#}"),
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
        let orch = GcCycleOrchestrator::new(
            fork_dir,
            vol,
            store,
            &stores,
            crate::config::GcConfig::default(),
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
        orch.publish_head_delta().await;
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
        let (mut orch, _tmp) = orchestrator(store.clone());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let a2 = m.next();
        orch.tick_added.push(a1);
        orch.tick_added.push(a2);

        orch.publish_head_delta().await;

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
        let (mut orch, _tmp) = orchestrator(store.clone());
        let mut m = UlidMint::new(Ulid::nil());
        let input_a = m.next();
        let input_b = m.next();
        let output = m.next();
        let since = Utc::now();
        orch.tick_added.push(output);
        orch.tick_superseded.push((input_a, output, since));
        orch.tick_superseded.push((input_b, output, since));

        orch.publish_head_delta().await;

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

        let (mut orch, _tmp) = orchestrator(store.clone());
        orch.tick_added.push(new);
        orch.publish_head_delta().await;

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

        orch.publish_head_delta().await;

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

        orch.publish_head_delta().await;

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

        orch.publish_head_delta().await;

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
        let (mut orch, _tmp) = orchestrator(store.clone());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let foreign = m.next();
        let a2 = m.next();

        orch.tick_added.push(a1);
        orch.publish_head_delta().await;

        let mut planted = segment_head::SegmentHead::empty(None);
        planted.added.insert(foreign);
        put_head_via(&store, &planted).await;

        orch.tick_added.push(a2);
        orch.publish_head_delta().await;

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
        let (mut orch, _tmp) = orchestrator(store.clone());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let input = m.next();
        let output = m.next();

        orch.tick_added.push(a1);
        orch.publish_head_delta().await;

        let key = seed_expired_input(&store, &mut orch, input, output).await;
        let planted = read_head_via(&store).await;

        orch.publish_head_delta().await;

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
        // pass re-reads S3 before merging. The reseed is observable
        // because a body planted in S3 after the failure IS absorbed
        // by the next merge — the opposite of the warm-cache case.
        let inner: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let store: Arc<dyn ObjectStore> = Arc::new(PutFailOnce {
            inner: Arc::clone(&inner),
            armed: std::sync::atomic::AtomicBool::new(true),
        });
        let (mut orch, _tmp) = orchestrator(store.clone());
        let mut m = UlidMint::new(Ulid::nil());
        let a1 = m.next();
        let planted_ulid = m.next();
        let a2 = m.next();

        orch.tick_added.push(a1);
        orch.publish_head_delta().await;

        let mut planted = segment_head::SegmentHead::empty(None);
        planted.added.insert(planted_ulid);
        vd_for(Arc::clone(&inner))
            .head()
            .put(&planted)
            .await
            .unwrap();

        orch.tick_added.push(a2);
        orch.publish_head_delta().await;

        let head = read_head_via(&inner).await;
        assert!(
            head.added.contains(&planted_ulid),
            "the pass after a failed PUT must reseed from S3"
        );
        assert!(head.added.contains(&a2));
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

        orch.publish_head_delta().await;

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

        orch.publish_head_delta().await;

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

        orch.publish_head_delta().await;

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
        let (mut orch, _tmp) = orchestrator(store.clone());
        let mut m = UlidMint::new(Ulid::nil());
        let drained = m.next();
        let input = m.next();
        let output = m.next();
        let since = Utc::now();
        orch.tick_added.push(drained);
        orch.tick_added.push(output);
        orch.tick_superseded.push((input, output, since));

        orch.publish_head_delta().await;

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
}
