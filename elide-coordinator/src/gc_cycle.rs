// Per-volume drain + GC tick orchestrator.
//
// Mechanical extraction of the tick body that used to live inline in
// `run_volume_tasks` (see `tasks.rs`). One `run_tick()` call performs the
// pre-flight checks, volume-side IPC compactions, S3 drain, and the
// rate-limited GC pass — same call order, same logs, same behaviour.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use object_store::ObjectStore;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{error, info, warn};
use ulid::Ulid;

use crate::config::GcConfig;
use crate::segment_head;
use crate::volume_data::VolumeData;
use crate::volume_state::IMPORTING_FILE;
use crate::{SnapshotLockRegistry, control, gc, snapshot_lock_for, upload};

/// Outcome of a single tick. `Stop` is returned when the fork directory has
/// disappeared and the per-volume task should exit.
pub enum TickOutcome {
    Continue,
    Stop,
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
    /// (`design-mint-volume-attestation.md` § *New-volume bootstrap*).
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
    /// `docs/design-segment-index.md` *Reaper fold*.
    last_reap: Instant,
    /// Per-tick scratch: ULIDs uploaded (drain) or produced (GC output)
    /// that must land in HEAD's `Added` set before this tick reports
    /// success. Cleared at the start of every `run_tick`.
    tick_added: Vec<Ulid>,
    /// Per-tick scratch: GC supersession edges produced this tick —
    /// `(input, output, since)` — that must land in HEAD's `Superseded`
    /// set. `since` is captured at handoff completion time per
    /// `docs/design-segment-index.md` (the GC output ULID is
    /// history-derived, not wall-clock).
    tick_superseded: Vec<(Ulid, Ulid, DateTime<Utc>)>,
    /// `coord-rw` handle for the `names/<name>.latest_snapshot` bump
    /// after a drain uploads a `User` manifest (the retry path for a
    /// manifest whose inline snapshot-op upload failed, and the import
    /// drain). The volume-rw `store` cannot write `names/*`.
    name_claims: Arc<dyn crate::name_claims::NameClaims>,
    /// Name bound to this fork, if it has one. Nameless forks (pulled
    /// ancestors) have no `names/<name>` record to bump.
    volume_name: Option<String>,
}

impl GcCycleOrchestrator {
    pub fn new(
        fork_dir: PathBuf,
        vol_ulid: Ulid,
        store: Arc<dyn ObjectStore>,
        stores: &Arc<dyn crate::stores::ScopedStores>,
        gc_config: GcConfig,
        snapshot_locks: &SnapshotLockRegistry,
        volume_name: Option<String>,
    ) -> Self {
        let meta_store = stores.writer();
        let name_claims = stores.name_claims();
        let by_id_dir = fork_dir
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| fork_dir.clone());
        let snap_lock = snapshot_lock_for(snapshot_locks, &fork_dir);
        // Run GC and reap on the first tick to clear any backlog from a
        // previous run.
        let last_gc = Instant::now()
            .checked_sub(gc_config.interval)
            .unwrap_or_else(Instant::now);
        let last_reap = Instant::now()
            .checked_sub(gc_config.reaper_cadence())
            .unwrap_or_else(Instant::now);
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
            tick_added: Vec::new(),
            tick_superseded: Vec::new(),
            name_claims,
            volume_name,
        }
    }

    pub fn fork_dir(&self) -> &Path {
        &self.fork_dir
    }

    pub async fn run_tick(&mut self) -> TickOutcome {
        if !self.fork_dir.exists() {
            info!(
                "[coordinator] fork removed, stopping: {}",
                self.fork_dir.display()
            );
            return TickOutcome::Stop;
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

        // Fresh scratch every tick — HEAD is read-modify-write per
        // active tick (`docs/design-segment-index.md` *Writer state*),
        // never accumulated across ticks in memory.
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
        // pay one GET + one PUT. A partial drain still publishes the
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

        // Phase 5 Tier 1: rewrite post-snapshot pending segments with
        // zstd-dictionary deltas against same-LBA extents from the latest
        // sealed snapshot. Runs before drain so converted segments reach S3
        // as thin Delta entries rather than full bodies.
        if let Some(s) = control::delta_repack_post_snapshot(&self.fork_dir).await
            && s.entries_converted > 0
        {
            info!(
                "[drain {vol_ulid}] delta_repack: {}/{} segment(s) rewritten, \
                 {} entries converted, {} → {} bytes",
                s.segments_rewritten,
                s.segments_scanned,
                s.entries_converted,
                s.original_body_bytes,
                s.delta_body_bytes,
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
        match upload::drain_pending(&self.fork_dir, vol_ulid, &self.store, &self.meta_store).await {
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
                // (folded into the tick loop in a follow-up PR) checks
                // `since + retention_window <= now`; one-tick precision
                // is well inside the retention window's 10× slack.
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

    /// Read HEAD once, apply this tick's drain/GC/reap deltas, and
    /// overwrite. The reap step is folded in here (`docs/design-
    /// segment-index.md` *Reaper fold*) so a tick that fires drain +
    /// GC + reap still pays exactly one GET + one PUT.
    ///
    /// Single-writer-per-vol-epoch is structural (the per-volume tick
    /// loop is the sole writer for this volume); a plain GET + merge +
    /// PUT, no CAS. A lost HEAD self-heals on the next active tick:
    /// `read_head` treats a 404 or unparseable body as empty, and we
    /// rewrite from the current truth.
    async fn publish_head_delta(&mut self) {
        let reap_due = self.last_reap.elapsed() >= self.gc_config.reaper_cadence();
        let has_scratch = !self.tick_added.is_empty() || !self.tick_superseded.is_empty();
        if !reap_due && !has_scratch {
            return;
        }

        let mut head = match self.volume_data.head().read().await {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    "[head {}] read failed: {e}; treating as empty",
                    self.vol_ulid
                );
                segment_head::SegmentHead::empty(None)
            }
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
            return;
        }
        if let Err(e) = self.volume_data.head().put(&head).await {
            warn!(
                "[head {}] put failed: {e}; \
                 self-heals on the next active tick",
                self.vol_ulid
            );
        }
    }

    /// Reap step: walk HEAD's `Superseded` edges, DELETE the input
    /// objects whose `since + retention_window <= now`, and update
    /// `head` via `apply_reap`. Returns `true` if any input was
    /// reaped (the caller PUTs HEAD only when mutated).
    ///
    /// Crash ordering (`docs/design-segment-index.md` *Writers and
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
        let to_reap: Vec<Ulid> = head
            .superseded
            .iter()
            .filter(|(_, edge)| edge.since + retention <= now)
            .map(|(input, _)| *input)
            .collect();
        if to_reap.is_empty() {
            return false;
        }

        // Reap is the only destructive tick op: a `claim --force` on
        // another host may be copying these very objects, so re-check
        // `names/<name>` still binds this fork before DELETEing. Best
        // effort (check-then-act, one-tick window) — the claimant's
        // per-pass HEAD re-read remains the correctness backstop.
        if let Some(name) = &self.volume_name {
            match self.name_claims.read(name).await {
                Ok(Some(rec)) if rec.vol_ulid == self.vol_ulid => {}
                Ok(Some(rec)) => {
                    error!(
                        "[reap {}] names/{name} now binds {}; this fork has been \
                         displaced — skipping reap",
                        self.vol_ulid, rec.vol_ulid
                    );
                    return false;
                }
                Ok(None) => {
                    error!(
                        "[reap {}] names/{name} record is gone; skipping reap",
                        self.vol_ulid
                    );
                    return false;
                }
                Err(e) => {
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
            "[reap {vol_ulid}] reaped {} input segment(s) past retention",
            to_reap.len()
        );
        true
    }

    async fn run_gc_pass(&mut self) {
        let vol_ulid = self.vol_ulid;
        let max_buckets = self.gc_config.max_buckets_per_tick.max(1);
        let Some(bucket_ulids) = control::gc_checkpoint(&self.fork_dir, max_buckets).await else {
            return;
        };

        let handoffs_applied = control::apply_gc_handoffs(&self.fork_dir).await;
        if handoffs_applied > 0 {
            info!("[gc {vol_ulid}] volume applied {handoffs_applied} GC handoff(s)");
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
        let tmp = TempDir::new().unwrap();
        // Build `<tmp>/by_id/<vol>/` so by_id_dir resolves to a real
        // path; the orchestrator's tick logic exists() checks the fork
        // dir but the publish_head_delta path does not touch the fs.
        let by_id = tmp.path().join("by_id");
        std::fs::create_dir_all(&by_id).unwrap();
        let vol = vol_ulid();
        let fork_dir = by_id.join(vol.to_string());
        std::fs::create_dir_all(&fork_dir).unwrap();
        let locks = crate::new_snapshot_lock_registry();
        let stores: Arc<dyn crate::stores::ScopedStores> =
            Arc::new(crate::stores::PassthroughStores::new(Arc::clone(&store)));
        let orch = GcCycleOrchestrator::new(
            fork_dir,
            vol,
            store,
            &stores,
            crate::config::GcConfig::default(),
            &locks,
            volume_name.map(String::from),
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
}
