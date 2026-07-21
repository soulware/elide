//! Sweep / repack / delta-repack data types and the `impl Volume` blocks
//! that drive them.

use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use ulid::Ulid;

use crate::{
    extentindex, lbamap,
    segment::{self},
    segment_cache,
};

use super::{ResolvabilityGate, Volume, latest_snapshot};

/// Results from a single compaction run.
#[derive(Debug, Default, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct CompactionStats {
    /// Number of input segments consumed (deleted after compaction).
    pub segments_compacted: usize,
    /// Number of output segments written.
    pub new_segments: usize,
    /// Stored bytes reclaimed from deleted segment bodies.
    pub bytes_freed: u64,
    /// Number of dead extent entries removed from the extent index.
    pub extents_removed: usize,
    /// Buckets rolled back by the apply-time resolvability gate: a
    /// claim minted while the worker ran references an input-owned
    /// hash the output doesn't carry. Inputs kept, output dropped.
    #[serde(default)]
    pub buckets_refused: usize,
}

/// Data needed by the worker to repack sparse segments in `pending/`.
/// Produced by [`super::Volume::prepare_repack`] on the actor thread.
///
/// Per-segment output ULIDs are pre-minted in `output_ulids` (one per
/// pending segment at prep time, monotonically increasing, all below
/// `u_flush` and the next WAL ULID). The worker assigns them in
/// input-ULID order and only consumes as many as it actually rewrites.
///
/// `ceiling` is the WAL-flush ULID minted at prep time: every output
/// ULID is below it, so any pending segment with a strictly greater ULID
/// was minted after prep (e.g. by a `prepare_promote` racing under the
/// dropped lock) and the prep-time `lbamap_snapshot` knows nothing
/// about its entries. The worker skips such segments — including them
/// as bucket inputs would let `apply_repack_result` delete them and
/// clobber the lbamap claims they made.
pub struct RepackJob {
    pub base_dir: PathBuf,
    pub pending_dir: PathBuf,
    pub floor: Option<Ulid>,
    pub ceiling: Ulid,
    pub output_ulids: Vec<Ulid>,
    pub lbamap_snapshot: Arc<lbamap::LbaMap>,
    pub extent_index_snapshot: Arc<extentindex::ExtentIndex>,
    pub ancestor_layers: Vec<super::AncestorLayer>,
    pub fetcher: Option<segment::BoxFetcher>,
    pub signer: Arc<dyn segment::SegmentSigner>,
    pub verifying_key: ed25519_dalek::VerifyingKey,
    pub segment_cache: Arc<segment_cache::SegmentIndexCache>,
}

/// One bucket from a repack run. A bucket pairs N input segments (1
/// for solo rewrites, ≥2 for bin-packed merges) with a single rewrite
/// output, or with `output = None` when every input classified
/// fully dead — the input files are untouched by the worker either
/// way.
///
/// Apply (a) derives the per-input "to remove from extent_index" set
/// as `owned_hashes - carried_hashes(output)` and CAS-removes against
/// the per-input gate (`current loc.segment_id == input_ulid`), then
/// (b) inserts the carried entries under the same gate against the
/// new output ULID — both behind the resolvability gate — and (c)
/// returns each input file path for the caller to unlink once its
/// read snapshot is published.
pub struct RepackedBucket {
    pub inputs: Vec<RepackedInput>,
    pub output: Option<RepackedOutput>,
    pub bytes_freed: u64,
}

/// One selected input contributing to a [`RepackedBucket`].
pub struct RepackedInput {
    pub input_ulid: Ulid,
    pub input_path: PathBuf,
    pub owned_hashes: Vec<blake3::Hash>,
}

/// Materialised rewrite output for a repack bucket.
pub struct RepackedOutput {
    pub new_ulid: Ulid,
    pub new_body_section_start: u64,
    pub out_entries: Vec<segment::SegmentEntry>,
}

/// Result of a [`RepackJob`]. Consumed by [`super::Volume::apply_repack_result`]
/// on the actor thread.
pub struct RepackResult {
    pub stats: CompactionStats,
    pub buckets: Vec<RepackedBucket>,
}

impl Volume {
    /// Rewrite every pending segment with at least one hash-dead body
    /// entry under a freshly-minted ULID; all-dead segments produce no
    /// output and are unlinked after apply. Skips fully-live segments
    /// larger than the small threshold.
    /// Guarantees deleted data does not leave the host.
    ///
    /// Synchronous wrapper around [`Self::prepare_repack`] +
    /// [`crate::actor::execute_repack`] + [`Self::apply_repack_result`]
    /// for tests and inline callers; the actor uses the trio directly
    /// to offload the middle phase.
    pub fn repack(&mut self) -> io::Result<CompactionStats> {
        let Some(job) = self.prepare_repack()? else {
            return Ok(CompactionStats::default());
        };
        let result = crate::actor::execute_repack(job)?;
        let (stats, consumed_inputs) = self.apply_repack_result(result)?;
        self.remove_consumed_inputs(&consumed_inputs)?;
        Ok(stats)
    }

    /// Prep phase of `repack` — runs on the actor thread.
    ///
    /// Pre-mints `u_flush` and one output ULID per pending segment at
    /// prep time, then flushes the WAL into `pending/<u_flush>`. The
    /// pre-minted ULIDs are monotonically increasing and all sort
    /// below the next WAL ULID so subsequent flushes win on rebuild —
    /// preserves `max(pending) < running_WAL`. Snapshots `lbamap`,
    /// `extent_index`, `ancestor_layers`, and `fetcher` for the
    /// worker's classifier and body resolver.
    ///
    /// Returns `None` when `pending/` is missing or has no segments.
    pub fn prepare_repack(&mut self) -> io::Result<Option<RepackJob>> {
        let pending_dir = self.base_dir.join("pending");
        let segs = match segment::collect_segment_files(&pending_dir) {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        if segs.is_empty() {
            return Ok(None);
        }
        let floor = latest_snapshot(&self.base_dir)?;

        // Pre-mint output ULIDs (one per current pending segment plus
        // one for the WAL-flush peer that prepare creates next) and
        // u_flush. The WAL-flush peer can itself be hash-dead-bearing
        // — multiple writes to the same LBA inside one open WAL leave
        // the earlier hashes dead in the flushed segment — so the
        // worker may need to rewrite it too.
        let mut output_ulids: Vec<Ulid> = Vec::with_capacity(segs.len() + 1);
        for _ in 0..segs.len() + 1 {
            output_ulids.push(self.mint.next());
        }
        let u_flush = self.mint.next();
        self.flush_wal_to_pending_as(u_flush)?;

        Ok(Some(RepackJob {
            base_dir: self.base_dir.clone(),
            pending_dir,
            floor,
            ceiling: u_flush,
            output_ulids,
            lbamap_snapshot: Arc::clone(&self.lbamap),
            extent_index_snapshot: Arc::clone(&self.extent_index),
            ancestor_layers: self.ancestor_layers.clone(),
            fetcher: self.fetcher.clone(),
            signer: Arc::clone(&self.signer),
            verifying_key: self.verifying_key,
            segment_cache: Arc::clone(&self.segment_cache),
        }))
    }

    /// Apply phase of `repack` — runs on the actor thread after the
    /// worker returns.
    ///
    /// Each bucket's in-memory merge runs behind
    /// [`Self::mutate_gated_on_resolvability`]:
    ///   - CAS-remove dropped owned hashes (`current loc.segment_id ==
    ///     input_ulid`); concurrent writers that re-pointed the hash
    ///     win.
    ///   - If a fresh output was written: insert carried entries into
    ///     the extent index under the same per-input CAS gate, then
    ///     merge them into `self.lbamap` via `insert_if_newer` keyed
    ///     on `out.new_ulid`. Concurrent live writes have higher
    ///     claimant ULIDs and are preserved on overlapping LBAs.
    ///
    /// A refused bucket is rolled back whole: the worker classified
    /// against a prep-time lbamap snapshot, so a dedup ref minted
    /// while it ran can reference an input-owned hash the output
    /// doesn't carry. The output file is deleted, the inputs stay,
    /// and the next repack pass — whose prep snapshot includes the
    /// new claim — carries the hash.
    ///
    /// Applied buckets queue `pending/<input_ulid>` into the returned
    /// unlink list (for all-dead buckets too — `output: None`). The
    /// worker has already written `pending/<new_ulid>` separately.
    /// Each input's file-cache fd is evicted.
    ///
    /// The consumed input files are returned, not deleted: the caller
    /// must publish its read snapshot first and then pass them to
    /// [`Self::remove_consumed_inputs`] — deleting before publishing
    /// would leave the currently-published snapshot pointing at
    /// unlinked files, failing concurrent reads with `NotFound`.
    pub fn apply_repack_result(
        &mut self,
        result: RepackResult,
    ) -> io::Result<(CompactionStats, Vec<PathBuf>)> {
        let RepackResult { mut stats, buckets } = result;

        let pending_dir = self.base_dir.join("pending");
        let mut consumed_inputs: Vec<PathBuf> = Vec::new();

        for bucket in &buckets {
            let carried_hashes = bucket
                .output
                .as_ref()
                .map(|o| extentindex::ExtentIndex::carried_hashes(&o.out_entries))
                .unwrap_or_default();

            let bucket_input_ulids: std::collections::HashSet<Ulid> =
                bucket.inputs.iter().map(|i| i.input_ulid).collect();

            let delta_body_source = match &bucket.output {
                Some(out) => Some(extentindex::DeltaBodySource::full_for_segment(
                    &pending_dir.join(out.new_ulid.to_string()),
                    &out.out_entries,
                    out.new_body_section_start,
                )?),
                None => None,
            };

            let mut extents_removed = 0usize;
            let gate = self.mutate_gated_on_resolvability(|vol| {
                let index = Arc::make_mut(&mut vol.extent_index);

                // Per-input CAS-remove for hashes the bucket's output
                // didn't carry — gated on the specific input's ULID so
                // a concurrent writer that re-pointed the hash wins.
                for input in &bucket.inputs {
                    extents_removed += index.remove_input_owned(
                        input.input_ulid,
                        &input.owned_hashes,
                        &carried_hashes,
                    );
                }

                // Register carried entries against the new bucket
                // output as the disk rebuild would, gated on the
                // current owner being any of the bucket's inputs.
                if let Some(out) = &bucket.output {
                    let ctx = extentindex::SegmentRegistrationCtx {
                        segment_id: out.new_ulid,
                        body_section_start: out.new_body_section_start,
                        body_tier: extentindex::RegistrationBodyTier::Local,
                        // `delta_body_source` is Some whenever `bucket.output` is.
                        delta_body_source: delta_body_source
                            .ok_or_else(|| io::Error::other("repack: missing delta body source"))?,
                        inline: extentindex::InlineSource::EntryInline,
                    };
                    for (raw_idx, e) in out.out_entries.iter().enumerate() {
                        index.register_entry_consuming_inputs(
                            e,
                            raw_idx as u32,
                            &ctx,
                            &bucket_input_ulids,
                        )?;
                    }

                    let lbamap = Arc::make_mut(&mut vol.lbamap);
                    for e in &out.out_entries {
                        lbamap.register_entry_consuming_inputs(
                            e,
                            out.new_ulid,
                            &bucket_input_ulids,
                        );
                    }
                }
                Ok(())
            })?;

            let inputs_fmt = bucket
                .inputs
                .iter()
                .map(|i| i.input_ulid.to_string())
                .collect::<Vec<_>>()
                .join(",");

            if let ResolvabilityGate::Refused(orphaned) = gate {
                let detail = orphaned
                    .iter()
                    .map(|(lba, hash)| format!("lba={lba} hash={}", hash.to_hex()))
                    .collect::<Vec<_>>()
                    .join(", ");
                log::error!(
                    "repack [{inputs_fmt}]: refusing rewrite — {} lbamap-referenced hash(es) \
                     would be unresolvable through the extent index after apply: [{detail}]; \
                     dropping output and keeping inputs",
                    orphaned.len(),
                );
                stats.buckets_refused += 1;
                if let Some(out) = &bucket.output {
                    let _ = fs::remove_file(pending_dir.join(out.new_ulid.to_string()));
                }
                continue;
            }

            stats.extents_removed += extents_removed;

            if let Some(out) = &bucket.output {
                if self.last_segment_ulid < Some(out.new_ulid) {
                    self.last_segment_ulid = Some(out.new_ulid);
                }
                self.has_new_segments = true;
            }

            for input in &bucket.inputs {
                self.evict_cached_segment(input.input_ulid);
                consumed_inputs.push(input.input_path.clone());
            }

            stats.bytes_freed += bucket.bytes_freed;

            match &bucket.output {
                Some(out) => log::info!(
                    "repack: [{inputs_fmt}] -> {} ({} entries, {} bytes freed)",
                    out.new_ulid,
                    out.out_entries.len(),
                    bucket.bytes_freed,
                ),
                None => log::info!(
                    "repack: [{inputs_fmt}] -> deleted ({} bytes freed)",
                    bucket.bytes_freed,
                ),
            }
        }

        segment::fsync_dir(&pending_dir)?;

        Ok((stats, consumed_inputs))
    }

    /// Unlink input segment files consumed by a repack or delta-repack
    /// apply, then fsync `pending/`. Called after the read snapshot
    /// reflecting the apply has been published, so no published
    /// snapshot ever references an unlinked file.
    ///
    /// Already-missing files are fine — a previous partial unlink may
    /// have removed some of the batch.
    ///
    /// This is the end of the repack transaction, so the volume
    /// invariants are asserted here rather than in the apply phase:
    /// between apply and this unlink the consumed inputs are still on
    /// disk, and a disk rebuild ranks a still-present `u_flush` input
    /// above the pre-minted output ULIDs — content-equal but not
    /// claimant-equal to the in-memory maps.
    pub fn remove_consumed_inputs(&mut self, paths: &[PathBuf]) -> io::Result<()> {
        for path in paths {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        if !paths.is_empty() {
            segment::fsync_dir(&self.base_dir.join("pending"))?;
        }
        self.assert_volume_invariants("remove_consumed_inputs");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::*;
    use super::*;
    use std::fs;

    // --- compaction tests ---

    #[test]
    fn repack_noop_when_all_live() {
        // Write two blocks, promote, compact — nothing should be compacted
        // since all data is still referenced.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();
        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.write(1, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        let stats = vol.repack().unwrap();
        assert_eq!(stats.segments_compacted, 0);
        assert_eq!(stats.bytes_freed, 0);
        assert_eq!(stats.extents_removed, 0);

        // Data still readable.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x11u8; 4096]);
        assert_eq!(vol.read(1, 1).unwrap(), vec![0x22u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_reclaims_overwritten_extent() {
        // Write block A, promote, overwrite block A with B, promote.
        // First segment now has a dead extent; compaction should reclaim it.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let original = vec![0x11u8; 4096];
        let replacement = vec![0x22u8; 4096];

        vol.write(0, &original).unwrap();
        vol.promote_for_test().unwrap();

        vol.write(0, &replacement).unwrap();
        vol.promote_for_test().unwrap();

        // Two segments: first is 100% dead, second is live small.
        // The unified pass packs both into one bucket.
        let stats = vol.repack().unwrap();
        assert_eq!(
            stats.segments_compacted, 2,
            "both inputs go into the packed bucket"
        );
        assert_eq!(stats.new_segments, 1, "single packed output");
        assert!(stats.bytes_freed > 0);
        assert_eq!(stats.extents_removed, 1);

        // Data still reads back correctly after compaction.
        assert_eq!(vol.read(0, 1).unwrap(), replacement);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn apply_defers_input_unlink_to_remove_consumed_inputs() {
        // The apply phase must leave consumed input files on disk and
        // return their paths — the actor publishes its read snapshot
        // between apply and unlink, and an unlink inside apply would
        // fail reads served from the still-published pre-apply
        // snapshot.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.write(1, &vec![0x33u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(0, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        let job = vol.prepare_repack().unwrap().expect("repack job");
        let result = crate::actor::execute_repack(job).unwrap();
        let (stats, consumed) = vol.apply_repack_result(result).unwrap();

        assert!(stats.segments_compacted > 0);
        assert!(!consumed.is_empty(), "rewritten inputs must be returned");
        for path in &consumed {
            assert!(
                path.exists(),
                "consumed input {} must survive apply",
                path.display()
            );
        }
        // The live maps already resolve through the repack output.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);
        assert_eq!(vol.read(1, 1).unwrap(), vec![0x33u8; 4096]);

        vol.remove_consumed_inputs(&consumed).unwrap();
        for path in &consumed {
            assert!(!path.exists(), "{} must be unlinked", path.display());
        }
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);
        assert_eq!(vol.read(1, 1).unwrap(), vec![0x33u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_refuses_rewrite_when_dedup_ref_minted_in_worker_window() {
        // The worker classifies liveness against the prep-time lbamap
        // snapshot while the actor keeps serving writes. A write whose
        // content matches an input-owned extent mints a thin DedupRef
        // and never re-points the extent index, so the apply's CAS
        // gate alone would drop the canonical body out from under the
        // fresh claim. The resolvability gate must refuse the bucket.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let recurring = vec![0x11u8; 4096];
        let interim = vec![0x22u8; 4096];

        // The recurring content is a pending segment; its overwrite is
        // in the WAL at prep, so the snapshot sees the recurring hash
        // as dead.
        vol.write(0, &recurring).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(0, &interim).unwrap();

        let job = vol.prepare_repack().unwrap().expect("repack job");

        // Worker window: the recurring content returns as a DedupRef
        // against the repack input.
        vol.write(0, &recurring).unwrap();

        let result = crate::actor::execute_repack(job).unwrap();
        let (stats, consumed) = vol.apply_repack_result(result).unwrap();

        assert_eq!(stats.buckets_refused, 1);
        assert!(consumed.is_empty(), "refused bucket must keep its inputs");
        assert_eq!(vol.read(0, 1).unwrap(), recurring);

        // The next pass preps a snapshot that includes the claim,
        // carries the body, and converges.
        let stats = vol.repack().unwrap();
        assert_eq!(stats.buckets_refused, 0);
        assert_eq!(vol.read(0, 1).unwrap(), recurring);

        drop(vol);
        let vol = Volume::open(&base, &base).unwrap();
        assert_eq!(vol.read(0, 1).unwrap(), recurring);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn apply_gates_all_dead_bucket_and_defers_its_unlink() {
        // Apply-side contract for `output: None` buckets, which the
        // worker hands over with the input files untouched. The bucket
        // is synthesized directly: bin-packing folds an all-dead
        // candidate into the first live bucket, so the worker only
        // emits `output: None` when every candidate is dead — a
        // geometry ordered drains don't produce, but the branch must
        // still gate on current-lbamap resolvability.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let recurring = vec![0x11u8; 4096];
        let interim = vec![0x22u8; 4096];

        vol.write(0, &recurring).unwrap();
        vol.promote_for_test().unwrap();
        let (input_ulid, input_path) = {
            let mut paths: Vec<PathBuf> = fs::read_dir(base.join("pending"))
                .unwrap()
                .map(|e| e.unwrap().path())
                .collect();
            assert_eq!(paths.len(), 1);
            let path = paths.pop().unwrap();
            let ulid = Ulid::from_string(path.file_name().unwrap().to_str().unwrap()).unwrap();
            (ulid, path)
        };
        let all_dead_bucket = || RepackResult {
            stats: CompactionStats::default(),
            buckets: vec![RepackedBucket {
                inputs: vec![RepackedInput {
                    input_ulid,
                    input_path: input_path.clone(),
                    owned_hashes: vec![blake3::hash(&recurring)],
                }],
                output: None,
                bytes_freed: 4096,
            }],
        };

        // LBA 0 still claims the recurring hash, so removing the
        // input's extent entry must be refused and the file kept.
        let (stats, consumed) = vol.apply_repack_result(all_dead_bucket()).unwrap();
        assert_eq!(stats.buckets_refused, 1);
        assert!(consumed.is_empty(), "refused bucket must keep its inputs");
        assert!(input_path.exists());
        assert_eq!(vol.read(0, 1).unwrap(), recurring);

        // Once the claim moves off the recurring hash the same bucket
        // applies, and the input unlinks through the deferred path.
        vol.write(0, &interim).unwrap();
        let (stats, consumed) = vol.apply_repack_result(all_dead_bucket()).unwrap();
        assert_eq!(stats.buckets_refused, 0);
        assert_eq!(consumed, vec![input_path.clone()]);
        assert!(
            input_path.exists(),
            "unlink is deferred to remove_consumed_inputs"
        );
        vol.remove_consumed_inputs(&consumed).unwrap();
        assert!(!input_path.exists());
        assert_eq!(vol.read(0, 1).unwrap(), interim);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_reads_back_correctly_after_reopen() {
        // Verify that the compacted segment is a valid segment that survives
        // a volume reopen (LBA map rebuild + extent index rebuild).
        let base = keyed_temp_dir();

        {
            let mut vol = Volume::open(&base, &base).unwrap();
            vol.write(0, &vec![0xAAu8; 4096]).unwrap();
            vol.promote_for_test().unwrap();
            vol.write(0, &vec![0xBBu8; 4096]).unwrap(); // overwrite
            vol.promote_for_test().unwrap();
            vol.repack().unwrap();
        }

        let vol = Volume::open(&base, &base).unwrap();
        assert_eq!(vol.read(0, 1).unwrap(), vec![0xBBu8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_partial_segment() {
        // Segment has two extents; one is overwritten (dead), one is live.
        // Compaction should rewrite the segment keeping only the live extent.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &vec![0x11u8; 4096]).unwrap(); // will be overwritten
        vol.write(1, &vec![0x22u8; 4096]).unwrap(); // stays live
        vol.promote_for_test().unwrap();

        vol.write(0, &vec![0x33u8; 4096]).unwrap(); // overwrites LBA 0
        vol.promote_for_test().unwrap();

        // First segment has a hash-dead entry; second is small and live.
        // The unified pass packs both into one bucket.
        let stats = vol.repack().unwrap();
        assert_eq!(stats.segments_compacted, 2);
        assert_eq!(stats.new_segments, 1);
        assert!(stats.bytes_freed > 0);

        // Both LBAs read back correctly.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x33u8; 4096]);
        assert_eq!(vol.read(1, 1).unwrap(), vec![0x22u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_does_not_touch_pre_snapshot_segments() {
        // Write and overwrite a block, then snapshot. The dead segment is
        // pre-snapshot and must not be compacted — it is frozen by the floor.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(0, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        // Snapshot freezes both segments (floor = latest segment ULID).
        vol.snapshot().unwrap();

        // Even with a strict threshold the pre-snapshot segments must be skipped.
        let stats = vol.repack().unwrap();
        assert_eq!(
            stats.segments_compacted, 0,
            "pre-snapshot segments must not be compacted"
        );

        // Data still readable.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_only_touches_post_snapshot_segments() {
        // Pre-snapshot dead segment: frozen. Post-snapshot dead segment: compactable.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        // Pre-snapshot: write and overwrite LBA 0.
        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(0, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        vol.snapshot().unwrap();

        // Post-snapshot: write and overwrite LBA 1.
        vol.write(1, &vec![0x33u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(1, &vec![0x44u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        // Pre-snapshot dead segment is frozen; the two post-snapshot segments
        // (one dead, one live small) pack into one bucket.
        let stats = vol.repack().unwrap();
        assert_eq!(
            stats.segments_compacted, 2,
            "both post-snapshot segments are packed; pre-snapshot is frozen"
        );

        // Both LBAs read back correctly.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);
        assert_eq!(vol.read(1, 1).unwrap(), vec![0x44u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_does_not_touch_uploaded_segments() {
        // Simulate an uploaded segment (promoted to cache/ by the coordinator).
        // repack() must not touch it even if its extents are dead.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        // Simulate coordinator upload + promote IPC: pending → index/ + cache/.
        simulate_upload(&mut vol);

        // Overwrite LBA 0 — the uploaded segment's extent is now dead.
        vol.write(0, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        // Strict threshold: repack anything with dead bytes.
        let stats = vol.repack().unwrap();
        assert_eq!(
            stats.segments_compacted, 0,
            "repack must not touch uploaded (cache/) segments"
        );

        // Data still reads correctly.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    // --- packing-specific tests ---

    #[test]
    fn repack_removes_dead_extents() {
        // Write LBA 0, promote, overwrite LBA 0, promote.
        // repack should remove the dead extent from the first segment.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(0, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        let stats = vol.repack().unwrap();
        assert!(stats.segments_compacted >= 1);
        assert!(stats.bytes_freed > 0);
        assert_eq!(stats.extents_removed, 1);

        // Current value of LBA 0 must be the replacement.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_only_scans_pending_not_uploaded() {
        // Upload a segment (simulate coordinator promoting pending → cache/).
        // repack must not touch uploaded segments.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        // Simulate coordinator upload + promote IPC: pending → index/ + cache/.
        simulate_upload(&mut vol);

        // Now overwrite LBA 0 and promote — creates a new pending segment.
        vol.write(0, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        let stats = vol.repack().unwrap();
        // The old dead extent is in cache/ — repack doesn't touch it.
        assert_eq!(stats.extents_removed, 0);
        // The new pending segment is small and all-live: single segment, no
        // dead extents, so repack correctly leaves it alone.
        assert_eq!(stats.segments_compacted, 0);

        // Data still reads correctly.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_respects_snapshot_floor() {
        // Segments at or below the snapshot ULID must not be touched.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        // Write and promote before snapshot.
        vol.write(0, &vec![0x11u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(0, &vec![0x22u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        vol.snapshot().unwrap();

        // The two pre-snapshot segments are now frozen.
        let stats = vol.repack().unwrap();
        assert_eq!(
            stats.segments_compacted, 0,
            "pre-snapshot segments must not be touched"
        );

        assert_eq!(vol.read(0, 1).unwrap(), vec![0x22u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_multi_block_inplace_overwrite_same_wal() {
        // Regression: two multi-block DATA writes at the same LBA range in the
        // same WAL flush. Both land as DATA entries (different hashes) in one
        // pending segment. repack then partitions entries into live/dead,
        // rewrites the segment, and updates the extent index — the surviving
        // live entry must read back correctly from the rewritten segment.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        // High-entropy so neither payload is inlined and both stay in the
        // body section. Eight 4 KiB blocks each.
        let payload_a: Vec<u8> = (0..8 * 4096usize).map(|i| (i * 7 + 13) as u8).collect();
        let payload_b: Vec<u8> = (0..8 * 4096usize).map(|i| (i * 11 + 3) as u8).collect();
        assert_ne!(payload_a, payload_b);

        vol.write(24, &payload_a).unwrap();
        vol.write(24, &payload_b).unwrap();
        vol.flush_wal().unwrap();
        assert_eq!(
            vol.read(24, 8).unwrap(),
            payload_b,
            "pre-repack read must return the second write"
        );

        vol.repack().unwrap();
        assert_eq!(
            vol.read(24, 8).unwrap(),
            payload_b,
            "post-repack read must still return the second write"
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_merges_multiple_small_segments() {
        // Three separate promotes → three small pending segments.
        // repack should merge them into one.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &vec![0xaau8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(1, &vec![0xbbu8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(2, &vec![0xccu8; 4096]).unwrap();
        vol.promote_for_test().unwrap();

        let stats = vol.repack().unwrap();
        assert_eq!(stats.segments_compacted, 3);
        assert_eq!(stats.new_segments, 1);

        // All three LBAs must still read back correctly.
        assert_eq!(vol.read(0, 1).unwrap(), vec![0xaau8; 4096]);
        assert_eq!(vol.read(1, 1).unwrap(), vec![0xbbu8; 4096]);
        assert_eq!(vol.read(2, 1).unwrap(), vec![0xccu8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }

    /// Build a 4 KiB block whose first byte is `seed` and the rest are
    /// pseudo-random — high entropy so compression stays a no-op.
    fn unique_block(seed: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let s = seed as u64;
        for (i, b) in buf.iter_mut().enumerate() {
            // Distinct per-(seed,i) using a cheap hash. Coprime multipliers
            // keep the byte distribution uniform.
            *b = ((s.wrapping_mul(0x9E37_79B9).wrapping_add(i as u64)) ^ (i as u64 * 31)) as u8;
        }
        buf
    }

    /// Promote `block_count` distinct 4 KiB blocks into one pending segment.
    fn promote_segment_with_blocks(vol: &mut Volume, base_lba: u64, block_count: u64, tag: u32) {
        for i in 0..block_count {
            // Mix `tag` into the seed so different segments don't dedup.
            let block = unique_block(tag.wrapping_mul(0x10001).wrapping_add(i as u32));
            vol.write(base_lba + i, &block).unwrap();
        }
        vol.promote_for_test().unwrap();
    }

    #[test]
    fn repack_packs_small_with_filler() {
        // One small (~4 KiB live) + one ~17 MiB live segment.
        // Bin-pack admits both into one bucket — 17 MiB + 4 KiB
        // ≤ 32 MiB target.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        // Small segment: 1 block.
        promote_segment_with_blocks(&mut vol, 0, 1, 1);
        // 17 MiB live (4352 blocks of 4 KiB) — must fit in the 32 MiB
        // budget alongside the small.
        promote_segment_with_blocks(&mut vol, 1, 4352, 2);

        let stats = vol.repack().unwrap();
        assert_eq!(
            stats.segments_compacted, 2,
            "bin-pack must combine the small and the 17 MiB segment"
        );
        assert_eq!(stats.new_segments, 1);

        // Both ranges must still read back correctly.
        assert_eq!(vol.read(0, 1).unwrap(), unique_block(0x10001));
        assert_eq!(vol.read(1, 1).unwrap(), unique_block(0x10001 * 2));
        assert_eq!(
            vol.read(4352, 1).unwrap(),
            unique_block(0x10001u32.wrapping_mul(2).wrapping_add(4351))
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_respects_entry_cap() {
        // Three pending segments, each carrying 4096 DedupRef entries
        // (live_bytes = 0 — DedupRef has no body cost) plus one tiny
        // DATA segment, total 12_289 entries. Without an entry cap,
        // tier-1 packing would admit all three (byte budget never bites
        // on 0-live_bytes inputs) and produce a 12_289-entry output —
        // far past the WAL's flush cap. With REPACK_ENTRY_CAP = 8192,
        // tier 1 admits exactly two of the dedup segments (8192 entries)
        // and stops; the third dedup segment and the lone DATA are left
        // for a later pass.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        // Anchor segment: a single DATA entry establishing the dedup hash.
        let payload = unique_block(0xCAFE);
        vol.write(0, &payload).unwrap();
        vol.promote_for_test().unwrap();

        // Two dedup-only pending segments, 4096 DedupRef entries each.
        for i in 1..=4096u64 {
            vol.write(i, &payload).unwrap();
        }
        vol.promote_for_test().unwrap();
        for i in 100_000..(100_000u64 + 4096) {
            vol.write(i, &payload).unwrap();
        }
        vol.promote_for_test().unwrap();

        // Plus another dedup-only segment so the cap actually has to
        // refuse one of them.
        for i in 200_000..(200_000u64 + 4096) {
            vol.write(i, &payload).unwrap();
        }
        vol.promote_for_test().unwrap();

        let stats = vol.repack().unwrap();
        // Anchor (1 entry) + first dedup (4096 entries) fill bucket[0]
        // (4097 entries; the next 4096 wouldn't fit). Buckets[1] takes
        // the remaining two dedup segments (4096 + 4096 = 8192). All
        // four inputs are processed in this pass; the entry cap forces
        // two output buckets rather than leaving a segment behind.
        assert_eq!(
            stats.segments_compacted, 4,
            "all four candidates are bucketed (entry cap forces two outputs)"
        );
        assert_eq!(stats.new_segments, 2);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn repack_skips_lone_filler() {
        // A single filler (~17 MiB live, no small to pair with) must
        // not be rewritten — repack does not pack across the small threshold
        // segments around. Repack is what handles single-segment cleanup.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        promote_segment_with_blocks(&mut vol, 0, 4352, 1);

        let stats = vol.repack().unwrap();
        assert_eq!(stats.segments_compacted, 0);
        assert_eq!(stats.new_segments, 0);

        fs::remove_dir_all(base).unwrap();
    }

    // ----------------------------------------------------------------------
    // Lock-drop window regression tests.
    //
    // PR #302 (50511cd) lets `VolumeClient::write` acquire the volume mutex
    // from the calling thread instead of routing through the actor request
    // channel.  That moves writes outside the actor's serialisation window:
    // a write can land between `prepare_repack` returning and
    // `apply_repack_result` reacquiring the lock, while the worker is
    // classifying / materialising against a frozen snapshot.
    //
    // These tests exercise that window deterministically by driving the
    // prep / execute / apply trio directly (the synchronous wrapper
    // `Volume::repack` would close the window before the test could
    // interpose a write).  They mirror the production sequence:
    //
    //   1. Set up at least one pending segment carrying a Keep entry.
    //   2. Call `prepare_repack` — captures lbamap + extent_index snapshot,
    //      mints u_flush + output_ulids.
    //   3. Issue a `Volume::write` that targets one of the snapshot's
    //      Keep entries' LBA ranges.
    //   4. Call `execute_repack` on the captured job — classifies against
    //      the frozen snapshot, materialises the bucket output.
    //   5. Call `apply_repack_result` — must commit the post-prep direct
    //      write, not roll lbamap back to the snapshot's body.
    //
    // See `docs/finding-cargo-build-stale-read.md`.
    // ----------------------------------------------------------------------

    #[test]
    fn lock_drop_full_overwrite_single_block() {
        // Sanity: a single-block Keep entry, fully overwritten by a direct
        // write during the lock-drop window.  apply_repack_result's
        // insert_consuming_inputs blocks check should refuse to clobber
        // the post-prep claim.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let payload_a = vec![0x11u8; 4096];
        let payload_b = vec![0x22u8; 4096];
        let payload_peer = vec![0x33u8; 4096];

        // Pending S1: data [100+1, H_A].  Pending S2 at LBA 200 is the peer
        // that lets the bin-pack put S1 into a non-solo bucket so the rewrite
        // actually runs (a solo all-live bucket would be skipped).
        vol.write(100, &payload_a).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(200, &payload_peer).unwrap();
        vol.promote_for_test().unwrap();

        let job = vol.prepare_repack().unwrap().expect("repack job");

        // Lock-drop window: same LBA, different bytes → different hash.
        vol.write(100, &payload_b).unwrap();

        let result = crate::actor::execute_repack(job).unwrap();
        let (_stats, consumed) = vol.apply_repack_result(result).unwrap();
        vol.remove_consumed_inputs(&consumed).unwrap();

        assert_eq!(
            vol.read(100, 1).unwrap(),
            payload_b,
            "post-apply read must reflect the post-prep direct write"
        );

        drop(vol);
        let vol2 = Volume::open(&base, &base).unwrap();
        assert_eq!(
            vol2.read(100, 1).unwrap(),
            payload_b,
            "reopen rebuild must agree"
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn lock_drop_full_overwrite_multi_block() {
        // Multi-block Keep entry, fully overwritten by three single-block
        // direct writes during the lock-drop window.  Each direct write
        // splits the predecessor in lbamap; insert_consuming_inputs at
        // apply time must mark every sub-range as blocked.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let payload_a: Vec<u8> = (0..3 * 4096usize).map(|i| (i * 7 + 13) as u8).collect();
        let kernel_blocks: Vec<Vec<u8>> = (0..3)
            .map(|n| (0..4096).map(|i| ((i + n * 1009) * 11 + 3) as u8).collect())
            .collect();
        let peer = vec![0xCDu8; 4096];

        // Pending S1: data [100+3, H_A].
        vol.write(100, &payload_a).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(200, &peer).unwrap();
        vol.promote_for_test().unwrap();

        let job = vol.prepare_repack().unwrap().expect("repack job");

        // Lock-drop window: three single-block direct writes covering the
        // whole [100..103) range.
        vol.write(100, &kernel_blocks[0]).unwrap();
        vol.write(101, &kernel_blocks[1]).unwrap();
        vol.write(102, &kernel_blocks[2]).unwrap();

        let result = crate::actor::execute_repack(job).unwrap();
        let (_stats, consumed) = vol.apply_repack_result(result).unwrap();
        vol.remove_consumed_inputs(&consumed).unwrap();

        for (i, block) in kernel_blocks.iter().enumerate() {
            assert_eq!(
                &vol.read(100 + i as u64, 1).unwrap(),
                block,
                "lba {} must reflect the post-prep direct write",
                100 + i,
            );
        }

        drop(vol);
        let vol2 = Volume::open(&base, &base).unwrap();
        for (i, block) in kernel_blocks.iter().enumerate() {
            assert_eq!(
                &vol2.read(100 + i as u64, 1).unwrap(),
                block,
                "reopen rebuild must agree at lba {}",
                100 + i,
            );
        }

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn lock_drop_partial_overwrite_middle_block() {
        // Multi-block Keep entry with a SINGLE middle block overwritten
        // during the lock-drop window.
        //
        // Mirrors the cargo-build inode-table workload shape: snapshot
        // carries a 3-block DATA at [L+3], kernel writes a single block
        // somewhere inside.  At apply time `insert_consuming_inputs` must:
        //   - install the bucket output's claim on the head and tail
        //     sub-ranges with the correct payload_block_offset (0 and 2),
        //   - leave the middle sub-range pointing at the direct write.
        //
        // The current `insert_inner` hard-codes payload_block_offset: 0 for
        // every fresh insert, so a multi-block Keep that has to be split
        // around a blocked middle sub-range loses the trailing block's
        // offset — reads at the trailing LBA return the snapshot's first
        // body block instead of the third.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let block_a0: Vec<u8> = (0..4096).map(|i| (i * 7 + 13) as u8).collect();
        let block_a1: Vec<u8> = (0..4096).map(|i| (i * 11 + 3) as u8).collect();
        let block_a2: Vec<u8> = (0..4096).map(|i| (i * 13 + 5) as u8).collect();
        assert_ne!(block_a0, block_a1);
        assert_ne!(block_a1, block_a2);
        assert_ne!(block_a0, block_a2);
        let payload_a: Vec<u8> = block_a0
            .iter()
            .chain(block_a1.iter())
            .chain(block_a2.iter())
            .copied()
            .collect();
        let kernel_middle: Vec<u8> = (0..4096).map(|i| (i * 17 + 23) as u8).collect();
        let peer = vec![0xCDu8; 4096];

        // Pending S1: data [100+3, H_A].
        vol.write(100, &payload_a).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(200, &peer).unwrap();
        vol.promote_for_test().unwrap();

        let job = vol.prepare_repack().unwrap().expect("repack job");

        // Lock-drop window: single-block direct write at the middle of the
        // 3-block range.  Splits lbamap into three:
        //   [100..101) = (H_A, S1, payload_block_offset=0)
        //   [101..102) = (H_kernel, U_w, payload_block_offset=0)
        //   [102..103) = (H_A, S1, payload_block_offset=2)
        vol.write(101, &kernel_middle).unwrap();

        // Pre-apply sanity: reads still walk through the live state correctly.
        assert_eq!(vol.read(100, 1).unwrap(), block_a0, "pre-apply lba 100");
        assert_eq!(
            vol.read(101, 1).unwrap(),
            kernel_middle,
            "pre-apply lba 101"
        );
        assert_eq!(vol.read(102, 1).unwrap(), block_a2, "pre-apply lba 102");

        let result = crate::actor::execute_repack(job).unwrap();
        let (_stats, consumed) = vol.apply_repack_result(result).unwrap();
        vol.remove_consumed_inputs(&consumed).unwrap();

        // After apply, the bucket output O carries the same 3-block H_A
        // body.  Reads must still resolve to the correct block of H_A on
        // the head and tail, and the kernel's middle write on lba 101.
        assert_eq!(
            vol.read(100, 1).unwrap(),
            block_a0,
            "post-apply lba 100 — should be block 0 of H_A"
        );
        assert_eq!(
            vol.read(101, 1).unwrap(),
            kernel_middle,
            "post-apply lba 101 — should be the post-prep direct write"
        );
        assert_eq!(
            vol.read(102, 1).unwrap(),
            block_a2,
            "post-apply lba 102 — should be block 2 of H_A (NOT block 0)"
        );

        drop(vol);
        let vol2 = Volume::open(&base, &base).unwrap();
        assert_eq!(vol2.read(100, 1).unwrap(), block_a0, "reopen lba 100");
        assert_eq!(vol2.read(101, 1).unwrap(), kernel_middle, "reopen lba 101");
        assert_eq!(vol2.read(102, 1).unwrap(), block_a2, "reopen lba 102");

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn lock_drop_full_overwrite_then_wal_flush() {
        // Same shape as `lock_drop_full_overwrite_multi_block` but with a
        // WAL flush after the direct writes and before `execute_repack`.
        // This bumps lbamap claimants for the kernel writes from the WAL
        // ULID to a fresh pending segment ULID — exercising the
        // claimant-bump path in `flush_wal_to_pending_as` while the
        // worker still holds the original snapshot.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let payload_a: Vec<u8> = (0..3 * 4096usize).map(|i| (i * 7 + 13) as u8).collect();
        let kernel_blocks: Vec<Vec<u8>> = (0..3)
            .map(|n| (0..4096).map(|i| ((i + n * 1009) * 11 + 3) as u8).collect())
            .collect();
        let peer = vec![0xCDu8; 4096];

        vol.write(100, &payload_a).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(200, &peer).unwrap();
        vol.promote_for_test().unwrap();

        let job = vol.prepare_repack().unwrap().expect("repack job");

        for (i, block) in kernel_blocks.iter().enumerate() {
            vol.write(100 + i as u64, block).unwrap();
        }
        // Flush the post-prep WAL into a fresh pending segment with ULID
        // strictly greater than every output ULID.  Bumps lbamap claimants
        // from U_w to the new segment ULID.
        vol.flush_wal().unwrap();

        let result = crate::actor::execute_repack(job).unwrap();
        let (_stats, consumed) = vol.apply_repack_result(result).unwrap();
        vol.remove_consumed_inputs(&consumed).unwrap();

        for (i, block) in kernel_blocks.iter().enumerate() {
            assert_eq!(
                &vol.read(100 + i as u64, 1).unwrap(),
                block,
                "post-apply lba {}",
                100 + i,
            );
        }

        drop(vol);
        let vol2 = Volume::open(&base, &base).unwrap();
        for (i, block) in kernel_blocks.iter().enumerate() {
            assert_eq!(
                &vol2.read(100 + i as u64, 1).unwrap(),
                block,
                "reopen lba {}",
                100 + i,
            );
        }

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn lock_drop_full_overwrite_then_second_repack_pass() {
        // After the first repack apply, the post-prep direct writes live in
        // the running WAL (or, after a flush, in a fresh pending segment).
        // A second repack pass should pick those up and carry them into a
        // new bucket output.  Exercises the cross-pass interaction.
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let payload_a: Vec<u8> = (0..3 * 4096usize).map(|i| (i * 7 + 13) as u8).collect();
        let kernel_blocks: Vec<Vec<u8>> = (0..3)
            .map(|n| (0..4096).map(|i| ((i + n * 1009) * 11 + 3) as u8).collect())
            .collect();
        let peer = vec![0xCDu8; 4096];

        vol.write(100, &payload_a).unwrap();
        vol.promote_for_test().unwrap();
        vol.write(200, &peer).unwrap();
        vol.promote_for_test().unwrap();

        let job = vol.prepare_repack().unwrap().expect("repack job");
        for (i, block) in kernel_blocks.iter().enumerate() {
            vol.write(100 + i as u64, block).unwrap();
        }
        let result = crate::actor::execute_repack(job).unwrap();
        let (_stats, consumed) = vol.apply_repack_result(result).unwrap();
        vol.remove_consumed_inputs(&consumed).unwrap();

        // Second repack pass — now operating on the bucket output + the
        // segment(s) carrying the kernel writes.
        vol.flush_wal().unwrap();
        vol.repack().unwrap();

        for (i, block) in kernel_blocks.iter().enumerate() {
            assert_eq!(
                &vol.read(100 + i as u64, 1).unwrap(),
                block,
                "after second repack, lba {}",
                100 + i,
            );
        }

        drop(vol);
        let vol2 = Volume::open(&base, &base).unwrap();
        for (i, block) in kernel_blocks.iter().enumerate() {
            assert_eq!(
                &vol2.read(100 + i as u64, 1).unwrap(),
                block,
                "reopen after second repack, lba {}",
                100 + i,
            );
        }

        fs::remove_dir_all(base).unwrap();
    }

    /// Distinct, incompressible 4 KiB block per seed (splitmix64 stream).
    /// `unique_block` above lz4-compresses below `INLINE_THRESHOLD` for
    /// some seeds; these tests need entries that stay `Data` kind.
    fn incompressible_block(seed: u32) -> Vec<u8> {
        let mut x = (seed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut out = Vec::with_capacity(4096);
        for _ in 0..512 {
            x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = x;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            out.extend_from_slice(&z.to_le_bytes());
        }
        out
    }

    #[test]
    fn repack_result_carries_inline_bytes() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        // Two small pending segments so bin-pack merges them into one
        // output. The constant-fill block compresses below
        // INLINE_THRESHOLD, giving the output an Inline entry.
        vol.write(0, &incompressible_block(1)).unwrap();
        vol.write(1, &[7u8; 4096]).unwrap();
        vol.promote_for_test().unwrap();
        promote_segment_with_blocks(&mut vol, 2, 2, 2);

        let job = vol.prepare_repack().unwrap().expect("repack job");
        let result = crate::actor::execute_repack(job).unwrap();

        let mut saw_inline = false;
        for bucket in &result.buckets {
            let out = bucket.output.as_ref().expect("merge output");
            for e in &out.out_entries {
                if e.kind.is_inline() {
                    saw_inline = true;
                    assert!(e.inline.is_some(), "inline entry lost its apply bytes");
                }
            }
        }
        assert!(saw_inline, "setup must yield an Inline entry");

        let (_stats, consumed) = vol.apply_repack_result(result).unwrap();
        vol.remove_consumed_inputs(&consumed).unwrap();

        assert_eq!(vol.read(0, 1).unwrap(), incompressible_block(1));
        assert_eq!(vol.read(1, 1).unwrap(), [7u8; 4096]);
        assert_eq!(
            vol.read(2, 1).unwrap(),
            unique_block(2u32.wrapping_mul(0x10001))
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn promote_result_carries_inline_bytes() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &incompressible_block(9)).unwrap();
        vol.write(1, &[3u8; 4096]).unwrap();

        let job = vol.prepare_promote().unwrap().expect("promote job");
        let result =
            crate::actor::execute_promote(job, &mut crate::actor::PriorSourceCache::default())
                .unwrap();

        let mut saw_inline = false;
        for e in &result.entries {
            if e.kind.is_inline() {
                saw_inline = true;
                assert!(e.inline.is_some(), "inline entry lost its apply bytes");
            }
        }
        assert!(saw_inline, "setup must yield an Inline entry");

        vol.apply_promote(&result).unwrap();

        assert_eq!(vol.read(0, 1).unwrap(), incompressible_block(9));
        assert_eq!(vol.read(1, 1).unwrap(), [3u8; 4096]);

        fs::remove_dir_all(base).unwrap();
    }
}
