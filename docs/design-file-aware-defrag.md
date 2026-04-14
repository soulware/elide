# Design: file-aware extent defragmentation

**Status:** Proposed, not implemented.

## Problem

The write path never coalesces. Every `Volume::write()` produces exactly one `SegmentEntry` whose `lba_length` equals the inbound write size; flush, sweep, GC, delta repack, and snapshot promote all preserve extent boundaries (see `elide-core/src/volume.rs:539`, `segment.rs:1110`, `elide-coordinator/src/gc.rs:1081`, `elide-core/src/delta_compute.rs:516`). For an imported volume — where the importer hands the volume one large contiguous buffer per file fragment — the resulting segments contain large extents that cleanly mirror file layout. Subsequent NBD traffic is the opposite: 4 KiB block writes punch single-block extents into the LBA map. Because nothing recoalesces, extent fragmentation for any LBA range is monotonically non-decreasing.

The cost grows with volume age:

- **Read amplification.** A sequential file read fans out to one extent index lookup per 4 KiB. If the live blocks landed across many segments (post-GC, post-eviction), each lookup is a separate body access.
- **Extent index bloat.** The in-memory `extent_index` and on-disk `.idx` size scale with extent count, not data size.
- **Delta repack ceiling.** Phase 5 dictionary compression benefits from larger source and target fragments; many single-block extents give zstd very little to work with.

The key observation is that extent boundaries are the wrong granularity to reason about fragmentation. A file is fragmented when its LBAs no longer live in one extent — which is information we only have at one place in the system: when the filemap is generated.

## The lever: filemap-time file boundary knowledge

Phase 4 generates `snapshots/<ulid>.filemap` inline during snapshot sealing, parsing ext4 metadata from the just-frozen segments and recording each path's fragment list (`elide-coordinator/src/inbound.rs`, `elide-core/src/import.rs`). At that moment the snapshot lock is held; nothing else is mutating the volume's segment set. The filemap is the only structure in the system that maps file identity to LBA ranges. It is the natural place to ask: *which files have become fragmented, and can we merge their extents back together within file boundaries?*

"Within file boundaries" is the safety property that distinguishes this from generic extent coalescing. Two physically adjacent extents may belong to different files and have completely different lifetimes; merging them across the boundary would couple unrelated content. Merging within a single path is always semantically safe — the bytes already belong together.

## Mechanism sketch

After `generate_filemap` and before `sign_snapshot_manifest`, under the snapshot lock, run a defrag pass:

1. **Walk the filemap.** For each file row, evaluate a fragmentation predicate (see § Selection heuristic). Files that pass are candidates.
2. **Read live content.** For each candidate, use `BlockReader::open_snapshot` (already constructed for filemap generation) to read the file's logical bytes in one pass. The reader resolves overrides correctly — newest-wins per LBA — so the result is the current file content regardless of which segment each block currently lives in.
3. **Write a merged extent.** Append a single `Data` entry covering the file's full LBA range to a fresh post-floor pending segment. The new entry supersedes the fragments at LBA-map level.
4. **Update LBA map.** Point every LBA in the file's range at the new entry. Old fragments become dead in their respective segments and will be reclaimed by ordinary coordinator GC at the usual cadence.
5. **Re-emit the filemap row.** The path's fragment list collapses to one entry. The filemap on disk reflects the post-defrag layout, so consumers (delta repack, future Phase 5 Tier 2) see the merged view.
6. **Seal.** Phase 4 continues with `sign_snapshot_manifest`. The new merged segment is part of the snapshot floor.

The pass is best-effort: any file whose live bytes cannot be assembled (missing body, demand-fetch failure, snapshot-floor segment skip rules) is left unchanged. Correctness story matches Phase 5 — *always correct, sometimes no benefit*.

## Pipeline position

Two plausible positions:

**A. Inside snapshot sealing, before `sign_snapshot_manifest` (recommended).** Defrag is part of producing the snapshot, so the just-sealed snapshot is the defragmented one. Clones from this snapshot read merged extents immediately. Filemap-write happens once, after defrag, and reflects final state. The cost is borne under the snapshot lock.

**B. Between snapshots, sibling to Phase 5 delta repack.** Defrag operates only on post-floor pending segments using the *prior* snapshot's filemap to identify file-belonging LBAs. Lighter coupling to snapshot sealing, but only fragments produced after the prior snapshot can be merged — the dominant case (a long-lived large extent punched by 4 KiB writes) cannot, because the punched extent is below the floor and immutable.

Position A is the only option that recovers fragmentation that crosses the snapshot floor, which is the case the user is actually paying for. Position B is the conservative fallback if snapshot-time I/O is unacceptable.

## Tradeoffs

**1. Dedup conflict.** Any 4 KiB block in the middle of a fragmented file that is currently a `DedupRef` to another file — zero pages, ELF section padding, common library blobs — loses its dedup when its content gets materialised into a merged file extent. The new merged `Data` entry hashes to a fresh value and contributes a new body. For files dominated by unique content this is fine; for files dominated by shared content (sparse files, files with large zero regions, common base layers) it is a clear regression. The selection heuristic must account for "fragments are dedup'd, not stale."

A possible refinement: skip merging through DedupRef runs, producing two merged Data extents bracketing the dedup'd run. Adds complexity but preserves dedup wins where they exist.

**2. Delta extent conflict.** Phase 5 converts post-floor `Data` entries to thin `Delta` entries. `Data` and `Delta` use different encodings and cannot be merged together. Two consequences:

- Defrag must run *before* Phase 5 in any tick where both fire. Order: filemap → defrag → seal → (next tick) Phase 5 delta repack.
- Defrag cannot touch fragments that have already been converted to `Delta` in a prior tick. If the merged file's LBA range contains any `Delta` entries from a previous Phase 5 pass, either skip the file or accept a partial merge that brackets the delta region.

There is also a synergy: a merged file extent is exactly the granularity Phase 5 Tier 2 wants as a delta target. Tier 1 (same-LBA prior fragment) becomes more effective because the prior-snapshot lookup returns one fragment for the whole merged range instead of N independent lookups. Defrag and delta repack reinforce each other when sequenced correctly.

**3. Snapshot becomes I/O-heavy.** Today snapshot sealing is a metadata operation — generate filemap (read-only walk), sign manifest, fsync, done. Defrag adds *read live bytes for fragmented files* and *write merged segments*, both inside the snapshot lock. For a heavily-fragmented multi-GiB volume this could turn a sub-second snapshot into a multi-second one. Mitigations:

- Hard cap on bytes rewritten per snapshot (e.g. 64 MiB), with the rest deferred to subsequent snapshots.
- Skip the pass entirely below a global fragmentation threshold, so quiet volumes pay nothing.
- Run the read+rewrite *outside* the snapshot lock, against the just-sealed snapshot's `BlockReader`, and apply the LBA-map updates as a separate handoff (closer in spirit to GC). Loses the "snapshot is the defragmented version" property but recovers metadata-fast snapshots.

**4. Pre-floor fragment liveness.** Merging produces dead bytes inside pre-floor immutable segments. Those segments cannot be rewritten until ordinary GC visits them (and the leaf-only constraint means ancestors with active descendants can never be reclaimed). For fork-heavy workloads, defrag adds permanent dead weight to ancestors. Either accept this (fork lifetimes are typically bounded), or restrict defrag to leaves with no live descendants.

**5. Write amplification.** Every defrag pass rewrites file bytes that were already on disk. The amplification budget needs to be set against the read-amplification savings — for read-heavy workloads it pays back quickly; for write-heavy workloads it might not. Real measurement required before committing to thresholds.

## Selection heuristic

A file is a defrag candidate when *all* of:

- `fragment_count >= MIN_FRAGMENTS` (e.g. 8) — small fragment counts aren't worth touching.
- `total_bytes / fragment_count <= MAX_AVG_FRAGMENT_BYTES` (e.g. 16 KiB) — files whose fragments are already large enough are fine.
- `total_bytes >= MIN_FILE_BYTES` (e.g. 64 KiB) — tiny files don't benefit from being one extent vs many.
- `dedup_ref_ratio < MAX_DEDUP_RATIO` (e.g. 0.25) — files dominated by DedupRefs would lose more than they gain.
- `delta_entry_count == 0` (or partial-merge supported) — merging cannot cross encoding-kind boundaries.

All thresholds are placeholders pending measurement. The right values depend on the workload mix observed in `docs/findings.md`.

## Open questions

- **Threshold defaults.** Need empirical data on real fragmented volumes before fixing values. A diagnostic command (`elide volume inspect --fragmentation`) that reports per-file fragment counts against the latest filemap would let us measure before deciding.
- **Lock duration vs snapshot speed.** Position A inside the snapshot lock is the cleanest sequencing but the heaviest. Worth prototyping to measure actual cost on a representative volume before committing.
- **DedupRef-aware bracketing.** Is the complexity of skipping over DedupRef runs justified, or is "skip files above a dedup threshold" sufficient?
- **Interaction with the no-op write skip path** (`design-noop-write-skip.md`). The merged extent is, by definition, content-identical to the bytes already on disk. Does the dedup-by-hash cache short-circuit anything useful here, or is it inert because we are creating one new aggregate hash from many small ones?
- **Filemap regeneration vs incremental update.** Position A requires either rewriting the filemap row in place after defrag or re-running filemap generation. In-place row rewrite is cheaper but couples defrag to filemap format internals.
- **Diagnostic visibility.** Per-file fragmentation is currently invisible. Even before implementing defrag, exposing it via `inspect-segment` or a new `inspect-filemap` would help reason about whether this is a real problem on real workloads.

## Relationship to existing passes

| Pass | Operates on | Granularity | Merges contiguous? |
|---|---|---|---|
| `sweep_pending` | `pending/` segments | extent | no — concatenates live entries |
| Coordinator GC repack | uploaded segments | extent | no — copies entries one-by-one |
| Phase 5 delta repack | post-floor `pending/` | entry kind | no — Data→Delta in place |
| Snapshot promote | source segment | segment | no — passes through |
| **File-aware defrag (this proposal)** | **post-floor `pending/` + LBA-map updates** | **file** | **yes — within file boundaries** |

This is the first pass in the system that uses *file identity* as a structuring principle for extent layout. Every other pass operates at the LBA or segment level. That is also why it can only live where the filemap lives.
