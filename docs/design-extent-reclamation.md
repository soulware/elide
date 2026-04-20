# Extent reclamation

**Status:** Work in progress. The code described below is a proof-of-concept, not a finished feature. Do not cite anything in this doc when solving an unrelated correctness problem.

## What exists today

A volume-side primitive that rewrites bloated multi-LBA extent bodies into compact new-hash entries, and a test hook to drive it.

### Why anything needs rewriting

`Volume::write()` produces one `SegmentEntry` per write, with `lba_length` equal to the inbound size. Later partial overwrites split the LBA map entry via `payload_block_offset` aliasing (`elide-core/src/lbamap.rs::insert`) without touching the original stored body. Reads remain correct — each surviving sub-range resolves through the original compressed payload — but the body may end up with many dead interior blocks that every read still has to decompress past. The alias-merge primitive rewrites those surviving sub-ranges into fresh compact payloads and leaves the original hash fully orphaned, which lets a later GC pass reclaim it.

### The primitive

Three phases, of which only the middle is heavy. See `docs/design-noop-write-skip.md` for why rewrite writes pass cleanly through the no-op skip path.

1. **Snapshot** (`Volume::reclaim_snapshot`). Under the actor lock, clone `Arc<LbaMap>` and capture the extents over the target LBA range. Cheap — O(log n) range query plus an Arc bump. Returns a `ReclaimPlan`.

2. **Compute rewrites** (`ReclaimPlan::compute_rewrites`). Runs without the actor lock. For each non-zero-hash extent in the plan, two gates decide whether it's worth rewriting:
   - **Containment.** Every run of the hash in the current lbamap must sit inside the target range. Rewriting a hash whose body is referenced outside the target would leave those outside references pointing at the now-bloated body and make things worse.
   - **Bloat.** At least one run of the hash must have `payload_block_offset != 0`, indicating a prior split that left dead bytes inside the stored body.
   Extents that pass both gates have their live bytes read through the normal read path, re-hashed, and compressed. The output is a list of `ReclaimProposed { start_lba, data, hash }`.

3. **Commit** (`Volume::reclaim_commit`). Under the actor lock, check `Arc::ptr_eq(plan.lbamap_snapshot, self.lbamap)`. If the pointers differ, something mutated the lbamap between phase 1 and now — return `ReclaimOutcome { discarded: true, .. }` without doing anything. Otherwise assemble the proposals into a single pending segment (via `segment::write_and_commit`) under a fresh mint ULID — the segment rename is the durability commit point — then splice the resulting entries into the live lbamap + extent index. The WAL is not touched: reclaim's output is fully derivable from durable state, so a crash before rename leaves nothing to recover and a crash between rename and splice leaves an orphan segment that GC classifies as all-dead on the next pass. Proposals already present at their target LBA with the same hash are absorbed by the no-op skip check; proposals whose hash is already indexed elsewhere emit thin DedupRef entries rather than duplicate bodies.

### The test hook

`VolumeHandle::reclaim_alias_merge(start_lba, lba_length)` ties the three phases together in the simplest possible way: snapshot, compute, commit, return the outcome.

`scan_reclaim_candidates` walks the live lbamap and extent index and produces `ReclaimCandidate { start_lba, lba_length, dead_blocks, live_blocks, stored_bytes }` entries for hashes with detectable bloat (controlled by `ReclaimThresholds`, all defaults placeholder values).

`elide volume reclaim <name>` calls the scanner, then calls the primitive once per candidate. It exists so the primitive can be exercised end-to-end — this is not a customer-facing operation.

## Proposed: worker-thread offload and coordinator wiring

Stage A — landed. The three-phase structure above is the current behaviour: phase 3 assembles one pending segment instead of looping `write_with_hash`, and the WAL is bypassed. What remains is moving phase 2 off the caller thread onto the worker, and wiring reclaim into the coordinator tick loop.

### Phase mapping

| Phase | Today (Stage A) | Stage B |
| --- | --- | --- |
| 1. Prepare | `reclaim_snapshot` on actor (Arc-clone lbamap + range query) | unchanged |
| 2. Middle | `compute_rewrites` on caller thread; reads round-trip through actor IPC via `VolumeHandle::read` | `WorkerJob::Reclaim`; reads resolve against the held snapshot directly (no channel round-trips); worker assembles + writes the segment file |
| 3. Apply | `reclaim_commit` on actor: one lock, `Arc::ptr_eq` guard, splice rewrites into lbamap + extent index, one segment rename as commit point | `apply_reclaim_result` on actor: identical shape, just consumes the worker's pre-built `ReclaimResult` |

Stage A captured the dominant latency win (N WAL fsyncs → 1 segment rename, no loop of `write_with_hash`). Stage B captures the remaining win: phase 2's reads no longer contend with writes on the actor channel.

### Why bypassing the WAL is safe

WAL records exist to make writes crash-replayable before they reach a segment. Reclaim rewrites are *derivable* from already-durable state: the source hashes are live in existing segments, and the lbamap change is a pure remap onto a fresh body. If the actor crashes before the rename, there's nothing to recover — the old entries are still there, unchanged. If we crash between rename and lbamap splice, the new segment is an orphan that GC will classify as all-dead and sweep. Same property repack relies on.

### Discard window

`Arc::ptr_eq(plan.lbamap_snapshot, self.lbamap)` today spans (snapshot → compute_rewrites → commit) on the caller thread. Stage B widens it to (snapshot → worker done → apply), which increases the chance of a concurrent mutation voiding the plan on a high-churn volume. Repack has the same property and it hasn't been a problem; the fallback is a clean discard, not a retry-in-place, so the next scheduled pass picks up whatever state now exists.

### Coordinator wiring

Two options once the primitive is worker-offloaded:

1. **Pre-drain, scanner-gated** — in `tasks.rs`, alongside `sweep_pending` / `repack` / `delta_repack_post_snapshot`. Each tick: call a cheap `control::reclaim_scan` IPC that returns the top candidate's score; if it clears a configured bar, call `control::reclaim`. Symmetric with how `repack` is wired. Orphaned bodies from the reclaim output become ordinary sparse-segment candidates on the next GC tick.

2. **Post-snapshot** — trigger once after `sign_snapshot_manifest`. Rationale: bloat accumulates across a snapshot's lifetime, and the snapshot floor is what lets GC actually reclaim the resulting orphans. Sharper knife; requires an explicit event hook.

Lean is (1) as the first wiring: no new event path, symmetric with existing maintenance ops, and a single per-tick knob controls cadence.

### Concurrency constraint

Like repack and delta_repack, reclaim takes a `parked_reclaim: Option<Sender<...>>` slot on the actor. Concurrent IPC calls return `err concurrent reclaim not allowed`. Callers (coordinator tick loop) serialise naturally.

## Open questions

- **Threshold shape.** `ReclaimThresholds` defaults are placeholders. The scanner-gated trigger needs a single-number "worth firing" signal — likely `top_candidate.dead_blocks × dead_ratio` above a bar, but empirical work on an aged volume is needed before picking it.
- **Proposal cap per pass.** Scanner already sorts by `dead_blocks` desc; a hard cap on proposals kept per pass bounds the worker's CPU and the single-apply lock-hold duration. What cap?
- **Interaction with CANONICAL_ONLY demotion for hashes used as dedup/delta sources.** When the rewritten hash H has DedupRef or Delta entries elsewhere pointing at it, GC partial-death demotes H to `CANONICAL_ONLY` (body preserved, no LBA claim) rather than dropping it. This is a clean separation of concerns — H' serves this volume's LBA reads with no aliasing overhead; H serves remote dedup/delta consumers with the full body they hashed against — not a failure mode. But it does change the cost accounting: when H has outbound dedup/delta refs, reclaim adds `sizeof(H')` of new body on top of the preserved H; when H has none, reclaim is essentially free (H is orphaned and GC drops it entirely). The scanner threshold may want to factor in outbound-ref presence so the "worth firing" bar is stricter for hashes whose old body will survive.

  The signals are already available on `LbaMap`:

  - **Delta sources:** `delta_source_refcount(H)` returns the count of live Delta LBAs whose source is H. Already maintained via `incref`/`decref` on every lbamap mutation; currently marked "diagnostics" but the data is load-bearing (`lba_referenced_hashes()` depends on it). Just expose it as production API.
  - **DedupRef references within this volume:** no separate refcount needed. A DedupRef LBA contributes `X → H` to the lbamap with `entry.hash = H`, so the existing containment gate (every run of H sits inside the target range) already sweeps in any in-volume DedupRef for H. A DedupRef at an LBA outside the range fails containment and reclaim skips H.
  - **Cross-volume DedupRef/Delta:** not tracked by any refcount. Also not relevant to reclaim's cost accounting — reclaim mutates only this volume's lbamap and writes a new segment; other volumes' consumers pin their sources via their own `extent_index` against S3 segments, which reclaim doesn't touch.

  Translation to threshold logic: `delta_source_refcount(H) > 0` ⇒ H will survive demotion, apply a stricter cost-benefit bar (need sufficiently high dead-ratio to offset `sizeof(H')`). Otherwise H is orphaned post-reclaim and dropped next GC, and the looser bar is correct.
- **Reclaiming a Delta-bodied hash.** Distinct from the source-hash case above: if H itself is a `Delta` entry (not DATA), rewriting it re-materialises it as DATA and loses the delta saving on this volume. `compute_rewrites` should skip Delta-bodied hashes, or the rewrite must preserve the delta shape.
