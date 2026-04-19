# Design: compacting partial-LBA-death segments

**Status:** Partially implemented. Data/Inline partial-death is live on the
`docs/gc-partial-death-compaction` branch (commits `eb1b52d` and `8a1d6e1`);
DedupRef/Delta partial-death is deferred — see [Implementation status](#implementation-status).

## Motivation

[`docs/design-gc-overlap-correctness.md`](design-gc-overlap-correctness.md) established correctness by *skipping* any segment containing a partial-LBA-death entry.

This doc describes a compaction path that **decouples the composite body from the surviving sub-runs**, so each can subsequently be handled by normal GC independently. It preserves the correctness property of the skip rule — every emitted LBA claim agrees with the live `lbamap` across its full range — while breaking the coupling that kept them pinned together.

The compaction output for a partial-death entry:
- `canonical_only` (when needed to preserve the composite hash — see step 2 below) holding the full composite body (all original bytes, live and dead), **plus**
- a new entry for each live sub-run.

What we gain in the general case is *separability*: after compaction,

- the composite body is referenced only by whatever external DedupRefs/Deltas still point at it;
- each surviving sub-run is a first-class entry with its own hash and its own LBA claim;
- normal GC can reclaim either piece on its own — the composite once its external refs go away, a sub-run once overwritten.

## Design

Partial-death is a fourth outcome of `collect_stats`'s per-entry classifier, alongside fully-alive, fully-dead, and `canonical_only`. The segment is no longer partitioned out of the GC pipeline (as PR #77 did); it flows through normal GC, with partial-death entries processed per the steps below and non-partial-death entries handled by the existing paths in the same pass.

Partial-death compaction runs **per entry**, not per segment. For each partial-death entry encountered by `collect_stats`:

1. **Resolve the body.** Depending on entry shape:
   - `Data` / `Inline` → read the inline body.
   - `DedupRef` → look up `extent_index[hash]` and read the referenced body.
   - `Delta` → resolve `base_hash`, apply the delta to reconstruct the body.

2. **Handle the composite body.** The action depends on the original entry's type:
   - **Data / Inline**: the source segment owns the composite body. If the hash is externally referenced (any `dedup_hash == entry.hash` or `base_hash == entry.hash` — see the External reference check section), emit `canonical_only` in the compaction output preserving the composite body. Otherwise drop the composite body entirely.
   - **DedupRef**: the source segment does not own the composite body — it lives in the canonical segment pointed at by `extent_index[entry.hash]`, which is untouched by this compaction. **Skip this step entirely.** No `canonical_only` is needed: the canonical body remains resolvable via its existing location, whether or not external references exist.
   - **Delta**: the source segment owns the delta payload, not the reconstructed body. If the hash is externally referenced, emit `canonical_only` holding the **reconstructed composite body inlined as a full body** (not as a Delta). This keeps dedup reads O(1) rather than forcing per-read reconstruction. Otherwise drop the delta payload entirely.

3. **Slice into live sub-runs.** Use `lba_map.extents_in_range(start, end)` and filter to runs where `r.hash == entry.hash`. Each such run is a surviving slice of the composite body. There can be one (head / tail) or more (interior, or multiple disjoint overwriters) — emit one sub-run entry per run.

4. **Emit each sub-run through the normal write path** into the compaction output segment. For each sub-run bytes `B_i`:
   - Compute `hash(B_i)`.
   - If `extent_index` already has that hash → emit a whole-body `DedupRef`.
   - Otherwise → emit a fresh `Data` entry containing `B_i`.
   - In both cases the emitted entry's `(start_lba, lba_length)` matches the surviving sub-run exactly.

## Why this is correct

Rebuild applies segments in ULID order. The compaction output segment has ULID > all source ULIDs. After rebuild:

- Every surviving sub-run is claimed by a first-class entry in the compaction output, with `(start_lba, lba_length)` matching exactly.
- The composite body remains resolvable via its hash if and only if something still refers to it (DedupRef or Delta). `canonical_only` preserves it when needed; dropping it when not needed is safe because no reader path can reach it.
- The source segment is deleted because nothing on disk still depends on it: its live sub-runs have been re-emitted as first-class entries, and its composite body has either been carried forward as `canonical_only` or dropped as unreachable.

## External reference check

The check covers **both** resolution paths that can pin a body by hash:

- `DedupRef.hash == H_composite` — a DedupRef in any segment resolves by hash lookup.
- `Delta.base_hash == H_composite` — a Delta entry's base is resolved by hash lookup.

This is the same predicate that normal GC's `canonical_only` emission must already be evaluating for whole-entry LBA-dead cases. If the existing check covers only `DedupRef.hash` and not `Delta.base_hash`, that is a pre-existing correctness gap in normal GC — not a gap introduced by this design — and should be fixed alongside this work.

## Scope and notes

- This path handles only partial-LBA-death entries. Fully alive and fully dead entries are untouched; normal GC handles them.
- No changes to `SegmentEntry` or `ExtentLocation` on-disk shapes.
- **Hash collision (overwriter's hash happens to equal `entry.hash`).** `extents_in_range` reports the whole range as matching — `matching_bytes == total_bytes` — classified as fully-alive. The entry is not partial-death and never enters this path.
- **Post-GC `extent_index` ordering.** The compaction output's `canonical_only` entry has a higher ULID than any pre-existing DedupRef to the same hash. Normal GC already produces this "DedupRef precedes its canonical" state post-GC (the "DedupRef → lower ULID" invariant holds at write time but not after GC, per PR #23); this design inherits whatever rebuild resolution the existing GC relies on and does not introduce a novel ordering problem.

## Testing

Extend the tests in [`design-gc-overlap-correctness.md`](design-gc-overlap-correctness.md):

- For each of the three wrong shapes (head / tail / interior), after partial-death compaction runs:
  - The source segment is absent.
  - The compaction output segment contains first-class entries covering exactly the surviving sub-runs.
  - If the composite hash had no external refs, the composite body is absent.
  - If the composite hash had external refs (add a DedupRef or Delta-base variant to the fixture), a `canonical_only` entry in the output preserves the composite body.
- The `MultiLbaWriteThenOverwrite` proptest SimOp continues to satisfy `gc_oracle`, and additionally asserts that the source segment is gone after GC.

## Implementation status

### What's implemented (Data / Inline)

`collect_stats` routes partial-death Data / Inline entries into a per-entry
`partial_death_runs` list (parallel to `live_entries`). `compact_segments`'s
`expand_partial_death` reads the composite body from the source segment
(already populated by `fetch_live_bodies` for Data, or by inline pre-population
for Inline), slices into live sub-runs, hashes each slice, and emits either a
whole-body `DedupRef` (if the hash already exists) or a fresh `Data` entry.
The composite hash is preserved as `CanonicalData` / `CanonicalInline` when
externally referenced, dropped otherwise. The source segment is deleted
(rather than deferred) once all its partial-death entries are handled.

Tests that cover this path:
- `gc::tests::collect_stats_skips_entry_with_{head,tail,interior}_overwrite`
  (deterministic).
- `gc_oracle`, `gc_segment_cleanup`, `gc_oracle_repro_bug_h` (proptest).

### What's deferred (DedupRef / Delta)

Partial-death DedupRef and Delta entries still hit the segment-level skip rule
from PR #77: `collect_stats` sets `has_partial_death = true` for their
segment, and `gc_fork` partitions the segment out of the current pass. Those
segments sit on disk with dead bytes until either (a) later writes kill their
surviving sub-ranges (which lets normal GC reclaim them), or (b) this work
lands.

The design in this doc's `## Design` section already specifies the intended
behaviour for both: reconstruct-and-inline. The sub-run emission path is the
same as Data / Inline. The differences are in how the composite body is
obtained and what the canonical-hash handling looks like.

#### DedupRef

**Compose body source.** The DedupRef entry's segment doesn't hold the body;
`extent_index[entry.hash]` points at the canonical segment that does. Fetch
from there:
- Inline case: bytes live in the canonical segment's `.idx` inline section,
  or pre-read into `extent_location.inline_data`.
- Data case: read from the canonical segment's body section
  (`cache/<id>.body` or S3 range-GET via the usual demand-fetch mechanism),
  decompress if `compressed`.

**Canonical-hash handling.** None. The composite body is preserved by the
canonical segment, which this GC pass doesn't touch. The DedupRef is dropped
from the compacted output; sub-runs are emitted in its place.

#### Delta

**Composite body source.** Two-step reconstruction:
1. Resolve the base body via `extent_index[delta_options[0].source_hash]`
   (same fetch mechanics as DedupRef above). Pick the first `source_hash`
   that resolves, matching the read path.
2. Read the delta blob from this segment's delta body section at
   `delta_options[0].delta_offset`, and zstd-dict-decompress against the
   base body.

**Canonical-hash handling.** The Delta's hash may be externally referenced
(by a DedupRef or another Delta's `source_hash`). **Reconstruct-and-inline**:
emit the reconstructed composite body as `CanonicalData` (or `CanonicalInline`
if small). The delta encoding is not preserved — the canonical body is stored
uncompressed (or LZ4-compressed by `new_data`'s usual rules), not delta-
encoded. This avoids per-read delta reconstruction for the canonical body
at the cost of losing its delta-compactness.

The rejected alternative: extend `canonical_only` to cover Delta (a Delta
entry with zero LBA claim that still holds delta_options + source_hash).
Saves canonical-body storage; adds read-time reconstruction cost on every
dedup resolution through that hash. Not worth the complexity for a rare case.

### Machinery required for the deferred work

1. **Cross-segment body resolution.** A coordinator-side helper that takes
   a hash and returns the uncompressed composite body, handling both
   locally-cached and demand-fetch paths, and both Data-section and Inline-
   section sources. Roughly the coordinator analogue of `block_reader`'s
   body resolution, but operating on segment files directly rather than
   through a `Volume`. Reuses `fetch_live_bodies`'s local/S3 tiering.
2. **Delta application.** A shared `apply_delta(base_body, delta_blob)`
   helper. `block_reader::read_delta_block` already does this work; extract
   it so the coordinator can call it without constructing a BlockReader.
3. **`collect_stats` routing.** Route DedupRef/Delta partial-death into
   `partial_death_runs` (currently only Data/Inline populate it). Drop the
   `has_partial_death = true` branch for those kinds once the above
   machinery exists. The remaining `has_partial_death` use cases would
   collapse to "body fetch failed" — see below.
4. **Expand-partial-death branching.** `expand_partial_death` currently
   assumes the composite body is already in `entry.data`. Extend to branch
   on `entry.kind`:
   - Data/Inline: current path.
   - DedupRef: call the body-resolution helper on `entry.hash`; no canonical
     emit.
   - Delta: resolve base via helper + apply_delta; emit canonical via
     reconstruct-and-inline when `live_hashes.contains(&entry.hash)`.

### Open questions

- **Fetch failure fallback.** If the base or canonical body isn't locally
  cached and S3 is unreachable (or slow), we can't reconstruct. The clean
  answer is: treat this entry as "defer this pass" — set `has_partial_death`
  on the segment and partition it out, same as today. Retry next pass.
  Requires `collect_stats` to attempt the resolution (or at least a
  cheap check for local availability) before routing.
- **Dependency within a pass.** If the canonical body for a partial-death
  DedupRef is itself a Data entry that's *also* partial-death in the same
  pass, we read the Data body off its source segment. The fact that the
  Data entry will be compacted doesn't affect on-disk bytes at fetch time.
  Probably a non-issue; document and move on.
- **`source_hash` selection for Delta.** Delta carries multiple
  `delta_options`. Pick the first whose `source_hash` resolves via
  `extent_index`, matching the read-path order. If none resolve, defer.

### Testing for the deferred work

New proptest `SimOp` variants:
- `MultiLbaDedupRefOverwrite` — prior multi-LBA Data write (established
  hash H), later dedup write of the same bytes producing a multi-LBA
  DedupRef, partial overwrite on the DedupRef, GC. Expected: DedupRef's
  segment is compacted; sub-runs emitted; canonical segment untouched;
  surviving LBAs read correctly.
- `MultiLbaDeltaOverwrite` — file-aware import producing a multi-LBA
  Delta entry, partial overwrite, GC. Expected: Delta's segment compacted
  (either to canonical reconstructed body + sub-runs, or dropped if H
  has no external refs); read path still works for both the composite
  hash (if externally referenced) and the surviving sub-run LBAs.

Both should satisfy `gc_oracle` and leave no `has_partial_death` segments
once the machinery is in place.
