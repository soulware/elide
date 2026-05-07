---
status: landed
related: [design-gc-overlap-correctness.md]
landed_in: ../operations.md
---

# Compacting partial-LBA-death segments

[`design-gc-overlap-correctness.md`](design-gc-overlap-correctness.md) established correctness by *skipping* segments that contain a partial-LBA-death entry. This compaction path **decouples the composite body from the surviving sub-runs**, so each can subsequently be handled by normal GC independently.

The compaction output for a partial-death entry:
- `canonical_only` (when needed to preserve the composite hash) holding the full composite body, **plus**
- a fresh `Data` entry for each live sub-run.

After compaction the composite body is referenced only by whatever external DedupRefs/Deltas still point at it; each surviving sub-run is a first-class entry with its own hash and LBA claim; normal GC can then reclaim either piece on its own.

## Decision

Partial-death is a fourth outcome of `collect_stats`'s per-entry classifier (alongside fully-alive, fully-dead, and `canonical_only`). The segment flows through normal GC; compaction runs **per entry**, not per segment.

Body resolution depends on entry kind: `Data`/`Inline` read inline; `DedupRef` resolves through `extent_index[hash]`; `Delta` resolves a `delta_options[i].source_hash` via the index and reconstructs through `apply_delta`.

The composite body is emitted as `canonical_only` only if the hash is still externally referenced — checked against both `DedupRef.hash == H` and `Delta.base_hash == H`. For Delta entries the canonical is **reconstruct-and-inline**: stored as an uncompressed full body, not re-encoded as a Delta — trading compactness for O(1) dedup reads. For DedupRef the source segment never owned the composite body, so no canonical is emitted at all.

Sub-runs always emit fresh `Data`, never `DedupRef`. A `DedupRef` would depend on the target segment surviving this pass, which isn't determinable at expand time. Space cost is bounded — partial-death is rare.

## Defer case

A segment stays deferred (`has_partial_death = true`) iff it contains a partial-death Delta entry whose `delta_options` have no resolvable `source_hash` in the current extent index. No base body, no reconstruction this pass. Retries next tick, when a later write may re-establish a source. Every other partial-death shape is handled in-band.

## Notes

- Hash collision (overwriter's hash happens to equal `entry.hash`): `extents_in_range` reports the whole range as matching — fully-alive, never enters this path.
- Post-GC `extent_index` ordering inherits the existing "DedupRef → lower ULID" relaxation (PR #23); no novel ordering problem introduced.
- `MultiLbaDeltaOverwrite` proptest SimOp is the outstanding coverage gap — needs filemap orchestration in the SimOp driver.
