---
name: LSVD GC Strategies - StartGC vs SweepSmallSegments
description: Two distinct GC segment-selection strategies in LSVD: density-driven (StartGC) vs size-driven packing (SweepSmallSegments)
type: reference
---

## StartGC — Density-driven GC

**Triggered:** Explicitly on demand, or automatically when data density drops below threshold after a segment close.

**Segment selection:** `LeastDenseSegment()` — picks the single least-dense segment by utilization ratio (live bytes / total bytes). Iterates all segments, finds lowest density.

**Processing:** `gcSegment()` — copies live extents from one selected segment into a fresh output segment, then marks source segment deleted. Single-segment GC.

**Purpose:** Maximize space reclamation and improve overall utilization density when fragmentation builds up. Targets "worst offenders" (segments with most wasted space).

**Code path:** `control.go:304-347` (`startGC`, `gcSegment`), `segments.go:312-341` (`LeastDenseSegment`).

## SweepSmallSegments — Size-driven packing

**Triggered:** On idle (1-minute tick) if ≥2 small segments exist, or explicitly via `SweepSmallSegments` event.

**Segment selection:** `FindSmallSegments(cutoff=200, max=20_000)` — finds all segments with ≤200 blocks of live data, bundles them together up to 20K blocks total. **Not density-driven; purely size-based.**

**Processing:** `packSegments()` — packs **multiple segments** into a single output segment by copying live extents from all of them, then marks all sources deleted.

**Purpose:** Consolidate many small segments (low utilization, high metadata overhead) into fewer, fuller segments. Trades multiple sparse segments for one more-utilized segment.

**Code path:** `control.go:157-166` (`sweepSmallSegments`), `control.go:403-459` (`packSegments`), `segments.go:194-221` (`FindSmallSegments`).

## Key Distinction

| Aspect | StartGC | SweepSmallSegments |
|--------|---------|-------------------|
| **Selector** | `LeastDenseSegment()` — lowest utilization % | `FindSmallSegments()` — smallest absolute sizes |
| **Trigger** | Density threshold breach or on-demand | Idle tick if ≥2 small segments |
| **Input segments** | 1 (worst offender) | 2–N (all under size cutoff) |
| **Output** | Single new segment | Single new segment (packed) |
| **Goal** | Space efficiency via density | Metadata efficiency via consolidation |

StartGC is **reactive and sparse-fixing**: when density degrades, target the wasteful segment. SweepSmallSegments is **proactive and preventive**: during idle, sweep up accumulated small segments to avoid metric bloat.

## Implementation Notes

- Both use same `CopyIterator` machinery to extract and repack live extents.
- Both are atomic at the LBA-map level (patching only applies if no extents were recycled).
- `handleLongIdle()` (line 126–135) chains: find small segments → if ≥2, pack; else improve density (run StartGC).
- Constants: `SmallSegmentCutOff=200` blocks, `MaxBlocksPerSmallPack=20_000` blocks, `GCDensityThreshold=75%`.
