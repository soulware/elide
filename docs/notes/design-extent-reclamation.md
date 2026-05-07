---
status: landed
related: [design-noop-write-skip.md, plan-actor-offload.md]
---

# Extent reclamation

Volume-side primitive that rewrites bloated multi-LBA extent bodies into compact new-hash entries.

## Why this exists

`Volume::write()` produces one `SegmentEntry` per write with `lba_length` equal to the inbound size. Later partial overwrites split the LBA-map entry via `payload_block_offset` aliasing without touching the original stored body. Reads stay correct (each surviving sub-range resolves through the original compressed payload) but every read decompresses past the dead interior blocks. Reclaim rewrites the surviving sub-ranges into fresh compact payloads, leaving the original hash fully orphaned so a later GC pass can reclaim the body.

## Three-phase shape

Same pattern as the other actor offloads (see [plan-actor-offload.md](plan-actor-offload.md)).

1. **Prepare** (actor): Arc-clone `LbaMap` and `ExtentIndex`, capture extents over the target range, mint output ULID, package into a `ReclaimJob`.
2. **Execute** (worker): for each non-zero-hash extent, two gates decide whether it's worth rewriting:
   - **Containment**: every run of the hash in the lbamap must sit inside the target range. Rewriting a hash referenced outside would leave external references pointing at the bloated body.
   - **Bloat**: `live_blocks < logical_blocks` (`logical_blocks = body_length / 4096` exact for uncompressed Data, `max_offset_end` lower bound otherwise). Catches both middle splits and pure tail overwrites.
   Hashes that pass are sliced, re-hashed, compressed, and emitted as a single signed segment in `pending/`.
3. **Apply** (actor): `Arc::ptr_eq(result.lbamap_snapshot, self.lbamap)` — if the lbamap was mutated mid-flight, delete the orphan segment and discard. Otherwise splice the new entries.

## Why the WAL is bypassed

Reclaim outputs are derivable from already-durable state. Crash before the segment rename → nothing to recover (old entries unchanged). Crash between rename and apply → orphan segment that GC sweeps as all-dead. Same property repack relies on.

## Space reclamation is deferred to GC

A successful reclaim updates the lbamap and leaves the original hash's body in its source segment as an LBA-dead entry. GC reclaims it later when the containing segment crosses the eligibility threshold. So `runs_rewritten > 0` from `elide volume reclaim` means "scheduled", not "freed on disk".

## Coordinator wiring

`elide-coordinator/src/tasks.rs` calls `control::reclaim(&fork_dir, Some(1))` per drain tick: scanner runs, top-scoring candidate is reclaimed. Cap of 1 per tick bounds latency; sustained bloat converges across ticks because the scanner sorts most-wasteful-first. Skipped for readonly volumes and during import-serve. Like repack/delta_repack, reclaim takes a `parked_reclaim` slot — concurrent IPC returns an error.

## Output shape: prefer Delta when the source will survive anyway

When the reclaimed hash H will outlive the reclaim — either because `H.segment_id <= snapshot_floor_ulid` (snapshot-pinned) or `delta_source_refcount(H) > 0` (already a delta source) — the sliced sub-range is emitted as `Delta { source_hash: H }`. zstd-dict-compressing a literal substring of H against H itself resolves to a few-hundred-byte dictionary reference, dramatically smaller than a fresh body. When neither pin holds, fresh Data lets GC drop H next pass. DedupRef still beats both when the new hash is already canonical.

## Open questions

- **Threshold tuning.** `ReclaimThresholds` defaults are placeholders. Needs empirical work on an aged volume to pick the "worth firing" bar.
- **Hard cap on proposals per pass.** Scanner sorts most-wasteful-first; a per-pass cap bounds worker CPU and apply lock-hold duration.
- **`elide volume reclaim` is not customer-facing** — exists to exercise the primitive end-to-end.
