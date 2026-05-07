---
status: landed
related: [design-gc-plan-handoff.md, design-gc-self-describing-handoff.md]
---

# GC ULID ordering and the single-mint invariant

## The invariant

**Every segment ULID in a fork must come from a single monotonic source.** ULID ordering is the foundation of crash-recovery correctness: rebuild applies segments in ULID order, and a GC output sorting *after* a concurrent WAL would shadow the WAL's correct entries with the GC output's stale ones.

## Why two-source minting was unsafe

Volume and coordinator originally generated ULIDs independently:

- Volume: `UlidMint` seeded from `max(existing ULIDs)` on open.
- Coordinator GC: `max(inputs).increment()`.

In production, GC inputs are seconds to minutes old, so `increment()` produces a ULID far below the current WAL — the invariant held by time alone. Proptest collapses time to zero, exposing the race: same-millisecond ULIDs sort by the 80-bit random portion (a coin flip), and after multiple GC rounds `increment()` deterministically marches forward while the volume's mint draws random positions.

A naive single-mint fix (coordinator requests GC ULIDs from the volume) actually broke rebuild ordering more thoroughly: a future-minted GC output ULID always sorted **after** the in-flight WAL, so its stale entries unconditionally won.

## Fix: `gc_checkpoint`

Before running a GC pass the coordinator calls `gc_checkpoint` on the volume actor. The handler:

1. Flushes the in-flight WAL to `pending/`.
2. Mints fresh ULIDs from the volume's own generator (`mint.next()`).
3. Returns them to the coordinator.

Because the WAL is flushed *before* minting, no in-flight WAL segment can have a ULID below the returned value. The mint advances past the minted ULIDs, so all subsequent WAL segments sort above the GC output. The GC output therefore always sorts below any concurrent or future write, and the WAL's entries win on rebuild.

The actor's `GcCheckpoint` handler **must** use the volume mint, not `Ulid::new()` (system clock) — bug a9d0488 was a regression that produced ULIDs unrelated to the mint.

## Related guards

- **Extent-index per-entry CAS**: `apply_gc_handoffs` updates each entry only if `extent_index[hash].segment_id == old_ulid` (the entry's recorded source). Closes the TOCTOU between coordinator liveness check and volume apply.
- **`NotFound` tolerance in rebuild**: `lbamap::rebuild` / `extentindex::rebuild` / `Volume::repack` skip-with-warning on a missing segment file (coordinator GC may have deleted it). Always safe — the new compacted segment with higher ULID provides the correct entries.

## Note on terminology

This doc predates the plan-handoff GC protocol (see [design-gc-plan-handoff.md](design-gc-plan-handoff.md), [design-gc-self-describing-handoff.md](design-gc-self-describing-handoff.md)). The historical `.pending` / `.applied` / `.done` filenames have been replaced by `gc/<ulid>.plan` → bare `gc/<ulid>` → deleted, with the consumed-input ULID list carried in the segment header. The ULID ordering invariants are unchanged. `gc_checkpoint` now pre-mints `(u_gc, u_flush)` in one shot under the unified GC pass; the post-checkpoint WAL is opened lazily on the next write since `mint.next()` is strictly monotonic.
