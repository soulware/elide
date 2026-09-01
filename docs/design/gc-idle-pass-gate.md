# GC idle pass gate

## Problem

A GC pass rebuilds the full liveness view before it can learn that there
is nothing to collect. `load_pass_state` walks the fork chain, parses and
verifies every segment index, builds the extent index and the LBA map,
and replays the WAL. Only then does `eligible_stats` exist, and only then
can the pass answer "no candidates".

The cost is per volume, per tick, and it does not depend on guest
activity. Measured on `fragrant-meadow-060` at v0.1.58-rc24, with no
guest and no writes:

    running volume servers   ticks/120s   core
    0                              15     0.125%
    1                             532     4.43%
    3                            1528    12.73%

The three points are collinear. **An idle volume costs the coordinator
about 4.2% of a core, forever**, which puts the host ceiling near 24
volumes per core. A pass over a 213-segment volume takes about 415 ms of
coordinator CPU, 12 times per 120 s.

## The gate

A pass reads a small set of inputs, and a directory listing names all of
them. Hash that listing. When the hash matches the hash of a previous
pass that emitted no plan, replay that pass's result and skip the
rebuild.

`pass_fingerprint` hashes, in order:

- each layer of the rebuild chain: the directory path and the branch ULID
- each segment the layer discovers: the tier and the ULID, in the order
  `discover_fork_segments` returns them
- each WAL file: the name, the length and the modification time
- the snapshot floor ULID

The segment part reuses `discover_fork_segments`, so the fingerprint sees
the list the rebuild consumes, in the same processing order. A segment's
content is fixed once written, so the ULID stands for the content. The
tier is in the hash because a promote moves a segment from `pending/` to
`index/`, which moves it in the processing order at identical content.

## Why a stale fingerprint is safe

**The fingerprint is sampled before the views are built.** A segment that
arrives between the two listings is absent from this pass's fingerprint
and present in the next one, so the next pass rebuilds. The same holds
for a WAL append. A missed input delays the gate by one tick; it survives
no tick.

The inverse ordering would be unsafe. A fingerprint taken after the
rebuild would record inputs the rebuild did not read, and the gate would
then replay a decision that was never made against that state.

## When the gate applies

The gate replays a cached result, so it applies only to a pass that had
no side effects and no unhashed inputs:

- the strategy was `None(NoCandidates)`, so no plan reached `gc/`
- `deferred_cold` was zero

The second condition covers cache residency. `is_cache_resident` filters
candidates after `load_pass_state`, and `cache/` is absent from the
fingerprint. A pass that deferred a cold candidate rests on an input the
hash does not cover, so it is never cached. A pass with no cold deferrals
reads `cache/` for nothing.

Everything else the pass reads is in the fingerprint, is constant for the
process (`GcConfig`), or matters only when a plan is emitted (the
pre-minted bucket ULIDs).

## An idle volume holds still

`rotate_wal_into_promote` removes the open WAL when the volume has no
pending writes, so an idle fork's `wal/` is empty and stays empty. The
`gc_checkpoint` the coordinator sends every tick therefore leaves no
mark, and `index/`, `pending/` and `gc/` do not move either. The
fingerprint of an idle fork is stable across ticks, which is what lets
the gate fire at all.

## The hold

`IDLE_PASS_HOLD` bounds how long the tick loop replays one result. The
hold measures from the pass that ran rather than from the last replay, so
a static volume rebuilds on a fixed slow clock rather than never.

The hold is a floor under the reaction time, not a correctness device.
Its value is that the argument above may be incomplete in a way this
document does not name. At 120 s against a `gc.interval` of 10 s it costs
one pass in 12, and it turns "GC may never run again on this volume" into
"GC runs within two minutes".

The census rides the same clock. A replayed pass carries no census, and
`CENSUS_INTERVAL` is 300 s, so every census window holds real passes.

## Result

Measured against the same 213-segment corpus the pass cost came from:

    discover_fork_segments             0.179 ms
    listing + hash (the fingerprint)   0.188 ms
    rebuild_views (what it skips)    179.091 ms

**The fingerprint costs 0.1% of the rebuild it replaces.** An idle volume
runs one real pass per hold window instead of one per `gc.interval`, so
its coordinator cost falls from about 4.2% of a core to about 0.35%, and
the host ceiling rises from about 24 volumes per core to about 280.

The gate changes no admission rule, no plan, and no liveness
computation. A pass that does work runs as before, and pays one extra
directory listing.

## Related

- `docs/design/gc-plan-handoff.md` — what a pass emits
- `docs/design/read-state-divergence-check.md` — the other per-tick disk
  scan, which compares the committed tier against the daemon
