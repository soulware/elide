---
status: landed
related: [design-gc-partial-death-compaction.md]
---

# GC correctness for overlapped multi-LBA entries

A multi-LBA segment entry whose range has been partially overwritten can either shadow the overwriter (tail / interior overlap) or erase a surviving sub-run (head overlap) when GC compacts the old segment. The bug was in `collect_stats`: it decided liveness with a single-LBA point query, missing what was happening at the other LBAs in the entry's range.

## The five shapes

Using **head / tail / interior** anchored to the existing entry:

| Shape | `hash_at(start_lba)` | Old behaviour | Correct? |
|---|---|---|---|
| Disjoint | entry.hash | kept intact | yes |
| Whole entry overwritten | different | `canonical_only` (or dropped) | yes |
| **Head** (first LBA overwritten, tail survives) | different | `canonical_only`; surviving tail's binding lost on rebuild | **no** |
| **Tail** (last LBA overwritten, start survives) | entry.hash | kept intact; dead tail shadows overwriter on rebuild | **no** |
| **Interior** (both ends survive, middle overwritten) | entry.hash | kept intact; dead middle shadows overwriter on rebuild | **no** |

Three of five shapes are wrong. Same root cause: the emitted entry's `(start_lba, lba_length)` tuple disagrees with the live `lbamap` across its range.

## Fix: skip partial-LBA-death in `collect_stats`

Use a range scan, not a point query. Count how many of the entry's claimed LBAs still map to `entry.hash`:

- `matching_bytes == total_bytes` → fully alive, keep intact.
- `matching_bytes == 0` → fully dead, `canonical_only` if hash externally referenced, else removed.
- otherwise → **partial-death**: skip compaction of this segment this round.

Skipping is correct because rebuild applies segments in ULID order. The bloated entry's full-range claim is split by the later overwriter at insert time — `lbamap::insert`'s split logic produces the right runtime state. Coordinator's liveness view now matches the volume's; stale-liveness cancels stop firing.

`canonical_only` narrows correctly: it now only fires when `matching_bytes == 0` (whole entry LBA-dead while hash remains live via a DedupRef elsewhere) — its original intent.

## Followup

Skip-only leaves the bloated segment on disk indefinitely with its dead bytes. [design-gc-partial-death-compaction.md](design-gc-partial-death-compaction.md) added the compaction path that decouples the composite body from the surviving sub-runs so each can subsequently be reclaimed by normal GC.
