---
status: landed
related: [design-dedup-delta-invariants.md, design-delta-materialisation.md]
landed_in: ../formats.md
---

# Delta compression via file-path matching

Empirical work ([findings.md](../findings.md)) shows zstd-with-dictionary delta compression saves 94% of S3 fetch bytes between Ubuntu 22.04 point releases when the prior file version is the dictionary. The shipping pipeline rests on **file-path matching**: same path in two snapshots is overwhelmingly likely the same logical file, so the prior version of that path is the natural dictionary. LBA matching doesn't work — ext4 relocates file data across updates, so the same LBA may hold a completely different file.

The two preconditions:
1. A `path → hash` map at each snapshot — the **filemap**.
2. File-aligned extents (one extent ≈ one file) so the dictionary is the whole prior file.

Both produced at import time by parsing ext4 metadata before writing segments.

## Filemap format

`snapshots/<ulid>.filemap`, line-oriented text:

```
# elide-filemap v2
<path>\t<file_offset>\t<blake3-hex>\t<byte_count>
```

A contiguous file appears as a single line with `file_offset = 0`; a fragmented file appears as multiple lines with the same path. Written once, never modified, uploaded to S3 alongside segments. Only ext4 volumes have filemaps; non-ext4 has no delta — full extents only.

**Not in the segment format.** Paths are a snapshot-level concept. Embedding paths in the segment index would couple storage to filesystem awareness for data only used at delta-compute time.

## Thin Delta entry kind

`EntryKind::Delta` mirrors thin DedupRef: `stored_offset = 0, stored_length = 0`, no body bytes. Content is materialised by fetching the delta blob from the segment's delta section and zstd-dict-decompressing against the source extent body, located via `extent_index.lookup(source_hash)`. Multiple delta options per entry act as hints (graceful degradation across skipped releases).

**Source must resolve to a DATA entry** — no delta-of-delta chains. Bounds decompression to a single dictionary apply and keeps GC liveness reasoning linear.

Invariants and worked examples: see [design-dedup-delta-invariants.md](design-dedup-delta-invariants.md).

## Read path: source selection

For an entry with multiple delta options:

1. Scan options in order. If a source segment's body is **already in local cache**, pick it and stop.
2. Otherwise scan again and pick the **earliest-ULID** source — oldest bases are most reusable across future deltas, and any two hosts fetching the same child extent pick the same source (cross-host cache convergence).
3. Fetch source body + delta blob + zstd-dict decompress → write to `.body`, set `.present`.
4. If no option resolves: thin Delta returns a fetch error. No fallback is the price of thin delta.

Delta bodies live in their own per-segment file — `cache/<id>.delta` — separate from `.body`. Keeping them out of `.body` means `.body` has a single unambiguous shape.

## Pipelines (where delta entries get produced)

**File-aware import** — `elide-import` parses ext4, iterates files, and emits one DATA entry per contiguous fragment with the fragment's BLAKE3 as the hash. After all pending segments are written but before `serve_promote`, `delta_compute::rewrite_pending_with_deltas` path-matches changed files against the source filemap (via provenance lineage) and rewrites matching DATA entries as thin Delta. Skip heuristics: extent below threshold, `delta_length >= body_length`, source body not locally available. Skipped extents stay as DATA.

**Post-snapshot delta repack (Tier 1)** — `Volume::delta_repack_post_snapshot` (`elide-core/src/volume.rs`) runs from the per-volume coordinator tick before `drain_pending`. Walks pending segments above the latest sealed snapshot's ULID and rewrites Data entries against the prior snapshot's same-LBA fragment via a snapshot-pinned `BlockReader`. No filemap needed — `lba_map.lookup → extent_index.lookup` returns the whole containing fragment. Covers in-place file modification (package upgrades, config edits, fixed-offset log writes), the dominant NBD case.

**Tier 2 (deferred)** — same-path cross-LBA via filemaps. Catches cases where LBAs moved between snapshots (defrag, rename-with-realloc). Lands later with no format change.

zstd dictionary compression is always correct regardless of dictionary; the source-selection heuristic only affects ratio. The `delta_length >= body_length` check catches misses. **Always correct, sometimes no benefit.**

## Why filemap generation is an explicit verb

Originally ran inline in the snapshot sequence after `sign_snapshot_manifest`. Removed: the ext4 layout scan + per-fragment hash lookup demand-fetched each missing block range across the ancestor chain and dominated `volume release` wall time on freshly-pulled volumes (~104 s on an 8-deep chain). Phase 4 is strictly additive — failures never fail the snapshot — and the only consumer is operator-invoked `volume import --extents-from`. So the cost was on the user-visible release path while the benefit landed on a separate manual command.

Now: `elide volume generate-filemap <name> [--snapshot <ulid>]`, run before `volume import --extents-from <source>` if delta on that source is wanted. Without a source filemap the import path skips delta opportunities for that source and falls back to plain DATA.

## Snapshot integrity prerequisite

Tier 1 was the first real consumer of `BlockReader::open_snapshot` in the live loop and surfaced a latent bug: the snapshot manifest was being signed over `index/` before in-flight GC handoffs had been applied, so volume-applied handoffs from the prior tick could still reference segments `promote_segment` was about to delete. Fix: drain GC handoffs (`apply_gc_handoffs` IPC + `apply_done_handoffs`) inside `snapshot_volume` **before** `sign_snapshot_manifest`, under the snapshot lock. The structural follow-on (every `gc/` mutation routing through the volume actor) landed alongside; see [design-gc-self-describing-handoff.md](design-gc-self-describing-handoff.md).

## Open questions

- **Symlinks and hardlinks.** Symlinks are skipped (not regular files). Hardlinks produce duplicate filemap entries with different paths but the same hash — harmless, worth deduplicating to keep the filemap compact.
- **Phase 6 (content-similarity selection).** Filesystem-agnostic delta via content fingerprinting. Deferred — marginal benefit over path matching for the primary workload, significantly more complex.
