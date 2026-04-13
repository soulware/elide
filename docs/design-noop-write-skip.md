# Design: skip no-op writes

**Status:** Proposed.

## Problem

The current write path in `Volume::write()` (`elide-core/src/volume.rs:505`) treats every inbound block uniformly: hash, dedup-check, append WAL record, update LBA map. For an incoming 4 KiB block whose content is *identical* to what already lives at that LBA, the path still writes a ~50 byte DedupRef (REF) record to the WAL and pays the durability barrier.

This case is not rare under real workloads: ext4 journal replay, filesystem metadata rewrites landing on identical values, page-cache double-flushes, and zero-over-zero writes during `mkfs`/`fstrim` all generate same-LBA same-content writes.

## Proposal

After hashing the incoming block, check the LBA map. If the LBA already maps to the same hash, return `Ok(())` immediately.

```rust
let hash = blake3::hash(data);

if let Some((existing, _)) = self.lbamap.lookup(lba)
    && existing == hash
    && covers_full_range(lba, lba_length) // see below
{
    return Ok(());
}
```

Placed at `volume.rs:518`, before the existing extent-index dedup check at line 532.

## What is saved

Per skipped write:
- WAL append (~50 bytes) and its durability barrier
- `pending_entries` growth (one `SegmentEntry::new_dedup_ref`)
- `lbamap.insert()` of an identical entry
- The resulting REF record that later flushes into `pending/` as a zero-body segment entry

Hashing still runs — the skip is decided *from* the hash, not in place of it.

## Correctness

**Fork layering.** `open_read_state()` (`volume.rs:2783`) builds a single flat `LbaMap` via `lbamap::rebuild_segments()` (`lbamap.rs:319`) that walks the entire ancestor chain oldest-first and inserts every segment entry into one map. Parent entries are flattened into `self.lbamap` at open time; there is no chain-walking at lookup. Consequence: a child fork's `lbamap.lookup(lba)` already surfaces inherited parent mappings, so an identical-content write to an inherited LBA matches and is correctly skipped. On reopen, `rebuild_segments` reproduces the same flat state from the ancestor chain, so the skipped write leaves no footprint and needs none.

**Snapshots.** A skipped write produces no local segment entry. The snapshot's view of that LBA is inherited from the parent — which is exactly right, since the content is unchanged.

**Multi-block writes.** `lbamap::lookup(lba)` returns the hash of the extent that *starts at or before* `lba` and covers it. To skip a write of length `lba_length`, every 4 KiB block in the range must map to a matching hash. The straightforward form is to require a single LBA map entry that covers the full range with the matching hash. Partial-match skipping (some blocks match, some don't) is out of scope: fall through to the normal path.

**No body fetch.** The check is pure in-memory hash comparison against the LBA map. It never triggers a demand fetch of ancestor or S3 bodies. BLAKE3's collision resistance makes hash equality sufficient; no byte comparison is needed. If the canonical body for the matching hash lives only in S3 (not demand-fetched), the skip still works — we never touch the body.

**Durability.** The NBD layer must continue to honour FUA/FLUSH by calling `volume.fsync()`. The skip only means *this* call adds no new WAL bytes; any previously-appended WAL data still needs to be durably committed on flush. The skip does not change the flush/fsync contract.

## Comparison: lsvd

The lab47/lsvd reference implementation does **not** have this optimization — and has no write-time content dedup at all. `disk.go:681` (`WriteExtent`) unconditionally buffers every incoming write; `segment.go:538` (`SegmentBuilder.WriteExtent`) computes entropy and compression stats but no content hash. Duplicate LBA writes simply overwrite previous LBA map entries, and stale extents are reclaimed later by GC.

Elide already diverges from lsvd by doing write-time content dedup (the REF-record path). This proposal is an incremental tightening of that existing mechanism: once you pay for the hash, use it to catch the same-LBA no-op as well as the cross-LBA duplicate.

## Non-goals

- Partial-range no-op skipping (only full-range matches are skipped).
- Any change to `write_zeroes` / `trim`, which already bypass hashing.
- Any change to the REF-record path for cross-LBA dedup.
