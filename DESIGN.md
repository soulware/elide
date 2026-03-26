# Design

## Problem Statement

Running many VMs at scale on shared infrastructure presents a storage challenge: base images are largely identical across instances, evolve incrementally over time, and yet are conventionally treated as independent copies. Each VM gets its own full copy of the image, even though 90%+ of the data is shared and most of it is never read at runtime.

The goal is a block storage system that minimises storage cost, minimises cold-start latency, and handles image updates efficiently at scale. The approach combines four techniques that individually exist but have not previously been integrated in this way:

- **Log-structured virtual disk (LSVD)** — write ordering and local durability, with S3 as the large capacity tier
- **Demand-fetch** — only retrieve data from S3 when it is actually needed; data never accessed is never transferred
- **Content-addressed dedup** — identical chunks written to the same volume tree are stored once; dedup is local and opportunistic
- **Delta compression** — near-identical chunks (e.g. a file updated by a security patch) are stored as small deltas in S3, reducing fetch size for updated images

The combination is particularly effective for the VM-at-scale use case because: base images are highly repetitive across snapshots of the same volume (dedup captures shared content), images evolve incrementally (delta compression captures changed content), most of each image is never read at runtime (demand-fetch avoids fetching unused data), and the same image is booted many times (locality optimisation pays back repeatedly).

## Key Concepts

**Block** — the fundamental unit of a block device, 4KB. This is what the VM sees.

**Extent** — a contiguous run of blocks at adjacent LBA addresses, and the fundamental unit of dedup and storage. Extents are variable-size and identified by the BLAKE3 hash of their content. BLAKE3 is chosen because: it is as fast as non-cryptographic hashes on modern hardware (SIMD-parallel tree construction), its 256-bit output makes accidental collisions negligible (birthday bound ~2^128 operations), and it has first-class Rust support. Collisions cannot be prevented by any hash function, but with 256-bit output the probability is effectively zero for any realistic chunk count.

Note: "extent" is also an ext4 term — an ext4 extent is a mapping from a range of logical file blocks to physical disk blocks, recorded in the inode extent tree. These are distinct concepts. Where the distinction matters, "ext4 extent" or "filesystem extent" refers to the filesystem structure; "extent" alone refers to the LSVD storage unit.

**Live write extents** are bounded by fsync and contiguous LBA writes. A write to LBA 100–115 and an adjacent write to LBA 116–131 arriving before the next fsync are coalesced into one extent covering LBA 100–131. Writes to non-contiguous LBAs stay as separate extents regardless of fsync timing — coalescing only applies to adjacent LBA ranges. Live write extents are **opportunistic dedup candidates**: full-file writes (e.g. `apt install`) may happen to align with file boundaries and dedup well; partial file edits will not.

**Manifest** — a serialised point-in-time freeze of the LBA map. The live LBA map is the authoritative source; the manifest is an optional cache of it, useful for fast startup. **The manifest is always derivable from the segments** — each segment's `.idx` file carries the LBA metadata for its extents, so the LBA map can be reconstructed by scanning the volume tree's `.idx` files. S3 persistence of the manifest is an optimisation (to avoid expensive segment scans at startup), not a correctness requirement.

**Snapshot** — a frozen volume node. Taking a snapshot creates a new live child node under the current node; the current node becomes frozen (read-only). Snapshots form a tree: the directory structure is the source of truth for the parent chain. No separate manifest is required to traverse the tree. A snapshot can be used as a rollback point or as the base for multiple independent forks.

**Segment** — a packed collection of extents, typically ~32MB, stored as three S3 objects: a full body, a delta body, and a companion `.idx` file. The 32MB size is a soft flush threshold. Each segment's `.idx` carries the LBA metadata for its extents, making the LBA map reconstructible from `.idx` files alone. Segments are the unit of S3 I/O.

**Write log** — the local durability boundary. Writes land here first (fsync = durable). Extents are promoted to segments in the background.

**Extent index** — maps `extent_hash → (segment_ULID, body_offset)`. Tells the read path where a given extent lives. The ULID is globally unique; its path on disk is derived at runtime by scanning the common root. Built at startup by scanning the volume's own tree plus, opportunistically, all other volumes' segments under the common root — enabling best-effort cross-volume dedup with no coordinator involvement.

## Operation Modes

The system operates in two tiers depending on whether the volume's filesystem is understood:

**Basic LSVD** (any filesystem or raw block usage):
- Write coalescing, local durability, demand-fetch, S3 backend, snapshots — all work correctly
- Dedup is opportunistic: fsync-bounded extents may or may not align with file boundaries
- Cross-version dedup quality is low without alignment — raw fixed-offset blocks yield ~1% overlap between image versions
- Suitable for data volumes, Windows VMs, XFS/btrfs volumes, or any use case where dedup is not the primary concern

**Enhanced LSVD + dedup** (ext4 volumes):
- Everything above, plus snapshot-time ext4 re-alignment of extents to file boundaries
- Reliable file-aligned extents → ~84% exact match between Ubuntu point releases
- Delta compression maximally effective because extents correspond to files
- The approximation "one extent ≈ one file" holds well — the palimpsest `extents` subcommand, which parses ext4 inode extent trees directly, is the prototype for this

The block device itself is filesystem-agnostic in both modes. ext4 awareness is an optional layer that sits alongside the snapshot process — it re-slices and re-hashes extents at file boundaries using the ext4 extent tree as ground truth. A coalesced extent spanning multiple files is split; multiple extents covering one file are merged. The live write path is unaffected in either mode.

Other filesystem parsers (XFS, btrfs) could bring additional filesystems into the enhanced tier over time. The interface is simply: "given this volume at snapshot time, return file extent boundaries."

## Architecture

### Design principle: the volume is the primitive

A volume process is **always self-contained and fully functional on its own**. It requires no coordinator, no S3, no other volumes. Local storage (WAL + segments on NVMe) is a complete and correct deployment — not a degraded or temporary state. This must remain true as the system grows: nothing added to the coordinator should become a correctness dependency for the volume.

The coordinator and S3 are **strictly additive**:
- Without coordinator: volumes run indefinitely on local storage; `pending/` accumulates but I/O is always correct
- With coordinator: GC reclaims space, S3 provides durability and capacity beyond local NVMe
- With coordinator + S3: full production deployment

This layering also means a single volume process can be started standalone for development, testing, or debugging with no service scaffolding required.

### Components

A single **palimpsest coordinator** runs on each host and manages all volumes. It forks one child process per volume — the process boundary is deliberate: a fault in one volume's I/O path cannot corrupt another, and the boundary forces the inter-component interface to be explicit and real (filesystem layout, IPC protocol, GC ownership) rather than loose in-process coupling.

**Coordinator (main process)** — spawns and supervises volume processes; owns GC (runs as a coordinator-level task with access to all volumes' on-disk state); handles S3 upload/download.

**Volume process** (one per volume) — owns the ublk/NBD frontend for one volume; owns the WAL and pending promotion for that volume; holds the live LBA map in memory. Does not communicate with other volume processes directly. Communicates with the coordinator via a defined IPC boundary (TBD — Unix socket or similar). Never requires the coordinator for correct I/O.

### Directory layout

All volume state lives under a shared root directory on a dedicated local NVMe mount. **The directory tree is the snapshot tree**: each node is a volume state at a point in time. A node containing `wal/` is a live (writable) leaf. A node without `wal/` is frozen (read-only). The parent chain is the directory ancestry — no manifest is needed to traverse it.

```
/var/lib/palimpsest/
  volumes/
    <volume-id>/                  — root node of a volume tree
      segments/                   — frozen after first snapshot
      <snap-ulid>/                — child node (snapshot or fork)
        segments/                 — frozen after next snapshot
        <snap-ulid>/              — grandchild node
          segments/
          wal/                    — live leaf: this is the current write target
          pending/
        <fork-ulid>/              — another live fork from the same parent
          segments/
          wal/
          pending/
  service.sock                    — Unix socket at a stable, known path
```

**Invariants:**
- `wal/` present → live leaf; the volume process writes here
- `wal/` absent → frozen; contents are immutable
- `pending/` always accompanies `wal/`
- All ancestor nodes of a live leaf are frozen and shared across all sibling forks; GC must not modify them

**Finding live volumes:** scan for directories containing `wal/`. Each such directory is an independently running volume process.

**Finding a volume's ancestry:** walk up the directory tree from the live leaf to the root. Each parent directory is a frozen snapshot layer; its `segments/` contribute to the LBA map via layer merging (ancestors first, descendants shadow).

```
VM
 │  block I/O (ublk / NBD)
 ▼
Volume process  (one per volume)
 │  write path: buffer → extent boundary → hash → local dedup check → WAL append
 │  read path:  LBA → LBA map → extent index → segment file (local or S3)
 │
 ├─ WAL  (wal/<ULID>)
 ├─ Pending segments  (pending/<ULID>{,.idx})
 ├─ Live LBA map  (in memory, LBA → hash; merged from own + ancestor layers)
 └─ IPC  (service.sock — optional for I/O, used for coordination)
      │
      ▼
Coordinator (main process)
 ├─ Volume supervisor  (spawn/re-adopt volume processes)
 ├─ GC / segment packer  (compacts live leaf segments; never touches frozen ancestors)
 └─ S3 uploader  (async, not on write critical path)
```

### Coordinator restartability

Volume processes are **detached** from the coordinator at spawn time (`setsid` / new session) so they are not in the coordinator's process group and are not signalled when it exits. The coordinator can be stopped, upgraded, or restarted without interrupting running volumes.

**Re-adoption on coordinator start:** when the coordinator starts, it scans for `wal/` directories and checks whether each has a running process (via a `volume.pid` file alongside `wal/`). Volumes with a live process are re-adopted. Volumes with no running process are started fresh and recover from their WAL as normal.

**IPC is reconnectable:** volume processes handle `service.sock` disappearing and attempt reconnection when it reappears. The IPC channel carries coordination traffic only (GC notifications, S3 upload confirmations) — loss of the channel degrades background efficiency but never affects correctness or I/O availability.

## Write Path

```
1. VM issues write for LBA range
2. Buffer contiguous writes; each non-contiguous LBA gap finalises an extent
3. For each extent:
   a. Hash extent content → extent_hash
   b. Check local extent index (own segments + all ancestor segments) for extent_hash
      - Found  → write REF record to WAL (no data payload)
      - Not found → write DATA record to WAL (fsync = durable)
4. Update live LBA map with new (start_LBA, length, extent_hash) entries
```

Durability is at the write log. S3 upload is asynchronous and not on the critical path.

**Dedup is local and opportunistic.** The write path checks the local extent index (covering the current volume's segments and all ancestor segments in the tree) before writing data. If the extent already exists anywhere in the local tree, a REF record is written instead — no data is stored again. Dedup is bounded to the local volume tree; no cross-tree or cross-host dedup check is performed. The quality of dedup depends on write alignment: fsync-bounded writes to the same files as prior snapshots dedup well; partial overwrites do not.

**No delta compression locally.** Delta compression is computed at S3 upload time and exists in S3 only. Local segment bodies contain either the full extent data (DATA records) or nothing (REF records, where the data already lives in an ancestor segment and is not duplicated). On S3 fetch, deltas are applied and the full extent is materialised locally before being cached and served to the VM.

## Read Path

```
1. VM reads LBA range
2. Look up LBA in live LBA map → extent_hash H
3. Check local segments (own pending/ + segments/, then ancestor segments/) for H
   - Hit  → return data
   - Miss → look up H in extent index → S3 location
4. Fetch extent from S3 (using .idx to select full or delta retrieval strategy)
5. Materialise full extent locally; return data to VM
```

The kernel page cache sits above the block device and handles most hot reads. The local segment cache handles warm reads. S3 is the cold path.

## LBA Map

The **LBA map** is the live in-memory data structure mapping logical block addresses to content. It is a sorted structure (B-tree or equivalent) keyed by `start_LBA`, where each entry holds `(start_lba, lba_length, extent_hash)`. It is updated on every write (new entries added, existing entries trimmed or replaced for overwrites) and is the authoritative source for read path lookups.

**Contrast with lab47/lsvd:** the reference implementation calls this `lba2pba` and maps `LBA → segment+offset` (physical location). GC repacking must update it for every moved extent. Palimpsest maps `LBA → hash` — the logical layer. Physical location (`hash → segment+offset`) is a separate extent index. This two-level indirection means GC repacking updates only the extent index; the LBA map is never rewritten for GC.

**Layer merging:** a live volume's LBA map is the union of its own data and all ancestor layers. At startup, layers are merged oldest-first (root ancestor first, live node last), so later writes shadow earlier ones. This is the same model as the lsvd `lowers` array, encoded in the directory tree.

### LBA map persistence

The LBA map is optionally persisted to a local `lba.map` file on clean shutdown and used as a fast-start cache on restart.

**Freshness guard:** the file includes a BLAKE3 hash of the sorted list of all current local segment IDs (own + ancestors). On startup, if the guard matches the current segment list, the cached LBA map is loaded directly without scanning `.idx` files. If the guard doesn't match (new segments were written, or ancestry changed), the LBA map is rebuilt from scratch.

**Rebuild procedure:**
1. Walk the directory tree from the root ancestor to the live node
2. For each node, scan its `segments/` and `pending/` `.idx` files
3. Apply each `.idx` entry to the LBA map (later layers take precedence for any overlapping LBA range)
4. Replay the current WAL on top (WAL entries are the most recent writes)

Since `.idx` files are the ground truth for segment contents, rebuilding the LBA map requires only `.idx` files and the WAL — never the segment data bodies. A full startup rebuild for a volume with 100 segments across its ancestry is a scan of ~6MB of `.idx` data, not 3GB of segment bodies.

### Manifest format

"Manifest" refers specifically to the **serialised form** of the LBA map, written optionally at snapshot time or as a startup cache. It is a correctness-optional optimisation — the LBA map is always reconstructible from `.idx` files. When a manifest exists and its freshness guard is valid, it allows startup without scanning any `.idx` files.

When persisted, the format is a binary flat file:

**Header (84 bytes):**

| Offset | Size | Field        | Description                          |
|--------|------|--------------|--------------------------------------|
| 0      | 8    | magic        | `PLMPST\x00\x02`                     |
| 8      | 32   | snapshot_id  | blake3 of all extent hashes in LBA order |
| 40     | 32   | parent_id    | snapshot_id of parent; zeros = root  |
| 72     | 4    | entry_count  | number of entries (u32 le)           |
| 76     | 8    | timestamp    | unix seconds (u64 le)                |

**Entries (44 bytes each, sorted by start_LBA):**

| Offset | Size | Field      | Description                          |
|--------|------|------------|--------------------------------------|
| 0      | 8    | start_lba  | first logical block address (u64 le) |
| 4      | 4    | length     | extent length in 4KB blocks (u32 le) |
| 12     | 32   | hash       | BLAKE3 extent hash                   |

One entry per extent. Unwritten LBA ranges have no entry (implicitly zero).

**Snapshot identity:** `snapshot_id = blake3(all extent hashes in LBA order)` — derived from the live LBA map, not from the file bytes. Identical volume state always produces the same snapshot_id regardless of when or where the manifest was serialised. The directory ancestry is the authoritative parent chain; `parent_id` in the manifest is a convenience field for S3 contexts where directory structure is not available.

## Extent Index

Maps `extent_hash → local location` (segment file + offset). Separate from the LBA map — the LBA map is purely logical (what data is at each LBA range), the extent index is physical (where that data lives on disk).

**Contrast with lab47/lsvd:** the reference implementation uses a single `lba2pba` map — a direct `LBA → segment+offset` (physical location) index. GC repacking requires updating this map for every moved extent. The LBA map + extent index split means GC can repack extents (changing their location) by updating only the extent index. The LBA map is never rewritten for GC.

The extent index covers the live node's own segments, all ancestor segments, and — on a best-effort basis — segments from other volumes stored under the same common root. At startup, the volume process scans the full common root directory tree, reading the index section of each segment file it finds. Ongoing updates use inotify (or periodic re-scan) to pick up new segments from other volumes as they are promoted. Because segment ULIDs are globally unique, `hash → ULID + body_offset` is sufficient to locate any extent; the on-disk path is derived at runtime from the ULID by searching the common root.

This is **purely local and coordinator-free**: the shared filesystem layout is the coordination mechanism. Cross-volume dedup is best-effort — a segment promoted by another volume after the last scan is a missed opportunity, not an error. Such duplicates are harmless and can be coalesced by GC.

## Dedup

**Exact dedup:** two extents with the same BLAKE3 hash are identical. Dedup is detected and applied **opportunistically on the write path**: before writing a DATA record to the WAL, the extent hash is checked against the local extent index (covering own + all ancestor segments). If a match is found, a REF record is written instead — no data payload, just a reference to the existing extent. This keeps the data volume in the WAL and segment files minimal without requiring any coordination or remote lookup.

Dedup scope is **all volumes on the local host**. The extent index covers the current volume's own tree (own + ancestor segments) plus, on a best-effort basis, all other volumes stored under the same common root. No remote or cross-host dedup check is performed. Dedup quality is highest for snapshot-derived volumes (ancestor segments already contain most of the data) and lower for freshly provisioned volumes; cross-volume dedup raises quality for volumes that share a common base image even without a snapshot relationship.

**Delta compression** is a separate concern from dedup and is **S3-only**. Local segment bodies never contain delta records — an entry in a local segment is either a full extent (DATA record, data present in body) or a reference (REF record, no data in this segment's body, data lives in an ancestor segment). At S3 upload time, extents that differ only slightly from extents in ancestor segments are stored as deltas in a separate delta segment file (see S3 Layout). The benefit is reduced S3 fetch size, not local storage cost. The primary value is latency: fetching a small delta instead of a full extent from S3 is dramatically faster on the cold-read path. On fetch, the delta is applied and the full extent is materialised locally before being cached and served.

**Delta source selection** is trivial at the extent level: the natural reference for a changed file is the same-path file in the parent snapshot. The snapshot parent chain gives direct access to the prior version of each extent.

Delta compression is compelling for point-release image updates; not worth the complexity for cross-version (major version) updates where content is genuinely different throughout.

**Empirically measured (Ubuntu 22.04 point releases, 14 months apart):**
- 84% of file extents are exact matches by count (zero marginal cost)
- 35% of bytes are covered by exact-match extents; the remaining 65% are in files touched by security patches
- The 65% in changed extents is the delta compression target: whole-file deltas against the previous snapshot's copy, which are typically tiny (a patch changes a small region of a large binary)
- Overall marginal S3 fetch to advance from one point release to the next: ~94% saving vs fetching fresh

## Snapshots

A snapshot freezes the current live node and starts a new live child. Snapshots serve two purposes: **checkpointing** (a rollback point for the same ongoing volume) and **forking** (launching a new independent volume from a known state). Both use the same mechanism.

**Taking a snapshot:**

```
1. Create <snap-ulid>/ as a child of the current live node
2. Create <snap-ulid>/wal/, <snap-ulid>/pending/, <snap-ulid>/segments/
3. Redirect new writes to the child immediately (live volume continues uninterrupted)
4. Background: flush any remaining WAL data to segments/ in the current (now-freezing) node
5. Background: remove wal/ and pending/ from the current node when flush completes
   → node is now frozen; directory contains only segments/
```

Steps 1–3 are the only blocking part and are instantaneous. Steps 4–5 are background and do not block I/O.

**Forking** (two VMs from the same snapshot point): once a node is frozen, create multiple children. Each child is an independent live volume that inherits the parent's data via the directory ancestry.

```
volumes/<base-id>/
  segments/                 ← frozen, shared by both forks
  <fork-a-ulid>/            ← VM A
    wal/
    pending/
    segments/
  <fork-b-ulid>/            ← VM B
    wal/
    pending/
    segments/
```

**Rollback:** delete the live leaf (and any of its descendants if needed), then re-create `wal/` and `pending/` in the target ancestor. The ancestor's segments are untouched.

**Checkpoint semantics (linear history):**

```
Before snapshot:          After snapshot:
volumes/<base>/           volumes/<base>/
  segments/                 segments/         ← frozen
  wal/               →      <snap-1>/
  pending/                    wal/            ← live continues here
                              pending/
                              segments/
```

**The directory tree is the source of truth.** No manifest file is required to understand the snapshot relationships or to reconstruct the LBA map. A manifest may be written as an optional startup optimisation, but its absence never affects correctness.

**GC interaction:** GC operates only on live leaf nodes (those with `wal/`). Frozen ancestor nodes are structurally immutable and shared across all descendants — a segment in a frozen ancestor cannot be deleted or repacked while any live descendant exists. This is the same constraint as the lsvd reference implementation's `removeSegmentIfPossible()` check: a segment is only reclaimable when no volume's read path can reach it. In the directory model, this is enforced structurally: a frozen node has no `wal/`, so GC never selects it.

**Migration and disaster recovery** share the snapshot code path: start a volume from a snapshot manifest on a new host. One operation, multiple use cases.

## S3 Layout and Index

Each segment is a **single S3 object** at `s3://bucket/segments/<ULID>`. The segment file contains four sections laid out sequentially. All section lengths are recorded in the header, so any byte range within the file is computable after reading the first 32 bytes.

### Segment file format

```
[Header: 32 bytes]
  magic          (8 bytes)  — "PLMPSEG\x01"
  entry_count    (4 bytes)  — number of index entries (u32 le)
  index_length   (4 bytes)  — byte length of index section (u32 le)
  inline_length  (4 bytes)  — byte length of inline section (u32 le); 0 if none
  body_length    (8 bytes)  — byte length of full extent body (u64 le)
  delta_length   (4 bytes)  — byte length of delta body (u32 le); 0 if no deltas

[Index section]             — starts at byte 32; length = index_length
[Inline section]            — starts at byte 32 + index_length; length = inline_length
[Full body]                 — starts at byte 32 + index_length + inline_length; length = body_length
[Delta body]                — starts at byte 32 + index_length + inline_length + body_length; length = delta_length
```

Derived section offsets (computable from the header alone):
```
index_offset  = 32
inline_offset = 32 + index_length
body_offset   = 32 + index_length + inline_length
delta_offset  = 32 + index_length + inline_length + body_length
```

**The full body** is raw concatenated extent data — DATA-record extents only, clean bytes, no framing. REF-record extents contribute nothing to the body. All navigation is via the index section.

**The delta body** is raw concatenated delta blobs, referenced by byte offset from the index section. It is absent on locally-stored segments (delta computation happens at S3 upload time) and present on the S3 object when the coordinator has computed deltas against ancestor segments.

**The inline section** holds raw bytes for inlined extents and inlined delta blobs. It is placed before the full body so a single `GET [0, body_offset)` retrieves the header, index, and all inline data together — sufficient for a warm-start client to serve all small extents without fetching the body at all.

### Index section entry format

**Flag bits** (1 byte per entry):
- `0x01` `FLAG_INLINE` — extent data is in the inline section; no body fetch needed
- `0x02` `FLAG_HAS_DELTAS` — one or more delta options follow
- `0x04` `FLAG_COMPRESSED` — stored data is zstd-compressed; lengths are compressed sizes
- `0x08` `FLAG_DEDUP_REF` — extent data lives in an ancestor segment; no body in this segment

```
For each extent:
  hash          (32 bytes)  — BLAKE3 extent hash
  start_lba     (8 bytes)   — first logical block address (u64 le)
  lba_length    (4 bytes)   — extent length in 4KB blocks (u32 le)
  flags         (1 byte)    — flag bits above

  if FLAG_DEDUP_REF:
    (no body fields — data located via extent index lookup on hash)

  if !FLAG_DEDUP_REF and !FLAG_INLINE:
    body_offset (8 bytes)   — byte offset within full body section (u64 le)
    body_length (4 bytes)   — byte length (compressed size if FLAG_COMPRESSED)

  if FLAG_INLINE:
    inline_offset (8 bytes) — byte offset within inline section (u64 le)
    inline_length (4 bytes) — byte length of inline data

  if FLAG_HAS_DELTAS:
    delta_count  (1 byte)   — number of delta options (≥1)
    per delta option:
      source_hash        (32 bytes) — BLAKE3 hash of the source extent
      option_flags       (1 byte)   — bit 0: FLAG_DELTA_INLINE
      if !FLAG_DELTA_INLINE:
        delta_offset     (8 bytes)  — byte offset within delta body section (u64 le)
        delta_length     (4 bytes)  — byte length in delta body (u32 le)
      if FLAG_DELTA_INLINE:
        delta_inline_offset (8 bytes) — byte offset within inline section (u64 le)
        delta_inline_length (4 bytes) — byte length of inline delta
```

`lba_length × 4096` always gives the uncompressed extent size. `body_length` / `inline_length` gives the stored (possibly compressed) size.

**FLAG_DEDUP_REF entries** carry only the LBA mapping, sufficient for LBA map reconstruction at startup. The extent data is located via the extent index (`hash → segment + body_offset`), populated from ancestor segment files at startup.

**FLAG_INLINE extents** store their full data in the inline section. This is particularly effective for the boot path: small config files, scripts, and locale data appear frequently during boot and are naturally small. A warm-start client that fetches `[0, body_offset)` gets all inline extents with no further requests.

**Multiple delta options** allow an extent to have deltas against several source extents (e.g. against the immediately prior snapshot and an earlier one). The client picks the first option whose `source_hash` is in its local extent index. If no source is available, the full extent is fetched from the body instead. This provides graceful degradation across skipped releases.

**FLAG_DELTA_INLINE** applies the same logic to delta blobs: a small delta is stored in the inline section, avoiding a separate byte-range fetch into the delta body.

**Index entries serve two purposes with a single scan:** LBA map reconstruction (`start_lba + lba_length + hash`) and extent index population (`hash → segment_id + body_offset + body_length`). No separate pass needed.

### Typical segment file sizes (~1000 extents, ~32MB body)

| Configuration | Index section | Notes |
|---|---|---|
| No deltas | ~57KB | Base case |
| 3 delta options, 16% of extents | ~70KB | Realistic point-release update |
| 3 delta options, all extents | ~193KB | Worst case |

Inline section size depends on the inline threshold and extent size distribution — typically small if the threshold is kept tight (e.g. ≤ a few KB per extent).

### Retrieval strategies

The header is 32 bytes; all section offsets are computable from it. This drives three distinct retrieval patterns:

**Cold start** (no local data — cannot use deltas):
```
Single GET of the entire file.
Delta body is at the end; the extra bytes are the cost of one request instead of two.
Parse index section → materialise all extents from body.
```

**Warm start** (some local data):
```
1. GET [0, body_offset)         — header + index + inline; make all fetch decisions
2. GET byte-ranges within body  — full extents needed (ranges coalesced)
3. GET byte-ranges within delta — delta blobs where source is available locally (ranges coalesced)
```

Steps 2 and 3 are independent and can be issued in parallel. Byte ranges within each section are sorted and nearby ranges merged into single GETs before issuing.

**Index-only** (startup LBA map and extent index rebuild):
```
GET [0, inline_offset)          — header + index section only; skip inline, body, delta
```

**Adaptive full-body fetch:** when the ratio of needed body bytes to `body_length` exceeds a threshold, a single GET of the body section is cheaper than many byte-range GETs. Threshold is byte-ratio based (not count-based) since extents are variable size.

**Segment files are the ground truth.** All derived structures (in-memory extent index, optional manifest) are caches reconstructible from segment files. On cold start or after index loss, reconstruction is: download index sections of all segment files (fast, small) rather than full segment bodies.

**Snapshot indexes** are consolidated index-section views written at snapshot time, covering all extents reachable from that snapshot. They are smaller than the full set of per-segment index sections and remain immutable. A snapshot index enables fast cold startup on a new host: download the snapshot index, then download index sections for segments written since the snapshot, union to get the full extent index.

**Index recovery flow:**
```
1. GET snapshot index for the relevant snapshot (if available)
2. GET [0, inline_offset) for each segment written since that snapshot
3. Union → full extent index
```

## GC and Repacking

**GC scope:** GC operates only on live leaf nodes — those containing `wal/`. Frozen ancestor nodes are structurally immutable and shared by all their descendants; their segments cannot be touched while any live descendant exists. This matches the lsvd reference implementation's approach: `removeSegmentIfPossible()` refuses to delete a segment referenced by any volume. In the directory model this is structural: absence of `wal/` means no GC.

To reclaim space from a frozen ancestor, all its live descendants must first be deleted or re-based. This constraint is intentional: it makes the invariant ("ancestor segments are immutable") enforceable without any reference counting.

**Standard GC within a live node:** walk the live node's LBA map, identify extents no longer referenced by any LBA range (overwritten or deleted), remove them from local segments after a grace period. Compact sparse segments by merging live extents into fresh, denser segments and updating the extent index.

**Delta dependency handling:** when a source extent is about to be removed and a live delta in S3 depends on it, materialise the delta first (fetch source + delta → full extent, write full extent to S3, update extent index). Then remove the source. The dependency map is derived fresh each GC sweep from the extent index — no persistent reverse index needed.

**Access-pattern-driven repacking:** GC extends beyond space reclamation to also improve data locality. Boot-path extents — identified from observed access patterns during VM startup — are co-located in dedicated segments. A cold VM boot then fetches one or two S3 segments to get everything needed for boot, rather than many scattered segments.

**Boot hint accumulation:** every VM boot records which extents were accessed during the boot phase (identified by time window after volume attach, or explicit VM lifecycle signals from the hypervisor). These observations accumulate per snapshot. After sufficient boots (converges quickly at scale — 500 VMs/day = 500 observations/day), the hint set is stable enough to guide repacking decisions.

**Continuous improvement:** first boot is cold; boot access patterns are recorded; next GC repack co-locates those extents; subsequent boots are faster. The feedback loop strengthens with scale.

**Snapshot-aligned repacking:** GC can reorganise S3 segments around snapshot boundaries, converging toward a two-tier layout:

```
s3://bucket/segments/base-<hash>     — extents shared across many snapshots
s3://bucket/segments/snap-<id>-N     — extents unique to a specific snapshot
```

Shared extents (e.g. the ~84% identical between Ubuntu 22.04 point releases) are consolidated into base segments. A new host serving any snapshot from the same family fetches these once. Snapshot-specific segments contain only the changed extents, stored as deltas against their counterparts in the base segments.

**Ext4 re-alignment during GC:** GC is a natural point to perform or improve extent re-alignment, not just snapshot time.

- **Snapshot nodes:** safe and clean — a snapshot is frozen, the filesystem state is fixed. GC can parse ext4 metadata and re-align any snapshot that was not aligned at creation time.
- **Live nodes:** the filesystem is in flux. GC uses the most recent frozen ancestor's ext4 metadata as a proxy. Re-alignment is approximate but safe — dedup quality improves progressively without risk of data corruption.

## Filesystem Metadata Awareness

Since the system controls the underlying block device, it sees every write — including writes to ext4 metadata structures (superblock, group descriptors, inode tables, extent trees, journal). This visibility is an opportunity to handle metadata blocks smarter than opaque data blocks.

**Metadata extent tagging:** once metadata LBAs are identified from the superblock (all at well-defined offsets), those extents can be tagged in the LBA map. Tagged metadata extents receive special treatment:
- Skip dedup — inode tables and group descriptors are volume-specific (unique inode numbers, volume-specific block addresses) and will never match across snapshots
- Cache aggressively — metadata blocks are hot; every filesystem operation reads them

**Incremental shadow filesystem view:** because every write to a known metadata LBA is visible, the system could maintain a continuously-updated internal view of the filesystem layout — which LBA ranges belong to which files, as files are created, deleted, and modified. At snapshot time, the shadow view is already current: no parse-from-scratch, re-alignment is essentially free.

**The journal problem:** ext4 metadata does not go directly to its final LBA. It is written to the jbd2 journal first (write → journal commit → checkpoint to final location). There are three levels of journal handling with very different complexity profiles:

- **Level 1 — detect that metadata changed (trivial):** writes to journal LBAs are visible at the block device level. We know a transaction is in flight but not what changed. Useful only for invalidating the shadow view ("metadata changed, re-parse at next opportunity"). No journal parsing required.

- **Level 2 — parse committed transactions at snapshot/GC time (moderate):** at a known-clean point (snapshot or GC checkpoint), read the journal, walk committed transactions, and replay them to recover current metadata state. This is what `e2fsck` does. The jbd2 format is well-documented with reference implementations in `e2fsprogs` and the kernel. A few hundred lines of careful Rust. Risk is low — we are parsing a frozen, consistent state. This is sufficient for snapshot and GC re-alignment.

- **Level 3 — live transaction tracking (high):** intercept journal writes in real time, parse each transaction as it commits, and update the shadow view incrementally. Requires recognising journal LBAs in the write stream, parsing jbd2 descriptor blocks to correlate data blocks with their final destinations, and correctly handling the circular log structure, transaction abort/rollback, and journal checkpointing. Getting this wrong silently produces an incorrect shadow view. The kernel's jbd2 module is the authoritative reference and is non-trivial.

One simplifying factor across all levels: ext4's default journaling mode is `data=ordered` — only metadata goes through the journal; data blocks are written directly to their final locations. Journal handling is therefore scoped to metadata only, not the full write stream.

**Recommended approach:** implement Level 2 first — sufficient for snapshot/GC re-alignment and well-understood. Level 3 (live shadow view) is only needed for real-time file-identity-aware dedup decisions and should be deferred until Level 2 is working well.

**Future potential:** a live shadow filesystem view would enable real-time dedup decisions informed by file identity — knowing that a write is to a known shared library vs. a per-VM log file, for example, without waiting for snapshot time. This is a significant capability that falls out naturally from controlling the block device, and is worth designing toward even if not implemented immediately.

## Empirical Findings

See [FINDINGS.md](FINDINGS.md) for full measurements. Key results:

- **93.9% of a 2.1GB Ubuntu image is never read during a full boot** — validates the demand-fetch model
- **84% of extents match exactly between 22.04 point releases** (by count); 35% by bytes — the large changed files are the delta compression target
- **~94% marginal S3 fetch saving** for a point-release update (exact dedup + delta compression combined)
- **~1.5MB manifest** for a 762MB filesystem (~33,700 extents at 44 bytes each)

## Write Log

The write log is the local durability boundary. Writes land here on fsync; the log is promoted to a segment in the background.

### File format

A single append-only file per in-progress segment, living at `wal/<ULID>`. One file, records appended sequentially, no separate index.

**Magic header:** `PLMPWL\x00\x01` (8 bytes)

**Record types:**

*DATA record* — a new extent with its payload:
```
hash        (32 bytes)    BLAKE3 extent hash
start_lba   (u64 varint)  first logical block address
lba_length  (u32 varint)  extent length in 4KB blocks
flags       (u8)          see flag bits below
data_length (u32 varint)  byte length of payload (compressed size if FLAG_COMPRESSED)
data        (data_length bytes)
```

*REF record* — a dedup reference; no data payload, maps an LBA range to an existing extent:
```
hash        (32 bytes)    BLAKE3 hash of the existing extent
start_lba   (u64 varint)
lba_length  (u32 varint)
flags       (u8)          FLAG_DEDUP_REF set; no further fields
```

**Flag bits:**
- `0x01` `FLAG_COMPRESSED` — payload is zstd-compressed; `data_length` is compressed size
- `0x02` `FLAG_DEDUP_REF` — REF record; no data payload

The hash is computed before the dedup check and stored in the log record. Recovery can reconstruct the LBA map without re-reading or re-hashing the data.

### Pre-log coalescing

Contiguous LBA writes are merged in memory before they reach the write log — in the NBD/ublk handler, not in the log itself. This mirrors lsvd's `pendingWrite` buffer. The coalescing window is bounded by both a block count limit (to prevent unbounded memory accumulation between fsyncs) and the fsync boundary (a guest fsync flushes any pending buffer). The write log only ever sees finalised, already-coalesced extents.

### Durability model

```
write arrives → in-memory coalescing buffer
                        │
               count limit or fsync
                        │
                        ▼
               hash → local dedup check → append_data / append_ref → bufio (OS buffer)
                        │
                    guest fsync
                        │
                        ▼
               logF.sync_data() ← write log durable on local disk; reply sent to guest
                        │
                [background, async]
                        │
                        ▼
               segment close → clean body written + .idx written → S3 upload
```

After a guest fsync returns, all prior writes are durable in the write log on local NVMe. S3 upload is asynchronous and not on the fsync critical path.

### Crash recovery

On startup, if a write log file exists, `scan()` reads it sequentially. If a partial record is found at the tail (power loss mid-write), the file is truncated to the last complete record. All complete records are replayed to reconstruct the in-memory LBA map. The write log is then reopened for continued appending.

**Failure scenarios:**

| Scenario | State on restart | Recovery |
|---|---|---|
| Crash mid-write (before fsync) | WAL tail partial | Truncate WAL to last complete record; replay |
| Crash after fsync, before promotion starts | `wal/<ULID>` intact; nothing in `pending/` | Replay WAL; promote normally |
| Crash during segment file write (steps 1–2) | `pending/<ULID>.tmp` may exist; WAL intact | Delete `.tmp`; replay WAL |
| Crash after rename, before WAL delete (steps 3–4) | Both `pending/<ULID>` and `wal/<ULID>` exist | Delete WAL; use pending segment |
| Crash after WAL delete, before LBA map update (steps 4–5) | `pending/<ULID>` present; no WAL | Rebuild LBA map from pending segment header + index |
| Crash mid-upload or after upload before rename (steps 6–8) | Segment still in `pending/`; may be in S3 already | Retry upload (idempotent); rename on success |
| Total local disk loss | All local state gone | Data loss bounded to writes not yet in S3 — same guarantee as a local SSD |

The final row is an intentional design choice: local NVMe is the durability boundary, matching the stated goal of "durability semantics similar to a local SSD". S3 is async offload, not the primary durability mechanism.

### Promotion to segment

When the write log reaches the 32MB threshold (or on an explicit flush), the background promotion task converts the WAL into a committed local segment. The WAL is assigned a ULID at creation time; that same ULID becomes the segment ID.

**Promotion writes a clean segment body.** The WAL format includes per-record headers that are useful for recovery but should not be part of the permanent segment format. Promotion reads the WAL sequentially and writes only the raw extent data bytes (no headers) to a clean body file. REF records contribute no bytes to the body — their `.idx` entries carry only the LBA mapping and `FLAG_DEDUP_REF`. The `.idx` records exact byte offsets into the clean body for DATA records. All segments — freshly promoted or GC-repacked — have the same uniform format: raw concatenated DATA extent bytes, navigated entirely via `.idx`.

**Directory layout within a live node:**

```
wal/<ULID>          — WAL file (active or awaiting promotion)
pending/<ULID>      — segment file committed locally, S3 upload pending
segments/<ULID>     — segment file confirmed uploaded to S3 (evictable)
```

Each directory corresponds to one stage in the lifecycle:

```
wal/<ULID>  →  pending/<ULID>  →  segments/<ULID>
```

Both `pending/` and `segments/` hold segment files in the same format (header + index + inline + body). The distinction is upload state, not file format. Locally-stored segment files have `delta_length = 0` in the header; the coordinator appends the delta body when computing deltas at S3 upload time, producing the final S3 object.

`wal/` normally contains one entry — the active WAL — but can contain two during the brief promotion window. On crash recovery all files in `wal/` are treated identically: scan, truncate partial tail, promote.

`pending/` segments are the only local copy of their data; they must not be evicted. `segments/` are S3-backed caches; freely evictable under space pressure. No list files are needed — the filesystem is the index.

**Commit ordering:**

```
1. Build index section in memory from WAL extent list
2. Write pending/<ULID>.tmp: header + index + inline + body (DATA extents only, no headers)
3. Rename pending/<ULID>.tmp → pending/<ULID>            ← COMMIT POINT
4. Delete wal/<ULID>
5. Update LBA map in memory
```

Step 3 is the commit point — a complete segment file at `pending/<ULID>` means promotion is done. The entire file is written atomically via rename; there is no window where a partial file is visible as the committed name.

**S3 upload completion:**

```
6. Read pending/<ULID>; compute delta body against ancestor segments (if applicable)
7. Upload to S3: stream header + index (updated with delta offsets) + inline + body + delta body
8. Rename pending/<ULID> → segments/<ULID>
```

The S3 object may differ from the local file in that it carries a delta body (and correspondingly updated header and index section). The body section is identical and can be streamed directly from the local file. Step 8 is a single rename.

**On startup:** scan all three directories within the live node. Each maps to one recovery action:
- `wal/` — replay (truncate partial tail if needed) and promote
- `pending/` — read header + index section for LBA map rebuild; queue S3 upload
- `segments/` — read header + index section for LBA map rebuild

Then scan ancestor nodes' `segments/` directories (no `wal/` or `pending/` — they are frozen), oldest ancestor first, to build the full merged LBA map.

---

## lsvd Reference Implementation Notes

The [lab47/lsvd](https://github.com/lab47/lsvd) Go implementation is the primary reference. Key design decisions we studied and how they influenced palimpsest:

### lsvd local directory layout

```
<volume-dir>/
├── head.map                          — persisted LBA→PBA map (CBOR-encoded,
│                                       SHA-256 of segment list as freshness guard)
├── writecache.<ULID>                 — active WAL (receiving writes)
├── writecache.<ULID>                 — old WAL(s) queued for promotion (up to 20)
├── segments/
│   ├── segment.<ULID>               — single-file segment:
│   │                                   [SegmentHeader 8B][varint index][data body]
│   └── segment.<ULID>.complete      — transient during Flush(); renamed to final
└── volumes/
    └── <volName>/
        └── segments                 — binary: appended 16-byte ULIDs, one per segment
```

WAL files live at the root alongside `head.map`. There is no upload-state distinction in the directory layout because S3 upload is synchronous within the background promotion goroutine — by the time a WAL is deleted, its segment is already in S3 and `volumes/<vol>/segments` has been updated. Everything in `segments/` is guaranteed to be in S3.

### Palimpsest local directory layout (comparison)

```
<live-node-dir>/
├── lba.map                          — optional persisted LBA map (rebuilt from segment headers if stale)
├── wal/
│   └── <ULID>                      — WAL file(s): active or awaiting promotion
├── pending/
│   └── <ULID>                      — segment file committed locally, S3 upload pending
└── segments/
    └── <ULID>                      — segment file confirmed uploaded to S3 (evictable)

<parent-node-dir>/                   — frozen; no wal/ or pending/
└── segments/
    └── <ULID>                      — segment file (read-only)
```

The `pending/` directory exists because palimpsest decouples local promotion from S3 upload. lsvd has no equivalent — it never has locally-committed segments that aren't yet in S3. The three-directory structure makes the full lifecycle visible via `ls`: `wal/` = in flight, `pending/` = local only, `segments/` = safely in S3.

| | lsvd | Palimpsest |
|---|---|---|
| WAL location | Root-level `writecache.<ULID>` | `wal/` subdir |
| Segment format | Single file (index embedded in body) | Single file (header + index + inline + body + delta) |
| Upload tracking | Not needed (S3 sync in promotion) | `pending/` vs `segments/` dirs |
| Temp files | `segment.<ULID>.complete` | `pending/<ULID>.tmp` |
| LBA map | `head.map` (CBOR, SHA-256 guard) | `lba.map` (optional; rebuilt from segment index sections) |
| Eviction policy | Not applicable | `segments/` evictable; `pending/` never |
| Snapshot model | `lowers` array (read-only lower disks) | Directory tree (ancestors are frozen nodes) |
| Dedup | Not implemented | Opportunistic on write path; local tree + best-effort cross-volume via shared root |

**Segment format:** lsvd uses a single file per segment: `[SegmentHeader (8 bytes)][ExtentHeaders (varint-encoded)][body data]` — all metadata embedded in the body. Palimpsest also uses a single file, but with a four-section layout (header + index + inline + body + delta) that allows the index section to be fetched independently via byte-range GET, avoiding retrieval of body data that isn't needed. The local file and S3 object use the same format; the S3 object may additionally carry a delta body computed at upload time.

**Snapshot / lower-disk model:** lsvd implements layering via a `lowers` parameter — an array of read-only disk handles that the read path falls through. Palimpsest encodes the same relationship in the directory tree: ancestor directories are the "lower disks", their absence of `wal/` enforces read-only semantics, and the ancestry is directly inspectable via `ls`.

**GC asymmetry:** in lsvd, `removeSegmentIfPossible()` prevents deleting a segment referenced by any volume, making lower-disk segments effectively immutable while any volume uses them. Palimpsest enforces this structurally: GC only targets nodes containing `wal/`; frozen nodes are never selected.

**Write log format:** single append-only file, one record per finalised extent. Palimpsest's write log follows this shape, adding the BLAKE3 hash and a `FLAG_DEDUP_REF` record type (absent in lsvd which is LBA-addressed, not content-addressed). Unlike lsvd, palimpsest writes a **clean segment body** at promotion time rather than renaming the WAL directly — the WAL format includes recovery headers that are not part of the segment format.

**Async promotion:** lsvd's `closeSegmentAsync()` sends to a background goroutine, but within that goroutine `Flush()` calls `UploadSegment()` synchronously — the LBA map is not updated until after S3 upload. Palimpsest decouples local promotion from S3 upload entirely: the WAL is committed as a local segment and the LBA map is updated without waiting for S3.

**Durability equivalence:** both have the same fundamental durability guarantee — local NVMe is the boundary, not S3. At any moment lsvd has one active WAL + up to 20 queued old WALs not yet in S3. Palimpsest has one active WAL + some number of promoted-but-not-yet-uploaded local segments. In both cases, total local disk failure loses data that the guest's fsync acknowledged.

**LBA map vs content-addressed:** lsvd's `lba2pba` maps `LBA → segment+offset` (physical). GC repacking must update it for every moved extent. Palimpsest's LBA map is `LBA → hash` (logical); physical location is tracked separately in the extent index. GC repacking updates only the extent index; the LBA map is unaffected.

**Pre-log coalescing:** lsvd's `nbdWrapper` buffers up to 20 contiguous blocks in a `pendingWrite` buffer. Palimpsest follows the same pattern; the count limit is a tuning parameter.

**Fsync handling:** `writeLog()` calls `bufio.Flush()` after each extent (OS buffer, not disk). The actual fsync happens only when the guest issues a flush. Palimpsest's `WriteLog::fsync()` follows this exactly.

**Compression:** lsvd uses LZ4 with an entropy threshold of 7.0 bits/byte and a minimum compression ratio of 1.5×. Palimpsest uses zstd (already a dependency) with the same 7.0-bit entropy threshold as a starting point.

---

## Implementation Notes

**S3 is intentionally deferred.** The system can be developed and validated end-to-end using local storage only — `pending/` and `segments/` act as local-only segment stores without any upload step. This covers the full write path, promotion pipeline, LBA map, crash recovery, and read path. S3 hookup comes later.

A clean progression for introducing S3:
1. **Local only** — `pending/` and `segments/` as local stores, no upload step
2. **Local S3-compatible service** (MinIO, LocalStack) — write the S3 client code against a local service; real upload/download paths exercised without cloud dependency
3. **Real S3** — swap in credentials, no code changes needed

Constraints to keep in mind so S3 integration stays straightforward:
- Segment IDs (ULIDs) are already globally unique and suitable as S3 object keys
- The `pending/` → `segments/` transition maps cleanly to "upload to S3, then rename locally"
- Persistent structures (manifests, segment files) reference segment IDs only — local paths are derived at runtime, never stored

---

## Open Questions

- **Hash output size:** BLAKE3 at full 256-bit is the current choice — collision probability is negligible (~2^-128 birthday bound) at any realistic extent count, and speed is equivalent to non-cryptographic hashes on AVX2/NEON hardware. A truncated 128-bit output would halve the per-entry cost in the extent index while keeping collision probability effectively zero at practical scales. Worth revisiting once the index size and memory pressure are measured empirically.
- **Inline extent threshold:** extents below this size are stored inline in `.idx` files rather than referenced by segment offset. Needs empirical validation against the actual extent size distribution in target images.
- **Entropy threshold:** 7.0 bits used in experiments, taken from the lab47/lsvd reference implementation. Optimal value depends on workload mix.
- **Segment size:** ~32MB soft threshold, taken from the lab47/lsvd reference implementation (`FlushThreshHold = 32MB`). Not a hard maximum — a segment closes when it exceeds the threshold. Optimal value depends on S3 request cost vs read amplification tradeoff.
- **Extent index implementation:** sled, rocksdb, or custom. Needs random reads and range scans.
- **Pre-log coalescing block limit:** lsvd uses 20 blocks. The right value for palimpsest depends on typical write burst sizes and acceptable memory footprint between fsyncs.
- **LBA map cache invalidation:** validate the cached `lba.map` against a hash of the current segment IDs across the full ancestor tree, not just the live node.
- **Delta segment threshold:** not every segment needs a delta companion — only useful when changed extents have known prior versions in the ancestor tree. Criteria for when to compute and upload a delta segment need empirical validation.
- **Boot hint persistence:** where are hint sets stored, how are they distributed across hosts?
- **Empirical validation of repacking benefit:** measure segment fetch count before and after access-pattern-driven repacking.
- **ublk integration:** Linux-only, io_uring-based. NBD kept for development and macOS.
