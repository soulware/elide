# Design: Local read cache for segment bodies (`.bmat`)

Status: **Proposed.**

Date: 2026-07-29

---

## Context

[compression-codecs.md](compression-codecs.md) moves segment bodies to zstd, because their byte count is what is uploaded to S3 and charged for. zstd decompresses roughly three to four times slower than lz4, and every guest read materialises the whole extent it lands in and verifies its content hash, so the codec that shrinks the uploaded object also sits on the guest's read path.

This document specifies a local-only sidecar, `cache/<ULID>.bmat`, holding lz4-re-encoded body plaintext after its first read. Reads serve from it with an lz4 decompress. The uploaded object stays zstd, and `cache/<ULID>.body` stays a byte-identical slice of it.

The two artefacts are then priced separately, which is the whole point of one codec per artefact. Upload bytes get zstd. Read CPU gets lz4.

## Goals

- Re-encode each entry at most once per host between evictions.
- Leave `cache/<ULID>.body` byte-identical to the uploaded segment, so demand-fetch range-GETs still land at the offsets the signed index carries.
- Bound local disk by a configured budget rather than by the size of the volume.
- Stay reconstructible from `.body` alone, so losing a `.bmat` costs CPU and nothing else.
- Keep the on-disk shape inspectable with `ls -l` and an `inspect` verb.

## Non-goals

- **Eager re-encoding at promote.** Bodies that are never read should not consume disk or CPU. Population is lazy, on first read.
- **Replacing `.body`.** `.body` is the canonical local copy and the demand-fetch target. `.bmat` is a read-side cache.
- **Serving anything to S3.** `.bmat` is local-only and never uploaded.

## Why a second file rather than extending `.dmat`

`.dmat` already holds lz4-compressed materialised plaintext keyed by `(segment, entry_idx)`, which is exactly the record `.bmat` needs. The format and its recovery discipline are reused verbatim.

They stay separate files because their rebuild costs differ by orders of magnitude. Rebuilding a `.dmat` record reads the source extent, reads the delta blob, and runs a zstd-dictionary decompress. Rebuilding a `.bmat` record reads the local `.body` and runs one zstd decompress. Under a shared budget the cheap-to-rebuild records would evict the expensive ones, so the two populations get their own files and their own retention.

## File format

Identical to `.dmat` (see [delta-materialisation.md](delta-materialisation.md)), with its own magic.

```
cache/<ULID>.bmat

Magic header (8 bytes):  "ELIBMAT\x01"

Then a sequence of self-contained records, appended:

Record:
  entry_idx      (u32 le)         index of the entry in the segment's index section
  flags          (u8)             bit 0: FLAG_COMPRESSED (lz4_flex)
  stored_length  (u32 le)         length of `data`
  data           (stored_length bytes)
```

`entry_idx` names a body-carrying entry of the segment. Open scans the file once and builds the in-memory `entry_idx → offset` map, truncating at the first record that fails to parse.

Authentication comes free from the read path. `read_extents` verifies the extent content hash on every serve, so bytes arriving from `.bmat` are checked against the signed index exactly as bytes arriving from `.body` are. The sidecar introduces no second trust root and needs no hash of its own.

## Population

A read that resolves to a `.body` entry decompresses it as it does today, and appends the lz4 re-encoding to `.bmat` before returning. The entry is served from the bytes already in hand, so the append is off the critical path of the read that triggered it.

An append that fails for any reason leaves the read successful. A short or torn record is removed by the open scan.

## Eviction

Eviction removes a whole `.bmat` file with `unlink`. Records are never rewritten or punched out.

This is what lets the append-only format keep its recovery argument. `.dmat` can truncate at the first bad record because the file only ever grows, so a bad record means a torn tail. Per-record eviction would put holes in the middle and that inference would stop holding. Whole-file eviction keeps every file append-only for its whole life, and reclaim is one `unlink` against a file whose contents are all rebuildable from the `.body` sitting next to it.

Selection is LRU over segments against a byte budget. The budget is a configured cap, so local footprint is a number an operator sets rather than a fraction of the volume.

The eviction unit matching the segment also matches how the rest of the cache is reclaimed, and it means a hot segment keeps all of its re-encoded entries together rather than a scattered subset.

## Footprint

Keeping a `.bmat` for every segment would take local storage from about 14.8% of plaintext to about 21%, since both copies are held and lz4 is roughly 2.4 times the size of zstd for the same content. The budget replaces that with a cap. What the cap buys is the hot set, and the tail of cold segments serves from `.body` at zstd speed.

## What has to be measured

lz4 is larger on disk than zstd, so a `.bmat` read moves more bytes to spend less CPU. That is a win while the bytes are in page cache and a loss when they are not.

The LRU population and the page-cache-resident population are selected by the same signal, recent access, so the sidecar should hold the segments whose bytes are already resident. That argument is structural rather than measured, and it is what a read-latency run has to confirm. The same run answers the open read-locality question in [compression-codecs.md](compression-codecs.md).

## Sequencing

The codec change lands first and `.bmat` follows. Three properties keep that order open, and each one is a decision the codec change could otherwise foreclose.

**`.body` stays byte-identical to the uploaded object.** [compression-codecs.md](compression-codecs.md) already rejects re-encoding `.body` locally, on the grounds that demand-fetch range-GETs land at signed-index offsets. That rejection is also what gives `.bmat` a canonical local source to rebuild from.

**Codec travels with the resolved location, not with the entry alone.** `SegmentEntry.compressed` becomes a codec tag naming the codec of the uploaded body. A read from `.bmat` gets lz4 regardless of that tag, so the read path has to take its codec from the location it resolved, with the entry's tag as the answer for `.body`. Written that way, `.bmat` is one more arm on an existing choice. Written as one decompress keyed off `entry.compressed`, adding it means reworking the read path.

**Chunk geometry is shared.** If chunked frames land (#807), a `.bmat` record covers the same plaintext boundaries as the `.body` chunk it came from, so a read decompresses one chunk from whichever source serves it. A `.bmat` holding whole-extent frames would reintroduce the whole-extent materialisation that chunking exists to remove.

## Rejected

**Per-record eviction.** It puts holes in an append-only file, which costs the truncate-at-first-bad-record recovery that makes the format cheap. Whole-file eviction keeps it, and the granularity is the same one the rest of the cache reclaims at.

**Sharing one file with `.dmat`.** A shared budget lets records that cost one local read to rebuild evict records that cost a source read plus a dictionary decompress.

**Eager re-encoding at promote.** It spends CPU and disk on bodies before anything has read them, on volumes that are mostly written once and never read back.
