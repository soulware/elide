# Design: compression codecs

Status: Proposed, not started. Measurements in § Measurement come from one bulk-load-dominated postgres corpus; § Open questions lists what a churned corpus has to confirm before the codec change is taken.

Date: 2026-07-25

## What compression buys

Compression earns its cost in three different currencies, and each artefact spends a different one.

Segment bodies are uploaded to S3. Their byte count is the upload bandwidth, the time-to-durable, and the stored footprint of every volume kept for DR. Most volumes are written locally, uploaded once, and never read back — the bytes are paid for on the way out and rarely on the way in.

The WAL is never uploaded. It absorbs guest writes and is consumed at formation. Its compression sits inside `Volume::write` (`actor.rs:1467`), before the WAL append, so it is on the guest's synchronous write path and its cost is write latency.

`cache/<ULID>.dmat` is a local-only read cache. Its compression is paid on write-back and its decompression on every subsequent cold delta read, so its cost is read latency.

## Where compression happens today

There is one compression, and it is on the write path. `Volume::write` calls `maybe_compress` before handing bytes to the WAL. Formation then carries the result through unchanged: `volume/wal.rs:72-79` translates `WalFlags::COMPRESSED` into `SegmentFlags::COMPRESSED` and reuses the same buffer and length.

So the codec that decides how many bytes reach S3 is selected on the guest ack path, by a function chosen for write latency. lz4 is the right answer to the question that call site asks. It is not the question the uploaded artefact asks.

## Proposed: one codec per artefact

Formation is the seam. It is asynchronous, off the ack path, and already visits every entry.

**WAL — lz4.** On the ack path, where the codec's cost is guest write latency and its benefit is a smaller WAL file that is deleted at formation.

**Segment body — zstd.** Every `Data` and `CanonicalData` entry, re-encoded at formation: lz4-decompress the WAL body, zstd-compress the plaintext, store that. This is the artefact whose bytes are uploaded, and the only one whose size is charged to S3. The delta body section alongside it already holds zstd blobs, produced against a source extent as dictionary, so this extends a codec the segment format already carries rather than introducing one.

**Inline section — lz4.** An `Inline` entry holds under 256 stored bytes, and below roughly 1 KiB zstd's frame header costs more than its coding saves — one to four bytes, on every content pattern measured. The crossover is framing overhead, so it sits at a fixed size rather than moving with content.

**`.dmat` — lz4.** A local read cache whose whole purpose is to be faster to read than re-materialising a delta.

Level 3. Level 19 measured 11% smaller on a 64 KiB entry (1,640 bytes against 1,835) for roughly twenty times the compression CPU. zstd decompression speed is close to independent of compression level, so the level can be raised later against formation CPU headroom without touching the read path.

Formation gains an lz4-decompress plus a zstd-compress per entry, asynchronous, roughly eight seconds of CPU per GiB of plaintext at level 3.

Codec contexts are pooled per formation worker and per queue thread. At body scope every entry compresses once and every cold extent read decompresses, so a context constructed per call runs at the rate of the whole workload rather than the 0.2% of entries that carry deltas. Per-call construction is the allocation shape that ratcheted RSS into the OOMs behind `malloc_policy.rs`, which makes pooling a constraint on the design rather than a tuning step. `delta_compute::apply_delta` builds a decompression context per call today and is the pattern not to extend.

## The ratio threshold

`maybe_compress` (`volume/compress.rs:18`) compresses, then keeps the result only if it is at least 1.5× smaller. Data compressing 1.4× is stored raw, giving up 29%.

The threshold prices decompression CPU on read. Under the asymmetry above that is the wrong quantity for segment bodies, whose cost is upload bytes and whose reads mostly never happen. It remains the right quantity for `.dmat`.

It is also a weaker safety net under zstd than under lz4. On incompressible input lz4 expands by about 0.4% (65,536 bytes of random data becomes 65,798) while zstd emits a raw block and adds a flat ~13 bytes (65,546). The expansion the threshold guards against is an lz4 property.

Two knobs to settle with the churned-corpus rerun: the ratio itself, and whether segment bodies and `.dmat` share one.

## zstd and dictionaries

zstd with no dictionary compresses against an empty window. There is no built-in content dictionary; the window fills with the input's own earlier bytes as the frame proceeds. The format does define default FSE distributions for literal lengths, match lengths and offset codes, used when a block selects predefined mode rather than transmitting its own table, and blocks may reuse a previous block's Huffman and FSE tables within a frame. That prior is entropy tables, not content.

Dictionary benefit therefore scales inversely with input size: a dictionary substitutes for history and for table budget, and a large frame supplies both itself. Measured against dictionaryless zstd on the held-out segments, per power-of-two entry size:

| entry size | entries | gain |
|---|---|---|
| 4 KiB | 30 | 22.5% |
| 8 KiB | 53 | 17.4% |
| 16 KiB | 9 | 15.0% |
| 128 KiB | 17 | 7.9% |
| 256 KiB | 45 | 3.6% |
| 512 KiB | 23 | 2.0% |
| 1 MiB | 370 | 0.0% |

The aggregate over the same set is 0.3%, because 370 entries near a megabyte carry 378 MB of the 382.6 MB and set the total on their own. So the dictionary works, on the inputs small enough to need it, and this volume holds almost none of them. Drift against a dictionary trained on the test set is 0.0 to 0.2 points, so what limits it is input size rather than staleness.

The economics follow the same shape. The gain totals ~109 KiB across 382.6 MiB of plaintext, and most rows are served best by a 1 MiB dictionary — which has to be stored. A dictionary sized to what these rows want costs more than it saves; a 112 KiB one breaks even at roughly this much data and is worth ~0.03% of plaintext after. Whether a trained dictionary pays is therefore a property of a volume's entry-size distribution, not of the workload's content.

## Measurement

`elide corpus-sim` over 34 segments of a pgbench volume, 1,677 entries, 993.3 MiB of plaintext, both codecs recomputed from plaintext:

| | bytes | of plain |
|---|---|---|
| lz4 | 147.2 MiB | 14.8% |
| zstd-3 | 61.5 MiB | 6.2% |

zstd-3 is 85.7 MiB smaller, 58.2% fewer bytes uploaded for the same data. lz4 produced the smaller output on 0 of 1,677 entries.

lz4 does win below roughly 1 KiB, by one to four bytes, on every content pattern — its four-byte size prefix against zstd's frame header. The crossover is a framing constant, not a content property, and it sits below the 256-byte threshold at which extents become `Inline`.

## Rejected

**Separate codecs for the local cache and the uploaded object.** `cache/<ULID>.body` is a byte-identical slice of the uploaded segment, which is what lets demand-fetch range-GET directly into it. Different codecs give different sizes, so the segment index would have to carry two offset tables. That is a permanent format cost for a read-latency win that has not been shown to be needed.

**A precomputed entropy gate.** `volume/compress.rs` already records the reasoning: running the codec decides faster than estimating first. Today's measurement removes the remaining motive, since codec choice does not depend on content — lz4 never produces smaller output above the framing crossover, so there is nothing for an entropy signal to select between.

**Raising the level to 19.** 11% for twenty times the CPU, on hosts that are already CPU- and memory-constrained.

## Format

`SegmentEntry.compressed` becomes a codec tag rather than a boolean, and `maybe_compress` becomes per-artefact rather than one shared function. `WalFlags::COMPRESSED` keeps its meaning, since the WAL keeps lz4. Existing volumes are not readable across this change.

## Open questions

The measured corpus is dominated by an initial bulk load. A churned corpus — many small overwrites, a large canonical-only population from GC output — gave a very different picture on the same workload, with stored bytes within 1% of plaintext because almost every entry failed the 1.5× bar. The codec gap, the funnel, and the threshold all need re-measuring there before the change is taken.

A trained dictionary reopens on that corpus too. Its mean entry ran to 8.8 KiB against 592 KiB here, and 8 KiB is the size at which the dictionary earns 17.4%. A volume that churns into small extents is the shape the per-size table says a dictionary is for, so the question is which distribution real volumes settle into rather than whether dictionaries work.

Guest read latency under zstd is unmeasured. Decompression is roughly three to four times slower than lz4 and is absorbed by the materialised-extent cache across an extent, but the cost per cold extent read has not been measured on the ublk path.

Delta compression and a stronger body codec are substitutes at the margin. The first keep bar is "beat the stored body", which becomes a smaller number under zstd, so conversions drop. Delta's measured value needs re-baselining against zstd bodies rather than lz4 ones.
