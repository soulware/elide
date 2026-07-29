# Design: compression codecs

Status: Proposed, not started. § Measurement covers a bulk-load-dominated and a churned postgres corpus. Guest read latency, in § Open questions, is what still gates the codec change.

Date: 2026-07-25

## What compression buys

Compression earns its cost in three different currencies, and each artefact spends a different one.

Segment bodies are uploaded to S3. Their byte count is the upload bandwidth, the time-to-durable, and the stored footprint of every volume kept for DR. Most volumes are written locally, uploaded once, and never read back — the bytes are paid for on the way out and rarely on the way in.

The WAL is never uploaded. It absorbs guest writes and is consumed at formation. Its compression sits inside `Volume::write` (`actor.rs:1467`), before the WAL append, so it is on the guest's synchronous write path and its cost is write latency.

`cache/<ULID>.dmat` is a local-only read cache. Its compression is paid on write-back and its decompression on every subsequent cold delta read, so its cost is read latency.

Local reads are held to a standard rather than a budget: the aim is to serve them as close to raw-disk performance as the format allows. Decompression cost on the read path is therefore a constraint on the design, not one term to trade off against uploaded bytes, and it is what the local cache in § Open questions exists to serve.

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

The churned corpus prices the bar. Stored bytes there run 18.0% of plaintext against a per-entry lz4 recompute of 18.0%, so the ratio turns away too little to be the lever. What stays open is whether segment bodies and `.dmat` share one.

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

`elide corpus-sim` over two pgbench corpora, both codecs recomputed from plaintext. The bulk corpus is 34 segments, 1,677 entries, 993.3 MiB of plaintext at a mean entry of 592 KiB. The churned corpus is a fresh volume driven through eight 300-second rounds, 65,012 entries, 753.7 MiB at a mean entry of 11.9 KiB.

| | bulk | of plain | churn | of plain |
|---|---|---|---|---|
| lz4 | 147.2 MiB | 14.8% | 135.7 MiB | 18.0% |
| zstd-3 | 61.5 MiB | 6.2% | 74.0 MiB | 9.8% |

zstd-3 is 58.2% smaller on the bulk corpus and 45.5% smaller on the churned one, and produced the smaller output on every entry of both, 1,677 and 65,012. Over the churned corpus's newest twenty segments alone it is 42.0% smaller.

lz4 does win below roughly 1 KiB, by one to four bytes, on every content pattern — its four-byte size prefix against zstd's frame header. The crossover is a framing constant, not a content property, and it sits below the 256-byte threshold at which extents become `Inline`.

## Rejected

**Re-encoding `cache/<ULID>.body` itself to a codec the uploaded object does not use.** The `.body` file is a byte-identical slice of the uploaded segment, which is what lets demand-fetch range-GET straight into it at the offsets the signed index already carries. A second codec gives different sizes, so the index would have to carry a second offset table. A local sidecar that leaves `.body` alone is a different shape and stays open (§ Open questions).

**A precomputed entropy gate.** `volume/compress.rs` already records the reasoning: running the codec decides faster than estimating first. Today's measurement removes the remaining motive, since codec choice does not depend on content — lz4 never produces smaller output above the framing crossover, so there is nothing for an entropy signal to select between.

**Raising the level to 19.** 11% for twenty times the CPU, on hosts that are already CPU- and memory-constrained.

**Chunk-granular dedup.** Measured over three Ubuntu cloud-image pairs, reproducing import's extent rule of one extent per ext4 file fragment plus one 4 KiB extent per non-zero non-file block. Against a zstd-3 128 KiB chunked baseline, chunk dedup saves 5.0%, 9.7% and 0.3% of the bytes that survive whole-extent dedup, where delta against the parent's same-path fragment saves 13.9%, 24.7% and 7.5% of the same bytes and leaves chunk dedup 2.8, 6.6 and 0.1 points to add on top. The matches concentrate in same-path-same-offset chunks, 61.7 of 64.3 MiB in the widest pair, which is the population delta already converts; same-path-other-offset runs to 0.1 MiB in every pair, so a fixed chunk size matches only while content stays put. Chunk dedup also moves the referenced unit, making `ReferencedHashes`, GC liveness and delta-source liveness chunk-level and letting one entry be partially live, and it splits the stored payload, so `stored_offset`/`stored_length` describe one run per chunk, demand-fetch issues one range-GET per chunk, and the presence bitset needs sub-entry granularity.

**A per-fd verified bitset as a stopgap.** Verify an extent once per open segment fd, then serve raw sub-ranges with plain preads — sound on immutable files, since inode-replacement events already clear the fd cache. It removes only the repeat hashing on raw extents; the decompression on compressed extents, the dominant shape, stays, and chunked frames remove both.

## Format

`SegmentEntry.compressed` becomes a codec tag rather than a boolean, and `maybe_compress` becomes per-artefact rather than one shared function. `WalFlags::COMPRESSED` keeps its meaning, since the WAL keeps lz4. Existing volumes are not readable across this change.

## Open questions

A trained dictionary pays on the churned corpus, on the shape the per-size table predicts. Its 8 KiB entries, 26,117 of them and the population that carries the corpus, gain 32.8%; 16 KiB gains 17.7% and 32 to 64 KiB around 10%. The held-out aggregate runs 29.6 MiB down to 22.4 MiB, 24% under dictionaryless zstd, with 0.1 points of drift against a dictionary trained on the test set. What stays open is which distribution real volumes settle into, since the bulk corpus above wants no dictionary at all.

Guest read latency under zstd is unmeasured, and under the aim above it gates the change rather than costing against it. Decompression is roughly three to four times slower than lz4. What decides whether that is visible is extent-level read locality under the guest, which nothing measures today.

Two ways to hold reads near raw-disk speed, cheapest first.

`BlockReader.materialised` caches one extent, so a guest alternating between two hot extents re-materialises both on every read. A bounded LRU keyed by content hash with a byte budget — the shape `delta_compute::SourceCache` already uses — costs no format change, no disk and no recovery story, and targets that thrash directly.

Beyond that, a local lz4 sidecar per segment, built from the zstd `.body` on first read, in the shape `.dmat` already has. It leaves `.body` byte-identical to the object, so demand-fetch is untouched. Three things it has to answer that `.dmat` does not. `.dmat` is append-only with no eviction, which is affordable only because delta entries are a fraction of a percent of a volume; across all entries the sidecar is a second complete copy and needs reclamation, and eviction is what makes its truncate-at-first-bad-record recovery argument stop holding. Local footprint rises to about 21% of plaintext against 14.8% today, since both copies are kept. And lz4 is roughly 2.4 times the size of zstd for the same content, so the sidecar reads more bytes to spend less CPU — a win while those bytes are in page cache and a loss when they are not.

Whole-extent materialisation pulls against the same aim from the other side. An extent is one guest write — there is no coalescing, and `src/ublk.rs`'s `IO_BUF_BYTES` caps a single request at 1 MiB — or one imported file fragment, which no request cap bounds. The extent is the unit of compression and of the content hash alike, and the read path verifies content on every serve (#800), raw extents included, so a 4 KiB read reads, decompresses and hashes up to the whole extent.

The lever is compression granularity rather than hash granularity. Per-chunk hashes on their own remove the hashing pass and leave the rest, because a frame covering the whole extent is not randomly decodable: block 5 is unreachable without decompressing 0 through 4. Compressing in independently decodable chunks of fixed plaintext length bounds both, paying for it in a per-chunk table (compressed length and hash, offsets being a prefix sum) and in the cross-chunk matches the compressor no longer sees. The extent content hash is untouched — it covers plaintext and says nothing about layout — so dedup, the LBA map, sketches and delta source resolution all stand as they are.

Chunk size is the knob. At 4 KiB the hashes alone run to ~7.8 MiB against the corpus's 61.5 MiB of body, 13% on the bytes this whole change exists to reduce; at 64 KiB they run to ~0.5 MiB, 0.8%, for a sixteenfold cut in decompression per read. The table belongs in the body section rather than the index, since `.idx` is fetched eagerly for every ancestor at open and a volume that never reads a body should not carry its hashes.

The chunk table sits outside the signed region, so its hashes need an anchor. Either the signed `.idx` entry carries one hash of the table — 32 bytes per entry, against the eager-fetch concern above — or chunk boundaries align to BLAKE3's own tree so the chunk hashes are subtree values, verifiable against the extent content hash itself (the construction bao encodes). The table anchor is the simpler build; the subtree alignment adds no index bytes and no second trust root, and constrains the chunk size to a power-of-two number of BLAKE3's 1 KiB leaves. Subtree alignment also leaves per-chunk chaining values in hand, which are an exact resemblance signal for delta source selection where `sketch.rs` samples.

The lost cross-chunk matches are bounded by codec reach. lz4 matches within a 64 KiB window, so chunks at or above that size cost it nothing, and the dictionary table above shows zstd gaining little from history beyond ~128 KiB, because inputs that size supply their own. At 128 KiB the chunk table falls to ~0.4% of body bytes and a 4 KiB read decompresses at most 128 KiB.

Chunked frames are a second body-format break beside the codec tag (§ Format). Existing volumes are already unreadable across the codec change, so both belong in one format revision — one break, not two.

`IO_BUF_BYTES` reaches the same variable with no format change, since it is what bounds an extent. Lowering it shrinks extents directly, at the cost of more I/Os per large sequential write and more entries in the eagerly-fetched `.idx`. It is the cheap way to find out whether read amplification is worth a format change before making one, and it reaches guest-write extents alone. Import fragments take their size from the ext4 extent tree instead. Over three Ubuntu cloud-image pairs the fragments above 128 KiB are a small minority by count after whole-extent dedup (199 of 2600, 453 of 7574, 1331 of 39793) and hold 66 to 84% of the bytes, so on boot-image volumes most bytes sit in extents large enough for chunking to bound a read.

Which volumes chunking reaches follows the same distribution. The bulk corpus puts 98.5% of its bytes in extents above 128 KiB, and the churned one puts 89.3% at or under it, 99.5% over its newest twenty segments. So chunking bounds reads on imported and bulk-loaded volumes, and a volume that has churned into small extents is already below the chunk size.

Delta compression and a stronger body codec are substitutes at the margin. The first keep bar is "beat the stored body", which becomes a smaller number under zstd. Against zstd-3 in 128 KiB chunked frames the bar still clears on import corpora, keeping 423 of 429, 1646 of 1652 and 2469 of 2481 eligible conversions across three Ubuntu cloud-image pairs and saving 13.9%, 24.7% and 7.5% of the stored bytes that survive whole-extent dedup. On the churned corpus delta is weak from the other direction: 133 chains, and a delta against a fixed anchor lands at 79.2% of dictionaryless zstd one version out, decaying to 93.5% by four, with anchor retention costing 0.8 MiB more than it saves.
