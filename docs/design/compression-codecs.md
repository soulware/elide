# Design: compression codecs

Status: Built, including the chunked granularity in § Open questions. § Measurement covers a bulk-load-dominated and a churned postgres corpus. The read-side answers in § Open questions follow this change rather than gating it, and § Format carries what it preserves for them to stay available.

Date: 2026-07-25

## What compression buys

Compression earns its cost in three different currencies, and each artefact spends a different one.

Segment bodies are uploaded to S3. Their byte count is the upload bandwidth, the time-to-durable, and the stored footprint of every volume kept for DR. Most volumes are written locally, uploaded once, and never read back — the bytes are paid for on the way out and rarely on the way in.

The WAL is never uploaded. It absorbs guest writes and is consumed at formation. Its compression sits inside `Volume::write` (`actor.rs:1467`), before the WAL append, so it is on the guest's synchronous write path and its cost is write latency.

`cache/<ULID>.dmat` is a local-only read cache. Its compression is paid on write-back and its decompression on every subsequent cold delta read, so its cost is read latency.

## Where compression happens today

There is one compression, and it is on the write path. `Volume::write` calls `maybe_compress` before handing bytes to the WAL. Formation then carries the result through unchanged: `volume/wal.rs:72-79` translates `WalFlags::COMPRESSED` into `SegmentFlags::COMPRESSED` and reuses the same buffer and length.

So the codec that decides how many bytes reach S3 is selected on the guest ack path, by a function chosen for write latency. lz4 is the right answer to the question that call site asks. It is not the question the uploaded artefact asks.

## One codec per artefact

Formation is the seam. It is asynchronous, off the ack path, and already visits every entry.

**WAL — lz4.** On the ack path, where the codec's cost is guest write latency and its benefit is a smaller WAL file that is deleted at formation.

**Segment body — zstd.** Every `Data` and `CanonicalData` entry, re-encoded at formation: lz4-decompress the WAL body, zstd-compress the plaintext, store that. This is the artefact whose bytes are uploaded, and the only one whose size is charged to S3. The delta body section alongside it already holds zstd blobs, produced against a source extent as dictionary, so this extends a codec the segment format already carries rather than introducing one.

**Inline section — lz4.** Inline bytes ride in the `.idx`, which every host fetches eagerly and decodes from memory, so the cost is the same one the ratio threshold prices. `compress_body` takes lz4 when the stored form lands under `INLINE_THRESHOLD` under both codecs, and only entries that small pay for the second encode.

**Journal tier — lz4.** Journal bytes reap whole with their segment and are never a dedup or delta source, so a better ratio buys little on content that does not outlive its segment, and lz4 keeps formation CPU off a tier that is a large share of segments on a churning volume. The codec byte is per entry, so one segment carries journal entries in lz4 beside durable ones in zstd.

**`.dmat` — lz4.** A local read cache whose whole purpose is to be faster to read than re-materialising a delta.

**Bodies take level 3.** Measured over three corpora, stored bytes as a share of plaintext:

| corpus | lz4 | zstd-3 | zstd-9 | 9 under 3 |
|---|---|---|---|---|
| pg5, churn, 1 MiB extents | 14.8% | 6.2% | 5.3% | 14.3% |
| pg6, churn, 8 KiB extents | 18.0% | 9.8% | 9.3% | 5.7% |
| Ubuntu cloud image, import | 41.6% | 29.3% | 27.6% | 6.1% |

Level 9 buys 6 to 14% for roughly 3.4 times the compression CPU, on every entry formation touches. The delta tier takes 9 on the same trade because it buys 34 to 36% there, over the fraction of a percent of entries that carry a delta. A residual against a dictionary holds redundancy a longer search finds; a whole extent, often 8 KiB of one, does not. The asymmetry that makes a level cheap — compress once, off the ack path, decompress faster as it rises — applies to both, and is not what separates them.

The step from lz4 is where the ratio is: 30 to 58% fewer stored bytes, which is the change this document exists for.

**Delta blobs take level 9.** Measured over two Ubuntu cloud-image pairs, 429 and 1,652 fragments, deltas against the same-path parent fragment:

| level | pair A stored | pair B stored | compress | decompress |
|---|---|---|---|---|
| 3 | 26.1% of plain | 20.0% | 300 to 371 MB/s | 1150 to 1846 MB/s |
| 9 | 16.6% | 13.2% | 90 to 106 MB/s | 1583 to 1932 MB/s |
| 19 | 9.1% | 8.3% | 3.7 MB/s | 1869 to 2200 MB/s |

Level 9 is 34 to 36% smaller than level 3 for about 3.4 times the compression CPU. Level 19 is smaller again, at 80 to 100 times level 3, and 3.7 MB/s puts a GiB of delta targets at several minutes of CPU on hosts already short of it.

The tier's own source selection reaches those ratios and beats them. Probing the resemblance index with each target's sketch returns a candidate for 653 of 821 and 2,297 of 2,551 sketchable residual fragments, and the deltas against those candidates run 15.2% and 11.8% of plaintext at level 9, over a population a fifth larger than the same-path pairing gives. About 62% of the picks are the same-path fragment, so the rest are sources same-path pairing reaches for nothing.

Decompression rises with the level rather than holding flat, because a denser blob carries fewer literals and longer matches, so the decoder does less work per output byte. A level is therefore bought with compression CPU alone. Dictionary loading is not part of that price on the read path either: timing `apply_delta`'s whole load-plus-decompress against decompress alone leaves the two within noise of each other, since a decompression dictionary needs little preprocessing.

The level is a write-time choice with no read-time dependency. A zstd frame declares its window, its content size and optionally a dictionary id, never the level that produced it, so a segment written at any level decodes under any configuration. Changing the level needs no tag, no migration and no compatibility path, which is what separates it from the codec choice in § Format.

Formation gains an lz4-decompress plus a zstd-compress per entry, asynchronous. Formation compresses every entry where the delta tier reaches a fraction of a percent of them, so the level's throughput cost lands on the whole write volume rather than a slice of it.

Codec contexts are pooled for the allocation rather than the CPU, which the timing above prices at nothing on the read path. Pooling is per formation worker and per queue thread. At body scope every entry compresses once and every cold extent read decompresses, so a context constructed per call runs at the rate of the whole workload rather than the 0.2% of entries that carry deltas. Per-call construction is the allocation shape that ratcheted RSS into the OOMs behind `malloc_policy.rs`, which makes pooling a constraint on the design rather than a tuning step. `delta_compute::apply_delta` builds a decompression context per call today and is the pattern not to extend.

## The ratio threshold

`maybe_compress` (`volume/compress.rs:18`) compresses, then keeps the result only if it is at least 1.5× smaller. Data compressing 1.4× is stored raw, giving up 29%.

The threshold prices decompression CPU on read. Under the asymmetry above that is the wrong quantity for segment bodies, whose cost is upload bytes and whose reads mostly never happen, so `compress_body` keeps the compressed form whenever it is smaller than the plaintext. The threshold remains the right quantity for the WAL, the inline section and `.dmat`, which `maybe_compress` still serves.

It is also a weaker safety net under zstd than under lz4. On incompressible input lz4 expands by about 0.4% (65,536 bytes of random data becomes 65,798) while zstd emits a raw block and adds a flat ~13 bytes (65,546). The expansion the threshold guards against is an lz4 property.

The churned corpus prices the bar. Stored bytes there run 18.0% of plaintext against a per-entry lz4 recompute of 18.0%, so the ratio turns away too little to be the lever.

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

**A chunk table anchored by one hash of itself in the signed `.idx` entry.** It is the simpler build, and it accepts any chunk size rather than a power-of-two multiple of BLAKE3's 1 KiB chunk. It costs 32 bytes per entry on the file fetched eagerly for every ancestor at open, and it makes the table a second thing to trust where subtree alignment leaves the extent content hash as the only one.

**A per-fd verified bitset as a stopgap.** Verify an extent once per open segment fd, then serve raw sub-ranges with plain preads — sound on immutable files, since inode-replacement events already clear the fd cache. It removes only the repeat hashing on raw extents; the decompression on compressed extents, the dominant shape, stays, and chunked frames remove both.

## Format

`SegmentEntry.compressed` becomes a codec tag rather than a boolean, and `maybe_compress` becomes per-artefact rather than one shared function. `WalFlags::COMPRESSED` keeps its meaning, since the WAL keeps lz4. Existing volumes are not readable across this change.

The tag names the codec of the uploaded body, and the read path takes its codec from the location it resolved rather than from the tag alone. Written that way a second local source in a different codec is one more arm on a choice the read path already makes. Written as one decompress keyed off `entry.compressed`, adding one means reworking the path. The local read cache in [body-materialisation.md](body-materialisation.md) is that second source, and it holds lz4 whatever the tag says.

## Open questions

Whether the levels are configurable is open, and the answer costs nothing on-disk because a level leaves no trace a reader consults. Three parts to it. Where the setting lives, with `volume.toml` the existing shape for per-volume config and formation CPU headroom a property of the host and the workload rather than of the format. Whether the level a segment was produced at is recorded, which correctness never needs and only diagnostics would read, so it would be a field written for people. And whether bodies and delta blobs share one setting or take two, since a body compresses once per entry and a delta only on the fraction of entries that convert, which is the same asymmetry that gives them different levels here.

A trained dictionary pays on the churned corpus, on the shape the per-size table predicts. Its 8 KiB entries, 26,117 of them and the population that carries the corpus, gain 32.8%; 16 KiB gains 17.7% and 32 to 64 KiB around 10%. The held-out aggregate runs 29.6 MiB down to 22.4 MiB, 24% under dictionaryless zstd, with 0.1 points of drift against a dictionary trained on the test set. What stays open is which distribution real volumes settle into, since the bulk corpus above wants no dictionary at all.

Guest read latency under zstd is unmeasured. Decompression is roughly three to four times slower than lz4, and what decides whether that is visible is extent-level read locality under the guest, which nothing measures today. The codec change is taken on its own and the read-side answers follow it, so the measurement runs against zstd bodies in place rather than ahead of them.

Two ways to hold reads near raw-disk speed, cheapest first.

`BlockReader.materialised` caches one extent, so a guest alternating between two hot extents re-materialises both on every read. A bounded LRU keyed by content hash with a byte budget — the shape `delta_compute::SourceCache` already uses — costs no format change, no disk and no recovery story, and targets that thrash directly.

Beyond that, a local lz4 sidecar per segment, built from the zstd `.body` on first read, in the shape `.dmat` already has. It leaves `.body` byte-identical to the object, so demand-fetch is untouched. Specified in [body-materialisation.md](body-materialisation.md), which takes it after this change rather than with it, and lists the three properties this change has to keep so that order stays open.

Whole-extent materialisation pulls against the same aim from the other side. An extent is one guest write — there is no coalescing, and `src/ublk.rs`'s `IO_BUF_BYTES` caps a single request at 1 MiB — or one imported file fragment, which no request cap bounds. The extent is the unit of compression and of the content hash alike, and the read path verifies content on every serve (#800), raw extents included, so a 4 KiB read reads, decompresses and hashes up to the whole extent.

The lever is compression granularity rather than hash granularity. Per-chunk hashes on their own remove the hashing pass and leave the rest, because a frame covering the whole extent is not randomly decodable: block 5 is unreachable without decompressing 0 through 4. Compressing in independently decodable chunks of fixed plaintext length bounds both, paying for it in a per-chunk table (compressed length and chaining value, offsets being a prefix sum) and in the cross-chunk matches the compressor no longer sees. The extent content hash is untouched — it covers plaintext and says nothing about layout — so dedup, the LBA map, sketches and delta source resolution all stand as they are. What moves to the chunk is verification on read, which #800 put on every serve against the whole extent.

Chunk size is the knob. At 4 KiB the hashes alone run to ~7.8 MiB against the corpus's 61.5 MiB of body, 13% on the bytes this whole change exists to reduce; at 64 KiB they run to ~0.5 MiB, 0.8%, for a sixteenfold cut in decompression per read. The table belongs in the body section rather than the index, since `.idx` is fetched eagerly for every ancestor at open and a volume that never reads a body should not carry its hashes.

The chunk table sits outside the signed region, so it needs an anchor. Chunk boundaries align to BLAKE3's own tree, which makes each chunk's table entry a subtree chaining value and the extent content hash their root. This is the construction bao encodes.

Reading the table verifies it. Compose the chaining values upward and compare the root against the entry's content hash, once, and every value in the table is then authenticated by the signature already covering that hash. There is one trust root, the `.idx` entry that dedup and the LBA map already rely on, and the index grows by nothing. A chunk read afterwards verifies against its own chaining value.

Two things this asks of the layout. Chunk size is a power-of-two multiple of BLAKE3's 1 KiB chunk, starting at an aligned plaintext offset, which 128 KiB satisfies at 128 leaves. And the rightmost subtree is short, so composing the tree follows `left_subtree_len` recursion rather than a balanced fold over the table. `blake3` 1.8.3 exposes what this needs in its `hazmat` module, ungated: `merge_subtrees_non_root`, `merge_subtrees_root`, `left_subtree_len`, and `HasherExt::set_input_offset`.

The chaining values also serve delta source selection, where a shared value between two extents is an exact resemblance signal against the sampling `sketch.rs` does.

An extent over one chunk is chunked whether or not the frames shrink it. On content no codec shrinks, the chunked form runs about 0.04% over the plaintext — one frame header and one table entry per chunk — and that buys a read that decodes and hashes one chunk where a raw extent makes it decode and hash all of them. Never producing a large raw extent is what keeps the read bound a property of the format rather than of the content, and it is the shape #800 made expensive on import fragments, which `IO_BUF_BYTES` does not bound.

The lost cross-chunk matches are what chunking costs, and they run larger than codec reach suggests. Measured at the body level over the entries above 64 KiB in each corpus, against storing the same extent as one frame:

| chunk | pg5 | pg6 | import |
|---|---|---|---|
| 64 KiB | +9.77% | +6.67% | +7.84% |
| 128 KiB | +6.53% | +4.83% | +6.00% |
| 256 KiB | +1.95% | +1.25% | +2.65% |
| 512 KiB | +1.00% | +1.66% | +2.04% |

zstd keeps finding matches past 128 KiB, so the ~128 KiB plateau in the dictionary table above is about what a *trained* dictionary adds and not about a frame's own history.

**Chunks are 256 KiB,** where the curve flattens: it costs 1.3 to 2.7% of the stored bytes of the extents it chunks, a third of what 128 KiB costs, and 512 KiB buys little more and is worse on one corpus. On the import corpus, where 72% of plaintext sits in chunked extents, 256 KiB is 0.58% of everything stored. It bounds a 4 KiB read at 256 KiB of decode and hash against a corpus holding a 62.2 MiB extent.

Chunked frames are a second body-format break beside the codec tag (§ Format). Existing volumes are already unreadable across the codec change, so both belong in one format revision — one break, not two.

`IO_BUF_BYTES` reaches the same variable with no format change, since it is what bounds an extent. Lowering it shrinks extents directly, at the cost of more I/Os per large sequential write and more entries in the eagerly-fetched `.idx`. It is the cheap way to find out whether read amplification is worth a format change before making one, and it reaches guest-write extents alone. Import fragments take their size from the ext4 extent tree instead. Over three Ubuntu cloud-image pairs the fragments above 128 KiB are a small minority by count after whole-extent dedup (199 of 2600, 453 of 7574, 1331 of 39793) and hold 66 to 84% of the bytes, so on boot-image volumes most bytes sit in extents large enough for chunking to bound a read.

Which volumes chunking reaches follows the same distribution. The bulk corpus puts 98.5% of its bytes in extents above 128 KiB, and the churned one puts 89.3% at or under it, 99.5% over its newest twenty segments. So chunking bounds reads on imported and bulk-loaded volumes, and a volume that has churned into small extents is already below the chunk size.

Delta compression and a stronger body codec are substitutes at the margin. The first keep bar is "beat the stored body", which becomes a smaller number under zstd. Against zstd-3 in 128 KiB chunked frames the bar still clears on import corpora, keeping 423 of 429, 1646 of 1652 and 2469 of 2481 eligible conversions across three Ubuntu cloud-image pairs and saving 13.9%, 24.7% and 7.5% of the stored bytes that survive whole-extent dedup. On the churned corpus delta is weak from the other direction: 133 chains, and a delta against a fixed anchor lands at 79.2% of dictionaryless zstd one version out, decaying to 93.5% by four, with anchor retention costing 0.8 MiB more than it saves.
