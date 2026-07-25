# Empirical Findings

Measured using `elide` — a Rust tool purpose-built to explore these concepts against real Ubuntu images.

## Demand-fetch: how much of an image is actually read?

Ubuntu 22.04 minimal cloud image (2.1GB root partition, 68,512 × 32KB chunks):

| Stage | Chunks read | Data | % of image |
|---|---|---|---|
| Full systemd boot to login prompt | 4,159 | 130 MB | 6.1% |
| + all shared libraries | 923 | 29 MB | 7.6% cumulative |
| + all of /usr/share | 4,244 | 133 MB | 13.8% cumulative |
| + all executables | 1,289 | 40 MB | 15.7% cumulative |

**93.9% of the image is never read during a full boot.** Even exhaustive use of the system touches only ~16% of the raw image (including unallocated space; ~35% of actual filesystem data).

## Dedup: extent overlap between image versions

Extent-level dedup using inode-based physical extent boundaries:

| Comparison | Exact extent overlap (count) | Exact extent overlap (bytes) |
|---|---|---|
| 22.04 point releases (14 months apart) | 84% | 35% |

The count/bytes divergence reveals the size distribution: the 84% of extents that match are predominantly small files (configs, scripts, locale data). The 16% that don't match are the large files (libraries, executables) touched by security patches — these account for 65% of bytes. That 65% is the delta compression target.

For comparison, earlier analysis using fixed-size file-content-aware chunking:

| Approach | Exact overlap |
|---|---|
| 32KB chunks, file-aligned | ~70% of chunks |
| Raw block-level (fixed offsets) | ~1% of chunks |

The chunk-level 70% includes partial credit — a library with a 200-byte patch still contributes 31/32 unchanged chunks. Extent-level loses that partial credit but recovers it via delta compression at a coarser, more natural granularity (whole-file deltas with trivial source selection).

## Delta compression: marginal S3 cost

| Scenario | Exact dedup | Delta benefit | Marginal fetch |
|---|---|---|---|
| 22.04 point release | 67% exact | 56% of remainder | ~43MB of ~700MB (~94% saving) |
| 22.04 vs 24.04 | 19% exact | 13% of remainder | ~95MB of ~700MB (~86% saving) |

The 22.04 vs 24.04 saving (86%) is almost entirely from compression — delta contributes little. For point releases, delta compression does the heavy lifting.

In production, the relevant comparison is always point-release: continuous deployment means each update is a small delta from the previous. The system always operates in the point-release regime, never the major-version regime.

## Sparse vs delta compression

Measured on 22.04 point releases (14 months apart, 717.8 MB of file data in image2).

### File-level breakdown

| Category | Files | Bytes | Notes |
|---|---|---|---|
| Exact match | 14,019 | 253.7 MB (35%) | Zero marginal cost |
| Changed | 3,807 | 293.7 MB raw | Delta / sparse applies |
| New (image2 only) | — | 170.4 MB | Full upload always |
| Removed (image1 only) | — | 166.5 MB | — |

### Why sparse underperforms for this workload

Within the 3,807 changed files, 75.8% of 4KB blocks actually differ — only 24.2% are unchanged. Sparse therefore saves only 22% of changed-file bytes.

Change concentration per file:

| Fraction of blocks changed | Files | Share |
|---|---|---|
| 0–20% (highly sparse) | 329 | 9% |
| 20–40% | 348 | 9% |
| 40–60% | 571 | 15% |
| 60–80% | 75 | 2% |
| 80–100% (mostly changed) | 2,484 | **65%** |

The dominant 80–100% bucket reflects compiled binaries: even a small source fix causes recompilation with different symbol addresses, relocations, and alignment padding cascading across the whole binary. Nearly every 4KB block differs, so sparse has little to skip.

Delta compression is effective on the same files (84.9% of changed files achieve 80–100% saving vs standalone zstd) because it operates at byte granularity — the actual changed bytes in a patched library are tiny; the surrounding unchanged bytes compress away with the source as dictionary.

### Cold-boot fetch cost: 4-strategy comparison

All strategies apply zstd compression as a baseline. The comparison isolates the marginal benefit of sparse (skip unchanged 4KB blocks) and delta (use image1 file as zstd dictionary), and their combination. Saving % is the improvement over zstd-only.

**Warm host** (exact-match extents already cached locally, only changed extents fetched):

| Strategy | Fetch cost | Saving vs zstd-only |
|---|---|---|
| zstd only | 43.0 MB | — |
| zstd + sparse | 36.6 MB | 14.9% |
| zstd + delta | 33.4 MB | 22.3% |
| zstd + delta + sparse | 31.6 MB | 26.5% |

**Cold host** (no local data; exact-match extents must also be fetched):

| Strategy | Fetch cost | Saving vs zstd-only |
|---|---|---|
| zstd only | 63.1 MB | — |
| zstd + sparse | 56.6 MB | 10.3% |
| zstd + delta | 53.5 MB | 15.2% |
| zstd + delta + sparse | 51.7 MB | 18.1% |

Combining delta and sparse (31.6 MB warm) saves only 1.8 MB over delta alone (33.4 MB) — well below the theoretical additive maximum. The strategies overlap: files where sparse skips unchanged blocks are largely the same files where delta compression is most effective (small patches to large binaries).

**Conclusion:** zstd+sparse (36.6 MB warm) achieves 81% of the marginal improvement of zstd+delta (33.4 MB) — only 3.2 MB apart on the boot trace — while being substantially simpler to implement: no diff library, no source-hash dependency chains, cleaner GC semantics. For point-release Ubuntu workloads, zstd+sparse is the preferred default. Delta compression is the higher-complexity option that closes the remaining gap.

## Delta source selection on a live-written volume

Measured 2026-07-20 with `elide delta-sim` on one 4 GiB ext4 filesystem captured before and after an in-place `apt upgrade` (Ubuntu noble, release pocket to noble-updates, 272 package unpack operations) plus tmp+rename config rewrites (`scripts/delta-sim-workload` generates the pair). The tool replays the production same-LBA selection rule over the changed blocks, attempts super-feature similarity matching on the misses, and bounds what filemap path matching would achieve with a same-path oracle. One workload on a freshly-made filesystem; the numbers are indicative, not general.

**Where the churn goes** (721.4 MiB changed):

| Bucket | Bytes | Share |
|---|---|---|
| jbd2 journal range | 64.0 MiB | 8.9% |
| Metadata (non-file blocks) | 101.5 MiB | 14.1% |
| File data | 555.8 MiB | 77.1% |

The journal region cycled completely during the upgrade. Journal plus metadata is 23% of all changed bytes — the churn the proposed journal-region exclusion and metadata tagging would keep out of the delta and similarity pipelines.

**Same-LBA selection barely fires on this workload:** 31.9 MiB of the 555.8 file-data MiB (5.7%) found a beneficial same-LBA source. Package upgrades re-materialise nearly everything at fresh LBAs. (In-place writers such as postgres are the opposite regime and are already covered.)

Round 1's keep criterion was zstd-with-dictionary against LZ4. That comparison varies the codec and the dictionary at once, so the recovery figures below include bytes the dictionary did not earn (round 2 measures the split at 27%). They stand as measured under that criterion.

**Similarity matching on the 523.9 MiB of misses** (16 features, grouped in pairs into eight 8-byte super-features, 32 KiB threshold):

| Outcome | Bytes | Note |
|---|---|---|
| Recovered | 158.1 MiB (30.2%) | delta 39.0 MiB vs 90.3 MiB as LZ4 |
| No candidate | 327.8 MiB | see oracle split below |
| Matched, no benefit | 0 MiB | zero false positives survive the size check |
| Sub-threshold | 38.0 MiB | runs < 32 KiB |

**Similarity vs the same-path oracle**, on miss bytes at or above the threshold:

| | Bytes |
|---|---|
| Both find a source | 136.3 MiB |
| Similarity only | 21.8 MiB |
| Oracle only | 48.5 MiB |
| Neither | 300.4 MiB |

The "neither" bucket is almost entirely `/var/cache/apt` and `/var/lib/apt` — downloaded `.deb` archives and compressed package lists, new high-entropy content for which no delta source exists under any selection strategy. Excluding it, similarity recovers 158.1 MiB against the oracle's 184.8 MiB (~86% of what path matching achieves), without filemaps, plus 21.8 MiB that same-path lookup cannot reach (content under a different path).

**Costs:** sketching ran at ~490 MiB/s single-threaded; the index over 1,911 before-fragments is ~179 KiB; 1.7 candidate dictionaries tried per matched run.

**Two parameter findings:**

- Super-feature grouping width dominated recall. Four-feature groups recovered 101.4 MiB; two-feature pairs recovered 158.1 MiB. Rebuilt binaries have diffuse byte-level diffs, so requiring four features to survive jointly is what broke matching. With pair grouping, the cheap positional construction (max per fixed subchunk) matched the position-independent one within 1%.
- A plain `mv` rename moves no data blocks, so rotated-in-place files never enter the changed-block set at all. Rename-only churn costs nothing at the block layer; the case that matters is a rewrite landing at fresh LBAs.

### Sketch geometry, round 2

Measured 2026-07-25 on a freshly generated image pair from the same workload script (694.1 MiB changed, 576.3 MiB of file data, and an identical 31.9 MiB same-LBA hit to round 1). Every figure below is **dictionary-attributable**: the delta had to beat plain zstd on the same plaintext, not just the stored LZ4 body, so the codec's contribution is excluded. Recall is measured over the miss bytes a same-path oracle proves a source exists for, which isolates the sketch from content that has no source at all.

**Grouping is the dominant knob, and less is better.** These three geometries all store eight values per sketch, so sketch bytes, posting count and map size are identical and grouping is the only variable:

| features | grouping | recall | dict saving |
|---|---|---|---|
| 32 | fours | 57.5% | 27.8 MiB |
| 16 | pairs | 81.0% | 33.6 MiB |
| **8** | **none** | **94.1%** | **40.4 MiB** |

Ungrouped also computes the fewest features of the three. Grouping buys precision the size check already provides exactly, and it destroys the shared-feature count that candidate ranking uses.

**Feature count is the weaker knob, and its slope depends on grouping.** At pair grouping, doubling to 32 features moved recall 81.0% to 85.0% for 2.3 MiB more saving, where a uniform-resemblance fit to round 1 predicted 93%. The fit overstates it because the pairs a sketch misses are the low-resemblance tail the aggregate does not represent. Ungrouped, the count matters more, with a knee around eight:

| features (ungrouped) | sketch | map | recall | dict saving |
|---|---|---|---|---|
| 2 | 8 B | 29 KiB | 78.0% | 33.7 MiB |
| 4 | 16 B | 59 KiB | 87.0% | 37.7 MiB |
| **8** | **32 B** | **119 KiB** | **94.1%** | **40.4 MiB** |
| 16 | 64 B | 238 KiB | 98.7% | 41.9 MiB |

Two ungrouped features in 8 bytes match the shipping 64-byte geometry's 33.6 MiB. Eight in 32 bytes beat it by 20% at half the size. Sixteen buys 1.5 MiB more for another 32 bytes.

**Width is inert.** Four-byte and eight-byte super-features produced bit-identical results on every recovery number at both grouping widths. Two-byte values inflate apparent recovery by 69% through collisions while saving exactly the same 40.4 MiB, which is how the LZ4-baseline flaw surfaced.

**The candidate cap is inert once candidates are ranked** by shared-feature count. Recovery is identical at caps of 1, 2, 4, 8, 16 and 32, so the best dictionary ranks first almost always. Ungrouped features raise candidates surfaced per probe from 13 to 72 without raising dictionaries tried, because the cap holds.

**Codec versus dictionary.** Under the LZ4 baseline, 61.7 MiB of recovered target bytes in 11 runs came from zstd beating LZ4 with no dictionary contribution (delta 30.9 MiB against plain zstd's 30.8 MiB). The content is ordinary: shared libraries, apt archives, udev rules. Declining those costs 6.2 MiB of stored bytes and avoids 11 arbitrary source dependencies.

**Multi-source dictionaries buy nothing.** Building one dictionary from the top-ranked candidates concatenated (`--dict-sources`, best-ranked last so it sits closest to the input) was measured against the single-source result on the same targets:

| | top 2 | top 3 |
|---|---|---|
| Recall gain over single-source | 0 MiB, 0 runs | 0 MiB, 0 runs |
| Delta size where both cleared the bar | 5.7 → 5.7 MiB | 5.7 → 5.7 MiB |
| Targets where combined won | 9.5 MiB, 84 runs | 10.0 MiB, 85 runs |

Not one target that single-source failed was rescued by a combined dictionary, so the residual recall gap is content with no source at all rather than content spread across two. Aggregate delta size is unchanged to a tenth of a MiB, the combined dictionary winning marginally on some targets and losing on others. Mean combined dictionary was 0.2 to 0.3 MiB, well short of the size where long offsets would penalise it, so this is not a ceiling effect.

On 36% of recovered targets (400 of 1,102) the probe surfaces only one candidate, so there is nothing to combine in the first place.

**Trying past a loss rescues nothing, and a shared-feature floor costs more than it saves.** Across every configuration measured, the bytes recovered by a lower-ranked candidate after the top-ranked one failed the keep rule were **0 MiB in 0 runs**. A floor on shared features, requiring any k of eight rather than one, trades recall for candidate volume:

| min shared | recall | dict saving | candidates past the floor |
|---|---|---|---|
| **1** | **94.1%** | **40.4 MiB** | 72.9 per run |
| 2 | 87.5% | 37.3 MiB | 25.9 |
| 3 | 74.7% | 32.1 MiB | 10.0 |
| 4 | 60.2% | 29.2 MiB | 8.2 |

Every step costs recall, for the same reason grouping does: demanding more joint evidence discards the low-resemblance tail, which is where the value is. A floor of 2 on eight features lands at 87.5%, almost exactly where four features with no floor land (87.0%), so the two are the same lever.

The floor also saves less than it appears to. Candidates *surfaced* barely moves (72.9 to 72.5), because the posting runs are walked to count shared features before the floor can apply, and given that a tried-and-lost candidate ends the target, only one dictionary is ever compressed against per target anyway. There is nothing left for the floor to save.

**A trained shared dictionary earns almost nothing here.** `--train-dict` trains one zstd dictionary over 4 KiB windows sampled from the before-image and measures it against the baseline each bucket already has:

| bucket | bytes | baseline | trained 110 KiB | trained 532 KiB |
|---|---|---|---|---|
| Sub-threshold runs | 29.6 MiB in 4,252 runs | plain zstd 8.7 MiB | 8.2 MiB | 7.9 MiB |
| No similarity source | 344.5 MiB in 175 runs | plain zstd 137.9 MiB | 137.9 MiB | 137.9 MiB |
| Similarity recovered | 170.3 MiB in 1,102 runs | single-source 25.2 MiB | 65.7 MiB | 64.4 MiB |

On the sub-threshold population it was meant to serve, the population too small to carry a sketch, the dictionary earns 0.5 to 0.8 MiB against similarity's 40.4 MiB. On content with no similarity source it earns exactly nothing, that bucket being `/var/cache/apt` archives which are already compressed. Where a near-copy source exists the trained dictionary is 2.6× worse than that source, which is expected: the near-copy is the ideal dictionary and 110 KiB of trained structure cannot approach it.

Dictionary size is not the limit. Asking for 1 MiB produced 532 KiB, `zdict` having found no more shared structure in a 100 MiB corpus, and the 5× size increase moved the sub-threshold figure by 0.3 MiB. Training cost 0.6s for 110 KiB from a 10.7 MiB corpus and 4.2s for 532 KiB from 100 MiB.

The value scales with the sub-threshold population, which is small on this workload. A churn profile dominated by small uncompressed files would be a different measurement.

**Costs:** sketching runs at 383 to 431 MiB/s single-threaded across all geometries, so the gear hash dominates and the permutation count is nearly free. A full run over the 4 GiB pair takes 12 seconds.

## OCI container images vs cloud images

The findings above are from Ubuntu 22.04 cloud images (~2.1 GB root partition). OCI container
images (as imported by `elide-import --image`) have a very different profile.

### Image size and boot footprint

| Image type | Total file data | Boot footprint (raw) | Boot footprint (compressed) |
|---|---|---|---|
| Cloud image (22.04) | 2.1 GB | 130 MB (6.1%) | — |
| OCI jammy point release | 98 MB | 35.5 MB (36%) | ~1.7 MB |
| OCI noble (24.04) | 102 MB | 35.7 MB (35%) | ~1.7 MB |

OCI images are minimal: no kernel, no initrd, far fewer packages. A much higher fraction of
what is present gets touched at boot, but the raw footprint includes a large amount of
zero-padded ext4 blocks. The effective content — what must actually be transferred — is ~1.7 MB
after compression.

### Cold-start cost vs a full OCI pull

Ubuntu 24.04 OCI is a single layer of 27 MB compressed. A `docker pull` downloads the full
layer before the container can start. Elide fetches only the blocks read during boot; the
rest of the image arrives lazily on demand as the workload touches it.

These are therefore measuring different things:

- **OCI pull (27 MB):** full image on disk before start
- **Elide fetch (1.7 MB cold / 0.3 MB warm):** blocks needed to reach a running shell; total
  lifetime fetch will be higher as the workload accesses more of the image

The relevant metric is **time-to-running-VM** — how much must be transferred before the
instance is usable:

| Scenario | Cold-start fetch |
|---|---|
| Full OCI pull (`docker pull`) | 27 MB (full layer, then start) |
| Elide cold fetch (no prior cache) | 1.7 MB |
| Elide warm fetch — point release cached | 0.3 MB |
| Elide warm fetch — cross-major cached | 1.7 MB |

Even from cold, Elide reaches a running VM having fetched **16× less** than a full pull.
The warm point-release case (**90× less**) is where the block-level cache compounds the
demand-fetch savings. OCI layer caching (containerd/docker) does not help here — layers are
whole-blob content-addressed, so a point-release update re-downloads the entire ~27 MB layer
even if only a handful of packages changed.

### Point-release vs cross-major for OCI

| | Jammy point release (feb → may) | Jammy → Noble |
|---|---|---|
| Exact dedup (of boot footprint) | 0.5% | 0.0% |
| Changed extents | 5 extents, 3.1 MB raw | 3 extents, all >80% changed |
| New extents | 2 extents | 12 extents |
| Warm fetch — zstd only | 1.5 MB | 1.7 MB |
| Warm fetch — zstd+delta+sparse | **0.3 MB** | 1.7 MB (no improvement) |

Cross-major: delta and sparse provide no benefit over zstd-only because all changed extents are
>80% different and there are no matching files to use as delta dictionaries. The compression
savings come entirely from zstd on sparse ext4 content.

Point-release: delta+sparse achieves a further 5× improvement over zstd-only (0.3 MB vs
1.5 MB) because changed files are lightly patched and the delta strategy is effective.

### Comparison to cloud image cold-boot

Cloud images operate at a different scale: 130 MB boot footprint and 31–63 MB warm/cold fetch
cost (see §Cold-boot fetch cost above). OCI images invert the profile — very high % of image
touched at boot, but tiny absolute fetch cost because the images themselves are small and
compress aggressively.

## Manifest size

Ubuntu 22.04 (~762MB of file data): ~33,700 extents. At 44 bytes per entry, the binary manifest is ~1.5MB. Well within "a few MB" as expected.
