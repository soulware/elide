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

### Demand-fetch cost vs a full OCI pull

Ubuntu 24.04 OCI is a single layer of 27 MB compressed.

| Scenario | Fetch cost |
|---|---|
| Full OCI pull (`docker pull`) | 27 MB |
| Elide cold fetch (no cache) | 1.7 MB |
| Elide warm fetch — jammy point release cached | 0.3 MB |
| Elide warm fetch — jammy (cross-major) cached | 1.7 MB |

Even from cold and with no prior version cached, Elide fetches **16× less** than a full image
pull, because only the blocks read at boot are retrieved. The rest of the image is fetched
lazily on demand.

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
