# Empirical Findings

Measured using `palimpsest` — a Rust tool purpose-built to explore these concepts against real Ubuntu images.

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

## Manifest size

Ubuntu 22.04 (~762MB of file data): ~33,700 extents. At 44 bytes per entry, the binary manifest is ~1.5MB. Well within "a few MB" as expected.
