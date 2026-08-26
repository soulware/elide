---
name: LSVD Integrity Verification
description: What integrity verification mechanisms LSVD uses (or doesn't use) on segments and extents
type: reference
---

## What LSVD Does NOT Have

**No cryptographic signatures on segments:**
- No Ed25519 or other asymmetric signatures over segment headers or metadata
- No HMAC, BLAKE3, or other keyed verification over segment content
- Segment files are written and read without signature envelope or verification

**No content-hash verification on extent bodies:**
- Extents are **not** hashed on write or verified on read
- No per-extent content hashes stored in segment headers
- No pull of extents with hash verification

**No integrity envelope at all:**
- Segment format is straightforward: SegmentHeader (ExtentCount, DataOffset) → ExtentHeader stream → extent body data
- No checksum fields in SegmentHeader or ExtentHeader structs
- All data is trusted after being written

## What LSVD DOES Have (Limited Scope)

**Two unused/stub functions in checksum.go:**
- `crcLBA()`: Computes CRC64-ECMA of an LBA; **never called** in the codebase
- `blkSum()`: SHA256 hash of block data, base58-encoded; only used for **debug logging** in nbd.go's `logBlocks()` function
- `rangeSum()`: SHA256 of arbitrary byte ranges, base58-encoded; used in debug/validation paths only:
  - `validation.go`: `extentValidator.populate()` and `extentValidator.validate()` — diagnostic/test code for extent validation
  - `extent_reader.go`: Error logging only; logs compressed data hash on decompression failure for debugging

**CLI-level verification (post-import only):**
- Import command accepts `--verify sha256:HEX` to validate the *entire disk image* **after** importing:
  - Computes SHA256 of all data written during import (line 646: `h := sha256.New()`)
  - Compares against user-provided hash at line 681
  - This is **not a storage integrity mechanism** — it's a one-time import validation
- `--readback` flag: Re-reads all data after import and validates SHA256 matches; again, diagnostic-only

## No Integrity Path in Read Operations

The read path (`extent_reader.go`, `range_cache.go`) does not verify:
- Segment headers before reading
- Extent data against stored hashes
- Compressed data before decompression (except retry on decompression *failure*, line 160)
- Cache hits/misses use no integrity tags

## Implications for Elide

**LSVD accepts data integrity risk:**
- Corrupted segment files on disk/S3 are not detected
- Corrupted extents silently return corrupted data
- No protection against bit flips, truncation, or man-in-the-middle (S3)
- Relies entirely on storage layer (filesystem, S3) checksums

**Elide considerations:**
1. **If local-only storage**: filesystem checksums (ext4, APFS) provide some protection; acceptable
2. **If S3 integration**: must decide whether to add signatures/hashes
   - S3 provides ETag/MD5 but not authentication
   - Consider content-addressed storage (hash-keyed) for S3 segments
   - Or add HMAC envelope if coordinator has shared secrets
3. **Can defer**: If building locally first, this is a defer-to-later decision
