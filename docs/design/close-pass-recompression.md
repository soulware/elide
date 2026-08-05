# Design: re-encoding bodies at the close pass

**Status:** Parked (2026-08-05). No implementation. The measured saving is 6
to 14% of stored bytes against a cost that lands on every durable byte, on the
thread where guest-visible tps losses have been measured twice.

## What it is

The close pass over `pending/upload/` decodes each admitted body and re-encodes
it at a higher zstd level before the generation drains. The bytes get denser;
nothing else about them changes.

Bodies are written at `BODY_ZSTD_LEVEL` (3), chosen in `compression-codecs.md`
against the formation CPU budget. The close pass is the last point where a
body is local, classified, and not yet paid for, which makes it the place to
re-decide a choice that formation made under a tighter constraint.

## Why it needs no format change

A zstd frame declares its window and its content size, never the level that
produced it. `entry.codec` stays `Zstd` or `ZstdChunked` and every reader
decodes the denser bytes unchanged.

The extent hash is BLAKE3 of the *decoded* body (`segment::verify_body_hash`),
so re-encoding leaves it untouched, and with it the extent index key, the
lbamap claims, `DedupRef` resolution, delta source references, and
classification. What moves is `stored_length`, `stored_offset`, and the header
length fields, all of which the pass rewrites anyway.

`ZstdChunked` re-encodes per chunk. One frame over the whole extent would give
up the read bound that chunking holds.

## The saving

Stored bytes as a share of plaintext, from `compression-codecs.md`:

| corpus | zstd-3 | zstd-9 | 9 under 3 |
|---|---|---|---|
| pg5, churn, 1 MiB extents | 6.2% | 5.3% | 14.3% |
| pg6, churn, 8 KiB extents | 9.8% | 9.3% | 5.7% |
| Ubuntu cloud image, import | 29.3% | 27.6% | 6.1% |

The saving lands twice, on the upload and on the stored object for as long as
it lives.

## The cost

Level 9 is about 3.4 times the compression CPU of level 3. The close pass sees
every sealed generation, so that cost applies to substantially every durable
byte the volume writes. This is the same reason formation takes level 3. The
delta tier affords level 9 because it reaches a fraction of a percent of
entries; the body tier reaches all of them, at either end of the pipeline.

What moving the work to the close pass changes is where the CPU lands, from
formation to the worker thread between ticks. That is the column two separate
measurements name as the source of guest tps loss, repack-every-tick costing
43% and 60% of guest tps. A first estimate puts a 75 MiB pg14 generation at
around a second of worker CPU per 120s cut, from a decode at zstd's usual
GB/s and a re-encode at the ~100 MB/s the delta table records for level 9.
That rate is borrowed from the delta corpus, and the close pass's existing
0.6s figure covers materialise, which touches only partial-death entries. A
recompress touches every byte, so the number wants measuring on bodies before
it is trusted.

## Kind is preserved

`SegmentEntry::new_data` derives `EntryKind` from the stored length, so a body
that falls under `INLINE_THRESHOLD` after a denser encode would become
`Inline`. A re-encoding path preserves the input entry's kind instead, which
needs a constructor that takes it rather than deriving it.

The inline section rides in the `.idx`, which every host fetches eagerly, so it
holds data that is genuinely tiny. A body that reached that size only because
the search ran longer is ordinary data that compressed well.

The consequence is that `stored_length < INLINE_THRESHOLD` stops implying
`Inline`. The converse holds by construction and is the direction the format
relies on.

## Outputs take fresh ULIDs

A reader resolves a `Local` body by filename against a `ReadSnapshot` it may
have taken before the apply, carrying that body's former `stored_offset`. Bytes
re-encoded under the same name would answer such a reader from inside a body
section that is still structurally valid, at an offset that no longer means
what it did. A fresh ULID leaves the input name holding the input bytes until
`remove_consumed_inputs` unlinks it, which is the window every consumed input
already relies on. The pass reserves output ULIDs in the same critical section
as the rotate, so the reservation is already being minted.

This makes a bucket of one fully-live segment into a real output, where today
it is skipped as byte-identical (`solo_no_op`). `emits_data_output` shares that
predicate and decides whether the journal is lifted above the pass's data
outputs, so both move together. Relaxing one alone mints a data output above a
journal segment that stayed where it was, which is the ordering inversion
`journal-pending-consolidation.md` exists to prevent.

## What would restart this

A measurement of re-encode throughput on real bodies rather than delta
residuals, and a rig run that prices the worker CPU against guest tps at the
close cadence. If the cost holds near a second per cut, 6 to 14% of every
uploaded and stored byte is bought for well under a percent of one core.
