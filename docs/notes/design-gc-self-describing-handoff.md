---
status: landed
related: [design-gc-plan-handoff.md, design-gc-ulid-ordering.md]
landed_in: ../formats.md
---

# Self-describing GC handoff

GC handoffs previously required a plaintext manifest sidecar (`gc/<ulid>.{pending,applied,done}`) carrying `repack` / `remove` / `dead` lines, with the suffix doubling as the "body is safe to read" gate. This coupled two distinct concerns — body readability and handoff protocol state — and a second read site silently drifted off the gate before being unified.

The new segment header carries an `inputs: Vec<Ulid>` field naming the consumed segments. The volume reconstructs apply actions from the new segment's entry table plus each input's `.idx` at apply time. No manifest, no sidecar.

## Filename lifecycle

```
gc/<ulid>.staged    ← coordinator staged, not yet applied, NOT readable
gc/<ulid>           ← volume applied + re-signed, readable
(deleted after upload)
```

**Rule: a bare-name segment in `gc/` is always safe to read.** `locate_segment_body` collapses to one `exists()` check; the `gc/` branch is symmetric with `pending/` and `wal/`.

## Why crash recovery is content-resolved

Three properties make recovery safe without intermediate filename states:

- **Re-apply is deterministic.** Inputs list + input `.idx` files + new segment's entries produce the same apply set on every run.
- **Re-sign is deterministic.** Hash input is `header[0..36] || index_bytes`, both fixed on disk. A torn `.tmp` is discarded; a fresh one regenerates byte-identical output.
- **Rename is the only commit.** No in-place mutation of `.staged`. Either `.tmp` was renamed to bare or it wasn't — no half-committed state.

| Crash point | On-disk state | Recovery |
|---|---|---|
| Coordinator mid-write | `.staged.tmp` | sweep at startup |
| Coordinator wrote `.staged`, volume hasn't applied | `.staged` | volume's next apply tick picks it up |
| Volume mid-apply | `.staged` (+ partial `.tmp`) | sweep stale `.tmp`, re-run apply (idempotent) |
| Volume post-rename, pre-cleanup | `.staged` + bare | bare wins; remove `.staged` |
| Volume post-cleanup | bare | coordinator picks it up |
| Coordinator post-upload, pre-delete | bare + S3 | idempotent re-upload + delete |

## Apply set derivation

```
for each input_ulid in gc_segment.inputs:
    old_entries = read_segment_index(input_ulid)
    for each entry in old_entries:
        if entry.hash in gc_segment.entries:   # repacked
            update extent_index: hash → (new_ulid, new_offset)
        else:                                  # superseded
            maybe remove extent_index entry (lowest-ULID-wins still applies)
```

The "remove" arm uses the lowest-ULID-wins rule (extent-index PR #23) — drop the entry only if it currently points at the old segment.

## Notes

- Segment format bumped to magic `ELIDSEG\x05`. No back-compat path; old segments must be regenerated.
- `gc.rs` handoff state machine, manifest parser, and `.pending/.applied/.done` lifecycle were deleted in the same landing.
