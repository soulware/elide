# Design: thin delta demotion

**Status:** Proposed.

## Problem

Demoting a Delta entry materialises its composite. `into_canonical` maps
every body-owning kind to `CanonicalData`, so an LBA-dead hash-live Delta —
stored as a few KB of delta blob — is reconstructed and carried as its full
composite body, typically ~250× larger. The rewrite undoes, entry by entry,
exactly the compression the delta tier performed.

Measured on the 2026-07-21 ladder: a bucket of `live_lba=2MB` priced at
`materialised=982MB`, from 943 demoted Delta entries at ~1MB composite each.
The budget was honest (#751 made it so); the solo-oversize path emitted the
bucket anyway, the apply held ~940MB of output bodies, and the result is a
982MB segment in cache and S3. A 1.4GB precedent exists from July 19.

The same amplification runs through partial death: a Delta with surviving
runs and a live hash emits its full composite as a canonical alongside the
run slices.

## Design

A demoted Delta stays a delta. New entry kind `CanonicalDelta`: the delta's
options and blobs, no LBA claim — to `Delta` what `CanonicalData` is to
`Data`.

The cost collapses from `lba_length × 4096` to the sum of `delta_length`.
The 982MB bucket prices at a few MB, packs as an ordinary bucket member, and
the solo-oversize escape hatch is never taken for this shape.

### Wire encoding

Entry kinds serialise as a flags byte, so `CanonicalDelta` is the
`DELTA | CANONICAL_ONLY` combination (plus `HAS_DELTAS`) — a new legal
combination, not a new discriminant, and no format version bump.
`start_lba` and `lba_length` serialise as zero like every canonical kind.
The composite's length is not stored anywhere: reads recover it from the
delta decode itself, and `DeltaLocation` carries no length today.

A binary without the new kind decodes the combination as `Delta` with a
zero-length claim — it claims nothing on rebuild and registers the hash in
the deltas map, which is the correct read behaviour. That is a property of
the encoding, not a compatibility path.

### Demotion and carry

`SegmentEntry::into_canonical` maps `Delta → CanonicalDelta`, keeping the
options and zeroing the claim.

The classifier's ownership probe routes through the map that actually
homes the entry: `lookup` for body kinds, `lookup_delta` for recipe
kinds. A fully-dead hash-live Delta that owns its deltas-map slot
classifies `DemoteToCanonical`; a duplicate encoding (its hash homed in
another segment) classifies `Drop`, since its blobs are redundant. The
data-map-only probe this replaces made ownership read as false for
every recipe entry: the owner of a live hash classified `Drop`, the
apply removed its deltas-map slot as an uncarried owned hash, and every
duplicate claim on the hash lost its only resolvable home until a
restart rebuilt the index and re-registered one of the duplicates.

A demoted entry travels as a `Canonical` plan record, so the plan-emission
arm that recognises demoted kinds admits `CanonicalDelta` beside
`CanonicalData` and `CanonicalInline`; without it the record falls through
to `Keep`, which re-reads the input entry by index and carries the original
`Delta` claim forward instead of the demoted form.

`emit_canonical`'s Delta arm stops resolving the composite. It copies the
entry's blobs into the output's delta body and re-bases the options'
offsets — the same mechanics as `emit_keep`'s Delta arm — and emits
`CanonicalDelta`. `emit_keep` gains a `CanonicalDelta` arm doing the same,
so the entry survives later rewrites.

The partial-death canonical emission goes through the same `Canonical` plan
record, so it thins with no separate change: run slices still materialise
through the composite slot, and the canonical companion carries blobs.

### Reads

Resolution is content-addressed: the extent index holds one home per hash
(body form in the data map, recipe form in the deltas map), and every
claim on that hash resolves through it. A recipe home's dependents are
duplicate encodings of the same content — the dedup tier consults the
data map only, so a hash whose home is a recipe is re-encoded on a second
write, the duplicate's registration is refused, and its claim resolves
through the home. `read_block` falls through data map to deltas map, so
those reads reconstruct today while the home is a live `Delta`.

`CanonicalDelta` registers in the deltas map exactly as `Delta` does; the
claim skip is `is_canonical_only()`, which the kind joins. Reads of the
dependent claims cost what they always cost: one reconstruction (source
body + blob decode), amortised by the `.dmat` materialisation cache.
Demotion stops changing the hash's storage form — the home loses its
claim, and that is all.

### Source survival

No new gate. The demoted entry's hash is in `live_hashes` — that is why it
demotes rather than drops — and the live-hash computation unions in the
sources of every live delta in the deltas map. A hash in `live_hashes` is
never removed by a rewrite, so the source stays resolvable for as long as
the demoted delta is referenced, and the output segment's rebuild puts the
`CanonicalDelta` back in the deltas map where the next pass's union finds
it. A source that already fails to resolve reads as a loud error, exactly
as it does for a live Delta today.

`CanonicalDelta` cannot itself become a source: delta sources resolve
through the data index only, and Data-entry demotion still produces
materialised `CanonicalData`. Resolution depth stays bounded at
recipe → body: a claim resolves in at most two hops.

## Out of scope

The two oversize canonical segments already in the fleet store full
composites; there is no delta to re-thin. They stay frozen (the skip-check
requires something dead) until their canonicals die and they tombstone.
Bounding apply memory for genuinely large plans is streaming apply,
a separate design.

## Verification

- A GC pass over a fully-LBA-dead, hash-live Delta emits `CanonicalDelta`,
  and the bucket's materialised price is the blob bytes, not the composite.
- A fully-LBA-dead Delta whose hash is homed in another segment drops,
  and the home survives.
- A duplicate claim on the demoted hash reads back correctly after the
  rewrite, across a reopen.
- A second rewrite carries a `CanonicalDelta` forward intact.
- A partial-death Delta emits run slices plus a thin canonical, and the
  runs still read correctly.
- An unreferenced `CanonicalDelta` is dropped and its hash removed, like
  any canonical.
- `gc_proptest` and the crash-recovery oracles at raised cases; the
  delta-over-snapshot shapes in `volume_proptest` cover the seal
  interaction.

## Related

- [`delta-compression.md`](delta-compression.md) for the delta tier that
  mints the entries being demoted.
- [`gc-partial-death-compaction.md`](gc-partial-death-compaction.md) for
  the run-slice machinery the thin canonical sits beside.
- [`gc-bucket-unification.md`](gc-bucket-unification.md) for the budget
  the new pricing feeds.
