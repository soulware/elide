//! Per-entry liveness classification — the shared logic that decides what
//! to do with an input segment's entries when rewriting that segment under
//! a fresh ULID.
//!
//! Used by every site that rewrites a segment under a new ULID:
//! coordinator-driven GC ([`crate::gc_plan`] / [`crate::gc_apply`]), redact,
//! sweep_pending, repack, and delta_repack. All four operations face the
//! same problem: the rewrite's new ULID sorts after every input ULID, so
//! on crash-recovery rebuild any entry the rewrite preserves competes with
//! later writes via `lbamap`'s last-write-wins rule. Stale LBA claims in
//! the rewrite would shadow genuine newer writes and corrupt the volume.
//!
//! The classifier walks each input entry against the current `lbamap`
//! (truth for "what hash should LBA X currently resolve to") and the
//! current `extent_index` (truth for "is this segment still the canonical
//! body for this hash"). It returns one of [`EntryClassification`]'s
//! variants, which the caller translates into a [`crate::gc_plan::PlanOutput`]
//! (or its in-memory equivalent for synchronous rewriters).
//!
//! The classifier is pure: no I/O, no state mutation. Caller threads the
//! `lbamap` / `extent_index` snapshots in via [`ClassifyCtx`].
//!
//! ## Multi-block partial-overwrite handling
//!
//! `Volume::write` writes a multi-block payload as one `Data` entry
//! covering N LBAs. A later write that overwrites only some of those LBAs
//! leaves the entry partially live. The classifier counts surviving
//! blocks via `lbamap.extents_in_range` (NOT a point query at
//! `start_lba`) and emits [`EntryClassification::PartialDeath`] with the
//! list of live sub-runs. The caller emits one Run per sub-run, each
//! carrying a `payload_block_offset` that the materialiser uses to slice
//! into the composite body.
//!
//! See `docs/design-gc-overlap-correctness.md` and
//! `docs/design-gc-partial-death-compaction.md`.

use std::collections::HashSet;
use std::sync::Arc;

use ulid::Ulid;

use crate::extentindex::ExtentIndex;
use crate::lbamap::{ExtentRead, LbaMap};
use crate::segment::{EntryKind, SegmentEntry};
use crate::volume::ZERO_HASH;

/// Outcome of classifying one input entry against the current `lbamap` +
/// `extent_index`. Drives plan emission.
///
/// The variants partition the input space such that exactly one applies
/// per entry; callers `match` on the result.
#[derive(Debug, Clone)]
pub enum EntryClassification {
    /// Every block in the entry's LBA range still maps to its hash.
    /// The caller passes the entry through unchanged
    /// ([`crate::gc_plan::PlanOutput::Keep`]).
    FullyLive,

    /// The entry's LBA range is fully overwritten, but its hash is still
    /// referenced elsewhere (DedupRef target / Delta source) AND this
    /// segment owns the body in `extent_index`. Demote to `CanonicalData`
    /// or `CanonicalInline` ([`crate::gc_plan::PlanOutput::Canonical`]) —
    /// preserves the body for dedup resolution, drops the LBA claim.
    DemoteToCanonical,

    /// Multi-LBA `Zero` entry whose original span is partially or fully
    /// overwritten. Caller emits one Zero per surviving sub-run
    /// ([`crate::gc_plan::PlanOutput::ZeroSplit`]). Empty `live_runs`
    /// means fully overwritten — caller drops the entry.
    ZeroSubRuns(Vec<ExtentRead>),

    /// Some blocks of this multi-block entry are still live, some are
    /// overwritten. Caller emits one
    /// [`crate::gc_plan::PlanOutput::Run`] per surviving sub-run,
    /// optionally preceded by a [`crate::gc_plan::PlanOutput::Canonical`]
    /// (when `emit_canonical` is true) to preserve the composite body
    /// for owned-body kinds whose hash is externally referenced.
    PartialDeath {
        live_runs: Arc<[ExtentRead]>,
        emit_canonical: bool,
    },

    /// Entry is fully dead AND this segment owns its hash in
    /// `extent_index`. Caller drops the entry from the rewrite output and
    /// schedules the hash for removal from `extent_index` at apply time
    /// (so a later read does not resolve the hash to bytes that won't be
    /// in the rewritten segment).
    DropAndRemoveHash,

    /// Entry is fully dead and `extent_index` already points the hash
    /// elsewhere (or never owned it). Drop the entry without touching
    /// `extent_index`.
    Drop,

    /// Partial-LBA-death `Delta` entry whose `delta_options[*].source_hash`
    /// don't resolve to anything in `extent_index`. There is no base body
    /// to reconstruct against this pass; caller defers the segment
    /// (skip rewrite) so a later pass can retry once a source is
    /// re-established.
    DeferUnresolvableDelta,
}

/// External state the classifier reads. All references are immutable —
/// the classifier never mutates anything.
pub struct ClassifyCtx<'a> {
    /// Current LBA → hash mapping. Reflects every write that has
    /// committed; the classifier counts per-block matches via
    /// [`LbaMap::extents_in_range`].
    pub lba_map: &'a LbaMap,
    /// Current hash → segment-location index. The classifier uses
    /// `lookup(hash).segment_id == segment_id` to determine whether
    /// the input segment still owns the canonical body for its
    /// entry's hash.
    pub extent_index: &'a ExtentIndex,
    /// Hashes the LBA map references at least once. Built once per
    /// classification pass via [`LbaMap::lba_referenced_hashes`] and
    /// reused across every entry — included in the context rather than
    /// recomputed because it's `O(lbamap)` to build.
    pub live_hashes: &'a HashSet<blake3::Hash>,
    /// ULID of the segment the entry came from. Used by the
    /// extent-index ownership check.
    pub segment_id: Ulid,
}

/// Classify one input entry. Pure function; result is one of
/// [`EntryClassification`]'s variants.
///
/// `Zero` entries are handled separately — they do not have an
/// `extent_index` slot of their own and use `ZERO_HASH` as a sentinel.
/// All other body-owning kinds (`Data` / `Inline` / `DedupRef` / `Delta`)
/// share the same matching-blocks-vs-total-blocks accounting; the kind
/// only matters for the dead branch (whether to demote to Canonical or
/// drop).
///
/// `CanonicalData` / `CanonicalInline` are not expected to reach this
/// classifier — they have `lba_length == 0` and make no LBA claim, so
/// rewriters that include them simply pass them through. Callers may
/// route them as `FullyLive` for that purpose; the classifier does so
/// here as a safety net.
pub fn classify_entry(entry: &SegmentEntry, ctx: &ClassifyCtx<'_>) -> EntryClassification {
    if entry.kind == EntryKind::Zero {
        let end_lba = entry.start_lba + entry.lba_length as u64;
        let live_runs: Vec<ExtentRead> = ctx
            .lba_map
            .extents_in_range(entry.start_lba, end_lba)
            .into_iter()
            .filter(|r| r.hash == ZERO_HASH)
            .collect();
        return EntryClassification::ZeroSubRuns(live_runs);
    }

    if entry.kind.is_canonical_only() {
        // Canonical entries already make no LBA claim. Pass them through
        // (subject to hash-liveness checks at the caller's discretion —
        // this classifier doesn't know whether the caller is a stripping
        // rewrite that wants to drop unreferenced canonicals).
        return EntryClassification::FullyLive;
    }

    let end_lba = entry.start_lba + entry.lba_length as u64;
    let runs = ctx.lba_map.extents_in_range(entry.start_lba, end_lba);
    let matching_blocks: u64 = runs
        .iter()
        .filter(|r| r.hash == entry.hash)
        .map(|r| r.range_end - r.range_start)
        .sum();
    let total_blocks = entry.lba_length as u64;
    let extent_live = ctx
        .extent_index
        .lookup(&entry.hash)
        .is_some_and(|loc| loc.segment_id == ctx.segment_id);

    if matching_blocks == total_blocks {
        EntryClassification::FullyLive
    } else if matching_blocks == 0 {
        match entry.kind {
            EntryKind::Data | EntryKind::Inline | EntryKind::Delta
                if extent_live && ctx.live_hashes.contains(&entry.hash) =>
            {
                EntryClassification::DemoteToCanonical
            }
            _ if extent_live => EntryClassification::DropAndRemoveHash,
            _ => EntryClassification::Drop,
        }
    } else {
        // Partial-LBA death. Build the live sub-run list once; per-kind
        // logic decides how the caller turns it into output records.
        let live_runs: Arc<[ExtentRead]> =
            runs.into_iter().filter(|r| r.hash == entry.hash).collect();
        match entry.kind {
            EntryKind::Data | EntryKind::Inline => EntryClassification::PartialDeath {
                live_runs,
                emit_canonical: ctx.live_hashes.contains(&entry.hash),
            },
            EntryKind::DedupRef => EntryClassification::PartialDeath {
                live_runs,
                // DedupRef carries no body of its own — the canonical
                // body lives in another segment via the extent index.
                // Never emit a canonical for it.
                emit_canonical: false,
            },
            EntryKind::Delta => {
                let has_resolvable_source = entry
                    .delta_options
                    .iter()
                    .any(|opt| ctx.extent_index.lookup(&opt.source_hash).is_some());
                if has_resolvable_source {
                    EntryClassification::PartialDeath {
                        live_runs,
                        emit_canonical: ctx.live_hashes.contains(&entry.hash),
                    }
                } else {
                    EntryClassification::DeferUnresolvableDelta
                }
            }
            // Zero is handled at function entry; Canonical* are
            // is_canonical_only() and short-circuited above.
            _ => EntryClassification::FullyLive,
        }
    }
}
