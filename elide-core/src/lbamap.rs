// LBA map: in-memory structure mapping logical block addresses to content hashes.
//
// The map is a BTreeMap keyed by `start_lba`. Each entry holds
// `(lba_length, extent_hash)`. It is the authoritative source for read-path
// lookups and is updated after every promoted write.
//
// Rebuild on startup:
//   1. Scan index/*.idx for uploaded segments and pending/ for not-yet-uploaded
//      segments, in ULID order (oldest first). Applying oldest-to-newest means
//      each insert naturally overwrites earlier entries for the same LBA range.
//   2. Volume::open() replays the in-progress WAL on top in a single pass
//      that also rebuilds the pending writes (see src/volume.rs).
//
// Contrast with lab47/lsvd: the reference uses a red-black tree (TreeMap) with
// a `compactPE` value encoding both logical and physical location. Palimpsest's
// map is purely logical (LBA → hash); physical location (hash → segment+offset)
// lives in the separate extent index. This means GC repacking never touches the
// LBA map.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;

use imbl::OrdMap;
use log::warn;
use ulid::Ulid;

use crate::blake3_id_hasher::{Blake3HamtMap, Blake3HashSet};
use crate::segment;
use crate::signing;

/// A portion of a stored extent that overlaps a read request.
///
/// Returned by [`LbaMap::extents_in_range`]. Describes exactly which blocks
/// the caller needs to copy from the stored payload.
#[derive(Clone, Debug, PartialEq)]
pub struct ExtentRead {
    /// Content hash — key into the extent index to find the segment file and offset.
    pub hash: blake3::Hash,
    /// First LBA within the requested range covered by this extent.
    pub range_start: u64,
    /// One past the last LBA within the requested range covered by this extent.
    pub range_end: u64,
    /// Block offset within the stored payload for `range_start`.
    /// Byte offset into the payload = `payload_block_offset as u64 * 4096`.
    pub payload_block_offset: u32,
    /// ULID of the segment (or WAL) that staked this LBA claim. The read
    /// path uses it to resolve a journal-tier extent through the extent
    /// index's `(segment, hash)` journal map, where a hash repeated across
    /// journal segments has a distinct body per segment.
    pub claimant_ulid: Ulid,
}

/// Value stored per LBA map entry.
#[derive(Clone, Copy)]
struct MapEntry {
    lba_length: u32,
    hash: blake3::Hash,
    /// Number of 4KB blocks from the start of the stored payload to the data
    /// for this entry's `start_lba`. Zero for freshly inserted entries;
    /// non-zero only for entries produced by splitting a larger entry —
    /// e.g. if `[0, 100) → H` is split by a write to `[30, 50)`, the
    /// resulting tail `[50, 100) → H` has `payload_block_offset = 50`.
    payload_block_offset: u32,
    /// ULID of the segment (or WAL) that staked this LBA claim. Distinct
    /// from `extent_index[hash].segment_id` (the body owner): a DedupRef
    /// in segment `u_dr` claims its LBA range under `u_dr` even though
    /// the body lives in some earlier `u_owner`. Used by `insert_if_newer`
    /// to let structural-commit outputs (GC / redact / repack) merge into
    /// the live lbamap without clobbering concurrent live writes whose
    /// ULID is higher. See `docs/design/lbamap-claimant-tracking.md`.
    claimant_ulid: Ulid,
}

/// Admission policy for [`LbaMap::register_entry_inner`].
enum Admission<'a> {
    Unconditional,
    IfNewer,
    ConsumingInputs(&'a HashSet<Ulid>),
    OutputHorizon(Ulid),
}

/// Overlap-blocking rule for [`LbaMap::insert_inner_if_newer`].
enum Blocking<'a> {
    /// An existing claimant `>=` ours keeps its sub-range.
    SameOrHigher,
    /// An existing claimant `>` ours keeps its sub-range; an equal
    /// claimant is overridden (same-segment re-registration, where
    /// entry order is authoritative).
    Higher,
    /// Structural-commit apply: see the comment in
    /// [`LbaMap::insert_inner_if_newer`].
    Consuming(&'a HashSet<Ulid>),
    /// Rebuild admission for a compaction output: an existing claimant
    /// above the output's view horizon (`max(inputs)`) keeps its
    /// sub-range; see the comment in [`LbaMap::insert_inner_if_newer`].
    AboveHorizon(Ulid),
}

/// The live in-memory LBA map.
///
/// Maps `start_lba → MapEntry` for every committed extent. Unwritten LBA
/// ranges have no entry (implicitly zero, as the block device presents
/// unwritten blocks as zeroes).
///
/// The map tracks claims only. A hash whose canonical form is
/// delta-encoded depends on its source extents for decompression, and
/// the extent index owns canonical forms, so that dependency lives
/// there: deletion decisions union `ExtentIndex::named_delta_sources`
/// with `claim_referenced_hashes()`.
///
/// Snapshot of which hashes are referenced, composed by the volume from
/// the claim map plus the named delta sources
/// ([`LbaMap::referenced_hashes`]).
///
/// Exists so a worker can ask the liveness question against state captured
/// on the actor, which is where the delta producer decides whether a
/// candidate source is worth pinning.
#[derive(Clone, Default)]
pub struct ReferencedHashes {
    claims: Blake3HamtMap<u32>,
    delta_sources: Blake3HashSet,
}

impl ReferencedHashes {
    pub fn contains(&self, hash: &blake3::Hash) -> bool {
        self.claims.contains_key(hash) || self.delta_sources.contains(hash)
    }
}

#[derive(Clone)]
pub struct LbaMap {
    inner: OrdMap<u64, MapEntry>,
    /// Refcounts for hashes claimed by an LBA. Invariant:
    /// `claim_counts[h]` equals the number of keys in `inner` whose entry
    /// has `hash == h`, and zero-count entries are removed eagerly, so a
    /// key is present exactly when some LBA claims that hash.
    /// [`Self::recount_claims`] recomputes it as the oracle.
    ///
    /// Maintaining it makes "is this hash claimed" an O(1) question. The
    /// walk it replaces is the primary liveness oracle for GC, staged
    /// apply and full-warm enumeration, all of which asked it by
    /// collecting a fresh set over every entry.
    claim_counts: Blake3HamtMap<u32>,
}

impl LbaMap {
    pub fn new() -> Self {
        Self {
            inner: OrdMap::new(),
            claim_counts: Blake3HamtMap::default(),
        }
    }

    fn claim_incref(&mut self, h: blake3::Hash) {
        *self.claim_counts.entry(h).or_insert(0) += 1;
    }

    fn claim_decref(&mut self, h: &blake3::Hash) {
        match self.claim_counts.get_mut(h) {
            Some(c) if *c == 1 => {
                self.claim_counts.remove(h);
            }
            Some(c) => *c -= 1,
            None => debug_assert!(false, "decref of unclaimed hash"),
        }
    }

    /// Remove the entry at `key` from `inner` and decref its claimed
    /// hash. Returns the removed entry if one existed.
    fn remove_entry(&mut self, key: u64) -> Option<MapEntry> {
        let entry = self.inner.remove(&key)?;
        self.claim_decref(&entry.hash);
        Some(entry)
    }

    /// Insert `(key, entry)` into `inner` and increment the claimed
    /// hash's refcount.
    fn add_entry(&mut self, key: u64, entry: MapEntry) {
        // Displacing an occupied key would drop its claim ref without
        // decrefing it. Every caller trims or removes first, and the
        // refcount depends on that holding.
        debug_assert!(
            !self.inner.contains_key(&key),
            "add_entry would displace the entry at {key}"
        );
        self.claim_incref(entry.hash);
        self.inner.insert(key, entry);
    }

    /// Insert an extent `[start_lba, start_lba + lba_length)` → `hash`,
    /// trimming or splitting any existing entries it overlaps.
    ///
    /// `claimant` is the ULID of the segment (or open WAL) that's making
    /// the claim. New entries always have `payload_block_offset = 0`;
    /// non-zero offsets arise only in the split/tail entries created internally.
    /// Splits propagate the original entry's claimant unchanged.
    pub fn insert(&mut self, start_lba: u64, lba_length: u32, hash: blake3::Hash, claimant: Ulid) {
        self.insert_inner(start_lba, lba_length, 0, hash, claimant);
    }

    /// Insert only on sub-ranges where no overlapping current entry has a
    /// claimant `>=` ours; leave higher-claimant overlaps untouched. Used by
    /// structural-commit apply paths (GC / redact / repack) to merge their
    /// output into the live lbamap without clobbering concurrent live
    /// writes whose ULID is higher than the structural op's `new_ulid`. See
    /// `docs/design/lbamap-claimant-tracking.md` and
    /// `gc_output_loses_to_live_write_applied_after_gc`.
    ///
    /// Returns the number of LBA blocks installed, which is less than
    /// `lba_length` when a blocking claimant kept part of the range.
    pub fn insert_if_newer(
        &mut self,
        start_lba: u64,
        lba_length: u32,
        hash: blake3::Hash,
        claimant: Ulid,
    ) -> u32 {
        self.insert_inner_if_newer(
            start_lba,
            lba_length,
            hash,
            claimant,
            Blocking::SameOrHigher,
        )
    }

    /// [`insert_if_newer`] variant for rewrite apply paths (GC fold /
    /// sweep / repack): installs on a sub-range whose current claimant is
    /// one of the `consumed_inputs` this apply consumes and deletes, or
    /// which holds our hash at a lower ULID. A consumed claimant is
    /// overridable at any ULID order — e.g. the `u_flush` segment a sweep
    /// bin-packs sits *above* the output ULID (see
    /// `docs/finding-sweep-flush-claimant-bug.md`). A same-hash lower-ULID
    /// claimant names a segment with identical bytes, so adopting the
    /// higher ULID matches the rebuild's highest-ULID-wins claim. Every
    /// other claimant keeps its sub-range: it marks a write the rewrite's
    /// plan did not carry.
    pub fn insert_consuming_inputs(
        &mut self,
        start_lba: u64,
        lba_length: u32,
        hash: blake3::Hash,
        claimant: Ulid,
        consumed_inputs: &HashSet<Ulid>,
    ) -> u32 {
        self.insert_inner_if_newer(
            start_lba,
            lba_length,
            hash,
            claimant,
            Blocking::Consuming(consumed_inputs),
        )
    }

    /// Register one segment entry's LBA claim — the single place that
    /// maps an [`segment::EntryKind`] to its lbamap routing:
    /// CanonicalData / CanonicalInline carry a body for dedup resolution
    /// but make no LBA claim, and every other kind (Delta included)
    /// claims its range → content hash. The rebuild walks and the apply
    /// paths all route through it, so an incremental update cannot
    /// branch differently from what a fresh rebuild would produce. A
    /// Delta's source dependency is the extent index's business
    /// (`ExtentIndex::named_delta_sources`), keyed by hash rather than
    /// by claim.
    ///
    /// `admission` selects the overlap policy: `Unconditional` installs
    /// over whatever is there, `IfNewer` installs on sub-ranges whose
    /// current claimant ULID is lower or equal (highest claimant wins
    /// across segments; entry order wins within one), and
    /// `ConsumingInputs` defers to any overlapping claimant `>=`
    /// `claimant` that is not one of the inputs the apply consumes.
    ///
    /// Returns the number of LBA blocks the claim took, which an apply
    /// path reads to tell a run that landed from one a blocking
    /// claimant kept. A canonical-only kind makes no claim and returns
    /// zero.
    fn register_entry_inner(
        &mut self,
        entry: &segment::SegmentEntry,
        claimant: Ulid,
        admission: Admission<'_>,
    ) -> u32 {
        if entry.kind.is_canonical_only() {
            return 0;
        }
        match admission {
            Admission::Unconditional => {
                self.insert(entry.start_lba, entry.lba_length, entry.hash, claimant);
                entry.lba_length
            }
            Admission::IfNewer => self.insert_inner_if_newer(
                entry.start_lba,
                entry.lba_length,
                entry.hash,
                claimant,
                Blocking::Higher,
            ),
            Admission::ConsumingInputs(inputs) => self.insert_consuming_inputs(
                entry.start_lba,
                entry.lba_length,
                entry.hash,
                claimant,
                inputs,
            ),
            Admission::OutputHorizon(horizon) => self.insert_inner_if_newer(
                entry.start_lba,
                entry.lba_length,
                entry.hash,
                claimant,
                Blocking::AboveHorizon(horizon),
            ),
        }
    }

    /// [`register_entry_inner`](Self::register_entry_inner) with
    /// unconditional admission.
    pub fn register_entry(&mut self, entry: &segment::SegmentEntry, claimant: Ulid) -> u32 {
        self.register_entry_inner(entry, claimant, Admission::Unconditional)
    }

    /// [`register_entry_inner`](Self::register_entry_inner) with
    /// claimant-aware admission: the entry claims sub-ranges whose
    /// current claimant ULID is lower or equal, and defers to any
    /// higher claimant. Cross-segment winners are therefore independent
    /// of registration order (claimants are distinct segment ULIDs),
    /// while a segment's own entries apply in order, later overriding
    /// earlier at the same LBA — the write order a WAL-flush segment
    /// records. The rebuild walk routes through this, so a rebuild
    /// computes the same winners the live path maintained.
    pub fn register_entry_if_newer(
        &mut self,
        entry: &segment::SegmentEntry,
        claimant: Ulid,
    ) -> u32 {
        self.register_entry_inner(entry, claimant, Admission::IfNewer)
    }

    /// [`register_entry_inner`](Self::register_entry_inner) with the
    /// apply-phase admission: install only on sub-ranges whose current
    /// claimant is one of the `inputs` this apply consumes and deletes;
    /// every other claimant's sub-range is left untouched.
    pub fn register_entry_consuming_inputs(
        &mut self,
        entry: &segment::SegmentEntry,
        claimant: Ulid,
        inputs: &HashSet<Ulid>,
    ) -> u32 {
        self.register_entry_inner(entry, claimant, Admission::ConsumingInputs(inputs))
    }

    /// [`register_entry_inner`](Self::register_entry_inner) with the
    /// rebuild admission for a compaction output whose view horizon is
    /// `max(inputs)`: the entry claims sub-ranges whose current claimant
    /// sits at or below the horizon — a claim the output's pass
    /// classified — and defers to claimants above it, which name writes
    /// flushed after the classification.
    pub fn register_entry_with_horizon(
        &mut self,
        entry: &segment::SegmentEntry,
        claimant: Ulid,
        horizon: Ulid,
    ) -> u32 {
        self.register_entry_inner(entry, claimant, Admission::OutputHorizon(horizon))
    }

    fn insert_inner_if_newer(
        &mut self,
        start_lba: u64,
        lba_length: u32,
        hash: blake3::Hash,
        claimant: Ulid,
        blocking: Blocking<'_>,
    ) -> u32 {
        let new_end = start_lba + lba_length as u64;
        // `Consuming`: an existing entry blocks the install unless its
        // claimant is one of the inputs this apply consumes and deletes,
        // or it is this same apply's own earlier entry (claimant equals
        // ours), or it holds our hash at a lower ULID. The first is a
        // claim the rewrite tears down; the second keeps the segment's
        // internal write order — a fold output can carry a kept Delta and
        // the final claim at the same LBA, and the later entry must
        // override the earlier exactly as the rebuild's `Higher` rule
        // applies them; the third names a segment with identical bytes
        // sorting below ours, so adopting the higher ULID matches the
        // rebuild's highest-ULID-wins claim and changes no read. Distinct
        // content at a distinct lower ULID, or a higher ULID, blocks:
        // that marks a write the plan did not carry (a WAL whose flush
        // promote failed keeps stamping claims below the output ULID).
        // `SameOrHigher`: a claimant `>=` ours blocks. `Higher`: only a
        // claimant `>` ours blocks — an equal claimant is this same
        // segment's own earlier entry, and a segment's entries apply in
        // order (a WAL-flush segment carries its epoch's writes in write
        // order, later entries overriding earlier ones at the same LBA).
        // `AboveHorizon`: the rebuild's admission for a compaction
        // output. Its claims are only as fresh as the liveness view its
        // pass classified from, and `max(inputs)` bounds that view: every
        // flush applied before classification sorts at or below it (the
        // promote worker is FIFO, so apply order is mint order), and
        // every flush applied after sorts above. A claimant above the
        // horizon therefore names a write the pass never saw — the claim
        // the live apply kept via `Consuming` — and blocks whatever the
        // ULID order of claimant and output says; a claimant at or below
        // the horizon holds a claim the pass classified dead, and the
        // output overrides it. The equal-claimant and same-hash-below
        // clauses carry over from `Consuming` unchanged.
        let blocks = |existing: Ulid, existing_hash: blake3::Hash| -> bool {
            match blocking {
                Blocking::Consuming(set) => {
                    !(set.contains(&existing)
                        || existing == claimant
                        || existing_hash == hash && existing < claimant)
                }
                Blocking::SameOrHigher => existing >= claimant,
                Blocking::Higher => existing > claimant,
                Blocking::AboveHorizon(horizon) => {
                    !(existing <= horizon
                        || existing == claimant
                        || existing_hash == hash && existing < claimant)
                }
            }
        };

        // Exact-extent fast path. Entries are disjoint, so one keyed at
        // `start_lba` and exactly this long is the only entry this range
        // meets: no predecessor reaches past `start_lba`, and nothing
        // else starts below `new_end`. The claim can then be restated in
        // place, and a carry that keeps the hash leaves the refcount
        // alone. A GC fold takes this for every extent it carries
        // forward without reslicing.
        if let Some(existing) = self.inner.get(&start_lba).copied()
            && existing.lba_length == lba_length
        {
            if blocks(existing.claimant_ulid, existing.hash) {
                return 0;
            }
            self.inner.insert(
                start_lba,
                MapEntry {
                    lba_length,
                    hash,
                    payload_block_offset: 0,
                    claimant_ulid: claimant,
                },
            );
            if existing.hash != hash {
                self.claim_decref(&existing.hash);
                self.claim_incref(hash);
            }
            return lba_length;
        }

        // Sub-ranges of [start_lba, new_end) covered by an existing entry
        // whose claimant blocks ours — those we must leave untouched. The
        // BTreeMap's no-overlap invariant means these are emitted in
        // ascending order and never overlap each other.
        let mut blocked: Vec<(u64, u64)> = Vec::new();

        if let Some((&pred_start, &pred)) = self.inner.range(..start_lba).next_back() {
            let pred_end = pred_start + pred.lba_length as u64;
            if pred_end > start_lba && blocks(pred.claimant_ulid, pred.hash) {
                blocked.push((start_lba, pred_end.min(new_end)));
            }
        }

        for (&k, e) in self.inner.range(start_lba..new_end) {
            if blocks(e.claimant_ulid, e.hash) {
                let k_end = k + e.lba_length as u64;
                blocked.push((k, k_end.min(new_end)));
            }
        }

        // Install on each gap between blocked regions; insert_inner handles
        // trimming any non-blocked overlaps inside the gap. The caller's
        // logical entry covers `[start_lba, new_end)` with body block 0
        // anchored at `start_lba`, so each gap's `payload_block_offset`
        // is its distance from `start_lba` — without this, a multi-block
        // carry split around a blocked middle sub-run would lose the
        // trailing gap's offset and reads at the trailing LBAs would
        // resolve to body block 0 of the carry instead of block N.
        let mut installed = 0u32;
        let mut cursor = start_lba;
        for (b_start, b_end) in blocked {
            if cursor < b_start {
                let gap_len = (b_start - cursor) as u32;
                let pbo = (cursor - start_lba) as u32;
                self.insert_inner(cursor, gap_len, pbo, hash, claimant);
                installed += gap_len;
            }
            cursor = cursor.max(b_end);
        }
        if cursor < new_end {
            let gap_len = (new_end - cursor) as u32;
            let pbo = (cursor - start_lba) as u32;
            self.insert_inner(cursor, gap_len, pbo, hash, claimant);
            installed += gap_len;
        }
        installed
    }

    fn insert_inner(
        &mut self,
        start_lba: u64,
        lba_length: u32,
        payload_block_offset: u32,
        hash: blake3::Hash,
        claimant: Ulid,
    ) {
        let new_end = start_lba + lba_length as u64;

        // Step 1: Handle a predecessor entry that starts before `start_lba`
        // but whose tail overlaps the new range.
        if let Some((&pred_start, &pred)) = self.inner.range(..start_lba).next_back() {
            let pred_end = pred_start + pred.lba_length as u64;
            if pred_end > start_lba {
                self.remove_entry(pred_start);
                // Prefix [pred_start, start_lba): same payload_block_offset.
                self.add_entry(
                    pred_start,
                    MapEntry {
                        lba_length: (start_lba - pred_start) as u32,
                        hash: pred.hash,
                        payload_block_offset: pred.payload_block_offset,
                        claimant_ulid: pred.claimant_ulid,
                    },
                );
                // Suffix [new_end, pred_end): only present in the "hole punch"
                // case. payload_block_offset advances by (new_end - pred_start).
                if pred_end > new_end {
                    self.add_entry(
                        new_end,
                        MapEntry {
                            lba_length: (pred_end - new_end) as u32,
                            hash: pred.hash,
                            payload_block_offset: pred.payload_block_offset
                                + (new_end - pred_start) as u32,
                            claimant_ulid: pred.claimant_ulid,
                        },
                    );
                }
            }
        }

        // Step 2: Remove all entries that start within [start_lba, new_end).
        // Collect keys first to avoid mutating the map while iterating it.
        // In typical sequential-write workloads this Vec holds 0 or 1 element.
        let overlapping: Vec<u64> = self
            .inner
            .range(start_lba..new_end)
            .map(|(&k, _)| k)
            .collect();
        for key in overlapping {
            // Key was found in range query above; remove cannot fail.
            let Some(e) = self.remove_entry(key) else {
                continue;
            };
            let entry_end = key + e.lba_length as u64;
            if entry_end > new_end {
                // Entry extends past the new range; preserve its tail.
                // payload_block_offset advances by (new_end - key).
                self.add_entry(
                    new_end,
                    MapEntry {
                        lba_length: (entry_end - new_end) as u32,
                        hash: e.hash,
                        payload_block_offset: e.payload_block_offset + (new_end - key) as u32,
                        claimant_ulid: e.claimant_ulid,
                    },
                );
            }
        }

        self.add_entry(
            start_lba,
            MapEntry {
                lba_length,
                hash,
                payload_block_offset,
                claimant_ulid: claimant,
            },
        );
    }

    /// Promote the claimant ULID to `new_claimant` for every lbamap
    /// entry whose hash equals `expected_hash` and whose key falls in
    /// `[start_lba, start_lba + lba_length)`, including a predecessor
    /// whose tail extends into the range. Only entries with current
    /// claimant strictly less than `new_claimant` are updated. Returns
    /// the number of entries promoted.
    ///
    /// Used by in-place segment rewrites and WAL→segment flushes where
    /// the segment file (and thus the canonical claimant) moves to a
    /// fresh ULID but the lbamap entries' LBA ranges and hashes are
    /// unchanged. Range-walking is required because a concurrent
    /// overwrite can split the original entry — the surviving tail or
    /// head ends up keyed at an LBA other than the entry's
    /// `start_lba`. The hash-match filter still rejects sub-runs
    /// claimed by a different hash (e.g. the overwriter's). The
    /// strict inequality guard prevents downgrading a higher-ULID
    /// writer's idempotent RMW that landed mid-flight.
    pub fn set_claimant_if_matches(
        &mut self,
        start_lba: u64,
        lba_length: u32,
        expected_hash: blake3::Hash,
        new_claimant: Ulid,
    ) -> u32 {
        let end = start_lba + lba_length as u64;

        // imbl::OrdMap has no range_mut; collect matching keys first, then
        // promote each via get_mut. Two-pass cost is O(matches * log N),
        // dominated by the path-clone get_mut already pays per call.
        let mut keys: Vec<u64> = Vec::new();

        if let Some((&pred_start, pred)) = self.inner.range(..start_lba).next_back() {
            let pred_end = pred_start + pred.lba_length as u64;
            if pred_end > start_lba
                && pred.hash == expected_hash
                && pred.claimant_ulid < new_claimant
            {
                keys.push(pred_start);
            }
        }

        for (&k, entry) in self.inner.range(start_lba..end) {
            if entry.hash == expected_hash && entry.claimant_ulid < new_claimant {
                keys.push(k);
            }
        }

        let updated = keys.len() as u32;
        for k in keys {
            if let Some(entry) = self.inner.get_mut(&k) {
                entry.claimant_ulid = new_claimant;
            }
        }
        updated
    }

    /// Like [`set_claimant_if_matches`] but also promotes entries whose
    /// current claimant equals `consumed_input` — the segment the caller
    /// is consuming and about to delete. Intended for rewrite apply
    /// paths whose output ULID sorts *below* the input (delta repack
    /// pre-mints outputs under the prep-time `u_flush`): when the input
    /// is the WAL-flush segment itself, its claims sit at `u_flush` and
    /// the strict-newer guard alone would leave them pointing at the
    /// deleted file. A concurrent writer's claimant is never the input
    /// ULID, so the identity match can only move claims off the segment
    /// being deleted. Mirrors [`insert_consuming_inputs`]'s override.
    ///
    /// [`set_claimant_if_matches`]: Self::set_claimant_if_matches
    /// [`insert_consuming_inputs`]: Self::insert_consuming_inputs
    pub fn set_claimant_consuming_input(
        &mut self,
        start_lba: u64,
        lba_length: u32,
        expected_hash: blake3::Hash,
        new_claimant: Ulid,
        consumed_input: Ulid,
    ) -> u32 {
        let end = start_lba + lba_length as u64;
        let promotes =
            |existing: Ulid| -> bool { existing < new_claimant || existing == consumed_input };

        let mut keys: Vec<u64> = Vec::new();

        if let Some((&pred_start, pred)) = self.inner.range(..start_lba).next_back() {
            let pred_end = pred_start + pred.lba_length as u64;
            if pred_end > start_lba && pred.hash == expected_hash && promotes(pred.claimant_ulid) {
                keys.push(pred_start);
            }
        }

        for (&k, entry) in self.inner.range(start_lba..end) {
            if entry.hash == expected_hash && promotes(entry.claimant_ulid) {
                keys.push(k);
            }
        }

        let updated = keys.len() as u32;
        for k in keys {
            if let Some(entry) = self.inner.get_mut(&k) {
                entry.claimant_ulid = new_claimant;
            }
        }
        updated
    }

    /// Iterate over all extents that overlap `[start_lba, end_lba)`, in ascending LBA order.
    ///
    /// Each yielded item describes the portion of the extent that falls within the requested range:
    /// - `hash` — identifies the stored payload via the extent index
    /// - `range_start`, `range_end` — the sub-range of LBAs within `[start_lba, end_lba)`
    ///   that this extent covers; `range_end - range_start` blocks are needed
    /// - `payload_block_offset` — block offset within the stored payload for `range_start`
    ///
    /// Unwritten gaps between extents are omitted; the caller is responsible for
    /// leaving those output bytes as zero. The returned iterator borrows `self`
    /// — reads on the volume hot path consume it directly without ever
    /// materialising a `Vec`.
    pub fn extents_in_range(
        &self,
        start_lba: u64,
        end_lba: u64,
    ) -> impl Iterator<Item = ExtentRead> + '_ {
        // A predecessor entry (key < start_lba) may extend into the range.
        let predecessor = self
            .inner
            .range(..start_lba)
            .next_back()
            .and_then(move |(&key, &e)| {
                let entry_end = key + e.lba_length as u64;
                (entry_end > start_lba).then(|| ExtentRead {
                    hash: e.hash,
                    range_start: start_lba,
                    range_end: entry_end.min(end_lba),
                    payload_block_offset: e.payload_block_offset + (start_lba - key) as u32,
                    claimant_ulid: e.claimant_ulid,
                })
            });

        // All entries whose start_lba falls within [start_lba, end_lba).
        let in_range = self.inner.range(start_lba..end_lba).map(move |(&key, &e)| {
            let range_end = (key + e.lba_length as u64).min(end_lba);
            ExtentRead {
                hash: e.hash,
                range_start: key,
                range_end,
                payload_block_offset: e.payload_block_offset,
                claimant_ulid: e.claimant_ulid,
            }
        });

        predecessor.into_iter().chain(in_range)
    }

    /// Look up the extent containing `lba`.
    ///
    /// True iff the map has an extent keyed at exactly `start_lba` that
    /// covers `lba_length` blocks, has `payload_block_offset == 0`, and
    /// matches `hash`.
    ///
    /// Used by the no-op write skip in `Volume::write`: a match means the
    /// LBA map already records our exact content at the exact range, so
    /// the write can return immediately without touching the WAL, segment
    /// tree, or extent index. See `docs/design/noop-write-skip.md`.
    ///
    /// BLAKE3 length folding means a hash match would already imply a
    /// length match *for whole payloads*, but an LBA map entry may be a
    /// proper prefix of the payload (head of a split extent). The
    /// `lba_length` and `payload_block_offset == 0` checks reject those
    /// cases — skipping them would leave stale mappings in the tail of
    /// the incoming range.
    pub fn has_full_match(&self, start_lba: u64, lba_length: u32, hash: &blake3::Hash) -> bool {
        self.inner.get(&start_lba).is_some_and(|e| {
            e.lba_length == lba_length && e.payload_block_offset == 0 && &e.hash == hash
        })
    }

    /// Returns `(hash, block_offset)` where `block_offset` is the number of
    /// 4KB blocks from the start of the stored payload (identified by `hash`)
    /// to `lba`'s data. The byte offset into the segment body is
    /// `body_offset + block_offset as u64 * 4096`.
    ///
    /// Returns `None` if `lba` falls in an unwritten region.
    pub fn lookup(&self, lba: u64) -> Option<(blake3::Hash, u32)> {
        let (&start, &e) = self.inner.range(..=lba).next_back()?;
        if lba < start + e.lba_length as u64 {
            Some((e.hash, e.payload_block_offset + (lba - start) as u32))
        } else {
            None
        }
    }

    /// [`lookup`](Self::lookup) plus the claiming segment ULID, for readers
    /// that resolve journal-tier extents through the extent index's
    /// `(segment, hash)` journal map.
    pub fn lookup_with_claimant(&self, lba: u64) -> Option<(blake3::Hash, u32, Ulid)> {
        let (&start, &e) = self.inner.range(..=lba).next_back()?;
        if lba < start + e.lba_length as u64 {
            Some((
                e.hash,
                e.payload_block_offset + (lba - start) as u32,
                e.claimant_ulid,
            ))
        } else {
            None
        }
    }

    /// Number of extents in the map.
    #[allow(dead_code)] // used in tests; available for diagnostics
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Return the set of all content hashes currently claimed by any LBA
    /// range, regardless of how the LBA got its hash (DATA write, DedupRef
    /// write, Delta write, or rebuilt from a segment of any entry kind) —
    /// hence the `claim_` prefix: everything here is known through claims.
    ///
    /// **This set alone does not satisfy the canonical-presence
    /// invariant.** A claimed hash whose canonical form is delta-encoded
    /// depends on source extents this set knows nothing about. Every
    /// deletion decision must union in `ExtentIndex::named_delta_sources`,
    /// or a kept delta loses the base extent it decompresses against and
    /// the LBA reads "no source option resolved in extent index". The GC
    /// planner, the plan-apply stale-liveness veto, repack, and the index
    /// liveness walk all follow that pattern.
    pub fn claim_referenced_hashes(&self) -> Blake3HashSet {
        self.claim_counts.keys().copied().collect()
    }

    /// Whether any LBA claims `hash` — the same claim-level definition
    /// [`Self::claim_referenced_hashes`] uses, with the same caveat: a
    /// deletion decision needs the named delta sources on top. One hash
    /// lookup against the maintained refcounts, for callers that only ask
    /// membership and have no use for an owned set.
    pub fn is_referenced(&self, hash: &blake3::Hash) -> bool {
        self.claim_counts.contains_key(hash)
    }

    /// A detached view of claim membership plus the caller-supplied
    /// delta-source pin set, for a worker that needs the liveness
    /// question off-lock. The volume composes the set from its extent
    /// index (`ExtentIndex::named_delta_sources`) at snapshot time.
    ///
    /// The claim map is persistent, so this shares structure rather than
    /// copying, and the view is a snapshot: it answers as of the moment
    /// it was taken.
    pub fn referenced_hashes(&self, delta_sources: Blake3HashSet) -> ReferencedHashes {
        ReferencedHashes {
            claims: self.claim_counts.clone(),
            delta_sources,
        }
    }

    /// Recompute `claim_counts` from `inner`, the definition the maintained
    /// map has to match.
    ///
    /// This is the walk `claim_referenced_hashes` used to do on every call.
    /// It survives as the oracle for [`Self::debug_assert_claim_counts`].
    fn recount_claims(&self) -> Blake3HamtMap<u32> {
        let mut out: Blake3HamtMap<u32> = Blake3HamtMap::default();
        for e in self.inner.values() {
            *out.entry(e.hash).or_insert(0) += 1;
        }
        out
    }

    /// Assert the incrementally maintained `claim_counts` equals a fresh
    /// recount. Compiled out of release builds; call it after mutations in
    /// tests and at apply boundaries.
    pub fn debug_assert_claim_counts(&self) {
        debug_assert_eq!(
            self.claim_counts,
            self.recount_claims(),
            "claim_counts diverged from a recount over inner"
        );
    }

    /// Iterate every entry in the map as
    /// `(start_lba, lba_length, hash, payload_block_offset)`, sorted by
    /// `start_lba`. Used by the extent-reclamation candidate scanner to
    /// fold LBA map state into per-hash run lists in a single O(n) pass.
    pub fn iter_entries(&self) -> impl Iterator<Item = (u64, u32, blake3::Hash, u32)> + '_ {
        self.inner
            .iter()
            .map(|(&lba, e)| (lba, e.lba_length, e.hash, e.payload_block_offset))
    }

    /// Diagnostic: every entry as
    /// `(start_lba, lba_length, hash, payload_block_offset, claimant)`.
    pub fn iter_entries_with_claimant(
        &self,
    ) -> impl Iterator<Item = (u64, u32, blake3::Hash, u32, Ulid)> + '_ {
        self.inner.iter().map(|(&lba, e)| {
            (
                lba,
                e.lba_length,
                e.hash,
                e.payload_block_offset,
                e.claimant_ulid,
            )
        })
    }

    /// Return all (start_lba, lba_length) ranges whose hash equals `target`.
    ///
    /// Used for diagnostics only (linear scan).
    pub fn lbas_for_hash(&self, target: &blake3::Hash) -> Vec<(u64, u32)> {
        self.inner
            .iter()
            .filter(|(_, e)| &e.hash == target)
            .map(|(&lba, e)| (lba, e.lba_length))
            .collect()
    }

    /// Return all `(start_lba, lba_length, payload_block_offset)` runs
    /// whose hash equals `target`.
    ///
    /// Extent reclamation uses this for two checks:
    /// - **Containment**: every run must fall inside a given target range
    ///   before we can safely rewrite the hash (otherwise a rewrite in
    ///   isolation would strand out-of-range references on the bloated
    ///   body).
    /// - **Bloat detection**: any run with `payload_block_offset != 0`
    ///   is evidence that a prior write split the original payload, and
    ///   dead bytes exist inside the stored body.
    ///
    /// Linear scan over the full map.
    pub fn runs_for_hash(&self, target: &blake3::Hash) -> Vec<(u64, u32, u32)> {
        self.inner
            .iter()
            .filter(|(_, e)| &e.hash == target)
            .map(|(&lba, e)| (lba, e.lba_length, e.payload_block_offset))
            .collect()
    }

    /// How many LBA entries claim `target`. Returns 0 when no LBA does.
    /// The count exceeds 1 when a claim was split, or when separate LBA
    /// ranges dedup to the same content.
    pub fn claim_refcount(&self, target: &blake3::Hash) -> u32 {
        self.claim_counts.get(target).copied().unwrap_or(0)
    }

    /// Return the content hash mapped to `lba`, if any entry covers it.
    ///
    /// Used by GC to check whether a dedup-ref entry is still live: the ref
    /// should only be carried into the GC output if the LBA still maps to
    /// the ref's hash.
    pub fn hash_at(&self, lba: u64) -> Option<blake3::Hash> {
        if let Some((&start, entry)) = self.inner.range(..=lba).next_back()
            && lba < start + entry.lba_length as u64
        {
            return Some(entry.hash);
        }
        None
    }

    /// Return the claimant ULID of the entry covering `lba`, if any.
    ///
    /// Used by delta_repack's superseded-claim guard (a segment is only
    /// rewritten if it still claims every LBA it covers) and by
    /// `assert_lbamap_consistent` to verify the in-memory claimant
    /// matches the one a from-disk rebuild would produce.
    pub fn claimant_at(&self, lba: u64) -> Option<Ulid> {
        if let Some((&start, entry)) = self.inner.range(..=lba).next_back()
            && lba < start + entry.lba_length as u64
        {
            return Some(entry.claimant_ulid);
        }
        None
    }
}

impl Default for LbaMap {
    fn default() -> Self {
        Self::new()
    }
}

// --- rebuild from disk ---

/// Rebuild the LBA map from all committed segments across a fork ancestry chain.
///
/// `layers` is ordered oldest-first (root ancestor first, live fork last).
/// Each element is `(fork_dir, branch_ulid)`:
/// - `fork_dir`: the fork directory containing `pending/`, `index/`, and `cache/`.
/// - `branch_ulid`: if `Some`, only segments whose ULID string is ≤ this value
///   are included. `None` means include all segments (used for the live fork).
///
/// Applying layers oldest-to-newest means later layers shadow earlier ones for
/// any overlapping LBA range, which is the correct layer-merge semantics.
///
/// The caller (`Volume::open`) is responsible for replaying the in-progress
/// WAL on top of the result.
pub fn rebuild_segments(layers: &[(PathBuf, Option<String>)]) -> io::Result<LbaMap> {
    rebuild_segments_inner(layers, true).map(|(map, _)| map)
}

/// Rebuild, also reporting the highest segment ULID the walk read.
///
/// `gc_fork` logs that ceiling beside the plans a pass emits. A fold refused
/// at apply names the claimant that blocked it, and the two together say which
/// side of the pass the fault sits on: a claimant at or below the ceiling was
/// in the view the plan was built from, one above it was not.
pub fn rebuild_segments_with_ceiling(
    layers: &[(PathBuf, Option<String>)],
) -> io::Result<(LbaMap, Option<Ulid>)> {
    rebuild_segments_inner(layers, true)
}

/// Same as [`rebuild_segments`] but skips ed25519 signature verification.
///
/// Used only by the runtime invariants
/// (`Volume::assert_*_consistent`) — they need to compare in-memory state
/// against the on-disk projection on every mutating op, and the signature
/// check dominates the cost (~50 µs per segment). The signatures are
/// already verified at `Volume::open` time and segments don't change after
/// that, so re-verifying on every consistency check is paranoid overhead.
///
/// **Do not use for production rebuild paths** — they must verify.
pub fn rebuild_segments_unverified(layers: &[(PathBuf, Option<String>)]) -> io::Result<LbaMap> {
    rebuild_segments_inner(layers, false).map(|(map, _)| map)
}

fn rebuild_segments_inner(
    layers: &[(PathBuf, Option<String>)],
    verify: bool,
) -> io::Result<(LbaMap, Option<Ulid>)> {
    let mut map = LbaMap::new();
    // The highest ULID whose entries reached the map, so the ceiling names
    // coverage rather than intent: a segment listed but skipped below is one
    // the caller's view does not carry.
    let mut ceiling: Option<Ulid> = None;

    for (fork_dir, branch_ulid) in layers {
        // `discover_fork_segments` handles the race-safe listing order
        // (pending → gc → index) and returns the committed tier
        // (gc ∪ index) by ULID ascending, then pending by ULID
        // ascending. Admission runs in two phases, both order-independent
        // within themselves. Flush-tier segments (empty inputs list)
        // admit by highest claimant ULID — the segment mint is monotonic,
        // so the highest claimant is the newest write. Compaction outputs
        // (recorded inputs list) admit afterwards, ULID ascending, under
        // `AboveHorizon(max(inputs))`: the output overrides claims its
        // pass classified and defers to claims flushed after the
        // classification, mirroring the `insert_consuming_inputs` rule
        // the live apply enforced. ULID order alone cannot express that
        // rule here — a pass's outputs can mint above a flush that landed
        // mid-pass, and admitting them by ULID would resurrect the stale
        // claim the live apply refused.
        let segments = segment::discover_fork_segments(fork_dir, branch_ulid.as_deref())?;

        if segments.is_empty() {
            continue;
        }

        // Load the verifying key only when this layer has segments to check
        // *and* the caller wants verification.
        let vk = if verify {
            Some(signing::load_verifying_key(
                fork_dir,
                signing::VOLUME_PUB_FILE,
            )?)
        } else {
            None
        };

        let mut outputs: Vec<(Ulid, Ulid, Vec<segment::SegmentEntry>)> = Vec::new();
        for sref in &segments {
            let parsed = match &vk {
                Some(vk) => segment::read_and_verify_segment_index(&sref.path, vk),
                None => segment::read_segment_index(&sref.path),
            };
            let (_bss, entries, inputs) = match parsed {
                Ok(v) => v,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    warn!(
                        "segment vanished during rebuild (GC race): {}",
                        sref.path.display()
                    );
                    continue;
                }
                Err(e) => return Err(e),
            };
            ceiling = ceiling.max(Some(sref.ulid));
            match inputs.iter().max().copied() {
                Some(horizon) => outputs.push((sref.ulid, horizon, entries)),
                None => {
                    for entry in entries {
                        map.register_entry_if_newer(&entry, sref.ulid);
                    }
                }
            }
        }
        outputs.sort_by_key(|(ulid, _, _)| *ulid);
        for (ulid, horizon, entries) in outputs {
            for entry in &entries {
                map.register_entry_with_horizon(entry, ulid, horizon);
            }
        }
    }

    Ok((map, ceiling))
}

// --- tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!("elide-lbamap-test-{}-{}", std::process::id(), n));
        p
    }

    fn h(b: u8) -> blake3::Hash {
        blake3::hash(&[b; 32])
    }

    /// Deterministic ULID derived from a single byte; ordering matches the
    /// byte ordering. Used for tests that don't care which segment claims
    /// what, only that `insert` accepts a claimant.
    fn u(b: u8) -> Ulid {
        Ulid::from_parts(b as u64, 0)
    }

    /// Write `volume.pub` into `dir` and return the signer.
    fn write_test_pub(dir: &std::path::Path) -> std::sync::Arc<dyn segment::SegmentSigner> {
        let (signer, vk) = signing::generate_ephemeral_signer();
        let pub_hex = signing::encode_hex(&vk.to_bytes()) + "\n";
        segment::write_file_atomic(&dir.join(signing::VOLUME_PUB_FILE), pub_hex.as_bytes())
            .unwrap();
        signer
    }

    // --- register_entry routing tests ---

    fn entry(
        kind: segment::EntryKind,
        start_lba: u64,
        lba_length: u32,
        hash: blake3::Hash,
    ) -> segment::SegmentEntry {
        segment::SegmentEntry {
            hash,
            start_lba,
            lba_length,
            codec: segment::Codec::None,
            kind,
            stored_offset: 0,
            stored_length: 0,
            inline: None,
            delta_options: Vec::new(),
            journal: false,
            sketch: None,
            stored_hash: None,
        }
    }

    fn delta_entry(
        start_lba: u64,
        lba_length: u32,
        hash: blake3::Hash,
        source: blake3::Hash,
    ) -> segment::SegmentEntry {
        let mut e = entry(segment::EntryKind::Delta, start_lba, lba_length, hash);
        e.delta_options = vec![segment::DeltaOption {
            source_hash: source,
            delta_offset: 0,
            delta_length: 0,
            delta_hash: crate::segment::stored_hash(&[0u8; 32]),
        }];
        e
    }

    #[test]
    fn register_entry_canonical_kinds_make_no_claim() {
        let mut map = LbaMap::new();
        map.register_entry(&entry(segment::EntryKind::CanonicalData, 0, 4, h(1)), u(1));
        map.register_entry(
            &entry(segment::EntryKind::CanonicalInline, 0, 4, h(2)),
            u(1),
        );
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn register_entry_routes_body_kinds_to_plain_claim() {
        let mut map = LbaMap::new();
        for (i, kind) in [
            segment::EntryKind::Data,
            segment::EntryKind::Inline,
            segment::EntryKind::DedupRef,
            segment::EntryKind::Zero,
        ]
        .into_iter()
        .enumerate()
        {
            let start = i as u64 * 10;
            map.register_entry(&entry(kind, start, 4, h(i as u8)), u(1));
            assert_eq!(map.lookup(start), Some((h(i as u8), 0)));
        }
    }

    #[test]
    fn register_entry_routes_delta_to_plain_claim() {
        let mut map = LbaMap::new();
        map.register_entry(&delta_entry(0, 4, h(1), h(9)), u(1));
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert!(map.is_referenced(&h(1)));
    }

    #[test]
    fn register_entry_consuming_inputs_overrides_input_claim_only() {
        let mut map = LbaMap::new();
        // u(5) is a consumed input despite being newer than the output u(3);
        // u(9) is a concurrent writer and must survive.
        map.insert(0, 4, h(1), u(5));
        map.insert(10, 4, h(2), u(9));
        let inputs: HashSet<Ulid> = [u(5)].into_iter().collect();
        map.register_entry_consuming_inputs(
            &entry(segment::EntryKind::Data, 0, 4, h(3)),
            u(3),
            &inputs,
        );
        map.register_entry_consuming_inputs(
            &entry(segment::EntryKind::Data, 10, 4, h(4)),
            u(3),
            &inputs,
        );
        assert_eq!(map.lookup(0), Some((h(3), 0)));
        assert_eq!(map.lookup(10), Some((h(2), 0)));
    }

    /// The exact-extent path carries a hash forward under a new
    /// claimant, which is what every unresliced entry of a GC fold does.
    #[test]
    fn consuming_inputs_restates_an_exact_extent_under_the_new_claimant() {
        let mut map = LbaMap::new();
        map.insert(8, 4, h(1), u(5));
        let inputs: HashSet<Ulid> = [u(5)].into_iter().collect();

        let installed = map.insert_consuming_inputs(8, 4, h(1), u(7), &inputs);

        assert_eq!(installed, 4);
        assert_eq!(map.lookup(8), Some((h(1), 0)));
        assert_eq!(map.lookup(11), Some((h(1), 3)));
        assert!(map.is_referenced(&h(1)));
        map.debug_assert_claim_counts();
    }

    /// Same extent, different hash: the claim count moves across.
    #[test]
    fn consuming_inputs_exact_extent_moves_the_claim_count() {
        let mut map = LbaMap::new();
        map.insert(8, 4, h(1), u(5));
        let inputs: HashSet<Ulid> = [u(5)].into_iter().collect();

        let installed = map.insert_consuming_inputs(8, 4, h(2), u(7), &inputs);

        assert_eq!(installed, 4);
        assert_eq!(map.lookup(8), Some((h(2), 0)));
        assert!(!map.is_referenced(&h(1)));
        assert!(map.is_referenced(&h(2)));
        map.debug_assert_claim_counts();
    }

    /// A claimant outside the consumed set keeps the whole extent.
    #[test]
    fn consuming_inputs_exact_extent_defers_to_a_blocking_claimant() {
        let mut map = LbaMap::new();
        map.insert(8, 4, h(1), u(9));
        let inputs: HashSet<Ulid> = [u(5)].into_iter().collect();

        let installed = map.insert_consuming_inputs(8, 4, h(2), u(7), &inputs);

        assert_eq!(installed, 0);
        assert_eq!(map.lookup(8), Some((h(1), 0)));
        assert!(!map.is_referenced(&h(2)));
        map.debug_assert_claim_counts();
    }

    #[test]
    fn register_entry_consuming_inputs_routes_delta_to_plain_claim() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(5));
        let inputs: HashSet<Ulid> = [u(5)].into_iter().collect();
        map.register_entry_consuming_inputs(&delta_entry(0, 4, h(2), h(9)), u(3), &inputs);
        assert_eq!(map.lookup(0), Some((h(2), 0)));
    }

    /// A claimant above the output's view horizon names a write its pass
    /// never classified: it keeps the range whatever the ULID order of
    /// claimant and output says (u(20) < u(30) here).
    #[test]
    fn register_with_horizon_defers_to_claimant_above_horizon() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(2), u(20));
        let installed = map.register_entry_with_horizon(
            &entry(segment::EntryKind::Data, 0, 4, h(1)),
            u(30),
            u(10),
        );
        assert_eq!(installed, 0);
        assert_eq!(map.lookup(0), Some((h(2), 0)));
        map.debug_assert_claim_counts();
    }

    /// A claimant at or below the horizon holds a claim the output's pass
    /// classified dead; the output overrides it.
    #[test]
    fn register_with_horizon_overrides_claimant_below_horizon() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(3), u(5));
        let installed = map.register_entry_with_horizon(
            &entry(segment::EntryKind::Data, 0, 4, h(1)),
            u(30),
            u(10),
        );
        assert_eq!(installed, 4);
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        map.debug_assert_claim_counts();
    }

    /// Same hash above the horizon: identical bytes, so the output adopts
    /// the claim under its higher ULID and no read changes.
    #[test]
    fn register_with_horizon_adopts_same_hash_above_horizon() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(20));
        let installed = map.register_entry_with_horizon(
            &entry(segment::EntryKind::Data, 0, 4, h(1)),
            u(30),
            u(10),
        );
        assert_eq!(installed, 4);
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        map.debug_assert_claim_counts();
    }

    // --- insert / lookup unit tests ---

    #[test]
    fn empty_lookup_returns_none() {
        let map = LbaMap::new();
        assert!(map.lookup(0).is_none());
        assert!(map.lookup(100).is_none());
    }

    #[test]
    fn insert_and_lookup_exact() {
        let mut map = LbaMap::new();
        map.insert(10, 5, h(1), u(1));
        // First block of extent — offset 0.
        assert_eq!(map.lookup(10), Some((h(1), 0)));
        // Middle block — offset 2.
        assert_eq!(map.lookup(12), Some((h(1), 2)));
        // Last block — offset 4.
        assert_eq!(map.lookup(14), Some((h(1), 4)));
    }

    #[test]
    fn lookup_miss_outside_extent() {
        let mut map = LbaMap::new();
        map.insert(10, 5, h(1), u(1)); // covers [10, 15)
        assert!(map.lookup(9).is_none());
        assert!(map.lookup(15).is_none());
        assert!(map.lookup(100).is_none());
    }

    #[test]
    fn lookup_miss_in_gap() {
        let mut map = LbaMap::new();
        map.insert(0, 5, h(1), u(1)); // [0, 5)
        map.insert(10, 5, h(2), u(2)); // [10, 15)
        assert!(map.lookup(5).is_none());
        assert!(map.lookup(7).is_none());
        assert!(map.lookup(9).is_none());
    }

    #[test]
    fn insert_overwrites_exact_range() {
        let mut map = LbaMap::new();
        map.insert(0, 10, h(1), u(1));
        map.insert(0, 10, h(2), u(2));
        assert_eq!(map.len(), 1);
        assert_eq!(map.lookup(0), Some((h(2), 0)));
        assert_eq!(map.lookup(9), Some((h(2), 9)));
    }

    #[test]
    fn insert_trims_predecessor_tail() {
        // [0, 20) → A; then insert [10, 30) → B.
        // Expected: [0, 10) → A, [10, 30) → B.
        let mut map = LbaMap::new();
        map.insert(0, 20, h(1), u(1));
        map.insert(10, 20, h(2), u(2));
        assert_eq!(map.len(), 2);
        assert_eq!(map.lookup(5), Some((h(1), 5)));
        assert_eq!(map.lookup(9), Some((h(1), 9)));
        assert_eq!(map.lookup(10), Some((h(2), 0)));
        assert_eq!(map.lookup(29), Some((h(2), 19)));
    }

    #[test]
    fn insert_splits_predecessor() {
        // [0, 100) → A; then insert [30, 20) → B (range [30, 50)).
        // Expected: [0, 30) → A, [30, 50) → B, [50, 100) → A.
        let mut map = LbaMap::new();
        map.insert(0, 100, h(1), u(1));
        map.insert(30, 20, h(2), u(2));
        assert_eq!(map.len(), 3);
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.lookup(29), Some((h(1), 29)));
        assert_eq!(map.lookup(30), Some((h(2), 0)));
        assert_eq!(map.lookup(49), Some((h(2), 19)));
        assert_eq!(map.lookup(50), Some((h(1), 50)));
        assert_eq!(map.lookup(99), Some((h(1), 99)));
    }

    #[test]
    fn insert_removes_fully_covered_entries() {
        // Three adjacent entries; overwrite the middle two.
        let mut map = LbaMap::new();
        map.insert(0, 10, h(1), u(1)); // [0, 10)
        map.insert(10, 10, h(2), u(2)); // [10, 20)
        map.insert(20, 10, h(3), u(3)); // [20, 30)
        map.insert(8, 15, h(4), u(4)); // [8, 23) — covers parts of all three
        // Expected: [0, 8) → A, [8, 23) → D, [23, 30) → C.
        assert_eq!(map.len(), 3);
        assert_eq!(map.lookup(7), Some((h(1), 7)));
        assert_eq!(map.lookup(8), Some((h(4), 0)));
        assert_eq!(map.lookup(22), Some((h(4), 14)));
        assert_eq!(map.lookup(23), Some((h(3), 3)));
        assert_eq!(map.lookup(29), Some((h(3), 9)));
    }

    #[test]
    fn insert_preserves_tail_of_last_covered_entry() {
        // [50, 100) → A; insert [30, 40) → B (range [30, 70)).
        // [50, 100) starts within [30, 70) but extends past 70.
        // Expected: [30, 70) → B, [70, 100) → A.
        // (Nothing before 30 to worry about.)
        let mut map = LbaMap::new();
        map.insert(50, 50, h(1), u(1)); // [50, 100)
        map.insert(30, 40, h(2), u(2)); // [30, 70)
        assert_eq!(map.len(), 2);
        assert_eq!(map.lookup(30), Some((h(2), 0)));
        assert_eq!(map.lookup(69), Some((h(2), 39)));
        assert_eq!(map.lookup(70), Some((h(1), 20)));
        assert_eq!(map.lookup(99), Some((h(1), 49)));
    }

    // --- rebuild integration test ---

    #[test]
    fn rebuild_from_segments_in_order() {
        use crate::segment::SegmentEntry;

        let base = temp_dir();
        let pending = crate::segment::pending_open_dir(&base);
        std::fs::create_dir_all(&pending).unwrap();
        let signer = write_test_pub(&base);

        // Segment 1 (ULID "01A..."): covers [0, 10) → hash_1.
        {
            let entries = vec![SegmentEntry::new_data(
                h(1),
                0,
                10,
                segment::Codec::None,
                vec![0u8; 40960],
            )];
            segment::write_segment(
                &pending.join("01AAAAAAAAAAAAAAAAAAAAAAAA"),
                entries,
                signer.as_ref(),
            )
            .unwrap();
        }

        // Segment 2 (ULID "01B..."): overwrites [5, 10) → hash_2.
        {
            let entries = vec![SegmentEntry::new_data(
                h(2),
                5,
                5,
                segment::Codec::None,
                vec![0u8; 20480],
            )];
            segment::write_segment(
                &pending.join("01BBBBBBBBBBBBBBBBBBBBBBBB"),
                entries,
                signer.as_ref(),
            )
            .unwrap();
        }

        let map = rebuild_segments(&[(base.clone(), None)]).unwrap();

        // [0, 5) should be from segment 1.
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.lookup(4), Some((h(1), 4)));
        // [5, 10) should be from segment 2 (newer wins).
        assert_eq!(map.lookup(5), Some((h(2), 0)));
        assert_eq!(map.lookup(9), Some((h(2), 4)));

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rebuild_low_ulid_pending_loses_to_higher_committed() {
        use crate::segment::SegmentEntry;

        let base = temp_dir();
        let pending = crate::segment::pending_open_dir(&base);
        let index = base.join("index");
        std::fs::create_dir_all(&pending).unwrap();
        std::fs::create_dir_all(&index).unwrap();
        let signer = write_test_pub(&base);

        // Pending segment at the LOW ulid: covers [0, 10) → hash_1. The
        // rebuild walk visits it last (pending after committed), so under
        // order-dependent admission it would shadow the committed claim.
        {
            let entries = vec![SegmentEntry::new_data(
                h(1),
                0,
                10,
                segment::Codec::None,
                vec![0u8; 40960],
            )];
            segment::write_segment(
                &pending.join("01AAAAAAAAAAAAAAAAAAAAAAAA"),
                entries,
                signer.as_ref(),
            )
            .unwrap();
        }

        // Committed segment at the HIGHER ulid: overwrites [5, 10) → hash_2.
        {
            let entries = vec![SegmentEntry::new_data(
                h(2),
                5,
                5,
                segment::Codec::None,
                vec![0u8; 20480],
            )];
            let scratch = base.join("01BBBBBBBBBBBBBBBBBBBBBBBB.seg");
            segment::write_segment(&scratch, entries, signer.as_ref()).unwrap();
            segment::extract_idx(&scratch, &index.join("01BBBBBBBBBBBBBBBBBBBBBBBB.idx")).unwrap();
            std::fs::remove_file(&scratch).unwrap();
        }

        let map = rebuild_segments(&[(base.clone(), None)]).unwrap();

        // [0, 5): only the pending segment claims it.
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.lookup(4), Some((h(1), 4)));
        // [5, 10): the higher-ULID committed claim wins even though the
        // walk visits the pending segment after it.
        assert_eq!(map.lookup(5), Some((h(2), 0)));
        assert_eq!(map.lookup(9), Some((h(2), 4)));

        std::fs::remove_dir_all(base).unwrap();
    }

    /// The 2026-08-13 pg28 straddler shape (#949): a flush lands
    /// mid-close, the pack output mints above it carrying an input's
    /// claim the flush superseded. The live apply kept the flush's claim
    /// (`insert_consuming_inputs`); the rebuild must reach the same
    /// winner, and the output's recorded inputs horizon is what lets it.
    #[test]
    fn rebuild_output_defers_to_flush_above_its_horizon() {
        use crate::segment::SegmentEntry;

        let base = temp_dir();
        let pending = crate::segment::pending_open_dir(&base);
        let index = base.join("index");
        std::fs::create_dir_all(&pending).unwrap();
        std::fs::create_dir_all(&index).unwrap();
        let signer = write_test_pub(&base);

        // The straddler flush: newer content at [0, 10), pending, minted
        // above the consumed input "01B..." and below the output "01D...".
        {
            let entries = vec![SegmentEntry::new_data(
                h(2),
                0,
                10,
                segment::Codec::None,
                vec![0u8; 40960],
            )];
            segment::write_segment(
                &pending.join("01CCCCCCCCCCCCCCCCCCCCCCCC"),
                entries,
                signer.as_ref(),
            )
            .unwrap();
        }

        // The pack output: committed, carries the consumed input's stale
        // claim at [0, 10) under a ULID above the straddler.
        {
            let entries = vec![SegmentEntry::new_data(
                h(1),
                0,
                10,
                segment::Codec::None,
                vec![0u8; 40960],
            )];
            let scratch = base.join("01DDDDDDDDDDDDDDDDDDDDDDDD.seg");
            let inputs = [Ulid::from_string("01BBBBBBBBBBBBBBBBBBBBBBBB").unwrap()];
            segment::write_gc_segment(&scratch, entries, &inputs, signer.as_ref()).unwrap();
            segment::extract_idx(&scratch, &index.join("01DDDDDDDDDDDDDDDDDDDDDDDD.idx")).unwrap();
            std::fs::remove_file(&scratch).unwrap();
        }

        let map = rebuild_segments(&[(base.clone(), None)]).unwrap();

        assert_eq!(map.lookup(0), Some((h(2), 0)));
        assert_eq!(map.lookup(9), Some((h(2), 9)));

        std::fs::remove_dir_all(base).unwrap();
    }

    /// The everyday post-GC state: an old segment still on disk holds a
    /// claim the (since unlinked) input had superseded. The old claimant
    /// sits below the output's inputs horizon, so the output overrides it.
    #[test]
    fn rebuild_output_overrides_stale_claim_below_its_horizon() {
        use crate::segment::SegmentEntry;

        let base = temp_dir();
        let index = base.join("index");
        std::fs::create_dir_all(&index).unwrap();
        let signer = write_test_pub(&base);

        // The old segment: its [0, 10) claim was superseded by the input
        // "01B..." that the output consumed.
        {
            let entries = vec![SegmentEntry::new_data(
                h(3),
                0,
                10,
                segment::Codec::None,
                vec![0u8; 40960],
            )];
            let scratch = base.join("01AAAAAAAAAAAAAAAAAAAAAAAA.seg");
            segment::write_segment(&scratch, entries, signer.as_ref()).unwrap();
            segment::extract_idx(&scratch, &index.join("01AAAAAAAAAAAAAAAAAAAAAAAA.idx")).unwrap();
            std::fs::remove_file(&scratch).unwrap();
        }

        // The pack output carrying the input's live claim at [0, 10).
        {
            let entries = vec![SegmentEntry::new_data(
                h(1),
                0,
                10,
                segment::Codec::None,
                vec![0u8; 40960],
            )];
            let scratch = base.join("01DDDDDDDDDDDDDDDDDDDDDDDD.seg");
            let inputs = [Ulid::from_string("01BBBBBBBBBBBBBBBBBBBBBBBB").unwrap()];
            segment::write_gc_segment(&scratch, entries, &inputs, signer.as_ref()).unwrap();
            segment::extract_idx(&scratch, &index.join("01DDDDDDDDDDDDDDDDDDDDDDDD.idx")).unwrap();
            std::fs::remove_file(&scratch).unwrap();
        }

        let map = rebuild_segments(&[(base.clone(), None)]).unwrap();

        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.lookup(9), Some((h(1), 9)));

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rebuild_empty_dirs_returns_empty_map() {
        let base = temp_dir();
        // No subdirs at all — fresh volume.
        std::fs::create_dir_all(&base).unwrap();
        let map = rebuild_segments(&[(base.clone(), None)]).unwrap();
        assert!(map.is_empty());
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rebuild_merges_ancestor_chain() {
        use crate::segment::SegmentEntry;

        let ancestor = temp_dir();
        let live = temp_dir();
        std::fs::create_dir_all(crate::segment::pending_open_dir(&ancestor)).unwrap();
        std::fs::create_dir_all(crate::segment::pending_open_dir(&live)).unwrap();
        let ancestor_signer = write_test_pub(&ancestor);
        let live_signer = write_test_pub(&live);

        // Ancestor: LBA 0..10 → h(1)
        {
            let entries = vec![SegmentEntry::new_data(
                h(1),
                0,
                10,
                segment::Codec::None,
                vec![0u8; 40960],
            )];
            segment::write_segment(
                &crate::segment::pending_open_dir(&ancestor).join("01AAAAAAAAAAAAAAAAAAAAAAAA"),
                entries,
                ancestor_signer.as_ref(),
            )
            .unwrap();
        }
        // Live node: LBA 5..10 → h(2) (shadows ancestor)
        {
            let entries = vec![SegmentEntry::new_data(
                h(2),
                5,
                5,
                segment::Codec::None,
                vec![0u8; 20480],
            )];
            segment::write_segment(
                &crate::segment::pending_open_dir(&live).join("01BBBBBBBBBBBBBBBBBBBBBBBB"),
                entries,
                live_signer.as_ref(),
            )
            .unwrap();
        }

        let map = rebuild_segments(&[(ancestor.clone(), None), (live.clone(), None)]).unwrap();

        // Ancestor range not overwritten.
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.lookup(4), Some((h(1), 4)));
        // Live node shadows ancestor.
        assert_eq!(map.lookup(5), Some((h(2), 0)));
        assert_eq!(map.lookup(9), Some((h(2), 4)));

        std::fs::remove_dir_all(ancestor).unwrap();
        std::fs::remove_dir_all(live).unwrap();
    }

    #[test]
    fn rebuild_registers_delta_source_hashes() {
        // A segment with a Delta entry claims its content hash, and the
        // named-source set over the rebuilt extent index carries its
        // source_hash(es). This is the load-bearing fold that keeps GC
        // from collecting the source DATA body out from under a live
        // Delta.
        use crate::segment::{DeltaOption, SegmentEntry};

        let base = temp_dir();
        std::fs::create_dir_all(crate::segment::pending_open_dir(&base)).unwrap();
        let signer = write_test_pub(&base);

        let content_hash = h(7);
        let source_a = h(11);
        let source_b = h(13);
        let unrelated = h(99);

        let options = vec![
            DeltaOption {
                source_hash: source_a,
                delta_offset: 0,
                delta_length: 16,
                delta_hash: crate::segment::stored_hash(b"blob-a"),
            },
            DeltaOption {
                source_hash: source_b,
                delta_offset: 16,
                delta_length: 16,
                delta_hash: crate::segment::stored_hash(b"blob-b"),
            },
        ];

        let entries = vec![segment::PendingEntry::from_entry(SegmentEntry::new_delta(
            content_hash,
            0,
            1,
            options,
        ))];
        segment::write_segment(
            &crate::segment::pending_open_dir(&base).join("01AAAAAAAAAAAAAAAAAAAAAAAA"),
            entries,
            signer.as_ref(),
        )
        .unwrap();

        let map = rebuild_segments(&[(base.clone(), None)]).unwrap();
        let mut referenced = map.claim_referenced_hashes();

        // Content hash reachable via the LBA map.
        assert!(
            referenced.contains(&content_hash),
            "delta content hash missing from claim_referenced_hashes"
        );
        // Both source hashes carried by the named-source set over the
        // rebuilt extent index.
        let index = crate::extentindex::rebuild(&[(base.clone(), None)]).unwrap();
        referenced.extend(index.named_delta_sources());
        assert!(
            referenced.contains(&source_a),
            "delta source A missing from the named delta sources"
        );
        assert!(
            referenced.contains(&source_b),
            "delta source B missing from the named delta sources"
        );
        // Unrelated hash not in the set.
        assert!(!referenced.contains(&unrelated));

        std::fs::remove_dir_all(base).unwrap();
    }

    // --- insert_if_newer tests ---

    #[test]
    fn insert_if_newer_installs_into_empty_map() {
        let mut map = LbaMap::new();
        map.insert_if_newer(0, 4, h(1), u(5));
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.lookup(3), Some((h(1), 3)));
    }

    #[test]
    fn insert_if_newer_overrides_lower_claimant() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(2));
        map.insert_if_newer(0, 4, h(2), u(5));
        assert_eq!(map.lookup(0), Some((h(2), 0)));
    }

    #[test]
    fn insert_if_newer_preserves_higher_claimant() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(9));
        map.insert_if_newer(0, 4, h(2), u(5));
        assert_eq!(map.lookup(0), Some((h(1), 0)));
    }

    #[test]
    fn insert_if_newer_preserves_equal_claimant() {
        // Idempotency: replaying the same structural commit's output
        // shouldn't overwrite itself with stale split offsets.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(5));
        map.insert_if_newer(0, 4, h(2), u(5));
        assert_eq!(map.lookup(0), Some((h(1), 0)));
    }

    #[test]
    fn insert_if_newer_splits_around_higher_claimant_in_middle() {
        // Existing claim of [4, 6) at higher claimant; structural commit
        // wants to install [0, 10) → h(2) at lower claimant. Head and
        // tail get installed; middle is preserved.
        //
        // The tail gap [6, 10) inherits its `payload_block_offset` from
        // its distance to the original carry's start_lba (= 6) — without
        // this, reads at lba 6..9 would resolve to the carry's body
        // block 0..3 instead of block 6..9.
        let mut map = LbaMap::new();
        map.insert(4, 2, h(9), u(9));
        map.insert_if_newer(0, 10, h(2), u(5));
        assert_eq!(map.lookup(0), Some((h(2), 0)));
        assert_eq!(map.lookup(3), Some((h(2), 3)));
        assert_eq!(map.lookup(4), Some((h(9), 0)));
        assert_eq!(map.lookup(5), Some((h(9), 1)));
        assert_eq!(map.lookup(6), Some((h(2), 6)));
        assert_eq!(map.lookup(9), Some((h(2), 9)));
    }

    #[test]
    fn insert_if_newer_blocked_by_overlapping_predecessor() {
        // Predecessor [0, 8) at higher claimant overlaps [4, 12); only
        // [8, 12) should be installed.  The installed entry's
        // `payload_block_offset` is its distance to the original carry's
        // start_lba (= 4), so lba 8 resolves to body block 4 of h(2),
        // not block 0.
        let mut map = LbaMap::new();
        map.insert(0, 8, h(9), u(9));
        map.insert_if_newer(4, 8, h(2), u(5));
        assert_eq!(map.lookup(4), Some((h(9), 4)));
        assert_eq!(map.lookup(7), Some((h(9), 7)));
        assert_eq!(map.lookup(8), Some((h(2), 4)));
        assert_eq!(map.lookup(11), Some((h(2), 7)));
    }

    #[test]
    fn insert_if_newer_skips_when_predecessor_covers_entire_range() {
        let mut map = LbaMap::new();
        map.insert(0, 100, h(9), u(9));
        map.insert_if_newer(20, 30, h(2), u(5));
        assert_eq!(map.lookup(20), Some((h(9), 20)));
        assert_eq!(map.lookup(49), Some((h(9), 49)));
    }

    #[test]
    fn insert_if_newer_trims_lower_claimant_predecessor() {
        // Lower-claimant predecessor [0, 10) gets trimmed by the new
        // [4, 8) claim at higher claimant — same as `insert` semantics.
        let mut map = LbaMap::new();
        map.insert(0, 10, h(1), u(2));
        map.insert_if_newer(4, 4, h(2), u(5));
        assert_eq!(map.lookup(3), Some((h(1), 3)));
        assert_eq!(map.lookup(4), Some((h(2), 0)));
        assert_eq!(map.lookup(7), Some((h(2), 3)));
        assert_eq!(map.lookup(8), Some((h(1), 8)));
    }

    #[test]
    fn insert_consuming_inputs_overrides_consumed_higher_claimant() {
        // Sweep scenario: existing claimant u(9) is one of the inputs
        // sweep is consuming; new claimant u(5) is sweep's output ULID
        // (mint order: u_sweep=5, u_flush=9). Install must succeed
        // because u(9) names a segment sweep is about to delete.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(9));
        let consumed: HashSet<Ulid> = std::iter::once(u(9)).collect();
        map.insert_consuming_inputs(0, 4, h(2), u(5), &consumed);
        assert_eq!(map.lookup(0), Some((h(2), 0)));
    }

    #[test]
    fn insert_consuming_inputs_preserves_concurrent_higher_claimant() {
        // Existing claimant u(9) is NOT in the consumed set — it's a
        // concurrent writer. Sweep's output at u(5) must not clobber it.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(9));
        let consumed: HashSet<Ulid> = std::iter::once(u(7)).collect();
        map.insert_consuming_inputs(0, 4, h(2), u(5), &consumed);
        assert_eq!(map.lookup(0), Some((h(1), 0)));
    }

    #[test]
    fn insert_consuming_inputs_preserves_lower_nonconsumed_claimant() {
        // Existing claimant u(3) sorts BELOW the rewrite output's u(5)
        // but is not a consumed input — e.g. a claim stamped through a
        // WAL minted before the pass's checkpoint — and holds different
        // content (h(1) vs the carried h(2)). The rewrite's plan never
        // saw that write, so the install must leave it untouched: a lower
        // ULID grants no override once the content differs.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(3));
        let consumed: HashSet<Ulid> = std::iter::once(u(2)).collect();
        map.insert_consuming_inputs(0, 4, h(2), u(5), &consumed);
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.claimant_at(0), Some(u(3)));
    }

    #[test]
    fn insert_consuming_inputs_adopts_lower_nonconsumed_same_hash_claimant() {
        // Existing claimant u(3) sorts below the output u(5), is not a
        // consumed input, but holds the SAME hash — a second segment with
        // identical bytes (implicit dedup). The rebuild walks ascending
        // and lands on u(5); apply must adopt it too, or the in-memory
        // claimant drifts from the disk rebuild. The bytes are unchanged.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(3));
        let consumed: HashSet<Ulid> = std::iter::once(u(2)).collect();
        map.insert_consuming_inputs(0, 4, h(1), u(5), &consumed);
        assert_eq!(map.lookup(0), Some((h(1), 0)));
        assert_eq!(map.claimant_at(0), Some(u(5)));
    }

    #[test]
    fn insert_consuming_inputs_splits_around_concurrent_overlap() {
        // Mix: middle [4, 6) is held by a concurrent writer at u(20);
        // surrounding range was claimed by a consumed input at u(9).
        // Sweep's output at u(5) installs head and tail, leaves middle.
        // The tail gap inherits its `payload_block_offset` from its
        // distance to the carry's start_lba (= 6) so reads at lba 6..9
        // resolve to body block 6..9 of h(2), not block 0..3.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(9));
        map.insert(4, 2, h(9), u(20));
        map.insert(6, 4, h(1), u(9));
        let consumed: HashSet<Ulid> = std::iter::once(u(9)).collect();
        map.insert_consuming_inputs(0, 10, h(2), u(5), &consumed);
        assert_eq!(map.lookup(0), Some((h(2), 0)));
        assert_eq!(map.lookup(3), Some((h(2), 3)));
        assert_eq!(map.lookup(4), Some((h(9), 0)));
        assert_eq!(map.lookup(5), Some((h(9), 1)));
        assert_eq!(map.lookup(6), Some((h(2), 6)));
        assert_eq!(map.lookup(9), Some((h(2), 9)));
    }

    #[test]
    fn set_claimant_consuming_input_moves_consumed_higher_claimant() {
        // Delta-repack scenario: the input is the prep-time WAL-flush
        // segment at u(9); the pre-minted output ULID u(5) sorts below
        // it. The promotion must move the claim off the input the apply
        // is about to delete.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(9));
        assert_eq!(map.set_claimant_consuming_input(0, 4, h(1), u(5), u(9)), 1);
        assert_eq!(map.claimant_at(0), Some(u(5)));
        assert_eq!(map.lookup(0), Some((h(1), 0)));
    }

    #[test]
    fn set_claimant_consuming_input_preserves_concurrent_claimant() {
        // Existing claimant u(9) is not the consumed input — it's a
        // concurrent writer. The strict-newer guard still applies.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(9));
        assert_eq!(map.set_claimant_consuming_input(0, 4, h(1), u(5), u(7)), 0);
        assert_eq!(map.claimant_at(0), Some(u(9)));
    }

    #[test]
    fn set_claimant_consuming_input_requires_hash_match() {
        // A consumed-input claimant with a different hash is an
        // overwriter's sub-run; the promotion must not touch it.
        let mut map = LbaMap::new();
        map.insert(0, 4, h(3), u(9));
        assert_eq!(map.set_claimant_consuming_input(0, 4, h(1), u(5), u(9)), 0);
        assert_eq!(map.claimant_at(0), Some(u(9)));
    }

    // --- extents_in_range tests ---

    fn extents_vec(map: &LbaMap, start: u64, end: u64) -> Vec<ExtentRead> {
        map.extents_in_range(start, end).collect()
    }

    #[test]
    fn extents_in_range_empty_map() {
        let map = LbaMap::new();
        assert!(extents_vec(&map, 0, 10).is_empty());
    }

    #[test]
    fn extents_in_range_single_extent_fully_inside() {
        let mut map = LbaMap::new();
        map.insert(5, 3, h(1), u(1)); // [5, 8)
        let result = extents_vec(&map, 0, 10);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].hash, h(1));
        assert_eq!(result[0].range_start, 5);
        assert_eq!(result[0].range_end, 8);
        assert_eq!(result[0].payload_block_offset, 0);
    }

    #[test]
    fn extents_in_range_predecessor_extends_into_range() {
        let mut map = LbaMap::new();
        map.insert(0, 10, h(1), u(1)); // [0, 10)
        // Request [5, 15) — predecessor starts before range but extends in.
        let result = extents_vec(&map, 5, 15);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].range_start, 5);
        assert_eq!(result[0].range_end, 10);
        assert_eq!(result[0].payload_block_offset, 5); // 5 blocks into the payload
    }

    #[test]
    fn extents_in_range_multiple_extents() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(1)); // [0, 4)
        map.insert(4, 4, h(2), u(2)); // [4, 8)
        map.insert(8, 4, h(3), u(3)); // [8, 12)
        let result = extents_vec(&map, 2, 10);
        assert_eq!(result.len(), 3);
        // First: predecessor [0,4) clipped to [2,4)
        assert_eq!(result[0].range_start, 2);
        assert_eq!(result[0].range_end, 4);
        assert_eq!(result[0].payload_block_offset, 2);
        // Second: [4,8) fully inside
        assert_eq!(result[1].range_start, 4);
        assert_eq!(result[1].range_end, 8);
        assert_eq!(result[1].payload_block_offset, 0);
        // Third: [8,12) clipped to [8,10)
        assert_eq!(result[2].range_start, 8);
        assert_eq!(result[2].range_end, 10);
        assert_eq!(result[2].payload_block_offset, 0);
    }

    #[test]
    fn extents_in_range_gap_between_extents() {
        let mut map = LbaMap::new();
        map.insert(0, 2, h(1), u(1)); // [0, 2)
        map.insert(5, 2, h(2), u(2)); // [5, 7) — gap at [2, 5)
        let result = extents_vec(&map, 0, 7);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].range_start, 0);
        assert_eq!(result[0].range_end, 2);
        assert_eq!(result[1].range_start, 5);
        assert_eq!(result[1].range_end, 7);
    }

    #[test]
    fn extents_in_range_extent_ends_exactly_at_range_start() {
        let mut map = LbaMap::new();
        map.insert(0, 5, h(1), u(1)); // [0, 5) — ends exactly at range start
        map.insert(5, 5, h(2), u(2)); // [5, 10)
        let result = extents_vec(&map, 5, 10);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].hash, h(2));
    }

    #[test]
    fn extents_in_range_split_extent_payload_offsets() {
        // Insert [0, 10) then split it with [3, 4). Tail [4, 10) gets payload_block_offset = 4.
        // extents_in_range over [5, 8) should return the tail clipped, with
        // payload_block_offset = 4 + (5 - 4) = 5.
        let mut map = LbaMap::new();
        map.insert(0, 10, h(1), u(1));
        map.insert(3, 1, h(2), u(2)); // splits [0,10) into [0,3), [3,4), [4,10) with offset=4
        let result = extents_vec(&map, 5, 8);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].hash, h(1));
        assert_eq!(result[0].range_start, 5);
        assert_eq!(result[0].range_end, 8);
        assert_eq!(result[0].payload_block_offset, 5); // 4 (tail offset) + 1 (5-4)
    }

    // --- claim refcount tests ---

    #[test]
    fn a_claim_is_counted_and_an_overwrite_moves_the_count() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(1));
        assert_eq!(map.claim_refcount(&h(1)), 1);
        assert!(map.is_referenced(&h(1)));

        map.insert(0, 4, h(2), u(2));
        assert_eq!(
            map.claim_refcount(&h(1)),
            0,
            "the displaced hash is no longer claimed"
        );
        assert!(!map.is_referenced(&h(1)));
        assert_eq!(map.claim_refcount(&h(2)), 1);
        map.debug_assert_claim_counts();
    }

    #[test]
    fn a_hole_punch_leaves_both_fragments_counted() {
        let mut map = LbaMap::new();
        map.insert(0, 10, h(1), u(1));
        // Splits [0,10) into [0,3) and [4,10), both still claiming h(1).
        map.insert(3, 1, h(2), u(2));

        assert_eq!(map.claim_refcount(&h(1)), 2);
        assert!(
            map.is_referenced(&h(1)),
            "a hash claimed only by fragments is still live"
        );
        map.debug_assert_claim_counts();
    }

    #[test]
    fn a_trim_keeps_the_surviving_fragment_counted() {
        let mut map = LbaMap::new();
        map.insert(0, 10, h(1), u(1));
        // Overwrites the tail, leaving [0,6) → h(1).
        map.insert(6, 4, h(2), u(2));

        assert_eq!(map.claim_refcount(&h(1)), 1);
        assert_eq!(map.claim_refcount(&h(2)), 1);
        map.debug_assert_claim_counts();
    }

    #[test]
    fn separate_ranges_deduping_to_one_hash_count_separately() {
        let mut map = LbaMap::new();
        map.insert(0, 4, h(1), u(1));
        map.insert(100, 4, h(1), u(2));
        assert_eq!(map.claim_refcount(&h(1)), 2);

        map.insert(0, 4, h(9), u(3));
        assert_eq!(
            map.claim_refcount(&h(1)),
            1,
            "the far range still claims it after the near one is overwritten"
        );
        assert!(map.is_referenced(&h(1)));
        map.debug_assert_claim_counts();
    }

    #[test]
    fn claim_counts_survive_a_churn_sequence() {
        // The oracle is the recount over `inner`; the point of the churn is
        // to drive every trim, split and displacement path into it.
        let mut map = LbaMap::new();
        let mut claimant = 0u8;
        for step in 0..40u64 {
            claimant += 1;
            let start = (step * 7) % 23;
            let len = 1 + (step % 5) as u32;
            map.insert(start, len, h((step % 6) as u8), u(claimant));
            map.debug_assert_claim_counts();
        }

        // The maintained map is exactly the set the old walk produced.
        let walked: Blake3HashSet = map.iter_entries().map(|(_, _, hash, _)| hash).collect();
        let mut referenced = map.claim_referenced_hashes();
        referenced.retain(|hash| map.claim_refcount(hash) > 0);
        assert_eq!(referenced, walked);
    }
}
