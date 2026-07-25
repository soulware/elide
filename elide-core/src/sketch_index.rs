//! Candidate map for similarity-based delta source selection.
//!
//! Inverts the per-entry sketches ([`crate::sketch`]) into a lookup from
//! one feature value to the extents carrying it, so the delta producer can
//! ask "which prior extents resemble this one" without scanning anything
//! (`docs/design/delta-compression.md`).
//!
//! This is a cache, not index state. Every candidate it returns is
//! resolved through the live extent index before use, so a posting for a
//! hash that no longer resolves costs one failed lookup and a hash it
//! never learned costs a missed delta. Nothing here needs to agree with a
//! rebuild, and nothing is persisted: the `.idx` files it is built from
//! are the durable copy.
//!
//! Layout is a flat open-addressed multimap. Each slot is one
//! `(feature, source)` posting in eight bytes with no per-key allocation,
//! duplicate features occupy neighbouring slots, and a probe is one slot
//! index plus a scan to the end of the cluster.

use std::collections::HashMap;

use crate::segment::{EntryKind, SegmentEntry};
use crate::sketch::Sketch;

/// Bytes an extent covers per LBA.
const LBA_BYTES: u64 = 4096;

/// Marks a slot as unoccupied. Bounds the source count one below
/// `u32::MAX`, which is 4 billion sketched extents short of mattering.
const EMPTY: u32 = u32::MAX;

/// Sources retained per feature value. A feature shared by more than this
/// many extents carries almost no signal about which of them resembles a
/// target, and the cap is what keeps one such value from dominating both
/// the map and every probe that touches it. With [`crate::sketch`]'s eight
/// features it bounds a probe to `8 × CAP_PER_FEATURE` candidates however
/// large the map grows.
const CAP_PER_FEATURE: usize = 32;

/// Slots occupied before the table doubles, in eighths. Linear probing
/// degrades as clusters merge, and a sparser table is cheap here.
const LOAD_NUM: usize = 7;
const LOAD_DEN: usize = 10;

/// Slots in a freshly built table. One page of postings.
const MIN_CAPACITY: usize = 512;

#[derive(Clone, Copy)]
struct Slot {
    feature: u32,
    source: u32,
}

/// A source extent the map can offer as a dictionary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SourceRef {
    hash: blake3::Hash,
    lba_length: u32,
}

/// A probe result: a source that shares `shared` features with the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// Content hash, resolved through the extent index to find the body.
    pub hash: blake3::Hash,
    /// Uncompressed byte length of the source extent. Lets a caller skip a
    /// dictionary far larger than the target before reading its body.
    pub raw_len: u64,
    /// How many of the target's features this source carries. An estimate
    /// of resemblance, since each feature is a minhash.
    pub shared: u32,
}

/// Shape of a [`SketchIndex`], from [`SketchIndex::stats`].
#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub sources: usize,
    pub postings: usize,
    pub slots: usize,
    pub memory_bytes: usize,
    /// Feature values with at least one posting. Well below `postings`
    /// means features recur across extents, which is what a probe walks.
    pub distinct_features: usize,
    pub max_per_feature: usize,
    /// Feature values holding the retention cap, whose further sources
    /// were declined.
    pub features_at_cap: usize,
}

/// `Clone` copies both tables outright, which `Arc::make_mut` needs to
/// extend a shared map. A promote's own Arc is dropped by the time the
/// actor applies its result, so that normally mutates in place.
#[derive(Clone)]
pub struct SketchIndex {
    slots: Vec<Slot>,
    sources: Vec<SourceRef>,
    postings: usize,
}

impl SketchIndex {
    pub fn new() -> Self {
        Self {
            slots: vec![
                Slot {
                    feature: 0,
                    source: EMPTY,
                };
                MIN_CAPACITY
            ],
            sources: Vec::new(),
            postings: 0,
        }
    }

    /// Index `entry`'s sketch, if it has one.
    ///
    /// Returns whether the entry became a source. Entries without a sketch
    /// are skipped, which is what keeps journal-tier content, delta-bearing
    /// entries, sub-threshold extents and body-less kinds out of the map:
    /// the producer never sketches them in the first place.
    pub fn insert_entry(&mut self, entry: &SegmentEntry) -> bool {
        let Some(sketch) = entry.sketch else {
            return false;
        };
        if !matches!(entry.kind, EntryKind::Data | EntryKind::CanonicalData) {
            return false;
        }
        if self.sources.len() as u32 >= EMPTY {
            return false;
        }
        let source = self.sources.len() as u32;
        self.sources.push(SourceRef {
            hash: entry.hash,
            lba_length: entry.lba_length,
        });

        let mut admitted = false;
        for feature in sketch {
            if self.insert_posting(feature, source) {
                admitted = true;
            }
        }
        // Every feature was already capped, so the source is unreachable.
        if !admitted {
            self.sources.pop();
        }
        admitted
    }

    /// Place one `(feature, source)` posting, growing the table first when
    /// it has reached the load limit. Returns whether it was placed.
    fn insert_posting(&mut self, feature: u32, source: u32) -> bool {
        if (self.postings + 1) * LOAD_DEN > self.slots.len() * LOAD_NUM {
            self.grow();
        }
        let mask = self.slots.len() - 1;
        let mut i = feature as usize & mask;
        let mut seen = 0usize;
        loop {
            let slot = self.slots[i];
            if slot.source == EMPTY {
                self.slots[i] = Slot { feature, source };
                self.postings += 1;
                return true;
            }
            if slot.feature == feature {
                // A sketch may repeat a feature value. Placing it twice
                // would spend a slot and, worse, count the source twice in
                // a probe's `shared` tally.
                if slot.source == source {
                    return false;
                }
                seen += 1;
                // Earliest-wins on the cap. The rebuild walk is
                // ULID-ascending, so the retained sources are the oldest
                // carrying this feature, which favours stable imported
                // content over churn and makes the map a deterministic
                // function of the lineage.
                if seen >= CAP_PER_FEATURE {
                    return false;
                }
            }
            i = (i + 1) & mask;
        }
    }

    /// Double the table and re-place every posting. Each feature already
    /// holds at most `CAP_PER_FEATURE` sources, so nothing is dropped and
    /// the visit order does not matter.
    fn grow(&mut self) {
        let doubled = self.slots.len() * 2;
        let old = std::mem::replace(
            &mut self.slots,
            vec![
                Slot {
                    feature: 0,
                    source: EMPTY,
                };
                doubled
            ],
        );
        self.postings = 0;
        for slot in old {
            if slot.source != EMPTY {
                self.insert_posting(slot.feature, slot.source);
            }
        }
    }

    /// Every source in this cluster carrying `feature`.
    fn postings_for(&self, feature: u32, out: &mut Vec<u32>) {
        let mask = self.slots.len() - 1;
        let mut i = feature as usize & mask;
        loop {
            let slot = self.slots[i];
            if slot.source == EMPTY {
                return;
            }
            if slot.feature == feature {
                out.push(slot.source);
            }
            i = (i + 1) & mask;
        }
    }

    /// The best `limit` sources for `sketch`, most features shared first.
    ///
    /// Ranking is what lets a caller try very few dictionaries: the count
    /// of shared features estimates resemblance, so the closest source
    /// comes first. Ties keep the lower source index, which is the earlier
    /// segment in the build walk.
    pub fn candidates(&self, sketch: &Sketch, limit: usize) -> Vec<Candidate> {
        if limit == 0 {
            return Vec::new();
        }
        let mut hits: Vec<u32> = Vec::new();
        for (i, feature) in sketch.iter().enumerate() {
            // A repeated feature value would query the same postings twice
            // and inflate every source's tally.
            if sketch[..i].contains(feature) {
                continue;
            }
            self.postings_for(*feature, &mut hits);
        }
        if hits.is_empty() {
            return Vec::new();
        }
        hits.sort_unstable();

        // Runs of equal source index collapse to one candidate whose
        // `shared` is the run length.
        let mut ranked: Vec<(u32, u32)> = Vec::new();
        let mut run_start = 0usize;
        for i in 1..=hits.len() {
            if i == hits.len() || hits[i] != hits[run_start] {
                ranked.push((hits[run_start], (i - run_start) as u32));
                run_start = i;
            }
        }
        ranked.sort_by_key(|&(source, shared)| (std::cmp::Reverse(shared), source));

        let mut out: Vec<Candidate> = Vec::with_capacity(limit.min(ranked.len()));
        for (source, shared) in ranked {
            let Some(src) = self.sources.get(source as usize) else {
                continue;
            };
            // One hash can reach the map from two segments; a caller
            // resolves by hash, so a second copy would spend an attempt
            // on bytes it already tried.
            if out.iter().any(|c| c.hash == src.hash) {
                continue;
            }
            out.push(Candidate {
                hash: src.hash,
                raw_len: src.lba_length as u64 * LBA_BYTES,
                shared,
            });
            if out.len() == limit {
                break;
            }
        }
        out
    }

    /// Sources the map can offer.
    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Postings placed, for telemetry alongside [`memory_bytes`](Self::memory_bytes).
    pub fn postings(&self) -> usize {
        self.postings
    }

    /// Heap bytes held, for the resident-size reporting this map is sized
    /// against.
    pub fn memory_bytes(&self) -> usize {
        self.slots.len() * std::mem::size_of::<Slot>()
            + self.sources.capacity() * std::mem::size_of::<SourceRef>()
    }

    /// Shape of the map, for the offline `sketch-index` report. Walks the
    /// whole slot table, so this is a diagnostic rather than something to
    /// call per promote.
    pub fn stats(&self) -> Stats {
        let mut per_feature: HashMap<u32, usize> = HashMap::new();
        for slot in &self.slots {
            if slot.source != EMPTY {
                *per_feature.entry(slot.feature).or_default() += 1;
            }
        }
        Stats {
            sources: self.sources.len(),
            postings: self.postings,
            slots: self.slots.len(),
            memory_bytes: self.memory_bytes(),
            distinct_features: per_feature.len(),
            max_per_feature: per_feature.values().copied().max().unwrap_or(0),
            features_at_cap: per_feature
                .values()
                .filter(|&&n| n >= CAP_PER_FEATURE)
                .count(),
        }
    }
}

impl Default for SketchIndex {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::SegmentFlags;

    /// A `Data` entry with a body matching `lba_length`. The body has to
    /// clear the inline threshold, or `new_data` yields an `Inline` entry
    /// and the map declines it.
    fn data_entry(seed: u8, sketch: Option<Sketch>, lba_length: u32) -> SegmentEntry {
        let mut e = SegmentEntry::new_data(
            blake3::hash(&[seed]),
            seed as u64 * 64,
            lba_length,
            SegmentFlags::empty(),
            vec![seed; lba_length as usize * LBA_BYTES as usize],
        )
        .entry;
        assert_eq!(e.kind, EntryKind::Data);
        e.sketch = sketch;
        e
    }

    /// A sketch whose features are `base..base+8`, so overlap between two
    /// sketches is controllable by construction.
    fn sketch_from(base: u32) -> Sketch {
        let mut s = [0u32; 8];
        for (i, f) in s.iter_mut().enumerate() {
            *f = base + i as u32;
        }
        s
    }

    #[test]
    fn probe_finds_an_indexed_source() {
        let mut idx = SketchIndex::new();
        let e = data_entry(1, Some(sketch_from(100)), 8);
        assert!(idx.insert_entry(&e));

        let found = idx.candidates(&sketch_from(100), 4);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].hash, e.hash);
        assert_eq!(
            found[0].shared, 8,
            "an identical sketch shares every feature"
        );
        assert_eq!(found[0].raw_len, 8 * 4096);
    }

    #[test]
    fn entries_without_a_sketch_are_not_sources() {
        let mut idx = SketchIndex::new();
        assert!(!idx.insert_entry(&data_entry(1, None, 8)));
        assert!(idx.is_empty());
        assert!(idx.candidates(&sketch_from(100), 4).is_empty());
    }

    #[test]
    fn non_data_kinds_are_not_sources() {
        let mut idx = SketchIndex::new();
        let mut e = SegmentEntry::new_dedup_ref(blake3::hash(b"ref"), 0, 1);
        e.sketch = Some(sketch_from(100));
        assert!(!idx.insert_entry(&e));
        assert!(idx.is_empty());
    }

    #[test]
    fn candidates_rank_by_shared_features() {
        let mut idx = SketchIndex::new();
        // Overlap with sketch_from(100) is 8, 6 and 2 features respectively.
        let close = data_entry(1, Some(sketch_from(100)), 8);
        let mid = data_entry(2, Some(sketch_from(102)), 8);
        let far = data_entry(3, Some(sketch_from(106)), 8);
        for e in [&far, &mid, &close] {
            assert!(idx.insert_entry(e));
        }

        let found = idx.candidates(&sketch_from(100), 8);
        assert_eq!(found.len(), 3);
        assert_eq!(found[0].hash, close.hash);
        assert_eq!(found[0].shared, 8);
        assert_eq!(found[1].hash, mid.hash);
        assert_eq!(found[1].shared, 6);
        assert_eq!(found[2].hash, far.hash);
        assert_eq!(found[2].shared, 2);
    }

    #[test]
    fn limit_keeps_the_best_candidates() {
        let mut idx = SketchIndex::new();
        let close = data_entry(1, Some(sketch_from(100)), 8);
        let mid = data_entry(2, Some(sketch_from(102)), 8);
        let far = data_entry(3, Some(sketch_from(106)), 8);
        for e in [&far, &mid, &close] {
            assert!(idx.insert_entry(e));
        }

        let found = idx.candidates(&sketch_from(100), 2);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].hash, close.hash);
        assert_eq!(found[1].hash, mid.hash);
    }

    #[test]
    fn a_disjoint_sketch_finds_nothing() {
        let mut idx = SketchIndex::new();
        assert!(idx.insert_entry(&data_entry(1, Some(sketch_from(100)), 8)));
        assert!(idx.candidates(&sketch_from(500), 4).is_empty());
    }

    #[test]
    fn zero_limit_probes_nothing() {
        let mut idx = SketchIndex::new();
        assert!(idx.insert_entry(&data_entry(1, Some(sketch_from(100)), 8)));
        assert!(idx.candidates(&sketch_from(100), 0).is_empty());
    }

    #[test]
    fn one_hash_yields_one_candidate() {
        let mut idx = SketchIndex::new();
        // The same content reachable from two segments: distinct sketches
        // both overlapping the target, one hash.
        let mut a = data_entry(1, Some(sketch_from(100)), 8);
        let mut b = a.clone();
        b.sketch = Some(sketch_from(104));
        a.sketch = Some(sketch_from(100));
        assert!(idx.insert_entry(&a));
        assert!(idx.insert_entry(&b));

        let found = idx.candidates(&sketch_from(100), 8);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].hash, a.hash);
    }

    #[test]
    fn a_feature_holds_at_most_the_cap() {
        let mut idx = SketchIndex::new();
        // Every entry shares feature 7 and nothing else, so the cap is
        // the only thing bounding the posting list.
        let shared = 7u32;
        for i in 0..(CAP_PER_FEATURE as u32 + 20) {
            let mut sk = [0u32; 8];
            sk[0] = shared;
            for (j, f) in sk.iter_mut().enumerate().skip(1) {
                *f = 1_000 + i * 8 + j as u32;
            }
            let mut e = data_entry(1, Some(sk), 1);
            e.hash = blake3::hash(&i.to_le_bytes());
            assert!(idx.insert_entry(&e));
        }

        let mut probe = [0u32; 8];
        probe[0] = shared;
        for (j, f) in probe.iter_mut().enumerate().skip(1) {
            *f = 900_000 + j as u32;
        }
        let found = idx.candidates(&probe, usize::MAX);
        assert_eq!(found.len(), CAP_PER_FEATURE);
        assert!(found.iter().all(|c| c.shared == 1));
    }

    #[test]
    fn growth_preserves_every_posting() {
        let mut idx = SketchIndex::new();
        // Enough distinct sources to force several doublings.
        let n = (MIN_CAPACITY * 2) as u32;
        let mut hashes = Vec::new();
        for i in 0..n {
            let mut e = data_entry(1, Some(sketch_from(10_000 + i * 8)), 1);
            e.hash = blake3::hash(&i.to_le_bytes());
            hashes.push(e.hash);
            assert!(idx.insert_entry(&e));
        }
        assert!(
            idx.slots.len() > MIN_CAPACITY,
            "fixture must have forced growth"
        );
        assert_eq!(idx.postings(), n as usize * 8);
        assert_eq!(idx.len(), n as usize);

        // Every source is still reachable by its own sketch.
        for (i, hash) in hashes.iter().enumerate() {
            let found = idx.candidates(&sketch_from(10_000 + i as u32 * 8), 1);
            assert_eq!(found.len(), 1, "source {i} lost");
            assert_eq!(found[0].hash, *hash);
            assert_eq!(found[0].shared, 8);
        }
    }

    #[test]
    fn a_repeated_registration_costs_slots_but_not_candidates() {
        let mut idx = SketchIndex::new();
        let e = data_entry(1, Some(sketch_from(100)), 8);
        assert!(idx.insert_entry(&e));
        let postings = idx.postings();

        // Sources are per registration, so the same entry twice takes a
        // second source slot. The probe collapses them by hash, so the cost
        // is slots rather than wasted dictionary attempts.
        assert!(idx.insert_entry(&e));
        assert_eq!(idx.postings(), postings * 2);
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.candidates(&sketch_from(100), 8).len(), 1);
    }

    #[test]
    fn a_repeated_feature_is_counted_once() {
        let mut idx = SketchIndex::new();
        // Two permutations landing on the same value is rare but legal, and
        // must not inflate the source's apparent resemblance.
        let mut sk = sketch_from(100);
        sk[3] = sk[0];
        let mut e = data_entry(1, Some(sk), 1);
        e.sketch = Some(sk);
        assert!(idx.insert_entry(&e));
        assert_eq!(idx.postings(), 7, "the repeat places no second posting");

        let found = idx.candidates(&sk, 4);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].shared, 7, "counted once, not twice");
    }

    #[test]
    fn memory_is_reported() {
        let mut idx = SketchIndex::new();
        assert_eq!(
            idx.memory_bytes(),
            MIN_CAPACITY * 8,
            "an empty map is its slot table"
        );
        assert!(idx.insert_entry(&data_entry(1, Some(sketch_from(100)), 8)));
        assert!(idx.memory_bytes() > MIN_CAPACITY * 8);
    }
}
