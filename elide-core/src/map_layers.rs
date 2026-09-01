//! The volume's maps as layers: a large `base`, and a small `delta` that
//! holds the open WAL's writes. Reads resolve `delta`, then `base`. A
//! mutation of `base` absorbs `delta` first, so iteration always runs over
//! one map (`docs/design/epoch-applies.md`).

use std::sync::Arc;

use ulid::Ulid;

use crate::extentindex::{DeltaLocation, ExtentIndex, ExtentLocation, SegmentPresence};
use crate::lbamap::{ExtentRead, LbaMap};

/// One layer: an LBA map and the extent index that resolves its hashes.
#[derive(Clone)]
pub struct Maps {
    pub lbamap: Arc<LbaMap>,
    pub extent_index: Arc<ExtentIndex>,
}

impl Maps {
    pub fn new(lbamap: LbaMap, extent_index: ExtentIndex) -> Self {
        Self {
            lbamap: Arc::new(lbamap),
            extent_index: Arc::new(extent_index),
        }
    }

    pub fn empty() -> Self {
        Self::new(LbaMap::new(), ExtentIndex::new())
    }

    fn is_empty(&self) -> bool {
        self.lbamap.is_empty()
            && self.extent_index.is_empty()
            && self.extent_index.journal_is_empty()
    }
}

impl Default for Maps {
    fn default() -> Self {
        Self::empty()
    }
}

/// `base` under `delta`. `delta` holds body locations in the open WAL and
/// the claims those writes made; every other kind of entry lives in `base`.
#[derive(Clone)]
pub struct MapLayers {
    base: Maps,
    delta: Maps,
}

impl MapLayers {
    pub fn new(base: Maps) -> Self {
        Self {
            base,
            delta: Maps::empty(),
        }
    }

    pub fn delta_is_empty(&self) -> bool {
        self.delta.is_empty()
    }

    /// The base layer alone. Segment presence lives only here, so a
    /// presence probe reads it without a fold.
    pub fn base(&self) -> &Maps {
        &self.base
    }

    /// The extents that cover `[start_lba, end_lba)`, in LBA order, each
    /// taken from the topmost layer that covers its sub-range.
    pub fn extents_in_range(&self, start_lba: u64, end_lba: u64) -> Vec<ExtentRead> {
        let mut out = Vec::new();
        overlay(
            &[&self.delta.lbamap, &self.base.lbamap],
            start_lba,
            end_lba,
            &mut out,
        );
        out
    }

    /// [`LbaMap::has_full_match`] on the topmost layer that covers any part
    /// of the range. A partial cover in `delta` answers for the range, so a
    /// match in `base` under it reads as no match.
    pub fn has_full_match(&self, start_lba: u64, lba_length: u32, hash: &blake3::Hash) -> bool {
        let end_lba = start_lba + lba_length as u64;
        if self
            .delta
            .lbamap
            .extents_in_range(start_lba, end_lba)
            .next()
            .is_some()
        {
            return self
                .delta
                .lbamap
                .has_full_match(start_lba, lba_length, hash);
        }
        self.base.lbamap.has_full_match(start_lba, lba_length, hash)
    }

    pub fn lookup_extent(&self, hash: &blake3::Hash) -> Option<&ExtentLocation> {
        self.delta
            .extent_index
            .lookup(hash)
            .or_else(|| self.base.extent_index.lookup(hash))
    }

    pub fn lookup_journal(&self, segment: Ulid, hash: &blake3::Hash) -> Option<&ExtentLocation> {
        self.delta
            .extent_index
            .lookup_journal(segment, hash)
            .or_else(|| self.base.extent_index.lookup_journal(segment, hash))
    }

    pub fn lookup_delta(&self, hash: &blake3::Hash) -> Option<&DeltaLocation> {
        self.delta
            .extent_index
            .lookup_delta(hash)
            .or_else(|| self.base.extent_index.lookup_delta(hash))
    }

    pub fn journal_is_empty(&self) -> bool {
        self.delta.extent_index.journal_is_empty() && self.base.extent_index.journal_is_empty()
    }

    pub fn segment_presence(&self, segment: Ulid) -> Option<&Arc<SegmentPresence>> {
        self.delta
            .extent_index
            .segment_presence(segment)
            .or_else(|| self.base.extent_index.segment_presence(segment))
    }

    /// The write path's target.
    pub fn delta_lbamap_mut(&mut self) -> &mut LbaMap {
        Arc::make_mut(&mut self.delta.lbamap)
    }

    /// The write path's target.
    pub fn delta_extent_index_mut(&mut self) -> &mut ExtentIndex {
        Arc::make_mut(&mut self.delta.extent_index)
    }

    /// Fold `delta` into `base` and leave `delta` empty.
    pub fn absorb(&mut self) {
        if self.delta.is_empty() {
            return;
        }
        let delta = std::mem::take(&mut self.delta);
        fold(&mut self.base, &delta);
    }

    /// `base`'s LBA map for mutation, with `delta` absorbed first.
    pub fn lbamap_mut(&mut self) -> &mut LbaMap {
        self.absorb();
        Arc::make_mut(&mut self.base.lbamap)
    }

    /// `base`'s extent index for mutation, with `delta` absorbed first.
    pub fn extent_index_mut(&mut self) -> &mut ExtentIndex {
        self.absorb();
        Arc::make_mut(&mut self.base.extent_index)
    }

    /// Both of `base`'s maps for mutation, with `delta` absorbed first.
    pub fn base_mut(&mut self) -> (&mut LbaMap, &mut ExtentIndex) {
        self.absorb();
        (
            Arc::make_mut(&mut self.base.lbamap),
            Arc::make_mut(&mut self.base.extent_index),
        )
    }

    /// One map with `delta` folded in. Two handle clones when `delta` is
    /// empty, otherwise a fold into a clone of `base`. `self` is unchanged.
    pub fn materialised(&self) -> Maps {
        if self.delta.is_empty() {
            return self.base.clone();
        }
        let mut maps = self.base.clone();
        fold(&mut maps, &self.delta);
        maps
    }

    /// Put `base` back to `pre`, a value [`Self::materialised`] returned
    /// after an absorb. `delta` is empty across a mutation and its rollback,
    /// which both run under one hold of the volume mutex.
    pub fn restore(&mut self, pre: Maps) {
        debug_assert!(self.delta.is_empty(), "restore with a populated delta");
        self.base = pre;
    }
}

/// Replay `delta`'s entries over `base`. The entries are disjoint and are
/// the net of the writes that produced them, so the replay equals the writes.
fn fold(base: &mut Maps, delta: &Maps) {
    let lbamap = Arc::make_mut(&mut base.lbamap);
    for (lba, len, hash, payload_block_offset, claimant) in
        delta.lbamap.iter_entries_with_claimant()
    {
        lbamap.insert_with_offset(lba, len, payload_block_offset, hash, claimant);
    }
    let index = Arc::make_mut(&mut base.extent_index);
    for (hash, location) in delta.extent_index.iter() {
        index.insert_if_absent(*hash, location.clone());
    }
    for ((segment, hash), location) in delta.extent_index.journal_iter() {
        index.insert_journal_if_absent(segment, hash, location.clone());
    }
    debug_assert!(
        delta.extent_index.deltas_iter().next().is_none(),
        "the delta layer holds Delta locations"
    );
}

/// Emit the extents of `[start, end)` from `layers[0]`, and fill each gap it
/// leaves from the layers under it.
fn overlay(layers: &[&Arc<LbaMap>], start: u64, end: u64, out: &mut Vec<ExtentRead>) {
    let Some((top, rest)) = layers.split_first() else {
        return;
    };
    let mut cursor = start;
    for extent in top.extents_in_range(start, end) {
        if extent.range_start > cursor {
            overlay(rest, cursor, extent.range_start, out);
        }
        cursor = extent.range_end;
        out.push(extent);
    }
    if cursor < end {
        overlay(rest, cursor, end, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(n: u8) -> blake3::Hash {
        blake3::hash(&[n])
    }

    fn seg(n: u64) -> Ulid {
        Ulid::from_parts(n, n as u128)
    }

    fn reads(v: &[ExtentRead]) -> Vec<(u64, u64, blake3::Hash, u32)> {
        v.iter()
            .map(|x| (x.range_start, x.range_end, x.hash, x.payload_block_offset))
            .collect()
    }

    #[test]
    fn delta_masks_base_and_base_fills_the_gaps() {
        let mut base = LbaMap::new();
        base.insert(0, 100, h(1), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        layers.delta_lbamap_mut().insert(30, 20, h(2), seg(2));

        assert_eq!(
            reads(&layers.extents_in_range(0, 100)),
            vec![(0, 30, h(1), 0), (30, 50, h(2), 0), (50, 100, h(1), 50)]
        );
        assert_eq!(
            reads(&layers.extents_in_range(40, 60)),
            vec![(40, 50, h(2), 10), (50, 60, h(1), 50)]
        );
        assert_eq!(
            reads(&layers.extents_in_range(100, 120)),
            Vec::<(u64, u64, blake3::Hash, u32)>::new()
        );
    }

    #[test]
    fn gaps_in_both_layers_stay_gaps() {
        let mut base = LbaMap::new();
        base.insert(10, 10, h(1), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        layers.delta_lbamap_mut().insert(40, 10, h(2), seg(2));

        assert_eq!(
            reads(&layers.extents_in_range(0, 60)),
            vec![(10, 20, h(1), 0), (40, 50, h(2), 0)]
        );
    }

    #[test]
    fn full_match_answers_from_the_topmost_covering_layer() {
        let mut base = LbaMap::new();
        base.insert(0, 4, h(1), seg(1));
        base.insert(8, 4, h(3), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        layers.delta_lbamap_mut().insert(1, 1, h(2), seg(2));
        layers.delta_lbamap_mut().insert(16, 4, h(4), seg(2));

        assert!(
            !layers.has_full_match(0, 4, &h(1)),
            "a partial delta cover masks base"
        );
        assert!(
            layers.has_full_match(8, 4, &h(3)),
            "base answers with no delta cover"
        );
        assert!(
            layers.has_full_match(16, 4, &h(4)),
            "delta answers its own full match"
        );
        assert!(!layers.has_full_match(16, 2, &h(4)));
    }

    struct Lcg(u64);

    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0 >> 33
        }
    }

    fn entries(m: &LbaMap) -> Vec<(u64, u32, blake3::Hash, u32, Ulid)> {
        m.iter_entries_with_claimant().collect()
    }

    #[test]
    fn absorb_equals_the_writes_applied_to_one_map() {
        let mut lcg = Lcg(7);
        let mut single = LbaMap::new();
        let mut base = LbaMap::new();
        for _ in 0..200 {
            let lba = lcg.next() % 64;
            let len = 1 + (lcg.next() % 4) as u32;
            let hash = h((lcg.next() % 16) as u8);
            single.insert(lba, len, hash, seg(1));
            base.insert(lba, len, hash, seg(1));
        }
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        for _ in 0..200 {
            let lba = lcg.next() % 64;
            let len = 1 + (lcg.next() % 4) as u32;
            let hash = h((lcg.next() % 16) as u8);
            single.insert(lba, len, hash, seg(2));
            layers.delta_lbamap_mut().insert(lba, len, hash, seg(2));
        }
        assert!(!layers.delta_is_empty());

        let materialised = layers.materialised();
        assert!(
            !layers.delta_is_empty(),
            "materialised leaves the layers alone"
        );
        assert_eq!(entries(&materialised.lbamap), entries(&single));

        layers.absorb();
        assert!(layers.delta_is_empty());
        let absorbed = layers.materialised();
        assert_eq!(entries(&absorbed.lbamap), entries(&single));
        for n in 0..16u8 {
            assert_eq!(
                absorbed.lbamap.claim_refcount(&h(n)),
                single.claim_refcount(&h(n)),
                "claim count for hash {n}"
            );
        }
        assert_eq!(reads(&layers.extents_in_range(0, 64)), {
            let v: Vec<ExtentRead> = single.extents_in_range(0, 64).collect();
            reads(&v)
        });
    }

    #[test]
    fn restore_puts_base_back() {
        let mut base = LbaMap::new();
        base.insert(0, 4, h(1), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        layers.delta_lbamap_mut().insert(8, 4, h(2), seg(2));

        layers.absorb();
        let pre = layers.materialised();
        layers.lbamap_mut().insert(0, 4, h(3), seg(3));
        assert!(layers.has_full_match(0, 4, &h(3)));

        layers.restore(pre);
        assert!(layers.has_full_match(0, 4, &h(1)));
        assert!(layers.has_full_match(8, 4, &h(2)));
        assert!(layers.delta_is_empty());
    }
}
