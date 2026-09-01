//! The volume's maps as layers: a large `base`, frozen layers that each hold
//! one WAL epoch a promote is in the middle of committing, and a small
//! `delta` that holds the open WAL's writes. Reads resolve `delta`, then the
//! frozen layers newest first, then `base`. A mutation of `base` absorbs every
//! layer first, so iteration always runs over one map
//! (`docs/design/epoch-applies.md`).

use std::io;
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

/// One WAL epoch between its promote's freeze and swap.
#[derive(Clone)]
struct FrozenLayer {
    wal_ulid: Ulid,
    maps: Maps,
}

/// `base` under the frozen layers under `delta`. `delta` and the frozen
/// layers hold body locations in a WAL and the claims those writes made;
/// every other kind of entry lives in `base`.
#[derive(Clone)]
pub struct MapLayers {
    base: Maps,
    /// Oldest first.
    frozen: Vec<FrozenLayer>,
    delta: Maps,
}

impl MapLayers {
    pub fn new(base: Maps) -> Self {
        Self {
            base,
            frozen: Vec::new(),
            delta: Maps::empty(),
        }
    }

    pub fn delta_is_empty(&self) -> bool {
        self.delta.is_empty()
    }

    pub fn frozen_depth(&self) -> usize {
        self.frozen.len()
    }

    /// The base layer alone. Segment presence lives only here, so a
    /// presence probe reads it without a fold.
    pub fn base(&self) -> &Maps {
        &self.base
    }

    /// The layers above `base`, newest first.
    fn upper(&self) -> impl Iterator<Item = &Maps> {
        std::iter::once(&self.delta).chain(self.frozen.iter().rev().map(|l| &l.maps))
    }

    /// Every layer, newest first.
    fn all(&self) -> impl Iterator<Item = &Maps> {
        self.upper().chain(std::iter::once(&self.base))
    }

    /// The extents that cover `[start_lba, end_lba)`, in LBA order, each
    /// taken from the topmost layer that covers its sub-range.
    pub fn extents_in_range(&self, start_lba: u64, end_lba: u64) -> Vec<ExtentRead> {
        let layers: Vec<&Arc<LbaMap>> = self.all().map(|m| &m.lbamap).collect();
        let mut out = Vec::new();
        overlay(&layers, start_lba, end_lba, &mut out);
        out
    }

    /// [`LbaMap::has_full_match`] on the topmost layer that covers any part
    /// of the range. A partial cover in an upper layer answers for the
    /// range, so a match in a layer under it reads as no match.
    pub fn has_full_match(&self, start_lba: u64, lba_length: u32, hash: &blake3::Hash) -> bool {
        let end_lba = start_lba + lba_length as u64;
        for layer in self.upper() {
            if layer
                .lbamap
                .extents_in_range(start_lba, end_lba)
                .next()
                .is_some()
            {
                return layer.lbamap.has_full_match(start_lba, lba_length, hash);
            }
        }
        self.base.lbamap.has_full_match(start_lba, lba_length, hash)
    }

    pub fn lookup_extent(&self, hash: &blake3::Hash) -> Option<&ExtentLocation> {
        self.all().find_map(|m| m.extent_index.lookup(hash))
    }

    pub fn lookup_journal(&self, segment: Ulid, hash: &blake3::Hash) -> Option<&ExtentLocation> {
        self.all()
            .find_map(|m| m.extent_index.lookup_journal(segment, hash))
    }

    pub fn lookup_delta(&self, hash: &blake3::Hash) -> Option<&DeltaLocation> {
        self.all().find_map(|m| m.extent_index.lookup_delta(hash))
    }

    pub fn journal_is_empty(&self) -> bool {
        self.all().all(|m| m.extent_index.journal_is_empty())
    }

    pub fn segment_presence(&self, segment: Ulid) -> Option<&Arc<SegmentPresence>> {
        self.base.extent_index.segment_presence(segment)
    }

    /// The write path's target.
    pub fn delta_lbamap_mut(&mut self) -> &mut LbaMap {
        Arc::make_mut(&mut self.delta.lbamap)
    }

    /// The write path's target.
    pub fn delta_extent_index_mut(&mut self) -> &mut ExtentIndex {
        Arc::make_mut(&mut self.delta.extent_index)
    }

    /// Close the open WAL's epoch: `delta` becomes a frozen layer tagged
    /// `wal_ulid`, and a fresh `delta` receives the next epoch's writes.
    pub fn freeze(&mut self, wal_ulid: Ulid) {
        if self.delta.is_empty() {
            return;
        }
        let maps = std::mem::take(&mut self.delta);
        self.frozen.push(FrozenLayer { wal_ulid, maps });
    }

    /// Fold every frozen layer, oldest first, then `delta`, into `base`,
    /// and leave both empty.
    pub fn absorb(&mut self) {
        for layer in self.frozen.drain(..) {
            fold(&mut self.base, &layer.maps);
        }
        if self.delta.is_empty() {
            return;
        }
        let delta = std::mem::take(&mut self.delta);
        fold(&mut self.base, &delta);
    }

    /// `base`'s LBA map for mutation, with every layer absorbed first.
    pub fn lbamap_mut(&mut self) -> &mut LbaMap {
        self.absorb();
        Arc::make_mut(&mut self.base.lbamap)
    }

    /// `base`'s extent index for mutation, with every layer absorbed first.
    pub fn extent_index_mut(&mut self) -> &mut ExtentIndex {
        self.absorb();
        Arc::make_mut(&mut self.base.extent_index)
    }

    /// Both of `base`'s maps for mutation, with every layer absorbed first.
    pub fn base_mut(&mut self) -> (&mut LbaMap, &mut ExtentIndex) {
        self.absorb();
        (
            Arc::make_mut(&mut self.base.lbamap),
            Arc::make_mut(&mut self.base.extent_index),
        )
    }

    /// One map with every layer folded in. Two handle clones when the
    /// layers are empty, otherwise a fold into a clone of `base`. `self` is
    /// unchanged.
    pub fn materialised(&self) -> Maps {
        if self.frozen.is_empty() && self.delta.is_empty() {
            return self.base.clone();
        }
        let mut maps = self.base.clone();
        for layer in &self.frozen {
            fold(&mut maps, &layer.maps);
        }
        if !self.delta.is_empty() {
            fold(&mut maps, &self.delta);
        }
        maps
    }

    /// A promote's fold: a clone of `base` with the layer tagged `wal_ulid`
    /// replayed into it, then `apply` run over the clone. `self` is
    /// unchanged, so the caller runs this with the volume mutex released.
    /// A layer an earlier absorb already folded is in `base`, so the
    /// replay is a no-op and `apply` finds its locations there.
    pub fn fold_promote(
        &self,
        wal_ulid: Ulid,
        apply: impl FnOnce(&mut LbaMap, &mut ExtentIndex) -> io::Result<()>,
    ) -> io::Result<Maps> {
        let mut maps = self.base.clone();
        if let Some(layer) = self.frozen.iter().find(|l| l.wal_ulid == wal_ulid) {
            fold(&mut maps, &layer.maps);
        }
        apply(
            Arc::make_mut(&mut maps.lbamap),
            Arc::make_mut(&mut maps.extent_index),
        )?;
        Ok(maps)
    }

    /// Install a promote's fold as `base` and retire its frozen layer.
    pub fn swap_promote(&mut self, folded_from: &Maps, new_base: Maps, wal_ulid: Ulid) {
        self.swap_base(folded_from, new_base);
        self.frozen.retain(|l| l.wal_ulid != wal_ulid);
    }

    /// A base-only apply's fold: `apply` run over a clone of `base`. `self`
    /// is unchanged, so the caller runs this with the volume mutex released.
    /// The layers above `base` hold WAL locations and the claims of the
    /// writes that made them, so an apply that re-points or registers
    /// segment locations finds every entry it acts on in `base`.
    pub fn fold_base(
        &self,
        apply: impl FnOnce(&mut LbaMap, &mut ExtentIndex) -> io::Result<()>,
    ) -> io::Result<Maps> {
        let mut maps = self.base.clone();
        apply(
            Arc::make_mut(&mut maps.lbamap),
            Arc::make_mut(&mut maps.extent_index),
        )?;
        Ok(maps)
    }

    /// Install a fold as `base`. The layers above it stay.
    ///
    /// `folded_from` is the `base` the fold started from. The actor is the
    /// only mutator of `base`, and it runs the fold and this swap on its own
    /// thread with no other apply between them, so the two are the same
    /// handles; the assertion states that invariant.
    pub fn swap_base(&mut self, folded_from: &Maps, new_base: Maps) {
        debug_assert!(
            Arc::ptr_eq(&self.base.lbamap, &folded_from.lbamap)
                && Arc::ptr_eq(&self.base.extent_index, &folded_from.extent_index),
            "base moved between a fold and its swap"
        );
        self.base = new_base;
    }

    /// The fold for an apply whose admission is ULID order: a clone of
    /// `base` with every frozen layer below `ulid` replayed in, oldest
    /// first, then `apply` run over the clone. A claim in a layer above
    /// `ulid` is newer than the apply's output and masks it, which is the
    /// order the rebuild from disk gives the two. `self` is unchanged, so
    /// the caller runs this with the volume mutex released.
    pub fn fold_below(
        &self,
        ulid: Ulid,
        apply: impl FnOnce(&mut LbaMap, &mut ExtentIndex) -> io::Result<()>,
    ) -> io::Result<Maps> {
        let mut maps = self.base.clone();
        for layer in self.frozen.iter().filter(|l| l.wal_ulid < ulid) {
            fold(&mut maps, &layer.maps);
        }
        apply(
            Arc::make_mut(&mut maps.lbamap),
            Arc::make_mut(&mut maps.extent_index),
        )?;
        Ok(maps)
    }

    /// Install a [`Self::fold_below`] as `base` and retire the layers it
    /// replayed. A promote whose layer retires here still folds and swaps:
    /// its replay finds the layer gone and its locations in `base`.
    pub fn swap_below(&mut self, folded_from: &Maps, new_base: Maps, ulid: Ulid) {
        self.swap_base(folded_from, new_base);
        self.frozen.retain(|l| l.wal_ulid >= ulid);
    }

    /// The layers above `ulid` over `base`: how a [`Self::fold_below`]
    /// resolves under the writes that landed after the apply's prep.
    pub fn above(&self, ulid: Ulid, base: Maps) -> Self {
        Self {
            base,
            frozen: self
                .frozen
                .iter()
                .filter(|l| l.wal_ulid >= ulid)
                .cloned()
                .collect(),
            delta: self.delta.clone(),
        }
    }

    /// Put `base` back to `pre`, a value [`Self::materialised`] returned
    /// after an absorb. The layers are empty across a mutation and its
    /// rollback, which both run under one hold of the volume mutex.
    pub fn restore(&mut self, pre: Maps) {
        debug_assert!(
            self.frozen.is_empty() && self.delta.is_empty(),
            "restore with populated layers"
        );
        self.base = pre;
    }
}

/// Replay `layer`'s entries over `base`. The entries are disjoint and are
/// the net of the writes that produced them, so the replay equals the writes.
fn fold(base: &mut Maps, layer: &Maps) {
    let lbamap = Arc::make_mut(&mut base.lbamap);
    for (lba, len, hash, payload_block_offset, claimant) in
        layer.lbamap.iter_entries_with_claimant()
    {
        lbamap.insert_with_offset(lba, len, payload_block_offset, hash, claimant);
    }
    let index = Arc::make_mut(&mut base.extent_index);
    for (hash, location) in layer.extent_index.iter() {
        index.insert_if_absent(*hash, location.clone());
    }
    for ((segment, hash), location) in layer.extent_index.journal_iter() {
        index.insert_journal_if_absent(segment, hash, location.clone());
    }
    debug_assert!(
        layer.extent_index.deltas_iter().next().is_none(),
        "an upper layer holds Delta locations"
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
    use crate::segment::{Codec, EntryKind, SegmentEntry};

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

    fn entries(m: &LbaMap) -> Vec<(u64, u32, blake3::Hash, u32, Ulid)> {
        m.iter_entries_with_claimant().collect()
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

    #[test]
    fn frozen_layers_sit_between_delta_and_base_newest_first() {
        let mut base = LbaMap::new();
        base.insert(0, 8, h(1), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));

        layers.delta_lbamap_mut().insert(2, 2, h(2), seg(10));
        layers.freeze(seg(10));
        layers.delta_lbamap_mut().insert(3, 2, h(3), seg(11));
        layers.freeze(seg(11));
        layers.delta_lbamap_mut().insert(6, 1, h(4), seg(12));
        assert_eq!(layers.frozen_depth(), 2);

        assert_eq!(
            reads(&layers.extents_in_range(0, 8)),
            vec![
                (0, 2, h(1), 0),
                (2, 3, h(2), 0),
                (3, 5, h(3), 0),
                (5, 6, h(1), 5),
                (6, 7, h(4), 0),
                (7, 8, h(1), 7),
            ]
        );
        assert!(layers.has_full_match(6, 1, &h(4)));
        assert!(
            !layers.has_full_match(2, 2, &h(2)),
            "the newer layer covers part"
        );

        let single = layers.materialised();
        assert_eq!(
            reads(&single.lbamap.extents_in_range(0, 8).collect::<Vec<_>>()),
            reads(&layers.extents_in_range(0, 8))
        );
    }

    #[test]
    fn an_empty_delta_freezes_nothing() {
        let mut layers = MapLayers::new(Maps::empty());
        layers.freeze(seg(10));
        assert_eq!(layers.frozen_depth(), 0);
    }

    #[test]
    fn fold_promote_replays_one_layer_and_swap_retires_it() {
        let mut base = LbaMap::new();
        base.insert(0, 8, h(1), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        layers.delta_lbamap_mut().insert(2, 2, h(2), seg(10));
        layers.freeze(seg(10));
        layers.delta_lbamap_mut().insert(4, 2, h(3), seg(11));
        layers.freeze(seg(11));
        layers.delta_lbamap_mut().insert(6, 1, h(4), seg(12));

        let folded_from = layers.base().clone();
        let new_base = layers
            .fold_promote(seg(10), |lbamap, _index| {
                assert_eq!(lbamap.set_claimant_if_matches(2, 2, h(2), seg(20)), 1);
                assert_eq!(
                    lbamap.set_claimant_if_matches(4, 2, h(3), seg(20)),
                    0,
                    "the other frozen layer is outside this fold"
                );
                Ok(())
            })
            .unwrap();
        assert_eq!(
            layers.base().lbamap.claimant_at(2),
            Some(seg(1)),
            "the fold leaves the live base alone"
        );

        layers.swap_promote(&folded_from, new_base, seg(10));
        assert_eq!(layers.frozen_depth(), 1);
        assert_eq!(layers.base().lbamap.claimant_at(2), Some(seg(20)));
        assert_eq!(
            reads(&layers.extents_in_range(0, 8)),
            vec![
                (0, 2, h(1), 0),
                (2, 4, h(2), 0),
                (4, 6, h(3), 0),
                (6, 7, h(4), 0),
                (7, 8, h(1), 7),
            ]
        );

        layers.absorb();
        assert_eq!(layers.frozen_depth(), 0);
        assert!(layers.delta_is_empty());
        assert_eq!(layers.base().lbamap.claimant_at(4), Some(seg(11)));
        assert_eq!(layers.base().lbamap.claimant_at(6), Some(seg(12)));
    }

    #[test]
    fn a_layer_an_absorb_took_still_folds_and_swaps() {
        let mut layers = MapLayers::new(Maps::empty());
        layers.delta_lbamap_mut().insert(0, 4, h(1), seg(10));
        layers.freeze(seg(10));
        layers.lbamap_mut().insert(8, 1, h(2), seg(30));
        assert_eq!(layers.frozen_depth(), 0);

        let folded_from = layers.base().clone();
        let new_base = layers
            .fold_promote(seg(10), |lbamap, _| {
                assert_eq!(lbamap.set_claimant_if_matches(0, 4, h(1), seg(20)), 1);
                Ok(())
            })
            .unwrap();
        layers.swap_promote(&folded_from, new_base, seg(10));
        assert_eq!(layers.base().lbamap.claimant_at(0), Some(seg(20)));
        assert_eq!(layers.base().lbamap.claimant_at(8), Some(seg(30)));
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
        for epoch in 2..5u64 {
            for _ in 0..100 {
                let lba = lcg.next() % 64;
                let len = 1 + (lcg.next() % 4) as u32;
                let hash = h((lcg.next() % 16) as u8);
                single.insert(lba, len, hash, seg(epoch));
                layers.delta_lbamap_mut().insert(lba, len, hash, seg(epoch));
            }
            if epoch < 4 {
                layers.freeze(seg(epoch));
            }
        }
        assert_eq!(layers.frozen_depth(), 2);
        assert!(!layers.delta_is_empty());

        let materialised = layers.materialised();
        assert_eq!(
            layers.frozen_depth(),
            2,
            "materialised leaves the layers alone"
        );
        assert_eq!(entries(&materialised.lbamap), entries(&single));
        assert_eq!(reads(&layers.extents_in_range(0, 64)), {
            let v: Vec<ExtentRead> = single.extents_in_range(0, 64).collect();
            reads(&v)
        });

        layers.absorb();
        assert!(layers.delta_is_empty());
        assert_eq!(layers.frozen_depth(), 0);
        let absorbed = layers.materialised();
        assert_eq!(entries(&absorbed.lbamap), entries(&single));
        for n in 0..16u8 {
            assert_eq!(
                absorbed.lbamap.claim_refcount(&h(n)),
                single.claim_refcount(&h(n)),
                "claim count for hash {n}"
            );
        }
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

    #[test]
    fn a_base_fold_swaps_under_the_layers() {
        let mut base = LbaMap::new();
        base.insert(0, 8, h(1), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        layers.delta_lbamap_mut().insert(0, 2, h(2), seg(10));
        layers.freeze(seg(10));
        layers.delta_lbamap_mut().insert(6, 2, h(3), seg(11));

        let before = layers.clone();
        let new_base = layers
            .fold_base(|lbamap, _| {
                lbamap.insert(0, 8, h(4), seg(5));
                Ok(())
            })
            .unwrap();
        assert_eq!(
            reads(&layers.extents_in_range(0, 8)),
            reads(&before.extents_in_range(0, 8)),
            "the fold leaves the live layers alone"
        );

        layers.swap_base(before.base(), new_base);
        assert_eq!(layers.frozen_depth(), 1);
        assert!(!layers.delta_is_empty());
        assert_eq!(
            reads(&layers.extents_in_range(0, 8)),
            vec![(0, 2, h(2), 0), (2, 6, h(4), 2), (6, 8, h(3), 0)]
        );
    }

    #[test]
    fn a_fold_below_takes_the_older_layers_and_leaves_the_newer() {
        let mut base = LbaMap::new();
        base.insert(0, 8, h(1), seg(1));
        let mut layers = MapLayers::new(Maps::new(base, ExtentIndex::new()));
        layers.delta_lbamap_mut().insert(0, 2, h(2), seg(10));
        layers.freeze(seg(10));
        layers.delta_lbamap_mut().insert(6, 2, h(3), seg(12));
        layers.freeze(seg(12));
        layers.delta_lbamap_mut().insert(4, 1, h(5), seg(13));

        let run = SegmentEntry {
            hash: h(4),
            start_lba: 0,
            lba_length: 8,
            codec: Codec::None,
            kind: EntryKind::Data,
            stored_offset: 0,
            stored_length: 8 * 4096,
            inline: None,
            delta_options: Vec::new(),
            journal: false,
            sketch: None,
            stored_hash: None,
        };
        let before = layers.clone();
        let new_base = layers
            .fold_below(seg(11), |lbamap, _| {
                assert_eq!(lbamap.claimant_at(0), Some(seg(10)), "layer 10 folded in");
                assert_eq!(lbamap.claimant_at(6), Some(seg(1)), "layer 12 left above");
                assert_eq!(
                    lbamap.register_entry_if_newer(&run, seg(11)),
                    8,
                    "the fold admits over base and layer 10"
                );
                Ok(())
            })
            .unwrap();

        let view = before.above(seg(11), new_base.clone());
        assert_eq!(
            reads(&view.extents_in_range(0, 8)),
            vec![
                (0, 4, h(4), 0),
                (4, 5, h(5), 0),
                (5, 6, h(4), 5),
                (6, 8, h(3), 0)
            ],
            "layers 12 and 13 mask the fold, layer 10 is under it"
        );

        layers.swap_below(before.base(), new_base, seg(11));
        assert_eq!(layers.frozen_depth(), 1, "layer 10 retired, layer 12 stays");
        assert!(!layers.delta_is_empty());
        assert_eq!(
            reads(&layers.extents_in_range(0, 8)),
            reads(&view.extents_in_range(0, 8))
        );
    }
}
