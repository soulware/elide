//! One walk builds both views, so what it produces has to match what two
//! separate walks produce — including the layer-end phase that admits
//! compaction outputs and the ancestor chain that spans layers.

use std::fs;
use std::path::Path;

use elide_core::segment::{self, Codec, SegmentEntry, SegmentSigner, write_segment};
use elide_core::ulid_mint::UlidMint;
use elide_core::{extentindex, lbamap, rebuild, signing};
use tempfile::TempDir;
use ulid::Ulid;

fn body(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut ctr = seed;
    while out.len() < len {
        out.extend_from_slice(blake3::hash(&ctr.to_le_bytes()).as_bytes());
        ctr = ctr.wrapping_add(1);
    }
    out.truncate(len);
    out
}

fn make_volume(dir: &Path) -> std::sync::Arc<dyn SegmentSigner> {
    fs::create_dir_all(segment::pending_open_dir(dir)).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();
    signing::generate_keypair(dir, signing::VOLUME_KEY_FILE, signing::VOLUME_PUB_FILE).unwrap();
    signing::load_signer(dir, signing::VOLUME_KEY_FILE).unwrap()
}

/// Write one segment holding `bodies` as consecutive Data entries starting
/// at `start_lba`, minted at `seg`.
fn write_seg(
    dir: &Path,
    signer: &dyn SegmentSigner,
    seg: Ulid,
    start_lba: u64,
    bodies: &[Vec<u8>],
) {
    let mut lba = start_lba;
    let entries: Vec<_> = bodies
        .iter()
        .map(|b| {
            let hash = blake3::hash(b);
            let blocks = (b.len() / 4096) as u32;
            let e = SegmentEntry::new_data(hash, lba, blocks, Codec::None, b.clone());
            lba += blocks as u64;
            e
        })
        .collect();
    write_segment(
        &segment::pending_open_dir(dir).join(seg.to_string()),
        entries,
        signer,
    )
    .unwrap();
}

/// Both views from two walks, the shape every caller built before one walk
/// served them together.
fn separately(
    chain: &[(std::path::PathBuf, Option<String>)],
) -> (extentindex::ExtentIndex, lbamap::LbaMap, Option<Ulid>) {
    let index = extentindex::rebuild(chain).unwrap();
    let (map, ceiling) = lbamap::rebuild_segments_with_ceiling(chain).unwrap();
    (index, map, ceiling)
}

fn assert_same_views(chain: &[(std::path::PathBuf, Option<String>)]) {
    let (want_index, want_map, want_ceiling) = separately(chain);
    let (got_index, got_map, got_ceiling) = rebuild::rebuild_views(chain).unwrap();

    // Two empty views compare equal, so the comparison below says nothing
    // unless the walk actually loaded something.
    assert!(
        !want_index.is_empty(),
        "extent index has content to compare"
    );
    assert!(!want_map.is_empty(), "lba map has content to compare");
    assert!(want_ceiling.is_some(), "the walk reached a segment");

    assert_eq!(got_ceiling, want_ceiling, "ceiling");

    assert_eq!(got_index.len(), want_index.len(), "extent index size");
    for (hash, loc) in want_index.iter() {
        let other = got_index.lookup(hash).expect("same hashes");
        assert_eq!(other.segment_id, loc.segment_id, "canonical segment");
        assert_eq!(other.body_offset, loc.body_offset, "body offset");
        assert_eq!(other.body_length, loc.body_length, "body length");
    }

    assert_eq!(got_map.len(), want_map.len(), "lba map size");
    let want: Vec<_> = want_map.iter_entries_with_claimant().collect();
    let got: Vec<_> = got_map.iter_entries_with_claimant().collect();
    assert_eq!(got, want, "lba map entries and claimants");
}

#[test]
fn one_walk_matches_two_walks_on_a_flush_tier_volume() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("vol");
    let signer = make_volume(&dir);

    // Monotonic mint: the LBA map admits a flush claim by highest claimant
    // ULID, so the two segments must be ordered.
    let mut mint = UlidMint::new(Ulid::nil());
    let first = mint.next();
    let second = mint.next();

    write_seg(
        &dir,
        signer.as_ref(),
        first,
        0,
        &[body(1, 8192), body(2, 8192)],
    );
    // Overlaps the first segment's opening extent, so the later claimant
    // has to win in both builds.
    write_seg(&dir, signer.as_ref(), second, 0, &[body(3, 8192)]);

    assert_same_views(&[(dir, None)]);
}

#[test]
fn one_walk_matches_two_walks_across_an_ancestor_chain() {
    let tmp = TempDir::new().unwrap();
    let parent = tmp.path().join("parent");
    let child = tmp.path().join("child");
    let parent_signer = make_volume(&parent);
    let child_signer = make_volume(&child);

    let mut mint = UlidMint::new(Ulid::nil());
    let in_parent = mint.next();
    let in_child = mint.next();

    write_seg(
        &parent,
        parent_signer.as_ref(),
        in_parent,
        0,
        &[body(10, 8192)],
    );
    write_seg(
        &child,
        child_signer.as_ref(),
        in_child,
        8,
        &[body(11, 8192)],
    );

    // Ancestor first, matching the order a volume open builds. The layer
    // boundary is what `end_layer` keys off.
    assert_same_views(&[(parent, None), (child, None)]);
}

#[test]
fn one_walk_matches_two_walks_with_a_compaction_output() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("vol");
    let signer = make_volume(&dir);

    let mut mint = UlidMint::new(Ulid::nil());
    let input_a = mint.next();
    let input_b = mint.next();
    let output = mint.next();

    write_seg(&dir, signer.as_ref(), input_a, 0, &[body(30, 8192)]);
    write_seg(&dir, signer.as_ref(), input_b, 2, &[body(31, 8192)]);

    // A recorded inputs list routes this segment to the layer-end phase,
    // where it admits under `AboveHorizon(max(inputs))`.
    let b = body(32, 8192);
    let hash = blake3::hash(&b);
    segment::write_segment_full(
        &segment::pending_open_dir(&dir).join(output.to_string()),
        vec![SegmentEntry::new_data(hash, 0, 2, Codec::None, b)],
        &[],
        &[input_a, input_b],
        false,
        signer.as_ref(),
    )
    .unwrap();

    assert_same_views(&[(dir, None)]);
}

#[test]
fn one_walk_matches_two_walks_with_a_committed_segment() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("vol");
    let signer = make_volume(&dir);

    let mut mint = UlidMint::new(Ulid::nil());
    let committed = mint.next();
    let pending = mint.next();

    // A promoted segment reaches the walk from index/, a fresh one from
    // pending/, so both tiers are in the comparison.
    write_seg(&dir, signer.as_ref(), committed, 0, &[body(20, 8192)]);
    let src = segment::pending_open_dir(&dir).join(committed.to_string());
    fs::rename(&src, dir.join("index").join(format!("{committed}.idx"))).unwrap();

    write_seg(&dir, signer.as_ref(), pending, 2, &[body(21, 8192)]);

    assert_same_views(&[(dir, None)]);
}
