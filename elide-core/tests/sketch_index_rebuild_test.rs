//! The candidate map is harvested from the same walk that rebuilds the
//! extent index, so what it holds has to come off the `.idx` files rather
//! than from anything the writer kept in memory.

use std::fs;
use std::path::Path;

use elide_core::extentindex;
use elide_core::segment::{self, Codec, SegmentEntry, SegmentSigner, write_segment};
use elide_core::signing;
use elide_core::sketch;
use tempfile::TempDir;
use ulid::Ulid;

/// High-entropy bytes, so an extent at the size threshold samples enough
/// windows to be sketched.
fn entropy(seed: u64, len: usize) -> Vec<u8> {
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
    fs::create_dir_all(elide_core::segment::pending_open_dir(&dir)).unwrap();
    fs::create_dir_all(dir.join("index")).unwrap();
    signing::generate_keypair(dir, signing::VOLUME_KEY_FILE, signing::VOLUME_PUB_FILE).unwrap();
    signing::load_signer(dir, signing::VOLUME_KEY_FILE).unwrap()
}

/// Write one segment holding `bodies` as consecutive Data entries.
fn write_segment_with(
    dir: &Path,
    signer: &dyn SegmentSigner,
    bodies: &[Vec<u8>],
) -> (Ulid, Vec<blake3::Hash>) {
    let seg = Ulid::new();
    let mut lba = 0u64;
    let mut hashes = Vec::new();
    let entries: Vec<_> = bodies
        .iter()
        .map(|b| {
            let hash = blake3::hash(b);
            hashes.push(hash);
            let blocks = (b.len() / 4096) as u32;
            let e = SegmentEntry::new_data(hash, lba, blocks, Codec::None, b.clone());
            lba += blocks as u64;
            e
        })
        .collect();
    write_segment(
        &elide_core::segment::pending_open_dir(&dir).join(seg.to_string()),
        entries,
        signer,
    )
    .unwrap();
    (seg, hashes)
}

#[test]
fn rebuild_harvests_sketches_from_disk() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("vol");
    let signer = make_volume(&dir);

    // Two extents at the size threshold, so both are sketched, plus one
    // below it, which the producer leaves unsketched.
    let big_a = entropy(1, sketch::MIN_SKETCH_BYTES);
    let big_b = entropy(2, sketch::MIN_SKETCH_BYTES);
    let small = entropy(3, 8192);
    let (_seg, hashes) = write_segment_with(&dir, signer.as_ref(), &[big_a.clone(), big_b, small]);

    let chain = vec![(dir.clone(), None)];
    let (extents, sketches) = extentindex::rebuild_with_sketches(&chain).unwrap();

    assert_eq!(extents.len(), 3, "every extent is in the extent index");
    assert_eq!(
        sketches.len(),
        2,
        "only the two at-threshold extents are sources"
    );
    assert_eq!(sketches.postings(), 2 * sketch::NUM_FEATURES);

    // The map resolves the target back to its own hash, which is only
    // possible if the sketch came off the `.idx`.
    let target = sketch::compute(&big_a).expect("sketchable");
    let found = sketches.candidates(&target, 4);
    assert_eq!(found[0].hash, hashes[0]);
    assert_eq!(found[0].shared, sketch::NUM_FEATURES as u32);
    assert_eq!(found[0].raw_len, sketch::MIN_SKETCH_BYTES as u64);
}

#[test]
fn rebuild_spans_the_lineage() {
    let tmp = TempDir::new().unwrap();
    let parent = tmp.path().join("parent");
    let child = tmp.path().join("child");
    let parent_signer = make_volume(&parent);
    let child_signer = make_volume(&child);

    let in_parent = entropy(10, sketch::MIN_SKETCH_BYTES);
    let in_child = entropy(11, sketch::MIN_SKETCH_BYTES);
    let (_, parent_hashes) = write_segment_with(
        &parent,
        parent_signer.as_ref(),
        std::slice::from_ref(&in_parent),
    );
    write_segment_with(&child, child_signer.as_ref(), &[in_child]);

    // Ancestor first, matching the order a volume open builds.
    let chain = vec![(parent.clone(), None), (child.clone(), None)];
    let (_, sketches) = extentindex::rebuild_with_sketches(&chain).unwrap();
    assert_eq!(sketches.len(), 2, "both layers contribute sources");

    let target = sketch::compute(&in_parent).expect("sketchable");
    let found = sketches.candidates(&target, 4);
    assert_eq!(
        found[0].hash, parent_hashes[0],
        "an ancestor extent is reachable as a candidate"
    );
}

#[test]
fn plain_rebuild_agrees_on_the_extent_index() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("vol");
    let signer = make_volume(&dir);
    write_segment_with(
        &dir,
        signer.as_ref(),
        &[
            entropy(20, sketch::MIN_SKETCH_BYTES),
            entropy(21, sketch::MIN_SKETCH_BYTES),
        ],
    );

    let chain = vec![(dir.clone(), None)];
    let plain = extentindex::rebuild(&chain).unwrap();
    let (harvested, sketches) = extentindex::rebuild_with_sketches(&chain).unwrap();

    // Harvesting must not perturb the index the walk exists to build.
    assert_eq!(plain.len(), harvested.len());
    for (hash, loc) in plain.iter() {
        let other = harvested.lookup(hash).expect("same hashes");
        assert_eq!(other.segment_id, loc.segment_id);
        assert_eq!(other.body_offset, loc.body_offset);
        assert_eq!(other.body_length, loc.body_length);
    }
    assert_eq!(sketches.len(), 2);
}

#[test]
fn a_journal_entry_contributes_no_source() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path().join("vol");
    let signer = make_volume(&dir);

    // Journal-tier content is never sketched at formation, so it cannot
    // reach the map even though it is a full-size Data entry.
    let body = entropy(30, sketch::MIN_SKETCH_BYTES);
    let mut e = SegmentEntry::new_data(
        blake3::hash(&body),
        0,
        (sketch::MIN_SKETCH_BYTES / 4096) as u32,
        Codec::None,
        body,
    );
    e.entry.journal = true;
    let seg = Ulid::new();
    write_segment(
        &elide_core::segment::pending_open_dir(&dir).join(seg.to_string()),
        vec![e],
        signer.as_ref(),
    )
    .unwrap();

    let (_, sketches) = extentindex::rebuild_with_sketches(&[(dir.clone(), None)]).unwrap();
    assert!(sketches.is_empty());

    // Confirm the entry is there at all, so the assertion above is about
    // the journal flag rather than an empty segment.
    let (_, entries, _) = segment::read_segment_index(
        &elide_core::segment::pending_open_dir(&dir).join(seg.to_string()),
    )
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].journal);
    assert_eq!(entries[0].sketch, None);
}
