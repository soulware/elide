// Integration test for the thin Delta entry read path (Phase C).
//
// Hand-crafts two segments:
//   1. A source segment with one DATA entry holding the "parent" bytes.
//   2. A Delta segment with one Delta entry whose source_hash points at
//      the parent DATA, plus a zstd-dict-compressed delta blob in the
//      segment's delta body section.
//
// Opens the volume, reads the LBA covered by the Delta entry, and
// verifies that the returned bytes equal the "child" bytes that went
// through the zstd-dict compression step.
//
// No producer exists yet — this test builds segments via low-level
// primitives. It verifies the format, the extent-index registration,
// and the volume read path decompression all work end-to-end.

use std::fs;
use std::sync::Arc;

use elide_core::config::VolumeConfig;
use elide_core::segment::{
    DeltaOption, SegmentEntry, SegmentFlags, SegmentSigner, write_segment,
    write_segment_with_delta_body,
};
use elide_core::signing;
use elide_core::volume::ReadonlyVolume;
use tempfile::TempDir;
use ulid::Ulid;

mod common;

/// Create a new volume directory with a keypair and an empty volume.toml,
/// returning the dir path and the signer. The volume is not yet opened.
fn setup_volume_dir(tmp: &TempDir) -> (std::path::PathBuf, Arc<dyn SegmentSigner>) {
    let vol_dir = tmp.path().join("vol");
    fs::create_dir_all(&vol_dir).unwrap();
    signing::generate_keypair(&vol_dir, signing::VOLUME_KEY_FILE, signing::VOLUME_PUB_FILE)
        .unwrap();
    fs::create_dir_all(vol_dir.join("pending")).unwrap();
    fs::create_dir_all(vol_dir.join("snapshots")).unwrap();
    let signer = signing::load_signer(&vol_dir, signing::VOLUME_KEY_FILE).unwrap();
    VolumeConfig {
        name: Some("test".to_owned()),
        size: Some(1024 * 1024),
        nbd: None,
    }
    .write(&vol_dir)
    .unwrap();
    (vol_dir, signer)
}

#[test]
fn delta_entry_end_to_end_decompression() {
    let tmp = TempDir::new().unwrap();
    let (vol_dir, signer) = setup_volume_dir(&tmp);

    // Parent file content — a whole 4 KiB block, lz4-compressible.
    let parent_bytes = vec![0x55u8; 4096];
    let parent_hash = blake3::hash(&parent_bytes);

    // Child file content — different from parent but structurally
    // similar so the zstd-dict delta is small.
    let mut child_bytes = vec![0x55u8; 4096];
    for (i, byte) in child_bytes.iter_mut().enumerate().take(256) {
        *byte = i as u8;
    }
    let child_hash = blake3::hash(&child_bytes);

    // Compute the delta blob using zstd with parent as dictionary.
    let mut compressor = zstd::bulk::Compressor::with_dictionary(3, &parent_bytes).unwrap();
    let delta_blob = compressor.compress(&child_bytes).unwrap();
    assert!(!delta_blob.is_empty());

    // --- Segment 1: holds the parent DATA entry at LBA 0. ---
    let parent_seg_ulid = Ulid::new();
    let parent_seg_path = vol_dir.join(format!("pending/{parent_seg_ulid}"));
    let mut parent_entries = vec![SegmentEntry::new_data(
        parent_hash,
        0,
        1,
        SegmentFlags::empty(),
        parent_bytes.clone(),
    )];
    write_segment(&parent_seg_path, &mut parent_entries, signer.as_ref()).unwrap();

    // --- Segment 2: holds the Delta entry at LBA 10. ---
    // Its ULID must be greater than the parent segment's so the LBA map
    // rebuild applies it after the parent (the parent contributes nothing
    // to LBA 10 anyway, but monotonic ULIDs are required for rebuild
    // ordering to be safe).
    let delta_seg_ulid = Ulid::new();
    assert!(delta_seg_ulid > parent_seg_ulid);
    let delta_seg_path = vol_dir.join(format!("pending/{delta_seg_ulid}"));
    let delta_option = DeltaOption {
        source_hash: parent_hash,
        delta_offset: 0,
        delta_length: delta_blob.len() as u32,
    };
    let mut delta_entries = vec![SegmentEntry::new_delta(
        child_hash,
        10,
        1,
        vec![delta_option],
    )];
    write_segment_with_delta_body(
        &delta_seg_path,
        &mut delta_entries,
        &delta_blob,
        signer.as_ref(),
    )
    .unwrap();

    // Write a snapshot marker so the volume has a floor.
    fs::write(vol_dir.join(format!("snapshots/{delta_seg_ulid}")), "").unwrap();

    // --- Open the volume and read the Delta LBA. ---
    let vol = ReadonlyVolume::open(&vol_dir, &vol_dir).unwrap();
    let bytes = vol.read(10, 1).unwrap();
    assert_eq!(
        bytes.len(),
        4096,
        "read should return one 4 KiB block for the Delta LBA"
    );
    assert_eq!(
        bytes, child_bytes,
        "delta-decompressed bytes must equal the original child content"
    );

    // Also: reading the parent LBA should return the parent bytes
    // (sanity check that the normal DATA path still works).
    let parent_read = vol.read(0, 1).unwrap();
    assert_eq!(parent_read, parent_bytes);
}
