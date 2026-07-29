// A read must not serve extent bytes that fail their content hash.
//
// When a location resolves to the wrong bytes, a compressed extent usually
// fails in lz4 and a raw-stored one fails nowhere at all — nothing downstream
// re-derives the hash, so the guest receives whatever the offset landed on.
// These cover both storage forms with a deliberately wrong claimed hash.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use elide_core::block_reader::BlockReader;
use elide_core::config::VolumeConfig;
use elide_core::segment::{Codec, SegmentEntry, SegmentSigner, write_segment};
use elide_core::signing;
use elide_core::volume::ReadonlyVolume;
use tempfile::TempDir;
use ulid::Ulid;

fn setup_volume_dir(tmp: &TempDir) -> (PathBuf, Arc<dyn SegmentSigner>) {
    let vol_dir = tmp.path().join(Ulid::new().to_string());
    fs::create_dir_all(&vol_dir).unwrap();
    signing::generate_keypair(&vol_dir, signing::VOLUME_KEY_FILE, signing::VOLUME_PUB_FILE)
        .unwrap();
    fs::create_dir_all(vol_dir.join("pending")).unwrap();
    fs::create_dir_all(vol_dir.join("snapshots")).unwrap();
    let signer = signing::load_signer(&vol_dir, signing::VOLUME_KEY_FILE).unwrap();
    VolumeConfig {
        name: Some("test".to_owned()),
        size: Some(1024 * 1024),
        ..Default::default()
    }
    .write(&vol_dir)
    .unwrap();
    (vol_dir, signer)
}

/// Write one Data entry at LBA 0 claiming `claimed_hash`, then read it back.
fn write_then_read(
    stored: Vec<u8>,
    codec: Codec,
    claimed_hash: blake3::Hash,
) -> std::io::Result<[u8; 4096]> {
    let tmp = TempDir::new().unwrap();
    let (vol_dir, signer) = setup_volume_dir(&tmp);
    let seg_path = vol_dir.join(format!("pending/{}", Ulid::new()));
    let entries = vec![SegmentEntry::new_data(claimed_hash, 0, 1, codec, stored)];
    write_segment(&seg_path, entries, signer.as_ref()).unwrap();

    let reader = BlockReader::open_live(Path::new(&vol_dir), Box::new(|_| None))?;
    reader.read_block(0)
}

fn plaintext() -> Vec<u8> {
    let mut v = vec![0x55u8; 4096];
    for (i, b) in v.iter_mut().enumerate().take(512) {
        *b = i as u8;
    }
    v
}

#[test]
fn a_raw_extent_whose_bytes_do_not_match_the_claimed_hash_is_refused() {
    let bytes = plaintext();
    let wrong = blake3::hash(b"a hash no stored extent holds");

    let err = write_then_read(bytes, Codec::None, wrong)
        .expect_err("a raw extent that fails its content hash must not be served");

    let msg = err.to_string();
    assert!(
        msg.contains("hashed") && msg.contains(&wrong.to_hex().to_string()),
        "error should name the claimed hash, got: {msg}"
    );
}

#[test]
fn a_compressed_extent_that_decompresses_cleanly_but_hashes_wrong_is_refused() {
    // lz4 succeeds here, so rejection cannot be a side effect of a decode
    // failure — only the content check catches it.
    let stored = lz4_flex::compress_prepend_size(&plaintext());
    let wrong = blake3::hash(b"a hash no stored extent holds");

    let err = write_then_read(stored, Codec::Lz4, wrong)
        .expect_err("a compressed extent that fails its content hash must not be served");

    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}

#[test]
fn a_raw_extent_matching_its_hash_still_reads() {
    let bytes = plaintext();
    let hash = blake3::hash(&bytes);

    let block = write_then_read(bytes.clone(), Codec::None, hash)
        .expect("a correct extent must still read");

    assert_eq!(&block[..], &bytes[..]);
}

#[test]
fn a_compressed_extent_matching_its_hash_still_reads() {
    let bytes = plaintext();
    let hash = blake3::hash(&bytes);
    let stored = lz4_flex::compress_prepend_size(&bytes);

    let block = write_then_read(stored, Codec::Lz4, hash)
        .expect("a correct compressed extent must still read");

    assert_eq!(&block[..], &bytes[..]);
}

/// Write one entry covering `lba_length` blocks at LBA 0 claiming
/// `claimed_hash`, then read `lba_count` blocks at `read_lba` through the
/// live path (`read_extents`, via `ReadonlyVolume`).
fn write_then_read_live(
    stored: Vec<u8>,
    lba_length: u32,
    codec: Codec,
    claimed_hash: blake3::Hash,
    read_lba: u64,
    lba_count: u32,
) -> std::io::Result<Vec<u8>> {
    let tmp = TempDir::new().unwrap();
    let (vol_dir, signer) = setup_volume_dir(&tmp);
    let seg_path = vol_dir.join(format!("pending/{}", Ulid::new()));
    let entries = vec![SegmentEntry::new_data(
        claimed_hash,
        0,
        lba_length,
        codec,
        stored,
    )];
    write_segment(&seg_path, entries, signer.as_ref()).unwrap();

    let rv = ReadonlyVolume::open(&vol_dir, &vol_dir)?;
    rv.read(read_lba, lba_count)
}

/// Four 4 KiB blocks, each with a distinct pattern so a mis-sliced
/// sub-range read cannot pass by accident.
fn multiblock_plaintext() -> Vec<u8> {
    let mut v = Vec::with_capacity(4 * 4096);
    for block in 0u8..4 {
        v.extend(std::iter::repeat_n(0xA0 | block, 4096));
    }
    for (i, b) in v.iter_mut().enumerate().take(512) {
        *b = i as u8;
    }
    v
}

#[test]
fn the_live_path_refuses_a_raw_extent_whose_bytes_do_not_match_the_hash() {
    let wrong = blake3::hash(b"a hash no stored extent holds");

    let err = write_then_read_live(plaintext(), 1, Codec::None, wrong, 0, 1)
        .expect_err("the live path must not serve a raw extent that fails its content hash");

    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}

#[test]
fn the_live_path_refuses_a_compressed_extent_that_decompresses_cleanly_but_hashes_wrong() {
    let stored = lz4_flex::compress_prepend_size(&plaintext());
    let wrong = blake3::hash(b"a hash no stored extent holds");

    let err = write_then_read_live(stored, 1, Codec::Lz4, wrong, 0, 1)
        .expect_err("the live path must not serve a compressed extent that fails its content hash");

    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}

#[test]
fn the_live_path_refuses_an_inline_extent_that_hashes_wrong() {
    // All one byte compresses under the 256-byte inline threshold, so the
    // stored form rides in the signed .idx rather than the body section.
    let stored = lz4_flex::compress_prepend_size(&vec![0x55u8; 4096]);
    assert!(stored.len() < 256, "stored form must be inline-sized");
    let wrong = blake3::hash(b"a hash no stored extent holds");

    let err = write_then_read_live(stored, 1, Codec::Lz4, wrong, 0, 1)
        .expect_err("the live path must not serve an inline extent that fails its content hash");

    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}

#[test]
fn a_sub_range_read_verifies_the_whole_extent() {
    // The claimed hash covers the clean four-block payload; the stored copy
    // is corrupted in the LAST block only. A read of block 0 lands entirely
    // in clean bytes — only whole-extent verification can refuse it.
    let clean = multiblock_plaintext();
    let hash = blake3::hash(&clean);
    let mut stored = clean;
    stored[3 * 4096 + 100] ^= 0xFF;

    let err = write_then_read_live(stored, 4, Codec::None, hash, 0, 1)
        .expect_err("a sub-range read of a corrupt extent must be refused");

    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}

#[test]
fn the_live_path_serves_a_sub_range_of_a_raw_extent() {
    let bytes = multiblock_plaintext();
    let hash = blake3::hash(&bytes);

    let block = write_then_read_live(bytes.clone(), 4, Codec::None, hash, 2, 1)
        .expect("a correct raw extent must still read");

    assert_eq!(&block[..], &bytes[2 * 4096..3 * 4096]);
}

#[test]
fn the_live_path_serves_a_whole_compressed_extent() {
    let bytes = multiblock_plaintext();
    let hash = blake3::hash(&bytes);
    let stored = lz4_flex::compress_prepend_size(&bytes);

    let read = write_then_read_live(stored, 4, Codec::Lz4, hash, 0, 4)
        .expect("a correct compressed extent must still read");

    assert_eq!(&read[..], &bytes[..]);
}

#[test]
fn the_live_path_serves_a_correct_inline_extent() {
    let bytes = vec![0x55u8; 4096];
    let hash = blake3::hash(&bytes);
    let stored = lz4_flex::compress_prepend_size(&bytes);
    assert!(stored.len() < 256, "stored form must be inline-sized");

    let read = write_then_read_live(stored, 1, Codec::Lz4, hash, 0, 1)
        .expect("a correct inline extent must still read");

    assert_eq!(&read[..], &bytes[..]);
}
