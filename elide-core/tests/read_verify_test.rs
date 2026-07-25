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
use elide_core::segment::{SegmentEntry, SegmentFlags, SegmentSigner, write_segment};
use elide_core::signing;
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
    flags: SegmentFlags,
    claimed_hash: blake3::Hash,
) -> std::io::Result<[u8; 4096]> {
    let tmp = TempDir::new().unwrap();
    let (vol_dir, signer) = setup_volume_dir(&tmp);
    let seg_path = vol_dir.join(format!("pending/{}", Ulid::new()));
    let entries = vec![SegmentEntry::new_data(claimed_hash, 0, 1, flags, stored)];
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

    let err = write_then_read(bytes, SegmentFlags::empty(), wrong)
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

    let err = write_then_read(stored, SegmentFlags::COMPRESSED, wrong)
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

    let block = write_then_read(bytes.clone(), SegmentFlags::empty(), hash)
        .expect("a correct extent must still read");

    assert_eq!(&block[..], &bytes[..]);
}

#[test]
fn a_compressed_extent_matching_its_hash_still_reads() {
    let bytes = plaintext();
    let hash = blake3::hash(&bytes);
    let stored = lz4_flex::compress_prepend_size(&bytes);

    let block = write_then_read(stored, SegmentFlags::COMPRESSED, hash)
        .expect("a correct compressed extent must still read");

    assert_eq!(&block[..], &bytes[..]);
}
