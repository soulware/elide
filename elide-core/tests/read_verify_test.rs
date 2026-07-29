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
fn the_live_path_serves_a_whole_raw_extent() {
    let bytes = multiblock_plaintext();
    let hash = blake3::hash(&bytes);

    let read = write_then_read_live(bytes.clone(), 4, Codec::None, hash, 0, 4)
        .expect("a correct raw extent must still read");

    assert_eq!(&read[..], &bytes[..]);
}

/// A sub-range of a compressed extent decodes through the scratch buffer
/// rather than straight into the caller's, so it agrees with the whole-extent
/// read only if both spell the slice the same way.
#[test]
fn the_live_path_serves_a_sub_range_of_a_compressed_extent() {
    let bytes = multiblock_plaintext();
    let hash = blake3::hash(&bytes);
    let stored = lz4_flex::compress_prepend_size(&bytes);

    for block in 0..4u64 {
        let read = write_then_read_live(stored.clone(), 4, Codec::Lz4, hash, block, 1)
            .expect("a correct compressed extent must still read");
        let want = &bytes[block as usize * 4096..(block as usize + 1) * 4096];
        assert_eq!(&read[..], want, "block {block}");
    }
}

/// Four distinct constant blocks: distinguishable per block, and small enough
/// compressed to land in the inline section.
fn inline_sized_multiblock() -> Vec<u8> {
    let mut v = Vec::with_capacity(4 * 4096);
    for block in 0u8..4 {
        v.extend(std::iter::repeat_n(0x30 | block, 4096));
    }
    v
}

#[test]
fn the_live_path_serves_a_sub_range_of_an_inline_extent() {
    let bytes = inline_sized_multiblock();
    let hash = blake3::hash(&bytes);
    let stored = lz4_flex::compress_prepend_size(&bytes);
    assert!(stored.len() < 256, "stored form must be inline-sized");

    for block in 0..4u64 {
        let read = write_then_read_live(stored.clone(), 4, Codec::Lz4, hash, block, 1)
            .expect("a correct inline extent must still read");
        let want = &bytes[block as usize * 4096..(block as usize + 1) * 4096];
        assert_eq!(&read[..], want, "block {block}");
    }
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

#[test]
fn the_live_path_serves_a_whole_zstd_extent() {
    let bytes = multiblock_plaintext();
    let hash = blake3::hash(&bytes);
    let stored = zstd::bulk::compress(&bytes, 9).expect("compress");

    let read = write_then_read_live(stored, 4, Codec::Zstd, hash, 0, 4)
        .expect("a correct zstd extent must still read");

    assert_eq!(&read[..], &bytes[..]);
}

#[test]
fn the_live_path_serves_a_sub_range_of_a_zstd_extent() {
    let bytes = multiblock_plaintext();
    let hash = blake3::hash(&bytes);
    let stored = zstd::bulk::compress(&bytes, 9).expect("compress");

    for block in 0..4u64 {
        let read = write_then_read_live(stored.clone(), 4, Codec::Zstd, hash, block, 1)
            .expect("a correct zstd extent must still read");
        let want = &bytes[block as usize * 4096..(block as usize + 1) * 4096];
        assert_eq!(&read[..], want, "block {block}");
    }
}

#[test]
fn the_live_path_refuses_a_zstd_extent_that_decodes_cleanly_but_hashes_wrong() {
    let stored = zstd::bulk::compress(&plaintext(), 9).expect("compress");
    let wrong = blake3::hash(b"a hash no stored extent holds");

    let err = write_then_read_live(stored, 1, Codec::Zstd, wrong, 0, 1)
        .expect_err("the live path must not serve a zstd extent that fails its content hash");

    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}

// --- chunked extents ---

use elide_core::chunk_tree::{self, CHUNK_BYTES, ChunkTable};

/// Build the `ZstdChunked` stored form of `plain` the way `compress_body`
/// does, so these tests exercise the reader against the real layout.
fn chunked_form(plain: &[u8]) -> Vec<u8> {
    let count = chunk_tree::chunk_count(plain.len());
    let mut frames = Vec::new();
    let mut table = ChunkTable {
        plain_len: plain.len(),
        stored_lengths: Vec::new(),
        cvs: Vec::new(),
    };
    for index in 0..count {
        let chunk = &plain[chunk_tree::chunk_range(index, plain.len())];
        let frame = zstd::bulk::compress(chunk, 9).expect("compress");
        table.cvs.push(chunk_tree::chunk_cv(index, chunk));
        table.stored_lengths.push(frame.len() as u32);
        frames.push(frame);
    }
    let mut out = Vec::new();
    table.encode(&mut out);
    for frame in frames {
        out.extend_from_slice(&frame);
    }
    out
}

/// Distinguishable per 4 KiB block and compressible, spanning several chunks.
fn multichunk_plaintext(blocks: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(blocks * 4096);
    for block in 0..blocks {
        v.extend(std::iter::repeat_n((block % 251) as u8, 4096));
        let tag = (block as u32).to_le_bytes();
        let at = v.len() - 4096;
        v[at..at + 4].copy_from_slice(&tag);
    }
    v
}

#[test]
fn the_live_path_serves_a_whole_chunked_extent() {
    let blocks = 100; // ~410 KiB, four chunks
    let bytes = multichunk_plaintext(blocks);
    assert!(bytes.len() > 3 * CHUNK_BYTES);
    let hash = blake3::hash(&bytes);

    let read = write_then_read_live(
        chunked_form(&bytes),
        blocks as u32,
        Codec::ZstdChunked,
        hash,
        0,
        blocks as u32,
    )
    .expect("a correct chunked extent must read");

    assert_eq!(&read[..], &bytes[..]);
}

/// Every single-block read across a multi-chunk extent, including the blocks
/// either side of each chunk boundary.
#[test]
fn the_live_path_serves_every_block_of_a_chunked_extent() {
    let blocks = 100;
    let bytes = multichunk_plaintext(blocks);
    let hash = blake3::hash(&bytes);
    let stored = chunked_form(&bytes);

    for block in 0..blocks as u64 {
        let read = write_then_read_live(
            stored.clone(),
            blocks as u32,
            Codec::ZstdChunked,
            hash,
            block,
            1,
        )
        .expect("a correct chunked extent must read");
        let at = block as usize * 4096;
        assert_eq!(&read[..], &bytes[at..at + 4096], "block {block}");
    }
}

/// A range straddling a chunk boundary needs both chunks, and the halves have
/// to line up in the caller's buffer.
#[test]
fn the_live_path_serves_a_range_straddling_a_chunk_boundary() {
    let blocks = 100;
    let bytes = multichunk_plaintext(blocks);
    let hash = blake3::hash(&bytes);
    let stored = chunked_form(&bytes);

    let boundary = (CHUNK_BYTES / 4096) as u64;
    for (start, count) in [
        (boundary - 1, 2),
        (boundary - 2, 4),
        (boundary * 2 - 1, 3),
        (0, blocks as u32 - 1),
        (1, blocks as u32 - 1),
    ] {
        let read = write_then_read_live(
            stored.clone(),
            blocks as u32,
            Codec::ZstdChunked,
            hash,
            start,
            count,
        )
        .expect("a correct chunked extent must read");
        let at = start as usize * 4096;
        assert_eq!(
            &read[..],
            &bytes[at..at + count as usize * 4096],
            "{count} blocks at {start}"
        );
    }
}

#[test]
fn the_live_path_refuses_a_chunked_extent_that_hashes_wrong() {
    let blocks = 100;
    let bytes = multichunk_plaintext(blocks);
    let wrong = blake3::hash(b"a hash no stored extent holds");

    let err = write_then_read_live(
        chunked_form(&bytes),
        blocks as u32,
        Codec::ZstdChunked,
        wrong,
        0,
        1,
    )
    .expect_err("the live path must not serve a chunked extent that fails its content hash");

    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}

/// A read verifies what it serves, and only that. Corrupting a chunk the read
/// does not touch leaves it unaffected, because the reader takes that chunk's
/// chaining value from the table rather than recomputing it; reading the
/// corrupt chunk is refused. That is the granularity of the check.
#[test]
fn a_chunked_read_verifies_the_chunks_it_serves() {
    let blocks = 100;
    let bytes = multichunk_plaintext(blocks);
    let hash = blake3::hash(&bytes);

    let mut stored = chunked_form(&bytes);
    // Land inside the last chunk's frame, past every earlier chunk.
    let at = stored.len() - 8;
    stored[at] ^= 0xFF;

    let read = write_then_read_live(
        stored.clone(),
        blocks as u32,
        Codec::ZstdChunked,
        hash,
        0,
        1,
    )
    .expect("a chunk the read does not touch does not affect it");
    assert_eq!(&read[..], &bytes[..4096]);

    let last = blocks as u64 - 1;
    write_then_read_live(stored, blocks as u32, Codec::ZstdChunked, hash, last, 1)
        .expect_err("the corrupt chunk itself must be refused");
}

/// The table is unsigned, so a chaining value for a chunk the read does not
/// decode still has to be covered — every one of them feeds the root.
#[test]
fn a_chunked_read_refuses_a_tampered_chunk_table() {
    let blocks = 100;
    let bytes = multichunk_plaintext(blocks);
    let hash = blake3::hash(&bytes);

    let mut stored = chunked_form(&bytes);
    // The last chaining value in the table, well away from chunk 0.
    let count = chunk_tree::chunk_count(bytes.len());
    let at = 4 + (count - 1) * 36 + 4;
    stored[at] ^= 0xFF;

    let err = write_then_read_live(stored, blocks as u32, Codec::ZstdChunked, hash, 0, 1)
        .expect_err("a tampered chaining value must be refused");
    assert!(
        err.to_string().contains("hashed"),
        "error should report the hash mismatch, got: {err}"
    );
}
