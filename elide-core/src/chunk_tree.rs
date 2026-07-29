//! Chunk-granular verification against an extent's own BLAKE3 hash.
//!
//! An extent's content hash is the root of a BLAKE3 tree over its plaintext.
//! Slicing that plaintext at multiples of [`CHUNK_BYTES`] lands on subtree
//! boundaries of that same tree, so each slice has a chaining value that
//! composes back into the root. A reader holding every slice's chaining value
//! can decode one slice, recompute the root, and compare it to the hash the
//! signed index already carries.
//!
//! That is what lets a compression chunk be verified without reading the
//! extent around it, and it needs no second trust root: the anchor is the
//! extent hash itself. It is the construction bao encodes.

use std::io;

use blake3::hazmat::{
    ChainingValue, HasherExt, Mode, left_subtree_len, merge_subtrees_non_root, merge_subtrees_root,
};

/// Plaintext bytes per chunk.
///
/// A power-of-two multiple of BLAKE3's 1 KiB chunk, which is what makes a
/// slice at a multiple of it a subtree rather than an arbitrary range. At
/// this size a 4 KiB read decodes at most 128 KiB, the table costs 36 bytes
/// per chunk, and lz4's 64 KiB match window and zstd's useful history both
/// fit inside one chunk, so little cross-chunk matching is given up.
pub const CHUNK_BYTES: usize = 128 * 1024;

/// Number of chunks `plain_len` bytes of plaintext divide into.
pub fn chunk_count(plain_len: usize) -> usize {
    plain_len.div_ceil(CHUNK_BYTES)
}

/// Byte range of chunk `index` within an extent of `plain_len` bytes.
pub fn chunk_range(index: usize, plain_len: usize) -> std::ops::Range<usize> {
    let start = index * CHUNK_BYTES;
    start..(start + CHUNK_BYTES).min(plain_len)
}

/// Chunk indices covering the plaintext range `start..end`.
pub fn chunks_covering(start: usize, end: usize) -> std::ops::Range<usize> {
    if end <= start {
        return 0..0;
    }
    (start / CHUNK_BYTES)..(end - 1) / CHUNK_BYTES + 1
}

/// Chaining value of chunk `index`, whose plaintext is `chunk`.
///
/// `chunk` must be the whole chunk — [`CHUNK_BYTES`] bytes, or the shorter
/// remainder for the last one. A partial slice hashes to a value that
/// reconstructs nothing.
pub fn chunk_cv(index: usize, chunk: &[u8]) -> ChainingValue {
    let mut hasher = blake3::Hasher::new();
    hasher.set_input_offset((index * CHUNK_BYTES) as u64);
    hasher.update(chunk);
    hasher.finalize_non_root()
}

/// Chaining values of every chunk of `plain`, in order.
pub fn chunk_cvs(plain: &[u8]) -> Vec<ChainingValue> {
    (0..chunk_count(plain.len()))
        .map(|i| chunk_cv(i, &plain[chunk_range(i, plain.len())]))
        .collect()
}

/// Chaining value of the subtree `cvs` spans, which covers `len` bytes.
fn merge_subtree(cvs: &[ChainingValue], len: u64) -> ChainingValue {
    let Some((only, [])) = cvs.split_first() else {
        let (left_cvs, right_cvs, left_len) = split(cvs, len);
        return merge_subtrees_non_root(
            &merge_subtree(left_cvs, left_len),
            &merge_subtree(right_cvs, len - left_len),
            Mode::Hash,
        );
    };
    *only
}

/// Split `cvs` where BLAKE3 splits an input of `len` bytes.
///
/// `left_subtree_len` returns a power of two of at least [`CHUNK_BYTES`] for
/// any `len` above it, and [`CHUNK_BYTES`] is itself a power of two, so the
/// split always lands on a chunk boundary.
fn split(cvs: &[ChainingValue], len: u64) -> (&[ChainingValue], &[ChainingValue], u64) {
    let left_len = left_subtree_len(len);
    let left_chunks = (left_len / CHUNK_BYTES as u64) as usize;
    let (left, right) = cvs.split_at(left_chunks.min(cvs.len()));
    (left, right, left_len)
}

/// The extent hash that `cvs` reconstruct, for an extent of `plain_len`
/// bytes.
///
/// Errors below two chunks: a lone subtree's chaining value is not its root
/// hash, and no merge turns one into the other. Extents that small carry no
/// chunk table, so nothing calls this for them.
pub fn root_from_cvs(cvs: &[ChainingValue], plain_len: usize) -> io::Result<blake3::Hash> {
    if cvs.len() != chunk_count(plain_len) {
        return Err(io::Error::other(format!(
            "chunk table holds {} chaining values for {plain_len} bytes of plaintext, expected {}",
            cvs.len(),
            chunk_count(plain_len)
        )));
    }
    if cvs.len() < 2 {
        return Err(io::Error::other(
            "an extent of one chunk has no root hash to reconstruct",
        ));
    }
    let (left, right, left_len) = split(cvs, plain_len as u64);
    Ok(merge_subtrees_root(
        &merge_subtree(left, left_len),
        &merge_subtree(right, plain_len as u64 - left_len),
        Mode::Hash,
    ))
}

/// Check that `chunk` is chunk `index` of the extent hashing to `expected`.
///
/// Substitutes the chaining value computed from `chunk` into `cvs` and
/// reconstructs the root. A wrong chunk gives a wrong chaining value and so a
/// wrong root, and a tampered `cvs` gives a wrong root for the same reason,
/// so one comparison covers the chunk and the table together.
pub fn verify_chunk(
    index: usize,
    chunk: &[u8],
    cvs: &[ChainingValue],
    plain_len: usize,
    expected: &blake3::Hash,
) -> io::Result<()> {
    let mut with_chunk = cvs.to_vec();
    let slot = with_chunk
        .get_mut(index)
        .ok_or_else(|| io::Error::other(format!("chunk {index} is past the chunk table")))?;
    *slot = chunk_cv(index, chunk);
    let root = root_from_cvs(&with_chunk, plain_len)?;
    if root != *expected {
        return Err(io::Error::other(format!(
            "chunk {index} reconstructs extent hash {} instead of {}",
            root.to_hex(),
            expected.to_hex()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i / 97 % 251) as u8).collect()
    }

    /// The whole point: chaining values taken at chunk boundaries reconstruct
    /// the hash `blake3::hash` produces over the same bytes. Sizes straddle
    /// one chunk, exact multiples, and both sides of the power-of-two
    /// boundaries where BLAKE3 splits its tree.
    #[test]
    fn chunk_chaining_values_reconstruct_the_extent_hash() {
        let mut lens: Vec<usize> = Vec::new();
        for chunks in 2..=33usize {
            let exact = chunks * CHUNK_BYTES;
            lens.extend([exact - CHUNK_BYTES + 1, exact - 1, exact]);
        }
        lens.extend([CHUNK_BYTES + 1, CHUNK_BYTES + 4096, 3 * CHUNK_BYTES + 7]);

        for len in lens {
            let plain = pattern(len);
            let cvs = chunk_cvs(&plain);
            assert_eq!(cvs.len(), chunk_count(len), "count at {len}");
            assert_eq!(
                root_from_cvs(&cvs, len).expect("root"),
                blake3::hash(&plain),
                "reconstructed root at {len} bytes"
            );
        }
    }

    #[test]
    fn a_chunk_verifies_against_the_extent_hash() {
        let len = 5 * CHUNK_BYTES + 1234;
        let plain = pattern(len);
        let cvs = chunk_cvs(&plain);
        let hash = blake3::hash(&plain);

        for index in 0..chunk_count(len) {
            let chunk = &plain[chunk_range(index, len)];
            verify_chunk(index, chunk, &cvs, len, &hash).expect("chunk verifies");
        }
    }

    #[test]
    fn a_chunk_whose_bytes_were_altered_is_refused() {
        let len = 4 * CHUNK_BYTES;
        let plain = pattern(len);
        let cvs = chunk_cvs(&plain);
        let hash = blake3::hash(&plain);

        let mut tampered = plain[chunk_range(2, len)].to_vec();
        tampered[100] ^= 0xFF;
        let err = verify_chunk(2, &tampered, &cvs, len, &hash).expect_err("altered chunk");
        assert!(
            err.to_string().contains("reconstructs extent hash"),
            "got: {err}"
        );
    }

    /// The table is unsigned, so a chaining value for a chunk the reader is
    /// not decoding has to be covered too. It is, because every one of them
    /// feeds the root.
    #[test]
    fn a_tampered_chaining_value_for_another_chunk_is_refused() {
        let len = 4 * CHUNK_BYTES;
        let plain = pattern(len);
        let hash = blake3::hash(&plain);

        let mut cvs = chunk_cvs(&plain);
        cvs[3][0] ^= 0xFF;

        let err = verify_chunk(0, &plain[chunk_range(0, len)], &cvs, len, &hash)
            .expect_err("tampered sibling chaining value");
        assert!(
            err.to_string().contains("reconstructs extent hash"),
            "got: {err}"
        );
    }

    /// Two extents that share a chunk share its chaining value, which is what
    /// makes the table a resemblance signal as well as a verifier.
    #[test]
    fn identical_chunks_have_identical_chaining_values() {
        let shared = pattern(CHUNK_BYTES);
        let mut a = shared.clone();
        a.extend(pattern(CHUNK_BYTES).iter().map(|b| b ^ 0x11));
        let mut b = shared;
        b.extend(pattern(CHUNK_BYTES).iter().map(|b| b ^ 0x22));

        let (ca, cb) = (chunk_cvs(&a), chunk_cvs(&b));
        assert_eq!(ca[0], cb[0], "the shared chunk shares its chaining value");
        assert_ne!(ca[1], cb[1]);
    }

    /// A reader asking for chunk `i` cannot be handed chunk `j`'s bytes: the
    /// chaining value it reconstructs is for the slot it was substituted into.
    #[test]
    fn one_chunks_bytes_do_not_verify_at_another_index() {
        let len = 4 * CHUNK_BYTES;
        let plain = pattern(len);
        let cvs = chunk_cvs(&plain);
        let hash = blake3::hash(&plain);

        verify_chunk(1, &plain[chunk_range(0, len)], &cvs, len, &hash)
            .expect_err("chunk 0's bytes are not chunk 1's content");
    }

    /// A chaining value covers the chunk's offset as well as its bytes, so
    /// repeated content within one extent still gets distinct values. This is
    /// what stops the tree from being reorderable.
    #[test]
    fn repeated_content_at_different_offsets_gets_different_chaining_values() {
        let mut plain = pattern(CHUNK_BYTES);
        plain.extend(pattern(CHUNK_BYTES));
        assert_eq!(plain[..CHUNK_BYTES], plain[CHUNK_BYTES..]);

        let cvs = chunk_cvs(&plain);
        assert_ne!(cvs[0], cvs[1], "identical bytes, different offsets");
    }

    #[test]
    fn chunks_covering_a_range_are_the_ones_holding_it() {
        assert_eq!(chunks_covering(0, 4096), 0..1);
        assert_eq!(chunks_covering(0, CHUNK_BYTES), 0..1);
        assert_eq!(chunks_covering(0, CHUNK_BYTES + 1), 0..2);
        assert_eq!(chunks_covering(CHUNK_BYTES - 1, CHUNK_BYTES + 1), 0..2);
        assert_eq!(chunks_covering(CHUNK_BYTES, 2 * CHUNK_BYTES), 1..2);
        assert_eq!(chunks_covering(3 * CHUNK_BYTES, 3 * CHUNK_BYTES + 8), 3..4);
        assert_eq!(chunks_covering(10, 10), 0..0);
    }

    #[test]
    fn a_table_that_does_not_match_the_plaintext_length_is_refused() {
        let plain = pattern(3 * CHUNK_BYTES);
        let cvs = chunk_cvs(&plain);
        let err = root_from_cvs(&cvs[..2], plain.len()).expect_err("short table");
        assert!(err.to_string().contains("expected 3"), "got: {err}");
    }

    #[test]
    fn a_single_chunk_extent_has_no_root_to_reconstruct() {
        let plain = pattern(4096);
        let cvs = chunk_cvs(&plain);
        assert_eq!(cvs.len(), 1);
        root_from_cvs(&cvs, plain.len()).expect_err("one chunk has no derivable root");
    }
}
