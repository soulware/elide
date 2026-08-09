//! Chunk-granular verification against an extent's own BLAKE3 hash.
//!
//! An extent's content hash is the root of a BLAKE3 tree over its plaintext.
//! Slicing that plaintext at multiples of a [`ChunkSize`] lands on subtree
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

/// Smallest chunk a table may declare: BLAKE3's own chunk.
const MIN_LOG2: u8 = 10;

/// Largest chunk a table may declare, one step over
/// [`segment::MAX_EXTENT_PLAINTEXT`](crate::segment::MAX_EXTENT_PLAINTEXT) so
/// any extent that can exist divides into at least one chunk.
const MAX_LOG2: u8 = 28;

/// The chunk size the write path takes.
///
/// Measured over four corpora at the body level, chunking's cost against a
/// single frame is not monotonic in this number: 256 KiB puts every chunk on a
/// plateau in zstd's compression-parameter table and costs about 7% of stored
/// bytes on the extents it chunks, where 128 KiB sits under that plateau and
/// costs nothing on the same extents. The remaining trade is the matches a
/// compressor gives up at a boundary, worth 4.8 to 6.5% at this size on
/// corpora with redundancy across one, against halving what a read decodes.
/// See `docs/design/compression-codecs.md`.
pub const WRITE_CHUNK_SIZE: ChunkSize = ChunkSize(17);

/// Plaintext bytes per chunk, held as its log2.
///
/// A power-of-two multiple of BLAKE3's 1 KiB chunk, which is what makes a
/// slice at a multiple of it a subtree rather than an arbitrary range. Every
/// constructor enforces that, so holding one is proof the geometry composes.
///
/// Each table declares the size it was written at, so this is write-time
/// policy: [`WRITE_CHUNK_SIZE`] may move without stranding what earlier sizes
/// produced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ChunkSize(u8);

impl ChunkSize {
    pub fn from_log2(log2: u8) -> io::Result<Self> {
        if !(MIN_LOG2..=MAX_LOG2).contains(&log2) {
            return Err(io::Error::other(format!(
                "chunk table declares a chunk of 2^{log2} bytes, outside 2^{MIN_LOG2}..=2^{MAX_LOG2}"
            )));
        }
        Ok(Self(log2))
    }

    pub const fn bytes(self) -> usize {
        1 << self.0
    }

    pub const fn log2(self) -> u8 {
        self.0
    }

    /// Number of chunks `plain_len` bytes of plaintext divide into.
    pub fn count(self, plain_len: usize) -> usize {
        plain_len.div_ceil(self.bytes())
    }

    /// Byte range of chunk `index` within an extent of `plain_len` bytes.
    pub fn range(self, index: usize, plain_len: usize) -> std::ops::Range<usize> {
        let start = index * self.bytes();
        start..(start + self.bytes()).min(plain_len)
    }

    /// Chunk indices covering the plaintext range `start..end`.
    pub fn covering(self, start: usize, end: usize) -> std::ops::Range<usize> {
        if end <= start {
            return 0..0;
        }
        (start / self.bytes())..(end - 1) / self.bytes() + 1
    }

    /// Chaining value of chunk `index`, whose plaintext is `chunk`.
    ///
    /// `chunk` must be the whole chunk — [`Self::bytes`] of them, or the
    /// shorter remainder for the last one. A partial slice hashes to a value
    /// that reconstructs nothing.
    pub fn cv(self, index: usize, chunk: &[u8]) -> ChainingValue {
        let mut hasher = blake3::Hasher::new();
        hasher.set_input_offset((index * self.bytes()) as u64);
        hasher.update(chunk);
        hasher.finalize_non_root()
    }

    /// Chaining values of every chunk of `plain`, in order.
    pub fn cvs(self, plain: &[u8]) -> Vec<ChainingValue> {
        (0..self.count(plain.len()))
            .map(|i| self.cv(i, &plain[self.range(i, plain.len())]))
            .collect()
    }

    /// Chaining value of the subtree `cvs` spans, which covers `len` bytes.
    fn merge_subtree(self, cvs: &[ChainingValue], len: u64) -> ChainingValue {
        let Some((only, [])) = cvs.split_first() else {
            let (left_cvs, right_cvs, left_len) = self.split(cvs, len);
            return merge_subtrees_non_root(
                &self.merge_subtree(left_cvs, left_len),
                &self.merge_subtree(right_cvs, len - left_len),
                Mode::Hash,
            );
        };
        *only
    }

    /// Split `cvs` where BLAKE3 splits an input of `len` bytes.
    ///
    /// `left_subtree_len` returns a power of two of at least 1 KiB for any
    /// `len` above it, and a chunk is a power-of-two multiple of that, so the
    /// split always lands on a chunk boundary.
    fn split(self, cvs: &[ChainingValue], len: u64) -> (&[ChainingValue], &[ChainingValue], u64) {
        let left_len = left_subtree_len(len);
        let left_chunks = (left_len / self.bytes() as u64) as usize;
        let (left, right) = cvs.split_at(left_chunks.min(cvs.len()));
        (left, right, left_len)
    }

    /// The extent hash that `cvs` reconstruct, for an extent of `plain_len`
    /// bytes.
    ///
    /// Errors below two chunks: a lone subtree's chaining value is not its
    /// root hash, and no merge turns one into the other. Extents that small
    /// carry no chunk table, so nothing calls this for them.
    pub fn root_from_cvs(
        self,
        cvs: &[ChainingValue],
        plain_len: usize,
    ) -> io::Result<blake3::Hash> {
        if cvs.len() != self.count(plain_len) {
            return Err(io::Error::other(format!(
                "chunk table holds {} chaining values for {plain_len} bytes of plaintext at a {}-byte chunk, expected {}",
                cvs.len(),
                self.bytes(),
                self.count(plain_len)
            )));
        }
        if cvs.len() < 2 {
            return Err(io::Error::other(
                "an extent of one chunk has no root hash to reconstruct",
            ));
        }
        let (left, right, left_len) = self.split(cvs, plain_len as u64);
        Ok(merge_subtrees_root(
            &self.merge_subtree(left, left_len),
            &self.merge_subtree(right, plain_len as u64 - left_len),
            Mode::Hash,
        ))
    }

    /// Check that `chunk` is chunk `index` of the extent hashing to
    /// `expected`.
    ///
    /// Substitutes the chaining value computed from `chunk` into `cvs` and
    /// reconstructs the root. A wrong chunk gives a wrong chaining value and
    /// so a wrong root, and a tampered `cvs` gives a wrong root for the same
    /// reason, so one comparison covers the chunk and the table together.
    pub fn verify_chunk(
        self,
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
        *slot = self.cv(index, chunk);
        let root = self.root_from_cvs(&with_chunk, plain_len)?;
        if root != *expected {
            return Err(io::Error::other(format!(
                "chunk {index} reconstructs extent hash {} instead of {}",
                root.to_hex(),
                expected.to_hex()
            )));
        }
        Ok(())
    }
}

/// Bytes each chunk takes in the table: its stored length and its chaining
/// value. Offsets are the prefix sum of the lengths, so they are not stored.
const TABLE_ENTRY_LEN: usize = 4 + 32;

/// Bytes the table header takes: the extent's plaintext length and the log2
/// of its chunk size, from which the chunk count follows.
const TABLE_HEADER_LEN: usize = 5;

/// The table at the head of a chunked stored payload.
///
/// It sits in the body section rather than the index because `.idx` is
/// fetched eagerly for every ancestor at open, and a volume that never reads
/// a body should not carry its chaining values.
pub struct ChunkTable {
    /// Chunk size the extent was written at.
    pub size: ChunkSize,
    /// Plaintext bytes the whole extent decodes to.
    pub plain_len: usize,
    /// Stored bytes of each chunk, in order.
    pub stored_lengths: Vec<u32>,
    /// Chaining value of each chunk, in order.
    pub cvs: Vec<ChainingValue>,
}

impl ChunkTable {
    /// Bytes a table for `plain_len` bytes of plaintext at `size` occupies.
    pub fn encoded_len(plain_len: usize, size: ChunkSize) -> usize {
        TABLE_HEADER_LEN + size.count(plain_len) * TABLE_ENTRY_LEN
    }

    /// The plaintext length and chunk size at the head of `stored`, before the
    /// rest of the table has been read.
    ///
    /// Lets a reader size its table read from a first byte range that may be
    /// shorter than the table.
    pub fn peek_header(stored: &[u8]) -> io::Result<(usize, ChunkSize)> {
        let header = stored
            .get(..TABLE_HEADER_LEN)
            .ok_or_else(|| io::Error::other("chunked payload missing its table header"))?;
        let plain_len: [u8; 4] = header[..4].try_into().map_err(io::Error::other)?;
        Ok((
            u32::from_le_bytes(plain_len) as usize,
            ChunkSize::from_log2(header[4])?,
        ))
    }

    pub fn parse(stored: &[u8]) -> io::Result<Self> {
        let (plain_len, size) = Self::peek_header(stored)?;
        let count = size.count(plain_len);
        let table = stored
            .get(..Self::encoded_len(plain_len, size))
            .ok_or_else(|| io::Error::other("chunked payload shorter than its table"))?;
        let mut stored_lengths = Vec::with_capacity(count);
        let mut cvs = Vec::with_capacity(count);
        for i in 0..count {
            let at = TABLE_HEADER_LEN + i * TABLE_ENTRY_LEN;
            let len: [u8; 4] = table[at..at + 4].try_into().map_err(io::Error::other)?;
            let cv: ChainingValue = table[at + 4..at + TABLE_ENTRY_LEN]
                .try_into()
                .map_err(io::Error::other)?;
            stored_lengths.push(u32::from_le_bytes(len));
            cvs.push(cv);
        }
        Ok(Self {
            size,
            plain_len,
            stored_lengths,
            cvs,
        })
    }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.plain_len as u32).to_le_bytes());
        out.push(self.size.log2());
        for (len, cv) in self.stored_lengths.iter().zip(&self.cvs) {
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(cv);
        }
    }

    /// Byte range of chunk `index` within the whole stored payload.
    pub fn chunk_span(&self, index: usize) -> io::Result<std::ops::Range<usize>> {
        if index >= self.stored_lengths.len() {
            return Err(io::Error::other(format!(
                "chunk {index} is past the chunk table"
            )));
        }
        let start = Self::encoded_len(self.plain_len, self.size)
            + self.stored_lengths[..index]
                .iter()
                .map(|l| *l as usize)
                .sum::<usize>();
        Ok(start..start + self.stored_lengths[index] as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sizes every geometry test runs at: the smallest a table may declare,
    /// two between, and the one the write path takes.
    const SIZES: [u8; 5] = [MIN_LOG2, 12, 14, WRITE_CHUNK_SIZE.log2(), 20];

    fn size(log2: u8) -> ChunkSize {
        ChunkSize::from_log2(log2).expect("a swept size is in range")
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i / 97 % 251) as u8).collect()
    }

    /// The whole point: chaining values taken at chunk boundaries reconstruct
    /// the hash `blake3::hash` produces over the same bytes. Lengths straddle
    /// one chunk, exact multiples, and both sides of the power-of-two
    /// boundaries where BLAKE3 splits its tree, at every size a table may
    /// declare — the subtree property is what each size has to earn.
    #[test]
    fn chunk_chaining_values_reconstruct_the_extent_hash() {
        for log2 in SIZES {
            let s = size(log2);
            let c = s.bytes();
            // The tree shape follows the chunk count, so sweep it widely where
            // chunks are cheap and far enough elsewhere to cross a split.
            let max_chunks = match c {
                0..=16384 => 33,
                16385..=131072 => 17,
                _ => 5,
            };
            let mut lens: Vec<usize> = vec![c + 1, c + 4096, 3 * c + 7];
            for chunks in 2..=max_chunks {
                let exact = chunks * c;
                lens.extend([exact - c + 1, exact - 1, exact]);
            }

            for len in lens {
                let plain = pattern(len);
                let cvs = s.cvs(&plain);
                assert_eq!(cvs.len(), s.count(len), "count at {len} for 2^{log2}");
                assert_eq!(
                    s.root_from_cvs(&cvs, len).expect("root"),
                    blake3::hash(&plain),
                    "reconstructed root at {len} bytes for a 2^{log2}-byte chunk"
                );
            }
        }
    }

    #[test]
    fn a_chunk_verifies_against_the_extent_hash() {
        for log2 in SIZES {
            let s = size(log2);
            let len = 5 * s.bytes() + 1234;
            let plain = pattern(len);
            let cvs = s.cvs(&plain);
            let hash = blake3::hash(&plain);

            for index in 0..s.count(len) {
                let chunk = &plain[s.range(index, len)];
                s.verify_chunk(index, chunk, &cvs, len, &hash)
                    .unwrap_or_else(|e| panic!("chunk {index} at 2^{log2} verifies: {e}"));
            }
        }
    }

    #[test]
    fn a_chunk_whose_bytes_were_altered_is_refused() {
        let s = WRITE_CHUNK_SIZE;
        let len = 4 * s.bytes();
        let plain = pattern(len);
        let cvs = s.cvs(&plain);
        let hash = blake3::hash(&plain);

        let mut tampered = plain[s.range(2, len)].to_vec();
        tampered[100] ^= 0xFF;
        let err = s
            .verify_chunk(2, &tampered, &cvs, len, &hash)
            .expect_err("altered chunk");
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
        let s = WRITE_CHUNK_SIZE;
        let len = 4 * s.bytes();
        let plain = pattern(len);
        let hash = blake3::hash(&plain);

        let mut cvs = s.cvs(&plain);
        cvs[3][0] ^= 0xFF;

        let err = s
            .verify_chunk(0, &plain[s.range(0, len)], &cvs, len, &hash)
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
        let s = WRITE_CHUNK_SIZE;
        let shared = pattern(s.bytes());
        let mut a = shared.clone();
        a.extend(pattern(s.bytes()).iter().map(|b| b ^ 0x11));
        let mut b = shared;
        b.extend(pattern(s.bytes()).iter().map(|b| b ^ 0x22));

        let (ca, cb) = (s.cvs(&a), s.cvs(&b));
        assert_eq!(ca[0], cb[0], "the shared chunk shares its chaining value");
        assert_ne!(ca[1], cb[1]);
    }

    /// Chunks of the same bytes at the same offset under *different* sizes are
    /// different subtrees, so a table read at the wrong size reconstructs
    /// nothing. This is what the declared size buys.
    #[test]
    fn the_same_bytes_under_a_different_chunk_size_do_not_verify() {
        let s = WRITE_CHUNK_SIZE;
        let other = size(s.log2() - 1);
        let len = 4 * s.bytes();
        let plain = pattern(len);
        let hash = blake3::hash(&plain);

        let err = other
            .root_from_cvs(&s.cvs(&plain), len)
            .expect_err("a table read at the wrong size does not describe the extent");
        assert!(err.to_string().contains("expected 8"), "got: {err}");

        let cvs = other.cvs(&plain);
        let root = other
            .root_from_cvs(&cvs, len)
            .expect("root at its own size");
        assert_eq!(root, hash, "each size reconstructs the one extent hash");
    }

    /// A reader asking for chunk `i` cannot be handed chunk `j`'s bytes: the
    /// chaining value it reconstructs is for the slot it was substituted into.
    #[test]
    fn one_chunks_bytes_do_not_verify_at_another_index() {
        let s = WRITE_CHUNK_SIZE;
        let len = 4 * s.bytes();
        let plain = pattern(len);
        let cvs = s.cvs(&plain);
        let hash = blake3::hash(&plain);

        s.verify_chunk(1, &plain[s.range(0, len)], &cvs, len, &hash)
            .expect_err("chunk 0's bytes are not chunk 1's content");
    }

    /// A chaining value covers the chunk's offset as well as its bytes, so
    /// repeated content within one extent still gets distinct values. This is
    /// what stops the tree from being reorderable.
    #[test]
    fn repeated_content_at_different_offsets_gets_different_chaining_values() {
        let s = WRITE_CHUNK_SIZE;
        let mut plain = pattern(s.bytes());
        plain.extend(pattern(s.bytes()));
        assert_eq!(plain[..s.bytes()], plain[s.bytes()..]);

        let cvs = s.cvs(&plain);
        assert_ne!(cvs[0], cvs[1], "identical bytes, different offsets");
    }

    #[test]
    fn chunks_covering_a_range_are_the_ones_holding_it() {
        for log2 in SIZES {
            let s = size(log2);
            let c = s.bytes();
            assert_eq!(s.covering(0, 1), 0..1);
            assert_eq!(s.covering(0, c), 0..1);
            assert_eq!(s.covering(0, c + 1), 0..2);
            assert_eq!(s.covering(c - 1, c + 1), 0..2);
            assert_eq!(s.covering(c, 2 * c), 1..2);
            assert_eq!(s.covering(3 * c, 3 * c + 8), 3..4);
            assert_eq!(s.covering(10, 10), 0..0);
        }
    }

    #[test]
    fn a_table_that_does_not_match_the_plaintext_length_is_refused() {
        let s = WRITE_CHUNK_SIZE;
        let plain = pattern(3 * s.bytes());
        let cvs = s.cvs(&plain);
        let err = s
            .root_from_cvs(&cvs[..2], plain.len())
            .expect_err("short table");
        assert!(err.to_string().contains("expected 3"), "got: {err}");
    }

    #[test]
    fn a_single_chunk_extent_has_no_root_to_reconstruct() {
        let s = WRITE_CHUNK_SIZE;
        let plain = pattern(4096);
        let cvs = s.cvs(&plain);
        assert_eq!(cvs.len(), 1);
        s.root_from_cvs(&cvs, plain.len())
            .expect_err("one chunk has no derivable root");
    }

    /// A size off the power-of-two ladder or past what an extent can be is
    /// refused where it is read, so nothing downstream slices at a geometry
    /// that lands off a subtree boundary.
    #[test]
    fn a_chunk_size_outside_the_ladder_is_refused() {
        for log2 in [0, 1, MIN_LOG2 - 1, MAX_LOG2 + 1, 255] {
            let err = ChunkSize::from_log2(log2).expect_err("out of range");
            assert!(
                err.to_string().contains("chunk table declares"),
                "got: {err}"
            );
        }
        for log2 in [MIN_LOG2, MAX_LOG2] {
            ChunkSize::from_log2(log2).expect("bounds are inclusive");
        }
    }

    /// The header carries the size, so a table encoded at one size parses back
    /// at that size whatever this build writes.
    #[test]
    fn a_table_round_trips_the_size_it_was_encoded_at() {
        for log2 in SIZES {
            let s = size(log2);
            let plain = pattern(3 * s.bytes() + 11);
            let table = ChunkTable {
                size: s,
                plain_len: plain.len(),
                stored_lengths: vec![7; s.count(plain.len())],
                cvs: s.cvs(&plain),
            };
            let mut encoded = Vec::new();
            table.encode(&mut encoded);
            assert_eq!(
                encoded.len(),
                ChunkTable::encoded_len(plain.len(), s),
                "encoded length at 2^{log2}"
            );

            let parsed = ChunkTable::parse(&encoded).expect("parse");
            assert_eq!(parsed.size, s);
            assert_eq!(parsed.plain_len, plain.len());
            assert_eq!(parsed.cvs, table.cvs);
            assert_eq!(parsed.stored_lengths, table.stored_lengths);
            assert_eq!(
                ChunkTable::peek_header(&encoded).expect("peek"),
                (plain.len(), s)
            );
        }
    }
}
