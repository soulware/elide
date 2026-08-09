//! Codec gating for the artefacts the write and formation paths produce.
//!
//! Pulled out of `volume/mod.rs` for legibility. Which codec each artefact
//! takes, and why, is `docs/design/compression-codecs.md`.

use std::io;

use crate::chunk_tree::{self, ChunkTable};
use crate::segment::Codec;

/// Minimum compression ratio required to store compressed data (1.5×).
///
/// If the compressed payload is not at least 1/3 smaller than the original,
/// the compression overhead is not worth it and the raw data is stored instead.
pub(in crate::volume) const MIN_COMPRESSION_RATIO_NUM: usize = 3;
pub(in crate::volume) const MIN_COMPRESSION_RATIO_DEN: usize = 2;

/// zstd level for segment bodies.
///
/// Level 9 measures 6 to 14% smaller than this over three corpora, for
/// roughly 3.4 times the compression CPU on every entry formation touches.
/// A whole extent, often 8 KiB of one, holds much less for a longer search
/// to find than the delta residuals that make level 9 pay in
/// `delta_compute::ZSTD_LEVEL`.
pub(crate) const BODY_ZSTD_LEVEL: i32 = 3;

/// Attempt lz4 compression on `data`.
///
/// Returns `Some(compressed_bytes)` if the compression ratio meets the
/// minimum threshold (1.5×); `None` to store raw. Incompressible data (high
/// entropy, already-compressed payloads) fails the ratio check naturally —
/// lz4 itself decides faster than a precomputed entropy gate would.
///
/// The WAL and `.dmat` take this. Their cost is decompression on a latency
/// path, which is the quantity the ratio threshold prices.
pub(crate) fn maybe_compress(data: &[u8]) -> Option<Vec<u8>> {
    let compressed = lz4_flex::compress_prepend_size(data);
    if compressed.len() * MIN_COMPRESSION_RATIO_NUM / MIN_COMPRESSION_RATIO_DEN >= data.len() {
        return None;
    }
    Some(compressed)
}

/// The stored form of a segment body holding `plain`, or `None` to store the
/// plaintext the caller already holds.
///
/// Body bytes are what a segment uploads and what S3 charges for, so the bar
/// is that the stored form is smaller. The 1.5× ratio `maybe_compress` applies
/// prices decompression CPU on a read that mostly never happens, which is the
/// wrong quantity here.
///
/// Journal-tier bytes take lz4. They reap whole with their segment and are
/// never a dedup or delta source, so a better ratio buys little on content
/// that does not outlive its segment, and lz4 keeps formation CPU off a tier
/// that is a large share of segments on a churning volume.
pub(crate) fn compress_body(plain: &[u8], journal: bool) -> io::Result<Option<(Codec, Vec<u8>)>> {
    if journal {
        return Ok(maybe_compress(plain).map(|c| (Codec::Lz4, c)));
    }

    // An extent over one chunk is always chunked, whether or not the frames
    // shrink it. On content no codec shrinks the chunked form runs about
    // 0.04% over the plaintext — a frame header and a table entry per chunk —
    // and that buys a read that decodes and hashes one chunk where a raw
    // extent makes it decode and hash all of them. Never producing a large
    // raw extent is what keeps the read bound a property of the format rather
    // than of the content.
    if plain.len() > chunk_tree::WRITE_CHUNK_SIZE.bytes() {
        return Ok(Some((Codec::ZstdChunked, compress_chunked(plain)?)));
    }

    let form = zstd_frame(plain)?;
    if form.len() >= plain.len() {
        return Ok(None);
    }
    // A stored form this small rides in the `.idx` rather than the body
    // section, and the inline section is lz4: it is fetched eagerly by every
    // host and decoded from memory, which is what the ratio threshold prices.
    // Only entries small enough to land there pay for the second encode.
    if crate::segment::would_be_inline(form.len())
        && let Some(lz4_form) = maybe_compress(plain)
        && crate::segment::would_be_inline(lz4_form.len())
    {
        return Ok(Some((Codec::Lz4, lz4_form)));
    }
    Ok(Some((Codec::Zstd, form)))
}

thread_local! {
    /// Pooled zstd compression context. Chunking turns one compress per
    /// extent into one per 128 KiB, so a context per call would be the
    /// allocation shape behind `malloc_policy.rs` at chunk frequency.
    static ZSTD_ENCODER: std::cell::RefCell<Option<zstd::bulk::Compressor<'static>>> =
        const { std::cell::RefCell::new(None) };
}

/// One zstd frame over `plain`, at [`BODY_ZSTD_LEVEL`].
fn zstd_frame(plain: &[u8]) -> io::Result<Vec<u8>> {
    ZSTD_ENCODER.with(|cell| {
        let mut slot = cell.borrow_mut();
        let encoder = match slot.as_mut() {
            Some(e) => e,
            None => slot.insert(
                zstd::bulk::Compressor::new(BODY_ZSTD_LEVEL)
                    .map_err(|e| io::Error::other(format!("zstd encoder init: {e}")))?,
            ),
        };
        encoder
            .compress(plain)
            .map_err(|e| io::Error::other(format!("zstd body compress failed: {e}")))
    })
}

/// A chunk table followed by one independently decodable frame per
/// [`chunk_tree::WRITE_CHUNK_SIZE`] of `plain`.
///
/// The table declares the size, so what a reader slices at comes from the
/// extent rather than from this build.
fn compress_chunked(plain: &[u8]) -> io::Result<Vec<u8>> {
    let size = chunk_tree::WRITE_CHUNK_SIZE;
    let count = size.count(plain.len());
    let mut frames = Vec::with_capacity(count);
    let mut table = ChunkTable {
        size,
        plain_len: plain.len(),
        stored_lengths: Vec::with_capacity(count),
        cvs: Vec::with_capacity(count),
    };
    for index in 0..count {
        let chunk = &plain[size.range(index, plain.len())];
        let frame = zstd_frame(chunk)?;
        table.cvs.push(size.cv(index, chunk));
        table.stored_lengths.push(frame.len() as u32);
        frames.push(frame);
    }
    let mut out = Vec::with_capacity(
        ChunkTable::encoded_len(plain.len(), size) + frames.iter().map(Vec::len).sum::<usize>(),
    );
    table.encode(&mut out);
    for frame in frames {
        out.extend_from_slice(&frame);
    }
    Ok(out)
}
