//! Codec gating for the artefacts the write and formation paths produce.
//!
//! Pulled out of `volume/mod.rs` for legibility. Which codec each artefact
//! takes, and why, is `docs/design/compression-codecs.md`.

use std::io;

use crate::segment::Codec;

/// Minimum compression ratio required to store compressed data (1.5×).
///
/// If the compressed payload is not at least 1/3 smaller than the original,
/// the compression overhead is not worth it and the raw data is stored instead.
pub(in crate::volume) const MIN_COMPRESSION_RATIO_NUM: usize = 3;
pub(in crate::volume) const MIN_COMPRESSION_RATIO_DEN: usize = 2;

/// zstd level for segment bodies.
///
/// A body compresses once at formation, off the ack path, and decompresses
/// faster as the level rises, so the level is paid for in formation CPU
/// alone. Body bytes are what a segment uploads and what S3 charges for,
/// which is the cost this buys down.
pub(crate) const BODY_ZSTD_LEVEL: i32 = 9;

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
    let zstd_form = zstd::bulk::compress(plain, BODY_ZSTD_LEVEL)
        .map_err(|e| io::Error::other(format!("zstd body compress failed: {e}")))?;
    if zstd_form.len() >= plain.len() {
        return Ok(None);
    }
    // A stored form this small rides in the `.idx` rather than the body
    // section, and the inline section is lz4: it is fetched eagerly by every
    // host and decoded from memory, which is what the ratio threshold prices.
    // Only entries small enough to land there pay for the second encode.
    if crate::segment::would_be_inline(zstd_form.len())
        && let Some(lz4_form) = maybe_compress(plain)
        && crate::segment::would_be_inline(lz4_form.len())
    {
        return Ok(Some((Codec::Lz4, lz4_form)));
    }
    Ok(Some((Codec::Zstd, zstd_form)))
}
