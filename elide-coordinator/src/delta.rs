// Delta compression: compute zstd-dictionary-compressed delta blobs for
// segment entries before S3 upload.
//
// Phase 1: LBA-based delta.  For each DATA entry in a pending segment, look
// up what hash previously occupied that LBA in the parent snapshot's LBA map.
// If the hash changed, compress the new extent body using the old extent body
// as a zstd dictionary.  The resulting delta blob is much smaller than the
// full extent for in-place file updates.

use std::io;
use std::path::Path;

use tracing::{debug, info};

use elide_core::extentindex::{self, ExtentIndex, ExtentLocation};
use elide_core::lbamap::{self, LbaMap};
use elide_core::segment::{self, DeltaOption, EntryKind, SegmentSigner};
use elide_core::signing;
use elide_core::volume;

/// Minimum extent size (bytes) to attempt delta compression.
/// Smaller extents have too little data for the zstd dictionary to help.
const MIN_EXTENT_BYTES: u32 = 4096;

/// zstd compression level for delta blobs.  Higher than real-time body
/// compression because deltas are computed once (at upload) and fetched
/// infrequently.  Level 3 is a good tradeoff between ratio and CPU.
const ZSTD_LEVEL: i32 = 3;

/// Result of delta computation for a segment.
pub struct DeltaResult {
    /// (entry_index, delta_options) pairs to attach to base entries.
    pub deltas: Vec<(usize, Vec<DeltaOption>)>,
    /// Concatenated delta blobs; offsets in `DeltaOption` are into this buffer.
    pub delta_body: Vec<u8>,
}

/// Attempt delta compression for a pending segment.
///
/// Reads the segment at `segment_path`, looks up prior LBA state in
/// `parent_lbamap`, and compresses changed extents against the source
/// extent bodies found via `source_index`.
///
/// `fork_dir` is the current fork's directory (used to locate local segment
/// files for reading source extent bodies).
///
/// Returns `None` if no deltas were produced (all entries are new, dedup'd,
/// or too small to benefit).
pub fn compute_deltas(
    segment_path: &Path,
    parent_lbamap: &LbaMap,
    source_index: &ExtentIndex,
    fork_dir: &Path,
    verifying_key: &signing::VerifyingKey,
) -> io::Result<Option<DeltaResult>> {
    let (body_section_start, entries) =
        segment::read_and_verify_segment_index(segment_path, verifying_key)?;

    // Read body data for DATA entries in the pending segment.
    let mut entries_with_data = entries;
    segment::read_extent_bodies(
        segment_path,
        body_section_start,
        &mut entries_with_data,
        [EntryKind::Data, EntryKind::Inline],
        &[], // inline bytes not needed for delta (inline extents are small)
    )?;

    let mut deltas: Vec<(usize, Vec<DeltaOption>)> = Vec::new();
    let mut delta_body: Vec<u8> = Vec::new();
    let mut candidates = 0u32;
    let mut original_bytes = 0u64;

    for (i, entry) in entries_with_data.iter().enumerate() {
        // Only DATA entries are delta candidates.
        if entry.kind != EntryKind::Data {
            continue;
        }
        // Skip tiny extents.
        let uncompressed_len = entry.lba_length as u64 * 4096;
        if uncompressed_len < MIN_EXTENT_BYTES as u64 {
            continue;
        }

        // Look up what hash previously occupied this LBA range.
        // For multi-block entries, all LBAs must map to the same source extent.
        // If any LBA is unmapped or maps to a different hash, skip delta.
        let old_hash = match parent_lbamap.hash_at(entry.start_lba) {
            Some(h) => h,
            None => {
                debug!(
                    "entry {i}: lba {} not in parent map, skipping",
                    entry.start_lba
                );
                continue;
            }
        };
        if entry.lba_length > 1 {
            let all_same = (1..entry.lba_length as u64)
                .all(|offset| parent_lbamap.hash_at(entry.start_lba + offset) == Some(old_hash));
            if !all_same {
                debug!("skipping delta for entry {i}: multi-block extent with fragmented parent");
                continue;
            }
        }
        if old_hash == entry.hash {
            continue; // unchanged, dedup handles it
        }

        // Find the source extent in the extent index.
        let source_loc = match source_index.lookup(&old_hash) {
            Some(loc) => loc,
            None => continue, // source not locally available
        };

        // Read source extent body bytes.
        let source_data = match read_extent_data(source_loc, fork_dir) {
            Ok(data) => data,
            Err(e) => {
                debug!("skipping delta for entry {i}: cannot read source extent: {e}");
                continue;
            }
        };

        // Decompress source if needed.
        let source_decompressed = if source_loc.compressed {
            decompress_lz4(&source_data)?
        } else {
            source_data
        };

        // Get new extent body bytes (already read above).
        let Some(new_stored) = &entry.data else {
            continue;
        };
        let new_decompressed = if entry.compressed {
            decompress_lz4(new_stored)?
        } else {
            new_stored.clone()
        };

        // Compress new data with source as zstd dictionary (raw content, not
        // a trained dictionary — zstd still benefits from the content overlap).
        let delta_blob = {
            let mut encoder =
                zstd::bulk::Compressor::with_dictionary(ZSTD_LEVEL, &source_decompressed)
                    .map_err(|e| io::Error::other(format!("zstd compressor init failed: {e}")))?;
            encoder
                .compress(&new_decompressed)
                .map_err(|e| io::Error::other(format!("zstd delta compression failed: {e}")))?
        };

        candidates += 1;

        // Skip if delta isn't smaller than the stored (possibly lz4-compressed) body.
        if delta_blob.len() >= entry.stored_length as usize {
            debug!(
                "skipping delta for entry {i}: delta {} >= stored {}",
                delta_blob.len(),
                entry.stored_length
            );
            continue;
        }

        original_bytes += entry.stored_length as u64;
        let delta_offset = delta_body.len() as u64;
        let delta_length = delta_blob.len() as u32;
        delta_body.extend_from_slice(&delta_blob);

        deltas.push((
            i,
            vec![DeltaOption {
                source_hash: old_hash,
                delta_offset,
                delta_length,
            }],
        ));
    }

    if deltas.is_empty() {
        if candidates > 0 {
            info!("delta: {candidates} candidate(s) but none produced smaller deltas");
        }
        return Ok(None);
    }

    let savings_pct = if original_bytes > 0 {
        100.0 - (delta_body.len() as f64 / original_bytes as f64 * 100.0)
    } else {
        0.0
    };
    info!(
        "delta: {}/{} entries, {} -> {} bytes ({savings_pct:.0}% savings)",
        deltas.len(),
        entries_with_data.len(),
        original_bytes,
        delta_body.len()
    );

    Ok(Some(DeltaResult { deltas, delta_body }))
}

/// Read extent body bytes from a local segment file.
///
/// Handles both full segment files (`pending/`, `gc/*.applied`) and cached
/// body files (`cache/<id>.body`).
fn read_extent_data(loc: &ExtentLocation, fork_dir: &Path) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};

    let segment_id_str = loc.segment_id.to_string();

    // Try locations in order: pending/, gc/*.applied, index/ (full seg), cache/*.body
    let (path, file_offset) = find_extent_file(fork_dir, &segment_id_str, loc)?;

    let mut f = std::fs::File::open(&path)?;
    f.seek(SeekFrom::Start(file_offset))?;
    let mut buf = vec![0u8; loc.body_length as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Locate the file and compute the absolute byte offset for reading an extent.
fn find_extent_file(
    fork_dir: &Path,
    segment_id: &str,
    loc: &ExtentLocation,
) -> io::Result<(std::path::PathBuf, u64)> {
    // Full segment files: body_section_start + body_offset
    let candidates_full = [
        fork_dir.join("pending").join(segment_id),
        fork_dir.join("gc").join(format!("{segment_id}.applied")),
    ];
    for path in &candidates_full {
        if path.exists() {
            return Ok((path.clone(), loc.body_section_start + loc.body_offset));
        }
    }

    // Cache body file: body_offset directly (body-relative)
    let cache_body = fork_dir.join("cache").join(format!("{segment_id}.body"));
    if cache_body.exists() {
        return Ok((cache_body, loc.body_offset));
    }

    Err(io::Error::other(format!(
        "source extent segment {segment_id} not found locally in {}",
        fork_dir.display()
    )))
}

/// Decompress lz4-compressed extent data.
///
/// Uses `decompress_size_prepended` matching the write path's
/// `compress_prepend_size`.
fn decompress_lz4(data: &[u8]) -> io::Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| io::Error::other(format!("lz4 decompression failed: {e}")))
}

/// Build the parent LBA map and extent index for delta source lookup.
///
/// Returns `None` if no snapshot exists (no prior LBA state to delta against).
pub fn build_parent_state(fork_dir: &Path) -> io::Result<Option<(LbaMap, ExtentIndex)>> {
    // Check for a snapshot — no snapshot means no prior LBA state.
    let snapshot_ulid = match volume::latest_snapshot(fork_dir)? {
        Some(u) => u,
        None => return Ok(None),
    };

    // The by_id directory is the parent of the fork dir (e.g. data/by_id/).
    let by_id_dir = fork_dir.parent().unwrap_or(fork_dir);

    // Walk ancestor chain.
    let ancestors = volume::walk_ancestors(fork_dir, by_id_dir)?;

    // Build rebuild chain: ancestors + current fork scoped to the snapshot ULID.
    // The snapshot ULID is the cutoff — only segments up to and including the
    // snapshot are part of the "parent" state.  Pending segments (written after
    // the snapshot) are excluded.
    let snapshot_cutoff = snapshot_ulid.to_string();
    let rebuild_chain: Vec<(std::path::PathBuf, Option<String>)> = ancestors
        .iter()
        .map(|l| (l.dir.clone(), l.branch_ulid.clone()))
        .chain(std::iter::once((
            fork_dir.to_owned(),
            Some(snapshot_cutoff),
        )))
        .collect();

    let lbamap = lbamap::rebuild_segments(&rebuild_chain)?;
    let extent_index = extentindex::rebuild(&rebuild_chain)?;

    info!(
        "delta: parent state from snapshot {snapshot_ulid}, lba map {} entries, extent index {} entries",
        lbamap.len(),
        extent_index.len()
    );

    Ok(Some((lbamap, extent_index)))
}

/// Attempt to compute deltas for a segment and rewrite it with delta data.
///
/// Returns `Some(delta_path)` if deltas were produced, `None` otherwise.
/// The caller should upload the delta path instead of the original.
pub fn try_rewrite_with_deltas(
    fork_dir: &Path,
    segment_path: &Path,
    delta_path: &Path,
    signer: &dyn SegmentSigner,
) -> io::Result<Option<std::path::PathBuf>> {
    let (parent_lbamap, source_index) = match build_parent_state(fork_dir)? {
        Some(state) => state,
        None => return Ok(None),
    };

    let vk = signing::load_verifying_key(fork_dir, signing::VOLUME_PUB_FILE)?;

    let delta_result =
        match compute_deltas(segment_path, &parent_lbamap, &source_index, fork_dir, &vk)? {
            Some(r) => r,
            None => return Ok(None),
        };

    segment::rewrite_with_deltas(
        segment_path,
        delta_path,
        &delta_result.deltas,
        &delta_result.delta_body,
        signer,
    )?;

    Ok(Some(delta_path.to_owned()))
}
