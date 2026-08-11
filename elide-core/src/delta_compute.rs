// File-aware delta computation for imported readonly volumes.
//
// Runs inside `elide-import` after all pending segments are written but
// before `serve_promote` publishes the control socket. Matches the newly
// imported volume's filemap against each extent_index source's filemap
// by path, and for each changed file fragment with a locally-available
// source body, computes a zstd-dict-compressed delta blob and rewrites
// the pending segment so the matching DATA entry becomes a thin Delta
// entry. The signer stays in the import process — no key material ever
// leaves the volume process.
//
// See docs/design/delta-compression.md §"Filemap-based delta".

use std::borrow::Cow;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};

use ulid::Ulid;

use crate::blake3_id_hasher::Blake3HashSet;
use crate::block_reader::SnapshotSourceMap;
use crate::extentindex::{self, ExtentIndex, ExtentLocation};
use crate::filemap::{self, Filemap};
use crate::segment::{
    self, DeltaOption, EntryKind, SegmentEntry, SegmentSigner, populate_inline_bodies,
    read_and_verify_segment_index, read_body_section_bodies, write_segment_with_delta_body,
};
use crate::signing::{self, VerifyingKey};
use crate::sketch_index::SketchIndex;
use crate::volume;

/// Bytes an extent covers per LBA.
const LBA_BYTES: u64 = 4096;

/// zstd compression level for delta blobs. A blob compresses once at
/// formation and decompresses faster as the level rises, so the level is
/// paid for in formation CPU alone. Level 9 measures 34% smaller than
/// level 3 on the import corpus for 3.4x the compression time.
pub(crate) const ZSTD_LEVEL: i32 = 9;

/// Byte budget for the per-pass source plaintext cache.
///
/// Sources average a few hundred KiB, so an unbounded cache holds every
/// distinct source a pass touches: measured at 5.4 MiB for a median
/// formation and 113 MiB for the largest. Bounding trades that tail for
/// re-reads of evicted sources, which come from cache files written
/// minutes earlier and are usually already in page cache.
const SOURCE_CACHE_BYTES: usize = 32 * 1024 * 1024;

/// Source plaintext held for the duration of one delta pass, bounded by
/// total bytes rather than entry count because source sizes vary by an
/// order of magnitude.
///
/// A source larger than the whole budget is still cached, as the sole
/// entry — evicting it would leave the pass unable to use it at all.
struct SourceCache {
    entries: lru::LruCache<blake3::Hash, Vec<u8>>,
    bytes: usize,
    budget: usize,
}

impl SourceCache {
    fn new() -> Self {
        Self::with_budget(SOURCE_CACHE_BYTES)
    }

    fn with_budget(budget: usize) -> Self {
        Self {
            entries: lru::LruCache::unbounded(),
            bytes: 0,
            budget,
        }
    }

    /// Take ownership of `plain` as the most recently used entry, evicting
    /// least-recently-used entries until the budget holds.
    fn put(&mut self, hash: blake3::Hash, plain: Vec<u8>) {
        self.bytes += plain.len();
        if let Some((_, replaced)) = self.entries.push(hash, plain) {
            self.bytes -= replaced.len();
        }
        while self.bytes > self.budget && self.entries.len() > 1 {
            match self.entries.pop_lru() {
                Some((_, evicted)) => self.bytes -= evicted.len(),
                None => break,
            }
        }
    }

    /// Source plaintext for `hash`, reading it if absent, with `true` when
    /// the cache served it. `None` when the source could not be read.
    fn get_or_read(
        &mut self,
        hash: &blake3::Hash,
        extent_index: &ExtentIndex,
        search_dirs: &[PathBuf],
    ) -> Option<(&[u8], bool)> {
        let hit = self.entries.contains(hash);
        if !hit {
            let plain = read_source_plaintext(extent_index, search_dirs, hash)?;
            self.put(*hash, plain);
        }
        self.entries.get(hash).map(|v| (v.as_slice(), hit))
    }
}

/// Compressed length of `plain` with no dictionary, at [`ZSTD_LEVEL`].
fn dictionaryless_len(plain: &[u8]) -> io::Result<usize> {
    zstd::bulk::compress(plain, ZSTD_LEVEL)
        .map(|blob| blob.len())
        .map_err(|e| io::Error::other(format!("zstd control compression failed: {e}")))
}

/// Whether a delta of `delta_len` bytes earns its place for an entry whose
/// body occupies `stored_length` bytes and decompresses to `plain`.
///
/// Two bars. The delta must not grow the stored bytes, and it must beat
/// what plain zstd achieves on the same plaintext. Beating only the stored
/// lz4 body shows that zstd is the stronger codec, not that the dictionary
/// contributed anything.
fn delta_is_worth_storing(delta_len: usize, stored_length: u32, plain: &[u8]) -> io::Result<bool> {
    if delta_len >= stored_length as usize {
        return Ok(false);
    }
    Ok(delta_len < dictionaryless_len(plain)?)
}

/// Upper bound on the uncompressed size of a delta-dict decompression.
///
/// A delta blob decodes to one extent, so this is the bound every decoder
/// applies to extent plaintext. Importing one Ubuntu cloud image produces a
/// 62.2 MiB extent, so a bound below that turns a delta over a large import
/// fragment into a read error.
pub const DELTA_DECOMPRESS_CAP: usize = segment::MAX_EXTENT_PLAINTEXT;

/// Apply a delta blob to its base body, reconstructing the composite
/// body bytes. Uses the base as a zstd dictionary.
///
/// `base_body` is the uncompressed bytes of the source extent that the
/// delta was computed against (via `zstd::bulk::Compressor::with_dictionary`
/// in the write path). `delta_blob` is the compressed payload stored in
/// the delta body section of the Delta entry's segment.
///
/// Decompression output is capped at [`DELTA_DECOMPRESS_CAP`].
pub fn apply_delta(base_body: &[u8], delta_blob: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoder = zstd::bulk::Decompressor::with_dictionary(base_body)
        .map_err(|e| io::Error::other(format!("zstd dict decoder: {e}")))?;
    decoder
        .decompress(delta_blob, DELTA_DECOMPRESS_CAP)
        .map_err(|e| io::Error::other(format!("zstd decompress: {e}")))
}

/// Summary of delta work performed for a single pending volume.
#[derive(Debug, Default)]
pub struct DeltaStats {
    /// Number of pending segments that had one or more entries converted.
    pub segments_rewritten: usize,
    /// Total Data-to-Delta conversions across all rewritten segments.
    pub entries_converted: usize,
    /// Sum of original `stored_length` for converted entries (before
    /// conversion). Zero after conversion because Delta entries reserve
    /// no body space.
    pub original_body_bytes: u64,
    /// Sum of delta blob sizes produced.
    pub delta_body_bytes: u64,
}

/// Compute and apply filemap-based deltas for a freshly imported volume.
///
/// `vol_dir` is the newly imported volume (`pending/` populated, filemap
/// written, `volume.provenance` signed). `by_id_dir` is the parent
/// directory so extent-index ancestors can be resolved.
///
/// Resolution of the lineage and filemap matching runs per source so
/// each source's filemap is paired with its own extent index — this is
/// how we know which source volume's on-disk bytes to read when we find
/// a delta candidate.
///
/// Returns `Ok(DeltaStats::default())` when there is nothing to do
/// (no lineage, no snapshot, no filemap, no convertible entries).
pub fn rewrite_pending_with_deltas(
    vol_dir: &Path,
    by_id_dir: &Path,
    signer: &dyn SegmentSigner,
) -> io::Result<DeltaStats> {
    // Resolve the child's latest snapshot and filemap. No snapshot =
    // nothing was written = nothing to delta.
    let Some(child_snap_ulid) = volume::latest_snapshot(vol_dir)? else {
        return Ok(DeltaStats::default());
    };
    let child_filemap_path = vol_dir
        .join("snapshots")
        .join(format!("{child_snap_ulid}.filemap"));
    if !child_filemap_path.exists() {
        // A non-ext4 or zero-sized import produces no filemap; silently skip.
        return Ok(DeltaStats::default());
    }
    let child_filemap = filemap::read(&child_filemap_path)?;

    // Walk the signed extent-index ancestors. Empty list is the common
    // case for a standalone (non-parented) import — nothing to delta.
    let ancestors = volume::walk_extent_ancestors(vol_dir, by_id_dir)?;
    if ancestors.is_empty() {
        return Ok(DeltaStats::default());
    }

    // Match the child filemap against each source independently. Per
    // source: load its filemap, rebuild its (standalone) extent index
    // so hash lookups resolve to segments inside that specific source
    // volume's directory. A hash that appears in multiple sources is
    // resolved by whichever source is walked first — extent-index
    // ancestors are already deduped at import time.
    //
    // Accumulates child-hash → (source_hash, delta_blob) across all
    // sources. The actual segment rewrite happens after matching so
    // a child segment containing conversions from multiple sources is
    // written once.
    let mut conversions: HashMap<blake3::Hash, Conversion> = HashMap::new();

    for layer in &ancestors {
        let source_dir = &layer.dir;
        let source_snap = match layer.branch_ulid.clone() {
            Some(u) => u,
            None => match volume::latest_snapshot(source_dir)? {
                Some(u) => u.to_string(),
                None => continue,
            },
        };
        let source_filemap_path = source_dir
            .join("snapshots")
            .join(format!("{source_snap}.filemap"));
        if !source_filemap_path.exists() {
            // Snapshot-time filemap generation no longer runs at release
            // time. Operators wanting delta compression must run
            // `elide volume generate-filemap <source>` first; without a
            // source filemap there is nothing to match against, so skip.
            continue;
        }
        let source_filemap = filemap::read(&source_filemap_path)?;

        let source_chain: Vec<(PathBuf, Option<String>)> =
            vec![(source_dir.clone(), Some(source_snap.clone()))];
        // Source-body resolution only — ownership preference is
        // irrelevant to which bytes a hash resolves to.
        let source_index = extentindex::rebuild(&source_chain)?;

        match_filemaps_into(
            &child_filemap,
            &source_filemap,
            &source_index,
            source_dir,
            &mut conversions,
        )?;
    }

    if conversions.is_empty() {
        return Ok(DeltaStats::default());
    }

    // Verifying key for reading the pending segments we just signed.
    let vk = signing::load_verifying_key(vol_dir, signing::VOLUME_PUB_FILE)?;

    // Rewrite every pending segment that contains at least one entry
    // matching the conversion map.
    let pending_dir = segment::pending_open_dir(vol_dir);
    let mut stats = DeltaStats::default();
    let mut entries_iter = fs::read_dir(&pending_dir)?;
    while let Some(entry) = entries_iter.next().transpose()? {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if name.ends_with(".tmp") {
            continue;
        }
        if Ulid::from_string(name).is_err() {
            continue;
        }
        let seg_path = entry.path();

        let seg_stats = maybe_rewrite_segment(&seg_path, &conversions, signer, &vk)?;
        if seg_stats.entries_converted > 0 {
            stats.segments_rewritten += 1;
            stats.entries_converted += seg_stats.entries_converted;
            stats.original_body_bytes += seg_stats.original_body_bytes;
            stats.delta_body_bytes += seg_stats.delta_body_bytes;
        }
    }

    Ok(stats)
}

struct Conversion {
    source_hash: blake3::Hash,
    delta_blob: Vec<u8>,
}

/// Walk both filemaps grouped by path, pair fragments by
/// `(file_offset, byte_count)`, and for each differing-hash pair where
/// the source body is locally available, compute a zstd-dict delta and
/// insert it into `out`. A child hash already present in `out` (from
/// an earlier source) is kept — first source wins.
fn match_filemaps_into(
    child: &Filemap,
    source: &Filemap,
    source_index: &ExtentIndex,
    source_dir: &Path,
    out: &mut HashMap<blake3::Hash, Conversion>,
) -> io::Result<()> {
    for path in child.paths() {
        let Some(child_frags) = child.fragments(path) else {
            continue;
        };
        let Some(source_frags) = source.fragments(path) else {
            continue; // new file in child, no delta candidate
        };
        if child_frags.len() != source_frags.len() {
            // Fragmented layout mismatch — skip this file entirely.
            // Graceful degradation per design doc §"Multi-extent files".
            continue;
        }
        // Fragment layouts match iff every (file_offset, byte_count)
        // tuple lines up. Both sides are sorted by file_offset.
        let layouts_match = child_frags
            .iter()
            .zip(source_frags.iter())
            .all(|(c, s)| c.file_offset == s.file_offset && c.byte_count == s.byte_count);
        if !layouts_match {
            continue;
        }

        for (child_frag, source_frag) in child_frags.iter().zip(source_frags.iter()) {
            if child_frag.hash == source_frag.hash {
                continue; // unchanged — dedup handles it
            }
            if out.contains_key(&child_frag.hash) {
                continue; // already produced a delta against an earlier source
            }
            // Source body must resolve locally — we never fetch from S3
            // just to compute a delta.
            let Some(loc) = source_index.lookup(&source_frag.hash) else {
                continue;
            };
            let Ok(source_plain) = read_source_extent(source_dir, loc, &source_frag.hash) else {
                continue;
            };

            out.insert(
                child_frag.hash,
                Conversion {
                    source_hash: source_frag.hash,
                    // Placeholder; filled in during the segment pass
                    // where we also have the child body bytes.
                    delta_blob: source_plain,
                },
            );
        }
    }
    Ok(())
}

/// Rewrite one pending segment if it contains entries whose hashes are
/// in the conversion map. For matching entries, computes the zstd
/// delta against the source body (currently stashed in
/// `Conversion::delta_blob` as plaintext), replaces the stored blob
/// with the compressed delta, accumulates it into the segment's delta
/// body section, and re-signs the segment via `signer`.
fn maybe_rewrite_segment(
    seg_path: &Path,
    conversions: &HashMap<blake3::Hash, Conversion>,
    signer: &dyn SegmentSigner,
    vk: &VerifyingKey,
) -> io::Result<SegmentDeltaStats> {
    let (body_section_start, mut entries, _inputs) = read_and_verify_segment_index(seg_path, vk)?;

    let any_match = entries
        .iter()
        .any(|e| e.kind == EntryKind::Data && conversions.contains_key(&e.hash));
    if !any_match {
        return Ok(SegmentDeltaStats::default());
    }

    // Load body bytes for all body-section entries so the rewrite can copy
    // unconverted bodies through verbatim. `DATA_KINDS` covers Data and
    // CanonicalData; delta_compute inputs are fresh imports today so
    // canonical variants don't appear in practice, but the filter aligns
    // with `is_data()` so any future canonical inputs are handled.
    // Inline bytes must ride along for the rewrite — the writer emits the
    // inline section from `entry.inline`.
    let has_inline = entries.iter().any(|e| e.kind.is_inline());
    if has_inline {
        let inline_bytes = read_inline_section(seg_path, &entries)?;
        populate_inline_bodies(&mut entries, &inline_bytes)?;
    }
    let mut pendings = read_body_section_bodies(seg_path, body_section_start, entries)?;

    let mut delta_body: Vec<u8> = Vec::new();
    let mut stats = SegmentDeltaStats::default();

    for pending in pendings.iter_mut() {
        let entry = &mut pending.entry;
        if entry.kind != EntryKind::Data {
            continue;
        }
        let Some(conv) = conversions.get(&entry.hash) else {
            continue;
        };
        let Some(stored) = pending.body.as_deref() else {
            continue;
        };
        let child_plain = entry.codec.decode(Cow::Borrowed(stored))?;
        let child_plain: &[u8] = &child_plain;

        let delta_blob = zstd::bulk::Compressor::with_dictionary(ZSTD_LEVEL, &conv.delta_blob)
            .map_err(|e| io::Error::other(format!("zstd compressor init failed: {e}")))?
            .compress(child_plain)
            .map_err(|e| io::Error::other(format!("zstd delta compression failed: {e}")))?;

        if !delta_is_worth_storing(delta_blob.len(), entry.stored_length, child_plain)? {
            continue;
        }

        let delta_offset = delta_body.len() as u64;
        let delta_length = delta_blob.len() as u32;
        let delta_hash = blake3::hash(&delta_blob);
        delta_body.extend_from_slice(&delta_blob);

        stats.original_body_bytes += entry.stored_length as u64;
        stats.delta_body_bytes += delta_length as u64;
        stats.entries_converted += 1;

        // Convert entry in place. Clear body bookkeeping, drop the body,
        // add delta option, flip the kind.
        let entry = &mut pending.entry;
        entry.kind = EntryKind::Delta;
        entry.stored_offset = 0;
        entry.stored_length = 0;
        entry.codec = segment::Codec::None;
        entry.delta_options.push(DeltaOption {
            source_hash: conv.source_hash,
            delta_offset,
            delta_length,
            delta_hash,
        });
        pending.body = None;
    }

    if stats.entries_converted == 0 {
        return Ok(stats);
    }

    // Write to a tmp sibling then rename atomically. The writer checks
    // that every remaining Data entry still has its loaded body.
    let tmp_path = {
        let mut name = seg_path
            .file_name()
            .ok_or_else(|| io::Error::other("segment path has no filename"))?
            .to_owned();
        name.push(".delta.tmp");
        seg_path.with_file_name(name)
    };
    let _ = fs::remove_file(&tmp_path);
    write_segment_with_delta_body(&tmp_path, pendings, &delta_body, signer)?;
    fs::rename(&tmp_path, seg_path)?;
    segment::fsync_dir(seg_path)?;

    Ok(stats)
}

/// Read the inline section bytes from a full segment file. The inline
/// section sits between the index section and the body section; its
/// length comes from the header. Returned bytes are passed to
/// `read_extent_bodies` as `inline_bytes`.
fn read_inline_section(seg_path: &Path, entries: &[SegmentEntry]) -> io::Result<Vec<u8>> {
    // Inline section length = sum of stored_length of Inline / CanonicalInline
    // entries. Position = body_section_start - inline_length.
    let layout = segment::read_segment_layout(seg_path)?;
    let inline_length: u64 = entries
        .iter()
        .filter(|e| e.kind.is_inline())
        .map(|e| e.stored_length as u64)
        .sum();
    if inline_length == 0 {
        return Ok(Vec::new());
    }
    let inline_start = layout.body_section_start - inline_length;
    let f = fs::File::open(seg_path)?;
    let mut buf = vec![0u8; inline_length as usize];
    f.read_exact_at(&mut buf, inline_start)?;
    Ok(buf)
}

/// Read the full plaintext for a source extent, verified against `hash`.
///
/// Inline entries are served directly from `loc.inline_data`, which the
/// extent-index rebuild already populates from the source segment's
/// `.idx` inline section — the `body_offset`/`body_length` fields on
/// an Inline location are inline-section-relative and must not be used
/// as a body seek. For non-inline entries, resolve the segment body
/// via `segment::locate_segment_body_from` (the home the entry names,
/// then the canonical precedence wal → pending → bare gc/<id> →
/// cache/.body) and pick the seek arithmetic from the returned layout:
/// body-only files seek at `body_offset` alone, full segment files seek
/// at `body_section_start + body_offset`.
///
/// Errors when the plaintext fails its content hash: a wrong local read
/// used as a dictionary would form a delta that can never reconstruct,
/// while the caller skipping this candidate loses nothing but a delta.
fn read_source_extent(
    source_dir: &Path,
    loc: &ExtentLocation,
    hash: &blake3::Hash,
) -> io::Result<Vec<u8>> {
    let stored = if let Some(inline) = loc.inline_data.as_deref() {
        inline.to_vec()
    } else {
        let (path, layout) =
            segment::locate_segment_body_from(source_dir, loc.segment_id, loc.body_source.home())
                .ok_or_else(|| {
                io::Error::other(format!(
                    "source extent segment {} not found under {}",
                    loc.segment_id,
                    source_dir.display()
                ))
            })?;
        let f = fs::File::open(&path)?;
        let mut buf = vec![0u8; loc.body_length as usize];
        f.read_exact_at(&mut buf, layout.body_seek(loc))?;
        buf
    };
    let plain = loc.codec.decode(Cow::Owned(stored))?.into_owned();
    verify_source_plaintext(&plain, hash, loc.segment_id)?;
    Ok(plain)
}

/// Refuse source plaintext that fails its content hash.
fn verify_source_plaintext(
    plain: &[u8],
    expected: &blake3::Hash,
    segment_id: Ulid,
) -> io::Result<()> {
    let got = blake3::hash(plain);
    if got == *expected {
        return Ok(());
    }
    log::error!(
        "delta source failed its content check: segment={segment_id} expected={} got={} ({} bytes)",
        expected.to_hex(),
        got.to_hex(),
        plain.len(),
    );
    Err(io::Error::other(format!(
        "source extent hashed {} instead of {} ({} bytes)",
        got.to_hex(),
        expected.to_hex(),
        plain.len()
    )))
}

#[derive(Default, Debug)]
pub struct SegmentDeltaStats {
    pub entries_converted: usize,
    pub original_body_bytes: u64,
    pub delta_body_bytes: u64,
    /// Pendings left as `Data` because another pending in the batch
    /// deltas against their content. See [`reserved_delta_sources`].
    pub entries_reserved_as_sources: usize,
}

/// Full plaintext of the Data/Inline extent `hash` resolves to, for use
/// as a delta dictionary. `None` when the hash has no DATA-map location
/// (a delta-backed hash never serves as a source — no delta-of-delta
/// chains), when a cached body's presence bit is unset (reading a sparse
/// hole would silently dictionary against zeros), when the plaintext
/// fails its content hash (a delta formed against wrong bytes can never
/// reconstruct), or when the bytes cannot be read — the delta tier is
/// best-effort and never fetches.
fn read_source_plaintext(
    extent_index: &ExtentIndex,
    search_dirs: &[PathBuf],
    hash: &blake3::Hash,
) -> Option<Vec<u8>> {
    let loc = extent_index.lookup(hash)?;
    let plain = if let Some(ref idata) = loc.inline_data {
        loc.codec.decode(Cow::Borrowed(idata)).ok()?.into_owned()
    } else {
        if let extentindex::BodySource::Cached(entry_idx) = loc.body_source {
            let present = extent_index
                .segment_presence(loc.segment_id)
                .is_some_and(|p| p.test(entry_idx));
            if !present {
                return None;
            }
        }
        let home = loc.body_source.home();
        let (path, layout) = search_dirs
            .iter()
            .find_map(|d| segment::locate_segment_body_from(d, loc.segment_id, home))?;
        let f = fs::File::open(&path).ok()?;
        let mut buf = vec![0u8; loc.body_length as usize];
        f.read_exact_at(&mut buf, layout.body_seek(loc)).ok()?;
        loc.codec.decode(Cow::Owned(buf)).ok()?.into_owned()
    };
    verify_source_plaintext(&plain, hash, loc.segment_id).ok()?;
    Some(plain)
}

/// How far down the ranked candidates to look for a source whose body is
/// locally readable.
///
/// Depth, not search width. Only one candidate is ever compressed against:
/// a delta that fails the keep rule ends the target, because round 2 found
/// no case where a lower-ranked source cleared the bar after the top-ranked
/// one lost. What this bounds is how many candidates can be skipped for
/// having no readable body, which the map cannot see.
const MAX_RESEMBLANCE_CANDIDATES: usize = 4;

/// Counters for one resemblance pass.
#[derive(Debug, Default)]
pub struct ResemblanceStats {
    pub delta: SegmentDeltaStats,
    /// Targets whose sketch was probed against the map.
    pub targets_probed: u64,
    /// Candidate dictionaries read and compressed against.
    pub candidates_tried: u64,
    /// Source plaintext read to seed dictionaries, before caching.
    pub dictionary_bytes_read: u64,
    /// Attempts served by the per-formation source cache rather than a
    /// read. `candidates_tried - dictionary_cache_hits` is the number of
    /// distinct sources read, so the two together give the mean source
    /// size and say how much a prepared dictionary would be reused.
    pub dictionary_cache_hits: u64,
    /// Candidates declined for being unreferenced when the job was
    /// prepared. A persistently high count means the map is holding dead
    /// sources, which is expected on a churning volume.
    pub candidates_unreferenced: u64,
}

/// Convert `Data` pendings to thin `Delta` entries against sources the
/// candidate map says resemble them.
///
/// Runs after the same-LBA tier, over the entries it left alone, and needs
/// no snapshot: `sketches` spans whatever the lineage held at open plus what
/// later promotes appended. Delta blobs append to `delta_body`, which the
/// same-LBA tier may already have filled.
///
/// Best-effort like every delta tier. A target too small to sketch, a
/// sketch with no candidate, a candidate whose body is not locally readable,
/// and a delta that fails the keep rule all leave the entry as the `Data`
/// entry it was.
///
/// A candidate can never come from this same batch, since the map is fed
/// after a promote commits, so no conversion here can leave another
/// conversion's source pointing at a `Delta`.
///
/// `reserved` carries the converse: hashes the same-LBA tier named as
/// delta sources over this same batch, whose pendings must keep their
/// bodies. See [`reserved_delta_sources`].
pub fn delta_pendings_by_resemblance(
    pendings: &mut [segment::PendingEntry],
    sketches: &SketchIndex,
    extent_index: &ExtentIndex,
    referenced: &crate::lbamap::ReferencedHashes,
    search_dirs: &[PathBuf],
    delta_body: &mut Vec<u8>,
    reserved: &Blake3HashSet,
) -> io::Result<ResemblanceStats> {
    let mut stats = ResemblanceStats::default();
    if sketches.is_empty() {
        return Ok(stats);
    }
    let mut source_cache = SourceCache::new();

    for pending in pendings.iter_mut() {
        let entry = &pending.entry;
        // The same-LBA tier converts before this one, and a delta-bearing
        // entry cannot take a second source.
        if entry.kind != EntryKind::Data || !entry.delta_options.is_empty() {
            continue;
        }
        if entry.journal {
            continue;
        }
        let raw_len = entry.lba_length as u64 * LBA_BYTES;
        if raw_len < crate::sketch::MIN_SKETCH_BYTES as u64 {
            continue;
        }
        let Some(stored) = pending.body.as_deref() else {
            continue;
        };
        if reserved.contains(&entry.hash) {
            stats.delta.entries_reserved_as_sources += 1;
            continue;
        }

        let child_plain = entry.codec.decode(Cow::Borrowed(stored))?;
        let child_plain: &[u8] = &child_plain;
        let Some(target_sketch) = crate::sketch::compute(child_plain) else {
            continue;
        };
        stats.targets_probed += 1;

        let mut converted = None;
        for cand in sketches.candidates(&target_sketch, MAX_RESEMBLANCE_CANDIDATES) {
            // A source that is its own target would be a delta naming its
            // own hash, which nothing can resolve. Exact-hash dedup runs
            // before this tier and takes that case.
            if cand.hash == entry.hash {
                continue;
            }
            // Deltaing against an unreferenced source costs twice over. It
            // pins bytes GC was about to free, to save a delta a fraction
            // of their size. And it makes the hash referenced again, so the
            // GC plan that omitted it is refused on apply and a whole pass
            // of rewrites and uploads is discarded.
            //
            // The map is a never-pruned cache built from historical `.idx`
            // walks, so it offers dead sources for as long as the process
            // lives, and a dead extent resembles whatever superseded it —
            // the likeliest-dead candidates rank first.
            //
            // This is a cost measure. Correctness rests on the plan apply
            // being ordered behind in-flight promotes and on stale-liveness
            // cancellation, both of which hold without it
            // (`specs/DeltaSourceLiveness.tla`).
            if !referenced.contains(&cand.hash) {
                stats.candidates_unreferenced += 1;
                continue;
            }
            let Some((source_plain, hit)) =
                source_cache.get_or_read(&cand.hash, extent_index, search_dirs)
            else {
                continue;
            };
            if hit {
                stats.dictionary_cache_hits += 1;
            } else {
                stats.dictionary_bytes_read += source_plain.len() as u64;
            }
            stats.candidates_tried += 1;

            let delta_blob = zstd::bulk::Compressor::with_dictionary(ZSTD_LEVEL, source_plain)
                .map_err(|e| io::Error::other(format!("zstd compressor init failed: {e}")))?
                .compress(child_plain)
                .map_err(|e| io::Error::other(format!("zstd delta compression failed: {e}")))?;

            if !delta_is_worth_storing(delta_blob.len(), entry.stored_length, child_plain)? {
                // Tried and lost, which is a fact about this target rather
                // than this source. Trying further down the ranking was
                // measured to rescue nothing.
                break;
            }
            converted = Some((cand.hash, delta_blob));
            break;
        }

        let entry = &mut pending.entry;
        let Some((source_hash, delta_blob)) = converted else {
            // Formation computes a sketch for every fresh Data entry; hand
            // over the one already computed so the segment write does not
            // repeat it.
            entry.sketch = Some(target_sketch);
            continue;
        };

        let delta_offset = delta_body.len() as u64;
        let delta_length = delta_blob.len() as u32;
        let delta_hash = blake3::hash(&delta_blob);
        delta_body.extend_from_slice(&delta_blob);

        stats.delta.original_body_bytes += entry.stored_length as u64;
        stats.delta.delta_body_bytes += delta_length as u64;
        stats.delta.entries_converted += 1;

        entry.kind = EntryKind::Delta;
        entry.stored_offset = 0;
        entry.stored_length = 0;
        entry.codec = segment::Codec::None;
        // A delta-bearing entry is not a valid source, so it advertises no
        // sketch.
        entry.sketch = None;
        entry.delta_options.push(DeltaOption {
            source_hash,
            delta_offset,
            delta_length,
            delta_hash,
        });
        pending.body = None;
    }

    Ok(stats)
}

/// Convert single-block `Data` pendings to thin `Delta` entries wherever
/// `prior` holds a different same-LBA extent whose body is locally
/// present and the zstd-dict delta beats the stored size. Runs at segment
/// formation, on the materialised pendings, before the segment is
/// written.
///
/// `prior` is the [`SnapshotSourceMap`] of the latest sealed snapshot;
/// source bodies are resolved by hash through `extent_index` (the live
/// index — any canonical serving the hash yields identical bytes) and
/// read from `search_dirs`. A source not locally readable is skipped,
/// never fetched from S3 to seed a dictionary. Multi-block entries are
/// left alone.
///
/// Returns the delta body region (each converted entry's `delta_offset`
/// indexes into it) and the conversion stats, along with the hashes this
/// pass reserved as delta sources — see [`reserved_delta_sources`]. Pass
/// that set to [`delta_pendings_by_resemblance`], which runs over the
/// same batch and would otherwise convert one of them.
pub fn delta_pendings_against_prior(
    pendings: &mut [segment::PendingEntry],
    prior: &SnapshotSourceMap,
    extent_index: &ExtentIndex,
    search_dirs: &[PathBuf],
) -> io::Result<(Vec<u8>, SegmentDeltaStats, Blake3HashSet)> {
    let mut delta_body: Vec<u8> = Vec::new();
    let mut stats = SegmentDeltaStats::default();
    let mut source_cache = SourceCache::new();
    let reserved = reserved_delta_sources(pendings, prior);

    for pending in pendings.iter_mut() {
        let entry = &pending.entry;
        if entry.kind != EntryKind::Data || entry.lba_length != 1 {
            continue;
        }
        let Some(source_hash) = prior.hash_for_lba(entry.start_lba) else {
            continue;
        };
        if source_hash == entry.hash {
            // Same content as prior snapshot — dedup handles this via
            // hash equality; nothing to delta.
            continue;
        }
        let Some(stored) = pending.body.as_deref() else {
            continue;
        };
        if reserved.contains(&entry.hash) {
            stats.entries_reserved_as_sources += 1;
            continue;
        }

        // Fetch source plaintext (cached per source hash — a hot file
        // being rewritten at multiple LBAs shares its dictionary).
        let Some((source_plain, _hit)) =
            source_cache.get_or_read(&source_hash, extent_index, search_dirs)
        else {
            continue;
        };

        let child_plain = entry.codec.decode(Cow::Borrowed(stored))?;
        let child_plain: &[u8] = &child_plain;

        let delta_blob = zstd::bulk::Compressor::with_dictionary(ZSTD_LEVEL, source_plain)
            .map_err(|e| io::Error::other(format!("zstd compressor init failed: {e}")))?
            .compress(child_plain)
            .map_err(|e| io::Error::other(format!("zstd delta compression failed: {e}")))?;

        if !delta_is_worth_storing(delta_blob.len(), entry.stored_length, child_plain)? {
            continue;
        }

        let delta_offset = delta_body.len() as u64;
        let delta_length = delta_blob.len() as u32;
        let delta_hash = blake3::hash(&delta_blob);
        delta_body.extend_from_slice(&delta_blob);

        stats.original_body_bytes += entry.stored_length as u64;
        stats.delta_body_bytes += delta_length as u64;
        stats.entries_converted += 1;

        let entry = &mut pending.entry;
        entry.kind = EntryKind::Delta;
        entry.stored_offset = 0;
        entry.stored_length = 0;
        entry.codec = segment::Codec::None;
        entry.delta_options.push(DeltaOption {
            source_hash,
            delta_offset,
            delta_length,
            delta_hash,
        });
        pending.body = None;
    }

    Ok((delta_body, stats, reserved))
}

/// The hashes a formation batch must leave carrying a body.
///
/// Each is the prior-snapshot content some single-block pending sits on
/// top of, so a conversion in this batch may name it as a delta source.
/// A delta source resolves through the DATA map alone
/// (`try_read_delta_extent` consults no other), so a pending carrying
/// one of these hashes has to stay `Data` — converting it strips the
/// body and leaves a delta naming a delta, which no read can resolve.
///
/// Computed up front over every eligible pending rather than accumulated
/// as conversions happen: the extent index this pass consults is a
/// snapshot taken before it, so it cannot see the batch's own
/// conversions, and a set built as the loop runs would make the outcome
/// depend on pending order.
///
/// A superset of the sources actually named — a candidate whose body is
/// unreadable or whose delta loses the keep rule reserves its source
/// anyway. The cost of that is one declined conversion in a batch that
/// both rewrites an LBA and re-lands its prior content elsewhere.
fn reserved_delta_sources(
    pendings: &[segment::PendingEntry],
    prior: &SnapshotSourceMap,
) -> Blake3HashSet {
    pendings
        .iter()
        .filter(|p| p.entry.kind == EntryKind::Data && p.entry.lba_length == 1)
        .filter_map(|p| prior.hash_for_lba(p.entry.start_lba))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Text-like content that zstd compresses substantially better than
    /// lz4, which is what makes the two bars distinguishable.
    fn compressible(len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut i = 0u32;
        while out.len() < len {
            out.extend_from_slice(format!("record {i} field=value status=ok\n").as_bytes());
            i += 1;
        }
        out.truncate(len);
        out
    }

    #[test]
    fn delta_larger_than_the_stored_body_is_rejected() {
        let plain = compressible(8192);
        let stored = lz4_flex::compress_prepend_size(&plain).len() as u32;
        assert!(!delta_is_worth_storing(stored as usize, stored, &plain).expect("gate"));
        assert!(!delta_is_worth_storing(stored as usize + 1, stored, &plain).expect("gate"));
    }

    #[test]
    fn delta_must_beat_plain_zstd_not_just_the_stored_body() {
        let plain = compressible(8192);
        let stored = lz4_flex::compress_prepend_size(&plain).len() as u32;
        let plain_zstd = dictionaryless_len(&plain).expect("control");
        assert!(
            plain_zstd < stored as usize,
            "fixture needs zstd to beat lz4 ({plain_zstd} vs {stored})"
        );

        // Between the two bars: smaller than the stored body, but the
        // dictionary added nothing a plain zstd encode would not have.
        let between = (plain_zstd + stored as usize) / 2;
        assert!(!delta_is_worth_storing(between, stored, &plain).expect("gate"));

        assert!(delta_is_worth_storing(plain_zstd - 1, stored, &plain).expect("gate"));
    }

    /// An import fragment can be far larger than a guest write, and a delta
    /// over one decodes to the whole extent. Measured: importing one Ubuntu
    /// cloud image produces a 62.2 MiB extent, which the previous 16 MiB
    /// bound turned into a read error.
    #[test]
    fn a_delta_over_an_extent_larger_than_a_guest_write_applies() {
        let base: Vec<u8> = (0..24 << 20).map(|i| (i / 97 % 251) as u8).collect();
        let mut target = base.clone();
        target[1 << 20..2 << 20].fill(0x5A);

        let blob = zstd::bulk::Compressor::with_dictionary(ZSTD_LEVEL, &base)
            .expect("compressor")
            .compress(&target)
            .expect("compress");

        assert!(
            base.len() > 16 * 1024 * 1024,
            "the fixture has to exceed the bound this covers"
        );
        assert_eq!(apply_delta(&base, &blob).expect("apply"), target);
    }

    /// A zstd frame declares its window, its content size and optionally a
    /// dictionary id, never the level that produced it, which is what makes
    /// `ZSTD_LEVEL` a write-time choice with no read-time dependency.
    #[test]
    fn blobs_apply_regardless_of_the_level_that_produced_them() {
        let base = compressible(64 * 1024);
        let mut target = base.clone();
        target[4096..8192].fill(b'x');

        for level in [1, 3, ZSTD_LEVEL, 19] {
            let blob = zstd::bulk::Compressor::with_dictionary(level, &base)
                .expect("compressor")
                .compress(&target)
                .expect("compress");
            assert_eq!(
                apply_delta(&base, &blob).expect("apply"),
                target,
                "level {level}"
            );
        }
    }
}

#[cfg(test)]
mod source_cache_tests {
    use super::*;

    fn h(n: u8) -> blake3::Hash {
        blake3::hash(&[n])
    }

    #[test]
    fn evicts_least_recently_used_once_the_budget_is_exceeded() {
        let mut cache = SourceCache::with_budget(1000);
        cache.put(h(1), vec![0u8; 400]);
        cache.put(h(2), vec![0u8; 400]);
        // Touching 1 makes 2 the least recently used.
        assert!(cache.entries.get(&h(1)).is_some());
        cache.put(h(3), vec![0u8; 400]);

        assert!(cache.bytes <= 1000, "budget held: {}", cache.bytes);
        assert!(cache.entries.contains(&h(1)), "recently used survives");
        assert!(
            !cache.entries.contains(&h(2)),
            "least recently used evicted"
        );
        assert!(cache.entries.contains(&h(3)));
    }

    #[test]
    fn keeps_a_source_larger_than_the_whole_budget() {
        let mut cache = SourceCache::with_budget(1000);
        cache.put(h(1), vec![0u8; 4000]);

        assert!(cache.entries.contains(&h(1)));
        assert_eq!(cache.bytes, 4000, "an oversized sole entry is not evicted");
    }

    #[test]
    fn an_oversized_entry_is_dropped_once_another_arrives() {
        let mut cache = SourceCache::with_budget(1000);
        cache.put(h(1), vec![0u8; 4000]);
        cache.put(h(2), vec![0u8; 100]);

        assert!(!cache.entries.contains(&h(1)));
        assert_eq!(cache.bytes, 100);
    }

    #[test]
    fn re_putting_the_same_hash_does_not_double_count() {
        let mut cache = SourceCache::with_budget(1000);
        cache.put(h(1), vec![0u8; 300]);
        cache.put(h(1), vec![0u8; 300]);

        assert_eq!(cache.bytes, 300);
        assert_eq!(cache.entries.len(), 1);
    }
}

#[cfg(test)]
mod source_verify_tests {
    use super::*;
    use crate::extentindex::BodySource;

    fn local_loc(segment_id: Ulid, body_length: u32) -> ExtentLocation {
        ExtentLocation {
            segment_id,
            body_offset: 0,
            body_length,
            codec: segment::Codec::None,
            body_source: BodySource::Local,
            body_section_start: 0,
            inline_data: None,
        }
    }

    /// Lay `bytes` down as `pending/<seg>` so `locate_segment_body`
    /// resolves it as a full-layout file with the body at offset 0.
    fn dir_with_body(seg: Ulid, bytes: &[u8]) -> tempfile::TempDir {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        fs::create_dir_all(crate::segment::pending_open_dir(tmp.path())).expect("mkdir");
        fs::write(
            crate::segment::pending_open_dir(tmp.path()).join(seg.to_string()),
            bytes,
        )
        .expect("write");
        tmp
    }

    #[test]
    fn a_source_whose_bytes_match_the_hash_is_served() {
        let seg = Ulid::new();
        let bytes = vec![0xABu8; 4096];
        let tmp = dir_with_body(seg, &bytes);

        let hash = blake3::hash(&bytes);
        let mut index = ExtentIndex::new();
        index.insert(hash, local_loc(seg, 4096));

        let plain = read_source_plaintext(&index, &[tmp.path().to_owned()], &hash)
            .expect("a correct source must be served");
        assert_eq!(plain, bytes);
    }

    #[test]
    fn a_source_whose_bytes_fail_the_content_check_is_skipped() {
        let seg = Ulid::new();
        let tmp = dir_with_body(seg, &vec![0xABu8; 4096]);

        // The index claims a hash the stored bytes do not have — a wrong
        // read must not become a dictionary.
        let claimed = blake3::hash(b"content the file does not hold");
        let mut index = ExtentIndex::new();
        index.insert(claimed, local_loc(seg, 4096));

        assert!(read_source_plaintext(&index, &[tmp.path().to_owned()], &claimed).is_none());
    }

    #[test]
    fn read_source_extent_refuses_bytes_that_fail_the_content_check() {
        let seg = Ulid::new();
        let tmp = dir_with_body(seg, &vec![0xABu8; 4096]);

        let claimed = blake3::hash(b"content the file does not hold");
        let err = read_source_extent(tmp.path(), &local_loc(seg, 4096), &claimed)
            .expect_err("a wrong source read must error, not become a dictionary");
        assert!(
            err.to_string().contains("hashed"),
            "error should report the hash mismatch, got: {err}"
        );
    }
}
