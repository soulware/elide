//! Read path: extent assembly, segment-file lookup across the fork ancestry,
//! and the LRU-of-open-fds the read path uses to amortise `open` syscalls.
//!
//! Pulled out of `volume/mod.rs` for legibility — no behaviour change. The
//! free functions here are the seam between the writable `Volume` and the
//! read-only `ReadonlyVolume` / actor read snapshots: they take a
//! `(lbamap, extent_index, file_cache, dirs, fetcher)` and serve reads
//! without depending on the broader volume actor state.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ulid::Ulid;

use crate::{
    chunk_tree, delta_compute, dmat,
    extentindex::{self, BodySource, SegmentPresence},
    lbamap,
    segment::{self},
};

use super::{AncestorLayer, BoxFetcher, ZERO_HASH};

/// Shared per-volume cache of opened `.dmat` sidecars, keyed by segment
/// ULID. Populated lazily when a Delta entry is first read for a segment.
///
/// One instance per volume per process, shared by every reader thread
/// and snapshot: `Dmat::open_or_create` truncates torn records on disk,
/// and a private instance per reader would run that truncation — and
/// its own appends — concurrently against offsets another instance's
/// map already holds.
pub type DmatCache = Arc<std::sync::Mutex<HashMap<Ulid, dmat::Dmat>>>;

/// Lock a [`DmatCache`], recovering from poisoning: the map only holds
/// rebuildable cache state, and every record served through it is
/// hash-verified by the caller.
fn lock_dmat_cache(cache: &DmatCache) -> std::sync::MutexGuard<'_, HashMap<Ulid, dmat::Dmat>> {
    cache
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Per-thread scratch buffers for compressed-extent reads.
///
/// `compressed` holds the stored bytes pread'd from the segment file;
/// `decompressed` holds the full extent plaintext when the caller wants a
/// sub-range of the extent (decoder output for a coded extent, the pread
/// payload for a raw one — the whole-extent path targets the caller buffer
/// and never touches `decompressed`). Both Vecs grow to the high-water-mark
/// of any read served by this thread and stay there — a declared plaintext
/// length is capped at `segment::MAX_EXTENT_PLAINTEXT`, so total per-thread
/// overhead is bounded.
struct ReadScratch {
    compressed: Vec<u8>,
    decompressed: Vec<u8>,
    /// A chunked extent's table, and the chaining values reconstructed from
    /// it with the decoded chunks' values substituted in.
    table: Vec<u8>,
    cvs: Vec<blake3::hazmat::ChainingValue>,
}

thread_local! {
    static READ_SCRATCH: RefCell<ReadScratch> = const {
        RefCell::new(ReadScratch {
            compressed: Vec::new(),
            decompressed: Vec::new(),
            table: Vec::new(),
            cvs: Vec::new(),
        })
    };
}

/// Refuse extent plaintext that fails its content hash.
///
/// `payload` must be the extent's whole plaintext: the hash covers all of
/// it, so it can only be checked against all of it. A location that
/// resolves to the wrong bytes is otherwise indistinguishable from a
/// correct read — lz4 rejects some of them, raw-stored extents produce
/// no error at all.
fn verify_extent_content(
    expected: &blake3::Hash,
    payload: &[u8],
    lba: u64,
    segment_id: Ulid,
) -> io::Result<()> {
    let got = blake3::hash(payload);
    if got == *expected {
        return Ok(());
    }
    log::error!(
        "content hash mismatch: lba={lba} segment={segment_id} expected={} got={} ({} bytes)",
        expected.to_hex(),
        got.to_hex(),
        payload.len(),
    );
    Err(io::Error::other(format!(
        "extent body hashed {} instead of {} ({} bytes)",
        got.to_hex(),
        expected.to_hex(),
        payload.len()
    )))
}

/// Verify `plain` against the extent's content hash, then copy
/// `src_start..src_end` of it into `out_slice`.
///
/// Every source ends here, so a source arm's job is to produce the extent's
/// plaintext and nothing else. A caller that wants the whole extent can
/// decode into `out_slice` directly and call [`verify_extent_content`] on it.
fn verify_and_slice(
    plain: &[u8],
    expected: &blake3::Hash,
    lba: u64,
    segment_id: Ulid,
    src_start: usize,
    src_end: usize,
    out_slice: &mut [u8],
) -> io::Result<()> {
    verify_extent_content(expected, plain, lba, segment_id)?;
    let src = plain
        .get(src_start..src_end)
        .ok_or_else(|| io::Error::other("corrupt segment: payload too short"))?;
    out_slice.copy_from_slice(src);
    Ok(())
}

/// Serve `src_start..src_end` of a chunked extent, reading and decoding only
/// the chunks that range lands in.
///
/// The chunk table's chaining values are subtree values of the extent's own
/// hash tree, so substituting the values computed from the decoded chunks and
/// reconstructing the root checks the decoded bytes and the unsigned table
/// together, against the hash the signed index carries. That is one
/// reconstruction per read whatever the read's shape.
#[allow(clippy::too_many_arguments)]
fn serve_chunked(
    f: &fs::File,
    file_body_offset: u64,
    body_length: usize,
    expected: &blake3::Hash,
    lba: u64,
    segment_id: Ulid,
    src_start: usize,
    src_end: usize,
    out_slice: &mut [u8],
) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    READ_SCRATCH.with(|s| {
        let mut s = s.borrow_mut();
        let s = &mut *s;

        // The table's own length follows from the plaintext length in its
        // first four bytes, so read a prefix that covers most tables outright
        // and extend it only when one runs longer.
        let prefix = TABLE_READ_PREFIX.min(body_length);
        s.table.resize(prefix, 0);
        f.read_exact_at(&mut s.table, file_body_offset)?;
        let plain_len = chunk_tree::ChunkTable::peek_plain_len(&s.table)?;
        if plain_len > segment::MAX_EXTENT_PLAINTEXT {
            return Err(io::Error::other(format!(
                "chunked payload declares {plain_len} bytes of plaintext, over the {} cap",
                segment::MAX_EXTENT_PLAINTEXT
            )));
        }
        let table_len = chunk_tree::ChunkTable::encoded_len(plain_len);
        if table_len > s.table.len() {
            s.table.resize(table_len, 0);
            f.read_exact_at(&mut s.table, file_body_offset)?;
        }
        let table = chunk_tree::ChunkTable::parse(&s.table)?;

        let wanted = chunk_tree::chunks_covering(src_start, src_end);
        let first = table.chunk_span(wanted.start)?;
        let last = table.chunk_span(wanted.end - 1)?;
        if last.end > body_length {
            return Err(io::Error::other(
                "chunk table spans past the stored payload",
            ));
        }

        // One pread for the run: chunks sit in index order, so the wanted
        // ones are contiguous.
        s.compressed.resize(last.end - first.start, 0);
        f.read_exact_at(&mut s.compressed, file_body_offset + first.start as u64)?;

        s.cvs.clear();
        s.cvs.extend_from_slice(&table.cvs);
        for index in wanted {
            let span = table.chunk_span(index)?;
            let frame = &s.compressed[span.start - first.start..span.end - first.start];
            let plain = chunk_tree::chunk_range(index, plain_len);

            // A chunk wholly inside the caller's range decodes into its
            // buffer; one that only overlaps decodes into the scratch and
            // contributes the overlap. Either way the whole chunk is in hand,
            // which is what its chaining value covers.
            let cv = if plain.start >= src_start && plain.end <= src_end {
                let at = plain.start - src_start;
                let into = &mut out_slice[at..at + plain.len()];
                segment::Codec::Zstd.decode_into(frame, into)?;
                chunk_tree::chunk_cv(index, into)
            } else {
                s.decompressed.resize(plain.len(), 0);
                segment::Codec::Zstd.decode_into(frame, &mut s.decompressed)?;
                let from = src_start.max(plain.start);
                let to = src_end.min(plain.end);
                out_slice[from - src_start..to - src_start]
                    .copy_from_slice(&s.decompressed[from - plain.start..to - plain.start]);
                chunk_tree::chunk_cv(index, &s.decompressed)
            };
            s.cvs[index] = cv;
        }

        let root = chunk_tree::root_from_cvs(&s.cvs, plain_len)?;
        if root != *expected {
            log::error!(
                "content hash mismatch: lba={lba} segment={segment_id} expected={} got={} \
                 ({plain_len} bytes over {} chunks)",
                expected.to_hex(),
                root.to_hex(),
                s.cvs.len(),
            );
            return Err(io::Error::other(format!(
                "extent body hashed {} instead of {} ({plain_len} bytes)",
                root.to_hex(),
                expected.to_hex()
            )));
        }
        Ok(())
    })
}

/// First read of a chunk table. Covers a table for an extent up to about
/// 14 MiB, so a second read is the tail of the size distribution.
const TABLE_READ_PREFIX: usize = 4096;

/// Default capacity for the segment file handle LRU cache.
const FILE_CACHE_CAPACITY: usize = 16;

/// The on-disk layout of a cached segment file, which determines how body
/// offsets are interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::volume) enum SegmentLayout {
    /// A full segment file (wal/, pending/, gc/). Body data starts at
    /// `body_section_start` — callers must add it to body-relative offsets.
    Full,
    /// A `.body` cache file (cache/<id>.body). Contains only body bytes
    /// starting at offset 0 — body-relative offsets are file offsets directly.
    BodyOnly,
}

impl SegmentLayout {
    /// Determine the layout from a file path: `.body` extension → `BodyOnly`,
    /// everything else → `Full`.
    fn from_path(path: &Path) -> Self {
        if path.extension().is_some_and(|e| e == "body") {
            Self::BodyOnly
        } else {
            Self::Full
        }
    }
}

/// Approximate-LRU cache of open segment file handles using the CLOCK algorithm.
///
/// Fixed-size ring buffer keyed by segment ULID. Each slot has a `referenced`
/// bit that is set on access. On eviction the clock hand sweeps the ring,
/// clearing referenced bits until it finds an unreferenced slot to evict.
///
/// The hot-path operation (`get`) is a linear scan + flag set — no data
/// movement, no allocation, no pointer chasing.  At 16 slots the scan fits
/// comfortably in L1 cache.
pub(crate) struct FileCache {
    slots: Vec<Option<FileCacheSlot>>,
    hand: usize,
}

struct FileCacheSlot {
    segment_id: Ulid,
    layout: SegmentLayout,
    file: fs::File,
    referenced: bool,
}

impl Default for FileCache {
    fn default() -> Self {
        Self::new(FILE_CACHE_CAPACITY)
    }
}

impl FileCache {
    pub(crate) fn new(capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(capacity);
        slots.resize_with(capacity, || None);
        Self { slots, hand: 0 }
    }

    /// Look up a cached file handle by segment id.
    /// On hit, sets the referenced bit and returns the layout and file handle.
    ///
    /// Returns a shared `&File` because the read path uses positional
    /// (`pread`) reads, which don't touch the file cursor. Holding `&mut`
    /// here would force serialization that the syscall doesn't require.
    pub(in crate::volume) fn get(
        &mut self,
        segment_id: Ulid,
    ) -> Option<(SegmentLayout, &fs::File)> {
        let slot = self
            .slots
            .iter_mut()
            .flatten()
            .find(|s| s.segment_id == segment_id)?;
        slot.referenced = true;
        Some((slot.layout, &slot.file))
    }

    /// Insert a file handle. If the segment is already cached, replaces it
    /// in-place. Otherwise, uses the CLOCK algorithm to find a slot to evict.
    pub(in crate::volume) fn insert(
        &mut self,
        segment_id: Ulid,
        layout: SegmentLayout,
        file: fs::File,
    ) {
        // Replace in-place if already present.
        for slot in self.slots.iter_mut() {
            if slot.as_ref().is_some_and(|s| s.segment_id == segment_id) {
                *slot = Some(FileCacheSlot {
                    segment_id,
                    layout,
                    file,
                    referenced: true,
                });
                return;
            }
        }

        // Fill an empty slot if one exists.
        for slot in self.slots.iter_mut() {
            if slot.is_none() {
                *slot = Some(FileCacheSlot {
                    segment_id,
                    layout,
                    file,
                    referenced: true,
                });
                return;
            }
        }

        // CLOCK sweep: advance the hand, clearing referenced bits, until we
        // find an unreferenced slot to evict.
        let len = self.slots.len();
        loop {
            let slot = self.slots[self.hand].as_mut().expect("all slots occupied");
            if slot.referenced {
                slot.referenced = false;
                self.hand = (self.hand + 1) % len;
            } else {
                self.slots[self.hand] = Some(FileCacheSlot {
                    segment_id,
                    layout,
                    file,
                    referenced: true,
                });
                self.hand = (self.hand + 1) % len;
                return;
            }
        }
    }

    /// Evict all entries for a given segment.
    pub(crate) fn evict(&mut self, segment_id: Ulid) {
        for slot in self.slots.iter_mut() {
            if slot.as_ref().is_some_and(|s| s.segment_id == segment_id) {
                *slot = None;
            }
        }
    }

    /// Clear all entries.
    pub(crate) fn clear(&mut self) {
        for slot in self.slots.iter_mut() {
            *slot = None;
        }
    }
}

/// Read 4 KiB blocks starting at `lba` into the caller-supplied `out` buffer.
///
/// `out.len()` must be a multiple of 4096; it determines how many blocks are
/// read. The caller's buffer is treated as uninitialised — every byte is
/// written before return: data extents are read from segment files; gaps
/// between extents (unwritten LBAs) and `ZERO_HASH` extents are explicitly
/// zero-filled.
#[allow(clippy::too_many_arguments)]
pub(crate) fn read_extents(
    lba: u64,
    out: &mut [u8],
    lbamap: &lbamap::LbaMap,
    extent_index: &extentindex::ExtentIndex,
    file_cache: &RefCell<FileCache>,
    dmat_cache: &DmatCache,
    dmat_stats: &Arc<dmat::DmatStats>,
    cache_dir: &Path,
    find_segment: impl Fn(Ulid, u64, BodySource) -> io::Result<PathBuf>,
    open_delta_body: impl Fn(Ulid) -> io::Result<fs::File>,
) -> io::Result<()> {
    use std::os::unix::fs::FileExt;

    debug_assert!(
        out.len().is_multiple_of(4096),
        "read buffer must be a multiple of 4096 bytes"
    );
    let lba_count = (out.len() / 4096) as u32;
    let end_lba = lba + lba_count as u64;
    let mut cursor = lba;
    // Per-loop cache for the most recently looked up segment's presence
    // bitset. Multi-extent reads on the same segment (the steady state)
    // skip the segment_presence HashMap probe after the first lookup.
    let mut last_segment_presence: Option<(Ulid, Option<&Arc<SegmentPresence>>)> = None;
    for er in lbamap.extents_in_range(lba, end_lba) {
        // Fill any gap between the previous extent and this one with zeros —
        // unwritten LBAs read back as zero by block-device convention.
        if er.range_start > cursor {
            let gap_start = (cursor - lba) as usize * 4096;
            let gap_end = (er.range_start - lba) as usize * 4096;
            out[gap_start..gap_end].fill(0);
        }
        cursor = er.range_end;

        // Zero extents: write zeros for the covered range, no body to fetch.
        if er.hash == ZERO_HASH {
            let s = (er.range_start - lba) as usize * 4096;
            let e = (er.range_end - lba) as usize * 4096;
            out[s..e].fill(0);
            continue;
        }

        // Journal-tier extents resolve through the `(claimant, hash)` journal
        // map: a hash repeated across journal segments has a distinct body
        // per segment, and the claimant names the reader's own copy. The
        // claimant of a durable extent is a durable segment, absent from the
        // journal map, so the probe misses and falls through to `inner` —
        // making the tiers disjoint without the read path knowing the window.
        // Gated on a non-empty journal map so non-ext4 volumes pay nothing.
        let resolved = if extent_index.journal_is_empty() {
            extent_index.lookup(&er.hash)
        } else {
            extent_index
                .lookup_journal(er.claimant_ulid, &er.hash)
                .or_else(|| extent_index.lookup(&er.hash))
        };
        let loc = match resolved {
            Some(loc) => loc,
            None => {
                // No direct DATA/Inline entry. Try a Delta entry.
                if try_read_delta_extent(
                    &er,
                    lba,
                    extent_index,
                    file_cache,
                    dmat_cache,
                    dmat_stats,
                    cache_dir,
                    &find_segment,
                    &open_delta_body,
                    out,
                )? {
                    continue;
                }
                // A mapped hash in neither index is lbamap/extent-index
                // divergence. Serving zeros here would mask corruption
                // as a hole; error loudly like `BlockReader::read_block`.
                return Err(io::Error::other(format!(
                    "lba {}..{}: hash {} present in lbamap but not in extent \
                     index (data, inline, or delta) — possible corruption",
                    er.range_start,
                    er.range_end,
                    er.hash.to_hex()
                )));
            }
        };

        let block_count = (er.range_end - er.range_start) as usize;
        let out_start = (er.range_start - lba) as usize * 4096;
        let out_slice = &mut out[out_start..out_start + block_count * 4096];
        let src_start = er.payload_block_offset as usize * 4096;
        let src_end = src_start + block_count * 4096;

        // Inline extents: bytes are held in the extent index, no file I/O.
        // A raw inline payload borrows straight out of the index buffer.
        if let Some(idata) = &loc.inline_data {
            let plain = loc.codec.decode(Cow::Borrowed(idata))?;
            verify_and_slice(
                &plain,
                &er.hash,
                lba,
                loc.segment_id,
                src_start,
                src_end,
                out_slice,
            )?;
            continue;
        }

        // Skip `find_segment` entirely on FD-cache hit + bit-set: the
        // FileCache keeps the FD and the file layout for this segment,
        // and the in-memory presence bitset already tells us this
        // entry's bytes are durable in the cached file. The dir-probe
        // chain in `find_segment_in_dirs` is the dominant per-extent
        // cost on a pulled host, so this is the steady-state win.
        //
        // We must still call `find_segment` when:
        //   * the FD isn't cached yet (first read of this segment),
        //   * the bit is clear (file may exist but this entry's bytes
        //     are not yet fetched — `find_segment` will demand-fetch),
        //   * or no bitset is registered for this segment, in which
        //     case `find_segment_in_dirs` falls back to reading the
        //     on-disk `.present` (covers test bypasses / pre-rebuild).
        //
        // The fetcher updates the bitset under its per-segment lock,
        // and `cache/<id>.body` is grown in place (no rename), so a
        // hot FD remains valid across demand-fetch completion. Inode
        // replacement events (sweep/drain/GC apply) bump `flush_gen`
        // and clear the entire FileCache, so a hot FD here is
        // guaranteed to point at the same inode the bitset describes.
        let presence_known_set = match loc.body_source {
            BodySource::Local => true,
            BodySource::Cached(idx) => {
                let presence = match last_segment_presence {
                    Some((id, p)) if id == loc.segment_id => p,
                    _ => {
                        let p = extent_index.segment_presence(loc.segment_id);
                        last_segment_presence = Some((loc.segment_id, p));
                        p
                    }
                };
                presence.is_some_and(|p| p.test(idx))
            }
        };
        let mut cache = file_cache.borrow_mut();
        if !presence_known_set || cache.get(loc.segment_id).is_none() {
            let path = find_segment(loc.segment_id, loc.body_section_start, loc.body_source)?;
            let layout = SegmentLayout::from_path(&path);
            cache.insert(loc.segment_id, layout, fs::File::open(&path)?);
        }
        let (layout, f) = cache
            .get(loc.segment_id)
            .expect("entry was just inserted or found");

        // body_offset is always body-relative (= stored_offset from the segment index).
        // For full segment files we must add body_section_start to get the file offset.
        let file_body_offset = match layout {
            SegmentLayout::BodyOnly => loc.body_offset,
            SegmentLayout::Full => loc.body_section_start + loc.body_offset,
        };

        let log_err = |stage: &str, read_len: usize, e: &dyn std::fmt::Display| {
            let file_size = f.metadata().map(|m| m.len()).unwrap_or(0);
            log::error!(
                "read_extents {stage} failed: lba={lba} segment={} codec={} layout={layout:?} \
                 bss={} body_offset={} body_length={} payload_block_offset={} \
                 file_body_offset={file_body_offset} read_len={read_len} \
                 file_size={file_size} err={e}",
                loc.segment_id,
                loc.codec,
                loc.body_section_start,
                loc.body_offset,
                loc.body_length,
                er.payload_block_offset,
            );
        };

        // An unchunked arm produces the extent's whole plaintext, either
        // straight into `out_slice` when the caller wants all of it or into
        // the TLS scratch when it wants a sub-range, because the content hash
        // can only be checked against the whole extent. The chunked arm
        // checks per chunk against the same hash, so it reads and decodes
        // only the chunks the caller's range lands in.
        match loc.codec {
            segment::Codec::ZstdChunked => {
                serve_chunked(
                    f,
                    file_body_offset,
                    loc.body_length as usize,
                    &er.hash,
                    lba,
                    loc.segment_id,
                    src_start,
                    src_end,
                    out_slice,
                )
                .inspect_err(|e| log_err("chunked decode", src_end - src_start, e))?;
            }
            segment::Codec::None => {
                let body_len = loc.body_length as usize;
                if src_start == 0 && out_slice.len() == body_len {
                    if let Err(e) = f.read_exact_at(out_slice, file_body_offset) {
                        log_err("read", out_slice.len(), &e);
                        return Err(e);
                    }
                    verify_extent_content(&er.hash, out_slice, lba, loc.segment_id)?;
                } else {
                    READ_SCRATCH.with(|s| -> io::Result<()> {
                        let mut s = s.borrow_mut();
                        s.decompressed.resize(body_len, 0);
                        if let Err(e) = f.read_exact_at(&mut s.decompressed, file_body_offset) {
                            log_err("read", body_len, &e);
                            return Err(e);
                        }
                        verify_and_slice(
                            &s.decompressed,
                            &er.hash,
                            lba,
                            loc.segment_id,
                            src_start,
                            src_end,
                            out_slice,
                        )
                    })?;
                }
            }
            codec @ (segment::Codec::Lz4 | segment::Codec::Zstd) => {
                READ_SCRATCH.with(|s| -> io::Result<()> {
                    let mut s = s.borrow_mut();
                    let s = &mut *s;

                    s.compressed.resize(loc.body_length as usize, 0);
                    if let Err(e) = f.read_exact_at(&mut s.compressed, file_body_offset) {
                        log_err("read", loc.body_length as usize, &e);
                        return Err(e);
                    }
                    let plain_len = codec.plain_len(&s.compressed)?;

                    if src_start == 0 && src_end == plain_len && out_slice.len() == plain_len {
                        codec
                            .decode_into(&s.compressed, out_slice)
                            .inspect_err(|e| log_err("decode", plain_len, e))?;
                        return verify_extent_content(&er.hash, out_slice, lba, loc.segment_id);
                    }

                    s.decompressed.resize(plain_len, 0);
                    codec
                        .decode_into(&s.compressed, &mut s.decompressed)
                        .inspect_err(|e| log_err("decode", plain_len, e))?;
                    verify_and_slice(
                        &s.decompressed,
                        &er.hash,
                        lba,
                        loc.segment_id,
                        src_start,
                        src_end,
                        out_slice,
                    )
                })?;
            }
        }
    }
    // Trailing gap after the last extent.
    if cursor < end_lba {
        let gap_start = (cursor - lba) as usize * 4096;
        out[gap_start..].fill(0);
    }
    Ok(())
}

/// Try to materialise a Delta extent for the range covered by `er`,
/// writing decoded bytes into `out` at the appropriate offset.
///
/// Returns `Ok(true)` if a Delta entry was found and decompressed
/// successfully, `Ok(false)` if no Delta entry is registered for
/// `er.hash` (caller falls through to "unwritten" handling), or
/// `Err` for any I/O or decompression failure.
///
/// Source selection uses the earliest-source preference: scan the
/// delta options in order, pick the first one whose `source_hash`
/// resolves via `extent_index.lookup` to a DATA/Inline location. No
/// caching of decompressed output — each read decompresses fresh.
/// Materialised bytes are cached in `cache/<ULID>.dmat` after a successful
/// decompress (see `docs/design/delta-materialisation.md`); subsequent reads
/// of the same Delta entry skip the source-body fetch and the
/// zstd-dict-decompress and instead read (and lz4-decompress) the cached
/// bytes directly.
#[allow(clippy::too_many_arguments)]
fn try_read_delta_extent(
    er: &lbamap::ExtentRead,
    lba: u64,
    extent_index: &extentindex::ExtentIndex,
    file_cache: &RefCell<FileCache>,
    dmat_cache: &DmatCache,
    dmat_stats: &Arc<dmat::DmatStats>,
    cache_dir: &Path,
    find_segment: &dyn Fn(Ulid, u64, BodySource) -> io::Result<PathBuf>,
    open_delta_body: &dyn Fn(Ulid) -> io::Result<fs::File>,
    out: &mut [u8],
) -> io::Result<bool> {
    use std::os::unix::fs::FileExt;

    let Some(delta_loc) = extent_index.lookup_delta(&er.hash) else {
        return Ok(false);
    };
    let delta_segment_id = delta_loc.segment_id;
    let delta_entry_idx = delta_loc.entry_idx;
    let delta_body_source = delta_loc.body_source;
    let options = delta_loc.options.clone();

    dmat_stats.record_lookup();

    // dmat hit path: materialised bytes are already on disk for this
    // (segment, entry_idx). Read + lz4-decompress, verify against the
    // entry's content hash (the dmat open-scan does not authenticate
    // records), copy out, return. Every failure — open, read, decode,
    // hash mismatch — is treated as a miss: the dmat is a rebuildable
    // cache, so re-materialisation writes a fresh record that
    // supersedes the bad one, and a cache failure never fails the read.
    if let Some(materialised) = dmat_lookup(
        dmat_cache,
        dmat_stats,
        cache_dir,
        delta_segment_id,
        delta_entry_idx,
    ) {
        if blake3::hash(&materialised) == er.hash {
            dmat_stats.record_hit();
            return copy_materialised_into(er, lba, &materialised, out).map(|()| true);
        }
        log::warn!(
            "dmat record for segment {delta_segment_id}[{delta_entry_idx}] failed \
             hash verification; re-materialising"
        );
    }
    dmat_stats.record_miss();

    // Pick the first option whose source hash resolves to a DATA/Inline
    // location. This is the earliest-source preference in its simplest
    // form; a more sophisticated version (prefer already-cached sources,
    // then earliest ULID among uncached) is a follow-up once the
    // demand-fetch path integrates.
    let mut picked: Option<(segment::DeltaOption, extentindex::ExtentLocation)> = None;
    for opt in &options {
        if let Some(source_loc) = extent_index.lookup(&opt.source_hash) {
            picked = Some((opt.clone(), source_loc.clone()));
            break;
        }
    }
    let Some((opt, source_loc)) = picked else {
        return Err(io::Error::other(format!(
            "delta extent {}: no source option resolved in extent index",
            er.hash.to_hex()
        )));
    };

    // --- Read the source body (full extent, lz4-decompressed if needed). ---
    let source_bytes: Vec<u8> = if let Some(ref idata) = source_loc.inline_data {
        source_loc.codec.decode(Cow::Borrowed(idata))?.into_owned()
    } else {
        // Same FD-cache + bitset short-circuit as the main read path:
        // skip `find_segment` when the FD is hot and presence is known
        // set, since `cache/<id>.body` is grown in place and inode
        // replacement bumps `flush_gen` (which clears the FileCache).
        let presence_known_set = match source_loc.body_source {
            BodySource::Local => true,
            BodySource::Cached(idx) => extent_index
                .segment_presence(source_loc.segment_id)
                .is_some_and(|p| p.test(idx)),
        };
        let mut cache = file_cache.borrow_mut();
        if !presence_known_set || cache.get(source_loc.segment_id).is_none() {
            let path = find_segment(
                source_loc.segment_id,
                source_loc.body_section_start,
                source_loc.body_source,
            )?;
            let layout = SegmentLayout::from_path(&path);
            cache.insert(source_loc.segment_id, layout, fs::File::open(&path)?);
        }
        let (layout, f) = cache
            .get(source_loc.segment_id)
            .expect("source just inserted or found");
        let file_body_offset = match layout {
            SegmentLayout::BodyOnly => source_loc.body_offset,
            SegmentLayout::Full => source_loc.body_section_start + source_loc.body_offset,
        };
        let mut buf = vec![0u8; source_loc.body_length as usize];
        f.read_exact_at(&mut buf, file_body_offset)?;
        source_loc.codec.decode(Cow::Owned(buf))?.into_owned()
    };

    // --- Read the delta blob from the Delta segment's delta body section. ---
    //
    // Two shapes: a full segment in `pending/` (delta body inline at
    // `body_section_start + body_length`) or a separate
    // `cache/<id>.delta` file (delta body starts at byte 0). The
    // extent_index records which via `DeltaBodySource`. For the
    // cached case we call `open_delta_body`, which returns an open
    // file handle — demand-fetching from the volume's attached
    // `SegmentFetcher` on miss.
    let delta_blob: Vec<u8> = match delta_body_source {
        extentindex::DeltaBodySource::Full {
            body_section_start: delta_bss,
            body_length: delta_body_length,
        } => {
            let mut cache = file_cache.borrow_mut();
            if cache.get(delta_segment_id).is_none() {
                let path = find_segment(delta_segment_id, delta_bss, BodySource::Local)?;
                let layout = SegmentLayout::from_path(&path);
                cache.insert(delta_segment_id, layout, fs::File::open(&path)?);
            }
            let (_layout, f) = cache
                .get(delta_segment_id)
                .expect("delta segment just inserted or found");
            let mut buf = vec![0u8; opt.delta_length as usize];
            f.read_exact_at(&mut buf, delta_bss + delta_body_length + opt.delta_offset)?;
            buf
        }
        extentindex::DeltaBodySource::Cached => {
            // Opens cache/<id>.delta (demand-fetching via the attached
            // `SegmentFetcher` if the file is absent on a pull host).
            // Not routed through `file_cache` because .delta is a
            // distinct file from the segment body, and delta reads
            // are rare enough that caching the FD would complicate
            // eviction for little benefit.
            let f = open_delta_body(delta_segment_id)?;
            let mut buf = vec![0u8; opt.delta_length as usize];
            f.read_exact_at(&mut buf, opt.delta_offset)?;
            buf
        }
    };

    // Reconstruct the full fragment bytes. We slice out the requested
    // portion below; the decompressor returns every byte the delta was
    // computed over, regardless of which LBA sub-range we want.
    let decompressed = delta_compute::apply_delta(&source_bytes, &delta_blob)?;

    // The zstd-dict decompress carries no content checksum: a wrong or
    // stale source dictionary yields plausible-length garbage, not an
    // error. The entry's content hash is the only integrity anchor.
    let got = blake3::hash(&decompressed);
    if got != er.hash {
        return Err(io::Error::other(format!(
            "delta materialisation for segment {delta_segment_id}[{delta_entry_idx}] \
             hashed {} instead of {} (source {})",
            got.to_hex(),
            er.hash.to_hex(),
            opt.source_hash.to_hex(),
        )));
    }

    // Cache the materialised bytes for future reads. Failure to write the
    // cache record is not fatal — the materialisation already succeeded
    // and can be re-derived next time.
    if let Err(e) = dmat_writeback(
        dmat_cache,
        dmat_stats,
        cache_dir,
        delta_segment_id,
        delta_entry_idx,
        &decompressed,
    ) {
        log::warn!(
            "dmat writeback failed for segment {delta_segment_id} entry {delta_entry_idx}: {e}"
        );
    }

    copy_materialised_into(er, lba, &decompressed, out).map(|()| true)
}

/// Copy the LBA sub-range described by `er` out of a fully-materialised extent
/// payload (`materialised`) into the caller's output buffer.
fn copy_materialised_into(
    er: &lbamap::ExtentRead,
    lba: u64,
    materialised: &[u8],
    out: &mut [u8],
) -> io::Result<()> {
    let block_count = (er.range_end - er.range_start) as usize;
    let out_start = (er.range_start - lba) as usize * 4096;
    let out_slice = &mut out[out_start..out_start + block_count * 4096];
    let src_start = er.payload_block_offset as usize * 4096;
    let src_end = src_start + block_count * 4096;
    let src_slice = materialised
        .get(src_start..src_end)
        .ok_or_else(|| io::Error::other("delta materialised payload too short"))?;
    out_slice.copy_from_slice(src_slice);
    Ok(())
}

/// Look up an entry in `cache/<segment_id>.dmat`.
///
/// Returns the lz4-decompressed canonical extent bytes on a hit, `None`
/// on any miss or cache failure: absent file, unmaterialised entry, or
/// an open, read, or decode error. The dmat is a rebuildable cache, so
/// a failure is logged, the record forgotten, and the caller
/// re-materialises from the delta — it never fails the read.
///
/// Lazily opens the `Dmat` instance and inserts it into the in-memory cache
/// on first access for a segment.
fn dmat_lookup(
    dmat_cache: &DmatCache,
    dmat_stats: &Arc<dmat::DmatStats>,
    cache_dir: &Path,
    segment_id: Ulid,
    entry_idx: u32,
) -> Option<Vec<u8>> {
    use std::collections::hash_map::Entry;
    let mut cache = lock_dmat_cache(dmat_cache);
    let dmat_inst = match cache.entry(segment_id) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => {
            let path = cache_dir.join(format!("{segment_id}.dmat"));
            if !path.exists() {
                return None;
            }
            match dmat::Dmat::open_or_create(&path, |_, _| true) {
                Ok((d, scan)) => {
                    dmat_stats.record_open_scan(scan);
                    v.insert(d)
                }
                Err(e) => {
                    log::warn!(
                        "dmat for segment {segment_id} failed to open ({e}); re-materialising"
                    );
                    return None;
                }
            }
        }
    };
    let loc = dmat_inst.lookup(entry_idx)?;
    match dmat_inst.read_materialised(loc) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::warn!(
                "dmat record for segment {segment_id}[{entry_idx}] failed to read ({e}); \
                 re-materialising"
            );
            dmat_inst.forget(entry_idx);
            None
        }
    }
}

/// Append a materialised entry to `cache/<segment_id>.dmat`.
///
/// Lazily opens or creates the file on first call for a segment. Applies the
/// shared compression-entropy gate before writing; the resulting record is
/// flagged `FLAG_COMPRESSED` iff lz4 produced a meaningfully smaller payload.
fn dmat_writeback(
    dmat_cache: &DmatCache,
    dmat_stats: &Arc<dmat::DmatStats>,
    cache_dir: &Path,
    segment_id: Ulid,
    entry_idx: u32,
    materialised: &[u8],
) -> io::Result<()> {
    use std::collections::hash_map::Entry;
    let mut cache = lock_dmat_cache(dmat_cache);
    let dmat_inst = match cache.entry(segment_id) {
        Entry::Occupied(o) => o.into_mut(),
        Entry::Vacant(v) => {
            let path = cache_dir.join(format!("{segment_id}.dmat"));
            let (d, scan) = dmat::Dmat::open_or_create(&path, |_, _| true)?;
            dmat_stats.record_open_scan(scan);
            v.insert(d)
        }
    };
    let compressed = super::maybe_compress(materialised);
    let loc = dmat_inst.append(entry_idx, materialised, compressed.as_deref())?;
    dmat_stats.record_write(loc.stored_length as u64);
    Ok(())
}

/// Open `cache/<id>.delta` for reading, demand-fetching it on miss.
///
/// Only called from `try_read_delta_extent` when the extent_index
/// recorded the Delta entry as `DeltaBodySource::Cached` — i.e. the
/// segment has already been promoted to the three-file cache shape,
/// so the delta body, if local, lives in its own `.delta` file
/// rather than inline in a full segment.
///
/// On a pull host where `.delta` is absent the attached fetcher
/// downloads it atomically (tmp+rename) before we open. Returns
/// `NotFound` when the file is missing locally and no fetcher is
/// attached to fetch it.
pub(crate) fn open_delta_body_in_dirs(
    segment_id: Ulid,
    base_dir: &Path,
    ancestor_layers: &[AncestorLayer],
    fetcher: Option<&BoxFetcher>,
) -> io::Result<fs::File> {
    let sid = segment_id.to_string();

    let cache_delta = base_dir.join("cache").join(format!("{sid}.delta"));
    if cache_delta.exists() {
        return fs::File::open(&cache_delta);
    }
    for layer in ancestor_layers.iter().rev() {
        let ancestor_delta = layer.dir.join("cache").join(format!("{sid}.delta"));
        if ancestor_delta.exists() {
            return fs::File::open(&ancestor_delta);
        }
    }
    if let Some(fetcher) = fetcher {
        // Find the owner — the only fork dir whose index/ holds this
        // segment's .idx. Same shape as `find_segment_in_dirs`'s
        // resolution for body fetch.
        let idx_filename = format!("{sid}.idx");
        let owner_dir = std::iter::once(base_dir)
            .chain(ancestor_layers.iter().map(|l| l.dir.as_path()))
            .find(|dir| dir.join("index").join(&idx_filename).exists())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "segment index not found in self or ancestors for delta body: {sid}.idx"
                    ),
                )
            })?;
        let owner_vol_id = owner_dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| Ulid::from_string(s).ok())
            .ok_or_else(|| {
                io::Error::other(format!(
                    "owner dir name is not a valid ULID: {}",
                    owner_dir.display()
                ))
            })?;
        let index_dir = owner_dir.join("index");
        let body_dir = owner_dir.join("cache");
        fetcher.fetch_delta_body(segment_id, owner_vol_id, &index_dir, &body_dir)?;
        return fs::File::open(body_dir.join(format!("{sid}.delta")));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("delta body not found: {sid}"),
    ))
}

/// Gate a `cache/<id>.body` hit on the per-entry presence bit for
/// `Cached` entries. Returns true for any non-cache layout
/// (wal/pending/gc) and for cache hits on `Local` entries.
///
/// For `Cached` cache hits, prefer the in-memory presence bitset
/// (one atomic load, no syscall — the steady-state case after a
/// normal rebuild). Fall back to reading the on-disk
/// `cache/<id>.present` when the bitset isn't installed in memory:
/// this covers paths that bypass the actor's normal promote/drain
/// flow (e.g. test helpers that move files directly), and any
/// transient window during init where `find_segment_in_dirs` is
/// invoked before the relevant segment's bitset has been loaded.
fn cache_hit_allowed(
    layout: segment::SegmentBodyLayout,
    dir: &Path,
    extent_index: &extentindex::ExtentIndex,
    segment_id: Ulid,
    body_source: BodySource,
) -> bool {
    if layout != segment::SegmentBodyLayout::BodyOnly {
        return true;
    }
    match body_source {
        BodySource::Local => true,
        BodySource::Cached(idx) => {
            if let Some(p) = extent_index.segment_presence(segment_id) {
                return p.test(idx);
            }
            let sid = segment_id.to_string();
            let present_path = dir.join("cache").join(format!("{sid}.present"));
            segment::check_present_bit(&present_path, idx).unwrap_or(false)
        }
    }
}

/// Search for a segment file across the fork directory tree.
///
/// Search order:
///   1. Current fork: `wal/`, `pending/`, bare `gc/<id>`, `cache/<id>.body`
///   2. Ancestor forks (newest-first): `pending/`, bare `gc/<id>`, `cache/<id>.body`
///   3. Demand-fetch via fetcher (writes three-file format to `cache/`)
///
/// For `Cached` entries, a `cache/<id>.body` hit is only accepted if the
/// corresponding bit in `cache/<id>.present` is set — otherwise the entry
/// is not yet locally available and we fall through to the fetcher.
///
/// `.idx` files live in `index/` (coordinator-written, permanent).
/// `.body` and `.present` files live in `cache/` (volume-managed read cache).
///
/// Extracted from `Volume::find_segment_file` so that `VolumeReader` can serve
/// reads directly from a `ReadSnapshot` without going through the actor channel.
pub(crate) fn find_segment_in_dirs(
    segment_id: Ulid,
    base_dir: &Path,
    ancestor_layers: &[AncestorLayer],
    fetcher: Option<&BoxFetcher>,
    extent_index: &extentindex::ExtentIndex,
    body_section_start: u64,
    body_source: BodySource,
) -> io::Result<PathBuf> {
    let sid = segment_id.to_string();
    // Self dir: full canonical precedence (wal → pending → bare gc/<id> → cache).
    // The bare-`gc/<id>` branch matters here because the extent index flips to
    // the new segment_id the moment the volume renames `<id>.tmp → <id>` (the
    // commit point of apply), before the coordinator has promoted the body to
    // `cache/`.
    if let Some((path, layout)) = segment::locate_segment_body(base_dir, segment_id)
        && cache_hit_allowed(layout, base_dir, extent_index, segment_id, body_source)
    {
        return Ok(path);
    }
    // Ancestor layers: segments here are always fork-parent state. They cannot
    // be mid-GC-handoff from this child's perspective, and they have no live
    // wal/, but pending/ and cache/<id>.body can both appear — the same helper
    // yields the right path; cache hits re-gate on the same in-memory bitset.
    for layer in ancestor_layers.iter().rev() {
        if let Some((path, layout)) = segment::locate_segment_body(&layer.dir, segment_id)
            && cache_hit_allowed(layout, &layer.dir, extent_index, segment_id, body_source)
        {
            return Ok(path);
        }
    }
    if let (Some(fetcher), BodySource::Cached(idx)) = (fetcher, body_source) {
        // The segment's `.idx` file lives in the index directory of whichever
        // volume wrote it — self for locally-written segments, an ancestor
        // for fork-parent segments. Search self first, then the ancestor
        // chain (in the same order rebuild_segments merges), and use that
        // volume's dirs so the fetched body lands in the owner's `cache/`
        // (where subsequent reads will find it via the ancestor scan above).
        let idx_filename = format!("{sid}.idx");
        let owner_dir = std::iter::once(base_dir)
            .chain(ancestor_layers.iter().map(|l| l.dir.as_path()))
            .find(|dir| dir.join("index").join(&idx_filename).exists())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!(
                        "segment index not found in self or ancestors: {sid}.idx \
                         (ancestor chain may not be prefetched yet)"
                    ),
                )
            })?;
        let owner_vol_id = owner_dir
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|s| Ulid::from_string(s).ok())
            .ok_or_else(|| {
                io::Error::other(format!(
                    "owner dir name is not a valid ULID: {}",
                    owner_dir.display()
                ))
            })?;
        let index_dir = owner_dir.join("index");
        let body_dir = owner_dir.join("cache");
        // Hand the fetcher the same Arc<SegmentPresence> reachable from
        // every reader's snapshot. The fetcher refreshes the bitset
        // from the freshly-written on-disk `.present` inside its
        // per-segment lock, so post-eviction stale bits get cleared
        // there rather than via any actor coordination.
        let presence = extent_index.segment_presence(segment_id).cloned();
        fetcher.fetch_extent(
            segment_id,
            owner_vol_id,
            &index_dir,
            &body_dir,
            &segment::ExtentFetch {
                body_section_start,
                body_offset: 0,
                body_length: 0,
                entry_idx: idx,
            },
            presence,
        )?;
        return Ok(body_dir.join(format!("{sid}.body")));
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        format!("segment not found: {sid}"),
    ))
}

/// `ext4_view::Ext4Read` adapter over a `Volume`'s in-memory read path,
/// for parsing the guest filesystem at open time (journal window
/// derivation). Byte-granular reads are assembled from whole-block
/// `read_into` calls; an unreadable block (e.g. an evicted body with no
/// fetcher attached) surfaces as an error the caller treats as
/// "no journal awareness".
pub(super) struct VolumeExt4Reader<'a> {
    pub volume: &'a super::Volume,
}

impl ext4_view::Ext4Read for VolumeExt4Reader<'_> {
    fn read(
        &mut self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if dst.is_empty() {
            return Ok(());
        }
        let lba = start_byte / 4096;
        let lba_end = (start_byte + dst.len() as u64).div_ceil(4096);
        let bytes = self
            .volume
            .read(lba, (lba_end - lba) as u32)
            .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)?;
        let off = (start_byte % 4096) as usize;
        dst.copy_from_slice(&bytes[off..off + dst.len()]);
        Ok(())
    }
}
