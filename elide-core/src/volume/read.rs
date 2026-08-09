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
use std::sync::atomic::{self, AtomicU64};

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

/// Shared per-volume cache of open segment-body descriptors, keyed by
/// segment ULID. One instance per volume per process, cloned into every
/// reader thread on the same terms as [`DmatCache`].
pub(crate) type SharedFileCache = Arc<std::sync::Mutex<FileCache>>;

/// Lock a [`SharedFileCache`], recovering from poisoning: the cache only
/// holds re-openable descriptors, and every byte served through them is
/// hash-verified downstream.
pub(crate) fn lock_file_cache(cache: &SharedFileCache) -> std::sync::MutexGuard<'_, FileCache> {
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

/// Chaining values a thread keeps across reads, over all cached tables.
///
/// One value is 36 bytes with its stored length, so this bounds the cache at
/// roughly 9 MiB per reading thread. A whole volume's tables are far smaller
/// than that at the chunk sizes in use, so the bound is a backstop.
const TABLE_CACHE_CVS: usize = 256 * 1024;

/// A chunk table whose chaining values reconstruct `root`.
struct ProvenTable {
    root: blake3::Hash,
    table: chunk_tree::ChunkTable,
}

/// Per-thread cache of chunk tables already checked against the extent hash
/// their signed index carries.
///
/// A table enters only after a root reconstruction proved it, and leaves only
/// to a read whose expected hash equals the one it was proved against, so an
/// entry that does not belong to the read at hand simply misses and the slow
/// path proves the table afresh. Body bytes for a segment ULID never change
/// under a reader, so nothing outside has to invalidate this.
#[derive(Default)]
struct TableCache {
    tables: HashMap<(Ulid, u64), ProvenTable>,
    order: std::collections::VecDeque<(Ulid, u64)>,
    cvs: usize,
}

impl TableCache {
    /// The table proved against `expected`, if this thread holds it.
    ///
    /// One proved against a different hash describes different content, so it
    /// misses and the caller proves the table this read needs.
    fn get(&self, key: &(Ulid, u64), expected: &blake3::Hash) -> Option<&chunk_tree::ChunkTable> {
        self.tables
            .get(key)
            .filter(|p| p.root == *expected)
            .map(|p| &p.table)
    }

    fn put(&mut self, key: (Ulid, u64), root: blake3::Hash, table: chunk_tree::ChunkTable) {
        self.cvs += table.cvs.len();
        if let Some(prev) = self.tables.insert(key, ProvenTable { root, table }) {
            self.cvs -= prev.table.cvs.len();
        } else {
            self.order.push_back(key);
        }
        while self.cvs > TABLE_CACHE_CVS {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            if let Some(dropped) = self.tables.remove(&oldest) {
                self.cvs -= dropped.table.cvs.len();
            }
        }
    }
}

thread_local! {
    static TABLE_CACHE: RefCell<TableCache> = RefCell::new(TableCache::default());
}

/// Serve `src_start..src_end` of a chunked extent, reading and decoding only
/// the chunks that range lands in.
///
/// The chunk table's chaining values are subtree values of the extent's own
/// hash tree. Proving a table costs one root reconstruction, over the
/// values computed from the decoded chunks substituted into the rest: that
/// checks the decoded bytes and the unsigned table together, against the hash
/// the signed index carries. A table holds for the life of the extent, so a
/// read that finds it already proved instead compares its decoded chunks
/// against the proven values directly — the same statement about the bytes it
/// serves, without the table read, the parse, or a reconstruction whose cost
/// grows with the whole extent's chunk count.
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
    let key = (segment_id, file_body_offset);
    let served = TABLE_CACHE.with(|c| {
        let cache = c.borrow();
        cache.get(&key, expected).map(|table| {
            serve_from_table(
                f,
                file_body_offset,
                body_length,
                table,
                None,
                lba,
                segment_id,
                src_start,
                src_end,
                out_slice,
            )
        })
    });
    if let Some(result) = served {
        return result.map(|_| ());
    }

    let mut table = read_chunk_table(f, file_body_offset, body_length)?;
    let proved = serve_from_table(
        f,
        file_body_offset,
        body_length,
        &table,
        Some(expected),
        lba,
        segment_id,
        src_start,
        src_end,
        out_slice,
    )?;
    if let Some(cvs) = proved {
        table.cvs = cvs;
        TABLE_CACHE.with(|c| c.borrow_mut().put(key, *expected, table));
    }
    Ok(())
}

/// Read and parse the table at the head of a chunked stored payload.
fn read_chunk_table(
    f: &fs::File,
    file_body_offset: u64,
    body_length: usize,
) -> io::Result<chunk_tree::ChunkTable> {
    use std::os::unix::fs::FileExt;
    READ_SCRATCH.with(|s| {
        let mut s = s.borrow_mut();
        // The table's own length follows from the plaintext length in its
        // first four bytes, so read a prefix that covers most tables outright
        // and extend it only when one runs longer.
        let prefix = TABLE_READ_PREFIX.min(body_length);
        s.table.resize(prefix, 0);
        f.read_exact_at(&mut s.table, file_body_offset)?;
        let (plain_len, size) = chunk_tree::ChunkTable::peek_header(&s.table)?;
        if plain_len > segment::MAX_EXTENT_PLAINTEXT {
            return Err(io::Error::other(format!(
                "chunked payload declares {plain_len} bytes of plaintext, over the {} cap",
                segment::MAX_EXTENT_PLAINTEXT
            )));
        }
        let table_len = chunk_tree::ChunkTable::encoded_len(plain_len, size);
        if table_len > s.table.len() {
            s.table.resize(table_len, 0);
            f.read_exact_at(&mut s.table, file_body_offset)?;
        }
        chunk_tree::ChunkTable::parse(&s.table)
    })
}

/// Decode the chunks `src_start..src_end` lands in out of `table`.
///
/// `prove` carries the extent hash when the table has yet to be checked
/// against it, and the proved chaining values come back for the caller to
/// cache. Without it the table is already proved, and each decoded chunk is
/// checked against the value the table holds for it — which says the same
/// thing about the bytes served, since those values are the ones a
/// reconstruction matched to the signed hash.
#[allow(clippy::too_many_arguments)]
fn serve_from_table(
    f: &fs::File,
    file_body_offset: u64,
    body_length: usize,
    table: &chunk_tree::ChunkTable,
    prove: Option<&blake3::Hash>,
    lba: u64,
    segment_id: Ulid,
    src_start: usize,
    src_end: usize,
    out_slice: &mut [u8],
) -> io::Result<Option<Vec<blake3::hazmat::ChainingValue>>> {
    use std::os::unix::fs::FileExt;
    READ_SCRATCH.with(|s| {
        let mut s = s.borrow_mut();
        let s = &mut *s;
        let plain_len = table.plain_len;

        let wanted = table.size.covering(src_start, src_end);
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

        // A reconstruction needs the whole array, with this read's chunks
        // substituted into the values the table supplies for the rest.
        if prove.is_some() {
            s.cvs.clear();
            s.cvs.extend_from_slice(&table.cvs);
        }
        for index in wanted {
            let span = table.chunk_span(index)?;
            let frame = &s.compressed[span.start - first.start..span.end - first.start];
            let plain = table.size.range(index, plain_len);

            // A chunk wholly inside the caller's range decodes into its
            // buffer; one that only overlaps decodes into the scratch and
            // contributes the overlap. Either way the whole chunk is in hand,
            // which is what its chaining value covers.
            let cv = if plain.start >= src_start && plain.end <= src_end {
                let at = plain.start - src_start;
                let into = &mut out_slice[at..at + plain.len()];
                segment::Codec::Zstd.decode_into(frame, into)?;
                table.size.cv(index, into)
            } else {
                s.decompressed.resize(plain.len(), 0);
                segment::Codec::Zstd.decode_into(frame, &mut s.decompressed)?;
                let from = src_start.max(plain.start);
                let to = src_end.min(plain.end);
                out_slice[from - src_start..to - src_start]
                    .copy_from_slice(&s.decompressed[from - plain.start..to - plain.start]);
                table.size.cv(index, &s.decompressed)
            };
            match prove {
                Some(_) => s.cvs[index] = cv,
                None if cv != table.cvs[index] => {
                    log::error!(
                        "chunk hash mismatch: lba={lba} segment={segment_id} chunk={index} \
                         of {} ({plain_len} bytes)",
                        table.cvs.len(),
                    );
                    return Err(io::Error::other(format!(
                        "chunk {index} of a {plain_len}-byte extent failed its chaining value"
                    )));
                }
                None => {}
            }
        }

        let Some(expected) = prove else {
            return Ok(None);
        };
        let root = table.size.root_from_cvs(&s.cvs, plain_len)?;
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
        Ok(Some(s.cvs.clone()))
    })
}

/// First read of a chunk table. Covers a table for an extent up to about
/// 28 MiB, so a second read is the tail of the size distribution.
const TABLE_READ_PREFIX: usize = 4096;

/// Default capacity for a volume's shared segment-descriptor cache.
///
/// One cache per volume, so this is the volume's whole descriptor budget
/// for segment bodies. Sized with headroom over the live segment count of
/// a churned volume: misses climb steeply once segments outnumber slots,
/// while spare slots cost only their array entry — descriptors open as
/// segments are touched, and `get` scans occupied slots. 512 stays a
/// small fraction of a typical 10240 fd rlimit.
pub const FILE_CACHE_CAPACITY: usize = 512;

/// Telemetry for the segment-descriptor cache.
///
/// One instance per reader, so the counters are uncontended — they are
/// atomics to match [`crate::dmat::DmatStats`] and to keep the read path on
/// a shared reference. A miss is what pays for `find_segment_in_dirs` and an
/// `open`, so the ratio is the number to watch when a read workload slows
/// down.
#[derive(Debug, Default)]
pub struct ReadStats {
    /// Extents resolved through a segment file. Inline and zero extents
    /// never reach the cache and are not counted.
    pub extents_total: AtomicU64,
    /// The cache held a descriptor for the extent's segment.
    pub fd_hit_total: AtomicU64,
    /// The cache did not, so the read resolved a path and opened the file.
    pub fd_miss_total: AtomicU64,
}

impl ReadStats {
    fn record_hit(&self) {
        self.extents_total.fetch_add(1, atomic::Ordering::Relaxed);
        self.fd_hit_total.fetch_add(1, atomic::Ordering::Relaxed);
    }

    fn record_miss(&self) {
        self.extents_total.fetch_add(1, atomic::Ordering::Relaxed);
        self.fd_miss_total.fetch_add(1, atomic::Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ReadStatsSnapshot {
        ReadStatsSnapshot {
            extents_total: self.extents_total.load(atomic::Ordering::Relaxed),
            fd_hit_total: self.fd_hit_total.load(atomic::Ordering::Relaxed),
            fd_miss_total: self.fd_miss_total.load(atomic::Ordering::Relaxed),
        }
    }
}

/// Counter values read together at one instant.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadStatsSnapshot {
    pub extents_total: u64,
    pub fd_hit_total: u64,
    pub fd_miss_total: u64,
}

impl ReadStatsSnapshot {
    /// Share of segment-file extents that had to open a file, in `0.0..=1.0`.
    /// Zero when no extent reached the cache.
    pub fn fd_miss_rate(&self) -> f64 {
        let looked_up = self.fd_hit_total + self.fd_miss_total;
        if looked_up == 0 {
            return 0.0;
        }
        self.fd_miss_total as f64 / looked_up as f64
    }

    /// Counters accumulated between `earlier` and this snapshot.
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            extents_total: self.extents_total - earlier.extents_total,
            fd_hit_total: self.fd_hit_total - earlier.fd_hit_total,
            fd_miss_total: self.fd_miss_total - earlier.fd_miss_total,
        }
    }
}

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
/// The hot-path operation (`get`) is a linear scan + flag set + `Arc` clone —
/// no data movement, no pointer chasing — cheap next to the `open` it saves.
///
/// Every slot belongs to the cache's current layout generation. `get` and
/// `insert` take the caller's generation: a newer generation empties the
/// cache and becomes current, the current generation operates normally, and
/// an older generation misses on `get` and is dropped on `insert`. Segment
/// files are replaced on disk across a generation bump (promote, drain,
/// repack, eviction), so this pins every served descriptor to the inode
/// that the caller's snapshot — and its presence bitsets — describe, even
/// while readers on different snapshots overlap mid-publication.
/// Single-owner users (`Volume`, `ReadonlyVolume`) pass a constant 0 and
/// evict explicitly.
pub(crate) struct FileCache {
    slots: Vec<Option<FileCacheSlot>>,
    hand: usize,
    layout_gen: u64,
}

struct FileCacheSlot {
    segment_id: Ulid,
    layout: SegmentLayout,
    file: Arc<fs::File>,
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
        Self {
            slots,
            hand: 0,
            layout_gen: 0,
        }
    }

    /// Empty the cache and adopt `layout_gen` when it is newer than the
    /// current generation.
    fn advance(&mut self, layout_gen: u64) {
        if layout_gen > self.layout_gen {
            self.clear();
            self.layout_gen = layout_gen;
        }
    }

    /// Replace the slot array with `capacity` empty slots, keeping the
    /// generation.
    pub(crate) fn set_capacity(&mut self, capacity: usize) {
        self.slots.clear();
        self.slots.resize_with(capacity, || None);
        self.hand = 0;
    }

    /// Look up a cached file handle by segment id, on behalf of a caller
    /// at layout generation `layout_gen`.
    ///
    /// On hit, sets the referenced bit and returns the layout and a clone
    /// of the handle, so the caller releases the cache lock before the
    /// positional reads the handle serves.
    pub(in crate::volume) fn get(
        &mut self,
        layout_gen: u64,
        segment_id: Ulid,
    ) -> Option<(SegmentLayout, Arc<fs::File>)> {
        self.advance(layout_gen);
        if layout_gen < self.layout_gen {
            return None;
        }
        let slot = self
            .slots
            .iter_mut()
            .flatten()
            .find(|s| s.segment_id == segment_id)?;
        slot.referenced = true;
        Some((slot.layout, Arc::clone(&slot.file)))
    }

    /// Insert a file handle opened by a caller at layout generation
    /// `layout_gen`;
    /// a stale generation is dropped, and the caller reads through the
    /// handle it already holds. If the segment is already cached, replaces
    /// it in-place. Otherwise, uses the CLOCK algorithm to find a slot to
    /// evict.
    pub(in crate::volume) fn insert(
        &mut self,
        layout_gen: u64,
        segment_id: Ulid,
        layout: SegmentLayout,
        file: Arc<fs::File>,
    ) {
        self.advance(layout_gen);
        if layout_gen < self.layout_gen || self.slots.is_empty() {
            return;
        }
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
    layout_gen: u64,
    file_cache: &SharedFileCache,
    dmat_cache: &DmatCache,
    dmat_stats: &Arc<dmat::DmatStats>,
    read_stats: &ReadStats,
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
                    layout_gen,
                    file_cache,
                    dmat_cache,
                    dmat_stats,
                    read_stats,
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
        // replacement events (sweep/drain/GC apply) bump `layout_gen`,
        // which retires every descriptor the cache opened under earlier
        // generations — so a hot FD here is guaranteed to point at the
        // same inode the bitset describes.
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
        let cached = if presence_known_set {
            lock_file_cache(file_cache).get(layout_gen, loc.segment_id)
        } else {
            None
        };
        let (layout, file) = match cached {
            Some(hit) => {
                read_stats.record_hit();
                hit
            }
            None => {
                read_stats.record_miss();
                let path = find_segment(loc.segment_id, loc.body_section_start, loc.body_source)?;
                let layout = SegmentLayout::from_path(&path);
                let file = Arc::new(fs::File::open(&path)?);
                lock_file_cache(file_cache).insert(
                    layout_gen,
                    loc.segment_id,
                    layout,
                    Arc::clone(&file),
                );
                (layout, file)
            }
        };
        let f = file.as_ref();

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
    layout_gen: u64,
    file_cache: &SharedFileCache,
    dmat_cache: &DmatCache,
    dmat_stats: &Arc<dmat::DmatStats>,
    read_stats: &ReadStats,
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
        // replacement bumps `layout_gen` (which retires cached
        // descriptors).
        let presence_known_set = match source_loc.body_source {
            BodySource::Local => true,
            BodySource::Cached(idx) => extent_index
                .segment_presence(source_loc.segment_id)
                .is_some_and(|p| p.test(idx)),
        };
        let cached = if presence_known_set {
            lock_file_cache(file_cache).get(layout_gen, source_loc.segment_id)
        } else {
            None
        };
        let (layout, file) = match cached {
            Some(hit) => {
                read_stats.record_hit();
                hit
            }
            None => {
                read_stats.record_miss();
                let path = find_segment(
                    source_loc.segment_id,
                    source_loc.body_section_start,
                    source_loc.body_source,
                )?;
                let layout = SegmentLayout::from_path(&path);
                let file = Arc::new(fs::File::open(&path)?);
                lock_file_cache(file_cache).insert(
                    layout_gen,
                    source_loc.segment_id,
                    layout,
                    Arc::clone(&file),
                );
                (layout, file)
            }
        };
        let file_body_offset = match layout {
            SegmentLayout::BodyOnly => source_loc.body_offset,
            SegmentLayout::Full => source_loc.body_section_start + source_loc.body_offset,
        };
        let mut buf = vec![0u8; source_loc.body_length as usize];
        file.read_exact_at(&mut buf, file_body_offset)?;
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
            let cached = lock_file_cache(file_cache).get(layout_gen, delta_segment_id);
            let file = match cached {
                Some((_layout, f)) => {
                    read_stats.record_hit();
                    f
                }
                None => {
                    read_stats.record_miss();
                    let path = find_segment(delta_segment_id, delta_bss, BodySource::Local)?;
                    let layout = SegmentLayout::from_path(&path);
                    let f = Arc::new(fs::File::open(&path)?);
                    lock_file_cache(file_cache).insert(
                        layout_gen,
                        delta_segment_id,
                        layout,
                        Arc::clone(&f),
                    );
                    f
                }
            };
            let mut buf = vec![0u8; opt.delta_length as usize];
            file.read_exact_at(&mut buf, delta_bss + delta_body_length + opt.delta_offset)?;
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
    let home = body_source.home();
    // Self dir: start where the index says the body is, then the canonical
    // precedence (wal → pending → bare gc/<id> → cache). The bare-`gc/<id>`
    // branch matters here because the extent index flips to the new segment_id
    // the moment the volume renames `<id>.tmp → <id>` (the commit point of
    // apply), before the coordinator has promoted the body to `cache/`.
    if let Some((path, layout)) = segment::locate_segment_body_from(base_dir, segment_id, home)
        && cache_hit_allowed(layout, base_dir, extent_index, segment_id, body_source)
    {
        return Ok(path);
    }
    // Ancestor layers: segments here are always fork-parent state. They cannot
    // be mid-GC-handoff from this child's perspective, and they have no live
    // wal/, but pending/ and cache/<id>.body can both appear — the same helper
    // yields the right path; cache hits re-gate on the same in-memory bitset.
    for layer in ancestor_layers.iter().rev() {
        if let Some((path, layout)) =
            segment::locate_segment_body_from(&layer.dir, segment_id, home)
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
