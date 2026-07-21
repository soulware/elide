// Measures delta source-selection strategies between two states of the
// same live-written ext4 image (before/after a workload such as a package
// upgrade). Replays the production Tier-1 rule (same-LBA prior fragment as
// zstd dictionary, keep iff smaller than the LZ4-stored size) over the
// changed blocks, then attempts super-feature similarity matching on the
// misses. Journal-range and non-file (metadata) bytes are bucketed
// separately. See docs/design/delta-compression.md § Measurement.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

use crate::extents::{
    INODE_FLAG_EXTENTS, SUPERBLOCK_OFFSET, Superblock, collect_extents, inode_table_block, u32le,
};

const LBA_SIZE: u64 = 4096;
const DIFF_CHUNK: usize = 4 << 20;
/// Candidates tried per miss (union of the three super-feature buckets).
const MAX_CANDIDATES: usize = 8;
/// Dictionary bytes held in the read cache before it is cleared.
const DICT_CACHE_CAP: u64 = 512 << 20;

// --- sketch ---

const SUBCHUNKS: usize = 16;
const FEATURES_PER_SF: usize = 2;
const NUM_SF: usize = SUBCHUNKS / FEATURES_PER_SF;

/// Content-defined sampling rate for the Broder sketch: positions where
/// the low bits of the rolling hash are all-ones (~1/32 of positions).
const SAMPLE_MASK: u64 = 0x1f;
/// Minimum sampled positions for a Broder sketch to be meaningful.
const MIN_SAMPLES: u64 = 16;

const fn splitmix(seed: u64) -> u64 {
    let mut z = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

const fn gear_table() -> [u64; 256] {
    let mut t = [0u64; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = splitmix(i as u64);
        i += 1;
    }
    t
}

static GEAR: [u64; 256] = gear_table();

const fn perm_table() -> [u64; SUBCHUNKS] {
    let mut t = [0u64; SUBCHUNKS];
    let mut i = 0usize;
    while i < SUBCHUNKS {
        t[i] = splitmix(0x1000 + i as u64) | 1;
        i += 1;
    }
    t
}

static PERMS: [u64; SUBCHUNKS] = perm_table();

#[derive(Clone, Copy, PartialEq)]
pub enum SketchKind {
    /// Positional: max Gear hash per fixed subchunk (Finesse-style).
    /// Cheap, but brittle when content shifts across subchunk boundaries.
    Finesse,
    /// Position-independent: max of SUBCHUNKS independent permutations
    /// over content-defined sampled window hashes (Broder resemblance).
    Broder,
}

impl SketchKind {
    pub fn parse(s: &str) -> io::Result<Self> {
        match s {
            "finesse" => Ok(Self::Finesse),
            "broder" => Ok(Self::Broder),
            other => Err(io::Error::other(format!("unknown sketch kind: {other}"))),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Finesse => "finesse",
            Self::Broder => "broder",
        }
    }
}

fn sfs_from_features(features: &[u64; SUBCHUNKS]) -> [u64; NUM_SF] {
    let mut sfs = [0u64; NUM_SF];
    for (j, sf) in sfs.iter_mut().enumerate() {
        let mut bytes = [0u8; FEATURES_PER_SF * 8];
        for k in 0..FEATURES_PER_SF {
            bytes[k * 8..(k + 1) * 8]
                .copy_from_slice(&features[j * FEATURES_PER_SF + k].to_le_bytes());
        }
        let h = blake3::hash(&bytes);
        let b = h.as_bytes();
        *sf = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
    }
    sfs
}

/// Super-feature sketch: SUBCHUNKS features grouped into NUM_SF 8-byte
/// super-features. Two inputs sharing any super-feature are likely
/// similar. Returns None when the input is too small to sketch reliably.
fn sketch(kind: SketchKind, data: &[u8]) -> Option<[u64; NUM_SF]> {
    let mut features = [0u64; SUBCHUNKS];
    match kind {
        SketchKind::Finesse => {
            let sub = data.len().div_ceil(SUBCHUNKS).max(1);
            for (i, chunk) in data.chunks(sub).enumerate().take(SUBCHUNKS) {
                let mut h = 0u64;
                let mut m = 0u64;
                for &b in chunk {
                    h = (h << 1).wrapping_add(GEAR[b as usize]);
                    if h > m {
                        m = h;
                    }
                }
                features[i] = m;
            }
        }
        SketchKind::Broder => {
            let mut samples = 0u64;
            let mut h = 0u64;
            for &b in data {
                h = (h << 1).wrapping_add(GEAR[b as usize]);
                if h & SAMPLE_MASK == SAMPLE_MASK {
                    samples += 1;
                    for (f, perm) in features.iter_mut().zip(PERMS) {
                        let v = h.wrapping_mul(perm);
                        if v > *f {
                            *f = v;
                        }
                    }
                }
            }
            if samples < MIN_SAMPLES {
                return None;
            }
        }
    }
    Some(sfs_from_features(&features))
}

// --- intervals ---

/// Byte range [start, start + len).
#[derive(Clone, Copy, Debug, PartialEq)]
struct Span {
    start: u64,
    len: u64,
}

impl Span {
    fn end(&self) -> u64 {
        self.start + self.len
    }
}

/// Split `span` against sorted non-overlapping `cuts`, returning the
/// (inside, outside) partition in ascending order.
fn partition_span(span: Span, cuts: &[Span]) -> (Vec<Span>, Vec<Span>) {
    let mut inside = Vec::new();
    let mut outside = Vec::new();
    let mut pos = span.start;
    let end = span.end();
    for c in cuts {
        if c.end() <= pos {
            continue;
        }
        if c.start >= end {
            break;
        }
        if c.start > pos {
            outside.push(Span {
                start: pos,
                len: c.start - pos,
            });
            pos = c.start;
        }
        let ov_end = c.end().min(end);
        inside.push(Span {
            start: pos,
            len: ov_end - pos,
        });
        pos = ov_end;
        if pos >= end {
            break;
        }
    }
    if pos < end {
        outside.push(Span {
            start: pos,
            len: end - pos,
        });
    }
    (inside, outside)
}

// --- ext4 scans ---

/// One contiguous LBA range owned by a regular file (allocated bytes,
/// truncated to file size on the tail fragment).
struct Frag {
    start_byte: u64,
    byte_count: u64,
    path: String,
}

fn scan_file_fragments(image: &Path) -> io::Result<Vec<Frag>> {
    let f = File::open(image)?;
    let image_size = f.metadata()?.len();
    let layout = elide_core::ext4_scan::scan_layout_via_reader(image_size, Box::new(f))?
        .ok_or_else(|| io::Error::other("image is not ext4"))?;
    let mut frags: Vec<Frag> = layout
        .fragments
        .into_iter()
        .map(|fr| Frag {
            start_byte: fr.lba_start * LBA_SIZE,
            byte_count: fr.byte_count,
            path: fr.path,
        })
        .collect();
    frags.sort_by_key(|fr| fr.start_byte);
    Ok(frags)
}

fn frag_spans(frags: &[Frag]) -> Vec<Span> {
    frags
        .iter()
        .map(|fr| Span {
            start: fr.start_byte,
            len: fr.byte_count.div_ceil(LBA_SIZE) * LBA_SIZE,
        })
        .collect()
}

/// The jbd2 journal's byte ranges, from the journal inode's extent tree.
/// Empty for external journals or a journal-less filesystem.
fn journal_spans(f: &mut File, sb: &Superblock) -> io::Result<Vec<Span>> {
    let mut raw_sb = vec![0u8; 1024];
    f.seek(SeekFrom::Start(SUPERBLOCK_OFFSET))?;
    f.read_exact(&mut raw_sb)?;
    let journal_inum = u32le(&raw_sb, 0xe0);
    if journal_inum == 0 {
        return Ok(Vec::new());
    }

    let group = (journal_inum - 1) / sb.inodes_per_group;
    let idx = (journal_inum - 1) % sb.inodes_per_group;
    let table_offset = inode_table_block(f, sb, group)? * sb.block_size;
    let mut inode_buf = vec![0u8; sb.inode_size];
    f.seek(SeekFrom::Start(
        table_offset + idx as u64 * sb.inode_size as u64,
    ))?;
    f.read_exact(&mut inode_buf)?;

    if (u32le(&inode_buf, 0x20) & INODE_FLAG_EXTENTS) == 0 {
        return Ok(Vec::new());
    }
    let i_block = inode_buf[0x28..0x28 + 60].to_vec();
    let mut raw: Vec<(u64, u16)> = Vec::new();
    collect_extents(&i_block, f, sb, &mut raw)?;

    let mut spans: Vec<Span> = raw
        .iter()
        .map(|&(start, len)| Span {
            start: start * sb.block_size,
            len: len as u64 * sb.block_size,
        })
        .collect();
    spans.sort_by_key(|s| s.start);
    Ok(spans)
}

// --- block diff ---

/// Coalesced runs of changed 4 KiB blocks (byte spans).
fn diff_images(before: &mut File, after: &mut File, image_size: u64) -> io::Result<Vec<Span>> {
    let mut runs: Vec<Span> = Vec::new();
    let mut buf_a = vec![0u8; DIFF_CHUNK];
    let mut buf_b = vec![0u8; DIFF_CHUNK];
    before.seek(SeekFrom::Start(0))?;
    after.seek(SeekFrom::Start(0))?;

    let mut offset = 0u64;
    let mut cur: Option<Span> = None;
    while offset < image_size {
        let want = DIFF_CHUNK.min((image_size - offset) as usize);
        before.read_exact(&mut buf_a[..want])?;
        after.read_exact(&mut buf_b[..want])?;
        let mut pos = 0usize;
        while pos < want {
            let n = (LBA_SIZE as usize).min(want - pos);
            let changed = buf_a[pos..pos + n] != buf_b[pos..pos + n];
            let block_start = offset + pos as u64;
            match (&mut cur, changed) {
                (Some(run), true) if run.end() == block_start => run.len += n as u64,
                (_, true) => {
                    if let Some(run) = cur.take() {
                        runs.push(run);
                    }
                    cur = Some(Span {
                        start: block_start,
                        len: n as u64,
                    });
                }
                (Some(_), false) => {
                    if let Some(run) = cur.take() {
                        runs.push(run);
                    }
                }
                (None, false) => {}
            }
            pos += n;
        }
        offset += want as u64;
    }
    if let Some(run) = cur {
        runs.push(run);
    }
    Ok(runs)
}

// --- measurement ---

fn read_span(f: &mut File, span: Span) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; span.len as usize];
    f.seek(SeekFrom::Start(span.start))?;
    f.read_exact(&mut buf)?;
    Ok(buf)
}

struct DictCache {
    bodies: HashMap<u32, Vec<u8>>,
    held: u64,
}

impl DictCache {
    fn new() -> Self {
        Self {
            bodies: HashMap::new(),
            held: 0,
        }
    }

    fn get(&mut self, f: &mut File, frags: &[Frag], idx: u32) -> io::Result<&[u8]> {
        if self.held > DICT_CACHE_CAP {
            self.bodies.clear();
            self.held = 0;
        }
        if !self.bodies.contains_key(&idx) {
            let fr = &frags[idx as usize];
            let body = read_span(
                f,
                Span {
                    start: fr.start_byte,
                    len: fr.byte_count,
                },
            )?;
            self.held += body.len() as u64;
            self.bodies.insert(idx, body);
        }
        Ok(self
            .bodies
            .get(&idx)
            .map(|v| v.as_slice())
            .unwrap_or_default())
    }
}

fn zstd_dict_len(level: i32, dict: &[u8], target: &[u8]) -> io::Result<usize> {
    let blob = zstd::bulk::Compressor::with_dictionary(level, dict)
        .map_err(|e| io::Error::other(format!("zstd compressor init failed: {e}")))?
        .compress(target)
        .map_err(|e| io::Error::other(format!("zstd delta compression failed: {e}")))?;
    Ok(blob.len())
}

/// Index of the fragment covering byte `pos`, if any.
fn covering_frag(frags: &[Frag], pos: u64) -> Option<u32> {
    let i = frags.partition_point(|fr| fr.start_byte <= pos);
    if i == 0 {
        return None;
    }
    let fr = &frags[i - 1];
    let end = fr.start_byte + fr.byte_count.div_ceil(LBA_SIZE) * LBA_SIZE;
    (pos < end).then_some((i - 1) as u32)
}

#[derive(Default)]
struct Bucket {
    bytes: u64,
    runs: u64,
    lz4: u64,
    delta: u64,
}

impl Bucket {
    fn add(&mut self, raw: u64, lz4: u64, delta: u64) {
        self.bytes += raw;
        self.runs += 1;
        self.lz4 += lz4;
        self.delta += delta;
    }
}

fn mib(v: u64) -> f64 {
    v as f64 / (1 << 20) as f64
}

/// First three path components, for directory-level attribution.
fn rollup(path: &str) -> String {
    let parts: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).take(3).collect();
    format!("/{}", parts.join("/"))
}

fn attribute(map: &mut HashMap<String, u64>, frags: &[Frag], target: Span) {
    let key = match covering_frag(frags, target.start) {
        Some(idx) => rollup(&frags[idx as usize].path),
        None => "(unattributed)".to_string(),
    };
    *map.entry(key).or_default() += target.len;
}

fn print_top_paths(label: &str, map: &HashMap<String, u64>) {
    let mut rows: Vec<(&String, &u64)> = map.iter().collect();
    rows.sort_by(|a, b| b.1.cmp(a.1));
    println!("  {label} by directory:");
    for (path, bytes) in rows.into_iter().take(8) {
        println!("    {:>8.1} MiB  {}", mib(*bytes), path);
    }
}

pub fn run(
    before_path: &Path,
    after_path: &Path,
    level: i32,
    threshold: u64,
    kind: SketchKind,
) -> io::Result<()> {
    let mut before = File::open(before_path)?;
    let mut after = File::open(after_path)?;
    let image_size = before.metadata()?.len();
    if image_size != after.metadata()?.len() {
        return Err(io::Error::other(
            "before/after image sizes differ; expected two states of the same filesystem",
        ));
    }

    let sb = Superblock::read(&mut after)?;
    let journal = journal_spans(&mut after, &sb)?;

    println!("Scanning file fragments (before) ...");
    let before_frags = scan_file_fragments(before_path)?;
    println!("Scanning file fragments (after) ...");
    let after_frags = scan_file_fragments(after_path)?;
    let after_cover = frag_spans(&after_frags);

    println!("Diffing images ...");
    let runs = diff_images(&mut before, &mut after, image_size)?;
    let changed_total: u64 = runs.iter().map(|r| r.len).sum();

    // Classify: journal / non-file metadata / file data.
    let mut journal_bytes = 0u64;
    let mut meta_bytes = 0u64;
    let mut targets: Vec<Span> = Vec::new();
    for run in &runs {
        let (in_journal, rest) = partition_span(*run, &journal);
        journal_bytes += in_journal.iter().map(|s| s.len).sum::<u64>();
        for piece in rest {
            let (in_file, out_file) = partition_span(piece, &after_cover);
            meta_bytes += out_file.iter().map(|s| s.len).sum::<u64>();
            targets.extend(in_file);
        }
    }

    // Tier-1 replay: same-LBA prior fragment as dictionary.
    println!(
        "Replaying Tier-1 same-LBA selection over {} targets ...",
        targets.len()
    );
    let mut dicts = DictCache::new();
    let mut tier1_hit = Bucket::default();
    let mut misses: Vec<(Span, u64)> = Vec::new(); // (target, lz4 len)
    for &target in &targets {
        let body = read_span(&mut after, target)?;
        let lz4_len = lz4_flex::compress_prepend_size(&body).len() as u64;
        let delta_len = match covering_frag(&before_frags, target.start) {
            Some(idx) => {
                let dict = dicts.get(&mut before, &before_frags, idx)?.to_vec();
                Some(zstd_dict_len(level, &dict, &body)? as u64)
            }
            None => None,
        };
        match delta_len {
            Some(d) if d < lz4_len => tier1_hit.add(target.len, lz4_len, d),
            _ => misses.push((target, lz4_len)),
        }
    }

    // Similarity index over before-image fragments at or above threshold.
    println!("Building similarity index over before-image fragments ...");
    let index_start = Instant::now();
    let mut sf_index: HashMap<u64, Vec<u32>> = HashMap::new();
    let mut indexed_frags = 0u64;
    let mut indexed_bytes = 0u64;
    for (i, fr) in before_frags.iter().enumerate() {
        if fr.byte_count < threshold {
            continue;
        }
        let body = read_span(
            &mut before,
            Span {
                start: fr.start_byte,
                len: fr.byte_count,
            },
        )?;
        let Some(sfs) = sketch(kind, &body) else {
            continue;
        };
        for sf in sfs {
            sf_index.entry(sf).or_default().push(i as u32);
        }
        indexed_frags += 1;
        indexed_bytes += fr.byte_count;
    }
    let index_elapsed = index_start.elapsed();

    // Similarity matching over Tier-1 misses.
    println!("Matching {} Tier-1 misses ...", misses.len());
    let mut sim_recovered = Bucket::default();
    let mut sim_nocandidate = Bucket::default();
    let mut sim_nobenefit = Bucket::default();
    let mut subthreshold = Bucket::default();
    let mut candidates_tried = 0u64;
    let mut recovered_paths: HashMap<String, u64> = HashMap::new();
    let mut nocandidate_paths: HashMap<String, u64> = HashMap::new();

    // Path oracle: what same-path (Tier-2 filemap) matching would achieve
    // on the same misses. Largest before-fragment of the path is the
    // dictionary.
    let mut before_by_path: HashMap<&str, u32> = HashMap::new();
    for (i, fr) in before_frags.iter().enumerate() {
        let entry = before_by_path.entry(fr.path.as_str()).or_insert(i as u32);
        if before_frags[*entry as usize].byte_count < fr.byte_count {
            *entry = i as u32;
        }
    }
    // Miss bytes by (similarity recovered, oracle recovered).
    let mut matrix = [[0u64; 2]; 2];
    for &(target, lz4_len) in &misses {
        if target.len < threshold {
            subthreshold.add(target.len, lz4_len, 0);
            continue;
        }
        let body = read_span(&mut after, target)?;

        let oracle_ok = match covering_frag(&after_frags, target.start)
            .and_then(|i| before_by_path.get(after_frags[i as usize].path.as_str()))
        {
            Some(&idx) => {
                let dict = dicts.get(&mut before, &before_frags, idx)?.to_vec();
                (zstd_dict_len(level, &dict, &body)? as u64) < lz4_len
            }
            None => false,
        };

        let mut cands: Vec<u32> = Vec::new();
        for sf in sketch(kind, &body).unwrap_or_default() {
            if let Some(v) = sf_index.get(&sf) {
                for &idx in v {
                    if !cands.contains(&idx) {
                        cands.push(idx);
                    }
                }
            }
        }
        cands.truncate(MAX_CANDIDATES);
        let mut best: Option<u64> = None;
        for &idx in &cands {
            candidates_tried += 1;
            let dict = dicts.get(&mut before, &before_frags, idx)?.to_vec();
            let d = zstd_dict_len(level, &dict, &body)? as u64;
            if best.is_none_or(|b| d < b) {
                best = Some(d);
            }
        }
        let sim_ok = matches!(best, Some(d) if d < lz4_len);
        matrix[usize::from(sim_ok)][usize::from(oracle_ok)] += target.len;

        if cands.is_empty() {
            sim_nocandidate.add(target.len, lz4_len, 0);
            attribute(&mut nocandidate_paths, &after_frags, target);
            continue;
        }
        match best {
            Some(d) if d < lz4_len => {
                sim_recovered.add(target.len, lz4_len, d);
                attribute(&mut recovered_paths, &after_frags, target);
            }
            _ => sim_nobenefit.add(target.len, lz4_len, 0),
        }
    }

    // --- report ---

    let file_bytes = changed_total - journal_bytes - meta_bytes;
    let miss_bytes: u64 = misses.iter().map(|(s, _)| s.len).sum();
    println!();
    println!("=== delta-sim ===");
    println!("  image size:        {:.1} MiB", mib(image_size));
    println!(
        "  changed:           {:.1} MiB in {} runs",
        mib(changed_total),
        runs.len()
    );
    println!(
        "  journal:           {:.1} MiB ({:.1}%)",
        mib(journal_bytes),
        pct(journal_bytes, changed_total)
    );
    println!(
        "  metadata (non-file): {:.1} MiB ({:.1}%)",
        mib(meta_bytes),
        pct(meta_bytes, changed_total)
    );
    println!("  file data:         {:.1} MiB", mib(file_bytes));
    println!();
    println!(
        "  tier-1 hit:        {:.1} MiB in {} runs -> delta {:.1} MiB (lz4 {:.1} MiB)",
        mib(tier1_hit.bytes),
        tier1_hit.runs,
        mib(tier1_hit.delta),
        mib(tier1_hit.lz4)
    );
    println!(
        "  tier-1 miss:       {:.1} MiB in {} runs",
        mib(miss_bytes),
        misses.len()
    );
    println!(
        "    sim recovered:   {:.1} MiB in {} runs -> delta {:.1} MiB (lz4 {:.1} MiB)",
        mib(sim_recovered.bytes),
        sim_recovered.runs,
        mib(sim_recovered.delta),
        mib(sim_recovered.lz4)
    );
    println!(
        "    no candidate:    {:.1} MiB in {} runs (lz4 {:.1} MiB)",
        mib(sim_nocandidate.bytes),
        sim_nocandidate.runs,
        mib(sim_nocandidate.lz4)
    );
    println!(
        "    no benefit:      {:.1} MiB in {} runs",
        mib(sim_nobenefit.bytes),
        sim_nobenefit.runs
    );
    println!(
        "    sub-threshold:   {:.1} MiB in {} runs (< {} bytes)",
        mib(subthreshold.bytes),
        subthreshold.runs,
        threshold
    );
    println!(
        "    candidates tried: {} ({:.1} per matched run)",
        candidates_tried,
        candidates_tried as f64 / (sim_recovered.runs + sim_nobenefit.runs).max(1) as f64
    );
    println!();
    println!(
        "  sketch index ({}): {} fragments, {:.1} MiB scanned in {:.2}s ({:.0} MiB/s), {} SF entries (~{} KiB)",
        kind.name(),
        indexed_frags,
        mib(indexed_bytes),
        index_elapsed.as_secs_f64(),
        mib(indexed_bytes) / index_elapsed.as_secs_f64().max(1e-9),
        sf_index.values().map(Vec::len).sum::<usize>(),
        sf_index.values().map(Vec::len).sum::<usize>() * 12 / 1024
    );
    let recovered_share = pct(sim_recovered.bytes, miss_bytes.max(1));
    println!(
        "  miss bytes recovered by similarity: {:.1}%",
        recovered_share
    );
    println!();
    println!("  similarity vs same-path oracle (miss bytes >= threshold):");
    println!("    both find a source:  {:.1} MiB", mib(matrix[1][1]));
    println!("    similarity only:     {:.1} MiB", mib(matrix[1][0]));
    println!("    oracle only:         {:.1} MiB", mib(matrix[0][1]));
    println!("    neither:             {:.1} MiB", mib(matrix[0][0]));
    println!();
    print_top_paths("recovered", &recovered_paths);
    print_top_paths("no candidate", &nocandidate_paths);
    Ok(())
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn span(start: u64, len: u64) -> Span {
        Span { start, len }
    }

    #[test]
    fn partition_splits_across_cuts() {
        let cuts = vec![span(100, 50), span(200, 50)];
        let (inside, outside) = partition_span(span(80, 200), &cuts);
        assert_eq!(inside, vec![span(100, 50), span(200, 50)]);
        assert_eq!(outside, vec![span(80, 20), span(150, 50), span(250, 30)]);
    }

    #[test]
    fn partition_no_overlap() {
        let cuts = vec![span(1000, 100)];
        let (inside, outside) = partition_span(span(0, 100), &cuts);
        assert!(inside.is_empty());
        assert_eq!(outside, vec![span(0, 100)]);
    }

    #[test]
    fn partition_fully_inside() {
        let cuts = vec![span(0, 4096)];
        let (inside, outside) = partition_span(span(1024, 512), &cuts);
        assert_eq!(inside, vec![span(1024, 512)]);
        assert!(outside.is_empty());
    }

    fn base_data() -> Vec<u8> {
        (0..200_000u32).flat_map(|i| i.to_le_bytes()).collect()
    }

    #[test]
    fn sketch_is_deterministic_and_detects_similarity() {
        for kind in [SketchKind::Finesse, SketchKind::Broder] {
            let base = base_data();
            assert_eq!(sketch(kind, &base), sketch(kind, &base));

            // A lightly patched copy shares at least one super-feature.
            let mut patched = base.clone();
            for b in patched[1000..1200].iter_mut() {
                *b ^= 0xff;
            }
            let a = sketch(kind, &base).expect("sketchable");
            let b = sketch(kind, &patched).expect("sketchable");
            assert!(a.iter().any(|sf| b.contains(sf)), "{a:?} vs {b:?}");

            // Unrelated content shares none.
            let other: Vec<u8> = (0..200_000u32)
                .flat_map(|i| (i.wrapping_mul(2_654_435_761)).to_le_bytes())
                .collect();
            let c = sketch(kind, &other).expect("sketchable");
            assert!(!a.iter().any(|sf| c.contains(sf)), "{a:?} vs {c:?}");
        }
    }

    #[test]
    fn broder_sketch_tolerates_shifted_content() {
        let base = base_data();
        // Prepend an unaligned prefix so every byte lands at a new offset
        // (and in different fixed subchunks).
        let mut shifted = vec![0xa5u8; 4321];
        shifted.extend_from_slice(&base);
        let a = sketch(SketchKind::Broder, &base).expect("sketchable");
        let b = sketch(SketchKind::Broder, &shifted).expect("sketchable");
        assert!(a.iter().any(|sf| b.contains(sf)), "{a:?} vs {b:?}");
    }

    #[test]
    fn broder_sketch_rejects_tiny_input() {
        assert_eq!(sketch(SketchKind::Broder, &[0u8; 64]), None);
    }

    #[test]
    fn covering_frag_lookup() {
        let frags = vec![
            Frag {
                start_byte: 4096,
                byte_count: 8192,
                path: "/a".into(),
            },
            Frag {
                start_byte: 40960,
                byte_count: 100,
                path: "/b".into(),
            },
        ];
        assert_eq!(covering_frag(&frags, 0), None);
        assert_eq!(covering_frag(&frags, 4096), Some(0));
        assert_eq!(covering_frag(&frags, 12287), Some(0));
        assert_eq!(covering_frag(&frags, 12288), None);
        // Tail fragment covers its full final block.
        assert_eq!(covering_frag(&frags, 41000), Some(1));
        assert_eq!(covering_frag(&frags, 45056), None);
    }
}
