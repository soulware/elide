// Measurement over a captured volume corpus (`index/*.idx` + `cache/*.body`).
//
// Reports three things:
//
//   funnel — what share of stored bytes is even sketch-eligible, i.e. reaches
//            `sketch::MIN_SKETCH_BYTES` and can enter the delta tier at all
//   dict   — what a zstd dictionary trained on early segments achieves on
//            held-out later ones, against per-entry lz4 and dictionaryless
//            zstd, and how much of that is lost by training on the past
//   chain  — what successive versions of one LBA cost to delta against their
//            immediate predecessor and against a fixed anchor, and whether
//            retaining a superseded source pays for itself

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::sim_util::{mib, pct, zstd_len};
use elide_core::chunk_tree;
use elide_core::segment;
use elide_core::sketch::MIN_SKETCH_BYTES;

const ZSTD_LEVEL: i32 = 3;

/// The level `volume::compress_body` takes for segment bodies.
const BODY_LEVEL: i32 = 9;

/// Sample bytes to train on per byte of dictionary produced. Below roughly
/// this ratio zstd's trainer warns and the dictionary overfits its samples.
const TRAIN_RATIO: usize = 100;

/// Width of one training window.
const SAMPLE_BYTES: usize = 8 * 1024;

struct Version {
    seg: ulid::Ulid,
    hash: blake3::Hash,
    start_lba: u64,
    /// Zero for a canonical-only entry, which holds no LBA claim.
    lba_length: u32,
    /// Size as the segment stores it, so lz4 when `compressed` was set.
    stored_length: u32,
    plain: Vec<u8>,
}

pub struct Options {
    pub max_mib: u64,
    pub dict_sizes: Vec<usize>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_mib: 4096,
            dict_sizes: vec![16 << 10, 64 << 10, 112 << 10, 256 << 10, 1 << 20],
        }
    }
}

fn load(dir: &Path, max_bytes: u64) -> io::Result<Vec<Version>> {
    // A promoted volume splits each segment into `index/<id>.idx` and
    // `cache/<id>.body`; a freshly imported one holds whole segments in
    // `pending/` with the body section at an offset inside the same file.
    let index_dir = dir.join("index");
    let cache_dir = dir.join("cache");
    let pending_dir = dir.join("pending");

    let ulids_in = |d: &Path, suffix: &str| -> io::Result<Vec<ulid::Ulid>> {
        let mut out = Vec::new();
        let Ok(rd) = fs::read_dir(d) else {
            return Ok(out);
        };
        for entry in rd {
            let name = entry?.file_name();
            let name = name.to_string_lossy();
            let Some(stem) = name.strip_suffix(suffix) else {
                continue;
            };
            if let Ok(u) = ulid::Ulid::from_string(stem) {
                out.push(u);
            }
        }
        out.sort();
        Ok(out)
    };

    let mut promoted = ulids_in(&index_dir, ".idx")?;
    let pending = if promoted.is_empty() {
        ulids_in(&pending_dir, "")?
    } else {
        Vec::new()
    };
    promoted.sort();

    let sources: Vec<(std::path::PathBuf, std::path::PathBuf)> = if pending.is_empty() {
        promoted
            .iter()
            .map(|seg| {
                (
                    index_dir.join(format!("{seg}.idx")),
                    cache_dir.join(format!("{seg}.body")),
                )
            })
            .collect()
    } else {
        pending
            .iter()
            .map(|seg| {
                (
                    pending_dir.join(seg.to_string()),
                    pending_dir.join(seg.to_string()),
                )
            })
            .collect()
    };

    let mut out = Vec::new();
    let mut total = 0u64;
    for (idx_path, body_path) in sources {
        let seg = ulid::Ulid::from_string(
            idx_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default()
                .trim_end_matches(".idx"),
        )
        .map_err(|e| io::Error::other(e.to_string()))?;
        let (body_section_start, entries, _) = segment::read_segment_index(&idx_path)?;
        // A `.body` file is the body section alone, so entry offsets index it
        // from zero; a whole segment carries a header and index before it.
        let body_base = if body_path == idx_path {
            body_section_start
        } else {
            0
        };
        let Ok(f) = fs::File::open(&body_path) else {
            continue;
        };
        for e in entries {
            if !e.kind.is_data() || e.stored_length == 0 || e.journal {
                continue;
            }
            let mut buf = vec![0u8; e.stored_length as usize];
            if f.read_exact_at(&mut buf, body_base + e.stored_offset)
                .is_err()
            {
                continue;
            }
            let Ok(plain) = e.codec.decode(std::borrow::Cow::Owned(buf)) else {
                continue;
            };
            let plain = plain.into_owned();
            total += plain.len() as u64;
            out.push(Version {
                seg,
                hash: e.hash,
                start_lba: e.start_lba,
                lba_length: e.lba_length,
                stored_length: e.stored_length,
                plain,
            });
            if total >= max_bytes {
                return Ok(out);
            }
        }
    }
    Ok(out)
}

fn dict_len(comp: &mut zstd::bulk::Compressor<'_>, plain: &[u8]) -> io::Result<usize> {
    comp.compress(plain).map(|v| v.len())
}

fn funnel(versions: &[Version]) {
    let mut eligible_bytes = 0u64;
    let mut eligible_count = 0u64;
    let mut total_bytes = 0u64;
    let mut stored_bytes = 0u64;
    let mut buckets: BTreeMap<u32, (u64, u64)> = BTreeMap::new();

    for v in versions {
        let n = v.plain.len() as u64;
        total_bytes += n;
        stored_bytes += v.stored_length as u64;
        if v.plain.len() >= MIN_SKETCH_BYTES {
            eligible_bytes += n;
            eligible_count += 1;
        }
        let e = buckets.entry(size_bucket(v.plain.len())).or_default();
        e.0 += 1;
        e.1 += n;
    }

    let canonical = versions.iter().filter(|v| v.lba_length == 0).count();
    let canonical_bytes: u64 = versions
        .iter()
        .filter(|v| v.lba_length == 0)
        .map(|v| v.plain.len() as u64)
        .sum();

    println!("== funnel");
    println!(
        "canonical-only     {} entries ({:.1}%), {:.1} MiB ({:.1}% of plain bytes)",
        canonical,
        pct(canonical as u64, versions.len() as u64),
        mib(canonical_bytes),
        pct(canonical_bytes, total_bytes),
    );
    println!(
        "entries            {}  ({:.1} MiB plain, {:.1} MiB stored, {:.2}x)",
        versions.len(),
        mib(total_bytes),
        mib(stored_bytes),
        total_bytes as f64 / stored_bytes.max(1) as f64,
    );
    println!(
        "sketch-eligible    {} entries ({:.1}%), {:.1} MiB ({:.1}% of plain bytes)",
        eligible_count,
        pct(eligible_count, versions.len() as u64),
        mib(eligible_bytes),
        pct(eligible_bytes, total_bytes),
    );
    println!("size distribution (plain):");
    for (log2, (count, bytes)) in &buckets {
        println!(
            "  <= {:>7}  {:>8} entries  {:>9.1} MiB",
            fmt_pow2(*log2),
            count,
            mib(*bytes)
        );
    }
}

fn fmt_pow2(log2: u32) -> String {
    let n = 1u64 << log2;
    if n >= 1 << 20 {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} B")
    }
}

/// Fixed-size windows taken round-robin across `entries` at increasing
/// offsets, until the corpus reaches [`TRAIN_RATIO`] times `dict_bytes`.
///
/// zdict is built for many small samples. Whole entries run to a megabyte
/// here, which both dilutes the dictionary and leaves the trainer too few
/// samples to accept.
fn training_samples(entries: &[&Version], dict_bytes: usize) -> Vec<Vec<u8>> {
    let target = dict_bytes * TRAIN_RATIO;
    let mut samples: Vec<Vec<u8>> = Vec::new();
    let mut held = 0usize;
    let mut round = 0usize;
    while held < target {
        let mut added = 0usize;
        for v in entries {
            let off = round * SAMPLE_BYTES;
            if off + SAMPLE_BYTES > v.plain.len() {
                continue;
            }
            samples.push(v.plain[off..off + SAMPLE_BYTES].to_vec());
            held += SAMPLE_BYTES;
            added += 1;
            if held >= target {
                break;
            }
        }
        if added == 0 {
            break;
        }
        round += 1;
    }
    samples
}

/// Per-entry lz4 against zstd, both recomputed from plaintext so the
/// comparison is between codecs rather than against whatever the write path
/// happened to store.
/// Chunk sizes to sweep. Each is a power-of-two multiple of BLAKE3's 1 KiB
/// chunk, which is what makes a slice at a multiple of it a subtree.
const CHUNK_SIZES: [usize; 4] = [64 << 10, 128 << 10, 256 << 10, 512 << 10];

/// Stored size of `plain` as a chunked body at `chunk_bytes`: the table plus
/// one frame per chunk. Mirrors `volume::compress_body`'s layout, including
/// the 4-byte header and the 36 bytes each chunk costs in the table.
fn chunked_len(level: i32, plain: &[u8], chunk_bytes: usize) -> io::Result<usize> {
    let count = plain.len().div_ceil(chunk_bytes);
    let mut total = 4 + count * 36;
    for index in 0..count {
        let start = index * chunk_bytes;
        total += zstd_len(level, &plain[start..(start + chunk_bytes).min(plain.len())])?;
    }
    Ok(total)
}

fn codec_study(versions: &[Version]) -> io::Result<()> {
    let mut plain = 0u64;
    let mut lz4_total = 0u64;
    let mut zstd_total = 0u64;
    let mut lz4_wins = 0u64;
    let mut lz4_win_margin = 0u64;
    let mut win_sizes: BTreeMap<u32, u64> = BTreeMap::new();

    // The population chunking touches, and what it costs there. Extents at or
    // below one chunk are stored as a single frame either way.
    let mut big_entries = 0u64;
    let mut big_plain = 0u64;
    let mut big_whole9 = 0u64;
    let mut big_chunked9 = [0u64; CHUNK_SIZES.len()];
    let mut zstd9_total = 0u64;

    for v in versions {
        let lz4 = lz4_flex::compress_prepend_size(&v.plain).len() as u64;
        let zst = zstd_len(ZSTD_LEVEL, &v.plain)? as u64;
        let zst9 = zstd_len(BODY_LEVEL, &v.plain)? as u64;
        plain += v.plain.len() as u64;
        lz4_total += lz4;
        zstd_total += zst;
        zstd9_total += zst9;
        if lz4 < zst {
            lz4_wins += 1;
            lz4_win_margin += zst - lz4;
            *win_sizes.entry(size_bucket(v.plain.len())).or_default() += 1;
        }
        // Sized against the smallest chunk swept, so every size is reported
        // over one population.
        if v.plain.len() > CHUNK_SIZES[0] {
            big_entries += 1;
            big_plain += v.plain.len() as u64;
            big_whole9 += zst9;
            for (slot, chunk_bytes) in big_chunked9.iter_mut().zip(CHUNK_SIZES) {
                *slot += chunked_len(BODY_LEVEL, &v.plain, chunk_bytes)? as u64;
            }
        }
    }

    println!("\n== codec");
    println!(
        "plain              {:.1} MiB\nlz4                {:.1} MiB ({:.1}% of plain)\nzstd-{}             {:.1} MiB ({:.1}% of plain)\nzstd over lz4      {:.1} MiB fewer ({:.1}%)",
        mib(plain),
        mib(lz4_total),
        pct(lz4_total, plain),
        ZSTD_LEVEL,
        mib(zstd_total),
        pct(zstd_total, plain),
        mib(lz4_total.saturating_sub(zstd_total)),
        pct(lz4_total.saturating_sub(zstd_total), lz4_total),
    );
    println!(
        "zstd-{}             {:.1} MiB ({:.1}% of plain), {:.1}% under zstd-{}",
        BODY_LEVEL,
        mib(zstd9_total),
        pct(zstd9_total, plain),
        pct(zstd_total.saturating_sub(zstd9_total), zstd_total),
        ZSTD_LEVEL,
    );
    println!(
        "entries lz4 smaller {} of {} ({:.1}%), {} bytes total margin",
        lz4_wins,
        versions.len(),
        pct(lz4_wins, versions.len() as u64),
        lz4_win_margin,
    );
    for (log2, count) in &win_sizes {
        println!("  <= {:>7}  {:>6} entries", fmt_pow2(*log2), count);
    }

    println!(
        "\nchunking at zstd-{}, over the {} of {} entries above {} KiB \
         ({:.1} MiB, {:.1}% of all plaintext)",
        BODY_LEVEL,
        big_entries,
        versions.len(),
        CHUNK_SIZES[0] / 1024,
        mib(big_plain),
        pct(big_plain, plain),
    );
    if big_entries == 0 {
        println!("  no entry exceeds one chunk; chunking changes nothing here");
        return Ok(());
    }
    println!(
        "  one frame        {:.1} MiB ({:.1}% of that plaintext)",
        mib(big_whole9),
        pct(big_whole9, big_plain),
    );
    for (chunked, chunk_bytes) in big_chunked9.iter().zip(CHUNK_SIZES) {
        println!(
            "  {:>4} KiB chunks  {:.1} MiB ({:.1}% of it)  costs {:+.2}% against one frame, \
             {:+.3}% of all plaintext",
            chunk_bytes / 1024,
            mib(*chunked),
            pct(*chunked, big_plain),
            100.0 * (*chunked as f64 - big_whole9 as f64) / big_whole9 as f64,
            100.0 * (*chunked as f64 - big_whole9 as f64) / plain as f64,
        );
    }
    Ok(())
}

/// Per-entry-size totals for the dictionary comparison.
#[derive(Default)]
struct SizeBucket {
    entries: u64,
    plain: u64,
    zstd: u64,
    /// Dictionary output keyed by dictionary size, so each row can report the
    /// size that served it best rather than one chosen for the whole corpus.
    by_dict: BTreeMap<usize, u64>,
}

/// Power-of-two bucket an entry of `len` bytes falls in.
fn size_bucket(len: usize) -> u32 {
    (len as u64).next_power_of_two().trailing_zeros()
}

fn dict_study(versions: &[Version], dict_sizes: &[usize]) -> io::Result<()> {
    let segs: Vec<ulid::Ulid> = {
        let mut s: Vec<ulid::Ulid> = versions.iter().map(|v| v.seg).collect();
        s.dedup();
        s
    };
    if segs.len() < 2 {
        println!("\n== dict: need at least 2 segments, have {}", segs.len());
        return Ok(());
    }
    let split = segs[segs.len() / 2];
    let (early, late): (Vec<&Version>, Vec<&Version>) =
        versions.iter().partition(|v| v.seg < split);
    if early.is_empty() || late.is_empty() {
        println!("\n== dict: empty split");
        return Ok(());
    }

    let mut stored = 0u64;
    let mut plain = 0u64;
    let mut zstd_plain = 0u64;
    // Per-size totals as well as the aggregate: a dictionary earns most on
    // small inputs, and a total dominated by megabyte entries hides whatever
    // it does to the small ones.
    let mut buckets: BTreeMap<u32, SizeBucket> = BTreeMap::new();
    for v in &late {
        let z = zstd_len(ZSTD_LEVEL, &v.plain)? as u64;
        stored += v.stored_length as u64;
        plain += v.plain.len() as u64;
        zstd_plain += z;
        let b = buckets.entry(size_bucket(v.plain.len())).or_default();
        b.entries += 1;
        b.plain += v.plain.len() as u64;
        b.zstd += z;
    }

    println!("\n== dict");
    println!(
        "train on {} entries from {} early segs, test on {} entries from {} late segs",
        early.len(),
        segs.len() / 2,
        late.len(),
        segs.len() - segs.len() / 2,
    );
    println!(
        "test plain         {:.1} MiB\ntest as-stored     {:.1} MiB ({:.1}% of plain, lz4)\ntest zstd-{}       {:.1} MiB ({:.1}% of plain)",
        mib(plain),
        mib(stored),
        pct(stored, plain),
        ZSTD_LEVEL,
        mib(zstd_plain),
        pct(zstd_plain, plain),
    );

    for &size in dict_sizes {
        let samples = training_samples(&early, size);
        let held_out = match zstd::dict::from_samples(&samples, size) {
            Ok(d) => d,
            Err(e) => {
                println!("  dict {:>5} KiB  train failed: {e}", size >> 10);
                continue;
            }
        };
        // Same dictionary size trained on the test set itself, as the
        // ceiling a perfectly fresh dictionary could reach.
        let oracle_samples = training_samples(&late, size);
        let oracle = zstd::dict::from_samples(&oracle_samples, size).ok();

        let mut held_total = 0u64;
        let prepared = zstd::dict::EncoderDictionary::copy(&held_out, ZSTD_LEVEL);
        let mut comp = zstd::bulk::Compressor::with_prepared_dictionary(&prepared)?;
        for v in &late {
            let d = dict_len(&mut comp, &v.plain)? as u64;
            held_total += d;
            let b = buckets.entry(size_bucket(v.plain.len())).or_default();
            *b.by_dict.entry(size).or_default() += d;
        }

        let oracle_total = match &oracle {
            Some(d) => {
                let prepared = zstd::dict::EncoderDictionary::copy(d, ZSTD_LEVEL);
                let mut comp = zstd::bulk::Compressor::with_prepared_dictionary(&prepared)?;
                let mut t = 0u64;
                for v in &late {
                    t += dict_len(&mut comp, &v.plain)? as u64;
                }
                Some(t)
            }
            None => None,
        };

        let vs_stored = stored as i64 - held_total as i64;
        print!(
            "  dict {:>5} KiB  held-out {:>8.1} MiB ({:>5.1}% of plain)  vs as-stored {:+.1} MiB ({:+.1}%)",
            size >> 10,
            mib(held_total),
            pct(held_total, plain),
            vs_stored as f64 / (1024.0 * 1024.0),
            100.0 * vs_stored as f64 / stored.max(1) as f64,
        );
        match oracle_total {
            Some(o) => println!(
                "  oracle {:.1}% (drift {:.1} pts)",
                pct(o, plain),
                pct(held_total, plain) - pct(o, plain)
            ),
            None => println!(),
        }
    }

    println!("\nheld-out dictionary by entry size (best dictionary size per row):");
    println!(
        "  {:>9}  {:>7}  {:>10}  {:>10}  {:>10}  {:>7}  {:>8}",
        "size", "entries", "plain", "zstd", "best dict", "gain", "dict"
    );
    for (log2, b) in &buckets {
        let Some((&best_size, &best)) = b.by_dict.iter().min_by_key(|entry| *entry.1) else {
            continue;
        };
        println!(
            "  {:>9}  {:>7}  {:>10}  {:>10}  {:>10}  {:>6.1}%  {:>5} KiB",
            fmt_pow2(*log2),
            b.entries,
            b.plain,
            b.zstd,
            best,
            100.0 * (b.zstd as f64 - best as f64) / b.zstd.max(1) as f64,
            best_size >> 10,
        );
    }
    Ok(())
}

/// Successive versions of one LBA, oldest first, for every LBA rewritten at
/// least once with a sketch-eligible first version.
///
/// A canonical-only entry holds no LBA claim and carries `start_lba` 0, so it
/// belongs to no chain and is dropped before grouping — otherwise every such
/// entry in the corpus collapses into one group at LBA 0.
fn rewrite_chains(versions: &[Version]) -> Vec<Vec<&Version>> {
    let mut by_lba: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
    for (i, v) in versions.iter().enumerate() {
        if v.lba_length == 0 {
            continue;
        }
        by_lba.entry(v.start_lba).or_default().push(i);
    }

    let mut out = Vec::new();
    for idxs in by_lba.values() {
        let mut chain: Vec<&Version> = idxs.iter().map(|&i| &versions[i]).collect();
        chain.sort_by_key(|v| v.seg);
        chain.dedup_by_key(|v| v.hash);
        if chain.len() < 2 || chain[0].plain.len() < MIN_SKETCH_BYTES {
            continue;
        }
        out.push(chain);
    }
    out
}

fn chain_study(versions: &[Version]) -> io::Result<()> {
    let mut chains = 0u64;
    let mut steps = 0u64;
    let mut step_stored = 0u64;
    let mut step_zstd = 0u64;
    let mut step_prev = 0u64;
    let mut step_anchor = 0u64;
    let mut anchor_cost = 0u64;
    let mut len_hist: BTreeMap<usize, u64> = BTreeMap::new();
    // Delta size against the anchor as a share of dictionaryless zstd, by
    // how many versions downstream of the anchor the target sits.
    let mut decay: BTreeMap<usize, (u64, u64)> = BTreeMap::new();

    for chain in rewrite_chains(versions) {
        chains += 1;
        *len_hist.entry(chain.len().min(16)).or_default() += 1;
        anchor_cost += chain[0].stored_length as u64;

        let anchor_prepared = zstd::dict::EncoderDictionary::copy(&chain[0].plain, ZSTD_LEVEL);
        let mut anchor_comp = zstd::bulk::Compressor::with_prepared_dictionary(&anchor_prepared)?;

        for i in 1..chain.len() {
            let target = &chain[i].plain;
            steps += 1;
            step_stored += chain[i].stored_length as u64;
            step_zstd += zstd_len(ZSTD_LEVEL, target)? as u64;

            let prev_prepared =
                zstd::dict::EncoderDictionary::copy(&chain[i - 1].plain, ZSTD_LEVEL);
            let mut prev_comp = zstd::bulk::Compressor::with_prepared_dictionary(&prev_prepared)?;
            step_prev += dict_len(&mut prev_comp, target)? as u64;

            let a = dict_len(&mut anchor_comp, target)? as u64;
            step_anchor += a;
            let d = decay.entry(i.min(8)).or_default();
            d.0 += a;
            d.1 += zstd_len(ZSTD_LEVEL, target)? as u64;
        }
    }

    println!("\n== chain");
    if chains == 0 {
        println!("no LBA had two distinct sketch-eligible versions in this corpus");
        return Ok(());
    }
    println!(
        "chains {chains}, rewrite steps {steps}\nstep as-stored     {:.1} MiB\nstep zstd-{}       {:.1} MiB\ndelta vs previous  {:.1} MiB ({:.1}% of as-stored)\ndelta vs anchor    {:.1} MiB ({:.1}% of as-stored)",
        mib(step_stored),
        ZSTD_LEVEL,
        mib(step_zstd),
        mib(step_prev),
        pct(step_prev, step_stored),
        mib(step_anchor),
        pct(step_anchor, step_stored),
    );
    let saving_prev = step_stored as i64 - step_prev as i64;
    let saving_anchor = step_stored as i64 - step_anchor as i64;
    println!(
        "\nretention economics (anchor = keep chain[0] alive as a source):\n  saving vs previous {:+.1} MiB\n  saving vs anchor   {:+.1} MiB\n  anchor bytes kept  {:.1} MiB\n  net (anchor)       {:+.1} MiB",
        saving_prev as f64 / (1024.0 * 1024.0),
        saving_anchor as f64 / (1024.0 * 1024.0),
        mib(anchor_cost),
        (saving_anchor - anchor_cost as i64) as f64 / (1024.0 * 1024.0),
    );
    println!("\nchain length distribution:");
    for (len, count) in &len_hist {
        println!("  {len:>3} versions  {count:>7}");
    }
    println!("\ndelta-vs-anchor size as % of dictionaryless zstd, by distance:");
    for (dist, (a, z)) in &decay {
        println!("  +{dist:<2}  {:.1}%", pct(*a, *z));
    }
    Ok(())
}

pub fn run(dir: &Path, opts: Options) -> io::Result<()> {
    let versions = load(dir, opts.max_mib * 1024 * 1024)?;
    if versions.is_empty() {
        return Err(io::Error::other("no data entries found in corpus"));
    }
    funnel(&versions);
    codec_study(&versions)?;
    dict_study(&versions, &opts.dict_sizes)?;
    chain_study(&versions)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use elide_core::ulid_mint::UlidMint;

    fn version(seg: ulid::Ulid, start_lba: u64, lba_length: u32, plain: Vec<u8>) -> Version {
        Version {
            seg,
            hash: blake3::hash(&plain),
            start_lba,
            lba_length,
            stored_length: plain.len() as u32,
            plain,
        }
    }

    fn eligible(fill: u8) -> Vec<u8> {
        vec![fill; MIN_SKETCH_BYTES]
    }

    #[test]
    fn two_versions_of_one_lba_form_a_chain_in_segment_order() {
        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let (older, newer) = (mint.next(), mint.next());
        // Built newest-first so the ordering asserted below comes from the
        // sort rather than from insertion order.
        let versions = vec![
            version(newer, 64, 8, eligible(2)),
            version(older, 64, 8, eligible(1)),
        ];

        let chains = rewrite_chains(&versions);

        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].len(), 2);
        assert_eq!(chains[0][0].seg, older);
        assert_eq!(chains[0][1].seg, newer);
    }

    #[test]
    fn canonical_only_entries_form_no_chain() {
        let mut mint = UlidMint::new(ulid::Ulid::nil());
        // Canonical-only entries all carry start_lba 0 and lba_length 0, the
        // shape that collapsed the whole corpus into one chain.
        let versions = vec![
            version(mint.next(), 0, 0, eligible(1)),
            version(mint.next(), 0, 0, eligible(2)),
            version(mint.next(), 0, 0, eligible(3)),
        ];

        assert!(rewrite_chains(&versions).is_empty());
    }

    #[test]
    fn an_lba_written_once_is_not_a_chain() {
        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let versions = vec![version(mint.next(), 64, 8, eligible(1))];

        assert!(rewrite_chains(&versions).is_empty());
    }

    #[test]
    fn a_rewrite_to_identical_content_is_not_a_step() {
        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let versions = vec![
            version(mint.next(), 64, 8, eligible(7)),
            version(mint.next(), 64, 8, eligible(7)),
        ];

        assert!(rewrite_chains(&versions).is_empty());
    }

    #[test]
    fn a_chain_below_the_sketch_floor_is_dropped() {
        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let small = || vec![9u8; MIN_SKETCH_BYTES - 1];
        let versions = vec![
            version(mint.next(), 64, 8, small()),
            version(mint.next(), 64, 8, vec![8u8; MIN_SKETCH_BYTES - 1]),
        ];

        assert!(rewrite_chains(&versions).is_empty());
    }

    #[test]
    fn distinct_lbas_do_not_share_a_chain() {
        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let versions = vec![
            version(mint.next(), 64, 8, eligible(1)),
            version(mint.next(), 64, 8, eligible(2)),
            version(mint.next(), 512, 8, eligible(3)),
            version(mint.next(), 512, 8, eligible(4)),
        ];

        let chains = rewrite_chains(&versions);

        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0][0].start_lba, 64);
        assert_eq!(chains[1][0].start_lba, 512);
    }

    #[test]
    fn power_of_two_buckets_render_at_each_scale() {
        assert_eq!(fmt_pow2(9), "512 B");
        assert_eq!(fmt_pow2(10), "1 KiB");
        assert_eq!(fmt_pow2(15), "32 KiB");
        assert_eq!(fmt_pow2(20), "1 MiB");
    }
}
