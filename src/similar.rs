use std::collections::HashMap;
use std::path::Path;

use ext4_view::{DirEntry, Ext4, Ext4Error, Metadata, PathBuf as Ext4PathBuf};

const NUM_HASHES: usize = 128;
const BANDS: usize = 32;
const ROWS: usize = NUM_HASHES / BANDS; // 4
const MAX_BUCKET_SIZE: usize = 50;
const ZSTD_LEVEL: i32 = 3;

fn make_hash_params() -> (Vec<u64>, Vec<u64>) {
    let mut state: u64 = 0xdeadbeefcafe1234;
    let mut a = Vec::with_capacity(NUM_HASHES);
    let mut b = Vec::with_capacity(NUM_HASHES);
    for _ in 0..NUM_HASHES {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        a.push(state | 1);
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        b.push(state);
    }
    (a, b)
}

fn minhash(chunk: &[u8], a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut sig = vec![u64::MAX; NUM_HASHES];
    for shingle in chunk.chunks(4) {
        let x = shingle.iter().fold(0u64, |acc, &byte| acc.wrapping_shl(8) | byte as u64);
        for i in 0..NUM_HASHES {
            let h = a[i].wrapping_mul(x).wrapping_add(b[i]);
            if h < sig[i] {
                sig[i] = h;
            }
        }
    }
    sig
}

fn jaccard_estimate(sig1: &[u64], sig2: &[u64]) -> f64 {
    let matches = sig1.iter().zip(sig2.iter()).filter(|(a, b)| a == b).count();
    matches as f64 / NUM_HASHES as f64
}

struct ChunkInfo {
    image_idx: usize,
    file: String,
    position: usize,
    hash: blake3::Hash,
    sig: Vec<u64>,
}

fn load_chunks(
    fs: &Ext4,
    chunk_size: usize,
    image_idx: usize,
    a: &[u64],
    b: &[u64],
) -> Result<Vec<ChunkInfo>, Ext4Error> {
    let mut chunks = Vec::new();
    let mut queue: Vec<Ext4PathBuf> = vec![Ext4PathBuf::new("/")];

    while let Some(dir) = queue.pop() {
        for entry in fs.read_dir(&dir)? {
            let entry: DirEntry = entry?;
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = entry.path();
            let metadata: Metadata = match fs.symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.file_type().is_dir() {
                queue.push(path);
            } else if metadata.file_type().is_regular_file() {
                let data: Vec<u8> = match fs.read(&path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                let file_name = String::from_utf8_lossy(path.as_ref()).into_owned();
                for (pos, chunk) in data.chunks(chunk_size).enumerate() {
                    if chunk.len() < 64 || chunk.iter().all(|&b| b == 0) {
                        continue;
                    }
                    let hash = blake3::hash(chunk);
                    let sig = minhash(chunk, a, b);
                    chunks.push(ChunkInfo { image_idx, file: file_name.clone(), position: pos, hash, sig });
                }
            }
        }
    }

    Ok(chunks)
}

fn fetch_chunks(
    fs: &Ext4,
    needed: &std::collections::HashSet<(String, usize)>,
    chunk_size: usize,
) -> Result<HashMap<(String, usize), Vec<u8>>, Ext4Error> {
    let mut chunk_data: HashMap<(String, usize), Vec<u8>> = HashMap::new();
    let mut queue: Vec<Ext4PathBuf> = vec![Ext4PathBuf::new("/")];

    while let Some(dir) = queue.pop() {
        for entry in fs.read_dir(&dir)? {
            let entry: DirEntry = entry?;
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = entry.path();
            let metadata: Metadata = match fs.symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if metadata.file_type().is_dir() {
                queue.push(path);
            } else if metadata.file_type().is_regular_file() {
                let file_name = String::from_utf8_lossy(path.as_ref()).into_owned();
                let positions_needed: Vec<usize> = needed
                    .iter()
                    .filter(|(f, _)| f == &file_name)
                    .map(|(_, p)| *p)
                    .collect();
                if positions_needed.is_empty() {
                    continue;
                }
                let data: Vec<u8> = match fs.read(&path) {
                    Ok(d) => d,
                    Err(_) => continue,
                };
                for pos in positions_needed {
                    let start = pos * chunk_size;
                    if start < data.len() {
                        let end = (start + chunk_size).min(data.len());
                        chunk_data.insert((file_name.clone(), pos), data[start..end].to_vec());
                    }
                }
            }
        }
    }

    Ok(chunk_data)
}

fn print_distribution(similarities: &[(f64, usize, usize)], label: &str) {
    if similarities.is_empty() {
        println!("  {}: none", label);
        return;
    }
    let mut dist_buckets = [0usize; 5];
    for &(sim, _, _) in similarities {
        let bucket = ((sim * 5.0) as usize).min(4);
        dist_buckets[bucket] += 1;
    }
    println!("\n  {} Jaccard distribution ({} pairs):", label, similarities.len());
    let labels = ["0.0-0.2", "0.2-0.4", "0.4-0.6", "0.6-0.8", "0.8-1.0"];
    for (i, &count) in dist_buckets.iter().enumerate() {
        let pct = 100.0 * count as f64 / similarities.len() as f64;
        let bar: String = "#".repeat((pct / 2.0) as usize);
        println!("    [{}]: {:>6} ({:>5.1}%)  {}", labels[i], count, pct, bar);
    }
}

fn investigate_perfect_pairs(
    pairs: &[(usize, usize)],
    chunks: &[ChunkInfo],
    fs1: &Ext4,
    fs2: Option<&Ext4>,
    chunk_size: usize,
    label: &str,
) -> Result<(), Ext4Error> {
    let capped: Vec<(usize, usize)> = pairs.iter().copied().take(50).collect();
    if capped.is_empty() {
        return Ok(());
    }

    println!("\n  Loading chunk data for {} perfect-Jaccard {} pairs...", capped.len(), label);

    // Partition needed chunks by image
    let mut needed0: std::collections::HashSet<(String, usize)> = std::collections::HashSet::new();
    let mut needed1: std::collections::HashSet<(String, usize)> = std::collections::HashSet::new();
    for &(i, j) in &capped {
        let ci = &chunks[i];
        let cj = &chunks[j];
        if ci.image_idx == 0 { needed0.insert((ci.file.clone(), ci.position)); }
        else { needed1.insert((ci.file.clone(), ci.position)); }
        if cj.image_idx == 0 { needed0.insert((cj.file.clone(), cj.position)); }
        else { needed1.insert((cj.file.clone(), cj.position)); }
    }

    let data0 = fetch_chunks(fs1, &needed0, chunk_size)?;
    let data1 = if let Some(fs) = fs2 {
        fetch_chunks(fs, &needed1, chunk_size)?
    } else {
        HashMap::new()
    };

    println!("\n  Perfect-Jaccard {} pairs — byte differences and delta compression:", label);
    println!("  {:>8}  {:>7}  {:>9}  {:>9}  {:>9}  {}", "diffbytes", "diff%", "raw", "standalone", "dict", "pair");

    let mut diff_counts: Vec<usize> = Vec::new();
    let mut total_raw = 0usize;
    let mut total_standalone = 0usize;
    let mut total_dict = 0usize;

    for (i, j) in &capped {
        let ci = &chunks[*i];
        let cj = &chunks[*j];
        let key_i = (ci.file.clone(), ci.position);
        let key_j = (cj.file.clone(), cj.position);
        let chunk_i = if ci.image_idx == 0 { data0.get(&key_i) } else { data1.get(&key_i) };
        let chunk_j = if cj.image_idx == 0 { data0.get(&key_j) } else { data1.get(&key_j) };

        if let (Some(c1), Some(c2)) = (chunk_i, chunk_j) {
            let len = c1.len().min(c2.len());
            let diff = c1[..len].iter().zip(c2[..len].iter()).filter(|(a, b)| a != b).count()
                + c1.len().abs_diff(c2.len());
            let diff_pct = 100.0 * diff as f64 / len.max(1) as f64;
            diff_counts.push(diff);

            let standalone = zstd::bulk::compress(c2, ZSTD_LEVEL).unwrap_or_default();
            let dict_compressed = zstd::bulk::Compressor::with_dictionary(ZSTD_LEVEL, c1)
                .and_then(|mut c| c.compress(c2))
                .unwrap_or_else(|_| standalone.clone());

            total_raw += c2.len();
            total_standalone += standalone.len();
            total_dict += dict_compressed.len();

            let img_i = if ci.image_idx == 0 { "img1" } else { "img2" };
            let img_j = if cj.image_idx == 0 { "img1" } else { "img2" };
            println!(
                "  {:>8}  {:>6.2}%  {:>9}  {:>9}  {:>9}  {}:{}[{}]  <>  {}:{}[{}]",
                diff, diff_pct, c2.len(), standalone.len(), dict_compressed.len(),
                img_i, ci.file, ci.position,
                img_j, cj.file, cj.position
            );
        }
    }

    if !diff_counts.is_empty() {
        diff_counts.sort();
        println!("\n  Summary for {} pairs:", diff_counts.len());
        println!("    Differing bytes — median: {}, max: {}", diff_counts[diff_counts.len() / 2], diff_counts[diff_counts.len() - 1]);
        println!("    Raw total:        {:>9} bytes", total_raw);
        println!("    Standalone zstd:  {:>9} bytes ({:.1}x)", total_standalone, total_raw as f64 / total_standalone.max(1) as f64);
        println!("    Dict zstd:        {:>9} bytes ({:.1}x)", total_dict, total_raw as f64 / total_dict.max(1) as f64);
        println!("    Delta benefit:    {:>9} bytes saved ({:.1}%)",
            total_standalone.saturating_sub(total_dict),
            100.0 * total_standalone.saturating_sub(total_dict) as f64 / total_standalone.max(1) as f64);
    }

    Ok(())
}

pub fn run(image1: &Path, image2: Option<&Path>, chunk_size: usize) -> Result<(), Ext4Error> {
    let (a, b) = make_hash_params();

    println!("Loading {}...", image1.display());
    let fs1 = Ext4::load_from_path(image1)?;
    let mut chunks = load_chunks(&fs1, chunk_size, 0, &a, &b)?;

    let fs2 = if let Some(p) = image2 {
        println!("Loading {}...", p.display());
        let fs = Ext4::load_from_path(p)?;
        let img2_chunks = load_chunks(&fs, chunk_size, 1, &a, &b)?;
        chunks.extend(img2_chunks);
        Some(fs)
    } else {
        None
    };

    println!("Chunks loaded: {} total", chunks.len());
    println!("Computing LSH buckets...");

    let mut candidate_pairs: std::collections::HashSet<(usize, usize)> = std::collections::HashSet::new();

    for band in 0..BANDS {
        let mut buckets: HashMap<u64, Vec<usize>> = HashMap::new();
        let row_start = band * ROWS;
        let row_end = row_start + ROWS;

        for (idx, chunk) in chunks.iter().enumerate() {
            let band_key = chunk.sig[row_start..row_end]
                .iter()
                .fold(0u64, |acc, &v| acc.wrapping_mul(6364136223846793005).wrapping_add(v));
            buckets.entry(band_key).or_default().push(idx);
        }

        for members in buckets.values() {
            if members.len() < 2 || members.len() > MAX_BUCKET_SIZE {
                continue;
            }
            for i in 0..members.len() {
                for j in i + 1..members.len() {
                    let (lo, hi) = if members[i] < members[j] { (members[i], members[j]) } else { (members[j], members[i]) };
                    candidate_pairs.insert((lo, hi));
                }
            }
        }
    }

    println!("Candidate pairs: {}", candidate_pairs.len());

    // Compute similarities, filter exact matches, split same-image vs cross-image
    let mut same_image: Vec<(f64, usize, usize)> = Vec::new();
    let mut cross_image: Vec<(f64, usize, usize)> = Vec::new();
    let mut exact_pairs = 0usize;

    for &(i, j) in &candidate_pairs {
        if chunks[i].hash == chunks[j].hash {
            exact_pairs += 1;
            continue;
        }
        let sim = jaccard_estimate(&chunks[i].sig, &chunks[j].sig);
        if chunks[i].image_idx == chunks[j].image_idx {
            same_image.push((sim, i, j));
        } else {
            cross_image.push((sim, i, j));
        }
    }

    same_image.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());
    cross_image.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap());

    println!("\n=== Similarity Report ===");
    println!("  Chunks analysed:         {}", chunks.len());
    println!("  Candidate pairs (LSH):   {}", candidate_pairs.len());
    println!("  Exact match pairs:       {}", exact_pairs);
    println!("  Same-image near-dupes:   {}", same_image.len());
    if image2.is_some() {
        println!("  Cross-image near-dupes:  {}", cross_image.len());
    }

    print_distribution(&same_image, "Same-image");
    if image2.is_some() {
        print_distribution(&cross_image, "Cross-image");

        println!("\n  Top 30 cross-image pairs:");
        for &(sim, i, j) in cross_image.iter().take(30) {
            println!("    {:.3}  img1:{}[{}]  <>  img2:{}[{}]",
                sim, chunks[i].file, chunks[i].position, chunks[j].file, chunks[j].position);
        }
    } else {
        println!("\n  Top 30 most similar pairs:");
        for &(sim, i, j) in same_image.iter().take(30) {
            println!("    {:.3}  {}[{}]  <>  {}[{}]",
                sim, chunks[i].file, chunks[i].position, chunks[j].file, chunks[j].position);
        }
    }

    // Investigate perfect-Jaccard pairs
    let perfect_same: Vec<(usize, usize)> = same_image.iter()
        .filter(|&&(sim, _, _)| sim == 1.0)
        .map(|&(_, i, j)| (i, j))
        .collect();

    investigate_perfect_pairs(&perfect_same, &chunks, &fs1, fs2.as_ref(), chunk_size, "same-image")?;

    if image2.is_some() {
        let perfect_cross: Vec<(usize, usize)> = cross_image.iter()
            .filter(|&&(sim, _, _)| sim == 1.0)
            .map(|&(_, i, j)| (i, j))
            .collect();
        investigate_perfect_pairs(&perfect_cross, &chunks, &fs1, fs2.as_ref(), chunk_size, "cross-image")?;
    }

    Ok(())
}
