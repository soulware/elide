// Human-readable inspection of elide binary file formats.
//
// inspect-segment <path>
//   Prints the header and index entries of a segment file or a cached .idx
//   file. Works on both: full segments (pending/, segments/) and index-only
//   files (cache/*.idx). Flags each data entry as OK or OVERFLOW relative
//   to the body file on disk (if present), and shows each entry's resemblance
//   sketch with the pairwise super-feature overlap between entries.
//
// inspect-wal <path>
//   Prints every record in a WAL file (wal/<ulid>). Uses scan_readonly so
//   the file is never modified.
//
// inspect-dmat <path>
//   Prints every materialised record in a `cache/<ulid>.dmat` file. The
//   scan is strictly read-only — the file is never modified, and the magic
//   is required to be already present.

use std::path::Path;

use elide_core::dmat::{self, DmatFlags};
use elide_core::segment::{self, EntryKind};
use elide_core::sketch;
use elide_core::writelog;

// --- inspect-segment ---

pub fn inspect_segment(path: &Path) -> std::io::Result<()> {
    let (body_section_start, entries, inputs) = segment::read_segment_index(path)?;

    // Detect whether this is a full segment or an index-only .idx file.
    // For .idx files, file_size == body_section_start (see idx_body_section_start).
    let file_size = std::fs::metadata(path)?.len();
    let is_idx_only = file_size == body_section_start;

    // If it's a full segment, body bytes follow immediately; body_size is
    // derivable from file_size. For .idx files, look for a sibling .body
    // file to get the actual body size for the overflow check.
    let body_size: Option<u64> = if is_idx_only {
        // Look for <stem>.body next to the .idx file.
        let body_path = path.with_extension("body");
        body_path
            .exists()
            .then(|| std::fs::metadata(&body_path).ok().map(|m| m.len()))
            .flatten()
    } else {
        Some(file_size - body_section_start)
    };

    let data_count = entries
        .iter()
        .filter(|e| e.kind != EntryKind::DedupRef && e.kind != EntryKind::Inline)
        .count();
    let dedup_count = entries
        .iter()
        .filter(|e| e.kind == EntryKind::DedupRef)
        .count();
    let inline_count = entries
        .iter()
        .filter(|e| e.kind == EntryKind::Inline)
        .count();

    println!("file:               {}", path.display());
    println!(
        "kind:               {}",
        if is_idx_only {
            "index-only (.idx)"
        } else {
            "full segment"
        }
    );
    println!("entry_count:        {}", entries.len());
    println!("body_section_start: {body_section_start}");
    println!(
        "body_size:          {}",
        match body_size {
            Some(n) => n.to_string(),
            None => "(no .body file)".to_string(),
        }
    );
    println!(
        "entries:            {data_count} data, {dedup_count} dedup_ref{}",
        if inline_count > 0 {
            format!(", {inline_count} inline")
        } else {
            String::new()
        }
    );
    if !inputs.is_empty() {
        println!("gc_inputs:          {} segment(s)", inputs.len());
        for input in &inputs {
            println!("  {input}");
        }
    }

    let data_entries: Vec<_> = entries.iter().collect();
    if data_entries.is_empty() {
        return Ok(());
    }

    let mut sorted = data_entries.clone();
    sorted.sort_by_key(|e| e.start_lba);

    let max_end = sorted
        .last()
        .map(|e| e.stored_offset + e.stored_length as u64)
        .unwrap_or(0);
    let overflow_count = body_size
        .map(|bs| {
            sorted
                .iter()
                .filter(|e| e.stored_offset + e.stored_length as u64 > bs)
                .count()
        })
        .unwrap_or(0);

    println!();
    println!(
        "{:<6}  {:<14}  {:>10}  {:>8}  {:<5}  status",
        "type", "lba_range", "body_off", "len", "codec"
    );
    println!("{}", "-".repeat(65));

    for e in &sorted {
        let end = e.stored_offset + e.stored_length as u64;
        let status = match body_size {
            Some(bs) if end > bs => "OVERFLOW",
            _ => "ok",
        };
        let kind_str = match e.kind {
            EntryKind::Data => "data",
            EntryKind::Inline => "inline",
            EntryKind::DedupRef => "dedup",
            EntryKind::Zero => "zero",
            EntryKind::Delta => "delta",
            EntryKind::CanonicalData => "canon-data",
            EntryKind::CanonicalInline => "canon-inline",
            EntryKind::CanonicalDelta => "canon-delta",
        };
        println!(
            "{:<6}  {:<14}  {:>10}  {:>8}  {:<5}  {:<8}  {}",
            kind_str,
            format!("[{}+{})", e.start_lba, e.lba_length),
            e.stored_offset,
            e.stored_length,
            e.codec.to_string(),
            status,
            e.hash.to_hex(),
        );
        for opt in &e.delta_options {
            println!(
                "          source={} delta_off={} delta_len={} delta_hash={}",
                opt.source_hash.to_hex(),
                opt.delta_offset,
                opt.delta_length,
                elide_core::segment::stored_hash_hex(&opt.delta_hash),
            );
        }
    }

    println!();
    println!(
        "max body used: {max_end}{}",
        body_size.map(|bs| format!(" / {bs}")).unwrap_or_default()
    );
    if overflow_count > 0 {
        println!("WARNING: {overflow_count} entries overflow the body file");
    }

    print_sketches(&sorted);

    Ok(())
}

/// Resemblance-sketch view: which entries carry a sketch, a short fingerprint
/// of each, and the pairwise feature overlap. The count two entries share
/// estimates their resemblance, which is the signal the similarity delta
/// producer ranks candidates on.
fn print_sketches(sorted: &[&segment::SegmentEntry]) {
    use elide_core::sketch::NUM_FEATURES;

    let sketchable = sorted
        .iter()
        .filter(|e| matches!(e.kind, EntryKind::Data | EntryKind::CanonicalData))
        .count();
    let sketched: Vec<&&segment::SegmentEntry> =
        sorted.iter().filter(|e| e.sketch.is_some()).collect();

    println!();
    println!(
        "sketches:           {} of {sketchable} data entr{} carry a resemblance sketch",
        sketched.len(),
        if sketchable == 1 { "y" } else { "ies" }
    );
    if sketched.is_empty() {
        return;
    }

    let lba = |e: &segment::SegmentEntry| format!("[{}+{})", e.start_lba, e.lba_length);

    println!();
    println!(
        "  {:<14}  {:<12}  features (top 16 bits each)",
        "lba_range", "hash"
    );
    for e in &sketched {
        let sk = e.sketch.expect("filtered to Some");
        let fp: Vec<String> = sk
            .iter()
            .map(|s| format!("{:04x}", (s >> 16) as u16))
            .collect();
        println!(
            "  {:<14}  {:<12}  {}",
            lba(e),
            &e.hash.to_hex()[..12],
            fp.join(" ")
        );
    }

    // Pairwise overlap over the full-width features (the fingerprint above
    // is truncated only for display).
    let mut pairs: Vec<(usize, usize, usize)> = Vec::new();
    for i in 0..sketched.len() {
        for j in (i + 1)..sketched.len() {
            let a = sketched[i].sketch.expect("filtered to Some");
            let b = sketched[j].sketch.expect("filtered to Some");
            let shared = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
            if shared > 0 {
                pairs.push((i, j, shared));
            }
        }
    }
    println!();
    if pairs.is_empty() {
        println!("shared features: none (no two entries resemble each other)");
        return;
    }
    pairs.sort_by_key(|p| std::cmp::Reverse(p.2));
    println!("shared features (likely-similar pairs, most first):");
    for (i, j, shared) in pairs {
        println!(
            "  {:<14} <-> {:<14}  {shared}/{NUM_FEATURES} shared",
            lba(sketched[i]),
            lba(sketched[j])
        );
    }
}

// --- inspect-wal ---

/// Build the candidate map for a volume's lineage from `.idx` files alone
/// and report its shape. Offline: reads no bodies and needs no running
/// volume, so it answers what the map costs on real content.
pub fn inspect_sketch_index(fork_dir: &Path) -> std::io::Result<()> {
    // Canonicalize so a by_name symlink resolves and the parent is the
    // by_id directory ancestor lookup needs.
    let dir = std::fs::canonicalize(fork_dir).unwrap_or_else(|_| fork_dir.to_owned());
    let by_id_dir = dir.parent().unwrap_or(&dir).to_owned();
    let ancestors = elide_core::volume::walk_ancestors(&dir, &by_id_dir)?;
    let chain: Vec<(std::path::PathBuf, Option<String>)> = ancestors
        .iter()
        .map(|l| (l.dir.clone(), l.branch_ulid.clone()))
        .chain(std::iter::once((dir.clone(), None)))
        .collect();

    let started = std::time::Instant::now();
    let (extents, sketches) = elide_core::extentindex::rebuild_with_sketches(&chain)?;
    let elapsed = started.elapsed();
    let st = sketches.stats();

    println!("=== sketch index ===");
    println!("  volume:            {}", dir.display());
    println!("  lineage:           {} layer(s)", chain.len());
    println!("  built in:          {elapsed:.2?}");
    println!();
    println!("  extent index:      {} hash(es)", extents.len());
    println!(
        "  sketched sources:  {} ({:.1}% of extent-index hashes)",
        st.sources,
        pct(st.sources as u64, extents.len() as u64)
    );
    println!("  postings:          {}", st.postings);
    println!(
        "  slots:             {} ({:.0}% occupied)",
        st.slots,
        pct(st.postings as u64, st.slots as u64)
    );
    if st.sources == 0 {
        println!(
            "  memory:            {:.1} KiB",
            st.memory_bytes as f64 / 1024.0
        );
        println!();
        println!(
            "  nothing sketched: no extent in this lineage is at or above {} bytes",
            sketch::MIN_SKETCH_BYTES
        );
        return Ok(());
    }
    println!(
        "  memory:            {:.1} KiB ({:.0} bytes per source)",
        st.memory_bytes as f64 / 1024.0,
        st.memory_bytes as f64 / st.sources as f64
    );
    println!();
    println!(
        "  distinct features: {} ({:.2} postings each on average)",
        st.distinct_features,
        st.postings as f64 / (st.distinct_features.max(1) as f64)
    );
    println!("  busiest feature:   {} sources", st.max_per_feature);
    println!(
        "  features at cap:   {} (further sources declined)",
        st.features_at_cap
    );
    Ok(())
}

fn pct(part: u64, whole: u64) -> f64 {
    if whole == 0 {
        return 0.0;
    }
    part as f64 * 100.0 / whole as f64
}

pub fn inspect_wal(path: &Path) -> std::io::Result<()> {
    let (records, truncated) = writelog::scan_readonly(path)?;

    let data_count = records
        .iter()
        .filter(|r| matches!(r, writelog::LogRecord::Data { .. }))
        .count();
    let ref_count = records
        .iter()
        .filter(|r| matches!(r, writelog::LogRecord::Ref { .. }))
        .count();

    println!("file:     {}", path.display());
    println!("records:  {} data, {} dedup_ref", data_count, ref_count);
    if truncated {
        println!("WARNING:  truncated tail record detected (crash recovery may apply)");
    }

    if records.is_empty() {
        println!("(empty)");
        return Ok(());
    }

    println!();
    println!(
        "{:<6}  {:<14}  {:>10}  {:>8}  codec",
        "type", "lba_range", "body_off", "len"
    );
    println!("{}", "-".repeat(55));

    for record in &records {
        match record {
            writelog::LogRecord::Data {
                start_lba,
                lba_length,
                flags,
                body_offset,
                data,
                ..
            } => {
                let codec = segment::Codec::from_wal_flags(*flags);
                println!(
                    "{:<6}  {:<14}  {:>10}  {:>8}  {}",
                    "data",
                    format!("[{}+{})", start_lba, lba_length),
                    body_offset,
                    data.len(),
                    codec,
                );
            }
            writelog::LogRecord::Ref {
                start_lba,
                lba_length,
                ..
            } => {
                println!(
                    "{:<6}  {:<14}  {:>10}  {:>8}  -",
                    "ref",
                    format!("[{}+{})", start_lba, lba_length),
                    "-",
                    "-",
                );
            }
            writelog::LogRecord::Zero {
                start_lba,
                lba_length,
            } => {
                println!(
                    "{:<6}  {:<14}  {:>10}  {:>8}  -",
                    "zero",
                    format!("[{}+{})", start_lba, lba_length),
                    "-",
                    "-",
                );
            }
        }
    }

    Ok(())
}

// --- inspect-dmat ---

pub fn inspect_dmat(path: &Path) -> std::io::Result<()> {
    let (records, scan) = dmat::scan_readonly(path)?;
    let file_size = std::fs::metadata(path)?.len();

    let compressed_count = records
        .iter()
        .filter(|r| r.flags.contains(DmatFlags::COMPRESSED))
        .count();
    let total_stored: u64 = records.iter().map(|r| r.stored_length as u64).sum();

    println!("file:        {}", path.display());
    println!("file_size:   {file_size}");
    println!("records:     {}", records.len());
    println!(
        "compressed:  {compressed_count} ({} raw)",
        records.len() - compressed_count
    );
    println!("stored:      {total_stored} bytes (sum of record payloads)");
    if scan.truncated {
        println!(
            "WARNING:     would-truncate-on-open: {} record(s) past last clean frame",
            scan.invalid
        );
    }

    if records.is_empty() {
        println!("(no records)");
        return Ok(());
    }

    println!();
    println!(
        "{:>6}  {:>10}  {:>10}  {:>6}",
        "idx", "offset", "len", "comp"
    );
    println!("{}", "-".repeat(40));
    for r in &records {
        println!(
            "{:>6}  {:>10}  {:>10}  {:>6}",
            r.entry_idx,
            r.record_offset,
            r.stored_length,
            if r.flags.contains(DmatFlags::COMPRESSED) {
                "yes"
            } else {
                "no"
            }
        );
    }

    Ok(())
}
