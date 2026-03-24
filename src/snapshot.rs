use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::Path;

use ext4_view::{DirEntry, Ext4, Ext4Error, Metadata, PathBuf as Ext4PathBuf};

const MAGIC: &[u8; 8] = b"PLMPST\x00\x01";
const HEADER_SIZE: usize = 88;
const ENTRY_SIZE: usize = 40;

pub struct Snapshot {
    pub snapshot_id: blake3::Hash,
    pub volume_id: [u8; 32],
    pub parent_id: [u8; 32],
    pub chunk_size: u32,
    pub timestamp: u64,
    pub entries: Vec<(u64, blake3::Hash)>, // (lba, hash), sorted by lba
}

impl Snapshot {
    pub fn is_root(&self) -> bool {
        self.parent_id == [0u8; 32]
    }

    pub fn hash_set(&self) -> std::collections::HashSet<blake3::Hash> {
        self.entries.iter().map(|(_, h)| *h).collect()
    }
}

fn read_u32_le(buf: &[u8]) -> u32 {
    u32::from_le_bytes(buf[..4].try_into().unwrap())
}

fn read_u64_le(buf: &[u8]) -> u64 {
    u64::from_le_bytes(buf[..8].try_into().unwrap())
}

pub fn load(path: &Path) -> Snapshot {
    let mut data = Vec::new();
    File::open(path)
        .expect("failed to open snapshot")
        .read_to_end(&mut data)
        .expect("failed to read snapshot");

    assert!(data.len() >= HEADER_SIZE, "file too small to be a snapshot");
    assert_eq!(&data[0..8], MAGIC, "bad magic — not a palimpsest snapshot");

    let snapshot_id = blake3::hash(&data);

    let mut volume_id = [0u8; 32];
    let mut parent_id = [0u8; 32];
    volume_id.copy_from_slice(&data[8..40]);
    parent_id.copy_from_slice(&data[40..72]);
    let chunk_size = read_u32_le(&data[72..]);
    let entry_count = read_u32_le(&data[76..]) as usize;
    let timestamp = read_u64_le(&data[80..]);

    assert_eq!(
        data.len(),
        HEADER_SIZE + entry_count * ENTRY_SIZE,
        "snapshot file size does not match entry_count"
    );

    let mut entries = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let off = HEADER_SIZE + i * ENTRY_SIZE;
        let lba = read_u64_le(&data[off..]);
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&data[off + 8..off + 40]);
        entries.push((lba, blake3::Hash::from(hash_bytes)));
    }

    Snapshot { snapshot_id, volume_id, parent_id, chunk_size, timestamp, entries }
}

fn write_snapshot(entries: &[(u64, blake3::Hash)], volume_id: [u8; 32], parent_id: [u8; 32], chunk_size: u32) -> Vec<u8> {
    let entry_count = entries.len();
    let mut buf = Vec::with_capacity(HEADER_SIZE + entry_count * ENTRY_SIZE);

    buf.extend_from_slice(MAGIC);
    buf.extend_from_slice(&volume_id);
    buf.extend_from_slice(&parent_id);
    buf.extend_from_slice(&chunk_size.to_le_bytes());
    buf.extend_from_slice(&(entry_count as u32).to_le_bytes());
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    buf.extend_from_slice(&timestamp.to_le_bytes());

    for &(lba, hash) in entries {
        buf.extend_from_slice(&lba.to_le_bytes());
        buf.extend_from_slice(hash.as_bytes());
    }

    buf
}

pub fn generate(image: &Path, chunk_kb: usize, parent: Option<&Path>, out_dir: &Path) -> Result<(), Ext4Error> {
    let chunk_size = chunk_kb * 1024;
    let fs = Ext4::load_from_path(image)?;
    let mut file_chunks: Vec<(String, Vec<blake3::Hash>)> = Vec::new();
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
                let hashes: Vec<blake3::Hash> = data
                    .chunks(chunk_size)
                    .filter(|c| !c.iter().all(|&b| b == 0))
                    .map(blake3::hash)
                    .collect();
                if !hashes.is_empty() {
                    file_chunks.push((file_name, hashes));
                }
            }
        }
    }

    // Sort by file path for deterministic LBA assignment
    file_chunks.sort_by(|a, b| a.0.cmp(&b.0));

    // Assign synthetic LBAs: each file gets a contiguous range
    let blocks_per_chunk = (chunk_size / 4096) as u64;
    let mut entries: Vec<(u64, blake3::Hash)> = Vec::new();
    let mut lba: u64 = 0;
    for (_, hashes) in &file_chunks {
        for &hash in hashes {
            entries.push((lba, hash));
            lba += blocks_per_chunk;
        }
    }

    // volume_id = blake3 of all hashes in order (deterministic from image content)
    let mut hasher = blake3::Hasher::new();
    for &(_, hash) in &entries {
        hasher.update(hash.as_bytes());
    }
    let volume_id: [u8; 32] = *hasher.finalize().as_bytes();

    let parent_id = if let Some(p) = parent {
        let snap = load(p);
        *snap.snapshot_id.as_bytes()
    } else {
        [0u8; 32]
    };

    let buf = write_snapshot(&entries, volume_id, parent_id, chunk_size as u32);
    let snapshot_id = blake3::hash(&buf);

    std::fs::create_dir_all(out_dir).ok();
    let out_path = out_dir.join(format!("{}.snap", snapshot_id));
    let file = File::create(&out_path).expect("failed to create snapshot file");
    let mut writer = BufWriter::new(file);
    writer.write_all(&buf).expect("write failed");

    println!("Snapshot written: {}", out_path.display());
    println!("  snapshot_id: {}", snapshot_id);
    println!("  volume_id:   {}", blake3::Hash::from(volume_id));
    println!("  parent_id:   {}", if parent_id == [0u8; 32] {
        "none (root)".to_string()
    } else {
        blake3::Hash::from(parent_id).to_string()
    });
    println!("  chunk_size:  {} KB", chunk_size / 1024);
    println!("  entries:     {}", entries.len());
    println!("  file size:   {:.1} KB", buf.len() as f64 / 1024.0);

    Ok(())
}

pub fn info(path: &Path) {
    let snap = load(path);
    let unique: std::collections::HashSet<_> = snap.entries.iter().map(|(_, h)| h).collect();

    println!("=== Snapshot Info ===");
    println!("  file:        {}", path.display());
    println!("  snapshot_id: {}", snap.snapshot_id);
    println!("  volume_id:   {}", blake3::Hash::from(snap.volume_id));
    println!("  parent_id:   {}", if snap.is_root() {
        "none (root)".to_string()
    } else {
        blake3::Hash::from(snap.parent_id).to_string()
    });
    println!("  chunk_size:  {} KB", snap.chunk_size / 1024);
    println!("  timestamp:   {}", snap.timestamp);
    println!("  entries:     {}", snap.entries.len());
    println!("  unique hashes: {}", unique.len());
    if !snap.entries.is_empty() {
        let max_lba = snap.entries.last().map(|(l, _)| l).unwrap();
        let vol_size = (*max_lba + snap.chunk_size as u64 / 4096) * 4096;
        println!("  volume size: ~{:.1} MB (synthetic LBAs)", vol_size as f64 / (1024.0 * 1024.0));
    }
}

pub fn diff(snap1_path: &Path, snap2_path: &Path) {
    let s1 = load(snap1_path);
    let s2 = load(snap2_path);

    // Build lookup maps
    let map1: std::collections::HashMap<u64, blake3::Hash> = s1.entries.iter().copied().collect();
    let map2: std::collections::HashMap<u64, blake3::Hash> = s2.entries.iter().copied().collect();
    let hashes1 = s1.hash_set();
    let hashes2 = s2.hash_set();

    let mut unchanged = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    let mut added = 0usize;

    for (lba, h1) in &map1 {
        match map2.get(lba) {
            Some(h2) if h1 == h2 => unchanged += 1,
            Some(_) => modified += 1,
            None => deleted += 1,
        }
    }
    for lba in map2.keys() {
        if !map1.contains_key(lba) {
            added += 1;
        }
    }

    let content_new = hashes2.iter().filter(|h| !hashes1.contains(h)).count();
    let content_shared = hashes2.len().saturating_sub(content_new);
    let total1 = s1.entries.len();
    let total2 = s2.entries.len();

    let same_volume = s1.volume_id == s2.volume_id;

    println!("=== Snapshot Diff ===");
    println!("  snap1: {} ({} entries)", s1.snapshot_id, total1);
    println!("  snap2: {} ({} entries)", s2.snapshot_id, total2);
    println!("  volume: {}", if same_volume {
        format!("same ({})", blake3::Hash::from(s1.volume_id))
    } else {
        format!("different — LBA diff not meaningful")
    });

    if same_volume {
        println!("\n  LBA-based diff:");
        println!("  Unchanged: {:>7}  ({:.1}%)", unchanged, 100.0 * unchanged as f64 / total1.max(1) as f64);
        println!("  Modified:  {:>7}  ({:.1}%)", modified,  100.0 * modified  as f64 / total1.max(1) as f64);
        println!("  Deleted:   {:>7}  ({:.1}%)", deleted,   100.0 * deleted   as f64 / total1.max(1) as f64);
        println!("  Added:     {:>7}  ({:.1}%)", added,     100.0 * added     as f64 / total2.max(1) as f64);
    }

    println!("\n  Content-addressed marginal cost:");
    println!("  Shared hashes: {:>7}  ({:.1}% of snap2)", content_shared, 100.0 * content_shared as f64 / hashes2.len().max(1) as f64);
    println!("  New hashes:    {:>7}  ({:.1}% of snap2)", content_new,    100.0 * content_new    as f64 / hashes2.len().max(1) as f64);
    println!("  Marginal S3 fetch: {} chunks (~{:.1} MB)",
        content_new, content_new as f64 * s2.chunk_size as f64 / (1024.0 * 1024.0));
}
