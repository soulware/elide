// Extent index: maps blake3::Hash → segment location.
//
// The extent index completes the read path:
//   lba → hash      (LBA map, src/lbamap.rs)
//   hash → location (this module)
//
// A location names the segment that contains the payload and the byte range
// within it. The segment_id is the ULID shared by the WAL file and its
// promoted counterpart in pending/ or segments/. At read time the file is
// located by checking each directory in order (wal/ → pending/ → segments/),
// so no update is needed when a WAL is promoted.
//
// Rebuild on startup:
//   extentindex::rebuild(base_dir) scans pending/*.idx and segments/*.idx.
//   Volume::open() then inserts WAL Data records via recover_wal(), which
//   calls extent_index.insert() for each record.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

use crate::segment;

/// Physical location of an extent within a segment file.
#[derive(Clone)]
pub struct ExtentLocation {
    /// ULID of the segment (filename in wal/, pending/, or segments/).
    pub segment_id: String,
    /// Byte offset of the start of the payload within the segment body.
    pub body_offset: u64,
    /// Byte length of the payload.
    pub body_length: u32,
}

/// In-memory index mapping content hash to segment location.
pub struct ExtentIndex {
    inner: HashMap<blake3::Hash, ExtentLocation>,
}

impl ExtentIndex {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Insert or overwrite the location for `hash`.
    pub fn insert(&mut self, hash: blake3::Hash, location: ExtentLocation) {
        self.inner.insert(hash, location);
    }

    /// Look up the segment location for `hash`.
    pub fn lookup(&self, hash: &blake3::Hash) -> Option<&ExtentLocation> {
        self.inner.get(hash)
    }

    /// Number of entries in the index.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for ExtentIndex {
    fn default() -> Self {
        Self::new()
    }
}

// --- rebuild from disk ---

/// Rebuild the extent index from all committed segments.
///
/// Scans `<base>/pending/*.idx` and `<base>/segments/*.idx` in ULID order
/// (oldest first). The ULID is derived from each `.idx` filename and
/// validated via `ulid::Ulid::from_string`.
///
/// Inline entries (payload lives in the `.idx` rather than the segment body)
/// are skipped — inline reads are not yet implemented.
///
/// The caller (`Volume::open`) is responsible for inserting the in-progress
/// WAL entries on top via `recover_wal`.
pub fn rebuild(base_dir: &Path) -> io::Result<ExtentIndex> {
    let mut index = ExtentIndex::new();

    let mut idx_paths = collect_idx_files(&base_dir.join("pending"))?;
    idx_paths.extend(collect_idx_files(&base_dir.join("segments"))?);
    // Chronological order: newer entries overwrite older ones for the same hash.
    idx_paths.sort_unstable_by(|a, b| a.file_name().cmp(&b.file_name()));

    for path in &idx_paths {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("bad .idx filename"))?;
        let segment_id = ulid::Ulid::from_string(stem)
            .map_err(|e| io::Error::other(e.to_string()))?
            .to_string();

        for entry in segment::read_idx(path)? {
            if !entry.inline_data.is_empty() {
                // TODO: inline entries store their payload in the .idx itself
                // rather than the segment body, so they need a different read
                // path. INLINE_THRESHOLD is 0 today, so no inline entries are
                // generated yet.
                continue;
            }
            index.insert(
                entry.hash,
                ExtentLocation {
                    segment_id: segment_id.clone(),
                    body_offset: entry.body_offset,
                    body_length: entry.body_length,
                },
            );
        }
    }

    Ok(index)
}

fn collect_idx_files(dir: &Path) -> io::Result<Vec<std::path::PathBuf>> {
    match fs::read_dir(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(e) => Err(e),
        Ok(entries) => {
            let mut paths = Vec::new();
            for entry in entries {
                let path = entry?.path();
                if path.extension().is_some_and(|e| e == "idx") {
                    paths.push(path);
                }
            }
            Ok(paths)
        }
    }
}

// --- tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use crate::segment::{IdxEntry, write_idx};
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "palimpsest-extentindex-test-{}-{}",
            std::process::id(),
            n
        ));
        p
    }

    fn h(b: u8) -> blake3::Hash {
        blake3::hash(&[b; 32])
    }

    #[test]
    fn empty_lookup_returns_none() {
        let index = ExtentIndex::new();
        assert!(index.lookup(&h(1)).is_none());
    }

    #[test]
    fn insert_and_lookup() {
        let mut index = ExtentIndex::new();
        let hash = h(1);
        index.insert(
            hash,
            ExtentLocation {
                segment_id: "01JQEXAMPLEULID0000000000A".to_string(),
                body_offset: 1024,
                body_length: 4096,
            },
        );
        let loc = index.lookup(&hash).unwrap();
        assert_eq!(loc.segment_id, "01JQEXAMPLEULID0000000000A");
        assert_eq!(loc.body_offset, 1024);
        assert_eq!(loc.body_length, 4096);
    }

    #[test]
    fn rebuild_from_pending() {
        let base = temp_dir();
        let pending = base.join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        let data = vec![0xabu8; 4096];
        let hash = blake3::hash(&data);
        let entries = vec![IdxEntry::from_wal_data(hash, 0, 1, 0, 512, data)];
        write_idx(&pending.join("01AAAAAAAAAAAAAAAAAAAAAAAA.idx"), &entries).unwrap();

        let index = rebuild(&base).unwrap();
        assert_eq!(index.len(), 1);
        let loc = index.lookup(&hash).unwrap();
        assert_eq!(loc.body_offset, 512);
        assert_eq!(loc.body_length, 4096);

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn newer_segment_overwrites_older_for_same_hash() {
        let base = temp_dir();
        let pending = base.join("pending");
        std::fs::create_dir_all(&pending).unwrap();

        let data = vec![0u8; 4096];
        let hash = blake3::hash(&data);

        // Older segment: hash at body_offset 0.
        {
            let entries = vec![IdxEntry::from_wal_data(hash, 0, 1, 0, 0, data.clone())];
            write_idx(&pending.join("01AAAAAAAAAAAAAAAAAAAAAAAA.idx"), &entries).unwrap();
        }
        // Newer segment: same hash at body_offset 4096.
        {
            let entries = vec![IdxEntry::from_wal_data(hash, 0, 1, 0, 4096, data)];
            write_idx(&pending.join("01BBBBBBBBBBBBBBBBBBBBBBBB.idx"), &entries).unwrap();
        }

        let index = rebuild(&base).unwrap();
        assert_eq!(index.len(), 1);
        // Newer segment wins.
        assert_eq!(index.lookup(&hash).unwrap().body_offset, 4096);

        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rebuild_empty_dirs_returns_empty() {
        let base = temp_dir();
        std::fs::create_dir_all(&base).unwrap();
        let index = rebuild(&base).unwrap();
        assert!(index.is_empty());
        std::fs::remove_dir_all(base).unwrap();
    }
}
