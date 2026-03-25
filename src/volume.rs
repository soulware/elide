// Volume: top-level I/O interface — owns the LBA map, WAL, and directory layout.
//
// Directory layout:
//   <base>/wal/       — active write-ahead log (at most one file at a time)
//   <base>/pending/   — promoted segments awaiting GC or upload
//   <base>/segments/  — GC'd or downloaded segments (S3-backed in future)
//
// Write path:
//   1. Volume::write(lba, data) — hashes data, appends to WAL, updates LBA map
//   2. When the WAL reaches FLUSH_THRESHOLD, it is promoted to pending/
//
// Read path:
//   Not yet implemented: returns zeros. The extent index (hash → segment body
//   location) must be built before reads can serve real data.
//
// Recovery:
//   Volume::open() calls lbamap::rebuild_segments() (segments only), then
//   scans the WAL once: that single pass truncates any partial-tail record,
//   replays entries into the LBA map, and rebuilds pending_entries.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use ulid::Ulid;

use crate::{lbamap, segment, writelog};

/// WAL size (bytes) at which the log is promoted to a pending segment.
const FLUSH_THRESHOLD: u64 = 32 * 1024 * 1024;

/// A writable block-device volume backed by a content-addressable store.
///
/// Owns the in-memory LBA map, the active WAL, and the directory layout.
pub struct Volume {
    base_dir: PathBuf,
    lbamap: lbamap::LbaMap,
    wal: writelog::WriteLog,
    wal_ulid: String,
    wal_path: PathBuf,
    /// DATA extents written since the last promotion; used to build the .idx
    /// on the next promote().
    pending_entries: Vec<segment::IdxEntry>,
}

impl Volume {
    /// Open (or create) a volume rooted at `base_dir`.
    ///
    /// Creates `wal/`, `pending/`, and `segments/` subdirectories if they do
    /// not exist. Rebuilds the LBA map from all committed segments and any
    /// in-progress WAL, then reopens or creates the WAL.
    pub fn open(base_dir: &Path) -> io::Result<Self> {
        let wal_dir = base_dir.join("wal");
        let pending_dir = base_dir.join("pending");
        let segments_dir = base_dir.join("segments");

        fs::create_dir_all(&wal_dir)?;
        fs::create_dir_all(&pending_dir)?;
        fs::create_dir_all(&segments_dir)?;

        // Rebuild the LBA map from all committed segments (pending/ + segments/).
        let mut lbamap = lbamap::rebuild_segments(base_dir)?;

        // Find the in-progress WAL file (there should be at most one).
        let mut wal_files: Vec<PathBuf> = Vec::new();
        for entry in fs::read_dir(&wal_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                wal_files.push(entry.path());
            }
        }
        wal_files.sort_unstable_by(|a, b| a.file_name().cmp(&b.file_name()));

        // recover_wal does the single WAL scan: truncates any partial tail,
        // replays records into the LBA map, and rebuilds pending_entries.
        let (wal, wal_ulid, wal_path, pending_entries) =
            if let Some(path) = wal_files.into_iter().last() {
                recover_wal(path, &mut lbamap)?
            } else {
                create_fresh_wal(&wal_dir)?
            };

        Ok(Self {
            base_dir: base_dir.to_owned(),
            lbamap,
            wal,
            wal_ulid,
            wal_path,
            pending_entries,
        })
    }

    /// Write `data` starting at logical block address `lba`.
    ///
    /// `data.len()` must be a non-zero multiple of 4096. The data is appended
    /// to the WAL and the LBA map is updated in memory. If the WAL reaches
    /// `FLUSH_THRESHOLD` after this write, it is automatically promoted to a
    /// pending segment.
    pub fn write(&mut self, lba: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() || !data.len().is_multiple_of(4096) {
            return Err(io::Error::other(
                "data length must be a non-zero multiple of 4096",
            ));
        }
        let lba_length = (data.len() / 4096) as u32;
        let hash = blake3::hash(data);

        let body_offset = self.wal.append_data(lba, lba_length, &hash, 0, data)?;
        self.lbamap.insert(lba, lba_length, hash);
        self.pending_entries.push(segment::IdxEntry {
            hash,
            start_lba: lba,
            lba_length,
            compressed: false,
            body_offset,
            body_length: data.len() as u32,
            inline_data: Vec::new(),
        });

        if self.wal.size() >= FLUSH_THRESHOLD {
            self.promote()?;
        }

        Ok(())
    }

    /// Read `lba_count` blocks (4096 bytes each) starting at `lba`.
    ///
    /// Not yet implemented: always returns zeros. The extent index
    /// (hash → segment body location) must be built before reads serve data.
    pub fn read(&self, lba: u64, lba_count: u32) -> io::Result<Vec<u8>> {
        let _ = lba;
        Ok(vec![0u8; lba_count as usize * 4096])
    }

    /// Flush buffered WAL writes and fsync to disk.
    pub fn fsync(&mut self) -> io::Result<()> {
        self.wal.fsync()
    }

    /// Promote the current WAL to a pending segment, then open a fresh WAL.
    fn promote(&mut self) -> io::Result<()> {
        self.wal.fsync()?;
        segment::promote(
            &self.wal_path,
            &self.wal_ulid,
            &self.base_dir.join("pending"),
            &self.pending_entries,
        )?;
        // Create the fresh WAL before clearing state. If this fails after the
        // rename above, the volume is unrecoverable until reopened; the segment
        // is safe in pending/ and will be found by the next lbamap rebuild.
        let (wal, wal_ulid, wal_path, _) = create_fresh_wal(&self.base_dir.join("wal"))?;
        self.wal = wal;
        self.wal_ulid = wal_ulid;
        self.wal_path = wal_path;
        self.pending_entries.clear();

        Ok(())
    }

    #[cfg(test)]
    pub fn lbamap_len(&self) -> usize {
        self.lbamap.len()
    }
}

// --- WAL helpers ---

/// Scan an existing WAL, replay its records into `lbamap`, rebuild
/// `pending_entries`, and reopen the WAL for continued appending.
///
/// This is the single WAL scan on startup — it both updates the LBA map
/// (WAL is more recent than any segment) and recovers the pending_entries
/// list needed for the next promotion.
///
/// `writelog::scan` truncates any partial-tail record before returning.
fn recover_wal(
    path: PathBuf,
    lbamap: &mut lbamap::LbaMap,
) -> io::Result<(writelog::WriteLog, String, PathBuf, Vec<segment::IdxEntry>)> {
    let ulid_str = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::other("bad WAL filename"))?;
    let ulid = Ulid::from_string(ulid_str)
        .map_err(|e| io::Error::other(e.to_string()))?
        .to_string();

    let (records, valid_size) = writelog::scan(&path)?;

    let mut pending_entries = Vec::new();
    for record in records {
        match record {
            writelog::LogRecord::Data {
                hash,
                start_lba,
                lba_length,
                flags,
                body_offset,
                data,
            } => {
                lbamap.insert(start_lba, lba_length, hash);
                pending_entries.push(segment::IdxEntry {
                    hash,
                    start_lba,
                    lba_length,
                    compressed: flags & writelog::FLAG_COMPRESSED != 0,
                    body_offset,
                    body_length: data.len() as u32,
                    inline_data: Vec::new(),
                });
            }
            writelog::LogRecord::Ref {
                hash,
                start_lba,
                lba_length,
            } => {
                lbamap.insert(start_lba, lba_length, hash);
                // TODO: dedup — Ref records will need an .idx entry type
                // before Volume::write can generate them.
            }
        }
    }

    let wal = writelog::WriteLog::reopen(&path, valid_size)?;
    Ok((wal, ulid, path, pending_entries))
}

/// Create a new WAL file with a fresh ULID.
fn create_fresh_wal(
    wal_dir: &Path,
) -> io::Result<(writelog::WriteLog, String, PathBuf, Vec<segment::IdxEntry>)> {
    let ulid = Ulid::new().to_string();
    let path = wal_dir.join(&ulid);
    let wal = writelog::WriteLog::create(&path)?;
    Ok((wal, ulid, path, Vec::new()))
}

// --- tests ---

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let mut p = std::env::temp_dir();
        p.push(format!(
            "palimpsest-volume-test-{}-{}",
            std::process::id(),
            n
        ));
        p
    }

    #[test]
    fn open_creates_directories() {
        let base = temp_dir();
        let _ = Volume::open(&base).unwrap();
        assert!(base.join("wal").is_dir());
        assert!(base.join("pending").is_dir());
        assert!(base.join("segments").is_dir());
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn open_is_idempotent() {
        let base = temp_dir();
        let _ = Volume::open(&base).unwrap();
        // Second open on the same dir should succeed (dirs already exist).
        let _ = Volume::open(&base).unwrap();
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn write_single_block() {
        let base = temp_dir();
        let mut vol = Volume::open(&base).unwrap();
        vol.write(0, &vec![0x42u8; 4096]).unwrap();
        vol.fsync().unwrap();
        assert_eq!(vol.lbamap_len(), 1);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn write_multi_block_extent() {
        let base = temp_dir();
        let mut vol = Volume::open(&base).unwrap();
        // Write 8 LBAs (32 KiB) as a single call.
        vol.write(10, &vec![0xabu8; 8 * 4096]).unwrap();
        assert_eq!(vol.lbamap_len(), 1);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn write_rejects_empty() {
        let base = temp_dir();
        let mut vol = Volume::open(&base).unwrap();
        let err = vol.write(0, &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn write_rejects_misaligned() {
        let base = temp_dir();
        let mut vol = Volume::open(&base).unwrap();
        let err = vol.write(0, &[0u8; 1000]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn write_promotes_on_flush() {
        let base = temp_dir();
        let mut vol = Volume::open(&base).unwrap();

        // Write 33 × 1 MiB to exceed FLUSH_THRESHOLD (32 MiB).
        let block = vec![0u8; 1024 * 1024];
        for i in 0u64..33 {
            vol.write(i * 256, &block).unwrap();
        }

        // At least one segment should have been promoted to pending/.
        let has_pending = fs::read_dir(base.join("pending"))
            .unwrap()
            .any(|e| e.is_ok());
        assert!(
            has_pending,
            "expected at least one promoted segment in pending/"
        );

        // A fresh WAL should have been created.
        let wal_count = fs::read_dir(base.join("wal"))
            .unwrap()
            .filter(|e| e.is_ok())
            .count();
        assert_eq!(
            wal_count, 1,
            "expected exactly one WAL file after promotion"
        );

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn recovery_rebuilds_lbamap() {
        let base = temp_dir();

        // Write two blocks, fsync, then drop (simulates clean shutdown before promotion).
        {
            let mut vol = Volume::open(&base).unwrap();
            vol.write(0, &vec![1u8; 4096]).unwrap();
            vol.write(1, &vec![2u8; 4096]).unwrap();
            vol.fsync().unwrap();
        }

        // Reopen — lbamap should contain both blocks.
        let vol = Volume::open(&base).unwrap();
        assert_eq!(vol.lbamap_len(), 2);

        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn read_returns_zeros() {
        let base = temp_dir();
        let vol = Volume::open(&base).unwrap();
        let data = vol.read(0, 4).unwrap();
        assert_eq!(data.len(), 4 * 4096);
        assert!(data.iter().all(|&b| b == 0));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn ulid_is_unique_and_sortable() {
        let u1 = Ulid::new().to_string();
        let u2 = Ulid::new().to_string();
        assert_eq!(u1.len(), 26);
        assert_ne!(u1, u2);
        // ULIDs generated in sequence should sort correctly (same millisecond
        // is not guaranteed, but two different values prove uniqueness).
    }
}
