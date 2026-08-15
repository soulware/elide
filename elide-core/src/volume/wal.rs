//! WAL lifecycle helpers used by the writable [`Volume`](super::Volume) open
//! and recovery paths: scan + replay an existing WAL, reopen it for continued
//! appending, or create a fresh one. Split out of `volume/mod.rs` for legibility
//! — no behaviour change.

use std::io;
use std::path::{Path, PathBuf};

use ulid::Ulid;

use crate::{
    extentindex::{self, BodySource},
    lbamap, segment, writelog,
};

use super::ZERO_HASH;

/// Output of [`replay_wal_records`]: the parsed records turned back into the
/// pending writes the next promote consumes, each carrying where its body
/// bytes sit in the WAL. The bytes themselves are read at promote time.
pub(super) struct WalReplay {
    pub ulid: Ulid,
    pub valid_size: u64,
    pub pending: Vec<super::PendingWrite>,
}

/// Scan a WAL file and replay its records into `lbamap` + `extent_index`,
/// returning the WAL ULID, the valid (non-partial) tail size, and the
/// reconstructed pending writes.
///
/// Shared between:
/// - [`recover_wal`], which also reopens the file for continued appending
///   (latest WAL case).
/// - `Volume::open_impl`'s recovery-time promote loop, which promotes
///   each non-latest WAL to a fresh segment and deletes the WAL file
///   rather than reopening it.
///
/// `writelog::scan` truncates any partial-tail record before returning.
pub(super) fn replay_wal_records(
    path: &Path,
    lbamap: &mut lbamap::LbaMap,
    extent_index: &mut extentindex::ExtentIndex,
    journal: &crate::journal::JournalRanges,
) -> io::Result<WalReplay> {
    let ulid_str = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| io::Error::other("bad WAL filename"))?;
    let ulid = Ulid::from_string(ulid_str).map_err(|e| io::Error::other(e.to_string()))?;

    let (records, valid_size) = writelog::scan(path)?;

    let mut pending: Vec<super::PendingWrite> = Vec::new();
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
                let body_length = data.len() as u32;
                let codec = segment::Codec::from_wal_flags(flags);
                lbamap.insert(start_lba, lba_length, hash, ulid);
                // Temporary WAL offset — updated to segment offset on
                // promotion. Mirrors `write_commit`: a journal-window record
                // goes to the disjoint journal tier keyed by `(ulid, hash)`,
                // never `inner`; a durable record uses `insert_if_absent`
                // (first owner wins, loser minted as a DedupRef at formation).
                let is_journal = journal.contains(start_lba);
                let location = extentindex::ExtentLocation {
                    segment_id: ulid,
                    body_offset,
                    body_length,
                    codec,
                    body_source: BodySource::Local,
                    body_section_start: 0,
                    inline_data: None,
                };
                if is_journal {
                    extent_index.insert_journal_if_absent(ulid, hash, location);
                } else {
                    extent_index.insert_if_absent(hash, location);
                }
                // Drop the body bytes here — they live in the WAL at
                // `body_offset` and the promote path reads them via that
                // sidecar offset rather than carrying them in memory.
                drop(data);
                let mut entry = segment::SegmentEntry::new_data_no_body(
                    hash,
                    start_lba,
                    lba_length,
                    codec,
                    body_length,
                );
                entry.journal = is_journal;
                pending.push(super::PendingWrite {
                    entry,
                    wal_body_offset: Some(body_offset),
                });
            }
            writelog::LogRecord::Ref {
                hash,
                start_lba,
                lba_length,
            } => {
                lbamap.insert(start_lba, lba_length, hash, ulid);
                // REF: no body bytes, no body reservation, no extent_index
                // update. The canonical entry is populated from whichever
                // segment holds the DATA for this hash.
                pending.push(super::PendingWrite {
                    entry: segment::SegmentEntry::new_dedup_ref(hash, start_lba, lba_length),
                    wal_body_offset: None,
                });
            }
            writelog::LogRecord::Zero {
                start_lba,
                lba_length,
            } => {
                lbamap.insert(start_lba, lba_length, ZERO_HASH, ulid);
                pending.push(super::PendingWrite {
                    entry: segment::SegmentEntry::new_zero(start_lba, lba_length),
                    wal_body_offset: None,
                });
            }
        }
    }

    Ok(WalReplay {
        ulid,
        valid_size,
        pending,
    })
}

/// Scan an existing WAL, replay its records into `lbamap`, rebuild the
/// pending writes, and reopen the WAL for continued appending.
///
/// This is the single WAL scan on startup — it both updates the LBA map
/// (WAL is more recent than any segment) and recovers the pending writes
/// needed for the next promotion.
pub(super) struct RecoveredWal {
    pub wal: writelog::WriteLog,
    pub ulid: Ulid,
    pub path: PathBuf,
    pub pending: Vec<super::PendingWrite>,
}

pub(super) fn recover_wal(
    path: PathBuf,
    lbamap: &mut lbamap::LbaMap,
    extent_index: &mut extentindex::ExtentIndex,
    journal: &crate::journal::JournalRanges,
) -> io::Result<RecoveredWal> {
    let replay = replay_wal_records(&path, lbamap, extent_index, journal)?;
    let wal = writelog::WriteLog::reopen(&path, replay.valid_size)?;
    Ok(RecoveredWal {
        wal,
        ulid: replay.ulid,
        path,
        pending: replay.pending,
    })
}

/// Create a new WAL file using the provided `ulid`.
///
/// The caller is responsible for generating a ULID that sorts after all
/// existing segments and WAL files (typically via `Volume::mint`).
pub(super) fn create_fresh_wal(
    wal_dir: &Path,
    ulid: Ulid,
) -> io::Result<(writelog::WriteLog, Ulid, PathBuf)> {
    let path = wal_dir.join(ulid.to_string());
    let wal = writelog::WriteLog::create(&path)?;
    // The directory entry must be as durable as the records: recovery
    // finds WALs by enumerating wal/, and a flush ack anchors on the
    // rotated file being found there.
    crate::segment::fsync_dir(wal_dir)?;
    log::info!("new WAL {ulid}");
    Ok((wal, ulid, path))
}
