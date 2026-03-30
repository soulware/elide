// Shared simulation helpers for proptest files.
//
// `drain_local` and `simulate_coord_gc_local` mirror the real coordinator's
// drain-pending and GC logic without requiring an object store.  Both proptest
// suites (volume_proptest and actor_proptest) use these to drive the same
// coordinator-side simulation.
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use elide_core::segment;
use ulid::Ulid;

/// Move all committed segments from pending/ to segments/.
/// Simulates `drain-pending` (upload + rename) without touching an object store.
pub fn drain_local(fork_dir: &Path) {
    let pending = fork_dir.join("pending");
    let segments = fork_dir.join("segments");
    if let Ok(entries) = fs::read_dir(&pending) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if !name_str.ends_with(".tmp") {
                let _ = fs::rename(entry.path(), segments.join(&*name_str));
            }
        }
    }
}

/// Simulate one coordinator GC pass on `segments/` without an object store.
///
/// Picks the two lowest-ULID segments as candidates, compacts their entries
/// (including REF entries so the oracle test can still resolve dedup hashes),
/// writes a new segment with ULID = `max(inputs).increment()`, and writes
/// `gc/<new_ulid>.pending` (the handoff file the coordinator produces).
///
/// The input segment files are **not** deleted inline.  The caller receives
/// the consumed paths and is responsible for deleting them — after calling
/// `vol.apply_gc_handoffs()` (or `handle.apply_gc_handoffs()`).  This models
/// the real coordinator's ordering constraint: local segment files must not
/// disappear until the volume has acknowledged the handoff by renaming
/// `.pending` → `.applied`.
///
/// Returns `Some((consumed_ulids, produced_ulid, paths_to_delete))` when
/// candidates were found, `None` when fewer than two segments exist.
pub fn simulate_coord_gc_local(fork_dir: &Path) -> Option<(Vec<Ulid>, Ulid, Vec<PathBuf>)> {
    let segments_dir = fork_dir.join("segments");

    let seg_files = segment::collect_segment_files(&segments_dir).ok()?;
    let mut candidates: Vec<(Ulid, PathBuf)> = seg_files
        .iter()
        .filter_map(|p| {
            let name = p.file_name()?.to_str()?;
            let ulid = Ulid::from_string(name).ok()?;
            Some((ulid, p.clone()))
        })
        .collect();
    if candidates.len() < 2 {
        return None;
    }
    candidates.sort_by_key(|(u, _)| *u);
    let candidates = candidates[..2].to_vec();

    let max_input = candidates.iter().map(|(u, _)| *u).max()?;
    let new_ulid = max_input
        .increment()
        .unwrap_or_else(|| Ulid::from_parts(max_input.timestamp_ms() + 1, 0));

    // Track per-entry source ULIDs separately since SegmentEntry doesn't
    // derive Clone.  source_ulids[i] is the segment ULID that entry i came
    // from — needed for the .pending file format.
    let mut all_entries: Vec<segment::SegmentEntry> = Vec::new();
    let mut source_ulids: Vec<Ulid> = Vec::new();
    for (ulid, path) in &candidates {
        let Ok((bss, mut entries)) = segment::read_segment_index(path) else {
            continue;
        };
        if segment::read_extent_bodies(path, bss, &mut entries).is_err() {
            continue;
        }
        for entry in entries.drain(..) {
            source_ulids.push(*ulid);
            all_entries.push(entry);
        }
    }

    if all_entries.is_empty() {
        let consumed = candidates.iter().map(|(u, _)| *u).collect();
        let to_delete = candidates.into_iter().map(|(_, p)| p).collect();
        return Some((consumed, new_ulid, to_delete));
    }

    let tmp_path = segments_dir.join(format!("{new_ulid}.tmp"));
    let final_path = segments_dir.join(new_ulid.to_string());
    let new_bss = match segment::write_segment(&tmp_path, &mut all_entries, None) {
        Ok(bss) => bss,
        Err(_) => return None,
    };
    fs::rename(&tmp_path, &final_path).ok()?;

    // Write the handoff file with per-entry source segment ULIDs, matching
    // the real coordinator's format.
    let gc_dir = fork_dir.join("gc");
    let _ = fs::create_dir_all(&gc_dir);
    let mut lines = String::new();
    for (e, src_ulid) in all_entries.iter().zip(source_ulids.iter()) {
        if !e.is_dedup_ref {
            let abs_offset = new_bss + e.stored_offset;
            lines.push_str(&format!(
                "{} {} {} {}\n",
                e.hash, src_ulid, new_ulid, abs_offset
            ));
        }
    }
    let _ = fs::write(gc_dir.join(format!("{new_ulid}.pending")), lines);

    let consumed = candidates.iter().map(|(u, _)| *u).collect();
    let to_delete = candidates.into_iter().map(|(_, p)| p).collect();
    Some((consumed, new_ulid, to_delete))
}
