//! The open generation's reap: unlink pending segments nothing references.
//!
//! The tick asks the volume to remove `pending/open/` segments that are
//! unreachable — no LBA-map claim names them and no extent-index location
//! at them holds a live hash. Whole-death is what a seconds-old window
//! produces (a jbd2 ring rewrite, a hot page overwritten twice), and the
//! reap takes exactly that: an index-region parse of the segments it
//! removes, a set of index removals, a publish, a batch of unlinks. The
//! close pass is the only pass that materialises bytes
//! (`docs/design/open-generation-reap.md`).
//!
//! Selection is a sweep over the published snapshot's maps and runs off
//! the volume mutex; the apply is the authority, revalidating every data
//! segment through the maintained-count liveness probes under the mutex,
//! so a selection staled by a concurrent claim refuses rather than
//! removes.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ulid::Ulid;

use super::Volume;
use crate::extentindex::ExtentIndex;
use crate::lbamap::LbaMap;
use crate::segment::{self, EntryKind};

/// Entries one pass may remove under the volume mutex — four
/// `FLUSH_ENTRY_THRESHOLD` flush segments' worth, so a backlog clears in
/// a few passes while each pass's apply stays bounded. The parse phase
/// stops taking data segments once the accumulated count reaches it.
/// Journal segments are exempt: each costs one outer removal, so pricing
/// them against the cap would throttle the tier that dies fastest.
pub const REAP_ENTRY_CAP: usize = 32_768;

/// What one reap pass did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReapStats {
    pub segments_reaped: u64,
    pub entries_removed: u64,
    pub bytes_reclaimed: u64,
    /// Segments the apply's revalidation kept because a hash became
    /// referenced after the sweep.
    pub segments_refused: u64,
}

/// One segment the sweep found unreachable.
#[derive(Debug, Clone)]
pub struct ReapCandidate {
    pub ulid: Ulid,
    pub path: PathBuf,
    /// File size, which is what the pass reports reclaimed.
    pub bytes: u64,
    /// Journal-tier segment: reaped whole via the segment-outer maps,
    /// with neither a parse nor a per-hash revalidation — its claims
    /// are keyed by its own ULID and can only decrease once it is
    /// sealed, so the sweep's zero is stable.
    pub journal: bool,
}

/// Stored body bytes a segment holds in the durable tier, split by
/// whether the hash owning each location is still live.
///
/// Both figures read the same locations, so their ratio prices one
/// population.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BodyBytes {
    pub live: u64,
    pub stored: u64,
}

/// What one sweep found.
#[derive(Debug, Default)]
pub struct Sweep {
    /// Segments nothing references, ready for the parse phase.
    pub candidates: Vec<ReapCandidate>,
    /// Per eligible segment, the body bytes its durable-tier locations
    /// account for (`docs/design/open-generation-reap.md`).
    pub body_bytes: HashMap<Ulid, BodyBytes>,
}

impl Sweep {
    /// Sum across every segment the sweep priced.
    pub fn totals(&self) -> BodyBytes {
        self.body_bytes
            .values()
            .fold(BodyBytes::default(), |mut acc, b| {
                acc.live += b.live;
                acc.stored += b.stored;
                acc
            })
    }
}

/// A candidate with its owned hashes parsed, ready for the apply.
#[derive(Debug)]
pub struct ReapSegment {
    pub ulid: Ulid,
    pub path: PathBuf,
    pub bytes: u64,
    pub journal: bool,
    /// Every non-DedupRef entry hash — the hashes whose location the
    /// segment may own. Empty for a journal segment.
    pub owned_hashes: Vec<blake3::Hash>,
}

/// List `pending/open/` as `(ulid, path, size)` triples, the sweep's
/// input.
pub fn list_open_segments(base_dir: &Path) -> io::Result<Vec<(Ulid, PathBuf, u64)>> {
    let dir = segment::pending_open_dir(base_dir);
    let mut out = Vec::new();
    for path in segment::collect_segment_files(&dir)? {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| io::Error::other("bad segment filename"))?;
        let ulid = Ulid::from_string(name)
            .map_err(|e| io::Error::other(format!("bad segment filename {name}: {e}")))?;
        let bytes = std::fs::metadata(&path)?.len();
        out.push((ulid, path, bytes));
    }
    out.sort_by_key(|(u, _, _)| *u);
    Ok(out)
}

/// Sweep the maps for open segments nothing references.
///
/// A segment is referenced while any LBA-map entry names it as claimant,
/// or any extent-index location at it holds a live hash — claimed, or
/// named as a delta source. Segments at or below the snapshot floor are
/// pinned whatever the maps say, exactly as they are for GC.
///
/// Runs against snapshot maps and takes no lock; the caller revalidates
/// at apply time, which is what makes a stale answer safe.
///
/// The same walk accumulates each eligible segment's live and stored
/// body bytes, which costs one liveness probe per durable-tier location
/// at an eligible segment.
pub fn sweep_unreachable(
    lbamap: &LbaMap,
    index: &ExtentIndex,
    open: &[(Ulid, PathBuf, u64)],
    floor: Option<Ulid>,
) -> Sweep {
    let eligible: HashSet<Ulid> = open
        .iter()
        .map(|(u, _, _)| *u)
        .filter(|u| floor.is_none_or(|f| *u > f))
        .collect();
    if eligible.is_empty() {
        return Sweep::default();
    }

    let mut referenced: HashSet<Ulid> = HashSet::new();
    for (_lba, _len, _hash, _off, claimant) in lbamap.iter_entries_with_claimant() {
        if eligible.contains(&claimant) {
            referenced.insert(claimant);
        }
    }
    // Segments holding any durable-tier location, live or dead. A dead
    // one still has to leave the index when its file goes — a stale
    // `inner` entry at an unlinked file is a body a later write dedups
    // against and cannot read — so holding one routes the segment
    // through the parsed path whatever its journal membership says.
    let mut durable: HashSet<Ulid> = HashSet::new();
    let mut body_bytes: HashMap<Ulid, BodyBytes> = HashMap::new();
    let live =
        |hash: &blake3::Hash| lbamap.is_referenced(hash) || index.is_named_delta_source(hash);
    for (hash, loc) in index.iter() {
        if eligible.contains(&loc.segment_id) {
            durable.insert(loc.segment_id);
            let live_hash = live(hash);
            let acc = body_bytes.entry(loc.segment_id).or_default();
            acc.stored += u64::from(loc.body_length);
            if live_hash {
                acc.live += u64::from(loc.body_length);
                referenced.insert(loc.segment_id);
            }
        }
    }
    for (hash, loc) in index.deltas_iter() {
        if eligible.contains(&loc.segment_id) {
            durable.insert(loc.segment_id);
            if !referenced.contains(&loc.segment_id) && live(hash) {
                referenced.insert(loc.segment_id);
            }
        }
    }

    let candidates = open
        .iter()
        .filter(|(u, _, _)| eligible.contains(u) && !referenced.contains(u))
        .map(|(u, p, b)| ReapCandidate {
            ulid: *u,
            path: p.clone(),
            bytes: *b,
            journal: index.is_journal_segment(*u) && !durable.contains(u),
        })
        .collect();

    Sweep {
        candidates,
        body_bytes,
    }
}

/// Parse each data candidate's index region for its owned hashes,
/// stopping once the accumulated count reaches [`REAP_ENTRY_CAP`];
/// what remains is next pass's work. Journal candidates pass through
/// parse-free.
///
/// The parse skips signature verification: `remove_owner_at` removes a
/// hash only where the current owner is the segment being reaped, so a
/// hash a bad parse invents either does not exist or is owned elsewhere,
/// and either way removes nothing. A segment that fails to parse is left
/// in place for the close pass, whose verifying read is where corruption
/// surfaces.
pub fn parse_reap_candidates(candidates: Vec<ReapCandidate>) -> Vec<ReapSegment> {
    parse_with_cap(candidates, REAP_ENTRY_CAP)
}

fn parse_with_cap(candidates: Vec<ReapCandidate>, cap: usize) -> Vec<ReapSegment> {
    let mut out = Vec::with_capacity(candidates.len());
    let mut entries = 0usize;
    for c in candidates {
        if c.journal {
            out.push(ReapSegment {
                ulid: c.ulid,
                path: c.path,
                bytes: c.bytes,
                journal: true,
                owned_hashes: Vec::new(),
            });
            continue;
        }
        if entries >= cap {
            continue;
        }
        match segment::read_segment_index(&c.path) {
            Ok((_bss, seg_entries, _inputs)) => {
                let owned_hashes: Vec<blake3::Hash> = seg_entries
                    .iter()
                    .filter(|e| e.kind != EntryKind::DedupRef)
                    .map(|e| e.hash)
                    .collect();
                entries += owned_hashes.len();
                out.push(ReapSegment {
                    ulid: c.ulid,
                    path: c.path,
                    bytes: c.bytes,
                    journal: false,
                    owned_hashes,
                });
            }
            Err(e) => {
                log::warn!(
                    "reap open [{}]: index parse failed, leaving for the close pass: {e}",
                    c.ulid
                );
            }
        }
    }
    out
}

impl Volume {
    /// Apply phase of the reap — runs under the volume mutex.
    ///
    /// Each data segment revalidates through the maintained-count
    /// probes: a hash the segment still owns that is claimed or named
    /// as a delta source refuses the segment whole, which is what
    /// absorbs a dedup claim minted between the sweep and this apply.
    /// A journal segment is taken on the sweep's word — its claims are
    /// keyed by its own ULID and only decrease once it is sealed — and
    /// costs two outer removals.
    ///
    /// Returns the files to unlink. The caller publishes its read
    /// snapshot first and then passes them to
    /// [`Self::remove_consumed_inputs`], the publish-before-unlink
    /// discipline every rewrite apply carries.
    pub fn apply_reap(&mut self, segments: Vec<ReapSegment>) -> (ReapStats, Vec<PathBuf>) {
        let mut stats = ReapStats::default();
        let mut unlink = Vec::new();
        let mut reaped_fmt: Vec<String> = Vec::new();
        let no_carried = crate::blake3_id_hasher::Blake3HashSet::default();
        for seg in segments {
            if !seg.journal {
                let fresh = seg.owned_hashes.iter().find(|hash| {
                    let owner_here = self
                        .extent_index
                        .lookup(hash)
                        .is_some_and(|loc| loc.segment_id == seg.ulid)
                        || self
                            .extent_index
                            .lookup_delta(hash)
                            .is_some_and(|loc| loc.segment_id == seg.ulid);
                    owner_here
                        && (self.lbamap.is_referenced(hash)
                            || self.extent_index.is_named_delta_source(hash))
                });
                if let Some(hash) = fresh {
                    log::info!(
                        "reap open [{}]: refused — hash {} became referenced after the sweep",
                        seg.ulid,
                        hash.to_hex(),
                    );
                    stats.segments_refused += 1;
                    continue;
                }
            }
            let index = Arc::make_mut(&mut self.extent_index);
            stats.entries_removed +=
                index.remove_input_owned(seg.ulid, &seg.owned_hashes, &no_carried) as u64;
            index.purge_journal_segment(seg.ulid);
            index.purge_segment_delta_sources(seg.ulid);
            self.pending_journal.remove(&seg.ulid);
            self.evict_cached_segment(seg.ulid);
            stats.segments_reaped += 1;
            stats.bytes_reclaimed += seg.bytes;
            reaped_fmt.push(seg.ulid.to_string());
            unlink.push(seg.path);
        }
        if stats.segments_reaped > 0 {
            log::info!(
                "reap open: [{}] {} entries removed, {} bytes reclaimed",
                reaped_fmt.join(","),
                stats.entries_removed,
                stats.bytes_reclaimed,
            );
        }
        (stats, unlink)
    }

    /// One whole reap pass, inline on the current thread: sweep the live
    /// maps, parse, apply, unlink. For callers without an actor — tests
    /// and the offline CLI. The actor's handler runs the same phases
    /// with the sweep and parse off the mutex.
    pub fn reap_open_generation(&mut self) -> io::Result<ReapStats> {
        let open = list_open_segments(&self.base_dir)?;
        if open.is_empty() {
            return Ok(ReapStats::default());
        }
        let floor = super::latest_snapshot(&self.base_dir)?;
        let candidates =
            sweep_unreachable(&self.lbamap, &self.extent_index, &open, floor).candidates;
        if candidates.is_empty() {
            return Ok(ReapStats::default());
        }
        let parsed = parse_reap_candidates(candidates);
        let (stats, unlink) = self.apply_reap(parsed);
        self.remove_consumed_inputs(&unlink)?;
        Ok(stats)
    }

    /// Simulate a crash inside the reap pipeline, for proptests.
    ///
    /// Applies the pass, then unlinks only the first `unlink` reaped
    /// files — a crash partway through [`Self::remove_consumed_inputs`].
    /// The caller must crash (drop and reopen) immediately after: the
    /// in-memory maps have dropped entries whose segment files are
    /// still on disk, and only a crash reaches that state in
    /// production, where apply and removal are atomic with respect to
    /// other ops on the actor. The rebuild restores the entries the
    /// apply dropped, so the reaped bytes come back until a later pass
    /// removes them.
    ///
    /// The sweep and parse phases mutate nothing, so a crash before
    /// the apply leaves a state no different from a pass that never
    /// ran, and takes no shape of its own here.
    ///
    /// Returns `false` when the sweep found nothing to reap.
    pub fn reap_crash_for_test(&mut self, unlink: usize) -> io::Result<bool> {
        let open = list_open_segments(&self.base_dir)?;
        if open.is_empty() {
            return Ok(false);
        }
        let floor = super::latest_snapshot(&self.base_dir)?;
        let candidates =
            sweep_unreachable(&self.lbamap, &self.extent_index, &open, floor).candidates;
        if candidates.is_empty() {
            return Ok(false);
        }
        let parsed = parse_reap_candidates(candidates);
        let (_stats, paths) = self.apply_reap(parsed);
        for path in paths.iter().take(unlink) {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::*;
    use super::*;
    use crate::segment::{Codec, SegmentEntry};
    use crate::ulid_mint::UlidMint;
    use std::fs;

    fn block(fill: u8) -> Vec<u8> {
        let mut buf = vec![0u8; 4096];
        let mut xof = blake3::Hasher::new_keyed(&[fill; 32]).finalize_xof();
        xof.fill(&mut buf);
        buf
    }

    fn open_files(base: &std::path::Path) -> Vec<PathBuf> {
        segment::collect_segment_files(&segment::pending_open_dir(base)).unwrap()
    }

    /// A segment whose only extent was overwritten reaps whole: the file
    /// goes, the index forgets it, and both the live volume and a fresh
    /// open read the surviving bytes.
    #[test]
    fn reap_takes_a_whole_dead_data_segment() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let a = block(1);
        let b = block(2);
        vol.write(0, &a).unwrap();
        vol.flush_wal().unwrap();
        assert_eq!(open_files(&base).len(), 1);
        vol.write(0, &b).unwrap();

        let stats = vol.reap_open_generation().unwrap();
        assert_eq!(stats.segments_reaped, 1);
        assert_eq!(stats.entries_removed, 1);
        assert!(stats.bytes_reclaimed > 0);
        assert!(open_files(&base).is_empty());
        assert!(
            vol.extent_index.lookup(&blake3::hash(&a)).is_none(),
            "the reaped body's location left the index"
        );
        assert_eq!(vol.read(0, 1).unwrap(), b);

        drop(vol);
        let vol = Volume::open(&base, &base).unwrap();
        assert_eq!(vol.read(0, 1).unwrap(), b);

        fs::remove_dir_all(base).unwrap();
    }

    /// A claimed segment is untouchable, and a pass over only-live
    /// segments reports nothing.
    #[test]
    fn reap_spares_a_live_segment() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &block(1)).unwrap();
        vol.flush_wal().unwrap();

        let stats = vol.reap_open_generation().unwrap();
        assert_eq!(stats, ReapStats::default());
        assert_eq!(open_files(&base).len(), 1);

        fs::remove_dir_all(base).unwrap();
    }

    /// The sweep prices every eligible segment: `stored` covers each
    /// durable-tier location at it, `live` the subset whose hash is
    /// still claimed. A segment holding one overwritten and one live
    /// 4 KiB extent reports half of itself dead, and stays off the
    /// candidate list while the live one holds it.
    #[test]
    fn the_sweep_prices_a_partly_dead_segment() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        vol.write(0, &block(1)).unwrap();
        vol.write(1, &block(2)).unwrap();
        vol.flush_wal().unwrap();

        // Kills block(1)'s hash. LBA 1 keeps block(2) claimed.
        vol.write(0, &block(3)).unwrap();

        let open = list_open_segments(&base).unwrap();
        let sweep = sweep_unreachable(&vol.lbamap, &vol.extent_index, &open, None);

        // XOF-filled blocks never shrink, so each rides its 4096 bytes raw.
        assert_eq!(
            sweep.totals(),
            BodyBytes {
                live: 4096,
                stored: 8192
            }
        );
        assert_eq!(sweep.body_bytes.len(), 1);
        assert!(
            sweep.candidates.is_empty(),
            "a segment holding a live hash is no candidate"
        );

        fs::remove_dir_all(base).unwrap();
    }

    /// A dedup claim minted between the sweep and the apply revives a
    /// hash the sweep classified dead. The apply's revalidation refuses
    /// the segment, and the revived claim reads through the kept body.
    #[test]
    fn reap_refuses_a_segment_whose_hash_revived_between_phases() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let a = block(1);
        vol.write(0, &a).unwrap();
        vol.flush_wal().unwrap();
        vol.write(0, &block(2)).unwrap();

        let open = list_open_segments(&base).unwrap();
        let candidates = sweep_unreachable(&vol.lbamap, &vol.extent_index, &open, None).candidates;
        assert_eq!(candidates.len(), 1);
        let parsed = parse_reap_candidates(candidates);

        // The worker-window race: the same content returns as a DedupRef
        // against the reap candidate's body.
        vol.write(5, &a).unwrap();

        let (stats, unlink) = vol.apply_reap(parsed);
        assert_eq!(stats.segments_refused, 1);
        assert_eq!(stats.segments_reaped, 0);
        assert!(unlink.is_empty());
        assert_eq!(open_files(&base).len(), 1);
        assert_eq!(vol.read(5, 1).unwrap(), a);

        fs::remove_dir_all(base).unwrap();
    }

    /// Journal segments whose ring was rewritten reap on the sweep's
    /// word: no parse, the journal tier purged whole, the live ring
    /// kept.
    #[test]
    fn dead_journal_segment_reaps_without_parse() {
        let base = keyed_temp_dir();
        let vol = Volume::open(&base, &base).unwrap();
        drop(vol);
        let signer = crate::signing::load_signer(&base, crate::signing::VOLUME_KEY_FILE).unwrap();

        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let old_ring = mint.next();
        let new_ring = mint.next();
        for (seg, fill) in [(old_ring, 3u8), (new_ring, 4u8)] {
            let body = block(fill);
            let mut e = SegmentEntry::new_data(blake3::hash(&body), 9, 1, Codec::None, body);
            e.entry.journal = true;
            segment::write_segment(
                &segment::pending_open_dir(&base).join(seg.to_string()),
                vec![e],
                signer.as_ref(),
            )
            .unwrap();
        }

        let mut vol = Volume::open(&base, &base).unwrap();
        assert!(vol.extent_index.is_journal_segment(old_ring));

        let open = list_open_segments(&base).unwrap();
        let candidates = sweep_unreachable(&vol.lbamap, &vol.extent_index, &open, None).candidates;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ulid, old_ring);
        assert!(
            candidates[0].journal,
            "a pure journal segment skips the parse"
        );

        let stats = vol.reap_open_generation().unwrap();
        assert_eq!(stats.segments_reaped, 1);
        assert_eq!(
            stats.entries_removed, 0,
            "journal purge is an outer removal"
        );
        assert!(!vol.extent_index.is_journal_segment(old_ring));
        assert!(vol.extent_index.is_journal_segment(new_ring));
        assert_eq!(vol.read(9, 1).unwrap(), block(4));

        drop(vol);
        let vol = Volume::open(&base, &base).unwrap();
        assert_eq!(vol.read(9, 1).unwrap(), block(4));

        fs::remove_dir_all(base).unwrap();
    }

    /// A segment holding journal and durable entries routes through the
    /// parsed path, so its durable locations leave the index with the
    /// file — a stale `inner` entry at an unlinked file would be a body
    /// a later write dedups against and cannot read.
    #[test]
    fn mixed_journal_and_data_segment_takes_the_parsed_path() {
        let base = keyed_temp_dir();
        let vol = Volume::open(&base, &base).unwrap();
        drop(vol);
        let signer = crate::signing::load_signer(&base, crate::signing::VOLUME_KEY_FILE).unwrap();

        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let mixed = mint.next();
        let ring_body = block(5);
        let data_body = block(6);
        let data_hash = blake3::hash(&data_body);
        let mut ring =
            SegmentEntry::new_data(blake3::hash(&ring_body), 9, 1, Codec::None, ring_body);
        ring.entry.journal = true;
        let data = SegmentEntry::new_data(data_hash, 20, 1, Codec::None, data_body);
        segment::write_segment(
            &segment::pending_open_dir(&base).join(mixed.to_string()),
            vec![ring, data],
            signer.as_ref(),
        )
        .unwrap();

        let mut vol = Volume::open(&base, &base).unwrap();
        // Both claims move on: the ring rewrites, the data LBA overwrites.
        vol.write(9, &block(7)).unwrap();
        vol.write(20, &block(8)).unwrap();

        let open = list_open_segments(&base).unwrap();
        let candidates = sweep_unreachable(&vol.lbamap, &vol.extent_index, &open, None).candidates;
        let cand = candidates
            .iter()
            .find(|c| c.ulid == mixed)
            .expect("the mixed segment is unreachable");
        assert!(
            !cand.journal,
            "a durable location routes the segment through the parse"
        );

        let stats = vol.reap_open_generation().unwrap();
        assert_eq!(stats.segments_reaped, 1);
        assert!(stats.entries_removed >= 1);
        assert!(
            vol.extent_index.lookup(&data_hash).is_none(),
            "the durable location left the index with the file"
        );
        assert!(!vol.extent_index.is_journal_segment(mixed));

        fs::remove_dir_all(base).unwrap();
    }

    /// The snapshot floor pins whatever sits at or below it, dead or
    /// not.
    #[test]
    fn the_snapshot_floor_pins_at_or_below() {
        let mut mint = UlidMint::new(ulid::Ulid::nil());
        let pinned = mint.next();
        let above = mint.next();
        let map = crate::lbamap::LbaMap::new();
        let index = ExtentIndex::new();
        let open = vec![
            (pinned, PathBuf::from("pinned"), 10),
            (above, PathBuf::from("above"), 10),
        ];

        let candidates = sweep_unreachable(&map, &index, &open, Some(pinned)).candidates;
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].ulid, above);

        let candidates = sweep_unreachable(&map, &index, &open, None).candidates;
        assert_eq!(candidates.len(), 2, "with no floor both are unreachable");
    }

    /// The cap bounds one pass's parse, and what it defers clears on the
    /// next pass.
    #[test]
    fn the_cap_defers_the_remainder_to_the_next_pass() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        for lba in 0..3u64 {
            vol.write(lba, &block(10 + lba as u8)).unwrap();
            vol.flush_wal().unwrap();
        }
        for lba in 0..3u64 {
            vol.write(lba, &block(20 + lba as u8)).unwrap();
        }

        let open = list_open_segments(&base).unwrap();
        let candidates = sweep_unreachable(&vol.lbamap, &vol.extent_index, &open, None).candidates;
        assert_eq!(candidates.len(), 3);

        // Cap of two entries: the first two single-entry segments parse,
        // the third defers.
        let parsed = super::parse_with_cap(candidates, 2);
        assert_eq!(parsed.len(), 2);
        let (stats, unlink) = vol.apply_reap(parsed);
        vol.remove_consumed_inputs(&unlink).unwrap();
        assert_eq!(stats.segments_reaped, 2);
        assert_eq!(open_files(&base).len(), 1);

        let stats = vol.reap_open_generation().unwrap();
        assert_eq!(stats.segments_reaped, 1);
        assert!(open_files(&base).is_empty());

        fs::remove_dir_all(base).unwrap();
    }

    /// Crash between the apply and the unlink: the reaped file survives
    /// on disk, a fresh open rebuilds it back in, and the next pass
    /// takes it again. Rebuild is the invariant; the reap only ever
    /// removes what a rebuild without the file reproduces.
    #[test]
    fn a_crash_before_the_unlink_loses_nothing() {
        let base = keyed_temp_dir();
        let mut vol = Volume::open(&base, &base).unwrap();

        let b = block(2);
        vol.write(0, &block(1)).unwrap();
        vol.flush_wal().unwrap();
        vol.write(0, &b).unwrap();
        vol.flush_wal().unwrap();

        let open = list_open_segments(&base).unwrap();
        let candidates = sweep_unreachable(&vol.lbamap, &vol.extent_index, &open, None).candidates;
        assert_eq!(candidates.len(), 1);
        let parsed = parse_reap_candidates(candidates);
        let (stats, unlink) = vol.apply_reap(parsed);
        assert_eq!(stats.segments_reaped, 1);
        assert!(!unlink.is_empty());
        // Crash here: the files were never unlinked.
        drop(vol);

        let mut vol = Volume::open(&base, &base).unwrap();
        assert_eq!(vol.read(0, 1).unwrap(), b);
        let stats = vol.reap_open_generation().unwrap();
        assert_eq!(stats.segments_reaped, 1);
        assert_eq!(vol.read(0, 1).unwrap(), b);

        fs::remove_dir_all(base).unwrap();
    }
}
