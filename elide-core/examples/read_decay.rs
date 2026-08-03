//! Measure how random-read throughput on a volume responds to churn.
//!
//! Builds a volume, ages it with rounds of random 8 KiB overwrites, and after
//! each round times random 8 KiB reads while reporting the descriptor-cache
//! counters that explain the timing. `fd miss rate` is a counter rather than a
//! timing, so it stays readable on a noisy machine where the throughput column
//! does not.
//!
//! What each knob isolates:
//!
//! * `WRITE_DURING=1` runs a writer thread throughout each measurement, which
//!   is what a read-write guest looks like. Reads and writes otherwise take
//!   turns, and a cache invalidated per write only shows up when they overlap.
//! * `PROMOTE_EVERY` sets how many rounds share a segment, so the same churn
//!   can be spread across many segments or few. Segment count and
//!   fragmentation move independently, which is what separates a cache sized
//!   against segment count from a lbamap split into more extents.
//! * `FD_CAPACITY` sizes the descriptor cache against that segment count.
//! * `DRAIN=0` leaves bodies in `pending/` instead of promoting them to
//!   `cache/<id>.body`, which is the difference between a body the extent
//!   index calls `Local` and one it calls `Cached`.
//!
//! Absolute throughput depends on local disk and on what else the machine is
//! doing; the counters and the shape across rounds are the portable part.
//!
//! Run with:
//!   cargo run --release -p elide-core --example read_decay
//!
//! Env knobs: BLOCKS ROUNDS OVERWRITES READS PROMOTE_EVERY WRITE_DURING
//!            DRAIN FD_CAPACITY SEED

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use elide_core::actor::{VolumeClient, VolumeReader, spawn};
use elide_core::volume::{FILE_CACHE_CAPACITY, ReadStatsSnapshot, Volume};
use ulid::Ulid;

const BLOCK: usize = 4096;
/// Guest page size: postgres reads and writes 8 KiB pages.
const PAGE_BLOCKS: u64 = 2;

fn env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 17
    }
}

/// Distinct incompressible content per seed, so every write lands as a new
/// hash — no dedup REF, no no-op skip, and no inline extent that would never
/// touch a segment file.
fn block(seed: u64) -> [u8; BLOCK] {
    let mut buf = [0u8; BLOCK];
    let mut lcg = Lcg(0xdeadbeef_cafebabe_u64.wrapping_mul(seed.wrapping_add(1)));
    for chunk in buf.chunks_mut(8) {
        chunk.copy_from_slice(&lcg.next().to_le_bytes()[..chunk.len()]);
    }
    buf
}

fn keypair(dir: &Path) -> io::Result<()> {
    let key = elide_core::signing::generate_keypair(
        dir,
        elide_core::signing::VOLUME_KEY_FILE,
        elide_core::signing::VOLUME_PUB_FILE,
    )?;
    elide_core::signing::write_provenance(
        dir,
        &key,
        elide_core::signing::VOLUME_PROVENANCE_FILE,
        &elide_core::signing::ProvenanceLineage::default(),
    )?;
    Ok(())
}

/// Promote every `pending/<id>` to `cache/<id>.body`, the shape a volume has
/// once the coordinator has drained it. Bodies then resolve through
/// `BodySource::Cached`.
fn drain(handle: &VolumeClient, dir: &Path) -> io::Result<()> {
    let pending = match std::fs::read_dir(dir.join("pending")) {
        Ok(rd) => rd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let ulids: Vec<Ulid> = pending
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|s| Ulid::from_string(s).ok())
        })
        .collect();
    for u in ulids {
        handle.promote_segment(u)?;
    }
    Ok(())
}

/// Segment bodies on disk, by the directory holding them.
fn segments(dir: &Path) -> (usize, usize, usize) {
    let count = |sub: &str, ext: Option<&str>| {
        std::fs::read_dir(dir.join(sub))
            .map(|rd| {
                rd.flatten()
                    .filter(|e| match ext {
                        Some(want) => e.path().extension().is_some_and(|x| x == want),
                        None => e.path().is_file(),
                    })
                    .count()
            })
            .unwrap_or(0)
    };
    (
        count("cache", Some("body")),
        count("pending", None),
        count("wal", None),
    )
}

struct Measurement {
    reads_per_sec: f64,
    stats: ReadStatsSnapshot,
    writes: u64,
}

impl Measurement {
    fn extents_per_read(&self, reads: u64) -> f64 {
        self.stats.extents_total as f64 / reads as f64
    }
}

/// Time `reads` random 8 KiB reads spread uniformly over the volume.
fn measure(
    reader: &VolumeReader,
    handle: &VolumeClient,
    blocks: u64,
    reads: u64,
    seed: u64,
    writer: bool,
) -> Measurement {
    let pages = blocks / PAGE_BLOCKS;
    let before = reader.read_stats();
    let stop = AtomicBool::new(false);
    let writes = Arc::new(AtomicU64::new(0));

    let elapsed = std::thread::scope(|s| {
        if writer {
            let writes = Arc::clone(&writes);
            let stop = &stop;
            s.spawn(move || {
                let mut lcg = Lcg(seed ^ 0xfeed);
                // Start the content stream far from the main loop's so a
                // writer never re-mints a block the reader's LBA already
                // holds, which would land as a no-op skip.
                let mut content = u64::MAX / 2;
                while !stop.load(Ordering::Relaxed) {
                    let lba = (lcg.next() % pages) * PAGE_BLOCKS;
                    content += 1;
                    if handle.write(lba, &block(content), false).is_ok() {
                        writes.fetch_add(1, Ordering::Relaxed);
                    }
                }
            });
        }

        let mut buf = vec![0u8; BLOCK * PAGE_BLOCKS as usize];
        let mut lcg = Lcg(seed);
        let start = Instant::now();
        for _ in 0..reads {
            let lba = (lcg.next() % pages) * PAGE_BLOCKS;
            reader.read_into(lba, &mut buf).expect("read");
        }
        let elapsed = start.elapsed().as_secs_f64();
        stop.store(true, Ordering::Relaxed);
        elapsed
    });

    Measurement {
        reads_per_sec: reads as f64 / elapsed,
        stats: reader.read_stats().since(&before),
        writes: writes.load(Ordering::Relaxed),
    }
}

fn main() -> io::Result<()> {
    let blocks: u64 = env("BLOCKS", 32_768);
    let rounds: u64 = env("ROUNDS", 24);
    let overwrites: u64 = env("OVERWRITES", 2_048);
    let reads: u64 = env("READS", 20_000);
    let promote_every: u64 = env("PROMOTE_EVERY", 1);
    let capacity: usize = env("FD_CAPACITY", FILE_CACHE_CAPACITY);
    let seed: u64 = env("SEED", 0x5eed);
    let writing: bool = env::<u64>("WRITE_DURING", 0) != 0;
    let draining: bool = env::<u64>("DRAIN", 1) != 0;

    println!(
        "blocks={blocks} ({} MiB)  rounds={rounds}  overwrites/round={overwrites} pages  \
         reads/measure={reads}\npromote_every={promote_every}  fd_capacity={capacity}  \
         write_during={writing}  drain={draining}  seed={seed:#x}",
        blocks * BLOCK as u64 / (1024 * 1024)
    );

    let dir = tempfile::TempDir::new()?;
    keypair(dir.path())?;
    let vol = Volume::open(dir.path(), dir.path())?;
    let (actor, handle) = spawn(vol);
    std::thread::Builder::new()
        .name("read-decay-actor".into())
        .spawn(move || actor.run())?;

    print!("bulk loading {blocks} blocks... ");
    let start = Instant::now();
    for lba in 0..blocks {
        handle.write(lba, &block(lba), false)?;
    }
    handle.promote_wal()?;
    if draining {
        drain(&handle, dir.path())?;
    }
    println!("{:.1}s", start.elapsed().as_secs_f64());

    let reader = handle.reader_with_cache_capacity(capacity);
    println!("\n round  cache/pend/wal    reads/s  vs fresh  extents/read  fd miss  writes");

    let report = |round: &str, m: &Measurement, fresh: Option<f64>, dir: &Path| {
        let (c, p, w) = segments(dir);
        let rel = match fresh {
            Some(f) => format!("{:+.0}%", (m.reads_per_sec / f - 1.0) * 100.0),
            None => "—".into(),
        };
        println!(
            "{round:>6}  {c:>5}/{p:<4}/{w:<3} {:>9.0}  {rel:>8}  {:>12.2}  {:>6.1}%  {:>6}",
            m.reads_per_sec,
            m.extents_per_read(reads),
            m.stats.fd_miss_rate() * 100.0,
            m.writes
        );
    };

    let fresh = measure(&reader, &handle, blocks, reads, seed, writing);
    report("fresh", &fresh, None, dir.path());
    let fresh_tps = fresh.reads_per_sec;

    let mut rng = Lcg(seed ^ 0xabcd);
    let mut content = blocks;
    let pages = blocks / PAGE_BLOCKS;
    for round in 1..=rounds {
        for _ in 0..overwrites {
            let lba = (rng.next() % pages) * PAGE_BLOCKS;
            for b in 0..PAGE_BLOCKS {
                handle.write(lba + b, &block(content), false)?;
                content += 1;
            }
        }
        if round.is_multiple_of(promote_every) {
            handle.promote_wal()?;
            if draining {
                drain(&handle, dir.path())?;
            }
        }
        let m = measure(
            &reader,
            &handle,
            blocks,
            reads,
            seed.wrapping_add(round),
            writing,
        );
        report(&format!("{round}"), &m, Some(fresh_tps), dir.path());
    }

    Ok(())
}
