//! Time guest-sized random reads against chunked extents.
//!
//! Writes extents over `chunk_tree::CHUNK_BYTES` so every read lands in a
//! chunked body, then reads 8 KiB at uniformly random offsets — the shape that
//! makes a read decode a whole chunk, and the shape a cold guest page cache
//! produces. Random offsets over a large address space mean a decoded-chunk
//! cache would almost never hit, so what this isolates is the per-read table
//! read and root reconstruction rather than the decode.
//!
//! Tables are proved once in a warm-up pass, so the timed loop measures the
//! steady state a long-running volume server is in.
//!
//! Run with:
//!   cargo run --release -p elide-core --example chunk_read
//!
//! Env knobs: EXTENTS EXTENT_KIB READS SEED

use std::io;
use std::path::Path;
use std::time::Instant;

use elide_core::actor::spawn;
use elide_core::volume::Volume;

const BLOCK: usize = 4096;
/// Guest page size: postgres reads and writes 8 KiB pages.
const PAGE: usize = 8192;

fn env<T: std::str::FromStr>(key: &str, default: T) -> T {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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

fn main() -> io::Result<()> {
    let extents: u64 = env("EXTENTS", 192);
    let extent_kib: u64 = env("EXTENT_KIB", 1024);
    let reads: u64 = env("READS", 200_000);
    let mut seed: u64 = env("SEED", 0x5EED_1234_ABCD_0001);

    let extent_bytes = extent_kib as usize * 1024;
    assert!(
        extent_bytes > elide_core::chunk_tree::WRITE_CHUNK_SIZE.bytes(),
        "extent must exceed CHUNK_BYTES ({}) to be chunked",
        elide_core::chunk_tree::WRITE_CHUNK_SIZE.bytes()
    );
    let blocks_per_extent = (extent_bytes / BLOCK) as u64;
    println!(
        "extents={extents} x {extent_kib} KiB ({} MiB)  chunk={} KiB  reads={reads}",
        extents * extent_kib / 1024,
        elide_core::chunk_tree::WRITE_CHUNK_SIZE.bytes() / 1024,
    );

    let dir = tempfile::TempDir::new()?;
    keypair(dir.path())?;
    let vol = Volume::open(dir.path(), dir.path())?;
    let (actor, handle) = spawn(vol);
    std::thread::Builder::new()
        .name("chunk-read-actor".into())
        .spawn(move || actor.run())?;

    // Compressible enough to produce real zstd frames, distinguishable enough
    // that a mis-sliced read would not pass unnoticed.
    let mut payload = vec![0u8; extent_bytes];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i / 61 % 251) as u8;
    }

    let start = Instant::now();
    for e in 0..extents {
        payload[..8].copy_from_slice(&e.to_le_bytes());
        handle.write(e * blocks_per_extent, &payload, false)?;
    }
    handle.promote_wal()?;
    println!("wrote in {:.1}s", start.elapsed().as_secs_f64());

    let reader = handle.reader();
    let total_blocks = extents * blocks_per_extent;
    let mut buf = vec![0u8; PAGE];
    for e in 0..extents {
        reader.read_into(e * blocks_per_extent, &mut buf)?;
    }

    let start = Instant::now();
    for _ in 0..reads {
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let lba = ((seed >> 16) % (total_blocks - 2)) & !1;
        reader.read_into(lba, &mut buf)?;
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "{:.0} reads/s   {:.2} us/read",
        reads as f64 / elapsed,
        elapsed * 1e6 / reads as f64,
    );
    Ok(())
}
