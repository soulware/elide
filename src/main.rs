use std::path::Path;

use clap::{Parser, Subcommand};
use ext4_view::{Ext4, Ext4Error, PathBuf as Ext4PathBuf};

use elide_core::volume;

mod extents;
mod inspect;
mod ls;
mod nbd;

/// Analyse ext4 disk images for dedup and delta compression potential.
#[derive(Parser)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan an image for file extents and analyse dedup + delta compression potential
    Extents {
        image1: String,
        image2: Option<String>,
        #[arg(long, default_value_t = 3)]
        level: i32,
    },
    /// Serve a raw ext4 image over NBD, tracking which blocks are read
    Serve {
        image: String,
        #[arg(long, default_value_t = 10809)]
        port: u16,
        /// Write a boot trace file on disconnect (for use with cold-boot)
        #[arg(long)]
        save_trace: Option<String>,
    },
    /// Combine a boot trace with cross-image analysis to estimate cold-boot fetch cost (4 strategies: zstd-only, zstd+sparse, zstd+delta, zstd+delta+sparse)
    ColdBoot {
        image1: String,
        image2: String,
        #[arg(long)]
        trace: String,
        #[arg(long, default_value_t = 3)]
        level: i32,
    },
    /// Measure file renames between two images (exact renames and size-matched rename+modify candidates)
    RenameAnalysis { image1: String, image2: String },
    /// Measure sparse-strategy savings: within changed files, how many 4KB blocks actually differ?
    SparseAnalysis { image1: String, image2: String },
    /// Serve an elide fork directory over NBD
    ServeVolume {
        /// Path to the fork directory (e.g. volumes/myvm/default) or volume root (uses default fork)
        dir: String,
        /// Volume size (e.g. "4G", "512M", "1073741824"). Required on first use;
        /// ignored on subsequent opens (size is stored in <vol-dir>/size).
        #[arg(long)]
        size: Option<String>,
        /// Address to bind (use 0.0.0.0 to allow connections from VMs)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long, default_value_t = 10809)]
        port: u16,
        /// Serve as a read-only block device (required for readonly-base forks)
        #[arg(long)]
        readonly: bool,
    },
    /// Extract kernel and initrd from an ext4 image's /boot directory
    ExtractBoot {
        image: String,
        #[arg(long, default_value = ".")]
        out_dir: String,
    },
    /// Inspect an elide volume directory and print a human-readable summary
    InspectVolume {
        /// Path to the volume root directory, or a fork directory (resolves to its parent)
        dir: String,
    },
    /// List ext4 filesystem contents of a volume directory (read-only)
    LsVolume {
        /// Path to the fork directory (e.g. volumes/myvm/default) or volume root (uses default fork)
        dir: String,
        /// Path within the ext4 filesystem to list (default: /)
        #[arg(default_value = "/")]
        path: String,
    },
    /// Compact sparse segments in a volume, reclaiming space from overwritten extents
    CompactVolume {
        /// Path to the fork directory (e.g. volumes/myvm/default) or volume root (uses default fork)
        dir: String,
        /// Compact segments where fewer than this fraction of stored bytes are live (default: 0.7)
        #[arg(long, default_value_t = 0.7)]
        min_live_ratio: f64,
    },
    /// Checkpoint a fork by writing a snapshot marker; the fork stays live
    SnapshotVolume {
        /// Path to the fork directory (e.g. volumes/myvm/default) or volume root (uses default fork)
        dir: String,
    },
    /// Create a new named fork branched from the latest snapshot of the source fork
    ForkVolume {
        /// Path to the volume directory (contains the named forks)
        vol_dir: String,
        /// Name for the new fork
        fork_name: String,
        /// Source fork to branch from (default: "default")
        #[arg(long, default_value = "default")]
        from: String,
    },
    /// List all forks in a volume directory
    ListForks {
        /// Path to the volume directory
        vol_dir: String,
    },
    /// Import an ext4 disk image as a readonly base volume
    ImportVolume {
        /// Path to the ext4 disk image to import
        image: String,
        /// Path to the volume directory to create (e.g. volumes/ubuntu-22.04)
        vol_dir: String,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::Extents {
            image1,
            image2,
            level,
        } => {
            extents::run(Path::new(&image1), image2.as_deref().map(Path::new), level)
                .expect("extents failed");
        }

        Command::Serve {
            image,
            port,
            save_trace,
        } => {
            nbd::run(&image, port, save_trace.as_deref()).expect("NBD server error");
        }

        Command::ColdBoot {
            image1,
            image2,
            trace,
            level,
        } => {
            extents::run_cold_boot(
                Path::new(&image1),
                Path::new(&image2),
                Path::new(&trace),
                level,
            )
            .expect("cold-boot analysis failed");
        }

        Command::RenameAnalysis { image1, image2 } => {
            extents::run_rename_analysis(Path::new(&image1), Path::new(&image2))
                .expect("rename-analysis failed");
        }

        Command::SparseAnalysis { image1, image2 } => {
            extents::run_sparse_analysis(Path::new(&image1), Path::new(&image2))
                .expect("sparse-analysis failed");
        }

        Command::ServeVolume {
            dir,
            size,
            bind,
            port,
            readonly,
        } => {
            let fork_dir =
                resolve_fork_dir(Path::new(&dir)).expect("failed to resolve fork directory");
            // The size file lives at the volume root.
            let size_dir = resolve_vol_dir(&fork_dir).to_owned();
            let size_bytes = resolve_volume_size(&size_dir, size.as_deref())
                .expect("failed to determine volume size");
            if readonly {
                nbd::run_volume_readonly(&fork_dir, size_bytes, &bind, port)
                    .expect("readonly NBD server error");
            } else {
                nbd::run_volume(&fork_dir, size_bytes, &bind, port)
                    .expect("volume NBD server error");
            }
        }

        Command::ExtractBoot { image, out_dir } => {
            extract_boot(Path::new(&image), Path::new(&out_dir)).expect("extract-boot failed");
        }

        Command::InspectVolume { dir } => {
            inspect::run(resolve_vol_dir(Path::new(&dir))).expect("inspect-volume failed");
        }

        Command::LsVolume { dir, path } => {
            let fork_dir =
                resolve_fork_dir(Path::new(&dir)).expect("failed to resolve fork directory");
            ls::run(&fork_dir, &path).expect("ls-volume failed");
        }

        Command::CompactVolume {
            dir,
            min_live_ratio,
        } => {
            let fork_dir =
                resolve_fork_dir(Path::new(&dir)).expect("failed to resolve fork directory");
            let mut vol = volume::Volume::open(&fork_dir).expect("failed to open volume");
            let stats = vol.compact(min_live_ratio).expect("compaction failed");
            println!(
                "segments compacted: {}  bytes freed: {}  extents removed: {}",
                stats.segments_compacted, stats.bytes_freed, stats.extents_removed,
            );
        }

        Command::SnapshotVolume { dir } => {
            let fork_dir =
                resolve_fork_dir(Path::new(&dir)).expect("failed to resolve fork directory");
            let mut vol = volume::Volume::open(&fork_dir).expect("failed to open volume");
            let snap_ulid = vol.snapshot().expect("snapshot failed");
            println!("{snap_ulid}");
        }

        Command::ForkVolume {
            vol_dir,
            fork_name,
            from,
        } => {
            let fork_dir =
                volume::fork_volume(resolve_vol_dir(Path::new(&vol_dir)), &fork_name, &from)
                    .expect("fork-volume failed");
            println!("{}", fork_dir.display());
        }

        Command::ListForks { vol_dir } => {
            list_forks(resolve_vol_dir(Path::new(&vol_dir))).expect("list-forks failed");
        }

        Command::ImportVolume { image, vol_dir } => {
            let image_path = Path::new(&image);
            let vol_dir_path = Path::new(&vol_dir);
            let image_size = std::fs::metadata(image_path)
                .expect("cannot stat image")
                .len();
            let total_blocks = image_size / 4096;
            eprintln!(
                "Importing {} ({} MiB, {} blocks)...",
                image,
                image_size >> 20,
                total_blocks
            );
            let mut last_pct = u64::MAX;
            elide_core::import::import_image(image_path, vol_dir_path, |done, total| {
                let pct = done * 100 / total;
                if pct != last_pct {
                    last_pct = pct;
                    eprint!("\r  {pct}% ({done}/{total} blocks)");
                }
                if done == total {
                    eprintln!();
                }
            })
            .expect("import failed");
            eprintln!("Done. Volume ready at {vol_dir}");
        }
    }
}

/// Returns true if `path` looks like a fork directory (has `wal/` or `pending/`).
fn is_fork_dir(path: &Path) -> bool {
    path.join("wal").is_dir() || path.join("pending").is_dir()
}

/// Resolve a user-supplied path to a volume root.
///
/// Accepts a volume root, a fork path under `forks/`, or the frozen `default/`
/// base fork at the volume root. Returns the volume root in all cases.
fn resolve_vol_dir(path: &Path) -> &Path {
    if is_fork_dir(path) {
        let parent = path.parent().unwrap_or(path);
        // If parent is "forks/", the volume root is one level above that.
        if parent.file_name().and_then(|n| n.to_str()) == Some("forks") {
            parent.parent().unwrap_or(parent)
        } else {
            parent
        }
    } else {
        path
    }
}

/// Resolve a user-supplied path to a fork directory.
///
/// Accepts a fork path directly, or a volume root (resolves to `forks/default`).
fn resolve_fork_dir(path: &Path) -> std::io::Result<std::path::PathBuf> {
    if is_fork_dir(path) {
        return Ok(path.to_path_buf());
    }
    // Try vol_root/forks/default.
    let via_forks = path.join("forks").join("default");
    if via_forks.is_dir() && is_fork_dir(&via_forks) {
        return Ok(via_forks);
    }
    Err(std::io::Error::other(format!(
        "{}: not a fork directory and has no 'forks/default' fork; pass the fork path directly (e.g. {}/forks/my-fork)",
        path.display(),
        path.display()
    )))
}

fn list_forks(vol_dir: &Path) -> std::io::Result<()> {
    use std::fs;

    let is_readonly = vol_dir.join("readonly").exists();

    if is_readonly {
        println!("readonly volume (template)");
    }

    let forks_dir = vol_dir.join("forks");
    let mut forks: Vec<(String, bool)> = Vec::new(); // (name, is_live)
    match fs::read_dir(&forks_dir) {
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                let name = match path.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_owned(),
                    None => continue,
                };
                let is_live = path.join("wal").is_dir();
                forks.push((name, is_live));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    forks.sort_by(|a, b| a.0.cmp(&b.0));

    if forks.is_empty() {
        println!("  (no forks yet — use fork-volume to create one)");
    } else {
        for (name, is_live) in &forks {
            let state = if *is_live { "live" } else { "base" };
            let snap_count = count_snapshots(&forks_dir.join(name));
            println!("  {name}  [{state}]  {snap_count} snapshot(s)");
        }
    }
    Ok(())
}

fn count_snapshots(fork_dir: &Path) -> usize {
    let snapshots_dir = fork_dir.join("snapshots");
    std::fs::read_dir(&snapshots_dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name()
                        .to_str()
                        .and_then(|n| ulid::Ulid::from_string(n).ok())
                        .is_some()
                })
                .count()
        })
        .unwrap_or(0)
}

/// Parse a human-readable size string: plain bytes, or with suffix K/M/G/T (base-2).
fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (num, shift) = if let Some(rest) = s.strip_suffix('T').or_else(|| s.strip_suffix("TB")) {
        (rest, 40)
    } else if let Some(rest) = s.strip_suffix('G').or_else(|| s.strip_suffix("GB")) {
        (rest, 30)
    } else if let Some(rest) = s.strip_suffix('M').or_else(|| s.strip_suffix("MB")) {
        (rest, 20)
    } else if let Some(rest) = s.strip_suffix('K').or_else(|| s.strip_suffix("KB")) {
        (rest, 10)
    } else {
        (s, 0)
    };
    let n: u64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid size: {}", s))?;
    Ok(n << shift)
}

/// Read the volume size from `<dir>/size`, or create it from `--size` if not present.
fn resolve_volume_size(dir: &Path, size_arg: Option<&str>) -> std::io::Result<u64> {
    let size_file = dir.join("size");
    if size_file.exists() {
        let s = std::fs::read_to_string(&size_file)?;
        s.trim()
            .parse::<u64>()
            .map_err(|e| std::io::Error::other(format!("bad size file: {}", e)))
    } else {
        let s = size_arg.ok_or_else(|| {
            std::io::Error::other("volume size required on first use: pass --size (e.g. --size 4G)")
        })?;
        let bytes =
            parse_size(s).map_err(|e| std::io::Error::other(format!("bad --size: {}", e)))?;
        if bytes == 0 {
            return Err(std::io::Error::other("volume size must be non-zero"));
        }
        std::fs::create_dir_all(dir)?;
        std::fs::write(&size_file, bytes.to_string())?;
        Ok(bytes)
    }
}

fn extract_boot(image: &Path, out_dir: &Path) -> Result<(), Ext4Error> {
    let fs = Ext4::load_from_path(image)?;
    std::fs::create_dir_all(out_dir).ok();

    for name in &["vmlinuz", "initrd.img"] {
        let path_str = format!("/boot/{}", name);
        let src = Ext4PathBuf::new(&path_str);
        match fs.read(&src) {
            Ok(data) => {
                let dst = out_dir.join(name);
                std::fs::write(&dst, &data).expect("write failed");
                println!(
                    "Extracted /boot/{} → {} ({:.1} MB)",
                    name,
                    dst.display(),
                    data.len() as f64 / (1024.0 * 1024.0)
                );
            }
            Err(e) => eprintln!("Could not read /boot/{}: {}", name, e),
        }
    }

    Ok(())
}
