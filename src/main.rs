use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use ext4_view::{Ext4, Ext4Error, PathBuf as Ext4PathBuf};

use elide_core::signing::{VOLUME_KEY_FILE, VOLUME_PROVENANCE_FILE, VOLUME_PUB_FILE};
use elide_core::volume;

use elide::{
    VolumeFetchInputs, coordinator_client, extents, inspect, inspect_files, parse_size,
    resolve_volume_dir, resolve_volume_size, serve, ublk, validate_volume_name, verify,
};

/// Elide volume management and analysis tools.
#[derive(Parser)]
#[command(version = elide_core::VERSION)]
struct Args {
    /// Data directory (default: elide_data)
    #[arg(long, env = "ELIDE_DATA_DIR", global = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Manage volumes
    Volume {
        #[command(subcommand)]
        command: VolumeCommand,
    },

    /// Serve an elide volume over ublk (spawned by coordinator; not for direct use)
    #[command(hide = true)]
    ServeVolume {
        /// Path to the volume directory (by_id/<ulid>/)
        fork_dir: PathBuf,
        /// Volume size (e.g. "4G", "512M"); required on first use only
        #[arg(long)]
        size: Option<String>,
        /// Serve as a read-only block device
        #[arg(long)]
        readonly: bool,
        /// Serve over ublk (default is coordinator IPC only, no block device)
        #[arg(long)]
        ublk: bool,
    },

    /// Scan an image for file extents and analyse dedup + delta compression potential
    #[command(hide = true)]
    Extents {
        image1: String,
        image2: Option<String>,
        #[arg(long, default_value_t = 3)]
        level: i32,
    },

    /// Combine a boot trace with cross-image analysis to estimate cold-boot fetch cost
    #[command(hide = true)]
    ColdBoot {
        image1: String,
        image2: String,
        #[arg(long)]
        trace: String,
        #[arg(long, default_value_t = 3)]
        level: i32,
    },

    /// Measure file renames between two images
    #[command(hide = true)]
    RenameAnalysis { image1: String, image2: String },

    /// Measure sparse-strategy savings within changed files
    #[command(hide = true)]
    SparseAnalysis { image1: String, image2: String },

    /// Extract kernel and initrd from an ext4 image's /boot directory
    #[command(hide = true)]
    ExtractBoot {
        image: String,
        #[arg(long, default_value = ".")]
        out_dir: String,
    },

    /// Rewrite pending segments that have any hash-dead body bytes (diagnostic)
    #[command(hide = true)]
    Repack { fork_dir: PathBuf },

    /// Print header and index entries of a segment or .idx file (diagnostic)
    #[command(hide = true)]
    InspectSegment { path: PathBuf },

    /// Print all records in a WAL file (diagnostic)
    #[command(hide = true)]
    InspectWal { path: PathBuf },

    /// Print all materialised records in a `.dmat` cache file (diagnostic)
    #[command(hide = true)]
    InspectDmat { path: PathBuf },

    /// Manage ublk devices (diagnostic, Linux-only)
    #[command(hide = true)]
    Ublk {
        #[command(subcommand)]
        command: UblkCommand,
    },

    /// Manage the coordinator daemon (start, stop, run, enroll)
    Coord {
        #[command(subcommand)]
        command: CoordCommand,
    },

    /// Log in as an operator (records the subject for `coord enroll`)
    Login {
        /// The operator subject to record
        #[arg(long)]
        subject: String,
    },

    /// Clear the stored operator login (`~/.config/elide`)
    Logout,
}

#[derive(Subcommand)]
enum CoordCommand {
    /// Start the coordinator as a detached background process
    Start {
        /// Coordinator config file (default: coordinator.toml)
        #[arg(long, env = "ELIDE_COORD_CONFIG")]
        config: Option<PathBuf>,
    },

    /// Stop the coordinator; volumes keep running unless --stop-volumes
    Stop {
        /// Also terminate managed volume processes
        #[arg(long)]
        stop_volumes: bool,
        /// Coordinator config file (default: coordinator.toml)
        #[arg(long, env = "ELIDE_COORD_CONFIG")]
        config: Option<PathBuf>,
    },

    /// Run the coordinator in the foreground
    Run {
        /// Coordinator config file (default: coordinator.toml)
        #[arg(long, env = "ELIDE_COORD_CONFIG")]
        config: Option<PathBuf>,
    },

    /// Enrol with the configured mint and provision per-role credentials
    Enroll {
        /// Coordinator config file (default: coordinator.toml)
        #[arg(long, env = "ELIDE_COORD_CONFIG")]
        config: Option<PathBuf>,
        /// Invite macaroon: inline text, a file path, or `-` for stdin
        invite: String,
        /// Bound on waiting for operator approval (humantime, e.g. "30m")
        #[arg(long)]
        timeout: Option<String>,
        /// Re-exchange and overwrite every role credential, not just missing ones
        #[arg(long)]
        force: bool,
        /// Enrol as a read-only attestation authority (attest-ro role only)
        #[arg(long)]
        attestation: bool,
    },
}

#[derive(Subcommand)]
enum UblkCommand {
    /// List ublk devices currently known to the kernel
    List,
    /// Delete a ublk device by id, or all devices with --all
    Delete {
        /// Specific device id (maps to /dev/ublkb<id>)
        id: Option<i32>,
        /// Delete every device found in /sys/class/ublk-char
        #[arg(long, conflicts_with = "id")]
        all: bool,
    },
}

#[derive(Subcommand)]
enum VolumeCommand {
    /// List volumes in the data directory (all by default)
    List {
        /// List only readonly volumes (imported bases)
        #[arg(long, conflicts_with = "rw")]
        ro: bool,
        /// List only writable volumes
        #[arg(long)]
        rw: bool,
        /// Also include pulled ancestors (no name, no by_name/ symlink)
        #[arg(long)]
        all: bool,
    },

    /// Show local volume lineage as a tree: anchors, ancestor skeletons,
    /// snapshot-pinned fork edges, missing ancestors
    Tree,

    /// Deep on-disk inspection: WAL, pending and cached segments, ancestry
    Inspect {
        /// Volume name
        name: String,
    },

    /// Verify extent bodies against their declared hashes; exit 1 on mismatch
    #[command(hide = true)]
    Verify {
        /// Volume name
        name: String,
    },

    /// Write a snapshot marker; the volume stays live
    Snapshot {
        /// Volume name
        name: String,
    },

    /// Generate a snapshot's filemap (consumed by `volume import --extents-from`)
    GenerateFilemap {
        /// Volume name
        name: String,
        /// Specific snapshot ULID (defaults to the latest local snapshot)
        #[arg(long, value_name = "ULID")]
        snapshot: Option<String>,
    },

    /// Create a new volume, fresh or forked from an existing one
    Create {
        /// Volume name
        name: String,
        /// Volume size (e.g. "4G", "512M"); required without --from
        #[arg(long, conflicts_with = "from")]
        size: Option<String>,
        /// Fork source: <name>, <name>/<snap_ulid>, or <vol_ulid>/<snap_ulid>
        #[arg(long)]
        from: Option<String>,
        /// Serve over ublk even if this host can't right now
        /// (default: ublk when the coordinator is root with ublk_drv loaded)
        #[arg(long, conflicts_with = "no_ublk")]
        ublk: bool,
        /// Never serve this volume over ublk (IPC only)
        #[arg(long)]
        no_ublk: bool,
    },

    /// Update configuration for a running volume
    Update {
        /// Volume name
        name: String,
        /// Switch this volume to ublk transport (restarts the volume process)
        #[arg(long, conflicts_with_all = ["no_ublk"])]
        ublk: bool,
        /// Disable ublk serving (restarts the volume process)
        #[arg(long, conflicts_with_all = ["ublk"])]
        no_ublk: bool,
    },

    /// Show the running status of a volume
    Status {
        /// Volume name
        name: String,
        /// Fetch the authoritative names/<name> record from the bucket
        #[arg(long)]
        remote: bool,
    },

    /// Show the per-name event log for a volume, oldest first
    Events {
        /// Volume name
        name: String,
        /// Number of recent events to show (default: coordinator HEAD window)
        #[arg(long)]
        num: Option<usize>,
        /// Emit one JSON object per event
        #[arg(long)]
        json: bool,
    },

    /// Import an OCI image into a new readonly volume (sync by default)
    Import(ImportArgs),

    /// Evict cached segment bodies; they are demand-fetched from S3 on next read
    #[command(hide = true)]
    Evict {
        /// Evict a single segment body by ULID
        #[arg(long, value_name = "ULID")]
        segment: Option<String>,

        /// Volume name
        name: String,
    },

    /// Remove the local instance of a volume (bucket-side state is kept)
    Remove {
        /// Volume name
        name: String,
        /// Discard local state not yet flushed and uploaded to S3
        #[arg(long)]
        force: bool,
    },

    /// Stop a running volume, draining and publishing a stop-snapshot
    Stop {
        /// Volume name
        name: String,
        /// Also release the name so any coordinator can claim it
        #[arg(long)]
        release: bool,
        /// Halt without draining; may leave pending/ and wal/ dirty
        #[arg(long)]
        force: bool,
    },

    /// Start a previously stopped volume
    Start {
        /// Volume name
        name: String,
        /// Claim a released name first, then start
        #[arg(long)]
        claim: bool,
        /// Disable ublk before starting (persists, like `update --no-ublk`;
        /// revert with `update --ublk`)
        #[arg(long)]
        no_ublk: bool,
    },

    /// Claim a released volume name into local ownership without starting it
    Claim {
        /// Volume name
        name: String,
        /// Force-claim from an unreachable owner; its undrained writes are lost
        #[arg(long)]
        force: bool,
    },

    /// Stop a volume and release its name so any coordinator may claim it
    Release {
        /// Volume name
        name: String,
    },
}

#[derive(clap::Args)]
#[command(args_conflicts_with_subcommands = true)]
struct ImportArgs {
    #[command(subcommand)]
    command: Option<ImportSubcommand>,

    /// Volume name to create
    name: Option<String>,

    /// OCI image reference (e.g. ubuntu:22.04, ghcr.io/org/image:tag)
    oci_ref: Option<String>,

    /// Create a fork with this name after the import completes
    #[arg(long, conflicts_with = "detach", value_name = "NAME")]
    fork: Option<String>,

    /// Dedup against this local volume's extent index (repeatable)
    #[arg(long = "extents-from", value_name = "NAME")]
    extents_from: Vec<String>,

    /// Start the import in the background and return immediately
    #[arg(long)]
    detach: bool,
}

#[derive(Subcommand)]
enum ImportSubcommand {
    /// Show the state of a running or completed import
    Status {
        /// Volume name
        name: String,
    },
    /// Stream output from a running import
    Attach {
        /// Volume name
        name: String,
    },
}

fn main() {
    // rustls 0.23 requires a process-level default `CryptoProvider` to be
    // installed before any TLS connection is made. Feature-flag auto-detect
    // fails in our dependency graph (rustls pulled in transitively, not as
    // a direct dep of any crate that enables the `aws_lc_rs` feature on it),
    // so install it explicitly. `install_default` returns `Err` if another
    // provider was already installed — ignore that, it's fine.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let args = Args::parse();

    // Concrete data_dir for non-coord commands: CLI flag (or env) wins,
    // otherwise fall back to `elide_data`. The coord subcommands use
    // their own resolution that also considers `--config`.
    let cli_data_dir = args.data_dir.clone();
    let data_dir = cli_data_dir
        .clone()
        .unwrap_or_else(|| PathBuf::from("elide_data"));
    let coord = coordinator_client::Client::new(data_dir.join("control.sock"));
    let by_id_dir = data_dir.join("by_id");

    // Initialise tracing. `serve-volume` is a long-lived host process
    // that shares the unified `<data_dir>/elide.log` with the
    // coordinator (each writer opens its own fd; concurrent appends
    // compose). It also tees through the coord-side log relay socket
    // so live output reaches whichever coord is currently attached
    // to the operator's terminal. Every other subcommand is
    // short-lived CLI work and logs to stderr only.
    match &args.command {
        Command::ServeVolume { fork_dir, .. } => {
            // fork_dir is `<data_dir>/by_id/<ulid>/`, so data_dir is two
            // levels up. Fall back to `data_dir` from the CLI flag if the
            // path shape is unexpected — init failure should not stop the
            // volume coming up.
            let inferred = fork_dir
                .parent()
                .and_then(|p| p.parent())
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| data_dir.clone());
            if elide_coordinator::log_init::init_for_volume(&inferred).is_err() {
                elide_coordinator::log_init::init_stderr();
            }
        }
        _ => elide_coordinator::log_init::init_stderr(),
    }

    match args.command {
        Command::Login { subject } => {
            if let Err(e) = elide_core::operator_session::save_subject(&subject) {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
            println!("logged in as {}", subject.trim());
        }
        Command::Logout => match elide_core::operator_session::clear() {
            Ok(true) => println!("logged out"),
            Ok(false) => println!("not logged in"),
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
        Command::Volume { command } => match command {
            VolumeCommand::List { ro, rw, all } => {
                let filter = if ro {
                    ListFilter::Readonly
                } else if rw {
                    ListFilter::Writable
                } else {
                    ListFilter::All
                };
                if let Err(e) = list_volumes(&data_dir, &coord, filter, all) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            VolumeCommand::Tree => {
                if let Err(e) = tree_volumes(&data_dir) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }

            VolumeCommand::Inspect { name } => {
                let vol_dir = resolve_volume_dir(&data_dir, &name);
                if let Err(e) = inspect::run(&vol_dir, &by_id_dir) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }

            VolumeCommand::Verify { name } => {
                let vol_dir = resolve_volume_dir(&data_dir, &name);
                match verify::run(&vol_dir) {
                    Ok(counts) if counts.mismatches == 0 && counts.scan_errors == 0 => {}
                    Ok(counts) if counts.mismatches > 0 => std::process::exit(1),
                    Ok(_) => std::process::exit(2),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(2);
                    }
                }
            }

            VolumeCommand::Snapshot { name } => match coord.snapshot_volume(&name) {
                Ok(ulid) => println!("{ulid}"),
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            },

            VolumeCommand::GenerateFilemap { name, snapshot } => {
                match coord.generate_filemap(&name, snapshot.as_deref()) {
                    Ok(ulid) => println!("{name}: filemap written for snapshot {ulid}"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            VolumeCommand::Create {
                name,
                size,
                from,
                ublk,
                no_ublk,
            } => {
                if let Some(from) = &from {
                    if let Err(e) = validate_volume_name(&name) {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                    let flags = encode_transport_flags(ublk, no_ublk);
                    if let Err(e) = create_fork(&data_dir, &name, from, &coord, &by_id_dir, &flags)
                    {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                } else {
                    let size_str = match size.as_deref() {
                        Some(s) => s,
                        None => {
                            eprintln!("error: --size is required (e.g. --size 4G)");
                            std::process::exit(1);
                        }
                    };
                    let bytes = match parse_size(size_str) {
                        Ok(b) if b > 0 => b,
                        Ok(_) => {
                            eprintln!("error: volume size must be non-zero");
                            std::process::exit(1);
                        }
                        Err(e) => {
                            eprintln!("error: bad --size: {e}");
                            std::process::exit(1);
                        }
                    };
                    let flags = encode_transport_flags(ublk, no_ublk);
                    let ulid = match coord.create_volume_remote(&name, bytes, &flags) {
                        Ok(u) => u,
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    };
                    let by_name = data_dir.join("by_name").join(&name);
                    let by_id = data_dir.join("by_id").join(&ulid);
                    println!("{}", by_name.display());
                    println!("{}", by_id.display());
                }
            }

            VolumeCommand::Update {
                name,
                ublk,
                no_ublk,
            } => {
                let flags = encode_transport_flags(ublk, no_ublk);
                match coord.update_volume(&name, &flags) {
                    Ok(reply) if reply.restarted => {
                        println!("volume restarting with new config")
                    }
                    Ok(_) => {
                        println!("volume not running; config will take effect on next start")
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            VolumeCommand::Status { name, remote } => {
                if remote {
                    match coord.status_remote(&name) {
                        Ok(rs) => print_remote_status(&name, &rs),
                        Err(e) => {
                            eprintln!("{name}: {e}");
                            std::process::exit(1);
                        }
                    }
                } else if let Err(e) = print_local_status(&name, &data_dir, &coord) {
                    eprintln!("{name}: {e}");
                    std::process::exit(1);
                }
            }

            VolumeCommand::Events { name, num, json } => match coord.volume_events(&name, num) {
                Ok(reply) => {
                    if json {
                        for entry in &reply.events {
                            match serde_json::to_string(entry) {
                                Ok(s) => println!("{s}"),
                                Err(e) => {
                                    eprintln!("{name}: serialise event: {e}");
                                    std::process::exit(1);
                                }
                            }
                        }
                    } else {
                        print_volume_events(&reply);
                    }
                }
                Err(e) => {
                    eprintln!("{name}: {e}");
                    std::process::exit(1);
                }
            },

            VolumeCommand::Import(import_args) => match import_args.command {
                Some(ImportSubcommand::Status { name }) => {
                    use coordinator_client::ImportStatusReply;
                    match coord.import_status_by_name(&name) {
                        Ok(ImportStatusReply::Running) => println!("{name}: running"),
                        Ok(ImportStatusReply::Done) => println!("{name}: done"),
                        Err(e) => {
                            eprintln!("{name}: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                Some(ImportSubcommand::Attach { name }) => {
                    let mut stdout = std::io::stdout();
                    if let Err(e) = coord.import_attach_by_name(&name, &mut stdout) {
                        eprintln!("import failed: {e}");
                        std::process::exit(1);
                    }
                }
                None => {
                    let (name, oci_ref) = match (import_args.name, import_args.oci_ref) {
                        (Some(n), Some(r)) => (n, r),
                        _ => {
                            eprintln!(
                                "error: usage: elide volume import <name> <oci_ref> [--fork <name>] [--detach]"
                            );
                            std::process::exit(1);
                        }
                    };
                    if let Err(e) = validate_volume_name(&name) {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                    if let Err(e) = coord.import_start(&name, &oci_ref, &import_args.extents_from) {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                    if import_args.detach {
                        eprintln!("Import started for '{name}'.");
                        eprintln!("  elide volume import attach {name}   # stream output");
                        eprintln!("  elide volume import status {name}   # check state");
                    } else {
                        // Sync: stream output and wait for completion.
                        // Install a Ctrl-C handler so the user gets a clear
                        // message if they interrupt: the import keeps running
                        // in the background and can be re-attached later.
                        let name_for_ctrlc = name.clone();
                        ctrlc::set_handler(move || {
                            eprintln!("\nImport still running in background.");
                            eprintln!("  elide volume import attach {name_for_ctrlc}");
                            eprintln!("  elide volume import status {name_for_ctrlc}");
                            std::process::exit(130);
                        })
                        .ok();

                        let mut stdout = std::io::stdout();
                        if let Err(e) = coord.import_attach_by_name(&name, &mut stdout) {
                            eprintln!("import failed: {e}");
                            std::process::exit(1);
                        }
                        // Optionally create a fork immediately after import.
                        if let Some(fork_name) = import_args.fork
                            && let Err(e) =
                                create_fork(&data_dir, &fork_name, &name, &coord, &by_id_dir, &[])
                        {
                            eprintln!("error creating fork '{fork_name}': {e}");
                            std::process::exit(1);
                        }
                    }
                }
            },

            VolumeCommand::Evict { segment, name } => {
                match coord.evict_volume(&name, segment.as_deref()) {
                    Ok(n) => {
                        let label = if n == 1 { "segment" } else { "segments" };
                        println!("evicted {n} {label}");
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            VolumeCommand::Remove { name, force } => {
                // Resolve `name` → ULID once, locally, against the
                // `by_name/<name>` symlink. The resolved ULID is what
                // the coordinator removes, so the bucket-side `names/`
                // record never re-enters the deletion decision.
                let volume_ulid = match resolve_local_volume_ulid(&data_dir, &name)
                    .and_then(|s| ulid::Ulid::from_string(&s).ok())
                {
                    Some(u) => u,
                    None => {
                        eprintln!(
                            "error: no local volume named {name:?}; the by_name/{name} \
                             link is missing or broken"
                        );
                        std::process::exit(1);
                    }
                };
                if let Err(e) = coord.remove_volume(volume_ulid, force) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }

            VolumeCommand::Stop {
                name,
                release,
                force,
            } => {
                // `--force` with no reachable coordinator: fall back to
                // direct CLI mode. Read volume.pid, SIGTERM if alive,
                // write volume.stopped marker. No bucket flip (no
                // credentials in the CLI), no stop-snapshot publish
                // (the daemon's the only signer). The bucket record is
                // left as-is — typically `Live` — so cross-host
                // recovery requires `volume claim --force` from
                // another host. This path exists for
                // when the coordinator is down and the volume daemon
                // needs to be halted urgently (e.g. a stuck drain, a
                // host being torn down quickly).
                //
                // Without `--force`, an unreachable coordinator is an
                // error — the operator should bring the coordinator
                // back up first (cleaner stop with bucket flip and
                // stop-snapshot).
                if force && !coord.is_reachable() {
                    if release {
                        eprintln!(
                            "error: `--release` is incompatible with coord-down `--force` \
                             (release needs S3 credentials only the coordinator has)"
                        );
                        std::process::exit(1);
                    }
                    match volume_stop_force_direct(&data_dir, &name) {
                        Ok(()) => {
                            eprintln!(
                                "warning: coordinator unreachable — halted local daemon directly; \
                                 names/{name} in S3 is unchanged (likely still Live). Recover \
                                 from another host via `volume claim --force {name}` if needed."
                            );
                            println!("{name}: stopped (direct)");
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    }
                    return;
                }
                if let Err(e) = coord.stop_volume(&name, force) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
                if release {
                    match coord.release_volume(&name) {
                        Ok(reply) => {
                            println!(
                                "{name}: released at handoff snapshot {}",
                                reply.handoff_snapshot
                            );
                        }
                        Err(e) => {
                            eprintln!("error: {e}");
                            std::process::exit(1);
                        }
                    }
                } else {
                    println!("{name}: stopped");
                }
            }

            VolumeCommand::Start {
                name,
                claim,
                no_ublk,
            } => {
                if claim {
                    // run_claim's foreign-claim path streams the prefetch
                    // already; no second await needed here.
                    if let Err(e) = run_claim(&name, false, &coord) {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                } else if let Some(vol_ulid) = resolve_local_volume_ulid(&data_dir, &name) {
                    // Plain start. Common case: volume was claimed and
                    // started before, prefetch is long done — quick probe
                    // returns Ok instantly and we stay silent. Edge case:
                    // a previous claim's streaming was Ctrl-C'd before
                    // completion, or the coordinator restarted mid-
                    // prefetch — quick probe times out, we surface the
                    // wait so start isn't a silent multi-second hang.
                    install_prefetch_ctrlc_handler(&name, "[start]");
                    let quick = std::time::Duration::from_millis(250);
                    if coord.await_prefetch(&vol_ulid, quick).is_err() {
                        eprintln!("[start] waiting for ancestor prefetch...");
                        match coord
                            .await_prefetch(&vol_ulid, coordinator_client::PREFETCH_AWAIT_BUDGET)
                        {
                            Ok(()) => eprintln!("[start] ready"),
                            Err(e) => eprintln!(
                                "[start] prefetch did not finish in time ({e}); \
                                 coordinator continues in background"
                            ),
                        }
                    }
                }
                if no_ublk {
                    // Drop the transport before the first spawn so the
                    // volume never attempts a ublk start.
                    let flags = encode_transport_flags(false, true);
                    if let Err(e) = coord.update_volume(&name, &flags) {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
                if let Err(e) = coord.start_volume(&name) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
                if claim {
                    println!("{name}: claimed and started");
                } else {
                    println!("{name}: started");
                }
            }

            VolumeCommand::Claim { name, force } => {
                if let Err(e) = run_claim(&name, force, &coord) {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
                let verb = if force { "force-claimed" } else { "claimed" };
                println!("{name}: {verb}");
            }

            VolumeCommand::Release { name } => match coord.release_volume(&name) {
                Ok(reply) => {
                    println!(
                        "{name}: released at handoff snapshot {}",
                        reply.handoff_snapshot
                    );
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            },
        },

        Command::ServeVolume {
            fork_dir,
            size,
            readonly,
            ublk,
        } => {
            // In the flat layout, fork_dir IS the volume directory.
            let size_bytes = resolve_volume_size(&fork_dir, size.as_deref())
                .expect("failed to determine volume size");
            let fetch_config =
                resolve_volume_fetch_config(&fork_dir).expect("failed to load fetch config");
            if ublk {
                if readonly {
                    panic!("ublk transport does not yet support --readonly");
                }
                match ublk::run_volume_ublk(&fork_dir, size_bytes, fetch_config) {
                    Ok(()) => return,
                    Err(ublk::UblkRunError::Config(msg)) => {
                        eprintln!("ublk: {msg}");
                        std::process::exit(ublk::EXIT_CONFIG);
                    }
                    Err(ublk::UblkRunError::Other(e)) => {
                        eprintln!("ublk server error: {e}");
                        std::process::exit(1);
                    }
                }
            }
            // No transport requested (or draining): IPC-only daemon.
            // Writable volumes need the signing keypair on disk before
            // the actor can promote segments; generate it here if the
            // volume is fresh and not marked readonly.
            if !readonly
                && !fork_dir.join("volume.readonly").exists()
                && !fork_dir.join(VOLUME_KEY_FILE).exists()
            {
                std::fs::create_dir_all(&fork_dir).expect("failed to create fork directory");
                let key = elide_core::signing::generate_keypair(
                    &fork_dir,
                    VOLUME_KEY_FILE,
                    VOLUME_PUB_FILE,
                )
                .expect("failed to generate volume keypair");
                elide_core::signing::write_provenance(
                    &fork_dir,
                    &key,
                    VOLUME_PROVENANCE_FILE,
                    &elide_core::signing::ProvenanceLineage::default(),
                )
                .expect("failed to write volume.provenance");
            }
            if fork_dir.join(VOLUME_KEY_FILE).exists() {
                elide_core::signing::read_lineage_verifying_signature(
                    &fork_dir,
                    VOLUME_PUB_FILE,
                    VOLUME_PROVENANCE_FILE,
                )
                .expect("volume.provenance signature check failed");
            }
            serve::run_volume_ipc_only(&fork_dir, fetch_config).expect("volume daemon error");
        }

        Command::Extents {
            image1,
            image2,
            level,
        } => {
            extents::run(Path::new(&image1), image2.as_deref().map(Path::new), level)
                .expect("extents failed");
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

        Command::ExtractBoot { image, out_dir } => {
            extract_boot(Path::new(&image), Path::new(&out_dir)).expect("extract-boot failed");
        }

        Command::Repack { fork_dir } => {
            let by_id_dir = fork_dir.parent().unwrap_or(&fork_dir).to_owned();
            let mut vol =
                volume::Volume::open(&fork_dir, &by_id_dir).expect("failed to open volume");
            let stats = vol.repack().expect("repack failed");
            println!(
                "segments repacked: {}  bytes freed: {}  extents removed: {}",
                stats.segments_compacted, stats.bytes_freed, stats.extents_removed,
            );
        }

        Command::InspectSegment { path } => {
            inspect_files::inspect_segment(&path).expect("inspect-segment failed");
        }

        Command::InspectWal { path } => {
            inspect_files::inspect_wal(&path).expect("inspect-wal failed");
        }

        Command::InspectDmat { path } => {
            inspect_files::inspect_dmat(&path).expect("inspect-dmat failed");
        }

        Command::Ublk { command } => match command {
            UblkCommand::List => {
                if let Err(e) = ublk::list_devices() {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            UblkCommand::Delete { id, all } => {
                let result = match (id, all) {
                    (Some(id), false) => ublk::delete_device(id),
                    (None, true) => ublk::delete_all_devices(),
                    _ => {
                        eprintln!("error: specify a device id, or use --all (but not both)");
                        std::process::exit(1);
                    }
                };
                if let Err(e) = result {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        },

        Command::Coord { command } => match command {
            CoordCommand::Start { config } => {
                let result = resolve_coord_data_dir(cli_data_dir.as_deref(), config.as_deref())
                    .and_then(|dd| coord_start(&dd, cli_data_dir.as_deref(), config.as_deref()));
                if let Err(e) = result {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            CoordCommand::Stop {
                stop_volumes,
                config,
            } => {
                let result = resolve_coord_data_dir(cli_data_dir.as_deref(), config.as_deref())
                    .and_then(|dd| {
                        let coord = coordinator_client::Client::new(dd.join("control.sock"));
                        coord_stop(&coord, &dd, !stop_volumes)
                    });
                if let Err(e) = result {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
            CoordCommand::Run { config } => {
                // coord_run execs the coordinator and lets it own
                // data_dir resolution from --config. We only forward
                // --data-dir when the user explicitly set it.
                let e = coord_run(cli_data_dir.as_deref(), config.as_deref());
                eprintln!("error: {e}");
                std::process::exit(1);
            }
            CoordCommand::Enroll {
                config,
                invite,
                timeout,
                force,
                attestation,
            } => {
                // Like `run`: exec the sibling and let it own data_dir
                // resolution from --config; exec returns only on
                // failure (success replaces this process, so the
                // daemon's exit code flows through).
                let e = coord_enroll(
                    cli_data_dir.as_deref(),
                    config.as_deref(),
                    &invite,
                    timeout.as_deref(),
                    force,
                    attestation,
                );
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        },
    }
}

/// Resolve the data_dir for `coord` subcommands: explicit `--data-dir`
/// (or `ELIDE_DATA_DIR`) wins, otherwise parse `--config` to read its
/// `data_dir` field, otherwise fall back to `elide_data`. This mirrors
/// the precedence used inside the coordinator itself, so the CLI and
/// the daemon always agree on which directory holds the pidfile,
/// socket, and per-volume state.
fn resolve_coord_data_dir(cli: Option<&Path>, config: Option<&Path>) -> std::io::Result<PathBuf> {
    if let Some(dd) = cli {
        return Ok(dd.to_owned());
    }
    if let Some(cfg) = config {
        let parsed = elide_coordinator::config::load(cfg)
            .map_err(|e| std::io::Error::other(format!("loading {}: {e:#}", cfg.display())))?;
        return Ok(parsed.data_dir);
    }
    Ok(PathBuf::from("elide_data"))
}

/// Exec the sibling `elide-coordinator serve` with stdio inherited.
/// Returns only on failure — on success, exec replaces this process so
/// signals and exit status flow directly through the coordinator.
fn coord_run(cli_data_dir: Option<&Path>, config: Option<&Path>) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let bin = sibling_bin("elide-coordinator");
    let mut cmd = Command::new(&bin);
    cmd.arg("serve");
    // Only forward --data-dir if the user explicitly set it; otherwise
    // let the coordinator's config loader own the default so the
    // `data_dir` field in coordinator.toml is honoured.
    if let Some(dd) = cli_data_dir {
        cmd.arg("--data-dir").arg(dd);
    }
    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }
    // exec() returns only on failure; the success path replaces this
    // process image with the coordinator's, so signals (SIGINT,
    // SIGTERM, SIGHUP) and the exit code flow through directly.
    let err = cmd.exec();
    std::io::Error::other(format!("execing {}: {err}", bin.display()))
}

/// Exec the sibling `elide-coordinator enroll` with stdio inherited.
/// Returns only on failure — on success, exec replaces this process so
/// the blocking enrollment's exit status and signals flow through.
fn coord_enroll(
    cli_data_dir: Option<&Path>,
    config: Option<&Path>,
    invite: &str,
    timeout: Option<&str>,
    force: bool,
    attestation: bool,
) -> std::io::Error {
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    let bin = sibling_bin("elide-coordinator");
    let mut cmd = Command::new(&bin);
    cmd.arg("enroll");
    // Only forward --data-dir if the user explicitly set it; otherwise
    // let the coordinator's config loader own the default so the
    // `data_dir` field in coordinator.toml is honoured.
    if let Some(dd) = cli_data_dir {
        cmd.arg("--data-dir").arg(dd);
    }
    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }
    if let Some(t) = timeout {
        cmd.arg("--timeout").arg(t);
    }
    if force {
        cmd.arg("--force");
    }
    if attestation {
        cmd.arg("--attestation");
    }
    // Positional invite last, so a value like `-` (stdin) is
    // unambiguous after the flags.
    cmd.arg(invite);
    let err = cmd.exec();
    std::io::Error::other(format!("execing {}: {err}", bin.display()))
}

/// Time to wait for the coordinator's control socket to appear after
/// `coord start` spawns the daemon.
const COORD_START_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// Time to wait for the coordinator to exit after `coord stop` sends
/// the Shutdown IPC. Generous because full teardown waits for volume
/// children to exit (10s SIGTERM grace + drain).
const COORD_STOP_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// In the direct-teardown fallback, how long to give a volume child to
/// react to SIGTERM (graceful flush + exit) before escalating to
/// SIGKILL. The ublk transport's signal watcher caps its own flush at
/// 3s, so 10s is well past the worst legitimate case.
const SIGTERM_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// After SIGKILL, how long to wait for the kernel to actually reap the
/// process before giving up. SIGKILL can't be blocked, so anything
/// past this is a kernel-side stuck process (e.g. D-state on broken
/// I/O) that no supervisor can clean up.
const SIGKILL_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn `elide-coordinator serve` as a detached background process.
///
/// Stdout/stderr are appended to `<data_dir>/elide.log`; the
/// child is placed in a new session (setsid) so it survives the parent
/// shell. We then poll for the control socket to appear, returning
/// once it accepts connections.
fn coord_start(
    data_dir: &Path,
    cli_data_dir: Option<&Path>,
    config: Option<&Path>,
) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    std::fs::create_dir_all(data_dir).map_err(|e| {
        std::io::Error::other(format!("creating data dir {}: {e}", data_dir.display()))
    })?;
    let pid_path = data_dir.join("coordinator.pid");
    if let Ok(text) = std::fs::read_to_string(&pid_path)
        && let Ok(pid) = text.trim().parse::<u32>()
        && elide_core::process::pid_is_alive(pid)
    {
        return Err(std::io::Error::other(format!(
            "coordinator already running (pid {pid})"
        )));
    }

    let bin = sibling_bin("elide-coordinator");
    let log_path = data_dir.join("elide.log");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| std::io::Error::other(format!("opening {}: {e}", log_path.display())))?;
    let log_clone = log_file.try_clone()?;

    let mut cmd = Command::new(&bin);
    cmd.arg("serve");
    // Only forward --data-dir if the user explicitly set it; otherwise
    // let the coordinator resolve from --config (or its own default)
    // so the `data_dir` field in coordinator.toml is honoured.
    if let Some(dd) = cli_data_dir {
        cmd.arg("--data-dir").arg(dd);
    }
    if let Some(cfg) = config {
        cmd.arg("--config").arg(cfg);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_clone));
    // Detach from the parent's session so the daemon survives the shell.
    // pre_exec runs between fork() and exec(); setsid() is async-signal-safe.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| std::io::Error::other(format!("spawning {}: {e}", bin.display())))?;
    let child_pid = child.id();

    let socket_path = data_dir.join("control.sock");
    let deadline = std::time::Instant::now() + COORD_START_WAIT;
    loop {
        if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
            println!(
                "coordinator started (pid {child_pid}, socket {})",
                socket_path.display()
            );
            return Ok(());
        }
        // Detect early exit: try_wait reaps the zombie if the daemon
        // already exited. pid_is_alive returns true for zombies (the
        // process entry exists until the parent waits), which would
        // mask early failures until our deadline expires.
        if let Ok(Some(status)) = child.try_wait() {
            return Err(std::io::Error::other(format!(
                "coordinator exited before becoming ready ({status}); see {}",
                log_path.display()
            )));
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::other(format!(
                "timed out waiting for control socket {}; see {}",
                socket_path.display(),
                log_path.display()
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Send the `Shutdown` IPC and poll until the coordinator process actually
/// exits (socket disappears / pidfile pid stops responding).
///
/// `keep_volumes = true` (the default) is the rolling-upgrade path: the
/// coordinator exits, its volume children continue running detached.
/// `keep_volumes = false` (`--stop-volumes`) terminates managed volume
/// processes as well — and when the coordinator is not running, falls
/// back to direct per-volume teardown by walking `<data_dir>/by_id/*/`
/// and SIGTERMing every `volume.pid` / `import.pid` it finds. The
/// fallback covers post-crash cleanup; in the keep-volumes path it is
/// a no-op since "coordinator gone, volumes running" is already the
/// desired state.
fn coord_stop(
    coord: &coordinator_client::Client,
    data_dir: &Path,
    keep_volumes: bool,
) -> std::io::Result<()> {
    if !coord.is_reachable() {
        if keep_volumes {
            println!(
                "coordinator not running ({}); volumes left running",
                coord.socket_path().display()
            );
            return Ok(());
        }
        return fallback_stop_volumes(data_dir);
    }
    coord.shutdown(keep_volumes)?;

    let pid_path = data_dir.join("coordinator.pid");
    let pid = std::fs::read_to_string(&pid_path)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok());
    let deadline = std::time::Instant::now() + COORD_STOP_WAIT;
    loop {
        let still_alive = match pid {
            Some(p) => elide_core::process::pid_is_alive(p),
            None => coord.is_reachable(),
        };
        if !still_alive {
            println!(
                "coordinator stopped{}",
                if keep_volumes {
                    " (volumes left running)"
                } else {
                    ""
                }
            );
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(std::io::Error::other(format!(
                "coordinator did not exit within {COORD_STOP_WAIT:?}"
            )));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Direct teardown of every running volume + import process under
/// Direct-CLI equivalent of `volume stop --force <name>` when the
/// coordinator socket is unreachable. Resolves `by_name/<name>` to the
/// fork directory, SIGTERMs the running daemon if any, then writes
/// `volume.stopped` so a future coordinator start respects the halt.
/// No bucket flip and no stop-snapshot publish — the daemon is the
/// only thing with the signing key for a stop-snapshot, and the
/// CLI doesn't carry S3 credentials.
///
/// On success the caller surfaces a warning explaining that
/// `names/<name>` in S3 is now stale: cross-host recovery is
/// `volume claim --force` from the host that wants the volume.
fn volume_stop_force_direct(data_dir: &Path, name: &str) -> std::io::Result<()> {
    let link = data_dir.join("by_name").join(name);
    if !link.exists() {
        return Err(std::io::Error::other(format!(
            "volume not found: {name} (no {} symlink)",
            link.display()
        )));
    }
    let vol_dir = std::fs::canonicalize(&link)
        .map_err(|e| std::io::Error::other(format!("resolving {}: {e}", link.display())))?;

    if vol_dir.join("volume.stopped").exists() {
        // Already stopped — idempotent.
        return Ok(());
    }

    // Read pid, SIGTERM if alive. Missing pid file is fine — daemon
    // isn't running.
    let pid_path = vol_dir.join("volume.pid");
    if let Ok(text) = std::fs::read_to_string(&pid_path)
        && let Ok(pid) = text.trim().parse::<u32>()
        && elide_core::process::pid_is_alive(pid)
        && let Ok(raw) = i32::try_from(pid)
    {
        // SAFETY: libc::kill takes a pid + signal; the kernel checks
        // permission and existence. SIGTERM has no observable
        // side-effect on this process.
        if unsafe { libc::kill(raw, libc::SIGTERM) } != 0 {
            let err = std::io::Error::last_os_error();
            // Permission-denied is the most likely failure here: the
            // daemon was spawned under sudo and the CLI is unsudo'd.
            return Err(std::io::Error::other(format!("SIGTERM pid {pid}: {err}")));
        }
    }

    // Write the marker so the next coordinator start respects the
    // stop. Best-effort: a write failure here means the daemon will
    // be re-spawned next coordinator start, but the SIGTERM (if it
    // succeeded) already halted the current process.
    std::fs::write(vol_dir.join("volume.stopped"), "")
        .map_err(|e| std::io::Error::other(format!("writing volume.stopped: {e}")))?;

    Ok(())
}

/// `<data_dir>/by_id/*/` when the coordinator socket is unreachable.
/// Reads each `volume.pid` / `import.pid`, SIGTERMs the live ones, and
/// polls until they exit or the wait budget expires.
fn fallback_stop_volumes(data_dir: &Path) -> std::io::Result<()> {
    let by_id = data_dir.join("by_id");
    let entries = match std::fs::read_dir(&by_id) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("no volume processes to stop ({} absent)", by_id.display());
            return Ok(());
        }
        Err(e) => return Err(e),
    };

    let mut pids: Vec<(u32, String)> = Vec::new();
    for entry in entries.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        for filename in &["volume.pid", "import.pid"] {
            let pid_path = dir.join(filename);
            let Ok(text) = std::fs::read_to_string(&pid_path) else {
                continue;
            };
            let Ok(pid) = text.trim().parse::<u32>() else {
                continue;
            };
            if !elide_core::process::pid_is_alive(pid) {
                continue;
            }
            let Ok(raw) = i32::try_from(pid) else {
                continue;
            };
            let label = format!("{filename}={pid} in {}", dir.display());
            // SAFETY: libc::kill takes a pid + signal; the kernel checks
            // permission and existence. SIGTERM has no observable
            // side-effect on this process.
            if unsafe { libc::kill(raw, libc::SIGTERM) } != 0 {
                let err = std::io::Error::last_os_error();
                eprintln!("SIGTERM {label}: {err}");
                continue;
            }
            println!("SIGTERM {label}");
            pids.push((pid, label));
        }
    }

    if pids.is_empty() {
        println!("no volume processes to stop");
        return Ok(());
    }

    // Phase 1: wait up to SIGTERM_GRACE for graceful exit.
    let term_deadline = std::time::Instant::now() + SIGTERM_GRACE;
    let mut survivors = wait_for_exit(&pids, term_deadline);
    if survivors.is_empty() {
        println!("all volume processes stopped");
        return Ok(());
    }

    // Phase 2: anything still alive after SIGTERM_GRACE gets SIGKILL.
    // The volume's ublk signal watcher caps its own flush at 3s,
    // so anything past SIGTERM_GRACE is a wedged process the operator
    // wants gone. Mirrors `systemctl stop`'s TimeoutStopSec → SIGKILL.
    for (pid, label) in &survivors {
        let Ok(raw) = i32::try_from(*pid) else {
            continue;
        };
        // SAFETY: libc::kill takes a pid + signal; the kernel checks
        // permission and existence. SIGKILL cannot be caught or
        // blocked, so this either succeeds or returns ESRCH.
        if unsafe { libc::kill(raw, libc::SIGKILL) } != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("SIGKILL {label}: {err}");
            continue;
        }
        println!("SIGKILL {label} (did not exit within {SIGTERM_GRACE:?})");
    }

    let kill_deadline = std::time::Instant::now() + SIGKILL_WAIT;
    survivors = wait_for_exit(&survivors, kill_deadline);
    if survivors.is_empty() {
        println!("all volume processes stopped");
        return Ok(());
    }
    let labels: Vec<&str> = survivors.iter().map(|(_, l)| l.as_str()).collect();
    Err(std::io::Error::other(format!(
        "{n} process(es) still alive after SIGKILL+{SIGKILL_WAIT:?}: {labels:?}",
        n = survivors.len()
    )))
}

/// Wait until `deadline` for every pid in `pids` to exit; return the
/// ones still alive when the wait expires. Polls at 100ms intervals.
fn wait_for_exit(pids: &[(u32, String)], deadline: std::time::Instant) -> Vec<(u32, String)> {
    loop {
        let still: Vec<(u32, String)> = pids
            .iter()
            .filter(|(p, _)| elide_core::process::pid_is_alive(*p))
            .cloned()
            .collect();
        if still.is_empty() || std::time::Instant::now() >= deadline {
            return still;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Locate a sibling binary alongside the running `elide` executable.
/// Falls back to PATH lookup if the current exe path can't be resolved.
fn sibling_bin(name: &str) -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|dir| dir.join(name)))
        .unwrap_or_else(|| PathBuf::from(name))
}

enum ListFilter {
    Writable,
    Readonly,
    All,
}

use elide_coordinator::volume_state::{VolumeLifecycle, VolumeMode};

/// Cell value for the STATE column in `elide volume list`. Wraps the
/// disk-derived `VolumeLifecycle` with one CLI-only sentinel:
///
/// - `Ancestor` — pulled ancestor volume that has no `by_name/` entry
///   and is never supervised. Lifecycle classification doesn't apply.
enum CliVolumeState {
    Lifecycle(VolumeLifecycle),
    Ancestor,
}

impl CliVolumeState {
    fn label(&self) -> &'static str {
        match self {
            Self::Lifecycle(l) => l.label(),
            Self::Ancestor => "ancestor",
        }
    }
}

struct VolumeRow {
    name: String,
    ulid: String,
    mode: VolumeMode,
    state: CliVolumeState,
    device: String,
    pending: String,
    pid: String,
}

fn list_volumes(
    data_dir: &Path,
    coord: &coordinator_client::Client,
    filter: ListFilter,
    include_ancestors: bool,
) -> std::io::Result<()> {
    let coordinator_up = coord.is_reachable();
    let by_name_dir = data_dir.join("by_name");
    let by_id_dir = data_dir.join("by_id");
    let mut rows: Vec<VolumeRow> = Vec::new();
    let mut seen: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    match std::fs::read_dir(&by_name_dir) {
        Ok(dir_entries) => {
            for entry in dir_entries {
                let entry = entry?;
                let name = entry.file_name().to_string_lossy().into_owned();
                // Resolve symlink to get the actual volume dir.
                let vol_dir = std::fs::read_link(entry.path())
                    .ok()
                    .map(|target| {
                        if target.is_absolute() {
                            target
                        } else {
                            by_name_dir.join(target)
                        }
                    })
                    .unwrap_or_else(|| entry.path());
                if let Ok(canonical) = std::fs::canonicalize(&vol_dir) {
                    seen.insert(canonical);
                }
                let is_readonly = vol_dir.join("volume.readonly").exists();
                let include = match filter {
                    ListFilter::All => true,
                    ListFilter::Readonly => is_readonly,
                    ListFilter::Writable => !is_readonly,
                };
                if !include {
                    continue;
                }
                rows.push(volume_row(name, &vol_dir, is_readonly));
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    if include_ancestors && !matches!(filter, ListFilter::Writable) {
        match std::fs::read_dir(&by_id_dir) {
            Ok(dir_entries) => {
                for entry in dir_entries {
                    let entry = entry?;
                    let vol_dir = entry.path();
                    if !vol_dir.is_dir() {
                        continue;
                    }
                    let Some(ulid_str) = vol_dir.file_name().and_then(|n| n.to_str()) else {
                        continue;
                    };
                    if ulid::Ulid::from_string(ulid_str).is_err() {
                        continue;
                    }
                    let canonical =
                        std::fs::canonicalize(&vol_dir).unwrap_or_else(|_| vol_dir.clone());
                    if seen.contains(&canonical) {
                        continue;
                    }
                    if !vol_dir.join("volume.readonly").exists() {
                        continue;
                    }
                    rows.push(volume_row("-".to_owned(), &vol_dir, true));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
    }
    // Named volumes first (alphabetical), pulled ancestors at the bottom (by ULID).
    rows.sort_by(|a, b| match (a.name.as_str(), b.name.as_str()) {
        ("-", "-") => a.ulid.cmp(&b.ulid),
        ("-", _) => std::cmp::Ordering::Greater,
        (_, "-") => std::cmp::Ordering::Less,
        _ => a.name.cmp(&b.name),
    });
    if rows.is_empty() {
        println!("no volumes found in {}", data_dir.display());
        if !coordinator_up {
            println!(
                "coordinator is not running ({})",
                coord.socket_path().display()
            );
        }
        return Ok(());
    }
    let name_w = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    let ulid_w = rows.iter().map(|r| r.ulid.len()).max().unwrap_or(4).max(4);
    let mode_w = 4;
    let state_w = rows
        .iter()
        .map(|r| r.state.label().len())
        .max()
        .unwrap_or(5)
        .max(5);
    let device_w = rows
        .iter()
        .map(|r| r.device.len())
        .max()
        .unwrap_or(6)
        .max(6);
    let pending_w = rows
        .iter()
        .map(|r| r.pending.len())
        .max()
        .unwrap_or(7)
        .max(7);
    println!(
        "{:<name_w$}  {:<ulid_w$}  {:<mode_w$}  {:<state_w$}  {:<device_w$}  {:<pending_w$}  PID",
        "NAME", "ULID", "MODE", "STATE", "DEVICE", "PENDING"
    );
    for r in &rows {
        println!(
            "{:<name_w$}  {:<ulid_w$}  {:<mode_w$}  {:<state_w$}  {:<device_w$}  {:<pending_w$}  {}",
            r.name,
            r.ulid,
            r.mode.label(),
            r.state.label(),
            r.device,
            r.pending,
            r.pid
        );
    }
    if !coordinator_up {
        println!();
        println!(
            "coordinator is not running ({})",
            coord.socket_path().display()
        );
    }
    Ok(())
}

/// Render the local lineage forest (`docs/design/ancestor-liveness.md`):
/// anchors and skeletons joined by fork-parent edges, each child row
/// carrying its branch snapshot pin. Reads only local `by_id/` state.
fn tree_volumes(data_dir: &Path) -> std::io::Result<()> {
    use elide_coordinator::lineage_forest::{ForestNode, NodeClass, build_forest};

    let forest = build_forest(data_dir)?;
    if forest.nodes.is_empty() {
        println!("no volumes");
        return Ok(());
    }

    let mut children: std::collections::BTreeMap<ulid::Ulid, Vec<ulid::Ulid>> = Default::default();
    let mut roots: Vec<ulid::Ulid> = Vec::new();
    for node in &forest.nodes {
        match &node.parent {
            Some(edge) => children.entry(edge.ulid).or_default().push(node.ulid),
            None => roots.push(node.ulid),
        }
    }
    // Siblings order along the parent's timeline: by branch snapshot,
    // then by their own ULID — same-basis forks render adjacent.
    for kids in children.values_mut() {
        kids.sort_by_key(|k| {
            let snapshot = forest
                .get(*k)
                .and_then(|n| n.parent.as_ref().map(|p| p.snapshot));
            (snapshot, *k)
        });
    }

    fn describe(node: &ForestNode) -> String {
        let mut parts: Vec<String> = Vec::new();
        match node.class {
            NodeClass::Anchor => {
                let lifecycle = node.lifecycle.as_ref();
                let readonly = matches!(
                    lifecycle,
                    Some(elide_coordinator::volume_state::VolumeLifecycle::ReadonlyImported)
                );
                parts.push(if readonly { "ro".into() } else { "rw".into() });
                if let Some(l) = lifecycle {
                    parts.push(l.label().to_owned());
                }
            }
            NodeClass::Skeleton => {
                parts.push("skeleton".into());
                if !node.live {
                    parts.push("unreferenced".into());
                }
            }
            NodeClass::Missing => parts.push("MISSING".into()),
            NodeClass::Unclassified => parts.push("unclassified".into()),
        }
        if node.extent_sources > 0 {
            parts.push(format!("+{} extent source(s)", node.extent_sources));
        }
        if node.recovery_sources > 0 {
            parts.push(format!("+{} recovery source(s)", node.recovery_sources));
        }
        if node.lineage_error.is_some() {
            parts.push("provenance unreadable".into());
        }
        parts.join("  ")
    }

    fn render(
        forest: &elide_coordinator::lineage_forest::LineageForest,
        children: &std::collections::BTreeMap<ulid::Ulid, Vec<ulid::Ulid>>,
        visited: &mut std::collections::HashSet<ulid::Ulid>,
        ulid: ulid::Ulid,
        prefix: &str,
        connector: &str,
        child_prefix: &str,
    ) {
        let Some(node) = forest.get(ulid) else {
            return;
        };
        let name = node.name.as_deref().unwrap_or("-");
        // The pin leads the row: siblings sort by it, so it reads as
        // the position in the parent's history the fork branched from.
        let pin = node
            .parent
            .as_ref()
            .map(|e| format!("@{}  ", e.snapshot))
            .unwrap_or_default();
        if !visited.insert(ulid) {
            println!("{prefix}{connector}{pin}{ulid}  {name}  cycle!");
            return;
        }
        println!("{prefix}{connector}{pin}{ulid}  {name}  {}", describe(node));
        let kids = children.get(&ulid).map(Vec::as_slice).unwrap_or(&[]);
        for (i, kid) in kids.iter().enumerate() {
            let last = i == kids.len() - 1;
            render(
                forest,
                children,
                visited,
                *kid,
                &format!("{prefix}{child_prefix}"),
                if last { "└─ " } else { "├─ " },
                if last { "   " } else { "│  " },
            );
        }
    }

    let mut visited = std::collections::HashSet::new();
    for root in roots {
        render(&forest, &children, &mut visited, root, "", "", "");
    }
    Ok(())
}

/// Gather per-volume display state: lifecycle, ublk device, and pid.
///
/// State labels mirror the coordinator's IPC `volume_status`
/// (`elide-coordinator/src/inbound.rs`):
///
/// - `running`          — `volume.pid` present and the process is alive.
/// - `importing`        — an import lock is held.
/// - `stopped (manual)` — `volume.stopped` is set; the coordinator will not
///   auto-start this volume.
/// - `stopped`          — neither a live pid nor a manual-stop marker.
///
/// All of these derive from on-disk markers plus a `kill(pid, 0)` liveness
/// check, so the row renders the same whether or not the coordinator IPC is
/// reachable. The caller prints a footer when the coordinator is down so
/// operators know auto-supervision is paused, but the visible state of each
/// volume (live pid, manual-stop, importing) is a fact about disk regardless.
fn volume_row(name: String, vol_dir: &Path, is_readonly: bool) -> VolumeRow {
    let device = device_summary(vol_dir);
    let ulid = vol_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|s| ulid::Ulid::from_string(s).ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let mode = if is_readonly {
        VolumeMode::Ro
    } else {
        VolumeMode::Rw
    };
    // Pulled ancestors (no by_name/ symlink, no volume.name) are never
    // supervised — render a static "ancestor" state instead of inferring
    // lifecycle from markers that don't apply.
    let state = if name == "-" && is_readonly {
        CliVolumeState::Ancestor
    } else {
        CliVolumeState::Lifecycle(VolumeLifecycle::from_dir(vol_dir))
    };
    let pid = match &state {
        CliVolumeState::Lifecycle(l) => l
            .pid()
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_owned()),
        CliVolumeState::Ancestor => "-".to_owned(),
    };
    VolumeRow {
        name,
        ulid,
        mode,
        state,
        device,
        pending: pending_cell(vol_dir),
        pid,
    }
}

/// Render the bytes not yet uploaded to S3 (pending segments + WAL payload)
/// as a table cell: a size when non-zero, `-` when clean or unreadable.
fn pending_cell(vol_dir: &Path) -> String {
    match inspect::pending_summary(vol_dir) {
        Ok(p) if p.total_bytes() > 0 => inspect::fmt_size(p.total_bytes()),
        _ => "-".to_owned(),
    }
}

/// Operational summary for one volume, derived from on-disk markers so it
/// renders whether or not the coordinator is up; a footer flags paused
/// supervision, mirroring `volume list`.
fn print_local_status(
    name: &str,
    data_dir: &Path,
    coord: &coordinator_client::Client,
) -> std::io::Result<()> {
    let link = resolve_volume_dir(data_dir, name);
    let vol_dir = std::fs::canonicalize(&link).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no local volume named '{name}'"),
            )
        } else {
            e
        }
    })?;
    let lifecycle = VolumeLifecycle::from_dir(&vol_dir);
    println!("{name}: {}", lifecycle.wire_body());
    let ulid = vol_dir
        .file_name()
        .and_then(|n| n.to_str())
        .and_then(|s| ulid::Ulid::from_string(s).ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| "-".to_owned());
    let mode = if vol_dir.join("volume.readonly").exists() {
        VolumeMode::Ro
    } else {
        VolumeMode::Rw
    };
    println!("  ulid:     {ulid}");
    println!("  mode:     {}", mode.label());
    if let Some(pid) = lifecycle.pid() {
        println!("  pid:      {pid}");
    }
    println!("  device:   {}", device_summary(&vol_dir));
    let p = inspect::pending_summary(&vol_dir)?;
    if p.total_bytes() == 0 {
        println!("  pending:  none");
    } else {
        println!(
            "  pending:  {} ({} segment{} {}, wal {})",
            inspect::fmt_size(p.total_bytes()),
            p.pending_files,
            if p.pending_files == 1 { "" } else { "s" },
            inspect::fmt_size(p.pending_bytes),
            inspect::fmt_size(p.wal_bytes),
        );
    }
    match volume::latest_snapshot(&vol_dir).ok().flatten() {
        Some(s) => println!("  snapshot: {s}"),
        None => println!("  snapshot: -"),
    }
    if !coord.is_reachable() {
        println!();
        println!(
            "coordinator is not running ({})",
            coord.socket_path().display()
        );
    }
    Ok(())
}

/// Summarise the volume's ublk block device for display: the bound
/// `/dev/ublkb<id>` (written back to `volume.toml` on a successful ADD),
/// `auto` for a `[ublk]` section with no id yet, or `-` when ublk is off.
fn device_summary(vol_dir: &Path) -> String {
    let cfg = match elide_core::config::VolumeConfig::read(vol_dir) {
        Ok(c) => c,
        Err(_) => return "-".to_owned(),
    };
    if let Some(ublk) = cfg.ublk.as_ref() {
        return match ublk.dev_id {
            Some(id) => format!("/dev/ublkb{id}"),
            None => "auto".to_owned(),
        };
    }
    "-".to_owned()
}

/// Encode the CLI's typed transport flags as the space-separated tokens
/// understood by the coordinator's `create` / `update` IPC verbs. Order
/// follows the IPC parser; absent options emit nothing.
fn encode_transport_flags(ublk: bool, no_ublk: bool) -> Vec<String> {
    let mut out = Vec::new();
    if ublk {
        out.push("ublk".to_owned());
    }
    if no_ublk {
        out.push("no-ublk".to_owned());
    }
    out
}

/// Parse a `--from` value into the `ForkSource` the coordinator's
/// `fork-start` IPC takes.
///
/// Accepted forms:
///   - `<vol_ulid>/<snap_ulid>` — explicit pin to a specific snapshot
///   - `<name>/<snap_ulid>` — explicit pin, source addressed by name
///   - `<name>` — volume name, resolved locally then by remote store
///
/// A bare `<vol_ulid>` is rejected: raw ULIDs always carry an explicit
/// snapshot pin; the name is the discovery surface.
///
/// ULID-wins rule: if the part before `/` parses as a valid ULID it is
/// always treated as one, never looked up as a volume name. This
/// prevents ambiguity when a volume is named with a ULID string.
fn parse_fork_source(from: &str) -> std::io::Result<coordinator_client::ForkSource> {
    if let Some((vol, snap)) = from.split_once('/') {
        let snap_ulid = ulid::Ulid::from_string(snap)
            .map_err(|e| std::io::Error::other(format!("invalid snapshot ULID in --from: {e}")))?;
        if let Ok(vol_ulid) = ulid::Ulid::from_string(vol) {
            Ok(coordinator_client::ForkSource::Pinned {
                vol_ulid,
                snap_ulid,
            })
        } else {
            validate_volume_name(vol)?;
            Ok(coordinator_client::ForkSource::PinnedName {
                name: vol.to_owned(),
                snap_ulid,
            })
        }
    } else if ulid::Ulid::from_string(from).is_ok() {
        Err(std::io::Error::other(format!(
            "--from {from}: a bare volume ULID needs an explicit snapshot pin \
             (--from {from}/<snap_ulid>); use the volume's name to fork from \
             its latest published snapshot"
        )))
    } else {
        Ok(coordinator_client::ForkSource::Name {
            name: from.to_owned(),
        })
    }
}

/// Create a new volume forked from a source.
///
/// `from` is parsed by [`parse_fork_source`]. The source is tried local
/// first, then the remote store (auto-pulling the volume and its
/// ancestor chain).
///
/// For writable volumes, an implicit snapshot is taken first. For
/// readonly volumes (pulled or already local), the latest snapshot is
/// discovered from the local manifests then the `names/<name>` record.
/// For explicit pins the caller already chose a snapshot.
fn create_fork(
    data_dir: &Path,
    fork_name: &str,
    from: &str,
    coord: &coordinator_client::Client,
    by_id_dir: &Path,
    flags: &[String],
) -> std::io::Result<()> {
    validate_volume_name(fork_name)?;

    let by_name_dir = data_dir.join("by_name");
    let symlink_path = by_name_dir.join(fork_name);
    if symlink_path.exists() {
        return Err(std::io::Error::other(format!(
            "volume already exists: {fork_name}"
        )));
    }

    let source = parse_fork_source(from)?;

    coord.fork_start(fork_name, source, flags)?;

    // Stream coordinator-side progress to stderr (chain pull, snapshot
    // decision, fork mint, prefetch warm-up). The terminal `Done`
    // event hands back the new fork's ULID.
    let mut stderr = std::io::stderr();
    let new_vol_ulid = coord.fork_attach_by_name(fork_name, &mut stderr)?;
    let new_fork_dir = by_id_dir.join(new_vol_ulid.to_string());
    println!("{}", new_fork_dir.display());
    Ok(())
}

/// CLI orchestration of `volume claim`.
///
/// Calls the coordinator's `claim` IPC and dispatches:
///   - `Reclaimed`: nothing else to do; the bucket flipped in place.
///   - `NeedsClaim`: pull source if needed, mint a fresh local fork
///     via `fork-create`, then `rebind-name` to atomically rebind the
///     bucket record to the new fork (in `Stopped` state). The
///     conditional PUT inside `rebind-name` resolves races; the local
///     fork is left in place as a usable orphan if another
///     coordinator wins.
fn run_claim(name: &str, force: bool, coord: &coordinator_client::Client) -> std::io::Result<()> {
    use coordinator_client::ClaimStartReply;
    match coord.claim_start(name, force)? {
        ClaimStartReply::Reclaimed => Ok(()),
        ClaimStartReply::Claiming { released_vol_ulid } => {
            eprintln!("[claim] claiming '{name}' from {released_vol_ulid}");
            install_prefetch_ctrlc_handler(name, "[claim]");
            let mut stderr = std::io::stderr();
            // An error here means the orchestrator failed before `finalize`:
            // the bucket points at us but the local fork is incomplete, so
            // the volume can't start. Propagate it so the claim exits non-
            // zero. A stream that breaks *after* the fork was finalized
            // (e.g. during prefetch warm-up) is already reported as success
            // by `claim_attach_by_name`.
            coord.claim_attach_by_name(name, &mut stderr).map(|_| ())
        }
    }
}

/// Install a process-wide Ctrl-C handler for prefetch waits.
///
/// The handler prints a "continuing in background" message tagged with
/// `label` (e.g. `"[claim]"`, `"[start]"`) and exits 130 (sigint
/// convention). The coordinator's prefetch task is server-side and
/// runs to completion regardless; this handler only signals that the
/// CLI subscriber has gone away.
fn install_prefetch_ctrlc_handler(name: &str, label: &'static str) {
    let name_for_ctrlc = name.to_owned();
    ctrlc::set_handler(move || {
        eprintln!(
            "\n{label} prefetch continuing in background for {name_for_ctrlc}; \
             coordinator will report completion in its log"
        );
        std::process::exit(130);
    })
    .ok();
}

/// Resolve a local volume name to its ULID by reading the
/// `by_name/<name>` symlink. Returns `None` if the symlink is absent,
/// is broken, or points to a non-ULID directory.
fn resolve_local_volume_ulid(data_dir: &Path, name: &str) -> Option<String> {
    let symlink = data_dir.join("by_name").join(name);
    let target = std::fs::read_link(&symlink).ok()?;
    let last = target.file_name().and_then(|n| n.to_str())?;
    // Parse-don't-validate: round-trip through the ULID type so the
    // returned string is canonical.
    Some(ulid::Ulid::from_string(last).ok()?.to_string())
}

/// Resolve the fetch config for a volume subprocess (`serve-volume`).
///
/// The coordinator exports `ELIDE_COORDINATOR_SOCKET` into each spawned
/// volume's environment. When set, we pull store config from the
/// coordinator over IPC and authenticate to its credential vending via
/// the macaroon handshake (`register` then `credentials`). The volume
/// ULID is the fork directory's basename. When the env var is unset
/// (standalone `elide serve-volume` invocation with no coordinator),
/// fall back to `FetchConfig::load` from the volume directory.
fn resolve_volume_fetch_config(fork_dir: &Path) -> std::io::Result<VolumeFetchInputs> {
    if let Ok(sock) = std::env::var("ELIDE_COORDINATOR_SOCKET") {
        let coord = coordinator_client::Client::new(&sock);
        let volume_ulid = elide_fetch::derive_volume_id(fork_dir)?;
        if let Some(inputs) = fetch_config_via_coordinator_macaroon(&coord, &volume_ulid)? {
            return Ok(inputs);
        }
    }
    let fetch_config = elide_fetch::FetchConfig::load(fork_dir)?;
    // Standalone fallback (no coordinator): if the resolved config is
    // S3 mode, source credentials directly from this process's env
    // once at startup. The volume binary itself never reads `AWS_*`
    // anywhere else. No re-issue path — these creds live for the life
    // of the process.
    let creds = match fetch_config.as_ref() {
        Some(cfg) if cfg.bucket.is_some() => Some(s3_creds_from_env()?),
        _ => None,
    };
    Ok(VolumeFetchInputs {
        fetch_config,
        creds,
        reissue: None,
        peer_endpoint: None,
    })
}

/// Read S3 credentials from the volume process's own env. Used only
/// in the standalone (no-coordinator) path of
/// [`resolve_volume_fetch_config`]; the coordinator-spawned path
/// receives creds over IPC and never touches env.
fn s3_creds_from_env() -> std::io::Result<elide_fetch::S3Credentials> {
    let access_key_id = std::env::var("AWS_ACCESS_KEY_ID").map_err(|_| {
        std::io::Error::other(
            "S3 fetch config but AWS_ACCESS_KEY_ID is unset; \
             set it (and AWS_SECRET_ACCESS_KEY) or run under a coordinator",
        )
    })?;
    let secret_access_key = std::env::var("AWS_SECRET_ACCESS_KEY")
        .map_err(|_| std::io::Error::other("S3 fetch config but AWS_SECRET_ACCESS_KEY is unset"))?;
    let session_token = std::env::var("AWS_SESSION_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    Ok(elide_fetch::S3Credentials {
        access_key_id,
        secret_access_key,
        session_token,
    })
}

/// Pull store config + macaroon-scoped S3 credentials from the
/// coordinator over IPC. The CLI itself never holds raw S3 credentials
/// — only spawned volume subprocesses can authenticate (PID-bound via
/// SO_PEERCRED) and obtain creds for demand-fetch.
///
/// The coordinator's [`coordinator_client::RegisterReply`] also carries
/// the discovered peer-fetch endpoint for the volume's previous
/// claimer (when peer-fetch is configured and a clean handoff is in
/// the event log); it is returned alongside the fetch config so the
/// daemon can stack a peer body byte-range fetcher in front of S3.
fn fetch_config_via_coordinator_macaroon(
    coord: &coordinator_client::Client,
    volume_ulid: &str,
) -> std::io::Result<Option<VolumeFetchInputs>> {
    if !coord.socket_path().exists() {
        return Ok(None);
    }
    let config = match coord.get_store_config() {
        Ok(c) => c,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    if let Some(path) = config.local_path {
        return Ok(Some(VolumeFetchInputs {
            fetch_config: Some(elide_fetch::FetchConfig {
                bucket: None,
                endpoint: None,
                region: None,
                local_path: Some(path),
                fetch_batch_bytes: None,
            }),
            creds: None,
            reissue: None,
            peer_endpoint: None,
        }));
    }
    let Some(bucket) = config.bucket else {
        return Err(std::io::Error::other(
            "coordinator returned empty store config",
        ));
    };
    // Register only — do not request credentials. The lazy-creds
    // wrapper will issue a `Credentials` IPC the first time the
    // volume actually needs to talk to S3.
    let registered = coord.register_volume_with_retry(volume_ulid)?;
    let reissue = elide::CredsReissue {
        coordinator_socket: coord.socket_path().to_path_buf(),
        macaroon: registered.macaroon,
    };
    Ok(Some(VolumeFetchInputs {
        fetch_config: Some(elide_fetch::FetchConfig {
            bucket: Some(bucket),
            endpoint: config.endpoint,
            region: config.region,
            local_path: None,
            fetch_batch_bytes: None,
        }),
        creds: None,
        reissue: Some(reissue),
        peer_endpoint: registered.peer_endpoint,
    }))
}

/// Pretty-print a `StatusRemoteReply` for `elide volume status --remote`.
fn print_volume_events(reply: &coordinator_client::VolumeEventsReply) {
    use coordinator_client::SignatureStatus;
    use elide_core::volume_event::EventKind;

    if reply.events.is_empty() {
        println!("(no events)");
        return;
    }

    for entry in &reply.events {
        let ev = &entry.event;
        // Sigil column: a single character, padded to width 1, so the
        // log lines stay aligned. Empty for valid signatures keeps
        // the common case visually quiet.
        let sigil = match &entry.signature_status {
            SignatureStatus::Valid => ' ',
            SignatureStatus::Invalid { .. } => '!',
            SignatureStatus::KeyUnavailable { .. } => '?',
            SignatureStatus::Missing => '-',
            SignatureStatus::Unparseable => '~',
        };
        let when = ev.at.format("%Y-%m-%d %H:%M:%SZ");
        let kind_label = ev.kind.as_str();
        let coord = &ev.coordinator_id;
        let vol = ev.vol_ulid;
        // `on=<hostname>` only when the event recorded one. Old
        // events from before this field landed render without it
        // rather than with `on=<unknown>` clutter.
        let host = match ev.hostname.as_deref() {
            Some(h) => format!(" on={h}"),
            None => String::new(),
        };
        let extra = match &ev.kind {
            EventKind::Created | EventKind::Claimed => String::new(),
            EventKind::Released { handoff_snapshot } => {
                format!(" handoff={handoff_snapshot}")
            }
            EventKind::ForceClaimed {
                source_vol_ulid,
                displaced_coordinator_id,
            } => match displaced_coordinator_id {
                Some(d) => format!(" source={source_vol_ulid} displaced={d}"),
                None => format!(" source={source_vol_ulid}"),
            },
            EventKind::ForkedFrom {
                source_name,
                source_vol_ulid,
                source_snap_ulid,
            } => {
                format!(" source={source_name}@{source_vol_ulid}/{source_snap_ulid}")
            }
            EventKind::RenamedTo { new_name } => format!(" to={new_name}"),
            EventKind::RenamedFrom {
                old_name,
                inherits_log_from,
            } => {
                format!(" from={old_name} inherits={inherits_log_from}")
            }
            EventKind::Displaced {
                source_name,
                source_fork,
                displaced_by,
            } => match displaced_by {
                Some(d) => format!(" source={source_name}@{source_fork} displaced-by={d}"),
                None => format!(" source={source_name}@{source_fork}"),
            },
            EventKind::Superseded {
                source_name,
                source_fork,
                superseded_by,
            } => match superseded_by {
                Some(d) => format!(" source={source_name}@{source_fork} superseded-by={d}"),
                None => format!(" source={source_name}@{source_fork}"),
            },
            EventKind::Unknown { original_kind } => match original_kind {
                Some(k) => format!(" unparseable was={k}"),
                None => " unparseable".to_owned(),
            },
        };
        println!("{sigil} {when}  {kind_label:<14} vol={vol}  by={coord}{host}{extra}");
    }

    // Footer: any non-Valid statuses get explained, so the operator
    // sees the failure reason without re-running with --json.
    let mut had_explanation = false;
    for entry in &reply.events {
        let reason = match &entry.signature_status {
            SignatureStatus::Valid => continue,
            SignatureStatus::Invalid { reason } => format!("invalid: {reason}"),
            SignatureStatus::KeyUnavailable { reason } => {
                format!("key unavailable: {reason}")
            }
            SignatureStatus::Missing => "no signature on event".to_string(),
            SignatureStatus::Unparseable => "unparseable kind — signature not checked".to_string(),
        };
        if !had_explanation {
            println!();
            had_explanation = true;
        }
        println!("  {} {}", entry.event.event_ulid, reason);
    }
}

fn print_remote_status(name: &str, rs: &coordinator_client::StatusRemoteReply) {
    println!("{name}");
    println!("  state           {}", rs.state);
    println!("  vol_ulid        {}", rs.vol_ulid);
    if let Some(id) = &rs.coordinator_id {
        println!("  coordinator_id  {id}");
    }
    if let Some(host) = &rs.hostname {
        println!("  hostname        {host}");
    }
    if let Some(when) = &rs.claimed_at {
        println!("  claimed_at      {when}");
    }
    if let Some(parent) = &rs.parent {
        println!("  parent          {parent}");
    }
    if let Some(snap) = &rs.handoff_snapshot {
        println!("  handoff_snap    {snap}");
    }
    println!("  eligibility     {}", rs.eligibility.wire_str());
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn parse_fork_source_pinned_ulid() {
        let vol = ulid::Ulid::new();
        let snap = ulid::Ulid::new();
        let src = parse_fork_source(&format!("{vol}/{snap}")).unwrap();
        assert_eq!(
            src,
            coordinator_client::ForkSource::Pinned {
                vol_ulid: vol,
                snap_ulid: snap
            }
        );
    }

    #[test]
    fn parse_fork_source_pinned_name() {
        let snap = ulid::Ulid::new();
        let src = parse_fork_source(&format!("base/{snap}")).unwrap();
        assert_eq!(
            src,
            coordinator_client::ForkSource::PinnedName {
                name: "base".to_owned(),
                snap_ulid: snap
            }
        );
    }

    #[test]
    fn parse_fork_source_name() {
        let src = parse_fork_source("base").unwrap();
        assert_eq!(
            src,
            coordinator_client::ForkSource::Name {
                name: "base".to_owned()
            }
        );
    }

    #[test]
    fn parse_fork_source_rejects_bare_ulid() {
        let vol = ulid::Ulid::new();
        let err = parse_fork_source(&vol.to_string()).expect_err("bare ULID must refuse");
        assert!(err.to_string().contains("snapshot pin"), "{err}");
    }

    #[test]
    fn parse_fork_source_rejects_bad_snapshot_ulid() {
        let err = parse_fork_source("base/notaulid").expect_err("bad snap must refuse");
        assert!(err.to_string().contains("invalid snapshot ULID"), "{err}");
    }

    /// Build a minimal `<data_dir>/by_id/<ulid>/` skeleton plus a
    /// `by_name/<name>` symlink. Returns the data dir and vol_dir for
    /// the caller's assertions.
    fn make_volume_skeleton(name: &str) -> (TempDir, PathBuf) {
        let tmp = TempDir::new().unwrap();
        let by_id = tmp.path().join("by_id");
        let by_name = tmp.path().join("by_name");
        std::fs::create_dir_all(&by_id).unwrap();
        std::fs::create_dir_all(&by_name).unwrap();
        let vol_ulid = ulid::Ulid::new();
        let vol_dir = by_id.join(vol_ulid.to_string());
        std::fs::create_dir_all(&vol_dir).unwrap();
        std::fs::create_dir_all(vol_dir.join("index")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            std::path::PathBuf::from(format!("../by_id/{vol_ulid}")),
            by_name.join(name),
        )
        .unwrap();
        (tmp, vol_dir)
    }

    #[test]
    fn stop_force_direct_writes_marker_when_no_pid() {
        let (data_dir, vol_dir) = make_volume_skeleton("vol");
        // No volume.pid → no SIGTERM, but marker still written.
        volume_stop_force_direct(data_dir.path(), "vol").unwrap();
        assert!(
            vol_dir.join("volume.stopped").exists(),
            "marker must be written even without a running daemon"
        );
    }

    #[test]
    fn stop_force_direct_idempotent_when_already_stopped() {
        let (data_dir, vol_dir) = make_volume_skeleton("vol");
        // Pre-existing marker.
        std::fs::write(vol_dir.join("volume.stopped"), "").unwrap();
        // Should succeed without touching anything.
        volume_stop_force_direct(data_dir.path(), "vol").unwrap();
        assert!(vol_dir.join("volume.stopped").exists());
    }

    #[test]
    fn stop_force_direct_errors_on_unknown_name() {
        let (data_dir, _) = make_volume_skeleton("vol");
        let err = volume_stop_force_direct(data_dir.path(), "ghost")
            .expect_err("unknown name must error");
        assert!(err.to_string().contains("volume not found: ghost"), "{err}");
    }

    #[test]
    fn stop_force_direct_ignores_stale_pid_file() {
        let (data_dir, vol_dir) = make_volume_skeleton("vol");
        // Write a pid that's vanishingly unlikely to be alive (kernel
        // pid_max defaults to 4194304 but reuse-after-reboot is real;
        // use a very large value to avoid hitting an unrelated
        // process). pid_is_alive returns false → no SIGTERM attempt.
        std::fs::write(vol_dir.join("volume.pid"), "99999999").unwrap();
        volume_stop_force_direct(data_dir.path(), "vol").unwrap();
        assert!(vol_dir.join("volume.stopped").exists());
    }
}
