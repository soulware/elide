//! ublk transport (Linux userspace block device).
//!
//! Step-2: multi-queue at depth 1, synchronous handler per queue. Each queue
//! thread runs libublk's sync `wait_and_handle_io` loop; the I/O closure
//! dispatches directly to the per-thread `VolumeReader`. Concurrency comes
//! from `nr_hw_queues = min(num_cpus, 4)` — each queue runs independently on
//! its own thread with its own reader, so a slow backend call on one queue
//! does not stall the others.
//!
//! **Why depth stays at 1 here.** A naive "depth > 1 with `blocking::unblock`
//! offload" plan deadlocks: the `blocking` crate wakes futures on its own
//! thread pool, but that wake cannot interrupt `io_uring::submit_and_wait`,
//! so the queue thread sleeps on the ring until a kernel event or the ring's
//! idle timeout fires. A correct depth > 1 implementation needs either a
//! uring-registered eventfd wired into the async waker path, or a worker-
//! pool model that submits completion SQEs from the workers. That is
//! step 2b; see docs/design-ublk-transport.md.
//!
//! `UBLK_F_USER_RECOVERY_REISSUE` and zero-copy (`UBLK_F_AUTO_BUF_REG`) are
//! follow-up steps. See docs/design-ublk-transport.md.
//!
//! On non-Linux targets, and on Linux without the `ublk` cargo feature, this
//! module compiles to a stub that errors when the transport is invoked.

use std::io;
use std::path::Path;

#[cfg(all(target_os = "linux", feature = "ublk"))]
mod imp {
    use std::io;
    use std::num::NonZeroUsize;
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::Arc;

    use libublk::BufDesc;
    use libublk::UblkFlags;
    use libublk::UblkIORes;
    use libublk::ctrl::{UblkCtrl, UblkCtrlBuilder, ublk_init_ctrl_task_ring};
    use libublk::io::{BufDescList, UblkDev, UblkIOCtx, UblkQueue};

    use elide_core::actor::{VolumeClient, VolumeReader};
    use elide_core::volume::Volume;

    const BLOCK: u64 = 4096;
    const LOGICAL_BS_SHIFT: u8 = 12;
    const PHYSICAL_BS_SHIFT: u8 = 12;
    const IO_MIN_SHIFT: u8 = 12;
    const IO_OPT_SHIFT: u8 = 12;

    /// Per-I/O buffer size. Caps the largest single request the kernel will
    /// issue to userspace. 1 MiB matches the step-1 spike and comfortably
    /// covers typical blk-mq dispatch sizes (max_sectors_kb is usually
    /// 512–1280).
    const IO_BUF_BYTES: u32 = 1 << 20;

    /// In-flight requests per queue. Held at 1 until the async + waker
    /// integration is built (step 2b). See module-level comment.
    const QUEUE_DEPTH: u16 = 1;

    /// Upper bound on queue count. With blk-mq one queue per CPU is ideal for
    /// locality; capped so tiny hosts do not pay for idle queues.
    const MAX_QUEUES: u16 = 4;

    const UBLK_IO_OP_READ: u32 = libublk::sys::UBLK_IO_OP_READ;
    const UBLK_IO_OP_WRITE: u32 = libublk::sys::UBLK_IO_OP_WRITE;
    const UBLK_IO_OP_FLUSH: u32 = libublk::sys::UBLK_IO_OP_FLUSH;
    const UBLK_IO_OP_DISCARD: u32 = libublk::sys::UBLK_IO_OP_DISCARD;
    const UBLK_IO_OP_WRITE_ZEROES: u32 = libublk::sys::UBLK_IO_OP_WRITE_ZEROES;

    pub fn run_volume_ublk(
        dir: &Path,
        size_bytes: u64,
        fetch_config: Option<elide_fetch::FetchConfig>,
        dev_id: Option<i32>,
    ) -> io::Result<()> {
        let by_id_dir = dir.parent().unwrap_or(dir);
        let mut volume = Volume::open(dir, by_id_dir)?;

        if let Some(config) = fetch_config {
            let fetcher = elide_fetch::RemoteFetcher::new(&config, &volume.fork_dirs())?;
            volume.set_fetcher(Arc::new(fetcher));
            println!("[demand-fetch enabled]");
        }

        let (actor, client) = elide_core::actor::spawn(volume);
        let _actor_thread = std::thread::Builder::new()
            .name("volume-actor".into())
            .spawn(move || actor.run())
            .map_err(io::Error::other)?;

        let connected = Arc::new(std::sync::atomic::AtomicBool::new(false));
        crate::control::start(dir, client.clone(), Arc::clone(&connected))?;

        let nr_queues = pick_nr_queues();

        let ctrl = Arc::new(
            UblkCtrlBuilder::default()
                .name("elide")
                .id(dev_id.unwrap_or(-1))
                .nr_queues(nr_queues)
                .depth(QUEUE_DEPTH)
                .io_buf_bytes(IO_BUF_BYTES)
                .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
                .build()
                .map_err(|e| io::Error::other(format!("ublk ctrl build: {e}")))?,
        );

        // Break run_target out of its queue-thread join on SIGINT/SIGTERM/SIGHUP.
        // kill_dev() is the libublk-recommended safe path from outside the
        // target callbacks; it triggers STOP_DEV, which causes the queue
        // threads to exit and run_target to return, after which we issue a
        // DEL_DEV so the device does not accumulate across serve restarts.
        //
        // kill_dev uses the *calling thread's* thread-local control ring,
        // which ctrlc's signal thread has not initialized. Set it up on
        // first signal delivery before issuing the ioctl, otherwise
        // kill_dev() panics with "Control ring not initialized".
        //
        // Ignore an error from set_handler: another signal handler being
        // installed already (e.g. in test) should not fail the serve.
        {
            let ctrl_sig = Arc::clone(&ctrl);
            let _ = ctrlc::set_handler(move || {
                if let Err(e) = ublk_init_ctrl_task_ring(|opt| {
                    if opt.is_none() {
                        *opt = Some(
                            io_uring::IoUring::<io_uring::squeue::Entry128>::builder()
                                .build(32)
                                .map_err(libublk::UblkError::IOError)?,
                        );
                    }
                    Ok(())
                }) {
                    tracing::error!("ublk signal-thread ctrl ring init failed: {e}");
                    return;
                }
                if let Err(e) = ctrl_sig.kill_dev() {
                    tracing::error!("ublk kill_dev on signal failed: {e}");
                }
            });
        }

        let tgt_init = move |dev: &mut UblkDev| {
            set_params(dev, size_bytes);
            Ok(())
        };

        // VolumeClient is Send + Sync + Clone, so it satisfies run_target's
        // queue-handler bound directly. Each queue thread constructs its own
        // VolumeReader (Send, !Sync) on entry.
        let q_handler = {
            let client = client.clone();
            move |qid, dev: &UblkDev| {
                q_fn(qid, dev, client.reader());
            }
        };

        let wait_hook = move |d_ctrl: &UblkCtrl| {
            d_ctrl.dump();
            println!(
                "[ublk device ready: /dev/ublkb{}]",
                d_ctrl.dev_info().dev_id
            );
        };

        let run_result = ctrl
            .run_target(tgt_init, q_handler, wait_hook)
            .map_err(|e| io::Error::other(format!("ublk run_target: {e}")));

        // Always attempt DEL_DEV so the kernel-side device does not linger
        // after the daemon exits. run_target's internal stop_dev only stops
        // the device; without del_dev the entry stays in /sys/class/ublk-char
        // and the dev_id cannot be reused. ENOENT is expected if the device
        // was already removed out-of-band.
        if let Err(e) = ctrl.del_dev() {
            tracing::debug!("ublk del_dev on shutdown returned: {e}");
        }

        run_result?;
        Ok(())
    }

    fn pick_nr_queues() -> u16 {
        let cpus = std::thread::available_parallelism()
            .map(NonZeroUsize::get)
            .unwrap_or(1);
        let clamped = cpus.min(MAX_QUEUES as usize).max(1);
        clamped as u16
    }

    /// Populate device params so the kernel issues only 4K-aligned I/O and
    /// advertises DISCARD / WRITE_ZEROES support to the blk-mq layer.
    fn set_params(dev: &mut UblkDev, size_bytes: u64) {
        let tgt = &mut dev.tgt;
        tgt.dev_size = size_bytes;
        tgt.params = libublk::sys::ublk_params {
            types: libublk::sys::UBLK_PARAM_TYPE_BASIC | libublk::sys::UBLK_PARAM_TYPE_DISCARD,
            basic: libublk::sys::ublk_param_basic {
                logical_bs_shift: LOGICAL_BS_SHIFT,
                physical_bs_shift: PHYSICAL_BS_SHIFT,
                io_opt_shift: IO_OPT_SHIFT,
                io_min_shift: IO_MIN_SHIFT,
                max_sectors: dev.dev_info.max_io_buf_bytes >> 9,
                dev_sectors: size_bytes >> 9,
                ..Default::default()
            },
            discard: libublk::sys::ublk_param_discard {
                discard_alignment: 0,
                discard_granularity: BLOCK as u32,
                max_discard_sectors: u32::MAX,
                max_write_zeroes_sectors: u32::MAX,
                max_discard_segments: 1,
                ..Default::default()
            },
            ..Default::default()
        };
    }

    /// Per-queue entry point. Runs on a dedicated thread spawned by libublk's
    /// `run_target`. At depth 1 the synchronous `wait_and_handle_io` loop is
    /// sufficient; concurrency across queues comes from multiple queue
    /// threads running this function independently.
    fn q_fn(qid: u16, dev: &UblkDev, reader: VolumeReader) {
        let bufs_rc = Rc::new(dev.alloc_queue_io_bufs());
        let bufs = bufs_rc.clone();

        let io_handler = move |q: &UblkQueue, tag: u16, _io: &UblkIOCtx| {
            let iod = q.get_iod(tag);
            let op = iod.op_flags & 0xff;
            let off = (iod.start_sector << 9) as u64;
            let bytes = (iod.nr_sectors << 9) as u32;

            let iob = &bufs[tag as usize];
            let reg_slice = iob.as_slice();
            // SAFETY: each tag owns a unique IoBuf allocation. The sync
            // handler is called serially per tag with no concurrent access,
            // and the kernel has already copied WRITE payload into the buffer
            // by the time the handler runs. libublk's own loop.rs example
            // does the same `as_ptr() as *mut u8` cast.
            let slice: &mut [u8] = unsafe {
                std::slice::from_raw_parts_mut(reg_slice.as_ptr() as *mut u8, reg_slice.len())
            };

            let res = if (bytes as usize) <= slice.len() {
                dispatch(&reader, op, off, bytes, &mut slice[..bytes as usize])
            } else {
                -libc::EINVAL
            };

            if let Err(e) = q.complete_io_cmd_unified(
                tag,
                BufDesc::Slice(reg_slice),
                Ok(UblkIORes::Result(res)),
            ) {
                tracing::error!("ublk complete_io_cmd_unified failed: {e}");
            }
        };

        let queue = match UblkQueue::new(qid, dev)
            .and_then(|q| q.submit_fetch_commands_unified(BufDescList::Slices(Some(&bufs_rc))))
        {
            Ok(q) => q,
            Err(e) => {
                tracing::error!("ublk queue {qid} setup failed: {e}");
                return;
            }
        };

        queue.wait_and_handle_io(io_handler);
    }

    /// Translate one ublk I/O into a `VolumeReader` / `VolumeClient` call.
    /// Returns the kernel completion status: bytes on success, negative errno
    /// on failure.
    fn dispatch(reader: &VolumeReader, op: u32, offset: u64, length: u32, buf: &mut [u8]) -> i32 {
        // ublk SET_PARAMS pinned logical_bs_shift=12, so offset and length
        // are always 4K-aligned — no RMW path needed.
        debug_assert!(offset.is_multiple_of(BLOCK));
        debug_assert!((length as u64).is_multiple_of(BLOCK));

        let start_lba = offset / BLOCK;
        let lba_count = (length as u64 / BLOCK) as u32;

        match op {
            UBLK_IO_OP_READ => match reader.read(start_lba, lba_count) {
                Ok(data) => {
                    let len = data.len().min(length as usize);
                    buf[..len].copy_from_slice(&data[..len]);
                    len as i32
                }
                Err(e) => {
                    tracing::error!("[ublk read error offset={offset} len={length}: {e}]");
                    -libc::EIO
                }
            },
            UBLK_IO_OP_WRITE => {
                let data = buf[..length as usize].to_vec();
                match reader.write(start_lba, data) {
                    Ok(()) => length as i32,
                    Err(e) => {
                        tracing::error!("[ublk write error offset={offset} len={length}: {e}]");
                        -libc::EIO
                    }
                }
            }
            UBLK_IO_OP_FLUSH => match reader.flush() {
                Ok(()) => 0,
                Err(e) => {
                    tracing::error!("[ublk flush error: {e}]");
                    -libc::EIO
                }
            },
            UBLK_IO_OP_DISCARD => match reader.trim(start_lba, lba_count) {
                Ok(()) => length as i32,
                Err(e) => {
                    tracing::error!("[ublk discard error offset={offset} len={length}: {e}]");
                    -libc::EIO
                }
            },
            UBLK_IO_OP_WRITE_ZEROES => match reader.write_zeroes(start_lba, lba_count) {
                Ok(()) => length as i32,
                Err(e) => {
                    tracing::error!("[ublk write-zeroes error offset={offset} len={length}: {e}]");
                    -libc::EIO
                }
            },
            _ => -libc::EINVAL,
        }
    }

    pub fn list_devices() -> io::Result<()> {
        use libublk::ctrl::UblkCtrl;

        let ids = scan_dev_ids()?;
        if ids.is_empty() {
            println!("no ublk devices");
            return Ok(());
        }
        for id in ids {
            match UblkCtrl::new_simple(id) {
                Ok(ctrl) => ctrl.dump(),
                Err(e) => eprintln!("ublk{id}: failed to open ctrl: {e}"),
            }
        }
        Ok(())
    }

    pub fn delete_device(id: i32) -> io::Result<()> {
        use libublk::ctrl::UblkCtrl;

        let ctrl = UblkCtrl::new_simple(id)
            .map_err(|e| io::Error::other(format!("open ctrl for dev {id}: {e}")))?;
        // kill_dev is the documented safe-from-anywhere stop; del_dev then
        // removes the kernel entry and libublk's json file.
        let _ = ctrl.kill_dev();
        ctrl.del_dev()
            .map_err(|e| io::Error::other(format!("del_dev {id}: {e}")))?;
        println!("deleted ublk device {id}");
        Ok(())
    }

    pub fn delete_all_devices() -> io::Result<()> {
        let ids = scan_dev_ids()?;
        if ids.is_empty() {
            println!("no ublk devices");
            return Ok(());
        }
        for id in ids {
            if let Err(e) = delete_device(id) {
                eprintln!("ublk{id}: {e}");
            }
        }
        Ok(())
    }

    /// Scan `/sys/class/ublk-char` for `ublkcN` entries and return the ids.
    /// This mirrors what `libublk::ctrl::UblkCtrl::for_each_dev_id` does
    /// internally, but without its `Fn + Clone + 'static` closure bound that
    /// prevents borrowing mutable state.
    fn scan_dev_ids() -> io::Result<Vec<i32>> {
        let mut ids = Vec::new();
        let entries = match std::fs::read_dir("/sys/class/ublk-char") {
            Ok(d) => d,
            // Missing directory means no devices / module not loaded.
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(ids),
            Err(e) => return Err(e),
        };
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str()
                && let Some(rest) = name.strip_prefix("ublkc")
                && let Ok(id) = rest.parse::<i32>()
            {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }
}

#[cfg(not(all(target_os = "linux", feature = "ublk")))]
mod imp {
    use std::io;
    use std::path::Path;

    pub fn run_volume_ublk(
        _dir: &Path,
        _size_bytes: u64,
        _fetch_config: Option<elide_fetch::FetchConfig>,
        _dev_id: Option<i32>,
    ) -> io::Result<()> {
        Err(stub_err())
    }

    pub fn list_devices() -> io::Result<()> {
        Err(stub_err())
    }

    pub fn delete_device(_id: i32) -> io::Result<()> {
        Err(stub_err())
    }

    pub fn delete_all_devices() -> io::Result<()> {
        Err(stub_err())
    }

    fn stub_err() -> io::Error {
        io::Error::other("ublk transport requires Linux and the 'ublk' cargo feature")
    }
}

/// Serve a volume over ublk. Creates `/dev/ublkbN` and runs the I/O loop.
///
/// Step-2: multi-queue (up to 4) at queue_depth = 1 with a sync handler.
/// `dev_id = None` lets the kernel auto-allocate. See
/// docs/design-ublk-transport.md for why depth stays at 1 pending step 2b.
pub fn run_volume_ublk(
    dir: &Path,
    size_bytes: u64,
    fetch_config: Option<elide_fetch::FetchConfig>,
    dev_id: Option<i32>,
) -> io::Result<()> {
    imp::run_volume_ublk(dir, size_bytes, fetch_config, dev_id)
}

/// List ublk devices known to the kernel (reads `/sys/class/ublk-char`).
pub fn list_devices() -> io::Result<()> {
    imp::list_devices()
}

/// Delete a single ublk device by id. Stops it first (safe even if already
/// stopped) and then removes the kernel entry and libublk's json file.
pub fn delete_device(id: i32) -> io::Result<()> {
    imp::delete_device(id)
}

/// Delete every ublk device found in `/sys/class/ublk-char`.
pub fn delete_all_devices() -> io::Result<()> {
    imp::delete_all_devices()
}
