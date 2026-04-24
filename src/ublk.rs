//! ublk transport (Linux userspace block device).
//!
//! Each queue runs a `smol::LocalExecutor` pinned to one thread (libublk
//! spawns one thread per queue). The executor hosts `depth` per-tag async
//! tasks; each task loops FETCH → dispatch → COMMIT. Backend calls into
//! `VolumeClient` are synchronous, so they go through `blocking::unblock` to
//! run on smol's thread pool — letting the queue's executor progress other
//! tags while one is waiting on the actor mailbox / WAL / a segment read.
//!
//! `VolumeClient` is `Send + Sync + Clone`: each tag's async task holds its
//! own clone, and the shared volume-level file cache lives behind it, so
//! concurrent reads across tags resolve against one hot set of open segment
//! FDs rather than per-tag duplicates.
//!
//! See docs/design-ublk-transport.md for the phased rollout.
//!
//! On non-Linux targets, and on Linux without the `ublk` cargo feature, this
//! module compiles to a stub that errors when the transport is invoked.

use std::io;
use std::path::Path;

#[cfg(all(target_os = "linux", feature = "ublk"))]
mod imp {
    use std::io;
    use std::path::Path;
    use std::rc::Rc;
    use std::sync::Arc;

    use libublk::BufDesc;
    use libublk::UblkError;
    use libublk::UblkFlags;
    use libublk::ctrl::{UblkCtrl, UblkCtrlBuilder};
    use libublk::helpers::IoBuf;
    use libublk::io::{UblkDev, UblkQueue};

    use elide_core::actor::VolumeClient;
    use elide_core::volume::Volume;

    const BLOCK: u64 = 4096;
    const LOGICAL_BS_SHIFT: u8 = 12;
    const PHYSICAL_BS_SHIFT: u8 = 12;
    const IO_MIN_SHIFT: u8 = 12;
    const IO_OPT_SHIFT: u8 = 12;

    /// Step 2 starting point per design doc: multi-queue, depth 64, 1 MiB
    /// buffer. Tuned further after fio on a real host.
    const MAX_QUEUES: usize = 4;
    const QUEUE_DEPTH: u16 = 64;
    const IO_BUF_BYTES: u32 = 1 << 20;

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

        let nr_queues: u16 = std::thread::available_parallelism()
            .map(|n| n.get().min(MAX_QUEUES))
            .unwrap_or(1)
            .try_into()
            .unwrap_or(1);

        let ctrl = UblkCtrlBuilder::default()
            .name("elide")
            .id(dev_id.unwrap_or(-1))
            .nr_queues(nr_queues)
            .depth(QUEUE_DEPTH)
            .io_buf_bytes(IO_BUF_BYTES)
            .dev_flags(UblkFlags::UBLK_DEV_F_ADD_DEV)
            .build()
            .map_err(|e| io::Error::other(format!("ublk ctrl build: {e}")))?;

        let tgt_init = move |dev: &mut UblkDev| {
            set_params(dev, size_bytes);
            Ok(())
        };

        // `VolumeClient` is Send + Sync + Clone; libublk hands a clone to each
        // queue thread where it is further cloned into per-tag async tasks.
        let q_handler = move |qid, dev: &UblkDev| {
            queue_thread(qid, dev, client.clone());
        };

        let wait_hook = move |d_ctrl: &UblkCtrl| {
            d_ctrl.dump();
            println!(
                "[ublk device ready: /dev/ublkb{}]",
                d_ctrl.dev_info().dev_id
            );
        };

        ctrl.run_target(tgt_init, q_handler, wait_hook)
            .map_err(|e| io::Error::other(format!("ublk run_target: {e}")))?;

        Ok(())
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

    /// Entry point for libublk's queue thread. Builds a queue, a local
    /// executor, and one async task per tag; then drives the io_uring reactor.
    ///
    /// Based on the `q_a_fn` pattern in `libublk/examples/loop.rs`.
    fn queue_thread(qid: u16, dev: &UblkDev, client: VolumeClient) {
        let queue = match UblkQueue::new(qid, dev) {
            Ok(q) => Rc::new(q),
            Err(e) => {
                tracing::error!("[ublk queue {qid} setup failed: {e}]");
                return;
            }
        };
        let depth = dev.dev_info.queue_depth;
        let exec = Rc::new(smol::LocalExecutor::new());

        let mut tasks = Vec::with_capacity(depth as usize);
        for tag in 0..depth {
            let q = queue.clone();
            let c = client.clone();
            tasks.push(exec.spawn(async move {
                if let Err(e) = io_task(&q, tag, c).await {
                    if !matches!(e, UblkError::QueueIsDown) {
                        tracing::error!("[ublk io_task qid={qid} tag={tag} failed: {e}]");
                    }
                }
            }));
        }

        let run_ops = || while exec.try_tick() {};
        let done = || tasks.iter().all(|t| t.is_finished());

        smol::block_on(exec.run(async move {
            if let Err(e) =
                libublk::wait_and_handle_io_events(&queue, Some(20), run_ops, done).await
            {
                tracing::error!("[ublk wait_and_handle_io_events qid={qid}: {e}]");
            }
        }));
    }

    /// Per-tag async loop. Submits the initial FETCH, then repeats
    /// dispatch → COMMIT_AND_FETCH until the queue is torn down.
    async fn io_task(q: &UblkQueue<'_>, tag: u16, client: VolumeClient) -> Result<(), UblkError> {
        let buf_size = q.dev.dev_info.max_io_buf_bytes as usize;
        let mut buf = IoBuf::<u8>::new(buf_size);

        // Initial FETCH_REQ: tells the kernel "this tag is idle; send me the
        // next I/O". `submit_io_prep_cmd` also registers the IoBuf.
        q.submit_io_prep_cmd(tag, BufDesc::Slice(buf.as_slice()), 0, Some(&buf))
            .await?;

        loop {
            let iod = q.get_iod(tag);
            let op = iod.op_flags & 0xff;
            let off = (iod.start_sector << 9) as u64;
            let bytes = (iod.nr_sectors << 9) as u32;

            let res = run_dispatch(&client, op, off, bytes, &mut buf).await;

            // COMMIT_AND_FETCH_REQ: hand back the result for this tag and
            // await the next I/O in one round trip.
            q.submit_io_commit_cmd(tag, BufDesc::Slice(buf.as_slice()), res)
                .await?;
        }
    }

    /// Move the synchronous backend call onto smol's blocking thread pool so
    /// the queue's executor stays free to progress other tags. Result is the
    /// kernel completion status (bytes on success, negative errno on failure).
    async fn run_dispatch(
        client: &VolumeClient,
        op: u32,
        offset: u64,
        length: u32,
        buf: &mut IoBuf<u8>,
    ) -> i32 {
        // ublk SET_PARAMS pinned logical_bs_shift=12, so offset and length
        // are always 4K-aligned — no RMW path needed.
        debug_assert!(offset.is_multiple_of(BLOCK));
        debug_assert!((length as u64).is_multiple_of(BLOCK));

        if (length as usize) > buf.as_slice().len() {
            return -libc::EINVAL;
        }

        let start_lba = offset / BLOCK;
        let lba_count = (length as u64 / BLOCK) as u32;

        match op {
            UBLK_IO_OP_READ => {
                let client = client.clone();
                match blocking::unblock(move || client.read(start_lba, lba_count)).await {
                    Ok(data) => {
                        let len = data.len().min(length as usize);
                        let slice = unsafe {
                            std::slice::from_raw_parts_mut(
                                buf.as_slice().as_ptr() as *mut u8,
                                buf.as_slice().len(),
                            )
                        };
                        slice[..len].copy_from_slice(&data[..len]);
                        len as i32
                    }
                    Err(e) => {
                        tracing::error!("[ublk read error offset={offset} len={length}: {e}]");
                        -libc::EIO
                    }
                }
            }
            UBLK_IO_OP_WRITE => {
                // Copy the payload out of the shared IoBuf into an owned
                // Vec so the `blocking::unblock` closure (which must be
                // 'static) can take ownership.
                let data = buf.as_slice()[..length as usize].to_vec();
                let client = client.clone();
                match blocking::unblock(move || client.write(start_lba, data)).await {
                    Ok(()) => length as i32,
                    Err(e) => {
                        tracing::error!("[ublk write error offset={offset} len={length}: {e}]");
                        -libc::EIO
                    }
                }
            }
            UBLK_IO_OP_FLUSH => {
                let client = client.clone();
                match blocking::unblock(move || client.flush()).await {
                    Ok(()) => 0,
                    Err(e) => {
                        tracing::error!("[ublk flush error: {e}]");
                        -libc::EIO
                    }
                }
            }
            UBLK_IO_OP_DISCARD => {
                let client = client.clone();
                match blocking::unblock(move || client.trim(start_lba, lba_count)).await {
                    Ok(()) => length as i32,
                    Err(e) => {
                        tracing::error!("[ublk discard error offset={offset} len={length}: {e}]");
                        -libc::EIO
                    }
                }
            }
            UBLK_IO_OP_WRITE_ZEROES => {
                let client = client.clone();
                match blocking::unblock(move || client.write_zeroes(start_lba, lba_count)).await {
                    Ok(()) => length as i32,
                    Err(e) => {
                        tracing::error!(
                            "[ublk write-zeroes error offset={offset} len={length}: {e}]"
                        );
                        -libc::EIO
                    }
                }
            }
            _ => -libc::EINVAL,
        }
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
        Err(io::Error::other(
            "ublk transport requires Linux and the 'ublk' cargo feature",
        ))
    }
}

/// Serve a volume over ublk. Creates `/dev/ublkbN` and runs the I/O loop.
///
/// Multi-queue (up to 4) with queue depth 64 per step 2 of the design doc.
/// `dev_id = None` lets the kernel auto-allocate.
pub fn run_volume_ublk(
    dir: &Path,
    size_bytes: u64,
    fetch_config: Option<elide_fetch::FetchConfig>,
    dev_id: Option<i32>,
) -> io::Result<()> {
    imp::run_volume_ublk(dir, size_bytes, fetch_config, dev_id)
}
