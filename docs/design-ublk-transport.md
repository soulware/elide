# ublk as an alternative transport

Status: steps 1–2 landed. Multi-queue (up to 4) with queue depth 64 runs on
real Linux hosts behind the `ublk` cargo feature. Steps 3–5 pending; see
"Phased rollout" below.

## Framing

- ublk is a Linux userspace block device subsystem: kernel presents `/dev/ublkbN`, userspace daemon handles I/O over an `io_uring` passthrough channel on `/dev/ublkcN`.
- It is **host-side only**. From inside a VM we still need NBD (or vhost-user-blk).
- Goal: **ublk as preferred host-local transport; NBD stays for remote/VM**. Both first-class, not a replacement.
- **Transport is mutually exclusive per volume** — a writable volume is served on ublk *or* NBD, never both. Two transports would mean two independent page-cache views of the same backing data; serialising writes through `VolumeClient` doesn't prevent stale reads on the other side.
- **Explicit transport choice for now.** Working toward ublk-by-default on Linux hosts, but the coordinator will not auto-pick until the ublk path is proven.

## Why it's worth doing

- 2–4× IOPS vs `nbd-client` on loopback and lower tail latency (no TCP, no socket wakeup, no serialised reply framing).
- Guest sees a real blk-mq device — partitions, `blkdiscard`, `fstrim`, `O_DIRECT`, `BLKZEROOUT` all work.
- Zero-copy WRITE path (`UBLK_F_AUTO_BUF_REG`) lets guest pages flow into our hash/compress pipeline without a memcpy.
- Crash recovery (`UBLK_F_USER_RECOVERY_REISSUE`) pairs naturally with WAL idempotence + lowest-ULID-wins — a feature NBD cannot offer.

## Current NBD surface we need to match

All in `src/nbd.rs:handle_volume_connection` (src/nbd.rs:924). Every command maps 1:1 to a ublk op:

- `NBD_CMD_READ` → `UBLK_IO_OP_READ` → `VolumeReader::read`
- `NBD_CMD_WRITE` → `UBLK_IO_OP_WRITE` → `VolumeClient::write`
- `NBD_CMD_FLUSH` → `UBLK_IO_OP_FLUSH` → `VolumeClient::flush`
- `NBD_CMD_TRIM` → `UBLK_IO_OP_DISCARD` → `VolumeClient::trim`
- `NBD_CMD_WRITE_ZEROES` → `UBLK_IO_OP_WRITE_ZEROES` → `VolumeClient::write_zeroes`

The sub-4K RMW path (src/nbd.rs:1049) is NBD-only noise — ublk's `SET_PARAMS` pins logical block size to 4096 and the kernel won't issue sub-4K I/O.

## Architecture

- New module `src/ublk.rs` mirroring `src/nbd.rs` shape: `pub fn run_volume_ublk(dir, size_bytes, dev_id: Option<i32>) -> io::Result<()>`.
- Use `libublk` crate (Ming Lei — kernel maintainer; MIT/Apache; v0.4.x; active).
- One `io_uring` per queue, pinned to queue's affine CPU. Starting point: `nr_hw_queues = min(num_cpus, 4)`, `queue_depth = 64`, `max_io_buf_bytes = 1 MiB`. Tune later.
- I/O handler = thin adapter onto `VolumeClient`/`VolumeReader` — same shape as NBD transmission loop, different transport.
- **No shared transport trait up front.** Sockets vs io_uring + queue affinity are different enough that a trait is premature. Op dispatch is trivially the same; both call the client/reader directly.

## Async model

ublk's I/O transport is io_uring — async is inherent. But the async surface is **scoped to `src/ublk.rs`**; `VolumeClient` and the rest of the core stay synchronous.

**Shape (as implemented in step 2).** libublk-rs as designed — one `io_uring` per queue, `smol::LocalExecutor` per queue thread. For each tag, an async task loops: await FETCH_REQ, run the backend call, await COMMIT_AND_FETCH_REQ. Backend calls go through `blocking::unblock` (smol's thread-pool offload), so a stalled backend call on one tag does not block the queue's executor from progressing other tags. The actor serialises writes at its mailbox, so concurrent blocking calls from the smol pool just queue up — same shape as today's NBD-per-connection threading.

**Why not C (hand-rolled sync io_uring loop).** Considered and rejected:

- Performance delta vs libublk-rs is in the noise. Async overhead is tens of ns per I/O; backend path (actor hop, WAL, occasional S3 fetch) dominates by orders of magnitude. Both B and C need a thread-pool offload for the backend anyway.
- Strictly more complex: we'd own the UAPI bindings, the FETCH/COMMIT tag state machine, the control-plane ioctl shapes, and the cost of tracking kernel protocol evolution (batched I/O, auto-buf-reg, new recovery modes). libublk-rs is maintained by the ublk driver's author.
- At `queue_depth > 1` with a thread-pool backend, we'd reinvent async by hand anyway.
- Escape hatch if libublk-rs is ever abandoned, not a starting point.

**Runtime coexistence.** libublk-rs uses `smol`; we already use `tokio` in the coordinator. No conflict — smol here is a thread-local executor, not a global runtime.

**Handle Send/Sync shape.** The transport boundary uses one type:

- `VolumeClient` (Send+Sync+Clone): mailbox channel, atomic snapshot pointer, immutable config, and a shared volume-level file-FD cache (`Arc<Mutex<FileCache>>`) + shared flush-generation counter. All read/write/flush methods live here. No per-thread state.

Each queue thread captures a `VolumeClient` by clone; each tag's async task captures its own clone from that, and moves it through `blocking::unblock` closures. The shared cache holds ~16 segment FDs total per volume, regardless of queue count or depth — `pread(2)` lets concurrent readers share an `Arc<File>` safely, and the mutex is held only for the lookup/insert. (An earlier iteration split this into a separate `VolumeReader` per worker thread with its own `RefCell`-protected cache, but the per-thread split inflated FD count without measurably improving hit rate: all readers on a volume see the same workload and converge on the same hot set. PR #107 added the split as step-2 prep; step 2 removed it in favour of the volume-scoped design.)

## Control plane

- Lifecycle: `ADD_DEV` → `SET_PARAMS` → `START_DEV` → run → `STOP_DEV` → `DEL_DEV`.
- Add `UblkConfig { dev_id: Option<i32> }` in `elide-core/src/config.rs` alongside `NbdConfig`. `ublk` and `nbd` sections are mutually exclusive in `volume.toml`; config parse rejects both being set.
- CLI: `--ublk` / `--ublk-id N`, conflicts with `--nbd-port` / `--nbd-socket` in clap.
- Conflict detection: `find_nbd_conflict` grows a `find_ublk_conflict` checking `dev_id`.
- Coordinator supervision unchanged: spawn `elide serve ... --ublk-id N`, respawn on crash.

## Crash recovery

- `UBLK_F_USER_RECOVERY_REISSUE`: kernel holds in-flight I/O across a daemon restart and re-issues to the new daemon.
- Safe because WAL + lowest-ULID-wins already handles duplicate writes (same LBA, same or newer ULID — idempotent).
- **Enabled by default.** Crash → coordinator respawns → kernel reissues → clean recovery. NBD cannot do this.
- Paired with a crash-injection test in the rollout (step 3) to validate before we rely on it operationally.

## Dependencies & platform gating

- Linux-only. New `libublk` dep behind `#[cfg(target_os = "linux")]` + cargo feature `ublk` (on by default on Linux, off elsewhere).
- Requires kernel 6.0+ with `CONFIG_BLK_DEV_UBLK` (module shipped by Fedora 37+, Debian 12+, Ubuntu 22.10+, RHEL 9+; `modprobe ublk_drv` on demand).
- Default mode: `UBLK_F_UNPRIVILEGED_DEV` (kernel 6.5+) so we don't demand `CAP_SYS_ADMIN`. Zero-copy still requires root and is deferred as a future optional enhancement (step 4).
- Document `modprobe ublk_drv` + udev rules prereq in `docs/operations.md`.

## Testing

- Not runnable in `cargo test` sandbox — needs `/dev/ublk-control`, kernel module, udev perms. Treat like `nbd::tests`: sandbox-incompatible, run on a real Linux host.
- Minimal smoke: start ublk-backed volume, write pattern via `/dev/ublkbN` with `O_DIRECT`, read back, compare.
- Proptest coverage unchanged — it drives `VolumeClient`/`VolumeReader` directly, under the transport.

## Phased rollout

Each step lands on its own PR.

1. **Spike (landed — PR #105).** Port NBD handler logic to a `libublk` handler. Single queue, depth 1, synchronous dispatch, no zero-copy, no recovery. Proves plumbing against a ramdisk volume.
2. **Multi-queue + depth (landed).** `nr_hw_queues = min(num_cpus, 4)`, `queue_depth = 64`, `max_io_buf_bytes = 1 MiB`. Per-queue `smol::LocalExecutor` with one async task per tag; backend calls via `blocking::unblock` so the executor progresses other tags while any one tag is waiting on the actor/WAL/S3. File-FD cache promoted to a volume-level `Mutex<FileCache>` of `Arc<File>`s so concurrent readers share one hot set; reads use `pread(2)` so the mutex is held only for lookup/insert. `fio` validation pending on a real host.
3. **USER_RECOVERY_REISSUE.** Coordinator calls `START_USER_RECOVERY` on respawn. Crash-injection test. Enabled by default once validated.
4. **Zero-copy (optional, future).** `UBLK_F_AUTO_BUF_REG` on WRITE. Benchmark. Requires root — likely a separate "privileged" tier.
5. **Config + CLI.** First-class `ublk` section in `volume.toml` (mutually exclusive with `nbd`), coordinator lifecycle integration, docs.

## References

- Kernel: <https://docs.kernel.org/block/ublk.html> (source `Documentation/block/ublk.rst`)
- Driver: `drivers/block/ublk_drv.c`; UAPI `include/uapi/linux/ublk_cmd.h`
- libublk-rs: <https://github.com/ublk-org/libublk-rs> · <https://crates.io/crates/libublk> · <https://docs.rs/libublk>
- ublksrv (C reference): <https://github.com/ublk-org/ublksrv>
- rublk (Rust server, all targets): <https://github.com/ublk-org/rublk>
- Design slides: <https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>
