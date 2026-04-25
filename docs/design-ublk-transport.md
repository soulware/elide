# ublk as an alternative transport

Status: exploration / pre-implementation reference. Captures the plan before any code changes.

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

ublk's I/O transport is io_uring — async is inherent. But the async surface is **scoped to `src/ublk.rs`**; `VolumeClient`/`VolumeReader` and the rest of the core stay synchronous.

**Plan: A → B → (2b).**

- **A (spike, step 1, landed).** libublk-rs synchronous handler — one `io_uring` per queue, single queue, `queue_depth = 1`, synchronous `VolumeClient` call inline. Acceptable for proving plumbing; no head-of-line concern at depth 1.
- **B (step 2, landed).** `nr_hw_queues = min(num_cpus, 4)` at `queue_depth = 1`, synchronous handler per queue. Concurrency comes from multiple queue threads running independently with their own `VolumeReader`. A slow backend call on one queue (e.g. demand-fetch from S3) stalls only that queue, not its siblings.
- **2b (landed).** `queue_depth = 64` with an async per-tag handler, backend work offloaded to a per-queue worker pool of 8 threads. The earlier `smol::LocalExecutor` + `blocking::unblock` attempt was reverted: `blocking` wakes futures on its own thread pool and that wake cannot interrupt `io_uring::submit_and_wait` on the queue thread, so every I/O waited for a kernel event or the ring's idle timeout (`mount /dev/ublkb0` hung 20–30 s per metadata read). The shipped design uses route (a): each tag's task submits a `PollAdd` SQE on the queue's own ring watching an eventfd; the worker writes the eventfd on completion, producing a CQE on the queue thread's ring so the smol executor wakes directly — no cross-thread waker stall.

**Why not C (hand-rolled sync io_uring loop).** Considered and rejected:

- Performance delta vs libublk-rs is in the noise. Async overhead is tens of ns per I/O; backend path (actor hop, WAL, occasional S3 fetch) dominates by orders of magnitude. Both B and C need a thread-pool offload for the backend anyway.
- Strictly more complex: we'd own the UAPI bindings, the FETCH/COMMIT tag state machine, the control-plane ioctl shapes, and the cost of tracking kernel protocol evolution (batched I/O, auto-buf-reg, new recovery modes). libublk-rs is maintained by the ublk driver's author.
- At `queue_depth > 1` with a thread-pool backend, we'd reinvent async by hand anyway.
- Escape hatch if libublk-rs is ever abandoned, not a starting point.

**Runtime coexistence.** libublk-rs uses `smol`; we already use `tokio` in the coordinator. No conflict — smol here is a thread-local executor, not a global runtime.

**Handle Send/Sync shape.** `VolumeHandle` was split into two types ahead of step 2:

- `VolumeClient` (Send+Sync+Clone): mailbox channel, atomic snapshot pointer, immutable config. No per-thread state.
- `VolumeReader` (Send, !Sync): owns the per-thread file-fd cache; derefs to `VolumeClient` so it can also issue writes/flushes.

`actor::spawn` returns a `VolumeClient`; the queue-handler closure captures a `VolumeClient` directly (satisfies libublk's `Send + Sync + Clone + 'static` bound). Each queue thread constructs one `VolumeReader` on entry. Step 2b will revisit reader ownership once the depth > 1 model is chosen.

## Control plane

- Lifecycle: `ADD_DEV` → `SET_PARAMS` → `START_DEV` → run → `STOP_DEV` → `DEL_DEV`. `libublk::run_target` handles the first four; elide installs a SIGINT/SIGTERM/SIGHUP handler that calls `kill_dev` (safe from outside the target callbacks) to break the queue-thread join, then explicitly calls `del_dev` after `run_target` returns so the device does not linger in `/sys/class/ublk-char` and the id can be reused on the next serve.
- Add `UblkConfig { dev_id: Option<i32> }` in `elide-core/src/config.rs` alongside `NbdConfig`. `ublk` and `nbd` sections are mutually exclusive in `volume.toml`; config parse rejects both being set.
- CLI: `--ublk` / `--ublk-id N`, conflicts with `--nbd-port` / `--nbd-socket` in clap.
- Conflict detection: `find_nbd_conflict` grows a `find_ublk_conflict` checking `dev_id`.
- Coordinator supervision unchanged: spawn `elide serve ... --ublk-id N`, respawn on crash.

## Crash recovery

- `UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_REISSUE`: on unclean daemon exit the kernel transitions the device to QUIESCED instead of tearing it down, buffers in-flight I/O, and reissues it once a new daemon attaches.
- Safe because WAL + lowest-ULID-wins already handles duplicate writes (same LBA, same or newer ULID — idempotent).
- **Enabled unconditionally.** Both flags are set on every `ADD_DEV`. There is no non-recoverable mode.
- **Volume ↔ device binding.** The kernel's sysfs entry alone does not identify which volume a QUIESCED device belongs to. Reissuing one volume's buffered writes into a different volume's WAL is silent corruption, so every successful ADD records the kernel-assigned id in `<volume>/ublk.id` (per-host runtime state). On clean shutdown the file is removed; on crash it survives, which is how the next serve recognises the device as ours to recover.
- **Startup routing.** Let `P = read(ublk.id)`, `C = --ublk-id`, `sysfs(id)` = `/sys/class/ublk-char/ublkc<id>` exists. Decision table:
  - `P` and `C` both set and disagree → refuse with "volume bound to X, got Y".
  - `target = P.or(C)`. If `target` is none → ADD, let the kernel auto-allocate.
  - If `sysfs(target)` is false → ADD with `target` (rebind the slot).
  - If `sysfs(target)` is true and `P == Some(target)` → `START_USER_RECOVERY` + `RECOVER_DEV`; `run_target` finishes with `END_USER_RECOVERY`.
  - If `sysfs(target)` is true and `P` is none → refuse with "ublk dev N exists but this volume is not bound to it".
- **Clean vs crash exit.** SIGINT/SIGTERM/SIGHUP → signal handler `kill_dev` → queue threads exit → `run_target` returns → `del_dev` → clear `ublk.id`. Sysfs entry and binding file are both gone, next serve performs ADD. Crash (SIGKILL, OOM, panic) → kernel observes uring_cmd fds closing → device QUIESCED, sysfs entry stays, `ublk.id` stays, next serve performs RECOVER against the bound id.
- **Crash-injection test follow-up.** A kernel-lane integration test that drives an actual write → SIGKILL → respawn → read-back loop is tracked as a follow-up; the plumbing lands here so step 5 (coordinator supervision) can rely on it.

## Dependencies & platform gating

- Linux-only. New `libublk` dep behind `#[cfg(target_os = "linux")]` + cargo feature `ublk` (on by default on Linux, off elsewhere).
- Requires kernel 6.0+ with `CONFIG_BLK_DEV_UBLK` (module shipped by Fedora 37+, Debian 12+, Ubuntu 22.10+, RHEL 9+; `modprobe ublk_drv` on demand).
- **Current state:** the ublk control flags are `UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_REISSUE` only; `UBLK_F_UNPRIVILEGED_DEV` is *not* set, so `serve-volume --ublk` requires root today. Wiring up the unprivileged-default path (kernel 6.5+, plus a documented udev rule) is tracked as part of step 1's hardening; `operations.md` flags this for operators.
- Zero-copy will continue to require root even after the unprivileged flag lands — the kernel gates `UBLK_F_AUTO_BUF_REG` on `CAP_SYS_ADMIN`. Deferred to step 4.
- Document `modprobe ublk_drv` + udev rules prereq in `docs/operations.md`.

## Testing

- Not runnable in `cargo test` sandbox — needs `/dev/ublk-control`, kernel module, udev perms. Treat like `nbd::tests`: sandbox-incompatible, run on a real Linux host.
- Minimal smoke: start ublk-backed volume, write pattern via `/dev/ublkbN` with `O_DIRECT`, read back, compare.
- Proptest coverage unchanged — it drives `VolumeClient`/`VolumeReader` directly, under the transport.

## Phased rollout

First PR is the spike only. Later steps are sequenced separately, each on its own PR.

1. **Spike (landed).** Port NBD handler logic to a `libublk` handler. Single queue, depth 1, no zero-copy, no recovery. Prove plumbing.
2. **Multi-queue, depth 1 (landed).** `nr_hw_queues = min(num_cpus, 4)`, sync handler per queue. Lifecycle cleanup: signal-thread `kill_dev` + post-`run_target` `del_dev` so devices do not leak across serve restarts. `elide ublk list` / `elide ublk delete` diagnostic CLI.
2b. **Depth > 1 (landed).** `queue_depth = 64` via uring-registered eventfd bridging from a per-queue worker pool. See Async model above for the dead-end we avoided.
3. **USER_RECOVERY_REISSUE (landed).** Added with `UBLK_F_USER_RECOVERY | UBLK_F_USER_RECOVERY_REISSUE` by default; sysfs-scan-based add/recover routing at serve startup; `START_USER_RECOVERY` issued before the recovery builder, `END_USER_RECOVERY` via libublk's internal `start_dev` path. Crash-injection integration test is a follow-up.
4. **Zero-copy (optional, future).** `UBLK_F_AUTO_BUF_REG` on WRITE. Benchmark. Beyond the obvious cost — root is required (`CAP_SYS_ADMIN`) and the kernel floor lifts to 6.10+ for `AUTO_BUF_REG` — the real cost is that the synchronous `VolumeReader` model in *Async model* breaks. Zero-copy hands the daemon a kernel-registered buffer index per tag; reads must land directly in that buffer via io_uring SQEs against the queue's ring, not via a sync `pread` into an arbitrary `&mut [u8]`. The backend either reworks its I/O path to issue ring-targeted ops, or copies into the registered buffer at the boundary and gives up the win. Internal copies (cache, dedup, decompression) further bound the upside, so this should be measured before committing. Likely a separate "privileged" tier.
5. **Config + CLI (landed).** `[ublk]` section in `volume.toml` (mutually exclusive with `[nbd]`, enforced at parse time). `volume create` / `volume update` grew `--ublk` / `--ublk-id` / `--no-ublk` flags. Supervisor reads `[ublk]` and passes `--ublk` / `--ublk-id` to `serve-volume`; `find_ublk_conflict` mirrors `find_nbd_conflict` (lowest-ULID-wins by `dev_id`). Operator docs in `operations.md` and `quickstart.md`.

## References

- Kernel: <https://docs.kernel.org/block/ublk.html> (source `Documentation/block/ublk.rst`)
- Driver: `drivers/block/ublk_drv.c`; UAPI `include/uapi/linux/ublk_cmd.h`
- libublk-rs: <https://github.com/ublk-org/libublk-rs> · <https://crates.io/crates/libublk> · <https://docs.rs/libublk>
- ublksrv (C reference): <https://github.com/ublk-org/ublksrv>
- rublk (Rust server, all targets): <https://github.com/ublk-org/rublk>
- Design slides: <https://github.com/ming1/ubdsrv/blob/master/doc/ublk_intro.pdf>
