# ublk integration — plan

Branch: `ublk-initial`

## Goal

Expose an Elide volume as `/dev/ublkbN` via the in-kernel ublk driver, as a
second transport alongside the existing NBD server. Same volume semantics, same
op set (read / write / flush / trim / write_zeroes), same coordinator
supervision — different edge. ublk replaces the `nbd-client` process plus the
kernel `nbd` module with a direct io_uring-backed block device.

Sequencing step 3 in [`integrations.md`](integrations.md). Prerequisite for the
container-density story in [`design-oci-export.md`](design-oci-export.md) (NBD
caps at ~16 devices per host; ublk scales to hundreds).

## Non-goals

- **Replacing NBD.** NBD stays. It is the portable transport (macOS dev,
  cross-platform CI, network-reachable bind for tooling), and the unix-socket
  variant remains the default for in-VM and Firecracker paths until ublk is
  fully proven.
- **vhost-user-blk.** Separate track, separate protocol. ublk is host-side;
  vhost-user-blk is VMM-side. Called out in `integrations.md` but out of scope
  here.
- **Multi-queue performance tuning.** First landing uses one queue. Throughput
  work comes after correctness.
- **Packaging the ublk kernel module / udev rules.** Host-side prereq, not a
  project-owned artifact.

## Why ublk (beyond NBD)

1. **No `nbd-client` process, no kernel `nbd` module.** ublk is a kernel driver
   + a userspace daemon talking over io_uring SQEs. One less process to
   supervise; the daemon dies → kernel sees `-ENOTCONN` and returns EIO, no
   dangling TCP state.
2. **Device density.** The `nbd` module defaults to 16 devices and maxes out at
   a few hundred with tuning. ublk allocates minors dynamically and routinely
   runs thousands. This is the gating constraint for the OCI-snapshotter
   direction.
3. **Lower per-I/O overhead.** NBD moves each request through a TCP/Unix socket
   plus kernel block layer; ublk submits commands and data buffers via io_uring
   shared rings. Single-digit-microsecond savings per I/O, non-trivial at queue
   depth.
4. **Clean kernel-side abstraction.** `/dev/ublkbN` looks like any other block
   device. Firecracker, Cloud Hypervisor, mkfs, mount, direct-kernel-boot — all
   of these treat it identically.

None of these individually justify the work; together with the density cap
they do, and the integration roadmap already assumes ublk.

## Architectural fit

The current transport split in NBD sits at the `Volume::{read, write,
write_zeroes, trim, flush_wal}` API (`elide-core/src/volume.rs:1291`, `:1423`,
`:1436`, `:1446`, `:3403`). The NBD server translates on-wire bytes into those
five calls; ublk translates io_uring SQEs into the same five calls. The volume
core is transport-agnostic — the missing piece is a single dispatch surface
both transports can share instead of duplicating the op matching.

Proposed layering (no change to `elide-core`):

```
┌────────────────────────────────────────────────────────┐
│ src/nbd.rs          src/ublk.rs (new)                  │  Transport
│  (protocol parse)    (io_uring SQE parse)              │
├────────────────────────────────────────────────────────┤
│ src/volume_io.rs (new)                                 │  Shared dispatch
│   fn handle_read/write/flush/trim/write_zeroes         │  (one place to
│   on &VolumeHandle or &ReadonlyVolume                  │   change RMW,
│                                                        │   offset slicing,
│                                                        │   COW block logic)
├────────────────────────────────────────────────────────┤
│ elide_core::{actor::VolumeHandle, volume::*}           │  Volume core
└────────────────────────────────────────────────────────┘
```

Today the per-op logic lives in three places inside `src/nbd.rs` —
`handle_connection` (image-backed, `:279`), `handle_readonly_connection`
(`:627`), `handle_volume_connection` (`:869`). Extracting the per-op body
removes that triplication and gives ublk a drop-in consumer. The extraction is
a worthwhile refactor on its own merits even before ublk lands.

## Dependency: `libublk-rs`

Candidate: [`libublk`](https://crates.io/crates/libublk) 0.4.5, MIT/Apache-2.0,
~100k downloads, maintained by Ming Lei (the ublk kernel maintainer). Owns the
ublk ctrl-device dance, io_uring ring setup, and per-queue I/O handler traits.
Recent enough (Oct 2025) to track the current ublk UAPI.

Alternatives considered:

- **Raw ublk ctrl + io_uring via `io-uring` crate.** Doable — ublksrv (C) is
  the reference — but the ctrl protocol is non-trivial (UBLK_CMD_START_DEV,
  per-queue ring fd passing, STOP_DEV on teardown, UBLK_FEATURE negotiation)
  and shifts with kernel versions. Not worth hand-rolling when libublk-rs is
  actively kernel-tracking.
- **`duende-ublk` (a wrapper over libublk for swap daemons).** Higher-level
  lifecycle helpers. Don't need them yet; our lifecycle is simpler.

**Risk:** libublk-rs 0.x — API may move. Pin a minor version and upgrade
deliberately. Rust 1.80 MSRV is fine (Elide tracks stable).

### Runtime model: async on tokio

libublk-rs's handler traits are `async fn`, but the crate is
**executor-agnostic** — the upstream `async_null` example drives per-queue
tasks with `smol::LocalExecutor` + `smol::block_on`, and a tokio current-thread
runtime works equivalently. This is not a sync-vs-async tradeoff; the I/O
handlers must be async. The choice is *which* executor drives them.

Decision: **tokio**, for two reasons:

1. Tokio is already in the workspace (`Cargo.toml:28` +
   `elide-coordinator/Cargo.toml:23` + `elide-fetch`, `elide-import`). Adding
   smol for ublk alone would mean two executors in the dep tree for no payoff.
2. The rest of the process model stays sync. `elide-core` is deliberately
   synchronous (explicit contract at `elide-core/src/segment.rs:128`), the
   volume actor is a plain `std::thread`, and `src/main.rs:411` is
   non-tokio `fn main()` — tokio runtimes get constructed per-subcommand when
   needed (`Runtime::new()` at `src/main.rs:1148, 1313, 1523, 1603`). The
   ublk transport follows that pattern: one tokio current-thread runtime per
   ublk queue, built inside the serve path, torn down on shutdown. Nothing
   outside `src/ublk.rs` becomes async.

Inside an ublk handler, calling `VolumeHandle::read`/`write` (sync channel
round-trip) is fine: the queue thread is a dedicated worker where blocking is
expected, and the actor handle is explicitly designed to be called from
anywhere. Same model as `src/nbd.rs` today, just with async-framed SQE parsing
around the sync call.

What still needs a spike in phase 2: confirm libublk-rs works cleanly with a
tokio current-thread runtime (the examples use smol, but there's nothing in
the API that should prevent it). If it turns out to require a runtime feature
we don't have, falling back to smol is a small, contained change — it would
live entirely inside `src/ublk.rs`.

## CLI surface

Mirror the existing `--nbd-socket` / `--nbd-port` flag shape:

```
elide volume serve <name> --ublk                  # device number auto-allocated
elide volume serve <name> --ublk --ublk-id 7      # force /dev/ublkb7
elide volume serve <name> --ublk --readonly
```

Mutually exclusive with `--nbd-port`/`--nbd-socket` for a single invocation —
one transport per serve. A single volume could run two serves (one NBD, one
ublk) if anyone ever wants that, but it's not a goal. `main.rs:222-247` is the
clap site; add a `TransportBind` enum that enumerates {NbdTcp, NbdUnix, Ublk}
and drive `run_volume_*` off that instead of the current `NbdBind`.

The coordinator invokes `volume serve` today with `--nbd-socket` in the
supervision path (`src/volume_up.rs:174`). Coordinator-driven ublk is a
follow-up: the first landing is user-invoked `elide volume serve --ublk`, no
coordinator integration, so the blast radius stays bounded.

## Device lifecycle

NBD's transport is ephemeral: client disconnects → socket closes → state gone.
ublk is stickier:

- The device stays registered in the kernel until explicitly deleted
  (`UBLK_CMD_DEL_DEV`), even if the userspace daemon dies.
- If the daemon dies with the device still registered, any subsequent I/O
  returns EIO until the device is deleted.
- Re-attaching userspace to an orphan device is possible but not something we
  want to support in the first landing.

Required discipline:

1. **On clean shutdown (SIGTERM):** `DEL_DEV`, then exit. Matches the
   `install_sigusr1_handler` pattern in `src/nbd.rs:765`.
2. **On crash:** orphan device remains. Startup must detect an existing
   device owned by this volume (track the ublk dev-id in the volume dir, e.g.
   `ublk.pid` / `ublk.devid`) and either reclaim it or `DEL_DEV` + re-create.
   Stale-device reclaim is a known pattern (ublksrv has `ublk recover`);
   simplest first-cut is "delete and recreate."
3. **On supervisor restart:** coordinator-supervised case — the coordinator
   SIGTERMs the volume process and expects clean shutdown. Add `DEL_DEV` to
   the existing shutdown path.

This is a real semantic difference from NBD and the main reason ublk is a
separate doc rather than a one-line transport swap.

## Platform gating

- `#[cfg(target_os = "linux")]` everywhere in `src/ublk.rs`. The module
  compiles but is empty on non-Linux; CLI flags return a clear error on those
  targets.
- Cargo feature `ublk` (default off initially, flip to default on after the
  first couple of releases). Keeps the dep tree lean on macOS dev and in
  minimal builds.
- Runtime probe on Linux: check `/dev/ublk-control` exists before attempting
  to start a device. If absent, error with "ublk kernel module not loaded"
  rather than a cryptic ioctl failure.

## Phases

### Phase 1 — transport-agnostic refactor (no ublk yet)

- Extract `src/volume_io.rs` (or similar) with `handle_{read,write,flush,
  trim,write_zeroes}` taking `&VolumeHandle` (or a `&ReadonlyVolume`) plus the
  offset/length.
- Route `handle_connection`, `handle_volume_connection`,
  `handle_readonly_connection` through it.
- Remove the triplication; existing NBD tests continue to pass.
- Lands on its own branch, independent of ublk.

**Done when:** the NBD paths call into `volume_io` exclusively; no behavioural
change; existing NBD integration tests green.

### Phase 2 — libublk-rs spike

- Add `libublk` as an optional dep behind the `ublk` feature.
- Sample binary (`examples/ublk-echo.rs` or a scratch crate) that stands up a
  null-backed ublk device on a tokio current-thread runtime, responds to
  reads/writes with zeros. Confirms the ctrl-device dance, tokio-executor
  compatibility (upstream uses smol — see *Runtime model* above), and Rust
  MSRV fit.
- Test on a Linux 6.x VM (Multipass or similar — the same infra as the NBD
  integration tests).

**Done when:** can bring up `/dev/ublkb0` from a Rust binary, mount ext4 on
it, and tear it down cleanly.

### Phase 3 — ublk transport

- Add `src/ublk.rs` implementing the ublk I/O handler on top of the
  `volume_io` dispatch from phase 1.
- Wire `--ublk` / `--ublk-id` into `main.rs`, `NbdBind` → `TransportBind`.
- Lifecycle: startup checks, SIGTERM handling, orphan-device teardown.
- Linux-only build, feature-gated.

**Done when:** `elide volume serve <name> --ublk` on Linux produces a working
block device; mkfs + mount + scribble round-trips data; SIGTERM cleanly
deletes the device.

### Phase 4 — CI and soak

- Add a Linux-only CI job that runs a ublk smoke test (mkfs + mount + small
  workload + unmount + DEL_DEV).
- Add a ublk variant to the proptest simulation model if practical, or
  explicitly note why not (ublk stands up real kernel devices, not easily
  in-process).
- Dogfood: run the quickstart flows (`docs/quickstart.md`,
  `docs/quickstart-data-volume.md`) with `--ublk` and update the docs to show
  both paths.

### Phase 5 — coordinator-driven ublk (deferred)

- Teach the coordinator supervisor (`src/volume_up.rs:174`) to pick ublk over
  NBD when requested.
- Per-volume transport pref stored in volume dir (or coordinator state).
- Not urgent — users can invoke `volume serve --ublk` directly until the
  coordinator integration is needed for a specific downstream consumer.

## Testing

- **Unit.** `volume_io` dispatch is covered incidentally by existing NBD
  tests. Add a minimal `volume_io` test that exercises each op against a
  scratch volume directly (no transport).
- **Integration (Linux-only).** A new test file gated on `#[cfg(all(
  target_os = "linux", feature = "ublk"))]` that:
  1. Opens a volume.
  2. Spins up a ublk device.
  3. Opens `/dev/ublkbN` as a file, writes a pattern, reads it back.
  4. Tears the device down.
  Pattern mirrors `elide-core/tests/*_volume_test.rs`.
- **End-to-end on a VM.** Multipass VM with Linux 6.x. Run quickstart flows.
  This already exists for NBD; extend it.
- **Platform gate.** CI must still pass cleanly on macOS — the feature-off
  build is the important invariant.

## Open questions

1. **Queue count and depth.** Start with 1 queue, depth 128. Revisit only
   after measurement. Multi-queue ublk serialises at the volume actor anyway
   (single writer), so queue parallelism only buys read concurrency — which
   the volume already supports through the read path, but the actor handle
   may still be the bottleneck. Worth measuring before over-engineering.
3. **Orphan-device recovery on crash.** First-cut: startup deletes any
   device tagged with our volume's ULID and re-creates. Reclaim (keep the
   device, just re-attach the userspace) is an optimisation; skip initially.
4. **Readonly ublk.** ublk supports read-only flags at device creation
   (`UBLK_F_READ_ONLY`). Mirror the `ReadonlyVolume` path; write commands
   return EPERM. No new volume semantics.
5. **Metrics / observability.** NBD prints `[reads: N]` at disconnect.
   ublk has no disconnect event in the same sense; emit periodic counters to
   the coordinator instead, or at device-stop. Minor — align with whatever
   the existing observability story lands on.
6. **vhost-user-blk overlap.** The `volume_io` dispatch should also be the
   entry point for a future vhost-user-blk backend. Keep the trait/function
   shape narrow enough not to foreclose that.

## Related docs

- [`integrations.md`](integrations.md) — layered architecture; ublk is
  sequencing step 3.
- [`design-oci-export.md`](design-oci-export.md) — the density story that
  makes ublk load-bearing.
- [`vm-boot.md`](vm-boot.md) — direct-kernel-boot flow currently uses NBD;
  eventually swaps to ublk.
