# Postgres-on-elide correctness soak

This deploys the standalone Elide coordinator (see `../elide-standalone` — same
entrypoint, same keypair-in-environment credential model, same private-app
shape) with PostgreSQL 16 baked into the image, and drives postgres as a
correctness workload on an elide volume. Postgres is a demanding, self-checking
storage client: its commit path is an fdatasync-per-transaction WAL stream,
its checkpoints are bursts of random 8K heap writes, and after any crash it
either recovers to a consistent committed state through its own WAL replay or
reports exactly what broke. The soak crashes it, the elide volume server, and
the whole machine mid-workload, and checks after every crash that no acked
write was lost, no stale page resurrected, and no page corrupted.

The entrypoint runs only the coordinator. Everything postgres-shaped happens
over `fly ssh` through `pgsoak`, a harness baked into the image.

## Bring-up

`./launch.sh` does the whole setup in one step (app, Tigris bucket, fly.toml,
deploy), the same flow as elide-standalone's. Then:

    fly ssh console -C "pgsoak setup"

which creates an 8G volume `pg0`, formats it ext4, mounts it at `/mnt/pg0`,
runs `initdb --data-checksums`, and initialises a scale-50 pgbench database
(~750MB). `./deploy.sh [tag]` redeploys at a verified elide release.

## What a cycle checks

`pgsoak cycle <mode>` runs pgbench (TPC-B, 8 clients) and crashes the rig at a
random point mid-run, then recovers and verifies. Four independent checks run
after every crash:

1. **Balance invariant.** Every pgbench transaction adds the same delta to one
   account, one teller, and one branch, and inserts a history row, so at any
   committed state `sum(abalance) = sum(tbalance) = sum(bbalance) =
   sum(history.delta)`. A lost acked write or a resurrected stale page breaks
   the equality even when every page is internally valid.
2. **Page checksums.** The cluster runs with data checksums; the invariant
   sums scan every heap page, so any torn or corrupted page fails loudly on
   read.
3. **amcheck.** `pg_amcheck` validates index structure against the heap.
4. **ext4.** Recovery runs `e2fsck -fp` before remounting; anything beyond
   journal replay fails the cycle.

## Crash modes

`./soak.sh [cycles]` drives cycles from the workstation, rotating three modes:

- **pg** — `kill -9` every postgres process. The device stays healthy; this is
  the postgres-WAL-recovery baseline that any correct disk passes.
- **vol** — `kill -9` the elide volume server mid-IO. Postgres is left on a
  dead block device; the coordinator's supervisor respawns the volume (elide
  WAL replay), then recovery fscks, remounts, and restarts postgres. Acked
  fsyncs must have reached elide's WAL.
- **host** — `fly machine stop --signal KILL` mid-run, then start. The whole
  VM dies with no clean unmount; acked fsyncs must survive through elide's
  local WAL on the Fly volume. This is the closest Fly gets to pulling the
  power, and it exercises the ublk flush/FUA path end to end.

Evidence (harness log, postgres log, pgbench output, fsck and amcheck logs)
accumulates under `/data/pgsoak` on the Fly volume, so it survives the crashes
the soak inflicts.

## Knobs

`pgsoak` reads `VOL`, `VOL_SIZE`, `SCALE`, `CLIENTS`, `JOBS`, `RUN_SECS`,
`OUT_ROOT` from the environment; `soak.sh` reads `MODES`, `RUN_SECS`,
`MACHINE`. `pgsoak` with no verb prints the full usage. Postgres runs with a
128MB buffer pool and a 256MB WAL ceiling so the workload reaches the device
(frequent checkpoints, steady WAL fsync stream) rather than idling in shared
memory.

## What this is not

A benchmark. The default machine size is shared-cpu, where Fly's iowait-based
throttling of ublk hosts distorts timings; the soak's pass/fail is unaffected,
but read TPS numbers only from a performance-size machine. The credential
model is elide-standalone's shared unscoped keypair, with the same trade-offs
documented there.
