# Design: the WAL sync gate

**Status:** implemented (2026-09-03), measurement pending. The measurements come from the rig's
`[lock …]`, `[flush …]` and `[ublk io]` lines on v0.1.60-rc2 (#997, 2026-09-03).
Builds on the FUA sync off the mutex (#905) and the write-hold split (#997).
Relates to the epoch applies (`epoch-applies.md`), which took the structural
applies off the write path, and to `wal-recycling.md`, which attacks the cost of
one fdatasync from the other side.

## Problem

A guest durability request reaches the WAL file as an fdatasync. There are two
request kinds. A FLUSH op arrives through the actor mailbox, and the actor
thread syncs the WAL and every rotated WAL the promote pipeline owns
(`VolumeRequest::Flush` in `elide-core/src/actor.rs`). A FUA write takes the
WAL's file handle under the volume mutex and syncs it on the ublk thread after
the release (`sync_wal_handle`). Both end in `sync_data` on the same inode.

The rc2 loaded windows show the rates on pg35 under pgbench at 500 tps:

| per 10 s window | count |
|---|---|
| guest writes | 7,000 to 10,000 |
| FLUSH ops | 3,500 to 4,000 |

So the WAL inode takes about 400 fdatasync calls per second from the FLUSH
path against 700 to 1,000 appends per second. A wchan sample of the volume
process over one arm (2026-09-03) put the actor thread inside `fdatasync` in
14% of the samples and caught the ublk job threads there in six, so the FUA
path is a small fraction of the sync traffic. Each call that finds new appends
is a full jbd2 commit, because every append extends the file. The FLUSH calls
run strictly serially on the actor thread, each after the previous one
returned, with two or three appends landed in between. The kernel's joiner
window (`j_max_batch_time`) batches concurrent callers only, and these calls
arrive one at a time.

The `[flush …]` line reports two costs for the FLUSH path. The fsync segment
peaked at 75 to 193 ms in the worst rc2 windows. The mailbox segment peaked at
260 to 330 ms in the same windows: a guest flush waits behind whatever the
actor thread is doing.

The write-hold split (#997) put the tail of a guest write's mutex hold in the
WAL append syscall: in 8 of the 10 worst windows the WAL maximum equals the hold
maximum, at 9 to 13 ms. The wchan sample caught the append (`writev`) blocked
in `do_get_write_access`, `__wait_on_buffer` and `jbd2_log_wait_commit`: the
append's metadata update waits for a buffer the running journal commit holds,
and the FLUSH syncs drive those commits. Fewer syncs give the append fewer
commits to wait behind.

## The contract

The block layer promises two things, and only these two.

- A FLUSH completes when every write that completed before the flush was
  issued is durable.
- A FUA write completes when that write is durable.

Each promise covers the writes before the request, and a later write is
outside it. One fdatasync that starts after a set of writes landed satisfies
every request in that set. The current code spends one fdatasync per request
because each request runs its own sync.

## Design

### Generations

The volume already counts the events the gate needs. `flush_gen` is an atomic
that every write bumps in `publish_snapshot`, under the volume mutex, after the
WAL append. A generation number therefore names a point in the append order,
and a write with generation `g` has its bytes in the page cache before any
thread can observe `flush_gen >= g`.

Each request takes a generation:

- A FUA write takes the generation its own publish produced.
- A FLUSH takes `flush_gen` at its arrival. Every write the guest saw complete
  before it issued the flush published before that load.

### Rounds

A round is one fdatasync of the WAL file plus one of every rotated WAL the
promote pipeline owns. A round records `start`, the value of
`flush_gen` loaded before its first `sync_data` call. When the round completes,
the gate sets `completed = start`.

A request with generation `g` is satisfied by any round with `start >= g`. The
round began after the request's bytes landed, so the sync reached them.

At most one round runs at a time. The gate holds:

```
struct SyncGate {
    completed: u64,        // start generation of the last completed round
    running: Option<u64>,  // start generation of the round in flight
    outcome: io::Result<()> of the last completed round
}
```

A request with generation `g`:

1. If `completed >= g`, return.
2. If a round is running with `start >= g`, wait for it, then return its
   outcome.
3. If a round is running with `start < g`, wait for it, then go to 1.
4. If the gate is idle, start a round on the calling thread: record `start`,
   release the gate, sync, take the gate, publish `completed` and the outcome,
   wake every waiter, and return.

Step 3 is the only case with two waits. A request that arrives after a round
started waits for that round and then for the next one, and the next one is
started by the first such request to wake. So every request completes within
two rounds, and every round serves every request whose generation is at or
below its start.

The number of `sync_data` calls falls from one per request to one per round.
Under load the rounds run back to back, so the sync latency sets the round
rate, and the request rate sets the batch size.

### What a round syncs

A write that appended to a WAL the promote pipeline has since rotated has its
bytes in that rotated file. The round syncs the current WAL through the handle
`wal_sync_handle` returns, and every rotated WAL through a registry the
pipeline keeps: the pipeline adds the old WAL's handle at dispatch and removes
it on the promote result. A handle in the registry survives the unlink, and an
unlinked WAL is one whose bytes are in a committed segment, so a sync through
a stale handle is redundant and harmless (#905 states the ordering).

The promote worker fsyncs the old WAL before it commits the segment. The
registry covers the window between the rotation and that fsync. A failed
promote keeps its old WAL in the registry across retries, as the stash keeps
its path today.

### Where it runs

The gate lives beside the read snapshot, shared by the `VolumeClient` handles,
and a request runs on the thread that made it. A FUA write already syncs on
its ublk job thread. A FLUSH moves there too: `VolumeClient::flush` takes the
gate directly, and the actor's `Flush` request goes. The mailbox wait goes
with it.

The leader of a round syncs on its own thread. The followers block on the
gate's condition variable. A ublk job thread blocks for the same time it
blocks today for a FUA sync.

### Failure

A round that fails fails every request it served, with the error `sync_data`
returned. The gate stores the outcome with `completed`, so a request that
finds `completed >= g` returns the outcome of the round that set it. The next
round starts fresh. A request that started a failed round returns the error
to the guest as an EIO on that op, which is what each request does today.

### Other callers of `flush`

`gc_checkpoint`, `snapshot`, the shutdown flush and the CLI's flush all call
`VolumeClient::flush`. They take a generation at arrival and use the gate the
same way. Their guarantee is the FLUSH contract, which is what they have today.

## Measurement

The `[flush …]` line reports the gate:

```
[flush <vol>] 10s: flush n= fua n= rounds= batch max= wait mean= max= sync mean= max= rotated=
```

- `flush n` and `fua n` count the requests by kind.
- `rounds` counts the syncs. The ratio of requests to rounds is the batching.
- `batch max` is the most requests one round served.
- `wait` is a request's time from arrival to return.
- `sync` is the round's `sync_data` time.
- `rotated` counts the rounds that synced a rotated WAL.

The readings that decide the result, on the same arms as rc2:

1. `rounds` against `flush n + fua n`. The design predicts a round rate near
   `1 / sync latency` under load.
2. The `wait` maximum against the rc2 mailbox plus fsync maxima.
3. The WAL half of the write hold in the `[lock …]` line. A fall in `maxwal`
   with the round count says the append blocked behind the syncs. A flat
   `maxwal` says the append blocks on something else, and the flush gain
   stands on its own.
4. pgbench latency and the worst 10 s window.

## Tests

- The three FUA tests in `actor.rs` stand:
  `fua_sync_survives_promote_between_handle_and_sync`,
  `concurrent_fua_writes_are_each_durable`, `fua_write_is_durable_without_flush`.
- The gate takes its sync as a function, so a unit test drives it with a
  blocking fake and asserts the round rules: a request that arrives during a
  round with a lower start waits for a second round; a request with a
  satisfied generation returns at once; a failed round fails every
  request it served and the next round starts clean.
- The crash-recovery oracle in `volume_proptest.rs` reads back every write
  after a flush and a crash. It covers the gate through the same `flush`
  call.

## Plan

1. The gate, the rotated-WAL registry, the FUA and FLUSH paths through it, and
   the `[flush …]` counters, in one PR.
2. Three arms on the rig, read as above.

## Open questions

- Whether a round should hold a joiner delay before its sync, as jbd2 does,
  to raise the batch at the cost of latency. The design starts at zero delay:
  the sync latency is the batch window.
- Whether the rotated-WAL sync in a round earns its place once the promote
  worker's own fsync moves earlier in the promote. The window it covers is
  the time between rotation and that fsync.
