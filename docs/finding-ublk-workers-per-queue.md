# Finding: ublk worker threads per queue against the guest write tail

**Status:** measured 2026-09-05 at v0.1.60-rc8 on the rig (Fly, two vCPUs),
twelve arms, 30 minutes after the boot. Follows
`docs/finding-write-tail-cpu-scheduling.md`, which read sixteen ublk worker
threads that wait 1.1 s per second for a core at 0.15 cores of work, and
named the count as the first lever.

## Method

`[ublk] workers` in `volume.toml` sets the worker threads per ublk queue.
The rig has two queues. One build served four counts, 8, 4, 2 and 1 per
queue, in the order 8 4 2 1 1 2 4 8 8 4 2 1, so each count took every
position of the set once. Each arm stopped the volume, wrote the count,
started it, asserted the thread count under `/proc`, and ran the sampled
pgbench arm of the rc7 set, 180 s at 500 tps on pg35. Scripts:
`ab60i.sh`, driver `ab5d.sh`, sampler `csample.sh`, parser `workers.py`.

## Result

Each cell is the median of the three arms, with the arm range in brackets.
The slowest write is the phase clock's slowest guest write per loaded lock
window, 16 to 18 windows per arm. The run delay is the sum over the ublk
worker threads of the time spent runnable and waiting for a core.

| per queue | threads | slowest write med / max, ms | windows with a slowest write over 8 ms | wait max, ms | run delay med / p95, ms per s | runnable p95 | read max med, ms | writes blocked per arm |
|---|---|---|---|---|---|---|---|---|
| 8 | 16 | 6.3 / 16.8 [10.7..31.7] | 5 [4..5] | 13.6 | 992 / 3382 | 13 | 5.5 | 3513 to 15868 |
| 4 | 8 | 5.1 / 12.3 [12.1..21.9] | 2 [1..4] | 11.9 | 676 / 2121 | 10 | 5.1 | 2864 to 7042 |
| 2 | 4 | 5.2 / 11.2 [10.3..23.5] | 2 [1..4] | 8.0 | 418 / 1027 | 8 | 5.9 | 1985 to 2027 |
| 1 | 2 | 4.3 / 7.6 [5.5..75.7] | 0 [0..1] | 6.3 | 216 / 517 | 7 | 8.3 | 285 to 1033 |

**The scheduling tail follows the count.** Every measure of the write
path's own tail falls with the count. The slowest write per window falls
from 6.3 to 4.3 ms at the median. The windows with a slowest write over 8
ms fall from 5 per arm to 0. The slowest write's mutex wait falls from 13.6
to 6.3 ms. The ublk run delay falls from 992 to 216 ms per second, and the
p95 runnable count from 13 to 7. The busiest ublk thread waits the same 280
to 320 ms per second at every count, so the sum falls because fewer threads
wait, and each request waits less because fewer threads share the period.

**The guest sees a small part of it.** pgbench latency reads 5.9, 5.1 and
17.1 ms at 8 per queue, 5.2, 14.2 and 9.7 at 4, 5.6, 4.7 and 5.1 at 2, and
4.7, 4.8 and 5.8 at 1. Three arms carry an event with a cause outside the
count, and the rest sit inside the rig's 8% noise floor, with the cleanest
three arms at 1 and 2 per queue.

- Arm w8-1 ran 31 to 33 minutes after the boot and carried three windows
  where a guest read and a WAL sync held to the same value, 232, 111 and
  396 ms. That is the held virtio request family of
  `docs/design/segment-write-behind.md`, which reaches past 30 minutes
  after a boot.
- Arms w4-2 and w4-3 read a worst guest window of 127 and 89 ms with every
  ublk read, write and sync under 30 ms. The event is inside the guest.

**One worker per queue serialises the queue.** At 1 per queue the read
max per window rises from 5.5 to 8.3 ms and the read mean from 0.28 to
0.36 ms, because a read waits behind the writes and syncs on the queue's
one worker. Arm w1-3 shows the cost in full. A guest write's `post` phase
ran 75.7 ms at 16:54:56, in the window where a promote-segment apply
retired the previous snapshot. On queue 0 that one worker was the queue,
so the window's read max and write max read 79.4 and 80.4 ms, and the
guest's worst window read 18.6 ms. The same `post` class fired at 2 and 4
per queue, 23.5 and 21.9 ms, and stayed inside one worker there.

**Cost is nil.** Guest tps, the volume's CPU per transaction, the ublk
workers' own CPU, 0.13 to 0.19 cores, steal and the sync max are the same
at every count.

## What this settles

The count sets the size of the scheduling tail on a two-core machine, and
the per-thread wait is a property of the machine, 280 to 320 ms per second
for the busiest thread. Two per queue takes most of the gain, run delay 418
against 992 ms per second and the slowest write's max 11 against 17 ms,
and keeps a second worker on each queue for the request that blocks, a WAL
sync, an S3 fetch, or a `post` drop. One per queue takes the rest of the
gain and hands every blocked request to the whole queue.

The `post` tail after a promote-segment apply is the remaining write-path
class in this set, 75.7 ms once in twelve arms. `docs/design/retired-base.md`
closed the same class for the repack bucket swap.

## Options

- A default of 2 per queue, with the field for an operator who reads
  differently on another machine.
- A default tied to the core count, so a two-core host runs 2 per queue and
  a larger host keeps 8.
- The priority lever of `docs/finding-write-tail-cpu-scheduling.md`, which
  keeps the count and takes the cores from the background threads.
