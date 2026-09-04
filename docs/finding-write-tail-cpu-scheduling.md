# Finding: the guest write tail is CPU scheduling on the rig's two cores

**Status:** measured 2026-09-04 at v0.1.60-rc7 on the rig (Fly, two vCPUs),
three arms, 32 minutes after the boot. Follows `docs/design/retired-base.md`,
whose rc7 read left the slowest guest write per window at 7 to 27 ms across
the `pre`, `wait` and `held` phases.

## Symptom

The `pre` phase of a guest write is a blake3 hash and a zstd compress of 8
to 16 KiB, at a mean of 38 us. In the worst windows it runs 8 to 26 ms. The
`wait` phase runs 10 to 16 ms in windows where the mutex holder held it under
1 ms. A thread that runs 38 us of work in 26 ms, and a waiter that takes 16
ms to take a mutex released after 1 ms, are both threads off the CPU.

## Measurement

A sampler on the rig reads once a second, alongside the arms: the
`/proc/stat` cpu lines, the load average with its runnable count, and every
thread of the volume and coordinator processes with its CPU ticks and its
schedstat run delay, which is the time the thread spent runnable and waiting
for a core. The parser joins the seconds to each loaded `[lock …]` window.
Scripts: `csample.sh`, driver `ab5d.sh`, parser `cpu.py`.

## Result

**The host takes little.** Steal reads a median of 1.4% per second, a p95 of
3.2% and a maximum of 7.7%. The windows with a slow write read the same
steal as the quiet ones.

**The VM is oversubscribed in bursts.** Over an arm the two cores are 59%
busy: 1.17 cores, of which the volume and coordinator threads take 0.44 and
postgres, pgbench and the kernel take 0.74. In the loaded windows the busiest
second reaches 80 to 88% with 5 to 18 runnable threads. The volume alone runs
sixteen ublk worker threads, an actor, a worker and a sync gate on those two
cores, next to eight postgres backends and pgbench.

| thread | cores, mean of an arm | run delay, ms per second |
|---|---|---|
| ublk workers, sixteen threads summed | 0.15 | 1110 to 1213 |
| volume-worker | 0.16 | 45 to 50 |
| volume-actor | 0.07 | 27 to 46 |
| coordinator tokio runtime | 0.01 to 0.05 | up to 60 |

**The ublk workers wait for cores.** The sixteen ublk worker threads
together spend 1.1 to 1.2 seconds per second runnable and waiting, at 0.15
cores of work. The single busiest ublk thread in a second waits a median of
94 ms and a p95 of 231 ms of that second. Per request that is about 0.6 ms
of wait on average, which is the gap between the `[ublk io]` write mean of
0.42 to 0.52 ms and the phase clock's total of 0.13 to 0.15 ms per write,
because the clock starts once the worker runs.

**The worst waits match the scheduling period.** With 8 to 18 runnable
threads on two cores, the fair scheduler's period runs to 12 to 27 ms, and
a thread that wakes into it waits up to that long. The worst `pre` of 26 ms
and the worst `wait` of 16 ms sit inside that band, and the windows with a
slow write read a deeper run delay for the ublk workers, a median of 255
against 207 ms per second, and for the volume-worker, 214 against 146.

**The threads that hold the cores in those seconds.** The busiest thread in
a loaded second is the coordinator's tokio runtime at 0.9 to 1.0 cores, the
volume-worker at 0.5 to 0.9 cores while it compresses a segment, or the
actor at 0.5 cores while it applies. Each of them holds a core for the whole
second, so a ublk worker woken to serve a write waits for the other core
behind postgres.

**The guest in this set.** Latency 5.5, 5.1 and 5.2 ms, worst windows 8.7,
6.2 and 6.9 ms. The reboot tail is absent at 32 minutes after the boot.

## What this settles

The write path's own work per guest write is 130 to 150 us, and the mutex
holds under 1 ms. The tail above that on this machine is the wait for a core
on a two-core VM that runs the guest's database, the volume's sixteen
request threads, a compressing worker and a coordinator runtime together.
It is the machine class and the thread layout, and every further read of the
guest write tail on this rig reads against that floor.

## Options

The finding names three levers, each a change to how the volume shares the
cores rather than to what it does per write:

- Fewer ublk worker threads per queue. Sixteen threads for 0.15 cores of work
  means each request wakes a sleeping thread into the run queue.
- Priority. The ublk workers and the sync gate serve the guest; the worker's
  compress, the actor's applies and the coordinator's uploads serve the
  background, and can run at a lower priority.
- A machine with more cores, which moves the floor for the rig and says
  nothing for a two-core deployment.
