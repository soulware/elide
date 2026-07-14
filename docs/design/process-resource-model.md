# Per-process resource model

Status: open exploration (2026-07-14). Grounded in the
`scripts/loadtest-ladder` findings on proud-acorn-872 (Fly shared-1x,
1GB); the open questions need a shared-2x/4x machine to resolve.

Elide runs one coordinator plus one process per volume. The scaling
policy is scale-out: more cores host more volume processes, not faster
individual ones. This doc captures what the load testing established
about per-process memory behaviour, and the design questions it opened
about which per-process behaviours should be pinned (hardware-invariant)
versus host-scaled (budgeted).

## Measured: glibc converts transient buffers into retained RSS

Workload: `loadtest-ladder rung3` — 8 volumes × (256MiB urandom seed +
256MiB cp), 4-way concurrency, drain to S3 between phases. Evidence
dirs under `/data/loadtest/` on the box; per-process RSS sampled at 5s.

| run (chronological) | binary | allocator config | coordinator peak/settled | total peak/settled | outcome |
|---|---|---|---|---|---|
| baseline | v0.1.14 | stock glibc | 297 / 294 MB | 803 / 769 MB | cold pass at 10MB avail; warm repeat wedged the machine |
| combined tunables | v0.1.14 | `mmap_threshold=1MiB` + `arena_max=2` | 119 / 16 MB | 551 / 210 MB | cold + warm pass |
| part-buffer pool (#726) alone | v0.1.15 | stock glibc | 408 / — MB | 822 / — MB | cold run wedged the machine mid-copy |
| threshold only | v0.1.15 | `mmap_threshold=1MiB` | in flight | in flight | in flight |

Mechanism: glibc's dynamic mmap threshold starts at 128KB and slides up
to 32MB as large blocks are freed, moving subsequent large allocations
onto heap arenas; the matching trim threshold slides up in lockstep, so
arena memory is effectively never returned to the OS. Fragmentation
(long-lived small allocations interleaved with large transients) blocks
top-of-heap trimming, and freed chunks are only reusable from the arena
that owns them — glibc creates up to 8×cores arenas for a multi-threaded
process, so the same working set duplicates across arenas.

Churn sources by process: the coordinator's multipart upload path cycles
`part_size` (5MiB default) buffers per part; the volume process's
promote path materialises ~70–160KB per-entry body buffers (measured
extent granularity — not 4KB) up to 32MiB per promote. The #726 pool
row shows that reducing the coordinator's churn frequency alone does
not stop the ratchet; the threshold change does.

## Allocator policy is per-role

Proposed (agreed direction, parameters pending the threshold-only run):

- **Volume process: `mallopt(M_ARENA_MAX, 2)`** at startup, behind
  `cfg(target_env = "gnu")`. This is an architectural constant, not a
  machine tune: the volume process has a fixed thread structure in
  which exactly two threads are malloc-hot (actor: imbl path-copies per
  write; worker: promote body materialisation). The glibc default of
  8×cores hands the same process ~8 potential arenas on a 1-core host
  and ~256 on a 32-core host — the opposite of the invariance the
  process model wants. ublk queue threads use buffers preallocated at
  setup and are assumed malloc-cold; a read/decompression-heavy
  workload could falsify that (open question below).
- **Coordinator: arenas stay dynamic.** The coordinator legitimately
  scales with the host (more volumes → more concurrent tick tasks,
  spawn_blocking GC threads, parallel drains, all allocating). Capping
  its arenas based on 1-vCPU measurements would trade unmeasured
  contention on the hosts we actually want to run on.
- **`M_MMAP_THRESHOLD` pinning** (1MiB) covers the large-transient
  ratchet wherever large transients remain. Whether it is needed in
  one binary or both is what the threshold-only run discriminates.

jemalloc was considered and not adopted (dependency); `malloc_trim` at
quiesce points remains a fallback if pinned thresholds leave residue.

## Open: which volume-process behaviours are pinned vs budgeted

The volume process is not hardware-invariant today: `pick_nr_queues`
(`src/ublk.rs:833`) sets the ublk queue count to
`available_parallelism().min(4)`, so queue threads and the potential
IO-buffer floor (64 × 1MiB per queue) scale with the host. Every
per-volume RSS floor measured so far is a 1-queue number.

For each host-scaling behaviour the design choice is pin or budget:

- **ublk queue count** — plausibly *budgeted*: a volume on a larger
  host serving IO with more parallelism may be desirable, at a known
  memory price (+64MiB potential per queue). Alternatively pinned at 1
  to keep per-volume cost constant. Undecided.
- **Arena count** — *pinned* (above).
- Any future runtime/thread-pool sized from `available_parallelism`
  inside the volume process needs the same decision made explicitly.

The invariant worth defending is not "identical process on every host"
but "known per-volume cost as a function of host size", with each
scaling term chosen deliberately.

A related blind spot: on the 1-vCPU box the actor and worker threads
have never truly run in parallel. Multi-core runs change peak memory
(both pipeline stages' buffers live at once), timing windows, and
malloc contention — the conditions under which the actor/worker
dispatch deadlock class was dangerous.

## Open: coordinator per-volume cost must stay sublinear

The scale-out model holds only while the coordinator's cost per managed
volume is small and bounded. Known unbounded-today items (from the
2026-07-14 audit):

- `MintScopedStores` caches one `RoleStore` per volume ULID with no
  eviction (`elide-coordinator/src/mint_stores.rs:254`), each holding a
  distinct S3 client with an uncapped reqwest idle connection pool
  (`config.rs:302` sets timeouts only).
- Per-volume tick tasks and their drain buffers
  (`(MAX_CONCURRENT_PARTS + 1) × part_size` per active upload).

Proposed: RoleStore eviction on volume removal; a pool cap on the S3
clients. Open: a measured coordinator cost-per-volume figure on a
multi-core host with more volumes than the current nine.

## Open: upload-path memory is coupled to the throughput problem

Measured on this box: segment PUTs to same-region Tigris run at
0.6–3MB/s (10–55s per ≤32MiB segment, `[upload]` lines in
`/data/elide_data/elide.log`), while KB-range objects PUT in ~130ms.
Drain wall time is effectively the sum of sequential per-segment upload
times; this sets the tempo of every load test and lengthens the windows
in which pending data and memory pressure accumulate.

The likely remedies (bigger parts, more parts in flight) multiply the
upload path's resident memory, which is what makes the representation
question part of this doc: parts are currently materialised owned
buffers because `object_store`'s multipart API needs replayable owned
payloads. An mmap-backed `Bytes` (map the pending file, slice
`Bytes::from_owner` views per part) would make part memory file-backed
and evictable instead of pinned anonymous heap — near-zero marginal
memory for more in-flight parts. It leans on the invariant that pending
files are immutable until promote deletes them, and promote runs only
after upload completes. This route supersedes the #726 pool in
`put_from_file`.

Discriminating probes for the throughput anomaly (elide out of the
picture): a raw 32MB PUT from the box with a plain HTTP client; the
same with higher part concurrency; CPU/steal sampling during upload;
and the same probes from a shared-2x/4x machine (if throughput scales
with CPU, the bottleneck is compute — TLS + payload checksumming on a
starved shared core — not the network path).

## Test plan: shared-2x/4x runs

Re-run the ladder on a shared-2x or shared-4x machine, same workload,
per-process sampling:

- Volume processes: same settled RSS as shared-1x (invariance holds
  once arenas are pinned) or not (a scaling term is missing from the
  budget). Queue count will double/quadruple unless pinned first —
  decide before running so the run tests one thing.
- Coordinator: profile shift with real parallelism; arena behaviour
  under its dynamic default; cost-per-volume at higher volume counts.
- Upload throughput: CPU-bound hypothesis (above).
- Actor/worker true concurrency: liveness under real parallelism
  (regression surface for the dispatch deadlock class).
