# Partial-fork supervision gate

The `volume.claiming` marker keeps a fork directory minted by
`volume claim` / `volume claim --force` invisible to the coordinator's
supervision loop until the claim job finishes building it. Without the
gate, discovery admits the dir the moment its keypair lands — seconds
before the claim completes — and for `--force` that was a data-loss
bug: the volume daemon could open the fork *after* its provenance was
readable but *before* the head-delta re-own materialised, serve the
pre-delta state, and then have GC fold the re-owned segment together
with writes made through that stale view — durably losing the head
delta's filesystem-visible changes.

## Incident (coord-1, 2026-07-02)

`vol2` running on coord A; guest wrote `hello4.txt`, deleted
`hello3.txt`, clean `umount`. Coord A drained fully — WAL empty, the GC
output segment `01KWHVKM…` (carrying both changes) uploaded at
16:47:02. Coord B then ran `claim --force`:

| time (UTC)   | event |
|--------------|-------|
| 16:47:06.196 | `rebind` mints fork `01KWHVM5…`: dir + `volume.key` on disk |
| 16:47:06.266 | discovery tick: `discovered volume: …/01KWHVM5…` |
| 16:47:06.344 | supervisor spawns serve-volume pid 773 → exit 101 (no `volume.toml` yet); 2s backoff |
| 16:47:06.596 | fence: `names/vol2 → 01KWHVM5…` CAS lands; `volume.toml` written |
| 16:47:08.430 | supervisor respawn pid 774: `open_read_state` succeeds — lbamap from the provenance parent only, **no head delta**; ublk device up |
| 16:47:12.033 | `re_own` lands `01KWHVKM…` under the fork's prefix (mint `volume-rw` assumption cost ~2s each) |
| 16:47:12.165 | `finalize`: `volume.stopped` written (moot — daemon already serving), rescan triggered (no-op for a running daemon) |
| 16:47:36     | fork GC folds `01KWHVKM…` with post-mount segments |

The user mounted the device and saw the pre-delta state: `hello3.txt`
resurrected, `hello4.txt` missing. The mount's own ext4 metadata writes
(directory and journal blocks, at higher ULIDs) then shadowed the head
delta's directory blocks in the GC fold, making the stale view the
durable canonical state. The head delta's changes survive only in the
displaced fork (`vol2-b26ff2`) on coord A.

## The broken invariant

Both claim paths mint the fork directory in stage 1 and park it only in
`finalize`:

- regular claim: `early_rebind` writes `volume.{key,pub,provenance}`
  (`elide-coordinator/src/claim.rs`), `finalize` writes `wal/`,
  `pending/`, the `by_name` symlink, and `volume.stopped`;
- force-claim: `rebind` writes the same skeleton plus `volume.toml`
  (`elide-coordinator/src/force_claim.rs`), then `re_own` copies the
  head delta, then `finalize` parks.

Both were written against a discovery gate that no longer exists. The
doc comment on `early_rebind` states it: the skeleton holds
"crucially **no `wal/`, no `pending/`, no `index/`**, so the daemon's
discovery loop won't pick the partial fork up". Commit `34e0d9c`
widened `discover_volumes` to admit any dir carrying `volume.key` — a
correct fix for its own problem (a genuinely empty owned fork, reachable
since #641, was never supervised and `volume start` timed out) — which
silently voided the claim paths' invisibility assumption.

Three defence layers each miss the window:

1. **`reconcile_marker` is one-shot at discovery.** Pre-fence it reads
   the record as owned by the foreign coordinator → no action. Pre-
   `volume.toml` it cannot resolve a name → skipped entirely. It never
   re-runs for a known dir, so the post-fence `Stopped` record (both
   `mark_claimed` and `mark_claimed_force` write `NameState::Stopped` —
   the fork is meant to land parked) is never consulted again.
2. **The supervisor's park check reads local markers only.** Nothing
   writes `volume.stopped` until `finalize`; every loop iteration until
   then is spawn-eligible.
3. **`finalize`'s rescan cannot repair a running daemon.** The daemon's
   lbamap is built once at `open_read_state`; segments re-owned into the
   fork afterwards are invisible to it for the life of the process.

The per-volume drain/GC task is also spawned for the partial fork at
discovery (observed: `[head …] read failed … cannot anchor … treating
as empty` at 16:47:06.344), so the tick loop runs concurrently with the
claim job's `re_own` writes into the same `index/`.

## Why `--force` loses data and plain claim does not

Force-claim has an *openable-but-incomplete* window: `rebind` writes a
complete, verifiable provenance (the basis pin, or the takeover
`ParentRef` when the source never published a manifest), but the
content above that anchor arrives only in `re_own`. Anything that opens
the fork inside the window gets a correct-looking, verifiably-signed,
*stale* volume — the silent-stale failure shape.

Plain claim has no such window. The provisional provenance written by
`early_rebind` pins `released_vol@handoff_snap`, and the handoff
manifest covers the released volume's entire content (`release` refuses
`NeedsDrain`); `skip_empty_intermediates` only ever substitutes a
content-identical ancestor. A daemon that opens mid-claim either
crash-loops (skeleton not yet openable — observed exit 101) or serves
correct content while the record says `Stopped`. Nuisance and log
noise, not data loss: premature supervision, a daemon the user never
started, and `finalize` rewriting `volume.provenance` under a running
process.

## The gate

A claim-in-progress marker, `volume.claiming`
(`elide-coordinator/src/volume_state.rs`), exactly parallel to
`volume.importing`:

- `early_rebind` / `rebind` write it immediately after
  `create_dir_all`, *before* `generate_keypair` — discovery keys on
  `volume.key`/`pending/`/`index/`, none of which exist until the
  keypair, so marker-before-keypair leaves no discoverable instant
  without it. Force-claim's resume `rebind` re-writes it over the
  partial fork it picks up.
- `finalize` removes it after `volume.stopped` lands, so there is no
  instant where the dir is discoverable without one marker or the
  other.
- `discover_volumes` skips dirs bearing it, which gates the
  supervisor, the per-volume drain/GC task, and the
  `by_name`-symlink reconcile in one place (the same choke point the
  `volume.importing` skip uses).

The fork is structurally not-a-volume until the claim job completes:
no daemon can open it early, no tick loop can race `re_own`, and
`finalize`'s existing rescan-after-park sequencing is sufficient — no
daemon-reload mechanism is needed. The `34e0d9c` case stays intact: a
completed empty fork carries `volume.key` and no `volume.claiming`, so
it is discovered and supervised as before.

The gate is a distinct marker rather than an early `volume.stopped`
because the park marker gates only the supervisor — the drain/GC task
would still tick against the partial fork concurrently with `re_own`'s
writes into `index/` — and because on-disk state should say which of
"complete, parked volume" and "half-built fork" a directory is (`ls`
shows `volume.claiming` and the operator knows a claim is in flight or
died in flight).

Crash mid-claim leaves the marker in place, and discovery ignoring the
dir is the correct disposition: the documented recovery for a partial
fork is `claim --force`, whose resume path re-enters the claim job that
owns the marker lifecycle. A partial fork abandoned by a *superseding*
fresh claim (which mints a new dir rather than resuming) stays
marker-bearing and invisible — inert dead weight, minus the
crash-looping supervisor it used to attract.

Mid-claim forks stay out of `volume list`: the listing enumerates
`by_name/`, and a claiming dir has no symlink until `finalize` (the
reconcile skip keeps it that way).

## Open questions

- Garbage collection of abandoned partial forks (marker present, no
  in-flight job, record pointing elsewhere) — manual `rm -rf` works
  today; is an automatic sweep worth it?
- The incident's durable outcome shows a second-order gap: nothing
  detects a daemon serving a segment set narrower than the fork's
  on-disk `index/`. The gate removes the known cause; the GC-commit
  enforcement of the single-writer rule is designed in
  `read-state-divergence-check.md`.
- `volume fork` and ancestor pulls also materialise directories over
  several steps, but with content complete-by-reference throughout —
  no openable-but-incomplete window. They keep their existing
  ordering; adopting the marker there would be hygiene, not a fix.
