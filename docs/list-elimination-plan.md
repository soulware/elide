# LIST-elimination plan

Remove every `s3:ListBucket` use from the coordinator runtime. Each
prefix LIST becomes a deterministic GET; then the `ListBucket`
statement is deleted from `coord-writer`'s role template and from
`design-mint.md` (resolves open question #12). The decision stands
independent of whether Tigris can prefix-scope `ListBucket` — that is
parked (`design-mint.md` #12); this work is the backend-portable answer
and a long-wanted perf win regardless.

Authority: `design-mint.md` § *`coord-writer`* / open question #12.
Related: `design-volume-event-log.md` (event HEAD pointer),
`design-peer-segment-fetch.md`.

## The LIST surface (from a full sweep of `elide-coordinator/src`)

| Prefix LISTed | Call sites | What it derives | Role today |
|---|---|---|---|
| `by_id/<vol>/snapshots/` | `fetch.rs:325`, `fork.rs:561`, `prefetch.rs:949`, `start_remote.rs:147` | max snapshot ULID + its dated `.manifest` key | `coord-data` |
| `by_id/<vol>/snapshots/` | `inbound/lifecycle.rs:777`, `inbound/lifecycle.rs:1502` | the *set* of snapshots, for cleanup/delete | `coord-data`/`writer` |
| `by_id/<vol>/segments/` | `prefetch.rs:442`, `fork.rs:670`, `recovery.rs:165` | the live segment-ULID set for the volume | `coord-data` |
| `by_id/<vol>/retention/` | `prefetch.rs:643` (`list_supersessions`), `reaper.rs:80` | GC supersession markers (input→output) | `coord-data` |
| `events/<name>/` | `peer_discovery.rs:171`, `volume_event_store.rs:155/253` | the event-record set / head for a name | `coord-writer` |

`config.rs:289` (`probe`, bare `by_id/`) is the *non*-mint passthrough
reachability check — not on the mint path, out of scope.

Keys are date-partitioned (`…/snapshots/YYYYMMDD/<ulid>.manifest`,
`…/segments/YYYYMMDD/<ulid>`), so today's LIST is a recursive prefix
scan; the substitutes below do not need the date partition.

## Substitution design

### Identity axes — why snapshots split cleanly

`name` and `vol_ulid` are two identity axes, instantaneously
bijective for a live name but **not stable over time**:

- **`names/<name>`** — stable ownership identity. Its lifecycle
  (Created/Claimed/Released/ForceReleased/Renamed/ForkedFrom) is
  intrinsically per-*name* — ownership CAS, cross-host handoff
  rendezvous, rename — and *cannot* move to per-vol: a claiming
  coordinator finds the volume **through the name**; it does not know
  the new `vol_ulid` until it reads the name. This is the event log,
  `events/<name>/`, under `coord-writer`.
- **`by_id/<vol_ulid>/`** — the data (segments/snapshots/retention),
  per-*vol_ulid*, under `coord-data`. A name walks through a sequence
  of `vol_ulid`s over its life (fork lineage); a `vol_ulid`'s data
  outlives the instant (ancestors are read by descendants).

Role restriction did not create this coupling — it made a pre-existing
axis crossing legible. Snapshots split along it exactly, and
respecting the split (rather than forcing a cross-axis write) is what
keeps the design simple:

The latest-snapshot need splits into a *benign* per-vol case and a
*correctness-sensitive* per-name case, and each goes to the substitute
that cannot skew for it:

- **Per-vol "latest stable basis" — a single `by_id/<vol>/snapshots/LATEST`
  pointer (`User` snapshots only).** Body is the bare snapshot ULID.
  Written GET-max-PUT (no CAS — single-writer per vol) in
  `upload_snapshot_manifests` immediately after the manifest PUT,
  **under `coord-data` only — no cross-role write, no event**. Migrates
  `fetch.rs:325`, `fork.rs:561`, `prefetch.rs:947`,
  `start_remote.rs:147`, `lifecycle.rs:777`. Here a stale/lost pointer
  is genuinely benign and self-heals on the next publish: these
  consumers fetch a basis and then catch up via segments, so an old
  basis only costs extra GETs, never data. A pointer is the right tool
  *because* the failure mode is harmless.
- **Per-name "the handoff/fork/stop point" — on the event-log spine,
  not a pointer.** The cross-epoch references are name-axis facts and
  must commit atomically with the ordered, CAS'd `events/<name>/HEAD`
  (P1), so there is no separate mutable object to skew:
  - `Released`/`ForceReleased` carry `handoff_snapshot`, `ForkedFrom`
    carries `source_snap_ulid` (already today). Covers the claim path
    and `lifecycle.rs:560/707` — `latest_release_handoff_snapshot`'s
    LIST is *pure redundancy* (recomputes a ULID the `Released` event
    already records; the releaser also knows it directly).
  - **New `EventKind::Stopped { checkpoint_snapshot }`**, emitted at
    `volume stop`. `Stopped` is a durable resting state (a host can
    die while a volume is parked, having cleanly stopped but never
    released — `Released` never fires, so its `handoff_snapshot`
    cannot carry the basis). This is the missing `Live→Stopped`
    lifecycle transition the event log should record anyway; it is
    *not* per-snapshot spam (one event per `volume stop`, lifecycle
    cadence — steady-state `User` snapshots emit nothing). Recovery
    (`recovery.rs:379/384`) reads the latest of
    `{Released, ForceReleased, Stopped}` checkpoint off the HEAD
    window; absent → segment-list synthesis exactly as today. This is
    why there is **no `LATEST-stop` pointer**: the recovery basis is
    the one place a pointer's manifest-then-crash-before-bump window
    *would* lose committed data (no "next seal" after a crash), so it
    goes on the spine where the event append *is* the commit point.
  - **Leftover `-stop` cleanup** (`lifecycle.rs:1502`) — the `-stop`
    being swept is the `Stopped`/`Released` checkpoint; delete by
    known key from the event, no per-vol enumeration.

A full sweep confirms **no consumer needs a per-vol snapshot *set***:
there is no stable-snapshot retention/GC enumerator, and `prefetch`
resolves ancestor snapshots from the *branch ULID in signed
provenance* (name-axis lineage), only the writable head wanting the
per-vol `LATEST`. So no `SnapshotPublished`/`SnapshotDeleted` events,
no snapshot projection, no snapshot index — snapshots are a single
benign per-vol pointer plus the handoff/fork/stop references the
per-name event spine carries.

### The event-log spine (existing events, existing back-links)

- **`events/<name>/HEAD` — a bounded window, not a scalar pointer.**
  `HEAD` carries the **last *N* events as full signed records**,
  rebuilt on every append as `new_HEAD = (new_event :: old_HEAD)[..N]`
  — one conditional-PUT, the same write that advances ordering today,
  just carrying *N* compact entries instead of one ULID. Events are
  tiny (ULID + enum + coord id + sig); N≈16 is a few KB.

  **`prev_event_ulid` is already on every record** (`volume_event.rs`,
  written by `emit_event`), so the authoritative chain already exists;
  what is LIST-based today is only latest-ULID *discovery*
  (`latest_event_ulid`) and the two walkers choosing LIST+sort over
  the link that is already there. **No event-format change, no new
  event kinds.**

  **HEAD is the ordering authority, but not the integrity authority.**
  HEAD decides *which event is latest* (so `emit` never needs a LIST),
  but each entry is still the already-individually-signed event
  record, so a tampered entry fails the existing per-event signature
  check. Integrity rests on the per-event signatures + the
  `prev_event_ulid` chain exactly as today; only *ordering discovery*
  moved from LIST to HEAD.

  **Write order — HEAD *before* the record PUT.** `emit` reads HEAD
  (+etag), derives `prev = HEAD[0]`, writes the new entry onto HEAD
  (`If-Match` etag for a normal emit; *unconditional* for the
  `release --force` emit), *then* PUTs the immutable record
  (`If-None-Match:*`). The `If-Match` is **not** a serializer with a
  retry loop — normal appends are already single-writer by
  `names/<name>` ownership (§ *Single-writer*), so a mismatch never
  means "lost a race": it means **this coordinator has been
  displaced** (only `release --force` can change HEAD under a
  still-alive owner) → **fail hard**, no retry, no merge. A crash
  between the HEAD write and the record PUT leaves HEAD naming an
  event whose body is absent: a reader GETs it, 404s, and **skips the
  phantom entry** — the same tolerate-the-dangling-reference pattern
  the segment/retention index uses (§ *Reconcile*). Ordering is never
  wrong; the only residue is a benign, self-describing phantom (a HEAD
  entry whose 404 says "announced, body never landed, ignore"),
  optionally compacted out on the next successful append.

  This is the **deliberate inverse** of the segment/retention index's
  ordering (object-before-index): there the index trails
  object-authoritative data so a crash leaks a reclaimable object;
  here HEAD *is* the ordering authority so it must lead, and a crash
  leaks a skippable phantom. Two structures, two authority models, two
  write orders — stated explicitly so neither rule is misapplied to
  the other. HEAD's authoritative "rebuild" remains the
  prev-walk / elevated LIST (the project invariant for derived state:
  the rebuild defines correctness).

  **Single-writer by ownership; `release --force` is the only
  exception.** The `names/<name>` conditional update is already the
  serialization point: an event is emitted *only after* a won
  ownership transition (`claim.rs:628` emits `Claimed` solely on the
  `MarkClaimedOutcome::Claimed` branch — losers never reach `emit`).
  Fork is a fresh name; rename is single-owner. So in normal
  operation exactly one coordinator appends to a name's log, and
  `emit` needs no cross-coordinator concurrency control — only an
  in-process per-name lock so a coordinator's own concurrent tasks
  don't race (reuse the existing per-name lock registry if present).

  The **sole** multi-writer case is `release --force` with a
  still-alive displaced owner A. Authority/ordering rules:

  - **Authority before journal.** The decisive act is the
    *unconditional* `names/<name>` overwrite (Released, `handoff=Sh`,
    `displaced=A`); the `ForceReleased` event is the journal entry
    that *follows* it. Full order: synthesize+write `Sh` → unconditional
    `names/<name>` overwrite → event append (HEAD then record). This
    is unchanged behaviour — `finalize_force_release` already runs only
    after the overwrite. Reversing it (journal before authority) lets
    a crash leave the log asserting a `ForceReleased` the authority
    never made *and* fence the legitimate owner with no transfer → a
    self-inflicted **ownership vacuum**. Authority-first leaves only a
    recoverable journal gap (best-effort contract).
  - **The force-releaser B never fails.** Its `ForceReleased` HEAD
    write is **unconditional** (mirroring the unconditional
    `names/<name>` overwrite — force is the override at both layers).
  - **The displaced A fails hard *on the name*, not its data.** A is
    fenced at the authoritative layer the instant the name overwrite
    lands (A's own `If-Match` name-ops fail). B's unconditional HEAD
    write also bumps the etag, so A's next normal `If-Match` emit
    fails — a *secondary* displacement detector → A stops touching
    `names/<name>`/`events/<name>/`. A's `by_id/<V_a>/` lineage is
    **untouched** and survives as an unnamed, recoverable fork
    (claim-after-force forks a new `vol_ulid` from `Sh`; `V_a` is
    never overwritten). "Fail hard" = lose the *name*, not the data.

  `events/<name>/` therefore stays a **single clean chain** (B's, post-
  `ForceReleased`); A's post-displacement activity is a *different
  lineage*, not entries in this name's log. The log *records* the
  displacement (`displaced_coordinator_id`); it does not *resolve* the
  data-plane fork — that, and any **automatic fork-continuation** for
  the displaced lineage, is explicitly **out of scope here** (future
  direction; `design-force-release-fencing.md`). If A crashed mid-emit
  (HEAD write done, record PUT not), the full signed record is still
  inline in HEAD, so in-window readers are unaffected; the missing
  standalone object only truncates a past-window prev-walk, optionally
  self-healed by an idempotent `If-None-Match:*` backfill from the
  in-HEAD copy.

  Replaces `peer_discovery.rs:171`, `volume_event_store.rs:155/253`.
  Key shape coordinated with `design-volume-event-log.md`. Runs under
  `coord-writer`. *N* is a tuning param (default ≈16), not pinned by
  the design.

#### Access patterns (always bounded; no unbounded path exists)

1. **Append** — `GET HEAD`+etag, derive `prev = HEAD[0]`, CAS `HEAD`
   (`If-Match`), then PUT the record (`If-None-Match:*`). O(1), no
   walk. The common write path
   (`Created`/`Claimed`/`Released`/`Renamed`); replaces
   `latest_event_ulid`'s LIST.
2. **Claim / peer-discovery** — the decisive event
   (`Released`/`ForceReleased`/`ForkedFrom`) and its payload are
   almost always within the last *N*, so they are **in the HEAD GET
   itself — zero extra hops**. Only a pathological tail (>*N* events
   since the last `Released`) falls back to the bounded
   `prev_event_ulid` walk. Subsumes the redundant
   `latest_release_handoff_snapshot` LIST. (Peer-discovery still does
   one *keyed* GET for the releaser's `coordinators/<id>/peer-endpoint`
   — not a walk, unavoidable.)
3. **Operator `volume events`** — always bounded by an explicit
   count. Default = the HEAD window size *N* (served entirely from the
   one HEAD GET, **zero walk**). `--num <n>` requests the most-recent
   *n*; `n ≤ N` is still zero-walk, `n > N` walks `prev` for the
   extra (LIST-free, bounded by *n*, crossing `inherits_log_from`
   only if *n* exceeds the current name's chain). **There is no
   `--all` / unbounded / to-genesis option** — full reconstruction is
   not a product surface; it is the elevated offline LIST rebuild in
   § *Reconcile* (operator-privileged, not this CLI).
   `list_events`' whole-prefix LIST goes away.

So at runtime the chain is never walked unboundedly: appends are a
single GET+PUT; the common claim/peer-discovery and the default
history view are answered from the one HEAD GET; the only `prev` walk
is a long unclaimed tail or an operator-supplied `--num n > N`, both
bounded.

### Maintained index (`segments`, `retention` only)

The genuinely high-cardinality per-write sets — accreted by the WAL
drain and GC, pruned by the reaper — are too large to fold from a
chain on every read, so they keep a dedicated per-volume index object
(`coord-data`, same axis as the data):

- **segment index** — appended by the drain (`upload.rs`) as each
  segment is uploaded and by GC as it writes outputs; the reaper
  tombstones entries it deletes. Replaces `prefetch.rs:442`,
  `fork.rs:670`, `recovery.rs:165`.
- **retention index** — appended by GC with each supersession marker.
  Replaces `prefetch.rs:643`, `reaper.rs:80`.

These two may collapse into one per-volume append-only "manifest
delta log" — an implementation choice deferred to its phase, but
constrained by the next section. Snapshots are deliberately **not**
here (per-vol pointer + per-name handoff references, above).

### Worked example — a release/claim cycle

Coordinator **A** owns `myvol`; **B** later claims it. Every step is a
GET or a known-key PUT/DELETE — no LIST.

1. **Steady state (A).** A seals snapshot `S2`: writes
   `by_id/<vol>/snapshots/<date>/S2.manifest` then bumps
   `by_id/<vol>/snapshots/LATEST → S2` (bare ULID, `User` only). Both
   writes are per-vol, **`coord-data` only** — no event, no
   `coord-writer`.
2. **Release (A).** A seals the handoff/stop snapshot `Sh` (it knows
   `Sh`'s ULID directly — it just minted it), CASes `names/myvol`
   Live→Released, then appends to `events/myvol/`: CAS `HEAD` with
   `Released{handoff_snapshot: Sh}`, then PUT the record. This event
   **already exists today**; nothing new on the name axis.
3. **Claim (B).** B CASes `names/myvol` Released→Claimed. It learns
   the fork point from the **single `HEAD` GET** — `Released{handoff:
   Sh}` is in the window (no `prev` walk in the common case;
   replacing the redundant `latest_release_handoff_snapshot` LIST). B
   appends `Claimed` (CAS `HEAD`, then PUT the record).
4. **Hydrate (B).** From `Sh.manifest` (a GET, key known from step 3)
   B gets the segment ULID set — the manifest already enumerates
   segments, so no LIST; any segment not local is range-GET by
   deterministic key.
5. **Stop-snapshot cleanup (B).** Today `lifecycle.rs:1502` LISTs the
   snapshot prefix to find leftover `-stop` objects. `Sh` is already
   known from step 3's event walk: B `DELETE`s `Sh` by known key. No
   LIST, no new marker.

**Unclean variant.** If A had instead `stop`ped `myvol` and the host
died while it was parked (never reaching step 2's `Released`), step 2
is absent — but A's `volume stop` emitted `Stopped{checkpoint: Sh}` on
the same HEAD spine. B's force-release reads `Sh` from the HEAD window
exactly as step 3 reads `Released`; the recovery basis never depended
on the per-vol pointer, so the manifest-then-crash-before-bump window
cannot lose it.

The invariant the example illustrates: **the name axis (event log)
carries ownership and the cross-epoch handoff/fork snapshot
references; the vol axis carries the data and a per-vol `LATEST`
pointer. Neither writes across to the other; every read is a chain
walk from `HEAD` or a known-key GET.**

### Reconcile/repair without LIST

LIST is today's implicit source of truth ("what is actually in the
bucket"). Removing it removes that self-heal, so the plan must replace
it, not merely delete it:

- **Snapshots / event spine have no LIST reconcile to add.** The
  per-name handoff/fork references live in events that already exist
  and are durable on the chain (`HEAD` durability is
  `design-volume-event-log.md`'s concern, not redesigned here). The
  per-vol `snapshots/LATEST` pointer is not a correctness datum: it
  serves only the clean data-axis consumers (`User` basis), is
  reconstructable from local volume state, and is overwritten by the
  next publish, so a lost/stale pointer self-heals — a perf event, not
  a correctness one. This holds *because* the one
  correctness-sensitive case — the unclean-recovery basis — was kept
  off the pointer and put on the event spine (`Stopped` / `Released` /
  `ForceReleased`), where there is no manifest-then-crash-before-bump
  window to lose.
- **The segment/retention index is authoritative for the runtime**;
  readers trust it. Divergence is bounded and one-directional by
  construction if the
  index entry is written *after* the object PUT and *before* the
  operation reports success: a crash can leave an object with no index
  entry (a reclaimable space leak — never a correctness loss, since an
  un-indexed segment is simply not consumed), never an index entry
  with no object on a path that matters (readers already tolerate a
  `404` on segment fetch — `list_supersessions` explicitly does).
- The **rebuild defines correctness** (cf. the project invariant for
  derived state with rebuild + incremental paths): the
  segment/retention index's authoritative regeneration is a one-time
  elevated LIST, and the incremental drain/GC/reaper updates must
  structurally match what that rebuild would produce — asserted in the
  proptest model (below), not by convention.
- Orphan reclamation (un-indexed objects) is an **explicit operator
  maintenance pass** that may use a privileged LIST under a separate
  elevated credential — deliberately *not* the coordinator runtime or
  the exposed surface. Runtime stays LIST-free; this keeps the "no
  optional correctness path in runtime" principle intact (repair is
  explicit and privileged, not a silent fallback).

## Phasing

Each phase is independently shippable and leaves the tree green; no
phase introduces a dual LIST+index runtime fallback (that would defeat
the purpose and is itself an optional-correctness path).

Ordered so each phase builds on the prior.

- **P1 — event-log spine: windowed `events/<name>/HEAD`.** Add the
  `HEAD` object carrying the last *N* signed records (HEAD CAS
  `If-Match` *before* the record PUT — § *spine*). `emit_event`
  reads/advances `HEAD` instead of LIST-max; `peer_discovery` and
  `volume_event_store` read the window, 404-tolerant on entries,
  falling back to the **already-present** `prev_event_ulid` walk only
  on a long tail.
  **No event-format change, no new event kinds.** Change `volume
  events` to always-bounded: default = window size *N*, `--num <n>`
  for more (no `--all`/unbounded option; `list_events`' whole-prefix
  LIST is removed, not replaced by a deeper walk). Align key/shape
  with `design-volume-event-log.md`. Also gives the claim path its
  handoff from the HEAD window via the existing `Released`/`ForkedFrom`
  events.
- **P2 — per-vol `snapshots/LATEST` pointer.** Write it (per kind) at
  publish under `coord-data`; migrate the latest-snapshot consumers
  (`fetch.rs:325`, `fork.rs:561`, `prefetch.rs:949`,
  `start_remote.rs:147`, `lifecycle.rs:777`). Repoint the handoff /
  cleanup consumers (`lifecycle.rs:560/707/1502`) at the P1 chain
  walk / known-key delete. Removes every snapshot LIST; no new events,
  no cross-role write.
- **P3 — segment index.** Drain + GC maintenance, crash-ordering as
  above; migrate `prefetch`/`recovery`/`fork-verify`; define + test
  the reconcile invariant.
- **P4 — retention index** (or fold into P3's delta log); migrate
  `prefetch` supersession and `reaper`.
- **P5 — drop the grant.** Delete `s3:ListBucket` from
  `mint/examples/elide_roles/coord-writer.json`, the §*`coord-writer`*
  policy, and the role-inventory table in `design-mint.md`; add a CI
  grep guard that no `.list(` reaches a mint-backed store. End state:
  no role carries `ListBucket`.

## Back-compat

Clean break (project default). Indexes/pointers are derived state,
regenerated once by an elevated offline migration (or by republishing
a snapshot). No on-disk format negotiation, no runtime dual path.

## Validation

- Per phase: targeted unit/integration tests.
- The proptest simulation already drives drain/GC/reaper; extend it so
  the index — not a LIST — is the queried set, and assert the
  index ≡ object-set invariant after every op, including crash
  injection between object PUT and index append (proptest-guardian
  scope).
- End-to-end on the Tigris VM with `coord-data` carrying no
  `ListBucket` and `coord-writer`'s `ListBucket` removed.

## Out of scope / revisit later

- Whether Tigris honours prefix-scoped `ListBucket` (`design-mint.md`
  #12). If it does, this work still stands (perf + portability); it
  only relaxes the security urgency.
- `volume list --remote` and any operator-facing bucket enumeration —
  these legitimately enumerate and run under an explicit elevated
  credential, not the coordinator runtime; they are not in this
  removal.
- The interim credential posture before P5 lands (the per-volume LIST
  paths fail on Tigris under `coord-data` until then) — a separate
  decision, tracked with the mint cutover, not here.
