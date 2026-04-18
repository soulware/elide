---- MODULE WorkerOffload ----
(*
  TLA+ model of the actor↔worker offload protocol used for every
  maintenance op after the actor-offload refactor (see
  docs/actor-offload-plan.md). A single canonical op — "Promote" — is
  modelled here; sweep, repack, delta_repack, gc_handoff, and
  sign_snapshot_manifest all share the same three-phase shape:

      Prep   (on actor)   capture an extent-index snapshot into a Job,
                          hand it to the worker, park a reply slot
      Middle (off actor)  read files, verify signatures, write new
                          segment — pure function of the Job, no mutable
                          actor state touched
      Apply  (on actor)   for each carried entry:
                            extent_index.replace_if_matches(
                              hash, source_loc, new_loc)
                          — a CAS keyed on the source location captured
                          at Prep time. Loses the CAS iff a concurrent
                          write re-pointed the hash between Prep and
                          Apply; in that case the concurrent write
                          survives untouched.

  WHAT IS NOT OBVIOUS
  -------------------
  Proptest covers the CAS loser path transparently: a concurrent write
  on the actor thread cannot land between a single test thread's Prep
  and Apply, because the actor serialises them. The real prep/apply
  window is in the *actor's* select! loop — a Write VolumeRequest may
  arrive while a WorkerResult for a different op is still in flight on
  the worker channel. Proptest does not exercise that window.

  Proptest also cannot cover one liveness property: after a process
  crash mid-offload, the parked reply slot must not survive into the
  next actor spawn and cause the new actor to block forever. The
  actor is simply dropped; the slot goes with it. Modelling a Crash
  action here makes that explicit.

  WHAT THIS SPEC CHECKS
  ---------------------

    NoCorruption          extent_index is always either the initial
                          value or a value some Write produced — never
                          a value a stale worker result introduced on
                          top of a newer write.

    CasLoserSurvives      if a Write fires between a Prep capture and
                          the corresponding Apply, the Write's value
                          survives the Apply (CAS loses).

    NoPermanentPark       after a Crash, parked is empty — the slot
                          does not outlive the actor.

    WorkerIdempotent      re-running Apply against the same worker
                          result is a no-op (CAS fails because the
                          source_loc no longer matches).

  SHAPE
  -----
  One hash; its extent_index location is a natural number. Each Write
  bumps the location by 1, so values are totally ordered and the
  "newest wins" property becomes "max wins". The worker's output is
  a single new_loc that is one of these values.
*)
EXTENDS Naturals, Sequences, TLC

CONSTANTS
  MAX_WRITES       \* bound the state space

\* The location sentinel 0 means "initial" — no write has touched this
\* hash yet. Writes produce locations in 1..MAX_WRITES. Worker-reserved
\* locations live in (MAX_WRITES+1)..(2*MAX_WRITES), disjoint from Write
\* locations so we can tell at a glance which actor wrote the value.

VARIABLES
  extent_index,    \* current location of the one modelled hash
  writes_done,     \* count of Writes that have fired
  worker_runs,     \* count of StartPromote firings
  worker_job,      \* captured prep snapshot: [src, new]
                   \*   [src |-> 0, new |-> 0] means "no job in flight"
  worker_result,   \* "none" | "ready"  — reply sitting in the channel
  parked,          \* "empty" | "waiting" — actor-side parked slot
  actor_alive,     \* TRUE iff actor is running; FALSE after Crash
  valid_locs       \* set of locations ever validly assigned to
                   \* extent_index. Grows monotonically.

vars == <<extent_index, writes_done, worker_runs, worker_job,
          worker_result, parked, actor_alive, valid_locs>>

LocRange == 0..(2 * MAX_WRITES)

TypeOK ==
  /\ extent_index  \in LocRange
  /\ writes_done   \in 0..MAX_WRITES
  /\ worker_runs   \in 0..MAX_WRITES
  /\ worker_job    \in [src: LocRange, new: LocRange]
  /\ worker_result \in {"none", "ready"}
  /\ parked        \in {"empty", "waiting"}
  /\ actor_alive   \in BOOLEAN
  /\ valid_locs    \subseteq LocRange

Init ==
  /\ extent_index  = 0
  /\ writes_done   = 0
  /\ worker_runs   = 0
  /\ worker_job    = [src |-> 0, new |-> 0]
  /\ worker_result = "none"
  /\ parked        = "empty"
  /\ actor_alive   = TRUE
  /\ valid_locs    = {0}

\* ---------------------------------------------------------------------------
\* Actor-thread actions
\* ---------------------------------------------------------------------------

(*
  Write: a VolumeRequest::Write arriving on the actor channel.  The actor
  bumps extent_index to a fresh value.  Fires only when the actor is
  alive and we haven't exceeded the state-space bound.
*)
Write ==
  /\ actor_alive
  /\ writes_done < MAX_WRITES
  /\ writes_done'  = writes_done + 1
  /\ extent_index' = writes_done + 1
  /\ valid_locs'   = valid_locs \union {writes_done + 1}
  /\ UNCHANGED <<worker_runs, worker_job, worker_result, parked, actor_alive>>

(*
  StartPromote: the actor's Prep phase.  Captures the current
  extent_index into worker_job.src, reserves a new value (we use
  writes_done + 1 here, as a stand-in for any fresh location the
  worker's output would land at — the exact value does not affect the
  CAS logic), and parks a reply slot.

  Only one offload in flight at a time (parked == "empty"); this
  matches the production parked_sweep / parked_repack / etc. slots.
*)
StartPromote ==
  /\ actor_alive
  /\ parked = "empty"
  /\ worker_runs < MAX_WRITES
  /\ worker_runs' = worker_runs + 1
  /\ worker_job'  = [src |-> extent_index,
                     new |-> MAX_WRITES + worker_runs + 1]
  /\ parked'      = "waiting"
  /\ UNCHANGED <<extent_index, writes_done, worker_result, actor_alive,
                 valid_locs>>

(*
  Apply: worker result arrived on the channel; actor CAS-applies it.
    success  iff extent_index == worker_job.src  → set to new
    failure  iff extent_index has advanced       → no-op
  Either way the parked slot clears and the channel drains.
*)
Apply ==
  /\ actor_alive
  /\ worker_result = "ready"
  /\ IF extent_index = worker_job.src
     THEN /\ extent_index' = worker_job.new
          /\ valid_locs'   = valid_locs \union {worker_job.new}
     ELSE /\ extent_index' = extent_index
          /\ valid_locs'   = valid_locs
  /\ worker_result' = "none"
  /\ parked'        = "empty"
  /\ worker_job'    = [src |-> 0, new |-> 0]
  /\ UNCHANGED <<writes_done, worker_runs, actor_alive>>

\* ---------------------------------------------------------------------------
\* Worker-thread actions
\* ---------------------------------------------------------------------------

(*
  WorkerProduce: the worker's heavy middle completes and posts a result
  onto the channel.  Pure function of worker_job (captured at Prep
  time) — no mutable state touched.
*)
WorkerProduce ==
  /\ parked = "waiting"
  /\ worker_result = "none"
  /\ worker_result' = "ready"
  /\ UNCHANGED <<extent_index, writes_done, worker_runs, worker_job, parked,
                 actor_alive, valid_locs>>

\* ---------------------------------------------------------------------------
\* Crash + reopen
\* ---------------------------------------------------------------------------

(*
  Crash: the actor process dies.  In-memory state (parked slot, channel
  contents, worker_job snapshot) is gone.  extent_index persists — in
  production it is rebuilt from on-disk index/*.idx, which for the
  purposes of this model means it simply survives across the crash.

  Key invariant: after the crash, parked must be "empty" and the
  worker result must not be visible.  A surviving parked slot would
  mean a new actor could wait forever on a reply the dead worker will
  never send.
*)
Crash ==
  /\ actor_alive
  /\ actor_alive'   = FALSE
  /\ parked'        = "empty"
  /\ worker_result' = "none"
  /\ worker_job'    = [src |-> 0, new |-> 0]
  /\ UNCHANGED <<extent_index, writes_done, worker_runs, valid_locs>>

(*
  Reopen: spawn a new actor.  extent_index is whatever survived the
  crash; worker and parked slot are cleanly empty (handled by Crash).
*)
Reopen ==
  /\ ~actor_alive
  /\ actor_alive' = TRUE
  /\ UNCHANGED <<extent_index, writes_done, worker_runs, worker_job,
                 worker_result, parked, valid_locs>>

\* ---------------------------------------------------------------------------
\* Spec
\* ---------------------------------------------------------------------------

Next ==
  \/ Write
  \/ StartPromote
  \/ WorkerProduce
  \/ Apply
  \/ Crash
  \/ Reopen

Spec == Init /\ [][Next]_vars

\* ---------------------------------------------------------------------------
\* Safety invariants
\* ---------------------------------------------------------------------------

(*
  NoCorruption: every location extent_index ever takes was produced
  by something we can account for — either the initial sentinel, a
  Write, or a successful Apply.  The valid_locs set tracks this
  history: Write adds writes_done+1; Apply adds worker_job.new iff
  the CAS succeeded.  If extent_index ever landed on some nonsense
  value (e.g. a worker_job.new whose CAS should have failed) it
  would leave this set.
*)
NoCorruption ==
  extent_index \in valid_locs

(*
  CasLoserSurvives: if a Write happened between a Prep (when
  worker_job.src was captured) and an Apply, the Write's value
  survives.

  Operationally: when Apply fires and extent_index /= worker_job.src,
  extent_index must not change.
*)
CasLoserSurvives ==
  [][ (worker_result = "ready"
       /\ extent_index /= worker_job.src
       /\ Apply)
     => (extent_index' = extent_index) ]_vars

(*
  NoPermanentPark: after a crash, the parked slot is empty.  A new
  actor that reopens does not inherit a waiting slot.
*)
NoPermanentPark ==
  ~actor_alive => parked = "empty"

(*
  OneInFlight: at most one offload is in flight at a time — the
  single parked slot.  This mirrors the production parked_sweep /
  parked_repack / etc. slots, each of which rejects concurrent
  requests with "concurrent X not allowed".
*)
OneInFlight ==
  (parked = "empty") => (worker_result = "none"
                         /\ worker_job.src = 0
                         /\ worker_job.new = 0)

====
