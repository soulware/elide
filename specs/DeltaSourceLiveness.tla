---- MODULE DeltaSourceLiveness ----
(*
  TLA+ model of the three mechanisms that together keep a Delta entry's
  source extent present for as long as the Delta names it.

  WHY A SEPARATE MODULE FROM WorkerOffload
  ----------------------------------------
  WorkerOffload models one offloaded op against concurrent writes, and
  asserts OneInFlight — at most one op on the worker. The hazard here is
  a *cross-op* interleaving: a promote is in flight while a GC plan apply
  lands. That is excluded by construction there, so it needs its own
  model.

  THE HAZARD
  ----------
  A promote captures index state at Prep on the actor, decides against
  that snapshot on the worker (off-lock), and commits at Apply. A delta
  is the only reference a promote commits that can name an extent nothing
  else references: a DedupRef or a carried entry names live content, and
  a rewrite must carry live content forward, so those cannot dangle.

  A GC plan removes the extents GC found dead. If one lands between a
  promote's Prep and its Apply, the promote can commit a delta naming an
  extent that is already gone — an unreadable extent, which for a block
  device is corruption, not a cost.

  Detecting this at Apply is not an option in the implementation: by then
  the pending segment is committed and the old WAL consumed, so there is
  nothing to roll back to. Both mechanisms below are therefore
  preventative.

  THE THREE MECHANISMS
  --------------------
    1. LIVENESS FILTER (delta_compute::delta_pendings_by_resemblance)
       The worker only chooses a source that was referenced at Prep. The
       candidate map is a never-pruned cache built from historical .idx
       walks, so without this it offers extents whose last claim is long
       gone — and a dead extent resembles whatever superseded it, so the
       likeliest-dead sources rank first.
       Modelled by: PromoteChoose requiring src \in job_referenced.

       This one is NOT required for NoDanglingDeltaSource; see the
       ablation results below. What it buys is cost: not pinning bytes GC
       was about to free, and not provoking the plan cancellations that
       mechanism 3 would otherwise have to make. Its justification is the
       frequency argument — dead sources accumulate and rank first — which
       is not a safety property and is not checkable here.

    2. APPLY ORDERING (actor::apply_or_defer_gc_plan)
       A finished plan-apply result is held until no promote is in
       flight. Closes the case where a source is referenced at Prep and
       its last claim disappears mid-promote.
       Modelled by: PlanApply requiring promote = "idle", PlanDefer
       otherwise.

    3. STALE-LIVENESS CANCELLATION (volume::apply_plan_apply_result)
       A plan is cancelled if it would drop a hash the volume now
       considers referenced. Closes the reverse order: the promote
       applies first, so the delta's source refcount makes the extent
       live, and the plan that would have dropped it is refused.
       Modelled by: PlanApply cancelling when drop_set intersects
       referenced'.

  Mechanisms 2 and 3 are each necessary for NoDanglingDeltaSource; 1 is
  not. See the measured ablation results below.

  WHAT THIS SPEC CHECKS
  ---------------------
    NoDanglingDeltaSource   every committed delta's source extent is
                            still present. This is the property whose
                            violation is an unreadable extent.

    NoApplyInsidePromote    no plan apply commits while a promote is in
                            flight. The mechanism, checked directly so a
                            regression in the deferral shows up as
                            itself rather than only via a downstream
                            dangle.

    DeferredEventuallyApplies
                            a deferred plan is not held forever.

  ABLATION RESULTS (measured, MAX_EXTENTS = 3)
  --------------------------------------------
  Baseline: 3266 distinct states, depth 14, everything holds.

    Drop mechanism 1 — remove `src \in job_referenced` from
      PromoteChoose. NoDanglingDeltaSource STILL HOLDS (3566 distinct
      states). Choosing a dead source is safe here because PromoteApply
      adds it to `referenced`, after which mechanism 3 refuses any plan
      that would drop it. The filter is a cost measure, not a safety one.

    Drop mechanism 2 — let PlanApply fire regardless of `promote`.
      Violates NoApplyInsidePromote immediately, and with that property
      unchecked, violates NoDanglingDeltaSource at depth 8:
        Write(1) → StartPromote(2) → Unreference(1) → PromoteChoose(1)
        → StartPlan → PlanApply → PromoteApply
      The claim on 1 goes away *after* Prep, so the filter admits it;
      the plan drops it before the delta commits. Mechanism 1 cannot
      reach this case and mechanism 3 does not see it, because the
      delta's reference does not exist yet when the plan applies.

    Drop mechanism 3 — replace the cancellation branch with an
      unconditional `present' = present \ plan_drop`. Violates
      NoDanglingDeltaSource. This is the mechanism doing most of the work,
      including covering the case mechanism 1 was assumed to own.

  Controls: with 1 and 2 both dropped, and with all three dropped, the
  invariant is still violated — so mechanism 1's pass above is a real
  result rather than the invariant being unreachable.

  SHAPE
  -----
  Extents are identifiers from 1..MAX_EXTENTS. `present` is what the
  index resolves; `referenced` is what the lbamap claims (claim
  refcounts plus delta source refcounts, which is exactly
  LbaMap::is_referenced). A delta is a pair [target, src]; committing
  one adds src to `referenced`, modelling the delta-source refcount.
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  MAX_EXTENTS      \* bound the state space

Extents == 1..MAX_EXTENTS

VARIABLES
  present,         \* extents the index resolves
  referenced,      \* extents the lbamap references (claims + delta srcs)
  deltas,          \* set of [target |-> e, src |-> e] committed
  written,         \* extents ever written, to bound Write
  promote,         \* "idle" | "prepped" | "chose"
  job_present,     \* index snapshot captured at promote Prep
  job_referenced,  \* referenced snapshot captured at promote Prep
  job_target,      \* the extent this promote is writing
  job_src,         \* chosen delta source, or 0 for none
  plan,            \* "idle" | "ready" | "deferred"
  plan_drop        \* extents this plan would remove

vars == <<present, referenced, deltas, written, promote, job_present,
          job_referenced, job_target, job_src, plan, plan_drop>>

TypeOK ==
  /\ present        \subseteq Extents
  /\ referenced     \subseteq Extents
  /\ written        \subseteq Extents
  /\ deltas         \subseteq [target: Extents, src: Extents]
  /\ promote        \in {"idle", "prepped", "chose"}
  /\ job_present    \subseteq Extents
  /\ job_referenced \subseteq Extents
  /\ job_target     \in 0..MAX_EXTENTS
  /\ job_src        \in 0..MAX_EXTENTS
  /\ plan           \in {"idle", "ready", "deferred"}
  /\ plan_drop      \subseteq Extents

Init ==
  /\ present        = {}
  /\ referenced     = {}
  /\ deltas         = {}
  /\ written        = {}
  /\ promote        = "idle"
  /\ job_present    = {}
  /\ job_referenced = {}
  /\ job_target     = 0
  /\ job_src        = 0
  /\ plan           = "idle"
  /\ plan_drop      = {}

\* ---------------------------------------------------------------------------
\* Ordinary volume activity
\* ---------------------------------------------------------------------------

(*
  Write: an extent lands and is claimed. Stands for a promote that needed
  no delta; the interesting promote is modelled explicitly below.
*)
Write(e) ==
  /\ e \notin written
  /\ written'    = written \union {e}
  /\ present'    = present \union {e}
  /\ referenced' = referenced \union {e}
  /\ UNCHANGED <<deltas, promote, job_present, job_referenced, job_target,
                 job_src, plan, plan_drop>>

(*
  Unreference: the extent's last claim goes away (its LBA is overwritten).
  It stays present — the index still resolves it — until a rewrite drops
  it. An extent named by a committed delta keeps its delta-source
  reference, so it does not become unreferenced.
*)
Unreference(e) ==
  /\ e \in referenced
  /\ ~(\E d \in deltas: d.src = e)
  /\ referenced' = referenced \ {e}
  /\ UNCHANGED <<present, deltas, written, promote, job_present,
                 job_referenced, job_target, job_src, plan, plan_drop>>

\* ---------------------------------------------------------------------------
\* Promote: Prep on the actor, Choose on the worker, Apply on the actor
\* ---------------------------------------------------------------------------

(*
  StartPromote: the actor's Prep. Captures both the index snapshot and
  the referenced snapshot — the latter is PromoteDeltaSpec.referenced,
  taken via LbaMap::referenced_hashes.
*)
StartPromote(t) ==
  /\ promote = "idle"
  /\ t \notin written
  /\ promote'        = "prepped"
  /\ job_present'    = present
  /\ job_referenced' = referenced
  /\ job_target'     = t
  /\ job_src'        = 0
  /\ written'        = written \union {t}
  /\ UNCHANGED <<present, referenced, deltas, plan, plan_drop>>

(*
  PromoteChoose: the worker picks a delta source, or none.

  MECHANISM 1 — the source must have been referenced at Prep. Drop the
  `src \in job_referenced` conjunct to see the filter earn its place.
*)
PromoteChoose ==
  /\ promote = "prepped"
  /\ promote' = "chose"
  /\ \/ /\ \E src \in job_present:
              /\ src \in job_referenced
              /\ src /= job_target
              /\ job_src' = src
     \/ job_src' = 0
  /\ UNCHANGED <<present, referenced, deltas, written, job_present,
                 job_referenced, job_target, plan, plan_drop>>

(*
  PromoteApply: the actor commits the segment. The target becomes
  present and claimed; a chosen source picks up a delta-source
  reference, which is what keeps it alive from here on.
*)
PromoteApply ==
  /\ promote = "chose"
  /\ present'    = present \union {job_target}
  /\ referenced' = referenced \union {job_target}
                     \union (IF job_src = 0 THEN {} ELSE {job_src})
  /\ deltas'     = IF job_src = 0
                   THEN deltas
                   ELSE deltas \union {[target |-> job_target,
                                        src |-> job_src]}
  /\ promote'        = "idle"
  /\ job_present'    = {}
  /\ job_referenced' = {}
  /\ job_target'     = 0
  /\ job_src'        = 0
  /\ UNCHANGED <<written, plan, plan_drop>>

\* ---------------------------------------------------------------------------
\* GC plan: computed by the coordinator, applied on the volume's actor
\* ---------------------------------------------------------------------------

(*
  StartPlan: the coordinator computes a plan. Its drop set is whatever
  is present but unreferenced *now* — a plan can only ever drop what it
  observed dead, which is why a plan computed before an extent died
  cannot drop it.
*)
StartPlan ==
  /\ plan = "idle"
  /\ plan'      = "ready"
  /\ plan_drop' = present \ referenced
  /\ UNCHANGED <<present, referenced, deltas, written, promote,
                 job_present, job_referenced, job_target, job_src>>

(*
  PlanDefer: MECHANISM 2. The result is finished on the worker but a
  promote is in flight, so the actor holds it.
*)
PlanDefer ==
  /\ plan = "ready"
  /\ promote /= "idle"
  /\ plan' = "deferred"
  /\ UNCHANGED <<present, referenced, deltas, written, promote,
                 job_present, job_referenced, job_target, job_src,
                 plan_drop>>

(*
  PlanApply: remove the drop set.

  MECHANISM 2 — requires `promote = "idle"`. Let it fire regardless to
  see the ordering earn its place.

  MECHANISM 3 — stale-liveness cancellation: if anything in the drop set
  is referenced by now, the whole plan is refused. Remove that branch to
  see the cancellation earn its place.
*)
PlanApply ==
  /\ plan \in {"ready", "deferred"}
  /\ promote = "idle"
  /\ IF plan_drop \cap referenced = {}
     THEN present' = present \ plan_drop
     ELSE present' = present            \* cancelled
  /\ plan'      = "idle"
  /\ plan_drop' = {}
  /\ UNCHANGED <<referenced, deltas, written, promote, job_present,
                 job_referenced, job_target, job_src>>

\* ---------------------------------------------------------------------------
\* Spec
\* ---------------------------------------------------------------------------

Next ==
  \/ \E e \in Extents: Write(e)
  \/ \E e \in Extents: Unreference(e)
  \/ \E t \in Extents: StartPromote(t)
  \/ PromoteChoose
  \/ PromoteApply
  \/ StartPlan
  \/ PlanDefer
  \/ PlanApply

Fairness ==
  /\ WF_vars(PromoteChoose)
  /\ WF_vars(PromoteApply)
  /\ WF_vars(PlanApply)

Spec == Init /\ [][Next]_vars /\ Fairness

\* ---------------------------------------------------------------------------
\* Safety
\* ---------------------------------------------------------------------------

(*
  NoDanglingDeltaSource: the property that matters. A delta whose source
  is absent is an extent the block device cannot read.
*)
NoDanglingDeltaSource ==
  \A d \in deltas: d.src \in present

(*
  NoApplyInsidePromote: mechanism 2 stated directly. No plan apply
  commits while a promote occupies its prep→apply window.
*)
NoApplyInsidePromote ==
  [][ (plan \in {"ready", "deferred"} /\ plan' = "idle")
      => (promote = "idle") ]_vars

(*
  DeltaSourceReferenced: a committed delta keeps its source referenced,
  which is what stops a later plan from dropping it. The implementation
  of this is LbaMap's delta_source_counts.
*)
DeltaSourceReferenced ==
  \A d \in deltas: d.src \in referenced

\* ---------------------------------------------------------------------------
\* Liveness
\* ---------------------------------------------------------------------------

(*
  DeferredEventuallyApplies: deferral is bounded. The promote it waits on
  is already dispatched, so it completes and releases the plan.
*)
DeferredEventuallyApplies ==
  (plan = "deferred") ~> (plan = "idle")

====
