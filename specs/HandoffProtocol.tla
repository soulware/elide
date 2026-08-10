---- MODULE HandoffProtocol ----
(*
  TLA+ model of the Elide GC plan handoff protocol.

  Covers `elide-coordinator/src/gc.rs` (plan emission, apply_done_handoffs),
  `elide-core/src/volume/mod.rs` (apply_all_staged_handoffs,
  apply_plan_apply_result, finalize_gc_handoff) and
  `elide-core/src/rewrite_apply.rs` (materialise).

  BACKGROUND
  ----------
  The coordinator plans a compaction and hands the plan to the volume, which
  materialises the body itself. Three filename states exist in `gc/`:

      gc/<ulid>.plan     coordinator wrote a declarative RewritePlan naming its
                         input ULIDs and, per output entry, what to carry.
                         No body bytes. Volume has not applied.
      gc/<ulid>          (bare) volume materialised the bodies, signed with the
                         volume key, and renamed <ulid>.tmp to this name. That
                         rename is the atomic commit point. Coordinator has not
                         yet uploaded.
      (deleted)          coordinator finished apply_done_handoffs (upload to S3,
                         promote IPC, delete old S3, finalize IPC) and the
                         volume's finalize_gc_handoff removed the bare body.

  gc/<ulid>.tmp is volume-owned apply scratch, swept on sight by the next pass.

  Step 1 - Coordinator emits a plan.
    Derives liveness from a full `lbamap::rebuild_segments` over the ancestor
    chain plus a WAL replay (gc.rs), so the plan reflects `index/`, `gc/`,
    `pending/` and the open WAL. Writes gc/<ulid>.plan atomically.

  Step 2 - Volume applies (apply_plan_apply_result). One actor message:
    a. Worker materialises bodies from the plan, resolving composites through
       the extent index. A missing input or unresolvable hash cancels here.
    b. Derives to-remove and stale-cancel against the CURRENT extent index and
       lbamap, which may have moved while the worker ran.
    c. Merges the output into the extent index and the lbamap.
    d. Four refusals can reject the fold after the merge; see REFUSALS.
    e. Renames <ulid>.tmp to bare <ulid>. ATOMIC COMMIT POINT.
    f. Removes the .plan.

  Step 3 - Coordinator cleans up (apply_done_handoffs), unchanged in shape:
    3a  upload the bare body to S3 (idempotent PUT)
    3b  promote IPC: volume writes index/<new>.idx and cache/<new>.{body,present},
        and deletes index/<input>.idx for each input
    3c  delete old S3 objects (404 is success)
    3d  finalize IPC: volume deletes the bare body

    3b before 3c upholds: index/<ulid>.idx present <-> segment is in S3.
    3d after 3c keeps the bare body as the retry trigger until the S3 cleanup
    has finished.

  REFUSALS
  --------
  A plan is derived from a view of the volume taken at scan time and applied
  later against the live one. Where the two disagree about an LBA, the fold is
  rejected rather than committed. Four rejections exist; all restore the
  pre-apply maps, delete the scratch and the plan, and leave the next pass to
  re-derive:

    stale-liveness      a hash the plan drops is still claim-live or is named
                        as a delta source
    resolvability gate  the fold would leave an lbamap-referenced hash with no
                        body location
    superseded carry    an entry the plan carries is held by a lower-ULID
                        claimant this apply does not consume, so a rebuild
                        would prefer the fold over a live write
    dropped claim       an LBA claimed by a consumed input is absent from the
                        output, so the fold would drop a claim the volume
                        still serves

  The last two are #936. Both exist because the apply and the disk rebuild
  admit claims by different rules, and only a liveness view that reflects
  every tier keeps them agreeing.

  This model collapses all four into VolumeRefusePlan, gated on `view_stale`.
  Which of the four fires is a detail of what the plan got wrong; the protocol
  question is what a rejection does to the lifecycle, and that is identical
  for all four.

  A fifth outcome, StagedApply::Diverged, is deliberately NOT modelled as a
  refusal: it leaves the plan on disk, halts the apply loop, and in production
  exits the process. It is a stop, not a retry, so it has no lifecycle to
  check.

  CRASH RECOVERY
  --------------
  Filename states resolve without bookkeeping:

    <ulid>.tmp          stale scratch, swept on the next apply pass
    .plan alone         re-run apply; materialisation is deterministic
    .plan + bare        bare wins; drop the plan
    bare alone          applied; the coordinator's turn

  A .plan carries no body, so a crash before the commit leaves nothing of the
  fold on disk and the rebuild sees only the inputs. This is simpler than the
  superseded .staged protocol, where the coordinator's signed body was already
  on disk before the volume had applied anything.

  WHY THE VOLUME MATERIALISES
  ---------------------------
  The coordinator holds no volume signing key, and a plan is a description
  rather than bytes. The volume resolves the plan against its own extent
  index, writes <ulid>.tmp, signs it, and renames. The bare name therefore
  implies volume-signed by construction.

  WHAT WE CHECK
  -------------
  TLC explores every crash and restart interleaving, every concurrent write,
  and every refusal, against six safety invariants and two temporal
  properties:

    NoSegmentNotFound     the extent index never references a missing segment
    NoLostData            segments are removed only when nothing points at them
    OldOnlyDeletedAfterApplied
                          the input is absent only after the volume applied
    OldIdxOnlyPresentWhenSegmentPresent
                          index/<old>.idx is absent whenever the S3 object is
    CacheOnlyAfterUpload  cache/<new> is populated only after the bare commit
    NoCommitOnStaleView   no fold is committed from a plan whose view
                          disagreed with the live map

  NoCommitOnStaleView is the safety half of the #936 refusals. It is not a
  restatement of VolumeApplyPlan's guard: TLC checks it against every
  interleaving where a crash lands inside the refusal, inside the apply, or
  between the commit and the plan removal.

    EventuallyDoneWhenViewSettles
                          if the coordinator's view is fresh infinitely often,
                          the handoff completes
    RefusalIsNotProgress  a refused plan returns the volume to a state where
                          the fold has left no trace

  EventuallyDoneWhenViewSettles is deliberately conditional. A view that stays
  stale re-derives to the same verdict and refuses again, so the unconditional
  <>(handoff = "cleaned") is FALSE and should be. That is the fail-stop
  working: a volume whose disk-derived view and live map disagree about an LBA
  in a way re-deriving does not fix should not be folding. The condition on
  this property is where that design decision is written down, and TLC checks
  the other half of it, that a settling view always completes.

  HOW TO READ THIS
  ----------------
  TLA+ describes a system as:
    - VARIABLES: the current state
    - Actions: relations between current and next state (written with ')
    - UNCHANGED: these variables are the same in the next state
    - Init: the initial state predicate
    - Next: the disjunction of all actions (one fires per step)
    - Spec: Init /\ [][Next]_vars

  INSTANTIATION EXAMPLES
  ----------------------
  Standard compaction (carried + removed):
    Carried <- {c1, c2},  Removed <- {r1},  Dead <- FALSE
  Removal-only (nothing live to carry, index references to clean up):
    Carried <- {},        Removed <- {r1},  Dead <- FALSE
  Tombstone (all-dead input, no hashes at all):
    Carried <- {},        Removed <- {},    Dead <- TRUE
*)
EXTENDS Naturals, FiniteSets, TLC

CONSTANTS
  Carried,    \* hashes the plan carries into the output
  Removed,    \* hashes the plan drops
  Dead,       \* TRUE iff this is a tombstone handoff (all-dead input).
              \* Carried and Removed must both be {} when TRUE.
  MaxCrashes  \* Bound on CoordCrash + VolumeCrash events. Under unbounded
              \* crashes an adversary can keep the two processes from ever
              \* being up together when a progress action is enabled, so
              \* liveness would fail as fairness theory rather than as a real
              \* defect. Bounding lets TLC explore every interleaving up to
              \* the bound and then reach a quiescent phase where SF on the
              \* progress actions carries the handoff to completion.

ASSUME Carried \cap Removed = {}
ASSUME Dead => (Carried = {} /\ Removed = {})
ASSUME Carried \cup Removed # {} \/ Dead
ASSUME MaxCrashes \in Nat

VARIABLES
  handoff,        \* on-disk state of this handoff:
                  \*   "absent"  - nothing in gc/ for this output
                  \*   "plan"    - gc/<ulid>.plan exists; volume must apply
                  \*   "bare"    - bare gc/<ulid> exists; coordinator finishes
                  \*   "cleaned" - apply_done_handoffs finished

  extent,         \* hash -> what the extent index says
                  \*   "old"  - the original input segment
                  \*   "gc"   - the new output body (Carried only)
                  \*   "gone" - entry removed (Removed only)
                  \*   "new"  - a concurrent write superseded it

  view_stale,     \* TRUE iff the plan currently on disk was derived from a
                  \* view that disagrees with the live map about some LBA.
                  \* Chosen nondeterministically at emission: gc_fork's
                  \* liveness rebuild is meant to make this always FALSE, and
                  \* the model admits TRUE to check what happens when it is
                  \* not. Meaningless while handoff = "absent".

  committed_stale, \* TRUE iff a fold was ever committed from a stale plan.
                   \* Latches, so no later transition can hide it from the
                   \* invariant.

  old_present,     \* TRUE iff the input S3 object is present. Cleared by
                   \* CoordFinalize.
  old_idx_present, \* TRUE iff index/<old>.idx exists. Cleared by CoordPromote.
  bare_present,    \* TRUE iff bare gc/<ulid> exists. Set by VolumeApplyPlan's
                   \* rename, cleared by CoordFinalize's finalize IPC.
  gc_s3_uploaded,  \* TRUE iff the bare body is confirmed in S3. Reset on
                   \* coordinator crash; the re-PUT is idempotent.
  new_seg_present, \* TRUE iff cache/<new>.body exists. Set by CoordPromote.
                   \* Stays FALSE for zero-entry outputs, which promote skips.
  old_cache_present, \* TRUE iff cache/<old>.{body,present} exist. Initially
                     \* TRUE; the coordinator evicts them in apply_done_handoffs
                     \* after promote has published the output.

  coord_up,
  vol_up,
  crashes_remaining

vars == <<handoff, extent, view_stale, committed_stale, old_present, old_idx_present, bare_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up, vol_up, crashes_remaining>>

Hashes == Carried \cup Removed

TypeOK ==
  /\ handoff           \in {"absent", "plan", "bare", "cleaned"}
  /\ extent            \in [Hashes -> {"old", "gc", "gone", "new"}]
  /\ view_stale        \in BOOLEAN
  /\ committed_stale   \in BOOLEAN
  /\ old_present       \in BOOLEAN
  /\ old_idx_present   \in BOOLEAN
  /\ bare_present      \in BOOLEAN
  /\ gc_s3_uploaded    \in BOOLEAN
  /\ new_seg_present   \in BOOLEAN
  /\ old_cache_present \in BOOLEAN
  /\ coord_up          \in BOOLEAN
  /\ vol_up            \in BOOLEAN
  /\ crashes_remaining \in 0..MaxCrashes

Init ==
  /\ handoff           = "absent"
  /\ extent            = [h \in Hashes |-> "old"]
  /\ view_stale        = FALSE
  /\ committed_stale   = FALSE
  /\ old_present       = TRUE
  /\ old_idx_present   = TRUE
  /\ bare_present      = FALSE
  /\ gc_s3_uploaded    = FALSE
  /\ new_seg_present   = FALSE
  /\ old_cache_present = TRUE
  /\ coord_up          = TRUE
  /\ vol_up            = TRUE
  /\ crashes_remaining = MaxCrashes

\* ---------------------------------------------------------------------------
\* Coordinator
\* ---------------------------------------------------------------------------

(*
  Step 1. gc_fork writes gc/<ulid>.plan. Emission is gated on gc/ being clear
  of prior handoffs (collect_bare_handoffs / the PendingHandoffs bail), which
  handoff = "absent" expresses.

  view_stale' is unconstrained: the plan either agrees with the live map or it
  does not. gc_fork deriving liveness from a full rebuild plus a WAL replay is
  what is meant to keep it FALSE, and admitting TRUE is what lets TLC check
  the refusal path.
*)
CoordEmitPlan ==
  /\ coord_up
  /\ handoff = "absent"
  /\ handoff' = "plan"
  /\ view_stale' \in BOOLEAN
  /\ UNCHANGED <<extent, committed_stale, old_present, old_idx_present, bare_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up, vol_up, crashes_remaining>>

(* Step 3a. Idempotent PUT of the volume-signed bare body. *)
CoordUploadGc ==
  /\ coord_up
  /\ handoff = "bare"
  /\ bare_present
  /\ ~gc_s3_uploaded
  /\ gc_s3_uploaded' = TRUE
  /\ UNCHANGED <<handoff, extent, view_stale, committed_stale, old_present, old_idx_present, bare_present, new_seg_present, old_cache_present, coord_up, vol_up, crashes_remaining>>

(*
  Step 3b. promote IPC. The volume writes index/<new>.idx and
  cache/<new>.{body,present}, and deletes index/<input>.idx for every input.
  One actor message, so serialised with the apply. Zero-entry outputs produce
  no idx or cache body, which is why new_seg_present tracks Carried # {}.

  The coordinator then evicts cache/<old>, safe here because promote has
  published the output and cleared the input idx.
*)
CoordPromote ==
  /\ coord_up
  /\ vol_up
  /\ handoff = "bare"
  /\ gc_s3_uploaded
  /\ old_idx_present
  /\ new_seg_present'   = (Carried # {})
  /\ old_idx_present'   = FALSE
  /\ old_cache_present' = FALSE
  /\ UNCHANGED <<handoff, extent, view_stale, committed_stale, old_present, bare_present, gc_s3_uploaded, coord_up, vol_up, crashes_remaining>>

(*
  Steps 3c and 3d. Delete the old S3 objects, then finalize. One step here;
  split in production, where a crash between them re-runs apply_done_handoffs
  against a bare body that is still on disk.

  ~old_idx_present orders the idx delete ahead of the S3 delete.
*)
CoordFinalize ==
  /\ coord_up
  /\ vol_up
  /\ handoff = "bare"
  /\ ~old_idx_present
  /\ (new_seg_present \/ Carried = {})
  /\ old_present'  = FALSE
  /\ bare_present' = FALSE
  /\ handoff'      = "cleaned"
  /\ UNCHANGED <<extent, view_stale, committed_stale, old_idx_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up, vol_up, crashes_remaining>>

CoordCrash ==
  /\ coord_up
  /\ crashes_remaining > 0
  /\ coord_up' = FALSE
  /\ gc_s3_uploaded' = FALSE
  /\ crashes_remaining' = crashes_remaining - 1
  /\ UNCHANGED <<handoff, extent, view_stale, committed_stale, old_present, old_idx_present, bare_present, new_seg_present, old_cache_present, vol_up>>

CoordRestart ==
  /\ ~coord_up
  /\ coord_up' = TRUE
  /\ UNCHANGED <<handoff, extent, view_stale, committed_stale, old_present, old_idx_present, bare_present, gc_s3_uploaded, new_seg_present, old_cache_present, vol_up, crashes_remaining>>

\* ---------------------------------------------------------------------------
\* Volume
\* ---------------------------------------------------------------------------

(*
  Step 2, the committing path. Materialise, merge, no refusal fires, rename
  <ulid>.tmp to bare, drop the plan. One actor message, so readers never see
  the partial merge: the next ReadSnapshot publishes after apply returns.

  The per-entry guard on the extent update is `register_entry_consuming_inputs`
  declining a hash a concurrent write has taken, modelled by leaving "new"
  alone.
*)
VolumeApplyPlan ==
  /\ vol_up
  /\ handoff = "plan"
  /\ ~view_stale
  /\ extent' = [h \in Hashes |->
                  IF extent[h] = "old"
                  THEN IF h \in Carried THEN "gc" ELSE "gone"
                  ELSE extent[h]]
  /\ handoff'      = "bare"
  /\ bare_present' = TRUE
  \* Records what this commit was derived from, so NoCommitOnStaleView is a
  \* claim about the trace rather than a restatement of the guard above.
  /\ committed_stale' = (committed_stale \/ view_stale)
  /\ UNCHANGED <<view_stale, old_present, old_idx_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up, vol_up, crashes_remaining>>

(*
  Step 2, the rejecting path: any of the four refusals. The maps are restored
  from the pre-apply snapshots, the scratch and the plan are deleted, and the
  handoff returns to "absent" for the next pass to re-derive.

  Nothing of the fold survives: no bare body was renamed, so the extent index
  is where it was and the disk carries no trace. That is what
  RefusalIsNotProgress checks.
*)
VolumeRefusePlan ==
  /\ vol_up
  /\ handoff = "plan"
  /\ view_stale
  /\ handoff' = "absent"
  /\ UNCHANGED <<extent, view_stale, committed_stale, old_present, old_idx_present, bare_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up, vol_up, crashes_remaining>>

VolumeCrash ==
  /\ vol_up
  /\ crashes_remaining > 0
  /\ vol_up' = FALSE
  /\ crashes_remaining' = crashes_remaining - 1
  /\ UNCHANGED <<handoff, extent, view_stale, committed_stale, old_present, old_idx_present, bare_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up>>

(*
  Restart rebuilds the extent index from disk (extentindex::rebuild). Bare
  gc/<ulid> files are read first and win over index/*.idx under
  insert_if_absent, and `discover_fork_segments` drops every index/<input>.idx
  named by a bare body's `inputs` field. Without that filter a rebuild during
  the bare phase re-introduces the Removed entries the apply had deleted --
  the counterexample this model found, pinned by
  `gc_staged_crash_in_bare_phase_drops_removed_extents`
  (elide-core/src/volume/tests.rs).

  extent[h] after a rebuild:

    "new"           preserved; a concurrent write owns the LBA.

    h \in Carried
      bare_present            the bare body inserts h -> "gc"
      new_seg_present         bare gone but promote left index/<new>.idx -> "gc"
      otherwise               no output on disk; index/<old>.idx -> "old"

    h \in Removed
      bare_present            the inputs filter drops the input idx, and the
                              output does not carry h, so nothing inserts it
                              -> "gone"
      old_idx_present         no bare body, so no filter; index/<old>.idx
                              -> "old"
      otherwise               post-finalize; nothing inserts h -> "gone"

  A plan on disk contributes nothing here: it holds no body. So a crash in
  the "plan" state, whether the apply had refused or had not run at all,
  rebuilds to exactly the pre-GC view.
*)
VolumeRestart ==
  /\ ~vol_up
  /\ vol_up' = TRUE
  /\ extent' = [h \in Hashes |->
                  IF extent[h] = "new" THEN "new"
                  ELSE IF h \in Carried THEN
                    IF bare_present \/ new_seg_present THEN "gc"
                    ELSE "old"
                  ELSE
                    IF bare_present THEN "gone"
                    ELSE IF old_idx_present THEN "old"
                    ELSE "gone"]
  /\ UNCHANGED <<handoff, view_stale, committed_stale, old_present, old_idx_present, bare_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up, crashes_remaining>>

\* ---------------------------------------------------------------------------
\* Environment
\* ---------------------------------------------------------------------------

(*
  A write lands on an LBA the handoff covers, at any point. This is the
  coordinator's scan going stale under it.

  From "old": the write beat the apply. The per-entry guard keeps it.
  From "gc":  the write followed the apply. The carried extent is orphaned in
              the output, which leaks space and reads correctly.

  A write that lands between the plan and the apply is also what makes
  view_stale reachable, but the two are modelled separately: this action moves
  the extent index, view_stale describes what the plan believes about it.
*)
NewerWrite(h) ==
  /\ extent[h] \in {"old", "gc"}
  /\ extent' = [extent EXCEPT ![h] = "new"]
  /\ UNCHANGED <<handoff, view_stale, committed_stale, old_present, old_idx_present, bare_present, gc_s3_uploaded, new_seg_present, old_cache_present, coord_up, vol_up, crashes_remaining>>

\* ---------------------------------------------------------------------------
\* Specification
\* ---------------------------------------------------------------------------

Next ==
  \/ CoordEmitPlan
  \/ CoordUploadGc
  \/ CoordPromote
  \/ CoordFinalize
  \/ CoordCrash
  \/ CoordRestart
  \/ VolumeApplyPlan
  \/ VolumeRefusePlan
  \/ VolumeCrash
  \/ VolumeRestart
  \/ \E h \in Hashes : NewerWrite(h)

(*
  WF on the restart actions: they stay enabled while an actor is down.

  SF on the progress actions: they need their actor up, so a trace with
  crashes never leaves them continuously enabled and weak fairness would not
  fire. Strong fairness fires on infinitely-often-enabled, which the restart
  loop supplies.

  Crashes and writes carry no fairness: they are the adversary. Whether a
  given emission is stale is likewise a free choice inside CoordEmitPlan, so
  the model never assumes the thing EventuallyDoneWhenViewSettles is
  conditioned on.
*)
Spec ==
  /\ Init
  /\ [][Next]_vars
  /\ WF_vars(CoordRestart)
  /\ WF_vars(VolumeRestart)
  /\ SF_vars(CoordEmitPlan)
  /\ SF_vars(CoordUploadGc)
  /\ SF_vars(CoordPromote)
  /\ SF_vars(CoordFinalize)
  /\ SF_vars(VolumeApplyPlan)
  /\ SF_vars(VolumeRefusePlan)

\* ---------------------------------------------------------------------------
\* Safety
\* ---------------------------------------------------------------------------

(* The extent index never references a segment that is not there. *)
NoSegmentNotFound ==
  /\ \A h \in Hashes  : extent[h] = "old" => old_present
  /\ \A h \in Carried : extent[h] = "gc"  => bare_present \/ new_seg_present

(* A segment is removed only once nothing in the extent index points at it. *)
NoLostData ==
  /\ (~old_present => \A h \in Hashes : extent[h] # "old")
  /\ (\A h \in Carried :
        ~(bare_present \/ new_seg_present) => extent[h] # "gc")

(* The input is deleted only after the volume acknowledged, by committing. *)
OldOnlyDeletedAfterApplied ==
  ~old_present => handoff = "cleaned"

(* index/<old>.idx may exist only while the S3 object does. *)
OldIdxOnlyPresentWhenSegmentPresent ==
  old_idx_present => old_present

(* cache/<new> is populated only after the commit. *)
CacheOnlyAfterUpload ==
  new_seg_present => handoff \in {"bare", "cleaned"}

(*
  The safety half of the #936 refusals: no fold reaches the commit point from
  a plan whose view disagreed with the live map.

  committed_stale latches, so a later ViewSettles cannot launder a commit that
  already happened. It stays FALSE in every reachable state because
  VolumeApplyPlan is the only action setting bare_present and it is gated on
  ~view_stale -- and, more to the point, because no crash interleaving reaches
  the rename with view_stale set.
*)
NoCommitOnStaleView == ~committed_stale

(*
  A refused plan leaves nothing behind. The volume's maps are restored, the
  scratch and the plan are gone, and no output body was committed, so the next
  pass starts from the same place the refused one did.
*)
RefusalIsNotProgress ==
  (handoff = "absent") => ~bare_present

\* ---------------------------------------------------------------------------
\* Liveness
\* ---------------------------------------------------------------------------

(*
  A plan that is fresh infinitely often carries the handoff to completion.

  The antecedent is about the plan on disk, not about the flag alone. A
  coordinator that re-derives a fresh plan infinitely often gets one applied,
  because SF on VolumeApplyPlan fires on infinitely-often-enabled. Phrasing it
  as []<>(~view_stale) instead admits a trace where the flag reads FALSE only
  while gc/ is empty and every plan ever emitted is stale, which satisfies the
  antecedent while the handoff never completes. TLC produced exactly that as a
  counterexample to the first draft of this property.

  The unconditional form is FALSE and should be: a stable disagreement
  re-derives to the same verdict and refuses forever. That is the fail-stop,
  and the condition here is where it is written down.
*)
EventuallyDoneWhenViewSettles ==
  ([]<>(handoff = "plan" /\ ~view_stale)) => <>(handoff = "cleaned")
====
