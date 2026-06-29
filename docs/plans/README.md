# Implementation plans

Phased implementation plans — sequencing, landing breakdowns, and the
decisions made along the way. Many are landed or superseded; each notes its
status. One file per plan.

| Document | Contents |
|---|---|
| [actor-offload-plan.md](actor-offload-plan.md) | Offload heavy maintenance work off the volume actor to isolate write tail latency. The umbrella plan the offload steps below land under |
| [promote-offload-plan.md](promote-offload-plan.md) | Offload WAL promotion onto the worker thread (first landing step of actor-offload). Landed |
| [promote-segment-offload-plan.md](promote-segment-offload-plan.md) | Offload the `promote_segment` IPC handler to the worker thread (step 6 of actor-offload). Landed |
| [snapshot-offload-plan.md](snapshot-offload-plan.md) | Offload `sign_snapshot_manifest` off the volume actor (step 7 of actor-offload). Landed (#68) |
| [list-elimination-plan.md](list-elimination-plan.md) | Remove all `s3:ListBucket` use from the coordinator runtime — replace each per-volume/event prefix LIST with a deterministic GET (latest-pointer or maintained index), then delete the grant from `coord-rw`. Phased P1–P5; no-LIST reconcile story. Landed (#392–#406) |
| [portable-live-volume-plan.md](portable-live-volume-plan.md) | Phased implementation of portable live volumes (foundations → schema → lifecycle verbs → `claim --force` recovery → CLI unification → tests/docs). Fresh-bucket-only; clean break for `volume remote` |
| [fork-from-remote-plan.md](fork-from-remote-plan.md) | `fork --from` auto-pulls the source volume and its ancestor chain from S3 when not present locally |
| [peer-segment-fetch-v1-plan.md](peer-segment-fetch-v1-plan.md) | Peer-fetch v1 — `.idx`-only, coordinator-driven, opt-in via coordinator config. New `elide-peer-fetch` crate. Decision criteria for whether to extend to body fetch |
| [coordinator-mint-enrollment-plan-v2.md](coordinator-mint-enrollment-plan-v2.md) | Coordinator-side mint enrollment — one blocking `elide coord enroll` (`A → wait approval → exchange fan-out`) writing `credentials/<role>`, plus a hard `[mint]` startup gate. Threads the three operator-discharge gates (enroll / approve / exchange); needs a logged-in operator session; ticket in-memory only; bootstrap operator-supplied not config. Supersedes the v1 plan |
| [coordinator-mint-enrollment-plan.md](coordinator-mint-enrollment-plan.md) | Original coordinator-side mint enrollment plan; superseded by [coordinator-mint-enrollment-plan-v2.md](coordinator-mint-enrollment-plan-v2.md) |
| [coordinator-driven-snapshot-plan.md](coordinator-driven-snapshot-plan.md) | Coordinator-driven snapshot sequence with a signed manifest. Landed (#42) |
