# Volume size lives with the live owner

**Status:** Proposed.

`size` is the only mutable, load-bearing field carried by `manifest.toml` today, and it has no cryptographic anchor — it sits in an unsigned TOML file on S3, trusted via S3 IAM alone. The proposal is to relocate it to the `names/<name>` claim record (already authoritative for current ownership, already CAS-protected, already chained into the signed event log) and drop it from the per-volume on-disk skeleton entirely.

## The shape

- Add `size: u64` to `NameRecord` (the TOML at `names/<name>`).
- Drop `size` from `manifest.toml`. Ancestors carry no size on disk at all.
- The single owner of `names/<name>` — the coordinator currently holding the claim — is the sole writer of `size`. Updates are CAS-mutations on the same record that already serialises ownership, state, and handoff snapshot.
- Local `volume.toml.size` becomes a *cache* of the authoritative `names/<name>.size`, populated at claim/bootstrap time, the same way `name` is already cached locally.

## Why this works

`size` has the same shape as `name`: mutable, identity-ish, single-writer, and already gated by the CAS-on-`names/<name>` mechanism. The current asymmetry — name in `names/<name>`, size in `manifest.toml` — exists by accident, not by design. Putting them together collapses the trust model:

| Concern | Today | Proposed |
|---|---|---|
| Ownership | `names/<name>.coordinator_id` | unchanged |
| State | `names/<name>.state` | unchanged |
| Capacity | `manifest.toml.size` (unsigned, S3-IAM-only) | `names/<name>.size` (CAS, signed in event log) |
| Authoritative writer | implicit | explicit: holder of `names/<name>` |

## Why ancestors don't need it

Tracing actual size readers (`src/lib.rs:104` → ublk/nbd `nr_sectors`; `inbound.rs:2061` fork inheritance; `filemap.rs:165` ext4 scan; `upload.rs:461` re-publish; `import.rs:259` initial write), every path that consumes `size` operates on a *live* volume — the current fork being served, the source of a fork operation, or the import in progress. Ancestors are read-only segment containers; their data is reached through a child's LBA map, and the child's *own* size determines what the guest sees. There is no read path that consults an ancestor's `size`.

So ancestors simply stop carrying it. Pulled skeletons drop from `volume.pub + volume.provenance + manifest.toml` to `volume.pub + volume.provenance`. The peer-fetch trust gap closes (every skeleton file is now either signed or a public key), and the bootstrap pull is one fewer S3 GET per ancestor.

## Resize semantics

Resize becomes a metadata operation against the claim record, not a fork:

1. Coordinator computes the new size (validate: shrink requires no LBAs ≥ new_size carry data; grow is unconditional).
2. CAS on `names/<name>` bumps `size`; emits a signed `Resized { new_size }` entry in `events/<name>/`.
3. Coordinator (or volume process) calls `UBLK_U_CMD_UPDATE_SIZE` (Linux 6.16+) on the running ublk device — `set_capacity_and_notify()` updates the gendisk capacity live, no I/O interruption.
4. Local `volume.toml.size` cache is updated.

NBD has no equivalent live-update; resize against an NBD-served volume requires reconnect (acceptable: NBD is the simpler-deployment transport, not the primary one).

## What happens to `manifest.toml`

Once `size` moves out, the remaining fields are all derivable or non-load-bearing:

- `name` — already not consumed (pull explicitly drops it in favour of `names/<name>`).
- `origin` — redundant with `volume.provenance.parent`, which is signed.
- `source` (OCI digest/arch) — bookkeeping only, never consumed by code.
- `readonly` — implied by `volume.readonly` marker presence and `volume.key` absence.

`manifest.toml` could be dropped entirely as a follow-up. That's a separate, smaller cleanup; the size relocation stands alone.

## Migration

Per project convention (no backwards-compat by default): existing `names/<name>` records get rewritten with `size` populated from their volume's current `manifest.toml` on first read by a coordinator running the new code. `manifest.toml` either lingers harmlessly (if kept for now) or gets removed in the follow-up cleanup. Existing ancestors keep their `manifest.toml` files on disk; nothing reads them under the new code.

## Tradeoffs

- **Pro:** size joins the same trust root as name/ownership/state. No more unsigned correctness-relevant field.
- **Pro:** peer-fetch can extend to the skeleton without further design — both remaining files are signed/anchored.
- **Pro:** resize is a CAS, not a fork — no new vol_ulids per resize, no ancestor chain growth, no name rebind needed.
- **Con:** ublk online resize requires Linux 6.16+. Older kernels need the older fall-back (stop + del + re-add) — but that's true of any resize implementation, with or without this proposal.
- **Con:** an ancestor pulled by a host that *only* needs it as a fork source must skip it. There may be diagnostic tools that today walk ancestors and report sizes; those would need to either look up `names/<ancestor-name>` (only works if the ancestor is currently named) or accept that ancestor size isn't recoverable. Per the trace, no production code path does this.
