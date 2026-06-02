# Coordinator-side mint enrollment — implementation plan (v2)

**Supersedes [`coordinator-mint-enrollment-plan.md`](coordinator-mint-enrollment-plan.md).**
That plan predates the three-operator-gate enrollment model: it treated
`/v1/enroll` and `/v1/enroll-exchange` as PoP-only calls. They are now
each gated by a logged-in operator's third-party-caveat discharge. This
revision threads those discharges through the coordinator-side command;
the single-command shape, the startup gate, the in-memory ticket, and
the role inventory carry over unchanged.

Implements the coordinator's half of mint enrollment: the thing that
actually writes `<data_dir>/credentials/<role>`. The mint server
(`/v1/enroll`, `/v1/enroll-exchange`, operator approve), the discharge
issuer, and the generic reference client already exist and are
conformance-tested (`mint/tests/enroll.rs`).
`elide-coordinator/src/mint_client.rs` already has the steady-state
`assume-role` half and explicitly defers provisioning. This plan fills
that gap.

Authority: `docs/design-mint.md` § *Enrollment*, § *Credential macaroon
& lifecycle*, § *Coordinator store architecture*;
`docs/design-auth-service.md` § *Discharge flows*.

## The three gates this command drives

Enrollment is gated by three operator discharges (see
`design-mint.md` § *Enrollment*). Two of them are presented by the
coordinator and are therefore this command's responsibility; the third
is the approver's, on the mint host:

| Gate | Discharged against | Presented by | When |
|---|---|---|---|
| **request** | the invite's TPC `CID` | this command, at `/v1/enroll` | step A |
| **approve** | (admin-plane discharge) | `mint enroll approve`, separate operator | step B |
| **initialize** | the ticket's TPC `CID` | this command, at `/v1/enroll-exchange` | step C |

The operator who runs `elide coord enroll` is the *requesting* and
*initializing* operator (the same human is allowed; mint records each
`Subject` regardless). They must be **logged in** — the command fetches
both discharges from the auth service using a stored operator session.
The *approving* operator is whoever runs `mint enroll approve` on the
mint host; that half is unchanged and out of scope here.

## Shape: one blocking operator command + a hard startup gate

Enrollment is **not** a daemon reconciler. It is a single operator-run
command that performs the whole `A → (wait for B) → C` sequence, and the
daemon **refuses to start** (when `[mint]` is configured) until it has
completed successfully.

- **A — `POST /v1/enroll`.** The command attenuates the
  operator-supplied invite macaroon with `sub=<coord-ulid>` and
  `cnf=ed25519:<coordinator.pub>`, **fetches a requesting discharge** for
  the invite's TPC (route derived from the TPC `location`; gated by the
  operator session), bundles `[invite ⊕ sub/cnf, discharge]`, PoP-signs
  the body (`{ts}`) with `coordinator.key`, and receives the short-lived
  **credential ticket** (which carries its own TPC). It prints the `cnf`
  fingerprint and the exact `mint enroll approve <coord-ulid>` line the
  approving operator runs out of band.
- **wait for B — operator approval.** The command blocks, polling
  `/v1/enroll-exchange`. `403` ⇒ not approved yet ⇒ backoff and retry.
  A (possibly different) operator runs `mint enroll approve <coord-ulid>`
  on the mint host, matching the printed fingerprint through a trusted
  side channel first.
- **C — exchange fan-out.** Once approved, the command **fetches one
  initializing discharge** for the ticket's TPC, then exchanges the
  ticket once per role in the canonical inventory (`coord-ro`,
  `coord-rw`, `volume-rw`, `volume-ro`) — bundle `[ticket, discharge]`,
  body `{ts, role}`, same PoP — and writes each re-minted credential to
  `credentials/<role>` (mode `0600`). One initializing discharge covers
  all four exchanges within its `NotAfter`; the approved record is not
  consumed per exchange.

On success: four files under `credentials/`. Exit `0`.

### Startup gate

In `main.rs`, in the existing `if let Some(mint_cfg) = &config.mint`
branch (right after `mint_cfg.validate()?`, before constructing
`MintScopedStores`): assert every role file in the canonical inventory
exists under `<data_dir>/credentials/` and decodes as a macaroon.
Missing or undecodable ⇒ `bail!` with a message naming the missing
role(s) and pointing at `elide coord enroll`. The `[mint]`-absent branch
(shared-key `PassthroughStores`) is unchanged — no gate.

## Decisions

1. **Single blocking command, not split enroll/exchange.** The reference
   client splits them across CLI invocations and persists the ticket to
   disk. The coordinator collapses the sequence into one process, so
   **the ticket lives in memory for the command's duration and never
   touches disk**. `credentials/<role>` is the only durable enrollment
   artifact. Reasoned deviation from the reference client; consistent
   with keeping on-disk state inspectable and minimal.

2. **Operator session is a prerequisite; discharges are fetched, not
   stored.** The command requires a live operator session (from `elide
   operator login`); it fetches the requesting and initializing
   discharges on demand and holds them only in memory for the call. The
   discharge route is derived from each macaroon's TPC `location`, so no
   separate `--auth-url` flag is needed (the transport may still come
   from config / the session). Discharges are short-lived (~5 min) — the
   command fetches the initializing discharge **after** approval, so it
   is fresh for the fan-out, and re-fetches if a leg outlives it.

3. **Self-healing the ticket-and-discharge expiry race.** Because the
   single command holds the invite for its whole duration, if the ticket
   `exp` passes during the wait-for-approval (operator slow), the command
   transparently re-runs A — re-fetching the requesting discharge and
   re-enrolling — and continues. (After ticket expiry the mint-side
   pending record is GC'd and needs fresh approval; the command surfaces
   that it is re-enrolling so the operator knows a re-approve is
   required.) A discharge that expires mid-fan-out is re-fetched in
   place. The split reference client structurally cannot do either.

4. **Invite is operator-supplied, never config.** `<mac|file|->`
   argument mirroring `mint client enroll`; not a `[mint]` key. The
   invite is reusable and non-expiring — parking it in `coordinator.toml`
   on every host is the surface we explicitly avoid. `MintConfig` stays
   as-is (`url` + timeouts only).

5. **Canonical role inventory consolidated.** Introduce one `pub const
   COORD_ENROLL_ROLES: &[&str]` (single source of truth) used by the
   exchange fan-out **and** the startup gate **and** referenced by the
   existing stores, so the three can never drift. `volume-rw` is
   per-volume only at `assume-role` time (the `elide:Volume` narrowing
   caveat) — enrollment still produces exactly one `credentials/volume-rw`.

6. **All-or-nothing per run, idempotent per file.** If C partially
   completes and the ticket then expires, decision (3) re-enrolls and
   continues only the missing roles (per-file presence check). Re-running
   `elide coord enroll` after a full success is a no-op-ish: A is
   idempotent for identical `(sub, pub)`; already-present credentials are
   permanent and left untouched unless `--force`.

## Code layout

- **New `elide-coordinator/src/enroll.rs`.** Enroll/exchange are one-shot
  provisioning; `assume-role` is steady-state — different lifecycles,
  shared primitives. Reuses, from `mint_client.rs` (made `pub(crate)` as
  needed): `WireMacaroon` (decode/attenuate/encode), `pop_digest`, `post`
  (TCP + UDS), `now_unix`, the JSON field helpers. **New** here: a
  `fetch_discharge(macaroon, session)` helper that reads the TPC
  `location` + `CID` off a presented macaroon and POSTs the session to
  the auth `/v1/discharge` route. No new crypto.
- **`mint_client.rs`** — add `pub(crate)` to the shared primitives; add
  `COORD_ENROLL_ROLES`; otherwise untouched.
- **Operator session** — load the session written by `elide operator
  login` (see `design-auth-service.md` § *Login flow*); reuse its
  storage path and decode. If no `elide operator login` surface exists in
  the coordinator CLI yet, that is a prerequisite this plan depends on
  (flag it explicitly rather than inlining a login flow here).
- **`main.rs`** — new `Command::Enroll`; startup-gate check in the
  `[mint]` serve branch.
- **`config.rs`** — unchanged (decision 4).

### CLI surface

```
elide coord enroll [--data-dir <dir>] <invite-macaroon | file | ->
                   [--timeout <humantime>] [--force]
```

- positional invite source: inline macaroon, a file path, or `-` for
  stdin (same resolution as `mint client enroll`).
- requires a live operator session (`elide operator login` first);
  errors clearly if absent or expired.
- `--timeout`: overall wait-for-approval bound (default e.g. `30m`); on
  timeout, exit non-zero with the resume instruction (re-run is safe).
- `--force`: re-exchange and overwrite existing `credentials/<role>`
  (default: keep present files, only fill missing).
- Loads `CoordinatorIdentity::load_or_generate(data_dir)` for
  `sub`/`cnf`/PoP. Reads `[mint] url` + timeouts from the resolved config.

## Edge cases

- **No / expired operator session**: fail fast before touching mint,
  pointing at `elide operator login`.
- **Auth unreachable** (cannot fetch a discharge): fail with a clear
  "auth service unreachable — enrollment needs a logged-in operator"
  message; re-run is safe.
- **Discharge `403`** (session valid but policy denies request- or
  initialize-scope): surface the auth error; this Subject is not
  permitted to enroll/initialize coordinators.
- **403 forever at exchange** (operator never approves): bounded by
  `--timeout`; clear message, idempotent re-run.
- **401 at enroll**: bad/stale invite, wrong `op`, or an unsatisfied
  invite TPC (missing/expired requesting discharge) — fail fast with the
  mint error snippet.
- **401 at exchange**: ticket expired, or the ticket TPC undischarged
  (initializing discharge missing/expired) — decision (3) re-fetches and
  retries; if a fresh ticket also 401s, the invite itself is
  stale/rotated (`mint invite --rotate`) — fail with that diagnosis.
- **pub/sub conflict**: exchange keeps returning non-200; the command
  reports the mint snippet so the operator can `mint enroll list` and
  reconcile.
- **`[mint]` configured, `coord enroll` never run**: startup gate
  `bail!`s — the daemon does not come up half-credentialed.

## Testing

- Unit (in `enroll.rs`): invite attenuation chain (`sub`/`cnf` appended
  in order), PoP digest over `{ts}` / `{ts, role}`, `fetch_discharge`
  route derivation from a TPC `location`, ticket-expiry → re-enroll
  branch and discharge-expiry → re-fetch branch with a fake `post`.
- Integration against the real mint binary in demo-auth mode
  (`demo-enabled = true`, discharges rubber-stamped, no session needed):
  extend `mint/tests/enroll.rs` — spin mint on a UDS, run the enroll
  command with `--timeout` short, drive `mint enroll approve`, assert all
  four `credentials/<role>` files appear and decode, and that a second
  run is idempotent. The demo path exercises the full
  request/initialize discharge legs end-to-end without a standalone auth
  service.
- Startup gate: `serve` with `[mint]` and an empty `credentials/` fails
  with the expected message; with all four present, proceeds.

## Out of scope

- The steady-state Tigris-keypair cache / proactive refresh
  (`assume-role` side) — credentials themselves never expire, so
  enrollment is converge-once and has no refresh cadence.
- The standalone auth-service binary and `elide operator login` UX
  beyond consuming a session it produces (demo-auth covers the test
  path).
- `mint invite --rotate` handling beyond surfacing the diagnosis.
- The future domain-typed S3 layer (§ *Coordinator store architecture*).
