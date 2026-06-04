# Mint template seal

## Status

Implemented as described. Follows on from `docs/design-mint.md` § *Mint
state in the tenant bucket* and § *Root-key rotation* (the keyring landed
in PR #454). Modules: `mint/src/seal.rs`, `mint/src/sealed_cache.rs`,
`mint/src/admin.rs`. CLI verb: `mint seal`.

The earlier flow — a local `mint seal` writing `pending-seal.json`,
published by `mint serve` on its next startup — is superseded by the
approach described here: an authenticated `POST /v1/admin/seal` against a
running daemon, a *dormant-until-sealed* startup state, and a local
*sealed cache* (`<data_dir>/sealed/`) that mint serves from so a host can
restart safely during a fleet-wide template update before the re-seal.
There is no pending file: `mint seal` is an authenticated client call,
and the request path reads the *sealed* role surface (audience,
`required_caveats`, TTL bounds, policy bytes) — never the live
config.

## Why

Mint's role templates (`mint_roles/*.json`) become Tigris IAM policies
at `/v1/assume-role` time. A template controls what S3 surface a
credential authorises:

```handlebars
"Resource": ["arn:aws:s3:::{{tenant.bucket}}/by_id/{{caveat "elide:Volume"}}/*"]
```

A tampered template trivially widens that surface — change `/by_id/`
to `/`, or drop the resource constraint entirely, and the role goes
from one-volume-read to bucket-wide-read with no other signal.
Role-block fields in `mint.toml` (`required_caveats`,
`min_ttl_seconds`) have the same property: drop `elide:Volume` from
`required_caveats` and `volume-ro` becomes effectively bucket-wide.
Every such field has to be inside the seal, not just the
policy template.

Filesystem write to `roles_dir/` or `mint.toml` is the attacker's
prerequisite. That's a *different* trust pipeline from the keyring in
most deployments: keyring secrets ship via the secrets-manager
mechanism (systemd `LoadCredential=`, Vault, SOPS), while
`roles_dir/` is shipped via the same config-management plane as
everything else (Ansible / Terraform / Helm). A CI compromise that
can't touch secrets can still mutate templates and silently rewrite
IAM authority.

Mint also runs in HA shapes (multiple instances against one `_mint/`
prefix; `docs/design-mint.md` § *Admin credential custody*). Without
a cross-instance agreement on template content, hosts can drift —
two mints serving against the same enrollment state, rendering
different policies for the same role.

## Goal

> **No rendered policy ever differs from the policy the operator
> deliberately reviewed and consented to.**

Three properties:

1. **Tamper-evident.** A `mint-rw` bucket compromise alone cannot
   change what mint renders. The served bytes are always verified
   against the canonical seal; filesystem tamper of `roles_dir/`,
   `mint.toml`, or the local cache is surfaced (logged) and never
   rendered.
2. **Explicit operator consent.** Mint never commits to template
   content as canonical except in response to an explicit operator
   command. Startup verifies an existing seal; it does not author
   one.
3. **Cross-instance agreement.** Two mints sharing `_mint/` always
   serve the same policy bytes for the same role + caveat inputs, or
   one of them isn't running.

## Design overview

A **seal** is a small signed object in the tenant bucket that pins:

- Every role definition (the relevant subset of `mint.toml`).
- The BLAKE3 hash of every policy template file referenced by those
  roles.

The seal is MAC'd under the macaroon keyring's current kid — the
same trust anchor that signs `_mint/approved/<sub>` (PR #454). A
bucket-only attacker can't produce a valid seal; only a process
holding the keyring can. Template *bytes* never enter the bucket —
they are distributed to every host out-of-band by the same
config-management plane that ships `mint.toml`. The seal holds only
their hashes.

Mint serves from a **local sealed cache** (`<data_dir>/sealed/`): the
template bytes that were verified against the canonical `seal.json` at
the moment they were sealed or adopted. `roles_dir/` and `mint.toml`'s
role blocks are *staging input to `mint seal`* — never served
directly. At startup mint verifies the cache against `seal.json` and
loads it into an immutable in-memory `TemplateSet`; the on-disk files
are not re-read on the request path. Decoupling the served content
(the cache) from the staged content (`roles_dir/`) is what lets a host
restart safely in the window after templates are updated fleet-wide
but before they are re-sealed — see *The sealed cache* and *Startup*.

The seal is authored by a single explicit operator action: an
authenticated `POST /v1/admin/seal` against a running daemon (CLI
verb `mint seal`), gated by an `op=admin:seal` discharge — the same
operator-auth machinery as `invite` and `enroll`. The request
carries only authorisation, no content: the daemon hashes its **own
local** `roles_dir/`, MACs the manifest under the keyring, and PUTs
`seal.json` to the bucket synchronously. The running daemon already
holds bucket credentials, so there is no pending file and no
deferred publish.

### Dormant until sealed

A `mint serve` that finds no verifiable seal in the bucket comes up
**dormant**: the auth and admin planes (`/v1/login`, `/v1/discharge`,
`/v1/admin/*`) are live, but the role-rendering plane
(`/v1/assume-role`) returns *not sealed* and the readiness probe
reports not-ready. This is the load-bearing state. It works because
the auth and admin planes are seal-independent — they key off the
keyring, never off templates — so a dormant daemon can still
authenticate the operator and accept the seal that lifts it out of
dormancy.

Dormant-until-sealed replaces both the old auto-seal-on-first-start
and the old refuse-to-start-on-missing-seal. From the bucket's point
of view a missing seal has exactly one shape — there is no
`seal.json` — whether the deployment was never sealed or the seal was
deleted, and mint cannot tell the two apart from bucket state.
Collapsing both to "run dormant, wait for an explicit seal" means
mint never silently re-commits on-disk bytes as canonical, and never
has to make that distinction. It realises the design's intent —
*explicit `mint seal` first, every time* — that the local-CLI flow
could not, because there was no running daemon to seal against on a
cold box.

The host that authors a seal (`POST /v1/admin/seal`) swaps its own
served surface live. After PUTting `seal.json` and writing its sealed
cache, it builds the surface from its own config — which satisfies the
seal it just authored by construction — and atomically replaces what it
was serving (an `ArcSwap`; in-flight requests finish against the surface
they started on). So `mint seal` takes effect immediately on the host it
runs against, whether that host was dormant or already serving an
earlier seal. Other hosts do not watch the bucket; they adopt the new
canonical seal on their next restart (see *Startup*), so a fleet still
converges through a rolling restart — the authoring host is simply the
first to flip. The swap is the last step and has no side effects: PUT
bucket → write cache → swap, so a crash before the swap leaves bucket
and cache consistent and a restart resolves to the same surface.

### The sealed cache

`roles_dir/` cannot be both the served content and the
"must-match-the-seal" content without creating a do-not-restart
window: the moment provisioning updates templates fleet-wide, every
host's local files diverge from the still-canonical seal, and a
restart in that gap can't reconcile. The sealed cache removes the
window by separating the two roles.

`<data_dir>/sealed/` holds a host's last-verified sealed state:

```
<data_dir>/sealed/
  seal.json                 # copy of the canonical seal this cache satisfies
  policies/<blake3>         # one file per policy template, content-addressed
  env.json                  # materialised [env] values, pinned by env_blake3
```

The cache is a *derived* artefact — always reconstructable from
`roles_dir/` + `[env]` + a canonical `seal.json` — so it is not precious; it is
content-addressed and `ls`/`cat`-inspectable like the rest of mint's
on-disk state. The seal holds only hashes, so the bytes have to be
persisted somewhere for a restarting host to serve last-sealed content
after `roles_dir/` drifts; keeping them in a local cache (rather than
in the bucket) gives that restart-robustness while template bytes stay
config-managed and out of the bucket.

The cache is written in exactly two places, both from bytes that have
just been verified against a canonical seal:

- The `POST /v1/admin/seal` handler, after it hashes `roles_dir/` and
  publishes `seal.json` — the sealing host caches what it just sealed.
- A restarting host that finds the bucket seal has advanced past its
  cache, and whose `roles_dir/` matches the new seal — it *adopts* the
  new seal by re-deriving the cache (see *Startup*).

Everything in the cache therefore traces to an explicit `mint seal`;
mint never writes the cache from unsealed bytes.

## The seal object

```
_mint/templates/seal.json
{
  "audience":   "mint",
  "roles": {
    "volume-ro": {
      "required_caveats":   ["elide:Volume", "aud", "exp"],
      "min_ttl_seconds":    60,
      "max_ttl_seconds":    2592000,
      "default_ttl_seconds": 2592000,
      "policy_blake3":      "<64 hex>"
    },
    ...
  },
  "env_blake3": "<64 hex>",
  "sealed_at": "2026-05-24T12:00:00Z",
  "kid":       3,
  "mac":       "<64 hex>"
}
```

Fields:

- **`audience`** — copied from `mint.toml`. Caveat checks against
  `aud=mint` are part of the policy surface and must agree across
  the fleet.
- **`roles`** — every field of every `[[role]]` block that bears on
  what mint will render or grant: `required_caveats` and the TTL bounds. The one
  role-block field *not* sealed is `policy_file`: it is replaced by a
  `policy_blake3` content hash, because what matters is the bytes the
  file currently contains, not where the operator put them. The hash is
  over the raw
  file content; no canonicalisation, no whitespace normalisation.
  `Seal::build_from_config` destructures each role exhaustively, so a
  new role-config field is a compile error until it is consciously
  sealed or skipped — the seal cannot fall behind the role surface.
- **`env_blake3`** — BLAKE3 of the canonical `[env]` serialisation, the
  pin for the materialised `sealed/env.json`. Binds the operator-defined
  `{{env.X}}` template values (bucket names, prefixes) into the attested
  surface: a host serves the env it can reproduce to this hash from its
  local `[env]`, not the live config, so the concrete resources a minted
  policy grants on are sealed. A host whose `[env]` can't reproduce the
  hash goes dormant rather than serve divergent authority.
- **`sealed_at`** — RFC 3339 timestamp of the seal operation.
  Operator-readable; not load-bearing for any check.
- **`kid`** — keyring generation that produced the MAC. The
  verifier looks this up in its local keyring.
- **`mac`** — `BLAKE3_keyed(keyring[kid], DOMAIN || canonical_body)`
  where `DOMAIN = "mint-templates-seal-v1"` and `canonical_body` is
  the seal JSON with the `mac` field omitted, encoded by
  `serde_json::to_vec` (deterministic for the field set we use —
  small object, no floats, no Maps with non-string keys). Length-
  prefixing is unnecessary because the JSON is self-delimiting.

## The `mint seal` command

`mint seal` is an authenticated client call to a running daemon,
structurally identical to the other operator verbs (`mint enroll`,
`mint invite`).

```
mint seal [--config <path>]
```

Client side:

1. Load the operator session and fetch an `op=admin:seal` discharge
   over the auth socket — the `operator_session()` path shared with
   every admin verb.
2. `POST /v1/admin/seal` with the operator bundle (`Authorization:
   MintV1 <attenuated-admin-service>,<discharge>` plus the `X-Mint-Pop`
   signature). Empty body.

Daemon side:

1. Verify the discharge and clear `op=admin:seal`. 401 on failure.
2. Walk every `[[role]]` block in the loaded config. For each role,
   read `<roles_dir>/<policy_file>` and hash the bytes with BLAKE3.
3. Build the seal JSON, MAC under `keyring.current_kid()`.
4. `PUT _mint/templates/seal.json` (overwrite — the operator is the
   authority; no etag-CAS). Append an audit entry naming the kid,
   `sealed_at`, the operator subject, and per-role hashes.
5. Write the sealed cache to `<data_dir>/sealed/` from the bytes just
   hashed — the sealing host now holds a cache for the seal it
   published.
6. Atomically swap the served surface to the one just sealed; the new
   content is live on this host immediately, dormant or not. In-flight
   requests finish against the surface they started on.
7. Return the kid, `sealed_at`, and per-role hashes to the client,
   which prints a one-line summary.

The daemon seals its **own local** `roles_dir/` — there is no
upload. On the host the operator seals against, whatever the
config-management plane placed on disk becomes the committed content;
every other host adopts the published seal (re-deriving its own cache
from its own local files) the next time it restarts (see *Deployment
shapes*). This is the "one host signs" semantics.

The first seal on a fresh deployment authenticates with the
bootstrap `admin-service` that `mint serve` mints at first start. That
requires filesystem access to `<data_dir>` but **not** to
`<data_dir>/root_keys/`: the keyring stays the daemon's, and sealing
never requires a human to read it. Once the first operator is
enrolled, seals are fully remote. Seal is, in every respect, just
another admin verb — attributable to an operator subject, revocable
by revoking that operator's enrolment.

## Startup

On `mint serve`:

1. Load the keyring. `GET _mint/templates/seal.json`.
   - **No seal** (`NotFound`): run **dormant** — serve the auth and
     admin planes, return *not sealed* from the role-rendering plane,
     report not-ready, **log loudly**. An operator's `mint seal`
     publishes a seal; a restart then loads it.
   - **Unverifiable** — `kid` not in the ring (retired/unknown) or MAC
     mismatch under the named kid: run **dormant** and **log loudly**.
     A canonical baseline can't be established; recovery is the same as
     a missing seal — `mint seal` re-publishes under the current kid
     against the running (dormant) daemon, then restart. Dormant rather
     than refuse keeps recovery in-band: there is always a running
     daemon to seal against. (A bucket attacker can force this state,
     but only to the same effect as deleting the seal — denial of
     role-serving, recovered by re-seal; they cannot produce a seal
     that *verifies* without the keyring.)
2. **Serve the cache if it satisfies this seal.** If `<data_dir>/sealed/`
   holds a cache whose `seal.json` is semantically equal to the bucket
   seal (same `audience` and `roles` map including per-template hashes;
   `sealed_at`/`kid`/`mac` ignored), re-hash the cached policy bytes
   against the seal's `policy_blake3` (cheap integrity check on the
   bytes about to be served).
   - Match → load into the in-memory `TemplateSet` and serve. **The
     bucket seal being unchanged means `roles_dir/` is not consulted to
     decide what to serve.**
   - Cache tampered/corrupt (bytes don't match) → fall through to (3).
3. **Otherwise adopt the seal from `roles_dir/`.** No cache, or the
   bucket seal has advanced past the cache. Hash `roles_dir/` + the
   `mint.toml` role blocks against the bucket seal.
   - Match → write `<data_dir>/sealed/` from these bytes, load, serve.
   - Mismatch → this host cannot produce the canonical content (its
     templates are behind, or misprovisioned, or tampered). Run
     **dormant** and **log loudly** with the diff. It recovers when
     provisioning delivers matching templates and it restarts, or when
     the fleet is re-sealed to content it does have.
4. **Drift check (always, informational).** Independently of the above,
   hash `roles_dir/` and compare to the served cache. On mismatch, **log
   loudly** *"staged template changes are not sealed; run `mint seal` to
   commit"* — and serve anyway. This is the visible signal for the
   edited-but-not-resealed state; it never blocks a restart.

No content or seal state ever crashes the process: mint is always
either **serving the canonical content** or **dormant and not-ready**,
with a loud log on every not-serving path. Only genuine infrastructure
errors (keyring unreadable, bucket unreachable, config unparseable)
hard-fail startup.

The dormant diff in (3) names the specific divergence — *"role
volume-ro: required_caveats sealed as [elide:Volume, aud, exp], local
has [aud, exp]; deliver the sealed templates to this host or re-seal."*
The cache is immutable for the process lifetime; the request path reads
it without locking and consults nothing on disk.

## Runtime behaviour

There is no per-render hash check. The in-memory `TemplateSet`,
loaded from the sealed cache at startup, is the trusted source of
bytes from the moment startup passes until the process exits.
Mid-runtime fs changes to `roles_dir/` *or* to `<data_dir>/sealed/`
have zero effect on what mint renders.

This is stronger than per-render re-hashing: with the in-memory
model, the "compromise window" is exactly the gap between mint
starting and the next restart. No transient states, no race between
"files updated" and "files re-hashed," nothing for an attacker to
exploit between a successful render and the next file read. The bytes
that were verified at startup are the bytes that get rendered.

It also costs less: BLAKE3 is fast but per-render fs reads and
hashes are still allocation-and-syscall work that the in-memory set
eliminates.

`fs::read` (which we use to load the sealed cache into memory) copies
into anonymous heap, so OS paging out a page just means it comes back
from swap when accessed — never from disk. This is unlike `mmap`,
which would re-read from disk on page-fault and reintroduce the tamper
window. We do not use `mmap`.

## Deployment shapes

### Single instance / first bring-up

```
mint serve              # comes up dormant — no seal yet
mint seal               # authenticated; daemon hashes local templates, publishes, and serves
```

To update templates:

```
edit roles_dir/volume-ro.json   # via config-management
mint seal                       # re-publishes over the new content and serves it
```

The seal call needs no downtime and no restart — the host it runs
against swaps to the new content the moment it publishes.

### Multi-instance

Templates are distributed to every host by the provisioning system,
exactly as `mint.toml` is. To (re)seal the fleet:

1. Provisioning writes the template files to every host.
2. Operator runs `mint seal` once, against any one running host.
   That daemon hashes its local templates, publishes `seal.json`, and
   swaps its own surface to serve the new content immediately.
3. Rolling-restart the other hosts. On restart each sees the seal has
   advanced past its cache, adopts it by re-deriving its cache from its
   own local templates, and serves. A host provisioning hasn't reached,
   or whose files were tampered, can't reconcile to the new seal and
   comes up **dormant + not-ready** (not a crash) — held out by the
   orchestrator until it is reprovisioned and restarted.

A fleet brought up from cold comes up all-dormant; the single seal in
step 2 brings the host it runs against to serving, and the rolling
restart in step 3 brings the rest. No host needs shell access for the
seal — it is a network call to one daemon, gated by an operator
discharge.

### Restart before re-seal is safe

The window between steps 1 and 2 — templates updated fleet-wide,
nothing re-sealed yet — used to be a do-not-restart zone. With the
sealed cache it is not. A host that restarts in that window finds the
bucket seal unchanged from its cache, so it serves its cache (the
still-canonical prior content) and ignores the staged `roles_dir/`
drift, logging the drift loudly. The new content goes live only at the
restart *after* step 2's re-seal. Crashes, autoscaling, and rolling
node replacement during a template rollout are therefore safe; they
never strand a host on un-reconcilable state.

### Rollout consistency note

The window between "seal published" and "every host has been
restarted to load it" has a mixed fleet: some hosts still serving the
old in-memory `TemplateSet`, some on the new. Mint does not enforce
single-version-at-a-time across the fleet — that's an
orchestration question.

For most template changes (additive permissions, narrowing
constraints) the mixed window is fine. For changes between
mutually-incompatible policies the operator's options are:

- **All-down → seal → all-up.** Downtime-tolerant; trivially
  consistent.
- **Forward-compatible two-phase rollout.** Step 1 publishes a
  policy that is a superset of both old and new; step 2 narrows
  to the new policy. Standard rolling-deploy territory.

The seal model intentionally pushes this question to the
orchestrator rather than baking it into mint.

## Relationship to keyring rotation

The keyring is the trust anchor for the seal MAC; that's the only
hard coupling. The cadences are independent: keys rotate for
hygiene/compromise, seals rotate when policy intent changes.
Forcing a re-seal on every key rotation adds ceremony; forcing a
key rotation on every seal is nonsense.

The happy-path workflow re-seals before retiring, so the seal is
already under the current kid when the old one goes away:

```
mint seal              # re-publishes under current kid
... wait for fleet to restart and verify against the re-sealed manifest
mint admin keyring retire <old_kid>
```

If a daemon does restart while the canonical seal is still under a
retired kid, it can no longer verify the seal and comes up **dormant**
(*Startup*, unverifiable case) rather than refusing — the operator
re-seals under the current kid against the running dormant daemon,
then restarts. Recovery never requires a seal authored offline.

A `mint admin keyring inspect-kid <kid>` (future) reports both the
approvals and the seal still under that kid, so the operator can
audit what `retire` would invalidate before pulling the trigger.

Lazy migration (the
`Store::migrate_approval_to_current_kid` pattern) does not apply
to the seal — the seal is a singleton, and the operator's
`mint seal` invocation is the natural moment to rebind it. Auto-
re-MAC on startup-with-stale-kid would defeat the explicit-consent
principle (mint would silently change the canonical state under an
operator's nose every time the keyring rotated).

## What's out of scope

- **Fleet-wide live reload.** The host that runs `mint seal` swaps its
  own served surface live (see *Dormant until sealed*), but other hosts
  do not watch the bucket seal — they adopt a new canonical seal on
  their next restart, not the moment it is published. A fleet converges
  through a rolling restart, not a push.
- **Auto-seal.** Mint never commits on-disk bytes as canonical on its
  own. The dormant state makes the first seal an explicit operator
  action like every later one, and removes the "operator deletes the
  seal and a restart silently re-commits" failure mode.
- **Per-role manifests.** One whole-deployment seal keeps things
  atomic and matches the "all hosts agree" property exactly. A
  per-role split saves nothing in the common case and complicates
  the rollout story.
- **Template-content distribution via the bucket.** Templates are
  config-managed out-of-band, same as `mint.toml`. The seal holds
  only their hashes, not their bytes. Bucket bandwidth is for
  enrollment state, not deploy artefacts.
- **Config outside the `[[role]]` blocks.** The seal covers the role
  surface (`audience`, every role block and each policy file), not the rest of
  `mint.toml`, which carries host-specific settings that legitimately
  vary across the fleet (listener address, `data_dir`, the
  `[demo_auth]` transport, the operator admin-service's `[operator]`
  location). The operator/demo endpoints in particular are left
  unsealed deliberately: repointing one is a denial-of-service, not an
  authority escalation, because a discharge from a rogue endpoint still
  has to verify under the third-party-caveat key mint holds.
- **Template version stamped in issued credentials.** The credential
  macaroon doesn't carry the template version; the seal at
  render-time governs render-time. Stamping would add a second
  authority surface for no operational benefit.
- **Cryptographic role-block parsing.** The seal pins the literal
  values in `roles` (caveat names as written, TTL bounds as
  integers). It does not normalise. Two semantically-identical
  configs with different field order or whitespace will produce
  different seals — that's fine, the operator re-seals on every
  change.

## Open questions

1. **Whether `mint seal` should pre-render policies and verify
   they compile against a synthetic caveat set.** Catches
   "template parses but breaks at render time" at seal time
   rather than first-request time. Cheap to add; possibly v1.1.

## Resolved during design

- **Bucket credentials for sealing.** There is no cold seal: `mint
  seal` runs against a running daemon, which already holds the bucket
  credentials it uses for every `_mint/` write. No separate principal
  for sealing.
- **Where the audit-log entry lives.** Written synchronously by the
  daemon in the `POST /v1/admin/seal` handler, recording the operator
  subject, kid, `sealed_at`, and per-role hashes — one event, one
  timestamp.
- **Distinguishing never-sealed from seal-deleted.** Not
  distinguished. Resolved by the dormant state: both present as "no
  `seal.json`," and dormant is the same safe behaviour for both —
  serve no roles, wait for an explicit seal, never re-commit on-disk
  bytes silently.
- **Restart between seal and serving.** Engineered away on the
  authoring host: `POST /v1/admin/seal` swaps that host's served
  surface live, dormant or not. Other hosts still pick up a new
  canonical seal on their next restart — a rolling restart, not a
  fleet-wide push (see *Fleet-wide live reload*).
- **Restart-before-reseal must stay safe.** Resolved by the sealed
  cache: serving reads `<data_dir>/sealed/` (verified against the
  canonical seal), not `roles_dir/`, so a host can restart during the
  fleet-wide template-update window without stranding on
  un-reconcilable state. Putting the bytes in a local cache rather than
  the bucket keeps templates config-managed and out of the bucket while
  still giving the restart-robustness that bucket-stored bytes would.
- **Cache integrity vs `roles_dir/` drift.** Two distinct cheap hashes
  on every restart: the *served* cache bytes are re-hashed against the
  seal (tamper-evidence on what is rendered), and `roles_dir/` is
  hashed against the cache (a loud, non-blocking warning that staged
  edits are not yet sealed).
