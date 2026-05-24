# Mint template seal

## Status

Proposed. Follows on from `docs/design-mint.md` § *Mint state in the
tenant bucket* and § *Root-key rotation* (the keyring landed in
PR #454). No code yet — this doc is the design.

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
   change what mint renders. Filesystem tamper of `roles_dir/` or
   `mint.toml` is detected before any IAM call.
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
holding the keyring can.

At startup, mint reads the seal, verifies the MAC, hashes its own
local files, and refuses to start on mismatch. Once running, mint
serves entirely from an immutable in-memory cache loaded at startup
— the on-disk files are not re-read on the request path.

The seal is replaced by a single explicit operator command,
`mint seal`. The command is purely local — it reads templates,
signs the manifest under the keyring, and writes the result to
`<data_dir>/pending-seal.json`. The bucket PUT happens inside
`mint serve` on the next startup, so the CLI needs no bucket
credentials of its own. There is no auto-seal-on-start and no
hot-reload — a running mint instance has exactly one possible
state with respect to templates: *verified against the current
canonical seal, serving from the in-memory cache loaded at that
verification.* Anything else is "not running."

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
      "policy_file":        "volume-ro.json",
      "policy_blake3":      "<64 hex>"
    },
    ...
  },
  "sealed_at": "2026-05-24T12:00:00Z",
  "kid":       3,
  "mac":       "<64 hex>"
}
```

Fields:

- **`audience`** — copied from `mint.toml`. Caveat checks against
  `aud=mint` are part of the policy surface and must agree across
  the fleet.
- **`roles`** — every role block, with one composed field: each
  role's `policy_file` is replaced by a `policy_blake3` content
  hash. The filename is part of the role config, not the seal's
  authority — what matters is the bytes that file currently
  contains. The hash is over the raw file content; no
  canonicalisation, no whitespace normalisation.
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

A top-level CLI subcommand. The authoring step is purely local —
read templates, hash, MAC under the keyring — and the result is
written to a pending file on disk for `mint serve` to publish on
its next startup. The CLI never opens the bucket.

```
mint seal [--config <path>]
```

Steps:

1. Load `mint.toml`. Walk every `[[role]]` block.
2. For each role, read `<roles_dir>/<policy_file>`, hash the bytes
   with BLAKE3, store `(role_name → role_block_with_hash)`.
3. Load the keyring (`<data_dir>/root_keys/`).
4. Build the seal JSON, MAC under `keyring.current_kid()`.
5. Write the signed seal to `<data_dir>/pending-seal.json` (atomic
   tmp+rename, mode 0600). Print a one-line summary to stdout
   naming the kid, `sealed_at`, and per-role hashes.

That's it. No bucket I/O, no IAM-plane work, no daemon dependency.
The CLI's required surface is exactly what the operator needs to
run mint at all: filesystem access to `roles_dir/`, `mint.toml`,
and `<data_dir>/root_keys/`. Cold `mint seal` against a stopped
daemon works identically to `mint seal` against a running one —
both stage the same pending file.

The pending file is signed under the same keyring as approvals and
credential macaroons. An attacker with fs access to `<data_dir>/`
already holds the keyring; the pending file is no more sensitive
than what was already there.

Subsequent `mint seal` invocations overwrite `pending-seal.json`.
The operator can also discard a pending seal pre-restart by
removing the file — explicit, easy to undo.

## Publishing on `mint serve` startup

The PUT to the bucket happens inside `mint serve`. On startup,
before the existing verification path:

1. Load the keyring.
2. If `<data_dir>/pending-seal.json` exists:
   - Verify its MAC under the keyring. Invalid kid or bad MAC →
     **fail closed**, leave the pending file in place, and refuse
     to start with the specific reason and the file path. The
     pending stays on disk so the operator can inspect what was
     staged before deciding how to resolve. This case usually
     means the keyring was rotated and the authoring kid retired
     between `mint seal` and the restart — operationally
     surprising and worth surfacing, not silently recovering from.
     Resolution: either re-run `mint seal` (overwrites the pending
     under the current kid; same intent if templates are unchanged)
     or `rm <data_dir>/pending-seal.json` (discards the staged
     intent, falls back to the existing bucket seal). Then
     restart.
   - `GET _mint/templates/seal.json` (the current canonical seal,
     if any).
   - If the canonical seal exists and is **semantically equal** to
     the pending (same `audience`, same `roles` content including
     per-template hashes — ignoring `sealed_at`, `kid`, `mac`),
     delete the pending file and proceed: another host already
     published this intent.
   - Otherwise: `PUT _mint/templates/seal.json` (overwrite — the
     operator is the authority; no etag-CAS), then delete the
     pending file.
   - In either case, append an audit entry naming `kid`, the
     pending's `sealed_at`, the daemon's published-at timestamp,
     and per-role hashes.
3. Proceed with startup verification against the canonical bucket
   seal (next section).

Semantic equality is a small helper, intentionally narrow: a
strict comparison over the *intent* fields (`audience` and the
`roles` map with its hashes), ignoring the *metadata* fields
(`sealed_at`, `kid`, `mac`). This is what handles the
"every-host-signs / first-restart-wins / subsequent-restarts-
reconcile" pattern below: identical intent on two hosts produces
seals that differ only in `sealed_at` (and therefore `mac`), and
the second host gracefully recognises the bucket already
represents its intent.

A `mint serve` with no pending file falls through to startup
verification unchanged — the steady-state path is cheap (no
extra reads, no extra writes).

## Startup verification

After the publish-pending step above:

1. `GET _mint/templates/seal.json`. If `NotFound`: refuse to start
   with *"no template seal at `_mint/templates/seal.json`; run
   `mint seal` first."* No implicit-first-seal — deleting the seal
   must not silently re-commit whatever's on disk on the next
   restart.
2. Verify the seal's MAC. If `kid` is not in the ring (retired or
   unknown): refuse to start with the diff. If MAC mismatches under
   the named kid: same.
3. Load `mint.toml` locally. Compare its role blocks to the seal.
   Any drift in `required_caveats`, TTL bounds, etc. → refuse with
   the diff.
4. For each role, read `<roles_dir>/<policy_file>`, hash, compare to
   the seal's `policy_blake3`. Any mismatch → refuse with the diff.
5. Parse and template-compile each policy file once. Hold parsed
   templates in memory (`Arc<TemplateSet>`).
6. Proceed to serving.

The cache is immutable for the process lifetime. The request path
reads it without locking; render-time consults nothing on disk.

The error messages on (1)–(4) name the specific divergence — *"role
volume-ro: required_caveats sealed as [elide:Volume, aud, exp], local
has [aud, exp]; restore the sealed values or run `mint seal` to
commit the new content."* Refuse-closed is binary; the operator needs
to know which side to bring into agreement.

## Runtime behaviour

There is no per-render hash check. The in-memory cache is the
trusted source of bytes from the moment startup-verification passes
until the process exits. Mid-runtime fs changes to `roles_dir/`
have zero effect on what mint renders.

This is stronger than per-render re-hashing: with the in-memory
model, the "compromise window" is exactly the gap between mint
starting and the operator running a fresh `mint seal`. No transient
states, no race between "files updated" and "files re-hashed,"
nothing for an attacker to exploit between a successful render and
the next file read. The bytes that were verified at startup are the
bytes that get rendered.

It also costs less: BLAKE3 is fast but per-render fs reads and
hashes are still allocation-and-syscall work that the cache
eliminates.

`fs::read` (which we use to load the templates into memory) copies
into anonymous heap, so OS paging out a cache page just means the
page comes back from swap when accessed — never from `roles_dir/`.
This is unlike `mmap`, which would re-read from disk on page-fault
and reintroduce the tamper window. We do not use `mmap`.

## Deployment shapes

### Single instance

```
mint seal              # stages pending-seal.json locally
mint serve             # publishes the pending, verifies, runs
```

To update templates:

```
systemctl stop mint
edit roles_dir/volume-ro.json
mint seal              # stages the new pending
systemctl start mint   # publishes + verifies + runs against new content
```

The downtime window is the restart itself — small for a stateless
auth service.

### Multi-instance (recommended: every host signs)

`mint seal` is a purely local operation, so the simplest workflow
is to run it on every host as part of the same provisioning step
that drops in the new template files:

1. Provisioning system writes the new template files to every host.
2. Same provisioning system runs `mint seal` on every host.
   Each host stages its own `pending-seal.json` over the same
   template inputs — identical intent, different `sealed_at`.
3. Rolling-restart every host. The first restart publishes its
   pending to the bucket. Each subsequent restart, on seeing both
   its local pending and a bucket seal already representing the
   same intent (semantic equality), deletes its pending and
   proceeds. No operator coordination required.

A host that gets restarted before steps 1–2 have been applied to
it fails startup verification (local templates don't match the
bucket seal) — caught by the orchestrator before any client is
routed to a half-updated instance.

### Multi-instance (alternative: one host signs)

If the operator prefers, `mint seal` can be run on a single host
(any one) before the rolling restart. The signed host's pending
publishes on its restart; remaining hosts have no pending file
and verify against the freshly-published bucket seal. Same end
state.

Either pattern works because semantic-equality reconcile makes
"every host signs" benign: redundant pending files don't cause
extra writes or conflicting intent, they just get cleaned up
quietly. Pick whichever fits the provisioning pipeline better.

### Rollout consistency note

The window between "seal published" and "every host has been
restarted to load it" has a mixed fleet: some hosts still on the
old in-memory cache, some on the new. Mint does not enforce
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

One concrete interaction: when a kid is retired
(`Keyring::retire`), any seal MAC'd under that kid stops verifying.
This is identical to the approval-record story (PR #454) and has
the same operator workflow:

```
mint seal              # re-signs under current kid
... wait for fleet to restart and verify against the re-sealed manifest
mint admin keyring retire <old_kid>
```

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

- **Hot reload.** No `mint admin templates seal` endpoint. The
  single-state principle is worth the small restart cost. If hot
  reload becomes load-bearing we can add it later as a separate
  decision.
- **Per-role manifests.** One whole-deployment seal keeps things
  atomic and matches the "all hosts agree" property exactly. A
  per-role split saves nothing in the common case and complicates
  the rollout story.
- **Template-content distribution via the bucket.** Templates are
  config-managed out-of-band, same as `mint.toml`. The seal holds
  only their hashes, not their bytes. Bucket bandwidth is for
  enrollment state, not deploy artefacts.
- **Auto-seal on first start.** Explicit `mint seal` first, every
  time. Eliminates the "operator deletes the seal and a restart
  silently re-commits" failure mode.
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

- **Bucket credentials for cold `mint seal`.** Resolved by
  deferred-PUT: the CLI never touches the bucket, so no
  cold-mode credential question. The daemon's existing bootstrap
  admin credential remains the single principal for `_mint/`
  writes.
- **Where the audit-log entry for `mint seal` lives.** Resolved
  by deferred-PUT: the daemon writes the audit entry on its next
  startup, when it actually publishes. The pending file carries
  the CLI-side `sealed_at` so the audit entry can record both
  "authored at" and "published at" times.
- **Behaviour when `pending-seal.json` exists but the keyring no
  longer holds its kid.** Resolved as fail-closed (leave file in
  place, refuse to start with reason + path). Operator inspects,
  then either re-runs `mint seal` or `rm`s the file. Auto-discard
  was considered and rejected — the situations that produce this
  state (sequencing mistake, compromise response, very-stale
  pending) are all things the operator wants to be told about,
  not silently recovered from.
