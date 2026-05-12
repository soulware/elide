# Auth model: macaroons, operator tokens, isolation

This doc captures the coordinator's auth surface in one place: how volume
processes authenticate to the coordinator, how human operators authenticate
the destructive verbs in the CLI, and what these mechanisms do and do not
enforce given the same-host trust model.

The high-level shape:

- **Volume macaroons** — minted on `register`, PID-bound, scope-bound. Used
  by volume processes to request short-lived read-only S3 credentials.
  Implemented today.
- **Operator tokens** — minted on `elide token create` (IPC), not
  PID-bound, attenuated per use by the CLI to the narrowest volume/expiry
  needed. Used to gate destructive coordinator verbs (`remove`, and later
  `release --force`, `coord stop --stop-volumes`). Proposed.
- **Isolation model** — the surrounding context that explains what either
  scheme can enforce on a shared-uid host.

## Macaroon construction

The coordinator holds a **root key** (32 random bytes, generated at first
start, stored at `<data_dir>/coordinator.root_key` with mode 0600). All
macaroons are minted against this key. Verification is stateless — no
token storage, no revocation list.

A macaroon is a chain of typed caveats with a chained MAC:

```
mac_0  = HMAC(root_key,    encode(caveat_0))
mac_i  = HMAC(mac_{i-1},   encode(caveat_i))     for i = 1..n
sig    = mac_n
```

The wire encoding is a single hex line: `v1.<sig hex>.<caveat blob hex>`.

**Why the chain.** A flat MAC over a single caveat blob cannot be
attenuated without re-minting at the root, which means anyone wanting to
narrow a token would need the root key. The chain form lets a holder
append a caveat and recompute the new tail MAC using only the previous
tail — no root-key access. The verifier replays the chain from the root
and compares the final tail. This is the standard macaroon construction
(Birgisson et al., 2014).

**Caveat encoding.** Each caveat is a `(tag: u8, body)` pair where the
body's length is implied by the tag. The tag space is small and shared
across volume and operator tokens; readers ignore tags they don't
recognise *for the purpose of MAC verification* but reject unknown tags
*for the purpose of authorisation* (an unknown caveat is a restriction
the verifier doesn't understand and so cannot honour, so it must fail
closed).

Implemented in `elide-coordinator/src/macaroon.rs` using
`blake3::keyed_hash` as the HMAC primitive.

## Volume macaroons (implemented)

A volume macaroon authenticates a specific volume process to the
coordinator for the duration of that process's life. Caveats:

| Caveat | Value | Purpose |
|---|---|---|
| `volume` | `<volume-name>` | Binds token to this volume only |
| `scope` | `credentials` or `fetch-worker` | Limits the requests this token may make |
| `pid` | `<process-pid>` | Locks token to the spawned process |

### Registration flow

The PID is only known after the volume is spawned, so the macaroon
cannot be minted before spawn:

1. Coordinator spawns volume process, records PID in `volume.pid`.
2. Volume connects to `control.sock` and sends
   `{"verb":"register","volume_ulid":"<ulid>"}`.
3. Coordinator reads peer credentials from the Unix socket connection
   (`SO_PEERCRED`) → obtains peer PID.
4. Coordinator cross-checks: is this PID the one recorded in
   `volume.pid`? If not → `Envelope::Err { kind: "forbidden" }`.
5. Coordinator mints a macaroon with the caveats above (including
   `pid = <peer-pid>`) and replies
   `{"outcome":"ok","data":{"macaroon":"…"}}`.
6. Volume stores the macaroon in memory.

The supervisor writes `volume.pid` immediately after `Command::spawn()`
returns, but a fast-starting volume can reach step 2 before that write
completes. The volume retries `register` a handful of times on a
`forbidden` reply to absorb that window.

### Credential exchange

When the volume needs S3 credentials:

1. Volume sends `{"verb":"credentials","macaroon":"…"}`.
2. Coordinator replays the MAC chain (proves it minted this token).
3. Coordinator checks all caveats: volume matches, scope is
   `credentials`, `pid` matches `SO_PEERCRED` of the current connection.
4. Coordinator issues short-lived read-only credentials scoped to the
   volume's S3 prefix — `by_id/<volume-ulid>/*` (see
   `architecture.md` § *Directory layout*). Issuance mechanism per the
   `CredentialIssuer` selected at coordinator startup (see
   *Credential backends* below).
5. Replies `{"outcome":"ok","data":{access_key, secret_key,
   session_token, expiry_unix}}`.

The PID check on every request means an exfiltrated macaroon is useless
— it can only be presented from the original process. The MAC chain
means no volume can forge a token for a different volume.

### Refresh and clock skew

Short-lived credentials require the volume to refresh before expiry.
The fetcher's `CredentialProvider` re-issues a `credentials <macaroon>`
request when the remaining lifetime drops below 10%, or 60 s, whichever
is greater. Refresh is lazy — driven by the next fetch request, not a
background timer — so an idle volume holds stale credentials until it
next needs to fetch.

A fetch that receives HTTP 403 retries once after forcing a refresh.
This absorbs clock skew between coordinator, volume, and the backend's
signing check. A second 403 propagates as a fetch error.

In-flight fetches started under the old credentials are not cancelled
on refresh — they either succeed under the old signature or fail and
retry with the new one. No lock is held across refresh.

### Token lifetime

The volume macaroon lives for the lifetime of the volume process.
"Token dies when process is stopped" is the revocation model: when the
coordinator stops a volume (on `remove` or coordinator shutdown), the
PID is no longer live. Any subsequent `credentials` request fails the
`SO_PEERCRED` check — the PID either doesn't exist or belongs to a
different process.

No revocation list is needed. This holds as long as the coordinator
runs on the same host as the volumes. If the coordinator were ever
moved off-host (not a current goal), the `SO_PEERCRED` check would be
unavailable and explicit revocation would need to be designed.

## Operator tokens (proposed)

Operator tokens are coordinator-wide macaroons issued to human
operators. They gate destructive CLI verbs — currently `remove`, with
`release --force` and `coord stop --stop-volumes` as the next likely
additions.

### Issuance

```
elide token create [--expires 30d]
```

This is an IPC verb against `control.sock`. The coordinator mints with
its in-memory root key and returns the encoded macaroon; the CLI prints
it to stdout. The operator stores it at `~/.elide/operator-token` (or
passes it via `--token` / `ELIDE_OPERATOR_TOKEN`).

The mint endpoint is ungated beyond socket reachability. The trust
floor for "can mint an operator token" is "can reach the coordinator's
unix socket," which is the same floor as "can perform every other
coordinator operation." There is no separate gate to add here without
moving the trust boundary, and that move requires off-host transport,
which is out of scope.

`--expires` defaults to 30 days. The default is configurable down for
tests; there is no indefinite-lifetime option.

Each minted token carries a fresh 16-byte nonce (cryptographically
random). The coordinator logs the mint event with the nonce, expiry,
and timestamp, so every authenticated operation can be traced back to
the `token create` that produced it.

### Caveats

The minted root token carries:

| Caveat | Value | Purpose |
|---|---|---|
| `role` | `operator` | Distinguishes from volume tokens |
| `nonce` | 16 random bytes | Audit-log linkage to the mint event |
| `not-after` | mint + `--expires` | Required; bounded lifetime |

It does **not** carry a `volume` caveat — the root token is
coordinator-wide. Volume scoping happens per use, via attenuation.

### CLI-side attenuation per use

Each destructive CLI verb appends caveats before sending the token to
the coordinator. Attenuation narrows by three axes: operation, volume,
expiry.

```
stored:     role=operator, nonce=…, not-after=<+30d>
on the wire (volume remove myvm):
            role=operator, nonce=…, not-after=<+30d>,
            op=remove, volume=myvm, not-after=<now+60s>
```

The attenuation is performed entirely in the CLI — no coordinator
round-trip. The verifier checks all caveats: the op must match the
verb being dispatched, the volume (if present in the chain) must
match the verb's target, and the narrowest `not-after` must be in the
future.

The wire token is therefore single-operation, single-volume,
very-short-lived, and useless to anyone who intercepts it after the
fact. The persistent stored token never leaves the operator's machine
in narrowed form.

### Typed operation surface

The `op` caveat is typed, not a free string. The coordinator-side
enum enumerates every gated verb:

```rust
pub enum OperatorOp {
    Remove,
    // ReleaseForce, CoordStopWithVolumes, ... slot in here as
    // new verbs become operator-gated.
}
```

The dispatcher hands the verifier the `OperatorOp` it is about to
execute (`verify_operator(..., OperatorOp::Remove, target_volume)`).
The verifier requires the chain to carry the matching `Op` caveat.
Unknown op-bytes on the wire → `OperatorReject::Malformed` (fail
closed).

Two consequences worth calling out:

- **Exhaustiveness.** Adding a new gated verb is "add an enum variant
  and a dispatch arm." A new verb cannot accidentally inherit
  authority from an existing operator token, because operator tokens
  are minted as `Op = ∅` and only the CLI's attenuation step adds the
  op caveat for the specific verb being invoked.
- **The op caveat must match the entry-point IPC verb,** not any
  sub-operation a handler dispatches internally. Today every gated
  verb is a single dispatch and this is moot, but if a future verb
  fans out into authenticated sub-calls, the design choice is either
  to re-attenuate per sub-call (more macaroon-like) or to document
  that the entry-point caveat is what matters.

### Audit log

The coordinator logs every operator-token-authenticated operation
under `target = "operator_token::authn"` with:

- the nonce (links back to mint)
- the operation name
- the volume target
- the chain's caveats as observed (so the audit trail records what
  scope was actually presented)

Rejection paths log under the same target with a coarse
`OperatorReject` reason. Reasons are intentionally coarse — finer
detail would help an attacker probe token state.

## Isolation model

Volume processes on the same host share a uid and a filesystem. This
has direct consequences for what the macaroon scheme can and cannot
enforce.

**What macaroons do not enforce — local filesystem.** A compromised
volume process can read or corrupt any other volume's local directory
directly, without touching the coordinator. Macaroons provide no
protection here. Proper local isolation requires OS-level mechanisms:
separate uids per volume, Linux user namespaces, or running each
volume in its own container. This is a separate layer and is not
addressed by the current design.

**What macaroons do enforce — S3.** S3 credentials are scoped by IAM
to a specific volume's prefix. This enforcement is external to Elide —
AWS (or equivalent) rejects requests that exceed the credential's
scope regardless of what the caller claims. The macaroon scheme
ensures a volume process can only obtain credentials for its own
volume. A compromised `myvm` process cannot request credentials for
`othervm`, so it cannot read, write, or delete `othervm`'s S3 objects
even with full local filesystem access.

**What operator tokens provide — audit + ceremony, not access
control.** Requiring an operator token for coordinator mutations
raises the bar slightly over bare socket access, and provides an
audit trail. It does not prevent a compromised local process from
achieving the same effect via direct filesystem manipulation (`rm
-rf` on the volume dir achieves `remove` without going through the
coordinator). The value is auditability, forced ceremony for
destructive verbs, and per-request attenuation — not a hard security
boundary against a local attacker.

**Summary:**

| Resource | Isolation mechanism | Enforced by |
|---|---|---|
| S3 data | IAM credential scoping + macaroon gating | AWS + coordinator |
| Local filesystem | uid separation / namespacing | OS (not yet implemented) |
| Coordinator mutations | Operator token + audit log | Coordinator (defense-in-depth) |

## Credential backends

The `credentials` verb delegates to a `CredentialIssuer` selected at
coordinator startup from `coordinator.toml`. The macaroon handshake
runs identically for every backend — only the credential material
returned changes.

| Backend | Issuer | Notes |
|---|---|---|
| AWS S3 | STS `AssumeRole` with a session policy narrowing `s3:GetObject` to `arn:aws:s3:::<bucket>/by_id/<volume-ulid>/*` | Session duration 15 min – 12 h; the coordinator's own role needs `sts:AssumeRole` on a dedicated read-only role |
| S3-compatible with STS (e.g. MinIO, Ceph RGW/STS) | `AssumeRole` against the backend's STS endpoint with the same session policy | Compatibility varies by backend; the session policy shape is the portable part |
| S3-compatible with IAM-keyed policies (e.g. Tigris) | Mint a per-volume access key via `CreateAccessKey`, attach a policy granting `s3:GetObject` on `arn:aws:s3:::<bucket>/by_id/<volume-ulid>/*` (plus ancestor prefixes for forks) with a `DateLessThan` condition | See [`design-iam-key-model.md`](design-iam-key-model.md) |
| S3-compatible without STS or per-key IAM | Coordinator returns its own configured read-only key pair with no per-volume scoping | Defense-in-depth only — the coordinator must be configured with a distinct read-only key, not the upload key. Logged as a downgrade at coordinator startup |
| Local filesystem (`elide_store/`) | No-op issuer — returns a sentinel the volume's fetcher treats as "no auth needed" | Tests and single-host deployments |

The volume never negotiates the backend type. It treats the returned
triple as opaque and passes it to `object_store`; the no-op sentinel
is detected by the fetcher and skips signing entirely.

### Standalone mode (no coordinator)

`serve-volume` accepts `--s3-access-key`, `--s3-secret-key`,
`--s3-session-token` flags for direct credential passing. No macaroon
is involved. This supports the fully standalone tier and is also
useful for development.

## Open questions

- **Bootstrap.** First-ever `elide token create` against a fresh
  coordinator currently has no offline escape hatch (`elide-coordinator
  token create` is dropped under this design). If the coordinator
  socket is unreachable, there is no way to mint. Likely fine —
  destructive verbs are coordinator-mediated anyway — but worth
  noting.
- **Token rotation UX.** No `revoke` command. A leaked token is
  mitigated by its `not-after` and by re-keying the root (which
  invalidates all tokens, including volume macaroons). Whether root
  rotation needs a dedicated verb or can stay manual is open.
- **Backward compatibility of the MAC-chain format change.** Volume
  macaroons live in process memory and don't survive restarts, so
  switching the construction is free for them. Operator tokens are
  new. No on-disk macaroons exist. So the format change is a clean
  break with no migration.

## Future directions

These do not affect the design above; they describe extensions that
slot in cleanly when the threat model or deployment shape warrants
them.

- **Third-party caveats for authentication.** The model above is
  authorisation-only: possession of an operator token is treated as
  operator identity. A future extension adds *third-party caveats* —
  a caveat that says "valid only if the bearer also presents a
  discharge macaroon from `<auth_service>` attesting predicate P."
  This adds a real authentication step (SSO, webauthn, whatever the
  auth service does) tied to each token use, with the discharge's
  lifetime acting as the session length. The chained-MAC construction
  already accommodates this — third-party caveats are just another
  `Caveat` variant whose body is `(location_uri, caveat_id,
  vid_key)`. None of the existing `Op` / `Volume` / `NotAfter`
  surface needs to change.
- **Root key in a separate signing process.** Today the coordinator
  holds the root key in memory. Splitting it into a standalone
  signing service reduces blast radius (coordinator compromise can
  no longer forge across the fleet), gives mint operations an
  independent audit boundary, and enables TPM/HSM backing. Verify is
  hot — every operator-token IPC and every volume `credentials`
  request — so the likely shape is per-coordinator derived keys
  (signing service issues an HKDF-derived sub-key the coordinator
  uses to verify locally) rather than RPC-on-verify. Mint is rare
  enough to comfortably stay RPC. Worth doing when there is more
  than one coordinator host, or when the coordinator's trust level
  is bounded below the key's.
