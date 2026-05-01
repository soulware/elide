# Peer segment fetch — v1 implementation plan

Plan for landing the `.idx`-only first iteration of peer fetch. Design lives in [`design-peer-segment-fetch.md`](design-peer-segment-fetch.md); this doc sequences the work.

## Scope

**In:** Opportunistic peer-fetch tier in front of S3 for `.idx` files and `.prefetch` warming hints. Coordinator-driven (matches existing `prefetch_indexes` flow). Single-peer discovery from the volume event log. Bearer-token auth signed by `coordinator.key`, verified entirely against S3. `.prefetch` is an advisory hint (the peer derives it from its local `.present`, but the wire resource is its own thing) used to drive background byte-range prefetch from S3 — body bytes themselves still go direct to S3 in v1.

**Out:** Peer body fetch, image-pull discovery (mDNS / shared registry), TLS, multi-source peer fanout, source-host cache retention policy, release-time hint artifact, per-coordinator rate-limiting / blacklist. See the design doc for rationale.

## Settled decisions

- **Crate:** new `elide-peer-fetch` crate. Clean isolation; the surface (HTTP server, HTTP client, token type) is self-contained and shouldn't bloat `elide-coordinator`.
- **Token signing:** `coordinator.key`. The fetching process signs; for `.idx` + `.prefetch` that's the coordinator.
- **Transport:** plain HTTP/2 for v1. TLS deferred.
- **Coordinator config:** the peer-fetch port is **optional**. Absence ⇒ no peer-fetch server starts and the prefetch path skips the peer tier entirely. v1 ships off-by-default; opt-in per coordinator config.
- **Endpoint registry:** `coordinators/<coordinator_id>/peer-endpoint.toml`, sibling to the existing `coordinator.pub`. Written at coordinator startup when peer-fetch is configured; absent otherwise.
- **URL shape:** `GET /v1/<vol_id>/<ulid>.idx` and `GET /v1/<vol_id>/<ulid>.prefetch`. No batch endpoint — HTTP/2 multiplexing handles fan-out. No mirroring of S3 paths; the peer's local layout is independent.
- **Wire/on-disk decoupling for the prefetch hint.** The wire resource is `<ulid>.prefetch`; the peer synthesises it from its local `cache/<ulid>.present` (v1 returns the bytes as-is). The deliberately different name keeps three distinct things from collapsing — the peer's local cache state, the wire advice, and the new host's own cache state — and leaves room to evolve the encoding (RLE, LBA-restricted, etc.) without renaming the resource.
- **The hint is advisory.** Fetched from the peer as a warming hint, never trusted as authoritative for local cache state; the new host builds its own `cache/<ulid>.present` from its actual fetches.

## Existing infrastructure (no work)

- `CoordinatorIdentity` (load/generate keypair, sign, publish/fetch `coordinator.pub`).
- Volume event log (`append_event`, `latest_event_ulid`, `list_and_verify_events`).
- `prefetch_indexes` in `elide-coordinator/src/prefetch.rs` — natural integration point.
- `volume.pub`, `volume.provenance`, signed ancestor walk.
- `names/<name>` schema with `coordinator_id` of current claimer.

## Work items

### 1. `elide-peer-fetch` crate scaffold

New workspace crate. Public surface:

- `PeerFetchToken` — struct with canonical signing payload; `sign(&CoordinatorIdentity)` and `verify(&VerifyingKey)`.
- `PeerFetchClient` — HTTP/2 client wrapper with token caching (~60 s validity).
- `PeerFetchServer` — HTTP/2 server with route handler and auth middleware.
- `PeerEndpoint` — endpoint-registry record (`peer-endpoint.toml`) with `read`/`write` against an `ObjectStore`.

Dependencies: `hyper` (HTTP/2), `ed25519-dalek` (already in tree via `elide-core`), `object_store`, `serde`/`toml`.

### 2. Endpoint registry

- `PeerEndpoint::write_to_store` — coordinator publishes `coordinators/<id>/peer-endpoint.toml` at startup.
- `PeerEndpoint::fetch_from_store` — read another coord's endpoint by id; returns `None` cleanly on absence.

Coordinator startup (in `elide-coordinator`): when peer-fetch is configured, call `write_to_store` after the existing `publish_pub` step.

### 3. Token type

`PeerFetchToken { volume_name, coordinator_id, issued_at, signature }`. Canonical signing payload: domain tag `"elide peer-fetch v1\0"` + sorted-key serialisation of the non-signature fields. Base64 encoding for `Authorization: Bearer …`.

Tests: round-trip sign/verify; tampered payload fails; expired `issued_at` rejected.

### 4. Peer-fetch HTTP server

Two routes, both full-file GETs (no `Range:` support in v1):

```
GET /v1/<vol_id>/<ulid>.idx       → serves index/<ulid>.idx
GET /v1/<vol_id>/<ulid>.prefetch  → serves cache/<ulid>.present (v1: bytes as-is)
```

Server steps per request:

1. **Auth** (middleware): see item 5.
2. **Route dispatch:** `.idx` → `<data_dir>/by_id/<vol_id>/index/<ulid>.idx`. `.prefetch` → `<data_dir>/by_id/<vol_id>/cache/<ulid>.present` (the peer's local `.present` is the v1 source for the prefetch hint, opaque to the client).
3. **Existence check:** stat-only on miss → 404.
4. **Stream response:** open file, send full contents.

Bind to the configured peer port; only start the server task if the port is configured.

### 5. Auth middleware (peer side)

Five-step pipeline per request, mapping to the four auth properties (identity, ownership, lineage, segment membership):

1. **Decode + freshness.** Extract bearer token from `Authorization`; reject malformed; check `issued_at` within ±60 s of `now`.
2. **Signature.** Fetch `coordinators/<token.coordinator_id>/coordinator.pub` from S3 (cache forever per `coordinator_id`). Verify Ed25519 signature. Mismatch → 401.
3. **Ownership.** ETag-conditional GET `names/<token.volume_name>` from S3 (cache the value, revalidate via `If-None-Match` per request). Confirm `name_record.coordinator_id == token.coordinator_id`. Mismatch → 401.
4. **Lineage.** Walk `volume.provenance` from `name_record.vol_ulid` (signature-verified against `volume.pub`). Cache the resulting ancestry set forever per `volume_name` (provenance is immutable once a volume exists). Check the URL's `<vol_id>` is in the ancestry. Not in lineage → 403.
5. **Segment membership.** Local stat of the file the route resolves to (`index/<ulid>.idx` for `.idx`, `cache/<ulid>.present` for `.prefetch`) under `by_id/<vol_id>/`. Missing → 404.

Caching is pragmatic per check — `coordinator.pub` and ancestry are immutable so cache forever; `names/<name>` uses ETag-conditional revalidation so the auth fence coincides with the S3 CAS (closes the `release --force` window with no TTL gap). See the design doc for the full caching profile and the rationale for not using a time-bounded auth cache.

### 6. Peer-fetch client (caller side)

```rust
PeerFetchClient::fetch_idx(peer_endpoint, vol_id, ulid, token)            -> Result<Option<Bytes>>
PeerFetchClient::fetch_prefetch_hint(peer_endpoint, vol_id, ulid, token)  -> Result<Option<PrefetchHint>>
```

- `Some(_)` on 200.
- `None` on 404 / 401 / 403 / network error / timeout (all treated identically — caller falls through to S3 for `.idx`, drops the warming hint for `.prefetch`).
- HTTP/2 connection pool keyed by peer endpoint; reuse across requests in the same prefetch run.
- Token cached by the client for ~60 s, re-minted on demand.

`PrefetchHint` is a typed wrapper around the wire bytes (v1: a thin newtype around the response). The wrapper exposes "iterate populated extents" — clients consume it as advice, not as raw bitmap state, so a future encoding change doesn't ripple into call sites.

### 7. Discovery hook in claim flow

After the existing claim CAS in `volume claim` succeeds, the handler already loads the latest event in `events/<name>/` for the new `claimed` event's `prev_event_ulid`. Branch on it:

- `kind == "released"` + signature verifies + endpoint resolves → record `(coordinator_id, peer-endpoint)` against this volume's prefetch context.
- Anything else → no peer.

The "peer for this volume's prefetch" hint is held alongside the volume's other registration state, consumed once by the next prefetch tick, and discarded afterwards. (No persistent cross-tick state — fresh prefetches after the initial claim go peer-less.)

### 8. Prefetch integration

In `elide-coordinator/src/prefetch.rs`:

- Extend `prefetch_indexes` to take an optional peer-fetch context (`Option<(PeerFetchClient, PeerEndpoint, CoordinatorIdentity)>`).
- For each missing `.idx`:
  - Attempt peer `fetch_idx(vol_id, ulid)`. On `Some(bytes)`, verify signature, write to `index/<ulid>.idx`. On `None` or verification failure, fall through to the existing S3 path.
  - In parallel, attempt peer `fetch_prefetch_hint(vol_id, ulid)`. On `Some(hint)`, hold in memory and enqueue background S3 Range-GETs for the bytes the hint indicates, populating `cache/<ulid>.body` on the new host. On `None`, no hint is recorded — that segment falls back to demand-only.
- Existing call sites (`tasks.rs:177`, `inbound.rs:1712`) pass `None` initially; the claim-discovery hook (item 7) passes a populated context for the volume just claimed.

The peer-fetched hint is never written to disk under the new host's `cache/<ulid>.present`. The new host's local `.present` is built from the bits its own S3 Range-GETs actually populate (whether triggered by the warming hint or by subsequent demand-fetch once the volume is mounted).

### 9. Tests

- **Unit (`elide-peer-fetch`):** token round-trip; auth middleware happy/sad paths against a mock object store; lineage walk and ancestry-cache reuse; route dispatch (`.idx` vs `.prefetch`).
- **Integration:** spin two coordinators against a shared local object store. Coord A holds `vol-X` with hydrated `index/` and `cache/`. Coord B claims `vol-X` (after A releases); B's prefetch tick uses the claim hint, fetches `.idx` + `.prefetch` from A, and enqueues S3 Range-GETs from the hint. Verify (a) `.idx` files are byte-identical to S3, (b) the body bytes the hint indicated are populated on B's `cache/<ulid>.body` after the prefetch run, (c) B's `cache/<ulid>.present` reflects only the bits B actually fetched (not a copy of the wire response).
- **Failure modes:**
  - A's peer-fetch port disabled → B falls back to S3 cleanly.
  - A's coord crashed (endpoint unreachable) → fallback.
  - `force_released` instead of clean `released` → B skips peer, fetches from S3.
  - Token replay outside `issued_at` window → 401.
  - Caller asserts a `volume_name` they don't currently claim → 401.
  - Caller requests `vol_id` outside the claimed volume's ancestry → 403.
  - A has `.idx` locally but evicted `cache/<ulid>.present` → B gets the `.idx`, the `.prefetch` route 404s, no warming hint; reads fall back to demand-fetch from S3.
- **Counters:** per-prefetch-run hit/miss/error counts (separately for `.idx` and `.prefetch`); logged at info on completion. These are the signal for whether to extend to peer body fetch.

## Sequencing

1. **Item 1** (crate scaffold) and **item 3** (token type) first — small, no I/O, straightforward to test.
2. **Item 2** (endpoint registry) — short, no external dependencies.
3. **Items 4 + 5** (server + auth) together — testable with a mock object store before any client exists.
4. **Item 6** (client) — testable against the server from item 4.
5. **Items 7 + 8** (discovery + prefetch wire-up) — depends on the rest being usable.
6. **Item 9** (tests) — alongside each item; the integration test caps the work.

## Out of scope for v1 (re-stated, for clarity)

- Peer body fetch (body bytes still go direct to S3 in v1; the `.prefetch` warming hint drives those S3 Range-GETs).
- Image-pull discovery beyond "the previous releaser of this name".
- TLS / mTLS.
- Persistent peer-fetch hints across prefetch runs.
- Per-connection or time-bounded auth caching beyond the staleness profile in item 5.
- Per-coordinator rate-limiting / blacklist (auth model exposes `coordinator_id` so this is a cheap drop-in later).
- Multi-tenant peer (peer serving multiple buckets under different scopes).

## Decision criteria for extending to peer body fetch

The point of shipping `.idx` + `.prefetch` first is to learn whether the mechanism is worth the additional complexity of peer body fetch (range arithmetic, partial-coverage semantics, larger transfers). Look for:

- **Peer hit rate** for `.idx` and `.prefetch` for handoff specifically — is it reliably high when the predecessor coordinator is alive and reachable?
- **Warming-hint quality.** Does the peer-fetched `.prefetch` materially reduce time-to-warm vs. demand-only? If yes, peer body fetch (cutting the S3 hop entirely) is the obvious next step. If no, body fetch is a poor bet regardless.
- **Latency improvement** for cold-claim prefetch — measurable reduction in time-to-first-read after `volume claim`.
- **Operational behaviour** through real `release` / `claim` / `release --force` sequences — does the auth fence hold cleanly under `--force`? Are there discovery races that surfaced?

If those are weak, peer body fetch likely isn't worth it. If they're strong, the body-fetch design (sketched in `design-peer-segment-fetch.md`) becomes the natural extension.
