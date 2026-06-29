# Coord IPC over HTTP+UDS

**Status: proposed. Not yet implemented.** Supersedes the NDJSON+UDS
shape currently documented in
[`architecture.md`](../architecture.md) § *Coordinator inbound socket*
for the CLI ↔ coord surface. The volume-control surface
(coord ↔ volume) is out of scope here and stays on NDJSON+UDS.

## Why

The current coord inbound socket is NDJSON-over-UDS: one tagged
JSON request per line, one or more `Envelope<T>` reply lines, close.
Workable, but the auth pivot in
[`auth-service.md`](auth-service.md) forces the protocol
to grow features that are already part of HTTP — and that mint and
the auth-service already speak natively over the same UDS transport:

- A per-request **authentication header** (the macaroon discharge
  bundle), distinct from the request body.
- A **challenge response** when authentication is missing or
  stale, carrying structured payload (`cid`, `auth_url`) that the
  client must consume before retrying.
- A discriminator for **streaming** vs unary replies — current
  `import attach` / `fetch attach` are bespoke NDJSON sequences.

Reinventing these on top of NDJSON produces a private dialect of
HTTP. Switching to HTTP+UDS removes the translation tax: the
auth surface uses `Authorization` headers and `401 +
WWW-Authenticate: Macaroon`, the streaming surface uses chunked
transfer with NDJSON body, the error surface uses HTTP status
codes. The doc describing operator-auth flows can say the same
words the code uses.

Mint and the auth-service are HTTP+UDS in the demo deployment
already. Unifying the third surface means one transport, one
auth model, one server framework (`axum`), one client crate
(`reqwest`) across the whole Elide control plane.

## Scope

This doc covers **coord inbound** (`<data-dir>/control.sock`,
CLI ↔ coord). Out of scope:

- **Volume control socket** (`<vol-dir>/control.sock`,
  coord ↔ volume process). Internal-only, PID-trusted, no
  operator-auth surface. Stays NDJSON+UDS until a separate motivation
  appears.
- **Remote coord IPC** (coord ↔ coord across hosts). Uses the
  existing peer channel — see
  [`remote-coord-ipc.md`](remote-coord-ipc.md).

## Transport

HTTP/1.1 over UDS at `<data-dir>/control.sock` — same path as today,
same single-socket convention as mint's UDS listener. `axum` on the
server side, `reqwest` on the client side; both already in the
workspace via `mint/`. No TLS at this layer — connection-level
trust is filesystem permissions + `SO_PEERCRED`, the same as today.

## Connection-level authentication

`SO_PEERCRED` UID match is retained. Coord rejects connections whose
peer UID does not match its own (this is the gate that makes "local
IPC = trusted operator surface" hold). Macaroon-based operator auth
layers on top via the `Authorization` header on each request — see
[*Operator-auth integration*](#operator-auth-integration) below.

## Routing

**RPC-style.** Each verb is `POST /v1/<verb>` with the verb's
arguments in the JSON body. Verb names are the kebab-case strings
the current `Request` enum already uses, so the wire vocabulary
doesn't change.

```
POST /v1/snapshot HTTP/1.1
Host: localhost
Content-Type: application/json

{"volume":"foo"}
```

RESTful URLs (`POST /v1/volumes/foo/snapshot`) were considered and
deferred. The 73-verb current surface maps 1:1 to RPC routes;
redesigning each verb's URL structure is independent work and not
required for the transport pivot.

GET is reserved for read-only verbs (status, list); POST is the
default. The mapping is per-verb config, not inferred from the verb
name.

## Request shape

JSON body for verb arguments, exactly the per-variant payload of
today's `Request` enum minus the `verb` discriminator (the URL
carries that). Headers carry transport-level concerns:

- `Content-Type: application/json` (required for any verb with a
  body).
- `Authorization: Macaroon <base64>` (operator verbs only — see
  *Operator-auth integration*).
- Standard HTTP headers (`Accept`, `Content-Length`, etc.) as
  needed.

The IPC frame no longer carries a `bundle` field — the discharge
rides as a header, where it belongs.

## Response shape

HTTP status code + JSON body. The `Envelope<T>` /
`outcome: ok | err` discriminator is **removed**: status code is
the discriminator. Success responses carry the verb-specific reply
payload as the JSON body directly:

```
HTTP/1.1 200 OK
Content-Type: application/json

{"snap_ulid":"01JABC..."}
```

Verbs whose current reply is `null` (no payload) return `204 No
Content` with an empty body.

## Error responses

HTTP status code + JSON body with `message` and any error-kind-
specific fields. The current `IpcErrorKind` enum collapses into HTTP
status codes:

| Current `IpcErrorKind` | HTTP status |
|---|---|
| `NotFound` | 404 Not Found |
| `Conflict` | 409 Conflict |
| `PreconditionFailed` | 412 Precondition Failed |
| `BadRequest` | 400 Bad Request |
| `Forbidden` | 403 Forbidden |
| `Store` | 502 Bad Gateway |
| `Internal` | 500 Internal Server Error |

The error body carries the operator-readable message:

```
HTTP/1.1 404 Not Found
Content-Type: application/json

{"message":"volume foo not found"}
```

Client-side code branches on status code rather than a `kind` string.

## Operator-auth integration

The CLI presents a per-IPC attenuated discharge as the bearer
credential, framed exactly as RFC 7235 `Authorization` for the
custom `Macaroon` scheme:

```
POST /v1/snapshot HTTP/1.1
Authorization: Macaroon <base64-attenuated-discharge>
Content-Type: application/json

{"volume":"foo"}
```

On a missing or stale-`CID` discharge, coord responds with the
canonical 401 challenge ([`auth-service.md`](auth-service.md)
§ *Coord: forward and clear*):

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Macaroon
Content-Type: application/json

{"cid":"<base64>","auth_url":"https://auth.elide.example/"}
```

The `WWW-Authenticate` header is the formal RFC 7235 challenge
mechanism; the body carries the discovery payload the CLI needs to
fetch a fresh discharge. The CLI POSTs `cid` to `auth_url`, gets a
discharge, attenuates per-IPC, retries the original request.

`403 Forbidden` is distinct from `401 Unauthorized`: 401 means "the
discharge needed refresh, here's how"; 403 means "the discharge was
fresh and the caveat clearing failed against this request's context"
(wrong Op, wrong Volume, expired exp on the attenuation). 403
is terminal — the client should not retry with a fresh discharge,
because that wasn't the problem.

Verbs that are read-only and ungated by operator-auth (status,
list, resolve-name) accept requests without `Authorization` and
never 401. Per-verb config declares whether each verb is
operator-auth-gated.

## Streaming verbs

`import attach`, `fetch attach`, and any future verb that produces a
sequence of events use **chunked transfer encoding with NDJSON
body**: one JSON event per line, line-delimited, connection stays
open until the operation completes or the server sends a terminal
event. Same body format as today, different framing layer.

```
HTTP/1.1 200 OK
Content-Type: application/x-ndjson
Transfer-Encoding: chunked

{"event":"progress","bytes":1024}
{"event":"progress","bytes":2048}
{"event":"done"}
```

SSE (`text/event-stream`) was considered and rejected: it adds a
distinct content type and parsing rules for marginal gain over
chunked NDJSON. Chunked NDJSON keeps the per-event JSON shape the
existing handlers already produce.

Error during a stream — e.g. the underlying job fails mid-attach —
is delivered as a final event in the stream (`{"event":"error",
...}`) and the stream closes normally. The HTTP status remains 200
because the stream itself opened successfully; in-stream failures
are application-level, not transport-level.

## Migration

Single wire transport per socket — coord cannot serve both NDJSON
and HTTP on `control.sock` simultaneously. Migration is therefore
**big-bang for coord inbound**: one PR (or PR series on a feature
branch) cuts the entire surface over. Phased per-verb migration is
not viable on a shared socket.

Migration shape:

1. **HTTP listener + router skeleton.** `axum` server bound to the
   UDS socket; one empty handler per current verb. No verb logic
   yet — every handler returns 501 Not Implemented.
2. **Per-verb-group handler migration.** Each verb's handler moves
   from the NDJSON dispatcher (`elide-coordinator::inbound::dispatch`)
   to its `axum` handler, preserving behaviour. Verb groups
   (status family, lifecycle, import, etc.) migrate as units.
3. **Client cutover.** `src/coordinator_client.rs` rewritten to
   issue `reqwest` calls. Same external API; internal transport
   switches.
4. **Drop NDJSON.** Once every verb is on the HTTP path, the
   NDJSON dispatcher is removed. `Envelope<T>` and `IpcError` /
   `IpcErrorKind` types go with it.

The volume control socket is unaffected — it shares the
`Envelope<T>` type today, but that type can split into a coord-
inbound copy (removed) and a volume-control copy (retained) as part
of step 4.

Each step compiles and tests cleanly on its own; the whole
migration is a sequence of green commits, not a "big diff that
becomes safe at the end."

## What the doc deliberately doesn't say

- **Verb-to-route catalog.** The mapping is mechanical — each
  current `Request` variant becomes a `POST /v1/<kebab-name>` route
  with the variant's payload as body. The mapping lives in code,
  not in this doc.
- **HTTP framework choice.** `axum` is in the workspace already
  (mint) and is the only HTTP-server-on-UDS option that's been
  vetted in this project. If a future need outgrows it, that's a
  separate decision.
- **CLI client API.** `src/coordinator_client.rs`'s public surface
  (the `Client` struct and its methods) is unchanged from the
  caller's perspective. Internal transport switches; the API stays.

## Open

- **`SO_PEERCRED` + UDS + HTTP.** `axum` over UDS via `tower` /
  `hyperlocal` exposes the peer credentials on the listener side,
  but the exact integration shape (middleware? extractor?) needs
  pinning at code time. Mint already binds an HTTP server to UDS
  without a peer-cred check; coord's listener will need the check
  added.
- **Volume control socket convergence.** If a future need surfaces
  to gate volume-control verbs with macaroons (e.g. cross-host
  volume control), that's the moment to revisit converging the
  volume socket to HTTP+UDS too. Not in scope now.
