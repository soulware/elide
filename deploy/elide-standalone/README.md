# Running the Elide coordinator standalone

This deploys an Elide coordinator on Fly.io that talks to Tigris directly with a
read/write keypair — no `mint`, no enrollment, no auth or attestation service.
The coordinator signs every S3 operation with the `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` in its environment and vends that same keypair to each
volume it serves. For the mint-backed deployment (per-volume scoped credentials,
operator-gated enrollment), use `deploy/elide/` instead.

`Dockerfile` + `fly.toml` (from the committed `fly.toml.example`) deploy the
coordinator as a **private** Fly app (no public service): it binds no TCP port,
its control plane is an in-container UDS, and ublk is local. The image downloads
the released `elide`, `elide-coordinator`, and `elide-import` binaries — the
newest release by default, or the tag `deploy.sh` pins — bakes `DATA_BUCKET`
into `coord.toml`, loads `ublk_drv`, and runs `elide-coordinator serve`.
Coordinator state (`index/`, `cache/`, keys) lives on the `elide_data` volume
and survives redeploys.

Prerequisites: the `fly` CLI, a Tigris bucket, and a keypair with read/write on
it (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`).

1. Copy the template — `cp fly.toml.example fly.toml` (the live `fly.toml` is
   gitignored) — and set `app` / `primary_region` and the `DATA_BUCKET` build
   arg (= `coord.toml`'s `[store].bucket`). All deploy commands run from this
   directory.
2. `fly apps create <app>`.
3. `fly secrets set AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=…`.
4. `fly deploy` — runs the newest elide release; the first deploy creates the
   `elide_data` state volume (`initial_size` in the template). To deploy a
   specific release, `./deploy.sh v0.1.2` verifies the tag's assets exist and
   passes its path as the `ELIDE_RELEASE` build arg.

The coordinator comes up serving immediately — there is no enrollment step. If
the keypair secrets are unset it fails loudly at startup (`AWS_ACCESS_KEY_ID not
set`) rather than falling back to an instance-metadata credential probe.

## Creating volumes

The coordinator's control plane is a UDS inside the machine, so volume
operations run there:

    fly ssh console
    elide volume create <name> …

(The image sets `ELIDE_COORD_CONFIG=/app/coord.toml` and
`ELIDE_DATA_DIR=/data/elide_data`, so the subcommands need no `--config` or
`--data-dir`.)

## What this is not

The keypair is shared, unscoped, and long-lived: every volume the coordinator
serves can read and write the whole bucket. There is no per-volume IAM scoping
and no operator authorization on writes. That is the deliberate trade for a
simplified deploy; `deploy/elide/` is the scoped, mint-backed alternative.
