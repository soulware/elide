# Elide attestation authority (coord B) on Fly.io

A dedicated, discharge-only coordinator instance. It assumes `attest-ro`
through mint, opens attested TPC CIDs under `K_M-B`, and serves
`POST /v1/discharge` over 6PN — none of the volume serving, supervisor, GC,
or import a full coordinator runs (`docs/design/mint-volume-attestation.md`
§ *A dedicated attestation instance*, shape 2). It runs
`elide-coordinator attest` against `coord.toml`.

## Prerequisites

- A deployed mint app (`deploy/mint`) and a Tigris data bucket.
- `K_M-B` in `coord.toml` must be **byte-identical** to mint's, and `K_M-A`
  to mint's and to `deploy/elide/coord.toml`: mint seals attested CIDs under
  `K_M-B` and coord B opens them; `K_M-A` self-issues the enroll gate. A
  mismatch fails every discharge open.

## Deploy

```sh
cp fly.toml.example fly.toml      # then set app / primary_region / build args
fly volumes create elide_data --size 1 -a <app>
./deploy.sh                        # resolves the latest elide release tag
```

The app is private (no public service); it binds `0.0.0.0:8087`, reachable
over 6PN at `<app>.internal:8087`.

## Enrol (once, over `fly ssh`)

The daemon comes up and waits for enrollment. Enrol it as a read-only
attestation authority:

```sh
fly ssh console -a <app>
elide login --subject <operator>
elide coord enroll --attestation <invite>
```

Then approve it on the mint app (`mint enroll approve <coord-sub>`). coord B
then assumes `attest-ro` and starts serving discharges. An attestation
enrollment grants `attest-ro` only.

## Point the volume coordinator(s) at it

Each volume coordinator (`deploy/elide`) fetches discharges from here rather
than running its own authority. Set `ATTEST_APP` to this app in its `fly.toml`
build args — it bakes into `coord.toml`'s `attestation_transport` as
`http://<this-app>.internal:8087` — then redeploy that coordinator.
