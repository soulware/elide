# Running mint for Elide

[mint](https://github.com/soulware/mint) is a generic credential broker. An
Elide deployment runs the **stock mint binary** sealed with the role inventory
in this directory — there is no Elide-specific mint build. This directory is
that inventory, version-locked to the coordinator:

- **`roles/`** — the four role policy templates (IAM policy JSON). They encode
  Elide's S3 layout and caveat contract directly (`by_id/{{caveat.volume}}/*`,
  `events/*` append-only, `coordinators/{{caveat.sub}}/*`, `meta/*`, `names/*`),
  so they move in lockstep with the coordinator. The `attested-e2e` CI job is
  the lockstep check — it runs the real coordinator client against exactly
  these templates. The volume-data bucket is a literal in each template (`elide`
  by default); a site using a different bucket edits all four.
- **`mint-elide.toml`** — the role inventory + contracts (fixed) plus the keys
  marked `PER-DEPLOYMENT` (mint's admin/store bucket + endpoint, auth/attestation
  discharge URLs, listener). Copy it and fill those in per site.

Caveat provenance is **derived from the template**, not declared: a
`{{caveat.X}}` whose name is reserved (`sub`) is issuer-stamped by mint; any
other name (`volume`) is attested. So `volume-ro`/`volume-rw` are attested by
virtue of binding `{{caveat.volume}}`, and `coord-ro`/`coord-rw` are issuer-only.
Each role's single `ttl_seconds` is the credential lifetime ceiling.

## Roles

| Role | Scope | Notes |
|------|-------|-------|
| `coord-ro` / `coord-rw` | coordinator control plane | directly assumable after enrollment |
| `volume-ro` / `volume-rw` | one volume's `by_id/<vol>/*` | attested + per-volume |

The volume roles are **attested**: `enroll-exchange` returns a durable
intermediate the coordinator holds and finalizes **per volume** under a fresh
attestation-coordinator (coord B) discharge. The operator gate is paid once, at
enrollment; per-volume finalize is unattended. See `docs/design-mint.md` §
*Elide as customer* and `docs/design-mint-volume-attestation.md`.

## Bring-up

Prerequisites: a `mint` binary, an S3/Tigris bucket, an auth service, and an
attestation coordinator (coord B). For mint's own keyring and `mint serve` /
`mint seal` mechanics, see `docs/design-mint.md` § *Mint configuration*.

1. Copy `mint-elide.toml`; fill the `PER-DEPLOYMENT` keys.
2. Provision mint's keyring (`<data_dir>/root_keys/`) out of band.
3. `mint serve --config mint-elide.toml`
4. `mint seal --config mint-elide.toml` — seals the `roles/` templates.
5. Operator: `mint login` (against the auth service), then `mint invite`.
6. Each coordinator: `elide coord enroll <invite>` — provisions the two
   `coord-*` credentials and the two `volume-*` intermediates.
7. Operator: `mint enroll approve <coordinator-sub>`.

Coordinators then finalize per-volume credentials on demand, with no further
operator interaction.

## Deployment shapes

- **Single-host dev** — coordinator + mint co-resident over the UDS `socket`,
  with the demo auth issuer and a co-located coord B. This is the shape the
  `attested-e2e` job exercises; see `docs/design-mint.md` for `[auth.demo]` and
  the co-located attestation listener.
- **Production** — mint standalone on a TCP `bind`, with a separate
  auth-service and attestation coordinator at the `PER-DEPLOYMENT` discharge
  URLs.
