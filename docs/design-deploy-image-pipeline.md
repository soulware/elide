# Deploy image pipeline

**Status:** Implemented for mint; proposed for the coordinator. mint's binary is
built in CI and published as a GitHub release (mint #43; first tag `v0.1.0`), and
`deploy/mint/` downloads and checksum-verifies it at a pinned `MINT_VERSION` in
place of the source compile. The coordinator image (`deploy/coord/`) still
compiles from source; the rest of this note covers extending the same pipeline to
the elide binaries.

## Problem

The coordinator image (`deploy/coord/`) compiles its binary from source inside
the image build, at deploy time, from a `*_REF` build arg:

```dockerfile
RUN git clone https://github.com/soulware/<repo> /src \
 && git -C /src checkout "${REF}" \
 && cargo build --release ...
```

That single `RUN` is the whole build, and it has three recurring failure modes:

1. **Silent staleness.** The layer's cache key is the instruction text plus the
   ARG *value*. A branch ref (`main`, a feature branch) is a moving pointer
   whose string never changes, so Docker reuses the cached binary as the branch
   advances — a plain `fly deploy` ships a stale binary unless `--no-cache` is
   remembered. The failure is silent: you get an old binary, not an error.
2. **Slow, heavy builds.** Every deploy re-clones and cold-compiles Rust, and
   the build stage carries a full toolchain (rustup, `build-essential`, `clang`,
   `libclang-dev`) that the runtime image does not need.
3. **Cross-repo lockstep.** mint and elide must agree on a compatible pair (the
   role-template coupling, lockstep-tested by elide CI). The version of record
   lives in three places — mint's repo, elide's repo, and the deploy's
   `MINT_REF` / `ELIDE_REF` — kept aligned by hand.

These are not hypothetical. A deploy with `MINT_REF` pinned to a pre-#41 commit
shipped a mint that generated its own `K_M-A` instead of reading it from config,
which silently broke coordinator enrollment (the coordinator's gate discharge
could not be decrypted). The cause was a stale `*_REF`.

## The pipeline: build binaries in CI, download at deploy

CI compiles each repo's binaries once per release and publishes them as
**release artifacts**; the deploy Dockerfile downloads the pinned binary version
in place of the clone-and-compile.

```
soulware/mint   ──CI build (GH Actions)──▶  release asset:  mint-vX.Y
soulware/elide  ──CI build (GH Actions)──▶  release assets: elide-vX.Y, elide-coordinator-vX.Y, elide-import-vX.Y

deploy Dockerfile (runs at deploy time):
  curl -L .../mint/releases/download/vX.Y/mint -o /usr/local/bin/mint
  mint render --build bucket=<DATA_BUCKET> ...     # resolves the per-deploy bucket into roles/
  COPY mint.toml ; sed [store].bucket
```

The build stage runs the `mint render` pass with the downloaded binary. Both
repos are public, so release assets download with no token.

This fixes all three failure modes:

- **Cache trap gone.** The Dockerfile fetches an immutable, *versioned* artifact
  (`mint-v0.3`), not a `git checkout` of a moving branch. Bumping the version
  changes the URL, so the layer rebuilds.
- **Slow builds gone.** The deploy-time image build is a download plus light
  packaging — no `cargo build`, no rustup/clang toolchain in the image.
- **Lockstep explicit.** The deploy pins `(mint version, elide version)` as
  readable release tags rather than SHAs, in one place.

## Settled by mint's pipeline

- **Artifact hosting** — GitHub Releases: one release asset per tag, durable and
  tokenless for the public repo.
- **Version scheme** — semver release tags (`vX.Y.Z`); the deploy pins the tag
  and the asset's sha256 together, so a bump moves both.
- **CI trigger** — publish on a `v*` tag, a deliberate release cadence rather
  than on every `main` push.
- **Binary ABI** — the release builds on `ubuntu-24.04` and the runtime base is
  `ubuntu:24.04`, so glibc matches with no static-musl build.

## The mint ↔ elide lockstep

The compatible `(mint, elide)` pair is pinned in **one place** — the deploy
config, or the standalone deploy repo floated earlier — as two release versions
bumped together. The compatibility itself stays *tested* where it is today:
elide CI exercises the role templates against a specific mint version. The
deploy config records the validated pair.

## Open for the coordinator half

1. **Native deps at runtime.** The `elide` binary links libublk (liburing); the
   runtime base must carry whatever the CI-built binary loads — confirm
   `ubuntu:24.04` satisfies it, or `apt install` the libs in the runtime stage.
   mint has no such native deps.
2. **Where the pinned pair lives.** elide's `deploy/`, or a standalone deploy
   repo — the cleaner home for the `(mint, elide)` pin and per-deploy configs,
   though the role-template lockstep tests stay in elide CI.
