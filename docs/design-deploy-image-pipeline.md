# Deploy image pipeline

**Status:** Proposed. No implementation. Captures the discussion for building the
mint and coordinator binaries in CI and downloading them at deploy time, in
place of the source compile in the Fly image builds.

## Problem

Both Fly images (`deploy/mint/`, `deploy/coord/`) compile from source inside the
image build, at deploy time, from a `*_REF` build arg:

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

## Proposed: build binaries in CI, download at deploy

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

## Wrinkles to design for

1. **Binary ABI matches the runtime base.** CI builds on `ubuntu-24.04`, runtime
   is `ubuntu:24.04`, so glibc matches. (A static musl build would remove the
   coupling entirely — probably more than needed.)
2. **Native deps present at runtime.** The `elide` binary links libublk
   (liburing); the runtime base must carry whatever the CI-built binary loads.
3. **A release/tag step.** Each repo's CI publishes the artifact on a tag (clean
   versioning, deliberate cadence) or on every `main` push (named by version /
   SHA).

## The mint ↔ elide lockstep

The compatible `(mint, elide)` pair is pinned in **one place** — the deploy
config, or the standalone deploy repo floated earlier — as two release versions
bumped together. The compatibility itself stays *tested* where it is today:
elide CI exercises the role templates against a specific mint version. The
deploy config records the validated pair.

## Open questions

1. **Artifact hosting.** GitHub Releases (release assets per tag, durable,
   tokenless for public repos) is the obvious default; confirm nothing wants a
   container/package registry instead.
2. **Version scheme.** Semver release tags (`v0.3`, readable lockstep) vs
   per-commit artifacts named by SHA.
3. **Where the pinned pair lives.** elide's `deploy/`, or the standalone deploy
   repo — the cleaner home for the `(mint, elide)` pin and per-deploy configs,
   though the role-template lockstep tests stay in elide CI.
4. **Native-deps verification.** Confirm the `elide` binary's runtime
   dependencies (liburing et al.) are satisfied by `ubuntu:24.04`, or `apt
   install` them in the runtime stage.
5. **CI trigger.** Publish on tag (deliberate release) vs on every `main` push.
