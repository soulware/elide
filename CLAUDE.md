# Elide

## Rust code quality rules

Clippy with `-D warnings` runs in CI, and a pre-commit hook runs `cargo fmt --check`. The rules here are the ones no lint catches.

**No panicking code in library paths.**
- No `.unwrap()` or `.expect()` outside of tests and `main.rs`. Propagate errors with `?`.
- `.expect()` is only acceptable in tests, `main.rs` entry points, and for invariants that are genuinely impossible to violate — in that case, add a comment explaining why.
- No `panic!`, `unreachable!`, `todo!`, or `unimplemented!` in library code unless behind a `#[cfg(test)]` or clearly guarded.
- For a fixed-size slice conversion, use the module's const-generic `read_fixed::<N>` helper rather than `.try_into().expect(...)`. `elide-core/src/segment.rs` and `elide-core/src/writelog.rs` each define one.

**Avoid unnecessary data copies.**
- Avoid allocating a `Vec` for a small, fixed-size header — use a stack buffer (`[u8; N]`) instead.
- When you already own an allocation, pass it by value rather than borrowing it only to copy it again.

**Prefer crates over hand-rolled implementations.**
- Before implementing a non-trivial algorithm or format (e.g. ULID, UUID, base64, checksums), check whether a well-known crate exists and discuss with the user before deciding to roll it by hand.
- Hand-rolling is sometimes the right call (zero-dep binary, custom constraints), but the choice should be explicit, not a default.

**Parse, don't validate: use typed parsers when reading string representations.**
- When reading a string from an external source (filename, file content, CLI arg) that represents a typed value, always parse it through the type's own parser rather than using the raw string directly.
- This validates the value at the boundary and produces a canonical string if re-serialised (e.g. `Ulid::from_string(s)?.to_string()`, not `s.to_owned()`).
- The same applies to any structured string: paths, hashes, addresses, IDs.

**Monotonic ULIDs in tests.**
- When a test mints two or more ULIDs that must be ordered (e.g. a parent segment and a later delta segment), use `elide_core::ulid_mint::UlidMint` — seed with `Ulid::nil()` and call `.next()` per ULID.
- Two back-to-back `Ulid::new()` calls in the same millisecond produce ULIDs in random order — a flake source that has bitten CI more than once.
- Independent test IDs (distinct volume dirs, unrelated segment IDs in uniqueness tests) can still use `Ulid::new()` directly.

## Design principles

**No backward compatibility by default.**
- When a change would break existing on-disk data or behaviour, surface the tradeoff explicitly and discuss it — don't silently add a legacy/optional path to avoid the conversation.
- The default answer is often "break it": data can be regenerated, tooling can migrate it, and optional paths add permanent complexity.
- A compatibility path may sometimes be warranted, but it is never free: it adds code complexity, and — critically — it creates execution paths where important operations are skipped, making the system harder to reason about. That cost must be justified explicitly.
- If backward compatibility is genuinely needed, it should be an explicit, reasoned decision, not a reflex.

**No optional paths for correctness properties.**
- If a property must hold (e.g. every segment is signed), enforce it unconditionally — no fallback mode, no warn-and-continue.
- An optional path for a correctness invariant means the invariant doesn't actually hold.

## Comments

@docs/rules/comments.md

## Writing style

@docs/rules/ste.md

## Macaroons

Read [`docs/rules/macaroons.md`](docs/rules/macaroons.md) before you design or change anything macaroon-shaped.

## Documentation

Design documentation lives in `docs/`.

- `docs/overview.md` — problem statement, key concepts, operation modes, empirical findings
- `docs/architecture.md` — system architecture, directory layout, write/read paths, LBA map, extent index, dedup, snapshots
- `docs/formats.md` — WAL format, segment file format, S3 retrieval strategies
- `docs/operations.md` — GC, repacking, boot hints, filesystem metadata awareness
- `docs/findings.md` — empirical measurements: dedup rates, demand-fetch patterns, delta compression data, write amplification
- `docs/testing.md` — property-based tests: ULID monotonicity invariant, crash-recovery oracle, simulation model
- `docs/reference.md` — lsvd reference comparison, implementation notes, open questions
- `docs/quickstart.md` — the walkthrough, with `quickstart-{local,tigris,data-volume}.md` per deployment
- `docs/design/` — per-feature design docs, one file per subsystem or change
- `docs/plans/` — work plans for changes in flight
- `docs/status/` — snapshots of a soak, an investigation, or a release
- `docs/rules/` — the rule files imported above
- `docs/finding-*.md`, `docs/reference-{lsvd,dis,nydus}.md` — one-off investigations and surveys of other systems

## References

`refs/` is gitignored, so it exists only in the primary checkout. From a worktree, resolve the path with `git worktree list | head -1`.

- `refs/lsvd-paper.pdf` — local copy of ["Beating the I/O Bottleneck: A Case for Log-Structured Virtual Disks"](https://doi.org/10.1145/3492321.3524271) (EuroSys 2022)
- `refs/lsvd/` — local clone of lab47/lsvd, Evan Phoenix's independent Go reimplementation of the paper; our primary studied reference
- `refs/composefs-rs/` — [composefs/composefs-rs](https://github.com/composefs/composefs-rs), the Rust composefs implementation
- `refs/nydus-snapshotter/` — containerd/nydus-snapshotter
- [asch/dis](https://github.com/asch/dis) — the paper authors' original implementation (named DIS in code; kernel device-mapper module + Go userspace daemon), surveyed in `docs/reference-dis.md`
