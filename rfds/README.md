# RFDs

Short, in-repo Request-for-Discussion documents recording the *reasoning* behind Elide's design decisions — specifically the alternatives considered and why each was rejected. See [RFD 0004](0004-lightweight-rfd-process.md) for the process and template.

`docs/` is the source of truth for *how the system works now*. RFDs are the audit trail for *why it is shaped that way*.

Inspired by [Oxide's RFD process](https://rfd.shared.oxide.computer/rfd/0001), deliberately lighter-weight: short markdown files in the repo, reviewed via normal PRs, with a minimal template.

## Index

- [0001 — GC output ULID ordering](0001-gc-output-ulid-ordering.md) — why all GC-round ULIDs are minted by the volume in one pre-I/O checkpoint _(retrospective, implemented)_
- [0002 — Extent index lowest-ULID-wins](0002-extent-index-lowest-ulid-wins.md) — why the original DATA entry stays canonical over DedupRefs and GC repacks _(retrospective, implemented)_
- [0003 — Volume owns `index/` and `cache/`](0003-volume-owns-index-and-cache.md) — why the volume is the sole writer of those directories, driven by a `promote` IPC _(retrospective, implemented)_
- [0004 — Lightweight RFD process](0004-lightweight-rfd-process.md) — this process: template, lifecycle, when to write one _(accepted)_
