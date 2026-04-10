---
rfd: 0004
title: Lightweight RFD process
status: accepted
created: 2026-04-10
references:
  - rfds/0001-gc-output-ulid-ordering.md
  - rfds/0002-extent-index-lowest-ulid-wins.md
  - rfds/0003-volume-owns-index-and-cache.md
---

# RFD 0004: Lightweight RFD process

## Summary

Elide uses short, in-repo Request-for-Discussion documents to record the *reasoning* behind design decisions — specifically the alternatives that were considered and why each was rejected. RFDs live in `rfds/` as numbered markdown files. `docs/` remains the source of truth for *how the system works now*; RFDs are the audit trail for *why it is shaped that way*.

## Context

`docs/` captures the current design but loses historical context as it is updated in place. When revisiting a decision months later, the information that is hardest to reconstruct is the set of alternatives that were considered and *rejected*, and the constraints that made one option win. Git history preserves fragments of this but is hard to search by subsystem and easy to miss.

An RFD archive closes that gap — but only if it is lightweight enough to actually get used, and disciplined enough to capture the things that matter. This process was drafted after writing three retrospective RFDs (0001–0003) as a calibration exercise.

## Alternatives considered

### A — No process; rely on docs and commit history
Keep `docs/` as the single source of truth and let commit messages carry the "why".

**Rejected.** Commit messages are fragmented across changes and hard to search by topic. Design-level reasoning gets scattered across dozens of commits, and in practice the *why* is lost within weeks of the change landing.

### B — Full Oxide-style RFDs
Long-form documents with multiple review stages, dedicated tooling, and a separate numbering authority. Each RFD is a significant artifact.

**Rejected.** Too heavy for this project. The friction would push the process off the happy path, and short decisions would simply never get written down.

### C — Lightweight in-repo RFDs *(chosen)*
Short markdown files in `rfds/`, numbered sequentially, reviewed via normal PRs. No separate tooling, a fixed but minimal template, and a clear rule that not every change needs one.

## Decision

**Option C.** See *Template*, *When to write one*, and *Lifecycle* below.

## Template

Each RFD is a single markdown file at `rfds/NNNN-kebab-title.md`:

```markdown
---
rfd: NNNN
title: ...
status: draft | accepted | implemented | superseded | abandoned
retrospective: true     # omit if false
created: YYYY-MM-DD
references:             # optional; any related docs, RFD or otherwise
  - docs/...
---

# RFD NNNN: Title

## Summary
One paragraph — what and why.

## Context
What problem prompted this, and what constraints are in play.

## Alternatives considered
At least two options, each with how it works and why it was rejected (or chosen).
A single-option RFD is a sign the thinking isn't done.

## Decision
Which option won and the specific reason it beat the others.

## Invariants preserved
Properties that must still hold after this lands.
```

Additional sections (Scope, Acceptance criteria, Test plan, Revisit if, Open questions) are optional and should appear only when they carry real content. Empty frontmatter fields are omitted.

## When to write one

- **Write an RFD** when a non-trivial design decision is being made, alternatives exist, and the reasoning would be hard to reconstruct from code alone. Retrospective RFDs for already-shipped decisions are welcome at any time.
- **Skip the RFD** when the change is mechanical, the decision is purely local, or there is no interesting alternative to discuss.
- **Lite variant**: for small decisions that still warrant a record, a shorter form is fine — keep at least Summary, one Alternative, and Decision.

## Lifecycle

- **draft** — in progress, under discussion
- **accepted** — decision made, not yet (or never to be) implemented
- **implemented** — shipped
- **superseded** — replaced by a later RFD (set `superseded-by:` on this one)
- **abandoned** — decided against or dropped

RFD numbers are assigned in write order, not decision order. Retrospective RFDs get numbers alongside live ones.

## Invariants preserved

- **Alternatives considered** is the highest-value section and must not be empty. If only one option was considered, the decision isn't ready.
- Rejected options must include the *specific* reason they were rejected, not just "we chose the other one".
- RFDs record *why*; `docs/` records *how it works now*. When an RFD is accepted, any consequent changes to `docs/` land alongside it in the same PR.
- Forward references to unwritten RFDs are avoided; references are backward-only or to non-RFD docs.
