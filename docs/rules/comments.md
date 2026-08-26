# Comments

Write no comment by default. Write the code first. Then add a comment only where
it gives a non-obvious reason, an invariant, or a trap. This order gives fewer
comments than a write-then-prune order, and it makes each comment a deliberate
choice.

A comment describes only what the adjacent code does now. A comment that
describes one of these four subjects fails that test:

- **Other code** — the context around it, the behaviour at run time, or the way another component uses it. In a config file, describe only what this key means.
- **Other time** — what the code did before, what it will do, or how it changed. Put that in the commit message.
- **Other place** — that something is unchanged, or that something else handles it.
- **Other choice** — what you rejected, or what you decided to omit. Put that in the commit message or the design doc.

State the comment positively. A comment says what the code does. A negative
becomes wrong when someone adds the case later, and it makes the reader derive
the real behaviour. The positive form is shorter, and it tells the reader more.
Write "the live index suffices", not "no snapshot-pinned locations are needed".
Write "bodies stay in the WAL until the segment is written", not "never carries
body bytes between commit and promote".

These words show that a comment already failed. Delete the comment. Do not
reword it.

- unchanged, untouched, stays, remains, still, for now, left as-is, not a change to, not done here, unlike
- no, not, never, without, rather than, instead of

Trim a comment, or delete it. Never grow a comment across edits.

Both tests govern the prose in a design doc and in a PR description. State what
the change is.
