---
status: landed
related: [plan-snapshot-offload.md]
landed_in: ../architecture.md
---

# Coordinator-driven snapshot — design rationale

Shipped in PR #42 (coordinator-driven sequence + signed ancestor manifests) and extended in PR #46 (snapshot-time filemap). Current flow is in `architecture.md` and `elide-coordinator/src/inbound.rs::snapshot_volume`. This note keeps only the rationale that's not obvious from reading the code.

## Why the coordinator owns the sequence

Snapshot previously ran in-process in the CLI (`Volume::snapshot()` wrote a marker and returned), with drain/upload happening later on the coordinator's tick loop. Two problems forced the move:

1. **"Snapshot complete" didn't mean "durable in S3".** A user who snapshotted then deleted locally could lose data — marker on disk, `pending/` hadn't drained.
2. **No seam for a post-drain completeness manifest.** The signed `.manifest` has to list every `index/<ulid>.idx` in the snapshot, which only exists after drain+promote — outside the volume's snapshot call as it stood.

Coordinator drives the sequence: per-volume snapshot lock, runs drain/upload/promote inline, then asks the volume to sign the manifest and write the marker. The volume process still owns anything touching the private signing key.

## Why not a "snapshot" WAL record

A WAL record is the right tool when recovery needs to replay a decision after a crash. A snapshot isn't a mutation — it's a durability fence (`pending/` empty, `index/` populated) plus a signed manifest. The fence is observable from directory state; there's nothing for WAL replay to reconstruct. A WAL record would introduce a new recovery invariant for no gain, and would push orchestration back into the volume process. **Coordinator-retries-on-restart** is the recovery model.

## Why `.manifest` is full, not a delta

Each `snapshots/<S>.manifest` lists **every** ULID in `index/` at snapshot time, not a delta over the previous snapshot.

A fork's open-time verification walks one manifest per volume in the ancestry chain. If manifests were deltas, verifying a fork of a mid-history snapshot would require chaining through every prior snapshot on every ancestor. Full manifests collapse the two-dimensional walk to a one-dimensional one: walk the fork chain, read one `.manifest` per ancestor, union the ULIDs, check each file exists.

Size cost is negligible: ~26 bytes per ULID line; 10k segments ≈ 260 KB signed.

## Trust root: provenance chain, not on-disk `volume.pub`

Each ancestor's `.manifest` is verified with that ancestor's public key, taken from the **child's signed provenance**, not from the ancestor's `volume.pub` file. Each `volume.provenance` embeds `parent_pubkey` under the child's signature, so trusting the current volume transitively trusts every ancestor.

This works because **keys never rotate**. A volume's keypair is minted once at creation. "Rotation" means forking: the fork gets a fresh keypair, pins the old volume as its parent, and from that point the old volume is read-only ancestor data. No in-place rotation, no keyring, no revocation list.

Consequence: if an ancestor's on-disk `volume.pub` ever disagrees with the child's provenance, the provenance wins. That's the whole point of embedding it.
