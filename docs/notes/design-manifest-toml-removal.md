---
status: landed
related: [design-volume-size-ownership.md]
landed_in: ../formats.md
---

# Drop `manifest.toml`

Once `size` moved off `manifest.toml` (see [design-volume-size-ownership.md](design-volume-size-ownership.md)), every remaining field was either redundant or moved onto a signed surface, so the file went away.

## Field migration

| Field | Fate |
|---|---|
| `name` | Dropped. Reverse lookup is `names/<name>`. |
| `readonly` | Dropped. Implied by the local `volume.readonly` marker and by `NameRecord.state` in the bucket. |
| `origin` | Dropped. Redundant with the signed `volume.provenance.parent`. |
| `source` (OCI image / digest / arch) | Moved to `volume.provenance.oci_source` (`elide_core::signing::OciSource`). |

`oci_source` is the only field carrying information not already represented elsewhere; provenance is its natural home because (1) provenance is already signed, (2) it's already pulled on cross-host fetches, and (3) `ProvenanceLineage` already mixes optional fields with "present iff this kind of root" semantics. `oci_source` lives only on the import root — forks do not inherit it.

## Tradeoffs

- Every per-volume metadata file in S3 is now signed or a public key — no unsigned correctness-or-provenance-relevant field anywhere in the skeleton.
- One fewer S3 surface to author and reason about.
- OCI label on a forked volume needs a provenance walk to the import root to display. `volume inspect` isn't a hot path; acceptable.

Migration was fresh-bucket-only; the signing input changed, so older signatures don't validate.
