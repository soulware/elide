//! S3 object-key layout for top-level metadata objects.
//!
//! `volume.provenance` and `volume.pub` are stored in the object store
//! under a flat `meta/` prefix — `meta/<ulid>.provenance`,
//! `meta/<ulid>.pub` — not nested under the per-volume `by_id/<ulid>/`
//! prefix. The flat layout makes `meta/*` a trailing wildcard, which
//! Tigris IAM resource ARNs match (mid-resource `*` is not supported):
//! a credential can be granted bucket-wide read of these metadata
//! objects without also granting the per-volume bulk data under
//! `by_id/`.
//!
//! These are object-store keys only. The local volume directory keeps
//! `volume.provenance` and `volume.pub` inside `by_id/<ulid>/`.

use ulid::Ulid;

/// Object-store key for a volume's signed provenance.
pub fn meta_provenance_key(vol_ulid: Ulid) -> String {
    format!("meta/{vol_ulid}.provenance")
}

/// Object-store key for a volume's public key.
pub fn meta_pub_key(vol_ulid: Ulid) -> String {
    format!("meta/{vol_ulid}.pub")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_keys_are_flat_and_ulid_named() {
        let u = Ulid::from_string("01ARZ3NDEKTSV4RRFFQ69G5FAV").expect("ulid");
        assert_eq!(
            meta_provenance_key(u),
            "meta/01ARZ3NDEKTSV4RRFFQ69G5FAV.provenance"
        );
        assert_eq!(meta_pub_key(u), "meta/01ARZ3NDEKTSV4RRFFQ69G5FAV.pub");
    }
}
