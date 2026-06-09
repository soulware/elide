//! The attestation-coordinator (coord B) discharge endpoint.
//!
//! coord B is mint's volume-attestation discharge authority
//! (`docs/design-mint-volume-attestation.md`). It serves `POST /v1/discharge`
//! on this peer-fetch server — the structural twin that already holds
//! `coord-ro` and verifies signed metadata — recovering `r` from an attested
//! TPC's CID, verifying a possession proof of the volume's signing key over
//! public signed state, and minting a discharge that attests the scoped
//! volume.
//!
//! This module is built up incrementally: [`crypto`] is the reimplemented
//! discharge-mint primitive (CID decrypt + macaroon mint), pinned to
//! canonical mint by a shared known-answer fixture.

pub mod crypto;
