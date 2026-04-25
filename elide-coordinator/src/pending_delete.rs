// Pending-delete markers and the typed reap-target parser.
//
// See `docs/design-replica-model.md` for the surrounding design. The
// reaper itself lives in `pending_delete::reaper` (added in a later
// task); this module defines only the on-disk record format and the
// validation primitives.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use object_store::path::Path as StorePath;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Hard cap on `targets.len()` for a single marker. Realistic GC handoffs
/// sit at ~tens of inputs; anything close to the cap is a malformed-marker
/// or runaway-bug signal that the reaper rejects up front.
pub const MAX_TARGETS_PER_MARKER: usize = 1024;

/// Reason a marker was minted. v1 has a single value; the enum is open
/// so future writers can add reasons without breaking on-disk markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    GcInput,
}

/// On-disk record stored at
/// `by_id/<vol_ulid>/pending-delete/<marker_ulid>.toml`.
///
/// Field semantics are documented in `docs/design-replica-model.md`
/// under "Marker record". The marker filename ULID is the creation time
/// and is the sole source of truth for when the marker was minted; the
/// reaper derives the deadline as
/// `ulid_timestamp(marker_ulid) + retention`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDeleteMarker {
    /// Stamped at creation from the coordinator's config; live config
    /// changes never affect existing markers.
    #[serde(with = "humantime_serde")]
    pub retention: Duration,

    /// Audit/diagnostic only. The reaper ignores this field.
    pub reason: Reason,

    /// S3 keys retired together by this marker. The reaper deletes every
    /// listed key before deleting the marker itself.
    pub targets: Vec<String>,
}

impl PendingDeleteMarker {
    /// Render to its TOML form. Stable, sorted-key output.
    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    /// Parse a marker from its TOML form. Does **not** validate target
    /// keys — call `parse_target` per entry under the owning volume.
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

/// A target that has passed all validation and is safe to delete.
///
/// Each variant corresponds to one S3 key shape that v1 of the marker
/// writer is allowed to retire. New shapes are deliberate code changes
/// (a new variant + parser arm), not marker-content changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReapTarget {
    /// `by_id/<vol>/segments/YYYYMMDD/<seg>` — segment body, where the
    /// `YYYYMMDD` component matches the segment ULID's embedded
    /// timestamp.
    Segment { vol: Ulid, seg: Ulid },
}

impl ReapTarget {
    /// Render back to the canonical S3 key.
    pub fn to_key(&self) -> StorePath {
        match self {
            ReapTarget::Segment { vol, seg } => {
                let dt: DateTime<Utc> = seg.datetime().into();
                let date = dt.format("%Y%m%d").to_string();
                StorePath::from(format!("by_id/{vol}/segments/{date}/{seg}"))
            }
        }
    }
}

/// Reasons a target string may fail validation. Every variant is a
/// reject-the-marker signal — the reaper never deletes a partial set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseTargetError {
    Shape,
    VolumeMismatch { expected: Ulid, actual: Ulid },
    InvalidUlid,
    InvalidDate,
    DateUlidMismatch,
    PathWeirdness,
}

impl fmt::Display for ParseTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseTargetError::Shape => write!(f, "unrecognised target shape"),
            ParseTargetError::VolumeMismatch { expected, actual } => {
                write!(f, "volume ULID mismatch: expected {expected}, got {actual}")
            }
            ParseTargetError::InvalidUlid => write!(f, "invalid ULID component"),
            ParseTargetError::InvalidDate => write!(f, "invalid date component"),
            ParseTargetError::DateUlidMismatch => {
                write!(f, "date does not match ULID timestamp")
            }
            ParseTargetError::PathWeirdness => {
                write!(f, "path contains traversal or NUL components")
            }
        }
    }
}

impl std::error::Error for ParseTargetError {}

/// Parse an S3 key string into a typed `ReapTarget`, enforcing the
/// three-checkpoint volume-scope rule from `docs/design-replica-model.md`:
///
///   - `expected_vol` is the invocation ULID (ground truth).
///   - The key's volume component must equal `expected_vol`.
///   - ULIDs and the date component are parsed through their typed
///     parsers, never substring-matched.
///
/// Anything outside the allowed shapes — `manifest.toml`, `volume.pub`,
/// keys under `pending-delete/`, paths with `..`, double slashes, NUL
/// bytes, or unknown sub-prefixes — is rejected.
pub fn parse_target(key: &str, expected_vol: Ulid) -> Result<ReapTarget, ParseTargetError> {
    if key.contains('\0') || key.starts_with('/') || key.ends_with('/') || key.contains("//") {
        return Err(ParseTargetError::PathWeirdness);
    }
    let parts: Vec<&str> = key.split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err(ParseTargetError::PathWeirdness);
    }

    // All v1 keys: by_id/<vol>/segments/YYYYMMDD/<seg>
    if parts.len() != 5 || parts[0] != "by_id" || parts[2] != "segments" {
        return Err(ParseTargetError::Shape);
    }
    let vol = Ulid::from_string(parts[1]).map_err(|_| ParseTargetError::InvalidUlid)?;
    if vol != expected_vol {
        return Err(ParseTargetError::VolumeMismatch {
            expected: expected_vol,
            actual: vol,
        });
    }
    let date = parts[3];
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseTargetError::InvalidDate);
    }
    let seg = Ulid::from_string(parts[4]).map_err(|_| ParseTargetError::InvalidUlid)?;
    let seg_dt: DateTime<Utc> = seg.datetime().into();
    if seg_dt.format("%Y%m%d").to_string() != date {
        return Err(ParseTargetError::DateUlidMismatch);
    }
    Ok(ReapTarget::Segment { vol, seg })
}

/// Parse the volume ULID and marker ULID out of a marker's own S3 key.
///
/// Expected shape: `by_id/<vol>/pending-delete/<marker>.toml`. The reaper
/// asserts the parsed `vol` equals its invocation ULID before acting on
/// the marker — see *Target validation* in the design doc.
pub fn parse_marker_key(key: &str) -> Result<(Ulid, Ulid), ParseTargetError> {
    if key.contains('\0') || key.starts_with('/') || key.ends_with('/') || key.contains("//") {
        return Err(ParseTargetError::PathWeirdness);
    }
    let parts: Vec<&str> = key.split('/').collect();
    if parts
        .iter()
        .any(|p| p.is_empty() || *p == "." || *p == "..")
    {
        return Err(ParseTargetError::PathWeirdness);
    }
    if parts.len() != 4 || parts[0] != "by_id" || parts[2] != "pending-delete" {
        return Err(ParseTargetError::Shape);
    }
    let vol = Ulid::from_string(parts[1]).map_err(|_| ParseTargetError::InvalidUlid)?;
    let filename = parts[3];
    let marker_str = filename
        .strip_suffix(".toml")
        .ok_or(ParseTargetError::Shape)?;
    let marker = Ulid::from_string(marker_str).map_err(|_| ParseTargetError::InvalidUlid)?;
    Ok((vol, marker))
}

/// Build the canonical S3 key under which a marker is stored.
pub fn marker_key(vol: Ulid, marker: Ulid) -> StorePath {
    StorePath::from(format!("by_id/{vol}/pending-delete/{marker}.toml"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vol_ulid() -> Ulid {
        Ulid::from_string("01J0000000000000000000000V").unwrap()
    }

    fn seg_ulid() -> Ulid {
        // Pick a ULID that decodes to a stable date so the test is
        // deterministic regardless of when it runs.
        Ulid::from_parts(1_700_000_000_000, 42)
    }

    #[test]
    fn marker_round_trips_through_toml() {
        let m = PendingDeleteMarker {
            retention: Duration::from_secs(24 * 3600),
            reason: Reason::GcInput,
            targets: vec!["by_id/X/segments/20251114/Y".into()],
        };
        let s = m.to_toml().unwrap();
        let back = PendingDeleteMarker::from_toml(&s).unwrap();
        assert_eq!(back.retention, m.retention);
        assert!(matches!(back.reason, Reason::GcInput));
        assert_eq!(back.targets, m.targets);
    }

    #[test]
    fn parses_well_formed_segment_target() {
        let vol = vol_ulid();
        let seg = seg_ulid();
        let date = chrono::DateTime::<chrono::Utc>::from(seg.datetime())
            .format("%Y%m%d")
            .to_string();
        let key = format!("by_id/{vol}/segments/{date}/{seg}");
        let parsed = parse_target(&key, vol).unwrap();
        assert_eq!(parsed, ReapTarget::Segment { vol, seg });
        assert_eq!(parsed.to_key().as_ref(), key);
    }

    #[test]
    fn rejects_cross_volume_target() {
        let vol = vol_ulid();
        let other = Ulid::from_string("01J0000000000000000000000W").unwrap();
        let seg = seg_ulid();
        let date = chrono::DateTime::<chrono::Utc>::from(seg.datetime())
            .format("%Y%m%d")
            .to_string();
        let key = format!("by_id/{other}/segments/{date}/{seg}");
        let err = parse_target(&key, vol).unwrap_err();
        assert!(matches!(err, ParseTargetError::VolumeMismatch { .. }));
    }

    #[test]
    fn rejects_unknown_shape() {
        let vol = vol_ulid();
        for bad in [
            format!("by_id/{vol}/manifest.toml"),
            format!("by_id/{vol}/volume.pub"),
            format!("by_id/{vol}/pending-delete/01J0000000000000000000000V.toml"),
            format!("by_id/{vol}/snapshots/20251114/01J0000000000000000000000V"),
            format!("names/anything"),
        ] {
            let err = parse_target(&bad, vol).unwrap_err();
            assert!(
                matches!(err, ParseTargetError::Shape),
                "expected Shape error for {bad}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_path_traversal() {
        let vol = vol_ulid();
        for bad in [
            "by_id/../etc/passwd",
            "by_id//double-slash",
            "/by_id/leading-slash/segments/20251114/X",
            "by_id/x/segments/../../escape",
        ] {
            let err = parse_target(bad, vol).unwrap_err();
            assert!(
                matches!(
                    err,
                    ParseTargetError::PathWeirdness | ParseTargetError::InvalidUlid
                ),
                "expected weirdness/invalid for {bad}, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_date_ulid_mismatch() {
        let vol = vol_ulid();
        let seg = seg_ulid();
        // Plausible-looking date that doesn't match the seg ULID's embedded
        // timestamp.
        let key = format!("by_id/{vol}/segments/19990101/{seg}");
        let err = parse_target(&key, vol).unwrap_err();
        assert!(matches!(err, ParseTargetError::DateUlidMismatch));
    }

    #[test]
    fn parses_marker_key() {
        let vol = vol_ulid();
        let marker = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let key = format!("by_id/{vol}/pending-delete/{marker}.toml");
        let (v, m) = parse_marker_key(&key).unwrap();
        assert_eq!(v, vol);
        assert_eq!(m, marker);
    }

    #[test]
    fn rejects_marker_key_without_toml_suffix() {
        let vol = vol_ulid();
        let marker = Ulid::from_string("01J0000000000000000000000V").unwrap();
        let key = format!("by_id/{vol}/pending-delete/{marker}");
        let err = parse_marker_key(&key).unwrap_err();
        assert!(matches!(err, ParseTargetError::Shape));
    }
}
