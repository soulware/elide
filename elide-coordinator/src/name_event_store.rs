//! Bucket-level read/write helpers for `names/<name>/events/`.
//!
//! Pairs with [`crate::name_store`] (which manages the
//! `names/<name>` pointer object) by storing the append-only event
//! log under the corresponding `events/` prefix. See
//! `docs/design-name-event-log.md` for the design.
//!
//! Keys: `names/<name>/events/<event_ulid>.toml`. Each object is
//! written exactly once via `If-None-Match: *` — duplicate ULIDs
//! would be a programmer error, not a race.

use std::sync::Arc;

use bytes::Bytes;
use futures::TryStreamExt;
use object_store::path::Path as StorePath;
use object_store::{ObjectStore, PutResult};
use tracing::{debug, warn};
use ulid::Ulid;

use elide_core::name_event::{EventKind, NameEvent};
use elide_core::signing;

use crate::identity::CoordinatorIdentity;
use crate::portable::{ConditionalPutError, put_if_absent};

/// Errors from `name_event_store` operations.
#[derive(Debug)]
pub enum NameEventStoreError {
    /// Failed to serialise the event as TOML.
    Serialise(toml::ser::Error),
    /// The underlying store reported an error.
    Store(object_store::Error),
    /// `If-None-Match: *` failed — an event with the same
    /// `event_ulid` already exists. This is a programmer error
    /// (caller minted a duplicate ULID), not a race.
    DuplicateEventUlid,
    /// `event_ulid.timestamp_ms()` cannot be represented as
    /// `DateTime<Utc>`. Practically impossible for ULIDs minted in
    /// this century.
    UnrepresentableTimestamp,
}

impl std::fmt::Display for NameEventStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialise(e) => write!(f, "serialising NameEvent: {e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::DuplicateEventUlid => write!(f, "duplicate event_ulid"),
            Self::UnrepresentableTimestamp => {
                write!(f, "event_ulid timestamp out of DateTime<Utc> range")
            }
        }
    }
}

impl std::error::Error for NameEventStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialise(e) => Some(e),
            Self::Store(e) => Some(e),
            _ => None,
        }
    }
}

impl From<object_store::Error> for NameEventStoreError {
    fn from(e: object_store::Error) -> Self {
        Self::Store(e)
    }
}

impl From<ConditionalPutError> for NameEventStoreError {
    fn from(e: ConditionalPutError) -> Self {
        match e {
            ConditionalPutError::PreconditionFailed => Self::DuplicateEventUlid,
            ConditionalPutError::Other(e) => Self::Store(e),
        }
    }
}

fn event_prefix(name: &str) -> StorePath {
    StorePath::from(format!("names/{name}/events/"))
}

fn event_key(name: &str, event_ulid: Ulid) -> StorePath {
    StorePath::from(format!("names/{name}/events/{event_ulid}.toml"))
}

/// Sign `event` in place using `identity`'s coordinator key. The
/// payload is the bytes returned by [`NameEvent::signing_payload`];
/// the resulting hex-encoded signature lands in `event.signature`.
fn sign_event(event: &mut NameEvent, identity: &CoordinatorIdentity) {
    let payload = event.signing_payload();
    let sig = identity.sign(&payload);
    event.signature = Some(signing::encode_hex(&sig));
}

/// PUT a fully-formed signed event at
/// `names/<name>/events/<event_ulid>.toml` using `If-None-Match: *`.
///
/// Refuses to write an unsigned event — the log invariant is that
/// every event on the wire is signed, so accepting an unsigned one
/// would silently break verification.
pub async fn append_event(
    store: &Arc<dyn ObjectStore>,
    name: &str,
    event: &NameEvent,
) -> Result<PutResult, NameEventStoreError> {
    debug_assert!(
        event.signature.is_some(),
        "append_event called with unsigned event — call sign+append via emit_event"
    );

    let body = event.to_toml().map_err(NameEventStoreError::Serialise)?;
    let key = event_key(name, event.event_ulid);
    let started = std::time::Instant::now();
    let r = put_if_absent(store.as_ref(), &key, Bytes::from(body.into_bytes())).await?;
    debug!(
        "[name_event_store] PUT-IF-ABSENT {key} kind={} ({:.2?})",
        event.kind.as_str(),
        started.elapsed()
    );
    Ok(r)
}

/// Return the highest `event_ulid` present under
/// `names/<name>/events/`, or `None` if the prefix is empty.
///
/// Listed objects whose filename does not parse as `<ulid>.toml`
/// are silently skipped — they aren't event records this code
/// emitted, and a stray file should not block a fresh emit.
pub async fn latest_event_ulid(
    store: &Arc<dyn ObjectStore>,
    name: &str,
) -> Result<Option<Ulid>, NameEventStoreError> {
    let prefix = event_prefix(name);
    let objects: Vec<_> = store.list(Some(&prefix)).try_collect().await?;

    let mut best: Option<Ulid> = None;
    for obj in objects {
        let Some(filename) = obj.location.filename() else {
            continue;
        };
        let Some(stem) = filename.strip_suffix(".toml") else {
            continue;
        };
        let Ok(ulid) = Ulid::from_string(stem) else {
            continue;
        };
        if best.is_none_or(|b| ulid > b) {
            best = Some(ulid);
        }
    }
    Ok(best)
}

/// Mint a fresh event, sign it with `identity`, and append it to
/// `names/<name>/events/`.
///
/// Steps:
///   1. Look up `prev_event_ulid` (best-effort — list failures fall
///      back to `None`, which produces a small audit gap rather
///      than blocking the emit).
///   2. Mint a fresh `event_ulid` via `Ulid::new()`. Callers that
///      need monotonicity guarantees across rapid back-to-back
///      events should wrap this with a `UlidMint`.
///   3. Build the `NameEvent` with `at` derived from the ULID.
///   4. Sign with `identity.signing_key()` over the canonical
///      payload.
///   5. PUT under `If-None-Match: *`.
///
/// Returns the constructed signed event on success.
pub async fn emit_event(
    store: &Arc<dyn ObjectStore>,
    identity: &CoordinatorIdentity,
    name: &str,
    kind: EventKind,
    vol_ulid: Ulid,
) -> Result<NameEvent, NameEventStoreError> {
    let prev_event_ulid = match latest_event_ulid(store, name).await {
        Ok(p) => p,
        Err(e) => {
            warn!(
                "[name_event_store] failed to list prior events for {name}: {e}; \
                 emitting with prev_event_ulid=None"
            );
            None
        }
    };

    let event_ulid = Ulid::new();
    let mut event = NameEvent::new(
        event_ulid,
        identity.coordinator_id_str().to_owned(),
        vol_ulid,
        prev_event_ulid,
        kind,
    )
    .ok_or(NameEventStoreError::UnrepresentableTimestamp)?;

    sign_event(&mut event, identity);
    append_event(store, name, &event).await?;
    Ok(event)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CoordinatorIdentity;
    use object_store::memory::InMemory;
    use tempfile::TempDir;

    fn store() -> Arc<dyn ObjectStore> {
        Arc::new(InMemory::new())
    }

    fn fresh_identity() -> (TempDir, CoordinatorIdentity) {
        let tmp = TempDir::new().expect("tmpdir");
        let id = CoordinatorIdentity::load_or_generate(tmp.path()).expect("identity");
        (tmp, id)
    }

    fn vol_ulid() -> Ulid {
        Ulid::from_string("01J0000000000000000000000V").unwrap()
    }

    #[tokio::test]
    async fn emit_then_read_latest() {
        let s = store();
        let (_tmp, id) = fresh_identity();

        assert!(
            latest_event_ulid(&s, "vol").await.unwrap().is_none(),
            "empty prefix must return None"
        );

        let ev = emit_event(&s, &id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("first emit");
        assert!(ev.signature.is_some(), "emitted event must be signed");
        assert_eq!(ev.coordinator_id, id.coordinator_id_str());

        let latest = latest_event_ulid(&s, "vol")
            .await
            .expect("list")
            .expect("one event present");
        assert_eq!(latest, ev.event_ulid);
    }

    #[tokio::test]
    async fn second_event_chains_via_prev_event_ulid() {
        let s = store();
        let (_tmp, id) = fresh_identity();

        let first = emit_event(&s, &id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("first");
        let second = emit_event(&s, &id, "vol", EventKind::Claimed, vol_ulid())
            .await
            .expect("second");

        assert_eq!(
            second.prev_event_ulid,
            Some(first.event_ulid),
            "second event must reference the first"
        );
    }

    #[tokio::test]
    async fn emitted_event_round_trips_through_storage() {
        let s = store();
        let (_tmp, id) = fresh_identity();

        let ev = emit_event(&s, &id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("emit");

        // Read the object back and parse it.
        let key = event_key("vol", ev.event_ulid);
        let bytes = s.get(&key).await.unwrap().bytes().await.unwrap();
        let parsed = NameEvent::from_toml(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(parsed, ev);
    }
}
