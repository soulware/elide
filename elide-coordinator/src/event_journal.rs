//! Domain-typed handle over the per-name event log.
//!
//! First slice of the domain-typed store layer
//! (`docs/design/domain-store.md`). Replaces module-level functions
//! over `Arc<dyn ObjectStore>` with the [`EventJournal`] trait — an
//! object-typed handle vended by [`crate::stores::ScopedStores`].
//!
//! The trait has **no `delete` method**. The `events/` append-only
//! invariant the IAM policy enforces is mirrored here as a type-level
//! property: a caller holding only an [`EventJournal`] cannot delete
//! an event because the operation does not exist on the trait.
//!
//! Storage layout (unchanged from the previous `volume_event_store`):
//! * `events/<name>/HEAD` — the windowed pointer with the last
//!   [`HEAD_WINDOW`] signed events.
//! * `events/<name>/<event_ulid>` — the immutable archival record,
//!   one per event.
//!
//! See `docs/design/volume-event-log.md` for the on-disk shape and
//! `docs/plans/list-elimination-plan.md` § *event-log spine* for the
//! single-writer / no-LIST invariants this implementation preserves.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::Mutex as StdMutex;

use async_trait::async_trait;
use bytes::Bytes;
use object_store::path::Path as StorePath;
use object_store::{ObjectStore, UpdateVersion};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};
use ulid::Ulid;

use elide_core::signing::{self, VerifyingKey};
use elide_core::volume_event::{EventKind, VolumeEvent};

use crate::identity::{self, CoordinatorIdentity};
use crate::ipc::{SignatureStatus, VolumeEventEntry};
use crate::portable::{
    ConditionalPutError, MIME_TOML, put_if_absent_with_type, put_with_match_with_type,
};

/// Number of most-recent signed events carried inline in the
/// `events/<name>/HEAD` window. Tuning parameter (see
/// `docs/plans/list-elimination-plan.md` § *event-log spine*).
const HEAD_WINDOW: usize = 16;

/// Default `limit` for [`EventJournal::recent`] / `volume events` when
/// the caller doesn't specify one: the full HEAD window, answered in a
/// single GET with no `prev_event_ulid` walk.
pub const DEFAULT_EVENTS_LIMIT: usize = HEAD_WINDOW;

fn head_key(name: &str) -> StorePath {
    StorePath::from(format!("events/{name}/HEAD"))
}

fn event_key(name: &str, event_ulid: Ulid) -> StorePath {
    StorePath::from(format!("events/{name}/{event_ulid}"))
}

/// Per-name in-process serialization of this coordinator's own emits
/// (the plan's "small Mutex map"). Cross-coordinator concurrency is
/// handled by the `names/<name>` ownership CAS upstream; this only
/// stops a coordinator's own concurrent tasks from racing each other's
/// HEAD read-modify-write.
static NAME_EMIT_LOCKS: LazyLock<StdMutex<HashMap<String, Arc<AsyncMutex<()>>>>> =
    LazyLock::new(|| StdMutex::new(HashMap::new()));

fn name_emit_lock(name: &str) -> Arc<AsyncMutex<()>> {
    let mut map = NAME_EMIT_LOCKS
        .lock()
        .expect("name-emit lock registry poisoned");
    map.entry(name.to_owned())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

/// One entry in the HEAD window: either a fully-parsed event, or one
/// whose `kind` payload did not parse under this binary's schema.
///
/// Opaque entries keep their raw TOML table so a HEAD rewrite re-emits
/// them verbatim — a single event a different version wrote can never
/// brick the log or be silently dropped/rewritten. The common fields
/// (always plain scalars) are extracted so the ordering spine and
/// `recent`'s consumers still work.
#[derive(Debug, Clone)]
enum HeadEvent {
    Parsed(Box<VolumeEvent>),
    Opaque(Box<OpaqueEvent>),
}

/// An event whose `kind` payload did not deserialize. The `raw` table is
/// the verbatim on-disk form (re-emitted unchanged on rewrite); the
/// extracted fields drive ordering and a lossy [`VolumeEvent`] stand-in.
#[derive(Debug, Clone)]
struct OpaqueEvent {
    event_ulid: Option<Ulid>,
    prev_event_ulid: Option<Ulid>,
    vol_ulid: Option<Ulid>,
    name: Option<String>,
    coordinator_id: Option<String>,
    hostname: Option<String>,
    signature: Option<String>,
    original_kind: Option<String>,
    raw: toml::Table,
}

impl OpaqueEvent {
    fn from_table(raw: toml::Table) -> Self {
        let str_at = |k: &str| raw.get(k).and_then(|v| v.as_str()).map(str::to_owned);
        let ulid_at = |k: &str| str_at(k).and_then(|s| Ulid::from_string(&s).ok());
        OpaqueEvent {
            event_ulid: ulid_at("event_ulid"),
            prev_event_ulid: ulid_at("prev_event_ulid"),
            vol_ulid: ulid_at("vol_ulid"),
            name: str_at("name"),
            coordinator_id: str_at("coordinator_id"),
            hostname: str_at("hostname"),
            signature: str_at("signature"),
            original_kind: str_at("kind"),
            raw,
        }
    }

    /// Lossy `VolumeEvent` stand-in with an [`EventKind::Unknown`] kind.
    /// `at` is re-derived from `event_ulid` (the two are the same fact).
    /// `None` when a required common field is missing/unparseable — a
    /// genuinely malformed record, not just an unknown kind.
    fn as_volume_event(&self) -> Option<VolumeEvent> {
        let mut ev = VolumeEvent::new(
            self.event_ulid?,
            self.name.clone()?,
            self.coordinator_id.clone()?,
            self.hostname.clone(),
            self.vol_ulid?,
            self.prev_event_ulid,
            EventKind::Unknown {
                original_kind: self.original_kind.clone(),
            },
        )?;
        ev.signature = self.signature.clone();
        Some(ev)
    }
}

impl HeadEvent {
    /// Try the typed event; fall back to opaque on a kind-payload parse
    /// failure so one bad entry never fails the whole window.
    fn from_value(v: toml::Value) -> HeadEvent {
        match v.clone().try_into::<VolumeEvent>() {
            Ok(ev) => HeadEvent::Parsed(Box::new(ev)),
            Err(_) => {
                let raw = match v {
                    toml::Value::Table(t) => t,
                    _ => toml::Table::new(),
                };
                HeadEvent::Opaque(Box::new(OpaqueEvent::from_table(raw)))
            }
        }
    }

    /// The event's ordering key, present for any well-formed entry
    /// (`event_ulid` is a common field even on opaque entries).
    fn event_ulid(&self) -> Option<Ulid> {
        match self {
            HeadEvent::Parsed(e) => Some(e.event_ulid),
            HeadEvent::Opaque(o) => o.event_ulid,
        }
    }

    /// Lossy `VolumeEvent` view for `recent`'s consumers; `None` drops a
    /// malformed entry that cannot be reconstructed.
    fn into_volume_event(self) -> Option<VolumeEvent> {
        match self {
            HeadEvent::Parsed(e) => Some(*e),
            HeadEvent::Opaque(o) => o.as_volume_event(),
        }
    }

    /// The verbatim TOML for a rewrite: the raw table for opaque
    /// entries, re-serialised typed form for parsed ones.
    fn to_value(&self) -> Result<toml::Value, EventError> {
        match self {
            HeadEvent::Parsed(e) => {
                toml::Value::try_from(e.as_ref()).map_err(EventError::Serialise)
            }
            HeadEvent::Opaque(o) => Ok(toml::Value::Table(o.raw.clone())),
        }
    }
}

/// The `events/<name>/HEAD` window: the last [`HEAD_WINDOW`] signed
/// events, newest-first (`events[0]` is the latest). HEAD is the
/// ordering authority for `emit` (so no LIST is needed) but **not**
/// the integrity authority — each entry is the same individually
/// signed `VolumeEvent` stored standalone, so a tampered entry still
/// fails the per-event signature check.
#[derive(Debug, Clone, Default)]
pub struct EventHead {
    events: Vec<HeadEvent>,
}

impl EventHead {
    /// Newest event, or `None` for an empty/just-created log.
    fn latest(&self) -> Option<&HeadEvent> {
        self.events.first()
    }

    /// `[new] ++ self.events`, truncated to [`HEAD_WINDOW`].
    fn pushed(&self, new: VolumeEvent) -> EventHead {
        let mut events = Vec::with_capacity((self.events.len() + 1).min(HEAD_WINDOW));
        events.push(HeadEvent::Parsed(Box::new(new)));
        events.extend(self.events.iter().take(HEAD_WINDOW - 1).cloned());
        EventHead { events }
    }
}

/// Unforgeable read-receipt for `events/<name>/HEAD`. Carries the
/// `If-Match` precondition for a subsequent CAS rewrite. Constructible
/// only inside this module: holding one proves the caller has read
/// HEAD's current state, and a downstream CAS write cannot be issued
/// without first reading.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EventHeadToken {
    version: UpdateVersion,
}

/// Errors from [`EventJournal`] operations.
#[derive(Debug)]
pub enum EventError {
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
    /// `events/<name>/HEAD` did not parse as an [`EventHead`].
    ParseHead(toml::de::Error),
    /// The `If-Match` HEAD rewrite failed: `events/<name>/HEAD`
    /// changed under us. The only writer that can do that to a name
    /// we own is a concurrent `claim --force` — i.e. **this
    /// coordinator has been displaced**. Caller must fail hard, not
    /// retry (`docs/plans/list-elimination-plan.md` § *Single-writer*).
    Displaced,
}

impl std::fmt::Display for EventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Serialise(e) => write!(f, "serialising VolumeEvent: {e}"),
            Self::Store(e) => write!(f, "{e}"),
            Self::DuplicateEventUlid => write!(f, "duplicate event_ulid"),
            Self::UnrepresentableTimestamp => {
                write!(f, "event_ulid timestamp out of DateTime<Utc> range")
            }
            Self::ParseHead(e) => write!(f, "parsing events HEAD: {e}"),
            Self::Displaced => write!(
                f,
                "event-log HEAD changed under us — this coordinator has been displaced \
                 (concurrent claim --force)"
            ),
        }
    }
}

impl std::error::Error for EventError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Serialise(e) => Some(e),
            Self::Store(e) => Some(e),
            Self::ParseHead(e) => Some(e),
            _ => None,
        }
    }
}

impl From<object_store::Error> for EventError {
    fn from(e: object_store::Error) -> Self {
        Self::Store(e)
    }
}

impl From<ConditionalPutError> for EventError {
    fn from(e: ConditionalPutError) -> Self {
        match e {
            ConditionalPutError::PreconditionFailed => Self::DuplicateEventUlid,
            ConditionalPutError::Other(e) => Self::Store(e),
        }
    }
}

/// Read-only view over the per-name event log. Split out from
/// [`EventJournal`] so a pure-read call site (`volume events` IPC,
/// peer-discovery, the per-volume task's claim-handoff lookup) can
/// take `&dyn EventJournalReader` and **cannot** call `emit` at
/// compile time. The split mirrors [`crate::stores::ReadStore`] vs
/// `ObjectStore`: credential scope becomes type scope.
///
/// Backed by the `coord-ro` role — reads on `events/*` and on
/// `coordinators/<other>/*` (the latter is what `list_and_verify`
/// needs for cross-coordinator pubkey resolution; `coord-rw`'s
/// policy does not grant it).
///
/// Acquired via [`crate::stores::ScopedStores::event_journal_ro`].
#[async_trait]
pub trait EventJournalReader: Send + Sync {
    /// GET `events/<name>/HEAD`. `Ok(None)` means the object is absent
    /// — a genuinely empty log (first event for this name). A
    /// transient store error is propagated, **not** mapped to `None`.
    async fn read_head(
        &self,
        name: &str,
    ) -> Result<Option<(EventHead, EventHeadToken)>, EventError>;

    /// Up to `limit` most-recent events for `name`, newest-first.
    /// Served from the HEAD window in a single GET when possible;
    /// otherwise walks the `prev_event_ulid` back-link chain.
    async fn recent(&self, name: &str, limit: usize) -> Result<Vec<VolumeEvent>, EventError>;

    /// Read the `limit` most-recent events ordered chronologically
    /// (ascending `event_ulid`) and pair each with a
    /// [`SignatureStatus`].
    async fn list_and_verify(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Vec<VolumeEventEntry>, EventError>;
}

/// Per-name append-only event log. The trait deliberately omits any
/// `delete` operation: the `events/` append-only invariant becomes a
/// type-level property.
///
/// Extends [`EventJournalReader`] with the mutating [`Self::emit`].
/// Backed by both `coord-rw` (for the emit CAS, which runs wholly
/// on one credential per `docs/design/mint.md`) and `coord-ro` (for
/// the inherited read methods, which need cross-coord pubkey reads
/// for verify).
///
/// Acquired via [`crate::stores::ScopedStores::event_journal`].
#[async_trait]
pub trait EventJournal: EventJournalReader {
    /// Mint a fresh event, sign it with `identity`, and append it.
    /// Holds the in-process per-name emit lock for the duration of
    /// the read-modify-write. The whole CAS (HEAD GET → HEAD PUT →
    /// record PUT) runs on the `coord-rw` credential — never
    /// split mid-mutation.
    async fn emit(
        &self,
        identity: &CoordinatorIdentity,
        name: &str,
        kind: EventKind,
        vol_ulid: Ulid,
    ) -> Result<VolumeEvent, EventError>;

    /// Best-effort companion to [`Self::emit`]. Logs and discards any
    /// error — used by lifecycle call sites that have already CAS'd
    /// `names/<name>` and need to append the corresponding journal
    /// entry without blocking or failing the lifecycle op.
    async fn emit_best_effort(
        &self,
        identity: &CoordinatorIdentity,
        name: &str,
        kind: EventKind,
        vol_ulid: Ulid,
    ) {
        let kind_str = kind.as_str();
        if let Err(e) = self.emit(identity, name, kind, vol_ulid).await {
            warn!("[event-journal] failed to emit {kind_str} event for {name}: {e}");
        }
    }
}

/// Read-only `EventJournalReader` over a `coord-ro`-scoped store.
/// Constructed by [`crate::stores::ScopedStores::event_journal_ro`].
pub struct ReadOnlyEventJournal {
    reader: Arc<dyn ObjectStore>,
}

impl ReadOnlyEventJournal {
    pub fn new(reader: Arc<dyn ObjectStore>) -> Self {
        Self { reader }
    }
}

/// Full `EventJournal` impl. Holds two credential-scoped store
/// handles: `writer` (`coord-rw`) for the emit CAS, and `reader`
/// (`coord-ro`) for read methods + signature-verify pubkey reads.
pub struct BucketEventJournal {
    writer: Arc<dyn ObjectStore>,
    reader: Arc<dyn ObjectStore>,
}

impl BucketEventJournal {
    pub fn new(writer: Arc<dyn ObjectStore>, reader: Arc<dyn ObjectStore>) -> Self {
        Self { writer, reader }
    }
}

fn sign_event(event: &mut VolumeEvent, identity: &CoordinatorIdentity) {
    let payload = event.signing_payload();
    let sig = identity.sign(&payload);
    event.signature = Some(signing::encode_hex(&sig));
}

/// Serialise a HEAD to TOML. Parsed entries go through the typed
/// serializer; opaque entries are re-emitted from their raw table
/// verbatim, so an event a different version wrote survives a rewrite
/// unchanged.
fn serialise_head(head: &EventHead) -> Result<String, EventError> {
    let mut events = Vec::with_capacity(head.events.len());
    for e in &head.events {
        events.push(e.to_value()?);
    }
    let mut root = toml::Table::new();
    root.insert("events".to_owned(), toml::Value::Array(events));
    toml::to_string(&toml::Value::Table(root)).map_err(EventError::Serialise)
}

/// Parse a HEAD, tolerating any single event whose `kind` payload does
/// not deserialize under this binary's schema (kept as opaque). A
/// wholly malformed document (not valid TOML, or `events` not an array)
/// is still a hard [`EventError::ParseHead`].
fn parse_head(text: &str) -> Result<EventHead, EventError> {
    let root: toml::Table = toml::from_str(text).map_err(EventError::ParseHead)?;
    let events = match root.get("events") {
        None => Vec::new(),
        // `events` must be an array; a non-array is a corrupt HEAD, so
        // let the typed conversion surface a real parse error.
        Some(v) => {
            let arr: Vec<toml::Value> = v.clone().try_into().map_err(EventError::ParseHead)?;
            arr.into_iter().map(HeadEvent::from_value).collect()
        }
    };
    Ok(EventHead { events })
}

async fn write_head(
    store: &dyn ObjectStore,
    name: &str,
    head: &EventHead,
    expected: Option<UpdateVersion>,
    is_force: bool,
) -> Result<(), EventError> {
    let body = Bytes::from(serialise_head(head)?.into_bytes());
    let key = head_key(name);
    if is_force {
        return store
            .put(&key, body.into())
            .await
            .map(|_| ())
            .map_err(EventError::Store);
    }
    let displaced = |e| match e {
        ConditionalPutError::PreconditionFailed => EventError::Displaced,
        ConditionalPutError::Other(e) => EventError::Store(e),
    };
    match expected {
        Some(ver) => put_with_match_with_type(store, &key, body, ver, MIME_TOML)
            .await
            .map(|_| ())
            .map_err(displaced),
        None => put_if_absent_with_type(store, &key, body, MIME_TOML)
            .await
            .map(|_| ())
            .map_err(displaced),
    }
}

async fn append_record(
    store: &dyn ObjectStore,
    name: &str,
    event: &VolumeEvent,
) -> Result<(), EventError> {
    debug_assert!(
        event.signature.is_some(),
        "append_record called with unsigned event"
    );
    let body = event.to_toml().map_err(EventError::Serialise)?;
    let key = event_key(name, event.event_ulid);
    let started = std::time::Instant::now();
    put_if_absent_with_type(store, &key, Bytes::from(body.into_bytes()), MIME_TOML).await?;
    debug!(
        "[event-journal] PUT-IF-ABSENT {key} kind={} ({:.2?})",
        event.kind.as_str(),
        started.elapsed()
    );
    Ok(())
}

async fn read_head_via(
    store: &dyn ObjectStore,
    name: &str,
) -> Result<Option<(EventHead, EventHeadToken)>, EventError> {
    let key = head_key(name);
    let got = match store.get(&key).await {
        Ok(g) => g,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(EventError::Store(e)),
    };
    let version = UpdateVersion {
        e_tag: got.meta.e_tag.clone(),
        version: got.meta.version.clone(),
    };
    let bytes = got.bytes().await.map_err(EventError::Store)?;
    let text = std::str::from_utf8(&bytes).map_err(|e| {
        EventError::Store(object_store::Error::Generic {
            store: "events",
            source: format!("HEAD not utf-8: {e}").into(),
        })
    })?;
    let head = parse_head(text)?;
    Ok(Some((head, EventHeadToken { version })))
}

async fn recent_via(
    store: &dyn ObjectStore,
    name: &str,
    limit: usize,
) -> Result<Vec<VolumeEvent>, EventError> {
    if limit == 0 {
        return Ok(Vec::new());
    }
    let Some((head, _tok)) = read_head_via(store, name).await? else {
        return Ok(Vec::new());
    };
    let head_len = head.events.len();
    let mut events: Vec<VolumeEvent> = head
        .events
        .into_iter()
        .filter_map(HeadEvent::into_volume_event)
        .collect();
    if events.len() >= limit {
        events.truncate(limit);
        return Ok(events);
    }
    // Only walk back beyond the window if the window was full — a short
    // window is the whole log. Base this on the raw head length, not the
    // post-filter count, so a dropped malformed entry can't spuriously
    // trigger a walk.
    if head_len < HEAD_WINDOW {
        return Ok(events);
    }
    let mut prev = events.last().and_then(|e| e.prev_event_ulid);
    while events.len() < limit {
        let Some(p) = prev else { break };
        let key = event_key(name, p);
        let got = match store.get(&key).await {
            Ok(g) => g,
            Err(object_store::Error::NotFound { .. }) => {
                debug!("[event-journal] {key} missing (phantom back-link); stop walk");
                break;
            }
            Err(e) => return Err(EventError::Store(e)),
        };
        let bytes = got.bytes().await.map_err(EventError::Store)?;
        // Tolerate an unparseable-kind archival record the same way the
        // HEAD does: read it as an opaque event so the walk continues,
        // rather than stopping the whole history at one bad entry.
        let event = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|t| toml::from_str::<toml::Value>(t).ok())
            .map(HeadEvent::from_value)
            .and_then(HeadEvent::into_volume_event);
        let Some(event) = event else {
            debug!("[event-journal] {key} unreadable/corrupt; stop walk");
            break;
        };
        prev = event.prev_event_ulid;
        events.push(event);
    }
    Ok(events)
}

async fn list_and_verify_via(
    store: &dyn ObjectStore,
    name: &str,
    limit: usize,
) -> Result<Vec<VolumeEventEntry>, EventError> {
    let mut events = recent_via(store, name, limit).await?;
    events.reverse();

    let mut keys: HashMap<String, Option<VerifyingKey>> = HashMap::new();
    let mut key_failures: HashMap<String, String> = HashMap::new();

    let mut entries = Vec::with_capacity(events.len());
    for event in events {
        // An unparseable-kind event has no reconstructable signing
        // payload, so verification is impossible — report it as such
        // rather than fetching a key and reporting a spurious Invalid.
        if matches!(event.kind, EventKind::Unknown { .. }) {
            entries.push(VolumeEventEntry {
                event,
                signature_status: SignatureStatus::Unparseable,
            });
            continue;
        }
        let coord_id = event.coordinator_id.clone();
        if !keys.contains_key(&coord_id) {
            match identity::fetch_coordinator_pub(store, &coord_id).await {
                Ok(vk) => {
                    keys.insert(coord_id.clone(), Some(vk));
                }
                Err(e) => {
                    key_failures.insert(coord_id.clone(), format!("{e}"));
                    keys.insert(coord_id.clone(), None);
                }
            }
        }
        let status = match keys.get(&coord_id).and_then(|opt| opt.as_ref()) {
            Some(vk) => verify_event_signature(&event, vk),
            None => SignatureStatus::KeyUnavailable {
                reason: key_failures
                    .get(&coord_id)
                    .cloned()
                    .unwrap_or_else(|| "pubkey unavailable".to_string()),
            },
        };
        entries.push(VolumeEventEntry {
            event,
            signature_status: status,
        });
    }
    Ok(entries)
}

#[async_trait]
impl EventJournalReader for ReadOnlyEventJournal {
    async fn read_head(
        &self,
        name: &str,
    ) -> Result<Option<(EventHead, EventHeadToken)>, EventError> {
        read_head_via(self.reader.as_ref(), name).await
    }

    async fn recent(&self, name: &str, limit: usize) -> Result<Vec<VolumeEvent>, EventError> {
        recent_via(self.reader.as_ref(), name, limit).await
    }

    async fn list_and_verify(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Vec<VolumeEventEntry>, EventError> {
        list_and_verify_via(self.reader.as_ref(), name, limit).await
    }
}

#[async_trait]
impl EventJournalReader for BucketEventJournal {
    async fn read_head(
        &self,
        name: &str,
    ) -> Result<Option<(EventHead, EventHeadToken)>, EventError> {
        read_head_via(self.reader.as_ref(), name).await
    }

    async fn recent(&self, name: &str, limit: usize) -> Result<Vec<VolumeEvent>, EventError> {
        recent_via(self.reader.as_ref(), name, limit).await
    }

    async fn list_and_verify(
        &self,
        name: &str,
        limit: usize,
    ) -> Result<Vec<VolumeEventEntry>, EventError> {
        list_and_verify_via(self.reader.as_ref(), name, limit).await
    }
}

#[async_trait]
impl EventJournal for BucketEventJournal {
    async fn emit(
        &self,
        identity: &CoordinatorIdentity,
        name: &str,
        kind: EventKind,
        vol_ulid: Ulid,
    ) -> Result<VolumeEvent, EventError> {
        let lock = name_emit_lock(name);
        let _guard = lock.lock().await;

        // CAS runs wholly on coord-rw: the design-mint rule is that
        // a mutation path uses one credential end-to-end, including the
        // reads that are part of the mutation.
        let head = read_head_via(self.writer.as_ref(), name).await?;
        let (prev_head, expected) = match head {
            Some((h, tok)) => (Some(h), Some(tok.version)),
            None => (None, None),
        };
        let prev_event_ulid = prev_head
            .as_ref()
            .and_then(|h| h.latest())
            .and_then(|e| e.event_ulid());

        let event_ulid = match prev_event_ulid {
            Some(prev) => elide_core::ulid_mint::UlidMint::new(prev).next(),
            None => Ulid::new(),
        };
        let mut event = VolumeEvent::new(
            event_ulid,
            name.to_owned(),
            identity.coordinator_id_str().to_owned(),
            identity.hostname().map(str::to_owned),
            vol_ulid,
            prev_event_ulid,
            kind,
        )
        .ok_or(EventError::UnrepresentableTimestamp)?;
        sign_event(&mut event, identity);

        let new_head = prev_head.unwrap_or_default().pushed(event.clone());
        let is_force = matches!(event.kind, EventKind::ForceClaimed { .. });
        write_head(self.writer.as_ref(), name, &new_head, expected, is_force).await?;
        append_record(self.writer.as_ref(), name, &event).await?;
        Ok(event)
    }
}

/// Verify `event.signature` against `verifying_key`. Pure helper —
/// not on the trait because it touches no store.
pub fn verify_event_signature(
    event: &VolumeEvent,
    verifying_key: &VerifyingKey,
) -> SignatureStatus {
    use ed25519_dalek::Verifier;

    let Some(sig_hex) = event.signature.as_deref() else {
        return SignatureStatus::Missing;
    };
    let sig_bytes = match signing::decode_hex(sig_hex) {
        Ok(b) => b,
        Err(e) => {
            return SignatureStatus::Invalid {
                reason: format!("signature hex decode: {e}"),
            };
        }
    };
    let sig_arr: [u8; 64] = match sig_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return SignatureStatus::Invalid {
                reason: format!("signature wrong length ({}, want 64)", sig_bytes.len()),
            };
        }
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    match verifying_key.verify(&event.signing_payload(), &signature) {
        Ok(()) => SignatureStatus::Valid,
        Err(e) => SignatureStatus::Invalid {
            reason: format!("signature did not verify: {e}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::CoordinatorIdentity;
    use object_store::memory::InMemory;
    use tempfile::TempDir;

    fn journal() -> (Arc<dyn ObjectStore>, BucketEventJournal) {
        // Tests use a single in-memory store for both writer and
        // reader — the credential fan-out is a deployment concern, not
        // a behavioural one.
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let j = BucketEventJournal::new(Arc::clone(&store), Arc::clone(&store));
        (store, j)
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
        let (_s, j) = journal();
        let (_tmp, id) = fresh_identity();

        assert!(
            j.recent("vol", DEFAULT_EVENTS_LIMIT)
                .await
                .unwrap()
                .is_empty()
        );

        let ev = j
            .emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("emit");
        assert!(ev.signature.is_some());
        assert_eq!(ev.coordinator_id, id.coordinator_id_str());

        let recent = j.recent("vol", DEFAULT_EVENTS_LIMIT).await.expect("recent");
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].event_ulid, ev.event_ulid);
    }

    #[tokio::test]
    async fn second_event_chains_via_prev_event_ulid() {
        let (_s, j) = journal();
        let (_tmp, id) = fresh_identity();

        let first = j
            .emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("first");
        let second = j
            .emit(&id, "vol", EventKind::Claimed, vol_ulid())
            .await
            .expect("second");

        assert_eq!(second.prev_event_ulid, Some(first.event_ulid));
    }

    #[tokio::test]
    async fn back_to_back_emits_are_strictly_monotonic() {
        let (_s, j) = journal();
        let (_tmp, id) = fresh_identity();

        let mut last_ulid: Option<Ulid> = None;
        for _ in 0..32 {
            let ev = j
                .emit(&id, "vol", EventKind::Created, vol_ulid())
                .await
                .expect("emit");
            if let Some(prev) = last_ulid {
                assert!(ev.event_ulid > prev);
            }
            last_ulid = Some(ev.event_ulid);
        }
    }

    #[tokio::test]
    async fn emitted_event_round_trips_through_storage() {
        let (s, j) = journal();
        let (_tmp, id) = fresh_identity();

        let ev = j
            .emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("emit");

        let key = event_key("vol", ev.event_ulid);
        let bytes = s.get(&key).await.unwrap().bytes().await.unwrap();
        let parsed = VolumeEvent::from_toml(std::str::from_utf8(&bytes).unwrap()).unwrap();
        assert_eq!(parsed, ev);
    }

    #[tokio::test]
    async fn recent_events_newest_first_and_chronological() {
        let (s, j) = journal();
        let (_tmp, id) = fresh_identity();
        id.publish_pub(s.as_ref()).await.expect("publish pub");

        let a = j
            .emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("first");
        let b = j
            .emit(&id, "vol", EventKind::Claimed, vol_ulid())
            .await
            .expect("second");
        assert!(b.event_ulid > a.event_ulid);
        assert_eq!(b.prev_event_ulid, Some(a.event_ulid));

        let recent = j.recent("vol", DEFAULT_EVENTS_LIMIT).await.expect("recent");
        assert_eq!(
            recent.iter().map(|e| e.event_ulid).collect::<Vec<_>>(),
            vec![b.event_ulid, a.event_ulid],
        );

        let listed = j
            .list_and_verify("vol", DEFAULT_EVENTS_LIMIT)
            .await
            .expect("verify");
        assert_eq!(
            listed
                .iter()
                .map(|e| e.event.event_ulid)
                .collect::<Vec<_>>(),
            vec![a.event_ulid, b.event_ulid],
        );
    }

    #[tokio::test]
    async fn recent_events_walks_back_links_past_full_window() {
        let (s, j) = journal();
        let (_tmp, id) = fresh_identity();

        let total = HEAD_WINDOW + 4;
        let mut emitted = Vec::with_capacity(total);
        for _ in 0..total {
            emitted.push(
                j.emit(&id, "vol", EventKind::Created, vol_ulid())
                    .await
                    .expect("emit"),
            );
        }

        let windowed = j.recent("vol", HEAD_WINDOW).await.expect("win");
        assert_eq!(windowed.len(), HEAD_WINDOW);
        assert!(
            windowed
                .windows(2)
                .all(|w| w[0].event_ulid > w[1].event_ulid)
        );
        assert_eq!(windowed[0].event_ulid, emitted[total - 1].event_ulid);

        let all = j.recent("vol", total).await.expect("all");
        assert_eq!(all.len(), total);
        assert!(all.windows(2).all(|w| w[0].event_ulid > w[1].event_ulid));
        assert_eq!(all[total - 1].event_ulid, emitted[0].event_ulid);

        let oldest_in_window = &all[HEAD_WINDOW - 1];
        let first_off_window = oldest_in_window
            .prev_event_ulid
            .expect("there is an older event");
        s.delete(&event_key("vol", first_off_window))
            .await
            .expect("delete record");

        let truncated = j.recent("vol", total).await.expect("truncated");
        assert_eq!(truncated.len(), HEAD_WINDOW);
    }

    #[tokio::test]
    async fn write_head_cas_is_displaced_but_force_is_unconditional() {
        let (s, j) = journal();
        let (_tmp, id) = fresh_identity();

        j.emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("seed");
        let (head_v1, tok_v1) = j.read_head("vol").await.expect("read").expect("present");

        write_head(s.as_ref(), "vol", &head_v1, None, true)
            .await
            .expect("force overwrite");

        let displaced = write_head(
            s.as_ref(),
            "vol",
            &head_v1,
            Some(tok_v1.version.clone()),
            false,
        )
        .await;
        assert!(matches!(displaced, Err(EventError::Displaced)));

        write_head(s.as_ref(), "vol", &head_v1, Some(tok_v1.version), true)
            .await
            .expect("force write must never fail on a version mismatch");
    }

    #[tokio::test]
    async fn list_and_verify_marks_valid_when_pubkey_published() {
        let (s, j) = journal();
        let (_tmp, id) = fresh_identity();
        id.publish_pub(s.as_ref()).await.expect("publish pub");

        j.emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("emit");

        let entries = j
            .list_and_verify("vol", DEFAULT_EVENTS_LIMIT)
            .await
            .expect("verify");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].signature_status, SignatureStatus::Valid);
    }

    #[tokio::test]
    async fn list_and_verify_reports_key_unavailable_without_published_pub() {
        let (_s, j) = journal();
        let (_tmp, id) = fresh_identity();

        j.emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("emit");

        let entries = j
            .list_and_verify("vol", DEFAULT_EVENTS_LIMIT)
            .await
            .expect("verify");
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].signature_status,
            SignatureStatus::KeyUnavailable { .. }
        ));
    }

    #[tokio::test]
    async fn list_and_verify_reports_invalid_for_tampered_event() {
        let (s, j) = journal();
        let (_tmp, id) = fresh_identity();
        id.publish_pub(s.as_ref()).await.expect("publish pub");

        let original = j
            .emit(&id, "vol", EventKind::Created, vol_ulid())
            .await
            .expect("emit");

        let mut tampered = original.clone();
        tampered.kind = EventKind::Claimed;
        let head = EventHead {
            events: vec![HeadEvent::Parsed(Box::new(tampered))],
        };
        let body = serialise_head(&head).expect("serialise head");
        s.put(&head_key("vol"), Bytes::from(body.into_bytes()).into())
            .await
            .expect("overwrite head");

        let entries = j
            .list_and_verify("vol", DEFAULT_EVENTS_LIMIT)
            .await
            .expect("verify");
        assert_eq!(entries.len(), 1);
        assert!(matches!(
            entries[0].signature_status,
            SignatureStatus::Invalid { .. }
        ));
    }

    /// A `force_claimed` event written before `source_vol_ulid` became a
    /// required field: the whole HEAD used to fail to parse, freezing
    /// every future emit for the name. The read path now tolerates it.
    #[tokio::test]
    async fn head_with_unparseable_event_is_tolerated() {
        let (s, j) = journal();
        let (_tmp, id) = fresh_identity();
        id.publish_pub(s.as_ref()).await.expect("publish pub");

        let legacy_head = r#"
[[events]]
version = 3
event_ulid = "01J0000000000000000000000E"
at = "2026-06-15T00:00:00.000Z"
name = "vol"
coordinator_id = "01ABCDEFGHJKMNPQRSTVWXYZ23"
vol_ulid = "01J0000000000000000000000V"
kind = "force_claimed"
displaced_coordinator_id = "01OLDCOORDXXXXXXXXXXXXXXXX"
signature = "00"
"#;
        s.put(
            &head_key("vol"),
            Bytes::from(legacy_head.as_bytes().to_vec()).into(),
        )
        .await
        .expect("seed head");

        // recent tolerates it: surfaced as Unknown, common fields intact.
        let recent = j.recent("vol", DEFAULT_EVENTS_LIMIT).await.expect("recent");
        assert_eq!(recent.len(), 1);
        assert!(matches!(recent[0].kind, EventKind::Unknown { .. }));
        assert_eq!(recent[0].vol_ulid, vol_ulid());

        // emit is no longer frozen — a new event appends.
        let new = j
            .emit(&id, "vol", EventKind::Claimed, vol_ulid())
            .await
            .expect("emit unfreezes");

        // The opaque event survives the HEAD rewrite verbatim, newest-first.
        let after = j
            .recent("vol", DEFAULT_EVENTS_LIMIT)
            .await
            .expect("recent after");
        assert_eq!(after.len(), 2);
        assert_eq!(after[0].event_ulid, new.event_ulid);
        assert!(matches!(
            &after[1].kind,
            EventKind::Unknown { original_kind } if original_kind.as_deref() == Some("force_claimed")
        ));

        // list_and_verify reports it Unparseable, not a spurious Invalid.
        let entries = j
            .list_and_verify("vol", DEFAULT_EVENTS_LIMIT)
            .await
            .expect("verify");
        let unknown = entries
            .iter()
            .find(|e| matches!(e.event.kind, EventKind::Unknown { .. }))
            .expect("unknown entry present");
        assert_eq!(unknown.signature_status, SignatureStatus::Unparseable);
    }

    /// Property: under any interleaving of normal emits, force-release
    /// emits, and crash-injected emits (HEAD written, standalone
    /// record skipped — the Option-3 phantom), the readable log is
    /// always a single contiguous newest-first chain and the HEAD
    /// window is exactly its newest-N prefix.
    mod prop_event_log {
        use super::*;
        use proptest::prelude::*;

        #[derive(Debug, Clone)]
        enum Op {
            Emit(u8),
            EmitForce,
            EmitCrashed,
        }

        fn arb_op() -> impl Strategy<Value = Op> {
            prop_oneof![
                (0u8..2).prop_map(Op::Emit),
                Just(Op::EmitForce),
                Just(Op::EmitCrashed),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 96, ..ProptestConfig::default() })]

            #[test]
            fn window_is_prefix_of_chain_under_crash_and_force(
                ops in prop::collection::vec(arb_op(), 1..40)
            ) {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let (s, j) = journal();
                    let (_ta, id_a) = fresh_identity();
                    let (_tb, id_b) = fresh_identity();
                    let name = "vol";
                    let v = vol_ulid();

                    for op in &ops {
                        match op {
                            Op::Emit(k) => {
                                let kind = if *k == 0 {
                                    EventKind::Created
                                } else {
                                    EventKind::Claimed
                                };
                                j.emit(&id_a, name, kind, v).await.expect("emit");
                            }
                            Op::EmitForce => {
                                j.emit(
                                    &id_b,
                                    name,
                                    EventKind::ForceClaimed {
                                        source_vol_ulid: v,
                                        displaced_coordinator_id: Some(
                                            id_a.coordinator_id_str().to_owned(),
                                        ),
                                    },
                                    v,
                                )
                                .await
                                .expect("force emit");
                            }
                            Op::EmitCrashed => {
                                let head = j.read_head(name).await.expect("read head");
                                let (prev_head, expected) = match head {
                                    Some((h, tok)) => (Some(h), Some(tok.version)),
                                    None => (None, None),
                                };
                                let prev_ulid = prev_head
                                    .as_ref()
                                    .and_then(|h| h.latest())
                                    .and_then(|e| e.event_ulid());
                                let event_ulid = match prev_ulid {
                                    Some(p) => {
                                        elide_core::ulid_mint::UlidMint::new(p).next()
                                    }
                                    None => Ulid::new(),
                                };
                                let mut ev = VolumeEvent::new(
                                    event_ulid,
                                    name.to_owned(),
                                    id_a.coordinator_id_str().to_owned(),
                                    id_a.hostname().map(str::to_owned),
                                    v,
                                    prev_ulid,
                                    EventKind::Created,
                                )
                                .expect("event");
                                sign_event(&mut ev, &id_a);
                                let new_head =
                                    prev_head.unwrap_or_default().pushed(ev.clone());
                                write_head(s.as_ref(), name, &new_head, expected, false)
                                    .await
                                    .expect("crash write_head");
                                assert!(
                                    s.get(&event_key(name, ev.event_ulid)).await.is_err()
                                );
                            }
                        }
                    }

                    let window = j.recent(name, HEAD_WINDOW).await.expect("window");
                    let full = j.recent(name, usize::MAX).await.expect("full");

                    assert!(window.len() <= HEAD_WINDOW);
                    assert!(window.len() <= full.len());
                    for (w, f) in window.iter().zip(full.iter()) {
                        assert_eq!(w.event_ulid, f.event_ulid);
                    }

                    for pair in full.windows(2) {
                        assert!(pair[0].event_ulid > pair[1].event_ulid);
                        assert_eq!(pair[0].prev_event_ulid, Some(pair[1].event_ulid));
                    }
                });
            }
        }
    }
}
