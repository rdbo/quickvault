// SPDX-License-Identifier: AGPL-3.0-or-later

//! Snapshot-bound views with bounded selection and short session reads (0004 §7).

use std::cmp::{Ordering, Reverse};
use std::collections::BinaryHeap;
use std::ops::Bound::{Excluded, Unbounded};

use qv_crypto::{ContentHasher, RecordId, SecretArray};
use qv_model::{RandomId, RecordKind, Text, Timestamp};
use zeroize::Zeroizing;

use crate::index::{Data, ViewData};
use crate::session::{Ctx, SessionTag};
use crate::view_cache::TextLease;
use crate::views::{entry_summary, group_summary, item_handle, item_name, trash_item};
use crate::{
    CancelToken, ConflictSummary, CoreError, EntrySummary, GroupHandle, GroupSummary,
    MAX_QUERY_BYTES, SearchHit, Session, TrashItem,
};

/// Maximum rows in a page.
pub const MAX_PAGE_ROWS: usize = 32;
/// Maximum owned display text in a page, distinct from cache/workspace text.
pub const MAX_PAGE_TEXT_BYTES: usize = 2 * 1024 * 1024;
const MIN_PAGE_TEXT_BYTES: usize = qv_model::MAX_RECORD_BYTES + 3 * qv_model::MAX_TEXT_BYTES;

/// Validated page bounds; the minimum text bound fits one maximum valid row.
#[derive(Clone, Copy, Debug)]
pub struct PageLimit {
    rows: usize,
    bytes: usize,
}
impl Default for PageLimit {
    fn default() -> Self {
        Self {
            rows: MAX_PAGE_ROWS,
            bytes: MAX_PAGE_TEXT_BYTES,
        }
    }
}
impl PageLimit {
    /// Bounds rows to1–32 and text to the maximum-row-safe range (1.75–2MiB). Smaller bounds could exclude a valid row.
    pub fn new(rows: usize, bytes: usize) -> Result<Self, CoreError> {
        if !(1..=MAX_PAGE_ROWS).contains(&rows)
            || !(MIN_PAGE_TEXT_BYTES..=MAX_PAGE_TEXT_BYTES).contains(&bytes)
        {
            return Err(CoreError::InvalidInput);
        }
        Ok(Self { rows, bytes })
    }
}

/// A page and an optional continuation, neither cloneable nor secret-formatted.
pub struct ViewPage<T> {
    /// Complete rows in the existing view order.
    pub items: Vec<T>,
    /// Continue the same query/revision; a mutation returns StaleHandle.
    pub next: Option<ViewCursor>,
    /// Read the immediately preceding rows without retaining a page history.
    pub previous: Option<ViewCursor>,
    /// The authenticated local-state revision used for all rows.
    pub revision: u64,
}
impl<T> core::fmt::Debug for ViewPage<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ViewPage(<redacted>)")
    }
}

/// Entry-list scope and optional local title/first-field filter.
#[derive(Default)]
pub struct ItemFilter<'a> {
    /// Include entries in this group and all displayed descendants.
    pub group: Option<GroupHandle>,
    /// Match one of [`TYPE_BUCKETS`]: the lowercased type hint exactly, or
    /// `other` for every hint outside the standard four.
    pub kind: Option<&'a str>,
    /// Match title or first visible field, as the app's list filter does.
    pub text: Option<&'a str>,
    /// Restrict to entries whose group is missing/deleted.
    pub recovered: bool,
    /// Search every searchable field, instead of only the first visible field.
    pub search_all_fields: bool,
}

struct BudgetText {
    value: Zeroizing<String>,
    _lease: TextLease,
}
impl BudgetText {
    fn as_str(&self) -> &str {
        &self.value
    }
}

struct SortKey {
    category: u8,
    date: Reverse<Option<Timestamp>>,
    text: BudgetText,
    id: [u8; 16],
    version: [u8; 16],
}
impl PartialEq for SortKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for SortKey {}
impl PartialOrd for SortKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SortKey {
    fn cmp(&self, other: &Self) -> Ordering {
        (
            self.category,
            self.date,
            self.text.as_str(),
            self.id,
            self.version,
        )
            .cmp(&(
                other.category,
                other.date,
                other.text.as_str(),
                other.id,
                other.version,
            ))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Types,
    Autofill,
    Children(RecordId),
    GroupItems(RecordId),
    Groups(Option<RecordId>),
    Search,
    Items {
        group: Option<RecordId>,
        recovered: bool,
        kind: bool,
        all_fields: bool,
    },
    Trash,
    Conflicts,
    AllConflicts,
}

/// One type bucket present in live entries, with an exact count.
pub struct KindSummary {
    /// One of [`TYPE_BUCKETS`].
    pub kind: Zeroizing<String>,
    /// Live entries of this type.
    pub count: usize,
}
impl core::fmt::Debug for KindSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("KindSummary(<redacted>)")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Direction {
    Forward,
    Backward,
}

struct Candidate {
    key: SortKey,
    direction: Direction,
    count: std::cell::Cell<usize>,
}
impl PartialEq for Candidate {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key
    }
}
impl Eq for Candidate {}
impl PartialOrd for Candidate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Candidate {
    fn cmp(&self, other: &Self) -> Ordering {
        self.direction
            .cmp(&other.direction)
            .then_with(|| match self.direction {
                Direction::Forward => self.key.cmp(&other.key),
                Direction::Backward => other.key.cmp(&self.key),
            })
    }
}

/// Private continuation bound to one unlocked session, revision, scope and query.
#[derive(Clone)]
pub struct ViewCursor(std::sync::Arc<CursorState>);
struct CursorState {
    session: SessionTag,
    revision: u64,
    scope: Scope,
    query: std::sync::Arc<SecretArray<32>>,
    after: std::sync::Arc<SortKey>,
    direction: Direction,
}
impl core::fmt::Debug for ViewCursor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ViewCursor(<redacted>)")
    }
}

struct Request<'a> {
    requester: Option<&'a crate::platform::autofill::Requester>,
    session: SessionTag,
    revision: u64,
    scope: Scope,
    text: BudgetText,
    kind: BudgetText,
    fingerprint: std::sync::Arc<SecretArray<32>>,
}

fn text(ctx: &Ctx<'_>, value: Zeroizing<String>) -> Result<BudgetText, CoreError> {
    let lease = ctx
        .open
        .index
        .cache
        .reserve(value.capacity())
        .ok_or(CoreError::LimitExceeded)?;
    Ok(BudgetText {
        value,
        _lease: lease,
    })
}
/// The type buckets `kinds_page` returns, in order; every lowercased type
/// hint outside the first four, including an empty one, is `other` (0003 §5.1).
pub const TYPE_BUCKETS: [&str; 5] = ["login", "note", "card", "wifi", "other"];
/// The [`TYPE_BUCKETS`] entry of a lowercased type hint.
pub fn type_bucket(kind: &str) -> &'static str {
    TYPE_BUCKETS[..4]
        .iter()
        .find(|b| **b == kind)
        .copied()
        .unwrap_or("other")
}
fn lower(ctx: &Ctx<'_>, value: &str) -> Result<BudgetText, CoreError> {
    text(ctx, Zeroizing::new(value.to_lowercase()))
}
fn fingerprint(a: &str, b: &str) -> std::sync::Arc<SecretArray<32>> {
    let mut hash = ContentHasher::new();
    hash.update(b"qv/view-query/v1");
    hash.update(&(a.len() as u64).to_be_bytes());
    hash.update(a.as_bytes());
    hash.update(&(b.len() as u64).to_be_bytes());
    hash.update(b.as_bytes());
    std::sync::Arc::new(hash.finalize())
}
fn check(ctx: &Ctx<'_>, request: &Request, cancel: &CancelToken) -> Result<(), CoreError> {
    ctx.check_cancel()?;
    if cancel.is_cancelled() {
        return Err(CoreError::Cancelled);
    }
    if ctx.tag() != request.session || ctx.open.vault.local_seq() != request.revision {
        return Err(CoreError::StaleHandle);
    }
    Ok(())
}
fn in_group(ctx: &Ctx<'_>, at: RecordId, target: RecordId) -> bool {
    let mut current = match ctx.open.index.tree.place_entry(at) {
        qv_model::EntryPlace::Group(id) => Some(id),
        qv_model::EntryPlace::Recovered => None,
    };
    for _ in 0..=ctx.open.index.records.len() {
        let Some(id) = current else { return false };
        if id == target {
            return true;
        }
        current = ctx.open.index.tree.parent(id).flatten();
    }
    false
}

fn key(ctx: &Ctx<'_>, request: &Request, id: RecordId) -> Result<Option<SortKey>, CoreError> {
    let index = &ctx.open.index;
    let info = index.get(id).ok_or(CoreError::Internal)?;
    let wanted = match request.scope {
        Scope::Autofill => false,
        Scope::Types => info.status.live && info.kind == RecordKind::Entry,
        Scope::Trash => {
            info.status.in_trash && matches!(info.kind, RecordKind::Entry | RecordKind::Group)
        }
        Scope::AllConflicts => info.status.conflict,
        Scope::Conflicts => {
            info.status.conflict && matches!(info.kind, RecordKind::Entry | RecordKind::Group)
        }
        Scope::GroupItems(parent) => {
            info.status.live
                && match &info.data {
                    Data::Group(_) => {
                        id != index.root && index.tree.parent(id) == Some(Some(parent))
                    }
                    Data::Entry(e) => in_group(ctx, e.group, parent),
                    _ => false,
                }
        }
        Scope::Groups(parent) => {
            info.status.live
                && info.kind == RecordKind::Group
                && match parent {
                    Some(parent) => id != index.root && index.tree.parent(id) == Some(Some(parent)),
                    None => index.tree.parent(id).is_some(),
                }
        }
        Scope::Children(parent) => {
            info.status.live
                && match &info.data {
                    Data::Group(_) => {
                        id != index.root && index.tree.parent(id) == Some(Some(parent))
                    }
                    Data::Entry(e) => {
                        index.tree.place_entry(e.group) == qv_model::EntryPlace::Group(parent)
                    }
                    _ => false,
                }
        }
        Scope::Items {
            group, recovered, ..
        } => {
            info.status.live
                && match &info.data {
                    Data::Entry(e) if recovered => {
                        index.tree.place_entry(e.group) == qv_model::EntryPlace::Recovered
                    }
                    Data::Entry(e) => group.is_none_or(|parent| in_group(ctx, e.group, parent)),
                    _ => false,
                }
        }
        Scope::Search => {
            info.status.live
                && match info.kind {
                    RecordKind::Entry => true,
                    RecordKind::Group => index.tree.parent(id).is_some(),
                    _ => false,
                }
        }
    };
    if !wanted {
        return Ok(None);
    }
    if matches!(
        request.scope,
        Scope::Trash | Scope::Conflicts | Scope::AllConflicts
    ) {
        let deleted = match &info.data {
            Data::Entry(e) => e.deleted_at,
            Data::Group(g) => g.deleted_at,
            _ => None,
        };
        return Ok(Some(SortKey {
            category: 0,
            date: Reverse(if request.scope == Scope::Trash {
                deleted
            } else {
                None
            }),
            text: text(ctx, Zeroizing::new(String::new()))?,
            id: id.0,
            version: [0; 16],
        }));
    }
    let view = ctx.view(id)?;
    if request.scope == Scope::Types {
        let ViewData::Entry(entry) = &**view else {
            return Err(CoreError::Internal);
        };
        let kind = type_bucket(lower(ctx, entry.type_hint.expose())?.as_str());
        let category = TYPE_BUCKETS
            .iter()
            .position(|b| *b == kind)
            .and_then(|i| u8::try_from(i).ok())
            .ok_or(CoreError::Internal)?;
        return Ok(Some(SortKey {
            category,
            date: Reverse(None),
            text: text(ctx, Zeroizing::new(kind.to_owned()))?,
            id: [0; 16],
            version: [0; 16],
        }));
    }
    let mut category = 0;
    let mut date = Reverse(None);
    let sort = match &**view {
        ViewData::Group(group) => match request.scope {
            Scope::Search | Scope::Groups(None) => {
                if matches!(request.scope, Scope::Groups(None)) {
                    category = u8::from(id != index.root);
                }
                let name = lower(ctx, group.name.expose())?;
                if !name.as_str().contains(request.text.as_str()) {
                    return Ok(None);
                }
                name
            }
            Scope::Children(_) | Scope::GroupItems(_) | Scope::Groups(Some(_)) => {
                if matches!(request.scope, Scope::Groups(_))
                    && !request.text.as_str().is_empty()
                    && !lower(ctx, group.name.expose())?
                        .as_str()
                        .contains(request.text.as_str())
                {
                    return Ok(None);
                }
                text(ctx, Zeroizing::new(group.order.expose().to_owned()))?
            }
            Scope::Trash => {
                date = Reverse(group.deleted_at);
                text(ctx, Zeroizing::new(String::new()))?
            }
            Scope::Conflicts => text(ctx, Zeroizing::new(String::new()))?,
            _ => return Ok(None),
        },
        ViewData::Entry(entry) => {
            if matches!(request.scope, Scope::Items { kind: true, .. })
                && type_bucket(lower(ctx, entry.type_hint.expose())?.as_str())
                    != request.kind.as_str()
            {
                return Ok(None);
            }
            let title = lower(ctx, entry.title.expose())?;
            if matches!(
                request.scope,
                Scope::Search | Scope::Items { .. } | Scope::GroupItems(_)
            ) && !request.text.as_str().is_empty()
                && !title.as_str().contains(request.text.as_str())
            {
                let mut hit = false;
                let fields = if matches!(
                    request.scope,
                    Scope::Search
                        | Scope::Items {
                            all_fields: true,
                            ..
                        }
                ) {
                    entry.fields.len()
                } else {
                    1
                };
                for field in entry.fields.iter().take(fields) {
                    if lower(ctx, field.value.expose())?
                        .as_str()
                        .contains(request.text.as_str())
                    {
                        hit = true;
                        break;
                    }
                }
                if !hit {
                    return Ok(None);
                }
            }
            match request.scope {
                Scope::Search | Scope::Children(_) | Scope::GroupItems(_) => {
                    category = 1;
                    title
                }
                Scope::Trash => {
                    date = Reverse(entry.deleted_at);
                    text(ctx, Zeroizing::new(String::new()))?
                }
                Scope::Conflicts => text(ctx, Zeroizing::new(String::new()))?,
                _ => title,
            }
        }
        _ => return Ok(None),
    };
    Ok(Some(SortKey {
        category,
        date,
        text: sort,
        id: id.0,
        version: [0; 16],
    }))
}

pub(crate) enum Row {
    Hit(SearchHit),
    Trash(TrashItem),
    Conflict(ConflictSummary),
    AllConflict(crate::conflict::ConflictRecordSummary),
    Kind(KindSummary),
    Autofill(crate::autofill::FillCandidate),
}
impl Row {
    fn bytes(&self) -> usize {
        match self {
            Self::Hit(SearchHit::Group(g)) => {
                g.name.allocated_bytes()
                    + g.order.allocated_bytes()
                    + g.icon.as_ref().map_or(0, Text::allocated_bytes)
            }
            Self::Hit(SearchHit::Entry(e)) => {
                e.title.allocated_bytes()
                    + e.type_hint.allocated_bytes()
                    + e.type_key.capacity()
                    + e.icon.as_ref().map_or(0, Text::allocated_bytes)
                    + e.fields
                        .iter()
                        .map(|f| f.name.allocated_bytes() + f.value.allocated_bytes())
                        .sum::<usize>()
            }
            Self::Autofill(c) => {
                c.title.allocated_bytes() + c.username.as_ref().map_or(0, Text::allocated_bytes)
            }
            Self::Kind(k) => k.kind.capacity(),
            Self::Trash(t) => t.name.allocated_bytes(),
            Self::Conflict(c) => c.name.allocated_bytes(),
            Self::AllConflict(c) => c.name.as_ref().map_or(0, Text::allocated_bytes),
        }
    }
}
fn row(ctx: &Ctx<'_>, request: &Request, candidate: &Candidate) -> Result<Row, CoreError> {
    if request.scope == Scope::Types {
        return Ok(Row::Kind(KindSummary {
            kind: Zeroizing::new(candidate.key.text.as_str().to_owned()),
            count: candidate.count.get(),
        }));
    }
    let id = RecordId(candidate.key.id);
    let info = ctx.open.index.get(id).ok_or(CoreError::Internal)?;
    if let Some(requester) = request.requester {
        let version =
            qv_model::VersionId::from_bytes(candidate.key.version).map_err(crate::error::data)?;
        let e = crate::autofill::entry_of(crate::views::decrypt(ctx, id, version)?.body)
            .filter(|e| crate::autofill::identifies(e, requester))
            .ok_or(CoreError::StaleHandle)?;
        return Ok(Row::Autofill(crate::autofill::candidate(
            ctx.entry_handle(id),
            version,
            e,
            info.status.conflict,
        )));
    }
    if request.scope == Scope::AllConflicts {
        let name = if matches!(info.kind, RecordKind::Entry | RecordKind::Group) {
            let view = ctx.view(id)?;
            item_name(&view)
                .map(|v| Text::new(v.expose()).map_err(crate::error::data))
                .transpose()?
        } else {
            None
        };
        return Ok(Row::AllConflict(crate::conflict::ConflictRecordSummary {
            record: crate::conflict::ConflictRecord {
                handle: crate::conflict::ConflictRecordHandle {
                    session: ctx.tag(),
                    record: id,
                },
                kind: info.kind,
                versions: info.heads.len(),
            },
            name,
        }));
    }
    if request.scope == Scope::Trash {
        return trash_item(ctx, id, info)?
            .map(Row::Trash)
            .ok_or(CoreError::Internal);
    }
    let view = ctx.view(id)?;
    if request.scope == Scope::Conflicts {
        let item = item_handle(ctx, id, info).ok_or(CoreError::Internal)?;
        let name = Text::new(item_name(&view).ok_or(CoreError::Internal)?.expose())
            .map_err(crate::error::data)?;
        return Ok(Row::Conflict(ConflictSummary {
            item,
            name,
            heads: info.heads.len(),
            in_trash: info.status.in_trash,
        }));
    }
    Ok(Row::Hit(match &**view {
        ViewData::Group(g) => SearchHit::Group(group_summary(ctx, id, info, g)?),
        ViewData::Entry(e) => SearchHit::Entry(entry_summary(ctx, id, info, e)?),
        _ => return Err(CoreError::Internal),
    }))
}

impl Session {
    fn page(
        &self,
        scope: Scope,
        query: &str,
        kind: &str,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<Row>, CoreError> {
        self.scan_page(scope, query, kind, None, cursor, limit, cancel)
    }

    #[allow(clippy::too_many_arguments)] // Internal shared scanner; method/scope and query remain explicit.
    fn scan_page(
        &self,
        scope: Scope,
        query: &str,
        kind: &str,
        requester: Option<&crate::platform::autofill::Requester>,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<Row>, CoreError> {
        if query.len() > MAX_QUERY_BYTES || kind.len() > 3 * qv_model::MAX_TEXT_BYTES {
            return Err(CoreError::InvalidInput);
        }
        let request = self.read(|ctx| {
            if cancel.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            if let Scope::Children(group)
            | Scope::Items {
                group: Some(group), ..
            } = scope
                && ctx.open.index.tree.parent(group).is_none()
            {
                return Err(CoreError::NotFound);
            }
            let text = lower(ctx, query)?;
            let kind = lower(ctx, kind)?;
            let fingerprint = if let Some(requester) = requester {
                use crate::platform::autofill::Requester;
                match requester {
                    Requester::App(app) => fingerprint(&app.to_url(), "app"),
                    Requester::Web { browser, origin } => {
                        fingerprint(&browser.to_url(), &origin.display())
                    }
                }
            } else {
                fingerprint(text.as_str(), kind.as_str())
            };
            let request = Request {
                requester,
                session: ctx.tag(),
                revision: ctx.open.vault.local_seq(),
                scope,
                text,
                kind,
                fingerprint,
            };
            if let Some(cursor) = &cursor
                && (cursor.0.session != request.session
                    || cursor.0.revision != request.revision
                    || cursor.0.scope != scope
                    || !cursor.0.query.ct_eq(request.fingerprint.expose_secret()))
            {
                return Err(CoreError::StaleHandle);
            }
            Ok(request)
        })?;
        let direction = cursor
            .as_ref()
            .map_or(Direction::Forward, |c| c.0.direction);
        let had_boundary = cursor.is_some();
        let mut selected = BinaryHeap::<Candidate>::new();
        let mut scanned = None;
        let mut excess = false;
        loop {
            let done = self.read(|ctx| {
                check(ctx, &request, cancel)?;
                let ids: Vec<_> = ctx
                    .open
                    .index
                    .records
                    .range((scanned.map_or(Unbounded, Excluded), Unbounded))
                    .take(16)
                    .map(|(id, _)| *id)
                    .collect();
                for &id in &ids {
                    check(ctx, &request, cancel)?;
                    let mut consider = |candidate: SortKey| -> Result<(), CoreError> {
                        if cursor.as_ref().is_some_and(|c| match direction {
                            Direction::Forward => candidate <= *c.0.after,
                            Direction::Backward => candidate >= *c.0.after,
                        }) {
                            return Ok(());
                        }
                        if request.scope == Scope::Types
                            && let Some(existing) = selected.iter().find(|v| v.key == candidate)
                        {
                            existing.count.set(
                                existing
                                    .count
                                    .get()
                                    .checked_add(1)
                                    .ok_or(CoreError::Internal)?,
                            );
                            return Ok(());
                        }
                        let candidate = Candidate {
                            key: candidate,
                            direction,
                            count: std::cell::Cell::new(1),
                        };
                        if selected.len() < limit.rows {
                            selected.push(candidate);
                        } else {
                            excess = true;
                            if selected.peek().is_some_and(|last| candidate < *last) {
                                selected.pop();
                                selected.push(candidate);
                            }
                        }
                        Ok(())
                    };
                    if let Some(requester) = request.requester {
                        let r = ctx.open.index.get(id).ok_or(CoreError::Internal)?;
                        if r.kind != RecordKind::Entry || !r.status.live || r.status.finally_deleted
                        {
                            continue;
                        }
                        for &version in &r.heads {
                            check(ctx, &request, cancel)?;
                            if let Some(e) = crate::autofill::entry_of(
                                crate::views::decrypt(ctx, id, version)?.body,
                            ) && crate::autofill::identifies(&e, requester)
                            {
                                consider(SortKey {
                                    category: 0,
                                    date: Reverse(None),
                                    text: text(ctx, Zeroizing::new(e.title.expose().to_owned()))?,
                                    id: id.0,
                                    version: version.to_bytes(),
                                })?;
                            }
                        }
                    } else if let Some(candidate) = key(ctx, &request, id)? {
                        consider(candidate)?;
                    }
                }
                scanned = ids.last().copied().or(scanned);
                Ok(ids.len() < 16)
            })?;
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::PageBatch);
            if done {
                break;
            }
        }
        // Drop the incoming cursor before reserving/moving the continuation.
        drop(cursor);
        let mut items = Vec::new();
        let mut bytes = 0usize;
        let mut first = None;
        let mut last = None;
        let selected_len = selected.len();
        for candidate in selected.into_sorted_vec() {
            let value = self.read(|ctx| {
                check(ctx, &request, cancel)?;
                row(ctx, &request, &candidate)
            })?;
            let next_bytes = bytes
                .checked_add(value.bytes())
                .ok_or(CoreError::Internal)?;
            if next_bytes > limit.bytes {
                if items.is_empty() {
                    return Err(CoreError::Internal);
                }
                break;
            }
            bytes = next_bytes;
            items.push(value);
            let key = std::sync::Arc::new(candidate.key);
            match direction {
                Direction::Forward => {
                    if first.is_none() {
                        first = Some(std::sync::Arc::clone(&key));
                    }
                    last = Some(key);
                }
                Direction::Backward => {
                    if last.is_none() {
                        last = Some(std::sync::Arc::clone(&key));
                    }
                    first = Some(key);
                }
            }
        }
        self.read(|ctx| check(ctx, &request, cancel))?;
        let more = excess || selected_len > items.len();
        let make_cursor = |after, direction| {
            ViewCursor(std::sync::Arc::new(CursorState {
                session: request.session,
                revision: request.revision,
                scope,
                query: std::sync::Arc::clone(&request.fingerprint),
                after,
                direction,
            }))
        };
        let can_next = match direction {
            Direction::Forward => more,
            Direction::Backward => had_boundary,
        };
        let can_previous = match direction {
            Direction::Forward => had_boundary,
            Direction::Backward => more,
        };
        let next = if can_next && !items.is_empty() {
            Some(make_cursor(
                last.ok_or(CoreError::Internal)?,
                Direction::Forward,
            ))
        } else {
            None
        };
        let previous = if can_previous && !items.is_empty() {
            Some(make_cursor(
                first.ok_or(CoreError::Internal)?,
                Direction::Backward,
            ))
        } else {
            None
        };
        if direction == Direction::Backward {
            items.reverse();
        }
        Ok(ViewPage {
            items,
            next,
            previous,
            revision: request.revision,
        })
    }

    /// Matching live entry heads, ordered by exact title, entry and version.
    /// Each head is decoded independently; no protected value is returned.
    pub fn autofill_candidates_page(
        &self,
        requester: &crate::platform::autofill::Requester,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<crate::autofill::FillCandidate>, CoreError> {
        let page = self.scan_page(
            Scope::Autofill,
            "",
            "",
            Some(requester),
            cursor,
            limit,
            cancel,
        )?;
        let items = page
            .items
            .into_iter()
            .map(|row| match row {
                Row::Autofill(c) => Ok(c),
                _ => Err(CoreError::Internal),
            })
            .collect::<Result<_, _>>()?;
        Ok(ViewPage {
            items,
            next: page.next,
            previous: page.previous,
            revision: page.revision,
        })
    }

    /// Resume a direct listing after a previously returned item at this revision.
    /// Callers can keep an ID per ancestor instead of a text-bearing cursor per depth.
    pub fn list_resume(
        &self,
        group: GroupHandle,
        after: crate::ItemHandle,
        revision: u64,
    ) -> Result<ViewCursor, CoreError> {
        self.read(|ctx| {
            ctx.own(group.session)?;
            let id = match after {
                crate::ItemHandle::Group(g) => {
                    ctx.own(g.session)?;
                    g.record
                }
                crate::ItemHandle::Entry(e) => {
                    ctx.own(e.session)?;
                    e.record
                }
            };
            if ctx.open.vault.local_seq() != revision {
                return Err(CoreError::StaleHandle);
            }
            let scope = Scope::Children(group.record);
            let request = Request {
                requester: None,
                session: ctx.tag(),
                revision,
                scope,
                text: lower(ctx, "")?,
                kind: lower(ctx, "")?,
                fingerprint: fingerprint("", ""),
            };
            let after = key(ctx, &request, id)?.ok_or(CoreError::NotFound)?;
            Ok(ViewCursor(std::sync::Arc::new(CursorState {
                session: ctx.tag(),
                revision,
                scope,
                query: request.fingerprint,
                after: std::sync::Arc::new(after),
                direction: Direction::Forward,
            })))
        })
    }

    /// Current authenticated local revision, without decrypting display text.
    pub fn view_revision(&self) -> Result<u64, CoreError> {
        self.read(|ctx| Ok(ctx.open.vault.local_seq()))
    }

    /// Live entries per [`TYPE_BUCKETS`] entry, in that order; empty buckets are omitted.
    pub fn kinds_page(
        &self,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<KindSummary>, CoreError> {
        let page = self.page(Scope::Types, "", "", cursor, limit, cancel)?;
        let items = page
            .items
            .into_iter()
            .map(|r| match r {
                Row::Kind(v) => Ok(v),
                _ => Err(CoreError::Internal),
            })
            .collect::<Result<_, _>>()?;
        Ok(ViewPage {
            items,
            next: page.next,
            previous: page.previous,
            revision: page.revision,
        })
    }

    /// Group choices: direct children in group order, or all visible groups by name.
    pub fn groups_page(
        &self,
        parent: Option<GroupHandle>,
        query: &str,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<GroupSummary>, CoreError> {
        if let Some(parent) = parent {
            self.read(|ctx| ctx.own(parent.session))?;
        }
        let page = hits(self.page(
            Scope::Groups(parent.map(|g| g.record)),
            query,
            "",
            cursor,
            limit,
            cancel,
        )?)?;
        let items = page
            .items
            .into_iter()
            .map(|r| match r {
                SearchHit::Group(v) => Ok(v),
                _ => Err(CoreError::Internal),
            })
            .collect::<Result<_, _>>()?;
        Ok(ViewPage {
            items,
            next: page.next,
            previous: page.previous,
            revision: page.revision,
        })
    }

    /// Child-group choices followed by all descendant entries, as the app's group view.
    pub fn browse_items_page(
        &self,
        group: GroupHandle,
        query: &str,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<SearchHit>, CoreError> {
        self.read(|ctx| ctx.own(group.session))?;
        hits(self.page(
            Scope::GroupItems(group.record),
            query,
            "",
            cursor,
            limit,
            cancel,
        )?)
    }

    /// A complete bounded page of direct children, groups then entries.
    pub fn list_page(
        &self,
        group: GroupHandle,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<SearchHit>, CoreError> {
        self.read(|ctx| {
            ctx.own(group.session)?;
            if ctx.open.index.tree.parent(group.record).is_none() {
                return Err(CoreError::NotFound);
            }
            Ok(())
        })?;
        hits(self.page(Scope::Children(group.record), "", "", cursor, limit, cancel)?)
    }

    /// Search all live searchable metadata, independent of cache residency.
    pub fn search_page(
        &self,
        query: &str,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<SearchHit>, CoreError> {
        if query.is_empty() {
            return Err(CoreError::InvalidInput);
        }
        hits(self.page(Scope::Search, query, "", cursor, limit, cancel)?)
    }

    /// All live entries, by lowercase title and ID.
    pub fn all_items_page(
        &self,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<EntrySummary>, CoreError> {
        self.items_page(ItemFilter::default(), cursor, limit, cancel)
    }

    /// A scoped entry page, including descendants for a group filter.
    pub fn items_page(
        &self,
        filter: ItemFilter<'_>,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<EntrySummary>, CoreError> {
        if filter.group.is_some() && filter.recovered {
            return Err(CoreError::InvalidInput);
        }
        if let Some(group) = filter.group {
            self.read(|ctx| ctx.own(group.session))?;
        }
        entries(self.page(
            Scope::Items {
                group: filter.group.map(|g| g.record),
                recovered: filter.recovered,
                kind: filter.kind.is_some(),
                all_fields: filter.search_all_fields,
            },
            filter.text.unwrap_or(""),
            filter.kind.unwrap_or(""),
            cursor,
            limit,
            cancel,
        )?)
    }

    /// A bounded page of recovered entries.
    pub fn recovered_page(
        &self,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<EntrySummary>, CoreError> {
        self.items_page(
            ItemFilter {
                recovered: true,
                ..ItemFilter::default()
            },
            cursor,
            limit,
            cancel,
        )
    }

    /// A bounded page of trash, newest deletion first with ID tie breaks.
    pub fn trash_page(
        &self,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<TrashItem>, CoreError> {
        let page = self.page(Scope::Trash, "", "", cursor, limit, cancel)?;
        let items = page
            .items
            .into_iter()
            .map(|r| match r {
                Row::Trash(v) => Ok(v),
                _ => Err(CoreError::Internal),
            })
            .collect::<Result<_, _>>()?;
        Ok(ViewPage {
            items,
            next: page.next,
            previous: page.previous,
            revision: page.revision,
        })
    }

    /// All conflicting record kinds, with bounded optional display names.
    pub fn conflict_records_page(
        &self,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<crate::conflict::ConflictRecordSummary>, CoreError> {
        let page = self.page(Scope::AllConflicts, "", "", cursor, limit, cancel)?;
        let items = page
            .items
            .into_iter()
            .map(|r| match r {
                Row::AllConflict(v) => Ok(v),
                _ => Err(CoreError::Internal),
            })
            .collect::<Result<_, _>>()?;
        Ok(ViewPage {
            items,
            next: page.next,
            previous: page.previous,
            revision: page.revision,
        })
    }

    /// A bounded page of conflicting records, by record ID.
    pub fn conflicts_page(
        &self,
        cursor: Option<ViewCursor>,
        limit: PageLimit,
        cancel: &CancelToken,
    ) -> Result<ViewPage<ConflictSummary>, CoreError> {
        let page = self.page(Scope::Conflicts, "", "", cursor, limit, cancel)?;
        let items = page
            .items
            .into_iter()
            .map(|r| match r {
                Row::Conflict(v) => Ok(v),
                _ => Err(CoreError::Internal),
            })
            .collect::<Result<_, _>>()?;
        Ok(ViewPage {
            items,
            next: page.next,
            previous: page.previous,
            revision: page.revision,
        })
    }
}

fn hits(page: ViewPage<Row>) -> Result<ViewPage<SearchHit>, CoreError> {
    let items = page
        .items
        .into_iter()
        .map(|r| match r {
            Row::Hit(v) => Ok(v),
            _ => Err(CoreError::Internal),
        })
        .collect::<Result<_, _>>()?;
    Ok(ViewPage {
        items,
        next: page.next,
        previous: page.previous,
        revision: page.revision,
    })
}
fn entries(page: ViewPage<Row>) -> Result<ViewPage<EntrySummary>, CoreError> {
    let page = hits(page)?;
    let items = page
        .items
        .into_iter()
        .map(|r| match r {
            SearchHit::Entry(v) => Ok(v),
            _ => Err(CoreError::Internal),
        })
        .collect::<Result<_, _>>()?;
    Ok(ViewPage {
        items,
        next: page.next,
        previous: page.previous,
        revision: page.revision,
    })
}

#[cfg(test)]
#[path = "paging_tests.rs"]
mod tests;
