// SPDX-License-Identifier: AGPL-3.0-or-later

//! Drafts and mutations (spec 0005 §1.2, §2.3–2.6; 0007 §2; 0003 §2–5;
//! 0004 §5.2).
//!
//! Every mutation runs through [`commit`], which is the only caller of the
//! store's write path: it authorizes nothing itself, so each operation
//! checks first, while holding the session:
//!
//! 1. the handles are this session's, every touched record exists with the
//!    expected kind and is not finally deleted;
//! 2. the record has exactly one head ([`CoreError::Conflict`] otherwise:
//!    resolution is phase 2.2), and a draft's base is still that head
//!    ([`CoreError::StaleHandle`]);
//! 3. the operation's own rules (live target groups, no cycles, the root
//!    stays put, deletion only through the delete calls).
//!
//! [`commit`] then builds one causal version per record (the store's head
//! clocks joined and advanced with a reserved counter, 0005 §1.2), checks
//! the model rules and compact projection, stops if a lock was requested, and
//! commits all of them in one store transaction (0004 §5.2). Once the
//! commit is durable the index follows it, even if the anchor update then
//! failed (the store reports that error).
//!
//! Drafts hold a decrypted payload in the model's zeroizing types. They
//! keep the payload's and the record's unknown keys, so an edit preserves
//! them (0003 §2.2).

use std::collections::{BTreeMap, BTreeSet};

use qv_crypto::RecordId;
use qv_model::{
    Clock, Entry, Extensions, Field, FieldId, FieldKind, FieldValue, Group, Payload, RandomId,
    RecordBody, RecordKind, RecordVersion, Text, Timestamp, VersionId,
};

use crate::error::{CoreError, data, input};
use crate::index::{Data, Index, RecordInfo, ViewData};
use crate::order::key_after;
use crate::session::{Canceller, Ctx, EntryHandle, GroupHandle, ItemHandle, Session, SessionTag};
use crate::views::{decrypt, record};

/// One record's new version, before it has a clock.
pub(crate) struct Change {
    pub(crate) record: RecordId,
    pub(crate) kind: RecordKind,
    pub(crate) body: RecordBody,
    pub(crate) ext: Extensions,
}

fn rng<E>(_: E) -> CoreError {
    CoreError::Rng
}

/// Commits `changes` as one transaction and updates the index.
pub(crate) fn commit(ctx: &mut Ctx<'_>, changes: Vec<Change>) -> Result<(), CoreError> {
    if changes.is_empty() {
        return Ok(());
    }
    commit_with(ctx, |_| Ok(changes), &|| false)
}

/// Shared staging/causal transaction path, including post-durable index repair.
pub(crate) fn commit_with(
    ctx: &mut Ctx<'_>,
    build: impl FnOnce(&mut qv_store::Write<'_>) -> Result<Vec<Change>, CoreError>,
    cancelled: &impl Fn() -> bool,
) -> Result<(), CoreError> {
    let now = ctx.now();
    let cancel = ctx.canceller();
    let open = &mut *ctx.open;
    let seq = open.vault.local_seq();
    let mut w = open.vault.write()?;
    let changes = build(&mut w)?;
    let mut infos = Vec::with_capacity(changes.len());
    for ch in changes {
        infos.push(stage(&mut w, now, ch)?);
    }
    let committed = commit_staged(&open.index, w, &infos, cancel, cancelled)?;
    after_commit(ctx, seq, infos, committed, cancelled)
}

/// Commits one change per record of `ids` in one transaction (plan 0053):
/// each record is read, edited and staged before the next is read, so at
/// most one decoded record is held. `make` returns `None` to leave a record
/// unchanged; the write opens only at the first change, as [`commit`] opens
/// none for no changes. An error or cancellation at any record rolls back.
pub(crate) fn commit_each(
    ctx: &mut Ctx<'_>,
    ids: &[RecordId],
    mut make: impl FnMut(
        &Index,
        &dyn Fn(RecordId, VersionId) -> Result<RecordVersion, CoreError>,
        RecordId,
    ) -> Result<Option<Change>, CoreError>,
) -> Result<(), CoreError> {
    let now = ctx.now();
    let cancel = ctx.canceller();
    let open = &mut *ctx.open;
    let mut rest = ids.iter();
    let first = loop {
        let Some(&id) = rest.next() else {
            return Ok(());
        };
        cancel.check()?;
        #[cfg(test)]
        staging_event('r', id);
        let read = |r, v| open.vault.read_version(r, v).map_err(CoreError::from);
        if let Some(change) = make(&open.index, &read, id)? {
            break change;
        }
    };
    let seq = open.vault.local_seq();
    let mut w = open.vault.write()?;
    let mut infos = Vec::with_capacity(ids.len());
    infos.push(stage(&mut w, now, first)?);
    for &id in rest {
        cancel.check()?;
        #[cfg(test)]
        staging_event('r', id);
        let change = {
            let read = |r, v| w.read_base_version(r, v).map_err(CoreError::from);
            make(&open.index, &read, id)?
        };
        if let Some(change) = change {
            infos.push(stage(&mut w, now, change)?);
        }
    }
    let committed = commit_staged(&open.index, w, &infos, cancel, &|| false)?;
    after_commit(ctx, seq, infos, committed, &|| false)
}

/// Gives one change its clock and stages its sealed version; only its
/// compact index entry is kept.
fn stage(
    w: &mut qv_store::Write<'_>,
    now: Timestamp,
    ch: Change,
) -> Result<(RecordId, RecordInfo), CoreError> {
    let counter = w.reserve_counter()?;
    let heads = w.head_clocks(ch.record);
    let clock = Clock::for_edit(&heads, w.writer_id(), counter).map_err(data)?;
    let v = RecordVersion {
        version_id: VersionId::generate().map_err(rng)?,
        clock,
        modified_at: now,
        body: ch.body,
        ext: ch.ext,
    };
    // The model's encode rules apply to what the caller supplied; the
    // decoded copy is exactly what a later unlock will index.
    let encoded = v.encode().map_err(input)?;
    let copy = RecordVersion::decode(&encoded).map_err(data)?;
    let mut info = RecordInfo::from_heads(ch.kind, vec![copy])?;
    info.discard_view();
    w.put_local(ch.record, v)?;
    #[cfg(test)]
    staging_event('s', ch.record);
    Ok((ch.record, info))
}

#[cfg(test)]
thread_local! {
    /// Bulk-change reads ('r') and stages ('s') on this thread (plan 0053).
    static STAGING: std::cell::RefCell<Vec<(char, RecordId)>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
#[cfg(test)]
fn staging_event(kind: char, id: RecordId) {
    STAGING.with(|e| e.borrow_mut().push((kind, id)));
}

/// Index preflight, cancellation and the commit itself. Dropping `w` on an
/// error rolls the transaction back.
fn commit_staged(
    index: &Index,
    w: qv_store::Write<'_>,
    infos: &[(RecordId, RecordInfo)],
    cancel: Canceller<'_>,
    cancelled: &impl Fn() -> bool,
) -> Result<Result<(), qv_store::StoreError>, CoreError> {
    index.check(infos.iter().map(|(id, i)| (*id, i)))?;
    #[cfg(test)]
    crate::session::hooks::reached(crate::session::hooks::Point::BeforeCommit);
    cancel.check()?;
    if cancelled() {
        return Err(CoreError::Cancelled);
    }
    let committed = w.commit_cancellable(&|| cancel.check().is_err() || cancelled());
    #[cfg(test)]
    crate::session::hooks::reached(crate::session::hooks::Point::AfterCommit);
    Ok(committed)
}

/// Applies a commit's outcome: the index follows a durable commit even when
/// a later step (the anchor) failed.
fn after_commit(
    ctx: &mut Ctx<'_>,
    seq: u64,
    infos: Vec<(RecordId, RecordInfo)>,
    committed: Result<(), qv_store::StoreError>,
    cancelled: &impl Fn() -> bool,
) -> Result<(), CoreError> {
    let cancel = ctx.canceller();
    let open = &mut *ctx.open;
    if open.vault.local_seq() != seq {
        for (id, info) in infos {
            open.index.replace(id, info);
        }
        if open.index.retree().is_err() {
            ctx.poison = true;
            return Err(CoreError::Internal);
        }
    }
    if open.vault.local_seq() == seq && (cancel.check().is_err() || cancelled()) {
        return Err(CoreError::Cancelled);
    }
    Ok(committed?)
}

/// A record that may be edited: exists with `kind`, not finally deleted,
/// one head. Returns that head.
fn single(ctx: &Ctx<'_>, id: RecordId, kind: RecordKind) -> Result<VersionId, CoreError> {
    single_in(&ctx.open.index, id, kind)
}

fn single_in(index: &Index, id: RecordId, kind: RecordKind) -> Result<VersionId, CoreError> {
    record(index, id, kind)?.single_head()
}

/// Whether `g` is a group shown in the tree (live; the root included).
fn live_group(ctx: &Ctx<'_>, g: RecordId) -> bool {
    ctx.open.index.tree.parent(g).is_some()
        && ctx
            .open
            .index
            .get(g)
            .is_some_and(|r| r.kind == RecordKind::Group)
}

fn entry_of(v: RecordVersion) -> Result<(Entry, Extensions), CoreError> {
    match v.body {
        RecordBody::Live(Payload::Entry(e)) => Ok((e, v.ext)),
        _ => Err(CoreError::NotFound),
    }
}

fn group_of(v: RecordVersion) -> Result<(Group, Extensions), CoreError> {
    match v.body {
        RecordBody::Live(Payload::Group(g)) => Ok((g, v.ext)),
        _ => Err(CoreError::NotFound),
    }
}

fn text(s: &str) -> Result<Text, CoreError> {
    Text::new(s).map_err(input)
}

/// A new or edited entry: a decrypted, short-lived copy (0008 §1.2).
pub struct EntryDraft {
    session: SessionTag,
    record: RecordId,
    base: Option<VersionId>,
    base_group: RecordId,
    base_created: Timestamp,
    base_deleted: Option<Timestamp>,
    entry: Entry,
    ext: Extensions,
}

impl core::fmt::Debug for EntryDraft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("EntryDraft(<redacted>)")
    }
}

impl EntryDraft {
    /// The entry's record ID as 32 lowercase hex digits, also for a new entry
    /// not saved yet. IDs are metadata, not secrets.
    pub fn id_hex(&self) -> String {
        crate::setup::hex(&self.record.0)
    }

    /// The entry being edited.
    pub fn entry(&self) -> &Entry {
        &self.entry
    }

    /// The entry, to change. `created_at` and `deleted_at` must stay as
    /// they are ([`CoreError::NotAllowed`] on save); a new `group` must be
    /// a live group (a move); `modified_at` is set on save.
    pub fn entry_mut(&mut self) -> &mut Entry {
        &mut self.entry
    }

    /// The entry's group as a handle of this session.
    pub fn group(&self) -> GroupHandle {
        GroupHandle {
            session: self.session,
            record: self.entry.group,
        }
    }

    /// Places the entry in `group` on save (a move for a saved entry; save
    /// checks that the group is live). A handle from another session is
    /// refused with [`CoreError::StaleHandle`].
    pub fn set_group(&mut self, group: GroupHandle) -> Result<(), CoreError> {
        if group.session != self.session {
            return Err(CoreError::StaleHandle);
        }
        self.entry.group = group.record;
        Ok(())
    }

    /// Appends a field with a new ID, protected by default for `secret`
    /// and `totp` fields (0003 §5.3).
    pub fn add_field(
        &mut self,
        name: &str,
        kind: FieldKind,
        value: FieldValue,
    ) -> Result<FieldId, CoreError> {
        let id = FieldId::generate().map_err(rng)?;
        self.entry.fields.push(Field {
            id,
            name: text(name)?,
            kind,
            value,
            protected: kind.protected_by_default(),
            ext: Extensions::new(),
        });
        Ok(id)
    }
}

/// A new or edited group.
pub struct GroupDraft {
    session: SessionTag,
    record: RecordId,
    base: Option<VersionId>,
    base_parent: Option<RecordId>,
    base_deleted: Option<Timestamp>,
    group: Group,
    ext: Extensions,
}

impl core::fmt::Debug for GroupDraft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("GroupDraft(<redacted>)")
    }
}

impl GroupDraft {
    /// The group's record ID as 32 lowercase hex digits, also for a new
    /// group not saved yet. IDs are metadata, not secrets.
    pub fn id_hex(&self) -> String {
        crate::setup::hex(&self.record.0)
    }

    /// The group being edited.
    pub fn group(&self) -> &Group {
        &self.group
    }

    /// The group, to change. `deleted_at` must stay as it is; a new
    /// `parent` must be a live group outside this group's subtree (a move);
    /// the root's parent stays `None`.
    pub fn group_mut(&mut self) -> &mut Group {
        &mut self.group
    }
}

fn unique_fields(e: &Entry) -> Result<(), CoreError> {
    let ids: BTreeSet<FieldId> = e.fields.iter().map(|f| f.id).collect();
    if ids.len() == e.fields.len() {
        Ok(())
    } else {
        Err(CoreError::InvalidInput)
    }
}

/// The draft's base must still be the record's only head.
fn check_base(
    ctx: &Ctx<'_>,
    id: RecordId,
    kind: RecordKind,
    base: Option<VersionId>,
) -> Result<(), CoreError> {
    match base {
        Some(b) => {
            if single(ctx, id, kind)? != b {
                return Err(CoreError::StaleHandle);
            }
            Ok(())
        }
        None if ctx.open.index.get(id).is_some() => Err(CoreError::StaleHandle),
        None => Ok(()),
    }
}

/// Whether `target` is `group` or displayed below it.
fn in_subtree(ctx: &Ctx<'_>, group: RecordId, target: RecordId) -> bool {
    let tree = &ctx.open.index.tree;
    let mut cur = Some(target);
    for _ in 0..=tree.len() {
        match cur {
            Some(c) if c == group => return true,
            Some(c) => cur = tree.parent(c).flatten(),
            None => return false,
        }
    }
    // A loop in the projected tree cannot happen; refuse rather than guess.
    true
}

fn entry_change(record: RecordId, e: Entry, ext: Extensions) -> Change {
    Change {
        record,
        kind: RecordKind::Entry,
        body: RecordBody::Live(Payload::Entry(e)),
        ext,
    }
}

fn group_change(record: RecordId, g: Group, ext: Extensions) -> Change {
    Change {
        record,
        kind: RecordKind::Group,
        body: RecordBody::Live(Payload::Group(g)),
        ext,
    }
}

fn load_entry(ctx: &Ctx<'_>, id: RecordId) -> Result<(VersionId, Entry, Extensions), CoreError> {
    let v = single(ctx, id, RecordKind::Entry)?;
    let (e, ext) = entry_of(decrypt(ctx, id, v)?)?;
    Ok((v, e, ext))
}

fn load_group(ctx: &Ctx<'_>, id: RecordId) -> Result<(VersionId, Group, Extensions), CoreError> {
    let v = single(ctx, id, RecordKind::Group)?;
    let (g, ext) = group_of(decrypt(ctx, id, v)?)?;
    Ok((v, g, ext))
}

fn save_entry_in(ctx: &mut Ctx<'_>, d: EntryDraft) -> Result<EntryHandle, CoreError> {
    ctx.own(d.session)?;
    check_base(ctx, d.record, RecordKind::Entry, d.base)?;
    let mut e = d.entry;
    if e.created_at != d.base_created
        || e.deleted_at != d.base_deleted
        || e.delete_operation.is_some()
    {
        return Err(CoreError::NotAllowed);
    }
    if (e.group != d.base_group || d.base.is_none()) && !live_group(ctx, e.group) {
        return Err(CoreError::NotAllowed);
    }
    unique_fields(&e)?;
    e.modified_at = ctx.now();
    commit(ctx, vec![entry_change(d.record, e, d.ext)])?;
    Ok(ctx.entry_handle(d.record))
}

fn save_group_in(ctx: &mut Ctx<'_>, d: GroupDraft) -> Result<GroupHandle, CoreError> {
    ctx.own(d.session)?;
    check_base(ctx, d.record, RecordKind::Group, d.base)?;
    let g = d.group;
    if g.deleted_at != d.base_deleted || g.delete_operation.is_some() {
        return Err(CoreError::NotAllowed);
    }
    if d.record == ctx.open.index.root {
        if g.parent.is_some() {
            return Err(CoreError::NotAllowed);
        }
    } else if g.parent != d.base_parent || d.base.is_none() {
        let Some(p) = g.parent else {
            return Err(CoreError::NotAllowed);
        };
        if !live_group(ctx, p) || in_subtree(ctx, d.record, p) {
            return Err(CoreError::NotAllowed);
        }
    }
    commit(ctx, vec![group_change(d.record, g, d.ext)])?;
    Ok(ctx.group_handle(d.record))
}

/// The live groups displayed under `group` (itself included) and the live
/// entries placed in them.
fn subtree(ctx: &Ctx<'_>, group: RecordId) -> (Vec<RecordId>, Vec<RecordId>) {
    let index = &ctx.open.index;
    let mut groups = vec![group];
    let mut i = 0;
    while let Some(&g) = groups.get(i) {
        groups.extend(index.tree.children(g));
        i += 1;
    }
    let set: BTreeSet<RecordId> = groups.iter().copied().collect();
    let entries = index
        .records
        .iter()
        .filter_map(|(id, r)| match (&r.data, r.status.live) {
            (Data::Entry(e), true) => match index.tree.place_entry(e.group) {
                qv_model::EntryPlace::Group(g) if set.contains(&g) => Some(*id),
                _ => None,
            },
            _ => None,
        })
        .collect();
    (groups, entries)
}

/// Soft-deletes (`Some(now)`) or restores (`None`) the given records.
fn set_deleted(
    ctx: &mut Ctx<'_>,
    groups: &[RecordId],
    entries: &[RecordId],
    deleted_at: Option<Timestamp>,
) -> Result<(), CoreError> {
    let operation = deleted_at
        .map(|_| qv_model::DeleteOperationId::generate().map_err(rng))
        .transpose()?;
    // Compact preflight: every record is editable before anything is read.
    for &id in groups {
        single(ctx, id, RecordKind::Group)?;
    }
    for &id in entries {
        single(ctx, id, RecordKind::Entry)?;
    }
    let ids: Vec<RecordId> = groups.iter().chain(entries).copied().collect();
    let first_entry = groups.len();
    let mut n = 0;
    commit_each(ctx, &ids, |index, read, id| {
        let change = if n < first_entry {
            let (mut g, ext) = group_of(read(id, single_in(index, id, RecordKind::Group)?)?)?;
            g.deleted_at = deleted_at;
            g.delete_operation = operation;
            group_change(id, g, ext)
        } else {
            let (mut e, ext) = entry_of(read(id, single_in(index, id, RecordKind::Entry)?)?)?;
            e.deleted_at = deleted_at;
            e.delete_operation = operation;
            entry_change(id, e, ext)
        };
        n += 1;
        Ok(Some(change))
    })
}

/// The most handles one batch call accepts (plan 0044).
pub const MAX_BATCH: usize = 4096;

/// Distinct live entries of this session, checked before any write.
fn live_entries(ctx: &Ctx<'_>, entries: &[EntryHandle]) -> Result<Vec<RecordId>, CoreError> {
    if entries.len() > MAX_BATCH {
        return Err(CoreError::LimitExceeded);
    }
    let mut ids = BTreeSet::new();
    for h in entries {
        ctx.own(h.session)?;
        if !record(&ctx.open.index, h.record, RecordKind::Entry)?
            .status
            .live
        {
            return Err(CoreError::NotAllowed);
        }
        ids.insert(h.record);
    }
    Ok(ids.into_iter().collect())
}

/// Applies `edit` to each live entry and commits the changed ones together.
fn edit_entries(
    ctx: &mut Ctx<'_>,
    entries: &[EntryHandle],
    edit: impl Fn(&mut Entry) -> bool,
) -> Result<(), CoreError> {
    let ids = live_entries(ctx, entries)?;
    for &id in &ids {
        single(ctx, id, RecordKind::Entry)?;
    }
    let now = ctx.now();
    commit_each(ctx, &ids, |index, read, id| {
        let (mut e, ext) = entry_of(read(id, single_in(index, id, RecordKind::Entry)?)?)?;
        if e.deleted_at.is_some() {
            return Err(CoreError::NotAllowed);
        }
        Ok(edit(&mut e).then(|| {
            e.modified_at = now;
            entry_change(id, e, ext)
        }))
    })
}

fn trashed_info(ctx: &Ctx<'_>, item: ItemHandle) -> Result<(RecordId, RecordKind), CoreError> {
    ctx.own(item.tag())?;
    let (id, kind) = match item {
        ItemHandle::Entry(h) => (h.record, RecordKind::Entry),
        ItemHandle::Group(h) => (h.record, RecordKind::Group),
    };
    let r = record(&ctx.open.index, id, kind)?;
    if !r.status.in_trash {
        return Err(CoreError::NotAllowed);
    }
    r.single_head()?;
    Ok((id, kind))
}

fn delete_operation_of(r: &RecordInfo) -> Option<qv_model::DeleteOperationId> {
    match &r.data {
        Data::Entry(e) => e.delete_operation,
        Data::Group(g) => g.delete_operation,
        _ => None,
    }
}

/// Trashed records from the same explicit deletion, connected by source parents.
fn deleted_with(
    ctx: &Ctx<'_>,
    g: RecordId,
    operation: qv_model::DeleteOperationId,
) -> (Vec<RecordId>, Vec<RecordId>) {
    let index = &ctx.open.index;
    let same = |r: &RecordInfo| {
        r.status.in_trash && !r.status.conflict && delete_operation_of(r) == Some(operation)
    };
    let mut children: BTreeMap<RecordId, Vec<RecordId>> = BTreeMap::new();
    let mut entries_of: BTreeMap<RecordId, Vec<RecordId>> = BTreeMap::new();
    for (id, r) in &index.records {
        if !same(r) {
            continue;
        }
        match &r.data {
            Data::Group(x) => {
                if let Some(p) = x.parent {
                    children.entry(p).or_default().push(*id);
                }
            }
            Data::Entry(e) => entries_of.entry(e.group).or_default().push(*id),
            _ => {}
        }
    }
    let mut groups = vec![g];
    let mut seen: BTreeSet<RecordId> = BTreeSet::from([g]);
    let mut i = 0;
    while let Some(&cur) = groups.get(i) {
        for &c in children.get(&cur).into_iter().flatten() {
            if seen.insert(c) {
                groups.push(c);
            }
        }
        i += 1;
    }
    let entries = groups
        .iter()
        .flat_map(|x| entries_of.get(x).into_iter().flatten().copied())
        .collect();
    (groups, entries)
}

/// Final deletion of trashed records and the attachments their entries
/// own (0007 §2.2).
fn purge_in(ctx: &mut Ctx<'_>, items: &[(RecordId, RecordKind)]) -> Result<(), CoreError> {
    if !items.is_empty() {
        if ctx.open.read_only {
            return Err(qv_store::StoreError::NoAnchor.into());
        }
        crate::snapshot::require_recovery(ctx)?;
    }
    let index = &ctx.open.index;
    let entries: BTreeSet<RecordId> = items
        .iter()
        .filter(|(_, k)| *k == RecordKind::Entry)
        .map(|(id, _)| *id)
        .collect();
    let mut targets: BTreeMap<RecordId, RecordKind> = items.iter().copied().collect();
    for (id, r) in &index.records {
        if let Data::Attachment { entry } = &r.data
            && entries.contains(entry)
            && !r.status.finally_deleted
        {
            r.single_head()?;
            targets.insert(*id, RecordKind::AttachmentMeta);
        }
    }
    let changes = targets
        .into_iter()
        .map(|(record, kind)| Change {
            record,
            kind,
            body: RecordBody::Tombstone(kind),
            // A minimal tombstone (0007 §2.2): no unknown keys either.
            ext: Extensions::new(),
        })
        .collect();
    commit(ctx, changes)
}

/// What [`Session::empty_trash`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PurgeReport {
    /// Items finally deleted.
    pub purged: usize,
    /// Conflicted items left in the trash (they need a resolution first).
    pub skipped_conflicts: usize,
}

impl Session {
    /// A draft for a new entry in a live group.
    pub fn new_entry(
        &self,
        group: GroupHandle,
        type_hint: &str,
        title: &str,
    ) -> Result<EntryDraft, CoreError> {
        self.read(|ctx| {
            ctx.own(group.session)?;
            if !live_group(ctx, group.record) {
                return Err(CoreError::NotFound);
            }
            let now = ctx.now();
            Ok(EntryDraft {
                session: ctx.tag(),
                record: RecordId::generate().map_err(rng)?,
                base: None,
                base_group: group.record,
                base_created: now,
                base_deleted: None,
                entry: Entry {
                    group: group.record,
                    type_hint: text(type_hint)?,
                    title: text(title)?,
                    fields: Vec::new(),
                    notes: None,
                    icon: None,
                    expires_at: None,
                    created_at: now,
                    modified_at: now,
                    deleted_at: None,
                    delete_operation: None,
                    ext: Extensions::new(),
                },
                ext: Extensions::new(),
            })
        })
    }

    /// A draft of a live entry's current version, protected values included.
    pub fn edit_entry(&self, entry: EntryHandle) -> Result<EntryDraft, CoreError> {
        self.read(|ctx| {
            ctx.own(entry.session)?;
            let (v, e, ext) = load_entry(ctx, entry.record)?;
            if e.deleted_at.is_some() {
                return Err(CoreError::NotAllowed);
            }
            Ok(EntryDraft {
                session: ctx.tag(),
                record: entry.record,
                base: Some(v),
                base_group: e.group,
                base_created: e.created_at,
                base_deleted: e.deleted_at,
                entry: e,
                ext,
            })
        })
    }

    /// Saves an entry draft as a new causal version.
    pub fn save_entry(&self, draft: EntryDraft) -> Result<EntryHandle, CoreError> {
        self.mutate(|ctx| save_entry_in(ctx, draft))
    }

    /// A draft for a new group, ordered after its siblings.
    pub fn new_group(&self, parent: GroupHandle, name: &str) -> Result<GroupDraft, CoreError> {
        self.read(|ctx| {
            ctx.own(parent.session)?;
            if !live_group(ctx, parent.record) {
                return Err(CoreError::NotFound);
            }
            let index = &ctx.open.index;
            let mut last = zeroize::Zeroizing::new(String::new());
            for id in index.tree.children(parent.record) {
                let view = ctx.view(id)?;
                if let ViewData::Group(g) = &**view
                    && g.order.expose() > last.as_str()
                {
                    last = zeroize::Zeroizing::new(g.order.expose().to_owned());
                }
            }
            Ok(GroupDraft {
                session: ctx.tag(),
                record: RecordId::generate().map_err(rng)?,
                base: None,
                base_parent: Some(parent.record),
                base_deleted: None,
                group: Group {
                    parent: Some(parent.record),
                    name: text(name)?,
                    notes: None,
                    icon: None,
                    order: text(&key_after(&last))?,
                    deleted_at: None,
                    delete_operation: None,
                    ext: Extensions::new(),
                },
                ext: Extensions::new(),
            })
        })
    }

    /// A draft of a live group's current version.
    pub fn edit_group(&self, group: GroupHandle) -> Result<GroupDraft, CoreError> {
        self.read(|ctx| {
            ctx.own(group.session)?;
            let (v, g, ext) = load_group(ctx, group.record)?;
            if g.deleted_at.is_some() {
                return Err(CoreError::NotAllowed);
            }
            Ok(GroupDraft {
                session: ctx.tag(),
                record: group.record,
                base: Some(v),
                base_parent: g.parent,
                base_deleted: g.deleted_at,
                group: g,
                ext,
            })
        })
    }

    /// Saves a group draft as a new causal version.
    pub fn save_group(&self, draft: GroupDraft) -> Result<GroupHandle, CoreError> {
        self.mutate(|ctx| save_group_in(ctx, draft))
    }

    /// Moves a live entry or group into a live group.
    pub fn move_item(&self, item: ItemHandle, to: GroupHandle) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            ctx.own(item.tag())?;
            ctx.own(to.session)?;
            match item {
                ItemHandle::Entry(h) => {
                    let (v, mut e, ext) = load_entry(ctx, h.record)?;
                    if e.deleted_at.is_some() {
                        return Err(CoreError::NotAllowed);
                    }
                    let d = EntryDraft {
                        session: ctx.tag(),
                        record: h.record,
                        base: Some(v),
                        base_group: e.group,
                        base_created: e.created_at,
                        base_deleted: None,
                        entry: {
                            e.group = to.record;
                            e
                        },
                        ext,
                    };
                    save_entry_in(ctx, d).map(|_| ())
                }
                ItemHandle::Group(h) => {
                    let (v, mut g, ext) = load_group(ctx, h.record)?;
                    if g.deleted_at.is_some() {
                        return Err(CoreError::NotAllowed);
                    }
                    let d = GroupDraft {
                        session: ctx.tag(),
                        record: h.record,
                        base: Some(v),
                        base_parent: g.parent,
                        base_deleted: None,
                        group: {
                            g.parent = Some(to.record);
                            g
                        },
                        ext,
                    };
                    save_group_in(ctx, d).map(|_| ())
                }
            }
        })
    }

    /// Moves a live entry, or a group with everything shown under it, to
    /// the trash in one transaction (0007 §2.1). A group with contents
    /// needs `recursive` ([`CoreError::NotEmpty`]); the root cannot be
    /// deleted.
    pub fn delete(&self, item: ItemHandle, recursive: bool) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            ctx.own(item.tag())?;
            let now = ctx.now();
            match item {
                ItemHandle::Entry(h) => {
                    let r = record(&ctx.open.index, h.record, RecordKind::Entry)?;
                    if !r.status.live {
                        return Err(CoreError::NotAllowed);
                    }
                    set_deleted(ctx, &[], &[h.record], Some(now))
                }
                ItemHandle::Group(h) => {
                    if h.record == ctx.open.index.root {
                        return Err(CoreError::NotAllowed);
                    }
                    record(&ctx.open.index, h.record, RecordKind::Group)?;
                    if !live_group(ctx, h.record) {
                        return Err(CoreError::NotAllowed);
                    }
                    let (groups, entries) = subtree(ctx, h.record);
                    if !recursive && (groups.len() > 1 || !entries.is_empty()) {
                        return Err(CoreError::NotEmpty);
                    }
                    set_deleted(ctx, &groups, &entries, Some(now))
                }
            }
        })
    }

    /// Restores a trashed entry, or a trashed group together with what was
    /// deleted with it. A restored entry whose group is gone appears under
    /// recovered items (0003 §4.2).
    pub fn restore(&self, item: ItemHandle) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            let (id, kind) = trashed_info(ctx, item)?;
            if kind == RecordKind::Entry {
                return set_deleted(ctx, &[], &[id], None);
            }
            let Some(operation) = ctx.open.index.get(id).and_then(delete_operation_of) else {
                // Missing legacy identity never groups independent deletions by time.
                return set_deleted(ctx, &[id], &[], None);
            };
            let (groups, entries) = deleted_with(ctx, id, operation);
            set_deleted(ctx, &groups, &entries, None)
        })
    }

    /// Moves live entries to the trash in one transaction (plan 0044). Every
    /// handle is checked before anything is written; one that is foreign,
    /// not an entry or not live fails the whole call. At most
    /// [`MAX_BATCH`] handles ([`CoreError::LimitExceeded`]); none is a no-op.
    pub fn delete_entries(&self, entries: &[EntryHandle]) -> Result<(), CoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.mutate(|ctx| {
            let ids = live_entries(ctx, entries)?;
            let now = ctx.now();
            set_deleted(ctx, &[], &ids, Some(now))
        })
    }

    /// Restores trashed entries in one transaction (the batch Undo); the
    /// same all-or-nothing checks as [`Session::delete_entries`].
    pub fn restore_entries(&self, entries: &[EntryHandle]) -> Result<(), CoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        if entries.len() > MAX_BATCH {
            return Err(CoreError::LimitExceeded);
        }
        self.mutate(|ctx| {
            let mut ids = BTreeSet::new();
            for &h in entries {
                ids.insert(trashed_info(ctx, ItemHandle::Entry(h))?.0);
            }
            let ids: Vec<RecordId> = ids.into_iter().collect();
            set_deleted(ctx, &[], &ids, None)
        })
    }

    /// Moves live entries into a live group: one new version per entry that
    /// is elsewhere, all in one transaction.
    pub fn move_entries(&self, entries: &[EntryHandle], to: GroupHandle) -> Result<(), CoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        self.mutate(|ctx| {
            ctx.own(to.session)?;
            if !live_group(ctx, to.record) {
                return Err(CoreError::NotAllowed);
            }
            edit_entries(ctx, entries, |e| {
                let changed = e.group != to.record;
                e.group = to.record;
                changed
            })
        })
    }

    /// Sets (`Some`) or clears (`None`) the icon of live entries, the colour
    /// token of 0003 §5.5, in one transaction; entries that already hold it
    /// get no new version.
    pub fn set_entry_icons(
        &self,
        entries: &[EntryHandle],
        icon: Option<&str>,
    ) -> Result<(), CoreError> {
        if entries.is_empty() {
            return Ok(());
        }
        if let Some(i) = icon {
            Text::new(i).map_err(input)?;
        }
        self.mutate(|ctx| {
            edit_entries(ctx, entries, |e| {
                if e.icon.as_ref().map(Text::expose) == icon {
                    return false;
                }
                // Validated above; a failure leaves the entry unchanged.
                match icon.map(Text::new).transpose() {
                    Ok(next) => {
                        e.icon = next;
                        true
                    }
                    Err(_) => false,
                }
            })
        })
    }

    /// Finally deletes trashed items (0007 §2.2): each becomes a permanent
    /// tombstone, its history is dropped, and an entry's attachments are
    /// tombstoned too, all in one transaction. Every item must be in the
    /// trash ([`CoreError::NotAllowed`]) and free of conflicts
    /// ([`CoreError::Conflict`]). Frontends confirm before calling this.
    pub fn purge(&self, items: &[ItemHandle]) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            let mut targets = BTreeMap::new();
            for &item in items {
                let (id, kind) = trashed_info(ctx, item)?;
                targets.insert(id, kind);
            }
            let list: Vec<(RecordId, RecordKind)> = targets.into_iter().collect();
            purge_in(ctx, &list)
        })
    }

    /// Finally deletes every non-conflicted item in the trash. Conflicted
    /// items stay and are counted (0005 §2.5).
    ///
    /// This is only the vault half of the destructive operation: the caller
    /// must write and pin its recovery snapshot with
    /// [`Session::begin_destructive`] first and reclassify it with
    /// [`Session::finish_destructive`] after this returns (0007 §3.2; the CLI
    /// provides that flow). Core enforces a verified copy of the exact current
    /// state before destroying data. Soft deletes take no snapshot.
    pub fn empty_trash(&self) -> Result<PurgeReport, CoreError> {
        self.mutate(|ctx| {
            let mut list = Vec::new();
            let mut skipped = 0;
            for (id, r) in &ctx.open.index.records {
                if !r.status.in_trash || !matches!(r.kind, RecordKind::Entry | RecordKind::Group) {
                    continue;
                }
                if r.status.conflict {
                    skipped += 1;
                } else {
                    list.push((*id, r.kind));
                }
            }
            let purged = list.len();
            purge_in(ctx, &list)?;
            Ok(PurgeReport {
                purged,
                skipped_conflicts: skipped,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use qv_crypto::{GeneratorSettings, PinSettings};
    use qv_encoding::{Decoder, Kind};
    use qv_model::{Causality, Clock, FieldKind, FieldValue, GeneratorDefaults, WriterId};

    use super::*;
    use crate::testutil::{Env, add_entry, add_group, err, seq};

    fn head_clock(s: &Session, id: RecordId) -> (Clock, WriterId) {
        s.read(|ctx| {
            let m = ctx.open.vault.manifest();
            let h = &m.record(id).unwrap().heads()[0];
            Ok((h.clock().clone(), ctx.open.vault.writer_id()))
        })
        .unwrap()
    }

    fn names(s: &Session, g: GroupHandle) -> (Vec<String>, Vec<String>) {
        let l = s.list(g).unwrap();
        (
            l.groups
                .iter()
                .map(|x| x.name.expose().to_owned())
                .collect(),
            l.entries
                .iter()
                .map(|x| x.title.expose().to_owned())
                .collect(),
        )
    }

    #[test]
    fn edit_create_edit_move_and_reopen() {
        let env = Env::new();
        let (a, b, e);
        {
            let s = env.unlock();
            let root = s.root().unwrap();
            a = add_group(&s, root, "A").record;
            b = add_group(&s, root, "B").record;
            let ga = s.read(|ctx| Ok(ctx.group_handle(a))).unwrap();
            let gb = s.read(|ctx| Ok(ctx.group_handle(b))).unwrap();
            let eh = add_entry(&s, ga, "Mail");
            e = eh.record;
            let (before, writer) = head_clock(&s, e);
            let mut d = s.edit_entry(eh).unwrap();
            d.entry_mut().title = Text::new("Mail (work)").unwrap();
            s.save_entry(d).unwrap();
            let (after, _) = head_clock(&s, e);
            assert_eq!(after.compare(&before), Causality::After);
            assert_eq!(after.get(writer), before.get(writer) + 1);
            s.move_item(ItemHandle::Entry(eh), gb).unwrap();
            s.move_item(ItemHandle::Group(gb), ga).unwrap();
            let mut gd = s.edit_group(ga).unwrap();
            gd.group_mut().name = Text::new("Alpha").unwrap();
            s.save_group(gd).unwrap();
            assert_eq!(names(&s, root), (vec!["Alpha".into()], vec![]));
            assert_eq!(names(&s, ga), (vec!["B".into()], vec![]));
            assert_eq!(names(&s, gb), (vec![], vec!["Mail (work)".into()]));
            assert_eq!(seq(&s), 8);
        }
        let s = env.unlock();
        let root = s.root().unwrap();
        let (ga, gb) = s
            .read(|ctx| Ok((ctx.group_handle(a), ctx.group_handle(b))))
            .unwrap();
        assert_eq!(names(&s, root), (vec!["Alpha".into()], vec![]));
        assert_eq!(names(&s, ga), (vec!["B".into()], vec![]));
        assert_eq!(names(&s, gb), (vec![], vec!["Mail (work)".into()]));
        let detail = s
            .entry(s.read(|ctx| Ok(ctx.entry_handle(e))).unwrap())
            .unwrap();
        assert_eq!(detail.fields.len(), 4);
        assert_eq!(detail.notes.unwrap().expose(), "xyzzy notes");
    }

    fn head(out: &mut Vec<u8>, major: u8, n: u64) {
        let m = major << 5;
        match n {
            0..=23 => out.push(m | n as u8),
            24..=0xff => out.extend([m | 24, n as u8]),
            _ => {
                out.push(m | 25);
                out.extend((n as u16).to_be_bytes());
            }
        }
    }

    /// Copies one CBOR item, adding the unknown entry `100: "x"` to every
    /// map (canonical: `0x18 0x64` sorts after every one-byte key).
    fn add_unknown(d: &mut Decoder<'_>, out: &mut Vec<u8>) {
        match d.peek_kind().unwrap() {
            Kind::Map => {
                let n = d.map().unwrap();
                head(out, 5, n + 1);
                for _ in 0..n {
                    let k = d.int().unwrap();
                    assert!((0..24).contains(&k));
                    out.push(k as u8);
                    add_unknown(d, out);
                }
                out.extend([0x18, 100, 0x61, b'x']);
            }
            Kind::Array => {
                let n = d.array().unwrap();
                head(out, 4, n);
                for _ in 0..n {
                    add_unknown(d, out);
                }
            }
            _ => out.extend_from_slice(d.raw_item().unwrap()),
        }
    }

    fn ext_counts(v: &RecordVersion) -> (usize, usize, Vec<usize>) {
        match &v.body {
            RecordBody::Live(Payload::Entry(e)) => (
                v.ext.len(),
                e.ext.len(),
                e.fields.iter().map(|f| f.ext.len()).collect(),
            ),
            _ => panic!("not an entry"),
        }
    }

    #[test]
    fn draft_group_moves_on_save_and_refuses_foreign_handles() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let a = add_group(&s, root, "A");
        let b = add_group(&s, root, "B");
        let e = add_entry(&s, a, "Mail");
        let mut d = s.edit_entry(e).unwrap();
        assert_eq!(d.group(), a);
        let other = Env::new();
        let foreign = other.unlock().root().unwrap();
        assert_eq!(d.set_group(foreign), Err(CoreError::StaleHandle));
        assert_eq!(d.group(), a);
        d.set_group(b).unwrap();
        s.save_entry(d).unwrap();
        assert_eq!(names(&s, a), (vec![], vec![]));
        assert_eq!(names(&s, b), (vec![], vec!["Mail".into()]));

        // A new entry is created in the chosen group; a deleted one is refused.
        let mut n = s.new_entry(a, "login", "Bank").unwrap();
        n.set_group(b).unwrap();
        s.save_entry(n).unwrap();
        assert_eq!(names(&s, b).1, vec!["Bank".to_owned(), "Mail".to_owned()]);
        s.delete(ItemHandle::Group(a), false).unwrap();
        let before = seq(&s);
        let mut n = s.new_entry(b, "login", "Lost").unwrap();
        n.set_group(a).unwrap();
        assert_eq!(err(s.save_entry(n)), CoreError::NotAllowed);
        assert_eq!(seq(&s), before);
    }

    #[test]
    fn edit_keeps_unknown_keys() {
        let env = Env::new();
        let id = RecordId::generate().unwrap();
        {
            // An entry from a newer client, written below the core.
            let s = env.unlock();
            let root = s.root().unwrap().record;
            s.mutate(|ctx| {
                let mut w = ctx.open.vault.write()?;
                let c = w.reserve_counter()?;
                let clock = Clock::from_pairs(vec![(w.writer_id(), c)]).unwrap();
                let mut e =
                    crate::index::tests::version(&[], RecordBody::Tombstone(RecordKind::Entry));
                e.clock = clock;
                e.body = crate::index::tests::entry(root, "Newer", false);
                let bytes = e.encode().unwrap();
                let mut crafted = Vec::new();
                add_unknown(&mut Decoder::new(&bytes).unwrap(), &mut crafted);
                let v = RecordVersion::decode(&crafted).unwrap();
                assert_eq!(ext_counts(&v), (1, 1, vec![1; 5]));
                w.put_local(id, v)?;
                Ok(w.commit()?)
            })
            .unwrap();
        }
        let s = env.unlock();
        let h = s.read(|ctx| Ok(ctx.entry_handle(id))).unwrap();
        let mut d = s.edit_entry(h).unwrap();
        d.entry_mut().title = Text::new("Edited").unwrap();
        d.add_field("New", FieldKind::Text, FieldValue::text("v").unwrap())
            .unwrap();
        s.save_entry(d).unwrap();
        let v = s
            .read(|ctx| {
                let r = ctx.open.index.get(id).unwrap();
                decrypt(ctx, id, r.heads[0])
            })
            .unwrap();
        assert_eq!(ext_counts(&v), (1, 1, vec![1, 1, 1, 1, 1, 0]));
    }

    #[test]
    fn edit_refusals_change_nothing() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let a = add_group(&s, root, "A");
        let b = add_group(&s, a, "B");
        let t = add_group(&s, root, "Trash me");
        s.delete(ItemHandle::Group(t), false).unwrap();
        let e = add_entry(&s, a, "Mail");

        // A stale draft.
        let d1 = s.edit_entry(e).unwrap();
        let d2 = s.edit_entry(e).unwrap();
        s.save_entry(d1).unwrap();
        let before = seq(&s);
        assert_eq!(err(s.save_entry(d2)), CoreError::StaleHandle);
        assert_eq!(seq(&s), before);
        let refused = |r: Result<(), CoreError>, want: CoreError| {
            assert_eq!(r, Err(want));
            assert_eq!(seq(&s), before);
        };

        // Fields a draft may not change.
        let mut d = s.edit_entry(e).unwrap();
        d.entry_mut().created_at = Timestamp(3);
        refused(s.save_entry(d).map(|_| ()), CoreError::NotAllowed);
        let mut d = s.edit_entry(e).unwrap();
        d.entry_mut().deleted_at = Some(Timestamp(3));
        refused(s.save_entry(d).map(|_| ()), CoreError::NotAllowed);
        let mut d = s.edit_group(a).unwrap();
        d.group_mut().deleted_at = Some(Timestamp(3));
        refused(s.save_group(d).map(|_| ()), CoreError::NotAllowed);
        let mut d = s.edit_settings().unwrap();
        d.meta_mut().root_group = RecordId::generate().unwrap();
        refused(s.save_settings(d), CoreError::NotAllowed);
        // Duplicate field IDs, a 257 KiB title, too many fields.
        let mut d = s.edit_entry(e).unwrap();
        let dup = d.entry().fields[0].id;
        d.entry_mut().fields.push(Field {
            id: dup,
            name: Text::new("dup").unwrap(),
            kind: FieldKind::Text,
            value: FieldValue::text("x").unwrap(),
            protected: false,
            ext: Extensions::new(),
        });
        refused(s.save_entry(d).map(|_| ()), CoreError::InvalidInput);
        assert_eq!(
            err(s.new_entry(a, "login", &"t".repeat(256 * 1024 + 1))),
            CoreError::LimitExceeded
        );
        let mut d = s.new_entry(a, "login", "Many").unwrap();
        for _ in 0..=qv_model::MAX_FIELDS {
            d.add_field("f", FieldKind::Text, FieldValue::text("v").unwrap())
                .unwrap();
        }
        refused(s.save_entry(d).map(|_| ()), CoreError::LimitExceeded);

        // Moves: into a trashed group, into itself or below itself, the root.
        refused(s.move_item(ItemHandle::Entry(e), t), CoreError::NotAllowed);
        refused(s.move_item(ItemHandle::Group(a), a), CoreError::NotAllowed);
        refused(s.move_item(ItemHandle::Group(a), b), CoreError::NotAllowed);
        refused(
            s.move_item(ItemHandle::Group(root), a),
            CoreError::NotAllowed,
        );
        assert_eq!(err(s.new_entry(t, "login", "x")), CoreError::NotFound);

        // A conflicted record (two heads, as a merge would leave it).
        s.mutate(|ctx| {
            let r = ctx.open.index.records.get_mut(&e.record).unwrap();
            r.heads.push(VersionId::generate().unwrap());
            Ok(())
        })
        .unwrap();
        assert_eq!(err(s.edit_entry(e)), CoreError::Conflict);
        refused(s.move_item(ItemHandle::Entry(e), b), CoreError::Conflict);
        refused(s.delete(ItemHandle::Entry(e), false), CoreError::Conflict);
    }

    #[test]
    fn edit_settings_round_trip() {
        let env = Env::new();
        {
            let s = env.unlock();
            let mut d = s.edit_settings().unwrap();
            let m = d.meta_mut();
            m.name = Text::new("Renamed").unwrap();
            m.description = Some(Text::new("work vault").unwrap());
            m.settings.trash_retention_days = Some(7);
            m.settings.history_depth = Some(3);
            m.settings.generator = Some(GeneratorDefaults {
                settings: GeneratorSettings::Pin(PinSettings { length: 9 }),
                ext: Extensions::new(),
            });
            s.save_settings(d).unwrap();
            assert_eq!(s.overview().unwrap().name.expose(), "Renamed");
        }
        let s = env.unlock();
        assert_eq!(s.overview().unwrap().name.expose(), "Renamed");
        let d = s.edit_settings().unwrap();
        assert_eq!(
            d.meta().description.as_ref().unwrap().expose(),
            "work vault"
        );
        assert_eq!(d.meta().settings.trash_retention_days, Some(7));
        assert_eq!(d.meta().settings.history_depth, Some(3));
        assert_eq!(
            s.generator_defaults().unwrap(),
            GeneratorSettings::Pin(PinSettings { length: 9 })
        );
    }
}

#[cfg(test)]
mod trash_tests {
    use qv_model::{AttachmentMeta, Clock};

    use super::*;
    use crate::testutil::{Env, add_entry, add_group, err, seq};

    #[test]
    fn batch_entry_operations_are_all_or_nothing() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let g = add_group(&s, root, "G");
        let a = add_entry(&s, root, "a");
        let b = add_entry(&s, root, "b");
        let c = add_entry(&s, root, "c");
        // Empty lists change nothing and write nothing.
        let before = seq(&s);
        s.delete_entries(&[]).unwrap();
        s.restore_entries(&[]).unwrap();
        s.move_entries(&[], g).unwrap();
        s.set_entry_icons(&[], None).unwrap();
        assert_eq!(seq(&s), before);
        // Over the limit: refused before reading.
        assert_eq!(
            err(s.delete_entries(&vec![a; MAX_BATCH + 1])),
            CoreError::LimitExceeded
        );
        // One trashed handle in the list fails the whole call.
        s.delete(ItemHandle::Entry(c), false).unwrap();
        let before = seq(&s);
        assert_eq!(err(s.delete_entries(&[a, b, c])), CoreError::NotAllowed);
        assert_eq!(err(s.move_entries(&[a, c], g)), CoreError::NotAllowed);
        assert_eq!(seq(&s), before);
        assert_eq!(trash_names(&s), ["c"]);
        // A foreign session's handle fails it too.
        let other = Env::new();
        let o = other.unlock();
        let foreign = add_entry(&o, o.root().unwrap(), "x");
        assert_eq!(err(s.delete_entries(&[a, foreign])), CoreError::StaleHandle);
        assert_eq!(seq(&s), before);
        let live = add_entry(&s, root, "live");
        let before = seq(&s);
        // Batch trash is one transaction (duplicates collapse); restore too.
        s.delete_entries(&[a, b, a]).unwrap();
        assert_eq!(seq(&s), before + 1);
        assert_eq!(trash_names(&s), ["a", "b", "c"]);
        assert_eq!(err(s.restore_entries(&[a, live])), CoreError::NotAllowed);
        s.restore_entries(&[a, b]).unwrap();
        assert_eq!(seq(&s), before + 2);
        assert_eq!(trash_names(&s), ["c"]);
        // Move: one transaction; an entry already there gets no version.
        s.move_entries(&[a, b], g).unwrap();
        assert_eq!(seq(&s), before + 3);
        assert_eq!(s.list(g).unwrap().entries.len(), 2);
        let modified = |s: &Session| {
            s.list(g)
                .unwrap()
                .entries
                .iter()
                .map(|e| e.modified_at)
                .collect::<Vec<_>>()
        };
        let at = modified(&s);
        env.time
            .set(env.time.0.load(std::sync::atomic::Ordering::SeqCst) + 5000);
        s.move_entries(&[a, b], g).unwrap();
        assert_eq!(modified(&s), at);
        // Into a trashed group: refused.
        let gone = add_group(&s, root, "Gone");
        s.delete(ItemHandle::Group(gone), false).unwrap();
        let before = seq(&s);
        assert_eq!(err(s.move_entries(&[a], gone)), CoreError::NotAllowed);
        assert_eq!(seq(&s), before);
        // Icons: set on both, then clearing only touches entries with one.
        s.set_entry_icons(&[a, b], Some("hue:3")).unwrap();
        assert!(
            s.list(g)
                .unwrap()
                .entries
                .iter()
                .all(|e| e.icon.as_ref().map(Text::expose) == Some("hue:3"))
        );
        let at = modified(&s);
        s.set_entry_icons(&[a, b], Some("hue:3")).unwrap();
        assert_eq!(modified(&s), at);
        s.set_entry_icons(&[a], None).unwrap();
        assert_eq!(
            s.list(g)
                .unwrap()
                .entries
                .iter()
                .filter(|e| e.icon.is_none())
                .count(),
            1
        );
    }

    const DAY: i64 = 86_400_000;

    // 0012 §1: Deleted-entry resurrection
    #[test]
    fn trash_restore_does_not_group_separate_deletions_at_identical_times() {
        let env = Env::new();
        let s = env.unlock();
        let a = add_group(&s, s.root().unwrap(), "A");
        let b = add_group(&s, a, "separately deleted group");
        let e = add_entry(&s, a, "separately deleted entry");
        add_entry(&s, b, "child of separate deletion");
        let restored = add_entry(&s, a, "same operation");
        // The fixed clock never advances across these independent operations.
        s.delete(ItemHandle::Entry(e), false).unwrap();
        s.delete(ItemHandle::Group(b), true).unwrap();
        s.delete(ItemHandle::Group(a), true).unwrap();
        drop(s);
        // Identity survives storage/reopen and cache reconstruction.
        let s = env.unlock();
        let a = s
            .trash()
            .unwrap()
            .into_iter()
            .find(|r| r.name.expose() == "A")
            .unwrap()
            .item;
        s.restore(a).unwrap();
        assert_eq!(
            trash_names(&s),
            [
                "child of separate deletion",
                "separately deleted entry",
                "separately deleted group"
            ]
        );
        s.read(|ctx| {
            let (_, entry, _) = load_entry(ctx, restored.record)?;
            assert!(entry.deleted_at.is_none());
            assert!(entry.delete_operation.is_none());
            Ok(())
        })
        .unwrap();
    }

    // 0012 §1: Deleted-entry resurrection
    #[test]
    fn trash_group_without_operation_restores_only_itself() {
        let env = Env::new();
        let s = env.unlock();
        let a = add_group(&s, s.root().unwrap(), "A");
        let b = add_group(&s, a, "B");
        let e = add_entry(&s, b, "e");
        s.delete(ItemHandle::Group(a), true).unwrap();
        s.mutate(|ctx| {
            let mut changes = Vec::new();
            for id in [a.record, b.record] {
                let (_, mut group, ext) = load_group(ctx, id)?;
                group.delete_operation = None;
                changes.push(group_change(id, group, ext));
            }
            let (_, mut entry, ext) = load_entry(ctx, e.record)?;
            entry.delete_operation = None;
            changes.push(entry_change(e.record, entry, ext));
            commit(ctx, changes)
        })
        .unwrap();
        s.restore(ItemHandle::Group(a)).unwrap();
        assert_eq!(trash_names(&s), ["B", "e"]);
        s.restore(ItemHandle::Group(b)).unwrap();
        assert_eq!(trash_names(&s), ["e"]);
        s.restore(ItemHandle::Entry(e)).unwrap();
        assert!(trash_names(&s).is_empty());
    }

    fn staged() -> Vec<(char, RecordId)> {
        STAGING.with(|e| std::mem::take(&mut *e.borrow_mut()))
    }

    /// Each record is read and staged before the next one is read, so at
    /// most one decoded record is held (plan 0053).
    fn assert_sequential(events: &[(char, RecordId)], records: usize) {
        assert_eq!(events.len(), 2 * records, "{events:?}");
        for pair in events.chunks(2) {
            assert!(matches!(pair, [('r', a), ('s', b)] if a == b), "{events:?}");
        }
    }

    #[test]
    fn bulk_changes_read_and_stage_one_record_at_a_time() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let g = add_group(&s, root, "G");
        let inner = add_group(&s, g, "inner");
        let entries: Vec<_> = (0..12)
            .map(|i| add_entry(&s, if i % 2 == 0 { g } else { inner }, &format!("e{i}")))
            .collect();
        staged();
        let before = seq(&s);
        s.set_entry_icons(&entries, Some("blue")).unwrap();
        assert_sequential(&staged(), 12);
        // Unchanged records are read but not staged; the rest still commit.
        s.set_entry_icons(&entries[..3], Some("blue")).unwrap();
        assert_eq!(staged().iter().filter(|(k, _)| *k == 's').count(), 0);
        s.move_entries(&entries, root).unwrap();
        assert_sequential(&staged(), 12);
        s.move_entries(&entries, inner).unwrap();
        staged();
        s.delete(ItemHandle::Group(g), true).unwrap();
        assert_sequential(&staged(), 14);
        s.restore(ItemHandle::Group(g)).unwrap();
        assert_sequential(&staged(), 14);
        assert_eq!(seq(&s), before + 5);
        assert!(s.verify(None).unwrap().ok());
    }

    #[test]
    fn bulk_change_failure_mid_staging_commits_nothing() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let entries: Vec<_> = (0..8)
            .map(|i| add_entry(&s, root, &format!("e{i}")))
            .collect();
        let ids: Vec<RecordId> = entries.iter().map(|e| e.record).collect();
        let summary = |s: &Session| s.read(|ctx| ctx.open.index.summary(Some(&ctx.open.vault)));
        let before = (seq(&s), summary(&s).unwrap());
        for failure in [
            CoreError::Cancelled,
            CoreError::Store(qv_store::StoreError::Integrity),
        ] {
            let mut n = 0;
            let r = s.mutate(|ctx| {
                commit_each(ctx, &ids, |index, read, id| {
                    n += 1;
                    if n == 5 {
                        return Err(failure);
                    }
                    let (mut e, ext) =
                        entry_of(read(id, single_in(index, id, RecordKind::Entry)?)?)?;
                    e.icon = Some(text("red")?);
                    Ok(Some(entry_change(id, e, ext)))
                })
            });
            assert_eq!(r, Err(failure));
            assert_eq!((seq(&s), summary(&s).unwrap()), before);
        }
        // A record already staged in this write cannot be re-read as base.
        let r = s.mutate(|ctx| {
            commit_each(ctx, &[ids[0], ids[0]], |index, read, id| {
                let (e, ext) = entry_of(read(id, single_in(index, id, RecordKind::Entry)?)?)?;
                Ok(Some(entry_change(id, e, ext)))
            })
        });
        assert_eq!(r, Err(CoreError::Store(qv_store::StoreError::InvalidEdit)));
        assert_eq!((seq(&s), summary(&s).unwrap()), before);
        staged();
        assert!(s.verify(None).unwrap().ok());
    }

    fn trash_names(s: &Session) -> Vec<String> {
        let mut v: Vec<String> = s
            .trash()
            .unwrap()
            .iter()
            .map(|t| t.name.expose().to_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn trash_group_delete_and_restore() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let a = add_group(&s, root, "A");
        let b = add_group(&s, a, "B");
        let e1 = add_entry(&s, a, "e1");
        add_entry(&s, b, "e2");
        let e0 = add_entry(&s, a, "e0");
        let t = env.time.0.load(std::sync::atomic::Ordering::SeqCst);
        s.delete(ItemHandle::Entry(e0), false).unwrap();
        env.time.set(t + 1000);
        assert_eq!(
            err(s.delete(ItemHandle::Group(a), false)),
            CoreError::NotEmpty
        );
        assert_eq!(
            err(s.delete(ItemHandle::Group(root), true)),
            CoreError::NotAllowed
        );
        let before = seq(&s);
        s.delete(ItemHandle::Group(a), true).unwrap();
        assert_eq!(seq(&s), before + 1);
        assert_eq!(trash_names(&s), ["A", "B", "e0", "e1", "e2"]);
        let at: Vec<_> = s
            .trash()
            .unwrap()
            .iter()
            .map(|x| (x.name.expose().to_owned(), x.deleted_at))
            .collect();
        for (name, d) in &at {
            let want = if name == "e0" { t } else { t + 1000 };
            assert_eq!(*d, Some(Timestamp(want)), "{name}");
        }
        assert!(s.list(root).unwrap().groups.is_empty());
        assert_eq!(err(s.list(a)), CoreError::NotFound);
        assert_eq!(err(s.edit_entry(e1)), CoreError::NotAllowed);
        assert_eq!(
            err(s.delete(ItemHandle::Entry(e1), false)),
            CoreError::NotAllowed
        );

        // Restoring A brings back what was deleted with it, not e0.
        s.restore(ItemHandle::Group(a)).unwrap();
        assert_eq!(trash_names(&s), ["e0"]);
        let l = s.list(a).unwrap();
        assert_eq!(l.groups.len(), 1);
        assert_eq!(l.entries.len(), 1);
        assert_eq!(s.list(b).unwrap().entries.len(), 1);
        assert_eq!(err(s.restore(ItemHandle::Entry(e1))), CoreError::NotAllowed);

        // An entry restored while its group is still in the trash is shown
        // under recovered items.
        s.delete(ItemHandle::Group(b), true).unwrap();
        let e2 = s
            .trash()
            .unwrap()
            .into_iter()
            .find(|x| x.name.expose() == "e2")
            .unwrap();
        s.restore(e2.item).unwrap();
        let rec = s.recovered().unwrap();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].title.expose(), "e2");
        assert_eq!(s.entry(rec[0].handle).unwrap().group, None);
    }

    #[test]
    fn trash_purge_and_empty() {
        let env = Env::new();
        let (keep, gone, att) = {
            let s = env.unlock_with(Some(env.snapshot_policy()));
            let root = s.root().unwrap();
            let keep = add_entry(&s, root, "keep");
            let gone = add_entry(&s, root, "gone");
            for i in 0..2 {
                let mut d = s.edit_entry(gone).unwrap();
                d.entry_mut().title = Text::new(&format!("gone {i}")).unwrap();
                s.save_entry(d).unwrap();
            }
            // An attachment owned by `gone`, written below the core.
            let att = RecordId::generate().unwrap();
            s.mutate(|ctx| {
                let mut w = ctx.open.vault.write()?;
                let c = w.reserve_counter()?;
                let v = RecordVersion {
                    version_id: VersionId::generate().unwrap(),
                    clock: Clock::from_pairs(vec![(w.writer_id(), c)]).unwrap(),
                    modified_at: Timestamp(1),
                    body: RecordBody::Live(Payload::AttachmentMeta(AttachmentMeta {
                        entry: gone.record,
                        name: Text::new("empty.txt").unwrap(),
                        mime: Text::new("text/plain").unwrap(),
                        size: 0,
                        chunk_object_ids: Vec::new(),
                        content_hash: *qv_crypto::ContentHasher::new().finalize().expose_secret(),
                        ext: Extensions::new(),
                    })),
                    ext: Extensions::new(),
                };
                w.put_local(att, v)?;
                Ok(w.commit()?)
            })
            .unwrap();
            (keep.record, gone.record, att)
        };
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let h = |r| s.read(|ctx| Ok(ctx.entry_handle(r))).unwrap();
        let (keep, gone) = (h(keep), h(gone));
        let before = seq(&s);
        assert_eq!(
            err(s.purge(&[ItemHandle::Entry(keep)])),
            CoreError::NotAllowed
        );
        assert_eq!(seq(&s), before);
        s.delete(ItemHandle::Entry(gone), false).unwrap();
        s.delete(ItemHandle::Entry(keep), false).unwrap();

        // A conflicted trash item (a delete/edit race) is skipped.
        s.mutate(|ctx| {
            let r = ctx.open.index.records.get_mut(&keep.record).unwrap();
            r.heads.push(VersionId::generate().unwrap());
            r.status.conflict = true;
            Ok(())
        })
        .unwrap();
        assert_eq!(
            err(s.purge(&[ItemHandle::Entry(keep)])),
            CoreError::Conflict
        );
        let report = crate::testutil::destructive(&s, || s.empty_trash()).unwrap();
        assert_eq!(
            report,
            PurgeReport {
                purged: 1,
                skipped_conflicts: 1
            }
        );

        let check = |s: &Session| {
            s.read(|ctx| {
                let m = ctx.open.vault.manifest();
                for id in [gone.record, att] {
                    let rec = m.record(id).unwrap();
                    assert_eq!(rec.heads().len(), 1);
                    assert!(rec.history().is_empty());
                    let v = decrypt(ctx, id, rec.heads()[0].version_id()).unwrap();
                    assert_eq!(v.deletion(), qv_model::Deletion::Final);
                    assert!(ctx.open.index.get(id).unwrap().status.finally_deleted);
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(
                err(s.entry(s.read(|ctx| Ok(ctx.entry_handle(gone.record))).unwrap())),
                CoreError::NotFound
            );
        };
        check(&s);
        assert_eq!(trash_names(&s), ["keep"]);
        assert!(s.search("gone").unwrap().is_empty());
        drop(s);
        let s = env.unlock_with(Some(env.snapshot_policy()));
        check(&s);
        assert_eq!(trash_names(&s), ["keep"]);
        let o = s.overview().unwrap();
        assert_eq!((o.entries, o.in_trash), (0, 1));
    }

    #[test]
    fn trash_expiry_report() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let l = s.overview().unwrap().last_modified.unwrap().0;
        env.time.set(l);
        let old = add_entry(&s, root, "old");
        let young = add_entry(&s, root, "young");
        env.time.set(l - 31 * DAY);
        s.delete(ItemHandle::Entry(old), false).unwrap();
        env.time.set(l - 29 * DAY);
        s.delete(ItemHandle::Entry(young), false).unwrap();
        env.time.set(l);
        let r = s.expired_trash().unwrap();
        let names: Vec<_> = r
            .expired
            .iter()
            .map(|t| t.name.expose().to_owned())
            .collect();
        assert_eq!(names, ["old"]);
        assert!(!r.clock_anomaly);
        // A shorter retention period applies at once.
        let mut d = s.edit_settings().unwrap();
        d.meta_mut().settings.trash_retention_days = Some(1);
        s.save_settings(d).unwrap();
        assert_eq!(s.expired_trash().unwrap().expired.len(), 2);

        let l = s.overview().unwrap().last_modified.unwrap().0;
        env.time.set(l - 11 * 60 * 1000);
        assert!(s.expired_trash().unwrap().clock_anomaly);
        env.time.set(l - 9 * 60 * 1000);
        assert!(!s.expired_trash().unwrap().clock_anomaly);
    }
}

#[cfg(test)]
mod property_tests {
    use proptest::prelude::*;

    use super::*;
    use crate::testutil::{Env, add_entry, add_group};

    fn summary(s: &Session) -> Vec<String> {
        s.read(|ctx| ctx.open.index.summary(Some(&ctx.open.vault)))
            .unwrap()
    }

    fn pick<T: Copy>(v: &[T], i: usize) -> Option<T> {
        (!v.is_empty()).then(|| v[i % v.len()])
    }

    /// Applies one operation; refusals are fine, other errors are not.
    fn apply(
        s: &Session,
        groups: &mut Vec<GroupHandle>,
        entries: &mut Vec<EntryHandle>,
        op: u8,
        i: usize,
        j: usize,
    ) {
        let ok = |r: Result<(), CoreError>| match r {
            Ok(())
            | Err(
                CoreError::NotAllowed
                | CoreError::NotFound
                | CoreError::NotEmpty
                | CoreError::Conflict,
            ) => {}
            Err(e) => panic!("operation {op} failed: {e:?}"),
        };
        let root = s.root().unwrap();
        let mut all = vec![root];
        all.extend(groups.iter().copied());
        match op {
            0 => {
                let parent = pick(&all, i).unwrap();
                if let Ok(d) = s.new_group(parent, &format!("g{i}")) {
                    groups.push(s.save_group(d).unwrap());
                }
            }
            1 => {
                let g = pick(&all, i).unwrap();
                if s.new_entry(g, "login", "probe").is_ok() {
                    entries.push(add_entry(s, g, &format!("e{j}")));
                }
            }
            2 => {
                if let Some(e) = pick(entries, i) {
                    ok(s.edit_entry(e).and_then(|mut d| {
                        d.entry_mut().title =
                            Text::new(&format!("edited {j}")).map_err(crate::error::input)?;
                        s.save_entry(d).map(|_| ())
                    }));
                }
            }
            3 => {
                if let Some(e) = pick(entries, i) {
                    ok(s.move_item(ItemHandle::Entry(e), pick(&all, j).unwrap()));
                }
            }
            4 => {
                if let Some(g) = pick(groups, i) {
                    ok(s.move_item(ItemHandle::Group(g), pick(&all, j).unwrap()));
                }
            }
            5 => {
                let item = if j.is_multiple_of(2) {
                    pick(entries, i).map(ItemHandle::Entry)
                } else {
                    pick(groups, i).map(ItemHandle::Group)
                };
                if let Some(item) = item {
                    ok(s.delete(item, true));
                }
            }
            6 => {
                if let Some(t) = pick(
                    &s.trash()
                        .unwrap()
                        .iter()
                        .map(|t| t.item)
                        .collect::<Vec<_>>(),
                    i,
                ) {
                    ok(s.restore(t));
                }
            }
            _ => {
                if j.is_multiple_of(3) {
                    crate::testutil::destructive(s, || s.empty_trash()).unwrap();
                } else if let Some(t) = pick(
                    &s.trash()
                        .unwrap()
                        .iter()
                        .map(|t| t.item)
                        .collect::<Vec<_>>(),
                    i,
                ) {
                    ok(crate::testutil::destructive(s, || s.purge(&[t])));
                }
            }
        }
    }

    proptest! {
        // Each case runs Argon2id twice.
        #![proptest_config(ProptestConfig::with_cases(6))]

        #[test]
        fn edit_random_operations_match_reopen(
            ops in proptest::collection::vec((0u8..8, 0usize..16, 0usize..16), 1..24)
        ) {
            let env = Env::new();
            let mut groups = Vec::new();
            let mut entries = Vec::new();
            let incremental = {
                let s = env.unlock_with(Some(env.snapshot_policy()));
                let root = s.root().unwrap();
                groups.push(add_group(&s, root, "start"));
                for (op, i, j) in ops {
                    apply(&s, &mut groups, &mut entries, op, i, j);
                }
                summary(&s)
            };
            let s = env.unlock_with(Some(env.snapshot_policy()));
            prop_assert_eq!(incremental, summary(&s));
        }
    }
}
