// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read calls: listings and search from the index, and on-demand decryption
//! of details and protected values (spec 0004 §5.1, 0008 §1.2, 0005 §2.3,
//! 0011 §4 *Browsing*).
//!
//! Every returned view holds zeroizing copies and has a redacted `Debug`
//! and no `Clone`: the caller drops it when the screen or command is done,
//! and must drop every view when the session locks.

use qv_crypto::{OtpCode, RecordId};
use qv_model::{
    Entry, FieldKind, FieldValue, Group, Payload, RecordBody, RecordKind, RecordVersion, Text,
    Timestamp, Totp, VersionId,
};
use zeroize::Zeroizing;

use crate::error::{CoreError, data};
use crate::index::{Data, EntryInfo, GroupInfo, Index, RecordInfo};
use crate::session::{Ctx, EntryHandle, FieldHandle, GroupHandle, ItemHandle, Session};

/// The longest search query, in bytes.
pub const MAX_QUERY_BYTES: usize = 1024;

/// How far in the future a timestamp may be before trash expiry reports a
/// clock anomaly (development value).
pub(crate) const CLOCK_TOLERANCE_MS: i64 = 10 * 60 * 1000;

const DAY_MS: i64 = 86_400_000;

macro_rules! redacted {
    ($($t:ident),+) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )+};
}

/// A non-protected field shown in listings: `text`, `url` and `email`
/// fields that are not protected (usernames, URLs, e-mail addresses).
pub struct FieldSummary {
    /// The field's name.
    pub name: Text,
    /// Its kind.
    pub kind: FieldKind,
    /// Its value.
    pub value: Text,
}

/// An entry in a listing.
pub struct EntrySummary {
    /// The entry.
    pub handle: EntryHandle,
    /// Its title.
    pub title: Text,
    /// Its type hint (`login`, `note`, …); UI only.
    pub type_hint: Text,
    /// Its icon name.
    pub icon: Option<Text>,
    /// Its non-protected text, URL and e-mail fields, in order.
    pub fields: Vec<FieldSummary>,
    /// When it was last modified (display only).
    pub modified_at: Timestamp,
    /// When it expires.
    pub expires_at: Option<Timestamp>,
    /// Whether it has conflicting versions.
    pub conflict: bool,
}

/// A group in a listing.
pub struct GroupSummary {
    /// The group.
    pub handle: GroupHandle,
    /// Its name.
    pub name: Text,
    /// Its icon name.
    pub icon: Option<Text>,
    /// Its fractional ordering key.
    pub order: Text,
    /// Shown under another parent than its record names (0003 §4.1).
    pub repaired: bool,
    /// Whether it has conflicting versions.
    pub conflict: bool,
}

/// The direct children of a group.
pub struct Listing {
    /// Child groups by (order, ID).
    pub groups: Vec<GroupSummary>,
    /// Entries by (title, ID), case-insensitively.
    pub entries: Vec<EntrySummary>,
}

/// An item in the trash.
pub struct TrashItem {
    /// The item.
    pub item: ItemHandle,
    /// Its title or name.
    pub name: Text,
    /// When it was deleted (`None` if only a concurrent version deleted it).
    pub deleted_at: Option<Timestamp>,
    /// Whether it has conflicting versions (a delete/edit race, 0005 §2.5).
    pub conflict: bool,
}

/// An item with conflicting versions (0005 §2.3).
pub struct ConflictSummary {
    /// The item.
    pub item: ItemHandle,
    /// Its representative's title or name.
    pub name: Text,
    /// The number of concurrent heads.
    pub heads: usize,
    /// Whether it is (also) in the trash.
    pub in_trash: bool,
}

/// A search result.
pub enum SearchHit {
    /// A group whose name matches.
    Group(GroupSummary),
    /// An entry whose title or a non-protected field matches.
    Entry(EntrySummary),
}

/// Trash items past the retention period (0007 §2.1). Nothing is deleted
/// until the frontend confirms and calls [`Session::purge`].
pub struct ExpiryReport {
    /// Expired, non-conflicted items.
    pub expired: Vec<TrashItem>,
    /// Some vault timestamp is more than ten minutes after this device's
    /// clock: the clock may be wrong, so the frontend must warn before
    /// deleting anything.
    pub clock_anomaly: bool,
}

/// The vault at a glance (0011 `info --full`).
pub struct Overview {
    /// The vault's name.
    pub name: Text,
    /// Live entries.
    pub entries: usize,
    /// Live groups, the root excluded.
    pub groups: usize,
    /// Entries and groups in the trash.
    pub in_trash: usize,
    /// Records with conflicting versions.
    pub conflicts: usize,
    /// The local commit sequence number.
    pub local_seq: u64,
    /// The latest timestamp in the vault (display only).
    pub last_modified: Option<Timestamp>,
}

/// One field of an entry version. A protected value is not included; use
/// [`Session::reveal`].
pub struct FieldDetail {
    /// The field (of this version).
    pub handle: FieldHandle,
    /// Its name.
    pub name: Text,
    /// Its kind.
    pub kind: FieldKind,
    /// Whether the UI may show it only on an explicit reveal (0003 §5.3).
    pub protected: bool,
    /// The value, or `None` when protected.
    pub value: Option<FieldValue>,
}

/// One decrypted entry version.
pub struct EntryDetail {
    /// The entry.
    pub handle: EntryHandle,
    /// The version shown.
    pub version: VersionId,
    /// Its title.
    pub title: Text,
    /// Its type hint.
    pub type_hint: Text,
    /// Its group, or `None` if the group is missing or deleted (recovered
    /// items).
    pub group: Option<GroupHandle>,
    /// Its notes.
    pub notes: Option<Text>,
    /// Its icon name.
    pub icon: Option<Text>,
    /// Creation time (display only).
    pub created_at: Timestamp,
    /// Modification time (display only).
    pub modified_at: Timestamp,
    /// Expiry time.
    pub expires_at: Option<Timestamp>,
    /// Soft-deletion time.
    pub deleted_at: Option<Timestamp>,
    /// Its fields, in order.
    pub fields: Vec<FieldDetail>,
}

/// One decrypted group version.
pub struct GroupDetail {
    /// The group.
    pub handle: GroupHandle,
    /// The version shown.
    pub version: VersionId,
    /// Its name.
    pub name: Text,
    /// Its notes.
    pub notes: Option<Text>,
    /// Its icon name.
    pub icon: Option<Text>,
    /// Its fractional ordering key.
    pub order: Text,
    /// Its parent as the record names it (`None` for the root).
    pub parent: Option<RecordId>,
    /// Its displayed parent (`None` for the root and for groups not in the
    /// tree).
    pub shown_parent: Option<GroupHandle>,
    /// Soft-deletion time.
    pub deleted_at: Option<Timestamp>,
}

/// A TOTP code and how long it stays valid.
pub struct TotpNow {
    /// The code.
    pub code: OtpCode,
    /// Seconds until the next code.
    pub seconds_remaining: u32,
}

redacted!(
    FieldSummary,
    EntrySummary,
    GroupSummary,
    Listing,
    TrashItem,
    ConflictSummary,
    SearchHit,
    ExpiryReport,
    Overview,
    FieldDetail,
    EntryDetail,
    GroupDetail,
    TotpNow
);

fn copy(t: &Text) -> Result<Text, CoreError> {
    Text::new(t.expose()).map_err(data)
}

fn copy_opt(t: Option<&Text>) -> Result<Option<Text>, CoreError> {
    t.map(copy).transpose()
}

fn lower(s: &str) -> Zeroizing<String> {
    Zeroizing::new(s.to_lowercase())
}

/// The record behind a handle, if it is of `kind` and not finally deleted.
pub(crate) fn record(
    index: &Index,
    id: RecordId,
    kind: RecordKind,
) -> Result<&RecordInfo, CoreError> {
    match index.get(id) {
        Some(r) if r.kind == kind && !r.status.finally_deleted => Ok(r),
        _ => Err(CoreError::NotFound),
    }
}

pub(crate) fn entry_summary(
    ctx: &Ctx<'_>,
    id: RecordId,
    r: &RecordInfo,
    e: &EntryInfo,
) -> Result<EntrySummary, CoreError> {
    Ok(EntrySummary {
        handle: ctx.entry_handle(id),
        title: copy(&e.title)?,
        type_hint: copy(&e.type_hint)?,
        icon: copy_opt(e.icon.as_ref())?,
        fields: e
            .fields
            .iter()
            .map(|f| {
                Ok(FieldSummary {
                    name: copy(&f.name)?,
                    kind: f.kind,
                    value: copy(&f.value)?,
                })
            })
            .collect::<Result<_, CoreError>>()?,
        modified_at: e.modified_at,
        expires_at: e.expires_at,
        conflict: r.status.conflict,
    })
}

pub(crate) fn group_summary(
    ctx: &Ctx<'_>,
    id: RecordId,
    r: &RecordInfo,
    g: &GroupInfo,
) -> Result<GroupSummary, CoreError> {
    Ok(GroupSummary {
        handle: ctx.group_handle(id),
        name: copy(&g.name)?,
        icon: copy_opt(g.icon.as_ref())?,
        order: copy(&g.order)?,
        repaired: ctx.open.index.tree.is_repaired(id),
        conflict: r.status.conflict,
    })
}

fn item_name(r: &RecordInfo) -> Option<&Text> {
    match &r.data {
        Data::Entry(e) => Some(&e.title),
        Data::Group(g) => Some(&g.name),
        _ => None,
    }
}

fn item_handle(ctx: &Ctx<'_>, id: RecordId, r: &RecordInfo) -> Option<ItemHandle> {
    match r.kind {
        RecordKind::Entry => Some(ItemHandle::Entry(ctx.entry_handle(id))),
        RecordKind::Group => Some(ItemHandle::Group(ctx.group_handle(id))),
        _ => None,
    }
}

fn trash_item(ctx: &Ctx<'_>, id: RecordId, r: &RecordInfo) -> Result<Option<TrashItem>, CoreError> {
    let (Some(item), Some(name)) = (item_handle(ctx, id, r), item_name(r)) else {
        return Ok(None);
    };
    let deleted_at = match &r.data {
        Data::Entry(e) => e.deleted_at,
        Data::Group(g) => g.deleted_at,
        _ => None,
    };
    Ok(Some(TrashItem {
        item,
        name: copy(name)?,
        deleted_at,
        conflict: r.status.conflict,
    }))
}

/// Live entries placed in `group` (or under recovered items for `None`),
/// sorted by (lowercased title, ID).
fn entries_in(ctx: &Ctx<'_>, place: Option<RecordId>) -> Result<Vec<EntrySummary>, CoreError> {
    let index = &ctx.open.index;
    let mut found: Vec<(Zeroizing<String>, RecordId)> = Vec::new();
    for (id, r) in &index.records {
        if let (true, Data::Entry(e)) = (r.status.live, &r.data) {
            let at = match index.tree.place_entry(e.group) {
                qv_model::EntryPlace::Group(g) => Some(g),
                qv_model::EntryPlace::Recovered => None,
            };
            if at == place {
                found.push((lower(e.title.expose()), *id));
            }
        }
    }
    found.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));
    found
        .iter()
        .map(|(_, id)| {
            let r = index.get(*id).ok_or(CoreError::Internal)?;
            match &r.data {
                Data::Entry(e) => entry_summary(ctx, *id, r, e),
                _ => Err(CoreError::Internal),
            }
        })
        .collect()
}

fn group_info(r: &RecordInfo) -> Option<&GroupInfo> {
    match &r.data {
        Data::Group(g) => Some(g),
        _ => None,
    }
}

/// The displayed children of `group`, by (order, ID).
pub(crate) fn child_groups(index: &Index, group: RecordId) -> Vec<RecordId> {
    let mut kids: Vec<(&str, RecordId)> = index
        .tree
        .children(group)
        .into_iter()
        .filter_map(|id| {
            let g = index.get(id).and_then(group_info)?;
            Some((g.order.expose(), id))
        })
        .collect();
    kids.sort();
    kids.into_iter().map(|(_, id)| id).collect()
}

/// Decrypts one head of `id`.
pub(crate) fn decrypt(
    ctx: &Ctx<'_>,
    id: RecordId,
    version: VersionId,
) -> Result<RecordVersion, CoreError> {
    Ok(ctx.open.vault.read_version(id, version)?)
}

fn entry_detail(
    ctx: &Ctx<'_>,
    handle: EntryHandle,
    version: VersionId,
    e: Entry,
) -> Result<EntryDetail, CoreError> {
    let index = &ctx.open.index;
    let group = match index.tree.place_entry(e.group) {
        qv_model::EntryPlace::Group(g) => Some(ctx.group_handle(g)),
        qv_model::EntryPlace::Recovered => None,
    };
    let fields = e
        .fields
        .into_iter()
        .map(|f| FieldDetail {
            handle: FieldHandle {
                entry: handle,
                version,
                field: f.id,
            },
            name: f.name,
            kind: f.kind,
            protected: f.protected,
            value: if f.protected { None } else { Some(f.value) },
        })
        .collect();
    Ok(EntryDetail {
        handle,
        version,
        title: e.title,
        type_hint: e.type_hint,
        group,
        notes: e.notes,
        icon: e.icon,
        created_at: e.created_at,
        modified_at: e.modified_at,
        expires_at: e.expires_at,
        deleted_at: e.deleted_at,
        fields,
    })
}

fn as_entry(v: RecordVersion) -> Option<Entry> {
    match v.body {
        RecordBody::Live(Payload::Entry(e)) => Some(e),
        _ => None,
    }
}

fn as_group(v: RecordVersion) -> Option<Group> {
    match v.body {
        RecordBody::Live(Payload::Group(g)) => Some(g),
        _ => None,
    }
}

/// The decrypted field of a field handle; the version must still be a head.
fn field_of(ctx: &Ctx<'_>, field: FieldHandle) -> Result<qv_model::Field, CoreError> {
    ctx.own(field.entry.session)?;
    let r = record(&ctx.open.index, field.entry.record, RecordKind::Entry)?;
    if !r.heads.contains(&field.version) {
        return Err(CoreError::StaleHandle);
    }
    let e =
        as_entry(decrypt(ctx, field.entry.record, field.version)?).ok_or(CoreError::NotFound)?;
    e.fields
        .into_iter()
        .find(|f| f.id == field.field)
        .ok_or(CoreError::NotFound)
}

impl Session {
    /// The vault at a glance.
    pub fn overview(&self) -> Result<Overview, CoreError> {
        self.read(|ctx| {
            let index = &ctx.open.index;
            let mut o = Overview {
                name: copy(&index.meta().ok_or(CoreError::Internal)?.name)?,
                entries: 0,
                groups: 0,
                in_trash: 0,
                conflicts: 0,
                local_seq: ctx.open.vault.local_seq(),
                last_modified: None,
            };
            for (id, r) in &index.records {
                match (r.kind, r.status.live) {
                    (RecordKind::Entry, true) => o.entries += 1,
                    (RecordKind::Group, true) if *id != index.root => o.groups += 1,
                    _ => {}
                }
                if r.status.in_trash && matches!(r.kind, RecordKind::Entry | RecordKind::Group) {
                    o.in_trash += 1;
                }
                if r.status.conflict {
                    o.conflicts += 1;
                }
                o.last_modified = o.last_modified.max(Some(r.latest));
            }
            Ok(o)
        })
    }

    /// The root group.
    pub fn root(&self) -> Result<GroupHandle, CoreError> {
        self.read(|ctx| Ok(ctx.group_handle(ctx.open.index.root)))
    }

    /// The displayed children of a live group (0003 §4).
    pub fn list(&self, group: GroupHandle) -> Result<Listing, CoreError> {
        self.read(|ctx| {
            ctx.own(group.session)?;
            let index = &ctx.open.index;
            record(index, group.record, RecordKind::Group)?;
            if index.tree.parent(group.record).is_none() {
                // In the trash (or not in the tree at all).
                return Err(CoreError::NotFound);
            }
            let groups = child_groups(index, group.record)
                .into_iter()
                .map(|id| {
                    let r = index.get(id).ok_or(CoreError::Internal)?;
                    let g = group_info(r).ok_or(CoreError::Internal)?;
                    group_summary(ctx, id, r, g)
                })
                .collect::<Result<_, CoreError>>()?;
            ctx.check_cancel()?;
            let entries = entries_in(ctx, Some(group.record))?;
            Ok(Listing { groups, entries })
        })
    }

    /// Live entries whose group is missing or deleted (0003 §4.2).
    pub fn recovered(&self) -> Result<Vec<EntrySummary>, CoreError> {
        self.read(|ctx| entries_in(ctx, None))
    }

    /// Every entry and group in the trash, newest deletion first.
    pub fn trash(&self) -> Result<Vec<TrashItem>, CoreError> {
        self.read(|ctx| {
            let mut out = Vec::new();
            for (id, r) in &ctx.open.index.records {
                if r.status.in_trash
                    && let Some(t) = trash_item(ctx, *id, r)?
                {
                    out.push(t);
                }
            }
            out.sort_by_key(|t| core::cmp::Reverse(t.deleted_at));
            Ok(out)
        })
    }

    /// Every entry and group with conflicting versions. Conflicts are shown,
    /// not resolved, in this phase (0005 §2.3).
    pub fn conflicts(&self) -> Result<Vec<ConflictSummary>, CoreError> {
        self.read(|ctx| {
            let mut out = Vec::new();
            for (id, r) in &ctx.open.index.records {
                if !r.status.conflict {
                    continue;
                }
                if let (Some(item), Some(name)) = (item_handle(ctx, *id, r), item_name(r)) {
                    out.push(ConflictSummary {
                        item,
                        name: copy(name)?,
                        heads: r.heads.len(),
                        in_trash: r.status.in_trash,
                    });
                }
            }
            Ok(out)
        })
    }

    /// Case-insensitive search over live entry titles, live group names and
    /// non-protected `text`, `url` and `email` field values (0011 `search`).
    /// Protected values, notes and other fields are never searched, and no
    /// search index is kept (0008 §1.2). Groups come first, then entries,
    /// each sorted as in listings.
    pub fn search(&self, query: &str) -> Result<Vec<SearchHit>, CoreError> {
        if query.is_empty() || query.len() > MAX_QUERY_BYTES {
            return Err(CoreError::InvalidInput);
        }
        let q = lower(query);
        self.read(|ctx| {
            let index = &ctx.open.index;
            let mut groups: Vec<(Zeroizing<String>, RecordId)> = Vec::new();
            let mut entries: Vec<(Zeroizing<String>, RecordId)> = Vec::new();
            for (id, r) in &index.records {
                ctx.check_cancel()?;
                if !r.status.live {
                    continue;
                }
                match &r.data {
                    Data::Group(g) if index.tree.parent(*id).is_some() => {
                        let name = lower(g.name.expose());
                        if name.contains(q.as_str()) {
                            groups.push((name, *id));
                        }
                    }
                    Data::Entry(e) => {
                        let title = lower(e.title.expose());
                        let hit = title.contains(q.as_str())
                            || e.fields
                                .iter()
                                .any(|f| lower(f.value.expose()).contains(q.as_str()));
                        if hit {
                            entries.push((title, *id));
                        }
                    }
                    _ => {}
                }
            }
            groups.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));
            entries.sort_by(|a, b| (a.0.as_str(), a.1).cmp(&(b.0.as_str(), b.1)));
            let mut out = Vec::with_capacity(groups.len() + entries.len());
            for (_, id) in groups {
                let r = index.get(id).ok_or(CoreError::Internal)?;
                let g = group_info(r).ok_or(CoreError::Internal)?;
                out.push(SearchHit::Group(group_summary(ctx, id, r, g)?));
            }
            for (_, id) in entries {
                let r = index.get(id).ok_or(CoreError::Internal)?;
                if let Data::Entry(e) = &r.data {
                    out.push(SearchHit::Entry(entry_summary(ctx, id, r, e)?));
                }
            }
            Ok(out)
        })
    }

    /// Entries and groups whose ID starts with `prefix` (0011 §2.2): 6 to
    /// 32 hex digits in any case, else [`CoreError::InvalidInput`]. Without
    /// `in_trash`, only items shown in the tree or under recovered items;
    /// with it, only items in the trash. Finally deleted records never match.
    pub fn find_id(&self, prefix: &str, in_trash: bool) -> Result<Vec<ItemHandle>, CoreError> {
        if !(6..=32).contains(&prefix.len()) || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidInput);
        }
        let prefix = prefix.to_ascii_lowercase();
        self.read(|ctx| {
            let index = &ctx.open.index;
            let mut out = Vec::new();
            for (id, r) in &index.records {
                if r.status.finally_deleted {
                    continue;
                }
                let shown = match r.kind {
                    RecordKind::Entry => r.status.live,
                    RecordKind::Group => index.tree.parent(*id).is_some(),
                    _ => continue,
                };
                let wanted = if in_trash { r.status.in_trash } else { shown };
                if wanted
                    && crate::setup::hex(&id.0).starts_with(&prefix)
                    && let Some(h) = item_handle(ctx, *id, r)
                {
                    out.push(h);
                }
            }
            Ok(out)
        })
    }

    /// Trash items past the vault's retention period (0007 §2.1), and
    /// whether the clock looks wrong. Conflicted items are never listed: they
    /// need an explicit resolution first.
    pub fn expired_trash(&self) -> Result<ExpiryReport, CoreError> {
        self.read(|ctx| {
            let now = ctx.now();
            let index = &ctx.open.index;
            let days = index
                .meta()
                .map_or(qv_model::DEFAULT_TRASH_RETENTION_DAYS, |m| m.retention_days);
            let cutoff = now.0.saturating_sub(i64::from(days).saturating_mul(DAY_MS));
            let mut expired = Vec::new();
            let mut clock_anomaly = false;
            for (id, r) in &index.records {
                if r.latest.0 > now.0.saturating_add(CLOCK_TOLERANCE_MS) {
                    clock_anomaly = true;
                }
                if !r.status.in_trash || r.status.conflict {
                    continue;
                }
                if let Some(t) = trash_item(ctx, *id, r)?
                    && t.deleted_at.is_some_and(|d| d.0 <= cutoff)
                {
                    expired.push(t);
                }
            }
            Ok(ExpiryReport {
                expired,
                clock_anomaly,
            })
        })
    }

    /// Decrypts an entry's representative version (the live one, else the
    /// one in the trash). Protected values are left out.
    pub fn entry(&self, entry: EntryHandle) -> Result<EntryDetail, CoreError> {
        self.read(|ctx| {
            ctx.own(entry.session)?;
            let r = record(&ctx.open.index, entry.record, RecordKind::Entry)?;
            let v = r.shown.ok_or(CoreError::NotFound)?;
            let e = as_entry(decrypt(ctx, entry.record, v)?).ok_or(CoreError::NotFound)?;
            entry_detail(ctx, entry, v, e)
        })
    }

    /// Decrypts every head of an entry that holds an entry payload (more
    /// than one when it is in conflict, 0005 §2.3).
    pub fn entry_versions(&self, entry: EntryHandle) -> Result<Vec<EntryDetail>, CoreError> {
        self.read(|ctx| {
            ctx.own(entry.session)?;
            let r = record(&ctx.open.index, entry.record, RecordKind::Entry)?;
            let mut out = Vec::new();
            for v in r.heads.clone() {
                if let Some(e) = as_entry(decrypt(ctx, entry.record, v)?) {
                    out.push(entry_detail(ctx, entry, v, e)?);
                }
            }
            Ok(out)
        })
    }

    /// Decrypts a group's representative version.
    pub fn group(&self, group: GroupHandle) -> Result<GroupDetail, CoreError> {
        self.read(|ctx| {
            ctx.own(group.session)?;
            let r = record(&ctx.open.index, group.record, RecordKind::Group)?;
            let v = r.shown.ok_or(CoreError::NotFound)?;
            let g = as_group(decrypt(ctx, group.record, v)?).ok_or(CoreError::NotFound)?;
            let shown_parent = ctx
                .open
                .index
                .tree
                .parent(group.record)
                .flatten()
                .map(|p| ctx.group_handle(p));
            Ok(GroupDetail {
                handle: group,
                version: v,
                name: g.name,
                notes: g.notes,
                icon: g.icon,
                order: g.order,
                parent: g.parent,
                shown_parent,
                deleted_at: g.deleted_at,
            })
        })
    }

    /// Decrypts one field's value, protected or not, into locked memory
    /// (an explicit reveal, 0008 §1.2). The field's version must still be a
    /// head ([`CoreError::StaleHandle`] otherwise).
    pub fn reveal(&self, field: FieldHandle) -> Result<FieldValue, CoreError> {
        self.read(|ctx| Ok(field_of(ctx, field)?.value))
    }

    /// The current code of a TOTP field (0003 §5.4). The seed never leaves
    /// the core.
    pub fn totp(&self, field: FieldHandle) -> Result<TotpNow, CoreError> {
        self.read(|ctx| {
            let f = field_of(ctx, field)?;
            if f.kind != FieldKind::Totp {
                return Err(CoreError::InvalidInput);
            }
            let totp = Totp::parse(f.value.expose_secret())?;
            let now = ctx.now();
            Ok(TotpNow {
                code: totp.code_at(now)?,
                seconds_remaining: totp.seconds_remaining(now)?,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use qv_crypto::{GeneratorError, GeneratorSettings, PinSettings};
    use qv_model::{FieldKind, FieldValue, GeneratorDefaults};

    use super::*;
    use crate::testutil::{Env, add_entry, add_group, err};

    fn titles(l: &[EntrySummary]) -> Vec<String> {
        l.iter().map(|e| e.title.expose().to_owned()).collect()
    }

    fn hits(s: &Session, q: &str) -> Vec<String> {
        s.search(q)
            .unwrap()
            .iter()
            .map(|h| match h {
                SearchHit::Group(g) => format!("g:{}", g.name.expose()),
                SearchHit::Entry(e) => format!("e:{}", e.title.expose()),
            })
            .collect()
    }

    #[test]
    fn views_find_by_id_prefix() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let g = add_group(&s, root, "G");
        let e = add_entry(&s, g, "E");
        let gone = add_entry(&s, g, "Gone");
        s.delete(ItemHandle::Entry(gone), false).unwrap();
        let id = e.id_hex();
        assert_eq!(id.len(), 32);
        assert_eq!(ItemHandle::Entry(e).id_hex(), id);
        assert_eq!(s.find_id(&id[..6], false).unwrap(), [ItemHandle::Entry(e)]);
        assert_eq!(
            s.find_id(&id.to_uppercase(), false).unwrap(),
            [ItemHandle::Entry(e)]
        );
        assert_eq!(
            s.find_id(&g.id_hex()[..8], false).unwrap(),
            [ItemHandle::Group(g)]
        );
        assert_eq!(
            s.find_id(&root.id_hex(), false).unwrap(),
            [ItemHandle::Group(root)]
        );
        for bad in ["abcde", "abcdeg", "", &"a".repeat(33)] {
            assert_eq!(err(s.find_id(bad, false)), CoreError::InvalidInput, "{bad}");
        }
        // Trashed items only with `in_trash`; finally deleted ones never.
        let g_id = gone.id_hex();
        assert!(s.find_id(&g_id, false).unwrap().is_empty());
        assert_eq!(s.find_id(&g_id, true).unwrap(), [ItemHandle::Entry(gone)]);
        assert!(s.find_id(&id, true).unwrap().is_empty());
        s.purge(&[ItemHandle::Entry(gone)]).unwrap();
        assert!(s.find_id(&g_id, true).unwrap().is_empty());
        assert!(s.find_id(&g_id, false).unwrap().is_empty());
    }

    #[test]
    fn views_listing_and_search() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let work = add_group(&s, root, "Work");
        let home = add_group(&s, root, "Home");
        for t in ["beta", "GitHub", "Zulu"] {
            add_entry(&s, work, t);
        }
        let l = s.list(root).unwrap();
        let names: Vec<_> = l
            .groups
            .iter()
            .map(|g| g.name.expose().to_owned())
            .collect();
        // Appended in creation order (fractional keys).
        assert_eq!(names, ["Work", "Home"]);
        assert!(l.entries.is_empty());
        let l = s.list(work).unwrap();
        assert_eq!(titles(&l.entries), ["beta", "GitHub", "Zulu"]);
        let gh = &l.entries[1];
        let shown: Vec<_> = gh
            .fields
            .iter()
            .map(|f| f.value.expose().to_owned())
            .collect();
        assert_eq!(shown, ["alice", "https://github.com/login"]);
        assert!(s.list(home).unwrap().entries.is_empty());

        // Every entry's URL names github.com.
        assert_eq!(hits(&s, "GITHUB"), ["e:beta", "e:GitHub", "e:Zulu"]);
        assert_eq!(hits(&s, "ZUL"), ["e:Zulu"]);
        assert_eq!(hits(&s, "alice").len(), 3);
        assert_eq!(hits(&s, "wor"), ["g:Work"]);
        for never in ["hunter2", "xyzzy", "memo"] {
            assert!(hits(&s, never).is_empty(), "{never}");
        }
        assert_eq!(err(s.search("")), CoreError::InvalidInput);
        assert_eq!(
            err(s.search(&"a".repeat(MAX_QUERY_BYTES + 1))),
            CoreError::InvalidInput
        );
        assert!(s.search(&"a".repeat(MAX_QUERY_BYTES)).unwrap().is_empty());

        let o = s.overview().unwrap();
        assert_eq!((o.entries, o.groups, o.in_trash, o.conflicts), (3, 2, 0, 0));
        assert_eq!(o.local_seq, 6);
        assert!(s.recovered().unwrap().is_empty());
        assert!(s.trash().unwrap().is_empty());
        assert!(s.conflicts().unwrap().is_empty());
        assert_eq!(format!("{o:?}"), "Overview(<redacted>)");
        assert_eq!(format!("{:?}", l.entries[0]), "EntrySummary(<redacted>)");
    }

    #[test]
    fn views_details_and_reveal() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let e = add_entry(&s, root, "GitHub");
        let d = s.entry(e).unwrap();
        assert_eq!(d.title.expose(), "GitHub");
        assert_eq!(d.notes.as_ref().unwrap().expose(), "xyzzy notes");
        assert_eq!(d.group, Some(root));
        let pass = d
            .fields
            .iter()
            .find(|f| f.name.expose() == "Password")
            .unwrap();
        assert!(pass.protected && pass.value.is_none());
        let user = d
            .fields
            .iter()
            .find(|f| f.name.expose() == "Username")
            .unwrap();
        assert_eq!(user.value.as_ref().unwrap().expose_secret(), b"alice");
        assert_eq!(s.reveal(pass.handle).unwrap().expose_secret(), b"hunter2");
        assert_eq!(s.entry_versions(e).unwrap().len(), 1);
        assert_eq!(format!("{d:?}"), "EntryDetail(<redacted>)");

        // After an edit the old version's field handle is stale.
        let old = pass.handle;
        let mut draft = s.edit_entry(e).unwrap();
        draft.entry_mut().title = qv_model::Text::new("GitHub 2").unwrap();
        s.save_entry(draft).unwrap();
        assert_eq!(err(s.reveal(old)), CoreError::StaleHandle);

        let g = s.group(root).unwrap();
        assert_eq!(g.name.expose(), crate::testutil::NAME);
        assert_eq!(g.parent, None);
        assert_eq!(g.shown_parent, None);
    }

    #[test]
    fn views_totp() {
        let env = Env::new();
        let s = env.unlock();
        let root = s.root().unwrap();
        let mut d = s.new_entry(root, "login", "2FA").unwrap();
        // RFC 6238 appendix B, SHA-1, 8 digits.
        let uri = "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8";
        d.add_field("OTP", FieldKind::Totp, FieldValue::text(uri).unwrap())
            .unwrap();
        d.add_field("User", FieldKind::Text, FieldValue::text("bob").unwrap())
            .unwrap();
        let e = s.save_entry(d).unwrap();
        let detail = s.entry(e).unwrap();
        let otp = &detail.fields[0];
        assert!(otp.protected && otp.value.is_none());
        env.time.set(59_000);
        let now = s.totp(otp.handle).unwrap();
        assert_eq!(now.code.expose_secret(), "94287082");
        assert_eq!(now.seconds_remaining, 1);
        assert_eq!(
            err(s.totp(detail.fields[1].handle)),
            CoreError::InvalidInput
        );
    }

    #[test]
    fn views_generator_defaults() {
        let env = Env::new();
        let s = env.unlock();
        assert_eq!(
            s.generator_defaults().unwrap(),
            GeneratorSettings::default()
        );
        assert_eq!(s.generate(None).unwrap().expose_secret().len(), 24);
        let pin = GeneratorSettings::Pin(PinSettings { length: 8 });
        assert_eq!(s.generate(Some(&pin)).unwrap().expose_secret().len(), 8);
        let set = |settings: GeneratorSettings| {
            let mut d = s.edit_settings().unwrap();
            d.meta_mut().settings.generator = Some(GeneratorDefaults {
                settings,
                ext: qv_model::Extensions::new(),
            });
            s.save_settings(d).unwrap();
        };
        set(pin.clone());
        let g = s.generate(None).unwrap();
        assert!(
            g.expose_secret().len() == 8 && g.expose_secret().bytes().all(|b| b.is_ascii_digit())
        );
        // Stored defaults are revalidated at use (0010 §2.1.3).
        set(GeneratorSettings::Pin(PinSettings { length: 2 }));
        assert_eq!(
            err(s.generate(None)),
            CoreError::Generator(GeneratorError::LengthOutOfRange)
        );
        assert_eq!(
            err(crate::generate(&GeneratorSettings::Pin(PinSettings {
                length: 2
            }))),
            CoreError::Generator(GeneratorError::LengthOutOfRange)
        );
        assert!(crate::estimate(&pin).unwrap().bits > 26.0);
    }
}
