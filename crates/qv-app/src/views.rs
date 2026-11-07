// SPDX-License-Identifier: AGPL-3.0-or-later

//! Display data read through core for one render. Vault text is copied into
//! zeroizing strings and rendered only as escaped text. Protected values are
//! never included: they reach the renderer only through a 30 s reveal.
//! No type here derives `Debug` or `Display`.
use qv_core::{
    AttachmentHandle, ConflictDetails, CoreError, Deletion, EntryHandle, FieldHandle, FieldId,
    FieldKind, GroupHandle, ItemHandle, RecordKind, Session, Text, Timestamp,
};
use zeroize::Zeroizing;

/// Owned vault text for one render.
pub type Z = Zeroizing<String>;
fn z(s: &str) -> Z {
    Zeroizing::new(s.to_owned())
}
/// UTC date and time for display only.
pub fn date(t: Timestamp) -> String {
    let secs = t.0.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        tod / 3600,
        tod % 3600 / 60
    )
}
/// A field kind's display name.
pub fn kind_name(k: FieldKind) -> &'static str {
    match k {
        FieldKind::Text => "Text",
        FieldKind::Secret => "Secret",
        FieldKind::Url => "URL",
        FieldKind::Email => "Email",
        FieldKind::Totp => "TOTP",
        FieldKind::Multiline => "Multi-line",
        FieldKind::Date => "Date",
        _ => "Other",
    }
}
/// A group row.
#[derive(Clone, PartialEq)]
pub struct GroupRow {
    /// The group.
    pub handle: GroupHandle,
    /// Its name.
    pub name: Z,
    /// The colour the user chose (0003 §5.5), else automatic.
    pub colour: Option<u8>,
    /// It has conflicting versions.
    pub conflict: bool,
}
/// An entry row: title plus the first non-protected field.
#[derive(Clone, PartialEq)]
pub struct EntryRow {
    /// The entry.
    pub handle: EntryHandle,
    /// Its title.
    pub title: Z,
    /// First non-protected text/URL/email value.
    pub subtitle: Z,
    /// The colour the user chose (0003 §5.5), else automatic.
    pub colour: Option<u8>,
    /// It has conflicting versions.
    pub conflict: bool,
}
fn entry_row(e: &qv_core::EntrySummary) -> EntryRow {
    EntryRow {
        handle: e.handle,
        title: z(e.title.expose()),
        subtitle: e
            .fields
            .first()
            .map_or_else(|| z(""), |f| z(f.value.expose())),
        colour: crate::editor::colour(e.icon.as_ref().map(Text::expose)),
        conflict: e.conflict,
    }
}
fn group_row(g: &qv_core::GroupSummary) -> GroupRow {
    GroupRow {
        handle: g.handle,
        name: z(g.name.expose()),
        colour: crate::editor::colour(g.icon.as_ref().map(Text::expose)),
        conflict: g.conflict,
    }
}
/// The vault at a glance.
#[derive(Clone, PartialEq)]
pub struct OverviewView {
    /// Vault name.
    pub name: Z,
    /// Live entries.
    pub entries: usize,
    /// Live groups.
    pub groups: usize,
    /// Items in trash.
    pub trash: usize,
    /// Conflicted records.
    pub conflicts: usize,
}
/// Read the overview.
pub fn overview(s: &Session) -> Result<OverviewView, CoreError> {
    let o = s.overview()?;
    Ok(OverviewView {
        name: z(o.name.expose()),
        entries: o.entries,
        groups: o.groups,
        trash: o.in_trash,
        conflicts: o.conflicts,
    })
}
/// One group's children with a bounded breadcrumb trail.
#[derive(Clone, PartialEq)]
pub struct BrowseView {
    /// The shown group.
    pub here: GroupHandle,
    /// It is the root.
    pub root: bool,
    /// Ancestors from the root, then this group.
    pub crumbs: Vec<(GroupHandle, Z)>,
    /// Child groups.
    pub groups: Vec<GroupRow>,
    /// Entries.
    pub entries: Vec<EntryRow>,
    /// Entries whose group is missing (root only).
    pub recovered: usize,
}
/// Read a group listing.
pub fn browse(s: &Session, group: Option<GroupHandle>) -> Result<BrowseView, CoreError> {
    let root = s.root()?;
    let here = group.unwrap_or(root);
    let listing = s.list(here)?;
    let mut crumbs = Vec::new();
    let mut at = Some(here);
    while let Some(g) = at {
        if crumbs.len() >= 64 {
            break;
        }
        let d = s.group(g)?;
        crumbs.push((g, z(d.name.expose())));
        at = d.shown_parent;
    }
    crumbs.reverse();
    let recovered = if here == root {
        s.recovered()?.len()
    } else {
        0
    };
    Ok(BrowseView {
        here,
        root: here == root,
        crumbs,
        groups: listing.groups.iter().map(group_row).collect(),
        entries: listing.entries.iter().map(entry_row).collect(),
        recovered,
    })
}
/// An item for the "All items", type and group lists (plan 0040 R6).
#[derive(Clone, PartialEq)]
pub struct ItemRow {
    /// Title, subtitle and handle, as in group listings.
    pub row: EntryRow,
    /// The entry's type hint (`login`, `note`, …), lower-cased; UI only.
    pub kind: Z,
    /// Its groups from the top level down to its own; empty at the root.
    pub path: Vec<GroupHandle>,
    /// The top-level group's name, or empty.
    pub top_name: Z,
}
/// The groups directly under the root, for the sidebar.
pub fn top_groups(s: &Session) -> Result<Vec<GroupRow>, CoreError> {
    Ok(s.list(s.root()?)?.groups.iter().map(group_row).collect())
}
/// Every live entry in the tree (and recovered ones), with its group path,
/// walked through the existing listings; at most 64 levels deep.
pub fn all_items(s: &Session) -> Result<Vec<ItemRow>, CoreError> {
    let root = s.root()?;
    let mut out = Vec::new();
    let mut stack: Vec<(GroupHandle, Vec<GroupHandle>, Z)> = vec![(root, Vec::new(), z(""))];
    while let Some((g, path, top)) = stack.pop() {
        let listing = s.list(g)?;
        for e in &listing.entries {
            out.push(item(e, path.clone(), top.clone()));
        }
        if path.len() < 64 {
            for child in &listing.groups {
                let mut deeper = path.clone();
                deeper.push(child.handle);
                let top = if path.is_empty() {
                    z(child.name.expose())
                } else {
                    top.clone()
                };
                stack.push((child.handle, deeper, top));
            }
        }
    }
    for e in s.recovered()? {
        out.push(item(&e, Vec::new(), z("")));
    }
    let mut keyed: Vec<(Z, ItemRow)> = out
        .into_iter()
        .map(|r| (Zeroizing::new(r.row.title.to_lowercase()), r))
        .collect();
    keyed.sort_by(|a, b| a.0.as_str().cmp(b.0.as_str()));
    Ok(keyed.into_iter().map(|k| k.1).collect())
}
fn item(e: &qv_core::EntrySummary, path: Vec<GroupHandle>, top_name: Z) -> ItemRow {
    ItemRow {
        row: entry_row(e),
        kind: Zeroizing::new(e.type_hint.expose().to_lowercase()),
        path,
        top_name,
    }
}
/// The first non-protected and first protected field handles of an entry,
/// for quick copy from a list row (handles are read at click time).
pub fn quick_fields(
    s: &Session,
    e: EntryHandle,
) -> Result<(Option<qv_core::FieldHandle>, Option<qv_core::FieldHandle>), CoreError> {
    let v = entry(s, e)?;
    if v.versions > 1 {
        return Ok((None, None));
    }
    let user = v
        .fields
        .iter()
        .find(|f| !f.protected && f.kind != FieldKind::Totp)
        .map(|f| f.handle);
    let secret = v
        .fields
        .iter()
        .find(|f| f.protected && f.kind != FieldKind::Totp)
        .map(|f| f.handle);
    Ok((user, secret))
}
/// Entries whose group is missing.
pub fn recovered(s: &Session) -> Result<Vec<EntryRow>, CoreError> {
    Ok(s.recovered()?.iter().map(entry_row).collect())
}
/// Search over non-protected data (core bounds the query).
pub fn search(s: &Session, query: &str) -> Result<(Vec<GroupRow>, Vec<EntryRow>), CoreError> {
    let mut groups = Vec::new();
    let mut entries = Vec::new();
    if query.is_empty() {
        return Ok((groups, entries));
    }
    for hit in s.search(query)? {
        match hit {
            qv_core::SearchHit::Group(g) => groups.push(group_row(&g)),
            qv_core::SearchHit::Entry(e) => entries.push(entry_row(&e)),
        }
    }
    Ok((groups, entries))
}
/// One displayed field.
#[derive(Clone, PartialEq)]
pub struct FieldRow {
    /// The field of this version.
    pub handle: FieldHandle,
    /// Stable field ID.
    pub id: FieldId,
    /// Its name.
    pub name: Z,
    /// Its kind.
    pub kind: FieldKind,
    /// Shown only through a reveal.
    pub protected: bool,
    /// Non-protected value as text.
    pub value: Option<Z>,
}
fn field_rows(fields: &[qv_core::FieldDetail]) -> Vec<FieldRow> {
    fields
        .iter()
        .map(|f| FieldRow {
            handle: f.handle,
            id: f.handle.field_id(),
            name: z(f.name.expose()),
            kind: f.kind,
            protected: f.protected,
            value: f
                .value
                .as_ref()
                .filter(|_| !f.protected)
                .map(|v| Zeroizing::new(String::from_utf8_lossy(v.expose_secret()).into_owned())),
        })
        .collect()
}
/// One entry version.
#[derive(Clone, PartialEq)]
pub struct EntryView {
    /// The entry.
    pub handle: EntryHandle,
    /// Title.
    pub title: Z,
    /// Type hint.
    pub type_hint: Z,
    /// Displayed group, if any.
    pub group: Option<GroupHandle>,
    /// Active versions (more than one is a conflict).
    pub versions: usize,
    /// Fields in order.
    pub fields: Vec<FieldRow>,
    /// Notes.
    pub notes: Option<Z>,
    /// Created (display only).
    pub created: String,
    /// Modified (display only).
    pub modified: String,
    /// Expiry.
    pub expires: Option<String>,
    /// In trash.
    pub deleted: bool,
    /// Current attachments.
    pub attachments: usize,
    /// The colour the user chose (0003 §5.5), else automatic.
    pub colour: Option<u8>,
}
fn entry_view(d: &qv_core::EntryDetail, versions: usize, attachments: usize) -> EntryView {
    EntryView {
        handle: d.handle,
        title: z(d.title.expose()),
        type_hint: z(d.type_hint.expose()),
        group: d.group,
        versions,
        fields: field_rows(&d.fields),
        notes: d.notes.as_ref().map(|n| z(n.expose())),
        created: date(d.created_at),
        modified: date(d.modified_at),
        expires: d.expires_at.map(date),
        deleted: d.deleted_at.is_some(),
        attachments,
        colour: crate::editor::colour(d.icon.as_ref().map(Text::expose)),
    }
}
/// Read one entry.
pub fn entry(s: &Session, e: EntryHandle) -> Result<EntryView, CoreError> {
    let d = s.entry(e)?;
    let versions = s.entry_versions(e)?.len();
    let attachments = s.attachments(e).map(|a| a.len()).unwrap_or(0);
    Ok(entry_view(&d, versions, attachments))
}
/// A saved card's face for its page: the number is read in place for its
/// brand, last four digits and validity only (0009 §1.8).
pub fn card_face(s: &Session, v: &EntryView) -> Option<CardFace> {
    use crate::editor::{self, CARD_NUMBER, EXPIRES, ItemType, same_slot};
    if ItemType::from_hint(&v.type_hint) != Some(ItemType::Card) {
        return None;
    }
    let named = |name: &str| v.fields.iter().find(|f| same_slot(&f.name, name));
    let info = named(CARD_NUMBER)
        .and_then(|f| s.reveal(f.handle).ok())
        .map(|n| editor::CardInfo::of(n.expose_secret()))
        .unwrap_or_default();
    let plain = |name: &str| {
        named(name)
            .and_then(|f| f.value.clone())
            .unwrap_or_else(|| z(""))
    };
    let expiry = plain(EXPIRES);
    Some(CardFace {
        info,
        name: plain("Name on card"),
        left: editor::expiry(&expiry, editor::this_month()),
        expiry: Zeroizing::new(editor::expiry_shown(&expiry)),
    })
}
/// A trash row.
#[derive(Clone, PartialEq)]
pub struct TrashRow {
    /// The item.
    pub item: ItemHandle,
    /// Title or name.
    pub name: Z,
    /// When deleted.
    pub deleted: Option<String>,
    /// Delete/edit race.
    pub conflict: bool,
}
/// Trash contents and expiry state.
#[derive(Clone, PartialEq)]
pub struct TrashView {
    /// Items.
    pub items: Vec<TrashRow>,
    /// Expired, non-conflicted items.
    pub expired: usize,
    /// Vault dates are ahead of this clock.
    pub clock_anomaly: bool,
}
/// Read the trash.
pub fn trash(s: &Session) -> Result<TrashView, CoreError> {
    let items = s
        .trash()?
        .iter()
        .map(|t| TrashRow {
            item: t.item,
            name: z(t.name.expose()),
            deleted: t.deleted_at.map(date),
            conflict: t.conflict,
        })
        .collect();
    let expiry = s.expired_trash()?;
    Ok(TrashView {
        items,
        expired: expiry.expired.len(),
        clock_anomaly: expiry.clock_anomaly,
    })
}
/// A retained version.
#[derive(Clone, PartialEq)]
pub struct HistoryRow {
    /// Full version ID.
    pub version: String,
    /// Modified.
    pub modified: String,
    /// Concurrent with another retained version.
    pub conflict: bool,
    /// Changed properties and field names.
    pub changed: Vec<Z>,
}
/// Read an entry's retained history, newest first.
pub fn history(s: &Session, e: EntryHandle) -> Result<Vec<HistoryRow>, CoreError> {
    Ok(s.history(e)?
        .iter()
        .map(|h| HistoryRow {
            version: h.handle.version_hex(),
            modified: date(h.modified_at),
            conflict: h.conflict,
            changed: h
                .changed_properties
                .iter()
                .map(|p| z(p.expose()))
                .chain(h.changed_fields.iter().map(|(_, n)| z(n.expose())))
                .collect(),
        })
        .collect())
}
/// Read one retained version.
pub fn history_version(s: &Session, e: EntryHandle, version: &str) -> Result<EntryView, CoreError> {
    let h = crate::ops::history_handle(s, e, version)?;
    Ok(entry_view(&s.history_entry(h)?, 1, 0))
}
/// A conflicted record.
#[derive(Clone, PartialEq)]
pub struct ConflictRow {
    /// Full record ID.
    pub record: String,
    /// Record kind label.
    pub kind: &'static str,
    /// Display name for entries and groups, when known.
    pub name: Option<Z>,
    /// Active versions.
    pub versions: usize,
}
fn kind_label(k: RecordKind) -> &'static str {
    match k {
        RecordKind::Entry => "Entry",
        RecordKind::Group => "Group",
        RecordKind::VaultMeta => "Vault settings",
        RecordKind::AttachmentMeta => "Attachment",
        RecordKind::PasswordKeyslot => "Password slot",
    }
}
/// Read all conflicted records.
pub fn conflicts(s: &Session) -> Result<Vec<ConflictRow>, CoreError> {
    let names: Vec<(String, Z)> = s
        .conflicts()?
        .iter()
        .map(|c| (c.item.id_hex(), z(c.name.expose())))
        .collect();
    Ok(s.conflict_records()?
        .iter()
        .map(|r| {
            let id = r.handle.id_hex();
            ConflictRow {
                name: names.iter().find(|(i, _)| *i == id).map(|(_, n)| n.clone()),
                record: id,
                kind: kind_label(r.kind),
                versions: r.versions,
            }
        })
        .collect())
}
/// One active version of a conflicted record.
#[derive(Clone, PartialEq)]
pub struct VersionView {
    /// Full version ID.
    pub version: String,
    /// Deletion state label.
    pub state: &'static str,
    /// Modified.
    pub modified: String,
    /// Labelled non-protected details.
    pub details: Vec<(&'static str, Z)>,
    /// Entry fields (protected values only through a reveal).
    pub fields: Vec<FieldRow>,
    /// Choosing it needs that version's master password.
    pub needs_password: bool,
    /// Unknown optional values are present and preserved.
    pub unknown: bool,
}
/// Read the versions of one conflicted record.
pub fn conflict_record(s: &Session, record: &str) -> Result<Vec<VersionView>, CoreError> {
    let [r] = s.conflict_matches(record)?[..] else {
        return Err(CoreError::NotFound);
    };
    let mut out = Vec::new();
    for h in s.conflict_versions(r)? {
        let v = s.conflict_version(&h)?;
        let mut details = Vec::new();
        let mut fields = Vec::new();
        let mut needs_password = false;
        match &v.details {
            ConflictDetails::Entry { detail, .. } => {
                details.push(("Title", z(detail.title.expose())));
                details.push(("Type", z(detail.type_hint.expose())));
                if let Some(n) = &detail.notes {
                    details.push(("Notes", z(n.expose())));
                }
                fields = field_rows(&detail.fields);
            }
            ConflictDetails::Group(g) => {
                details.push(("Name", z(g.name.expose())));
                if let Some(n) = &g.notes {
                    details.push(("Notes", z(n.expose())));
                }
            }
            ConflictDetails::VaultMeta(m) => {
                details.push(("Vault name", z(m.name.expose())));
                if let Some(d) = &m.description {
                    details.push(("Description", z(d.expose())));
                }
                details.push((
                    "History depth",
                    z(&m.settings
                        .history_depth
                        .map_or("default".into(), |n| n.to_string())),
                ));
                details.push((
                    "Trash retention days",
                    z(&m.settings
                        .trash_retention_days
                        .map_or("default".into(), |n| n.to_string())),
                ));
            }
            ConflictDetails::Attachment {
                name, mime, size, ..
            } => {
                details.push(("Name", z(name.expose())));
                details.push(("MIME type", z(mime.expose())));
                details.push(("Size", z(&format!("{size} bytes"))));
            }
            ConflictDetails::PasswordSlot { slot_id, .. } => {
                details.push(("Slot", z(slot_id)));
                needs_password = true;
            }
            ConflictDetails::Tombstone(k) => {
                details.push(("Permanently deleted", z(kind_label(*k))));
            }
        }
        out.push(VersionView {
            version: h.version_hex(),
            state: match v.state {
                Deletion::Live => "Live",
                Deletion::SoftDeleted => "In trash",
                Deletion::Final => "Permanently deleted",
            },
            modified: date(v.modified_at),
            details,
            fields,
            needs_password,
            unknown: v.unknown_extensions,
        });
    }
    Ok(out)
}
/// An attachment row (no content or hash).
#[derive(Clone, PartialEq)]
pub struct AttachmentRow {
    /// The attachment.
    pub handle: AttachmentHandle,
    /// Untrusted name, shown as text.
    pub name: Z,
    /// Declared MIME type, never sniffed or executed.
    pub mime: Z,
    /// Size in bytes.
    pub size: u64,
    /// Conflicting metadata heads.
    pub conflicted: bool,
}
/// Read an entry's attachments.
pub fn attachments(s: &Session, e: EntryHandle) -> Result<Vec<AttachmentRow>, CoreError> {
    Ok(s.attachments(e)?
        .iter()
        .map(|a| AttachmentRow {
            handle: a.handle,
            name: z(a.name.expose()),
            mime: z(a.mime.expose()),
            size: a.size,
            conflicted: a.conflicted,
        })
        .collect())
}
/// A local snapshot row.
#[derive(Clone, PartialEq)]
pub struct SnapshotRow {
    /// Archive ID.
    pub id: String,
    /// Created.
    pub created: String,
    /// Kind label.
    pub kind: &'static str,
    /// Bytes on disk.
    pub size: u64,
}
/// Read local snapshots and the unreadable count.
pub fn snapshots(s: &Session) -> Result<(Vec<SnapshotRow>, u64), CoreError> {
    let l = s.snapshots()?;
    Ok((
        l.snapshots
            .iter()
            .map(|x| SnapshotRow {
                id: x.archive_id.clone(),
                created: date(x.created_at),
                kind: x.kind.label(),
                size: x.size,
            })
            .collect(),
        l.unreadable,
    ))
}
/// Unverified public header fields.
#[derive(Clone, PartialEq)]
pub struct AboutView {
    /// Vault ID.
    pub vault_id: String,
    /// Key generation.
    pub key_generation: u32,
    /// KDF memory in MiB, iterations and lanes.
    pub kdf: (u32, u32, u32),
    /// Format number.
    pub format: u32,
}
/// Read the unverified header of the open vault.
pub fn about(core: &qv_core::Core, path: &std::path::Path) -> Result<AboutView, CoreError> {
    let i = core.inspect(path)?;
    Ok(AboutView {
        vault_id: i.vault_id,
        key_generation: i.key_generation,
        kdf: (i.kdf.memory_kib / 1024, i.kdf.iterations, i.kdf.parallelism),
        format: i.schema_version,
    })
}
/// One entry-form row. Protected values are never included.
#[derive(Clone, PartialEq)]
pub struct FormRow {
    /// Index in the draft.
    pub index: u16,
    /// Field name.
    pub name: Z,
    /// Kind.
    pub kind: FieldKind,
    /// Protected (value replaced, never prefilled).
    pub protected: bool,
    /// Non-protected current value.
    pub value: Option<Z>,
    /// A protected replacement is set.
    pub replaced: bool,
    /// The replacement was generated.
    pub generated: bool,
    /// The replacement was filled from the start box.
    pub filled: bool,
    /// Too large to edit in the app.
    pub too_large: bool,
    /// A protected value is saved (one bit; never the value).
    pub stored: bool,
    /// How the editor presents it.
    pub role: Role,
}
/// How the item editor presents a field (plan 0040 E5, E8, E9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// An ordinary input.
    Plain,
    /// A protected value with the generator.
    Password,
    /// A protected value without the generator.
    Hidden,
    /// A card's number (protected; brand, last four and validity shown).
    CardNumber,
    /// A card's `MM/YY` expiry.
    Expiry,
    /// A Wi‑Fi network's security choice.
    Security,
}
/// The start step's guess, without any card number (0009 §1.8).
#[derive(Clone, PartialEq)]
pub struct GuessView {
    /// The suggested type.
    pub kind: crate::editor::ItemType,
    /// Headline.
    pub line: Z,
    /// Second line.
    pub sub: Z,
}
/// A card's face: never the number, only what 0009 §1.8 allows.
#[derive(Clone, PartialEq)]
pub struct CardFace {
    /// Brand, last four and validity.
    pub info: crate::editor::CardInfo,
    /// Name on the card.
    pub name: Z,
    /// Expiry as typed.
    pub expiry: Z,
    /// Time left on the expiry and whether that is comfortable.
    pub left: Option<(String, bool)>,
}
/// A Wi‑Fi network's join card.
#[derive(Clone, PartialEq)]
pub struct WifiCard {
    /// Network name.
    pub name: Z,
    /// Security as stored (`WPA2`, `None`, …).
    pub security: Z,
}
/// The entry form.
#[derive(Clone, PartialEq)]
pub struct EntryFormView {
    /// A new entry.
    pub new: bool,
    /// Record ID (hex), for its stable colour.
    pub id: String,
    /// Title.
    pub title: Z,
    /// Type hint.
    pub type_hint: Z,
    /// Notes.
    pub notes: Z,
    /// Notes too large to edit here.
    pub notes_too_large: bool,
    /// Fields.
    pub rows: Vec<FormRow>,
    /// The "What are you saving?" step.
    pub start: bool,
    /// The start step's guess.
    pub guess: Option<GuessView>,
    /// The item type, when the hint is a known one.
    pub kind: Option<crate::editor::ItemType>,
    /// The chosen colour, else automatic.
    pub colour: Option<u8>,
    /// The entry's group.
    pub group: GroupHandle,
    /// The title used if the title stays empty, and where it comes from.
    pub auto_title: Option<(Z, &'static str)>,
    /// A card's face.
    pub card: Option<CardFace>,
    /// A Wi‑Fi network's join card.
    pub wifi: Option<WifiCard>,
    /// The kind (and protection) the typed new-field name suggests.
    pub new_kind: (FieldKind, bool),
    /// The last removed field's name, for Undo.
    pub removed: Option<Z>,
    /// The replacement whose eye is on (its control shows the typed text).
    pub showing: Option<u16>,
    /// A save would pass the naming checks (`editor::ready_to_save`).
    pub ready: bool,
}
fn text_of(f: &qv_core::Field) -> Z {
    Zeroizing::new(String::from_utf8_lossy(f.value.expose_secret()).into_owned())
}
fn role(kind: Option<crate::editor::ItemType>, f: &qv_core::Field) -> Role {
    use crate::editor::{CARD_NUMBER, EXPIRES, ItemType, SECURITY, same_slot};
    let name = f.name.expose();
    match kind {
        Some(ItemType::Card) if f.protected && same_slot(name, CARD_NUMBER) => {
            return Role::CardNumber;
        }
        Some(ItemType::Card) if !f.protected && same_slot(name, EXPIRES) => return Role::Expiry,
        Some(ItemType::Wifi) if !f.protected && same_slot(name, SECURITY) => return Role::Security,
        _ => {}
    }
    if !f.protected {
        return Role::Plain;
    }
    let lower = name.to_lowercase();
    let short = ["pin", "cvv", "cvc", "security code"]
        .iter()
        .any(|w| lower.contains(w));
    if f.kind == FieldKind::Secret && !short {
        Role::Password
    } else {
        Role::Hidden
    }
}
/// Build the entry form view, with the workspace's start box, new-field
/// name and reveal state.
pub(crate) fn entry_form_in(
    ws: &crate::workspace::Workspace,
    f: &crate::workspace::EntryForm,
) -> EntryFormView {
    use crate::editor::{self, ItemType};
    let mut v = entry_form(f);
    let e = f.draft.entry();
    let kind = ItemType::from_hint(e.type_hint.expose());
    v.kind = kind;
    for (row, field) in v.rows.iter_mut().zip(&e.fields) {
        row.role = role(kind, field);
    }
    v.guess = f
        .start
        .then(|| editor::guess(ws.input(crate::workspace::WsField::Start)))
        .flatten()
        .map(|g| GuessView {
            kind: g.kind,
            line: g.line,
            sub: g.sub,
        });
    let typed = ws
        .text(crate::workspace::WsField::NewFieldName)
        .unwrap_or_default();
    v.new_kind = editor::kind_for(typed);
    v.showing = v.rows.iter().map(|r| r.index).find(|i| {
        ws.revealed(&crate::workspace::RevealKey::Replacement(*i))
            .is_some()
    });
    let named = |name: &str| editor::find(&e.fields, name).map(|i| &e.fields[i]);
    v.card = (kind == Some(ItemType::Card)).then(|| {
        let number = editor::find(&e.fields, editor::CARD_NUMBER).map(|i| {
            let replaced = u16::try_from(i).ok().and_then(|k| f.replacements.get(&k));
            editor::CardInfo::of(match replaced {
                Some(r) => r.expose_secret(),
                None => e.fields[i].value.expose_secret(),
            })
        });
        let plain = |name: &str| {
            named(name)
                .filter(|x| !x.protected)
                .map(text_of)
                .unwrap_or_else(|| z(""))
        };
        let expiry = plain(editor::EXPIRES);
        CardFace {
            info: number.unwrap_or_default(),
            name: plain("Name on card"),
            left: editor::expiry(&expiry, editor::this_month()),
            expiry: Zeroizing::new(editor::expiry_shown(&expiry)),
        }
    });
    v.wifi = (kind == Some(ItemType::Wifi)).then(|| {
        let plain = |name: &str| {
            named(name)
                .filter(|x| !x.protected)
                .map(text_of)
                .unwrap_or_else(|| z(""))
        };
        WifiCard {
            name: plain(editor::NETWORK),
            security: plain(editor::SECURITY),
        }
    });
    v
}
/// Build the entry form view.
pub(crate) fn entry_form(f: &crate::workspace::EntryForm) -> EntryFormView {
    let e = f.draft.entry();
    EntryFormView {
        start: f.start,
        guess: None,
        kind: None,
        colour: crate::editor::colour(e.icon.as_ref().map(Text::expose)),
        group: f.draft.group(),
        auto_title: crate::editor::auto_title(f).map(|(t, from)| (Zeroizing::new(t), from)),
        card: None,
        wifi: None,
        new_kind: (FieldKind::Text, false),
        removed: f.removed.as_ref().map(|r| z(r.field.name.expose())),
        showing: None,
        ready: crate::editor::ready_to_save(f),
        new: f.new,
        id: f.draft.id_hex(),
        title: z(e.title.expose()),
        type_hint: z(e.type_hint.expose()),
        notes: if f.notes_too_large {
            z("")
        } else {
            e.notes.as_ref().map_or_else(|| z(""), |n| z(n.expose()))
        },
        notes_too_large: f.notes_too_large,
        rows: e
            .fields
            .iter()
            .enumerate()
            .filter_map(|(i, x)| {
                let index = u16::try_from(i).ok()?;
                let too_large = f.too_large.contains(&index);
                Some(FormRow {
                    index,
                    name: z(x.name.expose()),
                    kind: x.kind,
                    protected: x.protected,
                    value: (!x.protected && !too_large).then(|| {
                        Zeroizing::new(
                            String::from_utf8_lossy(x.value.expose_secret()).into_owned(),
                        )
                    }),
                    replaced: f.replacements.contains_key(&index),
                    generated: f.generated.contains(&index),
                    filled: f.filled.contains(&index),
                    too_large,
                    stored: x.protected && !x.value.expose_secret().is_empty(),
                    role: Role::Plain,
                })
            })
            .collect(),
    }
}
/// The group form.
#[derive(Clone, PartialEq)]
pub struct GroupFormView {
    /// A new group.
    pub new: bool,
    /// Record ID (hex), for its stable colour.
    pub id: String,
    /// Name.
    pub name: Z,
    /// The chosen colour, else automatic.
    pub colour: Option<u8>,
}
/// General settings form.
#[derive(Clone, PartialEq)]
pub struct SettingsView {
    /// Vault name.
    pub name: Z,
    /// Description.
    pub description: Z,
    /// History depth (blank = default).
    pub history_depth: String,
    /// Trash retention days (blank = default).
    pub trash_days: String,
}
/// Generator form.
#[derive(Clone, PartialEq)]
pub struct GeneratorView {
    /// Mode.
    pub mode: crate::workspace::GenMode,
    /// Character length.
    pub length: u32,
    /// Words.
    pub words: u32,
    /// PIN digits.
    pub pin: u32,
    /// Toggles: lower, upper, digits, symbols, ambiguous, capitalize, digit, require each.
    pub flags: [bool; 8],
    /// Separator.
    pub separator: String,
    /// Excluded characters.
    pub exclude: Z,
    /// Entropy of the current settings, when valid.
    pub bits: Option<f64>,
}
/// The recovery phrase screen.
#[derive(Clone, PartialEq)]
pub struct PhraseScreen {
    /// A prepared rotation (else a redisplay).
    pub rotation: bool,
    /// One-based requested positions.
    pub positions: [usize; 3],
    /// Words already confirmed (redisplay) or install allowed (rotation).
    pub confirmed: bool,
}
impl crate::controller::Controller {
    /// The entry form for the current epoch.
    pub fn entry_form(&self, epoch: crate::controller::FormEpoch) -> Option<EntryFormView> {
        self.peek(epoch, |ws| {
            ws.entry_form.as_ref().map(|f| entry_form_in(ws, f))
        })
        .flatten()
    }
    /// The group form for the current epoch.
    pub fn group_form(&self, epoch: crate::controller::FormEpoch) -> Option<GroupFormView> {
        self.peek(epoch, |ws| {
            ws.group_form.as_ref().map(|f| GroupFormView {
                new: f.new,
                id: f.draft.id_hex(),
                name: z(f.draft.group().name.expose()),
                colour: crate::editor::colour(f.draft.group().icon.as_ref().map(Text::expose)),
            })
        })
        .flatten()
    }
    /// The general settings form.
    pub fn settings_form(&self, epoch: crate::controller::FormEpoch) -> Option<SettingsView> {
        self.peek(epoch, |ws| {
            ws.settings.as_ref().map(|d| {
                let m = d.meta();
                SettingsView {
                    name: z(m.name.expose()),
                    description: m
                        .description
                        .as_ref()
                        .map_or_else(|| z(""), |t| z(t.expose())),
                    history_depth: m
                        .settings
                        .history_depth
                        .map_or(String::new(), |n| n.to_string()),
                    trash_days: m
                        .settings
                        .trash_retention_days
                        .map_or(String::new(), |n| n.to_string()),
                }
            })
        })
        .flatten()
    }
    /// The generator form.
    pub fn generator_form(&self, epoch: crate::controller::FormEpoch) -> Option<GeneratorView> {
        self.peek(epoch, |ws| {
            let g = &ws.generator;
            GeneratorView {
                mode: g.mode,
                length: g.length,
                words: g.words,
                pin: g.pin,
                flags: g.flags,
                separator: g.separator.to_string(),
                exclude: g.exclude.clone(),
                bits: qv_core::estimate(&crate::ops::settings_from(g))
                    .ok()
                    .map(|e| e.bits),
            }
        })
    }
    /// The redisplayed phrase screen state; words come from [`Self::phrase_words`].
    pub fn phrase_screen(&self, epoch: crate::controller::FormEpoch) -> Option<PhraseScreen> {
        self.peek(epoch, |ws| {
            ws.phrase.as_ref().map(|p| match p {
                crate::workspace::PhraseView::Redisplay {
                    positions,
                    confirmed,
                    ..
                } => PhraseScreen {
                    rotation: false,
                    positions: positions.map(|n| n + 1),
                    confirmed: *confirmed,
                },
            })
        })
        .flatten()
    }
    /// The redisplayed phrase, copied into a protected buffer for rendering.
    pub fn phrase_words(
        &self,
        epoch: crate::controller::FormEpoch,
    ) -> Option<qv_core::SecretBytes> {
        self.peek(epoch, |ws| {
            let crate::workspace::PhraseView::Redisplay { phrase, .. } = ws.phrase.as_ref()?;
            crate::workspace::protect(phrase.expose_secret().as_bytes()).ok()
        })
        .flatten()
    }
    /// Notice, error and report for the current screen.
    pub fn status(
        &self,
        epoch: crate::controller::FormEpoch,
    ) -> Option<(
        Option<&'static str>,
        Option<crate::controller::AppError>,
        Option<crate::workspace::Report>,
    )> {
        self.peek(epoch, |ws| (ws.notice, ws.error, ws.report.clone()))
    }
    /// The unverified header read before this unlock, for Settings → About.
    pub fn about(&self, epoch: crate::controller::FormEpoch) -> Option<AboutView> {
        self.peek(epoch, |_| ())?;
        self.state().about.clone()
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn views_date_is_utc_civil_time() {
        assert_eq!(super::date(qv_core::Timestamp(0)), "1970-01-01 00:00 UTC");
        assert_eq!(
            super::date(qv_core::Timestamp(951_782_400_000 + 3_661_000)),
            "2000-02-29 01:01 UTC"
        );
    }
}
