// SPDX-License-Identifier: AGPL-3.0-or-later

//! Display data read through core for one render. Vault text is copied into
//! zeroizing strings and rendered only as escaped text. Protected values are
//! never included: they reach the renderer only through a 30 s reveal.
//! No type here derives `Debug` or `Display`.
use qv_core::{
    AttachmentHandle, ConflictDetails, CoreError, Deletion, EntryHandle, FieldHandle, FieldId,
    FieldKind, GroupHandle, ItemHandle, RecordKind, Session, Timestamp,
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
        conflict: e.conflict,
    }
}
fn group_row(g: &qv_core::GroupSummary) -> GroupRow {
    GroupRow {
        handle: g.handle,
        name: z(g.name.expose()),
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
    }
}
/// Read one entry.
pub fn entry(s: &Session, e: EntryHandle) -> Result<EntryView, CoreError> {
    let d = s.entry(e)?;
    let versions = s.entry_versions(e)?.len();
    let attachments = s.attachments(e).map(|a| a.len()).unwrap_or(0);
    Ok(entry_view(&d, versions, attachments))
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
    /// Too large to edit in the app.
    pub too_large: bool,
}
/// The entry form.
#[derive(Clone, PartialEq)]
pub struct EntryFormView {
    /// A new entry.
    pub new: bool,
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
}
/// Build the entry form view.
pub(crate) fn entry_form(f: &crate::workspace::EntryForm) -> EntryFormView {
    let e = f.draft.entry();
    EntryFormView {
        new: f.new,
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
                    too_large,
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
    /// Name.
    pub name: Z,
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
    /// Toggles: lower, upper, digits, symbols, ambiguous, capitalize, digit.
    pub flags: [bool; 7],
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
        self.peek(epoch, |ws| ws.entry_form.as_ref().map(entry_form))
            .flatten()
    }
    /// The group form for the current epoch.
    pub fn group_form(&self, epoch: crate::controller::FormEpoch) -> Option<GroupFormView> {
        self.peek(epoch, |ws| {
            ws.group_form.as_ref().map(|f| GroupFormView {
                new: f.new,
                name: z(f.draft.group().name.expose()),
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
