// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unlocked operations behind the typed actions. Each follows the CLI command
//! semantics (0011 §4) through qv-core only: conflict refusals, confirmations,
//! the mandatory recovery snapshot before permanent deletion (0007 §3), and
//! explicit consent before that snapshot exceeds its budget.
use crate::controller::{AppError, Controller, FormEpoch, State};
use crate::editor::ItemType;
use crate::workspace::{
    Apply, CopyKey, EntryForm, GenFlag, GenMode, GroupForm, LINE_MAX, MULTI_MAX, Pane, PhraseView,
    Report, RevealKey, Screen, Workspace, WsAction, WsField, on_ws, protect,
};
use ctutils::CtEq;
use qv_core::{
    CancelToken, CoreError, Deletion, EntryHandle, FieldKind, FieldValue, MasterPassword,
    PasswordVerdict, Session,
};
use std::path::{Path, PathBuf};

/// Fixed anchor label for verification reports.
fn anchor_label(a: qv_core::AnchorStatus) -> &'static str {
    match a {
        qv_core::AnchorStatus::Verified => "verified",
        qv_core::AnchorStatus::Advanced => "advanced",
        qv_core::AnchorStatus::Missing => "missing",
        qv_core::AnchorStatus::Mismatch => "mismatch",
        _ => "unknown",
    }
}
fn note_label(n: qv_core::VerifyNote) -> &'static str {
    match n {
        qv_core::VerifyNote::SuppressionFloorCoversDominatedVersions => {
            "suppression-floor-covers-dominated-versions"
        }
        _ => "note",
    }
}
/// A conflicted record's chosen version is a permanent deletion.
pub(crate) fn is_final_deletion(
    s: &Session,
    record: &str,
    version: &str,
) -> Result<bool, CoreError> {
    let v = conflict_version(s, record, version)?;
    Ok(s.conflict_version(&v)?.state == Deletion::Final)
}
fn conflict_version(
    s: &Session,
    record: &str,
    version: &str,
) -> Result<qv_core::ConflictVersionHandle, CoreError> {
    let [r] = s.conflict_matches(record)?[..] else {
        return Err(CoreError::NotFound);
    };
    s.conflict_versions(r)?
        .into_iter()
        .find(|v| v.version_hex() == version)
        .ok_or(CoreError::NotFound)
}
pub(crate) fn history_handle(
    s: &Session,
    entry: EntryHandle,
    version: &str,
) -> Result<qv_core::HistoryHandle, CoreError> {
    s.history(entry)?
        .into_iter()
        .find(|h| h.handle.version_hex() == version)
        .map(|h| h.handle)
        .ok_or(CoreError::NotFound)
}
fn password(ws: &Workspace, field: WsField) -> Result<MasterPassword, AppError> {
    MasterPassword::from_utf8(ws.input(field)).map_err(|_| AppError::InvalidInput)
}
/// An absolute local path from the path input (Linux), never a relative or
/// oversized one. The file helpers or core then apply no-follow rules.
fn local_path(ws: &Workspace) -> Result<PathBuf, AppError> {
    let path = PathBuf::from(ws.text(WsField::Path)?);
    if !path.is_absolute() {
        return Err(AppError::InvalidInput);
    }
    Ok(path)
}
/// Target for a restored snapshot: an absolute `.qvault` path on Linux, or a
/// plain file name inside the app's private vault directory on Android.
pub(crate) fn restore_target(base: &Path, ws: &Workspace) -> Result<PathBuf, AppError> {
    let input = ws.text(WsField::Path)?;
    if cfg!(target_os = "android") {
        let ok = !input.is_empty()
            && input.len() <= 200
            && input
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'-' || b == b'_');
        if !ok {
            return Err(AppError::InvalidInput);
        }
        return Ok(base.join("vaults").join(format!("{input}.qvault")));
    }
    local_path(ws)
}
/// A text field value; model refusals become a data-free input error.
fn field_value(text: &str) -> Result<FieldValue, AppError> {
    FieldValue::text(text).map_err(|_| AppError::InvalidInput)
}
/// Append an empty field with this protection to the open entry form.
fn add_field(
    ws: &mut Workspace,
    name: &str,
    kind: FieldKind,
    protected: bool,
) -> Result<(), AppError> {
    let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
    form.draft.add_field(name, kind, field_value("")?)?;
    if let Some(f) = form.draft.entry_mut().fields.last_mut() {
        f.protected = protected;
    }
    Ok(())
}
/// Size bound for a value shown in an editable input.
fn editable(kind: FieldKind, value: &[u8]) -> bool {
    let limit = if kind == FieldKind::Multiline {
        MULTI_MAX
    } else {
        LINE_MAX
    };
    value.len() <= limit
}
fn entry_form(draft: qv_core::EntryDraft, new: bool) -> EntryForm {
    let too_large = draft
        .entry()
        .fields
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.protected && !editable(f.kind, f.value.expose_secret()))
        .filter_map(|(i, _)| u16::try_from(i).ok())
        .collect();
    let notes_too_large = draft
        .entry()
        .notes
        .as_ref()
        .is_some_and(|n| n.expose().len() > MULTI_MAX);
    EntryForm {
        draft,
        new,
        replacements: Default::default(),
        generated: Vec::new(),
        filled: Vec::new(),
        too_large,
        notes_too_large,
        start: false,
        removed: None,
    }
}
/// Fill a new item from what its start box held (plan 0040 E1). A card
/// number goes only into a card's protected number; it never becomes a title.
fn apply_start(
    form: &mut EntryForm,
    kind: ItemType,
    start: crate::editor::Start,
) -> Result<(), AppError> {
    use crate::editor::{CARD_NUMBER, NETWORK, Start, find};
    let text = |v: &str| qv_core::Text::new(v).map_err(|_| AppError::InvalidInput);
    let entry = form.draft.entry_mut();
    match start {
        Start::Card(digits) => {
            if kind == ItemType::Card
                && let Some(i) = find(&entry.fields, CARD_NUMBER)
            {
                let i = u16::try_from(i).map_err(|_| AppError::InvalidInput)?;
                form.replacements.insert(i, protect(&digits)?);
                form.filled.push(i);
            }
        }
        Start::Site(domain) => match (
            kind,
            entry.fields.iter_mut().find(|f| f.kind == FieldKind::Url),
        ) {
            (ItemType::Login, Some(f)) => f.value = field_value(&domain)?,
            _ => entry.title = text(&domain)?,
        },
        Start::Name(name) => match (kind, find(&entry.fields, NETWORK)) {
            (ItemType::Wifi, Some(i)) => entry.fields[i].value = field_value(&name)?,
            _ => entry.title = text(&name)?,
        },
    }
    Ok(())
}
fn set_screen(ws: &mut Workspace, screen: Screen) {
    ws.screen = screen;
}
pub(crate) fn settings_from(g: &crate::workspace::GenForm) -> qv_core::GeneratorSettings {
    match g.mode {
        GenMode::Characters => qv_core::GeneratorSettings::Characters(qv_core::CharacterSettings {
            length: g.length,
            lowercase: g.flags[0],
            uppercase: g.flags[1],
            digits: g.flags[2],
            symbols: g.flags[3],
            exclude_ambiguous: g.flags[4],
            exclude_chars: g.exclude.as_str().to_owned(),
            require_each_class: g.flags[7],
        }),
        GenMode::Words => qv_core::GeneratorSettings::Passphrase(qv_core::PassphraseSettings {
            words: g.words,
            separator: g.separator,
            capitalize: if g.flags[5] {
                qv_core::Capitalization::FirstLetter
            } else {
                qv_core::Capitalization::None
            },
            append_digit: g.flags[6],
            ..Default::default()
        }),
        GenMode::Pin => qv_core::GeneratorSettings::Pin(qv_core::PinSettings { length: g.pin }),
    }
}
/// Load generator settings into the form (vault defaults on entry).
pub(crate) fn load_generator(
    g: &mut crate::workspace::GenForm,
    settings: &qv_core::GeneratorSettings,
) {
    match settings {
        qv_core::GeneratorSettings::Characters(c) => {
            g.mode = GenMode::Characters;
            g.length = c.length;
            g.flags[0] = c.lowercase;
            g.flags[1] = c.uppercase;
            g.flags[2] = c.digits;
            g.flags[3] = c.symbols;
            g.flags[4] = c.exclude_ambiguous;
            g.flags[7] = c.require_each_class;
            g.exclude = zeroize::Zeroizing::new(c.exclude_chars.clone());
        }
        qv_core::GeneratorSettings::Passphrase(p) => {
            g.mode = GenMode::Words;
            g.words = p.words;
            g.separator = p.separator;
            g.flags[5] = p.capitalize == qv_core::Capitalization::FirstLetter;
            g.flags[6] = p.append_digit;
        }
        qv_core::GeneratorSettings::Pin(p) => {
            g.mode = GenMode::Pin;
            g.pin = p.length;
        }
    }
}
/// Prepare screen-specific state when a screen is entered.
pub(crate) fn on_enter(ws: &mut Workspace, session: &Session) {
    match ws.screen {
        Screen::Settings(Pane::General) => ws.settings = session.edit_settings().ok(),
        Screen::Generator => {
            if let Ok(defaults) = session.generator_defaults() {
                load_generator(&mut ws.generator, &defaults);
            }
        }
        _ => {}
    }
}
/// The mandatory recovery snapshot, the change, then reclassification. A
/// failure before the change keeps everything; a reclassification failure
/// after it is reported without hiding the committed change.
fn with_snapshot<T>(
    s: &Session,
    over_budget: bool,
    token: &CancelToken,
    f: impl FnOnce() -> Result<T, CoreError>,
) -> Result<(T, bool), AppError> {
    let copy = s.begin_destructive(over_budget, Some(token))?;
    let out = f()?;
    let cleanup_failed = s.finish_destructive(copy).is_err();
    Ok((out, cleanup_failed))
}
const CLEANUP: &str = "Done. The recovery snapshot could not be reclassified and remains on disk.";

/// Run one action.
pub(crate) fn run(
    c: &Controller,
    epoch: FormEpoch,
    action: WsAction,
    over_budget: bool,
) -> Result<(), AppError> {
    let retry = Some(action.clone());
    match action {
        WsAction::Search => c
            .with_ws(epoch, |ws, _| ws.searched = true)
            .ok_or(AppError::InvalidInput),
        WsAction::Dismiss => c
            .with_ws(epoch, |ws, _| {
                ws.notice = None;
                ws.report = None;
                ws.error = None;
                ws.undo = None;
            })
            .ok_or(AppError::InvalidInput),
        WsAction::Hide => c
            .with_ws(epoch, |ws, _| Controller::hide(ws))
            .ok_or(AppError::InvalidInput),
        WsAction::Reveal(key) => c
            .with_ws(epoch, |ws, session| -> Result<(), AppError> {
                let value = reveal_value(ws, session, &key)?;
                Controller::set_reveal(ws, key, value);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::Copy(key) => {
            let (value, session) = c
                .with_ws(epoch, |ws, session| -> Result<_, AppError> {
                    let value = match &key {
                        CopyKey::Field(entry, field) => {
                            if session.entry_versions(*entry)?.len() > 1 {
                                return Err(AppError::Conflict);
                            }
                            protect(session.reveal(*field)?.expose_secret())?
                        }
                        CopyKey::Totp(entry, field) => {
                            if session.entry_versions(*entry)?.len() > 1 {
                                return Err(AppError::Conflict);
                            }
                            protect(session.totp(*field)?.code.expose_secret().as_bytes())?
                        }
                        CopyKey::Generated => {
                            let (g, _) = ws.generated.as_ref().ok_or(AppError::InvalidInput)?;
                            protect(g.expose_secret().as_bytes())?
                        }
                    };
                    let session = (!matches!(key, CopyKey::Generated)).then(|| session.clone());
                    Ok((value, session))
                })
                .ok_or(AppError::InvalidInput)??;
            c.start_clip(epoch, value, session)
        }
        WsAction::NewEntry(group) => c
            .with_ws(epoch, |ws, session| -> Result<(), AppError> {
                // The type and its fields are chosen in the start step.
                let draft = session.new_entry(group, ItemType::Login.hint(), "")?;
                let mut form = entry_form(draft, true);
                form.start = true;
                ws.inputs.remove(&WsField::Start);
                ws.entry_form = Some(form);
                set_screen(ws, Screen::EditEntry);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::EditEntry(entry) => c
            .with_ws(epoch, |ws, session| -> Result<(), AppError> {
                if session.entry_versions(entry)?.len() > 1 {
                    return Err(AppError::Conflict);
                }
                let draft = session.edit_entry(entry)?;
                ws.entry_form = Some(entry_form(draft, false));
                set_screen(ws, Screen::EditEntry);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::StartAs(kind) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let start = ws.inputs.remove(&WsField::Start);
                let form = ws
                    .entry_form
                    .as_mut()
                    .filter(|f| f.start)
                    .ok_or(AppError::InvalidInput)?;
                let guess = start
                    .as_ref()
                    .and_then(|s| crate::editor::guess(s.expose_secret()));
                let kind = kind
                    .or(guess.as_ref().map(|g| g.kind))
                    .unwrap_or(ItemType::Login);
                crate::editor::set_type(form, kind)?;
                form.start = false;
                if let Some(g) = guess {
                    apply_start(form, kind, g.start)?;
                }
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::SetType(kind) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                if crate::editor::set_type(form, kind)? {
                    ws.notice = Some("Changed the type. Fields you had filled in were kept.");
                }
                Controller::hide(ws);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::SetGroup(group) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                Ok(form.draft.set_group(group)?)
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::SetHue(pick) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let token = |icon: Option<&qv_core::Text>| -> Result<Option<qv_core::Text>, AppError> {
                    crate::editor::pick_colour(icon.map(qv_core::Text::expose), pick)?
                        .map(|t| qv_core::Text::new(&t).map_err(|_| AppError::InvalidInput))
                        .transpose()
                };
                if ws.screen == Screen::EditGroup {
                    let g = ws.group_form.as_mut().ok_or(AppError::InvalidInput)?;
                    let icon = token(g.draft.group().icon.as_ref())?;
                    g.draft.group_mut().icon = icon;
                } else {
                    let f = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                    let icon = token(f.draft.entry().icon.as_ref())?;
                    f.draft.entry_mut().icon = icon;
                }
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::AddField(kind) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let typed = zeroize::Zeroizing::new(ws.text(WsField::NewFieldName)?.trim().to_owned());
                let (kind, protected) = match kind {
                    Some(k) => (k, k.protected_by_default()),
                    None => crate::editor::kind_for(&typed),
                };
                let name = if typed.is_empty() {
                    // Adding without a name names the field after its kind.
                    zeroize::Zeroizing::new(crate::editor::kind_label(kind).to_owned())
                } else {
                    typed
                };
                add_field(ws, &name, kind, protected)?;
                ws.inputs.remove(&WsField::NewFieldName);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::AddNamedField(name) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let (kind, protected) = crate::editor::kind_for(name);
                add_field(ws, name, kind, protected)?;
                ws.inputs.remove(&WsField::NewFieldName);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::MoveField(i, up) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                crate::editor::move_field(form, i, up)?;
                Controller::hide(ws);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::RemoveField(i) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                crate::editor::remove_field(form, i)?;
                Controller::hide(ws);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::UndoRemoveField => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                crate::editor::undo_remove(form)?;
                Controller::hide(ws);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::UseGenerated(i) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                let protected = form
                    .draft
                    .entry()
                    .fields
                    .get(usize::from(i))
                    .is_some_and(|f| f.protected);
                if !protected {
                    return Err(AppError::InvalidInput);
                }
                let (generated, _) = ws.generated.take().ok_or(AppError::InvalidInput)?;
                form.replacements
                    .insert(i, protect(generated.expose_secret().as_bytes())?);
                if !form.generated.contains(&i) {
                    form.generated.push(i);
                }
                Controller::hide(ws);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::ToggleProtect(i) => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                let index = usize::from(i);
                let replacement = form.replacements.remove(&i);
                let field = form
                    .draft
                    .entry_mut()
                    .fields
                    .get_mut(index)
                    .ok_or(AppError::InvalidInput)?;
                if let Some(value) = replacement {
                    let text = std::str::from_utf8(value.expose_secret())
                        .map_err(|_| AppError::InvalidInput)?;
                    field.value = field_value(text)?;
                }
                field.protected = !field.protected;
                let large = !field.protected && !editable(field.kind, field.value.expose_secret());
                form.generated.retain(|g| *g != i);
                form.filled.retain(|g| *g != i);
                form.too_large.retain(|g| *g != i);
                if large {
                    form.too_large.push(i);
                }
                Controller::hide(ws);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::GenerateInto(i) => c
            .with_ws(epoch, |ws, session| -> Result<(), AppError> {
                let generated = session.generate(None)?;
                let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                if usize::from(i) >= form.draft.entry().fields.len() {
                    return Err(AppError::InvalidInput);
                }
                form.replacements
                    .insert(i, protect(generated.expose_secret().as_bytes())?);
                if !form.generated.contains(&i) {
                    form.generated.push(i);
                }
                Controller::hide(ws);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::SaveEntry => {
            let form = c
                .with_ws(epoch, |ws, _| -> Result<EntryForm, AppError> {
                    let form = ws.entry_form.as_mut().ok_or(AppError::InvalidInput)?;
                    if form.start {
                        return Err(AppError::NameRequired);
                    }
                    if form.draft.entry().title.expose().is_empty()
                        && let Some((title, _)) = crate::editor::auto_title(form)
                    {
                        form.draft.entry_mut().title =
                            qv_core::Text::new(&title).map_err(|_| AppError::InvalidInput)?;
                    }
                    let entry = form.draft.entry();
                    if entry.title.expose().is_empty()
                        || entry.fields.iter().any(|f| f.name.expose().is_empty())
                    {
                        return Err(AppError::NameRequired);
                    }
                    let mut form = ws.entry_form.take().ok_or(AppError::InvalidInput)?;
                    let replacements = std::mem::take(&mut form.replacements);
                    for (i, value) in replacements {
                        let text = std::str::from_utf8(value.expose_secret())
                            .map_err(|_| AppError::InvalidInput)?;
                        let field = form
                            .draft
                            .entry_mut()
                            .fields
                            .get_mut(usize::from(i))
                            .ok_or(AppError::InvalidInput)?;
                        field.value = field_value(text)?;
                    }
                    Controller::hide(ws);
                    Ok(form)
                })
                .ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, None, move |s, _, _| {
                let entry = s.save_entry(form.draft)?;
                Ok(on_ws(move |ws| {
                    ws.screen = Screen::Entry(entry);
                    ws.notice = Some("Saved.");
                }))
            })
        }
        WsAction::NewGroup(parent) => c
            .with_ws(epoch, |ws, session| -> Result<(), AppError> {
                let draft = session.new_group(parent, "New group")?;
                ws.group_form = Some(GroupForm { draft, new: true });
                set_screen(ws, Screen::EditGroup);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::RenameGroup(group) => c
            .with_ws(epoch, |ws, session| -> Result<(), AppError> {
                let draft = session.edit_group(group)?;
                ws.group_form = Some(GroupForm { draft, new: false });
                set_screen(ws, Screen::EditGroup);
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::SaveGroup => {
            let form = c
                .with_ws(epoch, |ws, _| ws.group_form.take())
                .flatten()
                .ok_or(AppError::InvalidInput)?;
            c.run_op(epoch, None, move |s, _, _| {
                let group = s.save_group(form.draft)?;
                Ok(on_ws(move |ws| {
                    ws.screen = Screen::Browse(Some(group));
                    ws.notice = Some("Saved.");
                }))
            })
        }
        WsAction::MoveTo(item, group) => c.run_op(epoch, None, move |s, _, _| {
            s.move_item(item, group)?;
            Ok(on_ws(move |ws| {
                ws.screen = match item {
                    qv_core::ItemHandle::Entry(e) => Screen::Entry(e),
                    qv_core::ItemHandle::Group(g) => Screen::Browse(Some(g)),
                };
                ws.notice = Some("Moved.");
            }))
        }),
        WsAction::Delete(item) => c.run_op(epoch, None, move |s, _, _| {
            s.delete(item, matches!(item, qv_core::ItemHandle::Group(_)))?;
            Ok(on_ws(move |ws| {
                ws.screen = ws.list_context();
                ws.notice = Some("Moved to the trash.");
                ws.undo = Some(item);
            }))
        }),
        WsAction::Restore(item) => c.run_op(epoch, None, move |s, _, _| {
            s.restore(item)?;
            Ok(on_ws(|ws| {
                ws.undo = None;
                ws.notice = Some("Restored from the trash.");
            }))
        }),
        WsAction::EmptyTrash => c.run_op(epoch, retry, move |s, token, _| {
            let (report, cleanup) = with_snapshot(s, over_budget, token, || s.empty_trash())?;
            Ok(on_ws(move |ws| {
                ws.report = Some(Report::Purged {
                    purged: report.purged,
                    kept: report.skipped_conflicts,
                });
                ws.notice = cleanup.then_some(CLEANUP);
            }))
        }),
        WsAction::PurgeExpired => c.run_op(epoch, retry, move |s, token, _| {
            let items: Vec<_> = s.expired_trash()?.expired.iter().map(|t| t.item).collect();
            let count = items.len();
            let ((), cleanup) = with_snapshot(s, over_budget, token, || s.purge(&items))?;
            Ok(on_ws(move |ws| {
                ws.report = Some(Report::Purged {
                    purged: count,
                    kept: 0,
                });
                ws.notice = cleanup.then_some(CLEANUP);
            }))
        }),
        WsAction::RestoreHistory(entry, version, resolve) => c.run_op(epoch, None, move |s, _, _| {
            let h = history_handle(s, entry, &version)?;
            let entry = s.restore_history(h, resolve)?;
            Ok(on_ws(move |ws| {
                ws.screen = Screen::Entry(entry);
                ws.notice = Some("Restored as a new version.");
            }))
        }),
        WsAction::PurgeHistory(entry) => c.run_op(epoch, None, move |s, _, _| {
            s.purge_history(entry)?;
            Ok(on_ws(|ws| {
                ws.notice = Some(
                    "Local history suppressed. Snapshots, unseen concurrent history and independent copies may remain; no secure erasure.",
                )
            }))
        }),
        WsAction::Resolve(record, version) => {
            let password = c
                .peek(epoch, |ws| password(ws, WsField::Password).ok())
                .ok_or(AppError::InvalidInput)?;
            c.run_op(epoch, None, move |s, token, _| {
                let h = conflict_version(s, &record, &version)?;
                let needs = matches!(
                    s.conflict_version(&h)?.details,
                    qv_core::ConflictDetails::PasswordSlot { .. }
                );
                let pw = if needs {
                    Some(password.ok_or(AppError::InvalidInput)?)
                } else {
                    None
                };
                let r = s.resolve_version(&h, pw.as_ref(), Some(token))?;
                Ok(on_ws(move |ws| {
                    ws.screen = Screen::Conflicts;
                    ws.report = Some(Report::Resolved {
                        conflicts: r.conflicts,
                        incomplete: r.completion_error.is_some(),
                    });
                }))
            })
        }
        WsAction::RestoreSnapshot(id) => {
            // The open session restores directly: reopening would contend for
            // the vault's exclusive lock, and a pruned snapshot fails closed.
            let target = c
                .peek(epoch, |ws| restore_target(&c.0.base, ws))
                .ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, None, move |s, token, _| {
                let [ref selected] = s.snapshot_matches(&id)?[..] else {
                    return Err(AppError::Core(CoreError::NotFound));
                };
                let selected = selected.clone();
                s.restore_snapshot(&selected, &target, Some(token))?;
                Ok(on_ws(|ws| {
                    ws.notice = Some(
                        "Restored into a new vault file. The snapshot may be old and is a new recovery baseline; all conflicts are preserved.",
                    )
                }))
            })
        }
        WsAction::ExportArchive(self_contained) => {
            let dir = c
                .peek(epoch, crate::documents::export_dir)
                .ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, None, move |s, token, ctl| {
                let r = s.export_archive(&dir, self_contained, Some(token))?;
                crate::documents::finish_export(ctl, &dir, &r.archive_id)?;
                Ok(on_ws(move |ws| {
                    ws.report = Some(Report::Export {
                        id: r.archive_id,
                        self_contained,
                        incomplete: r.completion_error.is_some(),
                    })
                }))
            })
        }
        WsAction::MergeArchive => {
            let source = c
                .peek(epoch, crate::documents::import_source)
                .ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, retry, move |s, token, ctl| {
                let source = crate::documents::stage_import(ctl, source, token)?;
                let result = s.merge_archive(source.path(), over_budget, Some(token));
                drop(source);
                let r = result?;
                Ok(on_ws(move |ws| {
                    ws.report = Some(Report::Merge {
                        accepted: r.accepted,
                        conflicts: r.conflicts,
                        incomplete: r.completion_error.is_some(),
                    })
                }))
            })
        }
        WsAction::AddAttachment(entry) => {
            let (source, name, mime) = c
                .peek(epoch, |ws| -> Result<_, AppError> {
                    let source = crate::documents::attachment_source(ws)?;
                    let name = zeroize::Zeroizing::new(ws.text(WsField::AttachName)?.to_owned());
                    let mime = zeroize::Zeroizing::new(ws.text(WsField::AttachMime)?.to_owned());
                    Ok((source, name, mime))
                })
                .ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, None, move |s, token, ctl| {
                if s.entry_versions(entry)?.len() > 1 {
                    return Err(AppError::Conflict);
                }
                let (mut reader, default_name) = crate::documents::open_attachment(ctl, source, token)?;
                let name = if name.is_empty() { default_name } else { name };
                let mime = if mime.is_empty() {
                    "application/octet-stream"
                } else {
                    mime.as_str()
                };
                s.add_attachment(entry, &name, mime, &mut reader, Some(token))?;
                Ok(on_ws(|ws| ws.notice = Some("Attachment added.")))
            })
        }
        WsAction::SaveAttachment(handle) => {
            let target = c
                .peek(epoch, crate::documents::attachment_target)
                .ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, None, move |s, token, ctl| {
                // Verify the complete content before creating any output.
                s.verify_attachment(handle, Some(token))?;
                let mut sink = crate::documents::create_output(ctl, target, token)?;
                let result = s
                    .save_attachment(handle, &mut sink, Some(token))
                    .map_err(AppError::from)
                    .and_then(|()| sink.finish());
                match result {
                    Ok(()) => Ok(on_ws(|ws| ws.notice = Some("Attachment saved."))),
                    Err(_) => Ok(on_ws(|ws| {
                        ws.notice = Some(
                            "Saving failed; the chosen destination may contain incomplete plaintext.",
                        );
                    })),
                }
            })
        }
        WsAction::RemoveAttachment(handle) => c.run_op(epoch, None, move |s, _, _| {
            s.remove_attachment(handle)?;
            Ok(on_ws(|ws| {
                ws.notice = Some(
                    "Attachment removed. Independent copies may remain; no secure erasure.",
                )
            }))
        }),
        WsAction::GenMode(mode) => c
            .with_ws(epoch, |ws, _| {
                ws.generator.mode = mode;
                ws.generated = None;
            })
            .ok_or(AppError::InvalidInput),
        WsAction::GenToggle(flag) => c
            .with_ws(epoch, |ws, _| {
                let i = match flag {
                    GenFlag::Lower => 0,
                    GenFlag::Upper => 1,
                    GenFlag::Digits => 2,
                    GenFlag::Symbols => 3,
                    GenFlag::Ambiguous => 4,
                    GenFlag::Each => 7,
                    GenFlag::Capitalize => 5,
                    GenFlag::AppendDigit => 6,
                };
                ws.generator.flags[i] = !ws.generator.flags[i];
            })
            .ok_or(AppError::InvalidInput),
        WsAction::Generate => c
            .with_ws(epoch, |ws, _| -> Result<(), AppError> {
                ws.generated = None;
                let g = qv_core::generate(&settings_from(&ws.generator))?;
                ws.generated = Some((g, std::time::Instant::now()));
                Ok(())
            })
            .ok_or(AppError::InvalidInput)?,
        WsAction::SuggestPassword => c.with_ws(epoch, |ws, _| -> Result<(), AppError> {
            ws.generated = Some((qv_core::generate(&qv_core::GeneratorSettings::Passphrase(
                qv_core::PassphraseSettings::default()))?, std::time::Instant::now()));
            Ok(())
        }).ok_or(AppError::InvalidInput)?,
        WsAction::SaveGeneratorDefaults => {
            let settings = c
                .peek(epoch, |ws| settings_from(&ws.generator))
                .ok_or(AppError::InvalidInput)?;
            qv_core::estimate(&settings)?;
            c.run_op(epoch, None, move |s, _, _| {
                let mut draft = s.edit_settings()?;
                draft.meta_mut().settings.generator = Some(qv_core::GeneratorDefaults {
                    settings,
                    ext: Default::default(),
                });
                s.save_settings(draft)?;
                Ok(on_ws(|ws| ws.notice = Some("Generator defaults saved.")))
            })
        }
        WsAction::SaveSettings => {
            let draft = c
                .with_ws(epoch, |ws, _| ws.settings.take())
                .flatten()
                .ok_or(AppError::InvalidInput)?;
            c.run_op(epoch, None, move |s, _, _| {
                s.save_settings(draft)?;
                let fresh = s.edit_settings().ok();
                Ok(on_ws(move |ws| {
                    ws.settings = fresh;
                    ws.notice = Some("Settings saved.");
                }))
            })
        }
        WsAction::ChangePassword => change_password(c, epoch),
        WsAction::EnrollQuick(policy) => {
            let pw = c.peek(epoch, |ws| password(ws, WsField::Password)).ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, None, move |s, token, _| {
                s.enroll_quick(&pw, policy, Some(token))?;
                Ok(on_ws(|ws| { ws.inputs.clear(); ws.notice = Some("Quick unlock enabled for this app process. Restart, reboot, expiry, three failures or credential changes require the master password."); }))
            })
        }
        WsAction::DisableQuick => c.run_op(epoch, None, move |s, _, _| {
            s.disable_quick()?;
            Ok(on_ws(|ws| ws.notice = Some("Quick unlock disabled; the hardware key was removed.")))
        }),
        WsAction::AutofillFill(key) => {
            let (native, requester, roles) = c.autofill_bound().ok_or(AppError::AutofillExpired)?;
            c.run_op(epoch, None, move |s, token, _| {
                let values = s.autofill_values(&requester, key, roles)?;
                // A lock cancels the token; never hand values over after it.
                if token.is_cancelled()
                    || !crate::autofill::sink().complete(
                        native,
                        values.username.as_ref(),
                        values.password.as_ref(),
                    )
                {
                    return Err(AppError::AutofillExpired);
                }
                Ok(Box::new(move |st: &mut crate::controller::State| {
                    Controller::autofill_completed(st, native);
                    if let Some(ws) = st.workspace.as_mut() {
                        ws.go(Screen::Browse(None));
                        ws.notice = Some("Login handed to the requesting app.");
                    }
                }))
            })
        }
        WsAction::AutofillCancel => {
            c.autofill_cancel();
            Ok(())
        }
        WsAction::AutofillLink(entry) => {
            let Some((_, qv_core::platform::autofill::Requester::App(app), _)) = c.autofill_bound()
            else {
                return Err(AppError::InvalidInput);
            };
            c.run_op(epoch, None, move |s, _, _| {
                s.link_app(entry, &app)?;
                Ok(on_ws(|ws| {
                    ws.inputs.clear();
                    ws.notice = Some("App linked. Choose the entry to fill.");
                }))
            })
        }
        WsAction::OpenAutofillSettings => {
            #[cfg(all(feature = "desktop", target_os = "android"))]
            crate::android::open_autofill_settings();
            Ok(())
        }
        WsAction::DeleteOldSnapshots => {
            let ids = c
                .with_ws(epoch, |ws, _| std::mem::take(&mut ws.old_snapshots))
                .ok_or(AppError::InvalidInput)?;
            c.run_op(epoch, None, move |s, _, _| {
                s.delete_snapshots(&ids)?;
                Ok(on_ws(|ws| ws.notice = Some("Pre-change local snapshots deleted.")))
            })
        }
        WsAction::ShowPhrase => {
            let pw = c
                .peek(epoch, |ws| password(ws, WsField::Password))
                .ok_or(AppError::InvalidInput)??;
            c.run_op(epoch, None, move |s, _, _| {
                let phrase = s.recovery_phrase(&pw)?;
                drop(pw);
                let positions = qv_core::confirmation_positions()?;
                Ok(on_ws(move |ws| {
                    ws.inputs.clear();
                    ws.phrase = Some(PhraseView::Redisplay {
                        phrase,
                        positions,
                        confirmed: false,
                    });
                }))
            })
        }
        WsAction::HidePhrase => c
            .with_ws(epoch, |ws, _| {
                ws.phrase = None;
                ws.inputs.clear();
            })
            .ok_or(AppError::InvalidInput),
        WsAction::ConfirmWords => confirm_words(c, epoch),
        WsAction::BeginRotation => begin_rotation(c, epoch, over_budget, retry),
        WsAction::Verify => c.run_op(epoch, None, move |s, token, _| {
            let r = s.verify(Some(token))?;
            Ok(on_ws(move |ws| {
                ws.report = Some(Report::Verify {
                    ok: r.ok(),
                    anchor: anchor_label(r.anchor),
                    objects: r.counts.objects,
                    bytes: r.counts.total_bytes,
                    records: r.counts.records,
                    notes: r.notes.iter().map(|n| note_label(*n)).collect(),
                })
            }))
        }),
        WsAction::LanPair => crate::lan::pair(c, epoch),
        WsAction::LanReceive => crate::lan::receive(c, epoch),
        WsAction::LanSync(link) => crate::lan::sync(c, epoch, link),
        WsAction::LanLink => crate::lan::link(c, epoch),
        WsAction::LanRemove(link) => crate::lan::remove(c, epoch, link),
        WsAction::Answer(_) => Err(AppError::InvalidInput),
    }
}
fn reveal_value(
    ws: &Workspace,
    session: &Session,
    key: &RevealKey,
) -> Result<qv_core::SecretBytes, AppError> {
    let bytes = match key {
        RevealKey::Field(field) => protect(session.reveal(*field)?.expose_secret())?,
        RevealKey::History(version, field) => {
            let Screen::HistoryVersion(entry, shown) = &ws.screen else {
                return Err(AppError::InvalidInput);
            };
            if shown != version {
                return Err(AppError::InvalidInput);
            }
            let h = history_handle(session, *entry, version)?;
            protect(session.reveal_history(h, *field)?.expose_secret())?
        }
        RevealKey::Conflict(record, version, field) => {
            let h = conflict_version(session, record, version)?;
            let v = session.conflict_version(&h)?;
            let qv_core::ConflictDetails::Entry { detail, .. } = v.details else {
                return Err(AppError::InvalidInput);
            };
            let f = detail
                .fields
                .iter()
                .find(|f| f.handle.field_id() == *field)
                .ok_or(AppError::InvalidInput)?;
            protect(session.reveal(f.handle)?.expose_secret())?
        }
        RevealKey::Replacement(i) => {
            let form = ws.entry_form.as_ref().ok_or(AppError::InvalidInput)?;
            let value = form.replacements.get(i).ok_or(AppError::InvalidInput)?;
            protect(value.expose_secret())?
        }
        RevealKey::Totp(field) => protect(session.totp(*field)?.code.expose_secret().as_bytes())?,
        RevealKey::WifiJoin(entry) => {
            if session.entry_versions(*entry)?.len() > 1 {
                return Err(AppError::Conflict);
            }
            let d = session.entry(*entry)?;
            let named = |name: &str| {
                d.fields
                    .iter()
                    .find(|f| crate::editor::same_slot(f.name.expose(), name))
            };
            let value = |f: Option<&qv_core::FieldDetail>| -> Result<Option<qv_core::SecretBytes>, AppError> {
                f.map(|f| protect(session.reveal(f.handle)?.expose_secret()))
                    .transpose()
            };
            let ssid = value(named(crate::editor::NETWORK))?.ok_or(AppError::InvalidInput)?;
            let password = value(named("Password"))?;
            let security = value(named(crate::editor::SECURITY))?;
            let security = security
                .as_ref()
                .and_then(|s| std::str::from_utf8(s.expose_secret()).ok())
                .unwrap_or("WPA2");
            crate::editor::wifi_payload(
                ssid.expose_secret(),
                password.as_ref().map(|p| p.expose_secret()),
                security,
            )?
        }
        RevealKey::Generated => return Err(AppError::InvalidInput),
    };
    Ok(bytes)
}
/// Candidate inputs clear this consent on every change; the dispatch layer
/// enforces the deadline as well as the disabled UI button.
fn strength_consent(
    c: &Controller,
    epoch: FormEpoch,
    candidate: &MasterPassword,
    action: WsAction,
) -> Result<bool, AppError> {
    c.with_ws(epoch, |ws, _| {
        let generated = ws.generated.as_ref().is_some_and(|(g, _)| {
            g.expose_secret()
                .as_bytes()
                .ct_eq(candidate.expose_secret().as_bytes())
                .to_bool()
        });
        let verdict = if generated {
            PasswordVerdict::Accept
        } else {
            qv_core::password_strength(candidate).verdict
        };
        ws.fair_warning = verdict == PasswordVerdict::Warn;
        if verdict == PasswordVerdict::ConfirmWeak
            && (!ws.weak_accepted
                || ws
                    .weak_until
                    .is_none_or(|until| std::time::Instant::now() < until))
        {
            ws.weak_until = Some(std::time::Instant::now() + std::time::Duration::from_secs(5));
            ws.set_pending(crate::workspace::ConfirmKind::WeakPassword, action, false);
            return false;
        }
        ws.weak_until = None;
        true
    })
    .ok_or(AppError::InvalidInput)
}
/// New password twice (constant-time comparison) with the creation strength
/// rules; a weak one needs an explicit confirmation, which re-dispatches with
/// `weak_ok` set.
fn change_password(c: &Controller, epoch: FormEpoch) -> Result<(), AppError> {
    let new = c
        .peek(epoch, |ws| -> Result<MasterPassword, AppError> {
            let a = password(ws, WsField::NewPassword)?;
            let b = password(ws, WsField::Repeat)?;
            if a.expose_secret().is_empty()
                || !a
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(b.expose_secret().as_bytes())
                    .to_bool()
            {
                return Err(AppError::InvalidInput);
            }
            Ok(a)
        })
        .ok_or(AppError::InvalidInput)??;
    if !strength_consent(c, epoch, &new, WsAction::ChangePassword)? {
        return Ok(());
    }
    c.run_op(epoch, None, move |s, token, _| {
        let ids: Vec<String> = s
            .snapshots()
            .map(|l| l.snapshots.into_iter().map(|x| x.archive_id).collect())
            .unwrap_or_default();
        s.change_password(&new, Some(token))?;
        drop(new);
        Ok(on_ws(move |ws| {
            ws.inputs.clear();
            ws.notice = Some(
                "Master password changed. Old copies of the vault and its password slot still open this key generation; rotate keys after a suspected compromise.",
            );
            if !ids.is_empty() {
                ws.offer_old_snapshots(ids);
            }
        }))
    })
}
fn confirm_words(c: &Controller, epoch: FormEpoch) -> Result<(), AppError> {
    c.with_ws(epoch, |ws, _| -> Result<(), AppError> {
        let words: Vec<qv_core::SecretBytes> = (0..3u8)
            .map(|i| protect(ws.input(WsField::Word(i))))
            .collect::<Result<_, _>>()?;
        let ok = match ws.phrase.as_mut() {
            Some(PhraseView::Redisplay {
                phrase,
                positions,
                confirmed,
            }) => {
                let ok = positions
                    .iter()
                    .zip(&words)
                    .all(|(p, w)| phrase.confirm_word(*p, w.expose_secret()).is_ok());
                *confirmed |= ok;
                ok
            }
            None => return Err(AppError::InvalidInput),
        };
        for i in 0..3u8 {
            ws.inputs.remove(&WsField::Word(i));
        }
        if !ok {
            return Err(AppError::InvalidInput);
        }
        ws.notice = Some("The recovery words are confirmed.");
        Ok(())
    })
    .ok_or(AppError::InvalidInput)?
}
fn begin_rotation(
    c: &Controller,
    epoch: FormEpoch,
    over_budget: bool,
    retry: Option<WsAction>,
) -> Result<(), AppError> {
    let new = c
        .peek(epoch, |ws| -> Result<MasterPassword, AppError> {
            if ws.input(WsField::Confirmation) != b"rotate" {
                return Err(AppError::Consent);
            }
            let a = password(ws, WsField::NewPassword)?;
            let b = password(ws, WsField::Repeat)?;
            if a.expose_secret().is_empty()
                || !a
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(b.expose_secret().as_bytes())
                    .to_bool()
            {
                return Err(AppError::InvalidInput);
            }
            Ok(a)
        })
        .ok_or(AppError::InvalidInput)??;
    if !strength_consent(c, epoch, &new, WsAction::BeginRotation)? {
        return Ok(());
    }
    // The rotation consumes and locks the session once its recovery snapshot
    // exists; that expected lock must not discard the prepared rotation.
    c.state().rotating = true;
    let started = c.run_op(epoch, retry, move |s, token, ctl| {
        let result = s.begin_rotation(&new, over_budget, Some(token));
        drop(new);
        match result {
            Ok(rotation) => {
                let positions = qv_core::confirmation_positions()?;
                Ok(Box::new(move |state: &mut State| {
                    Controller::enter_rotation(state, rotation, positions)
                }) as Apply)
            }
            Err(e) => {
                ctl.state().rotating = false;
                if s.is_locked() {
                    Ok(Box::new(|state: &mut State| {
                        state.invalidate();
                        state.status =
                            "Key rotation stopped before it was installed; nothing changed.";
                    }) as Apply)
                } else {
                    Err(e.into())
                }
            }
        }
    });
    if started.is_err() {
        c.state().rotating = false;
    }
    started
}
impl Workspace {
    fn offer_old_snapshots(&mut self, ids: Vec<String>) {
        let n = ids.len();
        self.old_snapshots = ids;
        self.set_pending(
            crate::workspace::ConfirmKind::OldSnapshots(n),
            WsAction::DeleteOldSnapshots,
            false,
        );
    }
}
