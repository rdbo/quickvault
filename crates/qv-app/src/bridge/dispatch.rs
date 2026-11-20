// SPDX-License-Identifier: AGPL-3.0-or-later

//! Requests to controller calls, one arm per page action (plan 0071). References are resolved against the table; a stale or
//! foreign one fails closed with `NotFound` and nothing happens. The
//! controller still checks the epoch, handles and session itself.
use super::convert;
use super::frame::UiState;
use super::hooks::Hooks;
use super::refs::Refs;
use crate::controller::{Controller, FormEpoch, InputField, SwitchTo};
use crate::workspace::{Screen, Shortcut, Undo, WsAction, WsField};
use qv_ui_api as api;
use qv_ui_api::{Act, Field, Request, UiError};
use zeroize::Zeroize;

/// The undo action shown with a notice.
pub(crate) fn undo(refs: &mut Refs, u: &Undo) -> api::WsAct {
    match u {
        Undo::Item(i) => api::WsAct::Restore(convert::item(refs, *i)),
        Undo::Entries(e) => api::WsAct::RestoreMany(
            e.iter()
                .map(|h| refs.issue(super::refs::Target::Entry(*h)))
                .collect(),
        ),
    }
}

fn locked_field(f: api::LockedField) -> InputField {
    match f {
        api::LockedField::Path => InputField::Path,
        api::LockedField::Name => InputField::Name,
        api::LockedField::Password => InputField::Password,
        api::LockedField::Repeat => InputField::Repeat,
        api::LockedField::Phrase => InputField::Phrase,
        api::LockedField::Word0 => InputField::Word0,
        api::LockedField::Word1 => InputField::Word1,
        api::LockedField::Word2 => InputField::Word2,
        api::LockedField::LanCode => InputField::LanCode,
        api::LockedField::LanEndpoint => InputField::LanEndpoint,
    }
}

fn ws_field(f: api::WsField) -> WsField {
    use api::WsField as F;
    match f {
        F::Query => WsField::Query,
        F::Command => WsField::Command,
        F::Title => WsField::Title,
        F::TypeHint => WsField::TypeHint,
        F::Notes => WsField::Notes,
        F::FieldName(i) => WsField::FieldName(i),
        F::FieldValue(i) => WsField::FieldValue(i),
        F::Replacement(i) => WsField::Replacement(i),
        F::NewFieldName => WsField::NewFieldName,
        F::Start => WsField::Start,
        F::GroupName => WsField::GroupName,
        F::Path => WsField::Path,
        F::Password => WsField::Password,
        F::NewPassword => WsField::NewPassword,
        F::Repeat => WsField::Repeat,
        F::Word(i) => WsField::Word(i),
        F::GenLength => WsField::GenLength,
        F::GenWords => WsField::GenWords,
        F::GenSeparator => WsField::GenSeparator,
        F::GenExclude => WsField::GenExclude,
        F::VaultName => WsField::VaultName,
        F::Description => WsField::Description,
        F::HistoryDepth => WsField::HistoryDepth,
        F::TrashDays => WsField::TrashDays,
        F::AttachMime => WsField::AttachMime,
        F::AttachName => WsField::AttachName,
        F::Confirmation => WsField::Confirmation,
        F::LanCode => WsField::LanCode,
        F::LanEndpoint => WsField::LanEndpoint,
        F::TotpInput => WsField::TotpInput,
    }
}

fn entries(refs: &Refs, list: &[api::Ref]) -> Option<Vec<qv_core::EntryHandle>> {
    if list.len() > 4096 {
        return None;
    }
    list.iter().map(|r| refs.entry(*r)).collect()
}

fn hex(s: &str) -> Option<String> {
    (s.len() <= 64 && s.bytes().all(|b| b.is_ascii_hexdigit())).then(|| s.to_owned())
}

/// A page-named workspace action, references resolved.
fn ws_back(c: &Controller, epoch: FormEpoch, refs: &Refs, a: &api::WsAct) -> Option<WsAction> {
    use api::WsAct as A;
    Some(match a {
        A::Search => WsAction::Search,
        A::Reveal(k) => WsAction::Reveal(convert::reveal_back(refs, k)?),
        A::Hide => WsAction::Hide,
        A::Copy(k) => WsAction::Copy(convert::copy_back(refs, k)?),
        A::NewEntry(g) => WsAction::NewEntry(refs.group(*g)?),
        A::EditEntry(e) => WsAction::EditEntry(refs.entry(*e)?),
        A::StartAs(t) => WsAction::StartAs(t.map(convert::item_type_back)),
        A::SetType(t) => WsAction::SetType(convert::item_type_back(*t)),
        A::SetGroup(g) => WsAction::SetGroup(refs.group(*g)?),
        A::SetHue(h) => WsAction::SetHue(h.filter(|n| *n < crate::editor::HUES)),
        A::AddField(k) => WsAction::AddField(match k {
            Some(k) => Some(convert::field_kind_back(*k)?),
            None => None,
        }),
        A::AddNamedField(i) => {
            let kind = c
                .entry_form(epoch)?
                .kind
                .unwrap_or(crate::editor::ItemType::Other);
            WsAction::AddNamedField(kind.common().get(usize::from(*i))?)
        }
        A::MoveField(i, up) => WsAction::MoveField(*i, *up),
        A::UndoRemoveField => WsAction::UndoRemoveField,
        A::UseGenerated(i) => WsAction::UseGenerated(*i),
        A::RemoveField(i) => WsAction::RemoveField(*i),
        A::ToggleProtect(i) => WsAction::ToggleProtect(*i),
        A::GenerateInto(i) => WsAction::GenerateInto(*i),
        A::SaveEntry => WsAction::SaveEntry,
        A::NewGroup(g) => WsAction::NewGroup(refs.group(*g)?),
        A::RenameGroup(g) => WsAction::RenameGroup(refs.group(*g)?),
        A::SaveGroup => WsAction::SaveGroup,
        A::MoveTo(i, g) => WsAction::MoveTo(convert::item_back(refs, *i)?, refs.group(*g)?),
        A::Delete(i) => WsAction::Delete(convert::item_back(refs, *i)?),
        A::Restore(i) => WsAction::Restore(convert::item_back(refs, *i)?),
        A::TrashMany(e) => WsAction::TrashMany(entries(refs, e)?),
        A::RestoreMany(e) => WsAction::RestoreMany(entries(refs, e)?),
        A::MoveMany(e, g) => WsAction::MoveMany(entries(refs, e)?, refs.group(*g)?),
        A::ColourMany(e, h) => {
            WsAction::ColourMany(entries(refs, e)?, h.filter(|n| *n < crate::editor::HUES))
        }
        A::Preview(a) => WsAction::Preview(refs.attachment(*a)?),
        A::LoadPreview(a) => WsAction::LoadPreview(refs.attachment(*a)?),
        A::PreviewStep(d) => WsAction::PreviewStep((*d).clamp(-1, 1)),
        A::ClosePreview => WsAction::ClosePreview,
        A::EmptyTrash => WsAction::EmptyTrash,
        A::PurgeExpired => WsAction::PurgeExpired,
        A::RestoreHistory(e, v, resolve) => {
            WsAction::RestoreHistory(refs.entry(*e)?, hex(v)?, *resolve)
        }
        A::PurgeHistory(e) => WsAction::PurgeHistory(refs.entry(*e)?),
        A::Resolve(r, v) => WsAction::Resolve(hex(r)?, hex(v)?),
        A::RestoreSnapshot(id) => WsAction::RestoreSnapshot(hex(id)?),
        A::ExportArchive(b) => WsAction::ExportArchive(*b),
        A::MergeArchive => WsAction::MergeArchive,
        A::AddAttachment(e) => WsAction::AddAttachment(refs.entry(*e)?),
        A::SaveAttachment(a) => WsAction::SaveAttachment(refs.attachment(*a)?),
        A::RemoveAttachment(a) => WsAction::RemoveAttachment(refs.attachment(*a)?),
        A::GenMode(m) => WsAction::GenMode(convert::gen_mode_back(*m)),
        A::GenToggle(f) => WsAction::GenToggle(convert::gen_flag_back(*f)),
        A::Generate => WsAction::Generate,
        A::SuggestPassword => WsAction::SuggestPassword,
        A::SaveGeneratorDefaults => WsAction::SaveGeneratorDefaults,
        A::SaveSettings => WsAction::SaveSettings,
        A::ChangePassword => WsAction::ChangePassword,
        A::EnrollQuick(p) => WsAction::EnrollQuick(convert::quick_policy_back(*p)),
        A::DisableQuick => WsAction::DisableQuick,
        A::AutofillFill(k) => WsAction::AutofillFill(refs.candidate(*k)?),
        A::AutofillCancel => WsAction::AutofillCancel,
        A::AutofillLink(e) => WsAction::AutofillLink(refs.entry(*e)?),
        A::OpenAutofillSettings => WsAction::OpenAutofillSettings,
        A::DeleteOldSnapshots => WsAction::DeleteOldSnapshots,
        A::DeleteSnapshot(id) => WsAction::DeleteSnapshot(hex(id)?),
        A::DeleteAllSnapshots => WsAction::DeleteAllSnapshots,
        A::Compact => WsAction::Compact,
        A::ShowPhrase => WsAction::ShowPhrase,
        A::ConfirmWords => WsAction::ConfirmWords,
        A::HidePhrase => WsAction::HidePhrase,
        A::BeginRotation => WsAction::BeginRotation,
        A::Verify => WsAction::Verify,
        A::LanOffer => WsAction::LanOffer,
        A::LanSync => WsAction::LanSync,
        A::Answer(b) => WsAction::Answer(*b),
        A::KeepSnapshots(b) => WsAction::KeepSnapshots(*b),
        A::Dismiss => WsAction::Dismiss,
        A::RatePassword => WsAction::RatePassword,
        A::TotpOpen(target) => WsAction::TotpOpen(*target),
        A::TotpCheck => WsAction::TotpCheck,
        A::TotpOptions(o) => WsAction::TotpOptions(convert::totp_options_back(*o)),
        A::TotpAdd => WsAction::TotpAdd,
        A::TotpClose => WsAction::TotpClose,
    })
}

/// A secret input's bytes as the controller's `&mut String` (it wipes it).
fn with_text(value: &api::Secret, f: impl FnOnce(&mut String)) -> Result<(), UiError> {
    let text = std::str::from_utf8(value.expose()).map_err(|_| UiError::Malformed)?;
    let mut s = String::with_capacity(text.len());
    s.push_str(text);
    f(&mut s);
    s.zeroize();
    Ok(())
}

/// An attachment's name, for the save dialog's suggestion.
#[cfg(any(target_os = "linux", windows))]
fn attachment_name(c: &Controller, epoch: FormEpoch, h: qv_core::AttachmentHandle) -> String {
    if let Some(p) = c.peek(epoch, |ws| ws.preview.clone()).flatten()
        && p.handle == h
    {
        return p.name.to_string();
    }
    if let Some(Screen::Attachments(e)) = c.screen(epoch)
        && let Some(Ok(rows)) = c.read(epoch, |s| crate::views::attachments(s, e))
        && let Some(a) = rows.iter().find(|a| a.handle == h)
    {
        return a.name.to_string();
    }
    "attachment".to_owned()
}

fn pick(c: &Controller, epoch: FormEpoch, refs: &Refs, p: &api::Pick) -> Result<(), UiError> {
    #[cfg(any(target_os = "linux", windows))]
    {
        use crate::documents::{PathFor, Pick, pick_path};
        let ws = |kind: Pick, title: &'static str, then: WsAction| {
            pick_path(c, epoch, PathFor::Workspace, kind, title, Some(then));
        };
        match p {
            api::Pick::Vault => crate::documents::pick_vault(c, epoch),
            api::Pick::Folder => pick_path(
                c,
                epoch,
                PathFor::Folder,
                Pick::Folder,
                "Choose where new vaults are saved",
                None,
            ),
            api::Pick::NewVault => pick_path(
                c,
                epoch,
                PathFor::Locked,
                Pick::Save("vault.qvault".into()),
                "Save the new vault",
                None,
            ),
            api::Pick::AddAttachment(e) => ws(
                Pick::Open,
                "Add an attachment",
                WsAction::AddAttachment(refs.entry(*e).ok_or(UiError::NotFound)?),
            ),
            api::Pick::SaveAttachment(a) => {
                let h = refs.attachment(*a).ok_or(UiError::NotFound)?;
                ws(
                    Pick::Save(attachment_name(c, epoch, h)),
                    "Save the attachment",
                    WsAction::SaveAttachment(h),
                )
            }
            api::Pick::RestoreSnapshot(id) => ws(
                Pick::Save("restored.qvault".into()),
                "Save the restored vault",
                WsAction::RestoreSnapshot(hex(id).ok_or(UiError::Malformed)?),
            ),
            api::Pick::ExportArchive(b) => ws(
                Pick::Folder,
                "Choose a folder for the archive",
                WsAction::ExportArchive(*b),
            ),
            api::Pick::MergeArchive => ws(
                Pick::Open,
                "Choose an archive to merge",
                WsAction::MergeArchive,
            ),
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = (refs, p);
        if matches!(p, api::Pick::Vault) {
            crate::documents::pick_vault(c, epoch);
        }
        Ok(())
    }
}

/// The validation flow's report (validation builds only).
#[cfg(feature = "fixture")]
fn fixture(c: &Controller, value: &str) {
    if value.len() > 128 {
        return;
    }
    // Terminal results end the process.
    if value.starts_with("BOUNDARY:") || value == "PASS" || value.starts_with("FAIL") {
        super::remove_temporary();
    }
    if let Some(result) = value.strip_prefix("BOUNDARY:") {
        if result == "PASS" {
            println!("boundary harness passed");
            std::process::exit(0);
        }
        eprintln!("boundary harness failed checks: {result}");
        std::process::exit(1);
    }
    if crate::validation_media::enabled()
        && let Some(stage) = value
            .strip_prefix("MEDIA-STAGE:")
            .and_then(|n| n.parse::<u8>().ok())
    {
        println!("synthetic media stage {stage}");
        return;
    }
    if crate::validation_media::enabled()
        && let Some(frames) = value.strip_prefix("MEDIA-FRAMES:")
        && frames.len() <= 54
        && frames.split(',').count() == 5
        && frames.split(',').all(|n| n.parse::<u32>().is_ok())
    {
        println!("synthetic media frames {frames}");
        return;
    }
    if crate::validation_media::enabled()
        && let Some(facts) = value.strip_prefix("MEDIA-FACTS:")
        && facts.len() <= 80
        && facts.split(',').count() == 11
        && facts.split(',').all(|n| n.parse::<u32>().is_ok())
    {
        println!("synthetic media facts {facts}");
        return;
    }
    #[cfg(target_os = "linux")]
    if value == "LAN-PEER" {
        crate::lan::fixture::start(c);
        return;
    }
    if let Some(stage) = value
        .strip_prefix("FAIL:")
        .and_then(|n| n.parse::<u8>().ok())
    {
        eprintln!("synthetic flow stage {stage} failed");
        if let Some(v) = c.lan_view(c.snapshot().epoch) {
            if let Some(d) = v.done {
                let confirmed = d
                    .lines
                    .first()
                    .is_some_and(|s| s == "A new device joined this vault.");
                eprintln!(
                    "synthetic LAN receipt: confirmed={confirmed} error={:?}",
                    d.error
                );
            } else {
                eprintln!("synthetic LAN is still active");
            }
        }
    }
    if crate::validation_media::enabled() {
        crate::validation_media::finish(c, value == "PASS");
        return;
    }
    c.finish_fixture(value == "PASS")
}

/// Handles one decoded request (not `Frame`, which the caller long-polls).
pub(crate) fn handle(
    c: &Controller,
    refs: &mut Refs,
    hooks: &mut Hooks,
    ui: &mut UiState,
    generation: u64,
    request: Request,
) -> Result<(), UiError> {
    let epoch = FormEpoch(generation);
    match request {
        Request::Frame { .. } | Request::Window { .. } => Ok(()),
        Request::Activity => {
            c.activity(epoch);
            Ok(())
        }
        Request::Input { field, value } => match field {
            Field::Locked(f) => with_text(&value, |s| c.input(epoch, locked_field(f), s)),
            Field::Ws(f) => with_text(&value, |s| c.ws_input(epoch, ws_field(f), s)),
            Field::LanSecret { question } => {
                with_text(&value, |s| c.lan_secret(epoch, question, s))
            }
        },
        Request::Key { key, ctrl } => {
            if key.len() > 32 {
                return Err(UiError::Malformed);
            }
            c.activity(epoch);
            if key == "Escape" && c.lan_escape(epoch) {
                return Ok(());
            }
            let handled = Shortcut::from_key(&key, ctrl)
                .is_some_and(|s| s != Shortcut::Search && c.shortcut(epoch, s));
            if !handled && key == "Escape" && cfg!(target_os = "android") {
                // Android Back arrives as Escape; nothing took it, so the
                // activity asks for a second Back before closing (plan 0044).
                #[cfg(target_os = "android")]
                crate::android::back_at_root();
            }
            Ok(())
        }
        Request::PageTurn {
            slot,
            serial,
            forward,
        } => {
            let owner = hooks.owner(&slot).ok_or(UiError::NotFound)?;
            c.page_turn(epoch, owner, serial, forward);
            Ok(())
        }
        Request::Act { act } => handle_act(c, refs, ui, epoch, act),
    }
}

fn handle_act(
    c: &Controller,
    refs: &mut Refs,
    ui: &mut UiState,
    epoch: FormEpoch,
    act: Act,
) -> Result<(), UiError> {
    let missing = UiError::NotFound;
    match act {
        Act::Lock => c.lock(),
        Act::Theme(name) => {
            let theme = match name.as_str() {
                "dark" => crate::prefs::Theme::Dark,
                "light" => crate::prefs::Theme::Light,
                "system" => crate::prefs::Theme::System,
                _ => return Err(UiError::Malformed),
            };
            if let Err(e) = c.set_theme(theme) {
                c.report(epoch, e);
            }
            c.touch();
        }
        Act::Perform(action, consent) => {
            let consent = match consent {
                api::Consent::Recorded => c.consent(),
                api::Consent::Given(b) => b,
            };
            c.perform(epoch, convert::action_back(action), consent);
        }
        Act::AcknowledgeProtection(next) => {
            match c.acknowledge_protection() {
                Ok(()) => {
                    if let Some(action) = next {
                        c.perform(epoch, convert::action_back(action), c.consent());
                    }
                }
                Err(e) => c.report(epoch, e),
            }
            c.touch();
        }
        Act::QuickStarted => c.quick_started(),
        Act::RatePassword => c.rate_password(epoch),
        Act::SelectMode(m) => c.select_mode(epoch, convert::mode_back(m)),
        Act::SelectVault(r) => {
            let path = refs.vault(r).ok_or(missing)?;
            let mut empty = String::new();
            c.input(epoch, InputField::Path, &mut empty);
            c.select_vault(epoch, &path);
        }
        Act::ForgetVault(r) => c.forget_vault(epoch, &refs.vault(r).ok_or(missing)?),
        Act::ImportAck(b) => c.acknowledge_vault_import(epoch, b),
        Act::SwitchVault(to) => {
            let to = match to {
                api::SwitchTo::Vault(r) => SwitchTo::Vault(refs.vault(r).ok_or(missing)?),
                api::SwitchTo::Mode(m) => SwitchTo::Mode(convert::mode_back(m)),
            };
            c.switch_vault(epoch, to);
        }
        Act::SwitchToFile => crate::documents::switch_to_file(c, epoch),
        Act::Pick(p) => pick(c, epoch, refs, &p)?,
        Act::AndroidPick(k) => {
            #[cfg(target_os = "android")]
            {
                use crate::documents::PickKind;
                let (kind, create) = match k {
                    api::AndroidPick::Open => (PickKind::Any, false),
                    api::AndroidPick::Create => (PickKind::Any, true),
                    api::AndroidPick::ArchiveOpen => (PickKind::Archive, false),
                    api::AndroidPick::ArchiveCreate => (PickKind::Archive, true),
                };
                crate::android::request_pick(c, epoch, kind, create);
            }
            #[cfg(not(target_os = "android"))]
            let _ = k;
        }
        Act::Go(s) => c.navigate(epoch, convert::screen_back(refs, &s).ok_or(missing)?),
        Act::Select(s) => c.select(epoch, convert::screen_back(refs, &s).ok_or(missing)?),
        Act::Back => c.back(epoch),
        Act::Ws(a) => c.act(epoch, ws_back(c, epoch, refs, &a).ok_or(missing)?),
        Act::QuickCopy(e, secret) => {
            let e = refs.entry(e).ok_or(missing)?;
            let handles = c
                .read(epoch, |s| crate::views::quick_fields(s, e))
                .and_then(Result::ok);
            if let Some(h) = handles.and_then(|(u, p)| if secret { p } else { u }) {
                c.act(
                    epoch,
                    WsAction::Copy(crate::workspace::CopyKey::Field(e, h)),
                );
            } else {
                // No such field: say so instead of doing nothing (plan 0069).
                c.with_ws(epoch, |ws, _| {
                    ws.notice = Some(crate::workspace::NOTHING_TO_COPY);
                    ws.error = None;
                });
            }
        }
        Act::Selection(set) => {
            let set = match set {
                Some(ids) => {
                    if ids.len() > 4096 {
                        return Err(UiError::Malformed);
                    }
                    Some(
                        ids.iter()
                            .map(|i| hex(i).ok_or(UiError::Malformed))
                            .collect::<Result<std::collections::BTreeSet<_>, _>>()?,
                    )
                }
                None => None,
            };
            c.set_selection(epoch, set);
        }
        Act::RequestQr(t) => c.request_qr(
            epoch,
            match t {
                api::QrTarget::NewDevice => crate::qr::QrTarget::NewDevice,
                api::QrTarget::Sync => crate::qr::QrTarget::Sync,
                api::QrTarget::Totp => crate::qr::QrTarget::Totp,
            },
        ),
        Act::CancelQr => c.cancel_qr(epoch),
        Act::LanAnswer(id, yes) => c.lan_answer(epoch, id, yes),
        Act::LanCancel => c.lan_cancel(epoch),
        Act::LanKeep => c.lan_keep(epoch),
        Act::LanDismiss => c.lan_dismiss(epoch),
        Act::LanResolve => {
            // One conflicted record opens its comparison directly.
            let only = c
                .read(epoch, |s| {
                    let rows = s.conflict_records()?;
                    Ok::<_, qv_core::CoreError>((rows.len() == 1).then(|| rows[0].handle.id_hex()))
                })
                .and_then(Result::ok)
                .flatten();
            // Close the receipt first: navigating starts a new epoch.
            c.lan_dismiss(epoch);
            c.navigate(
                epoch,
                only.map_or(Screen::Conflicts, Screen::ConflictRecord),
            );
        }
        Act::LanOpen(r) => {
            let e = refs.entry(r).ok_or(missing)?;
            c.lan_keep(epoch);
            c.navigate(epoch, Screen::Entry(e));
        }
        Act::Ui(op) => {
            match op {
                api::UiOp::Palette(open) => ui.palette = open,
                api::UiOp::CopyMenu(rid) => {
                    ui.copy_menu = rid.and_then(|r| hex(&r));
                    ui.row_menu = None;
                }
                api::UiOp::RowMenu(rid) => {
                    ui.row_menu = rid.and_then(|r| hex(&r));
                    ui.copy_menu = None;
                }
                api::UiOp::GroupMenu(open) => ui.group_menu = open,
                api::UiOp::BarPop(p) => ui.bar_pop = p,
                api::UiOp::EditorPop(p) => {
                    // Opening the generator: characters (not a PIN), then a
                    // fresh value.
                    if matches!(p, Some(api::EditorPop::Gen(_))) && ui.editor_pop != p {
                        if c.generator_form(epoch)
                            .is_some_and(|g| g.mode == crate::workspace::GenMode::Pin)
                        {
                            c.act(
                                epoch,
                                WsAction::GenMode(crate::workspace::GenMode::Characters),
                            );
                        }
                        c.act(epoch, WsAction::Generate);
                    }
                    ui.editor_pop = p;
                }
            }
            c.touch();
        }
        Act::Fixture(value) => {
            #[cfg(feature = "fixture")]
            fixture(c, &value);
            #[cfg(not(feature = "fixture"))]
            let _ = value;
        }
    }
    Ok(())
}

#[cfg(all(test, feature = "fixture"))]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use qv_ui_api::{Ref, WsAct};

    fn send(c: &Controller, refs: &mut Refs, request: Request) -> Result<(), UiError> {
        let mut hooks = Hooks::default();
        let mut ui = UiState::default();
        handle(c, refs, &mut hooks, &mut ui, 0, request)
    }

    // 0012 §1: Webview exposure
    #[test]
    fn unknown_references_slots_keys_and_names_are_refused() {
        let c = Controller::preview().unwrap();
        let mut refs = Refs::default();
        // A reference the backend never issued (or cleared on lock).
        let forged = Ref([7; 16]);
        for act in [
            Act::Select(api::Screen::Entry(forged)),
            Act::QuickCopy(forged, true),
            Act::Ws(WsAct::EditEntry(forged)),
            Act::Ws(WsAct::Preview(forged)),
            Act::LanOpen(forged),
        ] {
            assert_eq!(
                send(&c, &mut refs, Request::Act { act }),
                Err(UiError::NotFound)
            );
        }
        let turn = Request::PageTurn {
            slot: "nowhere".into(),
            serial: 0,
            forward: true,
        };
        assert_eq!(send(&c, &mut refs, turn), Err(UiError::NotFound));
        let key = Request::Key {
            key: "k".repeat(33),
            ctrl: false,
        };
        assert_eq!(send(&c, &mut refs, key), Err(UiError::Malformed));
        let theme = Act::Theme("sepia".into());
        assert_eq!(
            send(&c, &mut refs, Request::Act { act: theme }),
            Err(UiError::Malformed)
        );
    }
}
