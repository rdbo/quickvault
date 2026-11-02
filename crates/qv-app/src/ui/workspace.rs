// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unlocked screens shared by Android and Linux. Vault text renders only as
//! escaped text; protected values appear only through a 30 s reveal. Every
//! handler sends a typed action with the current form epoch; Rust re-checks it.
use crate::controller::{AppError, Controller, FormEpoch};
use crate::views::{self, EntryView, FieldRow, kind_name};
use crate::workspace::{
    ConfirmKind, CopyKey, GenFlag, GenMode, Live, Pane, Report, RevealKey, Screen, WsAction,
    WsField,
};
use dioxus::prelude::*;
use qv_core::{FieldKind, ItemHandle};

fn act(c: &Controller, e: FormEpoch, a: WsAction) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| c.act(e, a.clone())
}
fn go(c: &Controller, e: FormEpoch, s: Screen) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| c.navigate(e, s.clone())
}
fn text(v: Option<qv_core::SecretBytes>) -> String {
    v.map(|v| String::from_utf8_lossy(v.expose_secret()).into_owned())
        .unwrap_or_default()
}
const MASK: &str = "••••••••";
/// Stable DOM id for an input (accessibility labels and the synthetic flow).
fn dom_id(field: WsField) -> String {
    match field {
        WsField::Query => "ws-query".into(),
        WsField::Title => "ws-title".into(),
        WsField::TypeHint => "ws-type".into(),
        WsField::Notes => "ws-notes".into(),
        WsField::FieldName(i) => format!("ws-field-name-{i}"),
        WsField::FieldValue(i) => format!("ws-field-value-{i}"),
        WsField::Replacement(i) => format!("ws-replacement-{i}"),
        WsField::NewFieldName => "ws-new-field".into(),
        WsField::GroupName => "ws-group-name".into(),
        WsField::Path => "ws-path".into(),
        WsField::Password => "ws-password".into(),
        WsField::NewPassword => "ws-new-password".into(),
        WsField::Repeat => "ws-repeat".into(),
        WsField::Word(i) => format!("ws-word-{i}"),
        WsField::GenLength => "ws-gen-length".into(),
        WsField::GenWords => "ws-gen-words".into(),
        WsField::GenSeparator => "ws-gen-separator".into(),
        WsField::GenExclude => "ws-gen-exclude".into(),
        WsField::VaultName => "ws-vault-name".into(),
        WsField::Description => "ws-description".into(),
        WsField::HistoryDepth => "ws-history-depth".into(),
        WsField::TrashDays => "ws-trash-days".into(),
        WsField::AttachMime => "ws-attach-mime".into(),
        WsField::AttachName => "ws-attach-name".into(),
        WsField::Confirmation => "ws-confirmation".into(),
    }
}

/// Input kinds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Single-line text (controlled when a value is given).
    Line,
    /// Masked secret, never prefilled.
    Secret,
    /// Multi-line text.
    Multi,
}
#[component]
fn Input(
    controller: Controller,
    epoch: FormEpoch,
    field: WsField,
    label: String,
    kind: Kind,
    value: Option<String>,
    disabled: bool,
) -> Element {
    let limit = match field {
        WsField::Query => crate::workspace::QUERY_MAX,
        WsField::Path => crate::workspace::PATH_MAX,
        WsField::Notes | WsField::Replacement(_) => crate::workspace::MULTI_MAX,
        _ if kind == Kind::Multi => crate::workspace::MULTI_MAX,
        _ => crate::workspace::LINE_MAX,
    };
    let controlled = value.is_some();
    let id = dom_id(field);
    let c = controller.clone();
    let oninput = move |event: FormEvent| {
        let mut v = event.value();
        c.ws_input(epoch, field, &mut v);
    };
    rsx! {
        label { class: "field",
            span { "{label}" }
            if kind == Kind::Multi {
                textarea {
                    id: id.clone(),
                    maxlength: limit,
                    disabled,
                    spellcheck: "false",
                    autocomplete: "off",
                    "data-qv-controlled": if controlled { "true" } else { "false" },
                    value: value.clone().unwrap_or_default(),
                    oninput,
                }
            } else {
                input {
                    id: id.clone(),
                    r#type: if kind == Kind::Secret { "password" } else { "text" },
                    maxlength: limit,
                    disabled,
                    autocomplete: "off",
                    spellcheck: "false",
                    autocapitalize: "off",
                    autocorrect: "off",
                    "data-qv-controlled": if controlled { "true" } else { "false" },
                    value: value.clone().unwrap_or_default(),
                    oninput,
                }
            }
        }
    }
}
/// The unlocked application shell.
#[component]
pub fn Shell(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    live: Live,
    busy: bool,
    reduced_lifecycle: bool,
    fixture: bool,
    on_fixture: EventHandler<FormEvent>,
) -> Element {
    let _ = revision;
    let Some(screen) = controller.screen(epoch) else {
        return rsx! {};
    };
    let overview = controller.read(epoch, views::overview).and_then(Result::ok);
    let name = overview
        .as_ref()
        .map_or_else(String::new, |o| o.name.to_string());
    let trash = overview.as_ref().map_or(0, |o| o.trash);
    let conflicts = overview.as_ref().map_or(0, |o| o.conflicts);
    let (notice, error, report) = controller.status(epoch).unwrap_or((None, None, None));
    let pending = controller.pending(epoch);
    let lock = {
        let c = controller.clone();
        move |_| c.lock()
    };
    let nav = [
        (Screen::Browse(None), "Vault", "▤"),
        (Screen::Search, "Search", "⌕"),
        (Screen::Generator, "Generator", "✱"),
        (Screen::Trash, "Trash", "⌫"),
        (Screen::Conflicts, "Conflicts", "⇄"),
        (Screen::Snapshots, "Snapshots", "◷"),
        (Screen::Archives, "Archives", "⇅"),
        (Screen::Settings(Pane::General), "Settings", "⚙"),
    ];
    let current = |s: &Screen| match (s, &screen) {
        (
            Screen::Browse(_),
            Screen::Browse(_)
            | Screen::Entry(_)
            | Screen::EditEntry
            | Screen::EditGroup
            | Screen::Move(..)
            | Screen::History(_)
            | Screen::HistoryVersion(..)
            | Screen::Attachments(_)
            | Screen::Recovered,
        ) => true,
        (Screen::Settings(_), Screen::Settings(_)) => true,
        (Screen::Conflicts, Screen::ConflictRecord(_)) => true,
        (a, b) => a == b,
    };
    rsx! {
        main { class: "ws", "data-qv-epoch": "{epoch.0}",
            header { class: "ws-top",
                div { class: "brand", span { class: "brand-mark", "Q" } span { class: "ws-name", "{name.as_str()}" } }
                button { class: "lock-button", "data-qv-clear": "true", onclick: lock, "Lock" }
            }
            if reduced_lifecycle {
                p { class: "warning ws-banner", role: "status",
                    "Automatic locking on screen lock or sleep is unavailable. Manual lock and the 60-second inactivity lock remain active."
                }
            }
            div { class: "ws-body",
                nav { class: "ws-nav", "aria-label": "Sections",
                    for (target, label, icon) in nav {
                        button {
                            class: if current(&target) { "nav-item selected" } else { "nav-item" },
                            disabled: busy,
                            onclick: go(&controller, epoch, target.clone()),
                            span { class: "nav-icon", "{icon}" }
                            span { class: "nav-label", "{label}" }
                            if label == "Trash" && trash > 0 { span { class: "badge", "{trash}" } }
                            if label == "Conflicts" && conflicts > 0 { span { class: "badge alert", "{conflicts}" } }
                        }
                    }
                }
                section { class: "ws-main",
                    if busy {
                        div { class: "busy", role: "status", "Working… The vault stays locked to other actions until this finishes." }
                    } else {
                        if let Some(kind) = pending {
                            Confirm { controller: controller.clone(), epoch, kind }
                        }
                        if let Some(n) = notice { p { class: "notice", role: "status", "{n}" } }
                        if let Some(e) = error { p { class: "error", role: "alert", "{e.message()}" } }
                        if let Some(r) = report { ReportView { controller: controller.clone(), epoch, report: r } }
                        for k in [epoch.0] {
                            div { key: "{k}", class: "screen",
                                Body { controller: controller.clone(), epoch, revision, live, screen: screen.clone() }
                            }
                        }
                    }
                }
            }
            if live.clipboard > 0 {
                div { class: "toast", role: "status", "Copied · clears in {live.clipboard} s if unchanged" }
            }
            if fixture { input { id: "validation-result", oninput: move |e| on_fixture.call(e) } }
        }
    }
}
#[component]
fn Confirm(controller: Controller, epoch: FormEpoch, kind: ConfirmKind) -> Element {
    let message = match kind {
        ConfirmKind::DeleteRecursive => "Move this group and everything in it to the trash?".to_owned(),
        ConfirmKind::EmptyTrash => "Permanently delete every non-conflicted item in the trash? A recovery snapshot is taken first. Independent copies may remain.".to_owned(),
        ConfirmKind::PurgeExpired(false) => "Permanently delete the trash items past their retention period? A recovery snapshot is taken first.".to_owned(),
        ConfirmKind::PurgeExpired(true) => "Vault dates are ahead of this device's clock, so expiry may be wrong. Check the clock first. Permanently delete the expired items anyway?".to_owned(),
        ConfirmKind::PurgeHistory => "Purge this entry's local history? Active versions remain. Snapshots, unseen concurrent history and independent copies may remain; there is no secure erasure.".to_owned(),
        ConfirmKind::RemoveAttachment => "Permanently remove this attachment? Independent copies may remain; there is no secure erasure.".to_owned(),
        ConfirmKind::SaveAttachment => "Write this attachment's plaintext to the chosen file? It is not encrypted there, and a failure may leave incomplete plaintext.".to_owned(),
        ConfirmKind::SelfContained => "Include the password slot? Anyone holding this file can try offline master-password guessing, and a later password change does not revoke it.".to_owned(),
        ConfirmKind::Resolve(false) => "Create a new complete version from this choice, covering every version shown? Edits not seen here may still conflict.".to_owned(),
        ConfirmKind::Resolve(true) => "This choice permanently deletes the record's payload and history. Independent copies may remain. Create this resolution?".to_owned(),
        ConfirmKind::RestoreConflicts => "Restore this version and resolve the entry's current conflict with it?".to_owned(),
        ConfirmKind::OverBudget(n) => format!("The mandatory recovery snapshot needs {n} bytes and exceeds the snapshot budget. Allow it to exceed the budget? Nothing changes otherwise."),
        ConfirmKind::OldSnapshots(n) => format!("{n} local snapshots were taken before this password change and still open with the old password. Delete them? Copies elsewhere remain; deletion is not cryptographic erasure."),
        ConfirmKind::WeakPassword => "This password is weak and could be guessed by an attacker who obtains your vault file. Use it anyway?".to_owned(),
    };
    rsx! {
        div { class: "dialog", role: "alertdialog", "aria-label": "Confirmation",
            p { "{message}" }
            div { class: "row",
                button { class: "secondary", onclick: act(&controller, epoch, WsAction::Answer(false)), "Cancel" }
                button { class: "danger", onclick: act(&controller, epoch, WsAction::Answer(true)), "Continue" }
            }
        }
    }
}
#[component]
fn ReportView(controller: Controller, epoch: FormEpoch, report: Report) -> Element {
    let lines: Vec<String> = match &report {
        Report::Merge {
            accepted,
            conflicts,
            incomplete,
        } => vec![
            if *accepted {
                "Archive merged: a new local acceptance was committed.".into()
            } else {
                "This archive was already accepted.".into()
            },
            format!("Conflicts now: {conflicts}"),
            if *incomplete {
                "Completion reporting failed after the durable acceptance; check the vault before retrying.".into()
            } else {
                String::new()
            },
        ],
        Report::Export {
            id,
            self_contained,
            incomplete,
        } => vec![
            format!("Archive published: {id}"),
            if *self_contained {
                "It includes the password slot.".into()
            } else {
                "It opens only with this vault's key (another device or the recovery phrase)."
                    .into()
            },
            if *incomplete {
                "Crash durability is unconfirmed because publication completion failed.".into()
            } else {
                String::new()
            },
        ],
        Report::Resolved {
            conflicts,
            incomplete,
        } => vec![
            format!("Resolution committed. Conflicts now: {conflicts}"),
            if *incomplete {
                "Completion reporting failed after durable publication.".into()
            } else {
                String::new()
            },
        ],
        Report::Verify {
            ok,
            anchor,
            objects,
            bytes,
            records,
            notes,
        } => {
            let mut v = vec![
                if *ok {
                    "Integrity check passed.".to_owned()
                } else {
                    "Integrity check FAILED. Keep the original file and recover from a verified backup.".to_owned()
                },
                format!("External anchor: {anchor}"),
                format!("{objects} objects ({bytes} bytes) re-hashed; {records} records checked"),
            ];
            v.extend(notes.iter().map(|n| format!("Note: {n}")));
            v
        }
        Report::Purged { purged, kept } => vec![
            format!("{purged} item(s) permanently deleted."),
            if *kept > 0 {
                format!("{kept} conflicted item(s) kept in the trash.")
            } else {
                String::new()
            },
        ],
    };
    rsx! {
        div { class: "report", role: "status",
            for l in lines.into_iter().filter(|l| !l.is_empty()) { p { "{l}" } }
            button { class: "text-button", onclick: act(&controller, epoch, WsAction::Dismiss), "Dismiss" }
        }
    }
}
#[component]
fn Body(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    live: Live,
    screen: Screen,
) -> Element {
    let _ = (revision, live);
    let c = controller;
    match screen {
        Screen::Browse(g) => rsx! { Browse { controller: c, epoch, revision, group: g } },
        Screen::Recovered => rsx! { Recovered { controller: c, epoch, revision } },
        Screen::Search => rsx! { Search { controller: c, epoch, revision } },
        Screen::Entry(e) => rsx! { EntryScreen { controller: c, epoch, revision, entry: e } },
        Screen::EditEntry => rsx! { EditEntry { controller: c, epoch, revision } },
        Screen::EditGroup => rsx! { EditGroup { controller: c, epoch, revision } },
        Screen::Move(item, at) => rsx! { Move { controller: c, epoch, revision, item, at } },
        Screen::Trash => rsx! { Trash { controller: c, epoch, revision } },
        Screen::History(e) => rsx! { History { controller: c, epoch, revision, entry: e } },
        Screen::HistoryVersion(e, v) => {
            rsx! { HistoryVersion { controller: c, epoch, revision, entry: e, version: v } }
        }
        Screen::Conflicts => rsx! { Conflicts { controller: c, epoch, revision } },
        Screen::ConflictRecord(r) => {
            rsx! { ConflictRecord { controller: c, epoch, revision, record: r } }
        }
        Screen::Attachments(e) => rsx! { Attachments { controller: c, epoch, revision, entry: e } },
        Screen::Generator => rsx! { Generator { controller: c, epoch, revision } },
        Screen::Snapshots => rsx! { Snapshots { controller: c, epoch, revision } },
        Screen::Archives => rsx! { Archives { controller: c, epoch, revision } },
        Screen::Settings(p) => rsx! { Settings { controller: c, epoch, revision, pane: p } },
    }
}
#[component]
fn Unreadable(error: Option<AppError>) -> Element {
    let message = error.map_or("Loading…", AppError::message);
    rsx! { p { class: "muted", "{message}" } }
}
#[component]
fn Browse(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    group: Option<qv_core::GroupHandle>,
) -> Element {
    let _ = revision;
    let view = match controller.read(epoch, |s| views::browse(s, group)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let here = view.here;
    rsx! {
        div { class: "crumbs",
            for (g, name) in view.crumbs.iter().cloned() {
                button { class: "crumb", onclick: go(&controller, epoch, Screen::Browse(Some(g))), "{name.as_str()}" }
            }
        }
        div { class: "toolbar",
            button { class: "primary-small", onclick: act(&controller, epoch, WsAction::NewEntry(here)), "New entry" }
            button { class: "secondary-small", onclick: act(&controller, epoch, WsAction::NewGroup(here)), "New group" }
            if !view.root {
                button { class: "secondary-small", onclick: act(&controller, epoch, WsAction::RenameGroup(here)), "Rename" }
                button { class: "secondary-small", onclick: go(&controller, epoch, Screen::Move(ItemHandle::Group(here), None)), "Move" }
                button { class: "danger-small", onclick: act(&controller, epoch, WsAction::Delete(ItemHandle::Group(here))), "Delete" }
            }
        }
        if view.groups.is_empty() && view.entries.is_empty() {
            p { class: "muted empty", "Nothing here yet. Create an entry to get started." }
        }
        ul { class: "list",
            for g in view.groups.iter().cloned() {
                li { button { class: "row-button", onclick: go(&controller, epoch, Screen::Browse(Some(g.handle))),
                    span { class: "row-icon", "▸" }
                    span { class: "row-title", "{g.name.as_str()}" }
                    if g.conflict { span { class: "badge alert", "conflict" } }
                } }
            }
            for e in view.entries.iter().cloned() {
                li { button { class: "row-button", onclick: go(&controller, epoch, Screen::Entry(e.handle)),
                    span { class: "row-icon", "•" }
                    span { class: "row-text", span { class: "row-title", "{e.title.as_str()}" } span { class: "row-sub", "{e.subtitle.as_str()}" } }
                    if e.conflict { span { class: "badge alert", "conflict" } }
                } }
            }
        }
        if view.recovered > 0 {
            button { class: "text-button", onclick: go(&controller, epoch, Screen::Recovered), "Recovered items ({view.recovered})" }
        }
    }
}
#[component]
fn Recovered(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let rows = match controller.read(epoch, views::recovered) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    rsx! {
        h2 { "Recovered items" }
        p { class: "muted", "These entries' groups are missing. Move them into a group to keep them organised." }
        ul { class: "list",
            for e in rows {
                li { button { class: "row-button", onclick: go(&controller, epoch, Screen::Entry(e.handle)),
                    span { class: "row-title", "{e.title.as_str()}" }
                } }
            }
        }
    }
}
#[component]
fn Search(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let query = controller
        .peek(epoch, |ws| {
            String::from_utf8_lossy(ws.input(WsField::Query)).into_owned()
        })
        .unwrap_or_default();
    let results = controller
        .read(epoch, |s| views::search(s, &query))
        .and_then(Result::ok);
    rsx! {
        h2 { "Search" }
        p { class: "muted", "Titles, usernames, URLs and group names. Protected values are never searched." }
        Input { controller: controller.clone(), epoch, field: WsField::Query, label: "Search the vault", kind: Kind::Line, value: Some(query.clone()), disabled: false }
        if let Some((groups, entries)) = results {
            if !query.is_empty() && groups.is_empty() && entries.is_empty() { p { class: "muted", "No matches." } }
            ul { class: "list",
                for g in groups {
                    li { button { class: "row-button", onclick: go(&controller, epoch, Screen::Browse(Some(g.handle))), span { class: "row-icon", "▸" } span { class: "row-title", "{g.name.as_str()}" } } }
                }
                for e in entries {
                    li { button { class: "row-button", onclick: go(&controller, epoch, Screen::Entry(e.handle)),
                        span { class: "row-text", span { class: "row-title", "{e.title.as_str()}" } span { class: "row-sub", "{e.subtitle.as_str()}" } }
                    } }
                }
            }
        }
    }
}
#[component]
fn FieldLine(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: Option<qv_core::EntryHandle>,
    field: FieldRow,
    reveal: RevealKey,
    copy: bool,
) -> Element {
    let _ = revision;
    let shown = text(controller.revealed(epoch, &reveal));
    let revealed = !shown.is_empty();
    let totp = field.kind == FieldKind::Totp;
    let code_key = RevealKey::Totp(field.handle);
    let code = if totp {
        text(controller.revealed(epoch, &code_key))
    } else {
        String::new()
    };
    let value = if let Some(v) = &field.value {
        v.to_string()
    } else if revealed {
        shown
    } else {
        MASK.to_owned()
    };
    rsx! {
        div { class: "field-line",
            span { class: "field-name", "{field.name.as_str()}" span { class: "kind", "{kind_name(field.kind)}" } }
            if field.kind == FieldKind::Multiline || value.contains('\n') {
                pre { class: if revealed { "field-value revealed" } else { "field-value" }, "{value.as_str()}" }
            } else {
                span { class: if revealed { "field-value revealed" } else { "field-value" }, "{value.as_str()}" }
            }
            div { class: "field-actions",
                if field.protected {
                    if revealed {
                        button { class: "chip", onclick: act(&controller, epoch, WsAction::Hide), "Hide" }
                    } else {
                        button { class: "chip", onclick: act(&controller, epoch, WsAction::Reveal(reveal.clone())), "Reveal 30 s" }
                    }
                }
                if totp {
                    if code.is_empty() {
                        button { class: "chip", onclick: act(&controller, epoch, WsAction::Reveal(code_key.clone())), "Show code" }
                    } else {
                        span { class: "code revealed", "{code}" }
                    }
                }
                if copy && let Some(e) = entry {
                    button { class: "chip", onclick: act(&controller, epoch, WsAction::Copy(CopyKey::Field(e, field.handle))), "Copy" }
                    if totp {
                        button { class: "chip", onclick: act(&controller, epoch, WsAction::Copy(CopyKey::Totp(e, field.handle))), "Copy code" }
                    }
                }
            }
        }
    }
}
#[component]
fn EntryBody(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    view: EntryView,
    history: Option<String>,
) -> Element {
    let current = history.is_none();
    rsx! {
        h2 { "{view.title.as_str()}" }
        p { class: "muted", "{view.type_hint.as_str()} · modified {view.modified} · created {view.created}" }
        if let Some(x) = &view.expires { p { class: "muted", "Expires {x}" } }
        if view.versions > 1 {
            p { class: "warning", "This entry has {view.versions} conflicting versions; one is shown. Resolve the conflict before copying or editing." }
        }
        if view.deleted { p { class: "warning", "This entry is in the trash." } }
        div { class: "fields",
            for f in view.fields.iter().cloned() {
                FieldLine {
                    controller: controller.clone(),
                    epoch,
                    revision,
                    entry: current.then_some(view.handle),
                    reveal: match &history { Some(v) => RevealKey::History(v.clone(), f.id), None => RevealKey::Field(f.handle) },
                    copy: current && view.versions == 1,
                    field: f,
                }
            }
        }
        if let Some(n) = &view.notes {
            div { class: "notes", span { class: "field-name", "Notes" } pre { "{n.as_str()}" } }
        }
    }
}
#[component]
fn EntryScreen(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: qv_core::EntryHandle,
) -> Element {
    let _ = revision;
    let view = match controller.read(epoch, |s| views::entry(s, entry)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let item = ItemHandle::Entry(entry);
    rsx! {
        EntryBody { controller: controller.clone(), epoch, revision, view: view.clone(), history: None }
        div { class: "toolbar",
            if view.deleted {
                button { class: "primary-small", onclick: act(&controller, epoch, WsAction::Restore(item)), "Restore" }
            } else {
                button { class: "primary-small", disabled: view.versions > 1, onclick: act(&controller, epoch, WsAction::EditEntry(entry)), "Edit" }
                button { class: "secondary-small", onclick: go(&controller, epoch, Screen::Attachments(entry)), "Attachments ({view.attachments})" }
                button { class: "secondary-small", onclick: go(&controller, epoch, Screen::History(entry)), "History" }
                button { class: "secondary-small", onclick: go(&controller, epoch, Screen::Move(item, None)), "Move" }
                button { class: "danger-small", onclick: act(&controller, epoch, WsAction::Delete(item)), "Delete" }
            }
            button { class: "text-button", onclick: { let c = controller.clone(); move |_| c.back(epoch) }, "Back" }
        }
    }
}
#[component]
fn EditEntry(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(form) = controller.entry_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    let kinds = [
        (FieldKind::Text, "Text"),
        (FieldKind::Secret, "Secret"),
        (FieldKind::Url, "URL"),
        (FieldKind::Email, "Email"),
        (FieldKind::Multiline, "Multi-line"),
        (FieldKind::Totp, "TOTP URI"),
    ];
    rsx! {
        h2 { if form.new { "New entry" } else { "Edit entry" } }
        p { class: "hint", "Protected values are never shown here. Leave a protected value blank to keep it unchanged." }
        Input { controller: controller.clone(), epoch, field: WsField::Title, label: "Title", kind: Kind::Line, value: Some(form.title.to_string()), disabled: false }
        Input { controller: controller.clone(), epoch, field: WsField::TypeHint, label: "Type", kind: Kind::Line, value: Some(form.type_hint.to_string()), disabled: false }
        for row in form.rows.iter().cloned() {
            div { class: "form-row",
                Input { controller: controller.clone(), epoch, field: WsField::FieldName(row.index), label: "Field name", kind: Kind::Line, value: Some(row.name.to_string()), disabled: false }
                if row.too_large {
                    p { class: "hint", "{AppError::TooLargeForApp.message()}" }
                } else if row.protected {
                    Input { controller: controller.clone(), epoch, field: WsField::Replacement(row.index), label: format!("New {} value (blank keeps it)", kind_name(row.kind)), kind: if row.kind == FieldKind::Multiline { Kind::Multi } else { Kind::Secret }, value: None, disabled: false }
                    if row.generated { p { class: "hint", "A generated value is set (hidden)." } }
                    div { class: "row",
                        button { class: "chip", onclick: act(&controller, epoch, WsAction::GenerateInto(row.index)), "Generate" }
                        if row.replaced {
                            RevealReplacement { controller: controller.clone(), epoch, revision, index: row.index }
                        }
                    }
                } else {
                    Input { controller: controller.clone(), epoch, field: WsField::FieldValue(row.index), label: format!("{} value", kind_name(row.kind)), kind: if row.kind == FieldKind::Multiline { Kind::Multi } else { Kind::Line }, value: Some(row.value.as_deref().map(String::as_str).unwrap_or_default().to_owned()), disabled: false }
                }
                div { class: "row",
                    button { class: "chip", onclick: act(&controller, epoch, WsAction::ToggleProtect(row.index)), if row.protected { "Unprotect" } else { "Protect" } }
                    button { class: "chip danger-chip", onclick: act(&controller, epoch, WsAction::RemoveField(row.index)), "Remove field" }
                }
            }
        }
        div { class: "form-row",
            Input { controller: controller.clone(), epoch, field: WsField::NewFieldName, label: "New field name", kind: Kind::Line, value: None, disabled: false }
            div { class: "row",
                for (k, label) in kinds {
                    button { class: "chip", onclick: act(&controller, epoch, WsAction::AddField(k)), "Add {label}" }
                }
            }
        }
        if form.notes_too_large {
            p { class: "hint", "Notes: {AppError::TooLargeForApp.message()}" }
        } else {
            Input { controller: controller.clone(), epoch, field: WsField::Notes, label: "Notes", kind: Kind::Multi, value: Some(form.notes.to_string()), disabled: false }
        }
        div { class: "toolbar",
            button { class: "primary-small", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::SaveEntry), "Save" }
            button { class: "text-button", "data-qv-clear": "true", onclick: { let c = controller.clone(); move |_| c.back(epoch) }, "Cancel" }
        }
    }
}
#[component]
fn RevealReplacement(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    index: u16,
) -> Element {
    let _ = revision;
    let key = RevealKey::Replacement(index);
    let shown = text(controller.revealed(epoch, &key));
    rsx! {
        if shown.is_empty() {
            button { class: "chip", onclick: act(&controller, epoch, WsAction::Reveal(key.clone())), "Reveal 30 s" }
        } else {
            span { class: "code revealed", "{shown}" }
            button { class: "chip", onclick: act(&controller, epoch, WsAction::Hide), "Hide" }
        }
    }
}
#[component]
fn EditGroup(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(form) = controller.group_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    rsx! {
        h2 { if form.new { "New group" } else { "Rename group" } }
        Input { controller: controller.clone(), epoch, field: WsField::GroupName, label: "Name", kind: Kind::Line, value: Some(form.name.to_string()), disabled: false }
        div { class: "toolbar",
            button { class: "primary-small", onclick: act(&controller, epoch, WsAction::SaveGroup), "Save" }
            button { class: "text-button", onclick: { let c = controller.clone(); move |_| c.back(epoch) }, "Cancel" }
        }
    }
}
#[component]
fn Move(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    item: ItemHandle,
    at: Option<qv_core::GroupHandle>,
) -> Element {
    let _ = revision;
    let view = match controller.read(epoch, |s| views::browse(s, at)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let here = view.here;
    rsx! {
        h2 { "Move to…" }
        div { class: "crumbs",
            for (g, name) in view.crumbs.iter().cloned() {
                button { class: "crumb", onclick: go(&controller, epoch, Screen::Move(item, Some(g))), "{name.as_str()}" }
            }
        }
        ul { class: "list",
            for g in view.groups.iter().filter(|&g| ItemHandle::Group(g.handle) != item).cloned() {
                li { button { class: "row-button", onclick: go(&controller, epoch, Screen::Move(item, Some(g.handle))), span { class: "row-icon", "▸" } span { class: "row-title", "{g.name.as_str()}" } } }
            }
        }
        div { class: "toolbar",
            button { class: "primary-small", onclick: act(&controller, epoch, WsAction::MoveTo(item, here)), "Move here" }
            button { class: "text-button", onclick: { let c = controller.clone(); move |_| c.back(epoch) }, "Cancel" }
        }
    }
}
#[component]
fn Trash(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let view = match controller.read(epoch, views::trash) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    rsx! {
        h2 { "Trash" }
        if view.clock_anomaly { p { class: "warning", "Vault dates are ahead of this device's clock; check it before deleting anything." } }
        if view.items.is_empty() { p { class: "muted", "The trash is empty." } }
        ul { class: "list",
            for t in view.items.iter().cloned() {
                li { class: "row-static",
                    span { class: "row-text", span { class: "row-title", "{t.name.as_str()}" } span { class: "row-sub", "{t.deleted.clone().unwrap_or_else(|| \"deleted by a concurrent version\".into())}" } }
                    if t.conflict { span { class: "badge alert", "conflict" } }
                    button { class: "chip", onclick: act(&controller, epoch, WsAction::Restore(t.item)), "Restore" }
                }
            }
        }
        div { class: "toolbar",
            if view.expired > 0 {
                button { class: "secondary-small", onclick: act(&controller, epoch, WsAction::PurgeExpired), "Delete {view.expired} expired" }
            }
            if !view.items.is_empty() {
                button { class: "danger-small", onclick: act(&controller, epoch, WsAction::EmptyTrash), "Empty trash" }
            }
        }
    }
}
#[component]
fn History(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: qv_core::EntryHandle,
) -> Element {
    let _ = revision;
    let rows = match controller.read(epoch, |s| views::history(s, entry)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    rsx! {
        h2 { "History" }
        if rows.is_empty() { p { class: "muted", "No retained earlier versions." } }
        ul { class: "list",
            for r in rows {
                li { button { class: "row-button", onclick: go(&controller, epoch, Screen::HistoryVersion(entry, r.version.clone())),
                    span { class: "row-text",
                        span { class: "row-title", "{r.modified}" }
                        span { class: "row-sub", "{r.changed.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(\", \")}" }
                    }
                    if r.conflict { span { class: "badge alert", "concurrent" } }
                } }
            }
        }
        div { class: "toolbar",
            button { class: "danger-small", onclick: act(&controller, epoch, WsAction::PurgeHistory(entry)), "Purge history" }
            button { class: "text-button", onclick: { let c = controller.clone(); move |_| c.back(epoch) }, "Back" }
        }
    }
}
#[component]
fn HistoryVersion(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: qv_core::EntryHandle,
    version: String,
) -> Element {
    let _ = revision;
    let view = match controller.read(epoch, |s| views::history_version(s, entry, &version)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let conflicted = controller
        .read(epoch, |s| Ok(s.entry_versions(entry)?.len() > 1))
        .and_then(Result::ok)
        .unwrap_or(false);
    rsx! {
        p { class: "hint", "An earlier version. Restoring creates a new version; nothing is overwritten." }
        EntryBody { controller: controller.clone(), epoch, revision, view, history: Some(version.clone()) }
        div { class: "toolbar",
            button { class: "primary-small", onclick: act(&controller, epoch, WsAction::RestoreHistory(entry, version.clone(), false)), "Restore this version" }
            if conflicted {
                button { class: "secondary-small", onclick: act(&controller, epoch, WsAction::RestoreHistory(entry, version.clone(), true)), "Restore and resolve conflict" }
            }
            button { class: "text-button", onclick: { let c = controller.clone(); move |_| c.back(epoch) }, "Back" }
        }
    }
}
#[component]
fn Conflicts(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let rows = match controller.read(epoch, views::conflicts) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    rsx! {
        h2 { "Conflicts" }
        p { class: "muted", "Concurrent edits from merged archives are kept side by side until you choose a complete version." }
        if rows.is_empty() { p { class: "muted", "No conflicts." } }
        ul { class: "list",
            for r in rows {
                li { button { class: "row-button", onclick: go(&controller, epoch, Screen::ConflictRecord(r.record.clone())),
                    span { class: "row-text",
                        span { class: "row-title", "{r.name.as_deref().map(String::as_str).unwrap_or(r.kind)}" }
                        span { class: "row-sub", "{r.kind} · {r.versions} versions" }
                    }
                } }
            }
        }
    }
}
#[component]
fn ConflictRecord(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    record: String,
) -> Element {
    let _ = revision;
    let versions = match controller.read(epoch, |s| views::conflict_record(s, &record)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let needs_password = versions.iter().any(|v| v.needs_password);
    rsx! {
        h2 { "Choose a version" }
        if needs_password {
            Input { controller: controller.clone(), epoch, field: WsField::Password, label: "The chosen password slot's master password", kind: Kind::Secret, value: None, disabled: false }
        }
        for v in versions {
            div { class: "card-inner",
                p { class: "muted", "{v.state} · modified {v.modified}" }
                if v.unknown { p { class: "hint", "Unknown optional values are present and will be preserved." } }
                for (label, value) in v.details.iter().cloned() {
                    div { class: "field-line", span { class: "field-name", "{label}" } span { class: "field-value", "{value.as_str()}" } }
                }
                for f in v.fields.iter().cloned() {
                    FieldLine { controller: controller.clone(), epoch, revision, entry: None, reveal: RevealKey::Conflict(record.clone(), v.version.clone(), f.id), copy: false, field: f }
                }
                button { class: "primary-small", onclick: act(&controller, epoch, WsAction::Resolve(record.clone(), v.version.clone())), "Choose this version" }
            }
        }
    }
}
#[component]
fn PathInput(
    controller: Controller,
    epoch: FormEpoch,
    label: String,
    pick: crate::documents::PickKind,
    revision: u64,
) -> Element {
    // A finished pick advances the revision so the chosen name appears.
    let _ = revision;
    #[cfg(target_os = "android")]
    {
        let picked = crate::android::picked_name();
        let open = controller.clone();
        let create = controller.clone();
        return rsx! {
            div { class: "field",
                span { "{label}" }
                div { class: "row",
                    button { class: "secondary-small", onclick: move |_| crate::android::request_pick(&open, epoch, pick, false), "Choose a file…" }
                    button { class: "secondary-small", onclick: move |_| crate::android::request_pick(&create, epoch, pick, true), "Choose where to save…" }
                }
                if let Some(name) = picked { span { class: "hint", "Chosen: {name}" } }
            }
        };
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = pick;
        rsx! {
            Input { controller, epoch, field: WsField::Path, label: "{label} (absolute path)", kind: Kind::Line, value: None, disabled: false }
        }
    }
}
#[component]
fn Attachments(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: qv_core::EntryHandle,
) -> Element {
    let _ = revision;
    let rows = match controller.read(epoch, |s| views::attachments(s, entry)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    rsx! {
        h2 { "Attachments" }
        p { class: "muted", "Up to 10 MiB each. Names and types are shown as text; files are never opened or sniffed." }
        PathInput { controller: controller.clone(), epoch, label: "File to add, or destination to save to", pick: crate::documents::PickKind::Any, revision }
        ul { class: "list",
            for a in rows {
                li { class: "row-static",
                    span { class: "row-text", span { class: "row-title", "{a.name.as_str()}" } span { class: "row-sub", "{a.mime.as_str()} · {a.size} bytes" } }
                    if a.conflicted { span { class: "badge alert", "conflict" } }
                    button { class: "chip", disabled: a.conflicted, onclick: act(&controller, epoch, WsAction::SaveAttachment(a.handle)), "Save…" }
                    button { class: "chip danger-chip", disabled: a.conflicted, onclick: act(&controller, epoch, WsAction::RemoveAttachment(a.handle)), "Remove" }
                }
            }
        }
        Input { controller: controller.clone(), epoch, field: WsField::AttachName, label: "Name for a new attachment (optional)", kind: Kind::Line, value: None, disabled: false }
        Input { controller: controller.clone(), epoch, field: WsField::AttachMime, label: "MIME type (optional)", kind: Kind::Line, value: None, disabled: false }
        div { class: "toolbar",
            button { class: "primary-small", onclick: act(&controller, epoch, WsAction::AddAttachment(entry)), "Add attachment" }
            button { class: "text-button", onclick: { let c = controller.clone(); move |_| c.back(epoch) }, "Back" }
        }
    }
}
#[component]
fn Generator(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(form) = controller.generator_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    let generated = controller.generated(epoch);
    let value = generated
        .as_ref()
        .map(|(v, _)| String::from_utf8_lossy(v.expose_secret()).into_owned());
    let bits = form
        .bits
        .map_or_else(|| "invalid settings".to_owned(), |b| format!("{b:.1} bits"));
    let flags: &[(GenFlag, &str, usize)] = match form.mode {
        GenMode::Characters => &[
            (GenFlag::Lower, "a–z", 0),
            (GenFlag::Upper, "A–Z", 1),
            (GenFlag::Digits, "0–9", 2),
            (GenFlag::Symbols, "Symbols", 3),
            (GenFlag::Ambiguous, "Avoid look-alikes", 4),
        ],
        GenMode::Words => &[
            (GenFlag::Capitalize, "Capitalize", 5),
            (GenFlag::AppendDigit, "Add a digit", 6),
        ],
        GenMode::Pin => &[],
    };
    rsx! {
        h2 { "Password generator" }
        nav { class: "tabs",
            for (m, label) in [(GenMode::Characters, "Characters"), (GenMode::Words, "Passphrase"), (GenMode::Pin, "PIN")] {
                button { class: if form.mode == m { "selected" } else { "" }, onclick: act(&controller, epoch, WsAction::GenMode(m)), "{label}" }
            }
        }
        match form.mode {
            GenMode::Characters => rsx! {
                Input { controller: controller.clone(), epoch, field: WsField::GenLength, label: "Length (8–256)", kind: Kind::Line, value: Some(form.length.to_string()), disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::GenExclude, label: "Exclude characters", kind: Kind::Line, value: Some(form.exclude.to_string()), disabled: false }
            },
            GenMode::Words => rsx! {
                Input { controller: controller.clone(), epoch, field: WsField::GenWords, label: "Words (3–20)", kind: Kind::Line, value: Some(form.words.to_string()), disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::GenSeparator, label: "Separator", kind: Kind::Line, value: Some(form.separator.clone()), disabled: false }
            },
            GenMode::Pin => rsx! {
                Input { controller: controller.clone(), epoch, field: WsField::GenLength, label: "Digits (4–32)", kind: Kind::Line, value: Some(form.pin.to_string()), disabled: false }
            },
        }
        div { class: "row",
            for (flag, label, i) in flags.iter().copied() {
                label { class: "check",
                    input { r#type: "checkbox", checked: form.flags[i], onchange: act_change(&controller, epoch, WsAction::GenToggle(flag)) }
                    span { "{label}" }
                }
            }
        }
        p { class: "hint", "Strength of these settings: {bits}" }
        if let Some(v) = value {
            div { class: "phrase revealed", "{v}" }
            p { class: "hint", "Visible for 30 seconds." }
        }
        div { class: "toolbar",
            button { class: "primary-small", onclick: act(&controller, epoch, WsAction::Generate), "Generate" }
            if generated.is_some() {
                button { class: "secondary-small", onclick: act(&controller, epoch, WsAction::Copy(CopyKey::Generated)), "Copy" }
            }
            button { class: "text-button", onclick: act(&controller, epoch, WsAction::SaveGeneratorDefaults), "Use as vault defaults" }
        }
    }
}
fn act_change(c: &Controller, e: FormEpoch, a: WsAction) -> impl FnMut(FormEvent) + 'static {
    let c = c.clone();
    move |_| c.act(e, a.clone())
}
#[component]
fn Snapshots(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let (rows, unreadable) = match controller.read(epoch, views::snapshots) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let label = if cfg!(target_os = "android") {
        "Name for the restored vault"
    } else {
        "New vault file for the restore (.qvault)"
    };
    rsx! {
        h2 { "Local snapshots" }
        p { class: "muted", "Restoring creates a new vault file and a new recovery baseline. A snapshot may be old; it does not show the latest state." }
        if unreadable > 0 { p { class: "warning", "{unreadable} snapshot file(s) could not be authenticated and were skipped." } }
        if cfg!(target_os = "android") {
            Input { controller: controller.clone(), epoch, field: WsField::Path, label, kind: Kind::Line, value: None, disabled: false }
        } else {
            Input { controller: controller.clone(), epoch, field: WsField::Path, label: "{label} (absolute path)", kind: Kind::Line, value: None, disabled: false }
        }
        if rows.is_empty() { p { class: "muted", "No snapshots yet." } }
        ul { class: "list",
            for r in rows {
                li { class: "row-static",
                    span { class: "row-text", span { class: "row-title", "{r.created}" } span { class: "row-sub", "{r.kind} · {r.size} bytes · {r.id}" } }
                    button { class: "chip", onclick: act(&controller, epoch, WsAction::RestoreSnapshot(r.id.clone())), "Restore" }
                }
            }
        }
    }
}
#[component]
fn Archives(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    rsx! {
        h2 { "Archive exchange" }
        p { class: "muted", "Export an encrypted archive to move changes to another copy of this vault, or merge an archive from one. Merging keeps concurrent edits as conflicts." }
        PathInput { controller: controller.clone(), epoch, label: "Archive file to merge, or folder to export into", pick: crate::documents::PickKind::Archive, revision }
        div { class: "toolbar",
            button { class: "primary-small", onclick: act(&controller, epoch, WsAction::MergeArchive), "Merge archive" }
            button { class: "secondary-small", onclick: act(&controller, epoch, WsAction::ExportArchive(false)), "Export archive" }
            button { class: "secondary-small", onclick: act(&controller, epoch, WsAction::ExportArchive(true)), "Export with password slot" }
        }
    }
}
#[component]
fn Settings(controller: Controller, epoch: FormEpoch, revision: u64, pane: Pane) -> Element {
    let _ = revision;
    let panes = [
        (Pane::General, "General"),
        (Pane::Password, "Password"),
        (Pane::Phrase, "Recovery phrase"),
        (Pane::Rotation, "Key rotation"),
        (Pane::Verify, "Verify"),
        (Pane::About, "About"),
    ];
    rsx! {
        h2 { "Settings" }
        nav { class: "tabs",
            for (p, label) in panes {
                button { class: if pane == p { "selected" } else { "" }, onclick: go(&controller, epoch, Screen::Settings(p)), "{label}" }
            }
        }
        match pane {
            Pane::General => rsx! { General { controller: controller.clone(), epoch, revision } },
            Pane::Password => rsx! {
                p { class: "muted", "Old copies of the vault and its password slot still open this key generation. After a suspected compromise, rotate keys instead." }
                Input { controller: controller.clone(), epoch, field: WsField::NewPassword, label: "New master password", kind: Kind::Secret, value: None, disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::Repeat, label: "Confirm new master password", kind: Kind::Secret, value: None, disabled: false }
                button { class: "primary-small", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::ChangePassword), "Change master password" }
            },
            Pane::Phrase => rsx! { PhrasePane { controller: controller.clone(), epoch, revision } },
            Pane::Rotation => rsx! {
                p { class: "muted", "Key rotation creates a new key generation with a new master password and a new recovery phrase. It can take a while, is resumable, and locks the vault when it finishes. Type rotate to continue." }
                Input { controller: controller.clone(), epoch, field: WsField::Confirmation, label: "Type rotate", kind: Kind::Line, value: None, disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::NewPassword, label: "New master password", kind: Kind::Secret, value: None, disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::Repeat, label: "Confirm new master password", kind: Kind::Secret, value: None, disabled: false }
                button { class: "danger-small", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::BeginRotation), "Prepare key rotation" }
            },
            Pane::Verify => rsx! {
                p { class: "muted", "Re-hash and authenticate every object, manifest and the local head. Nothing is changed or repaired." }
                button { class: "primary-small", onclick: act(&controller, epoch, WsAction::Verify), "Verify integrity" }
            },
            Pane::About => rsx! { About { controller: controller.clone(), epoch, revision } },
        }
    }
}
#[component]
fn General(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(form) = controller.settings_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    rsx! {
        Input { controller: controller.clone(), epoch, field: WsField::VaultName, label: "Vault name", kind: Kind::Line, value: Some(form.name.to_string()), disabled: false }
        Input { controller: controller.clone(), epoch, field: WsField::Description, label: "Description", kind: Kind::Line, value: Some(form.description.to_string()), disabled: false }
        Input { controller: controller.clone(), epoch, field: WsField::HistoryDepth, label: "History versions to keep (blank = default)", kind: Kind::Line, value: Some(form.history_depth.clone()), disabled: false }
        Input { controller: controller.clone(), epoch, field: WsField::TrashDays, label: "Days before trash is offered for deletion (blank = default)", kind: Kind::Line, value: Some(form.trash_days.clone()), disabled: false }
        button { class: "primary-small", onclick: act(&controller, epoch, WsAction::SaveSettings), "Save settings" }
    }
}
#[component]
fn PhrasePane(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(screen) = controller.phrase_screen(epoch) else {
        return rsx! {
            p { class: "muted", "Re-enter your master password to show the recovery phrase. Anyone with the phrase and your vault file can open it." }
            Input { controller: controller.clone(), epoch, field: WsField::Password, label: "Master password", kind: Kind::Secret, value: None, disabled: false }
            button { class: "primary-small", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::ShowPhrase), "Show recovery phrase" }
        };
    };
    let words = text(controller.phrase_words(epoch));
    rsx! {
        div { class: "phrase", "{words}" }
        if screen.confirmed {
            p { class: "notice", "The recovery words are confirmed." }
        } else {
            p { "Optionally confirm words {screen.positions[0]}, {screen.positions[1]} and {screen.positions[2]}." }
            for (i, label) in [(0u8, "First requested word"), (1, "Second requested word"), (2, "Third requested word")] {
                Input { controller: controller.clone(), epoch, field: WsField::Word(i), label, kind: Kind::Secret, value: None, disabled: false }
            }
            button { class: "secondary-small", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::ConfirmWords), "Confirm words" }
        }
        button { class: "text-button", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::HidePhrase), "Hide the phrase" }
    }
}
#[component]
fn About(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let about = controller.about(epoch);
    let overview = controller.read(epoch, views::overview).and_then(Result::ok);
    rsx! {
        if let Some(o) = overview {
            div { class: "card-inner",
                p { class: "eyebrow", "VAULT CONTENTS (VERIFIED)" }
                p { "{o.entries} entries · {o.groups} groups · {o.trash} in trash · {o.conflicts} conflicts" }
            }
        }
        if about.is_none() {
            p { class: "muted", "Header details appear after the next unlock." }
        }
        if let Some(a) = about {
            div { class: "card-inner",
                p { class: "eyebrow", "HEADER (UNVERIFIED WITHOUT THE PASSWORD)" }
                p { "Vault ID {a.vault_id}" }
                p { "Key generation {a.key_generation} · format {a.format:#010x}" }
                p { "Password KDF: Argon2id, {a.kdf.0} MiB, {a.kdf.1} iterations, {a.kdf.2} lanes" }
            }
        }
    }
}
