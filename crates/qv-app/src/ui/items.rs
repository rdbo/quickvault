// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault items: the list beside the detail, the entry card (click a field to
//! copy, 30 s reveals), in-place editing, move, history and attachments.
//! Protected values appear only through a reveal; forms never prefill them.
use super::icons::{Icon, Svg, hue_class, initial, item_hue, kind_icon};
use super::shell::{ReportCard, Unreadable, act, go, kind_label};
use crate::controller::{Controller, FormEpoch};
use crate::views::{self, EntryView, FieldRow, kind_name};
use crate::workspace::{CopyKey, Live, Report, RevealKey, Screen, WsAction, WsField};
use dioxus::prelude::*;
use qv_core::{EntryHandle, FieldKind, ItemHandle};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const MASK: &str = "••••••••";
/// A listed row and its lower-cased type hint.
type Listed = (views::EntryRow, Zeroizing<String>);

fn text(v: Option<qv_core::SecretBytes>) -> Zeroizing<String> {
    v.map_or_else(
        || views::z(""),
        |v| views::z(&String::from_utf8_lossy(v.expose_secret())),
    )
}
fn back(c: &Controller, e: FormEpoch) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| c.back(e)
}

/// Stable DOM id for an input (accessibility labels and the synthetic flows).
pub(crate) fn dom_id(field: WsField) -> String {
    match field {
        WsField::Query => "ws-query".into(),
        WsField::Command => "palette-input".into(),
        WsField::Title => "ws-title".into(),
        WsField::TypeHint => "ws-type".into(),
        WsField::Notes => "ws-notes".into(),
        WsField::FieldName(i) => format!("ws-field-name-{i}"),
        WsField::FieldValue(i) => format!("ws-field-value-{i}"),
        WsField::Replacement(i) => format!("ws-replacement-{i}"),
        WsField::NewFieldName => "ws-new-field".into(),
        WsField::Start => "ws-start".into(),
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
        WsField::LanCode => "ws-lan-code".into(),
        WsField::LanEndpoint => "ws-lan-endpoint".into(),
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
/// Controlled text without echo races. Each keystroke round-trips through
/// Rust, and a render can arrive while newer keystrokes are still in flight.
/// Dioxus writes `value` on every render (it is volatile), which dropped or
/// reordered typing, so controls render `initial_value` only. The control
/// keeps what the user typed; only a value the user did not type (a chip, a
/// reset, a different form) replaces it, by remounting the control.
pub(crate) struct Echo {
    shown: Zeroizing<String>,
    typed: Option<Zeroizing<String>>,
    generation: u64,
}
impl Echo {
    pub(crate) fn new(value: &str) -> Self {
        Self {
            shown: Zeroizing::new(value.to_owned()),
            typed: None,
            generation: 0,
        }
    }
    /// The value to render and the control's mount generation.
    pub(crate) fn sync(&mut self, value: &str) -> (Zeroizing<String>, u64) {
        let echo = self.typed.as_ref().is_some_and(|t| t.as_str() == value);
        if !echo && (self.typed.is_some() || self.shown.as_str() != value) {
            self.shown = Zeroizing::new(value.to_owned());
            self.typed = None;
            self.generation = self.generation.wrapping_add(1);
        }
        (self.shown.clone(), self.generation)
    }
    /// Record what the user typed, before it moves to protected storage.
    pub(crate) fn typed(&mut self, value: &str) {
        self.typed = Some(Zeroizing::new(value.to_owned()));
    }
}
/// The component-lifetime echo state for one controlled control.
pub(crate) fn use_echo(value: &str) -> std::rc::Rc<std::cell::RefCell<Echo>> {
    use_hook(|| std::rc::Rc::new(std::cell::RefCell::new(Echo::new(value))))
}

/// One bounded workspace input. Values move to protected Rust storage on
/// every keystroke; secrets are never prefilled.
#[component]
pub(crate) fn Input(
    controller: Controller,
    epoch: FormEpoch,
    field: WsField,
    label: String,
    kind: Kind,
    value: Option<String>,
    disabled: bool,
    #[props(default)] autofocus: bool,
    #[props(default)] bare: bool,
    #[props(default)] class: &'static str,
    #[props(default)] placeholder: String,
    /// `card`: digits only, grouped as typed (app.js), numeric keyboard.
    #[props(default)]
    format: &'static str,
) -> Element {
    let limit = match field {
        WsField::Query | WsField::Command => crate::workspace::QUERY_MAX,
        WsField::Path => crate::workspace::PATH_MAX,
        WsField::Notes | WsField::Replacement(_) => crate::workspace::MULTI_MAX,
        _ if kind == Kind::Multi => crate::workspace::MULTI_MAX,
        _ => crate::workspace::LINE_MAX,
    };
    let controlled = value.is_some();
    let echo = use_echo(value.as_deref().unwrap_or_default());
    let (shown, generation) = if controlled {
        echo.borrow_mut().sync(value.as_deref().unwrap_or_default())
    } else {
        (Zeroizing::new(String::new()), 0)
    };
    let id = dom_id(field);
    let c = controller.clone();
    let oninput = move |event: FormEvent| {
        let mut v = event.value();
        if controlled {
            echo.borrow_mut().typed(&v);
        }
        c.ws_input(epoch, field, &mut v);
    };
    let control = if kind == Kind::Multi {
        rsx! {
            for g in [generation] {
                textarea { key: "{g}", id: id.clone(), class, maxlength: limit, disabled, autofocus, placeholder: placeholder.clone(), spellcheck: "false", autocomplete: "off",
                    "aria-label": if bare { label.clone() } else { String::new() },
                    "data-qv-controlled": if controlled { "true" } else { "false" },
                    initial_value: shown.as_str(), oninput: oninput.clone() }
            }
        }
    } else {
        rsx! {
            for g in [generation] {
                input { key: "{g}", id: id.clone(), class, r#type: if kind == Kind::Secret { "password" } else { "text" }, maxlength: limit, disabled, autofocus,
                    "data-qv-format": format, inputmode: if format.is_empty() { "text" } else { "numeric" },
                    placeholder: placeholder.clone(), autocomplete: "off", spellcheck: "false", autocapitalize: "off", autocorrect: "off",
                    "aria-label": if bare { label.clone() } else { String::new() },
                    "data-qv-controlled": if controlled { "true" } else { "false" },
                    initial_value: shown.as_str(), oninput: oninput.clone() }
            }
        }
    };
    if bare {
        return control;
    }
    rsx! { div { class: "field", label { r#for: id.clone(), "{label}" } {control} } }
}

/// Run the system file picker into the screen's path input, then an action
/// (Linux portal; elsewhere the caller uses the platform's own picker).
#[cfg(target_os = "linux")]
pub(crate) fn picker(
    c: &Controller,
    e: FormEpoch,
    kind: qv_core::platform::portal::Pick,
    title: &'static str,
    then: Option<WsAction>,
) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| {
        crate::documents::pick_path(
            &c,
            e,
            crate::documents::PathFor::Workspace,
            kind.clone(),
            title,
            then.clone(),
        )
    }
}

/// The list beside a vault detail: all items, a type, a group, recovered
/// items or search results. Rows are disabled while a form is open.
#[component]
pub(crate) fn ListPane(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    list: Screen,
    screen: Screen,
    busy: bool,
    conflicts: usize,
) -> Element {
    let _ = revision;
    let fallback = use_signal(|| false);
    let mut vault_sheet = try_use_context::<super::VaultSheet>().map_or(fallback, |v| v.0);
    let mut menu = use_signal(|| false);
    // Plan 0044: multi-select (record ids) and the open row menu.
    let mut anchor = use_signal(|| None::<String>);
    let mut row_menu = use_signal(|| None::<String>);
    let mut bar_pop = use_signal(|| None::<BarPop>);
    let form = screen.is_form() || busy;
    let current = match &screen {
        Screen::Entry(e)
        | Screen::History(e)
        | Screen::HistoryVersion(e, _)
        | Screen::Attachments(e) => Some(*e),
        _ => None,
    };
    let query = controller
        .peek(epoch, |ws| {
            String::from_utf8_lossy(ws.input(WsField::Query)).into_owned()
        })
        .map(Zeroizing::new)
        .unwrap_or_default();
    let spec = crate::page_read::Spec::Items {
        group: match &list {
            Screen::Browse(Some(group)) => Some(*group),
            _ => None,
        },
        kind: match &list {
            Screen::Kind(kind) => Some(kind.clone()),
            _ => None,
        },
        query: query.clone(),
        recovered: list == Screen::Recovered,
        full_search: list == Screen::Search,
    };
    let (page_owner, page_read) =
        super::use_page(&controller, epoch, crate::page_read::Lane::Main, 1, spec);
    let page = page_read.as_ref().and_then(|r| r.page.clone());
    let (rows, groups) = match page.as_deref().map(|p| &p.rows) {
        Some(crate::page_read::Rows::Items { items, groups }) => (
            items
                .iter()
                .map(|i| (i.row.clone(), i.kind.clone()))
                .collect::<Vec<_>>(),
            groups.clone(),
        ),
        _ => (Vec::new(), Vec::new()),
    };
    let mut group_view = match &list {
        Screen::Browse(Some(group)) => controller
            .read(epoch, |s| views::browse_header(s, Some(*group)))
            .and_then(Result::ok),
        _ => None,
    };
    if let Some(view) = &mut group_view {
        view.groups = groups;
    }
    let title = match &list {
        Screen::Browse(Some(_)) => group_view
            .as_ref()
            .and_then(|v| v.crumbs.last())
            .map(|(_, n)| n.to_string())
            .unwrap_or_default(),
        Screen::Kind(kind) => kind_label(kind),
        Screen::Recovered => "Recovered items".to_owned(),
        Screen::Search => "Search".to_owned(),
        _ => "All items".to_owned(),
    };
    let shown = rows;
    let new_in = match &list {
        Screen::Browse(Some(g)) => Some(*g),
        _ => controller.read(epoch, |s| s.root()).and_then(Result::ok),
    };
    let new_entry = {
        let c = controller.clone();
        move |_| {
            if let Some(g) = new_in {
                c.act(epoch, WsAction::NewEntry(g));
            }
        }
    };
    let quick = |e: qv_core::EntryHandle, secret: bool| {
        let c = controller.clone();
        move |ev: MouseEvent| {
            ev.stop_propagation();
            let handles = c
                .read(epoch, |s| views::quick_fields(s, e))
                .and_then(Result::ok);
            if let Some(h) = handles.and_then(|(u, p)| if secret { p } else { u }) {
                c.act(epoch, WsAction::Copy(CopyKey::Field(e, h)));
            }
        }
    };
    let mut sections: Vec<(String, Vec<Listed>)> = Vec::new();
    for (row, kind) in shown {
        let letter = initial(&row.title);
        match sections.last_mut() {
            Some((l, v)) if *l == letter => v.push((row, kind)),
            _ => sections.push((letter, vec![(row, kind)])),
        }
    }
    let count: usize = sections.iter().map(|s| s.1.len()).sum();
    let group = match &list {
        Screen::Browse(Some(g)) => Some(*g),
        _ => None,
    };
    // Shown rows in display order; the selection only counts what is shown.
    let order: Vec<(String, EntryHandle)> = sections
        .iter()
        .flat_map(|(_, v)| v.iter().map(|(r, _)| (r.handle.id_hex(), r.handle)))
        .collect();
    // The multi-selection lives in the workspace, so Escape and Android Back
    // can end it from anywhere (plan 0044).
    let selection = controller.selection(epoch);
    let chosen = selection.clone().unwrap_or_default();
    let picked: Vec<EntryHandle> = order
        .iter()
        .filter(|(id, _)| chosen.contains(id))
        .map(|(_, h)| *h)
        .collect();
    let in_selection = selection.is_some() && !form;
    let click = {
        let c = controller.clone();
        let order = order.clone();
        move |id: String, h: EntryHandle| {
            let c = c.clone();
            let order = order.clone();
            move |e: MouseEvent| {
                let m = e.modifiers();
                let from = anchor();
                let current = c.selection(epoch);
                if m.shift() && (current.is_some() || from.is_some()) {
                    let mut set = current.unwrap_or_default();
                    let at = |x: &str| order.iter().position(|(i, _)| i == x);
                    if let (Some(a), Some(b)) = (from.as_deref().and_then(at), at(&id)) {
                        let (lo, hi) = (a.min(b), a.max(b));
                        for (i, _) in &order[lo..=hi] {
                            set.insert(i.clone());
                        }
                    } else {
                        set.insert(id.clone());
                    }
                    c.set_selection(epoch, Some(set));
                } else if current.is_some() || m.ctrl() || m.meta() {
                    let mut set = current.clone().unwrap_or_default();
                    if !set.remove(&id) {
                        set.insert(id.clone());
                    }
                    anchor.set(Some(id.clone()));
                    // Ctrl-clicking the last one off ends a Ctrl-started selection.
                    let keep = !set.is_empty() || current.is_some() && !(m.ctrl() || m.meta());
                    c.set_selection(epoch, keep.then_some(set));
                } else {
                    anchor.set(Some(id.clone()));
                    c.select(epoch, Screen::Entry(h));
                }
            }
        }
    };
    let leave = {
        let c = controller.clone();
        move || {
            bar_pop.set(None);
            c.set_selection(epoch, None);
        }
    };
    // Escape closes the row menu or a bar popover here; ending the selection
    // is the root shortcut's job (it works wherever focus is).
    let keys = {
        let order = order.clone();
        let c = controller.clone();
        move |e: KeyboardEvent| {
            let ctrl = e.modifiers().ctrl() || e.modifiers().meta();
            if e.key() == Key::Escape && (row_menu().is_some() || bar_pop().is_some()) {
                e.stop_propagation();
                e.prevent_default();
                if row_menu().is_some() {
                    row_menu.set(None);
                } else {
                    bar_pop.set(None);
                }
            } else if c.selection(epoch).is_some()
                && ctrl
                && matches!(e.key(), Key::Character(ref k) if k == "a" || k == "A")
            {
                e.stop_propagation();
                e.prevent_default();
                c.set_selection(epoch, Some(order.iter().map(|(i, _)| i.clone()).collect()));
            }
        }
    };
    let start_selecting = {
        let c = controller.clone();
        move |_| {
            row_menu.set(None);
            c.set_selection(epoch, Some(BTreeSet::new()));
        }
    };
    let selbar = {
        let all_ids: BTreeSet<String> = order.iter().map(|(i, _)| i.clone()).collect();
        let all_on = !all_ids.is_empty() && picked.len() == all_ids.len();
        let n = picked.len();
        let none = n == 0;
        let batch = |a: fn(Vec<EntryHandle>) -> WsAction| {
            let c = controller.clone();
            let picked = picked.clone();
            let mut leave = leave.clone();
            move |_| {
                c.act(epoch, a(picked.clone()));
                leave();
            }
        };
        let colour = |n: Option<u8>| {
            let c = controller.clone();
            let picked = picked.clone();
            let mut leave = leave.clone();
            move |_| {
                c.act(epoch, WsAction::ColourMany(picked.clone(), n));
                leave();
            }
        };
        let move_to = {
            let c = controller.clone();
            let picked = picked.clone();
            let mut leave = leave.clone();
            move |group| {
                c.act(epoch, WsAction::MoveMany(picked.clone(), group));
                leave();
            }
        };
        let mut leave_btn = leave.clone();
        rsx! {
            div { class: "selbar", role: "toolbar", "aria-label": "Selection",
                button { class: "icon-btn", id: "sel-exit", "aria-label": "Leave selection", title: "Leave selection (Esc)", onclick: move |_| leave_btn(), Svg { icon: Icon::Close } }
                b { class: "sel-n", if none { "Select items" } else { "{n} selected" } }
                button { class: if all_on { "icon-btn on" } else { "icon-btn" }, id: "sel-all", title: if all_on { "Clear the selection" } else { "Select this page (Ctrl A)" }, "aria-label": if all_on { "Clear the selection" } else { "Select this page" },
                    onclick: { let c = controller.clone(); move |_| c.set_selection(epoch, Some(if all_on { BTreeSet::new() } else { all_ids.clone() })) },
                    Svg { icon: Icon::All }
                }
                div { class: "pop-anchor",
                    button { class: "icon-btn", id: "sel-colour", "aria-label": "Color", title: "Color", disabled: none,
                        onclick: move |_| bar_pop.set(if bar_pop() == Some(BarPop::Colour) { None } else { Some(BarPop::Colour) }),
                        Svg { icon: Icon::Palette }
                    }
                    if bar_pop() == Some(BarPop::Colour) {
                        button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| bar_pop.set(None) }
                        div { class: "menu pop end", role: "menu", "aria-label": "Color",
                            div { class: "label", "COLOR" }
                            div { class: "ie-swatches",
                                for h in 0..crate::editor::HUES {
                                    button { class: hue_class(h), id: "sel-colour-{h}", "aria-label": "Color {h + 1}", onclick: colour(Some(h)) }
                                }
                            }
                            hr {}
                            button { class: "mi", id: "sel-colour-auto", onclick: colour(None), Svg { icon: Icon::Refresh } "Automatic" }
                        }
                    }
                }
                div { class: "pop-anchor",
                    button { class: "icon-btn", id: "sel-move", "aria-label": "Move", title: "Move to a group", disabled: none,
                        onclick: move |_| bar_pop.set(if bar_pop() == Some(BarPop::Move) { None } else { Some(BarPop::Move) }),
                        Svg { icon: Icon::Move }
                    }
                    if bar_pop() == Some(BarPop::Move) {
                        button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| bar_pop.set(None) }
                        div { class: "menu pop end", role: "menu",
                            div { class: "label", "MOVE TO" }
                            if let Some(current) = group.or(new_in) {
                                super::editor::GroupChoices { controller: controller.clone(), epoch, current, on_pick: move_to }
                            }
                        }
                    }
                }
                button { class: "icon-btn danger", id: "sel-trash", "aria-label": "Move to the trash", title: "Move to the trash", disabled: none, onclick: batch(WsAction::TrashMany), Svg { icon: Icon::Trash } }
            }
        }
    };
    rsx! {
        // `fade-in` plays when the list mounts again after a tool page.
        section { class: if in_selection { "list selecting fade-in" } else { "list fade-in" }, "aria-label": "Items", onkeydown: keys,
            div { class: "phone-head",
                div { class: "ph-row",
                    h2 { "{title}" }
                    // Android selects by holding a row (plan 0045).
                    if count > 0 && !in_selection && !cfg!(target_os = "android") { button { class: "link", id: "list-select-phone", disabled: form, onclick: start_selecting.clone(), "Select" } }
                    // The open vault as an account-style tile; tapping it
                    // opens the vault switcher (plan 0045).
                    if let Some(v) = controller.open_vault() {
                        button { class: "vault-avatar tile {super::shell::vault_hue(&v.name)}", id: "vault-chip", disabled: form, "aria-haspopup": "dialog",
                            "aria-label": "Vault {crate::views::z(&v.name).as_str()}. Switch vault", title: "{crate::views::z(&v.name).as_str()}",
                            onclick: move |_| vault_sheet.set(true),
                            "{initial(&v.name)}"
                        }
                    }
                }
            }
            if in_selection { {selbar} } else {
            div { class: "list-head",
                h2 { "{title}" } span { class: "count", "{count}" } span { class: "sp" }
                if let Some(g) = group {
                    div { class: "pop-anchor",
                        button { class: "icon-btn", id: "group-menu", "aria-label": "Group actions", title: "Group actions", disabled: form,
                            onclick: move |_| menu.set(!menu()),
                            Svg { icon: Icon::More, large: true }
                        }
                        if menu() {
                            button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| menu.set(false) }
                            div { class: "menu pop end", role: "menu",
                                button { class: "mi", onclick: { let mut f = act(&controller, epoch, WsAction::NewGroup(g)); move |e| { menu.set(false); f(e) } }, Svg { icon: Icon::Folder } "New subgroup" }
                                button { class: "mi", onclick: { let mut f = act(&controller, epoch, WsAction::RenameGroup(g)); move |e| { menu.set(false); f(e) } }, Svg { icon: Icon::Edit } "Rename group" }
                                button { class: "mi", id: "group-colour", onclick: { let mut f = act(&controller, epoch, WsAction::RenameGroup(g)); move |e| { menu.set(false); f(e) } }, Svg { icon: Icon::Palette } "Change color" }
                                button { class: "mi", onclick: { let mut f = go(&controller, epoch, Screen::Move(ItemHandle::Group(g), None)); move |e| { menu.set(false); f(e) } }, Svg { icon: Icon::Move } "Move group" }
                                hr {}
                                button { class: "mi danger", onclick: { let mut f = act(&controller, epoch, WsAction::Delete(ItemHandle::Group(g))); move |e| { menu.set(false); f(e) } }, Svg { icon: Icon::Trash } "Delete group" }
                            }
                        }
                    }
                }
                if count > 0 { button { class: "icon-btn", id: "list-select", "aria-label": "Select items", title: "Select items (Ctrl-click, Shift-click)", disabled: form, onclick: start_selecting, Svg { icon: Icon::Check } } }
                button { class: "icon-btn acc", id: "list-new", "aria-label": "New item", title: "New item (Ctrl N)", disabled: form, onclick: new_entry, Svg { icon: Icon::Plus } }
            }
            }
            if let (Some(owner), Some(read)) = (page_owner, page_read.clone()) {
                super::PageNav { controller: controller.clone(), epoch, owner, read }
            }
            label { class: "filter", Svg { icon: Icon::Search }
                Input { controller: controller.clone(), epoch, field: WsField::Query, label: if list == Screen::Search { "Search the vault".to_owned() } else { format!("Filter {}", title.to_lowercase()) },
                    placeholder: if list == Screen::Search { "Search titles, usernames, websites".to_owned() } else { format!("Filter {}", title.to_lowercase()) },
                    kind: super::items::Kind::Line, value: Some(query.to_string()), disabled: form, bare: true, autofocus: list == Screen::Search }
            }
            if let Some(v) = group_view.as_ref() {
                if !v.groups.is_empty() {
                    div { class: "subgroups",
                        for g in v.groups.iter().cloned() {
                            button { class: "chip", disabled: form, onclick: go(&controller, epoch, Screen::Browse(Some(g.handle))), Svg { icon: Icon::Folder } "{g.name.as_str()}" }
                        }
                    }
                }
            }
            if conflicts > 0 && !in_selection {
                button { class: "conflict-note", id: "list-conflicts", disabled: form, onclick: go(&controller, epoch, Screen::Conflicts),
                    Svg { icon: Icon::Conflicts }
                    span { class: "sp", if conflicts == 1 { "1 item has conflicting versions" } else { "{conflicts} items have conflicting versions" } }
                    b { "Resolve" }
                }
            }
            div { class: "rows", id: "rows",
                if count == 0 {
                    div { class: "empty", div {
                        div { class: "big", Svg { icon: if query.is_empty() { Icon::Key } else { Icon::Search } } }
                        if page.is_none() { "Loading items…" } else if query.is_empty() && list != Screen::Search { "Nothing here yet. Create an item with the + button." } else { "No items match." }
                    } }
                }
                for (letter, items) in sections {
                    div { class: "sect", "{letter}" }
                    for (row, kind) in items {
                        {
                            let id = row.handle.id_hex();
                            let on = chosen.contains(&id);
                            let menu_open = row_menu().as_deref() == Some(id.as_str());
                            let h = row.handle;
                            let class = match (in_selection && on, current == Some(h) && !in_selection) {
                                (true, _) => "row sel",
                                (false, true) => "row on",
                                _ => "row",
                            };
                            let label = if in_selection { format!("Select {}", row.title.as_str()) } else { format!("Open {}", row.title.as_str()) };
                            rsx! {
                        div { class, key: "{id}",
                            oncontextmenu: { let id = id.clone(); move |e: MouseEvent| { e.prevent_default(); if !form && !in_selection { row_menu.set(Some(id.clone())); } } },
                            button { class: "open item-open", "aria-label": "{label}", "aria-pressed": if in_selection { if on { "true" } else { "false" } } else { "" }, disabled: form, onclick: click(id.clone(), h) }
                            if in_selection {
                                span { class: if on { "tile check on" } else { "tile check" }, Svg { icon: Icon::Check, large: true } }
                            } else {
                                span { class: "tile {item_hue(row.colour, &id)}", "{initial(&row.title)}" }
                            }
                            span { class: "t", b { class: "row-title", "{row.title.as_str()}" }
                                span { if row.subtitle.is_empty() { "{kind_label(&kind)}" } else { "{row.subtitle.as_str()}" } }
                            }
                            if row.conflict { span { class: "cbadge", "conflict" } }
                            if !in_selection {
                            span { class: "quick",
                                if !row.subtitle.is_empty() { button { "aria-label": "Copy the first field", title: "Copy {row.subtitle.as_str()}", disabled: form, onclick: quick(row.handle, false), Svg { icon: Icon::User } } }
                                button { "aria-label": "Copy the protected field", title: "Copy password", disabled: form, onclick: quick(row.handle, true), Svg { icon: Icon::Key } }
                            }
                            }
                            if menu_open {
                                button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| row_menu.set(None),
                                    // A right click elsewhere closes this menu (it must not reopen it).
                                    oncontextmenu: move |e: MouseEvent| { e.prevent_default(); e.stop_propagation(); row_menu.set(None); } }
                                div { class: "row-menu",
                                    div { class: "menu pop end", role: "menu", "aria-label": "{row.title.as_str()}",
                                        button { class: "mi", role: "menuitem", id: "row-open", onclick: { let c = controller.clone(); move |_| { row_menu.set(None); c.select(epoch, Screen::Entry(h)); } }, Svg { icon: Icon::Right } "Open" }
                                        if !row.subtitle.is_empty() { button { class: "mi", role: "menuitem", onclick: { let f = quick(h, false); move |e| { row_menu.set(None); f(e) } }, Svg { icon: Icon::User } "Copy {row.subtitle.as_str()}" } }
                                        button { class: "mi", role: "menuitem", id: "row-copy-password", onclick: { let f = quick(h, true); move |e| { row_menu.set(None); f(e) } }, Svg { icon: Icon::Key } "Copy password" }
                                        hr {}
                                        div { class: "label", "COLOR" }
                                        div { class: "ie-swatches",
                                            for n in 0..crate::editor::HUES {
                                                button { class: if row.colour == Some(n) { format!("on {}", hue_class(n)) } else { hue_class(n).to_owned() }, "aria-label": "Color {n + 1}",
                                                    onclick: { let c = controller.clone(); move |_| { row_menu.set(None); c.act(epoch, WsAction::ColourMany(vec![h], Some(n))); } } }
                                            }
                                        }
                                        button { class: "mi", role: "menuitem", onclick: { let c = controller.clone(); move |_| { row_menu.set(None); c.act(epoch, WsAction::ColourMany(vec![h], None)); } }, Svg { icon: Icon::Refresh } "Automatic color" }
                                        hr {}
                                        button { class: "mi", role: "menuitem", onclick: { let c = controller.clone(); move |_| { row_menu.set(None); c.navigate(epoch, Screen::Move(ItemHandle::Entry(h), None)); } }, Svg { icon: Icon::Move } "Move to group…" }
                                        button { class: "mi", role: "menuitem", id: "row-select", onclick: { let id = id.clone(); let c = controller.clone(); move |_| { row_menu.set(None); anchor.set(Some(id.clone())); c.set_selection(epoch, Some(BTreeSet::from([id.clone()]))); } }, Svg { icon: Icon::Check } "Select" }
                                        hr {}
                                        button { class: "mi danger", role: "menuitem", id: "row-trash", onclick: { let c = controller.clone(); move |_| { row_menu.set(None); c.act(epoch, WsAction::TrashMany(vec![h])); } }, Svg { icon: Icon::Trash } "Move to trash" }
                                    }
                                }
                            }
                        }
                            }
                        }
                    }
                }
                if list == Screen::Browse(None) {
                    RecoveredLink { controller: controller.clone(), epoch, revision }
                }
            }
        }
    }
}
/// The selection bar's open popover.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BarPop {
    Colour,
    Move,
}
#[component]
fn RecoveredLink(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let n = super::use_last(controller.read(epoch, |s| s.overview().map(|o| o.recovered)))
        .and_then(Result::ok)
        .unwrap_or(0);
    rsx! {
        if n > 0 { button { class: "link m8", onclick: go(&controller, epoch, Screen::Recovered), "Recovered items whose group is missing ({n})" } }
    }
}

/// The detail pane: the open entry, its form, history or attachments.
#[component]
pub(crate) fn Detail(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    screen: Screen,
    live: Live,
    busy: bool,
    report: Option<Report>,
) -> Element {
    let closed = screen.is_list();
    let inner = match screen.clone() {
        Screen::Entry(e) => {
            rsx! { EntryScreen { controller: controller.clone(), epoch, revision, entry: e, live } }
        }
        Screen::EditEntry => {
            rsx! { super::editor::EditEntry { controller: controller.clone(), epoch, revision } }
        }
        Screen::EditGroup => {
            rsx! { super::editor::EditGroup { controller: controller.clone(), epoch, revision } }
        }
        Screen::Move(item, at) => {
            rsx! { MoveScreen { controller: controller.clone(), epoch, revision, item, at } }
        }
        Screen::History(e) => {
            rsx! { History { controller: controller.clone(), epoch, revision, entry: e } }
        }
        Screen::HistoryVersion(e, v) => {
            rsx! { HistoryVersion { controller: controller.clone(), epoch, revision, entry: e, version: v, live } }
        }
        Screen::Attachments(e) => {
            rsx! { Attachments { controller: controller.clone(), epoch, revision, entry: e } }
        }
        _ => rsx! {
            div { class: "empty", div {
                div { class: "big", Svg { icon: Icon::Key } }
                "Select an item to see it here."
            } }
        },
    };
    let _ = busy;
    rsx! {
        section { class: if closed { "detail closed" } else { "detail" }, "aria-label": "Item",
            if let Some(r) = report { div { class: "detail-inner pb0", ReportCard { controller: controller.clone(), epoch, report: r } } }
            {inner}
        }
    }
}

/// One field of an entry. A click copies it (current entries only); a
/// protected value shows only through a 30 s reveal.
#[component]
fn FieldLine(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: Option<qv_core::EntryHandle>,
    field: FieldRow,
    reveal: RevealKey,
    copy: bool,
    live: Live,
) -> Element {
    let _ = revision;
    let shown = text(controller.revealed(epoch, &reveal));
    let revealed = !shown.is_empty();
    let totp = field.kind == FieldKind::Totp;
    let code_key = RevealKey::Totp(field.handle);
    let code = if totp {
        text(controller.revealed(epoch, &code_key))
    } else {
        Zeroizing::new(String::new())
    };
    let left = live.reveal_left.min(30);
    let offset = 56.5 - 56.5 * (left as f64) / 30.0;
    let copy_key = entry.filter(|_| copy).map(|e| {
        if totp {
            CopyKey::Totp(e, field.handle)
        } else {
            CopyKey::Field(e, field.handle)
        }
    });
    let ring = rsx! {
        svg { class: "revealring", view_box: "0 0 22 22", "aria-hidden": "true",
            circle { class: "track", cx: "11", cy: "11", r: "9" }
            circle { class: "left", cx: "11", cy: "11", r: "9", stroke_dasharray: "56.5", stroke_dashoffset: "{offset:.1}" }
        }
    };
    rsx! {
        div { class: "fld",
            if let Some(k) = copy_key.clone() {
                button { class: "copy-hit", "aria-label": "Copy {field.name.as_str()}", title: "Click to copy", onclick: act(&controller, epoch, WsAction::Copy(k)) }
            }
            div { class: "body",
                span { class: "k", "{field.name.as_str()}" small { "{kind_name(field.kind)}" } }
                if totp {
                    if code.is_empty() { span { class: "v masked", "One-time code" } }
                    else { span { class: "totp", span { class: "code revealed", "{code.as_str()}" } } }
                } else if let Some(v) = &field.value {
                    pre { class: "v field-value", "{v.as_str()}" }
                } else if revealed {
                    pre { class: "v field-value revealed", "{shown.as_str()}" }
                } else {
                    span { class: "v masked field-value", "{MASK}" }
                }
            }
            div { class: "acts",
                if totp {
                    if code.is_empty() {
                        button { class: "btn subtle", id: "show-code", onclick: act(&controller, epoch, WsAction::Reveal(code_key.clone())), Svg { icon: Icon::Eye } "Show code" }
                    } else {
                        button { class: "icon-btn", "aria-label": "Hide code", title: "Hide · {left} s left", onclick: act(&controller, epoch, WsAction::Hide), {ring} }
                    }
                } else if field.protected {
                    if revealed {
                        button { class: "icon-btn", "aria-label": "Hide", title: "Hide · {left} s left", onclick: act(&controller, epoch, WsAction::Hide), {ring} }
                    } else {
                        button { class: "icon-btn", "aria-label": "Reveal for 30 seconds", title: "Reveal for 30 s", onclick: act(&controller, epoch, WsAction::Reveal(reveal.clone())), Svg { icon: Icon::Eye } }
                    }
                }
                if let Some(k) = copy_key {
                    button { class: "icon-btn", "aria-label": "Copy", title: "Copy", onclick: act(&controller, epoch, WsAction::Copy(k)), Svg { icon: Icon::Copy } }
                }
            }
        }
    }
}

/// An entry's fields and notes, current or historical (read-only).
#[component]
fn EntryBody(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    view: EntryView,
    history: Option<String>,
    live: Live,
) -> Element {
    let current = history.is_none();
    let group = view.group.and_then(|g| {
        controller
            .read(epoch, |s| views::browse_header(s, Some(g)))
            .and_then(Result::ok)
            .and_then(|b| {
                (!b.root)
                    .then(|| b.crumbs.last().map(|c| c.1.to_string()))
                    .flatten()
            })
    });
    let url = view
        .fields
        .iter()
        .find(|f| f.kind == FieldKind::Url)
        .and_then(|f| f.value.clone());
    let kind = Zeroizing::new(view.type_hint.to_lowercase());
    let group_hue = view.group.map(|h| {
        let colour = controller
            .read(epoch, |s| s.group(h))
            .and_then(Result::ok)
            .and_then(|g| crate::editor::colour(g.icon.as_ref().map(qv_core::Text::expose)));
        item_hue(colour, &h.id_hex())
    });
    let tile = item_hue(view.colour, &view.handle.id_hex());
    let card = if current {
        controller
            .read(epoch, |s| Ok(views::card_face(s, &view)))
            .and_then(Result::ok)
            .flatten()
    } else {
        None
    };
    let wifi = current
        && view.versions == 1
        && crate::editor::ItemType::from_hint(&view.type_hint)
            == Some(crate::editor::ItemType::Wifi)
        && view
            .fields
            .iter()
            .any(|f| crate::editor::same_slot(&f.name, crate::editor::NETWORK));
    rsx! {
        div { class: "hero",
            span { class: "tile {tile}", "{initial(&view.title)}" }
            div { class: "min0",
                h1 { "{view.title.as_str()}" }
                div { class: "meta",
                    if let Some(u) = url { span { class: "pill link", Svg { icon: Icon::Globe } "{u.as_str()}" } }
                    if !view.type_hint.is_empty() { span { class: "pill", Svg { icon: kind_icon(&kind) } "{view.type_hint.as_str()}" } }
                    if let (Some(g), Some(h)) = (group, group_hue) { span { class: "pill", span { class: "dot {h}" } "{g}" } }
                }
            }
        }
        if view.versions > 1 {
            div { class: "banner", Svg { icon: Icon::Conflicts }
                span { class: "sp", "This entry has {view.versions} conflicting versions; one is shown. Choose one before copying or editing." }
                button { class: "btn", id: "entry-resolve", onclick: go(&controller, epoch, Screen::ConflictRecord(view.handle.id_hex())), "Compare and resolve" }
            }
        }
        if let Some(x) = &view.expires { div { class: "banner", Svg { icon: Icon::Clock } span { "Expires {x}" } } }
        if let Some(c) = card { div { class: "ie-face", {super::editor::card_face(&c, tile)} } }
        if wifi { WifiJoin { controller: controller.clone(), epoch, revision, entry: view.handle, live } }
        if !view.fields.is_empty() {
            div { class: "card fields",
                for f in view.fields.iter().cloned() {
                    FieldLine {
                        controller: controller.clone(), epoch, revision, live,
                        entry: current.then_some(view.handle),
                        reveal: match &history { Some(v) => RevealKey::History(v.clone(), f.id), None => RevealKey::Field(f.handle) },
                        copy: current && view.versions == 1,
                        field: f,
                    }
                }
            }
        }
        if let Some(n) = &view.notes {
            div { class: "card", div { class: "card-h", "NOTES" } pre { class: "notes", "{n.as_str()}" } }
        }
    }
}

/// "Show join code": a Wi‑Fi `WIFI:` QR for 30 s. It carries the password,
/// so it is an explicit reveal (0008 §4, 0009 §1.8).
#[component]
fn WifiJoin(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: qv_core::EntryHandle,
    live: Live,
) -> Element {
    let _ = revision;
    let key = RevealKey::WifiJoin(entry);
    let symbol = controller
        .revealed(epoch, &key)
        .and_then(|p| crate::qr::encode(p.expose_secret()).ok());
    let left = live.reveal_left.min(30);
    rsx! {
        div { class: "card ie-join",
            if let Some(symbol) = symbol {
                {join_qr(&symbol)}
                div { class: "min0",
                    b { "Scan to join" }
                    span { "Point the phone's camera at the code. It hides in {left} s." }
                    button { class: "btn subtle", id: "wifi-join-hide", onclick: act(&controller, epoch, WsAction::Hide), Svg { icon: Icon::EyeOff } "Hide" }
                }
            } else {
                span { class: "ie-qr", Svg { icon: Icon::Qr, large: true } }
                div { class: "min0",
                    b { "Join code" }
                    span { "Phones scan it to join this network. It contains the password and shows for 30 seconds." }
                    button { class: "btn", id: "wifi-join", onclick: act(&controller, epoch, WsAction::Reveal(key.clone())), Svg { icon: Icon::Qr } "Show join code" }
                }
            }
        }
    }
}
fn join_qr(symbol: &crate::qr::Symbol) -> Element {
    let side = symbol.size() + 8;
    let path = symbol.path();
    rsx! {
        svg { class: "ie-qrcode revealed", xmlns: "http://www.w3.org/2000/svg", view_box: "0 0 {side} {side}",
            width: "168", height: "168", shape_rendering: "crispEdges", role: "img", "aria-label": "Wi‑Fi join QR code",
            rect { width: "100%", height: "100%", fill: "white" }
            path { d: path.as_str(), fill: "black" }
        }
    }
}

#[component]
fn EntryScreen(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    entry: qv_core::EntryHandle,
    live: Live,
) -> Element {
    let _ = revision;
    // Which ⋯ opened the menu (0 phone bar, 1 desktop toolbar); it opens
    // under that button (a bottom sheet on phones).
    let mut menu = use_signal(|| None::<u8>);
    // Kept while an operation owns the vault, so the page does not blank.
    let read = super::use_last(controller.read(epoch, |s| {
        Ok((views::entry(s, entry)?, views::attachments(s, entry)?))
    }));
    let (view, files) = match read {
        Some(Ok((v, f))) if v.handle == entry => (v, f),
        Some(Ok(_)) => return rsx! { Unreadable { error: None } },
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let item = ItemHandle::Entry(entry);
    let editable = !view.deleted && view.versions == 1;
    let open_menu =
        move |at: u8| move |_| menu.set(if menu() == Some(at) { None } else { Some(at) });
    let entry_menu = rsx! {
        button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| menu.set(None) }
        div { class: "menu pop end", role: "menu",
            button { class: "mi", id: "menu-history", onclick: { let mut f = go(&controller, epoch, Screen::History(entry)); move |e| { menu.set(None); f(e) } }, Svg { icon: Icon::History } "History" }
            button { class: "mi", id: "menu-attachments", onclick: { let mut f = go(&controller, epoch, Screen::Attachments(entry)); move |e| { menu.set(None); f(e) } }, Svg { icon: Icon::Attach } "Attachments" span { class: "sub", "{view.attachments}" } }
            if !view.deleted {
                button { class: "mi", id: "menu-move", onclick: { let mut f = go(&controller, epoch, Screen::Move(item, None)); move |e| { menu.set(None); f(e) } }, Svg { icon: Icon::Move } "Move to group…" }
                hr {}
                button { class: "mi danger", id: "menu-delete", onclick: { let mut f = act(&controller, epoch, WsAction::Delete(item)); move |e| { menu.set(None); f(e) } }, Svg { icon: Icon::Trash } "Move to trash" }
            }
        }
    };
    rsx! {
        div { class: "phone-bar",
            button { class: "icon-btn back", "aria-label": "Back", onclick: back(&controller, epoch), Svg { icon: Icon::Back, large: true } }
            span { class: "sp" }
            if editable { button { class: "icon-btn", "aria-label": "Edit", onclick: act(&controller, epoch, WsAction::EditEntry(entry)), Svg { icon: Icon::Edit, large: true } } }
            div { class: "pop-anchor",
                button { class: "icon-btn", "aria-label": "More actions", onclick: open_menu(0), Svg { icon: Icon::More, large: true } }
                if menu() == Some(0) { {entry_menu.clone()} }
            }
        }
        div { class: "detail-inner fade-in",
            if view.deleted {
                div { class: "banner", Svg { icon: Icon::Trash } span { class: "sp", "This item is in the trash." }
                    button { class: "btn", onclick: act(&controller, epoch, WsAction::Restore(item)), Svg { icon: Icon::Restore } "Restore" }
                }
            }
            div { class: "toolbar desk-only tool-end",
                if editable { button { class: "btn", id: "entry-edit", onclick: act(&controller, epoch, WsAction::EditEntry(entry)), Svg { icon: Icon::Edit } "Edit" } }
                div { class: "pop-anchor",
                    button { class: "icon-btn", id: "entry-menu", "aria-label": "More actions", title: "More", onclick: open_menu(1), Svg { icon: Icon::More, large: true } }
                    if menu() == Some(1) { {entry_menu} }
                }
            }
            EntryBody { controller: controller.clone(), epoch, revision, view: view.clone(), history: None, live }
            // The attachment shelf (plan 0044): open one to preview it here.
            if editable || !files.is_empty() {
                div { class: "shelf",
                    div { class: "shelf-h", span { "FILES" } if !files.is_empty() { button { class: "link", onclick: go(&controller, epoch, Screen::Attachments(entry)), "Manage" } } }
                    div { class: "shelf-row",
                        for a in files {
                            button { class: "shelf-tile {file_tone(&a.name, &a.mime)}", disabled: a.conflicted, title: "{a.name.as_str()}",
                                "aria-label": "Preview {a.name.as_str()}",
                                onclick: act(&controller, epoch, WsAction::Preview(a.handle)),
                                span { class: "st-glyph", Svg { icon: file_icon(&a.name, &a.mime), large: true } }
                                b { "{a.name.as_str()}" }
                                small { if a.conflicted { "conflict" } else { "{human_size(a.size)}" } }
                            }
                        }
                        if editable {
                            button { class: "shelf-tile add", id: "shelf-add", onclick: go(&controller, epoch, Screen::Attachments(entry)),
                                span { class: "st-glyph", Svg { icon: Icon::Plus, large: true } }
                                b { "Add a file" }
                                small { "Up to 10 MiB" }
                            }
                        }
                    }
                }
            }
            div { class: "foot",
                span { "Modified {view.modified} · created {view.created}" }
                button { class: "link", id: "entry-history", onclick: go(&controller, epoch, Screen::History(entry)), "History" }
            }
        }
    }
}

#[component]
fn MoveScreen(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    item: ItemHandle,
    at: Option<qv_core::GroupHandle>,
) -> Element {
    let _ = revision;
    let mut view = match controller.read(epoch, |s| views::browse_header(s, at)) {
        Some(Ok(view)) => view,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let (owner, read) = super::use_page(
        &controller,
        epoch,
        crate::page_read::Lane::Groups,
        2,
        crate::page_read::Spec::Groups {
            parent: Some(view.here),
            query: Zeroizing::new(String::new()),
        },
    );
    let page = read.as_ref().and_then(|r| r.page.clone());
    if let Some(crate::page_read::Rows::Groups(groups)) = page.as_deref().map(|p| &p.rows) {
        view.groups = groups.clone();
    }
    let here = view.here;
    rsx! {
        div { class: "phone-bar", button { class: "icon-btn back", "aria-label": "Cancel", onclick: back(&controller, epoch), Svg { icon: Icon::Close, large: true } } }
        div { class: "detail-inner fade-in",
            h1 { class: "title-sm", "Move to a group" }
            div { class: "toolbar mb",
                for (g, name) in view.crumbs.iter().cloned() {
                    button { class: "chip", onclick: go(&controller, epoch, Screen::Move(item, Some(g))), Svg { icon: Icon::Folder } "{name.as_str()}" }
                }
            }
            div { class: "card",
                if view.groups.iter().all(|g| ItemHandle::Group(g.handle) == item) { div { class: "set-row", span { class: "l", span { "No groups inside this one." } } } }
                for g in view.groups.iter().filter(|&g| ItemHandle::Group(g.handle) != item).cloned() {
                    button { class: "set-row", onclick: go(&controller, epoch, Screen::Move(item, Some(g.handle))),
                        span { class: "si", Svg { icon: Icon::Folder } } span { class: "l", b { "{g.name.as_str()}" } } Svg { icon: Icon::Right }
                    }
                }
            }
            if let (Some(owner), Some(read)) = (owner, read) { super::PageNav { controller: controller.clone(), epoch, owner, read } }
            div { class: "actions",
                button { class: "btn subtle", onclick: back(&controller, epoch), "Cancel" }
                button { class: "btn primary", id: "move-here", onclick: act(&controller, epoch, WsAction::MoveTo(item, here)), "Move here" }
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
        div { class: "phone-bar", button { class: "icon-btn back", "aria-label": "Back", onclick: back(&controller, epoch), Svg { icon: Icon::Back, large: true } } }
        div { class: "detail-inner fade-in",
            div { class: "hero", span { class: "tile h6", Svg { icon: Icon::History, large: true } } div { h1 { "History" } p { class: "muted", "Earlier versions kept for this item. Restoring creates a new version." } } }
            if rows.is_empty() { div { class: "empty", "No earlier versions are kept." } }
            div { class: "timeline",
                for r in rows {
                    div { class: "tl-i",
                        button { class: "history-row", onclick: go(&controller, epoch, Screen::HistoryVersion(entry, r.version.clone())),
                            b { "{r.modified}" }
                            span { "{r.changed.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(\", \")}" if r.conflict { " · concurrent" } }
                        }
                    }
                }
            }
            div { class: "actions",
                button { class: "btn subtle", onclick: back(&controller, epoch), "Back" }
                button { class: "btn danger-text", onclick: act(&controller, epoch, WsAction::PurgeHistory(entry)), Svg { icon: Icon::Trash } "Purge history…" }
            }
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
    live: Live,
) -> Element {
    let _ = revision;
    let view = match controller.read(epoch, |s| views::history_version(s, entry, &version)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let conflicted = controller
        .read(epoch, |s| Ok(s.entry_version_count(entry)? > 1))
        .and_then(Result::ok)
        .unwrap_or(false);
    rsx! {
        div { class: "phone-bar", button { class: "icon-btn back", "aria-label": "Back", onclick: back(&controller, epoch), Svg { icon: Icon::Back, large: true } } }
        div { class: "detail-inner fade-in",
            div { class: "banner", Svg { icon: Icon::History } span { "An earlier version. Restoring creates a new version; nothing is overwritten." } }
            EntryBody { controller: controller.clone(), epoch, revision, view, history: Some(version.clone()), live }
            div { class: "actions",
                button { class: "btn subtle", onclick: back(&controller, epoch), "Back" }
                if conflicted { button { class: "btn", onclick: act(&controller, epoch, WsAction::RestoreHistory(entry, version.clone(), true)), "Restore and resolve conflict" } }
                button { class: "btn primary", id: "restore-version", onclick: act(&controller, epoch, WsAction::RestoreHistory(entry, version.clone(), false)), Svg { icon: Icon::Restore } "Restore this version" }
            }
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
        div { class: "phone-bar", button { class: "icon-btn back", "aria-label": "Back", onclick: back(&controller, epoch), Svg { icon: Icon::Back, large: true } } }
        div { class: "detail-inner fade-in",
            div { class: "hero", span { class: "tile h1", Svg { icon: Icon::Attach, large: true } } div { h1 { "Attachments" } p { class: "muted", "Up to 10 MiB each. Names and types are shown as text; files are never opened." } } }
            div { class: "card",
                if rows.is_empty() { div { class: "set-row", span { class: "l", span { "No attachments yet." } } } }
                for a in rows {
                    div { class: "dev",
                        div { class: "di", Svg { icon: Icon::File, large: true } }
                        div { class: "l", b { "{a.name.as_str()}" } span { "{a.mime.as_str()} · {a.size} bytes" if a.conflicted { " · conflict" } } }
                        button { class: "btn", disabled: a.conflicted, onclick: act(&controller, epoch, WsAction::Preview(a.handle)), Svg { icon: Icon::Eye } "Preview" }
                        SaveAttachment { controller: controller.clone(), epoch, handle: a.handle, name: a.name.to_string(), disabled: a.conflicted }
                        button { class: "btn subtle", "aria-label": "Remove {a.name.as_str()}", disabled: a.conflicted, onclick: act(&controller, epoch, WsAction::RemoveAttachment(a.handle)), Svg { icon: Icon::Trash } }
                    }
                }
            }
            super::pages::FilePicker { controller: controller.clone(), epoch, revision, purpose: super::pages::Purpose::AddAttachment(entry) }
            details { class: "muted mt",
                summary { "Name and type for the next attachment (optional)" }
                Input { controller: controller.clone(), epoch, field: WsField::AttachName, label: "Name", kind: Kind::Line, value: None, disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::AttachMime, label: "MIME type", kind: Kind::Line, value: None, disabled: false }
            }
        }
    }
}
/// A size for people: bytes, KB or MB.
pub(crate) fn human_size(n: u64) -> String {
    match n {
        0..1_000 => format!("{n} bytes"),
        1_000..1_000_000 => format!("{:.0} KB", n as f64 / 1_000.0),
        _ => format!("{:.1} MB", n as f64 / 1_000_000.0),
    }
}
/// The shelf's colour family for a file, from its untrusted name and type
/// (decoration only; previews never trust these).
fn file_tone(name: &str, mime: &str) -> &'static str {
    match file_family(name, mime) {
        Family::Image => "img",
        Family::Audio => "aud",
        Family::Video => "vid",
        Family::Text => "txt",
        Family::Other => "oth",
    }
}
fn file_icon(name: &str, mime: &str) -> Icon {
    match file_family(name, mime) {
        Family::Text => Icon::Note,
        _ => Icon::File,
    }
}
enum Family {
    Image,
    Audio,
    Video,
    Text,
    Other,
}
fn file_family(name: &str, mime: &str) -> Family {
    let ext = name
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();
    let m = mime.to_ascii_lowercase();
    if m.starts_with("image/") || matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "gif" | "webp") {
        Family::Image
    } else if m.starts_with("audio/")
        || matches!(ext.as_str(), "mp3" | "ogg" | "wav" | "flac" | "m4a")
    {
        Family::Audio
    } else if m.starts_with("video/") || matches!(ext.as_str(), "mp4" | "webm") {
        Family::Video
    } else if m.starts_with("text/")
        || matches!(ext.as_str(), "txt" | "md" | "csv" | "json" | "log")
    {
        Family::Text
    } else {
        Family::Other
    }
}

/// The full-window attachment viewer (0003 §6.4, 0009 §1.8; plan 0044).
/// Media load from the in-memory route; text renders as text. Escape or
/// Back closes it and wipes the content; arrows step through the entry's
/// files.
#[component]
pub(crate) fn Viewer(
    controller: Controller,
    epoch: FormEpoch,
    preview: crate::preview::PreviewView,
) -> Element {
    use crate::preview::Kind;
    let mut actual = use_signal(|| false);
    let mut wrap = use_signal(|| true);
    let p = preview;
    let many = p.count > 1;
    let keys = {
        let c = controller.clone();
        move |e: KeyboardEvent| match e.key() {
            Key::Escape => {
                e.stop_propagation();
                e.prevent_default();
                c.act(epoch, WsAction::ClosePreview);
            }
            Key::ArrowLeft if many => {
                e.stop_propagation();
                c.act(epoch, WsAction::PreviewStep(-1));
            }
            Key::ArrowRight if many => {
                e.stop_propagation();
                c.act(epoch, WsAction::PreviewStep(1));
            }
            _ => {}
        }
    };
    let kind_name = match p.kind {
        Kind::Image => "Image",
        Kind::Audio => "Audio",
        Kind::Video => "Video",
        Kind::Text => "Text",
        Kind::Unsupported => "File",
    };
    let lines = p.text.as_ref().map_or(0, |t| t.lines().count());
    let save = {
        #[cfg(target_os = "linux")]
        let direct = !crate::documents::picker_missing();
        #[cfg(not(target_os = "linux"))]
        let direct = false;
        let c = controller.clone();
        let handle = p.handle;
        let entry = p.entry;
        let name = p.name.to_string();
        move |e: MouseEvent| {
            e.stop_propagation();
            if direct {
                #[cfg(target_os = "linux")]
                crate::documents::pick_path(
                    &c,
                    epoch,
                    crate::documents::PathFor::Workspace,
                    qv_core::platform::portal::Pick::Save(name.clone()),
                    "Save a copy of the attachment",
                    Some(WsAction::SaveAttachment(handle)),
                );
            } else {
                // Android and portal-less desktops save from the files screen.
                c.navigate(epoch, Screen::Attachments(entry));
            }
            let _ = (&name, handle);
        }
    };
    let tone = file_tone(&p.name, p.mime);
    let step = |d: i8| {
        let c = controller.clone();
        move |e: MouseEvent| {
            e.stop_propagation();
            c.act(epoch, WsAction::PreviewStep(d));
        }
    };
    rsx! {
        // A click anywhere on the dark backdrop (title strip, stage, footer)
        // closes the preview; the content and the controls keep their clicks.
        div { class: "viewer v-{tone}", role: "dialog", "aria-modal": "true", "aria-label": "Preview of {p.name.as_str()}", tabindex: "-1", autofocus: true, onkeydown: keys,
            onclick: act(&controller, epoch, WsAction::ClosePreview),
            div { class: "v-top",
                span { class: "v-badge", Svg { icon: file_icon(&p.name, p.mime) } }
                div { class: "v-title", b { "{p.name.as_str()}" } span { "{kind_name} · {human_size(p.size)}" if many { " · {p.index + 1} of {p.count}" } } }
                span { class: "sp" }
                if p.kind == Kind::Image {
                    button { class: "v-btn", id: "viewer-zoom", title: if actual() { "Fit to window" } else { "Actual size" }, onclick: move |e: MouseEvent| { e.stop_propagation(); actual.set(!actual()) },
                        if actual() { "Fit" } else { "1:1" }
                    }
                }
                if p.kind == Kind::Text {
                    button { class: if wrap() { "v-btn on" } else { "v-btn" }, id: "viewer-wrap", "aria-pressed": if wrap() { "true" } else { "false" }, onclick: move |e: MouseEvent| { e.stop_propagation(); wrap.set(!wrap()) }, "Wrap" }
                }
                button { class: "v-btn", id: "viewer-save", onclick: save, Svg { icon: Icon::Archive } span { class: "v-lbl", "Save a copy" } }
                button { class: "v-btn icon", id: "viewer-close", "aria-label": "Close preview", title: "Close (Esc)", onclick: act(&controller, epoch, WsAction::ClosePreview), Svg { icon: Icon::Close, large: true } }
            }
            div { class: "v-stage",
                if many {
                    button { class: "v-nav prev", "aria-label": "Previous file", onclick: step(-1), Svg { icon: Icon::Back, large: true } }
                }
                if let Some(image) = p.image_load {
                    div { class: "v-none", onclick: |e: MouseEvent| e.stop_propagation(),
                        div { class: "v-none-glyph", Svg { icon: Icon::File, large: true } }
                        b { "Load this image?" }
                        span { "{image.description()}" }
                        button { class: "btn primary", id: "viewer-load-image", onclick: act(&controller, epoch, WsAction::LoadPreview(p.handle)), "Load image" }
                    }
                } else { match (p.kind, p.src.clone(), p.text.clone()) {
                    (Kind::Image, Some(src), _) => rsx! {
                        div { class: if actual() { "v-img actual" } else { "v-img" },
                            img { src: "{src.as_str()}", alt: "{p.name.as_str()}", draggable: "false", onclick: move |e: MouseEvent| { e.stop_propagation(); actual.set(!actual()) } }
                        }
                    },
                    (Kind::Audio, Some(src), _) => rsx! {
                        div { class: "v-audio", onclick: |e: MouseEvent| e.stop_propagation(),
                            div { class: "v-disc", div { class: "v-disc-label", Svg { icon: Icon::File, large: true } } }
                            div { class: "v-eq", "aria-hidden": "true", for _ in 0..24 { i {} } }
                            b { class: "v-track", "{p.name.as_str()}" }
                            audio { src: "{src.as_str()}", controls: true, preload: "none" }
                        }
                    },
                    (Kind::Video, Some(src), _) => rsx! {
                        div { class: "v-video", onclick: |e: MouseEvent| e.stop_propagation(), video { src: "{src.as_str()}", controls: true, preload: "none", "playsinline": "true" } }
                    },
                    (Kind::Text, _, Some(text)) => rsx! {
                        div { class: "v-text", onclick: |e: MouseEvent| e.stop_propagation(),
                            div { class: "v-text-meta", span { "{lines} lines" } if p.cut { span { class: "v-cut", "Showing the first 1 MB" } } }
                            pre { class: if wrap() { "v-pre wrap" } else { "v-pre" }, "{text.as_str()}" }
                        }
                    },
                    _ => rsx! {
                        div { class: "v-none", onclick: |e: MouseEvent| e.stop_propagation(),
                            div { class: "v-none-glyph", Svg { icon: Icon::File, large: true } }
                            b { "No preview for this kind of file" }
                            span { "QuickVault shows images, audio, video and text. Other files never open here; save a copy to use them in another app." }
                        }
                    },
                }
                }
                if many {
                    button { class: "v-nav next", "aria-label": "Next file", onclick: step(1), Svg { icon: Icon::Right, large: true } }
                }
            }
            if many {
                div { class: "v-dots", "aria-hidden": "true",
                    for i in 0..p.count.min(12) { i { class: if i == p.index { "on" } else { "" } } }
                }
            }
            div { class: "v-foot", Svg { icon: Icon::Shield } "Decrypted in memory only. Nothing is written to disk unless you save a copy." }
        }
    }
}
#[component]
fn SaveAttachment(
    controller: Controller,
    epoch: FormEpoch,
    handle: qv_core::AttachmentHandle,
    name: String,
    disabled: bool,
) -> Element {
    let _ = &name;
    #[cfg(target_os = "linux")]
    if !crate::documents::picker_missing() {
        return rsx! {
            button { class: "btn", disabled, onclick: picker(&controller, epoch, qv_core::platform::portal::Pick::Save(name.clone()), "Save the attachment", Some(WsAction::SaveAttachment(handle))), "Save…" }
        };
    }
    rsx! {
        button { class: "btn", disabled, onclick: act(&controller, epoch, WsAction::SaveAttachment(handle)), "Save…" }
    }
}
