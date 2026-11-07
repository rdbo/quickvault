// SPDX-License-Identifier: AGPL-3.0-or-later

//! The item editor (plan 0040 E1–E11, the approved prototype): a start box
//! that recognises what is being saved, a form shaped by the item's type,
//! field tools behind ⋯, one "Add a field" that infers the kind, card and
//! Wi‑Fi previews, the generator popover and the tile's colour picker.
//! Protected values are never prefilled: a saved one shows "Saved · Change",
//! and a generated one moves into its field in Rust.
use super::icons::{Icon, Svg, hue_class, item_hue, kind_icon, type_hue};
use super::items::{Input, Kind};
use super::pages::strength_label;
use super::shell::{Unreadable, act};
use crate::controller::{Controller, FormEpoch};
use crate::editor::{ADD_KINDS, HUES, ItemType, SECURITY_CHOICES, kind_label};
use crate::views::{self, CardFace, EntryFormView, FormRow, Role};
use crate::workspace::{GenFlag, GenMode, RevealKey, WsAction, WsField};
use dioxus::prelude::*;
use qv_core::{FieldKind, GroupHandle};
use std::collections::BTreeSet;
use zeroize::Zeroizing;

const MASK: &str = "••••••••";

/// What is open over the editor; one at a time.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pop {
    Colour,
    Type,
    Group,
    Field(u16),
    Kind,
    Gen(u16),
}

fn back(c: &Controller, e: FormEpoch) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| c.back(e)
}
fn set(
    c: &Controller,
    e: FormEpoch,
    field: WsField,
    value: &'static str,
) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| {
        let mut v = value.to_owned();
        c.ws_input(e, field, &mut v);
    }
}
fn text(v: Option<qv_core::SecretBytes>) -> Zeroizing<String> {
    Zeroizing::new(
        v.map(|v| String::from_utf8_lossy(v.expose_secret()).into_owned())
            .unwrap_or_default(),
    )
}
fn type_name(form: &EntryFormView) -> String {
    match form.kind {
        Some(t) => t.name().to_owned(),
        None if form.type_hint.is_empty() => "Something else".to_owned(),
        None => form.type_hint.to_string(),
    }
}

/// A transparent full-window layer under an open popover; a click closes it.
fn scrim(mut pop: Signal<Option<Pop>>) -> Element {
    rsx! { button { class: "pop-scrim", "aria-label": "Close", tabindex: "-1", onclick: move |_| pop.set(None) } }
}

#[component]
pub(crate) fn EditEntry(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let Some(form) = controller.entry_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    if form.start {
        return rsx! { StartStep { controller, epoch, revision, form } };
    }
    // Another entry's draft gets a fresh editor (local popover, rename and
    // notes state); a lone key would be ignored, hence the one-item list.
    rsx! {
        for id in [form.id.clone()] {
            Editor { key: "{id}", controller: controller.clone(), epoch, revision, form: form.clone() }
        }
    }
}

/// "What are you saving?": one box, a guess made on the device, type tiles.
#[component]
fn StartStep(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    form: EntryFormView,
) -> Element {
    let _ = revision;
    let guess = form.guess.clone();
    let has_guess = guess.is_some();
    let enter = {
        let c = controller.clone();
        move |e: KeyboardEvent| {
            if e.key() == Key::Enter && has_guess {
                e.prevent_default();
                c.act(epoch, WsAction::StartAs(None));
            }
        }
    };
    rsx! {
        div { class: "phone-bar",
            button { class: "icon-btn back", "aria-label": "Cancel", "data-qv-clear": "true", onclick: back(&controller, epoch), Svg { icon: Icon::Close, large: true } }
            span { class: "sp" }
        }
        div { class: "ie-start fade-in",
            h2 { "What are you saving?" }
            p { class: "lead", "Paste a website or a card number, or just type a name." }
            div { class: "ie-omni", onkeydown: enter,
                Svg { icon: Icon::Search }
                Input { controller: controller.clone(), epoch, field: WsField::Start, label: "What are you saving?", kind: Kind::Line, value: None, disabled: false, bare: true, autofocus: true, placeholder: "github.com, 4242 4242…, Home Wi‑Fi" }
            }
            if let Some(g) = guess {
                button { class: "ie-guess", id: "start-guess", onclick: act(&controller, epoch, WsAction::StartAs(None)),
                    span { class: "tile {type_hue(g.kind)}", Svg { icon: kind_icon(g.kind.hint()) } }
                    span { class: "t", b { "{g.line.as_str()}" } span { "{g.sub.as_str()}" } }
                    kbd { "Enter ↵" }
                }
                div { class: "ie-alts",
                    span { "Or save it as" }
                    for t in ItemType::ALL.into_iter().filter(|t| *t != g.kind && *t != ItemType::Other) {
                        button { onclick: act(&controller, epoch, WsAction::StartAs(Some(t))), "{t.name()}" }
                    }
                }
            }
            div { class: "ie-kinds",
                for t in ItemType::ALL {
                    button { class: "ie-kind", id: "start-{t.hint()}", onclick: act(&controller, epoch, WsAction::StartAs(Some(t))),
                        span { class: "tile {type_hue(t)}", Svg { icon: kind_icon(t.hint()), large: true } }
                        "{t.name()}"
                    }
                }
            }
            div { class: "ie-offline", Svg { icon: Icon::Shield } "Recognized on this device. Nothing is looked up online." }
        }
    }
}

/// The groups an entry can be saved in: the root, the top-level groups and
/// the entry's own group if it is nested deeper.
fn group_choices(
    controller: &Controller,
    epoch: FormEpoch,
    current: GroupHandle,
) -> Vec<(GroupHandle, String, &'static str)> {
    controller
        .read(epoch, |s| {
            let root = s.root()?;
            let mut out = vec![(root, "No group".to_owned(), "h11")];
            for g in views::top_groups(s)? {
                out.push((
                    g.handle,
                    g.name.to_string(),
                    item_hue(g.colour, &g.handle.id_hex()),
                ));
            }
            if out.iter().all(|(h, _, _)| *h != current)
                && let Some(name) = views::browse(s, Some(current))?
                    .crumbs
                    .last()
                    .map(|c| c.1.to_string())
            {
                out.push((current, name, super::icons::id_hue(&current.id_hex())));
            }
            Ok(out)
        })
        .and_then(Result::ok)
        .unwrap_or_default()
}

#[component]
fn Editor(controller: Controller, epoch: FormEpoch, revision: u64, form: EntryFormView) -> Element {
    let mut pop = use_signal(|| None::<Pop>);
    let mut adding = use_signal(|| false);
    let add_kind = use_signal(|| None::<FieldKind>);
    let renaming = use_signal(|| None::<u16>);
    let changing = use_signal(BTreeSet::<u16>::new);
    let mut notes_open = use_signal(|| !form.notes.is_empty() || form.kind == Some(ItemType::Note));
    let kind = form.kind.unwrap_or(ItemType::Other);
    let is_note = form.kind == Some(ItemType::Note);
    let hue = item_hue(form.colour, &form.id);
    let groups = group_choices(&controller, epoch, form.group);
    let group = groups.iter().find(|g| g.0 == form.group).cloned();
    let save = act(&controller, epoch, WsAction::SaveEntry);
    // Esc closes what is open before it reaches the root (which cancels).
    let keys = move |e: KeyboardEvent| {
        if e.key() == Key::Escape && (pop().is_some() || adding()) {
            e.stop_propagation();
            e.prevent_default();
            pop.set(None);
            adding.set(false);
        }
    };
    let verb = if form.new { "Create" } else { "Save" };
    let heading = if form.new {
        format!("New {}", type_name(&form).to_lowercase())
    } else {
        "Edit".to_owned()
    };
    let placeholder = form
        .auto_title
        .as_ref()
        .map_or_else(|| kind.placeholder().to_owned(), |t| t.0.to_string());
    // A new item focuses its title, or, once the title is known, its first
    // empty plain field.
    let focus = (form.new && (!form.title.is_empty() || form.auto_title.is_some()))
        .then(|| {
            form.rows
                .iter()
                .find(|r| {
                    !r.protected
                        && matches!(r.role, Role::Plain | Role::Expiry)
                        && r.value.as_ref().is_none_or(|v| v.is_empty())
                })
                .map(|r| r.index)
        })
        .flatten();
    let fields = rsx! {
        if !form.rows.is_empty() {
            div { class: "ie-fields",
                for (n, row) in form.rows.iter().cloned().enumerate() {
                    {field_row(&controller, epoch, &form, row.clone(), n == 0, n + 1 == form.rows.len(), focus == Some(row.index), pop, renaming, changing)}
                }
            }
        }
        if let Some(name) = form.removed.as_ref() {
            div { class: "ie-undo", role: "status", span { "Removed “{name.as_str()}”" } button { id: "undo-remove", onclick: act(&controller, epoch, WsAction::UndoRemoveField), "Undo" } }
        }
        {adder(&controller, epoch, kind, form.new_kind, pop, adding, add_kind)}
    };
    let notes = rsx! {
        div { class: "ie-notes",
            if form.notes_too_large {
                p { class: "hint", "{crate::controller::AppError::TooLargeForApp.message()}" }
            } else if notes_open() {
                Input { controller: controller.clone(), epoch, field: WsField::Notes, label: "Notes", kind: Kind::Multi, value: Some(form.notes.to_string()), disabled: false, bare: true, class: "ie-notearea", placeholder: if is_note { "Start writing…" } else { "Notes" }, autofocus: !form.new && !is_note && form.notes.is_empty() }
            } else {
                button { class: "ie-notelink", id: "add-note", onclick: move |_| notes_open.set(true), Svg { icon: Icon::Note } "Add a note" }
            }
        }
    };
    rsx! {
        div { class: "phone-bar",
            button { class: "icon-btn back", "aria-label": "Cancel", "data-qv-clear": "true", onclick: back(&controller, epoch), Svg { icon: Icon::Close, large: true } }
            b { class: "ie-pbar-t", "{heading}" }
            button { class: "btn primary", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::SaveEntry), "{verb}" }
        }
        div { class: if is_note { "detail-inner ie isnote fade-in" } else { "detail-inner ie fade-in" }, onkeydown: keys,
            div { class: "ie-head",
                div { class: "pop-anchor",
                    button { class: "tile ie-tile {hue}", id: "item-colour", "aria-label": "Choose a color", title: "Color",
                        onclick: move |_| pop.set(if pop() == Some(Pop::Colour) { None } else { Some(Pop::Colour) }),
                        Svg { icon: kind_icon(kind.hint()), large: true }
                    }
                    if pop() == Some(Pop::Colour) {
                        {scrim(pop)}
                        {swatches(&controller, epoch, form.colour, pop, "menu pop")}
                    }
                }
                div { class: "ie-grow",
                    Input { controller: controller.clone(), epoch, field: WsField::Title, label: "Title", kind: Kind::Line, value: Some(form.title.to_string()), disabled: false, bare: true, class: "ie-title", placeholder, autofocus: form.new && form.title.is_empty() && form.auto_title.is_none() }
                    div { class: "ie-chips",
                        div { class: "pop-anchor",
                            button { class: "ie-chip", id: "type-chip", "aria-haspopup": "menu",
                                onclick: move |_| pop.set(if pop() == Some(Pop::Type) { None } else { Some(Pop::Type) }),
                                Svg { icon: kind_icon(kind.hint()) } "{type_name(&form)}" Svg { icon: Icon::ChevronDown }
                            }
                            if pop() == Some(Pop::Type) {
                                {scrim(pop)}
                                div { class: "menu pop", role: "menu",
                                    div { class: "label", "WHAT IT IS" }
                                    for t in ItemType::ALL {
                                        button { class: "mi", role: "menuitem", id: "type-{t.hint()}",
                                            onclick: { let c = controller.clone(); move |_| { pop.set(None); c.act(epoch, WsAction::SetType(t)); } },
                                            Svg { icon: kind_icon(t.hint()) } "{t.name()}"
                                            if form.kind == Some(t) { span { class: "sub", Svg { icon: Icon::Check } } }
                                        }
                                    }
                                }
                            }
                        }
                        div { class: "pop-anchor",
                            button { class: "ie-chip", id: "group-chip", "aria-haspopup": "menu",
                                onclick: move |_| pop.set(if pop() == Some(Pop::Group) { None } else { Some(Pop::Group) }),
                                if let Some((_, name, h)) = group.clone() { span { class: "ie-dot {h}" } "{name}" } else { "Group" }
                                Svg { icon: Icon::ChevronDown }
                            }
                            if pop() == Some(Pop::Group) {
                                {scrim(pop)}
                                div { class: "menu pop", role: "menu",
                                    div { class: "label", "SAVE IN" }
                                    for (g, name, h) in groups.clone() {
                                        button { class: "mi", role: "menuitem",
                                            onclick: { let c = controller.clone(); move |_| { pop.set(None); c.act(epoch, WsAction::SetGroup(g)); } },
                                            span { class: "ie-dot {h}" } "{name}"
                                            if g == form.group { span { class: "sub", Svg { icon: Icon::Check } } }
                                        }
                                    }
                                }
                            }
                        }
                        if form.title.is_empty() && let Some((_, from)) = form.auto_title.as_ref() {
                            span { class: "ie-auto", "Title from {from}" }
                        }
                    }
                }
            }
            if let Some(card) = form.card.clone() { {card_face(&card, hue)} }
            if let Some(w) = form.wifi.clone() {
                div { class: "ie-wifi",
                    span { class: "ie-qr", Svg { icon: Icon::Qr, large: true } }
                    div { class: "min0",
                        b { if w.name.is_empty() { "Network name" } else { "{w.name.as_str()}" } }
                        span { "After you save, the item's page can show a code that phones scan to join." }
                        span { class: "ie-sec", "{security_label(&w.security)}" }
                    }
                }
            }
            if is_note { {notes.clone()} {fields} } else { {fields} {notes} }
            div { class: "savebar desk-only",
                span { "Esc cancels · Ctrl S saves" }
                button { class: "btn subtle", "data-qv-clear": "true", onclick: back(&controller, epoch), "Cancel" }
                button { class: "btn primary", id: "entry-save", "data-qv-clear": "true", onclick: save, if form.new { "Create item" } else { "Save changes" } }
            }
        }
    }
}

fn security_label(v: &str) -> &'static str {
    SECURITY_CHOICES
        .iter()
        .find(|(value, _)| value.eq_ignore_ascii_case(v))
        .map_or("", |(_, label)| label)
}

/// The colour swatches and "Automatic" (0003 §5.5).
fn swatches(
    controller: &Controller,
    epoch: FormEpoch,
    current: Option<u8>,
    mut pop: Signal<Option<Pop>>,
    class: &'static str,
) -> Element {
    let pick = |n: Option<u8>| {
        let c = controller.clone();
        move |_| {
            pop.set(None);
            c.act(epoch, WsAction::SetHue(n));
        }
    };
    // A popover is a menu; inside a form the swatches are a labelled group.
    let popover = class.contains("menu");
    rsx! {
        div { class, role: if popover { "menu" } else { "group" }, "aria-label": "Color",
            div { class: "label", if popover { "COLOR" } else { "Color" } }
            div { class: "ie-swatches",
                for n in 0..HUES {
                    button { class: if current == Some(n) { format!("on {}", hue_class(n)) } else { hue_class(n).to_owned() }, id: "colour-{n}", "aria-label": "Color {n + 1}", "aria-pressed": if current == Some(n) { "true" } else { "false" }, onclick: pick(Some(n)) }
                }
            }
            hr {}
            button { class: "mi", id: "colour-auto", onclick: pick(None), Svg { icon: Icon::Refresh } "Automatic" if current.is_none() { span { class: "sub", Svg { icon: Icon::Check } } } }
        }
    }
}

/// A payment card's face: brand, masked number with its last four, name
/// and expiry (never the number, 0009 §1.8). While the card-number input
/// has focus, app.js mirrors that input's own digits into the empty `live`
/// line, which then hides the masked one; Rust never renders them.
pub(crate) fn card_face(card: &CardFace, hue: &'static str) -> Element {
    let number = format!(
        "•••• •••• •••• {}",
        card.info.last4.as_deref().unwrap_or("••••")
    );
    rsx! {
        div { class: "ie-card {hue}", role: "img", "aria-label": "Card preview",
            div { class: "row1", span { class: "emv" } span { class: "ie-brand", "{card.info.brand.unwrap_or(\"\")}" } }
            div { class: "num live", "aria-hidden": "true" }
            div { class: "num", "{number}" }
            div { class: "row2",
                div { class: "min0", small { "Card holder" } b { if card.name.is_empty() { "Your name" } else { "{card.name.as_str()}" } } }
                div { class: "r", small { "Expires" } b { if card.expiry.is_empty() { "MM/YY" } else { "{card.expiry.as_str()}" } } }
            }
        }
    }
}

fn placeholder(row: &FormRow) -> &'static str {
    let name = row.name.to_lowercase();
    match (row.role, row.kind) {
        (Role::Expiry, _) => "MM/YY",
        (Role::CardNumber, _) => "1234 5678 9012 3456",
        (_, FieldKind::Url) => "example.com",
        (_, FieldKind::Email) => "name@example.com",
        (_, FieldKind::Totp) => "otpauth:// link from the site",
        _ if name == "username" => "you@example.com",
        _ if name == "network name" => "What your devices show",
        _ if name == "name on card" => "As printed",
        _ if name == "security code" => "3 or 4 digits",
        _ => "",
    }
}

#[allow(clippy::too_many_arguments)] // One row's view of the form and the editor's UI state.
fn field_row(
    controller: &Controller,
    epoch: FormEpoch,
    form: &EntryFormView,
    row: FormRow,
    first: bool,
    last: bool,
    focus: bool,
    mut pop: Signal<Option<Pop>>,
    mut renaming: Signal<Option<u16>>,
    mut changing: Signal<BTreeSet<u16>>,
) -> Element {
    let i = row.index;
    let open = pop() == Some(Pop::Field(i));
    let showing = form.showing == Some(i);
    let protected_role = matches!(row.role, Role::Password | Role::Hidden | Role::CardNumber);
    let card_number = row.role == Role::CardNumber;
    let card_format: &'static str = if card_number { "card" } else { "" };
    let label = if renaming() == Some(i) {
        let done = move |e: KeyboardEvent| {
            if e.key() == Key::Enter || e.key() == Key::Escape {
                e.stop_propagation();
                e.prevent_default();
                renaming.set(None);
            }
        };
        rsx! {
            div { class: "ie-label renaming", onkeydown: done, onfocusout: move |_| renaming.set(None),
                Input { controller: controller.clone(), epoch, field: WsField::FieldName(i), label: "Field name", kind: Kind::Line, value: Some(row.name.to_string()), disabled: false, bare: true, autofocus: true }
            }
        }
    } else {
        rsx! { label { class: "ie-label", r#for: super::items::dom_id(if row.protected { WsField::Replacement(i) } else { WsField::FieldValue(i) }), title: "{row.name.as_str()}", "{row.name.as_str()}" } }
    };
    let keep = {
        let c = controller.clone();
        move |_| {
            let mut v = String::new();
            c.ws_input(epoch, WsField::Replacement(i), &mut v);
            changing.write().remove(&i);
        }
    };
    let card = form.card.clone();
    let check = match (row.role, card.as_ref()) {
        (Role::CardNumber, Some(c)) => match c.info.valid {
            Some(true) => Some((
                format!("✓ {}", c.info.brand.unwrap_or("Valid")),
                "ie-check ok",
            )),
            Some(false) => Some(("Check the number".to_owned(), "ie-check bad")),
            None => c.info.brand.map(|b| (b.to_owned(), "ie-check")),
        },
        (Role::Expiry, Some(c)) => c
            .left
            .clone()
            .map(|(t, ok)| (t, if ok { "ie-check ok" } else { "ie-check bad" })),
        _ => None,
    };
    let reveal_key = RevealKey::Replacement(i);
    // A value set in Rust (generated, or from the start box) is not in the
    // control, so it shows as dots with a 30 s reveal and Change.
    let generated = (row.generated || row.filled) && row.replaced;
    let gen_open = pop() == Some(Pop::Gen(i));
    let open_gen = {
        let c = controller.clone();
        move |_| {
            if gen_open {
                pop.set(None);
                return;
            }
            if c.generator_form(epoch)
                .is_some_and(|g| g.mode == GenMode::Pin)
            {
                c.act(epoch, WsAction::GenMode(GenMode::Characters));
            }
            c.act(epoch, WsAction::Generate);
            pop.set(Some(Pop::Gen(i)));
        }
    };
    let gen_button = rsx! {
        if row.role == Role::Password {
            div { class: "pop-anchor",
                button { class: "ie-ib", id: "gen-{i}", "aria-label": "Generate a password", title: "Generate", onclick: open_gen, Svg { icon: Icon::Generator } }
                if gen_open { {scrim(pop)} {generator(controller, epoch, i, pop)} }
            }
        }
    };
    let value = if row.too_large {
        rsx! { p { class: "hint", "{crate::controller::AppError::TooLargeForApp.message()}" } }
    } else if protected_role && generated {
        let shown = text(controller.revealed(epoch, &reveal_key));
        let masked = match (row.role, card.as_ref().and_then(|c| c.info.last4.as_ref())) {
            (Role::CardNumber, Some(last4)) => format!("•••• {last4}"),
            _ => MASK.to_owned(),
        };
        rsx! {
            div { class: "ie-box",
                div { class: "ie-saved generated",
                    if shown.is_empty() { span { class: "dots", "{masked}" } } else { span { class: "mono revealed", "{shown.as_str()}" } }
                    if row.generated { span { class: "tag", Svg { icon: Icon::Generator } "Generated" } }
                    if shown.is_empty() {
                        button { class: "ie-ib", "aria-label": "Show for 30 seconds", onclick: act(controller, epoch, WsAction::Reveal(reveal_key.clone())), Svg { icon: Icon::Eye } }
                    } else {
                        button { class: "ie-ib", "aria-label": "Hide", onclick: act(controller, epoch, WsAction::Hide), Svg { icon: Icon::EyeOff } }
                    }
                    button { class: "ie-change", onclick: { let c = controller.clone(); move |_| { let mut v = String::new(); c.ws_input(epoch, WsField::Replacement(i), &mut v); changing.write().insert(i); } }, "Change" }
                }
                {gen_button}
            }
        }
    } else if protected_role && row.stored && !row.replaced && !changing().contains(&i) {
        rsx! {
            div { class: "ie-box",
                div { class: "ie-saved",
                    span { class: "dots", "{MASK}" }
                    span { class: "tag", Svg { icon: Icon::Lock } "Saved" }
                    button { class: "ie-change", id: "change-{i}", onclick: move |_| { changing.write().insert(i); }, "Change" }
                }
            }
        }
    } else if protected_role || (row.protected && row.kind != FieldKind::Multiline) {
        rsx! {
            div { class: "ie-box",
                // A card number shows what is typed (grouped in fours, like the
                // card), so the user can check it; it is still stored protected.
                Input { controller: controller.clone(), epoch, field: WsField::Replacement(i), label: row.name.to_string(), kind: if showing || card_number { Kind::Line } else { Kind::Secret }, value: None, disabled: false, bare: true, class: "mono", placeholder: placeholder(&row), autofocus: changing().contains(&i), format: card_format }
                if let Some((t, class)) = check.clone() { span { class, "{t}" } }
                if card_number {
                } else if showing {
                    button { class: "ie-ib", "aria-label": "Hide", title: "Hide", onclick: act(controller, epoch, WsAction::Hide), Svg { icon: Icon::EyeOff } }
                } else {
                    button { class: "ie-ib", "aria-label": "Show for 30 seconds", title: "Show for 30 s", disabled: !row.replaced, onclick: act(controller, epoch, WsAction::Reveal(reveal_key.clone())), Svg { icon: Icon::Eye } }
                }
                {gen_button}
                if row.stored && changing().contains(&i) {
                    button { class: "ie-ib", "aria-label": "Keep the saved value", title: "Keep the saved value", onclick: keep, Svg { icon: Icon::Close } }
                }
            }
        }
    } else if row.protected {
        // A protected multi-line value (recovery codes): typed in a textarea.
        rsx! {
            div { class: "ie-box",
                Input { controller: controller.clone(), epoch, field: WsField::Replacement(i), label: row.name.to_string(), kind: Kind::Multi, value: None, disabled: false, bare: true, placeholder: if row.stored { "Saved. Type to replace it" } else { "" } }
            }
        }
    } else if row.role == Role::Security {
        let current = row
            .value
            .as_deref()
            .map(String::as_str)
            .unwrap_or_default()
            .to_owned();
        rsx! {
            div { class: "ie-seg", role: "radiogroup", "aria-label": "{row.name.as_str()}",
                for (v, label) in SECURITY_CHOICES {
                    button { role: "radio", class: if current.eq_ignore_ascii_case(v) { "on" } else { "" }, "aria-checked": if current.eq_ignore_ascii_case(v) { "true" } else { "false" }, onclick: set(controller, epoch, WsField::FieldValue(i), v), "{label}" }
                }
            }
        }
    } else {
        let multi = row.kind == FieldKind::Multiline;
        let mono: &'static str = if row.role == Role::Expiry { "mono" } else { "" };
        rsx! {
            div { class: "ie-box",
                Input { controller: controller.clone(), epoch, field: WsField::FieldValue(i), label: row.name.to_string(), kind: if multi { Kind::Multi } else { Kind::Line }, value: Some(row.value.as_deref().map(String::as_str).unwrap_or_default().to_owned()), disabled: false, bare: true, class: mono, placeholder: placeholder(&row), autofocus: focus }
                if let Some((t, class)) = check.clone() { span { class, "{t}" } }
            }
        }
    };
    let can_hide =
        row.kind != FieldKind::Totp && !matches!(row.role, Role::CardNumber | Role::Security);
    let menu_item = |a: WsAction| {
        let c = controller.clone();
        move |_| {
            pop.set(None);
            c.act(epoch, a.clone());
        }
    };
    rsx! {
        div { class: if open { "ie-row open" } else { "ie-row" },
            {label}
            {value}
            div { class: "pop-anchor",
                button { class: "ie-ib ie-more", id: "field-more-{i}", "aria-label": "Options for {row.name.as_str()}", "aria-haspopup": "menu", "aria-expanded": if open { "true" } else { "false" },
                    onclick: move |_| pop.set(if open { None } else { Some(Pop::Field(i)) }),
                    Svg { icon: Icon::More }
                }
                if open {
                    {scrim(pop)}
                    div { class: "menu pop end", role: "menu",
                        button { class: "mi", role: "menuitem", onclick: move |_| { pop.set(None); renaming.set(Some(i)); }, Svg { icon: Icon::Edit } "Rename" }
                        if can_hide {
                            button { class: "mi", role: "menuitem", id: "field-protect-{i}", onclick: menu_item(WsAction::ToggleProtect(i)),
                                if row.protected { Svg { icon: Icon::Eye } "Show the value normally" } else { Svg { icon: Icon::Lock } "Hide the value" }
                            }
                        }
                        if !first { button { class: "mi", role: "menuitem", onclick: menu_item(WsAction::MoveField(i, true)), Svg { icon: Icon::Up } "Move up" } }
                        if !last { button { class: "mi", role: "menuitem", onclick: menu_item(WsAction::MoveField(i, false)), Svg { icon: Icon::ChevronDown } "Move down" } }
                        hr {}
                        button { class: "mi danger", role: "menuitem", id: "field-remove-{i}", onclick: menu_item(WsAction::RemoveField(i)), Svg { icon: Icon::Trash } "Remove field" }
                    }
                }
            }
        }
    }
}

/// The generator popover over the workspace generator form. "Use it" moves
/// the value into the field in Rust; it never passes through the DOM.
fn generator(
    controller: &Controller,
    epoch: FormEpoch,
    i: u16,
    mut pop: Signal<Option<Pop>>,
) -> Element {
    let Some(g) = controller.generator_form(epoch) else {
        return rsx! {};
    };
    let value = text(controller.generated(epoch).map(|(v, _)| v));
    let words = g.mode == GenMode::Words;
    let regen = |a: WsAction| {
        let c = controller.clone();
        move |_| {
            c.act(epoch, a.clone());
            c.act(epoch, WsAction::Generate);
        }
    };
    let slide = {
        let c = controller.clone();
        let field = if words {
            WsField::GenWords
        } else {
            WsField::GenLength
        };
        move |e: FormEvent| {
            let mut v = e.value();
            c.ws_input(epoch, field, &mut v);
            c.act(epoch, WsAction::Generate);
        }
    };
    let (n, min, max) = if words {
        (g.words, 3, 12)
    } else {
        (g.length, 12, 64)
    };
    let use_it = {
        let c = controller.clone();
        move |_| {
            pop.set(None);
            c.act(epoch, WsAction::UseGenerated(i));
        }
    };
    rsx! {
        div { class: "menu pop end ie-gen", role: "dialog", "aria-label": "Generate a password",
            div { class: "out mono revealed", id: "gen-value", if value.is_empty() { "…" } else { "{value.as_str()}" } }
            label { span { if words { "Words" } else { "Length" } } b { "{n}" } }
            input { r#type: "range", id: "gen-range", min: "{min}", max: "{max}", initial_value: "{n}", "aria-label": if words { "Words" } else { "Length" }, oninput: slide }
            div { class: "sw-row", span { "Use words" }
                button { class: "sw", role: "switch", "aria-label": "Use words", "aria-checked": if words { "true" } else { "false" },
                    onclick: regen(WsAction::GenMode(if words { GenMode::Characters } else { GenMode::Words })) }
            }
            if !words {
                div { class: "sw-row", span { "Symbols" }
                    button { class: "sw", role: "switch", "aria-label": "Symbols", "aria-checked": if g.flags[3] { "true" } else { "false" }, onclick: regen(WsAction::GenToggle(GenFlag::Symbols)) }
                }
            }
            if let Some(bits) = g.bits { p { class: "ie-bits", "{strength_label(bits)} · {bits:.0} bits" } }
            div { class: "ie-genacts",
                button { class: "btn", onclick: act(controller, epoch, WsAction::Generate), Svg { icon: Icon::Refresh } "Again" }
                button { class: "btn primary", id: "gen-use", disabled: value.is_empty(), onclick: use_it, "Use it" }
            }
        }
    }
}

/// "Add a field": a name box whose kind follows the name, with a few
/// common names for the item's type.
fn adder(
    controller: &Controller,
    epoch: FormEpoch,
    kind: ItemType,
    inferred: (FieldKind, bool),
    mut pop: Signal<Option<Pop>>,
    mut adding: Signal<bool>,
    mut add_kind: Signal<Option<FieldKind>>,
) -> Element {
    if !adding() {
        return rsx! {
            div { class: "ie-addrow",
                button { class: "ie-addbtn", id: "add-field", onclick: move |_| { add_kind.set(None); adding.set(true); }, Svg { icon: Icon::Plus } "Add a field" }
            }
        };
    }
    let shown = add_kind().unwrap_or(inferred.0);
    let commit = {
        let c = controller.clone();
        move || {
            c.act(epoch, WsAction::AddField(add_kind()));
            add_kind.set(None);
            adding.set(false);
        }
    };
    let keys = {
        let mut commit = commit.clone();
        move |e: KeyboardEvent| {
            if e.key() == Key::Enter {
                e.prevent_default();
                commit();
            } else if e.key() == Key::Escape {
                e.stop_propagation();
                e.prevent_default();
                adding.set(false);
            }
        }
    };
    let kind_open = pop() == Some(Pop::Kind);
    rsx! {
        div { class: "ie-addrow",
            div { class: "ie-adder",
                div { class: "ie-box dashed", onkeydown: keys,
                    Input { controller: controller.clone(), epoch, field: WsField::NewFieldName, label: "Field name", kind: Kind::Line, value: None, disabled: false, bare: true, autofocus: true, placeholder: "Name the field, like PIN or Email" }
                    div { class: "pop-anchor",
                        button { class: "ie-kindpill", id: "add-kind", "aria-label": "Kind of field", onclick: move |_| pop.set(if kind_open { None } else { Some(Pop::Kind) }),
                            "{kind_label(shown)}" Svg { icon: Icon::ChevronDown }
                        }
                        if kind_open {
                            {scrim(pop)}
                            div { class: "menu pop end", role: "menu",
                                div { class: "label", "KIND OF FIELD" }
                                for k in ADD_KINDS {
                                    button { class: "mi", role: "menuitem", onclick: move |_| { add_kind.set(Some(k)); pop.set(None); },
                                        "{kind_label(k)}" if k == shown { span { class: "sub", Svg { icon: Icon::Check } } }
                                    }
                                }
                            }
                        }
                    }
                    button { class: "ie-ib", id: "add-field-ok", "aria-label": "Add the field", title: "Add", onclick: { let mut commit = commit.clone(); move |_| commit() }, Svg { icon: Icon::Check } }
                    button { class: "ie-ib", "aria-label": "Cancel", title: "Cancel", onclick: move |_| adding.set(false), Svg { icon: Icon::Close } }
                }
                div { class: "ie-quick",
                    span { "Common:" }
                    for name in kind.common().iter().copied() {
                        button { onclick: { let c = controller.clone(); move |_| { c.act(epoch, WsAction::AddNamedField(name)); adding.set(false); } }, "{name}" }
                    }
                }
            }
        }
    }
}

/// Group editing: the name and the colour (0003 §5.5).
#[component]
pub(crate) fn EditGroup(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let pop = use_signal(|| None::<Pop>);
    let Some(form) = controller.group_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    let hue = item_hue(form.colour, &form.id);
    rsx! {
        div { class: "phone-bar", button { class: "icon-btn back", "aria-label": "Cancel", onclick: back(&controller, epoch), Svg { icon: Icon::Close, large: true } } }
        div { class: "detail-inner fade-in",
            div { class: "hero", span { class: "tile {hue}", Svg { icon: Icon::Folder, large: true } }
                h1 { if form.new { "New group" } else { "Edit group" } }
            }
            div { class: "card", div { class: "ed",
                label { r#for: "ws-group-name", "Name" }
                Input { controller: controller.clone(), epoch, field: WsField::GroupName, label: "Name", kind: Kind::Line, value: Some(form.name.to_string()), disabled: false, bare: true, autofocus: true, placeholder: "Group name" }
            } }
            {swatches(&controller, epoch, form.colour, pop, "card ie-colours")}
            div { class: "actions",
                button { class: "btn subtle", onclick: back(&controller, epoch), "Cancel" }
                button { class: "btn primary", id: "group-save", onclick: act(&controller, epoch, WsAction::SaveGroup), "Save" }
            }
        }
    }
}
