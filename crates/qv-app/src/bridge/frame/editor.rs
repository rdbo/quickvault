// SPDX-License-Identifier: AGPL-3.0-or-later

//! The item editor. Protected values are never
//! prefilled; a revealed replacement shows only during its 30 s reveal.
use super::{Ctx, convert, items};
use crate::editor::{ADD_KINDS, ItemType, SECURITY_CHOICES, kind_label};
use crate::views::{EntryFormView, FormRow, Role};
use crate::workspace::{GenMode, RevealKey};
use qv_core::FieldKind;
use qv_ui_api as api;
use qv_ui_api::{EditorPop, Z};

const MASK: &str = "••••••••";

fn role(r: Role) -> api::Role {
    match r {
        Role::Plain => api::Role::Plain,
        Role::Password => api::Role::Password,
        Role::Hidden => api::Role::Hidden,
        Role::CardNumber => api::Role::CardNumber,
        Role::Expiry => api::Role::Expiry,
        Role::Security => api::Role::Security,
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

fn security_label(v: &str) -> &'static str {
    SECURITY_CHOICES
        .iter()
        .find(|(value, _)| value.eq_ignore_ascii_case(v))
        .map_or("", |(_, label)| label)
}

fn strength_label(bits: f64) -> &'static str {
    if bits < 50.0 {
        "Weak"
    } else if bits < 70.0 {
        "Fair"
    } else if bits < 90.0 {
        "Strong"
    } else {
        "Very strong"
    }
}

pub(super) fn edit_entry(ctx: &mut Ctx<'_>) -> api::DetailInner {
    let Some(form) = ctx.c.entry_form(ctx.epoch) else {
        return api::DetailInner::Unreadable("Loading…".to_owned());
    };
    let types: Vec<api::TypeChoice> = ItemType::ALL
        .iter()
        .map(|t| convert::type_choice(*t))
        .collect();
    if form.start {
        ctx.ui.editor_pop = None;
        return api::DetailInner::EditEntry(Box::new(api::Editor::Start {
            guess: form.guess.as_ref().map(|g| {
                (
                    convert::type_choice(g.kind),
                    Z::from(g.line.clone()),
                    Z::from(g.sub.clone()),
                )
            }),
            types,
        }));
    }
    // Another entry's draft gets a fresh editor (its popover closes).
    if ctx.ui.editor_form.as_deref() != Some(form.id.as_str()) {
        ctx.ui.editor_pop = None;
        ctx.ui.editor_form = Some(form.id.clone());
    }
    api::DetailInner::EditEntry(Box::new(api::Editor::Form(Box::new(form_view(
        ctx, &form, types,
    )))))
}

fn form_view(ctx: &mut Ctx<'_>, form: &EntryFormView, types: Vec<api::TypeChoice>) -> api::Form {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let kind = form.kind.unwrap_or(ItemType::Other);
    let is_note = form.kind == Some(ItemType::Note);
    let hue = convert::item_hue(form.colour, &form.id);
    let group = c
        .read(epoch, |s| {
            // The group's own color, as the sidebar shows it (plan 0072).
            let (name, colour) = crate::views::group_chip(s, form.group)?;
            Ok::<_, qv_core::CoreError>((
                Z::from(name),
                convert::item_hue(colour, &form.group.id_hex()).to_owned(),
            ))
        })
        .and_then(Result::ok);
    let placeholder_title = form
        .auto_title
        .as_ref()
        .map_or_else(|| Z::new(kind.placeholder()), |t| Z::from(t.0.clone()));
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
    let card = form.card.as_ref().map(items::card_face);
    let rows = form
        .rows
        .iter()
        .map(|row| {
            let reveal_key = RevealKey::Replacement(row.index);
            let shown = c
                .revealed(epoch, &reveal_key)
                .map(|v| Z::from(crate::views::z(&String::from_utf8_lossy(v.expose_secret()))))
                .filter(|z| !z.is_empty());
            let masked = match (
                row.role,
                form.card.as_ref().and_then(|c| c.info.last4.as_ref()),
            ) {
                (Role::CardNumber, Some(last4)) => format!("•••• {last4}"),
                _ => MASK.to_owned(),
            };
            let check = match (row.role, form.card.as_ref()) {
                (Role::CardNumber, Some(c)) => match c.info.valid {
                    Some(true) => Some((
                        format!("✓ {}", c.info.brand.unwrap_or("Valid")),
                        "ie-check ok".to_owned(),
                    )),
                    Some(false) => Some(("Check the number".to_owned(), "ie-check bad".to_owned())),
                    None => c.info.brand.map(|b| (b.to_owned(), "ie-check".to_owned())),
                },
                (Role::Expiry, Some(c)) => c.left.clone().map(|(t, ok)| {
                    (
                        t,
                        if ok { "ie-check ok" } else { "ie-check bad" }.to_owned(),
                    )
                }),
                _ => None,
            };
            api::FormRow {
                index: row.index,
                name: Z::from(row.name.clone()),
                kind: convert::field_kind(row.kind),
                protected: row.protected,
                value: row.value.clone().map(Z::from),
                replaced: row.replaced,
                generated: row.generated,
                filled: row.filled,
                too_large: row.too_large,
                stored: row.stored,
                role: role(row.role),
                shown,
                masked,
                check,
                placeholder: placeholder(row).to_owned(),
            }
        })
        .collect();
    let pop = ctx.ui.editor_pop;
    let generator = match pop {
        Some(EditorPop::Gen(_)) => c.generator_form(epoch).map(|g| {
            let value = c
                .generated(epoch)
                .map(|(v, _)| Z::from(crate::views::z(&String::from_utf8_lossy(v.expose_secret()))))
                .filter(|z| !z.is_empty());
            let words = g.mode == GenMode::Words;
            let (n, min, max) = if words {
                (g.words, 3, 12)
            } else {
                (g.length, 12, 64)
            };
            api::GenPopover {
                value,
                words,
                n,
                min,
                max,
                symbols: g.flags[3],
                bits: g
                    .bits
                    .map(|b| format!("{} · {b:.0} bits", strength_label(b))),
            }
        }),
        _ => None,
    };
    let group_choices = match pop {
        Some(EditorPop::Group) => Some(items::group_choices(ctx, "editor.group", form.group)),
        _ => None,
    };
    api::Form {
        id: form.id.clone(),
        new: form.new,
        kind: convert::item_type(kind),
        type_name: match form.kind {
            Some(t) => t.name().to_owned(),
            None => ItemType::Other.name().to_owned(),
        },
        icon: convert::kind_icon(kind.hint()),
        is_note,
        hue: hue.to_owned(),
        colour: form.colour,
        title: Z::from(form.title.clone()),
        placeholder: placeholder_title,
        auto_from: form
            .auto_title
            .as_ref()
            .filter(|_| form.title.is_empty())
            .map(|(_, from)| (*from).to_owned()),
        title_focus: form.new && form.title.is_empty() && form.auto_title.is_none(),
        group,
        rows,
        focus,
        removed: form.removed.clone().map(Z::from),
        new_kind: convert::field_kind(form.new_kind.0),
        notes: Z::from(form.notes.clone()),
        notes_too_large: form.notes_too_large,
        notes_open: !form.notes.is_empty() || is_note,
        notes_focus: !form.new && !is_note && form.notes.is_empty(),
        card,
        wifi: form.wifi.as_ref().map(|w| {
            (
                Z::from(w.name.clone()),
                security_label(&w.security).to_owned(),
            )
        }),
        ready: form.ready,
        showing: form.showing,
        pop,
        generator,
        group_choices,
        types,
        common: kind.common().iter().map(|s| (*s).to_owned()).collect(),
        add_kinds: ADD_KINDS
            .iter()
            .map(|k| (convert::field_kind(*k), kind_label(*k).to_owned()))
            .collect(),
        security: SECURITY_CHOICES
            .iter()
            .map(|(v, l)| ((*v).to_owned(), (*l).to_owned()))
            .collect(),
        kind_labels: [
            FieldKind::Text,
            FieldKind::Secret,
            FieldKind::Url,
            FieldKind::Email,
            FieldKind::Totp,
            FieldKind::Multiline,
            FieldKind::Date,
        ]
        .iter()
        .map(|k| (convert::field_kind(*k), kind_label(*k).to_owned()))
        .collect(),
    }
}

pub(super) fn edit_group(ctx: &mut Ctx<'_>) -> api::DetailInner {
    let Some(form) = ctx.c.group_form(ctx.epoch) else {
        return api::DetailInner::Unreadable("Loading…".to_owned());
    };
    api::DetailInner::EditGroup(api::GroupEditor {
        new: form.new,
        hue: convert::item_hue(form.colour, &form.id).to_owned(),
        name: Z::from(form.name.clone()),
        colour: form.colour,
    })
}
