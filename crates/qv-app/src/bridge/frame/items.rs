// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault items.
use super::super::refs::Target;
use super::{Ctx, convert};
use crate::controller::View;
use crate::page_read::{Lane, Rows, Spec};
use crate::views::{self, EntryView, RowCopy};
use crate::workspace::{CopyKey, Report, RevealKey, Screen, WsField};
use qv_core::{EntryHandle, FieldKind, GroupHandle, ItemHandle};
use qv_ui_api as api;
use qv_ui_api::{BarPop, Icon, Z};
use zeroize::Zeroizing;

fn row_copy(c: RowCopy) -> api::RowCopy {
    match c {
        RowCopy::None => api::RowCopy::None,
        RowCopy::Pair { user, secret } => api::RowCopy::Pair { user, secret },
        RowCopy::Secret => api::RowCopy::Secret,
        RowCopy::Menu => api::RowCopy::Menu,
    }
}

/// A bounded group picker.
pub(super) fn group_choices(
    ctx: &mut Ctx<'_>,
    slot: &'static str,
    current: GroupHandle,
) -> api::GroupChoices {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let root = c.read(epoch, |s| s.root()).and_then(Result::ok);
    let (_, read) = ctx.hooks.page(
        c,
        epoch,
        slot,
        Lane::Overlay,
        2,
        Spec::Groups {
            parent: root,
            query: Zeroizing::new(String::new()),
        },
    );
    let groups = match read
        .as_ref()
        .and_then(|r| r.page.as_deref())
        .map(|p| &p.rows)
    {
        Some(Rows::Groups(groups)) => groups.clone(),
        _ => Vec::new(),
    };
    let extra = if root != Some(current) && groups.iter().all(|g| g.handle != current) {
        c.read(epoch, |s| {
            s.group(current).map(|g| views::z(g.name.expose()))
        })
        .and_then(Result::ok)
        .map(|n| (ctx.refs.issue(Target::Group(current)), Z::from(n)))
    } else {
        None
    };
    api::GroupChoices {
        root: root.map(|r| ctx.refs.issue(Target::Group(r))),
        groups: groups
            .iter()
            .map(|g| {
                (
                    ctx.refs.issue(Target::Group(g.handle)),
                    Z::from(g.name.clone()),
                    convert::item_hue(g.colour, &g.handle.id_hex()).to_owned(),
                    g.handle == current,
                )
            })
            .collect(),
        extra,
        page: Ctx::page_nav(slot, read.as_ref()),
    }
}

/// An entry's copyable fields for a menu (no values). The row's context
/// menu marks fields only as protected or not; the copy menu by kind.
fn menu_fields(ctx: &mut Ctx<'_>, h: EntryHandle, card: bool, row: bool) -> Vec<api::MenuField> {
    let fields = ctx
        .c
        .read(ctx.epoch, |s| views::entry(s, h))
        .and_then(Result::ok)
        .map(|v| v.fields)
        .unwrap_or_default();
    // A code that cannot be made is not offered (plan 0073).
    let (c, epoch) = (ctx.c, ctx.epoch);
    fields
        .iter()
        .filter(|f| {
            f.kind != FieldKind::Totp || matches!(c.read(epoch, |s| s.totp(f.handle)), Some(Ok(_)))
        })
        .map(|f| {
            let code = f.kind == FieldKind::Totp;
            let icon = if code {
                Icon::Shield
            } else if row {
                if f.protected { Icon::Key } else { Icon::Copy }
            } else if card && f.name.as_str() == crate::editor::CARD_NUMBER {
                Icon::Card
            } else if card && f.name.as_str() == crate::editor::EXPIRES {
                Icon::Clock
            } else if card && f.protected {
                Icon::Shield
            } else if f.protected {
                Icon::Key
            } else if f.kind == FieldKind::Url {
                Icon::Globe
            } else if card {
                Icon::User
            } else {
                Icon::Copy
            };
            api::MenuField {
                field: ctx.refs.issue(Target::Field(f.handle)),
                name: Z::from(f.name.clone()),
                icon,
                code,
            }
        })
        .collect()
}

/// The list beside the detail.
pub(super) fn list_pane(
    ctx: &mut Ctx<'_>,
    view: &View,
    list: &Screen,
    screen: &Screen,
    conflicts: usize,
    top_groups: &[views::GroupRow],
) -> api::ListPane {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let busy = view.busy;
    let form = screen.is_form() || busy;
    let current = match screen {
        Screen::Entry(e)
        | Screen::History(e)
        | Screen::HistoryVersion(e, _)
        | Screen::Attachments(e) => Some(*e),
        _ => None,
    };
    let query = c
        .peek(epoch, |ws| {
            String::from_utf8_lossy(ws.input(WsField::Query)).into_owned()
        })
        .map(Zeroizing::new)
        .unwrap_or_default();
    let spec = Spec::Items {
        group: match list {
            Screen::Browse(Some(group)) => Some(*group),
            _ => None,
        },
        kind: match list {
            Screen::Kind(kind) => Some(kind.clone()),
            _ => None,
        },
        query: query.clone(),
        recovered: *list == Screen::Recovered,
        full_search: *list == Screen::Search,
    };
    let (_, page_read) = ctx.hooks.page(c, epoch, "list", Lane::Main, 1, spec);
    let page = page_read.as_ref().and_then(|r| r.page.clone());
    // While a held page shows, so does the list it belongs to (plan 0051).
    let stale = page_read.as_ref().is_some_and(|r| r.stale);
    let list = if stale {
        ctx.hooks.shown_list.clone().unwrap_or_else(|| list.clone())
    } else {
        ctx.hooks.shown_list = Some(list.clone());
        list.clone()
    };
    let (rows, groups) = match page.as_deref().map(|p| &p.rows) {
        Some(Rows::Items { items, groups }) => (
            items.iter().map(|i| i.row.clone()).collect::<Vec<_>>(),
            groups.clone(),
        ),
        _ => (Vec::new(), Vec::new()),
    };
    let mut group_view = ctx
        .hooks
        .last(
            "list.header",
            match &list {
                Screen::Browse(Some(group)) => {
                    c.read(epoch, |s| views::browse_header(s, Some(*group)))
                }
                _ => None,
            },
        )
        .and_then(Result::ok)
        .filter(|_| matches!(list, Screen::Browse(Some(_))));
    if let Some(v) = &mut group_view {
        v.groups = groups;
    }
    let title = match &list {
        Screen::Browse(Some(_)) => group_view
            .as_ref()
            .and_then(|v| v.crumbs.last())
            .map(|(_, n)| n.to_string())
            .unwrap_or_default(),
        Screen::Kind(kind) => convert::kind_label(kind),
        Screen::Recovered => "Recovered items".to_owned(),
        Screen::Search => "Search".to_owned(),
        _ => "All items".to_owned(),
    };
    let root = c.read(epoch, |s| s.root()).and_then(Result::ok);
    let new_in = match &list {
        Screen::Browse(Some(g)) => Some(*g),
        _ => root,
    };
    let mut sections: Vec<api::Section> = Vec::new();
    for row in &rows {
        let letter = convert::initial(&row.title);
        let id = row.handle.id_hex();
        let r = api::Row {
            id: ctx.refs.issue(Target::Entry(row.handle)),
            hue: convert::item_hue(row.colour, &id).to_owned(),
            rid: id,
            title: Z::from(row.title.clone()),
            sub: if row.subtitle.is_empty() {
                Z::new(convert::type_name(row.kind))
            } else {
                Z::from(row.subtitle.clone())
            },
            glyph: convert::entry_glyph(row.kind, &row.title),
            conflict: row.conflict,
            copy: row_copy(row.copy),
            card: row.kind == "card",
            colour: row.colour,
        };
        match sections.last_mut() {
            Some(s) if s.letter == letter => s.rows.push(r),
            _ => sections.push(api::Section {
                letter,
                rows: vec![r],
            }),
        }
    }
    let count: usize = sections.iter().map(|s| s.rows.len()).sum();
    let group = match &list {
        Screen::Browse(Some(g)) => Some(*g),
        _ => None,
    };
    let order: Vec<(String, qv_ui_api::Ref)> = sections
        .iter()
        .flat_map(|s| s.rows.iter().map(|r| (r.rid.clone(), r.id)))
        .collect();
    let selection = c.selection(epoch);
    let chosen: Vec<String> = selection
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|id| order.iter().any(|(o, _)| o == id))
        .collect();
    let in_selection = selection.is_some() && !form;
    let chips = matches!(list, Screen::Browse(_)).then(|| {
        let inside: Vec<GroupHandle> = group_view
            .as_ref()
            .map(|v| v.crumbs.iter().map(|c| c.0).collect())
            .unwrap_or_default();
        let chips = top_groups
            .iter()
            .filter_map(|g| {
                let on = inside.contains(&g.handle);
                let to = if on {
                    Screen::Browse(None)
                } else {
                    Screen::Browse(Some(g.handle))
                };
                Some(api::Chip {
                    target: convert::screen(ctx.refs, &to)?,
                    name: Z::from(g.name.clone()),
                    hue: convert::item_hue(g.colour, &g.handle.id_hex()).to_owned(),
                    on,
                })
            })
            .collect();
        (chips, root.map(|r| ctx.refs.issue(Target::Group(r))))
    });
    let subgroups = group_view
        .as_ref()
        .map(|v| v.groups.clone())
        .unwrap_or_default()
        .iter()
        .filter_map(|g| {
            Some(api::Chip {
                target: convert::screen(ctx.refs, &Screen::Browse(Some(g.handle)))?,
                name: Z::from(g.name.clone()),
                hue: String::new(),
                on: false,
            })
        })
        .collect();
    let empty_text = if page.is_none() {
        "Loading items…"
    } else if query.is_empty() && list != Screen::Search {
        "Nothing here yet. Create an item with the + button."
    } else {
        "No items match."
    };
    let empty_icon = if query.is_empty() {
        Icon::Key
    } else {
        Icon::Search
    };
    let recovered = if list == Screen::Browse(None) {
        ctx.hooks
            .last(
                "list.recovered",
                c.read(epoch, |s| s.overview().map(|o| o.recovered)),
            )
            .and_then(Result::ok)
            .unwrap_or(0)
    } else {
        0
    };
    let bar_pop = ctx.ui.bar_pop.filter(|_| in_selection);
    let move_choices = match (bar_pop, group.or(new_in)) {
        (Some(BarPop::Move), Some(at)) => Some(group_choices(ctx, "list.move", at)),
        _ => None,
    };
    let find = |rid: &str| rows.iter().find(|r| r.handle.id_hex() == rid).cloned();
    let copy_menu = match ctx
        .ui
        .copy_menu
        .clone()
        .and_then(|rid| find(&rid).map(|r| (rid, r)))
    {
        Some((rid, r)) if !in_selection => {
            let fields = menu_fields(ctx, r.handle, r.kind == "card", false);
            Some((rid, fields))
        }
        _ => None,
    };
    let row_menu = match ctx
        .ui
        .row_menu
        .clone()
        .and_then(|rid| find(&rid).map(|r| (rid, r)))
    {
        Some((rid, r)) if !in_selection && !form => {
            // Its own copy buttons cover the rest; a code is always listed.
            let mut fields = menu_fields(ctx, r.handle, false, true);
            if r.copy != RowCopy::Menu {
                fields.retain(|f| f.code);
            }
            Some((rid, fields))
        }
        _ => None,
    };
    let filter = if list == Screen::Search {
        "Search the vault".to_owned()
    } else {
        format!("Filter {}", title.to_lowercase())
    };
    let placeholder = if list == Screen::Search {
        "Search titles, usernames, websites".to_owned()
    } else {
        format!("Filter {}", title.to_lowercase())
    };
    let vault = c
        .open_vault()
        .map(|v| convert::vault_choice(ctx.refs, &v, true, false));
    api::ListPane {
        kind: match &list {
            Screen::Browse(Some(_)) => api::ListKind::Group,
            Screen::Kind(_) => api::ListKind::Kind,
            Screen::Recovered => api::ListKind::Recovered,
            Screen::Search => api::ListKind::Search,
            _ => api::ListKind::All,
        },
        title: Z::from(title),
        count,
        stale,
        loaded: page.is_some(),
        group: group.map(|g| ctx.refs.issue(Target::Group(g))),
        form,
        in_selection,
        chosen,
        order,
        current: current.map(|e| ctx.refs.issue(Target::Entry(e))),
        query: Z::from(query),
        filter,
        placeholder,
        autofocus: list == Screen::Search,
        page: Ctx::page_nav("list", page_read.as_ref()),
        chips,
        subgroups,
        conflicts,
        sections,
        empty: (empty_text.to_owned(), empty_icon),
        vault,
        recovered,
        new_in: new_in.map(|g| ctx.refs.issue(Target::Group(g))),
        group_menu: ctx.ui.group_menu && group.is_some(),
        bar_pop,
        move_choices,
        copy_menu,
        row_menu,
    }
}

/// The detail pane.
pub(super) fn detail(
    ctx: &mut Ctx<'_>,
    view: &View,
    screen: &Screen,
    report: Option<Report>,
) -> api::Detail {
    let inner = match screen.clone() {
        Screen::Entry(e) => entry_screen(ctx, view, e),
        Screen::EditEntry => super::editor::edit_entry(ctx),
        Screen::EditGroup => super::editor::edit_group(ctx),
        Screen::Move(item, at) => move_screen(ctx, item, at),
        Screen::History(e) => history(ctx, e),
        Screen::HistoryVersion(e, v) => history_version(ctx, view, e, &v),
        Screen::Attachments(e) => attachments(ctx, e),
        _ => api::DetailInner::Empty,
    };
    if !matches!(screen, Screen::EditEntry) {
        ctx.ui.editor_pop = None;
        ctx.ui.editor_form = None;
    }
    api::Detail {
        closed: screen.is_list(),
        report: report.as_ref().map(super::shell::report),
        inner,
    }
}

fn unreadable(error: Option<crate::controller::AppError>) -> api::DetailInner {
    api::DetailInner::Unreadable(
        error
            .map_or("Loading…", crate::controller::AppError::message)
            .to_owned(),
    )
}

/// One entry's fields and notes.
fn entry_body(
    ctx: &mut Ctx<'_>,
    view: &View,
    v: &EntryView,
    history: Option<&str>,
) -> api::EntryBody {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let current = history.is_none();
    let group = v.group.and_then(|g| {
        c.read(epoch, |s| views::browse_header(s, Some(g)))
            .and_then(Result::ok)
            .and_then(|b| {
                (!b.root)
                    .then(|| b.crumbs.last().map(|c| c.1.to_string()))
                    .flatten()
            })
    });
    let url = v
        .fields
        .iter()
        .find(|f| f.kind == FieldKind::Url)
        .and_then(|f| f.value.clone());
    let kind = Zeroizing::new(v.type_hint.to_lowercase());
    let group_hue = v.group.map(|h| {
        let colour = c
            .read(epoch, |s| s.group(h))
            .and_then(Result::ok)
            .and_then(|g| crate::editor::colour(g.icon.as_ref().map(qv_core::Text::expose)));
        convert::item_hue(colour, &h.id_hex())
    });
    let card = if current {
        c.read(epoch, |s| Ok(views::card_face(s, v)))
            .and_then(Result::ok)
            .flatten()
            .map(|cf| card_face(&cf))
    } else {
        None
    };
    let wifi = current
        && v.versions == 1
        && crate::editor::ItemType::from_hint(&v.type_hint) == Some(crate::editor::ItemType::Wifi)
        && v.fields
            .iter()
            .any(|f| crate::editor::same_slot(&f.name, crate::editor::NETWORK));
    let wifi = wifi.then(|| {
        c.revealed(epoch, &RevealKey::WifiJoin(v.handle))
            .and_then(|p| crate::qr::encode(p.expose_secret()).ok())
            .map(|s| qr(&s))
    });
    let fields = v
        .fields
        .iter()
        .map(|f| {
            let reveal = match history {
                Some(ver) => RevealKey::History(ver.to_owned(), f.id),
                None => RevealKey::Field(f.handle),
            };
            let totp = f.kind == FieldKind::Totp;
            let copy = (current && v.versions == 1).then_some(if totp {
                CopyKey::Totp(v.handle, f.handle)
            } else {
                CopyKey::Field(v.handle, f.handle)
            });
            let code_key = RevealKey::Totp(f.handle);
            // An open entry's code shows without a reveal; the stored URI
            // never leaves Rust (0008 §4.3, plan 0073).
            let code = (totp && current && history.is_none())
                .then(|| c.read(epoch, |s| s.totp(f.handle)).and_then(Result::ok))
                .flatten()
                .map(|now| {
                    convert::code(&views::CodeNow {
                        code: zeroize::Zeroizing::new(now.code.expose_secret().to_owned()),
                        left: now.seconds_remaining,
                        period: now.period,
                    })
                });
            api::FieldLine {
                name: Z::from(f.name.clone()),
                kind_name: views::kind_name(f.kind).to_owned(),
                totp,
                value: f.value.clone().map(Z::from),
                protected: f.protected,
                shown: convert::shown(c.revealed(epoch, &reveal)),
                code,
                reveal: convert::reveal(ctx.refs, &reveal),
                code_key: totp.then(|| convert::reveal(ctx.refs, &code_key)),
                copy: copy.map(|k| convert::copy(ctx.refs, &k)),
            }
        })
        .collect();
    let _ = view;
    api::EntryBody {
        entry: ctx.refs.issue(Target::Entry(v.handle)),
        current,
        title: Z::from(v.title.clone()),
        tile: convert::item_hue(v.colour, &v.handle.id_hex()).to_owned(),
        glyph: convert::entry_glyph(&kind, &v.title),
        url: url.map(Z::from),
        type_hint: Z::from(v.type_hint.clone()),
        kind_icon: convert::kind_icon(&kind),
        group: group
            .zip(group_hue)
            .map(|(g, h)| (Z::from(views::z(&g)), h.to_owned())),
        versions: v.versions,
        record: v.handle.id_hex(),
        expires: v.expires.clone(),
        card,
        wifi,
        fields,
        notes: v.notes.clone().map(Z::from),
    }
}

/// A card's face, never its number.
pub(super) fn card_face(c: &views::CardFace) -> api::CardFace {
    api::CardFace {
        brand: c.info.brand.unwrap_or("").to_owned(),
        number: format!(
            "•••• •••• •••• {}",
            c.info.last4.as_deref().unwrap_or("••••")
        ),
        name: Z::from(c.name.clone()),
        expiry: Z::from(c.expiry.clone()),
    }
}

pub(super) fn qr(symbol: &crate::qr::Symbol) -> api::Qr {
    api::Qr {
        side: symbol.size() + 8,
        path: Z::from(symbol.path()),
    }
}

fn entry_screen(ctx: &mut Ctx<'_>, view: &View, entry: EntryHandle) -> api::DetailInner {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let read = ctx.hooks.last(
        "entry",
        c.read(epoch, |s| {
            Ok((views::entry(s, entry)?, views::attachments(s, entry)?))
        }),
    );
    let (v, files) = match read {
        Some(Ok((v, f))) if v.handle == entry => (v, f),
        Some(Ok(_)) => return unreadable(None),
        other => return unreadable(other.and_then(Result::err)),
    };
    let editable = !v.deleted && v.versions == 1;
    let body = entry_body(ctx, view, &v, None);
    api::DetailInner::Entry(Box::new(api::EntryScreen {
        entry: ctx.refs.issue(Target::Entry(entry)),
        editable,
        deleted: v.deleted,
        attachments: v.attachments,
        body,
        files: files
            .iter()
            .map(|a| api::FileTile {
                id: ctx.refs.issue(Target::Attachment(a.handle)),
                name: Z::from(a.name.clone()),
                tone: convert::file_tone(&a.name, &a.mime).to_owned(),
                icon: convert::file_icon(&a.name, &a.mime),
                conflicted: a.conflicted,
                size: views::human_size(a.size),
            })
            .collect(),
        modified: v.modified.clone(),
        created: v.created.clone(),
    }))
}

fn move_screen(ctx: &mut Ctx<'_>, item: ItemHandle, at: Option<GroupHandle>) -> api::DetailInner {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let mut v = match c.read(epoch, |s| views::browse_header(s, at)) {
        Some(Ok(v)) => v,
        other => return unreadable(other.and_then(Result::err)),
    };
    let (_, read) = ctx.hooks.page(
        c,
        epoch,
        "move",
        Lane::Overlay,
        2,
        Spec::Groups {
            parent: Some(v.here),
            query: Zeroizing::new(String::new()),
        },
    );
    if let Some(Rows::Groups(groups)) = read
        .as_ref()
        .and_then(|r| r.page.as_deref())
        .map(|p| &p.rows)
    {
        v.groups = groups.clone();
    }
    let empty = v
        .groups
        .iter()
        .all(|g| ItemHandle::Group(g.handle) == item)
        .then(|| {
            if v.root {
                Z::new("No groups yet. Move here keeps it in All items.")
            } else if let Some((_, name)) = v.crumbs.last() {
                Z::from(format!(
                    "“{}” has no subgroups. Move here puts it in “{}”.",
                    name.as_str(),
                    name.as_str()
                ))
            } else {
                Z::new("No subgroups here.")
            }
        });
    api::DetailInner::Move(api::MoveScreen {
        item: convert::item(ctx.refs, item),
        crumbs: v
            .crumbs
            .iter()
            .map(|(g, n)| (ctx.refs.issue(Target::Group(*g)), Z::from(n.clone())))
            .collect(),
        empty,
        groups: v
            .groups
            .iter()
            .filter(|g| ItemHandle::Group(g.handle) != item)
            .map(|g| {
                (
                    ctx.refs.issue(Target::Group(g.handle)),
                    Z::from(g.name.clone()),
                )
            })
            .collect(),
        here: ctx.refs.issue(Target::Group(v.here)),
        page: Ctx::page_nav("move", read.as_ref()),
    })
}

fn history(ctx: &mut Ctx<'_>, entry: EntryHandle) -> api::DetailInner {
    let rows = match ctx.c.read(ctx.epoch, |s| views::history(s, entry)) {
        Some(Ok(v)) => v,
        other => return unreadable(other.and_then(Result::err)),
    };
    api::DetailInner::History(api::HistoryScreen {
        entry: ctx.refs.issue(Target::Entry(entry)),
        rows: rows
            .iter()
            .map(|r| api::HistoryRow {
                version: r.version.clone(),
                modified: r.modified.clone(),
                changed: Z::from(
                    r.changed
                        .iter()
                        .map(|c| c.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
                conflict: r.conflict,
            })
            .collect(),
    })
}

fn history_version(
    ctx: &mut Ctx<'_>,
    view: &View,
    entry: EntryHandle,
    version: &str,
) -> api::DetailInner {
    let c = ctx.c;
    let epoch = ctx.epoch;
    let v = match c.read(epoch, |s| views::history_version(s, entry, version)) {
        Some(Ok(v)) => v,
        other => return unreadable(other.and_then(Result::err)),
    };
    let conflicted = c
        .read(epoch, |s| Ok(s.entry_version_count(entry)? > 1))
        .and_then(Result::ok)
        .unwrap_or(false);
    let body = entry_body(ctx, view, &v, Some(version));
    api::DetailInner::Version(Box::new(api::VersionScreen {
        entry: ctx.refs.issue(Target::Entry(entry)),
        version: version.to_owned(),
        body,
        conflicted,
    }))
}

/// How files are chosen on this platform.
pub(super) fn picker() -> api::Picker {
    #[cfg(target_os = "android")]
    {
        api::Picker::Android(crate::android::picked_name().map(|n| Z::from(views::z(&n))))
    }
    #[cfg(not(target_os = "android"))]
    {
        if crate::documents::picker_missing() {
            api::Picker::Typed
        } else {
            api::Picker::Portal
        }
    }
}

fn attachments(ctx: &mut Ctx<'_>, entry: EntryHandle) -> api::DetailInner {
    let rows = match ctx.c.read(ctx.epoch, |s| views::attachments(s, entry)) {
        Some(Ok(v)) => v,
        other => return unreadable(other.and_then(Result::err)),
    };
    api::DetailInner::Attachments(api::AttachmentsScreen {
        entry: ctx.refs.issue(Target::Entry(entry)),
        rows: rows
            .iter()
            .map(|a| api::Attachment {
                id: ctx.refs.issue(Target::Attachment(a.handle)),
                name: Z::from(a.name.clone()),
                mime: Z::from(a.mime.clone()),
                size: a.size,
                conflicted: a.conflicted,
            })
            .collect(),
        picker: picker(),
    })
}

/// The open preview.
pub(super) fn viewer(ctx: &mut Ctx<'_>) -> Option<Box<api::Viewer>> {
    use crate::preview::Kind;
    let p = ctx.c.peek(ctx.epoch, |ws| ws.preview.clone()).flatten()?;
    let (kind, kind_name) = match p.kind {
        Kind::Image => ("image", "Image"),
        Kind::Audio => ("audio", "Audio"),
        Kind::Video => ("video", "Video"),
        Kind::Text => ("text", "Text"),
        Kind::Unsupported => ("file", "File"),
    };
    #[cfg(any(target_os = "linux", windows))]
    let direct = !crate::documents::picker_missing();
    #[cfg(not(any(target_os = "linux", windows)))]
    let direct = false;
    Some(Box::new(api::Viewer {
        key: p.handle.version_hex(),
        id: ctx.refs.issue(Target::Attachment(p.handle)),
        entry: ctx.refs.issue(Target::Entry(p.entry)),
        name: Z::from(p.name.clone()),
        kind: kind.to_owned(),
        kind_name: kind_name.to_owned(),
        mime: p.mime.to_owned(),
        size: p.size,
        size_label: views::human_size(p.size),
        src: p.src.clone().map(Z::from),
        lines: p.text.as_ref().map_or(0, |t| t.lines().count()),
        text: p.text.clone().map(Z::from),
        cut: p.cut,
        image_load: p.image_load.map(|i| i.description()),
        index: p.index,
        count: p.count,
        tone: convert::file_tone(&p.name, p.mime).to_owned(),
        icon: convert::file_icon(&p.name, p.mime),
        direct_save: direct,
    }))
}
