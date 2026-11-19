// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault items: the list beside the detail, the
//! entry card (click a field to copy, 30 s reveals), move, history,
//! attachments and the full-window viewer. Protected values appear only
//! through a reveal; forms never prefill them.
use crate::icons::{Icon, Svg, glyph, svg};
use crate::input::{Input, Kind};
use crate::shell::{PageNavBar, act, field, go, report_card, unreadable};
use crate::{editor, ui};
use leptos::prelude::*;
use qv_ui_api::{
    Act, BarPop, CopyKey, DetailInner, EntryBody as Body, FieldLine as F, ItemRef, ListKind,
    MenuField, Picker, RowCopy, Screen, Shell as S, UiOp, WsAct, WsField,
};
use std::collections::BTreeSet;

/// The largest image the viewer reads into renderer memory (0003 §6.4).
const IMAGE_MAX: u64 = 64 * 1024 * 1024;

const MASK: &str = "••••••••";

fn ui_op(op: UiOp) {
    ui().act(Act::Ui(op));
}

/// The list beside a vault detail.
#[component]
pub(crate) fn ListPane(s: Memo<Option<S>>) -> impl IntoView {
    let l = field(s, None, |s| match &s.content {
        qv_ui_api::Content::Vault { list, .. } => Some((**list).clone()),
        _ => None,
    });
    let lf = move |f: fn(&qv_ui_api::ListPane) -> String| {
        Memo::new(move |_| l.with(|l| l.as_ref().map(f).unwrap_or_default()))
    };
    let get = move || l.get();
    let title = lf(|l| l.title.to_string());
    let filter = lf(|l| l.filter.clone());
    let placeholder = lf(|l| l.placeholder.clone());
    let query = lf(|l| l.query.to_string());
    let form = Memo::new(move |_| l.with(|l| l.as_ref().is_some_and(|l| l.form)));
    let in_selection = Memo::new(move |_| l.with(|l| l.as_ref().is_some_and(|l| l.in_selection)));
    let stale = Memo::new(move |_| l.with(|l| l.as_ref().is_some_and(|l| l.stale)));
    let chosen =
        Memo::new(move |_| l.with(|l| l.as_ref().map(|l| l.chosen.clone()).unwrap_or_default()));
    let current = Memo::new(move |_| l.with(|l| l.as_ref().and_then(|l| l.current)));
    let sections =
        Memo::new(move |_| l.with(|l| l.as_ref().map(|l| l.sections.clone()).unwrap_or_default()));
    let row_menu = Memo::new(move |_| l.with(|l| l.as_ref().and_then(|l| l.row_menu.clone())));
    let copy_menu = Memo::new(move |_| l.with(|l| l.as_ref().and_then(|l| l.copy_menu.clone())));
    let autofocus = Memo::new(move |_| l.with(|l| l.as_ref().is_some_and(|l| l.autofocus)));
    // Plan 0044: the selection anchor for Shift-click ranges.
    let anchor = RwSignal::new(None::<String>);
    let order =
        move || l.with_untracked(|l| l.as_ref().map(|l| l.order.clone()).unwrap_or_default());
    let set_selection = move |set: Option<BTreeSet<String>>| {
        ui().act(Act::Selection(set.map(|s| s.into_iter().collect())))
    };
    let selecting = move || l.with_untracked(|l| l.as_ref().is_some_and(|l| l.in_selection));
    let click = move |rid: String, id: qv_ui_api::Ref| {
        move |e: web_sys::MouseEvent| {
            let from = anchor.get_untracked();
            let current =
                selecting().then(|| chosen.get_untracked().into_iter().collect::<BTreeSet<_>>());
            if e.shift_key() && (current.is_some() || from.is_some()) {
                let mut set = current.unwrap_or_default();
                let order = order();
                let at = |x: &str| order.iter().position(|(i, _)| i == x);
                if let (Some(a), Some(b)) = (from.as_deref().and_then(at), at(&rid)) {
                    for (i, _) in &order[a.min(b)..=a.max(b)] {
                        set.insert(i.clone());
                    }
                } else {
                    set.insert(rid.clone());
                }
                set_selection(Some(set));
            } else if current.is_some() || e.ctrl_key() || e.meta_key() {
                let mut set = current.clone().unwrap_or_default();
                if !set.remove(&rid) {
                    set.insert(rid.clone());
                }
                anchor.set(Some(rid.clone()));
                // Ctrl-clicking the last one off ends a Ctrl-started selection.
                let keep = !set.is_empty() || current.is_some() && !(e.ctrl_key() || e.meta_key());
                set_selection(keep.then_some(set));
            } else {
                anchor.set(Some(rid.clone()));
                ui().act(Act::Select(Screen::Entry(id)));
            }
        }
    };
    // Escape closes the row menu or a bar popover here; ending the
    // selection is the root shortcut's job.
    let keys = move |e: web_sys::KeyboardEvent| {
        let ctrl = e.ctrl_key() || e.meta_key();
        let menus = l.with_untracked(|l| {
            l.as_ref()
                .is_some_and(|l| l.row_menu.is_some() || l.bar_pop.is_some())
        });
        if e.key() == "Escape" && menus {
            e.stop_propagation();
            e.prevent_default();
            if row_menu.get_untracked().is_some() {
                ui_op(UiOp::RowMenu(None));
            } else {
                ui_op(UiOp::BarPop(None));
            }
        } else if selecting() && ctrl && (e.key() == "a" || e.key() == "A") {
            e.stop_propagation();
            e.prevent_default();
            set_selection(Some(order().into_iter().map(|(i, _)| i).collect()));
        }
    };
    let start_selecting = move |_| {
        ui_op(UiOp::RowMenu(None));
        set_selection(Some(BTreeSet::new()));
    };
    let quick = move |id: qv_ui_api::Ref, secret: bool| {
        move |e: web_sys::MouseEvent| {
            e.stop_propagation();
            ui().act(Act::QuickCopy(id, secret));
        }
    };
    let group_actions = move |g: qv_ui_api::Ref, button_id: &'static str| {
        let open = Memo::new(move |_| l.with(|l| l.as_ref().is_some_and(|l| l.group_menu)));
        let close_then = move |a: Act| {
            move |_| {
                ui_op(UiOp::GroupMenu(false));
                ui().act(a.clone());
            }
        };
        view! {
            <div class="pop-anchor">
                <button class="icon-btn" id=button_id aria-label="Group actions" title="Group actions" disabled=move || form.get()
                    on:click=move |_| ui_op(UiOp::GroupMenu(!open.get_untracked()))>
                    <Svg icon=Icon::More large=true/>
                </button>
                <Show when=move || open.get()>
                    <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| ui_op(UiOp::GroupMenu(false))></button>
                    <div class="menu pop end" role="menu">
                        <button class="mi" on:click=close_then(Act::Ws(WsAct::NewGroup(g)))><Svg icon=Icon::Folder/>"New subgroup"</button>
                        <button class="mi" on:click=close_then(Act::Ws(WsAct::RenameGroup(g)))><Svg icon=Icon::Edit/>"Rename group"</button>
                        <button class="mi" id=format!("{button_id}-colour") on:click=close_then(Act::Ws(WsAct::RenameGroup(g)))><Svg icon=Icon::Palette/>"Change color"</button>
                        <button class="mi" on:click=close_then(Act::Go(Screen::Move(ItemRef::Group(g), None)))><Svg icon=Icon::Move/>"Move group"</button>
                        <hr/>
                        <button class="mi danger" on:click=close_then(Act::Ws(WsAct::Delete(ItemRef::Group(g))))><Svg icon=Icon::Trash/>"Delete group"</button>
                    </div>
                </Show>
            </div>
        }
    };
    let selbar = move || {
        let order = order();
        let picked: Vec<qv_ui_api::Ref> = order
            .iter()
            .filter(|(id, _)| chosen.get().contains(id))
            .map(|(_, r)| *r)
            .collect();
        let all_ids: BTreeSet<String> = order.iter().map(|(i, _)| i.clone()).collect();
        let all_on = !all_ids.is_empty() && picked.len() == all_ids.len();
        let n = picked.len();
        let none = n == 0;
        let bar_pop = l.with(|l| l.as_ref().and_then(|l| l.bar_pop));
        let leave = move || {
            ui_op(UiOp::BarPop(None));
            set_selection(None);
        };
        let p1 = picked.clone();
        let p2 = picked.clone();
        let p3 = picked.clone();
        let colour = move |h: Option<u8>| {
            let p = p2.clone();
            move |_| {
                ui().act(Act::Ws(WsAct::ColourMany(p.clone(), h)));
                leave();
            }
        };
        let choices = l.with(|l| l.as_ref().and_then(|l| l.move_choices.clone()));
        view! {
            <div class="selbar" role="toolbar" aria-label="Selection">
                <button class="icon-btn" id="sel-exit" aria-label="Leave selection" title="Leave selection (Esc)" on:click=move |_| leave()><Svg icon=Icon::Close/></button>
                <b class="sel-n">{if none { "Select items".to_owned() } else { format!("{n} selected") }}</b>
                <button class=if all_on { "icon-btn on" } else { "icon-btn" } id="sel-all"
                    title=if all_on { "Clear the selection" } else { "Select this page (Ctrl A)" }
                    aria-label=if all_on { "Clear the selection" } else { "Select this page" }
                    on:click=move |_| set_selection(Some(if all_on { BTreeSet::new() } else { all_ids.clone() }))>
                    <Svg icon=Icon::All/>
                </button>
                <div class="pop-anchor">
                    <button class="icon-btn" id="sel-colour" aria-label="Color" title="Color" disabled=none
                        on:click=move |_| ui_op(UiOp::BarPop(if bar_pop == Some(BarPop::Colour) { None } else { Some(BarPop::Colour) }))>
                        <Svg icon=Icon::Palette/>
                    </button>
                    {(bar_pop == Some(BarPop::Colour)).then(|| view! {
                        <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| ui_op(UiOp::BarPop(None))></button>
                        <div class="menu pop end" role="menu" aria-label="Color">
                            <div class="label">"COLOR"</div>
                            <div class="ie-swatches">
                                {(0..12u8).map(|h| view! { <button class=editor::hue_class(h) id=format!("sel-colour-{h}") aria-label=format!("Color {}", h + 1) on:click=colour(Some(h))></button> }).collect_view()}
                            </div>
                            <hr/>
                            <button class="mi" id="sel-colour-auto" on:click=colour(None)><Svg icon=Icon::Refresh/>"Automatic"</button>
                        </div>
                    })}
                </div>
                <div class="pop-anchor">
                    <button class="icon-btn" id="sel-move" aria-label="Move" title="Move to a group" disabled=none
                        on:click=move |_| ui_op(UiOp::BarPop(if bar_pop == Some(BarPop::Move) { None } else { Some(BarPop::Move) }))>
                        <Svg icon=Icon::Move/>
                    </button>
                    {(bar_pop == Some(BarPop::Move)).then(|| view! {
                        <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| ui_op(UiOp::BarPop(None))></button>
                        <div class="menu pop end" role="menu">
                            <div class="label">"MOVE TO"</div>
                            {choices.map(|c| editor::group_choices(c, move |g| { ui().act(Act::Ws(WsAct::MoveMany(p3.clone(), g))); leave(); }))}
                        </div>
                    })}
                </div>
                <button class="icon-btn danger" id="sel-trash" aria-label="Move to the trash" title="Move to the trash" disabled=none
                    on:click=move |_| { ui().act(Act::Ws(WsAct::TrashMany(p1.clone()))); leave(); }><Svg icon=Icon::Trash/></button>
            </div>
        }
    };
    let menu_buttons = move |id: qv_ui_api::Ref, fields: Vec<MenuField>, close: UiOp| {
        fields
            .into_iter()
            .map(|f| {
                let close = close.clone();
                view! {
                    <button class="mi" role="menuitem" on:click=move |e: web_sys::MouseEvent| {
                        e.stop_propagation();
                        ui_op(close.clone());
                        ui().act(Act::Ws(WsAct::Copy(CopyKey::Field(id, f.field))));
                    }>
                        <Svg icon=f.icon/>{format!("Copy “{}”", f.name.as_str())}
                    </button>
                }
            })
            .collect_view()
    };
    let row_view = move |row: qv_ui_api::Row| {
        let rid = row.rid.clone();
        let id = row.id;
        let rid_on = rid.clone();
        let rid_menu = rid.clone();
        let rid_copy = rid.clone();
        let on = Memo::new(move |_| chosen.get().contains(&rid_on));
        let menu_open = Memo::new(move |_| row_menu.get().is_some_and(|(r, _)| r == rid_menu));
        let copy_open = Memo::new(move |_| copy_menu.get().is_some_and(|(r, _)| r == rid_copy));
        let class = move || match (
            in_selection.get() && on.get(),
            current.get() == Some(id) && !in_selection.get(),
        ) {
            (true, _) => "row sel",
            (false, true) => "row on",
            _ => "row",
        };
        let title = row.title.to_string();
        let label_title = title.clone();
        let rid_ctx = rid.clone();
        let rid_click = rid.clone();
        let rid_select = rid.clone();
        let copy = row.copy;
        let card = row.card;
        let colour = row.colour;
        let hue = row.hue.clone();
        let g = row.glyph.clone();
        view! {
            <div class=class
                on:contextmenu=move |e: web_sys::MouseEvent| { e.prevent_default(); if !form.get_untracked() && !in_selection.get_untracked() { ui_op(UiOp::RowMenu(Some(rid_ctx.clone()))); } }>
                <button class="open item-open"
                    aria-label=move || if in_selection.get() { format!("Select {label_title}") } else { format!("Open {label_title}") }
                    aria-pressed=move || if in_selection.get() { if on.get() { "true" } else { "false" } } else { "" }
                    disabled=move || form.get() on:click=click(rid_click.clone(), id)></button>
                {move || if in_selection.get() {
                    view! { <i class=move || if on.get() { "tile tick on" } else { "tile tick" }><Svg icon=Icon::Check large=true/></i> }.into_any()
                } else {
                    view! { <span class=format!("tile {hue}")>{glyph(&g)}</span> }.into_any()
                }}
                <span class="t"><b class="row-title">{title.clone()}</b><span>{row.sub.to_string()}</span></span>
                {row.conflict.then(|| view! { <span class="cbadge">"conflict"</span> })}
                <Show when=move || !in_selection.get()>
                    {match copy {
                        RowCopy::None => ().into_any(),
                        RowCopy::Menu => {
                            let rid = rid.clone();
                            view! {
                                <span class=move || if copy_open.get() { "quick open" } else { "quick" }>
                                    <button aria-label=if card { "Copy a card detail" } else { "Copy a field" } title="Copy…" aria-haspopup="menu"
                                        aria-expanded=move || if copy_open.get() { "true" } else { "false" } disabled=move || form.get()
                                        on:click={ let rid = rid.clone(); move |e: web_sys::MouseEvent| { e.stop_propagation(); ui_op(UiOp::CopyMenu(if copy_open.get_untracked() { None } else { Some(rid.clone()) })); } }>
                                        <Svg icon=Icon::Copy/>
                                    </button>
                                </span>
                                {move || copy_open.get().then(|| {
                                    let fields = copy_menu.get().map(|(_, f)| f).unwrap_or_default();
                                    view! {
                                        <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); ui_op(UiOp::CopyMenu(None)); }></button>
                                        <div class="card-menu">
                                            <div class="menu pop end" role="menu" aria-label="Copy">{menu_buttons(id, fields, UiOp::CopyMenu(None))}</div>
                                        </div>
                                    }
                                })}
                            }.into_any()
                        }
                        RowCopy::Secret => view! {
                            <span class="quick"><button aria-label="Copy the password" title="Copy password" disabled=move || form.get() on:click=quick(id, true)><Svg icon=Icon::Key/></button></span>
                        }.into_any(),
                        RowCopy::Pair { user, secret } => view! {
                            <span class="quick">
                                {user.then(|| view! { <button aria-label="Copy the username" title="Copy username" disabled=move || form.get() on:click=quick(id, false)><Svg icon=Icon::User/></button> })}
                                {secret.then(|| view! { <button aria-label="Copy the password" title="Copy password" disabled=move || form.get() on:click=quick(id, true)><Svg icon=Icon::Key/></button> })}
                            </span>
                        }.into_any(),
                    }}
                </Show>
                {move || menu_open.get().then(|| {
                    let fields = row_menu.get().map(|(_, f)| f).unwrap_or_default();
                    let close = || ui_op(UiOp::RowMenu(None));
                    let rid = rid_select.clone();
                    view! {
                        <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| close()
                            on:contextmenu=move |e: web_sys::MouseEvent| { e.prevent_default(); e.stop_propagation(); close(); }></button>
                        <div class="row-menu">
                            <div class="menu pop end" role="menu" aria-label=title.clone()>
                                <button class="mi" role="menuitem" id="row-open" on:click=move |_| { close(); ui().act(Act::Select(Screen::Entry(id))); }><Svg icon=Icon::Right/>"Open"</button>
                                {match copy {
                                    RowCopy::None => ().into_any(),
                                    RowCopy::Pair { user, secret } => view! {
                                        {user.then(|| view! { <button class="mi" role="menuitem" on:click=move |e| { close(); quick(id, false)(e) }><Svg icon=Icon::User/>"Copy “Username”"</button> })}
                                        {secret.then(|| view! { <button class="mi" role="menuitem" id="row-copy-password" on:click=move |e| { close(); quick(id, true)(e) }><Svg icon=Icon::Key/>"Copy “Password”"</button> })}
                                    }.into_any(),
                                    RowCopy::Secret => view! {
                                        <button class="mi" role="menuitem" id="row-copy-password" on:click=move |e| { close(); quick(id, true)(e) }><Svg icon=Icon::Key/>"Copy “Password”"</button>
                                    }.into_any(),
                                    RowCopy::Menu => menu_buttons(id, fields, UiOp::RowMenu(None)).into_any(),
                                }}
                                {(copy != RowCopy::None).then(|| view! { <hr/> })}
                                <div class="label">"COLOR"</div>
                                <div class="ie-swatches">
                                    {(0..12u8).map(|n| view! {
                                        <button class=if colour == Some(n) { format!("on {}", editor::hue_class(n)) } else { editor::hue_class(n).to_owned() } aria-label=format!("Color {}", n + 1)
                                            on:click=move |_| { close(); ui().act(Act::Ws(WsAct::ColourMany(vec![id], Some(n)))); }></button>
                                    }).collect_view()}
                                </div>
                                <button class="mi" role="menuitem" on:click=move |_| { close(); ui().act(Act::Ws(WsAct::ColourMany(vec![id], None))); }><Svg icon=Icon::Refresh/>"Automatic color"</button>
                                <hr/>
                                <button class="mi" role="menuitem" on:click=move |_| { close(); ui().act(Act::Go(Screen::Move(ItemRef::Entry(id), None))); }><Svg icon=Icon::Move/>"Move to group…"</button>
                                <button class="mi" role="menuitem" id="row-select" on:click={ let rid = rid.clone(); move |_| { close(); anchor.set(Some(rid.clone())); set_selection(Some(BTreeSet::from([rid.clone()]))); } }><Svg icon=Icon::Check/>"Select"</button>
                                <hr/>
                                <button class="mi danger" role="menuitem" id="row-trash" on:click=move |_| { close(); ui().act(Act::Ws(WsAct::TrashMany(vec![id]))); }><Svg icon=Icon::Trash/>"Move to trash"</button>
                            </div>
                        </div>
                    }
                })}
            </div>
        }
    };
    view! {
        // `fade-in` plays when the list mounts again after a tool page.
        <section class=move || if in_selection.get() { "list selecting fade-in" } else { "list fade-in" } aria-label="Items" on:keydown=keys>
            <div class="phone-head">
                <div class="ph-row">
                    <h2>{move || title.get()}</h2>
                    {move || get().and_then(|l| l.group.filter(|_| !l.in_selection)).map(|g| group_actions(g, "group-menu-phone"))}
                    // Android selects by holding a row (plan 0045).
                    {move || get().filter(|l| l.count > 0 && !l.in_selection && !crate::android()).map(|_| view! {
                        <button class="link" id="list-select-phone" disabled=move || form.get() on:click=start_selecting>"Select"</button>
                    })}
                    {move || get().and_then(|l| l.vault).map(|v| view! {
                        <button class=format!("vault-avatar tile {}", v.hue) id="vault-chip" disabled=move || form.get() aria-haspopup="dialog"
                            aria-label=format!("Vault {}. Switch vault", v.name.as_str()) title=v.name.to_string()
                            on:click=move |_| open_sheet()>
                            {v.initial.clone()}
                        </button>
                    })}
                </div>
            </div>
            {move || if in_selection.get() {
                selbar().into_any()
            } else {
                view! {
                    <div class="list-head">
                        <h2>{move || title.get()}</h2>
                        <span class="count">{move || get().map(|l| l.count.to_string())}</span>
                        <span class="sp"></span>
                        {move || get().and_then(|l| l.group).map(|g| group_actions(g, "group-menu"))}
                        {move || get().filter(|l| l.count > 0).map(|_| view! {
                            <button class="icon-btn" id="list-select" aria-label="Select items" title="Select items (Ctrl-click, Shift-click)" disabled=move || form.get() on:click=start_selecting><Svg icon=Icon::Check/></button>
                        })}
                        <button class="icon-btn acc" id="list-new" aria-label="New item" title="New item (Ctrl N)" disabled=move || form.get()
                            on:click=move |_| { if let Some(g) = get().and_then(|l| l.new_in) { ui().act(Act::Ws(WsAct::NewEntry(g))); } }><Svg icon=Icon::Plus/></button>
                    </div>
                }.into_any()
            }}
            <PageNavBar nav=Signal::derive(move || get().and_then(|l| l.page))/>
            <label class="filter"><Svg icon=Icon::Search/>
                {move || {
                    // The filter is rebuilt only when the list's label changes.
                    let label = filter.get();
                    view! {
                        <Input field=WsField::Query label=label kind=Kind::Line value=Signal::derive(move || query.get())
                            disabled=Signal::derive(move || form.get()) bare=true autofocus=autofocus.get_untracked()
                            placeholder=placeholder.get_untracked()/>
                    }
                }}
            </label>
            {move || get().and_then(|l| l.chips.clone()).map(|(chips, new_group)| view! {
                <div class="subgroups root-groups" role="group" aria-label="Groups">
                    {chips.into_iter().map(|c| view! {
                        <button class=if c.on { "chip on" } else { "chip" } disabled=move || form.get() aria-pressed=if c.on { "true" } else { "false" } on:click=go(c.target.clone())>
                            <span class=format!("dot {}", c.hue)></span>{c.name.to_string()}
                        </button>
                    }).collect_view()}
                    {new_group.map(|r| view! { <button class="chip add" id="chip-new-group" disabled=move || form.get() on:click=act(WsAct::NewGroup(r))><Svg icon=Icon::Plus/>"New group"</button> })}
                </div>
            })}
            {move || get().filter(|l| !l.subgroups.is_empty()).map(|l| view! {
                <div class="subgroups">
                    {l.subgroups.into_iter().map(|c| view! { <button class="chip" disabled=move || form.get() on:click=go(c.target.clone())><Svg icon=Icon::Folder/>{c.name.to_string()}</button> }).collect_view()}
                </div>
            })}
            {move || get().filter(|l| l.conflicts > 0 && !l.in_selection).map(|l| view! {
                <button class="conflict-note" id="list-conflicts" disabled=move || form.get() on:click=go(Screen::Conflicts)>
                    <Svg icon=Icon::Conflicts/>
                    <span class="sp">{if l.conflicts == 1 { "1 item has conflicting versions".to_owned() } else { format!("{} items have conflicting versions", l.conflicts) }}</span>
                    <b>"Resolve"</b>
                </button>
            })}
            <div class=move || if stale.get() { "rows stale" } else { "rows" } id="rows">
                {move || get().filter(|l| l.count == 0).map(|l| view! {
                    <div class=if l.loaded { "empty" } else { "empty late" }><div>
                        <div class="big">{svg(l.empty.1)}</div>
                        {l.empty.0.clone()}
                    </div></div>
                })}
                {move || sections.get().into_iter().map(|s| view! {
                    <div class="sect">{s.letter.clone()}</div>
                    {s.rows.into_iter().map(row_view).collect_view()}
                }).collect_view()}
                {move || get().filter(|l| l.kind == ListKind::All && l.recovered > 0).map(|l| view! {
                    <button class="link m8" on:click=go(Screen::Recovered)>{format!("Recovered items whose group is missing ({})", l.recovered)}</button>
                })}
            </div>
        </section>
    }
}

thread_local! {
    static SHEET: std::cell::Cell<Option<RwSignal<bool>>> = const { std::cell::Cell::new(None) };
}

/// Registers the shell's vault sheet signal.
pub(crate) fn sheet_signal(s: RwSignal<bool>) {
    SHEET.with(|c| c.set(Some(s)));
}
/// Opens the phone vault sheet.
pub(crate) fn open_sheet() {
    if let Some(s) = SHEET.with(std::cell::Cell::get) {
        s.set(true);
    }
}

/// The detail pane.
#[component]
pub(crate) fn Detail(s: Memo<Option<S>>) -> impl IntoView {
    let d = field(s, None, |s| match &s.content {
        qv_ui_api::Content::Vault { detail, .. } => Some((**detail).clone()),
        _ => None,
    });
    let closed = Memo::new(move |_| d.with(|d| d.as_ref().is_some_and(|d| d.closed)));
    let report = Memo::new(move |_| d.with(|d| d.as_ref().and_then(|d| d.report.clone())));
    // The screen kind: the inner view is rebuilt only when it changes.
    let kind = Memo::new(move |_| {
        d.with(|d| {
            d.as_ref().map_or(0u8, |d| match &d.inner {
                DetailInner::Empty => 0,
                DetailInner::Unreadable(_) => 1,
                DetailInner::Entry(_) => 2,
                DetailInner::EditEntry(_) => 3,
                DetailInner::EditGroup(_) => 4,
                DetailInner::Move(_) => 5,
                DetailInner::History(_) => 6,
                DetailInner::Version(_) => 7,
                DetailInner::Attachments(_) => 8,
            })
        })
    });
    let inner = Memo::new(move |_| d.with(|d| d.as_ref().map(|d| d.inner.clone())));
    let live = field(s, Default::default(), |s| s.live);
    view! {
        <section class=move || if closed.get() { "detail closed" } else { "detail" } aria-label="Item">
            {move || report.get().map(|r| view! { <div class="detail-inner pb0">{report_card(r)}</div> })}
            {move || match kind.get() {
                1 => view! { {move || match inner.get() { Some(DetailInner::Unreadable(m)) => unreadable(m).into_any(), _ => ().into_any() }} }.into_any(),
                2 => view! { <EntryScreen inner live/> }.into_any(),
                3 => view! { <editor::EditEntry inner/> }.into_any(),
                4 => view! { <editor::EditGroup inner/> }.into_any(),
                5 => view! { <MoveScreen inner/> }.into_any(),
                6 => view! { <HistoryScreen inner/> }.into_any(),
                7 => view! { <VersionScreen inner live/> }.into_any(),
                8 => view! { <AttachmentsScreen inner/> }.into_any(),
                _ => view! {
                    <div class="empty"><div>
                        <div class="big"><Svg icon=Icon::Key/></div>
                        "Select an item to see it here."
                    </div></div>
                }.into_any(),
            }}
        </section>
    }
}

fn back_bar(close: bool) -> impl IntoView {
    view! {
        <div class="phone-bar">
            <button class="icon-btn back" aria-label=if close { "Cancel" } else { "Back" } on:click=move |_| ui().act(Act::Back)>
                <Svg icon=if close { Icon::Close } else { Icon::Back } large=true/>
            </button>
        </div>
    }
}

/// One field of an entry.
fn field_line(f: F, live: Memo<qv_ui_api::Live>) -> impl IntoView {
    let left = move || live.get().reveal_left.min(30);
    let ring = move || {
        view! {
            <span class="hide-ring">
                <svg class="revealring" viewBox="0 0 22 22" aria-hidden="true">
                    <circle class="track" cx="11" cy="11" r="10"></circle>
                    <circle class="left" cx="11" cy="11" r="10" stroke-dasharray="62.8"
                        stroke-dashoffset=move || format!("{:.1}", 62.8 - 62.8 * (left() as f64) / 30.0)></circle>
                </svg>
                <Svg icon=Icon::EyeOff/>
            </span>
        }
    };
    let name = f.name.to_string();
    let value = if f.totp {
        match &f.code {
            None => view! { <span class="v masked">"One-time code"</span> }.into_any(),
            Some(c) => view! { <span class="totp"><span class="code revealed">{c.to_string()}</span></span> }.into_any(),
        }
    } else if let Some(v) = &f.value {
        view! { <pre class="v field-value">{v.to_string()}</pre> }.into_any()
    } else if let Some(s) = &f.shown {
        view! { <pre class="v field-value revealed">{s.to_string()}</pre> }.into_any()
    } else {
        view! { <span class="v masked field-value">{MASK}</span> }.into_any()
    };
    let acts = if f.totp {
        match (&f.code, f.code_key.clone()) {
            (None, Some(k)) => view! { <button class="btn subtle" id="show-code" on:click=act(WsAct::Reveal(k))><Svg icon=Icon::Eye/>"Show code"</button> }.into_any(),
            (Some(_), _) => view! { <button class="icon-btn" aria-label="Hide code" title=move || format!("Hide · {} s left", left()) on:click=act(WsAct::Hide)>{ring()}</button> }.into_any(),
            _ => ().into_any(),
        }
    } else if f.protected {
        if f.shown.is_some() {
            view! { <button class="icon-btn" aria-label="Hide" title=move || format!("Hide · {} s left", left()) on:click=act(WsAct::Hide)>{ring()}</button> }.into_any()
        } else {
            view! { <button class="icon-btn" aria-label="Reveal for 30 seconds" title="Reveal for 30 s" on:click=act(WsAct::Reveal(f.reveal.clone()))><Svg icon=Icon::Eye/></button> }.into_any()
        }
    } else {
        ().into_any()
    };
    let copy = f.copy.clone();
    view! {
        <div class="fld">
            {copy.clone().map(|k| view! { <button class="copy-hit" aria-label=format!("Copy {name}") title="Click to copy" on:click=act(WsAct::Copy(k))></button> })}
            <div class="body">
                <span class="k">{f.name.to_string()}<small>{f.kind_name.clone()}</small></span>
                {value}
            </div>
            <div class="acts">
                {acts}
                {copy.map(|k| view! { <button class="icon-btn" aria-label="Copy" title="Copy" on:click=act(WsAct::Copy(k))><Svg icon=Icon::Copy/></button> })}
            </div>
        </div>
    }
}

/// A card's face, never its number.
pub(crate) fn card_face(c: &qv_ui_api::CardFace, hue: &str) -> impl IntoView + use<> {
    view! {
        <div class=format!("ie-card {hue}") role="img" aria-label="Card preview">
            <div class="row1"><span class="emv"></span><span class="ie-brand">{c.brand.clone()}</span></div>
            <div class="num live" aria-hidden="true"></div>
            <div class="num">{c.number.clone()}</div>
            <div class="row2">
                <div class="min0"><small>"Card holder"</small><b>{if c.name.is_empty() { "Your name".to_owned() } else { c.name.to_string() }}</b></div>
                <div class="r"><small>"Expires"</small><b>{if c.expiry.is_empty() { "MM/YY".to_owned() } else { c.expiry.to_string() }}</b></div>
            </div>
        </div>
    }
}

fn qr_svg(q: &qv_ui_api::Qr) -> impl IntoView + use<> {
    view! {
        <svg class="ie-qrcode revealed" xmlns="http://www.w3.org/2000/svg" viewBox=format!("0 0 {0} {0}", q.side)
            width="168" height="168" shape-rendering="crispEdges" role="img" aria-label="Wi‑Fi join QR code">
            <rect width="100%" height="100%" fill="white"></rect>
            <path d=q.path.to_string() fill="black"></path>
        </svg>
    }
}

/// An entry's fields and notes, current or historical.
fn entry_body(b: Body, live: Memo<qv_ui_api::Live>) -> impl IntoView {
    let entry = b.entry;
    let left = move || live.get().reveal_left.min(30);
    view! {
        <div class="hero">
            <span class=format!("tile {}", b.tile)>{glyph(&b.glyph)}</span>
            <div class="min0">
                <h1>{b.title.to_string()}</h1>
                <div class="meta">
                    {b.url.clone().map(|u| view! { <span class="pill link"><Svg icon=Icon::Globe/>{u.to_string()}</span> })}
                    {(!b.type_hint.is_empty()).then(|| view! { <span class="pill"><Svg icon=b.kind_icon/>{b.type_hint.to_string()}</span> })}
                    {b.group.clone().map(|(g, h)| view! { <span class="pill"><span class=format!("dot {h}")></span>{g.to_string()}</span> })}
                </div>
            </div>
        </div>
        {(b.versions > 1).then(|| view! {
            <div class="banner"><Svg icon=Icon::Conflicts/>
                <span class="sp">{format!("This entry has {} conflicting versions; one is shown. Choose one before copying or editing.", b.versions)}</span>
                <button class="btn" id="entry-resolve" on:click=go(Screen::ConflictRecord(b.record.clone()))>"Compare and resolve"</button>
            </div>
        })}
        {b.expires.clone().map(|x| view! { <div class="banner"><Svg icon=Icon::Clock/><span>{format!("Expires {x}")}</span></div> })}
        {b.card.clone().map(|c| view! { <div class="ie-face">{card_face(&c, &b.tile)}</div> })}
        {b.wifi.clone().map(|qr| view! {
            <div class="card ie-join">
                {match qr {
                    Some(q) => view! {
                        {qr_svg(&q)}
                        <div class="min0">
                            <b>"Scan to join"</b>
                            <span>{move || format!("Point the phone's camera at the code. It hides in {} s.", left())}</span>
                            <button class="btn subtle" id="wifi-join-hide" on:click=act(WsAct::Hide)><Svg icon=Icon::EyeOff/>"Hide"</button>
                        </div>
                    }.into_any(),
                    None => view! {
                        <span class="ie-qr"><Svg icon=Icon::Qr large=true/></span>
                        <div class="min0">
                            <b>"Join code"</b>
                            <span>"Phones scan it to join this network. It contains the password and shows for 30 seconds."</span>
                            <button class="btn" id="wifi-join" on:click=act(WsAct::Reveal(qv_ui_api::RevealKey::WifiJoin(entry)))><Svg icon=Icon::Qr/>"Show join code"</button>
                        </div>
                    }.into_any(),
                }}
            </div>
        })}
        {(!b.fields.is_empty()).then(|| view! {
            <div class="card fields">{b.fields.iter().cloned().map(|f| field_line(f, live)).collect_view()}</div>
        })}
        {b.notes.clone().map(|n| view! {
            <div class="card">
                <div class="card-h">"NOTES"
                    // Browser copies are cancelled; notes copy through the
                    // app's clipboard, which clears itself (plan 0063).
                    {b.current.then(|| view! { <button class="link" id="notes-copy" on:click=act(WsAct::Copy(CopyKey::Notes(entry)))><Svg icon=Icon::Copy/>"Copy"</button> })}
                </div>
                <pre class="notes">{n.to_string()}</pre>
            </div>
        })}
    }
}

#[component]
fn EntryScreen(inner: Memo<Option<DetailInner>>, live: Memo<qv_ui_api::Live>) -> impl IntoView {
    // Which ⋯ opened the menu (0 phone bar, 1 desktop toolbar).
    let menu = RwSignal::new(None::<u8>);
    let e = Memo::new(move |_| {
        inner.with(|i| match i {
            Some(DetailInner::Entry(e)) => Some((**e).clone()),
            _ => None,
        })
    });
    let entry_menu = move |v: &qv_ui_api::EntryScreen| {
        let id = v.entry;
        let item = ItemRef::Entry(id);
        let deleted = v.deleted;
        let n = v.attachments;
        let close_then = move |a: Act| {
            move |_| {
                menu.set(None);
                ui().act(a.clone());
            }
        };
        view! {
            <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| menu.set(None)></button>
            <div class="menu pop end" role="menu">
                <button class="mi" id="menu-history" on:click=close_then(Act::Go(Screen::History(id)))><Svg icon=Icon::History/>"History"</button>
                <button class="mi" id="menu-attachments" on:click=close_then(Act::Go(Screen::Attachments(id)))><Svg icon=Icon::Attach/>"Attachments"<span class="sub">{n.to_string()}</span></button>
                {(!deleted).then(|| view! {
                    <button class="mi" id="menu-move" on:click=close_then(Act::Go(Screen::Move(item, None)))><Svg icon=Icon::Move/>"Move to group…"</button>
                    <hr/>
                    <button class="mi danger" id="menu-delete" on:click=close_then(Act::Ws(WsAct::Delete(item)))><Svg icon=Icon::Trash/>"Move to trash"</button>
                })}
            </div>
        }
    };
    move || {
        e.get().map(|v| {
            let id = v.entry;
            let editable = v.editable;
            let files = v.files.clone();
            let show_shelf = editable || !files.is_empty();
            let v1 = v.clone();
            let v2 = v.clone();
            view! {
                <div class="phone-bar">
                    <button class="icon-btn back" aria-label="Back" on:click=move |_| ui().act(Act::Back)><Svg icon=Icon::Back large=true/></button>
                    <span class="sp"></span>
                    {editable.then(|| view! { <button class="icon-btn" aria-label="Edit" on:click=act(WsAct::EditEntry(id))><Svg icon=Icon::Edit large=true/></button> })}
                    <div class="pop-anchor">
                        <button class="icon-btn" aria-label="More actions" on:click=move |_| menu.update(|m| *m = if *m == Some(0) { None } else { Some(0) })><Svg icon=Icon::More large=true/></button>
                        {move || (menu.get() == Some(0)).then(|| entry_menu(&v1))}
                    </div>
                </div>
                <div class="detail-inner fade-in">
                    {v.deleted.then(|| view! {
                        <div class="banner"><Svg icon=Icon::Trash/><span class="sp">"This item is in the trash."</span>
                            <button class="btn" on:click=act(WsAct::Restore(ItemRef::Entry(id)))><Svg icon=Icon::Restore/>"Restore"</button>
                        </div>
                    })}
                    <div class="toolbar desk-only tool-end">
                        {editable.then(|| view! { <button class="btn" id="entry-edit" on:click=act(WsAct::EditEntry(id))><Svg icon=Icon::Edit/>"Edit"</button> })}
                        <div class="pop-anchor">
                            <button class="icon-btn" id="entry-menu" aria-label="More actions" title="More" on:click=move |_| menu.update(|m| *m = if *m == Some(1) { None } else { Some(1) })><Svg icon=Icon::More large=true/></button>
                            {move || (menu.get() == Some(1)).then(|| entry_menu(&v2))}
                        </div>
                    </div>
                    {entry_body(v.body.clone(), live)}
                    {show_shelf.then(|| view! {
                        <div class="shelf">
                            <div class="shelf-h"><span>"FILES"</span>{(!files.is_empty()).then(|| view! { <button class="link" on:click=go(Screen::Attachments(id))>"Manage"</button> })}</div>
                            <div class="shelf-row">
                                {files.into_iter().map(|a| view! {
                                    <button class=format!("shelf-tile {}", a.tone) disabled=a.conflicted title=a.name.to_string()
                                        aria-label=format!("Preview {}", a.name.as_str()) on:click=act(WsAct::Preview(a.id))>
                                        <span class="st-glyph"><Svg icon=a.icon large=true/></span>
                                        <b>{a.name.to_string()}</b>
                                        <small>{if a.conflicted { "conflict".to_owned() } else { a.size.clone() }}</small>
                                    </button>
                                }).collect_view()}
                                {editable.then(|| view! {
                                    <button class="shelf-tile add" id="shelf-add" on:click=go(Screen::Attachments(id))>
                                        <span class="st-glyph"><Svg icon=Icon::Plus large=true/></span>
                                        <b>"Add a file"</b>
                                        <small>"Up to 2 GiB"</small>
                                    </button>
                                })}
                            </div>
                        </div>
                    })}
                    <div class="foot">
                        <span>{format!("Modified {} · created {}", v.modified, v.created)}</span>
                        <button class="link" id="entry-history" on:click=go(Screen::History(id))>"History"</button>
                    </div>
                </div>
            }
        })
    }
}

#[component]
fn MoveScreen(inner: Memo<Option<DetailInner>>) -> impl IntoView {
    let m = Memo::new(move |_| {
        inner.with(|i| match i {
            Some(DetailInner::Move(m)) => Some(m.clone()),
            _ => None,
        })
    });
    move || {
        m.get().map(|m| {
            let item = m.item;
            let here = m.here;
            view! {
                {back_bar(true)}
                <div class="detail-inner fade-in">
                    <h1 class="title-sm">"Move to a group"</h1>
                    <div class="toolbar mb">
                        {m.crumbs.into_iter().map(|(g, name)| view! { <button class="chip" on:click=go(Screen::Move(item, Some(g)))><Svg icon=Icon::Folder/>{name.to_string()}</button> }).collect_view()}
                    </div>
                    <div class="card">
                        {m.empty.clone().map(|t| view! { <div class="set-row"><span class="l"><span>{t.to_string()}</span></span></div> })}
                        {m.groups.into_iter().map(|(g, name)| view! {
                            <button class="set-row" on:click=go(Screen::Move(item, Some(g)))>
                                <span class="si"><Svg icon=Icon::Folder/></span><span class="l"><b>{name.to_string()}</b></span><Svg icon=Icon::Right/>
                            </button>
                        }).collect_view()}
                    </div>
                    <PageNavBar nav=m.page.clone()/>
                    <div class="actions">
                        <button class="btn subtle" on:click=move |_| ui().act(Act::Back)>"Cancel"</button>
                        <button class="btn primary" id="move-here" on:click=act(WsAct::MoveTo(item, here))>"Move here"</button>
                    </div>
                </div>
            }
        })
    }
}

fn sub_back() -> impl IntoView {
    // Desktop has no phone bar: the item's sub-pages get a back link (plan 0054).
    view! { <button class="sub-back desk-only" on:click=move |_| ui().act(Act::Back)><Svg icon=Icon::Back/>"Back"</button> }
}

#[component]
fn HistoryScreen(inner: Memo<Option<DetailInner>>) -> impl IntoView {
    let h = Memo::new(move |_| {
        inner.with(|i| match i {
            Some(DetailInner::History(h)) => Some(h.clone()),
            _ => None,
        })
    });
    move || {
        h.get().map(|h| {
            let entry = h.entry;
            view! {
                {back_bar(false)}
                <div class="detail-inner fade-in">
                    {sub_back()}
                    <div class="hero"><span class="tile h6"><Svg icon=Icon::History large=true/></span><div><h1>"History"</h1><p class="muted">"Earlier versions kept for this item. Restoring creates a new version."</p></div></div>
                    {h.rows.is_empty().then(|| view! { <div class="empty">"No earlier versions are kept."</div> })}
                    <div class="timeline">
                        {h.rows.into_iter().map(|r| view! {
                            <div class="tl-i">
                                <button class="history-row" on:click=go(Screen::HistoryVersion(entry, r.version.clone()))>
                                    <b>{r.modified.clone()}</b>
                                    <span>{r.changed.to_string()}{r.conflict.then_some(" · concurrent")}</span>
                                </button>
                            </div>
                        }).collect_view()}
                    </div>
                    <div class="actions">
                        <button class="btn subtle" on:click=move |_| ui().act(Act::Back)>"Back"</button>
                        <button class="btn danger-text" on:click=act(WsAct::PurgeHistory(entry))><Svg icon=Icon::Trash/>"Purge history…"</button>
                    </div>
                </div>
            }
        })
    }
}

#[component]
fn VersionScreen(inner: Memo<Option<DetailInner>>, live: Memo<qv_ui_api::Live>) -> impl IntoView {
    let v = Memo::new(move |_| {
        inner.with(|i| match i {
            Some(DetailInner::Version(v)) => Some((**v).clone()),
            _ => None,
        })
    });
    move || {
        v.get().map(|v| {
            let entry = v.entry;
            let version = v.version.clone();
            let version2 = version.clone();
            view! {
                {back_bar(false)}
                <div class="detail-inner fade-in">
                    {sub_back()}
                    <div class="banner"><Svg icon=Icon::History/><span>"An earlier version. Restoring creates a new version; nothing is overwritten."</span></div>
                    {entry_body(v.body.clone(), live)}
                    <div class="actions">
                        <button class="btn subtle" on:click=move |_| ui().act(Act::Back)>"Back"</button>
                        {v.conflicted.then(|| view! { <button class="btn" on:click=act(WsAct::RestoreHistory(entry, version.clone(), true))>"Restore and resolve conflict"</button> })}
                        <button class="btn primary" id="restore-version" on:click=act(WsAct::RestoreHistory(entry, version2.clone(), false))><Svg icon=Icon::Restore/>"Restore this version"</button>
                    </div>
                </div>
            }
        })
    }
}

/// Choose a file through the system picker, then add it; a typed path
/// appears only without a picker.
pub(crate) fn file_picker(picker: Picker, entry: qv_ui_api::Ref) -> impl IntoView {
    match picker {
        Picker::Android(picked) => view! {
            <div class="actions start">
                <button class="btn" on:click=move |_| ui().act(Act::AndroidPick(qv_ui_api::AndroidPick::Open))><Svg icon=Icon::File/>"Choose a file…"</button>
                <button class="btn" on:click=move |_| ui().act(Act::AndroidPick(qv_ui_api::AndroidPick::Create))><Svg icon=Icon::Folder/>"Choose where to save…"</button>
                <button class="btn primary" on:click=act(WsAct::AddAttachment(entry))><Svg icon=Icon::Plus/>"Add attachment"</button>
            </div>
            {picked.map(|n| view! { <p class="hint">{format!("Chosen: {}", n.as_str())}</p> })}
        }
        .into_any(),
        Picker::Portal => view! {
            <div class="actions start">
                <button class="btn primary" id="add-attachment" on:click=move |_| ui().act(Act::Pick(qv_ui_api::Pick::AddAttachment(entry)))><Svg icon=Icon::Plus/>"Add a file…"</button>
            </div>
        }
        .into_any(),
        Picker::Typed => view! {
            <Input field=WsField::Path label="File to add, or destination to save to (full path)" kind=Kind::Line/>
            <div class="actions start">
                <button class="btn primary" id="add-attachment" on:click=act(WsAct::AddAttachment(entry))><Svg icon=Icon::Plus/>"Add attachment"</button>
            </div>
        }
        .into_any(),
    }
}

#[component]
fn AttachmentsScreen(inner: Memo<Option<DetailInner>>) -> impl IntoView {
    let a = Memo::new(move |_| {
        inner.with(|i| match i {
            Some(DetailInner::Attachments(a)) => Some(a.clone()),
            _ => None,
        })
    });
    let rows =
        Memo::new(move |_| a.with(|a| a.as_ref().map(|a| a.rows.clone()).unwrap_or_default()));
    let entry = Memo::new(move |_| a.with(|a| a.as_ref().map(|a| a.entry)));
    let picker = Memo::new(move |_| a.with(|a| a.as_ref().map(|a| a.picker.clone())));
    view! {
        {back_bar(false)}
        <div class="detail-inner fade-in">
            {sub_back()}
            <div class="hero"><span class="tile h1"><Svg icon=Icon::Attach large=true/></span><div><h1>"Attachments"</h1><p class="muted">"Up to 2 GiB each. Names and types are shown as text; files are never opened."</p></div></div>
            <div class="card">
                {move || rows.get().is_empty().then(|| view! { <div class="set-row"><span class="l"><span>"No attachments yet."</span></span></div> })}
                {move || {
                    let portal = matches!(picker.get(), Some(Picker::Portal));
                    rows.get().into_iter().map(|a| {
                        let id = a.id;
                        view! {
                            <div class="dev">
                                <div class="di"><Svg icon=Icon::File large=true/></div>
                                <div class="l"><b>{a.name.to_string()}</b><span>{format!("{} · {} bytes", a.mime.as_str(), a.size)}{a.conflicted.then_some(" · conflict")}</span></div>
                                <button class="btn" disabled=a.conflicted on:click=act(WsAct::Preview(id))><Svg icon=Icon::Eye/>"Preview"</button>
                                {if portal {
                                    view! { <button class="btn" disabled=a.conflicted on:click=move |_| ui().act(Act::Pick(qv_ui_api::Pick::SaveAttachment(id)))>"Save…"</button> }.into_any()
                                } else {
                                    view! { <button class="btn" disabled=a.conflicted on:click=act(WsAct::SaveAttachment(id))>"Save…"</button> }.into_any()
                                }}
                                <button class="btn subtle" aria-label=format!("Remove {}", a.name.as_str()) disabled=a.conflicted on:click=act(WsAct::RemoveAttachment(id))><Svg icon=Icon::Trash/></button>
                            </div>
                        }
                    }).collect_view()
                }}
            </div>
            {move || picker.get().zip(entry.get()).map(|(p, e)| file_picker(p, e))}
            <details class="muted mt">
                <summary>"Name and type for the next attachment (optional)"</summary>
                <Input field=WsField::AttachName label="Name" kind=Kind::Line/>
                <Input field=WsField::AttachMime label="MIME type" kind=Kind::Line/>
            </details>
        </div>
    }
}

/// The full-window attachment viewer (0003 §6.4, 0009 §1.8; plan 0044).
#[component]
pub(crate) fn Viewer(s: Memo<Option<S>>) -> impl IntoView {
    let v = field(s, None, |s| s.viewer.as_deref().cloned());
    let actual = RwSignal::new(false);
    let wrap = RwSignal::new(true);
    // Window full screen for video (WebKitGTK's native video full screen
    // draws black, plan 0057); leaving the viewer restores the window.
    let full = RwSignal::new(false);
    let set_full = move |on: bool| {
        ui().window(qv_ui_api::WindowOp::Fullscreen(on));
        full.set(on);
    };
    on_cleanup(move || {
        if full.get_untracked() {
            ui().window(qv_ui_api::WindowOp::Fullscreen(false));
        }
    });
    let close = move || ui().act(Act::Ws(WsAct::ClosePreview));
    let many = Memo::new(move |_| v.with(|v| v.as_ref().is_some_and(|v| v.count > 1)));
    let keys = move |e: web_sys::KeyboardEvent| match e.key().as_str() {
        "Escape" if full.get_untracked() => {
            e.stop_propagation();
            e.prevent_default();
            set_full(false);
        }
        "Escape" => {
            e.stop_propagation();
            e.prevent_default();
            close();
        }
        "ArrowLeft" if many.get_untracked() => {
            e.stop_propagation();
            ui().act(Act::Ws(WsAct::PreviewStep(-1)));
        }
        "ArrowRight" if many.get_untracked() => {
            e.stop_propagation();
            ui().act(Act::Ws(WsAct::PreviewStep(1)));
        }
        _ => {}
    };
    let stop = |e: web_sys::MouseEvent| e.stop_propagation();
    let step = move |d: i8| {
        move |e: web_sys::MouseEvent| {
            e.stop_propagation();
            ui().act(Act::Ws(WsAct::PreviewStep(d)));
        }
    };
    let controls = move |video: bool| {
        let android = crate::android();
        view! {
            <div class="v-ctl" on:keydown=move |e: web_sys::KeyboardEvent| {
                if matches!(e.key().as_str(), "ArrowLeft" | "ArrowRight" | "ArrowUp" | "ArrowDown" | "Home" | "End" | "PageUp" | "PageDown") { e.stop_propagation(); }
            }>
                <button class="v-cb v-play" type="button" aria-label="Play" title="Play (Space)">
                    <span class="i-play"><Svg icon=Icon::Play/></span><span class="i-pause"><Svg icon=Icon::Pause/></span>
                </button>
                <input class="v-seek" type="range" min="0" max="1" step="any" value="0" aria-label="Seek"/>
                <span class="v-time"></span>
                <button class="v-cb v-mute" type="button" aria-label="Mute" title="Mute (M)">
                    <span class="i-loud"><Svg icon=Icon::Volume/></span><span class="i-quiet"><Svg icon=Icon::Muted/></span>
                </button>
                <input class="v-volume" type="range" min="0" max="1" step="any" value="1" aria-label="Volume"/>
                {(video && !android).then(|| view! {
                    <button class="v-cb v-fs" id="viewer-full" type="button"
                        aria-label=move || if full.get() { "Exit full screen" } else { "Full screen" }
                        title=move || if full.get() { "Exit full screen (F)" } else { "Full screen (F)" }
                        on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); set_full(!full.get_untracked()); }>
                        {move || if full.get() { svg(Icon::Shrink).into_any() } else { svg(Icon::Expand).into_any() }}
                    </button>
                })}
                // Android: the player itself goes full screen (player.js).
                {(video && android).then(|| view! {
                    <button class="v-cb v-fs" id="viewer-full" type="button" data-qv-fs="element" aria-label="Full screen" title="Full screen">
                        <span class="i-expand"><Svg icon=Icon::Expand/></span><span class="i-shrink"><Svg icon=Icon::Shrink/></span>
                    </button>
                })}
            </div>
        }
    };
    move || {
        v.get().map(|p| {
            let linux = ui().platform() == qv_ui_api::Platform::Linux;
            let android = crate::android();
            let id = p.id;
            let entry = p.entry;
            let name = p.name.to_string();
            let direct = p.direct_save;
            let save = move |e: web_sys::MouseEvent| {
                e.stop_propagation();
                if direct {
                    ui().act(Act::Pick(qv_ui_api::Pick::SaveAttachment(id)));
                } else {
                    // Android and portal-less desktops save from the files screen.
                    ui().act(Act::Go(Screen::Attachments(entry)));
                }
            };
            let src = p.src.as_ref().map(|s| s.to_string()).unwrap_or_default();
            let mime = p.mime.clone();
            let size = p.size.to_string();
            let stage = if let Some(desc) = p.image_load.clone() {
                view! {
                    <div class="v-none" on:click=stop>
                        <div class="v-none-glyph"><Svg icon=Icon::File large=true/></div>
                        <b>"Load this image?"</b>
                        <span>{desc}</span>
                        <button class="btn primary" id="viewer-load-image" on:click=act(WsAct::LoadPreview(id))>"Load image"</button>
                    </div>
                }.into_any()
            } else {
                match (p.kind.as_str(), p.src.is_some(), p.text.clone()) {
                    ("image", true, _) if p.size > IMAGE_MAX => view! {
                        <div class="v-none" on:click=stop>
                            <div class="v-none-glyph"><Svg icon=Icon::File large=true/></div>
                            <b>"This image is too large to preview"</b>
                            <span>"QuickVault previews images up to 64 MB. Save a copy to open it in another app."</span>
                        </div>
                    }.into_any(),
                    ("image", true, _) => {
                        let alt = name.clone();
                        // An <img> asks the media scheme once and gets at most
                        // 64 KiB, so player.js reads the image range by range
                        // into a blob (0003 §6.4, plan 0072).
                        view! {
                            <div class=move || if actual.get() { "v-img actual" } else { "v-img" }>
                                <img data-qv-src=src.clone() data-qv-type=mime.clone() data-qv-size=size.clone() alt=alt draggable="false" on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); actual.update(|a| *a = !*a); }/>
                            </div>
                        }.into_any()
                    }
                    ("audio", true, _) => view! {
                        <div class="v-audio" on:click=stop>
                            <div class="v-disc"><div class="v-disc-label"><Svg icon=Icon::File large=true/></div></div>
                            <div class="v-eq" aria-hidden="true">{(0..24).map(|_| view! { <i></i> }).collect_view()}</div>
                            <b class="v-track">{name.clone()}</b>
                            <div class="v-player">
                                // WebKitGTK buffers playing HTTP media to disk, so on
                                // Linux player.js plays it from memory (plans 0057, 0059).
                                {if linux {
                                    view! { <audio data-qv-src=src.clone() data-qv-type=mime.clone() data-qv-size=size.clone() preload="auto"></audio> }.into_any()
                                } else if android {
                                    // A CORS request lets the level bars read the sound (plan 0061).
                                    view! { <audio src=src.clone() preload="metadata" crossorigin="anonymous"></audio> }.into_any()
                                } else {
                                    view! { <audio src=src.clone() preload="metadata"></audio> }.into_any()
                                }}
                                {controls(false)}
                            </div>
                        </div>
                    }.into_any(),
                    ("video", true, _) => view! {
                        <div class="v-video" on:click=stop>
                            <div class="v-player">
                                {if linux {
                                    view! { <video data-qv-src=src.clone() data-qv-type=mime.clone() data-qv-size=size.clone() preload="auto" playsinline="true"></video> }.into_any()
                                } else {
                                    view! { <video src=src.clone() preload="auto" playsinline="true"></video> }.into_any()
                                }}
                                {controls(true)}
                            </div>
                        </div>
                    }.into_any(),
                    ("text", _, Some(text)) => view! {
                        <div class="v-text" on:click=stop>
                            <div class="v-text-meta"><span>{format!("{} lines", p.lines)}</span>{p.cut.then(|| view! { <span class="v-cut">"Showing the first 1 MB"</span> })}</div>
                            <pre class=move || if wrap.get() { "v-pre wrap" } else { "v-pre" }>{text.to_string()}</pre>
                        </div>
                    }.into_any(),
                    _ => view! {
                        <div class="v-none" on:click=stop>
                            <div class="v-none-glyph"><Svg icon=Icon::File large=true/></div>
                            <b>"No preview for this kind of file"</b>
                            <span>"QuickVault shows images, audio, video and text. Other files never open here; save a copy to use them in another app."</span>
                        </div>
                    }.into_any(),
                }
            };
            let is_image = p.kind == "image";
            let is_text = p.kind == "text";
            let index = p.index;
            let count = p.count;
            view! {
                // A click anywhere on the dark backdrop closes the preview.
                <div class=move || if full.get() { format!("viewer full tone-{}", p.tone) } else { format!("viewer tone-{}", p.tone) }
                    role="dialog" aria-modal="true" aria-label=format!("Preview of {name}") tabindex="-1" autofocus=true
                    on:keydown=keys on:click=move |_| close()>
                    <div class="v-top">
                        <span class="v-badge"><Svg icon=p.icon/></span>
                        <div class="v-title"><b>{p.name.to_string()}</b><span>{format!("{} · {}", p.kind_name, p.size_label)}{(count > 1).then(|| format!(" · {} of {}", index + 1, count))}</span></div>
                        <span class="sp"></span>
                        {is_image.then(|| view! {
                            <button class="v-btn" id="viewer-zoom" title=move || if actual.get() { "Fit to window" } else { "Actual size" }
                                on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); actual.update(|a| *a = !*a); }>
                                {move || if actual.get() { "Fit" } else { "1:1" }}
                            </button>
                        })}
                        {is_text.then(|| view! {
                            <button class=move || if wrap.get() { "v-btn on" } else { "v-btn" } id="viewer-wrap" aria-pressed=move || if wrap.get() { "true" } else { "false" }
                                on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); wrap.update(|w| *w = !*w); }>"Wrap"</button>
                        })}
                        <button class="v-btn" id="viewer-save" on:click=save><Svg icon=Icon::Archive/><span class="v-lbl">"Save a copy"</span></button>
                        <button class="v-btn icon" id="viewer-close" aria-label="Close preview" title="Close (Esc)" on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); close(); }><Svg icon=Icon::Close large=true/></button>
                    </div>
                    <div class="v-stage">
                        {(count > 1).then(|| view! { <button class="v-nav prev" aria-label="Previous file" on:click=step(-1)><Svg icon=Icon::Back large=true/></button> })}
                        {stage}
                        {(count > 1).then(|| view! { <button class="v-nav next" aria-label="Next file" on:click=step(1)><Svg icon=Icon::Right large=true/></button> })}
                    </div>
                    {(count > 1).then(|| view! {
                        <div class="v-dots" aria-hidden="true">{(0..count.min(12)).map(|i| view! { <i class=if i == index { "on" } else { "" }></i> }).collect_view()}</div>
                    })}
                    <div class="v-foot"><Svg icon=Icon::Shield/>"Decrypted in memory only. Nothing is written to disk unless you save a copy."</div>
                </div>
            }
        })
    }
}
