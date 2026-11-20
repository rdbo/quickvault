// SPDX-License-Identifier: AGPL-3.0-or-later

//! The item editor (plan 0040 E1–E11): a start box
//! that recognises what is being saved, a form shaped by the item's type,
//! field tools behind ⋯, one "Add a field" that infers the kind, card and
//! Wi‑Fi previews, the generator popover and the tile's colour picker.
//! Protected values are never prefilled: a saved one shows "Saved · Change",
//! and a generated one moves into its field in Rust.
use crate::icons::{Icon, Svg};
use crate::input::{Input, Kind};
use crate::shell::{PageNavBar, act};
use crate::ui;
use leptos::prelude::*;
use qv_ui_api::{
    Act, DetailInner, EditorPop as Pop, FieldKind, Form, FormRow, GroupChoices, Role, UiOp, WsAct,
    WsField,
};
use std::collections::BTreeSet;

const MASK: &str = "••••••••";

pub(crate) fn hue_class(n: u8) -> &'static str {
    const HUES: [&str; 12] = [
        "h0", "h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9", "h10", "h11",
    ];
    HUES[usize::from(n) % 12]
}

fn pop(p: Option<Pop>) {
    ui().act(Act::Ui(UiOp::EditorPop(p)));
}

fn scrim() -> impl IntoView {
    view! { <button class="pop-scrim" aria-label="Close" tabindex="-1" on:click=move |_| pop(None)></button> }
}

fn set(field: WsField, value: String) {
    ui().input(qv_ui_api::Field::Ws(field), &value);
}

/// A bounded top-level group picker.
pub(crate) fn group_choices(
    c: GroupChoices,
    on_pick: impl Fn(qv_ui_api::Ref) + Clone + Send + Sync + 'static,
) -> impl IntoView {
    let pick = move |g: qv_ui_api::Ref| {
        let on_pick = on_pick.clone();
        move |_| on_pick(g)
    };
    view! {
        {c.root.map(|r| view! { <button type="button" class="mi" role="menuitem" on:click=pick(r)>"No group"</button> })}
        {c.groups.into_iter().map(|(id, name, hue, current)| view! {
            <button type="button" class="mi" role="menuitem" on:click=pick(id)>
                <span class=format!("ie-dot {hue}")></span>{name.to_string()}
                {current.then(|| view! { <span class="sub"><Svg icon=Icon::Check/></span> })}
            </button>
        }).collect_view()}
        {c.extra.clone().map(|(id, name)| view! {
            <button type="button" class="mi" role="menuitem" on:click=pick(id)>{name.to_string()}<span class="sub"><Svg icon=Icon::Check/></span></button>
        })}
        <PageNavBar nav=c.page.clone()/>
    }
}

/// The colour swatches and "Automatic" (0003 §5.5).
fn swatches(current: Option<u8>, class: &'static str) -> impl IntoView {
    let popover = class.contains("menu");
    let pick = move |n: Option<u8>| {
        move |_| {
            pop(None);
            ui().act(Act::Ws(WsAct::SetHue(n)));
        }
    };
    view! {
        <div class=class role=if popover { "menu" } else { "group" } aria-label="Color">
            <div class="label">{if popover { "COLOR" } else { "Color" }}</div>
            <div class="ie-swatches">
                {(0..12u8).map(|n| view! {
                    <button class=if current == Some(n) { format!("on {}", hue_class(n)) } else { hue_class(n).to_owned() }
                        id=format!("colour-{n}") aria-label=format!("Color {}", n + 1)
                        aria-pressed=if current == Some(n) { "true" } else { "false" } on:click=pick(Some(n))></button>
                }).collect_view()}
            </div>
            <hr/>
            <button class="mi" id="colour-auto" on:click=pick(None)><Svg icon=Icon::Refresh/>"Automatic"{current.is_none().then(|| view! { <span class="sub"><Svg icon=Icon::Check/></span> })}</button>
        </div>
    }
}

#[component]
pub(crate) fn EditEntry(inner: Memo<Option<DetailInner>>) -> impl IntoView {
    let ed = Memo::new(move |_| {
        inner.with(|i| match i {
            Some(DetailInner::EditEntry(e)) => Some((**e).clone()),
            _ => None,
        })
    });
    // Another entry's draft gets a fresh editor (local state reset).
    let key = Memo::new(move |_| {
        ed.with(|e| match e {
            Some(qv_ui_api::Editor::Start { .. }) => Some(String::new()),
            Some(qv_ui_api::Editor::Form(f)) => Some(f.id.clone()),
            None => None,
        })
    });
    move || match key.get() {
        None => crate::shell::unreadable("Loading…".to_owned()).into_any(),
        Some(k) if k.is_empty() => view! { <StartStep ed/> }.into_any(),
        Some(_) => view! { <Editor ed/> }.into_any(),
    }
}

/// "What are you saving?": one box, a guess made on the device, type tiles.
#[component]
fn StartStep(ed: Memo<Option<qv_ui_api::Editor>>) -> impl IntoView {
    let guess = Memo::new(move |_| {
        ed.with(|e| match e {
            Some(qv_ui_api::Editor::Start { guess, .. }) => guess.clone(),
            _ => None,
        })
    });
    let types = Memo::new(move |_| {
        ed.with(|e| match e {
            Some(qv_ui_api::Editor::Start { types, .. }) => types.clone(),
            _ => Vec::new(),
        })
    });
    view! {
        <div class="phone-bar">
            <button class="icon-btn back" aria-label="Cancel" data-qv-clear="true" on:click=move |_| ui().act(Act::Back)><Svg icon=Icon::Close large=true/></button>
            <span class="sp"></span>
        </div>
        <div class="ie-start fade-in">
            <h2>"What are you saving?"</h2>
            <p class="lead">"Paste a website or a card number, or just type a name."</p>
            <div class="ie-omni" on:keydown=move |e: web_sys::KeyboardEvent| {
                if e.key() == "Enter" && guess.get_untracked().is_some() { e.prevent_default(); ui().act(Act::Ws(WsAct::StartAs(None))); }
            }>
                <Svg icon=Icon::Search/>
                <Input field=WsField::Start label="What are you saving?" kind=Kind::Line bare=true autofocus=true placeholder="github.com, 4242 4242…, Home Wi‑Fi"/>
            </div>
            {move || guess.get().map(|(g, line, sub)| {
                let kind = g.kind;
                view! {
                    <button class="ie-guess" id="start-guess" on:click=act(WsAct::StartAs(None))>
                        <span class=format!("tile {}", g.hue)><Svg icon=g.icon/></span>
                        <span class="t"><b>{line.to_string()}</b><span>{sub.to_string()}</span></span>
                        <kbd>"Enter ↵"</kbd>
                    </button>
                    <div class="ie-alts">
                        <span>"Or save it as"</span>
                        {types.get().into_iter().filter(|t| t.kind != kind && t.kind != qv_ui_api::ItemType::Other).map(|t| view! {
                            <button on:click=act(WsAct::StartAs(Some(t.kind)))>{t.name.clone()}</button>
                        }).collect_view()}
                    </div>
                }
            })}
            <div class="ie-kinds">
                {move || types.get().into_iter().map(|t| view! {
                    <button class="ie-kind" id=format!("start-{}", t.hint) on:click=act(WsAct::StartAs(Some(t.kind)))>
                        <span class=format!("tile {}", t.hue)><Svg icon=t.icon large=true/></span>
                        {t.name.clone()}
                    </button>
                }).collect_view()}
            </div>
            <div class="ie-offline"><Svg icon=Icon::Shield/>"Recognized on this device. Nothing is looked up online."</div>
        </div>
    }
}

/// How a row's value area shows (rebuilt only when this changes).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueMode {
    TooLarge,
    Generated,
    Saved,
    Protected,
    Multi,
    Security,
    Plain,
    /// A two-factor code: set up in its sheet, never typed (plan 0073).
    Totp,
}

fn value_mode(row: &FormRow, changing: bool) -> ValueMode {
    let protected_role = matches!(row.role, Role::Password | Role::Hidden | Role::CardNumber);
    if row.too_large {
        ValueMode::TooLarge
    } else if row.kind == FieldKind::Totp {
        ValueMode::Totp
    } else if protected_role && (row.generated || row.filled) && row.replaced {
        ValueMode::Generated
    } else if protected_role && row.stored && !row.replaced && !changing {
        ValueMode::Saved
    } else if protected_role || (row.protected && row.kind != FieldKind::Multiline) {
        ValueMode::Protected
    } else if row.protected {
        ValueMode::Multi
    } else if row.role == Role::Security {
        ValueMode::Security
    } else {
        ValueMode::Plain
    }
}

#[component]
fn Editor(ed: Memo<Option<qv_ui_api::Editor>>) -> impl IntoView {
    let form = Memo::new(move |_| {
        ed.with(|e| match e {
            Some(qv_ui_api::Editor::Form(f)) => Some((**f).clone()),
            _ => None,
        })
    });
    let ff = move |f: fn(&Form) -> String| {
        Memo::new(move |_| form.with(|x| x.as_ref().map(f).unwrap_or_default()))
    };
    let fb =
        move |f: fn(&Form) -> bool| Memo::new(move |_| form.with(|x| x.as_ref().is_some_and(f)));
    let adding = RwSignal::new(false);
    let add_kind = RwSignal::new(None::<FieldKind>);
    let renaming = RwSignal::new(None::<u16>);
    let changing = RwSignal::new(BTreeSet::<u16>::new());
    let notes_open =
        RwSignal::new(form.with_untracked(|f| f.as_ref().is_some_and(|f| f.notes_open)));
    let is_note = fb(|f| f.is_note);
    let totp_slot = fb(|f| f.totp_slot);
    let has_sheet = fb(|f| f.totp_sheet.is_some());
    let new = fb(|f| f.new);
    let ready = fb(|f| f.ready);
    let hue = ff(|f| f.hue.clone());
    let title = ff(|f| f.title.to_string());
    let type_name = ff(|f| f.type_name.clone());
    let popped = Memo::new(move |_| form.with(|f| f.as_ref().and_then(|f| f.pop)));
    let clear = move || if ready.get() { "true" } else { "false" };
    // Esc closes what is open before it reaches the root (which cancels).
    let keys = move |e: web_sys::KeyboardEvent| {
        if e.key() == "Escape" && (popped.get_untracked().is_some() || adding.get_untracked()) {
            e.stop_propagation();
            e.prevent_default();
            pop(None);
            adding.set(false);
        }
    };
    let heading = move || {
        if new.get() {
            format!("New {}", type_name.get().to_lowercase())
        } else {
            "Edit".to_owned()
        }
    };
    // The rows' structure; values update in place.
    let structure = Memo::new(move |_| {
        form.with(|f| {
            f.as_ref()
                .map(|f| {
                    f.rows
                        .iter()
                        .map(|r| (r.index, r.role, r.kind, r.protected))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        })
    });
    let row_view = move |index: u16, first: bool, last: bool| {
        let row = Memo::new(move |_| {
            form.with(|f| {
                f.as_ref()
                    .and_then(|f| f.rows.iter().find(|r| r.index == index).cloned())
            })
        });
        let name = Memo::new(move |_| {
            row.with(|r| r.as_ref().map(|r| r.name.to_string()).unwrap_or_default())
        });
        let open = Memo::new(move |_| popped.get() == Some(Pop::Field(index)));
        let mode = Memo::new(move |_| {
            row.with(|r| {
                r.as_ref()
                    .map(|r| value_mode(r, changing.get().contains(&index)))
            })
        });
        let role = row
            .with_untracked(|r| r.as_ref().map(|r| r.role))
            .unwrap_or(Role::Plain);
        let kind = row
            .with_untracked(|r| r.as_ref().map(|r| r.kind))
            .unwrap_or(FieldKind::Text);
        let protected = row.with_untracked(|r| r.as_ref().is_some_and(|r| r.protected));
        let card_number = role == Role::CardNumber;
        let showing =
            Memo::new(move |_| form.with(|f| f.as_ref().and_then(|f| f.showing)) == Some(index));
        let check = move || {
            row.with(|r| r.as_ref().and_then(|r| r.check.clone()))
                .map(|(t, class)| view! { <span class=class>{t}</span> })
        };
        let placeholder = row.with_untracked(|r| {
            r.as_ref()
                .map(|r| r.placeholder.clone())
                .unwrap_or_default()
        });
        let focus = form.with_untracked(|f| f.as_ref().and_then(|f| f.focus)) == Some(index);
        let gen_open = Memo::new(move |_| popped.get() == Some(Pop::Gen(index)));
        let gen_button = move || {
            (role == Role::Password).then(|| view! {
                <div class="pop-anchor">
                    <button class="ie-ib" id=format!("gen-{index}") aria-label="Generate a password" title="Generate"
                        on:click=move |_| pop(if gen_open.get_untracked() { None } else { Some(Pop::Gen(index)) })><Svg icon=Icon::Generator/></button>
                    {move || gen_open.get().then(|| view! { {scrim()}{generator(form, index)} })}
                </div>
            })
        };
        let label = move || {
            if renaming.get() == Some(index) {
                let done = move |e: web_sys::KeyboardEvent| {
                    if e.key() == "Enter" || e.key() == "Escape" {
                        e.stop_propagation();
                        e.prevent_default();
                        renaming.set(None);
                    }
                };
                view! {
                    <div class="ie-label renaming" on:keydown=done on:focusout=move |_| renaming.set(None)>
                        <Input field=WsField::FieldName(index) label="Field name" kind=Kind::Line value=Signal::derive(move || name.get()) bare=true autofocus=true/>
                    </div>
                }.into_any()
            } else {
                let target = if protected {
                    WsField::Replacement(index)
                } else {
                    WsField::FieldValue(index)
                };
                view! { <label class="ie-label" for=target.dom_id() title=move || name.get()>{move || name.get()}</label> }.into_any()
            }
        };
        let value = move || {
            let Some(m) = mode.get() else {
                return ().into_any();
            };
            match m {
                ValueMode::TooLarge => view! { <p class="hint">"This value is larger than the app can edit. View or copy it here, and edit it with the CLI."</p> }.into_any(),
                ValueMode::Generated => {
                    let shown = Memo::new(move |_| row.with(|r| r.as_ref().and_then(|r| r.shown.as_ref().map(|s| s.to_string()))));
                    let masked = row.with_untracked(|r| r.as_ref().map(|r| r.masked.clone()).unwrap_or_default());
                    let generated = row.with_untracked(|r| r.as_ref().is_some_and(|r| r.generated));
                    view! {
                        <div class="ie-box">
                            <div class="ie-saved generated">
                                {move || match shown.get() {
                                    None => view! { <span class="dots">{masked.clone()}</span> }.into_any(),
                                    Some(s) => view! { <span class="mono revealed">{s}</span> }.into_any(),
                                }}
                                {generated.then(|| view! { <span class="tag"><Svg icon=Icon::Generator/>"Generated"</span> })}
                                {move || if shown.get().is_none() {
                                    view! { <button class="ie-ib" aria-label="Show for 30 seconds" on:click=act(WsAct::Reveal(qv_ui_api::RevealKey::Replacement(index)))><Svg icon=Icon::Eye/></button> }.into_any()
                                } else {
                                    view! { <button class="ie-ib" aria-label="Hide" on:click=act(WsAct::Hide)><Svg icon=Icon::EyeOff/></button> }.into_any()
                                }}
                                <button class="ie-change" on:click=move |_| { set(WsField::Replacement(index), String::new()); changing.update(|c| { c.insert(index); }); }>"Change"</button>
                            </div>
                            {gen_button}
                        </div>
                    }.into_any()
                }
                ValueMode::Saved => view! {
                    <div class="ie-box">
                        <div class="ie-saved">
                            <span class="dots">{MASK}</span>
                            <span class="tag"><Svg icon=Icon::Lock/>"Saved"</span>
                            <button class="ie-change" id=format!("change-{index}") on:click=move |_| changing.update(|c| { c.insert(index); })>"Change"</button>
                        </div>
                    </div>
                }.into_any(),
                ValueMode::Protected => {
                    let stored = row.with_untracked(|r| r.as_ref().is_some_and(|r| r.stored));
                    let replaced = Memo::new(move |_| row.with(|r| r.as_ref().is_some_and(|r| r.replaced)));
                    let autofocus = changing.get_untracked().contains(&index);
                    let placeholder = placeholder.clone();
                    view! {
                        <div class="ie-box">
                            // A card number shows what is typed (grouped in fours),
                            // so the user can check it; it is still stored protected.
                            {move || {
                                let secret = !(showing.get() || card_number);
                                view! {
                                    <Input field=WsField::Replacement(index) label=name.get_untracked()
                                        kind=if secret { Kind::Secret } else { Kind::Line } bare=true class="mono"
                                        placeholder=placeholder.clone() autofocus=autofocus format=if card_number { "card" } else { "" }/>
                                }
                            }}
                            {check}
                            {move || if card_number {
                                ().into_any()
                            } else if showing.get() {
                                view! { <button class="ie-ib" aria-label="Hide" title="Hide" on:click=act(WsAct::Hide)><Svg icon=Icon::EyeOff/></button> }.into_any()
                            } else {
                                view! { <button class="ie-ib" aria-label="Show for 30 seconds" title="Show for 30 s" disabled=move || !replaced.get()
                                    on:click=act(WsAct::Reveal(qv_ui_api::RevealKey::Replacement(index)))><Svg icon=Icon::Eye/></button> }.into_any()
                            }}
                            {gen_button}
                            {move || (stored && changing.get().contains(&index)).then(|| view! {
                                <button class="ie-ib" aria-label="Keep the saved value" title="Keep the saved value"
                                    on:click=move |_| { set(WsField::Replacement(index), String::new()); changing.update(|c| { c.remove(&index); }); }><Svg icon=Icon::Close/></button>
                            })}
                        </div>
                    }.into_any()
                }
                ValueMode::Multi => {
                    let stored = row.with_untracked(|r| r.as_ref().is_some_and(|r| r.stored));
                    view! {
                        <div class="ie-box">
                            <Input field=WsField::Replacement(index) label=name.get_untracked() kind=Kind::Multi bare=true
                                placeholder=if stored { "Saved. Type to replace it" } else { "" }/>
                        </div>
                    }.into_any()
                }
                ValueMode::Security => {
                    let current = Memo::new(move |_| row.with(|r| r.as_ref().and_then(|r| r.value.as_ref().map(|v| v.to_string())).unwrap_or_default()));
                    let choices = form.with_untracked(|f| f.as_ref().map(|f| f.security.clone()).unwrap_or_default());
                    view! {
                        <div class="ie-seg" role="radiogroup" aria-label=move || name.get()>
                            {choices.into_iter().map(|(v, label)| {
                                let v2 = v.clone();
                                let v3 = v.clone();
                                view! {
                                    <button role="radio" class=move || if current.get().eq_ignore_ascii_case(&v) { "on" } else { "" }
                                        aria-checked=move || if current.get().eq_ignore_ascii_case(&v2) { "true" } else { "false" }
                                        on:click=move |_| set(WsField::FieldValue(index), v3.clone())>{label}</button>
                                }
                            }).collect_view()}
                        </div>
                    }.into_any()
                }
                ValueMode::Totp => {
                    let code = Signal::derive(move || row.with(|r| r.as_ref().and_then(|r| r.code.clone())));
                    let set_up = Memo::new(move |_| row.with(|r| r.as_ref().is_some_and(|r| r.stored || r.replaced)));
                    let has_code = Memo::new(move |_| code.with(Option::is_some));
                    view! {
                        <div class="ie-box ie-totp">
                            {move || if has_code.get() {
                                view! {
                                    {crate::items::code_view(code)}
                                    <button class="ie-change" id=format!("totp-replace-{index}") on:click=act(WsAct::TotpOpen(Some(index)))>"Replace"</button>
                                }.into_any()
                            } else if set_up.get() {
                                view! {
                                    <span class="hint">"This setup can't make codes."</span>
                                    <button class="ie-change" id=format!("totp-replace-{index}") on:click=act(WsAct::TotpOpen(Some(index)))>"Set up again"</button>
                                }.into_any()
                            } else {
                                view! {
                                    <button class="btn" id=format!("totp-setup-{index}") on:click=act(WsAct::TotpOpen(Some(index)))><Svg icon=Icon::Shield/>"Set up"</button>
                                }.into_any()
                            }}
                        </div>
                    }.into_any()
                }
                ValueMode::Plain => {
                    let multi = kind == FieldKind::Multiline;
                    let mono = if role == Role::Expiry { "mono" } else { "" };
                    let value = Signal::derive(move || row.with(|r| r.as_ref().and_then(|r| r.value.as_ref().map(|v| v.to_string())).unwrap_or_default()));
                    view! {
                        <div class="ie-box">
                            <Input field=WsField::FieldValue(index) label=name.get_untracked() kind=if multi { Kind::Multi } else { Kind::Line }
                                value=value bare=true class=mono placeholder=placeholder.clone() autofocus=focus/>
                            {check}
                        </div>
                    }.into_any()
                }
            }
        };
        let can_hide =
            kind != FieldKind::Totp && !matches!(role, Role::CardNumber | Role::Security);
        let label = move || {
            if kind == FieldKind::Totp && renaming.get() != Some(index) {
                // Nothing to focus: the code is set up in its sheet.
                view! { <span class="ie-label" title=move || name.get()>{move || name.get()}</span> }.into_any()
            } else {
                label().into_any()
            }
        };
        let menu_item = move |a: WsAct| {
            move |_| {
                pop(None);
                ui().act(Act::Ws(a.clone()));
            }
        };
        view! {
            <div class=move || if open.get() { "ie-row open" } else { "ie-row" }>
                {label}
                {value}
                <div class="pop-anchor">
                    <button class="ie-ib ie-more" id=format!("field-more-{index}") aria-label=move || format!("Options for {}", name.get()) aria-haspopup="menu"
                        aria-expanded=move || if open.get() { "true" } else { "false" }
                        on:click=move |_| pop(if open.get_untracked() { None } else { Some(Pop::Field(index)) })>
                        <Svg icon=Icon::More/>
                    </button>
                    {move || open.get().then(|| view! {
                        {scrim()}
                        <div class="menu pop end" role="menu">
                            <button class="mi" role="menuitem" on:click=move |_| { pop(None); renaming.set(Some(index)); }><Svg icon=Icon::Edit/>"Rename"</button>
                            {can_hide.then(|| view! {
                                <button class="mi" role="menuitem" id=format!("field-protect-{index}") on:click=menu_item(WsAct::ToggleProtect(index))>
                                    {if protected { view! { <Svg icon=Icon::Eye/>"Show the value normally" }.into_any() } else { view! { <Svg icon=Icon::Lock/>"Hide the value" }.into_any() }}
                                </button>
                            })}
                            {(!first).then(|| view! { <button class="mi" role="menuitem" on:click=menu_item(WsAct::MoveField(index, true))><Svg icon=Icon::Up/>"Move up"</button> })}
                            {(!last).then(|| view! { <button class="mi" role="menuitem" on:click=menu_item(WsAct::MoveField(index, false))><Svg icon=Icon::ChevronDown/>"Move down"</button> })}
                            <hr/>
                            <button class="mi danger" role="menuitem" id=format!("field-remove-{index}") on:click=menu_item(WsAct::RemoveField(index))><Svg icon=Icon::Trash/>"Remove field"</button>
                        </div>
                    })}
                </div>
            </div>
        }
    };
    let fields = move || {
        view! {
            {move || {
                let rows = structure.get();
                let n = rows.len();
                (!rows.is_empty()).then(|| view! {
                    <div class="ie-fields">
                        {rows.into_iter().enumerate().map(|(i, (index, ..))| row_view(index, i == 0, i + 1 == n)).collect_view()}
                    </div>
                })
            }}
            {move || totp_slot.get().then(|| view! {
                <div class="ie-fields ie-slot">
                    <div class="ie-row">
                        <span class="ie-label">"Two-factor code"</span>
                        <div class="ie-box ie-totp">
                            <button class="btn" id="totp-setup" on:click=act(WsAct::TotpOpen(None))><Svg icon=Icon::Shield/>"Set up"</button>
                            <span class="hint">"The six-digit codes a site asks for after your password"</span>
                        </div>
                    </div>
                </div>
            })}
            {move || form.with(|f| f.as_ref().and_then(|f| f.removed.clone())).map(|name| view! {
                <div class="ie-undo" role="status"><span>{format!("Removed “{}”", name.as_str())}</span><button id="undo-remove" on:click=act(WsAct::UndoRemoveField)>"Undo"</button></div>
            })}
            {adder(form, adding, add_kind, popped)}
        }
    };
    let notes_value = ff(|f| f.notes.to_string());
    let notes = move || {
        view! {
            <div class="ie-notes">
                {move || if form.with(|f| f.as_ref().is_some_and(|f| f.notes_too_large)) {
                    view! { <p class="hint">"This value is larger than the app can edit. View or copy it here, and edit it with the CLI."</p> }.into_any()
                } else if notes_open.get() {
                    let focus = form.with_untracked(|f| f.as_ref().is_some_and(|f| f.notes_focus));
                    view! {
                        <Input field=WsField::Notes label="Notes" kind=Kind::Multi value=Signal::derive(move || notes_value.get()) bare=true class="ie-notearea"
                            placeholder=if is_note.get_untracked() { "Start writing…" } else { "Notes" } autofocus=focus/>
                    }.into_any()
                } else {
                    view! { <button class="ie-notelink" id="add-note" on:click=move |_| notes_open.set(true)><Svg icon=Icon::Note/>"Add a note"</button> }.into_any()
                }}
            </div>
        }
    };
    let title_focus = form.with_untracked(|f| f.as_ref().is_some_and(|f| f.title_focus));
    let placeholder = form.with_untracked(|f| {
        f.as_ref()
            .map(|f| f.placeholder.to_string())
            .unwrap_or_default()
    });
    view! {
        <div class="phone-bar">
            <button class="icon-btn back" aria-label="Cancel" data-qv-clear="true" on:click=move |_| ui().act(Act::Back)><Svg icon=Icon::Close large=true/></button>
            <b class="ie-pbar-t">{heading}</b>
            <button class="btn primary" data-qv-clear=clear on:click=act(WsAct::SaveEntry)>{move || if new.get() { "Create" } else { "Save" }}</button>
        </div>
        <div class=move || if is_note.get() { "detail-inner ie isnote fade-in" } else { "detail-inner ie fade-in" } on:keydown=keys>
            <div class="ie-head">
                <div class="pop-anchor">
                    <button class=move || format!("tile ie-tile {}", hue.get()) id="item-colour" aria-label="Choose a color" title="Color"
                        on:click=move |_| pop(if popped.get_untracked() == Some(Pop::Colour) { None } else { Some(Pop::Colour) })>
                        {move || form.with(|f| f.as_ref().map(|f| f.icon)).map(|i| view! { <Svg icon=i large=true/> })}
                    </button>
                    {move || (popped.get() == Some(Pop::Colour)).then(|| view! { {scrim()}{swatches(form.with_untracked(|f| f.as_ref().and_then(|f| f.colour)), "menu pop")} })}
                </div>
                <div class="ie-grow">
                    <Input field=WsField::Title label="Title" kind=Kind::Line value=Signal::derive(move || title.get()) bare=true class="ie-title"
                        placeholder=placeholder autofocus=title_focus/>
                    <div class="ie-chips">
                        <div class="pop-anchor">
                            <button class="ie-chip" id="type-chip" aria-haspopup="menu"
                                on:click=move |_| pop(if popped.get_untracked() == Some(Pop::Type) { None } else { Some(Pop::Type) })>
                                {move || form.with(|f| f.as_ref().map(|f| f.icon)).map(|i| view! { <Svg icon=i/> })}{move || type_name.get()}<Svg icon=Icon::ChevronDown/>
                            </button>
                            {move || (popped.get() == Some(Pop::Type)).then(|| {
                                let (types, kind) = form.with_untracked(|f| f.as_ref().map(|f| (f.types.clone(), f.kind)).unwrap_or((Vec::new(), qv_ui_api::ItemType::Other)));
                                view! {
                                    {scrim()}
                                    <div class="menu pop" role="menu">
                                        <div class="label">"WHAT IT IS"</div>
                                        {types.into_iter().map(|t| {
                                            let k = t.kind;
                                            view! {
                                                <button class="mi" role="menuitem" id=format!("type-{}", t.hint) on:click=move |_| { pop(None); ui().act(Act::Ws(WsAct::SetType(k))); }>
                                                    <Svg icon=t.icon/>{t.name.clone()}
                                                    {(kind == k).then(|| view! { <span class="sub"><Svg icon=Icon::Check/></span> })}
                                                </button>
                                            }
                                        }).collect_view()}
                                    </div>
                                }
                            })}
                        </div>
                        <div class="pop-anchor">
                            <button class="ie-chip" id="group-chip" aria-haspopup="menu"
                                on:click=move |_| pop(if popped.get_untracked() == Some(Pop::Group) { None } else { Some(Pop::Group) })>
                                {move || match form.with(|f| f.as_ref().and_then(|f| f.group.clone())) {
                                    Some((name, h)) => view! { <span class=format!("ie-dot {h}")></span>{name.to_string()} }.into_any(),
                                    None => "Group".into_any(),
                                }}
                                <Svg icon=Icon::ChevronDown/>
                            </button>
                            {move || (popped.get() == Some(Pop::Group)).then(|| view! {
                                {scrim()}
                                <div class="menu pop" role="menu">
                                    <div class="label">"SAVE IN"</div>
                                    {form.with(|f| f.as_ref().and_then(|f| f.group_choices.clone())).map(|c| group_choices(c, move |g| { pop(None); ui().act(Act::Ws(WsAct::SetGroup(g))); }))}
                                </div>
                            })}
                        </div>
                        {move || form.with(|f| f.as_ref().and_then(|f| f.auto_from.clone())).map(|from| view! { <span class="ie-auto">{format!("Title from {from}")}</span> })}
                    </div>
                </div>
            </div>
            {move || form.with(|f| f.as_ref().and_then(|f| f.card.clone().map(|c| (c, f.hue.clone())))).map(|(c, h)| crate::items::card_face(&c, &h))}
            {move || form.with(|f| f.as_ref().and_then(|f| f.wifi.clone())).map(|(name, security)| view! {
                <div class="ie-wifi">
                    <span class="ie-qr"><Svg icon=Icon::Qr large=true/></span>
                    <div class="min0">
                        <b>{if name.is_empty() { "Network name".to_owned() } else { name.to_string() }}</b>
                        <span>"After you save, the item's page can show a code that phones scan to join."</span>
                        <span class="ie-sec">{security}</span>
                    </div>
                </div>
            })}
            {move || if is_note.get() { view! { {notes()}{fields()} }.into_any() } else { view! { {fields()}{notes()} }.into_any() }}
            {move || has_sheet.get().then(|| totp_sheet(form))}
            <div class="savebar desk-only">
                <span>"Esc cancels · Ctrl S saves"</span>
                <button class="btn subtle" data-qv-clear="true" on:click=move |_| ui().act(Act::Back)>"Cancel"</button>
                <button class="btn primary" id="entry-save" data-qv-clear=clear on:click=act(WsAct::SaveEntry)>{move || if new.get() { "Create item" } else { "Save changes" }}</button>
            </div>
        </div>
    }
}

/// The two-factor setup sheet, in the order sites present it: scan the QR
/// code, or enter the setup key (or paste the link). Rust checks the input
/// once typing pauses and shows the current code, which sites ask for to
/// finish (0009 §1.8, plan 0073). Mounted once; its parts update in place.
fn totp_sheet(form: Memo<Option<Form>>) -> impl IntoView {
    use qv_ui_api::{OtpHash, TotpOptions, TotpState};
    let sheet = Memo::new(move |_| form.with(|f| f.as_ref().and_then(|f| f.totp_sheet.clone())));
    let state = Memo::new(move |_| {
        sheet.with(|s| s.as_ref().map_or(TotpState::Empty, |s| s.state.clone()))
    });
    let scanned = Memo::new(move |_| sheet.with(|s| s.as_ref().is_some_and(|s| s.scanned)));
    let can_scan = sheet.with_untracked(|s| s.as_ref().is_some_and(|s| s.can_scan));
    let replacing = sheet.with_untracked(|s| s.as_ref().is_some_and(|s| s.replacing));
    let options = Memo::new(move |_| {
        sheet
            .with(|s| s.as_ref().map(|s| s.options))
            .unwrap_or(TotpOptions {
                digits: 6,
                period: 30,
                hash: OtpHash::Sha1,
            })
    });
    let valid =
        Memo::new(move |_| state.with(|s| matches!(s, TotpState::Key(_) | TotpState::Link(_))));
    let is_key = Memo::new(move |_| state.with(|s| !matches!(s, TotpState::Link(_))));
    let code = Signal::derive(move || {
        state.with(|s| match s {
            TotpState::Key(c) | TotpState::Link(c) => c.clone(),
            _ => None,
        })
    });
    let more = RwSignal::new(false);
    let set = move |f: fn(&mut TotpOptions)| {
        move |_| {
            let mut o = options.get_untracked();
            f(&mut o);
            ui().act(Act::Ws(WsAct::TotpOptions(o)));
        }
    };
    let close = move || ui().act(Act::Ws(WsAct::TotpClose));
    let keys = move |e: web_sys::KeyboardEvent| {
        if e.key() == "Escape" {
            e.stop_propagation();
            e.prevent_default();
            close();
        } else if e.key() == "Enter" && valid.get_untracked() {
            e.prevent_default();
            ui().act(Act::Ws(WsAct::TotpAdd));
        }
    };
    let seg = move |label: &'static str, on: Memo<bool>, pick: fn(&mut TotpOptions)| {
        view! {
            <button role="radio" class=move || if on.get() { "on" } else { "" }
                aria-checked=move || if on.get() { "true" } else { "false" } on:click=set(pick)>{label}</button>
        }
    };
    let opt = move |f: fn(&TotpOptions) -> bool| Memo::new(move |_| f(&options.get()));
    view! {
        <div class="layer" on:keydown=keys>
            <button class="scrim" aria-label="Close" on:click=move |_| close()></button>
            <div class="dialog totp-sheet" role="dialog" aria-modal="true" aria-label="Two-factor code" id="totp-sheet">
                <h3>{if replacing { "Replace the two-factor code" } else { "Set up a two-factor code" }}</h3>
                <p>"On the site, turn on two-factor authentication (it may say 2FA or authenticator app). It shows a QR code."</p>
                {can_scan.then(|| view! {
                    <button class="btn primary totp-scan" id="totp-scan" data-qv-clear="true" on:click=move |_| ui().act(Act::RequestQr(qv_ui_api::QrTarget::Totp))>
                        <Svg icon=Icon::Qr/>"Scan the QR code"
                    </button>
                })}
                <div class="field">
                    <label for=WsField::TotpInput.dom_id()>{if can_scan { "Or enter the setup key" } else { "Enter the setup key" }}</label>
                    {move || if scanned.get() {
                        view! { <p class="banner ok" role="status" id="totp-scanned"><Svg icon=Icon::Check/>" Code from the QR code"</p> }.into_any()
                    } else {
                        view! { <Input field=WsField::TotpInput label="Setup key" kind=Kind::Secret bare=true autofocus=!can_scan reveal=true rate=true
                            class="mono" placeholder="ABCD EFGH IJKL MNOP"/> }.into_any()
                    }}
                    <p class="hint">"Sites show it under “Can't scan it?” or “Enter a key manually”. A pasted otpauth:// link works too."</p>
                </div>
                {move || match state.get() {
                    TotpState::Invalid(why) => view! { <p class="hint bad" role="status" id="totp-invalid">{why}</p> }.into_any(),
                    TotpState::Key(_) | TotpState::Link(_) => view! {
                        <div class="totp-now" role="status" id="totp-now">
                            <span class="k">"Your code now"</span>
                            {crate::items::code_view(code)}
                            <span class="hint">"If the site asks for a code to finish, type this one."</span>
                        </div>
                    }.into_any(),
                    TotpState::Empty => ().into_any(),
                }}
                {move || is_key.get().then(|| view! {
                    <details class="totp-more" prop:open=move || more.get() on:toggle=move |e| more.set(event_target::<web_sys::HtmlDetailsElement>(&e).open())>
                        <summary>"More options"</summary>
                        <p class="hint">"Only if the site lists them. Most use 6 digits every 30 seconds."</p>
                        <div class="ie-seg" role="radiogroup" aria-label="Digits">
                            {seg("6 digits", opt(|o| o.digits == 6), |o| o.digits = 6)}
                            {seg("7", opt(|o| o.digits == 7), |o| o.digits = 7)}
                            {seg("8", opt(|o| o.digits == 8), |o| o.digits = 8)}
                        </div>
                        <div class="ie-seg" role="radiogroup" aria-label="Period">
                            {seg("Every 30 s", opt(|o| o.period == 30), |o| o.period = 30)}
                            {seg("60 s", opt(|o| o.period == 60), |o| o.period = 60)}
                        </div>
                        <div class="ie-seg" role="radiogroup" aria-label="Algorithm">
                            {seg("SHA-1", opt(|o| o.hash == OtpHash::Sha1), |o| o.hash = OtpHash::Sha1)}
                            {seg("SHA-256", opt(|o| o.hash == OtpHash::Sha256), |o| o.hash = OtpHash::Sha256)}
                            {seg("SHA-512", opt(|o| o.hash == OtpHash::Sha512), |o| o.hash = OtpHash::Sha512)}
                        </div>
                    </details>
                })}
                <div class="actions">
                    <button class="btn subtle" data-qv-clear="true" on:click=move |_| close()>"Cancel"</button>
                    <button class="btn primary" id="totp-add" data-qv-clear="true" disabled=move || !valid.get()
                        on:click=act(WsAct::TotpAdd)>{if replacing { "Replace" } else { "Add" }}</button>
                </div>
            </div>
        </div>
    }
}

/// The generator popover. "Use it" moves the value into the field in Rust;
/// it never passes through the page.
fn generator(form: Memo<Option<Form>>, index: u16) -> impl IntoView {
    let g = Memo::new(move |_| form.with(|f| f.as_ref().and_then(|f| f.generator.clone())));
    let regen = move |a: WsAct| {
        move |_| {
            ui().act(Act::Ws(a.clone()));
            ui().act(Act::Ws(WsAct::Generate));
        }
    };
    move || {
        g.get().map(|g| {
            let words = g.words;
            let has_value = g.value.is_some();
            view! {
                <div class="menu pop end ie-gen" role="dialog" aria-label="Generate a password">
                    <div class="out mono revealed" id="gen-value">{g.value.as_ref().map_or_else(|| "…".to_owned(), |v| v.to_string())}</div>
                    <label><span>{if words { "Words" } else { "Length" }}</span><b>{g.n.to_string()}</b></label>
                    <input type="range" id="gen-range" min=g.min.to_string() max=g.max.to_string() prop:value=g.n.to_string()
                        aria-label=if words { "Words" } else { "Length" }
                        on:input=move |e| { set(if words { WsField::GenWords } else { WsField::GenLength }, event_target_value(&e)); ui().act(Act::Ws(WsAct::Generate)); }/>
                    <div class="sw-row"><span>"Use words"</span>
                        <button class="sw" role="switch" aria-label="Use words" aria-checked=if words { "true" } else { "false" }
                            on:click=regen(WsAct::GenMode(if words { qv_ui_api::GenMode::Characters } else { qv_ui_api::GenMode::Words }))></button>
                    </div>
                    {(!words).then(|| view! {
                        <div class="sw-row"><span>"Symbols"</span>
                            <button class="sw" role="switch" aria-label="Symbols" aria-checked=if g.symbols { "true" } else { "false" } on:click=regen(WsAct::GenToggle(qv_ui_api::GenFlag::Symbols))></button>
                        </div>
                    })}
                    {g.bits.clone().map(|b| view! { <p class="ie-bits">{b}</p> })}
                    <div class="ie-genacts">
                        <button class="btn" on:click=act(WsAct::Generate)><Svg icon=Icon::Refresh/>"Again"</button>
                        <button class="btn primary" id="gen-use" disabled=!has_value on:click=move |_| { pop(None); ui().act(Act::Ws(WsAct::UseGenerated(index))); }>"Use it"</button>
                    </div>
                </div>
            }
        })
    }
}

/// "Add a field": a name box whose kind follows the name, with a few common
/// names for the item's type.
fn adder(
    form: Memo<Option<Form>>,
    adding: RwSignal<bool>,
    add_kind: RwSignal<Option<FieldKind>>,
    popped: Memo<Option<Pop>>,
) -> impl IntoView {
    let commit = move || {
        ui().act(Act::Ws(WsAct::AddField(add_kind.get_untracked())));
        add_kind.set(None);
        adding.set(false);
    };
    move || {
        if !adding.get() {
            return view! {
                <div class="ie-addrow">
                    <button class="ie-addbtn" id="add-field" on:click=move |_| { add_kind.set(None); adding.set(true); }><Svg icon=Icon::Plus/>"Add a field"</button>
                </div>
            }
            .into_any();
        }
        let kind_open = Memo::new(move |_| popped.get() == Some(Pop::Kind));
        let label = move |k: FieldKind| {
            form.with(|f| {
                f.as_ref().and_then(|f| {
                    f.kind_labels
                        .iter()
                        .find(|(x, _)| *x == k)
                        .map(|(_, l)| l.clone())
                })
            })
            .unwrap_or_default()
        };
        let shown = move || {
            add_kind
                .get()
                .or_else(|| form.with(|f| f.as_ref().map(|f| f.new_kind)))
                .unwrap_or(FieldKind::Text)
        };
        let common =
            form.with_untracked(|f| f.as_ref().map(|f| f.common.clone()).unwrap_or_default());
        let add_kinds =
            form.with_untracked(|f| f.as_ref().map(|f| f.add_kinds.clone()).unwrap_or_default());
        view! {
            <div class="ie-addrow">
                <div class="ie-adder">
                    <div class="ie-box dashed" on:keydown=move |e: web_sys::KeyboardEvent| {
                        if e.key() == "Enter" { e.prevent_default(); commit(); }
                        else if e.key() == "Escape" { e.stop_propagation(); e.prevent_default(); adding.set(false); }
                    }>
                        <Input field=WsField::NewFieldName label="Field name" kind=Kind::Line bare=true autofocus=true placeholder="Name the field, like PIN or Email"/>
                        <div class="pop-anchor">
                            <button class="ie-kindpill" id="add-kind" aria-label="Kind of field" on:click=move |_| pop(if kind_open.get_untracked() { None } else { Some(Pop::Kind) })>
                                {move || label(shown())}<Svg icon=Icon::ChevronDown/>
                            </button>
                            {move || kind_open.get().then(|| view! {
                                {scrim()}
                                <div class="menu pop end" role="menu">
                                    <div class="label">"KIND OF FIELD"</div>
                                    {add_kinds.clone().into_iter().map(|(k, l)| view! {
                                        <button class="mi" role="menuitem" on:click=move |_| { add_kind.set(Some(k)); pop(None); }>
                                            {l}{(k == shown()).then(|| view! { <span class="sub"><Svg icon=Icon::Check/></span> })}
                                        </button>
                                    }).collect_view()}
                                </div>
                            })}
                        </div>
                        <button class="ie-ib" id="add-field-ok" aria-label="Add the field" title="Add" on:click=move |_| commit()><Svg icon=Icon::Check/></button>
                        <button class="ie-ib" aria-label="Cancel" title="Cancel" on:click=move |_| adding.set(false)><Svg icon=Icon::Close/></button>
                    </div>
                    <div class="ie-quick">
                        <span>"Common:"</span>
                        {common.into_iter().enumerate().map(|(i, name)| view! {
                            <button on:click=move |_| { ui().act(Act::Ws(WsAct::AddNamedField(i as u8))); adding.set(false); }>{name}</button>
                        }).collect_view()}
                    </div>
                </div>
            </div>
        }
        .into_any()
    }
}

/// Group editing: the name and the colour (0003 §5.5).
#[component]
pub(crate) fn EditGroup(inner: Memo<Option<DetailInner>>) -> impl IntoView {
    let g = Memo::new(move |_| {
        inner.with(|i| match i {
            Some(DetailInner::EditGroup(g)) => Some(g.clone()),
            _ => None,
        })
    });
    let name =
        Memo::new(move |_| g.with(|g| g.as_ref().map(|g| g.name.to_string()).unwrap_or_default()));
    let colour = Memo::new(move |_| g.with(|g| g.as_ref().and_then(|g| g.colour)));
    view! {
        <div class="phone-bar"><button class="icon-btn back" aria-label="Cancel" on:click=move |_| ui().act(Act::Back)><Svg icon=Icon::Close large=true/></button></div>
        <div class="detail-inner fade-in">
            <div class="hero"><span class=move || format!("tile {}", g.with(|g| g.as_ref().map(|g| g.hue.clone()).unwrap_or_default()))><Svg icon=Icon::Folder large=true/></span>
                <h1>{move || if g.with(|g| g.as_ref().is_some_and(|g| g.new)) { "New group" } else { "Edit group" }}</h1>
            </div>
            <div class="card"><div class="ed">
                <label for="ws-group-name">"Name"</label>
                <Input field=WsField::GroupName label="Name" kind=Kind::Line value=Signal::derive(move || name.get()) bare=true autofocus=true placeholder="Group name"/>
            </div></div>
            {move || swatches(colour.get(), "card ie-colours")}
            <div class="actions">
                <button class="btn subtle" on:click=move |_| ui().act(Act::Back)>"Cancel"</button>
                <button class="btn primary" id="group-save" on:click=act(WsAct::SaveGroup)>"Save"</button>
            </div>
        </div>
    }
}
