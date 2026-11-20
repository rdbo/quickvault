// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sections beside the vault: generator, sync,
//! trash, conflicts, snapshots, archives, settings and autofill. File
//! choices use the system picker; a typed path appears only without one.
use crate::icons::{Icon, Logo, Svg};
use crate::input::{Input, Kind};
use crate::shell::{PageNavBar, act, field, go, report_card, unreadable};
use crate::ui;
use leptos::prelude::*;
use qv_ui_api::{
    Act, Cell, Content, GenFlag, GenMode, PageBody, Pane, Picker, QuickPolicy, Screen,
    SettingsBody, Shell as S, WsAct, WsField,
};

fn set(field: WsField, value: String) {
    ui().input(qv_ui_api::Field::Ws(field), &value);
}

/// A page heading with a back button where the page is nested.
fn head(title: String, lead: String, nested: bool) -> impl IntoView {
    view! {
        {nested.then(|| view! {
            <div class="phone-bar head-bar">
                <button class="icon-btn back" aria-label="Back" on:click=move |_| ui().act(Act::Back)><Svg icon=Icon::Back large=true/></button>
            </div>
            <button class="link desk-only mb" on:click=move |_| ui().act(Act::Back)>"‹ Back"</button>
        })}
        <h1>{title}</h1>
        {(!lead.is_empty()).then(|| view! { <p class="lead">{lead}</p> })}
    }
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

/// One section page.
#[component]
pub(crate) fn Page(s: Memo<Option<S>>) -> impl IntoView {
    let p = field(s, None, |s| match &s.content {
        Content::Page(p) => Some((**p).clone()),
        _ => None,
    });
    // Every page switch rebuilds the wrapper, so it fades in again.
    let key = Memo::new(move |_| p.with(|p| p.as_ref().map(|p| p.key.clone()).unwrap_or_default()));
    let report = Memo::new(move |_| p.with(|p| p.as_ref().and_then(|p| p.report.clone())));
    let body = Memo::new(move |_| p.with(|p| p.as_ref().map(|p| p.body.clone())));
    let busy = field(s, false, |s| s.busy);
    view! {
        <section class="page">
            {move || {
                let _ = key.get();
                view! {
                    <div class="page-inner fade-in">
                        {move || report.get().map(report_card)}
                        <PageBodyView body busy/>
                    </div>
                }
            }}
        </section>
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Which {
    None,
    Unreadable,
    Generator,
    Devices,
    Trash,
    Conflicts,
    Compare,
    Snapshots,
    Archives,
    Settings(Pane),
    Autofill,
}

#[component]
fn PageBodyView(body: Memo<Option<PageBody>>, busy: Memo<bool>) -> impl IntoView {
    let which = Memo::new(move |_| {
        body.with(|b| match b {
            None | Some(PageBody::Empty) => Which::None,
            Some(PageBody::Unreadable(_)) => Which::Unreadable,
            Some(PageBody::Generator(_)) => Which::Generator,
            Some(PageBody::Devices(_)) => Which::Devices,
            Some(PageBody::Trash(_)) => Which::Trash,
            Some(PageBody::Conflicts(_)) => Which::Conflicts,
            Some(PageBody::Compare(_)) => Which::Compare,
            Some(PageBody::Snapshots(_)) => Which::Snapshots,
            Some(PageBody::Archives(_)) => Which::Archives,
            Some(PageBody::Settings(s)) => Which::Settings(s.pane),
            Some(PageBody::Autofill(_)) => Which::Autofill,
        })
    });
    move || match which.get() {
        Which::None => ().into_any(),
        Which::Unreadable => (move || match body.get() {
            Some(PageBody::Unreadable(m)) => unreadable(m).into_any(),
            _ => ().into_any(),
        })
        .into_any(),
        Which::Generator => generator(body).into_any(),
        Which::Devices => devices(body, busy).into_any(),
        Which::Trash => trash(body).into_any(),
        Which::Conflicts => conflicts(body).into_any(),
        Which::Compare => compare(body).into_any(),
        Which::Snapshots => snapshots(body).into_any(),
        Which::Archives => archives(body).into_any(),
        Which::Settings(pane) => settings(body, pane).into_any(),
        Which::Autofill => autofill(body).into_any(),
    }
}

fn generator(body: Memo<Option<PageBody>>) -> impl IntoView {
    let g = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Generator(g)) => Some(g.clone()),
            _ => None,
        })
    });
    let exclude = Memo::new(move |_| {
        g.with(|g| {
            g.as_ref()
                .map(|g| g.exclude.to_string())
                .unwrap_or_default()
        })
    });
    let mode = Memo::new(move |_| g.with(|g| g.as_ref().map(|g| g.mode)));
    view! {
        {head("Generator".into(), "Strong passwords and passphrases, made on this device.".into(), false)}
        {move || g.get().map(|g| {
            let value = g.value.as_ref().map(|v| v.to_string()).unwrap_or_default();
            let bits = g.bits.unwrap_or(0.0);
            let pct = (bits / 1.28).clamp(0.0, 100.0);
            let meter = if bits < 50.0 { "meter weak" } else if bits < 64.0 { "meter fair" } else { "meter" };
            let empty = value.is_empty();
            view! {
                <div class="gen-out">
                    {if empty {
                        view! { <div class="gen-pw empty-gen">"Choose your settings, then generate."</div> }.into_any()
                    } else {
                        view! {
                            <div class="gen-pw mono revealed" id="generated">
                                {value.chars().map(|ch| {
                                    let class = if ch.is_ascii_digit() { "d" } else if ch.is_alphabetic() || ch == ' ' { "" } else { "s" };
                                    view! { <span class=class>{ch.to_string()}</span> }
                                }).collect_view()}
                            </div>
                        }.into_any()
                    }}
                    <div class=meter><b class=format!("w{}", (pct / 10.0).round() as u32)></b></div>
                    <div class="meter-l">
                        <span>{g.bits.map_or_else(|| "Impossible settings".to_owned(), |b| format!("{b:.1} bits"))}</span>
                        <span>{g.bits.map(strength_label).unwrap_or("")}</span>
                    </div>
                    {g.bits.is_some_and(|b| b < 64.0).then(|| view! { <p class="hint" role="status">"Low strength: less than 64 bits. Consider a longer password or passphrase."</p> })}
                    <div class="gen-acts">
                        <button class="btn" id="generate" on:click=act(WsAct::Generate)><Svg icon=Icon::Refresh/>{if empty { "Generate" } else { "New" }}</button>
                        {(!empty).then(|| view! { <button class="btn primary" id="generated-copy" on:click=act(WsAct::Copy(qv_ui_api::CopyKey::Generated))><Svg icon=Icon::Copy/>"Copy"</button> })}
                    </div>
                    {(!empty).then(|| view! { <p class="hint">"Visible for 30 seconds."</p> })}
                </div>
                <div class="seg mt" role="tablist">
                    {[(GenMode::Characters, "Random"), (GenMode::Words, "Passphrase"), (GenMode::Pin, "PIN")].into_iter().map(|(m, label)| view! {
                        <button class=if g.mode == m { "on" } else { "" } role="tab" on:click=act(WsAct::GenMode(m))>{label}</button>
                    }).collect_view()}
                </div>
            }
        })}
        <div class="opts">
            {move || g.get().map(|g| {
                let flags: Vec<(GenFlag, &str, &str, usize)> = match g.mode {
                    GenMode::Characters => vec![
                        (GenFlag::Lower, "Lowercase letters", "a–z", 0),
                        (GenFlag::Upper, "Uppercase letters", "A–Z", 1),
                        (GenFlag::Digits, "Digits", "0–9", 2),
                        (GenFlag::Symbols, "Symbols", "!#$%", 3),
                        (GenFlag::Ambiguous, "Avoid look-alikes", "no 0/O, 1/l", 4),
                        (GenFlag::Each, "Use every enabled class", "at least one of each", 7),
                    ],
                    GenMode::Words => vec![
                        (GenFlag::Capitalize, "Capitalize", "Cedar-Ripple-Orbit", 5),
                        (GenFlag::AppendDigit, "Add a digit", "…-orbit7", 6),
                    ],
                    GenMode::Pin => Vec::new(),
                };
                let sliders = match g.mode {
                    GenMode::Characters => view! {
                        <div class="opt"><div class="l"><b>"Length"</b><span>"8–256 characters"</span></div>
                            <div class="slider"><input type="range" id="ws-gen-length" min="8" max="128" prop:value=g.length.to_string() aria-label="Length" on:input=move |e| set(WsField::GenLength, event_target_value(&e))/><output>{g.length.to_string()}</output></div>
                        </div>
                    }.into_any(),
                    GenMode::Words => {
                        let sep = g.separator.clone();
                        view! {
                            <div class="opt"><div class="l"><b>"Words"</b><span>"3–20"</span></div>
                                <div class="slider"><input type="range" id="ws-gen-words" min="3" max="20" prop:value=g.words.to_string() aria-label="Words" on:input=move |e| set(WsField::GenWords, event_target_value(&e))/><output>{g.words.to_string()}</output></div>
                            </div>
                            <div class="opt"><div class="l"><b>"Separator"</b></div>
                                <div class="seg fixed">
                                    {["-", ".", "_", " "].into_iter().map(|s| view! {
                                        <button class=if sep == s { "on narrow" } else { "narrow" } on:click=move |_| set(WsField::GenSeparator, s.to_owned())>{if s == " " { "␣" } else { s }}</button>
                                    }).collect_view()}
                                </div>
                            </div>
                        }.into_any()
                    }
                    GenMode::Pin => view! {
                        <div class="opt"><div class="l"><b>"Digits"</b><span>"4–32"</span></div>
                            <div class="slider"><input type="range" id="ws-gen-length" min="4" max="32" prop:value=g.pin.to_string() aria-label="Digits" on:input=move |e| set(WsField::GenLength, event_target_value(&e))/><output>{g.pin.to_string()}</output></div>
                        </div>
                    }.into_any(),
                };
                view! {
                    {sliders}
                    {flags.into_iter().map(|(flag, label, sample, i)| view! {
                        <div class="opt"><div class="l"><b>{label}</b><span class="mono">{sample}</span></div>
                            <button class="sw" role="switch" aria-checked=if g.flags[i] { "true" } else { "false" } aria-label=label on:click=act(WsAct::GenToggle(flag))></button>
                        </div>
                    }).collect_view()}
                }
            })}
            // The exclusion box survives regeneration (it is only rebuilt with the mode).
            {move || (mode.get() == Some(GenMode::Characters)).then(|| view! {
                <div class="opt"><div class="l"><b>"Exclude characters"</b><span>"Never use these"</span></div>
                    <Input field=WsField::GenExclude label="Exclude characters" kind=Kind::Line value=Signal::derive(move || exclude.get()) bare=true class="small"/>
                </div>
            })}
        </div>
        <div class="actions start">
            <button class="btn subtle" on:click=act(WsAct::SaveGeneratorDefaults)><Svg icon=Icon::Check/>"Use these settings as the vault's defaults"</button>
        </div>
    }
}

fn devices(body: Memo<Option<PageBody>>, busy: Memo<bool>) -> impl IntoView {
    let d = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Devices(d)) => Some(d.clone()),
            _ => None,
        })
    });
    let typing = RwSignal::new(false);
    let scanned = Memo::new(move |_| d.with(|d| d.as_ref().is_some_and(|d| d.scanned)));
    let scan = Memo::new(move |_| d.with(|d| d.as_ref().is_some_and(|d| d.scan)));
    let open = move || scanned.get() || typing.get();
    view! {
        {head("Sync".into(), String::new(), false)}
        <div class="dev-hero">
            <div class="sync-orbit" aria-hidden="true">
                <span class="dev a"><Svg icon=Icon::Devices/></span>
                <span class="beam"><i></i><i></i><i></i></span>
                <span class="dev b"><Svg icon=Icon::Devices/></span>
            </div>
            <b>"Sync with another device"</b>
            <span>"Over your local network. No account, no server. One device shows a code, the other scans it. Each code works once."</span>
            {move || d.with(|d| d.as_ref().and_then(|d| d.vault.clone())).map(|v| view! {
                <div class="sync-vault" id="sync-vault">
                    <span class=format!("tile {}", v.hue)>{v.initial.clone()}</span>
                    <span class="l"><small>"Vault to sync"</small><b>{v.name.to_string()}</b></span>
                    <button class="btn" id="sync-vault-change" disabled=move || busy.get() on:click=move |_| crate::items::open_sheet()>"Change"</button>
                </div>
            })}
        </div>
        <div class="choices dev-choices">
            <button class="choice" id="show-code" disabled=move || busy.get() on:click=act(WsAct::LanOffer)>
                <span class="ci"><Svg icon=Icon::Qr/></span><b>"Show a code"</b><span>"The other device scans or types it"</span>
            </button>
            {move || if scan.get() {
                view! {
                    <button class="choice" id="scan-code" disabled=move || busy.get() data-qv-clear="true" on:click=move |_| ui().act(Act::RequestQr(qv_ui_api::QrTarget::Sync))>
                        <span class="ci"><Svg icon=Icon::Devices/></span><b>"Scan a code"</b><span>"Point the camera at the other device's code"</span>
                    </button>
                }.into_any()
            } else {
                view! {
                    <button class="choice" id="type-code" disabled=move || busy.get() on:click=move |_| typing.set(true)>
                        <span class="ci"><Svg icon=Icon::Devices/></span><b>"Type a code"</b><span>"Enter the code and address the other device shows"</span>
                    </button>
                }.into_any()
            }}
        </div>
        <Show when=move || scan.get()>
            <button class="btn dev-type" id="type-code" disabled=move || busy.get() on:click=move |_| typing.set(true)><Svg icon=Icon::Edit/>"Type a code instead"</button>
        </Show>
        <Show when=open>
            <div class="layer">
                <button class="scrim" aria-label="Close" on:click=move |_| typing.set(false)></button>
                <div class="dialog" role="dialog" aria-modal="true" aria-label="Use another device's code">
                    <h3>"Use another device's code"</h3>
                    <p>"On the other device, open Sync and choose Show a code. Type the code and the address it shows."</p>
                    {move || if scanned.get() {
                        view! { <p class="banner ok" role="status" id="lan-code-scanned"><Svg icon=Icon::Check/>" Code from the QR code"</p> }.into_any()
                    } else {
                        view! { <Input field=WsField::LanCode label="Code" kind=Kind::Secret autofocus=true reveal=true/> }.into_any()
                    }}
                    <Input field=WsField::LanEndpoint label="The other device's address (ip:port)" kind=Kind::Line autofocus=scanned.get_untracked()/>
                    <div class="actions">
                        <button class="btn subtle" on:click=move |_| typing.set(false)>"Cancel"</button>
                        <button class="btn primary" id="sync-submit" data-qv-clear="true" on:click=move |_| { typing.set(false); ui().act(Act::Ws(WsAct::LanSync)); }>"Sync"</button>
                    </div>
                </div>
            </div>
        </Show>
    }
}

fn trash(body: Memo<Option<PageBody>>) -> impl IntoView {
    let t = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Trash(t)) => Some(t.clone()),
            _ => None,
        })
    });
    view! {
        {head("Trash".into(), "Items stay here until you delete them for good. Deleting them for good also removes them from snapshots, unless you choose to keep them there.".into(), false)}
        {move || t.get().map(|t| view! {
            {t.clock_anomaly.then(|| view! { <div class="banner"><Svg icon=Icon::Warn/><span>"Vault dates are ahead of this device's clock; check it before deleting anything."</span></div> })}
            {if t.items.is_empty() && t.loaded {
                view! { <div class="empty empty-tall"><div><div class="big"><Svg icon=Icon::Trash/></div><span class="muted">"The trash is empty."</span></div></div> }.into_any()
            } else {
                view! {
                    <div class="card">
                        {t.items.into_iter().map(|r| view! {
                            <div class="dev">
                                <span class=format!("tile {}", r.hue)>{r.initial.clone()}</span>
                                <div class="l"><b class="row-title">{r.name.to_string()}</b><span>{r.deleted.clone()}{r.conflict.then_some(" · conflict")}</span></div>
                                <button class="btn" on:click=act(WsAct::Restore(r.item))><Svg icon=Icon::Restore/>"Restore"</button>
                            </div>
                        }).collect_view()}
                    </div>
                    <div class="actions start">
                        {(t.expired > 0).then(|| view! { <button class="btn" on:click=act(WsAct::PurgeExpired)>{format!("Delete {} expired", t.expired)}</button> })}
                        <button class="btn danger-text" id="empty-trash" on:click=act(WsAct::EmptyTrash)><Svg icon=Icon::Trash/>"Empty trash…"</button>
                    </div>
                }.into_any()
            }}
            <PageNavBar nav=t.page.clone()/>
        })}
    }
}

fn conflicts(body: Memo<Option<PageBody>>) -> impl IntoView {
    let c = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Conflicts(c)) => Some(c.clone()),
            _ => None,
        })
    });
    view! {
        {head("Conflicts".into(), "Edits made on two devices at once are kept side by side until you choose one complete version.".into(), false)}
        {move || c.get().map(|c| view! {
            {(c.rows.is_empty() && c.loaded).then(|| view! { <div class="empty empty-tall"><div><div class="big"><Svg icon=Icon::Check/></div><span class="muted">"No conflicts."</span></div></div> })}
            <div class="card">
                {c.rows.into_iter().map(|r| view! {
                    <button class="set-row" on:click=go(Screen::ConflictRecord(r.record.clone()))>
                        <span class="si"><Svg icon=Icon::Conflicts/></span>
                        <span class="l"><b>{r.name.to_string()}</b><span>{format!("{} · {} versions", r.kind, r.versions)}</span></span>
                        <Svg icon=Icon::Right/>
                    </button>
                }).collect_view()}
            </div>
            <PageNavBar nav=c.page.clone()/>
        })}
    }
}

fn cell(c: Cell) -> impl IntoView {
    match c {
        Cell::Empty => view! { <div class="cmp-cell" role="cell"><span class="muted">"Empty"</span></div> }.into_any(),
        Cell::Text(v) => view! { <div class="cmp-cell" role="cell"><pre class="field-value">{v.to_string()}</pre></div> }.into_any(),
        Cell::Missing => view! { <div class="cmp-cell" role="cell"><span class="muted">"Not in this version"</span></div> }.into_any(),
        Cell::SameProtected => view! { <div class="cmp-cell" role="cell"><span class="muted">"Same protected value"</span></div> }.into_any(),
        Cell::Masked(key, shown) => view! {
            <div class="cmp-cell masked" role="cell">
                {match &shown {
                    Some(s) => view! { <pre class="field-value revealed">{s.to_string()}</pre> }.into_any(),
                    None => view! { <span class="masked field-value">"••••••••"</span> }.into_any(),
                }}
                {if shown.is_some() {
                    view! { <button class="icon-btn" aria-label="Hide" on:click=act(WsAct::Hide)><Svg icon=Icon::EyeOff/></button> }.into_any()
                } else {
                    view! { <button class="icon-btn" aria-label="Reveal for 30 seconds" on:click=act(WsAct::Reveal(key))><Svg icon=Icon::Eye/></button> }.into_any()
                }}
            </div>
        }.into_any(),
    }
}

fn compare(body: Memo<Option<PageBody>>) -> impl IntoView {
    let c = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Compare(c)) => Some((**c).clone()),
            _ => None,
        })
    });
    let needs_password =
        Memo::new(move |_| c.with(|c| c.as_ref().is_some_and(|c| c.needs_password)));
    view! {
        {move || c.with(|c| c.as_ref().map(|c| c.lead.clone())).map(|lead| head("Compare versions".into(), lead, true))}
        <Show when=move || needs_password.get()>
            <Input field=WsField::Password label="The chosen password slot's master password" kind=Kind::Secret/>
        </Show>
        {move || c.get().map(|c| {
            let record = c.record.clone();
            let all_same = c.diff.is_empty();
            view! {
                {c.identical.then(|| view! { <div class="banner ok"><Svg icon=Icon::Check/><span>"Nothing you can see differs: the versions were saved at different times with the same content."</span></div> })}
                <div class=format!("cmp {}", c.cols) role="table" aria-label="Versions compared">
                    <div class="cmp-row cmp-heads" role="row">
                        <span class="k" role="columnheader">{c.kind.clone()}</span>
                        {c.heads.clone().into_iter().map(|h| view! {
                            <div class=format!("cmp-col v{}", h.label.to_ascii_lowercase()) role="columnheader">
                                <b><span class="vl">{h.label.clone()}</span>{format!("Version {}", h.label)}</b>
                                <span>{format!("{} · {}", h.state, h.modified)}</span>
                            </div>
                        }).collect_view()}
                    </div>
                    {(!c.diff.is_empty()).then(|| view! { <div class="cmp-sect">"DIFFERENT"</div> })}
                    {c.diff.iter().cloned().map(|(label, cells)| view! {
                        <div class="cmp-row diff" role="row">
                            <span class="k" role="rowheader">{label.to_string()}</span>
                            {cells.into_iter().map(cell).collect_view()}
                        </div>
                    }).collect_view()}
                </div>
                {(!c.same.is_empty()).then(|| view! {
                    <details class="cmp-same" open=all_same>
                        <summary><Svg icon=Icon::Check/>{format!("Same in every version · {}", c.same.len())}</summary>
                        <div class="cmp-same-list">
                            {c.same.iter().cloned().map(|(label, first)| view! {
                                <div class="fld"><div class="body">
                                    <span class="k">{label.to_string()}</span>
                                    {match first {
                                        Cell::Empty => view! { <span class="v muted">"Empty"</span> }.into_any(),
                                        Cell::Text(v) => view! { <pre class="v field-value">{v.to_string()}</pre> }.into_any(),
                                        Cell::SameProtected | Cell::Masked(..) => view! { <span class="v muted">"Same protected value"</span> }.into_any(),
                                        Cell::Missing => view! { <span class="v muted">"Not set"</span> }.into_any(),
                                    }}
                                </div></div>
                            }).collect_view()}
                        </div>
                    </details>
                })}
                <div class="cmp-bar" role="group" aria-label="Choose a version">
                    <span class="hint">{if c.identical { "They look the same, so keep either to end the conflict." } else { "The version you keep becomes the item." }}</span>
                    {c.heads.iter().cloned().enumerate().map(|(i, h)| view! {
                        <button class=if i == 0 { "btn primary" } else { "btn" } id=format!("keep-{}", h.label.to_ascii_lowercase())
                            on:click=act(WsAct::Resolve(record.clone(), h.version.clone()))>
                            <span class="keep"><b>{format!("Keep {}", h.label)}</b><small>{h.modified.clone()}</small></span>
                        </button>
                    }).collect_view()}
                </div>
            }
        })}
    }
}

fn snapshots(body: Memo<Option<PageBody>>) -> impl IntoView {
    let s = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Snapshots(s)) => Some(s.clone()),
            _ => None,
        })
    });
    let typed = Memo::new(move |_| s.with(|s| s.as_ref().and_then(|s| s.typed.clone())));
    view! {
        {head("Snapshots".into(), "Past states of this vault, kept inside the vault file: at most one an hour while you make changes, and before merges. Each keeps only what has changed since, using room the vault does not need; the oldest go first when space runs low. Restoring creates a new vault file and a new recovery baseline; this vault is not changed.".into(), true)}
        <div class="banner"><Svg icon=Icon::Archive/><span>"Snapshots live in the vault file, so they do not protect against losing it. Export an archive for a backup."</span></div>
        {move || s.get().filter(|s| s.unreadable > 0).map(|s| view! { <div class="banner"><Svg icon=Icon::Warn/><span>{format!("{} snapshot file(s) could not be authenticated and were skipped.", s.unreadable)}</span></div> })}
        {move || typed.get().map(|label| view! { <Input field=WsField::Path label=label kind=Kind::Line/> })}
        {move || s.get().map(|s| {
            let count = s.rows.len();
            let portal = s.portal;
            view! {
                {(count > 0).then(|| view! {
                    <div class="card">
                        <div class="set-row" id="snapshots-summary">
                            <span class="si"><Svg icon=Icon::Archive/></span>
                            <span class="l"><b>{if count == 1 { "1 snapshot".to_owned() } else { format!("{count} snapshots") }}</b><span>{format!("They keep {} that the vault itself no longer holds", s.kept)}</span></span>
                            <button class="btn danger-text" id="delete-all-snapshots" on:click=act(WsAct::DeleteAllSnapshots)><Svg icon=Icon::Trash/>"Delete all…"</button>
                        </div>
                    </div>
                })}
                <div class="card">
                    {s.rows.is_empty().then(|| view! { <div class="set-row"><span class="l"><span>"No snapshots yet."</span></span></div> })}
                    {s.rows.into_iter().map(|r| {
                        let id = r.id.clone();
                        let restore = move |_| {
                            if portal {
                                ui().act(Act::Pick(qv_ui_api::Pick::RestoreSnapshot(id.clone())));
                            } else {
                                ui().act(Act::Ws(WsAct::RestoreSnapshot(id.clone())));
                            }
                        };
                        view! {
                            <div class="set-row">
                                <span class="si"><Svg icon=Icon::Clock/></span>
                                <span class="l"><b>{r.created.clone()}</b><span>{format!("{} · keeps {} · {}", r.kind, r.size, r.id)}</span></span>
                                <button class="btn" on:click=restore><Svg icon=Icon::Restore/>"Restore…"</button>
                                <button class="icon-btn danger" aria-label="Delete snapshot" title="Delete" on:click=act(WsAct::DeleteSnapshot(r.id.clone()))><Svg icon=Icon::Trash/></button>
                            </div>
                        }
                    }).collect_view()}
                </div>
            }
        })}
    }
}

fn archives(body: Memo<Option<PageBody>>) -> impl IntoView {
    let picker = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Archives(a)) => Some(a.picker.clone()),
            _ => None,
        })
    });
    let lead = "Move changes between copies of this vault with an encrypted file. Merging keeps concurrent edits as conflicts.";
    view! {
        {head("Archives".into(), lead.into(), true)}
        {move || picker.get().map(|p| match p {
            Picker::Portal => view! {
                <div class="card">
                    <button class="set-row" id="export-archive" on:click=move |_| ui().act(Act::Pick(qv_ui_api::Pick::ExportArchive(false)))>
                        <span class="si"><Svg icon=Icon::Archive/></span><span class="l"><b>"Export an archive"</b><span>"Opens only with this vault's key: another device or the recovery phrase"</span></span><Svg icon=Icon::Right/>
                    </button>
                    <button class="set-row" on:click=move |_| ui().act(Act::Pick(qv_ui_api::Pick::ExportArchive(true)))>
                        <span class="si"><Svg icon=Icon::Key/></span><span class="l"><b>"Export with the password slot"</b><span>"Also opens with the master password; anyone holding it can try to guess"</span></span><Svg icon=Icon::Right/>
                    </button>
                    <button class="set-row" id="merge-archive" on:click=move |_| ui().act(Act::Pick(qv_ui_api::Pick::MergeArchive))>
                        <span class="si"><Svg icon=Icon::Folder/></span><span class="l"><b>"Merge an archive"</b><span>"Bring in changes from another copy of this vault"</span></span><Svg icon=Icon::Right/>
                    </button>
                </div>
            }.into_any(),
            other => view! {
                {match other {
                    Picker::Android(picked) => view! {
                        <div class="actions start">
                            <button class="btn" on:click=move |_| ui().act(Act::AndroidPick(qv_ui_api::AndroidPick::ArchiveOpen))>"Choose an archive…"</button>
                            <button class="btn" on:click=move |_| ui().act(Act::AndroidPick(qv_ui_api::AndroidPick::ArchiveCreate))>"Choose where to export…"</button>
                        </div>
                        {picked.map(|n| view! { <p class="hint">{format!("Chosen: {}", n.as_str())}</p> })}
                    }.into_any(),
                    _ => view! { <Input field=WsField::Path label="Archive file to merge, or folder to export into (full path)" kind=Kind::Line/> }.into_any(),
                }}
                <div class="actions start">
                    <button class="btn primary" id="merge-archive" on:click=act(WsAct::MergeArchive)>"Merge archive"</button>
                    <button class="btn" id="export-archive" on:click=act(WsAct::ExportArchive(false))>"Export archive"</button>
                    <button class="btn" on:click=act(WsAct::ExportArchive(true))>"Export with password slot"</button>
                </div>
            }.into_any(),
        })}
    }
}

fn settings_row(
    icon: Icon,
    title: &'static str,
    sub: String,
    to: Screen,
    id: &'static str,
) -> impl IntoView {
    view! {
        <button class="set-row" id=id on:click=go(to)>
            <span class="si"><Svg icon/></span><span class="l"><b>{title}</b>{(!sub.is_empty()).then(|| view! { <span>{sub}</span> })}</span><Svg icon=Icon::Right/>
        </button>
    }
}

fn guidance(g: qv_ui_api::Guidance) -> impl IntoView {
    let rated = g.meter.is_some();
    view! {
        {crate::input::meter_view(g.meter)}
        {(g.fair && !rated).then(|| view! { <div class="banner"><Svg icon=Icon::Warn/><span>"This password is fair. Consider a longer, less predictable passphrase."</span></div> })}
        <button class="link" on:click=act(WsAct::SuggestPassword)>"Suggest a six-word passphrase"</button>
        {g.suggestion.map(|s| view! { <div class="phrase single mono revealed">{s.to_string()}</div><p class="hint">"Visible for 30 seconds."</p> })}
    }
}

/// The quick-unlock card for the current policy (plan 0068). The device
/// keeps one enrollment; while another vault holds it, this vault's card
/// says so and offers to move it here (plan 0072).
fn quick_card(policy: Option<QuickPolicy>) -> impl IntoView {
    let enroll = |p: QuickPolicy| act(WsAct::EnrollQuick(p));
    let password =
        || view! { <Input field=WsField::Password label="Master password" kind=Kind::Secret/> };
    let expiry = || view! { <p class="hint">"Restarting the phone, seven days, three failed attempts or a password change ask for the master password again."</p> };
    // Each vault has its own (plan 0074): this card is this vault's only.
    match policy {
        None => view! {
            <p class="hint">"Off for this vault. Enter your master password to turn on fingerprint unlock."</p>
            {expiry()}
            {password()}
            <div class="actions stack">
                <button class="btn primary" data-qv-clear="true" on:click=enroll(QuickPolicy::Class3)><Svg icon=Icon::Finger/>"Turn on fingerprint unlock"</button>
                <button class="btn" data-qv-clear="true" on:click=enroll(QuickPolicy::DeviceCredential)>"Use your screen lock PIN or pattern instead (lower protection)…"</button>
            </div>
        }.into_any(),
        Some(QuickPolicy::Class3) => view! {
            <div class="banner ok" id="quick-on"><Svg icon=Icon::Finger/><span>"Fingerprint unlock is on for this vault. The locked screen asks for your fingerprint first."</span></div>
            {expiry()}
            <div class="actions stack"><button class="btn" id="quick-off" on:click=act(WsAct::DisableQuick)>"Turn off fingerprint unlock"</button></div>
            <div class="quick-alt">
                <b>"Screen lock instead"</b>
                <p class="hint">"Lower protection: your PIN or pattern would open this vault, so anyone who knows it could too."</p>
                {password()}
                <div class="actions stack"><button class="btn" data-qv-clear="true" on:click=enroll(QuickPolicy::DeviceCredential)>"Use your screen lock instead…"</button></div>
            </div>
        }.into_any(),
        Some(QuickPolicy::DeviceCredential) => view! {
            <div class="banner ok" id="quick-on"><Svg icon=Icon::Finger/><span>"Screen-lock unlock is on (lower protection: your PIN or pattern opens this vault)."</span></div>
            {expiry()}
            <div class="actions stack"><button class="btn" id="quick-off" on:click=act(WsAct::DisableQuick)>"Turn off screen-lock unlock"</button></div>
            <div class="quick-alt">
                <b>"Fingerprint instead"</b>
                <p class="hint">"Higher protection: only your fingerprint opens this vault, not your PIN or pattern."</p>
                {password()}
                <div class="actions stack"><button class="btn primary" data-qv-clear="true" on:click=enroll(QuickPolicy::Class3)><Svg icon=Icon::Finger/>"Switch to fingerprint unlock"</button></div>
            </div>
        }.into_any(),
    }
}

fn settings(body: Memo<Option<PageBody>>, pane: Pane) -> impl IntoView {
    let s = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Settings(s)) => Some(s.body.clone()),
            _ => None,
        })
    });
    let nested = pane != Pane::Overview;
    match pane {
        Pane::Overview => view! {
            {head("Settings".into(), String::new(), false)}
            {move || match s.get() {
                Some(SettingsBody::Overview(o)) => {
                    let theme = o.theme.clone();
                    view! {
                        <div class="group-t">"APPEARANCE"</div>
                        <div class="card">
                            <div class="set-row"><span class="si"><Svg icon=Icon::Palette/></span><span class="l"><b>"Theme"</b></span>
                                <div class="seg seg-wide">
                                    {[("system", "System"), ("light", "Light"), ("dark", "Dark")].into_iter().map(|(t, label)| view! {
                                        <button class=if theme == t { "on" } else { "" } id=format!("theme-{t}") on:click=move |_| ui().act(Act::Theme(t.to_owned()))>{label}</button>
                                    }).collect_view()}
                                </div>
                            </div>
                        </div>
                        <div class="group-t">"SECURITY"</div>
                        <div class="card">
                            {if o.idle_only {
                                view! {
                                    <div class="set-row" id="settings-autolock"><span class="si"><Svg icon=Icon::Clock/></span><span class="l"><b>"Auto-lock"</b><span>"After 5 minutes without activity. This system does not report screen lock or sleep, so they do not lock QuickVault; lock it yourself before leaving."</span></span>
                                        <span class="r warn">"Idle only"</span>
                                    </div>
                                }.into_any()
                            } else {
                                view! {
                                    <div class="set-row" id="settings-autolock"><span class="si"><Svg icon=Icon::Clock/></span><span class="l"><b>"Auto-lock"</b>
                                        <span>{if crate::android() { "After 5 minutes without activity, also while you use other apps, and when the screen locks" } else { "After 5 minutes without activity, and when the screen locks or the device sleeps" }}</span></span></div>
                                }.into_any()
                            }}
                            <div class="set-row" id="settings-protection"><span class="si"><Svg icon=Icon::Shield/></span><span class="l"><b>"Device protection"</b><span>{o.detail.clone()}</span></span>
                                <span class=format!("r {}", o.tone)>{o.level.clone()}</span>
                            </div>
                            {settings_row(Icon::Finger, "Quick unlock and autofill", o.quick.clone(), Screen::Settings(Pane::Password), "settings-quick")}
                        </div>
                        <div class="group-t">"MASTER PASSWORD AND RECOVERY"</div>
                        <div class="card">
                            {settings_row(Icon::Key, "Change master password", String::new(), Screen::Settings(Pane::Password), "settings-password")}
                            {settings_row(Icon::Note, "Recovery phrase", "View or confirm your 24 words".into(), Screen::Settings(Pane::Phrase), "settings-phrase")}
                            {settings_row(Icon::Refresh, "Rotate vault keys", "After a suspected compromise: new password and new phrase".into(), Screen::Settings(Pane::Rotation), "settings-rotation")}
                        </div>
                        <div class="group-t">"VAULT"</div>
                        <div class="card">
                            {o.file.clone().map(|(file, place)| view! {
                                // Android keeps vaults in the app's private folder: no place to show.
                                <div class="set-row" id="settings-file"><span class="si"><Svg icon=Icon::File/></span><span class="l"><b>"Vault file"</b>
                                    <span>{if crate::android() { file.to_string() } else { format!("{} in {}", file.as_str(), place.as_str()) }}</span></span></div>
                            })}
                            <button class="set-row" id="settings-switch" on:click=move |_| ui().act(Act::SwitchVault(qv_ui_api::SwitchTo::Mode(qv_ui_api::Mode::Unlock)))>
                                <span class="si"><Svg icon=Icon::Lock/></span><span class="l"><b>"Switch vault"</b><span>"Locks this vault; open, create or join another from the lock screen"</span></span><Svg icon=Icon::Right/>
                            </button>
                            {(!crate::android()).then(|| view! {
                                <div class="set-row" id="settings-folder"><span class="si"><Svg icon=Icon::Folder/></span><span class="l"><b>"Folder for new vaults"</b><span>{o.folder.to_string()}</span></span>
                                    {o.folder_change.then(|| view! { <button class="btn" id="settings-folder-change" on:click=move |_| ui().act(Act::Pick(qv_ui_api::Pick::Folder))>"Change…"</button> })}
                                </div>
                            })}
                            {settings_row(Icon::Edit, "Name and retention", "Vault name, description, history and trash".into(), Screen::Settings(Pane::General), "settings-general")}
                            // The phone has no sidebar: Trash is reachable here (plan 0063).
                            {settings_row(Icon::Trash, "Trash", "Deleted items, kept until you delete them for good".into(), Screen::Trash, "settings-trash")}
                            {settings_row(Icon::Clock, "Snapshots", "Restore an earlier copy into a new vault".into(), Screen::Snapshots, "settings-snapshots")}
                            {settings_row(Icon::File, "Storage", "File size, free space and compaction".into(), Screen::Settings(Pane::Storage), "settings-storage")}
                            {settings_row(Icon::Archive, "Archives", "Export or merge changes as an encrypted file".into(), Screen::Archives, "settings-archives")}
                            {settings_row(Icon::Check, "Check vault integrity", "Re-checks every stored object; changes nothing".into(), Screen::Settings(Pane::Verify), "settings-verify")}
                            {settings_row(Icon::Shield, "About this vault", "Identifiers and key-derivation settings".into(), Screen::Settings(Pane::About), "settings-about")}
                        </div>
                    }.into_any()
                }
                _ => ().into_any(),
            }}
        }.into_any(),
        Pane::General => {
            let g = Memo::new(move |_| s.with(|s| match s {
                Some(SettingsBody::General(g)) => g.clone(),
                _ => None,
            }));
            let f = move |x: fn(&qv_ui_api::General) -> String| Signal::derive(move || g.with(|g| g.as_ref().map(x).unwrap_or_default()));
            let ready = Memo::new(move |_| g.with(Option::is_some));
            view! {
                {head("Name and retention".into(), String::new(), nested)}
                {move || if ready.get() {
                    view! {
                        <div class="card card-pad">
                            <Input field=WsField::VaultName label="Vault name" kind=Kind::Line value=f(|g| g.name.to_string())/>
                            <Input field=WsField::Description label="Description" kind=Kind::Line value=f(|g| g.description.to_string())/>
                            <Input field=WsField::HistoryDepth label="Earlier versions to keep per item (blank: default)" kind=Kind::Line value=f(|g| g.history_depth.clone())/>
                            <Input field=WsField::TrashDays label="Days before trash is offered for deletion (blank: default)" kind=Kind::Line value=f(|g| g.trash_days.clone())/>
                            <div class="actions"><button class="btn primary" id="save-settings" on:click=act(WsAct::SaveSettings)>"Save"</button></div>
                        </div>
                    }.into_any()
                } else {
                    unreadable("Loading…".to_owned()).into_any()
                }}
            }.into_any()
        }
        Pane::Password => {
            let p = Memo::new(move |_| s.with(|s| match s {
                Some(SettingsBody::Password(p)) => Some(p.clone()),
                _ => None,
            }));
            let policy = Memo::new(move |_| p.with(|p| p.as_ref().map(|p| (p.quick_available, p.policy, p.autofill))));
            let g = Memo::new(move |_| p.with(|p| p.as_ref().map(|p| p.guidance.clone())));
            view! {
                {head("Password and quick unlock".into(), String::new(), nested)}
                {move || policy.get().map(|(available, policy, autofill)| view! {
                    <div class="group-t">"QUICK UNLOCK"</div>
                    <div class="card card-pad">
                        {if available { quick_card(policy).into_any() } else {
                            view! { <p class="hint">"Unavailable: this device has no supported fingerprint or screen lock for QuickVault. The master password still works."</p> }.into_any()
                        }}
                    </div>
                    <div class="group-t">"AUTOFILL"</div>
                    <div class="card card-pad">
                        {if autofill {
                            view! {
                                <p class="hint">"Fills only entries linked to a verified app or an exact website from a validated browser, after you unlock and choose."</p>
                                <div class="actions start"><button class="btn" on:click=act(WsAct::OpenAutofillSettings)>"Open Android autofill settings"</button></div>
                            }.into_any()
                        } else {
                            view! { <p class="hint">"Unavailable: autofill is disabled on devices without recorded validation."</p> }.into_any()
                        }}
                    </div>
                })}
                <div class="group-t">"CHANGE MASTER PASSWORD"</div>
                <div class="card card-pad">
                    <p class="hint">"Older copies of the vault and its password slot still open with the old password. After a suspected compromise, rotate keys instead."</p>
                    <Input field=WsField::NewPassword label="New master password" kind=Kind::Secret rate=true/>
                    <Input field=WsField::Repeat label="Type it again" kind=Kind::Secret/>
                    {move || g.get().map(guidance)}
                    <div class="actions"><button class="btn primary" id="change-password" data-qv-clear="true" on:click=act(WsAct::ChangePassword)>"Change master password"</button></div>
                </div>
            }.into_any()
        }
        Pane::Phrase => {
            let shown = Memo::new(move |_| s.with(|s| match s {
                Some(SettingsBody::Phrase(p)) => p.shown.clone(),
                _ => None,
            }));
            let on = Memo::new(move |_| shown.with(Option::is_some));
            view! {
                {head("Recovery phrase".into(), String::new(), nested)}
                {move || if !on.get() {
                    view! {
                        <div class="card card-pad">
                            <p class="hint">"Enter your master password to show the recovery phrase. Anyone with the phrase and your vault file can open it."</p>
                            <Input field=WsField::Password label="Master password" kind=Kind::Secret autofocus=true/>
                            <div class="actions"><button class="btn primary" id="show-phrase" data-qv-clear="true" on:click=act(WsAct::ShowPhrase)>"Show recovery phrase"</button></div>
                        </div>
                    }.into_any()
                } else {
                    let confirmed = Memo::new(move |_| shown.with(|s| s.as_ref().is_some_and(|s| s.1)));
                    let positions = shown.with_untracked(|s| s.as_ref().map(|s| s.2)).unwrap_or([0; 3]);
                    view! {
                        <div class="phrase mono">
                            {move || shown.get().map(|(words, ..)| words.into_iter().enumerate().map(|(i, w)| view! {
                                <span><small>{(i + 1).to_string()}</small><b class="w">{w.to_string()}</b></span>
                            }).collect_view())}
                        </div>
                        {move || if confirmed.get() {
                            view! { <div class="banner ok"><Svg icon=Icon::Check/><span>"The recovery words are confirmed."</span></div> }.into_any()
                        } else {
                            view! {
                                <div class="card card-pad mt">
                                    <p class="hint">{format!("Optionally check words {}, {} and {} against your copy.", positions[0], positions[1], positions[2])}</p>
                                    {[(0u8, positions[0]), (1, positions[1]), (2, positions[2])].into_iter().map(|(i, n)| view! {
                                        <Input field=WsField::Word(i) label=format!("Word {n}") kind=Kind::Secret/>
                                    }).collect_view()}
                                    <div class="actions"><button class="btn" data-qv-clear="true" on:click=act(WsAct::ConfirmWords)>"Check words"</button></div>
                                </div>
                            }.into_any()
                        }}
                        <div class="actions start"><button class="btn subtle" data-qv-clear="true" on:click=act(WsAct::HidePhrase)><Svg icon=Icon::EyeOff/>"Hide the phrase"</button></div>
                    }.into_any()
                }}
            }.into_any()
        }
        Pane::Rotation => {
            let g = Memo::new(move |_| s.with(|s| match s {
                Some(SettingsBody::Rotation(g)) => Some(g.clone()),
                _ => None,
            }));
            view! {
                {head("Rotate vault keys".into(), "Creates a new key generation with a new master password and a new recovery phrase. It can take a while, can be resumed, and locks the vault when it finishes.".into(), nested)}
                <div class="card card-pad">
                    <Input field=WsField::Confirmation label="Type rotate to continue" kind=Kind::Line/>
                    <Input field=WsField::NewPassword label="New master password" kind=Kind::Secret rate=true/>
                    <Input field=WsField::Repeat label="Type it again" kind=Kind::Secret/>
                    {move || g.get().map(guidance)}
                    <div class="actions"><button class="btn danger" data-qv-clear="true" on:click=act(WsAct::BeginRotation)>"Prepare key rotation"</button></div>
                </div>
            }.into_any()
        }
        Pane::Verify => view! {
            {head("Check vault integrity".into(), "Re-hashes and authenticates every object, manifest and the local head. Nothing is changed or repaired.".into(), nested)}
            <div class="actions start"><button class="btn primary" id="verify" on:click=act(WsAct::Verify)><Svg icon=Icon::Check/>"Check now"</button></div>
        }.into_any(),
        Pane::Storage => view! {
            {head("Storage".into(), "Deleting data leaves free space inside the vault file. Compacting rewrites the file without it, so this device gets the space back. QuickVault also compacts by itself after large deletions. Snapshots use whatever room the vault does not need and give way when it is needed.".into(), nested)}
            {move || match s.get() {
                Some(SettingsBody::Storage(Ok(i))) => view! {
                    <div class="card">
                        <div class="set-row" id="storage-file"><span class="si"><Svg icon=Icon::File/></span><span class="l"><b>"Vault file"</b><span>{i.file.clone()}</span></span></div>
                        <div class="set-row" id="storage-free"><span class="si"><Svg icon=Icon::Refresh/></span><span class="l"><b>"Free space inside the file"</b><span>{i.free.clone()}</span></span></div>
                        <div class="set-row" id="storage-snapshots"><span class="si"><Svg icon=Icon::Clock/></span><span class="l"><b>"Snapshots"</b><span>{i.snapshots.clone()}</span></span></div>
                        <div class="set-row" id="storage-disk"><span class="si"><Svg icon=Icon::Folder/></span><span class="l"><b>"Free space on this device"</b><span>{i.disk.clone()}</span></span></div>
                    </div>
                    <div class="actions start"><button class="btn primary" id="compact" disabled=i.empty on:click=act(WsAct::Compact)><Svg icon=Icon::Refresh/>"Compact now"</button></div>
                }.into_any(),
                Some(SettingsBody::Storage(Err(m))) => unreadable(m).into_any(),
                _ => ().into_any(),
            }}
        }.into_any(),
        Pane::About => view! {
            {head("About this vault".into(), String::new(), nested)}
            {move || match s.get() {
                Some(SettingsBody::About(a)) => view! {
                    {a.overview.map(|o| view! {
                        <div class="group-t">"CONTENTS (VERIFIED)"</div>
                        <div class="card"><div class="set-row"><span class="l"><b>{format!("{} items · {} groups", o[0], o[1])}</b><span>{format!("{} in trash · {} conflicts", o[2], o[3])}</span></span></div></div>
                    })}
                    <div class="group-t">"HEADER (UNVERIFIED WITHOUT THE PASSWORD)"</div>
                    {match a.header.clone() {
                        Some((id, generation, format, kdf)) => view! {
                            <div class="card">
                                <div class="set-row"><span class="l"><b>"Vault ID"</b><span class="mono">{id}</span></span></div>
                                <div class="set-row"><span class="l"><b>"Key generation"</b><span>{format!("{generation} · format {format:#010x}")}</span></span></div>
                                <div class="set-row"><span class="l"><b>"Password key derivation"</b><span>{kdf}</span></span></div>
                            </div>
                        }.into_any(),
                        None => view! { <p class="muted">"Header details appear after the next unlock."</p> }.into_any(),
                    }}
                    <div class="about-brand mt"><Logo class="logo-about"/>
                        <span><b>"QuickVault"</b><span class="hint">{format!("Version {} · offline-first, end-to-end encrypted · AGPL-3.0-or-later", a.version)}</span></span>
                    </div>
                }.into_any(),
                _ => ().into_any(),
            }}
        }.into_any(),
    }
}

fn autofill(body: Memo<Option<PageBody>>) -> impl IntoView {
    let a = Memo::new(move |_| {
        body.with(|b| match b {
            Some(PageBody::Autofill(a)) => Some((**a).clone()),
            _ => None,
        })
    });
    let query =
        Memo::new(move |_| a.with(|a| a.as_ref().map(|a| a.query.to_string()).unwrap_or_default()));
    let app = Memo::new(move |_| a.with(|a| a.as_ref().and_then(|a| a.app.clone())));
    view! {
        {move || a.with(|a| a.as_ref().map(|a| a.label.is_none())).map(|none| if none {
            head("Autofill".into(), "No autofill request is waiting.".into(), false).into_any()
        } else {
            head("Fill a login".into(), "Only items linked to this exact verified identity are listed. Titles and app names are never used for matching.".into(), false).into_any()
        })}
        {move || a.get().filter(|a| a.label.is_some()).map(|a| view! {
            <div class="banner ok"><Svg icon=Icon::Shield/><span>{format!("For: {}", a.label.as_ref().map(|l| l.to_string()).unwrap_or_default())}</span></div>
            {(a.candidates.is_empty() && a.loaded).then(|| view! { <p class="muted">"No entry matches this verified identity."</p> })}
            <div class="card">
                {a.candidates.into_iter().map(|c| view! {
                    <button class="set-row" data-qv-autofill="candidate" on:click=act(WsAct::AutofillFill(c.key))>
                        <span class=format!("tile {}", c.hue)>{c.initial.clone()}</span>
                        <span class="l"><b>{c.title.to_string()}</b>
                            <span>{c.conflicted.then_some("Conflicting version · check before filling · ")}{c.username.to_string()}</span>
                        </span>
                    </button>
                }).collect_view()}
            </div>
            <PageNavBar nav=a.page.clone()/>
        })}
        {move || app.get().map(|(package, signers)| view! {
            <details class="mt">
                <summary>"Link this app to an item…"</summary>
                <div class="banner"><Svg icon=Icon::Warn/><span>"QuickVault cannot tell whether this app belongs to the service. Link only an app you trust."</span></div>
                <p class="hint">{format!("Package {package} · signer {signers}…")}</p>
                <Input field=WsField::Query label="Find the item to link" kind=Kind::Line value=Signal::derive(move || query.get())/>
                <div class="card">
                    {move || a.with(|a| a.as_ref().map(|a| a.results.clone()).unwrap_or_default()).into_iter().map(|(e, title)| view! {
                        <button class="set-row" data-qv-autofill="link" on:click=act(WsAct::AutofillLink(e))>
                            <span class="l"><b>{title.to_string()}</b><span>"Link this app"</span></span>
                        </button>
                    }).collect_view()}
                </div>
            </details>
        })}
        {move || a.with(|a| a.as_ref().and_then(|a| a.link_page.clone())).map(|n| view! { <PageNavBar nav=Some(n)/> })}
        {move || a.with(|a| a.as_ref().is_some_and(|a| a.label.is_some())).then(|| view! {
            <div class="actions start"><button class="btn" data-qv-autofill="cancel" on:click=act(WsAct::AutofillCancel)>"Cancel autofill"</button></div>
        })}
    }
}
