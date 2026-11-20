// SPDX-License-Identifier: AGPL-3.0-or-later

//! The unlocked shell: sidebar, tabs, toasts and
//! confirmations. Layout comes from CSS container queries over one DOM.
use crate::icons::{Icon, Svg, glyph, svg};
use crate::input::{Input, Kind};
use crate::{items, pages, ui};
use leptos::prelude::*;
use qv_ui_api::{
    Act, Body, Content, Lan, PageNav, Question, Receipt, ReportCard, Screen, Shell as S, UiOp,
    WsAct, WsField,
};

pub(crate) fn field<T: Clone + PartialEq + Send + Sync + 'static>(
    s: Memo<Option<S>>,
    d: T,
    f: impl Fn(&S) -> T + Send + Sync + 'static,
) -> Memo<T> {
    Memo::new(move |_| s.with(|s| s.as_ref().map_or_else(|| d.clone(), &f)))
}

/// Keeps a value that disappears for its exit fade (plan 0072): a new value
/// shows at once; `None` marks the old one leaving for 180 ms, then drops
/// it. Only status text passes through here, never a secret.
pub(crate) fn fading<T: Clone + PartialEq + Send + Sync + 'static>(
    src: Memo<Option<T>>,
) -> (RwSignal<Option<T>>, RwSignal<bool>) {
    let shown = RwSignal::new(src.get_untracked());
    let leaving = RwSignal::new(false);
    let turn = StoredValue::new(0u64);
    Effect::new(move |_| {
        let v = src.get();
        turn.update_value(|t| *t = t.wrapping_add(1));
        match v {
            Some(v) => {
                leaving.set(false);
                shown.set(Some(v));
            }
            None if shown.with_untracked(Option::is_some) => {
                leaving.set(true);
                let mine = turn.get_value();
                set_timeout(
                    move || {
                        if turn.try_get_value() == Some(mine) {
                            let _ = shown.try_set(None);
                            let _ = leaving.try_set(false);
                        }
                    },
                    std::time::Duration::from_millis(180),
                );
            }
            None => {}
        }
    });
    (shown, leaving)
}

/// `class`, plus ` leaving` while it fades out.
fn leave(class: &'static str, leaving: RwSignal<bool>) -> impl Fn() -> String {
    move || {
        if leaving.get() {
            format!("{class} leaving")
        } else {
            class.to_owned()
        }
    }
}

/// The shell frame as a memo.
pub(crate) fn shell_memo() -> Memo<Option<S>> {
    ui().sel(None, |f| match &f.body {
        Body::Unlocked(s) => Some((**s).clone()),
        _ => None,
    })
}

pub(crate) fn go(s: Screen) -> impl Fn(web_sys::MouseEvent) + Clone + 'static {
    move |_| ui().act(Act::Go(s.clone()))
}
pub(crate) fn act(a: WsAct) -> impl Fn(web_sys::MouseEvent) + Clone + 'static {
    move |_| ui().act(Act::Ws(a.clone()))
}

/// A paged list's Previous/Next.
#[component]
pub(crate) fn PageNavBar(#[prop(into)] nav: Signal<Option<PageNav>>) -> impl IntoView {
    move || {
        nav.get().map(|n| {
            let back = n.clone();
            let fwd = n.clone();
            if n.window {
                // A scrolling list (plan 0072): app.js presses the sentinel
                // when it comes near the viewport; past the window's bound,
                // "Show more" starts the next window.
                let start = n.clone();
                let more = n.clone();
                return view! {
                    {n.error.clone().map(|e| view! { <p class="banner warn">{e}</p> })}
                    {(n.next && n.more).then(|| view! {
                        <button type="button" class="list-more" data-qv-more="true" disabled=n.loading
                            on:click=move |_| ui().page_turn(&more, true)>"Loading more…"</button>
                    })}
                    {((n.next && !n.more) || n.previous).then(|| {
                        let next = n.clone();
                        view! {
                            <div class="actions start">
                                {n.previous.then(|| view! { <button type="button" class="btn subtle" disabled=n.loading on:click=move |_| ui().page_turn(&start, false)>"Back to the start"</button> })}
                                {n.loading.then(|| view! { <span class="muted">"Loading…"</span> })}
                                {(n.next && !n.more).then(|| view! { <button type="button" class="btn subtle" id="list-show-more" disabled=n.loading on:click=move |_| ui().page_turn(&next, true)>"Show more"</button> })}
                            </div>
                        }
                    })}
                }.into_any();
            }
            view! {
                {n.error.clone().map(|e| view! { <p class="banner warn">{e}</p> })}
                {(n.previous || n.next).then(|| view! {
                    <div class="actions start">
                        <button type="button" class="btn subtle" disabled=n.loading || !n.previous on:click=move |_| ui().page_turn(&back, false)>"Previous"</button>
                        {n.loading.then(|| view! { <span class="muted">"Loading…"</span> })}
                        <button type="button" class="btn subtle" disabled=n.loading || !n.next on:click=move |_| ui().page_turn(&fwd, true)>"Next"</button>
                    </div>
                })}
            }.into_any()
        })
    }
}

/// A finished task's result.
pub(crate) fn report_card(r: ReportCard) -> impl IntoView {
    view! {
        <div class=if r.ok { "banner ok report" } else { "banner bad report" } role="status">
            {svg(if r.ok { Icon::Check } else { Icon::Warn })}
            <div class="sp">{r.lines.into_iter().map(|l| view! { <p>{l}</p> }).collect_view()}</div>
            <button class="link" on:click=act(WsAct::Dismiss)>"Dismiss"</button>
        </div>
    }
}

/// A placeholder for unreadable or loading content.
pub(crate) fn unreadable(message: String) -> impl IntoView {
    view! { <div class="empty"><p>{message}</p></div> }
}

/// Where a LAN panel's data comes from.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LanSource {
    Locked,
    Unlocked,
}

/// The running or finished LAN operation.
#[component]
pub(crate) fn LanPanel(source: LanSource) -> impl IntoView {
    let lan = ui().sel(None, move |f| match (&f.body, source) {
        (Body::Locked(l), LanSource::Locked) => l.lan.clone(),
        (Body::Unlocked(s), LanSource::Unlocked) => s.lan.clone(),
        _ => None,
    });
    let expanded = RwSignal::new(false);
    let active = Memo::new(move |_| lan.with(|l| l.as_ref().map(|l| l.done.is_none())));
    move || match active.get() {
        None => ().into_any(),
        Some(false) => view! { <ReceiptView lan expanded/> }.into_any(),
        Some(true) => view! { <LanDialog lan/> }.into_any(),
    }
}

#[component]
fn LanDialog(lan: Memo<Option<Lan>>) -> impl IntoView {
    let get = move || lan.get();
    let question = Memo::new(move |_| lan.with(|l| l.as_ref().and_then(|l| l.question.clone())));
    let qid = Memo::new(move |_| lan.with(|l| l.as_ref().map_or(0, |l| l.question_id)));
    let answer = move |yes: bool| move |_| ui().act(Act::LanAnswer(qid.get_untracked(), yes));
    let typed = move |e: web_sys::Event| {
        ui().input(
            qv_ui_api::Field::LanSecret {
                question: qid.get_untracked(),
            },
            &event_target_value(&e),
        )
    };
    view! {
        <div class="layer">
            <div class="scrim"></div>
            <div class="dialog wide lan" role="region" aria-label="Local network">
                {move || get().map(|v| {
                    let orbit = v.question.is_none() && v.qr.is_none() && v.code.is_none();
                    view! {
                        {orbit.then(|| view! {
                            <div class="sync-orbit" aria-hidden="true">
                                <span class="dev a"><Svg icon=Icon::Devices/></span>
                                <span class="beam"><i></i><i></i><i></i></span>
                                <span class="dev b"><Svg icon=Icon::Devices/></span>
                            </div>
                        })}
                        <h3>{v.title.clone()}</h3>
                        {v.vault.clone().filter(|_| v.names_vault).map(|(name, hue)| view! {
                            <p class="lan-vault" id="lan-vault"><span class=format!("dot {hue}")></span>"Vault "<b>{name.to_string()}</b></p>
                        })}
                        {v.qr.clone().map(|q| view! {
                            <svg id="lan-qr" class="qr-card" xmlns="http://www.w3.org/2000/svg" viewBox=format!("0 0 {0} {0}", q.side)
                                width="216" height="216" shape-rendering="crispEdges" role="img" aria-label="LAN QR code">
                                <rect width="100%" height="100%" fill="white"></rect>
                                <path d=q.path.to_string() fill="black"></path>
                            </svg>
                        })}
                        {v.code.clone().map(|c| view! {
                            <p class="center hint">"The code works once. Show it only to the device you want to sync with."</p>
                            <div class="phrase single mono center" id="lan-code">{c.to_string()}</div>
                        })}
                        {(!v.endpoints.is_empty()).then(|| view! {
                            <p class="center hint">"This device's address:"</p>
                            <div class="center mono">{v.endpoints.iter().map(|e| view! { <div>{e.clone()}</div> }).collect_view()}</div>
                        })}
                        // Once the other device is admitted, the countdown no
                        // longer means "use the code" (plan 0062).
                        {(v.seconds > 0 && !v.admitted).then(|| view! {
                            <p class="center hint">{format!("Closes in {}:{:02}", v.seconds / 60, v.seconds % 60)}</p>
                        })}
                        {v.sas.clone().filter(|_| v.question.is_none()).map(|sas| view! {
                            <div role="status" aria-label="Comparison code">
                                <p class="center">"Check that the other device shows this code:"</p>
                                <div class="code-big mono phrase single" id="lan-sas-wait">{sas}</div>
                                <p class="center hint">"If the codes differ, cancel. The vault is only joined after you confirm it."</p>
                            </div>
                        })}
                        {v.info.clone().map(|i| view! { <p class="banner ok notice" role="status">{i}</p> })}
                    }
                })}
                {move || match question.get() {
                    Some(Question::Approve { sas, vault }) => view! {
                        <div role="alertdialog" aria-label="Compare codes">
                            <p class="center">{format!("A new device asks to join “{vault}”. It will receive this vault.")}</p>
                            <div class="code-big mono phrase single" id="lan-sas">{sas}</div>
                            <p class="center hint">"Confirm only if the other device shows exactly this code."</p>
                            <div class="actions">
                                <button class="btn subtle" on:click=answer(false)>"They differ"</button>
                                <button class="btn primary" id="lan-codes-match" on:click=answer(true)>"Codes match"</button>
                            </div>
                        </div>
                    }.into_any(),
                    Some(Question::JoinVault { vault, sas }) => view! {
                        <div role="alertdialog" aria-label="Join vault">
                            <p class="center">{format!("Join the vault “{vault}”?")}</p>
                            <div class="code-big mono phrase single">{sas}</div>
                            <p class="center hint">"Join only a vault you expect, from a device showing this comparison code."</p>
                            <div class="actions">
                                <button class="btn subtle" on:click=answer(false)>"Cancel"</button>
                                <button class="btn primary" id="lan-join-vault" on:click=answer(true)>"Join this vault"</button>
                            </div>
                        </div>
                    }.into_any(),
                    Some(Question::ChooseCredential) => view! {
                        <div role="alertdialog" aria-label="Choose vault credential">
                            <p>"Authenticate with the vault’s password or recovery words."</p>
                            <div class="actions">
                                <button class="btn subtle" on:click=move |_| ui().act(Act::LanCancel)>"Cancel"</button>
                                <button class="btn subtle" id="lan-use-phrase" on:click=answer(false)>"Recovery words"</button>
                                <button class="btn primary" id="lan-use-password" on:click=answer(true)>"Vault password"</button>
                            </div>
                        </div>
                    }.into_any(),
                    Some(Question::RecoveryPhrase) => view! {
                        <div role="alertdialog" aria-label="Vault recovery words">
                            <div class="field">
                                <label for="lan-phrase">"Vault recovery words"</label>
                                <input id="lan-phrase" type="password" maxlength=qv_ui_api::LINE_MAX.to_string() autocomplete="off" spellcheck="false" autofocus=true on:input=typed/>
                            </div>
                            <div class="actions">
                                <button class="btn subtle" on:click=answer(false)>"Cancel"</button>
                                <button class="btn primary" data-qv-clear="true" id="lan-phrase-submit" on:click=answer(true)>"Authenticate"</button>
                            </div>
                        </div>
                    }.into_any(),
                    Some(Question::JoinRecoveredVault { vault }) => view! {
                        <div role="alertdialog" aria-label="Join vault">
                            <p>{format!("Join the authenticated vault “{vault}” using the recovery words?")}</p>
                            <div class="actions">
                                <button class="btn subtle" on:click=answer(false)>"Cancel"</button>
                                <button class="btn primary" id="lan-join-vault" on:click=answer(true)>"Join this vault"</button>
                            </div>
                        </div>
                    }.into_any(),
                    Some(Question::Password { retry, offering }) => view! {
                        <div role="alertdialog" aria-label="Master password">
                            {retry.then(|| view! { <p class="banner bad error">"Wrong password. Try again."</p> })}
                            <div class="field">
                                <label for="lan-password">{if offering { "This vault’s master password" } else { "The vault’s master password" }}</label>
                                <input id="lan-password" type="password" maxlength=qv_ui_api::LINE_MAX.to_string() autocomplete="off" spellcheck="false" autofocus=true on:input=typed/>
                            </div>
                            <div class="actions">
                                <button class="btn subtle" on:click=answer(false)>"Cancel"</button>
                                <button class="btn primary" data-qv-clear="true" id="lan-password-submit" on:click=answer(true)>"Authenticate"</button>
                            </div>
                        </div>
                    }.into_any(),
                    None => view! {
                        <div class="actions"><button class="btn subtle" id="lan-cancel" on:click=move |_| ui().act(Act::LanCancel)>"Cancel"</button></div>
                    }.into_any(),
                }}
            </div>
        </div>
    }
}

/// The finished operation as a receipt docked at the bottom (0009 §1.8).
#[component]
fn ReceiptView(lan: Memo<Option<Lan>>, expanded: RwSignal<bool>) -> impl IntoView {
    let (r, leaving) = fading(Memo::new(move |_| {
        lan.with(|l| l.as_ref().and_then(|l| l.done.clone()))
    }));
    let keep = move |_| ui().act(Act::LanKeep);
    move || {
        r.get().map(|r: Receipt| {
            let shown = if expanded.get() { r.listed.len() } else { r.listed.len().min(3) };
            let more = r.total.saturating_sub(shown);
            let counts = r.counts;
            view! {
                <div class=move || format!("receipt {}{}", r.tone, if leaving.get() { " leaving" } else { "" }) id="lan-receipt" role="status" aria-live="polite" tabindex="0" on:click=keep on:focus=move |_| ui().act(Act::LanKeep)>
                    <div class="r-mark"><Svg icon=r.icon large=true/></div>
                    <div class="r-body">
                        <b class="r-title" id="lan-receipt-title">{r.title.clone()}</b>
                        {(!r.sub.is_empty()).then(|| view! { <span class="r-sub">{r.sub.clone()}</span> })}
                        {(r.total > 0).then(|| view! {
                            <div class="r-chips">
                                {(counts[0] > 0).then(|| view! { <span class="r-chip new">{format!("+{} new", counts[0])}</span> })}
                                {(counts[1] > 0).then(|| view! { <span class="r-chip changed">{format!("{} changed", counts[1])}</span> })}
                                {(counts[2] > 0).then(|| view! { <span class="r-chip trash">{format!("{} to trash", counts[2])}</span> })}
                            </div>
                            <ul class="r-list">
                                {r.listed.into_iter().take(shown).map(|(mark, entry, title)| view! {
                                    <li class=format!("r-item {mark}")>
                                        {match entry {
                                            Some(e) => view! {
                                                <button class="r-open" on:click=move |ev: web_sys::MouseEvent| { ev.stop_propagation(); ui().act(Act::LanOpen(e)); }>
                                                    <i></i><span>{title.to_string()}</span><Svg icon=Icon::Right/>
                                                </button>
                                            }.into_any(),
                                            None => view! { <span class="r-open static"><i></i><span>{title.to_string()}</span></span> }.into_any(),
                                        }}
                                    </li>
                                }).collect_view()}
                            </ul>
                            {(more > 0 && !expanded.get()).then(|| view! {
                                <button class="link r-more" on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); expanded.set(true); }>{format!("and {more} more")}</button>
                            })}
                        })}
                        {(r.conflicts > 0).then(|| view! {
                            <div class="r-actions">
                                <button class="btn primary" id="lan-resolve" on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); ui().act(Act::LanResolve); }><Svg icon=Icon::Conflicts/>"Resolve now"</button>
                            </div>
                        })}
                    </div>
                    <button class="r-close" id="lan-dismiss" aria-label="Close" title="Close" on:click=move |e: web_sys::MouseEvent| { e.stop_propagation(); ui().act(Act::LanDismiss); }>
                        {r.ring.clone().map(|offset| view! {
                            <svg class="r-ring" viewBox="0 0 22 22" width="26" height="26" aria-hidden="true">
                                <circle cx="11" cy="11" r="9" fill="none" stroke-width="2" stroke-dasharray="56.5" stroke-dashoffset=offset></circle>
                            </svg>
                        })}
                        <Svg icon=Icon::Close/>
                    </button>
                </div>
            }
        })
    }
}

#[component]
pub(crate) fn ScanPanel(#[prop(optional, into)] totp: Signal<bool>) -> impl IntoView {
    view! {
        <div class="layer"><div class="scrim"></div>
            <div class="dialog" role="status">
                <h3>"Scan a QR code"</h3>
                <p>{move || if totp.get() {
                    "Point the camera at the QR code the site shows for two-factor authentication."
                } else {
                    "Point the camera at the other device's code. A code that names its address connects at once; otherwise you type the address."
                }}</p>
                <div class="actions"><button class="btn" on:click=move |_| ui().act(Act::CancelQr)>"Cancel scan"</button></div>
            </div>
        </div>
    }
}

/// The phone vault switcher (0009 §1.8, plan 0045): a sheet of vault cards.
#[component]
fn VaultCards(s: Memo<Option<S>>, open: RwSignal<bool>) -> impl IntoView {
    let cards = field(s, None, |s| Some(s.cards.clone()));
    let switch = move |to: qv_ui_api::SwitchTo| {
        open.set(false);
        ui().act(Act::SwitchVault(to));
    };
    move || {
        cards.get().map(|c| {
            let editing = c.editing;
            let open_quick = c.open_quick;
            view! {
                <div class="layer vault-sheet">
                    <button class="scrim" aria-label="Close" on:click=move |_| open.set(false)></button>
                    <div class="dialog" role="dialog" aria-modal="true" aria-label="Vaults" tabindex="-1" autofocus=true>
                        <div class="grab" aria-hidden="true"></div>
                        <h3>"Vaults"</h3>
                        <div class="vcards">
                            {c.vaults.into_iter().map(|v| {
                                let id = v.id;
                                if v.current {
                                    view! {
                                        <div class="vcard on" id="vcard-open">
                                            <span class=format!("tile {}", v.hue)>{v.initial.clone()}</span>
                                            <span class="l"><b>{v.name.to_string()}</b>
                                                <small><span class="live"></span>{if open_quick { "Open · fingerprint unlock" } else { "Open now" }}</small>
                                            </span>
                                            <button class="btn" id="vcard-lock" data-qv-clear="true" on:click=move |_| { open.set(false); ui().act(Act::Lock); }><Svg icon=Icon::Lock/>"Lock"</button>
                                        </div>
                                    }.into_any()
                                } else {
                                    let small = if !v.exists { "Not found" } else if v.quick { "Fingerprint unlock" } else { "Master password" };
                                    let quick = v.quick;
                                    view! {
                                        <button class="vcard" disabled=editing || !v.exists on:click=move |_| switch(qv_ui_api::SwitchTo::Vault(id))>
                                            <span class=format!("tile {}", v.hue)>{v.initial.clone()}</span>
                                            <span class="l"><b>{v.name.to_string()}</b><small>{small}</small></span>
                                            {quick.then(|| view! { <span class="vq" aria-hidden="true"><Svg icon=Icon::Finger/></span> })}
                                            <Svg icon=Icon::Right/>
                                        </button>
                                    }.into_any()
                                }
                            }).collect_view()}
                        </div>
                        <div class="vmore">
                            <button class="vact" id="sheet-create" disabled=editing on:click=move |_| switch(qv_ui_api::SwitchTo::Mode(qv_ui_api::Mode::Create))><span class="ci"><Svg icon=Icon::Plus/></span>"New vault"</button>
                            <button class="vact" id="sheet-join" disabled=editing on:click=move |_| switch(qv_ui_api::SwitchTo::Mode(qv_ui_api::Mode::Join))><span class="ci"><Svg icon=Icon::Qr/></span>"Join a device"</button>
                            <button class="vact" id="sheet-open" disabled=editing on:click=move |_| { open.set(false); ui().act(Act::SwitchToFile); }><span class="ci"><Svg icon=Icon::Folder/></span>"Open a vault file…"</button>
                        </div>
                        <p class="note">{if editing { "Save or cancel your changes to switch vaults." } else { "Switching locks the open vault." }}</p>
                    </div>
                </div>
            }
        })
    }
}

#[derive(Clone)]
enum Command {
    Open(Screen),
    New,
    Theme,
    Lock,
}

/// The command bar (plan 0040 R7): items through the existing search and
/// commands for existing actions only.
#[component]
fn Palette(s: Memo<Option<S>>) -> impl IntoView {
    let p = field(s, None, |s| s.palette.clone());
    let light = field(s, false, |s| s.light);
    let root = field(s, None, |s| s.root);
    let close = move || ui().act(Act::Ui(UiOp::Palette(false)));
    let query =
        Memo::new(move |_| p.with(|p| p.as_ref().map(|p| p.query.to_string()).unwrap_or_default()));
    let commands = move || {
        let light = light.get();
        let all: Vec<(&'static str, Icon, Command, &'static str)> = vec![
            ("New item", Icon::Plus, Command::New, "Ctrl N"),
            (
                "Password generator",
                Icon::Generator,
                Command::Open(Screen::Generator),
                "",
            ),
            (
                "Sync with another device",
                Icon::Refresh,
                Command::Open(Screen::Devices),
                "",
            ),
            ("Trash", Icon::Trash, Command::Open(Screen::Trash), ""),
            (
                "Conflicts",
                Icon::Conflicts,
                Command::Open(Screen::Conflicts),
                "",
            ),
            (
                "Snapshots",
                Icon::Clock,
                Command::Open(Screen::Snapshots),
                "",
            ),
            (
                "Export or merge an archive",
                Icon::Archive,
                Command::Open(Screen::Archives),
                "",
            ),
            (
                "Check vault integrity",
                Icon::Check,
                Command::Open(Screen::Settings(qv_ui_api::Pane::Verify)),
                "",
            ),
            (
                "Change master password",
                Icon::Key,
                Command::Open(Screen::Settings(qv_ui_api::Pane::Password)),
                "",
            ),
            (
                "Show recovery phrase",
                Icon::Note,
                Command::Open(Screen::Settings(qv_ui_api::Pane::Phrase)),
                "",
            ),
            (
                "Settings",
                Icon::Settings,
                Command::Open(Screen::Settings(qv_ui_api::Pane::Overview)),
                "",
            ),
            (
                if light {
                    "Switch to dark theme"
                } else {
                    "Switch to light theme"
                },
                Icon::Sun,
                Command::Theme,
                "",
            ),
            ("Lock vault", Icon::Lock, Command::Lock, "Ctrl L"),
        ];
        let q = query.get().to_lowercase();
        all.into_iter()
            .filter(|c| q.is_empty() || c.0.to_lowercase().contains(q.as_str()))
            .collect::<Vec<_>>()
    };
    let run = move |cmd: Command| {
        close();
        match cmd {
            Command::Open(s) => ui().act(Act::Go(s)),
            Command::New => {
                if let Some(r) = root.get_untracked() {
                    ui().act(Act::Ws(WsAct::NewEntry(r)));
                }
            }
            Command::Theme => ui().act(Act::Theme(
                if light.get_untracked() {
                    "dark"
                } else {
                    "light"
                }
                .to_owned(),
            )),
            Command::Lock => ui().act(Act::Lock),
        }
    };
    let first = move || {
        p.with_untracked(|p| {
            p.as_ref()
                .and_then(|p| p.hits.first().map(|h| Command::Open(Screen::Entry(h.id))))
        })
        .or_else(|| commands().first().map(|c| c.2.clone()))
    };
    view! {
        <div class="layer">
            <button class="scrim" aria-label="Close command bar" on:click=move |_| close()></button>
            <div class="palette" role="dialog" aria-label="Command bar">
                <div class="q" on:keydown=move |e: web_sys::KeyboardEvent| { if e.key() == "Enter" { e.prevent_default(); if let Some(c) = first() { run(c); } } }>
                    <Svg icon=Icon::Search large=true/>
                    <Input field=WsField::Command label="Search" kind=Kind::Line value=Signal::derive(move || query.get()) bare=true autofocus=true
                        placeholder="Search items, or type a command"/>
                    <kbd>"Esc"</kbd>
                </div>
                <div class="res">
                    {move || p.get().map(|p| {
                        let q = p.query.to_string();
                        view! {
                            {(!p.hits.is_empty()).then(|| view! { <div class="grp">"ITEMS"</div> })}
                            {p.hits.clone().into_iter().map(|h| {
                                let id = h.id;
                                view! {
                                    <button class="it" on:click=move |_| run(Command::Open(Screen::Entry(id)))>
                                        <span class=format!("tile {}", h.hue)>{glyph(&h.glyph)}</span>
                                        <span>{h.title.to_string()}</span><small>{h.sub.to_string()}</small>
                                    </button>
                                }
                            }).collect_view()}
                            {(!p.groups.is_empty()).then(|| view! { <div class="grp">"GROUPS"</div> })}
                            {p.groups.iter().cloned().map(|(id, name)| view! {
                                <button class="it" on:click=move |_| run(Command::Open(Screen::Browse(Some(id))))>
                                    <span class="ic"><Svg icon=Icon::Folder/></span><span>{name.to_string()}</span>
                                </button>
                            }).collect_view()}
                            <PageNavBar nav=p.page.clone()/>
                            {(p.hits.is_empty() && !q.is_empty()).then(|| view! {
                                <p class="muted pad-sm">"Items match titles, usernames, websites and group names. Protected values are never searched."</p>
                            })}
                        }
                    })}
                    {move || {
                        let cmds = commands();
                        view! {
                            {(!cmds.is_empty()).then(|| view! { <div class="grp">"COMMANDS"</div> })}
                            {cmds.into_iter().map(|(label, icon, cmd, keys)| view! {
                                <button class="it" on:click=move |_| run(cmd.clone())>
                                    <span class="ic"><Svg icon/></span><span>{label}</span><small>{keys}</small>
                                </button>
                            }).collect_view()}
                        }
                    }}
                </div>
                <div class="foot2"><span>"Enter to open the first result"</span><span>"Esc to close"</span></div>
            </div>
        </div>
    }
}

/// A modal confirmation. Escape and Cancel answer "no"; it never defaults to yes.
#[component]
fn ConfirmView(s: Memo<Option<S>>) -> impl IntoView {
    let c = field(s, None, |s| s.confirm.clone());
    move || {
        c.get().map(|c| {
            let weak = c.weak;
            let seconds = c.seconds;
            view! {
                <div class="layer">
                    <button class="scrim" aria-label="Cancel" on:click=act(WsAct::Answer(false))></button>
                    <div class="dialog" role="alertdialog" aria-modal="true" aria-label="Confirmation">
                        <h3>{if weak { "Weak password" } else { "Are you sure?" }}</h3>
                        <p>{c.message.clone()}</p>
                        {(c.holding > 0).then(|| view! {
                            <label class="check">
                                <input id="confirm-keep" type="checkbox" prop:checked=c.keep
                                    on:change=move |e| ui().act(Act::Ws(WsAct::KeepSnapshots(event_target_checked(&e))))/>
                                <span>"Keep in snapshots"</span>
                            </label>
                        })}
                        <div class="actions">
                            <button class="btn subtle" id="confirm-cancel" autofocus=true on:click=act(WsAct::Answer(false))>{if weak { "Choose a stronger password" } else { "Cancel" }}</button>
                            <button class="btn danger" id="confirm-continue" data-qv-clear="true" disabled={weak && seconds > 0} on:click=act(WsAct::Answer(true))>
                                {if weak { format!("Use anyway · {seconds}s") } else { "Continue".to_owned() }}
                            </button>
                        </div>
                    </div>
                </div>
            }
        })
    }
}

/// The unlocked shell.
#[component]
pub(crate) fn Shell() -> impl IntoView {
    let s = shell_memo();
    let sheet = RwSignal::new(false);
    items::sheet_signal(sheet);
    let busy = field(s, false, |s| s.busy);
    let vault_screen = field(s, false, |s| s.vault_screen);
    let inert = field(s, false, |s| s.inert);
    let side = field(s, None, |s| Some(s.sidebar.clone()));
    let tabs = field(s, [false; 4], |s| s.tabs);
    let fab = field(s, false, |s| s.fab);
    let new_in = field(s, None, |s| s.new_in);
    let busy_toast = field(s, false, |s| s.busy_toast);
    let scanning = field(s, false, |s| s.scanning);
    let scanning_totp = field(s, false, |s| s.scanning_totp);
    let toasts = field(s, Default::default(), |s| s.toasts.clone());
    // Each toast fades out on its own (plan 0072); the copy toast keeps its
    // element while the seconds count down.
    let (busy_shown, busy_leaving) = fading(Memo::new(move |_| busy_toast.get().then_some(())));
    let clip = Memo::new(move |_| toasts.with(|t| (t.clipboard > 0).then_some(t.clipboard)));
    let (clip_shown, clip_leaving) = fading(clip);
    let clip_on = Memo::new(move |_| clip_shown.with(Option::is_some));
    let clip_left = Memo::new(move |_| clip_shown.get().unwrap_or(0));
    let (err_shown, err_leaving) = fading(Memo::new(move |_| toasts.with(|t| t.error.clone())));
    let (note_shown, note_leaving) = fading(Memo::new(move |_| {
        toasts.with(|t| t.notice.clone().map(|n| (n, t.undo.clone())))
    }));
    let palette_open = field(s, false, |s| s.palette.is_some());
    let viewer_key = field(s, None, |s| s.viewer.as_ref().map(|v| v.key.clone()));
    let anchor = field(s, false, |s| s.anchor_warning);
    let fixture_banner = field(s, false, |s| s.fixture_banner);
    let content_kind = field(s, 0u8, |s| match s.content {
        Content::Vault { .. } => 1,
        Content::Page(_) => 2,
    });
    let nav_class = |on: bool| if on { "nav on" } else { "nav" };
    let sidebar = move || {
        side.get().map(|sb| {
            let root = sb.root;
            view! {
                <button class=nav_class(sb.all_on) id="nav-all" title="All items" disabled=move || busy.get() on:click=go(Screen::Browse(None))>
                    <Svg icon=Icon::All/><span class="t">"All items"</span><span class="n">{sb.total.to_string()}</span>
                </button>
                <div class="h">"TYPES"</div>
                {sb.types.into_iter().map(|t| view! {
                    <button class=nav_class(t.on) id=format!("nav-type-{}", t.kind) title=t.label.clone() disabled=move || busy.get() on:click=go(Screen::Kind(t.kind.clone()))>
                        <Svg icon=t.icon/><span class="t">{t.label.clone()}</span><span class="n">{t.count.map(|n| n.to_string())}</span>
                    </button>
                }).collect_view()}
                {sb.kind_error.clone().map(|e| view! { <p class="banner warn">{e}</p> })}
                <div class="h">"GROUPS"
                    {root.map(|r| view! { <button title="New group" aria-label="New group" disabled=move || busy.get() on:click=act(WsAct::NewGroup(r))><Svg icon=Icon::Plus/></button> })}
                </div>
                {sb.groups.into_iter().map(|g| view! {
                    <button class=nav_class(g.on) title=g.name.to_string() disabled=move || busy.get() on:click=go(Screen::Browse(Some(g.id)))>
                        <span class=format!("dot {}", g.hue)></span><span class="t">{g.name.to_string()}</span><span class="n">{g.entries.to_string()}</span>
                    </button>
                }).collect_view()}
                <PageNavBar nav=sb.group_page.clone()/>
                {(sb.recovered > 0).then(|| view! {
                    <button class=nav_class(sb.recovered_on) title="Recovered items" disabled=move || busy.get() on:click=go(Screen::Recovered)>
                        <Svg icon=Icon::Restore/><span class="t">"Recovered items"</span><span class="n">{sb.recovered.to_string()}</span>
                    </button>
                })}
                <div class="h">"TOOLS"</div>
                {sb.tools.into_iter().map(|t| view! {
                    <button class=nav_class(t.on) id=t.id.clone() title=t.label.clone() disabled=move || busy.get() on:click=go(t.target.clone())>
                        <Svg icon=t.icon/><span class="t">{t.label.clone()}</span>
                        {(t.count > 0).then(|| view! { <span class="badge">{t.count.to_string()}</span> })}
                    </button>
                }).collect_view()}
                <div class="grow"></div>
                <button class=nav_class(sb.settings_on) id="nav-settings" title="Settings" disabled=move || busy.get() on:click=go(Screen::Settings(qv_ui_api::Pane::Overview))>
                    <Svg icon=Icon::Settings/><span class="t">"Settings"</span>
                </button>
            }
        })
    };
    let tab_list: [(Screen, &str, Icon, &str); 4] = [
        (Screen::Browse(None), "Vault", Icon::All, "tab-vault"),
        (
            Screen::Generator,
            "Generator",
            Icon::Generator,
            "tab-generator",
        ),
        (Screen::Devices, "Sync", Icon::Refresh, "tab-devices"),
        (
            Screen::Settings(qv_ui_api::Pane::Overview),
            "Settings",
            Icon::Settings,
            "tab-settings",
        ),
    ];
    view! {
        <Show when=move || fixture_banner.get()><p class="banner inset">"Synthetic validation build · isolated test vault only"</p></Show>
        <Show when=move || anchor.get()><p class="banner inset" role="status">"The rollback record may be copied or rolled back with this vault. Keep it in independent private device storage."</p></Show>
        <div class=move || if vault_screen.get() { "shell" } else { "shell nolist" } inert=move || inert.get().then_some("true")>
            <nav class="side" aria-label="Vault">{sidebar}</nav>
            {move || match content_kind.get() {
                1 => view! { <items::ListPane s/><items::Detail s/> }.into_any(),
                2 => view! { <pages::Page s/> }.into_any(),
                _ => ().into_any(),
            }}
        </div>
        <Show when=move || fab.get()>
            <button class="fab" aria-label="New item" on:click=move |_| { if let Some(g) = new_in.get_untracked() { ui().act(Act::Ws(WsAct::NewEntry(g))); } }><Svg icon=Icon::Plus/></button>
        </Show>
        <nav class="tabbar" aria-label="Sections" inert=move || inert.get().then_some("true")>
            {tab_list.into_iter().enumerate().map(|(i, (target, label, icon, id))| {
                let vault = id == "tab-vault";
                view! {
                    <button class=move || if tabs.get()[i] { "on" } else { "" } id=id disabled=move || busy.get()
                        // Holding the Vault tab (app.js sends it as a Ctrl-click)
                        // opens the vault switcher (plan 0045).
                        on:click=move |e: web_sys::MouseEvent| { if vault && e.ctrl_key() { sheet.set(true); } else { ui().act(Act::Go(target.clone())); } }>
                        <i><Svg icon/></i>{label}
                    </button>
                }
            }).collect_view()}
        </nav>
        {move || busy_shown.get().map(|_| view! {
            <div class="toasts"><div class=leave("toast busy-toast", busy_leaving) role="status">"Working… other actions wait until this finishes."</div></div>
        })}
        <LanPanel source=LanSource::Unlocked/>
        <Show when=move || scanning.get()><ScanPanel totp=scanning_totp/></Show>
        <Show when=move || sheet.get() && !busy.get()><VaultCards s open=sheet/></Show>
        {move || viewer_key.get().map(|_| view! { <items::Viewer s/> })}
        <Show when=move || !busy.get()><ConfirmView s/></Show>
        <Show when=move || !busy.get()>
            <div class="toasts">
                {move || clip_on.get().then(|| view! {
                    <div class=leave("toast", clip_leaving) role="status"><Svg icon=Icon::Copy/><span>{move || format!("Copied · clears in {} s", clip_left.get())}</span>
                        // One width per second with a 1 s transition (classes:
                        // the CSP forbids inline styles).
                        <span class=move || format!("bar drain{}", clip_left.get().saturating_sub(1).min(19))></span>
                    </div>
                })}
                {move || err_shown.get().map(|e| view! {
                    <div class=leave("toast bad", err_leaving) role="alert"><Svg icon=Icon::Warn/><span class="error">{e}</span>
                        <button on:click=act(WsAct::Dismiss)>"Dismiss"</button>
                    </div>
                })}
                {move || note_shown.get().map(|(n, undo)| view! {
                    <div class=leave("toast", note_leaving) role="status"><Svg icon=Icon::Check/><span class="notice">{n}</span>
                        {undo.map(|u| view! { <button id="toast-undo" on:click=act(u.clone())>"Undo"</button> })}
                        <button aria-label="Dismiss" on:click=act(WsAct::Dismiss)><Svg icon=Icon::Close/></button>
                    </div>
                })}
            </div>
        </Show>
        <Show when=move || palette_open.get() && !busy.get()><Palette s/></Show>
    }
}
