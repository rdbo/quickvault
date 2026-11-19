// SPDX-License-Identifier: AGPL-3.0-or-later

//! The locked screens: welcome, unlock, create,
//! phrase, recover, import, join, recovery baseline and key rotation. The
//! wizard step, the phrase's shown state and the menus are this page's own
//! state, kept per form epoch as the component's signals were.
use crate::icons::{Icon, Logo, Svg};
use crate::input::{SecretInput, WordInput};
use crate::{shell, ui};
use leptos::prelude::*;
use qv_ui_api::{Act, Action, Body, Consent, Locked as L, LockedField, Mode, Phase, Z};

fn field<T: Clone + PartialEq + Send + Sync + 'static>(
    l: Memo<Option<L>>,
    d: T,
    f: impl Fn(&L) -> T + Send + Sync + 'static,
) -> Memo<T> {
    Memo::new(move |_| l.with(|l| l.as_ref().map_or_else(|| d.clone(), &f)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sheet {
    None,
    VaultMenu,
    SaveMenu,
    Protection,
}

/// Which locked body shows; it is rebuilt when this changes (a new epoch
/// rebuilds the form, dropping any typed DOM value).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    Resume,
    Rotation,
    Phrase,
    Recovery,
    Create,
    Import,
    Recover,
    Join,
    Welcome,
    Unlock,
}

fn perform(a: Action, consent: Consent) {
    ui().act(Act::Perform(a, consent));
}

#[component]
fn PhraseGrid(
    #[prop(into)] words: Signal<Vec<Z>>,
    #[prop(into)] hidden: Signal<bool>,
) -> impl IntoView {
    view! {
        <div class=move || if hidden.get() { "phrase mono blurred" } else { "phrase mono" }
            aria-hidden=move || if hidden.get() { "true" } else { "false" }>
            {move || words.get().into_iter().enumerate().map(|(i, w)| view! {
                <span><small>{(i + 1).to_string()}</small><b class="w">{w.to_string()}</b></span>
            }).collect_view()}
        </div>
    }
}

/// The spinning dial around the vault mark (decorative).
#[component]
fn Safe(#[prop(into)] opening: Signal<bool>) -> impl IntoView {
    let ticks = (0..48)
        .map(|i| {
            let a = f64::from(i) * 7.5_f64.to_radians();
            let inner = if i % 6 == 0 { 56.0 } else { 60.0 };
            let class = if i % 6 == 0 { "major" } else { "" };
            view! {
                <line class=class x1=format!("{:.2}", 66.0 + inner * a.sin()) y1=format!("{:.2}", 66.0 - inner * a.cos())
                    x2=format!("{:.2}", 66.0 + 64.0 * a.sin()) y2=format!("{:.2}", 66.0 - 64.0 * a.cos())></line>
            }
        })
        .collect_view();
    view! {
        <div class=move || if opening.get() { "safe opening" } else { "safe" }>
            <svg class="ticks" viewBox="0 0 132 132" aria-hidden="true">{ticks}</svg>
            <div class="avatar"><Svg icon=Icon::Lock/></div>
        </div>
    }
}

#[component]
pub(crate) fn Locked() -> impl IntoView {
    let u = ui();
    let l = u.sel(None, |f| match &f.body {
        Body::Locked(l) => Some((**l).clone()),
        _ => None,
    });
    let epoch = u.sel(0, |f| f.epoch);
    let busy = field(l, false, |l| l.busy);
    let preview = field(l, false, |l| l.preview);
    let fixture = field(l, false, |l| l.fixture);
    let gate_on = field(l, false, |l| l.gate);
    let error = field(l, None, |l| l.error.clone());
    let notice = field(l, None, |l| l.notice.clone());
    let sheet = RwSignal::new(Sheet::None);
    // The protection sheet runs this action once acknowledged.
    let after_ack = RwSignal::new(None::<Action>);
    let step = RwSignal::new((u64::MAX, 0u8));
    let shown = RwSignal::new((u64::MAX, false));
    let confirming = RwSignal::new((u64::MAX, false));
    let skip = RwSignal::new((u64::MAX, false));
    let on = move |s: RwSignal<(u64, bool)>| s.get().0 == epoch.get() && s.get().1;
    // Create/unlock/recover need the reduced-protection acknowledgement first.
    let gate = move |a: Action| {
        if gate_on.get_untracked() {
            after_ack.set(Some(a));
            sheet.set(Sheet::Protection);
        } else {
            perform(a, Consent::Recorded);
        }
    };
    // A scanned join that waits only for the review opens it at once and
    // joins when it is acknowledged; "Not now" leaves the filled form
    // (0014 §6.3, plan 0072).
    let join_review = field(l, false, |l| l.join_review);
    Effect::new(move |_| {
        if join_review.get() && gate_on.get_untracked() {
            after_ack.set(Some(Action::JoinDevice));
            sheet.set(Sheet::Protection);
        }
    });
    let to_mode = move |m: Mode| -> Box<dyn Fn(web_sys::MouseEvent) + Send + Sync> {
        Box::new(move |_| {
            sheet.set(Sheet::None);
            ui().act(Act::SelectMode(m));
        })
    };
    let screen = Memo::new(move |_| {
        l.with(|l| {
            let Some(l) = l else {
                return (Screen::Unlock, 0);
            };
            let s = if l.phase == Phase::Locked && l.resume.is_some() {
                Screen::Resume
            } else if l.phase == Phase::Rotation {
                Screen::Rotation
            } else if l.phase == Phase::Phrase {
                Screen::Phrase
            } else if l.phase == Phase::Recovery {
                Screen::Recovery
            } else if l.mode == Mode::Create {
                Screen::Create
            } else if l.mode == Mode::Import {
                Screen::Import
            } else if l.mode == Mode::Recover {
                Screen::Recover
            } else if l.mode == Mode::Join {
                Screen::Join
            } else if l.first_run && !l.busy {
                Screen::Welcome
            } else {
                Screen::Unlock
            };
            (s, epoch.get())
        })
    });
    let err_view = move || {
        if let Some(e) = error.get() {
            view! { <div class="err" role="alert"><Svg icon=Icon::Warn/><span>{e}</span></div> }
                .into_any()
        } else if let Some(n) = notice.get() {
            view! { <p class="banner ok" role="status">{n}</p> }.into_any()
        } else {
            ().into_any()
        }
    };
    let words = field(l, Vec::new(), |l| l.words.clone());
    let positions = field(l, [0, 0, 0], |l| l.positions);
    let typed_path = field(l, false, |l| l.typed_path);
    let picked = field(l, None, |l| l.picked.as_ref().map(|p| p.to_string()));
    let can_pick = field(l, false, |l| l.can_pick);
    let pick_vault = move |_| {
        sheet.set(Sheet::None);
        ui().act(Act::Pick(qv_ui_api::Pick::Vault));
    };
    let path_input = move || -> Option<AnyView> {
        typed_path.get().then(|| view! {
            <SecretInput field=LockedField::Path label="Vault file (full path)" id="vault-path" secret=false disabled=busy/>
        }.into_any())
    };
    let vault_line = move || {
        view! {
            <div class="banner ok">
                <Svg icon=Icon::Folder/>
                <span class="sp">{move || match picked.get() { Some(f) => format!("Vault file: {f}"), None => "This device's vault".to_owned() }}</span>
                <Show when=move || can_pick.get()><button class="link" on:click=pick_vault>"Use another file…"</button></Show>
            </div>
        }
    };
    let body = move || {
        let (s, _) = screen.get();
        match s {
            Screen::Resume => {
                let need_new = field(l, false, |l| l.resume.is_some_and(|r| r.0));
                let need_old = field(l, false, |l| l.resume.is_some_and(|r| r.1));
                view! {
                    <div class="wizard fade-in">
                        <h2>"Finish the interrupted key rotation"</h2>
                        <p>"A key rotation for this vault was interrupted. Complete it to use the new master password and phrase, or roll it back to keep the previous ones. Nothing else can open the vault until it is finished."</p>
                        <Show when=move || need_new.get()><SecretInput field=LockedField::Password label="New master password (chosen for the rotation)" id="resume-new" secret=true disabled=busy/></Show>
                        <Show when=move || need_old.get()><SecretInput field=LockedField::Repeat label="Previous master password" id="resume-old" secret=true disabled=busy/></Show>
                        {err_view}
                        <div class="actions stack">
                            <button class="btn primary" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::ResumeComplete, Consent::Recorded)>"Complete the rotation"</button>
                            <button class="btn" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::ResumeRollback, Consent::Recorded)>"Roll back to the previous generation"</button>
                            <button class="btn subtle" data-qv-clear="true" on:click=move |_| ui().act(Act::Lock)>"Cancel"</button>
                        </div>
                    </div>
                }.into_any()
            }
            Screen::Rotation => {
                let confirmed = field(l, false, |l| l.rotation_confirmed);
                view! {
                    <div class="wizard fade-in">
                        <h2>"Your new recovery phrase"</h2>
                        <p>"Write these 24 words down in order. They replace the old phrase once the rotation is installed. Nothing has changed yet."</p>
                        <PhraseGrid words=words hidden=false/>
                        {move || if confirmed.get() {
                            view! {
                                <div class="banner ok"><Svg icon=Icon::Check/><span>"The new recovery words are confirmed."</span></div>
                                <div class="actions">
                                    <button class="btn subtle" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::CancelRotation, Consent::Given(true))>"Cancel the rotation"</button>
                                    <button class="btn primary" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::InstallRotation, Consent::Given(true))>{move || if busy.get() { "Installing…" } else { "Install the key rotation" }}</button>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <p class="hint">{move || { let p = positions.get(); format!("Word positions: {}, {}, {}", p[0], p[1], p[2]) }}</p>
                                <WordInput field=LockedField::Word0 id="rot-word-0" n=Signal::derive(move || positions.get()[0]) disabled=busy/>
                                <WordInput field=LockedField::Word1 id="rot-word-1" n=Signal::derive(move || positions.get()[1]) disabled=busy/>
                                <WordInput field=LockedField::Word2 id="rot-word-2" n=Signal::derive(move || positions.get()[2]) disabled=busy/>
                                {err_view}
                                <div class="actions">
                                    <button class="btn subtle" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::CancelRotation, Consent::Given(true))>"Cancel the rotation (nothing changes)"</button>
                                    <button class="btn primary" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::ConfirmRotation, Consent::Given(true))>"Confirm recovery words"</button>
                                </div>
                            }.into_any()
                        }}
                    </div>
                }.into_any()
            }
            Screen::Phrase => view! {
                <div class="wizard fade-in">
                    <div class="steps"><i class="on"></i><i class="on"></i><i class="on"></i></div>
                    {move || if !on(confirming) {
                        view! {
                            <h2>"Your recovery phrase"</h2>
                            <p>"If you forget your password, these 24 words open your vault. Anyone with them and your vault file can open it, so keep them somewhere safe and offline."</p>
                            <div class="reveal-cover">
                                <PhraseGrid words=words hidden=Signal::derive(move || !on(shown))/>
                                <Show when=move || !on(shown)>
                                    <button class="btn primary" id="phrase-show" on:click=move |_| shown.set((epoch.get_untracked(), true))><Svg icon=Icon::Eye/>"Show words"</button>
                                </Show>
                            </div>
                            <div class="actions">
                                <button class="btn subtle" data-qv-clear="true" on:click=move |_| ui().act(Act::Lock)>"Lock and clear phrase"</button>
                                <button class="btn primary" id="phrase-written" disabled=move || !on(shown) on:click=move |_| confirming.set((epoch.get_untracked(), true))>"I wrote them down"</button>
                            </div>
                        }.into_any()
                    } else {
                        view! {
                            <h2>"Check three words"</h2>
                            <p>"Type the requested words from your copy to confirm it."</p>
                            <p class="hint">{move || { let p = positions.get(); format!("Word positions: {}, {}, {}", p[0], p[1], p[2]) }}</p>
                            <WordInput field=LockedField::Word0 id="word-0" n=Signal::derive(move || positions.get()[0]) disabled=busy/>
                            <WordInput field=LockedField::Word1 id="word-1" n=Signal::derive(move || positions.get()[1]) disabled=busy/>
                            <WordInput field=LockedField::Word2 id="word-2" n=Signal::derive(move || positions.get()[2]) disabled=busy/>
                            {err_view}
                            <div class="actions">
                                <button class="btn subtle" on:click=move |_| confirming.set((epoch.get_untracked(), false))>"Back to the words"</button>
                                <button class="btn primary" id="phrase-confirm" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::ConfirmPhrase, Consent::Given(true))>"Confirm and open"</button>
                            </div>
                            <details class="muted">
                                <summary>"Skip phrase confirmation"</summary>
                                <label class="check">
                                    <input type="checkbox" prop:checked=move || on(skip) on:change=move |e| skip.set((epoch.get_untracked(), event_target_checked(&e)))/>
                                    <span>"I understand I may lose access if I forget my password. Record that I skipped confirmation."</span>
                                </label>
                                <button class="btn" disabled=move || busy.get() || !on(skip) on:click=move |_| perform(Action::SkipPhrase, Consent::Given(on(skip)))>"Record skip and continue"</button>
                            </details>
                        }.into_any()
                    }}
                </div>
            }.into_any(),
            Screen::Recovery => view! {
                <div class="wizard fade-in">
                    <h2>"Check this recovery baseline"</h2>
                    <p>"The external anchor is missing or mismatched. This verified file may be an older copy; opening it does not prove it is the latest state."</p>
                    <p>"Accepting it establishes a new local baseline from exactly this file's contents. Nothing is adopted without your action."</p>
                    {err_view}
                    <div class="actions stack">
                        <button class="btn primary" data-qv-clear="true" disabled=move || busy.get() on:click=move |_| perform(Action::AdoptBaseline, Consent::Given(true))>"Accept this file as the recovery baseline"</button>
                        <button class="btn" on:click=move |_| ui().act(Act::Lock)>"Decline and lock"</button>
                    </div>
                </div>
            }.into_any(),
            Screen::Create => create(l, epoch, step, sheet, busy, preview, err_view, gate, to_mode, path_input),
            Screen::Import => {
                let ready = field(l, false, |l| l.import_ready);
                let ack = field(l, false, |l| l.import_ack);
                let name = field(l, String::new(), |l| l.import_name.to_string());
                view! {
                    <div class="wizard fade-in">
                        <h2>"Import a private copy"</h2>
                        <p>"Changes in QuickVault won't update the selected file. Choose a closed or exported vault file; a live database copy may be incomplete."</p>
                        <p>"This file has no trusted rollback record on this device. Authentication can verify its contents, but cannot establish that it is the latest copy."</p>
                        <Show when=move || ready.get()>
                            <div class="field">
                                <label for="import-name">"Local file name"</label>
                                <input id="import-name" type="text" maxlength="256" prop:value=move || name.get_untracked() disabled=move || busy.get()
                                    autocomplete="off" spellcheck="false"
                                    on:input=move |e| ui().input(qv_ui_api::Field::Locked(LockedField::Name), &event_target_value(&e))/>
                            </div>
                            <SecretInput field=LockedField::Password label="Master password" id="import-password" secret=true disabled=busy autofocus=true/>
                            <label class="check">
                                <input id="import-ack" type="checkbox" prop:checked=move || ack.get() disabled=move || busy.get()
                                    on:input=move |e| ui().act(Act::ImportAck(event_target_checked(&e)))/>
                                "I accept this file as a new local baseline and understand that QuickVault will edit a private copy."
                            </label>
                        </Show>
                        {err_view}
                        <div class="actions">
                            <button class="btn subtle" disabled=move || busy.get() on:click=to_mode(Mode::Unlock)>"Cancel"</button>
                            <button class="btn primary" id="import-submit" data-qv-clear="true"
                                disabled=move || busy.get() || preview.get() || !ready.get() || !ack.get()
                                on:click=move |_| gate(Action::ImportVault)>"Verify and import"</button>
                        </div>
                    </div>
                }.into_any()
            }
            Screen::Recover => view! {
                <div class="wizard fade-in">
                    <h2>"Recover with your phrase"</h2>
                    <p>"Type your 24 recovery words, separated by spaces. You can choose a new master password once the vault is open."</p>
                    {vault_line}
                    <SecretInput field=LockedField::Phrase label="Recovery phrase · 24 words" id="phrase" secret=true disabled=busy autofocus=true/>
                    {path_input}
                    {err_view}
                    <div class="actions">
                        <button class="btn subtle" on:click=to_mode(Mode::Unlock)>"Back"</button>
                        <button class="btn primary" id="recover-submit" data-qv-clear="true" disabled=move || busy.get() || preview.get() on:click=move |_| gate(Action::Recover)>{move || if busy.get() { "Opening…" } else { "Open with recovery phrase" }}</button>
                    </div>
                    <details class="muted">
                        <summary>"Inspect a missing or mismatched anchor with your password"</summary>
                        <SecretInput field=LockedField::Password label="Master password" id="recovery-password" secret=true disabled=busy/>
                        <button class="btn" disabled=move || busy.get() || preview.get() on:click=move |_| gate(Action::RecoverPassword)>"Inspect for recovery"</button>
                    </details>
                </div>
            }.into_any(),
            Screen::Join => {
                let scanned = field(l, false, |l| l.code_scanned);
                let camera = field(l, false, |l| l.camera);
                let scanning = field(l, false, |l| l.scanning);
                view! {
                    <div class="wizard fade-in">
                        <h2>"Join from another device"</h2>
                        <p>"On the other device, open Sync and choose Show a code. Scan it, or type the code and the address it shows."</p>
                        <Show when=crate::android>
                            <button class="btn wide" disabled=move || !camera.get() || busy.get() data-qv-clear="true"
                                on:click=move |_| ui().act(Act::RequestQr(qv_ui_api::QrTarget::NewDevice))>
                                <Svg icon=Icon::Qr/>"Scan a code"
                            </button>
                            <Show when=move || !camera.get()><p class="hint">"Camera scanning is unavailable. Type the code and address instead."</p></Show>
                        </Show>
                        {move || if scanned.get() {
                            view! { <p class="banner ok" role="status" id="lan-code-scanned"><Svg icon=Icon::Check/>" Code from the QR code"</p> }.into_any()
                        } else {
                            view! { <SecretInput field=LockedField::LanCode label="Code" id="lan-join-code" secret=true disabled=busy reveal=true/> }.into_any()
                        }}
                        <SecretInput field=LockedField::LanEndpoint label="The other device's address (ip:port)" id="lan-join-endpoint" secret=false disabled=busy/>
                        {err_view}
                        <div class="actions">
                            <button class="btn subtle" on:click=to_mode(Mode::Unlock)>"Back"</button>
                            <button class="btn primary" id="join-submit" data-qv-clear="true" disabled=move || busy.get() || preview.get() on:click=move |_| gate(Action::JoinDevice)>{move || if busy.get() { "Joining…" } else { "Join" }}</button>
                        </div>
                    </div>
                    <shell::LanPanel source=shell::LanSource::Locked/>
                    <Show when=move || scanning.get()><shell::ScanPanel/></Show>
                }.into_any()
            }
            Screen::Welcome => view! {
                <div class="welcome fade-in">
                    <Logo class="logo-hero"/>
                    <h1>"Welcome to QuickVault"</h1>
                    <p>"Your passwords stay encrypted on this device. No account, no server."</p>
                    <div class="choices">
                        <button class="choice" id="welcome-create" on:click=to_mode(Mode::Create)><span class="ci"><Svg icon=Icon::Plus/></span><b>"Create a new vault"</b><span>"Start fresh on this device"</span></button>
                        <button class="choice" id="welcome-join" on:click=to_mode(Mode::Join)><span class="ci"><Svg icon=Icon::Qr/></span><b>"Join from another device"</b><span>"Copy a vault from your phone or computer"</span></button>
                        <Show when=move || can_pick.get()>
                            <button class="choice" id="welcome-open" on:click=pick_vault><span class="ci"><Svg icon=Icon::Folder/></span><b>"Open a vault file"</b><span>"Use a vault you already have"</span></button>
                        </Show>
                        <button class="choice" id="welcome-recover" on:click=to_mode(Mode::Recover)><span class="ci"><Svg icon=Icon::Key/></span><b>"Recover with your phrase"</b><span>"Use your 24 recovery words"</span></button>
                    </div>
                    {err_view}
                    {path_input}
                </div>
            }.into_any(),
            Screen::Unlock => unlock(l, sheet, busy, preview, err_view, gate, to_mode, pick_vault, path_input),
        }
    };
    let protection = field(l, None, |l| Some(l.protection.clone()));
    let ack_needed = field(l, false, |l| l.ack_needed);
    let android_fixture = Memo::new(move |_| fixture.get() && crate::android());
    view! {
        <div class="locked"
            on:keydown=move |e: web_sys::KeyboardEvent| {
                if e.key() == "Escape" && sheet.get_untracked() != Sheet::None {
                    e.stop_propagation();
                    e.prevent_default();
                    sheet.set(Sheet::None);
                } else if e.key() == "Escape" && l.with_untracked(|l| l.as_ref().is_some_and(|l| l.mode != Mode::Unlock && !l.busy)) {
                    // Create, Recover and Join step back to the vault (also
                    // Android Back, plan 0044).
                    e.stop_propagation();
                    e.prevent_default();
                    ui().act(Act::SelectMode(Mode::Unlock));
                }
            }>
            <Show when=move || android_fixture.get()><p class="banner">"Synthetic validation build · isolated test vault only"</p></Show>
            <Show when=move || preview.get()><p class="banner">"Read-only preview · vault actions are disabled. Do not enter real credentials."</p></Show>
            <div class="locked-body">{body}</div>
            <Show when=move || ack_needed.get()>
                <div class="locked-foot">
                    {move || protection.get().map(|p| view! {
                        <button class=format!("status-chip {}", p.tone) id="protection-chip" on:click=move |_| { after_ack.set(None); sheet.set(Sheet::Protection); }>
                            <Svg icon=Icon::Shield/>{format!("{} protection · review", p.label)}
                        </button>
                    })}
                </div>
            </Show>
        </div>
        {move || (sheet.get() == Sheet::Protection).then(|| protection.get().map(|p| {
            let reduced = p.reduced;
            let quick = p.quick_unlock;
            view! {
                <div class="layer">
                    <button class="scrim" aria-label="Close" on:click=move |_| sheet.set(Sheet::None)></button>
                    <div class="dialog" role="dialog" aria-modal="true" aria-label="Device protection">
                        <h3>"Device protection"</h3>
                        <div class=format!("level {}", p.tone) id="protection-level"><Svg icon=Icon::Shield/><b>{p.label.clone()}</b><span>"protection"</span></div>
                        <p>{if reduced { "QuickVault could not confirm everything below on this device. Read what it checked before using a vault here." } else { "QuickVault checked how this device protects data at rest." }}</p>
                        <div class="card" id="protection-status">
                            {p.rows.into_iter().map(|r| view! { <div class="set-row"><span class="l"><b>{r.label}</b></span><span class=r.class>{r.text}</span></div> }).collect_view()}
                        </div>
                        <p class="hint">"Clearing an input cannot guarantee erasure of framework or operating-system copies. Storage, swap and hibernation protection depend on the operating system."</p>
                        <p class="hint">{if quick { "Fingerprint unlock turns on after you unlock with your master password." } else { "Quick unlock is unavailable on this device." }}</p>
                        <div class="actions">
                            {move || if ack_needed.get() {
                                view! {
                                    <button class="btn subtle" on:click=move |_| sheet.set(Sheet::None)>"Not now"</button>
                                    <button class="btn primary" id="protection-ack" on:click=move |_| {
                                        let next = after_ack.get_untracked();
                                        after_ack.set(None);
                                        sheet.set(Sheet::None);
                                        ui().act(Act::AcknowledgeProtection(next));
                                    }>"I understand, continue"</button>
                                }.into_any()
                            } else {
                                view! { <button class="btn primary" on:click=move |_| sheet.set(Sheet::None)>"Done"</button> }.into_any()
                            }}
                        </div>
                    </div>
                </div>
            }
        }))}
    }
}

#[allow(clippy::too_many_arguments)] // The create wizard's view of the locked screen's state.
fn create(
    l: Memo<Option<L>>,
    epoch: Memo<u64>,
    step: RwSignal<(u64, u8)>,
    sheet: RwSignal<Sheet>,
    busy: Memo<bool>,
    preview: Memo<bool>,
    err_view: impl Fn() -> AnyView + Copy + Send + Sync + 'static,
    gate: impl Fn(Action) + Copy + Send + Sync + 'static,
    to_mode: impl Fn(Mode) -> Box<dyn Fn(web_sys::MouseEvent) + Send + Sync>
    + Copy
    + Send
    + Sync
    + 'static,
    path_input: impl Fn() -> Option<AnyView> + Copy + Send + Sync + 'static,
) -> AnyView {
    let wizard = move || {
        if step.get().0 == epoch.get() {
            step.get().1
        } else {
            0
        }
    };
    let mismatch = field(l, false, |l| l.mismatch);
    let fair = field(l, false, |l| l.fair_warning);
    let meter = field(l, None, |l| l.meter.clone());
    let weak = field(l, false, |l| l.phase == Phase::WeakPassword);
    let weak_seconds = field(l, 0, |l| l.weak_seconds);
    let suggestion = field(l, None, |l| l.suggestion.as_ref().map(|s| s.to_string()));
    let picked = field(l, None, |l| l.picked.as_ref().map(|p| p.to_string()));
    let folder = field(l, String::new(), |l| l.folder_place.to_string());
    let fallback = field(l, false, |l| l.fallback);
    let pick = move |p: qv_ui_api::Pick| {
        move |_| {
            sheet.set(Sheet::None);
            ui().act(Act::Pick(p.clone()));
        }
    };
    view! {
        <div class="wizard fade-in">
            <div class="steps"><i class="on"></i><i class=move || { if wizard() >= 1 { "on" } else { "" } }></i><i></i></div>
            <div hidden=move || wizard() != 0>
                <h2>"Name your vault"</h2>
                <SecretInput field=LockedField::Name label="Vault name" id="vault-name" secret=false disabled=busy autofocus=true placeholder="Personal"/>
                // Android keeps vaults in the app's private folder: no place to show.
                <Show when=move || !crate::android()>
                    <div class="banner ok">
                        <Svg icon=Icon::Folder/>
                        <span class="sp" id="create-place">{move || match picked.get() { Some(f) => format!("Saves as {f}"), None => format!("Saves in {}", folder.get()) }}</span>
                        <Show when=move || !fallback.get()>
                            <div class="pop-anchor">
                                <button class="link" id="create-change" on:click=move |_| sheet.update(|s| *s = if *s == Sheet::SaveMenu { Sheet::None } else { Sheet::SaveMenu })>"Change"</button>
                                <Show when=move || sheet.get() == Sheet::SaveMenu>
                                    <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| sheet.set(Sheet::None)></button>
                                    <div class="menu pop end" role="menu">
                                        <button class="mi" id="create-folder" on:click=pick(qv_ui_api::Pick::Folder)><Svg icon=Icon::Folder/>"Change the folder…"</button>
                                        <button class="mi" id="create-save-as" on:click=pick(qv_ui_api::Pick::NewVault)><Svg icon=Icon::File/>"Save just this one elsewhere…"</button>
                                    </div>
                                </Show>
                            </div>
                        </Show>
                    </div>
                </Show>
                {path_input}
                {move || (wizard() == 0).then(err_view)}
                <div class="actions">
                    <button class="btn subtle" on:click=to_mode(Mode::Unlock)>"Cancel"</button>
                    <button class="btn primary" id="create-next" disabled=move || busy.get() on:click=move |_| step.set((epoch.get_untracked(), 1))>"Continue"</button>
                </div>
            </div>
            <div hidden=move || wizard() != 1>
                <h2>"Choose a master password"</h2>
                <p class="muted">"It is the key to this vault. QuickVault cannot reset it, so make it long and memorable."</p>
                <SecretInput field=LockedField::Password label="Master password" id="password" secret=true disabled=busy rate=true/>
                {move || crate::input::meter_view(meter.get())}
                <SecretInput field=LockedField::Repeat label="Type it again" id="repeat" secret=true disabled=busy/>
                <Show when=move || mismatch.get()><p class="hint" role="status">"The two passwords do not match yet."</p></Show>
                <Show when=move || fair.get() && meter.with(Option::is_none)><div class="banner"><Svg icon=Icon::Warn/><span>"This password is fair. Consider a longer, less predictable passphrase."</span></div></Show>
                <div class="banner ok"><Svg icon=Icon::Generator/>
                    <div class="sp">
                        "Want one that is easy to remember? "
                        <button class="link" disabled=move || busy.get() || weak.get() || preview.get() on:click=move |_| perform(Action::SuggestPassword, Consent::Given(true))>"Suggest a six-word passphrase"</button>
                        {move || suggestion.get().map(|s| view! {
                            <div class="phrase single mono">{s}</div>
                            <span class="hint">"Visible for 30 seconds. Type it into both fields above."</span>
                        })}
                    </div>
                </div>
                <Show when=move || weak.get()>
                    <div class="banner bad" role="alertdialog" aria-label="Weak password confirmation">
                        <Svg icon=Icon::Warn/>
                        <div class="sp">
                            <p>"This password is weak and could be guessed by an attacker who obtains your vault file. Create the vault anyway?"</p>
                            <div class="actions start">
                                <button class="btn" autofocus=true on:click=to_mode(Mode::Create)>"Choose a stronger password"</button>
                                <button class="btn danger" disabled=move || { weak_seconds.get() > 0 } on:click=move |_| gate(Action::ConfirmWeak)>{move || format!("Create anyway · {}s", weak_seconds.get())}</button>
                            </div>
                        </div>
                    </div>
                </Show>
                {move || (wizard() == 1).then(err_view)}
                <Show when=move || !weak.get()>
                    <div class="actions">
                        <button class="btn subtle" disabled=move || busy.get() on:click=move |_| step.set((epoch.get_untracked(), 0))>"Back"</button>
                        <button class="btn primary" id="create-submit" data-qv-clear="true" disabled=move || busy.get() || preview.get() || mismatch.get() on:click=move |_| gate(Action::Create)>{move || if busy.get() { "Creating…" } else { "Create vault" }}</button>
                    </div>
                </Show>
            </div>
        </div>
    }
    .into_any()
}

#[allow(clippy::too_many_arguments)] // The unlock card's view of the locked screen's state.
fn unlock(
    l: Memo<Option<L>>,
    sheet: RwSignal<Sheet>,
    busy: Memo<bool>,
    preview: Memo<bool>,
    err_view: impl Fn() -> AnyView + Copy + Send + Sync + 'static,
    gate: impl Fn(Action) + Copy + Send + Sync + 'static,
    to_mode: impl Fn(Mode) -> Box<dyn Fn(web_sys::MouseEvent) + Send + Sync>
    + Copy
    + Send
    + Sync
    + 'static,
    pick_vault: impl Fn(web_sys::MouseEvent) + Copy + Send + Sync + 'static,
    path_input: impl Fn() -> Option<AnyView> + Copy + Send + Sync + 'static,
) -> AnyView {
    let vaults = field(l, Vec::new(), |l| l.vaults.clone());
    let selected = field(l, None, |l| l.selected.clone());
    let picked = field(l, None, |l| l.picked.as_ref().map(|p| p.to_string()));
    let quick = field(l, false, |l| l.quick);
    let quick_label = field(l, String::new(), |l| l.quick_label.clone());
    let autoprompt = field(l, None, |l| l.autoprompt);
    let has_error = field(l, false, |l| l.error.is_some());
    let banner = field(l, None, |l| l.autofill_banner.clone());
    let can_pick = field(l, false, |l| l.can_pick);
    let vault_menu = move || {
        view! {
            <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| sheet.set(Sheet::None)></button>
            <div class="menu pop mid" role="menu">
                <Show when=move || !vaults.get().is_empty()><div class="label">"VAULTS"</div></Show>
                {move || vaults.get().into_iter().map(|v| {
                    let on = v.current;
                    let id = v.id;
                    let small = if v.exists { v.place.to_string() } else { format!("Not found · {}", v.place.as_str()) };
                    view! {
                        <button class=if on { "mi on" } else { "mi" } role="menuitemradio"
                            on:click=move |_| { sheet.set(Sheet::None); ui().act(Act::SelectVault(id)); }>
                            <Svg icon=Icon::Lock/>
                            <span class="vault-mi"><b>{v.name.to_string()}</b><small>{small}</small></span>
                            {on.then(|| view! { <span class="sub"><Svg icon=Icon::Check/></span> })}
                        </button>
                    }
                }).collect_view()}
                <Show when=move || !vaults.get().is_empty()><hr/></Show>
                <Show when=move || can_pick.get()><button class="mi" id="menu-open-file" on:click=pick_vault><Svg icon=Icon::Folder/>"Open a vault file…"</button></Show>
                <button class="mi" id="menu-create" on:click=to_mode(Mode::Create)><Svg icon=Icon::Plus/>"Create a new vault"</button>
                <button class="mi" id="menu-join" on:click=to_mode(Mode::Join)><Svg icon=Icon::Qr/>"Join from another device"</button>
                <button class="mi" id="menu-recover" on:click=to_mode(Mode::Recover)><Svg icon=Icon::Key/>"Recover with recovery phrase"</button>
            </div>
        }
    };
    let missing = Memo::new(move |_| {
        if picked.get().is_some() {
            return None;
        }
        selected.get().filter(|v| !v.exists)
    });
    view! {
        <div class="unlock-card fade-in">
            <Safe opening=busy/>
            <div class="pop-anchor">
                <button class="vault-switch" id="vault-menu" aria-haspopup="menu" on:click=move |_| sheet.update(|s| *s = if *s == Sheet::VaultMenu { Sheet::None } else { Sheet::VaultMenu })>
                    {move || picked.get().or_else(|| selected.get().map(|v| v.name.to_string())).unwrap_or_else(|| "Your vault".to_owned())}
                    <Svg icon=Icon::ChevronDown/>
                </button>
                <Show when=move || sheet.get() == Sheet::VaultMenu>{vault_menu}</Show>
            </div>
            // Android keeps vaults in the app's private folder: no place to show.
            <Show when=move || !crate::android()>
                <div class="vault-meta" id="vault-place">
                    {move || if picked.get().is_some() { "Vault file".to_owned() } else { selected.get().map(|v| v.place.to_string()).unwrap_or_default() }}
                </div>
            </Show>
            {move || missing.get().map(|v| {
                let id = v.id;
                view! {
                    <div class="banner bad" role="status"><Svg icon=Icon::Warn/>
                        <span class="sp">"This vault file is not where it was."</span>
                        {(!v.in_folder).then(|| view! {
                            <button class="btn subtle" id="vault-forget" on:click=move |_| ui().act(Act::ForgetVault(id))>"Remove from list"</button>
                        })}
                    </div>
                }
            })}
            <Show when=move || quick.get()>
                // `data-qv-autoprompt`: app.js clicks this once the locked
                // screen is on screen (plan 0045).
                <button class="btn primary quick-go" id="quick-unlock" data-qv-clear="true" disabled=move || busy.get() || preview.get()
                    data-qv-autoprompt=move || autoprompt.get().map(|n| n.to_string())
                    on:click=move |_| { ui().act(Act::QuickStarted); gate(Action::QuickUnlock); }>
                    <Svg icon=Icon::Finger large=true/>{move || quick_label.get()}
                </button>
                <div class="or-line"><span>"or use your master password"</span></div>
            </Show>
            <div class=move || if has_error.get() { "pw bad" } else { "pw" }>
                <input id="password" type="password" placeholder="Master password" aria-label="Master password" maxlength="1024"
                    autofocus=move || !quick.get_untracked() disabled=move || busy.get()
                    autocomplete="off" spellcheck="false" autocapitalize="off"
                    on:input=move |e| ui().input(qv_ui_api::Field::Locked(LockedField::Password), &event_target_value(&e))
                    on:keydown=move |e: web_sys::KeyboardEvent| { if e.key() == "Enter" && !preview.get_untracked() { e.prevent_default(); gate(Action::Unlock); } }/>
                <button class="go" id="unlock-submit" aria-label="Unlock" data-qv-clear="true" disabled=move || busy.get() || preview.get() on:click=move |_| gate(Action::Unlock)><Svg icon=Icon::Right/></button>
            </div>
            <Show when=move || busy.get()><p class="muted">"Opening…"</p></Show>
            {err_view}
            {path_input}
            {move || banner.get().map(|b| view! { <p class="banner ok" role="status" data-qv-autofill="banner">{b}</p> })}
        </div>
    }
    .into_any()
}
