// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded inputs. Every keystroke moves the whole value to protected Rust
//! storage; secrets are never prefilled. A controlled input shows Rust's
//! value and replaces what is in the control only when that value is not
//! what the user typed, so typing never races.
use crate::icons::{Icon, Svg};
use crate::ui;
use leptos::html;
use leptos::prelude::*;
use qv_ui_api::{Act, Field, LockedField, StrengthMeter, WsAct, WsField};
use std::cell::RefCell;
use std::rc::Rc;

/// A locked-screen input. `reveal` adds Show/Hide (typed codes only).
#[component]
pub(crate) fn SecretInput(
    field: LockedField,
    label: &'static str,
    id: &'static str,
    secret: bool,
    #[prop(into)] disabled: Signal<bool>,
    #[prop(optional)] autofocus: bool,
    #[prop(optional)] placeholder: &'static str,
    #[prop(optional)] reveal: bool,
    /// A new master password: rated once typing pauses (plan 0072).
    #[prop(optional)]
    rate: bool,
) -> impl IntoView {
    let shown = RwSignal::new(false);
    let pause = paused(|| ui().act(Act::RatePassword));
    let input = view! {
        <input id=id type=move || if secret && !shown.get() { "password" } else { "text" }
            maxlength=if field == LockedField::Path { "4096" } else { "1024" }
            disabled=move || disabled.get() autofocus=autofocus placeholder=placeholder
            autocomplete="off" spellcheck="false" autocapitalize="off"
            on:input=move |e| {
                ui().input(Field::Locked(field), &event_target_value(&e));
                if rate {
                    pause();
                }
            }/>
    };
    view! {
        <div class="field">
            <label for=id>{label}</label>
            {if reveal {
                view! { <div class="reveal-wrap">{input}{reveal_toggle(shown, disabled)}</div> }.into_any()
            } else {
                input.into_any()
            }}
        </div>
    }
}

/// Runs `send` once input pauses for 400 ms: the live password rating asks
/// Rust at most once per pause, never per keystroke (0010 §4.2, plan 0072).
fn paused(send: fn()) -> impl Fn() + Copy {
    let turn = StoredValue::new(0u64);
    move || {
        turn.update_value(|t| *t = t.wrapping_add(1));
        let mine = turn.get_value();
        set_timeout(
            move || {
                if turn.try_get_value() == Some(mine) {
                    send();
                }
            },
            std::time::Duration::from_millis(400),
        );
    }
}

/// The live strength of a new master password: label, bits and a bar; the
/// Fair warning and the Weak notice belong to it (0010 §4.2, plan 0072).
pub(crate) fn meter_view(m: Option<StrengthMeter>) -> impl IntoView {
    m.map(|m| {
        let note = match m.level {
            0 => "Weak: you will be asked to confirm it. Longer, less predictable passphrases are much harder to guess.",
            1 => "Fair. Consider a longer, less predictable passphrase.",
            _ => "",
        };
        view! {
            <div class=format!("meter m{}", m.level.min(3)) id="password-meter" role="status" aria-live="polite">
                <div class="meter-bar" aria-hidden="true"><i></i><i></i><i></i><i></i></div>
                <span class="meter-l"><b>{m.label}</b>{format!(" · about {} bits", m.bits)}</span>
                {(!note.is_empty()).then(|| view! { <span class="meter-note">{note}</span> })}
            </div>
        }
    })
}

/// Show/Hide for a typed code (0014 §6.4, plan 0072). It flips only the
/// input's type; the value stays where the user typed it. The code is
/// masked again when the page is hidden or the form turns busy (submit);
/// leaving the form, a scan or a lock removes the control.
fn reveal_toggle(shown: RwSignal<bool>, disabled: Signal<bool>) -> impl IntoView {
    let hidden = window_event_listener_untyped("visibilitychange", move |_| {
        if document().hidden() {
            shown.set(false);
        }
    });
    on_cleanup(move || hidden.remove());
    Effect::new(move |_| {
        if disabled.get() {
            shown.set(false);
        }
    });
    view! {
        <button type="button" class="icon-btn reveal" data-qv-reveal="true"
            aria-label=move || if shown.get() { "Hide the code" } else { "Show the code" }
            aria-pressed=move || if shown.get() { "true" } else { "false" }
            on:click=move |_| shown.update(|s| *s = !*s)>
            {move || if shown.get() { view! { <Svg icon=Icon::EyeOff/> } } else { view! { <Svg icon=Icon::Eye/> } }}
        </button>
    }
}

/// One requested recovery word.
#[component]
pub(crate) fn WordInput(
    field: LockedField,
    id: &'static str,
    #[prop(into)] n: Signal<usize>,
    #[prop(into)] disabled: Signal<bool>,
) -> impl IntoView {
    view! {
        <div class="field">
            <label for=id>{move || format!("Word {}", n.get())}</label>
            <input id=id type="password" class="mono" maxlength="1024" disabled=move || disabled.get()
                autocomplete="off" spellcheck="false" autocapitalize="off"
                on:input=move |e| ui().input(Field::Locked(field), &event_target_value(&e))/>
        </div>
    }
}

/// Input kinds.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Single-line text.
    Line,
    /// Masked secret, never prefilled.
    Secret,
    /// Multi-line text.
    Multi,
}

/// The echo rule's state: what the user last typed.
#[derive(Clone, Default)]
struct Echo(Rc<RefCell<Option<String>>>);

/// One bounded workspace input. `value` makes it
/// controlled.
#[component]
pub(crate) fn Input(
    field: WsField,
    #[prop(into)] label: String,
    kind: Kind,
    #[prop(optional, into)] value: Option<Signal<String>>,
    #[prop(optional, into)] disabled: Signal<bool>,
    #[prop(optional)] autofocus: bool,
    #[prop(optional)] bare: bool,
    #[prop(optional)] class: &'static str,
    #[prop(optional, into)] placeholder: String,
    /// `card`: digits only, grouped as typed (app.js), numeric keyboard.
    #[prop(optional)]
    format: &'static str,
    /// Show/Hide for a secret line (typed codes only, plan 0072).
    #[prop(optional)]
    reveal: bool,
    /// A new master password: rated once typing pauses (plan 0072).
    #[prop(optional)]
    rate: bool,
) -> impl IntoView {
    let shown = RwSignal::new(false);
    let pause = paused(|| ui().act(Act::Ws(WsAct::RatePassword)));
    let id = field.dom_id();
    let limit = field.limit(kind == Kind::Multi).to_string();
    let controlled = value.is_some();
    let echo = Echo::default();
    let initial = value.map(|v| v.get_untracked()).unwrap_or_default();
    let line = NodeRef::<html::Input>::new();
    let area = NodeRef::<html::Textarea>::new();
    if let Some(value) = value {
        let echo = echo.clone();
        Effect::new(move |_| {
            let v = value.get();
            let typed = echo.0.borrow().clone();
            if typed.as_deref() == Some(v.as_str()) {
                return;
            }
            *echo.0.borrow_mut() = None;
            if let Some(el) = line.get_untracked()
                && el.value() != v
            {
                el.set_value(&v);
            }
            if let Some(el) = area.get_untracked()
                && el.value() != v
            {
                el.set_value(&v);
            }
        });
    }
    let on_input = {
        let echo = echo.clone();
        move |e: web_sys::Event| {
            let v = event_target_value(&e);
            if controlled {
                *echo.0.borrow_mut() = Some(v.clone());
            }
            ui().input(Field::Ws(field), &v);
            if rate {
                pause();
            }
        }
    };
    let aria = if bare { label.clone() } else { String::new() };
    let control = if kind == Kind::Multi {
        view! {
            <textarea node_ref=area id=id.clone() class=class maxlength=limit disabled=move || disabled.get()
                autofocus=autofocus placeholder=placeholder spellcheck="false" autocomplete="off"
                aria-label=aria data-qv-controlled=if controlled { "true" } else { "false" }
                prop:value=initial on:input=on_input></textarea>
        }
        .into_any()
    } else {
        view! {
            <input node_ref=line id=id.clone() class=class type=move || if kind == Kind::Secret && !shown.get() { "password" } else { "text" }
                maxlength=limit disabled=move || disabled.get() autofocus=autofocus
                data-qv-format=format inputmode=if format.is_empty() { "text" } else { "numeric" }
                placeholder=placeholder autocomplete="off" spellcheck="false" autocapitalize="off"
                aria-label=aria data-qv-controlled=if controlled { "true" } else { "false" }
                prop:value=initial on:input=on_input/>
        }
        .into_any()
    };
    let control = if reveal && kind == Kind::Secret {
        view! { <div class="reveal-wrap">{control}{reveal_toggle(shown, disabled)}</div> }
            .into_any()
    } else {
        control
    };
    if bare {
        return control;
    }
    view! { <div class="field"><label for=id>{label}</label>{control}</div> }.into_any()
}
