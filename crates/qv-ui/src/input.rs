// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded inputs. Every keystroke moves the whole value to protected Rust
//! storage; secrets are never prefilled. A controlled input shows Rust's
//! value and replaces what is in the control only when that value is not
//! what the user typed, so typing never races.
use crate::ui;
use leptos::html;
use leptos::prelude::*;
use qv_ui_api::{Field, LockedField, WsField};
use std::cell::RefCell;
use std::rc::Rc;

/// A locked-screen input.
#[component]
pub(crate) fn SecretInput(
    field: LockedField,
    label: &'static str,
    id: &'static str,
    secret: bool,
    #[prop(into)] disabled: Signal<bool>,
    #[prop(optional)] autofocus: bool,
    #[prop(optional)] placeholder: &'static str,
) -> impl IntoView {
    view! {
        <div class="field">
            <label for=id>{label}</label>
            <input id=id type=if secret { "password" } else { "text" }
                maxlength=if field == LockedField::Path { "4096" } else { "1024" }
                disabled=move || disabled.get() autofocus=autofocus placeholder=placeholder
                autocomplete="off" spellcheck="false" autocapitalize="off"
                on:input=move |e| ui().input(Field::Locked(field), &event_target_value(&e))/>
        </div>
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
) -> impl IntoView {
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
            <input node_ref=line id=id.clone() class=class type=if kind == Kind::Secret { "password" } else { "text" }
                maxlength=limit disabled=move || disabled.get() autofocus=autofocus
                data-qv-format=format inputmode=if format.is_empty() { "text" } else { "numeric" }
                placeholder=placeholder autocomplete="off" spellcheck="false" autocapitalize="off"
                aria-label=aria data-qv-controlled=if controlled { "true" } else { "false" }
                prop:value=initial on:input=on_input/>
        }
        .into_any()
    };
    if bare {
        return control;
    }
    view! { <div class="field"><label for=id>{label}</label>{control}</div> }.into_any()
}
