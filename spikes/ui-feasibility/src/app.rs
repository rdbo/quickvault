// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared, deliberately small fixture screen. No existing vault can be selected.
use crate::controller::Controller;
use dioxus::prelude::*;
use std::sync::OnceLock;
use zeroize::{Zeroize, Zeroizing};

pub(crate) static ACTIVE: OnceLock<Controller> = OnceLock::new();

pub(crate) fn app() -> Element {
    let mut controller = use_signal_sync(|| None::<Controller>);
    let mut failed = use_signal_sync(|| false);
    use_hook(move || {
        crate::platform::initialize(move |result| match result {
            Ok(path) => {
                let c = Controller::new(path);
                let _ = ACTIVE.set(c.clone());
                crate::platform::watch_background(c.clone());
                if let Ok(mut slot) = controller.try_write() {
                    *slot = Some(c);
                }
            }
            Err(()) => {
                if let Ok(mut slot) = failed.try_write() {
                    *slot = true;
                }
            }
        });
    });
    let c = controller.read().clone();
    if let Some(c) = c {
        rsx! { View { controller: c } }
    } else if *failed.read() {
        rsx! { p { "Could not initialize the spike's private storage" } }
    } else {
        rsx! { p { "Preparing disposable fixture…" } }
    }
}

#[component]
fn View(controller: Controller) -> Element {
    let changed = use_signal_sync(|| 0u64);
    let mut acknowledged = use_signal(|| false);
    let mut probe = use_signal_sync(String::new);
    use_hook({
        let c = controller.clone();
        move || {
            c.notify_with(move || {
                let mut changed = changed;
                if let Ok(mut value) = changed.try_write() {
                    *value = value.wrapping_add(1);
                }
            });
            let weak_loop = c.clone();
            std::thread::spawn(move || {
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    weak_loop.idle();
                }
            });
        }
    });
    let _ = *changed.read();
    let snapshot = controller.snapshot();
    let form = snapshot.form;
    let protection = qv_core::harden();
    rsx! {
        style { "body{{font:16px sans-serif;background:#f4f6fa;color:#172334;margin:0}}main{{max-width:720px;margin:auto;padding:24px}}input,button{{font:inherit;padding:10px;margin:6px 0;box-sizing:border-box}}input[type=text],input[type=password]{{width:100%}}button{{margin-right:8px}}article{{padding:16px;background:white;margin:12px 0;border-radius:8px}}small{{display:block}}" }
        main {
            h1 { "QuickVault feasibility" }
            p { "Disposable prototype — use dummy credentials only." }
            small { "Framework/OS memory copies cannot be guaranteed erased. Production webview hardening and OS protection validation are incomplete." }
            if protection.is_reduced() { p { "Reduced process or memory-lock protection." } }
            button { onclick: move |_| crate::platform::probe(move |summary| {
                if let Ok(mut value) = probe.try_write() { *value = summary; }
            }), "Check OS API availability" }
            p { "{probe}" }
            p { role: "status", "{snapshot.message}" }
            if let Some(error) = snapshot.error { p { "{error}" } }
            for (i, m) in snapshot.measurements.iter().enumerate() {
                p { "Sample {i}: {m.ms} ms; RSS {m.before_kib} → {m.peak_kib} → {m.after_kib} KiB" }
            }
            if snapshot.unlocked {
                button { onclick: { let c = controller.clone(); move |_| c.lock() }, "Lock" }
                p { "Idle timeout: 60 seconds. Protected stored values are never rendered." }
                for row in snapshot.rows {
                    article { key: "{row.handle.id_hex()}-{form}",
                        h2 { "{row.title.as_str()}" }
                        input { key: "title-{form}", r#type: "text", placeholder: "Replacement title (blank keeps current)", maxlength: 262144,
                            oninput: { let c = controller.clone(); move |event: FormEvent| {
                                let input = Zeroizing::new(event.value()); c.title(form, &input);
                            } }
                        }
                        input { key: "replacement-{form}", r#type: "password", placeholder: "Replacement protected value (blank keeps current)", autocomplete: "new-password", spellcheck: "false", maxlength: 262144,
                            oninput: { let c = controller.clone(); move |event: FormEvent| {
                                let mut input = Zeroizing::new(event.value()); c.replacement(form, &input); input.zeroize();
                            } }
                        }
                        button { disabled: snapshot.busy, onclick: { let c = controller.clone(); move |_| { let _ = c.save(row.handle); } }, "Save entry" }
                    }
                }
            } else {
                section { key: "unlock-{form}",
                label {
                    input { r#type: "checkbox", checked: acknowledged(), onchange: move |event| acknowledged.set(event.checked()) }
                    "I acknowledge the prototype/OS-protection limits and explicitly skip recovery confirmation for this disposable fixture."
                }
                input { r#type: "password", placeholder: "Test vault password", autocomplete: "off", spellcheck: "false", maxlength: 1024,
                    oninput: { let c = controller.clone(); move |event: FormEvent| {
                        let mut input = Zeroizing::new(event.value()); c.password(form, &input); input.zeroize();
                    } }
                }
                button { disabled: snapshot.busy, onclick: { let c = controller.clone(); move |_| { let _ = c.open(true, acknowledged()); } }, "Create test vault" }
                button { disabled: snapshot.busy, onclick: { let c = controller.clone(); move |_| { let _ = c.open(false, acknowledged()); } }, "Unlock test vault" }
                button { disabled: snapshot.busy, onclick: { let c = controller.clone(); move |_| { let _ = c.benchmark(acknowledged()); } }, "Run 5 unlock samples" }
                button { onclick: { let c = controller.clone(); move |_| c.lock() }, "Cancel / clear" }
                }
            }
        }
    }
}
