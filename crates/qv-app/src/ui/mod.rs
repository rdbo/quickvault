// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared app UI (plan 0040): one DOM for desktop and phone. Vault text is
//! rendered as escaped text only; every handler sends a typed action with the
//! current form epoch and Rust re-checks it.
mod editor;
mod icons;
mod items;
mod pages;
mod shell;
use crate::controller::{Action, AppError, Controller, FormEpoch, InputField, Mode, Phase, View};
use crate::workspace::Shortcut;
use dioxus::prelude::*;
use icons::{Icon, Logo, Svg};
use std::sync::OnceLock;
use zeroize::Zeroizing;

pub(crate) static ACTIVE: OnceLock<Result<Controller, crate::controller::AppError>> =
    OnceLock::new();

/// Redraws the app now. Handlers change the controller synchronously, so a
/// redraw right after the event shows the result without waiting for the
/// poll below (which still catches background work and timers).
#[derive(Clone, Copy)]
struct Redraw(Signal<u64, SyncStorage>);
impl Redraw {
    fn now(mut self) {
        if let Ok(mut value) = self.0.try_write() {
            *value = value.wrapping_add(1);
        }
    }
}

pub(crate) fn app() -> Element {
    let mut changed = use_signal_sync(|| 0u64);
    use_context_provider(|| Redraw(changed));
    use_hook(move || {
        std::thread::spawn(move || {
            let mut previous = None;
            loop {
                std::thread::sleep(std::time::Duration::from_millis(200));
                if let Some(Ok(controller)) = ACTIVE.get() {
                    controller.pump();
                }
                // Async startup failures must refresh the screen too.
                let snapshot = ACTIVE.get().map(|result| {
                    result
                        .as_ref()
                        .map(Controller::snapshot)
                        .map_err(|error| *error)
                });
                if previous != snapshot {
                    previous = snapshot;
                    if let Ok(mut value) = changed.try_write() {
                        *value = value.wrapping_add(1);
                    }
                }
            }
        });
    });
    let revision = *changed.read();
    match ACTIVE.get() {
        Some(Ok(controller)) => rsx! { Root { controller: controller.clone(), revision } },
        _ => {
            let error = ACTIVE
                .get()
                .and_then(|r| r.as_ref().err())
                .copied()
                .unwrap_or(AppError::Unavailable);
            let title = match error {
                AppError::LockMonitoring => "Lock monitoring unavailable",
                AppError::PrivateStorage => "Private storage unavailable",
                AppError::AlreadyRunning => "QuickVault is already running",
                _ => "Protection unavailable",
            };
            let message = error.message();
            rsx! {
                div { class: "qv", "data-mode": "dark",
                    shell::TitleBar { controller: None, epoch: FormEpoch(0), unlocked: false, idle_left: 0, busy: false, palette: None, vault: None }
                    div { class: "locked", div { class: "locked-body",
                        div { class: "wizard",
                            h2 { "{title}" }
                            p { "{message}" }
                            p { class: "muted", "No vault has been opened by this window." }
                        }
                    } }
                    shell::ResizeHandles {}
                }
            }
        }
    }
}
/// Synthetic flow result handler; a no-op outside validation builds.
#[cfg(feature = "validation")]
fn fixture_report(controller: &Controller) -> impl FnMut(FormEvent) + 'static {
    let c = controller.clone();
    move |event: FormEvent| {
        let value = event.value();
        if crate::validation_media::enabled()
            && let Some(stage) = value
                .strip_prefix("MEDIA-STAGE:")
                .and_then(|n| n.parse::<u8>().ok())
        {
            println!("synthetic media stage {stage}");
            return;
        }
        if crate::validation_media::enabled()
            && let Some(facts) = value.strip_prefix("MEDIA-FACTS:")
            && facts.len() == 11
            && facts.split(',').count() == 6
            && facts.bytes().all(|b| b.is_ascii_digit() || b == b',')
        {
            println!("synthetic media facts {facts}");
            return;
        }
        #[cfg(target_os = "linux")]
        if value == "LAN-PEER" {
            crate::lan::fixture::start(&c);
            return;
        }
        if let Some(stage) = value
            .strip_prefix("FAIL:")
            .and_then(|n| n.parse::<u8>().ok())
        {
            eprintln!("synthetic flow stage {stage} failed");
            if let Some(v) = c.lan_view(c.snapshot().epoch) {
                if let Some(d) = v.done {
                    let confirmed = d
                        .lines
                        .first()
                        .is_some_and(|s| s == "A new device joined this vault.");
                    eprintln!(
                        "synthetic LAN receipt: confirmed={confirmed} error={:?}",
                        d.error
                    );
                } else {
                    eprintln!("synthetic LAN is still active");
                }
            }
        }
        if crate::validation_media::enabled() {
            crate::validation_media::finish(&c, value == "PASS");
            return;
        }
        c.finish_fixture(value == "PASS")
    }
}
#[cfg(not(feature = "validation"))]
fn fixture_report(_: &Controller) -> impl FnMut(FormEvent) + 'static {
    |_| {}
}
pub(crate) fn is_fixture(controller: &Controller) -> bool {
    #[cfg(feature = "validation")]
    {
        controller.is_fixture()
    }
    #[cfg(not(feature = "validation"))]
    {
        let _ = controller;
        false
    }
}
/// Validation fixtures expose only a non-secret completion bit to the driver.
pub(crate) fn fixture_peer_opened() -> bool {
    #[cfg(all(feature = "validation", target_os = "linux"))]
    {
        crate::lan::fixture::complete()
    }
    #[cfg(not(all(feature = "validation", target_os = "linux")))]
    {
        false
    }
}
fn is_preview(controller: &Controller) -> bool {
    #[cfg(feature = "validation")]
    {
        controller.is_preview()
    }
    #[cfg(not(feature = "validation"))]
    {
        let _ = controller;
        false
    }
}

/// The app root: theme, title bar, keyboard shortcuts and the phase's screen.
#[component]
fn Root(controller: Controller, revision: u64) -> Element {
    let _ = revision;
    let redraw = use_context::<Redraw>();
    let view = controller.snapshot();
    let epoch = view.epoch;
    // Clicks anywhere count as activity for the inactivity lock (reported at
    // most twice a second). Pointer movement and scrolling arrive from app.js
    // through `#qv-activity`, because the webview bridge forwards only click,
    // input, change, key and focus events.
    let last_seen = use_hook(|| std::rc::Rc::new(std::cell::Cell::new(std::time::Instant::now())));
    let seen = {
        let c = controller.clone();
        move || {
            if last_seen.get().elapsed() >= std::time::Duration::from_millis(500) {
                last_seen.set(std::time::Instant::now());
                c.activity(epoch);
            }
        }
    };
    let palette = use_signal(|| false);
    // The phone vault switcher (plan 0045), opened from the list or the tab.
    let switcher = use_signal(|| false);
    use_context_provider(|| VaultSheet(switcher));
    let unlocked = view.phase == Phase::Unlocked;
    let keys = {
        let c = controller.clone();
        let mut palette = palette;
        let mut switcher = switcher;
        move |event: KeyboardEvent| {
            // Bubbled after the target's own handler: show its result now.
            redraw.now();
            c.activity(epoch);
            let key = event.key().to_string();
            let ctrl = event.modifiers().ctrl() || event.modifiers().meta();
            if unlocked && ctrl && matches!(key.as_str(), "k" | "K" | "f" | "F") {
                palette.set(true);
                event.prevent_default();
                return;
            }
            if key == "Escape" && palette() {
                palette.set(false);
                event.prevent_default();
                return;
            }
            if key == "Escape" && switcher() {
                switcher.set(false);
                event.prevent_default();
                return;
            }
            let handled = Shortcut::from_key(&key, ctrl)
                .is_some_and(|s| s != Shortcut::Search && c.shortcut(epoch, s));
            if handled {
                event.prevent_default();
            } else if key == "Escape" && cfg!(target_os = "android") {
                // Android Back arrives as Escape; nothing took it, so the
                // activity asks for a second Back before closing (plan 0044).
                #[cfg(target_os = "android")]
                crate::android::back_at_root();
            }
        }
    };
    #[cfg(target_os = "android")]
    crate::android::sync_theme(view.theme);
    // The title bar's vault name, kept while an operation owns the vault so
    // it does not blank and shift the command bar (plan 0044).
    let name = use_last(if unlocked {
        controller.read(epoch, |s| {
            crate::views::overview(s).map(|o| Some(o.name.to_string()))
        })
    } else {
        Some(Ok(None))
    })
    .and_then(Result::ok)
    .flatten();
    rsx! {
        div { class: "qv", "data-mode": view.theme.name(), "data-qv-epoch": "{epoch.0}", tabindex: "-1", onkeydown: keys,
            onclick: { let seen = seen.clone(); move |_| { seen(); redraw.now() } },
            oninput: move |_| redraw.now(),
            shell::TitleBar {
                controller: Some(controller.clone()), epoch, unlocked, idle_left: view.idle_left, busy: if unlocked { view.busy_shown } else { view.busy },
                palette: unlocked.then_some(palette), vault: name, idle_only: view.reduced_lifecycle,
            }
            if unlocked {
                shell::Shell { controller: controller.clone(), view: ShellView::from(&view), palette }
            } else {
                // Any snapshot change (errors, busy, typed path) redraws the locked screens.
                Locked { controller: controller.clone(), revision }
            }
            shell::ResizeHandles {}
            input { id: "qv-activity", class: "qv-activity", r#type: "text", tabindex: "-1", "aria-hidden": "true", maxlength: 0,
                oninput: { let c = controller.clone(); move |e: FormEvent| { e.stop_propagation(); c.activity(epoch); } } }
            input { id: "qv-preview-stop", class: "qv-activity", r#type: "text", tabindex: "-1", "aria-hidden": "true", maxlength: 0,
                oninput: { let c = controller.clone(); move |e: FormEvent| { e.stop_propagation(); c.act(epoch, crate::workspace::WsAction::ClosePreview); } } }
        }
    }
}

/// Whether the phone vault switcher sheet is open (plan 0045).
#[derive(Clone, Copy)]
pub(crate) struct VaultSheet(pub(crate) Signal<bool>);

/// The parts of the snapshot the unlocked shell renders.
#[derive(Clone, Copy, PartialEq)]
pub(crate) struct ShellView {
    pub(crate) epoch: FormEpoch,
    pub(crate) revision: u64,
    pub(crate) live: crate::workspace::Live,
    pub(crate) busy: bool,
    pub(crate) busy_shown: bool,
    pub(crate) scanning: bool,
    pub(crate) reduced_lifecycle: bool,
    /// Seconds left in a LAN window: part of the props so its countdown
    /// redraws every second.
    pub(crate) lan_seconds: u64,
}
impl From<&View> for ShellView {
    fn from(v: &View) -> Self {
        Self {
            epoch: v.epoch,
            revision: v.revision,
            live: v.live,
            lan_seconds: v.lan_seconds,
            // Disable actions immediately; only progress indicators use the delayed flag.
            busy: v.busy,
            busy_shown: v.busy_shown,
            scanning: v.scanning,
            reduced_lifecycle: v.reduced_lifecycle,
        }
    }
}

/// A locked-screen input: bounded, converted to protected Rust storage on
/// every keystroke, never prefilled.
#[component]
fn SecretInput(
    controller: Controller,
    epoch: FormEpoch,
    field: InputField,
    label: &'static str,
    id: &'static str,
    secret: bool,
    disabled: bool,
    #[props(default)] autofocus: bool,
    #[props(default)] placeholder: &'static str,
) -> Element {
    rsx! {
        div { class: "field",
            label { r#for: id, "{label}" }
            input { id, r#type: if secret { "password" } else { "text" }, maxlength: if field == InputField::Path { 4096 } else { 1024 },
                disabled, autofocus, placeholder, autocomplete: "off", spellcheck: "false", autocapitalize: "off", autocorrect: "off",
                oninput: move |event: FormEvent| { let mut value = event.value(); controller.input(epoch, field, &mut value); }
            }
        }
    }
}

/// The spinning dial around the vault mark (decorative).
#[component]
fn Safe(opening: bool) -> Element {
    let ticks: Vec<(&'static str, String, String, String, String)> = (0..48)
        .map(|i| {
            let a = f64::from(i) * 7.5_f64.to_radians();
            let inner = if i % 6 == 0 { 56.0 } else { 60.0 };
            (
                if i % 6 == 0 { "major" } else { "" },
                format!("{:.2}", 66.0 + inner * a.sin()),
                format!("{:.2}", 66.0 - inner * a.cos()),
                format!("{:.2}", 66.0 + 64.0 * a.sin()),
                format!("{:.2}", 66.0 - 64.0 * a.cos()),
            )
        })
        .collect();
    rsx! {
        div { class: if opening { "safe opening" } else { "safe" },
            svg { class: "ticks", view_box: "0 0 132 132", "aria-hidden": "true",
                for (class, x1, y1, x2, y2) in ticks { line { class, x1, y1, x2, y2 } }
            }
            div { class: "avatar", Svg { icon: Icon::Lock } }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum Sheet {
    None,
    VaultMenu,
    /// Where a new vault is saved: the default folder, or one file.
    SaveMenu,
    Protection,
}

/// Locked phases: welcome, unlock, create, phrase, recover, join, recovery
/// baseline and key-rotation steps.
#[component]
fn Locked(controller: Controller, revision: u64) -> Element {
    let _ = revision;
    let view = controller.snapshot();
    let epoch = view.epoch;
    let mode = view.mode;
    let phase = view.phase;
    let busy = view.busy;
    let preview = is_preview(&controller);
    let fixture = is_fixture(&controller);
    let mut sheet = use_signal(|| Sheet::None);
    let mut step = use_signal(|| (FormEpoch(u64::MAX), 0u8));
    let mut shown = use_signal(|| (FormEpoch(u64::MAX), false));
    let mut confirming = use_signal(|| (FormEpoch(u64::MAX), false));
    let mut skip = use_signal(|| (FormEpoch(u64::MAX), false));
    // The action that opened the protection sheet; it runs once acknowledged.
    let mut after_ack = use_signal(|| None::<Action>);
    let on = |s: (FormEpoch, bool)| s.0 == epoch && s.1;
    let wizard_step = if step().0 == epoch { step().1 } else { 0 };
    // Create/unlock/recover need the reduced-protection acknowledgement first.
    let gate = {
        let c = controller.clone();
        move |action: Action| {
            if c.protection_ack_needed() {
                after_ack.set(Some(action));
                sheet.set(Sheet::Protection);
            } else {
                c.perform(epoch, action, c.consent());
            }
        }
    };
    let error = view.error;
    let notice = view.notice();
    let picked = controller.picked_vault(epoch);
    let app_vault = controller.app_vault_exists();
    let first_run = !app_vault && picked.is_none();
    // The vault list (plan 0041): names are file names, shown before unlock.
    let vaults = controller.vaults();
    let selected = controller.selected_vault();
    let folder_place = crate::vaults::shown_place(&controller.default_folder());
    let phrase = controller.phrase(epoch);
    let words: Vec<(usize, Zeroizing<String>)> = phrase
        .as_ref()
        .and_then(|v| std::str::from_utf8(v.expose_secret()).ok())
        .unwrap_or("")
        .split_whitespace()
        .enumerate()
        .map(|(i, w)| (i + 1, Zeroizing::new(w.to_owned())))
        .collect();
    let suggestion = controller.suggestion(epoch);
    let suggestion_text = Zeroizing::new(
        suggestion
            .as_ref()
            .and_then(|v| std::str::from_utf8(v.expose_secret()).ok())
            .unwrap_or("")
            .to_owned(),
    );
    let lock = {
        let c = controller.clone();
        move |_| c.lock()
    };
    let to_mode = |m: Mode| {
        let c = controller.clone();
        move |_| {
            sheet.set(Sheet::None);
            c.select_mode(epoch, m);
        }
    };
    let pick_vault = {
        let c = controller.clone();
        move |_: MouseEvent| {
            sheet.set(Sheet::None);
            crate::documents::pick_vault(&c, epoch);
        }
    };
    let pick_folder = {
        let c = controller.clone();
        move |_: MouseEvent| {
            sheet.set(Sheet::None);
            #[cfg(target_os = "linux")]
            crate::documents::pick_path(
                &c,
                epoch,
                crate::documents::PathFor::Folder,
                qv_core::platform::portal::Pick::Folder,
                "Choose where new vaults are saved",
                None,
            );
            #[cfg(not(target_os = "linux"))]
            let _ = &c;
        }
    };
    let pick_new = {
        let c = controller.clone();
        move |_: MouseEvent| {
            sheet.set(Sheet::None);
            #[cfg(target_os = "linux")]
            crate::documents::pick_path(
                &c,
                epoch,
                crate::documents::PathFor::Locked,
                qv_core::platform::portal::Pick::Save("vault.qvault".into()),
                "Save the new vault",
                None,
            );
            #[cfg(not(target_os = "linux"))]
            let _ = &c;
        }
    };
    let can_pick = cfg!(any(target_os = "linux", target_os = "android"));
    // Validation fixtures keep their synthetic vaults at a typed private path;
    // nothing else types a vault path here (0009 §1.8): a failed picker
    // reports the missing portal and only hides the picker choices.
    let fallback = crate::documents::picker_missing() || fixture;
    let typed_path = fixture;
    // Quick unlock enrolled for the selected vault comes first (plan 0045).
    let quick = mode == Mode::Unlock && controller.quick_ready();
    let quick_label =
        if controller.quick_policy() == Some(qv_core::platform::QuickPolicy::DeviceCredential) {
            "Unlock with screen lock"
        } else {
            "Unlock with fingerprint"
        };
    let os = controller.protection();
    let process_reduced = qv_core::harden().is_reduced();
    let reduced = os.is_reduced() || process_reduced;
    let level = crate::prefs::level(&os, process_reduced);
    let err_view = rsx! {
        if let Some(e) = error { div { class: "err", role: "alert", Svg { icon: Icon::Warn } span { "{e.message()}" } } }
        else if let Some(n) = notice { p { class: "banner ok", role: "status", "{n}" } }
    };
    let vault_menu = rsx! {
        button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| sheet.set(Sheet::None) }
        div { class: "menu pop mid", role: "menu",
            if !vaults.is_empty() { div { class: "label", "VAULTS" } }
            for v in vaults.iter().cloned() {
                button { class: if selected.as_ref().is_some_and(|s| s.path == v.path) && picked.is_none() { "mi on" } else { "mi" }, role: "menuitemradio",
                    onclick: { let c = controller.clone(); let p = v.path.clone(); move |_| { sheet.set(Sheet::None); let mut empty = String::new(); c.input(epoch, InputField::Path, &mut empty); c.select_vault(epoch, &p); } },
                    Svg { icon: Icon::Lock }
                    span { class: "vault-mi", b { "{v.name}" } small { if v.exists { "{v.place}" } else { "Not found · {v.place}" } } }
                    if selected.as_ref().is_some_and(|s| s.path == v.path) && picked.is_none() { span { class: "sub", Svg { icon: Icon::Check } } }
                }
            }
            if !vaults.is_empty() { hr {} }
            if can_pick { button { class: "mi", id: "menu-open-file", onclick: pick_vault.clone(), Svg { icon: Icon::Folder } "Open a vault file…" } }
            button { class: "mi", id: "menu-create", onclick: to_mode(Mode::Create), Svg { icon: Icon::Plus } "Create a new vault" }
            button { class: "mi", id: "menu-join", onclick: to_mode(Mode::Join), Svg { icon: Icon::Qr } "Join from another device" }
            button { class: "mi", id: "menu-recover", onclick: to_mode(Mode::Recover), Svg { icon: Icon::Key } "Recover with recovery phrase" }
        }
    };
    let perform = |action: Action, consent: bool| {
        let c = controller.clone();
        move |_| c.perform(epoch, action, consent)
    };
    let body = if phase == Phase::Locked && view.resume.is_some() {
        let need = view.resume.unwrap_or(crate::controller::Resume {
            old: false,
            new: false,
        });
        let consent = controller.consent();
        rsx! {
            div { class: "wizard fade-in",
                h2 { "Finish the interrupted key rotation" }
                p { "A key rotation for this vault was interrupted. Complete it to use the new master password and phrase, or roll it back to keep the previous ones. Nothing else can open the vault until it is finished." }
                if need.new { SecretInput { controller: controller.clone(), epoch, field: InputField::Password, label: "New master password (chosen for the rotation)", id: "resume-new", secret: true, disabled: busy } }
                if need.old { SecretInput { controller: controller.clone(), epoch, field: InputField::Repeat, label: "Previous master password", id: "resume-old", secret: true, disabled: busy } }
                {err_view}
                div { class: "actions stack",
                    button { class: "btn primary", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::ResumeComplete, consent), "Complete the rotation" }
                    button { class: "btn", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::ResumeRollback, consent), "Roll back to the previous generation" }
                    button { class: "btn subtle", "data-qv-clear": "true", onclick: lock, "Cancel" }
                }
            }
        }
    } else if phase == Phase::Rotation {
        rsx! {
            div { class: "wizard fade-in",
                h2 { "Your new recovery phrase" }
                p { "Write these 24 words down in order. They replace the old phrase once the rotation is installed. Nothing has changed yet." }
                PhraseGrid { words: words.clone(), hidden: false }
                if view.rotation_confirmed {
                    div { class: "banner ok", Svg { icon: Icon::Check } span { "The new recovery words are confirmed." } }
                    div { class: "actions",
                        button { class: "btn subtle", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::CancelRotation, true), "Cancel the rotation" }
                        button { class: "btn primary", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::InstallRotation, true), if busy { "Installing…" } else { "Install the key rotation" } }
                    }
                } else {
                    p { class: "hint", "Word positions: {view.positions[0]}, {view.positions[1]}, {view.positions[2]}" }
                    WordInput { controller: controller.clone(), epoch, field: InputField::Word0, id: "rot-word-0", n: view.positions[0], disabled: busy }
                    WordInput { controller: controller.clone(), epoch, field: InputField::Word1, id: "rot-word-1", n: view.positions[1], disabled: busy }
                    WordInput { controller: controller.clone(), epoch, field: InputField::Word2, id: "rot-word-2", n: view.positions[2], disabled: busy }
                    {err_view}
                    div { class: "actions",
                        button { class: "btn subtle", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::CancelRotation, true), "Cancel the rotation (nothing changes)" }
                        button { class: "btn primary", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::ConfirmRotation, true), "Confirm recovery words" }
                    }
                }
            }
        }
    } else if phase == Phase::Phrase {
        let confirm_stage = on(confirming());
        let skipped = on(skip());
        let revealed = on(shown());
        rsx! {
            div { class: "wizard fade-in",
                div { class: "steps", i { class: "on" } i { class: "on" } i { class: "on" } }
                if !confirm_stage {
                    h2 { "Your recovery phrase" }
                    p { "If you forget your password, these 24 words open your vault. Anyone with them and your vault file can open it, so keep them somewhere safe and offline." }
                    div { class: "reveal-cover",
                        PhraseGrid { words: words.clone(), hidden: !revealed }
                        if !revealed {
                            button { class: "btn primary", id: "phrase-show", onclick: move |_| shown.set((epoch, true)), Svg { icon: Icon::Eye } "Show words" }
                        }
                    }
                    div { class: "actions",
                        button { class: "btn subtle", "data-qv-clear": "true", onclick: lock, "Lock and clear phrase" }
                        button { class: "btn primary", id: "phrase-written", disabled: !revealed, onclick: move |_| confirming.set((epoch, true)), "I wrote them down" }
                    }
                } else {
                    h2 { "Check three words" }
                    p { "Type the requested words from your copy to confirm it." }
                    p { class: "hint", "Word positions: {view.positions[0]}, {view.positions[1]}, {view.positions[2]}" }
                    WordInput { controller: controller.clone(), epoch, field: InputField::Word0, id: "word-0", n: view.positions[0], disabled: busy }
                    WordInput { controller: controller.clone(), epoch, field: InputField::Word1, id: "word-1", n: view.positions[1], disabled: busy }
                    WordInput { controller: controller.clone(), epoch, field: InputField::Word2, id: "word-2", n: view.positions[2], disabled: busy }
                    {err_view}
                    div { class: "actions",
                        button { class: "btn subtle", onclick: move |_| confirming.set((epoch, false)), "Back to the words" }
                        button { class: "btn primary", id: "phrase-confirm", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::ConfirmPhrase, true), "Confirm and open" }
                    }
                    details { class: "muted",
                        summary { "Skip phrase confirmation" }
                        label { class: "check", input { r#type: "checkbox", checked: skipped, onchange: move |e| skip.set((epoch, e.checked())) } span { "I understand I may lose access if I forget my password. Record that I skipped confirmation." } }
                        button { class: "btn", disabled: busy || !skipped, onclick: perform(Action::SkipPhrase, skipped), "Record skip and continue" }
                    }
                }
            }
        }
    } else if phase == Phase::Recovery {
        rsx! {
            div { class: "wizard fade-in",
                h2 { "Check this recovery baseline" }
                p { "The external anchor is missing or mismatched. This verified file may be an older copy; opening it does not prove it is the latest state." }
                p { "Accepting it first creates a verified recovery snapshot, then establishes a new local baseline. Nothing is adopted without your action." }
                if let Some(needed) = view.over_budget {
                    div { class: "banner", Svg { icon: Icon::Warn } span { "The mandatory recovery snapshot needs {needed} bytes and exceeds the snapshot budget." } }
                }
                {err_view}
                div { class: "actions stack",
                    if view.over_budget.is_some() {
                        button { class: "btn primary", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::AdoptBaselineOverBudget, true), "Allow the snapshot to exceed the budget and accept" }
                    } else {
                        button { class: "btn primary", "data-qv-clear": "true", disabled: busy, onclick: perform(Action::AdoptBaseline, true), "Accept this file as the recovery baseline" }
                    }
                    button { class: "btn", onclick: lock, "Decline and lock" }
                }
            }
        }
    } else if mode == Mode::Create {
        let mut g1 = gate.clone();
        let mut g2 = gate.clone();
        let mismatch = controller.repeat_mismatch(epoch);
        rsx! {
            div { class: "wizard fade-in",
                div { class: "steps", i { class: "on" } i { class: if wizard_step >= 1 { "on" } else { "" } } i {} }
                div { hidden: wizard_step != 0,
                    h2 { "Name your vault" }
                    SecretInput { controller: controller.clone(), epoch, field: InputField::Name, label: "Vault name", id: "vault-name", secret: false, disabled: busy, autofocus: true, placeholder: "Personal" }
                    div { class: "banner ok", hidden: cfg!(target_os = "android"),
                        Svg { icon: Icon::Folder }
                        span { class: "sp", id: "create-place",
                            if let Some(file) = picked.as_ref() { "Saves as {file}" } else { "Saves in {folder_place}" }
                        }
                        if cfg!(target_os = "linux") && !fallback {
                            div { class: "pop-anchor",
                                button { class: "link", id: "create-change", onclick: move |_| sheet.set(if sheet() == Sheet::SaveMenu { Sheet::None } else { Sheet::SaveMenu }), "Change" }
                                if sheet() == Sheet::SaveMenu {
                                    button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| sheet.set(Sheet::None) }
                                    div { class: "menu pop end", role: "menu",
                                        button { class: "mi", id: "create-folder", onclick: pick_folder.clone(), Svg { icon: Icon::Folder } "Change the folder…" }
                                        button { class: "mi", id: "create-save-as", onclick: pick_new.clone(), Svg { icon: Icon::File } "Save just this one elsewhere…" }
                                    }
                                }
                            }
                        }
                    }
                    if typed_path { SecretInput { controller: controller.clone(), epoch, field: InputField::Path, label: "Vault file (full path)", id: "vault-path", secret: false, disabled: busy } }
                    if wizard_step == 0 { {err_view.clone()} }
                    div { class: "actions",
                        button { class: "btn subtle", onclick: to_mode(Mode::Unlock), "Cancel" }
                        button { class: "btn primary", id: "create-next", disabled: busy, onclick: move |_| step.set((epoch, 1)), "Continue" }
                    }
                }
                div { hidden: wizard_step != 1,
                    h2 { "Choose a master password" }
                    p { class: "muted", "It is the key to this vault. QuickVault cannot reset it, so make it long and memorable." }
                    SecretInput { controller: controller.clone(), epoch, field: InputField::Password, label: "Master password", id: "password", secret: true, disabled: busy }
                    SecretInput { controller: controller.clone(), epoch, field: InputField::Repeat, label: "Type it again", id: "repeat", secret: true, disabled: busy }
                    if mismatch { p { class: "hint", role: "status", "The two passwords do not match yet." } }
                    if view.fair_warning { div { class: "banner", Svg { icon: Icon::Warn } span { "This password is fair. Consider a longer, less predictable passphrase." } } }
                    div { class: "banner ok", Svg { icon: Icon::Generator }
                        div { class: "sp",
                            "Want one that is easy to remember? "
                            button { class: "link", disabled: busy || phase == Phase::WeakPassword || preview, onclick: perform(Action::SuggestPassword, true), "Suggest a six-word passphrase" }
                            if view.suggestion_visible {
                                div { class: "phrase single mono", "{suggestion_text.as_str()}" }
                                span { class: "hint", "Visible for 30 seconds. Type it into both fields above." }
                            }
                        }
                    }
                    if phase == Phase::WeakPassword {
                        div { class: "banner bad", role: "alertdialog", "aria-label": "Weak password confirmation",
                            Svg { icon: Icon::Warn }
                            div { class: "sp",
                                p { "This password is weak and could be guessed by an attacker who obtains your vault file. Create the vault anyway?" }
                                div { class: "actions start",
                                    button { class: "btn", autofocus: true, onclick: to_mode(Mode::Create), "Choose a stronger password" }
                                    button { class: "btn danger", disabled: view.weak_seconds > 0, onclick: move |_| g1(Action::ConfirmWeak), "Create anyway · {view.weak_seconds}s" }
                                }
                            }
                        }
                    }
                    if wizard_step == 1 { {err_view} }
                    if phase != Phase::WeakPassword {
                        div { class: "actions",
                            button { class: "btn subtle", disabled: busy, onclick: move |_| step.set((epoch, 0)), "Back" }
                            button { class: "btn primary", id: "create-submit", "data-qv-clear": "true", disabled: busy || preview || mismatch, onclick: move |_| g2(Action::Create), if busy { "Creating…" } else { "Create vault" } }
                        }
                    }
                }
            }
        }
    } else if mode == Mode::Import {
        let name = controller.import_name(epoch);
        let name_c = controller.clone();
        let ack_c = controller.clone();
        let mut g = gate.clone();
        rsx! {
            div { class: "wizard fade-in",
                h2 { "Import a private copy" }
                p { "Changes in QuickVault won't update the selected file. Choose a closed or exported vault file; a live database copy may be incomplete." }
                p { "This file has no trusted rollback record on this device. Authentication can verify its contents, but cannot establish that it is the latest copy." }
                if view.import_ready {
                    div { class: "field",
                        label { r#for: "import-name", "Local file name" }
                        input { id: "import-name", r#type: "text", maxlength: 256, value: "{name}", disabled: busy,
                            autocomplete: "off", spellcheck: "false",
                            oninput: move |e: FormEvent| { let mut name = e.value(); name_c.input(epoch, InputField::Name, &mut name); }
                        }
                    }
                    SecretInput { controller: controller.clone(), epoch, field: InputField::Password,
                        label: "Master password", id: "import-password", secret: true, disabled: busy, autofocus: true }
                    label { class: "check",
                        input { id: "import-ack", r#type: "checkbox", checked: view.import_ack, disabled: busy,
                            oninput: move |e: FormEvent| ack_c.acknowledge_vault_import(epoch, e.checked()) }
                        "I accept this file as a new local baseline and understand that QuickVault will edit a private copy."
                    }
                }
                {err_view}
                div { class: "actions",
                    button { class: "btn subtle", disabled: busy, onclick: to_mode(Mode::Unlock), "Cancel" }
                    button { class: "btn primary", id: "import-submit", "data-qv-clear": "true",
                        disabled: busy || preview || !view.import_ready || !view.import_ack,
                        onclick: move |_| g(Action::ImportVault), "Verify and import" }
                }
            }
        }
    } else if mode == Mode::Recover {
        let mut g1 = gate.clone();
        let mut g2 = gate.clone();
        rsx! {
            div { class: "wizard fade-in",
                h2 { "Recover with your phrase" }
                p { "Type your 24 recovery words, separated by spaces. You can choose a new master password once the vault is open." }
                VaultLine { picked: picked.clone(), can_pick, onpick: pick_vault.clone() }
                SecretInput { controller: controller.clone(), epoch, field: InputField::Phrase, label: "Recovery phrase · 24 words", id: "phrase", secret: true, disabled: busy, autofocus: true }
                if typed_path { SecretInput { controller: controller.clone(), epoch, field: InputField::Path, label: "Vault file (full path)", id: "vault-path", secret: false, disabled: busy } }
                {err_view}
                div { class: "actions",
                    button { class: "btn subtle", onclick: to_mode(Mode::Unlock), "Back" }
                    button { class: "btn primary", id: "recover-submit", "data-qv-clear": "true", disabled: busy || preview, onclick: move |_| g1(Action::Recover), if busy { "Opening…" } else { "Open with recovery phrase" } }
                }
                details { class: "muted",
                    summary { "Inspect a missing or mismatched anchor with your password" }
                    SecretInput { controller: controller.clone(), epoch, field: InputField::Password, label: "Master password", id: "recovery-password", secret: true, disabled: busy }
                    button { class: "btn", disabled: busy || preview, onclick: move |_| g2(Action::RecoverPassword), "Inspect for recovery" }
                }
            }
        }
    } else if mode == Mode::Join {
        let mut g1 = gate.clone();
        rsx! {
            div { class: "wizard fade-in",
                h2 { "Join from another device" }
                p { "On the other device, open Sync and choose Show a code. Scan it, or type the code and the address it shows." }
                pages::ScanButton { controller: controller.clone(), epoch, target: crate::qr::QrTarget::NewDevice }
                if view.code_scanned() {
                    p { class: "banner ok", role: "status", id: "lan-code-scanned", Svg { icon: Icon::Check } " Code from the QR code" }
                } else {
                    SecretInput { controller: controller.clone(), epoch, field: InputField::LanCode, label: "Code", id: "lan-join-code", secret: true, disabled: busy }
                }
                SecretInput { controller: controller.clone(), epoch, field: InputField::LanEndpoint, label: "The other device's address (ip:port)", id: "lan-join-endpoint", secret: false, disabled: busy }
                {err_view}
                div { class: "actions",
                    button { class: "btn subtle", onclick: to_mode(Mode::Unlock), "Back" }
                    button { class: "btn primary", id: "join-submit", "data-qv-clear": "true", disabled: busy || preview, onclick: move |_| g1(Action::JoinDevice), if busy { "Joining…" } else { "Join" } }
                }
            }
            pages::LanPanel { controller: controller.clone(), epoch, revision, seconds: view.lan_seconds }
            if view.scanning { pages::ScanPanel { controller: controller.clone(), epoch } }
        }
    } else if first_run && !busy {
        rsx! {
            div { class: "welcome fade-in",
                Logo { class: "logo-hero" }
                h1 { "Welcome to QuickVault" }
                p { "Your passwords stay encrypted on this device. No account, no server." }
                div { class: "choices",
                    button { class: "choice", id: "welcome-create", onclick: to_mode(Mode::Create), span { class: "ci", Svg { icon: Icon::Plus } } b { "Create a new vault" } span { "Start fresh on this device" } }
                    button { class: "choice", id: "welcome-join", onclick: to_mode(Mode::Join), span { class: "ci", Svg { icon: Icon::Qr } } b { "Join from another device" } span { "Copy a vault from your phone or computer" } }
                    if can_pick { button { class: "choice", id: "welcome-open", onclick: pick_vault.clone(), span { class: "ci", Svg { icon: Icon::Folder } } b { "Open a vault file" } span { "Use a vault you already have" } } }
                    button { class: "choice", id: "welcome-recover", onclick: to_mode(Mode::Recover), span { class: "ci", Svg { icon: Icon::Key } } b { "Recover with your phrase" } span { "Use your 24 recovery words" } }
                }
                {err_view}
                if typed_path { SecretInput { controller: controller.clone(), epoch, field: InputField::Path, label: "Vault file (full path)", id: "vault-path", secret: false, disabled: busy } }
            }
        }
    } else {
        let mut g1 = gate.clone();
        let mut g2 = gate.clone();
        rsx! {
            div { class: "unlock-card fade-in",
                Safe { opening: busy }
                div { class: "pop-anchor",
                    button { class: "vault-switch", id: "vault-menu", "aria-haspopup": "menu", onclick: move |_| sheet.set(if sheet() == Sheet::VaultMenu { Sheet::None } else { Sheet::VaultMenu }),
                        if let Some(file) = picked.as_ref() { "{file}" } else if let Some(v) = selected.as_ref() { "{v.name}" } else { "Your vault" }
                        Svg { icon: Icon::ChevronDown }
                    }
                    if sheet() == Sheet::VaultMenu { {vault_menu} }
                }
                // Android keeps vaults in the app's private folder: no place to show.
                if !cfg!(target_os = "android") {
                    div { class: "vault-meta", id: "vault-place",
                        if picked.is_some() { "Vault file" } else if let Some(v) = selected.as_ref() { "{v.place}" } else { "" }
                    }
                }
                if let (None, Some(v)) = (picked.as_ref(), selected.as_ref().filter(|v| !v.exists)) {
                    div { class: "banner bad", role: "status", Svg { icon: Icon::Warn }
                        span { class: "sp", "This vault file is not where it was." }
                        if !v.in_folder {
                            button { class: "btn subtle", id: "vault-forget", onclick: { let c = controller.clone(); let p = v.path.clone(); move |_| c.forget_vault(epoch, &p) }, "Remove from list" }
                        }
                    }
                }
                if quick {
                    // `data-qv-autoprompt`: app.js clicks this once the locked
                    // screen is on screen (plan 0045).
                    button { class: "btn primary quick-go", id: "quick-unlock", "data-qv-clear": "true", disabled: busy || preview,
                        "data-qv-autoprompt": view.autoprompt.map(|n| n.to_string()),
                        onclick: { let c = controller.clone(); move |_| { c.quick_started(); g2(Action::QuickUnlock) } },
                        Svg { icon: Icon::Finger, large: true } "{quick_label}"
                    }
                    div { class: "or-line", span { "or use your master password" } }
                }
                div { class: if error.is_some() { "pw bad" } else { "pw" },
                    // No keyboard under the fingerprint prompt.
                    input { id: "password", r#type: "password", placeholder: "Master password", "aria-label": "Master password", maxlength: 1024, autofocus: !quick, disabled: busy,
                        autocomplete: "off", spellcheck: "false", autocapitalize: "off", autocorrect: "off",
                        oninput: { let c = controller.clone(); move |event: FormEvent| { let mut value = event.value(); c.input(epoch, InputField::Password, &mut value); } },
                        onkeydown: { let mut g = gate.clone(); move |e: KeyboardEvent| { if e.key() == Key::Enter && !preview { e.prevent_default(); g(Action::Unlock); } } }
                    }
                    button { class: "go", id: "unlock-submit", "aria-label": "Unlock", "data-qv-clear": "true", disabled: busy || preview, onclick: move |_| g1(Action::Unlock), Svg { icon: Icon::Right } }
                }
                if busy { p { class: "muted", "Opening…" } }
                {err_view}
                if typed_path { SecretInput { controller: controller.clone(), epoch, field: InputField::Path, label: "Vault file (full path)", id: "vault-path", secret: false, disabled: busy } }
                if let Some(banner) = controller.autofill_banner() {
                    p { class: "banner ok", role: "status", "data-qv-autofill": "banner", "{banner}" }
                }
            }
        }
    };
    let sheet_view = match sheet() {
        Sheet::None => rsx! {},
        Sheet::VaultMenu | Sheet::SaveMenu => rsx! {},
        Sheet::Protection => rsx! {
            div { class: "layer",
                button { class: "scrim", "aria-label": "Close", onclick: move |_| sheet.set(Sheet::None) }
                div { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Device protection",
                    h3 { "Device protection" }
                    div { class: "level {level.tone()}", id: "protection-level", Svg { icon: Icon::Shield } b { "{level.label()}" } span { "protection" } }
                    p { if reduced { "QuickVault could not confirm everything below on this device. Read what it checked before using a vault here." } else { "QuickVault checked how this device protects data at rest." } }
                    div { class: "card", id: "protection-status",
                        ProtectionRow { label: "Disk encryption", evidence: os.storage }
                        ProtectionRow { label: "Swap", evidence: os.swap }
                        ProtectionRow { label: "Hibernation", evidence: os.hibernation }
                        StatusRow { label: "Screen-lock and sleep detection", ok: os.lifecycle }
                        StatusRow { label: "Clipboard clearing", ok: os.clipboard }
                        StatusRow { label: "Process and memory protection", ok: !process_reduced }
                    }
                    p { class: "hint", "Clearing an input cannot guarantee erasure of framework or operating-system copies. Storage, swap and hibernation protection depend on the operating system." }
                    p { class: "hint", if os.quick_unlock { "Fingerprint unlock turns on after you unlock with your master password." } else { "Quick unlock is unavailable on this device." } }
                    div { class: "actions",
                        if view.ack_needed {
                            button { class: "btn subtle", onclick: move |_| sheet.set(Sheet::None), "Not now" }
                            button { class: "btn primary", id: "protection-ack", onclick: { let c = controller.clone(); move |_| { let next = after_ack.take(); sheet.set(Sheet::None); match c.acknowledge_protection() { Ok(()) => { if let Some(action) = next { c.perform(epoch, action, c.consent()); } } Err(e) => c.report(epoch, e) } c.touch(); } }, "I understand, continue" }
                        } else {
                            button { class: "btn primary", onclick: move |_| sheet.set(Sheet::None), "Done" }
                        }
                    }
                }
            }
        },
    };
    rsx! {
        div { class: "locked",
            // Esc closes an open menu or sheet before anything else.
            onkeydown: {
                let c = controller.clone();
                move |e: KeyboardEvent| {
                    if e.key() == Key::Escape && sheet() != Sheet::None {
                        e.stop_propagation();
                        e.prevent_default();
                        sheet.set(Sheet::None);
                    } else if e.key() == Key::Escape && mode != Mode::Unlock && !busy {
                        // Create, Recover and Join step back to the vault
                        // (also Android Back, plan 0044).
                        e.stop_propagation();
                        e.prevent_default();
                        c.select_mode(epoch, Mode::Unlock);
                    }
                }
            },
            if fixture && cfg!(target_os = "android") { p { class: "banner", "Synthetic validation build · isolated test vault only" } }
            if preview { p { class: "banner", "Read-only preview · vault actions are disabled. Do not enter real credentials." } }
            // A new epoch rebuilds the form, dropping any typed DOM value.
            Remount { token: format!("locked-{}", epoch.0), class: "locked-body", {body} }
            // Only while a reduced status awaits acknowledgement (0009 §1.8);
            // afterwards Settings shows the mode, not a lasting chip.
            if view.ack_needed {
                div { class: "locked-foot",
                    button { class: "status-chip {level.tone()}", id: "protection-chip", onclick: move |_| { after_ack.set(None); sheet.set(Sheet::Protection); }, Svg { icon: Icon::Shield } "{level.label()} protection · review" }
                }
            }
            if fixture { input { id: "validation-result", oninput: fixture_report(&controller) } }
        }
        {sheet_view}
    }
}

#[component]
fn ProtectionRow(label: &'static str, evidence: qv_core::platform::Evidence) -> Element {
    use qv_core::platform::Evidence;
    let (class, text) = match evidence {
        Evidence::Verified => ("r ok", "Protected"),
        Evidence::KnownGap => ("r warn", "Not protected"),
        Evidence::Unknown => ("r warn", "Unknown"),
    };
    rsx! { div { class: "set-row", span { class: "l", b { "{label}" } } span { class, "{text}" } } }
}
#[component]
fn StatusRow(label: &'static str, ok: bool) -> Element {
    rsx! { div { class: "set-row", span { class: "l", b { "{label}" } } span { class: if ok { "r ok" } else { "r warn" }, if ok { "Available" } else { "Unavailable" } } } }
}

/// The vault this form opens: this device's, or a chosen file.
#[component]
fn VaultLine(picked: Option<String>, can_pick: bool, onpick: EventHandler<MouseEvent>) -> Element {
    rsx! {
        div { class: "banner ok",
            Svg { icon: Icon::Folder }
            span { class: "sp", if let Some(file) = picked.as_ref() { "Vault file: {file}" } else { "This device's vault" } }
            if can_pick { button { class: "link", onclick: move |e| onpick.call(e), "Use another file…" } }
        }
    }
}

/// One requested recovery word.
#[component]
fn WordInput(
    controller: Controller,
    epoch: FormEpoch,
    field: InputField,
    id: &'static str,
    n: usize,
    disabled: bool,
) -> Element {
    rsx! {
        div { class: "field",
            label { r#for: id, "Word {n}" }
            input { id, r#type: "password", class: "mono", maxlength: 1024, disabled, autocomplete: "off", spellcheck: "false", autocapitalize: "off", autocorrect: "off",
                oninput: move |event: FormEvent| { let mut value = event.value(); controller.input(epoch, field, &mut value); }
            }
        }
    }
}

/// The last successful read of a screen's data. Reads are refused while an
/// operation owns the vault; showing the last data meanwhile keeps a screen
/// from blanking and then rebuilding (plan 0044). Errors pass through. The
/// copy lives as long as the component (it is dropped, and zeroized, when
/// the vault view unmounts on lock).
pub(crate) fn use_last<T: Clone + 'static>(
    fresh: Option<Result<T, AppError>>,
) -> Option<Result<T, AppError>> {
    let cache = use_hook(|| std::rc::Rc::new(std::cell::RefCell::new(None::<T>)));
    match fresh {
        Some(Ok(v)) => {
            *cache.borrow_mut() = Some(v.clone());
            Some(Ok(v))
        }
        None => cache.borrow().clone().map(Ok),
        other => other,
    }
}

/// Numbered recovery words; the `.phrase` class lets cleanup clear them.
#[component]
fn PhraseGrid(words: Vec<(usize, Zeroizing<String>)>, hidden: bool) -> Element {
    rsx! {
        div { class: if hidden { "phrase mono blurred" } else { "phrase mono" }, "aria-hidden": if hidden { "true" } else { "false" },
            for (n, w) in words { span { small { "{n}" } b { class: "w", "{w.as_str()}" } } }
        }
    }
}

/// A `div` rebuilt whenever `token` changes, so CSS entry animations such as
/// `fade-in` replay. Dioxus ignores the key of a lone element; it applies
/// only within a keyed list, hence the one-item list.
#[component]
pub(crate) fn Remount(token: String, class: &'static str, children: Element) -> Element {
    rsx! {
        for t in std::iter::once(token) {
            div { key: "{t}", class, {children.clone()} }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use dioxus::dioxus_core::{Mutation, ScopeId};
    use std::cell::RefCell;

    thread_local! {
        static TOKEN: RefCell<String> = RefCell::new("a".to_owned());
    }
    fn probe() -> Element {
        let token = TOKEN.with(|t| t.borrow().clone());
        rsx! { Remount { token, class: "fade-in", "page" } }
    }
    fn render(dom: &mut VirtualDom, token: &str) -> Vec<Mutation> {
        TOKEN.with(|t| *t.borrow_mut() = token.to_owned());
        dom.mark_dirty(ScopeId::APP);
        dom.render_immediate_to_vec().edits
    }
    fn creates(edits: &[Mutation]) -> bool {
        edits
            .iter()
            .any(|m| matches!(m, Mutation::LoadTemplate { .. }))
    }

    thread_local! {
        static MOUNTS: RefCell<u32> = const { RefCell::new(0) };
    }
    #[component]
    fn Stateful(label: String) -> Element {
        use_hook(|| MOUNTS.with(|m| *m.borrow_mut() += 1));
        rsx! { "{label}" }
    }
    fn keyed() -> Element {
        let token = TOKEN.with(|t| t.borrow().clone());
        rsx! {
            for k in [token.clone()] {
                Stateful { key: "{k}", label: token.clone() }
            }
        }
    }

    #[test]
    fn keyed_component_gets_fresh_state_only_for_a_new_key() {
        TOKEN.with(|t| *t.borrow_mut() = "a".to_owned());
        let mut dom = VirtualDom::new(keyed);
        dom.rebuild_to_vec();
        let mounts = || MOUNTS.with(|m| *m.borrow());
        assert_eq!(mounts(), 1);
        render(&mut dom, "a");
        assert_eq!(mounts(), 1);
        render(&mut dom, "b");
        assert_eq!(mounts(), 2);
    }

    #[derive(Props, Clone, PartialEq)]
    struct ListProbe {
        controller: crate::controller::Controller,
    }
    fn list_probe(p: ListProbe) -> Element {
        let c = p.controller;
        let epoch = c.snapshot().epoch;
        let screen = c.screen(epoch).unwrap();
        rsx! { items::ListPane { controller: c.clone(), epoch, revision: c.snapshot().revision, list: crate::workspace::Screen::Browse(None), screen, busy: false, conflicts: 0 } }
    }

    #[test]
    fn items_with_the_same_title_and_subtitle_can_be_selected() {
        let _k = crate::workspace_tests::KDF
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let env = crate::workspace_tests::Env::unlocked();
        // Same title and first field (the username).
        let first = env.add_entry("Bank", "one");
        env.add_entry("Bank", "two");
        env.c
            .navigate(env.epoch(), crate::workspace::Screen::Browse(None));
        let mut dom = VirtualDom::new_with_props(
            list_probe,
            ListProbe {
                controller: env.c.clone(),
            },
        );
        dom.rebuild_to_vec();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while env.c.state().pages.main_items() != 2 {
            assert!(
                std::time::Instant::now() < until,
                "paged list did not load its duplicate rows"
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        dom.mark_dirty(ScopeId::APP);
        dom.render_immediate_to_vec();
        // Selecting one re-renders the list; duplicate row keys panicked
        // in the keyed diff.
        env.c
            .navigate(env.epoch(), crate::workspace::Screen::Entry(first));
        dom.mark_dirty(ScopeId::APP);
        dom.render_immediate_to_vec();
    }

    thread_local! {
        static FRESH: RefCell<Option<Result<String, AppError>>> = const { RefCell::new(None) };
    }
    fn cached() -> Element {
        let shown = use_last(FRESH.with(|f| f.borrow().clone()));
        match shown {
            Some(Ok(v)) => rsx! { p { "{v}" } },
            Some(Err(_)) => rsx! { p { "error" } },
            None => rsx! { p { "Loading…" } },
        }
    }
    /// Dynamic text the edits write.
    fn texts(edits: &[Mutation]) -> Vec<String> {
        edits
            .iter()
            .filter_map(|m| match m {
                Mutation::CreateTextNode { value, .. } | Mutation::SetText { value, .. } => {
                    Some(value.clone())
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn screens_keep_their_last_data_while_reads_are_refused() {
        FRESH.with(|f| *f.borrow_mut() = Some(Ok("Bank".to_owned())));
        let mut dom = VirtualDom::new(cached);
        assert_eq!(texts(&dom.rebuild_to_vec().edits), ["Bank"]);
        // An operation owns the vault: the read is refused (None). Nothing
        // changes on screen: no "Loading…", no rebuilt template.
        FRESH.with(|f| *f.borrow_mut() = None);
        dom.mark_dirty(ScopeId::APP);
        let edits = dom.render_immediate_to_vec().edits;
        assert!(edits.is_empty(), "{edits:?}");
        // Fresh data updates the text in place; an error still shows.
        FRESH.with(|f| *f.borrow_mut() = Some(Ok("Mail".to_owned())));
        dom.mark_dirty(ScopeId::APP);
        let edits = dom.render_immediate_to_vec().edits;
        assert_eq!(texts(&edits), ["Mail"]);
        assert!(!creates(&edits), "{edits:?}");
        FRESH.with(|f| *f.borrow_mut() = Some(Err(AppError::Unavailable)));
        dom.mark_dirty(ScopeId::APP);
        assert!(creates(&dom.render_immediate_to_vec().edits));
    }

    #[test]
    fn remount_rebuilds_only_when_the_token_changes() {
        TOKEN.with(|t| *t.borrow_mut() = "a".to_owned());
        let mut dom = VirtualDom::new(probe);
        dom.rebuild_to_vec();
        let same = render(&mut dom, "a");
        assert!(!creates(&same), "{same:?}");
        let changed = render(&mut dom, "b");
        assert!(creates(&changed), "{changed:?}");
        assert!(
            changed
                .iter()
                .any(|m| matches!(m, Mutation::ReplaceWith { .. } | Mutation::Remove { .. })),
            "{changed:?}"
        );
    }
}

/// One cancellable page owner. Hooks keep only its non-secret identity; page
/// text lives in the controller's three bounded slots, never in `use_last`.
pub(crate) fn use_page(
    controller: &Controller,
    epoch: FormEpoch,
    lane: crate::page_read::Lane,
    priority: u8,
    spec: crate::page_read::Spec,
) -> (
    Option<crate::page_read::Owner>,
    Option<crate::page_read::Read>,
) {
    let owner = use_hook(|| controller.page_owner(lane, priority));
    let cleanup = controller.clone();
    use_drop(move || {
        if let Some(owner) = owner {
            cleanup.release_page(owner);
        }
    });
    let read = owner.and_then(|owner| controller.page(epoch, owner, spec));
    (owner, read)
}

#[component]
pub(crate) fn PageNav(
    controller: Controller,
    epoch: FormEpoch,
    owner: crate::page_read::Owner,
    read: crate::page_read::Read,
) -> Element {
    let previous = read.page.as_ref().is_some_and(|p| p.previous.is_some());
    let next = read.page.as_ref().is_some_and(|p| p.next.is_some());
    let loading = read.loading;
    let serial = read.serial;
    let back = controller.clone();
    // Only a page with neighbours shows the bar, so a load never inserts
    // and removes it (plan 0051).
    rsx! {
        if let Some(error) = read.error { p { class: "banner warn", "{error.message()}" } }
        if previous || next {
            div { class: "actions start",
                button { r#type: "button", class: "btn subtle", disabled: loading || !previous,
                    onclick: move |_| back.page_turn(epoch, owner, serial, false), "Previous" }
                if loading { span { class: "muted", "Loading…" } }
                button { r#type: "button", class: "btn subtle", disabled: loading || !next,
                    onclick: move |_| controller.page_turn(epoch, owner, serial, true), "Next" }
            }
        }
    }
}
