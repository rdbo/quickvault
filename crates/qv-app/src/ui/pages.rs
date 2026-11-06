// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sections beside the vault: generator, devices and LAN pairing, trash,
//! conflicts, snapshots, archives, settings and autofill. File choices use
//! the system picker; a typed path appears only when no picker is available.
use super::icons::{Icon, Svg, hue, id_hue, initial};
use super::items::{Input, Kind};
use super::shell::{ReportCard, Unreadable, act, go};
use crate::controller::{Controller, FormEpoch};
use crate::prefs::Theme;
use crate::views::{self, FieldRow, kind_name};
use crate::workspace::{
    CopyKey, GenFlag, GenMode, Live, Pane, Report, RevealKey, Screen, WsAction, WsField,
};
use dioxus::prelude::*;
use zeroize::Zeroizing;

fn back(c: &Controller, e: FormEpoch) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| c.back(e)
}

/// One section page.
#[component]
pub(crate) fn Page(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    screen: Screen,
    live: Live,
    busy: bool,
    report: Option<Report>,
) -> Element {
    let c = controller.clone();
    let body = match screen {
        Screen::Generator => rsx! { Generator { controller: c, epoch, revision } },
        Screen::Devices => rsx! { Devices { controller: c, epoch, revision, busy } },
        Screen::Trash => rsx! { Trash { controller: c, epoch, revision } },
        Screen::Conflicts => rsx! { Conflicts { controller: c, epoch, revision } },
        Screen::ConflictRecord(r) => {
            rsx! { ConflictRecord { controller: c, epoch, revision, record: r, live } }
        }
        Screen::Snapshots => rsx! { Snapshots { controller: c, epoch, revision } },
        Screen::Archives => rsx! { Archives { controller: c, epoch, revision } },
        Screen::Settings(p) => rsx! { Settings { controller: c, epoch, revision, pane: p } },
        Screen::More => rsx! { Settings { controller: c, epoch, revision, pane: Pane::Overview } },
        Screen::Autofill => rsx! { AutofillScreen { controller: c, epoch, revision } },
        _ => rsx! {},
    };
    rsx! {
        section { class: "page",
            div { class: "page-inner fade-in", key: "{epoch.0}",
                if let Some(r) = report { ReportCard { controller: controller.clone(), epoch, report: r } }
                {body}
            }
        }
    }
}

/// A page heading with a back button where the page is nested.
#[component]
fn Head(
    controller: Controller,
    epoch: FormEpoch,
    title: String,
    lead: String,
    #[props(default)] nested: bool,
) -> Element {
    rsx! {
        if nested {
            div { class: "phone-bar head-bar",
                button { class: "icon-btn back", "aria-label": "Back", onclick: back(&controller, epoch), Svg { icon: Icon::Back, large: true } }
            }
            button { class: "link desk-only mb", onclick: back(&controller, epoch), "‹ Back" }
        }
        h1 { "{title}" }
        if !lead.is_empty() { p { class: "lead", "{lead}" } }
    }
}

pub(crate) fn strength_label(bits: f64) -> &'static str {
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

#[component]
fn Generator(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(form) = controller.generator_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    let generated = controller.generated(epoch);
    let value = Zeroizing::new(
        generated
            .as_ref()
            .map(|(v, _)| String::from_utf8_lossy(v.expose_secret()).into_owned())
            .unwrap_or_default(),
    );
    let parts: Vec<(&'static str, String)> = value
        .chars()
        .map(|ch| {
            let class = if ch.is_ascii_digit() {
                "d"
            } else if ch.is_alphabetic() || ch == ' ' {
                ""
            } else {
                "s"
            };
            (class, ch.to_string())
        })
        .collect();
    let set = |field: WsField| {
        let c = controller.clone();
        move |e: FormEvent| {
            let mut v = e.value();
            c.ws_input(epoch, field, &mut v);
        }
    };
    let bits = form.bits.unwrap_or(0.0);
    let pct = (bits / 1.28).clamp(0.0, 100.0);
    let meter = if bits < 50.0 {
        "meter weak"
    } else if bits < 64.0 {
        "meter fair"
    } else {
        "meter"
    };
    let flags: &[(GenFlag, &str, &str, usize)] = match form.mode {
        GenMode::Characters => &[
            (GenFlag::Lower, "Lowercase letters", "a–z", 0),
            (GenFlag::Upper, "Uppercase letters", "A–Z", 1),
            (GenFlag::Digits, "Digits", "0–9", 2),
            (GenFlag::Symbols, "Symbols", "!#$%", 3),
            (GenFlag::Ambiguous, "Avoid look-alikes", "no 0/O, 1/l", 4),
            (
                GenFlag::Each,
                "Use every enabled class",
                "at least one of each",
                7,
            ),
        ],
        GenMode::Words => &[
            (GenFlag::Capitalize, "Capitalize", "Cedar-Ripple-Orbit", 5),
            (GenFlag::AppendDigit, "Add a digit", "…-orbit7", 6),
        ],
        GenMode::Pin => &[],
    };
    let toggle = |flag: GenFlag| {
        let c = controller.clone();
        move |_| c.act(epoch, WsAction::GenToggle(flag))
    };
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Generator", lead: "Strong passwords and passphrases, made on this device." }
        div { class: "gen-out",
            if value.is_empty() {
                div { class: "gen-pw empty-gen", "Choose your settings, then generate." }
            } else {
                div { class: "gen-pw mono revealed", id: "generated", for (class, ch) in parts { span { class, "{ch}" } } }
            }
            div { class: "{meter}", b { class: "w{(pct / 10.0).round() as u32}" } }
            div { class: "meter-l",
                span { if let Some(b) = form.bits { "{b:.1} bits" } else { "Impossible settings" } }
                span { if let Some(b) = form.bits { "{strength_label(b)}" } else { "" } }
            }
            if form.bits.is_some_and(|b| b < 64.0) { p { class: "hint", role: "status", "Low strength: less than 64 bits. Consider a longer password or passphrase." } }
            div { class: "gen-acts",
                button { class: "btn", id: "generate", onclick: act(&controller, epoch, WsAction::Generate), Svg { icon: Icon::Refresh } if value.is_empty() { "Generate" } else { "New" } }
                if !value.is_empty() { button { class: "btn primary", id: "generated-copy", onclick: act(&controller, epoch, WsAction::Copy(CopyKey::Generated)), Svg { icon: Icon::Copy } "Copy" } }
            }
            if !value.is_empty() { p { class: "hint", "Visible for 30 seconds." } }
        }
        div { class: "seg mt", role: "tablist",
            for (m, label) in [(GenMode::Characters, "Random"), (GenMode::Words, "Passphrase"), (GenMode::Pin, "PIN")] {
                button { class: if form.mode == m { "on" } else { "" }, role: "tab", onclick: act(&controller, epoch, WsAction::GenMode(m)), "{label}" }
            }
        }
        div { class: "opts",
            match form.mode {
                GenMode::Characters => rsx! {
                    div { class: "opt", div { class: "l", b { "Length" } span { "8–256 characters" } }
                        div { class: "slider", input { r#type: "range", id: "ws-gen-length", min: "8", max: "128", value: "{form.length}", "aria-label": "Length", oninput: set(WsField::GenLength) } output { "{form.length}" } }
                    }
                    div { class: "opt", div { class: "l", b { "Exclude characters" } span { "Never use these" } }
                        Input { controller: controller.clone(), epoch, field: WsField::GenExclude, label: "Exclude characters", kind: Kind::Line, value: Some(form.exclude.to_string()), disabled: false, bare: true, class: "small" }
                    }
                },
                GenMode::Words => rsx! {
                    div { class: "opt", div { class: "l", b { "Words" } span { "3–20" } }
                        div { class: "slider", input { r#type: "range", id: "ws-gen-words", min: "3", max: "20", value: "{form.words}", "aria-label": "Words", oninput: set(WsField::GenWords) } output { "{form.words}" } }
                    }
                    div { class: "opt", div { class: "l", b { "Separator" } }
                        div { class: "seg fixed",
                            for sep in ["-", ".", "_", " "] {
                                button { class: if form.separator == sep { "on" } else { "" }, class: "narrow",
                                    onclick: { let c = controller.clone(); move |_| { let mut v = sep.to_owned(); c.ws_input(epoch, WsField::GenSeparator, &mut v); } },
                                    if sep == " " { "␣" } else { "{sep}" }
                                }
                            }
                        }
                    }
                },
                GenMode::Pin => rsx! {
                    div { class: "opt", div { class: "l", b { "Digits" } span { "4–32" } }
                        div { class: "slider", input { r#type: "range", id: "ws-gen-length", min: "4", max: "32", value: "{form.pin}", "aria-label": "Digits", oninput: set(WsField::GenLength) } output { "{form.pin}" } }
                    }
                },
            }
            for (flag, label, sample, i) in flags.iter().copied() {
                div { class: "opt", div { class: "l", b { "{label}" } span { class: "mono", "{sample}" } }
                    button { class: "sw", role: "switch", "aria-checked": if form.flags[i] { "true" } else { "false" }, "aria-label": "{label}", onclick: toggle(flag) }
                }
            }
        }
        div { class: "actions start",
            button { class: "btn subtle", onclick: act(&controller, epoch, WsAction::SaveGeneratorDefaults), Svg { icon: Icon::Check } "Use these settings as the vault's defaults" }
        }
    }
}

#[derive(Clone, Copy, PartialEq)]
enum DeviceSheet {
    None,
    Pair,
    Link,
    Sync,
}

#[component]
fn Devices(controller: Controller, epoch: FormEpoch, revision: u64, busy: bool) -> Element {
    let _ = revision;
    let mut sheet = use_signal(|| (FormEpoch(u64::MAX), DeviceSheet::None, String::new()));
    let links = match controller.read(epoch, views::lan_links) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let open = if sheet().0 == epoch {
        sheet().1
    } else {
        DeviceSheet::None
    };
    let target = sheet().2;
    let close = move |_| sheet.set((epoch, DeviceSheet::None, String::new()));
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Devices", lead: "Sync directly over your local network. No account, no server. Nothing syncs until you start it." }
        div { class: "card",
            if links.is_empty() {
                div { class: "dev", div { class: "di", Svg { icon: Icon::Devices, large: true } }
                    div { class: "l", b { "No linked devices yet" } span { "Pair another device to sync this vault with it." } }
                }
            }
            for l in links {
                div { class: "dev",
                    div { class: "di", span { class: "tile big {hue(&l.label)}", "{initial(&l.label)}" } }
                    div { class: "l", b { "{l.label}" } span { "Linked {l.created}" } }
                    button { class: "btn", disabled: busy, onclick: { let id = l.id.clone(); move |_| sheet.set((epoch, DeviceSheet::Sync, id.clone())) }, Svg { icon: Icon::Refresh } "Sync…" }
                    button { class: "btn subtle", "aria-label": "Remove {l.label}", disabled: busy, onclick: act(&controller, epoch, WsAction::LanRemove(l.id.clone())), Svg { icon: Icon::Trash } }
                }
            }
        }
        div { class: "actions start",
            button { class: "btn primary", id: "pair-device", disabled: busy, onclick: move |_| sheet.set((epoch, DeviceSheet::Pair, String::new())), Svg { icon: Icon::Plus } "Pair a device" }
            button { class: "btn", id: "link-device", disabled: busy, onclick: move |_| sheet.set((epoch, DeviceSheet::Link, String::new())), Svg { icon: Icon::Qr } "Use a code from another device" }
            button { class: "btn", id: "receive", disabled: busy, onclick: act(&controller, epoch, WsAction::LanReceive), Svg { icon: Icon::Devices } "Let a linked device sync with this one" }
        }
        match open {
            DeviceSheet::None => rsx! {},
            DeviceSheet::Pair => rsx! {
                div { class: "layer",
                    button { class: "scrim", "aria-label": "Close", onclick: close }
                    div { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Pair a device",
                        h3 { "Pair a device" }
                        p { "This device shows a code. The other device scans or types it, and then both show a comparison code to check." }
                        Input { controller: controller.clone(), epoch, field: WsField::LanLabel, label: "A name for the other device", kind: Kind::Line, value: None, disabled: false, autofocus: true, placeholder: "Phone" }
                        div { class: "actions",
                            button { class: "btn subtle", onclick: close, "Cancel" }
                            button { class: "btn primary", id: "show-pairing-code", onclick: { let mut f = act(&controller, epoch, WsAction::LanPair); move |e| { sheet.set((epoch, DeviceSheet::None, String::new())); f(e) } }, "Show a pairing code" }
                        }
                    }
                }
            },
            DeviceSheet::Link => rsx! {
                div { class: "layer",
                    button { class: "scrim", "aria-label": "Close", onclick: close }
                    div { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Use a code from another device",
                        h3 { "Link to another device's code" }
                        p { "On the other device, choose Pair a device. Scan its code, or type the code and its address." }
                        ScanButton { controller: controller.clone(), epoch, target: crate::qr::QrTarget::Link }
                        Input { controller: controller.clone(), epoch, field: WsField::LanCode, label: "Pairing code", kind: Kind::Secret, value: None, disabled: false }
                        Input { controller: controller.clone(), epoch, field: WsField::LanEndpoint, label: "The other device's address (ip:port)", kind: Kind::Line, value: None, disabled: false }
                        Input { controller: controller.clone(), epoch, field: WsField::LanLabel, label: "A name for the other device", kind: Kind::Line, value: None, disabled: false }
                        div { class: "actions",
                            button { class: "btn subtle", onclick: close, "Cancel" }
                            button { class: "btn primary", id: "link-submit", "data-qv-clear": "true", onclick: { let mut f = act(&controller, epoch, WsAction::LanLink); move |e| { sheet.set((epoch, DeviceSheet::None, String::new())); f(e) } }, "Link" }
                        }
                    }
                }
            },
            DeviceSheet::Sync => rsx! {
                div { class: "layer",
                    button { class: "scrim", "aria-label": "Close", onclick: close }
                    div { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Sync with a linked device",
                        h3 { "Sync with a linked device" }
                        p { "On the other device, choose \"Let a linked device sync with this one\". Then scan its code, or type the address it shows." }
                        ScanButton { controller: controller.clone(), epoch, target: crate::qr::QrTarget::Sync }
                        Input { controller: controller.clone(), epoch, field: WsField::LanEndpoint, label: "The other device's address (ip:port)", kind: Kind::Line, value: None, disabled: false, autofocus: true }
                        div { class: "actions",
                            button { class: "btn subtle", onclick: close, "Cancel" }
                            button { class: "btn primary", id: "sync-submit", onclick: { let mut f = act(&controller, epoch, WsAction::LanSync(target.clone())); move |e| { sheet.set((epoch, DeviceSheet::None, String::new())); f(e) } }, "Sync now" }
                        }
                    }
                }
            },
        }
    }
}

/// The running or finished LAN operation as a modal: code, QR, endpoints,
/// countdown, comparison questions and the outcome. Also on the locked screen.
#[component]
pub(crate) fn LanPanel(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(v) = controller.lan_view(epoch) else {
        return rsx! {};
    };
    use crate::lan::{LanKind, Question};
    let title = match v.kind {
        LanKind::Pair => "Show this code on the other device",
        LanKind::Receive => "Ready for a linked device",
        LanKind::Sync => "Syncing with a linked device",
        LanKind::Link => "Joining another device's pairing window",
        LanKind::Join => "Joining from another device",
    };
    let code = v
        .code
        .as_ref()
        .map(|c| Zeroizing::new(String::from_utf8_lossy(c.expose_secret()).into_owned()));
    let answer = |yes: bool| {
        let c = controller.clone();
        move |_| c.lan_answer(epoch, yes)
    };
    let cancel = {
        let c = controller.clone();
        move |_| c.lan_cancel(epoch)
    };
    let dismiss = {
        let c = controller.clone();
        move |_| c.lan_dismiss(epoch)
    };
    let typed = {
        let c = controller.clone();
        move |event: FormEvent| {
            let mut value = event.value();
            c.lan_secret(epoch, &mut value);
        }
    };
    rsx! {
        div { class: "layer",
            div { class: "scrim" }
            div { class: "dialog wide lan", role: "region", "aria-label": "Local network",
                if v.done.is_none() && v.question.is_none() && v.qr.is_none() && code.is_none() { div { class: "prog", b {} } }
                h3 { "{title}" }
                if let Some(symbol) = v.qr.as_ref() { { qr_image(symbol) } }
                if let Some(code) = code {
                    p { class: "center hint", "Type this pairing code on the other device. Show it only to that device." }
                    div { class: "phrase single mono center", id: "lan-code", "{code.as_str()}" }
                }
                if !v.endpoints.is_empty() {
                    p { class: "center hint", "This device's address:" }
                    div { class: "center mono", for e in v.endpoints.iter() { div { "{e}" } } }
                }
                if v.seconds > 0 { p { class: "center hint", "Closes in {v.seconds / 60}:{v.seconds % 60:02}" } }
                if let Some(i) = v.info.as_ref() { p { class: "banner ok notice", role: "status", "{i}" } }
                match v.question.clone() {
                    Some(Question::Approve { sas, mode, vault }) => rsx! {
                        div { role: "alertdialog", "aria-label": "Compare codes",
                            p { class: "center", "A device asks to pair with “{vault}”: {mode}." }
                            div { class: "code-big mono phrase single", id: "lan-sas", "{sas}" }
                            p { class: "center hint", "Confirm only if the other device shows exactly this code." }
                            div { class: "actions",
                                button { class: "btn subtle", onclick: answer(false), "They differ" }
                                button { class: "btn primary", id: "lan-codes-match", onclick: answer(true), "Codes match" }
                            }
                        }
                    },
                    Some(Question::Matches { sas }) => rsx! {
                        div { role: "alertdialog", "aria-label": "Compare codes",
                            div { class: "code-big mono phrase single", id: "lan-sas", "{sas}" }
                            p { class: "center hint", "Does the other device show exactly this code?" }
                            div { class: "actions",
                                button { class: "btn subtle", onclick: answer(false), "No, cancel" }
                                button { class: "btn primary", id: "lan-codes-match", onclick: answer(true), "Codes match" }
                            }
                        }
                    },
                    Some(Question::JoinVault { vault, sas }) => rsx! {
                        div { role: "alertdialog", "aria-label": "Join vault",
                            p { class: "center", "Join the vault “{vault}”?" }
                            div { class: "code-big mono phrase single", "{sas}" }
                            p { class: "center hint", "Join only a vault you expect, from a device showing this comparison code." }
                            div { class: "actions",
                                button { class: "btn subtle", onclick: answer(false), "Cancel" }
                                button { class: "btn primary", id: "lan-join-vault", onclick: answer(true), "Join this vault" }
                            }
                        }
                    },
                    Some(Question::Password { retry }) => rsx! {
                        div { role: "alertdialog", "aria-label": "Master password",
                            if retry { p { class: "banner bad error", "Wrong password. Try again." } }
                            div { class: "field",
                                label { r#for: "lan-password", "The joined vault's master password" }
                                input { id: "lan-password", r#type: "password", maxlength: crate::workspace::LINE_MAX, autocomplete: "off", spellcheck: "false", autofocus: true, oninput: typed }
                            }
                            div { class: "actions",
                                button { class: "btn subtle", onclick: answer(false), "Cancel" }
                                button { class: "btn primary", "data-qv-clear": "true", id: "lan-password-submit", onclick: answer(true), "Open the vault" }
                            }
                        }
                    },
                    None => rsx! {},
                }
                if let Some(done) = v.done.as_ref() {
                    div { class: "lan-done", for line in done.lines.iter() { p { "{line}" } } }
                    if let Some(e) = done.error { p { class: "banner bad error", role: "alert", "{e.message()}" } }
                    div { class: "actions", button { class: "btn primary", id: "lan-dismiss", onclick: dismiss, "Dismiss" } }
                } else if v.question.is_none() {
                    div { class: "actions", button { class: "btn subtle", id: "lan-cancel", onclick: cancel, "Cancel" } }
                }
            }
        }
    }
}

fn qr_image(symbol: &crate::qr::Symbol) -> Element {
    let side = symbol.size() + 8;
    let path = symbol.path();
    rsx! {
        svg { id: "lan-qr", class: "qr-card", xmlns: "http://www.w3.org/2000/svg", view_box: "0 0 {side} {side}",
            width: "216", height: "216", shape_rendering: "crispEdges", role: "img", "aria-label": "LAN QR code",
            rect { width: "100%", height: "100%", fill: "white" }
            path { d: path.as_str(), fill: "black" }
        }
    }
}

#[component]
pub(crate) fn ScanButton(
    controller: Controller,
    epoch: FormEpoch,
    target: crate::qr::QrTarget,
) -> Element {
    if !cfg!(target_os = "android") {
        return rsx! {};
    }
    let available = crate::qr::camera_available();
    rsx! {
        button { class: "btn wide", disabled: !available || controller.snapshot().busy, "data-qv-clear": "true",
            onclick: move |_| controller.request_qr(epoch, target),
            Svg { icon: Icon::Qr }
            if target == crate::qr::QrTarget::Sync { "Scan to sync" } else { "Scan pairing QR" }
        }
        if !available { p { class: "hint", "Camera scanning is unavailable. Type the code and address instead." } }
    }
}

#[component]
pub(crate) fn ScanPanel(controller: Controller, epoch: FormEpoch) -> Element {
    rsx! {
        div { class: "layer", div { class: "scrim" }
            div { class: "dialog", role: "status",
                h3 { "Scan a QR code" }
                p { "Point the camera at the other device's code. Scanning fills the form; you choose when to connect." }
                div { class: "actions", button { class: "btn", onclick: move |_| controller.cancel_qr(epoch), "Cancel scan" } }
            }
        }
    }
}

/// What a file choice is for.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Purpose {
    AddAttachment(qv_core::EntryHandle),
}
/// Choose a file through the system picker (Linux portal, Android documents),
/// then run the action. A typed path appears only without a picker.
#[component]
pub(crate) fn FilePicker(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    purpose: Purpose,
) -> Element {
    let _ = revision;
    let Purpose::AddAttachment(entry) = purpose;
    #[cfg(target_os = "android")]
    {
        let picked = crate::android::picked_name();
        let open = controller.clone();
        let create = controller.clone();
        return rsx! {
            div { class: "actions start",
                button { class: "btn", onclick: move |_| crate::android::request_pick(&open, epoch, crate::documents::PickKind::Any, false), Svg { icon: Icon::File } "Choose a file…" }
                button { class: "btn", onclick: move |_| crate::android::request_pick(&create, epoch, crate::documents::PickKind::Any, true), Svg { icon: Icon::Folder } "Choose where to save…" }
                button { class: "btn primary", onclick: act(&controller, epoch, WsAction::AddAttachment(entry)), Svg { icon: Icon::Plus } "Add attachment" }
            }
            if let Some(name) = picked { p { class: "hint", "Chosen: {name}" } }
        };
    }
    #[cfg(not(target_os = "android"))]
    {
        if !crate::documents::picker_missing() {
            #[cfg(target_os = "linux")]
            return rsx! {
                div { class: "actions start",
                    button { class: "btn primary", id: "add-attachment", onclick: super::items::picker(&controller, epoch, qv_core::platform::portal::Pick::Open, "Add an attachment", Some(WsAction::AddAttachment(entry))), Svg { icon: Icon::Plus } "Add a file…" }
                }
            };
        }
        rsx! {
            Input { controller: controller.clone(), epoch, field: WsField::Path, label: "File to add, or destination to save to (full path)", kind: Kind::Line, value: None, disabled: false }
            div { class: "actions start",
                button { class: "btn primary", id: "add-attachment", onclick: act(&controller, epoch, WsAction::AddAttachment(entry)), Svg { icon: Icon::Plus } "Add attachment" }
            }
        }
    }
}

#[component]
fn Trash(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let view = match controller.read(epoch, views::trash) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Trash", lead: "Items stay here until you delete them for good. A snapshot is taken first, so they can still be restored from Snapshots." }
        if view.clock_anomaly { div { class: "banner", Svg { icon: Icon::Warn } span { "Vault dates are ahead of this device's clock; check it before deleting anything." } } }
        if view.items.is_empty() {
            div { class: "empty empty-tall", div { div { class: "big", Svg { icon: Icon::Trash } } span { class: "muted", "The trash is empty." } } }
        } else {
            div { class: "card",
                for t in view.items.iter().cloned() {
                    div { class: "dev",
                        span { class: "tile {id_hue(&t.item.id_hex())}", "{initial(&t.name)}" }
                        div { class: "l", b { class: "row-title", "{t.name.as_str()}" } span { "{t.deleted.clone().unwrap_or_else(|| \"Deleted by a concurrent version\".into())}" if t.conflict { " · conflict" } } }
                        button { class: "btn", onclick: act(&controller, epoch, WsAction::Restore(t.item)), Svg { icon: Icon::Restore } "Restore" }
                    }
                }
            }
            div { class: "actions start",
                if view.expired > 0 { button { class: "btn", onclick: act(&controller, epoch, WsAction::PurgeExpired), "Delete {view.expired} expired" } }
                button { class: "btn", id: "empty-trash", class: "danger-text", onclick: act(&controller, epoch, WsAction::EmptyTrash), Svg { icon: Icon::Trash } "Empty trash…" }
            }
        }
    }
}

#[component]
fn Conflicts(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let rows = match controller.read(epoch, views::conflicts) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Conflicts", lead: "Edits made on two devices at once are kept side by side until you choose one complete version." }
        if rows.is_empty() {
            div { class: "empty empty-tall", div { div { class: "big", Svg { icon: Icon::Check } } span { class: "muted", "No conflicts." } } }
        }
        div { class: "card",
            for r in rows {
                button { class: "set-row", onclick: go(&controller, epoch, Screen::ConflictRecord(r.record.clone())),
                    span { class: "si", Svg { icon: Icon::Conflicts } }
                    span { class: "l", b { "{r.name.as_deref().map(String::as_str).unwrap_or(r.kind)}" } span { "{r.kind} · {r.versions} versions" } }
                    Svg { icon: Icon::Right }
                }
            }
        }
    }
}

#[component]
fn ConflictRecord(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    record: String,
    live: Live,
) -> Element {
    let _ = (revision, live);
    let versions = match controller.read(epoch, |s| views::conflict_record(s, &record)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let needs_password = versions.iter().any(|v| v.needs_password);
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Choose a version", lead: "The chosen version becomes the record's only current version.", nested: true }
        if needs_password {
            Input { controller: controller.clone(), epoch, field: WsField::Password, label: "The chosen password slot's master password", kind: Kind::Secret, value: None, disabled: false }
        }
        for v in versions {
            div { class: "card mb",
                div { class: "card-h", "{v.state} · modified {v.modified}" }
                if v.unknown { p { class: "hint card-text", "Unknown optional values are present and will be preserved." } }
                for (label, value) in v.details.iter().cloned() {
                    div { class: "fld", div { class: "body", span { class: "k", "{label}" } pre { class: "v field-value", "{value.as_str()}" } } }
                }
                for f in v.fields.iter().cloned() {
                    ConflictField { controller: controller.clone(), epoch, record: record.clone(), version: v.version.clone(), field: f }
                }
                div { class: "actions card-actions", button { class: "btn primary", onclick: act(&controller, epoch, WsAction::Resolve(record.clone(), v.version.clone())), "Choose this version" } }
            }
        }
    }
}
#[component]
fn ConflictField(
    controller: Controller,
    epoch: FormEpoch,
    record: String,
    version: String,
    field: FieldRow,
) -> Element {
    let key = RevealKey::Conflict(record, version, field.id);
    let shown = controller
        .revealed(epoch, &key)
        .map(|v| Zeroizing::new(String::from_utf8_lossy(v.expose_secret()).into_owned()));
    rsx! {
        div { class: "fld",
            div { class: "body",
                span { class: "k", "{field.name.as_str()}" small { "{kind_name(field.kind)}" } }
                if let Some(v) = &field.value { pre { class: "v field-value", "{v.as_str()}" } }
                else if let Some(s) = &shown { pre { class: "v field-value revealed", "{s.as_str()}" } }
                else { span { class: "v masked field-value", "••••••••" } }
            }
            if field.protected {
                div { class: "acts",
                    if shown.is_some() {
                        button { class: "icon-btn", "aria-label": "Hide", onclick: act(&controller, epoch, WsAction::Hide), Svg { icon: Icon::EyeOff } }
                    } else {
                        button { class: "icon-btn", "aria-label": "Reveal for 30 seconds", onclick: act(&controller, epoch, WsAction::Reveal(key.clone())), Svg { icon: Icon::Eye } }
                    }
                }
            }
        }
    }
}

#[component]
fn Snapshots(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let (rows, unreadable) = match controller.read(epoch, views::snapshots) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let typed = cfg!(target_os = "android") || crate::documents::picker_missing();
    let restore = |id: String| -> Box<dyn FnMut(MouseEvent)> {
        #[cfg(target_os = "linux")]
        if !crate::documents::picker_missing() {
            return Box::new(super::items::picker(
                &controller,
                epoch,
                qv_core::platform::portal::Pick::Save("restored.qvault".into()),
                "Save the restored vault",
                Some(WsAction::RestoreSnapshot(id)),
            ));
        }
        Box::new(act(&controller, epoch, WsAction::RestoreSnapshot(id)))
    };
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Snapshots", lead: "Taken automatically before risky changes. Restoring creates a new vault file and a new recovery baseline; this vault is not changed.", nested: true }
        if unreadable > 0 { div { class: "banner", Svg { icon: Icon::Warn } span { "{unreadable} snapshot file(s) could not be authenticated and were skipped." } } }
        if typed {
            Input { controller: controller.clone(), epoch, field: WsField::Path, label: if cfg!(target_os = "android") { "Name for the restored vault".to_owned() } else { "New vault file for the restore (full path)".to_owned() }, kind: Kind::Line, value: None, disabled: false }
        }
        div { class: "card",
            if rows.is_empty() { div { class: "set-row", span { class: "l", span { "No snapshots yet." } } } }
            for r in rows {
                div { class: "set-row",
                    span { class: "si", Svg { icon: Icon::Clock } }
                    span { class: "l", b { "{r.created}" } span { "{r.kind} · {r.size} bytes · {r.id}" } }
                    button { class: "btn", onclick: restore(r.id.clone()), Svg { icon: Icon::Restore } "Restore…" }
                }
            }
        }
    }
}

#[component]
fn Archives(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    #[cfg(target_os = "linux")]
    if !crate::documents::picker_missing() {
        use qv_core::platform::portal::Pick;
        return rsx! {
            Head { controller: controller.clone(), epoch, title: "Archives", lead: "Move changes between copies of this vault with an encrypted file. Merging keeps concurrent edits as conflicts.", nested: true }
            div { class: "card",
                button { class: "set-row", id: "export-archive", onclick: super::items::picker(&controller, epoch, Pick::Folder, "Choose a folder for the archive", Some(WsAction::ExportArchive(false))),
                    span { class: "si", Svg { icon: Icon::Archive } } span { class: "l", b { "Export an archive" } span { "Opens only with this vault's key: another device or the recovery phrase" } } Svg { icon: Icon::Right }
                }
                button { class: "set-row", onclick: super::items::picker(&controller, epoch, Pick::Folder, "Choose a folder for the archive", Some(WsAction::ExportArchive(true))),
                    span { class: "si", Svg { icon: Icon::Key } } span { class: "l", b { "Export with the password slot" } span { "Also opens with the master password; anyone holding it can try to guess" } } Svg { icon: Icon::Right }
                }
                button { class: "set-row", id: "merge-archive", onclick: super::items::picker(&controller, epoch, Pick::Open, "Choose an archive to merge", Some(WsAction::MergeArchive)),
                    span { class: "si", Svg { icon: Icon::Folder } } span { class: "l", b { "Merge an archive" } span { "Bring in changes from another copy of this vault" } } Svg { icon: Icon::Right }
                }
            }
        };
    }
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Archives", lead: "Move changes between copies of this vault with an encrypted file. Merging keeps concurrent edits as conflicts.", nested: true }
        if cfg!(target_os = "android") {
            ArchivePicks { controller: controller.clone(), epoch, revision }
        } else {
            Input { controller: controller.clone(), epoch, field: WsField::Path, label: "Archive file to merge, or folder to export into (full path)", kind: Kind::Line, value: None, disabled: false }
        }
        div { class: "actions start",
            button { class: "btn primary", id: "merge-archive", onclick: act(&controller, epoch, WsAction::MergeArchive), "Merge archive" }
            button { class: "btn", id: "export-archive", onclick: act(&controller, epoch, WsAction::ExportArchive(false)), "Export archive" }
            button { class: "btn", onclick: act(&controller, epoch, WsAction::ExportArchive(true)), "Export with password slot" }
        }
    }
}
#[component]
fn ArchivePicks(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    #[cfg(target_os = "android")]
    {
        let picked = crate::android::picked_name();
        let open = controller.clone();
        let create = controller.clone();
        rsx! {
            div { class: "actions start",
                button { class: "btn", onclick: move |_| crate::android::request_pick(&open, epoch, crate::documents::PickKind::Archive, false), "Choose an archive…" }
                button { class: "btn", onclick: move |_| crate::android::request_pick(&create, epoch, crate::documents::PickKind::Archive, true), "Choose where to export…" }
            }
            if let Some(name) = picked { p { class: "hint", "Chosen: {name}" } }
        }
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (controller, epoch);
        rsx! {}
    }
}

#[component]
fn Settings(controller: Controller, epoch: FormEpoch, revision: u64, pane: Pane) -> Element {
    let _ = revision;
    let nested = pane != Pane::Overview;
    let row = |icon: Icon, title: &'static str, sub: &'static str, to: Screen, id: &'static str| {
        rsx! {
            button { class: "set-row", id, onclick: go(&controller, epoch, to),
                span { class: "si", Svg { icon } } span { class: "l", b { "{title}" } if !sub.is_empty() { span { "{sub}" } } } Svg { icon: Icon::Right }
            }
        }
    };
    match pane {
        Pane::Overview => {
            let theme = controller.theme();
            let os = controller.protection();
            let reduced = os.is_reduced() || qv_core::harden().is_reduced();
            let idle_only = controller.snapshot().reduced_lifecycle;
            let set = |t: Theme| {
                let c = controller.clone();
                move |_| {
                    if let Err(e) = c.set_theme(t) {
                        c.report(epoch, e);
                    }
                    c.touch();
                }
            };
            rsx! {
                Head { controller: controller.clone(), epoch, title: "Settings", lead: "" }
                div { class: "group-t", "APPEARANCE" }
                div { class: "card",
                    div { class: "set-row", span { class: "si", Svg { icon: Icon::Palette } } span { class: "l", b { "Theme" } }
                        div { class: "seg seg-wide",
                            for (t, label) in [(Theme::System, "System"), (Theme::Light, "Light"), (Theme::Dark, "Dark")] {
                                button { class: if theme == t { "on" } else { "" }, id: "theme-{t.name()}", onclick: set(t), "{label}" }
                            }
                        }
                    }
                }
                div { class: "group-t", "SECURITY" }
                div { class: "card",
                    if idle_only {
                        div { class: "set-row", id: "settings-autolock", span { class: "si", Svg { icon: Icon::Clock } } span { class: "l", b { "Auto-lock" } span { "After 1 minute without activity. This system does not report screen lock or sleep, so they do not lock QuickVault; lock it yourself before leaving." } }
                            span { class: "r warn", "Idle only" }
                        }
                    } else {
                        div { class: "set-row", id: "settings-autolock", span { class: "si", Svg { icon: Icon::Clock } } span { class: "l", b { "Auto-lock" } span { "After 1 minute without activity, and when the screen locks or the device sleeps" } } }
                    }
                    div { class: "set-row", span { class: "si", Svg { icon: Icon::Shield } } span { class: "l", b { "Device protection" }
                        span { if reduced { "Reduced protection, acknowledged on this device. Storage, swap or hibernation protection could not be established." } else { "Full: encrypted storage, swap and hibernation, with screen-lock detection" } } }
                        span { class: if reduced { "r warn" } else { "r ok" }, if reduced { "Reduced" } else { "Full" } }
                    }
                    {row(Icon::Finger, "Quick unlock and autofill", "Optional hardware unlock; autofill on supported phones", Screen::Settings(Pane::Password), "settings-quick")}
                }
                div { class: "group-t", "MASTER PASSWORD AND RECOVERY" }
                div { class: "card",
                    {row(Icon::Key, "Change master password", "", Screen::Settings(Pane::Password), "settings-password")}
                    {row(Icon::Note, "Recovery phrase", "View or confirm your 24 words", Screen::Settings(Pane::Phrase), "settings-phrase")}
                    {row(Icon::Refresh, "Rotate vault keys", "After a suspected compromise: new password and new phrase", Screen::Settings(Pane::Rotation), "settings-rotation")}
                }
                div { class: "group-t", "VAULT" }
                div { class: "card",
                    {row(Icon::Edit, "Name and retention", "Vault name, description, history and trash", Screen::Settings(Pane::General), "settings-general")}
                    {row(Icon::Clock, "Snapshots", "Restore an earlier copy into a new vault", Screen::Snapshots, "settings-snapshots")}
                    {row(Icon::Archive, "Archives", "Export or merge changes as an encrypted file", Screen::Archives, "settings-archives")}
                    {row(Icon::Check, "Check vault integrity", "Re-checks every stored object; changes nothing", Screen::Settings(Pane::Verify), "settings-verify")}
                    {row(Icon::Shield, "About this vault", "Identifiers and key-derivation settings", Screen::Settings(Pane::About), "settings-about")}
                }
            }
        }
        Pane::General => rsx! {
            Head { controller: controller.clone(), epoch, title: "Name and retention", lead: "", nested }
            General { controller: controller.clone(), epoch, revision }
        },
        Pane::Password => rsx! {
            Head { controller: controller.clone(), epoch, title: "Password and quick unlock", lead: "", nested }
            QuickSettings { controller: controller.clone(), epoch, revision }
            div { class: "group-t", "CHANGE MASTER PASSWORD" }
            div { class: "card card-pad",
                p { class: "hint", "Older copies of the vault and its password slot still open with the old password. After a suspected compromise, rotate keys instead." }
                Input { controller: controller.clone(), epoch, field: WsField::NewPassword, label: "New master password", kind: Kind::Secret, value: None, disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::Repeat, label: "Type it again", kind: Kind::Secret, value: None, disabled: false }
                PasswordGuidance { controller: controller.clone(), epoch, revision }
                div { class: "actions", button { class: "btn primary", id: "change-password", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::ChangePassword), "Change master password" } }
            }
        },
        Pane::Phrase => rsx! {
            Head { controller: controller.clone(), epoch, title: "Recovery phrase", lead: "", nested }
            PhrasePane { controller: controller.clone(), epoch, revision }
        },
        Pane::Rotation => rsx! {
            Head { controller: controller.clone(), epoch, title: "Rotate vault keys", lead: "Creates a new key generation with a new master password and a new recovery phrase. It can take a while, can be resumed, and locks the vault when it finishes.", nested }
            div { class: "card card-pad",
                Input { controller: controller.clone(), epoch, field: WsField::Confirmation, label: "Type rotate to continue", kind: Kind::Line, value: None, disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::NewPassword, label: "New master password", kind: Kind::Secret, value: None, disabled: false }
                Input { controller: controller.clone(), epoch, field: WsField::Repeat, label: "Type it again", kind: Kind::Secret, value: None, disabled: false }
                PasswordGuidance { controller: controller.clone(), epoch, revision }
                div { class: "actions", button { class: "btn danger", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::BeginRotation), "Prepare key rotation" } }
            }
        },
        Pane::Verify => rsx! {
            Head { controller: controller.clone(), epoch, title: "Check vault integrity", lead: "Re-hashes and authenticates every object, manifest and the local head. Nothing is changed or repaired.", nested }
            div { class: "actions start", button { class: "btn primary", id: "verify", onclick: act(&controller, epoch, WsAction::Verify), Svg { icon: Icon::Check } "Check now" } }
        },
        Pane::About => rsx! {
            Head { controller: controller.clone(), epoch, title: "About this vault", lead: "", nested }
            About { controller: controller.clone(), epoch, revision }
        },
    }
}
#[component]
fn General(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(form) = controller.settings_form(epoch) else {
        return rsx! { Unreadable { error: None } };
    };
    rsx! {
        div { class: "card card-pad",
            Input { controller: controller.clone(), epoch, field: WsField::VaultName, label: "Vault name", kind: Kind::Line, value: Some(form.name.to_string()), disabled: false }
            Input { controller: controller.clone(), epoch, field: WsField::Description, label: "Description", kind: Kind::Line, value: Some(form.description.to_string()), disabled: false }
            Input { controller: controller.clone(), epoch, field: WsField::HistoryDepth, label: "Earlier versions to keep per item (blank: default)", kind: Kind::Line, value: Some(form.history_depth.clone()), disabled: false }
            Input { controller: controller.clone(), epoch, field: WsField::TrashDays, label: "Days before trash is offered for deletion (blank: default)", kind: Kind::Line, value: Some(form.trash_days.clone()), disabled: false }
            div { class: "actions", button { class: "btn primary", id: "save-settings", onclick: act(&controller, epoch, WsAction::SaveSettings), "Save" } }
        }
    }
}
#[component]
fn QuickSettings(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let available = controller.protection().quick_unlock;
    rsx! {
        div { class: "group-t", "QUICK UNLOCK" }
        div { class: "card card-pad",
            p { class: "hint", "Opt-in hardware authentication for this app process. Restart, reboot, seven days, three failed attempts or a password or key change need the master password again." }
            if !available {
                p { class: "hint", "Unavailable: this device has no validated quick-unlock backend. The master password still works." }
            } else {
                Input { controller: controller.clone(), epoch, field: WsField::Password, label: "Master password to enroll quick unlock", kind: Kind::Secret, value: None, disabled: false }
                div { class: "actions start",
                    button { class: "btn primary", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::EnrollQuick(qv_core::platform::QuickPolicy::Class3)), Svg { icon: Icon::Finger } "Enable biometric quick unlock" }
                    button { class: "btn", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::EnrollQuick(qv_core::platform::QuickPolicy::DeviceCredential)), "Device credential (reduced protection)…" }
                    button { class: "btn subtle", onclick: act(&controller, epoch, WsAction::DisableQuick), "Disable quick unlock" }
                }
            }
        }
        div { class: "group-t", "AUTOFILL" }
        div { class: "card card-pad",
            if controller.autofill_available() {
                p { class: "hint", "Fills only entries linked to a verified app or an exact website from a validated browser, after you unlock and choose." }
                div { class: "actions start", button { class: "btn", onclick: act(&controller, epoch, WsAction::OpenAutofillSettings), "Open Android autofill settings" } }
            } else {
                p { class: "hint", "Unavailable: autofill is disabled on devices without recorded validation." }
            }
        }
    }
}
#[component]
fn PasswordGuidance(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let fair = controller
        .peek(epoch, |ws| ws.fair_warning)
        .unwrap_or(false);
    let suggestion = Zeroizing::new(
        controller
            .generated(epoch)
            .map(|(v, _)| String::from_utf8_lossy(v.expose_secret()).into_owned())
            .unwrap_or_default(),
    );
    rsx! {
        if fair { div { class: "banner", Svg { icon: Icon::Warn } span { "This password is fair. Consider a longer, less predictable passphrase." } } }
        button { class: "link", onclick: act(&controller, epoch, WsAction::SuggestPassword), "Suggest a six-word passphrase" }
        if !suggestion.is_empty() { div { class: "phrase single mono revealed", "{suggestion.as_str()}" } p { class: "hint", "Visible for 30 seconds." } }
    }
}
#[component]
fn PhrasePane(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(screen) = controller.phrase_screen(epoch) else {
        return rsx! {
            div { class: "card card-pad",
                p { class: "hint", "Enter your master password to show the recovery phrase. Anyone with the phrase and your vault file can open it." }
                Input { controller: controller.clone(), epoch, field: WsField::Password, label: "Master password", kind: Kind::Secret, value: None, disabled: false, autofocus: true }
                div { class: "actions", button { class: "btn primary", id: "show-phrase", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::ShowPhrase), "Show recovery phrase" } }
            }
        };
    };
    let words: Vec<(usize, Zeroizing<String>)> = controller
        .phrase_words(epoch)
        .map(|v| {
            String::from_utf8_lossy(v.expose_secret())
                .split_whitespace()
                .enumerate()
                .map(|(i, w)| (i + 1, Zeroizing::new(w.to_owned())))
                .collect()
        })
        .unwrap_or_default();
    rsx! {
        div { class: "phrase mono", for (n, w) in words { span { small { "{n}" } b { class: "w", "{w.as_str()}" } } } }
        if screen.confirmed {
            div { class: "banner ok", Svg { icon: Icon::Check } span { "The recovery words are confirmed." } }
        } else {
            div { class: "card card-pad mt",
                p { class: "hint", "Optionally check words {screen.positions[0]}, {screen.positions[1]} and {screen.positions[2]} against your copy." }
                for (i, n) in [(0u8, screen.positions[0]), (1, screen.positions[1]), (2, screen.positions[2])] {
                    Input { controller: controller.clone(), epoch, field: WsField::Word(i), label: format!("Word {n}"), kind: Kind::Secret, value: None, disabled: false }
                }
                div { class: "actions", button { class: "btn", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::ConfirmWords), "Check words" } }
            }
        }
        div { class: "actions start", button { class: "btn subtle", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::HidePhrase), Svg { icon: Icon::EyeOff } "Hide the phrase" } }
    }
}
#[component]
fn About(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let about = controller.about(epoch);
    let overview = controller.read(epoch, views::overview).and_then(Result::ok);
    rsx! {
        if let Some(o) = overview {
            div { class: "group-t", "CONTENTS (VERIFIED)" }
            div { class: "card", div { class: "set-row", span { class: "l", b { "{o.entries} items · {o.groups} groups" } span { "{o.trash} in trash · {o.conflicts} conflicts" } } } }
        }
        div { class: "group-t", "HEADER (UNVERIFIED WITHOUT THE PASSWORD)" }
        if let Some(a) = about {
            div { class: "card",
                div { class: "set-row", span { class: "l", b { "Vault ID" } span { class: "mono", "{a.vault_id}" } } }
                div { class: "set-row", span { class: "l", b { "Key generation" } span { "{a.key_generation} · format {a.format:#010x}" } } }
                div { class: "set-row", span { class: "l", b { "Password key derivation" } span { "Argon2id, {a.kdf.0} MiB, {a.kdf.1} iterations, {a.kdf.2} lanes" } } }
            }
        } else {
            p { class: "muted", "Header details appear after the next unlock." }
        }
        p { class: "hint mt", "QuickVault · offline-first, end-to-end encrypted · AGPL-3.0-or-later" }
    }
}
#[component]
fn AutofillScreen(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let Some(view) = controller.autofill_view() else {
        return rsx! {
            Head { controller: controller.clone(), epoch, title: "Autofill", lead: "No autofill request is waiting." }
        };
    };
    let requester = view.requester.clone();
    let candidates = controller
        .read(epoch, move |s| s.autofill_candidates(&requester))
        .and_then(Result::ok)
        .unwrap_or_default();
    let query = controller
        .peek(epoch, |ws| {
            String::from_utf8_lossy(ws.input(WsField::Query)).into_owned()
        })
        .map(Zeroizing::new)
        .unwrap_or_default();
    let results = if view.app.is_some() && !query.is_empty() {
        controller
            .read(epoch, |s| views::search(s, &query))
            .and_then(Result::ok)
            .map(|(_, entries)| entries)
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Fill a login", lead: "Only items linked to this exact verified identity are listed. Titles and app names are never used for matching." }
        div { class: "banner ok", Svg { icon: Icon::Shield } span { "For: {view.label}" } }
        if candidates.is_empty() { p { class: "muted", "No entry matches this verified identity." } }
        div { class: "card",
            for c in candidates {
                button { class: "set-row", "data-qv-autofill": "candidate", onclick: act(&controller, epoch, WsAction::AutofillFill(c.key())),
                    span { class: "tile {id_hue(&c.entry().id_hex())}", "{initial(c.title.expose())}" }
                    span { class: "l", b { "{c.title.expose()}" }
                        span { if c.conflicted { "Conflicting version · check before filling · " } "{c.username.as_ref().map_or(\"\", |u| u.expose())}" }
                    }
                }
            }
        }
        if let Some((package, signers)) = view.app.clone() {
            details { class: "mt",
                summary { "Link this app to an item…" }
                div { class: "banner", Svg { icon: Icon::Warn } span { "QuickVault cannot tell whether this app belongs to the service. Link only an app you trust." } }
                p { class: "hint", "Package {package} · signer {signers}…" }
                Input { controller: controller.clone(), epoch, field: WsField::Query, label: "Find the item to link", kind: Kind::Line, value: Some(query.to_string()), disabled: false }
                div { class: "card",
                    for e in results {
                        button { class: "set-row", "data-qv-autofill": "link", onclick: act(&controller, epoch, WsAction::AutofillLink(e.handle)),
                            span { class: "l", b { "{e.title.as_str()}" } span { "Link this app" } }
                        }
                    }
                }
            }
        }
        div { class: "actions start", button { class: "btn", "data-qv-autofill": "cancel", onclick: act(&controller, epoch, WsAction::AutofillCancel), "Cancel autofill" } }
    }
}
