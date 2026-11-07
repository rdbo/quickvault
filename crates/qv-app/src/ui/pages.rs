// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sections beside the vault: generator, devices and LAN sync, trash,
//! conflicts, snapshots, archives, settings and autofill. File choices use
//! the system picker; a typed path appears only when no picker is available.
use super::icons::{Icon, Logo, Svg, id_hue, initial};
use super::items::{Input, Kind};
use super::shell::{ReportCard, Unreadable, act, go};
use crate::controller::{Controller, FormEpoch};
use crate::prefs::Theme;
use crate::views;
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
    // Every page switch rebuilds the wrapper, so it fades in again.
    let key = match &screen {
        Screen::Settings(p) => format!("{}-Settings-{p:?}", epoch.0),
        s => format!("{}-{s:?}", epoch.0),
    };
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
            super::Remount { token: key, class: "page-inner fade-in",
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

#[component]
fn Devices(controller: Controller, epoch: FormEpoch, revision: u64, busy: bool) -> Element {
    let _ = revision;
    let mut typing = use_signal(|| FormEpoch(u64::MAX));
    // A scanned code without an address opens the form to ask for it.
    let scanned = controller.lan_scanned(epoch);
    let open = scanned || typing() == epoch;
    let close = move |_| typing.set(FormEpoch(u64::MAX));
    let scan = cfg!(target_os = "android") && crate::qr::camera_available();
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Devices", lead: "" }
        // One explanation, then the two ways to start (plan 0045): this
        // device shows a code, or it scans (or types) the other one's.
        div { class: "dev-hero",
            div { class: "sync-orbit", "aria-hidden": "true",
                span { class: "dev a", Svg { icon: Icon::Devices } }
                span { class: "beam", i {} i {} i {} }
                span { class: "dev b", Svg { icon: Icon::Devices } }
            }
            b { "Sync with another device" }
            span { "Over your local network. No account, no server. One device shows a code, the other scans it. Each code works once." }
        }
        div { class: "choices dev-choices",
            button { class: "choice", id: "show-code", disabled: busy, onclick: act(&controller, epoch, WsAction::LanOffer),
                span { class: "ci", Svg { icon: Icon::Qr } } b { "Show a code" } span { "The other device scans or types it" }
            }
            if scan {
                button { class: "choice", id: "scan-code", disabled: busy, "data-qv-clear": "true", onclick: { let c = controller.clone(); move |_| c.request_qr(epoch, crate::qr::QrTarget::Sync) },
                    span { class: "ci", Svg { icon: Icon::Devices } } b { "Scan a code" } span { "Point the camera at the other device's code" }
                }
            } else {
                button { class: "choice", id: "type-code", disabled: busy, onclick: move |_| typing.set(epoch),
                    span { class: "ci", Svg { icon: Icon::Devices } } b { "Type a code" } span { "Enter the code and address the other device shows" }
                }
            }
        }
        if scan {
            p { class: "center", button { class: "link", id: "type-code", disabled: busy, onclick: move |_| typing.set(epoch), "Type a code instead" } }
        }
        if open {
            div { class: "layer",
                button { class: "scrim", "aria-label": "Close", onclick: close }
                div { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Use another device's code",
                    h3 { "Use another device's code" }
                    p { "On the other device, open Devices and choose Show a code. Type the code and the address it shows." }
                    if scanned {
                        p { class: "banner ok", role: "status", id: "lan-code-scanned", Svg { icon: Icon::Check } " Code from the QR code" }
                    } else {
                        Input { controller: controller.clone(), epoch, field: WsField::LanCode, label: "Code", kind: Kind::Secret, value: None, disabled: false, autofocus: true }
                    }
                    Input { controller: controller.clone(), epoch, field: WsField::LanEndpoint, label: "The other device's address (ip:port)", kind: Kind::Line, value: None, disabled: false, autofocus: scanned }
                    div { class: "actions",
                        button { class: "btn subtle", onclick: close, "Cancel" }
                        button { class: "btn primary", id: "sync-submit", "data-qv-clear": "true", onclick: { let mut f = act(&controller, epoch, WsAction::LanSync); move |e| { typing.set(FormEpoch(u64::MAX)); f(e) } }, "Sync" }
                    }
                }
            }
        }
    }
}

/// The running or finished LAN operation as a modal: code, QR, endpoints,
/// countdown, comparison questions and the outcome. Also on the locked screen.
/// `seconds` is a prop only so that the countdown redraws as it changes.
#[component]
pub(crate) fn LanPanel(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    seconds: u64,
) -> Element {
    let _ = (revision, seconds);
    let expanded = use_signal(|| false);
    let Some(v) = controller.lan_view(epoch) else {
        return rsx! {};
    };
    use crate::lan::{LanKind, Question};
    if let Some(done) = v.done.as_ref() {
        return receipt(&controller, epoch, v.kind, done, v.closes_in, expanded);
    }
    let title = match v.kind {
        LanKind::Window => "Scan or type this code on the other device",
        LanKind::Sync => "Syncing with another device",
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
                if v.question.is_none() && v.qr.is_none() && code.is_none() {
                    div { class: "sync-orbit", "aria-hidden": "true",
                        span { class: "dev a", Svg { icon: Icon::Devices } }
                        span { class: "beam", i {} i {} i {} }
                        span { class: "dev b", Svg { icon: Icon::Devices } }
                    }
                }
                h3 { "{title}" }
                if let Some(symbol) = v.qr.as_ref() { { qr_image(symbol) } }
                if let Some(code) = code {
                    p { class: "center hint", "The code works once. Show it only to the device you want to sync with." }
                    div { class: "phrase single mono center", id: "lan-code", "{code.as_str()}" }
                }
                if !v.endpoints.is_empty() {
                    p { class: "center hint", "This device's address:" }
                    div { class: "center mono", for e in v.endpoints.iter() { div { "{e}" } } }
                }
                if v.seconds > 0 { p { class: "center hint", "Closes in {v.seconds / 60}:{v.seconds % 60:02}" } }
                if let (Some(sas), true) = (v.sas.as_ref(), v.question.is_none() && v.done.is_none()) {
                    div { role: "status", "aria-label": "Comparison code",
                        p { class: "center", "Check that the other device shows this code:" }
                        div { class: "code-big mono phrase single", id: "lan-sas-wait", "{sas}" }
                        p { class: "center hint", "If the codes differ, cancel. The vault is only joined after you confirm it." }
                    }
                }
                if let Some(i) = v.info.as_ref() { p { class: "banner ok notice", role: "status", "{i}" } }
                match v.question.clone() {
                    Some(Question::Approve { sas, vault }) => rsx! {
                        div { role: "alertdialog", "aria-label": "Compare codes",
                            p { class: "center", "A new device asks to join “{vault}”. It will receive this vault." }
                            div { class: "code-big mono phrase single", id: "lan-sas", "{sas}" }
                            p { class: "center hint", "Confirm only if the other device shows exactly this code." }
                            div { class: "actions",
                                button { class: "btn subtle", onclick: answer(false), "They differ" }
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
                if v.question.is_none() {
                    div { class: "actions", button { class: "btn subtle", id: "lan-cancel", onclick: cancel, "Cancel" } }
                }
            }
        }
    }
}

/// The finished operation as a receipt docked at the bottom, not a modal
/// (0009 §1.8, plan 0044): what happened, what changed here (openable), the
/// other device's confirmation, and the one next step. A clean receipt
/// closes itself; a click or focus keeps it.
fn receipt(
    controller: &Controller,
    epoch: FormEpoch,
    kind: crate::lan::LanKind,
    done: &crate::lan::LanDone,
    closes_in: Option<u64>,
    mut expanded: Signal<bool>,
) -> Element {
    use crate::lan::LanKind;
    let round = done.round.as_ref();
    let conflicts = round.map_or(0, |r| r.conflicts);
    let confirmed = round.is_none_or(|r| r.peer_confirmed);
    let tone = if done.error.is_some() {
        "bad"
    } else if conflicts > 0 || !confirmed {
        "warn"
    } else {
        "ok"
    };
    let plural = |n: usize, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    let title = match (round, done.error) {
        (None, Some(_)) if kind == LanKind::Join => "Joining didn't finish".to_owned(),
        (None, Some(_)) => "Sync didn't finish".to_owned(),
        (None, None) => done
            .lines
            .first()
            .cloned()
            .unwrap_or_else(|| "Done".to_owned()),
        (Some(_), Some(_)) => "Synced, with a problem".to_owned(),
        (Some(r), None) if r.conflicts > 0 => format!(
            "{} your choice",
            plural(r.conflicts, "item needs", "items need")
        ),
        (Some(r), None) if r.received && r.changes.total() > 0 => format!(
            "Received {}",
            plural(r.changes.total(), "change", "changes")
        ),
        (Some(r), None) if r.received => "Received changes".to_owned(),
        (Some(_), None) => "Up to date".to_owned(),
    };
    let sub = match (round, done.error) {
        (_, Some(e)) => e.message().to_owned(),
        (Some(r), None) if !r.peer_confirmed => {
            "The other device didn't confirm receipt. Sync again later to be sure.".to_owned()
        }
        (Some(r), None) if r.conflicts > 0 => {
            "Both devices changed the same items. Pick what to keep.".to_owned()
        }
        (Some(_), None) => "Both devices now hold the same vault.".to_owned(),
        (None, None) => done.lines.get(1).cloned().unwrap_or_default(),
    };
    let icon = match tone {
        "bad" => Icon::Warn,
        "warn" if conflicts > 0 => Icon::Conflicts,
        "warn" => Icon::Warn,
        _ => Icon::Check,
    };
    let changes = round.map(|r| r.changes.clone()).unwrap_or_default();
    let listed: Vec<(&'static str, crate::lan::Change)> = changes
        .added
        .iter()
        .map(|c| ("new", c.clone()))
        .chain(changes.updated.iter().map(|c| ("changed", c.clone())))
        .chain(changes.trashed.iter().map(|c| ("trash", c.clone())))
        .collect();
    let shown = if expanded() {
        listed.len()
    } else {
        listed.len().min(3)
    };
    let more = changes.total().saturating_sub(shown);
    let keep = {
        let c = controller.clone();
        move |_| c.lan_keep(epoch)
    };
    let keep_focus = {
        let c = controller.clone();
        move |_| c.lan_keep(epoch)
    };
    let close = {
        let c = controller.clone();
        move |e: MouseEvent| {
            e.stop_propagation();
            c.lan_dismiss(epoch);
        }
    };
    let resolve = {
        let c = controller.clone();
        move |e: MouseEvent| {
            e.stop_propagation();
            // One conflicted record opens its comparison directly.
            let only = c
                .read(epoch, views::conflicts)
                .and_then(Result::ok)
                .and_then(|rows| (rows.len() == 1).then(|| rows[0].record.clone()));
            c.navigate(
                epoch,
                only.map_or(Screen::Conflicts, Screen::ConflictRecord),
            );
            c.lan_dismiss(epoch);
        }
    };
    // The countdown ring: a 2π·9 ≈ 56.5 circumference, emptied over 6 s.
    let ring = closes_in.map(|left| {
        let total = crate::lan::RECEIPT_SECONDS as f64;
        format!(
            "{:.1}",
            56.5 * (1.0 - (left as f64 / total).clamp(0.0, 1.0))
        )
    });
    rsx! {
        div { class: "receipt {tone}", id: "lan-receipt", role: "status", "aria-live": "polite", tabindex: "0", onclick: keep, onfocus: keep_focus,
            div { class: "r-mark", Svg { icon, large: true } }
            div { class: "r-body",
                b { class: "r-title", id: "lan-receipt-title", "{title}" }
                if !sub.is_empty() { span { class: "r-sub", "{sub}" } }
                if changes.total() > 0 {
                    div { class: "r-chips",
                        if changes.counts[0] > 0 { span { class: "r-chip new", "+{changes.counts[0]} new" } }
                        if changes.counts[1] > 0 { span { class: "r-chip changed", "{changes.counts[1]} changed" } }
                        if changes.counts[2] > 0 { span { class: "r-chip trash", "{changes.counts[2]} to trash" } }
                    }
                    ul { class: "r-list",
                        for (mark, ch) in listed.into_iter().take(shown) {
                            li { class: "r-item {mark}",
                                if let Some(h) = ch.entry {
                                    button { class: "r-open", onclick: { let c = controller.clone(); move |e: MouseEvent| { e.stop_propagation(); c.lan_keep(epoch); c.navigate(epoch, Screen::Entry(h)); } },
                                        i {} span { "{ch.title.as_str()}" } Svg { icon: Icon::Right }
                                    }
                                } else {
                                    span { class: "r-open static", i {} span { "{ch.title.as_str()}" } }
                                }
                            }
                        }
                    }
                    if more > 0 && !expanded() {
                        button { class: "link r-more", onclick: move |e: MouseEvent| { e.stop_propagation(); expanded.set(true); }, "and {more} more" }
                    }
                }
                if conflicts > 0 {
                    div { class: "r-actions",
                        button { class: "btn primary", id: "lan-resolve", onclick: resolve, Svg { icon: Icon::Conflicts } "Resolve now" }
                    }
                }
            }
            button { class: "r-close", id: "lan-dismiss", "aria-label": "Close", title: "Close", onclick: close,
                if let Some(offset) = ring {
                    svg { class: "r-ring", view_box: "0 0 22 22", width: "26", height: "26", "aria-hidden": "true",
                        circle { cx: "11", cy: "11", r: "9", fill: "none", stroke_width: "2", stroke_dasharray: "56.5", stroke_dashoffset: "{offset}" }
                    }
                }
                Svg { icon: Icon::Close }
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
            "Scan a code"
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
                p { "Point the camera at the other device's code. A code that names its address connects at once; otherwise you type the address." }
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
    let view = match controller.read(epoch, |s| views::conflict_compare(s, &record)) {
        Some(Ok(v)) => v,
        other => return rsx! { Unreadable { error: other.and_then(Result::err) } },
    };
    let identical = view.identical();
    let n = view.heads.len();
    let cols = match n {
        0..=2 => "cols-2",
        3 => "cols-3",
        _ => "cols-4",
    };
    let diff: Vec<views::CompareRow> = view.rows.iter().filter(|r| !r.same).cloned().collect();
    let same: Vec<views::CompareRow> = view.rows.iter().filter(|r| r.same).cloned().collect();
    let heads = view.heads.clone();
    let all_same = diff.is_empty();
    let lead = if identical {
        format!(
            "“{}” has {n} versions with the same content. Keep either one.",
            view.name.as_str()
        )
    } else {
        format!(
            "“{}” was changed on more than one device. Only the differences are shown side by side; keep the version you want.",
            view.name.as_str()
        )
    };
    rsx! {
        Head { controller: controller.clone(), epoch, title: "Compare versions", lead, nested: true }
        if identical {
            div { class: "banner ok", Svg { icon: Icon::Check } span { "Nothing you can see differs. The versions differ only in internal details, such as when they were saved." } }
        }
        if view.needs_password {
            Input { controller: controller.clone(), epoch, field: WsField::Password, label: "The chosen password slot's master password", kind: Kind::Secret, value: None, disabled: false }
        }
        div { class: "cmp {cols}", role: "table", "aria-label": "Versions compared",
            div { class: "cmp-row cmp-heads", role: "row",
                span { class: "k", role: "columnheader", "{view.kind}" }
                for h in heads.iter() {
                    div { class: "cmp-col v{h.label.to_ascii_lowercase()}", role: "columnheader",
                        b { span { class: "vl", "{h.label}" } "Version {h.label}" }
                        span { "{h.state} · {h.modified}" }
                    }
                }
            }
            if !diff.is_empty() {
                div { class: "cmp-sect", "DIFFERENT" }
            }
            for row in diff {
                div { class: "cmp-row diff", role: "row",
                    span { class: "k", role: "rowheader", "{row.label.as_str()}" }
                    for (i, cell) in row.cells.iter().cloned().enumerate() {
                        {cmp_cell(&controller, epoch, &record, heads.get(i).map(|h| h.version.clone()).unwrap_or_default(), cell)}
                    }
                }
            }
        }
        if !same.is_empty() {
            details { class: "cmp-same", open: all_same,
                summary { Svg { icon: Icon::Check } "Same in every version · {same.len()}" }
                div { class: "cmp-same-list",
                    for row in same {
                        div { class: "fld",
                            div { class: "body",
                                span { class: "k", "{row.label.as_str()}" }
                                match row.cells.first() {
                                    Some(views::Cell::Text(v)) if v.is_empty() => rsx! { span { class: "v muted", "Empty" } },
                                    Some(views::Cell::Text(v)) => rsx! { pre { class: "v field-value", "{v.as_str()}" } },
                                    Some(views::Cell::Masked(_)) => rsx! { span { class: "v muted", "Same protected value" } },
                                    _ => rsx! { span { class: "v muted", "Not set" } },
                                }
                            }
                        }
                    }
                }
            }
        }
        div { class: "cmp-bar", role: "group", "aria-label": "Choose a version",
            span { class: "hint", if identical { "Keep one to end the conflict." } else { "The version you keep becomes the item." } }
            for (i, h) in view.heads.iter().enumerate() {
                if !identical || i == 0 {
                    button { class: if i == 0 { "btn primary" } else { "btn" }, id: "keep-{h.label.to_ascii_lowercase()}",
                        onclick: act(&controller, epoch, WsAction::Resolve(record.clone(), h.version.clone())),
                        if identical { "Keep it" } else { span { class: "keep", b { "Keep {h.label}" } small { "{h.modified}" } } }
                    }
                }
            }
        }
    }
}
/// One comparison cell; a protected one reveals only that version's value.
fn cmp_cell(
    controller: &Controller,
    epoch: FormEpoch,
    record: &str,
    version: String,
    cell: views::Cell,
) -> Element {
    match cell {
        views::Cell::Text(v) if v.is_empty() => {
            rsx! { div { class: "cmp-cell", role: "cell", span { class: "muted", "Empty" } } }
        }
        views::Cell::Text(v) => {
            rsx! { div { class: "cmp-cell", role: "cell", pre { class: "field-value", "{v.as_str()}" } } }
        }
        views::Cell::Missing => {
            rsx! { div { class: "cmp-cell", role: "cell", span { class: "muted", "Not in this version" } } }
        }
        views::Cell::Masked(field) => {
            let key = RevealKey::Conflict(record.to_owned(), version, field);
            let shown = controller
                .revealed(epoch, &key)
                .map(|v| Zeroizing::new(String::from_utf8_lossy(v.expose_secret()).into_owned()));
            rsx! {
                div { class: "cmp-cell masked", role: "cell",
                    if let Some(s) = &shown { pre { class: "field-value revealed", "{s.as_str()}" } } else { span { class: "masked field-value", "••••••••" } }
                    if shown.is_some() {
                        button { class: "icon-btn", "aria-label": "Hide", onclick: act(controller, epoch, WsAction::Hide), Svg { icon: Icon::EyeOff } }
                    } else {
                        button { class: "icon-btn", "aria-label": "Reveal for 30 seconds", onclick: act(controller, epoch, WsAction::Reveal(key.clone())), Svg { icon: Icon::Eye } }
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
            let level = crate::prefs::level(&os, qv_core::harden().is_reduced());
            let missing = protection_gaps(&os, qv_core::harden().is_reduced());
            let detail = if missing.is_empty() {
                "Encrypted storage, swap and hibernation, with screen-lock detection and clipboard clearing".to_owned()
            } else {
                format!("Not confirmed: {}", missing.join(", "))
            };
            let idle_only = controller.snapshot().reduced_lifecycle;
            let open_vault = controller.open_vault();
            let folder_place = crate::vaults::shown_place(&controller.default_folder());
            let pick_folder = {
                let c = controller.clone();
                move |_: MouseEvent| {
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
                    div { class: "set-row", id: "settings-protection", span { class: "si", Svg { icon: Icon::Shield } } span { class: "l", b { "Device protection" }
                        span { "{detail}" } }
                        span { class: "r {level.tone()}", "{level.label()}" }
                    }
                    {row(Icon::Finger, "Quick unlock and autofill", if controller.quick_policy().is_some() { "Fingerprint unlock is on" } else { "Fingerprint unlock; autofill on supported phones" }, Screen::Settings(Pane::Password), "settings-quick")}
                }
                div { class: "group-t", "MASTER PASSWORD AND RECOVERY" }
                div { class: "card",
                    {row(Icon::Key, "Change master password", "", Screen::Settings(Pane::Password), "settings-password")}
                    {row(Icon::Note, "Recovery phrase", "View or confirm your 24 words", Screen::Settings(Pane::Phrase), "settings-phrase")}
                    {row(Icon::Refresh, "Rotate vault keys", "After a suspected compromise: new password and new phrase", Screen::Settings(Pane::Rotation), "settings-rotation")}
                }
                div { class: "group-t", "VAULT" }
                div { class: "card",
                    if let Some(v) = open_vault.as_ref() {
                        div { class: "set-row", id: "settings-file", span { class: "si", Svg { icon: Icon::File } } span { class: "l", b { "Vault file" } span { "{v.file} in {v.place}" } } }
                    }
                    button { class: "set-row", id: "settings-switch",
                        onclick: { let c = controller.clone(); move |_| { c.switch_vault(epoch, crate::controller::SwitchTo::Mode(crate::controller::Mode::Unlock)); } },
                        span { class: "si", Svg { icon: Icon::Lock } } span { class: "l", b { "Switch vault" } span { "Locks this vault; open, create or join another from the lock screen" } } Svg { icon: Icon::Right }
                    }
                    div { class: "set-row", id: "settings-folder", span { class: "si", Svg { icon: Icon::Folder } } span { class: "l", b { "Folder for new vaults" } span { "{folder_place}" } }
                        if cfg!(target_os = "linux") && !crate::documents::picker_missing() {
                            button { class: "btn", id: "settings-folder-change", onclick: pick_folder, "Change…" }
                        }
                    }
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
/// The checks behind a protection level that are not in place.
fn protection_gaps(
    os: &qv_core::platform::ProtectionStatus,
    process_reduced: bool,
) -> Vec<&'static str> {
    use qv_core::platform::Evidence::Verified;
    [
        (os.storage == Verified, "disk encryption"),
        (os.swap == Verified, "swap"),
        (os.hibernation == Verified, "hibernation"),
        (os.lifecycle, "screen-lock detection"),
        (os.clipboard, "clipboard clearing"),
        (!process_reduced, "memory protection"),
    ]
    .into_iter()
    .filter(|(ok, _)| !ok)
    .map(|(_, name)| name)
    .collect()
}
#[component]
fn QuickSettings(controller: Controller, epoch: FormEpoch, revision: u64) -> Element {
    let _ = revision;
    let available = controller.protection().quick_unlock;
    let policy = controller.quick_policy();
    rsx! {
        div { class: "group-t", "QUICK UNLOCK" }
        div { class: "card card-pad",
            if !available {
                p { class: "hint", "Unavailable: this device has no supported fingerprint or screen lock for QuickVault. The master password still works." }
            } else {
                match policy {
                    Some(qv_core::platform::QuickPolicy::Class3) => rsx! { div { class: "banner ok", id: "quick-on", Svg { icon: Icon::Finger } span { "Fingerprint unlock is on. The locked screen asks for your fingerprint first." } } },
                    Some(qv_core::platform::QuickPolicy::DeviceCredential) => rsx! { div { class: "banner ok", id: "quick-on", Svg { icon: Icon::Finger } span { "Screen-lock unlock is on (lower protection: your PIN or pattern opens this vault)." } } },
                    None => rsx! { p { class: "hint", "Off. Enter your master password to turn on fingerprint unlock." } },
                }
                p { class: "hint", "Restarting the phone, seven days, three failed attempts or a password change ask for the master password again." }
                Input { controller: controller.clone(), epoch, field: WsField::Password, label: "Master password", kind: Kind::Secret, value: None, disabled: false }
                div { class: "actions start",
                    button { class: "btn primary", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::EnrollQuick(qv_core::platform::QuickPolicy::Class3)), Svg { icon: Icon::Finger } if policy.is_some() { "Turn on fingerprint unlock again" } else { "Turn on fingerprint unlock" } }
                    button { class: "btn", "data-qv-clear": "true", onclick: act(&controller, epoch, WsAction::EnrollQuick(qv_core::platform::QuickPolicy::DeviceCredential)), "Use your screen lock PIN or pattern instead (lower protection)…" }
                    if policy.is_some() { button { class: "btn subtle", id: "quick-off", onclick: act(&controller, epoch, WsAction::DisableQuick), "Turn off quick unlock" } }
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
    let version = env!("CARGO_PKG_VERSION");
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
        div { class: "about-brand mt", Logo { class: "logo-about" }
            span { b { "QuickVault" } span { class: "hint", "Version {version} · offline-first, end-to-end encrypted · AGPL-3.0-or-later" } }
        }
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
