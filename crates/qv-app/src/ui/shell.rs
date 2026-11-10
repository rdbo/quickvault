// SPDX-License-Identifier: AGPL-3.0-or-later

//! The window chrome and the unlocked shell: title bar (desktop windows have
//! no OS decorations, 0009 §1.8), sidebar, phone tabs, command bar, toasts
//! and confirmations. Layout comes from CSS container queries over one DOM.
use super::ShellView;
#[cfg(not(target_os = "android"))]
use super::icons::Logo;
use super::icons::{Icon, Svg, initial, item_hue, kind_icon};
use super::{items, pages};
use crate::controller::{AppError, Controller, FormEpoch};
use crate::controller::{Mode, SwitchTo};
use crate::prefs::Theme;
use crate::views;
use crate::workspace::{ConfirmKind, Pane, Report, Screen, WsAction, WsField};
use dioxus::prelude::*;
use zeroize::Zeroizing;

pub(crate) fn go(c: &Controller, e: FormEpoch, s: Screen) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| c.navigate(e, s.clone())
}
pub(crate) fn act(c: &Controller, e: FormEpoch, a: WsAction) -> impl FnMut(MouseEvent) + 'static {
    let c = c.clone();
    move |_| c.act(e, a.clone())
}

/// The app's own title bar on desktop: drag, double-click to maximize,
/// window buttons, theme, the command bar and Lock with its idle ring.
#[component]
pub(crate) fn TitleBar(
    controller: Option<Controller>,
    epoch: FormEpoch,
    unlocked: bool,
    idle_left: u64,
    busy: bool,
    palette: Option<Signal<bool>>,
    vault: Option<String>,
    #[props(default)] idle_only: bool,
) -> Element {
    #[cfg(target_os = "android")]
    {
        let _ = (
            controller, epoch, unlocked, idle_left, busy, palette, vault, idle_only,
        );
        rsx! {}
    }
    #[cfg(not(target_os = "android"))]
    {
        let mut switcher = use_signal(|| false);
        let window = dioxus_desktop::use_window();
        let drag = {
            let w = window.clone();
            move |e: MouseEvent| {
                if e.trigger_button() == Some(dioxus::html::input_data::MouseButton::Primary) {
                    w.drag();
                }
            }
        };
        let maximize = {
            let w = window.clone();
            move |_| w.toggle_maximized()
        };
        let theme = controller.as_ref().map_or(Theme::Dark, Controller::theme);
        let next = if theme == Theme::Light {
            Theme::Dark
        } else {
            Theme::Light
        };
        let offset = 66.0 - 66.0 * (idle_left.min(60) as f64) / 60.0;
        rsx! {
            div { class: "titlebar", onmousedown: drag.clone(), ondoubleclick: maximize.clone(),
                if unlocked && let Some(c) = controller.clone() {
                    // The vault name opens the vault switcher (0009 §1.8). It
                    // must not start a window drag or maximize.
                    div { class: "pop-anchor", onmousedown: |e| e.stop_propagation(), ondoubleclick: |e| e.stop_propagation(),
                        onkeydown: move |e: KeyboardEvent| { if e.key() == Key::Escape && switcher() { e.stop_propagation(); switcher.set(false); } },
                        button { class: "brand", id: "vault-switch", title: "Switch vault", disabled: busy, "aria-haspopup": "menu",
                            "aria-expanded": if switcher() { "true" } else { "false" },
                            onclick: move |_| switcher.set(!switcher()),
                            Logo { class: "logo-bar" }
                            b { "{crate::views::z(&vault.clone().unwrap_or_default()).as_str()}" }
                            Svg { icon: Icon::ChevronDown }
                        }
                        if switcher() && !busy { VaultSwitcher { controller: c, epoch, open: switcher } }
                    }
                } else {
                    div { class: "brand", Logo { class: "logo-bar" } b { "QuickVault" } }
                }
                div { class: "drag" }
                if let Some(mut p) = palette {
                    button { class: "cmd", id: "command-bar", disabled: busy, onmousedown: |e| e.stop_propagation(), onclick: move |_| p.set(true),
                        Svg { icon: Icon::Search } span { "Search or run a command" } kbd { "Ctrl K" }
                    }
                }
                div { class: "drag" }
                if let Some(c) = controller.clone() {
                    button { class: "tb-btn", id: "theme-toggle", title: "Switch to {next.name()} theme", "aria-label": "Switch theme",
                        onmousedown: |e| e.stop_propagation(),
                        onclick: move |_| { if let Err(e) = c.set_theme(next) { c.report(epoch, e); } c.touch(); },
                        Svg { icon: if theme == Theme::Light { Icon::Moon } else { Icon::Sun } }
                    }
                }
                if unlocked && let Some(c) = controller.clone() {
                    // Without screen-lock/sleep detection (0008 §1.4) the lock
                    // carries a lasting mark and says so, instead of a banner.
                    button { class: if idle_only { "tb-btn lock-button idle-only" } else { "tb-btn lock-button" }, id: "lock",
                        title: if idle_only { "Lock now (Ctrl L). Locks after 60 s without activity. This system does not report screen lock or sleep, so they do not lock QuickVault." } else { "Lock now (Ctrl L). Locks after 60 s without activity, and when the screen locks or the device sleeps." },
                        "aria-label": if idle_only { "Lock. Screen lock and sleep do not lock QuickVault on this system." } else { "Lock" },
                        "data-qv-clear": "true", onmousedown: |e| e.stop_propagation(), onclick: move |_| c.lock(),
                        Svg { icon: Icon::Lock }
                        if idle_only { span { class: "lock-mark", "aria-hidden": "true" } }
                        svg { class: "ring", view_box: "0 0 26 24", "aria-hidden": "true",
                            circle { class: "track", cx: "13", cy: "12", r: "10.5" }
                            circle { class: "left", cx: "13", cy: "12", r: "10.5", stroke_dasharray: "66", stroke_dashoffset: "{offset:.1}" }
                        }
                    }
                }
                div { class: "winctl", onmousedown: |e| e.stop_propagation(),
                    button { "aria-label": "Minimize", title: "Minimize", onclick: { let w = window.clone(); move |_| w.set_minimized(true) }, Svg { icon: Icon::Minimize } }
                    button { "aria-label": "Maximize", title: "Maximize", onclick: maximize, Svg { icon: Icon::Maximize } }
                    button { class: "close", "aria-label": "Close", title: "Close", onclick: { let w = window.clone(); move |_| w.close() }, Svg { icon: Icon::Close } }
                }
            }
        }
    }
}

/// The vault switcher under the title bar's vault name (0009 §1.8; phones
/// use Settings' "Switch vault"): one vault is open at a time, so every
/// choice locks this one first and opens the locked screen on the choice.
/// While a form holds unsaved input the choices are disabled instead.
#[cfg(not(target_os = "android"))]
#[component]
pub(crate) fn VaultSwitcher(
    controller: Controller,
    epoch: FormEpoch,
    open: Signal<bool>,
) -> Element {
    let vaults = controller.vaults();
    let current = controller.open_vault().map(|v| v.path);
    let editing = controller.screen(epoch).is_some_and(|s| s.is_form());
    let mut close = move || open.set(false);
    let switch = |to: SwitchTo| {
        let c = controller.clone();
        move |_| {
            open.set(false);
            c.switch_vault(epoch, to.clone());
        }
    };
    rsx! {
        button { class: "pop-scrim", "aria-label": "Close menu", tabindex: "-1", onclick: move |_| close() }
        div { class: "menu pop switcher", role: "menu", "aria-label": "Vaults",
            div { class: "label", "VAULTS" }
            for v in vaults {
                if current.as_ref() == Some(&v.path) {
                    button { class: "mi on", role: "menuitemradio", "aria-checked": "true", onclick: move |_| close(),
                        Svg { icon: Icon::Lock }
                        span { class: "vault-mi", b { "{crate::views::z(&v.name).as_str()}" } small { "Open · {crate::views::z(&v.place).as_str()}" } }
                        span { class: "sub", Svg { icon: Icon::Check } }
                    }
                } else {
                    button { class: "mi", role: "menuitemradio", "aria-checked": "false", disabled: editing, onclick: switch(SwitchTo::Vault(v.path.clone())),
                        Svg { icon: Icon::Lock }
                        span { class: "vault-mi", b { "{crate::views::z(&v.name).as_str()}" } small { if v.exists { "{crate::views::z(&v.place).as_str()}" } else { "Not found · {crate::views::z(&v.place).as_str()}" } } }
                    }
                }
            }
            hr {}
            button { class: "mi", id: "switch-create", disabled: editing, onclick: switch(SwitchTo::Mode(Mode::Create)), Svg { icon: Icon::Plus } "Create a new vault" }
            button { class: "mi", id: "switch-join", disabled: editing, onclick: switch(SwitchTo::Mode(Mode::Join)), Svg { icon: Icon::Qr } "Join from another device" }
            p { class: "note", if editing { "Save or cancel your changes to switch vaults." } else { "Switching locks this vault." } }
        }
    }
}

/// A vault's colour, from its name (vault names are not secret, 0009 §1.8).
pub(crate) fn vault_hue(name: &str) -> &'static str {
    let n = name
        .bytes()
        .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(u32::from(b)));
    super::icons::hue_class((n % 12) as u8)
}

/// The phone vault switcher (0009 §1.8, plan 0045): a sheet of vault cards.
/// The open vault's card locks it; any other card locks this one and opens
/// the locked screen on that vault, with its quick-unlock prompt if it has
/// one. Disabled while a form holds unsaved input, as on the desktop.
#[component]
pub(crate) fn VaultCards(controller: Controller, epoch: FormEpoch, open: Signal<bool>) -> Element {
    let vaults = controller.vaults();
    let current = controller.open_vault().map(|v| v.path);
    let editing = controller.screen(epoch).is_some_and(|s| s.is_form());
    // The open vault's header is held by its session, so its mark is
    // inferred: an enrollment that matches no other listed vault.
    let quick: Vec<bool> = vaults
        .iter()
        .map(|v| {
            current.as_ref() != Some(&v.path) && v.exists && controller.quick_ready_for(&v.path)
        })
        .collect();
    let open_quick = controller.quick_policy().is_some() && !quick.contains(&true);
    let mut close = move || open.set(false);
    let switch = |to: SwitchTo| {
        let c = controller.clone();
        move |_| {
            open.set(false);
            c.switch_vault(epoch, to.clone());
        }
    };
    let lock = {
        let c = controller.clone();
        move |_| {
            open.set(false);
            c.lock();
        }
    };
    rsx! {
        div { class: "layer vault-sheet",
            button { class: "scrim", "aria-label": "Close", onclick: move |_| close() }
            div { class: "dialog", role: "dialog", "aria-modal": "true", "aria-label": "Vaults", tabindex: "-1", autofocus: true,
                div { class: "grab", "aria-hidden": "true" }
                h3 { "Vaults" }
                div { class: "vcards",
                    for (v, has_quick) in vaults.into_iter().zip(quick) {
                        if current.as_ref() == Some(&v.path) {
                            div { class: "vcard on", id: "vcard-open",
                                span { class: "tile {vault_hue(&v.name)}", "{initial(&v.name)}" }
                                span { class: "l", b { "{crate::views::z(&v.name).as_str()}" }
                                    small { span { class: "live" } if open_quick { "Open · fingerprint unlock" } else { "Open now" } }
                                }
                                button { class: "btn", id: "vcard-lock", "data-qv-clear": "true", onclick: lock.clone(), Svg { icon: Icon::Lock } "Lock" }
                            }
                        } else {
                            button { class: "vcard", disabled: editing || !v.exists, onclick: switch(SwitchTo::Vault(v.path.clone())),
                                span { class: "tile {vault_hue(&v.name)}", "{initial(&v.name)}" }
                                span { class: "l", b { "{crate::views::z(&v.name).as_str()}" }
                                    small { if !v.exists { "Not found" } else if has_quick { "Fingerprint unlock" } else { "Master password" } }
                                }
                                if has_quick { span { class: "vq", "aria-hidden": "true", Svg { icon: Icon::Finger } } }
                                Svg { icon: Icon::Right }
                            }
                        }
                    }
                }
                div { class: "vmore",
                    button { class: "vact", id: "sheet-create", disabled: editing, onclick: switch(SwitchTo::Mode(Mode::Create)), span { class: "ci", Svg { icon: Icon::Plus } } "New vault" }
                    button { class: "vact", id: "sheet-join", disabled: editing, onclick: switch(SwitchTo::Mode(Mode::Join)), span { class: "ci", Svg { icon: Icon::Qr } } "Join a device" }
                }
                p { class: "note", if editing { "Save or cancel your changes to switch vaults." } else { "Switching locks the open vault." } }
            }
        }
    }
}

/// Edge and corner handles for resizing a window without OS decorations.
#[component]
pub(crate) fn ResizeHandles() -> Element {
    #[cfg(target_os = "android")]
    {
        rsx! {}
    }
    #[cfg(not(target_os = "android"))]
    {
        use dioxus_desktop::tao::window::ResizeDirection as D;
        let window = dioxus_desktop::use_window();
        let edges = [
            ("rz rz-n", D::North),
            ("rz rz-s", D::South),
            ("rz rz-e", D::East),
            ("rz rz-w", D::West),
            ("rz rz-ne", D::NorthEast),
            ("rz rz-nw", D::NorthWest),
            ("rz rz-se", D::SouthEast),
            ("rz rz-sw", D::SouthWest),
        ];
        rsx! {
            for (class, dir) in edges {
                div { class, "aria-hidden": "true",
                    onmousedown: { let w = window.clone(); move |_| { if !w.window.is_maximized() { let _ = w.window.drag_resize_window(dir); } } }
                }
            }
        }
    }
}

/// The unlocked shell. Vault screens show a list beside the detail; other
/// sections fill the content area.
#[component]
pub(crate) fn Shell(controller: Controller, view: ShellView, palette: Signal<bool>) -> Element {
    let epoch = view.epoch;
    let revision = view.revision;
    let fallback = use_signal(|| false);
    let mut sheet = try_use_context::<super::VaultSheet>().map_or(fallback, |v| v.0);
    let Some(screen) = controller.screen(epoch) else {
        return rsx! {};
    };
    let fixture = super::is_fixture(&controller);
    // The last data stays on screen while an operation owns the vault.
    let overview = super::use_last(controller.read(epoch, views::overview)).and_then(Result::ok);
    let root = super::use_last(controller.read(epoch, |s| s.root())).and_then(Result::ok);
    let (group_owner, group_read) = super::use_page(
        &controller,
        epoch,
        crate::page_read::Lane::Groups,
        0,
        crate::page_read::Spec::Groups {
            parent: root,
            query: Zeroizing::new(String::new()),
        },
    );
    let (kind_owner, kind_read) = super::use_page(
        &controller,
        epoch,
        crate::page_read::Lane::Kinds,
        0,
        crate::page_read::Spec::Kinds,
    );
    let group_page = group_read.as_ref().and_then(|r| r.page.clone());
    let kind_page = kind_read.as_ref().and_then(|r| r.page.clone());
    let groups = match group_page.as_deref().map(|p| &p.rows) {
        Some(crate::page_read::Rows::Groups(groups)) => groups.as_slice(),
        _ => &[],
    };
    let kinds = match kind_page.as_deref().map(|p| &p.rows) {
        Some(crate::page_read::Rows::Kinds(kinds)) => kinds.as_slice(),
        _ => &[],
    };
    let recovered = overview.as_ref().map_or(0, |o| o.recovered);
    let total_items = overview.as_ref().map_or(0, |o| o.entries);
    let context = controller
        .list_context(epoch)
        .unwrap_or(Screen::Browse(None));
    let vault_screen = screen.is_list() || screen.is_vault_detail();
    let (notice, error, report) = controller.status(epoch).unwrap_or((None, None, None));
    let undo = controller.peek(epoch, |ws| ws.undo.clone()).flatten();
    let pending = controller.pending(epoch);
    let busy = view.busy;
    let live = view.live;
    let new_in = match &context {
        Screen::Browse(Some(g)) => Some(*g),
        _ => root,
    };
    let nav_class = |on: bool| if on { "nav on" } else { "nav" };
    let section_on = |s: &Screen| match (s, &screen) {
        (Screen::Settings(_), Screen::Settings(_) | Screen::More) => true,
        (Screen::Conflicts, Screen::ConflictRecord(_)) => true,
        (Screen::Snapshots, Screen::Snapshots) | (Screen::Archives, Screen::Archives) => true,
        (a, b) => a == b,
    };
    let tab_on = |t: &Screen| match t {
        Screen::Browse(_) => vault_screen,
        Screen::Settings(_) => matches!(
            screen,
            Screen::Settings(_)
                | Screen::More
                | Screen::Trash
                | Screen::Conflicts
                | Screen::ConflictRecord(_)
                | Screen::Snapshots
                | Screen::Archives
                | Screen::Autofill
        ),
        other => *other == screen,
    };
    let trash = overview.as_ref().map_or(0, |o| o.trash);
    let conflicts = overview.as_ref().map_or(0, |o| o.conflicts);
    let new_entry = {
        let c = controller.clone();
        move |_| {
            if let Some(g) = new_in {
                c.act(epoch, WsAction::NewEntry(g));
            }
        }
    };
    let tabs = [
        (Screen::Browse(None), "Vault", Icon::All, "tab-vault"),
        (
            Screen::Generator,
            "Generator",
            Icon::Generator,
            "tab-generator",
        ),
        // "Sync": there are no device links any more, only syncing (plan 0045).
        (Screen::Devices, "Sync", Icon::Refresh, "tab-devices"),
        (
            Screen::Settings(Pane::Overview),
            "Settings",
            Icon::Settings,
            "tab-settings",
        ),
    ];
    let tools = [
        (
            Screen::Generator,
            "Generator",
            Icon::Generator,
            "nav-generator",
            0usize,
        ),
        (Screen::Devices, "Sync", Icon::Refresh, "nav-devices", 0),
        (Screen::Trash, "Trash", Icon::Trash, "nav-trash", trash),
        (
            Screen::Conflicts,
            "Conflicts",
            Icon::Conflicts,
            "nav-conflicts",
            conflicts,
        ),
    ];
    let all_on = vault_screen && context == Screen::Browse(None);
    rsx! {
        if fixture && cfg!(target_os = "android") { p { class: "banner inset", "Synthetic validation build · isolated test vault only" } }
        if overview.as_ref().is_some_and(|o| o.anchor_warning) {
            p { class: "banner inset", role: "status", "The rollback record may be copied or rolled back with this vault. Keep it in independent private device storage." }
        }
        // `inert` is not a Dioxus boolean attribute: a false value would still
        // render `inert="false"` and block the pointer, so omit it instead.
        div { class: if vault_screen { "shell" } else { "shell nolist" }, inert: pending.is_some().then_some("true"),
            nav { class: "side", "aria-label": "Vault",
                button { class: nav_class(all_on), id: "nav-all", title: "All items", disabled: busy, onclick: go(&controller, epoch, Screen::Browse(None)),
                    Svg { icon: Icon::All } span { class: "t", "All items" } span { class: "n", "{total_items}" }
                }
                if !kinds.is_empty() { div { class: "h", "TYPES" } }
                for kind in kinds.iter().cloned() {
                    { let k = kind.kind; let n = kind.count; rsx! {
                    button { class: nav_class(vault_screen && context == Screen::Kind(k.clone())), title: "{kind_label(&k)}", disabled: busy,
                        onclick: go(&controller, epoch, Screen::Kind(k.clone())),
                        Svg { icon: kind_icon(&k) } span { class: "t", "{kind_label(&k)}" } span { class: "n", "{n}" }
                    }
                    } }
                }
                if let (Some(owner), Some(read)) = (kind_owner, kind_read.clone()) {
                    super::PageNav { controller: controller.clone(), epoch, owner, read }
                }
                div { class: "h", "GROUPS"
                    if let Some(r) = root {
                        button { title: "New group", "aria-label": "New group", disabled: busy, onclick: act(&controller, epoch, WsAction::NewGroup(r)), Svg { icon: Icon::Plus } }
                    }
                }
                for g in groups.iter().cloned() {
                    button { class: nav_class(vault_screen && context == Screen::Browse(Some(g.handle))), title: "{g.name.as_str()}", disabled: busy,
                        onclick: go(&controller, epoch, Screen::Browse(Some(g.handle))),
                        span { class: "dot {item_hue(g.colour, &g.handle.id_hex())}" } span { class: "t", "{g.name.as_str()}" } span { class: "n", "{g.entries}" }
                    }
                }
                if let (Some(owner), Some(read)) = (group_owner, group_read.clone()) {
                    super::PageNav { controller: controller.clone(), epoch, owner, read }
                }
                if recovered > 0 {
                    button { class: nav_class(vault_screen && context == Screen::Recovered), title: "Recovered items", disabled: busy, onclick: go(&controller, epoch, Screen::Recovered),
                        Svg { icon: Icon::Restore } span { class: "t", "Recovered items" } span { class: "n", "{recovered}" }
                    }
                }
                div { class: "h", "TOOLS" }
                for (target, label, icon, id, count) in tools {
                    if label != "Conflicts" || count > 0 || screen == Screen::Conflicts {
                        button { class: nav_class(section_on(&target)), id, title: label, disabled: busy, onclick: go(&controller, epoch, target.clone()),
                            Svg { icon } span { class: "t", "{label}" }
                            if count > 0 { span { class: "badge", "{count}" } }
                        }
                    }
                }
                div { class: "grow" }
                button { class: nav_class(section_on(&Screen::Settings(Pane::Overview))), id: "nav-settings", title: "Settings", disabled: busy,
                    onclick: go(&controller, epoch, Screen::Settings(Pane::Overview)),
                    Svg { icon: Icon::Settings } span { class: "t", "Settings" }
                }
            }
            if vault_screen {
                items::ListPane { controller: controller.clone(), epoch, revision, list: context.clone(), screen: screen.clone(), busy, conflicts }
                items::Detail { controller: controller.clone(), epoch, revision, screen: screen.clone(), live, busy, report: report.clone() }
            } else {
                pages::Page { controller: controller.clone(), epoch, revision, screen: screen.clone(), live, busy, report: report.clone() }
            }
        }
        if vault_screen && screen.is_list() && !busy {
            button { class: "fab", "aria-label": "New item", onclick: new_entry, Svg { icon: Icon::Plus } }
        }
        nav { class: "tabbar", "aria-label": "Sections", inert: pending.is_some().then_some("true"),
            for (target, label, icon, id) in tabs {
                button { class: if tab_on(&target) { "on" } else { "" }, id, disabled: busy,
                    // Holding the Vault tab (app.js sends it as a Ctrl-click)
                    // opens the vault switcher (plan 0045).
                    onclick: { let mut f = go(&controller, epoch, target.clone()); let vault = id == "tab-vault"; move |e: MouseEvent| { if vault && e.modifiers().ctrl() { sheet.set(true); } else { f(e) } } },
                    i { Svg { icon } } "{label}"
                }
            }
        }
        if view.busy_shown && controller.lan_view(epoch).is_none() && !view.scanning {
            div { class: "toasts", div { class: "toast busy-toast", role: "status", "Working… other actions wait until this finishes." } }
        }
        pages::LanPanel { controller: controller.clone(), epoch, revision, seconds: view.lan_seconds }
        if view.scanning { pages::ScanPanel { controller: controller.clone(), epoch } }
        if sheet() && !busy { VaultCards { controller: controller.clone(), epoch, open: sheet } }
        if let Some(p) = controller.peek(epoch, |ws| ws.preview.clone()).flatten() {
            for k in [p.handle.version_hex()] {
                super::items::Viewer { key: "{k}", controller: controller.clone(), epoch, preview: p.clone() }
            }
        }
        if let Some(kind) = pending.filter(|_| !busy) {
            Confirm { controller: controller.clone(), epoch, kind, seconds: live.weak_seconds }
        }
        if !busy {
            div { class: "toasts",
                if live.clipboard > 0 {
                    div { class: "toast", role: "status", Svg { icon: Icon::Copy } span { "Copied · clears in {live.clipboard} s" }
                        span { class: "bar w{live.clipboard.div_ceil(2)}" }
                    }
                }
                if let Some(e) = error {
                    div { class: "toast bad", role: "alert", Svg { icon: Icon::Warn } span { class: "error", "{e.message()}" }
                        button { onclick: act(&controller, epoch, WsAction::Dismiss), "Dismiss" }
                    }
                }
                if let Some(n) = notice {
                    div { class: "toast", role: "status", Svg { icon: Icon::Check } span { class: "notice", "{n}" }
                        if let Some(u) = undo { button { id: "toast-undo", onclick: act(&controller, epoch, u.action()), "Undo" } }
                        button { "aria-label": "Dismiss", onclick: act(&controller, epoch, WsAction::Dismiss), Svg { icon: Icon::Close } }
                    }
                }
            }
        }
        if palette() && !busy {
            Palette { controller: controller.clone(), epoch, revision, palette, root, theme: controller.theme() }
        }
        if fixture { input { id: "validation-result", "data-fixture-root": controller.0.base.to_string_lossy().as_ref(), "data-peer-opened": super::fixture_peer_opened().to_string(), oninput: super::fixture_report(&controller) } }
    }
}

/// A sidebar label for a type hint.
pub(crate) fn kind_label(kind: &str) -> String {
    match kind {
        "login" => "Logins".into(),
        "note" => "Notes".into(),
        "card" => "Cards".into(),
        "wifi" => "Wi-Fi".into(),
        other => {
            let mut c = other.chars();
            c.next()
                .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
                .unwrap_or_default()
        }
    }
}

#[derive(Clone, PartialEq)]
enum Command {
    Open(Screen),
    New,
    Theme,
    Lock,
}
/// The command bar: items through the existing search and commands for
/// existing actions only (plan 0040 R7).
#[component]
fn Palette(
    controller: Controller,
    epoch: FormEpoch,
    revision: u64,
    palette: Signal<bool>,
    root: Option<qv_core::GroupHandle>,
    theme: Theme,
) -> Element {
    let _ = revision;
    let mut palette = palette;
    let query = controller
        .peek(epoch, |ws| {
            String::from_utf8_lossy(ws.input(WsField::Command)).into_owned()
        })
        .map(Zeroizing::new)
        .unwrap_or_default();
    let echo = items::use_echo(&query);
    let (shown, generation) = echo.borrow_mut().sync(&query);
    let (owner, read) = super::use_page(
        &controller,
        epoch,
        crate::page_read::Lane::Main,
        2,
        crate::page_read::Spec::Search(query.clone()),
    );
    let page = read.as_ref().and_then(|r| r.page.clone());
    let (groups, hits) = match page.as_deref().map(|p| &p.rows) {
        Some(crate::page_read::Rows::Search { groups, entries }) => {
            (groups.as_slice(), entries.as_slice())
        }
        _ => (&[][..], &[][..]),
    };
    let commands: Vec<(&'static str, Icon, Command, &'static str)> = vec![
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
            Command::Open(Screen::Settings(Pane::Verify)),
            "",
        ),
        (
            "Change master password",
            Icon::Key,
            Command::Open(Screen::Settings(Pane::Password)),
            "",
        ),
        (
            "Show recovery phrase",
            Icon::Note,
            Command::Open(Screen::Settings(Pane::Phrase)),
            "",
        ),
        (
            "Settings",
            Icon::Settings,
            Command::Open(Screen::Settings(Pane::Overview)),
            "",
        ),
        (
            if theme == Theme::Light {
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
    let q = query.to_lowercase();
    let commands: Vec<_> = commands
        .into_iter()
        .filter(|c| q.is_empty() || c.0.to_lowercase().contains(q.as_str()))
        .collect();
    let run = {
        let c = controller.clone();
        move |cmd: Command| {
            palette.set(false);
            match cmd {
                Command::Open(s) => c.navigate(epoch, s),
                Command::New => {
                    if let Some(r) = root {
                        c.act(epoch, WsAction::NewEntry(r));
                    }
                }
                Command::Theme => {
                    let next = if theme == Theme::Light {
                        Theme::Dark
                    } else {
                        Theme::Light
                    };
                    if let Err(e) = c.set_theme(next) {
                        c.report(epoch, e);
                    }
                    c.touch();
                }
                Command::Lock => c.lock(),
            }
        }
    };
    let first: Option<Command> = hits
        .first()
        .map(|e| Command::Open(Screen::Entry(e.handle)))
        .or_else(|| commands.first().map(|c| c.2.clone()));
    rsx! {
        div { class: "layer",
            button { class: "scrim", "aria-label": "Close command bar", onclick: move |_| palette.set(false) }
            div { class: "palette", role: "dialog", "aria-label": "Command bar",
                div { class: "q",
                    Svg { icon: Icon::Search, large: true }
                    for g in [generation] {
                        input { key: "{g}", id: "palette-input", autofocus: true, placeholder: "Search items, or type a command", maxlength: crate::workspace::QUERY_MAX,
                            autocomplete: "off", spellcheck: "false", "data-qv-controlled": "true", initial_value: shown.as_str(), "aria-label": "Search",
                            oninput: { let c = controller.clone(); let echo = echo.clone(); move |e: FormEvent| { let mut v = e.value(); echo.borrow_mut().typed(&v); c.ws_input(epoch, WsField::Command, &mut v); } },
                            onkeydown: { let mut run = run.clone(); let first = first.clone(); move |e: KeyboardEvent| { if e.key() == Key::Enter { e.prevent_default(); if let Some(cmd) = first.clone() { run(cmd); } } } }
                        }
                    }
                    kbd { "Esc" }
                }
                div { class: "res",
                    if !hits.is_empty() { div { class: "grp", "ITEMS" } }
                    for e in hits.iter().cloned() {
                        button { class: "it", onclick: { let mut run = run.clone(); let h = e.handle; move |_| run(Command::Open(Screen::Entry(h))) },
                            span { class: "tile {item_hue(e.colour, &e.handle.id_hex())}", "{initial(&e.title)}" }
                            span { "{e.title.as_str()}" } small { "{e.subtitle.as_str()}" }
                        }
                    }
                    if !groups.is_empty() { div { class: "grp", "GROUPS" } }
                    for g in groups {
                        button { class: "it", onclick: { let mut run = run.clone(); let h = g.handle; move |_| run(Command::Open(Screen::Browse(Some(h)))) },
                            span { class: "ic", Svg { icon: Icon::Folder } } span { "{g.name.as_str()}" }
                        }
                    }
                    if let (Some(owner), Some(read)) = (owner, read) { super::PageNav { controller: controller.clone(), epoch, owner, read } }
                    if !commands.is_empty() { div { class: "grp", "COMMANDS" } }
                    for (label, icon, cmd, keys) in commands {
                        button { class: "it", onclick: { let mut run = run.clone(); move |_| run(cmd.clone()) },
                            span { class: "ic", Svg { icon } } span { "{label}" } small { "{keys}" }
                        }
                    }
                    if hits.is_empty() && !q.is_empty() { p { class: "muted pad-sm", "Items match titles, usernames, websites and group names. Protected values are never searched." } }
                }
                div { class: "foot2", span { "Enter to open the first result" } span { "Esc to close" } }
            }
        }
    }
}

/// A modal confirmation. Escape and Cancel answer "no"; it never defaults to yes.
#[component]
pub(crate) fn Confirm(
    controller: Controller,
    epoch: FormEpoch,
    kind: ConfirmKind,
    seconds: u64,
) -> Element {
    let message = match kind {
        ConfirmKind::DeleteRecursive => "Move this group and everything in it to the trash?".to_owned(),
        ConfirmKind::EmptyTrash => "Permanently delete every non-conflicted item in the trash? A recovery snapshot is taken first. Independent copies may remain.".to_owned(),
        ConfirmKind::PurgeExpired(false) => "Permanently delete the trash items past their retention period? A recovery snapshot is taken first.".to_owned(),
        ConfirmKind::PurgeExpired(true) => "Vault dates are ahead of this device's clock, so expiry may be wrong. Check the clock first. Permanently delete the expired items anyway?".to_owned(),
        ConfirmKind::PurgeHistory => "Purge this entry's local history? Active versions remain. Snapshots, unseen concurrent history and independent copies may remain; there is no secure erasure.".to_owned(),
        ConfirmKind::RemoveAttachment => "Permanently remove this attachment? Independent copies may remain; there is no secure erasure.".to_owned(),
        ConfirmKind::SaveAttachment => "Write this attachment's plaintext to the chosen file? It is not encrypted there, and a failure may leave incomplete plaintext.".to_owned(),
        ConfirmKind::SelfContained => "Include the password slot? Anyone holding this file can try offline master-password guessing, and a later password change does not revoke it.".to_owned(),
        ConfirmKind::Resolve(false) => "Create a new complete version from this choice, covering every version shown? Edits not seen here may still conflict.".to_owned(),
        ConfirmKind::Resolve(true) => "This choice permanently deletes the record's payload and history. Independent copies may remain. Create this resolution?".to_owned(),
        ConfirmKind::RestoreConflicts => "Restore this version and resolve the entry's current conflict with it?".to_owned(),
        ConfirmKind::OverBudget(n) => format!("The mandatory recovery snapshot needs {n} bytes and exceeds the snapshot budget. Allow it to exceed the budget? Nothing changes otherwise."),
        ConfirmKind::OldSnapshots(n) => format!("{n} local snapshots were taken before this password change and still open with the old password. Delete them? Copies elsewhere remain; deletion is not cryptographic erasure."),
        ConfirmKind::LinkApp => "Link this app to the entry? QuickVault verified the app's package and signing certificate, but cannot tell whether the app belongs to the service. Link only an app you trust.".to_owned(),
        ConfirmKind::ReducedQuick => "Lower protection: your screen lock PIN, pattern or password would open this vault, so anyone who knows it could too. Use it instead of your fingerprint? Fingerprint unlock never falls back to it by itself.".to_owned(),
        ConfirmKind::WeakPassword => "This password is weak and could be guessed by an attacker who obtains your vault file. Use it anyway?".to_owned(),
    };
    let weak = kind == ConfirmKind::WeakPassword;
    rsx! {
        div { class: "layer",
            button { class: "scrim", "aria-label": "Cancel", onclick: act(&controller, epoch, WsAction::Answer(false)) }
            div { class: "dialog", role: "alertdialog", "aria-modal": "true", "aria-label": "Confirmation",
                h3 { if weak { "Weak password" } else { "Are you sure?" } }
                p { "{message}" }
                div { class: "actions",
                    button { class: "btn subtle", id: "confirm-cancel", autofocus: true, onclick: act(&controller, epoch, WsAction::Answer(false)), if weak { "Choose a stronger password" } else { "Cancel" } }
                    button { class: "btn danger", id: "confirm-continue", "data-qv-clear": "true", disabled: weak && seconds > 0, onclick: act(&controller, epoch, WsAction::Answer(true)), if weak { "Use anyway · {seconds}s" } else { "Continue" } }
                }
            }
        }
    }
}

/// The result of a finished task (merge, export, verify, purge).
#[component]
pub(crate) fn ReportCard(controller: Controller, epoch: FormEpoch, report: Report) -> Element {
    let (ok, lines): (bool, Vec<String>) = match &report {
        Report::Merge {
            accepted,
            conflicts,
            incomplete,
        } => (
            !incomplete,
            vec![
                if *accepted {
                    "Archive merged: a new local acceptance was committed.".into()
                } else {
                    "This archive was already accepted.".into()
                },
                format!("Conflicts now: {conflicts}"),
                if *incomplete {
                    "Completion reporting failed after the durable acceptance; check the vault before retrying.".into()
                } else {
                    String::new()
                },
            ],
        ),
        Report::Export {
            id,
            self_contained,
            incomplete,
        } => (
            !incomplete,
            vec![
                format!("Archive published: {id}"),
                if *self_contained {
                    "It includes the password slot.".into()
                } else {
                    "It opens only with this vault's key (another device or the recovery phrase)."
                        .into()
                },
                if *incomplete {
                    "Crash durability is unconfirmed because publication completion failed.".into()
                } else {
                    String::new()
                },
            ],
        ),
        Report::Resolved {
            conflicts,
            incomplete,
        } => (
            !incomplete,
            vec![
                format!("Resolution committed. Conflicts now: {conflicts}"),
                if *incomplete {
                    "Completion reporting failed after durable publication.".into()
                } else {
                    String::new()
                },
            ],
        ),
        Report::Verify {
            ok,
            anchor,
            objects,
            bytes,
            records,
            notes,
        } => {
            let mut v = vec![
                if *ok {
                    "Integrity check passed.".to_owned()
                } else {
                    "Integrity check FAILED. Keep the original file and recover from a verified backup.".to_owned()
                },
                format!("External anchor: {anchor}"),
                format!("{objects} objects ({bytes} bytes) re-hashed; {records} records checked"),
            ];
            v.extend(notes.iter().map(|n| format!("Note: {n}")));
            (*ok, v)
        }
        Report::Purged { purged, kept } => (
            true,
            vec![
                format!("{purged} item(s) permanently deleted."),
                if *kept > 0 {
                    format!("{kept} conflicted item(s) kept in the trash.")
                } else {
                    String::new()
                },
            ],
        ),
    };
    rsx! {
        div { class: if ok { "banner ok report" } else { "banner bad report" }, role: "status",
            Svg { icon: if ok { Icon::Check } else { Icon::Warn } }
            div { class: "sp", for l in lines.into_iter().filter(|l| !l.is_empty()) { p { "{l}" } } }
            button { class: "link", onclick: act(&controller, epoch, WsAction::Dismiss), "Dismiss" }
        }
    }
}

/// A placeholder for unreadable or loading content.
#[component]
pub(crate) fn Unreadable(error: Option<AppError>) -> Element {
    let message = error.map_or("Loading…", AppError::message);
    rsx! { div { class: "empty", p { "{message}" } } }
}
