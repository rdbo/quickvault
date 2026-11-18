// SPDX-License-Identifier: AGPL-3.0-or-later

//! The QuickVault page (plan 0071): Leptos, client-side rendering, wasm32.
//! It renders frames built in Rust and sends typed actions back; it holds
//! only what the screen shows. The DOM, classes and ids are the ones
//! `app.css`, `app.js` and `player.js` expect.
mod bridge;
mod editor;
mod icons;
mod input;
mod items;
mod locked;
mod pages;
mod shell;

use icons::{Icon, Logo, Svg};
use leptos::prelude::*;
use qv_ui_api::{Act, Body, Field, Frame, PageNav, Platform, Request, Secret, WindowOp};
use wasm_bindgen::prelude::*;

/// The page's handle on the current frame and the bridge.
#[derive(Clone, Copy)]
pub(crate) struct Ui {
    frame: RwSignal<Option<Frame>>,
}

impl Ui {
    fn epoch(self) -> u64 {
        self.frame
            .with_untracked(|f| f.as_ref().map_or(0, |f| f.epoch))
    }
    /// Sends an action.
    pub(crate) fn act(self, act: Act) {
        bridge::enqueue(self.epoch(), Request::Act { act });
    }
    /// Moves an input's whole value to Rust (it is wiped here after sending).
    pub(crate) fn input(self, field: Field, value: &str) {
        if let Ok(value) = Secret::new(value.as_bytes()) {
            bridge::enqueue(self.epoch(), Request::Input { field, value });
        }
    }
    /// A key the page did not handle.
    pub(crate) fn key(self, key: String, ctrl: bool) {
        bridge::enqueue(self.epoch(), Request::Key { key, ctrl });
    }
    /// User activity.
    pub(crate) fn activity(self) {
        bridge::enqueue(self.epoch(), Request::Activity);
    }
    /// Turns a paged list.
    pub(crate) fn page_turn(self, nav: &PageNav, forward: bool) {
        bridge::enqueue(
            self.epoch(),
            Request::PageTurn {
                slot: nav.slot.clone(),
                serial: nav.serial,
                forward,
            },
        );
    }
    /// A window operation.
    pub(crate) fn window(self, op: WindowOp) {
        bridge::enqueue(self.epoch(), Request::Window { op });
    }
    /// The platform.
    pub(crate) fn platform(self) -> Platform {
        self.frame
            .with_untracked(|f| f.as_ref().map_or(Platform::Linux, |f| f.platform))
    }
    /// A memoized slice of the frame: it notifies only when it changes.
    pub(crate) fn sel<T: PartialEq + Clone + Send + Sync + 'static>(
        self,
        default: T,
        f: impl Fn(&Frame) -> T + Send + Sync + 'static,
    ) -> Memo<T> {
        let frame = self.frame;
        Memo::new(move |_| frame.with(|fr| fr.as_ref().map_or_else(|| default.clone(), &f)))
    }
}

pub(crate) fn ui() -> Ui {
    expect_context::<Ui>()
}

/// The page's focused text, for key handling: a control keeps its keys.
pub(crate) fn android() -> bool {
    ui().platform() == Platform::Android
}

/// Throttled activity reports (the inactivity lock is Rust's).
fn activity_reporter() -> impl Fn() + Clone {
    let last = std::rc::Rc::new(std::cell::Cell::new(0.0));
    move || {
        let now = js_sys::Date::now();
        if now - last.get() >= 500.0 {
            last.set(now);
            ui().activity();
        }
    }
}

#[component]
fn ResizeHandles() -> impl IntoView {
    if android() {
        return ().into_any();
    }
    use qv_ui_api::Edge;
    let edges = [
        ("rz rz-n", Edge::N),
        ("rz rz-s", Edge::S),
        ("rz rz-e", Edge::E),
        ("rz rz-w", Edge::W),
        ("rz rz-ne", Edge::Ne),
        ("rz rz-nw", Edge::Nw),
        ("rz rz-se", Edge::Se),
        ("rz rz-sw", Edge::Sw),
    ];
    edges
        .into_iter()
        .map(|(class, edge)| {
            view! { <div class=class aria-hidden="true" on:mousedown=move |_| ui().window(WindowOp::Resize(edge))></div> }
        })
        .collect_view()
        .into_any()
}

/// The vault switcher under the title bar's vault name (0009 §1.8).
#[component]
fn VaultSwitcher(open: RwSignal<bool>) -> impl IntoView {
    let u = ui();
    let vaults = u.sel(Vec::new(), |f| f.title.vaults.clone());
    let editing = u.sel(false, |f| f.title.editing);
    let switch = move |to: qv_ui_api::SwitchTo| {
        open.set(false);
        u.act(Act::SwitchVault(to));
    };
    view! {
        <button class="pop-scrim" aria-label="Close menu" tabindex="-1" on:click=move |_| open.set(false)></button>
        <div class="menu pop switcher" role="menu" aria-label="Vaults">
            <div class="label">"VAULTS"</div>
            {move || vaults.get().into_iter().map(|v| {
                let id = v.id;
                if v.current {
                    view! {
                        <button class="mi on" role="menuitemradio" aria-checked="true" on:click=move |_| open.set(false)>
                            <Svg icon=Icon::Lock/>
                            <span class="vault-mi"><b>{v.name.to_string()}</b><small>{format!("Open · {}", v.place.as_str())}</small></span>
                            <span class="sub"><Svg icon=Icon::Check/></span>
                        </button>
                    }.into_any()
                } else {
                    let small = if v.exists { v.place.to_string() } else { format!("Not found · {}", v.place.as_str()) };
                    view! {
                        <button class="mi" role="menuitemradio" aria-checked="false" disabled=move || editing.get()
                            on:click=move |_| switch(qv_ui_api::SwitchTo::Vault(id))>
                            <Svg icon=Icon::Lock/>
                            <span class="vault-mi"><b>{v.name.to_string()}</b><small>{small}</small></span>
                        </button>
                    }.into_any()
                }
            }).collect_view()}
            <hr/>
            <button class="mi" id="switch-create" disabled=move || editing.get() on:click=move |_| switch(qv_ui_api::SwitchTo::Mode(qv_ui_api::Mode::Create))><Svg icon=Icon::Plus/>"Create a new vault"</button>
            <button class="mi" id="switch-join" disabled=move || editing.get() on:click=move |_| switch(qv_ui_api::SwitchTo::Mode(qv_ui_api::Mode::Join))><Svg icon=Icon::Qr/>"Join from another device"</button>
            <button class="mi" id="switch-open" disabled=move || editing.get() on:click=move |_| { open.set(false); u.act(Act::SwitchToFile); }><Svg icon=Icon::Folder/>"Open a vault file…"</button>
            <p class="note">{move || if editing.get() { "Save or cancel your changes to switch vaults." } else { "Switching locks this vault." }}</p>
        </div>
    }
}

/// The app's own title bar on desktop (windows have no OS decorations,
/// 0009 §1.8); none on Android.
#[component]
fn TitleBar(palette: RwSignal<bool>) -> impl IntoView {
    let u = ui();
    if android() {
        return ().into_any();
    }
    let switcher = RwSignal::new(false);
    let unlocked = u.sel(false, |f| f.title.unlocked);
    let busy = u.sel(false, |f| f.title.busy);
    let ready = u.sel(false, |f| f.title.ready);
    let light = u.sel(false, |f| f.title.light);
    let idle_only = u.sel(false, |f| f.title.idle_only);
    let idle_left = u.sel(0, |f| f.title.idle_left);
    let vault = u.sel(String::new(), |f| {
        f.title
            .vault
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or_default()
    });
    let stop = |e: web_sys::MouseEvent| e.stop_propagation();
    view! {
        <div class="titlebar"
            on:mousedown=move |e: web_sys::MouseEvent| { if e.button() == 0 { u.window(WindowOp::Drag); } }
            on:dblclick=move |_| u.window(WindowOp::ToggleMaximize)>
            {move || if unlocked.get() {
                view! {
                    <div class="pop-anchor" on:mousedown=stop on:dblclick=stop
                        on:keydown=move |e: web_sys::KeyboardEvent| { if e.key() == "Escape" && switcher.get() { e.stop_propagation(); switcher.set(false); } }>
                        <button class="brand" id="vault-switch" title="Switch vault" disabled=move || busy.get() aria-haspopup="menu"
                            aria-expanded=move || if switcher.get() { "true" } else { "false" }
                            on:click=move |_| switcher.update(|s| *s = !*s)>
                            <Logo class="logo-bar" small=true/>
                            <b>{move || vault.get()}</b>
                            <Svg icon=Icon::ChevronDown/>
                        </button>
                        <Show when=move || switcher.get() && !busy.get()>
                            <VaultSwitcher open=switcher/>
                        </Show>
                    </div>
                }.into_any()
            } else {
                view! { <div class="brand"><Logo class="logo-bar" small=true/><b>"QuickVault"</b></div> }.into_any()
            }}
            <div class="drag"></div>
            <Show when=move || unlocked.get()>
                <button class="cmd" id="command-bar" disabled=move || busy.get() on:mousedown=stop
                    on:click=move |_| { palette.set(true); ui().act(Act::Ui(qv_ui_api::UiOp::Palette(true))); }>
                    <Svg icon=Icon::Search/><span>"Search or run a command"</span><kbd>"Ctrl K"</kbd>
                </button>
            </Show>
            <div class="drag"></div>
            <Show when=move || ready.get()>
                <button class="tb-btn" id="theme-toggle"
                    title=move || if light.get() { "Switch to dark theme" } else { "Switch to light theme" }
                    aria-label="Switch theme" on:mousedown=stop
                    on:click=move |_| ui().act(Act::Theme(if light.get_untracked() { "dark" } else { "light" }.to_owned()))>
                    {move || if light.get() { icons::svg(Icon::Moon).into_any() } else { icons::svg(Icon::Sun).into_any() }}
                </button>
            </Show>
            <Show when=move || unlocked.get()>
                <button class=move || if idle_only.get() { "tb-btn lock-button idle-only" } else { "tb-btn lock-button" } id="lock"
                    title=move || if idle_only.get() { "Lock now (Ctrl L). Locks after 5 minutes without activity. This system does not report screen lock or sleep, so they do not lock QuickVault." } else { "Lock now (Ctrl L). Locks after 5 minutes without activity, and when the screen locks or the device sleeps." }
                    aria-label=move || if idle_only.get() { "Lock. Screen lock and sleep do not lock QuickVault on this system." } else { "Lock" }
                    data-qv-clear="true" on:mousedown=stop on:click=move |_| ui().act(Act::Lock)>
                    <Svg icon=Icon::Lock/>
                    <Show when=move || idle_only.get()><span class="lock-mark" aria-hidden="true"></span></Show>
                    <svg class="ring" viewBox="0 0 26 24" aria-hidden="true">
                        <circle class="track" cx="13" cy="12" r="10.5"></circle>
                        // The ring drains over the last minute before the lock.
                        <circle class="left" cx="13" cy="12" r="10.5" stroke-dasharray="66"
                            stroke-dashoffset=move || format!("{:.1}", 66.0 - 66.0 * (idle_left.get().min(60) as f64) / 60.0)></circle>
                    </svg>
                </button>
            </Show>
            <div class="winctl" on:mousedown=stop>
                <button aria-label="Minimize" title="Minimize" on:click=move |_| ui().window(WindowOp::Minimize)><Svg icon=Icon::Minimize/></button>
                <button aria-label="Maximize" title="Maximize" on:click=move |_| ui().window(WindowOp::ToggleMaximize)><Svg icon=Icon::Maximize/></button>
                <button class="close" aria-label="Close" title="Close" on:click=move |_| ui().window(WindowOp::Close)><Svg icon=Icon::Close/></button>
            </div>
        </div>
    }
    .into_any()
}

/// Which body shows.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    None,
    Failed,
    Locked,
    Unlocked,
}

/// The app root: theme, title bar, keyboard shortcuts and the phase's screen.
#[component]
fn Root() -> impl IntoView {
    let u = ui();
    let kind = u.sel(Kind::None, |f| match f.body {
        Body::Failed { .. } => Kind::Failed,
        Body::Locked(_) => Kind::Locked,
        Body::Unlocked(_) => Kind::Unlocked,
    });
    let mode = u.sel("dark".to_owned(), |f| f.mode.clone());
    let epoch = u.sel(0, |f| f.epoch);
    // The command bar is the backend's popover (it owns its search page);
    // this mirrors it for the keys.
    let palette = RwSignal::new(false);
    let shell_palette = u.sel(false, |f| match &f.body {
        Body::Unlocked(s) => s.palette.is_some(),
        _ => false,
    });
    Effect::new(move |_| palette.set(shell_palette.get()));
    let seen = activity_reporter();
    let keys = {
        let seen = seen.clone();
        move |e: web_sys::KeyboardEvent| {
            seen();
            let key = e.key();
            let ctrl = e.ctrl_key() || e.meta_key();
            let unlocked = kind.get_untracked() == Kind::Unlocked;
            if unlocked && ctrl && matches!(key.as_str(), "k" | "K" | "f" | "F") {
                palette.set(true);
                ui().act(Act::Ui(qv_ui_api::UiOp::Palette(true)));
                e.prevent_default();
                return;
            }
            // Browser shortcuts (reload, print, find, history, source,
            // devtools, caret browsing) are not the app's; WebView2 would
            // act on them, as its accelerator keys stay on (plan 0071).
            let lower = key.to_ascii_lowercase();
            if matches!(key.as_str(), "F3" | "F5" | "F7" | "F12")
                || (ctrl
                    && matches!(
                        lower.as_str(),
                        "r" | "p" | "g" | "u" | "j" | "h" | "f" | "o"
                    ))
                || (ctrl && e.shift_key() && matches!(lower.as_str(), "i" | "c"))
            {
                e.prevent_default();
                return;
            }
            if key == "Escape" && palette.get_untracked() {
                palette.set(false);
                ui().act(Act::Ui(qv_ui_api::UiOp::Palette(false)));
                e.prevent_default();
                return;
            }
            if key == "Escape"
                || (ctrl && matches!(key.as_str(), "n" | "N" | "l" | "L" | "s" | "S"))
            {
                e.prevent_default();
                ui().key(key, ctrl);
            }
        }
    };
    let failed = u.sel((String::new(), String::new()), |f| match &f.body {
        Body::Failed { title, message } => (title.clone(), message.clone()),
        _ => Default::default(),
    });
    let fixture = u.sel(None, |f| f.fixture.clone());
    view! {
        <div class="qv" data-mode=move || mode.get() data-qv-epoch=move || epoch.get().to_string() tabindex="-1"
            on:keydown=keys on:click={ let seen = seen.clone(); move |_| seen() }>
            <TitleBar palette/>
            {move || match kind.get() {
                Kind::None => ().into_any(),
                Kind::Failed => view! {
                    <div class="locked"><div class="locked-body">
                        <div class="wizard">
                            <h2>{move || failed.get().0}</h2>
                            <p>{move || failed.get().1}</p>
                            <p class="muted">"No vault has been opened by this window."</p>
                        </div>
                    </div></div>
                }.into_any(),
                Kind::Locked => view! { <locked::Locked/> }.into_any(),
                Kind::Unlocked => view! { <shell::Shell/> }.into_any(),
            }}
            <ResizeHandles/>
            <input id="qv-activity" class="qv-activity" type="text" tabindex="-1" aria-hidden="true" maxlength="0"
                on:input=move |e| { e.stop_propagation(); ui().activity(); }/>
            <input id="qv-preview-stop" class="qv-activity" type="text" tabindex="-1" aria-hidden="true" maxlength="0"
                on:input=move |e| { e.stop_propagation(); ui().act(Act::Ws(qv_ui_api::WsAct::ClosePreview)); }/>
            {move || fixture.get().map(|fx| view! {
                <input id="validation-result" data-fixture-root=fx.root data-peer-opened=fx.peer_opened.to_string()
                    on:input=move |e| ui().act(Act::Fixture(event_target_value(&e)))/>
            })}
        </div>
    }
}

/// Mounts the page and starts the frame stream.
#[wasm_bindgen(start)]
pub fn start() {
    let frame = RwSignal::new(None::<Frame>);
    let u = Ui { frame };
    bridge::poll(move |f| frame.set(Some(f)));
    leptos::mount::mount_to_body(move || {
        provide_context(u);
        view! { <Root/> }
    });
}
