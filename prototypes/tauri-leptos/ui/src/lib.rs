// SPDX-License-Identifier: AGPL-3.0-or-later

//! Plan 0070 prototype page, in Leptos (client-side rendering, wasm32).
//! It holds only what a screen shows; secrets typed here go to Rust at once
//! and the inputs are cleared (0008 §4.4). Uses the app's own CSS and
//! scripts (`app.css`, `app.js`, `player.js`), unchanged.
mod bridge;

use leptos::html;
use leptos::prelude::*;
use leptos::task::spawn_local;
use qv_proto_api::{
    EntryView, Event, MediaView, Ref, Reply, Request, Row, Sample, Secret, UiError,
};
use std::cell::Cell;
use std::time::Duration;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

/// An open preview and how it plays.
#[derive(Clone, PartialEq)]
struct Open {
    view: MediaView,
    /// Mode B: `player.js` fetches chunks (MediaSource or a blob) instead of
    /// the engine loading `src` (mode A).
    streamed: bool,
}

/// Everything the page shows, as signals.
#[derive(Clone, Copy)]
struct Ui {
    unlocked: RwSignal<bool>,
    hint: RwSignal<String>,
    platform: RwSignal<String>,
    busy: RwSignal<bool>,
    error: RwSignal<Option<&'static str>>,
    groups: RwSignal<Vec<Row>>,
    group: RwSignal<Option<Ref>>,
    entries: RwSignal<Vec<Row>>,
    entry: RwSignal<Option<(Ref, EntryView)>>,
    revealed: RwSignal<Vec<(Ref, String)>>,
    clip: RwSignal<u64>,
    note: RwSignal<Option<&'static str>>,
    media: RwSignal<Option<Open>>,
    password: NodeRef<html::Input>,
}

impl Ui {
    fn new() -> Self {
        Self {
            unlocked: RwSignal::new(false),
            hint: RwSignal::new(String::new()),
            platform: RwSignal::new(String::new()),
            busy: RwSignal::new(false),
            error: RwSignal::new(None),
            groups: RwSignal::new(Vec::new()),
            group: RwSignal::new(None),
            entries: RwSignal::new(Vec::new()),
            entry: RwSignal::new(None),
            revealed: RwSignal::new(Vec::new()),
            clip: RwSignal::new(0),
            note: RwSignal::new(None),
            media: RwSignal::new(None),
            password: NodeRef::new(),
        }
    }

    /// The vault locked: drop everything vault-derived and every input.
    fn locked(self) {
        self.unlocked.set(false);
        self.busy.set(false);
        self.groups.set(Vec::new());
        self.group.set(None);
        self.entries.set(Vec::new());
        self.entry.set(None);
        self.revealed.set(Vec::new());
        self.media.set(None);
        self.note.set(None);
        clear_inputs();
    }

    fn fail(self, e: UiError) {
        match e {
            // Stale: the lock event has already reset the screen.
            UiError::Stale => {}
            UiError::Locked => self.locked(),
            e => self.note.set(Some(e.message())),
        }
    }

    fn on_event(self, event: Event) {
        match event {
            Event::Locked { generation } => {
                if generation > bridge::generation() {
                    bridge::set_generation(generation);
                }
                self.locked();
            }
            Event::RevealExpired { field } => {
                self.revealed.update(|r| r.retain(|(f, _)| *f != field))
            }
            Event::Clipboard { seconds } => self.clip.set(seconds),
        }
    }

    fn load_groups(self) {
        spawn_local(async move {
            match bridge::call(Request::Groups).await {
                Ok(Reply::Groups(rows)) => self.groups.set(rows),
                Ok(_) => self.fail(UiError::Malformed),
                Err(e) => self.fail(e),
            }
        });
    }

    fn open_group(self, group: Ref) {
        spawn_local(async move {
            match bridge::call(Request::Entries { group }).await {
                Ok(Reply::Entries(rows)) => {
                    // Content changes only when the answer is here: no blank flash.
                    self.entries.set(rows);
                    self.entry.set(None);
                    self.group.set(Some(group));
                }
                Ok(_) => self.fail(UiError::Malformed),
                Err(e) => self.fail(e),
            }
        });
    }

    fn open_entry(self, entry: Ref) {
        spawn_local(async move {
            match bridge::call(Request::Entry { entry }).await {
                Ok(Reply::Entry(view)) => {
                    self.revealed.set(Vec::new());
                    self.entry.set(Some((entry, view)));
                }
                Ok(_) => self.fail(UiError::Malformed),
                Err(e) => self.fail(e),
            }
        });
    }

    fn reveal(self, field: Ref) {
        spawn_local(async move {
            match bridge::call(Request::Reveal { field }).await {
                Ok(Reply::Revealed {
                    field,
                    value,
                    expires_ms,
                }) => {
                    let text = String::from_utf8_lossy(value.expose()).into_owned();
                    drop(value);
                    self.revealed.update(|r| {
                        r.retain(|(f, _)| *f != field);
                        r.push((field, text));
                    });
                    // The page drops it by itself too (0008 §4.3).
                    let generation = bridge::generation();
                    set_timeout(
                        move || {
                            if bridge::generation() == generation {
                                self.revealed.update(|r| r.retain(|(f, _)| *f != field));
                            }
                        },
                        Duration::from_millis(u64::from(expires_ms)),
                    );
                }
                Ok(_) => self.fail(UiError::Malformed),
                Err(e) => self.fail(e),
            }
        });
    }

    fn copy(self, field: Ref) {
        spawn_local(async move {
            match bridge::call(Request::Copy { field }).await {
                Ok(_) => self
                    .note
                    .set(Some("Copied. The clipboard clears in 30 seconds.")),
                Err(e) => self.fail(e),
            }
        });
    }

    fn open_media(self, sample: Sample, streamed: bool) {
        spawn_local(async move {
            match bridge::call(Request::OpenMedia { sample }).await {
                Ok(Reply::Media(view)) => self.media.set(Some(Open { view, streamed })),
                Ok(_) => self.fail(UiError::Malformed),
                Err(e) => self.fail(e),
            }
        });
    }

    fn close_media(self) {
        if let Some(open) = self.media.get_untracked() {
            self.media.set(None);
            spawn_local(async move {
                let _ = bridge::call(Request::CloseMedia {
                    media: open.view.media,
                })
                .await;
            });
        }
    }

    /// Escape, and Android Back (sent as Escape): close the innermost panel.
    fn back(self) -> bool {
        if self.media.get_untracked().is_some() {
            self.close_media();
        } else if self.entry.get_untracked().is_some() {
            self.entry.set(None);
            self.revealed.set(Vec::new());
        } else if self.group.get_untracked().is_some() {
            self.group.set(None);
        } else {
            return false;
        }
        true
    }
}

fn clear_inputs() {
    let Some(document) = web_sys::window().and_then(|w| w.document()) else {
        return;
    };
    let Ok(nodes) = document.query_selector_all("input:not([type=range]),textarea") else {
        return;
    };
    for i in 0..nodes.length() {
        let node = nodes.item(i);
        if let Some(input) = node
            .as_ref()
            .and_then(|n| n.dyn_ref::<web_sys::HtmlInputElement>())
        {
            input.set_value("");
        } else if let Some(area) =
            node.and_then(|n| n.dyn_into::<web_sys::HtmlTextAreaElement>().ok())
        {
            area.set_value("");
        }
    }
}

fn unlock(ui: Ui) {
    let Some(input) = ui.password.get_untracked() else {
        return;
    };
    if ui.busy.get_untracked() {
        return;
    }
    // Into a wiped Rust buffer at once; the field is cleared before the
    // request leaves (0008 §4.4).
    let typed = zeroize::Zeroizing::new(input.value());
    input.set_value("");
    let password = Secret::new(typed.as_bytes());
    drop(typed);
    let password = match password {
        Ok(p) => p,
        Err(e) => return ui.error.set(Some(e.message())),
    };
    ui.busy.set(true);
    ui.error.set(None);
    spawn_local(async move {
        let result = bridge::call(Request::Unlock { password }).await;
        ui.busy.set(false);
        match result {
            Ok(_) => {
                ui.unlocked.set(true);
                ui.load_groups();
            }
            Err(UiError::Stale) => {}
            Err(e) => ui.error.set(Some(e.message())),
        }
    });
}

/// Reports user activity at most once a second (the idle lock is Rust's).
fn watch_activity() {
    let Some(window) = web_sys::window() else {
        return;
    };
    let last = std::rc::Rc::new(Cell::new(0.0));
    let report = Closure::<dyn Fn()>::new(move || {
        let now = js_sys::Date::now();
        if now - last.get() < 1000.0 {
            return;
        }
        last.set(now);
        spawn_local(async {
            let _ = bridge::call(Request::Active).await;
        });
    });
    for name in ["pointerdown", "keydown", "wheel", "touchstart", "input"] {
        let _ = window.add_event_listener_with_callback(name, report.as_ref().unchecked_ref());
    }
    report.forget();
}

#[component]
fn Locked(ui: Ui) -> impl IntoView {
    view! {
        <div class="locked">
            <div class="locked-body">
                <div class="unlock-card fade-in">
                    <h1 class="proto-title">"QuickVault prototype"</h1>
                    <div class="vault-meta" id="vault-place">
                        "Synthetic vault · password: " <b>{move || ui.hint.get()}</b>
                    </div>
                    <div class=move || if ui.error.get().is_some() { "pw bad" } else { "pw" }>
                        <input node_ref=ui.password id="password" type="password"
                            placeholder="Master password" aria-label="Master password" maxlength="1024"
                            autocomplete="off" spellcheck="false" autocapitalize="off"
                            disabled=move || ui.busy.get()
                            on:keydown=move |e: web_sys::KeyboardEvent| {
                                if e.key() == "Enter" {
                                    e.prevent_default();
                                    unlock(ui);
                                }
                            } />
                        <button class="go" id="unlock-submit" aria-label="Unlock"
                            disabled=move || ui.busy.get() on:click=move |_| unlock(ui)>"→"</button>
                    </div>
                    <Show when=move || ui.busy.get()>
                        <p class="muted">"Opening…"</p>
                    </Show>
                    {move || ui.error.get().map(|m| view! { <p class="banner bad" role="alert">{m}</p> })}
                </div>
            </div>
        </div>
    }
}

#[component]
fn Viewer(ui: Ui, open: Open) -> impl IntoView {
    let video = open.view.mime.starts_with("video/");
    let MediaView {
        url, mime, size, ..
    } = open.view;
    let android = ui.platform.get_untracked() == "android";
    let controls = view! {
        <div class="v-ctl">
            <button class="v-cb v-play" type="button" aria-label="Play" title="Play (Space)">
                <span class="i-play">"▶"</span><span class="i-pause">"⏸"</span>
            </button>
            <input class="v-seek" type="range" min="0" max="1" step="any" value="0" aria-label="Seek" />
            <span class="v-time"></span>
            <button class="v-cb v-mute" type="button" aria-label="Mute" title="Mute (M)">
                <span class="i-loud">"🔊"</span><span class="i-quiet">"🔇"</span>
            </button>
            <input class="v-volume" type="range" min="0" max="1" step="any" value="1" aria-label="Volume" />
        </div>
    };
    let media = match (video, open.streamed) {
        (true, true) => view! { <video data-qv-src=url data-qv-type=mime data-qv-size=size.to_string() preload="auto" playsinline="true"></video> }.into_any(),
        (true, false) => view! { <video src=url preload="auto" playsinline="true"></video> }.into_any(),
        (false, true) => view! { <audio data-qv-src=url data-qv-type=mime data-qv-size=size.to_string() preload="auto"></audio> }.into_any(),
        (false, false) if android => view! { <audio src=url preload="metadata" crossorigin="anonymous"></audio> }.into_any(),
        (false, false) => view! { <audio src=url preload="metadata"></audio> }.into_any(),
    };
    let mode = if open.streamed {
        "mode B (chunks)"
    } else {
        "mode A (src)"
    };
    let stage = if video {
        view! { <div class="v-video" on:click=|e| e.stop_propagation()><div class="v-player">{media}{controls}</div></div> }.into_any()
    } else {
        view! {
            <div class="v-audio" on:click=|e| e.stop_propagation()>
                <div class="v-disc"><div class="v-disc-label"></div></div>
                <div class="v-eq" aria-hidden="true">{(0..24).map(|_| view! { <i></i> }).collect_view()}</div>
                <b class="v-track">"Sample"</b>
                <div class="v-player">{media}{controls}</div>
            </div>
        }
        .into_any()
    };
    view! {
        <div class="viewer tone-dark" role="dialog" aria-modal="true" aria-label="Preview" tabindex="-1"
            on:click=move |_| ui.close_media()>
            <div class="v-top">
                <div class="v-title"><b>"Preview"</b><span id="viewer-mode">{mode}</span></div>
                <span class="sp"></span>
                <button class="v-btn icon" id="viewer-close" aria-label="Close preview" on:click=move |e| { e.stop_propagation(); ui.close_media(); }>"✕"</button>
            </div>
            <div class="v-stage">{stage}</div>
        </div>
    }
}

#[component]
fn Unlocked(ui: Ui) -> impl IntoView {
    let field_row = move |f: qv_proto_api::FieldView| {
        let id = f.id;
        let shown = move || {
            ui.revealed
                .get()
                .iter()
                .find(|(r, _)| *r == id)
                .map(|(_, v)| v.clone())
        };
        let protected = f.protected;
        let plain = f.value.clone().unwrap_or_default();
        view! {
            <div class="set-row">
                <span class="l"><b>{f.name}</b>
                    <span class="mono proto-value">
                        {move || if protected { shown().unwrap_or_else(|| "••••••••".to_owned()) } else { plain.clone() }}
                    </span>
                </span>
                <span class="r-actions">
                    <Show when=move || protected>
                        <button class="btn subtle" on:click=move |_| ui.reveal(id)>"Reveal"</button>
                    </Show>
                    <button class="btn subtle" on:click=move |_| ui.copy(id)>"Copy"</button>
                </span>
            </div>
        }
    };
    view! {
        <div class="proto">
            <div class="proto-bar">
                <b>"QuickVault prototype"</b>
                <span class="sp"></span>
                <button class="btn subtle" id="lock" on:click=move |_| {
                    spawn_local(async move { if let Err(e) = bridge::call(Request::Lock).await { ui.fail(e) } });
                }>"Lock"</button>
            </div>
            <div class="proto-body">
                {move || ui.note.get().map(|m| view! { <p class="banner ok" role="status">{m}</p> })}
                <Show when=move || { ui.clip.get() > 0 }>
                    <p class="hint" id="clip">{move || format!("Clipboard clears in {} s", ui.clip.get())}</p>
                </Show>
                <div class="card card-pad">
                    <div class="card-h">"Groups"</div>
                    <For each=move || ui.groups.get() key=|r| r.id let:row>
                        <button class="choice" on:click=move |_| ui.open_group(row.id)><b>{row.name}</b></button>
                    </For>
                </div>
                <Show when=move || ui.group.get().is_some()>
                    <div class="card card-pad">
                        <div class="card-h">"Entries"</div>
                        <For each=move || ui.entries.get() key=|r| r.id let:row>
                            <button class="choice" on:click=move |_| ui.open_entry(row.id)><b>{row.name}</b></button>
                        </For>
                    </div>
                </Show>
                {move || ui.entry.get().map(|(_, e)| view! {
                    <div class="card card-pad" id="entry">
                        <div class="card-h">{e.title}</div>
                        {e.fields.into_iter().map(field_row).collect_view()}
                        <p class="notes">{e.notes}</p>
                    </div>
                })}
                <div class="card card-pad">
                    <div class="card-h">"Typing and paste"</div>
                    <label class="fld"><span>"Text field"</span><input type="text" id="plain" maxlength="1024" /></label>
                    <label class="fld"><span>"Notes"</span><textarea id="notes" rows="4" maxlength="4096"></textarea></label>
                </div>
                <div class="card card-pad">
                    <div class="card-h">"Media"</div>
                    {[(Sample::Video, "Short video"), (Sample::VideoLong, "Long video"), (Sample::VideoGop, "Long-GOP video"), (Sample::AudioMp4, "MP4 audio"), (Sample::Wav, "WAV")]
                        .into_iter()
                        .map(|(s, name)| view! {
                            <div class="set-row">
                                <span class="l"><b>{name}</b></span>
                                <span class="r-actions">
                                    <button class="btn subtle" on:click=move |_| ui.open_media(s, false)>"A"</button>
                                    <button class="btn subtle" on:click=move |_| ui.open_media(s, true)>"B"</button>
                                </span>
                            </div>
                        })
                        .collect_view()}
                </div>
            </div>
            {move || ui.media.get().map(|open| view! { <Viewer ui open /> })}
        </div>
    }
}

#[component]
fn App() -> impl IntoView {
    let ui = Ui::new();
    if bridge::listen(move |e| ui.on_event(e)).is_err() {
        ui.error.set(Some(UiError::Unavailable.message()));
    }
    spawn_local(async move {
        match bridge::status().await {
            Ok(Reply::Status {
                unlocked,
                platform,
                hint,
            }) => {
                ui.hint.set(hint);
                ui.platform.set(platform);
                ui.unlocked.set(unlocked);
                if unlocked {
                    ui.load_groups();
                }
            }
            Ok(_) => ui.error.set(Some(UiError::Malformed.message())),
            Err(e) => ui.error.set(Some(e.message())),
        }
    });
    watch_activity();
    let _ = window_event_listener(leptos::ev::keydown, move |e| {
        if e.key() != "Escape" {
            return;
        }
        e.prevent_default();
        e.stop_propagation();
        if !ui.back() && ui.platform.get_untracked() == "android" {
            spawn_local(async {
                let _ = bridge::call(Request::BackAtRoot).await;
            });
        }
    });
    view! {
        <div class="qv" data-mode="dark" tabindex="-1">
            <Show when=move || ui.unlocked.get() fallback=move || view! { <Locked ui /> }>
                <Unlocked ui />
            </Show>
        </div>
    }
}

/// Mounts the page.
#[wasm_bindgen(start)]
pub fn start() {
    leptos::mount::mount_to_body(App);
}
