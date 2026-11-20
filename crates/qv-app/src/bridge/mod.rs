// SPDX-License-Identifier: AGPL-3.0-or-later

//! The app on Tauri 2, fully in process (plan 0071, 0008 §4): the Leptos
//! page reaches Rust through one bounded command, frames come back as raw
//! command replies (long poll), media through the `qvmedia` scheme. Nothing
//! here listens on a socket.
mod convert;
mod dispatch;
mod frame;
mod hooks;
mod hub;
pub(crate) mod media;
mod refs;
#[cfg(target_os = "linux")]
mod webkit;

#[cfg(any(target_os = "linux", windows))]
use crate::controller::AppError;
use crate::controller::{ACTIVE, Controller, private_dir};
use hub::Hub;
use qv_ui_api::{Envelope, FRAME_WAIT_MS, MAX_REQUEST, Reply, Request, UiError};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;
#[cfg(desktop)]
use tauri::Manager;
use tauri::ipc::{InvokeBody, Response};
use tauri::{WebviewUrl, WebviewWindowBuilder};
use zeroize::Zeroizing;

/// What frames are built from and requests act on.
struct State {
    refs: refs::Refs,
    hooks: hooks::Hooks,
    ui: frame::UiState,
    /// The controller's lock generation the references belong to.
    lock_gen: Option<u64>,
    /// The last frame's encoding without its sequence, to skip duplicates.
    last: Zeroizing<Vec<u8>>,
}

struct Bridge {
    hub: Hub,
    state: Mutex<State>,
    dirty: std::sync::atomic::AtomicBool,
}

static BRIDGE: OnceLock<Arc<Bridge>> = OnceLock::new();

fn bridge() -> Arc<Bridge> {
    BRIDGE
        .get_or_init(|| {
            Arc::new(Bridge {
                hub: Hub::new(),
                state: Mutex::new(State {
                    refs: refs::Refs::default(),
                    hooks: hooks::Hooks::default(),
                    ui: frame::UiState::default(),
                    lock_gen: None,
                    last: Zeroizing::new(Vec::new()),
                }),
                dirty: std::sync::atomic::AtomicBool::new(true),
            })
        })
        .clone()
}

impl Bridge {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Builds and publishes a frame if anything visible changed.
    fn render(&self) {
        let active = ACTIVE.get();
        let mut st = self.state();
        // A lock (or a new session) ends every reference and hook slot.
        if let Some(Ok(c)) = active {
            let lock_gen = c.state().lock_gen;
            if st.lock_gen != Some(lock_gen) {
                let State {
                    refs, hooks, ui, ..
                } = &mut *st;
                refs.clear_session();
                hooks.clear(c);
                *ui = frame::UiState::default();
                st.lock_gen = Some(lock_gen);
            }
        }
        let seq = self.hub.next_seq();
        let State {
            refs, hooks, ui, ..
        } = &mut *st;
        let mut built = frame::build(active, refs, hooks, ui, seq);
        built.seq = 0;
        let content = Zeroizing::new(serde_json::to_vec(&built).unwrap_or_default());
        let same = content.as_slice() == st.last.as_slice();
        if same {
            return;
        }
        built.seq = seq;
        let reply = Reply::Frame(Box::new(built));
        let bytes = Zeroizing::new(serde_json::to_vec(&reply).unwrap_or_default());
        st.last = content;
        drop(st);
        self.hub.publish(seq, bytes, false);
    }

    fn mark_dirty(&self) {
        self.dirty.store(true, std::sync::atomic::Ordering::SeqCst);
        crate::controller::wake_ui();
    }
}

/// The render loop: wake on background changes or
/// requests, pump the controller, rebuild when the snapshot or anything
/// else visible changed.
fn render_loop() {
    let b = bridge();
    let mut previous = None;
    loop {
        let woken = crate::controller::wait_ui(Duration::from_millis(200));
        if let Some(Ok(c)) = ACTIVE.get() {
            c.pump();
            // The system bars follow the app theme (JNI only on a change).
            #[cfg(target_os = "android")]
            crate::android::sync_theme(c.theme());
        }
        let snapshot = ACTIVE
            .get()
            .map(|r| r.as_ref().map(Controller::snapshot).map_err(|e| *e));
        let dirty = b.dirty.swap(false, std::sync::atomic::Ordering::SeqCst);
        if woken || dirty || previous != snapshot {
            b.render();
            previous = snapshot;
        }
    }
}

/// Copies the request body into wiped memory, checking its length first.
/// Linux and Windows deliver the page's bytes as is; Android's postMessage
/// IPC delivers them as a JSON array of numbers, which Tauri has already
/// decoded (its envelope, depth-limited) before this runs (0008 §4).
fn take_body(body: &InvokeBody) -> Result<Zeroizing<Vec<u8>>, UiError> {
    match body {
        InvokeBody::Raw(bytes) => {
            if bytes.len() > MAX_REQUEST {
                return Err(UiError::TooLarge);
            }
            let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
            out.extend_from_slice(bytes);
            Ok(out)
        }
        InvokeBody::Json(serde_json::Value::Array(values)) => {
            if values.len() > MAX_REQUEST {
                return Err(UiError::TooLarge);
            }
            let mut out = Zeroizing::new(Vec::with_capacity(values.len()));
            for v in values {
                let b = v
                    .as_u64()
                    .and_then(|n| u8::try_from(n).ok())
                    .ok_or(UiError::Malformed)?;
                out.push(b);
            }
            Ok(out)
        }
        InvokeBody::Json(_) => Err(UiError::Malformed),
    }
}

fn encoded(reply: &Reply) -> Vec<u8> {
    serde_json::to_vec(reply).unwrap_or_default()
}

/// Android has no title bar and plays video full screen inside the page.
#[cfg(mobile)]
fn window_op(_: &tauri::AppHandle, _: qv_ui_api::WindowOp) {}

/// Window operations from the title bar; the page has no window rights.
#[cfg(desktop)]
fn window_op(app: &tauri::AppHandle, op: qv_ui_api::WindowOp) {
    use qv_ui_api::{Edge, WindowOp};
    let Some(w) = app.get_webview_window("main") else {
        return;
    };
    match op {
        WindowOp::Drag => {
            let _ = w.start_dragging();
        }
        WindowOp::ToggleMaximize => {
            if w.is_maximized().unwrap_or(false) {
                let _ = w.unmaximize();
            } else {
                let _ = w.maximize();
            }
        }
        WindowOp::Minimize => {
            let _ = w.minimize();
        }
        WindowOp::Close => {
            let _ = w.close();
        }
        WindowOp::Fullscreen(on) => {
            let _ = w.set_fullscreen(on);
        }
        WindowOp::Resize(edge) => {
            use tauri_runtime::ResizeDirection as D;
            if !w.is_maximized().unwrap_or(false) {
                let _ = w.as_ref().window().start_resize_dragging(match edge {
                    Edge::N => D::North,
                    Edge::S => D::South,
                    Edge::E => D::East,
                    Edge::W => D::West,
                    Edge::Ne => D::NorthEast,
                    Edge::Nw => D::NorthWest,
                    Edge::Se => D::SouthEast,
                    Edge::Sw => D::SouthWest,
                });
            }
        }
    }
}

/// The one command. Work runs off the main thread (unlock takes the
/// Argon2id time); a frame request waits for a newer frame.
#[tauri::command]
async fn qv(app: tauri::AppHandle, request: tauri::ipc::Request<'_>) -> Result<Response, ()> {
    let body = take_body(request.body());
    let reply = tauri::async_runtime::spawn_blocking(move || -> Vec<u8> {
        let body = match body {
            Ok(b) => b,
            Err(e) => return encoded(&Reply::Error(e)),
        };
        let Envelope {
            generation,
            request,
        } = match qv_ui_api::decode(&body) {
            Ok(e) => e,
            Err(e) => return encoded(&Reply::Error(e)),
        };
        drop(body);
        let b = bridge();
        match request {
            Request::Frame { after } => {
                let frame = b
                    .hub
                    .wait_newer(after, Duration::from_millis(FRAME_WAIT_MS))
                    .or_else(|| b.hub.current());
                match frame {
                    Some(bytes) => bytes.as_slice().to_vec(),
                    None => encoded(&Reply::Error(UiError::Unavailable)),
                }
            }
            Request::Window { op } => {
                window_op(&app, op);
                encoded(&Reply::Ok)
            }
            request => {
                let Some(Ok(c)) = ACTIVE.get() else {
                    return encoded(&Reply::Error(UiError::Unavailable));
                };
                let result = {
                    let mut st = b.state();
                    let State {
                        refs, hooks, ui, ..
                    } = &mut *st;
                    dispatch::handle(c, refs, hooks, ui, generation, request)
                };
                b.mark_dirty();
                encoded(&match result {
                    Ok(()) => Reply::Ok,
                    Err(e) => Reply::Error(e),
                })
            }
        }
    })
    .await
    .map_err(|_| ())?;
    Ok(Response::new(reply))
}

/// Only the bundled document may load; everything else is refused.
fn allowed_document(url: &tauri::Url) -> bool {
    let origin = url.origin().ascii_serialization();
    // Custom-scheme origins are opaque to the URL parser on Linux.
    let same = origin == media::app_origin()
        || (url.scheme() == "tauri" && url.host_str() == Some("localhost") && url.port().is_none());
    // Linux loads `tauri://localhost` (an empty path: not a special scheme).
    same && matches!(url.path(), "" | "/" | "/index.html") && url.query().is_none()
}

/// The initial window size. Validation builds accept `QV_UI_SIZE=WxH`.
fn window_size() -> (f64, f64) {
    #[cfg(feature = "fixture")]
    if let Some((w, h)) = std::env::var("QV_UI_SIZE")
        .ok()
        .and_then(|v| v.split_once('x').map(|(w, h)| (w.parse(), h.parse())))
        .and_then(|(w, h)| Some((w.ok()?, h.ok()?)))
        .filter(|&(w, h): &(f64, f64)| {
            (360.0..=4096.0).contains(&w) && (480.0..=4096.0).contains(&h)
        })
    {
        return (w, h);
    }
    (1200.0, 800.0)
}

/// Starts the window and blocks until the app exits.
fn launch(title: &'static str, script: Option<&'static str>, webview: Option<WebviewDir>) -> ! {
    start_app(title, script, webview);
    std::process::exit(0)
}

/// Builds and runs the app. On desktop this returns when the app exits; on
/// Android the activity drives the event loop and it returns after setup.
fn start_app(title: &'static str, script: Option<&'static str>, webview: Option<WebviewDir>) {
    let data = webview.as_ref().map(|w| w.path.clone());
    if let Some(w) = webview.filter(|w| w.temporary) {
        let _ = TEMPORARY.set(w.path);
    }
    let result = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![qv])
        .register_asynchronous_uri_scheme_protocol(media::SCHEME, |_ctx, request, responder| {
            std::thread::spawn(move || {
                responder.respond(media::serve(&request, &media::Preview));
            });
        })
        .setup(move |app| {
            let (width, height) = window_size();
            let window =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .on_navigation(allowed_document)
                    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)
                    // As the hardened Dioxus webview did (0008 §4): no
                    // website data kept on disk, no inspector, no downloads.
                    .incognito(true)
                    .devtools(false)
                    .on_download(|_, _| false);
            let window = match data.clone() {
                Some(dir) => window.data_directory(dir),
                None => window,
            };
            #[cfg(desktop)]
            let window = window
                .title(title)
                // The app draws its own title bar (0009 §1.8).
                .decorations(false)
                .inner_size(width, height)
                .min_inner_size(360.0, 480.0);
            #[cfg(not(desktop))]
            let _ = (title, width, height);
            // Validation flows: a synthetic script after each page load,
            // in an async function as the flow scripts use top-level await.
            let window = match script {
                Some(js) => {
                    let js = format!("(async () => {{\n{js}\n}})();");
                    window.on_page_load(move |w, payload| {
                        if payload.event() == tauri::webview::PageLoadEvent::Finished {
                            let _ = w.eval(&js);
                        }
                    })
                }
                None => window,
            };
            #[cfg(windows)]
            let window = window.general_autofill_enabled(false);
            let window = window.build()?;
            #[cfg(target_os = "linux")]
            let _ = window.with_webview(|webview| webkit::harden(&webview.inner()));
            #[cfg(target_os = "android")]
            let _ = window.with_webview(|webview| {
                webview
                    .jni_handle()
                    .exec(|env, activity, _| crate::android::start(env, activity));
            });
            #[cfg(not(target_os = "android"))]
            let _ = window;
            std::thread::Builder::new()
                .name("qv-render".into())
                .spawn(render_loop)?;
            Ok(())
        })
        .on_window_event(|_, event| {
            if matches!(
                event,
                tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed
            ) && let Some(Ok(c)) = ACTIVE.get()
            {
                c.lock();
            }
        })
        .build(tauri::generate_context!());
    let Ok(app) = result else {
        std::process::exit(1);
    };
    app.run(|_, event| {
        if matches!(event, tauri::RunEvent::Exit) {
            if let Some(Ok(c)) = ACTIVE.get() {
                c.lock();
            }
            remove_temporary();
        }
    });
}

/// The Android entry point: the activity's `onCreate` starts the app here
/// (the Android platform services start in `android::start`, from the setup).
#[cfg(target_os = "android")]
#[tauri::mobile_entry_point]
fn android_main() {
    qv_core::harden();
    #[cfg(feature = "validation")]
    if crate::validation_media::enabled() {
        start_app(
            "QuickVault synthetic media",
            Some(include_str!("../bin/media.js")),
            None,
        );
        return;
    }
    start_app("QuickVault", None, None);
}

/// The webview's data folder. Incognito keeps no website data on disk, but
/// Tauri creates the folder on Linux and Windows (in the user's data folder
/// by default): the app uses its private state folder, and previews and
/// harnesses a private random folder under the system temporary folder,
/// removed at exit, so a fixture never touches the user's own data.
struct WebviewDir {
    path: std::path::PathBuf,
    temporary: bool,
}
static TEMPORARY: OnceLock<std::path::PathBuf> = OnceLock::new();

#[cfg_attr(target_os = "android", allow(dead_code))]
fn webview_dir(state: Option<std::path::PathBuf>) -> Option<WebviewDir> {
    if !cfg!(any(target_os = "linux", windows)) {
        return None;
    }
    let (path, temporary) = match state {
        Some(state) => (state.join("webview"), false),
        None => {
            let mut id = [0u8; 16];
            getrandom::fill(&mut id).ok()?;
            let name: String = id.iter().map(|b| format!("{b:02x}")).collect();
            (
                std::env::temp_dir().join(format!("qv-webview-{name}")),
                true,
            )
        }
    };
    (path.is_absolute() && private_dir(&path).is_ok()).then_some(WebviewDir { path, temporary })
}

/// Removes a preview's or harness's temporary webview folder.
pub(crate) fn remove_temporary() {
    if let Some(path) = TEMPORARY.get() {
        let _ = std::fs::remove_dir_all(path);
    }
}

/// Private state, single-instance ownership and the controller, in that order.
#[cfg(any(target_os = "linux", windows))]
fn desktop_setup(
    base: Result<std::path::PathBuf, AppError>,
) -> Result<
    (
        qv_core::platform::InstanceLock,
        Result<Controller, AppError>,
    ),
    AppError,
> {
    let base = base?;
    private_dir(&base).map_err(|_| AppError::PrivateStorage)?;
    let guard = qv_core::platform::InstanceLock::acquire(&base).map_err(|error| {
        if error == qv_core::platform::PlatformError::Busy {
            AppError::AlreadyRunning
        } else {
            AppError::PrivateStorage
        }
    })?;
    #[cfg(target_os = "linux")]
    let services = Arc::new(qv_core::platform::LinuxPlatform::default());
    // Windows requires the WTS lock/sleep watcher (0009 §5.1).
    #[cfg(windows)]
    let services = Arc::new(qv_core::platform::WindowsPlatform::default());
    let controller = Controller::new(base, services);
    Ok((guard, controller))
}
/// `%LOCALAPPDATA%\QuickVault\state`: device-local, never roaming.
#[cfg(windows)]
fn state_root() -> Result<std::path::PathBuf, AppError> {
    let path =
        std::path::PathBuf::from(std::env::var_os("LOCALAPPDATA").ok_or(AppError::Unavailable)?)
            .join("QuickVault")
            .join("state");
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::Unavailable);
    }
    Ok(path)
}
#[cfg(target_os = "linux")]
fn state_root() -> Result<std::path::PathBuf, AppError> {
    let path = if let Some(root) = std::env::var_os("XDG_STATE_HOME") {
        std::path::PathBuf::from(root).join("quickvault")
    } else {
        std::path::PathBuf::from(std::env::var_os("HOME").ok_or(AppError::Unavailable)?)
            .join(".local/state/quickvault")
    };
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(AppError::Unavailable);
    }
    Ok(path)
}

/// Launch the shared Android/Linux/Windows app with its platform services.
pub fn run() -> ! {
    // The file-picker helper (plan 0044): answer and exit before hardening,
    // the instance lock or any vault access.
    #[cfg(target_os = "linux")]
    if let Some(code) = crate::picker::helper() {
        std::process::exit(code);
    }
    qv_core::harden();
    #[cfg(any(target_os = "linux", windows))]
    let (guard, webview) = match desktop_setup(state_root().map_err(|_| AppError::PrivateStorage)) {
        Ok((guard, controller)) => {
            let _ = ACTIVE.set(controller);
            (
                Some(guard),
                state_root().ok().and_then(|s| webview_dir(Some(s))),
            )
        }
        Err(error) => {
            let _ = ACTIVE.set(Err(error));
            (None, webview_dir(None))
        }
    };
    #[cfg(not(any(target_os = "linux", windows)))]
    let webview = None;
    #[cfg(any(target_os = "linux", windows))]
    let _instance = guard;
    #[cfg(feature = "validation")]
    if crate::validation_media::enabled() {
        launch(
            "QuickVault synthetic media",
            Some(include_str!("../bin/media.js")),
            webview,
        );
    }
    launch("QuickVault", None, webview)
}

/// Synthetic shared-screen preview; no persistent vault action is permitted.
#[cfg(feature = "validation")]
pub fn run_preview() -> ! {
    let _ = ACTIVE.set(Controller::preview());
    launch("QuickVault · read-only preview", None, webview_dir(None))
}

/// Webview boundary checks (0012 §1 "Webview exposure"): the read-only
/// preview with `boundary.js`, which reports through the one command.
#[cfg(feature = "validation")]
pub fn run_boundary() -> ! {
    let _ = ACTIVE.set(Controller::preview());
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(60));
        eprintln!("boundary harness timeout");
        std::process::exit(2)
    });
    launch(
        "QuickVault boundary",
        Some(include_str!("../bin/boundary.js")),
        webview_dir(None),
    )
}

/// Actual shared screens and core operations, using only synthetic fixture data.
#[cfg(feature = "validation")]
pub fn run_flow_fixture() -> ! {
    let fixture = Controller::validation_fixture();
    if crate::validation_media::enabled()
        && let Err(error) = fixture
    {
        eprintln!("synthetic media setup failed: {}", error.message());
        std::process::exit(1);
    }
    let _ = ACTIVE.set(fixture);
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(150));
        eprintln!("full UI fixture timeout");
        std::process::exit(2)
    });
    if crate::validation_media::enabled() {
        launch(
            "QuickVault synthetic media",
            Some(include_str!("../bin/media.js")),
            webview_dir(None),
        );
    }
    launch(
        "QuickVault synthetic flow",
        Some(include_str!("../bin/flow.js")),
        webview_dir(None),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    // 0012 §1: Webview exposure
    #[test]
    fn bodies_are_bounded_before_copying() {
        assert_eq!(
            &take_body(&InvokeBody::Raw(vec![1, 2, 3])).unwrap()[..],
            &[1, 2, 3]
        );
        assert_eq!(
            take_body(&InvokeBody::Raw(vec![0; MAX_REQUEST + 1])).err(),
            Some(UiError::TooLarge)
        );
        let json = InvokeBody::Json(serde_json::json!([123, 34, 125]));
        assert_eq!(&take_body(&json).unwrap()[..], b"{\"}");
        let big = InvokeBody::Json(serde_json::Value::Array(vec![
            serde_json::json!(0);
            MAX_REQUEST + 1
        ]));
        assert_eq!(take_body(&big).err(), Some(UiError::TooLarge));
        for bad in [
            serde_json::json!([256]),
            serde_json::json!([-1]),
            serde_json::json!(["a"]),
            serde_json::json!({"generation": 0}),
        ] {
            assert_eq!(
                take_body(&InvokeBody::Json(bad)).err(),
                Some(UiError::Malformed)
            );
        }
    }

    // 0012 §1: Webview exposure
    #[test]
    fn only_the_bundled_document_navigates() {
        let ok = |u: &str| allowed_document(&tauri::Url::parse(u).unwrap());
        assert!(ok(media::app_origin()));
        assert!(ok(&format!("{}/index.html", media::app_origin())));
        for bad in [
            "https://example.org/",
            "http://tauri.localhost.evil.example/",
            "http://tauri.localhost:8080/",
            "tauri://localhost/other.html",
            "tauri://evil/",
            "qvmedia://localhost/",
            "data:text/html,hi",
            "javascript:alert(1)",
            "file:///etc/passwd",
        ] {
            assert!(!ok(bad), "{bad}");
        }
        assert!(!ok(&format!("{}/?x=1", media::app_origin())));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_startup_reports_the_specific_storage_or_instance_refusal() {
        let dir = std::env::temp_dir().join(format!("qv-app-startup-{}", std::process::id()));
        private_dir(&dir).unwrap();
        let (guard, controller) = desktop_setup(Ok(dir.clone())).unwrap();
        assert!(controller.is_ok());
        assert!(matches!(
            desktop_setup(Ok(dir.clone())),
            Err(AppError::AlreadyRunning)
        ));
        drop(guard);
        let file = dir.join("not-a-directory");
        std::fs::write(&file, b"").unwrap();
        assert!(matches!(
            desktop_setup(Ok(file)),
            Err(AppError::PrivateStorage)
        ));
        drop(controller);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
