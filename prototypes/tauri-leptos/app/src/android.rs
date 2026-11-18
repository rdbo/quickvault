// SPDX-License-Identifier: AGPL-3.0-or-later

//! Android glue for the prototype, adapted from qv-app's `android.rs`: the
//! activity's lifecycle and clipboard reach qv-platform through JNI. Copied
//! text crosses JNI as a documented best-effort JVM intermediate (0008 §4.4).
//! No unsafe code.
use crate::backend::IDLE;
use jni::objects::{GlobalRef, JObject, JValue};
use jni::{JNIEnv, JavaVM};
use qv_core::platform::{
    AndroidClipboardBackend, AndroidPlatform, AndroidState, ClipToken, PlatformError,
    PlatformServices,
};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tauri::Manager;

static BRIDGE: OnceLock<(JavaVM, GlobalRef)> = OnceLock::new();
static OS: OnceLock<Arc<AndroidPlatform>> = OnceLock::new();

/// Calls the activity on this thread; a pending Java exception is cleared
/// and reported as a data-free failure.
fn call<T>(f: impl FnOnce(&mut JNIEnv, &JObject) -> jni::errors::Result<T>) -> Result<T, ()> {
    let (vm, activity) = BRIDGE.get().ok_or(())?;
    let mut env = vm.attach_current_thread().map_err(|_| ())?;
    let result = f(&mut env, activity.as_obj());
    if result.is_err() {
        let _ = env.exception_clear();
    }
    result.map_err(|_| ())
}

struct NativeClipboard;
impl AndroidClipboardBackend for NativeClipboard {
    fn set(&self, text: &str) -> Result<ClipToken, PlatformError> {
        call(|env, a| {
            let s = env.new_string(text)?;
            env.call_method(a, "qvCopy", "(Ljava/lang/String;)J", &[JValue::Object(&s)])?
                .j()
        })
        .map(ClipToken)
        .map_err(|_| PlatformError::Io)
    }
    fn owned(&self, token: ClipToken) -> Option<bool> {
        match call(|env, a| {
            env.call_method(a, "qvClipOwned", "(J)I", &[JValue::Long(token.0)])?
                .i()
        }) {
            Ok(1) => Some(true),
            Ok(0) => Some(false),
            _ => None,
        }
    }
    fn clear(&self) -> Result<(), PlatformError> {
        call(|env, a| env.call_method(a, "qvClipClear", "()V", &[]).map(|_| ()))
            .map_err(|_| PlatformError::Io)
    }
}

fn platform() -> Arc<AndroidPlatform> {
    OS.get_or_init(|| {
        Arc::new(
            AndroidPlatform::default()
                .with_background_limit(IDLE)
                .with_clipboard(Arc::new(NativeClipboard)),
        )
    })
    .clone()
}

/// The OS services: lifecycle from the poller below, clipboard via Kotlin.
pub fn services() -> Arc<dyn PlatformServices> {
    platform()
}

/// Back with nothing left to close: the activity leaves on a second press.
pub fn back_at_root() {
    let _ = call(|env, a| env.call_method(a, "qvBackAtRoot", "()V", &[]).map(|_| ()));
}

/// Takes the activity from the main window's webview, then polls its
/// lifecycle (foreground, screen lock, background time) every 100 ms, as
/// qv-app does. Observations come from the OS, never from the page.
pub fn start(app: tauri::AppHandle) {
    let Some(window) = app.get_webview_window("main") else {
        return;
    };
    let _ = window.with_webview(|webview| {
        webview.jni_handle().exec(|env, activity, _| {
            let Ok(vm) = env.get_java_vm() else {
                return;
            };
            let Ok(activity) = env.new_global_ref(activity) else {
                return;
            };
            if BRIDGE.set((vm, activity)).is_err() {
                return;
            }
            let _ = std::thread::Builder::new()
                .name("qv-proto-lifecycle".into())
                .spawn(poll);
        });
    });
}

fn poll() {
    let os = platform();
    let mut generation: Option<(i64, i64)> = None;
    loop {
        let observed = call(|env, a| {
            let flags = env.call_method(a, "qvStatus", "()I", &[])?.i()?;
            let background = env.call_method(a, "qvBackgroundMillis", "()J", &[])?.j()?;
            let pause = env.call_method(a, "qvGeneration", "()J", &[])?.j()?;
            let screen = env.call_method(a, "qvScreenGeneration", "()J", &[])?.j()?;
            Ok((flags, background, pause, screen))
        });
        let Ok((flags, background, pause, screen)) = observed else {
            os.update(AndroidState::default());
            return;
        };
        if flags & 16 != 0 {
            os.update(AndroidState::default());
            return;
        }
        let state = AndroidState {
            monitoring: true,
            foreground: flags & 1 != 0,
            screen_unlocked: flags & 2 != 0,
            secure_window: flags & 4 != 0,
            background: Duration::from_millis(u64::try_from(background).unwrap_or(0)),
        };
        // Keep a pause/resume or screen-off that happened entirely between
        // two polls: a screen-off locks at once, a pause only starts the
        // background clock.
        if let Some((p, s)) = generation {
            if s != screen {
                os.update(AndroidState {
                    foreground: false,
                    screen_unlocked: false,
                    ..state
                });
            } else if p != pause {
                os.update(AndroidState {
                    foreground: false,
                    ..state
                });
            }
        }
        generation = Some((pause, screen));
        os.update(state);
        std::thread::sleep(Duration::from_millis(100));
    }
}
