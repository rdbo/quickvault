// SPDX-License-Identifier: AGPL-3.0-or-later

//! Plan 0070 prototype: QuickVault's backend on Tauri 2, fully in process.
//! The page reaches Rust through one command and one event; media comes from
//! an in-process scheme. Nothing here listens on a socket.
#[cfg(target_os = "android")]
mod android;
pub mod backend;
pub mod media;

use backend::{Backend, IDLE, Shared};
use qv_proto_api::{Answer, EVENT, MAX_REQUEST, Reply, UiError};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::{InvokeBody, Response};
use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder};
use zeroize::Zeroizing;

/// Copies the request body into wiped memory, checking its length first.
/// Linux and Windows deliver the page's bytes as is; Android's postMessage
/// IPC delivers them as a JSON array of numbers, which Tauri has already
/// decoded (its envelope, with serde_json's depth limit) before this runs.
pub fn take_body(body: &InvokeBody) -> Result<Zeroizing<Vec<u8>>, UiError> {
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

/// Encodes an answer for the page. The buffer handed to Tauri is a
/// framework copy outside our control (0008 §4.4).
fn encode(answer: &Answer) -> Vec<u8> {
    serde_json::to_vec(answer).unwrap_or_default()
}

/// The one command. The work runs off the main thread (unlock takes the
/// Argon2id time), so the window keeps drawing.
#[tauri::command]
async fn qv(
    request: tauri::ipc::Request<'_>,
    state: tauri::State<'_, Shared>,
) -> Result<Response, ()> {
    let shared = state.inner().clone();
    let body = take_body(request.body());
    let answer = tauri::async_runtime::spawn_blocking(move || {
        let mut backend = shared.get();
        match body {
            Ok(body) => backend.handle(&body),
            Err(e) => Answer {
                generation: backend.generation(),
                reply: Reply::Error(e),
            },
        }
    })
    .await
    .map_err(|_| ())?;
    Ok(Response::new(encode(&answer)))
}

/// Only the bundled document may load; everything else is refused.
fn allowed_document(url: &tauri::Url) -> bool {
    let origin = url.origin().ascii_serialization();
    let expected = media::app_origin();
    // Custom-scheme origins are opaque to the URL parser on Linux.
    let same = origin == expected
        || (url.scheme() == "tauri" && url.host_str() == Some("localhost") && url.port().is_none());
    // Linux loads `tauri://localhost` (an empty path: the scheme is not special).
    same && matches!(url.path(), "" | "/" | "/index.html") && url.query().is_none()
}

fn data_dir(app: &tauri::App) -> Result<PathBuf, UiError> {
    // A relative override for test runs (see backend tests on 0011 §4).
    if cfg!(debug_assertions)
        && let Some(dir) = std::env::var_os("QV_PROTO_DATA")
    {
        return Ok(PathBuf::from(dir));
    }
    app.path()
        .app_data_dir()
        .map(|d| d.join("quickvault"))
        .map_err(|_| UiError::Unavailable)
}

fn services() -> Arc<dyn qv_core::platform::PlatformServices> {
    #[cfg(target_os = "android")]
    {
        android::services()
    }
    #[cfg(target_os = "linux")]
    {
        Arc::new(qv_core::platform::LinuxPlatform::default())
    }
    #[cfg(windows)]
    {
        Arc::new(qv_core::platform::WindowsPlatform::default())
    }
}

/// Debug builds only: `QV_PROTO_PROBE=<file.js>` runs that script in the
/// page after each load, and a page title starting with `PROBE ` is printed,
/// so tests can drive the real window and read results (plan 0070 A3, A6).
#[cfg(debug_assertions)]
fn probe<'a, R: tauri::Runtime, M: Manager<R>>(
    window: WebviewWindowBuilder<'a, R, M>,
) -> Result<WebviewWindowBuilder<'a, R, M>, std::io::Error> {
    let Some(path) = std::env::var_os("QV_PROTO_PROBE") else {
        return Ok(window);
    };
    let script = std::fs::read_to_string(path)?;
    Ok(window
        .on_page_load(move |w, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                let _ = w.eval(&script);
            }
        })
        .on_document_title_changed(|_, title| {
            if let Some(result) = title.strip_prefix("PROBE ") {
                println!("{result}");
            }
        }))
}

/// Starts the app.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    qv_core::harden();
    let result = tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![qv])
        .register_asynchronous_uri_scheme_protocol(media::SCHEME, |ctx, request, responder| {
            let shared = ctx.app_handle().state::<Shared>().inner().clone();
            std::thread::spawn(move || {
                let response = media::serve(&request, |token| shared.get().media(token));
                // Debug builds: QV_PROTO_TRACE=1 prints each media exchange
                // (method, range and status only).
                if cfg!(debug_assertions) && std::env::var_os("QV_PROTO_TRACE").is_some() {
                    let header = |r: &tauri::http::HeaderMap, n| {
                        r.get(n)
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("-")
                            .to_owned()
                    };
                    eprintln!(
                        "media {} range={} -> {} {} origin={}",
                        request.method(),
                        header(request.headers(), tauri::http::header::RANGE),
                        response.status().as_u16(),
                        header(response.headers(), tauri::http::header::CONTENT_RANGE),
                        header(request.headers(), tauri::http::header::ORIGIN),
                    );
                }
                responder.respond(response);
            });
        })
        .setup(|app| {
            let handle = app.handle().clone();
            let emit = Arc::new(move |event: qv_proto_api::Event| {
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = handle.emit(EVENT, json);
                }
            });
            let idle = std::env::var("QV_PROTO_IDLE_MS")
                .ok()
                .filter(|_| cfg!(debug_assertions))
                .and_then(|ms| ms.parse().ok())
                .map_or(IDLE, Duration::from_millis);
            let base = data_dir(app).map_err(|_| "data directory")?;
            let backend = Backend::open(&base, services(), emit, idle).map_err(|e| e.message())?;
            let shared = Shared(Arc::new(Mutex::new(backend)));
            app.manage(shared.clone());
            std::thread::Builder::new()
                .name("qv-proto-timers".into())
                .spawn(move || {
                    loop {
                        std::thread::sleep(Duration::from_millis(250));
                        shared.get().tick(Instant::now());
                    }
                })?;
            let window =
                WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
                    .on_navigation(allowed_document)
                    .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny);
            #[cfg(debug_assertions)]
            let window = probe(window)?;
            #[cfg(desktop)]
            let window = window
                .title("QuickVault prototype")
                .inner_size(420.0, 760.0)
                .min_inner_size(320.0, 480.0);
            window.build()?;
            #[cfg(target_os = "android")]
            android::start(app.handle().clone());
            Ok(())
        })
        .run(tauri::generate_context!());
    if result.is_err() {
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_is_the_one_the_page_calls() {
        // `qv` is the command function's name and build.rs's allowlist.
        assert_eq!(qv_proto_api::COMMAND, "qv");
    }

    #[test]
    fn bodies_are_bounded_before_copying() {
        let ok = take_body(&InvokeBody::Raw(vec![1, 2, 3])).unwrap();
        assert_eq!(&ok[..], &[1, 2, 3]);
        assert_eq!(
            take_body(&InvokeBody::Raw(vec![0; MAX_REQUEST + 1])).unwrap_err(),
            UiError::TooLarge
        );
        let json = InvokeBody::Json(serde_json::json!([123, 34, 125]));
        assert_eq!(&take_body(&json).unwrap()[..], b"{\"}");
        let big = InvokeBody::Json(serde_json::Value::Array(vec![
            serde_json::json!(0);
            MAX_REQUEST + 1
        ]));
        assert_eq!(take_body(&big).unwrap_err(), UiError::TooLarge);
        for bad in [
            serde_json::json!([256]),
            serde_json::json!([-1]),
            serde_json::json!(["a"]),
            serde_json::json!({"generation": 0}),
            serde_json::json!("text"),
        ] {
            assert_eq!(
                take_body(&InvokeBody::Json(bad)).unwrap_err(),
                UiError::Malformed
            );
        }
    }

    #[test]
    fn only_the_bundled_document_navigates() {
        let ok = |u: &str| allowed_document(&tauri::Url::parse(u).unwrap());
        assert!(ok(media::app_origin()));
        assert!(ok(&format!("{}/", media::app_origin())));
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
            if bad.starts_with(media::app_origin()) {
                continue;
            }
            assert!(!ok(bad), "{bad}");
        }
        assert!(!ok(&format!("{}/?x=1", media::app_origin())));
    }
}
