// SPDX-License-Identifier: AGPL-3.0-or-later

//! The page side of the bridge: one Tauri command over in-process IPC, one
//! event. Answers from an older lock generation are dropped (0008 §4.4).
use qv_proto_api::{Answer, COMMAND, EVENT, Envelope, Event, MAX_REQUEST, Reply, Request, UiError};
use std::cell::Cell;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI_INTERNALS__"], js_name = invoke, catch)]
    fn tauri_invoke(cmd: &str, payload: JsValue) -> Result<js_sys::Promise, JsValue>;
    #[wasm_bindgen(js_namespace = ["window", "__TAURI_INTERNALS__"], js_name = transformCallback)]
    fn transform_callback(callback: &js_sys::Function, once: bool) -> f64;
}

thread_local! {
    static GENERATION: Cell<u64> = const { Cell::new(0) };
}

/// The generation the page is showing.
pub fn generation() -> u64 {
    GENERATION.with(Cell::get)
}

/// Moves to a newer generation (from `Status` or a `Locked` event).
pub fn set_generation(g: u64) {
    GENERATION.with(|c| c.set(g));
}

fn bytes_of(value: &JsValue) -> Option<Vec<u8>> {
    if let Some(buffer) = value.dyn_ref::<js_sys::ArrayBuffer>() {
        return Some(js_sys::Uint8Array::new(buffer).to_vec());
    }
    if let Some(view) = value.dyn_ref::<js_sys::Uint8Array>() {
        return Some(view.to_vec());
    }
    if let Some(text) = value.as_string() {
        return Some(text.into_bytes());
    }
    if js_sys::Array::is_array(value) {
        let array = js_sys::Array::from(value);
        return array
            .iter()
            .map(|v| {
                v.as_f64()
                    .filter(|n| (0.0..=255.0).contains(n))
                    .map(|n| n as u8)
            })
            .collect();
    }
    None
}

/// Asks the backend. A reply from another generation than the one this
/// request was sent under is discarded as [`UiError::Stale`].
pub async fn call(request: Request) -> Result<Reply, UiError> {
    let sent = generation();
    let envelope = Envelope {
        generation: sent,
        request,
    };
    let mut body = zeroize::Zeroizing::new(Vec::with_capacity(MAX_REQUEST));
    serde_json::to_writer(&mut *body, &envelope).map_err(|_| UiError::Malformed)?;
    drop(envelope);
    if body.len() > MAX_REQUEST {
        return Err(UiError::TooLarge);
    }
    let payload = js_sys::Uint8Array::from(&body[..]);
    drop(body);
    let promise = tauri_invoke(COMMAND, payload.clone().into()).map_err(|_| UiError::Unavailable);
    // The JS copy of the request is wiped once the IPC layer has read it.
    let result = match promise {
        Ok(p) => JsFuture::from(p).await.map_err(|_| UiError::Unavailable),
        Err(e) => Err(e),
    };
    payload.fill(0, 0, payload.length());
    let raw = bytes_of(&result?).ok_or(UiError::Malformed)?;
    let raw = zeroize::Zeroizing::new(raw);
    let answer: Answer = serde_json::from_slice(&raw).map_err(|_| UiError::Malformed)?;
    if answer.generation != sent || answer.generation != generation() {
        return Err(UiError::Stale);
    }
    match answer.reply {
        Reply::Error(e) => Err(e),
        reply => Ok(reply),
    }
}

/// Like [`call`] for `Status`, which is how the page learns the generation.
pub async fn status() -> Result<Reply, UiError> {
    let envelope = Envelope {
        generation: generation(),
        request: Request::Status,
    };
    let body = serde_json::to_vec(&envelope).map_err(|_| UiError::Malformed)?;
    let payload = js_sys::Uint8Array::from(&body[..]);
    let promise = tauri_invoke(COMMAND, payload.into()).map_err(|_| UiError::Unavailable)?;
    let value = JsFuture::from(promise)
        .await
        .map_err(|_| UiError::Unavailable)?;
    let raw = bytes_of(&value).ok_or(UiError::Malformed)?;
    let answer: Answer = serde_json::from_slice(&raw).map_err(|_| UiError::Malformed)?;
    set_generation(answer.generation);
    match answer.reply {
        Reply::Error(e) => Err(e),
        reply => Ok(reply),
    }
}

/// Subscribes to backend events. The closure lives as long as the page.
pub fn listen(on_event: impl Fn(Event) + 'static) -> Result<(), UiError> {
    let handler = Closure::<dyn Fn(JsValue)>::new(move |message: JsValue| {
        let payload = js_sys::Reflect::get(&message, &JsValue::from_str("payload"))
            .ok()
            .and_then(|p| p.as_string());
        if let Some(event) = payload.and_then(|p| serde_json::from_str::<Event>(&p).ok()) {
            on_event(event);
        }
    });
    let id = transform_callback(handler.as_ref().unchecked_ref(), false);
    handler.forget();
    let args = js_sys::Object::new();
    let target = js_sys::Object::new();
    let set = |o: &js_sys::Object, k: &str, v: &JsValue| {
        js_sys::Reflect::set(o, &JsValue::from_str(k), v).map(|_| ())
    };
    set(&target, "kind", &JsValue::from_str("Any")).map_err(|_| UiError::Unavailable)?;
    set(&args, "event", &JsValue::from_str(EVENT)).map_err(|_| UiError::Unavailable)?;
    set(&args, "target", &target).map_err(|_| UiError::Unavailable)?;
    set(&args, "handler", &JsValue::from_f64(id)).map_err(|_| UiError::Unavailable)?;
    let promise =
        tauri_invoke("plugin:event|listen", args.into()).map_err(|_| UiError::Unavailable)?;
    wasm_bindgen_futures::spawn_local(async move {
        let _ = JsFuture::from(promise).await;
    });
    Ok(())
}
