// SPDX-License-Identifier: AGPL-3.0-or-later

//! The page side of the bridge (plan 0071): one Tauri command over
//! in-process IPC. Requests go out one at a time in order (typing and
//! actions must reach Rust in sequence); frames come back by long poll.
use qv_ui_api::{COMMAND, Envelope, Frame, MAX_REQUEST, Reply, Request};
use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = ["window", "__TAURI_INTERNALS__"], js_name = invoke, catch)]
    fn tauri_invoke(cmd: &str, payload: JsValue) -> Result<js_sys::Promise, JsValue>;
}

thread_local! {
    static QUEUE: RefCell<VecDeque<(u64, Request)>> = const { RefCell::new(VecDeque::new()) };
    static RUNNING: Cell<bool> = const { Cell::new(false) };
}

fn bytes_of(value: &JsValue) -> Option<Vec<u8>> {
    if let Some(buffer) = value.dyn_ref::<js_sys::ArrayBuffer>() {
        return Some(js_sys::Uint8Array::new(buffer).to_vec());
    }
    if let Some(view) = value.dyn_ref::<js_sys::Uint8Array>() {
        return Some(view.to_vec());
    }
    if js_sys::Array::is_array(value) {
        return js_sys::Array::from(value)
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

/// Sends one envelope and decodes the reply.
async fn send(generation: u64, request: Request) -> Option<Reply> {
    let envelope = Envelope {
        generation,
        request,
    };
    let mut body = zeroize::Zeroizing::new(Vec::with_capacity(1024));
    serde_json::to_writer(&mut *body, &envelope).ok()?;
    drop(envelope);
    if body.len() > MAX_REQUEST {
        return None;
    }
    let payload = js_sys::Uint8Array::from(&body[..]);
    drop(body);
    let result = match tauri_invoke(COMMAND, payload.clone().into()) {
        Ok(p) => JsFuture::from(p).await.ok(),
        Err(_) => None,
    };
    // The JS copy of the request is wiped once the IPC layer has read it.
    payload.fill(0, 0, payload.length());
    let raw = zeroize::Zeroizing::new(bytes_of(&result?)?);
    serde_json::from_slice(&raw).ok()
}

/// Queues a request; requests run one after another, in order. A newer
/// value for the same input replaces a queued older one.
pub(crate) fn enqueue(generation: u64, request: Request) {
    QUEUE.with(|q| {
        let mut q = q.borrow_mut();
        if let (Request::Input { field, .. }, Some((g, Request::Input { field: last, .. }))) =
            (&request, q.back())
            && last == field
            && *g == generation
        {
            q.pop_back();
        }
        q.push_back((generation, request));
    });
    if RUNNING.with(|r| r.replace(true)) {
        return;
    }
    wasm_bindgen_futures::spawn_local(async {
        loop {
            let Some((generation, request)) = QUEUE.with(|q| q.borrow_mut().pop_front()) else {
                break;
            };
            let _ = send(generation, request).await;
        }
        RUNNING.with(|r| r.set(false));
    });
}

/// Frames for as long as the page lives: each request waits in Rust until a
/// newer frame exists.
pub(crate) fn poll(on_frame: impl Fn(Frame) + 'static) {
    wasm_bindgen_futures::spawn_local(async move {
        let mut after = 0;
        loop {
            match send(0, Request::Frame { after }).await {
                Some(Reply::Frame(frame)) => {
                    if frame.seq > after {
                        after = frame.seq;
                        on_frame(*frame);
                    }
                }
                _ => {
                    let wait = js_sys::Promise::new(&mut |resolve, _| {
                        if let Some(w) = web_sys::window() {
                            let _ = w.set_timeout_with_callback_and_timeout_and_arguments_0(
                                &resolve, 300,
                            );
                        }
                    });
                    let _ = JsFuture::from(wait).await;
                }
            }
        }
    });
}
