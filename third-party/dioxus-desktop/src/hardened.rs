// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault's opt-in webview boundary. No raw input is included in errors.
use crate::ipc::IpcMessage;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};

/// Compiled assets for the restricted local document. No filesystem fallback.
#[derive(Clone, Default)]
pub struct HardenedWebview {
    /// Absolute local route → (MIME type, compiled bytes).
    pub assets: BTreeMap<&'static str, (&'static str, &'static [u8])>,
}
/// Maximum native IPC or decoded synchronous-event body.
pub const MAX_INPUT: usize = 64 * 1024;
/// Exact bundled main document on supported platforms.
pub fn local_document(uri: &str) -> bool {
    #[cfg(target_os = "android")]
    {
        uri == "https://dioxus.index.html/"
    }
    #[cfg(not(target_os = "android"))]
    {
        uri == "dioxus://index.html/"
    }
}
/// Only one initial main-document navigation is permitted.
pub fn navigation(uri: &str, loaded: &AtomicBool) -> bool {
    local_document(uri) && !loaded.swap(true, Ordering::SeqCst)
}
/// CSP permits only packaged code and this process's exact loopback endpoint.
pub fn csp(edits: &str) -> String {
    // edits is constructed by the framework from its own listener, not IPC.
    let endpoint = edits.split('/').take(3).collect::<Vec<_>>().join("/");
    format!("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self' {endpoint}; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'")
}

// Reject duplicate object keys at every level instead of silently taking the last.
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded JSON")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Unique, E> {
                Ok(Unique(Value::from(v)))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Unique, E> {
                Ok(Unique(v.into()))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_none<E: de::Error>(self) -> Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = Vec::new();
                while let Some(Unique(v)) = a.next_element()? {
                    out.push(v)
                }
                Ok(Unique(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Unique, A::Error> {
                let mut out = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if out.contains_key(&k) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let Unique(v) = a.next_value()?;
                    out.insert(k, v);
                }
                Ok(Unique(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}
pub(crate) fn json(bytes: &[u8]) -> Option<Value> {
    if bytes.len() > MAX_INPUT {
        return None;
    }
    serde_json::from_slice::<Unique>(bytes).ok().map(|v| v.0)
}
pub(crate) fn event(value: Value) -> Option<dioxus_html::HtmlEvent> {
    let obj = value.as_object()?;
    if obj.len() != 4
        || !matches!(
            obj.get("name")?.as_str()?,
            "click" | "input" | "change" | "keydown" | "keyup" | "focus" | "blur"
        )
    {
        return None;
    }
    // File access is absent from this application bridge, including forged form data.
    if let Some(values) = obj.get("data")?.get("values").and_then(Value::as_array) {
        if values
            .iter()
            .any(|v| v.get("file").is_some_and(|v| !v.is_null()))
        {
            return None;
        }
    }
    serde_json::from_value(value).ok()
}
#[derive(Debug)]
pub(crate) struct Permit(Arc<AtomicUsize>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
/// Native ingress before the event loop queue. Failed input is never logged.
pub(crate) fn ipc(
    origin: &str,
    body: &str,
    initialized: &AtomicBool,
    queued: &Arc<AtomicUsize>,
) -> Option<IpcMessage> {
    if !local_document(origin) {
        return None;
    }
    let value = json(body.as_bytes())?;
    let obj = value.as_object()?;
    if obj.len() != 2 {
        return None;
    }
    let method = obj.get("method")?.as_str()?;
    match method {
        "initialize" if obj.get("params")?.as_object()?.is_empty() => {
            if initialized.swap(true, Ordering::SeqCst) {
                return None;
            }
        }
        "user_event" if initialized.load(Ordering::SeqCst) => {
            event(obj.get("params")?.clone())?;
        }
        _ => return None,
    }
    queued
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < 32).then_some(n + 1)
        })
        .ok()?;
    let mut msg: IpcMessage = serde_json::from_value(value).ok()?;
    msg.permit = Some(Arc::new(Permit(queued.clone())));
    Some(msg)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hardened_navigation_only_exact_initial_document() {
        let loaded = AtomicBool::new(false);
        for uri in [
            "https://evil.example/",
            "dioxus://index.html.evil/",
            "dioxus://index.html/else",
            "javascript:alert(1)",
            "file:///etc/passwd",
        ] {
            assert!(!navigation(uri, &loaded));
        }
        assert!(navigation("dioxus://index.html/", &loaded));
        assert!(!navigation("dioxus://index.html/", &loaded));
    }
    #[test]
    fn hardened_native_ingress_rejects_oversize_duplicates_methods_and_queue_flood() {
        let init = AtomicBool::new(false);
        let pending = Arc::new(AtomicUsize::new(0));
        let origin = "dioxus://index.html/";
        for body in [
            r#"{"method":"query","params":{}}"#,
            r#"{"method":"initialize","method":"initialize","params":{}}"#,
            r#"{"method":"initialize","params":{"x":1,"x":2}}"#,
        ] {
            assert!(ipc(origin, body, &init, &pending).is_none());
        }
        assert!(json(&vec![b' '; MAX_INPUT + 1]).is_none());
        assert!(json(format!("{}0{}", "[".repeat(256), "]".repeat(256)).as_bytes()).is_none());
        assert!(ipc(
            "https://evil/",
            r#"{"method":"initialize","params":{}}"#,
            &init,
            &pending
        )
        .is_none());
        let msg = ipc(
            origin,
            r#"{"method":"initialize","params":{}}"#,
            &init,
            &pending,
        )
        .unwrap();
        assert_eq!(pending.load(Ordering::SeqCst), 1);
        assert!(!format!("{msg:?}").contains("params"));
        drop(msg);
        assert_eq!(pending.load(Ordering::SeqCst), 0);
        let mut messages = Vec::new();
        for _ in 0..32 {
            let fresh = AtomicBool::new(false);
            messages.push(
                ipc(
                    origin,
                    r#"{"method":"initialize","params":{}}"#,
                    &fresh,
                    &pending,
                )
                .unwrap(),
            );
        }
        assert!(ipc(
            origin,
            r#"{"method":"initialize","params":{}}"#,
            &AtomicBool::new(false),
            &pending
        )
        .is_none());
        drop(messages);
        assert_eq!(pending.load(Ordering::SeqCst), 0);
        assert!(ipc(
            origin,
            r#"{"method":"initialize","params":{}}"#,
            &init,
            &pending
        )
        .is_none());
    }
}
