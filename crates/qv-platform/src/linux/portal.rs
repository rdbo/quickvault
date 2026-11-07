// SPDX-License-Identifier: AGPL-3.0-or-later

//! System file picker through xdg-desktop-portal's FileChooser (0009 §1.8).
//! The user chooses in the desktop's own dialog; only a local `file:` result
//! becomes a path, which callers still check with the 0011 §4 rules. Errors
//! are redacted: no path, URI or bus message is reported.
use crate::PlatformError;
use futures_lite::{StreamExt, future};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;
use zbus::{MatchRule, MessageStream, Proxy, Variant, message::Type, wire::OwnedVariant};

const PORTAL: &str = "org.freedesktop.portal.Desktop";
const PATH: &str = "/org/freedesktop/portal/desktop";
const CHOOSER: &str = "org.freedesktop.portal.FileChooser";
const REQUEST: &str = "org.freedesktop.portal.Request";
/// Longest accepted result path, in bytes.
pub const MAX_PICKED: usize = 4096;
/// A user may take a while to choose; the dialog is closed after this.
const CHOOSE_FOR: Duration = Duration::from_secs(600);
const QUEUE: std::num::NonZeroUsize = match std::num::NonZeroUsize::new(4) {
    Some(n) => n,
    None => std::num::NonZeroUsize::MIN,
};

/// What the picker chooses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pick {
    /// An existing file to read.
    Open,
    /// A new file to write, suggesting this file name.
    Save(String),
    /// An existing folder.
    Folder,
}

/// Show the desktop's file picker and wait for the user's choice. `Ok(None)`
/// means the user cancelled. Without a portal this is `Unavailable`.
pub fn pick(title: &str, kind: &Pick) -> Result<Option<PathBuf>, PlatformError> {
    let builder = zbus::connection::Builder::session();
    future::block_on(future::or(choose(builder, title, kind), async {
        async_io::Timer::after(CHOOSE_FOR).await;
        Err(PlatformError::Cancelled)
    }))
}

async fn choose(
    builder: zbus::connection::Builder<'_>,
    title: &str,
    kind: &Pick,
) -> Result<Option<PathBuf>, PlatformError> {
    let map = |_| PlatformError::Unavailable;
    let conn = builder.max_queued(QUEUE).build().await.map_err(map)?;
    // The request object path is predictable from our bus name and a token,
    // so subscribe to its Response before asking (no reply/signal race).
    let sender = conn.unique_name().ok_or(PlatformError::Unavailable)?;
    let token = format!("qv{}", std::process::id());
    let request = format!(
        "{PATH}/request/{}/{token}",
        sender.as_str().trim_start_matches(':').replace('.', "_")
    );
    let rule = MatchRule::builder()
        .msg_type(Type::Signal)
        .interface(REQUEST)
        .member("Response")
        .path(request.as_str())
        .build()
        .map_err(map)?;
    let mut responses = MessageStream::for_match_rule(rule, &conn, Some(QUEUE))
        .await
        .map_err(map)?;
    let chooser = Proxy::new(&conn, PORTAL, PATH, CHOOSER)
        .await
        .map_err(map)?;
    let mut options: HashMap<&str, Variant<'_>> = HashMap::new();
    options.insert("handle_token", Variant::from(token.as_str()));
    options.insert("modal", Variant::from(true));
    let method = match kind {
        Pick::Open => "OpenFile",
        Pick::Folder => {
            options.insert("directory", Variant::from(true));
            "OpenFile"
        }
        Pick::Save(name) => {
            options.insert("current_name", Variant::from(name.as_str()));
            "SaveFile"
        }
    };
    let _handle: zbus::OwnedObjectPath = chooser
        .call(method, &("", title, options))
        .await
        .map_err(map)?;
    while let Some(message) = responses.next().await {
        let Ok(message) = message else { continue };
        let Ok((code, results)) = message
            .body()
            .deserialize::<(u32, HashMap<String, OwnedVariant>)>()
        else {
            continue;
        };
        if code != 0 {
            return Ok(None);
        }
        let uri = results
            .get("uris")
            .and_then(|v| Vec::<String>::try_from(v.clone()).ok())
            .and_then(|uris| uris.into_iter().next())
            .ok_or(PlatformError::Unavailable)?;
        return uri_to_path(&uri)
            .map(Some)
            .ok_or(PlatformError::Unavailable);
    }
    Err(PlatformError::Unavailable)
}

/// A local absolute path from a `file:` URI, or `None` for anything else.
pub fn uri_to_path(uri: &str) -> Option<PathBuf> {
    let rest = uri.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') || rest.len() > MAX_PICKED * 3 {
        return None;
    }
    let mut bytes = Vec::with_capacity(rest.len());
    let mut it = rest.bytes();
    while let Some(b) = it.next() {
        if b == b'%' {
            let hi = hex(it.next()?)?;
            let lo = hex(it.next()?)?;
            bytes.push(hi << 4 | lo);
        } else if b == b'?' || b == b'#' {
            return None;
        } else {
            bytes.push(b);
        }
    }
    if bytes.contains(&0) || bytes.len() > MAX_PICKED {
        return None;
    }
    use std::os::unix::ffi::OsStringExt;
    Some(PathBuf::from(std::ffi::OsString::from_vec(bytes)))
}
fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn portal_uri_to_path_accepts_only_local_absolute_files() {
        assert_eq!(
            uri_to_path("file:///home/a/My%20Vault.qvault"),
            Some(PathBuf::from("/home/a/My Vault.qvault"))
        );
        assert_eq!(
            uri_to_path("file://localhost/tmp/x"),
            Some(PathBuf::from("/tmp/x"))
        );
        for bad in [
            "https://example.invalid/x",
            "file://other-host/x",
            "file:relative",
            "file:///a%00b",
            "file:///a%zz",
            "file:///a%4",
            "file:///a?b",
            "/plain/path",
        ] {
            assert_eq!(uri_to_path(bad), None, "{bad}");
        }
        let long = format!("file:///{}", "a".repeat(MAX_PICKED + 1));
        assert_eq!(uri_to_path(&long), None);
    }
    /// Against a real or mock portal on the bus in `QV_TEST_PORTAL_BUS`
    /// (skipped when unset): a pick must answer, not hang.
    #[test]
    fn portal_pick_answers_on_a_live_bus() {
        let Ok(address) = std::env::var("QV_TEST_PORTAL_BUS") else {
            return;
        };
        for kind in [Pick::Open, Pick::Save("x.qvault".into()), Pick::Open] {
            let builder = zbus::connection::Builder::address(address.as_str());
            let result = future::block_on(future::or(choose(builder, "Open", &kind), async {
                async_io::Timer::after(Duration::from_secs(15)).await;
                Err(PlatformError::Cancelled)
            }));
            assert_eq!(result, Ok(Some(PathBuf::from("/tmp/picked file.qvault"))));
        }
    }
    #[test]
    fn portal_without_a_session_bus_is_unavailable() {
        // Point the session bus at a socket that does not exist.
        let dir = std::env::temp_dir().join(format!("qv-portal-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap_or(());
        let address = format!("unix:path={}/missing", dir.display());
        let builder = zbus::connection::Builder::address(address.as_str());
        let result = future::block_on(choose(builder, "Open", &Pick::Open));
        assert_eq!(result, Err(PlatformError::Unavailable));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
