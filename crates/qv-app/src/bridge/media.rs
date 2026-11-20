// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `qvmedia` scheme (0003 §6.4, 0008 §4, plan 0071): in-process media
//! ranges for the open preview, no socket. A request names the preview's
//! token and at most one byte range; the answer is at most 64 KiB read into
//! a protected buffer, so the engine and `player.js` ask again for the rest.
//! Unknown or revoked tokens get 404, malformed or multiple ranges 416.
use qv_ui_api::MAX_RANGE;
use tauri::http::{Method, Request, Response, StatusCode, header};
use zeroize::Zeroizing;

/// The scheme name.
pub(crate) const SCHEME: &str = "qvmedia";

/// The URL the page uses for a preview route (`/preview/<token>`). Tauri
/// maps custom schemes to `http://<scheme>.localhost` on Windows and Android.
pub(crate) fn url(route: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(64));
    if cfg!(any(windows, target_os = "android")) {
        out.push_str("http://");
        out.push_str(SCHEME);
        out.push_str(".localhost");
    } else {
        out.push_str(SCHEME);
        out.push_str("://localhost");
    }
    out.push_str(route);
    out
}

/// The app document's origin; the only origin a media request may carry.
pub(crate) fn app_origin() -> &'static str {
    if cfg!(any(windows, target_os = "android")) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    }
}

/// One `bytes=` range of a resource of `total` bytes, clamped to
/// [`MAX_RANGE`]. `None` for anything malformed, multiple or unsatisfiable.
pub(crate) fn byte_range(header: &str, total: u64) -> Option<(u64, u64)> {
    if header.len() > 256 || total == 0 {
        return None;
    }
    let spec = header.trim().strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None;
    }
    let (a, b) = spec.split_once('-')?;
    let digits = |s: &str| s.bytes().all(|c| c.is_ascii_digit()) && s.len() <= 19;
    if !digits(a) || !digits(b) {
        return None;
    }
    let (start, end) = if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 {
            return None;
        }
        (total.saturating_sub(n), total - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        let end = if b.is_empty() {
            total - 1
        } else {
            b.parse::<u64>().ok()?.min(total - 1)
        };
        (start, end)
    };
    if start > end || start >= total {
        return None;
    }
    Some((start, end.min(start + MAX_RANGE - 1)))
}

fn refused(status: StatusCode, total: Option<u64>) -> Response<Vec<u8>> {
    let mut r = Response::builder()
        .status(status)
        .header(header::CACHE_CONTROL, "no-store");
    if let Some(n) = total {
        r = r.header(header::CONTENT_RANGE, format!("bytes */{n}"));
    }
    r.body(Vec::new()).unwrap_or_default()
}

/// The media source a route names: type, size and a range reader.
pub(crate) trait Source {
    /// Type and size of a live preview route.
    fn describe(&self, path: &str) -> Option<(&'static str, u64)>;
    /// One range of it, at most [`MAX_RANGE`] bytes.
    fn read(&self, path: &str, offset: u64, length: usize) -> Option<qv_core::SecretBytes>;
}

/// The app's open preview (`preview.rs`).
pub(crate) struct Preview;
impl Source for Preview {
    fn describe(&self, path: &str) -> Option<(&'static str, u64)> {
        crate::preview::describe(path)
    }
    fn read(&self, path: &str, offset: u64, length: usize) -> Option<qv_core::SecretBytes> {
        crate::preview::read(path, offset, length)
    }
}

/// Answers one scheme request. The response body is a framework copy
/// handed to the engine (0008 §4.4); the protected read is dropped here.
pub(crate) fn serve(request: &Request<Vec<u8>>, source: &dyn Source) -> Response<Vec<u8>> {
    let head = request.method() == Method::HEAD;
    if !head && request.method() != Method::GET {
        return refused(StatusCode::METHOD_NOT_ALLOWED, None);
    }
    let headers = request.headers();
    let cors = match headers.get(header::ORIGIN).map(|v| v.to_str()) {
        None => None,
        Some(Ok(o)) if o == app_origin() => Some(o.to_owned()),
        // WebKitGTK sends an opaque origin for media elements; never CORS.
        Some(Ok("null")) if cfg!(target_os = "linux") => None,
        Some(_) => return refused(StatusCode::FORBIDDEN, None),
    };
    let path = request.uri().path();
    if !path.starts_with("/preview/") || path.len() > 64 {
        return refused(StatusCode::NOT_FOUND, None);
    }
    let Some((mime, total)) = source.describe(path) else {
        return refused(StatusCode::NOT_FOUND, None);
    };
    if total == 0 {
        return refused(StatusCode::RANGE_NOT_SATISFIABLE, Some(total));
    }
    let mut ranges = headers.get_all(header::RANGE).iter();
    let (start, end) = match (ranges.next(), ranges.next()) {
        (None, _) => (0, total.min(MAX_RANGE) - 1),
        (Some(asked), None) => match asked.to_str().ok().and_then(|a| byte_range(a, total)) {
            Some(r) => r,
            None => return refused(StatusCode::RANGE_NOT_SATISFIABLE, Some(total)),
        },
        (Some(_), Some(_)) => return refused(StatusCode::RANGE_NOT_SATISFIABLE, Some(total)),
    };
    let length = end - start + 1;
    let body = if head {
        Vec::new()
    } else {
        let Some(bytes) = usize::try_from(length)
            .ok()
            .and_then(|n| source.read(path, start, n))
        else {
            return refused(StatusCode::NOT_FOUND, None);
        };
        bytes.expose_secret().to_vec()
    };
    let mut r = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, length.to_string())
        .header(
            header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{total}"),
        )
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::PRAGMA, "no-cache")
        .header(header::X_CONTENT_TYPE_OPTIONS, "nosniff")
        .header(header::REFERRER_POLICY, "no-referrer")
        .header(header::CONTENT_SECURITY_POLICY, "default-src 'none'");
    if let Some(o) = cors {
        r = r
            .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, o)
            .header(header::VARY, "Origin");
    }
    r.body(body).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    const LIVE: &str = "/preview/0123456789abcdef0123456789abcdef";

    struct Fake(Vec<u8>);
    impl Source for Fake {
        fn describe(&self, path: &str) -> Option<(&'static str, u64)> {
            (path == LIVE).then_some(("video/mp4", self.0.len() as u64))
        }
        fn read(&self, path: &str, offset: u64, length: usize) -> Option<qv_core::SecretBytes> {
            assert!(length as u64 <= MAX_RANGE, "no read over 64 KiB");
            let at = usize::try_from(offset).ok()?;
            let bytes = self.0.get(at..at + length)?;
            (path == LIVE).then(|| {
                qv_core::SecretBytes::try_init(length, |o| {
                    o.copy_from_slice(bytes);
                    Ok::<(), ()>(())
                })
                .unwrap()
            })
        }
    }

    fn fake() -> Fake {
        Fake((0..200_000u32).map(|n| (n % 251) as u8).collect())
    }

    fn ask(method: &str, path: &str, headers: &[(&str, &str)]) -> Response<Vec<u8>> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{SCHEME}://localhost{path}"));
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        serve(&b.body(Vec::new()).unwrap(), &fake())
    }

    #[test]
    fn ranges_are_answered_in_bounded_chunks() {
        let data = fake().0;
        let r = ask("GET", LIVE, &[("Range", "bytes=0-")]);
        assert_eq!(r.status(), 206);
        assert_eq!(r.body().len() as u64, MAX_RANGE);
        assert_eq!(r.body()[..], data[..MAX_RANGE as usize]);
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(r.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        let r = ask("GET", LIVE, &[("Range", "bytes=10-19")]);
        assert_eq!(r.body()[..], data[10..20]);
        let r = ask("GET", LIVE, &[("Range", "bytes=-5")]);
        assert_eq!(r.body()[..], data[data.len() - 5..]);
        let r = ask("GET", LIVE, &[]);
        assert_eq!(r.status(), 206);
        let r = ask("HEAD", LIVE, &[("Range", "bytes=2-4")]);
        assert!(r.body().is_empty());
        assert_eq!(r.headers()[header::CONTENT_LENGTH], "3");
    }

    // 0012 §1: Webview exposure
    #[test]
    fn bad_ranges_routes_methods_and_origins_are_refused() {
        for bad in [
            "bytes=0-1,4-5",
            "bytes=x-1",
            "bytes=5-1",
            "bytes=200000-",
            "bytes=-0",
            "items=0-1",
            "bytes=99999999999999999999-",
        ] {
            let r = ask("GET", LIVE, &[("Range", bad)]);
            assert_eq!(r.status(), 416, "{bad}");
            assert!(r.body().is_empty());
        }
        assert_eq!(
            ask(
                "GET",
                LIVE,
                &[("Range", "bytes=0-1"), ("Range", "bytes=2-3")]
            )
            .status(),
            416
        );
        assert_eq!(
            ask("GET", "/preview/ffffffffffffffffffffffffffffffff", &[]).status(),
            404
        );
        assert_eq!(ask("GET", "/other", &[]).status(), 404);
        assert_eq!(ask("POST", LIVE, &[]).status(), 405);
        assert_eq!(
            ask("GET", LIVE, &[("Origin", "https://evil.example")]).status(),
            403
        );
        let r = ask("GET", LIVE, &[("Origin", app_origin())]);
        assert_eq!(
            r.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            app_origin()
        );
        assert!(url("/preview/x").ends_with("/preview/x"));
    }
}
