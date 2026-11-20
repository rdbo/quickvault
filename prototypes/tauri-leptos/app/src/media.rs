// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `qvmedia` scheme: in-process media ranges for previews, no socket
//! (plan 0070). A request names a live token and at most one byte range; the
//! answer is at most [`MAX_RANGE`] bytes, so the engine asks again for more.
//! Unknown or revoked tokens get 404, malformed or multiple ranges 416.
use qv_proto_api::{MAX_RANGE, Ref, Sample};
use std::sync::OnceLock;
use tauri::http::{Method, Request, Response, StatusCode, header};

/// The scheme name.
pub const SCHEME: &str = "qvmedia";

static VIDEO: &[u8] = include_bytes!("../../../../crates/qv-app/tests/fixtures/preview.mp4");
static VIDEO_LONG: &[u8] =
    include_bytes!("../../../../crates/qv-app/tests/fixtures/preview-long.mp4");
static VIDEO_GOP: &[u8] =
    include_bytes!("../../../../crates/qv-app/tests/fixtures/preview-long-gop.mp4");
static TONE: &[u8] = include_bytes!("../fixtures/tone.m4a");

/// Five seconds of a 440 Hz tone, 16-bit mono PCM at 22.05 kHz.
fn wav() -> &'static [u8] {
    static WAV: OnceLock<Vec<u8>> = OnceLock::new();
    WAV.get_or_init(|| {
        const RATE: u32 = 22_050;
        const SAMPLES: u32 = RATE * 5;
        let data = SAMPLES * 2;
        let mut out = Vec::with_capacity(44 + data as usize);
        out.extend_from_slice(b"RIFF");
        out.extend_from_slice(&(36 + data).to_le_bytes());
        out.extend_from_slice(b"WAVEfmt ");
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&RATE.to_le_bytes());
        out.extend_from_slice(&(RATE * 2).to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&16u16.to_le_bytes());
        out.extend_from_slice(b"data");
        out.extend_from_slice(&data.to_le_bytes());
        for n in 0..SAMPLES {
            let t = f64::from(n) / f64::from(RATE);
            let v = (t * 440.0 * std::f64::consts::TAU).sin() * 6000.0;
            out.extend_from_slice(&(v as i16).to_le_bytes());
        }
        out
    })
}

/// A sample's bytes and MIME type.
pub fn sample(s: Sample) -> (&'static [u8], &'static str) {
    match s {
        Sample::Video => (VIDEO, "video/mp4"),
        Sample::VideoLong => (VIDEO_LONG, "video/mp4"),
        Sample::VideoGop => (VIDEO_GOP, "video/mp4"),
        Sample::AudioMp4 => (TONE, "audio/mp4"),
        Sample::Wav => (wav(), "audio/wav"),
    }
}

/// The URL the page uses for a token. Tauri maps custom schemes to
/// `http://<scheme>.localhost` on Windows and Android.
pub fn url(token: &Ref) -> String {
    if cfg!(any(windows, target_os = "android")) {
        format!("http://{SCHEME}.localhost/{}", token.hex())
    } else {
        format!("{SCHEME}://localhost/{}", token.hex())
    }
}

/// The app document's origin on this platform; also the only origin a
/// media request may carry (none is fine).
pub fn app_origin() -> &'static str {
    if cfg!(any(windows, target_os = "android")) {
        "http://tauri.localhost"
    } else {
        "tauri://localhost"
    }
}

/// One `bytes=` range of a resource of `total` bytes, clamped to
/// [`MAX_RANGE`]. `None` for anything malformed, multiple or unsatisfiable.
pub fn byte_range(header: &str, total: u64) -> Option<(u64, u64)> {
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

/// Answers one scheme request. `lookup` maps a live token to its sample.
pub fn serve(
    request: &Request<Vec<u8>>,
    lookup: impl FnOnce(&Ref) -> Option<Sample>,
) -> Response<Vec<u8>> {
    let head = request.method() == Method::HEAD;
    if !head && request.method() != Method::GET {
        return refused(StatusCode::METHOD_NOT_ALLOWED, None);
    }
    let headers = request.headers();
    let origin = headers.get(header::ORIGIN).map(|v| v.to_str());
    let cors = match origin {
        None => None,
        Some(Ok(o)) if o == app_origin() => Some(o.to_owned()),
        // WebKitGTK sends an opaque origin for media elements; never CORS.
        Some(Ok("null")) if cfg!(target_os = "linux") => None,
        Some(_) => return refused(StatusCode::FORBIDDEN, None),
    };
    let path = request.uri().path();
    let Some(token) = path.strip_prefix('/').and_then(Ref::parse) else {
        return refused(StatusCode::NOT_FOUND, None);
    };
    let Some(found) = lookup(&token) else {
        return refused(StatusCode::NOT_FOUND, None);
    };
    let (bytes, mime) = sample(found);
    let total = bytes.len() as u64;
    let mut ranges = headers.get_all(header::RANGE).iter();
    let (start, end) = match (ranges.next(), ranges.next()) {
        (None, _) => (0, (total.min(MAX_RANGE)).saturating_sub(1)),
        (Some(asked), None) => match asked.to_str().ok().and_then(|a| byte_range(a, total)) {
            Some(r) => r,
            None => return refused(StatusCode::RANGE_NOT_SATISFIABLE, Some(total)),
        },
        (Some(_), Some(_)) => return refused(StatusCode::RANGE_NOT_SATISFIABLE, Some(total)),
    };
    if total == 0 {
        return refused(StatusCode::RANGE_NOT_SATISFIABLE, Some(total));
    }
    let (Ok(s), Ok(e)) = (usize::try_from(start), usize::try_from(end)) else {
        return refused(StatusCode::RANGE_NOT_SATISFIABLE, Some(total));
    };
    let body = if head {
        Vec::new()
    } else {
        bytes.get(s..=e).map(<[u8]>::to_vec).unwrap_or_default()
    };
    let mut r = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(header::CONTENT_TYPE, mime)
        .header(header::CONTENT_LENGTH, (end - start + 1).to_string())
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
    use super::*;

    const LIVE: Ref = Ref([7; 16]);

    fn ask(method: &str, path: &str, headers: &[(&str, &str)]) -> Response<Vec<u8>> {
        let mut b = Request::builder()
            .method(method)
            .uri(format!("{SCHEME}://localhost{path}"));
        for (k, v) in headers {
            b = b.header(*k, *v);
        }
        serve(&b.body(Vec::new()).unwrap(), |t| {
            (*t == LIVE).then_some(Sample::VideoLong)
        })
    }

    fn live() -> String {
        format!("/{}", LIVE.hex())
    }

    #[test]
    fn ranges_are_answered_in_bounded_chunks() {
        let total = VIDEO_LONG.len() as u64;
        let r = ask("GET", &live(), &[("Range", "bytes=0-")]);
        assert_eq!(r.status(), 206);
        assert_eq!(r.body().len() as u64, MAX_RANGE);
        assert_eq!(
            r.headers()[header::CONTENT_RANGE],
            format!("bytes 0-{}/{total}", MAX_RANGE - 1).as_str()
        );
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(r.headers()[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(r.body()[..], VIDEO_LONG[..MAX_RANGE as usize]);
        let r = ask("GET", &live(), &[("Range", "bytes=10-19")]);
        assert_eq!(r.body()[..], VIDEO_LONG[10..20]);
        let r = ask("GET", &live(), &[("Range", "bytes=-5")]);
        assert_eq!(r.body()[..], VIDEO_LONG[VIDEO_LONG.len() - 5..]);
        // No range: the first chunk, still partial.
        let r = ask("GET", &live(), &[]);
        assert_eq!(r.status(), 206);
        assert_eq!(r.body().len() as u64, MAX_RANGE);
        let r = ask("HEAD", &live(), &[("Range", "bytes=2-4")]);
        assert_eq!(r.status(), 206);
        assert!(r.body().is_empty());
        assert_eq!(r.headers()[header::CONTENT_LENGTH], "3");
    }

    #[test]
    fn bad_ranges_tokens_methods_and_origins_are_refused() {
        let total = VIDEO_LONG.len();
        for bad in [
            "bytes=0-1,4-5".to_owned(),
            "bytes=x-1".to_owned(),
            "bytes=5-1".to_owned(),
            format!("bytes={total}-"),
            "bytes=-0".to_owned(),
            "items=0-1".to_owned(),
            "bytes=99999999999999999999-".to_owned(),
        ] {
            let r = ask("GET", &live(), &[("Range", &bad)]);
            assert_eq!(r.status(), 416, "{bad}");
            assert!(r.body().is_empty());
        }
        let r = ask(
            "GET",
            &live(),
            &[("Range", "bytes=0-1"), ("Range", "bytes=2-3")],
        );
        assert_eq!(r.status(), 416);
        assert_eq!(
            ask("GET", &format!("/{}", Ref([8; 16]).hex()), &[]).status(),
            404
        );
        assert_eq!(ask("GET", "/not-a-token", &[]).status(), 404);
        assert_eq!(ask("POST", &live(), &[]).status(), 405);
        assert_eq!(
            ask("GET", &live(), &[("Origin", "https://evil.example")]).status(),
            403
        );
        let r = ask("GET", &live(), &[("Origin", app_origin())]);
        assert_eq!(
            r.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN],
            app_origin()
        );
    }

    #[test]
    fn the_wav_is_well_formed() {
        let (w, mime) = sample(Sample::Wav);
        assert_eq!(mime, "audio/wav");
        assert_eq!(&w[..4], b"RIFF");
        assert_eq!(w.len(), 44 + 22_050 * 5 * 2);
    }
}
