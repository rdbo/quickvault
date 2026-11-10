// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded capability media responses on the existing loopback listener.
//! No request paths, capabilities or media content are logged.
use crate::hardened::{byte_range, Preview, PREVIEW_PREFIX};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

/// Read exactly through the initial header, with an absolute deadline and cap.
/// The same bytes can be replayed to tungstenite without losing a frame prefix.
pub(crate) fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let end = Instant::now() + Duration::from_secs(3);
    let mut head = Vec::with_capacity(1024);
    while head.len() < 8192 {
        let left = end.checked_duration_since(Instant::now())?;
        stream.set_read_timeout(Some(left)).ok()?;
        let mut byte = [0];
        stream.read_exact(&mut byte).ok()?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Some(head);
        }
    }
    None
}

pub(crate) fn is_preview(head: &[u8]) -> bool {
    head.split(|b| *b == b'\n')
        .next()
        .and_then(|line| line.split(|b| *b == b' ').nth(1))
        .is_some_and(|path| path.starts_with(PREVIEW_PREFIX.as_bytes()))
}
struct Request<'a> {
    path: &'a str,
    head: bool,
    range: Option<&'a str>,
    invalid_range: bool,
}
fn request(bytes: &[u8], port: u16) -> Option<Request<'_>> {
    if !bytes.is_ascii() || bytes.len() > 8192 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let text = text.strip_suffix("\r\n\r\n")?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?;
    if !matches!(method, "GET" | "HEAD") {
        return None;
    }
    let path = first.next()?;
    let token = path.strip_prefix(PREVIEW_PREFIX)?;
    if token.len() != 32
        || !token
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    if first.next()? != "HTTP/1.1" || first.next().is_some() {
        return None;
    }
    let mut names = BTreeSet::new();
    let mut host = None;
    let mut range = None;
    let mut invalid_range = false;
    for (index, line) in lines.enumerate() {
        if index == 64 {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return None;
        }
        let name = name.to_ascii_lowercase();
        if !names.insert(name.clone()) {
            if name == "range" {
                invalid_range = true;
                continue;
            }
            return None;
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return None;
        }
        match name.as_str() {
            "host" => host = Some(value),
            "range" => range = Some(value),
            "origin" if !origin(value) => return None,
            "content-length" if value != "0" => return None,
            "transfer-encoding" => return None,
            _ => {}
        }
    }
    if host != Some(format!("127.0.0.1:{port}").as_str()) {
        return None;
    }
    Some(Request {
        path,
        head: method == "HEAD",
        range,
        invalid_range,
    })
}
fn origin(value: &str) -> bool {
    #[cfg(target_os = "android")]
    {
        value == "https://dioxus.index.html"
    }
    #[cfg(not(target_os = "android"))]
    {
        matches!(value, "dioxus://index.html" | "null")
    }
}
fn error(stream: &mut TcpStream, status: u16, total: Option<u64>) -> std::io::Result<()> {
    let range = total
        .map(|n| format!("Content-Range: bytes */{n}\r\n"))
        .unwrap_or_default();
    write!(stream, "HTTP/1.1 {status} Refused\r\nContent-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n{range}\r\n")
}
/// The caller owns a connection permit through this synchronous response.
pub(crate) fn serve(stream: &mut TcpStream, bytes: &[u8], port: u16, provider: Option<&Preview>) {
    let result = (|| -> std::io::Result<()> {
        let Some(request) = request(bytes, port) else {
            return error(stream, 400, None);
        };
        let Some(served) = provider
            .and_then(|p| p(request.path))
            .filter(|s| s.body.available())
        else {
            return error(stream, 404, None);
        };
        if request.invalid_range {
            return error(stream, 416, Some(served.total));
        }
        let (start, length, status) = match request.range {
            Some(asked) => match byte_range(asked, served.total) {
                Some((start, end)) => (start, end - start + 1, 206),
                None => return error(stream, 416, Some(served.total)),
            },
            None => (0, served.total, 200),
        };
        let range = if status == 206 {
            format!(
                "Content-Range: bytes {}-{}/{}\r\n",
                start,
                start + length - 1,
                served.total
            )
        } else {
            String::new()
        };
        write!(stream, "HTTP/1.1 {status} OK\r\nContent-Length: {length}\r\nContent-Type: {}\r\nAccept-Ranges: bytes\r\nCache-Control: no-store\r\nPragma: no-cache\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'none'\r\nConnection: close\r\n{range}\r\n", served.mime)?;
        if !request.head && length != 0 {
            served.body.write_range(start, length, stream)?;
        }
        Ok(())
    })();
    // Drop/close on every failure, including revocation during streaming.
    let _ = result;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardened::{PreviewBody, Served};
    use std::net::{Shutdown, TcpListener};
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    };
    const TOKEN: &str = "/preview/0123456789abcdef0123456789abcdef";
    struct Body {
        live: AtomicBool,
        delivered: AtomicUsize,
    }
    impl PreviewBody for Body {
        fn available(&self) -> bool {
            self.live.load(Ordering::SeqCst)
        }
        fn write_range(
            &self,
            offset: u64,
            length: u64,
            output: &mut dyn Write,
        ) -> std::io::Result<()> {
            self.delivered.fetch_add(length as usize, Ordering::SeqCst);
            output.write_all(&b"0123456789"[offset as usize..(offset + length) as usize])
        }
    }
    fn exchange(method: &str, path: &str, headers: &str, live: bool) -> (String, usize) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let body = Arc::new(Body {
            live: AtomicBool::new(live),
            delivered: AtomicUsize::new(0),
        });
        let source = body.clone();
        let provider: Preview = Arc::new(move |path| {
            (path == TOKEN).then(|| Served {
                mime: "audio/wav",
                total: 10,
                body: source.clone(),
            })
        });
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            if let Some(head) = read_head(&mut stream) {
                serve(&mut stream, &head, port, Some(&provider));
            }
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            client,
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n{headers}\r\n"
        )
        .unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        worker.join().unwrap();
        (response, body.delivered.load(Ordering::SeqCst))
    }
    #[test]
    fn hardened_media_http_streams_ranges_and_head_without_response_vectors() {
        let (full, n) = exchange("GET", TOKEN, "", true);
        assert!(full.starts_with("HTTP/1.1 200"));
        assert!(full.ends_with("\r\n\r\n0123456789"));
        assert_eq!(n, 10);
        assert!(full.contains("Cache-Control: no-store") && full.contains("nosniff"));
        for (range, body, content_range) in [
            ("bytes=2-4", "234", "bytes 2-4/10"),
            ("bytes=-3", "789", "bytes 7-9/10"),
            ("bytes=0-", "0123456789", "bytes 0-9/10"),
        ] {
            let (response, n) = exchange("GET", TOKEN, &format!("Range: {range}\r\n"), true);
            assert!(response.starts_with("HTTP/1.1 206"));
            assert!(response.contains(content_range));
            assert!(response.ends_with(body));
            assert_eq!(n, body.len());
        }
        let (head, n) = exchange("HEAD", TOKEN, "Range: bytes=2-4\r\n", true);
        assert!(head.starts_with("HTTP/1.1 206") && head.contains("Content-Length: 3"));
        assert!(head.ends_with("\r\n\r\n"));
        assert_eq!(n, 0);
    }
    #[test]
    fn hardened_media_refuses_bad_ranges_without_releasing_any_plaintext() {
        for range in [
            "bytes=0-1,4-5",
            "bytes=10-",
            "bytes=4-2",
            "bytes=-0",
            "bytes=+1-2",
            "bytes=0 - 1",
            "items=1-2",
            "bytes=18446744073709551616-",
            "garbage",
        ] {
            let (response, n) = exchange("GET", TOKEN, &format!("Range: {range}\r\n"), true);
            assert!(response.starts_with("HTTP/1.1 416"), "{range}");
            assert!(response.contains("Content-Range: bytes */10"));
            assert_eq!(n, 0);
        }
        let (response, n) = exchange(
            "GET",
            TOKEN,
            "Range: bytes=0-1\r\nRange: bytes=2-3\r\n",
            true,
        );
        assert!(response.starts_with("HTTP/1.1 416"));
        assert_eq!(n, 0);
    }
    #[test]
    fn hardened_media_requires_capability_numeric_host_and_permitted_origin() {
        for headers in [
            "Host: localhost\r\n",
            "Origin: https://attacker.invalid\r\n",
            "Transfer-Encoding: chunked\r\n",
            "Content-Length: 1\r\n",
        ] {
            let (response, n) = exchange("GET", TOKEN, headers, true);
            assert!(response.starts_with("HTTP/1.1 400"));
            assert_eq!(n, 0);
        }
        let (revoked, n) = exchange("GET", TOKEN, "", false);
        assert!(revoked.starts_with("HTTP/1.1 404"));
        assert_eq!(n, 0);
        let (wrong, n) = exchange("GET", "/preview/00000000000000000000000000000000", "", true);
        assert!(wrong.starts_with("HTTP/1.1 404"));
        assert_eq!(n, 0);
        let (query, n) = exchange("GET", &format!("{TOKEN}?x=1"), "", true);
        assert!(query.starts_with("HTTP/1.1 400"));
        assert_eq!(n, 0);
        let (post, n) = exchange("POST", TOKEN, "", true);
        assert!(post.starts_with("HTTP/1.1 400"));
        assert_eq!(n, 0);
    }
    #[test]
    fn hardened_media_header_is_bounded_before_a_provider_runs() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        peer.write_all(&[b'a'; 8193]).unwrap();
        assert!(read_head(&mut stream).is_none());
    }
}
