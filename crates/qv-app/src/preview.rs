// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-app attachment previews (0003 §6.4, 0009 §1.8; plan 0044).
//!
//! On an explicit action the whole attachment is decrypted into a protected
//! buffer, accepted only after the store verified its content hash, and
//! identified from its bytes against an allow-list (the stored MIME type and
//! name are never trusted for rendering). One preview is active at a time:
//! - images, audio and video are served to the webview from memory, at a
//!   `/preview/<128-bit random token>` route on the app's own origin
//!   (vendored `hardened` provider), with `no-store`;
//! - UTF-8 text is decoded into a zeroizing string and rendered as text.
//!
//! Nothing is written to disk. Closing, navigating away and locking wipe the
//! buffer and the token. Copies made by the framework (response bodies) and
//! by webview decoders follow 0008's best-effort cleanup limits.
use std::io::Write;
use std::sync::{Mutex, PoisonError};

use qv_core::SecretBytes;
use zeroize::Zeroizing;

use crate::controller::AppError;

/// What a preview can show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// PNG, JPEG, GIF or WebP.
    Image,
    /// MP3, Ogg, WAV, FLAC or MP4 audio.
    Audio,
    /// MP4 or WebM video.
    Video,
    /// UTF-8 text.
    Text,
    /// Anything else: offer only "Save a copy".
    Unsupported,
}

/// Text larger than this is not previewed as text.
pub const TEXT_MAX: usize = 2 * 1024 * 1024;
/// At most this much text is shown; the rest is noted as cut.
pub const TEXT_SHOWN: usize = 1024 * 1024;

/// Identifies content from its leading bytes. Only the listed signatures are
/// rendered; SVG, HTML, PDF and scripts are never anything but
/// [`Kind::Unsupported`] (text that looks like markup still renders as text).
pub fn sniff(b: &[u8]) -> (Kind, &'static str) {
    let at = |i: usize, sig: &[u8]| b.get(i..i + sig.len()) == Some(sig);
    if at(0, b"\x89PNG\r\n\x1a\n") {
        return (Kind::Image, "image/png");
    }
    if at(0, b"\xff\xd8\xff") {
        return (Kind::Image, "image/jpeg");
    }
    if at(0, b"GIF87a") || at(0, b"GIF89a") {
        return (Kind::Image, "image/gif");
    }
    if at(0, b"RIFF") && at(8, b"WEBP") {
        return (Kind::Image, "image/webp");
    }
    if at(0, b"RIFF") && at(8, b"WAVE") {
        return (Kind::Audio, "audio/wav");
    }
    if at(0, b"OggS") {
        return (Kind::Audio, "audio/ogg");
    }
    if at(0, b"fLaC") {
        return (Kind::Audio, "audio/flac");
    }
    // An MPEG audio Layer III frame header: sync, a valid version, a real
    // bitrate and sample rate (so a UTF-16 byte-order mark is not audio).
    let mp3_frame = b.len() >= 3
        && b[0] == 0xff
        && b[1] & 0xe0 == 0xe0
        && (b[1] >> 3) & 3 != 1
        && (b[1] >> 1) & 3 == 1
        && !matches!(b[2] >> 4, 0 | 15)
        && (b[2] >> 2) & 3 != 3;
    if at(0, b"ID3") || mp3_frame {
        return (Kind::Audio, "audio/mpeg");
    }
    if at(4, b"ftyp") {
        // MP4 family: audio-only brands are audio, the rest video.
        return match b.get(8..12) {
            Some(b"M4A " | b"M4B ") => (Kind::Audio, "audio/mp4"),
            Some(b"isom" | b"iso2" | b"mp41" | b"mp42" | b"avc1" | b"M4V " | b"dash") => {
                (Kind::Video, "video/mp4")
            }
            _ => (Kind::Unsupported, "application/octet-stream"),
        };
    }
    if at(0, b"\x1a\x45\xdf\xa3") {
        return (Kind::Video, "video/webm");
    }
    // Documents and archives are never shown, not even as text.
    if at(0, b"%PDF-") || at(0, b"PK\x03\x04") || at(0, b"\x7fELF") {
        return (Kind::Unsupported, "application/octet-stream");
    }
    // Text: valid UTF-8 whose head has no control characters other than
    // tab, line feed, form feed and carriage return.
    let head = &b[..b.len().min(8192)];
    let plain = head
        .iter()
        .all(|c| *c >= 0x20 || matches!(c, b'\t' | b'\n' | 0x0c | b'\r'));
    if b.len() <= TEXT_MAX && plain && std::str::from_utf8(b).is_ok() {
        return (Kind::Text, "text/plain; charset=utf-8");
    }
    (Kind::Unsupported, "application/octet-stream")
}

/// A writer into a fixed protected buffer that refuses to overflow it.
pub(crate) struct Bounded {
    buf: SecretBytes,
    len: usize,
}
impl Bounded {
    /// A buffer for exactly `size` bytes (the summary's verified size).
    pub(crate) fn new(size: u64) -> Result<Self, AppError> {
        if size > crate::documents::MAX_ATTACHMENT {
            return Err(AppError::TooLargeForApp);
        }
        let n = usize::try_from(size).map_err(|_| AppError::TooLargeForApp)?;
        Ok(Self {
            buf: SecretBytes::zeroed(n),
            len: 0,
        })
    }
    /// The content, only if exactly the expected size arrived.
    pub(crate) fn finish(self) -> Result<SecretBytes, AppError> {
        if self.len == self.buf.len() {
            Ok(self.buf)
        } else {
            Err(AppError::PreviewUnavailable)
        }
    }
}
impl Write for Bounded {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let end = self
            .len
            .checked_add(data.len())
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| std::io::Error::other("attachment larger than its size"))?;
        self.buf.expose_secret_mut()[self.len..end].copy_from_slice(data);
        self.len = end;
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The renderer's view of the open preview.
#[derive(Clone, PartialEq)]
pub struct PreviewView {
    /// The attachment.
    pub handle: qv_core::AttachmentHandle,
    /// The entry it belongs to.
    pub entry: qv_core::EntryHandle,
    /// Untrusted name, shown as text.
    pub name: Zeroizing<String>,
    /// Content length.
    pub size: u64,
    /// What it is.
    pub kind: Kind,
    /// The sniffed type.
    pub mime: &'static str,
    /// The media route (images, audio, video).
    pub src: Option<String>,
    /// Decoded text (text only), at most [`TEXT_SHOWN`] bytes.
    pub text: Option<Zeroizing<String>>,
    /// The text was cut at [`TEXT_SHOWN`].
    pub cut: bool,
    /// Position among the entry's attachments (from 0) and their count.
    pub index: usize,
    /// Number of attachments on the entry.
    pub count: usize,
}

// Read only by the webview route, which exists in desktop/Android builds.
#[cfg_attr(not(any(test, feature = "desktop")), allow(dead_code))]
struct Active {
    token: SecretBytes,
    mime: &'static str,
    bytes: SecretBytes,
}
static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// What [`open`] made of the content.
pub(crate) struct Opened {
    pub(crate) kind: Kind,
    pub(crate) mime: &'static str,
    /// The media route, for images, audio and video.
    pub(crate) src: Option<String>,
    /// The decoded text, for text.
    pub(crate) text: Option<Zeroizing<String>>,
    /// The text was cut at [`TEXT_SHOWN`].
    pub(crate) cut: bool,
}
/// Registers decrypted, verified content as the one active preview
/// (wiping any previous one).
pub(crate) fn open(bytes: SecretBytes) -> Result<Opened, AppError> {
    let (kind, mime) = sniff(bytes.expose_secret());
    close();
    let mut out = Opened {
        kind,
        mime,
        src: None,
        text: None,
        cut: false,
    };
    match kind {
        Kind::Text => {
            let all = std::str::from_utf8(bytes.expose_secret())
                .map_err(|_| AppError::PreviewUnavailable)?;
            let mut end = all.len().min(TEXT_SHOWN);
            while !all.is_char_boundary(end) {
                end -= 1;
            }
            out.text = Some(Zeroizing::new(all[..end].to_owned()));
            out.cut = end < all.len();
        }
        Kind::Image | Kind::Audio | Kind::Video => {
            let token = SecretBytes::random(16).map_err(|_| AppError::Unavailable)?;
            out.src = Some(format!("preview/{}", hex(token.expose_secret())));
            *ACTIVE.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(Active { token, mime, bytes });
        }
        Kind::Unsupported => {}
    }
    Ok(out)
}

/// Wipes and unregisters the active preview (close, navigation, lock).
pub(crate) fn close() {
    // Dropping SecretBytes zeroizes it.
    drop(ACTIVE.lock().unwrap_or_else(PoisonError::into_inner).take());
}

/// Whether a preview is registered.
#[cfg(test)]
pub(crate) fn active() -> bool {
    ACTIVE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some()
}

/// The content for `/preview/<hex token>`: only the exact current token, in
/// constant time; an optional single byte range.
#[cfg(any(test, feature = "desktop"))]
pub(crate) fn content(
    path: &str,
    range: Option<(u64, u64)>,
) -> Option<(&'static str, u64, u64, Vec<u8>)> {
    use ctutils::CtEq;
    let asked = path.strip_prefix("/preview/")?;
    let guard = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
    let a = guard.as_ref()?;
    let want = hex(a.token.expose_secret());
    if asked.len() != want.len() || !asked.as_bytes().ct_eq(want.as_bytes()).to_bool() {
        return None;
    }
    let all = a.bytes.expose_secret();
    let total = all.len() as u64;
    let (start, end) = range.unwrap_or((0, total.saturating_sub(1)));
    let (s, e) = (usize::try_from(start).ok()?, usize::try_from(end).ok()?);
    let body = all.get(s..=e.min(all.len().checked_sub(1)?))?.to_vec();
    Some((a.mime, total, start, body))
}

/// The vendored webview provider (desktop and Android builds).
#[cfg(feature = "desktop")]
pub(crate) fn serve(path: &str, range: Option<&str>) -> Option<dioxus_desktop::hardened::Served> {
    let total = {
        let guard = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
        guard.as_ref()?.bytes.len() as u64
    };
    let range = range.and_then(|r| dioxus_desktop::hardened::byte_range(r, total));
    let (mime, total, start, body) = content(path, range)?;
    Some(dioxus_desktop::hardened::Served {
        mime,
        total,
        start,
        body,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn sniffing_is_an_allow_list_by_content() {
        let cases: &[(&[u8], Kind, &str)] = &[
            (b"\x89PNG\r\n\x1a\n....", Kind::Image, "image/png"),
            (b"\xff\xd8\xff\xe0....", Kind::Image, "image/jpeg"),
            (b"GIF89a....", Kind::Image, "image/gif"),
            (b"RIFF\0\0\0\0WEBPVP8 ", Kind::Image, "image/webp"),
            (b"RIFF\0\0\0\0WAVEfmt ", Kind::Audio, "audio/wav"),
            (b"OggS\0\x02....", Kind::Audio, "audio/ogg"),
            (b"fLaC....", Kind::Audio, "audio/flac"),
            (b"ID3\x04\0....", Kind::Audio, "audio/mpeg"),
            (b"\xff\xfb\x90\x00", Kind::Audio, "audio/mpeg"),
            (b"\0\0\0\x20ftypM4A \0\0", Kind::Audio, "audio/mp4"),
            (b"\0\0\0\x20ftypisom\0\0", Kind::Video, "video/mp4"),
            (b"\x1a\x45\xdf\xa3....", Kind::Video, "video/webm"),
            (b"hello\nworld", Kind::Text, "text/plain; charset=utf-8"),
            (
                "caf\u{e9} \u{1f511}".as_bytes(),
                Kind::Text,
                "text/plain; charset=utf-8",
            ),
        ];
        for (b, kind, mime) in cases {
            assert_eq!(sniff(b), (*kind, *mime), "{b:?}");
        }
        // Markup is text (rendered as text), never an image or a document.
        assert_eq!(
            sniff(b"<svg xmlns='http://www.w3.org/2000/svg'><script/></svg>").0,
            Kind::Text
        );
        assert_eq!(sniff(b"<!doctype html><script>x</script>").0, Kind::Text);
        for refused in [
            &b"%PDF-1.7\n%\xe2\xe3\xcf\xd3"[..],
            b"\0\0\0\x20ftypqt  ",
            b"PK\x03\x04....",
            b"\x89PNG",
            b"RIFF\0\0\0\0AVI ",
            b"text\0with nul",
            b"bell\x07ring",
            b"\x7fELF\x02\x01",
            b"\xff\xfe\xfd",
        ] {
            assert_eq!(sniff(refused).0, Kind::Unsupported, "{refused:?}");
        }
        let big = vec![b'a'; TEXT_MAX + 1];
        assert_eq!(sniff(&big).0, Kind::Unsupported);
    }

    #[test]
    fn the_bounded_writer_refuses_overflow_and_short_content() {
        let mut w = Bounded::new(4).unwrap();
        w.write_all(b"ab").unwrap();
        assert!(w.write_all(b"cde").is_err());
        assert_eq!(w.finish().err(), Some(AppError::PreviewUnavailable));
        let mut w = Bounded::new(3).unwrap();
        w.write_all(b"abc").unwrap();
        assert_eq!(w.finish().unwrap().expose_secret(), b"abc");
        assert!(Bounded::new(crate::documents::MAX_ATTACHMENT + 1).is_err());
    }

    #[test]
    fn only_the_current_token_serves_and_close_wipes_it() {
        let _g = crate::workspace_tests::KDF
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend_from_slice(&[7; 24]);
        let o = open(crate::workspace::protect(&png).unwrap()).unwrap();
        assert_eq!((o.kind, o.mime), (Kind::Image, "image/png"));
        assert!(o.text.is_none());
        let path = format!("/{}", o.src.unwrap());
        let (m, total, start, body) = content(&path, None).unwrap();
        assert_eq!((m, total, start), ("image/png", png.len() as u64, 0));
        assert_eq!(body, png);
        let (_, _, start, body) = content(&path, Some((8, 9))).unwrap();
        assert_eq!((start, body), (8, vec![7, 7]));
        assert!(content(&path, Some((99, 100))).is_none());
        // Wrong, shortened or foreign tokens: nothing.
        let mut wrong = path.clone();
        let last = wrong.pop().unwrap();
        assert!(content(&wrong, None).is_none());
        let other = if last == '0' { '1' } else { '0' };
        assert!(content(&format!("{wrong}{other}"), None).is_none());
        assert!(content("/preview/", None).is_none());
        assert!(content("/app.css", None).is_none());
        // A new preview replaces (and wipes) the old one.
        let o = open(crate::workspace::protect(&png).unwrap()).unwrap();
        assert!(content(&path, None).is_none());
        let path2 = format!("/{}", o.src.unwrap());
        assert!(content(&path2, None).is_some());
        close();
        assert!(!active());
        assert!(content(&path2, None).is_none());
        // Text never registers a route; long text is cut on a char boundary.
        let mut long = "é".repeat(TEXT_SHOWN / 2 + 3);
        long.push('x');
        let o = open(crate::workspace::protect(long.as_bytes()).unwrap()).unwrap();
        assert_eq!(o.kind, Kind::Text);
        assert!(o.src.is_none() && o.cut && !active());
        assert!(o.text.unwrap().len() <= TEXT_SHOWN);
        // Unsupported content registers nothing.
        let o = open(crate::workspace::protect(b"%PDF-1.4").unwrap()).unwrap();
        assert!(o.kind == Kind::Unsupported && o.src.is_none() && o.text.is_none() && !active());
    }
}
