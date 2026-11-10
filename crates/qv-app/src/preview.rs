// SPDX-License-Identifier: AGPL-3.0-or-later

//! In-app attachment previews (0003 §6.4, 0009 §1.8; plan 0044).
//!
//! Explicit previews verify the whole hash through bounded protected buffers,
//! then serve individually authenticated ranges from the exact unlocked session.
//! No whole media attachment or plaintext response vector is retained. Sources
//! revoke on close/navigation/lock; kernel and decoder copies remain best effort.
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

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

/// Maximum retained plaintext prefix, independent of attachment size.
const PREFIX_MAX: usize = TEXT_SHOWN + 4;
const RANGE_MAX: usize = 64 * 1024;
const IMAGE_AUTO_BYTES: u64 = 64 * 1024 * 1024;

/// A bounded prefix plus streaming UTF-8 validity, not a whole-file collector.
struct Prefix {
    bytes: SecretBytes,
    len: usize,
    total: u64,
    utf8: bool,
    nul: bool,
    carry: SecretBytes,
    carried: usize,
}
impl Prefix {
    fn new() -> Self {
        Self {
            bytes: SecretBytes::zeroed(PREFIX_MAX),
            len: 0,
            total: 0,
            utf8: true,
            nul: false,
            carry: SecretBytes::zeroed(3),
            carried: 0,
        }
    }
    fn check_utf8(&mut self, bytes: &[u8]) {
        if !self.utf8 {
            return;
        }
        let joined = if self.carried != 0 {
            let mut joined = SecretBytes::zeroed(self.carried + bytes.len());
            joined.expose_secret_mut()[..self.carried]
                .copy_from_slice(&self.carry.expose_secret()[..self.carried]);
            joined.expose_secret_mut()[self.carried..].copy_from_slice(bytes);
            Some(joined)
        } else {
            None
        };
        let bytes = joined.as_ref().map_or(bytes, SecretBytes::expose_secret);
        self.carried = 0;
        match std::str::from_utf8(bytes) {
            Ok(_) => {}
            Err(error) if error.error_len().is_none() => {
                let tail = &bytes[error.valid_up_to()..];
                if tail.len() <= 3 {
                    self.carry.expose_secret_mut()[..tail.len()].copy_from_slice(tail);
                    self.carried = tail.len();
                } else {
                    self.utf8 = false;
                }
            }
            Err(_) => self.utf8 = false,
        }
    }
    fn finish(self, expected: u64) -> Result<Prepared, AppError> {
        if self.total != expected {
            return Err(AppError::PreviewUnavailable);
        }
        let bytes = &self.bytes.expose_secret()[..self.len];
        let end = match std::str::from_utf8(bytes) {
            Err(e) if e.error_len().is_none() => e.valid_up_to(),
            _ => bytes.len(),
        };
        let (mut kind, mut mime) = sniff(&bytes[..end]);
        if kind == Kind::Text && (!self.utf8 || self.nul || self.carried != 0) {
            (kind, mime) = (Kind::Unsupported, "application/octet-stream");
        }
        let mut text = None;
        let mut cut = false;
        if kind == Kind::Text {
            let all =
                std::str::from_utf8(&bytes[..end]).map_err(|_| AppError::PreviewUnavailable)?;
            let mut shown = all.len().min(TEXT_SHOWN);
            while !all.is_char_boundary(shown) {
                shown -= 1;
            }
            text = Some(crate::views::z(&all[..shown]));
            cut = (shown as u64) < self.total;
        }
        let image = if kind == Kind::Image {
            let dimensions = image_dimensions(&bytes[..bytes.len().min(RANGE_MAX)], mime);
            let decoded_bytes = dimensions
                .and_then(|(w, h)| u64::from(w).checked_mul(u64::from(h))?.checked_mul(4));
            if decoded_bytes.is_none_or(|n| n > IMAGE_AUTO_BYTES) {
                Some(ImageLoad {
                    dimensions,
                    decoded_bytes,
                })
            } else {
                None
            }
        } else {
            None
        };
        Ok(Prepared {
            kind,
            mime,
            text,
            cut,
            image,
        })
    }
}
impl Write for Prefix {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        if data.len() > RANGE_MAX {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        self.total = self
            .total
            .checked_add(data.len() as u64)
            .ok_or(std::io::ErrorKind::InvalidData)?;
        let count = data.len().min(self.bytes.len() - self.len);
        self.bytes.expose_secret_mut()[self.len..self.len + count].copy_from_slice(&data[..count]);
        self.len += count;
        self.nul |= data.contains(&0);
        self.check_utf8(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A preview that has completed content-hash verification. No media bytes retained.
pub(crate) struct Prepared {
    kind: Kind,
    mime: &'static str,
    text: Option<Zeroizing<String>>,
    cut: bool,
    image: Option<ImageLoad>,
}
/// A potentially expensive image decode that requires an explicit action.
#[derive(Clone, Copy, PartialEq)]
pub struct ImageLoad {
    /// Measured dimensions, if a bounded header establishes them.
    pub dimensions: Option<(u32, u32)>,
    /// RGBA lower bound; renderer/GPU overhead is additional.
    pub decoded_bytes: Option<u64>,
}
impl ImageLoad {
    /// Fixed explanation with measured sizes only.
    pub fn description(&self) -> String {
        match (self.dimensions, self.decoded_bytes) {
            (Some((w, h)), Some(n)) => format!(
                "{w} × {h} pixels; at least {} MiB to display. Loading it may use substantial memory.",
                n.div_ceil(1024 * 1024)
            ),
            (Some((w, h)), None) => {
                format!("{w} × {h} pixels. Displaying this image may use substantial memory.")
            }
            _ => {
                "The image dimensions could not be checked. Loading it may use substantial memory."
                    .to_owned()
            }
        }
    }
}

/// Verify by streaming and retain only a fixed prefix for content identification.
pub(crate) fn prepare(
    session: &qv_core::Session,
    handle: qv_core::AttachmentHandle,
    size: u64,
    cancel: Option<&qv_core::CancelToken>,
) -> Result<Prepared, AppError> {
    let mut prefix = Prefix::new();
    session
        .save_attachment(handle, &mut prefix, cancel)
        .map_err(|e| match e {
            qv_core::CoreError::Cancelled => AppError::from(e),
            _ => AppError::PreviewUnavailable,
        })?;
    prefix.finish(size)
}

/// The renderer's bounded view of the active preview.
#[derive(Clone, PartialEq)]
pub struct PreviewView {
    /// Exact attachment capability.
    pub handle: qv_core::AttachmentHandle,
    /// Owning entry.
    pub entry: qv_core::EntryHandle,
    /// Untrusted name, already escaped for display.
    pub name: Zeroizing<String>,
    /// Authenticated size.
    pub size: u64,
    /// Sniffed content category.
    pub kind: Kind,
    /// Sniffed type.
    pub mime: &'static str,
    /// Revocable capability URL; never logged or persisted.
    pub src: Option<Zeroizing<String>>,
    /// Bounded text only.
    pub text: Option<Zeroizing<String>>,
    /// Text continues beyond the displayed prefix.
    pub cut: bool,
    /// Image decode awaiting explicit consent for this attachment.
    pub image_load: Option<ImageLoad>,
    /// Position among the entry's attachments.
    pub index: usize,
    /// Attachment count.
    pub count: usize,
}
// The native media adapter is absent in the headless non-test library.
#[cfg_attr(not(any(test, feature = "desktop")), allow(dead_code))]
struct Source {
    session: Weak<qv_core::Session>,
    handle: qv_core::AttachmentHandle,
    total: u64,
    mime: &'static str,
    revoked: AtomicBool,
    allowed: AtomicBool,
}
impl Source {
    #[cfg(any(test, feature = "desktop"))]
    fn available(&self) -> bool {
        !self.revoked.load(Ordering::SeqCst)
            && self.allowed.load(Ordering::SeqCst)
            && self.session.upgrade().is_some_and(|s| !s.is_locked())
    }
    #[cfg(any(test, feature = "desktop"))]
    fn stream(&self, offset: u64, length: u64, output: &mut dyn Write) -> std::io::Result<()> {
        let unavailable = || std::io::Error::other("preview unavailable");
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= self.total)
            .ok_or_else(unavailable)?;
        let mut at = offset;
        while at < end {
            if !self.available() {
                return Err(unavailable());
            }
            let session = self.session.upgrade().ok_or_else(unavailable)?;
            let count = (end - at).min(RANGE_MAX as u64) as usize;
            let bytes = session
                .attachment_range(self.handle, at, count, None)
                .map_err(|_| unavailable())?;
            drop(session); // No session mutex/key is retained across socket writes.
            let mut sent = 0;
            while sent < bytes.len() {
                if !self.available() {
                    return Err(unavailable());
                }
                let count = output.write(&bytes.expose_secret()[sent..])?;
                if count == 0 {
                    return Err(std::io::ErrorKind::WriteZero.into());
                }
                sent += count;
            }
            at += bytes.len() as u64;
        }
        if !self.available() {
            return Err(unavailable());
        }
        Ok(())
    }
}
// In headless builds the token is only retained for revocation/drop.
#[cfg_attr(not(any(test, feature = "desktop")), allow(dead_code))]
struct Active {
    token: SecretBytes,
    source: Arc<Source>,
}
static ACTIVE: Mutex<Option<Active>> = Mutex::new(None);

/// The new preview's bounded renderer fields.
pub(crate) struct Opened {
    pub(crate) kind: Kind,
    pub(crate) mime: &'static str,
    pub(crate) src: Option<Zeroizing<String>>,
    pub(crate) text: Option<Zeroizing<String>>,
    pub(crate) cut: bool,
    pub(crate) image_load: Option<ImageLoad>,
}
pub(crate) fn open(
    prepared: Prepared,
    session: Weak<qv_core::Session>,
    handle: qv_core::AttachmentHandle,
    size: u64,
) -> Result<Opened, AppError> {
    close();
    let mut opened = Opened {
        kind: prepared.kind,
        mime: prepared.mime,
        src: None,
        text: prepared.text,
        cut: prepared.cut,
        image_load: prepared.image,
    };
    if matches!(prepared.kind, Kind::Image | Kind::Audio | Kind::Video) {
        let token = SecretBytes::random(16).map_err(|_| AppError::Unavailable)?;
        let mut route = Zeroizing::new(String::with_capacity(41));
        route.push_str("/preview/");
        for byte in token.expose_secret() {
            route.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
            route.push(char::from(b"0123456789abcdef"[usize::from(byte & 15)]));
        }
        #[cfg(feature = "desktop")]
        {
            let url = dioxus_desktop::hardened::preview_url(&route);
            #[cfg(test)]
            let url = url.or_else(|| Some(route.to_string()));
            opened.src = Some(Zeroizing::new(url.ok_or(AppError::PreviewUnavailable)?));
        }
        #[cfg(not(feature = "desktop"))]
        {
            opened.src = Some(route);
        }
        let source = Arc::new(Source {
            session,
            handle,
            total: size,
            mime: prepared.mime,
            revoked: AtomicBool::new(false),
            allowed: AtomicBool::new(prepared.image.is_none()),
        });
        *ACTIVE.lock().unwrap_or_else(PoisonError::into_inner) = Some(Active { token, source });
    }
    Ok(opened)
}
/// Revoke all cloned streams before dropping their protected token/state.
pub(crate) fn close() {
    if let Some(active) = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner).take() {
        active.source.revoked.store(true, Ordering::SeqCst);
    }
}
/// Explicit image consent is bound to the exact attachment, never another preview.
pub(crate) fn allow_image(handle: qv_core::AttachmentHandle) -> Result<(), AppError> {
    let active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
    let source = &active.as_ref().ok_or(AppError::PreviewUnavailable)?.source;
    if source.handle != handle
        || source.revoked.load(Ordering::SeqCst)
        || source.session.upgrade().is_none_or(|s| s.is_locked())
    {
        return Err(AppError::PreviewUnavailable);
    }
    source.allowed.store(true, Ordering::SeqCst);
    Ok(())
}
#[cfg(test)]
pub(crate) fn active() -> bool {
    ACTIVE
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some()
}

/// Exercise the actual protected streaming source without a native webview.
#[cfg(test)]
pub(crate) fn test_range(path: &str, offset: u64, length: usize) -> Option<SecretBytes> {
    if length > RANGE_MAX {
        return None;
    }
    let path = &path[path.find("/preview/")?..];
    let source = source(path)?;
    let mut bytes = SecretBytes::zeroed(length);
    source
        .stream(
            offset,
            length as u64,
            &mut std::io::Cursor::new(bytes.expose_secret_mut()),
        )
        .ok()?;
    Some(bytes)
}

#[cfg(any(test, feature = "desktop"))]
fn source(path: &str) -> Option<Arc<Source>> {
    use ctutils::CtEq;
    let token = path.strip_prefix("/preview/")?;
    if token.len() != 32 {
        return None;
    }
    let mut decoded = SecretBytes::zeroed(16);
    let digit = |b| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    };
    for (out, pair) in decoded
        .expose_secret_mut()
        .iter_mut()
        .zip(token.as_bytes().as_chunks::<2>().0)
    {
        *out = digit(pair[0])? * 16 + digit(pair[1])?;
    }
    let active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner);
    let active = active.as_ref()?;
    if !decoded
        .expose_secret()
        .ct_eq(active.token.expose_secret())
        .to_bool()
        || !active.source.available()
    {
        return None;
    }
    Some(Arc::clone(&active.source))
}
#[cfg(feature = "desktop")]
impl dioxus_desktop::hardened::PreviewBody for Source {
    fn available(&self) -> bool {
        self.available()
    }
    fn write_range(&self, offset: u64, length: u64, output: &mut dyn Write) -> std::io::Result<()> {
        self.stream(offset, length, output)
    }
}
#[cfg(feature = "desktop")]
pub(crate) fn serve(path: &str) -> Option<dioxus_desktop::hardened::Served> {
    let source = source(path)?;
    Some(dioxus_desktop::hardened::Served {
        mime: source.mime,
        total: source.total,
        body: source,
    })
}

fn image_dimensions(bytes: &[u8], mime: &str) -> Option<(u32, u32)> {
    let be = |at| Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?));
    let le16 = |at| {
        Some(u32::from(u16::from_le_bytes(
            bytes.get(at..at + 2)?.try_into().ok()?,
        )))
    };
    let le24 = |at| {
        let b = bytes.get(at..at + 3)?;
        Some(u32::from(b[0]) | u32::from(b[1]) << 8 | u32::from(b[2]) << 16)
    };
    let (width, height) = match mime {
        "image/png" if bytes.get(12..16) == Some(b"IHDR") => (be(16)?, be(20)?),
        "image/gif" => (le16(6)?, le16(8)?),
        "image/webp" => match bytes.get(12..16)? {
            b"VP8X" => (le24(24)?.checked_add(1)?, le24(27)?.checked_add(1)?),
            b"VP8L" if bytes.get(20) == Some(&0x2f) => {
                let bits = u32::from_le_bytes(bytes.get(21..25)?.try_into().ok()?);
                ((bits & 0x3fff) + 1, ((bits >> 14) & 0x3fff) + 1)
            }
            b"VP8 " if bytes.get(23..26) == Some(b"\x9d\x01\x2a") => {
                (le16(26)? & 0x3fff, le16(28)? & 0x3fff)
            }
            _ => return None,
        },
        "image/jpeg" => {
            let mut at = 2usize;
            loop {
                if bytes.get(at)? != &0xff {
                    return None;
                }
                while bytes.get(at) == Some(&0xff) {
                    at += 1;
                }
                let marker = *bytes.get(at)?;
                at += 1;
                if matches!(marker, 0xd9 | 0xda) {
                    return None;
                }
                if matches!(marker, 0x01 | 0xd0..=0xd8) {
                    continue;
                }
                let length =
                    usize::from(u16::from_be_bytes(bytes.get(at..at + 2)?.try_into().ok()?));
                if length < 2 || at.checked_add(length)? > bytes.len() {
                    return None;
                }
                if matches!(marker, 0xc0..=0xc3 | 0xc5..=0xc7 | 0xc9..=0xcb | 0xcd..=0xcf) {
                    if length < 8 {
                        return None;
                    }
                    let height = u32::from(u16::from_be_bytes(
                        bytes.get(at + 3..at + 5)?.try_into().ok()?,
                    ));
                    let width = u32::from(u16::from_be_bytes(
                        bytes.get(at + 5..at + 7)?.try_into().ok()?,
                    ));
                    break (width, height);
                }
                at += length;
            }
        }
        _ => return None,
    };
    (width != 0 && height != 0).then_some((width, height))
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
    fn huge_text_stream_keeps_a_fixed_prefix_and_checks_the_unshown_tail() {
        let mut prefix = Prefix::new();
        let block = [b'a'; RANGE_MAX];
        for _ in 0..16384 {
            prefix.write_all(&block).unwrap();
        }
        assert_eq!(prefix.len, PREFIX_MAX);
        assert_eq!(prefix.bytes.len(), PREFIX_MAX);
        let prepared = prefix.finish(1024 * 1024 * 1024).unwrap();
        assert_eq!(prepared.kind, Kind::Text);
        assert!(prepared.cut);
        assert_eq!(prepared.text.unwrap().len(), TEXT_SHOWN);
        let mut prefix = Prefix::new();
        for _ in 0..20 {
            prefix.write_all(&block).unwrap();
        }
        prefix.write_all(&[0xff]).unwrap();
        assert_eq!(
            prefix.finish(20 * RANGE_MAX as u64 + 1).unwrap().kind,
            Kind::Unsupported
        );
        let mut split = Prefix::new();
        split.write_all(b"caf\xc3").unwrap();
        split.write_all(b"\xa9").unwrap();
        assert_eq!(split.finish(5).unwrap().text.unwrap().as_str(), "café");
    }
    #[test]
    fn image_memory_consent_uses_dimensions_and_unknowns() {
        let png = |width: u32, height: u32| {
            let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
            bytes.extend(width.to_be_bytes());
            bytes.extend(height.to_be_bytes());
            bytes
        };
        for (w, h, large) in [
            (100, 100, false),
            (12000, 9000, true),
            (u32::MAX, u32::MAX, true),
        ] {
            let bytes = png(w, h);
            let mut prefix = Prefix::new();
            prefix.write_all(&bytes).unwrap();
            let prepared = prefix.finish(bytes.len() as u64).unwrap();
            assert_eq!(prepared.kind, Kind::Image);
            assert_eq!(prepared.image.is_some(), large);
        }
        let mut prefix = Prefix::new();
        prefix.write_all(b"\xff\xd8\xff").unwrap();
        assert!(prefix.finish(3).unwrap().image.is_some());
    }
    #[test]
    fn source_checks_capability_ranges_and_revocation_even_after_clone() {
        let _g = crate::workspace_tests::KDF
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let env = crate::workspace_tests::Env::unlocked();
        let mut bytes = vec![7; RANGE_MAX * 3 + 3];
        bytes[..12].copy_from_slice(b"RIFF\0\0\0\0WAVE");
        let entry = env.read(|s| s.save_entry(s.new_entry(s.root()?, "note", "media")?));
        let handle = env
            .read(|s| s.add_attachment(entry, "media", "wrong/type", &mut bytes.as_slice(), None));
        let session = env.c.with_ws(env.epoch(), |_, s| Arc::clone(s)).unwrap();
        let prepared = prepare(&session, handle, bytes.len() as u64, None).unwrap();
        let opened = open(
            prepared,
            Arc::downgrade(&session),
            handle,
            bytes.len() as u64,
        )
        .unwrap();
        let path = opened.src.unwrap();
        #[cfg(feature = "desktop")]
        let path = path
            .find("/preview/")
            .map(|i| path[i..].to_owned())
            .unwrap();
        let active_source = source(&path).unwrap();
        assert_eq!(active_source.mime, "audio/wav");
        assert!(source("/preview/00000000000000000000000000000000").is_none());
        let mut out = Vec::new();
        active_source.stream(65535, 65539, &mut out).unwrap();
        assert_eq!(out, bytes[65535..131074]);
        assert!(active_source.stream(u64::MAX, 2, &mut Vec::new()).is_err());
        close();
        assert!(!active() && source(&path).is_none());
        assert!(active_source.stream(0, 1, &mut Vec::new()).is_err());
        let prepared = prepare(&session, handle, bytes.len() as u64, None).unwrap();
        let opened = open(
            prepared,
            Arc::downgrade(&session),
            handle,
            bytes.len() as u64,
        )
        .unwrap();
        let path = opened.src.unwrap();
        #[cfg(feature = "desktop")]
        let path = path
            .find("/preview/")
            .map(|i| path[i..].to_owned())
            .unwrap();
        let old = source(&path).unwrap();
        session.lock();
        assert!(source(&path).is_none());
        assert!(old.stream(0, 1, &mut Vec::new()).is_err());
        close();
    }
}
