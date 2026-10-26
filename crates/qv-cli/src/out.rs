// SPDX-License-Identifier: AGPL-3.0-or-later

//! Output: zeroizing buffers written straight to the file descriptor, the
//! escaping of vault text, and timestamps (spec 0011 §5, 0008 §1).
//!
//! All vault text (titles, names, field values, notes, revealed secrets,
//! generated values, codes) goes through an [`Out`]. It is built in a
//! zeroizing buffer that never reallocates without wiping the old copy, and
//! written with `write(2)` on fd 1 or 2, so std's `Stdout` buffer never
//! holds vault text.
//!
//! **Escaping** (0011 §5.3): in human-readable output, `\` becomes `\\`;
//! tab, newline and carriage return become `\t`, `\n`, `\r`; every other C0
//! control and DEL become `\xNN`; C1 controls, the Unicode bidirectional
//! controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069) and the
//! line and paragraph separators (U+2028, U+2029) become `\u{NN}` or
//! `\u{NNNN}`. Bytes
//! that are not UTF-8 become `\xNN`. Escape sequences (ANSI CSI, OSC 52 and
//! the like) start with ESC or a C1 control, so none survives. Multi-line
//! values keep their line breaks only through [`Out::multiline`], which
//! indents every continuation line, so stored text cannot imitate another
//! line of output.

use zeroize::{Zeroize, Zeroizing};

use crate::exit::{CliError, OTHER};

/// Where an [`Out`] writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fd {
    Stdout,
    Stderr,
}

/// A zeroizing output buffer for one file descriptor.
pub(crate) struct Out {
    buf: Zeroizing<Vec<u8>>,
    fd: Fd,
}

/// Whether `c` is printed as an escape sequence.
fn needs_escape(c: char) -> bool {
    matches!(c,
        '\\' | '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'
        | '\u{61c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}' | '\u{2028}' | '\u{2029}')
}

/// The longest escape of one scalar: `\u{NNNN}` (8 bytes).
const MAX_ESCAPE: usize = 8;

fn push_escaped_char(out: &mut Vec<u8>, c: char) {
    let mut tmp = [0u8; 4];
    match c {
        '\\' => out.extend_from_slice(b"\\\\"),
        '\t' => out.extend_from_slice(b"\\t"),
        '\n' => out.extend_from_slice(b"\\n"),
        '\r' => out.extend_from_slice(b"\\r"),
        c if (c as u32) < 0x80 && needs_escape(c) => push_hex_byte(out, c as u8),
        c if needs_escape(c) => {
            out.extend_from_slice(b"\\u{");
            let v = c as u32;
            let digits = if v > 0xff { 4 } else { 2 };
            for i in (0..digits).rev() {
                out.push(HEX[((v >> (4 * i)) & 0xf) as usize]);
            }
            out.push(b'}');
        }
        c => out.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes()),
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_hex_byte(out: &mut Vec<u8>, b: u8) {
    out.extend_from_slice(b"\\x");
    out.push(HEX[usize::from(b >> 4)]);
    out.push(HEX[usize::from(b & 0xf)]);
}

/// Calls `f` for each scalar of `bytes`, or `Err(byte)` for each byte that
/// is not part of valid UTF-8.
fn scalars(bytes: &[u8], mut f: impl FnMut(Result<char, u8>)) {
    let mut rest = bytes;
    while !rest.is_empty() {
        match core::str::from_utf8(rest) {
            Ok(s) => {
                s.chars().for_each(|c| f(Ok(c)));
                return;
            }
            Err(e) => {
                let (good, bad) = rest.split_at(e.valid_up_to());
                // `good` is valid UTF-8 by the error's contract.
                core::str::from_utf8(good)
                    .unwrap_or_default()
                    .chars()
                    .for_each(|c| f(Ok(c)));
                let n = e.error_len().unwrap_or(bad.len()).max(1);
                bad.iter().take(n).for_each(|b| f(Err(*b)));
                rest = bad.get(n..).unwrap_or_default();
            }
        }
    }
}

/// `s` escaped, as an ordinary string (for error messages and other
/// non-secret text).
pub(crate) fn escape_str(s: &str) -> String {
    let mut v = Vec::with_capacity(s.len());
    s.chars().for_each(|c| push_escaped_char(&mut v, c));
    String::from_utf8(v).unwrap_or_default()
}

impl Out {
    fn new(fd: Fd) -> Self {
        Self {
            buf: Zeroizing::new(Vec::new()),
            fd,
        }
    }

    /// A buffer for standard output.
    pub(crate) fn stdout() -> Self {
        Self::new(Fd::Stdout)
    }

    /// A buffer for standard error.
    pub(crate) fn stderr() -> Self {
        Self::new(Fd::Stderr)
    }

    /// Makes room for `extra` more bytes. Growing copies into a new
    /// buffer and wipes the old one, so no stale copy is left behind.
    fn reserve(&mut self, extra: usize) {
        let need = self.buf.len().saturating_add(extra);
        if need <= self.buf.capacity() {
            return;
        }
        let mut grown = Zeroizing::new(Vec::with_capacity(need.max(self.buf.capacity() * 2)));
        grown.extend_from_slice(&self.buf);
        // Dropping the old `Zeroizing` wipes it.
        self.buf = grown;
    }

    /// Program text (labels, headings): never vault content.
    pub(crate) fn raw(&mut self, s: &str) -> &mut Self {
        self.reserve(s.len());
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    /// Vault text, escaped.
    pub(crate) fn text(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// Vault bytes (a field value), escaped.
    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.reserve(b.len().saturating_mul(MAX_ESCAPE));
        let buf = &mut *self.buf;
        scalars(b, |r| match r {
            Ok(c) => push_escaped_char(buf, c),
            Err(byte) => push_hex_byte(buf, byte),
        });
        self
    }

    /// A path built by [`crate::address::path_escape`]: its backslashes
    /// are already escape introducers, so only controls are escaped.
    pub(crate) fn path(&mut self, p: &str) -> &mut Self {
        self.reserve(p.len().saturating_mul(MAX_ESCAPE));
        let buf = &mut *self.buf;
        let mut tmp = [0u8; 4];
        for c in p.chars() {
            if c == '\\' {
                buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes());
            } else {
                push_escaped_char(buf, c);
            }
        }
        self
    }

    /// Vault bytes exactly as stored, for a pipe (`show --field` when
    /// stdout is not a terminal).
    pub(crate) fn verbatim(&mut self, b: &[u8]) -> &mut Self {
        self.reserve(b.len());
        self.buf.extend_from_slice(b);
        self
    }

    /// Multi-line vault text: each line escaped, continuation lines
    /// indented by `indent`.
    pub(crate) fn multiline(&mut self, s: &str, indent: &str) -> &mut Self {
        for (i, line) in s.split('\n').enumerate() {
            if i > 0 {
                self.raw("\n").raw(indent);
            }
            self.text(line.strip_suffix('\r').unwrap_or(line));
        }
        self
    }

    /// The bytes built so far (tests).
    #[cfg(test)]
    pub(crate) fn contents(&self) -> &[u8] {
        &self.buf
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.buf.capacity()
    }

    /// JSON-escaped string with quotes (RFC 8259): `"`, `\`, controls,
    /// DEL, C1 and the bidi controls as escapes; other text as is.
    pub(crate) fn json_str(&mut self, b: &[u8]) -> &mut Self {
        self.reserve(b.len().saturating_mul(6).saturating_add(2));
        let buf = &mut *self.buf;
        buf.push(b'"');
        let mut tmp = [0u8; 4];
        scalars(b, |r| match r {
            Ok('"') => buf.extend_from_slice(b"\\\""),
            Ok('\\') => buf.extend_from_slice(b"\\\\"),
            Ok('\n') => buf.extend_from_slice(b"\\n"),
            Ok('\t') => buf.extend_from_slice(b"\\t"),
            Ok('\r') => buf.extend_from_slice(b"\\r"),
            Ok(c) if needs_escape(c) => {
                buf.extend_from_slice(b"\\u");
                let v = c as u32;
                for i in (0..4).rev() {
                    buf.push(HEX[((v >> (4 * i)) & 0xf) as usize]);
                }
            }
            Ok(c) => buf.extend_from_slice(c.encode_utf8(&mut tmp).as_bytes()),
            // JSON strings are Unicode: an invalid byte becomes U+FFFD.
            Err(_) => buf.extend_from_slice("\u{fffd}".as_bytes()),
        });
        buf.push(b'"');
        self
    }

    /// Writes everything to the descriptor and wipes the buffer.
    pub(crate) fn flush(&mut self) -> Result<(), CliError> {
        let r = write_all(self.fd, &self.buf);
        self.buf.zeroize();
        r
    }
}

fn write_all(fd: Fd, mut b: &[u8]) -> Result<(), CliError> {
    while !b.is_empty() {
        let r = match fd {
            Fd::Stdout => rustix::io::write(rustix::stdio::stdout(), b),
            Fd::Stderr => rustix::io::write(rustix::stdio::stderr(), b),
        };
        match r {
            Ok(0) => return Err(CliError::new(OTHER, "cannot write output")),
            Ok(n) => b = b.get(n..).unwrap_or_default(),
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err(CliError::new(OTHER, "cannot write output")),
        }
    }
    Ok(())
}

/// Writes non-vault text to stderr (warnings, errors); best effort.
pub(crate) fn eprint(s: &str) {
    let _ = write_all(Fd::Stderr, s.as_bytes());
}

/// A timestamp (ms since the Unix epoch, UTC) as RFC 3339, e.g.
/// `2026-10-26T14:05:09Z`. Display only; dates never order versions.
pub(crate) fn rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        tod % 3600 / 60,
        tod % 60
    )
}

/// Days since 1970-01-01 → (year, month, day), proleptic Gregorian
/// (H. Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    (
        y,
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn esc(b: &[u8]) -> String {
        let mut o = Out::stdout();
        o.bytes(b);
        String::from_utf8(o.contents().to_vec()).unwrap()
    }

    fn json(b: &[u8]) -> String {
        let mut o = Out::stdout();
        o.json_str(b);
        String::from_utf8(o.contents().to_vec()).unwrap()
    }

    #[test]
    fn out_escapes_terminal_sequences() {
        assert_eq!(esc(b"plain caf\xc3\xa9"), "plain café");
        assert_eq!(esc(b"\x1b[31mred\x1b[0m"), "\\x1b[31mred\\x1b[0m");
        assert_eq!(esc(b"\x1b]52;c;aGk=\x07"), "\\x1b]52;c;aGk=\\x07");
        assert_eq!(esc("\u{9b}31m".as_bytes()), "\\u{9b}31m");
        assert_eq!(esc(b"a\tb\nc\rd\x7f"), "a\\tb\\nc\\rd\\x7f");
        assert_eq!(esc("abc\u{202e}fed".as_bytes()), "abc\\u{202e}fed");
        assert_eq!(
            esc("\u{2066}\u{200f}\u{61c}\u{2028}".as_bytes()),
            "\\u{2066}\\u{200f}\\u{061c}\\u{2028}"
        );
        assert_eq!(esc(b"back\\slash"), "back\\\\slash");
        assert_eq!(esc(b"bad\xff\xfeutf"), "bad\\xff\\xfeutf");
        assert_eq!(esc(b"cut\xe2\x82"), "cut\\xe2\\x82");
        assert_eq!(escape_str("x\u{1b}y"), "x\\x1by");
        let mut o = Out::stdout();
        o.multiline("one\ntwo\x1b\r\nthree", "  ");
        assert_eq!(o.contents(), b"one\n  two\\x1b\n  three");
    }

    #[test]
    fn out_json_escaping() {
        assert_eq!(json(b"a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json(b"\x00\x1b\n\x7f"), "\"\\u0000\\u001b\\n\\u007f\"");
        assert_eq!(json("\u{85}\u{202e}é".as_bytes()), "\"\\u0085\\u202eé\"");
        assert_eq!(json(b"\xff"), "\"\u{fffd}\"");
    }

    #[test]
    fn out_never_reallocates_a_reserved_value() {
        let mut o = Out::stdout();
        let v = "x".repeat(1000);
        o.bytes(v.as_bytes());
        let cap = o.capacity();
        assert!(cap >= 1000 * MAX_ESCAPE);
        // The worst case (every byte escaped) fits what was reserved.
        let mut w = Out::stdout();
        let ctrl = vec![0x01u8; 1000];
        w.bytes(&ctrl);
        assert_eq!(w.contents().len(), 4000);
        assert!(w.capacity() >= 1000 * MAX_ESCAPE);
    }

    #[test]
    fn out_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400_000), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339(1_798_761_599_999), "2026-12-31T23:59:59Z");
        assert_eq!(rfc3339(253_402_300_799_000), "9999-12-31T23:59:59Z");
        assert_eq!(rfc3339(-1), "1969-12-31T23:59:59Z");
    }

    proptest::proptest! {
        #[test]
        fn out_escaped_text_has_no_control_characters(b in proptest::collection::vec(proptest::num::u8::ANY, 0..64)) {
            let s = esc(&b);
            proptest::prop_assert!(!s.chars().any(|c| c != '\\' && needs_escape(c)));
            proptest::prop_assert!(!s.bytes().any(|x| x < 0x20 || x == 0x7f));
        }
    }
}
