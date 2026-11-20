// SPDX-License-Identifier: AGPL-3.0-or-later

//! The bridge between the Leptos page (`qv-ui`) and the Tauri backend in
//! `qv-app` (plan 0071, 0008 §4): one command, typed requests checked for
//! size before they are decoded, opaque references instead of Rust handles,
//! and frames (view models built in Rust) as command replies.
//!
//! Enums are externally tagged (`{"act":{...}}`): serde decodes internally
//! tagged enums through an untyped buffer, which would copy a secret outside
//! [`Secret`]. No type here derives `Debug` over vault text.
mod act;
mod frame;

pub use act::*;
pub use frame::*;

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

/// The one Tauri command.
pub const COMMAND: &str = "qv";
/// Largest request body, checked before decoding.
pub const MAX_REQUEST: usize = 64 * 1024;
/// Largest secret in a request, in UTF-8 bytes: the longest input (8,192
/// characters of multi-line text) at four bytes each. As base64 it stays
/// under [`MAX_REQUEST`].
pub const MAX_SECRET: usize = 32 * 1024;
/// Largest media range answered at once.
pub const MAX_RANGE: u64 = 64 * 1024;
/// How long a frame request waits for a newer frame.
pub const FRAME_WAIT_MS: u64 = 20_000;

/// An opaque 128-bit reference from the backend's table. It names a vault
/// handle, a listed vault or a media token and carries no vault data.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Ref(pub [u8; 16]);

impl Ref {
    /// Lowercase hex, as on the wire.
    pub fn hex(&self) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut s = String::with_capacity(32);
        for b in self.0 {
            s.push(char::from(DIGITS[usize::from(b >> 4)]));
            s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
        }
        s
    }

    /// Parses exactly 32 lowercase hex digits.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() != 32 {
            return None;
        }
        let digit = |c: u8| match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        };
        let mut out = [0u8; 16];
        for (i, [hi, lo]) in bytes.as_chunks::<2>().0.iter().enumerate() {
            out[i] = (digit(*hi)? << 4) | digit(*lo)?;
        }
        Some(Self(out))
    }
}

impl fmt::Debug for Ref {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ref(..)")
    }
}

impl Serialize for Ref {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.hex())
    }
}

impl<'de> Deserialize<'de> for Ref {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Ref;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a reference")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Ref, E> {
                Ref::parse(v).ok_or_else(|| E::custom("reference"))
            }
        }
        d.deserialize_str(V)
    }
}

/// Text shown on screen, in zeroizing memory on both sides (vault names,
/// titles, revealed values). `Debug` never shows it.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Z(pub Zeroizing<String>);

impl Z {
    /// Copies `s`.
    pub fn new(s: &str) -> Self {
        Self(Zeroizing::new(s.to_owned()))
    }
    /// The text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// Whether it is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::ops::Deref for Z {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Z {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for Z {
    fn from(s: String) -> Self {
        Self(Zeroizing::new(s))
    }
}

impl From<Zeroizing<String>> for Z {
    fn from(s: Zeroizing<String>) -> Self {
        Self(s)
    }
}

impl fmt::Debug for Z {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Z(..)")
    }
}

impl Serialize for Z {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Z {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Z;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("text")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Z, E> {
                Ok(Z::new(v))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Z, E> {
                Ok(Z(Zeroizing::new(v)))
            }
        }
        d.deserialize_string(V)
    }
}

/// Secret bytes (UTF-8 text) in zeroizing memory, at most [`MAX_SECRET`].
/// On the wire it is standard base64, which never needs JSON escapes, so the
/// decoder reads it in place from the request and writes into one buffer
/// allocated at its final size: no unwiped copy from growth or unescaping.
/// `Debug` never shows it.
pub struct Secret(Zeroizing<Vec<u8>>);

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

impl Secret {
    /// Copies `bytes` into a new secret.
    pub fn new(bytes: &[u8]) -> Result<Self, UiError> {
        if bytes.len() > MAX_SECRET {
            return Err(UiError::TooLarge);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
        out.extend_from_slice(bytes);
        Ok(Self(out))
    }

    /// The bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Standard base64 of the bytes, in zeroizing memory.
    pub fn encode(&self) -> Zeroizing<String> {
        let mut out = Zeroizing::new(String::with_capacity(self.0.len().div_ceil(3) * 4));
        for chunk in self.0.chunks(3) {
            let n = chunk
                .iter()
                .enumerate()
                .fold(0u32, |n, (i, b)| n | u32::from(*b) << (16 - 8 * i));
            for i in 0..4 {
                if i <= chunk.len() {
                    out.push(char::from(B64[((n >> (18 - 6 * i)) & 63) as usize]));
                } else {
                    out.push('=');
                }
            }
        }
        out
    }

    /// Decodes standard padded base64; `None` for anything else.
    pub fn decode(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if !bytes.len().is_multiple_of(4) || bytes.len() / 4 * 3 > MAX_SECRET + 2 {
            return None;
        }
        let pad = bytes.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 {
            return None;
        }
        let len = bytes.len() / 4 * 3 - pad;
        if len > MAX_SECRET {
            return None;
        }
        let mut out = Zeroizing::new(Vec::with_capacity(len));
        for (q, quad) in bytes.chunks(4).enumerate() {
            let last = q + 1 == bytes.len() / 4;
            let mut n = 0u32;
            for (i, c) in quad.iter().enumerate() {
                let v = if *c == b'=' && last && i >= 4 - pad {
                    0
                } else {
                    b64_value(*c)?
                };
                n |= v << (18 - 6 * i);
            }
            let take = if last { 3 - pad } else { 3 };
            for i in 0..take {
                out.push((n >> (16 - 8 * i)) as u8);
            }
        }
        Some(Self(out))
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.encode())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Secret;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("base64 secret")
            }
            // Only text read in place from the request: an escaped string
            // would arrive through the decoder's scratch buffer.
            fn visit_borrowed_str<E: de::Error>(self, v: &'de str) -> Result<Secret, E> {
                Secret::decode(v).ok_or_else(|| E::custom("secret"))
            }
            fn visit_str<E: de::Error>(self, _: &str) -> Result<Secret, E> {
                Err(E::custom("secret"))
            }
        }
        d.deserialize_str(V)
    }
}

/// A request and the frame epoch the page last rendered.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// The epoch of the frame the page acted on. The controller ignores
    /// actions from another epoch.
    pub generation: u64,
    /// What it asks.
    pub request: Request,
}

/// Every request the page may make.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Request {
    /// The next frame after sequence `after` (long poll).
    Frame {
        /// The last sequence the page holds.
        after: u64,
    },
    /// A typed action.
    Act {
        /// The action.
        act: Act,
    },
    /// One keystroke's worth of an input's value, moved to Rust at once.
    Input {
        /// Which input.
        field: Field,
        /// Its whole current value.
        value: Secret,
    },
    /// A key the page did not handle itself (shortcuts, Escape, Back).
    Key {
        /// The key name, as the engine reports it.
        key: String,
        /// Ctrl or Meta held.
        ctrl: bool,
    },
    /// The user did something (at most twice a second).
    Activity,
    /// Turn a page of a paged list.
    PageTurn {
        /// The page's slot, from its [`PageNav`].
        slot: String,
        /// The read serial shown.
        serial: u64,
        /// Forward, else back.
        forward: bool,
    },
    /// A window operation (desktop title bar).
    Window {
        /// The operation.
        op: WindowOp,
    },
}

/// What the backend answers.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Reply {
    /// Done; the effect arrives with the next frame.
    Ok,
    /// A frame.
    Frame(Box<Frame>),
    /// A refusal.
    Error(UiError),
}

/// Why a request failed. Fixed messages only: no input is echoed.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UiError {
    /// The body is over [`MAX_REQUEST`] or a secret over [`MAX_SECRET`].
    TooLarge,
    /// Not a valid request.
    Malformed,
    /// The reference is unknown or expired.
    NotFound,
    /// Something else went wrong.
    Unavailable,
}

impl UiError {
    /// The message the page shows.
    pub fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "That is too long.",
            Self::Malformed => "The app sent a request it does not understand.",
            Self::NotFound => "That item is no longer available.",
            Self::Unavailable => "That did not work. Try again.",
        }
    }
}

/// Checks the size, then decodes. Fails closed with a fixed error.
pub fn decode(body: &[u8]) -> Result<Envelope, UiError> {
    if body.len() > MAX_REQUEST {
        return Err(UiError::TooLarge);
    }
    serde_json::from_slice(body).map_err(|_| UiError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_typed_requests() {
        let e = decode(br#"{"generation":3,"request":{"input":{"field":{"locked":"password"},"value":"cHc="}}}"#)
            .unwrap();
        assert_eq!(e.generation, 3);
        match e.request {
            Request::Input { field, value } => {
                assert_eq!(field, Field::Locked(LockedField::Password));
                assert_eq!(value.expose(), b"pw");
            }
            _ => panic!("input"),
        }
        let e = decode(br#"{"generation":0,"request":{"frame":{"after":7}}}"#).unwrap();
        assert!(matches!(e.request, Request::Frame { after: 7 }));
        let e = decode(br#"{"generation":1,"request":{"act":{"act":"lock"}}}"#).unwrap();
        assert!(matches!(e.request, Request::Act { act: Act::Lock }));
    }

    #[test]
    fn refuses_an_oversized_body_before_decoding() {
        let mut big = br#"{"generation":0,"request":"activity"}"#.to_vec();
        big.resize(MAX_REQUEST + 1, b' ');
        assert_eq!(decode(&big).err(), Some(UiError::TooLarge));
        big.truncate(MAX_REQUEST);
        assert!(decode(&big).is_ok());
    }

    #[test]
    fn refuses_unknown_fields_ops_duplicates_and_shapes() {
        for bad in [
            r#"{"generation":0,"request":"activity","x":1}"#,
            r#"{"generation":0,"generation":1,"request":"activity"}"#,
            r#"{"generation":0,"request":"format_disk"}"#,
            r#"{"generation":0,"request":{"act":{"act":"lock","x":1}}}"#,
            r#"{"generation":0,"request":{"input":{"field":{"locked":"password"},"value":[112]}}}"#,
            r#"{"generation":0,"request":{"input":{"field":{"locked":"password"},"value":"cHc"}}}"#,
            r#"{"generation":0,"request":{"input":{"field":{"locked":"password"},"value":"c\u0048c="}}}"#,
            r#"{"generation":0,"request":{"act":{"act":{"go":{"entry":"00"}}}}}"#,
            r#"{"generation":-1,"request":"activity"}"#,
            r#"{"request":"activity"}"#,
            "",
        ] {
            assert_eq!(
                decode(bad.as_bytes()).err(),
                Some(UiError::Malformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn refuses_a_secret_over_the_limit() {
        let big = Secret(Zeroizing::new(vec![b'a'; MAX_SECRET + 3])).encode();
        let json = format!(
            r#"{{"generation":0,"request":{{"input":{{"field":{{"locked":"password"}},"value":"{}"}}}}}}"#,
            big.as_str()
        );
        assert!(json.len() < MAX_REQUEST);
        assert_eq!(decode(json.as_bytes()).err(), Some(UiError::Malformed));
        assert_eq!(
            Secret::new(&[0; MAX_SECRET + 1]).err(),
            Some(UiError::TooLarge)
        );
        // The largest secret still fits a request.
        let max = Secret::new(&[0xff; MAX_SECRET]).unwrap().encode();
        assert!(max.len() + 100 < MAX_REQUEST);
    }

    #[test]
    fn base64_round_trips_and_rejects_bad_text() {
        for n in 0..10usize {
            let bytes: Vec<u8> = (0..n as u8).map(|b| b.wrapping_mul(37)).collect();
            let s = Secret::new(&bytes).unwrap();
            assert_eq!(Secret::decode(&s.encode()).unwrap().expose(), &bytes[..]);
        }
        assert_eq!(Secret::new(b"pw").unwrap().encode().as_str(), "cHc=");
        for bad in ["cHc", "c=Hc", "cH==c===", "cHc*", "===="] {
            assert!(Secret::decode(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn secrets_text_and_refs_never_print() {
        assert_eq!(
            format!("{:?}", Secret::new(b"hunter2").unwrap()),
            "Secret(..)"
        );
        assert_eq!(format!("{:?}", Z::new("hunter2")), "Z(..)");
        assert_eq!(format!("{:?}", Ref([1; 16])), "Ref(..)");
        let r = Ref([0x0f; 16]);
        assert_eq!(Ref::parse(&r.hex()), Some(r));
    }
}
