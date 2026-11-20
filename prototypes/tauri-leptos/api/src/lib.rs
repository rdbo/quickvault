// SPDX-License-Identifier: AGPL-3.0-or-later

//! The bridge between the Leptos page and the Tauri backend (plan 0070,
//! 0008 §4.3): one command, typed requests checked for size before they are
//! decoded, opaque references instead of Rust handles, and replies and events
//! tagged with the lock generation they belong to.
//!
//! Enums are externally tagged (`{"unlock":{...}}`): serde decodes
//! internally tagged enums through an untyped buffer, which would copy a
//! password outside [`Secret`].
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::Zeroizing;

/// The one Tauri command.
pub const COMMAND: &str = "qv";
/// The one Tauri event name.
pub const EVENT: &str = "qv-event";
/// Largest request body, checked before decoding.
pub const MAX_REQUEST: usize = 64 * 1024;
/// Largest secret in a request or reply, in UTF-8 bytes (1024 characters).
pub const MAX_SECRET: usize = 4096;
/// How long a revealed value stays on screen (0008 §4.3).
pub const REVEAL_MS: u32 = 30_000;
/// Largest media range answered at once.
pub const MAX_RANGE: u64 = 64 * 1024;

/// An opaque 128-bit reference from the backend's per-session table. It
/// names a group, entry, field or media token and carries no vault data.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
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

/// Secret bytes (UTF-8 text) in zeroizing memory, at most [`MAX_SECRET`].
/// On the wire it is an array of byte values: decoding one fills a buffer
/// allocated once at full size, so no unwiped copy is left by growth or by
/// unescaping a string. `Debug` never shows it.
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Copies `bytes` into a new secret.
    pub fn new(bytes: &[u8]) -> Result<Self, UiError> {
        if bytes.len() > MAX_SECRET {
            return Err(UiError::TooLarge);
        }
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_SECRET));
        out.extend_from_slice(bytes);
        Ok(Self(out))
    }

    /// The bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter())
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Secret;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("secret bytes")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Secret, A::Error> {
                let mut out = Zeroizing::new(Vec::with_capacity(MAX_SECRET));
                while let Some(b) = seq.next_element::<u8>()? {
                    if out.len() == MAX_SECRET {
                        return Err(de::Error::custom("secret too long"));
                    }
                    out.push(b);
                }
                Ok(Secret(out))
            }
        }
        d.deserialize_seq(V)
    }
}

/// A request and the lock generation the page last saw.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// The page's generation; a request from an older one is refused.
    pub generation: u64,
    /// What it asks.
    pub request: Request,
}

/// The media fixtures the prototype can preview.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Sample {
    /// A 25 KiB MP4 video.
    Video,
    /// A longer MP4 video, index at the end.
    VideoLong,
    /// A long-GOP MP4 video.
    VideoGop,
    /// The long MP4's audio track only.
    AudioMp4,
    /// A generated PCM WAV tone.
    Wav,
}

/// Every operation the page may ask for.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Request {
    /// The lock state, generation and platform.
    Status,
    /// Unlock the prototype vault.
    Unlock {
        /// The master password.
        password: Secret,
    },
    /// Lock now.
    Lock,
    /// The user did something (at most once a second).
    Active,
    /// The root's groups.
    Groups,
    /// A group's entries.
    Entries {
        /// The group.
        group: Ref,
    },
    /// One entry.
    Entry {
        /// The entry.
        entry: Ref,
    },
    /// Show a protected value for [`REVEAL_MS`].
    Reveal {
        /// The field.
        field: Ref,
    },
    /// Copy a field through the OS clipboard (never through the page).
    Copy {
        /// The field.
        field: Ref,
    },
    /// Open a media preview.
    OpenMedia {
        /// Which fixture.
        sample: Sample,
    },
    /// Close a media preview, revoking its token.
    CloseMedia {
        /// The token.
        media: Ref,
    },
    /// Back was pressed with nothing left to close (Android leaves the app
    /// on a second press).
    BackAtRoot,
}

/// A reply and the generation it was produced under.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Answer {
    /// The backend's generation when the reply was made.
    pub generation: u64,
    /// The reply.
    pub reply: Reply,
}

/// A listed group or entry.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Row {
    /// Its reference.
    pub id: Ref,
    /// Its name or title.
    pub name: String,
}

/// A field of an open entry. Protected values are absent until revealed.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FieldView {
    /// Its reference.
    pub id: Ref,
    /// Its name.
    pub name: String,
    /// Shown only on an explicit reveal.
    pub protected: bool,
    /// The value, when not protected.
    pub value: Option<String>,
}

/// An open entry.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct EntryView {
    /// Its title.
    pub title: String,
    /// Its fields.
    pub fields: Vec<FieldView>,
    /// Its notes.
    pub notes: String,
}

/// An open media preview.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MediaView {
    /// The token, revoked by [`Request::CloseMedia`] and by lock.
    pub media: Ref,
    /// The scheme URL for this platform.
    pub url: String,
    /// The MIME type.
    pub mime: String,
    /// The size in bytes.
    pub size: u64,
}

/// What the backend answers.
#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Reply {
    /// Done.
    Ok,
    /// The lock state.
    Status {
        /// Whether a vault is open.
        unlocked: bool,
        /// `linux`, `android` or `windows`.
        platform: String,
        /// The synthetic vault's password, shown on the lock screen.
        hint: String,
    },
    /// The root's groups.
    Groups(Vec<Row>),
    /// A group's entries.
    Entries(Vec<Row>),
    /// One entry.
    Entry(EntryView),
    /// A revealed value and how long it may stay on screen.
    Revealed {
        /// The field.
        field: Ref,
        /// The value.
        value: Secret,
        /// Milliseconds until the page must drop it.
        expires_ms: u32,
    },
    /// An open media preview.
    Media(MediaView),
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
    /// From an older lock generation.
    Stale,
    /// The vault is locked.
    Locked,
    /// Wrong password.
    WrongPassword,
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
            Self::Stale => "The vault was locked meanwhile.",
            Self::Locked => "The vault is locked.",
            Self::WrongPassword => "Wrong password.",
            Self::NotFound => "That item is no longer available.",
            Self::Unavailable => "That did not work. Try again.",
        }
    }
}

/// What the backend tells the page unasked.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Event {
    /// The vault locked: drop everything from older generations.
    Locked {
        /// The new generation.
        generation: u64,
    },
    /// A revealed value must go now.
    RevealExpired {
        /// The field.
        field: Ref,
    },
    /// Clipboard countdown: seconds until it is cleared, 0 when cleared.
    Clipboard {
        /// Seconds left.
        seconds: u64,
    },
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

    fn body(json: &str) -> Vec<u8> {
        json.as_bytes().to_vec()
    }

    #[test]
    fn decodes_a_typed_request() {
        let e = decode(&body(
            r#"{"generation":3,"request":{"unlock":{"password":[112,119]}}}"#,
        ))
        .unwrap();
        assert_eq!(e.generation, 3);
        match e.request {
            Request::Unlock { password } => assert_eq!(password.expose(), b"pw"),
            other => panic!("{other:?}"),
        }
        let e = decode(&body(r#"{"generation":0,"request":"status"}"#)).unwrap();
        assert!(matches!(e.request, Request::Status));
    }

    #[test]
    fn refuses_an_oversized_body_before_decoding() {
        let mut big = body(r#"{"generation":0,"request":"status"}"#);
        big.resize(MAX_REQUEST + 1, b' ');
        assert_eq!(decode(&big).unwrap_err(), UiError::TooLarge);
        // Exactly at the limit still decodes (trailing whitespace is JSON).
        big.truncate(MAX_REQUEST);
        assert!(decode(&big).is_ok());
    }

    #[test]
    fn refuses_unknown_fields_ops_and_shapes() {
        for bad in [
            r#"{"generation":0,"request":"status","extra":1}"#,
            r#"{"generation":0,"request":{"entry":{"entry":"00000000000000000000000000000000","x":1}}}"#,
            r#"{"generation":0,"request":"format_disk"}"#,
            r#"{"generation":0,"request":{"unlock":{"password":"plain text"}}}"#,
            r#"{"generation":0,"request":{"unlock":{"password":[256]}}}"#,
            r#"{"generation":0,"request":{"entry":{"entry":"0000"}}}"#,
            r#"{"generation":0,"request":{"entry":{"entry":"0000000000000000000000000000000G"}}}"#,
            r#"{"generation":-1,"request":"status"}"#,
            r#"{"generation":0,"generation":1,"request":"status"}"#,
            r#"{"generation":0,"request":{"lock":null,"unlock":{"password":[]}}}"#,
            r#"{"request":"status"}"#,
            "not json",
            "",
        ] {
            assert_eq!(decode(&body(bad)).unwrap_err(), UiError::Malformed, "{bad}");
        }
    }

    #[test]
    fn refuses_a_secret_over_the_limit() {
        let bytes = vec!["1"; MAX_SECRET + 1].join(",");
        let json = format!(r#"{{"generation":0,"request":{{"unlock":{{"password":[{bytes}]}}}}}}"#);
        assert!(json.len() < MAX_REQUEST);
        assert_eq!(decode(json.as_bytes()).unwrap_err(), UiError::Malformed);
        assert_eq!(
            Secret::new(&[0; MAX_SECRET + 1]).unwrap_err(),
            UiError::TooLarge
        );
    }

    #[test]
    fn secrets_and_refs_never_print() {
        let s = Secret::new(b"hunter2").unwrap();
        assert_eq!(format!("{s:?}"), "Secret(..)");
        let r = Ref([0xab; 16]);
        assert_eq!(format!("{r:?}"), "Ref(..)");
        let e = Envelope {
            generation: 1,
            request: Request::Unlock { password: s },
        };
        assert!(!format!("{e:?}").contains("hunter2"));
    }

    #[test]
    fn round_trips_replies_and_refs() {
        let r = Ref([0x0f; 16]);
        assert_eq!(Ref::parse(&r.hex()), Some(r));
        let a = Answer {
            generation: 2,
            reply: Reply::Revealed {
                field: r,
                value: Secret::new(b"v").unwrap(),
                expires_ms: REVEAL_MS,
            },
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: Answer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.generation, 2);
        assert!(matches!(back.reply, Reply::Revealed { value, .. } if value.expose() == b"v"));
        let ev = serde_json::to_string(&Event::Locked { generation: 4 }).unwrap();
        assert_eq!(ev, r#"{"locked":{"generation":4}}"#);
    }
}
