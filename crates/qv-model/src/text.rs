// SPDX-License-Identifier: AGPL-3.0-or-later

//! Containers for decrypted plaintext (spec 0008 §1.1–1.2).
//!
//! All vault content is confidential, including names and titles (0003,
//! *Security Considerations*). Metadata text lives in [`Text`]: a zeroizing
//! string that is never grown after construction, so no unwiped copy is left
//! by a reallocation. Field values are the short-lived protected values of
//! 0008 §1.2 and live in locked memory ([`FieldValue`], via
//! `qv_crypto::SecretBytes`). Unknown map entries are kept as zeroizing
//! [`RawValue`]s in [`Extensions`].
//!
//! None of these types has `Display`, `Clone` or `PartialEq`, and their
//! `Debug` is redacted:
//!
//! ```compile_fail
//! let t = qv_model::Text::new("x").unwrap();
//! let _ = t.clone();
//! ```
//!
//! ```compile_fail
//! let a = qv_model::Text::new("x").unwrap();
//! let b = qv_model::Text::new("x").unwrap();
//! let _ = a == b;
//! ```
//!
//! ```
//! let a = qv_model::Text::new("x").unwrap();
//! let b = qv_model::Text::new("x").unwrap();
//! assert_eq!(a.expose(), b.expose());
//! assert_eq!(format!("{a:?}"), "Text(<redacted>)");
//! ```

use core::fmt;

use qv_crypto::SecretBytes;
use qv_encoding::RawValue;
use zeroize::Zeroizing;

use crate::error::ModelError;

/// The largest text or byte value, in bytes (0004 §4.1).
pub const MAX_TEXT_BYTES: usize = 256 * 1024;
/// The largest record plaintext, in bytes (the 0004 §4.1 record budget).
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

fn check_len(len: usize) -> Result<(), ModelError> {
    if len <= MAX_TEXT_BYTES {
        Ok(())
    } else {
        Err(ModelError::LimitExceeded)
    }
}

/// Confidential metadata text (names, titles, notes, icons, MIME types).
pub struct Text(Zeroizing<String>);

impl Text {
    /// Copies `s` (at most [`MAX_TEXT_BYTES`]).
    pub fn new(s: &str) -> Result<Self, ModelError> {
        check_len(s.len())?;
        Ok(Self(Zeroizing::new(String::from(s))))
    }

    /// The text.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Text {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Text(<redacted>)")
    }
}

/// Text in locked memory: valid UTF-8 by construction.
pub struct SecretText(SecretBytes);

impl SecretText {
    /// Copies `s` (at most [`MAX_TEXT_BYTES`]) into locked memory.
    pub fn new(s: &str) -> Result<Self, ModelError> {
        check_len(s.len())?;
        Ok(Self(SecretBytes::try_init(s.len(), |out| {
            out.copy_from_slice(s.as_bytes());
            Ok::<(), ModelError>(())
        })?))
    }

    /// The text.
    pub fn expose_secret(&self) -> &str {
        // Valid UTF-8 by construction.
        core::str::from_utf8(self.0.expose_secret()).unwrap_or_default()
    }

    /// Whether the buffer's pages are locked (see `qv_crypto::SecretBytes`).
    pub fn is_locked(&self) -> bool {
        self.0.is_locked()
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretText(<redacted>)")
    }
}

/// A field's value (0003 §5): text or bytes, in locked memory.
pub enum FieldValue {
    /// A text value.
    Text(SecretText),
    /// A byte value.
    Bytes(SecretBytes),
}

impl FieldValue {
    /// A text value (at most [`MAX_TEXT_BYTES`]).
    pub fn text(s: &str) -> Result<Self, ModelError> {
        Ok(Self::Text(SecretText::new(s)?))
    }

    /// A byte value (at most [`MAX_TEXT_BYTES`]).
    pub fn bytes(b: &[u8]) -> Result<Self, ModelError> {
        check_len(b.len())?;
        Ok(Self::Bytes(SecretBytes::try_init(b.len(), |out| {
            out.copy_from_slice(b);
            Ok::<(), ModelError>(())
        })?))
    }

    /// The value's bytes (UTF-8 for a text value).
    pub fn expose_secret(&self) -> &[u8] {
        match self {
            Self::Text(t) => t.expose_secret().as_bytes(),
            Self::Bytes(b) => b.expose_secret(),
        }
    }
}

impl fmt::Debug for FieldValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FieldValue(<redacted>)")
    }
}

/// Map entries this version does not know, kept verbatim so a rewrite
/// preserves them (0003 §2.2). Only decoding fills it, so its keys never
/// collide with known keys.
#[derive(Default)]
pub struct Extensions(Vec<(i64, RawValue)>);

impl Extensions {
    /// No unknown entries.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of unknown entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no unknown entries.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Compares canonical extension content through confidential digests.
    /// Length-delimited fields prevent ambiguous concatenation; digest equality
    /// uses the reviewed constant-time comparison, and no digest is retained.
    pub fn content_eq(&self, other: &Self) -> bool {
        fn hash(ext: &Extensions) -> qv_crypto::SecretArray<32> {
            let mut hash = qv_crypto::ContentHasher::new();
            for (key, value) in &ext.0 {
                hash.update(&key.to_be_bytes());
                hash.update(&(value.as_bytes().len() as u64).to_be_bytes());
                hash.update(value.as_bytes());
            }
            hash.finalize()
        }
        hash(self).ct_eq(hash(other).expose_secret())
    }

    pub(crate) fn push(&mut self, key: i64, value: RawValue) {
        self.0.push((key, value));
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &(i64, RawValue)> {
        self.0.iter()
    }
}

impl fmt::Debug for Extensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Extensions(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_limits() {
        let max = "a".repeat(MAX_TEXT_BYTES);
        assert_eq!(Text::new(&max).unwrap().expose().len(), MAX_TEXT_BYTES);
        let over = "a".repeat(MAX_TEXT_BYTES + 1);
        assert_eq!(Text::new(&over).map(|_| ()), Err(ModelError::LimitExceeded));
        assert_eq!(
            SecretText::new(&over).map(|_| ()),
            Err(ModelError::LimitExceeded)
        );
        assert!(FieldValue::bytes(max.as_bytes()).is_ok());
        assert_eq!(
            FieldValue::bytes(over.as_bytes()).map(|_| ()),
            Err(ModelError::LimitExceeded)
        );
        assert!(Text::new("").unwrap().expose().is_empty());
    }

    #[test]
    fn values_round_trip() {
        assert_eq!(
            SecretText::new("pässword").unwrap().expose_secret(),
            "pässword"
        );
        assert_eq!(FieldValue::text("x").unwrap().expose_secret(), b"x");
        assert_eq!(
            FieldValue::bytes(&[0, 255]).unwrap().expose_secret(),
            [0, 255]
        );
    }

    #[test]
    fn debug_is_redacted() {
        assert_eq!(format!("{:?}", Text::new("t").unwrap()), "Text(<redacted>)");
        assert_eq!(
            format!("{:?}", SecretText::new("s").unwrap()),
            "SecretText(<redacted>)"
        );
        assert_eq!(
            format!("{:?}", FieldValue::text("v").unwrap()),
            "FieldValue(<redacted>)"
        );
        let mut ext = Extensions::new();
        ext.push(9, RawValue::from_canonical(&[0x61, b'x']).unwrap());
        assert_eq!(format!("{ext:?}"), "Extensions(<redacted>)");
        assert_eq!(ext.len(), 1);
    }

    #[test]
    fn history_extensions_confidential_comparison() {
        let mut a = Extensions::new();
        let mut b = Extensions::new();
        assert!(a.content_eq(&b));
        a.push(100, RawValue::from_canonical(&[0x01]).unwrap());
        assert!(!a.content_eq(&b));
        b.push(100, RawValue::from_canonical(&[0x01]).unwrap());
        assert!(a.content_eq(&b));
        let mut c = Extensions::new();
        c.push(101, RawValue::from_canonical(&[0x01]).unwrap());
        assert!(!a.content_eq(&c));
        let mut c = Extensions::new();
        c.push(100, RawValue::from_canonical(&[0x02]).unwrap());
        assert!(!a.content_eq(&c));
    }
}
