// SPDX-License-Identifier: AGPL-3.0-or-later

//! Owned canonical items kept verbatim, such as unknown map entries
//! (spec 0004 §3.1: preserve unknown optional keys).

use core::fmt;

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::decode::Decoder;
use crate::error::DecodeError;
use crate::validate::validate_item;

/// One canonical item, kept byte for byte.
///
/// It may hold secret data, so it is zeroized on drop, has a redacted `Debug`,
/// and cannot be cloned or compared:
///
/// ```compile_fail,E0599
/// let v = qv_encoding::RawValue::from_canonical(&[0x01]).unwrap();
/// let _w = v.clone();
/// ```
///
/// ```
/// let v = qv_encoding::RawValue::from_canonical(&[0x01]).unwrap();
/// let _w = v;
/// ```
///
/// ```compile_fail,E0369
/// let v = qv_encoding::RawValue::from_canonical(&[0x01]).unwrap();
/// let w = qv_encoding::RawValue::from_canonical(&[0x01]).unwrap();
/// let _ = v == w;
/// ```
///
/// ```
/// let v = qv_encoding::RawValue::from_canonical(&[0x01]).unwrap();
/// let w = qv_encoding::RawValue::from_canonical(&[0x01]).unwrap();
/// assert_eq!(v.as_bytes(), w.as_bytes());
/// assert_eq!(format!("{v:?}"), "RawValue(<redacted>)");
/// ```
pub struct RawValue {
    bytes: Box<[u8]>,
    depth: usize,
}

impl RawValue {
    pub(crate) fn new(bytes: &[u8], depth: usize) -> Self {
        Self {
            bytes: bytes.into(),
            depth,
        }
    }

    /// Validates `bytes` as exactly one canonical item and copies it.
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, DecodeError> {
        let item = validate_item(bytes, 0)?;
        if item.end != bytes.len() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self::new(bytes, item.depth))
    }

    /// The item's canonical encoding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// A decoder over the item (already validated, so not validated again).
    pub fn decoder(&self) -> Decoder<'_> {
        Decoder::validated(&self.bytes)
    }

    /// Container nesting of the item.
    pub(crate) fn depth(&self) -> usize {
        self.depth
    }
}

impl Drop for RawValue {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for RawValue {}

impl fmt::Debug for RawValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RawValue(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_from_canonical_validates() {
        assert_eq!(
            RawValue::from_canonical(&[0x18, 0x01]).err(),
            Some(DecodeError::NonShortestArgument)
        );
        assert_eq!(
            RawValue::from_canonical(&[0x01, 0x02]).err(),
            Some(DecodeError::TrailingBytes)
        );
        assert_eq!(
            RawValue::from_canonical(&[]).err(),
            Some(DecodeError::Truncated)
        );
        let v = RawValue::from_canonical(&[0x81, 0x80]).unwrap();
        assert_eq!(v.depth(), 2);
        assert_eq!(RawValue::from_canonical(&[0x05]).unwrap().depth(), 0);
    }

    #[test]
    fn raw_debug_is_redacted() {
        // "hunter2"
        let v =
            RawValue::from_canonical(&[0x67, b'h', b'u', b'n', b't', b'e', b'r', b'2']).unwrap();
        for out in [format!("{v:?}"), format!("{v:#?}")] {
            assert_eq!(out, "RawValue(<redacted>)");
        }
    }
}
