// SPDX-License-Identifier: AGPL-3.0-or-later

//! Codec errors. They carry no input bytes, offsets or lengths: decoded
//! plaintext may be secret, and an offset can reveal a field's length.

use core::fmt;

/// Why input was rejected, or why a typed read failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input ends inside an item (or is empty).
    Truncated,
    /// Bytes follow the single top-level item.
    TrailingBytes,
    /// Additional information 28–30 (reserved by RFC 8949).
    ReservedAdditionalInfo,
    /// An indefinite-length item (additional information 31).
    IndefiniteLength,
    /// An argument not in its shortest form.
    NonShortestArgument,
    /// A string length or container count larger than the remaining input.
    LengthExceedsInput,
    /// A text string that is not valid UTF-8.
    InvalidUtf8,
    /// A tag (major type 6).
    Tag,
    /// A floating-point value.
    Float,
    /// A simple value other than `false`, `true` or `null`, or a stray `break`.
    UnsupportedSimple,
    /// Containers nested deeper than [`crate::MAX_DEPTH`].
    DepthExceeded,
    /// A map key that is not an integer.
    NonIntegerKey,
    /// A map key equal to the previous one.
    DuplicateKey,
    /// A map key that sorts before the previous one.
    UnorderedKeys,
    /// A typed read found a different kind of item.
    UnexpectedType,
    /// A typed read found an integer outside the requested range.
    OutOfRange,
    /// The decoder finished with part of the item unread.
    Unconsumed,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Truncated => "CBOR input is truncated",
            Self::TrailingBytes => "CBOR input has trailing bytes",
            Self::ReservedAdditionalInfo => "CBOR uses reserved additional information",
            Self::IndefiniteLength => "CBOR uses an indefinite length",
            Self::NonShortestArgument => "CBOR argument is not in shortest form",
            Self::LengthExceedsInput => "CBOR length exceeds the input",
            Self::InvalidUtf8 => "CBOR text is not valid UTF-8",
            Self::Tag => "CBOR tags are not allowed",
            Self::Float => "CBOR floating-point values are not allowed",
            Self::UnsupportedSimple => "CBOR simple value is not allowed",
            Self::DepthExceeded => "CBOR nesting is too deep",
            Self::NonIntegerKey => "CBOR map key is not an integer",
            Self::DuplicateKey => "CBOR map has a duplicate key",
            Self::UnorderedKeys => "CBOR map keys are not in canonical order",
            Self::UnexpectedType => "CBOR item has an unexpected type",
            Self::OutOfRange => "CBOR integer is out of range",
            Self::Unconsumed => "CBOR item was not fully read",
        })
    }
}

impl std::error::Error for DecodeError {}

/// Why an encoding could not be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// Containers nested deeper than [`crate::MAX_DEPTH`].
    DepthExceeded,
    /// Two map entries have the same key.
    DuplicateKey,
    /// A map entry, or a finished encoder, did not hold exactly one item.
    ItemCount,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DepthExceeded => "CBOR nesting is too deep",
            Self::DuplicateKey => "CBOR map has a duplicate key",
            Self::ItemCount => "CBOR encoder did not hold exactly one item",
        })
    }
}

impl std::error::Error for EncodeError {}
