// SPDX-License-Identifier: AGPL-3.0-or-later

//! Borrowing pull decoder over one validated item.

use crate::error::DecodeError;
use crate::head::{
    ARRAY, BYTES, FALSE, Head, MAP, NEGATIVE, NULL, SIMPLE, TEXT, TRUE, UINT, read_head,
};
use crate::raw::RawValue;
use crate::validate::{validate, validate_item};

/// Kind of the item at the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Unsigned integer (major type 0).
    Uint,
    /// Negative integer (major type 1).
    Negative,
    /// Byte string.
    Bytes,
    /// UTF-8 text string.
    Text,
    /// Array.
    Array,
    /// Map with integer keys.
    Map,
    /// `false` or `true`.
    Bool,
    /// `null`.
    Null,
}

/// A cursor over one canonical item. It borrows the input and copies nothing,
/// except in [`Decoder::raw_value`].
///
/// [`Decoder::new`] validates the whole input first. Typed reads then walk it
/// in order: a container read returns only its header, and the caller reads its
/// items next. A read of the wrong kind returns [`DecodeError::UnexpectedType`]
/// and leaves the cursor where it was.
///
/// It has no `Debug`: the input it borrows may be secret.
pub struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Validates that `input` is exactly one canonical item and positions the
    /// cursor at its start.
    pub fn new(input: &'a [u8]) -> Result<Self, DecodeError> {
        validate(input)?;
        Ok(Self { input, pos: 0 })
    }

    /// A cursor over bytes already known to be one canonical item.
    pub(crate) fn validated(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    fn head(&self) -> Result<Head, DecodeError> {
        read_head(self.input, self.pos)
    }

    fn advance(&mut self, by: usize) -> Result<(), DecodeError> {
        self.pos = self.pos.checked_add(by).ok_or(DecodeError::Truncated)?;
        Ok(())
    }

    /// Consumes a head of `major` and returns its argument.
    fn expect(&mut self, major: u8) -> Result<u64, DecodeError> {
        let h = self.head()?;
        if h.major != major {
            return Err(DecodeError::UnexpectedType);
        }
        self.advance(h.len)?;
        Ok(h.arg)
    }

    /// Consumes a byte or text string head and returns its payload.
    fn string(&mut self, major: u8) -> Result<&'a [u8], DecodeError> {
        let h = self.head()?;
        if h.major != major {
            return Err(DecodeError::UnexpectedType);
        }
        let len = usize::try_from(h.arg).map_err(|_| DecodeError::LengthExceedsInput)?;
        let start = self.pos.checked_add(h.len).ok_or(DecodeError::Truncated)?;
        let end = start.checked_add(len).ok_or(DecodeError::Truncated)?;
        let payload = self.input.get(start..end).ok_or(DecodeError::Truncated)?;
        self.pos = end;
        Ok(payload)
    }

    /// The kind of the next item, without consuming it.
    pub fn peek_kind(&self) -> Result<Kind, DecodeError> {
        let h = self.head()?;
        Ok(match (h.major, h.arg) {
            (UINT, _) => Kind::Uint,
            (NEGATIVE, _) => Kind::Negative,
            (BYTES, _) => Kind::Bytes,
            (TEXT, _) => Kind::Text,
            (ARRAY, _) => Kind::Array,
            (MAP, _) => Kind::Map,
            (SIMPLE, FALSE | TRUE) => Kind::Bool,
            (SIMPLE, NULL) => Kind::Null,
            // read_head admits no other head.
            _ => return Err(DecodeError::UnsupportedSimple),
        })
    }

    /// Reads an unsigned integer.
    pub fn uint(&mut self) -> Result<u64, DecodeError> {
        self.expect(UINT)
    }

    /// Reads a negative integer as its raw argument `n`; the value is `-1 - n`.
    pub fn negative(&mut self) -> Result<u64, DecodeError> {
        self.expect(NEGATIVE)
    }

    /// Reads an unsigned or negative integer that fits in `i64`, otherwise
    /// returns [`DecodeError::OutOfRange`] without consuming it. Map keys are
    /// read with this.
    pub fn int(&mut self) -> Result<i64, DecodeError> {
        let h = self.head()?;
        let value = match h.major {
            UINT => i64::try_from(h.arg).map_err(|_| DecodeError::OutOfRange)?,
            // -1 - n, with n <= i64::MAX, is at least i64::MIN.
            NEGATIVE => -1 - i64::try_from(h.arg).map_err(|_| DecodeError::OutOfRange)?,
            _ => return Err(DecodeError::UnexpectedType),
        };
        self.advance(h.len)?;
        Ok(value)
    }

    /// Reads a byte string, borrowed from the input.
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        self.string(BYTES)
    }

    /// Reads a text string, borrowed from the input.
    pub fn text(&mut self) -> Result<&'a str, DecodeError> {
        let start = self.pos;
        let payload = self.string(TEXT)?;
        match core::str::from_utf8(payload) {
            Ok(s) => Ok(s),
            Err(_) => {
                self.pos = start;
                Err(DecodeError::InvalidUtf8)
            }
        }
    }

    /// Reads `false` or `true`.
    pub fn bool(&mut self) -> Result<bool, DecodeError> {
        let h = self.head()?;
        let value = match (h.major, h.arg) {
            (SIMPLE, FALSE) => false,
            (SIMPLE, TRUE) => true,
            _ => return Err(DecodeError::UnexpectedType),
        };
        self.advance(h.len)?;
        Ok(value)
    }

    /// Reads `null`.
    pub fn null(&mut self) -> Result<(), DecodeError> {
        if self.try_null()? {
            Ok(())
        } else {
            Err(DecodeError::UnexpectedType)
        }
    }

    /// Consumes a `null` and returns `true`, or returns `false` and consumes
    /// nothing.
    pub fn try_null(&mut self) -> Result<bool, DecodeError> {
        let h = self.head()?;
        if (h.major, h.arg) != (SIMPLE, NULL) {
            return Ok(false);
        }
        self.advance(h.len)?;
        Ok(true)
    }

    /// Reads an array header and returns its item count. The count is at most
    /// the remaining input length, but callers must still apply their own
    /// budget before allocating from it.
    pub fn array(&mut self) -> Result<u64, DecodeError> {
        self.expect(ARRAY)
    }

    /// Reads a map header and returns its entry count. The caller then reads
    /// that many (key, value) pairs, keys with [`Decoder::int`]. Keys arrive in
    /// canonical order without duplicates.
    pub fn map(&mut self) -> Result<u64, DecodeError> {
        self.expect(MAP)
    }

    /// Skips the next complete item.
    pub fn skip(&mut self) -> Result<(), DecodeError> {
        self.raw_item().map(|_| ())
    }

    /// Returns the exact bytes of the next complete item.
    pub fn raw_item(&mut self) -> Result<&'a [u8], DecodeError> {
        let item = validate_item(self.input, self.pos)?;
        let bytes = self
            .input
            .get(self.pos..item.end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = item.end;
        Ok(bytes)
    }

    /// Copies the next complete item into an owned [`RawValue`], for example
    /// an unknown map entry that must survive a rewrite.
    pub fn raw_value(&mut self) -> Result<RawValue, DecodeError> {
        let item = validate_item(self.input, self.pos)?;
        let bytes = self
            .input
            .get(self.pos..item.end)
            .ok_or(DecodeError::Truncated)?;
        self.pos = item.end;
        Ok(RawValue::new(bytes, item.depth))
    }

    /// Whether the whole input has been read.
    pub fn is_finished(&self) -> bool {
        self.pos == self.input.len()
    }

    /// Returns [`DecodeError::Unconsumed`] unless the whole input was read.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.is_finished() {
            Ok(())
        } else {
            Err(DecodeError::Unconsumed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_typed_reads() {
        // [0, 24, -1, -25, h'01', "a", true, false, null, {1: 2}]
        let input = [
            0x8a, 0x00, 0x18, 0x18, 0x20, 0x38, 0x18, 0x41, 0x01, 0x61, 0x61, 0xf5, 0xf4, 0xf6,
            0xa1, 0x01, 0x02,
        ];
        let mut d = Decoder::new(&input).unwrap();
        assert_eq!(d.peek_kind(), Ok(Kind::Array));
        assert_eq!(d.array(), Ok(10));
        assert_eq!(d.uint(), Ok(0));
        assert_eq!(d.int(), Ok(24));
        assert_eq!(d.peek_kind(), Ok(Kind::Negative));
        assert_eq!(d.int(), Ok(-1));
        assert_eq!(d.negative(), Ok(24));
        assert_eq!(d.bytes(), Ok(&[0x01][..]));
        assert_eq!(d.text(), Ok("a"));
        assert_eq!(d.peek_kind(), Ok(Kind::Bool));
        assert_eq!(d.bool(), Ok(true));
        assert_eq!(d.bool(), Ok(false));
        assert_eq!(d.peek_kind(), Ok(Kind::Null));
        assert_eq!(d.try_null(), Ok(true));
        assert_eq!(d.map(), Ok(1));
        assert_eq!(d.int(), Ok(1));
        assert!(!d.is_finished());
        assert_eq!(d.uint(), Ok(2));
        assert!(d.is_finished());
        assert_eq!(d.peek_kind(), Err(DecodeError::Truncated));
        assert_eq!(d.finish(), Ok(()));
    }

    #[test]
    fn decode_mismatch_leaves_cursor_in_place() {
        let input = [0x82, 0x61, 0x61, 0x01];
        let mut d = Decoder::new(&input).unwrap();
        assert_eq!(d.map(), Err(DecodeError::UnexpectedType));
        assert_eq!(d.array(), Ok(2));
        for wrong in [
            d.uint().err(),
            d.negative().err(),
            d.int().err(),
            d.bytes().err(),
            d.bool().err(),
            d.null().err(),
            d.array().err(),
        ] {
            assert_eq!(wrong, Some(DecodeError::UnexpectedType));
        }
        assert_eq!(d.try_null(), Ok(false));
        assert_eq!(d.text(), Ok("a"));
        assert_eq!(d.text(), Err(DecodeError::UnexpectedType));
        assert_eq!(d.uint(), Ok(1));
        d.finish().unwrap();
    }

    #[test]
    fn decode_int_range() {
        let max = [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut d = Decoder::new(&max).unwrap();
        assert_eq!(d.int(), Err(DecodeError::OutOfRange));
        assert_eq!(d.uint(), Ok(u64::MAX));

        let min = [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]; // -2^64
        let mut d = Decoder::new(&min).unwrap();
        assert_eq!(d.int(), Err(DecodeError::OutOfRange));
        assert_eq!(d.negative(), Ok(u64::MAX));

        let i64_max = [0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Decoder::new(&i64_max).unwrap().int(), Ok(i64::MAX));
        let i64_min = [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        assert_eq!(Decoder::new(&i64_min).unwrap().int(), Ok(i64::MIN));
        let below = [0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0]; // i64::MIN - 1
        assert_eq!(
            Decoder::new(&below).unwrap().int(),
            Err(DecodeError::OutOfRange)
        );
    }

    #[test]
    fn decode_new_validates_everything_first() {
        // The error is in the last item; nothing is readable.
        assert_eq!(
            Decoder::new(&[0x82, 0x01, 0xf7]).err(),
            Some(DecodeError::UnsupportedSimple)
        );
        assert_eq!(
            Decoder::new(&[0x01, 0x02]).err(),
            Some(DecodeError::TrailingBytes)
        );
    }

    #[test]
    fn decode_skip_and_raw_item_take_whole_subtrees() {
        // [[1, {2: [3]}], h'aa', 4]
        let input = [0x83, 0x82, 0x01, 0xa1, 0x02, 0x81, 0x03, 0x41, 0xaa, 0x04];
        let mut d = Decoder::new(&input).unwrap();
        d.array().unwrap();
        assert_eq!(d.raw_item(), Ok(&input[1..7]));
        d.skip().unwrap();
        assert_eq!(d.uint(), Ok(4));
        d.finish().unwrap();

        let mut d = Decoder::new(&input).unwrap();
        d.array().unwrap();
        assert_eq!(d.finish(), Err(DecodeError::Unconsumed));
    }

    #[test]
    fn decode_raw_value_owns_a_copy() {
        let input = [0x82, 0xa1, 0x05, 0x81, 0x80, 0x07];
        let mut d = Decoder::new(&input).unwrap();
        d.array().unwrap();
        let raw = d.raw_value().unwrap();
        assert_eq!(raw.as_bytes(), &input[1..5]);
        assert_eq!(raw.depth(), 3);
        assert_eq!(d.uint(), Ok(7));

        let mut inner = raw.decoder();
        assert_eq!(inner.map(), Ok(1));
        assert_eq!(inner.int(), Ok(5));
        assert_eq!(inner.array(), Ok(1));
        assert_eq!(inner.array(), Ok(0));
        inner.finish().unwrap();
    }
}
