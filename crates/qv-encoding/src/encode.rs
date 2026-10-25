// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encoder that can only produce canonical items.
//!
//! Containers are built through closures that write into a child encoder, so
//! counts are always exact and map entries can be sorted before they are
//! emitted. Buffers may hold secrets (spec 0008 §1.1): the encoder grows its
//! buffer itself, so `Vec` never reallocates and leaves an unwiped copy
//! behind. The old buffer is wiped on every growth, and every buffer is wiped
//! on drop.

use core::mem;

use zeroize::{Zeroize, Zeroizing};

use crate::MAX_DEPTH;
use crate::error::EncodeError;
use crate::head::{
    ARRAY, BYTES, FALSE, MAP, NEGATIVE, NULL, SIMPLE, TEXT, TRUE, UINT, encode_head,
};
use crate::raw::RawValue;

/// Smallest buffer allocated on first write.
const MIN_CAPACITY: usize = 64;

/// Builds exactly one canonical item.
///
/// It has no `Debug`: the bytes it holds may be secret.
pub struct Encoder {
    buf: Vec<u8>,
    /// Top-level items written so far.
    items: u64,
    /// Deepest container nesting among the items written.
    depth: usize,
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Encoder {
    /// An empty encoder.
    pub fn new() -> Self {
        Self {
            buf: Vec::new(),
            items: 0,
            depth: 0,
        }
    }

    /// Makes room for `n` more bytes. Growth copies into a new allocation and
    /// wipes the old one.
    fn reserve(&mut self, n: usize) {
        let needed = self.buf.len().saturating_add(n);
        if needed <= self.buf.capacity() {
            return;
        }
        let capacity = needed
            .max(self.buf.capacity().saturating_mul(2))
            .max(MIN_CAPACITY);
        let mut grown = Vec::with_capacity(capacity);
        grown.extend_from_slice(&self.buf);
        // Wipes the contents and the spare capacity before the old buffer is freed.
        self.buf.zeroize();
        self.buf = grown;
    }

    fn put(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        let capacity = self.buf.capacity();
        self.buf.extend_from_slice(bytes);
        debug_assert_eq!(capacity, self.buf.capacity(), "Vec reallocated by itself");
    }

    fn put_head(&mut self, major: u8, arg: u64) {
        let (head, len) = encode_head(major, arg);
        // len is at most 9, the array's size.
        self.put(&head[..len]);
    }

    /// Writes an unsigned integer.
    pub fn uint(&mut self, v: u64) {
        self.put_head(UINT, v);
        self.items += 1;
    }

    /// Writes the negative integer `-1 - n`.
    pub fn negative(&mut self, n: u64) {
        self.put_head(NEGATIVE, n);
        self.items += 1;
    }

    /// Writes a signed integer.
    pub fn int(&mut self, v: i64) {
        match u64::try_from(v) {
            Ok(u) => self.uint(u),
            // v < 0, so -1 - v is in 0..=i64::MAX and the cast is lossless.
            Err(_) => self.negative((-1 - v) as u64),
        }
    }

    /// Writes a byte string.
    pub fn bytes(&mut self, v: &[u8]) {
        self.put_head(BYTES, v.len() as u64);
        self.put(v);
        self.items += 1;
    }

    /// Writes a text string.
    pub fn text(&mut self, v: &str) {
        self.put_head(TEXT, v.len() as u64);
        self.put(v.as_bytes());
        self.items += 1;
    }

    /// Writes `false` or `true`.
    pub fn bool(&mut self, v: bool) {
        self.put_head(SIMPLE, if v { TRUE } else { FALSE });
        self.items += 1;
    }

    /// Writes `null`.
    pub fn null(&mut self) {
        self.put_head(SIMPLE, NULL);
        self.items += 1;
    }

    /// Writes a canonical item verbatim.
    pub fn raw(&mut self, v: &RawValue) -> Result<(), EncodeError> {
        if v.depth() > MAX_DEPTH {
            return Err(EncodeError::DepthExceeded);
        }
        self.put(v.as_bytes());
        self.depth = self.depth.max(v.depth());
        self.items += 1;
        Ok(())
    }

    /// Writes an array. `f` writes its items; the header gets the exact count.
    pub fn array(
        &mut self,
        f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        let mut child = Encoder::new();
        f(&mut child)?;
        let depth = child.depth + 1;
        if depth > MAX_DEPTH {
            return Err(EncodeError::DepthExceeded);
        }
        self.put_head(ARRAY, child.items);
        self.put(&child.buf);
        self.depth = self.depth.max(depth);
        self.items += 1;
        Ok(())
    }

    /// Writes a map. `f` adds entries in any order; they are emitted sorted
    /// by encoded key. A repeated key gives [`EncodeError::DuplicateKey`].
    pub fn map(
        &mut self,
        f: impl FnOnce(&mut MapEncoder) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        let mut m = MapEncoder {
            entries: Vec::new(),
        };
        f(&mut m)?;
        m.entries.sort_by(|a, b| a.key().cmp(b.key()));
        if m.entries.windows(2).any(|w| w[0].key() == w[1].key()) {
            return Err(EncodeError::DuplicateKey);
        }
        let depth = 1 + m.entries.iter().map(|e| e.value.depth).max().unwrap_or(0);
        if depth > MAX_DEPTH {
            return Err(EncodeError::DepthExceeded);
        }
        self.put_head(MAP, m.entries.len() as u64);
        for e in &m.entries {
            self.put(e.key());
            self.put(&e.value.buf);
        }
        self.depth = self.depth.max(depth);
        self.items += 1;
        Ok(())
    }

    /// Returns the encoding, wiped when dropped. Fails with
    /// [`EncodeError::ItemCount`] unless exactly one item was written.
    pub fn finish(mut self) -> Result<Zeroizing<Vec<u8>>, EncodeError> {
        if self.items != 1 {
            return Err(EncodeError::ItemCount);
        }
        Ok(Zeroizing::new(mem::take(&mut self.buf)))
    }
}

impl Drop for Encoder {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

struct Entry {
    key: [u8; 9],
    key_len: usize,
    value: Encoder,
}

impl Entry {
    fn key(&self) -> &[u8] {
        // key_len is at most 9, the array's size.
        &self.key[..self.key_len]
    }
}

/// Collects map entries for [`Encoder::map`].
///
/// It has no `Debug`: the values it holds may be secret.
pub struct MapEncoder {
    entries: Vec<Entry>,
}

impl MapEncoder {
    fn push(&mut self, key: i64, value: Encoder) -> Result<(), EncodeError> {
        if value.items != 1 {
            return Err(EncodeError::ItemCount);
        }
        let (key, key_len) = match u64::try_from(key) {
            Ok(u) => encode_head(UINT, u),
            // key < 0, so -1 - key is in 0..=i64::MAX and the cast is lossless.
            Err(_) => encode_head(NEGATIVE, (-1 - key) as u64),
        };
        self.entries.push(Entry {
            key,
            key_len,
            value,
        });
        Ok(())
    }

    /// Adds an entry. `f` must write exactly one item, the value.
    pub fn entry(
        &mut self,
        key: i64,
        f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
    ) -> Result<(), EncodeError> {
        let mut value = Encoder::new();
        f(&mut value)?;
        self.push(key, value)
    }

    /// Adds an entry whose value is kept verbatim (an unknown key being preserved).
    pub fn raw_entry(&mut self, key: i64, v: &RawValue) -> Result<(), EncodeError> {
        let mut value = Encoder::new();
        value.raw(v)?;
        self.push(key, value)
    }
}

/// Encodes one canonical array: the builder for AAD, HKDF info and
/// transcripts (spec 0002 §7.2).
///
/// ```
/// let info = qv_encoding::encode_array(|a| {
///     a.text("qv/kek/v1");
///     a.uint(1);
///     Ok(())
/// })
/// .unwrap();
/// assert_eq!(info.as_slice(), b"\x82\x69qv/kek/v1\x01");
/// ```
pub fn encode_array(
    f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
) -> Result<Zeroizing<Vec<u8>>, EncodeError> {
    let mut e = Encoder::new();
    e.array(f)?;
    e.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validate::validate;

    fn one(f: impl FnOnce(&mut Encoder)) -> Vec<u8> {
        let mut e = Encoder::new();
        f(&mut e);
        let out = e.finish().unwrap().to_vec();
        validate(&out).unwrap();
        out
    }

    #[test]
    fn encode_rfc_8949_appendix_a() {
        assert_eq!(one(|e| e.uint(0)), [0x00]);
        assert_eq!(one(|e| e.uint(1_000_000)), [0x1a, 0x00, 0x0f, 0x42, 0x40]);
        assert_eq!(
            one(|e| e.uint(u64::MAX)),
            [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(one(|e| e.int(-1)), [0x20]);
        assert_eq!(one(|e| e.int(-10)), [0x29]);
        assert_eq!(one(|e| e.int(-1000)), [0x39, 0x03, 0xe7]);
        assert_eq!(
            one(|e| e.int(i64::MIN)),
            [0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            one(|e| e.negative(u64::MAX)),
            [0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(one(|e| e.bytes(&[])), [0x40]);
        assert_eq!(one(|e| e.bytes(&[1, 2, 3, 4])), [0x44, 1, 2, 3, 4]);
        assert_eq!(one(|e| e.text("")), [0x60]);
        assert_eq!(one(|e| e.text("IETF")), [0x64, 0x49, 0x45, 0x54, 0x46]);
        assert_eq!(one(|e| e.text("\u{00fc}")), [0x62, 0xc3, 0xbc]);
        assert_eq!(one(|e| e.bool(false)), [0xf4]);
        assert_eq!(one(|e| e.bool(true)), [0xf5]);
        assert_eq!(one(|e| e.null()), [0xf6]);
        assert_eq!(one(|e| e.array(|_| Ok(())).unwrap()), [0x80]);
        assert_eq!(
            one(|e| e
                .array(|a| {
                    a.uint(1);
                    a.array(|b| {
                        b.uint(2);
                        b.uint(3);
                        Ok(())
                    })?;
                    a.array(|b| {
                        b.uint(4);
                        b.uint(5);
                        Ok(())
                    })
                })
                .unwrap()),
            [0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05]
        );
        let long: Vec<u8> = {
            let mut v = vec![0x98, 0x19];
            v.extend(1..=23u8);
            v.extend([0x18, 0x18, 0x18, 0x19]);
            v
        };
        assert_eq!(
            one(|e| e
                .array(|a| {
                    (1..=25).for_each(|i| a.uint(i));
                    Ok(())
                })
                .unwrap()),
            long
        );
        assert_eq!(one(|e| e.map(|_| Ok(())).unwrap()), [0xa0]);
    }

    #[test]
    fn encode_map_sorts_by_encoded_key() {
        let out = one(|e| {
            e.map(|m| {
                for k in [-1, 24, 3, -25, 0, 23, i64::MIN, i64::MAX] {
                    m.entry(k, |v| {
                        v.null();
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap()
        });
        let keys: &[&[u8]] = &[
            &[0x00],
            &[0x03],
            &[0x17],
            &[0x18, 0x18],
            &[0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            &[0x20],
            &[0x38, 0x18],
            &[0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ];
        let mut expected = vec![0xa8];
        for k in keys {
            expected.extend_from_slice(k);
            expected.push(0xf6);
        }
        assert_eq!(out, expected);
    }

    #[test]
    fn encode_map_rejects_duplicates() {
        let mut e = Encoder::new();
        let r = e.map(|m| {
            m.entry(7, |v| {
                v.uint(1);
                Ok(())
            })?;
            m.entry(7, |v| {
                v.uint(2);
                Ok(())
            })
        });
        assert_eq!(r, Err(EncodeError::DuplicateKey));
        assert_eq!(e.finish().err(), Some(EncodeError::ItemCount));
    }

    #[test]
    fn encode_item_counts_are_enforced() {
        let mut e = Encoder::new();
        assert_eq!(
            e.map(|m| m.entry(1, |_| Ok(()))),
            Err(EncodeError::ItemCount)
        );
        assert_eq!(
            e.map(|m| m.entry(1, |v| {
                v.uint(1);
                v.uint(2);
                Ok(())
            })),
            Err(EncodeError::ItemCount)
        );
        assert_eq!(Encoder::new().finish().err(), Some(EncodeError::ItemCount));
        let mut two = Encoder::new();
        two.uint(1);
        two.uint(2);
        assert_eq!(two.finish().err(), Some(EncodeError::ItemCount));
    }

    fn nest(e: &mut Encoder, levels: usize) -> Result<(), EncodeError> {
        if levels == 0 {
            e.uint(0);
            return Ok(());
        }
        e.array(|a| nest(a, levels - 1))
    }

    #[test]
    fn encode_depth_limit() {
        let mut e = Encoder::new();
        nest(&mut e, 32).unwrap();
        let out = e.finish().unwrap();
        validate(&out).unwrap();

        let mut e = Encoder::new();
        assert_eq!(nest(&mut e, 33), Err(EncodeError::DepthExceeded));

        // Maps count too.
        let mut e = Encoder::new();
        let r = e.map(|m| m.entry(0, |v| nest(v, 32)));
        assert_eq!(r, Err(EncodeError::DepthExceeded));

        // A raw value of depth 32 fits at the top, but not inside an array.
        let raw = RawValue::from_canonical(&out).unwrap();
        let mut e = Encoder::new();
        e.raw(&raw).unwrap();
        assert_eq!(e.finish().unwrap().as_slice(), out.as_slice());
        let mut e = Encoder::new();
        assert_eq!(e.array(|a| a.raw(&raw)), Err(EncodeError::DepthExceeded));
        let mut e = Encoder::new();
        assert_eq!(
            e.map(|m| m.raw_entry(1, &raw)),
            Err(EncodeError::DepthExceeded)
        );
    }

    #[test]
    fn encode_growth_keeps_content() {
        let big: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
        let out = one(|e| {
            e.array(|a| {
                for chunk in big.chunks(97) {
                    a.bytes(chunk);
                }
                a.text(&"x".repeat(5000));
                Ok(())
            })
            .unwrap()
        });
        let mut d = crate::Decoder::new(&out).unwrap();
        let n = d.array().unwrap();
        let mut joined = Vec::new();
        for _ in 0..n - 1 {
            joined.extend_from_slice(d.bytes().unwrap());
        }
        assert_eq!(joined, big);
        assert_eq!(d.text().unwrap().len(), 5000);
        d.finish().unwrap();
    }

    #[test]
    fn encode_array_builds_transcripts() {
        let out = encode_array(|a| {
            a.text("qv/kek/v1");
            a.uint(1);
            Ok(())
        })
        .unwrap();
        let mut expected = vec![0x82, 0x69];
        expected.extend_from_slice(b"qv/kek/v1");
        expected.push(0x01);
        assert_eq!(out.as_slice(), expected.as_slice());
        // Errors from the builder pass through.
        assert_eq!(
            encode_array(|_| Err(EncodeError::DuplicateKey)).err(),
            Some(EncodeError::DuplicateKey)
        );
    }
}
