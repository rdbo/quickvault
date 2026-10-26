// SPDX-License-Identifier: AGPL-3.0-or-later

//! Typed read and write helpers over the canonical codec.
//!
//! Decoders read a map's entries in canonical key order, put known keys into
//! `Option` slots and unknown keys into [`Extensions`]. The codec guarantees
//! unique keys, so a slot is never filled twice. Optional keys are absent
//! when the value is absent; a `null` where a value is expected fails the
//! typed read and is [`ModelError::Malformed`], so each value has exactly one
//! encoding.

use qv_encoding::{Decoder, EncodeError, Encoder, MapEncoder};

use crate::error::ModelError;
use crate::ids::RandomId;
use crate::text::{Extensions, Text};
use crate::time::Timestamp;

/// A required key's value, or [`ModelError::Malformed`].
pub(crate) fn req<T>(slot: Option<T>) -> Result<T, ModelError> {
    slot.ok_or(ModelError::Malformed)
}

/// A bounded text value (checked before copying).
pub(crate) fn read_text(d: &mut Decoder<'_>) -> Result<Text, ModelError> {
    Text::new(d.text()?)
}

/// A 16-byte UUIDv4 ID.
pub(crate) fn read_id<T: RandomId>(d: &mut Decoder<'_>) -> Result<T, ModelError> {
    T::from_bytes(read_array::<16>(d)?)
}

/// A byte string of exactly `N` bytes.
pub(crate) fn read_array<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], ModelError> {
    d.bytes()?.try_into().map_err(|_| ModelError::Malformed)
}

/// An unsigned integer that fits in `u32`.
pub(crate) fn read_u32(d: &mut Decoder<'_>) -> Result<u32, ModelError> {
    u32::try_from(d.uint()?).map_err(|_| ModelError::Malformed)
}

/// An unsigned integer that fits in `u16`.
pub(crate) fn read_u16(d: &mut Decoder<'_>) -> Result<u16, ModelError> {
    u16::try_from(d.uint()?).map_err(|_| ModelError::Malformed)
}

/// A timestamp (any integer that fits in `i64`).
pub(crate) fn read_time(d: &mut Decoder<'_>) -> Result<Timestamp, ModelError> {
    Ok(Timestamp(d.int()?))
}

/// An array header whose count is at most `max` ([`ModelError::LimitExceeded`]
/// otherwise), checked before the caller allocates.
pub(crate) fn read_array_len(d: &mut Decoder<'_>, max: usize) -> Result<usize, ModelError> {
    let n = usize::try_from(d.array()?).map_err(|_| ModelError::LimitExceeded)?;
    if n > max {
        return Err(ModelError::LimitExceeded);
    }
    Ok(n)
}

/// A map header's entry count.
pub(crate) fn read_map_len(d: &mut Decoder<'_>) -> Result<u64, ModelError> {
    Ok(d.map()?)
}

/// Keeps an unknown entry verbatim.
pub(crate) fn keep(ext: &mut Extensions, key: i64, d: &mut Decoder<'_>) -> Result<(), ModelError> {
    ext.push(key, d.raw_value()?);
    Ok(())
}

pub(crate) fn put_text(m: &mut MapEncoder, key: i64, t: &Text) -> Result<(), EncodeError> {
    m.entry(key, |v| {
        v.text(t.expose());
        Ok(())
    })
}

pub(crate) fn put_opt_text(
    m: &mut MapEncoder,
    key: i64,
    t: Option<&Text>,
) -> Result<(), EncodeError> {
    match t {
        Some(t) => put_text(m, key, t),
        None => Ok(()),
    }
}

pub(crate) fn put_id(m: &mut MapEncoder, key: i64, id: &impl RandomId) -> Result<(), EncodeError> {
    m.entry(key, |v| {
        v.bytes(&id.to_bytes());
        Ok(())
    })
}

pub(crate) fn put_bytes(m: &mut MapEncoder, key: i64, b: &[u8]) -> Result<(), EncodeError> {
    m.entry(key, |v| {
        v.bytes(b);
        Ok(())
    })
}

pub(crate) fn put_uint(m: &mut MapEncoder, key: i64, n: u64) -> Result<(), EncodeError> {
    m.entry(key, |v| {
        v.uint(n);
        Ok(())
    })
}

pub(crate) fn put_opt_uint(
    m: &mut MapEncoder,
    key: i64,
    n: Option<u64>,
) -> Result<(), EncodeError> {
    match n {
        Some(n) => put_uint(m, key, n),
        None => Ok(()),
    }
}

pub(crate) fn put_bool(m: &mut MapEncoder, key: i64, b: bool) -> Result<(), EncodeError> {
    m.entry(key, |v| {
        v.bool(b);
        Ok(())
    })
}

pub(crate) fn put_time(m: &mut MapEncoder, key: i64, t: Timestamp) -> Result<(), EncodeError> {
    m.entry(key, |v| {
        v.int(t.0);
        Ok(())
    })
}

pub(crate) fn put_opt_time(
    m: &mut MapEncoder,
    key: i64,
    t: Option<Timestamp>,
) -> Result<(), EncodeError> {
    match t {
        Some(t) => put_time(m, key, t),
        None => Ok(()),
    }
}

/// Writes every unknown entry back.
pub(crate) fn put_ext(m: &mut MapEncoder, ext: &Extensions) -> Result<(), EncodeError> {
    for (k, v) in ext.iter() {
        m.raw_entry(*k, v)?;
    }
    Ok(())
}

/// Encodes one item with `f`.
pub(crate) fn encode_item(
    f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
) -> Result<zeroize::Zeroizing<Vec<u8>>, ModelError> {
    let mut e = Encoder::new();
    f(&mut e)?;
    Ok(e.finish()?)
}
