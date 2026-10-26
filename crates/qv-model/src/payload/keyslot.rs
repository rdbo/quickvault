// SPDX-License-Identifier: AGPL-3.0-or-later

//! The password-keyslot record (spec 0003 §2.3, 0002 §3.2).
//!
//! One atomic slot descriptor; its fields are never merged individually
//! (0005 §2.6).
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | slot_id | bstr 16 |
//! | 1 | kdf_profile | uint (u16) |
//! | 2 | kdf_salt | bstr 32 |
//! | 3 | wrap_profile | uint (u16) |
//! | 4 | kek_commit | bstr 32 |
//! | 5 | nonce | bstr 24 |
//! | 6 | wrapped_vk | bstr 48 |
//!
//! All keys are required. An unknown profile ID fails closed
//! ([`ModelError::Unsupported`]).

use qv_crypto::{MacTag, PasswordKdfProfile, PasswordSlot, PasswordWrapProfile};
use qv_encoding::{Decoder, EncodeError, Encoder};

use zeroize::Zeroizing;

use crate::codec::{
    encode_item, keep, put_bytes, put_ext, put_id, put_uint, read_array, read_id, read_map_len,
    read_u16, req,
};
use crate::error::ModelError;
use crate::ids::is_v4;
use crate::text::{Extensions, MAX_RECORD_BYTES};

/// The password-keyslot record's payload.
pub struct Keyslot {
    /// The slot descriptor.
    pub slot: PasswordSlot,
    /// Unknown keys.
    pub ext: Extensions,
}

// A slot enables offline guessing; it is not printed (0004 §6.4).
crate::redacted_debug!(Keyslot);

impl Keyslot {
    /// The bare descriptor map: the same bytes as the payload of a keyslot
    /// record version. The vault file stores local slots in this encoding.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ModelError> {
        if !is_v4(&self.slot.slot_id.0) {
            return Err(ModelError::Malformed);
        }
        encode_item(|e| encode(self, e))
    }

    /// Decodes a bare descriptor map strictly: canonical, no trailing bytes,
    /// known profiles only ([`ModelError::Unsupported`] otherwise).
    pub fn decode(input: &[u8]) -> Result<Keyslot, ModelError> {
        if input.len() > MAX_RECORD_BYTES {
            return Err(ModelError::LimitExceeded);
        }
        let mut d = Decoder::new(input)?;
        let slot = decode(&mut d)?;
        d.finish()?;
        Ok(slot)
    }
}

pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Keyslot, ModelError> {
    let (mut id, mut kdf, mut salt, mut wrap, mut commit, mut nonce, mut wrapped) =
        (None, None, None, None, None, None, None);
    let mut ext = Extensions::new();
    let unsupported = |_| ModelError::Unsupported;
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => id = Some(read_id(d)?),
            1 => kdf = Some(PasswordKdfProfile::from_id(read_u16(d)?).map_err(unsupported)?),
            2 => salt = Some(read_array::<32>(d)?),
            3 => wrap = Some(PasswordWrapProfile::from_id(read_u16(d)?).map_err(unsupported)?),
            4 => commit = Some(read_array::<32>(d)?),
            5 => nonce = Some(read_array::<24>(d)?),
            6 => wrapped = Some(read_array::<48>(d)?),
            k => keep(&mut ext, k, d)?,
        }
    }
    Ok(Keyslot {
        slot: PasswordSlot {
            slot_id: req(id)?,
            kdf_profile: req(kdf)?,
            kdf_salt: req(salt)?,
            wrap_profile: req(wrap)?,
            kek_commit: MacTag::from_bytes(req(commit)?),
            nonce: req(nonce)?,
            wrapped_vk: req(wrapped)?,
        },
        ext,
    })
}

pub(crate) fn encode(p: &Keyslot, e: &mut Encoder) -> Result<(), EncodeError> {
    let s = &p.slot;
    e.map(|m| {
        put_id(m, 0, &s.slot_id)?;
        put_uint(m, 1, u64::from(s.kdf_profile.id()))?;
        put_bytes(m, 2, &s.kdf_salt)?;
        put_uint(m, 3, u64::from(s.wrap_profile.id()))?;
        put_bytes(m, 4, s.kek_commit.as_bytes())?;
        put_bytes(m, 5, &s.nonce)?;
        put_bytes(m, 6, &s.wrapped_vk)?;
        put_ext(m, &p.ext)
    })
}
