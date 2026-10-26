// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local keyslots (spec 0004 §2, 0002 §3.2).
//!
//! A `keyslot` row is `(slot_id, type, body)`. Type 0 is a password slot
//! and its body is the canonical slot descriptor of `qv_model::Keyslot`, the
//! same bytes as the payload of the password-keyslot record. Other types
//! (quick unlock, phase 2.6) are [`StoreError::Unsupported`]. Unknown
//! descriptor keys are preserved; the header MAC covers them. Version 1 of
//! the development format requires exactly one password slot.

use qv_crypto::{PasswordSlot, SlotId};
use qv_model::{Keyslot, RandomId};

use crate::error::StoreError;
use crate::header::SlotRow;
use crate::schema::StoredSlot;

/// Slot type of a password slot.
pub(crate) const PASSWORD_SLOT: u64 = 0;

/// A decoded local slot with its exact stored bytes.
pub(crate) struct LocalSlot {
    pub(crate) slot_id: SlotId,
    pub(crate) kind: u64,
    pub(crate) body: Vec<u8>,
    pub(crate) keyslot: Keyslot,
}

impl LocalSlot {
    /// Decodes a stored row: known type, valid descriptor, descriptor ID
    /// equal to the row key.
    pub(crate) fn from_stored(row: StoredSlot) -> Result<Self, StoreError> {
        if row.kind != PASSWORD_SLOT {
            return Err(StoreError::Unsupported);
        }
        let slot_id = SlotId::from_bytes(row.slot_id)?;
        let keyslot = Keyslot::decode(&row.body)?;
        if keyslot.slot.slot_id != slot_id {
            return Err(StoreError::Integrity);
        }
        Ok(Self {
            slot_id,
            kind: row.kind,
            body: row.body,
            keyslot,
        })
    }

    /// A new password slot row for `slot`.
    pub(crate) fn password(slot: PasswordSlot) -> Result<Self, StoreError> {
        let keyslot = Keyslot {
            slot,
            ext: qv_model::Extensions::new(),
        };
        let body = keyslot.encode()?.to_vec();
        Ok(Self {
            slot_id: keyslot.slot.slot_id,
            kind: PASSWORD_SLOT,
            body,
            keyslot,
        })
    }

    /// The row as the header MAC sees it.
    pub(crate) fn row(&self) -> SlotRow<'_> {
        SlotRow {
            slot_id: &self.slot_id.0,
            kind: self.kind,
            body: &self.body,
        }
    }
}

/// The one password slot ([`StoreError::Integrity`] for zero or several).
pub(crate) fn password_slot(slots: &[LocalSlot]) -> Result<&LocalSlot, StoreError> {
    let mut found = slots.iter().filter(|s| s.kind == PASSWORD_SLOT);
    match (found.next(), found.next()) {
        (Some(s), None) => Ok(s),
        _ => Err(StoreError::Integrity),
    }
}

#[cfg(test)]
mod tests {
    use qv_crypto::{MacTag, PasswordKdfProfile, PasswordWrapProfile};

    use super::*;
    use crate::header::tests::v4;

    fn descriptor(id: [u8; 16]) -> Vec<u8> {
        let slot = PasswordSlot {
            slot_id: SlotId(id),
            kdf_profile: PasswordKdfProfile::V1,
            kdf_salt: [1; 32],
            wrap_profile: PasswordWrapProfile::V1,
            kek_commit: MacTag::from_bytes([2; 32]),
            nonce: [3; 24],
            wrapped_vk: [4; 48],
        };
        LocalSlot::password(slot).unwrap().body
    }

    fn stored(id: [u8; 16], kind: u64, body: Vec<u8>) -> StoredSlot {
        StoredSlot {
            slot_id: id,
            kind,
            body,
        }
    }

    #[test]
    fn slot_decodes_and_checks_identity() {
        let s = LocalSlot::from_stored(stored(v4(1), 0, descriptor(v4(1)))).unwrap();
        assert_eq!(s.slot_id, SlotId(v4(1)));
        assert_eq!(s.keyslot.slot.kdf_salt, [1; 32]);
        assert_eq!(s.row().body, descriptor(v4(1)).as_slice());
        // Descriptor ID differs from the row key.
        assert_eq!(
            LocalSlot::from_stored(stored(v4(2), 0, descriptor(v4(1)))).err(),
            Some(StoreError::Integrity)
        );
        // Unknown slot type.
        assert_eq!(
            LocalSlot::from_stored(stored(v4(1), 1, descriptor(v4(1)))).err(),
            Some(StoreError::Unsupported)
        );
        // Non-v4 row key, garbage body.
        assert_eq!(
            LocalSlot::from_stored(stored([0; 16], 0, descriptor(v4(1)))).err(),
            Some(StoreError::Integrity)
        );
        assert_eq!(
            LocalSlot::from_stored(stored(v4(1), 0, vec![0xa0])).err(),
            Some(StoreError::Integrity)
        );
        // Unknown KDF profile in the descriptor: fails before any KDF.
        let mut body = descriptor(v4(1));
        let pos = body.windows(2).position(|w| w == [0x01, 0x01]).unwrap();
        body[pos + 1] = 0x02;
        assert_eq!(
            LocalSlot::from_stored(stored(v4(1), 0, body)).err(),
            Some(StoreError::Unsupported)
        );
    }

    #[test]
    fn slot_exactly_one_password_slot() {
        let a = LocalSlot::from_stored(stored(v4(1), 0, descriptor(v4(1)))).unwrap();
        let b = LocalSlot::from_stored(stored(v4(2), 0, descriptor(v4(2)))).unwrap();
        assert_eq!(password_slot(&[]).err(), Some(StoreError::Integrity));
        assert!(password_slot(std::slice::from_ref(&a)).is_ok());
        assert_eq!(password_slot(&[a, b]).err(), Some(StoreError::Integrity));
    }
}
