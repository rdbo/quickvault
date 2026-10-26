// SPDX-License-Identifier: AGPL-3.0-or-later

//! Random UUIDv4 identifiers (spec 0003 §1.1, 0005 §1.1).
//!
//! Every model ID is 16 random bytes with the RFC 9562 version (4) and
//! variant (`10`) bits set. [`RandomId::generate`] sets the bits and
//! [`RandomId::from_bytes`] rejects IDs without them, so a time-ordered ID
//! (UUIDv7) never enters the model. IDs are not secrets.
//!
//! The model's own IDs have private fields: [`RandomId`] is the only way to
//! build one, so the v4 bits are a type invariant. The IDs that also enter
//! key derivation ([`VaultId`], [`RecordId`], [`AttachmentId`], [`SlotId`])
//! live in `qv-crypto` with public fields and get the same trait here; for
//! them the invariant is enforced where they cross the model boundary: on
//! decode, and by the payload checks before every encode.

use qv_crypto::random_array;
pub use qv_crypto::{AttachmentId, RecordId, SlotId, VaultId};

use crate::error::ModelError;

/// A 128-bit random UUIDv4 identifier.
pub trait RandomId: Sized + Copy {
    /// A fresh ID from the OS CSPRNG, with the v4 bits set.
    fn generate() -> Result<Self, ModelError>;
    /// Wraps stored bytes; [`ModelError::Malformed`] without the v4 bits.
    fn from_bytes(bytes: [u8; 16]) -> Result<Self, ModelError>;
    /// The ID's bytes.
    fn to_bytes(&self) -> [u8; 16];
}

/// Whether `bytes` carry the UUIDv4 version and RFC 9562 variant bits.
pub(crate) fn is_v4(bytes: &[u8; 16]) -> bool {
    bytes[6] >> 4 == 4 && bytes[8] & 0xc0 == 0x80
}

/// 16 random bytes with the v4 bits set.
fn random_v4() -> Result<[u8; 16], ModelError> {
    let mut b = random_array::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(b)
}

macro_rules! model_ids {
    ($($(#[$doc:meta])* $name:ident;)+) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);
    )+};
}

model_ids! {
    /// A version's ID (0005 §1.1). The browsing representative of a conflict
    /// is the lexicographically largest one (0005 §2.3), which is the derived
    /// `Ord`.
    VersionId;
    /// One local replica of a vault (0005 §1.1, §1.3).
    WriterId;
    /// A field's stable ID within an entry, for UI handles (0003 §5).
    FieldId;
    /// An encrypted object's ID (0004 §2.1).
    ObjectId;
}

macro_rules! random_id {
    ($($name:ident),+) => {$(
        impl RandomId for $name {
            fn generate() -> Result<Self, ModelError> {
                Ok(Self(random_v4()?))
            }

            fn from_bytes(bytes: [u8; 16]) -> Result<Self, ModelError> {
                if is_v4(&bytes) {
                    Ok(Self(bytes))
                } else {
                    Err(ModelError::Malformed)
                }
            }

            fn to_bytes(&self) -> [u8; 16] {
                self.0
            }
        }
    )+};
}

random_id!(
    VaultId,
    RecordId,
    AttachmentId,
    SlotId,
    VersionId,
    WriterId,
    FieldId,
    ObjectId
);

/// The attachment ID of an `attachment_meta` record: its record ID
/// (0003 §6.1 has no separate attachment ID field; 0004 §3.3 keys chunks by
/// attachment ID).
pub fn attachment_id(record: RecordId) -> AttachmentId {
    AttachmentId(record.0)
}

#[cfg(test)]
pub(crate) mod test_ids {
    //! Deterministic v4 IDs for tests.

    use super::*;

    /// A v4 ID whose first byte is `n` (so IDs sort by `n`).
    pub(crate) fn v4(n: u8) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = n;
        b[6] = 0x40;
        b[8] = 0x80;
        b
    }

    pub(crate) fn rid(n: u8) -> RecordId {
        RecordId::from_bytes(v4(n)).unwrap()
    }

    pub(crate) fn vid(n: u8) -> VersionId {
        VersionId::from_bytes(v4(n)).unwrap()
    }

    pub(crate) fn wid(n: u8) -> WriterId {
        WriterId::from_bytes(v4(n)).unwrap()
    }

    pub(crate) fn fid(n: u8) -> FieldId {
        FieldId::from_bytes(v4(n)).unwrap()
    }

    pub(crate) fn oid(n: u8) -> ObjectId {
        ObjectId::from_bytes(v4(n)).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn ids_generated_are_v4_and_distinct() {
        let mut seen = BTreeSet::new();
        for _ in 0..1000 {
            let id = VersionId::generate().unwrap();
            let b = id.to_bytes();
            assert!(is_v4(&b));
            assert_eq!(b[6] >> 4, 4);
            assert_eq!(b[8] >> 6, 0b10);
            assert!(seen.insert(b));
        }
        let r = RecordId::generate().unwrap();
        assert_eq!(RecordId::from_bytes(r.to_bytes()), Ok(r));
    }

    #[test]
    fn ids_without_v4_bits_are_rejected() {
        // A UUIDv7 (time-ordered) ID.
        let mut v7 = test_ids::v4(1);
        v7[6] = 0x70;
        assert_eq!(WriterId::from_bytes(v7), Err(ModelError::Malformed));
        // Version 4 with the wrong variant.
        let mut variant = test_ids::v4(1);
        variant[8] = 0xc0;
        assert_eq!(FieldId::from_bytes(variant), Err(ModelError::Malformed));
        assert_eq!(VaultId::from_bytes([0; 16]), Err(ModelError::Malformed));
        assert_eq!(ObjectId::from_bytes([0xff; 16]), Err(ModelError::Malformed));
        assert!(SlotId::from_bytes(test_ids::v4(2)).is_ok());
    }

    #[test]
    fn attachment_id_is_the_record_id() {
        let r = test_ids::rid(7);
        assert_eq!(attachment_id(r).to_bytes(), r.to_bytes());
    }

    #[test]
    fn version_ids_order_bytewise() {
        assert!(test_ids::vid(1) < test_ids::vid(2));
        assert!(test_ids::vid(0x7f) < test_ids::vid(0x80));
    }
}
