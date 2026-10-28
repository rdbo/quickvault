// SPDX-License-Identifier: AGPL-3.0-or-later

//! Encrypted objects and record encryption (spec 0004 §2.1–2.2, §3.2).
//!
//! An object's plaintext metadata is limited to its object ID, key
//! generation, data profile, nonce and ciphertext (0004 §2.2). Which record,
//! version, attachment or chunk an object holds is known only from the
//! encrypted manifest. [`ObjectEnvelope`] is the portable form, the canonical
//! array `[object_id, key_generation, data_profile, nonce, ciphertext]`; the
//! `object` table stores the same five values as columns.
//!
//! A record version is encrypted under its per-record key with stored-data/1
//! and the AAD `["qv/record/v1", vault_id, key_generation, record_id,
//! version_id, object_id, data_profile]`. The record and version IDs come
//! from the manifest role, never from the envelope. The decrypted
//! `version_id` and clock must equal the role's.

use qv_crypto::{KeyGeneration, PurposeKey, RecordId, StoredDataProfile, VaultId, purpose};
use qv_encoding::{Decoder, Encoder, encode_array};
use qv_model::{Clock, ObjectId, RandomId, RecordVersion, VersionId};
use zeroize::Zeroizing;

use crate::error::StoreError;
use crate::limits::MAX_RECORD_CIPHERTEXT;

/// The record AAD label (0004 §3.2).
pub(crate) const RECORD_AAD_LABEL: &str = "qv/record/v1";

/// Bytes an envelope adds around its ciphertext, at most: the array head,
/// a 16-byte ID, a `u32` generation, a `u16` profile, a 24-byte nonce (its
/// length needs a two-byte CBOR head) and the ciphertext's byte-string head.
pub(crate) const ENVELOPE_OVERHEAD: usize = 1 + 17 + 5 + 3 + 26 + 9;

/// The portable form of an encrypted object (0004 §2.2).
pub struct ObjectEnvelope {
    /// The random object ID.
    pub object_id: ObjectId,
    /// The key generation it was encrypted under.
    pub key_generation: KeyGeneration,
    /// Its stored-data profile.
    pub data_profile: StoredDataProfile,
    /// The XChaCha20 nonce.
    pub nonce: [u8; 24],
    /// The ciphertext, tag included.
    pub ciphertext: Vec<u8>,
}

impl core::fmt::Debug for ObjectEnvelope {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ObjectEnvelope(..)")
    }
}

fn malformed<E>(_: E) -> StoreError {
    StoreError::Integrity
}

impl ObjectEnvelope {
    /// The canonical encoding.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut e = Encoder::new();
        e.array(|a| {
            a.bytes(&self.object_id.to_bytes());
            a.uint(u64::from(self.key_generation.0));
            a.uint(u64::from(self.data_profile.id()));
            a.bytes(&self.nonce);
            a.bytes(&self.ciphertext);
            Ok(())
        })
        .map_err(|_| StoreError::Internal)?;
        Ok(e.finish().map_err(|_| StoreError::Internal)?.to_vec())
    }

    /// Decodes an envelope whose ciphertext must be at most
    /// `max_ciphertext` bytes. Oversized input is
    /// [`StoreError::LimitExceeded`] before anything is parsed or copied.
    pub fn decode(bytes: &[u8], max_ciphertext: usize) -> Result<Self, StoreError> {
        if bytes.len() > max_ciphertext.saturating_add(ENVELOPE_OVERHEAD) {
            return Err(StoreError::LimitExceeded);
        }
        let mut d = Decoder::new(bytes).map_err(malformed)?;
        if d.array().map_err(malformed)? != 5 {
            return Err(StoreError::Integrity);
        }
        let id: [u8; 16] = d
            .bytes()
            .map_err(malformed)?
            .try_into()
            .map_err(malformed)?;
        let object_id = ObjectId::from_bytes(id)?;
        let generation = u32::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
        if generation == 0 {
            return Err(StoreError::Integrity);
        }
        let profile = u16::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
        let data_profile = StoredDataProfile::from_id(profile)?;
        let nonce: [u8; 24] = d
            .bytes()
            .map_err(malformed)?
            .try_into()
            .map_err(malformed)?;
        let ciphertext = d.bytes().map_err(malformed)?;
        if ciphertext.len() > max_ciphertext {
            return Err(StoreError::LimitExceeded);
        }
        let ciphertext = ciphertext.to_vec();
        d.finish().map_err(malformed)?;
        Ok(Self {
            object_id,
            key_generation: KeyGeneration(generation),
            data_profile,
            nonce,
            ciphertext,
        })
    }
}

/// Which vault and generation an object belongs to.
#[derive(Clone, Copy)]
pub(crate) struct Scope {
    pub(crate) vault_id: VaultId,
    pub(crate) key_generation: KeyGeneration,
}

/// `["qv/record/v1", vault_id, key_generation, record_id, version_id,
/// object_id, data_profile]`.
pub(crate) fn record_aad(
    scope: Scope,
    record: RecordId,
    version: VersionId,
    object: ObjectId,
    profile: StoredDataProfile,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    encode_array(|a| {
        a.text(RECORD_AAD_LABEL);
        a.bytes(&scope.vault_id.0);
        a.uint(u64::from(scope.key_generation.0));
        a.bytes(&record.0);
        a.bytes(&version.to_bytes());
        a.bytes(&object.to_bytes());
        a.uint(u64::from(profile.id()));
        Ok(())
    })
    .map_err(|_| StoreError::Internal)
}

/// An encrypted object ready for the `object` table.
pub(crate) struct SealedObject {
    pub(crate) object_id: ObjectId,
    pub(crate) data_profile: StoredDataProfile,
    pub(crate) nonce: [u8; 24],
    pub(crate) ciphertext: Vec<u8>,
}

/// Encrypts one record version under a new random object ID.
pub(crate) fn seal_record(
    root: &PurposeKey<purpose::Record>,
    scope: Scope,
    profile: StoredDataProfile,
    record: RecordId,
    version: &RecordVersion,
) -> Result<SealedObject, StoreError> {
    let object_id = ObjectId::generate()?;
    let plaintext = version.encode()?;
    let aad = record_aad(scope, record, version.version_id, object_id, profile)?;
    let key = root.record_key(scope.vault_id, record)?;
    let sealed = qv_crypto::seal(&key, profile, &aad, &plaintext, MAX_RECORD_CIPHERTEXT)?;
    Ok(SealedObject {
        object_id,
        data_profile: profile,
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    })
}

/// The manifest role of a record object.
pub(crate) struct RecordRole<'a> {
    pub(crate) record: RecordId,
    pub(crate) version: VersionId,
    pub(crate) clock: &'a Clock,
    pub(crate) object: ObjectId,
}

/// Decrypts a record object for its manifest role. Any authentication,
/// decoding or role mismatch is [`StoreError::Integrity`] (or the decoder's
/// limit and unsupported-content errors).
pub(crate) fn open_record(
    root: &PurposeKey<purpose::Record>,
    scope: Scope,
    role: &RecordRole<'_>,
    profile: StoredDataProfile,
    nonce: &[u8; 24],
    ciphertext: &[u8],
) -> Result<RecordVersion, StoreError> {
    let aad = record_aad(scope, role.record, role.version, role.object, profile)?;
    let key = root.record_key(scope.vault_id, role.record)?;
    let plaintext = qv_crypto::open(
        &key,
        profile,
        &aad,
        nonce,
        ciphertext,
        MAX_RECORD_CIPHERTEXT,
    )?;
    let version = RecordVersion::decode(plaintext.expose_secret())?;
    if version.version_id != role.version || &version.clock != role.clock {
        return Err(StoreError::Integrity);
    }
    Ok(version)
}

#[cfg(test)]
pub(crate) mod tests {
    use qv_crypto::{DerivationProfile, VaultKey};
    use qv_model::{Group, Payload, RecordBody, Text, Timestamp, WriterId};

    use super::*;

    pub(crate) fn scope() -> Scope {
        Scope {
            vault_id: VaultId(crate::header::tests::v4(0x51)),
            key_generation: KeyGeneration(1),
        }
    }

    pub(crate) fn root(vk: &VaultKey, s: Scope) -> PurposeKey<purpose::Record> {
        vk.purpose_key::<purpose::Record>(s.vault_id, s.key_generation, DerivationProfile::V1)
            .unwrap()
    }

    /// A group version with a name of `name_len` bytes.
    pub(crate) fn group_version(counter: u64, name_len: usize) -> RecordVersion {
        let writer = WriterId::from_bytes(crate::header::tests::v4(0x77)).unwrap();
        RecordVersion {
            version_id: VersionId::generate().unwrap(),
            clock: Clock::from_pairs(vec![(writer, counter)]).unwrap(),
            modified_at: Timestamp(1_700_000_000_000),
            body: RecordBody::Live(Payload::Group(Group {
                parent: None,
                name: Text::new(&"g".repeat(name_len)).unwrap(),
                notes: None,
                icon: None,
                order: Text::new("a").unwrap(),
                deleted_at: None,
                ext: qv_model::Extensions::new(),
            })),
            ext: qv_model::Extensions::new(),
        }
    }

    fn rid(n: u8) -> RecordId {
        RecordId(crate::header::tests::v4(n))
    }

    #[test]
    fn object_record_round_trip_and_binding() {
        let vk = VaultKey::generate().unwrap();
        let s = scope();
        let key = root(&vk, s);
        let v = group_version(1, 4);
        let sealed = seal_record(&key, s, StoredDataProfile::V1, rid(1), &v).unwrap();
        let role = RecordRole {
            record: rid(1),
            version: v.version_id,
            clock: &v.clock,
            object: sealed.object_id,
        };
        let open = |role: &RecordRole<'_>, s: Scope, key: &PurposeKey<purpose::Record>| {
            open_record(
                key,
                s,
                role,
                StoredDataProfile::V1,
                &sealed.nonce,
                &sealed.ciphertext,
            )
        };
        let back = open(&role, s, &key).unwrap();
        assert_eq!(back.version_id, v.version_id);
        assert_eq!(back.encode().unwrap(), v.encode().unwrap());

        // Every AAD component binds.
        let other_record = RecordRole {
            record: rid(2),
            ..role
        };
        assert_eq!(
            open(&other_record, s, &key).err(),
            Some(StoreError::Integrity)
        );
        let other_version = RecordRole {
            version: VersionId::generate().unwrap(),
            ..role
        };
        assert_eq!(
            open(&other_version, s, &key).err(),
            Some(StoreError::Integrity)
        );
        let other_object = RecordRole {
            object: ObjectId::generate().unwrap(),
            ..role
        };
        assert_eq!(
            open(&other_object, s, &key).err(),
            Some(StoreError::Integrity)
        );
        let other_gen = Scope {
            key_generation: KeyGeneration(2),
            ..s
        };
        assert_eq!(
            open(&role, other_gen, &key).err(),
            Some(StoreError::Integrity)
        );
        let other_vault = Scope {
            vault_id: VaultId(crate::header::tests::v4(0x52)),
            ..s
        };
        assert_eq!(
            open(&role, other_vault, &key).err(),
            Some(StoreError::Integrity)
        );
        // The profile is in the AAD: a sealed object whose AAD named
        // another profile fails (built by hand, as only V1 exists).
        let aad = record_aad(
            s,
            rid(1),
            v.version_id,
            sealed.object_id,
            StoredDataProfile::V1,
        )
        .unwrap();
        let mut aad2 = aad.to_vec();
        *aad2.last_mut().unwrap() = 0x02;
        let k = key.record_key(s.vault_id, rid(1)).unwrap();
        let plain = v.encode().unwrap();
        let wrong = qv_crypto::seal(&k, StoredDataProfile::V1, &aad2, &plain, 1 << 20).unwrap();
        assert_eq!(
            open_record(
                &key,
                s,
                &role,
                StoredDataProfile::V1,
                &wrong.nonce,
                &wrong.ciphertext
            )
            .err(),
            Some(StoreError::Integrity)
        );
        // Another VK.
        let vk2 = VaultKey::generate().unwrap();
        assert_eq!(
            open(&role, s, &root(&vk2, s)).err(),
            Some(StoreError::Integrity)
        );
    }

    #[test]
    fn object_role_must_match_decrypted_version() {
        let vk = VaultKey::generate().unwrap();
        let s = scope();
        let key = root(&vk, s);
        let v = group_version(3, 4);
        let sealed = seal_record(&key, s, StoredDataProfile::V1, rid(1), &v).unwrap();
        // A role naming the right version ID but another clock: the AAD
        // still verifies (clocks are not in it), the comparison does not.
        let other_clock = group_version(4, 4).clock;
        let role = RecordRole {
            record: rid(1),
            version: v.version_id,
            clock: &other_clock,
            object: sealed.object_id,
        };
        assert_eq!(
            open_record(
                &key,
                s,
                &role,
                StoredDataProfile::V1,
                &sealed.nonce,
                &sealed.ciphertext
            )
            .err(),
            Some(StoreError::Integrity)
        );
        // A version whose plaintext names another version ID than the AAD
        // (only an author holding VK could build one).
        let mut w = group_version(3, 4);
        w.version_id = VersionId::generate().unwrap();
        let object = ObjectId::generate().unwrap();
        let aad = record_aad(s, rid(1), v.version_id, object, StoredDataProfile::V1).unwrap();
        let k = key.record_key(s.vault_id, rid(1)).unwrap();
        let c = qv_crypto::seal(
            &k,
            StoredDataProfile::V1,
            &aad,
            &w.encode().unwrap(),
            1 << 20,
        )
        .unwrap();
        let role = RecordRole {
            record: rid(1),
            version: v.version_id,
            clock: &w.clock,
            object,
        };
        assert_eq!(
            open_record(
                &key,
                s,
                &role,
                StoredDataProfile::V1,
                &c.nonce,
                &c.ciphertext
            )
            .err(),
            Some(StoreError::Integrity)
        );
    }

    /// An entry version whose fields hold `total` bytes of text in all.
    fn entry_version(total: usize) -> RecordVersion {
        use qv_model::{Entry, Field, FieldId, FieldKind, FieldValue};
        let mut fields = Vec::new();
        let mut left = total;
        while left > 0 {
            let n = left.min(qv_model::MAX_TEXT_BYTES);
            fields.push(Field {
                id: FieldId::generate().unwrap(),
                name: Text::new("f").unwrap(),
                kind: FieldKind::Text,
                value: FieldValue::text(&"x".repeat(n)).unwrap(),
                protected: false,
                ext: qv_model::Extensions::new(),
            });
            left -= n;
        }
        let mut v = group_version(1, 1);
        v.body = RecordBody::Live(Payload::Entry(Entry {
            group: rid(9),
            type_hint: Text::new("login").unwrap(),
            title: Text::new("t").unwrap(),
            fields,
            notes: None,
            icon: None,
            expires_at: None,
            created_at: Timestamp(1),
            modified_at: Timestamp(1),
            deleted_at: None,
            ext: qv_model::Extensions::new(),
        }));
        v
    }

    #[test]
    fn object_record_budget_boundary() {
        let vk = VaultKey::generate().unwrap();
        let s = scope();
        let key = root(&vk, s);
        // Largest plaintext under the 1 MiB padded budget (plan 0005):
        // 1 MiB - 16 KiB - 4 bytes. Padmé rounds to 16 KiB steps here, so
        // its ciphertext is 1 MiB - 16 KiB plus the 16-byte tag, and the
        // next step would be over 1 MiB.
        let max_plain = MAX_RECORD_CIPHERTEXT - 16 * 1024 - 4;
        let max_sealed = MAX_RECORD_CIPHERTEXT - 16 * 1024 + 16;
        assert_eq!(qv_crypto::sealed_len(max_plain), Some(max_sealed));
        assert!(qv_crypto::sealed_len(max_plain + 1).unwrap() > MAX_RECORD_CIPHERTEXT);
        // Grow the text until the version encodes to exactly `max_plain`.
        let mut text = max_plain - 1000;
        let v = loop {
            let v = entry_version(text);
            let len = v.encode().unwrap().len();
            if len == max_plain {
                break v;
            }
            text = text + max_plain - len;
        };
        let sealed = seal_record(&key, s, StoredDataProfile::V1, rid(1), &v).unwrap();
        assert_eq!(sealed.ciphertext.len(), max_sealed);
        let role = RecordRole {
            record: rid(1),
            version: v.version_id,
            clock: &v.clock,
            object: sealed.object_id,
        };
        assert!(
            open_record(
                &key,
                s,
                &role,
                StoredDataProfile::V1,
                &sealed.nonce,
                &sealed.ciphertext
            )
            .is_ok()
        );
        // One byte more no longer fits.
        let w = entry_version(text + 1);
        assert_eq!(w.encode().unwrap().len(), max_plain + 1);
        assert_eq!(
            seal_record(&key, s, StoredDataProfile::V1, rid(1), &w).err(),
            Some(StoreError::LimitExceeded)
        );
    }

    fn envelope() -> ObjectEnvelope {
        ObjectEnvelope {
            object_id: ObjectId::from_bytes(crate::header::tests::v4(3)).unwrap(),
            key_generation: KeyGeneration(1),
            data_profile: StoredDataProfile::V1,
            nonce: [9; 24],
            ciphertext: vec![0xab; 40],
        }
    }

    #[test]
    fn object_envelope_golden_and_round_trip() {
        let e = envelope();
        let bytes = e.encode().unwrap();
        let mut expected = vec![0x85, 0x50];
        expected.extend_from_slice(&crate::header::tests::v4(3));
        expected.extend_from_slice(&[0x01, 0x01, 0x58, 0x18]);
        expected.extend_from_slice(&[9; 24]);
        expected.extend_from_slice(&[0x58, 0x28]);
        expected.extend_from_slice(&[0xab; 40]);
        assert_eq!(bytes, expected);
        let back = ObjectEnvelope::decode(&bytes, 40).unwrap();
        assert_eq!(back.encode().unwrap(), bytes);
        assert_eq!(format!("{back:?}"), "ObjectEnvelope(..)");
    }

    #[test]
    fn object_envelope_rejections() {
        let good = envelope().encode().unwrap();
        // Over the caller's bound: the ciphertext, and the whole input.
        assert_eq!(
            ObjectEnvelope::decode(&good, 39).err(),
            Some(StoreError::LimitExceeded)
        );
        assert_eq!(
            ObjectEnvelope::decode(&vec![0u8; 1000], 10).err(),
            Some(StoreError::LimitExceeded)
        );
        let build = |f: &dyn Fn(&mut qv_encoding::Encoder)| {
            let mut e = Encoder::new();
            f(&mut e);
            e.finish().unwrap().to_vec()
        };
        let fields = |a: &mut Encoder, id: &[u8], generation: u64, profile: u64, nonce: &[u8]| {
            a.bytes(id);
            a.uint(generation);
            a.uint(profile);
            a.bytes(nonce);
        };
        let id = crate::header::tests::v4(3);
        let four = build(&|e| {
            e.array(|a| {
                fields(a, &id, 1, 1, &[9; 24]);
                Ok(())
            })
            .unwrap()
        });
        assert_eq!(
            ObjectEnvelope::decode(&four, 40).err(),
            Some(StoreError::Integrity)
        );
        let six = build(&|e| {
            e.array(|a| {
                fields(a, &id, 1, 1, &[9; 24]);
                a.bytes(&[1]);
                a.bytes(&[2]);
                Ok(())
            })
            .unwrap()
        });
        assert_eq!(
            ObjectEnvelope::decode(&six, 40).err(),
            Some(StoreError::Integrity)
        );
        let with = |id: &[u8], generation: u64, profile: u64, nonce: &[u8]| {
            build(&|e| {
                e.array(|a| {
                    fields(a, id, generation, profile, nonce);
                    a.bytes(&[0xab; 40]);
                    Ok(())
                })
                .unwrap()
            })
        };
        let cases = [
            (with(&id[..15], 1, 1, &[9; 24]), StoreError::Integrity),
            (with(&[0; 16], 1, 1, &[9; 24]), StoreError::Integrity),
            (with(&id, 0, 1, &[9; 24]), StoreError::Integrity),
            (with(&id, 1 << 32, 1, &[9; 24]), StoreError::Integrity),
            (with(&id, 1, 2, &[9; 24]), StoreError::Unsupported),
            (with(&id, 1, 1, &[9; 23]), StoreError::Integrity),
        ];
        for (bytes, expect) in cases {
            assert_eq!(ObjectEnvelope::decode(&bytes, 40).err(), Some(expect));
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            ObjectEnvelope::decode(&trailing, 40).err(),
            Some(StoreError::Integrity)
        );
    }
}
