// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded offline rotation intent (0002 §3.5; plan 0021).
//!
//! Decoding establishes syntax only. A journal never authorizes filesystem
//! operations, anchor adoption, or a generation transition by itself. Recovery
//! must independently authenticate the retained databases, compare their heads
//! with this intent and the external anchor, and obtain the necessary credentials.
//! In particular, possession of the old VK must not authorize release of new VK.
//!
//! Development wire format: canonical CBOR map keys 0..=14, as enumerated by
//! [`RotationJournalBody`]. MACs occupy keys 13 and 14. Each generation MACs
//! `["qv/rotation-journal/v1", body]`, where body is the map of keys 0..=12,
//! using its own existing local-state purpose key and MAC/1. No keys, password
//! slots, phrases, paths or plaintext record content belong in this container.

use qv_crypto::{DerivationProfile, KeyGeneration, MacProfile, MacTag, VaultId, VaultKey, purpose};
use qv_encoding::{Decoder, Encoder, encode_array};
use qv_model::RandomId;
use zeroize::Zeroizing;

use crate::StoreError;

/// Input cap, checked before decoding or copying any field.
pub const MAX_ROTATION_JOURNAL_BYTES: usize = 4096;
const FORMAT: u64 = 1;
const LABEL: &str = "qv/rotation-journal/v1";

/// Which independently authenticated generation a caller is checking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationSide {
    /// The source generation, before installation.
    Old,
    /// The independently unlocked replacement generation.
    New,
}

/// Non-secret transition metadata. This is untrusted after decoding, even if
/// its old-generation MAC verifies. No field is a filesystem path.
#[derive(PartialEq, Eq)]
pub struct RotationJournalBody {
    /// Key 1: random UUIDv4 identifying this operation.
    pub operation_id: [u8; 16],
    /// Key 2: the common vault UUIDv4.
    pub vault_id: VaultId,
    /// Key 3: the retained replica/anchor identifier (opaque bytes).
    pub replica_id: [u8; 16],
    /// Keys 4/5: checked positive generation transition.
    pub old_generation: KeyGeneration,
    /// Exactly old_generation + 1.
    pub new_generation: KeyGeneration,
    /// Keys 6/7: the one-step local-head sequence transition.
    pub old_sequence: u64,
    /// Exactly old_sequence + 1.
    pub new_sequence: u64,
    /// Key 8: authenticated source local-head digest.
    pub old_digest: [u8; 32],
    /// Key 9: independently authenticated replacement local-head digest.
    pub new_digest: [u8; 32],
    /// Key 10: random sibling filename suffix, rendered as 32 hex digits.
    pub suffix: [u8; 16],
    /// Key 11: the pinned mandatory recovery snapshot identifier.
    pub snapshot_id: [u8; 16],
    /// Key 12: digest of the prepared cross-generation snapshot inventory.
    pub inventory_digest: [u8; 32],
}

impl RotationJournalBody {
    fn validate(&self) -> Result<(), StoreError> {
        qv_model::VersionId::from_bytes(self.operation_id).map_err(|_| StoreError::Integrity)?;
        VaultId::from_bytes(self.vault_id.0).map_err(|_| StoreError::Integrity)?;
        if self.old_generation.0 == 0
            || self.old_generation.0.checked_add(1) != Some(self.new_generation.0)
            || self.old_sequence == 0
            || self.old_sequence.checked_add(1) != Some(self.new_sequence)
            || self.old_digest == self.new_digest
        {
            return Err(StoreError::Integrity);
        }
        Ok(())
    }
}

/// An intent with two independent MACs. Contains no key or plaintext payload.
/// It has no publication, deletion, installation or anchor-adoption methods.
pub struct RotationJournal {
    body: RotationJournalBody,
    old_mac: MacTag,
    new_mac: MacTag,
}

macro_rules! redacted {
    ($($t:ty),+) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )+};
}
redacted!(RotationJournal, RotationJournalBody);

fn bad<E>(_: E) -> StoreError {
    StoreError::Integrity
}
fn bytes<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N], StoreError> {
    d.bytes().map_err(bad)?.try_into().map_err(bad)
}
fn required<T>(v: Option<T>) -> Result<T, StoreError> {
    v.ok_or(StoreError::Integrity)
}

impl RotationJournal {
    /// Validates and authenticates a prepared intent with both generation keys.
    /// This is a codec operation, not confirmation that either key matches a
    /// persisted vault or that a user confirmed the new recovery phrase.
    pub fn sign(
        body: RotationJournalBody,
        old_vk: &VaultKey,
        new_vk: &VaultKey,
    ) -> Result<Self, StoreError> {
        body.validate()?;
        let mut journal = Self {
            body,
            old_mac: MacTag::from_bytes([0; 32]),
            new_mac: MacTag::from_bytes([0; 32]),
        };
        let transcript = journal.transcript()?;
        journal.old_mac = journal.tag(old_vk, RotationSide::Old, &transcript)?;
        journal.new_mac = journal.tag(new_vk, RotationSide::New, &transcript)?;
        Ok(journal)
    }

    /// Untrusted metadata; verification alone still does not authorize I/O.
    pub fn body(&self) -> &RotationJournalBody {
        &self.body
    }

    fn tag(
        &self,
        vk: &VaultKey,
        side: RotationSide,
        transcript: &[u8],
    ) -> Result<MacTag, StoreError> {
        let key = self.key(vk, side)?;
        Ok(qv_crypto::mac(&key, MacProfile::V1, transcript)?)
    }

    fn key(
        &self,
        vk: &VaultKey,
        side: RotationSide,
    ) -> Result<qv_crypto::PurposeKey<purpose::LocalState>, StoreError> {
        let generation = match side {
            RotationSide::Old => self.body.old_generation,
            RotationSide::New => self.body.new_generation,
        };
        Ok(vk.purpose_key::<purpose::LocalState>(
            self.body.vault_id,
            generation,
            DerivationProfile::V1,
        )?)
    }

    /// Checks just the selected generation's MAC in constant time. Callers
    /// must verify both sides independently before an unconfirmed transition;
    /// an old-key-only verification says nothing about the replacement key.
    pub fn verify(&self, vk: &VaultKey, side: RotationSide) -> Result<(), StoreError> {
        self.body.validate()?;
        let tag = match side {
            RotationSide::Old => &self.old_mac,
            RotationSide::New => &self.new_mac,
        };
        let key = self.key(vk, side)?;
        qv_crypto::verify_mac(&key, MacProfile::V1, &self.transcript()?, tag).map_err(bad)
    }

    fn transcript(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let body = self.encode_map(false)?;
        encode_array(|e| {
            e.text(LABEL);
            e.bytes(&body);
            Ok(())
        })
        .map_err(|_| StoreError::Internal)
    }

    fn encode_map(&self, tags: bool) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.body.validate()?;
        let b = &self.body;
        let mut e = Encoder::new();
        e.map(|m| {
            for key in 0..=if tags { 14 } else { 12 } {
                m.entry(key, |e| {
                    match key {
                        0 => e.uint(FORMAT),
                        1 => e.bytes(&b.operation_id),
                        2 => e.bytes(&b.vault_id.0),
                        3 => e.bytes(&b.replica_id),
                        4 => e.uint(u64::from(b.old_generation.0)),
                        5 => e.uint(u64::from(b.new_generation.0)),
                        6 => e.uint(b.old_sequence),
                        7 => e.uint(b.new_sequence),
                        8 => e.bytes(&b.old_digest),
                        9 => e.bytes(&b.new_digest),
                        10 => e.bytes(&b.suffix),
                        11 => e.bytes(&b.snapshot_id),
                        12 => e.bytes(&b.inventory_digest),
                        13 => e.bytes(self.old_mac.as_bytes()),
                        14 => e.bytes(self.new_mac.as_bytes()),
                        _ => return Err(qv_encoding::EncodeError::ItemCount),
                    }
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|_| StoreError::Internal)?;
        e.finish().map_err(|_| StoreError::Internal)
    }

    /// Canonical wire bytes, with both MACs. No secret fields are serialized.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        Ok(self.encode_map(true)?.to_vec())
    }

    /// Checks size and strict canonical structure. No filesystem operation or
    /// trust decision is permitted from this result until independent checks.
    pub fn decode(input: &[u8]) -> Result<Self, StoreError> {
        if input.len() > MAX_ROTATION_JOURNAL_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        let mut d = Decoder::new(input).map_err(bad)?;
        let count = d.map().map_err(bad)?;
        if count > 15 {
            return Err(StoreError::Unsupported);
        }
        let (mut format, mut operation, mut vault, mut replica) = (None, None, None, None);
        let (mut old_generation, mut new_generation, mut old_sequence, mut new_sequence) =
            (None, None, None, None);
        let (mut old_digest, mut new_digest, mut suffix, mut snapshot, mut inventory) =
            (None, None, None, None, None);
        let (mut old_mac, mut new_mac) = (None, None);
        for _ in 0..count {
            match d.int().map_err(bad)? {
                0 => format = Some(d.uint().map_err(bad)?),
                1 => operation = Some(bytes(&mut d)?),
                2 => vault = Some(VaultId(bytes(&mut d)?)),
                3 => replica = Some(bytes(&mut d)?),
                4 => old_generation = Some(u32::try_from(d.uint().map_err(bad)?).map_err(bad)?),
                5 => new_generation = Some(u32::try_from(d.uint().map_err(bad)?).map_err(bad)?),
                6 => old_sequence = Some(d.uint().map_err(bad)?),
                7 => new_sequence = Some(d.uint().map_err(bad)?),
                8 => old_digest = Some(bytes(&mut d)?),
                9 => new_digest = Some(bytes(&mut d)?),
                10 => suffix = Some(bytes(&mut d)?),
                11 => snapshot = Some(bytes(&mut d)?),
                12 => inventory = Some(bytes(&mut d)?),
                13 => old_mac = Some(MacTag::from_bytes(bytes(&mut d)?)),
                14 => new_mac = Some(MacTag::from_bytes(bytes(&mut d)?)),
                _ => return Err(StoreError::Unsupported),
            }
        }
        d.finish().map_err(bad)?;
        if required(format)? != FORMAT {
            return Err(StoreError::Unsupported);
        }
        let journal = Self {
            body: RotationJournalBody {
                operation_id: required(operation)?,
                vault_id: required(vault)?,
                replica_id: required(replica)?,
                old_generation: KeyGeneration(required(old_generation)?),
                new_generation: KeyGeneration(required(new_generation)?),
                old_sequence: required(old_sequence)?,
                new_sequence: required(new_sequence)?,
                old_digest: required(old_digest)?,
                new_digest: required(new_digest)?,
                suffix: required(suffix)?,
                snapshot_id: required(snapshot)?,
                inventory_digest: required(inventory)?,
            },
            old_mac: required(old_mac)?,
            new_mac: required(new_mac)?,
        };
        journal.body.validate()?;
        Ok(journal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> [u8; 16] {
        let mut v = [b; 16];
        v[6] = (v[6] & 15) | 64;
        v[8] = (v[8] & 63) | 128;
        v
    }
    fn body() -> RotationJournalBody {
        RotationJournalBody {
            operation_id: id(0x11),
            vault_id: VaultId(id(0x22)),
            replica_id: [0x33; 16],
            old_generation: KeyGeneration(1),
            new_generation: KeyGeneration(2),
            old_sequence: 7,
            new_sequence: 8,
            old_digest: [0x66; 32],
            new_digest: [0x77; 32],
            suffix: [0x44; 16],
            snapshot_id: [0x55; 16],
            inventory_digest: [0x88; 32],
        }
    }
    fn keys() -> (VaultKey, VaultKey) {
        // Public BIP-39 encoding vectors: all-zero and all-one entropy.
        let zero = format!("{}art", "abandon ".repeat(23));
        let ones = format!("{}vote", "zoo ".repeat(23));
        (
            VaultKey::from_recovery_phrase(zero.as_bytes()).unwrap(),
            VaultKey::from_recovery_phrase(ones.as_bytes()).unwrap(),
        )
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn err(input: &[u8]) -> StoreError {
        RotationJournal::decode(input).err().unwrap()
    }
    fn fields(j: &RotationJournal) -> Vec<(u8, Vec<u8>)> {
        let input = j.encode().unwrap();
        let mut d = Decoder::new(&input).unwrap();
        let n = d.map().unwrap();
        (0..n)
            .map(|_| {
                let key = u8::try_from(d.uint().unwrap()).unwrap();
                (key, d.raw_value().unwrap().as_bytes().to_vec())
            })
            .collect()
    }
    fn reencode(fields: &[(u8, Vec<u8>)]) -> Vec<u8> {
        // Each field is already a bounded canonical CBOR value. Small positive
        // keys and a short map head suffice for this hostile-input fixture.
        let mut out = vec![0xa0 | u8::try_from(fields.len()).unwrap()];
        for (k, v) in fields {
            out.push(*k);
            out.extend_from_slice(v);
        }
        out
    }

    #[test]
    fn rotation_journal_independent_transcript_vector_and_round_trip() {
        let (old, new) = keys();
        let j = RotationJournal::sign(body(), &old, &new).unwrap();
        // Independently computed using Python stdlib HMAC/HKDF and a separate
        // CBOR encoder; reproduction script/evidence in plan 0021's log.
        assert_eq!(
            hex(j.old_mac.as_bytes()),
            "6e719a530472cdf5864ec9823c5502740631b380c227647ec548a42e2f3f417c"
        );
        assert_eq!(
            hex(j.new_mac.as_bytes()),
            "6f51b5b34fb68e777ab80b5511036fb389526d598e3c93bc6dcb7b30669cee4a"
        );
        let encoded = j.encode().unwrap();
        assert_eq!(
            encoded.as_slice(),
            include_bytes!("../tests/vectors/rotation-journal.cbor")
        );
        assert!(encoded.len() < MAX_ROTATION_JOURNAL_BYTES);
        let decoded = RotationJournal::decode(&encoded).unwrap();
        assert_eq!(decoded.body(), j.body());
        assert_eq!(decoded.encode().unwrap(), encoded);
        for (key, side) in [(&old, RotationSide::Old), (&new, RotationSide::New)] {
            assert_eq!(decoded.verify(key, side), Ok(()));
        }
        assert_eq!(
            decoded.verify(&old, RotationSide::New),
            Err(StoreError::Integrity)
        );
        assert_eq!(
            decoded.verify(&new, RotationSide::Old),
            Err(StoreError::Integrity)
        );
        let foreign = VaultKey::generate().unwrap();
        for side in [RotationSide::Old, RotationSide::New] {
            assert_eq!(decoded.verify(&foreign, side), Err(StoreError::Integrity));
        }
        assert_eq!(format!("{j:?}"), "RotationJournal(<redacted>)");
        assert_eq!(format!("{:?}", j.body()), "RotationJournalBody(<redacted>)");
    }

    #[test]
    fn rotation_journal_every_byte_is_structural_or_authenticated() {
        let (old, new) = keys();
        let j = RotationJournal::sign(body(), &old, &new).unwrap();
        let input = j.encode().unwrap();
        for i in 0..input.len() {
            let mut changed = input.clone();
            changed[i] ^= 1;
            if let Ok(candidate) = RotationJournal::decode(&changed) {
                assert!(
                    candidate.verify(&old, RotationSide::Old).is_err()
                        || candidate.verify(&new, RotationSide::New).is_err(),
                    "byte {i}"
                );
            }
        }
        for key in [13, 14] {
            let mut f = fields(&j);
            let last = f[key].1.len() - 1;
            f[key].1[last] ^= 1;
            let changed = RotationJournal::decode(&reencode(&f)).unwrap();
            assert_eq!(changed.verify(&old, RotationSide::Old).is_ok(), key != 13);
            assert_eq!(changed.verify(&new, RotationSide::New).is_ok(), key != 14);
        }
    }

    // 0012 §1: Hostile SQLite/CBOR
    #[test]
    fn rotation_journal_rejects_bad_shape_versions_and_unbounded_lengths() {
        let (old, new) = keys();
        let j = RotationJournal::sign(body(), &old, &new).unwrap();
        let input = j.encode().unwrap();
        for end in 0..input.len() {
            assert!(RotationJournal::decode(&input[..end]).is_err());
        }
        assert_eq!(
            err(&vec![0; MAX_ROTATION_JOURNAL_BYTES + 1]),
            StoreError::LimitExceeded
        );
        assert_eq!(
            err(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            StoreError::Integrity
        );
        let mut trailing = input.clone();
        trailing.push(0);
        assert_eq!(err(&trailing), StoreError::Integrity);
        let original = fields(&j);
        for key in 0..15 {
            let mut f = original.clone();
            f.remove(key);
            assert_eq!(err(&reencode(&f)), StoreError::Integrity, "missing {key}");
            let mut f = original.clone();
            f[key].1 = vec![0xf6];
            assert_eq!(err(&reencode(&f)), StoreError::Integrity, "null {key}");
        }
        for (key, value, error) in [
            (0, vec![2], StoreError::Unsupported),
            (4, vec![0], StoreError::Integrity),
            (5, vec![3], StoreError::Integrity),
            (6, vec![0], StoreError::Integrity),
            (7, vec![9], StoreError::Integrity),
            (4, vec![0x1b, 0, 0, 0, 1, 0, 0, 0, 0], StoreError::Integrity),
            (0, vec![0x18, 1], StoreError::Integrity),
        ] {
            let mut f = original.clone();
            f[key].1 = value;
            assert_eq!(err(&reencode(&f)), error);
        }
        // Wrong fixed-length byte strings, malformed UUIDs and equal heads.
        for key in [1, 2, 3, 8, 9, 10, 11, 12, 13, 14] {
            let mut f = original.clone();
            f[key].1 = vec![0x41, 0];
            assert_eq!(err(&reencode(&f)), StoreError::Integrity);
        }
        for key in [1, 2] {
            let mut f = original.clone();
            f[key].1[7] = 0;
            assert_eq!(err(&reencode(&f)), StoreError::Integrity);
        }
        let mut f = original.clone();
        f[9].1 = f[8].1.clone();
        assert_eq!(err(&reencode(&f)), StoreError::Integrity);
        let mut f = original.clone();
        f[14].0 = 15;
        assert_eq!(err(&reencode(&f)), StoreError::Unsupported);
        let mut f = original.clone();
        f[14].0 = 13;
        assert_eq!(err(&reencode(&f)), StoreError::Integrity);
        let mut f = original;
        f.swap(12, 13);
        assert_eq!(err(&reencode(&f)), StoreError::Integrity);
    }

    #[test]
    fn rotation_journal_sign_refuses_impossible_transitions() {
        let (old, new) = keys();
        for kind in 0..6 {
            let mut b = body();
            match kind {
                0 => {
                    b.old_generation = KeyGeneration(u32::MAX);
                    b.new_generation = KeyGeneration(0);
                }
                1 => {
                    b.old_sequence = u64::MAX;
                    b.new_sequence = 0;
                }
                2 => b.new_generation = b.old_generation,
                3 => b.new_sequence = b.old_sequence,
                4 => b.operation_id = [0; 16],
                _ => b.vault_id = VaultId([0; 16]),
            }
            assert_eq!(
                RotationJournal::sign(b, &old, &new).err(),
                Some(StoreError::Integrity)
            );
        }
    }
}
