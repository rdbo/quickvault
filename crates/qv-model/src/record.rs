// SPDX-License-Identifier: AGPL-3.0-or-later

//! Record versions (spec 0003 §2, 0004 §3.2).
//!
//! The plaintext of one version of one record:
//!
//! | Key | Field | CBOR | |
//! |-----|-------|------|---|
//! | 0 | kind | uint: 0 vault_meta, 1 group, 2 entry, 3 attachment_meta, 4 password_keyslot | required |
//! | 1 | version_id | bstr 16 (UUIDv4) | required |
//! | 2 | clock | array of `[writer_id, counter]` pairs (0005 §1.1), nonempty | required |
//! | 3 | modified_at | int (ms since the Unix epoch) | required |
//! | 4 | deleted | bool: a final tombstone | required |
//! | 5 | payload | map of the kind's payload | present iff `deleted` is false |
//!
//! The record ID is not part of the plaintext: it comes from the manifest
//! role, and the encryption AAD binds it (0004 §3.2). An unknown kind fails
//! closed ([`ModelError::Unsupported`]). Vault metadata and keyslot records
//! cannot be deleted ([`ModelError::InvalidTransition`], 0003 §2.3).

use qv_encoding::Decoder;
use zeroize::Zeroizing;

use crate::clock::{Clock, decode_clock, encode_clock};
use crate::codec::{
    encode_item, keep, put_bool, put_ext, put_id, put_time, put_uint, read_id, read_map_len,
    read_time, req,
};
use crate::error::ModelError;
use crate::ids::VersionId;
use crate::payload::Payload;
use crate::text::{Extensions, MAX_RECORD_BYTES};
use crate::time::Timestamp;

/// What a record is (0003 §2.1). Immutable for a record ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordKind {
    /// Vault metadata (one per vault).
    VaultMeta,
    /// A group.
    Group,
    /// An entry.
    Entry,
    /// Attachment metadata.
    AttachmentMeta,
    /// The password keyslot record.
    PasswordKeyslot,
}

impl RecordKind {
    pub(crate) fn code(self) -> u64 {
        match self {
            Self::VaultMeta => 0,
            Self::Group => 1,
            Self::Entry => 2,
            Self::AttachmentMeta => 3,
            Self::PasswordKeyslot => 4,
        }
    }

    pub(crate) fn from_code(code: u64) -> Result<Self, ModelError> {
        Ok(match code {
            0 => Self::VaultMeta,
            1 => Self::Group,
            2 => Self::Entry,
            3 => Self::AttachmentMeta,
            4 => Self::PasswordKeyslot,
            _ => return Err(ModelError::Unsupported),
        })
    }

    /// Whether records of this kind can never be deleted (0003 §2.3).
    fn undeletable(self) -> bool {
        matches!(self, Self::VaultMeta | Self::PasswordKeyslot)
    }
}

/// A version's deletion state (0005 §2.5, 0007 §2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deletion {
    /// Not deleted.
    Live,
    /// In trash: the payload's `deleted_at` is set.
    SoftDeleted,
    /// A final tombstone.
    Final,
}

/// A version's content.
// Tombstones are the rare case and versions are held one at a time while
// decoding or editing, so boxing the payload would add an allocation per
// live version without saving memory.
#[allow(clippy::large_enum_variant)]
pub enum RecordBody {
    /// A live (or soft-deleted) payload.
    Live(Payload),
    /// A final tombstone: the kind, and no payload.
    Tombstone(RecordKind),
}

/// One immutable version of a record.
pub struct RecordVersion {
    /// The version's random ID.
    pub version_id: VersionId,
    /// Its version vector; never empty.
    pub clock: Clock,
    /// When it was written (display only, 0005 §1.5).
    pub modified_at: Timestamp,
    /// The payload or tombstone.
    pub body: RecordBody,
    /// Unknown keys.
    pub ext: Extensions,
}

crate::redacted_debug!(RecordBody, RecordVersion);

impl RecordVersion {
    /// The record kind.
    pub fn kind(&self) -> RecordKind {
        match &self.body {
            RecordBody::Live(p) => p.kind(),
            RecordBody::Tombstone(k) => *k,
        }
    }

    /// The deletion state.
    pub fn deletion(&self) -> Deletion {
        match &self.body {
            RecordBody::Tombstone(_) => Deletion::Final,
            RecordBody::Live(p) if p.soft_deleted() => Deletion::SoftDeleted,
            RecordBody::Live(_) => Deletion::Live,
        }
    }

    /// Checks that this version may be the vault's root group (0003 §2.3,
    /// §4.1): a live group with no parent and no `deleted_at`. Anything else
    /// is [`ModelError::InvalidTransition`].
    pub fn check_root(&self) -> Result<(), ModelError> {
        match &self.body {
            RecordBody::Live(Payload::Group(g)) if g.parent.is_none() && g.deleted_at.is_none() => {
                Ok(())
            }
            _ => Err(ModelError::InvalidTransition),
        }
    }

    /// Checks shared by encode and decode.
    fn check(&self) -> Result<(), ModelError> {
        if self.clock.is_empty() {
            return Err(ModelError::Malformed);
        }
        match &self.body {
            RecordBody::Tombstone(k) if k.undeletable() => Err(ModelError::InvalidTransition),
            RecordBody::Tombstone(_) => Ok(()),
            RecordBody::Live(p) => p.check(),
        }
    }

    /// The canonical encoding. Fails with the same errors [`Self::decode`]
    /// would, so the model never writes what it would reject.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, ModelError> {
        self.check()?;
        let out = encode_item(|e| {
            e.map(|m| {
                put_uint(m, 0, self.kind().code())?;
                put_id(m, 1, &self.version_id)?;
                m.entry(2, |v| encode_clock(&self.clock, v))?;
                put_time(m, 3, self.modified_at)?;
                put_bool(m, 4, matches!(self.body, RecordBody::Tombstone(_)))?;
                if let RecordBody::Live(p) = &self.body {
                    m.entry(5, |v| p.encode(v))?;
                }
                put_ext(m, &self.ext)
            })
        })?;
        if out.len() > MAX_RECORD_BYTES {
            return Err(ModelError::LimitExceeded);
        }
        Ok(out)
    }

    /// Decodes and validates a version's plaintext. The length is checked
    /// before anything is parsed.
    pub fn decode(input: &[u8]) -> Result<Self, ModelError> {
        if input.len() > MAX_RECORD_BYTES {
            return Err(ModelError::LimitExceeded);
        }
        let mut d = Decoder::new(input)?;
        let (mut kind, mut version_id, mut clock, mut modified_at, mut deleted, mut payload) =
            (None, None, None, None, None, None);
        let mut ext = Extensions::new();
        for _ in 0..read_map_len(&mut d)? {
            match d.int()? {
                0 => kind = Some(RecordKind::from_code(d.uint()?)?),
                1 => version_id = Some(read_id(&mut d)?),
                2 => clock = Some(decode_clock(&mut d)?),
                3 => modified_at = Some(read_time(&mut d)?),
                4 => deleted = Some(d.bool()?),
                // Key 0 sorts first, so the kind is known here if present.
                5 => payload = Some(Payload::decode(req(kind)?, &mut d)?),
                k => keep(&mut ext, k, &mut d)?,
            }
        }
        d.finish()?;
        let kind = req(kind)?;
        let body = match (req(deleted)?, payload) {
            (false, Some(p)) => RecordBody::Live(p),
            (true, None) => RecordBody::Tombstone(kind),
            _ => return Err(ModelError::Malformed),
        };
        let version = Self {
            version_id: req(version_id)?,
            clock: req(clock)?,
            modified_at: req(modified_at)?,
            body,
            ext,
        };
        version.check()?;
        Ok(version)
    }
}

#[cfg(test)]
pub(crate) mod test_records {
    //! Builders for tests.

    use qv_encoding::{Encoder, RawValue};

    /// A canonical map from `(key, canonical value bytes)` entries.
    pub(crate) fn map(entries: &[(i64, Vec<u8>)]) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(|m| {
            for (k, v) in entries {
                m.raw_entry(*k, &RawValue::from_canonical(v).unwrap())?;
            }
            Ok(())
        })
        .unwrap();
        e.finish().unwrap().to_vec()
    }

    /// The canonical encoding of one item built by `f`.
    pub(crate) fn item(f: impl FnOnce(&mut Encoder)) -> Vec<u8> {
        let mut e = Encoder::new();
        f(&mut e);
        e.finish().unwrap().to_vec()
    }

    pub(crate) fn text(s: &str) -> Vec<u8> {
        item(|e| e.text(s))
    }

    pub(crate) fn bytes(b: &[u8]) -> Vec<u8> {
        item(|e| e.bytes(b))
    }

    pub(crate) fn uint(n: u64) -> Vec<u8> {
        item(|e| e.uint(n))
    }

    pub(crate) fn int(n: i64) -> Vec<u8> {
        item(|e| e.int(n))
    }

    pub(crate) fn boolean(b: bool) -> Vec<u8> {
        item(|e| e.bool(b))
    }

    pub(crate) fn null() -> Vec<u8> {
        item(|e| e.null())
    }

    /// The wire form of a one-writer clock.
    pub(crate) fn clock1(writer: [u8; 16], counter: u64) -> Vec<u8> {
        item(|e| {
            e.array(|a| {
                a.array(|p| {
                    p.bytes(&writer);
                    p.uint(counter);
                    Ok(())
                })
            })
            .unwrap()
        })
    }

    /// An envelope with keys 0–4 (and 5 if `payload` is given).
    pub(crate) fn envelope(
        kind: u64,
        deleted: bool,
        payload: Option<Vec<u8>>,
    ) -> Vec<(i64, Vec<u8>)> {
        use crate::ids::test_ids::v4;
        let mut e = vec![
            (0, uint(kind)),
            (1, bytes(&v4(0xa1))),
            (2, clock1(v4(0xb1), 1)),
            (3, int(1_700_000_000_000)),
            (4, boolean(deleted)),
        ];
        if let Some(p) = payload {
            e.push((5, p));
        }
        e
    }

    /// Removes key `k` from `entries`.
    pub(crate) fn without(entries: &[(i64, Vec<u8>)], k: i64) -> Vec<(i64, Vec<u8>)> {
        entries
            .iter()
            .filter(|(key, _)| *key != k)
            .cloned()
            .collect()
    }

    /// Replaces (or adds) key `k`.
    pub(crate) fn with(entries: &[(i64, Vec<u8>)], k: i64, v: Vec<u8>) -> Vec<(i64, Vec<u8>)> {
        let mut out = without(entries, k);
        out.push((k, v));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::test_records::*;
    use super::*;
    use crate::ids::test_ids::v4;

    fn decode(entries: &[(i64, Vec<u8>)]) -> Result<RecordVersion, ModelError> {
        RecordVersion::decode(&map(entries))
    }

    fn vault_meta_payload() -> Vec<(i64, Vec<u8>)> {
        vec![(0, text("V")), (2, bytes(&v4(0x02))), (3, map(&[]))]
    }

    fn keyslot_payload() -> Vec<(i64, Vec<u8>)> {
        vec![
            (0, bytes(&v4(0x03))),
            (1, uint(1)),
            (2, bytes(&[0x11; 32])),
            (3, uint(1)),
            (4, bytes(&[0x22; 32])),
            (5, bytes(&[0x33; 24])),
            (6, bytes(&[0x44; 48])),
        ]
    }

    /// Decodes, re-encodes and checks the bytes are identical.
    fn round_trip(bytes: &[u8]) -> RecordVersion {
        let v = RecordVersion::decode(bytes).unwrap();
        assert_eq!(v.encode().unwrap().as_slice(), bytes);
        v
    }

    #[test]
    fn record_vault_meta_golden() {
        let bytes = map(&envelope(0, false, Some(map(&vault_meta_payload()))));
        let mut expected = vec![0xa6, 0x00, 0x00, 0x01, 0x50];
        expected.extend_from_slice(&v4(0xa1));
        expected.extend_from_slice(&[0x02, 0x81, 0x82, 0x50]);
        expected.extend_from_slice(&v4(0xb1));
        expected.extend_from_slice(&[0x01, 0x03, 0x1b]);
        expected.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
        expected.extend_from_slice(&[0x04, 0xf4, 0x05, 0xa3, 0x00, 0x61, b'V', 0x02, 0x50]);
        expected.extend_from_slice(&v4(0x02));
        expected.extend_from_slice(&[0x03, 0xa0]);
        assert_eq!(bytes, expected);
        let v = round_trip(&bytes);
        assert_eq!(v.kind(), RecordKind::VaultMeta);
        assert_eq!(v.deletion(), Deletion::Live);
        assert_eq!(v.modified_at, Timestamp(1_700_000_000_000));
        let RecordBody::Live(Payload::VaultMeta(m)) = &v.body else {
            panic!("not vault meta");
        };
        assert_eq!(m.name.expose(), "V");
        assert!(m.description.is_none());
        assert_eq!(m.settings.history_depth_or_default(), 10);
        assert_eq!(m.settings.trash_retention_days_or_default(), 30);
        assert_eq!(format!("{v:?}"), "RecordVersion(<redacted>)");
    }

    #[test]
    fn record_keyslot_golden() {
        let bytes = map(&envelope(4, false, Some(map(&keyslot_payload()))));
        let mut payload = vec![0xa7, 0x00, 0x50];
        payload.extend_from_slice(&v4(0x03));
        payload.extend_from_slice(&[0x01, 0x01, 0x02, 0x58, 0x20]);
        payload.extend_from_slice(&[0x11; 32]);
        payload.extend_from_slice(&[0x03, 0x01, 0x04, 0x58, 0x20]);
        payload.extend_from_slice(&[0x22; 32]);
        payload.extend_from_slice(&[0x05, 0x58, 0x18]);
        payload.extend_from_slice(&[0x33; 24]);
        payload.extend_from_slice(&[0x06, 0x58, 0x30]);
        payload.extend_from_slice(&[0x44; 48]);
        assert!(bytes.ends_with(&payload));
        let v = round_trip(&bytes);
        let RecordBody::Live(Payload::PasswordKeyslot(k)) = &v.body else {
            panic!("not a keyslot");
        };
        assert_eq!(k.slot.kdf_salt, [0x11; 32]);
        assert_eq!(k.slot.kek_commit.as_bytes(), &[0x22; 32]);
        assert_eq!(format!("{k:?}"), "Keyslot(<redacted>)");
    }

    #[test]
    fn record_unknown_keys_survive_at_every_level() {
        let settings = map(&[(0, uint(5)), (2, map(&[(0, uint(9))])), (-3, text("s"))]);
        let payload = with(&vault_meta_payload(), 3, settings);
        let payload = with(&payload, 7, bytes(b"pay"));
        let mut env = envelope(0, false, Some(map(&payload)));
        env.push((9, text("env")));
        env.push((-1, null()));
        let bytes = map(&env);
        let v = round_trip(&bytes);
        assert_eq!(v.ext.len(), 2);
        let RecordBody::Live(Payload::VaultMeta(m)) = &v.body else {
            panic!("not vault meta");
        };
        assert_eq!(m.ext.len(), 1);
        assert_eq!(m.settings.ext.len(), 2);
        assert_eq!(m.settings.history_depth, Some(5));
        // Keyslot unknown keys too.
        let ks = with(&keyslot_payload(), 8, uint(1));
        round_trip(&map(&envelope(4, false, Some(map(&ks)))));
    }

    #[test]
    fn record_missing_required_keys() {
        let full = envelope(0, false, Some(map(&vault_meta_payload())));
        for k in 0..=5 {
            assert_eq!(
                decode(&without(&full, k)).map(|_| ()),
                Err(ModelError::Malformed),
                "envelope key {k}"
            );
        }
        for k in [0, 2, 3] {
            let p = without(&vault_meta_payload(), k);
            assert_eq!(
                decode(&envelope(0, false, Some(map(&p)))).map(|_| ()),
                Err(ModelError::Malformed),
                "vault meta key {k}"
            );
        }
        for k in 0..=6 {
            let p = without(&keyslot_payload(), k);
            assert_eq!(
                decode(&envelope(4, false, Some(map(&p)))).map(|_| ()),
                Err(ModelError::Malformed),
                "keyslot key {k}"
            );
        }
    }

    #[test]
    fn record_rejections() {
        let meta = map(&vault_meta_payload());
        let malformed = |e: &[(i64, Vec<u8>)]| {
            assert_eq!(decode(e).map(|_| ()), Err(ModelError::Malformed));
        };
        // Tombstone with a payload, live without one.
        malformed(&envelope(0, true, Some(meta.clone())));
        malformed(&envelope(0, false, None));
        // `null` for an optional key; ill-typed values.
        malformed(&envelope(
            0,
            false,
            Some(map(&with(&vault_meta_payload(), 1, null()))),
        ));
        malformed(&with(&envelope(0, false, Some(meta.clone())), 4, uint(0)));
        malformed(&with(
            &envelope(0, false, Some(meta.clone())),
            1,
            bytes(&[0; 16]),
        ));
        malformed(&with(
            &envelope(0, false, Some(meta.clone())),
            2,
            item(|e| e.array(|_| Ok(())).unwrap()),
        ));
        malformed(&envelope(
            0,
            false,
            Some(map(&with(
                &vault_meta_payload(),
                3,
                map(&[(0, uint(1 << 32))]),
            ))),
        ));
        // Not a map at all; trailing bytes.
        assert_eq!(
            RecordVersion::decode(&uint(0)).map(|_| ()),
            Err(ModelError::Malformed)
        );
        let mut trailing = map(&envelope(0, false, Some(meta.clone())));
        trailing.push(0x00);
        assert_eq!(
            RecordVersion::decode(&trailing).map(|_| ()),
            Err(ModelError::Malformed)
        );
        // Unknown kind; unknown profiles.
        assert_eq!(
            decode(&envelope(5, false, Some(meta.clone()))).map(|_| ()),
            Err(ModelError::Unsupported)
        );
        assert_eq!(
            decode(&envelope(5, true, None)).map(|_| ()),
            Err(ModelError::Unsupported)
        );
        for key in [1, 3] {
            let p = with(&keyslot_payload(), key, uint(2));
            assert_eq!(
                decode(&envelope(4, false, Some(map(&p)))).map(|_| ()),
                Err(ModelError::Unsupported),
                "profile key {key}"
            );
        }
        // Undeletable kinds.
        for kind in [0, 4] {
            assert_eq!(
                decode(&envelope(kind, true, None)).map(|_| ()),
                Err(ModelError::InvalidTransition)
            );
        }
    }

    #[test]
    fn record_length_is_checked_first() {
        let huge = vec![0xffu8; MAX_RECORD_BYTES + 1];
        assert_eq!(
            RecordVersion::decode(&huge).map(|_| ()),
            Err(ModelError::LimitExceeded)
        );
        // At the limit, the codec runs (and rejects these bytes).
        let at = vec![0xffu8; MAX_RECORD_BYTES];
        assert_eq!(
            RecordVersion::decode(&at).map(|_| ()),
            Err(ModelError::Malformed)
        );
    }

    #[test]
    fn record_encode_checks() {
        let mut v =
            RecordVersion::decode(&map(&envelope(0, false, Some(map(&vault_meta_payload())))))
                .unwrap();
        v.clock = Clock::new();
        assert_eq!(v.encode().map(|_| ()), Err(ModelError::Malformed));
        let mut t =
            RecordVersion::decode(&map(&envelope(0, false, Some(map(&vault_meta_payload())))))
                .unwrap();
        t.body = RecordBody::Tombstone(RecordKind::PasswordKeyslot);
        assert_eq!(t.encode().map(|_| ()), Err(ModelError::InvalidTransition));
    }
}
