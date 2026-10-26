// SPDX-License-Identifier: AGPL-3.0-or-later

//! The authenticated local head (spec 0005 §5.4, 0004 §2).
//!
//! Every commit writes one head: `{ vault_id, key_generation, local_seq,
//! previous_digest, manifest_hash, remote_checkpoint_id?, remote_sequence? }`,
//! MAC'd under the `local-state` purpose key. Body (canonical CBOR map;
//! unknown keys fail closed). Development values, frozen in phase 1.16:
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | vault_id | bstr 16 |
//! | 1 | key_generation | uint (u32, ≥ 1) |
//! | 2 | local_seq | uint (≥ 1) |
//! | 3 | previous_digest | bstr 32; absent iff `local_seq` = 1 |
//! | 4 | manifest_hash | bstr 32 |
//! | 5 | remote_checkpoint_id | bstr 32, optional (server mode; never written yet) |
//! | 6 | remote_sequence | uint, present iff key 5 is |
//!
//! MAC: MAC/1 over `["qv/local-head/v1", body]`. `local_digest` is SHA-256
//! of the canonical `[body, mac]`.
//!
//! [`compare`] is the head-versus-anchor table of 0005 §5.4.

use qv_crypto::{
    KeyGeneration, MacProfile, MacTag, ObjectHashProfile, PurposeKey, VaultId, mac, object_hash,
    purpose, verify_mac,
};
use qv_encoding::{Decoder, Encoder, encode_array};
use qv_model::RandomId;

use crate::error::StoreError;

/// How a vault's local head relates to its anchor (0005 §5.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnchorStatus {
    /// The head is the anchored commit.
    Verified,
    /// The head is one commit past the anchor and names it: a crash after
    /// the DB commit. The anchor has been advanced.
    Advanced,
    /// No anchor exists for this vault DB. Writes stay blocked until an
    /// explicit recovery adopts the current state.
    Missing,
    /// Older, forked, more than one commit ahead, another vault or
    /// generation: rollback evidence. Writes stay blocked.
    Mismatch,
}

/// An anchor's contents.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Anchor {
    pub(crate) vault_id: VaultId,
    pub(crate) key_generation: KeyGeneration,
    pub(crate) local_seq: u64,
    pub(crate) local_digest: [u8; 32],
}

/// The head-MAC transcript label (development value).
const MAC_LABEL: &str = "qv/local-head/v1";

/// Largest stored head body.
pub(crate) const MAX_HEAD_BYTES: usize = 1024;

/// A decoded local head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalHead {
    pub(crate) vault_id: VaultId,
    pub(crate) key_generation: KeyGeneration,
    pub(crate) local_seq: u64,
    pub(crate) previous_digest: Option<[u8; 32]>,
    pub(crate) manifest_hash: [u8; 32],
    pub(crate) remote: Option<([u8; 32], u64)>,
}

fn malformed<E>(_: E) -> StoreError {
    StoreError::Integrity
}

fn digest32(d: &mut Decoder<'_>) -> Result<[u8; 32], StoreError> {
    d.bytes().map_err(malformed)?.try_into().map_err(malformed)
}

impl LocalHead {
    /// The canonical body.
    pub(crate) fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut e = Encoder::new();
        e.map(|m| {
            m.entry(0, |e| {
                e.bytes(&self.vault_id.0);
                Ok(())
            })?;
            m.entry(1, |e| {
                e.uint(u64::from(self.key_generation.0));
                Ok(())
            })?;
            m.entry(2, |e| {
                e.uint(self.local_seq);
                Ok(())
            })?;
            if let Some(p) = &self.previous_digest {
                m.entry(3, |e| {
                    e.bytes(p);
                    Ok(())
                })?;
            }
            m.entry(4, |e| {
                e.bytes(&self.manifest_hash);
                Ok(())
            })?;
            if let Some((id, seq)) = &self.remote {
                m.entry(5, |e| {
                    e.bytes(id);
                    Ok(())
                })?;
                m.entry(6, |e| {
                    e.uint(*seq);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|_| StoreError::Internal)?;
        Ok(e.finish().map_err(|_| StoreError::Internal)?.to_vec())
    }

    /// Decodes and checks a stored body.
    pub(crate) fn decode(input: &[u8]) -> Result<Self, StoreError> {
        if input.len() > MAX_HEAD_BYTES {
            return Err(StoreError::Integrity);
        }
        let mut d = Decoder::new(input).map_err(malformed)?;
        let (mut vault_id, mut generation, mut seq, mut previous, mut manifest) =
            (None, None, None, None, None);
        let (mut checkpoint, mut remote_seq) = (None, None);
        for _ in 0..d.map().map_err(malformed)? {
            match d.int().map_err(malformed)? {
                0 => {
                    let b: [u8; 16] = d
                        .bytes()
                        .map_err(malformed)?
                        .try_into()
                        .map_err(malformed)?;
                    vault_id = Some(VaultId::from_bytes(b)?);
                }
                1 => generation = Some(d.uint().map_err(malformed)?),
                2 => seq = Some(d.uint().map_err(malformed)?),
                3 => previous = Some(digest32(&mut d)?),
                4 => manifest = Some(digest32(&mut d)?),
                5 => checkpoint = Some(digest32(&mut d)?),
                6 => remote_seq = Some(d.uint().map_err(malformed)?),
                _ => return Err(StoreError::Unsupported),
            }
        }
        d.finish().map_err(malformed)?;
        let generation = u32::try_from(generation.ok_or(StoreError::Integrity)?)
            .ok()
            .filter(|&g| g > 0)
            .ok_or(StoreError::Integrity)?;
        let local_seq = seq.filter(|&s| s > 0).ok_or(StoreError::Integrity)?;
        if (local_seq == 1) != previous.is_none() {
            return Err(StoreError::Integrity);
        }
        let remote = match (checkpoint, remote_seq) {
            (Some(id), Some(s)) => Some((id, s)),
            (None, None) => None,
            _ => return Err(StoreError::Integrity),
        };
        Ok(Self {
            vault_id: vault_id.ok_or(StoreError::Integrity)?,
            key_generation: KeyGeneration(generation),
            local_seq,
            previous_digest: previous,
            manifest_hash: manifest.ok_or(StoreError::Integrity)?,
            remote,
        })
    }
}

fn transcript(body: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
    encode_array(|a| {
        a.text(MAC_LABEL);
        a.bytes(body);
        Ok(())
    })
    .map_err(|_| StoreError::Internal)
}

/// The head MAC over a body.
pub(crate) fn head_mac(
    key: &PurposeKey<purpose::LocalState>,
    profile: MacProfile,
    body: &[u8],
) -> Result<MacTag, StoreError> {
    Ok(mac(key, profile, &transcript(body)?)?)
}

/// Verifies a stored head's MAC; a mismatch is [`StoreError::Integrity`].
pub(crate) fn verify_head(
    key: &PurposeKey<purpose::LocalState>,
    profile: MacProfile,
    body: &[u8],
    tag: &MacTag,
) -> Result<(), StoreError> {
    verify_mac(key, profile, &transcript(body)?, tag).map_err(|_| StoreError::Integrity)
}

/// SHA-256 of the canonical `[body, mac]` (0005 §5.4 `local_digest`).
pub(crate) fn local_digest(body: &[u8], tag: &MacTag) -> Result<[u8; 32], StoreError> {
    let bytes = encode_array(|a| {
        a.bytes(body);
        a.bytes(tag.as_bytes());
        Ok(())
    })
    .map_err(|_| StoreError::Internal)?;
    Ok(object_hash(ObjectHashProfile::V1, &bytes).0)
}

/// The head-versus-anchor table (0005 §5.4). `digest` is the head's
/// `local_digest`.
pub(crate) fn compare(
    head: &LocalHead,
    digest: &[u8; 32],
    anchor: Option<&Anchor>,
) -> AnchorStatus {
    let Some(a) = anchor else {
        return AnchorStatus::Missing;
    };
    if a.vault_id != head.vault_id {
        return AnchorStatus::Mismatch;
    }
    if head.local_seq == a.local_seq
        && head.key_generation == a.key_generation
        && *digest == a.local_digest
    {
        return AnchorStatus::Verified;
    }
    let next_seq = a.local_seq.checked_add(1) == Some(head.local_seq);
    let same_or_next_gen = head.key_generation == a.key_generation
        || a.key_generation.0.checked_add(1) == Some(head.key_generation.0);
    if next_seq && same_or_next_gen && head.previous_digest == Some(a.local_digest) {
        AnchorStatus::Advanced
    } else {
        AnchorStatus::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use qv_crypto::{DerivationProfile, VaultKey};

    use super::*;
    use crate::header::tests::v4;

    fn head(seq: u64) -> LocalHead {
        LocalHead {
            vault_id: VaultId(v4(1)),
            key_generation: KeyGeneration(1),
            local_seq: seq,
            previous_digest: (seq > 1).then_some([seq as u8; 32]),
            manifest_hash: [0xee; 32],
            remote: None,
        }
    }

    fn anchor(seq: u64, digest: [u8; 32]) -> Anchor {
        Anchor {
            vault_id: VaultId(v4(1)),
            key_generation: KeyGeneration(1),
            local_seq: seq,
            local_digest: digest,
        }
    }

    #[test]
    fn head_round_trip_and_golden() {
        let h = head(1);
        let body = h.encode().unwrap();
        let mut expected = vec![0xa4, 0x00, 0x50];
        expected.extend_from_slice(&v4(1));
        expected.extend_from_slice(&[0x01, 0x01, 0x02, 0x01, 0x04, 0x58, 0x20]);
        expected.extend_from_slice(&[0xee; 32]);
        assert_eq!(body, expected);
        assert_eq!(LocalHead::decode(&body).unwrap(), h);
        let mut r = head(7);
        r.remote = Some(([5; 32], 9));
        assert_eq!(LocalHead::decode(&r.encode().unwrap()).unwrap(), r);
    }

    #[test]
    fn head_rejections() {
        let enc = |h: &LocalHead| h.encode().unwrap();
        // previous_digest at seq 1, or missing later.
        let mut h = head(1);
        h.previous_digest = Some([1; 32]);
        assert_eq!(
            LocalHead::decode(&enc(&h)).err(),
            Some(StoreError::Integrity)
        );
        let mut h = head(2);
        h.previous_digest = None;
        assert_eq!(
            LocalHead::decode(&enc(&h)).err(),
            Some(StoreError::Integrity)
        );
        // Sequence 0, generation 0.
        let mut h = head(1);
        h.local_seq = 0;
        assert_eq!(
            LocalHead::decode(&enc(&h)).err(),
            Some(StoreError::Integrity)
        );
        let mut h = head(1);
        h.key_generation = KeyGeneration(0);
        assert_eq!(
            LocalHead::decode(&enc(&h)).err(),
            Some(StoreError::Integrity)
        );
        // remote_sequence without remote_checkpoint_id, and the reverse.
        type Entry<'a> = (i64, &'a dyn Fn(&mut Encoder));
        type Entries<'a> = [Entry<'a>];
        let raw = |entries: &Entries<'_>| {
            let mut e = Encoder::new();
            e.map(|m| {
                for (k, f) in entries {
                    m.entry(*k, |e| {
                        f(e);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap();
            e.finish().unwrap().to_vec()
        };
        let id = |e: &mut Encoder| e.bytes(&v4(1));
        let one = |e: &mut Encoder| e.uint(1);
        let d32 = |e: &mut Encoder| e.bytes(&[0; 32]);
        let base: Vec<Entry<'_>> = vec![(0, &id), (1, &one), (2, &one), (4, &d32)];
        assert!(LocalHead::decode(&raw(&base)).is_ok());
        let mut only6 = base.clone();
        only6.push((6, &one));
        assert_eq!(
            LocalHead::decode(&raw(&only6)).err(),
            Some(StoreError::Integrity)
        );
        let mut only5 = base.clone();
        only5.push((5, &d32));
        assert_eq!(
            LocalHead::decode(&raw(&only5)).err(),
            Some(StoreError::Integrity)
        );
        // Unknown key; missing manifest hash; oversized.
        let mut unknown = base.clone();
        unknown.push((7, &one));
        assert_eq!(
            LocalHead::decode(&raw(&unknown)).err(),
            Some(StoreError::Unsupported)
        );
        assert_eq!(
            LocalHead::decode(&raw(&base[..3])).err(),
            Some(StoreError::Integrity)
        );
        assert_eq!(
            LocalHead::decode(&vec![0; MAX_HEAD_BYTES + 1]).err(),
            Some(StoreError::Integrity)
        );
    }

    #[test]
    fn head_mac_and_digest() {
        let vk = VaultKey::generate().unwrap();
        let key = vk
            .purpose_key::<purpose::LocalState>(
                VaultId(v4(1)),
                KeyGeneration(1),
                DerivationProfile::V1,
            )
            .unwrap();
        let body = head(3).encode().unwrap();
        let tag = head_mac(&key, MacProfile::V1, &body).unwrap();
        verify_head(&key, MacProfile::V1, &body, &tag).unwrap();
        let mut bad = body.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            verify_head(&key, MacProfile::V1, &bad, &tag),
            Err(StoreError::Integrity)
        );
        let mut flipped = *tag.as_bytes();
        flipped[0] ^= 1;
        assert_eq!(
            verify_head(&key, MacProfile::V1, &body, &MacTag::from_bytes(flipped)),
            Err(StoreError::Integrity)
        );
        let d = local_digest(&body, &tag).unwrap();
        assert_ne!(
            d,
            local_digest(&body, &MacTag::from_bytes(flipped)).unwrap()
        );
        let other = head(4).encode().unwrap();
        assert_ne!(d, local_digest(&other, &tag).unwrap());
    }

    #[test]
    fn head_anchor_table() {
        let d5 = [5u8; 32];
        // head(n) names [n; 32] as its previous digest.
        let h = head(5);
        assert_eq!(compare(&h, &d5, None), AnchorStatus::Missing);
        assert_eq!(
            compare(&h, &d5, Some(&anchor(5, d5))),
            AnchorStatus::Verified
        );
        // Crash after commit: one ahead, naming the anchor's digest.
        assert_eq!(
            compare(&h, &d5, Some(&anchor(4, [5; 32]))),
            AnchorStatus::Advanced
        );
        // One ahead with another previous digest (a fork).
        assert_eq!(
            compare(&h, &d5, Some(&anchor(4, [9; 32]))),
            AnchorStatus::Mismatch
        );
        // Two ahead, one behind, equal sequence with another digest.
        assert_eq!(
            compare(&h, &d5, Some(&anchor(3, [5; 32]))),
            AnchorStatus::Mismatch
        );
        assert_eq!(
            compare(&h, &d5, Some(&anchor(6, d5))),
            AnchorStatus::Mismatch
        );
        assert_eq!(
            compare(&h, &d5, Some(&anchor(5, [6; 32]))),
            AnchorStatus::Mismatch
        );
        // Another vault.
        let mut other = anchor(5, d5);
        other.vault_id = VaultId(v4(2));
        assert_eq!(compare(&h, &d5, Some(&other)), AnchorStatus::Mismatch);
        // Same sequence and digest but another generation.
        let mut g = anchor(5, d5);
        g.key_generation = KeyGeneration(2);
        assert_eq!(compare(&h, &d5, Some(&g)), AnchorStatus::Mismatch);
        // A generation step: seq + 1, generation + 1, naming the old digest.
        let mut step = head(5);
        step.key_generation = KeyGeneration(2);
        assert_eq!(
            compare(&step, &d5, Some(&anchor(4, [5; 32]))),
            AnchorStatus::Advanced
        );
        // A generation jump of two is not one step.
        step.key_generation = KeyGeneration(3);
        assert_eq!(
            compare(&step, &d5, Some(&anchor(4, [5; 32]))),
            AnchorStatus::Mismatch
        );
        // A generation going back is not a step either.
        let mut back = anchor(4, [5; 32]);
        back.key_generation = KeyGeneration(2);
        assert_eq!(compare(&h, &d5, Some(&back)), AnchorStatus::Mismatch);
    }
}
