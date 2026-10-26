// SPDX-License-Identifier: AGPL-3.0-or-later

//! The vault header and the header-MAC transcript (spec 0004 §2, 0002 §1.4,
//! §3.3, §7.2).
//!
//! The header body is a canonical CBOR map; every key is required and an
//! unknown key fails closed ([`StoreError::Unsupported`]): the header is
//! security configuration, and a new field means a new format value.
//! Development values, frozen in phase 1.16:
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | format | uint, = [`FORMAT`] |
//! | 1 | vault_id | bstr 16 (UUIDv4) |
//! | 2 | key_generation | uint (u32, ≥ 1) |
//! | 3 | data_profile | uint (u16, stored-data) |
//! | 4 | derivation_profile | uint (u16) |
//! | 5 | mac_profile | uint (u16) |
//! | 6 | min_data_profile | uint (u16, stored-data) |
//! | 7 | min_derivation_profile | uint (u16) |
//!
//! The header MAC is MAC/1 under the `header-mac` purpose key over the
//! canonical array `["qv/header-mac/v1", header_body, [[slot_id, type,
//! body], …]]`, with the exact stored bytes and slots sorted by slot ID.

use qv_crypto::{DerivationProfile, KeyGeneration, MacProfile, StoredDataProfile, VaultId};
use qv_encoding::{Decoder, Encoder, encode_array};
use qv_model::RandomId;
use zeroize::Zeroizing;

use crate::error::StoreError;

/// The development vault format (also the SQLite `user_version`).
pub(crate) const FORMAT: u64 = 0x7FFF_0002;

/// The header-MAC transcript label (development value).
pub(crate) const MAC_LABEL: &str = "qv/header-mac/v1";

/// The key generation of a new vault (0002 §3.5 adds 1 per rotation).
pub(crate) const INITIAL_GENERATION: KeyGeneration = KeyGeneration(1);

/// The vault header: identity, key generation and profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// The vault ID.
    pub vault_id: VaultId,
    /// The current key generation.
    pub key_generation: KeyGeneration,
    /// The stored-data profile for new objects.
    pub data_profile: StoredDataProfile,
    /// The derivation profile for purpose keys.
    pub derivation_profile: DerivationProfile,
    /// The MAC profile of the header MAC.
    pub mac_profile: MacProfile,
    /// The minimum accepted stored-data profile.
    pub min_data_profile: StoredDataProfile,
    /// The minimum accepted derivation profile.
    pub min_derivation_profile: DerivationProfile,
}

/// One stored keyslot row, as covered by the header MAC.
pub(crate) struct SlotRow<'a> {
    pub(crate) slot_id: &'a [u8; 16],
    pub(crate) kind: u64,
    pub(crate) body: &'a [u8],
}

fn malformed<E>(_: E) -> StoreError {
    StoreError::Integrity
}

impl Header {
    /// A new vault's header: generation 1, every profile V1.
    pub(crate) fn new_vault(vault_id: VaultId) -> Self {
        Self {
            vault_id,
            key_generation: INITIAL_GENERATION,
            data_profile: StoredDataProfile::V1,
            derivation_profile: DerivationProfile::V1,
            mac_profile: MacProfile::V1,
            min_data_profile: StoredDataProfile::V1,
            min_derivation_profile: DerivationProfile::V1,
        }
    }

    /// The canonical body.
    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let mut e = Encoder::new();
        e.map(|m| {
            let mut uint = |k: i64, v: u64| {
                m.entry(k, |e| {
                    e.uint(v);
                    Ok(())
                })
            };
            uint(0, FORMAT)?;
            uint(2, u64::from(self.key_generation.0))?;
            uint(3, u64::from(self.data_profile.id()))?;
            uint(4, u64::from(self.derivation_profile.id()))?;
            uint(5, u64::from(self.mac_profile.id()))?;
            uint(6, u64::from(self.min_data_profile.id()))?;
            uint(7, u64::from(self.min_derivation_profile.id()))?;
            m.entry(1, |e| {
                e.bytes(&self.vault_id.0);
                Ok(())
            })
        })
        .map_err(|_| StoreError::Internal)?;
        e.finish().map_err(|_| StoreError::Internal)
    }

    /// Decodes and checks a stored body. The caller has bounded its length.
    pub(crate) fn decode(input: &[u8]) -> Result<Self, StoreError> {
        let mut d = Decoder::new(input).map_err(malformed)?;
        let mut slots: [Option<u64>; 8] = [None; 8];
        let mut vault_id = None;
        for _ in 0..d.map().map_err(malformed)? {
            match d.int().map_err(malformed)? {
                1 => {
                    let b: [u8; 16] = d
                        .bytes()
                        .map_err(malformed)?
                        .try_into()
                        .map_err(malformed)?;
                    vault_id = Some(VaultId::from_bytes(b)?);
                }
                k @ (0 | 2..=7) => {
                    let i = usize::try_from(k).map_err(malformed)?;
                    let v = d.uint().map_err(malformed)?;
                    *slots.get_mut(i).ok_or(StoreError::Internal)? = Some(v);
                }
                _ => return Err(StoreError::Unsupported),
            }
        }
        d.finish().map_err(malformed)?;
        let get = |i: usize| slots.get(i).copied().flatten().ok_or(StoreError::Integrity);
        if get(0)? != FORMAT {
            return Err(StoreError::Unsupported);
        }
        let generation = u32::try_from(get(2)?).map_err(malformed)?;
        if generation == 0 {
            return Err(StoreError::Integrity);
        }
        let profile = |i: usize| u16::try_from(get(i)?).map_err(malformed);
        let header = Self {
            vault_id: vault_id.ok_or(StoreError::Integrity)?,
            key_generation: KeyGeneration(generation),
            data_profile: StoredDataProfile::from_id(profile(3)?)?,
            derivation_profile: DerivationProfile::from_id(profile(4)?)?,
            mac_profile: MacProfile::from_id(profile(5)?)?,
            min_data_profile: StoredDataProfile::from_id(profile(6)?)?,
            min_derivation_profile: DerivationProfile::from_id(profile(7)?)?,
        };
        if !header.data_profile.accepts(header.min_data_profile)
            || !header
                .derivation_profile
                .accepts(header.min_derivation_profile)
        {
            return Err(StoreError::Unsupported);
        }
        Ok(header)
    }
}

/// The header-MAC transcript over the exact stored bytes. `slots` must be
/// sorted by slot ID (the caller reads them that way and checks it).
pub(crate) fn mac_transcript(
    header_body: &[u8],
    slots: &[SlotRow<'_>],
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    encode_array(|a| {
        a.text(MAC_LABEL);
        a.bytes(header_body);
        a.array(|list| {
            for s in slots {
                list.array(|row| {
                    row.bytes(s.slot_id);
                    row.uint(s.kind);
                    row.bytes(s.body);
                    Ok(())
                })?;
            }
            Ok(())
        })
    })
    .map_err(|_| StoreError::Internal)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn v4(n: u8) -> [u8; 16] {
        let mut b = [0u8; 16];
        b[0] = n;
        b[6] = 0x40;
        b[8] = 0x80;
        b
    }

    fn map(entries: &[(i64, u64)], id: Option<[u8; 16]>) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map(|m| {
            for &(k, v) in entries {
                m.entry(k, |e| {
                    e.uint(v);
                    Ok(())
                })?;
            }
            if let Some(id) = id {
                m.entry(1, |e| {
                    e.bytes(&id);
                    Ok(())
                })?;
            }
            Ok(())
        })
        .unwrap();
        e.finish().unwrap().to_vec()
    }

    fn fields() -> Vec<(i64, u64)> {
        vec![(0, FORMAT), (2, 1), (3, 1), (4, 1), (5, 1), (6, 1), (7, 1)]
    }

    #[test]
    fn header_golden_bytes() {
        let h = Header::new_vault(VaultId(v4(0x0a)));
        let body = h.encode().unwrap();
        let mut expected = vec![0xa8, 0x00, 0x1a, 0x7f, 0xff, 0x00, 0x02, 0x01, 0x50];
        expected.extend_from_slice(&v4(0x0a));
        expected.extend_from_slice(&[
            0x02, 0x01, 0x03, 0x01, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x07, 0x01,
        ]);
        assert_eq!(body.as_slice(), expected.as_slice());
        assert_eq!(Header::decode(&body).unwrap(), h);
        assert_eq!(map(&fields(), Some(v4(0x0a))), expected);
    }

    #[test]
    fn header_rejections() {
        let ok = map(&fields(), Some(v4(1)));
        assert!(Header::decode(&ok).is_ok());
        // Every missing key.
        for k in [0, 2, 3, 4, 5, 6, 7] {
            let f: Vec<_> = fields().into_iter().filter(|&(key, _)| key != k).collect();
            assert_eq!(
                Header::decode(&map(&f, Some(v4(1)))),
                Err(StoreError::Integrity),
                "key {k}"
            );
        }
        assert_eq!(
            Header::decode(&map(&fields(), None)),
            Err(StoreError::Integrity)
        );
        // Unknown key fails closed.
        let mut f = fields();
        f.push((8, 0));
        assert_eq!(
            Header::decode(&map(&f, Some(v4(1)))),
            Err(StoreError::Unsupported)
        );
        let mut f = fields();
        f.push((-1, 0));
        assert_eq!(
            Header::decode(&map(&f, Some(v4(1)))),
            Err(StoreError::Unsupported)
        );
        // Format, generation, profiles.
        let set = |k: i64, v: u64| {
            let f: Vec<_> = fields()
                .into_iter()
                .map(|(key, old)| (key, if key == k { v } else { old }))
                .collect();
            Header::decode(&map(&f, Some(v4(1))))
        };
        assert_eq!(set(0, 1), Err(StoreError::Unsupported));
        assert_eq!(set(2, 0), Err(StoreError::Integrity));
        assert_eq!(set(2, u64::from(u32::MAX) + 1), Err(StoreError::Integrity));
        assert!(set(2, u64::from(u32::MAX)).is_ok());
        for k in 3..=7 {
            assert_eq!(set(k, 2), Err(StoreError::Unsupported), "key {k}");
            assert_eq!(set(k, 0x1_0000), Err(StoreError::Integrity), "key {k}");
        }
        // Non-v4 vault ID, wrong ID length, trailing bytes, not a map.
        assert_eq!(
            Header::decode(&map(&fields(), Some([0; 16]))),
            Err(StoreError::Integrity)
        );
        let mut trailing = ok.clone();
        trailing.push(0);
        assert_eq!(Header::decode(&trailing), Err(StoreError::Integrity));
        assert_eq!(Header::decode(&[0x80]), Err(StoreError::Integrity));
        assert_eq!(Header::decode(&[]), Err(StoreError::Integrity));
    }

    #[test]
    fn header_mac_transcript_golden() {
        let body = [0xa0u8];
        let (a, b) = (v4(1), v4(2));
        let rows = [
            SlotRow {
                slot_id: &a,
                kind: 0,
                body: &[0xa1, 0x00, 0x00],
            },
            SlotRow {
                slot_id: &b,
                kind: 0,
                body: &[0xa0],
            },
        ];
        let t = mac_transcript(&body, &rows).unwrap();
        let mut expected = vec![0x83, 0x70];
        expected.extend_from_slice(MAC_LABEL.as_bytes());
        expected.extend_from_slice(&[0x41, 0xa0, 0x82, 0x83, 0x50]);
        expected.extend_from_slice(&a);
        expected.extend_from_slice(&[0x00, 0x43, 0xa1, 0x00, 0x00, 0x83, 0x50]);
        expected.extend_from_slice(&b);
        expected.extend_from_slice(&[0x00, 0x41, 0xa0]);
        assert_eq!(t.as_slice(), expected.as_slice());
        let empty = mac_transcript(&body, &[]).unwrap();
        assert!(empty.ends_with(&[0x41, 0xa0, 0x80]));
    }
}
