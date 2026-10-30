// SPDX-License-Identifier: AGPL-3.0-or-later

//! Password slots: VK wrapped under a password KEK, with a KEK commitment
//! against partitioning oracles (spec 0002 §3.2, §8).
//!
//! The wrapping AAD is the canonical CBOR array
//! `["qv/password-slot/v1", vault_id, key_generation, slot_id,
//! password_kdf_profile, kdf_salt, password_wrap_profile]`.
//!
//! Unlocking checks, in this order: KDF → KEK → **commitment, in constant
//! time** → wrap key → AEAD. A commitment mismatch stops before any AEAD is
//! attempted, so a slot crafted to decrypt under many KEKs (Poly1305 is not
//! key-committing) cannot be used as a multi-password guessing oracle. Both a
//! commitment and an AEAD failure report [`CryptoError::WrongPassword`] only.

use crate::error::CryptoError;
use crate::ids::{KeyGeneration, SlotId, VaultId};
use crate::keys::{VaultKey, cbor_array};
use crate::memory::SecretArray;
use crate::password::{
    Kek, MasterKey, MasterPassword, derive_kek, derive_master_key, kek_commit, verify_kek_commit,
    wrap_key,
};
use crate::primitives::{MacTag, NONCE_LEN, TAG_LEN, xchacha_open_in_place, xchacha_seal_in_place};
use crate::profile::{PasswordKdfProfile, PasswordWrapProfile};
use crate::rng::random_array;

/// One password slot (the `keyslot` row's password fields, 0004 §2).
///
/// Profiles are typed: whoever parses a stored slot (phase 1.6) must turn the
/// stored `u16`s into these with `from_id`, so an unknown profile fails at
/// parse time, before any KDF work.
///
/// It has no `Debug` and no `Clone`: a slot enables offline password
/// guessing, so it should not be printed or copied around (0004 §6.4).
pub struct PasswordSlot {
    /// The slot's random ID.
    pub slot_id: SlotId,
    /// The password-KDF profile.
    pub kdf_profile: PasswordKdfProfile,
    /// The random 32-byte KDF salt.
    pub kdf_salt: [u8; 32],
    /// The password-wrap profile.
    pub wrap_profile: PasswordWrapProfile,
    /// MAC/1 of the KEK over `["qv/kek-commit/v1", vault_id, key_generation, slot_id]`.
    pub kek_commit: MacTag,
    /// The random wrapping nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The 32-byte VK ciphertext followed by its 16-byte tag.
    pub wrapped_vk: [u8; 32 + TAG_LEN],
}

/// The slot wrapping AAD.
pub(crate) fn slot_aad(
    vault: VaultId,
    generation: KeyGeneration,
    slot: SlotId,
    kdf_profile_id: u16,
    kdf_salt: &[u8; 32],
    wrap_profile_id: u16,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text("qv/password-slot/v1");
        a.bytes(&vault.0);
        a.uint(generation.0.into());
        a.bytes(&slot.0);
        a.uint(kdf_profile_id.into());
        a.bytes(kdf_salt);
        a.uint(wrap_profile_id.into());
    })
}

/// Wraps VK under `wrap_key` with `aad` and a fresh nonce.
fn wrap_vk(
    vk: &VaultKey,
    wrap_key: &SecretArray<32>,
    aad: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<[u8; 32 + TAG_LEN], CryptoError> {
    let mut buf = SecretArray::<32>::try_init(|b| {
        b.copy_from_slice(vk.expose_secret());
        Ok::<(), CryptoError>(())
    })?;
    let tag = xchacha_seal_in_place(
        wrap_key.expose_secret(),
        &nonce,
        aad,
        buf.expose_secret_mut(),
    )?;
    // After sealing, `buf` holds ciphertext only.
    let mut wrapped = [0u8; 32 + TAG_LEN];
    let (ct, t) = wrapped.split_at_mut(32);
    ct.copy_from_slice(buf.expose_secret());
    t.copy_from_slice(&tag);
    Ok(wrapped)
}

impl PasswordSlot {
    /// Creates a slot for `vk` under `password`, with a fresh random salt and
    /// nonce. Runs the full password KDF once.
    pub fn create(
        password: &MasterPassword,
        vk: &VaultKey,
        vault: VaultId,
        generation: KeyGeneration,
        slot_id: SlotId,
        kdf: PasswordKdfProfile,
        wrap: PasswordWrapProfile,
    ) -> Result<Self, CryptoError> {
        let kdf_salt = random_array::<32>()?;
        let mk = derive_master_key(password, &kdf_salt, kdf)?;
        Self::create_with_master_key(&mk, vk, vault, generation, slot_id, kdf, kdf_salt, wrap)
    }

    /// Unlocks the slot and returns VK. Every failure to authenticate the
    /// password is [`CryptoError::WrongPassword`].
    pub fn unlock(
        &self,
        password: &MasterPassword,
        vault: VaultId,
        generation: KeyGeneration,
    ) -> Result<VaultKey, CryptoError> {
        let mk = derive_master_key(password, &self.kdf_salt, self.kdf_profile)?;
        self.unlock_with_master_key(&mk, vault, generation)
    }

    // Eight inputs mirror the slot's fields; a parameter struct would only
    // rename them for this one crate-private caller.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_with_master_key(
        mk: &MasterKey,
        vk: &VaultKey,
        vault: VaultId,
        generation: KeyGeneration,
        slot_id: SlotId,
        kdf: PasswordKdfProfile,
        kdf_salt: [u8; 32],
        wrap: PasswordWrapProfile,
    ) -> Result<Self, CryptoError> {
        match wrap {
            PasswordWrapProfile::V1 => {}
        }
        let kek = derive_kek(mk, vault, kdf)?;
        let commit = kek_commit(&kek, vault, generation, slot_id)?;
        let wk = wrap_key(&kek)?;
        let aad = slot_aad(vault, generation, slot_id, kdf.id(), &kdf_salt, wrap.id())?;
        let nonce = random_array::<NONCE_LEN>()?;
        let wrapped_vk = wrap_vk(vk, &wk, &aad, nonce)?;
        Ok(Self {
            slot_id,
            kdf_profile: kdf,
            kdf_salt,
            wrap_profile: wrap,
            kek_commit: commit,
            nonce,
            wrapped_vk,
        })
    }

    pub(crate) fn unlock_with_master_key(
        &self,
        mk: &MasterKey,
        vault: VaultId,
        generation: KeyGeneration,
    ) -> Result<VaultKey, CryptoError> {
        match self.wrap_profile {
            PasswordWrapProfile::V1 => {}
        }
        let kek = derive_kek(mk, vault, self.kdf_profile)?;
        // The commitment gate comes first: no AEAD on a mismatch.
        verify_kek_commit(&kek, vault, generation, self.slot_id, &self.kek_commit)
            .map_err(wrong_password)?;
        self.open_with_kek(&kek, vault, generation)
    }

    fn open_with_kek(
        &self,
        kek: &Kek,
        vault: VaultId,
        generation: KeyGeneration,
    ) -> Result<VaultKey, CryptoError> {
        let wk = wrap_key(kek)?;
        let aad = slot_aad(
            vault,
            generation,
            self.slot_id,
            self.kdf_profile.id(),
            &self.kdf_salt,
            self.wrap_profile.id(),
        )?;
        let (ct, tag) = self.wrapped_vk.split_at(32);
        let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::Internal)?;
        let vk = SecretArray::<32>::try_init(|b| {
            b.copy_from_slice(ct);
            xchacha_open_in_place(wk.expose_secret(), &self.nonce, &aad, b, tag)
                .map_err(wrong_password)
        })?;
        Ok(VaultKey::from_secret(vk))
    }
}

/// Maps authentication failures to "wrong password" (0002 §8); other errors
/// (RNG, internal) pass through unchanged.
fn wrong_password(e: CryptoError) -> CryptoError {
    match e {
        CryptoError::Integrity => CryptoError::WrongPassword,
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::purpose;
    use crate::profile::DerivationProfile;

    const VAULT: VaultId = VaultId([0x11; 16]);
    const GEN: KeyGeneration = KeyGeneration(1);
    const SLOT: SlotId = SlotId([0x22; 16]);
    const SALT: [u8; 32] = [0x44; 32];
    const KDF: PasswordKdfProfile = PasswordKdfProfile::V1;
    const WRAP: PasswordWrapProfile = PasswordWrapProfile::V1;

    fn vk() -> VaultKey {
        VaultKey::from_bytes([0x5a; 32])
    }

    fn slot_for(mk: &MasterKey) -> PasswordSlot {
        PasswordSlot::create_with_master_key(mk, &vk(), VAULT, GEN, SLOT, KDF, SALT, WRAP).unwrap()
    }

    fn unlock(slot: &PasswordSlot, mk: &MasterKey) -> Result<[u8; 32], CryptoError> {
        slot.unlock_with_master_key(mk, VAULT, GEN)
            .map(|k| k.bytes())
    }

    /// A slot whose AAD carries the given raw profile IDs (the stored typed
    /// fields stay V1).
    fn slot_with_aad_ids(mk: &MasterKey, kdf_id: u16, wrap_id: u16) -> PasswordSlot {
        let mut slot = slot_for(mk);
        let kek = derive_kek(mk, VAULT, KDF).unwrap();
        let aad = slot_aad(VAULT, GEN, SLOT, kdf_id, &SALT, wrap_id).unwrap();
        slot.wrapped_vk = wrap_vk(&vk(), &wrap_key(&kek).unwrap(), &aad, slot.nonce).unwrap();
        slot
    }

    #[test]
    fn slot_round_trip_returns_the_same_vk() {
        let _guard = crate::memory::secrets_test_guard();
        let mk = MasterKey::from_bytes([1; 32]);
        let slot = slot_for(&mk);
        let back = slot.unlock_with_master_key(&mk, VAULT, GEN).unwrap();
        assert_eq!(back.bytes(), vk().bytes());
        // It derives the same purpose keys as the original.
        let a = vk()
            .purpose_key::<purpose::Manifest>(VAULT, GEN, DerivationProfile::V1)
            .unwrap()
            .bytes();
        let b = back
            .purpose_key::<purpose::Manifest>(VAULT, GEN, DerivationProfile::V1)
            .unwrap()
            .bytes();
        assert_eq!(a, b);
        assert_ne!(slot.wrapped_vk[..32], vk().bytes());
    }

    #[test]
    fn slot_wrong_master_key_is_wrong_password() {
        let _guard = crate::memory::secrets_test_guard();
        let slot = slot_for(&MasterKey::from_bytes([1; 32]));
        assert_eq!(
            unlock(&slot, &MasterKey::from_bytes([2; 32])),
            Err(CryptoError::WrongPassword)
        );
    }

    /// 0012 §1 "Password-slot partitioning oracle": a multi-key slot is
    /// rejected as a wrong password before decryption (0002 §3.2).
    // 0012 §1: Password-slot partitioning oracle
    #[test]
    fn slot_partitioning_oracle_is_rejected_before_decryption() {
        let _guard = crate::memory::secrets_test_guard();
        let mk_a = MasterKey::from_bytes([0xa1; 32]);
        let mk_b = MasterKey::from_bytes([0xb2; 32]);
        let kek_b = derive_kek(&mk_b, VAULT, KDF).unwrap();
        // Commitment for A, VK wrapped for B: the AEAD alone accepts B.
        let mut slot = slot_for(&mk_a);
        let aad = slot_aad(VAULT, GEN, SLOT, KDF.id(), &SALT, WRAP.id()).unwrap();
        slot.wrapped_vk = wrap_vk(&vk(), &wrap_key(&kek_b).unwrap(), &aad, slot.nonce).unwrap();
        assert_eq!(
            slot.open_with_kek(&kek_b, VAULT, GEN).map(|k| k.bytes()),
            Ok(vk().bytes()),
            "the AEAD alone would open under B"
        );
        // Through the real path, B fails at the commitment gate.
        assert_eq!(unlock(&slot, &mk_b), Err(CryptoError::WrongPassword));
        // A passes the gate, but the AEAD is B's: still only "wrong password".
        assert_eq!(unlock(&slot, &mk_a), Err(CryptoError::WrongPassword));
    }

    #[test]
    fn slot_every_aad_field_is_bound() {
        let _guard = crate::memory::secrets_test_guard();
        let mk = MasterKey::from_bytes([3; 32]);
        let slot = slot_for(&mk);
        // Context mismatches (vault, generation) fail at the commitment.
        assert_eq!(
            slot.unlock_with_master_key(&mk, VaultId([0x12; 16]), GEN)
                .map(|_| ()),
            Err(CryptoError::WrongPassword)
        );
        assert_eq!(
            slot.unlock_with_master_key(&mk, VAULT, KeyGeneration(2))
                .map(|_| ()),
            Err(CryptoError::WrongPassword)
        );
        // A different stored slot ID or salt.
        let mut other_id = slot_for(&mk);
        other_id.slot_id = SlotId([0x23; 16]);
        assert_eq!(unlock(&other_id, &mk), Err(CryptoError::WrongPassword));
        let mut other_salt = slot_for(&mk);
        other_salt.kdf_salt[0] ^= 1;
        assert_eq!(unlock(&other_salt, &mk), Err(CryptoError::WrongPassword));
        // Profile IDs in the AAD: the commitment passes, the AEAD fails.
        for (kdf_id, wrap_id) in [(2, 1), (1, 2), (0, 1), (1, u16::MAX)] {
            let s = slot_with_aad_ids(&mk, kdf_id, wrap_id);
            assert_eq!(unlock(&s, &mk), Err(CryptoError::WrongPassword));
        }
        // Control: the helper with the real IDs opens.
        assert_eq!(unlock(&slot_with_aad_ids(&mk, 1, 1), &mk), Ok(vk().bytes()));
    }

    #[test]
    fn slot_tampering_is_wrong_password() {
        let _guard = crate::memory::secrets_test_guard();
        let mk = MasterKey::from_bytes([4; 32]);
        for i in 0..48 {
            let mut s = slot_for(&mk);
            s.wrapped_vk[i] ^= 0x01;
            assert_eq!(unlock(&s, &mk), Err(CryptoError::WrongPassword), "byte {i}");
        }
        let mut s = slot_for(&mk);
        s.nonce[0] ^= 1;
        assert_eq!(unlock(&s, &mk), Err(CryptoError::WrongPassword));
        let mut s = slot_for(&mk);
        let mut c = *s.kek_commit.as_bytes();
        c[31] ^= 1;
        s.kek_commit = MacTag::from_bytes(c);
        assert_eq!(unlock(&s, &mk), Err(CryptoError::WrongPassword));
    }

    // 0012 §1: Unpinned crypto
    #[test]
    fn slot_unknown_profiles_fail_at_parse_time() {
        assert_eq!(
            PasswordKdfProfile::from_id(2),
            Err(CryptoError::UnknownProfile)
        );
        assert_eq!(
            PasswordWrapProfile::from_id(0),
            Err(CryptoError::UnknownProfile)
        );
    }

    #[test]
    fn slot_create_uses_fresh_salt_and_nonce() {
        let _guard = crate::memory::secrets_test_guard();
        let mk = MasterKey::from_bytes([5; 32]);
        let a = slot_for(&mk);
        let b = slot_for(&mk);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.wrapped_vk, b.wrapped_vk);
    }

    /// End to end with the real password KDF (three full Argon2 runs).
    #[test]
    fn slot_end_to_end_with_password() {
        let _guard = crate::memory::secrets_test_guard();
        let password = MasterPassword::from_utf8("Cafe\u{301} correct horse".as_bytes()).unwrap();
        let slot = PasswordSlot::create(&password, &vk(), VAULT, GEN, SLOT, KDF, WRAP).unwrap();
        assert_ne!(slot.kdf_salt, [0u8; 32]);
        let same = MasterPassword::from_utf8("Caf\u{e9} correct horse".as_bytes()).unwrap();
        assert_eq!(
            slot.unlock(&same, VAULT, GEN).map(|k| k.bytes()),
            Ok(vk().bytes())
        );
        let wrong = MasterPassword::from_utf8(b"Cafe correct horse").unwrap();
        assert_eq!(
            slot.unlock(&wrong, VAULT, GEN).map(|_| ()),
            Err(CryptoError::WrongPassword)
        );
    }
}
