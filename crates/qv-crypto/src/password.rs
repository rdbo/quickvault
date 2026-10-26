// SPDX-License-Identifier: AGPL-3.0-or-later

//! The master password, password-kdf/1 and the password KEK (spec 0002 §3.1,
//! §3.2).
//!
//! | Value | Derivation |
//! |-------|------------|
//! | MK | Argon2id v1.3 (256 MiB, t=3, p=4, 32 bytes) over the NFC password and a random 32-byte salt |
//! | KEK | HKDF-SHA-512(IKM = MK, salt = vault ID, info = `["qv/kek/v1", password_kdf_profile]`) |
//! | KEK commitment | MAC/1(KEK, `["qv/kek-commit/v1", vault_id, key_generation, slot_id]`) |
//! | Wrap key | HKDF-SHA-512(IKM = KEK, no salt, info = `["qv/kek-wrap/v1"]`) |
//!
//! Residual copies we cannot wipe: `unicode-normalization` keeps a few
//! characters in its own small buffers while composing. Argon2's 256 MiB of
//! working memory is ours and is wiped after use, but it is far larger than
//! any memory-lock limit, so it is not locked.

use argon2::{Algorithm, Argon2, Block, Params, Version};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::ids::{KeyGeneration, SlotId, VaultId};
use crate::keys::{cbor_array, derive_secret};
use crate::memory::{SecretArray, SecretBytes};
use crate::primitives::{MacTag, mac1, mac1_verify};
use crate::profile::PasswordKdfProfile;

/// NFC output is at most three times the input's UTF-8 length: composition
/// never lengthens NFD, and no scalar value's NFD exceeds 3× its own length
/// (checked exhaustively by a test).
const NFC_EXPANSION: usize = 3;

/// A master password, NFC-normalized (0002 §3.1) into locked memory.
pub struct MasterPassword {
    buf: SecretBytes,
    len: usize,
}

impl MasterPassword {
    /// Validates UTF-8 and normalizes to NFC. `password` is only borrowed;
    /// the caller keeps (and wipes) its own buffer.
    pub fn from_utf8(password: &[u8]) -> Result<Self, CryptoError> {
        let text = core::str::from_utf8(password).map_err(|_| CryptoError::InvalidPassword)?;
        let capacity = text
            .len()
            .checked_mul(NFC_EXPANSION)
            .ok_or(CryptoError::LimitExceeded)?;
        let mut buf = SecretBytes::zeroed(capacity);
        let mut len = 0usize;
        let out = buf.expose_secret_mut();
        for c in text.nfc() {
            let end = len.checked_add(c.len_utf8()).ok_or(CryptoError::Internal)?;
            // Never reallocates: overflowing the bound fails closed.
            let dst = out.get_mut(len..end).ok_or(CryptoError::Internal)?;
            c.encode_utf8(dst);
            len = end;
        }
        Ok(Self { buf, len })
    }

    fn as_bytes(&self) -> &[u8] {
        self.buf.expose_secret().get(..self.len).unwrap_or_default()
    }

    /// The NFC-normalized password text, for a strength estimate. It is
    /// valid UTF-8 by construction.
    pub fn expose_secret(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or_default()
    }
}

impl core::fmt::Debug for MasterPassword {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MasterPassword(<redacted>)")
    }
}

/// MK: the Argon2id output. Never stored.
pub(crate) struct MasterKey(SecretArray<32>);

/// The password KEK derived from MK.
pub(crate) struct Kek(SecretArray<32>);

/// The exact Argon2 parameters of a password-kdf profile.
/// The public Argon2id parameters of a password-kdf profile (shown by
/// `qvault info`; they are not secret).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory in KiB.
    pub memory_kib: u32,
    /// Passes over memory.
    pub iterations: u32,
    /// Lanes.
    pub parallelism: u32,
}

impl PasswordKdfProfile {
    /// This profile's Argon2id parameters (0002 §1).
    pub fn argon2_params(self) -> Argon2Params {
        match self {
            PasswordKdfProfile::V1 => Argon2Params {
                memory_kib: 256 * 1024,
                iterations: 3,
                parallelism: 4,
            },
        }
    }
}

pub(crate) fn params(profile: PasswordKdfProfile) -> Result<Params, CryptoError> {
    let p = profile.argon2_params();
    Params::new(p.memory_kib, p.iterations, p.parallelism, Some(32))
        .map_err(|_| CryptoError::Internal)
}

/// Runs the password KDF. `salt` is the slot's random 32-byte KDF salt.
pub(crate) fn derive_master_key(
    password: &MasterPassword,
    salt: &[u8; 32],
    profile: PasswordKdfProfile,
) -> Result<MasterKey, CryptoError> {
    let params = params(profile)?;
    let mut blocks = vec![Block::new(); params.block_count()];
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let result = SecretArray::try_init(|out| {
        argon
            .hash_password_into_with_memory(password.as_bytes(), salt, out, &mut blocks[..])
            .map_err(|_| CryptoError::Internal)
    });
    // Wipe the working memory on every path, before it is freed.
    blocks.iter_mut().for_each(Zeroize::zeroize);
    Ok(MasterKey(result?))
}

/// KEK = HKDF-SHA-512(MK, salt = vault ID, `["qv/kek/v1", kdf_profile]`).
pub(crate) fn derive_kek(
    mk: &MasterKey,
    vault: VaultId,
    profile: PasswordKdfProfile,
) -> Result<Kek, CryptoError> {
    derive_kek_raw(mk, vault, profile.id())
}

/// `["qv/kek/v1", password_kdf_profile]`.
pub(crate) fn kek_info(kdf_profile_id: u16) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text("qv/kek/v1");
        a.uint(kdf_profile_id.into());
    })
}

fn derive_kek_raw(mk: &MasterKey, vault: VaultId, kdf_profile_id: u16) -> Result<Kek, CryptoError> {
    let info = kek_info(kdf_profile_id)?;
    Ok(Kek(derive_secret(
        mk.0.expose_secret(),
        Some(&vault.0),
        &info,
    )?))
}

/// `["qv/kek-commit/v1", vault_id, key_generation, slot_id]`.
pub(crate) fn commit_message(
    vault: VaultId,
    generation: KeyGeneration,
    slot: SlotId,
) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text("qv/kek-commit/v1");
        a.bytes(&vault.0);
        a.uint(generation.0.into());
        a.bytes(&slot.0);
    })
}

/// `kek_commit = MAC/1(KEK, ["qv/kek-commit/v1", vault_id, key_generation, slot_id])`.
pub(crate) fn kek_commit(
    kek: &Kek,
    vault: VaultId,
    generation: KeyGeneration,
    slot: SlotId,
) -> Result<MacTag, CryptoError> {
    mac1(
        kek.0.expose_secret(),
        &commit_message(vault, generation, slot)?,
    )
}

/// Checks a stored commitment in constant time; a mismatch is
/// [`CryptoError::Integrity`] (the slot reports it as a wrong password).
pub(crate) fn verify_kek_commit(
    kek: &Kek,
    vault: VaultId,
    generation: KeyGeneration,
    slot: SlotId,
    tag: &MacTag,
) -> Result<(), CryptoError> {
    mac1_verify(
        kek.0.expose_secret(),
        &commit_message(vault, generation, slot)?,
        tag,
    )
}

/// The slot wrapping key: HKDF-SHA-512(KEK, no salt, `["qv/kek-wrap/v1"]`).
pub(crate) fn wrap_key(kek: &Kek) -> Result<SecretArray<32>, CryptoError> {
    derive_secret(kek.0.expose_secret(), None, &wrap_info()?)
}

/// `["qv/kek-wrap/v1"]`.
pub(crate) fn wrap_info() -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| a.text("qv/kek-wrap/v1"))
}

#[cfg(test)]
impl MasterKey {
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(
            SecretArray::try_init(|b| {
                *b = bytes;
                Ok::<(), ()>(())
            })
            .unwrap(),
        )
    }

    pub(crate) fn bytes(&self) -> [u8; 32] {
        *self.0.expose_secret()
    }
}

#[cfg(test)]
impl Kek {
    pub(crate) fn bytes(&self) -> [u8; 32] {
        *self.0.expose_secret()
    }
}

#[cfg(test)]
impl MasterPassword {
    pub(crate) fn normalized(&self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: VaultId = VaultId([0x11; 16]);
    const GEN: KeyGeneration = KeyGeneration(1);
    const SLOT: SlotId = SlotId([0x22; 16]);

    fn nfc(s: &str) -> Vec<u8> {
        MasterPassword::from_utf8(s.as_bytes())
            .unwrap()
            .normalized()
    }

    #[test]
    fn password_nfc_equivalent_spellings_match() {
        let _guard = crate::memory::secrets_test_guard();
        assert_eq!(nfc("e\u{301}"), "\u{e9}".as_bytes());
        assert_eq!(nfc("\u{212b}"), "\u{c5}".as_bytes()); // ANGSTROM SIGN → Å
        assert_eq!(nfc("A\u{30a}"), "\u{c5}".as_bytes());
        assert_eq!(nfc("\u{1100}\u{1161}\u{11a8}"), "\u{ac01}".as_bytes()); // 각
        assert_eq!(nfc("plain ascii"), b"plain ascii");
        assert_eq!(nfc(""), b"");
        // Composition exclusions expand: U+0958 → U+0915 U+093C.
        assert_eq!(nfc("\u{958}"), "\u{915}\u{93c}".as_bytes());
    }

    #[test]
    fn password_rejects_invalid_utf8() {
        let _guard = crate::memory::secrets_test_guard();
        for bad in [&b"\xff"[..], b"ab\xc0\x80", b"\xed\xa0\x80", b"caf\xc3"] {
            assert_eq!(
                MasterPassword::from_utf8(bad).map(|_| ()),
                Err(CryptoError::InvalidPassword)
            );
        }
    }

    #[test]
    fn password_nfc_expansion_bound_holds_for_every_scalar() {
        let mut worst = 0usize;
        let mut buf = [0u8; 4];
        for c in (0..=0x10_ffffu32).filter_map(char::from_u32) {
            let s: &str = c.encode_utf8(&mut buf);
            let nfd: usize = s.nfd().map(char::len_utf8).sum();
            let nfc: usize = s.nfc().map(char::len_utf8).sum();
            assert!(nfd <= NFC_EXPANSION * s.len(), "NFD of U+{:04X}", c as u32);
            assert!(nfc <= nfd, "NFC longer than NFD for U+{:04X}", c as u32);
            worst = worst.max(nfd.div_ceil(s.len()));
        }
        assert_eq!(worst, NFC_EXPANSION, "the bound is tight");
    }

    #[test]
    fn password_debug_is_redacted() {
        let _guard = crate::memory::secrets_test_guard();
        let p = MasterPassword::from_utf8(b"hunter2").unwrap();
        assert_eq!(format!("{p:?}"), "MasterPassword(<redacted>)");
    }

    #[test]
    fn password_kdf_v1_parameters_are_exact() {
        let p = params(PasswordKdfProfile::V1).unwrap();
        assert_eq!(
            (p.m_cost(), p.t_cost(), p.p_cost(), p.output_len()),
            (262_144, 3, 4, Some(32))
        );
        assert_eq!(p.block_count(), 262_144);
        assert_eq!(
            PasswordKdfProfile::V1.argon2_params(),
            Argon2Params {
                memory_kib: 262_144,
                iterations: 3,
                parallelism: 4
            }
        );
    }

    #[test]
    fn password_expose_secret_is_the_nfc_text() {
        let _guard = crate::memory::secrets_test_guard();
        let p = MasterPassword::from_utf8("cafe\u{301} au lait".as_bytes()).unwrap();
        assert_eq!(p.expose_secret(), "caf\u{e9} au lait");
        let empty = MasterPassword::from_utf8(b"").unwrap();
        assert_eq!(empty.expose_secret(), "");
    }

    #[test]
    fn password_rfc9106_argon2id_through_the_pinned_crate() {
        let records = crate::kat::parse(include_str!("../tests/vectors/rfc9106-argon2id.txt"));
        let r = &records[0];
        let ad = argon2::AssociatedData::new(r.get("ad")).unwrap();
        let params = argon2::ParamsBuilder::new()
            .m_cost(32)
            .t_cost(3)
            .p_cost(4)
            .output_len(32)
            .data(ad)
            .build()
            .unwrap();
        let argon =
            Argon2::new_with_secret(r.get("secret"), Algorithm::Argon2id, Version::V0x13, params)
                .unwrap();
        let mut out = [0u8; 32];
        let mut blocks = vec![Block::new(); 32];
        argon
            .hash_password_into_with_memory(
                r.get("password"),
                r.get("salt"),
                &mut out,
                &mut blocks[..],
            )
            .unwrap();
        assert_eq!(out, r.get("tag"));
    }

    /// The one full-profile (256 MiB) KDF test in this module; the vector's
    /// MK was computed independently with OpenSSL.
    #[test]
    fn password_kdf_v1_full_profile_matches_openssl() {
        let _guard = crate::memory::secrets_test_guard();
        let records = crate::kat::parse(include_str!("../tests/vectors/qv-dev-password-kdf.txt"));
        let r = &records[0];
        let password = MasterPassword::from_utf8(r.get("password")).unwrap();
        assert_eq!(password.normalized(), r.get("nfc"));
        let mk = derive_master_key(&password, &r.array("salt"), PasswordKdfProfile::V1).unwrap();
        assert_eq!(mk.bytes(), r.get("mk"));
    }

    #[test]
    fn password_kek_commit_and_wrap_key_are_separated() {
        let _guard = crate::memory::secrets_test_guard();
        let mk = MasterKey::from_bytes([0x33; 32]);
        let kek = derive_kek(&mk, VAULT, PasswordKdfProfile::V1).unwrap();
        let wrap = wrap_key(&kek).unwrap();
        let commit = kek_commit(&kek, VAULT, GEN, SLOT).unwrap();
        let values = [
            mk.bytes(),
            kek.bytes(),
            *wrap.expose_secret(),
            *commit.as_bytes(),
        ];
        for i in 0..values.len() {
            for j in i + 1..values.len() {
                assert_ne!(values[i], values[j], "{i} == {j}");
            }
        }
        verify_kek_commit(&kek, VAULT, GEN, SLOT, &commit).unwrap();
        // The commitment binds vault, generation and slot.
        for (v, g, s) in [
            (VaultId([0x12; 16]), GEN, SLOT),
            (VAULT, KeyGeneration(2), SLOT),
            (VAULT, GEN, SlotId([0x23; 16])),
        ] {
            assert_ne!(
                kek_commit(&kek, v, g, s).unwrap().as_bytes(),
                commit.as_bytes()
            );
            assert_eq!(
                verify_kek_commit(&kek, v, g, s, &commit),
                Err(CryptoError::Integrity)
            );
        }
        // KEK binds the vault and the KDF profile ID.
        let other_vault = derive_kek(&mk, VaultId([0x12; 16]), PasswordKdfProfile::V1).unwrap();
        let other_profile = derive_kek_raw(&mk, VAULT, 2).unwrap();
        assert_ne!(other_vault.bytes(), kek.bytes());
        assert_ne!(other_profile.bytes(), kek.bytes());
    }
}
