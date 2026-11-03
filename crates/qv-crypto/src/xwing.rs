// SPDX-License-Identifier: AGPL-3.0-or-later

//! X-Wing hybrid KEM (spec 0002 §6.1), pinned to
//! draft-connolly-cfrg-xwing-kem-11.
//!
//! The KEM is `libcrux-kem`'s `XWingKemDraft06`. Draft-11 changed nothing
//! normative since draft-06 (its change log is editorial), and the two drafts'
//! test vectors are byte-identical; `tests/vectors/xwing-draft-11.txt` checks
//! this wrapper against draft-11 directly. QuickVault composes nothing: the
//! combiner, key expansion and the ML-KEM encapsulation-key check (FIPS 203
//! §7.2, required by the draft) all run inside libcrux.
//!
//! Randomness comes only from [`crate::fill_random`] (fail-closed OS CSPRNG,
//! 0002 §7.1), passed to libcrux's derandomized entry points, so production
//! and the known-answer tests run the same code.
//!
//! **Erasure limits** (0008 §1): the decapsulation seed and shared secret
//! live in locked [`SecretArray`]s, and the copies this module hands to or
//! gets from libcrux are wiped after use. libcrux itself does not zeroize its
//! intermediates (the expanded ML-KEM decapsulation key, the X25519 scalar,
//! the combiner input and its shared-secret struct); those stack and heap
//! copies are a documented residual.

use libcrux_kem::{
    Algorithm, Ct, PrivateKey, PublicKey, XWingKemDraft06PrivateKey, key_gen_derand,
};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::memory::SecretArray;

/// Encapsulation key length: ML-KEM-768 (1184) plus X25519 (32).
pub const XWING_ENCAPS_KEY_LEN: usize = 1216;
/// Ciphertext length: ML-KEM-768 (1088) plus X25519 (32).
pub const XWING_CIPHERTEXT_LEN: usize = 1120;
const ALG: Algorithm = Algorithm::XWingKemDraft06;

/// An X-Wing decapsulation key: the draft's 32-byte seed, in locked memory.
pub struct XWingDecapsKey(SecretArray<32>);

/// A validated X-Wing encapsulation key (exact length and the ML-KEM check).
#[derive(Clone, PartialEq, Eq)]
pub struct XWingEncapsKey(Box<[u8; XWING_ENCAPS_KEY_LEN]>);

/// An X-Wing ciphertext of exact length. Any bytes are accepted: ML-KEM
/// rejects implicitly, so a wrong ciphertext yields an unrelated secret that
/// the protocol's key confirmation then refuses.
#[derive(Clone, PartialEq, Eq)]
pub struct XWingCiphertext(Box<[u8; XWING_CIPHERTEXT_LEN]>);

/// The 32-byte X-Wing shared secret, in locked memory.
pub struct XWingSharedSecret(SecretArray<32>);

/// Builds the libcrux private key for one call; the caller wipes it.
fn private_key(seed: &[u8; 32]) -> PrivateKey {
    PrivateKey::XWingKemDraft06(XWingKemDraft06PrivateKey { seed: *seed })
}

fn wipe(key: &mut PrivateKey) {
    if let PrivateKey::XWingKemDraft06(k) = key {
        k.seed.zeroize();
    }
}

fn encaps_key_bytes(key: &PublicKey) -> Result<XWingEncapsKey, CryptoError> {
    let bytes = key.encode();
    let bytes: [u8; XWING_ENCAPS_KEY_LEN] = bytes.try_into().map_err(|_| CryptoError::Internal)?;
    Ok(XWingEncapsKey(Box::new(bytes)))
}

fn shared_secret(ss: &libcrux_kem::Ss) -> Result<XWingSharedSecret, CryptoError> {
    let mut bytes = ss.encode();
    let out = SecretArray::try_init(|out: &mut [u8; 32]| {
        if bytes.len() != 32 {
            return Err(CryptoError::Internal);
        }
        out.copy_from_slice(&bytes);
        Ok(())
    });
    bytes.zeroize();
    out.map(XWingSharedSecret)
}

impl XWingDecapsKey {
    /// A fresh key pair from 32 bytes of OS randomness.
    pub fn generate() -> Result<(Self, XWingEncapsKey), CryptoError> {
        let seed = SecretArray::<32>::random()?;
        Self::from_seed(seed)
    }

    fn from_seed(seed: SecretArray<32>) -> Result<(Self, XWingEncapsKey), CryptoError> {
        let (mut sk, pk) =
            key_gen_derand(ALG, seed.expose_secret()).map_err(|_| CryptoError::Integrity)?;
        wipe(&mut sk);
        Ok((Self(seed), encaps_key_bytes(&pk)?))
    }

    /// The key pair the draft derives from `seed`. Known-answer and
    /// interoperability vectors only: the `test-vectors` feature is never
    /// enabled in normal builds.
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn from_test_seed(seed: &[u8; 32]) -> Result<(Self, XWingEncapsKey), CryptoError> {
        let seed = SecretArray::try_init(|out| {
            out.copy_from_slice(seed);
            Ok::<(), CryptoError>(())
        })?;
        Self::from_seed(seed)
    }

    /// Recovers the shared secret from `ct`. A low-order X25519 half (an
    /// all-zero X25519 output) fails with [`CryptoError::Integrity`].
    pub fn decapsulate(&self, ct: &XWingCiphertext) -> Result<XWingSharedSecret, CryptoError> {
        let ct = Ct::decode(ALG, &ct.0[..]).map_err(|_| CryptoError::Integrity)?;
        let mut sk = private_key(self.0.expose_secret());
        let result = ct.decapsulate(&sk);
        wipe(&mut sk);
        shared_secret(&result.map_err(|_| CryptoError::Integrity)?)
    }
}

impl XWingEncapsKey {
    /// Accepts exactly [`XWING_ENCAPS_KEY_LEN`] bytes whose ML-KEM half passes
    /// the FIPS 203 §7.2 encapsulation-key check.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let exact: [u8; XWING_ENCAPS_KEY_LEN] =
            bytes.try_into().map_err(|_| CryptoError::LimitExceeded)?;
        PublicKey::decode(ALG, &exact).map_err(|_| CryptoError::Integrity)?;
        Ok(Self(Box::new(exact)))
    }

    /// The encoded key.
    pub fn as_bytes(&self) -> &[u8; XWING_ENCAPS_KEY_LEN] {
        &self.0
    }

    /// Encapsulates a fresh shared secret to this key.
    pub fn encapsulate(&self) -> Result<(XWingSharedSecret, XWingCiphertext), CryptoError> {
        let eseed = SecretArray::<64>::random()?;
        self.encapsulate_with(&eseed)
    }

    /// Draft `EncapsulateDerand`. Known-answer and interoperability vectors
    /// only (the `test-vectors` feature).
    #[cfg(any(test, feature = "test-vectors"))]
    pub fn encapsulate_derand(
        &self,
        eseed: &[u8; 64],
    ) -> Result<(XWingSharedSecret, XWingCiphertext), CryptoError> {
        let eseed = SecretArray::try_init(|out| {
            out.copy_from_slice(eseed);
            Ok::<(), CryptoError>(())
        })?;
        self.encapsulate_with(&eseed)
    }

    fn encapsulate_with(
        &self,
        eseed: &SecretArray<64>,
    ) -> Result<(XWingSharedSecret, XWingCiphertext), CryptoError> {
        let pk = PublicKey::decode(ALG, &self.0[..]).map_err(|_| CryptoError::Integrity)?;
        let (ss, ct) = pk
            .encapsulate_derand(eseed.expose_secret())
            .map_err(|_| CryptoError::Integrity)?;
        let ct: [u8; XWING_CIPHERTEXT_LEN] =
            ct.encode().try_into().map_err(|_| CryptoError::Internal)?;
        Ok((shared_secret(&ss)?, XWingCiphertext(Box::new(ct))))
    }
}

impl XWingCiphertext {
    /// Accepts exactly [`XWING_CIPHERTEXT_LEN`] bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let exact: [u8; XWING_CIPHERTEXT_LEN] =
            bytes.try_into().map_err(|_| CryptoError::LimitExceeded)?;
        Ok(Self(Box::new(exact)))
    }

    /// The encoded ciphertext.
    pub fn as_bytes(&self) -> &[u8; XWING_CIPHERTEXT_LEN] {
        &self.0
    }
}

impl XWingSharedSecret {
    /// Borrows the shared secret.
    pub fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl core::fmt::Debug for XWingDecapsKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingDecapsKey(<redacted>)")
    }
}
impl core::fmt::Debug for XWingSharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingSharedSecret(<redacted>)")
    }
}
impl core::fmt::Debug for XWingEncapsKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingEncapsKey(1216 bytes)")
    }
}
impl core::fmt::Debug for XWingCiphertext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("XWingCiphertext(1120 bytes)")
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;

    /// A shared secret with chosen bytes, for key-schedule tests.
    pub(crate) fn shared_secret(bytes: [u8; 32]) -> XWingSharedSecret {
        XWingSharedSecret(
            SecretArray::try_init(|out| {
                *out = bytes;
                Ok::<(), CryptoError>(())
            })
            .unwrap_or_else(|_| unreachable!()),
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn pair(seed: u8) -> (XWingDecapsKey, XWingEncapsKey) {
        XWingDecapsKey::from_test_seed(&[seed; 32]).unwrap()
    }

    // 0012 §1: Unpinned crypto
    #[test]
    fn xwing_missing_or_wrong_length_halves_are_refused() {
        let (_, ek) = pair(1);
        let bytes = ek.as_bytes();
        // Only the ML-KEM half, only the X25519 half, off-by-one lengths.
        for len in [0, 32, 1184, 1215, 1217] {
            let mut v = bytes.to_vec();
            v.resize(len, 0);
            assert_eq!(
                XWingEncapsKey::from_bytes(&v),
                Err(CryptoError::LimitExceeded),
                "{len}"
            );
        }
        for len in [0, 32, 1088, 1119, 1121] {
            assert_eq!(
                XWingCiphertext::from_bytes(&vec![0; len]),
                Err(CryptoError::LimitExceeded),
                "{len}"
            );
        }
    }

    // 0012 §1: Unpinned crypto
    #[test]
    fn xwing_encaps_key_fails_the_ml_kem_check() {
        let (_, ek) = pair(2);
        let mut v = ek.as_bytes().to_vec();
        // The first 12-bit coefficient becomes 0xFFF >= q = 3329.
        v[0] = 0xff;
        v[1] |= 0x0f;
        assert_eq!(XWingEncapsKey::from_bytes(&v), Err(CryptoError::Integrity));
    }

    #[test]
    fn xwing_round_trip_and_implicit_rejection() {
        let (dk, ek) = XWingDecapsKey::generate().unwrap();
        let (ss, ct) = ek.encapsulate().unwrap();
        assert_eq!(
            dk.decapsulate(&ct).unwrap().expose_secret(),
            ss.expose_secret()
        );
        // Fresh randomness: a second encapsulation differs.
        let (ss2, ct2) = ek.encapsulate().unwrap();
        assert_ne!(ct, ct2);
        assert_ne!(ss.expose_secret(), ss2.expose_secret());
        // A flipped ML-KEM byte gives a different but deterministic secret.
        let mut bad = ct.as_bytes().to_vec();
        bad[0] ^= 1;
        let bad = XWingCiphertext::from_bytes(&bad).unwrap();
        let a = dk.decapsulate(&bad).unwrap();
        let b = dk.decapsulate(&bad).unwrap();
        assert_ne!(a.expose_secret(), ss.expose_secret());
        assert_eq!(a.expose_secret(), b.expose_secret());
        // Another key pair recovers an unrelated secret.
        let (other, _) = pair(3);
        assert_ne!(
            other.decapsulate(&ct).unwrap().expose_secret(),
            ss.expose_secret()
        );
    }

    #[test]
    fn xwing_low_order_x25519_half_fails_closed() {
        let (dk, ek) = pair(4);
        let (_, ct) = ek.encapsulate().unwrap();
        let mut v = ct.as_bytes().to_vec();
        v[1088..].fill(0);
        let ct = XWingCiphertext::from_bytes(&v).unwrap();
        assert!(matches!(dk.decapsulate(&ct), Err(CryptoError::Integrity)));
    }

    #[test]
    fn xwing_secrets_are_redacted() {
        let (dk, ek) = pair(5);
        let (ss, ct) = ek.encapsulate().unwrap();
        assert_eq!(format!("{dk:?}"), "XWingDecapsKey(<redacted>)");
        assert_eq!(format!("{ss:?}"), "XWingSharedSecret(<redacted>)");
        assert_eq!(format!("{ek:?}"), "XWingEncapsKey(1216 bytes)");
        assert_eq!(format!("{ct:?}"), "XWingCiphertext(1120 bytes)");
    }
}
