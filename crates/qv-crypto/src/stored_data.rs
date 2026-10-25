// SPDX-License-Identifier: AGPL-3.0-or-later

//! stored-data/1: XChaCha20-Poly1305 with Padmé framing (spec 0002 §1.2,
//! 0004 §3.2).
//!
//! The encrypted plaintext is `u32_be(L) ‖ plaintext ‖ zeros`, padded to
//! `P = padme(4 + L)` bytes, so ciphertext lengths reveal only a rounded size.
//! The ciphertext is `P + 16` bytes (tag appended). On open, after the tag
//! verifies, the framing must be exactly canonical: `4 + L ≤ P`,
//! `padme(4 + L) == P` and every padding byte zero. Anything else is an
//! integrity failure.
//!
//! The caller passes its size budget (`max_ciphertext`, e.g. 1 MiB for a
//! padded record, 0004 §4.1). It is checked before anything is allocated or
//! decrypted.

use crate::error::CryptoError;
use crate::keys::AeadKey;
use crate::memory::SecretBytes;
use crate::primitives::{NONCE_LEN, TAG_LEN, xchacha_open_in_place, xchacha_seal_in_place};
use crate::profile::StoredDataProfile;
use crate::rng::random_array;

/// Bytes of the length prefix inside the framing.
const FRAME_HEADER: usize = 4;

/// A sealed object: its nonce and its ciphertext (tag included).
pub struct Sealed {
    /// The random 24-byte nonce (0002 §7.1).
    pub nonce: [u8; NONCE_LEN],
    /// `padme(4 + L) + 16` bytes.
    pub ciphertext: Vec<u8>,
}

/// Padmé (Nikitin et al., PURBs, 2019): rounds `n` up so that only its top
/// `⌊log2 ⌊log2 n⌋⌋ + 1` bits are significant. `None` on overflow.
pub(crate) fn padme(n: usize) -> Option<usize> {
    if n < 2 {
        return Some(n);
    }
    let e = usize::BITS - 1 - n.leading_zeros(); // ⌊log2 n⌋ ≥ 1
    let s = u32::BITS - e.leading_zeros(); // ⌊log2 e⌋ + 1, ≤ e
    let mask = (1usize << (e - s)) - 1;
    n.checked_add(mask).map(|v| v & !mask)
}

/// The ciphertext length for a plaintext of `plaintext_len` bytes, or `None`
/// if it cannot be framed (longer than `u32::MAX` or overflowing).
pub fn sealed_len(plaintext_len: usize) -> Option<usize> {
    u32::try_from(plaintext_len).ok()?;
    padme(plaintext_len.checked_add(FRAME_HEADER)?)?.checked_add(TAG_LEN)
}

/// Encrypts `plaintext` under a fresh random nonce.
///
/// Fails with [`CryptoError::LimitExceeded`] if the ciphertext would exceed
/// `max_ciphertext`, and with [`CryptoError::Rng`] if no nonce can be drawn.
pub fn seal(
    key: &impl AeadKey,
    profile: StoredDataProfile,
    aad: &[u8],
    plaintext: &[u8],
    max_ciphertext: usize,
) -> Result<Sealed, CryptoError> {
    match profile {
        StoredDataProfile::V1 => {}
    }
    let total = sealed_len(plaintext.len()).ok_or(CryptoError::LimitExceeded)?;
    if total > max_ciphertext {
        return Err(CryptoError::LimitExceeded);
    }
    let nonce = random_array::<NONCE_LEN>()?;
    seal_framed(key.aead_key(), nonce, aad, plaintext, total)
}

/// Frames and encrypts with a given nonce; `total` is `sealed_len(L)`.
fn seal_framed(
    key: &[u8; 32],
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
    total: usize,
) -> Result<Sealed, CryptoError> {
    let len = u32::try_from(plaintext.len()).map_err(|_| CryptoError::LimitExceeded)?;
    let padded = total.checked_sub(TAG_LEN).ok_or(CryptoError::Internal)?;
    let end = plaintext
        .len()
        .checked_add(FRAME_HEADER)
        .ok_or(CryptoError::Internal)?;
    let mut buf = SecretBytes::zeroed(padded);
    let b = buf.expose_secret_mut();
    b.get_mut(..FRAME_HEADER)
        .ok_or(CryptoError::Internal)?
        .copy_from_slice(&len.to_be_bytes());
    b.get_mut(FRAME_HEADER..end)
        .ok_or(CryptoError::Internal)?
        .copy_from_slice(plaintext);
    let tag = xchacha_seal_in_place(key, &nonce, aad, b)?;
    let mut ciphertext = Vec::with_capacity(total);
    ciphertext.extend_from_slice(buf.expose_secret());
    ciphertext.extend_from_slice(&tag);
    Ok(Sealed { nonce, ciphertext })
}

/// Decrypts and unframes `ciphertext` into a fresh locked buffer.
///
/// Fails with [`CryptoError::LimitExceeded`] if `ciphertext` exceeds
/// `max_ciphertext` (before anything is decrypted), and with
/// [`CryptoError::Integrity`] on any authentication or framing failure.
pub fn open(
    key: &impl AeadKey,
    profile: StoredDataProfile,
    aad: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    max_ciphertext: usize,
) -> Result<SecretBytes, CryptoError> {
    match profile {
        StoredDataProfile::V1 => {}
    }
    if ciphertext.len() > max_ciphertext {
        return Err(CryptoError::LimitExceeded);
    }
    let body_len = ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .filter(|&n| n >= FRAME_HEADER)
        .ok_or(CryptoError::Integrity)?;
    let (body, tag) = ciphertext.split_at(body_len);
    let tag: &[u8; TAG_LEN] = tag.try_into().map_err(|_| CryptoError::Integrity)?;
    let mut buf = SecretBytes::zeroed(body_len);
    buf.expose_secret_mut().copy_from_slice(body);
    xchacha_open_in_place(key.aead_key(), nonce, aad, buf.expose_secret_mut(), tag)?;
    unframe(buf.expose_secret())
}

/// Validates canonical framing (already authenticated) and copies out `L`
/// bytes. The padded buffer is the caller's and is wiped when it drops.
fn unframe(framed: &[u8]) -> Result<SecretBytes, CryptoError> {
    let header: [u8; FRAME_HEADER] = framed
        .get(..FRAME_HEADER)
        .and_then(|h| h.try_into().ok())
        .ok_or(CryptoError::Integrity)?;
    let len = usize::try_from(u32::from_be_bytes(header)).map_err(|_| CryptoError::Integrity)?;
    let end = len
        .checked_add(FRAME_HEADER)
        .filter(|&end| end <= framed.len() && padme(end) == Some(framed.len()))
        .ok_or(CryptoError::Integrity)?;
    let padding = framed.get(end..).ok_or(CryptoError::Integrity)?;
    if padding.iter().fold(0u8, |acc, &b| acc | b) != 0 {
        return Err(CryptoError::Integrity);
    }
    let plaintext = framed
        .get(FRAME_HEADER..end)
        .ok_or(CryptoError::Integrity)?;
    SecretBytes::try_init(len, |out| {
        out.copy_from_slice(plaintext);
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn seal_with_nonce(
    key: &impl AeadKey,
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Sealed {
    let total = sealed_len(plaintext.len()).unwrap();
    seal_framed(key.aead_key(), nonce, aad, plaintext, total).unwrap()
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::keys::sealed::AeadKeyBytes;
    use crate::keys::test_key::TestKey;

    const LIMIT: usize = 1 << 20;
    /// Near 1 MiB, Padmé rounds to 16 KiB steps, so the largest plaintext
    /// whose ciphertext fits 1 MiB is P = 1 MiB − 16 KiB, L = P − 4.
    const MAX_UNDER_LIMIT: usize = LIMIT - (16 << 10) - 4;

    /// Encrypts an arbitrary (possibly malformed) framed buffer.
    fn seal_raw(key: &TestKey, nonce: [u8; 24], aad: &[u8], framed: &[u8]) -> Vec<u8> {
        let mut buf = framed.to_vec();
        let tag = xchacha_seal_in_place(key.aead_key(), &nonce, aad, &mut buf).unwrap();
        buf.extend_from_slice(&tag);
        buf
    }

    fn frame(len_field: u32, payload: &[u8], total: usize) -> Vec<u8> {
        let mut v = len_field.to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v.resize(total, 0);
        v
    }

    #[test]
    fn stored_data_padme_values() {
        let _guard = crate::memory::secrets_test_guard();
        for (n, p) in [
            (4, 4),
            (8, 8),
            (9, 10),
            (100, 104),
            (1000, 1024),
            (1025, 1088),
        ] {
            assert_eq!(padme(n), Some(p), "padme({n})");
        }
        assert_eq!(padme(usize::MAX), None);
        assert_eq!(sealed_len(0), Some(4 + 16));
        assert_eq!(sealed_len(1), Some(5 + 16)); // padme(5) = 5: small sizes stay exact
        assert_eq!(sealed_len(u32::MAX as usize + 1), None);
    }

    proptest! {
        #[test]
        fn stored_data_padme_properties(n in 4usize..(1 << 40)) {
            let p = padme(n).unwrap();
            prop_assert!(p >= n);
            prop_assert_eq!(padme(p), Some(p));
            prop_assert!(padme(n + 1).unwrap() >= p);
            let e = usize::BITS - 1 - n.leading_zeros();
            let s = u32::BITS - e.leading_zeros();
            // Overhead is below 2^(E - S) ≤ n / 2^S (≈ 12 % around 1 KiB).
            prop_assert!(p - n < n >> s);
        }

        #[test]
        fn stored_data_open_random_bytes_fails(
            ct in proptest::collection::vec(any::<u8>(), 0..200),
            nonce in any::<[u8; 24]>(),
        ) {
            let _guard = crate::memory::secrets_test_guard();
            prop_assert!(open(&TestKey([3; 32]), StoredDataProfile::V1, b"", &nonce, &ct, LIMIT).is_err());
        }
    }

    #[test]
    fn stored_data_round_trip() {
        let _guard = crate::memory::secrets_test_guard();
        let key = TestKey([9; 32]);
        for len in [0usize, 1, 59, 60, 1000, MAX_UNDER_LIMIT] {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let s = seal(&key, StoredDataProfile::V1, b"aad", &pt, LIMIT).unwrap();
            assert_eq!(Some(s.ciphertext.len()), sealed_len(len));
            let out = open(
                &key,
                StoredDataProfile::V1,
                b"aad",
                &s.nonce,
                &s.ciphertext,
                LIMIT,
            )
            .unwrap();
            assert_eq!(out.expose_secret(), pt.as_slice());
        }
    }

    #[test]
    fn stored_data_one_mib_budget_boundary() {
        let _guard = crate::memory::secrets_test_guard();
        assert!(sealed_len(MAX_UNDER_LIMIT).unwrap() <= LIMIT);
        assert!(sealed_len(MAX_UNDER_LIMIT + 1).unwrap() > LIMIT);
        let key = TestKey([9; 32]);
        let pt = vec![0u8; MAX_UNDER_LIMIT + 1];
        assert_eq!(
            seal(&key, StoredDataProfile::V1, b"", &pt, LIMIT).map(|_| ()),
            Err(CryptoError::LimitExceeded)
        );
    }

    #[test]
    fn stored_data_nonces_are_fresh() {
        let _guard = crate::memory::secrets_test_guard();
        let key = TestKey([9; 32]);
        let a = seal(&key, StoredDataProfile::V1, b"", b"x", LIMIT).unwrap();
        let b = seal(&key, StoredDataProfile::V1, b"", b"x", LIMIT).unwrap();
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn stored_data_rejects_wrong_key_aad_nonce_and_tampering() {
        let _guard = crate::memory::secrets_test_guard();
        let key = TestKey([1; 32]);
        let s = seal_with_nonce(&key, [5; 24], b"aad", b"hello world");
        let open_with = |k: &TestKey, aad: &[u8], nonce: &[u8; 24], ct: &[u8]| {
            open(k, StoredDataProfile::V1, aad, nonce, ct, LIMIT).map(|_| ())
        };
        assert_eq!(open_with(&key, b"aad", &s.nonce, &s.ciphertext), Ok(()));
        assert_eq!(
            open_with(&TestKey([2; 32]), b"aad", &s.nonce, &s.ciphertext),
            Err(CryptoError::Integrity)
        );
        assert_eq!(
            open_with(&key, b"aae", &s.nonce, &s.ciphertext),
            Err(CryptoError::Integrity)
        );
        assert_eq!(
            open_with(&key, b"", &s.nonce, &s.ciphertext),
            Err(CryptoError::Integrity)
        );
        assert_eq!(
            open_with(&key, b"aad", &[6; 24], &s.ciphertext),
            Err(CryptoError::Integrity)
        );
        for i in 0..s.ciphertext.len() {
            for bit in [0x01, 0x80] {
                let mut ct = s.ciphertext.clone();
                ct[i] ^= bit;
                assert_eq!(
                    open_with(&key, b"aad", &s.nonce, &ct),
                    Err(CryptoError::Integrity),
                    "byte {i}"
                );
            }
        }
        // Truncation and extension.
        let short = &s.ciphertext[..s.ciphertext.len() - 1];
        assert_eq!(
            open_with(&key, b"aad", &s.nonce, short),
            Err(CryptoError::Integrity)
        );
        let mut long = s.ciphertext.clone();
        long.push(0);
        assert_eq!(
            open_with(&key, b"aad", &s.nonce, &long),
            Err(CryptoError::Integrity)
        );
    }

    #[test]
    fn stored_data_rejects_noncanonical_framing_under_a_valid_tag() {
        let _guard = crate::memory::secrets_test_guard();
        let key = TestKey([4; 32]);
        let nonce = [8; 24];
        let try_open = |framed: &[u8]| {
            let ct = seal_raw(&key, nonce, b"", framed);
            open(&key, StoredDataProfile::V1, b"", &nonce, &ct, LIMIT).map(|_| ())
        };
        // The canonical frame for "hello" (L = 5, P = padme(9) = 10) opens.
        assert_eq!(try_open(&frame(5, b"hello", 10)), Ok(()));
        // L larger than the buffer allows.
        assert_eq!(
            try_open(&frame(7, b"hello", 10)),
            Err(CryptoError::Integrity)
        );
        assert_eq!(
            try_open(&frame(u32::MAX, b"hello", 10)),
            Err(CryptoError::Integrity)
        );
        // Non-canonical P: an extra padding block (12 instead of 10).
        assert_eq!(
            try_open(&frame(5, b"hello", 12)),
            Err(CryptoError::Integrity)
        );
        // L too small for P (L = 3 gives padme(7) = 7, not 10).
        assert_eq!(
            try_open(&frame(3, b"hello", 10)),
            Err(CryptoError::Integrity)
        );
        // Non-zero padding byte.
        let mut f = frame(5, b"hello", 10);
        f[9] = 1;
        assert_eq!(try_open(&f), Err(CryptoError::Integrity));
        // Empty plaintext: P = 4 exactly.
        assert_eq!(try_open(&frame(0, b"", 4)), Ok(()));
    }

    #[test]
    fn stored_data_limits_are_checked_before_decryption() {
        let _guard = crate::memory::secrets_test_guard();
        let key = TestKey([4; 32]);
        // Tag-invalid input: if it were decrypted, the result would be Integrity.
        let junk = vec![0u8; 64];
        assert_eq!(
            open(&key, StoredDataProfile::V1, b"", &[0; 24], &junk, 63).map(|_| ()),
            Err(CryptoError::LimitExceeded)
        );
        for n in [0usize, 1, 19] {
            assert_eq!(
                open(
                    &key,
                    StoredDataProfile::V1,
                    b"",
                    &[0; 24],
                    &junk[..n],
                    LIMIT
                )
                .map(|_| ()),
                Err(CryptoError::Integrity)
            );
        }
        // seal refuses to produce an over-budget ciphertext.
        let pt = vec![0u8; 100];
        let need = sealed_len(100).unwrap();
        assert_eq!(
            seal(&key, StoredDataProfile::V1, b"", &pt, need - 1).map(|_| ()),
            Err(CryptoError::LimitExceeded)
        );
        assert!(seal(&key, StoredDataProfile::V1, b"", &pt, need).is_ok());
    }
}
