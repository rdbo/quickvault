// SPDX-License-Identifier: AGPL-3.0-or-later

//! Thin wrappers over the pinned RustCrypto primitives (spec 0002 §1.2, §7.3).
//!
//! Nothing here implements a primitive. The wrappers fix the parameters the
//! profiles name, take keys by reference, and wipe the intermediates that the
//! crates hand back to us. Intermediates the crates keep internally are
//! zeroized through their `zeroize` features, with one known gap: `hmac`
//! builds its padded-key block on the stack and does not wipe it.

use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::profile::ObjectHashProfile;

/// XChaCha20-Poly1305 tag length.
pub(crate) const TAG_LEN: usize = 16;
/// XChaCha20-Poly1305 nonce length.
pub(crate) const NONCE_LEN: usize = 24;

/// HKDF-SHA-512 with a 32-byte output (derivation/1).
pub(crate) fn hkdf_sha512(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8; 32],
) -> Result<(), CryptoError> {
    hkdf_sha512_into(ikm, salt, info, out)
}

/// HKDF-SHA-512 into `out` of any valid length (KATs use other lengths).
///
/// Runs extract and expand separately so the pseudorandom key that
/// `Hkdf::new` would drop unwiped is zeroized here.
pub(crate) fn hkdf_sha512_into(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    let (mut prk, hkdf) = Hkdf::<Sha512>::extract(salt, ikm);
    prk.as_mut_slice().zeroize();
    hkdf.expand(info, out).map_err(|_| CryptoError::Internal)
}

/// A MAC/1 tag: the first 32 bytes of HMAC-SHA-512.
///
/// A public value. It has no `PartialEq`, so tags are only ever compared
/// through the constant-time [`crate::verify_mac`] path.
pub struct MacTag([u8; 32]);

impl MacTag {
    /// Wraps stored tag bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The tag bytes, for storage.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for MacTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MacTag(..)")
    }
}

fn hmac_sha512(key: &[u8; 32], msg: &[u8]) -> Result<Hmac<Sha512>, CryptoError> {
    // HMAC accepts keys of any length, so this does not fail in practice.
    let mut mac =
        <Hmac<Sha512> as KeyInit>::new_from_slice(key).map_err(|_| CryptoError::Internal)?;
    mac.update(msg);
    Ok(mac)
}

/// MAC/1: HMAC-SHA-512 truncated to its first 32 bytes.
pub(crate) fn mac1(key: &[u8; 32], msg: &[u8]) -> Result<MacTag, CryptoError> {
    let mut full = hmac_sha512(key, msg)?.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&full[..32]);
    full.as_mut_slice().zeroize();
    Ok(MacTag(tag))
}

/// Verifies a MAC/1 tag in constant time (`verify_truncated_left`).
pub(crate) fn mac1_verify(key: &[u8; 32], msg: &[u8], tag: &MacTag) -> Result<(), CryptoError> {
    hmac_sha512(key, msg)?
        .verify_truncated_left(&tag.0)
        .map_err(|_| CryptoError::Integrity)
}

/// Encrypts `buf` in place with XChaCha20-Poly1305 and returns the tag.
pub(crate) fn xchacha_seal_in_place(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; TAG_LEN], CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_inout_detached(nonce.into(), aad, buf.into())
        .map_err(|_| CryptoError::LimitExceeded)?;
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Decrypts `buf` in place. On failure `buf` is wiped and `Integrity` returned.
pub(crate) fn xchacha_open_in_place(
    key: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; TAG_LEN],
) -> Result<(), CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    match cipher.decrypt_inout_detached(nonce.into(), aad, buf.into(), tag.into()) {
        Ok(()) => Ok(()),
        Err(_) => {
            buf.zeroize();
            Err(CryptoError::Integrity)
        }
    }
}

/// An object-hash/1 digest (SHA-256) of public ciphertext.
///
/// Object hashes are computed over ciphertext, not secrets, so ordinary
/// equality is fine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ObjectHash(pub [u8; 32]);

/// Hashes `data` with the given object-hash profile.
pub fn object_hash(profile: ObjectHashProfile, data: &[u8]) -> ObjectHash {
    let mut h = ObjectHasher::new(profile);
    h.update(data);
    h.finalize()
}

/// Streaming object hash, so large objects are never loaded whole (0004 §4.1).
pub struct ObjectHasher {
    inner: Sha256,
}

impl ObjectHasher {
    /// Starts a hash under `profile`.
    pub fn new(profile: ObjectHashProfile) -> Self {
        match profile {
            ObjectHashProfile::V1 => Self {
                inner: Sha256::new(),
            },
        }
    }

    /// Feeds more data.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finishes the hash.
    pub fn finalize(self) -> ObjectHash {
        ObjectHash(self.inner.finalize().into())
    }
}

/// Incremental SHA-256 of confidential attachment content; state zeroizes on drop.
/// No cloning or value-bearing formatting. Dependency scratch copies remain best effort.
pub struct ContentHasher {
    inner: Sha256,
}
impl core::fmt::Debug for ContentHasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ContentHasher(<redacted>)")
    }
}
impl Default for ContentHasher {
    fn default() -> Self {
        Self::new()
    }
}
impl ContentHasher {
    /// Starts an empty content hash.
    pub fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }
    /// Hashes the next plaintext fragment.
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    /// Finishes into protected memory and wipes the temporary digest.
    pub fn finalize(self) -> crate::SecretArray<32> {
        let mut digest = self.inner.finalize();
        let mut out = crate::SecretArray::zeroed();
        out.expose_secret_mut().copy_from_slice(&digest);
        digest.as_mut_slice().zeroize();
        out
    }
}

/// Plain SHA-256 into `out`, for checks that are not object hashes (word-list
/// integrity, the BIP-39 checksum). `out` may be a locked secret buffer.
pub(crate) fn sha256(data: &[u8], out: &mut [u8; 32]) {
    let mut h = Sha256::new();
    h.update(data);
    let mut digest = h.finalize();
    out.copy_from_slice(&digest);
    digest.as_mut_slice().zeroize();
}

#[cfg(test)]
pub(crate) fn hmac_sha512_full(key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha512> as KeyInit>::new_from_slice(key).unwrap();
    mac.update(msg);
    mac.finalize().into_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attachment_content_hash_fragmentation() {
        let _guard = crate::memory::secrets_test_guard();
        fn assert_wipes<T: zeroize::ZeroizeOnDrop>() {}
        assert_wipes::<Sha256>();
        let mut hash = ContentHasher::new();
        hash.update(b"a");
        hash.update(b"bc");
        assert_eq!(
            hash.finalize().expose_secret(),
            &[
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
    }
    #[test]
    fn primitives_mac1_verify_rejects_every_byte_change() {
        let key = [7u8; 32];
        let tag = mac1(&key, b"message").unwrap();
        mac1_verify(&key, b"message", &tag).unwrap();
        for i in 0..32 {
            let mut bad = *tag.as_bytes();
            bad[i] ^= 0x01;
            assert_eq!(
                mac1_verify(&key, b"message", &MacTag::from_bytes(bad)),
                Err(CryptoError::Integrity),
                "byte {i}"
            );
        }
        assert_eq!(
            mac1_verify(&key, b"messagf", &tag),
            Err(CryptoError::Integrity)
        );
        assert_eq!(
            mac1_verify(&[8u8; 32], b"message", &tag),
            Err(CryptoError::Integrity)
        );
    }

    #[test]
    fn primitives_mac1_is_truncated_hmac_sha512() {
        let key = [0x42u8; 32];
        let full = hmac_sha512_full(&key, b"abc");
        assert_eq!(full.len(), 64);
        assert_eq!(mac1(&key, b"abc").unwrap().as_bytes()[..], full[..32]);
        assert_eq!(format!("{:?}", mac1(&key, b"abc").unwrap()), "MacTag(..)");
    }

    #[test]
    fn primitives_object_hasher_streams() {
        let data: Vec<u8> = (0..200u8).collect();
        let whole = object_hash(ObjectHashProfile::V1, &data);
        for split in 0..=data.len() {
            let mut h = ObjectHasher::new(ObjectHashProfile::V1);
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), whole, "split {split}");
        }
    }

    #[test]
    fn primitives_xchacha_open_wipes_on_failure() {
        let key = [1u8; 32];
        let nonce = [2u8; 24];
        let mut buf = *b"secret plaintext";
        let tag = xchacha_seal_in_place(&key, &nonce, b"aad", &mut buf).unwrap();
        let mut bad = buf;
        assert_eq!(
            xchacha_open_in_place(&key, &nonce, b"aaD", &mut bad, &tag),
            Err(CryptoError::Integrity)
        );
        assert_eq!(bad, [0u8; 16]);
        xchacha_open_in_place(&key, &nonce, b"aad", &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"secret plaintext");
    }
}
