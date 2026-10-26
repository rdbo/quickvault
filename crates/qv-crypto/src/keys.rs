// SPDX-License-Identifier: AGPL-3.0-or-later

//! The key hierarchy below VK (spec 0002 §3.3, §3.6).
//!
//! | Key | HKDF-SHA-512 IKM | Salt | Info (canonical CBOR array) |
//! |-----|------------------|------|-----------------------------|
//! | Purpose key | VK | vault ID | `["qv/purpose/v1", label, key_generation, derivation_profile]` |
//! | Record key | record purpose key | vault ID | `["qv/record-key/v1", record_id]` |
//! | Attachment key | attachment purpose key | vault ID | `["qv/attachment-key/v1", attachment_id]` |
//!
//! Each purpose is a type ([`purpose`]), so a key can be used only as its
//! purpose allows. A header-MAC key cannot encrypt:
//!
//! ```compile_fail,E0277
//! use qv_crypto::{purpose, DerivationProfile, KeyGeneration, StoredDataProfile, VaultId, VaultKey};
//! let vk = VaultKey::generate().unwrap();
//! let k = vk
//!     .purpose_key::<purpose::HeaderMac>(VaultId([0; 16]), KeyGeneration(1), DerivationProfile::V1)
//!     .unwrap();
//! let _ = qv_crypto::seal(&k, StoredDataProfile::V1, b"", b"x", 1 << 20);
//! ```
//!
//! ```
//! use qv_crypto::{purpose, DerivationProfile, KeyGeneration, StoredDataProfile, VaultId, VaultKey};
//! let vk = VaultKey::generate().unwrap();
//! let k = vk
//!     .purpose_key::<purpose::Manifest>(VaultId([0; 16]), KeyGeneration(1), DerivationProfile::V1)
//!     .unwrap();
//! let _ = qv_crypto::seal(&k, StoredDataProfile::V1, b"", b"x", 1 << 20).unwrap();
//! ```
//!
//! A manifest key does not derive record keys:
//!
//! ```compile_fail,E0599
//! use qv_crypto::{purpose, DerivationProfile, KeyGeneration, RecordId, VaultId, VaultKey};
//! let vk = VaultKey::generate().unwrap();
//! let k = vk
//!     .purpose_key::<purpose::Manifest>(VaultId([0; 16]), KeyGeneration(1), DerivationProfile::V1)
//!     .unwrap();
//! let _ = k.record_key(VaultId([0; 16]), RecordId([1; 16]));
//! ```
//!
//! ```
//! use qv_crypto::{purpose, DerivationProfile, KeyGeneration, RecordId, VaultId, VaultKey};
//! let vk = VaultKey::generate().unwrap();
//! let k = vk
//!     .purpose_key::<purpose::Record>(VaultId([0; 16]), KeyGeneration(1), DerivationProfile::V1)
//!     .unwrap();
//! let _ = k.record_key(VaultId([0; 16]), RecordId([1; 16])).unwrap();
//! ```
//!
//! Keys cannot be cloned:
//!
//! ```compile_fail,E0599
//! let vk = qv_crypto::VaultKey::generate().unwrap();
//! let _ = vk.clone();
//! ```
//!
//! ```compile_fail,E0599
//! use qv_crypto::{purpose, DerivationProfile, KeyGeneration, RecordId, VaultId, VaultKey};
//! let vk = VaultKey::generate().unwrap();
//! let k = vk
//!     .purpose_key::<purpose::Record>(VaultId([0; 16]), KeyGeneration(1), DerivationProfile::V1)
//!     .unwrap();
//! let _ = k.record_key(VaultId([0; 16]), RecordId([1; 16])).unwrap().clone();
//! ```
//!
//! ```
//! let vk = qv_crypto::VaultKey::generate().unwrap();
//! let moved = vk;
//! assert_eq!(format!("{moved:?}"), "VaultKey(<redacted>)");
//! ```
//!
//! MAC tags are compared only through [`verify_mac`]:
//!
//! ```compile_fail,E0369
//! let a = qv_crypto::MacTag::from_bytes([0; 32]);
//! let b = qv_crypto::MacTag::from_bytes([0; 32]);
//! let _ = a == b;
//! ```
//!
//! ```
//! let a = qv_crypto::MacTag::from_bytes([0; 32]);
//! let b = qv_crypto::MacTag::from_bytes([0; 32]);
//! assert_eq!(a.as_bytes(), b.as_bytes());
//! ```
//!
//! Other crates cannot read key bytes through the key-use traits, not even
//! through a generic bound:
//!
//! ```compile_fail
//! fn leak<K: qv_crypto::AeadKey>(k: &K) -> [u8; 32] {
//!     *k.aead_key()
//! }
//! ```
//!
//! ```compile_fail
//! fn leak<K: qv_crypto::MacKey>(k: &K) -> [u8; 32] {
//!     *k.mac_key()
//! }
//! ```
//!
//! ```
//! fn use_key<K: qv_crypto::AeadKey>(k: &K) -> Result<qv_crypto::Sealed, qv_crypto::CryptoError> {
//!     qv_crypto::seal(k, qv_crypto::StoredDataProfile::V1, b"", b"x", 1 << 20)
//! }
//! ```

use core::fmt;
use core::marker::PhantomData;

use qv_encoding::{Encoder, encode_array};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::ids::{AttachmentId, KeyGeneration, RecordId, VaultId};
use crate::memory::SecretArray;
use crate::primitives::{MacTag, hkdf_sha512, mac1, mac1_verify};
use crate::profile::{DerivationProfile, MacProfile};

pub(crate) mod sealed {
    /// Seals the key-use traits: only this crate's key types implement them.
    pub trait Sealed {}

    /// Seals [`super::KeyPurpose`].
    pub trait SealedPurpose {}

    /// Proof of crate-internal access. Other crates cannot name or build it,
    /// so they cannot call the byte accessors below, not even through a
    /// generic `K: AeadKey` or `K: MacKey` bound.
    pub struct Token(());

    /// The only way to obtain a [`Token`].
    pub(crate) const TOKEN: Token = Token(());

    /// Crate-internal access to an AEAD key's bytes.
    pub trait AeadKeyBytes: Sealed {
        fn aead_key(&self, _: Token) -> &[u8; 32];
    }

    /// Crate-internal access to a MAC key's bytes.
    pub trait MacKeyBytes: Sealed {
        fn mac_key(&self, _: Token) -> &[u8; 32];
    }
}

/// A key usable with stored-data encryption ([`crate::seal`], [`crate::open`]).
pub trait AeadKey: sealed::AeadKeyBytes {}

/// A key usable with MAC/1 ([`mac`], [`verify_mac`]).
pub trait MacKey: sealed::MacKeyBytes {}

/// A purpose label from spec 0002 §3.3. Implemented only by the markers in
/// [`purpose`].
pub trait KeyPurpose: sealed::SealedPurpose {
    /// The exact label in the purpose-key info array.
    const LABEL: &'static str;
}

/// Purpose markers (spec 0002 §3.3). Labels are never reused.
pub mod purpose {
    macro_rules! purposes {
        ($($(#[$doc:meta])* $name:ident = $label:literal;)+) => {$(
            $(#[$doc])*
            #[derive(Debug)]
            pub enum $name {}
            impl super::sealed::SealedPurpose for $name {}
            impl super::KeyPurpose for $name {
                const LABEL: &'static str = $label;
            }
        )+};
    }

    purposes! {
        /// Root for per-record keys.
        Record = "record";
        /// Root for per-attachment keys.
        Attachment = "attachment";
        /// Authenticates the local header and slots.
        HeaderMac = "header-mac";
        /// Encrypts portable manifests.
        Manifest = "manifest";
        /// Remote checkpoint MACs.
        StateCommit = "state-commit";
        /// Encrypts sync/outbox state and MACs the local head (uses come in
        /// later phases).
        LocalState = "local-state";
        /// Wraps local device signing bundles (uses come in later phases).
        DeviceStorage = "device-storage";
        /// Independent Ed25519 recovery-key seed (uses come in later phases).
        RecoveryEd25519 = "recovery-ed25519";
        /// Independent ML-DSA-65 recovery-key seed (uses come in later phases).
        RecoveryMlDsa65 = "recovery-mldsa65";
    }
}

/// Builds a canonical CBOR info/AAD array. Fixed shapes cannot fail; an
/// encoder error would be a bug and maps to [`CryptoError::Internal`].
pub(crate) fn cbor_array(f: impl FnOnce(&mut Encoder)) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    encode_array(|a| {
        f(a);
        Ok(())
    })
    .map_err(|_| CryptoError::Internal)
}

/// HKDF-SHA-512 straight into a new locked 32-byte secret.
pub(crate) fn derive_secret(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> Result<SecretArray<32>, CryptoError> {
    SecretArray::try_init(|out| hkdf_sha512(ikm, salt, info, out))
}

/// `["qv/purpose/v1", label, key_generation, derivation_profile]`.
pub(crate) fn purpose_info(
    label: &str,
    generation: KeyGeneration,
    profile_id: u16,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text("qv/purpose/v1");
        a.text(label);
        a.uint(generation.0.into());
        a.uint(profile_id.into());
    })
}

/// `[label, id]` for record and attachment keys.
pub(crate) fn data_key_info(label: &str, id: &[u8; 16]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    cbor_array(|a| {
        a.text(label);
        a.bytes(id);
    })
}

/// The vault key VK: 32 random bytes, the root of all data keys.
pub struct VaultKey(SecretArray<32>);

impl VaultKey {
    /// Generates a fresh VK from the OS CSPRNG (0002 §3.2). Fails closed.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self(SecretArray::random()?))
    }

    pub(crate) fn from_secret(secret: SecretArray<32>) -> Self {
        Self(secret)
    }

    pub(crate) fn expose_secret(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }

    /// Derives the purpose key `P` for `generation` (0002 §3.3).
    pub fn purpose_key<P: KeyPurpose>(
        &self,
        vault: VaultId,
        generation: KeyGeneration,
        profile: DerivationProfile,
    ) -> Result<PurposeKey<P>, CryptoError> {
        match profile {
            DerivationProfile::V1 => self.purpose_key_raw(vault, generation, profile.id()),
        }
    }

    /// Derivation with a raw profile ID in the info (tests use other IDs).
    fn purpose_key_raw<P: KeyPurpose>(
        &self,
        vault: VaultId,
        generation: KeyGeneration,
        profile_id: u16,
    ) -> Result<PurposeKey<P>, CryptoError> {
        let info = purpose_info(P::LABEL, generation, profile_id)?;
        Ok(PurposeKey {
            key: derive_secret(self.0.expose_secret(), Some(&vault.0), &info)?,
            _purpose: PhantomData,
        })
    }

    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(
            SecretArray::try_init(|b| {
                *b = bytes;
                Ok::<(), ()>(())
            })
            .unwrap(),
        )
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> [u8; 32] {
        *self.0.expose_secret()
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultKey(<redacted>)")
    }
}

/// A purpose key derived from VK. What it can do depends on `P`.
pub struct PurposeKey<P: KeyPurpose> {
    key: SecretArray<32>,
    _purpose: PhantomData<fn() -> P>,
}

impl<P: KeyPurpose> fmt::Debug for PurposeKey<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PurposeKey<{}>(<redacted>)", P::LABEL)
    }
}

impl<P: KeyPurpose> PurposeKey<P> {
    #[cfg(test)]
    pub(crate) fn bytes(&self) -> [u8; 32] {
        *self.key.expose_secret()
    }
}

/// A per-record or per-attachment data key (0002 §3.6).
pub struct DataKey(SecretArray<32>);

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

impl DataKey {
    fn derive(
        root: &SecretArray<32>,
        vault: VaultId,
        label: &str,
        id: &[u8; 16],
    ) -> Result<Self, CryptoError> {
        let info = data_key_info(label, id)?;
        Ok(Self(derive_secret(
            root.expose_secret(),
            Some(&vault.0),
            &info,
        )?))
    }

    #[cfg(test)]
    pub(crate) fn bytes(&self) -> [u8; 32] {
        *self.0.expose_secret()
    }
}

impl PurposeKey<purpose::Record> {
    /// Derives the key of one record (0002 §3.6).
    pub fn record_key(&self, vault: VaultId, record: RecordId) -> Result<DataKey, CryptoError> {
        DataKey::derive(&self.key, vault, "qv/record-key/v1", &record.0)
    }
}

impl PurposeKey<purpose::Attachment> {
    /// Derives the key of one attachment (0002 §3.6).
    pub fn attachment_key(
        &self,
        vault: VaultId,
        attachment: AttachmentId,
    ) -> Result<DataKey, CryptoError> {
        DataKey::derive(&self.key, vault, "qv/attachment-key/v1", &attachment.0)
    }
}

impl sealed::Sealed for DataKey {}
impl sealed::AeadKeyBytes for DataKey {
    fn aead_key(&self, _: sealed::Token) -> &[u8; 32] {
        self.0.expose_secret()
    }
}
impl AeadKey for DataKey {}

impl<P: KeyPurpose> sealed::Sealed for PurposeKey<P> {}

macro_rules! aead_purposes {
    ($($p:ident),+) => {$(
        impl sealed::AeadKeyBytes for PurposeKey<purpose::$p> {
            fn aead_key(&self, _: sealed::Token) -> &[u8; 32] {
                self.key.expose_secret()
            }
        }
        impl AeadKey for PurposeKey<purpose::$p> {}
    )+};
}

macro_rules! mac_purposes {
    ($($p:ident),+) => {$(
        impl sealed::MacKeyBytes for PurposeKey<purpose::$p> {
            fn mac_key(&self, _: sealed::Token) -> &[u8; 32] {
                self.key.expose_secret()
            }
        }
        impl MacKey for PurposeKey<purpose::$p> {}
    )+};
}

aead_purposes!(Manifest);
mac_purposes!(HeaderMac, StateCommit);

/// Computes a MAC under `profile`.
pub fn mac(key: &impl MacKey, profile: MacProfile, msg: &[u8]) -> Result<MacTag, CryptoError> {
    match profile {
        MacProfile::V1 => mac1(key.mac_key(sealed::TOKEN), msg),
    }
}

/// Verifies a MAC in constant time; a mismatch is [`CryptoError::Integrity`].
pub fn verify_mac(
    key: &impl MacKey,
    profile: MacProfile,
    msg: &[u8],
    tag: &MacTag,
) -> Result<(), CryptoError> {
    match profile {
        MacProfile::V1 => mac1_verify(key.mac_key(sealed::TOKEN), msg, tag),
    }
}

#[cfg(test)]
pub(crate) mod test_key {
    /// A bare AEAD key for module tests.
    pub(crate) struct TestKey(pub [u8; 32]);
    impl super::sealed::Sealed for TestKey {}
    impl super::sealed::AeadKeyBytes for TestKey {
        fn aead_key(&self, _: super::sealed::Token) -> &[u8; 32] {
            &self.0
        }
    }
    impl super::AeadKey for TestKey {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::StoredDataProfile;
    use crate::stored_data::{open, seal};

    const VAULT: VaultId = VaultId([0x11; 16]);
    const GEN: KeyGeneration = KeyGeneration(1);

    fn vk() -> VaultKey {
        VaultKey::from_bytes(core::array::from_fn(|i| i as u8))
    }

    fn all_purpose_keys(
        vk: &VaultKey,
        vault: VaultId,
        generation: KeyGeneration,
        profile_id: u16,
    ) -> Vec<(&'static str, [u8; 32])> {
        macro_rules! each {
            ($($p:ident),+) => {
                vec![$((
                    purpose::$p::LABEL,
                    vk.purpose_key_raw::<purpose::$p>(vault, generation, profile_id).unwrap().bytes(),
                )),+]
            };
        }
        each!(
            Record,
            Attachment,
            HeaderMac,
            Manifest,
            StateCommit,
            LocalState,
            DeviceStorage,
            RecoveryEd25519,
            RecoveryMlDsa65
        )
    }

    #[test]
    fn keys_labels_match_spec_0002_3_3() {
        let _guard = crate::memory::secrets_test_guard();
        let labels: Vec<_> = all_purpose_keys(&vk(), VAULT, GEN, 1)
            .into_iter()
            .map(|(l, _)| l)
            .collect();
        assert_eq!(
            labels,
            [
                "record",
                "attachment",
                "header-mac",
                "manifest",
                "state-commit",
                "local-state",
                "device-storage",
                "recovery-ed25519",
                "recovery-mldsa65",
            ]
        );
    }

    #[test]
    fn keys_purpose_keys_are_pairwise_distinct() {
        let _guard = crate::memory::secrets_test_guard();
        let keys = all_purpose_keys(&vk(), VAULT, GEN, 1);
        for (i, (la, a)) in keys.iter().enumerate() {
            assert_ne!(*a, vk().bytes(), "{la} equals VK");
            for (lb, b) in &keys[i + 1..] {
                assert_ne!(a, b, "{la} == {lb}");
            }
        }
    }

    #[test]
    fn keys_depend_on_vault_generation_profile_and_vk() {
        let _guard = crate::memory::secrets_test_guard();
        let base = all_purpose_keys(&vk(), VAULT, GEN, 1);
        let variants = [
            all_purpose_keys(&vk(), VaultId([0x12; 16]), GEN, 1),
            all_purpose_keys(&vk(), VAULT, KeyGeneration(2), 1),
            all_purpose_keys(&vk(), VAULT, GEN, 2),
            all_purpose_keys(&VaultKey::from_bytes([0xee; 32]), VAULT, GEN, 1),
        ];
        for v in &variants {
            for ((label, a), (_, b)) in base.iter().zip(v) {
                assert_ne!(a, b, "{label}");
            }
        }
        // The public path is the raw path with the profile's own ID.
        let public = vk()
            .purpose_key::<purpose::Manifest>(VAULT, GEN, DerivationProfile::V1)
            .unwrap()
            .bytes();
        assert_eq!(public, base[3].1);
    }

    #[test]
    fn keys_record_and_attachment_keys_are_separated() {
        let _guard = crate::memory::secrets_test_guard();
        let vk = vk();
        let records = vk
            .purpose_key::<purpose::Record>(VAULT, GEN, DerivationProfile::V1)
            .unwrap();
        let attachments = vk
            .purpose_key::<purpose::Attachment>(VAULT, GEN, DerivationProfile::V1)
            .unwrap();
        let r1 = records
            .record_key(VAULT, RecordId([1; 16]))
            .unwrap()
            .bytes();
        let r2 = records
            .record_key(VAULT, RecordId([2; 16]))
            .unwrap()
            .bytes();
        let r1_other_vault = records
            .record_key(VaultId([0x12; 16]), RecordId([1; 16]))
            .unwrap()
            .bytes();
        let a1 = attachments
            .attachment_key(VAULT, AttachmentId([1; 16]))
            .unwrap()
            .bytes();
        assert_ne!(r1, r2);
        assert_ne!(r1, r1_other_vault);
        assert_ne!(r1, a1);
        assert_ne!(r1, records.bytes());
    }

    #[test]
    fn keys_mac_is_bound_to_its_purpose() {
        let _guard = crate::memory::secrets_test_guard();
        let vk = vk();
        let header = vk
            .purpose_key::<purpose::HeaderMac>(VAULT, GEN, DerivationProfile::V1)
            .unwrap();
        let commit = vk
            .purpose_key::<purpose::StateCommit>(VAULT, GEN, DerivationProfile::V1)
            .unwrap();
        let tag = mac(&header, MacProfile::V1, b"header").unwrap();
        verify_mac(&header, MacProfile::V1, b"header", &tag).unwrap();
        assert_eq!(
            verify_mac(&commit, MacProfile::V1, b"header", &tag),
            Err(CryptoError::Integrity)
        );
        assert_eq!(
            verify_mac(&header, MacProfile::V1, b"headex", &tag),
            Err(CryptoError::Integrity)
        );
    }

    #[test]
    fn keys_record_ciphertext_is_bound_to_its_record_key() {
        let _guard = crate::memory::secrets_test_guard();
        let records = vk()
            .purpose_key::<purpose::Record>(VAULT, GEN, DerivationProfile::V1)
            .unwrap();
        let k1 = records.record_key(VAULT, RecordId([1; 16])).unwrap();
        let k2 = records.record_key(VAULT, RecordId([2; 16])).unwrap();
        let s = seal(&k1, StoredDataProfile::V1, b"aad", b"secret", 1 << 20).unwrap();
        assert!(
            open(
                &k1,
                StoredDataProfile::V1,
                b"aad",
                &s.nonce,
                &s.ciphertext,
                1 << 20
            )
            .is_ok()
        );
        assert_eq!(
            open(
                &k2,
                StoredDataProfile::V1,
                b"aad",
                &s.nonce,
                &s.ciphertext,
                1 << 20
            )
            .map(|_| ()),
            Err(CryptoError::Integrity)
        );
    }

    #[test]
    fn keys_debug_is_redacted() {
        let _guard = crate::memory::secrets_test_guard();
        let vk = vk();
        let p = vk
            .purpose_key::<purpose::Record>(VAULT, GEN, DerivationProfile::V1)
            .unwrap();
        let d = p.record_key(VAULT, RecordId([1; 16])).unwrap();
        assert_eq!(format!("{vk:?}"), "VaultKey(<redacted>)");
        assert_eq!(format!("{p:?}"), "PurposeKey<record>(<redacted>)");
        assert_eq!(format!("{d:#?}"), "DataKey(<redacted>)");
    }
}
