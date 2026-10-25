// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault cryptography and protected memory.
//!
//! This crate is part of the trusted client (`ARCHITECTURE.md` §3). Its only
//! QuickVault dependency is `qv-encoding` (canonical CBOR for AAD and HKDF
//! info); it depends on no frontend. Frontends reach it only through `qv-core`.
//!
//! **Profiles** (spec 0002 §1): one type per namespace
//! ([`PasswordKdfProfile`], [`StoredDataProfile`], [`PasswordWrapProfile`],
//! [`DerivationProfile`], [`MacProfile`], [`ObjectHashProfile`]). Unknown IDs
//! fail closed at `from_id`; transitions are an explicit registry.
//!
//! **Key hierarchy** (0002 §3):
//!
//! | Key | Derivation |
//! |-----|------------|
//! | MK | Argon2id v1.3, 256 MiB, t=3, p=4, over the NFC [`MasterPassword`] and a 32-byte salt |
//! | KEK | HKDF-SHA-512(MK, salt = vault ID, `["qv/kek/v1", kdf_profile]`) |
//! | KEK commitment | MAC/1(KEK, `["qv/kek-commit/v1", vault_id, key_generation, slot_id]`), checked in constant time before the slot AEAD |
//! | Wrap key | HKDF-SHA-512(KEK, no salt, `["qv/kek-wrap/v1"]`); wraps VK in a [`PasswordSlot`] |
//! | Purpose key | HKDF-SHA-512(VK, salt = vault ID, `["qv/purpose/v1", label, key_generation, derivation_profile]`), typed by [`purpose`] |
//! | Record / attachment key | HKDF-SHA-512(purpose key, salt = vault ID, `["qv/record-key/v1", record_id]` / `["qv/attachment-key/v1", attachment_id]`) |
//!
//! **Primitives**, all from pinned RustCrypto crates: stored-data/1
//! ([`seal`]/[`open`]: XChaCha20-Poly1305 with Padmé framing), MAC/1
//! ([`mac`]/[`verify_mac`]: HMAC-SHA-512 truncated to 32 bytes), object-hash/1
//! ([`object_hash`]: SHA-256). Known-answer vectors are in `tests/vectors/`.
//!
//! **Errors**: [`CryptoError`] carries no data. "Wrong password" and
//! "integrity failure" are distinct, and the slot reports only the former
//! (0002 §8).
//!
//! **Memory protection is best effort** (spec 0008 §1). Zeroizing a buffer
//! does not erase copies made before the secret was wrapped, copies the OS
//! wrote to swap or hibernation images, or copies held by other libraries.
//! Locking and process hardening report reduced protection instead of failing
//! silently; callers must surface that status to the user. Known residual
//! copies in this crate's dependencies: `hmac` builds its padded-key block on
//! the stack without wiping it; `unicode-normalization` keeps a few characters
//! in its own buffers while composing; Argon2's 256 MiB working memory is
//! wiped after use but too large to lock.

mod error;
mod ids;
#[cfg(test)]
mod kat;
mod keys;
mod memory;
mod password;
mod primitives;
mod process;
mod profile;
mod rng;
mod slot;
mod stored_data;

pub use error::CryptoError;
pub use ids::{AttachmentId, KeyGeneration, RecordId, SlotId, VaultId};
pub use keys::{
    AeadKey, DataKey, KeyPurpose, MacKey, PurposeKey, VaultKey, mac, purpose, verify_mac,
};
pub use memory::{MemoryProtection, SecretArray, SecretBytes, memory_protection};
pub use password::MasterPassword;
pub use primitives::{MacTag, ObjectHash, ObjectHasher, object_hash};
pub use process::{Hardening, ProcessHardening, harden_process};
pub use profile::{
    DerivationProfile, MacProfile, ObjectHashProfile, PasswordKdfProfile, PasswordWrapProfile,
    StoredDataProfile,
};
pub use rng::{RngError, fill_random, random_array};
pub use slot::PasswordSlot;
pub use stored_data::{Sealed, open, seal, sealed_len};
