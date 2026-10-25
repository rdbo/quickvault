// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identifiers that enter key derivation and AAD.
//!
//! They are random 128-bit values (spec 0003 §1.1), not secrets, so they are
//! plain copyable values. Distinct types keep, say, a record ID from being
//! passed where a vault ID is expected. In AAD and HKDF info they are encoded
//! as 16-byte CBOR byte strings; as HKDF salt, the vault ID is its raw bytes.

/// A vault's 128-bit random identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VaultId(pub [u8; 16]);

/// A keyslot's 128-bit random identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SlotId(pub [u8; 16]);

/// A record's 128-bit random identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(pub [u8; 16]);

/// An attachment's 128-bit random identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AttachmentId(pub [u8; 16]);

/// A vault key generation (spec 0002 §3.5), encoded as a CBOR unsigned integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyGeneration(pub u32);
