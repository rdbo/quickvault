// SPDX-License-Identifier: AGPL-3.0-or-later

//! Archives (spec 0004 §6; 0007 §3): header, framing, writer, reader and the
//! private snapshot directory.
//!
//! An archive is a byte stream (0004 §6.1):
//!
//! ```text
//! "QVSNAP\0" || u8 format_version || u32be header_length || header
//!           || frame(manifest envelope) || frame(object envelope)*
//! frame = u32be length || bytes
//! ```
//!
//! Development values, frozen in phase 1.16:
//!
//! | Item | Value |
//! |------|-------|
//! | magic and version | `"QVSNAP\0"`, [`ARCHIVE_FORMAT`] |
//! | header | canonical CBOR map, at most [`MAX_ARCHIVE_HEADER_BYTES`] |
//! | frame | `u32be` length, then that many bytes |
//! | header-MAC label | [`ARCHIVE_HEADER_LABEL`] |
//! | snapshot files | `<32 lowercase hex>.qvsnap`, `recover-<32 hex>.qvsnap` |
//!
//! The header (0004 §6.2) is a canonical CBOR map with integer keys; every
//! key is required, an unknown key fails closed and a `password_slot` is
//! recognised only to be refused (no archive carries a slot until phase 2,
//! 0004 §6.4):
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | archive_id | bstr 16 (random 128-bit) |
//! | 1 | vault_id | bstr 16 |
//! | 2 | key_generation | uint (u32, ≥ 1) |
//! | 3 | data_profile | uint (u16, stored-data) |
//! | 4 | minimum_profiles | `[min_data_profile, min_derivation_profile]` |
//! | 5 | created_at | int (milliseconds since the Unix epoch) |
//! | 6 | manifest_hash | bstr 32 |
//! | 7 | reference_digest | bstr 32 |
//! | 8 | object_count | uint |
//! | 9 | total_length | uint |
//! | 10 | password_slot | refused: self-contained archives are phase 2 |
//! | 11 | header_mac | bstr 32 |
//!
//! The header MAC is MAC/1 under the `header-mac` purpose key (the key the
//! vault header already uses) over the canonical array `["qv/archive-header/
//! v1", header_body]`, where `header_body` is exactly the stored header map
//! without `header_mac`. The key is derived for the header's vault ID and key
//! generation with [`ARCHIVE_DERIVATION_PROFILE`], a development value: the
//! header carries no derivation-profile field of its own, so phase 1.16
//! freezes either that constant or a new field.
//!
//! Order of operations for hostile bytes (0004 §6.3, 0004 §4.1): fixed prefix
//! → `u32be` header length against the budget → bounded strict decode → the
//! caller's vault ID and generation → header MAC → manifest frame bounded and
//! hashed against `manifest_hash` → manifest decrypt/decode/validate → frames
//! matched to the next sorted reference by length and SHA-256 **before** any
//! AEAD. No length is used before it is checked and no archive byte reaches
//! SQLite.

use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};

use qv_crypto::{
    DerivationProfile, KeyGeneration, MacProfile, MacTag, ObjectHashProfile, PurposeKey,
    StoredDataProfile, VaultId, VaultKey, mac, object_hash, purpose, verify_mac,
};
use qv_encoding::{Decoder, Encoder, encode_array};
use qv_model::{ObjectId, RandomId, Timestamp};
use zeroize::Zeroizing;

use crate::error::StoreError;
use crate::limits::{
    MAX_ARCHIVE_MANIFEST_FRAME, MAX_ARCHIVE_OBJECT_FRAME, MAX_ARCHIVE_TOTAL_LENGTH, MAX_OBJECTS,
};
use crate::manifest::{ObjectRef, config_digest_for, open_manifest};
use crate::object::Scope;

/// The fixed prefix's magic (0004 §6.1).
pub const ARCHIVE_MAGIC: [u8; 7] = *b"QVSNAP\0";

/// The archive format version (development value, phase 1.16).
pub const ARCHIVE_FORMAT: u8 = 0x01;

/// Most bytes of an archive header (0004 §4.1, §6.2). Development value.
pub const MAX_ARCHIVE_HEADER_BYTES: usize = 64 * 1024;

/// The header-MAC transcript label (development value, phase 1.16).
pub const ARCHIVE_HEADER_LABEL: &str = "qv/archive-header/v1";

/// The archive file extension (0004 §6.1).
pub const ARCHIVE_EXTENSION: &str = "qvsnap";

/// The derivation profile of the archive header-MAC key (development value:
/// the header carries no derivation-profile field; phase 1.16 freezes this
/// constant or adds the field).
pub const ARCHIVE_DERIVATION_PROFILE: DerivationProfile = DerivationProfile::V1;

/// The MAC profile of the archive header MAC (development value).
pub const ARCHIVE_MAC_PROFILE: MacProfile = MacProfile::V1;

/// The object-hash profile of every archive hash (0004 §3.5).
pub(crate) const ARCHIVE_HASH_PROFILE: ObjectHashProfile = ObjectHashProfile::V1;

/// The header map key of a self-contained archive's password slot (0004
/// §6.4), recognised only to be refused.
const KEY_PASSWORD_SLOT: i64 = 10;

/// The header map key of the MAC itself.
const KEY_HEADER_MAC: i64 = 11;

/// The fixed prefix: magic, then the format version.
const PREFIX_BYTES: usize = ARCHIVE_MAGIC.len() + 1;

fn malformed<E>(_: E) -> StoreError {
    StoreError::Integrity
}

fn id16(d: &mut Decoder<'_>) -> Result<[u8; 16], StoreError> {
    d.bytes().map_err(malformed)?.try_into().map_err(malformed)
}

fn digest32(d: &mut Decoder<'_>) -> Result<[u8; 32], StoreError> {
    d.bytes().map_err(malformed)?.try_into().map_err(malformed)
}

/// 32 lowercase hex digits: an archive's name and CLI identifier.
pub(crate) fn hex32(id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in id {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Which vault and key generation an archive must belong to (0004 §6.3: the
/// reader obtains VK from the local vault with the same vault ID and
/// generation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArchiveScope {
    vault_id: VaultId,
    key_generation: KeyGeneration,
    archive_id: Option<[u8; 16]>,
}

impl ArchiveScope {
    /// Pins an explicitly selected archive ID across reader passes.
    pub fn with_archive_id(mut self, archive_id: [u8; 16]) -> Self {
        self.archive_id = Some(archive_id);
        self
    }

    /// The scope of one vault state.
    pub fn new(vault_id: VaultId, key_generation: KeyGeneration) -> Self {
        Self {
            vault_id,
            key_generation,
            archive_id: None,
        }
    }

    /// The vault ID an archive must name.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The key generation an archive must name.
    pub fn key_generation(&self) -> KeyGeneration {
        self.key_generation
    }
}

/// A decoded archive header (0004 §6.2).
///
/// It holds IDs, digests and counts, which are confidential metadata (0008
/// §1.2), so `Debug` is redacted.
pub struct ArchiveHeader {
    archive_id: [u8; 16],
    vault_id: VaultId,
    key_generation: KeyGeneration,
    data_profile: StoredDataProfile,
    min_data_profile: StoredDataProfile,
    min_derivation_profile: DerivationProfile,
    created_at: Timestamp,
    manifest_hash: [u8; 32],
    reference_digest: [u8; 32],
    object_count: u64,
    total_length: u64,
    header_mac: MacTag,
}

impl core::fmt::Debug for ArchiveHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ArchiveHeader(..)")
    }
}

/// The authenticated facts of one published archive (0004 §6.2).
///
/// Redacted `Debug` like [`ArchiveHeader`].
#[derive(Clone, PartialEq, Eq)]
pub struct ArchiveStats {
    /// The archive's random 32-hex identifier.
    pub archive_id: String,
    /// When it was written (unauthenticated clock, display only).
    pub created_at: Timestamp,
    /// The number of referenced objects it carries.
    pub object_count: u64,
    /// The total referenced ciphertext length.
    pub total_length: u64,
    /// The vault it belongs to.
    pub vault_id: VaultId,
    /// Its key generation.
    pub key_generation: KeyGeneration,
}

impl core::fmt::Debug for ArchiveStats {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ArchiveStats(..)")
    }
}

impl ArchiveHeader {
    /// Decodes and checks a header whose length the caller has bounded.
    ///
    /// Unknown fields are [`StoreError::Unsupported`]; a `password_slot`,
    /// missing or mistyped field is [`StoreError::Integrity`]; a count over
    /// its budget is [`StoreError::LimitExceeded`]. Nothing is allocated from
    /// a length before the decoder has checked it.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_ARCHIVE_HEADER_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        let mut d = Decoder::new(bytes).map_err(malformed)?;
        let mut archive_id = None;
        let mut vault_id = None;
        let mut generation = None;
        let mut data_profile = None;
        let mut minima = None;
        let mut created_at = None;
        let mut manifest_hash = None;
        let mut reference_digest = None;
        let mut object_count = None;
        let mut total_length = None;
        let mut header_mac = None;
        for _ in 0..d.map().map_err(malformed)? {
            match d.int().map_err(malformed)? {
                0 => archive_id = Some(id16(&mut d)?),
                1 => vault_id = Some(VaultId(id16(&mut d)?)),
                2 => generation = Some(d.uint().map_err(malformed)?),
                3 => data_profile = Some(d.uint().map_err(malformed)?),
                4 => {
                    if d.array().map_err(malformed)? != 2 {
                        return Err(StoreError::Integrity);
                    }
                    let data = d.uint().map_err(malformed)?;
                    let derivation = d.uint().map_err(malformed)?;
                    minima = Some((data, derivation));
                }
                5 => created_at = Some(Timestamp(d.int().map_err(malformed)?)),
                6 => manifest_hash = Some(digest32(&mut d)?),
                7 => reference_digest = Some(digest32(&mut d)?),
                8 => object_count = Some(d.uint().map_err(malformed)?),
                9 => total_length = Some(d.uint().map_err(malformed)?),
                // Refused before its value is looked at: a self-contained
                // archive is an explicit phase 2 choice (0004 §6.4).
                KEY_PASSWORD_SLOT => return Err(StoreError::Integrity),
                KEY_HEADER_MAC => header_mac = Some(MacTag::from_bytes(digest32(&mut d)?)),
                _ => return Err(StoreError::Unsupported),
            }
        }
        d.finish().map_err(malformed)?;
        let generation = u32::try_from(generation.ok_or(StoreError::Integrity)?)
            .ok()
            .filter(|&g| g > 0)
            .ok_or(StoreError::Integrity)?;
        let small = |v: u64| u16::try_from(v).map_err(|_| StoreError::Integrity);
        let data_profile =
            StoredDataProfile::from_id(small(data_profile.ok_or(StoreError::Integrity)?)?)?;
        let (min_data, min_derivation) = minima.ok_or(StoreError::Integrity)?;
        let min_data_profile = StoredDataProfile::from_id(small(min_data)?)?;
        let min_derivation_profile = DerivationProfile::from_id(small(min_derivation)?)?;
        if !data_profile.accepts(min_data_profile)
            || !ARCHIVE_DERIVATION_PROFILE.accepts(min_derivation_profile)
        {
            return Err(StoreError::Unsupported);
        }
        let object_count = object_count.ok_or(StoreError::Integrity)?;
        if usize::try_from(object_count).map_or(true, |n| n > MAX_OBJECTS) {
            return Err(StoreError::LimitExceeded);
        }
        let total_length = total_length.ok_or(StoreError::Integrity)?;
        if total_length > MAX_ARCHIVE_TOTAL_LENGTH {
            return Err(StoreError::LimitExceeded);
        }
        Ok(Self {
            archive_id: archive_id.ok_or(StoreError::Integrity)?,
            vault_id: vault_id.ok_or(StoreError::Integrity)?,
            key_generation: KeyGeneration(generation),
            data_profile,
            min_data_profile,
            min_derivation_profile,
            created_at: created_at.ok_or(StoreError::Integrity)?,
            manifest_hash: manifest_hash.ok_or(StoreError::Integrity)?,
            reference_digest: reference_digest.ok_or(StoreError::Integrity)?,
            object_count,
            total_length,
            header_mac: header_mac.ok_or(StoreError::Integrity)?,
        })
    }

    /// The canonical encoding, `header_mac` included.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.encode_map(Some(&self.header_mac))
    }

    /// The canonical map with or without the MAC entry. Only that entry
    /// differs, so the transcript covers exactly the stored fields.
    fn encode_map(&self, mac: Option<&MacTag>) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let mut e = Encoder::new();
        e.map(|m| {
            m.entry(0, |e| {
                e.bytes(&self.archive_id);
                Ok(())
            })?;
            m.entry(1, |e| {
                e.bytes(&self.vault_id.0);
                Ok(())
            })?;
            m.entry(2, |e| {
                e.uint(u64::from(self.key_generation.0));
                Ok(())
            })?;
            m.entry(3, |e| {
                e.uint(u64::from(self.data_profile.id()));
                Ok(())
            })?;
            m.entry(4, |e| {
                e.array(|a| {
                    a.uint(u64::from(self.min_data_profile.id()));
                    a.uint(u64::from(self.min_derivation_profile.id()));
                    Ok(())
                })
            })?;
            m.entry(5, |e| {
                e.int(self.created_at.0);
                Ok(())
            })?;
            m.entry(6, |e| {
                e.bytes(&self.manifest_hash);
                Ok(())
            })?;
            m.entry(7, |e| {
                e.bytes(&self.reference_digest);
                Ok(())
            })?;
            m.entry(8, |e| {
                e.uint(self.object_count);
                Ok(())
            })?;
            m.entry(9, |e| {
                e.uint(self.total_length);
                Ok(())
            })?;
            if let Some(tag) = mac {
                m.entry(KEY_HEADER_MAC, |e| {
                    e.bytes(tag.as_bytes());
                    Ok(())
                })?;
            }
            Ok(())
        })
        .map_err(|_| StoreError::Internal)?;
        e.finish().map_err(|_| StoreError::Internal)
    }

    /// The archive's random 128-bit identifier.
    pub fn archive_id(&self) -> [u8; 16] {
        self.archive_id
    }

    /// The archive's identifier as 32 lowercase hex digits.
    pub fn archive_id_hex(&self) -> String {
        hex32(&self.archive_id)
    }

    /// The vault the archive belongs to.
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// The archive's key generation.
    pub fn key_generation(&self) -> KeyGeneration {
        self.key_generation
    }

    /// The stored-data profile of the objects it carries.
    pub fn data_profile(&self) -> StoredDataProfile {
        self.data_profile
    }

    /// The minima it was written under, `(stored-data, derivation)`.
    pub fn minimum_profiles(&self) -> (StoredDataProfile, DerivationProfile) {
        (self.min_data_profile, self.min_derivation_profile)
    }

    /// The claimed creation time (unauthenticated clock, display only).
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// The manifest envelope's SHA-256 (0004 §3.5).
    pub fn manifest_hash(&self) -> &[u8; 32] {
        &self.manifest_hash
    }

    /// SHA-256 of the canonical sorted reference list (0004 §3.5).
    pub fn reference_digest(&self) -> &[u8; 32] {
        &self.reference_digest
    }

    /// How many object frames follow the manifest frame.
    pub fn object_count(&self) -> u64 {
        self.object_count
    }

    /// The sum of their ciphertext lengths.
    pub fn total_length(&self) -> u64 {
        self.total_length
    }

    /// Whether this header names `scope`'s vault ID and generation.
    pub fn matches(&self, scope: ArchiveScope) -> bool {
        self.vault_id == scope.vault_id
            && self.key_generation == scope.key_generation
            && scope.archive_id.is_none_or(|id| self.archive_id == id)
    }

    /// The header-MAC transcript: `["qv/archive-header/v1", header fields]`.
    fn transcript(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let body = self.encode_map(None)?;
        encode_array(|a| {
            a.text(ARCHIVE_HEADER_LABEL);
            a.bytes(&body);
            Ok(())
        })
        .map_err(|_| StoreError::Internal)
    }

    /// The MAC key: the `header-mac` purpose key of this header's vault and
    /// generation.
    fn mac_key(&self, vk: &VaultKey) -> Result<PurposeKey<purpose::HeaderMac>, StoreError> {
        Ok(vk.purpose_key::<purpose::HeaderMac>(
            self.vault_id,
            self.key_generation,
            ARCHIVE_DERIVATION_PROFILE,
        )?)
    }

    /// Verifies `header_mac` with the caller's VK (0004 §6.3). A mismatch is
    /// [`StoreError::Integrity`].
    pub fn verify_mac(&self, vk: &VaultKey) -> Result<(), StoreError> {
        let key = self.mac_key(vk)?;
        verify_mac(
            &key,
            ARCHIVE_MAC_PROFILE,
            &self.transcript()?,
            &self.header_mac,
        )
        .map_err(|_| StoreError::Integrity)
    }

    /// Computes `header_mac` in place, for a header being written.
    fn seal_mac(&mut self, vk: &VaultKey) -> Result<(), StoreError> {
        let key = self.mac_key(vk)?;
        self.header_mac = mac(&key, ARCHIVE_MAC_PROFILE, &self.transcript()?)?;
        Ok(())
    }
}

/// Writes the fixed prefix (0004 §6.1).
fn write_prefix<W: Write>(out: &mut W) -> Result<(), StoreError> {
    out.write_all(&ARCHIVE_MAGIC).map_err(|_| StoreError::Io)?;
    out.write_all(&[ARCHIVE_FORMAT]).map_err(|_| StoreError::Io)
}

/// Reads and checks the fixed prefix: another version is
/// [`StoreError::Unsupported`], a wrong magic [`StoreError::Integrity`]
/// (0004 §6.3).
fn read_prefix<R: Read>(input: &mut R) -> Result<(), StoreError> {
    let mut buf = [0u8; PREFIX_BYTES];
    input
        .read_exact(&mut buf)
        .map_err(|_| StoreError::Integrity)?;
    if buf[..ARCHIVE_MAGIC.len()] != ARCHIVE_MAGIC {
        return Err(StoreError::Integrity);
    }
    if buf[ARCHIVE_MAGIC.len()] != ARCHIVE_FORMAT {
        return Err(StoreError::Unsupported);
    }
    Ok(())
}

/// Writes one frame: its `u32be` length, then the bytes (0004 §6.1).
pub(crate) fn write_frame<W: Write>(out: &mut W, bytes: &[u8]) -> Result<(), StoreError> {
    let len = u32::try_from(bytes.len()).map_err(|_| StoreError::LimitExceeded)?;
    out.write_all(&len.to_be_bytes())
        .map_err(|_| StoreError::Io)?;
    out.write_all(bytes).map_err(|_| StoreError::Io)
}

/// Reads a frame's `u32be` length, refusing anything above `max` before
/// anything is allocated.
pub(crate) fn read_frame_len<R: Read>(input: &mut R, max: usize) -> Result<usize, StoreError> {
    let mut buf = [0u8; 4];
    input
        .read_exact(&mut buf)
        .map_err(|_| StoreError::Integrity)?;
    let len = usize::try_from(u32::from_be_bytes(buf)).map_err(|_| StoreError::LimitExceeded)?;
    if len > max {
        return Err(StoreError::LimitExceeded);
    }
    Ok(len)
}

/// Reads exactly `len` frame bytes into a fresh buffer (the caller has
/// bounded `len`).
pub(crate) fn read_frame<R: Read>(input: &mut R, len: usize) -> Result<Vec<u8>, StoreError> {
    let mut buf = vec![0u8; len];
    input
        .read_exact(&mut buf)
        .map_err(|_| StoreError::Integrity)?;
    Ok(buf)
}

/// The head length of the shortest canonical CBOR head of `value`.
fn head_len(value: u64) -> usize {
    if value < 24 {
        1
    } else if value <= 0xff {
        2
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

/// The exact length of one object frame for `r` (0004 §6.1): the canonical
/// envelope `[object_id, key_generation, data_profile, nonce, ciphertext]`.
/// Reading this before the frame means a lying length is refused without
/// allocating anything.
fn object_frame_len(generation: KeyGeneration, r: &ObjectRef) -> Result<usize, StoreError> {
    // A byte string of `n` bytes is its head plus `n`; the nonce is 24 bytes,
    // whose head is two bytes (24 does not fit in a one-byte head).
    let nonce = head_len(24) + 24;
    let ciphertext = usize::try_from(r.length()).map_err(|_| StoreError::LimitExceeded)?;
    let fixed = 1
        + head_len(16)
        + 16
        + head_len(u64::from(generation.0))
        + head_len(u64::from(r.data_profile().id()))
        + nonce
        + head_len(r.length());
    fixed
        .checked_add(ciphertext)
        .ok_or(StoreError::LimitExceeded)
}

/// One verified object frame, its ciphertext borrowed from the frame buffer
/// (0004 §6.3). A sink receives it only after all roles and attachment
/// contents have authenticated, with complete frame commitments checked again.
///
/// Redacted `Debug`: it links an object ID to a manifest reference (0004 §2.2).
pub struct ArchiveObject<'a> {
    object_id: ObjectId,
    key_generation: KeyGeneration,
    data_profile: StoredDataProfile,
    nonce: [u8; 24],
    ciphertext: &'a [u8],
}

impl core::fmt::Debug for ArchiveObject<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ArchiveObject(..)")
    }
}

impl ArchiveObject<'_> {
    /// The object ID the manifest references.
    pub fn object_id(&self) -> ObjectId {
        self.object_id
    }

    /// The key generation it was encrypted under.
    pub fn key_generation(&self) -> KeyGeneration {
        self.key_generation
    }

    /// Its stored-data profile.
    pub fn data_profile(&self) -> StoredDataProfile {
        self.data_profile
    }

    /// Its XChaCha20 nonce.
    pub fn nonce(&self) -> &[u8; 24] {
        &self.nonce
    }

    /// Its ciphertext (tag included), already checked against the reference's
    /// length and SHA-256.
    pub fn ciphertext(&self) -> &[u8] {
        self.ciphertext
    }
}

/// An archive whose header and manifest have been authenticated and whose
/// frames have all been verified (0004 §6.3).
///
/// Redacted `Debug`: it holds the manifest, which links records to objects.
pub struct OpenedArchive {
    header: ArchiveHeader,
    manifest: crate::manifest::Manifest,
    #[cfg(any(target_os = "linux", target_os = "android"))]
    pub(crate) frames: Vec<IndexedFrame>,
}

impl core::fmt::Debug for OpenedArchive {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("OpenedArchive(..)")
    }
}

impl OpenedArchive {
    /// The authenticated header.
    pub fn header(&self) -> &ArchiveHeader {
        &self.header
    }

    /// The authenticated, validated manifest.
    pub fn manifest(&self) -> &crate::manifest::Manifest {
        &self.manifest
    }
}

/// Reads and authenticates an archive header (0004 §6.3): fixed prefix,
/// `u32be` header length against the budget, bounded strict decode, the
/// caller's vault ID and generation, then the header MAC. Nothing after the
/// header is read, which is what `snapshot ls` needs.
pub fn read_header<R: Read>(
    input: &mut R,
    expect: ArchiveScope,
    vk: &VaultKey,
) -> Result<ArchiveHeader, StoreError> {
    read_prefix(input)?;
    let len = read_frame_len(input, MAX_ARCHIVE_HEADER_BYTES)?;
    let bytes = read_frame(input, len)?;
    let header = ArchiveHeader::decode(&bytes)?;
    if !header.matches(expect) {
        return Err(StoreError::Integrity);
    }
    header.verify_mac(vk)?;
    Ok(header)
}

/// Reads a whole seekable archive in the fixed 0004 §6.3 order and hands
/// verified object frames to `sink` only after full role authentication.
/// A bounded index of frame positions permits ordered attachment verification
/// without buffering the archive or staging plaintext. A sink failure may
/// leave partial output; callers must accept output only on overall success.
///
/// The order is: prefix → bounded header → the caller's vault ID and key
/// generation → header MAC → manifest frame bounded and hashed against
/// `manifest_hash` → manifest decrypt, decode and validate → counts and
/// totals → one frame per reference in the manifest's sorted order, each
/// matched by exact length and SHA-256 **before** any AEAD → exact EOF.
/// Cancellation is checked between frames. Trailing bytes, a missing or extra
/// frame, a wrong `object_count`/`total_length`, another profile or
/// generation and a substituted frame are [`StoreError::Integrity`].
pub fn read_archive<R: Read + Seek>(
    input: &mut R,
    expect: ArchiveScope,
    vk: &VaultKey,
    sink: &mut dyn FnMut(ArchiveObject<'_>) -> Result<(), StoreError>,
    cancelled: &dyn Fn() -> bool,
) -> Result<OpenedArchive, StoreError> {
    let header = read_header(input, expect, vk)?;

    // The manifest frame: bounded, then hashed against the header.
    let len = read_frame_len(input, MAX_ARCHIVE_MANIFEST_FRAME)?;
    let frame = read_frame(input, len)?;
    if object_hash(ARCHIVE_HASH_PROFILE, &frame).0 != *header.manifest_hash() {
        return Err(StoreError::Integrity);
    }
    let (profile, nonce, ciphertext) = manifest_envelope(&frame, &header)?;
    let scope = Scope {
        vault_id: header.vault_id(),
        key_generation: header.key_generation(),
    };
    let key = vk.purpose_key::<purpose::Manifest>(
        scope.vault_id,
        scope.key_generation,
        ARCHIVE_DERIVATION_PROFILE,
    )?;
    let manifest = open_manifest(&key, scope, profile, nonce, ciphertext)?;
    // The manifest's configuration digest must describe this header's vault,
    // generation and minima (0004 §3.4, §6.2).
    let (min_data, min_derivation) = header.minimum_profiles();
    if *manifest.config_digest()
        != config_digest_for(
            header.vault_id(),
            header.key_generation(),
            min_data,
            min_derivation,
        )?
    {
        return Err(StoreError::Integrity);
    }

    if manifest.reference_digest()? != *header.reference_digest() {
        return Err(StoreError::Integrity);
    }

    // Counts and totals, before a single object frame is read.
    let references = manifest.references();
    if u64::try_from(references.len()).ok() != Some(header.object_count()) {
        return Err(StoreError::Integrity);
    }
    // Both budgets are already enforced: the header decode bounds
    // `total_length` and `Manifest::validate` bounds the reference sum.
    let total = references
        .iter()
        .try_fold(0u64, |total, r| total.checked_add(r.length()))
        .ok_or(StoreError::LimitExceeded)?;
    if total != header.total_length() {
        return Err(StoreError::Integrity);
    }

    // Index encrypted frames only; no sink sees anything before full validation.
    let mut frames = Vec::with_capacity(references.len());
    for r in references {
        if cancelled() {
            return Err(StoreError::Io);
        }
        let expected = object_frame_len(header.key_generation(), r)?;
        if expected > MAX_ARCHIVE_OBJECT_FRAME {
            return Err(StoreError::LimitExceeded);
        }
        let offset = input.stream_position().map_err(|_| StoreError::Io)?;
        let len = read_frame_len(input, MAX_ARCHIVE_OBJECT_FRAME)?;
        if len != expected {
            return Err(StoreError::Integrity);
        }
        let frame = read_frame(input, len)?;
        object_envelope(&frame, &header, r)?;
        frames.push(IndexedFrame {
            offset,
            digest: object_hash(ARCHIVE_HASH_PROFILE, &frame).0,
        });
    }
    if cancelled() {
        return Err(StoreError::Io);
    }

    // Exact EOF: a trailing byte means the archive was extended or tampered
    // with (0004 §6.3).
    exact_eof(input)?;
    let end = input.stream_position().map_err(|_| StoreError::Io)?;
    crate::archive_verify::verify(input, &header, &manifest, &frames, vk, cancelled)?;
    for (r, indexed) in references.iter().zip(&frames) {
        if cancelled() {
            return Err(StoreError::Io);
        }
        let frame = indexed.read(input, &header, r)?;
        sink(object_envelope(&frame, &header, r)?)?;
    }
    input
        .seek(SeekFrom::Start(end))
        .map_err(|_| StoreError::Io)?;
    exact_eof(input)?;
    Ok(OpenedArchive {
        header,
        manifest,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        frames,
    })
}

fn exact_eof<R: Read>(input: &mut R) -> Result<(), StoreError> {
    let mut probe = [0u8; 1];
    loop {
        match input.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(StoreError::Integrity),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return Err(StoreError::Io),
        }
    }
}

/// One bounded frame's position and complete-envelope commitment between passes.
pub(crate) struct IndexedFrame {
    offset: u64,
    digest: [u8; 32],
}
impl IndexedFrame {
    pub(crate) fn read<R: Read + Seek>(
        &self,
        input: &mut R,
        header: &ArchiveHeader,
        r: &ObjectRef,
    ) -> Result<Vec<u8>, StoreError> {
        input
            .seek(SeekFrom::Start(self.offset))
            .map_err(|_| StoreError::Io)?;
        let len = read_frame_len(input, MAX_ARCHIVE_OBJECT_FRAME)?;
        if len != object_frame_len(header.key_generation(), r)? {
            return Err(StoreError::Integrity);
        }
        let frame = read_frame(input, len)?;
        if object_hash(ARCHIVE_HASH_PROFILE, &frame).0 != self.digest {
            return Err(StoreError::Integrity);
        }
        Ok(frame)
    }
}

/// Parses and checks the manifest frame's envelope `[key_generation,
/// data_profile, nonce, ciphertext]` (0004 §3.5, §6.1).
fn manifest_envelope<'a>(
    frame: &'a [u8],
    header: &ArchiveHeader,
) -> Result<(StoredDataProfile, &'a [u8; 24], &'a [u8]), StoreError> {
    let mut d = Decoder::new(frame).map_err(malformed)?;
    if d.array().map_err(malformed)? != 4 {
        return Err(StoreError::Integrity);
    }
    let generation = u32::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
    let profile = u16::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
    let data_profile = StoredDataProfile::from_id(profile)?;
    let nonce: &[u8; 24] = d
        .bytes()
        .map_err(malformed)?
        .try_into()
        .map_err(malformed)?;
    let ciphertext = d.bytes().map_err(malformed)?;
    d.finish().map_err(malformed)?;
    let (min_data, _) = header.minimum_profiles();
    if generation != header.key_generation().0
        || data_profile != header.data_profile()
        || !data_profile.accepts(min_data)
    {
        return Err(StoreError::Integrity);
    }
    Ok((data_profile, nonce, ciphertext))
}

/// Parses and checks one object frame against `r` (0004 §6.3): the envelope's
/// object ID, generation, profile, nonce length and ciphertext length and
/// SHA-256, all before any AEAD. The ciphertext is borrowed from `frame`.
pub(crate) fn object_envelope<'a>(
    frame: &'a [u8],
    header: &ArchiveHeader,
    r: &ObjectRef,
) -> Result<ArchiveObject<'a>, StoreError> {
    let mut d = Decoder::new(frame).map_err(malformed)?;
    if d.array().map_err(malformed)? != 5 {
        return Err(StoreError::Integrity);
    }
    let object_id = ObjectId::from_bytes(id16(&mut d)?)?;
    let generation = u32::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
    let profile = u16::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
    let data_profile = StoredDataProfile::from_id(profile)?;
    let nonce: [u8; 24] = d
        .bytes()
        .map_err(malformed)?
        .try_into()
        .map_err(malformed)?;
    let ciphertext = d.bytes().map_err(malformed)?;
    d.finish().map_err(malformed)?;
    if !data_profile.accepts(header.minimum_profiles().0)
        || object_id != r.object_id()
        || generation != header.key_generation().0
        || data_profile != r.data_profile()
        || u64::try_from(ciphertext.len()).ok() != Some(r.length())
        || object_hash(ARCHIVE_HASH_PROFILE, ciphertext).0 != *r.sha256()
    {
        return Err(StoreError::Integrity);
    }
    Ok(ArchiveObject {
        object_id,
        key_generation: KeyGeneration(generation),
        data_profile,
        nonce,
        ciphertext,
    })
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    //! The archive writer and the private snapshot directory (0004 §6.5,
    //! 0007 §3.1). They need the vault's SQLite read path and the private
    //! file checks, so other targets get fail-closed stubs (`unsupported`).

    use std::ffi::{OsStr, OsString};
    use std::io::Write;
    use std::path::{Path, PathBuf};

    use qv_model::Timestamp;

    use super::*;
    use crate::crash::{CrashPoint, point};
    use crate::fs;
    use crate::manifest;
    use crate::object::ObjectEnvelope;
    use crate::schema::{self, ObjectReader};
    use crate::vault::{UnlockedVault, accepted_profile};

    /// The suffix of every local snapshot file.
    const SNAPSHOT_SUFFIX: &str = ".qvsnap";

    /// The fixed text prefix of an ordinary snapshot's file name (0007 §3.2:
    /// the kind is bookkeeping outside the archive format).
    const RECOVERY_PREFIX: &str = "recover-";

    /// What a local snapshot is for (0007 §3.2). It is recorded only in the
    /// file name, never in the archive (0004 §6).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SnapshotKind {
        /// An automatic or user-visible snapshot.
        Ordinary,
        /// The mandatory pre-operation copy of a destructive operation.
        Recovery,
    }

    impl SnapshotKind {
        fn prefix(self) -> &'static str {
            match self {
                Self::Ordinary => "",
                Self::Recovery => RECOVERY_PREFIX,
            }
        }

        /// The fixed label `ordinary` or `recovery` (0011 §4).
        pub fn label(self) -> &'static str {
            match self {
                Self::Ordinary => "ordinary",
                Self::Recovery => "recovery",
            }
        }
    }

    /// One file in the snapshot directory: its name and size only. Reading
    /// what it contains needs the vault key (0011 `snapshot ls`).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct SnapshotEntry {
        name: OsString,
        size: u64,
        kind: SnapshotKind,
    }

    impl SnapshotEntry {
        /// The file name, `<prefix><32 hex>.qvsnap`. Not secret: it is the
        /// archive's random ID, which 0011 prints.
        pub fn name(&self) -> &OsStr {
            &self.name
        }

        /// The filename's full lowercase archive ID. Header agreement is checked on open.
        pub fn archive_id(&self) -> &str {
            self.name
                .to_str()
                .and_then(parse_name)
                .map(|(_, id)| id)
                .unwrap_or_default()
        }

        /// Its size on disk.
        pub fn size(&self) -> u64 {
            self.size
        }

        /// Whether it is an ordinary or a recovery copy.
        pub fn kind(&self) -> SnapshotKind {
            self.kind
        }
    }

    /// A verified archive published under a new name (0004 §6.5).
    #[derive(Debug)]
    pub struct PublishedSnapshot {
        entry: SnapshotEntry,
        stats: ArchiveStats,
    }

    impl PublishedSnapshot {
        /// The published file.
        pub fn entry(&self) -> &SnapshotEntry {
            &self.entry
        }

        /// What the writer committed to.
        pub fn stats(&self) -> &ArchiveStats {
            &self.stats
        }

        /// The archive's 32-hex identifier.
        pub fn archive_id(&self) -> &str {
            &self.stats.archive_id
        }

        /// Its claimed creation time.
        pub fn created_at(&self) -> Timestamp {
            self.stats.created_at
        }

        /// Its kind.
        pub fn kind(&self) -> SnapshotKind {
            self.entry.kind
        }

        /// Its size on disk.
        pub fn size(&self) -> u64 {
            self.entry.size
        }

        /// How many objects it carries.
        pub fn objects(&self) -> u64 {
            self.stats.object_count
        }

        /// Their total ciphertext length.
        pub fn total_bytes(&self) -> u64 {
            self.stats.total_length
        }
    }

    /// Parses a local snapshot file name into its kind and archive ID.
    fn parse_name(name: &str) -> Option<(SnapshotKind, &str)> {
        let (kind, rest) = match name.strip_prefix(RECOVERY_PREFIX) {
            Some(rest) => (SnapshotKind::Recovery, rest),
            None => (SnapshotKind::Ordinary, name),
        };
        let id = rest.strip_suffix(SNAPSHOT_SUFFIX)?;
        let hex = id.as_bytes();
        if hex.len() != 32
            || !hex
                .iter()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        {
            return None;
        }
        Some((kind, id))
    }

    impl UnlockedVault {
        /// Streams the committed state into `out` (0004 §6): the prefix, the
        /// header, the manifest envelope frame, then one frame per reference
        /// in the manifest's validated sorted order.
        ///
        /// The whole pass runs in one read transaction opened after
        /// re-checking the on-disk head ([`StoreError::Changed`] otherwise).
        /// Every object is re-read from its row and its profile, length and
        /// SHA-256 are checked against its reference **before** the frame is
        /// written; a missing or mismatched row aborts with
        /// [`StoreError::Integrity`] and the caller publishes nothing. Bytes
        /// are copied one object at a time (never a whole vault and never the
        /// whole archive), and cancellation is checked between objects and so
        /// between 1 MiB blocks ([`StoreError::Io`]).
        ///
        /// Nothing here writes to the vault: there is no `Write`, no manifest,
        /// head, anchor or pruning step, and the live SQLite file is never
        /// copied (0004 §5.3, §6).
        pub fn write_archive<W: Write>(
            &mut self,
            mut out: W,
            created_at: Timestamp,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<ArchiveStats, StoreError> {
            self.verify_all(cancelled)?;
            self.begin_read()?;
            match self.archive_stream(&mut out, created_at, cancelled) {
                Ok(stats) => {
                    self.end_read()?;
                    Ok(stats)
                }
                Err(e) => {
                    self.abort_read();
                    Err(e)
                }
            }
        }

        /// The archive pass itself, inside the caller's read transaction.
        fn archive_stream<W: Write>(
            &mut self,
            out: &mut W,
            created_at: Timestamp,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<ArchiveStats, StoreError> {
            let header = self.file.header;
            let manifest = &self.state.manifest;
            if cancelled() {
                return Err(StoreError::Io);
            }

            // The stored manifest row must be the one the verified head names,
            // and its re-encoded envelope must hash to the stored hash (0004
            // §3.5).
            let stored = schema::read_manifest(&self.file.conn)?;
            if stored.hash != self.state.head.manifest_hash
                || stored.key_generation != header.key_generation
            {
                return Err(StoreError::Integrity);
            }
            let profile = accepted_profile(&header, stored.data_profile)?;
            let envelope = manifest::envelope_bytes(
                header.key_generation,
                profile,
                &stored.nonce,
                &stored.ciphertext,
            )?;
            if envelope.len() > MAX_ARCHIVE_MANIFEST_FRAME
                || object_hash(ARCHIVE_HASH_PROFILE, &envelope).0 != stored.hash
            {
                return Err(StoreError::Integrity);
            }

            // The header's commitments about the reference set (0004 §3.5).
            let reference_digest = manifest.reference_digest()?;
            let object_count =
                u64::try_from(manifest.references().len()).map_err(|_| StoreError::Internal)?;
            let total_length = manifest
                .references()
                .iter()
                .try_fold(0u64, |total, r| total.checked_add(r.length()))
                .ok_or(StoreError::LimitExceeded)?;
            if total_length > MAX_ARCHIVE_TOTAL_LENGTH {
                return Err(StoreError::LimitExceeded);
            }

            let mut archive_header = ArchiveHeader {
                archive_id: qv_crypto::random_array::<16>().map_err(|_| StoreError::Rng)?,
                vault_id: header.vault_id,
                key_generation: header.key_generation,
                data_profile: header.data_profile,
                min_data_profile: header.min_data_profile,
                min_derivation_profile: header.min_derivation_profile,
                created_at,
                manifest_hash: stored.hash,
                reference_digest,
                object_count,
                total_length,
                header_mac: MacTag::from_bytes([0; 32]),
            };
            archive_header.seal_mac(&self.vk)?;

            write_prefix(out)?;
            let header_bytes = archive_header.encode()?;
            let header_len = u32::try_from(header_bytes.len()).map_err(|_| StoreError::Internal)?;
            if header_bytes.len() > MAX_ARCHIVE_HEADER_BYTES {
                return Err(StoreError::Internal);
            }
            out.write_all(&header_len.to_be_bytes())
                .map_err(|_| StoreError::Io)?;
            out.write_all(&header_bytes).map_err(|_| StoreError::Io)?;
            write_frame(out, &envelope)?;

            // One frame per reference, in the manifest's sorted order.
            let mut reader = ObjectReader::new(&self.file.conn)?;
            for r in manifest.references() {
                if cancelled() {
                    return Err(StoreError::Io);
                }
                accepted_profile(&header, r.data_profile().id())?;
                let (profile, nonce, ciphertext) =
                    reader.read(header.key_generation, &r.object_id().to_bytes(), r.length())?;
                if profile != r.data_profile().id()
                    || object_hash(ARCHIVE_HASH_PROFILE, &ciphertext).0 != *r.sha256()
                {
                    return Err(StoreError::Integrity);
                }
                let envelope = ObjectEnvelope {
                    object_id: r.object_id(),
                    key_generation: header.key_generation,
                    data_profile: r.data_profile(),
                    nonce,
                    ciphertext,
                }
                .encode()?;
                write_frame(out, &envelope)?;
            }
            if cancelled() {
                return Err(StoreError::Io);
            }
            Ok(ArchiveStats {
                archive_id: archive_header.archive_id_hex(),
                created_at,
                object_count,
                total_length,
                vault_id: header.vault_id,
                key_generation: header.key_generation,
            })
        }
    }

    /// A private directory of local snapshot archives (0007 §3.1).
    ///
    /// A snapshot is an archive written from verified objects; its kind lives
    /// only in the file name. Publication follows 0004 §6.5: a temp file in
    /// this directory, written, re-read and verified with the archive reader,
    /// `fsync`ed, then `RENAME_NOREPLACE`d under a new unique name, then the
    /// directory is `fsync`ed. A failure or a crash leaves at most an
    /// unpublished temp file.
    pub struct SnapshotDir {
        path: PathBuf,
    }

    impl core::fmt::Debug for SnapshotDir {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("SnapshotDir(..)")
        }
    }

    impl SnapshotDir {
        /// Opens `dir`, creating it (and missing parents) with mode 0700 if it
        /// does not exist. It must be a real directory (not a symlink) owned by
        /// the effective UID that no one else can write
        /// ([`StoreError::UnsafeFile`] otherwise).
        pub fn open(dir: &Path) -> Result<Self, StoreError> {
            match std::os::unix::fs::DirBuilderExt::mode(
                std::fs::DirBuilder::new().recursive(true),
                0o700,
            )
            .create(dir)
            {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(StoreError::Io),
            }
            fs::check_private_dir(dir)?;
            Ok(Self {
                path: dir.to_owned(),
            })
        }

        /// The directory's path.
        pub fn path(&self) -> &Path {
            &self.path
        }

        /// The default snapshot directory on Linux:
        /// `$XDG_STATE_HOME/quickvault/snapshots` if `XDG_STATE_HOME` is an
        /// absolute path, else `$HOME/.local/state/quickvault/snapshots`.
        /// [`StoreError::NotFound`] without a usable home directory;
        /// [`StoreError::Unsupported`] on Android until the platform layer
        /// provides its directory (phase 2.3).
        pub fn default_dir() -> Result<PathBuf, StoreError> {
            Self::default_dir_from(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
        }

        pub(crate) fn default_dir_from(
            xdg_state: Option<OsString>,
            home: Option<OsString>,
        ) -> Result<PathBuf, StoreError> {
            if cfg!(target_os = "android") {
                return Err(StoreError::Unsupported);
            }
            let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
            let base = match absolute(xdg_state) {
                Some(p) => p,
                None => absolute(home)
                    .ok_or(StoreError::NotFound)?
                    .join(".local")
                    .join("state"),
            };
            Ok(base.join("quickvault").join("snapshots"))
        }

        /// The path of one entry, refusing any name that is not a local
        /// snapshot file name (defence in depth: entries come from
        /// [`Self::entries`]).
        fn file(&self, entry: &SnapshotEntry) -> Result<PathBuf, StoreError> {
            let name = entry.name.to_str().ok_or(StoreError::Unsupported)?;
            parse_name(name).ok_or(StoreError::Unsupported)?;
            Ok(self.path.join(&entry.name))
        }

        /// Every local snapshot file in the directory, ascending by name.
        /// Files that are not local snapshots (temporary files, other names,
        /// directories and symlinks) are not listed. Nothing here is
        /// authenticated: call [`Self::read_header`].
        pub fn entries(&self) -> Result<Vec<SnapshotEntry>, StoreError> {
            let dir = std::fs::read_dir(&self.path).map_err(|_| StoreError::Io)?;
            let mut out = Vec::new();
            for entry in dir {
                let entry = entry.map_err(|_| StoreError::Io)?;
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                let Some((kind, _id)) = parse_name(&name) else {
                    continue;
                };
                let meta = entry.metadata().map_err(|_| StoreError::Io)?;
                if !meta.file_type().is_file() {
                    continue;
                }
                out.push(SnapshotEntry {
                    name: OsString::from(name),
                    size: meta.len(),
                    kind,
                });
            }
            out.sort_by(|a, b| a.name.cmp(&b.name));
            Ok(out)
        }

        /// Reads and authenticates one snapshot's header with the vault key
        /// (0011 `snapshot ls`). A file of another vault or generation, or a
        /// slot-bearing one, fails here (0004 §6.3, §6.4).
        pub fn read_header(
            &self,
            entry: &SnapshotEntry,
            expect: ArchiveScope,
            vk: &VaultKey,
        ) -> Result<ArchiveHeader, StoreError> {
            let file = self.open_entry(entry)?;
            let mut input = std::io::BufReader::new(file);
            let header = read_header(&mut input, expect, vk)?;
            if header.archive_id_hex() != entry.archive_id() {
                return Err(StoreError::Integrity);
            }
            Ok(header)
        }

        /// Opens one private local snapshot, never as a SQLite database.
        pub fn open_entry(&self, entry: &SnapshotEntry) -> Result<std::fs::File, StoreError> {
            fs::check_private_dir(&self.path)?;
            fs::open_private_ro(&self.file(entry)?)
        }

        /// Explicitly restores one snapshot into a new path and fresh local baseline.
        pub fn restore(
            &self,
            entry: &SnapshotEntry,
            source: &UnlockedVault,
            path: &Path,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<(), StoreError> {
            source.check_identity()?;
            let scope = ArchiveScope::new(source.header().vault_id, source.header().key_generation);
            let header = self.read_header(entry, scope, source.vault_key())?;
            let scope = scope.with_archive_id(header.archive_id());
            let mut input = std::io::BufReader::new(self.open_entry(entry)?);
            crate::VaultFile::create_from_archive(
                path,
                &mut input,
                scope,
                source.vault_key(),
                &source.anchors,
                cancelled,
            )
        }

        /// Removes one published snapshot (0007 §3.3 pruning).
        pub fn remove(&self, entry: &SnapshotEntry) -> Result<(), StoreError> {
            let path = self.file(entry)?;
            std::fs::remove_file(&path).map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => StoreError::NotFound,
                _ => StoreError::Io,
            })?;
            fs::sync_dir(&self.path)
        }

        /// Renames a recovery copy to an ordinary snapshot (0007 §3.2: after
        /// the destructive operation completes its copy is pruned like any
        /// other). Never replaces an existing name.
        pub fn reclassify_as_ordinary(
            &self,
            entry: &SnapshotEntry,
        ) -> Result<SnapshotEntry, StoreError> {
            let name = entry.name.to_str().ok_or(StoreError::Unsupported)?;
            let (kind, id) = parse_name(name).ok_or(StoreError::Unsupported)?;
            if kind == SnapshotKind::Ordinary {
                return Ok(entry.clone());
            }
            let target = format!("{id}{SNAPSHOT_SUFFIX}");
            fs::rename_noreplace(&self.path.join(&entry.name), &self.path.join(&target))?;
            fs::sync_dir(&self.path)?;
            Ok(SnapshotEntry {
                name: OsString::from(target),
                size: entry.size,
                kind: SnapshotKind::Ordinary,
            })
        }

        /// Writes, verifies and publishes a new snapshot (0004 §6.5,
        /// 0007 §3.2).
        ///
        /// The pass is: check the directory, create the temp file, write the
        /// archive, re-open the temp and verify it with the archive reader
        /// (header MAC, manifest frame hash, manifest decrypt/decode/validate,
        /// every frame's length and SHA-256 in order, exact EOF,
        /// `object_count`/`total_length`), `fsync`, `RENAME_NOREPLACE` to
        /// `<prefix><archive id>.qvsnap`, `fsync` the directory. On any
        /// failure the temp file is removed and nothing is published.
        pub fn publish(
            &self,
            vault: &mut UnlockedVault,
            kind: SnapshotKind,
            created_at: Timestamp,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<PublishedSnapshot, StoreError> {
            fs::check_private_dir(&self.path)?;
            // The temp name is not a snapshot name, so a crash never leaves a
            // file that `entries` would list (0004 §6.5).
            let placeholder = self.path.join(format!("snapshot{SNAPSHOT_SUFFIX}"));
            let (locked, temp) = fs::create_temp(&placeholder)?;
            let built = (|| -> Result<(ArchiveStats, u64), StoreError> {
                let file = locked.into_file();
                let mut file = file;
                let stats = vault.write_archive(&mut file, created_at, cancelled)?;
                let size = file.metadata().map_err(|_| StoreError::Io)?.len();

                // Re-open what is on disk under the temp's name and verify it
                // with the archive reader.
                {
                    let reopened = fs::open_private_ro(&temp)?;
                    let mut input = std::io::BufReader::new(reopened);
                    let scope =
                        ArchiveScope::new(vault.header().vault_id, vault.header().key_generation);
                    let mut sink = |_: ArchiveObject<'_>| Ok(());
                    let opened =
                        read_archive(&mut input, scope, vault.vault_key(), &mut sink, cancelled)?;
                    if opened.header().archive_id_hex() != stats.archive_id
                        || opened.manifest() != vault.manifest()
                    {
                        return Err(StoreError::Integrity);
                    }
                }
                point(CrashPoint::ArchiveVerified)?;
                rustix::fs::fsync(&file).map_err(crate::error::errno_err)?;
                drop(file);
                Ok((stats, size))
            })();
            let (stats, size) = match built {
                Ok(built) => built,
                Err(e) => {
                    fs::remove_best_effort(&temp);
                    return Err(e);
                }
            };
            let name = format!("{}{}{}", kind.prefix(), stats.archive_id, SNAPSHOT_SUFFIX);
            let target = self.path.join(&name);
            if let Err(e) = fs::rename_noreplace(&temp, &target) {
                fs::remove_best_effort(&temp);
                return Err(e);
            }
            point(CrashPoint::ArchivePublished)?;
            fs::sync_dir(&self.path)?;
            Ok(PublishedSnapshot {
                entry: SnapshotEntry {
                    name: OsString::from(name),
                    size,
                    kind,
                },
                stats,
            })
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use platform::{PublishedSnapshot, SnapshotDir, SnapshotEntry, SnapshotKind};

#[cfg(test)]
mod tests {
    use qv_crypto::VaultKey;
    use qv_encoding::{Encoder, RawValue};

    use super::*;

    const VAULT: VaultId = VaultId([0x11; 16]);

    fn sample() -> ArchiveHeader {
        ArchiveHeader {
            archive_id: [0x22; 16],
            vault_id: VAULT,
            key_generation: KeyGeneration(1),
            data_profile: StoredDataProfile::V1,
            min_data_profile: StoredDataProfile::V1,
            min_derivation_profile: DerivationProfile::V1,
            created_at: Timestamp(1_700_000_000_000),
            manifest_hash: [0x33; 32],
            reference_digest: [0x44; 32],
            object_count: 5,
            total_length: 6 * 1024,
            header_mac: MacTag::from_bytes([0; 32]),
        }
    }

    /// A sealed sample header and its VK.
    fn sealed() -> (ArchiveHeader, VaultKey) {
        let vk = VaultKey::generate().unwrap();
        let mut header = sample();
        header.seal_mac(&vk).unwrap();
        (header, vk)
    }

    fn scope() -> ArchiveScope {
        ArchiveScope::new(VAULT, KeyGeneration(1))
    }

    /// The canonical map entries of `bytes`, in stored (ascending key) order.
    fn entries(bytes: &[u8]) -> Vec<(i64, Vec<u8>)> {
        let mut d = Decoder::new(bytes).unwrap();
        let mut out = Vec::new();
        for _ in 0..d.map().unwrap() {
            let key = d.int().unwrap();
            out.push((key, d.raw_item().unwrap().to_vec()));
        }
        d.finish().unwrap();
        out
    }

    /// Re-encodes the canonical sample map after `f` changes its entries.
    fn reencode(f: impl FnOnce(&mut Vec<(i64, Vec<u8>)>)) -> Vec<u8> {
        let bytes = sample().encode().unwrap().to_vec();
        let mut list = entries(&bytes);
        f(&mut list);
        let mut e = Encoder::new();
        e.map(|m| {
            for (key, raw) in &list {
                m.raw_entry(*key, &RawValue::from_canonical(raw).unwrap())?;
            }
            Ok(())
        })
        .unwrap();
        e.finish().unwrap().to_vec()
    }

    /// Replaces the value of `key` in the canonical sample map.
    fn with_value(key: i64, value: Vec<u8>) -> Vec<u8> {
        reencode(|e| {
            if let Some(entry) = e.iter_mut().find(|(k, _)| *k == key) {
                entry.1 = value;
            }
        })
    }

    /// The shortest canonical encoding of one unsigned integer.
    fn uint(value: u64) -> Vec<u8> {
        let mut e = Encoder::new();
        e.uint(value);
        e.finish().unwrap().to_vec()
    }

    fn decode_err(bytes: &[u8]) -> Option<StoreError> {
        ArchiveHeader::decode(bytes).err()
    }

    #[test]
    fn archive_header_round_trips_canonically() {
        let (header, vk) = sealed();
        let bytes = header.encode().unwrap();
        let back = ArchiveHeader::decode(&bytes).unwrap();
        assert_eq!(back.encode().unwrap().as_slice(), bytes.as_slice());
        assert_eq!(back.archive_id(), [0x22; 16]);
        assert_eq!(back.archive_id_hex(), "22".repeat(16));
        assert_eq!(back.vault_id(), VAULT);
        assert_eq!(back.key_generation(), KeyGeneration(1));
        assert_eq!(back.data_profile(), StoredDataProfile::V1);
        assert_eq!(
            back.minimum_profiles(),
            (StoredDataProfile::V1, DerivationProfile::V1)
        );
        assert_eq!(back.created_at(), Timestamp(1_700_000_000_000));
        assert_eq!(back.object_count(), 5);
        assert_eq!(back.total_length(), 6 * 1024);
        assert_eq!(back.manifest_hash(), &[0x33; 32]);
        assert_eq!(back.reference_digest(), &[0x44; 32]);
        assert!(back.matches(scope()));
        assert_eq!(back.verify_mac(&vk), Ok(()));
        assert_eq!(format!("{back:?}"), "ArchiveHeader(..)");
        // Deterministic: a second encoding is the same bytes.
        assert_eq!(header.encode().unwrap().as_slice(), bytes.as_slice());
        // A changed field encodes differently and its own MAC verifies.
        let mut other = sample();
        other.created_at = Timestamp(1);
        other.seal_mac(&vk).unwrap();
        assert_ne!(other.encode().unwrap().as_slice(), bytes.as_slice());
        assert_eq!(
            ArchiveHeader::decode(&other.encode().unwrap())
                .unwrap()
                .verify_mac(&vk),
            Ok(())
        );
        assert!(other.matches(scope()));
    }

    #[test]
    fn archive_header_mac_binds_fields_vault_and_generation() {
        let (header, vk) = sealed();
        let good = header.encode().unwrap().to_vec();
        // A flipped MAC byte does not verify.
        let mut tampered = good.clone();
        let n = tampered.len();
        tampered[n - 1] ^= 0x01;
        assert_eq!(
            ArchiveHeader::decode(&tampered).unwrap().verify_mac(&vk),
            Err(StoreError::Integrity)
        );
        // A changed field under the old MAC does not verify: the transcript
        // covers every stored field but the MAC itself.
        let mut covered = 0;
        for (key, value) in [(2i64, uint(2)), (5, uint(1)), (8, uint(9)), (9, uint(1))] {
            let bytes = with_value(key, value);
            if let Ok(decoded) = ArchiveHeader::decode(&bytes) {
                assert_eq!(
                    decoded.verify_mac(&vk),
                    Err(StoreError::Integrity),
                    "key {key} is not covered by the MAC"
                );
                covered += 1;
            }
        }
        assert_eq!(covered, 4, "a replacement was not decodable");
        // A different VK never verifies.
        let stranger = VaultKey::generate().unwrap();
        assert_eq!(header.verify_mac(&stranger), Err(StoreError::Integrity));
        // Another vault ID and another generation each derive another key:
        // their own MAC verifies but they do not match this vault's scope.
        let mut foreign = sample();
        foreign.vault_id = VaultId([0x99; 16]);
        foreign.seal_mac(&vk).unwrap();
        assert_eq!(foreign.verify_mac(&vk), Ok(()));
        assert!(!foreign.matches(scope()));
        let mut newer = sample();
        newer.key_generation = KeyGeneration(2);
        newer.seal_mac(&vk).unwrap();
        assert_eq!(newer.verify_mac(&vk), Ok(()));
        assert!(!newer.matches(scope()));
        // The generation-2 MAC does not verify a generation-1 header.
        let mut mixed = sample();
        mixed.header_mac = MacTag::from_bytes(*newer.header_mac.as_bytes());
        assert_eq!(mixed.verify_mac(&vk), Err(StoreError::Integrity));
    }

    #[test]
    fn archive_header_rejections() {
        let (header, _) = sealed();
        let good = header.encode().unwrap().to_vec();
        // Truncated, empty, trailing bytes, garbage.
        assert_eq!(
            decode_err(&good[..good.len() - 1]),
            Some(StoreError::Integrity)
        );
        assert_eq!(decode_err(&[]), Some(StoreError::Integrity));
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert_eq!(decode_err(&trailing), Some(StoreError::Integrity));
        assert_eq!(decode_err(b"not cbor"), Some(StoreError::Integrity));
        // Over the header budget, refused before anything is parsed.
        assert_eq!(
            decode_err(&vec![0u8; MAX_ARCHIVE_HEADER_BYTES + 1]),
            Some(StoreError::LimitExceeded)
        );
        // A map claiming more entries than the bytes hold.
        let mut over = good.clone();
        over[0] = 0xad; // 13 entries claimed, 12 present
        assert_eq!(decode_err(&over), Some(StoreError::Integrity));
        // An unknown field fails closed.
        assert_eq!(
            decode_err(&reencode(|e| e.push((12, vec![0x00])))),
            Some(StoreError::Unsupported)
        );
        // A present password_slot is refused before its value is read.
        assert_eq!(
            decode_err(&reencode(|e| e.push((KEY_PASSWORD_SLOT, vec![0xa0])))),
            Some(StoreError::Integrity)
        );
        // Every required field.
        for key in [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, KEY_HEADER_MAC] {
            assert_eq!(
                decode_err(&reencode(|e| e.retain(|(k, _)| *k != key))),
                Some(StoreError::Integrity),
                "missing key {key}"
            );
        }
        // Wrong types.
        for (key, value, what) in [
            (0i64, vec![0x00], "archive_id as a uint"),
            (1, vec![0x41, 0x00], "vault_id of one byte"),
            (2, vec![0x20], "negative key generation"),
            (4, vec![0x81, 0x01], "minimum_profiles of one element"),
            (6, vec![0x00], "manifest_hash as a uint"),
            (11, vec![0x00], "header_mac as a uint"),
        ] {
            assert_eq!(
                decode_err(&with_value(key, value)),
                Some(StoreError::Integrity),
                "{what}"
            );
        }
        // Values outside their budgets or profiles.
        assert_eq!(
            decode_err(&with_value(2, vec![0x00])),
            Some(StoreError::Integrity),
            "key generation zero"
        );
        assert_eq!(
            decode_err(&with_value(3, vec![0x02])),
            Some(StoreError::Unsupported),
            "unknown stored-data profile"
        );
        assert_eq!(
            decode_err(&with_value(8, uint(MAX_OBJECTS as u64 + 1))),
            Some(StoreError::LimitExceeded),
            "object_count over the budget"
        );
        assert_eq!(
            decode_err(&with_value(9, uint(MAX_ARCHIVE_TOTAL_LENGTH + 1))),
            Some(StoreError::LimitExceeded),
            "total_length over the budget"
        );
        // A data profile below the minimum fails closed.
        let mut minimum = Encoder::new();
        minimum
            .array(|a| {
                a.uint(2);
                a.uint(1);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            decode_err(&with_value(4, minimum.finish().unwrap().to_vec())),
            Some(StoreError::Unsupported)
        );
        // A derivation minimum this build cannot satisfy fails closed.
        let mut derivation = Encoder::new();
        derivation
            .array(|a| {
                a.uint(1);
                a.uint(2);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            decode_err(&with_value(4, derivation.finish().unwrap().to_vec())),
            Some(StoreError::Unsupported)
        );
        // The unchanged header still decodes.
        assert!(ArchiveHeader::decode(&good).is_ok());
    }

    #[test]
    fn archive_header_accepts_its_own_boundaries() {
        // An empty object set and a total at the budget are valid.
        let mut header = sample();
        header.object_count = 0;
        header.total_length = MAX_ARCHIVE_TOTAL_LENGTH;
        let back = ArchiveHeader::decode(&header.encode().unwrap()).unwrap();
        assert_eq!(back.object_count(), 0);
        assert_eq!(back.total_length(), MAX_ARCHIVE_TOTAL_LENGTH);
        // A negative created_at is a clock anomaly, not damage: it decodes.
        let mut header = sample();
        header.created_at = Timestamp(-5);
        assert_eq!(
            ArchiveHeader::decode(&header.encode().unwrap())
                .unwrap()
                .created_at(),
            Timestamp(-5)
        );
    }

    #[test]
    fn archive_frames_round_trip_and_bound() {
        let mut out = Vec::new();
        write_frame(&mut out, b"hello").unwrap();
        write_frame(&mut out, b"").unwrap();
        assert_eq!(&out[..9], b"\x00\x00\x00\x05hello");
        let mut input = out.as_slice();
        let len = read_frame_len(&mut input, 16).unwrap();
        assert_eq!(read_frame(&mut input, len).unwrap(), b"hello");
        assert_eq!(read_frame_len(&mut input, 16).unwrap(), 0);
        assert!(read_frame(&mut input, 0).unwrap().is_empty());
        // A length over the caller's bound is refused before allocation.
        let mut input = out.as_slice();
        assert_eq!(
            read_frame_len(&mut input, 4),
            Err(StoreError::LimitExceeded)
        );
        // A truncated length or body is an integrity error, not a panic.
        let mut input = &out[..2];
        assert_eq!(read_frame_len(&mut input, 16), Err(StoreError::Integrity));
        let mut input = &out[..6];
        let len = read_frame_len(&mut input, 16).unwrap();
        assert_eq!(read_frame(&mut input, len), Err(StoreError::Integrity));
        // The prefix.
        let mut prefix = Vec::new();
        write_prefix(&mut prefix).unwrap();
        assert_eq!(prefix, b"QVSNAP\0\x01");
        assert_eq!(read_prefix(&mut prefix.as_slice()), Ok(()));
        for (at, value, expected) in [
            (0usize, b'X', StoreError::Integrity),
            (5usize, 0x00u8, StoreError::Integrity),
            (7usize, 0x02u8, StoreError::Unsupported),
        ] {
            let mut bytes = prefix.clone();
            bytes[at] = value;
            assert_eq!(
                read_prefix(&mut bytes.as_slice()),
                Err(expected),
                "byte {at}"
            );
        }
        assert_eq!(
            read_prefix(&mut &prefix[..4]),
            Err(StoreError::Integrity),
            "a truncated prefix"
        );
    }

    #[test]
    fn archive_scope_matches_exactly() {
        let (header, _) = sealed();
        assert!(header.matches(scope()));
        assert!(!header.matches(ArchiveScope::new(VAULT, KeyGeneration(2))));
        assert!(!header.matches(ArchiveScope::new(VaultId([0x12; 16]), KeyGeneration(1))));
        assert_eq!(scope().vault_id(), VAULT);
        assert_eq!(scope().key_generation(), KeyGeneration(1));
        assert_eq!(hex32(&[0xab; 16]), "ab".repeat(16));
        // The hash profile is the one the vault uses for references.
        assert_eq!(
            object_hash(ARCHIVE_HASH_PROFILE, b"x").0,
            object_hash(ObjectHashProfile::V1, b"x").0
        );
    }
    // --- Archive writer, publish protocol and reader ---------------------

    use crate::crash::CrashPoint;
    use crate::crash::test::{arm_dir, disarm};
    use crate::vault::tests::{PASSWORD, anchors, copy_fixture, edit, err, kdf, pw, unlock};
    use crate::vault::{UnlockedVault, VaultFile};
    use crate::{SnapshotDir, SnapshotKind};

    /// Where a test archive is written.
    const CREATED: Timestamp = Timestamp(1_700_000_000_000);

    fn scope_of(u: &UnlockedVault) -> ArchiveScope {
        ArchiveScope::new(u.header().vault_id, u.header().key_generation)
    }

    /// One vault with two entries beside the three control records. The
    /// second half of the pair keeps the anchor directory alive.
    fn vault_with(
        d: &crate::fs::test_dir::TestDir,
    ) -> (UnlockedVault, crate::fs::test_dir::TestDir) {
        let a = crate::fs::test_dir::TestDir::new();
        let (p, dir) = copy_fixture(d, &a, "v.qvault");
        let mut u = unlock(&p, &dir, PASSWORD).unwrap();
        for n in 0..2 {
            let r = <qv_crypto::RecordId as RandomId>::generate().unwrap();
            edit(&mut u, r, &format!("entry {n}"));
        }
        (u, a)
    }

    /// Writes an archive of `u`'s committed state into a buffer.
    fn archive_of(u: &mut UnlockedVault) -> Vec<u8> {
        let mut out = Vec::new();
        u.write_archive(&mut out, CREATED, &|| false).unwrap();
        out
    }

    /// The fixed prefix and header, and the frames, of an archive.
    struct Split {
        head: Vec<u8>,
        frames: Vec<Vec<u8>>,
    }

    fn split(bytes: &[u8]) -> Split {
        let len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
        let mut at = 12 + len;
        let mut frames = Vec::new();
        while at < bytes.len() {
            let n = u32::from_be_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            frames.push(bytes[at + 4..at + 4 + n].to_vec());
            at += 4 + n;
        }
        Split {
            head: bytes[..12 + len].to_vec(),
            frames,
        }
    }

    /// Rebuilds an archive from a split.
    fn join(s: &Split) -> Vec<u8> {
        let mut out = s.head.clone();
        for f in &s.frames {
            write_frame(&mut out, f).unwrap();
        }
        out
    }

    /// Replaces the header of an archive after `f` changes it, re-MACing it.
    fn rewrite_header(bytes: &[u8], vk: &VaultKey, f: impl FnOnce(&mut ArchiveHeader)) -> Vec<u8> {
        let s = split(bytes);
        let mut header = ArchiveHeader::decode(&s.head[12..]).unwrap();
        f(&mut header);
        header.seal_mac(vk).unwrap();
        let encoded = header.encode().unwrap();
        let mut out = Vec::new();
        write_prefix(&mut out).unwrap();
        out.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
        out.extend_from_slice(&encoded);
        for frame in &s.frames {
            write_frame(&mut out, frame).unwrap();
        }
        out
    }

    /// The one `.qvault` file in `d`.
    fn vault_path(d: &crate::fs::test_dir::TestDir) -> std::path::PathBuf {
        let mut paths: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|e| e == "qvault"))
            .collect();
        paths.sort();
        assert_eq!(paths.len(), 1, "expected exactly one vault file");
        paths.remove(0)
    }

    #[test]
    fn archive_round_trip_of_verified_objects() {
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let manifest = u.manifest().clone();
        let references = manifest.references().len();
        let total: u64 = manifest.references().iter().map(ObjectRef::length).sum();
        let mut out = Vec::new();
        let stats = u.write_archive(&mut out, CREATED, &|| false).unwrap();
        assert_eq!(stats.object_count, references as u64);
        assert_eq!(stats.total_length, total);
        assert_eq!(stats.vault_id, u.header().vault_id);
        assert_eq!(stats.key_generation, u.header().key_generation);
        assert_eq!(stats.created_at, CREATED);
        assert!(!out.is_empty());
        assert!(out.starts_with(&ARCHIVE_MAGIC));

        // The reader authenticates it, checks every frame against its
        // reference before any AEAD, and recovers the same manifest.
        let mut objects = 0;
        let mut sink = |o: ArchiveObject<'_>| {
            objects += 1;
            assert_eq!(o.key_generation(), u.header().key_generation);
            assert_eq!(
                object_hash(ARCHIVE_HASH_PROFILE, o.ciphertext()).0,
                *u.manifest()
                    .reference(o.object_id())
                    .ok_or(StoreError::Integrity)?
                    .sha256()
            );
            Ok(())
        };
        let opened = read_archive(
            &mut std::io::Cursor::new(&out[..]),
            scope_of(&u),
            u.vault_key(),
            &mut sink,
            &|| false,
        )
        .unwrap();
        assert_eq!(objects, references);
        assert_eq!(opened.manifest(), &manifest);
        assert_eq!(opened.header().object_count(), references as u64);
        assert_eq!(opened.header().total_length(), total);
        assert_eq!(opened.header().archive_id_hex(), stats.archive_id);
        assert_eq!(format!("{:?}", opened.header()), "ArchiveHeader(..)");

        // The header-only path agrees and stops before the frames.
        let header = read_header(
            &mut std::io::Cursor::new(&out[..]),
            scope_of(&u),
            u.vault_key(),
        )
        .unwrap();
        assert_eq!(header.archive_id(), opened.header().archive_id());

        // The frames are the manifest's references in their sorted order.
        let s = split(&out);
        assert_eq!(s.frames.len(), 1 + references);
        let mut sorted = manifest.references().to_vec();
        sorted.sort_by_key(|r| r.object_id());
        for (frame, r) in s.frames[1..].iter().zip(sorted.iter()) {
            let mut d = Decoder::new(frame).unwrap();
            assert_eq!(d.array().unwrap(), 5);
            let id: [u8; 16] = d.bytes().unwrap().try_into().unwrap();
            assert_eq!(ObjectId::from_bytes(id).unwrap(), r.object_id());
        }
    }

    // 0012 §1: Live SQLite copying
    #[test]
    fn archive_writer_aborts_on_a_corrupt_object_with_nothing_published() {
        // 0012 §1 row "Live SQLite copying": only verified objects are written.
        let cases = [
            "DELETE FROM object WHERE rowid = (SELECT min(rowid) FROM object)",
            "UPDATE object SET ciphertext = CAST(ciphertext || x'00' AS BLOB) \
             WHERE rowid = (SELECT min(rowid) FROM object)",
            "UPDATE object SET ciphertext = CAST((CASE WHEN substr(ciphertext, 1, 1) = x'00' \
             THEN x'01' ELSE x'00' END) || substr(ciphertext, 2) AS BLOB) \
             WHERE rowid = (SELECT min(rowid) FROM object)",
            "UPDATE object SET data_profile = 2 WHERE rowid = (SELECT min(rowid) FROM object)",
        ];
        for sql in cases {
            let d = crate::fs::test_dir::TestDir::new();
            let (mut u, _a) = vault_with(&d);
            u.file.conn.execute_batch(sql).unwrap();
            let mut out = Vec::new();
            assert_eq!(
                err(u.write_archive(&mut out, CREATED, &|| false)),
                StoreError::Integrity,
                "{sql}"
            );
            let _ = out;
        }
    }

    // 0012 §1: Live SQLite copying
    #[test]
    fn live_sqlite_copying_archive_is_built_from_verified_objects() {
        // 0012 §1 row "Live SQLite copying": the archive is a new stream of
        // verified objects, never a copy or normalization of the database.
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let path = vault_path(&d);
        let before = std::fs::read(&path).unwrap();
        let archive = archive_of(&mut u);
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after, "writing an archive changed the vault file");
        // No SQLite page or header is reproduced, and the archive is not the
        // database file.
        let sqlite_header = b"SQLite format 3\0";
        assert!(
            !archive
                .windows(sqlite_header.len())
                .any(|w| w == sqlite_header)
        );
        assert_ne!(archive.as_slice(), before.as_slice());
        assert!(!archive.is_empty());
        // It is exactly the prefix, the header, the manifest frame and one
        // frame per reference.
        let s = split(&archive);
        assert_eq!(s.frames.len(), 1 + u.manifest().references().len());
    }

    // 0012 §1: Live SQLite copying
    #[test]
    fn archive_during_a_concurrent_writer_is_safe() {
        // 0012 §1 row "Live SQLite copying": a concurrent writer attempt and a
        // head written behind this session's back each abort the archive.
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        // Another process cannot even open the vault (0004 §1.3).
        assert_eq!(err(VaultFile::open(&vault_path(&d))), StoreError::Locked);
        // A head written behind this session's back: the archive refuses and
        // writes nothing.
        u.file
            .conn
            .execute_batch("UPDATE local_head SET mac = zeroblob(32)")
            .unwrap();
        let mut out = Vec::new();
        assert_eq!(
            err(u.write_archive(&mut out, CREATED, &|| false)),
            StoreError::Changed
        );
        assert!(out.is_empty(), "a refused archive wrote bytes");
        // An external replacement of the path is noticed too.
        let path = vault_path(&d);
        let other = d.join("other.qvault");
        crate::fs::test_dir::write_file(&other, b"not a vault", 0o600);
        std::fs::rename(&other, &path).unwrap();
        assert_eq!(
            err(u.write_archive(&mut Vec::new(), CREATED, &|| false)),
            StoreError::Replaced
        );
    }

    /// A sink that behaves like a full disk after `limit` bytes.
    struct FullDisk {
        written: usize,
        limit: usize,
    }

    impl Write for FullDisk {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.written + buf.len() > self.limit {
                return Err(std::io::Error::from(std::io::ErrorKind::StorageFull));
            }
            self.written += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn archive_write_failure_is_io_and_publishes_nothing() {
        // A full disk during the pass is an I/O error (0011 exit 1), and
        // `publish` removes its temp file for any such failure, so no partial
        // archive is ever visible (0004 §6.5).
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let dir = snapshot_dir(&d);
        let whole = archive_of(&mut u);
        for limit in [0, 1, 16, 64, whole.len() / 2, whole.len() - 1] {
            let mut sink = FullDisk { written: 0, limit };
            assert_eq!(
                err(u.write_archive(&mut sink, CREATED, &|| false)),
                StoreError::Io,
                "limit {limit}"
            );
            assert!(sink.written <= limit);
        }
        // Whatever the pass writes is discarded with the temp file.
        assert!(dir.entries().unwrap().is_empty());
    }

    #[test]
    fn archive_cancellation_writes_nothing_and_io_is_reported() {
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let mut out = Vec::new();
        assert_eq!(
            err(u.write_archive(&mut out, CREATED, &|| true)),
            StoreError::Io
        );
        assert!(out.is_empty());
        // Cancelling a read is an I/O error too, not a silent success.
        let archive = archive_of(&mut u);
        let mut sink = |_: ArchiveObject<'_>| Ok(());
        assert_eq!(
            err(read_archive(
                &mut std::io::Cursor::new(&archive[..]),
                scope_of(&u),
                u.vault_key(),
                &mut sink,
                &|| true
            )),
            StoreError::Io
        );
    }

    // --- The publish protocol --------------------------------------------

    fn snapshot_dir(d: &crate::fs::test_dir::TestDir) -> SnapshotDir {
        SnapshotDir::open(&d.join("snapshots")).unwrap()
    }

    #[test]
    fn snapshot_publish_writes_verifies_and_lists() {
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let dir = snapshot_dir(&d);
        let stats_before = u.local_seq();
        let published = dir
            .publish(&mut u, SnapshotKind::Ordinary, CREATED, &|| false)
            .unwrap();
        assert_eq!(published.kind(), SnapshotKind::Ordinary);
        assert_eq!(published.created_at(), CREATED);
        assert_eq!(published.objects(), u.manifest().references().len() as u64);
        assert!(published.size() > 0);
        assert_eq!(u.local_seq(), stats_before, "publishing wrote to the vault");
        // The file is named after the archive ID, and nothing else is left.
        let name = published.entry().name().to_str().unwrap().to_owned();
        assert_eq!(name, format!("{}.qvsnap", published.archive_id()));
        let entries = dir.entries().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], *published.entry());
        // Its header authenticates with the vault key and names this vault.
        let header = dir
            .read_header(&entries[0], scope_of(&u), u.vault_key())
            .unwrap();
        assert_eq!(header.archive_id_hex(), published.archive_id());
        assert!(header.matches(scope_of(&u)));
        // A second publish is a second file; neither replaces the other.
        let second = dir
            .publish(&mut u, SnapshotKind::Recovery, CREATED, &|| false)
            .unwrap();
        assert_ne!(second.archive_id(), published.archive_id());
        let entries = dir.entries().unwrap();
        assert_eq!(entries.len(), 2);
        assert!(has_recovery_name(&entries));
        // The recovery copy becomes ordinary under its own name (0007 §3.2).
        let recovery = entries
            .iter()
            .find(|e| e.kind() == SnapshotKind::Recovery)
            .unwrap()
            .clone();
        let ordinary = dir.reclassify_as_ordinary(&recovery).unwrap();
        assert_eq!(ordinary.kind(), SnapshotKind::Ordinary);
        assert_eq!(
            ordinary.name().to_str().unwrap(),
            format!("{}.qvsnap", second.archive_id())
        );
        assert_eq!(dir.entries().unwrap().len(), 2);
        // Removal syncs the directory and forgets the file.
        dir.remove(published.entry()).unwrap();
        assert_eq!(dir.entries().unwrap().len(), 1);
        assert_eq!(err(dir.remove(published.entry())), StoreError::NotFound);
    }

    fn has_recovery_name(entries: &[SnapshotEntry]) -> bool {
        entries
            .iter()
            .any(|e| e.name().to_str().unwrap().starts_with("recover-"))
    }

    #[test]
    fn snapshot_publish_never_publishes_a_failure() {
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let dir = snapshot_dir(&d);
        // A corrupt object makes the writer fail after the temp file exists.
        let archive = archive_of(&mut u);
        assert!(!archive.is_empty());
        u.file
            .conn
            .execute_batch("DELETE FROM object WHERE rowid = (SELECT min(rowid) FROM object)")
            .unwrap();
        assert_eq!(
            err(dir.publish(&mut u, SnapshotKind::Recovery, CREATED, &|| false)),
            StoreError::Integrity
        );
        assert!(dir.entries().unwrap().is_empty());
        // Not even a temporary file is left behind.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert!(leftovers.is_empty(), "a failed publish left a file");
    }

    // 0012 §1: Live SQLite copying
    #[test]
    fn snapshot_publish_crash_points_leave_no_partial_archive() {
        for point in [CrashPoint::ArchiveVerified, CrashPoint::ArchivePublished] {
            let d = crate::fs::test_dir::TestDir::new();
            let snapshot = crate::fs::test_dir::TestDir::new();
            let (mut u, _a) = vault_with(&d);
            let dir = snapshot_dir(&d);
            let seq = u.local_seq();
            arm_dir(point, dir.path(), snapshot.path());
            assert_eq!(
                err(dir.publish(&mut u, SnapshotKind::Ordinary, CREATED, &|| false)),
                StoreError::Internal
            );
            assert!(!disarm(), "{point:?} was not reached");
            // What a crash leaves: at ArchiveVerified only the temp (which no
            // listing ever shows), at ArchivePublished the verified archive.
            let recovered = SnapshotDir::open(snapshot.path()).unwrap();
            let entries = recovered.entries().unwrap();
            match point {
                CrashPoint::ArchiveVerified => {
                    assert!(entries.is_empty(), "an unpublished temp is listed");
                    assert_eq!(std::fs::read_dir(snapshot.path()).unwrap().count(), 1);
                }
                _ => {
                    assert_eq!(entries.len(), 1);
                    let header = recovered
                        .read_header(&entries[0], scope_of(&u), u.vault_key())
                        .unwrap();
                    assert!(header.matches(scope_of(&u)));
                }
            }
            // The vault is unchanged either way.
            assert_eq!(u.local_seq(), seq);
        }
    }

    // 0012 §1: Exchange-file password guessing
    #[test]
    fn exchange_file_password_guessing_archives_carry_no_slot() {
        // 0012 §1 row "Exchange-file password guessing": nothing this crate
        // writes carries a password slot, and a slot-bearing header is
        // refused explicitly (0004 §6.4).
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let archive = archive_of(&mut u);
        let s = split(&archive);
        // The header has exactly the eleven documented fields and no slot:
        // its canonical map head is 0xab.
        assert_eq!(s.head[12], 0xab, "the header lost or gained a field");
        // A slot-bearing header is refused before anything is read.
        let mut entries = super::tests::entries(&s.head[12..]);
        entries.push((super::KEY_PASSWORD_SLOT, vec![0xa0]));
        let mut e = Encoder::new();
        e.map(|m| {
            for (key, raw) in &entries {
                m.raw_entry(*key, &RawValue::from_canonical(raw).unwrap())?;
            }
            Ok(())
        })
        .unwrap();
        let header = e.finish().unwrap().to_vec();
        let mut crafted = Vec::new();
        write_prefix(&mut crafted).unwrap();
        crafted.extend_from_slice(&(header.len() as u32).to_be_bytes());
        crafted.extend_from_slice(&header);
        let mut sink = |_: ArchiveObject<'_>| Ok(());
        assert_eq!(
            err(read_archive(
                &mut std::io::Cursor::new(&crafted[..]),
                scope_of(&u),
                u.vault_key(),
                &mut sink,
                &|| false
            )),
            StoreError::Integrity
        );
        // A published snapshot opens with the vault key, never with a
        // password alone: another vault's key does not authenticate it.
        let dir = snapshot_dir(&d);
        let published = dir
            .publish(&mut u, SnapshotKind::Ordinary, CREATED, &|| false)
            .unwrap();
        let (od, oa) = (
            crate::fs::test_dir::TestDir::new(),
            crate::fs::test_dir::TestDir::new(),
        );
        let foreign = {
            let _k = kdf();
            VaultFile::create(
                &od.join("other.qvault"),
                &pw(PASSWORD),
                "Other",
                &anchors(&oa),
            )
            .unwrap()
        };
        assert_eq!(
            err(dir.read_header(published.entry(), scope_of(&foreign), foreign.vault_key())),
            StoreError::Integrity,
            "another vault's key authenticated this snapshot"
        );
        assert_ne!(
            foreign.header().vault_id,
            u.header().vault_id,
            "the two vaults are not distinct"
        );
    }

    // --- The reader's rejection matrix -----------------------------------

    // 0012 §1: Hostile files from sync folders
    #[test]
    fn hostile_archive_files_are_rejected_before_any_sqlite_call() {
        // 0012 §1 row "Hostile files from sync folders": every mutation is a
        // specific error, never a panic, a huge allocation or a SQLite call.
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let good = archive_of(&mut u);
        let vk = u.vault_key();
        let scope = scope_of(&u);
        let read =
            |bytes: &[u8], sink: &mut dyn FnMut(ArchiveObject<'_>) -> Result<(), StoreError>| {
                read_archive(&mut std::io::Cursor::new(bytes), scope, vk, sink, &|| false)
            };
        let mut sink = |_: ArchiveObject<'_>| Ok(());
        assert!(read(&good, &mut sink).is_ok());

        // Truncated at every interesting boundary.
        assert_eq!(err(read(&good[..7], &mut sink)), StoreError::Integrity);
        assert_eq!(
            err(read(&good[..good.len() - 1], &mut sink)),
            StoreError::Integrity
        );
        // Trailing bytes.
        let mut trailing = good.clone();
        trailing.push(0x00);
        assert_eq!(err(read(&trailing, &mut sink)), StoreError::Integrity);
        // A wrong magic.
        let mut magic = good.clone();
        magic[0] = b'X';
        assert_eq!(err(read(&magic, &mut sink)), StoreError::Integrity);
        // Another format version.
        let mut version = good.clone();
        version[7] = 0x02;
        assert_eq!(err(read(&version, &mut sink)), StoreError::Unsupported);
        // A header length over the budget, refused before allocation.
        let mut oversized = good.clone();
        oversized[8..12].copy_from_slice(&(MAX_ARCHIVE_HEADER_BYTES as u32 + 1).to_be_bytes());
        assert_eq!(err(read(&oversized, &mut sink)), StoreError::LimitExceeded);

        let s = split(&good);
        // A missing final frame.
        let mut missing = s.frames.clone();
        missing.pop();
        let bytes = join(&Split {
            head: s.head.clone(),
            frames: missing,
        });
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // An extra frame after the last reference.
        let mut extra = s.frames.clone();
        extra.push(s.frames[1].clone());
        let bytes = join(&Split {
            head: s.head.clone(),
            frames: extra,
        });
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // Two object frames swapped.
        let mut swapped = s.frames.clone();
        swapped.swap(1, 2);
        let bytes = join(&Split {
            head: s.head.clone(),
            frames: swapped,
        });
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // One object frame duplicated in place of another.
        let mut doubled = s.frames.clone();
        doubled[2] = doubled[1].clone();
        let bytes = join(&Split {
            head: s.head.clone(),
            frames: doubled,
        });
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // A substituted ciphertext byte in the first object frame.
        let mut substituted = s.frames.clone();
        let n = substituted[1].len();
        substituted[1][n - 1] ^= 0x01;
        let bytes = join(&Split {
            head: s.head.clone(),
            frames: substituted,
        });
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // A lying frame length: one that is short, one that is long.
        let mut short = good.clone();
        let first = 12 + (s.head.len() - 12) + 4 + s.frames[0].len();
        short[first..first + 4].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(err(read(&short, &mut sink)), StoreError::Integrity);
        let mut long = good.clone();
        long[first..first + 4]
            .copy_from_slice(&(u32::try_from(s.frames[1].len() + 8).unwrap()).to_be_bytes());
        assert_eq!(err(read(&long, &mut sink)), StoreError::Integrity);
        // A frame length over the object budget.
        let mut huge = good.clone();
        huge[first..first + 4].copy_from_slice(&(u32::MAX).to_be_bytes());
        assert_eq!(err(read(&huge, &mut sink)), StoreError::LimitExceeded);
        // A manifest frame length over the manifest budget.
        let mut big_manifest = good.clone();
        let at = 8 + 4 + (s.head.len() - 12);
        big_manifest[at..at + 4]
            .copy_from_slice(&(MAX_ARCHIVE_MANIFEST_FRAME as u32 + 1).to_be_bytes());
        assert_eq!(
            err(read(&big_manifest, &mut sink)),
            StoreError::LimitExceeded
        );
        // A substituted manifest frame.
        let mut manifest = s.frames.clone();
        let n = manifest[0].len();
        manifest[0][n - 1] ^= 0x01;
        let bytes = join(&Split {
            head: s.head.clone(),
            frames: manifest,
        });
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // Wrong object_count and total_length under a valid MAC.
        let bytes = rewrite_header(&good, vk, |h| h.object_count = 99);
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        let bytes = rewrite_header(&good, vk, |h| h.total_length += 1);
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // Another generation, and another vault ID.
        let bytes = rewrite_header(&good, vk, |h| h.key_generation = KeyGeneration(2));
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        let bytes = rewrite_header(&good, vk, |h| h.vault_id = VaultId([0x99; 16]));
        assert_eq!(err(read(&bytes, &mut sink)), StoreError::Integrity);
        // The unchanged archive still reads.
        assert!(read(&good, &mut sink).is_ok());
        // No archive byte ever reached SQLite: the vault is untouched.
        drop(u);
    }

    #[test]
    fn archive_reader_agrees_with_the_manifest_configuration_digest() {
        // 0004 §3.4: the manifest's configuration digest must describe the
        // archive header's vault ID, generation and minima. Every namespace
        // has one profile in this format version, so a mismatch with an
        // otherwise valid MAC cannot be constructed; this pins the agreement
        // the reader checks and shows the digest is bound to both fields that
        // are not in the manifest itself (1.16 freezes the profile set).
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let good = archive_of(&mut u);
        let vk = u.vault_key();
        let scope = scope_of(&u);
        let mut sink = |_: ArchiveObject<'_>| Ok(());
        let opened = read_archive(
            &mut std::io::Cursor::new(&good[..]),
            scope,
            vk,
            &mut sink,
            &|| false,
        )
        .unwrap();
        let digest = config_digest_for(
            u.header().vault_id,
            u.header().key_generation,
            u.header().min_data_profile,
            u.header().min_derivation_profile,
        )
        .unwrap();
        assert_eq!(*opened.manifest().config_digest(), digest);
        let (min_data, min_derivation) = opened.header().minimum_profiles();
        assert_eq!(
            digest,
            config_digest_for(
                opened.header().vault_id(),
                opened.header().key_generation(),
                min_data,
                min_derivation
            )
            .unwrap()
        );
        // The digest binds the vault ID and the generation.
        assert_ne!(
            digest,
            config_digest_for(
                VaultId([0x99; 16]),
                u.header().key_generation,
                min_data,
                min_derivation
            )
            .unwrap()
        );
        assert_ne!(
            digest,
            config_digest_for(
                u.header().vault_id,
                KeyGeneration(2),
                min_data,
                min_derivation
            )
            .unwrap()
        );
    }

    #[test]
    fn snapshot_dir_ignores_foreign_files_and_rejects_unsafe_names() {
        let d = crate::fs::test_dir::TestDir::new();
        let dir = snapshot_dir(&d);
        let entries = dir.entries().unwrap();
        assert!(entries.is_empty());
        // Not snapshot names: a temp file, an uppercase ID, a short ID, a
        // directory and a symlink are never listed.
        crate::fs::test_dir::write_file(&dir.path().join(".snapshot.qvsnap.tmp-00"), b"x", 0o600);
        crate::fs::test_dir::write_file(
            &dir.path().join(format!("{}.qvsnap", "AB".repeat(16))),
            b"x",
            0o600,
        );
        crate::fs::test_dir::write_file(&dir.path().join("abcd.qvsnap"), b"x", 0o600);
        crate::fs::test_dir::write_file(&dir.path().join("notes.txt"), b"x", 0o600);
        std::fs::create_dir(dir.path().join(format!("{}.qvsnap", "cd".repeat(16)))).unwrap();
        assert!(dir.entries().unwrap().is_empty());
        // An unsafe directory is refused.
        let shared = d.subdir("shared", 0o770);
        assert_eq!(
            SnapshotDir::open(&shared).err(),
            Some(StoreError::UnsafeFile)
        );
        // The default directory follows the XDG state directory.
        let os = |s: &str| Some(std::ffi::OsString::from(s));
        assert_eq!(
            SnapshotDir::default_dir_from(os("/state"), os("/home/u")).unwrap(),
            std::path::PathBuf::from("/state/quickvault/snapshots")
        );
        assert_eq!(
            SnapshotDir::default_dir_from(None, os("/home/u")).unwrap(),
            std::path::PathBuf::from("/home/u/.local/state/quickvault/snapshots")
        );
        assert_eq!(
            SnapshotDir::default_dir_from(os("rel"), None).err(),
            Some(StoreError::NotFound)
        );
        assert_eq!(format!("{dir:?}"), "SnapshotDir(..)");
    }
    #[test]
    fn archive_rejects_nonce_only_corruption_in_every_role_before_sink() {
        let (_d, _a, mut u, _record) = crate::verify_tests::setup();
        let good = archive_of(&mut u);
        let original = split(&good);
        for index in 1..original.frames.len() {
            let mut parts = split(&good);
            let frame = &mut parts.frames[index];
            let mut d = Decoder::new(frame).unwrap();
            d.array().unwrap();
            d.bytes().unwrap();
            d.uint().unwrap();
            d.uint().unwrap();
            let nonce = d.bytes().unwrap();
            let offset = nonce.as_ptr() as usize - frame.as_ptr() as usize;
            frame[offset] ^= 1;
            let bad = join(&parts);
            let mut delivered = 0;
            assert_eq!(
                err(read_archive(
                    &mut std::io::Cursor::new(bad),
                    scope_of(&u),
                    u.vault_key(),
                    &mut |_| {
                        delivered += 1;
                        Ok(())
                    },
                    &|| false
                )),
                StoreError::Integrity,
                "frame {index}"
            );
            assert_eq!(delivered, 0);
        }
    }

    // 0012 §1: Self-referential/incomplete commitments
    #[test]
    fn archive_rejects_wrong_reference_digest_before_sink() {
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let good = archive_of(&mut u);
        let bad = rewrite_header(&good, u.vault_key(), |h| h.reference_digest[0] ^= 1);
        let mut delivered = 0;
        assert_eq!(
            err(read_archive(
                &mut std::io::Cursor::new(bad),
                scope_of(&u),
                u.vault_key(),
                &mut |_| {
                    delivered += 1;
                    Ok(())
                },
                &|| false
            )),
            StoreError::Integrity
        );
        assert_eq!(delivered, 0);
    }

    #[test]
    fn archive_publish_rejects_corrupt_history_and_chunks_after_unlock() {
        let (d, a, mut u, record) = crate::verify_tests::setup();
        let path = vault_path(&d);
        let history = u.manifest().record(record).unwrap().history()[0].object_id();
        let chunk = crate::verify_tests::chunk_object(&u);
        let dir = snapshot_dir(&d);
        dir.publish(&mut u, SnapshotKind::Ordinary, CREATED, &|| false)
            .unwrap();
        for id in [history, chunk] {
            let nonce: Vec<u8> = u
                .file
                .conn
                .query_row(
                    "SELECT nonce FROM object WHERE object_id = ?1",
                    [id.to_bytes().as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            u.file
                .conn
                .execute(
                    "UPDATE object SET nonce = zeroblob(24) WHERE object_id = ?1",
                    [id.to_bytes().as_slice()],
                )
                .unwrap();
            drop(u);
            let anchors = crate::AnchorDir::open(&a.join("anchors")).unwrap();
            u = unlock(&path, &anchors, PASSWORD).unwrap();
            assert_eq!(
                err(dir.publish(&mut u, SnapshotKind::Recovery, CREATED, &|| false)),
                StoreError::Integrity
            );
            assert_eq!(
                dir.entries().unwrap().len(),
                1,
                "failed publication changed old copies"
            );
            u.file
                .conn
                .execute(
                    "UPDATE object SET nonce = ?1 WHERE object_id = ?2",
                    rusqlite::params![nonce, id.to_bytes().as_slice()],
                )
                .unwrap();
        }
    }

    #[test]
    fn archive_rejects_frame_changes_between_verification_passes() {
        struct Changed {
            cursor: std::io::Cursor<Vec<u8>>,
            offset: usize,
            changed: bool,
        }
        impl Read for Changed {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                self.cursor.read(b)
            }
        }
        impl Seek for Changed {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                if matches!(pos, SeekFrom::Start(_)) && !self.changed {
                    self.cursor.get_mut()[self.offset] ^= 1;
                    self.changed = true;
                }
                self.cursor.seek(pos)
            }
        }
        let d = crate::fs::test_dir::TestDir::new();
        let (mut u, _a) = vault_with(&d);
        let good = archive_of(&mut u);
        let parts = split(&good);
        let offset = parts.head.len() + 4 + parts.frames[0].len() + 4 + parts.frames[1].len() - 1;
        let mut input = Changed {
            cursor: std::io::Cursor::new(good),
            offset,
            changed: false,
        };
        let mut delivered = 0;
        assert_eq!(
            err(read_archive(
                &mut input,
                scope_of(&u),
                u.vault_key(),
                &mut |_| {
                    delivered += 1;
                    Ok(())
                },
                &|| false
            )),
            StoreError::Integrity
        );
        assert_eq!(delivered, 0);
    }
}
