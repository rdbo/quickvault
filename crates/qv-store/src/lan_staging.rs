// SPDX-License-Identifier: AGPL-3.0-or-later

//! New-device staging (0013 §4.7, §10; plan 0037 decision 3).
//!
//! A joining device receives a peer's manifest envelope and every object it
//! references. It stages them in exact archive format (0004 §6) in an
//! unlinked private file, so the existing reader and restore protocol do all
//! the work:
//! 1. [`LanStaging::begin`] bounds and hashes the envelope, then decrypts and
//!    validates the manifest under the received VK. The configuration digest
//!    must match the only registered minima (stored-data/1, derivation/1);
//!    otherwise [`StoreError::Unsupported`]. It then checks the budgets and
//!    writes the prefix, a header MAC'd under VK, and the manifest frame.
//! 2. [`LanStaging::add_object`] takes objects in sorted reference order.
//!    Each one's ID, generation, profile, exact length and SHA-256 are
//!    checked against its authenticated reference before the frame is
//!    appended.
//! 3. [`LanStaging::finish`] runs the full archive authentication (every
//!    role and attachment, exact EOF) before anything is shown or kept.
//!
//! [`VerifiedLanStaging`] then answers the §10 questions (the keyslot, the
//! vault's name, the master password). [`crate::VaultFile::create_from_lan`]
//! builds the vault through the 1.13b creation protocol. No staged byte
//! reaches SQLite before full verification, and nothing is published before
//! the last step.

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use qv_crypto::{
    DerivationProfile, KeyGeneration, MasterPassword, ObjectHashProfile, SecretBytes,
    StoredDataProfile, VaultId, VaultKey, object_hash, purpose,
};
use qv_encoding::Decoder;
use qv_model::{ObjectId, Payload, RandomId, RecordBody};

use zeroize::Zeroizing;

use crate::archive::{ArchiveHeader, OpenedArchive, object_envelope, read_archive, write_prefix};
use crate::manifest::{Manifest, config_digest_for, open_manifest};
use crate::object::Scope;
use crate::{
    ArchiveScope, MAX_ARCHIVE_HEADER_BYTES, MAX_ARCHIVE_MANIFEST_FRAME, MAX_ARCHIVE_OBJECT_FRAME,
    MAX_ARCHIVE_TOTAL_LENGTH, MAX_OBJECTS, StoreError, fs,
};

/// The name the unlinked staging file is created under.
const STAGING_NAME: &str = "lan-staging.qvsnap";

fn malformed<T>(_: T) -> StoreError {
    StoreError::Integrity
}

fn check_cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
    if cancelled() {
        Err(StoreError::Io)
    } else {
        Ok(())
    }
}

/// A staging archive being received.
pub struct LanStaging {
    file: File,
    header: ArchiveHeader,
    wanted: Vec<ObjectId>,
    manifest: Manifest,
    next: usize,
}

impl core::fmt::Debug for LanStaging {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanStaging(..)")
    }
}

impl LanStaging {
    /// Verifies the peer's manifest envelope and starts the staging file in
    /// `private_dir` (see the module docs for the order of checks).
    #[allow(clippy::too_many_arguments)] // the scope, the envelope and its hash
    pub fn begin(
        private_dir: &Path,
        vk: &VaultKey,
        vault: VaultId,
        generation: KeyGeneration,
        manifest_hash: &[u8; 32],
        envelope: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, StoreError> {
        check_cancel(cancelled)?;
        fs::check_private_dir(private_dir)?;
        if envelope.len() > MAX_ARCHIVE_MANIFEST_FRAME {
            return Err(StoreError::LimitExceeded);
        }
        if object_hash(ObjectHashProfile::V1, envelope).0 != *manifest_hash {
            return Err(StoreError::Integrity);
        }
        let mut d = Decoder::new(envelope).map_err(malformed)?;
        if d.array().map_err(malformed)? != 4 {
            return Err(StoreError::Integrity);
        }
        if u32::try_from(d.uint().map_err(malformed)?).map_err(malformed)? != generation.0 {
            return Err(StoreError::Integrity);
        }
        let profile = StoredDataProfile::from_id(
            u16::try_from(d.uint().map_err(malformed)?).map_err(malformed)?,
        )?;
        let nonce: [u8; 24] = d
            .bytes()
            .map_err(malformed)?
            .try_into()
            .map_err(malformed)?;
        let ciphertext = d.bytes().map_err(malformed)?;
        d.finish().map_err(malformed)?;
        let minimum = (StoredDataProfile::V1, DerivationProfile::V1);
        let key = vk.purpose_key::<purpose::Manifest>(vault, generation, minimum.1)?;
        let scope = Scope {
            vault_id: vault,
            key_generation: generation,
        };
        let manifest = open_manifest(&key, scope, profile, &nonce, ciphertext)?;
        if *manifest.config_digest() != config_digest_for(vault, generation, minimum.0, minimum.1)?
        {
            return Err(StoreError::Unsupported);
        }
        let references = manifest.references();
        if references.len() > MAX_OBJECTS {
            return Err(StoreError::LimitExceeded);
        }
        let total = references
            .iter()
            .try_fold(0u64, |t, r| t.checked_add(r.length()))
            .filter(|t| *t <= MAX_ARCHIVE_TOTAL_LENGTH)
            .ok_or(StoreError::LimitExceeded)?;
        let header = ArchiveHeader::for_staging(
            vault,
            generation,
            profile,
            minimum,
            *manifest_hash,
            manifest.reference_digest()?,
            u64::try_from(references.len()).map_err(|_| StoreError::LimitExceeded)?,
            total,
            vk,
        )?;
        let wanted = references.iter().map(|r| r.object_id()).collect();

        let name = private_dir.join(STAGING_NAME);
        fs::remove_stale_temps(&name)?;
        let (locked, temp) = fs::create_temp(&name)?;
        // Unlinked before any content: success, failure or cancellation
        // leaves no name; a crash in the gap leaves an empty file that the
        // next attempt removes.
        if std::fs::remove_file(&temp).is_err() {
            fs::remove_best_effort(&temp);
            return Err(StoreError::Io);
        }
        let mut file = locked.into_file();
        write_prefix(&mut file)?;
        let header_bytes = header.encode()?;
        if header_bytes.len() > MAX_ARCHIVE_HEADER_BYTES {
            return Err(StoreError::Internal);
        }
        let len = u32::try_from(header_bytes.len()).map_err(|_| StoreError::Internal)?;
        file.write_all(&len.to_be_bytes())
            .map_err(|_| StoreError::Io)?;
        file.write_all(&header_bytes).map_err(|_| StoreError::Io)?;
        crate::archive::write_frame(&mut file, envelope)?;
        Ok(Self {
            file,
            header,
            wanted,
            manifest,
            next: 0,
        })
    }

    /// The object IDs to request, in sorted reference order.
    pub fn wanted(&self) -> &[ObjectId] {
        &self.wanted
    }

    /// The verified manifest being staged.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Appends the next expected object. Another ID (unrequested, duplicate
    /// or out of order) is [`StoreError::NotFound`]; a wrong generation,
    /// profile, length or SHA-256 is [`StoreError::Integrity`], checked
    /// before anything is written.
    pub fn add_object(&mut self, envelope: &[u8]) -> Result<(), StoreError> {
        if envelope.len() > MAX_ARCHIVE_OBJECT_FRAME {
            return Err(StoreError::LimitExceeded);
        }
        let Some(&expected) = self.wanted.get(self.next) else {
            return Err(StoreError::NotFound);
        };
        let mut d = Decoder::new(envelope).map_err(malformed)?;
        if d.array().map_err(malformed)? != 5 {
            return Err(StoreError::Integrity);
        }
        let id: [u8; 16] = d
            .bytes()
            .map_err(malformed)?
            .try_into()
            .map_err(malformed)?;
        if id != expected.to_bytes() {
            return Err(StoreError::NotFound);
        }
        let reference = &self.manifest.references()[self.next];
        object_envelope(envelope, &self.header, reference)?;
        crate::archive::write_frame(&mut self.file, envelope)?;
        self.next += 1;
        Ok(())
    }

    /// Requires every wanted object, then authenticates the complete staging
    /// archive with the archive reader.
    pub fn finish(
        mut self,
        vk: &VaultKey,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedLanStaging, StoreError> {
        if self.next != self.wanted.len() {
            return Err(StoreError::Integrity);
        }
        self.file.flush().map_err(|_| StoreError::Io)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| StoreError::Io)?;
        let scope = self.scope();
        let opened = read_archive(&mut self.file, scope, vk, &mut |_| Ok(()), cancelled)?;
        Ok(VerifiedLanStaging {
            file: self.file,
            opened,
            scope,
        })
    }

    fn scope(&self) -> ArchiveScope {
        ArchiveScope::new(self.header.vault_id(), self.header.key_generation())
            .with_archive_id(self.header.archive_id())
    }
}

/// The keyslot state of a staged vault (0013 §10 step 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StagedKeyslot {
    /// Exactly one verified password keyslot head.
    Unique,
    /// No keyslot record.
    Missing,
    /// Several keyslot heads: resolve on the approving device first.
    Conflicted,
}

/// A fully authenticated staging archive.
pub struct VerifiedLanStaging {
    pub(crate) file: File,
    opened: OpenedArchive,
    pub(crate) scope: ArchiveScope,
}

impl core::fmt::Debug for VerifiedLanStaging {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedLanStaging(..)")
    }
}

/// Proof that a master password unlocks the staged keyslot to the received
/// VK; consumed by [`crate::VaultFile::create_from_lan`].
pub struct PasswordProof {
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for PasswordProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PasswordProof(<redacted>)")
    }
}

impl VerifiedLanStaging {
    /// The authenticated manifest.
    pub fn manifest(&self) -> &Manifest {
        self.opened.manifest()
    }

    fn read_head(
        &mut self,
        vk: &VaultKey,
        record: qv_crypto::RecordId,
    ) -> Result<Option<qv_model::RecordVersion>, StoreError> {
        let manifest = self.opened.manifest();
        let Some(entry) = manifest.record(record) else {
            return Ok(None);
        };
        let Some(role) = entry.heads().first() else {
            return Err(StoreError::Integrity);
        };
        let header = self.opened.header();
        let key = vk.purpose_key::<purpose::Record>(
            header.vault_id(),
            header.key_generation(),
            crate::ARCHIVE_DERIVATION_PROFILE,
        )?;
        let version = crate::archive_verify::read_version(
            &mut self.file,
            header,
            manifest,
            &self.opened.frames,
            &key,
            record,
            role,
        )?;
        Ok(Some(version))
    }

    /// Whether the staged vault has exactly one password keyslot head.
    pub fn keyslot(&mut self, vk: &VaultKey) -> Result<StagedKeyslot, StoreError> {
        let id = self.opened.manifest().keyslot_id();
        let heads = self
            .opened
            .manifest()
            .record(id)
            .map_or(0, |e| e.heads().len());
        match heads {
            0 => Ok(StagedKeyslot::Missing),
            1 => match self.read_head(vk, id)?.map(|v| v.body) {
                Some(RecordBody::Live(Payload::PasswordKeyslot(_))) => Ok(StagedKeyslot::Unique),
                Some(_) => Ok(StagedKeyslot::Missing),
                None => Err(StoreError::Integrity),
            },
            _ => Ok(StagedKeyslot::Conflicted),
        }
    }

    /// The vault's name (the first head of the vault-meta record), display
    /// only.
    pub fn vault_name(&mut self, vk: &VaultKey) -> Result<SecretBytes, StoreError> {
        let id = self.opened.manifest().vault_meta_id();
        let Some(RecordBody::Live(Payload::VaultMeta(meta))) =
            self.read_head(vk, id)?.map(|v| v.body)
        else {
            return Err(StoreError::Integrity);
        };
        let name = meta.name.expose().as_bytes();
        SecretBytes::try_init(name.len(), |out| {
            out.copy_from_slice(name);
            Ok::<(), StoreError>(())
        })
    }

    /// Unlocks the unique keyslot with `password` and requires the result
    /// to be `vk`. A wrong password is [`StoreError::WrongPassword`]; a
    /// keyslot that wraps another key is [`StoreError::Integrity`].
    pub fn verify_password(
        &mut self,
        vk: &VaultKey,
        password: &MasterPassword,
    ) -> Result<PasswordProof, StoreError> {
        let id = self.opened.manifest().keyslot_id();
        if self.keyslot(vk)? != StagedKeyslot::Unique {
            return Err(StoreError::Integrity);
        }
        let Some(RecordBody::Live(Payload::PasswordKeyslot(descriptor))) =
            self.read_head(vk, id)?.map(|v| v.body)
        else {
            return Err(StoreError::Integrity);
        };
        let scope = self.scope;
        let unwrapped = descriptor
            .slot
            .unlock(password, scope.vault_id(), scope.key_generation())
            .map_err(|e| match e {
                qv_crypto::CryptoError::WrongPassword => StoreError::WrongPassword,
                qv_crypto::CryptoError::LimitExceeded => StoreError::LimitExceeded,
                _ => StoreError::Integrity,
            })?;
        if !unwrapped.ct_eq(vk) {
            return Err(StoreError::Integrity);
        }
        Ok(PasswordProof {
            body: descriptor.encode()?,
        })
    }

    /// Rewinds the staging file for the creation pass.
    pub(crate) fn rewind(&mut self) -> Result<&mut File, StoreError> {
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|_| StoreError::Io)?;
        Ok(&mut self.file)
    }
}

/// The first link of a vault created from a pairing (0013 §10 step 5).
pub struct NewLanLink<'a> {
    /// The link ID from the grant.
    pub link_id: [u8; 16],
    /// The link key.
    pub key: &'a qv_crypto::lan::LinkKey,
    /// The user's label for the approving device.
    pub label: &'a str,
    /// Creation time.
    pub created_at: qv_model::Timestamp,
}

impl core::fmt::Debug for NewLanLink<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NewLanLink(<redacted>)")
    }
}
