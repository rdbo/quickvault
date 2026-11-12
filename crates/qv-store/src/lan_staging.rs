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
//! vault's name, the granted head binding). [`crate::VaultFile::create_from_verified_lan`]
//! builds the vault through the 1.13b creation protocol. No staged byte
//! reaches SQLite before full verification, and nothing is published before
//! the last step.

use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

use qv_crypto::{
    DerivationProfile, KeyGeneration, MasterPassword, ObjectHashProfile, SecretBytes,
    StoredDataProfile, VaultId, VaultKey, object_hash, purpose,
};
use qv_encoding::Decoder;
use qv_model::{ObjectId, Payload, RandomId, RecordBody};

use zeroize::Zeroizing;

use crate::archive::{ArchiveHeader, object_envelope, read_archive, write_prefix};
use crate::incoming::StagedArchive;
use crate::manifest::{Manifest, ObjectRef, config_digest_for, open_manifest};
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

/// Where the next object of a staging comes from (0013 §7.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Planned {
    /// This vault holds an identical object; it is copied from its row.
    Local,
    /// It is requested from the peer.
    Peer,
}

/// A staging archive being received.
pub struct LanStaging {
    file: fs::ArchiveFile,
    header: ArchiveHeader,
    plan: Vec<(ObjectId, Planned)>,
    manifest: Manifest,
    next: usize,
}

impl core::fmt::Debug for LanStaging {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanStaging(..)")
    }
}

/// The expectations a staging checks a peer's manifest against.
pub(crate) struct StagingScope {
    pub(crate) vault: VaultId,
    pub(crate) generation: KeyGeneration,
    /// The archive header's minimum profiles.
    pub(crate) minimum: (StoredDataProfile, DerivationProfile),
}

impl LanStaging {
    /// Verifies the peer's manifest envelope and starts the staging file in
    /// `private_dir` for a new device: every object is requested (see the
    /// module docs for the order of checks).
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
        let scope = StagingScope {
            vault,
            generation,
            minimum: (StoredDataProfile::V1, DerivationProfile::V1),
        };
        Self::start(
            private_dir,
            vk,
            &scope,
            manifest_hash,
            envelope,
            &mut |_| Ok(Planned::Peer),
            cancelled,
        )
    }

    /// The shared start: bounds, hash, envelope, manifest under `vk`, the
    /// configuration digest of `scope`'s minima (else Unsupported), budgets,
    /// the plan, then the unlinked file.
    pub(crate) fn start(
        private_dir: &Path,
        vk: &VaultKey,
        scope: &StagingScope,
        manifest_hash: &[u8; 32],
        envelope: &[u8],
        plan_of: &mut dyn FnMut(&ObjectRef) -> Result<Planned, StoreError>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, StoreError> {
        let (vault, generation, minimum) = (scope.vault, scope.generation, scope.minimum);
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
        let key = vk.purpose_key::<purpose::Manifest>(
            vault,
            generation,
            crate::ARCHIVE_DERIVATION_PROFILE,
        )?;
        let manifest_scope = Scope {
            vault_id: vault,
            key_generation: generation,
        };
        let manifest = open_manifest(&key, manifest_scope, profile, &nonce, ciphertext)?;
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
        let mut plan = Vec::with_capacity(references.len());
        for r in references {
            check_cancel(cancelled)?;
            plan.push((r.object_id(), plan_of(r)?));
        }
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

        let name = private_dir.join(STAGING_NAME);
        fs::remove_stale_temps(&name)?;
        let (locked, temp) = fs::create_temp(&name)?;
        // Unlinked before any content: success, failure or cancellation
        // leaves no name; a crash in the gap leaves an empty file that the
        // next attempt removes.
        if fs::remove_file(&temp).is_err() {
            fs::remove_best_effort(&temp);
            return Err(StoreError::Io);
        }
        let mut file = locked.into_archive_file();
        write_prefix(&mut file)?;
        let header_bytes = header.encode()?;
        if header_bytes.len() > MAX_ARCHIVE_HEADER_BYTES {
            return Err(StoreError::Internal);
        }
        let len = u32::try_from(header_bytes.len()).map_err(|_| StoreError::Internal)?;
        file.write_all(&len.to_be_bytes())
            .map_err(crate::error::io_err)?;
        file.write_all(&header_bytes)
            .map_err(crate::error::io_err)?;
        crate::archive::write_frame(&mut file, envelope)?;
        Ok(Self {
            file,
            header,
            plan,
            manifest,
            next: 0,
        })
    }

    /// Every peer reference in archive order with its source.
    pub fn plan(&self) -> &[(ObjectId, Planned)] {
        &self.plan
    }

    /// The objects to request from the peer, in order.
    pub fn requested(&self) -> Vec<ObjectId> {
        self.plan
            .iter()
            .filter(|(_, p)| *p == Planned::Peer)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Where the next object comes from, or `None` once every planned
    /// object is staged.
    pub fn next(&self) -> Option<Planned> {
        self.plan.get(self.next).map(|(_, p)| *p)
    }

    /// The verified manifest being staged.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Appends the next expected peer object. Another ID (unrequested,
    /// duplicate or out of order) is [`StoreError::NotFound`]; a wrong
    /// generation, profile, length or SHA-256 is [`StoreError::Integrity`],
    /// checked before anything is written.
    pub fn add_object(&mut self, envelope: &[u8]) -> Result<(), StoreError> {
        self.append(envelope, Planned::Peer)
    }

    /// Appends the next planned object from `envelope`, which must come from
    /// `source`'s side of the plan.
    pub(crate) fn append(&mut self, envelope: &[u8], source: Planned) -> Result<(), StoreError> {
        if envelope.len() > MAX_ARCHIVE_OBJECT_FRAME {
            return Err(StoreError::LimitExceeded);
        }
        let Some(&(expected, planned)) = self.plan.get(self.next) else {
            return Err(StoreError::NotFound);
        };
        if planned != source {
            return Err(StoreError::NotFound);
        }
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

    /// The reference of the next planned object.
    pub(crate) fn next_reference(&self) -> Option<&ObjectRef> {
        self.manifest.references().get(self.next)
    }

    /// Requires every planned object, then authenticates the complete
    /// staging archive with the archive reader.
    pub fn finish(
        mut self,
        vk: &VaultKey,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedLanStaging, StoreError> {
        if self.next != self.plan.len() {
            return Err(StoreError::Integrity);
        }
        self.file.flush().map_err(crate::error::io_err)?;
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(crate::error::io_err)?;
        let scope = self.scope();
        let opened = read_archive(&mut self.file, scope, vk, &mut |_| Ok(()), cancelled)?;
        Ok(VerifiedLanStaging {
            archive: StagedArchive {
                file: self.file,
                opened,
            },
            scope,
        })
    }

    fn scope(&self) -> ArchiveScope {
        ArchiveScope::new(self.header.vault_id(), self.header.key_generation())
            .with_archive_id(self.header.archive_id())
    }
}

impl crate::UnlockedVault {
    /// Starts staging a peer's state for a merge into this vault (0013
    /// §7.3–7.5). The checks run in the order of [`LanStaging::begin`],
    /// against this vault's ID, generation, VK and configuration (another
    /// configuration is [`StoreError::Unsupported`]). Each reference this
    /// vault holds identically is planned [`Planned::Local`]; one it holds
    /// under the same ID with another reference is [`StoreError::Integrity`]
    /// (substitution evidence); the rest are [`Planned::Peer`].
    ///
    /// The staging file is created unlinked in this vault's private anchor
    /// directory, as for a new device.
    pub fn lan_stage(
        &self,
        manifest_hash: &[u8; 32],
        envelope: &[u8],
        cancelled: &dyn Fn() -> bool,
    ) -> Result<LanStaging, StoreError> {
        let private_dir = self.anchors.path().to_path_buf();
        let header = self.file.header;
        let scope = StagingScope {
            vault: header.vault_id,
            generation: header.key_generation,
            minimum: (header.min_data_profile, header.min_derivation_profile),
        };
        let local = &self.state.manifest;
        LanStaging::start(
            &private_dir,
            &self.vk,
            &scope,
            manifest_hash,
            envelope,
            &mut |r| match local.reference(r.object_id()) {
                Some(known) if known == r => Ok(Planned::Local),
                Some(_) => Err(StoreError::Integrity),
                None => Ok(Planned::Peer),
            },
            cancelled,
        )
    }

    /// Appends the next planned [`Planned::Local`] object from this vault's
    /// row, rechecked against the peer's reference. A row that is gone is
    /// [`StoreError::NotFound`].
    pub fn lan_stage_local(&self, staging: &mut LanStaging) -> Result<(), StoreError> {
        if staging.next() != Some(Planned::Local) {
            return Err(StoreError::Internal);
        }
        let r = *staging.next_reference().ok_or(StoreError::Internal)?;
        let envelope =
            self.local_envelope(r.object_id(), r.data_profile(), r.length(), r.sha256())?;
        staging.append(&envelope, Planned::Local)
    }

    /// The full authentication of a complete staging under this vault's VK.
    pub fn lan_finish(
        &self,
        staging: LanStaging,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedLanStaging, StoreError> {
        staging.finish(&self.vk, cancelled)
    }

    /// SHA-256 of the current manifest envelope (what `Done` names).
    pub fn manifest_hash(&self) -> [u8; 32] {
        self.state.head.manifest_hash
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
    pub(crate) archive: StagedArchive,
    pub(crate) scope: ArchiveScope,
}

impl core::fmt::Debug for VerifiedLanStaging {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VerifiedLanStaging(..)")
    }
}

/// Proof that a master password unlocks the staged keyslot to the received
/// VK; retained only for historical unit fixtures.
#[cfg(test)]
pub struct PasswordProof {
    pub(crate) body: Zeroizing<Vec<u8>>,
}

#[cfg(test)]
impl core::fmt::Debug for PasswordProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PasswordProof(<redacted>)")
    }
}

impl VerifiedLanStaging {
    /// The authenticated manifest.
    pub fn manifest(&self) -> &Manifest {
        self.archive.opened.manifest()
    }

    fn read_head(
        &mut self,
        vk: &VaultKey,
        record: qv_crypto::RecordId,
    ) -> Result<Option<qv_model::RecordVersion>, StoreError> {
        let manifest = self.archive.opened.manifest();
        let Some(entry) = manifest.record(record) else {
            return Ok(None);
        };
        let Some(role) = entry.heads().first() else {
            return Err(StoreError::Integrity);
        };
        let header = self.archive.opened.header();
        let key = vk.purpose_key::<purpose::Record>(
            header.vault_id(),
            header.key_generation(),
            crate::ARCHIVE_DERIVATION_PROFILE,
        )?;
        let version = crate::archive_verify::read_version(
            &mut self.archive.file,
            header,
            manifest,
            &self.archive.opened.frames,
            &key,
            record,
            role,
        )?;
        Ok(Some(version))
    }

    /// Whether the staged vault has exactly one password keyslot head.
    pub fn keyslot(&mut self, vk: &VaultKey) -> Result<StagedKeyslot, StoreError> {
        let id = self.archive.opened.manifest().keyslot_id();
        let heads = self
            .archive
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
        let id = self.archive.opened.manifest().vault_meta_id();
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
    #[cfg(test)]
    pub fn verify_password(
        &mut self,
        vk: &VaultKey,
        password: &MasterPassword,
    ) -> Result<PasswordProof, StoreError> {
        let id = self.archive.opened.manifest().keyslot_id();
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
            body: descriptor.encode_public_descriptor()?,
        })
    }

    /// Rewinds the staging file for the creation pass.
    pub(crate) fn rewind(&mut self) -> Result<&mut fs::ArchiveFile, StoreError> {
        self.archive
            .file
            .seek(SeekFrom::Start(0))
            .map_err(crate::error::io_err)?;
        Ok(&mut self.archive.file)
    }
}

impl crate::UnlockedVault {
    /// Allowlisted descriptor of the authenticated operational slot, for a
    /// short credential snapshot read. The caller must also compare it with
    /// the unique encrypted control head; no KDF occurs under this read.
    pub fn lan_working_password_descriptor(&self) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        self.check_identity()?;
        Ok(crate::slot::password_slot(&self.file.slots)?
            .keyslot
            .encode_public_descriptor()?)
    }
}

/// A password grant checked before receiving any bulk data. Its constructor
/// verifies the public projection and password unwrap against the received key.
/// It contains no password, master key or key-encryption key.
pub struct LanPasswordGrant {
    scope: ArchiveScope,
    descriptor: Zeroizing<Vec<u8>>,
    record: qv_model::RecordId,
    version: qv_model::VersionId,
    object: ObjectId,
    hash: [u8; 32],
    transcript: [u8; 32],
}
impl core::fmt::Debug for LanPasswordGrant {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanPasswordGrant(<redacted>)")
    }
}
impl LanPasswordGrant {
    /// Called after final-key grant authentication, while B still has its
    /// typed password. All identity/profile/width checks precede the fixed KDF.
    #[allow(clippy::too_many_arguments)] // Exact normative grant plus local credential/binding.
    pub fn verify(
        vk: &VaultKey,
        password: &MasterPassword,
        vault: [u8; 16],
        generation: u32,
        descriptor: &[u8],
        record: [u8; 16],
        version: [u8; 16],
        object: [u8; 16],
        hash: [u8; 32],
        transcript: [u8; 32],
    ) -> Result<Self, StoreError> {
        let vault = VaultId::from_bytes(vault)?;
        let record = qv_model::RecordId::from_bytes(record)?;
        let version = qv_model::VersionId::from_bytes(version)?;
        let object = ObjectId::from_bytes(object)?;
        if generation == 0 || descriptor.len() != 171 {
            return Err(StoreError::Integrity);
        }
        let slot = qv_model::Keyslot::decode(descriptor)?;
        let projection = slot.encode_public_descriptor()?;
        if projection.as_slice() != descriptor {
            return Err(StoreError::Integrity);
        }
        let scope = ArchiveScope::new(vault, KeyGeneration(generation));
        let unwrapped = slot.slot.unlock(password, vault, scope.key_generation())?;
        if !unwrapped.ct_eq(vk) {
            return Err(StoreError::Integrity);
        }
        Ok(Self {
            scope,
            descriptor: projection,
            record,
            version,
            object,
            hash,
            transcript,
        })
    }
}

/// A source- and method-bound publication capability. Only a fully verified
/// staging archive can issue it; no public fields or raw-key constructor.
pub struct LanEnrollmentProof {
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) scope: ArchiveScope,
    pub(crate) manifest_digest: [u8; 32],
    // Some = password route, None = independently possessed key route.
    pub(crate) password_transcript: Option<[u8; 32]>,
}
impl core::fmt::Debug for LanEnrollmentProof {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("LanEnrollmentProof(<redacted>)")
    }
}
impl VerifiedLanStaging {
    /// An authenticated head read for bounded core preflight before publication.
    pub fn read_version(
        &mut self,
        vk: &VaultKey,
        record: qv_model::RecordId,
        version: qv_model::VersionId,
    ) -> Result<qv_model::RecordVersion, StoreError> {
        let manifest = self.archive.opened.manifest();
        let entry = manifest.record(record).ok_or(StoreError::Integrity)?;
        let role = entry
            .heads()
            .iter()
            .find(|head| head.version_id() == version)
            .ok_or(StoreError::Integrity)?;
        let header = self.archive.opened.header();
        let key = vk.purpose_key::<purpose::Record>(
            header.vault_id(),
            header.key_generation(),
            crate::ARCHIVE_DERIVATION_PROFILE,
        )?;
        crate::archive_verify::read_version(
            &mut self.archive.file,
            header,
            manifest,
            &self.archive.opened.frames,
            &key,
            record,
            role,
        )
    }
    /// Verifies the unique encrypted password control record against the early
    /// grant, or adopts it under an independently authenticated key. No password
    /// is required or retained at this point for either method.
    pub fn verify_enrollment(
        &mut self,
        vk: &VaultKey,
        grant: Option<LanPasswordGrant>,
    ) -> Result<LanEnrollmentProof, StoreError> {
        if self.keyslot(vk)? != StagedKeyslot::Unique {
            return Err(StoreError::Integrity);
        }
        let record = self.manifest().keyslot_id();
        let Some(RecordBody::Live(Payload::PasswordKeyslot(slot))) =
            self.read_head(vk, record)?.map(|v| v.body)
        else {
            return Err(StoreError::Integrity);
        };
        let body = slot.encode_public_descriptor()?;
        let password_transcript = if let Some(grant) = grant {
            let entry = self
                .manifest()
                .record(record)
                .ok_or(StoreError::Integrity)?;
            let [head] = entry.heads() else {
                return Err(StoreError::Integrity);
            };
            let reference = self
                .manifest()
                .reference(head.object_id())
                .ok_or(StoreError::Integrity)?;
            if grant.scope.vault_id() != self.scope.vault_id()
                || grant.scope.key_generation() != self.scope.key_generation()
                || grant.record != record
                || grant.version != head.version_id()
                || grant.object != head.object_id()
                || grant.hash != *reference.sha256()
                || grant.descriptor.as_slice() != body.as_slice()
            {
                return Err(StoreError::Integrity);
            }
            Some(grant.transcript)
        } else {
            None
        };
        let manifest_digest = object_hash(ObjectHashProfile::V1, &self.manifest().encode()?).0;
        Ok(LanEnrollmentProof {
            body,
            scope: self.scope,
            manifest_digest,
            password_transcript,
        })
    }
}

impl LanEnrollmentProof {
    /// Distinguishes the authenticated enrollment route without exposing any
    /// secret or allowing modification of its source/method binding.
    pub fn is_password_enrollment(&self) -> bool {
        self.password_transcript.is_some()
    }
}

#[cfg(test)]
mod enrollment_tests {
    #![allow(clippy::unwrap_used, clippy::panic)]
    use super::*;
    use crate::fs::test_dir::TestDir;
    use crate::vault::tests::{PASSWORD, copy_fixture, pw, unlock};
    use crate::{UnlockedVault, VaultFile};

    fn staged(v: &UnlockedVault, private: &Path) -> VerifiedLanStaging {
        let state = v.lan_serve_state().unwrap();
        let mut staging = LanStaging::begin(
            private,
            v.vault_key(),
            v.header().vault_id,
            v.header().key_generation,
            state.manifest_hash(),
            state.envelope(),
            &|| false,
        )
        .unwrap();
        for object in staging.requested() {
            staging
                .add_object(&v.lan_object_envelope(&state, object).unwrap())
                .unwrap();
        }
        staging.finish(v.vault_key(), &|| false).unwrap()
    }
    fn grant(v: &UnlockedVault) -> LanPasswordGrant {
        let record = v.manifest().keyslot_id();
        let head = &v.manifest().record(record).unwrap().heads()[0];
        LanPasswordGrant::verify(
            v.vault_key(),
            &pw(PASSWORD),
            v.header().vault_id.0,
            v.header().key_generation.0,
            &v.lan_working_password_descriptor().unwrap(),
            record.0,
            head.version_id().to_bytes(),
            head.object_id().to_bytes(),
            *v.manifest().reference(head.object_id()).unwrap().sha256(),
            [47; 32],
        )
        .unwrap()
    }
    fn key(v: &UnlockedVault) -> VaultKey {
        let phrase = qv_crypto::RecoveryPhrase::from_vault_key(v.vault_key()).unwrap();
        VaultKey::from_recovery_phrase(phrase.expose_secret().as_bytes()).unwrap()
    }
    // 0012 §1: LAN partial acceptance
    #[test]
    fn lan_enrollment_grant_head_binding_and_private_staging_source_are_required_before_creation() {
        let d = TestDir::new();
        let a = TestDir::new();
        let (path, anchors) = copy_fixture(&d, &a, "source.qvault");
        let v = unlock(&path, &anchors, PASSWORD).unwrap();
        let private = d.subdir("private", 0o700);
        for field in 0..5 {
            let mut grant = grant(&v);
            match field {
                0 => grant.record = qv_model::RecordId::generate().unwrap(),
                1 => grant.version = qv_model::VersionId::generate().unwrap(),
                2 => grant.object = ObjectId::generate().unwrap(),
                3 => grant.hash[0] ^= 1,
                _ => grant.descriptor[0] ^= 1,
            }
            let mut staging = staged(&v, &private);
            assert_eq!(
                staging.verify_enrollment(v.vault_key(), Some(grant)).err(),
                Some(StoreError::Integrity)
            );
        }
        let mut first = staged(&v, &private);
        let proof = first
            .verify_enrollment(v.vault_key(), Some(grant(&v)))
            .unwrap();
        assert!(proof.is_password_enrollment());
        // Even another fully valid staging has a distinct private source ID.
        // Its ciphertext may be identical; this check binds an authorization
        // capability to its source, not filesystem copies to an inode.
        let second = staged(&v, &private);
        let destination = d.join("mismatched.qvault");
        assert_eq!(
            VaultFile::create_from_verified_lan(
                &destination,
                second,
                proof,
                key(&v),
                &anchors,
                &|| false
            )
            .err(),
            Some(StoreError::Integrity)
        );
        assert!(!destination.exists());
    }
    // 0012 §1: Anchor crash windows
    #[test]
    fn lan_enrollment_failure_after_publication_reports_the_created_file_and_preserves_its_anchor()
    {
        let d = TestDir::new();
        let a = TestDir::new();
        let snapshot = TestDir::new();
        let (path, anchors) = copy_fixture(&d, &a, "source.qvault");
        let v = unlock(&path, &anchors, PASSWORD).unwrap();
        let private = d.subdir("private", 0o700);
        let mut staging = staged(&v, &private);
        let proof = staging.verify_enrollment(v.vault_key(), None).unwrap();
        assert!(!proof.is_password_enrollment());
        let destination = d.join("published.qvault");
        crate::crash::test::arm(
            crate::crash::CrashPoint::LanPublished,
            &destination,
            anchors.path(),
            snapshot.path(),
        );
        let result = VaultFile::create_from_verified_lan(
            &destination,
            staging,
            proof,
            key(&v),
            &anchors,
            &|| false,
        );
        assert!(!crate::crash::test::disarm());
        assert_eq!(result.err(), Some(StoreError::PublicationIncomplete));
        assert!(destination.exists());
        let mut reopened = unlock(&destination, &anchors, PASSWORD).unwrap();
        reopened.verify_all(&|| false).unwrap();
        assert!(reopened.write().is_ok());
    }
}
