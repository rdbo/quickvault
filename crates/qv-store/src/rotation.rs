// SPDX-License-Identifier: AGPL-3.0-or-later

//! The private replacement of an offline VK rotation (0002 §2.2, §3.5.1–2;
//! plan 0022, roadmap 1.15b).
//!
//! [`UnlockedVault::prepare_rotation`] builds a complete database of the next
//! key generation from the fully verified source and verifies it again from
//! the persisted bytes. Nothing is published: the replacement lives under a
//! reserved `.qvrotate` name that ordinary opens refuse, its anchor is never
//! read or written, and the source file and every anchor stay unchanged.
//! Installation through the rotation journal is roadmap 1.15c.
//!
//! What the replacement preserves: every record, its heads (including
//! conflicts), retained history, floors, version IDs, clocks, modification
//! times and unknown extension fields; the replica and writer IDs, so the
//! same external anchor protects the transition. What it changes: a new VK,
//! generation + 1, a new password slot, fresh object IDs and nonces for every
//! object (records and attachment chunks), and one causal edit of the keyslot
//! record that carries the new descriptor, exactly as a password change
//! stages it. The previous keyslot head becomes history; it wraps only the old
//! VK. The first head has `local_seq` + 1 and names the old head's digest
//! (0005 §5.4), and the writer's next counter advances by one.
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use qv_crypto::{
    AttachmentId, ContentHasher, KeyGeneration, MasterPassword, ObjectHashProfile, PasswordSlot,
    RecordId, RecoveryPhrase, SlotId, VaultKey, object_hash, open_chunk, purpose, seal_chunk,
};
use qv_model::{Clock, ObjectId, Payload, RandomId, RecordBody, RecordVersion, VersionId};

use crate::creation::{self, Filled};
use crate::error::StoreError;
use crate::fs;
use crate::head::LocalHead;
use crate::header::Header;
use crate::manifest::{ObjectRef, VersionRef, seal_manifest};
use crate::object::{SealedObject, seal_record};
use crate::schema::{ObjectReader, StoredReplica, StoredSlot};
use crate::slot::{LocalSlot, PASSWORD_SLOT, password_slot};
use crate::vault::{
    FileRole, Keys, UnlockedVault, VaultFile, WriteGate, insert_object, now, read_role, scope,
    sign_head,
};
use crate::write::MAX_COUNTER;

#[cfg(test)]
thread_local! {
    /// Test hook: fail the build after this many objects (`Some(0)`: before
    /// the first), or with `usize::MAX` just before the creation COMMIT.
    pub(crate) static FAIL_AFTER: std::cell::Cell<Option<usize>> =
        const { std::cell::Cell::new(None) };
    /// Test hook: corrupt the build (1: a wrong chunk remap in one
    /// attachment version's payload; 2: a different keyslot head payload).
    pub(crate) static CORRUPT: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn fault(objects: usize) -> Result<(), StoreError> {
    if FAIL_AFTER.with(std::cell::Cell::get) == Some(objects) {
        return Err(StoreError::Internal);
    }
    Ok(())
}
#[cfg(not(test))]
fn fault(_: usize) -> Result<(), StoreError> {
    Ok(())
}

fn check_cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
    if cancelled() {
        Err(StoreError::Io)
    } else {
        Ok(())
    }
}

/// Removes an unpublished replacement unless disarmed.
pub(crate) struct Unpublished(pub(crate) Option<PathBuf>);

impl Drop for Unpublished {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            fs::remove_best_effort(&fs::with_suffix(&path, "-journal"));
            fs::remove_best_effort(&path);
        }
    }
}

/// A verified, unpublished replacement of the next key generation.
///
/// It owns the still-locked source session and the locked replacement file.
/// No accessor returns a key or a path. Dropping it removes the replacement
/// (best effort); the source file and every anchor are unchanged.
/// [`PreparedRotation::install`] publishes it through the rotation journal.
pub struct PreparedRotation {
    // Field order: the replacement's connection closes before its file is
    // removed by `cleanup`, and the source session stays locked until the end.
    pub(crate) replacement: UnlockedVault,
    pub(crate) _cleanup: Unpublished,
    pub(crate) source: UnlockedVault,
    pub(crate) phrase: RecoveryPhrase,
    pub(crate) suffix: [u8; 16],
}

impl core::fmt::Debug for PreparedRotation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("PreparedRotation(<redacted>)")
    }
}

impl PreparedRotation {
    /// The new generation's recovery phrase, in protected memory, for the
    /// frontend's confirmation (0002 §3.5.2).
    pub fn phrase(&self) -> &RecoveryPhrase {
        &self.phrase
    }

    /// The new key generation (the source's + 1).
    pub fn new_generation(&self) -> KeyGeneration {
        self.replacement.header().key_generation
    }

    /// The source session (old generation), for the inventory.
    pub(crate) fn source(&self) -> &UnlockedVault {
        &self.source
    }

    /// The verified replacement session (role Candidate).
    #[cfg(test)]
    pub(crate) fn replacement(&self) -> &UnlockedVault {
        &self.replacement
    }

    /// The new VK (the inventory's MAC key).
    pub(crate) fn new_vault_key(&self) -> &VaultKey {
        &self.replacement.vk
    }
}

/// What `build_replacement` returns.
struct Built {
    replacement: UnlockedVault,
    cleanup: Unpublished,
    phrase: RecoveryPhrase,
    suffix: [u8; 16],
}

impl UnlockedVault {
    /// Builds and verifies the private replacement of the next key generation
    /// with a new VK, phrase and password slot (0002 §3.5.1–2).
    ///
    /// Consumes the session: on error the source is dropped unchanged and the
    /// caller unlocks again. Runs the password KDF twice (creating the new
    /// slot, then unlocking it from the persisted replacement). Refuses
    /// before any KDF or file work: a blocked or mismatched anchor (its
    /// error), remote sync state ([`StoreError::Unsupported`]; remote
    /// rotation is phase 3.8), a control record with more than one head
    /// ([`StoreError::InvalidEdit`]), and an exhausted generation, sequence
    /// or counter ([`StoreError::LimitExceeded`]). Cancellation is
    /// [`StoreError::Io`]. Never writes the source, an anchor, a journal or a
    /// marker.
    pub fn prepare_rotation(
        mut self,
        new_password: &MasterPassword,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<PreparedRotation, StoreError> {
        // An ordinary pending-anchor retry first, like any write.
        self.finish_pending_anchor()?;
        if let WriteGate::Blocked(e) = self.gate {
            return Err(e);
        }
        if self.gate != WriteGate::Open {
            return Err(StoreError::Internal);
        }
        if self.state.head.remote.is_some() {
            return Err(StoreError::Unsupported);
        }
        let m = &self.state.manifest;
        for id in [m.vault_meta_id(), m.keyslot_id(), m.root_group_id()] {
            if m.record(id).map(|r| r.heads().len()) != Some(1) {
                return Err(StoreError::InvalidEdit);
            }
        }
        let source_header = self.file.header;
        let generation = source_header
            .key_generation
            .0
            .checked_add(1)
            .map(KeyGeneration)
            .ok_or(StoreError::LimitExceeded)?;
        let local_seq = self
            .state
            .head
            .local_seq
            .checked_add(1)
            .ok_or(StoreError::LimitExceeded)?;
        let counter = self.state.replica.next_counter;
        if counter >= MAX_COUNTER {
            return Err(StoreError::LimitExceeded);
        }
        check_cancel(cancelled)?;

        // Every head, history version and attachment authenticates first.
        self.verify_all(cancelled)?;
        self.begin_read()?;
        let built = self.build_replacement(generation, local_seq, counter, new_password, cancelled);
        let result = built.and_then(|b| {
            let prepared = PreparedRotation {
                replacement: b.replacement,
                _cleanup: b.cleanup,
                source: self,
                phrase: b.phrase,
                suffix: b.suffix,
            };
            prepared.compare(cancelled)?;
            prepared.source.end_read()?;
            Ok(prepared)
        });
        // On error `self` (or the prepared source) is dropped, which closes
        // the read transaction with its connection.
        result
    }

    /// Steps 4–10 of plan 0022's replacement design, inside the source's read
    /// transaction.
    fn build_replacement(
        &self,
        generation: KeyGeneration,
        local_seq: u64,
        counter: u64,
        new_password: &MasterPassword,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Built, StoreError> {
        let source_header = self.file.header;
        let manifest = &self.state.manifest;
        let header = Header {
            key_generation: generation,
            ..source_header
        };
        let vid = header.vault_id;

        // New VK, phrase and password slot (current slot profiles kept).
        let new_vk = VaultKey::generate()?;
        let phrase = RecoveryPhrase::from_vault_key(&new_vk)?;
        let current = &password_slot(&self.file.slots)?.keyslot.slot;
        let (kdf, wrap) = (current.kdf_profile, current.wrap_profile);
        check_cancel(cancelled)?;
        let slot = PasswordSlot::create(
            new_password,
            &new_vk,
            vid,
            generation,
            SlotId::generate()?,
            kdf,
            wrap,
        )?;
        let keyslot_id = manifest.keyslot_id();
        let [keyslot_head] = manifest
            .record(keyslot_id)
            .ok_or(StoreError::Integrity)?
            .heads()
        else {
            return Err(StoreError::InvalidEdit);
        };
        let mut keyslot_version = self.read_version(keyslot_id, keyslot_head.version_id())?;
        let RecordBody::Live(Payload::PasswordKeyslot(mut keyslot)) = keyslot_version.body else {
            return Err(StoreError::Integrity);
        };
        keyslot.slot = slot;
        let body = keyslot.encode()?;
        let local = LocalSlot::from_stored(StoredSlot {
            slot_id: keyslot.slot.slot_id.0,
            kind: PASSWORD_SLOT,
            body: body.to_vec(),
        })?;
        keyslot_version.version_id = VersionId::generate()?;
        keyslot_version.clock =
            Clock::for_edit([keyslot_head.clock()], self.state.writer, counter)?;
        keyslot_version.modified_at = now();
        keyslot_version.body = RecordBody::Live(Payload::PasswordKeyslot(keyslot));
        #[cfg(test)]
        if CORRUPT.with(std::cell::Cell::get) == 2 {
            let RecordBody::Live(Payload::PasswordKeyslot(k)) = &mut keyslot_version.body else {
                return Err(StoreError::Internal);
            };
            k.slot.slot_id = SlotId::generate()?;
        }

        // The replacement file under a reserved, never-published name.
        let suffix = qv_crypto::random_array::<16>().map_err(|_| StoreError::Rng)?;
        let final_path = crate::rotation_guard::sibling(
            self.file.path(),
            crate::rotation_guard::Sibling::New,
            &suffix,
        );
        let (lock, temp) = fs::create_temp(&final_path)?;
        let cleanup = Unpublished(Some(temp.clone()));

        let old_keys = Keys::derive(&self.vk, &source_header)?;
        let new_keys = Keys::derive(&new_vk, &header)?;
        let replica = StoredReplica {
            next_counter: counter.checked_add(1).ok_or(StoreError::LimitExceeded)?,
            ..self.state.replica
        };
        let mut expected = None;
        creation::write_database(
            &temp,
            &header,
            &new_vk,
            &local,
            replica,
            |tx| {
                let map = self.transcode(tx, &header, &new_vk, &old_keys, &new_keys, cancelled)?;
                let mut next = manifest.remapped(&header, &map)?;
                // The keyslot edit: the same causal step `passwd` stages.
                let object = seal_record(
                    &new_keys.record,
                    scope(&header),
                    header.data_profile,
                    keyslot_id,
                    &keyslot_version,
                )?;
                if manifest.reference(object.object_id).is_some()
                    || map.values().any(|r| r.object_id() == object.object_id)
                {
                    return Err(StoreError::Rng);
                }
                let reference =
                    ObjectRef::new(object.object_id, object.data_profile, &object.ciphertext)?;
                insert_object(tx, generation, &object)?;
                next.replace_heads(
                    keyslot_id,
                    VersionRef::new(
                        keyslot_version.version_id,
                        keyslot_version.clock.clone(),
                        object.object_id,
                    ),
                    reference,
                )?;
                let sealed = seal_manifest(
                    &new_keys.manifest,
                    scope(&header),
                    header.data_profile,
                    &next,
                )?;
                let head = LocalHead {
                    vault_id: vid,
                    key_generation: generation,
                    local_seq,
                    previous_digest: Some(self.state.digest),
                    manifest_hash: sealed.hash,
                    remote: None,
                };
                let (head, digest) = sign_head(&new_keys, &header, &head)?;
                #[cfg(test)]
                fault(usize::MAX)?;
                expected = Some((next, digest));
                Ok(Filled {
                    manifest: sealed,
                    head,
                })
            },
            cancelled,
        )?;
        let (next, digest) = expected.ok_or(StoreError::Internal)?;
        lock.sync()?;
        check_cancel(cancelled)?;

        // Reopen the persisted bytes hardened and unlock the new slot with the
        // new password; the in-memory key is used only to cross-check.
        let file = VaultFile::open_locked_as(&temp, lock, FileRole::Candidate)?;
        if file.header != header || file.slots.len() != 1 {
            return Err(StoreError::Integrity);
        }
        let unwrapped = password_slot(&file.slots)?
            .keyslot
            .slot
            .unlock(new_password, vid, generation)
            .map_err(|_| StoreError::Integrity)?;
        file.verify_header(&unwrapped)?;
        file.verify_header(&new_vk)?;
        let replacement = file.finish_candidate(unwrapped, &self.anchors)?;
        if replacement.state.manifest != next
            || replacement.state.digest != digest
            || replacement.state.replica != replica
            || replacement.state.head.local_seq != local_seq
            || replacement.state.head.previous_digest != Some(self.state.digest)
            || replacement.state.head.remote.is_some()
        {
            return Err(StoreError::Integrity);
        }
        replacement.verify_all(cancelled)?;
        Ok(Built {
            replacement,
            cleanup,
            phrase,
            suffix,
        })
    }

    /// Reencrypts every referenced object of the source into `tx` under the
    /// new generation with a fresh object ID. Returns old ID → new reference.
    fn transcode(
        &self,
        tx: &rusqlite::Transaction<'_>,
        header: &Header,
        new_vk: &VaultKey,
        old_keys: &Keys,
        new_keys: &Keys,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<BTreeMap<ObjectId, ObjectRef>, StoreError> {
        let source_header = self.file.header;
        let manifest = &self.state.manifest;
        let vid = header.vault_id;
        let old_root = self.vk.purpose_key::<purpose::Attachment>(
            vid,
            source_header.key_generation,
            source_header.derivation_profile,
        )?;
        let new_root = new_vk.purpose_key::<purpose::Attachment>(
            vid,
            header.key_generation,
            header.derivation_profile,
        )?;
        let mut reader = ObjectReader::new(&self.file.conn)?;
        let mut map = BTreeMap::new();
        let mut used = BTreeSet::new();
        let mut put = |map: &mut BTreeMap<ObjectId, ObjectRef>,
                       old: ObjectId,
                       object: &SealedObject|
         -> Result<ObjectId, StoreError> {
            // A collision of random 128-bit IDs means a broken RNG: never reuse.
            if manifest.reference(object.object_id).is_some() || !used.insert(object.object_id) {
                return Err(StoreError::Rng);
            }
            let reference =
                ObjectRef::new(object.object_id, object.data_profile, &object.ciphertext)?;
            insert_object(tx, header.key_generation, object)?;
            // `Manifest::validate` lets each reference serve exactly one role.
            if map.insert(old, reference).is_some() {
                return Err(StoreError::Integrity);
            }
            fault(map.len())?;
            Ok(object.object_id)
        };
        fault(0)?;
        for rec in manifest.records() {
            let record = rec.record_id();
            for v in rec.heads().iter().chain(rec.history()) {
                check_cancel(cancelled)?;
                let mut version: RecordVersion = read_role(
                    &mut reader,
                    old_keys,
                    &source_header,
                    manifest,
                    record,
                    v,
                    true,
                )?;
                if let RecordBody::Live(Payload::AttachmentMeta(meta)) = &mut version.body {
                    let chunks = v.chunks().ok_or(StoreError::Integrity)?;
                    if meta.chunk_object_ids != chunks {
                        return Err(StoreError::Integrity);
                    }
                    let old_key = old_root.attachment_key(vid, AttachmentId(record.0))?;
                    let new_key = new_root.attachment_key(vid, AttachmentId(record.0))?;
                    let mut ids = Vec::with_capacity(chunks.len());
                    for (index, id) in chunks.iter().enumerate() {
                        check_cancel(cancelled)?;
                        let object = self.reseal_chunk(
                            &mut reader,
                            header,
                            &old_key,
                            &new_key,
                            record,
                            *id,
                            index,
                        )?;
                        ids.push(put(&mut map, *id, &object)?);
                    }
                    #[cfg(test)]
                    if CORRUPT.with(std::cell::Cell::get) == 1 && ids.len() > 1 {
                        ids.swap(0, 1);
                    }
                    meta.chunk_object_ids = ids;
                } else if v.chunks().is_some() {
                    return Err(StoreError::Integrity);
                }
                let object = seal_record(
                    &new_keys.record,
                    scope(header),
                    header.data_profile,
                    record,
                    &version,
                )?;
                put(&mut map, v.object_id(), &object)?;
            }
        }
        Ok(map)
    }

    /// Opens one source chunk for its record and index and seals it again
    /// under the new attachment key with a fresh object ID.
    #[allow(clippy::too_many_arguments)]
    fn reseal_chunk(
        &self,
        reader: &mut ObjectReader<'_>,
        header: &Header,
        old_key: &qv_crypto::DataKey,
        new_key: &qv_crypto::DataKey,
        record: RecordId,
        id: ObjectId,
        index: usize,
    ) -> Result<SealedObject, StoreError> {
        let source_header = self.file.header;
        let r = self
            .state
            .manifest
            .reference(id)
            .ok_or(StoreError::Integrity)?;
        if r.length() != crate::manifest::chunk_ciphertext_len()? {
            return Err(StoreError::Integrity);
        }
        let (profile, nonce, ciphertext) =
            reader.read(source_header.key_generation, &id.to_bytes(), r.length())?;
        if profile != r.data_profile().id()
            || object_hash(ObjectHashProfile::V1, &ciphertext).0 != *r.sha256()
        {
            return Err(StoreError::Integrity);
        }
        let plaintext = open_chunk(
            old_key,
            r.data_profile(),
            &crate::attachment::aad(scope(&source_header), record, id, index, r.data_profile())?,
            &nonce,
            &ciphertext,
        )?;
        let object_id = ObjectId::generate()?;
        let sealed = seal_chunk(
            new_key,
            header.data_profile,
            &crate::attachment::aad(scope(header), record, object_id, index, header.data_profile)?,
            plaintext.expose_secret(),
        )?;
        Ok(SealedObject {
            object_id,
            data_profile: header.data_profile,
            nonce: sealed.nonce,
            ciphertext: sealed.ciphertext,
        })
    }
}

impl PreparedRotation {
    /// The logical comparison of the persisted replacement with its source
    /// (plan 0022 step 10): every source version equals its replacement with
    /// only the chunk IDs remapped, the keyslot gained exactly the staged
    /// edit, and every attachment streams to the same content.
    fn compare(&self, cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
        let old = &self.source.state.manifest;
        let new = &self.replacement.state.manifest;
        if old.records().len() != new.records().len() {
            return Err(StoreError::Integrity);
        }
        let keyslot = old.keyslot_id();
        for (a, b) in old.records().iter().zip(new.records()) {
            check_cancel(cancelled)?;
            let record = a.record_id();
            if b.record_id() != record || a.floor() != b.floor() {
                return Err(StoreError::Integrity);
            }
            for v in a.heads().iter().chain(a.history()) {
                check_cancel(cancelled)?;
                let ours = self.source.read_version(record, v.version_id())?;
                let theirs = self.replacement.read_version(record, v.version_id())?;
                let role = b.version(v.version_id()).ok_or(StoreError::Integrity)?;
                if role.clock() != v.clock() || !same_version(ours, &theirs, role)? {
                    return Err(StoreError::Integrity);
                }
                if v.chunks().is_some() {
                    let left = content(&self.source, record, v.version_id(), cancelled)?;
                    let right = content(&self.replacement, record, v.version_id(), cancelled)?;
                    if !left.ct_eq(right.expose_secret()) {
                        return Err(StoreError::Integrity);
                    }
                }
            }
            let (old_heads, new_heads) = (a.heads(), b.heads());
            if record == keyslot {
                // One new head dominating the old one; the old head is history.
                let ([old_head], [new_head]) = (old_heads, new_heads) else {
                    return Err(StoreError::Integrity);
                };
                let edit = self
                    .replacement
                    .read_version(record, new_head.version_id())?;
                let RecordBody::Live(Payload::PasswordKeyslot(descriptor)) = edit.body else {
                    return Err(StoreError::Integrity);
                };
                let staged = &password_slot(&self.replacement.file.slots)?.body;
                if digest(&descriptor.encode()?) != digest(staged)
                    || b.history().len() != a.history().len() + 1
                    || b.version(old_head.version_id()).is_none()
                    || !matches!(
                        new_head.clock().compare(old_head.clock()),
                        qv_model::Causality::After
                    )
                {
                    return Err(StoreError::Integrity);
                }
            } else if old_heads.len() != new_heads.len()
                || a.history().len() != b.history().len()
                || old_heads
                    .iter()
                    .zip(new_heads)
                    .any(|(x, y)| x.version_id() != y.version_id())
            {
                return Err(StoreError::Integrity);
            }
        }
        Ok(())
    }
}

/// SHA-256 of canonical plaintext, so two decrypted values are compared
/// without a data-dependent early exit over their bytes.
fn digest(bytes: &[u8]) -> [u8; 32] {
    object_hash(ObjectHashProfile::V1, bytes).0
}

/// Whether two decrypted versions encode identically once the source's
/// attachment chunk IDs are replaced by the replacement role's.
fn same_version(
    mut ours: RecordVersion,
    theirs: &RecordVersion,
    role: &VersionRef,
) -> Result<bool, StoreError> {
    match &mut ours.body {
        RecordBody::Live(Payload::AttachmentMeta(a)) => {
            let Some(chunks) = role.chunks() else {
                return Ok(false);
            };
            a.chunk_object_ids = chunks.to_vec();
        }
        _ if role.chunks().is_some() => return Ok(false),
        _ => {}
    }
    Ok(digest(&ours.encode()?) == digest(&theirs.encode()?))
}

/// The streamed content hash of one attachment version.
fn content(
    vault: &UnlockedVault,
    record: RecordId,
    version: VersionId,
    cancelled: &dyn Fn() -> bool,
) -> Result<qv_crypto::SecretArray<32>, StoreError> {
    struct Hashing(ContentHasher);
    impl std::io::Write for Hashing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut sink = Hashing(ContentHasher::new());
    vault.read_attachment(record, version, &mut sink, &cancelled)?;
    Ok(sink.0.finalize())
}

#[cfg(test)]
#[path = "rotation_tests.rs"]
mod tests;
