// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transaction-local candidate validation and atomic incoming acceptance.

use crate::vault::{self, UnlockedVault};
use crate::{IncomingRead, IncomingSource, Manifest, StoreError, VerifiedIncoming};
use crate::{
    crash::{CrashPoint, point},
    receipt_store,
    schema::ObjectReader,
    validation,
};
use qv_crypto::{ContentHasher, ObjectHashProfile, RecordId, object_hash, purpose};
use qv_model::{Payload, RandomId, RecordBody, RecordKind, VersionId};
use std::collections::{BTreeMap, BTreeSet};

fn cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
    if cancelled() {
        Err(StoreError::Io)
    } else {
        Ok(())
    }
}

impl UnlockedVault {
    /// Atomically accept a verified archive through the existing Write/anchor path.
    ///
    /// The builder computes metadata through authenticated transaction-local
    /// reads. Its result is independently checked against both complete inputs;
    /// an arbitrary builder cannot invent/drop versions or advance floors.
    /// Operational password slots remain unchanged. Returns false for identical
    /// filename/stream redelivery, after finishing any pending anchor update.
    pub fn accept_incoming(
        &mut self,
        incoming: &mut VerifiedIncoming,
        build: &mut impl FnMut(
            &Manifest,
            &Manifest,
            &mut IncomingRead<'_>,
        ) -> Result<Manifest, StoreError>,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<bool, StoreError> {
        cancel(cancelled)?;
        if incoming.header().vault_id() != self.header().vault_id
            || incoming.header().key_generation() != self.header().key_generation
        {
            return Err(StoreError::Integrity);
        }
        let mut write = self.write()?;
        let header = write.vault.file.header;
        let local = &write.vault.state.manifest;
        let mut receipts = receipt_store::open(
            &receipt_store::read(&write.vault.file.conn)?,
            &write.vault.state.head.archive_receipts_digest,
            &write.keys,
            &header,
            &write.vault.state.replica.replica_id,
        )?;
        if !receipts.remember(incoming.path.expose_secret(), *incoming.digest())? {
            cancel(cancelled)?;
            return Ok(false); // Write drops/rolls back; no sequence/counter advance.
        }
        let incoming_manifest = incoming.manifest().clone();
        if !local.same_configuration(&incoming_manifest) {
            return Err(StoreError::Integrity);
        }
        // Reference hashes commit to ciphertext. Immutability also includes
        // nonce/profile bytes, even for overlapping objects later suppressed.
        for reference in incoming_manifest.references() {
            cancel(cancelled)?;
            let Some(known) = local.reference(reference.object_id()) else {
                continue;
            };
            if known != reference {
                return Err(StoreError::Integrity);
            }
            write.vault.file.budget.reset();
            let object = incoming.read_object(reference.object_id())?;
            let (profile, nonce, ciphertext) = ObjectReader::new(&write.vault.file.conn)?.read(
                header.key_generation,
                &object.object_id.to_bytes(),
                reference.length(),
            )?;
            if profile != object.data_profile.id()
                || nonce != object.nonce
                || ciphertext != object.ciphertext
            {
                return Err(StoreError::Integrity);
            }
        }
        let mut read = |source, record, version| {
            cancel(cancelled)?;
            write.vault.file.budget.reset();
            match source {
                IncomingSource::Local => {
                    let role = local
                        .record(record)
                        .and_then(|r| r.version(version))
                        .ok_or(StoreError::Integrity)?;
                    vault::read_role(
                        &mut ObjectReader::new(&write.vault.file.conn)?,
                        &write.keys,
                        &header,
                        local,
                        record,
                        role,
                        true,
                    )
                }
                IncomingSource::Incoming => incoming.read_version(&write.vault.vk, record, version),
            }
        };
        let candidate = build(local, &incoming_manifest, &mut read)?;
        let kinds =
            validate_projection(local, &incoming_manifest, &candidate, &mut read, cancelled)?;
        // The reader borrow ends here; objects are copied without re-encryption.
        let blob = receipt_store::seal(
            &receipts,
            &write.keys,
            &header,
            &write.vault.state.replica.replica_id,
        )?;
        for reference in candidate.references() {
            cancel(cancelled)?;
            write.vault.file.budget.reset();
            if local.reference(reference.object_id()).is_some() {
                continue;
            }
            let object = incoming.read_object(reference.object_id())?;
            let mut reader = ObjectReader::new(&write.vault.file.conn)?;
            if reader
                .meta(header.key_generation, &object.object_id.to_bytes())?
                .is_some()
            {
                let (profile, nonce, ciphertext) = reader.read(
                    header.key_generation,
                    &object.object_id.to_bytes(),
                    reference.length(),
                )?;
                if profile != object.data_profile.id()
                    || nonce != object.nonce
                    || ciphertext != object.ciphertext
                {
                    return Err(StoreError::Integrity);
                }
            } else {
                vault::insert_object(
                    &write.vault.file.conn,
                    header.key_generation,
                    &crate::object::SealedObject {
                        object_id: object.object_id,
                        data_profile: object.data_profile,
                        nonce: object.nonce,
                        ciphertext: object.ciphertext,
                    },
                )?;
                write.growth = write.growth.saturating_add(reference.length());
            }
        }
        point(CrashPoint::ObjectsWritten)?;
        verify_candidate(write.vault, &write.keys, &candidate, cancelled)?;
        write.manifest = candidate;
        write.new_kinds = kinds.into_iter().collect();
        write.growth = write.growth.saturating_add(blob.len() as u64);
        write.receipt_blob = Some(blob);
        write.commit_cancellable(&|| cancelled())?;
        Ok(true)
    }
}

fn validate_projection(
    local: &Manifest,
    incoming: &Manifest,
    candidate: &Manifest,
    read: &mut IncomingRead<'_>,
    cancelled: &dyn Fn() -> bool,
) -> Result<BTreeMap<RecordId, RecordKind>, StoreError> {
    if !local.same_configuration(incoming) || !local.same_configuration(candidate) {
        return Err(StoreError::Integrity);
    }
    candidate.validate()?;
    let ids: BTreeSet<_> = local
        .records()
        .iter()
        .chain(incoming.records())
        .map(|r| r.record_id())
        .collect();
    if ids.len() != candidate.records().len()
        || ids.iter().any(|id| candidate.record(*id).is_none())
    {
        return Err(StoreError::Integrity);
    }
    for r in incoming.references() {
        if local
            .reference(r.object_id())
            .is_some_and(|known| known != r)
        {
            return Err(StoreError::Integrity);
        }
    }
    let mut owners = BTreeMap::new();
    let mut kinds = BTreeMap::new();
    for id in ids {
        cancel(cancelled)?;
        let result = candidate.record(id).ok_or(StoreError::Integrity)?;
        let mut floor = qv_model::HistoryFloor::default();
        let mut versions = BTreeMap::<VersionId, (crate::VersionRef, IncomingSource)>::new();
        let mut clocks = BTreeSet::new();
        for (source, manifest) in [
            (IncomingSource::Local, local),
            (IncomingSource::Incoming, incoming),
        ] {
            let Some(record) = manifest.record(id) else {
                continue;
            };
            floor = floor.join(&record.floor())?;
            for role in record.heads().iter().chain(record.history()) {
                cancel(cancelled)?;
                if owners
                    .insert(role.version_id(), id)
                    .is_some_and(|old| old != id)
                {
                    return Err(StoreError::Integrity);
                }
                let v = read(source, id, role.version_id())?;
                validation::check_head(manifest, id, role, &v)?;
                if v.version_id != role.version_id()
                    || &v.clock != role.clock()
                    || kinds
                        .insert(id, v.kind())
                        .is_some_and(|kind| kind != v.kind())
                {
                    return Err(StoreError::Integrity);
                }
                if let Some((old, source)) = versions.get(&role.version_id()) {
                    let prior = read(*source, id, old.version_id())?;
                    let mut a = ContentHasher::new();
                    a.update(&prior.encode()?);
                    let mut b = ContentHasher::new();
                    b.update(&v.encode()?);
                    if !a.finalize().ct_eq(b.finalize().expose_secret()) {
                        return Err(StoreError::Integrity);
                    }
                } else {
                    if !clocks.insert(role.clock().pairs().to_vec()) {
                        return Err(StoreError::Integrity);
                    }
                    versions.insert(role.version_id(), (role.clone(), source));
                }
            }
        }
        if result.floor() != floor {
            return Err(StoreError::Integrity);
        }
        for (role, _) in versions.values() {
            if let Some(retained) = result.version(role.version_id()) {
                if retained != role {
                    return Err(StoreError::Integrity);
                }
            } else if role.is_tombstone()
                || !floor.suppresses(role.clock())
                || !result
                    .heads()
                    .iter()
                    .any(|h| h.clock().dominates(role.clock()))
            {
                return Err(StoreError::Integrity);
            }
        }
        for role in result.heads().iter().chain(result.history()) {
            let (known, source) = versions
                .get(&role.version_id())
                .ok_or(StoreError::Integrity)?;
            if known != role {
                return Err(StoreError::Integrity);
            }
            let manifest = match source {
                IncomingSource::Local => local,
                IncomingSource::Incoming => incoming,
            };
            for object in std::iter::once(role.object_id())
                .chain(role.chunks().into_iter().flatten().copied())
            {
                if candidate.reference(object) != manifest.reference(object) {
                    return Err(StoreError::Integrity);
                }
            }
        }
    }
    validation::check_control_kinds(candidate, &kinds)?;
    Ok(kinds)
}

fn verify_candidate(
    vault: &UnlockedVault,
    keys: &vault::Keys,
    manifest: &Manifest,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), StoreError> {
    let header = &vault.file.header;
    let mut reader = ObjectReader::new(&vault.file.conn)?;
    let root = vault.vk.purpose_key::<purpose::Attachment>(
        header.vault_id,
        header.key_generation,
        header.derivation_profile,
    )?;
    for record in manifest.records() {
        for role in record.heads().iter().chain(record.history()) {
            cancel(cancelled)?;
            vault.file.budget.reset();
            let v = vault::read_role(
                &mut reader,
                keys,
                header,
                manifest,
                record.record_id(),
                role,
                true,
            )?;
            if let RecordBody::Live(Payload::AttachmentMeta(meta)) = &v.body {
                let key = root.attachment_key(
                    header.vault_id,
                    qv_crypto::AttachmentId(record.record_id().0),
                )?;
                let mut hash = ContentHasher::new();
                let mut total = 0u64;
                for (index, object) in meta.chunk_object_ids.iter().enumerate() {
                    cancel(cancelled)?;
                    vault.file.budget.reset();
                    let r = manifest.reference(*object).ok_or(StoreError::Integrity)?;
                    let (profile, nonce, ciphertext) =
                        reader.read(header.key_generation, &object.to_bytes(), r.length())?;
                    if profile != r.data_profile().id()
                        || object_hash(ObjectHashProfile::V1, &ciphertext).0 != *r.sha256()
                    {
                        return Err(StoreError::Integrity);
                    }
                    let bytes = qv_crypto::open_chunk(
                        &key,
                        r.data_profile(),
                        &crate::attachment::aad(
                            vault::scope(header),
                            record.record_id(),
                            *object,
                            index,
                            r.data_profile(),
                        )?,
                        &nonce,
                        &ciphertext,
                    )?;
                    let expected = meta
                        .size
                        .checked_sub(total)
                        .ok_or(StoreError::Integrity)?
                        .min(qv_model::CHUNK_SIZE);
                    if expected == 0 || bytes.len() as u64 != expected {
                        return Err(StoreError::Integrity);
                    }
                    total = total
                        .checked_add(expected)
                        .ok_or(StoreError::LimitExceeded)?;
                    hash.update(bytes.expose_secret());
                }
                if total != meta.size || !hash.finalize().ct_eq(&meta.content_hash) {
                    return Err(StoreError::Integrity);
                }
            }
        }
    }
    cancel(cancelled)
}

#[cfg(test)]
#[path = "acceptance_tests.rs"]
mod tests;
