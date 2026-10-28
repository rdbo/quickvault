// SPDX-License-Identifier: AGPL-3.0-or-later

//! Role-aware archive authentication, without SQLite or plaintext staging.
use std::{
    collections::BTreeMap,
    io::{Read, Seek},
};

use crate::{
    StoreError,
    archive::{ArchiveHeader, IndexedFrame, object_envelope},
    manifest::{Manifest, VersionRef},
    object::{RecordRole, Scope, open_record},
    validation::{check_control_kinds, check_head},
};
use qv_crypto::{AttachmentId, ContentHasher, RecordId, VaultKey, purpose};
use qv_model::{Payload, RecordBody, RecordKind, RecordVersion};

pub(crate) fn verify<R: Read + Seek>(
    input: &mut R,
    header: &ArchiveHeader,
    manifest: &Manifest,
    frames: &[IndexedFrame],
    vk: &VaultKey,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), StoreError> {
    let scope = Scope {
        vault_id: header.vault_id(),
        key_generation: header.key_generation(),
    };
    let record_key = vk.purpose_key::<purpose::Record>(
        scope.vault_id,
        scope.key_generation,
        crate::archive::ARCHIVE_DERIVATION_PROFILE,
    )?;
    let attachment_root = vk.purpose_key::<purpose::Attachment>(
        scope.vault_id,
        scope.key_generation,
        crate::archive::ARCHIVE_DERIVATION_PROFILE,
    )?;
    let mut kinds = BTreeMap::<RecordId, RecordKind>::new();
    for record in manifest.records() {
        for role in record.heads().iter().chain(record.history()) {
            if cancelled() {
                return Err(StoreError::Io);
            }
            let id = record.record_id();
            let version = read_version(input, header, manifest, frames, &record_key, id, role)?;
            check_head(manifest, id, role, &version)?;
            if let Some(kind) = kinds.insert(id, version.kind())
                && kind != version.kind()
            {
                return Err(StoreError::Integrity);
            }
            if let RecordBody::Live(Payload::AttachmentMeta(meta)) = &version.body {
                let key = attachment_root.attachment_key(scope.vault_id, AttachmentId(id.0))?;
                let mut hash = ContentHasher::new();
                let mut total = 0u64;
                for (index, object) in meta.chunk_object_ids.iter().enumerate() {
                    if cancelled() {
                        return Err(StoreError::Io);
                    }
                    let (reference, indexed) = locate(manifest, frames, *object)?;
                    if reference.length() != crate::manifest::chunk_ciphertext_len()? {
                        return Err(StoreError::Integrity);
                    }
                    let frame = indexed.read(input, header, reference)?;
                    let envelope = object_envelope(&frame, header, reference)?;
                    let bytes = qv_crypto::open_chunk(
                        &key,
                        reference.data_profile(),
                        &crate::attachment::aad(
                            scope,
                            id,
                            *object,
                            index,
                            reference.data_profile(),
                        )?,
                        envelope.nonce(),
                        envelope.ciphertext(),
                    )?;
                    let expected = meta
                        .size
                        .checked_sub(total)
                        .ok_or(StoreError::Integrity)?
                        .min(qv_model::CHUNK_SIZE);
                    if expected == 0 || bytes.len() as u64 != expected {
                        return Err(StoreError::Integrity);
                    }
                    hash.update(bytes.expose_secret());
                    total = total
                        .checked_add(expected)
                        .ok_or(StoreError::LimitExceeded)?;
                }
                if total != meta.size || !hash.finalize().ct_eq(&meta.content_hash) {
                    return Err(StoreError::Integrity);
                }
            }
        }
    }
    check_control_kinds(manifest, &kinds)?;
    if cancelled() {
        return Err(StoreError::Io);
    }
    Ok(())
}

fn locate<'a>(
    manifest: &'a Manifest,
    frames: &'a [IndexedFrame],
    id: qv_model::ObjectId,
) -> Result<(&'a crate::manifest::ObjectRef, &'a IndexedFrame), StoreError> {
    let index = manifest
        .references()
        .binary_search_by_key(&id, |r| r.object_id())
        .map_err(|_| StoreError::Integrity)?;
    Ok((
        &manifest.references()[index],
        frames.get(index).ok_or(StoreError::Integrity)?,
    ))
}

pub(crate) fn read_version<R: Read + Seek>(
    input: &mut R,
    header: &ArchiveHeader,
    manifest: &Manifest,
    frames: &[IndexedFrame],
    key: &qv_crypto::PurposeKey<purpose::Record>,
    record: RecordId,
    role: &VersionRef,
) -> Result<RecordVersion, StoreError> {
    let (reference, indexed) = locate(manifest, frames, role.object_id())?;
    let frame = indexed.read(input, header, reference)?;
    let envelope = object_envelope(&frame, header, reference)?;
    let scope = Scope {
        vault_id: header.vault_id(),
        key_generation: header.key_generation(),
    };
    open_record(
        key,
        scope,
        &RecordRole {
            record,
            version: role.version_id(),
            clock: role.clock(),
            object: role.object_id(),
        },
        reference.data_profile(),
        envelope.nonce(),
        envelope.ciphertext(),
    )
}
