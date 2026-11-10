// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded attachment chunk roles and streaming reads (0003 §6, 0004 §3.3).
use crate::StoreError;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::{UnlockedVault, schema::ObjectReader, vault::scope};
use qv_crypto::StoredDataProfile;
use qv_crypto::{RecordId, SecretArray};
use qv_encoding::encode_array;
use qv_model::{AttachmentMeta, Extensions, ObjectId, RandomId, Text};
use zeroize::Zeroizing;

/// The measured content of an attachment staged in a Write transaction.
pub struct StagedAttachment {
    pub(crate) chunks: Vec<ObjectId>,
    pub(crate) size: u64,
    pub(crate) hash: SecretArray<32>,
}
impl core::fmt::Debug for StagedAttachment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StagedAttachment(<redacted>)")
    }
}
impl StagedAttachment {
    /// Builds metadata from measured content, never from caller-supplied sizes/hashes.
    pub fn into_meta(self, entry: RecordId, name: Text, mime: Text) -> AttachmentMeta {
        AttachmentMeta {
            entry,
            name,
            mime,
            size: self.size,
            chunk_object_ids: self.chunks,
            content_hash: *self.hash.expose_secret(),
            ext: Extensions::new(),
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use super::*;
    use qv_crypto::{ContentHasher, ObjectHashProfile, purpose};
    use qv_model::{Payload, RecordBody, VersionId};

    impl UnlockedVault {
        /// Reads an individually authenticated range into protected memory.
        /// At most64 KiB; callers verify the whole hash separately before previewing.
        pub fn read_attachment_range(
            &self,
            record: RecordId,
            version: VersionId,
            offset: u64,
            length: usize,
            cancelled: &impl Fn() -> bool,
        ) -> Result<qv_crypto::SecretBytes, StoreError> {
            if length > qv_crypto::CHUNK_BYTES {
                return Err(StoreError::LimitExceeded);
            }
            self.check_identity()?;
            if cancelled() {
                return Err(StoreError::Io);
            }
            let meta = self.attachment_metadata(record, version)?;
            let end = offset
                .checked_add(length as u64)
                .filter(|end| *end <= meta.size)
                .ok_or(StoreError::LimitExceeded)?;
            let mut out = qv_crypto::SecretBytes::zeroed(length);
            if length == 0 {
                return Ok(out);
            }
            let header = self.file.header;
            let root = self.vk.purpose_key::<purpose::Attachment>(
                header.vault_id,
                header.key_generation,
                header.derivation_profile,
            )?;
            let key = root.attachment_key(header.vault_id, qv_crypto::AttachmentId(record.0))?;
            let mut reader = ObjectReader::new(&self.file.conn)?;
            let first = usize::try_from(offset / qv_model::CHUNK_SIZE)
                .map_err(|_| StoreError::LimitExceeded)?;
            let last = usize::try_from((end - 1) / qv_model::CHUNK_SIZE)
                .map_err(|_| StoreError::LimitExceeded)?;
            let mut copied = 0;
            for index in first..=last {
                if cancelled() {
                    return Err(StoreError::Io);
                }
                let bytes = self.attachment_chunk(&mut reader, &key, &meta, record, index)?;
                let start = if index == first {
                    (offset % qv_model::CHUNK_SIZE) as usize
                } else {
                    0
                };
                let count = (length - copied).min(
                    bytes
                        .len()
                        .checked_sub(start)
                        .ok_or(StoreError::Integrity)?,
                );
                out.expose_secret_mut()[copied..copied + count]
                    .copy_from_slice(&bytes.expose_secret()[start..start + count]);
                copied += count;
            }
            if copied != length {
                return Err(StoreError::Integrity);
            }
            if cancelled() {
                return Err(StoreError::Io);
            }
            Ok(out)
        }

        fn attachment_metadata(
            &self,
            record: RecordId,
            version: VersionId,
        ) -> Result<AttachmentMeta, StoreError> {
            let v = self.read_version(record, version)?;
            let meta = match v.body {
                RecordBody::Live(Payload::AttachmentMeta(a)) => a,
                _ => return Err(StoreError::NotFound),
            };
            let role = self
                .manifest()
                .record(record)
                .and_then(|r| r.version(version))
                .ok_or(StoreError::Integrity)?;
            if role.chunks() != Some(meta.chunk_object_ids.as_slice()) {
                return Err(StoreError::Integrity);
            }
            Ok(meta)
        }

        fn attachment_chunk(
            &self,
            reader: &mut ObjectReader<'_>,
            key: &qv_crypto::DataKey,
            meta: &AttachmentMeta,
            record: RecordId,
            index: usize,
        ) -> Result<qv_crypto::SecretBytes, StoreError> {
            let header = self.file.header;
            let id = *meta
                .chunk_object_ids
                .get(index)
                .ok_or(StoreError::Integrity)?;
            let reference = self.manifest().reference(id).ok_or(StoreError::Integrity)?;
            if reference.length() != crate::manifest::chunk_ciphertext_len()? {
                return Err(StoreError::Integrity);
            }
            let (profile, nonce, ciphertext) =
                reader.read(header.key_generation, &id.to_bytes(), reference.length())?;
            if profile != reference.data_profile().id()
                || qv_crypto::object_hash(ObjectHashProfile::V1, &ciphertext).0
                    != *reference.sha256()
            {
                return Err(StoreError::Integrity);
            }
            let bytes = qv_crypto::open_chunk(
                key,
                reference.data_profile(),
                &aad(scope(&header), record, id, index, reference.data_profile())?,
                &nonce,
                &ciphertext,
            )?;
            let start = (index as u64)
                .checked_mul(qv_model::CHUNK_SIZE)
                .ok_or(StoreError::Integrity)?;
            let expected = meta
                .size
                .checked_sub(start)
                .ok_or(StoreError::Integrity)?
                .min(qv_model::CHUNK_SIZE);
            if expected == 0 || bytes.len() as u64 != expected {
                return Err(StoreError::Integrity);
            }
            Ok(bytes)
        }

        /// Verifies all chunks and the complete content without releasing plaintext.
        pub fn verify_attachment(
            &self,
            record: RecordId,
            version: VersionId,
            cancelled: &impl Fn() -> bool,
        ) -> Result<(), StoreError> {
            self.read_attachment(record, version, &mut std::io::sink(), cancelled)
        }
        /// Streams individually authenticated chunks. Only Ok confirms the whole hash/length.
        /// A failed call can leave partial output in the caller's sink; it must not be accepted.
        pub fn read_attachment(
            &self,
            record: RecordId,
            version: VersionId,
            sink: &mut impl std::io::Write,
            cancelled: &impl Fn() -> bool,
        ) -> Result<(), StoreError> {
            self.check_identity()?;
            let meta = self.attachment_metadata(record, version)?;
            let header = self.file.header;
            let root = self.vk.purpose_key::<purpose::Attachment>(
                header.vault_id,
                header.key_generation,
                header.derivation_profile,
            )?;
            let key = root.attachment_key(header.vault_id, qv_crypto::AttachmentId(record.0))?;
            let mut reader = ObjectReader::new(&self.file.conn)?;
            let mut hash = ContentHasher::new();
            let mut total = 0u64;
            for index in 0..meta.chunk_object_ids.len() {
                if cancelled() {
                    return Err(StoreError::Io);
                }
                let bytes = self.attachment_chunk(&mut reader, &key, &meta, record, index)?;
                let expected = bytes.len() as u64;
                hash.update(bytes.expose_secret());
                total += expected;
                if cancelled() {
                    return Err(StoreError::Io);
                }
                sink.write_all(bytes.expose_secret())
                    .map_err(crate::error::io_err)?;
            }
            if cancelled() {
                return Err(StoreError::Io);
            }
            if total != meta.size || !hash.finalize().ct_eq(&meta.content_hash) {
                return Err(StoreError::Integrity);
            }
            Ok(())
        }
    }
}

pub(crate) fn aad(
    scope: crate::object::Scope,
    attachment: RecordId,
    object: ObjectId,
    index: usize,
    profile: StoredDataProfile,
) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    encode_array(|a| {
        a.text("qv/chunk/v1");
        a.bytes(&scope.vault_id.0);
        a.uint(u64::from(scope.key_generation.0));
        a.bytes(&attachment.0);
        a.bytes(&object.to_bytes());
        a.uint(index as u64);
        a.uint(u64::from(profile.id()));
        Ok(())
    })
    .map_err(|_| StoreError::Internal)
}
