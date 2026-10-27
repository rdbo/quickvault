// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded attachment chunk roles and streaming reads (0003 §6, 0004 §3.3).
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::{StoreError, UnlockedVault, schema::ObjectReader, vault::scope};
use qv_crypto::{RecordId, SecretArray};
#[cfg(any(target_os = "linux", target_os = "android"))]
use qv_encoding::encode_array;
use qv_model::{AttachmentMeta, Extensions, ObjectId, Text};

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
    use qv_crypto::{ContentHasher, ObjectHashProfile, StoredDataProfile, purpose};
    use qv_model::{Payload, RandomId, RecordBody, VersionId};
    use zeroize::Zeroizing;
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

    impl UnlockedVault {
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
            for (index, id) in meta.chunk_object_ids.iter().enumerate() {
                if cancelled() {
                    return Err(StoreError::Io);
                }
                let r = self
                    .manifest()
                    .reference(*id)
                    .ok_or(StoreError::Integrity)?;
                if r.length() != crate::manifest::chunk_ciphertext_len()? {
                    return Err(StoreError::Integrity);
                }
                let (profile, nonce, ciphertext) =
                    reader.read(header.key_generation, &id.to_bytes(), r.length())?;
                if profile != r.data_profile().id()
                    || qv_crypto::object_hash(ObjectHashProfile::V1, &ciphertext).0 != *r.sha256()
                {
                    return Err(StoreError::Integrity);
                }
                let bytes = qv_crypto::open_chunk(
                    &key,
                    r.data_profile(),
                    &aad(scope(&header), record, *id, index, r.data_profile())?,
                    &nonce,
                    &ciphertext,
                )?;
                let expected = (meta.size - total).min(qv_model::CHUNK_SIZE);
                if bytes.len() as u64 != expected || expected == 0 {
                    return Err(StoreError::Integrity);
                }
                hash.update(bytes.expose_secret());
                total += expected;
                if cancelled() {
                    return Err(StoreError::Io);
                }
                sink.write_all(bytes.expose_secret())
                    .map_err(|_| StoreError::Io)?;
            }
            if cancelled() {
                return Err(StoreError::Io);
            }
            if total != meta.size || hash.finalize().expose_secret() != &meta.content_hash {
                return Err(StoreError::Integrity);
            }
            Ok(())
        }
    }
}
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use platform::aad;
