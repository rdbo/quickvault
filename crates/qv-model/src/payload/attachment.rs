// SPDX-License-Identifier: AGPL-3.0-or-later

//! Attachment metadata (spec 0003 §6.1).
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | entry | bstr 16 |
//! | 1 | name | text |
//! | 2 | mime | text |
//! | 3 | size | uint (at most [`MAX_ATTACHMENT_BYTES`]) |
//! | 4 | chunk_count | uint |
//! | 5 | chunk_object_ids | array of bstr 16, unique |
//! | 6 | content_hash | bstr 32: SHA-256 of the whole plaintext |
//!
//! All keys are required. `chunk_count` must equal the list length and
//! `ceil(size / 64 KiB)`; it is written from the list. The attachment ID is
//! this record's ID ([`crate::attachment_id`]). Name and MIME type are
//! untrusted metadata (0003 §6.3).

use std::collections::BTreeSet;
use zeroize::{Zeroize, Zeroizing};

use qv_encoding::{Decoder, EncodeError, Encoder};

use crate::codec::{
    keep, put_bytes, put_ext, put_id, put_text, put_uint, read_array, read_array_len, read_id,
    read_map_len, read_text, req,
};
use crate::error::ModelError;
use crate::ids::{ObjectId, RecordId};
use crate::text::{Extensions, Text};

/// Attachment content chunk size (0003 §6.2).
pub const CHUNK_SIZE: u64 = 64 * 1024;
/// The initial client maximum attachment size (0003 §6.3).
pub const MAX_ATTACHMENT_BYTES: u64 = 10 * 1024 * 1024;
/// The most chunks an attachment can have.
const MAX_CHUNKS: usize = (MAX_ATTACHMENT_BYTES / CHUNK_SIZE) as usize;

/// An `attachment_meta` record's payload.
pub struct AttachmentMeta {
    /// The owning entry.
    pub entry: RecordId,
    /// The file name (untrusted).
    pub name: Text,
    /// The MIME type (untrusted).
    pub mime: Text,
    /// The content length in bytes.
    pub size: u64,
    /// The content's chunk objects, in order.
    pub chunk_object_ids: Vec<ObjectId>,
    /// SHA-256 of the complete plaintext content.
    pub content_hash: [u8; 32],
    /// Unknown keys.
    pub ext: Extensions,
}

crate::redacted_debug!(AttachmentMeta);

impl Drop for AttachmentMeta {
    fn drop(&mut self) {
        self.content_hash.zeroize();
    }
}

/// Size limit, chunk count and unique chunk IDs.
pub(crate) fn check(p: &AttachmentMeta) -> Result<(), ModelError> {
    if p.size > MAX_ATTACHMENT_BYTES || p.chunk_object_ids.len() > MAX_CHUNKS {
        return Err(ModelError::LimitExceeded);
    }
    let expected = p.size.div_ceil(CHUNK_SIZE);
    if u64::try_from(p.chunk_object_ids.len()).ok() != Some(expected) {
        return Err(ModelError::Malformed);
    }
    let unique: BTreeSet<_> = p.chunk_object_ids.iter().collect();
    if unique.len() != p.chunk_object_ids.len() {
        return Err(ModelError::Malformed);
    }
    Ok(())
}

pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<AttachmentMeta, ModelError> {
    let (mut entry, mut name, mut mime, mut size, mut count, mut chunks, mut hash) =
        (None, None, None, None, None, None, None);
    let mut ext = Extensions::new();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => entry = Some(read_id(d)?),
            1 => name = Some(read_text(d)?),
            2 => mime = Some(read_text(d)?),
            3 => size = Some(d.uint()?),
            4 => count = Some(d.uint()?),
            5 => {
                let n = read_array_len(d, MAX_CHUNKS)?;
                let mut list = Vec::with_capacity(n);
                for _ in 0..n {
                    list.push(read_id(d)?);
                }
                chunks = Some(list);
            }
            6 => hash = Some(Zeroizing::new(read_array::<32>(d)?)),
            k => keep(&mut ext, k, d)?,
        }
    }
    let meta = AttachmentMeta {
        entry: req(entry)?,
        name: req(name)?,
        mime: req(mime)?,
        size: req(size)?,
        chunk_object_ids: req(chunks)?,
        content_hash: *req(hash)?,
        ext,
    };
    check(&meta)?;
    if u64::try_from(meta.chunk_object_ids.len()).ok() != Some(req(count)?) {
        return Err(ModelError::Malformed);
    }
    Ok(meta)
}

pub(crate) fn encode(p: &AttachmentMeta, e: &mut Encoder) -> Result<(), EncodeError> {
    e.map(|m| {
        put_id(m, 0, &p.entry)?;
        put_text(m, 1, &p.name)?;
        put_text(m, 2, &p.mime)?;
        put_uint(m, 3, p.size)?;
        put_uint(m, 4, p.chunk_object_ids.len() as u64)?;
        m.entry(5, |v| {
            v.array(|a| {
                for id in &p.chunk_object_ids {
                    a.bytes(&crate::ids::RandomId::to_bytes(id));
                }
                Ok(())
            })
        })?;
        put_bytes(m, 6, &p.content_hash)?;
        put_ext(m, &p.ext)
    })
}
