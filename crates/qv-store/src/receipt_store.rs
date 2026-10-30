// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local receipt AEAD/storage binding (0004 §2.3); no incoming acceptance API.

use qv_crypto::{ObjectHashProfile, object_hash};
use qv_encoding::{Decoder, encode_array};
use rusqlite::Connection;

use crate::{
    ArchiveReceipts, StoreError,
    header::Header,
    receipts::{MAX_RECEIPT_CIPHERTEXT, MAX_RECEIPT_ENVELOPE},
    schema::validation_err,
    vault::{Keys, accepted_profile},
};

fn malformed<T>(_: T) -> StoreError {
    StoreError::Integrity
}

pub(crate) fn aad(
    header: &Header,
    replica: &[u8; 16],
    profile: u16,
) -> Result<zeroize::Zeroizing<Vec<u8>>, StoreError> {
    encode_array(|a| {
        a.text("qv/archive-receipts/v1");
        a.bytes(&header.vault_id.0);
        a.uint(u64::from(header.key_generation.0));
        a.bytes(replica);
        a.uint(u64::from(profile));
        Ok(())
    })
    .map_err(|_| StoreError::Internal)
}

pub(crate) fn digest(blob: &[u8]) -> [u8; 32] {
    object_hash(ObjectHashProfile::V1, blob).0
}

pub(crate) fn seal(
    receipts: &ArchiveReceipts,
    keys: &Keys,
    header: &Header,
    replica: &[u8; 16],
) -> Result<Vec<u8>, StoreError> {
    let plaintext = receipts.encode()?;
    let sealed = qv_crypto::seal(
        &keys.local,
        header.data_profile,
        &aad(header, replica, header.data_profile.id())?,
        plaintext.expose_secret(),
        MAX_RECEIPT_CIPHERTEXT,
    )?;
    Ok(encode_array(|a| {
        a.uint(1);
        a.uint(u64::from(header.data_profile.id()));
        a.bytes(&sealed.nonce);
        a.bytes(&sealed.ciphertext);
        Ok(())
    })
    .map_err(|_| StoreError::Internal)?
    .to_vec())
}

pub(crate) fn open(
    blob: &[u8],
    expected: &[u8; 32],
    keys: &Keys,
    header: &Header,
    replica: &[u8; 16],
) -> Result<ArchiveReceipts, StoreError> {
    if blob.len() > MAX_RECEIPT_ENVELOPE {
        return Err(StoreError::LimitExceeded);
    }
    if &digest(blob) != expected {
        return Err(StoreError::Integrity);
    }
    let mut d = Decoder::new(blob).map_err(malformed)?;
    if d.array().map_err(malformed)? != 4 {
        return Err(StoreError::Integrity);
    }
    if d.uint().map_err(malformed)? != 1 {
        return Err(StoreError::Unsupported);
    }
    let profile = u16::try_from(d.uint().map_err(malformed)?).map_err(malformed)?;
    let profile = accepted_profile(header, profile)?;
    let nonce = d
        .bytes()
        .map_err(malformed)?
        .try_into()
        .map_err(malformed)?;
    let ciphertext = d.bytes().map_err(malformed)?;
    d.finish().map_err(malformed)?;
    let plaintext = qv_crypto::open(
        &keys.local,
        profile,
        &aad(header, replica, profile.id())?,
        &nonce,
        ciphertext,
        MAX_RECEIPT_CIPHERTEXT,
    )
    .map_err(|e| match e {
        qv_crypto::CryptoError::LimitExceeded => StoreError::LimitExceeded,
        _ => StoreError::Integrity,
    })?;
    ArchiveReceipts::decode(plaintext.expose_secret())
}

/// Independently check row count/type/length before allocating an untrusted blob.
pub(crate) fn read(conn: &Connection) -> Result<Vec<u8>, StoreError> {
    check(conn)?;
    conn.query_row(
        "SELECT sealed FROM archive_receipts WHERE id = 1",
        [],
        |r| r.get(0),
    )
    .map_err(|e| validation_err(&e))
}

pub(crate) fn check(conn: &Connection) -> Result<(), StoreError> {
    let count: i64 = conn
        .query_row("SELECT count(*) FROM archive_receipts", [], |r| r.get(0))
        .map_err(|e| validation_err(&e))?;
    if count != 1 {
        return Err(StoreError::Integrity);
    }
    let (id, kind, len): (i64, String, i64) = conn
        .query_row(
            "SELECT id, typeof(sealed), octet_length(sealed) FROM archive_receipts",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .map_err(|e| validation_err(&e))?;
    if id != 1 || kind != "blob" || len < 0 {
        return Err(StoreError::Integrity);
    }
    if usize::try_from(len).map_err(malformed)? > MAX_RECEIPT_ENVELOPE {
        return Err(StoreError::LimitExceeded);
    }
    Ok(())
}

/// Only unpublished new-replica/generation builders initialize empty receipts.
pub(crate) fn initialize(
    conn: &Connection,
    keys: &Keys,
    header: &Header,
    replica: &[u8; 16],
) -> Result<[u8; 32], StoreError> {
    let blob = seal(&ArchiveReceipts::new(), keys, header, replica)?;
    conn.execute(
        "INSERT INTO archive_receipts (id, sealed) VALUES (1, ?1)",
        [&blob],
    )
    .map_err(|e| validation_err(&e))?;
    Ok(digest(&blob))
}
