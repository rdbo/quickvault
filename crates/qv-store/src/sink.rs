// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unlock verification hands authenticated heads to the caller (0004 §7.2).

use qv_crypto::RecordId;
use qv_model::RecordVersion;

use crate::error::StoreError;
use crate::manifest::Manifest;

/// Receives what unlock verification has authenticated, so a caller can
/// index each head without decrypting it again.
///
/// [`HeadSink::begin`] runs once, after the manifest is authenticated and
/// before any head is read. [`HeadSink::head`] then runs for every head of
/// every record, in manifest order with each record's heads consecutive,
/// after that head's AEAD and role checks. An error from either aborts the
/// unlock. If the unlock fails later, it returns that error and no vault,
/// so the caller must discard what it built.
pub trait HeadSink {
    /// The unlock's error type; store errors convert into it unchanged.
    type Error: From<StoreError>;

    /// The authenticated manifest, before any head is read.
    fn begin(&mut self, manifest: &Manifest) -> Result<(), Self::Error>;

    /// One authenticated head; `last` marks the record's final head.
    fn head(
        &mut self,
        record: RecordId,
        version: RecordVersion,
        last: bool,
    ) -> Result<(), Self::Error>;
}

/// Discards every head: the plain unlock entry points.
pub struct NoSink;

impl HeadSink for NoSink {
    type Error = StoreError;

    fn begin(&mut self, _manifest: &Manifest) -> Result<(), StoreError> {
        Ok(())
    }

    fn head(&mut self, _: RecordId, _: RecordVersion, _: bool) -> Result<(), StoreError> {
        Ok(())
    }
}
