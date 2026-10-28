// SPDX-License-Identifier: AGPL-3.0-or-later

//! The full `verify` pass (spec 0004 §3.6; 0011 `verify`).
//!
//! [`UnlockedVault::verify_all`] re-authenticates the committed state this
//! session holds, in one read transaction and one deterministic order:
//!
//! 1. the stored manifest row against the authenticated head (hash,
//!    generation and profile), then its AEAD, decode and validation, and
//!    finally its identity with the manifest the session verified;
//! 2. every referenced object's existence, accepted profile, referenced
//!    length and full SHA-256 of its stored ciphertext (0004 §3.6);
//! 3. every active head and every retained history version: reference hash
//!    (history), AEAD, the per-head rules and the record-kind rules;
//! 4. every attachment version's whole content, through the existing
//!    streaming chunk verifier.
//!
//! It reads only: no `Write`, no manifest, head, anchor or pruning step is
//! involved, and nothing is repaired. Missing or mismatched data is
//! [`StoreError::Integrity`], never an empty record; unreferenced object rows
//! are ignored. One object is authenticated at a time, so memory is bounded
//! by the largest single object, and cancellation between objects is
//! [`StoreError::Io`].
//!
//! A history floor that covers versions absent by design is *expected state*
//! after a purge (0007 §1.2, §1.4): it is counted in
//! [`VerifyCounts::suppressed_records`] and reported as a note by the caller,
//! never as damage. The local-head-versus-anchor comparison (0005 §5.4) is
//! the caller's, because a missing or mismatched anchor has to be *reported*
//! with the counts rather than raised before the report exists (0011 §4).

use std::collections::BTreeMap;

use qv_crypto::{ObjectHashProfile, RecordId, object_hash};
use qv_model::{RandomId, RecordKind};

use crate::error::StoreError;
use crate::manifest;
use crate::schema::{self, ObjectReader};
use crate::vault::{
    Keys, UnlockedVault, accepted_profile, check_control_kinds, check_head, read_role, scope,
};

/// What one full pass counted (0011 `verify`).
///
/// Counts are the same aggregate integers the command prints: no record,
/// version, object ID, hash or payload is kept.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyCounts {
    /// Referenced objects whose stored ciphertext was re-hashed.
    pub objects: u64,
    /// Records in the manifest, tombstones included.
    pub records: u64,
    /// Active heads whose AEAD was re-verified.
    pub active_heads: u64,
    /// Retained history versions whose AEAD was re-verified.
    pub retained_versions: u64,
    /// Active heads that are final tombstones.
    pub tombstones: u64,
    /// Records carrying a history suppression floor: expected after a purge.
    pub suppressed_records: u64,
    /// The total referenced ciphertext length.
    pub total_bytes: u64,
}

impl UnlockedVault {
    /// The full re-hash and authentication pass over the committed state
    /// (0004 §3.6). Read-only: it never mutates, repairs or rewrites
    /// anything.
    ///
    /// Fails with [`StoreError::Changed`] if the head on disk is no longer
    /// the one this session verified, and with [`StoreError::Integrity`] for
    /// any missing or mismatched manifest, object, head, history version or
    /// attachment chunk.
    pub fn verify_all(&self, cancelled: &dyn Fn() -> bool) -> Result<VerifyCounts, StoreError> {
        self.begin_read()?;
        match self.verify_pass(cancelled) {
            Ok(counts) => {
                self.end_read()?;
                Ok(counts)
            }
            Err(e) => {
                self.abort_read();
                Err(e)
            }
        }
    }

    /// The pass itself, inside the caller's read transaction.
    fn verify_pass(&self, cancelled: &dyn Fn() -> bool) -> Result<VerifyCounts, StoreError> {
        let header = self.file.header;
        let keys = Keys::derive(&self.vk, &header)?;

        // 1. The manifest against the head, then its AEAD and identity.
        let stored = schema::read_manifest(&self.file.conn)?;
        if stored.hash != self.state.head.manifest_hash
            || stored.key_generation != header.key_generation
        {
            return Err(StoreError::Integrity);
        }
        let profile = accepted_profile(&header, stored.data_profile)?;
        if manifest::envelope_hash(
            header.key_generation,
            profile,
            &stored.nonce,
            &stored.ciphertext,
        )? != stored.hash
        {
            return Err(StoreError::Integrity);
        }
        let manifest = manifest::open_manifest(
            &keys.manifest,
            scope(&header),
            profile,
            &stored.nonce,
            &stored.ciphertext,
        )?;
        if *manifest.config_digest() != manifest::config_digest(&header)?
            || manifest != self.state.manifest
        {
            return Err(StoreError::Integrity);
        }

        let mut counts = VerifyCounts::default();
        let mut reader = ObjectReader::new(&self.file.conn)?;

        // 2. Every reference: existence, profile, length and SHA-256.
        for r in manifest.references() {
            if cancelled() {
                return Err(StoreError::Io);
            }
            accepted_profile(&header, r.data_profile().id())?;
            let (row_profile, _nonce, ciphertext) =
                reader.read(header.key_generation, &r.object_id().to_bytes(), r.length())?;
            if row_profile != r.data_profile().id()
                || object_hash(ObjectHashProfile::V1, &ciphertext).0 != *r.sha256()
            {
                return Err(StoreError::Integrity);
            }
            counts.objects = counts.objects.checked_add(1).ok_or(StoreError::Internal)?;
            counts.total_bytes = counts
                .total_bytes
                .checked_add(r.length())
                .ok_or(StoreError::LimitExceeded)?;
        }

        // 3. Every head and retained version, one at a time, in manifest
        // order (records by ID, then version ID).
        let mut kinds: BTreeMap<RecordId, RecordKind> = BTreeMap::new();
        for entry in manifest.records() {
            if cancelled() {
                return Err(StoreError::Io);
            }
            let record = entry.record_id();
            counts.records = counts.records.checked_add(1).ok_or(StoreError::Internal)?;
            if !entry.floor().clock().pairs().is_empty() {
                // A purge floor covering versions absent by design (0007
                // §1.2, §1.4): expected state, not damage.
                counts.suppressed_records = counts
                    .suppressed_records
                    .checked_add(1)
                    .ok_or(StoreError::Internal)?;
            }
            for head in entry.heads() {
                if cancelled() {
                    return Err(StoreError::Io);
                }
                let version =
                    read_role(&mut reader, &keys, &header, &manifest, record, head, false)?;
                check_head(&manifest, record, head, &version)?;
                record_kind(&mut kinds, record, version.kind())?;
                if version.deletion() == qv_model::Deletion::Final {
                    counts.tombstones = counts
                        .tombstones
                        .checked_add(1)
                        .ok_or(StoreError::Internal)?;
                }
                counts.active_heads = counts
                    .active_heads
                    .checked_add(1)
                    .ok_or(StoreError::Internal)?;
                // 4. An attachment head verifies its whole content.
                self.verify_attachment_content(record, head.version_id(), &version, &cancelled)?;
            }
            for retained in entry.history() {
                if cancelled() {
                    return Err(StoreError::Io);
                }
                // A history read checks the reference hash before AEAD
                // (0004 §3.6).
                let version = read_role(
                    &mut reader,
                    &keys,
                    &header,
                    &manifest,
                    record,
                    retained,
                    true,
                )?;
                record_kind(&mut kinds, record, version.kind())?;
                counts.retained_versions = counts
                    .retained_versions
                    .checked_add(1)
                    .ok_or(StoreError::Internal)?;
                self.verify_attachment_content(
                    record,
                    retained.version_id(),
                    &version,
                    &cancelled,
                )?;
            }
        }
        check_control_kinds(&manifest, &kinds)?;
        if cancelled() {
            return Err(StoreError::Io);
        }
        Ok(counts)
    }

    /// Verifies an `attachment_meta` version's chunks and content hash. Other
    /// versions need nothing here.
    fn verify_attachment_content(
        &self,
        record: RecordId,
        version: qv_model::VersionId,
        decrypted: &qv_model::RecordVersion,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(), StoreError> {
        if matches!(
            decrypted.body,
            qv_model::RecordBody::Live(qv_model::Payload::AttachmentMeta(_))
        ) {
            self.verify_attachment(record, version, &cancelled)?;
        }
        Ok(())
    }
}

/// Records one decrypted version's kind, refusing a record whose versions
/// disagree (0003 §2.3).
fn record_kind(
    kinds: &mut BTreeMap<RecordId, RecordKind>,
    record: RecordId,
    kind: RecordKind,
) -> Result<(), StoreError> {
    match kinds.get(&record) {
        Some(&known) if known != kind => Err(StoreError::Integrity),
        Some(_) => Ok(()),
        None => {
            kinds.insert(record, kind);
            Ok(())
        }
    }
}
