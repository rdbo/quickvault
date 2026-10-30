// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared authenticated record-role checks for local vaults and archives.

use crate::{
    StoreError,
    manifest::{Manifest, VersionRef},
};
use qv_crypto::RecordId;
use qv_model::{Payload, RecordBody, RecordKind, RecordVersion};
use std::collections::BTreeMap;

/// The control-record kind rules of a verified state (0003 §2.3): the
/// metadata, keyslot and root-group IDs carry their own kinds and no other
/// record may be either control kind.
pub(crate) fn check_control_kinds(
    manifest: &Manifest,
    kinds: &BTreeMap<RecordId, RecordKind>,
) -> Result<(), StoreError> {
    for (&id, &kind) in kinds {
        let expected = if id == manifest.vault_meta_id() {
            Some(RecordKind::VaultMeta)
        } else if id == manifest.keyslot_id() {
            Some(RecordKind::PasswordKeyslot)
        } else if id == manifest.root_group_id() {
            Some(RecordKind::Group)
        } else {
            None
        };
        let ok = match expected {
            Some(e) => kind == e,
            None => !matches!(kind, RecordKind::VaultMeta | RecordKind::PasswordKeyslot),
        };
        if !ok {
            return Err(StoreError::Integrity);
        }
    }
    Ok(())
}

/// Per-head rules that need the decrypted version: chunk lists match an
/// `attachment_meta` payload, the root group stays a live root, and vault
/// metadata names the manifest's root.
pub(crate) fn check_head(
    manifest: &Manifest,
    record: RecordId,
    v: &VersionRef,
    version: &RecordVersion,
) -> Result<(), StoreError> {
    let chunks_ok = match &version.body {
        RecordBody::Live(Payload::AttachmentMeta(a)) => {
            v.chunks() == Some(a.chunk_object_ids.as_slice())
        }
        _ => v.chunks().is_none(),
    };
    if !chunks_ok || v.is_tombstone() != (version.deletion() == qv_model::Deletion::Final) {
        return Err(StoreError::Integrity);
    }
    if record == manifest.root_group_id() {
        version.check_root().map_err(|_| StoreError::Integrity)?;
    }
    if let RecordBody::Live(Payload::VaultMeta(m)) = &version.body
        && m.root_group != manifest.root_group_id()
    {
        return Err(StoreError::Integrity);
    }
    Ok(())
}
