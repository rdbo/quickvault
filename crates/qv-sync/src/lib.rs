// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared whole-record merge candidates (0005 §1–2, §4; 0007 §1–2).
//!
//! This layer does not write accepted state. A candidate contains validated
//! metadata, not authenticated object bytes or permission to commit them.
//! Callers must supply authenticated, role-bound reads from stable sources.
//! Later acceptance must check source scope/identity and stage objects through
//! the existing store transaction/anchor path; no unchecked frontend bridge.

use std::collections::{BTreeMap, BTreeSet};

use qv_crypto::RecordId;
use qv_model::{
    Clock, Deletion, HistoryFloor, ObjectId, Payload, RecordBody, RecordKind, RecordVersion,
    VersionId, Versioned,
};
use qv_store::{Manifest, ObjectRef, RecordEntry, StoreError, VersionRef};

/// Which stable input supplies an encrypted object or authenticated record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Current local accepted state.
    Local,
    /// Fully authenticated private incoming archive.
    Incoming,
}

/// Validated merged metadata and the source of each retained encrypted object.
/// No plaintext records, keys, timestamps or synthetic versions are retained.
pub struct Candidate {
    manifest: Manifest,
    sources: BTreeMap<ObjectId, Source>,
}

impl core::fmt::Debug for Candidate {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Candidate(..)")
    }
}

impl Candidate {
    /// Complete validated manifest, including joined suppression floors.
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Where to re-read a retained object for later authenticated staging.
    pub fn source(&self, object: ObjectId) -> Option<Source> {
        self.sources.get(&object).copied()
    }
}

struct Version {
    role: VersionRef,
    deletion: Deletion,
    source: Source,
}

impl Versioned for Version {
    fn version_id(&self) -> VersionId {
        self.role.version_id()
    }
    fn clock(&self) -> &Clock {
        self.role.clock()
    }
    fn deletion(&self) -> Deletion {
        self.deletion
    }
    fn same_version(&self, other: &Self) -> bool {
        // Full logical identity is checked before deduplication in merge_record.
        self.role == other.role && self.deletion == other.deletion
    }
}

/// Compute a bounded candidate without modifying either input or accepted state.
///
/// `read` must authenticate the requested source/record/version role. Only two
/// decoded versions at a time are needed for canonical identity comparison.
/// Neither receive order nor wall-clock dates create or resolve a version.
/// Duplicate logical versions prefer the local envelope, without re-encryption.
pub fn merge(
    local: &Manifest,
    incoming: &Manifest,
    read: &mut impl FnMut(Source, RecordId, VersionId) -> Result<RecordVersion, StoreError>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Candidate, StoreError> {
    check_cancel(cancelled)?;
    if !local.same_configuration(incoming) {
        return Err(StoreError::Integrity);
    }
    let mut owners = BTreeMap::new();
    for input in [local, incoming] {
        for record in input.records() {
            check_cancel(cancelled)?;
            for role in record.heads().iter().chain(record.history()) {
                if owners
                    .insert(role.version_id(), record.record_id())
                    .is_some_and(|id| id != record.record_id())
                {
                    return Err(StoreError::Integrity);
                }
            }
        }
    }
    // Check all overlapping object identities, even if history suppression
    // would otherwise remove one. Never use suppression to hide tampering.
    for r in incoming.references() {
        check_cancel(cancelled)?;
        if let Some(l) = local.reference(r.object_id())
            && l != r
        {
            return Err(StoreError::Integrity);
        }
    }
    let ids: BTreeSet<_> = local
        .records()
        .iter()
        .chain(incoming.records())
        .map(RecordEntry::record_id)
        .collect();
    if ids.len() > qv_store::MAX_RECORDS {
        return Err(StoreError::LimitExceeded);
    }
    let mut records = Vec::with_capacity(ids.len());
    let mut references = BTreeMap::<ObjectId, ObjectRef>::new();
    let mut sources = BTreeMap::new();
    let mut components = 0usize;
    let mut bytes = 0u64;
    for id in ids {
        check_cancel(cancelled)?;
        let (record, versions) = merge_record(local, incoming, id, read, cancelled)?;
        components = components.saturating_add(record.floor().clock().pairs().len());
        for v in versions {
            components = components.saturating_add(v.role.clock().pairs().len());
            if components > qv_store::MAX_CLOCK_COMPONENTS {
                return Err(StoreError::LimitExceeded);
            }
            let input = match v.source {
                Source::Local => local,
                Source::Incoming => incoming,
            };
            for object in std::iter::once(v.role.object_id())
                .chain(v.role.chunks().into_iter().flatten().copied())
            {
                check_cancel(cancelled)?;
                if references.len() == qv_store::MAX_OBJECTS {
                    return Err(StoreError::LimitExceeded);
                }
                let r = *input.reference(object).ok_or(StoreError::Integrity)?;
                bytes = bytes
                    .checked_add(r.length())
                    .filter(|n| *n <= qv_store::MAX_TOTAL_CIPHERTEXT)
                    .ok_or(StoreError::LimitExceeded)?;
                if references.insert(object, r).is_some() {
                    // An object must have exactly one record/chunk role.
                    return Err(StoreError::Integrity);
                }
                sources.insert(object, v.source);
            }
        }
        records.push(record);
    }
    check_cancel(cancelled)?;
    let manifest = local.candidate(records, references.into_values().collect())?;
    Ok(Candidate { manifest, sources })
}

fn check_cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
    if cancelled() {
        Err(StoreError::Io)
    } else {
        Ok(())
    }
}

fn merge_record(
    local: &Manifest,
    incoming: &Manifest,
    id: RecordId,
    read: &mut impl FnMut(Source, RecordId, VersionId) -> Result<RecordVersion, StoreError>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(RecordEntry, Vec<Version>), StoreError> {
    let mut floor = HistoryFloor::new(Clock::new());
    let mut versions = BTreeMap::<VersionId, Version>::new();
    let mut kind = None;
    for (source, input) in [(Source::Local, local), (Source::Incoming, incoming)] {
        let Some(record) = input.record(id) else {
            continue;
        };
        floor = floor.join(&record.floor())?;
        for role in record.heads().iter().chain(record.history()) {
            check_cancel(cancelled)?;
            let version = read(source, id, role.version_id())?;
            check_version(input, id, role, &version)?;
            if kind.is_some_and(|k| k != version.kind()) {
                return Err(StoreError::Integrity);
            }
            kind = Some(version.kind());
            if let Some(known) = versions.get(&role.version_id()) {
                let old = read(known.source, id, known.role.version_id())?;
                check_version(local, id, &known.role, &old)?;
                let mut left = qv_crypto::ContentHasher::new();
                left.update(&old.encode()?);
                let mut right = qv_crypto::ContentHasher::new();
                right.update(&version.encode()?);
                if !left.finalize().ct_eq(right.finalize().expose_secret()) {
                    return Err(StoreError::Integrity);
                }
                continue;
            }
            versions.insert(
                role.version_id(),
                Version {
                    role: role.clone(),
                    deletion: version.deletion(),
                    source,
                },
            );
        }
    }
    let (heads, dominated) = qv_model::merge(versions.into_values())?.into_parts();
    check_cancel(cancelled)?;
    let mut history = Vec::new();
    for v in dominated {
        if floor.suppresses(v.clock()) {
            // Permanent tombstones cannot be removed by a history floor. The
            // current manifest format cannot retain covered dominated roles;
            // fail closed instead of forgetting final-deletion knowledge.
            if v.deletion == Deletion::Final {
                return Err(StoreError::Integrity);
            }
        } else {
            history.push(v);
        }
    }
    let record = RecordEntry::from_parts(
        id,
        heads.iter().map(|v| v.role.clone()).collect(),
        history.iter().map(|v| v.role.clone()).collect(),
        floor,
    )?;
    let versions = heads.into_iter().chain(history).collect();
    Ok((record, versions))
}

fn check_version(
    manifest: &Manifest,
    id: RecordId,
    role: &VersionRef,
    version: &RecordVersion,
) -> Result<(), StoreError> {
    if version.version_id != role.version_id() || &version.clock != role.clock() {
        return Err(StoreError::Integrity);
    }
    let expected = if id == manifest.vault_meta_id() {
        Some(RecordKind::VaultMeta)
    } else if id == manifest.keyslot_id() {
        Some(RecordKind::PasswordKeyslot)
    } else if id == manifest.root_group_id() {
        Some(RecordKind::Group)
    } else {
        None
    };
    if (expected.is_some() && version.deletion() != Deletion::Live)
        || expected.is_some_and(|kind| kind != version.kind())
        || (expected.is_none()
            && matches!(
                version.kind(),
                RecordKind::VaultMeta | RecordKind::PasswordKeyslot
            ))
    {
        return Err(StoreError::Integrity);
    }
    let chunks = match &version.body {
        RecordBody::Live(Payload::AttachmentMeta(a)) => Some(a.chunk_object_ids.as_slice()),
        _ => None,
    };
    if role.chunks() != chunks {
        return Err(StoreError::Integrity);
    }
    if id == manifest.root_group_id() {
        version.check_root().map_err(|_| StoreError::Integrity)?;
    }
    if let RecordBody::Live(Payload::VaultMeta(m)) = &version.body
        && m.root_group != manifest.root_group_id()
    {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
