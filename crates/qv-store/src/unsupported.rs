// SPDX-License-Identifier: AGPL-3.0-or-later

//! The vault API on targets without the file-safety code (plans 0008, 0009).
//!
//! Owner-only permissions, symlink rejection, the process lock, no-replace
//! renames and the anchor files are implemented for Linux and Android only;
//! Windows comes in phase 4.1. Elsewhere every entry point fails with
//! [`StoreError::Unsupported`] instead of opening a vault unprotected. The
//! types are uninhabited, so no vault value can exist. On Linux this module
//! is compiled only for its tests.

use std::fmt;
use std::path::{Path, PathBuf};

use qv_crypto::{MasterPassword, PasswordKdfProfile, RecordId, VaultKey};
use qv_model::{Clock, RecordKind, RecordVersion, VersionId, WriterId};

use crate::error::StoreError;
use crate::head::AnchorStatus;
use crate::header::Header;
use crate::location::LocationWarnings;
use crate::manifest::Manifest;

/// The vault file extension (0004 §1.1).
pub const VAULT_EXTENSION: &str = "qvault";

/// Largest anchor file.
pub const MAX_ANCHOR_BYTES: usize = 256;

enum Never {}

/// A vault file (unavailable on this target).
pub struct VaultFile(Never);

/// An unlocked vault (unavailable on this target).
pub struct UnlockedVault(Never);

/// A directory of anchor files (unavailable on this target).
pub struct AnchorDir(Never);

/// A mutation (unavailable on this target).
pub struct Write<'v>(Never, core::marker::PhantomData<&'v ()>);

/// A private snapshot directory (unavailable on this target).
pub struct SnapshotDir(Never);

/// One snapshot file (unavailable on this target).
pub struct SnapshotEntry(Never);

/// A published snapshot (unavailable on this target).
pub struct PublishedSnapshot(Never);

/// The counts of a `verify` pass (0011 `verify`). The same plain aggregate
/// counters as the Linux/Android implementation; producing one fails closed
/// here.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VerifyCounts {
    /// Referenced objects re-hashed.
    pub objects: u64,
    /// Records in the manifest.
    pub records: u64,
    /// Active heads re-verified.
    pub active_heads: u64,
    /// Retained history versions re-verified.
    pub retained_versions: u64,
    /// Active heads that are final tombstones.
    pub tombstones: u64,
    /// Records carrying a suppression floor.
    pub suppressed_records: u64,
    /// Total referenced ciphertext length.
    pub total_bytes: u64,
}

/// What a local snapshot is for (0007 §3.2). A plain two-value type, because
/// callers match on it on every target; producing one fails closed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotKind {
    /// An automatic or user-visible snapshot.
    Ordinary,
    /// The mandatory pre-operation copy of a destructive operation.
    Recovery,
}

impl SnapshotKind {
    /// The fixed label `ordinary` or `recovery` (0011 §4).
    pub fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Recovery => "recovery",
        }
    }
}

macro_rules! never_debug {
    ($($t:ty),+) => {$(
        impl fmt::Debug for $t {
            fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self.0 {}
            }
        }
    )+};
}
never_debug!(
    VaultFile,
    UnlockedVault,
    AnchorDir,
    Write<'_>,
    SnapshotDir,
    SnapshotEntry,
    PublishedSnapshot
);

impl SnapshotDir {
    /// Always [`StoreError::Unsupported`] on this target.
    pub fn open(_dir: &Path) -> Result<SnapshotDir, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Always [`StoreError::Unsupported`] on this target.
    pub fn default_dir() -> Result<PathBuf, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Unreachable: no `SnapshotDir` exists on this target.
    pub fn path(&self) -> &Path {
        match self.0 {}
    }

    /// Unreachable: no `SnapshotDir` exists on this target.
    pub fn entries(&self) -> Result<Vec<SnapshotEntry>, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `SnapshotDir` exists on this target.
    pub fn read_header(
        &self,
        _entry: &SnapshotEntry,
        _expect: crate::ArchiveScope,
        _vk: &VaultKey,
    ) -> Result<crate::ArchiveHeader, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `SnapshotDir` exists on this target.
    pub fn remove(&self, _entry: &SnapshotEntry) -> Result<(), StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `SnapshotDir` exists on this target.
    pub fn reclassify_as_ordinary(
        &self,
        _entry: &SnapshotEntry,
    ) -> Result<SnapshotEntry, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `SnapshotDir` exists on this target.
    pub fn publish(
        &self,
        _vault: &mut UnlockedVault,
        _kind: SnapshotKind,
        _created_at: qv_model::Timestamp,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<PublishedSnapshot, StoreError> {
        match self.0 {}
    }
}

impl SnapshotEntry {
    /// Unreachable: no `SnapshotEntry` exists on this target.
    pub fn name(&self) -> &std::ffi::OsStr {
        match self.0 {}
    }

    /// Unreachable: no `SnapshotEntry` exists on this target.
    pub fn size(&self) -> u64 {
        match self.0 {}
    }

    /// Unreachable: no `SnapshotEntry` exists on this target.
    pub fn kind(&self) -> SnapshotKind {
        match self.0 {}
    }
}

impl PublishedSnapshot {
    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn entry(&self) -> &SnapshotEntry {
        match self.0 {}
    }

    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn stats(&self) -> &crate::ArchiveStats {
        match self.0 {}
    }

    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn archive_id(&self) -> &str {
        match self.0 {}
    }

    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn created_at(&self) -> qv_model::Timestamp {
        match self.0 {}
    }

    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn kind(&self) -> SnapshotKind {
        match self.0 {}
    }

    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn size(&self) -> u64 {
        match self.0 {}
    }

    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn objects(&self) -> u64 {
        match self.0 {}
    }

    /// Unreachable: no `PublishedSnapshot` exists on this target.
    pub fn total_bytes(&self) -> u64 {
        match self.0 {}
    }
}

impl AnchorDir {
    /// Always [`StoreError::Unsupported`] on this target.
    pub fn open(_dir: &Path) -> Result<AnchorDir, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Unreachable: no `AnchorDir` exists on this target.
    pub fn path(&self) -> &Path {
        match self.0 {}
    }

    /// Always [`StoreError::Unsupported`] on this target.
    pub fn default_dir() -> Result<PathBuf, StoreError> {
        Err(StoreError::Unsupported)
    }
}

impl VaultFile {
    /// Always [`StoreError::Unsupported`] on this target.
    pub fn open(_path: &Path) -> Result<VaultFile, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Always [`StoreError::Unsupported`] on this target.
    pub fn create(
        _path: &Path,
        _password: &MasterPassword,
        _name: &str,
        anchors: &AnchorDir,
    ) -> Result<UnlockedVault, StoreError> {
        match anchors.0 {}
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn unlock(
        self,
        _password: &MasterPassword,
        _anchors: &AnchorDir,
    ) -> Result<UnlockedVault, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn unlock_for_recovery(
        self,
        _password: &MasterPassword,
        _anchors: &AnchorDir,
    ) -> Result<(UnlockedVault, AnchorStatus), StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn warnings(&self) -> LocationWarnings {
        match self.0 {}
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn check_identity(&self) -> Result<(), StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn header(&self) -> &Header {
        match self.0 {}
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn schema_version(&self) -> u32 {
        match self.0 {}
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn password_kdf(&self) -> Result<PasswordKdfProfile, StoreError> {
        match self.0 {}
    }
}

impl UnlockedVault {
    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn verify_all(&self, _cancelled: &dyn Fn() -> bool) -> Result<VerifyCounts, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn write_archive<W: std::io::Write>(
        &mut self,
        _out: W,
        _created_at: qv_model::Timestamp,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<crate::ArchiveStats, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no UnlockedVault exists on this target.
    pub fn verify_attachment(
        &self,
        _record: RecordId,
        _version: VersionId,
        _cancelled: &impl Fn() -> bool,
    ) -> Result<(), StoreError> {
        match self.0 {}
    }
    /// Unreachable: no UnlockedVault exists on this target.
    pub fn read_attachment(
        &self,
        _record: RecordId,
        _version: VersionId,
        _sink: &mut impl std::io::Write,
        _cancelled: &impl Fn() -> bool,
    ) -> Result<(), StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn header(&self) -> &Header {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn warnings(&self) -> LocationWarnings {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn check_identity(&self) -> Result<(), StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn vault_key(&self) -> &VaultKey {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn manifest(&self) -> &Manifest {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn record_kind(&self, _id: RecordId) -> Option<RecordKind> {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn writer_id(&self) -> WriterId {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn local_seq(&self) -> u64 {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn read_version(
        &self,
        _record: RecordId,
        _version: VersionId,
    ) -> Result<RecordVersion, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn write(&mut self) -> Result<Write<'_>, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `UnlockedVault` exists on this target.
    pub fn adopt_baseline(&mut self) -> Result<(), StoreError> {
        match self.0 {}
    }
}

impl Write<'_> {
    /// Unreachable: no Write exists on this target.
    pub fn commit_cancellable(self, _cancelled: &impl Fn() -> bool) -> Result<(), StoreError> {
        match self.0 {}
    }
    /// Unreachable: no Write exists on this target.
    pub fn purge_history(&mut self, _record: RecordId) -> Result<(), StoreError> {
        match self.0 {}
    }
    /// Unreachable: no Write exists on this target.
    pub fn stage_attachment(
        &mut self,
        _record: RecordId,
        _source: &mut impl std::io::Read,
        _cancelled: &impl Fn() -> bool,
    ) -> Result<crate::StagedAttachment, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `Write` exists on this target.
    pub fn writer_id(&self) -> WriterId {
        match self.0 {}
    }

    /// Unreachable: no `Write` exists on this target.
    pub fn reserve_counter(&mut self) -> Result<u64, StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `Write` exists on this target.
    pub fn head_clocks(&self, _record: RecordId) -> Vec<Clock> {
        match self.0 {}
    }

    /// Unreachable: no `Write` exists on this target.
    pub fn put_local(
        &mut self,
        _record: RecordId,
        _version: RecordVersion,
    ) -> Result<(), StoreError> {
        match self.0 {}
    }

    /// Unreachable: no `Write` exists on this target.
    pub fn commit(self) -> Result<(), StoreError> {
        match self.0 {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_entry_points_fail_closed() {
        let p = Path::new("/nonexistent/v.qvault");
        assert!(matches!(VaultFile::open(p), Err(StoreError::Unsupported)));
        assert!(matches!(AnchorDir::open(p), Err(StoreError::Unsupported)));
        assert!(matches!(
            AnchorDir::default_dir(),
            Err(StoreError::Unsupported)
        ));
        assert_eq!(VAULT_EXTENSION, "qvault");
        assert_eq!(MAX_ANCHOR_BYTES, crate::anchor::MAX_ANCHOR_BYTES);
    }
}
