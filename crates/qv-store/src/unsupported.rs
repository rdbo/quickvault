// SPDX-License-Identifier: AGPL-3.0-or-later

//! The vault API on targets without the file-safety code (plan 0008).
//!
//! Owner-only permissions, symlink rejection, the process lock and
//! no-replace renames are implemented for Linux and Android only; Windows
//! comes in phase 4.1. Elsewhere every entry point fails with
//! [`StoreError::Unsupported`] instead of opening a vault unprotected. The
//! types are uninhabited, so no vault value can exist. On Linux this module
//! is compiled only for its tests.

use std::fmt;
use std::path::Path;

use qv_crypto::{MasterPassword, VaultKey};

use crate::error::StoreError;
use crate::header::Header;
use crate::location::LocationWarnings;

/// The vault file extension (0004 §1.1).
pub const VAULT_EXTENSION: &str = "qvault";

enum Never {}

/// A vault file (unavailable on this target).
pub struct VaultFile(Never);

/// An unlocked vault (unavailable on this target).
pub struct UnlockedVault(Never);

impl fmt::Debug for VaultFile {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {}
    }
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, _: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {}
    }
}

impl VaultFile {
    /// Always [`StoreError::Unsupported`] on this target.
    pub fn open(_path: &Path) -> Result<VaultFile, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Always [`StoreError::Unsupported`] on this target.
    pub fn create(_path: &Path, _password: &MasterPassword) -> Result<UnlockedVault, StoreError> {
        Err(StoreError::Unsupported)
    }

    /// Unreachable: no `VaultFile` exists on this target.
    pub fn unlock(self, _password: &MasterPassword) -> Result<UnlockedVault, StoreError> {
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
}

impl UnlockedVault {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_entry_points_fail_closed() {
        let p = Path::new("/nonexistent/v.qvault");
        assert!(matches!(VaultFile::open(p), Err(StoreError::Unsupported)));
        let pw = MasterPassword::from_utf8(b"pw").unwrap();
        assert!(matches!(
            VaultFile::create(p, &pw),
            Err(StoreError::Unsupported)
        ));
        assert_eq!(VAULT_EXTENSION, "qvault");
    }
}
