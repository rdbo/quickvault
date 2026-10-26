// SPDX-License-Identifier: AGPL-3.0-or-later

//! The entry point: configuration, process hardening, and creating and
//! unlocking vaults (spec 0004 §5.1, 0008 §1.1).

use std::path::Path;
use std::sync::{Arc, OnceLock};

use qv_crypto::{
    Argon2Params, MasterPassword, MemoryProtection, ProcessHardening, RecoveryPhrase,
    harden_process, memory_protection,
};
use qv_model::Timestamp;
use qv_store::{AnchorDir, AnchorStatus, LocationWarnings, UnlockedVault, VaultFile};

use crate::error::{CoreError, crypto};
use crate::session::{CancelToken, Session};

/// A clock for timestamps and trash expiry. Dates are display information
/// and policy input only, never causality (0005 §1.5).
pub trait TimeSource: Send + Sync {
    /// Milliseconds since the Unix epoch.
    fn now(&self) -> Timestamp;
}

/// The system clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemTime;

impl TimeSource for SystemTime {
    fn now(&self) -> Timestamp {
        let ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        Timestamp(i64::try_from(ms).unwrap_or(i64::MAX))
    }
}

/// How a [`Core`] is set up. There is no server, account or network
/// setting: local use needs none (0005 §0.1).
pub struct CoreConfig {
    /// Where external anchors live (private state outside the vault's
    /// directory, 0005 §5.4).
    pub anchors: AnchorDir,
    /// The clock.
    pub time: Arc<dyn TimeSource>,
}

impl CoreConfig {
    /// A configuration with the system clock.
    pub fn new(anchors: AnchorDir) -> Self {
        Self {
            anchors,
            time: Arc::new(SystemTime),
        }
    }
}

/// What the process-level protections achieved (0008 §1.1–1.2). Frontends
/// must show reduced protection to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protection {
    /// Core dumps and debugger attachment.
    pub process: ProcessHardening,
    /// Memory locking of secret buffers so far.
    pub memory: MemoryProtection,
}

impl Protection {
    /// Whether any protection is missing.
    pub fn is_reduced(&self) -> bool {
        self.process.is_reduced() || self.memory.is_reduced()
    }
}

/// The process hardening result, computed once per process.
static HARDENING: OnceLock<ProcessHardening> = OnceLock::new();

/// Hardens the process once (no core dumps, no debugger attachment, 0008
/// §1.1) and reports the protection reached. Frontends call this before
/// reading any secret, also when they never open a vault (the CLI's
/// `generate`); [`Core::new`] runs the same once-only hardening.
pub fn harden() -> Protection {
    Protection {
        process: *HARDENING.get_or_init(harden_process),
        memory: memory_protection(),
    }
}

/// Lowercase hex of `bytes`.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from(DIGITS[usize::from(b >> 4)]));
        s.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    s
}

/// A vault's public header data, read without a password and therefore
/// **unverified**: nothing here is authenticated until unlock (0011 `info`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultInfo {
    /// The vault ID, lowercase hex.
    pub vault_id: String,
    /// The vault format (schema) version.
    pub schema_version: u32,
    /// The current key generation.
    pub key_generation: u32,
    /// The stored-data profile ID.
    pub data_profile: u16,
    /// The derivation profile ID.
    pub derivation_profile: u16,
    /// The header-MAC profile ID.
    pub mac_profile: u16,
    /// The minimum accepted stored-data profile ID.
    pub min_data_profile: u16,
    /// The minimum accepted derivation profile ID.
    pub min_derivation_profile: u16,
    /// The password slot's KDF profile ID.
    pub kdf_profile: u16,
    /// That profile's Argon2id parameters.
    pub kdf: Argon2Params,
    /// Location warnings for the path (0004 §1.1).
    pub warnings: LocationWarnings,
}

/// A newly created vault: its session and its recovery phrase, which the
/// frontend shows once (0011 `init`).
pub struct Created {
    /// The unlocked session.
    pub session: Session,
    /// The 24-word recovery phrase.
    pub recovery_phrase: RecoveryPhrase,
}

impl core::fmt::Debug for Created {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Created(<redacted>)")
    }
}

/// The single entry point for frontends.
pub struct Core {
    anchors: AnchorDir,
    time: Arc<dyn TimeSource>,
    process: ProcessHardening,
}

impl core::fmt::Debug for Core {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Core(..)")
    }
}

fn cancelled(cancel: Option<&CancelToken>) -> Result<(), CoreError> {
    match cancel {
        Some(c) if c.is_cancelled() => Err(CoreError::Cancelled),
        _ => Ok(()),
    }
}

impl Core {
    /// Sets up the core and hardens the process (no core dumps, no debugger
    /// attachment) before any secret is read (0008 §1.1). The result is in
    /// [`Self::protection`].
    pub fn new(config: CoreConfig) -> Core {
        Core {
            anchors: config.anchors,
            time: config.time,
            process: harden().process,
        }
    }

    /// The process hardening result and the current memory-locking status.
    pub fn protection(&self) -> Protection {
        Protection {
            process: self.process,
            memory: memory_protection(),
        }
    }

    /// Reads a vault's public header without a password (0011 `info`). The
    /// result is unverified. The file is opened, checked and locked as for
    /// an unlock, and closed again before this returns.
    pub fn inspect(&self, path: &Path) -> Result<VaultInfo, CoreError> {
        let file = VaultFile::open(path)?;
        let h = file.header();
        let kdf = file.password_kdf()?;
        Ok(VaultInfo {
            vault_id: hex(&h.vault_id.0),
            schema_version: file.schema_version(),
            key_generation: h.key_generation.0,
            data_profile: h.data_profile.id(),
            derivation_profile: h.derivation_profile.id(),
            mac_profile: h.mac_profile.id(),
            min_data_profile: h.min_data_profile.id(),
            min_derivation_profile: h.min_derivation_profile.id(),
            kdf_profile: kdf.id(),
            kdf: kdf.argon2_params(),
            warnings: file.warnings(),
        })
    }

    /// [`CoreError::AnchorLocation`] if the vault's directory is the anchor
    /// directory or lies inside it: an anchor copied or restored together
    /// with the vault detects nothing (0005 §5.4). Paths that cannot be
    /// resolved are left to the store, which refuses them itself.
    fn check_anchor_location(&self, path: &Path) -> Result<(), CoreError> {
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let (Ok(dir), Ok(anchors)) = (
            std::fs::canonicalize(parent),
            std::fs::canonicalize(self.anchors.path()),
        ) else {
            return Ok(());
        };
        if dir.starts_with(&anchors) {
            return Err(CoreError::AnchorLocation);
        }
        Ok(())
    }

    /// Creates a vault named `name` at `path` (which must not exist) and
    /// returns it unlocked with its recovery phrase.
    pub fn create(
        &self,
        path: &Path,
        password: &MasterPassword,
        name: &str,
    ) -> Result<Created, CoreError> {
        self.check_anchor_location(path)?;
        let vault = VaultFile::create(path, password, name, &self.anchors)?;
        let recovery_phrase = RecoveryPhrase::from_vault_key(vault.vault_key()).map_err(crypto)?;
        let session = Session::open(vault, self.time.clone(), false, None)?;
        Ok(Created {
            session,
            recovery_phrase,
        })
    }

    /// Unlocks the vault at `path`. A missing anchor is
    /// `Store(NoAnchor)` and a mismatched one `Store(Rollback)`; see
    /// [`Self::unlock_for_recovery`]. The password KDF and the store's
    /// verification cannot be interrupted; `cancel` is checked before and
    /// after them and while the views are built.
    pub fn unlock(
        &self,
        path: &Path,
        password: &MasterPassword,
        cancel: Option<&CancelToken>,
    ) -> Result<Session, CoreError> {
        let vault = self.open(path, cancel, |f| f.unlock(password, &self.anchors))?;
        Session::open(vault, self.time.clone(), false, cancel)
    }

    /// Unlocks a vault whose anchor is missing or mismatched (0005 §5.4):
    /// the session can be read, and writes fail until
    /// [`Session::adopt_baseline`] makes the current state the new baseline.
    pub fn unlock_for_recovery(
        &self,
        path: &Path,
        password: &MasterPassword,
        cancel: Option<&CancelToken>,
    ) -> Result<(Session, AnchorStatus), CoreError> {
        let mut status = AnchorStatus::Verified;
        let vault = self.open(path, cancel, |f| {
            let (v, s) = f.unlock_for_recovery(password, &self.anchors)?;
            status = s;
            Ok(v)
        })?;
        let read_only = matches!(status, AnchorStatus::Missing | AnchorStatus::Mismatch);
        let session = Session::open(vault, self.time.clone(), read_only, cancel)?;
        Ok((session, status))
    }

    fn open(
        &self,
        path: &Path,
        cancel: Option<&CancelToken>,
        unlock: impl FnOnce(VaultFile) -> Result<UnlockedVault, qv_store::StoreError>,
    ) -> Result<UnlockedVault, CoreError> {
        cancelled(cancel)?;
        self.check_anchor_location(path)?;
        let file = VaultFile::open(path)?;
        let vault = unlock(file)?;
        cancelled(cancel)?;
        Ok(vault)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::DirBuilderExt;

    use qv_crypto::PasswordKdfProfile;

    use super::*;
    use crate::testutil::{Env, PASSWORD, TestDir, err, kdf, pw};

    #[test]
    fn setup_harden_is_once() {
        assert_eq!(harden().process, harden().process);
        let env = Env::new();
        assert_eq!(env.core().protection().process, harden().process);
    }

    #[test]
    fn setup_inspect_needs_no_password() {
        let env = Env::new();
        let core = env.core();
        let info = core.inspect(&env.path).unwrap();
        assert_eq!(info.vault_id.len(), 32);
        assert!(info.vault_id.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(info.schema_version, 0x7FFF_0002);
        assert_eq!(info.key_generation, 1);
        assert_eq!(
            (info.data_profile, info.derivation_profile, info.mac_profile),
            (1, 1, 1)
        );
        assert_eq!(info.kdf_profile, 1);
        assert_eq!(info.kdf, PasswordKdfProfile::V1.argon2_params());
        assert!(!info.warnings.any());
        // The header matches what unlock authenticates.
        let s = env.unlock();
        let id = s
            .read(|ctx| Ok(hex(&ctx.open.vault.header().vault_id.0)))
            .unwrap();
        assert_eq!(id, info.vault_id);
        drop(s);
        assert_eq!(
            err(core.inspect(&env.dir.path().join("none.qvault"))),
            CoreError::Store(qv_store::StoreError::NotFound)
        );
    }

    #[test]
    fn setup_vault_in_the_anchor_directory_is_refused() {
        let env = Env::new();
        let core = env.core();
        // Create: refused before anything is written.
        let inside = env.anchors.join("v.qvault");
        assert_eq!(
            err(core.create(&inside, &pw(PASSWORD), "x")),
            CoreError::AnchorLocation
        );
        assert!(!inside.exists());
        let below = env.anchors.join("sub");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&below)
            .unwrap();
        assert_eq!(
            err(core.create(&below.join("v.qvault"), &pw(PASSWORD), "x")),
            CoreError::AnchorLocation
        );
        // Unlock: refused before the KDF (a wrong password would otherwise
        // be `WrongPassword`).
        std::fs::rename(&env.path, &inside).unwrap();
        assert_eq!(
            err(core.unlock(&inside, &pw("wrong"), None)),
            CoreError::AnchorLocation
        );
        assert_eq!(
            err(core.unlock_for_recovery(&inside, &pw("wrong"), None)),
            CoreError::AnchorLocation
        );
        // A vault next to (not inside) the anchor directory is fine.
        let d = TestDir::new();
        let other = Env::empty(d);
        let _k = kdf();
        assert!(other.core().create(&other.path, &pw(PASSWORD), "y").is_ok());
        assert_eq!(
            CoreError::AnchorLocation.to_string(),
            "the vault must not be stored in the anchor directory or below it"
        );
    }

    #[test]
    fn setup_recovery_skip_is_recorded() {
        let env = Env::new();
        let s = env.unlock();
        assert!(
            s.edit_settings()
                .unwrap()
                .meta()
                .settings
                .recovery_skipped_at
                .is_none()
        );
        s.record_recovery_skip().unwrap();
        let now = env.time.now();
        drop(s);
        let s = env.unlock();
        assert_eq!(
            s.edit_settings()
                .unwrap()
                .meta()
                .settings
                .recovery_skipped_at,
            Some(now)
        );
    }
}
