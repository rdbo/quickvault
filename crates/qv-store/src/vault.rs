// SPDX-License-Identifier: AGPL-3.0-or-later

//! Creating, opening and unlocking a vault file (spec 0004 §1, §5.1;
//! 0002 §8).
//!
//! - [`VaultFile::open`]: file checks and lock, location warnings, SQLite
//!   with the vault flags, identity re-check, hardening, schema validation,
//!   then header and slot decoding. No KDF runs and nothing is
//!   authenticated yet.
//! - [`VaultFile::unlock`]: one Argon2id run unwraps VK from the password
//!   slot (a KEK-commitment or AEAD failure is only
//!   [`StoreError::WrongPassword`]), then the header MAC over the exact
//!   stored header and slots is verified (a mismatch is
//!   [`StoreError::Integrity`], never a wrong password).
//! - [`VaultFile::create`]: builds the vault under a temporary name in the
//!   same directory, commits durably, moves it into place without replacing
//!   anything, syncs the directory, and reopens it through the open path.
//!
//! Records, objects, manifests and the local head come in phase 1.7.

use std::fmt;
use std::path::{Path, PathBuf};

use qv_crypto::{
    MacTag, MasterPassword, PasswordKdfProfile, PasswordSlot, PasswordWrapProfile, SlotId, VaultId,
    VaultKey, mac, purpose, verify_mac,
};
use qv_model::RandomId;
use rusqlite::{Connection, TransactionBehavior};

use crate::error::{StoreError, errno_err};
use crate::fs::{self, LockedFile};
use crate::header::{Header, INITIAL_GENERATION, SlotRow, mac_transcript};
use crate::location::{LocationWarnings, warnings_for};
use crate::schema::{self, validation_err};
use crate::slot::{LocalSlot, password_slot};
use crate::sqlite::{StepBudget, harden, open_connection};

/// The vault file extension (0004 §1.1).
pub const VAULT_EXTENSION: &str = "qvault";

#[cfg(test)]
thread_local! {
    /// Test hook: `create` fails after its temporary file exists.
    pub(crate) static FAIL_CREATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// An open, locked and validated vault file whose header is not yet
/// authenticated. [`VaultFile::unlock`] turns it into an [`UnlockedVault`].
pub struct VaultFile {
    // Field order matters: the connection is dropped before the lock
    // descriptor, because closing any descriptor of the file drops SQLite's
    // POSIX locks on it (see `fs`).
    // Held open for the session; the 1.7 write path is its first reader.
    #[allow(dead_code)]
    conn: Connection,
    lock: LockedFile,
    path: PathBuf,
    header: Header,
    header_body: Vec<u8>,
    header_mac: MacTag,
    slots: Vec<LocalSlot>,
    warnings: LocationWarnings,
    budget: StepBudget,
}

/// A vault whose password slot and header MAC have been verified.
pub struct UnlockedVault {
    file: VaultFile,
    vk: VaultKey,
}

impl fmt::Debug for VaultFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // No path: it can name the user's vault.
        f.write_str("VaultFile(..)")
    }
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UnlockedVault(<redacted>)")
    }
}

/// The header MAC over the exact stored bytes.
fn header_tag(
    vk: &VaultKey,
    header: &Header,
    body: &[u8],
    slots: &[SlotRow<'_>],
) -> Result<
    (
        qv_crypto::PurposeKey<purpose::HeaderMac>,
        zeroize::Zeroizing<Vec<u8>>,
    ),
    StoreError,
> {
    let key = vk.purpose_key::<purpose::HeaderMac>(
        header.vault_id,
        header.key_generation,
        header.derivation_profile,
    )?;
    Ok((key, mac_transcript(body, slots)?))
}

impl VaultFile {
    /// Opens a vault for unlocking: file checks, lock, hardening, schema
    /// validation and header/slot decoding. No KDF runs here.
    pub fn open(path: &Path) -> Result<VaultFile, StoreError> {
        let lock = fs::open_existing(path)?;
        Self::open_locked(path, lock)
    }

    fn open_locked(path: &Path, lock: LockedFile) -> Result<VaultFile, StoreError> {
        let warnings = warnings_for(path, &lock);
        let conn = open_connection(path)?;
        lock.same_as_path(path)?;
        let budget = StepBudget::new();
        harden(&conn, &budget)?;
        schema::validate_schema(&conn)?;
        let rows = schema::read_rows(&conn)?;
        let header = Header::decode(&rows.header_body)?;
        let slots = rows
            .slots
            .into_iter()
            .map(LocalSlot::from_stored)
            .collect::<Result<Vec<_>, _>>()?;
        password_slot(&slots)?;
        Ok(VaultFile {
            conn,
            lock,
            path: path.to_owned(),
            header,
            header_body: rows.header_body,
            header_mac: MacTag::from_bytes(rows.header_mac),
            slots,
            warnings,
            budget,
        })
    }

    /// Unlocks with the master password: one KDF run, then the header MAC.
    /// On failure the file is closed; reopen to retry.
    pub fn unlock(self, password: &MasterPassword) -> Result<UnlockedVault, StoreError> {
        self.budget.reset();
        let slot = password_slot(&self.slots)?;
        let vk =
            slot.keyslot
                .slot
                .unlock(password, self.header.vault_id, self.header.key_generation)?;
        self.verify_header(&vk)?;
        Ok(UnlockedVault { file: self, vk })
    }

    fn verify_header(&self, vk: &VaultKey) -> Result<(), StoreError> {
        let rows: Vec<SlotRow<'_>> = self.slots.iter().map(LocalSlot::row).collect();
        let (key, transcript) = header_tag(vk, &self.header, &self.header_body, &rows)?;
        verify_mac(&key, self.header.mac_profile, &transcript, &self.header_mac)
            .map_err(|_| StoreError::Integrity)
    }

    /// Location warnings for this vault's path (0004 §1.1).
    pub fn warnings(&self) -> LocationWarnings {
        self.warnings
    }

    /// [`StoreError::Replaced`] if the path no longer names the locked
    /// file (0004 §1.3).
    pub fn check_identity(&self) -> Result<(), StoreError> {
        self.lock.same_as_path(&self.path)
    }

    /// Creates a new vault at `path`, which must not exist, in an existing
    /// private directory, with a `.qvault` name. Runs the password KDF once
    /// and returns the vault unlocked.
    pub fn create(path: &Path, password: &MasterPassword) -> Result<UnlockedVault, StoreError> {
        if path.extension().and_then(|e| e.to_str()) != Some(VAULT_EXTENSION) {
            return Err(StoreError::Unsupported);
        }
        match rustix::fs::lstat(path) {
            Ok(_) => return Err(StoreError::Exists),
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(errno_err(e)),
        }
        fs::check_parent(path)?;
        let (lock, temp) = fs::create_temp(path)?;
        let built = build(&temp, password).and_then(|vk| {
            lock.sync()?;
            fs::rename_noreplace(&temp, path)?;
            Ok(vk)
        });
        let vk = match built {
            Ok(vk) => vk,
            Err(e) => {
                fs::remove_best_effort(&fs::with_suffix(&temp, "-journal"));
                fs::remove_best_effort(&temp);
                return Err(e);
            }
        };
        fs::sync_dir(fs::parent_of(path))?;
        let file = Self::open_locked(path, lock)?;
        // Self-test: the stored header verifies under the new VK.
        file.verify_header(&vk)?;
        Ok(UnlockedVault { file, vk })
    }
}

/// Writes a complete new vault into the empty file at `temp` and returns VK.
fn build(temp: &Path, password: &MasterPassword) -> Result<VaultKey, StoreError> {
    #[cfg(test)]
    if FAIL_CREATE.with(std::cell::Cell::get) {
        return Err(StoreError::Internal);
    }
    let mut conn = open_connection(temp)?;
    harden(&conn, &StepBudget::new())?;
    conn.pragma_update(None, "page_size", 4096)
        .map_err(|e| validation_err(&e))?;

    let vault_id = VaultId::generate()?;
    let slot_id = SlotId::generate()?;
    let vk = VaultKey::generate()?;
    let slot = PasswordSlot::create(
        password,
        &vk,
        vault_id,
        INITIAL_GENERATION,
        slot_id,
        PasswordKdfProfile::V1,
        PasswordWrapProfile::V1,
    )?;
    let local = LocalSlot::password(slot)?;
    let header = Header::new_vault(vault_id);
    let body = header.encode()?;
    let (key, transcript) = header_tag(&vk, &header, &body, &[local.row()])?;
    let tag = mac(&key, header.mac_profile, &transcript)?;

    let e = |e: rusqlite::Error| crate::error::sqlite_err(&e);
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(e)?;
    schema::install(&tx)?;
    tx.execute(
        "INSERT INTO header (id, body, mac) VALUES (1, ?1, ?2)",
        rusqlite::params![body.as_slice(), tag.as_bytes().as_slice()],
    )
    .map_err(e)?;
    tx.execute(
        "INSERT INTO keyslot (slot_id, type, body) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            local.slot_id.0.as_slice(),
            i64::try_from(local.kind).map_err(|_| StoreError::Internal)?,
            local.body.as_slice()
        ],
    )
    .map_err(e)?;
    tx.commit().map_err(e)?;
    conn.close().map_err(|(_, err)| e(err))?;
    Ok(vk)
}

impl UnlockedVault {
    /// The authenticated header.
    pub fn header(&self) -> &Header {
        &self.file.header
    }

    /// Location warnings for this vault's path.
    pub fn warnings(&self) -> LocationWarnings {
        self.file.warnings
    }

    /// See [`VaultFile::check_identity`].
    pub fn check_identity(&self) -> Result<(), StoreError> {
        self.file.check_identity()
    }

    /// VK, for `qv-core` (1.8) and the 1.7 write path only. Frontends never
    /// call this (`ARCHITECTURE.md` §3).
    pub fn vault_key(&self) -> &VaultKey {
        &self.vk
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use qv_crypto::{DerivationProfile, KeyGeneration, MacProfile, StoredDataProfile};

    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};

    /// Argon2id at 256 MiB: at most one run at a time in this test binary.
    static KDF: Mutex<()> = Mutex::new(());

    pub(crate) fn kdf() -> MutexGuard<'static, ()> {
        KDF.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) const PASSWORD: &str = "correct horse battery staple";

    pub(crate) fn pw(s: &str) -> MasterPassword {
        MasterPassword::from_utf8(s.as_bytes()).unwrap()
    }

    /// A MAC under VK's header-MAC key: compares VKs without exposing them.
    fn fingerprint(u: &UnlockedVault) -> [u8; 32] {
        let h = u.header();
        let key = u
            .vault_key()
            .purpose_key::<purpose::HeaderMac>(h.vault_id, h.key_generation, h.derivation_profile)
            .unwrap();
        *mac(&key, MacProfile::V1, b"fingerprint")
            .unwrap()
            .as_bytes()
    }

    struct Fixture {
        bytes: Vec<u8>,
        fingerprint: [u8; 32],
    }

    /// One vault created with [`PASSWORD`], shared by the tamper tests.
    fn fixture() -> &'static Fixture {
        static F: OnceLock<Fixture> = OnceLock::new();
        F.get_or_init(|| {
            let _k = kdf();
            let d = TestDir::new();
            let p = d.join("fixture.qvault");
            let u = VaultFile::create(&p, &pw(PASSWORD)).unwrap();
            let fingerprint = fingerprint(&u);
            drop(u);
            Fixture {
                bytes: std::fs::read(&p).unwrap(),
                fingerprint,
            }
        })
    }

    /// A private copy of the fixture vault.
    pub(crate) fn copy_fixture(d: &TestDir, name: &str) -> PathBuf {
        let p = d.join(name);
        write_file(&p, &fixture().bytes, 0o600);
        p
    }

    fn unlock(p: &Path, password: &str) -> Result<UnlockedVault, StoreError> {
        let _k = kdf();
        VaultFile::open(p)?.unlock(&pw(password))
    }

    fn err<T>(r: Result<T, StoreError>) -> StoreError {
        match r {
            Ok(_) => panic!("unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn vault_create_then_unlock() {
        let d = TestDir::new();
        let p = d.join("v.qvault");
        let created = {
            let _k = kdf();
            VaultFile::create(&p, &pw(PASSWORD)).unwrap()
        };
        let meta = std::fs::symlink_metadata(&p).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let h = *created.header();
        assert_eq!(h.key_generation, KeyGeneration(1));
        assert_eq!(h.data_profile, StoredDataProfile::V1);
        assert_eq!(h.derivation_profile, DerivationProfile::V1);
        assert_eq!(h.mac_profile, MacProfile::V1);
        assert!(!created.warnings().sync_folder);
        let fp = fingerprint(&created);
        // While open, the vault is locked.
        assert_eq!(err(VaultFile::open(&p)), StoreError::Locked);
        drop(created);
        let reopened = unlock(&p, PASSWORD).unwrap();
        assert_eq!(*reopened.header(), h);
        assert_eq!(fingerprint(&reopened), fp);
        // Only the vault remains in the directory: no temp or journal file.
        let names: Vec<_> = std::fs::read_dir(d.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("v.qvault")]);
    }

    #[test]
    fn vault_fixture_unlocks_with_its_password() {
        let d = TestDir::new();
        let p = copy_fixture(&d, "v.qvault");
        let u = unlock(&p, PASSWORD).unwrap();
        assert_eq!(fingerprint(&u), fixture().fingerprint);
    }

    #[test]
    fn vault_wrong_password() {
        let d = TestDir::new();
        let p = copy_fixture(&d, "v.qvault");
        assert_eq!(err(unlock(&p, "wrong horse")), StoreError::WrongPassword);
    }

    #[test]
    fn vault_header_mac_tamper_is_integrity() {
        let d = TestDir::new();
        let p = copy_fixture(&d, "v.qvault");
        {
            let c = Connection::open(&p).unwrap();
            let mut mac: Vec<u8> = c
                .query_row("SELECT mac FROM header", [], |r| r.get(0))
                .unwrap();
            mac[0] ^= 1;
            c.execute("UPDATE header SET mac = ?1", [mac]).unwrap();
        }
        // The right password: the slot opens, the MAC does not verify.
        assert_eq!(err(unlock(&p, PASSWORD)), StoreError::Integrity);
    }

    #[test]
    fn vault_mac_covers_slots() {
        let d = TestDir::new();
        let p = copy_fixture(&d, "v.qvault");
        {
            let c = Connection::open(&p).unwrap();
            let mut body: Vec<u8> = c
                .query_row("SELECT body FROM keyslot", [], |r| r.get(0))
                .unwrap();
            // A canonical unknown key 9 after keys 0–6: still decodes.
            assert_eq!(body[0], 0xa7);
            body[0] = 0xa8;
            body.extend_from_slice(&[0x09, 0x00]);
            assert!(qv_model::Keyslot::decode(&body).is_ok());
            c.execute("UPDATE keyslot SET body = ?1", [body]).unwrap();
        }
        assert_eq!(err(unlock(&p, PASSWORD)), StoreError::Integrity);
    }

    #[test]
    fn vault_slot_from_another_vault_is_wrong_password() {
        let d = TestDir::new();
        let other = d.join("other.qvault");
        {
            let _k = kdf();
            drop(VaultFile::create(&other, &pw(PASSWORD)).unwrap());
        }
        let p = copy_fixture(&d, "v.qvault");
        {
            let c = Connection::open(&p).unwrap();
            c.execute("ATTACH DATABASE ?1 AS o", [other.to_str().unwrap()])
                .unwrap();
            c.execute_batch("DELETE FROM keyslot; INSERT INTO keyslot SELECT * FROM o.keyslot;")
                .unwrap();
        }
        // Same password, but the slot is bound to the other vault's ID.
        assert_eq!(err(unlock(&p, PASSWORD)), StoreError::WrongPassword);
    }

    #[test]
    fn vault_create_refusals() {
        let d = TestDir::new();
        let existing = d.join("v.qvault");
        write_file(&existing, b"keep", 0o600);
        // These fail before any KDF.
        let p = pw(PASSWORD);
        assert_eq!(err(VaultFile::create(&existing, &p)), StoreError::Exists);
        assert_eq!(std::fs::read(&existing).unwrap(), b"keep");
        let link = d.join("l.qvault");
        std::os::unix::fs::symlink(d.join("missing"), &link).unwrap();
        assert_eq!(err(VaultFile::create(&link, &p)), StoreError::Exists);
        assert_eq!(
            err(VaultFile::create(&d.join("v.db"), &p)),
            StoreError::Unsupported
        );
        assert_eq!(
            err(VaultFile::create(&d.join("v"), &p)),
            StoreError::Unsupported
        );
        let open_dir = d.subdir("open", 0o777);
        assert_eq!(
            err(VaultFile::create(&open_dir.join("v.qvault"), &p)),
            StoreError::UnsafeFile
        );
        assert_eq!(
            err(VaultFile::create(&d.join("missing/v.qvault"), &p)),
            StoreError::NotFound
        );
    }

    #[test]
    fn vault_failed_create_leaves_nothing() {
        let d = TestDir::new();
        FAIL_CREATE.with(|f| f.set(true));
        let r = VaultFile::create(&d.join("v.qvault"), &pw(PASSWORD));
        FAIL_CREATE.with(|f| f.set(false));
        assert_eq!(err(r), StoreError::Internal);
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn vault_open_lock_identity_and_debug() {
        let d = TestDir::new();
        let p = copy_fixture(&d, "v.qvault");
        let f = VaultFile::open(&p).unwrap();
        assert_eq!(err(VaultFile::open(&p)), StoreError::Locked);
        assert_eq!(f.check_identity(), Ok(()));
        assert!(!f.warnings().any());
        let shown = format!("{f:?}");
        assert_eq!(shown, "VaultFile(..)");
        assert!(!shown.contains("v.qvault"));
        let q = copy_fixture(&d, "w.qvault");
        std::fs::rename(&q, &p).unwrap();
        assert_eq!(f.check_identity(), Err(StoreError::Replaced));
        drop(f);
        // The replacement is a valid vault and opens on its own.
        assert!(VaultFile::open(&p).is_ok());
    }

    #[test]
    fn vault_unlocked_debug_is_redacted() {
        let d = TestDir::new();
        let p = copy_fixture(&d, "v.qvault");
        let u = unlock(&p, PASSWORD).unwrap();
        assert_eq!(format!("{u:?}"), "UnlockedVault(<redacted>)");
        assert_eq!(u.check_identity(), Ok(()));
    }
}
