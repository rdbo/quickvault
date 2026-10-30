// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile vault files through the public API (spec 0004 §1.2; 0012 §1 row
//! "Hostile SQLite/CBOR", SQLite half: malformed schema, pages and lengths,
//! before authentication).
//!
//! Each case starts from one vault made by `VaultFile::create`, changes it
//! with an ordinary SQLite connection (no hardening, as an attacker would),
//! and checks that `VaultFile::open` refuses it with the exact error and
//! leaves the file byte-for-byte unchanged: a rejected open writes nothing,
//! and no stored trigger ever runs.

#![cfg(any(target_os = "linux", target_os = "android"))]
// The helpers below are test code, but clippy's `allow-*-in-tests` settings
// only cover `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use qv_crypto::MasterPassword;
use qv_store::{AnchorDir, StoreError, VaultFile};
use rusqlite::Connection;

struct Dir(PathBuf);

impl Dir {
    fn new() -> Self {
        let mut name = String::from("qv-store-tamper-");
        for b in qv_crypto::random_array::<8>().unwrap() {
            name.push_str(&format!("{b:02x}"));
        }
        let p = std::env::temp_dir().join(name);
        std::fs::DirBuilder::new().mode(0o700).create(&p).unwrap();
        Self(p)
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The bytes of one freshly created vault.
fn vault_bytes() -> &'static [u8] {
    static BYTES: OnceLock<Vec<u8>> = OnceLock::new();
    BYTES.get_or_init(|| {
        let d = Dir::new();
        let p = d.0.join("v.qvault");
        let pw = MasterPassword::from_utf8(b"tamper test password").unwrap();
        let anchors = AnchorDir::open(&d.0.join("anchors")).unwrap();
        drop(VaultFile::create(&p, &pw, "tamper", &anchors).unwrap());
        std::fs::read(&p).unwrap()
    })
}

fn copy(d: &Dir) -> PathBuf {
    let p = d.0.join("v.qvault");
    std::fs::write(&p, vault_bytes()).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    p
}

/// Opens `path`, which must fail with `expected` and stay unchanged.
fn refused(path: &Path, expected: StoreError, what: &str) {
    let before = std::fs::read(path).unwrap();
    match VaultFile::open(path) {
        Ok(_) => panic!("{what}: opened"),
        Err(e) => assert_eq!(e, expected, "{what}"),
    }
    assert_eq!(std::fs::read(path).unwrap(), before, "{what}: file changed");
}

#[test]
fn tamper_untouched_vault_opens() {
    let d = Dir::new();
    let p = copy(&d);
    let before = std::fs::read(&p).unwrap();
    drop(VaultFile::open(&p).unwrap());
    assert_eq!(std::fs::read(&p).unwrap(), before);
}

// 0012 §1: Hostile SQLite/CBOR
#[test]
fn tamper_schema_changes_are_refused() {
    let cases: &[(&str, StoreError)] = &[
        ("CREATE TABLE extra (x)", StoreError::Integrity),
        ("CREATE INDEX i ON keyslot (body)", StoreError::Integrity),
        (
            "CREATE INDEX i ON keyslot (length(body))",
            StoreError::Integrity,
        ),
        (
            "CREATE INDEX i ON header (mac) WHERE id = 1",
            StoreError::Integrity,
        ),
        (
            "CREATE TRIGGER t AFTER UPDATE ON header BEGIN DELETE FROM keyslot; END",
            StoreError::Integrity,
        ),
        (
            "CREATE TRIGGER t BEFORE DELETE ON keyslot BEGIN SELECT 1; END",
            StoreError::Integrity,
        ),
        (
            "CREATE VIEW w AS SELECT * FROM header",
            StoreError::Integrity,
        ),
        (
            "CREATE TABLE h2 AS SELECT * FROM header; DROP TABLE header; \
             CREATE TABLE header (id INTEGER PRIMARY KEY, body BLOB NOT NULL, mac BLOB NOT NULL) STRICT; \
             INSERT INTO header SELECT * FROM h2; DROP TABLE h2;",
            StoreError::Integrity,
        ),
        (
            "ALTER TABLE keyslot RENAME COLUMN type TO kind",
            StoreError::Integrity,
        ),
        (
            "ALTER TABLE header ADD COLUMN extra BLOB",
            StoreError::Integrity,
        ),
        ("PRAGMA user_version = 1", StoreError::Unsupported),
        ("PRAGMA application_id = 1", StoreError::NotAVault),
        ("DELETE FROM header", StoreError::Integrity),
        ("DELETE FROM keyslot", StoreError::Integrity),
        ("UPDATE header SET mac = x'00'", StoreError::Integrity),
        ("UPDATE header SET body = x'a0'", StoreError::Integrity),
        ("UPDATE keyslot SET type = 7", StoreError::Unsupported),
        ("UPDATE keyslot SET body = x'a0'", StoreError::Integrity),
        (
            "CREATE INDEX i ON object (ciphertext)",
            StoreError::Integrity,
        ),
        (
            "CREATE TRIGGER t AFTER DELETE ON manifest BEGIN DELETE FROM object; END",
            StoreError::Integrity,
        ),
        ("DROP TABLE replica", StoreError::Integrity),
        ("DELETE FROM replica", StoreError::Integrity),
        ("DELETE FROM local_head", StoreError::Integrity),
        ("DELETE FROM manifest", StoreError::Integrity),
        (
            "INSERT INTO manifest SELECT randomblob(32), key_generation, data_profile, nonce, ciphertext FROM manifest",
            StoreError::Integrity,
        ),
        ("UPDATE replica SET next_counter = 0", StoreError::Integrity),
        ("UPDATE local_head SET mac = x'00'", StoreError::Integrity),
    ];
    for (sql, expected) in cases {
        let d = Dir::new();
        let p = copy(&d);
        Connection::open(&p).unwrap().execute_batch(sql).unwrap();
        refused(&p, *expected, sql);
    }
}

// 0012 §1: Hostile SQLite/CBOR
#[test]
fn tamper_pages_and_files_are_refused() {
    let good = vault_bytes();
    let d = Dir::new();
    let p = d.0.join("v.qvault");
    let write = |bytes: &[u8]| {
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    };
    // Truncated to its first page and to half a page.
    write(&good[..4096]);
    refused(&p, StoreError::Integrity, "one page");
    write(&good[..2048]);
    refused(&p, StoreError::Integrity, "half a page");
    // Every page after the first, overwritten in turn.
    for page in 1..good.len() / 4096 {
        let mut bad = good.to_vec();
        for b in &mut bad[page * 4096..(page + 1) * 4096] {
            *b = 0xa5;
        }
        write(&bad);
        refused(&p, StoreError::Integrity, &format!("page {page}"));
    }
    // Not a database at all, and an empty file.
    write(&[0x5a; 8192]);
    refused(&p, StoreError::Integrity, "random bytes");
    write(&[]);
    refused(&p, StoreError::NotAVault, "empty file");
}

#[test]
fn tamper_file_safety_is_enforced() {
    let d = Dir::new();
    let p = copy(&d);
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    refused(&p, StoreError::UnsafeFile, "mode 0644");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = d.0.join("link.qvault");
    std::os::unix::fs::symlink(&p, &link).unwrap();
    match VaultFile::open(&link) {
        Err(e) => assert_eq!(e, StoreError::UnsafeFile),
        Ok(_) => panic!("opened through a symlink"),
    }
}

/// A rollback journal that truncates the database to one page when SQLite
/// rolls it back. Writing it needs no knowledge of the vault (plan 0008
/// review finding 1).
fn truncating_journal() -> Vec<u8> {
    let mut j = vec![0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    for word in [0u32, 0x1234_5678, 1, 512, 4096] {
        // nRec, checksum seed, original size in pages, sector, page size.
        j.extend_from_slice(&word.to_be_bytes());
    }
    j.resize(512, 0);
    j
}

fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

// 0012 §1: Hostile SQLite/CBOR
#[test]
fn tamper_planted_sidecars_are_refused() {
    let d = Dir::new();
    let p = copy(&d);
    let journal = d.0.join("v.qvault-journal");
    // A world-writable journal, as another user would plant it in a shared
    // directory: SQLite would roll it back and truncate the vault.
    write_mode(&journal, &truncating_journal(), 0o666);
    refused(&p, StoreError::UnsafeFile, "planted journal");
    assert!(journal.exists());
    std::fs::remove_file(&journal).unwrap();
    // A symlinked journal.
    let target = d.0.join("elsewhere");
    write_mode(&target, &truncating_journal(), 0o600);
    std::os::unix::fs::symlink(&target, &journal).unwrap();
    refused(&p, StoreError::UnsafeFile, "symlinked journal");
    std::fs::remove_file(&journal).unwrap();

    // A real WAL for this vault's contents with the header MAC zeroed:
    // SQLite would replay it and checkpoint it into the vault.
    let c = d.0.join("c.qvault");
    std::fs::copy(&p, &c).unwrap();
    let conn = Connection::open(&c).unwrap();
    let mode: String = conn
        .query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "wal");
    conn.execute_batch("PRAGMA wal_autocheckpoint = 0; UPDATE header SET mac = zeroblob(32);")
        .unwrap();
    let wal = d.0.join("v.qvault-wal");
    std::fs::copy(d.0.join("c.qvault-wal"), &wal).unwrap();
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o600)).unwrap();
    drop(conn);
    refused(&p, StoreError::UnsafeFile, "planted wal");
    std::fs::remove_file(&wal).unwrap();
    let shm = d.0.join("v.qvault-shm");
    write_mode(&shm, &[], 0o600);
    refused(&p, StoreError::UnsafeFile, "planted shm");
    std::fs::remove_file(&shm).unwrap();

    drop(VaultFile::open(&p).unwrap());
}

#[test]
fn tamper_own_hot_journal_is_rolled_back() {
    // Our own journal after a crash must still reach SQLite: page 2 was
    // half-written when the process died, and the synced journal holds its
    // original image (SQLite's rollback-journal format: header, then
    // page number, page, checksum; the checksum is the seed plus every
    // 200th byte of the page from the end).
    let good = vault_bytes();
    let pages = u32::try_from(good.len() / 4096).unwrap();
    let original = &good[4096..8192];
    let seed = 0x1234_5678u32;
    let sum = (1..=4096 - 200)
        .rev()
        .step_by(200)
        .fold(seed, |s, i| s.wrapping_add(u32::from(original[i])));
    let mut j = vec![0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];
    for word in [1u32, seed, pages, 512, 4096] {
        j.extend_from_slice(&word.to_be_bytes());
    }
    j.resize(512, 0);
    j.extend_from_slice(&2u32.to_be_bytes());
    j.extend_from_slice(original);
    j.extend_from_slice(&sum.to_be_bytes());

    let d = Dir::new();
    let p = d.0.join("v.qvault");
    let mut torn = good.to_vec();
    for b in &mut torn[4096 + 1000..8192] {
        *b = 0xa5;
    }
    write_mode(&p, &torn, 0o600);
    let journal = d.0.join("v.qvault-journal");
    write_mode(&journal, &j, 0o600);

    drop(VaultFile::open(&p).unwrap());
    assert!(!journal.exists(), "the hot journal was not rolled back");
    assert_eq!(std::fs::read(&p).unwrap(), good);
}

#[test]
fn tamper_shared_parent_is_refused() {
    // A sticky world-writable directory (like /tmp) lets other users plant
    // files next to the vault.
    let d = Dir::new();
    let shared = d.0.join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o1777)).unwrap();
    let p = shared.join("v.qvault");
    write_mode(&p, vault_bytes(), 0o600);
    refused(&p, StoreError::UnsafeFile, "sticky shared parent");
}
