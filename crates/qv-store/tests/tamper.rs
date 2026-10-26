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
use qv_store::{StoreError, VaultFile};
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
        drop(VaultFile::create(&p, &pw).unwrap());
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
    ];
    for (sql, expected) in cases {
        let d = Dir::new();
        let p = copy(&d);
        Connection::open(&p).unwrap().execute_batch(sql).unwrap();
        refused(&p, *expected, sql);
    }
}

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
