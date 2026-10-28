// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile archive bytes (spec 0004 §6.3, §4.1; 0012 §1 row "Hostile files
//! from sync folders").
//!
//! One small real vault and one archive of it are built per process: the
//! archive is the seed, and `UnlockedVault::vault_key()` is the key the
//! reader authenticates with, so every iteration exercises the whole 0004
//! §6.3 order (prefix → bounded header → vault/generation → header MAC →
//! manifest frame hash → manifest decrypt/decode/validate → frames matched by
//! length and SHA-256 before AEAD → exact EOF) on attacker-controlled bytes.
//!
//! The input is applied to a copy of the seed as 5-byte groups `(offset u32,
//! byte)` plus a final 4-byte selector that truncates or extends the copy, so
//! one input covers substitution, truncation and trailing bytes. Any result
//! is acceptable; a panic, abort, hang, unbounded allocation or a SQLite call
//! is a finding.

#![no_main]

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use libfuzzer_sys::fuzz_target;
use qv_crypto::MasterPassword;
use qv_model::Timestamp;
use qv_store::{AnchorDir, ArchiveObject, ArchiveScope, UnlockedVault, VaultFile, read_archive};

/// The fuzz vault's password. Not a secret: the vault exists only inside this
/// process's temporary directory.
const PASSWORD: &str = "qv-fuzz-archive-read";

/// A fresh 0700 directory for this process.
fn private_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("qv-fuzz-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .expect("private fuzz directory");
    dir
}

/// One vault and one archive of it for the whole process.
struct Fixture {
    vault: UnlockedVault,
    archive: Vec<u8>,
}

/// The fixture, built on first use: the password KDF runs once per process.
fn fixture() -> &'static Mutex<Fixture> {
    static FIXTURE: OnceLock<Mutex<Fixture>> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let vault_dir = private_dir("archive-vault");
        let anchor_dir = private_dir("archive-anchors");
        let anchors = AnchorDir::open(&anchor_dir).expect("anchor directory");
        let password = MasterPassword::from_utf8(PASSWORD.as_bytes()).expect("fuzz password");
        let mut vault =
            VaultFile::create(&vault_dir.join("fuzz.qvault"), &password, "Fuzz", &anchors)
                .expect("create the fuzz vault");
        let mut archive = Vec::new();
        vault
            .write_archive(&mut archive, Timestamp(1_700_000_000_000), &|| false)
            .expect("write the fuzz archive");
        Mutex::new(Fixture { vault, archive })
    })
}

/// Applies `data` to a copy of the seed archive.
fn mutate(bytes: &mut Vec<u8>, data: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    for group in data.chunks_exact(5) {
        let offset = u32::from_be_bytes([group[0], group[1], group[2], group[3]]) as usize;
        if let Some(byte) = bytes.get_mut(offset) {
            *byte = group[4];
        }
    }
    let Some(tail) = data.get(data.len().saturating_sub(4)..) else {
        return;
    };
    let Ok(tail) = <[u8; 4]>::try_from(tail) else {
        return;
    };
    let selector = u32::from_be_bytes(tail) as usize;
    let len = bytes.len();
    match selector % 3 {
        0 => bytes.truncate(selector % (len + 1)),
        1 => {
            let extra = selector % 64;
            bytes.extend(std::iter::repeat_n(0xAA, extra));
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let guard = fixture()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut bytes = guard.archive.clone();
    mutate(&mut bytes, data);
    let vault = &guard.vault;
    let scope = ArchiveScope::new(vault.header().vault_id, vault.header().key_generation);
    let mut sink = |_: ArchiveObject<'_>| Ok(());
    let _ = read_archive(
        &mut &bytes[..],
        scope,
        vault.vault_key(),
        &mut sink,
        &|| false,
    );
});
