// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile bytes as a vault file (spec 0004 §1.2, §4.1; 0012 §1 row
//! "Hostile SQLite/CBOR", SQLite half).
//!
//! The candidate file is written to a private file and opened with
//! `VaultFile::open`: file checks, hardening, `quick_check`, exact-schema
//! validation, row checks and header/slot decoding, all before any key is
//! available. Any result is acceptable; a panic, abort or hang is a finding.
//! `unlock` is not fuzzed here: it runs a fixed Argon2id profile and then
//! only authenticated code.
//!
//! The first input byte selects how the rest becomes the file:
//! - even: the rest is the file, as raw bytes (hostile shapes of any kind);
//! - odd: the rest is applied to a copy of a real vault, created once per
//!   process, as 5-byte groups `(offset u32, byte)` plus a final 4-byte
//!   selector that truncates or extends the copy (as in `archive_read`).
//!   Random bytes rarely form a valid SQLite file, so without this seed
//!   most of the schema, row and header checks stay out of reach (plan
//!   0024: coverage 277 unseeded, 663 seeded).

#![no_main]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use qv_crypto::MasterPassword;
use qv_store::{AnchorDir, VaultFile};

/// The seed vault's password. Not a secret: the vault exists only inside
/// this process's temporary directory.
const PASSWORD: &str = "qv-fuzz-vault-open";

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

/// The private input path for this process.
fn input_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| private_dir("vault-open").join("fuzz.qvault"))
}

/// The bytes of a freshly created vault: the password KDF runs once per
/// process.
fn seed() -> &'static [u8] {
    static SEED: OnceLock<Vec<u8>> = OnceLock::new();
    SEED.get_or_init(|| {
        let vault_dir = private_dir("vault-open-seed");
        let anchors =
            AnchorDir::open(&private_dir("vault-open-anchors")).expect("anchor directory");
        let password = MasterPassword::from_utf8(PASSWORD.as_bytes()).expect("fuzz password");
        let path = vault_dir.join("seed.qvault");
        drop(VaultFile::create(&path, &password, "Fuzz", &anchors).expect("create the seed vault"));
        std::fs::read(&path).expect("read the seed vault")
    })
}

/// Applies `data` to `bytes` (see the module docs).
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
            let extra = selector % 8192;
            bytes.extend(std::iter::repeat_n(0xAA, extra));
        }
        _ => {}
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let file = if mode & 1 == 0 {
        rest.to_vec()
    } else {
        let mut bytes = seed().to_vec();
        mutate(&mut bytes, rest);
        bytes
    };
    let path = input_path();
    let _ = std::fs::remove_file(path);
    std::fs::write(path, &file).expect("write fuzz input");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod fuzz input");
    let _ = VaultFile::open(path);
});
