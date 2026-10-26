// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile bytes as a vault file (spec 0004 §1.2, §4.1; 0012 §1 row
//! "Hostile SQLite/CBOR", SQLite half).
//!
//! The input is written to a private file and opened with
//! `VaultFile::open`: file checks, hardening, `quick_check`, exact-schema
//! validation, row checks and header/slot decoding, all before any key is
//! available. Any result is acceptable; a panic, abort or hang is a finding.
//! `unlock` is not fuzzed here: it runs a fixed Argon2id profile and then
//! only authenticated code.

#![no_main]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use qv_store::VaultFile;

/// A private 0700 directory for this process's input file.
fn input_path() -> &'static PathBuf {
    static PATH: OnceLock<PathBuf> = OnceLock::new();
    PATH.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("qv-fuzz-vault-open-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .expect("private fuzz directory");
        dir.join("fuzz.qvault")
    })
}

fuzz_target!(|data: &[u8]| {
    let path = input_path();
    let _ = std::fs::remove_file(path);
    std::fs::write(path, data).expect("write fuzz input");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod fuzz input");
    let _ = VaultFile::open(path);
});
