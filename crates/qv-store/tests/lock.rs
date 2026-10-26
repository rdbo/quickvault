// SPDX-License-Identifier: AGPL-3.0-or-later

//! A second process cannot open a vault this process holds (spec 0004
//! §1.3). The test re-runs its own binary as an ignored helper test.

#![cfg(any(target_os = "linux", target_os = "android"))]
// The helpers below are test code, but clippy's `allow-*-in-tests` settings
// only cover `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::process::Command;

use qv_crypto::MasterPassword;
use qv_store::{StoreError, VaultFile};

const PATH_VAR: &str = "QV_STORE_LOCK_TEST_PATH";

/// Exit codes of the helper.
const OPENED: i32 = 0;
const LOCKED: i32 = 3;
const OTHER: i32 = 4;

/// Run by [`second_process_gets_lock_error`] in a child process.
#[test]
#[ignore = "helper; run by second_process_gets_lock_error"]
fn lock_helper() {
    let Some(path) = std::env::var_os(PATH_VAR) else {
        return;
    };
    let code = match VaultFile::open(&PathBuf::from(path)) {
        Ok(_) => OPENED,
        Err(StoreError::Locked) => LOCKED,
        Err(_) => OTHER,
    };
    std::process::exit(code);
}

fn child(path: &std::path::Path) -> i32 {
    Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "lock_helper", "--ignored", "--test-threads=1"])
        .env(PATH_VAR, path)
        .status()
        .unwrap()
        .code()
        .unwrap()
}

#[test]
fn second_process_gets_lock_error() {
    let mut name = String::from("qv-store-lock-");
    for b in qv_crypto::random_array::<8>().unwrap() {
        name.push_str(&format!("{b:02x}"));
    }
    let dir = std::env::temp_dir().join(name);
    std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    let path = dir.join("v.qvault");
    let pw = MasterPassword::from_utf8(b"lock test password").unwrap();
    drop(VaultFile::create(&path, &pw).unwrap());

    let held = VaultFile::open(&path).unwrap();
    assert_eq!(child(&path), LOCKED);
    drop(held);
    assert_eq!(child(&path), OPENED);
    std::fs::remove_dir_all(&dir).unwrap();
}
