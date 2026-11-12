// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable file-permission fixtures for the integration tests: Unix modes,
//! or their Windows ACL equivalents (spec 0009 §5.1; plan 0052).

#![allow(dead_code, clippy::unwrap_used, clippy::panic)]

use std::path::Path;

/// Creates an owner-only directory.
pub fn private_dir(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    #[cfg(windows)]
    qv_win::fs::create_private_dir(path).unwrap();
}

/// `chmod mode`, or the ACL equivalent: group/other write grants Everyone
/// modify, read bits grant Everyone read; an already owner-only object
/// stays as it is for a private mode.
pub fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(windows)]
    qv_win::fs::chmod_like(path, mode).unwrap();
}

/// Writes `bytes` (truncating) and applies `mode`. On Windows a new file
/// starts owner-only, as it would inherit in a private directory.
pub fn write_mode(path: &Path, bytes: &[u8], mode: u32) {
    #[cfg(windows)]
    if !path.exists() {
        drop(qv_win::fs::create_private_file(path).unwrap());
    }
    std::fs::write(path, bytes).unwrap();
    set_mode(path, mode);
}

/// Creates a symlink; `false` on Windows without the privilege outside CI.
pub fn symlink(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).unwrap();
        true
    }
    #[cfg(windows)]
    match std::os::windows::fs::symlink_file(target, link) {
        Ok(()) => true,
        Err(e) if e.raw_os_error() == Some(1314) && std::env::var_os("CI").is_none() => {
            eprintln!("skipped: no symlink privilege outside CI");
            false
        }
        Err(e) => panic!("symlink: {e}"),
    }
}
