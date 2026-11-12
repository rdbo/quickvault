// SPDX-License-Identifier: AGPL-3.0-or-later

//! A stable, never-removed instance lock: `instance.lock` in an owner-only
//! directory, held with an exclusive byte-range lock (the Windows
//! counterpart of the Linux `flock` guard).
use crate::PlatformError;
use qv_win::fs::{Access, Kind};
use qv_win::security::Rule;
use std::fs::File;
use std::path::Path;

/// Retain this guard for the process lifetime. Release never removes the file.
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Acquire `instance.lock` in an existing owner-only directory. A
    /// reparse point, a non-regular file or a foreign ACL is refused.
    pub fn acquire(directory: &Path) -> Result<Self, PlatformError> {
        if !directory.is_absolute() {
            return Err(PlatformError::InvalidInput);
        }
        let dir = qv_win::fs::open_nofollow(directory, Access::Inspect)
            .map_err(|_| PlatformError::Unavailable)?;
        if qv_win::fs::kind_of(&dir).map_err(|_| PlatformError::Io)? != Kind::Dir
            || !qv_win::fs::meets(&dir, Rule::VaultParent).map_err(|_| PlatformError::Io)?
        {
            return Err(PlatformError::Unavailable);
        }
        let path = directory.join("instance.lock");
        let file = match qv_win::fs::create_private_file(&path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                qv_win::fs::open_nofollow(&path, Access::ReadWrite)
                    .map_err(|_| PlatformError::Unavailable)?
            }
            Err(_) => return Err(PlatformError::Unavailable),
        };
        if qv_win::fs::kind_of(&file).map_err(|_| PlatformError::Io)? != Kind::File
            || !qv_win::fs::meets(&file, Rule::OwnerOnly).map_err(|_| PlatformError::Io)?
        {
            return Err(PlatformError::Unavailable);
        }
        match qv_win::fs::try_lock(&file, true) {
            Ok(true) => Ok(Self { _file: file }),
            Ok(false) => Err(PlatformError::Busy),
            Err(_) => Err(PlatformError::Io),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn instance_contention_release_and_unsafe_paths() {
        let dir = std::env::temp_dir().join(format!("qv-platform-instance-{}", std::process::id()));
        qv_win::fs::create_private_dir(&dir).unwrap();
        let guard = InstanceLock::acquire(&dir).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&dir),
            Err(PlatformError::Busy)
        ));
        drop(guard);
        let guard = InstanceLock::acquire(&dir).unwrap();
        drop(guard);
        assert!(dir.join("instance.lock").is_file());
        let everyone = qv_win::security::Sid::everyone();
        qv_win::fs::set_dacl(
            &dir.join("instance.lock"),
            qv_win::security::FILE_ALL_ACCESS,
            &[qv_win::security::Grant {
                sid: &everyone,
                mask: 0x0012_0089,
                inherit: false,
            }],
        )
        .unwrap();
        assert!(InstanceLock::acquire(&dir).is_err());
        std::fs::remove_file(dir.join("instance.lock")).unwrap();
        std::fs::create_dir(dir.join("instance.lock")).unwrap();
        assert!(InstanceLock::acquire(&dir).is_err());
        assert!(InstanceLock::acquire(Path::new("relative")).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
