// SPDX-License-Identifier: AGPL-3.0-or-later

//! A stable, never-unlinked instance lock, anchored to no-follow directory fds.
use crate::PlatformError;
use rustix::fs::{FileType, FlockOperation, Mode, OFlags, flock, fstat, open, openat};
use std::{
    os::fd::OwnedFd,
    path::{Component, Path},
};

/// Retain this guard for the process lifetime. Release never unlinks the file.
#[derive(Debug)]
pub struct InstanceLock {
    _fd: OwnedFd,
}
impl InstanceLock {
    /// Acquire `instance.lock` in an existing owner-only directory. No symlink
    /// component, non-regular file, shared mode or foreign owner is accepted.
    pub fn acquire(directory: &Path) -> Result<Self, PlatformError> {
        if !directory.is_absolute() {
            return Err(PlatformError::InvalidInput);
        }
        let mut dir = open(
            "/",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| PlatformError::Io)?;
        for component in directory.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => {
                    dir = openat(
                        &dir,
                        name,
                        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                        Mode::empty(),
                    )
                    .map_err(|_| PlatformError::Unavailable)?;
                }
                _ => return Err(PlatformError::InvalidInput),
            }
        }
        let stat = fstat(&dir).map_err(|_| PlatformError::Io)?;
        if stat.st_uid != rustix::process::geteuid().as_raw() || stat.st_mode & 0o077 != 0 {
            return Err(PlatformError::Unavailable);
        }
        let fd = openat(
            &dir,
            "instance.lock",
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| PlatformError::Unavailable)?;
        let stat = fstat(&fd).map_err(|_| PlatformError::Io)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_uid != rustix::process::geteuid().as_raw()
            || stat.st_mode & 0o077 != 0
            || stat.st_nlink != 1
        {
            return Err(PlatformError::Unavailable);
        }
        flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|e| {
            if e == rustix::io::Errno::WOULDBLOCK {
                PlatformError::Busy
            } else {
                PlatformError::Io
            }
        })?;
        Ok(Self { _fd: fd })
    }
}

#[cfg(test)]
mod tests {
    // Temporary fixtures are public metadata only.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[test]
    fn instance_contention_release_and_unsafe_paths() {
        let dir = std::env::temp_dir().join(format!("qv-platform-instance-{}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let guard = InstanceLock::acquire(&dir).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&dir),
            Err(PlatformError::Busy)
        ));
        drop(guard);
        let guard = InstanceLock::acquire(&dir).unwrap();
        drop(guard);
        assert!(dir.join("instance.lock").is_file());
        std::fs::set_permissions(
            dir.join("instance.lock"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(InstanceLock::acquire(&dir).is_err());
        std::fs::remove_file(dir.join("instance.lock")).unwrap();
        symlink("missing", dir.join("instance.lock")).unwrap();
        assert!(InstanceLock::acquire(&dir).is_err());
        std::fs::remove_file(dir.join("instance.lock")).unwrap();
        std::fs::create_dir(dir.join("instance.lock")).unwrap();
        assert!(InstanceLock::acquire(&dir).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
