// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit user-selected files, anchored to no-follow directory descriptors
//! (0011 §4 attachment path rules). Shared by the CLI and the Linux app.
//! Errors are redacted: no path or OS message is reported.
use crate::{Cancellation, PlatformError};
use rustix::fs::{self, FileType, Mode, OFlags, Stat};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};
fn errno_error(e: rustix::io::Errno) -> PlatformError {
    match e {
        rustix::io::Errno::NOSPC | rustix::io::Errno::DQUOT | rustix::io::Errno::FBIG => {
            PlatformError::StorageCapacity
        }
        _ => PlatformError::Io,
    }
}
fn io_error(e: std::io::Error) -> PlatformError {
    e.raw_os_error().map_or(PlatformError::Io, |code| {
        errno_error(rustix::io::Errno::from_raw_os_error(code))
    })
}
fn directory(fd: &OwnedFd) -> Result<(), PlatformError> {
    let s = fs::fstat(fd).map_err(errno_error)?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory
        || s.st_mode & 0o022 != 0
        || (s.st_uid != 0 && s.st_uid != rustix::process::geteuid().as_raw())
    {
        return Err(PlatformError::Io);
    }
    Ok(())
}
fn parent(path: &Path) -> Result<(OwnedFd, OsString), PlatformError> {
    let final_part = path
        .as_os_str()
        .as_encoded_bytes()
        .rsplit(|b| *b == b'/')
        .next()
        .unwrap_or_default();
    if final_part.is_empty() || final_part == b"." || final_part == b".." {
        return Err(PlatformError::Io);
    }
    let parts: Vec<_> = path.components().collect();
    let Some(Component::Normal(name)) = parts.last() else {
        return Err(PlatformError::Io);
    };
    if path.as_os_str().as_encoded_bytes().ends_with(b"/") {
        return Err(PlatformError::Io);
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::open(
        if path.is_absolute() { "/" } else { "." },
        flags,
        Mode::empty(),
    )
    .map_err(errno_error)?;
    directory(&fd)?;
    for part in &parts[..parts.len() - 1] {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(p) => {
                fd = fs::openat(&fd, *p, flags, Mode::empty()).map_err(errno_error)?;
                directory(&fd)?;
            }
            _ => return Err(PlatformError::Io),
        }
    }
    Ok((fd, name.to_os_string()))
}
/// Input with immutable descriptor identity; changes are rejected at EOF,
/// before the caller commits what it read.
pub struct Input {
    file: File,
    initial: Stat,
    parent: OwnedFd,
    name: OsString,
    cancel: Cancellation,
}
impl Input {
    /// Open a regular file of at most `max` bytes (`LimitExceeded` above it).
    pub fn open(path: &Path, max: u64, cancel: Cancellation) -> Result<Self, PlatformError> {
        let (dir, name) = parent(path)?;
        let fd = fs::openat(
            &dir,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(errno_error)?;
        let initial = fs::fstat(&fd).map_err(errno_error)?;
        if FileType::from_raw_mode(initial.st_mode) != FileType::RegularFile {
            return Err(PlatformError::Io);
        }
        if u64::try_from(initial.st_size).map_or(true, |size| size > max) {
            return Err(PlatformError::LimitExceeded);
        }
        Ok(Self {
            file: File::from(fd),
            initial,
            parent: dir,
            name,
            cancel,
        })
    }
    fn unchanged(&self) -> std::io::Result<()> {
        let s = fs::fstat(&self.file)?;
        let named = fs::statat(&self.parent, &self.name, fs::AtFlags::SYMLINK_NOFOLLOW)?;
        let a = &self.initial;
        if (named.st_dev, named.st_ino) != (a.st_dev, a.st_ino) {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        if (
            s.st_dev,
            s.st_ino,
            s.st_size,
            s.st_mtime,
            s.st_mtime_nsec,
            s.st_ctime,
            s.st_ctime_nsec,
        ) != (
            a.st_dev,
            a.st_ino,
            a.st_size,
            a.st_mtime,
            a.st_mtime_nsec,
            a.st_ctime,
            a.st_ctime_nsec,
        ) {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if (self.cancel)() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        let n = self.file.read(out)?;
        if n == 0 {
            self.unchanged()?;
        }
        Ok(n)
    }
}
/// Exclusively created owner-only plaintext output at the exact path; never
/// overwrites. Failures may leave partial content, which callers must report.
pub struct Output {
    file: File,
    parent: OwnedFd,
    name: OsString,
    cancel: Cancellation,
}
impl Output {
    /// Create a new 0600 regular file; an existing path is refused.
    pub fn create(path: &Path, cancel: Cancellation) -> Result<Self, PlatformError> {
        let (parent, name) = parent(path)?;
        let fd = fs::openat(
            &parent,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(errno_error)?;
        Ok(Self {
            file: File::from(fd),
            parent,
            name,
            cancel,
        })
    }
    /// Confirm the path still names this file, then sync file and directory.
    pub fn finish(&self) -> Result<(), PlatformError> {
        let held = fs::fstat(&self.file).map_err(errno_error)?;
        let named = fs::statat(&self.parent, &self.name, fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(errno_error)?;
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) {
            return Err(PlatformError::Io);
        }
        self.file.sync_all().map_err(io_error)?;
        fs::fsync(&self.parent).map_err(errno_error)
    }
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if (self.cancel)() {
            return Err(std::io::ErrorKind::ConnectionAborted.into());
        }
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::sync::Arc;
    fn never() -> Cancellation {
        Arc::new(|| false)
    }
    // Relative paths from one private working directory keep these tests
    // independent of host ancestors (a sandbox may not own "/").
    fn private(tag: &str) -> std::path::PathBuf {
        static ROOT: std::sync::Once = std::sync::Once::new();
        ROOT.call_once(|| {
            let root = std::env::temp_dir().join(format!("qv-files-{}", std::process::id()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            std::env::set_current_dir(&root).unwrap();
        });
        let dir = std::path::PathBuf::from(tag);
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        dir
    }
    #[test]
    fn files_changed_input_and_replaced_output() {
        let dir = private("change");
        let file_path = dir.join("input");
        std::fs::write(&file_path, b"abc").unwrap();
        let mut input = Input::open(&file_path, 1024, never()).unwrap();
        let mut bytes = [0; 3];
        assert_eq!(input.read(&mut bytes).unwrap(), 3);
        std::fs::write(&file_path, b"longer").unwrap();
        assert!(input.read(&mut [0; 8]).is_ok());
        assert!(input.read(&mut [0; 8]).is_err());
        std::fs::rename(&file_path, dir.join("old")).unwrap();
        std::fs::write(&file_path, b"replacement").unwrap();
        assert!(input.unchanged().is_err());
        let output_path = dir.join("output");
        let output = Output::create(&output_path, never()).unwrap();
        std::fs::rename(&output_path, dir.join("old-output")).unwrap();
        std::fs::write(&output_path, b"successor").unwrap();
        assert!(output.finish().is_err());
        drop(output);
        assert_eq!(std::fs::read(&output_path).unwrap(), b"successor");
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn files_reject_unsafe_paths_sizes_existing_output_and_cancellation() {
        let dir = private("reject");
        std::fs::write(dir.join("real"), b"12345").unwrap();
        std::os::unix::fs::symlink(&dir, dir.join("link")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("file-link")).unwrap();
        std::fs::create_dir(dir.join("sub")).unwrap();
        for bad in ["link/real", "file-link", "sub/../real", "sub", "real/", "."] {
            assert_eq!(
                Input::open(&dir.join(bad), 1024, never()).err(),
                Some(PlatformError::Io),
                "{bad}"
            );
        }
        assert_eq!(
            Input::open(&dir.join("real"), 4, never()).err(),
            Some(PlatformError::LimitExceeded)
        );
        assert_eq!(
            Output::create(&dir.join("real"), never()).err(),
            Some(PlatformError::Io)
        );
        assert_eq!(std::fs::read(dir.join("real")).unwrap(), b"12345");
        std::fs::create_dir(dir.join("shared")).unwrap();
        std::fs::set_permissions(dir.join("shared"), std::fs::Permissions::from_mode(0o777))
            .unwrap();
        assert!(Output::create(&dir.join("shared/out"), never()).is_err());
        let out = dir.join("new");
        let mut output = Output::create(&out, Arc::new(|| true)).unwrap();
        assert!(output.write(b"x").is_err());
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let mut input = Input::open(&dir.join("real"), 1024, Arc::new(|| true)).unwrap();
        assert!(input.read(&mut [0; 4]).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn files_absolute_paths_follow_actual_ancestor_ownership() {
        let dir = private("absolute");
        std::fs::write(dir.join("real"), b"1").unwrap();
        let absolute = std::fs::canonicalize(dir.join("real")).unwrap();
        let euid = rustix::process::geteuid().as_raw();
        let safe = absolute.ancestors().skip(1).all(|a| {
            let s = std::fs::metadata(a).unwrap();
            use std::os::unix::fs::MetadataExt;
            s.mode() & 0o022 == 0 && (s.uid() == 0 || s.uid() == euid)
        });
        assert_eq!(Input::open(&absolute, 1024, never()).is_ok(), safe);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
