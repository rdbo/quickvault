// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit user-selected files on Windows (0011 §4 attachment path rules;
//! 0009 §5.1; plan 0052), with the API of the Unix module.
//!
//! The path is made lexically absolute. Every component down to the parent
//! must be a real directory, not a reparse point, that no other account can
//! delete, rename or re-permission (adding new names cannot replace an
//! existing one); the parent must also give other accounts no right to add
//! or remove entries. The file itself is opened without following a reparse
//! point. Unlike `openat`, the component checks and the open are separate
//! steps, so identity is rechecked at EOF and on finish. Errors are
//! redacted: no path or OS message is reported.
use crate::{Cancellation, PlatformError};
use qv_win::fs::{Access, FileId, Kind};
use qv_win::security::Rule;
use std::{
    fs::File,
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    time::SystemTime,
};

fn io_error(e: std::io::Error) -> PlatformError {
    // ERROR_HANDLE_DISK_FULL, ERROR_DISK_FULL, ERROR_FILE_TOO_LARGE,
    // ERROR_DISK_QUOTA_EXCEEDED, ERROR_NOT_ENOUGH_QUOTA
    match e.raw_os_error() {
        Some(39 | 112 | 223 | 1295 | 1816) => PlatformError::StorageCapacity,
        _ => PlatformError::Io,
    }
}

fn check_dir(path: &Path, rule: Rule) -> Result<(), PlatformError> {
    let dir = qv_win::fs::open_nofollow(path, Access::Inspect).map_err(io_error)?;
    if qv_win::fs::kind_of(&dir).map_err(io_error)? != Kind::Dir
        || !qv_win::fs::meets(&dir, rule).map_err(io_error)?
    {
        return Err(PlatformError::Io);
    }
    Ok(())
}

/// Checks the components of `path` and returns its absolute form.
fn checked(path: &Path) -> Result<PathBuf, PlatformError> {
    let raw = path.as_os_str().as_encoded_bytes();
    if raw.is_empty() || raw.ends_with(b"\\") || raw.ends_with(b"/") {
        return Err(PlatformError::Io);
    }
    let absolute = std::path::absolute(path).map_err(io_error)?;
    let parts: Vec<_> = absolute.components().collect();
    let Some(Component::Normal(_)) = parts.last() else {
        return Err(PlatformError::Io);
    };
    let mut at = PathBuf::new();
    let last_dir = parts.len() - 2;
    for (i, part) in parts[..parts.len() - 1].iter().enumerate() {
        at.push(part.as_os_str());
        match part {
            Component::Prefix(_) => continue,
            Component::RootDir | Component::Normal(_) => {}
            _ => return Err(PlatformError::Io),
        }
        let rule = if i == last_dir {
            Rule::NoForeignWrite
        } else {
            Rule::NoForeignReplace
        };
        check_dir(&at, rule)?;
    }
    Ok(absolute)
}

fn identity(path: &Path) -> std::io::Result<FileId> {
    let f = qv_win::fs::open_nofollow(path, Access::Inspect)?;
    if qv_win::fs::kind_of(&f)? != Kind::File {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    qv_win::fs::file_id(&f)
}

/// Input with immutable identity; changes are rejected at EOF, before the
/// caller commits what it read.
pub struct Input {
    file: File,
    path: PathBuf,
    id: FileId,
    len: u64,
    modified: Option<SystemTime>,
    cancel: Cancellation,
}
impl Input {
    /// Open a regular file of at most `max` bytes (`LimitExceeded` above it).
    pub fn open(path: &Path, max: u64, cancel: Cancellation) -> Result<Self, PlatformError> {
        let path = checked(path)?;
        let file = qv_win::fs::open_nofollow(&path, Access::Read).map_err(io_error)?;
        if qv_win::fs::kind_of(&file).map_err(io_error)? != Kind::File {
            return Err(PlatformError::Io);
        }
        let meta = file.metadata().map_err(io_error)?;
        if meta.len() > max {
            return Err(PlatformError::LimitExceeded);
        }
        Ok(Self {
            id: qv_win::fs::file_id(&file).map_err(io_error)?,
            len: meta.len(),
            modified: meta.modified().ok(),
            file,
            path,
            cancel,
        })
    }
    fn unchanged(&self) -> std::io::Result<()> {
        let meta = self.file.metadata()?;
        if identity(&self.path)? != self.id
            || meta.len() != self.len
            || meta.modified().ok() != self.modified
        {
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
    path: PathBuf,
    id: FileId,
    cancel: Cancellation,
}
impl Output {
    /// Create a new owner-only regular file; an existing path is refused.
    pub fn create(path: &Path, cancel: Cancellation) -> Result<Self, PlatformError> {
        let path = checked(path)?;
        let file = qv_win::fs::create_private_file(&path).map_err(io_error)?;
        Ok(Self {
            id: qv_win::fs::file_id(&file).map_err(io_error)?,
            file,
            path,
            cancel,
        })
    }
    /// Confirm the path still names this file, then flush it. NTFS
    /// journals the new directory entry.
    pub fn finish(&self) -> Result<(), PlatformError> {
        if identity(&self.path).map_err(io_error)? != self.id {
            return Err(PlatformError::Io);
        }
        self.file.sync_all().map_err(io_error)
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
    use std::sync::Arc;
    fn never() -> Cancellation {
        Arc::new(|| false)
    }
    fn private(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("qv-files-{}-{tag}", std::process::id()));
        qv_win::fs::create_private_dir(&dir).unwrap();
        dir
    }

    #[test]
    fn files_round_trip_never_overwrite_and_detect_changes() {
        let dir = private("change");
        let file_path = dir.join("input");
        std::fs::write(&file_path, b"abc").unwrap();
        let mut input = Input::open(&file_path, 1024, never()).unwrap();
        let mut bytes = Vec::new();
        input.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"abc");
        assert!(matches!(
            Input::open(&file_path, 2, never()),
            Err(PlatformError::LimitExceeded)
        ));
        let mut input = Input::open(&file_path, 1024, never()).unwrap();
        std::fs::write(&file_path, b"longer").unwrap();
        assert!(input.read_to_end(&mut Vec::new()).is_err());

        let output_path = dir.join("output");
        let mut output = Output::create(&output_path, never()).unwrap();
        output.write_all(b"plain").unwrap();
        output.finish().unwrap();
        assert!(Output::create(&output_path, never()).is_err());
        assert!(Output::create(&dir.join("trailing\\"), never()).is_err());
        drop(output);
        std::fs::remove_file(&output_path).unwrap();
        assert!(Input::open(&dir, 1024, never()).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn files_refuse_shared_parents_and_cancel() {
        let dir = private("shared");
        let everyone = qv_win::security::Sid::everyone();
        qv_win::fs::set_dacl(
            &dir,
            qv_win::security::FILE_ALL_ACCESS,
            &[qv_win::security::Grant {
                sid: &everyone,
                mask: 0x0013_01BF,
                inherit: false,
            }],
        )
        .unwrap();
        assert!(Output::create(&dir.join("x"), never()).is_err());
        qv_win::fs::set_dacl(&dir, qv_win::security::FILE_ALL_ACCESS, &[]).unwrap();
        let mut out = Output::create(&dir.join("y"), Arc::new(|| true)).unwrap();
        assert!(out.write(b"z").is_err());
        drop(out);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
