// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit attachment files, anchored to no-follow directory descriptors.
use crate::exit::{CliError, LIMIT, OTHER};
use rustix::fs::{self, FileType, Mode, OFlags, Stat};
use std::{
    ffi::OsString,
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    path::{Component, Path},
};
fn error() -> CliError {
    CliError::new(OTHER, "attachment file I/O failed or path is unsafe")
}
fn directory(fd: &OwnedFd) -> Result<(), CliError> {
    let s = fs::fstat(fd).map_err(|_| error())?;
    if FileType::from_raw_mode(s.st_mode) != FileType::Directory
        || s.st_mode & 0o022 != 0
        || (s.st_uid != 0 && s.st_uid != rustix::process::geteuid().as_raw())
    {
        return Err(error());
    }
    Ok(())
}
fn parent(path: &Path) -> Result<(OwnedFd, OsString), CliError> {
    let final_part = path
        .as_os_str()
        .as_encoded_bytes()
        .rsplit(|b| *b == b'/')
        .next()
        .unwrap_or_default();
    if final_part.is_empty() || final_part == b"." || final_part == b".." {
        return Err(error());
    }
    let parts: Vec<_> = path.components().collect();
    let Some(Component::Normal(name)) = parts.last() else {
        return Err(error());
    };
    if path.as_os_str().as_encoded_bytes().ends_with(b"/") {
        return Err(error());
    }
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut fd = fs::open(
        if path.is_absolute() { "/" } else { "." },
        flags,
        Mode::empty(),
    )
    .map_err(|_| error())?;
    directory(&fd)?;
    for part in &parts[..parts.len() - 1] {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(p) => {
                fd = fs::openat(&fd, *p, flags, Mode::empty()).map_err(|_| error())?;
                directory(&fd)?;
            }
            _ => return Err(error()),
        }
    }
    Ok((fd, name.to_os_string()))
}
/// Open input with immutable descriptor identity; reject changes before import commit.
pub(crate) struct Input {
    file: File,
    initial: Stat,
    parent: OwnedFd,
    name: OsString,
}
impl Input {
    pub(crate) fn open(path: &Path) -> Result<Self, CliError> {
        let (dir, name) = parent(path)?;
        let fd = fs::openat(
            &dir,
            &name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|_| error())?;
        let initial = fs::fstat(&fd).map_err(|_| error())?;
        if FileType::from_raw_mode(initial.st_mode) != FileType::RegularFile {
            return Err(error());
        }
        if initial.st_size < 0 || initial.st_size > 10 * 1024 * 1024 {
            return Err(CliError::new(LIMIT, "attachment exceeds 10 MiB limit"));
        }
        Ok(Self {
            file: File::from(fd),
            initial,
            parent: dir,
            name,
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
        crate::signals::check().map_err(|_| std::io::ErrorKind::ConnectionAborted)?;
        let n = self.file.read(out)?;
        if n == 0 {
            self.unchanged()?;
        }
        Ok(n)
    }
}
/// Exclusively created explicit plaintext output; failures may leave partial content.
pub(crate) struct Output {
    file: File,
    parent: OwnedFd,
    name: OsString,
}
impl Output {
    pub(crate) fn create(path: &Path) -> Result<Self, CliError> {
        let (parent, name) = parent(path)?;
        let fd = fs::openat(
            &parent,
            &name,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| error())?;
        Ok(Self {
            file: File::from(fd),
            parent,
            name,
        })
    }
    pub(crate) fn finish(&self) -> Result<(), CliError> {
        let held = fs::fstat(&self.file).map_err(|_| error())?;
        let named = fs::statat(&self.parent, &self.name, fs::AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| error())?;
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) {
            return Err(error());
        }
        self.file.sync_all().map_err(|_| error())?;
        fs::fsync(&self.parent).map_err(|_| error())
    }
}
impl Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        crate::signals::check().map_err(|_| std::io::ErrorKind::ConnectionAborted)?;
        self.file.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    #[test]
    fn attachment_files_changed_input_and_replaced_output() {
        let dir = std::env::temp_dir().join(format!("qv-attach-files-{}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        let file_path = dir.join("input");
        std::fs::write(&file_path, b"abc").unwrap();
        let parent = fs::open(&dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let file = File::open(&file_path).unwrap();
        let initial = fs::fstat(&file).unwrap();
        let mut input = Input {
            file,
            initial,
            parent,
            name: "input".into(),
        };
        let mut bytes = [0; 3];
        assert_eq!(input.read(&mut bytes).unwrap(), 3);
        std::fs::write(&file_path, b"longer").unwrap();
        assert!(input.read(&mut [0; 8]).is_ok());
        assert!(input.read(&mut [0; 8]).is_err());
        std::fs::rename(&file_path, dir.join("old")).unwrap();
        std::fs::write(&file_path, b"replacement").unwrap();
        assert!(input.unchanged().is_err());
        let parent = fs::open(&dir, OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty()).unwrap();
        let output_path = dir.join("output");
        let output = Output {
            file: File::create(&output_path).unwrap(),
            parent,
            name: "output".into(),
        };
        std::fs::rename(&output_path, dir.join("old-output")).unwrap();
        std::fs::write(&output_path, b"successor").unwrap();
        assert!(output.finish().is_err());
        drop(output);
        assert_eq!(std::fs::read(&output_path).unwrap(), b"successor");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
