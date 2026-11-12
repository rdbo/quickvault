// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded lexical receipt names and no-reparse hostile input opening on
//! Windows (plan 0052; the Unix module pins every ancestor with `O_PATH`).
//!
//! Receipt names keep the stored form of `receipts` (absolute, `/`
//! separated, no empty, `.` or `..` part). A Windows path is first made
//! lexically absolute (`std::path::absolute`, which resolves `.` and `..`
//! without touching the filesystem), then written as `/C:/dir/name` for a
//! drive path and `/UNC/server/share/dir/name` for a share; verbatim
//! (`\\?\`) forms map to the same names. Device namespaces are refused.
//! Names are case-preserving, so differently cased spellings of one file
//! are different receipts (a redelivery is then merged again, which is
//! idempotent).
//!
//! Opening refuses a reparse point at every component from the volume root
//! down, then opens the leaf without following one. Unlike `openat`, the
//! ancestor check and the open are separate steps; a same-user process
//! could swap an ancestor between them. The incoming archive is
//! authenticated before use either way.

use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf, Prefix};

use qv_crypto::SecretBytes;
use qv_win::fs::Kind;

use crate::{MAX_RECEIPT_PATH_BYTES, StoreError};

pub(crate) fn normalize(path: &Path) -> Result<SecretBytes, StoreError> {
    let raw = path.as_os_str();
    if raw.is_empty() || raw.as_encoded_bytes().contains(&0) {
        return Err(StoreError::UnsafeFile);
    }
    if raw.len() > MAX_RECEIPT_PATH_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    // An OS intermediate (GetFullPathNameW for relative paths); its copies
    // are best effort, as getcwd's are on Unix.
    let absolute = std::path::absolute(path).map_err(crate::error::io_err)?;
    let mut out = String::new();
    let mut parts = 0usize;
    for c in absolute.components() {
        match c {
            Component::Prefix(p) => match p.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                    out.push('/');
                    out.push(char::from(d.to_ascii_uppercase()));
                    out.push(':');
                }
                Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
                    out.push_str("/UNC");
                    for part in [server, share] {
                        out.push('/');
                        out.push_str(part_str(part)?);
                    }
                }
                _ => return Err(StoreError::UnsafeFile),
            },
            Component::RootDir => {}
            Component::Normal(n) => {
                out.push('/');
                out.push_str(part_str(n)?);
                parts += 1;
            }
            Component::CurDir | Component::ParentDir => return Err(StoreError::UnsafeFile),
        }
        if out.len() > MAX_RECEIPT_PATH_BYTES {
            return Err(StoreError::LimitExceeded);
        }
    }
    if parts == 0 || !out.starts_with('/') {
        return Err(StoreError::UnsafeFile);
    }
    let mut bytes = out.into_bytes();
    Ok(SecretBytes::take_from(&mut bytes))
}

fn part_str(part: &OsStr) -> Result<&str, StoreError> {
    match part.to_str() {
        Some(s) if !s.is_empty() && s != "." && s != ".." && !s.contains('/') => Ok(s),
        _ => Err(StoreError::UnsafeFile),
    }
}

/// The Windows path of a receipt name made by [`normalize`].
fn to_windows(name: &str) -> Result<PathBuf, StoreError> {
    let mut parts = name
        .strip_prefix('/')
        .ok_or(StoreError::UnsafeFile)?
        .split('/');
    let mut path = match parts.next() {
        Some("UNC") => {
            let server = parts.next().ok_or(StoreError::UnsafeFile)?;
            let share = parts.next().ok_or(StoreError::UnsafeFile)?;
            PathBuf::from(format!(r"\\{server}\{share}\"))
        }
        Some(d) if d.len() == 2 && d.ends_with(':') && d.as_bytes()[0].is_ascii_alphabetic() => {
            PathBuf::from(format!(r"{d}\"))
        }
        _ => return Err(StoreError::UnsafeFile),
    };
    for p in parts {
        if p.is_empty() || p == "." || p == ".." {
            return Err(StoreError::UnsafeFile);
        }
        path.push(p);
    }
    Ok(path)
}

pub(crate) fn open_source(path: &SecretBytes) -> Result<crate::fs::ArchiveFile, StoreError> {
    let text = std::str::from_utf8(path.expose_secret()).map_err(|_| StoreError::UnsafeFile)?;
    let path = to_windows(text)?;
    let mut at = PathBuf::new();
    let mut components = path.components().peekable();
    while let Some(c) = components.next() {
        at.push(c.as_os_str());
        if components.peek().is_none() {
            return crate::fs::open_opaque(&at, false);
        }
        match c {
            // The prefix alone (`C:`) is not a directory; the root (`C:\`) is.
            Component::Prefix(_) => continue,
            Component::RootDir | Component::Normal(_) => {}
            _ => return Err(StoreError::UnsafeFile),
        }
        let dir = qv_win::fs::open_nofollow(&at, qv_win::fs::Access::Inspect)
            .map_err(crate::error::os_err)?;
        if qv_win::fs::kind_of(&dir).map_err(crate::error::os_err)? != Kind::Dir {
            return Err(StoreError::UnsafeFile);
        }
    }
    Err(StoreError::UnsafeFile)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(p: &str) -> String {
        String::from_utf8(normalize(Path::new(p)).unwrap().expose_secret().to_vec()).unwrap()
    }

    #[test]
    fn windows_receipt_names_use_the_stored_form() {
        assert_eq!(name(r"c:\a\..\b\in.qvsnap"), "/C:/b/in.qvsnap");
        assert_eq!(name(r"\\?\C:\b\in.qvsnap"), "/C:/b/in.qvsnap");
        assert_eq!(
            name(r"\\srv\share\x\in.qvsnap"),
            "/UNC/srv/share/x/in.qvsnap"
        );
        assert_eq!(
            name(r"\\?\UNC\srv\share\in.qvsnap"),
            "/UNC/srv/share/in.qvsnap"
        );
        assert!(normalize(Path::new(r"\\.\pipe\x")).is_err());
        assert!(normalize(Path::new(r"C:\")).is_err());
        assert_eq!(
            to_windows("/C:/b/in.qvsnap").unwrap(),
            PathBuf::from(r"C:\b\in.qvsnap")
        );
        assert_eq!(
            to_windows("/UNC/srv/share/x").unwrap(),
            PathBuf::from(r"\\srv\share\x")
        );
        for bad in ["C:/x", "/C/x", "/C:/../x", "/UNC/srv", "/C://x"] {
            assert!(to_windows(bad).is_err(), "{bad}");
        }
    }
}
