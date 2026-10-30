// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded lexical receipt names and descriptor-pinned hostile input traversal.

use crate::{MAX_RECEIPT_PATH_BYTES, StoreError};
use qv_crypto::SecretBytes;
use rustix::fd::OwnedFd;
use rustix::fs::{Mode, OFlags, open, openat};
use std::{
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::Path,
};

pub(crate) fn normalize(path: &Path) -> Result<SecretBytes, StoreError> {
    let raw = path.as_os_str().as_bytes();
    if raw.len() > MAX_RECEIPT_PATH_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    if raw.is_empty() || raw.contains(&0) {
        return Err(StoreError::UnsafeFile);
    }
    let mut cwd = if raw[0] != b'/' {
        // getcwd is an OS intermediate. Transfer its bytes promptly and wipe
        // application-owned storage; libc/kernel scratch copies are best effort.
        std::env::current_dir()
            .map_err(|_| StoreError::Io)?
            .into_os_string()
            .into_vec()
    } else {
        Vec::new()
    };
    let cwd = SecretBytes::take_from(&mut cwd);
    if cwd.len() > MAX_RECEIPT_PATH_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    let mut output = SecretBytes::zeroed(MAX_RECEIPT_PATH_BYTES);
    output.expose_secret_mut()[0] = b'/';
    let mut len = 1;
    let mut starts = Vec::new();
    for part in cwd
        .expose_secret()
        .split(|&b| b == b'/')
        .chain(raw.split(|&b| b == b'/'))
    {
        if part.is_empty() || part == b"." {
            continue;
        }
        if part == b".." {
            if let Some(start) = starts.pop() {
                len = start;
            }
            continue;
        }
        let start = len;
        let sep = usize::from(len > 1);
        let end = len + sep + part.len();
        if end > MAX_RECEIPT_PATH_BYTES {
            return Err(StoreError::LimitExceeded);
        }
        if sep != 0 {
            output.expose_secret_mut()[len] = b'/';
        }
        output.expose_secret_mut()[len + sep..end].copy_from_slice(part);
        len = end;
        starts.push(start);
    }
    if len == 1 {
        return Err(StoreError::UnsafeFile);
    }
    Ok(SecretBytes::take_from(
        &mut output.expose_secret_mut()[..len],
    ))
}

pub(crate) fn open_source(path: &SecretBytes) -> Result<OwnedFd, StoreError> {
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut directory =
        open("/", flags | OFlags::DIRECTORY, Mode::empty()).map_err(crate::error::errno_err)?;
    let mut parts = path.expose_secret()[1..].split(|&b| b == b'/').peekable();
    while let Some(part) = parts.next() {
        let leaf = parts.peek().is_none();
        let fd = openat(
            &directory,
            std::ffi::OsStr::from_bytes(part),
            flags
                | if leaf {
                    OFlags::NONBLOCK
                } else {
                    OFlags::DIRECTORY
                },
            Mode::empty(),
        )
        .map_err(crate::error::errno_err)?;
        if leaf {
            return Ok(fd);
        }
        directory = fd;
    }
    Err(StoreError::UnsafeFile)
}
