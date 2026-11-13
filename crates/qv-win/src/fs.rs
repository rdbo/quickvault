// SPDX-License-Identifier: AGPL-3.0-or-later

//! Win32 file primitives for the store and platform layers (plan 0052):
//! no-follow opens, kind and identity, byte-range locks, write-through
//! renames, private creation with a protected DACL and descriptor reads.
//! Opening existing objects uses `std` (no `unsafe`); the rest is the
//! smallest FFI that `std` does not offer.
#![allow(unsafe_code)] // Win32 FFI boundary; every block has a SAFETY note.

use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::sync::OnceLock;

use windows_sys::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, ERROR_LOCK_VIOLATION, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetLengthSid, GetTokenInformation, IsValidSid,
    OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_DISPOSITION_FLAG_DELETE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO, FILE_DISPOSITION_INFO_EX,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, FileDispositionInfo,
    FileDispositionInfoEx, FileIdInfo, GetDriveTypeW, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFileType, GetVolumePathNameW, LOCKFILE_EXCLUSIVE_LOCK,
    LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    MoveFileExW, READ_CONTROL, SetFileInformationByHandle, UnlockFileEx, WRITE_DAC,
};
use windows_sys::Win32::System::IO::OVERLAPPED;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::security::{self, Rule, Sid};

/// Share read, write and delete, like POSIX: other handles never block a
/// rename or removal that our own code performs.
pub const SHARE_ALL: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

/// The process lock's byte, far beyond any SQLite data or lock byte.
/// Windows byte-range locks are mandatory, so it must never cover data.
pub const LOCK_OFFSET: u64 = 0x7FFF_FFFF_FFFF_FF00;

/// A path as a NUL-terminated UTF-16 string. Interior NULs are refused.
pub fn wide(path: &OsStr) -> io::Result<Vec<u16>> {
    let mut w: Vec<u16> = path.encode_wide().collect();
    if w.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    w.push(0);
    Ok(w)
}

/// What a handle names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular disk file.
    File,
    /// A directory.
    Dir,
    /// A symlink, junction or other reparse point (never followed).
    Reparse,
    /// A device, pipe or anything else.
    Other,
}

/// Volume serial and 128-bit file ID: stable identity while the file exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FileId {
    /// Volume serial number.
    pub volume: u64,
    /// File ID within the volume.
    pub id: u128,
}

/// Rights for [`open_nofollow`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Metadata and security only.
    Inspect,
    /// Read data.
    Read,
    /// Read and write data.
    ReadWrite,
}

/// Opens an existing file or directory without following a reparse point at
/// the final component: a symlink is opened as itself and reports
/// [`Kind::Reparse`]. Never requests DELETE access, so SQLite's own handles
/// (which do not share delete) can still be opened beside it.
pub fn open_nofollow(path: &Path, access: Access) -> io::Result<File> {
    open(path, access, false)
}

/// [`open_nofollow`], or with `follow` resolving reparse points along the
/// whole path (for parents, where owner-controlled aliases are allowed).
pub fn open(path: &Path, access: Access, follow: bool) -> io::Result<File> {
    let rights = READ_CONTROL
        | FILE_READ_ATTRIBUTES
        | match access {
            Access::Inspect => 0,
            Access::Read => GENERIC_READ,
            Access::ReadWrite => GENERIC_READ | GENERIC_WRITE,
        };
    OpenOptions::new()
        .access_mode(rights)
        .share_mode(SHARE_ALL)
        .custom_flags(
            FILE_FLAG_BACKUP_SEMANTICS
                | if follow {
                    0
                } else {
                    FILE_FLAG_OPEN_REPARSE_POINT
                },
        )
        .open(path)
}

/// The kind of an open handle.
pub fn kind_of(file: &File) -> io::Result<Kind> {
    let attrs = file.metadata()?.file_attributes();
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Ok(Kind::Reparse);
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Ok(Kind::Dir);
    }
    // SAFETY: the handle is valid for the borrow of `file`.
    let ty = unsafe { GetFileType(file.as_raw_handle()) };
    Ok(if ty == FILE_TYPE_DISK {
        Kind::File
    } else {
        Kind::Other
    })
}

/// The kind of `path` itself (not following a reparse point).
pub fn kind_nofollow(path: &Path) -> io::Result<Kind> {
    kind_of(&open_nofollow(path, Access::Inspect)?)
}

/// The file's identity: the volume serial number with the 128-bit
/// `FileIdInfo` ID, or the 64-bit index where a filesystem lacks it (FAT).
/// The serial always comes from `GetFileInformationByHandle`, so every
/// handle of one file reports the same value (Wine fills `FileIdInfo`'s
/// serial inconsistently).
pub fn file_id(file: &File) -> io::Result<FileId> {
    let h = file.as_raw_handle();
    let mut by = BY_HANDLE_FILE_INFORMATION {
        dwFileAttributes: 0,
        ftCreationTime: Default::default(),
        ftLastAccessTime: Default::default(),
        ftLastWriteTime: Default::default(),
        dwVolumeSerialNumber: 0,
        nFileSizeHigh: 0,
        nFileSizeLow: 0,
        nNumberOfLinks: 0,
        nFileIndexHigh: 0,
        nFileIndexLow: 0,
    };
    // SAFETY: `by` is a writable BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(h, &raw mut by) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let volume = u64::from(by.dwVolumeSerialNumber);
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `info` is a writable FILE_ID_INFO of the size passed.
    let ok = unsafe {
        GetFileInformationByHandleEx(
            h,
            FileIdInfo,
            (&raw mut info).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    };
    let id = if ok != 0 {
        u128::from_le_bytes(info.FileId.Identifier)
    } else {
        (u128::from(by.nFileIndexHigh) << 32) | u128::from(by.nFileIndexLow)
    };
    Ok(FileId { volume, id })
}

fn lock_overlapped() -> OVERLAPPED {
    let mut o = OVERLAPPED::default();
    o.Anonymous.Anonymous.Offset = LOCK_OFFSET as u32;
    o.Anonymous.Anonymous.OffsetHigh = (LOCK_OFFSET >> 32) as u32;
    o
}

/// Takes the non-blocking process lock byte (exclusive or shared).
/// `Ok(false)` when another handle holds a conflicting lock.
pub fn try_lock(file: &File, exclusive: bool) -> io::Result<bool> {
    let mut o = lock_overlapped();
    let flags = LOCKFILE_FAIL_IMMEDIATELY
        | if exclusive {
            LOCKFILE_EXCLUSIVE_LOCK
        } else {
            0
        };
    // SAFETY: valid handle; `o` outlives the synchronous call (the handle
    // is not overlapped, so the call completes before returning).
    if unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &raw mut o) } != 0 {
        return Ok(true);
    }
    let e = io::Error::last_os_error();
    if e.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
        Ok(false)
    } else {
        Err(e)
    }
}

/// Releases the process lock byte (closing the handle also releases it).
pub fn unlock(file: &File) -> io::Result<()> {
    let mut o = lock_overlapped();
    // SAFETY: valid handle; synchronous call with a live OVERLAPPED.
    if unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &raw mut o) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn move_file(from: &Path, to: &Path, flags: u32) -> io::Result<()> {
    let (f, t) = (wide(from.as_os_str())?, wide(to.as_os_str())?);
    // SAFETY: both strings are NUL-terminated and live for the call.
    if unsafe { MoveFileExW(f.as_ptr(), t.as_ptr(), flags) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Renames without ever replacing an existing `to`; returns only after the
/// rename is on disk (`MOVEFILE_WRITE_THROUGH`).
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    move_file(from, to, MOVEFILE_WRITE_THROUGH)
}

/// Atomically replaces `to` (anchor metadata only), write-through.
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()> {
    move_file(from, to, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)
}

/// Removes the file or empty directory at `path` itself (never through a
/// reparse point), with POSIX semantics where the filesystem supports them:
/// the name disappears at once even while other handles (which share
/// delete) stay open, as `unlink` does. Elsewhere the classic
/// delete-on-close applies and the name lasts until the last handle closes.
pub fn remove_nofollow(path: &Path) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(DELETE | FILE_READ_ATTRIBUTES)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let h = file.as_raw_handle();
    let ex = FILE_DISPOSITION_INFO_EX {
        Flags: FILE_DISPOSITION_FLAG_DELETE | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
    };
    // SAFETY: valid handle with DELETE access; `ex` lives for the call.
    let posix = unsafe {
        SetFileInformationByHandle(
            h,
            FileDispositionInfoEx,
            (&raw const ex).cast(),
            size_of::<FILE_DISPOSITION_INFO_EX>() as u32,
        )
    };
    if posix != 0 {
        return Ok(());
    }
    let classic = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: as above, with a FILE_DISPOSITION_INFO.
    if unsafe {
        SetFileInformationByHandle(
            h,
            FileDispositionInfo,
            (&raw const classic).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The current process user's SID (cached).
pub fn current_user() -> io::Result<Sid> {
    static USER: OnceLock<Option<Sid>> = OnceLock::new();
    USER.get_or_init(|| query_user().ok())
        .clone()
        .ok_or_else(|| io::Error::other("token user unavailable"))
}

fn query_user() -> io::Result<Sid> {
    let mut token: HANDLE = std::ptr::null_mut();
    // SAFETY: returns a pseudo-handle that needs no closing.
    let process = unsafe { GetCurrentProcess() };
    // SAFETY: `token` is writable and receives a new handle.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a new handle that we now own.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut len = 0u32;
    // SAFETY: a size query with a null buffer of length 0.
    let probe = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &raw mut len,
        )
    };
    let err = io::Error::last_os_error();
    if probe != 0 || err.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || len > 4096 {
        return Err(io::Error::other("token size"));
    }
    // u64 words keep TOKEN_USER (pointer-aligned) correctly aligned.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: `buf` is writable for at least `len` bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            len,
            &raw mut len,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call filled a TOKEN_USER at the start of the aligned buffer.
    let sid: PSID = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    // SAFETY: `sid` points into `buf`, which is still alive.
    unsafe { sid_bytes(sid) }.ok_or_else(|| io::Error::other("token SID"))
}

/// Copies a SID that Win32 returned.
///
/// # Safety
/// `sid` must be null or point to a SID that stays valid for the call.
unsafe fn sid_bytes(sid: PSID) -> Option<Sid> {
    // SAFETY: caller contract; IsValidSid only reads the SID.
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return None;
    }
    // SAFETY: the SID is valid, so GetLengthSid reads its header.
    let len = unsafe { GetLengthSid(sid) } as usize;
    // SAFETY: a valid SID is `len` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), len) };
    Sid::parse(bytes)
}

/// Owner and DACL bytes of an open handle (needs READ_CONTROL).
/// The DACL is `None` for a NULL DACL.
pub fn security_of(file: &File) -> io::Result<(Sid, Option<Vec<u8>>)> {
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: valid handle; out-pointers are writable; the descriptor is
    // freed with LocalFree below.
    let err = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            std::ptr::null_mut(),
            &raw mut dacl,
            std::ptr::null_mut(),
            &raw mut sd,
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    // SAFETY: `owner` points into `sd`, alive until LocalFree.
    let owner = unsafe { sid_bytes(owner) };
    let dacl = if dacl.is_null() {
        None
    } else {
        // SAFETY: `dacl` points to an ACL header inside `sd`.
        let size = usize::from(unsafe { (*dacl).AclSize });
        // SAFETY: an ACL is `AclSize` readable bytes inside `sd`.
        Some(unsafe { std::slice::from_raw_parts(dacl.cast::<u8>(), size) }.to_vec())
    };
    // SAFETY: `sd` was allocated by GetSecurityInfo; no pointer into it is
    // used after this.
    unsafe { LocalFree(sd) };
    Ok((owner.ok_or_else(|| io::Error::other("owner SID"))?, dacl))
}

/// Whether the object behind `file` meets `rule` for the current user.
pub fn meets(file: &File, rule: Rule) -> io::Result<bool> {
    let (owner, dacl) = security_of(file)?;
    Ok(security::meets(
        &owner,
        dacl.as_deref(),
        &current_user()?,
        rule,
    ))
}

fn attributes(sd: &mut [u32]) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_mut_ptr().cast(),
        bInheritHandle: 0,
    }
}

/// Creates a new file (never an existing one or through a reparse point)
/// owned by the current user with a protected owner-only DACL, opened for
/// read/write with [`SHARE_ALL`]. The descriptor applies atomically at
/// creation, so no other principal can open it first.
pub fn create_private_file(path: &Path) -> io::Result<File> {
    let name = wide(path.as_os_str())?;
    let mut sd = security::private_descriptor(&current_user()?, false);
    let sa = attributes(&mut sd);
    // SAFETY: NUL-terminated name; `sa` and the descriptor it points to
    // live for the call.
    let h = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
            SHARE_ALL,
            &raw const sa,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a new handle that we now own.
    Ok(File::from(unsafe { OwnedHandle::from_raw_handle(h) }))
}

/// Creates a directory with a protected owner-only DACL that its children
/// inherit. Fails if `path` exists.
pub fn create_private_dir(path: &Path) -> io::Result<()> {
    let name = wide(path.as_os_str())?;
    let mut sd = security::private_descriptor(&current_user()?, true);
    let sa = attributes(&mut sd);
    // SAFETY: NUL-terminated name; `sa` and its descriptor live for the call.
    if unsafe { CreateDirectoryW(name.as_ptr(), &raw const sa) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Replaces the DACL of an existing object with a protected one granting
/// the user `user_mask` (inherited by children of a directory) plus
/// `grants`. For test fixtures that model shared or read-only folders;
/// production code refuses unsafe permissions instead of repairing them
/// (plan 0008). The owner keeps its implicit right to change the DACL.
pub fn set_dacl(path: &Path, user_mask: u32, grants: &[security::Grant<'_>]) -> io::Result<()> {
    let file = OpenOptions::new()
        .access_mode(READ_CONTROL | WRITE_DAC)
        .share_mode(SHARE_ALL)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    let dir = kind_of(&file)? == Kind::Dir;
    let user = current_user()?;
    let mut all = vec![security::Grant {
        sid: &user,
        mask: user_mask,
        inherit: dir,
    }];
    all.extend_from_slice(grants);
    let sd = security::descriptor(&user, &all);
    let bytes: Vec<u8> = sd.iter().flat_map(|w| w.to_le_bytes()).collect();
    let (_, dacl) = security::split_descriptor(&bytes).ok_or(io::ErrorKind::InvalidData)?;
    let mut dacl: Vec<u32> = dacl
        .ok_or(io::ErrorKind::InvalidData)?
        .chunks(4)
        .map(|w| u32::from_le_bytes(w.try_into().unwrap_or_default()))
        .collect();
    // SAFETY: valid handle with WRITE_DAC; `dacl` is an aligned ACL that
    // lives for the call.
    let err = unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            dacl.as_mut_ptr().cast::<ACL>(),
            std::ptr::null(),
        )
    };
    if err != 0 {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    Ok(())
}

/// The ACL counterpart of `chmod mode` for test fixtures written against
/// Unix modes: group/other write bits grant Everyone modify (inherited by a
/// directory's children), read/search bits grant Everyone read (never
/// inherited, like a listable folder whose new files stay private), and
/// without the owner write bit the user keeps only read and execute. An
/// object that is already owner-only and writable is left alone for a
/// private writable mode (Wine maps a rewritten owner-only DACL to a shared
/// mode); a read-only one (`0o500`) is rewritten, restoring write access.
pub fn chmod_like(path: &Path, mode: u32) -> io::Result<()> {
    if mode & 0o277 == 0o200
        && meets(&open_nofollow(path, Access::Inspect)?, Rule::OwnerOnly)?
        && open_nofollow(path, Access::ReadWrite).is_ok()
    {
        return Ok(());
    }
    let everyone = Sid::everyone();
    let dir = path.is_dir();
    let user = if mode & 0o200 != 0 {
        security::FILE_ALL_ACCESS
    } else {
        0x0012_00A9
    };
    let grant = if mode & 0o022 != 0 {
        Some(security::Grant {
            sid: &everyone,
            mask: 0x0013_01BF,
            inherit: dir,
        })
    } else if mode & 0o055 != 0 {
        Some(security::Grant {
            sid: &everyone,
            mask: 0x0012_00A9,
            inherit: false,
        })
    } else {
        None
    };
    set_dacl(path, user, grant.as_slice())
}

/// Where a path's volume lives, for 0004 §1.1 location warnings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drive {
    /// A local fixed disk (or unknown local type).
    Local,
    /// A network share.
    Remote,
    /// Removable or optical media.
    Removable,
    /// The volume could not be determined.
    Unknown,
}

// GetDriveTypeW results (windows-sys puts them in WindowsProgramming).
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;

/// The drive type of the volume containing `path`.
pub fn drive_type(path: &Path) -> Drive {
    let Ok(name) = wide(path.as_os_str()) else {
        return Drive::Unknown;
    };
    let mut root = [0u16; 1024];
    // SAFETY: NUL-terminated input; `root` is writable for its length.
    if unsafe { GetVolumePathNameW(name.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Drive::Unknown;
    }
    // SAFETY: GetVolumePathNameW wrote a NUL-terminated string into `root`.
    match unsafe { GetDriveTypeW(root.as_ptr()) } {
        DRIVE_REMOTE => Drive::Remote,
        DRIVE_REMOVABLE | DRIVE_CDROM => Drive::Removable,
        0 | 1 => Drive::Unknown,
        _ => Drive::Local,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
            let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos();
            let p = std::env::temp_dir().join(format!("qv-win-{}-{n}-{nanos}", std::process::id()));
            create_private_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn private_file_meets_rules_and_round_trips() {
        let d = Dir::new();
        let dir = open_nofollow(&d.0, Access::Inspect).unwrap();
        assert_eq!(kind_of(&dir).unwrap(), Kind::Dir);
        assert!(meets(&dir, Rule::VaultParent).unwrap());
        let p = d.0.join("v.qvault");
        let mut f = create_private_file(&p).unwrap();
        f.write_all(b"abc").unwrap();
        f.sync_all().unwrap();
        assert_eq!(kind_of(&f).unwrap(), Kind::File);
        assert!(meets(&f, Rule::OwnerOnly).unwrap());
        assert!(create_private_file(&p).is_err(), "CREATE_NEW never reuses");
        let mut again = open_nofollow(&p, Access::Read).unwrap();
        let mut s = String::new();
        again.read_to_string(&mut s).unwrap();
        assert_eq!(s, "abc");
        assert_eq!(file_id(&f).unwrap(), file_id(&again).unwrap());
    }

    #[test]
    fn foreign_grants_are_detected() {
        let d = Dir::new();
        let p = d.0.join("f");
        drop(create_private_file(&p).unwrap());
        let everyone = Sid::everyone();
        let grant = |mask| security::Grant {
            sid: &everyone,
            mask,
            inherit: false,
        };
        set_dacl(&p, security::FILE_ALL_ACCESS, &[grant(0x0012_0089)]).unwrap();
        let f = open_nofollow(&p, Access::Inspect).unwrap();
        assert!(!meets(&f, Rule::OwnerOnly).unwrap());
        assert!(meets(&f, Rule::NoForeignWrite).unwrap());
        set_dacl(&d.0, security::FILE_ALL_ACCESS, &[grant(0x0013_01BF)]).unwrap();
        let dir = open_nofollow(&d.0, Access::Inspect).unwrap();
        assert!(!meets(&dir, Rule::NoForeignWrite).unwrap());
        set_dacl(&d.0, security::FILE_ALL_ACCESS, &[]).unwrap();
    }

    #[test]
    fn chmod_like_restores_write_after_read_only() {
        let d = Dir::new();
        chmod_like(&d.0, 0o500).unwrap();
        // Wine does not enforce a read-only DACL; real Windows does.
        let denied = std::fs::write(d.0.join("probe"), b"").is_err();
        chmod_like(&d.0, 0o700).unwrap();
        std::fs::write(d.0.join("probe"), b"").unwrap();
        let dir = open_nofollow(&d.0, Access::Inspect).unwrap();
        assert!(meets(&dir, Rule::OwnerOnly).unwrap(), "denied={denied}");
    }

    #[test]
    fn lock_byte_excludes_other_handles() {
        let d = Dir::new();
        let p = d.0.join("l");
        let a = create_private_file(&p).unwrap();
        let b = open_nofollow(&p, Access::ReadWrite).unwrap();
        assert!(try_lock(&a, true).unwrap());
        assert!(!try_lock(&b, true).unwrap());
        assert!(!try_lock(&b, false).unwrap());
        unlock(&a).unwrap();
        assert!(try_lock(&b, false).unwrap());
        assert!(try_lock(&a, false).unwrap(), "shared locks coexist");
        assert!(!try_lock(&a, true).unwrap());
        // The lock byte never blocks data I/O.
        let mut b2 = &b;
        b2.write_all(b"data").unwrap();
    }

    #[test]
    fn renames_never_replace_unless_asked() {
        let d = Dir::new();
        let (a, b) = (d.0.join("a"), d.0.join("b"));
        std::fs::write(&a, b"1").unwrap();
        std::fs::write(&b, b"2").unwrap();
        assert!(rename_noreplace(&a, &b).is_err());
        assert_eq!(std::fs::read(&b).unwrap(), b"2");
        rename_replace(&a, &b).unwrap();
        assert_eq!(std::fs::read(&b).unwrap(), b"1");
        let c = d.0.join("c");
        rename_noreplace(&b, &c).unwrap();
        assert!(!b.exists() && c.exists());
        // Renaming or removing a file we hold open works because we share
        // delete; the name goes at once.
        let held = open_nofollow(&c, Access::ReadWrite).unwrap();
        rename_noreplace(&c, &b).unwrap();
        remove_nofollow(&b).unwrap();
        assert!(std::fs::read_dir(&d.0).unwrap().next().is_none());
        drop(held);
        assert!(remove_nofollow(&b).is_err());
    }

    #[test]
    fn reparse_points_are_not_followed() {
        let d = Dir::new();
        let target = d.0.join("t");
        std::fs::write(&target, b"x").unwrap();
        let link = d.0.join("link");
        match std::os::windows::fs::symlink_file(&target, &link) {
            Ok(()) => assert_eq!(kind_nofollow(&link).unwrap(), Kind::Reparse),
            // Creating symlinks needs Developer Mode or elevation; CI has it.
            Err(e) if e.raw_os_error() == Some(1314) && std::env::var_os("CI").is_none() => {
                eprintln!("skipped: no symlink privilege outside CI");
            }
            Err(e) => panic!("symlink: {e}"),
        }
        assert_eq!(kind_nofollow(&target).unwrap(), Kind::File);
        assert!(kind_nofollow(&d.0.join("missing")).is_err());
    }

    #[test]
    fn names_with_nul_are_refused() {
        assert!(wide(OsStr::new("a\0b")).is_err());
        assert_eq!(wide(OsStr::new("ab")).unwrap(), [97, 98, 0]);
    }

    #[test]
    fn temp_dir_is_local() {
        assert_ne!(drive_type(&std::env::temp_dir()), Drive::Remote);
    }
}
