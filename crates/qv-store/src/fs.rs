// SPDX-License-Identifier: AGPL-3.0-or-later

//! File safety for the vault file (spec 0004 §1.1, §1.3; 0008 §5).
//!
//! - The vault file must be a regular file owned by the effective UID with
//!   no group or other permission bits; a symlink at the path is refused
//!   (`O_NOFOLLOW`). Permissions are refused, not repaired (plan 0008).
//! - Its parent directory must be owned by the effective UID or root and
//!   writable by no one else (0004 §1.1, "private 0700 directory"; read and
//!   search bits are allowed, so `~/Documents` at 0755 works). There is no
//!   sticky-bit exception: whoever can create entries next to the vault can
//!   plant SQLite sidecar files (below). The one group-write exception is
//!   Android, whose per-app `files` directory is `0771` with the app's own
//!   UID and GID. Only the parent is checked: it is what lets another user
//!   replace the path or plant files next to it.
//! - SQLite's sidecar files are checked before SQLite opens the vault
//!   (plan 0008 review finding 1). SQLite rolls back a hot `-journal` and
//!   replays a `-wal` before any query runs, and neither is bound to the
//!   vault. A `-journal` must be a private file like the vault itself (our
//!   own journal after a crash must still roll back); a `-wal` or `-shm` is
//!   never ours (`journal_mode=DELETE`) and is refused whatever it is.
//! - The process lock is `flock(LOCK_EX | LOCK_NB)` on the vault file's own
//!   descriptor, which also gives the file identity (`st_dev`, `st_ino`).
//!   **That descriptor must stay open until the SQLite connection is
//!   closed**: closing any descriptor of a file drops the process's POSIX
//!   locks on it, SQLite's included (sqlite.org/howtocorrupt.html §2.2). On
//!   Linux, `flock` and SQLite's `fcntl` locks are independent.
//! - New vaults are built under a temporary name created with `O_EXCL` and
//!   moved into place with `RENAME_NOREPLACE`, so a path is never
//!   overwritten and a crash never leaves a partial vault at it.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};

use rustix::fs::{
    AtFlags, CWD, FileType, FlockOperation, Mode, OFlags, RenameFlags, Stat, flock, fstat, fsync,
    lstat, open, openat, renameat_with, stat, statat,
};
use rustix::io::Errno;
#[cfg(target_os = "android")]
use rustix::process::getegid;
use rustix::process::geteuid;

use crate::error::{StoreError, errno_err};
use crate::limits::MAX_DB_BYTES;

/// Group and other permission bits.
const GROUP_OTHER: u32 = 0o077;
const OTHER_WRITE: u32 = 0o002;
const GROUP_WRITE: u32 = 0o020;

type Identity = (u64, u64);
struct Registered {
    file: Arc<File>,
    token: Weak<LeaseToken>,
    opaque: bool,
}
static FILES: LazyLock<Mutex<HashMap<Identity, Registered>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn identity(st: &Stat) -> Identity {
    (st.st_dev, st.st_ino)
}

struct LeaseToken(Identity);
impl Drop for LeaseToken {
    fn drop(&mut self) {
        let mut files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
        // Close under the mutex, before another SQLite-capable acquisition.
        drop(files.remove(&self.0));
    }
}

#[derive(Clone)]
struct FileHandle {
    // Field order matters: the last token closes the registry's descriptor
    // under its mutex after all handles have released their own file Arc.
    file: Arc<File>,
    _token: Arc<LeaseToken>,
}

fn register(
    files: &mut HashMap<Identity, Registered>,
    fd: OwnedFd,
    st: &Stat,
    opaque: bool,
) -> FileHandle {
    let file = Arc::new(File::from(fd));
    let token = Arc::new(LeaseToken(identity(st)));
    files.insert(
        identity(st),
        Registered {
            file: file.clone(),
            token: Arc::downgrade(&token),
            opaque,
        },
    );
    FileHandle {
        file,
        _token: token,
    }
}

/// An opaque encrypted archive/journal descriptor with a lifetime lease and
/// an independent cursor. Positioned I/O permits readers to share a producer's
/// descriptor without opening/closing an extra fd or disturbing its cursor.
pub(crate) struct ArchiveFile {
    handle: FileHandle,
    offset: u64,
}
impl std::ops::Deref for ArchiveFile {
    type Target = File;
    fn deref(&self) -> &File {
        &self.handle.file
    }
}
impl AsFd for ArchiveFile {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.handle.file.as_fd()
    }
}
impl ArchiveFile {
    pub(crate) fn same_as_path(&self, path: &Path) -> Result<(), StoreError> {
        let now = lstat(path).map_err(errno_err)?;
        let own = fstat(self.as_fd()).map_err(errno_err)?;
        if !is_owner_only(&now) || identity(&now) != identity(&own) {
            return Err(StoreError::Replaced);
        }
        Ok(())
    }
}
impl Read for ArchiveFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.handle.file.read_at(buf, self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
}
impl Write for ArchiveFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.handle.file.write_at(buf, self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Seek for ArchiveFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let next = match pos {
            SeekFrom::Start(n) => Some(n),
            SeekFrom::Current(n) => self.offset.checked_add_signed(n),
            SeekFrom::End(n) => self.metadata()?.len().checked_add_signed(n),
        }
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        self.offset = next;
        Ok(next)
    }
}

/// Short cooperative directory lock: never retained during file production.
pub(crate) struct DirectoryLock(OwnedFd);
pub(crate) fn lock_dir(dir: &Path) -> Result<DirectoryLock, StoreError> {
    let fd = open(
        dir,
        // Preserve the existing parent policy: owner-controlled directory
        // aliases are allowed. Snapshot/anchor roots separately reject symlinks.
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno_err)?;
    flock(&fd, FlockOperation::LockExclusive).map_err(errno_err)?;
    Ok(DirectoryLock(fd))
}
impl Drop for DirectoryLock {
    fn drop(&mut self) {
        let _ = flock(&self.0, FlockOperation::Unlock);
    }
}

/// The vault file's descriptor: holds the process lock and the identity.
pub(crate) struct LockedFile {
    handle: FileHandle,
    identity: Stat,
}

impl LockedFile {
    /// The descriptor (for `fstatfs`, `fsync`).
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.handle.file.as_fd()
    }

    /// [`StoreError::Replaced`] unless `path` still names this file and is
    /// not a symlink (0004 §1.3).
    pub(crate) fn same_as_path(&self, path: &Path) -> Result<(), StoreError> {
        let now = lstat(path).map_err(|_| StoreError::Replaced)?;
        if FileType::from_raw_mode(now.st_mode) != FileType::RegularFile
            || now.st_dev != self.identity.st_dev
            || now.st_ino != self.identity.st_ino
        {
            return Err(StoreError::Replaced);
        }
        Ok(())
    }

    /// Flushes the file to stable storage.
    pub(crate) fn sync(&self) -> Result<(), StoreError> {
        fsync(&*self.handle.file).map_err(errno_err)
    }

    /// Appends `bytes` at the file's current position (staged imports).
    pub(crate) fn write_all(&self, mut bytes: &[u8]) -> Result<(), StoreError> {
        while !bytes.is_empty() {
            match rustix::io::write(self.fd(), bytes) {
                Ok(0) => return Err(StoreError::Io),
                Ok(n) => bytes = &bytes[n..],
                Err(Errno::INTR) => continue,
                Err(e) => return Err(errno_err(e)),
            }
        }
        Ok(())
    }

    fn lock(fd: OwnedFd, files: &mut HashMap<Identity, Registered>) -> Result<Self, StoreError> {
        flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|e| match e {
            Errno::WOULDBLOCK => StoreError::Locked,
            e => errno_err(e),
        })?;
        let identity = fstat(&fd).map_err(errno_err)?;
        let handle = register(files, fd, &identity, false);
        Ok(Self { handle, identity })
    }

    /// Reads the whole locked file from offset 0 with positioned reads
    /// (the descriptor and lock are kept). [`StoreError::Integrity`] if its
    /// size, checked by `fstat` before reading, or the bytes read exceed
    /// `max` (the rotation journal, plan 0023).
    pub(crate) fn read_bounded(&self, max: usize) -> Result<Vec<u8>, StoreError> {
        let st = fstat(self.fd()).map_err(errno_err)?;
        let len = usize::try_from(st.st_size).map_err(|_| StoreError::Integrity)?;
        if len > max {
            return Err(StoreError::Integrity);
        }
        // Used only for opaque rotation markers, never SQLite data. Do not
        // duplicate/close its descriptor: use positioned reads instead.
        let mut bytes = Vec::with_capacity(len);
        let mut chunk = [0; 4096];
        loop {
            let n = self
                .handle
                .file
                .read_at(
                    &mut chunk[..(max + 1 - bytes.len()).min(4096)],
                    bytes.len() as u64,
                )
                .map_err(crate::error::io_err)?;
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..n]);
            if bytes.len() > max {
                return Err(StoreError::Integrity);
            }
        }
        Ok(bytes)
    }

    /// Takes the descriptor out of the guard, for a temporary file that is
    /// written, re-read and published (archives, 0004 §6.5). Giving up the
    /// descriptor preserves its flock until the final reader/producer drops.
    /// This file must never subsequently host a SQLite connection.
    pub(crate) fn into_archive_file(self) -> ArchiveFile {
        FILES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(identity(&self.identity))
            .and_modify(|f| f.opaque = true);
        ArchiveFile {
            handle: self.handle,
            offset: 0,
        }
    }
}

/// The directory containing `path` (`.` for a bare file name).
pub(crate) fn parent_of(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Checks that the parent directory of `path` is private enough that no
/// other user can replace the path.
pub(crate) fn check_parent(path: &Path) -> Result<(), StoreError> {
    let dir = stat(parent_of(path)).map_err(errno_err)?;
    if FileType::from_raw_mode(dir.st_mode) != FileType::Directory {
        return Err(StoreError::UnsafeFile);
    }
    let owner_ok = dir.st_uid == geteuid().as_raw() || dir.st_uid == 0;
    let other_ok = dir.st_mode & OTHER_WRITE == 0;
    let group_ok = dir.st_mode & GROUP_WRITE == 0 || own_group_dir(&dir);
    if owner_ok && other_ok && group_ok {
        Ok(())
    } else {
        Err(StoreError::UnsafeFile)
    }
}

/// Android's per-app directory: owned by the app's UID with the app's own
/// GID, so group write adds no other writer.
#[cfg(target_os = "android")]
fn own_group_dir(dir: &Stat) -> bool {
    dir.st_uid == geteuid().as_raw() && dir.st_gid == getegid().as_raw()
}

/// Elsewhere a group can have other members: group write is refused.
#[cfg(not(target_os = "android"))]
fn own_group_dir(_: &Stat) -> bool {
    false
}

/// A regular file owned by `euid` with no group or other bits.
fn owner_only(kind: FileType, uid: u32, mode: u32, euid: u32) -> bool {
    kind == FileType::RegularFile && uid == euid && mode & GROUP_OTHER == 0
}

/// Whether `st` is a regular file owned by the effective UID with no group
/// or other bits (anchor files).
pub(crate) fn is_owner_only(st: &Stat) -> bool {
    owner_only(
        FileType::from_raw_mode(st.st_mode),
        st.st_uid,
        st.st_mode,
        geteuid().as_raw(),
    )
}

/// Checks a private directory of our own (the anchor directory): a real
/// directory, not a symlink, owned by the effective UID, writable by no one
/// else (group write only for Android's own-GID directory). Read and search
/// bits for others are allowed.
pub(crate) fn check_private_dir(dir: &Path) -> Result<(), StoreError> {
    let st = lstat(dir).map_err(errno_err)?;
    let ok = FileType::from_raw_mode(st.st_mode) == FileType::Directory
        && st.st_uid == geteuid().as_raw()
        && st.st_mode & OTHER_WRITE == 0
        && (st.st_mode & GROUP_WRITE == 0 || own_group_dir(&st));
    if ok {
        Ok(())
    } else {
        Err(StoreError::UnsafeFile)
    }
}

/// Checks a just-opened vault file's metadata.
fn check_file(st: &Stat) -> Result<(), StoreError> {
    if !owner_only(
        FileType::from_raw_mode(st.st_mode),
        st.st_uid,
        st.st_mode,
        geteuid().as_raw(),
    ) {
        return Err(StoreError::UnsafeFile);
    }
    match u64::try_from(st.st_size) {
        Ok(n) if n <= MAX_DB_BYTES => Ok(()),
        Ok(_) => Err(StoreError::LimitExceeded),
        Err(_) => Err(StoreError::Io),
    }
}

/// Opens and locks an existing vault file (plan 0008, *Open* steps 1–2).
pub(crate) fn open_existing(path: &Path) -> Result<LockedFile, StoreError> {
    let mut files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    let st = lstat(path).map_err(errno_err)?;
    if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
        return Err(StoreError::UnsafeFile);
    }
    check_parent(path)?;
    if files.contains_key(&identity(&st)) {
        return Err(StoreError::Locked);
    }
    let fd = open(
        path,
        OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| match e {
        // A FIFO or device swapped in after the lstat.
        Errno::NXIO | Errno::ISDIR => StoreError::UnsafeFile,
        e => errno_err(e),
    })?;
    check_file(&fstat(&fd).map_err(errno_err)?)?;
    LockedFile::lock(fd, &mut files)
}

/// Opens a private regular file read-only, for re-reading what was just
/// written before it is published (an archive temp file, 0004 §6.5).
/// [`StoreError::UnsafeFile`] for a symlink, a non-regular file or a file
/// that is not owner-only.
pub(crate) fn open_private_ro(path: &Path) -> Result<ArchiveFile, StoreError> {
    open_opaque_at(CWD, path, true)
}

pub(crate) fn open_opaque_at(
    dir: impl AsFd,
    path: &Path,
    private: bool,
) -> Result<ArchiveFile, StoreError> {
    let mut files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    let before = statat(&dir, path, AtFlags::SYMLINK_NOFOLLOW).map_err(errno_err)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || (private && !is_owner_only(&before))
    {
        return Err(StoreError::UnsafeFile);
    }
    if let Some(registered) = files.get(&identity(&before)) {
        if !registered.opaque {
            return Err(StoreError::Locked);
        }
        let token = registered.token.upgrade().ok_or(StoreError::Locked)?;
        return Ok(ArchiveFile {
            handle: FileHandle {
                file: registered.file.clone(),
                _token: token,
            },
            offset: 0,
        });
    }
    let fd = openat(
        &dir,
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|e| match e {
        Errno::LOOP | Errno::NXIO | Errno::ISDIR => StoreError::UnsafeFile,
        e => errno_err(e),
    })?;
    let st = fstat(&fd).map_err(errno_err)?;
    if FileType::from_raw_mode(st.st_mode) != FileType::RegularFile
        || (private && !is_owner_only(&st))
    {
        return Err(StoreError::UnsafeFile);
    }
    flock(&fd, FlockOperation::NonBlockingLockShared).map_err(|e| match e {
        Errno::WOULDBLOCK => StoreError::Locked,
        e => errno_err(e),
    })?;
    let handle = register(&mut files, fd, &st, true);
    Ok(ArchiveFile { handle, offset: 0 })
}

/// Atomic replacement is reserved for anchor metadata, never vault files.
pub(crate) fn replace_anchor(from: &Path, to: &Path) -> Result<(), StoreError> {
    let _files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    rustix::fs::rename(from, to).map_err(errno_err)
}

/// Checks SQLite's sidecar files next to `path` before SQLite opens it
/// (see the module docs): a `-journal` must be owner-only like the vault, a
/// `-wal` or `-shm` must not exist. [`StoreError::UnsafeFile`] otherwise.
/// Only the owner (or root) can create entries in a parent that passed
/// [`check_parent`], so the check cannot be raced by another user.
pub(crate) fn check_sidecars(path: &Path) -> Result<(), StoreError> {
    match lstat(with_suffix(path, "-journal")) {
        Ok(st) => {
            let kind = FileType::from_raw_mode(st.st_mode);
            if !owner_only(kind, st.st_uid, st.st_mode, geteuid().as_raw()) {
                return Err(StoreError::UnsafeFile);
            }
        }
        Err(Errno::NOENT) => {}
        Err(e) => return Err(errno_err(e)),
    }
    for suffix in ["-wal", "-shm"] {
        match lstat(with_suffix(path, suffix)) {
            Ok(_) => return Err(StoreError::UnsafeFile),
            Err(Errno::NOENT) => {}
            Err(e) => return Err(errno_err(e)),
        }
    }
    Ok(())
}

/// Creates and locks a new, empty temporary file next to `final_path`,
/// named `.<name>.tmp-<16 hex>`, with mode 0600. Never follows or reuses an
/// existing name.
pub(crate) fn create_temp(final_path: &Path) -> Result<(LockedFile, PathBuf), StoreError> {
    let name = final_path.file_name().ok_or(StoreError::Unsupported)?;
    let suffix = qv_crypto::random_array::<8>().map_err(|_| StoreError::Rng)?;
    let mut temp_name = OsString::from(".");
    temp_name.push(name);
    temp_name.push(".tmp-");
    for b in suffix {
        temp_name.push(format!("{b:02x}"));
    }
    let temp = parent_of(final_path).join(&temp_name);
    let _dir = lock_dir(parent_of(final_path))?;
    let mut files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    let fd = open(
        &temp,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(errno_err)?;
    let locked = match fstat(&fd).map_err(errno_err).and_then(|st| check_file(&st)) {
        Ok(()) => LockedFile::lock(fd, &mut files),
        Err(e) => Err(e),
    };
    match locked {
        Ok(l) => Ok((l, temp)),
        Err(e) => {
            remove_best_effort(&temp);
            Err(e)
        }
    }
}

/// Moves `from` to `to` without ever replacing an existing `to`.
pub(crate) fn rename_noreplace(from: &Path, to: &Path) -> Result<(), StoreError> {
    let _files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    renameat_with(CWD, from, CWD, to, RenameFlags::NOREPLACE).map_err(|e| match e {
        // The filesystem cannot rename without replacing; never fall back.
        Errno::INVAL | Errno::NOSYS => StoreError::Unsupported,
        e => errno_err(e),
    })
}

/// Flushes the directory entry changes of `dir` to stable storage.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    let fd = open(
        dir,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(errno_err)?;
    fsync(&fd).map_err(errno_err)
}

/// Flushes a file's data and metadata to stable storage.
pub(crate) fn sync_file(file: &File) -> Result<(), StoreError> {
    fsync(file).map_err(errno_err)
}

/// Creates `dir` and missing parents with mode 0700; existing ones are left
/// as they are (callers then check them).
pub(crate) fn create_private_dir_all(dir: &Path) -> Result<(), StoreError> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(crate::error::io_err(e)),
    }
}

/// What `path` itself is (`lstat`, never followed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    /// Nothing at the path.
    Missing,
    /// A regular file.
    Regular,
    /// Anything else (directory, symlink, FIFO, device).
    Other,
}

/// See [`Entry`].
pub(crate) fn entry(path: &Path) -> Result<Entry, StoreError> {
    match lstat(path) {
        Ok(st) if FileType::from_raw_mode(st.st_mode) == FileType::RegularFile => {
            Ok(Entry::Regular)
        }
        Ok(_) => Ok(Entry::Other),
        Err(Errno::NOENT) => Ok(Entry::Missing),
        Err(e) => Err(errno_err(e)),
    }
}

/// Removes the file at `path` (`unlink`; a symlink itself, never its target).
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    std::fs::remove_file(path)
}

/// Removes `path` if it exists; errors are ignored (cleanup after a
/// failure that is already being reported).
pub(crate) fn remove_best_effort(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// Removes temporary siblings that [`create_temp`] made for `final_path` and
/// a crash left behind: exactly `.<name>.tmp-<16 hex>` and its `-journal`.
/// Only regular files owned by this user are removed, checked with `lstat`
/// (never following a symlink). Every other name is left alone.
pub(crate) fn remove_stale_temps(final_path: &Path) -> Result<(), StoreError> {
    // Rotation recovery owns its replacements. Never reclaim this family on
    // the basis of an apparently unleased sibling alone.
    if crate::rotation_guard::is_reserved(final_path) {
        return Ok(());
    }
    let Some(name) = final_path.file_name().and_then(OsStr::to_str) else {
        return Err(StoreError::Unsupported);
    };
    let prefix = format!(".{name}.tmp-");
    let parent = parent_of(final_path);
    check_parent(final_path)?;
    let _dir = lock_dir(parent)?;
    let entries = match std::fs::read_dir(parent) {
        Ok(e) => e,
        Err(e) => return Err(crate::error::io_err(e)),
    };
    for entry in entries {
        let Ok(entry) = entry else { continue };
        let file_name = entry.file_name();
        let Some(n) = file_name.to_str() else {
            continue;
        };
        let Some(rest) = n.strip_prefix(&prefix) else {
            continue;
        };
        // A journal alone does not establish that no producer is live.
        let hex = rest;
        if hex.len() != 16 || !hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            continue;
        }
        let path = parent.join(n);
        let Ok(st) = rustix::fs::lstat(&path) else {
            continue;
        };
        if !is_owner_only(&st) {
            continue;
        }
        let lease = match open_existing(&path) {
            Ok(lease) => lease,
            Err(StoreError::Locked | StoreError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        lease.same_as_path(&path)?;
        let journal = with_suffix(&path, "-journal");
        match lstat(&journal) {
            Ok(st) if is_owner_only(&st) => {
                std::fs::remove_file(&journal).map_err(crate::error::io_err)?;
            }
            Ok(_) => continue,
            Err(Errno::NOENT) => {}
            Err(e) => return Err(errno_err(e)),
        }
        lease.same_as_path(&path)?;
        std::fs::remove_file(&path).map_err(crate::error::io_err)?;
    }
    sync_dir(parent)
}

/// `path` with `suffix` appended to its file name (e.g. `-journal`).
pub(crate) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_owned();
    s.push(OsStr::new(suffix));
    PathBuf::from(s)
}

#[cfg(test)]
pub(crate) mod test_dir {
    //! Private temporary directories for tests.

    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    /// A fresh 0700 directory under the system temp dir, removed on drop.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new() -> Self {
            let mut name = String::from("qv-store-test-");
            for b in qv_crypto::random_array::<8>().unwrap() {
                name.push_str(&format!("{b:02x}"));
            }
            let path = std::env::temp_dir().join(name);
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        pub(crate) fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// A subdirectory with `mode`.
        pub(crate) fn subdir(&self, name: &str, mode: u32) -> PathBuf {
            let p = self.join(name);
            std::fs::create_dir(&p).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
            p
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Writes `bytes` to a new file at `path` with `mode`.
    pub(crate) fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// `chmod mode` (Windows maps it to an ACL).
    pub(crate) fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    /// Whether `path` has exactly the permission bits `mode` (Windows: the
    /// matching owner-only or shared ACL).
    pub(crate) fn has_mode(path: &Path, mode: u32) -> bool {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
            == mode
    }

    /// Always false on Unix (see the Windows test helper).
    pub(crate) fn wine_lacks_acl_inheritance() -> bool {
        false
    }

    /// Always false on Unix (see the Windows test helper).
    pub(crate) fn wine_keeps_deleted_names() -> bool {
        false
    }

    /// Always false on Unix (see the Windows test helper).
    pub(crate) fn wine_ignores_read_only_dacl() -> bool {
        false
    }

    /// Creates a symlink; `false` only where the OS refuses the privilege
    /// outside CI (Windows), so callers skip that check.
    pub(crate) fn symlink(target: &Path, link: &Path) -> bool {
        std::os::unix::fs::symlink(target, link).unwrap();
        true
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::test_dir::{TestDir, write_file};
    use super::*;

    fn err<T>(r: Result<T, StoreError>) -> StoreError {
        match r {
            Ok(_) => panic!("unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn fs_open_rejects_missing_symlink_and_nonregular() {
        let d = TestDir::new();
        assert_eq!(
            err(open_existing(&d.join("none.qvault"))),
            StoreError::NotFound
        );
        let real = d.join("real.qvault");
        write_file(&real, b"x", 0o600);
        let link = d.join("link.qvault");
        symlink(&real, &link).unwrap();
        assert_eq!(err(open_existing(&link)), StoreError::UnsafeFile);
        let dir = d.subdir("dir.qvault", 0o700);
        assert_eq!(err(open_existing(&dir)), StoreError::UnsafeFile);
        let fifo = d.join("fifo.qvault");
        rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        assert_eq!(err(open_existing(&fifo)), StoreError::UnsafeFile);
        assert!(open_existing(&real).is_ok());
    }

    #[test]
    fn fs_open_checks_mode() {
        let d = TestDir::new();
        for (mode, ok) in [
            (0o600, true),
            (0o700, true),
            (0o640, false),
            (0o604, false),
            (0o660, false),
            (0o606, false),
            (0o610, false),
        ] {
            let p = d.join(&format!("m{mode:o}.qvault"));
            write_file(&p, b"x", mode);
            let r = open_existing(&p);
            if ok {
                assert!(r.is_ok(), "mode {mode:o}");
            } else {
                assert_eq!(err(r), StoreError::UnsafeFile, "mode {mode:o}");
            }
        }
    }

    #[test]
    fn fs_parent_rules() {
        let d = TestDir::new();
        let open_dir = d.subdir("open", 0o777);
        let p = open_dir.join("v.qvault");
        write_file(&p, b"x", 0o600);
        assert_eq!(err(open_existing(&p)), StoreError::UnsafeFile);
        assert_eq!(check_parent(&p), Err(StoreError::UnsafeFile));

        // No sticky-bit exception: anyone may create sidecar files there.
        let sticky = d.subdir("sticky", 0o1777);
        let p = sticky.join("v.qvault");
        write_file(&p, b"x", 0o600);
        assert_eq!(err(open_existing(&p)), StoreError::UnsafeFile);

        // Group write is refused outside Android, even for our own group
        // (new directories get it), which can have other members.
        let group = d.subdir("group", 0o770);
        let p = group.join("v.qvault");
        write_file(&p, b"x", 0o600);
        assert_eq!(err(open_existing(&p)), StoreError::UnsafeFile);
        let group_sticky = d.subdir("group-sticky", 0o1770);
        assert_eq!(
            check_parent(&group_sticky.join("v.qvault")),
            Err(StoreError::UnsafeFile)
        );

        // Group read and search are fine.
        let group_read = d.subdir("group-read", 0o750);
        let p = group_read.join("v.qvault");
        write_file(&p, b"x", 0o600);
        assert!(open_existing(&p).is_ok());

        let readable = d.subdir("readable", 0o755);
        let p = readable.join("v.qvault");
        write_file(&p, b"x", 0o600);
        assert!(open_existing(&p).is_ok());

        // The parent must be a directory.
        let file = d.join("file");
        write_file(&file, b"x", 0o600);
        assert_eq!(
            check_parent(&file.join("v.qvault")),
            Err(StoreError::UnsafeFile)
        );
    }

    #[test]
    fn fs_second_open_is_locked() {
        let d = TestDir::new();
        let p = d.join("v.qvault");
        write_file(&p, b"x", 0o600);
        let first = open_existing(&p).unwrap();
        assert_eq!(err(open_existing(&p)), StoreError::Locked);
        drop(first);
        assert!(open_existing(&p).is_ok());
    }

    #[test]
    fn fs_identity_detects_replacement() {
        let d = TestDir::new();
        let p = d.join("v.qvault");
        write_file(&p, b"x", 0o600);
        let f = open_existing(&p).unwrap();
        assert_eq!(f.same_as_path(&p), Ok(()));
        // Rewriting in place keeps the identity (mtime is not a check).
        std::fs::write(&p, b"changed").unwrap();
        assert_eq!(f.same_as_path(&p), Ok(()));
        let other = d.join("other");
        write_file(&other, b"y", 0o600);
        std::fs::rename(&other, &p).unwrap();
        assert_eq!(f.same_as_path(&p), Err(StoreError::Replaced));
        std::fs::remove_file(&p).unwrap();
        assert_eq!(f.same_as_path(&p), Err(StoreError::Replaced));
        let target = d.join("target");
        write_file(&target, b"z", 0o600);
        symlink(&target, &p).unwrap();
        assert_eq!(f.same_as_path(&p), Err(StoreError::Replaced));
    }

    #[test]
    fn fs_create_temp_and_rename() {
        let d = TestDir::new();
        let final_path = d.join("v.qvault");
        let (f, temp) = create_temp(&final_path).unwrap();
        let name = temp.file_name().unwrap().to_str().unwrap().to_owned();
        assert!(name.starts_with(".v.qvault.tmp-") && name.len() == ".v.qvault.tmp-".len() + 16);
        let meta = std::fs::symlink_metadata(&temp).unwrap();
        assert!(meta.file_type().is_file());
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.len(), 0);
        // Locked like an open vault.
        assert_eq!(err(open_existing(&temp)), StoreError::Locked);
        rename_noreplace(&temp, &final_path).unwrap();
        assert_eq!(f.same_as_path(&final_path), Ok(()));
        sync_dir(d.path()).unwrap();
        f.sync().unwrap();

        // Never onto an existing path; both files stay.
        let (_g, temp2) = create_temp(&final_path).unwrap();
        assert_eq!(
            rename_noreplace(&temp2, &final_path),
            Err(StoreError::Exists)
        );
        assert!(temp2.exists() && final_path.exists());
        assert_eq!(f.same_as_path(&final_path), Ok(()));
    }

    #[test]
    fn fs_create_temp_never_follows_or_reuses() {
        // O_EXCL | O_NOFOLLOW: a name that exists, as a file or a symlink,
        // is an error, never a reuse. Exercise the open flags directly with a
        // planted name, since the random suffix cannot be predicted.
        let d = TestDir::new();
        let target = d.join("target");
        write_file(&target, b"keep", 0o600);
        let planted = d.join(".v.qvault.tmp-planted");
        symlink(&target, &planted).unwrap();
        let r = open(
            &planted,
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        );
        assert_eq!(r.err().map(errno_err), Some(StoreError::Exists));
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        // Many temps for one name never collide.
        let final_path = d.join("v.qvault");
        let temps: Vec<_> = (0..32).map(|_| create_temp(&final_path).unwrap()).collect();
        let mut names: Vec<_> = temps.iter().map(|(_, p)| p.clone()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 32);
    }

    // 0012 §1: Snapshot disk growth
    #[test]
    fn stale_cleanup_keeps_live_producers_readers_and_unowned_journals() {
        let d = TestDir::new();
        let target = d.join("new.qvault");
        let (producer, temp) = create_temp(&target).unwrap();
        let journal = with_suffix(&temp, "-journal");
        write_file(&journal, b"synthetic journal", 0o600);
        // A hardlink alias must be detected before opening/closing an fd.
        let alias = d.join(".new.qvault.tmp-0123456789abcdef");
        std::fs::hard_link(&temp, &alias).unwrap();
        remove_stale_temps(&target).unwrap();
        assert!(temp.exists() && alias.exists() && journal.exists());
        assert_eq!(err(open_private_ro(&temp)), StoreError::Locked);
        let mut producer = producer.into_archive_file();
        producer.write_all(b"encrypted fixture").unwrap();
        let mut reader = open_private_ro(&temp).unwrap();
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"encrypted fixture");
        assert_eq!(producer.stream_position().unwrap(), 17);
        drop(producer);
        remove_stale_temps(&target).unwrap();
        assert!(temp.exists() && alias.exists() && journal.exists());
        drop(reader);
        let orphan = d.join(".new.qvault.tmp-fedcba9876543210-journal");
        write_file(&orphan, b"unknown owner", 0o600);
        remove_stale_temps(&target).unwrap();
        assert!(!temp.exists() && !alias.exists() && !journal.exists());
        assert!(orphan.exists());
    }

    #[test]
    #[ignore = "child process for stale_cleanup_waits_for_process_death"]
    fn temporary_producer_child() {
        let target = PathBuf::from(std::env::var_os("QV_TEMP_LEASE_FIXTURE").unwrap());
        let (lease, temp) = create_temp(&target).unwrap();
        let mut file = lease.into_archive_file();
        file.write_all(b"encrypted fixture").unwrap();
        write_file(&with_suffix(&temp, "-journal"), b"synthetic journal", 0o600);
        std::fs::write(target.with_extension("ready"), b"ready").unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    #[test]
    #[ignore = "child process for snapshot recovery lease tests"]
    fn existing_lease_child() {
        let path = PathBuf::from(std::env::var_os("QV_EXISTING_LEASE_FIXTURE").unwrap());
        let _lease = open_existing(&path).unwrap();
        std::fs::write(path.with_extension("ready"), b"ready").unwrap();
        loop {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    }

    // 0012 §1: Snapshot disk growth
    #[test]
    fn stale_cleanup_waits_for_process_death() {
        let d = TestDir::new();
        let target = d.join("new.qvault");
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "fs::tests::temporary_producer_child",
            ])
            .env("QV_TEMP_LEASE_FIXTURE", &target)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !target.with_extension("ready").exists() && std::time::Instant::now() < deadline {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let ready = target.with_extension("ready").exists();
        let count = || {
            std::fs::read_dir(d.path())
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .unwrap()
                        .file_name()
                        .as_encoded_bytes()
                        .starts_with(b".new.qvault.tmp-")
                })
                .count()
        };
        let before = count();
        let cleanup = remove_stale_temps(&target);
        let during = count();
        let _ = child.kill();
        let _ = child.wait();
        assert!(ready);
        cleanup.unwrap();
        assert_eq!(before, 2);
        assert_eq!(during, 2, "live producer was reclaimed");
        remove_stale_temps(&target).unwrap();
        assert_eq!(count(), 0);
    }

    #[test]
    #[ignore = "child process for cleanup_does_not_release_sqlite_posix_locks"]
    fn sqlite_lock_probe_child() {
        let path = PathBuf::from(std::env::var_os("QV_SQLITE_LEASE_FIXTURE").unwrap());
        let conn = rusqlite::Connection::open(path).unwrap();
        conn.busy_timeout(std::time::Duration::ZERO).unwrap();
        let error = conn
            .query_row("SELECT x FROM fixture", [], |r| r.get::<_, i64>(0))
            .unwrap_err();
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
    }

    // 0012 §1: Live SQLite copying
    #[test]
    fn cleanup_does_not_release_sqlite_posix_locks() {
        let d = TestDir::new();
        let target = d.join("new.qvault");
        let (lease, temp) = create_temp(&target).unwrap();
        let conn = rusqlite::Connection::open(&temp).unwrap();
        conn.execute_batch(
            "CREATE TABLE fixture(x); INSERT INTO fixture VALUES(1); BEGIN EXCLUSIVE;",
        )
        .unwrap();
        let alias = d.join(".new.qvault.tmp-0123456789abcdef");
        std::fs::hard_link(&temp, &alias).unwrap();
        assert_eq!(err(open_existing(&alias)), StoreError::Locked);
        assert_eq!(err(open_private_ro(&alias)), StoreError::Locked);
        remove_stale_temps(&target).unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "fs::tests::sqlite_lock_probe_child"])
            .env("QV_SQLITE_LEASE_FIXTURE", &temp)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "cleanup dropped the live SQLite lock");
        conn.execute_batch("ROLLBACK").unwrap();
        drop(conn);
        drop(lease);
        remove_stale_temps(&target).unwrap();
        assert!(!temp.exists() && !alias.exists());
    }

    #[test]
    fn temporary_leases_preserve_private_parent_aliases() {
        let d = TestDir::new();
        let real = d.subdir("private", 0o700);
        let alias = d.join("alias");
        symlink(&real, &alias).unwrap();
        let target = alias.join("new.qvault");
        let (lease, temp) = create_temp(&target).unwrap();
        remove_stale_temps(&target).unwrap();
        assert!(temp.exists());
        drop(lease);
        remove_stale_temps(&target).unwrap();
        assert!(!temp.exists());
    }

    #[test]
    fn fs_size_cap() {
        let d = TestDir::new();
        let p = d.join("big.qvault");
        let f = std::fs::File::create(&p).unwrap();
        f.set_len(MAX_DB_BYTES + 1).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(err(open_existing(&p)), StoreError::LimitExceeded);
        f.set_len(MAX_DB_BYTES).unwrap();
        assert!(open_existing(&p).is_ok());
    }

    #[test]
    fn fs_owner_only_rule() {
        let me = geteuid().as_raw();
        assert!(owner_only(FileType::RegularFile, me, 0o100600, me));
        assert!(owner_only(FileType::RegularFile, me, 0o100700, me));
        // Another owner, even root, with an otherwise private mode.
        assert!(!owner_only(FileType::RegularFile, me + 1, 0o100600, me));
        assert!(!owner_only(FileType::RegularFile, 0, 0o100600, me));
        assert!(!owner_only(FileType::RegularFile, me, 0o100666, me));
        assert!(!owner_only(FileType::RegularFile, me, 0o100640, me));
        assert!(!owner_only(FileType::Symlink, me, 0o120600, me));
        assert!(!owner_only(FileType::Directory, me, 0o040700, me));
        assert!(!owner_only(FileType::Fifo, me, 0o010600, me));
    }

    #[test]
    fn fs_sidecars() {
        let d = TestDir::new();
        let p = d.join("v.qvault");
        write_file(&p, b"x", 0o600);
        assert_eq!(check_sidecars(&p), Ok(()));

        // Our own journal (as SQLite leaves it after a crash) passes.
        let journal = d.join("v.qvault-journal");
        write_file(&journal, b"j", 0o600);
        assert_eq!(check_sidecars(&p), Ok(()));
        for mode in [0o666, 0o644, 0o660, 0o604] {
            std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(check_sidecars(&p), Err(StoreError::UnsafeFile), "{mode:o}");
        }
        std::fs::remove_file(&journal).unwrap();
        let target = d.join("target");
        write_file(&target, b"t", 0o600);
        symlink(&target, &journal).unwrap();
        assert_eq!(check_sidecars(&p), Err(StoreError::UnsafeFile));
        std::fs::remove_file(&journal).unwrap();
        std::fs::create_dir(&journal).unwrap();
        assert_eq!(check_sidecars(&p), Err(StoreError::UnsafeFile));
        std::fs::remove_dir(&journal).unwrap();
        // A dangling symlink is still an entry.
        symlink(d.join("absent"), &journal).unwrap();
        assert_eq!(check_sidecars(&p), Err(StoreError::UnsafeFile));
        std::fs::remove_file(&journal).unwrap();
        assert_eq!(check_sidecars(&p), Ok(()));

        // A WAL or shared-memory file is never ours, even when private.
        for suffix in ["-wal", "-shm"] {
            let side = with_suffix(&p, suffix);
            write_file(&side, b"", 0o600);
            assert_eq!(check_sidecars(&p), Err(StoreError::UnsafeFile), "{suffix}");
            std::fs::remove_file(&side).unwrap();
        }
        assert_eq!(check_sidecars(&p), Ok(()));
    }

    #[test]
    fn fs_helpers() {
        assert_eq!(parent_of(Path::new("v.qvault")), Path::new("."));
        assert_eq!(parent_of(Path::new("/a/v.qvault")), Path::new("/a"));
        assert_eq!(
            with_suffix(Path::new("/a/v.qvault"), "-journal"),
            Path::new("/a/v.qvault-journal")
        );
    }
}
