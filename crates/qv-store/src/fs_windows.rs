// SPDX-License-Identifier: AGPL-3.0-or-later

//! File safety for the vault file on Windows (spec 0004 §1.1, §1.3; 0008 §5;
//! 0009 §5.1; plan 0052). The same crate-private API as the Unix `fs`
//! module, with Windows primitives from `qv-win`:
//!
//! - **Owner-only** means the 0009 §5.1 ACL rules: owner and every allow
//!   ACE are trusted SIDs (the user, LocalSystem, Administrators). The vault
//!   parent must also give no foreign write-class right and nothing new
//!   files would inherit, because SQLite creates its `-journal` with
//!   inherited security. Unsafe permissions are refused, never repaired.
//! - **No reparse points**: final components are opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT` and refused if they are one. Parents may
//!   be owner-controlled aliases, as on Unix.
//! - **Identity** is the volume serial plus the 128-bit file ID.
//! - **Process lock**: an exclusive `LockFileEx` byte far beyond any SQLite
//!   lock byte (Windows locks are mandatory); opaque readers share it. Our
//!   handles share read, write and delete and never request DELETE, so
//!   SQLite can open the file beside them and we can rename it while we
//!   hold it. Windows refuses to rename a file SQLite holds open; callers
//!   close the connection first (`VaultFile::relocate`).
//! - **New files** are created with `CREATE_NEW` and a protected owner-only
//!   DACL applied atomically, then renamed without replacement
//!   (`MOVEFILE_WRITE_THROUGH`). Directory "sync" is a no-op: NTFS journals
//!   metadata and every rename here is write-through.
//! - **Directory locks** are session-local named mutexes keyed by the
//!   directory's identity (Windows cannot lock directory handles).

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex, PoisonError, Weak};

use qv_win::fs::{Access, FileId, Kind};
use qv_win::security::Rule;

use crate::error::{StoreError, os_err};
use crate::limits::MAX_DB_BYTES;

type Identity = FileId;
struct Registered {
    file: Arc<File>,
    token: Weak<LeaseToken>,
    opaque: bool,
}
static FILES: LazyLock<Mutex<HashMap<Identity, Registered>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

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
    // Field order matters: the last token closes the registry's handle
    // under its mutex after all handles have released their own file Arc.
    file: Arc<File>,
    _token: Arc<LeaseToken>,
}

fn register(
    files: &mut HashMap<Identity, Registered>,
    file: File,
    id: Identity,
    opaque: bool,
) -> FileHandle {
    let file = Arc::new(file);
    let token = Arc::new(LeaseToken(id));
    files.insert(
        id,
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

/// Opens `path` itself for inspection; a missing path is `NotFound`.
fn inspect(path: &Path) -> Result<File, StoreError> {
    qv_win::fs::open_nofollow(path, Access::Inspect).map_err(os_err)
}

fn kind(file: &File) -> Result<Kind, StoreError> {
    qv_win::fs::kind_of(file).map_err(os_err)
}

fn id_of(file: &File) -> Result<Identity, StoreError> {
    qv_win::fs::file_id(file).map_err(os_err)
}

fn meets(file: &File, rule: Rule) -> Result<bool, StoreError> {
    qv_win::fs::meets(file, rule).map_err(os_err)
}

/// A regular file meeting the owner-only rule.
fn is_owner_only(file: &File) -> Result<bool, StoreError> {
    Ok(kind(file)? == Kind::File && meets(file, Rule::OwnerOnly)?)
}

/// An opaque encrypted archive/journal handle with a lifetime lease and an
/// independent cursor. Positioned I/O lets readers share a producer's handle
/// without disturbing each other.
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
impl ArchiveFile {
    pub(crate) fn same_as_path(&self, path: &Path) -> Result<(), StoreError> {
        // Compare with the identity recorded when the file was leased.
        let now = inspect(path).map_err(|_| StoreError::Replaced)?;
        if !is_owner_only(&now)? || id_of(&now)? != self.handle._token.0 {
            return Err(StoreError::Replaced);
        }
        Ok(())
    }
}
impl Read for ArchiveFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.handle.file.seek_read(buf, self.offset)?;
        self.offset += n as u64;
        Ok(n)
    }
}
impl Write for ArchiveFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.handle.file.seek_write(buf, self.offset)?;
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
pub(crate) struct DirectoryLock(#[allow(dead_code)] qv_win::sync::NamedLock); // held, never read
pub(crate) fn lock_dir(dir: &Path) -> Result<DirectoryLock, StoreError> {
    // Owner-controlled directory aliases are allowed, as on Unix.
    let handle = qv_win::fs::open(dir, Access::Inspect, true).map_err(os_err)?;
    if kind(&handle)? != Kind::Dir {
        return Err(StoreError::UnsafeFile);
    }
    let id = id_of(&handle)?;
    let name = format!("QuickVault-dir-{:016x}-{:032x}", id.volume, id.id);
    qv_win::sync::named_lock(&name)
        .map(DirectoryLock)
        .map_err(os_err)
}

/// The vault file's handle: holds the process lock and the identity.
pub(crate) struct LockedFile {
    handle: FileHandle,
    identity: Identity,
}

impl LockedFile {
    /// [`StoreError::Replaced`] unless `path` still names this file and is
    /// not a reparse point (0004 §1.3).
    pub(crate) fn same_as_path(&self, path: &Path) -> Result<(), StoreError> {
        let now = inspect(path).map_err(|_| StoreError::Replaced)?;
        if kind(&now)? != Kind::File || id_of(&now)? != self.identity {
            return Err(StoreError::Replaced);
        }
        Ok(())
    }

    /// Flushes the file to stable storage.
    pub(crate) fn sync(&self) -> Result<(), StoreError> {
        sync_file(&self.handle.file)
    }

    /// Appends `bytes` at the end of the file (staged imports).
    pub(crate) fn write_all(&self, bytes: &[u8]) -> Result<(), StoreError> {
        let mut file = &*self.handle.file;
        file.seek(SeekFrom::End(0)).map_err(crate::error::io_err)?;
        file.write_all(bytes).map_err(crate::error::io_err)
    }

    fn lock(
        file: File,
        id: Identity,
        files: &mut HashMap<Identity, Registered>,
    ) -> Result<Self, StoreError> {
        if !qv_win::fs::try_lock(&file, true).map_err(os_err)? {
            return Err(StoreError::Locked);
        }
        let handle = register(files, file, id, false);
        Ok(Self {
            handle,
            identity: id,
        })
    }

    /// Reads the whole locked file from offset 0 with positioned reads (the
    /// handle and lock are kept). [`StoreError::Integrity`] if its size or
    /// the bytes read exceed `max` (the rotation journal, plan 0023).
    pub(crate) fn read_bounded(&self, max: usize) -> Result<Vec<u8>, StoreError> {
        let len = self
            .handle
            .file
            .metadata()
            .map_err(crate::error::io_err)?
            .len();
        let len = usize::try_from(len).map_err(|_| StoreError::Integrity)?;
        if len > max {
            return Err(StoreError::Integrity);
        }
        let mut bytes = Vec::with_capacity(len);
        let mut chunk = [0; 4096];
        loop {
            let n = self
                .handle
                .file
                .seek_read(
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

    /// Takes the handle out of the guard, for a temporary file that is
    /// written, re-read and published (archives, 0004 §6.5). The lock lasts
    /// until the final reader/producer drops. This file must never
    /// subsequently host a SQLite connection.
    pub(crate) fn into_archive_file(self) -> ArchiveFile {
        FILES
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(self.identity)
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
/// other user can replace the path or plant files next to it, and that
/// files created there (SQLite's journal) inherit no foreign access.
pub(crate) fn check_parent(path: &Path) -> Result<(), StoreError> {
    let dir = qv_win::fs::open(parent_of(path), Access::Inspect, true).map_err(os_err)?;
    if kind(&dir)? == Kind::Dir && meets(&dir, Rule::VaultParent)? {
        Ok(())
    } else {
        Err(StoreError::UnsafeFile)
    }
}

/// Checks a private directory of our own (anchors, snapshots, staging): a
/// real directory, not a reparse point, meeting the vault-parent rule.
pub(crate) fn check_private_dir(dir: &Path) -> Result<(), StoreError> {
    let d = inspect(dir)?;
    if kind(&d)? == Kind::Dir && meets(&d, Rule::VaultParent)? {
        Ok(())
    } else {
        Err(StoreError::UnsafeFile)
    }
}

/// Checks a just-opened vault file.
fn check_file(file: &File) -> Result<(), StoreError> {
    if !is_owner_only(file)? {
        return Err(StoreError::UnsafeFile);
    }
    let len = file.metadata().map_err(crate::error::io_err)?.len();
    if len > MAX_DB_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    Ok(())
}

/// Opens and locks an existing vault file (plan 0008, *Open* steps 1–2).
pub(crate) fn open_existing(path: &Path) -> Result<LockedFile, StoreError> {
    let mut files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    let probe = inspect(path)?;
    if kind(&probe)? != Kind::File {
        return Err(StoreError::UnsafeFile);
    }
    check_parent(path)?;
    let id = id_of(&probe)?;
    if files.contains_key(&id) {
        return Err(StoreError::Locked);
    }
    let file = qv_win::fs::open_nofollow(path, Access::ReadWrite).map_err(os_err)?;
    if kind(&file)? != Kind::File || id_of(&file)? != id {
        // Swapped between the probe and the open.
        return Err(StoreError::UnsafeFile);
    }
    check_file(&file)?;
    LockedFile::lock(file, id, &mut files)
}

/// Opens a private regular file read-only, for re-reading what was just
/// written before it is published (an archive temp file, 0004 §6.5).
/// [`StoreError::UnsafeFile`] for a reparse point, a non-regular file or a
/// file that is not owner-only.
pub(crate) fn open_private_ro(path: &Path) -> Result<ArchiveFile, StoreError> {
    open_opaque(path, true)
}

/// Opens an opaque file for reading under a shared lock, or shares the
/// handle of a live opaque producer/reader of the same file.
pub(crate) fn open_opaque(path: &Path, private: bool) -> Result<ArchiveFile, StoreError> {
    let mut files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    let before = inspect(path)?;
    if kind(&before)? != Kind::File || (private && !meets(&before, Rule::OwnerOnly)?) {
        return Err(StoreError::UnsafeFile);
    }
    let id = id_of(&before)?;
    if let Some(registered) = files.get(&id) {
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
    let file = qv_win::fs::open_nofollow(path, Access::Read).map_err(os_err)?;
    if kind(&file)? != Kind::File
        || id_of(&file)? != id
        || (private && !meets(&file, Rule::OwnerOnly)?)
    {
        return Err(StoreError::UnsafeFile);
    }
    if !qv_win::fs::try_lock(&file, false).map_err(os_err)? {
        return Err(StoreError::Locked);
    }
    let handle = register(&mut files, file, id, true);
    Ok(ArchiveFile { handle, offset: 0 })
}

/// Atomic replacement is reserved for anchor metadata, never vault files.
pub(crate) fn replace_anchor(from: &Path, to: &Path) -> Result<(), StoreError> {
    let _files = FILES.lock().unwrap_or_else(PoisonError::into_inner);
    qv_win::fs::rename_replace(from, to).map_err(os_err)
}

/// What `path` itself is, without following a reparse point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entry {
    /// Nothing at the path.
    Missing,
    /// A regular file.
    Regular,
    /// Anything else (directory, reparse point, device).
    Other,
}

/// See [`Entry`].
pub(crate) fn entry(path: &Path) -> Result<Entry, StoreError> {
    match inspect(path) {
        Ok(f) => Ok(if kind(&f)? == Kind::File {
            Entry::Regular
        } else {
            Entry::Other
        }),
        Err(StoreError::NotFound) => Ok(Entry::Missing),
        Err(e) => Err(e),
    }
}

/// Checks SQLite's sidecar files next to `path` before SQLite opens it: a
/// `-journal` must be owner-only like the vault, a `-wal` or `-shm` must not
/// exist. [`StoreError::UnsafeFile`] otherwise.
pub(crate) fn check_sidecars(path: &Path) -> Result<(), StoreError> {
    match inspect(&with_suffix(path, "-journal")) {
        Ok(j) if is_owner_only(&j)? => {}
        Ok(_) => return Err(StoreError::UnsafeFile),
        Err(StoreError::NotFound) => {}
        Err(e) => return Err(e),
    }
    for suffix in ["-wal", "-shm"] {
        match entry(&with_suffix(path, suffix))? {
            Entry::Missing => {}
            _ => return Err(StoreError::UnsafeFile),
        }
    }
    Ok(())
}

/// Creates and locks a new, empty temporary file next to `final_path`,
/// named `.<name>.tmp-<16 hex>`, owner-only. Never follows or reuses an
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
    let file = qv_win::fs::create_private_file(&temp).map_err(os_err)?;
    let locked = check_file(&file)
        .and_then(|()| id_of(&file))
        .and_then(|id| LockedFile::lock(file, id, &mut files));
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
    qv_win::fs::rename_noreplace(from, to).map_err(os_err)
}

/// Directory entries are durable once the write-through rename returns
/// (NTFS journals metadata); this checks that `dir` still exists.
pub(crate) fn sync_dir(dir: &Path) -> Result<(), StoreError> {
    let d = qv_win::fs::open(dir, Access::Inspect, true).map_err(os_err)?;
    if kind(&d)? != Kind::Dir {
        return Err(StoreError::UnsafeFile);
    }
    Ok(())
}

/// Flushes a file's data and metadata to stable storage.
pub(crate) fn sync_file(file: &File) -> Result<(), StoreError> {
    file.sync_all().map_err(crate::error::io_err)
}

/// Creates `dir` and missing parents as owner-only directories; existing
/// ones are left as they are (callers then check them).
pub(crate) fn create_private_dir_all(dir: &Path) -> Result<(), StoreError> {
    let mut missing = Vec::new();
    let mut at = Some(dir);
    while let Some(p) = at {
        if p.as_os_str().is_empty() {
            break;
        }
        match entry(p) {
            Ok(Entry::Missing) => missing.push(p),
            Ok(_) => break,
            Err(e) => return Err(e),
        }
        at = p.parent();
    }
    for p in missing.into_iter().rev() {
        match qv_win::fs::create_private_dir(p) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(os_err(e)),
        }
    }
    Ok(())
}

/// Removes the file at `path` itself, never through a reparse point; the
/// name disappears at once where the filesystem supports POSIX deletion,
/// even while our own (delete-sharing) handles stay open, like `unlink`.
pub(crate) fn remove_file(path: &Path) -> io::Result<()> {
    qv_win::fs::remove_nofollow(path)
}

/// Removes `path` if it exists; errors are ignored (cleanup after a
/// failure that is already being reported).
pub(crate) fn remove_best_effort(path: &Path) {
    let _ = remove_file(path);
}

/// Removes temporary siblings that [`create_temp`] made for `final_path`
/// and a crash left behind: exactly `.<name>.tmp-<16 hex>` and its
/// `-journal`. Only owner-only regular files no live process holds are
/// removed. Every other name is left alone.
pub(crate) fn remove_stale_temps(final_path: &Path) -> Result<(), StoreError> {
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
        let Some(hex) = n.strip_prefix(&prefix) else {
            continue;
        };
        if hex.len() != 16 || !hex.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
            continue;
        }
        let path = parent.join(n);
        match inspect(&path).and_then(|f| is_owner_only(&f)) {
            Ok(true) => {}
            _ => continue,
        }
        let lease = match open_existing(&path) {
            Ok(lease) => lease,
            Err(StoreError::Locked | StoreError::NotFound) => continue,
            Err(e) => return Err(e),
        };
        lease.same_as_path(&path)?;
        let journal = with_suffix(&path, "-journal");
        match inspect(&journal) {
            Ok(j) if is_owner_only(&j)? => {
                drop(j);
                remove_file(&journal).map_err(crate::error::io_err)?;
            }
            Ok(_) => continue,
            Err(StoreError::NotFound) => {}
            Err(e) => return Err(e),
        }
        lease.same_as_path(&path)?;
        remove_file(&path).map_err(crate::error::io_err)?;
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
    //! Private temporary directories for tests. Unix modes map to ACLs:
    //! group/other write bits grant Everyone modify; read/search bits grant
    //! Everyone read, inherited by new files for a file but not for a
    //! directory (a listable folder whose new files stay private).

    use std::path::{Path, PathBuf};

    /// A fresh owner-only directory under the system temp dir, removed on
    /// drop.
    pub(crate) struct TestDir(PathBuf);

    impl TestDir {
        pub(crate) fn new() -> Self {
            let mut name = String::from("qv-store-test-");
            for b in qv_crypto::random_array::<8>().unwrap() {
                name.push_str(&format!("{b:02x}"));
            }
            let path = std::env::temp_dir().join(name);
            qv_win::fs::create_private_dir(&path).unwrap();
            Self(path)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }

        pub(crate) fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }

        /// A subdirectory with `mode` (mapped to an ACL).
        pub(crate) fn subdir(&self, name: &str, mode: u32) -> PathBuf {
            let p = self.join(name);
            qv_win::fs::create_private_dir(&p).unwrap();
            set_mode(&p, mode);
            p
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Writes `bytes` to a new file at `path` with `mode` (mapped to an ACL).
    /// Like `std::fs::write`, an existing file is truncated and rewritten.
    pub(crate) fn write_file(path: &Path, bytes: &[u8], mode: u32) {
        use std::io::Write as _;
        let mut f = match qv_win::fs::create_private_file(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::File::create(path).unwrap()
            }
            Err(e) => panic!("create {e}"),
        };
        f.write_all(bytes).unwrap();
        drop(f);
        set_mode(path, mode);
    }

    /// Wine stores ACLs as Unix modes, so a readable directory always grants
    /// inheritable read; checks needing the distinction skip there (never on
    /// Windows). The test runner sets `QV_WINE=1`.
    pub(crate) fn wine_lacks_acl_inheritance() -> bool {
        let wine = std::env::var_os("QV_WINE").is_some();
        if wine {
            eprintln!("skipped under Wine: no ACL inheritance distinction");
        }
        wine
    }

    /// Wine keeps a deleted name listed while the handle that created the
    /// file is open, although it reports POSIX deletion; NTFS removes it at
    /// once. Checks of that skip there (never on Windows).
    pub(crate) fn wine_keeps_deleted_names() -> bool {
        let wine = std::env::var_os("QV_WINE").is_some();
        if wine {
            eprintln!("skipped under Wine: deleted names linger while open");
        }
        wine
    }

    /// Wine does not enforce a DACL that removes the owner's write right.
    pub(crate) fn wine_ignores_read_only_dacl() -> bool {
        let wine = std::env::var_os("QV_WINE").is_some();
        if wine {
            eprintln!("skipped under Wine: read-only DACL not enforced");
        }
        wine
    }

    /// Whether `path` is owner-only exactly when `mode` has no group or
    /// other bits.
    pub(crate) fn has_mode(path: &Path, mode: u32) -> bool {
        let f = qv_win::fs::open_nofollow(path, qv_win::fs::Access::Inspect).unwrap();
        let private = qv_win::fs::meets(&f, qv_win::security::Rule::OwnerOnly).unwrap();
        private == (mode & 0o077 == 0)
    }

    /// Creates a file or directory symlink; `false` (after a note) when the
    /// privilege is missing outside CI, so callers skip that check. CI
    /// runners have it, so the checks run there.
    pub(crate) fn symlink(target: &Path, link: &Path) -> bool {
        let made = if target.is_dir() {
            std::os::windows::fs::symlink_dir(target, link)
        } else {
            std::os::windows::fs::symlink_file(target, link)
        };
        match made {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(1314) && std::env::var_os("CI").is_none() => {
                eprintln!("skipped: no symlink privilege outside CI");
                false
            }
            Err(e) => panic!("symlink: {e}"),
        }
    }

    /// The ACL equivalent of `chmod mode` (see `qv_win::fs::chmod_like`).
    pub(crate) fn set_mode(path: &Path, mode: u32) {
        qv_win::fs::chmod_like(path, mode).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::test_dir::{TestDir, set_mode, write_file};
    use super::*;

    fn err<T>(r: Result<T, StoreError>) -> StoreError {
        match r {
            Ok(_) => panic!("unexpectedly succeeded"),
            Err(e) => e,
        }
    }

    #[test]
    fn fs_open_rejects_missing_reparse_and_nonregular() {
        let d = TestDir::new();
        assert_eq!(
            err(open_existing(&d.join("none.qvault"))),
            StoreError::NotFound
        );
        let real = d.join("real.qvault");
        write_file(&real, b"x", 0o600);
        if super::test_dir::symlink(&real, &d.join("link.qvault")) {
            assert_eq!(
                err(open_existing(&d.join("link.qvault"))),
                StoreError::UnsafeFile
            );
        }
        let dir = d.subdir("dir.qvault", 0o700);
        assert_eq!(err(open_existing(&dir)), StoreError::UnsafeFile);
        assert!(open_existing(&real).is_ok());
    }

    #[test]
    fn fs_open_checks_acl() {
        let d = TestDir::new();
        let p = d.join("v.qvault");
        write_file(&p, b"x", 0o644);
        assert_eq!(err(open_existing(&p)), StoreError::UnsafeFile);
        set_mode(&p, 0o600);
        assert!(open_existing(&p).is_ok());
    }

    #[test]
    fn fs_parent_rules() {
        let d = TestDir::new();
        // A listable directory whose new files stay private is fine.
        let listable = d.subdir("listable", 0o755);
        write_file(&listable.join("v.qvault"), b"x", 0o600);
        if !super::test_dir::wine_lacks_acl_inheritance() {
            assert!(open_existing(&listable.join("v.qvault")).is_ok());
        }
        // Foreign write on the parent is refused.
        let shared = d.subdir("shared", 0o777);
        write_file(&shared.join("v.qvault"), b"x", 0o600);
        assert_eq!(
            err(open_existing(&shared.join("v.qvault"))),
            StoreError::UnsafeFile
        );
        // Inherited foreign read (new journals would get it) is refused.
        let inherited = d.subdir("inherited", 0o700);
        let everyone = qv_win::security::Sid::everyone();
        qv_win::fs::set_dacl(
            &inherited,
            qv_win::security::FILE_ALL_ACCESS,
            &[qv_win::security::Grant {
                sid: &everyone,
                mask: 0x0012_00A9,
                inherit: true,
            }],
        )
        .unwrap();
        write_file(&inherited.join("v.qvault"), b"x", 0o600);
        assert_eq!(
            err(check_parent(&inherited.join("v.qvault"))),
            StoreError::UnsafeFile
        );
        assert_eq!(err(check_private_dir(&shared)), StoreError::UnsafeFile);
        assert!(check_private_dir(d.path()).is_ok());
    }

    #[test]
    fn fs_second_open_is_locked() {
        let d = TestDir::new();
        let p = d.join("v.qvault");
        write_file(&p, b"x", 0o600);
        let first = open_existing(&p).unwrap();
        assert_eq!(err(open_existing(&p)), StoreError::Locked);
        // Another handle (as another process would hold) cannot take the
        // lock byte, and the byte does not block data reads.
        let other = qv_win::fs::open_nofollow(&p, Access::Read).unwrap();
        assert!(!qv_win::fs::try_lock(&other, true).unwrap());
        assert_eq!(std::fs::read(&p).unwrap(), b"x");
        drop(first);
        assert!(open_existing(&p).is_ok());
    }

    #[test]
    fn fs_identity_detects_replacement() {
        let d = TestDir::new();
        let p = d.join("v.qvault");
        write_file(&p, b"x", 0o600);
        let lock = open_existing(&p).unwrap();
        assert!(lock.same_as_path(&p).is_ok());
        let moved = d.join("moved.qvault");
        rename_noreplace(&p, &moved).unwrap();
        write_file(&p, b"y", 0o600);
        assert_eq!(lock.same_as_path(&p), Err(StoreError::Replaced));
        assert!(lock.same_as_path(&moved).is_ok());
    }

    #[test]
    fn fs_create_temp_rename_and_sidecars() {
        let d = TestDir::new();
        let target = d.join("new.qvault");
        let (lock, temp) = create_temp(&target).unwrap();
        assert!(
            temp.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with(".new.qvault.tmp-")
        );
        assert!(is_owner_only(&inspect(&temp).unwrap()).unwrap());
        lock.write_all(b"abc").unwrap();
        lock.sync().unwrap();
        rename_noreplace(&temp, &target).unwrap();
        assert!(lock.same_as_path(&target).is_ok());
        let other = d.join("other");
        write_file(&other, b"o", 0o600);
        assert_eq!(err(rename_noreplace(&other, &target)), StoreError::Exists);
        assert_eq!(std::fs::read(&target).unwrap(), b"abc");
        drop(lock);

        assert!(check_sidecars(&target).is_ok());
        write_file(&with_suffix(&target, "-journal"), b"j", 0o644);
        assert_eq!(err(check_sidecars(&target)), StoreError::UnsafeFile);
        set_mode(&with_suffix(&target, "-journal"), 0o600);
        assert!(check_sidecars(&target).is_ok());
        write_file(&with_suffix(&target, "-wal"), b"w", 0o600);
        assert_eq!(err(check_sidecars(&target)), StoreError::UnsafeFile);
    }

    #[test]
    fn fs_stale_temps_are_removed_unless_live() {
        let d = TestDir::new();
        let target = d.join("v.qvault");
        let (live, live_path) = create_temp(&target).unwrap();
        let (dead, dead_path) = create_temp(&target).unwrap();
        drop(dead);
        write_file(&with_suffix(&dead_path, "-journal"), b"j", 0o600);
        let foreign = d.join(".v.qvault.tmp-00000000000000ff");
        write_file(&foreign, b"f", 0o644);
        remove_stale_temps(&target).unwrap();
        assert!(live_path.exists());
        assert!(!dead_path.exists());
        assert!(!with_suffix(&dead_path, "-journal").exists());
        assert!(foreign.exists(), "not owner-only: left alone");
        drop(live);
    }

    #[test]
    fn fs_opaque_readers_share_and_exclude_vault_locks() {
        let d = TestDir::new();
        let p = d.join("a.qvsnap");
        let (lock, temp) = create_temp(&p).unwrap();
        let mut producer = lock.into_archive_file();
        producer.write_all(b"archive").unwrap();
        let mut reader = open_private_ro(&temp).unwrap();
        let mut s = String::new();
        reader.read_to_string(&mut s).unwrap();
        assert_eq!(s, "archive");
        assert_eq!(err(open_existing(&temp)), StoreError::Locked);
        drop((producer, reader));
        let opened = open_opaque(&temp, false).unwrap();
        assert!(opened.same_as_path(&temp).is_ok());
    }

    // 0012 §1: Snapshot disk growth
    #[test]
    fn stale_cleanup_keeps_live_producers_readers_and_unowned_journals() {
        let d = TestDir::new();
        let target = d.join("new.qvault");
        let (producer, temp) = create_temp(&target).unwrap();
        let journal = with_suffix(&temp, "-journal");
        write_file(&journal, b"synthetic journal", 0o600);
        // A hardlink alias has the same identity, so it is seen as leased.
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
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
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
    fn fs_private_dirs_and_entries() {
        let d = TestDir::new();
        let deep = d.join("a").join("b");
        create_private_dir_all(&deep).unwrap();
        assert!(check_private_dir(&deep).is_ok());
        create_private_dir_all(&deep).unwrap();
        assert_eq!(entry(&deep).unwrap(), Entry::Other);
        assert_eq!(entry(&d.join("none")).unwrap(), Entry::Missing);
        write_file(&d.join("f"), b"", 0o600);
        assert_eq!(entry(&d.join("f")).unwrap(), Entry::Regular);
        let _l = lock_dir(d.path()).unwrap();
        assert!(sync_dir(d.path()).is_ok());
    }
}
