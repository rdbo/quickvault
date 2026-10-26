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

use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{
    CWD, FileType, FlockOperation, Mode, OFlags, RenameFlags, Stat, flock, fstat, fsync, lstat,
    open, renameat_with, stat,
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

/// The vault file's descriptor: holds the process lock and the identity.
pub(crate) struct LockedFile {
    fd: OwnedFd,
    identity: Stat,
}

impl LockedFile {
    /// The descriptor (for `fstatfs`, `fsync`).
    pub(crate) fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
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
        fsync(&self.fd).map_err(errno_err)
    }

    fn lock(fd: OwnedFd) -> Result<Self, StoreError> {
        flock(&fd, FlockOperation::NonBlockingLockExclusive).map_err(|e| match e {
            Errno::WOULDBLOCK => StoreError::Locked,
            e => errno_err(e),
        })?;
        let identity = fstat(&fd).map_err(errno_err)?;
        Ok(Self { fd, identity })
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
    let st = lstat(path).map_err(errno_err)?;
    if FileType::from_raw_mode(st.st_mode) == FileType::Symlink {
        return Err(StoreError::UnsafeFile);
    }
    check_parent(path)?;
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
    LockedFile::lock(fd)
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
    let fd = open(
        &temp,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(errno_err)?;
    let locked = match fstat(&fd).map_err(errno_err).and_then(|st| check_file(&st)) {
        Ok(()) => LockedFile::lock(fd),
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

/// Removes `path` if it exists; errors are ignored (cleanup after a
/// failure that is already being reported).
pub(crate) fn remove_best_effort(path: &Path) {
    let _ = std::fs::remove_file(path);
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
