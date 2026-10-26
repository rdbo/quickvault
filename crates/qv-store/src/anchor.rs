// SPDX-License-Identifier: AGPL-3.0-or-later

//! The external anchor (spec 0005 §5.4; plan 0009 D-B).
//!
//! The anchor lives in private state outside the vault DB and archives. It
//! stores `{ vault_id, key_generation, local_seq, local_digest }` of the last
//! commit whose success was reported. Each vault DB has its own anchor file,
//! named by the random replica ID in its `replica` row
//! (`<hex replica_id>.anchor`), so a restored copy of a vault next to the
//! active one never shares or replaces the active vault's anchor (0007
//! §3.4).
//!
//! File: at most [`MAX_ANCHOR_BYTES`], mode 0600, canonical CBOR map
//! (unknown keys fail closed). Development values, frozen in phase 1.16:
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | format | uint, = `ANCHOR_FORMAT` |
//! | 1 | vault_id | bstr 16 |
//! | 2 | key_generation | uint (u32, ≥ 1) |
//! | 3 | local_seq | uint (≥ 1) |
//! | 4 | local_digest | bstr 32 |
//!
//! The anchor is not authenticated: it is only compared against the MAC'd
//! head, so changing it can cause a refusal, never acceptance of a wrong
//! head. It is read with `O_NOFOLLOW` and must be a regular file owned by
//! the effective UID with no group or other bits. It is replaced
//! atomically: a new `O_EXCL` temp file is written and synced, renamed over
//! the old anchor, and the directory is synced.
//!
//! Location: [`AnchorDir::default_dir`] is `$XDG_STATE_HOME/quickvault/anchors`
//! (or `~/.local/state/quickvault/anchors`) on Linux. Callers may choose
//! another private directory. It must not be the vault's own directory or a
//! sync folder: an anchor that rolls back with the vault detects nothing.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use qv_crypto::{KeyGeneration, VaultId};
use qv_encoding::{Decoder, Encoder};
use qv_model::RandomId;
use rustix::fs::{Mode, OFlags, fstat, fsync, open, rename};
use rustix::io::Errno;

use crate::crash::{CrashPoint, point};
use crate::error::{StoreError, errno_err};
use crate::fs;
use crate::head::Anchor;

/// The development anchor format.
const ANCHOR_FORMAT: u64 = 0x7FFF_0001;

/// Largest anchor file.
pub const MAX_ANCHOR_BYTES: usize = 256;

fn malformed<E>(_: E) -> StoreError {
    StoreError::Integrity
}

impl Anchor {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut e = Encoder::new();
        e.map(|m| {
            m.entry(0, |e| {
                e.uint(ANCHOR_FORMAT);
                Ok(())
            })?;
            m.entry(1, |e| {
                e.bytes(&self.vault_id.0);
                Ok(())
            })?;
            m.entry(2, |e| {
                e.uint(u64::from(self.key_generation.0));
                Ok(())
            })?;
            m.entry(3, |e| {
                e.uint(self.local_seq);
                Ok(())
            })?;
            m.entry(4, |e| {
                e.bytes(&self.local_digest);
                Ok(())
            })
        })
        .map_err(|_| StoreError::Internal)?;
        Ok(e.finish().map_err(|_| StoreError::Internal)?.to_vec())
    }

    fn decode(input: &[u8]) -> Result<Self, StoreError> {
        let mut d = Decoder::new(input).map_err(malformed)?;
        let (mut format, mut vault_id, mut generation, mut seq, mut digest) =
            (None, None, None, None, None);
        for _ in 0..d.map().map_err(malformed)? {
            match d.int().map_err(malformed)? {
                0 => format = Some(d.uint().map_err(malformed)?),
                1 => {
                    let b: [u8; 16] = d
                        .bytes()
                        .map_err(malformed)?
                        .try_into()
                        .map_err(malformed)?;
                    vault_id = Some(VaultId::from_bytes(b)?);
                }
                2 => generation = Some(d.uint().map_err(malformed)?),
                3 => seq = Some(d.uint().map_err(malformed)?),
                4 => {
                    let b: [u8; 32] = d
                        .bytes()
                        .map_err(malformed)?
                        .try_into()
                        .map_err(malformed)?;
                    digest = Some(b);
                }
                _ => return Err(StoreError::Unsupported),
            }
        }
        d.finish().map_err(malformed)?;
        if format.ok_or(StoreError::Integrity)? != ANCHOR_FORMAT {
            return Err(StoreError::Unsupported);
        }
        let generation = u32::try_from(generation.ok_or(StoreError::Integrity)?)
            .ok()
            .filter(|&g| g > 0)
            .ok_or(StoreError::Integrity)?;
        Ok(Self {
            vault_id: vault_id.ok_or(StoreError::Integrity)?,
            key_generation: KeyGeneration(generation),
            local_seq: seq.filter(|&s| s > 0).ok_or(StoreError::Integrity)?,
            local_digest: digest.ok_or(StoreError::Integrity)?,
        })
    }
}

/// A private directory of anchor files.
#[derive(Clone)]
pub struct AnchorDir {
    path: PathBuf,
}

impl core::fmt::Debug for AnchorDir {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AnchorDir(..)")
    }
}

fn hex(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

impl AnchorDir {
    /// Opens `dir`, creating it (and missing parents) with mode 0700 if it
    /// does not exist. It must be a real directory (not a symlink) owned by
    /// the effective UID that no one else can write
    /// ([`StoreError::UnsafeFile`] otherwise).
    pub fn open(dir: &Path) -> Result<AnchorDir, StoreError> {
        match std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
        {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(StoreError::Io),
        }
        fs::check_private_dir(dir)?;
        Ok(AnchorDir {
            path: dir.to_owned(),
        })
    }

    /// The directory's path (as given to [`Self::open`]).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The default anchor directory on Linux: `$XDG_STATE_HOME/quickvault/
    /// anchors` if `XDG_STATE_HOME` is an absolute path, else
    /// `$HOME/.local/state/quickvault/anchors`. [`StoreError::NotFound`]
    /// without a usable home directory; [`StoreError::Unsupported`] on
    /// Android until the platform layer provides its directory (phase 2.3).
    pub fn default_dir() -> Result<PathBuf, StoreError> {
        Self::default_dir_from(std::env::var_os("XDG_STATE_HOME"), std::env::var_os("HOME"))
    }

    fn default_dir_from(
        xdg_state: Option<OsString>,
        home: Option<OsString>,
    ) -> Result<PathBuf, StoreError> {
        if cfg!(target_os = "android") {
            return Err(StoreError::Unsupported);
        }
        let absolute = |v: Option<OsString>| v.map(PathBuf::from).filter(|p| p.is_absolute());
        let base = match absolute(xdg_state) {
            Some(p) => p,
            None => absolute(home)
                .ok_or(StoreError::NotFound)?
                .join(".local")
                .join("state"),
        };
        Ok(base.join("quickvault").join("anchors"))
    }

    fn file(&self, replica: &[u8; 16]) -> PathBuf {
        self.path.join(format!("{}.anchor", hex(replica)))
    }

    /// Reads the anchor of `replica`; `None` if there is none.
    pub(crate) fn load(&self, replica: &[u8; 16]) -> Result<Option<Anchor>, StoreError> {
        let fd = match open(
            self.file(replica),
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NOCTTY | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::LOOP | Errno::NXIO | Errno::ISDIR) => return Err(StoreError::UnsafeFile),
            Err(e) => return Err(errno_err(e)),
        };
        let st = fstat(&fd).map_err(errno_err)?;
        if !fs::is_owner_only(&st) {
            return Err(StoreError::UnsafeFile);
        }
        if u64::try_from(st.st_size).map_or(true, |n| n > MAX_ANCHOR_BYTES as u64) {
            return Err(StoreError::Integrity);
        }
        let mut buf = Vec::with_capacity(MAX_ANCHOR_BYTES + 1);
        std::fs::File::from(fd)
            .take(MAX_ANCHOR_BYTES as u64 + 1)
            .read_to_end(&mut buf)
            .map_err(|_| StoreError::Io)?;
        if buf.len() > MAX_ANCHOR_BYTES {
            return Err(StoreError::Integrity);
        }
        Anchor::decode(&buf).map(Some)
    }

    /// Atomically replaces the anchor of `replica`.
    pub(crate) fn store(&self, replica: &[u8; 16], anchor: &Anchor) -> Result<(), StoreError> {
        let bytes = anchor.encode()?;
        let suffix = qv_crypto::random_array::<8>().map_err(|_| StoreError::Rng)?;
        let mut temp_suffix = [0u8; 16];
        temp_suffix[..8].copy_from_slice(&suffix);
        let temp = self.path.join(format!(
            ".{}.anchor.tmp-{}",
            hex(replica),
            &hex(&temp_suffix)[..16]
        ));
        let fd = open(
            &temp,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(errno_err)?;
        let written = (|| {
            let mut f = std::fs::File::from(fd);
            f.write_all(&bytes).map_err(|_| StoreError::Io)?;
            fsync(&f).map_err(errno_err)?;
            drop(f);
            point(CrashPoint::AnchorTempWritten)?;
            rename(&temp, self.file(replica)).map_err(errno_err)
        })();
        if let Err(e) = written {
            fs::remove_best_effort(&temp);
            return Err(e);
        }
        point(CrashPoint::AnchorReplaced)?;
        fs::sync_dir(&self.path)
    }

    /// Removes the anchor of `replica`, best effort (cleanup after a failed
    /// `create`).
    pub(crate) fn remove_best_effort(&self, replica: &[u8; 16]) {
        fs::remove_best_effort(&self.file(replica));
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};
    use crate::header::tests::v4;

    pub(crate) fn sample() -> Anchor {
        Anchor {
            vault_id: VaultId(v4(1)),
            key_generation: KeyGeneration(1),
            local_seq: 3,
            local_digest: [4; 32],
        }
    }

    #[test]
    fn anchor_store_and_load() {
        let d = TestDir::new();
        let dir = AnchorDir::open(&d.join("a/b/anchors")).unwrap();
        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
        let r = [7u8; 16];
        assert_eq!(dir.load(&r).unwrap(), None);
        dir.store(&r, &sample()).unwrap();
        assert_eq!(dir.load(&r).unwrap(), Some(sample()));
        let mut next = sample();
        next.local_seq = 4;
        dir.store(&r, &next).unwrap();
        assert_eq!(dir.load(&r).unwrap(), Some(next));
        // One file, 0600, no temp files left.
        let names: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![OsString::from(format!("{}.anchor", hex(&r)))]);
        let f = dir.file(&r);
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Replicas are separate.
        assert_eq!(dir.load(&[8; 16]).unwrap(), None);
        dir.remove_best_effort(&r);
        assert_eq!(dir.load(&r).unwrap(), None);
        assert_eq!(format!("{dir:?}"), "AnchorDir(..)");
    }

    #[test]
    fn anchor_file_rejections() {
        let d = TestDir::new();
        let dir = AnchorDir::open(&d.join("anchors")).unwrap();
        let r = [7u8; 16];
        let f = dir.file(&r);
        let good = sample().encode().unwrap();
        // 0644.
        write_file(&f, &good, 0o644);
        assert_eq!(dir.load(&r), Err(StoreError::UnsafeFile));
        std::fs::remove_file(&f).unwrap();
        // A symlink to a good file.
        let target = d.join("target");
        write_file(&target, &good, 0o600);
        std::os::unix::fs::symlink(&target, &f).unwrap();
        assert_eq!(dir.load(&r), Err(StoreError::UnsafeFile));
        std::fs::remove_file(&f).unwrap();
        // Too long.
        write_file(&f, &[0u8; MAX_ANCHOR_BYTES + 1], 0o600);
        assert_eq!(dir.load(&r), Err(StoreError::Integrity));
        std::fs::remove_file(&f).unwrap();
        // An unknown key, a wrong format, garbage.
        let raw = |entries: &[(i64, u64)]| {
            let mut e = Encoder::new();
            e.map(|m| {
                for &(k, v) in entries {
                    m.entry(k, |e| {
                        e.uint(v);
                        Ok(())
                    })?;
                }
                Ok(())
            })
            .unwrap();
            e.finish().unwrap().to_vec()
        };
        let mut unknown = good.clone();
        unknown[0] += 1; // one more map entry
        unknown.extend_from_slice(&[0x05, 0x00]);
        write_file(&f, &unknown, 0o600);
        assert_eq!(dir.load(&r), Err(StoreError::Unsupported));
        std::fs::remove_file(&f).unwrap();
        write_file(&f, &raw(&[(0, 1)]), 0o600);
        assert_eq!(dir.load(&r), Err(StoreError::Unsupported));
        std::fs::remove_file(&f).unwrap();
        write_file(&f, &raw(&[(0, ANCHOR_FORMAT)]), 0o600);
        assert_eq!(dir.load(&r), Err(StoreError::Integrity));
        std::fs::remove_file(&f).unwrap();
        write_file(&f, b"not cbor", 0o600);
        assert_eq!(dir.load(&r), Err(StoreError::Integrity));
        std::fs::remove_file(&f).unwrap();
        // A directory at the anchor's name.
        std::fs::create_dir(&f).unwrap();
        assert_eq!(dir.load(&r), Err(StoreError::UnsafeFile));
    }

    #[test]
    fn anchor_dir_rejections() {
        let d = TestDir::new();
        let shared = d.subdir("shared", 0o770);
        assert_eq!(AnchorDir::open(&shared).err(), Some(StoreError::UnsafeFile));
        let world = d.subdir("world", 0o1777);
        assert_eq!(AnchorDir::open(&world).err(), Some(StoreError::UnsafeFile));
        let real = d.subdir("real", 0o700);
        let link = d.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(AnchorDir::open(&link).err(), Some(StoreError::UnsafeFile));
        let file = d.join("file");
        write_file(&file, b"", 0o600);
        assert!(AnchorDir::open(&file).is_err());
        // Readable by others is fine; writable is not.
        let readable = d.subdir("readable", 0o755);
        assert!(AnchorDir::open(&readable).is_ok());
    }

    #[test]
    fn anchor_default_dir() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            AnchorDir::default_dir_from(os("/state"), os("/home/u")).unwrap(),
            PathBuf::from("/state/quickvault/anchors")
        );
        // A relative XDG_STATE_HOME is ignored (XDG base directory spec).
        assert_eq!(
            AnchorDir::default_dir_from(os("rel"), os("/home/u")).unwrap(),
            PathBuf::from("/home/u/.local/state/quickvault/anchors")
        );
        assert_eq!(
            AnchorDir::default_dir_from(None, os("/home/u")).unwrap(),
            PathBuf::from("/home/u/.local/state/quickvault/anchors")
        );
        assert_eq!(
            AnchorDir::default_dir_from(None, os("relative")).err(),
            Some(StoreError::NotFound)
        );
        assert_eq!(
            AnchorDir::default_dir_from(None, None).err(),
            Some(StoreError::NotFound)
        );
    }
}
