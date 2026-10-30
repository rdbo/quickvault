// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rotation intent excludes ordinary access, even if the active path is absent.
//! The marker is an untrusted hint to stop, never permission to open a sibling
//! or to reset an anchor. The resumed installation workflow comes in 1.15b.
use std::path::Path;

use crate::{StoreError, error::errno_err, fs};

/// The text every rotation sibling name contains: the marker
/// `<vault>.qvrotate`, the replacement `<vault>.qvrotate-new-<32 hex>`, the
/// retained `<vault>.qvrotate-old-<32 hex>` and their temporary names.
pub(crate) const RESERVED: &str = ".qvrotate";

/// Any existing marker blocks ordinary access, and so does a path that is
/// itself a reserved rotation name: an orphaned replacement or a retained old
/// copy shares the active replica's anchor, so an ordinary unlock could advance
/// or fork it. Do not follow the marker or parse it. A dangling symlink,
/// directory or truncated marker must also fail closed.
pub(crate) fn check(path: &Path) -> Result<(), StoreError> {
    if is_reserved(path) {
        return Err(StoreError::Integrity);
    }
    check_marker(path)
}

/// Whether the file name of `path` is a reserved rotation name.
pub(crate) fn is_reserved(path: &Path) -> bool {
    path.file_name().is_some_and(|n| {
        n.as_encoded_bytes()
            .windows(RESERVED.len())
            .any(|w| w == RESERVED.as_bytes())
    })
}

/// The two rotation siblings of a vault path (plan 0021 names).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sibling {
    /// `<name>.qvrotate-old-<32 hex>`: the retained previous generation.
    Old,
    /// `<name>.qvrotate-new-<32 hex>`: the verified candidate.
    New,
}

/// `<vault>.qvrotate`: the rotation journal, which is also the marker.
pub(crate) fn marker(path: &Path) -> std::path::PathBuf {
    fs::with_suffix(path, RESERVED)
}

/// A sibling name, built only from the vault path and the 16-byte suffix.
pub(crate) fn sibling(path: &Path, which: Sibling, suffix: &[u8; 16]) -> std::path::PathBuf {
    let kind = match which {
        Sibling::Old => "-old-",
        Sibling::New => "-new-",
    };
    let mut name = String::from(RESERVED);
    name.push_str(kind);
    name.push_str(&crate::archive::hex32(suffix));
    fs::with_suffix(path, &name)
}

/// The marker test alone, for the rotation's own replacement file, whose name
/// is reserved on purpose.
pub(crate) fn check_marker(path: &Path) -> Result<(), StoreError> {
    match rustix::fs::lstat(fs::with_suffix(path, RESERVED)) {
        Ok(_) => Err(StoreError::Integrity),
        Err(rustix::io::Errno::NOENT) => Ok(()),
        Err(e) => Err(errno_err(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};
    use crate::vault::tests::{PASSWORD, copy_fixture, entry_version, err, kdf, pw, unlock};
    use crate::{AnchorDir, ArchiveScope, VaultFile};
    use qv_model::{RandomId, RecordId};
    use std::path::PathBuf;

    fn marker(path: &Path) -> PathBuf {
        fs::with_suffix(path, RESERVED)
    }
    fn anchors(a: &AnchorDir) -> Vec<(PathBuf, Vec<u8>)> {
        let mut rows: Vec<_> = std::fs::read_dir(a.path())
            .unwrap()
            .map(|e| {
                let path = e.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect();
        rows.sort();
        rows
    }

    #[test]
    fn rotation_guard_refuses_every_marker_kind_before_sqlite() {
        for kind in 0..4 {
            let d = TestDir::new();
            let path = d.join("unparsed.qvault");
            let bytes = b"not a SQLite database";
            write_file(&path, bytes, 0o600);
            match kind {
                0 => write_file(&marker(&path), b"", 0o600),
                1 => write_file(&marker(&path), b"hostile or incomplete journal", 0o600),
                2 => std::fs::create_dir(marker(&path)).unwrap(),
                _ => std::os::unix::fs::symlink(d.join("absent"), marker(&path)).unwrap(),
            }
            assert_eq!(err(VaultFile::open(&path)), StoreError::Integrity);
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert!(!fs::with_suffix(&path, "-journal").exists());
            // Active name may be absent after moving the old copy aside.
            std::fs::remove_file(&path).unwrap();
            assert_eq!(err(VaultFile::open(&path)), StoreError::Integrity);
        }
    }

    #[test]
    fn rotation_guard_reserved_names_are_never_opened_created_or_restored() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (path, anchor_dir) = copy_fixture(&d, &a, "v.qvault");
        let source = unlock(&path, &anchor_dir, PASSWORD).unwrap();
        let old_anchors = anchors(&anchor_dir);
        let bytes = std::fs::read(&path).unwrap();
        for name in [
            "v.qvault.qvrotate-new-00112233445566778899aabbccddeeff",
            "v.qvault.qvrotate-old-00112233445566778899aabbccddeeff",
            ".v.qvault.qvrotate-new-00.tmp-0011223344556677",
            "x.qvrotate.qvault",
        ] {
            // A valid copy of the anchored vault under a reserved name: an
            // ordinary unlock would compare it with the shared anchor.
            let copy = d.join(name);
            write_file(&copy, &bytes, 0o600);
            assert_eq!(err(VaultFile::open(&copy)), StoreError::Integrity, "{name}");
            let lock = fs::open_existing(&copy).unwrap();
            assert_eq!(
                err(VaultFile::open_locked(&copy, lock)),
                StoreError::Integrity
            );
            assert!(!fs::with_suffix(&copy, "-journal").exists());
            std::fs::remove_file(&copy).unwrap();
        }
        let target = d.join("x.qvrotate.qvault");
        assert_eq!(
            err(VaultFile::create(
                &target,
                &pw(PASSWORD),
                "blocked",
                &anchor_dir
            )),
            StoreError::Integrity
        );
        let mut input = std::io::Cursor::new(b"must not be consumed");
        assert_eq!(
            VaultFile::create_from_archive(
                &target,
                &mut input,
                ArchiveScope::new(source.header().vault_id, source.header().key_generation),
                source.vault_key(),
                &anchor_dir,
                &|| false,
            ),
            Err(StoreError::Integrity)
        );
        assert_eq!(input.position(), 0);
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
        assert_eq!(anchors(&anchor_dir), old_anchors);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        // An ordinary name is unaffected.
        assert!(is_reserved(Path::new("/a/b.qvrotate")));
        assert!(!is_reserved(Path::new("/a.qvrotate/b.qvault")));
        assert!(source.check_identity().is_ok());
    }

    #[test]
    fn rotation_guard_checks_again_after_the_inode_lock() {
        let d = TestDir::new();
        let path = d.join("unparsed.qvault");
        write_file(&path, b"SQLite must never ingest these bytes", 0o600);
        check(&path).unwrap();
        let lock = fs::open_existing(&path).unwrap();
        write_file(&marker(&path), b"", 0o600);
        assert_eq!(
            err(VaultFile::open_locked(&path, lock)),
            StoreError::Integrity
        );
    }

    #[test]
    fn rotation_guard_missing_active_blocks_create_without_anchor_or_output() {
        let d = TestDir::new();
        let a = TestDir::new();
        let anchors = AnchorDir::open(&a.join("anchors")).unwrap();
        let path = d.join("missing.qvault");
        write_file(&marker(&path), b"", 0o600);
        assert_eq!(
            err(VaultFile::create(&path, &pw(PASSWORD), "blocked", &anchors)),
            StoreError::Integrity
        );
        assert!(!path.exists());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(anchors.path()).unwrap().count(), 0);
    }

    #[test]
    fn rotation_guard_restore_does_not_consume_input_or_touch_source() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (path, anchor_dir) = copy_fixture(&d, &a, "v.qvault");
        let source = unlock(&path, &anchor_dir, PASSWORD).unwrap();
        let target = d.join("missing.qvault");
        write_file(&marker(&target), b"", 0o600);
        let before = std::fs::read(&path).unwrap();
        let old_anchors = anchors(&anchor_dir);
        let mut input = std::io::Cursor::new(b"must not be consumed");
        assert_eq!(
            VaultFile::create_from_archive(
                &target,
                &mut input,
                ArchiveScope::new(source.header().vault_id, source.header().key_generation),
                source.vault_key(),
                &anchor_dir,
                &|| false,
            ),
            Err(StoreError::Integrity)
        );
        assert_eq!(input.position(), 0);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(anchors(&anchor_dir), old_anchors);
        assert!(!target.exists());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2);
    }

    #[test]
    fn rotation_guard_late_marker_blocks_unlock_and_mutations_without_anchor_repair() {
        let (d, a) = (TestDir::new(), TestDir::new());
        let (path, anchor_dir) = copy_fixture(&d, &a, "v.qvault");
        let before = std::fs::read(&path).unwrap();
        let old_anchors = anchors(&anchor_dir);
        let file = VaultFile::open(&path).unwrap();
        write_file(&marker(&path), b"", 0o600);
        {
            let _k = kdf();
            assert_eq!(
                err(file.unlock(&pw(PASSWORD), &anchor_dir)),
                StoreError::Integrity
            );
        }
        std::fs::remove_file(marker(&path)).unwrap();
        let mut u = unlock(&path, &anchor_dir, PASSWORD).unwrap();
        write_file(&marker(&path), b"", 0o600);
        assert_eq!(err(u.write()), StoreError::Integrity);
        assert_eq!(u.adopt_baseline(), Err(StoreError::Integrity));
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(anchors(&anchor_dir), old_anchors);
        std::fs::remove_file(marker(&path)).unwrap();
        assert!(u.verify_all(&|| false).is_ok());
    }

    #[test]
    fn rotation_guard_marker_during_write_rolls_back_before_commit() {
        for final_check in [false, true] {
            let (d, a) = (TestDir::new(), TestDir::new());
            let (path, anchor_dir) = copy_fixture(&d, &a, "v.qvault");
            let mut u = unlock(&path, &anchor_dir, PASSWORD).unwrap();
            let before = std::fs::read(&path).unwrap();
            let old_anchors = anchors(&anchor_dir);
            let root = u.manifest().root_group_id();
            let record = RecordId::generate().unwrap();
            let mut w = u.write().unwrap();
            let counter = w.reserve_counter().unwrap();
            let version = entry_version(root, "never published", w.writer_id(), counter, &[]);
            w.put_local(record, version).unwrap();
            if !final_check {
                write_file(&marker(&path), b"", 0o600);
            }
            assert_eq!(
                w.commit_cancellable(&|| {
                    // This callback runs during retention or immediately before COMMIT.
                    if final_check {
                        write_file(&marker(&path), b"", 0o600);
                    }
                    false
                }),
                Err(StoreError::Integrity)
            );
            assert_eq!(std::fs::read(&path).unwrap(), before);
            assert_eq!(anchors(&anchor_dir), old_anchors);
            assert!(!fs::with_suffix(&path, "-journal").exists());
            std::fs::remove_file(marker(&path)).unwrap();
            assert!(u.verify_all(&|| false).is_ok());
        }
    }

    #[test]
    fn rotation_guard_pending_anchor_is_not_repaired_while_marker_exists() {
        use crate::crash::{CrashPoint, test};
        let (d, a, copied) = (TestDir::new(), TestDir::new(), TestDir::new());
        let (path, anchor_dir) = copy_fixture(&d, &a, "v.qvault");
        let mut u = unlock(&path, &anchor_dir, PASSWORD).unwrap();
        let old_anchors = anchors(&anchor_dir);
        test::arm(
            CrashPoint::Committed,
            &path,
            anchor_dir.path(),
            copied.path(),
        );
        // A durable commit whose anchor reporting fails leaves AnchorPending.
        assert_eq!(u.write().unwrap().commit(), Err(StoreError::Internal));
        assert!(!test::disarm());
        assert_eq!(anchors(&anchor_dir), old_anchors);
        let committed = std::fs::read(&path).unwrap();
        write_file(&marker(&path), b"", 0o600);
        assert_eq!(err(u.write()), StoreError::Integrity);
        assert_eq!(u.adopt_baseline(), Err(StoreError::Integrity));
        assert_eq!(anchors(&anchor_dir), old_anchors);
        assert_eq!(std::fs::read(&path).unwrap(), committed);
        std::fs::remove_file(marker(&path)).unwrap();
        // Ordinary retry still repairs exactly that pending anchor afterward.
        drop(u.write().unwrap());
        assert_ne!(anchors(&anchor_dir), old_anchors);
        assert!(u.verify_all(&|| false).is_ok());
    }
}
