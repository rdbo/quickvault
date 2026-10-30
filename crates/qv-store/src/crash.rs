// SPDX-License-Identifier: AGPL-3.0-or-later

//! Crash-injection points of the write path (plan 0009).
//!
//! [`point`] marks each ordering point of a mutation and of `create`. In
//! normal builds it does nothing. In this crate's tests, a point armed with
//! `test::arm` copies what a killed process would leave on disk (the vault
//! file, its `-journal` if present, and the anchor directory) into a
//! snapshot directory and then fails with [`StoreError::Internal`], so the
//! operation stops there. The test then opens the snapshot.

use crate::error::StoreError;

/// An ordering point (plan 0009, *Data and control flow*).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CrashPoint {
    /// `BEGIN IMMEDIATE` and the head re-read are done.
    Begun,
    /// The first new object row is written.
    ObjectsWritten,
    /// The complete replacement password row and header MAC are staged.
    PasswordSlotWritten,
    /// The new manifest row is written and the old one deleted.
    ManifestWritten,
    /// Incoming acceptance has staged its receipt envelope, before the head/commit.
    ReceiptsWritten,
    /// The new head is written.
    HeadWritten,
    /// The counter is updated and unreferenced objects are pruned.
    Pruned,
    /// `COMMIT` returned.
    Committed,
    /// The anchor's temp file is written and synced, not yet renamed.
    AnchorTempWritten,
    /// The anchor is renamed into place; the directory is not yet synced.
    AnchorReplaced,
    /// `create`: the temp vault is built and synced.
    CreateBuilt,
    /// `create`: the first anchor is written; the vault is not yet renamed
    /// into place.
    CreateAnchored,
    /// `publish`: the temp archive is written and re-verified with the
    /// archive reader; it is neither synced nor renamed yet.
    ArchiveVerified,
    /// `publish`: the temp archive is renamed to its published name; the
    /// snapshot directory is not yet synced.
    ArchivePublished,
    /// Rotation I1: the candidate has its reserved final name (plan 0023).
    RotationCandidateNamed,
    /// Rotation I2: the next generation's inventory is published.
    RotationInventoryPublished,
    /// Rotation I3: the journal (marker) is published.
    RotationJournalPublished,
    /// Rotation I4: the active vault has its retained old name.
    RotationActiveRetired,
    /// Rotation I5: the candidate is at the active name.
    RotationInstalled,
    /// Rotation I6: the anchor names the new head.
    RotationAnchored,
    /// Rotation I7: the retained old vault is removed.
    RotationOldRemoved,
    /// Rotation I8: the superseded inventory is removed.
    RotationInventoryRetired,
    /// Rotation I9 (and rollback's last step): the journal is removed.
    RotationJournalRemoved,
    /// Rollback: the installed new vault is back at its candidate name.
    RollbackNewRetired,
    /// Rollback: the old vault is back at the active name.
    RollbackOldRestored,
    /// Rollback: the candidate is removed.
    RollbackCandidateRemoved,
    /// Rollback: the unused next-generation inventory is removed.
    RollbackInventoryRemoved,
}

/// Marks an ordering point.
pub(crate) fn point(p: CrashPoint) -> Result<(), StoreError> {
    #[cfg(test)]
    {
        test::hit(p)
    }
    #[cfg(not(test))]
    {
        let _ = p;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use std::cell::RefCell;
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::fs::with_suffix;

    struct Armed {
        point: CrashPoint,
        copy: Copy,
        snapshot: PathBuf,
    }

    /// What a killed process would leave behind, per kind of operation.
    enum Copy {
        /// A mutation or `create`: the vault file, its journal and the anchor
        /// directory.
        Vault { vault: PathBuf, anchors: PathBuf },
        /// `publish`: every file of one directory (the snapshot directory).
        Dir(PathBuf),
        /// Rotation: every file of several directories, each copied into
        /// `snapshot/<label>`.
        Dirs(Vec<(PathBuf, String)>),
    }

    thread_local! {
        static ARMED: RefCell<Option<Armed>> = const { RefCell::new(None) };
    }

    /// Arms `point` for the current thread. When reached, `vault` (its final
    /// path), its journal and every file in `anchors` are copied into
    /// `snapshot` (the vault and journal under their own names, the anchors
    /// under `snapshot/anchors`).
    pub(crate) fn arm(point: CrashPoint, vault: &Path, anchors: &Path, snapshot: &Path) {
        ARMED.with(|a| {
            *a.borrow_mut() = Some(Armed {
                point,
                copy: Copy::Vault {
                    vault: vault.to_owned(),
                    anchors: anchors.to_owned(),
                },
                snapshot: snapshot.to_owned(),
            });
        });
    }

    /// Arms `point` for the current thread. When reached, every file in `dir`
    /// (the snapshot directory) is copied into `snapshot`.
    pub(crate) fn arm_dir(point: CrashPoint, dir: &Path, snapshot: &Path) {
        ARMED.with(|a| {
            *a.borrow_mut() = Some(Armed {
                point,
                copy: Copy::Dir(dir.to_owned()),
                snapshot: snapshot.to_owned(),
            });
        });
    }

    /// Arms `point` for the current thread. When reached, every file of each
    /// directory is copied into `snapshot/<label>` (0700).
    pub(crate) fn arm_dirs(point: CrashPoint, dirs: &[(&Path, &str)], snapshot: &Path) {
        ARMED.with(|a| {
            *a.borrow_mut() = Some(Armed {
                point,
                copy: Copy::Dirs(
                    dirs.iter()
                        .map(|(d, l)| ((*d).to_owned(), (*l).to_owned()))
                        .collect(),
                ),
                snapshot: snapshot.to_owned(),
            });
        });
    }

    /// Disarms without firing; `true` if the armed point was never reached.
    pub(crate) fn disarm() -> bool {
        ARMED.with(|a| a.borrow_mut().take().is_some())
    }

    fn copy_if_exists(from: &Path, to: &Path) {
        if from.exists() {
            std::fs::copy(from, to).unwrap();
        }
    }

    /// Copies every regular file of `dir` into `to` (created 0700), keeping
    /// modes so owner-only checks still pass on the copy.
    fn copy_dir(dir: &Path, to: &Path) {
        std::fs::create_dir_all(to).unwrap();
        std::fs::set_permissions(to, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        if let Ok(entries) = std::fs::read_dir(dir) {
            for e in entries {
                let e = e.unwrap();
                if e.file_type().unwrap().is_file() {
                    copy_if_exists(&e.path(), &to.join(e.file_name()));
                }
            }
        }
    }

    pub(super) fn hit(p: CrashPoint) -> Result<(), StoreError> {
        let armed = ARMED.with(|a| {
            let mut a = a.borrow_mut();
            if a.as_ref().is_some_and(|x| x.point == p) {
                a.take()
            } else {
                None
            }
        });
        let Some(a) = armed else {
            return Ok(());
        };
        match &a.copy {
            Copy::Vault { vault, anchors } => {
                let name = vault.file_name().unwrap();
                let target = a.snapshot.join(name);
                copy_if_exists(vault, &target);
                copy_if_exists(
                    &with_suffix(vault, "-journal"),
                    &with_suffix(&target, "-journal"),
                );
                let dir = a.snapshot.join("anchors");
                std::fs::create_dir_all(&dir).unwrap();
                std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
                    .unwrap();
                if let Ok(entries) = std::fs::read_dir(anchors) {
                    for e in entries {
                        let e = e.unwrap();
                        copy_if_exists(&e.path(), &dir.join(e.file_name()));
                    }
                }
            }
            Copy::Dir(dir) => copy_dir(dir, &a.snapshot),
            Copy::Dirs(dirs) => {
                for (dir, label) in dirs {
                    copy_dir(dir, &a.snapshot.join(label));
                }
            }
        }
        Err(StoreError::Internal)
    }
}
