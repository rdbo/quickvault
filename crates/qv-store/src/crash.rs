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
    /// The new manifest row is written and the old one deleted.
    ManifestWritten,
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
        vault: PathBuf,
        anchors: PathBuf,
        snapshot: PathBuf,
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
                vault: vault.to_owned(),
                anchors: anchors.to_owned(),
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
        let name = a.vault.file_name().unwrap();
        let target = a.snapshot.join(name);
        copy_if_exists(&a.vault, &target);
        copy_if_exists(
            &with_suffix(&a.vault, "-journal"),
            &with_suffix(&target, "-journal"),
        );
        let anchors = a.snapshot.join("anchors");
        std::fs::create_dir_all(&anchors).unwrap();
        std::fs::set_permissions(
            &anchors,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        if let Ok(entries) = std::fs::read_dir(&a.anchors) {
            for e in entries {
                let e = e.unwrap();
                copy_if_exists(&e.path(), &anchors.join(e.file_name()));
            }
        }
        Err(StoreError::Internal)
    }
}
