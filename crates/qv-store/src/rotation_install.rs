// SPDX-License-Identifier: AGPL-3.0-or-later

//! Installation and restart of an offline VK rotation (0002 §3.5.4; plan
//! 0023, roadmap 1.15c).
//!
//! [`PreparedRotation::install`] publishes a verified replacement through the
//! bounded journal of plan 0021: name the candidate, publish the next
//! generation's snapshot inventory and the journal (`<vault>.qvrotate`, which
//! is also the marker that blocks ordinary access), move the active vault to
//! its retained old name and the candidate to the active name, advance the
//! shared anchor by its one generation step, then remove the old vault, the
//! superseded inventory and, last, the journal.
//!
//! [`InterruptedRotation`] resumes a transition after a crash. It reads the
//! locked journal, authenticates every copy it relies on with that copy's own
//! credential, checks both the copies' heads and the journal's MAC of each
//! side, compares the anchor and only then completes or rolls back. No file
//! is renamed or removed on the strength of names or unauthenticated bytes:
//! the one exception is the cleanup of a committed transition (the anchor
//! already names the authenticated new head), which removes the retained old
//! copy named by the authenticated journal without unlocking it.
//!
//! | State | Files | Anchor | Complete | Roll back |
//! |-------|-------|--------|----------|-----------|
//! | [`RotationState::CandidateReady`] | active = old, `-new-` | old | I4–I9 | remove candidate, inventory, journal |
//! | [`RotationState::ActiveRetired`] | `-old-`, `-new-` | old | I5–I9 | old → active, then as above |
//! | [`RotationState::AnchorPending`] | active = new, `-old-` | old | I6–I9 | new → `-new-`, old → active, then as above |
//! | [`RotationState::Committed`] | active = new, `-old-` optional | new | I7–I9 | refused (generation regression) |
//! | [`RotationState::RollbackPending`] | active = old | old | refused (no candidate) | remove inventory, journal |

/// What is on disk for an authenticated interrupted transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationState {
    /// The old vault is active and the verified candidate waits at its
    /// reserved name; the anchor names the old head.
    CandidateReady,
    /// The active path is missing: the old vault is at its retained name and
    /// the candidate at its reserved name; the anchor names the old head.
    ActiveRetired,
    /// The new vault is active, the old one retained; the anchor still names
    /// the old head.
    AnchorPending,
    /// The new vault is active and the anchor names its head: the rotation
    /// committed and only cleanup remains.
    Committed,
    /// A rollback was interrupted after the candidate was removed: the old
    /// vault is active and only the journal and unused inventory remain.
    RollbackPending,
}

/// How to finish an interrupted transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RotationChoice {
    /// Install the new generation (or finish its cleanup).
    Complete,
    /// Return to the old generation; refused once committed.
    RollBack,
}

/// Which master passwords an interrupted transition needs, from a reading of
/// unauthenticated headers and the anchor. A prompt hint only: it authorizes
/// nothing, and [`InterruptedRotation::open`] authenticates everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeededPasswords {
    /// The old generation's password.
    pub old: bool,
    /// The new generation's password.
    pub new: bool,
}

/// A completed installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Installed {
    /// The vault's generation now.
    pub new_generation: qv_crypto::KeyGeneration,
    /// The anchor advanced and the rotation committed, but the retained old
    /// vault, the superseded inventory or the journal could not be removed.
    /// The next `recovery rotate` finishes that with the new password.
    pub cleanup_pending: bool,
}

/// A failed installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallError {
    /// What failed.
    pub error: crate::StoreError,
    /// Whether the journal was already published: the transition is then
    /// recoverable only through [`InterruptedRotation`], and the frontend
    /// must say that the rotation may be partly applied.
    pub journal_published: bool,
}

/// Inert leftovers of a rotation that crashed before its journal existed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Leftovers {
    /// Candidate, temporary and unused-inventory files removed.
    pub removed: usize,
    /// `-old-` siblings found and kept (never removed without a journal).
    pub retained_old: usize,
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use platform::{InterruptedRotation, needed_passwords, rotation_pending};

#[cfg(any(target_os = "linux", target_os = "android"))]
mod platform {
    use std::path::{Path, PathBuf};

    use qv_crypto::{KeyGeneration, MasterPassword};
    use qv_model::{RandomId, VersionId};

    use super::*;
    use crate::archive::SnapshotDir;
    use crate::crash::{CrashPoint, point};
    use crate::error::errno_err;
    use crate::fs::{self, LockedFile};
    use crate::head::compare;
    use crate::rotation_guard::{self, Sibling};
    use crate::slot::password_slot;
    use crate::vault::{FileRole, anchor_of};
    use crate::{
        AnchorDir, AnchorStatus, MAX_ROTATION_JOURNAL_BYTES, PreparedRotation, RotationJournal,
        RotationJournalBody, RotationSide, SnapshotInventory, StoreError, UnlockedVault, VaultFile,
    };

    fn check_cancel(cancelled: &dyn Fn() -> bool) -> Result<(), StoreError> {
        if cancelled() {
            Err(StoreError::Io)
        } else {
            Ok(())
        }
    }

    /// The four names of one transition, derived only from the active path
    /// and the journal's 16-byte suffix.
    pub(super) struct Paths {
        pub(super) active: PathBuf,
        pub(super) marker: PathBuf,
        pub(super) old: PathBuf,
        pub(super) new: PathBuf,
    }

    impl Paths {
        pub(super) fn of(active: &Path, suffix: &[u8; 16]) -> Self {
            Paths {
                active: active.to_owned(),
                marker: rotation_guard::marker(active),
                old: rotation_guard::sibling(active, Sibling::Old, suffix),
                new: rotation_guard::sibling(active, Sibling::New, suffix),
            }
        }

        fn dir(&self) -> &Path {
            fs::parent_of(&self.active)
        }
    }

    /// Whether `path` exists (lstat; never followed).
    fn exists(path: &Path) -> Result<bool, StoreError> {
        match rustix::fs::lstat(path) {
            Ok(_) => Ok(true),
            Err(rustix::io::Errno::NOENT) => Ok(false),
            Err(e) => Err(errno_err(e)),
        }
    }

    /// Removes a regular file (never a symlink or directory) and its SQLite
    /// `-journal` if any. Absent is Ok.
    fn remove_regular(path: &Path) -> Result<(), StoreError> {
        match rustix::fs::lstat(path) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(e) => return Err(errno_err(e)),
            Ok(st) => {
                if rustix::fs::FileType::from_raw_mode(st.st_mode)
                    != rustix::fs::FileType::RegularFile
                {
                    return Err(StoreError::UnsafeFile);
                }
                std::fs::remove_file(path).map_err(|_| StoreError::Io)?;
            }
        }
        let journal = fs::with_suffix(path, "-journal");
        if exists(&journal)? {
            std::fs::remove_file(&journal).map_err(|_| StoreError::Io)?;
        }
        Ok(())
    }

    /// Whether `<path>.qvrotate` exists (lstat only, never followed or
    /// parsed): an ordinary open of `path` is then refused, and the frontend
    /// offers `recovery rotate`.
    pub fn rotation_pending(path: &Path) -> Result<bool, StoreError> {
        exists(&rotation_guard::marker(path))
    }

    /// Opens and locks the journal of `path`, then decodes it (syntax only;
    /// the MACs are checked against each authenticated copy).
    fn read_marker(path: &Path) -> Result<(LockedFile, RotationJournal), StoreError> {
        if rotation_guard::is_reserved(path) {
            return Err(StoreError::Integrity);
        }
        let marker = rotation_guard::marker(path);
        let lock = fs::open_existing(&marker)?;
        let bytes = lock.read_bounded(MAX_ROTATION_JOURNAL_BYTES)?;
        let journal = RotationJournal::decode(&bytes)?;
        Ok((lock, journal))
    }

    /// The kind of a directory entry next to the vault named `vault`.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Leftover {
        Removable,
        Old,
    }

    fn is_hex(b: &[u8], n: usize) -> bool {
        b.len() == n && b.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    }

    /// Matches the exact reserved patterns of plans 0021–0023:
    /// `N.qvrotate-new-<32>`, `.N.qvrotate-new-<32>.tmp-<16>`,
    /// `.N.qvrotate.tmp-<16>` (each optionally `-journal`) are removable;
    /// `N.qvrotate-old-<32>[-journal]` is an old copy.
    pub(super) fn classify(vault: &[u8], entry: &[u8]) -> Option<Leftover> {
        let entry = entry.strip_suffix(b"-journal").unwrap_or(entry);
        if let Some(rest) = entry.strip_prefix(vault) {
            if let Some(h) = rest.strip_prefix(b".qvrotate-new-") {
                return is_hex(h, 32).then_some(Leftover::Removable);
            }
            if let Some(h) = rest.strip_prefix(b".qvrotate-old-") {
                return is_hex(h, 32).then_some(Leftover::Old);
            }
            return None;
        }
        let rest = entry.strip_prefix(b".")?.strip_prefix(vault)?;
        if let Some(r) = rest.strip_prefix(b".qvrotate-new-") {
            let (h, t) = (r.get(..32)?, r.get(32..)?);
            let t = t.strip_prefix(b".tmp-")?;
            return (is_hex(h, 32) && is_hex(t, 16)).then_some(Leftover::Removable);
        }
        let t = rest.strip_prefix(b".qvrotate.tmp-")?;
        is_hex(t, 16).then_some(Leftover::Removable)
    }

    impl UnlockedVault {
        /// Removes the inert leftovers of a rotation that crashed before its
        /// journal was published: candidates, their temporary files and
        /// `-journal` siblings, temporary journals, and the unused inventory
        /// of the next generation. Counts `-old-` siblings but never touches
        /// them. Refuses while a marker exists (its identity check), and on
        /// sessions that are not ordinary.
        pub fn remove_rotation_leftovers(
            &self,
            snapshots: &SnapshotDir,
        ) -> Result<Leftovers, StoreError> {
            if self.file.role != FileRole::Ordinary {
                return Err(StoreError::Internal);
            }
            self.check_identity()?;
            let path = self.file.path();
            let vault = path
                .file_name()
                .ok_or(StoreError::Internal)?
                .as_encoded_bytes();
            let dir = fs::parent_of(path);
            let mut found = Leftovers::default();
            for entry in std::fs::read_dir(dir).map_err(|_| StoreError::Io)? {
                let entry = entry.map_err(|_| StoreError::Io)?;
                let name = entry.file_name();
                match classify(vault, name.as_encoded_bytes()) {
                    Some(Leftover::Removable) => {
                        let st = rustix::fs::lstat(entry.path()).map_err(errno_err)?;
                        if rustix::fs::FileType::from_raw_mode(st.st_mode)
                            != rustix::fs::FileType::RegularFile
                        {
                            return Err(StoreError::UnsafeFile);
                        }
                        std::fs::remove_file(entry.path()).map_err(|_| StoreError::Io)?;
                        found.removed += 1;
                    }
                    Some(Leftover::Old) => found.retained_old += 1,
                    None => {}
                }
            }
            if found.removed > 0 {
                fs::sync_dir(dir)?;
            }
            let h = self.header();
            if let Some(next) = h.key_generation.0.checked_add(1).map(KeyGeneration) {
                let inventory = snapshots
                    .path()
                    .join(crate::snapshot_inventory::file_name(h.vault_id, next));
                if exists(&inventory)? {
                    snapshots.remove_inventory(h.vault_id, next)?;
                    found.removed += 1;
                }
            }
            Ok(found)
        }
    }

    /// I6: advances the anchor of `new` by its one generation step.
    fn advance_anchor(new: &UnlockedVault, anchors: &AnchorDir) -> Result<(), StoreError> {
        let replica = new.state.replica.replica_id;
        let anchor = anchors.load(&replica)?;
        match compare(&new.state.head, &new.state.digest, anchor.as_ref()) {
            AnchorStatus::Advanced => {}
            AnchorStatus::Missing => return Err(StoreError::NoAnchor),
            _ => return Err(StoreError::Rollback),
        }
        anchors.store(&replica, &anchor_of(&new.state))
    }

    /// I7–I9: after the anchor names the new head. `old` is the retained old
    /// copy if it is open (its identity is checked before removal). `marker`
    /// owns the journal's locked descriptor and is dropped after its removal.
    fn cleanup<M>(
        paths: &Paths,
        old: Option<UnlockedVault>,
        snapshots: &SnapshotDir,
        vault_id: qv_crypto::VaultId,
        old_generation: KeyGeneration,
        marker: M,
    ) -> Result<(), StoreError> {
        if let Some(old) = &old {
            old.file.check_identity()?;
        }
        if exists(&paths.old)? {
            remove_regular(&paths.old)?;
            fs::sync_dir(paths.dir())?;
        }
        drop(old);
        point(CrashPoint::RotationOldRemoved)?;
        snapshots.remove_inventory(vault_id, old_generation)?;
        point(CrashPoint::RotationInventoryRetired)?;
        std::fs::remove_file(&paths.marker).map_err(|_| StoreError::Io)?;
        fs::sync_dir(paths.dir())?;
        drop(marker);
        point(CrashPoint::RotationJournalRemoved)
    }

    /// Rollback's tail: the candidate (if present), the unused inventory of
    /// the new generation, then the journal.
    fn roll_back_tail<M>(
        paths: &Paths,
        candidate: Option<UnlockedVault>,
        snapshots: &SnapshotDir,
        vault_id: qv_crypto::VaultId,
        new_generation: KeyGeneration,
        marker: M,
    ) -> Result<(), StoreError> {
        if let Some(c) = &candidate {
            c.file.check_identity()?;
            remove_regular(&paths.new)?;
            fs::sync_dir(paths.dir())?;
        }
        drop(candidate);
        point(CrashPoint::RollbackCandidateRemoved)?;
        snapshots.remove_inventory(vault_id, new_generation)?;
        point(CrashPoint::RollbackInventoryRemoved)?;
        std::fs::remove_file(&paths.marker).map_err(|_| StoreError::Io)?;
        fs::sync_dir(paths.dir())?;
        drop(marker);
        point(CrashPoint::RotationJournalRemoved)
    }

    /// Writes the journal at the marker name: temporary file, fsync, re-read,
    /// `RENAME_NOREPLACE`. The caller syncs the directory once it treats the
    /// journal as published: after the rename succeeded the transition
    /// exists, whatever that fsync returns. The returned descriptor holds
    /// the marker's lock for the rest of the installation.
    fn publish_marker(marker: &Path, bytes: &[u8]) -> Result<std::fs::File, StoreError> {
        use std::io::Write as _;
        let (locked, temp) = fs::create_temp(marker)?;
        let written = (|| {
            let mut file = locked.into_file();
            file.write_all(bytes).map_err(|_| StoreError::Io)?;
            rustix::fs::fsync(&file).map_err(errno_err)?;
            let mut back = Vec::with_capacity(bytes.len());
            std::io::Read::read_to_end(
                &mut std::io::Read::take(
                    fs::open_private_ro(&temp)?,
                    MAX_ROTATION_JOURNAL_BYTES as u64 + 1,
                ),
                &mut back,
            )
            .map_err(|_| StoreError::Io)?;
            if back != bytes {
                return Err(StoreError::Integrity);
            }
            fs::rename_noreplace(&temp, marker)?;
            Ok(file)
        })();
        written.inspect_err(|_| fs::remove_best_effort(&temp))
    }

    impl PreparedRotation {
        /// Publishes this verified replacement (plan 0023 steps I0–I9).
        ///
        /// `inventory` is `snapshots.prepare_inventory(&self, ..)` and
        /// `snapshot_id` the old generation's pinned recovery snapshot.
        /// Before the journal is published an error leaves the active vault
        /// and anchor unchanged and removes the candidate and inventory
        /// (best effort). Cancellation is honoured only until then. Once the
        /// journal exists, the sequence runs to completion or to its first
        /// error, which leaves a transition for [`InterruptedRotation`].
        /// After the anchor advanced, a cleanup failure is success with
        /// [`Installed::cleanup_pending`].
        pub fn install(
            self,
            snapshots: &SnapshotDir,
            inventory: &SnapshotInventory,
            snapshot_id: [u8; 16],
            cancelled: &dyn Fn() -> bool,
        ) -> Result<Installed, InstallError> {
            let pre = |error| InstallError {
                error,
                journal_published: false,
            };
            let post = |error| InstallError {
                error,
                journal_published: true,
            };
            let PreparedRotation {
                mut replacement,
                _cleanup: mut unpublished,
                mut source,
                phrase,
                suffix,
            } = self;
            drop(phrase);
            let header = *source.header();
            let new_generation = replacement.header().key_generation;
            let paths = Paths::of(source.file.path(), &suffix);

            // I0: nothing changed since preparation.
            let checked = (|| {
                check_cancel(cancelled)?;
                if inventory.vault_id() != header.vault_id
                    || inventory.generation() != new_generation
                {
                    return Err(StoreError::Internal);
                }
                source.check_identity()?;
                replacement.file.check_identity()?;
                source.begin_read()?;
                source.end_read()?;
                let anchor = source.anchors.load(&source.state.replica.replica_id)?;
                match compare(&source.state.head, &source.state.digest, anchor.as_ref()) {
                    AnchorStatus::Verified => Ok(()),
                    AnchorStatus::Missing => Err(StoreError::NoAnchor),
                    _ => Err(StoreError::Rollback),
                }
            })();
            checked.map_err(pre)?;

            // I1: the candidate's reserved final name.
            replacement.file.relocate(&paths.new).map_err(pre)?;
            unpublished.0 = Some(paths.new.clone());
            point(CrashPoint::RotationCandidateNamed).map_err(pre)?;

            // I2: the next generation's inventory.
            let published = (|| {
                check_cancel(cancelled)?;
                let digest = snapshots.publish_inventory(inventory)?;
                point(CrashPoint::RotationInventoryPublished)?;
                Ok(digest)
            })();
            let inventory_digest = match published {
                Ok(d) => d,
                Err(e) => {
                    if e != StoreError::Exists {
                        let _ = snapshots.remove_inventory(header.vault_id, new_generation);
                    }
                    return Err(pre(e));
                }
            };

            // I3: the journal. From its rename on, the transition exists.
            let journal = (|| {
                let body = RotationJournalBody {
                    operation_id: VersionId::generate()?.to_bytes(),
                    vault_id: header.vault_id,
                    replica_id: source.state.replica.replica_id,
                    old_generation: header.key_generation,
                    new_generation,
                    old_sequence: source.state.head.local_seq,
                    new_sequence: replacement.state.head.local_seq,
                    old_digest: source.state.digest,
                    new_digest: replacement.state.digest,
                    suffix,
                    snapshot_id,
                    inventory_digest,
                };
                let journal = RotationJournal::sign(body, &source.vk, &replacement.vk)?;
                let bytes = journal.encode()?;
                check_cancel(cancelled)?;
                publish_marker(&paths.marker, &bytes)
            })();
            let marker_file = match journal {
                Ok(f) => f,
                Err(e) => {
                    let _ = snapshots.remove_inventory(header.vault_id, new_generation);
                    return Err(pre(e));
                }
            };
            // The candidate now belongs to the journal: never remove it here.
            unpublished.0 = None;
            source.file.enter_transition();
            replacement.file.enter_transition();
            fs::sync_dir(paths.dir()).map_err(post)?;
            point(CrashPoint::RotationJournalPublished).map_err(post)?;

            // I4, I5: the two renames, never replacing a name.
            source.file.relocate(&paths.old).map_err(post)?;
            point(CrashPoint::RotationActiveRetired).map_err(post)?;
            replacement.file.relocate(&paths.active).map_err(post)?;
            point(CrashPoint::RotationInstalled).map_err(post)?;

            // I6: the anchor. After it the rotation is committed.
            advance_anchor(&replacement, &replacement.anchors).map_err(post)?;
            drop(replacement);
            // Committed from here: a failure is pending cleanup, not an error.
            let cleanup_pending = point(CrashPoint::RotationAnchored).is_err()
                || cleanup(
                    &paths,
                    Some(source),
                    snapshots,
                    header.vault_id,
                    header.key_generation,
                    marker_file,
                )
                .is_err();
            Ok(Installed {
                new_generation,
                cleanup_pending,
            })
        }
    }

    /// One opened copy of a transition, before or after authentication.
    struct Copy {
        file: VaultFile,
        side: RotationSide,
    }

    /// Opens a present copy with the transition role and assigns its side
    /// from its (unauthenticated) header generation.
    fn open_copy(path: &Path, body: &RotationJournalBody) -> Result<Copy, StoreError> {
        let lock = fs::open_existing(path)?;
        let file = VaultFile::open_locked_as(path, lock, FileRole::Transition)?;
        if file.header.vault_id != body.vault_id {
            return Err(StoreError::Integrity);
        }
        let side = if file.header.key_generation == body.old_generation {
            RotationSide::Old
        } else if file.header.key_generation == body.new_generation {
            RotationSide::New
        } else {
            return Err(StoreError::Integrity);
        };
        Ok(Copy { file, side })
    }

    /// Authenticates a copy with its own password: slot, header MAC, state,
    /// full verification, the journal's side digest and sequence, and that
    /// side's journal MAC.
    fn authenticate(
        copy: Copy,
        password: Option<&MasterPassword>,
        journal: &RotationJournal,
        anchors: &AnchorDir,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<UnlockedVault, StoreError> {
        let password = password.ok_or(StoreError::Integrity)?;
        let body = journal.body();
        let (generation, seq, digest) = match copy.side {
            RotationSide::Old => (body.old_generation, body.old_sequence, body.old_digest),
            RotationSide::New => (body.new_generation, body.new_sequence, body.new_digest),
        };
        copy.file.budget.reset();
        let vk = password_slot(&copy.file.slots)?.keyslot.slot.unlock(
            password,
            body.vault_id,
            generation,
        )?;
        copy.file.verify_header(&vk)?;
        let vault = copy.file.finish_candidate(vk, anchors)?;
        if vault.state.head.key_generation != generation
            || vault.state.head.local_seq != seq
            || vault.state.digest != digest
            || vault.state.head.remote.is_some()
            || vault.state.replica.replica_id != body.replica_id
        {
            return Err(StoreError::Integrity);
        }
        journal.verify(&vault.vk, copy.side)?;
        vault.verify_all(cancelled)?;
        Ok(vault)
    }

    /// The anchor status of `copy` against the journal's replica anchor.
    fn anchored(vault: &UnlockedVault, anchors: &AnchorDir) -> Result<AnchorStatus, StoreError> {
        let anchor = anchors.load(&vault.state.replica.replica_id)?;
        Ok(compare(
            &vault.state.head,
            &vault.state.digest,
            anchor.as_ref(),
        ))
    }

    /// Which copies are present: (active, old, new).
    fn present(paths: &Paths) -> Result<(bool, bool, bool), StoreError> {
        Ok((
            exists(&paths.active)?,
            exists(&paths.old)?,
            exists(&paths.new)?,
        ))
    }

    /// The prompt hint of [`NeededPasswords`], from unauthenticated bytes.
    pub fn needed_passwords(
        path: &Path,
        anchors: &AnchorDir,
    ) -> Result<NeededPasswords, StoreError> {
        let (_lock, journal) = read_marker(path)?;
        let body = journal.body();
        let paths = Paths::of(path, &body.suffix);
        let both = NeededPasswords {
            old: true,
            new: true,
        };
        match present(&paths)? {
            (true, false, false) | (true, true, false) => {
                let active = open_copy(&paths.active, body)?;
                if active.side == RotationSide::Old {
                    return Ok(NeededPasswords {
                        old: true,
                        new: false,
                    });
                }
                let anchor = anchors.load(&body.replica_id)?;
                if anchor.is_some_and(|a| a.key_generation == body.new_generation) {
                    Ok(NeededPasswords {
                        old: false,
                        new: true,
                    })
                } else {
                    Ok(both)
                }
            }
            _ => Ok(both),
        }
    }

    /// An authenticated interrupted transition. Holds the journal's lock and
    /// the locks of the copies it opened. No key or path accessor.
    pub struct InterruptedRotation {
        paths: Paths,
        anchors: AnchorDir,
        marker: LockedFile,
        vault_id: qv_crypto::VaultId,
        old_generation: KeyGeneration,
        new_generation: KeyGeneration,
        state: RotationState,
        old: Option<UnlockedVault>,
        new: Option<UnlockedVault>,
    }

    impl core::fmt::Debug for InterruptedRotation {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("InterruptedRotation(<redacted>)")
        }
    }

    impl InterruptedRotation {
        /// Reads and locks `<path>.qvrotate`, opens the copies its suffix
        /// names, authenticates each one it relies on with its own password
        /// (old: `old`, new: `new`), checks the journal's MAC of each side
        /// and the anchor, and classifies the state. A missing password that
        /// the state needs, any copy, journal or anchor that does not match,
        /// or a file combination outside the table is Integrity, with
        /// nothing changed. A wrong password is `WrongPassword`.
        pub fn open(
            path: &Path,
            anchors: &AnchorDir,
            old: Option<&MasterPassword>,
            new: Option<&MasterPassword>,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<Self, StoreError> {
            let (marker, journal) = read_marker(path)?;
            let body = journal.body();
            let paths = Paths::of(path, &body.suffix);
            // Each present copy, in its expected place.
            let (active, old_at, new_at) = present(&paths)?;
            let expect = |p: &Path, side: RotationSide| -> Result<Copy, StoreError> {
                let c = open_copy(p, body)?;
                if c.side == side {
                    Ok(c)
                } else {
                    Err(StoreError::Integrity)
                }
            };
            let (old_copy, new_copy, mut state) = match (active, old_at, new_at) {
                (true, false, true) => (
                    Some(expect(&paths.active, RotationSide::Old)?),
                    Some(expect(&paths.new, RotationSide::New)?),
                    RotationState::CandidateReady,
                ),
                (false, true, true) => (
                    Some(expect(&paths.old, RotationSide::Old)?),
                    Some(expect(&paths.new, RotationSide::New)?),
                    RotationState::ActiveRetired,
                ),
                (true, true, false) => (
                    Some(expect(&paths.old, RotationSide::Old)?),
                    Some(expect(&paths.active, RotationSide::New)?),
                    RotationState::AnchorPending,
                ),
                (true, false, false) => {
                    let c = open_copy(&paths.active, body)?;
                    match c.side {
                        RotationSide::Old => (Some(c), None, RotationState::RollbackPending),
                        RotationSide::New => (None, Some(c), RotationState::Committed),
                    }
                }
                _ => return Err(StoreError::Integrity),
            };
            // The new copy first: a committed transition needs only it.
            let new_vault = match new_copy {
                Some(c) => Some(authenticate(c, new, &journal, anchors, cancelled)?),
                None => None,
            };
            if let Some(n) = &new_vault {
                match anchored(n, anchors)? {
                    AnchorStatus::Verified
                        if matches!(
                            state,
                            RotationState::AnchorPending | RotationState::Committed
                        ) =>
                    {
                        state = RotationState::Committed;
                    }
                    AnchorStatus::Advanced if state != RotationState::Committed => {}
                    AnchorStatus::Missing => return Err(StoreError::NoAnchor),
                    _ => return Err(StoreError::Integrity),
                }
            }
            let old_vault = match (state, old_copy) {
                (RotationState::Committed, _) => None,
                (_, Some(c)) => {
                    let v = authenticate(c, old, &journal, anchors, cancelled)?;
                    match anchored(&v, anchors)? {
                        AnchorStatus::Verified => {}
                        AnchorStatus::Missing => return Err(StoreError::NoAnchor),
                        _ => return Err(StoreError::Integrity),
                    }
                    Some(v)
                }
                (_, None) => return Err(StoreError::Integrity),
            };
            Ok(InterruptedRotation {
                paths,
                anchors: anchors.clone(),
                marker,
                vault_id: body.vault_id,
                old_generation: body.old_generation,
                new_generation: body.new_generation,
                state,
                old: old_vault,
                new: new_vault,
            })
        }

        /// The classified state.
        pub fn state(&self) -> RotationState {
            self.state
        }

        /// The generation before the transition.
        pub fn old_generation(&self) -> KeyGeneration {
            self.old_generation
        }

        /// The generation the transition installs.
        pub fn new_generation(&self) -> KeyGeneration {
            self.new_generation
        }

        /// Completes or rolls back per the state table (module docs).
        /// Refusals (rollback of a committed transition, completion without a
        /// candidate) are Integrity before any change. Cancellation is
        /// checked once, before the first change.
        pub fn finish(
            self,
            choice: RotationChoice,
            snapshots: &SnapshotDir,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<(), StoreError> {
            let InterruptedRotation {
                paths,
                anchors,
                marker,
                vault_id,
                old_generation,
                new_generation,
                state,
                old,
                new,
            } = self;
            match (choice, state) {
                (RotationChoice::RollBack, RotationState::Committed)
                | (RotationChoice::Complete, RotationState::RollbackPending) => {
                    return Err(StoreError::Integrity);
                }
                _ => {}
            }
            check_cancel(cancelled)?;
            let (mut old, mut new) = (old, new);
            match choice {
                RotationChoice::Complete => {
                    if state == RotationState::CandidateReady {
                        let o = old.as_mut().ok_or(StoreError::Internal)?;
                        o.file.relocate(&paths.old)?;
                        point(CrashPoint::RotationActiveRetired)?;
                    }
                    if matches!(
                        state,
                        RotationState::CandidateReady | RotationState::ActiveRetired
                    ) {
                        let n = new.as_mut().ok_or(StoreError::Internal)?;
                        n.file.relocate(&paths.active)?;
                        point(CrashPoint::RotationInstalled)?;
                    }
                    if state != RotationState::Committed {
                        let n = new.as_ref().ok_or(StoreError::Internal)?;
                        advance_anchor(n, &anchors)?;
                        point(CrashPoint::RotationAnchored)?;
                    }
                    drop(new);
                    cleanup(&paths, old, snapshots, vault_id, old_generation, marker)
                }
                RotationChoice::RollBack => {
                    if state == RotationState::AnchorPending {
                        let n = new.as_mut().ok_or(StoreError::Internal)?;
                        n.file.relocate(&paths.new)?;
                        point(CrashPoint::RollbackNewRetired)?;
                    }
                    if matches!(
                        state,
                        RotationState::AnchorPending | RotationState::ActiveRetired
                    ) {
                        let o = old.as_mut().ok_or(StoreError::Internal)?;
                        o.file.relocate(&paths.active)?;
                        point(CrashPoint::RollbackOldRestored)?;
                    }
                    // The old vault is active again, with its anchor intact.
                    drop(old);
                    roll_back_tail(&paths, new, snapshots, vault_id, new_generation, marker)
                }
            }
        }
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "rotation_install_tests.rs"]
mod tests;
