// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline VK rotation (0002 §3.5; plan 0023, roadmap 1.15c).
//!
//! [`Session::begin_rotation`] takes and pins the mandatory recovery snapshot
//! of the current generation, then consumes the session: the store builds and
//! verifies the private next-generation replacement and the snapshot
//! inventory that carries older copies into the new budgets. The frontend
//! shows [`Rotation::phrase`] and confirms three of its words
//! ([`Rotation::confirm_word`]); only then does [`Rotation::install`] publish
//! it through the journal. A crash or failure after publication leaves a
//! transition that [`Core::resume_rotation`] and [`Core::finish_rotation`]
//! complete or roll back with the respective passwords.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use qv_crypto::{CryptoError, KeyGeneration, MasterPassword, RecoveryPhrase};
use qv_store::{
    InterruptedRotation, Leftovers, NeededPasswords, PreparedRotation, RotationChoice,
    SnapshotInventory, StoreError,
};

use crate::snapshot::{RecoverySnapshot, SnapshotPolicy};
use crate::{CancelToken, Core, CoreError, Session};

/// How many distinct phrase words must be confirmed before installation.
pub const ROTATION_CONFIRMATIONS: usize = 3;

/// A verified, unpublished rotation. Dropping it publishes nothing: the
/// private replacement is removed and the recovery snapshot stays as an
/// unpinned copy that the next unlock's policy reclassifies.
pub struct Rotation {
    // Field order: the replacement goes before the pin is released.
    prepared: PreparedRotation,
    inventory: SnapshotInventory,
    recovery: RecoverySnapshot,
    policy: Arc<SnapshotPolicy>,
    leftovers: Leftovers,
    confirmed: BTreeSet<usize>,
}

impl core::fmt::Debug for Rotation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rotation(<redacted>)")
    }
}

/// A completed rotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationOutcome {
    /// The vault's generation now.
    pub new_generation: KeyGeneration,
    /// Committed, but the retained old vault, the superseded inventory or
    /// the journal remains; `recovery rotate` finishes it with the new
    /// password.
    pub cleanup_pending: bool,
}

/// A failed installation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RotationError {
    /// What failed.
    pub error: CoreError,
    /// The journal was published: the rotation may be partly applied and is
    /// finished only through [`Core::resume_rotation`].
    pub journal_published: bool,
}

/// Store cancellation (`Io` after the flag was set) is [`CoreError::Cancelled`];
/// a control-record conflict is [`CoreError::Conflict`].
fn map(e: StoreError, cancel: Option<&CancelToken>) -> CoreError {
    match e {
        StoreError::Io if cancel.is_some_and(CancelToken::is_cancelled) => CoreError::Cancelled,
        StoreError::InvalidEdit => CoreError::Conflict,
        e => CoreError::Store(e),
    }
}

/// The 16 bytes of a 32-hex archive ID.
fn archive_bytes(hex: &str) -> Result<[u8; 16], CoreError> {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        let pair = hex.get(2 * i..2 * i + 2).ok_or(CoreError::Internal)?;
        *b = u8::from_str_radix(pair, 16).map_err(|_| CoreError::Internal)?;
    }
    Ok(out)
}

impl Session {
    /// Starts an offline rotation (0002 §3.5.1–2).
    ///
    /// Refusals before the recovery snapshot exists leave the session open
    /// and unchanged: a recovery session with writes blocked or no snapshot
    /// policy ([`CoreError::NotAllowed`]), cancellation, and
    /// [`CoreError::SnapshotOverBudget`] without `allow_snapshot_over_budget`
    /// (the frontend asks and retries). Once the pinned recovery snapshot is
    /// published, the session is consumed and locked whatever follows:
    /// pre-journal leftovers are removed, the replacement is built and
    /// verified (two password KDF runs), and the inventory is prepared.
    pub fn begin_rotation(
        &self,
        new_password: &MasterPassword,
        allow_snapshot_over_budget: bool,
        cancel: Option<&CancelToken>,
    ) -> Result<Rotation, CoreError> {
        self.read(|ctx| {
            if ctx.open.read_only || ctx.open.snapshots.is_none() {
                return Err(CoreError::NotAllowed);
            }
            Ok(())
        })?;
        let recovery = self.begin_destructive(allow_snapshot_over_budget, cancel)?;
        let open = self.take_open()?;
        let policy = open.snapshots.clone().ok_or(CoreError::Internal)?;
        let vault = open.vault;
        let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
        let leftovers = vault
            .remove_rotation_leftovers(&policy.dir)
            .map_err(|e| map(e, cancel))?;
        let prepared = vault
            .prepare_rotation(new_password, &cancelled)
            .map_err(|e| map(e, cancel))?;
        let inventory = policy
            .dir
            .prepare_inventory(&prepared, &cancelled)
            .map_err(|e| map(e, cancel))?;
        Ok(Rotation {
            prepared,
            inventory,
            recovery,
            policy,
            leftovers,
            confirmed: BTreeSet::new(),
        })
    }
}

impl Rotation {
    /// The new generation's recovery phrase, in protected memory.
    pub fn phrase(&self) -> &RecoveryPhrase {
        self.prepared.phrase()
    }

    /// The generation this rotation installs.
    pub fn new_generation(&self) -> KeyGeneration {
        self.prepared.new_generation()
    }

    /// What the pre-rotation cleanup found.
    pub fn leftovers(&self) -> Leftovers {
        self.leftovers
    }

    /// Checks one typed word (0-based `position`) in constant time and
    /// records a match. `false` for a mismatch; an out-of-range position is
    /// [`CoreError::InvalidInput`].
    pub fn confirm_word(&mut self, position: usize, typed: &[u8]) -> Result<bool, CoreError> {
        match self.prepared.phrase().confirm_word(position, typed) {
            Ok(()) => {
                self.confirmed.insert(position);
                Ok(true)
            }
            Err(CryptoError::WrongPhrase) => Ok(false),
            Err(_) => Err(CoreError::InvalidInput),
        }
    }

    /// Publishes the rotation (0002 §3.5.4). [`CoreError::NotAllowed`]
    /// unless [`ROTATION_CONFIRMATIONS`] distinct words were confirmed.
    /// Cancellation is honoured only until the journal is published. After
    /// success the vault must be unlocked again with the new password.
    pub fn install(self, cancel: Option<&CancelToken>) -> Result<RotationOutcome, RotationError> {
        let refuse = |error| RotationError {
            error,
            journal_published: false,
        };
        if self.confirmed.len() < ROTATION_CONFIRMATIONS {
            return Err(refuse(CoreError::NotAllowed));
        }
        let Rotation {
            prepared,
            inventory,
            recovery,
            policy,
            ..
        } = self;
        let snapshot = archive_bytes(&recovery.summary().archive_id).map_err(refuse)?;
        let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
        let result = prepared.install(&policy.dir, &inventory, snapshot, &cancelled);
        drop(recovery);
        match result {
            Ok(done) => Ok(RotationOutcome {
                new_generation: done.new_generation,
                cleanup_pending: done.cleanup_pending,
            }),
            Err(e) => Err(RotationError {
                error: map(e.error, cancel),
                journal_published: e.journal_published,
            }),
        }
    }
}

impl Core {
    /// Whether `path` has an interrupted rotation (`<path>.qvrotate`), so an
    /// ordinary unlock is refused and `recovery rotate` should be offered.
    pub fn rotation_pending(&self, path: &Path) -> Result<bool, CoreError> {
        Ok(qv_store::rotation_pending(path)?)
    }

    /// Which passwords an interrupted rotation needs: a prompt hint from
    /// unauthenticated bytes that authorizes nothing.
    pub fn rotation_passwords(&self, path: &Path) -> Result<NeededPasswords, CoreError> {
        Ok(qv_store::needed_passwords(path, &self.anchors)?)
    }

    /// Opens an interrupted rotation, authenticating every copy it relies on
    /// with its own password and the journal against each of them.
    pub fn resume_rotation(
        &self,
        path: &Path,
        old: Option<&MasterPassword>,
        new: Option<&MasterPassword>,
        cancel: Option<&CancelToken>,
    ) -> Result<InterruptedRotation, CoreError> {
        if self.snapshots.is_none() {
            return Err(CoreError::NotAllowed);
        }
        let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
        InterruptedRotation::open(path, &self.anchors, old, new, &cancelled)
            .map_err(|e| map(e, cancel))
    }

    /// Completes or rolls back an interrupted rotation. A rollback after the
    /// anchor named the new generation is refused (Integrity) before any
    /// change.
    pub fn finish_rotation(
        &self,
        rotation: InterruptedRotation,
        choice: RotationChoice,
        cancel: Option<&CancelToken>,
    ) -> Result<(), CoreError> {
        let policy = self.snapshots.as_ref().ok_or(CoreError::NotAllowed)?;
        let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
        rotation
            .finish(choice, &policy.dir, &cancelled)
            .map_err(|e| map(e, cancel))
    }
}

#[cfg(test)]
#[path = "rotation_tests.rs"]
mod tests;
