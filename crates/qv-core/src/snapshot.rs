// SPDX-License-Identifier: AGPL-3.0-or-later

//! Local snapshots and the full `verify` report (spec 0007 §3; 0011
//! *Snapshots and verification*).
//!
//! A snapshot is an archive (0004 §6, written by `qv-store` from verified
//! objects). This module owns the **policy** around them:
//!
//! - **Automatic ordinary snapshots** (0007 §3.2): on unlock, at most one
//!   ordinary snapshot per hour, plus one on the first unlock of a local
//!   day. The decision reads only authenticated archive headers of this
//!   vault ID and key generation: there is no marker row, no settings write
//!   and no vault commit on a read command. A snapshot failure or budget
//!   skip is reported through [`Session::snapshot_status`] so the frontend
//!   can warn; it never fails the requested command.
//! - **Budgets** (0007 §3.3): 30 days, 48 ordinary snapshots and 512 MiB per
//!   vault. Pruning removes the oldest ordinary snapshots first and never a
//!   copy pinned by an in-progress destructive operation. A `recover-` file
//!   left by a crash is reclassified as ordinary before it can be pruned.
//! - **Mandatory recovery snapshots** (0007 §3.2): [`Session::begin_destructive`]
//!   writes and verifies one before a destructive operation, pinning it until
//!   [`Session::finish_destructive`] (or the dropped handle) releases it.
//! - **`verify`** (0004 §3.6, 0011 §4): one read-only full pass, with the
//!   unlock-time anchor comparison and fixed notes.
//!
//! Every snapshot file is authenticated with the vault key before it can
//! affect policy or appear in a listing. Files that do not authenticate
//! (another vault or generation, a slot-bearing archive, damage) are ignored
//! by policy and counted as unreadable by [`Session::snapshots`], which the
//! CLI reports as warnings. The role of "today" is the UTC date: core has no
//! time-zone source and adds no dependency (development value, phase 1.16).

use std::sync::{Arc, Mutex, PoisonError};

use qv_model::Timestamp;
use qv_store::{
    AnchorStatus, ArchiveHeader, ArchiveScope, PublishedSnapshot, SnapshotDir, SnapshotEntry,
    SnapshotKind, StoreError, UnlockedVault, VerifyCounts,
};

use crate::error::CoreError;
use crate::session::{CancelToken, Open, Session};

/// Ordinary snapshots kept per vault (0007 §3.3, development value).
pub const DEFAULT_MAX_COUNT: u32 = 48;

/// Aggregate byte budget for ordinary snapshots (0007 §3.3, development
/// value: 512 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 512 * 1024 * 1024;

/// Maximum age of an ordinary snapshot (0007 §3.3, development value: 30
/// days).
pub const DEFAULT_MAX_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;

/// The coalescing interval of automatic ordinary snapshots (0007 §3.2).
pub const SNAPSHOT_INTERVAL_SECONDS: i64 = 60 * 60;

const MILLIS_PER_SECOND: i64 = 1000;
const MILLIS_PER_DAY: i64 = 24 * 60 * 60 * MILLIS_PER_SECOND;

/// Where local snapshots live and how many are kept (0007 §3.3).
pub struct SnapshotPolicy {
    /// The private snapshot directory (0007 §3.1).
    pub dir: SnapshotDir,
    /// Most ordinary snapshots kept.
    pub max_count: u32,
    /// Aggregate budget of the ordinary snapshots' files on disk.
    pub max_bytes: u64,
    /// Oldest age an ordinary snapshot may reach.
    pub max_age_seconds: i64,
}

impl SnapshotPolicy {
    /// The default budgets in `dir`.
    pub fn new(dir: SnapshotDir) -> Self {
        Self {
            dir,
            max_count: DEFAULT_MAX_COUNT,
            max_bytes: DEFAULT_MAX_BYTES,
            max_age_seconds: DEFAULT_MAX_AGE_SECONDS,
        }
    }

    /// The default policy in the private application directory
    /// (`$XDG_STATE_HOME/quickvault/snapshots`), creating it if needed.
    pub fn default_dir() -> Result<Self, StoreError> {
        let dir = SnapshotDir::default_dir()?;
        Ok(Self::new(SnapshotDir::open(&dir)?))
    }
}

impl core::fmt::Debug for SnapshotPolicy {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotPolicy")
            .field("dir", &self.dir)
            .field("max_count", &self.max_count)
            .field("max_bytes", &self.max_bytes)
            .field("max_age_seconds", &self.max_age_seconds)
            .finish()
    }
}

/// One authenticated local snapshot (0011 `snapshot ls`).
///
/// It carries no secret: the archive ID is random and non-linkable and the
/// counts are aggregate integers.
#[derive(Clone, PartialEq, Eq)]
pub struct SnapshotSummary {
    /// The archive's 32 lowercase hex identifier.
    pub archive_id: String,
    /// Its authenticated creation time.
    pub created_at: Timestamp,
    /// Whether it is an ordinary or a recovery copy.
    pub kind: SnapshotKind,
    /// Its size on disk in bytes.
    pub size: u64,
    /// How many objects it carries.
    pub objects: u64,
    /// Their total referenced ciphertext length.
    pub total_bytes: u64,
}

impl core::fmt::Debug for SnapshotSummary {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SnapshotSummary")
            .field("archive_id", &self.archive_id)
            .field("created_at", &self.created_at)
            .field("kind", &self.kind)
            .field("size", &self.size)
            .field("objects", &self.objects)
            .field("total_bytes", &self.total_bytes)
            .finish()
    }
}

/// Why the automatic policy did not take a snapshot (0007 §3.2–3.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SnapshotSkip {
    /// No snapshot policy is configured; snapshots are unavailable.
    Disabled,
    /// The newest ordinary snapshot is less than an hour old.
    OnePerHour,
    /// The first-of-day copy already exists and the hourly one is not due.
    /// The default rule takes the first-of-day copy even inside the hourly
    /// window, so it reports [`Self::OnePerHour`] instead; this variant is
    /// reserved for a daily-only policy.
    AlreadyToday,
    /// The copy needs `needed` bytes and does not fit the ordinary budgets
    /// (0007 §3.3). A destructive operation asks for approval.
    OverBudget {
        /// The size the copy needs on disk.
        needed: u64,
    },
}

/// The outcome of one automatic-policy attempt (0011 §4).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotReport {
    /// The copy that was written, if any.
    pub published: Option<SnapshotSummary>,
    /// The archive IDs of the snapshots pruning removed.
    pub pruned: Vec<String>,
    /// Why no copy was written, if it was skipped on purpose.
    pub skipped: Option<SnapshotSkip>,
    /// The copy could not be written (disk full, unsafe directory, an I/O
    /// failure). A warning, never an error for the requested command.
    pub failed: bool,
}

impl SnapshotReport {
    /// The report of a session without a snapshot policy.
    pub(crate) fn disabled() -> Self {
        Self {
            skipped: Some(SnapshotSkip::Disabled),
            ..Self::default()
        }
    }

    /// The report of an automatic copy that could not be written.
    pub(crate) fn failed() -> Self {
        Self {
            failed: true,
            ..Self::default()
        }
    }
}

/// An authenticated listing of the local snapshots (0011 `snapshot ls`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SnapshotListing {
    /// The snapshots of this vault ID and key generation, newest first by
    /// authenticated `created_at` and then archive ID.
    pub snapshots: Vec<SnapshotSummary>,
    /// How many files in the directory could not be authenticated and were
    /// therefore not listed. The CLI reports them as warnings.
    pub unreadable: u64,
}

/// A fixed-label note of the `verify` report (0011 §4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyNote {
    /// A history floor covers versions absent by design after a purge
    /// (0007 §1.2, §1.4): expected state, never damage.
    SuppressionFloorCoversDominatedVersions,
}

impl VerifyNote {
    /// The stable label the CLI prints (0011 §4).
    pub fn label(self) -> &'static str {
        match self {
            Self::SuppressionFloorCoversDominatedVersions => {
                "suppression-floor-covers-dominated-versions"
            }
        }
    }
}

/// One full `verify` pass (0011 §4; 0004 §3.6).
///
/// It carries counts, the vault's authenticated identity and the anchor
/// comparison only: no object ID, hash, record ID, payload or path.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifyReport {
    /// The vault ID, lowercase hex.
    pub vault_id: String,
    /// The current key generation.
    pub key_generation: u32,
    /// The committed local sequence number.
    pub local_seq: u64,
    /// The head-versus-anchor comparison made at unlock (0005 §5.4).
    pub anchor: AnchorStatus,
    /// What the pass counted.
    pub counts: VerifyCounts,
    /// Fixed-label notes, never damage.
    pub notes: Vec<VerifyNote>,
}

impl VerifyReport {
    /// Whether every check passed and the anchor is current or one step
    /// behind (0011 §4: exit 0 only for `verified` or `advanced`).
    pub fn ok(&self) -> bool {
        matches!(self.anchor, AnchorStatus::Verified | AnchorStatus::Advanced)
    }
}

impl core::fmt::Debug for VerifyReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyReport")
            .field("vault_id", &self.vault_id)
            .field("key_generation", &self.key_generation)
            .field("local_seq", &self.local_seq)
            .field("anchor", &self.anchor)
            .field("counts", &self.counts)
            .field("notes", &self.notes)
            .finish()
    }
}

/// A pinned recovery snapshot of an in-progress destructive operation
/// (0007 §3.2). Dropping it without [`Session::finish_destructive`] releases
/// the pin; the copy then stays as a `recover-` file that the next policy
/// pass reclassifies as ordinary.
pub struct RecoverySnapshot {
    pin: Arc<Mutex<Option<String>>>,
    summary: SnapshotSummary,
    entry: SnapshotEntry,
}

impl RecoverySnapshot {
    /// The published copy's authenticated facts.
    pub fn summary(&self) -> &SnapshotSummary {
        &self.summary
    }
}

impl core::fmt::Debug for RecoverySnapshot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoverySnapshot")
            .field("archive_id", &self.summary.archive_id)
            .finish_non_exhaustive()
    }
}

impl Drop for RecoverySnapshot {
    fn drop(&mut self) {
        let mut pin = self.pin.lock().unwrap_or_else(PoisonError::into_inner);
        if pin.as_deref() == Some(self.summary.archive_id.as_str()) {
            *pin = None;
        }
    }
}

/// The auth outcome of one policy pass: only authenticated local snapshots
/// of this vault ID and generation count.
fn authenticated(
    policy: &SnapshotPolicy,
    vault: &UnlockedVault,
) -> Result<(Vec<(SnapshotEntry, ArchiveHeader)>, u64), StoreError> {
    let scope = ArchiveScope::new(vault.header().vault_id, vault.header().key_generation);
    let mut rows = Vec::new();
    let mut unreadable = 0;
    for entry in policy.dir.entries()? {
        match policy.dir.read_header(&entry, scope, vault.vault_key()) {
            Ok(header) => rows.push((entry, header)),
            Err(_) => unreadable += 1,
        }
    }
    Ok((rows, unreadable))
}

fn summary(entry: &SnapshotEntry, header: &ArchiveHeader) -> SnapshotSummary {
    SnapshotSummary {
        archive_id: header.archive_id_hex(),
        created_at: header.created_at(),
        kind: entry.kind(),
        size: entry.size(),
        objects: header.object_count(),
        total_bytes: header.total_length(),
    }
}

/// The authenticated facts of a copy this process just published.
fn published_summary(published: &PublishedSnapshot) -> SnapshotSummary {
    SnapshotSummary {
        archive_id: published.archive_id().to_owned(),
        created_at: published.created_at(),
        kind: published.kind(),
        size: published.size(),
        objects: published.objects(),
        total_bytes: published.total_bytes(),
    }
}

/// The UTC day of `ms` (core has no time-zone source; development value).
fn day_of(ms: i64) -> i64 {
    ms.div_euclid(MILLIS_PER_DAY)
}

/// The automatic-policy decision from authenticated headers only (0007
/// §3.2): take a copy when there is none from today, or when the newest is
/// more than an hour old.
fn automatic_decision(
    rows: &[(SnapshotEntry, ArchiveHeader)],
    now: Timestamp,
) -> Option<SnapshotSkip> {
    let mut newest: Option<Timestamp> = None;
    let mut today = false;
    for (entry, header) in rows {
        if entry.kind() != SnapshotKind::Ordinary {
            continue;
        }
        let created = header.created_at();
        if newest.is_none_or(|t| created > t) {
            newest = Some(created);
        }
        if day_of(created.0) == day_of(now.0) {
            today = true;
        }
    }
    let recent = newest
        .is_some_and(|t| now.0.saturating_sub(t.0) < SNAPSHOT_INTERVAL_SECONDS * MILLIS_PER_SECOND);
    if today && recent {
        Some(SnapshotSkip::OnePerHour)
    } else {
        None
    }
}

/// One policy pass: reclassify stale recovery copies, prune expired and
/// over-budget ordinary snapshots, then write the new copy.
///
/// `pinned` is the archive ID an in-progress operation protects. The pass
/// never removes it, and never removes the copy it just wrote.
fn snapshot_pass(
    policy: &SnapshotPolicy,
    vault: &mut UnlockedVault,
    kind: SnapshotKind,
    now: Timestamp,
    allow_over_budget: bool,
    pinned: Option<&str>,
    cancelled: &dyn Fn() -> bool,
) -> Result<Taken, CoreError> {
    let dir = &policy.dir;
    let scope = ArchiveScope::new(vault.header().vault_id, vault.header().key_generation);

    // 1. A `recover-` file that no operation pins (a crash, or a finished
    //    operation whose reclassify failed) is ordinary before any pruning so
    //    recovery copies cannot accumulate forever (0007 §3.2).
    for entry in dir.entries()? {
        if entry.kind() != SnapshotKind::Recovery {
            continue;
        }
        let Ok(header) = dir.read_header(&entry, scope, vault.vault_key()) else {
            continue;
        };
        if pinned == Some(header.archive_id_hex().as_str()) {
            continue;
        }
        dir.reclassify_as_ordinary(&entry)?;
    }

    let mut report = SnapshotReport::default();
    let max_age_ms = policy.max_age_seconds.saturating_mul(MILLIS_PER_SECOND);

    // 2. Write and verify the new copy (0004 §6.5).
    let published = dir.publish(vault, kind, now, cancelled)?;
    let new = published_summary(&published);
    let new_entry = published.entry().clone();

    // 3. Age pruning, oldest first, authenticated headers only.
    let (rows, _) = authenticated(policy, vault)?;
    for (entry, header) in &rows {
        if cancelled() {
            return Err(CoreError::Cancelled);
        }
        if entry.kind() != SnapshotKind::Ordinary {
            continue;
        }
        let id = header.archive_id_hex();
        if pinned == Some(id.as_str()) {
            continue;
        }
        if now.0.saturating_sub(header.created_at().0) <= max_age_ms {
            continue;
        }
        remove_entry(dir, entry, &id, &mut report)?;
    }

    // 4. Count and byte pruning as if the new copy were ordinary, oldest
    //    first; the pinned copy and the new copy are never candidates.
    let (rows, _) = authenticated(policy, vault)?;
    let mut count = 0u64;
    let mut bytes = 0u64;
    let mut candidates = Vec::new();
    for (entry, header) in &rows {
        let id = header.archive_id_hex();
        if entry.kind() != SnapshotKind::Ordinary && id != new.archive_id {
            continue;
        }
        count = count.checked_add(1).ok_or(StoreError::LimitExceeded)?;
        bytes = bytes
            .checked_add(entry.size())
            .ok_or(StoreError::LimitExceeded)?;
        if id != new.archive_id && pinned != Some(id.as_str()) {
            candidates.push((header.created_at(), id, entry.clone()));
        }
    }
    candidates.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let fits =
        |count: u64, bytes: u64| count <= u64::from(policy.max_count) && bytes <= policy.max_bytes;
    // A copy that cannot fit even alone never justifies deleting others.
    if new.size <= policy.max_bytes && policy.max_count > 0 {
        for (_, id, entry) in candidates {
            if fits(count, bytes) {
                break;
            }
            remove_entry(dir, &entry, &id, &mut report)?;
            count = count.saturating_sub(1);
            bytes = bytes.saturating_sub(entry.size());
        }
    }

    // 5. What does not fit is a budget refusal, not damage: remove the copy
    //    we just wrote unless the caller approved exceeding the budget.
    if !fits(count, bytes) && !allow_over_budget {
        match dir.remove(&new_entry) {
            Ok(()) | Err(StoreError::NotFound) => {}
            Err(e) => return Err(e.into()),
        }
        if kind == SnapshotKind::Recovery {
            return Err(CoreError::SnapshotOverBudget { needed: new.size });
        }
        report.skipped = Some(SnapshotSkip::OverBudget { needed: new.size });
        return Ok(Taken {
            report,
            entry: None,
        });
    }
    report.published = Some(new);
    Ok(Taken {
        report,
        entry: Some(new_entry),
    })
}

/// Removes one snapshot and records its archive ID as pruned.
fn remove_entry(
    dir: &SnapshotDir,
    entry: &SnapshotEntry,
    id: &str,
    report: &mut SnapshotReport,
) -> Result<(), CoreError> {
    match dir.remove(entry) {
        Ok(()) | Err(StoreError::NotFound) => {
            report.pruned.push(id.to_owned());
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}

/// What one policy pass produced.
struct Taken {
    report: SnapshotReport,
    entry: Option<SnapshotEntry>,
}

impl Session {
    /// The authenticated local snapshots of this vault (0011 `snapshot ls`).
    ///
    /// Files that cannot be authenticated are counted in
    /// [`SnapshotListing::unreadable`] and never listed. An empty listing is
    /// returned when no snapshot policy is configured.
    pub fn snapshots(&self) -> Result<SnapshotListing, CoreError> {
        self.read(|ctx| {
            let Some(policy) = ctx.open.snapshots.clone() else {
                return Ok(SnapshotListing::default());
            };
            let (rows, unreadable) = authenticated(&policy, &ctx.open.vault)?;
            let mut snapshots: Vec<SnapshotSummary> =
                rows.iter().map(|(e, h)| summary(e, h)).collect();
            snapshots.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| a.archive_id.cmp(&b.archive_id))
            });
            Ok(SnapshotListing {
                snapshots,
                unreadable,
            })
        })
    }

    /// Matches local snapshot filename IDs, including damaged/foreign files.
    /// Authentication is required by `restore_snapshot` before acceptance.
    pub fn snapshot_matches(&self, prefix: &str) -> Result<Vec<String>, CoreError> {
        let prefix = prefix.strip_prefix('@').unwrap_or(prefix);
        if !(6..=32).contains(&prefix.len()) || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidInput);
        }
        let prefix = prefix.to_ascii_lowercase();
        self.read(|ctx| {
            let policy = ctx.open.snapshots.clone().ok_or(CoreError::NotAllowed)?;
            let mut ids: Vec<String> = policy
                .dir
                .entries()?
                .iter()
                .map(|e| e.archive_id().to_owned())
                .filter(|id| id.starts_with(&prefix))
                .collect();
            ids.sort();
            ids.dedup();
            Ok(ids)
        })
    }

    /// Explicitly restores a full local archive ID into a new path and fresh
    /// local baseline. The active vault and its anchor are preserved. This
    /// does not establish that the snapshot is the latest global state.
    pub fn restore_snapshot(
        &self,
        id: &str,
        path: &std::path::Path,
        cancel: Option<&CancelToken>,
    ) -> Result<(), CoreError> {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidInput);
        }
        let id = id.to_ascii_lowercase();
        let result = self.mutate(|ctx| {
            ctx.check_cancel()?;
            if cancel.is_some_and(CancelToken::is_cancelled) {
                return Err(CoreError::Cancelled);
            }
            let policy = ctx.open.snapshots.clone().ok_or(CoreError::NotAllowed)?;
            let entries = policy.dir.entries()?;
            let mut matches = entries.iter().filter(|e| e.archive_id() == id);
            let entry = matches.next().ok_or(CoreError::NotFound)?;
            if matches.next().is_some() {
                return Err(CoreError::Store(StoreError::Integrity));
            }
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::BeforeCommit);
            ctx.check_cancel()?;
            let c = ctx.canceller();
            policy.dir.restore(entry, &ctx.open.vault, path, &|| {
                c.is_cancelled() || cancel.is_some_and(CancelToken::is_cancelled)
            })?;
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::AfterCommit);
            Ok(())
        });
        if result.is_ok() {
            self.run_automatic_snapshot(cancel);
        }
        result
    }

    /// The snapshots created before `cutoff` (1.14 `passwd` support, 0007
    /// §3.5), newest first. Includes recovery copies.
    pub fn snapshots_before(&self, cutoff: Timestamp) -> Result<Vec<SnapshotSummary>, CoreError> {
        self.read(|ctx| {
            let Some(policy) = ctx.open.snapshots.clone() else {
                return Ok(Vec::new());
            };
            let (rows, _) = authenticated(&policy, &ctx.open.vault)?;
            let mut snapshots: Vec<SnapshotSummary> = rows
                .iter()
                .map(|(e, h)| summary(e, h))
                .filter(|s| s.created_at < cutoff)
                .collect();
            snapshots.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
                    .then_with(|| a.archive_id.cmp(&b.archive_id))
            });
            Ok(snapshots)
        })
    }

    /// Deletes the named snapshots (1.14 `passwd` support, 0007 §3.5) and
    /// returns how many were removed. Unknown archive IDs are ignored, and a
    /// copy pinned by an in-progress destructive operation is never deleted.
    pub fn delete_snapshots(&self, ids: &[String]) -> Result<usize, CoreError> {
        self.mutate(|ctx| {
            let Some(policy) = ctx.open.snapshots.clone() else {
                return Ok(0);
            };
            let pinned = ctx.open.pinned();
            let (rows, _) = authenticated(&policy, &ctx.open.vault)?;
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::BeforeCommit);
            ctx.check_cancel()?;
            let mut deleted = 0;
            for (entry, header) in &rows {
                let id = header.archive_id_hex();
                if !ids.contains(&id) || pinned.as_deref() == Some(id.as_str()) {
                    continue;
                }
                match policy.dir.remove(entry) {
                    Ok(()) | Err(StoreError::NotFound) => deleted += 1,
                    Err(e) => return Err(e.into()),
                }
            }
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::AfterCommit);
            Ok(deleted)
        })
    }

    /// The mandatory pre-operation recovery snapshot (0007 §3.2). It is
    /// written and verified before the caller performs the destructive
    /// operation, and pinned until [`Self::finish_destructive`] or the
    /// handle's drop.
    ///
    /// [`CoreError::SnapshotOverBudget`] means the copy needs `needed` bytes
    /// and does not fit the ordinary budgets: nothing is pinned and the
    /// caller must ask the user before retrying with
    /// `allow_over_budget = true`. Any other error means the copy could not
    /// be written at all, and the operation must not proceed.
    pub fn begin_destructive(
        &self,
        allow_over_budget: bool,
        cancel: Option<&CancelToken>,
    ) -> Result<RecoverySnapshot, CoreError> {
        self.read(|ctx| {
            let c = ctx.canceller();
            if cancel.is_some_and(CancelToken::is_cancelled) || c.is_cancelled() {
                return Err(CoreError::Cancelled);
            }
            let now = ctx.now();
            let open = &mut *ctx.open;
            // Only one serialized recovery operation may pin a snapshot
            // (0007 §3.2).
            if open.pinned().is_some() {
                return Err(CoreError::NotAllowed);
            }
            let policy = open.snapshots.clone().ok_or(CoreError::Internal)?;
            let taken = snapshot_pass(
                &policy,
                &mut open.vault,
                SnapshotKind::Recovery,
                now,
                allow_over_budget,
                None,
                &move || c.is_cancelled() || cancel.is_some_and(CancelToken::is_cancelled),
            )?;
            let summary = taken.report.published.clone().ok_or(CoreError::Internal)?;
            let entry = taken.entry.ok_or(CoreError::Internal)?;
            *open.pin.lock().unwrap_or_else(PoisonError::into_inner) =
                Some(summary.archive_id.clone());
            Ok(RecoverySnapshot {
                pin: Arc::clone(&open.pin),
                summary,
                entry,
            })
        })
    }

    /// Ends a destructive operation: the pinned copy becomes an ordinary
    /// snapshot subject to pruning (0007 §3.2). A failure here leaves the
    /// copy as a `recover-` file that the next policy pass reclassifies.
    pub fn finish_destructive(&self, snapshot: RecoverySnapshot) -> Result<(), CoreError> {
        self.read(|ctx| {
            if !Arc::ptr_eq(&ctx.open.pin, &snapshot.pin) {
                return Err(CoreError::StaleHandle);
            }
            {
                let mut pin = ctx.open.pin.lock().unwrap_or_else(PoisonError::into_inner);
                if pin.as_deref() != Some(snapshot.summary.archive_id.as_str()) {
                    return Err(CoreError::StaleHandle);
                }
                *pin = None;
            }
            match ctx.open.snapshots.clone() {
                Some(policy) => {
                    policy.dir.reclassify_as_ordinary(&snapshot.entry)?;
                    Ok(())
                }
                None => Err(CoreError::Internal),
            }
        })
    }

    /// One full integrity pass over the committed state (0011 `verify`;
    /// 0004 §3.6). It never mutates or repairs the vault.
    ///
    /// [`VerifyReport::anchor`] is the comparison made at unlock, so a
    /// session from [`crate::Core::unlock_for_recovery`] lets a missing or
    /// mismatched anchor be reported together with the counts instead of
    /// refusing before the report exists.
    pub fn verify(&self, cancel: Option<&CancelToken>) -> Result<VerifyReport, CoreError> {
        self.read(|ctx| {
            let c = ctx.canceller();
            let counts = ctx.open.vault.verify_all(&|| {
                c.is_cancelled() || cancel.is_some_and(CancelToken::is_cancelled)
            })?;
            let header = ctx.open.vault.header();
            let mut notes = Vec::new();
            if counts.suppressed_records > 0 {
                notes.push(VerifyNote::SuppressionFloorCoversDominatedVersions);
            }
            Ok(VerifyReport {
                vault_id: crate::setup::hex(&header.vault_id.0),
                key_generation: header.key_generation.0,
                local_seq: ctx.open.vault.local_seq(),
                anchor: ctx.open.anchor,
                counts,
                notes,
            })
        })
    }

    /// The automatic policy's outcome for this session, for the frontend's
    /// stderr warnings (0011 §4). `None` before an unlock and on a locked or
    /// never-unlocked session.
    pub fn snapshot_status(&self) -> Option<SnapshotReport> {
        self.read(|ctx| Ok(ctx.open.auto_snapshot.clone()))
            .ok()
            .flatten()
    }

    /// Runs the automatic ordinary-snapshot policy (0007 §3.2). Best effort:
    /// any failure is reported as a warning through
    /// [`Self::snapshot_status`] and never fails the unlock.
    pub(crate) fn run_automatic_snapshot(&self, cancel: Option<&CancelToken>) {
        let _ = self.read(|ctx| {
            let c = ctx.canceller();
            let now = ctx.now();
            let open: &mut Open = ctx.open;
            let Some(policy) = open.snapshots.clone() else {
                return Ok(());
            };
            let pinned = open.pinned();
            let cancelled =
                move || c.is_cancelled() || cancel.is_some_and(CancelToken::is_cancelled);
            let decision = match authenticated(&policy, &open.vault) {
                Ok((rows, _)) => automatic_decision(&rows, now),
                Err(_) => {
                    open.auto_snapshot = Some(SnapshotReport::failed());
                    return Ok(());
                }
            };
            if let Some(skip) = decision {
                open.auto_snapshot = Some(SnapshotReport {
                    skipped: Some(skip),
                    ..SnapshotReport::default()
                });
                return Ok(());
            }
            let report = match snapshot_pass(
                &policy,
                &mut open.vault,
                SnapshotKind::Ordinary,
                now,
                false,
                pinned.as_deref(),
                &cancelled,
            ) {
                Ok(taken) => taken.report,
                Err(_) => SnapshotReport::failed(),
            };
            open.auto_snapshot = Some(report);
            Ok(())
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{Env, add_entry, err, kdf, pw, seq};
    use crate::{CoreError, SnapshotSkip};

    fn policy(env: &Env, max_count: u32, max_bytes: u64, max_age_seconds: i64) -> SnapshotPolicy {
        SnapshotPolicy {
            dir: SnapshotDir::open(&env.dir.path().join("snapshots")).unwrap(),
            max_count,
            max_bytes,
            max_age_seconds,
        }
    }

    fn ids(listing: &SnapshotListing) -> Vec<String> {
        listing
            .snapshots
            .iter()
            .map(|s| s.archive_id.clone())
            .collect()
    }

    #[test]
    fn snapshot_policy_coalesces_hourly_and_first_of_day() {
        let env = Env::new();
        // Midday of an arbitrary UTC day.
        let day = 20_000i64;
        let t0 = day * MILLIS_PER_DAY + 12 * 60 * 60 * MILLIS_PER_SECOND;
        env.time.set(t0);
        let s = env.unlock_with(Some(policy(
            &env,
            DEFAULT_MAX_COUNT,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let first = s.snapshot_status().unwrap();
        let Some(published) = first.published.clone() else {
            panic!("the first unlock of the day took no snapshot: {first:?}");
        };
        assert_eq!(published.kind, SnapshotKind::Ordinary);
        assert_eq!(published.created_at, Timestamp(t0));
        assert!(published.size > 0 && published.objects > 0 && published.total_bytes > 0);
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 1);
        drop(s);

        // Half an hour later: the hourly coalescing skips it.
        env.time.set(t0 + 30 * 60 * MILLIS_PER_SECOND);
        let s = env.unlock_with(Some(policy(
            &env,
            DEFAULT_MAX_COUNT,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let second = s.snapshot_status().unwrap();
        assert_eq!(second.skipped, Some(SnapshotSkip::OnePerHour));
        assert!(second.published.is_none());
        assert!(second.pruned.is_empty());
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 1);
        drop(s);

        // More than an hour later: a second ordinary copy.
        env.time.set(t0 + 61 * 60 * MILLIS_PER_SECOND);
        let s = env.unlock_with(Some(policy(
            &env,
            DEFAULT_MAX_COUNT,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let third = s.snapshot_status().unwrap();
        let Some(second_copy) = third.published.clone() else {
            panic!("an hourly snapshot was not taken: {third:?}");
        };
        assert_ne!(second_copy.archive_id, published.archive_id);
        drop(s);

        // First unlock of the next day, only a few minutes later: taken even
        // though the hour has not passed (0007 §3.2).
        let next_day = (day + 1) * MILLIS_PER_DAY + 5 * 60 * MILLIS_PER_SECOND;
        env.time.set(next_day);
        let s = env.unlock_with(Some(policy(
            &env,
            DEFAULT_MAX_COUNT,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let report = s.snapshot_status().unwrap();
        let Some(today) = report.published.clone() else {
            panic!("the first unlock of the next day took no snapshot: {report:?}");
        };
        assert_eq!(today.created_at, Timestamp(next_day));
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 3);
        // The listing is newest first by authenticated creation time.
        let rows = s.snapshots().unwrap().snapshots;
        assert!(rows.windows(2).all(|w| w[0].created_at >= w[1].created_at));
    }

    #[test]
    fn snapshot_disk_growth_prunes_to_the_budgets_and_never_the_pinned_copy() {
        let env = Env::new();
        let day = 21_000i64;
        let t0 = day * MILLIS_PER_DAY + 8 * 60 * 60 * MILLIS_PER_SECOND;
        env.time.set(t0);
        let mut taken = Vec::new();
        for i in 0..3 {
            env.time.set(t0 + i * 61 * 60 * MILLIS_PER_SECOND);
            let s = env.unlock_with(Some(policy(
                &env,
                2,
                DEFAULT_MAX_BYTES,
                DEFAULT_MAX_AGE_SECONDS,
            )));
            let report = s.snapshot_status().unwrap();
            let Some(published) = report.published.clone() else {
                panic!("no snapshot at step {i}: {report:?}");
            };
            taken.push(published.archive_id);
            drop(s);
        }
        let s = env.unlock_with(Some(policy(
            &env,
            2,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let rows = s.snapshots().unwrap();
        assert_eq!(rows.snapshots.len(), 2, "the count budget did not prune");
        // Oldest first: the first copy is gone, the last two remain.
        assert!(!ids(&rows).contains(&taken[0]));
        assert!(ids(&rows).contains(&taken[1]) && ids(&rows).contains(&taken[2]));

        // The mandatory recovery copy is pinned: deleting every ID leaves it.
        let snap = s.begin_destructive(false, None).unwrap();
        let pinned = snap.summary().archive_id.clone();
        assert_eq!(
            s.delete_snapshots(std::slice::from_ref(&pinned)).unwrap(),
            0
        );
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 2);
        s.finish_destructive(snap).unwrap();
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 2);
        // After completion the copy is ordinary and deletable.
        assert_eq!(
            s.snapshots()
                .unwrap()
                .snapshots
                .iter()
                .filter(|x| x.archive_id == pinned)
                .count(),
            1
        );
        assert_eq!(s.delete_snapshots(&[pinned]).unwrap(), 1);
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 1);
        // The vault was never written by any of this.
        assert_eq!(seq(&s), 1);
    }

    #[test]
    fn snapshot_budget_covers_bytes_and_age() {
        let env = Env::new();
        let day = 22_000i64;
        let t0 = day * MILLIS_PER_DAY + 9 * 60 * 60 * MILLIS_PER_SECOND;
        env.time.set(t0);
        let s = env.unlock_with(Some(policy(
            &env,
            48,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let size = s.snapshot_status().unwrap().published.unwrap().size;
        drop(s);

        // A byte budget of one and a half snapshots keeps exactly one.
        let max_bytes = size + size / 2;
        for i in 0..2 {
            env.time.set(t0 + (i + 1) * 61 * 60 * MILLIS_PER_SECOND);
            let s = env.unlock_with(Some(policy(&env, 48, max_bytes, DEFAULT_MAX_AGE_SECONDS)));
            if i == 1 {
                let report = s.snapshot_status().unwrap();
                assert_eq!(report.pruned.len(), 1, "{report:?}");
                assert_eq!(s.snapshots().unwrap().snapshots.len(), 1);
            }
            drop(s);
        }

        // Age: an ordinary copy older than the maximum age is pruned even
        // when the count and byte budgets are not reached.
        env.time.set(t0 + 6 * 60 * 60 * MILLIS_PER_SECOND);
        let s = env.unlock_with(Some(policy(&env, 48, DEFAULT_MAX_BYTES, 60 * 60)));
        let report = s.snapshot_status().unwrap();
        assert_eq!(report.pruned.len(), 1, "{report:?}");
        assert_eq!(s.snapshots().unwrap().snapshots.len(), 1);
    }

    #[test]
    fn recovery_snapshot_needs_approval_and_never_writes_the_vault() {
        let env = Env::new();
        let before = std::fs::read(&env.path).unwrap();
        let s = env.unlock_with(Some(policy(&env, 48, 1, DEFAULT_MAX_AGE_SECONDS)));
        let seq_before = seq(&s);
        match err(s.begin_destructive(false, None)) {
            CoreError::SnapshotOverBudget { needed } => assert!(needed > 0),
            other => panic!("expected a budget refusal, got {other:?}"),
        }
        // The refused copy is removed and nothing is pinned or listed.
        assert!(s.snapshots().unwrap().snapshots.is_empty());
        assert_eq!(seq(&s), seq_before);

        // Explicit approval takes it anyway (0007 §3.3); it stays pinned.
        let snap = s.begin_destructive(true, None).unwrap();
        assert_eq!(snap.summary().kind, SnapshotKind::Recovery);
        let rows = s.snapshots().unwrap().snapshots;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, SnapshotKind::Recovery);
        // Only one serialized recovery operation may pin a snapshot.
        assert_eq!(err(s.begin_destructive(true, None)), CoreError::NotAllowed);
        s.finish_destructive(snap).unwrap();
        assert_eq!(
            s.snapshots().unwrap().snapshots[0].kind,
            SnapshotKind::Ordinary
        );

        // Dropping an unfinished handle releases the pin.
        let dropped = s.begin_destructive(true, None).unwrap();
        drop(dropped);
        assert!(s.begin_destructive(true, None).is_ok());
        assert_eq!(seq(&s), seq_before);
        assert_eq!(std::fs::read(&env.path).unwrap(), before);
    }

    #[test]
    fn snapshot_without_a_policy_is_disabled() {
        let env = Env::new();
        let s = env.unlock_with(None);
        assert_eq!(
            s.snapshot_status().unwrap().skipped,
            Some(SnapshotSkip::Disabled)
        );
        assert!(s.snapshots().unwrap().snapshots.is_empty());
        assert_eq!(err(s.begin_destructive(false, None)), CoreError::Internal);
        assert_eq!(s.delete_snapshots(&["00".repeat(16)]).unwrap(), 0);
        assert!(s.snapshots_before(Timestamp(i64::MAX)).unwrap().is_empty());
    }

    #[test]
    fn recovery_copy_left_by_a_crash_is_reclassified_before_pruning() {
        let env = Env::new();
        let day = 23_000i64;
        let t0 = day * MILLIS_PER_DAY + 10 * 60 * 60 * MILLIS_PER_SECOND;
        env.time.set(t0);
        let s = env.unlock_with(Some(policy(
            &env,
            48,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        // A crash: the handle is dropped without finish_destructive.
        let crashed = s.begin_destructive(false, None).unwrap();
        let crashed_id = crashed.summary().archive_id.clone();
        drop(crashed);
        let rows = s.snapshots().unwrap().snapshots;
        let crashed_row = rows
            .iter()
            .find(|r| r.archive_id == crashed_id)
            .expect("the crashed copy is not listed");
        assert_eq!(crashed_row.kind, SnapshotKind::Recovery);
        drop(s);

        // The next policy pass reclassifies it and then prunes it like any
        // ordinary snapshot.
        env.time.set(t0 + 61 * 60 * MILLIS_PER_SECOND);
        let s = env.unlock_with(Some(policy(
            &env,
            1,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let rows = s.snapshots().unwrap().snapshots;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, SnapshotKind::Ordinary);
        assert_ne!(
            rows[0].archive_id, crashed_id,
            "the crashed copy survived pruning"
        );
    }

    #[test]
    fn snapshot_failure_never_fails_an_unlock() {
        use std::os::unix::fs::PermissionsExt;

        let env = Env::new();
        let configured = policy(&env, 48, DEFAULT_MAX_BYTES, DEFAULT_MAX_AGE_SECONDS);
        let dir = configured.dir.path().to_owned();
        // The directory is private but not writable: publication fails.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let denied = std::fs::write(dir.join("probe"), b"").is_err();
        let _ = std::fs::remove_file(dir.join("probe"));
        if denied {
            let s = env.unlock_with(Some(policy(
                &env,
                48,
                DEFAULT_MAX_BYTES,
                DEFAULT_MAX_AGE_SECONDS,
            )));
            let report = s.snapshot_status().unwrap();
            assert!(report.failed, "{report:?}");
            assert!(report.published.is_none());
            // The unlocked vault still works.
            assert_eq!(s.overview().unwrap().name.expose(), crate::testutil::NAME);
        } else {
            // Permission-override privileges (uid 0 in a user namespace)
            // cannot produce this failure; the unsafe-directory refusal and
            // the writer's own error tests cover the abort.
            eprintln!(
                "note: permission-override privileges; the unwritable-directory arm is skipped"
            );
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        // A later unlock writes the copy normally.
        let s = env.unlock_with(Some(policy(
            &env,
            48,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        assert!(s.snapshot_status().unwrap().published.is_some());
    }

    #[test]
    fn snapshot_listing_ignores_unauthenticated_files() {
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let healthy = s.snapshots().unwrap();
        assert_eq!(healthy.snapshots.len(), 1);
        assert_eq!(healthy.unreadable, 0);
        let dir = env.dir.path().join("snapshots");
        // A garbage file with a valid snapshot name, and one of another kind.
        let name = "0123456789abcdef0123456789abcdef.qvsnap";
        std::fs::write(dir.join(name), b"not an archive").unwrap();
        std::fs::write(dir.join(format!("recover-{name}")), b"nor this").unwrap();
        // Files that are not snapshot names are not even considered.
        std::fs::write(dir.join("notes.txt"), b"x").unwrap();
        let listing = s.snapshots().unwrap();
        assert_eq!(listing.snapshots.len(), 1);
        assert_eq!(listing.unreadable, 2);
        let rows = s
            .snapshots_before(Timestamp(healthy.snapshots[0].created_at.0 + 1))
            .unwrap();
        assert_eq!(rows.len(), 1);
        let rows = s
            .snapshots_before(Timestamp(healthy.snapshots[0].created_at.0))
            .unwrap();
        assert!(rows.is_empty());
        assert_eq!(s.delete_snapshots(&["f".repeat(32)]).unwrap(), 0);
    }

    #[test]
    fn verify_report_counts_anchor_and_never_mutates() {
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let before = std::fs::read(&env.path).unwrap();
        let seq_before = seq(&s);
        let report = s.verify(None).unwrap();
        assert!(report.ok(), "{report:?}");
        assert_eq!(report.anchor, AnchorStatus::Verified);
        assert_eq!(report.local_seq, seq_before);
        assert_eq!(report.vault_id.len(), 32);
        assert_eq!(report.key_generation, 1);
        assert_eq!(report.counts.objects, report.counts.records);
        assert_eq!(report.counts.active_heads, report.counts.records);
        assert_eq!(report.counts.retained_versions, 0);
        assert_eq!(report.counts.tombstones, 0);
        assert_eq!(report.counts.suppressed_records, 0);
        assert!(report.counts.total_bytes > 0);
        assert!(report.notes.is_empty());
        assert_eq!(std::fs::read(&env.path).unwrap(), before);

        // A purge floor covering a dominated version is expected state: it is
        // counted and labelled, never reported as damage.
        let root = s.root().unwrap();
        let e = add_entry(&s, root, "Gone");
        s.delete(crate::ItemHandle::Entry(e), false).unwrap();
        s.empty_trash().unwrap();
        let report = s.verify(None).unwrap();
        assert!(report.ok(), "{report:?}");
        assert!(report.counts.suppressed_records >= 1);
        assert_eq!(
            report.notes,
            vec![VerifyNote::SuppressionFloorCoversDominatedVersions]
        );
        assert_eq!(
            VerifyNote::SuppressionFloorCoversDominatedVersions.label(),
            "suppression-floor-covers-dominated-versions"
        );
    }

    #[test]
    fn snapshot_pruning_breaks_equal_timestamps_by_archive_id() {
        let env = Env::new();
        let day = 24_000i64;
        let t0 = day * MILLIS_PER_DAY + 6 * 60 * 60 * MILLIS_PER_SECOND;
        env.time.set(t0);
        // The automatic copy and three finished recovery copies all carry the
        // same authenticated creation time.
        let s = env.unlock_with(Some(policy(
            &env,
            48,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let auto = s.snapshot_status().unwrap();
        let auto_id = auto.published.clone().unwrap().archive_id;
        let mut same_time = Vec::new();
        for _ in 0..3 {
            let snap = s.begin_destructive(false, None).unwrap();
            same_time.push(snap.summary().archive_id.clone());
            s.finish_destructive(snap).unwrap();
        }
        let rows = s.snapshots().unwrap().snapshots;
        assert_eq!(rows.len(), 4, "three copies plus the automatic one");
        assert!(rows.iter().all(|r| r.created_at == Timestamp(t0)));
        drop(s);

        // A pass with a count budget of two keeps the two highest archive IDs
        // of the equal-timestamp set plus its own new copy.
        env.time.set(t0 + 60 * 60 * MILLIS_PER_SECOND);
        let s = env.unlock_with(Some(policy(
            &env,
            2,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let mut old = same_time;
        old.push(auto_id);
        old.sort();
        let rows = ids(&s.snapshots().unwrap());
        assert_eq!(rows.len(), 2);
        assert!(rows.contains(&old[3]));
        for pruned in &old[..3] {
            assert!(!rows.contains(pruned));
        }
    }

    #[test]
    fn verify_reports_a_missing_anchor_and_keeps_checking() {
        let env = Env::new();
        for e in std::fs::read_dir(&env.anchors).unwrap() {
            std::fs::remove_file(e.unwrap().path()).unwrap();
        }
        let core: crate::Core = env.core();
        let _k = kdf();
        let (s, status) = core
            .unlock_for_recovery(&env.path, &pw(crate::testutil::PASSWORD), None)
            .unwrap();
        assert_eq!(status, AnchorStatus::Missing);
        let report = s.verify(None).unwrap();
        assert_eq!(report.anchor, AnchorStatus::Missing);
        assert!(!report.ok());
        assert!(report.counts.objects > 0);
        assert_eq!(report.notes, Vec::new());
    }

    #[test]
    fn verify_cancellation_is_an_error() {
        let env = Env::new();
        let s = env.unlock_with(None);
        let token = crate::CancelToken::new();
        token.cancel();
        assert_eq!(
            err(s.verify(Some(&token))),
            CoreError::Store(StoreError::Io)
        );
    }

    #[test]
    fn live_sqlite_copying_snapshots_never_copy_or_write_the_vault() {
        // 0012 §1 row "Live SQLite copying": the copy is a new archive stream
        // of verified objects, never a copy or normalization of the database,
        // and taking it writes no vault state.
        let env = Env::new();
        let before = std::fs::read(&env.path).unwrap();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let seq_before = seq(&s);
        let snapshot = s.begin_destructive(false, None).unwrap();
        s.finish_destructive(snapshot).unwrap();
        assert_eq!(seq(&s), seq_before, "a snapshot committed vault state");
        assert_eq!(
            std::fs::read(&env.path).unwrap(),
            before,
            "the vault file changed"
        );
        let dir = env.dir.path().join("snapshots");
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        assert!(!files.is_empty());
        for path in files {
            let bytes = std::fs::read(path).unwrap();
            assert_eq!(&bytes[..7], b"QVSNAP\0");
            assert_ne!(bytes, before);
            assert!(
                !bytes.windows(16).any(|w| w == b"SQLite format 3\0"),
                "a snapshot contains SQLite pages"
            );
        }
    }

    #[test]
    fn snapshot_disk_growth_a_full_disk_aborts_the_mandatory_copy() {
        use std::os::unix::fs::PermissionsExt;

        let env = Env::new();
        let s = env.unlock_with(Some(policy(
            &env,
            48,
            DEFAULT_MAX_BYTES,
            DEFAULT_MAX_AGE_SECONDS,
        )));
        let dir = env.dir.path().join("snapshots");
        let seq_before = seq(&s);
        // An unsafe private directory refuses the copy outright; this check
        // does not depend on the process's privileges.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            err(s.begin_destructive(false, None)),
            CoreError::Store(StoreError::UnsafeFile)
        );
        // A read-only directory is the same abort through the I/O path, where
        // the process cannot override permissions (ordinary unprivileged
        // runs). The store's writer covers the disk-full error path itself.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
        let denied = std::fs::write(dir.join("probe"), b"").is_err();
        let _ = std::fs::remove_file(dir.join("probe"));
        if denied {
            assert_eq!(
                err(s.begin_destructive(false, None)),
                CoreError::Store(StoreError::Io)
            );
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(seq(&s), seq_before);
        assert!(s.begin_destructive(true, None).is_ok());
    }
    #[test]
    fn snapshot_publication_failure_preserves_expired_recovery_material() {
        use std::os::unix::fs::PermissionsExt;
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let old = s.snapshots().unwrap().snapshots[0].archive_id.clone();
        drop(s);
        env.time.set(i64::MAX / 2);
        let configured = policy(&env, 48, DEFAULT_MAX_BYTES, 1);
        let dir = configured.dir.path().to_owned();
        let core = env.core_with(Some(configured));
        let _k = kdf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let s = core
            .unlock(&env.path, &pw(crate::testutil::PASSWORD), None)
            .unwrap();
        assert!(s.snapshot_status().unwrap().failed);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(ids(&s.snapshots().unwrap()), vec![old]);
    }
    #[test]
    fn snapshot_restore_preserves_source_and_defers_pruning_the_selected_input() {
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        add_entry(&s, s.root().unwrap(), "from snapshot");
        let snap = s.begin_destructive(false, None).unwrap();
        let id = snap.summary().archive_id.clone();
        s.finish_destructive(snap).unwrap();
        let before = std::fs::read(&env.path).unwrap();
        let anchors: Vec<_> = std::fs::read_dir(&env.anchors)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (p.clone(), std::fs::read(p).unwrap())
            })
            .collect();
        drop(s);
        env.time.set(i64::MAX / 2);
        let core = env.core_with(Some(policy(&env, 48, DEFAULT_MAX_BYTES, 1)));
        let s = {
            let _k = kdf();
            core.unlock_for_snapshot_restore(&env.path, &pw(crate::testutil::PASSWORD), None)
                .unwrap()
        };
        assert!(
            s.snapshot_status().is_none(),
            "automatic pruning ran before restore"
        );
        assert!(
            s.snapshot_matches(&format!("@{}", &id[..6]))
                .unwrap()
                .contains(&id)
        );
        let target = env.path.with_file_name("restored.qvault");
        s.restore_snapshot(&id.to_ascii_uppercase(), &target, None)
            .unwrap();
        assert_eq!(std::fs::read(&env.path).unwrap(), before);
        for (p, bytes) in anchors {
            assert_eq!(std::fs::read(p).unwrap(), bytes);
        }
        let restored = {
            let _k = kdf();
            core.unlock(&target, &pw(crate::testutil::PASSWORD), None)
                .unwrap()
        };
        assert_eq!(restored.overview().unwrap().local_seq, 1);
        assert_eq!(restored.search("from snapshot").unwrap().len(), 1);
        assert!(restored.verify(None).unwrap().ok());
        assert!(
            s.snapshot_status().is_some(),
            "deferred policy did not resume after success"
        );
    }

    #[test]
    fn snapshot_restore_rejects_invalid_foreign_missing_and_cancelled_inputs() {
        let env = Env::new();
        let s = env.unlock_with(Some(env.snapshot_policy()));
        let id = s.snapshots().unwrap().snapshots[0].archive_id.clone();
        let target = env.path.with_file_name("restored.qvault");
        assert_eq!(err(s.snapshot_matches("xyz")), CoreError::InvalidInput);
        assert_eq!(
            err(s.restore_snapshot("123456", &target, None)),
            CoreError::InvalidInput
        );
        assert_eq!(
            err(s.restore_snapshot(&"f".repeat(32), &target, None)),
            CoreError::NotFound
        );
        let token = crate::CancelToken::new();
        token.cancel();
        assert!(s.restore_snapshot(&id, &target, Some(&token)).is_err());
        assert!(!target.exists());
        let foreign = "abcdef1234567890abcdef1234567890";
        let path = env
            .dir
            .path()
            .join("snapshots")
            .join(format!("{foreign}.qvsnap"));
        std::fs::write(&path, b"QVSNAP\0garbage").unwrap();
        assert_eq!(
            s.snapshot_matches("abcdef").unwrap(),
            vec![foreign.to_owned()]
        );
        assert!(s.restore_snapshot(foreign, &target, None).is_err());
        assert!(!target.exists());
        s.lock();
        assert_eq!(
            err(s.restore_snapshot(&id, &target, None)),
            CoreError::SessionLocked
        );
    }
}
