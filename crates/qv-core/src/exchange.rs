// SPDX-License-Identifier: AGPL-3.0-or-later

//! Explicit archive exchange, serialized with recovery copies and core views.

use std::path::Path;

use qv_store::StoreError;
#[cfg(any(target_os = "linux", target_os = "android"))]
use qv_store::{ArchiveScope, SnapshotDir, SnapshotKind, VerifiedIncoming};

#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::index::{Index, MAX_VIEW_BYTES};
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::snapshot::{begin_recovery, finish_recovery};
use crate::{CancelToken, CoreError, Session};

/// Actual local acceptance, independently of anchor-completion errors.
pub struct ArchiveMergeReport {
    /// A new durable local commit; false means identical filename redelivery.
    pub accepted: bool,
    /// Current unresolved conflicts, including control records and attachments.
    pub conflicts: usize,
    /// A failure after durable acceptance, which must not hide that acceptance.
    pub completion_error: Option<CoreError>,
}

/// A newly published immutable archive. Its ID is random metadata.
pub struct ArchiveExportReport {
    /// The published filename is this ID followed by `.qvsnap`.
    pub archive_id: String,
    /// Whether explicit backup consent permitted a password guessing target.
    pub self_contained: bool,
}

macro_rules! redacted {
    ($($t:ty),+) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )+};
}
redacted!(ArchiveMergeReport, ArchiveExportReport);

#[cfg(any(target_os = "linux", target_os = "android"))]
impl Session {
    /// Authenticate a stable archive, take a mandatory recovery copy, and merge
    /// complete versions without resolving conflicts or adopting password slots.
    /// `allow_over_budget` requires explicit consent to the recovery-copy size.
    pub fn merge_archive(
        &self,
        source: &Path,
        allow_over_budget: bool,
        cancel: Option<&CancelToken>,
    ) -> Result<ArchiveMergeReport, CoreError> {
        self.merge_archive_with_budget(source, allow_over_budget, cancel, MAX_VIEW_BYTES)
    }

    fn merge_archive_with_budget(
        &self,
        source: &Path,
        allow_over_budget: bool,
        cancel: Option<&CancelToken>,
        view_budget: usize,
    ) -> Result<ArchiveMergeReport, CoreError> {
        self.mutate(|ctx| {
            let c = ctx.canceller();
            let cancelled = || c.is_cancelled() || cancel.is_some_and(CancelToken::is_cancelled);
            if cancelled() {
                return Err(CoreError::Cancelled);
            }
            if ctx.open.read_only {
                return Err(StoreError::NoAnchor.into());
            }
            let policy = ctx.open.snapshots.clone().ok_or(CoreError::NotAllowed)?;
            let header = ctx.open.vault.header();
            let mut incoming = VerifiedIncoming::open(
                source,
                policy.dir.path(),
                ArchiveScope::new(header.vault_id, header.key_generation),
                ctx.open.vault.vault_key(),
                &cancelled,
            )
            .map_err(|e| {
                if cancelled() {
                    CoreError::Cancelled
                } else {
                    e.into()
                }
            })?;
            let now = ctx.now();
            let recovery = begin_recovery(ctx.open, now, allow_over_budget, &cancelled)
                .map_err(|e| if cancelled() { CoreError::Cancelled } else { e })?;
            let before = ctx.open.vault.local_seq();
            let mut proposed = None;
            let mut preflight_error = None;
            let result = ctx.open.vault.accept_incoming(
                &mut incoming,
                &mut |local, incoming, read| {
                    let candidate =
                        qv_sync::merge(local, incoming, &mut |s, r, v| read(s, r, v), &cancelled)?;
                    let index = Index::from_manifest(
                        candidate.manifest(),
                        &mut |r, v| {
                            let role = candidate
                                .manifest()
                                .record(r)
                                .and_then(|r| r.version(v))
                                .ok_or(CoreError::Internal)?;
                            let source = candidate
                                .source(role.object_id())
                                .ok_or(CoreError::Internal)?;
                            Ok(read(source, r, v)?)
                        },
                        &cancelled,
                        view_budget,
                    )
                    .map_err(|e| {
                        preflight_error = Some(e);
                        StoreError::Internal
                    })?;
                    proposed = Some(index);
                    #[cfg(test)]
                    crate::session::hooks::reached(crate::session::hooks::Point::BeforeCommit);
                    Ok(candidate.manifest().clone())
                },
                &cancelled,
            );
            #[cfg(test)]
            crate::session::hooks::reached(crate::session::hooks::Point::AfterCommit);
            let accepted = ctx.open.vault.local_seq() != before;
            if accepted {
                let Some(index) = proposed else {
                    ctx.poison = true;
                    return Err(CoreError::Internal);
                };
                ctx.open.index = index;
            } else if let Err(e) = result {
                return Err(preflight_error.unwrap_or_else(|| {
                    if cancelled() {
                        CoreError::Cancelled
                    } else {
                        e.into()
                    }
                }));
            }
            let mut completion_error = result.err().map(Into::into);
            if completion_error.is_none() {
                completion_error = finish_recovery(ctx.open, recovery).err();
            }
            Ok(ArchiveMergeReport {
                accepted,
                conflicts: ctx
                    .open
                    .index
                    .records
                    .values()
                    .filter(|r| r.status.conflict)
                    .count(),
                completion_error,
            })
        })
    }

    /// Publish a new archive in a private directory separate from policy
    /// snapshots. A true `self_contained` is explicit authorization to include
    /// the working local password slot, after the frontend's guessing warning.
    pub fn export_archive(
        &self,
        directory: &Path,
        self_contained: bool,
        cancel: Option<&CancelToken>,
    ) -> Result<ArchiveExportReport, CoreError> {
        self.mutate(|ctx| {
            let c = ctx.canceller();
            let cancelled = || c.is_cancelled() || cancel.is_some_and(CancelToken::is_cancelled);
            if cancelled() {
                return Err(CoreError::Cancelled);
            }
            let destination = SnapshotDir::open(directory)?;
            if let Some(policy) = &ctx.open.snapshots {
                let canonical = |p| std::fs::canonicalize(p).map_err(|_| StoreError::Io);
                if canonical(destination.path())? == canonical(policy.dir.path())? {
                    return Err(StoreError::UnsafeFile.into());
                }
            }
            let now = ctx.now();
            let published = destination.publish_export(
                &mut ctx.open.vault,
                SnapshotKind::Ordinary,
                now,
                self_contained,
                &cancelled,
            )?;
            Ok(ArchiveExportReport {
                archive_id: published.archive_id().to_owned(),
                self_contained,
            })
        })
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
#[path = "exchange_tests.rs"]
mod tests;

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl Session {
    /// Archive exchange is unavailable until this platform has safe adapters.
    pub fn merge_archive(
        &self,
        _source: &Path,
        _allow_over_budget: bool,
        _cancel: Option<&CancelToken>,
    ) -> Result<ArchiveMergeReport, CoreError> {
        Err(StoreError::Unsupported.into())
    }
    /// Archive publication is unavailable until this platform has safe adapters.
    pub fn export_archive(
        &self,
        _directory: &Path,
        _self_contained: bool,
        _cancel: Option<&CancelToken>,
    ) -> Result<ArchiveExportReport, CoreError> {
        Err(StoreError::Unsupported.into())
    }
}
