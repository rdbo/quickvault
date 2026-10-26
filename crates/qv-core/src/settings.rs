// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault settings and the password generator (spec 0003 §3, 0007 §1.1,
//! §2.1, 0010 §5).
//!
//! The generator itself lives in `qv-crypto`, which validates every setting
//! before using the RNG; stored defaults are revalidated at each use
//! (0010 §2.1.3).

use qv_crypto::{Estimate, Generated, GeneratorSettings, RecordId};
use qv_model::{Extensions, Payload, RecordBody, RecordKind, VaultMeta, VersionId};

use crate::edit::{Change, commit};
use crate::error::CoreError;
use crate::session::{Session, SessionTag};
use crate::views::{decrypt, record};

/// Generates a password, passphrase or PIN without a vault (0011
/// `generate`).
pub fn generate(settings: &GeneratorSettings) -> Result<Generated, CoreError> {
    Ok(qv_crypto::generate(settings)?)
}

/// The exact entropy of `settings`, which are validated first.
pub fn estimate(settings: &GeneratorSettings) -> Result<Estimate, CoreError> {
    Ok(qv_crypto::estimate(settings)?)
}

/// The vault metadata, to change its name, description or settings.
pub struct SettingsDraft {
    session: SessionTag,
    record: RecordId,
    base: VersionId,
    root: RecordId,
    meta: VaultMeta,
    ext: Extensions,
}

impl core::fmt::Debug for SettingsDraft {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SettingsDraft(<redacted>)")
    }
}

impl SettingsDraft {
    /// The vault metadata.
    pub fn meta(&self) -> &VaultMeta {
        &self.meta
    }

    /// The vault metadata, to change. `root_group` must stay as it is
    /// ([`CoreError::NotAllowed`] on save, 0003 §2.3). `history_depth` is
    /// stored but not applied before history retention (phase 1.12).
    pub fn meta_mut(&mut self) -> &mut VaultMeta {
        &mut self.meta
    }
}

impl Session {
    /// The vault's generator defaults, or the 0010 defaults.
    pub fn generator_defaults(&self) -> Result<GeneratorSettings, CoreError> {
        self.read(|ctx| {
            Ok(ctx
                .open
                .index
                .meta()
                .and_then(|m| m.generator.clone())
                .unwrap_or_default())
        })
    }

    /// Generates with `overrides`, or with the vault's defaults.
    pub fn generate(&self, overrides: Option<&GeneratorSettings>) -> Result<Generated, CoreError> {
        let settings = match overrides {
            Some(s) => s.clone(),
            None => self.generator_defaults()?,
        };
        generate(&settings)
    }

    /// A draft of the vault metadata's current version.
    pub fn edit_settings(&self) -> Result<SettingsDraft, CoreError> {
        self.read(|ctx| {
            let id = ctx.open.index.vault_meta;
            let v = record(&ctx.open.index, id, RecordKind::VaultMeta)?.single_head()?;
            let version = decrypt(ctx, id, v)?;
            let RecordBody::Live(Payload::VaultMeta(meta)) = version.body else {
                return Err(CoreError::Store(qv_store::StoreError::Integrity));
            };
            Ok(SettingsDraft {
                session: ctx.tag(),
                record: id,
                base: v,
                root: ctx.open.index.root,
                meta,
                ext: version.ext,
            })
        })
    }

    /// Records that the user explicitly skipped confirming the recovery
    /// phrase (0002 §4.2), as a synced vault setting with the current time.
    pub fn record_recovery_skip(&self) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            let id = ctx.open.index.vault_meta;
            let v = record(&ctx.open.index, id, RecordKind::VaultMeta)?.single_head()?;
            let version = decrypt(ctx, id, v)?;
            let RecordBody::Live(Payload::VaultMeta(mut meta)) = version.body else {
                return Err(CoreError::Store(qv_store::StoreError::Integrity));
            };
            meta.settings.recovery_skipped_at = Some(ctx.now());
            commit(
                ctx,
                vec![Change {
                    record: id,
                    kind: RecordKind::VaultMeta,
                    body: RecordBody::Live(Payload::VaultMeta(meta)),
                    ext: version.ext,
                }],
            )
        })
    }

    /// Saves the vault metadata as a new causal version.
    pub fn save_settings(&self, draft: SettingsDraft) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            ctx.own(draft.session)?;
            let r = record(&ctx.open.index, draft.record, RecordKind::VaultMeta)?;
            if r.single_head()? != draft.base {
                return Err(CoreError::StaleHandle);
            }
            if draft.meta.root_group != draft.root {
                return Err(CoreError::NotAllowed);
            }
            commit(
                ctx,
                vec![Change {
                    record: draft.record,
                    kind: RecordKind::VaultMeta,
                    body: RecordBody::Live(Payload::VaultMeta(draft.meta)),
                    ext: draft.ext,
                }],
            )
        })
    }
}
