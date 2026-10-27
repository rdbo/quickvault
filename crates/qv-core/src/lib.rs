// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault core: sessions, views and vault operations.
//!
//! The single entry point for every frontend (`ARCHITECTURE.md` §3; 0009
//! §1.1): the CLI and the app call this crate only. It owns session policy
//! (unlock, lock, cancellation, session-scoped handles, mutation
//! authorization) and orchestrates `qv-store`, `qv-model` and `qv-crypto`.
//! It has no frontend, server or network dependency: creating, unlocking
//! and editing a vault needs no account or server (0005 §0.1).
//!
//! | Module | Contents | Spec |
//! |--------|----------|------|
//! | `setup` | [`Core`], [`CoreConfig`], [`TimeSource`], [`Protection`]: process hardening, create (with the recovery phrase), unlock, recovery unlock | 0004 §5.1, 0008 §1.1, 0005 §5.4 |
//! | `session` | [`Session`], [`CancelToken`], the handles | 0008 §1.4, §4.1 |
//! | `index` | The metadata index built from every head, with a 64 MiB budget | 0004 §5.1, 0008 §1.2 |
//! | `views` | Listings, recovered items, trash, conflicts, search, details, reveal, TOTP, expiry report | 0003 §4–5, 0005 §2.3, 0007 §2.1, 0011 §4 |
//! | `edit` | Drafts, edits, moves, soft delete, restore, final deletion | 0005 §1.2, §2.5, 0007 §2 |
//! | `attachment` | Session-bound metadata, streaming import/verify/save and confirmed-by-frontend permanent removal | 0003 §6, 0004 §3.3, 0011 §4 |
//! | `settings` | Vault settings and the password generator | 0003 §3, 0010 §5 |
//! | `order` | Fractional ordering keys for new groups | 0003 §4 |
//! | `strength` | [`password_strength`] (zxcvbn) and [`confirmation_positions`] | 0010 §3.2, §4.2; 0002 §4.2 |
//!
//! **Sessions.** A [`Session`] is `Send + Sync`; calls are serialized.
//! [`Session::lock`] stops running calls at their next check, drops and
//! zeroizes the vault, keys and views, and is final: a locked session never
//! unlocks again, so no late result can repopulate it, and a read that saw
//! the lock request returns [`CoreError::Cancelled`]. Handles carry the
//! session's random tag and cannot be forged outside this crate; one from
//! another session is [`CoreError::StaleHandle`].
//!
//! **Views and secrets.** After the store's verification, every head is
//! decrypted once more to build the index, which keeps only non-protected
//! metadata (titles, names, type hints, icons, timestamps, and non-protected
//! `text`/`url`/`email` field values) as zeroizing text. Protected values
//! and notes stay encrypted until [`Session::entry`], [`Session::reveal`],
//! [`Session::totp`] or a draft decrypts them into short-lived buffers.
//! Search scans the index; no search index exists (0008 §1.2). Every view
//! and draft type has a redacted `Debug` and no `Clone`.
//!
//! **Edits** are causal versions that join every head and advance this
//! replica's counter (0005 §1.2), committed through the store's single
//! mutation transaction (0004 §5.2). Drafts carry their base version, so a
//! stale draft fails with [`CoreError::StaleHandle`]. A record with
//! conflicting versions is shown but not changed ([`CoreError::Conflict`]):
//! resolution comes with merges (phase 2.2).
//!
//! **Trash** (0007 §2): soft deletion of a group covers everything shown
//! under it in one transaction; restoring a group restores what was deleted
//! with it. Final deletion is always an explicit call ([`Session::purge`],
//! [`Session::empty_trash`]): it leaves a permanent tombstone, drops the
//! record's history and advances its floor, and tombstones the entry's
//! attachments. [`Session::expired_trash`] lists what the retention period
//! offers for final deletion and flags a suspicious clock.
//!
//! **Development values** (frozen in phase 1.16): the 64 MiB view budget,
//! the 10-minute clock-anomaly tolerance, the generator-defaults layout in
//! `qv-model`.
//!
//! **Not in this phase:** conflict resolution and merges (2.2), history
//! views, restore and retention (1.12), attachments (1.11), path addressing
//! and the CLI (1.10), the inactivity timer and OS lifecycle hooks (1.9,
//! 2.3), password change and rotation (1.14, 1.15).
//!
//! **Errors**: [`CoreError`] (its rustdoc maps variants to CLI exit codes)
//! carries no data.

mod attachment;
mod edit;
mod error;
mod index;
mod order;
mod session;
mod settings;
mod setup;
mod strength;
#[cfg(test)]
mod testutil;
mod views;

pub use edit::{EntryDraft, GroupDraft, PurgeReport};
pub use error::CoreError;
pub use session::{CancelToken, EntryHandle, FieldHandle, GroupHandle, ItemHandle, Session};
pub use settings::{SettingsDraft, estimate, generate};
pub use setup::{Core, CoreConfig, Created, Protection, SystemTime, TimeSource, VaultInfo, harden};
pub use strength::{PasswordCheck, PasswordVerdict, confirmation_positions, password_strength};
pub use views::{
    ConflictSummary, EntryDetail, EntrySummary, ExpiryReport, FieldDetail, FieldSummary,
    GroupDetail, GroupSummary, Listing, MAX_QUERY_BYTES, Overview, SearchHit, TotpNow, TrashItem,
};

// What frontends need from the lower crates, so that they depend on
// `qv-core` only (`ARCHITECTURE.md` §3).
pub use qv_crypto::{
    Argon2Params, Capitalization, CharacterSettings, CryptoError, Estimate, Generated,
    GeneratorError, GeneratorSettings, Hardening, MasterPassword, MemoryProtection, OtpCode,
    PHRASE_WORDS, PassphraseSettings, PinSettings, ProcessHardening, RecordId, RecoveryPhrase,
    SecretBytes, Strength, WordListId,
};
pub use qv_model::{
    Entry, Extensions, Field, FieldId, FieldKind, FieldValue, GeneratorDefaults, Group, SecretText,
    Settings, Text, Timestamp, TotpError, VaultMeta, VersionId,
};
pub use qv_store::{AnchorDir, AnchorStatus, LocationWarnings, StoreError, VAULT_EXTENSION};

pub use attachment::{AttachmentHandle, AttachmentSummary};
