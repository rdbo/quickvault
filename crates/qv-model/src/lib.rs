// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault data model: records, version vectors and merge.
//!
//! This crate is part of the trusted client (`ARCHITECTURE.md` §3). It
//! depends on `qv-crypto` and `qv-encoding` only, and on no frontend.
//! Frontends reach it only through `qv-core`.
//!
//! **Trust boundary.** Records reach the model only after authentication
//! (phase 1.7), but any holder of the vault key can author them, including
//! another device or a hostile peer. Every decode is therefore strict and
//! bounded before allocation, and a fuzz target (`fuzz/record_decode`)
//! checks that accepted input re-encodes byte for byte.
//!
//! | Module | Contents | Spec |
//! |--------|----------|------|
//! | IDs | [`RandomId`]: UUIDv4 generation and validation for every ID | 0003 §1.1 |
//! | [`Clock`] | Version vectors: wire form, [`Causality`], join, [`Clock::for_edit`] | 0005 §1 |
//! | [`RecordVersion`] | One version's plaintext; [`Payload`] for the five kinds | 0003 §2–6, 0004 §3.2 |
//! | [`merge`] | Maximal-version merge, representative, [`RecordStatus`], [`HistoryFloor`] | 0005 §2, 0007 §1.2 |
//! | [`project_groups`] | Deterministic display tree and recovered-items placement | 0003 §4.1–4.2 |
//! | [`Totp`] | `otpauth://totp` URIs and RFC 6238 codes (HMAC in `qv-crypto`) | 0003 §5.4 |
//!
//! **Format.** Each record kind's integer-key registry is documented on its
//! payload type and on [`RecordVersion`]. The keys are **development values**:
//! the on-disk format is unstable until the format freeze (roadmap phase
//! 1.16), which records the frozen registry in specs 0003/0004. Optional keys
//! are absent when the value is absent, never `null`, so every value has one
//! encoding. Unknown keys are kept verbatim ([`Extensions`]); unknown record
//! kinds and keyslot profiles fail closed.
//!
//! **Readings of the specs** (plan 0007, *Decisions needed*): IDs without the
//! UUIDv4 bits are rejected on decode; a final tombstone keeps its kind and
//! has no payload; the attachment ID is the `attachment_meta` record ID; the
//! live and trash representatives follow the deletion-visibility rule in
//! [`merge`]; a group is deleted for the tree only when no head is live.
//!
//! **Secrets.** Field values are in locked memory ([`FieldValue`],
//! [`SecretText`]); metadata text is zeroizing ([`Text`]); unknown entries are
//! zeroizing `RawValue`s; encodings are returned as `Zeroizing<Vec<u8>>`. No
//! payload type has `Clone`, `PartialEq` or `Display`, and their `Debug` is
//! redacted. IDs, clocks, kinds and timestamps are not secret.
//!
//! **Errors**: [`ModelError`] (its rustdoc maps variants to CLI exit codes)
//! and [`TotpError`] carry no data.

/// Implements a redacted `Debug` (`Name(<redacted>)`) for each type.
macro_rules! redacted_debug {
    ($($t:ident),+ $(,)?) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )+};
}
pub(crate) use redacted_debug;

mod clock;
mod codec;
mod error;
mod ids;
mod merge;
mod payload;
mod record;
mod text;
mod time;
mod totp;
mod tree;

pub use clock::{Causality, Clock, MAX_WRITERS};
pub use error::ModelError;
pub use ids::{
    AttachmentId, FieldId, ObjectId, RandomId, RecordId, SlotId, VaultId, VersionId, WriterId,
    attachment_id,
};
pub use merge::{
    HistoryFloor, MAX_HEADS, Merged, RecordStatus, Versioned, View, merge, merge_record,
};
pub use payload::{
    AttachmentMeta, CHUNK_SIZE, DEFAULT_HISTORY_DEPTH, DEFAULT_TRASH_RETENTION_DAYS, Entry, Field,
    FieldKind, GeneratorDefaults, Group, Keyslot, MAX_ATTACHMENT_BYTES, MAX_FIELDS, Payload,
    Settings, VaultMeta,
};
pub use record::{Deletion, RecordBody, RecordKind, RecordVersion};
pub use text::{Extensions, FieldValue, MAX_RECORD_BYTES, MAX_TEXT_BYTES, SecretText, Text};
pub use time::Timestamp;
pub use totp::{Totp, TotpError};
pub use tree::{EntryPlace, GroupNode, GroupTree, MAX_GROUPS, project_groups};
