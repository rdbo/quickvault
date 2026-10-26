// SPDX-License-Identifier: AGPL-3.0-or-later

//! Record payloads (spec 0003 §3–6), one module per kind.

pub(crate) mod attachment;
pub(crate) mod entry;
pub(crate) mod group;
pub(crate) mod keyslot;
#[cfg(test)]
mod tests;
pub(crate) mod vault_meta;

use qv_encoding::{Decoder, EncodeError, Encoder};

use crate::error::ModelError;
use crate::record::RecordKind;

pub use attachment::{AttachmentMeta, CHUNK_SIZE, MAX_ATTACHMENT_BYTES};
pub use entry::{Entry, Field, FieldKind, MAX_FIELDS};
pub use group::Group;
pub use keyslot::Keyslot;
pub use vault_meta::{DEFAULT_HISTORY_DEPTH, DEFAULT_TRASH_RETENTION_DAYS, Settings, VaultMeta};

/// A live record's payload; its variant determines the record kind.
pub enum Payload {
    /// Vault metadata.
    VaultMeta(VaultMeta),
    /// A group.
    Group(Group),
    /// An entry.
    Entry(Entry),
    /// Attachment metadata.
    AttachmentMeta(AttachmentMeta),
    /// The password keyslot.
    PasswordKeyslot(Keyslot),
}

crate::redacted_debug!(Payload);

impl Payload {
    /// The record kind of this payload.
    pub fn kind(&self) -> RecordKind {
        match self {
            Self::VaultMeta(_) => RecordKind::VaultMeta,
            Self::Group(_) => RecordKind::Group,
            Self::Entry(_) => RecordKind::Entry,
            Self::AttachmentMeta(_) => RecordKind::AttachmentMeta,
            Self::PasswordKeyslot(_) => RecordKind::PasswordKeyslot,
        }
    }

    /// Whether the payload is soft-deleted (`deleted_at` is set).
    pub fn soft_deleted(&self) -> bool {
        match self {
            Self::Group(g) => g.deleted_at.is_some(),
            Self::Entry(e) => e.deleted_at.is_some(),
            Self::VaultMeta(_) | Self::AttachmentMeta(_) | Self::PasswordKeyslot(_) => false,
        }
    }

    /// Cross-field checks shared by encode and decode.
    pub(crate) fn check(&self) -> Result<(), ModelError> {
        match self {
            Self::Entry(e) => entry::check(e),
            Self::AttachmentMeta(a) => attachment::check(a),
            Self::VaultMeta(_) | Self::Group(_) | Self::PasswordKeyslot(_) => Ok(()),
        }
    }

    pub(crate) fn encode(&self, e: &mut Encoder) -> Result<(), EncodeError> {
        match self {
            Self::VaultMeta(p) => vault_meta::encode(p, e),
            Self::Group(p) => group::encode(p, e),
            Self::Entry(p) => entry::encode(p, e),
            Self::AttachmentMeta(p) => attachment::encode(p, e),
            Self::PasswordKeyslot(p) => keyslot::encode(p, e),
        }
    }

    pub(crate) fn decode(kind: RecordKind, d: &mut Decoder<'_>) -> Result<Self, ModelError> {
        Ok(match kind {
            RecordKind::VaultMeta => Self::VaultMeta(vault_meta::decode(d)?),
            RecordKind::Group => Self::Group(group::decode(d)?),
            RecordKind::Entry => Self::Entry(entry::decode(d)?),
            RecordKind::AttachmentMeta => Self::AttachmentMeta(attachment::decode(d)?),
            RecordKind::PasswordKeyslot => Self::PasswordKeyslot(keyslot::decode(d)?),
        })
    }
}
