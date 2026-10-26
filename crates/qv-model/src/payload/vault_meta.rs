// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault metadata (spec 0003 §3).
//!
//! | Key | Field | CBOR | |
//! |-----|-------|------|---|
//! | 0 | name | text | required |
//! | 1 | description | text | optional |
//! | 2 | root_group | bstr 16 | required |
//! | 3 | settings | map | required |
//!
//! Settings: 0 `history_depth` (uint, optional, default 10, 0007 §1.1),
//! 1 `trash_retention_days` (uint, optional, default 30, 0007 §2.1).
//! Key 2 is reserved for the password generator defaults (0010 §5.1,
//! phase 1.8); until then it is kept like any unknown key.

use qv_encoding::{Decoder, EncodeError, Encoder};

use crate::codec::{
    keep, put_ext, put_id, put_opt_text, put_opt_uint, put_text, read_id, read_map_len, read_text,
    read_u32, req,
};
use crate::error::ModelError;
use crate::ids::RecordId;
use crate::text::{Extensions, Text};

/// The default number of retained historical versions (0007 §1.1).
pub const DEFAULT_HISTORY_DEPTH: u32 = 10;
/// The default trash retention in days (0007 §2.1).
pub const DEFAULT_TRASH_RETENTION_DAYS: u32 = 30;

/// The vault metadata record's payload. Exactly one per vault.
pub struct VaultMeta {
    /// The vault's name.
    pub name: Text,
    /// An optional description.
    pub description: Option<Text>,
    /// The root group, fixed at vault creation (0003 §2.3).
    pub root_group: RecordId,
    /// Vault-wide settings.
    pub settings: Settings,
    /// Unknown keys.
    pub ext: Extensions,
}

/// Vault-wide settings (0003 §3). `None` means "the default".
#[derive(Default)]
pub struct Settings {
    /// Historical versions to keep per record.
    pub history_depth: Option<u32>,
    /// Days before trashed items are offered for final deletion.
    pub trash_retention_days: Option<u32>,
    /// Unknown keys, including the reserved generator defaults.
    pub ext: Extensions,
}

impl Settings {
    /// The history depth, or [`DEFAULT_HISTORY_DEPTH`].
    pub fn history_depth_or_default(&self) -> u32 {
        self.history_depth.unwrap_or(DEFAULT_HISTORY_DEPTH)
    }

    /// The trash retention, or [`DEFAULT_TRASH_RETENTION_DAYS`].
    pub fn trash_retention_days_or_default(&self) -> u32 {
        self.trash_retention_days
            .unwrap_or(DEFAULT_TRASH_RETENTION_DAYS)
    }
}

crate::redacted_debug!(VaultMeta, Settings);

pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<VaultMeta, ModelError> {
    let (mut name, mut description, mut root, mut settings) = (None, None, None, None);
    let mut ext = Extensions::new();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => name = Some(read_text(d)?),
            1 => description = Some(read_text(d)?),
            2 => root = Some(read_id(d)?),
            3 => settings = Some(decode_settings(d)?),
            k => keep(&mut ext, k, d)?,
        }
    }
    Ok(VaultMeta {
        name: req(name)?,
        description,
        root_group: req(root)?,
        settings: req(settings)?,
        ext,
    })
}

fn decode_settings(d: &mut Decoder<'_>) -> Result<Settings, ModelError> {
    let mut s = Settings::default();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => s.history_depth = Some(read_u32(d)?),
            1 => s.trash_retention_days = Some(read_u32(d)?),
            k => keep(&mut s.ext, k, d)?,
        }
    }
    Ok(s)
}

pub(crate) fn encode(p: &VaultMeta, e: &mut Encoder) -> Result<(), EncodeError> {
    e.map(|m| {
        put_text(m, 0, &p.name)?;
        put_opt_text(m, 1, p.description.as_ref())?;
        put_id(m, 2, &p.root_group)?;
        m.entry(3, |v| {
            v.map(|s| {
                put_opt_uint(s, 0, p.settings.history_depth.map(u64::from))?;
                put_opt_uint(s, 1, p.settings.trash_retention_days.map(u64::from))?;
                put_ext(s, &p.settings.ext)
            })
        })?;
        put_ext(m, &p.ext)
    })
}
