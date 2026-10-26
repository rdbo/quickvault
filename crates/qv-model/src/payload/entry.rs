// SPDX-License-Identifier: AGPL-3.0-or-later

//! Entries and fields (spec 0003 §5).
//!
//! Entry:
//!
//! | Key | Field | CBOR | |
//! |-----|-------|------|---|
//! | 0 | group | bstr 16 | required |
//! | 1 | type_hint | text | required |
//! | 2 | title | text | required |
//! | 3 | fields | array of field maps (at most [`MAX_FIELDS`]) | required |
//! | 4 | notes | text | optional |
//! | 5 | icon | text | optional |
//! | 6 | expires_at | int (ms) | optional |
//! | 7 | created_at | int (ms) | required |
//! | 8 | modified_at | int (ms) | required |
//! | 9 | deleted_at | int (ms) | optional: soft delete |
//!
//! Field:
//!
//! | Key | Field | CBOR |
//! |-----|-------|------|
//! | 0 | id | bstr 16 |
//! | 1 | name | text |
//! | 2 | kind | uint: 0 text, 1 secret, 2 url, 3 email, 4 totp, 5 multiline, 6 date; other values are kept |
//! | 3 | value | text or bstr (at most 256 KiB) |
//! | 4 | protected | bool |
//!
//! All field keys are required. Field IDs are unique within an entry.
//! `type_hint` is a UI hint only: an unknown one is shown as `custom`
//! (0003 §5.1).

use std::collections::BTreeSet;

use qv_encoding::{Decoder, EncodeError, Encoder, Kind};

use crate::codec::{
    keep, put_bool, put_ext, put_id, put_opt_text, put_opt_time, put_text, put_time, put_uint,
    read_array_len, read_id, read_map_len, read_text, read_time, req,
};
use crate::error::ModelError;
use crate::ids::{FieldId, RecordId};
use crate::text::{Extensions, FieldValue, SecretText, Text};
use crate::time::Timestamp;

/// The most fields in one entry (0004 §4.1).
pub const MAX_FIELDS: usize = 4096;

/// An entry record's payload.
pub struct Entry {
    /// The group the entry is in.
    pub group: RecordId,
    /// `login`, `note`, `card`, …; display only.
    pub type_hint: Text,
    /// The title.
    pub title: Text,
    /// Ordered fields.
    pub fields: Vec<Field>,
    /// Multi-line notes.
    pub notes: Option<Text>,
    /// An optional icon name.
    pub icon: Option<Text>,
    /// An optional expiry date.
    pub expires_at: Option<Timestamp>,
    /// Creation time (display only).
    pub created_at: Timestamp,
    /// Modification time (display only; written equal to the version's).
    pub modified_at: Timestamp,
    /// Set when the entry is in trash (0007 §2.1).
    pub deleted_at: Option<Timestamp>,
    /// Unknown keys.
    pub ext: Extensions,
}

/// One typed field of an entry.
pub struct Field {
    /// A stable ID for UI handles (0008 §4).
    pub id: FieldId,
    /// The field's name, e.g. "Username".
    pub name: Text,
    /// How the value is shown.
    pub kind: FieldKind,
    /// The value, in locked memory.
    pub value: FieldValue,
    /// Whether the UI may show the value directly (0003 §5.3).
    pub protected: bool,
    /// Unknown keys.
    pub ext: Extensions,
}

crate::redacted_debug!(Entry, Field);

/// A field's display kind (0003 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// Plain text.
    Text,
    /// A secret (password, PIN, …).
    Secret,
    /// A URL.
    Url,
    /// An email address.
    Email,
    /// An `otpauth://` URI (0003 §5.4).
    Totp,
    /// Multi-line text.
    Multiline,
    /// A date.
    Date,
    /// A kind from a newer version, kept as is. Its display follows the
    /// field's `protected` flag. Must not be one of the known codes 0–6.
    Unknown(u64),
}

impl FieldKind {
    /// Whether new fields of this kind start protected (0003 §5.3).
    pub fn protected_by_default(self) -> bool {
        matches!(self, Self::Secret | Self::Totp)
    }

    fn code(self) -> u64 {
        match self {
            Self::Text => 0,
            Self::Secret => 1,
            Self::Url => 2,
            Self::Email => 3,
            Self::Totp => 4,
            Self::Multiline => 5,
            Self::Date => 6,
            Self::Unknown(c) => c,
        }
    }

    fn from_code(code: u64) -> Self {
        match code {
            0 => Self::Text,
            1 => Self::Secret,
            2 => Self::Url,
            3 => Self::Email,
            4 => Self::Totp,
            5 => Self::Multiline,
            6 => Self::Date,
            c => Self::Unknown(c),
        }
    }
}

/// Cross-field checks: field count, unique field IDs, canonical unknown kinds.
pub(crate) fn check(p: &Entry) -> Result<(), ModelError> {
    if p.fields.len() > MAX_FIELDS {
        return Err(ModelError::LimitExceeded);
    }
    let mut ids = BTreeSet::new();
    for f in &p.fields {
        if !ids.insert(f.id) {
            return Err(ModelError::Malformed);
        }
        if let FieldKind::Unknown(c) = f.kind
            && c <= 6
        {
            return Err(ModelError::Malformed);
        }
    }
    Ok(())
}

pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Entry, ModelError> {
    let (mut group, mut type_hint, mut title, mut fields) = (None, None, None, None);
    let (mut notes, mut icon, mut expires_at) = (None, None, None);
    let (mut created_at, mut modified_at, mut deleted_at) = (None, None, None);
    let mut ext = Extensions::new();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => group = Some(read_id(d)?),
            1 => type_hint = Some(read_text(d)?),
            2 => title = Some(read_text(d)?),
            3 => {
                let n = read_array_len(d, MAX_FIELDS)?;
                let mut list = Vec::with_capacity(n);
                for _ in 0..n {
                    list.push(decode_field(d)?);
                }
                fields = Some(list);
            }
            4 => notes = Some(read_text(d)?),
            5 => icon = Some(read_text(d)?),
            6 => expires_at = Some(read_time(d)?),
            7 => created_at = Some(read_time(d)?),
            8 => modified_at = Some(read_time(d)?),
            9 => deleted_at = Some(read_time(d)?),
            k => keep(&mut ext, k, d)?,
        }
    }
    Ok(Entry {
        group: req(group)?,
        type_hint: req(type_hint)?,
        title: req(title)?,
        fields: req(fields)?,
        notes,
        icon,
        expires_at,
        created_at: req(created_at)?,
        modified_at: req(modified_at)?,
        deleted_at,
        ext,
    })
}

fn decode_field(d: &mut Decoder<'_>) -> Result<Field, ModelError> {
    let (mut id, mut name, mut kind, mut value, mut protected) = (None, None, None, None, None);
    let mut ext = Extensions::new();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => id = Some(read_id(d)?),
            1 => name = Some(read_text(d)?),
            2 => kind = Some(FieldKind::from_code(d.uint()?)),
            3 => {
                value = Some(match d.peek_kind()? {
                    Kind::Text => FieldValue::Text(SecretText::new(d.text()?)?),
                    Kind::Bytes => FieldValue::bytes(d.bytes()?)?,
                    _ => return Err(ModelError::Malformed),
                })
            }
            4 => protected = Some(d.bool()?),
            k => keep(&mut ext, k, d)?,
        }
    }
    Ok(Field {
        id: req(id)?,
        name: req(name)?,
        kind: req(kind)?,
        value: req(value)?,
        protected: req(protected)?,
        ext,
    })
}

pub(crate) fn encode(p: &Entry, e: &mut Encoder) -> Result<(), EncodeError> {
    e.map(|m| {
        put_id(m, 0, &p.group)?;
        put_text(m, 1, &p.type_hint)?;
        put_text(m, 2, &p.title)?;
        m.entry(3, |v| {
            v.array(|a| {
                for f in &p.fields {
                    encode_field(f, a)?;
                }
                Ok(())
            })
        })?;
        put_opt_text(m, 4, p.notes.as_ref())?;
        put_opt_text(m, 5, p.icon.as_ref())?;
        put_opt_time(m, 6, p.expires_at)?;
        put_time(m, 7, p.created_at)?;
        put_time(m, 8, p.modified_at)?;
        put_opt_time(m, 9, p.deleted_at)?;
        put_ext(m, &p.ext)
    })
}

fn encode_field(f: &Field, e: &mut Encoder) -> Result<(), EncodeError> {
    e.map(|m| {
        put_id(m, 0, &f.id)?;
        put_text(m, 1, &f.name)?;
        put_uint(m, 2, f.kind.code())?;
        m.entry(3, |v| {
            match &f.value {
                FieldValue::Text(t) => v.text(t.expose_secret()),
                FieldValue::Bytes(b) => v.bytes(b.expose_secret()),
            }
            Ok(())
        })?;
        put_bool(m, 4, f.protected)?;
        put_ext(m, &f.ext)
    })
}
