// SPDX-License-Identifier: AGPL-3.0-or-later

//! Groups (spec 0003 §4).
//!
//! | Key | Field | CBOR | |
//! |-----|-------|------|---|
//! | 0 | parent | bstr 16, or `null` (root only) | required |
//! | 1 | name | text | required |
//! | 2 | notes | text | optional |
//! | 3 | icon | text | optional |
//! | 4 | order | text (fractional index) | required |
//! | 5 | deleted_at | int (ms) | optional: soft delete |
//!
//! A non-root group with a `null`, missing, deleted or cyclic parent is
//! repaired for display by the tree projection (0003 §4.1), never here.

use qv_encoding::{Decoder, EncodeError, Encoder};

use crate::codec::{
    keep, put_ext, put_id, put_opt_text, put_opt_time, put_text, read_id, read_map_len, read_text,
    read_time, req,
};
use crate::error::ModelError;
use crate::ids::RecordId;
use crate::text::{Extensions, Text};
use crate::time::Timestamp;

/// A group record's payload.
pub struct Group {
    /// The parent group; `None` only for the root.
    pub parent: Option<RecordId>,
    /// The group's name.
    pub name: Text,
    /// Optional notes.
    pub notes: Option<Text>,
    /// An optional built-in icon name.
    pub icon: Option<Text>,
    /// A fractional index for manual ordering among siblings.
    pub order: Text,
    /// Set when the group is in trash (0007 §2.1).
    pub deleted_at: Option<Timestamp>,
    /// Unknown keys.
    pub ext: Extensions,
}

crate::redacted_debug!(Group);

pub(crate) fn decode(d: &mut Decoder<'_>) -> Result<Group, ModelError> {
    let (mut parent, mut name, mut notes, mut icon, mut order, mut deleted_at) =
        (None, None, None, None, None, None);
    let mut ext = Extensions::new();
    for _ in 0..read_map_len(d)? {
        match d.int()? {
            0 => {
                parent = Some(if d.try_null()? {
                    None
                } else {
                    Some(read_id(d)?)
                })
            }
            1 => name = Some(read_text(d)?),
            2 => notes = Some(read_text(d)?),
            3 => icon = Some(read_text(d)?),
            4 => order = Some(read_text(d)?),
            5 => deleted_at = Some(read_time(d)?),
            k => keep(&mut ext, k, d)?,
        }
    }
    Ok(Group {
        parent: req(parent)?,
        name: req(name)?,
        notes,
        icon,
        order: req(order)?,
        deleted_at,
        ext,
    })
}

pub(crate) fn encode(p: &Group, e: &mut Encoder) -> Result<(), EncodeError> {
    e.map(|m| {
        match &p.parent {
            Some(id) => put_id(m, 0, id)?,
            None => m.entry(0, |v| {
                v.null();
                Ok(())
            })?,
        }
        put_text(m, 1, &p.name)?;
        put_opt_text(m, 2, p.notes.as_ref())?;
        put_opt_text(m, 3, p.icon.as_ref())?;
        put_text(m, 4, &p.order)?;
        put_opt_time(m, 5, p.deleted_at)?;
        put_ext(m, &p.ext)
    })
}
