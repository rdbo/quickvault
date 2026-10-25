// SPDX-License-Identifier: AGPL-3.0-or-later

//! Whole-item validation against the profile, without heap allocation.
//!
//! The walk is iterative over a fixed stack of [`MAX_DEPTH`] frames, and every
//! length and count is checked against the remaining input before use. Work
//! is linear in the input length.

use core::cmp::Ordering;

use crate::MAX_DEPTH;
use crate::error::DecodeError;
use crate::head::{ARRAY, BYTES, MAP, NEGATIVE, TEXT, UINT, read_head};

/// Checks that `input` is exactly one canonical item in the QuickVault profile.
pub fn validate(input: &[u8]) -> Result<(), DecodeError> {
    let item = validate_item(input, 0)?;
    if item.end != input.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(())
}

/// The extent of one validated item.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Item {
    /// Offset just past the item.
    pub end: usize,
    /// Container nesting of the item (0 for a scalar).
    pub depth: usize,
}

#[derive(Clone, Copy)]
struct Frame {
    /// Items still to read, counting map keys and values separately.
    remaining: u64,
    is_map: bool,
    /// For maps: the next item is a key.
    expect_key: bool,
    /// For maps: byte range of the previous key.
    prev_key: Option<(usize, usize)>,
}

const EMPTY: Frame = Frame {
    remaining: 0,
    is_map: false,
    expect_key: false,
    prev_key: None,
};

/// Validates the single item starting at `start`; bytes after it are ignored.
pub(crate) fn validate_item(input: &[u8], start: usize) -> Result<Item, DecodeError> {
    let mut stack = [EMPTY; MAX_DEPTH];
    let mut depth = 0usize;
    let mut max_depth = 0usize;
    let mut pos = start;

    loop {
        let parent_is_key_slot = match depth.checked_sub(1) {
            Some(i) => stack.get(i).is_some_and(|f| f.is_map && f.expect_key),
            None => false,
        };
        let item_start = pos;
        let head = read_head(input, pos)?;
        pos = pos.checked_add(head.len).ok_or(DecodeError::Truncated)?;
        if parent_is_key_slot && head.major != UINT && head.major != NEGATIVE {
            return Err(DecodeError::NonIntegerKey);
        }
        let remaining = input.len().saturating_sub(pos);

        let mut opened = false;
        match head.major {
            BYTES | TEXT => {
                let len = usize::try_from(head.arg)
                    .ok()
                    .filter(|&n| n <= remaining)
                    .ok_or(DecodeError::LengthExceedsInput)?;
                let end = pos + len;
                if head.major == TEXT {
                    let text = input.get(pos..end).ok_or(DecodeError::Truncated)?;
                    core::str::from_utf8(text).map_err(|_| DecodeError::InvalidUtf8)?;
                }
                pos = end;
            }
            ARRAY | MAP => {
                let per_entry = if head.major == MAP { 2 } else { 1 };
                let items = head
                    .arg
                    .checked_mul(per_entry)
                    .filter(|&n| n <= remaining as u64)
                    .ok_or(DecodeError::LengthExceedsInput)?;
                if depth >= MAX_DEPTH {
                    return Err(DecodeError::DepthExceeded);
                }
                max_depth = max_depth.max(depth + 1);
                if items > 0 {
                    let is_map = head.major == MAP;
                    let frame = stack.get_mut(depth).ok_or(DecodeError::DepthExceeded)?;
                    *frame = Frame {
                        remaining: items,
                        is_map,
                        expect_key: is_map,
                        prev_key: None,
                    };
                    depth += 1;
                    opened = true;
                }
            }
            // Integers and the accepted simple values (read_head rejects the rest).
            _ => {}
        }

        if parent_is_key_slot {
            let parent = depth
                .checked_sub(1)
                .and_then(|i| stack.get_mut(i))
                .ok_or(DecodeError::Truncated)?;
            let key = input.get(item_start..pos).ok_or(DecodeError::Truncated)?;
            if let Some((a, b)) = parent.prev_key {
                let prev = input.get(a..b).ok_or(DecodeError::Truncated)?;
                match prev.cmp(key) {
                    Ordering::Less => {}
                    Ordering::Equal => return Err(DecodeError::DuplicateKey),
                    Ordering::Greater => return Err(DecodeError::UnorderedKeys),
                }
            }
            parent.prev_key = Some((item_start, pos));
        }

        if opened {
            continue;
        }
        // The item is complete: account for it in its parent(s).
        loop {
            let Some(i) = depth.checked_sub(1) else {
                return Ok(Item {
                    end: pos,
                    depth: max_depth,
                });
            };
            let frame = stack.get_mut(i).ok_or(DecodeError::Truncated)?;
            frame.remaining -= 1;
            if frame.is_map {
                frame.expect_key = !frame.expect_key;
            }
            if frame.remaining > 0 {
                break;
            }
            depth = i;
        }
    }
}
