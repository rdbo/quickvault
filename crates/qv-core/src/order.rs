// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fractional ordering keys for groups (spec 0003 §4: `order` is a
//! fractional index, so concurrent edits keep a stable manual order).
//!
//! Keys are strings of the letters `a`–`z` compared as bytes. Equal keys
//! (two devices appending at once) are ordered by record ID.

/// A key that sorts after `s`. For a key of `a`–`z` letters: `"n"` for an
/// empty `s`; else the first letter plus one if it is below `z` (for
/// example `"b"` after `"azz"`), else `"z"` followed by a key after the
/// rest, so keys stay short. Any other key (written by another client) gets
/// `"n"` appended: a proper prefix sorts first.
pub(crate) fn key_after(s: &str) -> String {
    if !s.bytes().all(|b| b.is_ascii_lowercase()) {
        return format!("{s}n");
    }
    let mut out = String::new();
    for b in s.bytes() {
        if b < b'z' {
            out.push(char::from(b + 1));
            return out;
        }
        out.push('z');
    }
    out.push('n');
    out
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn order_examples() {
        assert_eq!(key_after(""), "n");
        assert_eq!(key_after("a"), "b");
        assert_eq!(key_after("azz"), "b");
        assert_eq!(key_after("z"), "zn");
        assert_eq!(key_after("zzb"), "zzc");
        assert_eq!(key_after("Z"), "Zn");
        assert_eq!(key_after("é"), "én");
    }

    proptest! {
        #[test]
        fn order_key_after_sorts_after(s in "[a-z]{0,12}|\\PC{0,6}") {
            let k = key_after(&s);
            prop_assert!(k.as_bytes() > s.as_bytes());
            prop_assert!(k.len() <= s.len() + 1);
            if s.bytes().all(|b| b.is_ascii_lowercase()) {
                prop_assert!(k.bytes().all(|b| b.is_ascii_lowercase()));
            }
        }
    }
}
