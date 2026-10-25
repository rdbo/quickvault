// SPDX-License-Identifier: AGPL-3.0-or-later

//! Every noncanonical form of RFC 8949 §4.2, and every profile rejection,
//! fails with its exact error. Accepted forms are pinned alongside.

use qv_encoding::{DecodeError as E, MAX_DEPTH, validate};

#[track_caller]
fn rejects(input: &[u8], expected: E) {
    assert_eq!(validate(input), Err(expected), "input {input:02x?}");
}

#[track_caller]
fn accepts(input: &[u8]) {
    assert_eq!(validate(input), Ok(()), "input {input:02x?}");
}

/// `n` nested arrays around `inner`.
fn nested_arrays(n: usize, inner: &[u8]) -> Vec<u8> {
    let mut v = vec![0x81; n];
    v.extend_from_slice(inner);
    v
}

#[test]
fn reject_non_shortest_arguments_for_every_major_type() {
    // Each is a complete item, so only the argument form is wrong.
    for major in 0u8..=5 {
        let m = major << 5;
        let pad: &[u8] = match major {
            // Strings/containers of length 0 need no payload; length 1 needs one.
            2 | 3 => &[0x61],
            4 => &[0x00],
            5 => &[0x00, 0x00],
            _ => &[],
        };
        for (head, len_is_one) in [
            (vec![m | 24, 0x00], false),
            (vec![m | 24, 0x01], true),
            (vec![m | 24, 0x17], false),
            (vec![m | 25, 0x00, 0x00], false),
            (vec![m | 25, 0x00, 0x01], true),
            (vec![m | 25, 0x00, 0xff], false),
            (vec![m | 26, 0x00, 0x00, 0x00, 0x00], false),
            (vec![m | 26, 0x00, 0x00, 0x00, 0x01], true),
            (vec![m | 26, 0x00, 0x00, 0xff, 0xff], false),
            (vec![m | 27, 0, 0, 0, 0, 0, 0, 0, 0], false),
            (vec![m | 27, 0, 0, 0, 0, 0, 0, 0, 1], true),
            (vec![m | 27, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff], false),
        ] {
            let mut item = head;
            if len_is_one {
                item.extend_from_slice(pad);
            }
            rejects(&item, E::NonShortestArgument);
        }
    }
}

#[test]
fn reject_indefinite_lengths() {
    rejects(&[0x5f, 0x41, 0x00, 0xff], E::IndefiniteLength); // bytes
    rejects(&[0x7f, 0x61, 0x61, 0xff], E::IndefiniteLength); // text
    rejects(&[0x9f, 0x00, 0xff], E::IndefiniteLength); // array
    rejects(&[0xbf, 0x00, 0x00, 0xff], E::IndefiniteLength); // map
    rejects(&[0x1f], E::IndefiniteLength); // malformed for ints
    rejects(&[0x3f], E::IndefiniteLength);
    // A stray break is a simple-value item, not a container end.
    rejects(&[0xff], E::UnsupportedSimple);
    rejects(&[0x82, 0x00, 0xff], E::UnsupportedSimple);
}

#[test]
fn reject_reserved_additional_info() {
    for major in 0u8..=5 {
        for info in 28u8..=30 {
            rejects(&[(major << 5) | info], E::ReservedAdditionalInfo);
        }
    }
    for b in [0xfc, 0xfd, 0xfe] {
        rejects(&[b], E::ReservedAdditionalInfo);
    }
}

#[test]
fn reject_tags_including_bignums() {
    for b in 0xc0u8..=0xd7 {
        rejects(&[b, 0x00], E::Tag);
    }
    rejects(&[0xd8, 0x20, 0x00], E::Tag);
    rejects(&[0xd9, 0x01, 0x00, 0x00], E::Tag);
    rejects(&[0xc2, 0x41, 0x01], E::Tag); // positive bignum
    rejects(&[0xc3, 0x41, 0x01], E::Tag); // negative bignum
    rejects(&[0x81, 0xc0, 0x00], E::Tag); // nested
}

#[test]
fn reject_floats_and_simple_values() {
    rejects(&[0xf9, 0x00, 0x00], E::Float); // half 0.0
    rejects(&[0xf9, 0x7e, 0x00], E::Float); // half NaN
    rejects(&[0xfa, 0x47, 0xc3, 0x50, 0x00], E::Float);
    rejects(
        &[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a],
        E::Float,
    );
    rejects(&[0xf7], E::UnsupportedSimple); // undefined
    rejects(&[0xe0], E::UnsupportedSimple); // simple(0)
    rejects(&[0xf3], E::UnsupportedSimple); // simple(19)
    rejects(&[0xf8, 0x20], E::UnsupportedSimple); // simple(32)
    rejects(&[0xf8, 0xff], E::UnsupportedSimple);
    rejects(&[0xf8, 0x14], E::UnsupportedSimple); // false, badly encoded
}

#[test]
fn reject_invalid_utf8() {
    rejects(&[0x62, 0xc0, 0x80], E::InvalidUtf8); // overlong NUL
    rejects(&[0x63, 0xed, 0xa0, 0x80], E::InvalidUtf8); // lone surrogate
    rejects(&[0x62, 0xe2, 0x82], E::InvalidUtf8); // truncated 3-byte sequence
    rejects(&[0x61, 0xff], E::InvalidUtf8);
    rejects(&[0x61, 0x80], E::InvalidUtf8); // lone continuation byte
    accepts(&[0x63, 0xe2, 0x82, 0xac]); // "€"
    accepts(&[0x64, 0xf0, 0x9f, 0x94, 0x91]); // "🔑"
    accepts(&[0x62, 0xc3, 0xbc]); // "ü"
    // Bytes are not UTF-8 checked.
    accepts(&[0x42, 0xc0, 0x80]);
}

#[test]
fn reject_non_integer_map_keys() {
    rejects(&[0xa1, 0x61, 0x61, 0x00], E::NonIntegerKey); // text
    rejects(&[0xa1, 0x41, 0x00, 0x00], E::NonIntegerKey); // bytes
    rejects(&[0xa1, 0x80, 0x00], E::NonIntegerKey); // array
    rejects(&[0xa1, 0xa0, 0x00], E::NonIntegerKey); // map
    rejects(&[0xa1, 0xf4, 0x00], E::NonIntegerKey); // bool
    rejects(&[0xa1, 0xf6, 0x00], E::NonIntegerKey); // null
    // Values may be anything in the profile.
    accepts(&[0xa1, 0x00, 0x61, 0x61]);
    accepts(&[0xa1, 0x20, 0xa1, 0x00, 0x80]);
}

#[test]
fn reject_duplicate_and_unordered_keys() {
    rejects(&[0xa2, 0x01, 0x00, 0x01, 0x00], E::DuplicateKey);
    rejects(&[0xa2, 0x20, 0x00, 0x20, 0x00], E::DuplicateKey);
    rejects(&[0xa2, 0x02, 0x00, 0x01, 0x00], E::UnorderedKeys);
    rejects(
        &[0xa3, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00],
        E::UnorderedKeys,
    );
    rejects(&[0xa2, 0x21, 0x00, 0x20, 0x00], E::UnorderedKeys); // -2 before -1
    accepts(&[0xa3, 0x00, 0x00, 0x01, 0x00, 0x17, 0x00]);
    accepts(&[0xa2, 0x20, 0x00, 0x21, 0x00]); // -1, -2
}

#[test]
fn key_order_is_bytewise_not_length_first() {
    // 24 encodes as 18 18 and -1 as 20: bytewise, 24 comes first.
    // Length-first ordering (RFC 8949 §4.2.3) would put -1 first.
    accepts(&[0xa2, 0x18, 0x18, 0x00, 0x20, 0x00]);
    rejects(&[0xa2, 0x20, 0x00, 0x18, 0x18, 0x00], E::UnorderedKeys);
    // Every unsigned key sorts before every negative key.
    accepts(&[
        0xa2, 0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x20, 0x00,
    ]);
    rejects(&[0xa2, 0x20, 0x00, 0x00, 0x00], E::UnorderedKeys);
    // Within unsigned: shorter heads first.
    accepts(&[0xa2, 0x17, 0x00, 0x18, 0x18, 0x00]);
    rejects(
        &[0xa2, 0x19, 0x01, 0x00, 0x00, 0x18, 0xff, 0x00],
        E::UnorderedKeys,
    );
}

#[test]
fn key_order_is_checked_per_map_not_across_maps() {
    // {1: {0: 0}, 2: {0: 0}} — inner maps restart ordering.
    accepts(&[0xa2, 0x01, 0xa1, 0x00, 0x00, 0x02, 0xa1, 0x00, 0x00]);
    // {0: {5: 0}, 1: 0}: the outer key 1 is compared with outer key 0, not 5.
    accepts(&[0xa2, 0x00, 0xa1, 0x05, 0x00, 0x01, 0x00]);
    // Inner map ordering is still enforced.
    rejects(
        &[0xa1, 0x00, 0xa2, 0x02, 0x00, 0x01, 0x00],
        E::UnorderedKeys,
    );
}

#[test]
fn depth_limit_is_32_containers() {
    assert_eq!(MAX_DEPTH, 32);
    accepts(&nested_arrays(31, &[0x80])); // 32 levels with an empty innermost
    accepts(&nested_arrays(32, &[0x00]));
    rejects(&nested_arrays(32, &[0x80]), E::DepthExceeded);
    rejects(&nested_arrays(33, &[0x00]), E::DepthExceeded);
    rejects(&nested_arrays(10_000, &[0x00]), E::DepthExceeded);

    // Mixed maps and arrays: {0: [ {0: [ ... ]} ]}.
    let mixed = |levels: usize| {
        let mut v = Vec::new();
        for i in 0..levels {
            v.extend_from_slice(if i % 2 == 0 { &[0xa1, 0x00] } else { &[0x81] });
        }
        v.push(0x00);
        v
    };
    accepts(&mixed(32));
    rejects(&mixed(33), E::DepthExceeded);
}

#[test]
fn reject_lengths_beyond_the_input() {
    let huge = [0xff; 8];
    for major in [2u8, 3, 4, 5] {
        let mut item = vec![(major << 5) | 27];
        item.extend_from_slice(&huge);
        rejects(&item, E::LengthExceedsInput);
    }
    rejects(&[0x42, 0x00], E::LengthExceedsInput); // bytes: remaining + 1
    rejects(&[0x62, 0x61], E::LengthExceedsInput); // text: remaining + 1
    rejects(&[0x82, 0x00], E::LengthExceedsInput); // array: 2 items, 1 byte
    rejects(&[0xa2, 0x00, 0x00, 0x01], E::LengthExceedsInput); // map: 4 items, 3 bytes
    rejects(&[0xa1, 0x00], E::LengthExceedsInput); // map: 2 items, 1 byte
    // u32::MAX count with a tiny input.
    rejects(&[0x9a, 0xff, 0xff, 0xff, 0xff, 0x00], E::LengthExceedsInput);
}

#[test]
fn reject_truncation_and_trailing_bytes() {
    rejects(&[], E::Truncated);
    rejects(&[0x18], E::Truncated);
    rejects(&[0x82, 0x01, 0x18], E::Truncated); // second item's argument missing
    rejects(&[0x81, 0x81, 0x18], E::Truncated);
    rejects(&[0xa1, 0x01, 0x19, 0x01], E::Truncated);
    rejects(&[0x83, 0x01, 0x02], E::LengthExceedsInput);
    rejects(&[0x82, 0x81, 0x00], E::Truncated); // inner done, outer missing an item
    rejects(&[0x00, 0x00], E::TrailingBytes);
    rejects(&[0x80, 0x80], E::TrailingBytes);
    rejects(&[0x01, 0xff], E::TrailingBytes);
}

#[test]
fn accept_minimal_items_and_extremes() {
    for item in [
        &[0x00][..],
        &[0x20],
        &[0x40],
        &[0x60],
        &[0x80],
        &[0xa0],
        &[0xf4],
        &[0xf5],
        &[0xf6],
        &[0x17],
        &[0x18, 0x18],
        &[0x37],
        &[0x38, 0x18],
        &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // u64::MAX
        &[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // -2^64
    ] {
        accepts(item);
    }
    // RFC 8949 Appendix A: [1, [2, 3], [4, 5]] and {1: 2, 3: 4}.
    accepts(&[0x83, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05]);
    accepts(&[0xa2, 0x01, 0x02, 0x03, 0x04]);
    // A 25-element array (count in a 1-byte argument).
    let mut a = vec![0x98, 0x19];
    a.extend((1..=25u8).map(|i| if i < 24 { i } else { 0x00 }));
    accepts(&a);
}
