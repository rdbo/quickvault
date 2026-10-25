// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unknown map entries survive a decode → modify → encode cycle byte for byte
//! (spec 0004 §3.1, 0003 §2.2).

use qv_encoding::{Decoder, Encoder, RawValue};

#[test]
fn unknown_keys_are_preserved_across_a_rewrite() {
    // {1: "old", 2: [true, {0: h'beef'}], 3: 9, 7: null, -1: "x"}
    let input: &[u8] = &[
        0xa5, //
        0x01, 0x63, b'o', b'l', b'd', //
        0x02, 0x82, 0xf5, 0xa1, 0x00, 0x42, 0xbe, 0xef, //
        0x03, 0x09, //
        0x07, 0xf6, //
        0x20, 0x61, b'x',
    ];

    // A reader that knows keys 1 and 3 and keeps the rest.
    let mut d = Decoder::new(input).unwrap();
    let mut name = None;
    let mut count = None;
    let mut unknown: Vec<(i64, RawValue)> = Vec::new();
    for _ in 0..d.map().unwrap() {
        match d.int().unwrap() {
            1 => name = Some(d.text().unwrap()),
            3 => count = Some(d.uint().unwrap()),
            k => unknown.push((k, d.raw_value().unwrap())),
        }
    }
    d.finish().unwrap();
    assert_eq!((name, count), (Some("old"), Some(9)));
    assert_eq!(
        unknown.iter().map(|(k, _)| *k).collect::<Vec<_>>(),
        [2, 7, -1]
    );

    // Rewrite key 1, adding known keys after unknown ones on purpose.
    let mut e = Encoder::new();
    e.map(|m| {
        for (k, v) in &unknown {
            m.raw_entry(*k, v)?;
        }
        m.entry(3, |v| {
            v.uint(9);
            Ok(())
        })?;
        m.entry(1, |v| {
            v.text("new");
            Ok(())
        })
    })
    .unwrap();
    let out = e.finish().unwrap();

    let mut expected = input.to_vec();
    expected[3..6].copy_from_slice(b"new");
    assert_eq!(out.as_slice(), expected.as_slice());
    qv_encoding::validate(&out).unwrap();
}
