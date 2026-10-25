// SPDX-License-Identifier: AGPL-3.0-or-later

//! Hostile bytes into the CBOR profile (spec 0012 §1, "Hostile SQLite/CBOR").
//!
//! Valid input must survive a typed decode and re-encode unchanged (canonical
//! identity). Invalid input must be rejected with the same error by every
//! entry point. Any panic is a finding.

#![no_main]

use std::cell::Cell;

use libfuzzer_sys::fuzz_target;
use qv_encoding::{DecodeError, Decoder, Encoder, Kind, RawValue, validate};

/// Rebuilds a validated item through the typed API. A map whose keys fall
/// outside `i64` (which the typed API cannot express) is copied verbatim.
fn reencode(d: &mut Decoder<'_>, e: &mut Encoder) {
    match d.peek_kind().unwrap() {
        Kind::Uint => e.uint(d.uint().unwrap()),
        Kind::Negative => e.negative(d.negative().unwrap()),
        Kind::Bytes => e.bytes(d.bytes().unwrap()),
        Kind::Text => e.text(d.text().unwrap()),
        Kind::Bool => e.bool(d.bool().unwrap()),
        Kind::Null => d.null().map(|()| e.null()).unwrap(),
        Kind::Array => {
            let n = d.array().unwrap();
            e.array(|a| {
                (0..n).for_each(|_| reencode(d, a));
                Ok(())
            })
            .unwrap();
        }
        Kind::Map => {
            let item = d.raw_item().unwrap();
            let mut sub = Decoder::new(item).unwrap();
            let n = sub.map().unwrap();
            let wide = Cell::new(false);
            let mut scratch = Encoder::new();
            scratch
                .map(|m| {
                    for _ in 0..n {
                        match sub.int() {
                            Ok(k) => m.entry(k, |x| {
                                reencode(&mut sub, x);
                                Ok(())
                            })?,
                            Err(DecodeError::OutOfRange) => {
                                wide.set(true);
                                return Ok(());
                            }
                            Err(other) => panic!("unexpected {other:?}"),
                        }
                    }
                    Ok(())
                })
                .unwrap();
            let rebuilt = if wide.get() {
                RawValue::from_canonical(item).unwrap()
            } else {
                RawValue::from_canonical(&scratch.finish().unwrap()).unwrap()
            };
            e.raw(&rebuilt).unwrap();
        }
    }
}

fuzz_target!(|data: &[u8]| {
    match validate(data) {
        Ok(()) => {
            let mut d = Decoder::new(data).unwrap();
            let mut e = Encoder::new();
            reencode(&mut d, &mut e);
            d.finish().unwrap();
            assert_eq!(e.finish().unwrap().as_slice(), data);
            assert_eq!(RawValue::from_canonical(data).unwrap().as_bytes(), data);
        }
        Err(err) => {
            assert_eq!(Decoder::new(data).err(), Some(err));
            assert_eq!(RawValue::from_canonical(data).err(), Some(err));
        }
    }
});
