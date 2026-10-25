// SPDX-License-Identifier: AGPL-3.0-or-later

//! Property tests: encode/decode round trip, canonical identity of every
//! valid input (oracle), mutation robustness, and order-independent encoding.

// The helpers below are test code, but clippy's `allow-*-in-tests` settings
// cover only `#[test]` functions, not free helpers in an integration test.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::cell::Cell;

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use qv_encoding::{DecodeError, Decoder, EncodeError, Encoder, Kind, RawValue, validate};

/// Test-only owned model of one item.
#[derive(Clone, Debug, PartialEq)]
enum Value {
    Uint(u64),
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    Map(Vec<(i64, Value)>),
    Bool(bool),
    Null,
}

fn encode_into(e: &mut Encoder, v: &Value) -> Result<(), EncodeError> {
    match v {
        Value::Uint(n) => e.uint(*n),
        Value::Negative(n) => e.negative(*n),
        Value::Bytes(b) => e.bytes(b),
        Value::Text(t) => e.text(t),
        Value::Bool(b) => e.bool(*b),
        Value::Null => e.null(),
        Value::Array(items) => {
            return e.array(|a| items.iter().try_for_each(|i| encode_into(a, i)));
        }
        Value::Map(entries) => {
            return e.map(|m| {
                entries
                    .iter()
                    .try_for_each(|(k, v)| m.entry(*k, |x| encode_into(x, v)))
            });
        }
    }
    Ok(())
}

fn encode(v: &Value) -> Vec<u8> {
    let mut e = Encoder::new();
    encode_into(&mut e, v).unwrap();
    e.finish().unwrap().to_vec()
}

fn decode_value(d: &mut Decoder<'_>) -> Value {
    match d.peek_kind().unwrap() {
        Kind::Uint => Value::Uint(d.uint().unwrap()),
        Kind::Negative => Value::Negative(d.negative().unwrap()),
        Kind::Bytes => Value::Bytes(d.bytes().unwrap().to_vec()),
        Kind::Text => Value::Text(d.text().unwrap().to_owned()),
        Kind::Bool => Value::Bool(d.bool().unwrap()),
        Kind::Null => {
            d.null().unwrap();
            Value::Null
        }
        Kind::Array => {
            let n = d.array().unwrap();
            Value::Array((0..n).map(|_| decode_value(d)).collect())
        }
        Kind::Map => {
            let n = d.map().unwrap();
            Value::Map(
                (0..n)
                    .map(|_| (d.int().unwrap(), decode_value(d)))
                    .collect(),
            )
        }
    }
}

fn key_bytes(k: i64) -> Vec<u8> {
    let mut e = Encoder::new();
    e.int(k);
    e.finish().unwrap().to_vec()
}

/// Sorts every map by encoded key, as the canonical form requires.
fn canonical(v: &Value) -> Value {
    match v {
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        Value::Map(entries) => {
            let mut e: Vec<_> = entries.iter().map(|(k, v)| (*k, canonical(v))).collect();
            e.sort_by_key(|(k, _)| key_bytes(*k));
            Value::Map(e)
        }
        other => other.clone(),
    }
}

/// Reverses the insertion order of every map.
fn reverse_maps(v: &Value) -> Value {
    match v {
        Value::Array(items) => Value::Array(items.iter().map(reverse_maps).collect()),
        Value::Map(entries) => Value::Map(
            entries
                .iter()
                .rev()
                .map(|(k, v)| (*k, reverse_maps(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Rebuilds a validated item through the typed API. Maps are rebuilt in a
/// scratch encoder and appended as a raw value. A map with a key outside
/// `i64` (which the typed API cannot express) is copied verbatim instead.
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

/// For valid input, the typed walk must reproduce it exactly.
fn assert_canonical_identity(input: &[u8]) {
    let mut d = Decoder::new(input).unwrap();
    let mut e = Encoder::new();
    reencode(&mut d, &mut e);
    d.finish().unwrap();
    assert_eq!(e.finish().unwrap().as_slice(), input);
}

fn int_arg() -> impl Strategy<Value = u64> {
    prop_oneof![
        0u64..300,
        prop::sample::select(vec![
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            u64::from(u32::MAX),
            u64::from(u32::MAX) + 1,
            i64::MAX as u64,
            u64::MAX,
        ]),
        any::<u64>(),
    ]
}

fn key() -> impl Strategy<Value = i64> {
    prop_oneof![-30i64..30, any::<i64>(), Just(i64::MIN), Just(i64::MAX)]
}

fn value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        int_arg().prop_map(Value::Uint),
        int_arg().prop_map(Value::Negative),
        vec(any::<u8>(), 0..40).prop_map(Value::Bytes),
        "\\PC{0,16}".prop_map(Value::Text),
        any::<bool>().prop_map(Value::Bool),
        Just(Value::Null),
    ];
    leaf.prop_recursive(6, 96, 8, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..8).prop_map(Value::Array),
            btree_map(key(), inner, 0..8).prop_map(|m| Value::Map(m.into_iter().collect())),
        ]
    })
}

#[derive(Clone, Debug)]
enum Mutation {
    Flip(prop::sample::Index, u8),
    Truncate(prop::sample::Index),
    Append(u8),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<prop::sample::Index>(), 1u8..=255).prop_map(|(i, x)| Mutation::Flip(i, x)),
        any::<prop::sample::Index>().prop_map(Mutation::Truncate),
        any::<u8>().prop_map(Mutation::Append),
    ]
}

proptest! {
    #[test]
    fn roundtrip_encode_then_decode(v in value()) {
        let bytes = encode(&v);
        prop_assert_eq!(validate(&bytes), Ok(()));
        let mut d = Decoder::new(&bytes).unwrap();
        let back = decode_value(&mut d);
        prop_assert!(d.finish().is_ok());
        prop_assert_eq!(back, canonical(&v));
        assert_canonical_identity(&bytes);
    }

    #[test]
    fn roundtrip_oracle_on_arbitrary_bytes(bytes in vec(any::<u8>(), 0..512)) {
        if validate(&bytes).is_ok() {
            assert_canonical_identity(&bytes);
        } else {
            prop_assert!(Decoder::new(&bytes).is_err());
            prop_assert!(RawValue::from_canonical(&bytes).is_err());
        }
    }

    #[test]
    fn roundtrip_mutations_fail_or_stay_canonical(v in value(), m in mutation()) {
        let mut bytes = encode(&v);
        match m {
            Mutation::Flip(i, x) => {
                let i = i.index(bytes.len());
                bytes[i] ^= x;
            }
            Mutation::Truncate(i) => bytes.truncate(i.index(bytes.len())),
            Mutation::Append(b) => bytes.push(b),
        }
        if validate(&bytes).is_ok() {
            assert_canonical_identity(&bytes);
        }
    }

    #[test]
    fn roundtrip_map_insertion_order_is_irrelevant(v in value()) {
        prop_assert_eq!(encode(&v), encode(&reverse_maps(&v)));
    }
}
