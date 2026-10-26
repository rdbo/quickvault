// SPDX-License-Identifier: AGPL-3.0-or-later

//! Version vectors (spec 0005 §1).
//!
//! A [`Clock`] maps writer IDs to positive counters; missing writers count as
//! zero. It is stored as a list strictly ascending by writer ID with no zero
//! counters, so every logical clock has exactly one representation, and on
//! the wire as the sorted array of `[writer_id, counter]` pairs (0005 §1.1),
//! never as a CBOR map. At most [`MAX_WRITERS`] writers (0004 §4.1).

use core::cmp::Ordering;

use qv_encoding::{Decoder, EncodeError, Encoder};

use crate::error::ModelError;
use crate::ids::{RandomId, WriterId};

/// The most writers in one clock (0004 §4.1).
pub const MAX_WRITERS: usize = 256;

/// A version vector.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct Clock {
    pairs: Vec<(WriterId, u64)>,
}

/// How two clocks relate (0005 §1.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Causality {
    /// Identical clocks.
    Equal,
    /// The first is strictly dominated by the second.
    Before,
    /// The first strictly dominates the second.
    After,
    /// Neither dominates the other.
    Concurrent,
}

impl Clock {
    /// The zero clock.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a clock from pairs that must be strictly ascending by writer,
    /// with positive counters ([`ModelError::Malformed`] otherwise) and at
    /// most [`MAX_WRITERS`] of them ([`ModelError::LimitExceeded`]).
    pub fn from_pairs(pairs: Vec<(WriterId, u64)>) -> Result<Self, ModelError> {
        if pairs.len() > MAX_WRITERS {
            return Err(ModelError::LimitExceeded);
        }
        if pairs.iter().any(|&(_, c)| c == 0) || pairs.windows(2).any(|w| w[0].0 >= w[1].0) {
            return Err(ModelError::Malformed);
        }
        Ok(Self { pairs })
    }

    /// The counter of `writer` (0 if absent).
    pub fn get(&self, writer: WriterId) -> u64 {
        self.pairs
            .binary_search_by(|(w, _)| w.cmp(&writer))
            .ok()
            .and_then(|i| self.pairs.get(i))
            .map_or(0, |&(_, c)| c)
    }

    /// The nonzero components, ascending by writer.
    pub fn pairs(&self) -> &[(WriterId, u64)] {
        &self.pairs
    }

    /// Whether every component is zero.
    pub fn is_empty(&self) -> bool {
        self.pairs.is_empty()
    }

    /// Compares componentwise; missing components are zero.
    pub fn compare(&self, other: &Clock) -> Causality {
        let (mut less, mut greater) = (false, false);
        let (mut a, mut b) = (self.pairs.iter().peekable(), other.pairs.iter().peekable());
        loop {
            match (a.peek(), b.peek()) {
                (None, None) => break,
                (Some(_), None) => {
                    greater = true;
                    break;
                }
                (None, Some(_)) => {
                    less = true;
                    break;
                }
                (Some(&&(wa, ca)), Some(&&(wb, cb))) => match wa.cmp(&wb) {
                    // A writer only `self` has: self's component is larger.
                    Ordering::Less => {
                        greater = true;
                        a.next();
                    }
                    Ordering::Greater => {
                        less = true;
                        b.next();
                    }
                    Ordering::Equal => {
                        match ca.cmp(&cb) {
                            Ordering::Less => less = true,
                            Ordering::Greater => greater = true,
                            Ordering::Equal => {}
                        }
                        a.next();
                        b.next();
                    }
                },
            }
            if less && greater {
                break;
            }
        }
        match (less, greater) {
            (false, false) => Causality::Equal,
            (true, false) => Causality::Before,
            (false, true) => Causality::After,
            (true, true) => Causality::Concurrent,
        }
    }

    /// Whether `self` strictly dominates `other`.
    pub fn dominates(&self, other: &Clock) -> bool {
        self.compare(other) == Causality::After
    }

    /// The componentwise maximum. [`ModelError::LimitExceeded`] past
    /// [`MAX_WRITERS`] writers.
    pub fn join(&self, other: &Clock) -> Result<Clock, ModelError> {
        let mut out = Vec::with_capacity(self.pairs.len().max(other.pairs.len()));
        let (mut a, mut b) = (self.pairs.iter().peekable(), other.pairs.iter().peekable());
        loop {
            let next = match (a.peek(), b.peek()) {
                (None, None) => break,
                (Some(&&p), None) => {
                    a.next();
                    p
                }
                (None, Some(&&p)) => {
                    b.next();
                    p
                }
                (Some(&&(wa, ca)), Some(&&(wb, cb))) => match wa.cmp(&wb) {
                    Ordering::Less => {
                        a.next();
                        (wa, ca)
                    }
                    Ordering::Greater => {
                        b.next();
                        (wb, cb)
                    }
                    Ordering::Equal => {
                        a.next();
                        b.next();
                        (wa, ca.max(cb))
                    }
                },
            };
            if out.len() == MAX_WRITERS {
                return Err(ModelError::LimitExceeded);
            }
            out.push(next);
        }
        Ok(Clock { pairs: out })
    }

    /// The clock of a new edit (0005 §1.2): the join of all `heads`, then
    /// `writer` set to `counter`.
    ///
    /// `counter` comes from the writer's durable reservation (phase 1.7) and
    /// must exceed the joined component: otherwise [`ModelError::Integrity`]
    /// (counters are never reused), or [`ModelError::CounterExhausted`] if the
    /// joined component is already `u64::MAX` (a new writer ID is needed).
    pub fn for_edit<'a>(
        heads: impl IntoIterator<Item = &'a Clock>,
        writer: WriterId,
        counter: u64,
    ) -> Result<Clock, ModelError> {
        let mut joined = Clock::new();
        for head in heads {
            joined = joined.join(head)?;
        }
        let current = joined.get(writer);
        if current == u64::MAX {
            return Err(ModelError::CounterExhausted);
        }
        if counter <= current {
            return Err(ModelError::Integrity);
        }
        match joined.pairs.binary_search_by(|(w, _)| w.cmp(&writer)) {
            Ok(i) => {
                let slot = joined.pairs.get_mut(i).ok_or(ModelError::Internal)?;
                slot.1 = counter;
            }
            Err(i) => {
                if joined.pairs.len() == MAX_WRITERS {
                    return Err(ModelError::LimitExceeded);
                }
                joined.pairs.insert(i, (writer, counter));
            }
        }
        Ok(joined)
    }

    /// The sum of all counters (cannot overflow: at most 256 `u64`s).
    pub(crate) fn total(&self) -> u128 {
        self.pairs.iter().map(|&(_, c)| u128::from(c)).sum()
    }
}

/// Writes the wire form: an array of `[writer_id, counter]` pairs.
pub(crate) fn encode_clock(clock: &Clock, e: &mut Encoder) -> Result<(), EncodeError> {
    e.array(|a| {
        for (w, c) in &clock.pairs {
            a.array(|p| {
                p.bytes(&w.to_bytes());
                p.uint(*c);
                Ok(())
            })?;
        }
        Ok(())
    })
}

/// Reads the wire form, checking the writer count before allocating.
pub(crate) fn decode_clock(d: &mut Decoder<'_>) -> Result<Clock, ModelError> {
    let n = usize::try_from(d.array()?).map_err(|_| ModelError::LimitExceeded)?;
    if n > MAX_WRITERS {
        return Err(ModelError::LimitExceeded);
    }
    let mut pairs = Vec::with_capacity(n);
    for _ in 0..n {
        if d.array()? != 2 {
            return Err(ModelError::Malformed);
        }
        let bytes: [u8; 16] = d.bytes()?.try_into().map_err(|_| ModelError::Malformed)?;
        let writer = WriterId::from_bytes(bytes)?;
        pairs.push((writer, d.uint()?));
    }
    Clock::from_pairs(pairs)
}

#[cfg(test)]
pub(crate) mod test_clock {
    use super::*;
    use crate::ids::test_ids::wid;

    /// A clock from `(writer byte, counter)` pairs in any order; zeros dropped.
    pub(crate) fn clock(pairs: &[(u8, u64)]) -> Clock {
        let mut p: Vec<(WriterId, u64)> = pairs
            .iter()
            .filter(|&&(_, c)| c > 0)
            .map(|&(w, c)| (wid(w), c))
            .collect();
        p.sort();
        Clock::from_pairs(p).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::test_clock::clock;
    use super::*;
    use crate::ids::test_ids::{v4, wid};

    fn encode(c: &Clock) -> Vec<u8> {
        let mut e = Encoder::new();
        encode_clock(c, &mut e).unwrap();
        e.finish().unwrap().to_vec()
    }

    fn decode(bytes: &[u8]) -> Result<Clock, ModelError> {
        let mut d = Decoder::new(bytes)?;
        let c = decode_clock(&mut d)?;
        d.finish()?;
        Ok(c)
    }

    fn pair_bytes(writer: [u8; 16], counter: u8) -> Vec<u8> {
        let mut v = vec![0x82, 0x50];
        v.extend_from_slice(&writer);
        v.push(counter);
        v
    }

    #[test]
    fn clock_from_pairs_validates() {
        assert_eq!(
            Clock::from_pairs(vec![(wid(2), 1), (wid(1), 1)]),
            Err(ModelError::Malformed)
        );
        assert_eq!(
            Clock::from_pairs(vec![(wid(1), 1), (wid(1), 2)]),
            Err(ModelError::Malformed)
        );
        assert_eq!(
            Clock::from_pairs(vec![(wid(1), 0)]),
            Err(ModelError::Malformed)
        );
        let max: Vec<_> = (0..=255u8).map(|w| (wid(w), 1)).collect();
        assert_eq!(Clock::from_pairs(max.clone()).unwrap().pairs().len(), 256);
        let mut over = max;
        let mut b = v4(0);
        b[1] = 1;
        over.push((WriterId::from_bytes(b).unwrap(), 1));
        over.sort();
        assert_eq!(Clock::from_pairs(over), Err(ModelError::LimitExceeded));
    }

    #[test]
    fn clock_wire_form_golden() {
        let c = clock(&[(2, 300), (1, 1)]);
        let mut expected = vec![0x82, 0x82, 0x50];
        expected.extend_from_slice(&v4(1));
        expected.push(0x01);
        expected.extend_from_slice(&[0x82, 0x50]);
        expected.extend_from_slice(&v4(2));
        expected.extend_from_slice(&[0x19, 0x01, 0x2c]);
        assert_eq!(encode(&c), expected);
        assert_eq!(decode(&expected).unwrap(), c);
        assert_eq!(encode(&Clock::new()), [0x80]);
        assert_eq!(decode(&[0x80]).unwrap(), Clock::new());
    }

    #[test]
    fn clock_decode_rejects() {
        // A map instead of an array.
        assert_eq!(decode(&[0xa0]), Err(ModelError::Malformed));
        // A 3-element pair.
        let mut three = vec![0x81, 0x83, 0x50];
        three.extend_from_slice(&v4(1));
        three.extend_from_slice(&[0x01, 0x01]);
        assert_eq!(decode(&three), Err(ModelError::Malformed));
        // Negative and zero counters.
        let mut neg = vec![0x81];
        neg.extend(pair_bytes(v4(1), 0x20));
        assert_eq!(decode(&neg), Err(ModelError::Malformed));
        let mut zero = vec![0x81];
        zero.extend(pair_bytes(v4(1), 0x00));
        assert_eq!(decode(&zero), Err(ModelError::Malformed));
        // A 15-byte writer.
        let mut short = vec![0x81, 0x82, 0x4f];
        short.extend_from_slice(&v4(1)[..15]);
        short.push(0x01);
        assert_eq!(decode(&short), Err(ModelError::Malformed));
        // Descending writers.
        let mut desc = vec![0x82];
        desc.extend(pair_bytes(v4(2), 1));
        desc.extend(pair_bytes(v4(1), 1));
        assert_eq!(decode(&desc), Err(ModelError::Malformed));
        // A writer without the v4 bits.
        let mut not_v4 = vec![0x81];
        not_v4.extend(pair_bytes([0; 16], 1));
        assert_eq!(decode(&not_v4), Err(ModelError::Malformed));
        // 257 pairs, rejected from the header.
        let mut many = vec![0x99, 0x01, 0x01];
        for i in 0..=256u16 {
            let mut w = v4(0);
            w[1] = (i >> 8) as u8;
            w[2] = i as u8;
            many.extend(pair_bytes(w, 1));
        }
        assert_eq!(decode(&many), Err(ModelError::LimitExceeded));
    }

    #[test]
    fn clock_compare_cases() {
        use Causality::*;
        let a = clock(&[(1, 1), (2, 2)]);
        assert_eq!(a.compare(&a.clone()), Equal);
        assert_eq!(a.compare(&clock(&[(1, 1), (2, 3)])), Before);
        assert_eq!(a.compare(&clock(&[(1, 1)])), After);
        // A missing component is zero.
        assert_eq!(clock(&[(1, 1)]).compare(&clock(&[(1, 1), (3, 1)])), Before);
        assert_eq!(a.compare(&clock(&[(1, 2), (2, 1)])), Concurrent);
        assert_eq!(clock(&[(1, 1)]).compare(&clock(&[(2, 1)])), Concurrent);
        assert_eq!(Clock::new().compare(&a), Before);
        assert_eq!(Clock::new().compare(&Clock::new()), Equal);
        assert!(a.dominates(&clock(&[(2, 2)])));
        assert!(!a.dominates(&a));
        assert_eq!(a.get(wid(2)), 2);
        assert_eq!(a.get(wid(9)), 0);
    }

    #[test]
    fn clock_join_and_limit() {
        let j = clock(&[(1, 3), (2, 1)])
            .join(&clock(&[(2, 5), (3, 1)]))
            .unwrap();
        assert_eq!(j, clock(&[(1, 3), (2, 5), (3, 1)]));
        let low: Vec<_> = (0..128u8).map(|w| (wid(w), 1)).collect();
        let high: Vec<_> = (128..=255u8).map(|w| (wid(w), 1)).collect();
        let full = Clock::from_pairs(low)
            .unwrap()
            .join(&Clock::from_pairs(high).unwrap())
            .unwrap();
        assert_eq!(full.pairs().len(), 256);
        let mut b = v4(0);
        b[1] = 1;
        let extra = Clock::from_pairs(vec![(WriterId::from_bytes(b).unwrap(), 1)]).unwrap();
        assert_eq!(full.join(&extra), Err(ModelError::LimitExceeded));
    }

    #[test]
    fn clock_for_edit() {
        let heads = [
            clock(&[(1, 2), (2, 1)]),
            clock(&[(1, 1), (2, 3)]),
            clock(&[(3, 4)]),
        ];
        let e = Clock::for_edit(&heads, wid(1), 5).unwrap();
        assert_eq!(e, clock(&[(1, 5), (2, 3), (3, 4)]));
        for h in &heads {
            assert!(e.dominates(h));
        }
        let new_writer = Clock::for_edit(&heads, wid(4), 1).unwrap();
        assert_eq!(new_writer.get(wid(4)), 1);
        assert_eq!(
            Clock::for_edit(&heads, wid(1), 2),
            Err(ModelError::Integrity)
        );
        assert_eq!(
            Clock::for_edit(&heads, wid(3), 1),
            Err(ModelError::Integrity)
        );
        let exhausted = [clock(&[(1, u64::MAX)])];
        assert_eq!(
            Clock::for_edit(&exhausted, wid(1), u64::MAX),
            Err(ModelError::CounterExhausted)
        );
        assert_eq!(Clock::for_edit(&[], wid(1), 1).unwrap(), clock(&[(1, 1)]));
    }

    fn arb_clock() -> impl Strategy<Value = Clock> {
        proptest::collection::vec((0u8..5, 0u64..4), 0..5).prop_map(|p| {
            let mut m = std::collections::BTreeMap::new();
            for (w, c) in p {
                m.insert(w, c);
            }
            clock(&m.into_iter().collect::<Vec<_>>())
        })
    }

    proptest! {
        #[test]
        fn clock_compare_is_antisymmetric(a in arb_clock(), b in arb_clock()) {
            let expected = match a.compare(&b) {
                Causality::Before => Causality::After,
                Causality::After => Causality::Before,
                c => c,
            };
            prop_assert_eq!(b.compare(&a), expected);
            prop_assert_eq!(a.compare(&b) == Causality::Equal, a == b);
        }

        #[test]
        fn clock_join_is_a_least_upper_bound(a in arb_clock(), b in arb_clock(), c in arb_clock()) {
            let ab = a.join(&b).unwrap();
            prop_assert!(matches!(a.compare(&ab), Causality::Before | Causality::Equal));
            prop_assert!(matches!(b.compare(&ab), Causality::Before | Causality::Equal));
            prop_assert_eq!(&ab, &b.join(&a).unwrap());
            prop_assert_eq!(a.join(&a).unwrap(), a.clone());
            prop_assert_eq!(ab.join(&c).unwrap(), a.join(&b.join(&c).unwrap()).unwrap());
            for (w, n) in ab.pairs() {
                prop_assert_eq!(*n, a.get(*w).max(b.get(*w)));
            }
        }

        #[test]
        fn clock_wire_round_trip(a in arb_clock()) {
            prop_assert_eq!(decode(&encode(&a)).unwrap(), a);
        }
    }
}
