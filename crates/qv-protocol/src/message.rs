// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire messages (0013 §1.2): one canonical CBOR array whose first element
//! is a label string. [`MessageReader`] accepts exactly the expected label
//! with exactly its arity, typed fields of exact or bounded size and no
//! trailing data; everything else is refused.
//!
//! Only labels that travel as messages are listed in [`Label`]. KDF, MAC, AAD,
//! transcript and storage labels (for example `qv/lan-pair-mac/v1`,
//! `qv/lan-record/v1`, `qv/lan-link-row/v1`) and the out-of-band QR payload
//! `qv/lan-pair-qr/v1` are not wire labels.

use qv_encoding::{Decoder, EncodeError, Encoder, encode_array};
use zeroize::Zeroizing;

use crate::ProtocolError;

macro_rules! labels {
    ($($(#[$doc:meta])* $name:ident = $label:literal, $arity:literal;)+) => {
        /// A wire message label (0013 §4–§7, §11).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Label {
            $($(#[$doc])* $name,)+
        }

        impl Label {
            /// Every wire label.
            pub const ALL: &'static [Label] = &[$(Label::$name,)+];

            /// The exact label string.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$name => $label,)+
                }
            }

            /// Total element count, including the label and any trailing MAC.
            pub const fn arity(self) -> u64 {
                match self {
                    $(Self::$name => $arity,)+
                }
            }

            /// The label for an exact (case-sensitive) string.
            pub fn parse(s: &str) -> Option<Self> {
                match s {
                    $($label => Some(Self::$name),)+
                    _ => None,
                }
            }
        }
    };
}

labels! {
    /// §4.3 PairHello: body (6) + MAC.
    PairHello = "qv/lan-pair-hello/v1", 7;
    /// §4.4 PairAccept: body (3) + MAC.
    PairAccept = "qv/lan-pair-accept/v1", 4;
    /// §4.5 reveal of `nonce_B`.
    PairReveal = "qv/lan-pair-reveal/v1", 2;
    /// §4.7 new-device grant.
    PairGrant = "qv/lan-pair-grant/v1", 5;
    /// §4.8 link-mode proof by B.
    PairProve = "qv/lan-pair-prove/v1", 4;
    /// §4.8 link-mode proof by A.
    PairProved = "qv/lan-pair-proved/v1", 3;
    /// §4.8 B's durable commit.
    PairDone = "qv/lan-pair-done/v1", 1;
    /// §5.1 SyncHello: body (4) + MAC.
    Hello = "qv/lan-hello/v1", 5;
    /// §5.2 SyncAccept: body (3) + MAC.
    Accept = "qv/lan-accept/v1", 4;
    /// §5.3 key confirmation.
    Confirm = "qv/lan-confirm/v1", 2;
    /// §7.2 state.
    State = "qv/lan-state/v1", 6;
    /// §7.3 manifest part.
    Manifest = "qv/lan-manifest/v1", 3;
    /// §7.4 want.
    Want = "qv/lan-want/v1", 3;
    /// §7.5 object.
    Object = "qv/lan-object/v1", 2;
    /// §7.7 done.
    Done = "qv/lan-done/v1", 3;
    /// §11 error.
    Error = "qv/lan-error/v1", 2;
}

fn malformed<E>(_: E) -> ProtocolError {
    ProtocolError::Malformed
}

/// Exact-shape reader over one received message.
///
/// It has no `Debug`: a decrypted message (a grant) may carry VK.
pub struct MessageReader<'a> {
    d: Decoder<'a>,
    label: Label,
    remaining: u64,
}

impl<'a> MessageReader<'a> {
    /// Opens a message that must carry `expected`.
    pub fn open(bytes: &'a [u8], expected: Label) -> Result<Self, ProtocolError> {
        Self::open_any(bytes, &[expected])
    }

    /// Opens a message carrying any of `expected`. Checks, in order: one
    /// canonical item, an array, a text first element, a known label, an
    /// expected label, and the label's exact arity.
    pub fn open_any(bytes: &'a [u8], expected: &[Label]) -> Result<Self, ProtocolError> {
        let mut d = Decoder::new(bytes).map_err(malformed)?;
        let n = d.array().map_err(malformed)?;
        if n == 0 {
            return Err(ProtocolError::Malformed);
        }
        let label =
            Label::parse(d.text().map_err(malformed)?).ok_or(ProtocolError::UnknownLabel)?;
        if !expected.contains(&label) {
            return Err(ProtocolError::UnexpectedLabel);
        }
        if n != label.arity() {
            return Err(ProtocolError::Malformed);
        }
        Ok(Self {
            d,
            label,
            remaining: n - 1,
        })
    }

    /// The message's label.
    pub fn label(&self) -> Label {
        self.label
    }

    fn take(&mut self) -> Result<(), ProtocolError> {
        self.remaining = self
            .remaining
            .checked_sub(1)
            .ok_or(ProtocolError::Malformed)?;
        Ok(())
    }

    /// The next field as an unsigned integer.
    pub fn uint(&mut self) -> Result<u64, ProtocolError> {
        self.take()?;
        self.d.uint().map_err(malformed)
    }

    /// The next field as `false` or `true`.
    pub fn bool(&mut self) -> Result<bool, ProtocolError> {
        self.take()?;
        self.d.bool().map_err(malformed)
    }

    /// The next field as a byte string of exactly `N` bytes.
    pub fn bytes_exact<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        self.take()?;
        self.d
            .bytes()
            .map_err(malformed)?
            .try_into()
            .map_err(malformed)
    }

    /// The next field as a byte string of at most `max` bytes, borrowed.
    pub fn bytes_max(&mut self, max: usize) -> Result<&'a [u8], ProtocolError> {
        self.take()?;
        let b = self.d.bytes().map_err(malformed)?;
        if b.len() > max {
            return Err(ProtocolError::Malformed);
        }
        Ok(b)
    }

    /// The next field as text of at most `max` bytes, borrowed.
    pub fn text_max(&mut self, max: usize) -> Result<&'a str, ProtocolError> {
        self.take()?;
        let t = self.d.text().map_err(malformed)?;
        if t.len() > max {
            return Err(ProtocolError::Malformed);
        }
        Ok(t)
    }

    /// The next field as an array of at most `max` unsigned integers (for
    /// example `features`). The count is checked before allocating.
    pub fn uint_array_max(&mut self, max: usize) -> Result<Vec<u64>, ProtocolError> {
        self.take()?;
        let n = self.array_len(max)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.d.uint().map_err(malformed)?);
        }
        Ok(out)
    }

    /// The next field as an array of at most `max` byte strings of exactly
    /// `N` bytes each (for example `Want` IDs). The count is checked before
    /// allocating.
    pub fn bytes_array_exact<const N: usize>(
        &mut self,
        max: usize,
    ) -> Result<Vec<[u8; N]>, ProtocolError> {
        self.take()?;
        let n = self.array_len(max)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(
                self.d
                    .bytes()
                    .map_err(malformed)?
                    .try_into()
                    .map_err(malformed)?,
            );
        }
        Ok(out)
    }

    fn array_len(&mut self, max: usize) -> Result<usize, ProtocolError> {
        let n = usize::try_from(self.d.array().map_err(malformed)?).map_err(malformed)?;
        if n > max {
            return Err(ProtocolError::Malformed);
        }
        Ok(n)
    }

    /// Succeeds only if every element was read and nothing follows.
    pub fn finish(self) -> Result<(), ProtocolError> {
        if self.remaining != 0 {
            return Err(ProtocolError::Malformed);
        }
        self.d.finish().map_err(malformed)
    }
}

/// The canonical encoding of the message's elements except the last, as an
/// array: the MAC'd `body` of a hello or accept (0013 §4.3, §5.1), where the
/// message is `body ++ [mac]`. Canonical CBOR has one encoding per value, so
/// re-encoding the received elements is exact.
pub fn body_without_last(bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let mut d = Decoder::new(bytes).map_err(malformed)?;
    let n = d.array().map_err(malformed)?;
    if n < 2 {
        return Err(ProtocolError::Malformed);
    }
    let out = encode_array(|a| {
        for _ in 0..n - 1 {
            let item = d.raw_value().map_err(|_| EncodeError::ItemCount)?;
            a.raw(&item)?;
        }
        Ok(())
    })
    .map_err(malformed)?;
    Ok(out)
}

/// Encodes a message: the label, then the fields `f` writes. The result must
/// have exactly `label.arity()` elements (else [`ProtocolError::Malformed`])
/// and at most `max` bytes (else [`ProtocolError::FrameTooLarge`]).
pub fn write_message(
    label: Label,
    max: usize,
    f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    let out = encode_array(|a| {
        a.text(label.as_str());
        f(a)
    })
    .map_err(malformed)?;
    let mut d = Decoder::new(&out).map_err(malformed)?;
    if d.array().map_err(malformed)? != label.arity() {
        return Err(ProtocolError::Malformed);
    }
    if out.len() > max {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    fn msg(label: &str, f: impl FnOnce(&mut Encoder)) -> Vec<u8> {
        encode_array(|a| {
            a.text(label);
            f(a);
            Ok(())
        })
        .unwrap()
        .to_vec()
    }
    fn hello_body(a: &mut Encoder) {
        a.uint(1);
        a.bytes(&[1; 32]);
        a.bytes(&[2; 1216]);
    }

    #[test]
    fn labels_round_trip_and_match_the_spec_arities() {
        let arities: Vec<(&str, u64)> =
            Label::ALL.iter().map(|l| (l.as_str(), l.arity())).collect();
        assert_eq!(
            arities,
            [
                ("qv/lan-pair-hello/v1", 7),
                ("qv/lan-pair-accept/v1", 4),
                ("qv/lan-pair-reveal/v1", 2),
                ("qv/lan-pair-grant/v1", 5),
                ("qv/lan-pair-prove/v1", 4),
                ("qv/lan-pair-proved/v1", 3),
                ("qv/lan-pair-done/v1", 1),
                ("qv/lan-hello/v1", 5),
                ("qv/lan-accept/v1", 4),
                ("qv/lan-confirm/v1", 2),
                ("qv/lan-state/v1", 6),
                ("qv/lan-manifest/v1", 3),
                ("qv/lan-want/v1", 3),
                ("qv/lan-object/v1", 2),
                ("qv/lan-done/v1", 3),
                ("qv/lan-error/v1", 2),
            ]
        );
        for l in Label::ALL {
            assert_eq!(Label::parse(l.as_str()), Some(*l));
        }
        for bad in [
            "qv/lan-hello/v2",
            "QV/LAN-HELLO/V1",
            "qv/lan-record/v1",
            "qv/lan-pair-qr/v1",
            "",
        ] {
            assert_eq!(Label::parse(bad), None, "{bad}");
        }
    }

    #[test]
    fn reader_accepts_the_exact_shape() {
        let bytes = msg("qv/lan-hello/v1", |a| {
            hello_body(a);
            a.bytes(&[3; 32]);
        });
        let mut r = MessageReader::open(&bytes, Label::Hello).unwrap();
        assert_eq!(r.label(), Label::Hello);
        assert_eq!(r.uint().unwrap(), 1);
        assert_eq!(r.bytes_exact::<32>().unwrap(), [1; 32]);
        assert_eq!(r.bytes_exact::<1216>().unwrap(), [2; 1216]);
        assert_eq!(r.bytes_exact::<32>().unwrap(), [3; 32]);
        r.finish().unwrap();
        // The MAC'd body equals the independently encoded body.
        let body = msg("qv/lan-hello/v1", hello_body);
        assert_eq!(
            body_without_last(&bytes).unwrap().as_slice(),
            body.as_slice()
        );

        let state = msg("qv/lan-state/v1", |a| {
            a.bytes(&[0; 16]);
            a.uint(1);
            a.bytes(&[0; 32]);
            a.uint(0);
            a.array(|_| Ok(())).unwrap();
        });
        let mut r = MessageReader::open_any(&state, &[Label::State, Label::Error]).unwrap();
        r.bytes_exact::<16>().unwrap();
        r.uint().unwrap();
        r.bytes_exact::<32>().unwrap();
        r.uint().unwrap();
        assert!(r.uint_array_max(8).unwrap().is_empty());
        r.finish().unwrap();

        let want = msg("qv/lan-want/v1", |a| {
            a.array(|a| {
                a.bytes(&[9; 16]);
                a.bytes(&[8; 16]);
                Ok(())
            })
            .unwrap();
            a.bool(true);
        });
        let mut r = MessageReader::open(&want, Label::Want).unwrap();
        assert_eq!(r.bytes_array_exact::<16>(4096).unwrap(), [[9; 16], [8; 16]]);
        assert!(r.bool().unwrap());
        r.finish().unwrap();
        let mut r = MessageReader::open(&want, Label::Want).unwrap();
        assert_eq!(r.bytes_array_exact::<16>(1), Err(ProtocolError::Malformed));
    }

    #[test]
    fn reader_refuses_wrong_labels_and_shapes() {
        let confirm = msg("qv/lan-confirm/v1", |a| a.bytes(&[0; 32]));
        assert_eq!(
            MessageReader::open(&confirm, Label::Hello).err(),
            Some(ProtocolError::UnexpectedLabel)
        );
        for label in ["qv/lan-confirm/v2", "QV/LAN-CONFIRM/V1", "qv/lan-record/v1"] {
            let m = msg(label, |a| a.bytes(&[0; 32]));
            assert_eq!(
                MessageReader::open(&m, Label::Confirm).err(),
                Some(ProtocolError::UnknownLabel),
                "{label}"
            );
        }
        let malformed: Vec<Vec<u8>> = vec![
            // Missing and extra elements.
            msg("qv/lan-confirm/v1", |_| {}),
            msg("qv/lan-confirm/v1", |a| {
                a.bytes(&[0; 32]);
                a.uint(0);
            }),
            // Not an array, empty array, label not text.
            vec![0x01],
            vec![0x80],
            encode_array(|a| {
                a.uint(1);
                a.bytes(&[0; 32]);
                Ok(())
            })
            .unwrap()
            .to_vec(),
            // Trailing bytes, non-minimal length, indefinite array.
            [confirm.clone(), vec![0x00]].concat(),
            [vec![0x98, 0x02], confirm[1..].to_vec()].concat(),
            [vec![0x9f], confirm[1..].to_vec(), vec![0xff]].concat(),
        ];
        for (i, m) in malformed.iter().enumerate() {
            assert_eq!(
                MessageReader::open(m, Label::Confirm).err(),
                Some(ProtocolError::Malformed),
                "case {i}"
            );
        }
        // Field kinds and sizes.
        let neg = msg("qv/lan-confirm/v1", |a| a.int(-1));
        let null = msg("qv/lan-confirm/v1", |a| a.null());
        let map = msg("qv/lan-confirm/v1", |a| a.map(|_| Ok(())).unwrap());
        for m in [&neg, &null, &map] {
            let mut r = MessageReader::open(m, Label::Confirm).unwrap();
            assert_eq!(r.bytes_exact::<32>(), Err(ProtocolError::Malformed));
        }
        for len in [31, 33] {
            let m = msg("qv/lan-confirm/v1", |a| a.bytes(&vec![0; len]));
            let mut r = MessageReader::open(&m, Label::Confirm).unwrap();
            assert_eq!(r.bytes_exact::<32>(), Err(ProtocolError::Malformed));
        }
        let mut r = MessageReader::open(&confirm, Label::Confirm).unwrap();
        assert_eq!(r.bytes_max(31), Err(ProtocolError::Malformed));
        let text = msg("qv/lan-confirm/v1", |a| a.text("abc"));
        let mut r = MessageReader::open(&text, Label::Confirm).unwrap();
        assert_eq!(r.text_max(2), Err(ProtocolError::Malformed));
        // Reading past the arity or finishing early.
        let mut r = MessageReader::open(&confirm, Label::Confirm).unwrap();
        r.bytes_exact::<32>().unwrap();
        assert_eq!(r.uint(), Err(ProtocolError::Malformed));
        let r = MessageReader::open(&confirm, Label::Confirm).unwrap();
        assert_eq!(r.finish(), Err(ProtocolError::Malformed));
        assert_eq!(
            body_without_last(&[0x81, 0x00]).err(),
            Some(ProtocolError::Malformed)
        );
    }

    #[test]
    fn writer_enforces_arity_and_size() {
        let m = write_message(Label::Confirm, 64, |a| {
            a.bytes(&[5; 32]);
            Ok(())
        })
        .unwrap();
        let mut r = MessageReader::open(&m, Label::Confirm).unwrap();
        assert_eq!(r.bytes_exact::<32>().unwrap(), [5; 32]);
        r.finish().unwrap();
        assert_eq!(
            write_message(Label::Confirm, 64, |_| Ok(())).err(),
            Some(ProtocolError::Malformed)
        );
        assert_eq!(
            write_message(Label::Confirm, 16, |a| {
                a.bytes(&[5; 32]);
                Ok(())
            })
            .err(),
            Some(ProtocolError::FrameTooLarge)
        );
        assert_eq!(
            write_message(Label::PairDone, 64, |_| Ok(()))
                .unwrap()
                .len(),
            21
        );
    }

    proptest! {
        #[test]
        fn reader_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            if let Ok(mut r) = MessageReader::open_any(&bytes, Label::ALL) {
                for _ in 0..8 {
                    let _ = r.uint();
                    let _ = r.bytes_max(4096);
                    let _ = r.uint_array_max(16);
                }
            }
            let _ = body_without_last(&bytes);
        }
    }
}
