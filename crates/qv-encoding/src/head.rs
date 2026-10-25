// SPDX-License-Identifier: AGPL-3.0-or-later

//! Item heads: the initial byte plus its argument (RFC 8949 §3).
//!
//! Reading enforces the profile at head level, so every caller gets the same
//! rejections: tags, floats, unsupported simple values, reserved additional
//! information, indefinite lengths and non-shortest arguments all fail here.

use crate::error::DecodeError;

pub(crate) const UINT: u8 = 0;
pub(crate) const NEGATIVE: u8 = 1;
pub(crate) const BYTES: u8 = 2;
pub(crate) const TEXT: u8 = 3;
pub(crate) const ARRAY: u8 = 4;
pub(crate) const MAP: u8 = 5;
pub(crate) const SIMPLE: u8 = 7;

pub(crate) const FALSE: u64 = 20;
pub(crate) const TRUE: u64 = 21;
pub(crate) const NULL: u64 = 22;

/// A decoded head. For major type 7 the argument is the simple value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Head {
    pub major: u8,
    pub arg: u64,
    /// Bytes the head occupies (1–9).
    pub len: usize,
}

/// Reads the head at `pos`.
pub(crate) fn read_head(input: &[u8], pos: usize) -> Result<Head, DecodeError> {
    let initial = *input.get(pos).ok_or(DecodeError::Truncated)?;
    let major = initial >> 5;
    let info = initial & 0x1f;
    match major {
        6 => return Err(DecodeError::Tag),
        SIMPLE => {
            return match info {
                20..=22 => Ok(Head {
                    major,
                    arg: u64::from(info),
                    len: 1,
                }),
                25..=27 => Err(DecodeError::Float),
                28..=30 => Err(DecodeError::ReservedAdditionalInfo),
                _ => Err(DecodeError::UnsupportedSimple),
            };
        }
        _ => {}
    }
    let (width, min) = match info {
        0..=23 => {
            return Ok(Head {
                major,
                arg: u64::from(info),
                len: 1,
            });
        }
        24 => (1, 24),
        25 => (2, 0x100),
        26 => (4, 0x1_0000),
        27 => (8, 0x1_0000_0000),
        28..=30 => return Err(DecodeError::ReservedAdditionalInfo),
        _ => return Err(DecodeError::IndefiniteLength),
    };
    let start = pos.checked_add(1).ok_or(DecodeError::Truncated)?;
    let end = start.checked_add(width).ok_or(DecodeError::Truncated)?;
    let bytes = input.get(start..end).ok_or(DecodeError::Truncated)?;
    let arg = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
    if arg < min {
        return Err(DecodeError::NonShortestArgument);
    }
    Ok(Head {
        major,
        arg,
        len: 1 + width,
    })
}

/// Encodes a head in shortest form. Returns the buffer and its used length.
pub(crate) fn encode_head(major: u8, arg: u64) -> ([u8; 9], usize) {
    let mut out = [0u8; 9];
    let m = major << 5;
    let width = match arg {
        0..=23 => {
            // Fits the additional information directly; the cast is lossless.
            out[0] = m | arg as u8;
            return (out, 1);
        }
        24..=0xff => {
            out[0] = m | 24;
            1
        }
        0x100..=0xffff => {
            out[0] = m | 25;
            2
        }
        0x1_0000..=0xffff_ffff => {
            out[0] = m | 26;
            4
        }
        _ => {
            out[0] = m | 27;
            8
        }
    };
    let be = arg.to_be_bytes();
    out[1..=width].copy_from_slice(&be[8 - width..]);
    (out, 1 + width)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(major: u8, arg: u64) -> Vec<u8> {
        let (b, n) = encode_head(major, arg);
        b[..n].to_vec()
    }

    #[test]
    fn head_boundaries_match_rfc_8949_appendix_a() {
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (23, &[0x17]),
            (24, &[0x18, 0x18]),
            (255, &[0x18, 0xff]),
            (256, &[0x19, 0x01, 0x00]),
            (65535, &[0x19, 0xff, 0xff]),
            (65536, &[0x1a, 0x00, 0x01, 0x00, 0x00]),
            (0xffff_ffff, &[0x1a, 0xff, 0xff, 0xff, 0xff]),
            (0x1_0000_0000, &[0x1b, 0, 0, 0, 1, 0, 0, 0, 0]),
            (
                1_000_000_000_000,
                &[0x1b, 0, 0, 0, 0xe8, 0xd4, 0xa5, 0x10, 0],
            ),
            (
                u64::MAX,
                &[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            ),
        ];
        for &(arg, bytes) in cases {
            assert_eq!(enc(UINT, arg), bytes, "encode {arg}");
            let h = read_head(bytes, 0).unwrap();
            assert_eq!((h.major, h.arg, h.len), (UINT, arg, bytes.len()));
        }
        // Negative: -1 - n; Appendix A: -1 = 0x20, -100 = 0x3863, -1000 = 0x3903e7.
        assert_eq!(enc(NEGATIVE, 0), [0x20]);
        assert_eq!(enc(NEGATIVE, 99), [0x38, 0x63]);
        assert_eq!(enc(NEGATIVE, 999), [0x39, 0x03, 0xe7]);
    }

    #[test]
    fn head_rejects_non_shortest_at_every_width() {
        for major in [UINT, NEGATIVE, BYTES, TEXT, ARRAY, MAP] {
            let m = major << 5;
            let cases: [&[u8]; 8] = [
                &[m | 24, 0],
                &[m | 24, 23],
                &[m | 25, 0, 0],
                &[m | 25, 0, 0xff],
                &[m | 26, 0, 0, 0, 0],
                &[m | 26, 0, 0, 0xff, 0xff],
                &[m | 27, 0, 0, 0, 0, 0, 0, 0, 0],
                &[m | 27, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
            ];
            for bytes in cases {
                assert_eq!(
                    read_head(bytes, 0),
                    Err(DecodeError::NonShortestArgument),
                    "{bytes:02x?}"
                );
            }
        }
    }

    #[test]
    fn head_rejects_reserved_indefinite_and_truncated() {
        for info in 28..=30u8 {
            assert_eq!(
                read_head(&[info], 0),
                Err(DecodeError::ReservedAdditionalInfo)
            );
            assert_eq!(
                read_head(&[0xe0 | info], 0),
                Err(DecodeError::ReservedAdditionalInfo)
            );
        }
        for major in [UINT, NEGATIVE, BYTES, TEXT, ARRAY, MAP] {
            assert_eq!(
                read_head(&[(major << 5) | 31], 0),
                Err(DecodeError::IndefiniteLength)
            );
        }
        assert_eq!(read_head(&[], 0), Err(DecodeError::Truncated));
        assert_eq!(read_head(&[0x18], 0), Err(DecodeError::Truncated));
        assert_eq!(read_head(&[0x19, 1], 0), Err(DecodeError::Truncated));
        assert_eq!(read_head(&[0x1a, 1, 0, 0], 0), Err(DecodeError::Truncated));
        assert_eq!(
            read_head(&[0x1b, 1, 0, 0, 0, 0, 0, 0], 0),
            Err(DecodeError::Truncated)
        );
    }

    #[test]
    fn head_profile_for_tags_and_simple_values() {
        assert_eq!(read_head(&[0xc0], 0), Err(DecodeError::Tag));
        assert_eq!(read_head(&[0xd8, 0x20], 0), Err(DecodeError::Tag));
        assert_eq!(read_head(&[0xf9, 0, 0], 0), Err(DecodeError::Float));
        assert_eq!(read_head(&[0xf7], 0), Err(DecodeError::UnsupportedSimple));
        assert_eq!(
            read_head(&[0xf8, 0x20], 0),
            Err(DecodeError::UnsupportedSimple)
        );
        assert_eq!(read_head(&[0xff], 0), Err(DecodeError::UnsupportedSimple));
        for (byte, value) in [(0xf4, FALSE), (0xf5, TRUE), (0xf6, NULL)] {
            let h = read_head(&[byte], 0).unwrap();
            assert_eq!((h.major, h.arg, h.len), (SIMPLE, value, 1));
        }
    }
}
