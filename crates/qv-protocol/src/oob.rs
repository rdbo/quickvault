// SPDX-License-Identifier: AGPL-3.0-or-later

//! The out-of-band pairing code (0013 §4.2): the QR payload and the
//! 26-character manual code.
//!
//! Both carry the pairing secret `P`. They come from a camera or a keyboard,
//! not from a frame, so they are hostile input. They are never wire messages,
//! and the QR label is not in [`crate::message::Label`].
//! - The QR payload is the canonical array `["qv/lan-pair-qr/v1",
//!   lan_profile: uint, P: bstr(16), endpoints: [[addr: bstr(4)|bstr(16),
//!   port: uint]] (0–8), instance: tstr]`.
//! - The manual code is `P` in RFC 4648 base32 without padding. It is shown
//!   in groups of five; input ignores case, spaces and `-`.
//!
//! Decoders bound the input before parsing and borrow `P` from the caller's
//! buffer. Encoders return wiped buffers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use qv_encoding::Decoder;
use zeroize::Zeroizing;

use crate::ProtocolError;
use crate::registry::LanProfile;

/// The QR payload's label.
pub const QR_LABEL: &str = "qv/lan-pair-qr/v1";
/// Largest accepted QR payload.
pub const MAX_QR_BYTES: usize = 1024;
/// Most endpoints in one QR payload.
pub const MAX_QR_ENDPOINTS: usize = 8;
/// Longest accepted manual-code input, separators included.
pub const MAX_MANUAL_INPUT: usize = 64;
/// Symbols in a manual code.
pub const MANUAL_SYMBOLS: usize = 26;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// An endpoint hint: an IP literal and a port (0013 §1.4). Never trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireEndpoint {
    /// IPv4 or IPv6 address.
    pub addr: IpAddr,
    /// Port, 1–65535.
    pub port: u16,
}

/// A decoded QR payload. `secret` borrows from the caller's buffer.
pub struct QrPayload<'a> {
    /// The raw `lan_profile`, checked by the caller.
    pub profile: u64,
    /// The pairing secret `P`.
    pub secret: &'a [u8; 16],
    /// Endpoint hints.
    pub endpoints: Vec<WireEndpoint>,
    /// The window's DNS-SD instance name, or empty.
    pub instance: &'a str,
}

impl core::fmt::Debug for QrPayload<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("QrPayload(<redacted>)")
    }
}

fn bad<E>(_: E) -> ProtocolError {
    ProtocolError::Malformed
}

fn valid_instance(s: &str) -> bool {
    s.is_empty()
        || (s.len() == 19
            && s.starts_with("qv-")
            && s.bytes()
                .skip(3)
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

/// Encodes a QR payload.
pub fn encode_qr(
    profile: LanProfile,
    secret: &[u8; 16],
    endpoints: &[WireEndpoint],
    instance: &str,
) -> Result<Zeroizing<Vec<u8>>, ProtocolError> {
    if endpoints.len() > MAX_QR_ENDPOINTS
        || endpoints.iter().any(|e| e.port == 0)
        || !valid_instance(instance)
    {
        return Err(ProtocolError::Malformed);
    }
    let out = qv_encoding::encode_array(|a| {
        a.text(QR_LABEL);
        a.uint(profile.id());
        a.bytes(secret);
        write_endpoints(a, endpoints)?;
        a.text(instance);
        Ok(())
    })
    .map_err(bad)?;
    if out.len() > MAX_QR_BYTES {
        return Err(ProtocolError::Malformed);
    }
    Ok(out)
}

/// Decodes a QR payload: bounded, canonical, exact shape. Any failure is
/// [`ProtocolError::Malformed`].
pub fn decode_qr(bytes: &[u8]) -> Result<QrPayload<'_>, ProtocolError> {
    if bytes.len() > MAX_QR_BYTES {
        return Err(ProtocolError::Malformed);
    }
    let mut d = Decoder::new(bytes).map_err(bad)?;
    if d.array().map_err(bad)? != 5 || d.text().map_err(bad)? != QR_LABEL {
        return Err(ProtocolError::Malformed);
    }
    let profile = d.uint().map_err(bad)?;
    let secret: &[u8; 16] = d.bytes().map_err(bad)?.try_into().map_err(bad)?;
    let endpoints = read_endpoints(&mut d)?;
    let instance = d.text().map_err(bad)?;
    if !valid_instance(instance) {
        return Err(ProtocolError::Malformed);
    }
    d.finish().map_err(bad)?;
    Ok(QrPayload {
        profile,
        secret,
        endpoints,
        instance,
    })
}

/// Longest accepted endpoint text, `[v6]:port` included.
pub const MAX_ENDPOINT_TEXT: usize = 64;

fn write_endpoints(
    a: &mut qv_encoding::Encoder,
    endpoints: &[WireEndpoint],
) -> Result<(), qv_encoding::EncodeError> {
    a.array(|a| {
        for e in endpoints {
            a.array(|a| {
                match e.addr {
                    IpAddr::V4(v4) => a.bytes(&v4.octets()),
                    IpAddr::V6(v6) => a.bytes(&v6.octets()),
                }
                a.uint(e.port.into());
                Ok(())
            })?;
        }
        Ok(())
    })
}

fn read_endpoints(d: &mut Decoder<'_>) -> Result<Vec<WireEndpoint>, ProtocolError> {
    let n = usize::try_from(d.array().map_err(bad)?).map_err(bad)?;
    if n > MAX_QR_ENDPOINTS {
        return Err(ProtocolError::Malformed);
    }
    let mut endpoints = Vec::with_capacity(n);
    for _ in 0..n {
        if d.array().map_err(bad)? != 2 {
            return Err(ProtocolError::Malformed);
        }
        let raw = d.bytes().map_err(bad)?;
        let addr = if let Ok(v4) = <[u8; 4]>::try_from(raw) {
            IpAddr::V4(Ipv4Addr::from(v4))
        } else if let Ok(v6) = <[u8; 16]>::try_from(raw) {
            IpAddr::V6(Ipv6Addr::from(v6))
        } else {
            return Err(ProtocolError::Malformed);
        };
        let port = u16::try_from(d.uint().map_err(bad)?)
            .ok()
            .filter(|p| *p != 0)
            .ok_or(ProtocolError::Malformed)?;
        endpoints.push(WireEndpoint { addr, port });
    }
    Ok(endpoints)
}

/// Parses typed endpoint text (0013 §1.4): `a.b.c.d:port` or `[v6]:port`.
/// IP literals only, port 1–65535, no zone identifier, no whitespace, at
/// most [`MAX_ENDPOINT_TEXT`] bytes.
pub fn parse_endpoint(text: &str) -> Result<WireEndpoint, ProtocolError> {
    if text.len() > MAX_ENDPOINT_TEXT
        || text
            .bytes()
            .any(|c| c == b'%' || c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return Err(ProtocolError::Malformed);
    }
    let addr: std::net::SocketAddr = text.parse().map_err(bad)?;
    if addr.port() == 0 {
        return Err(ProtocolError::Malformed);
    }
    if let std::net::SocketAddr::V6(v6) = addr
        && (v6.scope_id() != 0 || v6.flowinfo() != 0)
    {
        return Err(ProtocolError::Malformed);
    }
    Ok(WireEndpoint {
        addr: addr.ip(),
        port: addr.port(),
    })
}

/// The text form of an endpoint (0013 §8.5).
pub fn format_endpoint(e: &WireEndpoint) -> String {
    std::net::SocketAddr::new(e.addr, e.port).to_string()
}

/// RFC 4648 base32 without padding, into a wiped buffer.
fn base32(bytes: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len().div_ceil(5) * 8));
    let mut acc: u16 = 0;
    let mut bits = 0u32;
    for &b in bytes {
        acc = (acc << 8) | u16::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[usize::from((acc >> bits) & 31)]);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(ALPHABET[usize::from((acc << (5 - bits)) & 31)]);
    }
    zeroize::Zeroize::zeroize(&mut acc);
    out
}

/// The manual code of `secret`: 26 uppercase symbols in groups of five,
/// joined by `-`.
pub fn encode_manual(secret: &[u8; 16]) -> Zeroizing<String> {
    let symbols = base32(secret);
    let mut out = Zeroizing::new(String::with_capacity(MANUAL_SYMBOLS + 5));
    for (i, c) in symbols.iter().enumerate() {
        if i > 0 && i % 5 == 0 {
            out.push('-');
        }
        out.push(char::from(*c));
    }
    out
}

/// Decodes a typed manual code. Case, spaces and `-` are ignored. The input
/// must be at most [`MAX_MANUAL_INPUT`] bytes and hold exactly 26 base32
/// symbols whose 2 unused trailing bits are zero; anything else is
/// [`ProtocolError::Malformed`].
pub fn decode_manual(text: &str) -> Result<Zeroizing<[u8; 16]>, ProtocolError> {
    if text.len() > MAX_MANUAL_INPUT {
        return Err(ProtocolError::Malformed);
    }
    let mut out = Zeroizing::new([0u8; 16]);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut written = 0usize;
    let mut symbols = 0usize;
    for c in text.bytes() {
        let v = match c.to_ascii_uppercase() {
            b' ' | b'-' => continue,
            c @ b'A'..=b'Z' => c - b'A',
            c @ b'2'..=b'7' => c - b'2' + 26,
            _ => {
                zeroize::Zeroize::zeroize(&mut acc);
                return Err(ProtocolError::Malformed);
            }
        };
        symbols += 1;
        if symbols > MANUAL_SYMBOLS {
            zeroize::Zeroize::zeroize(&mut acc);
            return Err(ProtocolError::Malformed);
        }
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            // At most 128 data bits arrive before the final symbol's padding.
            if let Some(slot) = out.get_mut(written) {
                *slot = (acc >> bits) as u8;
                written += 1;
            }
            acc &= (1 << bits) - 1;
        }
    }
    let pad_ok = bits == 2 && acc == 0;
    zeroize::Zeroize::zeroize(&mut acc);
    if symbols != MANUAL_SYMBOLS || written != 16 || !pad_ok {
        return Err(ProtocolError::Malformed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use proptest::prelude::*;

    fn v4(a: [u8; 4], port: u16) -> WireEndpoint {
        WireEndpoint {
            addr: IpAddr::V4(Ipv4Addr::from(a)),
            port,
        }
    }

    #[test]
    fn oob_base32_matches_rfc_4648_vectors() {
        for (input, want) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(&base32(input.as_bytes())[..], want.as_bytes(), "{input}");
        }
    }

    #[test]
    fn oob_manual_code_round_trips_and_tolerates_formatting() {
        let secret: [u8; 16] = core::array::from_fn(|i| i as u8 * 17);
        let code = encode_manual(&secret);
        assert_eq!(code.len(), 26 + 5);
        assert_eq!(
            code.split('-').map(str::len).collect::<Vec<_>>(),
            [5, 5, 5, 5, 5, 1]
        );
        assert_eq!(*decode_manual(&code).unwrap(), secret);
        let loose = code.to_lowercase().replace('-', " ");
        assert_eq!(*decode_manual(&loose).unwrap(), secret);
        let compact: String = code.chars().filter(|c| *c != '-').collect();
        assert_eq!(*decode_manual(&compact).unwrap(), secret);
        // All-zero and all-one secrets: the last symbol carries 3 data bits.
        assert_eq!(*decode_manual(&encode_manual(&[0; 16])).unwrap(), [0; 16]);
        assert_eq!(
            *decode_manual(&encode_manual(&[0xff; 16])).unwrap(),
            [0xff; 16]
        );
    }

    #[test]
    fn oob_manual_code_refuses_bad_input() {
        let code: String = encode_manual(&[0x5a; 16])
            .chars()
            .filter(|c| *c != '-')
            .collect();
        let bad = |s: &str| {
            assert_eq!(
                decode_manual(s).err(),
                Some(ProtocolError::Malformed),
                "{s}"
            )
        };
        bad(&code[..25]);
        bad(&format!("{code}A"));
        bad(&format!("{}1", &code[..25])); // '1' is not base32
        bad(&format!("{}!", &code[..25]));
        bad(&" ".repeat(MAX_MANUAL_INPUT + 1));
        bad("");
        // Non-zero padding bits in the last symbol.
        let last = code.as_bytes()[25];
        let idx = ALPHABET.iter().position(|c| *c == last).unwrap();
        let flipped = char::from(ALPHABET[idx ^ 1]);
        bad(&format!("{}{flipped}", &code[..25]));
    }

    #[test]
    fn oob_qr_round_trips() {
        let eps = [
            v4([192, 168, 1, 7], 40_000),
            WireEndpoint {
                addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
                port: 1,
            },
        ];
        for instance in ["", "qv-0123456789abcdef"] {
            let qr = encode_qr(LanProfile::V1, &[9; 16], &eps, instance).unwrap();
            let p = decode_qr(&qr).unwrap();
            assert_eq!(
                (p.profile, p.secret, &p.endpoints[..], p.instance),
                (1, &[9; 16], &eps[..], instance)
            );
            assert_eq!(format!("{p:?}"), "QrPayload(<redacted>)");
        }
        let max = vec![v4([10, 0, 0, 1], 65535); MAX_QR_ENDPOINTS];
        assert!(decode_qr(&encode_qr(LanProfile::V1, &[9; 16], &max, "").unwrap()).is_ok());
    }

    fn ep(s: &str) -> WireEndpoint {
        parse_endpoint(s).unwrap()
    }

    #[test]
    fn oob_retired_address_qr_is_refused() {
        // 0014 removed the receive window's address-only QR (0013 §8.5).
        let old = qv_encoding::encode_array(|a| {
            a.text("qv/lan-addr-qr/v1");
            a.uint(1);
            a.array(|a| {
                a.array(|a| {
                    a.bytes(&[192, 0, 2, 10]);
                    a.uint(7777);
                    Ok(())
                })
            })
        })
        .unwrap();
        assert_eq!(decode_qr(&old).err(), Some(ProtocolError::Malformed));
    }

    #[test]
    fn oob_endpoint_text_is_ip_literals_only() {
        assert_eq!(format_endpoint(&ep("192.0.2.1:9")), "192.0.2.1:9");
        assert_eq!(
            format_endpoint(&ep("[2001:db8::1]:65535")),
            "[2001:db8::1]:65535"
        );
        for bad in [
            "localhost:80",
            "example.com:80",
            "192.0.2.1",
            "192.0.2.1:0",
            "192.0.2.1:65536",
            "[fe80::1%2]:80",
            "[fe80::1%eth0]:80",
            " 192.0.2.1:80",
            "192.0.2.1:80\n",
            "2001:db8::1:80",
            "01.2.3.4:80",
            &format!("[{}]:80", "0".repeat(70)),
        ] {
            assert_eq!(
                parse_endpoint(bad).err(),
                Some(ProtocolError::Malformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn oob_qr_refuses_bad_payloads() {
        let enc = |f: &dyn Fn(&mut qv_encoding::Encoder)| {
            qv_encoding::encode_array(|a| {
                f(a);
                Ok(())
            })
            .unwrap()
            .to_vec()
        };
        let good = |a: &mut qv_encoding::Encoder| {
            a.text(QR_LABEL);
            a.uint(1);
            a.bytes(&[9; 16]);
            a.array(|_| Ok(())).unwrap();
            a.text("");
        };
        assert!(decode_qr(&enc(&good)).is_ok());
        let cases: Vec<Vec<u8>> = vec![
            enc(&|a| {
                a.text("qv/lan-pair-qr/v2");
                a.uint(1);
                a.bytes(&[9; 16]);
                a.array(|_| Ok(())).unwrap();
                a.text("");
            }),
            enc(&|a| {
                a.text(QR_LABEL);
                a.uint(1);
                a.bytes(&[9; 15]);
                a.array(|_| Ok(())).unwrap();
                a.text("");
            }),
            enc(&|a| {
                a.text(QR_LABEL);
                a.uint(1);
                a.bytes(&[9; 16]);
                a.array(|a| {
                    for _ in 0..=MAX_QR_ENDPOINTS {
                        a.array(|a| {
                            a.bytes(&[1, 2, 3, 4]);
                            a.uint(1);
                            Ok(())
                        })?;
                    }
                    Ok(())
                })
                .unwrap();
                a.text("");
            }),
            enc(&|a| {
                a.text(QR_LABEL);
                a.uint(1);
                a.bytes(&[9; 16]);
                a.array(|a| {
                    a.array(|a| {
                        a.bytes(&[1, 2, 3, 4, 5]);
                        a.uint(1);
                        Ok(())
                    })
                })
                .unwrap();
                a.text("");
            }),
            enc(&|a| {
                a.text(QR_LABEL);
                a.uint(1);
                a.bytes(&[9; 16]);
                a.array(|a| {
                    a.array(|a| {
                        a.bytes(&[1, 2, 3, 4]);
                        a.uint(0);
                        Ok(())
                    })
                })
                .unwrap();
                a.text("");
            }),
            enc(&|a| {
                a.text(QR_LABEL);
                a.uint(1);
                a.bytes(&[9; 16]);
                a.array(|a| {
                    a.array(|a| {
                        a.bytes(&[1, 2, 3, 4]);
                        a.uint(65536);
                        Ok(())
                    })
                })
                .unwrap();
                a.text("");
            }),
            enc(&|a| {
                a.text(QR_LABEL);
                a.uint(1);
                a.bytes(&[9; 16]);
                a.array(|_| Ok(())).unwrap();
                a.text("qv-0123456789ABCDEF");
            }),
            [enc(&good), vec![0]].concat(),
            vec![0xff; MAX_QR_BYTES + 1],
        ];
        for (i, c) in cases.iter().enumerate() {
            assert_eq!(
                decode_qr(c).err(),
                Some(ProtocolError::Malformed),
                "case {i}"
            );
        }
        assert_eq!(
            encode_qr(LanProfile::V1, &[0; 16], &[v4([1, 1, 1, 1], 0)], "").err(),
            Some(ProtocolError::Malformed)
        );
        assert_eq!(
            encode_qr(LanProfile::V1, &[0; 16], &[], "host").err(),
            Some(ProtocolError::Malformed)
        );
    }

    proptest! {
        #[test]
        fn oob_decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1100)) {
            let _ = decode_qr(&bytes);
            if let Ok(s) = core::str::from_utf8(&bytes) {
                let _ = decode_manual(s);
                let _ = parse_endpoint(s);
            }
        }
    }
}
