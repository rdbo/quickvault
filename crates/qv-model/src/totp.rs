// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOTP fields (spec 0003 §5.4): `otpauth://totp/…` URIs and RFC 6238 codes.
//!
//! The URI is what the user stored in a `totp` field, so these are local
//! parsing bounds, not format rules:
//!
//! | Parameter | Accepted | Otherwise |
//! |-----------|----------|-----------|
//! | type | `totp` (case-insensitive) | `hotp` → [`TotpError::Unsupported`]; anything else → [`TotpError::InvalidUri`] |
//! | `secret` | required; RFC 4648 base32, case-insensitive, `=` padding optional; 1–256 bytes decoded | [`TotpError::InvalidUri`] |
//! | `algorithm` | `SHA1` (default), `SHA256`, `SHA512` | [`TotpError::Unsupported`] |
//! | `digits` | 6 (default), 7, 8 | [`TotpError::Unsupported`] (non-numeric: [`TotpError::InvalidUri`]) |
//! | `period` | 1–86,400 s, default 30 | [`TotpError::Unsupported`] (non-numeric: [`TotpError::InvalidUri`]) |
//!
//! Parameter names are case-insensitive and values are percent-decoded. A
//! repeated known parameter is [`TotpError::InvalidUri`]; unknown parameters
//! (`issuer`, `image`, …) and the label are ignored. The key is decoded
//! straight into locked memory; the HMAC is `qv_crypto::hotp`.

use core::fmt;

use qv_crypto::{OtpAlgorithm, OtpCode, SecretBytes, hotp};
use zeroize::Zeroizing;

use crate::text::MAX_TEXT_BYTES;
use crate::time::Timestamp;

/// The largest decoded TOTP key.
const MAX_KEY_BYTES: usize = 256;
/// The longest TOTP period, in seconds.
const MAX_PERIOD: u32 = 86_400;

/// Why a TOTP URI or code was rejected. No variant carries data. All map to
/// CLI exit code 1 and are shown next to the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum TotpError {
    /// Not a well-formed `otpauth://totp` URI with a valid secret.
    InvalidUri,
    /// A well-formed URI with a type or parameter this build does not support.
    Unsupported,
    /// The time is before the Unix epoch.
    BeforeEpoch,
    /// A bug.
    Internal,
}

impl fmt::Display for TotpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidUri => "invalid TOTP URI",
            Self::Unsupported => "unsupported TOTP parameters",
            Self::BeforeEpoch => "time is before 1970",
            Self::Internal => "internal TOTP error",
        })
    }
}

impl std::error::Error for TotpError {}

/// A parsed TOTP configuration. `Debug` is redacted.
pub struct Totp {
    key: SecretBytes,
    algorithm: OtpAlgorithm,
    digits: u32,
    period: u32,
}

impl fmt::Debug for Totp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Totp(<redacted>)")
    }
}

/// `s` starts with `prefix`, ignoring ASCII case; returns the rest.
fn strip_prefix_ci<'a>(s: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    let head = s.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| s.get(prefix.len()..))
        .flatten()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes `value` into a zeroizing buffer of exact capacity.
fn percent_decode(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, TotpError> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut i = 0;
    while let Some(&b) = value.get(i) {
        if b == b'%' {
            let hi = value.get(i + 1).copied().and_then(hex_digit);
            let lo = value.get(i + 2).copied().and_then(hex_digit);
            match (hi, lo) {
                (Some(hi), Some(lo)) => out.push(hi << 4 | lo),
                _ => return Err(TotpError::InvalidUri),
            }
            i += 3;
        } else {
            out.push(b);
            i += 1;
        }
    }
    Ok(out)
}

/// RFC 4648 base32, case-insensitive, trailing `=` optional, straight into
/// locked memory. Leftover low bits of the last character are ignored.
pub(crate) fn base32_decode(input: &[u8]) -> Result<SecretBytes, TotpError> {
    let end = input.iter().rposition(|&b| b != b'=').map_or(0, |i| i + 1);
    let body = input.get(..end).ok_or(TotpError::Internal)?;
    if !matches!(body.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return Err(TotpError::InvalidUri);
    }
    let len = body.len() * 5 / 8;
    SecretBytes::try_init(len, |out| {
        let mut acc = Zeroizing::new(0u64);
        let mut bits = 0u32;
        let mut pos = 0usize;
        for &c in body {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a',
                b'2'..=b'7' => c - b'2' + 26,
                _ => return Err(TotpError::InvalidUri),
            };
            *acc = (*acc << 5) | u64::from(v);
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                // The low 8 bits after the shift; the cast keeps exactly them.
                *out.get_mut(pos).ok_or(TotpError::Internal)? = (*acc >> bits) as u8;
                pos += 1;
                *acc &= (1u64 << bits) - 1;
            }
        }
        if pos == len {
            Ok(())
        } else {
            Err(TotpError::Internal)
        }
    })
}

/// A short decimal number (at most 9 digits).
fn parse_decimal(value: &[u8]) -> Result<u32, TotpError> {
    if value.is_empty() || value.len() > 9 || !value.iter().all(u8::is_ascii_digit) {
        return Err(TotpError::InvalidUri);
    }
    Ok(value
        .iter()
        .fold(0u32, |n, &d| n * 10 + u32::from(d - b'0')))
}

impl Totp {
    /// Parses an `otpauth://totp/…` URI.
    pub fn parse(uri: &[u8]) -> Result<Self, TotpError> {
        if uri.len() > MAX_TEXT_BYTES {
            return Err(TotpError::InvalidUri);
        }
        let rest = strip_prefix_ci(uri, b"otpauth://").ok_or(TotpError::InvalidUri)?;
        let rest = if let Some(r) = strip_prefix_ci(rest, b"totp/") {
            r
        } else if strip_prefix_ci(rest, b"hotp/").is_some() {
            return Err(TotpError::Unsupported);
        } else {
            return Err(TotpError::InvalidUri);
        };
        let query = rest
            .iter()
            .position(|&b| b == b'?')
            .and_then(|i| rest.get(i + 1..))
            .ok_or(TotpError::InvalidUri)?;
        // A fragment is not part of the query.
        let query = query.split(|&b| b == b'#').next().unwrap_or_default();
        let (mut key, mut algorithm, mut digits, mut period) = (None, None, None, None);
        for param in query.split(|&b| b == b'&') {
            let (name, value) = match param.iter().position(|&b| b == b'=') {
                Some(i) => (
                    param.get(..i).unwrap_or_default(),
                    param.get(i + 1..).unwrap_or_default(),
                ),
                None => (param, &[][..]),
            };
            let known = [&b"secret"[..], b"algorithm", b"digits", b"period"]
                .iter()
                .position(|k| name.eq_ignore_ascii_case(k));
            let Some(which) = known else {
                continue;
            };
            let value = percent_decode(value)?;
            match which {
                0 if key.is_none() => key = Some(base32_decode(&value)?),
                1 if algorithm.is_none() => {
                    algorithm = Some(if value.eq_ignore_ascii_case(b"SHA1") {
                        OtpAlgorithm::Sha1
                    } else if value.eq_ignore_ascii_case(b"SHA256") {
                        OtpAlgorithm::Sha256
                    } else if value.eq_ignore_ascii_case(b"SHA512") {
                        OtpAlgorithm::Sha512
                    } else {
                        return Err(TotpError::Unsupported);
                    })
                }
                2 if digits.is_none() => digits = Some(parse_decimal(&value)?),
                3 if period.is_none() => period = Some(parse_decimal(&value)?),
                // A repeated known parameter.
                _ => return Err(TotpError::InvalidUri),
            }
        }
        let key = key.ok_or(TotpError::InvalidUri)?;
        if key.is_empty() || key.len() > MAX_KEY_BYTES {
            return Err(TotpError::InvalidUri);
        }
        let digits = digits.unwrap_or(6);
        let period = period.unwrap_or(30);
        if !(6..=8).contains(&digits) || !(1..=MAX_PERIOD).contains(&period) {
            return Err(TotpError::Unsupported);
        }
        Ok(Self {
            key,
            algorithm: algorithm.unwrap_or(OtpAlgorithm::Sha1),
            digits,
            period,
        })
    }

    /// Unix seconds of `at`, or [`TotpError::BeforeEpoch`].
    fn seconds(at: Timestamp) -> Result<u64, TotpError> {
        u64::try_from(at.0.div_euclid(1000)).map_err(|_| TotpError::BeforeEpoch)
    }

    /// The code at `at` (RFC 6238 with T0 = 0).
    pub fn code_at(&self, at: Timestamp) -> Result<OtpCode, TotpError> {
        let counter = Self::seconds(at)? / u64::from(self.period);
        hotp(
            self.key.expose_secret(),
            self.algorithm,
            counter,
            self.digits,
        )
        .map_err(|_| TotpError::Internal)
    }

    /// Seconds until the code at `at` changes (1 to `period`).
    pub fn seconds_remaining(&self, at: Timestamp) -> Result<u32, TotpError> {
        let period = u64::from(self.period);
        let left = period - Self::seconds(at)? % period;
        u32::try_from(left).map_err(|_| TotpError::Internal)
    }

    /// The HMAC hash.
    pub fn algorithm(&self) -> OtpAlgorithm {
        self.algorithm
    }

    /// The number of digits (6–8).
    pub fn digits(&self) -> u32 {
        self.digits
    }

    /// The time step in seconds.
    pub fn period(&self) -> u32 {
        self.period
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 base32 (test-only encoder).
    fn base32(data: &[u8]) -> String {
        const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let mut out = String::new();
        let (mut acc, mut bits) = (0u32, 0u32);
        for &b in data {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(ALPHABET[((acc >> bits) & 31) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(ALPHABET[((acc << (5 - bits)) & 31) as usize] as char);
        }
        while !out.len().is_multiple_of(8) {
            out.push('=');
        }
        out
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The RFC 6238 rows: (algorithm name, key, time, code).
    fn rfc6238() -> Vec<(&'static str, Vec<u8>, i64, String)> {
        let text = include_str!("../../qv-crypto/tests/vectors/rfc6238-totp.txt");
        let mut rows = Vec::new();
        let mut cur = std::collections::BTreeMap::new();
        for line in text.lines().chain([""]) {
            if line.starts_with('#') {
                continue;
            }
            if line.trim().is_empty() {
                if !cur.is_empty() {
                    let alg = match hex(cur["alg"]).as_slice() {
                        [1] => "SHA1",
                        [2] => "SHA256",
                        _ => "SHA512",
                    };
                    let time = i64::from_str_radix(cur["time"], 16).unwrap();
                    let code = String::from_utf8(hex(cur["totp"])).unwrap();
                    rows.push((alg, hex(cur["key"]), time, code));
                    cur.clear();
                }
                continue;
            }
            let (k, v) = line.split_once(" = ").unwrap();
            cur.insert(k, v);
        }
        rows
    }

    #[test]
    fn totp_rfc6238_vectors_through_uris() {
        let rows = rfc6238();
        assert_eq!(rows.len(), 18);
        for (alg, key, time, code) in rows {
            let uri = format!(
                "otpauth://totp/Example:alice?secret={}&algorithm={alg}&digits=8&period=30",
                base32(&key)
            );
            let t = Totp::parse(uri.as_bytes()).unwrap();
            let got = t.code_at(Timestamp(time * 1000 + 999)).unwrap();
            assert_eq!(got.expose_secret(), code, "time {time} {alg}");
        }
    }

    #[test]
    fn totp_defaults_and_accessors() {
        let t = Totp::parse(b"otpauth://totp/x?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").unwrap();
        assert_eq!(t.algorithm(), OtpAlgorithm::Sha1);
        assert_eq!((t.digits(), t.period()), (6, 30));
        // RFC 6238 time 59 → T = 1 → the 8-digit code 94287082, low 6 digits.
        assert_eq!(
            t.code_at(Timestamp(59_000)).unwrap().expose_secret(),
            "287082"
        );
        assert_eq!(t.seconds_remaining(Timestamp(59_000)), Ok(1));
        assert_eq!(t.seconds_remaining(Timestamp(60_000)), Ok(30));
        assert_eq!(t.seconds_remaining(Timestamp(0)), Ok(30));
        assert_eq!(format!("{t:?}"), "Totp(<redacted>)");
        assert_eq!(
            t.code_at(Timestamp(-1)).map(|_| ()),
            Err(TotpError::BeforeEpoch)
        );
        assert_eq!(
            t.seconds_remaining(Timestamp(-1000)),
            Err(TotpError::BeforeEpoch)
        );
        assert_eq!(TotpError::InvalidUri.to_string(), "invalid TOTP URI");
    }

    #[test]
    fn totp_lenient_spellings() {
        for uri in [
            "OTPAUTH://TOTP/x?SECRET=gezdgnbvgy3tqojq&Algorithm=sha256&DIGITS=7",
            "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ%3D%3D&issuer=Ex&image=y",
            "otpauth://totp/?secret=GEZDGNBVGY3TQOJQ====#frag",
            "otpauth://totp/a%20b?flag&secret=GEZDGNBVGY3TQOJQ",
        ] {
            let t = Totp::parse(uri.as_bytes()).unwrap_or_else(|e| panic!("{uri}: {e:?}"));
            assert_eq!(t.key.expose_secret(), b"1234567890", "{uri}");
        }
        let t = Totp::parse(b"otpauth://totp/x?algorithm=SHA512&secret=GE&period=86400&digits=8")
            .unwrap();
        assert_eq!(
            (t.algorithm(), t.digits(), t.period()),
            (OtpAlgorithm::Sha512, 8, 86_400)
        );
    }

    #[test]
    fn totp_rejections() {
        use TotpError::{InvalidUri, Unsupported};
        let ok_secret = "GEZDGNBVGY3TQOJQ";
        let cases: Vec<(String, TotpError)> = vec![
            (
                format!("otpauth://hotp/x?secret={ok_secret}&counter=1"),
                Unsupported,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&algorithm=SHA3-256"),
                Unsupported,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&digits=5"),
                Unsupported,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&digits=9"),
                Unsupported,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&period=0"),
                Unsupported,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&period=86401"),
                Unsupported,
            ),
            ("otpauth://totp/x?issuer=a".into(), InvalidUri),
            ("otpauth://totp/x".into(), InvalidUri),
            ("otpauth://totp/x?secret=GEZ1".into(), InvalidUri),
            ("otpauth://totp/x?secret=GEZ".into(), InvalidUri),
            ("otpauth://totp/x?secret=".into(), InvalidUri),
            (
                format!("otpauth://totp/x?secret={ok_secret}&secret={ok_secret}"),
                InvalidUri,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&digits=6&DIGITS=6"),
                InvalidUri,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}%G1"),
                InvalidUri,
            ),
            (format!("otpauth://totp/x?secret={ok_secret}%4"), InvalidUri),
            (
                format!("otpauth://totp/x?secret={ok_secret}&digits=six"),
                InvalidUri,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&period=-30"),
                InvalidUri,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&digits=0000000006"),
                InvalidUri,
            ),
            (
                format!("otpauth://totp/x?secret={ok_secret}&digits"),
                InvalidUri,
            ),
            (format!("https://totp/x?secret={ok_secret}"), InvalidUri),
            (format!("otpauth://xotp/x?secret={ok_secret}"), InvalidUri),
            (format!("otpauth:/totp/x?secret={ok_secret}"), InvalidUri),
            (
                format!("otpauth://totp/x?secret={}", base32(&[7; 257])),
                InvalidUri,
            ),
        ];
        for (uri, err) in cases {
            assert_eq!(Totp::parse(uri.as_bytes()).map(|_| ()), Err(err), "{uri}");
        }
        assert!(
            Totp::parse(format!("otpauth://totp/x?secret={}", base32(&[7; 256])).as_bytes())
                .is_ok()
        );
        let huge = vec![b'a'; MAX_TEXT_BYTES + 1];
        assert_eq!(Totp::parse(&huge).map(|_| ()), Err(InvalidUri));
    }

    #[test]
    fn totp_base32_round_trips() {
        for len in 0..40usize {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + 5) as u8).collect();
            let enc = base32(&data);
            assert_eq!(
                base32_decode(enc.as_bytes()).unwrap().expose_secret(),
                data.as_slice()
            );
            assert_eq!(
                base32_decode(enc.trim_end_matches('=').to_lowercase().as_bytes())
                    .unwrap()
                    .expose_secret(),
                data.as_slice()
            );
        }
    }
}
