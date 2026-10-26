// SPDX-License-Identifier: AGPL-3.0-or-later

//! One-time codes: RFC 4226 HOTP over HMAC from the pinned RustCrypto crates,
//! for the RFC 6238 TOTP fields of spec 0003 §5.4.
//!
//! This is the HOTP construction (dynamic truncation of an HMAC), not a new
//! primitive. Parsing `otpauth://` URIs and turning time into a counter live
//! in `qv-model`. The HMAC output and the code are wiped after use; the code
//! is held in a [`SecretArray`] with a redacted `Debug`. Codes are shown to
//! the user, never compared, so no constant-time comparison is needed.
//!
//! ```compile_fail
//! let c = qv_crypto::hotp(b"k", qv_crypto::OtpAlgorithm::Sha1, 0, 6).unwrap();
//! let _ = c.clone();
//! ```
//!
//! ```
//! let c = qv_crypto::hotp(b"12345678901234567890", qv_crypto::OtpAlgorithm::Sha1, 0, 6).unwrap();
//! assert_eq!(c.expose_secret(), "755224");
//! assert_eq!(format!("{c:?}"), "OtpCode(<redacted>)");
//! ```

use core::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

use crate::error::CryptoError;
use crate::memory::SecretArray;

/// The HMAC hash of an OTP (the `algorithm` URI parameter).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtpAlgorithm {
    /// HMAC-SHA-1 (the RFC 6238 default).
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

/// A one-time code: 6–8 ASCII digits in locked memory.
///
/// No `Clone`, `Display` or `PartialEq`; `Debug` is redacted.
pub struct OtpCode {
    digits: SecretArray<8>,
    len: usize,
}

impl OtpCode {
    /// The code's digits.
    pub fn expose_secret(&self) -> &str {
        let bytes = self
            .digits
            .expose_secret()
            .get(..self.len)
            .unwrap_or_default();
        // Always ASCII digits by construction.
        core::str::from_utf8(bytes).unwrap_or_default()
    }
}

impl fmt::Debug for OtpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OtpCode(<redacted>)")
    }
}

/// HMAC of `msg` under `key` into `out`; returns the output length.
fn hmac_into<M: Mac + KeyInit>(
    key: &[u8],
    msg: &[u8],
    out: &mut [u8; 64],
) -> Result<usize, CryptoError> {
    // HMAC accepts keys of any length, so this does not fail in practice.
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| CryptoError::Internal)?;
    mac.update(msg);
    let mut tag = mac.finalize().into_bytes();
    let n = tag.len();
    out.get_mut(..n)
        .ok_or(CryptoError::Internal)?
        .copy_from_slice(&tag);
    tag.as_mut_slice().zeroize();
    Ok(n)
}

/// RFC 4226 HOTP: HMAC(`key`, big-endian `counter`), dynamic truncation, the
/// low `digits` decimal digits, zero-padded. `digits` must be 6–8
/// ([`CryptoError::Internal`] otherwise: callers validate it first).
pub fn hotp(
    key: &[u8],
    algorithm: OtpAlgorithm,
    counter: u64,
    digits: u32,
) -> Result<OtpCode, CryptoError> {
    if !(6..=8).contains(&digits) {
        return Err(CryptoError::Internal);
    }
    let msg = counter.to_be_bytes();
    let mut mac = Zeroizing::new([0u8; 64]);
    let n = match algorithm {
        OtpAlgorithm::Sha1 => hmac_into::<Hmac<Sha1>>(key, &msg, &mut mac)?,
        OtpAlgorithm::Sha256 => hmac_into::<Hmac<Sha256>>(key, &msg, &mut mac)?,
        OtpAlgorithm::Sha512 => hmac_into::<Hmac<Sha512>>(key, &msg, &mut mac)?,
    };
    // Dynamic truncation (RFC 4226 §5.3).
    let last = mac
        .get(..n)
        .and_then(<[u8]>::last)
        .ok_or(CryptoError::Internal)?;
    let offset = usize::from(last & 0x0f);
    let word: [u8; 4] = mac
        .get(offset..offset + 4)
        .and_then(|w| w.try_into().ok())
        .ok_or(CryptoError::Internal)?;
    let mut value = Zeroizing::new(u32::from_be_bytes(word) & 0x7fff_ffff);
    let len = usize::try_from(digits).map_err(|_| CryptoError::Internal)?;
    let code = SecretArray::<8>::try_init(|out| {
        for slot in out
            .get_mut(..len)
            .ok_or(CryptoError::Internal)?
            .iter_mut()
            .rev()
        {
            // `% 10` is below 10, so the cast is lossless.
            *slot = b'0' + (*value % 10) as u8;
            *value /= 10;
        }
        Ok::<(), CryptoError>(())
    })?;
    Ok(OtpCode { digits: code, len })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kat;
    use crate::memory::secrets_test_guard;

    #[test]
    fn otp_rfc4226_hotp_vectors() {
        let _guard = secrets_test_guard();
        let records = kat::parse(include_str!("../tests/vectors/rfc4226-hotp.txt"));
        assert_eq!(records.len(), 10);
        for r in &records {
            let counter = u64::from_be_bytes(r.array::<8>("counter"));
            let code = hotp(r.get("key"), OtpAlgorithm::Sha1, counter, 6).unwrap();
            assert_eq!(
                code.expose_secret().as_bytes(),
                r.get("hotp"),
                "count {counter}"
            );
        }
    }

    #[test]
    fn otp_rfc6238_totp_vectors() {
        let _guard = secrets_test_guard();
        let records = kat::parse(include_str!("../tests/vectors/rfc6238-totp.txt"));
        assert_eq!(records.len(), 18);
        for r in &records {
            let algorithm = match r.get("alg") {
                [1] => OtpAlgorithm::Sha1,
                [2] => OtpAlgorithm::Sha256,
                [3] => OtpAlgorithm::Sha512,
                other => panic!("unknown alg {other:?}"),
            };
            let time = u64::from_be_bytes(r.array::<8>("time"));
            let t = u64::from_be_bytes(r.array::<8>("t"));
            assert_eq!(t, time / 30);
            let code = hotp(r.get("key"), algorithm, t, 8).unwrap();
            assert_eq!(
                code.expose_secret().as_bytes(),
                r.get("totp"),
                "time {time} {algorithm:?}"
            );
        }
    }

    #[test]
    fn otp_digits_and_padding() {
        let _guard = secrets_test_guard();
        let key = b"12345678901234567890";
        // Count 2's truncated value is 137359152: 6, 7 and 8 digits.
        let c = |d| hotp(key, OtpAlgorithm::Sha1, 2, d).unwrap();
        assert_eq!(c(6).expose_secret(), "359152");
        assert_eq!(c(7).expose_secret(), "7359152");
        assert_eq!(c(8).expose_secret(), "37359152");
        // Zero padding is covered by the RFC 6238 row 07081804.
        for d in [0, 5, 9, 10] {
            assert_eq!(
                hotp(key, OtpAlgorithm::Sha1, 0, d).map(|_| ()),
                Err(CryptoError::Internal)
            );
        }
        assert_eq!(format!("{:?}", c(6)), "OtpCode(<redacted>)");
        // An empty key is valid HMAC input.
        assert_eq!(
            hotp(b"", OtpAlgorithm::Sha256, 0, 6)
                .unwrap()
                .expose_secret()
                .len(),
            6
        );
    }
}
