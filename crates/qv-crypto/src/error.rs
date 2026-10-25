// SPDX-License-Identifier: AGPL-3.0-or-later

//! The redacted crypto error taxonomy (spec 0002 §8, 0011 §6).
//!
//! No variant carries data: no key material, plaintext, lengths or offsets.

use core::fmt;

use crate::rng::RngError;

/// Why a cryptographic operation failed.
///
/// The intended CLI exit codes (0011 §6) are listed per variant; the CLI maps
/// them in its own layer.
///
/// | Variant | Exit code |
/// |---------|-----------|
/// | [`WrongPassword`](Self::WrongPassword) | 3 |
/// | [`Integrity`](Self::Integrity) | 7 |
/// | [`LimitExceeded`](Self::LimitExceeded) | 9 |
/// | [`UnknownProfile`](Self::UnknownProfile), [`InvalidPassword`](Self::InvalidPassword), [`Rng`](Self::Rng), [`Internal`](Self::Internal) | 1 |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CryptoError {
    /// The KEK commitment or the password-slot AEAD failed (0002 §8). With
    /// the commitment, this reveals nothing about other candidate passwords.
    WrongPassword,
    /// Authenticated data failed verification: AEAD tag, MAC or framing.
    Integrity,
    /// A profile ID this build does not know. Fails before any work is done.
    UnknownProfile,
    /// A size budget would be exceeded; nothing was decrypted or produced.
    LimitExceeded,
    /// The master password is not valid UTF-8.
    InvalidPassword,
    /// The operating system random number generator failed (0002 §7.1).
    Rng,
    /// A fixed-shape internal encoding failed. This indicates a bug.
    Internal,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongPassword => "wrong password",
            Self::Integrity => "integrity check failed",
            Self::UnknownProfile => "unknown cryptographic profile",
            Self::LimitExceeded => "size limit exceeded",
            Self::InvalidPassword => "password is not valid UTF-8",
            Self::Rng => "operating system random number generator failed",
            Self::Internal => "internal cryptographic encoding error",
        })
    }
}

impl std::error::Error for CryptoError {}

impl From<RngError> for CryptoError {
    fn from(_: RngError) -> Self {
        Self::Rng
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_strings_are_fixed() {
        let all = [
            (CryptoError::WrongPassword, "wrong password"),
            (CryptoError::Integrity, "integrity check failed"),
            (CryptoError::UnknownProfile, "unknown cryptographic profile"),
            (CryptoError::LimitExceeded, "size limit exceeded"),
            (CryptoError::InvalidPassword, "password is not valid UTF-8"),
            (
                CryptoError::Rng,
                "operating system random number generator failed",
            ),
            (
                CryptoError::Internal,
                "internal cryptographic encoding error",
            ),
        ];
        for (e, s) in all {
            assert_eq!(e.to_string(), s);
        }
    }

    #[test]
    fn error_from_rng_error() {
        let rng: RngError = crate::rng::test_error();
        assert_eq!(CryptoError::from(rng), CryptoError::Rng);
    }
}
