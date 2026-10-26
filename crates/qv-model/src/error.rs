// SPDX-License-Identifier: AGPL-3.0-or-later

//! The redacted model error taxonomy.
//!
//! No variant carries data: no plaintext, IDs, lengths or offsets.

use core::fmt;

use qv_crypto::RngError;
use qv_encoding::{DecodeError, EncodeError};

/// Why a model operation failed.
///
/// The intended CLI exit codes (0011 §6) are listed per variant; the CLI maps
/// them in its own layer. Records reach the model only after authentication,
/// so a record that does not parse is an integrity failure (7), not a usage
/// error.
///
/// | Variant | Exit code |
/// |---------|-----------|
/// | [`Malformed`](Self::Malformed), [`Integrity`](Self::Integrity), [`InvalidTransition`](Self::InvalidTransition) | 7 |
/// | [`LimitExceeded`](Self::LimitExceeded) | 9 |
/// | [`Unsupported`](Self::Unsupported), [`CounterExhausted`](Self::CounterExhausted), [`Rng`](Self::Rng), [`Internal`](Self::Internal) | 1 |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ModelError {
    /// Not canonical CBOR, a missing, ill-typed or out-of-range key, an ID
    /// without the UUIDv4 bits, or an invalid clock.
    Malformed,
    /// An unknown record kind or keyslot profile (fails closed, 0003 §2.2).
    Unsupported,
    /// A resource budget would be exceeded (0004 §4.1); nothing was changed.
    LimitExceeded,
    /// Version identities are inconsistent (0005 §1.4), or a record ID's kind
    /// changed (0003 §2.3).
    Integrity,
    /// A deleted root group, vault metadata or keyslot record (0003 §2.3).
    InvalidTransition,
    /// The writer's counter cannot advance; a new writer ID is needed
    /// (0005 §1.3).
    CounterExhausted,
    /// The operating system random number generator failed.
    Rng,
    /// An encoder failure or a bug.
    Internal,
}

impl fmt::Display for ModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed record",
            Self::Unsupported => "unsupported record feature",
            Self::LimitExceeded => "record size limit exceeded",
            Self::Integrity => "record versions are inconsistent",
            Self::InvalidTransition => "invalid record transition",
            Self::CounterExhausted => "writer counter exhausted",
            Self::Rng => "operating system random number generator failed",
            Self::Internal => "internal model error",
        })
    }
}

impl std::error::Error for ModelError {}

impl From<DecodeError> for ModelError {
    fn from(_: DecodeError) -> Self {
        Self::Malformed
    }
}

impl From<EncodeError> for ModelError {
    fn from(_: EncodeError) -> Self {
        Self::Internal
    }
}

impl From<RngError> for ModelError {
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
            (ModelError::Malformed, "malformed record"),
            (ModelError::Unsupported, "unsupported record feature"),
            (ModelError::LimitExceeded, "record size limit exceeded"),
            (ModelError::Integrity, "record versions are inconsistent"),
            (ModelError::InvalidTransition, "invalid record transition"),
            (ModelError::CounterExhausted, "writer counter exhausted"),
            (
                ModelError::Rng,
                "operating system random number generator failed",
            ),
            (ModelError::Internal, "internal model error"),
        ];
        for (e, s) in all {
            assert_eq!(e.to_string(), s);
        }
    }

    #[test]
    fn codec_errors_map() {
        assert_eq!(
            ModelError::from(DecodeError::Truncated),
            ModelError::Malformed
        );
        assert_eq!(
            ModelError::from(EncodeError::DuplicateKey),
            ModelError::Internal
        );
    }
}
