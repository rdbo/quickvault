// SPDX-License-Identifier: AGPL-3.0-or-later

//! The core error taxonomy. No variant carries data beyond another crate's
//! data-free error enum: no IDs, names, paths or values.

use core::fmt;

use qv_crypto::{CryptoError, GeneratorError};
use qv_model::{ModelError, TotpError};
use qv_store::StoreError;

/// Why a core operation failed.
///
/// The intended CLI exit codes (0011 §6); the CLI maps them in its own layer.
///
/// | Variant | Exit code |
/// |---------|-----------|
/// | [`Store`](Self::Store) | as [`StoreError`] documents (3, 4, 6, 7, 9 or 1) |
/// | [`NotFound`](Self::NotFound) | 4 |
/// | [`StaleHandle`](Self::StaleHandle) | 6 |
/// | [`Conflict`](Self::Conflict) | 8 |
/// | [`LimitExceeded`](Self::LimitExceeded) | 9 |
/// | every other variant | 1 |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CoreError {
    /// The vault file or its verification failed.
    Store(StoreError),
    /// The session is locked; its handles have expired (0008 §1.4).
    SessionLocked,
    /// The handle belongs to another session, or names a version that is no
    /// longer current: the item changed since it was shown.
    StaleHandle,
    /// The operation was cancelled (a lock was requested, or the caller's
    /// token was cancelled). Nothing was changed.
    Cancelled,
    /// The record has an unresolved conflict; an explicit resolution is
    /// needed first (0005 §1.2, §2.3).
    Conflict,
    /// No such entry, group or field.
    NotFound,
    /// The group is not empty and the deletion was not recursive.
    NotEmpty,
    /// The operation is not allowed for this item (for example deleting the
    /// root, moving a group into itself, or editing an item in the trash).
    NotAllowed,
    /// A value breaks a model rule (length, field count, format).
    InvalidInput,
    /// Invalid password generator settings (0010).
    Generator(GeneratorError),
    /// An invalid or unsupported TOTP field.
    Totp(TotpError),
    /// A size budget would be exceeded; nothing was changed (0004 §4.4).
    LimitExceeded,
    /// The operating system random number generator failed.
    Rng,
    /// The vault's directory is the anchor directory or lies inside it, so
    /// the anchor could be copied or restored with the vault and would
    /// detect nothing (0005 §5.4). Move the vault elsewhere.
    AnchorLocation,
    /// A bug.
    Internal,
}

impl fmt::Display for CoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(e) => e.fmt(f),
            Self::Generator(e) => e.fmt(f),
            Self::Totp(e) => e.fmt(f),
            other => f.write_str(match other {
                Self::SessionLocked => "the vault session is locked",
                Self::StaleHandle => "the item changed; reload it",
                Self::Cancelled => "operation cancelled",
                Self::Conflict => "the item has conflicting versions; resolve them first",
                Self::NotFound => "entry, group or field not found",
                Self::NotEmpty => "the group is not empty",
                Self::NotAllowed => "operation not allowed for this item",
                Self::InvalidInput => "invalid value",
                Self::LimitExceeded => "size limit exceeded",
                Self::Rng => "operating system random number generator failed",
                Self::AnchorLocation => {
                    "the vault must not be stored in the anchor directory or below it"
                }
                _ => "internal error",
            }),
        }
    }
}

impl std::error::Error for CoreError {}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<GeneratorError> for CoreError {
    fn from(e: GeneratorError) -> Self {
        Self::Generator(e)
    }
}

impl From<TotpError> for CoreError {
    fn from(e: TotpError) -> Self {
        Self::Totp(e)
    }
}

/// A model error from a value the caller supplied (a draft field, a name).
pub(crate) fn input(e: ModelError) -> CoreError {
    match e {
        ModelError::LimitExceeded => CoreError::LimitExceeded,
        ModelError::Rng => CoreError::Rng,
        ModelError::Internal => CoreError::Internal,
        ModelError::CounterExhausted => CoreError::Store(StoreError::LimitExceeded),
        _ => CoreError::InvalidInput,
    }
}

/// A model error from authenticated vault data: anything structural is an
/// integrity failure.
pub(crate) fn data(e: ModelError) -> CoreError {
    match e {
        ModelError::LimitExceeded => CoreError::LimitExceeded,
        ModelError::Rng => CoreError::Rng,
        ModelError::Unsupported => CoreError::Store(StoreError::Unsupported),
        ModelError::CounterExhausted => CoreError::Store(StoreError::LimitExceeded),
        ModelError::Internal => CoreError::Internal,
        _ => CoreError::Store(StoreError::Integrity),
    }
}

/// A crypto error outside the store (the recovery phrase).
pub(crate) fn crypto(e: CryptoError) -> CoreError {
    match e {
        CryptoError::Rng => CoreError::Rng,
        _ => CoreError::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_error_strings_are_fixed() {
        assert_eq!(
            CoreError::Store(StoreError::WrongPassword).to_string(),
            "wrong password"
        );
        assert_eq!(
            CoreError::Conflict.to_string(),
            "the item has conflicting versions; resolve them first"
        );
        assert_eq!(CoreError::Internal.to_string(), "internal error");
        assert_eq!(format!("{:?}", CoreError::StaleHandle), "StaleHandle");
        assert_eq!(input(ModelError::Malformed), CoreError::InvalidInput);
        assert_eq!(
            data(ModelError::Malformed),
            CoreError::Store(StoreError::Integrity)
        );
        assert_eq!(input(ModelError::LimitExceeded), CoreError::LimitExceeded);
    }
}
