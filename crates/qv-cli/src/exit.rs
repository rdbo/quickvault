// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exit codes and error messages (spec 0011 §5.3, §6).
//!
//! | Code | Meaning | Sources |
//! |------|---------|---------|
//! | 0 | success | |
//! | 1 | other error | every unlisted error |
//! | 2 | usage error, no vault selected | clap, config, selection, missing TTY, bad address syntax |
//! | 3 | wrong master password or recovery phrase | `StoreError::WrongPassword`, `CryptoError::WrongPhrase` |
//! | 4 | entry, group or vault not found | `StoreError::NotFound`, `CoreError::NotFound` |
//! | 5 | ambiguous address | [`address`](crate::address) |
//! | 6 | locked by another process, or changed on disk | `Locked`, `Replaced`, `Changed`, `CoreError::StaleHandle` |
//! | 7 | integrity or rollback failure | `Integrity`, `Rollback`, `NoAnchor` |
//! | 8 | unresolved conflict | `CoreError::Conflict` |
//! | 9 | resource or safety limit | `LimitExceeded`, `CoreError::SnapshotOverBudget`, input over a bound |
//!
//! Messages are fixed text. The only variable parts are non-secret context
//! (a config line number, an escaped path or the matches of an ambiguous
//! address), already escaped by the caller.

use qv_core::{CoreError, CryptoError, StoreError};

/// Other error.
pub(crate) const OTHER: u8 = 1;
/// Usage error or no vault selected.
pub(crate) const USAGE: u8 = 2;
/// Wrong master password or recovery phrase.
pub(crate) const AUTH: u8 = 3;
/// Not found.
pub(crate) const NOT_FOUND: u8 = 4;
/// Ambiguous address.
pub(crate) const AMBIGUOUS: u8 = 5;
/// Locked by another process, or changed on disk.
pub(crate) const BUSY: u8 = 6;
/// Integrity or rollback failure.
pub(crate) const INTEGRITY: u8 = 7;
/// Unresolved conflict.
pub(crate) const CONFLICT: u8 = 8;
/// Resource or safety limit.
pub(crate) const LIMIT: u8 = 9;

/// A failed command: its exit code and the message for stderr.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CliError {
    pub(crate) code: u8,
    pub(crate) message: String,
}

impl CliError {
    pub(crate) fn new(code: u8, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// A usage error (exit 2).
    pub(crate) fn usage(message: impl Into<String>) -> Self {
        Self::new(USAGE, message)
    }

    /// The prompt was cancelled (Ctrl-C or Ctrl-D).
    pub(crate) fn cancelled() -> Self {
        Self::new(OTHER, "cancelled")
    }
}

/// The exit code of a store error.
pub(crate) fn store_code(e: StoreError) -> u8 {
    match e {
        StoreError::WrongPassword | StoreError::WrongPhrase => AUTH,
        StoreError::NotFound => NOT_FOUND,
        StoreError::Locked | StoreError::Replaced | StoreError::Changed => BUSY,
        StoreError::Integrity | StoreError::Rollback | StoreError::NoAnchor => INTEGRITY,
        StoreError::LimitExceeded => LIMIT,
        _ => OTHER,
    }
}

/// The exit code of a core error.
pub(crate) fn core_code(e: CoreError) -> u8 {
    match e {
        CoreError::Store(s) => store_code(s),
        CoreError::NotFound => NOT_FOUND,
        CoreError::StaleHandle => BUSY,
        CoreError::Conflict => CONFLICT,
        CoreError::LimitExceeded | CoreError::SnapshotOverBudget { .. } => LIMIT,
        _ => OTHER,
    }
}

/// The exit code of a crypto error (the recovery phrase, a password).
pub(crate) fn crypto_code(e: CryptoError) -> u8 {
    match e {
        CryptoError::WrongPassword | CryptoError::WrongPhrase => AUTH,
        CryptoError::LimitExceeded => LIMIT,
        _ => OTHER,
    }
}

/// An extra line for errors the user can act on.
fn hint(e: CoreError) -> Option<&'static str> {
    match e {
        CoreError::Store(StoreError::NoAnchor) => Some(
            "this device has no record of the vault's last state (it was copied here, or the \
             state directory was lost); use explicit `qvault recover <path>` with your recovery phrase to accept a baseline",
        ),
        CoreError::Store(StoreError::Rollback) => Some(
            "the vault is older than this device last saw it, or was replaced: it may have been \
             rolled back; nothing was changed",
        ),
        CoreError::Store(StoreError::Locked) => Some("another qvault process has it open"),
        CoreError::Conflict => Some(
            "the entry has conflicting versions; choosing one needs conflict resolution, which \
             qvault does not offer yet",
        ),
        CoreError::AnchorLocation => Some("move the vault out of the QuickVault state directory"),
        _ => None,
    }
}

impl From<CoreError> for CliError {
    fn from(e: CoreError) -> Self {
        let mut message = e.to_string();
        if let Some(h) = hint(e) {
            message.push_str("\nhint: ");
            message.push_str(h);
        }
        Self::new(core_code(e), message)
    }
}

impl From<StoreError> for CliError {
    fn from(e: StoreError) -> Self {
        CoreError::Store(e).into()
    }
}

impl From<CryptoError> for CliError {
    fn from(e: CryptoError) -> Self {
        Self::new(crypto_code(e), e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use qv_core::{GeneratorError, TotpError};

    use super::*;

    #[test]
    fn exit_table_rows() {
        let core = |e: CoreError| CliError::from(e).code;
        let store = |e: StoreError| CliError::from(e).code;
        // 3
        assert_eq!(store(StoreError::WrongPassword), 3);
        assert_eq!(store(StoreError::WrongPhrase), 3);
        assert_eq!(CliError::from(CryptoError::WrongPhrase).code, 3);
        // 4
        assert_eq!(store(StoreError::NotFound), 4);
        assert_eq!(core(CoreError::NotFound), 4);
        // 5 is produced by the address resolver (AMBIGUOUS).
        assert_eq!(AMBIGUOUS, 5);
        // 6
        for e in [
            StoreError::Locked,
            StoreError::Replaced,
            StoreError::Changed,
        ] {
            assert_eq!(store(e), 6, "{e:?}");
        }
        assert_eq!(core(CoreError::StaleHandle), 6);
        // 7
        for e in [
            StoreError::Integrity,
            StoreError::Rollback,
            StoreError::NoAnchor,
        ] {
            assert_eq!(store(e), 7, "{e:?}");
        }
        // 8
        assert_eq!(core(CoreError::Conflict), 8);
        // 9
        assert_eq!(store(StoreError::LimitExceeded), 9);
        assert_eq!(core(CoreError::LimitExceeded), 9);
        assert_eq!(core(CoreError::SnapshotOverBudget { needed: 4096 }), 9);
        assert_eq!(CliError::from(CryptoError::LimitExceeded).code, 9);
        // 2
        assert_eq!(CliError::usage("x").code, 2);
        // 1: everything else.
        for e in [
            CoreError::SessionLocked,
            CoreError::Cancelled,
            CoreError::NotEmpty,
            CoreError::NotAllowed,
            CoreError::InvalidInput,
            CoreError::Rng,
            CoreError::Internal,
            CoreError::AnchorLocation,
            CoreError::Generator(GeneratorError::NoClassEnabled),
            CoreError::Totp(TotpError::InvalidUri),
            CoreError::Store(StoreError::UnsafeFile),
            CoreError::Store(StoreError::Io),
            CoreError::Store(StoreError::NotAVault),
        ] {
            assert_eq!(core(e), 1, "{e:?}");
        }
        assert_eq!(CliError::from(CryptoError::InvalidPassword).code, 1);
        assert_eq!(CliError::cancelled().code, 1);
    }

    #[test]
    fn exit_messages_are_fixed_and_hinted() {
        let e = CliError::from(StoreError::NoAnchor);
        assert!(
            e.message
                .starts_with("no record of this vault's last known state")
        );
        assert!(e.message.contains("\nhint: "));
        assert_eq!(
            CliError::from(StoreError::Io).message,
            "vault input/output error"
        );
    }
}
