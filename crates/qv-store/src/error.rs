// SPDX-License-Identifier: AGPL-3.0-or-later

//! The redacted store error taxonomy.
//!
//! No variant carries data: no paths, SQL text, offsets or lengths. SQLite
//! and OS errors are mapped by crate-private helpers instead of `From`, so
//! their messages (which can name the path) never travel with the error.

use core::fmt;

use qv_crypto::CryptoError;
use qv_model::ModelError;

/// Why a vault-file operation failed.
///
/// The intended CLI exit codes (0011 §6); the CLI maps them in its own layer.
///
/// | Variant | Exit code |
/// |---------|-----------|
/// | [`WrongPassword`](Self::WrongPassword), [`WrongPhrase`](Self::WrongPhrase) | 3 |
/// | [`NotFound`](Self::NotFound) | 4 |
/// | [`Locked`](Self::Locked), [`Replaced`](Self::Replaced), [`Changed`](Self::Changed) | 6 |
/// | [`Integrity`](Self::Integrity), [`Rollback`](Self::Rollback), [`NoAnchor`](Self::NoAnchor) | 7 |
/// | [`LimitExceeded`](Self::LimitExceeded) | 9 |
/// | every other variant | 1 |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// The KEK commitment or the slot AEAD failed (0002 §8).
    WrongPassword,
    /// Invalid recovery phrase or failed initial phrase-key confirmation.
    WrongPhrase,
    /// The vault path does not exist.
    NotFound,
    /// Another open holds the vault's process lock, or SQLite is busy.
    Locked,
    /// The path no longer names the opened file (0004 §1.3).
    Replaced,
    /// Failed integrity: `quick_check`, the exact schema, row checks, the
    /// header or head MAC, the manifest, a missing or mismatched object, or
    /// a corrupt database.
    Integrity,
    /// The local head does not match the external anchor: an older or
    /// forked database, one more than a commit ahead, or another vault's
    /// (0005 §5.4). Writes are blocked until an explicit recovery.
    Rollback,
    /// There is no external anchor for this vault database (a new
    /// installation, or a copy from elsewhere). Writes are blocked until an
    /// explicit recovery; a missing anchor never resets the baseline
    /// silently (0005 §5.4).
    NoAnchor,
    /// The vault changed on disk since it was unlocked (0004 §1.3); reopen.
    Changed,
    /// An edit breaks a vault rule (counter, causality, kind or control
    /// record rules); nothing was written.
    InvalidEdit,
    /// A size budget (0004 §4.1) would be exceeded; nothing was changed.
    LimitExceeded,
    /// The file is a SQLite database but not a QuickVault vault.
    NotAVault,
    /// An unknown schema version, header format or key, profile or slot
    /// type, or a platform without the file-safety code.
    Unsupported,
    /// A symlink, nonregular file, wrong owner or mode, or an unsafe parent
    /// directory (0004 §1.1, 0008 §5).
    UnsafeFile,
    /// The path to create already exists.
    Exists,
    /// A required SQLite hardening setting did not take effect (0004 §1.2).
    Hardening,
    /// Another I/O or SQLite failure.
    Io,
    /// The operating system random number generator failed.
    Rng,
    /// A bug.
    Internal,
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::WrongPassword => "wrong password",
            Self::WrongPhrase => "wrong recovery phrase or damaged vault header",
            Self::NotFound => "vault not found",
            Self::Locked => "vault is locked by another process",
            Self::Replaced => "vault file was replaced on disk",
            Self::Integrity => "vault integrity check failed",
            Self::Rollback => "vault does not match its last known state (possible rollback)",
            Self::NoAnchor => "no record of this vault's last known state on this device",
            Self::Changed => "vault changed on disk; reopen it",
            Self::InvalidEdit => "edit rejected by a vault rule",
            Self::LimitExceeded => "vault size limit exceeded",
            Self::NotAVault => "not a QuickVault vault",
            Self::Unsupported => "unsupported vault format or platform",
            Self::UnsafeFile => "vault file or directory is not private",
            Self::Exists => "path already exists",
            Self::Hardening => "database hardening failed",
            Self::Io => "vault input/output error",
            Self::Rng => "operating system random number generator failed",
            Self::Internal => "internal store error",
        })
    }
}

impl std::error::Error for StoreError {}

impl From<CryptoError> for StoreError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::WrongPassword => Self::WrongPassword,
            CryptoError::WrongPhrase => Self::WrongPhrase,
            CryptoError::Integrity => Self::Integrity,
            CryptoError::UnknownProfile => Self::Unsupported,
            CryptoError::LimitExceeded => Self::LimitExceeded,
            CryptoError::Rng => Self::Rng,
            _ => Self::Internal,
        }
    }
}

impl From<ModelError> for StoreError {
    fn from(e: ModelError) -> Self {
        match e {
            ModelError::Malformed | ModelError::Integrity | ModelError::InvalidTransition => {
                Self::Integrity
            }
            ModelError::Unsupported => Self::Unsupported,
            ModelError::LimitExceeded => Self::LimitExceeded,
            ModelError::Rng => Self::Rng,
            _ => Self::Internal,
        }
    }
}

/// Maps a SQLite error without keeping its message.
pub(crate) fn sqlite_err(e: &rusqlite::Error) -> StoreError {
    use rusqlite::ErrorCode;
    match e.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => StoreError::Locked,
        Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase) => StoreError::Integrity,
        Some(ErrorCode::TooBig | ErrorCode::DiskFull) => StoreError::LimitExceeded,
        Some(ErrorCode::OperationInterrupted) => StoreError::LimitExceeded,
        Some(ErrorCode::CannotOpen) => StoreError::Io,
        _ => StoreError::Io,
    }
}

/// Pages of slack when deciding whether a full database hit its page limit:
/// b-tree and overflow-page overhead of the write being attempted.
const FULL_SLACK_PAGES: u64 = 64;

/// Maps a SQLite error from a write of at most `growth` bytes.
/// `SQLITE_FULL` is both "`max_page_count` reached" and "disk full"; it is
/// [`StoreError::LimitExceeded`] only when this write would take the file to
/// its page limit, and [`StoreError::Io`] otherwise (plan 0008 review,
/// finding 2). Best effort: the page count is read after the failure.
pub(crate) fn write_err(
    conn: &rusqlite::Connection,
    e: &rusqlite::Error,
    growth: u64,
) -> StoreError {
    if e.sqlite_error_code() != Some(rusqlite::ErrorCode::DiskFull) {
        return sqlite_err(e);
    }
    let read = |name: &str| {
        conn.pragma_query_value(None, name, |r| r.get::<_, i64>(0))
            .ok()
            .and_then(|v| u64::try_from(v).ok())
    };
    match (read("page_count"), read("max_page_count")) {
        (Some(pages), Some(max)) => full_err(pages, max, growth),
        _ => StoreError::Io,
    }
}

/// See [`write_err`].
pub(crate) fn full_err(pages: u64, max_pages: u64, growth: u64) -> StoreError {
    let needed = (growth / crate::limits::PAGE_SIZE).saturating_add(FULL_SLACK_PAGES);
    if pages.saturating_add(needed) >= max_pages {
        StoreError::LimitExceeded
    } else {
        StoreError::Io
    }
}

/// Maps an OS error without keeping its message.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) fn errno_err(e: rustix::io::Errno) -> StoreError {
    use rustix::io::Errno;
    match e {
        Errno::NOENT => StoreError::NotFound,
        Errno::LOOP => StoreError::UnsafeFile,
        Errno::EXIST => StoreError::Exists,
        Errno::WOULDBLOCK => StoreError::Locked,
        Errno::NOSPC | Errno::FBIG => StoreError::LimitExceeded,
        _ => StoreError::Io,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_strings_are_fixed() {
        assert_eq!(StoreError::WrongPassword.to_string(), "wrong password");
        assert_eq!(
            StoreError::Integrity.to_string(),
            "vault integrity check failed"
        );
        assert_eq!(
            StoreError::Locked.to_string(),
            "vault is locked by another process"
        );
        assert_eq!(format!("{:?}", StoreError::Replaced), "Replaced");
    }

    #[test]
    fn crypto_errors_map() {
        let cases = [
            (CryptoError::WrongPassword, StoreError::WrongPassword),
            (CryptoError::Integrity, StoreError::Integrity),
            (CryptoError::UnknownProfile, StoreError::Unsupported),
            (CryptoError::LimitExceeded, StoreError::LimitExceeded),
            (CryptoError::Rng, StoreError::Rng),
            (CryptoError::WrongPhrase, StoreError::WrongPhrase),
            (CryptoError::InvalidPassword, StoreError::Internal),
            (CryptoError::Internal, StoreError::Internal),
        ];
        for (from, to) in cases {
            assert_eq!(StoreError::from(from), to, "{from:?}");
        }
    }

    #[test]
    fn model_errors_map() {
        let cases = [
            (ModelError::Malformed, StoreError::Integrity),
            (ModelError::Integrity, StoreError::Integrity),
            (ModelError::InvalidTransition, StoreError::Integrity),
            (ModelError::Unsupported, StoreError::Unsupported),
            (ModelError::LimitExceeded, StoreError::LimitExceeded),
            (ModelError::Rng, StoreError::Rng),
            (ModelError::CounterExhausted, StoreError::Internal),
            (ModelError::Internal, StoreError::Internal),
        ];
        for (from, to) in cases {
            assert_eq!(StoreError::from(from), to, "{from:?}");
        }
    }

    #[test]
    fn sqlite_errors_map() {
        use rusqlite::ffi;
        let err = |code| rusqlite::Error::SqliteFailure(ffi::Error::new(code), None);
        let cases = [
            (ffi::SQLITE_BUSY, StoreError::Locked),
            (ffi::SQLITE_LOCKED, StoreError::Locked),
            (ffi::SQLITE_CORRUPT, StoreError::Integrity),
            (ffi::SQLITE_NOTADB, StoreError::Integrity),
            (ffi::SQLITE_TOOBIG, StoreError::LimitExceeded),
            (ffi::SQLITE_FULL, StoreError::LimitExceeded),
            (ffi::SQLITE_INTERRUPT, StoreError::LimitExceeded),
            (ffi::SQLITE_IOERR, StoreError::Io),
            (ffi::SQLITE_CANTOPEN, StoreError::Io),
        ];
        for (code, to) in cases {
            assert_eq!(sqlite_err(&err(code)), to, "code {code}");
        }
        assert_eq!(
            sqlite_err(&rusqlite::Error::QueryReturnedNoRows),
            StoreError::Io
        );
    }

    #[test]
    fn full_disk_is_not_the_size_budget() {
        let max = 524_288;
        assert_eq!(full_err(100, max, 4096), StoreError::Io);
        assert_eq!(full_err(max - 10, max, 4096), StoreError::LimitExceeded);
        assert_eq!(full_err(max - 300, max, 1 << 20), StoreError::LimitExceeded);
        assert_eq!(full_err(max - 400, max, 1 << 20), StoreError::Io);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn full_database_at_page_limit_is_limit_exceeded() {
        use crate::fs::test_dir::{TestDir, write_file};
        use crate::sqlite::{StepBudget, harden, open_connection};
        let d = TestDir::new();
        let p = d.join("f.qvault");
        write_file(&p, b"", 0o600);
        let conn = open_connection(&p).unwrap();
        harden(&conn, &StepBudget::new()).unwrap();
        conn.execute_batch("CREATE TABLE t (b BLOB)").unwrap();
        conn.pragma_update(None, "max_page_count", 20).unwrap();
        let blob = vec![0u8; 1 << 20];
        let err = conn
            .execute("INSERT INTO t VALUES (?1)", [blob.as_slice()])
            .unwrap_err();
        assert_eq!(err.sqlite_error_code(), Some(rusqlite::ErrorCode::DiskFull));
        assert_eq!(sqlite_err(&err), StoreError::LimitExceeded);
        assert_eq!(write_err(&conn, &err, 1 << 20), StoreError::LimitExceeded);
        // Other errors keep the ordinary mapping.
        let busy = rusqlite::Error::SqliteFailure(
            rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
            None,
        );
        assert_eq!(write_err(&conn, &busy, 0), StoreError::Locked);
    }

    #[cfg(any(target_os = "linux", target_os = "android"))]
    #[test]
    fn os_errors_map() {
        use rustix::io::Errno;
        let cases = [
            (Errno::NOENT, StoreError::NotFound),
            (Errno::LOOP, StoreError::UnsafeFile),
            (Errno::EXIST, StoreError::Exists),
            (Errno::WOULDBLOCK, StoreError::Locked),
            (Errno::NOSPC, StoreError::LimitExceeded),
            (Errno::FBIG, StoreError::LimitExceeded),
            (Errno::ACCESS, StoreError::Io),
        ];
        for (from, to) in cases {
            assert_eq!(errno_err(from), to, "{from:?}");
        }
    }
}
