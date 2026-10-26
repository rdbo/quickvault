// SPDX-License-Identifier: AGPL-3.0-or-later

//! The hardened SQLite connection (spec 0004 §1.2, §4.1).
//!
//! Every setting is applied before any statement reads the schema and is
//! read back; a setting that did not take effect is
//! [`StoreError::Hardening`] and the open is aborted.
//!
//! - Open flags: read-write, no create, no URI, no mutex, no symlinks,
//!   extended result codes. The vault file is created by `fs`, never by
//!   SQLite.
//! - `db_config`: defensive mode on; triggers, views, untrusted schema
//!   functions, double-quoted strings, the FTS3 tokenizer, a writable schema
//!   and attaching are off. Extension loading is compiled out
//!   (`SQLITE_OMIT_LOAD_EXTENSION`, `.cargo/config.toml`; rusqlite has no
//!   safe `db_config` for it).
//! - Pragmas: `secure_delete`, `temp_store=MEMORY`, `foreign_keys`,
//!   `journal_mode=DELETE`, `synchronous=FULL`, `trusted_schema=OFF`,
//!   `mmap_size=0`, `cell_size_check`, `max_page_count`, `busy_timeout=0`.
//! - Limits on lengths, columns, expressions, compound selects, program
//!   size, function arguments, attachments, LIKE patterns, variables,
//!   trigger depth and worker threads. Development values.
//! - An execution-step budget: a progress handler interrupts any statement
//!   once the budget for the current operation is spent.
//!
//! No application SQL functions, collations or hooks are registered other
//! than the progress handler.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::config::DbConfig;
use rusqlite::limits::Limit;
use rusqlite::{Connection, OpenFlags};

use crate::error::{StoreError, sqlite_err};
use crate::limits::{MAX_DB_BYTES, PAGE_SIZE};

/// VM operations allowed per `open`, `create` or `unlock` (development
/// value).
pub(crate) const STEP_BUDGET: u64 = 100_000_000;

/// The progress handler runs every this many VM operations.
const STEP_GRANULARITY: u64 = 1000;

/// Largest string or blob: an encrypted 64 MiB manifest plus framing
/// (0004 §4.1; phase 1.7 confirms it).
pub(crate) const MAX_LENGTH: i32 = 64 * 1024 * 1024 + 64 * 1024;

/// Limits applied to every connection, read back after setting.
const LIMITS: &[(Limit, &str, i32)] = &[
    (Limit::SQLITE_LIMIT_LENGTH, "length", MAX_LENGTH),
    (Limit::SQLITE_LIMIT_SQL_LENGTH, "sql_length", 64 * 1024),
    (Limit::SQLITE_LIMIT_COLUMN, "column", 16),
    (Limit::SQLITE_LIMIT_EXPR_DEPTH, "expr_depth", 32),
    (Limit::SQLITE_LIMIT_COMPOUND_SELECT, "compound_select", 2),
    (Limit::SQLITE_LIMIT_VDBE_OP, "vdbe_op", 25_000),
    (Limit::SQLITE_LIMIT_FUNCTION_ARG, "function_arg", 8),
    (Limit::SQLITE_LIMIT_ATTACHED, "attached", 0),
    (
        Limit::SQLITE_LIMIT_LIKE_PATTERN_LENGTH,
        "like_pattern_length",
        64,
    ),
    (Limit::SQLITE_LIMIT_VARIABLE_NUMBER, "variable_number", 32),
    (Limit::SQLITE_LIMIT_TRIGGER_DEPTH, "trigger_depth", 1),
    (Limit::SQLITE_LIMIT_WORKER_THREADS, "worker_threads", 0),
];

/// `db_config` flags and their required values.
const DB_CONFIG: &[(DbConfig, &str, bool)] = &[
    (DbConfig::SQLITE_DBCONFIG_DEFENSIVE, "defensive", true),
    (
        DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER,
        "enable_trigger",
        false,
    ),
    (DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, "enable_view", false),
    (
        DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA,
        "trusted_schema",
        false,
    ),
    (DbConfig::SQLITE_DBCONFIG_DQS_DDL, "dqs_ddl", false),
    (DbConfig::SQLITE_DBCONFIG_DQS_DML, "dqs_dml", false),
    (
        DbConfig::SQLITE_DBCONFIG_ENABLE_FTS3_TOKENIZER,
        "enable_fts3_tokenizer",
        false,
    ),
    (
        DbConfig::SQLITE_DBCONFIG_WRITABLE_SCHEMA,
        "writable_schema",
        false,
    ),
    (
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_CREATE,
        "enable_attach_create",
        false,
    ),
    (
        DbConfig::SQLITE_DBCONFIG_ENABLE_ATTACH_WRITE,
        "enable_attach_write",
        false,
    ),
];

/// Integer pragmas: name, value to set, value read back.
fn int_pragmas() -> [(&'static str, &'static str, i64); 8] {
    [
        ("secure_delete", "ON", 1),
        ("temp_store", "MEMORY", 2),
        ("foreign_keys", "ON", 1),
        ("synchronous", "FULL", 2),
        ("trusted_schema", "OFF", 0),
        ("mmap_size", "0", 0),
        ("cell_size_check", "ON", 1),
        ("busy_timeout", "0", 0),
    ]
}

/// The shared execution-step budget of one connection.
#[derive(Clone)]
pub(crate) struct StepBudget(Arc<AtomicU64>);

impl StepBudget {
    pub(crate) fn new() -> Self {
        Self(Arc::new(AtomicU64::new(STEP_BUDGET / STEP_GRANULARITY)))
    }

    /// Starts a new operation with the full budget.
    pub(crate) fn reset(&self) {
        self.0
            .store(STEP_BUDGET / STEP_GRANULARITY, Ordering::Relaxed);
    }

    /// Spends one unit; `true` once the budget is exhausted.
    fn spend(&self) -> bool {
        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |b| b.checked_sub(1))
            .is_err()
    }

    #[cfg(test)]
    pub(crate) fn set_units(&self, units: u64) {
        self.0.store(units, Ordering::Relaxed);
    }
}

#[cfg(test)]
thread_local! {
    /// Test hook: the named setting reads back wrong (plan 0008).
    pub(crate) static FAIL_SETTING: std::cell::Cell<Option<&'static str>> =
        const { std::cell::Cell::new(None) };
}

/// Whether a read-back value for `name` should be treated as wrong.
fn forced_failure(name: &str) -> bool {
    #[cfg(test)]
    {
        FAIL_SETTING.with(|f| f.get() == Some(name))
    }
    #[cfg(not(test))]
    {
        let _ = name;
        false
    }
}

fn check(name: &str, ok: bool) -> Result<(), StoreError> {
    if ok && !forced_failure(name) {
        Ok(())
    } else {
        Err(StoreError::Hardening)
    }
}

/// Opens an existing file with the vault's flags. SQLite never creates it.
pub(crate) fn open_connection(path: &Path) -> Result<Connection, StoreError> {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW
            | OpenFlags::SQLITE_OPEN_EXRESCODE,
    )
    .map_err(|e| sqlite_err(&e))
}

/// Applies and verifies every hardening setting, then installs the step
/// budget. Must run before anything reads the schema.
pub(crate) fn harden(conn: &Connection, budget: &StepBudget) -> Result<(), StoreError> {
    let e = |e: rusqlite::Error| sqlite_err(&e);
    for &(flag, name, value) in DB_CONFIG {
        conn.set_db_config(flag, value).map_err(e)?;
        check(name, conn.db_config(flag).map_err(e)? == value)?;
    }
    for &(limit, name, value) in LIMITS {
        conn.set_limit(limit, value).map_err(e)?;
        check(name, conn.limit(limit).map_err(e)? == value)?;
    }
    for (name, set, expect) in int_pragmas() {
        conn.pragma_update(None, name, set).map_err(e)?;
        let got: i64 = conn
            .pragma_query_value(None, name, |r| r.get(0))
            .map_err(e)?;
        check(name, got == expect)?;
    }
    let max_pages = i64::try_from(MAX_DB_BYTES / PAGE_SIZE).map_err(|_| StoreError::Internal)?;
    let got: i64 = conn
        .pragma_update_and_check(None, "max_page_count", max_pages, |r| r.get(0))
        .map_err(e)?;
    check("max_page_count", got == max_pages)?;
    let mode: String = conn
        .pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get(0))
        .map_err(e)?;
    check("journal_mode", mode.eq_ignore_ascii_case("delete"))?;

    let b = budget.clone();
    let granularity = i32::try_from(STEP_GRANULARITY).map_err(|_| StoreError::Internal)?;
    conn.progress_handler(granularity, Some(move || b.spend()))
        .map_err(e)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};

    fn fresh(d: &TestDir) -> (Connection, StepBudget) {
        let p = d.join("t.qvault");
        write_file(&p, b"", 0o600);
        let conn = open_connection(&p).unwrap();
        let budget = StepBudget::new();
        harden(&conn, &budget).unwrap();
        (conn, budget)
    }

    #[test]
    fn sqlite_settings_read_back() {
        let d = TestDir::new();
        let (conn, _) = fresh(&d);
        for &(flag, _, value) in DB_CONFIG {
            assert_eq!(conn.db_config(flag).unwrap(), value);
        }
        for &(limit, name, value) in LIMITS {
            assert_eq!(conn.limit(limit).unwrap(), value, "{name}");
        }
        for (name, _, expect) in int_pragmas() {
            let got: i64 = conn.pragma_query_value(None, name, |r| r.get(0)).unwrap();
            assert_eq!(got, expect, "{name}");
        }
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
        let pages: i64 = conn
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .unwrap();
        assert_eq!(pages, 524_288);
    }

    #[test]
    fn sqlite_open_does_not_create() {
        let d = TestDir::new();
        let p = d.join("absent.qvault");
        assert!(open_connection(&p).is_err());
        assert!(!p.exists());
    }

    #[test]
    fn sqlite_hardening_failures_abort() {
        let d = TestDir::new();
        let p = d.join("t.qvault");
        write_file(&p, b"", 0o600);
        for name in [
            "defensive",
            "enable_trigger",
            "worker_threads",
            "attached",
            "secure_delete",
            "temp_store",
            "max_page_count",
            "journal_mode",
        ] {
            FAIL_SETTING.with(|f| f.set(Some(name)));
            let conn = open_connection(&p).unwrap();
            assert_eq!(
                harden(&conn, &StepBudget::new()),
                Err(StoreError::Hardening),
                "{name}"
            );
        }
        FAIL_SETTING.with(|f| f.set(None));
        let conn = open_connection(&p).unwrap();
        assert_eq!(harden(&conn, &StepBudget::new()), Ok(()));
    }

    #[test]
    fn sqlite_defensive_protects_schema() {
        let d = TestDir::new();
        let (conn, _) = fresh(&d);
        conn.execute_batch("CREATE TABLE t (x INTEGER) STRICT")
            .unwrap();
        // writable_schema is ignored in defensive mode.
        conn.execute_batch("PRAGMA writable_schema = ON").unwrap();
        let r = conn.execute("UPDATE sqlite_schema SET sql = 'x' WHERE name = 't'", []);
        assert!(r.is_err());
        let sql: String = conn
            .query_row("SELECT sql FROM sqlite_schema WHERE name = 't'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(sql, "CREATE TABLE t (x INTEGER) STRICT");
    }

    #[test]
    fn sqlite_triggers_and_views_do_not_run() {
        let d = TestDir::new();
        let (conn, _) = fresh(&d);
        conn.execute_batch("CREATE TABLE t (x INTEGER); CREATE TABLE log (x INTEGER);")
            .unwrap();
        // SQLite 3.53 stores a trigger with triggers disabled, but never
        // fires it.
        conn.execute_batch(
            "CREATE TRIGGER tr AFTER INSERT ON t BEGIN INSERT INTO log VALUES (1); END",
        )
        .unwrap();
        conn.execute("INSERT INTO t VALUES (1)", []).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM log", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 0);
        // A view is stored too, but any use of it is refused.
        conn.execute_batch("CREATE VIEW v AS SELECT x FROM t")
            .unwrap();
        assert!(
            conn.query_row("SELECT count(*) FROM v", [], |r| r.get::<_, i64>(0))
                .is_err()
        );
    }

    #[test]
    fn sqlite_step_budget_interrupts() {
        let d = TestDir::new();
        let (conn, budget) = fresh(&d);
        budget.set_units(10);
        let r = conn.query_row(
            "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c",
            [],
            |r| r.get::<_, i64>(0),
        );
        assert_eq!(
            r.map_err(|e| sqlite_err(&e)),
            Err(StoreError::LimitExceeded)
        );
        budget.reset();
        let n: i64 = conn.query_row("SELECT 1", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn sqlite_no_attach_extensions_or_json() {
        let d = TestDir::new();
        let (conn, _) = fresh(&d);
        let other = d.join("other.db");
        let attach = format!("ATTACH DATABASE '{}' AS o", other.display());
        assert!(conn.execute_batch(&attach).is_err());
        assert!(!other.exists());
        assert!(
            conn.query_row("SELECT load_extension('x')", [], |r| r.get::<_, i64>(0))
                .is_err()
        );
        assert!(
            conn.query_row("SELECT json('{}')", [], |r| r.get::<_, String>(0))
                .is_err()
        );
        // Over-long SQL is refused (64 KiB limit).
        let long = format!("SELECT '{}'", "a".repeat(70_000));
        assert!(
            conn.query_row(&long, [], |r| r.get::<_, String>(0))
                .is_err()
        );
    }
}
