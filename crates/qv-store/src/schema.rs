// SPDX-License-Identifier: AGPL-3.0-or-later

//! The vault schema and its validation (spec 0004 §1.2, §2, §4.1).
//!
//! Development schema (phase 1.7 adds its tables and bumps
//! [`SCHEMA_VERSION`]):
//!
//! ```sql
//! CREATE TABLE header (id INTEGER PRIMARY KEY CHECK (id = 1), body BLOB NOT NULL, mac BLOB NOT NULL) STRICT
//! CREATE TABLE keyslot (slot_id BLOB PRIMARY KEY CHECK (length(slot_id) = 16), type INTEGER NOT NULL, body BLOB NOT NULL) STRICT, WITHOUT ROWID
//! ```
//!
//! [`validate`] runs after hardening and before anything else reads vault
//! tables: application ID ([`StoreError::NotAVault`]), schema version
//! ([`StoreError::Unsupported`]), page size, `quick_check(1)` (bounded by
//! the file-size cap, `max_page_count` and the step budget), then the exact
//! `sqlite_schema` rows: these two tables with byte-identical SQL and
//! nothing else (no index, trigger, view, extra table or sequence). The rows
//! are then checked independently of the SQL constraints, with types and
//! lengths read before any value (0004 §2): exactly one header row with
//! `id = 1` and a 32-byte MAC, at most [`MAX_SLOTS`] slots with 16-byte IDs,
//! and at most [`MAX_HEADER_BYTES`] for the header body plus every slot ID
//! and body.

use rusqlite::{Connection, ErrorCode, Transaction};

use crate::error::StoreError;
use crate::header::FORMAT;
use crate::limits::{MAX_HEADER_BYTES, MAX_SLOTS, PAGE_SIZE};

/// `PRAGMA application_id` of a vault: "QVLT".
pub(crate) const APPLICATION_ID: i64 = 0x5156_4C54;

/// `PRAGMA user_version` of the development schema.
pub(crate) const SCHEMA_VERSION: i64 = FORMAT as i64;

const HEADER_DDL: &str = "CREATE TABLE header (id INTEGER PRIMARY KEY CHECK (id = 1), body BLOB NOT NULL, mac BLOB NOT NULL) STRICT";
const KEYSLOT_DDL: &str = "CREATE TABLE keyslot (slot_id BLOB PRIMARY KEY CHECK (length(slot_id) = 16), type INTEGER NOT NULL, body BLOB NOT NULL) STRICT, WITHOUT ROWID";

/// The exact `sqlite_schema` rows, sorted by name.
const EXPECTED: [(&str, &str, &str, &str); 2] = [
    ("table", "header", "header", HEADER_DDL),
    ("table", "keyslot", "keyslot", KEYSLOT_DDL),
];

/// One stored keyslot row.
pub(crate) struct StoredSlot {
    pub(crate) slot_id: [u8; 16],
    pub(crate) kind: u64,
    pub(crate) body: Vec<u8>,
}

/// The validated contents of the header and keyslot tables, slots sorted
/// by slot ID.
pub(crate) struct StoredRows {
    pub(crate) header_body: Vec<u8>,
    pub(crate) header_mac: [u8; 32],
    pub(crate) slots: Vec<StoredSlot>,
}

/// Maps errors while validating an untrusted file: anything that is not an
/// operational failure means the file is not what it should be.
pub(crate) fn validation_err(e: &rusqlite::Error) -> StoreError {
    match e.sqlite_error_code() {
        Some(ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked) => StoreError::Locked,
        Some(ErrorCode::OperationInterrupted | ErrorCode::TooBig) => StoreError::LimitExceeded,
        Some(
            ErrorCode::SystemIoFailure
            | ErrorCode::OutOfMemory
            | ErrorCode::CannotOpen
            | ErrorCode::DiskFull
            | ErrorCode::PermissionDenied
            | ErrorCode::ReadOnly,
        ) => StoreError::Io,
        _ => StoreError::Integrity,
    }
}

fn v(e: rusqlite::Error) -> StoreError {
    validation_err(&e)
}

/// Writes the schema version, application ID and tables of a new vault.
pub(crate) fn install(tx: &Transaction<'_>) -> Result<(), StoreError> {
    tx.pragma_update(None, "application_id", APPLICATION_ID)
        .map_err(v)?;
    tx.pragma_update(None, "user_version", SCHEMA_VERSION)
        .map_err(v)?;
    tx.execute_batch(HEADER_DDL).map_err(v)?;
    tx.execute_batch(KEYSLOT_DDL).map_err(v)?;
    Ok(())
}

fn pragma_i64(conn: &Connection, name: &str) -> Result<i64, StoreError> {
    conn.pragma_query_value(None, name, |r| r.get(0)).map_err(v)
}

/// Checks the file format, integrity and exact schema; no vault table is
/// read before this succeeds.
pub(crate) fn validate_schema(conn: &Connection) -> Result<(), StoreError> {
    if pragma_i64(conn, "application_id")? != APPLICATION_ID {
        return Err(StoreError::NotAVault);
    }
    if pragma_i64(conn, "user_version")? != SCHEMA_VERSION {
        return Err(StoreError::Unsupported);
    }
    if u64::try_from(pragma_i64(conn, "page_size")?).ok() != Some(PAGE_SIZE) {
        return Err(StoreError::Integrity);
    }
    {
        let mut stmt = conn.prepare("PRAGMA quick_check(1)").map_err(v)?;
        let mut rows = stmt.query([]).map_err(v)?;
        let first: Option<String> = match rows.next().map_err(v)? {
            Some(r) => Some(r.get(0).map_err(v)?),
            None => None,
        };
        if first.as_deref() != Some("ok") || rows.next().map_err(v)?.is_some() {
            return Err(StoreError::Integrity);
        }
    }
    let mut stmt = conn
        .prepare("SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY name LIMIT 17")
        .map_err(v)?;
    let found: Vec<(String, String, String, Option<String>)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .map_err(v)?
        .collect::<Result<_, _>>()
        .map_err(v)?;
    let exact = found.len() == EXPECTED.len()
        && found
            .iter()
            .zip(EXPECTED.iter())
            .all(|(f, e)| f.0 == e.0 && f.1 == e.1 && f.2 == e.2 && f.3.as_deref() == Some(e.3));
    if exact {
        Ok(())
    } else {
        Err(StoreError::Integrity)
    }
}

fn usize_len(n: i64) -> Result<usize, StoreError> {
    usize::try_from(n).map_err(|_| StoreError::Integrity)
}

/// Reads the header and keyslot rows with the independent checks. Call
/// only after [`validate_schema`].
pub(crate) fn read_rows(conn: &Connection) -> Result<StoredRows, StoreError> {
    let header_count: i64 = conn
        .query_row("SELECT count(*) FROM header", [], |r| r.get(0))
        .map_err(v)?;
    if header_count != 1 {
        return Err(StoreError::Integrity);
    }
    let (id, body_type, body_len, mac_type, mac_len): (i64, String, i64, String, i64) = conn
        .query_row(
            "SELECT id, typeof(body), octet_length(body), typeof(mac), octet_length(mac) FROM header",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .map_err(v)?;
    if id != 1 || body_type != "blob" || mac_type != "blob" || mac_len != 32 {
        return Err(StoreError::Integrity);
    }
    let mut total = usize_len(body_len)?;
    if total > MAX_HEADER_BYTES {
        return Err(StoreError::LimitExceeded);
    }

    let slot_count: i64 = conn
        .query_row("SELECT count(*) FROM keyslot", [], |r| r.get(0))
        .map_err(v)?;
    if usize_len(slot_count)? > MAX_SLOTS {
        return Err(StoreError::LimitExceeded);
    }
    {
        let mut stmt = conn
            .prepare(
                "SELECT typeof(slot_id), octet_length(slot_id), typeof(type), typeof(body), \
                 octet_length(body) FROM keyslot LIMIT 65",
            )
            .map_err(v)?;
        let mut rows = stmt.query([]).map_err(v)?;
        let mut n = 0usize;
        while let Some(r) = rows.next().map_err(v)? {
            n += 1;
            let (id_type, id_len, kind_type, body_type, body_len): (
                String,
                i64,
                String,
                String,
                i64,
            ) = (
                r.get(0).map_err(v)?,
                r.get(1).map_err(v)?,
                r.get(2).map_err(v)?,
                r.get(3).map_err(v)?,
                r.get(4).map_err(v)?,
            );
            if id_type != "blob" || id_len != 16 || kind_type != "integer" || body_type != "blob" {
                return Err(StoreError::Integrity);
            }
            total = total
                .checked_add(16)
                .and_then(|t| t.checked_add(usize_len(body_len).ok()?))
                .ok_or(StoreError::LimitExceeded)?;
            if total > MAX_HEADER_BYTES {
                return Err(StoreError::LimitExceeded);
            }
        }
        if n > MAX_SLOTS {
            return Err(StoreError::LimitExceeded);
        }
    }

    let (header_body, mac): (Vec<u8>, Vec<u8>) = conn
        .query_row("SELECT body, mac FROM header", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .map_err(v)?;
    let header_mac: [u8; 32] = mac.try_into().map_err(|_| StoreError::Integrity)?;

    let mut stmt = conn
        .prepare("SELECT slot_id, type, body FROM keyslot ORDER BY slot_id LIMIT 65")
        .map_err(v)?;
    let mut rows = stmt.query([]).map_err(v)?;
    let mut slots: Vec<StoredSlot> = Vec::new();
    while let Some(r) = rows.next().map_err(v)? {
        if slots.len() == MAX_SLOTS {
            return Err(StoreError::LimitExceeded);
        }
        let id: Vec<u8> = r.get(0).map_err(v)?;
        let kind: i64 = r.get(1).map_err(v)?;
        let body: Vec<u8> = r.get(2).map_err(v)?;
        let slot_id: [u8; 16] = id.try_into().map_err(|_| StoreError::Integrity)?;
        let kind = u64::try_from(kind).map_err(|_| StoreError::Unsupported)?;
        // Strictly ascending: unique and in MAC order.
        if slots.last().is_some_and(|prev| prev.slot_id >= slot_id) {
            return Err(StoreError::Integrity);
        }
        slots.push(StoredSlot {
            slot_id,
            kind,
            body,
        });
    }
    Ok(StoredRows {
        header_body,
        header_mac,
        slots,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::fs::test_dir::{TestDir, write_file};
    use crate::sqlite::{StepBudget, harden, open_connection};

    /// A hardened connection to a new file with the schema installed.
    pub(crate) fn installed(d: &TestDir, name: &str) -> (Connection, std::path::PathBuf) {
        let p = d.join(name);
        write_file(&p, b"", 0o600);
        let mut conn = open_connection(&p).unwrap();
        harden(&conn, &StepBudget::new()).unwrap();
        conn.pragma_update(None, "page_size", 4096).unwrap();
        let tx = conn.transaction().unwrap();
        install(&tx).unwrap();
        tx.commit().unwrap();
        (conn, p)
    }

    /// Inserts a header row and slots with raw SQL.
    pub(crate) fn fill(conn: &Connection, body: &[u8], slots: &[([u8; 16], i64, Vec<u8>)]) {
        conn.execute(
            "INSERT INTO header (id, body, mac) VALUES (1, ?1, ?2)",
            rusqlite::params![body, [7u8; 32].as_slice()],
        )
        .unwrap();
        for (id, kind, b) in slots {
            conn.execute(
                "INSERT INTO keyslot (slot_id, type, body) VALUES (?1, ?2, ?3)",
                rusqlite::params![id.as_slice(), kind, b],
            )
            .unwrap();
        }
    }

    /// Runs `sql` with the schema writable (tests only: defensive mode off).
    pub(crate) fn tamper(conn: &Connection, sql: &str) {
        use rusqlite::config::DbConfig;
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, false)
            .unwrap();
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_TRIGGER, true)
            .unwrap();
        conn.set_db_config(DbConfig::SQLITE_DBCONFIG_ENABLE_VIEW, true)
            .unwrap();
        conn.set_limit(rusqlite::limits::Limit::SQLITE_LIMIT_SQL_LENGTH, 1_000_000)
            .unwrap();
        conn.execute_batch(sql).unwrap();
    }

    fn check(conn: &Connection) -> Result<StoredRows, StoreError> {
        validate_schema(conn)?;
        read_rows(conn)
    }

    fn id(n: u8) -> [u8; 16] {
        crate::header::tests::v4(n)
    }

    #[test]
    fn schema_valid_vault_reads_back() {
        let d = TestDir::new();
        let (conn, _) = installed(&d, "v.qvault");
        fill(
            &conn,
            &[0xa0],
            &[(id(2), 0, vec![0xa1]), (id(1), 0, vec![0xa2])],
        );
        let rows = check(&conn).unwrap();
        assert_eq!(rows.header_body, vec![0xa0]);
        assert_eq!(rows.header_mac, [7; 32]);
        // Sorted by slot ID, not insertion order.
        assert_eq!(rows.slots.len(), 2);
        assert_eq!(rows.slots[0].slot_id, id(1));
        assert_eq!(rows.slots[1].body, vec![0xa1]);
        // The stored DDL is exactly ours.
        let sql: Vec<String> = conn
            .prepare("SELECT sql FROM sqlite_schema ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(sql, vec![HEADER_DDL.to_owned(), KEYSLOT_DDL.to_owned()]);
    }

    #[test]
    fn schema_tamper_is_rejected() {
        let cases: &[(&str, StoreError)] = &[
            ("CREATE TABLE extra (x)", StoreError::Integrity),
            ("CREATE INDEX i ON keyslot (body)", StoreError::Integrity),
            (
                "CREATE INDEX i ON keyslot (length(body))",
                StoreError::Integrity,
            ),
            (
                "CREATE TRIGGER t AFTER INSERT ON keyslot BEGIN DELETE FROM header; END",
                StoreError::Integrity,
            ),
            (
                "CREATE VIEW w AS SELECT * FROM header",
                StoreError::Integrity,
            ),
            (
                "DROP TABLE header; CREATE TABLE header (id INTEGER PRIMARY KEY, body BLOB NOT NULL, mac BLOB NOT NULL) STRICT",
                StoreError::Integrity,
            ),
            (
                "ALTER TABLE keyslot RENAME COLUMN type TO kind",
                StoreError::Integrity,
            ),
            ("PRAGMA user_version = 1", StoreError::Unsupported),
            ("PRAGMA application_id = 1", StoreError::NotAVault),
            (
                "CREATE TABLE s (x INTEGER PRIMARY KEY AUTOINCREMENT)",
                StoreError::Integrity,
            ),
        ];
        for (sql, expect) in cases {
            let d = TestDir::new();
            let (conn, _) = installed(&d, "v.qvault");
            fill(&conn, &[0xa0], &[(id(1), 0, vec![0xa1])]);
            tamper(&conn, sql);
            assert_eq!(check(&conn).err(), Some(*expect), "{sql}");
        }
    }

    #[test]
    fn schema_page_size_and_foreign_files() {
        // A database with another page size.
        let d = TestDir::new();
        let p = d.join("p.qvault");
        write_file(&p, b"", 0o600);
        let conn = open_connection(&p).unwrap();
        harden(&conn, &StepBudget::new()).unwrap();
        conn.pragma_update(None, "page_size", 8192).unwrap();
        conn.execute_batch(&format!(
            "PRAGMA application_id = {APPLICATION_ID}; PRAGMA user_version = {SCHEMA_VERSION}; {HEADER_DDL}; {KEYSLOT_DDL};"
        ))
        .unwrap();
        assert_eq!(validate_schema(&conn), Err(StoreError::Integrity));

        // A plain SQLite database and a non-database.
        let q = d.join("q.qvault");
        write_file(&q, b"", 0o600);
        let conn = open_connection(&q).unwrap();
        harden(&conn, &StepBudget::new()).unwrap();
        conn.execute_batch("CREATE TABLE t (x)").unwrap();
        assert_eq!(validate_schema(&conn), Err(StoreError::NotAVault));
        let r = d.join("r.qvault");
        write_file(&r, &[0x5a; 8192], 0o600);
        let conn = open_connection(&r).unwrap();
        // Hardening may already notice; either way it never validates.
        let h = harden(&conn, &StepBudget::new()).and_then(|()| validate_schema(&conn));
        assert!(matches!(h, Err(StoreError::Integrity)), "{h:?}");
    }

    #[test]
    fn schema_corrupt_and_truncated_files() {
        let d = TestDir::new();
        let (conn, p) = installed(&d, "v.qvault");
        let big = vec![0x42u8; 3000];
        let slots: Vec<_> = (1..=20).map(|n| (id(n), 0, big.clone())).collect();
        fill(&conn, &[0xa0], &slots);
        drop(conn);
        let good = std::fs::read(&p).unwrap();
        assert!(good.len() >= 4 * 4096);

        // Corrupt the middle of a b-tree page (not page 1).
        let mut bad = good.clone();
        for b in &mut bad[2 * 4096 + 8..2 * 4096 + 64] {
            *b ^= 0xff;
        }
        let c = d.join("c.qvault");
        write_file(&c, &bad, 0o600);
        let conn = open_connection(&c).unwrap();
        let r = harden(&conn, &StepBudget::new()).and_then(|()| check(&conn).map(|_| ()));
        assert_eq!(r, Err(StoreError::Integrity));

        // Truncated to two pages.
        let t = d.join("t.qvault");
        write_file(&t, &good[..2 * 4096], 0o600);
        let conn = open_connection(&t).unwrap();
        // Hardening already reads the file header and may notice first.
        let r = harden(&conn, &StepBudget::new()).and_then(|()| check(&conn).map(|_| ()));
        assert_eq!(r, Err(StoreError::Integrity));
    }

    #[test]
    fn schema_row_checks() {
        let run = |setup: &dyn Fn(&Connection)| {
            let d = TestDir::new();
            let (conn, _) = installed(&d, "v.qvault");
            setup(&conn);
            check(&conn).err()
        };
        // No header row.
        assert_eq!(run(&|_| {}), Some(StoreError::Integrity));
        // A 31-byte MAC.
        assert_eq!(
            run(&|c| {
                c.execute(
                    "INSERT INTO header VALUES (1, x'a0', ?1)",
                    [[0u8; 31].as_slice()],
                )
                .unwrap();
            }),
            Some(StoreError::Integrity)
        );
        // A 15-byte slot ID (the CHECK constraint is bypassed by tampering).
        assert_eq!(
            run(&|c| {
                fill(c, &[0xa0], &[]);
                tamper(
                    c,
                    "PRAGMA ignore_check_constraints = ON; INSERT INTO keyslot VALUES (x'000102030405060708090a0b0c0d0e', 0, x'a0')",
                );
            }),
            Some(StoreError::Integrity)
        );
        // 64 slots pass, 65 do not.
        let many = |n: u8| -> Vec<([u8; 16], i64, Vec<u8>)> {
            (0..n).map(|i| (id(i), 0, vec![0xa0])).collect()
        };
        assert_eq!(run(&|c| fill(c, &[0xa0], &many(64))), None);
        assert_eq!(
            run(&|c| fill(c, &[0xa0], &many(65))),
            Some(StoreError::LimitExceeded)
        );
        // 64 KiB of header and slot bytes pass, one more does not.
        let body = |extra: usize| vec![0x42u8; MAX_HEADER_BYTES - 16 - 1 + extra];
        assert_eq!(run(&|c| fill(c, &[0xa0], &[(id(1), 0, body(0))])), None);
        assert_eq!(
            run(&|c| fill(c, &[0xa0], &[(id(1), 0, body(1))])),
            Some(StoreError::LimitExceeded)
        );
        assert_eq!(
            run(&|c| fill(c, &vec![0xa0; MAX_HEADER_BYTES + 1], &[])),
            Some(StoreError::LimitExceeded)
        );
        // A negative slot type.
        assert_eq!(
            run(&|c| fill(c, &[0xa0], &[(id(1), -1, vec![0xa0])])),
            Some(StoreError::Unsupported)
        );
    }

    #[test]
    fn schema_wrong_value_types() {
        // A crafted file can hold a text slot ID in a STRICT blob column.
        // Build one by editing the stored DDL, inserting, and restoring it.
        let d = TestDir::new();
        let (conn, p) = installed(&d, "v.qvault");
        fill(&conn, &[0xa0], &[]);
        tamper(
            &conn,
            "PRAGMA writable_schema = ON; \
             UPDATE sqlite_schema SET sql = replace(sql, ') STRICT, WITHOUT ROWID', ') WITHOUT ROWID') WHERE name = 'keyslot';",
        );
        drop(conn);
        let conn = Connection::open(&p).unwrap();
        conn.execute_batch("INSERT INTO keyslot VALUES ('abcdefghijklmnop', 0, x'a0')")
            .unwrap();
        tamper(
            &conn,
            "PRAGMA writable_schema = ON; \
             UPDATE sqlite_schema SET sql = replace(sql, ') WITHOUT ROWID', ') STRICT, WITHOUT ROWID') WHERE name = 'keyslot';",
        );
        drop(conn);
        let conn = open_connection(&p).unwrap();
        harden(&conn, &StepBudget::new()).unwrap();
        assert_eq!(check(&conn).err(), Some(StoreError::Integrity));
    }
}
