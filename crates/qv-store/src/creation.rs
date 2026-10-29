// SPDX-License-Identifier: AGPL-3.0-or-later

//! Writing a complete new vault database into an unpublished private file.
//!
//! Restore (0007 §3.4) and the rotation replacement (0002 §3.5.2) share this
//! sequence, so there is one place that opens, hardens and installs the
//! schema of a new database. The caller owns the file's lock and name and
//! publishes nothing here.
use std::path::Path;

use qv_crypto::{VaultKey, mac};
use rusqlite::{Transaction, TransactionBehavior};

use crate::error::{StoreError, sqlite_err, write_err};
use crate::header::Header;
use crate::manifest::SealedManifest;
use crate::schema::{self, StoredHead, StoredReplica};
use crate::slot::LocalSlot;
use crate::sqlite::{StepBudget, harden, open_connection};
use crate::vault::{self, insert_manifest};

/// What the caller's `fill` step adds after the singleton rows: the objects
/// are already inserted; these name the manifest and head that commit to them.
pub(crate) struct Filled {
    pub(crate) manifest: SealedManifest,
    pub(crate) head: StoredHead,
}

/// Writes a database with `header` (MAC'd under `vk` over the single password
/// `slot`), the `replica` row and whatever `fill` inserts, in one
/// transaction, then closes the connection. `fill` inserts the object rows
/// and returns the sealed manifest and the signed head. Cancellation is
/// checked once more before COMMIT.
pub(crate) fn write_database(
    temp: &Path,
    header: &Header,
    vk: &VaultKey,
    slot: &LocalSlot,
    replica: StoredReplica,
    fill: impl FnOnce(&Transaction<'_>) -> Result<Filled, StoreError>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), StoreError> {
    let mut conn = open_connection(temp)?;
    let budget = StepBudget::new();
    harden(&conn, &budget)?;
    conn.pragma_update(None, "page_size", 4096)
        .map_err(|e| sqlite_err(&e))?;
    let body = header.encode()?;
    let (key, transcript) = vault::header_tag(vk, header, &body, &[slot.row()])?;
    let tag = mac(&key, header.mac_profile, &transcript)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| sqlite_err(&e))?;
    schema::install(&tx)?;
    tx.execute(
        "INSERT INTO header (id, body, mac) VALUES (1, ?1, ?2)",
        rusqlite::params![body.as_slice(), tag.as_bytes().as_slice()],
    )
    .map_err(|e| write_err(&tx, &e, 0))?;
    tx.execute(
        "INSERT INTO keyslot (slot_id, type, body) VALUES (?1, ?2, ?3)",
        rusqlite::params![
            slot.slot_id.0.as_slice(),
            i64::try_from(slot.kind).map_err(|_| StoreError::Internal)?,
            slot.body.as_slice()
        ],
    )
    .map_err(|e| write_err(&tx, &e, 0))?;
    tx.execute(
        "INSERT INTO replica (id, replica_id, writer_id, next_counter) VALUES (1, ?1, ?2, ?3)",
        rusqlite::params![
            replica.replica_id.as_slice(),
            replica.writer_id.as_slice(),
            i64::try_from(replica.next_counter).map_err(|_| StoreError::LimitExceeded)?
        ],
    )
    .map_err(|e| write_err(&tx, &e, 0))?;
    let filled = fill(&tx)?;
    insert_manifest(&tx, &filled.manifest)?;
    tx.execute(
        "INSERT INTO local_head (id, body, mac) VALUES (1, ?1, ?2)",
        rusqlite::params![filled.head.body.as_slice(), filled.head.mac.as_slice()],
    )
    .map_err(|e| write_err(&tx, &e, 0))?;
    if cancelled() {
        return Err(StoreError::Io);
    }
    tx.commit().map_err(|e| sqlite_err(&e))?;
    conn.close().map_err(|(_, e)| sqlite_err(&e))?;
    Ok(())
}
