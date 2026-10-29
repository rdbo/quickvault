// SPDX-License-Identifier: AGPL-3.0-or-later

//! The QuickVault vault file (spec 0004 §1–5; 0005 §1.3, §5.1, §5.4).
//!
//! A vault is one SQLite database (`.qvault`) owned by this crate. It is
//! hostile input until authenticated (0004 *Security Considerations*): it is
//! opened only after owner-only file checks, under a process lock, with
//! every hardening setting in 0004 §1.2, a size cap, bounded `quick_check`
//! and exact-schema validation. After the password unlocks VK, the header
//! MAC, the local head MAC, the manifest and every head are verified, and
//! the head is compared with the external anchor. Records live in
//! encrypted immutable objects that cannot be linked to records without the
//! encrypted manifest; every change goes through one mutation transaction.
//!
//! Trust boundary: trusted client code. Frontends reach it only through
//! `qv-core` (`ARCHITECTURE.md` §3).
//!
//! # Modules
//!
//! | Module | Contents | Spec |
//! |--------|----------|------|
//! | `fs` | owner-only checks, symlink rejection, parent-directory rule, sidecar checks, `flock` process lock, file identity, temp file + `RENAME_NOREPLACE` | 0004 §1.1, §1.3; 0008 §5 |
//! | `location` | [`LocationWarnings`] for sync folders, network filesystems, removable media | 0004 §1.1 |
//! | `sqlite` | open flags, `db_config`, pragmas, limits, step budget, all read back | 0004 §1.2, §4.1 |
//! | `schema` | DDL, application ID, schema version, `quick_check`, exact schema, row checks, object rows | 0004 §1.2, §2, §4.1 |
//! | `header` | [`Header`] body codec, header-MAC transcript | 0002 §1.4, §3.3, §7.2 |
//! | `slot` | local password slots (the `qv_model::Keyslot` descriptor) | 0002 §3.2 |
//! | `object` | [`ObjectEnvelope`], record AAD, record encryption | 0004 §2.2, §3.2 |
//! | `manifest` | [`Manifest`]: codec, validation, budgets, digests, encryption, envelope hash | 0004 §3.4–3.5, §4.1–4.2 |
//! | `head` | the local head, its MAC and digest, the head-versus-anchor table ([`AnchorStatus`]) | 0005 §5.4 |
//! | `anchor` | [`AnchorDir`]: anchor files, atomic replacement | 0005 §5.4 |
//! | `archive_verify` / `validation` | Bounded role-aware archive authentication and shared record checks | 0004 §3.6, §6 |
//! | `restore` | New-path snapshot restoration with fresh local baseline and existing creation ordering | 0007 §3.4; 0005 §5.4 |
//! | `archive` | [`ArchiveHeader`], [`ArchiveScope`], framing, the archive writer and reader, [`SnapshotDir`] | 0004 §6; 0007 §3 |
//! | `vault` | [`VaultFile`] (`create`, `open`, `unlock`, `unlock_for_recovery`) and [`UnlockedVault`] (verification, reads) | 0004 §3.6, §5.1, 0002 §8 |
//! | `verify` | [`VerifyCounts`] and the full `verify` pass | 0004 §3.6 |
//! | `write` | [`Write`]: the mutation transaction, counters, `adopt_baseline` | 0004 §1.3, §5.2; 0005 §1.2–1.3 |
//! | `crash` | crash-injection points (active in this crate's tests only) | — |
//! | `unsupported` | the same API failing closed on targets other than Linux/Android | — |
//!
//! # Development format (unstable until phase 1.16)
//!
//! | Item | Value |
//! |------|-------|
//! | `application_id` | `0x5156_4C54` ("QVLT") |
//! | `user_version` and header `format` | `0x7FFF_0002` (schema 2) |
//! | manifest and anchor `format` | `0x7FFF_0001` |
//! | page size | 4096 |
//! | [`MAX_DB_BYTES`] | 2 GiB, checked before SQLite opens the file |
//! | [`MAX_HEADER_BYTES`], [`MAX_SLOTS`] | 64 KiB, 64 (0004 §4.1) |
//! | manifest budgets | [`MAX_MANIFEST_CIPHERTEXT`] 64 MiB, [`MAX_RECORDS`] 50,000, [`MAX_OBJECTS`] 250,000, [`MAX_TOTAL_CIPHERTEXT`] 1 GiB, [`MAX_CLOCK_COMPONENTS`] 2^20, [`MAX_RECORD_CIPHERTEXT`] 1 MiB, [`MAX_CHUNKS`] 160 |
//! | archive magic and version | [`ARCHIVE_MAGIC`] `"QVSNAP\0"`, [`ARCHIVE_FORMAT`] `0x01` |
//! | archive budgets | [`MAX_ARCHIVE_HEADER_BYTES`] 64 KiB, [`MAX_ARCHIVE_MANIFEST_FRAME`], [`MAX_ARCHIVE_OBJECT_FRAME`], [`MAX_ARCHIVE_TOTAL_LENGTH`] |
//! | initial key generation | 1 |
//! | labels | `qv/record/v1`, `qv/manifest/v1`, `qv/config/v1`, `qv/local-head/v1`, `qv/header-mac/v1`, [`ARCHIVE_HEADER_LABEL`] |
//!
//! Tables (all `STRICT`; see `schema`): `header`, `keyslot`, `object`,
//! `manifest`, `local_head`, `replica`. The header MAC is MAC/1 under the
//! `header-mac` purpose key over `["qv/header-mac/v1", header_body,
//! [[slot_id, type, body], …]]`, slots sorted by ID, exact stored bytes. The
//! manifest, head and anchor layouts are in their modules. A worst-case
//! manifest at every budget is 52,391,657 bytes (50.0 MiB sealed), inside
//! the 64 MiB limit (0004 §4.2; test `manifest_worst_case_fits_the_limit`).
//!
//! # Readings of the specs (plans 0008, 0009)
//!
//! - The parent directory must be owned by the user or root and writable by
//!   no one else: no other-write bit (no sticky exception) and no
//!   group-write bit, except Android's per-app `0771` directory with the
//!   app's own UID and GID. Only the parent is checked.
//! - Before SQLite opens the vault, a `-journal` next to it must be
//!   owner-only like the vault, and a `-wal` or `-shm` must not exist:
//!   SQLite rolls them back or replays them before any check runs (plan
//!   0008 review finding 1).
//! - Unsafe permissions on the vault file are refused, never repaired.
//! - Exactly one password slot; unknown slot types are unsupported.
//! - Before the header MAC is verified, a hostile file can cost one fixed
//!   Argon2id run, a SQLite parse bounded by the size cap and limits, and at
//!   most 64 KiB of CBOR decoding.
//! - Writer state (writer ID, next counter) and the anchor's name (a random
//!   replica ID) are in the local-only `replica` row, updated in the same
//!   transaction that uses the counters (0004 §2, plan 0009 D-B). Each DB
//!   has its own anchor, so a restored copy next to the active vault never
//!   shares it (0007 §3.4).
//! - A local edit must dominate every head of its record (0005 §1.2); all
//!   old heads become history unless covered by a retained suppression floor.
//!   Concurrent heads arrive only by sync. History retention targets ten
//!   authenticated versions in deterministic date/ID order, lowering the target
//!   under budgets only when conservative monotonic floor advances permit it.
//! - History purge advances the floor to the join of all current heads without
//!   modifying those heads or creating a synthetic record version/counter.
//!   Floors and reference release use the same transaction/anchor path.
//! - Final tombstones are heads with their own small object. Putting one
//!   drops the record's whole history and advances its floor over every
//!   dropped version, in the same manifest (0007 §2.2, §1.3); the vault
//!   metadata and keyslot records cannot get one.
//! - The manifest types print a redacted `Debug`: they link records to
//!   objects (0004 §2.2).
//! - Exactly one manifest row; the manifest carries the IDs of the three
//!   control records (0003 §2.3).
//! - Unlock fails closed on a missing (`NoAnchor`) or mismatched
//!   (`Rollback`) anchor; `unlock_for_recovery` + `adopt_baseline` is the
//!   explicit recovery, which always creates a new writer ID.
//! - If the anchor update after a durable commit fails, the commit returns
//!   that error and the next write retries the anchor first.
//! - The `local-state` key MACs the head; encrypting sync state with it
//!   comes with sync (milestone 3).
//!
//! Password replacement stages a fresh complete descriptor, encrypted causal
//! keyslot record and header MAC inside the existing write transaction. Commit
//! refuses an unstaged or mismatched descriptor; in-memory slots follow the
//! durable database even if its anchor update fails. The same fixed-profile
//! path can rewrap without changing VK, generation or application objects.
//!
//! Rotation foundation (1.15a): [`RotationJournal`] bounds and authenticates
//! transition metadata with independent old/new generation MACs. Decoding or
//! one verified MAC never authorizes installing a replacement or adopting an
//! anchor. An existing `.qvrotate` sibling blocks ordinary opens, creation,
//! restoration and mutations, including when the active name is absent.
//! No production API publishes that marker yet. Replacement construction,
//! durable restart recovery, snapshot inventory and the CLI remain in 1.15b.
//!
//! # Errors
//!
//! [`StoreError`] carries no data. CLI exit codes (0011 §6):
//! `WrongPassword`/`WrongPhrase` 3, `NotFound` 4, `Locked`/`Replaced`/`Changed` 6,
//! `Integrity`/`Rollback`/`NoAnchor` 7, `LimitExceeded` 9, and 1 for
//! everything else. Only the slot yields `WrongPassword`; a header-MAC
//! failure after password unlock is `Integrity`. Phrase recovery uses the
//! header MAC for initial key confirmation: mismatch is `WrongPhrase` (which
//! can also mean header damage); subsequent state failures remain Integrity.
//! `SQLITE_FULL` is `LimitExceeded` only at
//! the page limit, otherwise `Io` (a full disk).
//!
//! # Not yet implemented
//!
//! Received versions and merges of concurrent heads (2.2); archives that
//! carry a password slot (0004 §6.4, phase 2), archive merge and exchange
//! (2.2); standalone archive recovery using a phrase;
//! rotation (1.15); sync state, outbox and checkpoints (milestones 2–3);
//! quick-unlock slots (2.6); keystore-backed anchors (2.3, 2.6); Windows
//! and macOS file safety (4.1 and later).

#[cfg(any(target_os = "linux", target_os = "android"))]
mod anchor;
mod archive;
mod archive_verify;
mod attachment;
mod crash;
#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod crash_tests;
#[cfg(all(test, any(target_os = "linux", target_os = "android")))]
mod credentials;
mod error;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod fs;
mod head;
mod header;
mod limits;
mod location;
mod manifest;
mod object;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod restore;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod rotation_guard;
mod rotation_journal;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod schema;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod slot;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sqlite;
mod validation;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod vault;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod verify;
#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
mod verify_tests;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod write;
// Other targets get an API that fails closed; on Linux it is compiled only
// for its own tests, so its never-called methods are allowed to be unused.
#[cfg(any(not(any(target_os = "linux", target_os = "android")), test))]
#[cfg_attr(test, allow(dead_code))]
mod unsupported;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub use anchor::{AnchorDir, MAX_ANCHOR_BYTES};
pub use archive::{
    ARCHIVE_DERIVATION_PROFILE, ARCHIVE_EXTENSION, ARCHIVE_FORMAT, ARCHIVE_HEADER_LABEL,
    ARCHIVE_MAC_PROFILE, ARCHIVE_MAGIC, ArchiveHeader, ArchiveObject, ArchiveScope, ArchiveStats,
    MAX_ARCHIVE_HEADER_BYTES, OpenedArchive, read_archive, read_header,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use archive::{PublishedSnapshot, SnapshotDir, SnapshotEntry, SnapshotKind};
pub use attachment::StagedAttachment;
pub use error::StoreError;
pub use head::AnchorStatus;
pub use header::Header;
pub use limits::{
    MAX_ARCHIVE_MANIFEST_FRAME, MAX_ARCHIVE_OBJECT_FRAME, MAX_ARCHIVE_TOTAL_LENGTH, MAX_CHUNKS,
    MAX_CLOCK_COMPONENTS, MAX_DB_BYTES, MAX_HEADER_BYTES, MAX_MANIFEST_CIPHERTEXT, MAX_OBJECTS,
    MAX_RECORD_CIPHERTEXT, MAX_RECORDS, MAX_SLOTS, MAX_TOTAL_CIPHERTEXT, PAGE_SIZE,
};
pub use location::LocationWarnings;
pub use manifest::{MANIFEST_FORMAT, Manifest, ObjectRef, RecordEntry, VersionRef};
pub use object::ObjectEnvelope;
pub use rotation_journal::{
    MAX_ROTATION_JOURNAL_BYTES, RotationJournal, RotationJournalBody, RotationSide,
};
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use unsupported::{
    AnchorDir, MAX_ANCHOR_BYTES, UnlockedVault, VAULT_EXTENSION, VaultFile, VerifyCounts, Write,
};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use vault::{UnlockedVault, VAULT_EXTENSION, VaultFile};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use verify::VerifyCounts;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use write::Write;

#[cfg(test)]
mod tests {
    /// The bundled SQLite is built with `.cargo/config.toml`'s
    /// `LIBSQLITE3_FLAGS` (plan 0008); a build that lost them fails here.
    #[test]
    fn compile_options() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let mut stmt = conn.prepare("PRAGMA compile_options").unwrap();
        let opts: Vec<String> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for absent in [
            "ENABLE_FTS3",
            "ENABLE_FTS5",
            "ENABLE_RTREE",
            "ENABLE_DBSTAT_VTAB",
            "ENABLE_LOAD_EXTENSION",
            "ENABLE_COLUMN_METADATA",
            "SOUNDEX",
            "USE_URI",
        ] {
            assert!(!opts.iter().any(|o| o == absent), "{absent} is enabled");
        }
        for present in [
            "OMIT_LOAD_EXTENSION",
            "OMIT_JSON",
            "TEMP_STORE=3",
            "SECURE_DELETE",
            "DQS=0",
            "DEFAULT_FOREIGN_KEYS",
        ] {
            assert!(
                opts.iter().any(|o| o == present),
                "{present} missing: {opts:?}"
            );
        }
        assert_eq!(rusqlite::version(), "3.53.2");
    }
}
