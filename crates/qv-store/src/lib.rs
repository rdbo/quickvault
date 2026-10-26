// SPDX-License-Identifier: AGPL-3.0-or-later

//! The QuickVault vault file (spec 0004 §1–2, §4, §5.1).
//!
//! A vault is one SQLite database (`.qvault`) owned by this crate. It is
//! hostile input until authenticated (0004 *Security Considerations*): it is
//! opened only after owner-only file checks, under a process lock, with
//! every hardening setting in 0004 §1.2, a size cap, bounded `quick_check`
//! and exact-schema validation. The header and local keyslots are then
//! authenticated by the header MAC after the password unlocks VK.
//!
//! Trust boundary: trusted client code. Frontends reach it only through
//! `qv-core` (`ARCHITECTURE.md` §3).
//!
//! # Modules
//!
//! | Module | Contents | Spec |
//! |--------|----------|------|
//! | `fs` | owner-only checks, symlink rejection, parent-directory rule, `flock` process lock, file identity, temp file + `RENAME_NOREPLACE` | 0004 §1.1, §1.3; 0008 §5 |
//! | `location` | [`LocationWarnings`] for sync folders, network filesystems, removable media | 0004 §1.1 |
//! | `sqlite` | open flags, `db_config`, pragmas, limits, step budget, all read back | 0004 §1.2, §4.1 |
//! | `schema` | DDL, application ID, schema version, `quick_check`, exact schema, row checks | 0004 §1.2, §2, §4.1 |
//! | `header` | [`Header`] body codec, header-MAC transcript | 0002 §1.4, §3.3, §7.2 |
//! | `slot` | local password slots (the `qv_model::Keyslot` descriptor) | 0002 §3.2 |
//! | `vault` | [`VaultFile`] (`create`, `open`, `unlock`) and [`UnlockedVault`] | 0004 §5.1, 0002 §8 |
//! | `unsupported` | the same API failing closed on targets other than Linux/Android | — |
//!
//! # Development format (unstable until phase 1.16)
//!
//! | Item | Value |
//! |------|-------|
//! | `application_id` | `0x5156_4C54` ("QVLT") |
//! | `user_version` and header `format` | `0x7FFF_0001` |
//! | page size | 4096 |
//! | [`MAX_DB_BYTES`] | 2 GiB, checked before SQLite opens the file |
//! | [`MAX_HEADER_BYTES`], [`MAX_SLOTS`] | 64 KiB, 64 (0004 §4.1) |
//! | initial key generation | 1 |
//!
//! Tables: `header (id = 1, body, mac)` and `keyslot (slot_id, type, body)`,
//! both `STRICT`; phase 1.7 adds the object, manifest and local-head tables.
//! The header body is a canonical CBOR map (see `header`; unknown keys fail
//! closed). A password slot (type 0) stores the canonical
//! `qv_model::Keyslot` descriptor. The header MAC is MAC/1 under the
//! `header-mac` purpose key over `["qv/header-mac/v1", header_body,
//! [[slot_id, type, body], …]]`, slots sorted by ID, exact stored bytes.
//!
//! # Readings of the specs (plan 0008)
//!
//! - The parent directory must be owned by the user or root, not
//!   other-writable unless sticky, and group-writable only for the user's
//!   effective group. Only the parent is checked.
//! - Unsafe permissions on the vault file are refused, never repaired.
//! - Exactly one password slot; unknown slot types are unsupported.
//! - Before the header MAC is verified, a hostile file can cost one fixed
//!   Argon2id run, a SQLite parse bounded by the size cap and limits, and at
//!   most 64 KiB of CBOR decoding.
//!
//! # Errors
//!
//! [`StoreError`] carries no data. CLI exit codes (0011 §6):
//! `WrongPassword` 3, `NotFound` 4, `Locked`/`Replaced` 6, `Integrity` 7,
//! `LimitExceeded` 9, everything else 1. Only the slot yields
//! `WrongPassword`; a header-MAC failure is always `Integrity`.
//!
//! # Not in this phase
//!
//! Records, objects, manifests, the local head, the external anchor, writer
//! state and the mutation transaction (phase 1.7); quick-unlock slots
//! (2.6); Windows and macOS file safety (4.1 and later).

mod error;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod fs;
mod header;
mod limits;
mod location;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod schema;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod slot;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod sqlite;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod vault;
// Other targets get an API that fails closed; on Linux it is compiled only
// for its own tests, so its never-called methods are allowed to be unused.
#[cfg(any(not(any(target_os = "linux", target_os = "android")), test))]
#[cfg_attr(test, allow(dead_code))]
mod unsupported;

pub use error::StoreError;
pub use header::Header;
pub use limits::{MAX_DB_BYTES, MAX_HEADER_BYTES, MAX_SLOTS, PAGE_SIZE};
pub use location::LocationWarnings;
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub use unsupported::{UnlockedVault, VAULT_EXTENSION, VaultFile};
#[cfg(any(target_os = "linux", target_os = "android"))]
pub use vault::{UnlockedVault, VAULT_EXTENSION, VaultFile};

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
