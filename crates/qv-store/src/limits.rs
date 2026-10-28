// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault-file budgets (spec 0004 §4.1). Development values where the spec
//! gives none; the 1.16 format freeze records the final ones.

use crate::object::ENVELOPE_OVERHEAD;

/// Largest vault file accepted before SQLite parses it: the 1 GiB
/// referenced-ciphertext budget plus room for history, manifests and
/// objects awaiting pruning. Development value.
pub const MAX_DB_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The only accepted SQLite page size.
pub const PAGE_SIZE: u64 = 4096;

/// Most bytes of header and local keyslot metadata together (0004 §4.1).
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Most local keyslots (0004 §4.1).
pub const MAX_SLOTS: usize = 64;

/// Largest padded record ciphertext (0004 §4.1).
pub const MAX_RECORD_CIPHERTEXT: usize = 1024 * 1024;

/// Largest manifest ciphertext (0004 §4.1).
pub const MAX_MANIFEST_CIPHERTEXT: usize = 64 * 1024 * 1024;

/// Most record IDs in a manifest, tombstones included (0004 §4.1).
pub const MAX_RECORDS: usize = 50_000;

/// Most referenced objects in a manifest (0004 §4.1).
pub const MAX_OBJECTS: usize = 250_000;

/// Most referenced ciphertext bytes in total (0004 §4.1).
pub const MAX_TOTAL_CIPHERTEXT: u64 = 1024 * 1024 * 1024;

/// Most clock components across a manifest's heads, history and floors
/// (0004 §4.1, amended by plan 0009).
pub const MAX_CLOCK_COMPONENTS: usize = 1 << 20;

/// Most chunks of one attachment: 10 MiB in 64 KiB chunks (0003 §6).
pub const MAX_CHUNKS: usize = 160;

/// Largest object frame of an archive: one record or chunk envelope at its
/// ciphertext budget (0004 §4.1, §6.1). Development value.
pub const MAX_ARCHIVE_OBJECT_FRAME: usize = MAX_RECORD_CIPHERTEXT + ENVELOPE_OVERHEAD;

/// Largest manifest frame of an archive: a manifest envelope at the manifest
/// ciphertext budget (0004 §4.1, §6.3). Development value.
pub const MAX_ARCHIVE_MANIFEST_FRAME: usize = MAX_MANIFEST_CIPHERTEXT + ENVELOPE_OVERHEAD;

/// Largest sum of referenced ciphertext lengths one archive may claim: the
/// vault's own total budget, so a header is refused before any frame is read
/// (0004 §4.1).
pub const MAX_ARCHIVE_TOTAL_LENGTH: u64 = MAX_TOTAL_CIPHERTEXT;
