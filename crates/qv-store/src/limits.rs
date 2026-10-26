// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vault-file budgets (spec 0004 §4.1). Development values where the spec
//! gives none; the 1.16 format freeze records the final ones.

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
