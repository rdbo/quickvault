// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault cryptography and protected memory.
//!
//! This crate is part of the trusted client (`ARCHITECTURE.md` §3). It depends
//! on no other QuickVault crate and on no frontend. Frontends reach it only
//! through `qv-core`.
//!
//! Memory protection here is best effort (spec 0008 §1). Zeroizing a buffer
//! does not erase copies made before the secret was wrapped, copies the OS
//! wrote to swap or hibernation images, or copies held by other libraries.
//! Locking and process hardening report reduced protection instead of failing
//! silently; callers must surface that status to the user.

mod memory;
mod process;
mod rng;

pub use memory::{MemoryProtection, SecretArray, SecretBytes, memory_protection};
pub use process::{Hardening, ProcessHardening, harden_process};
pub use rng::{RngError, fill_random, random_array};
