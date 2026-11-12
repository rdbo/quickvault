// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows OS bindings for QuickVault (plan 0052; spec 0009 §5.1).
//!
//! This is the only workspace crate allowed to use `unsafe`, and only in
//! its Win32 FFI modules, each marked `#![allow(unsafe_code)]`. Every
//! `unsafe` block states why it is sound (`// SAFETY:`), enforced by
//! `clippy::undocumented_unsafe_blocks`. The public API is safe. Everything
//! except [`security`] (pure descriptor parsing, tested everywhere) exists
//! only on Windows.
#![deny(unsafe_code)]

pub mod security;

#[cfg(windows)]
pub mod clipboard;
#[cfg(windows)]
pub mod console;
#[cfg(windows)]
pub mod dialog;
#[cfg(windows)]
pub mod fs;
#[cfg(windows)]
pub mod session;
#[cfg(windows)]
pub mod sync;
