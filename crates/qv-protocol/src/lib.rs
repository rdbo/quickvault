// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault bounded wire framing and message registry (spec 0013 §1–2, §11).
//!
//! **Trust boundary.** Everything here parses hostile network input. The crate
//! holds no keys and depends on no QuickVault crate except `qv-encoding`, so
//! it can be shared with the future server. Authentication, the key schedule
//! and the record layer live in `qv-crypto`; state machines live in `qv-sync`.
//!
//! - [`frame`]: `u32` big-endian length-prefixed frames, bounded per phase
//!   before anything is allocated, read without read-ahead (0013 §1.3).
//! - [`registry`]: the `lan / 1` profile, the v1 feature set (empty: every
//!   listed feature is required and unknown) and the 0013 §11 error codes.
//!   Unknown profiles and features fail closed.
//! - [`message`]: wire labels with their exact arity, and an exact-shape
//!   reader and writer over canonical CBOR arrays (0013 §1.2).
//!
//! Errors are [`ProtocolError`] variants without data.

pub mod error;
pub mod frame;
pub mod message;
pub mod registry;

pub use error::ProtocolError;
