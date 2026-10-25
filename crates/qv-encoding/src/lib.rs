// SPDX-License-Identifier: AGPL-3.0-or-later

//! QuickVault bounded deterministic CBOR (spec 0004 §3.1, §4.1; 0002 §7.2).
//!
//! Every QuickVault payload, AAD, HKDF info and transcript uses this one
//! profile of RFC 8949 core deterministic encoding:
//!
//! | Item | Accepted | Rejected |
//! |------|----------|----------|
//! | Head | additional info 0–27, shortest argument | 28–30, 31 (indefinite), longer than needed |
//! | Integers | unsigned and negative, full range | — |
//! | Byte / text strings | definite; text is valid UTF-8 | indefinite, invalid UTF-8 |
//! | Arrays | definite | indefinite |
//! | Maps | definite, integer keys, strictly ascending by encoded key bytes | other keys, duplicates, misordered keys |
//! | Tags | — | all |
//! | Simple values | `false`, `true`, `null` | floats, undefined, every other simple value, stray `break` |
//! | Nesting | at most [`MAX_DEPTH`] containers | deeper |
//! | Top level | exactly one item | trailing bytes |
//!
//! Depth counts containers: a top-level scalar has depth 0 and `[]` has
//! depth 1. Map keys are ordered bytewise by their encodings (RFC 8949
//! §4.2.1), so every unsigned key sorts before every negative key.
//!
//! **Trust boundary.** This crate is a hostile-input parser at the bottom of
//! the dependency graph and depends on no other QuickVault crate.
//! [`Decoder::new`] validates the whole input before any typed read. Every
//! length is checked against the remaining input before use, and validation
//! allocates nothing. Callers still apply their own model budgets (field counts
//! and sizes) and authenticate data before parsing it where a key exists.
//!
//! **Secrets.** Decoded strings borrow from the caller's buffer, so decoding
//! makes no copies. [`RawValue`] and [`Encoder`] buffers are zeroized when
//! dropped, and the encoder wipes its old buffer whenever it grows. These
//! buffers are not page-locked; callers that need locked memory move the
//! output into `qv_crypto::SecretBytes`.
//!
//! The crate does not know record schemas, which keys are optional, or field
//! budgets; those belong to the data model.

mod decode;
mod encode;
mod error;
mod head;
mod raw;
mod validate;

pub use decode::{Decoder, Kind};
pub use encode::{Encoder, MapEncoder, encode_array};
pub use error::{DecodeError, EncodeError};
pub use raw::RawValue;
pub use validate::validate;

/// Maximum container nesting (spec 0004 §4.1).
pub const MAX_DEPTH: usize = 32;
