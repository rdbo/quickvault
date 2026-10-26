// SPDX-License-Identifier: AGPL-3.0-or-later

//! Timestamps: display information only (spec 0005 §1.5).

/// Milliseconds since the Unix epoch (UTC). Never used for causality,
/// conflict handling or merge order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(pub i64);
