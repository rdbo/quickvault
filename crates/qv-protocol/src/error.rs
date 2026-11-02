// SPDX-License-Identifier: AGPL-3.0-or-later

//! Redacted protocol errors: no bytes, lengths or offsets.

use core::fmt;

use crate::registry::ErrorCode;

/// Why a frame or message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    /// Clean end of stream before a frame header.
    Closed,
    /// End of stream inside a frame header or body.
    Truncated,
    /// A frame length above the phase bound; nothing was allocated.
    FrameTooLarge,
    /// A frame of length 0.
    EmptyFrame,
    /// Another transport error.
    Io,
    /// Not exactly one canonical CBOR array of the expected shape.
    Malformed,
    /// The first element is not a known wire label.
    UnknownLabel,
    /// A known label that is not expected at this point.
    UnexpectedLabel,
    /// An unknown `lan` profile or a required feature this build lacks.
    Unsupported,
}

impl ProtocolError {
    /// The 0013 §11 code to send once a session is authenticated, or `None`
    /// for transport failures (nothing is sent; the connection just closes).
    pub fn wire_code(self) -> Option<ErrorCode> {
        match self {
            Self::Closed | Self::Truncated | Self::Io => None,
            Self::Unsupported => Some(ErrorCode::Unsupported),
            Self::FrameTooLarge
            | Self::EmptyFrame
            | Self::Malformed
            | Self::UnknownLabel
            | Self::UnexpectedLabel => Some(ErrorCode::Protocol),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Closed => "connection closed",
            Self::Truncated => "connection closed inside a frame",
            Self::FrameTooLarge => "frame exceeds the size limit",
            Self::EmptyFrame => "empty frame",
            Self::Io => "transport error",
            Self::Malformed => "malformed message",
            Self::UnknownLabel => "unknown message label",
            Self::UnexpectedLabel => "unexpected message",
            Self::Unsupported => "unsupported protocol profile or feature",
        })
    }
}

impl std::error::Error for ProtocolError {}
