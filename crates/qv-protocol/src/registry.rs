// SPDX-License-Identifier: AGPL-3.0-or-later

//! Profiles, features and error codes (0002 §1, 0013 §1.1, §7.2, §11).

use crate::ProtocolError;

/// LAN profiles. Parsing is not negotiation: a driver must require its exact
/// profile and message labels, with no downgrade or previous-key fallback.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanProfile {
    /// Credential-authenticated profile2, ephemeral password/key methods and explicit epochs.
    V2,
    /// X-Wing draft-11, HKDF-SHA-512, MAC/1, XChaCha20-Poly1305 with
    /// per-direction counter nonces, SHA-256 transcripts.
    V1,
}

impl LanProfile {
    /// The wire ID.
    pub const fn id(self) -> u64 {
        match self {
            Self::V1 => 1,
            Self::V2 => 2,
        }
    }

    /// The profile for a received ID; unknown IDs are
    /// [`ProtocolError::Unsupported`].
    pub fn from_id(id: u64) -> Result<Self, ProtocolError> {
        match id {
            1 => Ok(Self::V1),
            2 => Ok(Self::V2),
            _ => Err(ProtocolError::Unsupported),
        }
    }
}

/// Checks a peer's `features` list (0013 §7.2). Every listed feature is
/// required, and v1 knows none, so any entry is
/// [`ProtocolError::Unsupported`]. v1 sends `[]`.
pub fn check_features(features: &[u64]) -> Result<(), ProtocolError> {
    if features.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::Unsupported)
    }
}

/// Error codes of `["qv/lan-error/v1", code]` (0013 §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum ErrorCode {
    /// Different vault ID or generation, or a failed link-mode proof.
    VaultMismatch = 1,
    /// Unknown profile or required feature.
    Unsupported = 2,
    /// A 0004 budget would be exceeded.
    Limit = 3,
    /// Manifest, object or reference verification failed.
    Integrity = 4,
    /// User cancel, lock or window close.
    Cancelled = 5,
    /// The vault is locked for writing.
    Busy = 6,
    /// The sender can no longer serve its named state.
    StateChanged = 7,
    /// No unique verified keyslot record for a new device.
    Keyslot = 8,
    /// Unexpected message or field.
    Protocol = 9,
}

impl ErrorCode {
    /// The wire value.
    pub const fn code(self) -> u64 {
        self as u64
    }

    /// A received code; unknown codes are treated as [`ErrorCode::Protocol`].
    pub fn from_wire(code: u64) -> Self {
        match code {
            1 => Self::VaultMismatch,
            2 => Self::Unsupported,
            3 => Self::Limit,
            4 => Self::Integrity,
            5 => Self::Cancelled,
            6 => Self::Busy,
            7 => Self::StateChanged,
            8 => Self::Keyslot,
            _ => Self::Protocol,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_profiles_fail_closed() {
        assert_eq!(LanProfile::from_id(1), Ok(LanProfile::V1));
        assert_eq!(LanProfile::V1.id(), 1);
        assert_eq!(LanProfile::from_id(2), Ok(LanProfile::V2));
        assert_eq!(LanProfile::V2.id(), 2);
        for id in [0, 3, u64::MAX] {
            assert_eq!(LanProfile::from_id(id), Err(ProtocolError::Unsupported));
        }
    }

    #[test]
    fn registry_features_are_required() {
        assert_eq!(check_features(&[]), Ok(()));
        assert_eq!(check_features(&[1]), Err(ProtocolError::Unsupported));
        assert_eq!(check_features(&[0, 7]), Err(ProtocolError::Unsupported));
    }

    #[test]
    fn registry_error_codes_round_trip_and_unknown_is_protocol() {
        for code in 1..=9 {
            assert_eq!(ErrorCode::from_wire(code).code(), code);
        }
        for code in [0, 10, u64::MAX] {
            assert_eq!(ErrorCode::from_wire(code), ErrorCode::Protocol);
        }
        assert_eq!(ProtocolError::Closed.wire_code(), None);
        assert_eq!(ProtocolError::Io.wire_code(), None);
        assert_eq!(ProtocolError::FrameTooLarge.wire_code(), None);
        assert_eq!(
            ProtocolError::Unsupported.wire_code(),
            Some(ErrorCode::Unsupported)
        );
        assert_eq!(
            ProtocolError::UnknownLabel.wire_code(),
            Some(ErrorCode::Protocol)
        );
    }
}
