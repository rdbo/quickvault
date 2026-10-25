// SPDX-License-Identifier: AGPL-3.0-or-later

//! The profile registry (spec 0002 §1).
//!
//! Profile IDs are `u16` values **within a namespace**; each namespace is its
//! own Rust type, so IDs from different namespaces cannot be mixed. An unknown
//! ID fails closed at [`from_id`](PasswordKdfProfile::from_id), before any
//! work is done with it. There is no numeric ordering: a profile satisfies a
//! minimum only if it is that minimum or reachable from it through the
//! namespace's explicit transition registry.

use crate::error::CryptoError;

/// Whether `to` is reachable from `from` through `table` (pairs `(old, new)`).
///
/// Iterative and bounded by `table.len()` steps, so cycles terminate.
fn reachable(table: &[(u16, u16)], from: u16, to: u16) -> bool {
    if from == to {
        return true;
    }
    // Grow the set of reached profiles one round at a time; each round scans
    // the whole table. A simple path has at most table.len() edges, and the
    // set holds at most table.len() + 1 profiles, so a fixed array suffices.
    let mut reached = [0u16; 64];
    let mut count = 1usize;
    reached[0] = from;
    if table.len() >= reached.len() {
        // A registry this large is a programming error; fail closed.
        return false;
    }
    for _ in 0..table.len() {
        let mut grew = false;
        for &(old, new) in table {
            let known = reached[..count].contains(&old);
            if known && !reached[..count].contains(&new) {
                if new == to {
                    return true;
                }
                reached[count] = new;
                count += 1;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    false
}

macro_rules! profiles {
    ($(
        $(#[$doc:meta])*
        $name:ident { $($(#[$vdoc:meta])* $variant:ident = $id:literal),+ $(,)? }
        transitions: [$(($old:literal, $new:literal)),* $(,)?];
    )+) => {$(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        #[non_exhaustive]
        pub enum $name {
            $($(#[$vdoc])* $variant),+
        }

        impl $name {
            /// Allowed transitions `(old, new)`; nothing else is implied.
            const TRANSITIONS: &'static [(u16, u16)] = &[$(($old, $new)),*];

            /// The profile's ID within its namespace.
            pub const fn id(self) -> u16 {
                match self {
                    $(Self::$variant => $id),+
                }
            }

            /// Parses an ID; unknown IDs fail with [`CryptoError::UnknownProfile`].
            pub fn from_id(id: u16) -> Result<Self, CryptoError> {
                match id {
                    $($id => Ok(Self::$variant),)+
                    _ => Err(CryptoError::UnknownProfile),
                }
            }

            /// Whether this profile satisfies `minimum`: it is `minimum` or
            /// is reachable from it in the transition registry.
            pub fn accepts(self, minimum: Self) -> bool {
                reachable(Self::TRANSITIONS, minimum.id(), self.id())
            }
        }
    )+};
}

profiles! {
    /// `password-kdf` namespace: master password → MK.
    PasswordKdfProfile {
        /// Argon2id v1.3, 256 MiB, t=3, p=4, 32-byte output, 32-byte salt.
        V1 = 1,
    }
    transitions: [];

    /// `stored-data` namespace: encryption of records, chunks and manifests.
    StoredDataProfile {
        /// XChaCha20-Poly1305, 24-byte random nonce, Padmé framing.
        V1 = 1,
    }
    transitions: [];

    /// `password-wrap` namespace: wrapping VK under a password KEK.
    PasswordWrapProfile {
        /// XChaCha20-Poly1305 with a 32-byte KEK commitment.
        V1 = 1,
    }
    transitions: [];

    /// `derivation` namespace: purpose and per-object key derivation.
    DerivationProfile {
        /// HKDF-SHA-512 with canonical CBOR info.
        V1 = 1,
    }
    transitions: [];

    /// `MAC` namespace.
    MacProfile {
        /// HMAC-SHA-512 truncated to its first 32 bytes.
        V1 = 1,
    }
    transitions: [];

    /// `object-hash` namespace.
    ObjectHashProfile {
        /// SHA-256.
        V1 = 1,
    }
    transitions: [];
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_ids_fail_closed() {
        for id in [0u16, 2, 3, 0x100, u16::MAX] {
            assert_eq!(
                PasswordKdfProfile::from_id(id),
                Err(CryptoError::UnknownProfile)
            );
            assert_eq!(
                StoredDataProfile::from_id(id),
                Err(CryptoError::UnknownProfile)
            );
            assert_eq!(
                PasswordWrapProfile::from_id(id),
                Err(CryptoError::UnknownProfile)
            );
            assert_eq!(
                DerivationProfile::from_id(id),
                Err(CryptoError::UnknownProfile)
            );
            assert_eq!(MacProfile::from_id(id), Err(CryptoError::UnknownProfile));
            assert_eq!(
                ObjectHashProfile::from_id(id),
                Err(CryptoError::UnknownProfile)
            );
        }
    }

    #[test]
    fn profile_ids_round_trip() {
        assert_eq!(PasswordKdfProfile::from_id(1), Ok(PasswordKdfProfile::V1));
        assert_eq!(StoredDataProfile::from_id(1), Ok(StoredDataProfile::V1));
        assert_eq!(PasswordWrapProfile::from_id(1), Ok(PasswordWrapProfile::V1));
        assert_eq!(DerivationProfile::from_id(1), Ok(DerivationProfile::V1));
        assert_eq!(MacProfile::from_id(1), Ok(MacProfile::V1));
        assert_eq!(ObjectHashProfile::from_id(1), Ok(ObjectHashProfile::V1));
        assert_eq!(PasswordKdfProfile::V1.id(), 1);
        assert_eq!(StoredDataProfile::V1.id(), 1);
        assert_eq!(PasswordWrapProfile::V1.id(), 1);
        assert_eq!(DerivationProfile::V1.id(), 1);
        assert_eq!(MacProfile::V1.id(), 1);
        assert_eq!(ObjectHashProfile::V1.id(), 1);
    }

    #[test]
    fn profile_v1_accepts_itself_only() {
        assert!(PasswordKdfProfile::V1.accepts(PasswordKdfProfile::V1));
        assert!(StoredDataProfile::V1.accepts(StoredDataProfile::V1));
        assert!(MacProfile::V1.accepts(MacProfile::V1));
    }

    #[test]
    fn profile_transitions_are_explicit_not_numeric() {
        let table = [(1, 3), (3, 2)];
        assert!(reachable(&table, 1, 3));
        assert!(reachable(&table, 1, 2)); // 1 → 3 → 2
        assert!(reachable(&table, 3, 2));
        assert!(!reachable(&table, 2, 1));
        assert!(!reachable(&table, 3, 1));
        assert!(!reachable(&table, 2, 3)); // 3 > 2 numerically, not listed
        assert!(!reachable(&table, 1, 4));
        assert!(reachable(&table, 7, 7)); // no self-pair needed
        assert!(!reachable(&[], 1, 2));
    }

    #[test]
    fn profile_transition_cycles_and_branches_terminate() {
        let cycle = [(1, 2), (2, 3), (3, 1)];
        assert!(reachable(&cycle, 1, 3));
        assert!(!reachable(&cycle, 1, 9));
        // Branching: 1 → 5, 1 → 2 → 4; the target is only on the second branch.
        let branches = [(2, 4), (1, 5), (1, 2)];
        assert!(reachable(&branches, 1, 4));
        assert!(!reachable(&branches, 5, 4));
    }

    #[test]
    fn profile_oversized_registry_fails_closed() {
        let big: Vec<(u16, u16)> = (0..64).map(|i| (i, i + 1)).collect();
        assert!(!reachable(&big, 0, 1));
    }
}
