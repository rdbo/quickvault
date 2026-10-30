// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bounded local receipt metadata (0004 §2.3). A decoded set is metadata,
//! never authenticated storage or permission to accept an incoming archive.

use qv_crypto::SecretBytes;
use qv_encoding::{Decoder, Encoder};

use crate::StoreError;

/// Maximum remembered filenames per local replica and generation.
pub const MAX_ARCHIVE_RECEIPTS: usize = 4096;
/// Maximum raw OS bytes in one canonical absolute filename.
pub const MAX_RECEIPT_PATH_BYTES: usize = 4096;
/// Maximum padded receipt ciphertext.
pub const MAX_RECEIPT_CIPHERTEXT: usize = 32 * 1024 * 1024;
/// Maximum complete canonical receipt envelope, checked before allocation.
pub const MAX_RECEIPT_ENVELOPE: usize = MAX_RECEIPT_CIPHERTEXT + 128;

struct Receipt {
    path: SecretBytes,
    digest: [u8; 32],
}

/// Sorted confidential filename/complete-archive SHA-256 metadata.
///
/// This pure type does not normalize/open paths or authenticate archive bytes.
/// Persisting receipts requires the future atomic incoming-acceptance path.
#[derive(Default)]
pub struct ArchiveReceipts {
    rows: Vec<Receipt>,
}

impl core::fmt::Debug for ArchiveReceipts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ArchiveReceipts(<redacted>)")
    }
}

fn malformed<T>(_: T) -> StoreError {
    StoreError::Integrity
}

fn protected_path(path: &[u8]) -> SecretBytes {
    let mut bytes = SecretBytes::zeroed(path.len());
    bytes.expose_secret_mut().copy_from_slice(path);
    bytes
}

fn check_path(path: &[u8]) -> Result<(), StoreError> {
    if path.len() > MAX_RECEIPT_PATH_BYTES {
        return Err(StoreError::LimitExceeded);
    }
    if path.len() < 2 || path[0] != b'/' || path.contains(&0) {
        return Err(StoreError::Integrity);
    }
    if path[1..]
        .split(|&b| b == b'/')
        .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(StoreError::Integrity);
    }
    Ok(())
}

impl ArchiveReceipts {
    /// Empty metadata, with no authority to reset persisted state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of remembered paths.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the metadata contains no paths.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Add an already canonical absolute raw path and a whole-stream digest.
    /// Returns true for a new path, false for identical redelivery. Changed
    /// bytes at an existing path fail without modifying this set, even at cap.
    pub fn remember(&mut self, path: &[u8], digest: [u8; 32]) -> Result<bool, StoreError> {
        check_path(path)?;
        match self
            .rows
            .binary_search_by(|r| r.path.expose_secret().cmp(path))
        {
            Ok(i) => {
                if self.rows[i].digest != digest {
                    return Err(StoreError::Integrity);
                }
                Ok(false)
            }
            Err(i) => {
                if self.rows.len() == MAX_ARCHIVE_RECEIPTS {
                    return Err(StoreError::LimitExceeded);
                }
                self.rows.insert(
                    i,
                    Receipt {
                        path: protected_path(path),
                        digest,
                    },
                );
                Ok(true)
            }
        }
    }

    /// Canonical confidential plaintext, not an authenticated envelope.
    pub fn encode(&self) -> Result<SecretBytes, StoreError> {
        let mut e = Encoder::new();
        e.array(|a| {
            a.uint(1);
            a.array(|rows| {
                for row in &self.rows {
                    rows.array(|r| {
                        r.bytes(row.path.expose_secret());
                        r.bytes(&row.digest);
                        Ok(())
                    })?;
                }
                Ok(())
            })
        })
        .map_err(|_| StoreError::Internal)?;
        let mut bytes = e.finish().map_err(|_| StoreError::Internal)?;
        Ok(SecretBytes::take_from(&mut bytes))
    }

    /// Decode bounded plaintext. Callers handling encrypted storage MUST
    /// authenticate it first. This result alone establishes no authenticity.
    pub fn decode(plaintext: &[u8]) -> Result<Self, StoreError> {
        // Largest possible plaintext under row/path limits, including all CBOR
        // overhead (array2 + version + array4096 + each array2/bstr4096/bstr32).
        const MAX_PLAIN: usize = 5 + MAX_ARCHIVE_RECEIPTS * (1 + 3 + MAX_RECEIPT_PATH_BYTES + 34);
        if plaintext.len() > MAX_PLAIN {
            return Err(StoreError::LimitExceeded);
        }
        let mut d = Decoder::new(plaintext).map_err(malformed)?;
        if d.array().map_err(malformed)? != 2 {
            return Err(StoreError::Integrity);
        }
        if d.uint().map_err(malformed)? != 1 {
            return Err(StoreError::Unsupported);
        }
        let n = usize::try_from(d.array().map_err(malformed)?)
            .map_err(|_| StoreError::LimitExceeded)?;
        if n > MAX_ARCHIVE_RECEIPTS {
            return Err(StoreError::LimitExceeded);
        }
        let mut rows = Vec::<Receipt>::with_capacity(n);
        for _ in 0..n {
            if d.array().map_err(malformed)? != 2 {
                return Err(StoreError::Integrity);
            }
            let path = d.bytes().map_err(malformed)?;
            check_path(path)?;
            if rows.last().is_some_and(|r| r.path.expose_secret() >= path) {
                return Err(StoreError::Integrity);
            }
            let digest = d
                .bytes()
                .map_err(malformed)?
                .try_into()
                .map_err(malformed)?;
            rows.push(Receipt {
                path: protected_path(path),
                digest,
            });
        }
        d.finish().map_err(malformed)?;
        Ok(Self { rows })
    }
}

#[cfg(test)]
#[cfg(any(target_os = "linux", target_os = "android"))]
#[path = "receipt_tests.rs"]
mod tests;
