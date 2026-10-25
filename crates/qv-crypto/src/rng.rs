// SPDX-License-Identifier: AGPL-3.0-or-later

//! Fail-closed access to the operating system CSPRNG (spec 0002 §7.1).
//!
//! There is no fallback generator: if the OS source fails, the operation that
//! asked for randomness must abort.

use core::fmt;

/// The OS random number generator failed. Carries no detail.
pub struct RngError(());

impl fmt::Debug for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RngError")
    }
}

impl fmt::Display for RngError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operating system random number generator failed")
    }
}

impl std::error::Error for RngError {}

/// Fills `buf` from the OS CSPRNG.
///
/// On failure `buf` is zeroed and an error is returned, so a partially filled
/// buffer is never mistaken for random output.
pub fn fill_random(buf: &mut [u8]) -> Result<(), RngError> {
    fill_from(getrandom::fill, buf)
}

/// Returns `N` random bytes for non-secret values such as nonces, salts and
/// identifiers. Secrets go into [`crate::SecretBytes::random`] or
/// [`crate::SecretArray::random`] instead.
pub fn random_array<const N: usize>() -> Result<[u8; N], RngError> {
    let mut out = [0u8; N];
    fill_random(&mut out)?;
    Ok(out)
}

fn fill_from<E>(
    source: impl FnOnce(&mut [u8]) -> Result<(), E>,
    buf: &mut [u8],
) -> Result<(), RngError> {
    match source(buf) {
        Ok(()) => Ok(()),
        Err(_) => {
            buf.fill(0);
            Err(RngError(()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_outputs_differ() {
        let a = random_array::<32>().unwrap();
        let b = random_array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn rng_empty_buffer_is_ok() {
        fill_random(&mut []).unwrap();
    }

    #[test]
    fn rng_failure_zeroes_buffer() {
        let mut buf = [0xAAu8; 16];
        let result = fill_from(
            |b: &mut [u8]| {
                b[0] = 0x55;
                Err(())
            },
            &mut buf,
        );
        assert!(result.is_err());
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn rng_error_strings_are_fixed() {
        let e = RngError(());
        assert_eq!(format!("{e:?}"), "RngError");
        assert_eq!(
            e.to_string(),
            "operating system random number generator failed"
        );
    }
}
