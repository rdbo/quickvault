// SPDX-License-Identifier: AGPL-3.0-or-later

//! Foreground Windows clipboard ownership (0008 §3, 0009 §5.1).
//!
//! The UTF-16 copy is staged in a protected buffer and handed to the
//! clipboard with the history/cloud/monitor exclusion formats. Windows
//! cannot confirm that a paste happened, so a sequence change before
//! expiry is reported as [`PlatformError::ClipboardReplaced`], as on
//! Android. Expiry and cancellation clear the clipboard only while it is
//! still ours, zeroing the OS copy first.
use crate::{Cancellation, Clipboard, PlatformError};
use qv_crypto::SecretBytes;
use qv_win::clipboard::{Owner, sequence};
use std::time::{Duration, Instant};

const MAX_VALUE: usize = 256 * 1024;
const POLL: Duration = Duration::from_millis(250);

/// The Win32 clipboard adapter.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinClipboard;

fn utf16le(text: &str) -> Result<SecretBytes, PlatformError> {
    if text.contains('\0') {
        return Err(PlatformError::InvalidInput);
    }
    let units = text.encode_utf16().count();
    let mut out = SecretBytes::zeroed(units * 2);
    for (slot, unit) in out
        .expose_secret_mut()
        .as_chunks_mut::<2>()
        .0
        .iter_mut()
        .zip(text.encode_utf16())
    {
        *slot = unit.to_le_bytes();
    }
    Ok(out)
}

impl Clipboard for WinClipboard {
    fn hold(
        &self,
        value: SecretBytes,
        timeout: Duration,
        cancel: Cancellation,
        progress: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        if value.len() > MAX_VALUE {
            return Err(PlatformError::LimitExceeded);
        }
        let Ok(text) = std::str::from_utf8(value.expose_secret()) else {
            return Err(PlatformError::InvalidInput);
        };
        if !(Duration::from_secs(1)..=Duration::from_secs(300)).contains(&timeout) {
            return Err(PlatformError::InvalidInput);
        }
        if cancel() {
            return Err(PlatformError::Cancelled);
        }
        let staged = utf16le(text)?;
        drop(value);
        let owner = Owner::new().map_err(|_| PlatformError::Unavailable)?;
        let seq = owner
            .set_text(staged.expose_secret())
            .map_err(|_| PlatformError::Unavailable)?;
        drop(staged);
        let end = Instant::now() + timeout;
        let mut last = None;
        let result = loop {
            if cancel() {
                break Err(PlatformError::Cancelled);
            }
            if sequence() != seq {
                // A successor owns it now; never clear theirs.
                return Err(PlatformError::ClipboardReplaced);
            }
            let now = Instant::now();
            if now >= end {
                break Ok(());
            }
            let left = end.saturating_duration_since(now).as_secs() + 1;
            if last != Some(left) {
                if let Err(e) = progress(left) {
                    break Err(e);
                }
                last = Some(left);
            }
            owner.pump(POLL.min(end.saturating_duration_since(now)));
        };
        match owner.clear_if(seq) {
            Ok(true) => result,
            Ok(false) => result.and(Err(PlatformError::ClipboardReplaced)),
            Err(_) => result.and(Err(PlatformError::Io)),
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests intentionally fail loudly on fixture errors.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn secret(bytes: &[u8]) -> SecretBytes {
        SecretBytes::take_from(&mut bytes.to_vec())
    }

    #[test]
    fn clipboard_rejects_invalid_text_size_and_cancellation_before_backend() {
        let hold = |v| {
            WinClipboard.hold(v, Duration::from_secs(1), Arc::new(|| false), &mut |_| {
                Ok(())
            })
        };
        let mut invalid = [0xff];
        assert_eq!(
            hold(SecretBytes::take_from(&mut invalid)),
            Err(PlatformError::InvalidInput)
        );
        assert_eq!(invalid, [0]);
        assert_eq!(
            hold(SecretBytes::zeroed(MAX_VALUE + 1)),
            Err(PlatformError::LimitExceeded)
        );
        assert_eq!(hold(secret(b"a\0b")), Err(PlatformError::InvalidInput));
        assert_eq!(
            WinClipboard.hold(
                SecretBytes::zeroed(1),
                Duration::from_secs(1),
                Arc::new(|| true),
                &mut |_| Ok(())
            ),
            Err(PlatformError::Cancelled)
        );
    }

    #[test]
    fn clipboard_expiry_clears_and_cancellation_reports() {
        let mut ticks = Vec::new();
        WinClipboard
            .hold(
                secret("pässword".as_bytes()),
                Duration::from_secs(1),
                Arc::new(|| false),
                &mut |left| {
                    ticks.push(left);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(ticks.first(), Some(&1));
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let r = WinClipboard.hold(
            secret(b"x"),
            Duration::from_secs(5),
            Arc::new(move || flag.load(Ordering::SeqCst)),
            &mut |_| {
                stop.store(true, Ordering::SeqCst);
                Ok(())
            },
        );
        assert_eq!(r, Err(PlatformError::Cancelled));
    }

    #[test]
    fn utf16_staging_is_little_endian() {
        assert_eq!(utf16le("aé").unwrap().expose_secret(), [0x61, 0, 0xe9, 0]);
    }
}
