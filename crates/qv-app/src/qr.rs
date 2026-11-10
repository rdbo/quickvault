// SPDX-License-Identifier: AGPL-3.0-or-later

//! Binary LAN QR graphics and bounded camera luminance decoding (plan 0039).
//! Library scratch, camera, JVM and renderer copies have best-effort cleanup;
//! protected application buffers and exposed decoder pixel/payload buffers wipe.
use crate::controller::AppError;
use crate::workspace::protect;
use qrcodegen_no_heap::{QrCode, QrCodeEcc, Version};
use qv_core::SecretBytes;
use zeroize::{Zeroize, Zeroizing};

/// Largest binary payload (0013 §4.2 / §8.5).
pub const MAX_PAYLOAD: usize = 1024;
/// Camera/decoder axis bound, before library allocation.
pub const MAX_AXIS: usize = 1024;
/// Camera/decoder pixel bound, before library allocation.
pub const MAX_PIXELS: usize = 786_432;

/// The form a scan fills. A code with endpoints starts its action at once;
/// one without asks for the address (0014 §6.2–§6.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QrTarget {
    /// Locked-screen new-device join.
    NewDevice,
    /// One sync of this unlocked vault (Devices screen).
    Sync,
}
pub(crate) struct Scan {
    pub(crate) cancel: qv_core::CancelToken,
}

/// Whether the native camera path is available and its platform gate is open.
pub fn camera_available() -> bool {
    #[cfg(all(feature = "desktop", target_os = "android"))]
    {
        crate::android::qr_available()
    }
    #[cfg(not(all(feature = "desktop", target_os = "android")))]
    {
        false
    }
}
pub(crate) fn capture(cancel: &qv_core::CancelToken) -> Result<SecretBytes, AppError> {
    #[cfg(all(feature = "desktop", target_os = "android"))]
    {
        crate::android::capture_qr(cancel)
    }
    #[cfg(not(all(feature = "desktop", target_os = "android")))]
    {
        let _ = cancel;
        Err(AppError::Unavailable)
    }
}

/// A QR symbol without its four-module quiet zone. No secret-bearing Debug.
pub struct Symbol {
    size: usize,
    modules: SecretBytes,
}
impl core::fmt::Debug for Symbol {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Symbol(<redacted>)")
    }
}
impl Symbol {
    /// Width and height in modules (at most 177).
    pub fn size(&self) -> usize {
        self.size
    }
    /// Whether a module is black. Out-of-bounds coordinates are white.
    pub fn black(&self, x: usize, y: usize) -> bool {
        x < self.size && y < self.size && self.modules.expose_secret()[y * self.size + x] != 0
    }
    /// A protected short-lived renderer copy.
    pub(crate) fn copy(&self) -> Result<Self, AppError> {
        Ok(Self {
            size: self.size,
            modules: protect(self.modules.expose_secret())?,
        })
    }
    /// Strictly generated SVG path data, never raw HTML or untrusted text.
    pub fn path(&self) -> Zeroizing<String> {
        use std::fmt::Write;
        let mut out = Zeroizing::new(String::with_capacity(self.size * self.size * 20));
        for y in 0..self.size {
            for x in 0..self.size {
                if self.black(x, y) {
                    let _ = write!(out, "M{},{}h1v1h-1z", x + 4, y + 4);
                }
            }
        }
        out
    }
}

/// Encode exact binary bytes, using caller-owned protected encoder scratch.
pub fn encode(payload: &[u8]) -> Result<Symbol, AppError> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD {
        return Err(AppError::InvalidInput);
    }
    let mut scratch = SecretBytes::zeroed(Version::MAX.buffer_len());
    let mut output = SecretBytes::zeroed(Version::MAX.buffer_len());
    scratch.expose_secret_mut()[..payload.len()].copy_from_slice(payload);
    let qr = QrCode::encode_binary(
        scratch.expose_secret_mut(),
        payload.len(),
        output.expose_secret_mut(),
        QrCodeEcc::Medium,
        Version::MIN,
        Version::MAX,
        None,
        true,
    )
    .map_err(|_| AppError::InvalidInput)?;
    let size = usize::try_from(qr.size()).map_err(|_| AppError::InvalidInput)?;
    let mut modules = SecretBytes::zeroed(size * size);
    for y in 0..size {
        for x in 0..size {
            modules.expose_secret_mut()[y * size + x] = u8::from(qr.get_module(x as i32, y as i32));
        }
    }
    Ok(Symbol { size, modules })
}

struct Decoder(quircs::Quirc);
impl Drop for Decoder {
    fn drop(&mut self) {
        self.0.pixels.zeroize();
        self.0.reset();
    }
}
struct Code(quircs::Code);
impl Drop for Code {
    fn drop(&mut self) {
        self.0.cell_bitmap.zeroize();
    }
}

/// Decode one byte-mode QR from tightly packed grayscale. No QR returns None;
/// ambiguous grids, unsupported modes and oversized/dimension-invalid input fail.
/// The caller validates the resulting payload with qv-core before using it.
pub fn decode(width: usize, height: usize, pixels: &[u8]) -> Result<Option<SecretBytes>, AppError> {
    if width == 0
        || height == 0
        || width > MAX_AXIS
        || height > MAX_AXIS
        || width.checked_mul(height) != Some(pixels.len())
        || pixels.len() > MAX_PIXELS
    {
        return Err(AppError::InvalidInput);
    }
    let mut decoder = Decoder(quircs::Quirc::default());
    let mut found = decoder.0.identify(width, height, pixels);
    let Some(code) = found.next() else {
        return Ok(None);
    };
    let code = Code(code.map_err(|_| AppError::InvalidInput)?);
    if let Some(extra) = found.next() {
        if let Ok(mut extra) = extra {
            extra.cell_bitmap.zeroize();
        }
        return Err(AppError::InvalidInput);
    }
    let mut data = match code.0.decode() {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };
    let payload = Zeroizing::new(std::mem::take(&mut data.payload));
    if payload.len() > MAX_PAYLOAD
        || data.data_type != Some(quircs::DataType::Byte)
        || data.eci.is_some()
    {
        return Err(AppError::InvalidInput);
    }
    Ok(Some(protect(&payload)?))
}

/// Decode a bounded in-process camera frame (little-endian width/height + Y).
pub fn decode_frame(frame: &[u8]) -> Result<Option<SecretBytes>, AppError> {
    if frame.len() < 8 || frame.len() > MAX_PIXELS + 8 {
        return Err(AppError::InvalidInput);
    }
    let width =
        u32::from_le_bytes(frame[..4].try_into().map_err(|_| AppError::InvalidInput)?) as usize;
    let height =
        u32::from_le_bytes(frame[4..8].try_into().map_err(|_| AppError::InvalidInput)?) as usize;
    decode(width, height, &frame[8..])
}

/// One camera frame of a running scan (0014 §6.6): the decoded payload, or
/// `None` to skip the frame and keep scanning. A frame without a readable
/// code, with several codes or with a code that is not a binary payload is
/// skipped; the caller validates a decoded payload and ends the scan on a
/// foreign or hostile one. Only the Android camera adapter scans.
#[cfg(any(test, all(feature = "desktop", target_os = "android")))]
pub(crate) fn scan_frame(frame: &[u8]) -> Option<SecretBytes> {
    decode_frame(frame).ok().flatten()
}

#[cfg(test)]
pub(crate) const TEST_PAIR: &[u8] = b"\x85\x71qv/lan-pair-qr/v2\x02\x50synthetic-secret\x80\x60";
/// [`TEST_PAIR`] with the endpoint hint 198.51.100.7:7777 (TEST-NET-2).
#[cfg(test)]
pub(crate) const TEST_PAIR_ADDR: &[u8] =
    b"\x85\x71qv/lan-pair-qr/v2\x02\x50synthetic-secret\x81\x82\x44\xc6\x33\x64\x07\x19\x1e\x61\x60";
/// The retired address-only QR (0014): refused like any foreign code.
#[cfg(test)]
pub(crate) const TEST_ADDR: &[u8] =
    b"\x83\x71qv/lan-addr-qr/v1\x01\x81\x82\x44\xc0\x00\x02\x0a\x19\x1e\x61";

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn image(s: &Symbol, scale: usize, rotate: bool) -> (usize, Zeroizing<Vec<u8>>) {
        let w = (s.size() + 8) * scale;
        let mut p = Zeroizing::new(vec![255; w * w]);
        for y in 0..w {
            for x in 0..w {
                let (xx, yy) = if rotate { (y, w - 1 - x) } else { (x, y) };
                let (mx, my) = (xx / scale, yy / scale);
                if mx >= 4 && my >= 4 && s.black(mx - 4, my - 4) {
                    p[y * w + x] = 0;
                }
            }
        }
        (w, p)
    }
    #[test]
    fn qr_binary_round_trip_rotated_and_scaled_and_redacted() {
        for payload in [TEST_PAIR, TEST_PAIR_ADDR] {
            let symbol = encode(payload).unwrap();
            assert_eq!(format!("{symbol:?}"), "Symbol(<redacted>)");
            for (scale, rotate) in [(3, false), (4, true)] {
                let (w, p) = image(&symbol, scale, rotate);
                assert_eq!(decode(w, w, &p).unwrap().unwrap().expose_secret(), payload);
                let mut frame = Zeroizing::new(Vec::new());
                frame.extend_from_slice(&(w as u32).to_le_bytes());
                frame.extend_from_slice(&(w as u32).to_le_bytes());
                frame.extend_from_slice(&p);
                let decoded = decode_frame(&frame).unwrap().unwrap();
                assert_eq!(decoded.expose_secret(), payload);
                assert!(qv_core::inspect_lan_qr(decoded.expose_secret()).is_ok());
            }
        }
    }
    #[test]
    fn qr_bounds_and_ambiguous_codes_are_refused() {
        assert!(decode_frame(&[0; 7]).is_err());
        assert!(decode_frame(&[255; 8]).is_err());
        assert!(encode(&[0; MAX_PAYLOAD + 1]).is_err());
        assert!(decode(usize::MAX, 2, &[]).is_err());
        assert!(decode(1024, 1024, &[]).is_err());
        assert!(decode(1, 2, &[0]).is_err());
        assert!(decode(64, 64, &[255; 4096]).unwrap().is_none());
        let s = encode(b"synthetic").unwrap();
        let (w, p) = image(&s, 4, false);
        let mut both = Zeroizing::new(vec![255; w * w * 2]);
        for y in 0..w {
            both[y * w * 2..y * w * 2 + w].copy_from_slice(&p[y * w..y * w + w]);
            both[y * w * 2 + w..(y + 1) * w * 2].copy_from_slice(&p[y * w..y * w + w]);
        }
        assert!(decode(w * 2, w, &both).is_err());
        // During a scan such frames are skipped, not fatal (0014 §6.6).
        let frame = |w: usize, h: usize, pixels: &[u8]| {
            let mut f = Zeroizing::new(Vec::new());
            f.extend_from_slice(&(w as u32).to_le_bytes());
            f.extend_from_slice(&(h as u32).to_le_bytes());
            f.extend_from_slice(pixels);
            f
        };
        assert!(scan_frame(&frame(w * 2, w, &both)).is_none());
        assert!(scan_frame(&frame(64, 64, &[255; 4096])).is_none());
        assert!(scan_frame(&[0; 7]).is_none());
        assert_eq!(
            scan_frame(&frame(w, w, &p)).unwrap().expose_secret(),
            b"synthetic"
        );
    }
    #[test]
    fn qr_non_byte_mode_is_refused() {
        // A numeric-mode symbol decodes cleanly but is not a binary payload.
        let mut scratch = vec![0; Version::MAX.buffer_len()];
        let mut output = vec![0; Version::MAX.buffer_len()];
        let qr = QrCode::encode_text(
            "0123456789",
            &mut scratch,
            &mut output,
            QrCodeEcc::Medium,
            Version::MIN,
            Version::MAX,
            None,
            true,
        )
        .unwrap();
        let size = usize::try_from(qr.size()).unwrap();
        let mut modules = SecretBytes::zeroed(size * size);
        for y in 0..size {
            for x in 0..size {
                modules.expose_secret_mut()[y * size + x] =
                    u8::from(qr.get_module(x as i32, y as i32));
            }
        }
        let (w, p) = image(&Symbol { size, modules }, 4, false);
        assert!(decode(w, w, &p).is_err());
    }
}
