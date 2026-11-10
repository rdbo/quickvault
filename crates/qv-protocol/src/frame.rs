// SPDX-License-Identifier: AGPL-3.0-or-later

//! Length-prefixed frames (0013 §1.3): a `u32` big-endian length, then that
//! many body bytes. The length is checked against the phase bound before any
//! allocation, and a reader never consumes more than one frame.

use std::io::{ErrorKind, Read, Write};

use crate::ProtocolError;

/// Largest frame body before the session keys exist.
pub const HANDSHAKE_FRAME_MAX: usize = 4096;
/// Largest encrypted credential/Finished/grant frame:4096 plaintext bytes +16-byte tag.
pub const CREDENTIAL_FRAME_MAX: usize = 4096 + 16;
/// Largest frame body afterwards (1 MiB plus 4 KiB).
pub const SESSION_FRAME_MAX: usize = 1_052_672;

/// Which bound applies to a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramePhase {
    /// Cleartext handshake frames.
    Handshake,
    /// Credential-authentication records, before bulk exchange.
    Credential,
    /// Records under the session (or pairing) keys.
    Session,
}

impl FramePhase {
    /// The largest body allowed in this phase.
    pub const fn max(self) -> usize {
        match self {
            Self::Handshake => HANDSHAKE_FRAME_MAX,
            Self::Credential => CREDENTIAL_FRAME_MAX,
            Self::Session => SESSION_FRAME_MAX,
        }
    }
}

fn io(e: &std::io::Error) -> ProtocolError {
    match e.kind() {
        ErrorKind::UnexpectedEof => ProtocolError::Truncated,
        _ => ProtocolError::Io,
    }
}

/// Writes one frame. An empty or oversized body is refused before anything
/// is written.
pub fn write_frame(
    w: &mut impl Write,
    phase: FramePhase,
    body: &[u8],
) -> Result<(), ProtocolError> {
    if body.is_empty() {
        return Err(ProtocolError::EmptyFrame);
    }
    if body.len() > phase.max() {
        return Err(ProtocolError::FrameTooLarge);
    }
    let len = u32::try_from(body.len()).map_err(|_| ProtocolError::FrameTooLarge)?;
    w.write_all(&len.to_be_bytes()).map_err(|e| io(&e))?;
    w.write_all(body).map_err(|e| io(&e))?;
    w.flush().map_err(|e| io(&e))
}

/// Reads exactly one frame into `buf` (cleared first, and cleared again on
/// any error). `buf` grows only after the length passed the phase bound.
pub fn read_frame(
    r: &mut impl Read,
    phase: FramePhase,
    buf: &mut Vec<u8>,
) -> Result<(), ProtocolError> {
    buf.clear();
    let result = read_into(r, phase, buf);
    if result.is_err() {
        buf.clear();
    }
    result
}

fn read_into(r: &mut impl Read, phase: FramePhase, buf: &mut Vec<u8>) -> Result<(), ProtocolError> {
    let mut header = [0u8; 4];
    let mut got = 0;
    while got < header.len() {
        match r.read(&mut header[got..]) {
            Ok(0) if got == 0 => return Err(ProtocolError::Closed),
            Ok(0) => return Err(ProtocolError::Truncated),
            Ok(n) => got += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(io(&e)),
        }
    }
    let len =
        usize::try_from(u32::from_be_bytes(header)).map_err(|_| ProtocolError::FrameTooLarge)?;
    if len == 0 {
        return Err(ProtocolError::EmptyFrame);
    }
    if len > phase.max() {
        return Err(ProtocolError::FrameTooLarge);
    }
    buf.try_reserve_exact(len)
        .map_err(|_| ProtocolError::FrameTooLarge)?;
    buf.resize(len, 0);
    r.read_exact(buf).map_err(|e| io(&e))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn framed(len: u32, body: &[u8]) -> Vec<u8> {
        let mut v = len.to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    #[test]
    fn frames_round_trip_at_the_bounds() {
        for (phase, len) in [
            (FramePhase::Handshake, 1),
            (FramePhase::Handshake, HANDSHAKE_FRAME_MAX),
            (FramePhase::Credential, CREDENTIAL_FRAME_MAX),
            (FramePhase::Session, SESSION_FRAME_MAX),
        ] {
            let body = vec![7u8; len];
            let mut wire = Vec::new();
            write_frame(&mut wire, phase, &body).unwrap();
            let mut buf = Vec::new();
            read_frame(&mut wire.as_slice(), phase, &mut buf).unwrap();
            assert_eq!(buf, body);
        }
    }

    #[test]
    fn oversized_frames_are_refused_before_allocation() {
        for (phase, len) in [
            (FramePhase::Handshake, HANDSHAKE_FRAME_MAX + 1),
            (FramePhase::Credential, CREDENTIAL_FRAME_MAX + 1),
            (FramePhase::Session, SESSION_FRAME_MAX + 1),
        ] {
            assert_eq!(
                write_frame(&mut Vec::new(), phase, &vec![0; len]),
                Err(ProtocolError::FrameTooLarge)
            );
            // Only the header is available: refusal must not wait for or
            // allocate the body.
            let header = u32::try_from(len).unwrap().to_be_bytes();
            let mut buf = Vec::new();
            assert_eq!(
                read_frame(&mut header.as_slice(), phase, &mut buf),
                Err(ProtocolError::FrameTooLarge)
            );
            assert_eq!(buf.capacity(), 0);
        }
        let mut buf = Vec::new();
        assert_eq!(
            read_frame(
                &mut u32::MAX.to_be_bytes().as_slice(),
                FramePhase::Session,
                &mut buf
            ),
            Err(ProtocolError::FrameTooLarge)
        );
        assert_eq!(buf.capacity(), 0);
    }

    #[test]
    fn empty_closed_and_truncated_frames() {
        let mut buf = Vec::new();
        assert_eq!(
            read_frame(
                &mut framed(0, &[]).as_slice(),
                FramePhase::Handshake,
                &mut buf
            ),
            Err(ProtocolError::EmptyFrame)
        );
        assert_eq!(
            write_frame(&mut Vec::new(), FramePhase::Handshake, &[]),
            Err(ProtocolError::EmptyFrame)
        );
        assert_eq!(
            read_frame(&mut [].as_slice(), FramePhase::Handshake, &mut buf),
            Err(ProtocolError::Closed)
        );
        assert_eq!(
            read_frame(&mut [0, 0].as_slice(), FramePhase::Handshake, &mut buf),
            Err(ProtocolError::Truncated)
        );
        assert_eq!(
            read_frame(
                &mut framed(4, &[1, 2]).as_slice(),
                FramePhase::Handshake,
                &mut buf
            ),
            Err(ProtocolError::Truncated)
        );
        assert!(buf.is_empty());
    }

    #[test]
    fn a_read_consumes_exactly_one_frame() {
        let mut wire = framed(2, b"ab");
        wire.extend(framed(3, b"cde"));
        let mut r = wire.as_slice();
        let mut buf = Vec::new();
        read_frame(&mut r, FramePhase::Handshake, &mut buf).unwrap();
        assert_eq!(buf, b"ab");
        assert_eq!(r, framed(3, b"cde").as_slice());
        read_frame(&mut r, FramePhase::Handshake, &mut buf).unwrap();
        assert_eq!(buf, b"cde");
        assert_eq!(
            read_frame(&mut r, FramePhase::Handshake, &mut buf),
            Err(ProtocolError::Closed)
        );
    }
}
