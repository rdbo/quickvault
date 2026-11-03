// SPDX-License-Identifier: AGPL-3.0-or-later

//! Framed TCP with deadlines and prompt cancellation (0013 §1.3; plan 0037
//! decision 5), and the record channel (§6).
//!
//! The socket runs with 100 ms read and write timeouts. [`Conn`]'s reader
//! and writer retry across those slices, checking cancellation and the
//! current deadline in between, so no frame byte is lost and a cancel takes
//! effect within about 100 ms. Frames go through `qv_protocol::frame`, which
//! bounds the length before allocating and never reads ahead.

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use qv_crypto::SecretBytes;
use qv_crypto::lan::{RecordOpener, RecordSealer};
use qv_protocol::ProtocolError;
use qv_protocol::frame::{FramePhase, read_frame, write_frame};
use qv_protocol::lan::ErrorMsg;

use super::LanError;

/// Socket timeout slice between cancellation checks.
const SLICE: Duration = Duration::from_millis(100);

/// A connection with a current deadline and a cancellation check.
pub(crate) struct Conn<'c> {
    stream: TcpStream,
    cancelled: &'c (dyn Fn() -> bool + Sync),
    deadline: Instant,
    /// Why the last I/O failed, when it was a deadline or a cancel.
    reason: Option<LanError>,
}

impl<'c> Conn<'c> {
    /// Wraps a connected stream (blocking, with the slice timeouts).
    pub(crate) fn new(
        stream: TcpStream,
        cancelled: &'c (dyn Fn() -> bool + Sync),
    ) -> Result<Self, LanError> {
        stream.set_nonblocking(false).map_err(|_| LanError::Io)?;
        stream
            .set_read_timeout(Some(SLICE))
            .map_err(|_| LanError::Io)?;
        stream
            .set_write_timeout(Some(SLICE))
            .map_err(|_| LanError::Io)?;
        let _ = stream.set_nodelay(true);
        Ok(Self {
            stream,
            cancelled,
            deadline: Instant::now(),
            reason: None,
        })
    }

    /// The next operations must finish within `limit` and before `cap`.
    pub(crate) fn within(&mut self, limit: Duration, cap: Option<Instant>) {
        let d = Instant::now() + limit;
        self.deadline = cap.map_or(d, |c| c.min(d));
    }

    fn wait(&mut self) -> std::io::Result<()> {
        if (self.cancelled)() {
            self.reason = Some(LanError::Cancelled);
        } else if Instant::now() >= self.deadline {
            self.reason = Some(LanError::Timeout);
        } else {
            return Ok(());
        }
        Err(std::io::Error::from(ErrorKind::Other))
    }

    fn map(&mut self, e: ProtocolError) -> LanError {
        if let Some(r) = self.reason.take() {
            return r;
        }
        match e {
            ProtocolError::Closed | ProtocolError::Truncated | ProtocolError::Io => {
                LanError::Timeout
            }
            ProtocolError::Unsupported => LanError::Unsupported,
            _ => LanError::Protocol,
        }
    }

    /// Reads one frame of `phase` into `buf`.
    pub(crate) fn recv_frame(
        &mut self,
        phase: FramePhase,
        buf: &mut Vec<u8>,
    ) -> Result<(), LanError> {
        self.reason = None;
        let r = read_frame(&mut IoRead(self), phase, buf);
        r.map_err(|e| self.map(e))
    }

    /// Writes one frame of `phase`.
    pub(crate) fn send_frame(&mut self, phase: FramePhase, body: &[u8]) -> Result<(), LanError> {
        self.reason = None;
        let r = write_frame(&mut IoWrite(self), phase, body);
        r.map_err(|e| self.map(e))
    }

    /// Closes both directions now.
    pub(crate) fn close(&self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

struct IoRead<'a, 'c>(&'a mut Conn<'c>);

impl Read for IoRead<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            match self.0.stream.read(buf) {
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    self.0.wait()?;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                r => return r,
            }
        }
    }
}

struct IoWrite<'a, 'c>(&'a mut Conn<'c>);

impl Write for IoWrite<'_, '_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            match self.0.stream.write(buf) {
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    self.0.wait()?;
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                r => return r,
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.stream.flush()
    }
}

/// Records under one pair of direction keys (0013 §6).
pub(crate) struct Channel<'c> {
    pub(crate) conn: Conn<'c>,
    sealer: RecordSealer,
    opener: RecordOpener,
    buf: Vec<u8>,
    /// The peer sent an error record: answer nothing more.
    peer_failed: bool,
}

impl<'c> Channel<'c> {
    pub(crate) fn new(conn: Conn<'c>, sealer: RecordSealer, opener: RecordOpener) -> Self {
        Self {
            conn,
            sealer,
            opener,
            buf: Vec::new(),
            peer_failed: false,
        }
    }

    /// Seals and sends one message within `limit`.
    pub(crate) fn send(&mut self, msg: &[u8], limit: Duration) -> Result<(), LanError> {
        let record = self.sealer.seal(msg).map_err(|_| LanError::Limit)?;
        self.conn.within(limit, None);
        self.conn.send_frame(FramePhase::Session, &record)
    }

    /// Receives and opens one message within `limit` (and before `cap`). An
    /// error record from the peer becomes its [`LanError`].
    pub(crate) fn recv(
        &mut self,
        limit: Duration,
        cap: Option<std::time::Instant>,
    ) -> Result<SecretBytes, LanError> {
        self.conn.within(limit, cap);
        self.conn.recv_frame(FramePhase::Session, &mut self.buf)?;
        let msg = self
            .opener
            .open(&self.buf)
            .map_err(|_| LanError::Integrity)?;
        match ErrorMsg::peek(msg.expose_secret()) {
            Ok(Some(e)) => {
                self.peer_failed = true;
                Err(LanError::from_peer(e.code))
            }
            Ok(None) => Ok(msg),
            Err(_) => Err(LanError::Protocol),
        }
    }

    /// Aborts after a local failure: sends its error record when it has
    /// one (best effort, 1 s), closes, and returns the error.
    pub(crate) fn abort(&mut self, e: LanError) -> LanError {
        if !self.peer_failed
            && let Some(code) = e.wire_code()
            && let Ok(msg) = ErrorMsg::encode(code)
        {
            let _ = self.send(&msg, Duration::from_secs(1));
        }
        self.conn.close();
        e
    }
}

/// Runs `f`; on error, aborts the channel with it.
pub(crate) fn guarded<T>(
    ch: &mut Channel<'_>,
    f: impl FnOnce(&mut Channel<'_>) -> Result<T, LanError>,
) -> Result<T, LanError> {
    match f(ch) {
        Ok(v) => Ok(v),
        // A peer-reported error or a transport failure: just close.
        Err(e @ (LanError::Timeout | LanError::Io | LanError::PeerCancelled)) => {
            ch.conn.close();
            Err(e)
        }
        Err(e) => Err(ch.abort(e)),
    }
}
