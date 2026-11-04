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
use std::net::{SocketAddr, TcpStream};
use std::sync::mpsc::RecvTimeoutError;
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
    cap: Option<Instant>,
    /// Why the last I/O failed, when it was a deadline or a cancel.
    reason: Option<LanError>,
    /// The last record of an abort is being sent: only its deadline
    /// applies, so a cancel can still tell the peer.
    closing: bool,
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
            cap: None,
            reason: None,
            closing: false,
        })
    }

    /// An absolute lifetime cap that later per-message deadlines cannot extend.
    pub(crate) fn cap(&mut self, expires: Instant) {
        self.cap = Some(self.cap.map_or(expires, |old| old.min(expires)));
    }

    /// The next operations must finish within `limit` and before `cap`.
    pub(crate) fn within(&mut self, limit: Duration, cap: Option<Instant>) {
        let d = Instant::now() + limit;
        self.deadline = cap.into_iter().chain(self.cap).fold(d, Instant::min);
    }

    fn wait(&mut self) -> std::io::Result<()> {
        if !self.closing && (self.cancelled)() {
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

    /// Reads one frame of `phase` into `buf`. A cancel is checked before
    /// the read as well as while it waits, so it takes effect even when the
    /// peer never makes this side wait.
    pub(crate) fn recv_frame(
        &mut self,
        phase: FramePhase,
        buf: &mut Vec<u8>,
    ) -> Result<(), LanError> {
        if (self.cancelled)() {
            return Err(LanError::Cancelled);
        }
        self.reason = None;
        let r = read_frame(&mut IoRead(self), phase, buf);
        r.map_err(|e| self.map(e))
    }

    /// Writes one frame of `phase`, checking a cancel first (see
    /// [`Self::recv_frame`]).
    pub(crate) fn send_frame(&mut self, phase: FramePhase, body: &[u8]) -> Result<(), LanError> {
        if !self.closing && (self.cancelled)() {
            return Err(LanError::Cancelled);
        }
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
            self.0.wait()?;
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
            self.0.wait()?;
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

    /// Seals and sends one message within `limit`. A cancel is checked
    /// before sealing, so a refused send never consumes a sequence number
    /// that the abort record would then skip.
    pub(crate) fn send(&mut self, msg: &[u8], limit: Duration) -> Result<(), LanError> {
        if !self.conn.closing && (self.conn.cancelled)() {
            return Err(LanError::Cancelled);
        }
        let record = self.seal(msg)?;
        self.send_sealed(&record, limit)
    }

    /// Seals one message into the next record without sending it.
    pub(crate) fn seal(&mut self, msg: &[u8]) -> Result<Vec<u8>, LanError> {
        self.sealer.seal(msg).map_err(|_| LanError::Limit)
    }

    /// Sends a record from [`Self::seal`] within `limit`.
    pub(crate) fn send_sealed(&mut self, record: &[u8], limit: Duration) -> Result<(), LanError> {
        self.conn.within(limit, None);
        self.conn.send_frame(FramePhase::Session, record)
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
            self.conn.closing = true;
            let _ = self.send(&msg, Duration::from_secs(1));
        }
        self.conn.close();
        e
    }
}

/// Opens a connection to `endpoint` within `limit`, checking `cancelled`
/// every slice (plan 0038 decision 10). `connect_timeout` runs on a helper
/// thread that is abandoned on cancel and ends by itself within `limit`.
/// `Ok(None)` means the endpoint did not accept.
pub(crate) fn connect(
    endpoint: SocketAddr,
    limit: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<TcpStream>, LanError> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("qv-lan-connect".into())
        .spawn(move || {
            let _ = tx.send(TcpStream::connect_timeout(&endpoint, limit));
        })
        .map_err(|_| LanError::Io)?;
    loop {
        if cancelled() {
            return Err(LanError::Cancelled);
        }
        match rx.recv_timeout(SLICE) {
            Ok(Ok(stream)) => return Ok(Some(stream)),
            Ok(Err(_)) | Err(RecvTimeoutError::Disconnected) => return Ok(None),
            Err(RecvTimeoutError::Timeout) => {}
        }
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn lan_absolute_deadline_rejects_ready_io_after_message_deadline_reset() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (stream, _) = listener.accept().unwrap();
        let mut conn = Conn::new(stream, &|| false).unwrap();
        // The entire frame is already readable; no socket timeout is needed.
        peer.write_all(&[0, 0, 0, 1, 0x80]).unwrap();
        conn.cap(Instant::now() - Duration::from_secs(1));
        conn.within(Duration::from_secs(60), None);
        assert_eq!(
            conn.recv_frame(FramePhase::Handshake, &mut Vec::new()),
            Err(LanError::Timeout)
        );
        conn.within(Duration::from_secs(60), None);
        assert_eq!(
            conn.send_frame(FramePhase::Handshake, &[0x80]),
            Err(LanError::Timeout)
        );
        peer.set_read_timeout(Some(Duration::from_millis(150)))
            .unwrap();
        assert!(peer.read(&mut [0]).is_err(), "expired send wrote nothing");
    }
}
