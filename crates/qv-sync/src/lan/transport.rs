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
use qv_protocol::ProtocolError;
use qv_protocol::frame::{FramePhase, read_frame, write_frame};

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
        if (self.cancelled)() {
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

/// Profile2 channel. Epoch replacement consumes the old channel and preserves
/// its socket/deadline. Neither receive nor transition ever tries another key.
/// Bulk exchange takes the default final-epoch specialization only.
pub(crate) struct V2Channel<'c, E: qv_crypto::lan::v2::Epoch = qv_crypto::lan::v2::FinalEpoch> {
    pub(crate) conn: Conn<'c>,
    pub(crate) sealer: qv_crypto::lan::v2::RecordSealer<E>,
    opener: qv_crypto::lan::v2::RecordOpener<E>,
    role: qv_crypto::lan::v2::Role,
    phase: FramePhase,
    buf: Vec<u8>,
    peer_failed: bool,
    errors_allowed: bool,
}

impl<'c> V2Channel<'c, qv_crypto::lan::v2::InitialEpoch> {
    pub(crate) fn initial(
        conn: Conn<'c>,
        keys: qv_crypto::lan::v2::TrafficKeys<qv_crypto::lan::v2::InitialEpoch>,
        role: qv_crypto::lan::v2::Role,
    ) -> Self {
        let (sealer, opener) = keys.split(role);
        Self {
            conn,
            sealer,
            opener,
            role,
            phase: FramePhase::Credential,
            buf: Vec::new(),
            peer_failed: false,
            errors_allowed: false,
        }
    }
    pub(crate) fn finish(
        self,
        keys: qv_crypto::lan::v2::TrafficKeys<qv_crypto::lan::v2::FinalEpoch>,
    ) -> Result<V2Channel<'c>, LanError> {
        let (sealer, opener) = keys.split(self.role);
        if sealer.binding() != self.sealer.binding() {
            self.conn.close();
            return Err(LanError::Integrity);
        }
        // Moving only the connection drops both epoch0 keys and its buffer.
        Ok(V2Channel {
            conn: self.conn,
            sealer,
            opener,
            role: self.role,
            phase: FramePhase::Credential,
            buf: Vec::new(),
            peer_failed: false,
            errors_allowed: false,
        })
    }
}
impl V2Channel<'_> {
    /// Called only after the state-specific credential/final-key checks. This
    /// permits normal exchange framing and authenticated exchange errors.
    pub(crate) fn begin_exchange(&mut self) {
        self.phase = FramePhase::Session;
        self.errors_allowed = true;
    }
}
impl<E: qv_crypto::lan::v2::Epoch> V2Channel<'_, E> {
    pub(crate) fn check(&self) -> Result<(), LanError> {
        if (self.conn.cancelled)() {
            Err(LanError::Cancelled)
        } else if self.conn.cap.is_some_and(|cap| Instant::now() >= cap) {
            Err(LanError::Timeout)
        } else {
            Ok(())
        }
    }
    pub(crate) fn send(&mut self, msg: &[u8], limit: Duration) -> Result<(), LanError> {
        self.check()?;
        if self.phase == FramePhase::Credential && msg.len() > qv_protocol::lan::v2::CREDENTIAL_MAX
        {
            return Err(LanError::Limit);
        }
        let record = self.sealer.seal(msg).map_err(|_| LanError::Integrity)?;
        self.send_sealed(&record, limit)
    }
    pub(crate) fn send_sealed(&mut self, record: &[u8], limit: Duration) -> Result<(), LanError> {
        self.check()?;
        self.conn.within(limit, None);
        self.conn.send_frame(self.phase, record)
    }
    pub(crate) fn recv(
        &mut self,
        limit: Duration,
        cap: Option<Instant>,
    ) -> Result<SecretBytes, LanError> {
        self.check()?;
        self.conn.within(limit, cap);
        self.conn.recv_frame(self.phase, &mut self.buf)?;
        let msg = self
            .opener
            .open(&self.buf)
            .map_err(|_| LanError::Integrity)?;
        match qv_protocol::lan::v2::ErrorMsg::peek(msg.expose_secret()) {
            Ok(Some(error)) => {
                self.peer_failed = true;
                Err(LanError::from_peer(error.code))
            }
            Ok(None) => Ok(msg),
            Err(_) => Err(LanError::Protocol),
        }
    }
    pub(crate) fn abort(&mut self, error: LanError) -> LanError {
        // Credential failures are deliberately silent, including component
        // decoding/wrong password. A sends no final error before confirming B.
        if self.errors_allowed
            && !self.peer_failed
            && self.check().is_ok()
            && let Some(code) = error.wire_code()
            && let Ok(msg) = qv_protocol::lan::v2::ErrorMsg::encode(code)
        {
            let _ = self.send(&msg, Duration::from_secs(1));
        }
        self.conn.close();
        error
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
