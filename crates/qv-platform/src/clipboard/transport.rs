// SPDX-License-Identifier: AGPL-3.0-or-later

//! Nonblocking local transport with lifetime, allocation and cancellation budgets.
use crate::Cancellation;
use rustix::event::{PollFd, PollFlags, Timespec};
use std::{
    cell::Cell,
    io::{self, IoSlice},
    os::fd::AsFd,
    os::unix::net::UnixStream,
    time::{Duration, Instant},
};
use x11rb::{
    rust_connection::{DefaultStream, PollMode, RustConnection, Stream},
    utils::RawFdContainer,
};
use x11rb_protocol::{
    parse_display::{ConnectAddress, parse_display},
    xauth::get_auth,
};

pub(super) type Connection = RustConnection<BoundedStream>;
const MAX_READ: usize = 4 * 1024 * 1024;
/// Largest X11 packet accepted, header included.
const MAX_PACKET: usize = 1024 * 1024;

/// X11 framing of the bytes handed to x11rb, checked before x11rb can size a
/// buffer from an advertised length. Only framing is inspected; x11rb still
/// decodes. The setup reply comes first (8-byte header, length in 4-byte units
/// at bytes 6..8), then 32-byte packets, where replies (type 1) and
/// GenericEvents (type 35) carry `length * 4` further bytes. The connection
/// uses native byte order.
#[derive(Clone, Copy)]
struct Framing {
    setup: bool,
    header: [u8; 32],
    used: usize,
    remaining: usize,
}
impl Default for Framing {
    fn default() -> Self {
        Self {
            setup: true,
            header: [0; 32],
            used: 0,
            remaining: 0,
        }
    }
}
impl Framing {
    fn feed(&mut self, mut bytes: &[u8]) -> io::Result<()> {
        while !bytes.is_empty() {
            if self.remaining > 0 {
                let n = self.remaining.min(bytes.len());
                self.remaining -= n;
                bytes = &bytes[n..];
                if self.remaining == 0 {
                    self.used = 0;
                }
                continue;
            }
            let size = if self.setup { 8 } else { 32 };
            let n = (size - self.used).min(bytes.len());
            self.header[self.used..self.used + n].copy_from_slice(&bytes[..n]);
            self.used += n;
            bytes = &bytes[n..];
            if self.used < size {
                continue;
            }
            let h = &self.header;
            let extra = if self.setup {
                self.setup = false;
                usize::from(u16::from_ne_bytes([h[6], h[7]])) * 4
            } else if h[0] == 1 || h[0] & 0x7f == 35 {
                usize::try_from(u32::from_ne_bytes([h[4], h[5], h[6], h[7]]))
                    .ok()
                    .and_then(|n| n.checked_mul(4))
                    .ok_or_else(failed)?
            } else {
                0
            };
            if extra > MAX_PACKET - size {
                return Err(failed());
            }
            self.remaining = extra;
            if extra == 0 {
                self.used = 0;
            }
        }
        Ok(())
    }
}

pub(super) struct BoundedStream {
    inner: DefaultStream,
    remaining: Cell<usize>,
    framing: Cell<Framing>,
    deadline: Cell<Instant>,
    cleanup: Cell<bool>,
    cancel: Cancellation,
}
fn failed() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}
impl BoundedStream {
    pub(super) fn begin(&self, deadline: Instant, cleanup: bool) {
        self.deadline.set(deadline);
        self.cleanup.set(cleanup);
    }
    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.deadline.get() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if !self.cleanup.get() && (self.cancel)() {
            return Err(io::ErrorKind::ConnectionAborted.into());
        }
        Ok(())
    }
}
fn poll(fd: impl AsFd, flags: PollFlags, deadline: Instant) -> io::Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let duration = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        let timeout = Timespec {
            tv_sec: 0,
            tv_nsec: i64::from(duration.subsec_nanos()),
        };
        let mut fds = [PollFd::new(&fd, flags)];
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) => return Ok(()), // callers recheck deadlines/cancellation
            Ok(_) => return Ok(()),
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}
impl Stream for BoundedStream {
    fn poll(&self, mode: PollMode) -> io::Result<()> {
        self.check()?;
        let mut flags = PollFlags::empty();
        if mode.readable() {
            flags |= PollFlags::IN;
        }
        if mode.writable() {
            flags |= PollFlags::OUT;
        }
        poll(&self.inner, flags, self.deadline.get())?;
        self.check()
    }
    fn read(&self, buf: &mut [u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        self.check()?;
        let max = buf.len().min(self.remaining.get());
        if max == 0 {
            return Err(failed());
        }
        let n = self.inner.read(&mut buf[..max], fds)?;
        if !fds.is_empty() {
            fds.clear();
            return Err(failed());
        }
        self.remaining.set(self.remaining.get() - n);
        let mut framing = self.framing.get();
        framing.feed(&buf[..n])?;
        self.framing.set(framing);
        Ok(n)
    }
    fn write(&self, data: &[u8], fds: &mut Vec<RawFdContainer>) -> io::Result<usize> {
        self.check()?;
        self.inner.write(data, fds)
    }
    fn write_vectored(
        &self,
        data: &[IoSlice<'_>],
        fds: &mut Vec<RawFdContainer>,
    ) -> io::Result<usize> {
        self.check()?;
        self.inner.write_vectored(data, fds)
    }
}

fn socket(
    address: &rustix::net::SocketAddrUnix,
    deadline: Instant,
    cancel: &Cancellation,
) -> io::Result<UnixStream> {
    use rustix::net::{AddressFamily, SocketFlags, SocketType, connect, socket_with};
    let fd = socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )?;
    match connect(&fd, address) {
        Ok(()) => {}
        Err(rustix::io::Errno::INPROGRESS | rustix::io::Errno::AGAIN) => loop {
            if cancel() {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
            poll(&fd, PollFlags::OUT, deadline)?;
            // A repeated connect confirms completion without a blocking socket call.
            match connect(&fd, address) {
                Ok(()) | Err(rustix::io::Errno::ISCONN) => break,
                Err(
                    rustix::io::Errno::INPROGRESS
                    | rustix::io::Errno::ALREADY
                    | rustix::io::Errno::AGAIN,
                ) => continue,
                Err(e) => return Err(e.into()),
            }
        },
        Err(e) => return Err(e.into()),
    }
    Ok(UnixStream::from(fd))
}

pub(super) fn connect(cancel: Cancellation) -> Result<(Connection, usize), ()> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let parsed = parse_display(None).map_err(|_| ())?;
    // Upstream connect_instruction also computes a u16 TCP port, even for :N.
    if parsed.display > u16::MAX - 6000 {
        return Err(());
    }
    for address in parsed.connect_instruction() {
        let ConnectAddress::Socket(path) = address else {
            continue;
        };
        let mut connected = None;
        for abstract_socket in [true, false] {
            let address = if abstract_socket {
                rustix::net::SocketAddrUnix::new_abstract_name(path.as_bytes())
            } else {
                rustix::net::SocketAddrUnix::new(path.as_str())
            }
            .map_err(|_| ())?;
            if let Ok(stream) = socket(&address, deadline, &cancel) {
                connected = Some(stream);
                break;
            }
        }
        let Some(stream) = connected else {
            continue;
        };
        let (inner, (family, peer)) = DefaultStream::from_unix_stream(stream).map_err(|_| ())?;
        let (auth_name, auth_data) = match get_auth(family, &peer, parsed.display) {
            Ok(auth) => auth.unwrap_or_default(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Vec::new(), Vec::new()),
            Err(_) => return Err(()),
        };
        let stream = BoundedStream {
            inner,
            remaining: Cell::new(MAX_READ),
            framing: Cell::new(Framing::default()),
            deadline: Cell::new(deadline),
            cleanup: Cell::new(false),
            cancel: cancel.clone(),
        };
        return Ok((
            RustConnection::connect_to_stream_with_auth_info(
                stream,
                usize::from(parsed.screen),
                auth_name,
                auth_data,
            )
            .map_err(|_| ())?,
            usize::from(parsed.screen),
        ));
    }
    Err(())
}

#[cfg(test)]
mod tests {
    // Test-only OS fixtures fail loudly.
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn stream() -> (BoundedStream, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        let (inner, _) = DefaultStream::from_unix_stream(a).unwrap();
        (
            BoundedStream {
                inner,
                remaining: Cell::new(MAX_READ),
                framing: Cell::new(Framing::default()),
                deadline: Cell::new(Instant::now() + Duration::from_secs(5)),
                cleanup: Cell::new(false),
                cancel: std::sync::Arc::new(|| false),
            },
            b,
        )
    }
    #[test]
    fn clipboard_lifetime_read_budget_cannot_be_reset_by_operations() {
        use std::io::Write;
        let (s, mut peer) = stream();
        s.remaining.set(3);
        peer.write_all(b"abcdef").unwrap();
        let mut data = [0u8; 8];
        assert_eq!(s.read(&mut data, &mut vec![]).unwrap(), 3);
        assert_eq!(&data[..3], b"abc");
        s.begin(Instant::now() + Duration::from_secs(5), false);
        assert_eq!(
            s.read(&mut data, &mut vec![]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
    #[test]
    fn clipboard_stalled_poll_and_cleanup_have_deadlines() {
        let (s, _peer) = stream();
        let start = Instant::now();
        s.begin(start + Duration::from_millis(30), true);
        while Stream::poll(&s, PollMode::Readable).is_ok() {}
        assert!(start.elapsed() < Duration::from_secs(1));
        assert_eq!(
            s.read(&mut [0u8; 1], &mut vec![]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
    #[test]
    fn clipboard_rejects_and_drops_received_descriptors() {
        let (s, peer) = stream();
        let (peer, _) = DefaultStream::from_unix_stream(peer).unwrap();
        let (read_fd, _write_fd) = rustix::pipe::pipe().unwrap();
        let mut fds = vec![read_fd];
        assert_eq!(peer.write(b"x", &mut fds).unwrap(), 1);
        assert!(fds.is_empty());
        let mut received = vec![];
        assert_eq!(
            s.read(&mut [0u8; 8], &mut received).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(received.is_empty());
    }
    fn reply(length: u32) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = 1;
        h[4..8].copy_from_slice(&length.to_ne_bytes());
        h
    }
    fn packets() -> Framing {
        Framing {
            setup: false,
            ..Framing::default()
        }
    }
    #[test]
    fn clipboard_framing_refuses_oversized_packets_before_x11rb_sees_them() {
        use std::io::Write;
        // Setup reply with 2 units of data, then an error, a small reply and
        // its body, all split at awkward points.
        let mut ok = vec![1u8, 0, 11, 0, 0, 0];
        ok.extend_from_slice(&2u16.to_ne_bytes());
        ok.extend_from_slice(&[0; 8]);
        ok.extend_from_slice(&[0u8; 32]);
        ok.extend_from_slice(&reply(1));
        ok.extend_from_slice(&[7; 4]);
        let mut f = Framing::default();
        for chunk in ok.chunks(5) {
            f.feed(chunk).unwrap();
        }
        assert!(!f.setup);
        assert_eq!((f.used, f.remaining), (0, 0));
        // At the cap is accepted; one unit more is refused.
        let max = u32::try_from((MAX_PACKET - 32) / 4).unwrap();
        packets().feed(&reply(max)).unwrap();
        assert!(packets().feed(&reply(max + 1)).is_err());
        let mut generic = reply(u32::MAX);
        generic[0] = 35 | 0x80;
        assert!(packets().feed(&generic).is_err());
        // Through the stream: the oversized header read fails.
        let (s, mut peer) = stream();
        s.framing.set(packets());
        peer.write_all(&reply(u32::MAX)).unwrap();
        let mut data = [0u8; 64];
        assert_eq!(
            s.read(&mut data, &mut vec![]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
