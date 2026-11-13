// SPDX-License-Identifier: AGPL-3.0-or-later

//! A minimal, bounded Wayland client that owns the clipboard through a
//! data-control protocol (plan 0055): `ext_data_control_manager_v1`, else
//! `zwlr_data_control_manager_v1`, which share their request and event
//! layout. It needs no window, so the CLI can use it. It never reads the
//! clipboard; other clients' offers are skipped by their size. Compositors
//! without data-control (GNOME) make [`Owner::start`] fail, and the caller
//! falls back to X11.
//!
//! Wire format: native-endian `u32` words. A message is the object id, then
//! `size << 16 | opcode` (`size` includes this 8-byte header), then arguments
//! padded to 4 bytes. File descriptors arrive as `SCM_RIGHTS`.
//!
//! Destroying our source (or closing the connection) removes the selection
//! only while that source is still the selection; the compositor orders it
//! against a successor's copy, so cleanup never clears a successor's value.
use crate::{Cancellation, PlatformError};
use rustix::event::{PollFd, PollFlags, Timespec};
use rustix::io::Errno;
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, SendFlags, SocketAddrUnix,
    SocketFlags, SocketType,
};
use std::collections::VecDeque;
use std::io::IoSliceMut;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// The protocol's own message size limit.
const MAX_MESSAGE: usize = 4096;
/// Bytes read from the compositor over one hold.
const READ_BUDGET: usize = 4 << 20;
/// Received descriptors waiting for the event that uses them.
const MAX_QUEUED_FDS: usize = 8;
const ROUNDTRIP: Duration = Duration::from_secs(5);
/// One paste: writing the value to the requester's pipe.
const TRANSFER: Duration = Duration::from_secs(5);
const SLICE: Duration = Duration::from_millis(100);

const DISPLAY: u32 = 1;
const REGISTRY: u32 = 2;
const MANAGERS: [&[u8]; 2] = [
    b"ext_data_control_manager_v1",
    b"zwlr_data_control_manager_v1",
];
pub(super) const TEXT_MIMES: [&str; 5] = [
    "text/plain;charset=utf-8",
    "text/plain",
    "UTF8_STRING",
    "STRING",
    "TEXT",
];
pub(super) const HINT_MIME: &str = "x-kde-passwordManagerHint";

/// The socket named by `WAYLAND_DISPLAY`, if this is a Wayland session.
pub(super) fn connect() -> Option<OwnedFd> {
    let name = std::env::var_os("WAYLAND_DISPLAY").filter(|n| !n.is_empty())?;
    let path = PathBuf::from(&name);
    let path = if path.is_absolute() {
        path
    } else {
        PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty())?).join(path)
    };
    let address = SocketAddrUnix::new(&path).ok()?;
    let fd = rustix::net::socket_with(
        AddressFamily::UNIX,
        SocketType::STREAM,
        SocketFlags::NONBLOCK | SocketFlags::CLOEXEC,
        None,
    )
    .ok()?;
    // A local stream connect completes at once or fails (a full backlog
    // reports EAGAIN); either way no blocking wait is needed.
    rustix::net::connect(&fd, &address).ok()?;
    Some(fd)
}

/// One outgoing request.
struct Msg {
    buf: Vec<u8>,
    opcode: u16,
}
impl Msg {
    fn new(object: u32, opcode: u16) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&object.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        Self { buf, opcode }
    }
    fn u32(mut self, value: u32) -> Self {
        self.buf.extend_from_slice(&value.to_ne_bytes());
        self
    }
    /// Our own constant strings only; never longer than a few dozen bytes.
    fn string(mut self, value: &str) -> Self {
        let len = u32::try_from(value.len() + 1).unwrap_or(u32::MAX);
        self = self.u32(len);
        self.buf.extend_from_slice(value.as_bytes());
        self.buf.push(0);
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
        self
    }
    fn bytes(mut self) -> Vec<u8> {
        let size = u32::try_from(self.buf.len()).unwrap_or(0);
        let word = (size << 16) | u32::from(self.opcode);
        if let Some(slot) = self.buf.get_mut(4..8) {
            slot.copy_from_slice(&word.to_ne_bytes());
        }
        self.buf
    }
}

/// One incoming event.
struct Event {
    object: u32,
    opcode: u16,
    body: Vec<u8>,
}
/// Bounded argument reader over an event body.
struct Args<'a> {
    body: &'a [u8],
    at: usize,
}
impl<'a> Args<'a> {
    fn new(body: &'a [u8]) -> Self {
        Self { body, at: 0 }
    }
    fn u32(&mut self) -> Result<u32, PlatformError> {
        let end = self.at.checked_add(4).ok_or(PlatformError::Unavailable)?;
        let word = self
            .body
            .get(self.at..end)
            .and_then(|w| <[u8; 4]>::try_from(w).ok())
            .ok_or(PlatformError::Unavailable)?;
        self.at = end;
        Ok(u32::from_ne_bytes(word))
    }
    /// A string without its terminating NUL; `None` for a null string.
    fn string(&mut self) -> Result<Option<&'a [u8]>, PlatformError> {
        let len = usize::try_from(self.u32()?).map_err(|_| PlatformError::Unavailable)?;
        if len == 0 {
            return Ok(None);
        }
        let padded = len.checked_add(3).ok_or(PlatformError::Unavailable)? & !3;
        let end = self
            .at
            .checked_add(padded)
            .ok_or(PlatformError::Unavailable)?;
        let field = self
            .body
            .get(self.at..end)
            .ok_or(PlatformError::Unavailable)?;
        let (text, rest) = field
            .split_at_checked(len - 1)
            .ok_or(PlatformError::Unavailable)?;
        if rest.first() != Some(&0) {
            return Err(PlatformError::Unavailable);
        }
        self.at = end;
        Ok(Some(text))
    }
}

/// Splits one complete message off `input`, if there is one.
fn parse(input: &mut Vec<u8>) -> Result<Option<Event>, PlatformError> {
    let mut header = Args::new(input);
    let (Ok(object), Ok(word)) = (header.u32(), header.u32()) else {
        return Ok(None);
    };
    let size = usize::try_from(word >> 16).map_err(|_| PlatformError::Unavailable)?;
    if !(8..=MAX_MESSAGE).contains(&size) || !size.is_multiple_of(4) {
        return Err(PlatformError::Unavailable);
    }
    if input.len() < size {
        return Ok(None);
    }
    let body = input
        .get(8..size)
        .ok_or(PlatformError::Unavailable)?
        .to_vec();
    input.drain(..size);
    Ok(Some(Event {
        object,
        opcode: u16::try_from(word & 0xffff).map_err(|_| PlatformError::Unavailable)?,
        body,
    }))
}

fn wait(fd: impl AsFd, flags: PollFlags, until: Instant) {
    let slice = until.saturating_duration_since(Instant::now()).min(SLICE);
    let timeout = Timespec {
        tv_sec: 0,
        tv_nsec: i64::from(slice.subsec_nanos()),
    };
    let mut fds = [PollFd::new(&fd, flags)];
    // Errors and EINTR only end this slice; callers recheck their deadlines.
    let _ = rustix::event::poll(&mut fds, Some(&timeout));
}

/// The connection, its unparsed input and its received descriptors.
struct Wire {
    sock: OwnedFd,
    input: Vec<u8>,
    fds: VecDeque<OwnedFd>,
    read: usize,
    next_id: u32,
    cancel: Cancellation,
}
impl Wire {
    fn new(sock: OwnedFd, cancel: Cancellation) -> Self {
        Self {
            sock,
            input: Vec::with_capacity(2 * MAX_MESSAGE),
            fds: VecDeque::new(),
            read: 0,
            next_id: REGISTRY + 1,
            cancel,
        }
    }
    fn id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    fn send(&self, msg: Msg, until: Instant) -> Result<(), PlatformError> {
        let bytes = msg.bytes();
        let mut at = 0;
        while let Some(rest) = bytes.get(at..).filter(|r| !r.is_empty()) {
            if Instant::now() >= until {
                return Err(PlatformError::Unavailable);
            }
            match rustix::net::send(&self.sock, rest, SendFlags::NOSIGNAL) {
                Ok(0) => return Err(PlatformError::Unavailable),
                Ok(n) => at += n,
                Err(Errno::AGAIN) => wait(&self.sock, PollFlags::OUT, until),
                Err(Errno::INTR) => {}
                Err(_) => return Err(PlatformError::Unavailable),
            }
        }
        Ok(())
    }
    /// Reads what is available now; `false` when nothing was.
    fn fill(&mut self) -> Result<bool, PlatformError> {
        let mut buf = [0u8; MAX_MESSAGE];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_QUEUED_FDS))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let got = match rustix::net::recvmsg(
            &self.sock,
            &mut [IoSliceMut::new(&mut buf)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC | RecvFlags::DONTWAIT,
        ) {
            Ok(got) => got,
            Err(Errno::AGAIN | Errno::INTR) => return Ok(false),
            Err(_) => return Err(PlatformError::Unavailable),
        };
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(fds) = message {
                self.fds.extend(fds);
            }
        }
        if self.fds.len() > MAX_QUEUED_FDS {
            return Err(PlatformError::Unavailable);
        }
        if got.bytes == 0 {
            return Err(PlatformError::Unavailable); // the compositor closed us
        }
        self.read = self.read.saturating_add(got.bytes);
        if self.read > READ_BUDGET {
            return Err(PlatformError::LimitExceeded);
        }
        self.input
            .extend_from_slice(buf.get(..got.bytes).ok_or(PlatformError::Unavailable)?);
        Ok(true)
    }
    /// The next event, waiting until `until`.
    fn next(&mut self, until: Instant) -> Result<Option<Event>, PlatformError> {
        loop {
            if let Some(event) = parse(&mut self.input)? {
                return Ok(Some(event));
            }
            if (self.cancel)() {
                return Err(PlatformError::Cancelled);
            }
            if self.fill()? {
                continue;
            }
            if Instant::now() >= until {
                return Ok(None);
            }
            wait(&self.sock, PollFlags::IN, until);
        }
    }
    /// Sends `wl_display.sync` and returns the events before its `done`.
    fn roundtrip(&mut self) -> Result<Vec<Event>, PlatformError> {
        let until = Instant::now() + ROUNDTRIP;
        let callback = self.id();
        self.send(Msg::new(DISPLAY, 0).u32(callback), until)?;
        let mut events = Vec::new();
        loop {
            let event = self.next(until)?.ok_or(PlatformError::Unavailable)?;
            if event.object == callback && event.opcode == 0 {
                return Ok(events);
            }
            if event.object == DISPLAY && event.opcode == 0 {
                return Err(PlatformError::Unavailable); // a protocol error
            }
            events.push(event);
        }
    }
}

/// The seat and data-control manager globals.
struct Globals {
    seat: Option<u32>,
    manager: Option<(usize, u32)>,
}
fn globals(events: &[Event]) -> Result<Globals, PlatformError> {
    let mut found = Globals {
        seat: None,
        manager: None,
    };
    for event in events
        .iter()
        .filter(|e| e.object == REGISTRY && e.opcode == 0)
    {
        let mut args = Args::new(&event.body);
        let name = args.u32()?;
        let interface = args.string()?.unwrap_or_default();
        if interface == b"wl_seat" && found.seat.is_none() {
            found.seat = Some(name);
        }
        if let Some(rank) = MANAGERS.iter().position(|m| *m == interface)
            && found.manager.is_none_or(|(best, _)| rank < best)
        {
            found.manager = Some((rank, name));
        }
    }
    Ok(found)
}

/// Whether the Wayland session offers a data-control clipboard.
pub(super) fn available() -> bool {
    let Some(sock) = connect() else {
        return false;
    };
    let mut wire = Wire::new(sock, std::sync::Arc::new(|| false));
    let until = Instant::now() + ROUNDTRIP;
    wire.send(Msg::new(DISPLAY, 1).u32(REGISTRY), until)
        .and_then(|()| wire.roundtrip())
        .and_then(|events| globals(&events))
        .is_ok_and(|g| g.seat.is_some() && g.manager.is_some())
}

/// Writes `bytes` to a requester's pipe within [`TRANSFER`]. Rust programs
/// ignore SIGPIPE, so a closed reader is an error here, not a signal.
fn write_all(fd: &OwnedFd, bytes: &[u8]) -> bool {
    if rustix::fs::fcntl_setfl(fd, rustix::fs::OFlags::NONBLOCK).is_err() {
        return false;
    }
    let until = Instant::now() + TRANSFER;
    let mut at = 0;
    while let Some(rest) = bytes.get(at..).filter(|r| !r.is_empty()) {
        if Instant::now() >= until {
            return false;
        }
        match rustix::io::write(fd, rest) {
            Ok(0) => return false,
            Ok(n) => at += n,
            Err(Errno::AGAIN) => wait(fd, PollFlags::OUT, until),
            Err(Errno::INTR) => {}
            Err(_) => return false,
        }
    }
    true
}

/// Our selection while it lasts.
pub(super) struct Owner {
    wire: Wire,
    manager: u32,
    device: u32,
    source: u32,
    delivered: bool,
    lost: bool,
}
impl Owner {
    /// Binds the seat and manager and makes our source the selection. Any
    /// error before this returns leaves nothing owned once the socket closes.
    pub(super) fn start(
        sock: OwnedFd,
        value: &[u8],
        cancel: Cancellation,
    ) -> Result<Self, PlatformError> {
        let mut wire = Wire::new(sock, cancel);
        let until = Instant::now() + ROUNDTRIP;
        wire.send(Msg::new(DISPLAY, 1).u32(REGISTRY), until)?;
        let found = globals(&wire.roundtrip()?)?;
        let (Some(seat_name), Some((rank, manager_name))) = (found.seat, found.manager) else {
            return Err(PlatformError::Unavailable);
        };
        let interface = MANAGERS
            .get(rank)
            .and_then(|m| std::str::from_utf8(m).ok())
            .ok_or(PlatformError::Unavailable)?;
        let (seat, manager, source, device) = (wire.id(), wire.id(), wire.id(), wire.id());
        let bind = |name: u32, interface: &str, id: u32| {
            Msg::new(REGISTRY, 0)
                .u32(name)
                .string(interface)
                .u32(1)
                .u32(id)
        };
        wire.send(bind(seat_name, "wl_seat", seat), until)?;
        wire.send(bind(manager_name, interface, manager), until)?;
        wire.send(Msg::new(manager, 0).u32(source), until)?;
        for mime in TEXT_MIMES.into_iter().chain([HINT_MIME]) {
            wire.send(Msg::new(source, 0).string(mime), until)?;
        }
        wire.send(Msg::new(manager, 1).u32(device).u32(seat), until)?;
        wire.send(Msg::new(device, 0).u32(source), until)?;
        let mut owner = Self {
            wire,
            manager,
            device,
            source,
            delivered: false,
            lost: false,
        };
        // A protocol error (for example no data-control on this seat)
        // surfaces here; requests that arrived meanwhile are served.
        for event in owner.wire.roundtrip()? {
            owner.handle(event, value)?;
        }
        Ok(owner)
    }

    fn handle(&mut self, event: Event, value: &[u8]) -> Result<(), PlatformError> {
        match (event.object, event.opcode) {
            (DISPLAY, 0) => Err(PlatformError::Unavailable),
            (object, 0) if object == self.source => {
                let mime = Args::new(&event.body).string()?.unwrap_or_default();
                let fd = self
                    .wire
                    .fds
                    .pop_front()
                    .ok_or(PlatformError::Unavailable)?;
                if mime == HINT_MIME.as_bytes() {
                    let _ = write_all(&fd, b"secret");
                } else if TEXT_MIMES.iter().any(|m| m.as_bytes() == mime) && write_all(&fd, value) {
                    // 0008 §3: the whole value reached the requester's pipe.
                    self.delivered = true;
                }
                Ok(()) // closing `fd` ends the transfer
            }
            (object, 1) if object == self.source => {
                self.lost = true;
                Ok(())
            }
            (object, 2) if object == self.device => Err(PlatformError::Unavailable),
            _ => Ok(()), // other objects: offers of the current selection
        }
    }

    /// Serves requests until expiry, cancellation or replacement.
    pub(super) fn serve(
        &mut self,
        value: &[u8],
        timeout: Duration,
        progress: &mut dyn FnMut(u64) -> Result<(), PlatformError>,
    ) -> Result<(), PlatformError> {
        let end = Instant::now() + timeout;
        let mut last = None;
        loop {
            if self.lost {
                return if self.delivered {
                    Ok(())
                } else {
                    Err(PlatformError::ClipboardReplaced)
                };
            }
            let now = Instant::now();
            if now >= end {
                return Ok(());
            }
            let left = end.saturating_duration_since(now).as_secs() + 1;
            if last != Some(left) {
                progress(left)?;
                last = Some(left);
            }
            if let Some(event) = self.wire.next((now + SLICE).min(end))? {
                self.handle(event, value)?;
            }
        }
    }

    /// Destroys our objects; the compositor drops the selection only if it
    /// is still ours. Closing the socket does the same if a send fails.
    pub(super) fn finish(self) -> Result<(), PlatformError> {
        let until = Instant::now() + Duration::from_millis(250);
        let result = self
            .wire
            .send(Msg::new(self.source, 1), until)
            .and_then(|()| self.wire.send(Msg::new(self.device, 1), until))
            .and_then(|()| self.wire.send(Msg::new(self.manager, 2), until));
        drop(self.wire);
        result
    }
}

#[cfg(test)]
mod tests {
    // Tests intentionally fail loudly on fixture errors.
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage};
    use std::io::IoSlice;
    use std::sync::Arc;

    fn pair() -> (OwnedFd, OwnedFd) {
        let (a, b) = rustix::net::socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .unwrap();
        rustix::fs::fcntl_setfl(&a, rustix::fs::OFlags::NONBLOCK).unwrap();
        (a, b)
    }
    fn never() -> Cancellation {
        Arc::new(|| false)
    }

    /// A scripted compositor on the other end of a socket pair.
    struct Fake {
        sock: OwnedFd,
        input: Vec<u8>,
    }
    impl Fake {
        fn request(&mut self) -> (u32, u16, Vec<u8>) {
            loop {
                if let Some(e) = parse(&mut self.input).unwrap() {
                    return (e.object, e.opcode, e.body);
                }
                let mut buf = [0u8; 4096];
                let n = rustix::io::read(&self.sock, &mut buf).unwrap();
                assert!(n > 0, "client closed early");
                self.input.extend_from_slice(&buf[..n]);
            }
        }
        fn event(&self, msg: Msg, fd: Option<&OwnedFd>) {
            let bytes = msg.bytes();
            let fds: Vec<_> = fd.iter().map(|f| f.as_fd()).collect();
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = SendAncillaryBuffer::new(&mut space);
            if !fds.is_empty() {
                assert!(control.push(SendAncillaryMessage::ScmRights(&fds)));
            }
            rustix::net::sendmsg(
                &self.sock,
                &[IoSlice::new(&bytes)],
                &mut control,
                SendFlags::empty(),
            )
            .unwrap();
        }
        fn done(&mut self) -> u32 {
            let (object, opcode, body) = self.request();
            assert_eq!((object, opcode), (DISPLAY, 0), "expected sync");
            let callback = Args::new(&body).u32().unwrap();
            self.event(Msg::new(callback, 0).u32(0), None);
            callback
        }
        /// Answers the registry; `managers` are advertised after a seat.
        fn globals(&mut self, managers: &[&str]) {
            assert_eq!(self.request().0, DISPLAY); // get_registry
            self.event(Msg::new(REGISTRY, 0).u32(1).string("wl_seat").u32(7), None);
            for (i, m) in managers.iter().enumerate() {
                self.event(
                    Msg::new(REGISTRY, 0).u32(10 + i as u32).string(m).u32(1),
                    None,
                );
            }
            self.done();
        }
        /// Expects the binds and selection setup; returns (source, manager name bound).
        fn setup(&mut self) -> (u32, Vec<u8>) {
            let (_, _, seat) = self.request();
            let mut a = Args::new(&seat);
            assert_eq!(a.u32().unwrap(), 1);
            assert_eq!(a.string().unwrap().unwrap(), b"wl_seat");
            let (_, _, manager) = self.request();
            let mut a = Args::new(&manager);
            a.u32().unwrap();
            let interface = a.string().unwrap().unwrap().to_vec();
            let (_, op, body) = self.request();
            assert_eq!(op, 0);
            let source = Args::new(&body).u32().unwrap();
            let mut offered = Vec::new();
            for _ in 0..6 {
                let (object, op, body) = self.request();
                assert_eq!((object, op), (source, 0));
                offered.push(Args::new(&body).string().unwrap().unwrap().to_vec());
            }
            assert!(offered.iter().any(|m| m == b"UTF8_STRING"));
            assert!(offered.iter().any(|m| m == HINT_MIME.as_bytes()));
            let (_, op, _) = self.request(); // get_data_device
            assert_eq!(op, 1);
            let (_, op, body) = self.request(); // set_selection
            assert_eq!(op, 0);
            assert_eq!(Args::new(&body).u32().unwrap(), source);
            self.done();
            (source, interface)
        }
        /// Sends a paste request and returns what the client wrote.
        fn paste(&self, source: u32, mime: &str) -> Vec<u8> {
            let (read, write) = rustix::pipe::pipe().unwrap();
            self.event(Msg::new(source, 0).string(mime), Some(&write));
            drop(write);
            let mut out = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                let n = rustix::io::read(&read, &mut buf).unwrap();
                if n == 0 {
                    return out;
                }
                out.extend_from_slice(&buf[..n]);
            }
        }
    }

    fn client(
        sock: OwnedFd,
        value: &'static [u8],
        timeout: Duration,
    ) -> std::thread::JoinHandle<Result<(), PlatformError>> {
        std::thread::spawn(move || {
            let mut owner = Owner::start(sock, value, never())?;
            let result = owner.serve(value, timeout, &mut |_| Ok(()));
            owner.finish().and(result)
        })
    }

    #[test]
    fn wayland_clipboard_serves_text_and_hint_then_reports_delivery() {
        let (mine, theirs) = pair();
        let worker = client(mine, b"hunter2", Duration::from_secs(30));
        let mut fake = Fake {
            sock: theirs,
            input: Vec::new(),
        };
        fake.globals(&[
            "zwlr_data_control_manager_v1",
            "ext_data_control_manager_v1",
        ]);
        let (source, interface) = fake.setup();
        assert_eq!(
            interface, b"ext_data_control_manager_v1",
            "ext preferred over wlr"
        );
        assert_eq!(fake.paste(source, HINT_MIME), b"secret");
        assert_eq!(fake.paste(source, "image/png"), b"");
        assert_eq!(fake.paste(source, "text/plain;charset=utf-8"), b"hunter2");
        fake.event(Msg::new(source, 1), None); // cancelled: a successor copied
        // The client destroys source, device and manager on the way out.
        let ops: Vec<_> = (0..3)
            .map(|_| fake.request())
            .map(|(o, op, _)| (o, op))
            .collect();
        assert_eq!(ops[0], (source, 1));
        assert_eq!(worker.join().unwrap(), Ok(()));
    }

    #[test]
    fn wayland_clipboard_replacement_before_delivery_is_reported() {
        let (mine, theirs) = pair();
        let worker = client(mine, b"hunter2", Duration::from_secs(30));
        let mut fake = Fake {
            sock: theirs,
            input: Vec::new(),
        };
        fake.globals(&["zwlr_data_control_manager_v1"]);
        let (source, interface) = fake.setup();
        assert_eq!(interface, b"zwlr_data_control_manager_v1");
        // Only the hint was read: that is not a delivery.
        assert_eq!(fake.paste(source, HINT_MIME), b"secret");
        fake.event(Msg::new(source, 1), None);
        assert_eq!(
            worker.join().unwrap(),
            Err(PlatformError::ClipboardReplaced)
        );
    }

    #[test]
    fn wayland_clipboard_without_data_control_fails_before_owning() {
        let (mine, theirs) = pair();
        let worker = client(mine, b"hunter2", Duration::from_secs(30));
        let mut fake = Fake {
            sock: theirs,
            input: Vec::new(),
        };
        fake.globals(&[]);
        assert_eq!(
            worker.join().unwrap().err(),
            Some(PlatformError::Unavailable)
        );
    }

    #[test]
    fn wayland_clipboard_expiry_destroys_its_source() {
        let (mine, theirs) = pair();
        let worker = client(mine, b"hunter2", Duration::from_secs(1));
        let mut fake = Fake {
            sock: theirs,
            input: Vec::new(),
        };
        fake.globals(&["ext_data_control_manager_v1"]);
        let (source, _) = fake.setup();
        assert_eq!(fake.request().0, source); // source.destroy at expiry
        assert_eq!(worker.join().unwrap(), Ok(()));
    }

    #[test]
    fn wayland_clipboard_protocol_error_fails() {
        let (mine, theirs) = pair();
        let worker = client(mine, b"hunter2", Duration::from_secs(30));
        let mut fake = Fake {
            sock: theirs,
            input: Vec::new(),
        };
        assert_eq!(fake.request().0, DISPLAY); // get_registry
        fake.event(Msg::new(DISPLAY, 0).u32(1).u32(0).string("bad"), None);
        assert_eq!(
            worker.join().unwrap().err(),
            Some(PlatformError::Unavailable)
        );
    }

    #[test]
    fn wayland_messages_are_bounded_and_strings_checked() {
        let header = |object: u32, size: u32| {
            let mut b = object.to_ne_bytes().to_vec();
            b.extend_from_slice(&(size << 16).to_ne_bytes());
            b
        };
        for size in [0, 4, 6, 4100, 8192] {
            assert!(parse(&mut header(1, size)).is_err(), "size {size}");
        }
        // Incomplete messages wait for more input.
        assert!(parse(&mut header(1, 16)).unwrap().is_none());
        assert!(parse(&mut vec![1, 0, 0]).unwrap().is_none());
        // A string must fit its body and end in NUL.
        let mut long = 64u32.to_ne_bytes().to_vec();
        long.extend_from_slice(b"abcd");
        assert!(Args::new(&long).string().is_err());
        let mut unterminated = 4u32.to_ne_bytes().to_vec();
        unterminated.extend_from_slice(b"abcd");
        assert!(Args::new(&unterminated).string().is_err());
        assert_eq!(Args::new(&0u32.to_ne_bytes()).string().unwrap(), None);
        let ok = Msg::new(9, 3).string("abc").bytes();
        let mut input = ok.clone();
        let event = parse(&mut input).unwrap().unwrap();
        assert_eq!((event.object, event.opcode), (9, 3));
        assert_eq!(Args::new(&event.body).string().unwrap(), Some(&b"abc"[..]));
        assert!(input.is_empty());
    }
}
