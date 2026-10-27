//! Read X11 packets from a reader

use std::io::{Error, ErrorKind, Result};
use std::{cmp, fmt};

use super::Stream;
use crate::utils::RawFdContainer;
use x11rb_protocol::packet_reader::PacketReader as ProtoPacketReader;

/// A wrapper around a reader that reads X11 packet.
pub(crate) struct PacketReader {
    /// The read buffer to store incoming bytes in.
    read_buffer: Box<[u8]>,
    /// The inner reader that breaks these bytes into packets.
    inner: ProtoPacketReader,
    // QuickVault: validate framing before the protocol reader can resize.
    guard: HeaderGuard,
}

impl fmt::Debug for PacketReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketReader")
            .field(
                "read_buffer",
                &format_args!("[buffer of size {}]", self.read_buffer.len()),
            )
            .field("inner", &self.inner)
            .finish()
    }
}

impl PacketReader {
    /// Create a new `PacketReader` that reads from the given stream.
    pub(crate) fn new() -> Self {
        Self {
            // Buffer size chosen by checking what libxcb does
            read_buffer: vec![0; 4096].into_boxed_slice(),
            inner: ProtoPacketReader::new(),
            guard: HeaderGuard::default(),
        }
    }

    /// Reads as many packets as possible from stream reader without blocking.
    pub(crate) fn try_read_packets(
        &mut self,
        stream: &impl Stream,
        out_packets: &mut Vec<Vec<u8>>,
        fd_storage: &mut Vec<RawFdContainer>,
    ) -> Result<()> {
        let original_length = out_packets.len();
        loop {
            let nread = match stream.read(&mut self.read_buffer, fd_storage) {
                Ok(0) => {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "X11 connection closed",
                    ))
                }
                Ok(n) => n,
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            let mut src = &self.read_buffer[..nread];
            while !src.is_empty() {
                let amount = cmp::min(src.len(), self.inner.remaining_capacity());
                self.guard.feed(&src[..amount])?;
                self.inner.buffer()[..amount].copy_from_slice(&src[..amount]);
                src = &src[amount..];
                if let Some(packet) = self.inner.advance(amount) {
                    out_packets.push(packet);
                }
            }
        }
        crate::trace!(
            "Read {} complete packet(s)",
            out_packets.len() - original_length
        );

        Ok(())
    }
}

// Only framing is inspected here. The upstream parser still decodes packets.
#[derive(Default)]
struct HeaderGuard {
    header: [u8; 32],
    used: usize,
    remaining: usize,
}
impl HeaderGuard {
    fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        if self.used < 32 {
            if bytes.len() > 32 - self.used {
                return Err(ErrorKind::InvalidData.into());
            }
            self.header[self.used..self.used + bytes.len()].copy_from_slice(bytes);
            self.used += bytes.len();
            if self.used == 32 {
                let kind = self.header[0];
                if kind == 1 || kind & 0x7f == 35 {
                    let length = u32::from_ne_bytes(self.header[4..8].try_into().unwrap());
                    self.remaining = usize::try_from(length)
                        .ok()
                        .and_then(|n| n.checked_mul(4))
                        .filter(|n| *n <= 1024 * 1024 - 32)
                        .ok_or_else(|| Error::from(ErrorKind::InvalidData))?;
                }
                if self.remaining == 0 {
                    self.used = 0;
                }
            }
        } else {
            self.remaining = self
                .remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| Error::from(ErrorKind::InvalidData))?;
            if self.remaining == 0 {
                self.used = 0;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::PacketReader;
    use crate::rust_connection::{PollMode, Stream};
    use crate::utils::RawFdContainer;
    use std::cell::RefCell;
    use std::cmp;
    use std::io::{Error, ErrorKind, Result};

    // make a Stream that just reads from a Vec<u8>
    struct TestStream {
        data: RefCell<Vec<u8>>,
    }

    impl TestStream {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: RefCell::new(data),
            }
        }
    }

    impl Stream for TestStream {
        fn read(&self, buf: &mut [u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
            let mut data = self.data.borrow_mut();
            if data.is_empty() {
                return Err(Error::from(ErrorKind::WouldBlock));
            }

            let nread = cmp::min(data.len(), buf.len());
            buf[..nread].copy_from_slice(&data[..nread]);
            let _ = data.drain(..nread);
            Ok(nread)
        }

        fn poll(&self, _: PollMode) -> Result<()> {
            Ok(())
        }

        fn write(&self, _: &[u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
            unreachable!()
        }
    }

    fn test_packet(packet: Vec<u8>) {
        let mut reader = PacketReader::new();
        let original_packet = packet.clone();
        let stream = TestStream::new(packet);

        let mut packets = Vec::new();
        let mut fd_storage = Vec::new();

        reader
            .try_read_packets(&stream, &mut packets, &mut fd_storage)
            .unwrap();

        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0], original_packet);
    }

    #[test]
    fn fixed_size_packet() {
        let packet = vec![0; 32];
        test_packet(packet);
    }

    #[test]
    fn variable_size_packet() {
        let mut len = 120;
        let mut packet = vec![0; len];
        len = (len - 32) / 4;

        // copy len to 4..8
        packet[4..8].copy_from_slice(&(len as u32).to_ne_bytes());
        packet[0] = 1;

        test_packet(packet);
    }

    #[test]
    fn very_large_packet() {
        let mut len = 4800;
        let mut packet = vec![0; len];
        len = (len - 32) / 4;

        // copy len to 4..8
        packet[4..8].copy_from_slice(&(len as u32).to_ne_bytes());
        packet[0] = 1;

        test_packet(packet);
    }
}

#[cfg(test)]
mod qv_tests {
    use super::*;
    #[test]
    fn fragment_and_length_bound() {
        let mut header = [0u8; 32];
        header[0] = 1;
        header[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
        let mut guard = HeaderGuard::default();
        guard.feed(&header[..17]).unwrap();
        assert_eq!(
            guard.feed(&header[17..]).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
        let mut fixed = header;
        fixed[0] = 28;
        HeaderGuard::default().feed(&fixed).unwrap();
        let mut exact = header;
        exact[4..8].copy_from_slice(&((1024u32 * 1024 - 32) / 4).to_ne_bytes());
        let mut guard = HeaderGuard::default();
        guard.feed(&exact).unwrap();
        assert_eq!(guard.remaining, 1024 * 1024 - 32);
        let mut generic = header;
        generic[0] = 35 | 0x80;
        assert!(HeaderGuard::default().feed(&generic).is_err());
    }
    #[test]
    fn maximum_length_rejected_under_memory_limit() {
        if std::env::var_os("QV_X11_LIMIT_CHILD").is_none() {
            let status = std::process::Command::new("sh")
                .args(["-c", "ulimit -v 65536; exec \"$@\"", "qv-limit"])
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "rust_connection::packet_reader::qv_tests::maximum_length_rejected_under_memory_limit"])
                .env("QV_X11_LIMIT_CHILD", "1").status().unwrap();
            assert!(status.success());
            return;
        }
        struct Input(std::cell::Cell<bool>);
        impl Stream for Input {
            fn poll(&self, _: super::super::PollMode) -> Result<()> {
                Ok(())
            }
            fn write(&self, _: &[u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
                unreachable!()
            }
            fn read(&self, data: &mut [u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
                if self.0.replace(true) {
                    return Err(ErrorKind::WouldBlock.into());
                }
                data[..32].fill(0);
                data[0] = 1;
                data[4..8].copy_from_slice(&u32::MAX.to_ne_bytes());
                Ok(32)
            }
        }
        let mut reader = PacketReader::new();
        assert_eq!(
            reader
                .try_read_packets(
                    &Input(std::cell::Cell::new(false)),
                    &mut vec![],
                    &mut vec![]
                )
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidData
        );
        assert_eq!(reader.inner.remaining_capacity(), 32);
    }
}
