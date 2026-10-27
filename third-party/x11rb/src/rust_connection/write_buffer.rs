use qv_crypto::SecretBytes;
use std::io::IoSlice;

use super::Stream;
use crate::utils::RawFdContainer;

// QuickVault patch: fixed protected ring; consumed slots are wiped immediately.
// No reallocation or plaintext-bearing Debug implementation.
#[derive(Debug)]
struct ProtectedQueue {
    bytes: SecretBytes,
    start: usize,
    len: usize,
}
impl ProtectedQueue {
    fn new(capacity: usize) -> Self {
        Self {
            bytes: SecretBytes::zeroed(capacity),
            start: 0,
            len: 0,
        }
    }
    fn capacity(&self) -> usize {
        self.bytes.len()
    }
    fn len(&self) -> usize {
        self.len
    }
    fn is_empty(&self) -> bool {
        self.len == 0
    }
    fn extend<'a>(&mut self, iter: impl IntoIterator<Item = &'a u8>) {
        for &byte in iter {
            assert!(self.len < self.capacity());
            let at = (self.start + self.len) % self.capacity();
            self.bytes.expose_secret_mut()[at] = byte;
            self.len += 1;
        }
    }
    fn as_slices(&self) -> (&[u8], &[u8]) {
        let first = self.len.min(self.capacity() - self.start);
        let bytes = self.bytes.expose_secret();
        (
            &bytes[self.start..self.start + first],
            &bytes[..self.len - first],
        )
    }
    fn consume(&mut self, n: usize) {
        assert!(n <= self.len);
        for _ in 0..n {
            self.bytes.expose_secret_mut()[self.start] = 0;
            self.start = (self.start + 1) % self.capacity();
            self.len -= 1;
        }
        if self.len == 0 {
            self.start = 0;
        }
    }
    fn clear(&mut self) {
        self.bytes.expose_secret_mut().fill(0);
        self.start = 0;
        self.len = 0;
    }
}

#[derive(Debug)]
pub(super) struct WriteBuffer {
    data_buf: ProtectedQueue,
    fd_buf: Vec<RawFdContainer>,
}

impl WriteBuffer {
    pub(super) fn new() -> Self {
        // Buffer size chosen by checking what libxcb does
        Self::with_capacity(16384)
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            data_buf: ProtectedQueue::new(capacity),
            fd_buf: Vec::new(),
        }
    }

    fn flush_buffer(&mut self, stream: &impl Stream) -> std::io::Result<()> {
        while self.needs_flush() {
            crate::trace!(
                "Trying to flush {} bytes of data and {} FDs",
                self.data_buf.len(),
                self.fd_buf.len()
            );
            let (data_buf_1, data_buf_2) = self.data_buf.as_slices();
            let data_bufs = [IoSlice::new(data_buf_1), IoSlice::new(data_buf_2)];
            match stream.write_vectored(&data_bufs, &mut self.fd_buf) {
                Ok(0) => {
                    if self.data_buf.is_empty() {
                        assert!(!self.fd_buf.is_empty());
                        self.data_buf.clear();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write the buffered FDs",
                        ));
                    } else {
                        self.data_buf.clear();
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "failed to write the buffered data",
                        ));
                    }
                }
                Ok(n) => {
                    crate::trace!("Flushing wrote {} bytes of data", n);
                    self.data_buf.consume(n);
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::WouldBlock {
                        self.data_buf.clear();
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn write_helper<W: Stream, F, G>(
        &mut self,
        stream: &W,
        fds: &mut Vec<RawFdContainer>,
        write_buffer: F,
        write_inner: G,
        first_buffer: &[u8],
        to_write_length: usize,
    ) -> std::io::Result<usize>
    where
        F: FnOnce(&mut ProtectedQueue),
        G: FnOnce(&W, &mut Vec<RawFdContainer>) -> std::io::Result<usize>,
    {
        crate::trace!(
            "Writing {} FDs and {} bytes of data",
            fds.len(),
            to_write_length
        );
        self.fd_buf.append(fds);

        // Is there enough buffer space left for this write?
        if (self.data_buf.capacity() - self.data_buf.len()) < to_write_length {
            // Not enough space, try to flush
            match self.flush_buffer(stream) {
                Ok(_) => {}
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        let available_buf = self.data_buf.capacity() - self.data_buf.len();
                        if available_buf == 0 {
                            // Buffer filled and cannot flush anything without
                            // blocking, so return `WouldBlock`.
                            crate::trace!("Writing failed due to full buffer: {:?}", e);
                            return Err(e);
                        } else {
                            let n_to_write = first_buffer.len().min(available_buf);
                            self.data_buf.extend(&first_buffer[..n_to_write]);
                            // Return `Ok` because some or all data has been buffered,
                            // so from the outside it is seen as a successful write.
                            crate::trace!("Writing appended {} bytes to the buffer", n_to_write);
                            return Ok(n_to_write);
                        }
                    } else {
                        return Err(e);
                    }
                }
            }
        }

        if to_write_length >= self.data_buf.capacity() {
            // Write is larger than the buffer capacity, thus we just flushed the buffer. This
            // means that at this point the buffer is empty. Write directly to self.inner. No data
            // is copied into the buffer, since that would just mean that the large write gets
            // split into multiple smaller ones.
            assert!(self.data_buf.is_empty());
            crate::trace!("Large write is written directly to the stream");
            {
                let result = write_inner(stream, &mut self.fd_buf);
                if result
                    .as_ref()
                    .err()
                    .is_some_and(|e| e.kind() != std::io::ErrorKind::WouldBlock)
                {
                    self.data_buf.clear();
                }
                result
            }
        } else {
            // At this point there is enough space available in the buffer.
            crate::trace!("Data to write is appended to the buffer");
            write_buffer(&mut self.data_buf);
            Ok(to_write_length)
        }
    }

    pub(super) fn write(
        &mut self,
        stream: &impl Stream,
        buf: &[u8],
        fds: &mut Vec<RawFdContainer>,
    ) -> std::io::Result<usize> {
        self.write_helper(
            stream,
            fds,
            |w| w.extend(buf),
            |w, fd| w.write(buf, fd),
            buf,
            buf.len(),
        )
    }

    pub(super) fn write_vectored(
        &mut self,
        stream: &impl Stream,
        bufs: &[IoSlice<'_>],
        fds: &mut Vec<RawFdContainer>,
    ) -> std::io::Result<usize> {
        let first_nonempty = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        let total_len = bufs.iter().map(|b| b.len()).sum();
        self.write_helper(
            stream,
            fds,
            |w| {
                for buf in bufs.iter() {
                    w.extend(&**buf);
                }
            },
            |w, fd| w.write_vectored(bufs, fd),
            first_nonempty,
            total_len,
        )
    }

    /// Returns `true` if there is buffered data or FDs.
    pub(super) fn needs_flush(&self) -> bool {
        !self.data_buf.is_empty() || !self.fd_buf.is_empty()
    }

    pub(super) fn flush(&mut self, stream: &impl Stream) -> std::io::Result<()> {
        let result = self.flush_buffer(stream);
        if result
            .as_ref()
            .err()
            .is_some_and(|e| e.kind() != std::io::ErrorKind::WouldBlock)
        {
            self.data_buf.clear();
        }
        result
    }
}

#[cfg(test)]
mod test {
    use std::io::{Error, ErrorKind, IoSlice, Result};

    use super::super::{PollMode, Stream};
    use super::WriteBuffer;
    use crate::utils::RawFdContainer;

    struct WouldBlockWriter;

    impl Stream for WouldBlockWriter {
        fn poll(&self, _mode: PollMode) -> Result<()> {
            unimplemented!();
        }

        fn read(&self, _buf: &mut [u8], _fd_storage: &mut Vec<RawFdContainer>) -> Result<usize> {
            unimplemented!();
        }

        fn write(&self, _buf: &[u8], _fds: &mut Vec<RawFdContainer>) -> Result<usize> {
            Err(Error::new(ErrorKind::WouldBlock, "would block"))
        }
    }

    // Once upon a time, this paniced because it did bufs[0]
    #[test]
    fn empty_write() {
        let stream = WouldBlockWriter;
        let mut write_buffer = WriteBuffer::new();
        let bufs = &[];
        let _ = write_buffer
            .write_vectored(&stream, bufs, &mut Vec::new())
            .unwrap();
    }

    // Once upon a time, BufWriteFD fell back to only writing the first buffer. This could be
    // mistaken as EOF.
    #[test]
    fn incorrect_eof() {
        let stream = WouldBlockWriter;
        let mut write_buffer = WriteBuffer::with_capacity(1);
        let bufs = &[IoSlice::new(&[]), IoSlice::new(b"fooo")];
        match write_buffer.write_vectored(&stream, bufs, &mut Vec::new()) {
            Ok(0) => panic!("This looks like EOF!?"),
            Ok(_) => {}
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => panic!("Unexpected error: {e:?}"),
        }
    }
}

#[cfg(test)]
mod qv_tests {
    use super::*;
    use std::cell::RefCell;
    use std::io::{Error, ErrorKind, Result};
    struct Writer {
        limit: usize,
        output: RefCell<Vec<u8>>,
        fail: Option<ErrorKind>,
    }
    impl Stream for Writer {
        fn poll(&self, _: super::super::PollMode) -> Result<()> {
            Ok(())
        }
        fn read(&self, _: &mut [u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
            unreachable!()
        }
        fn write(&self, data: &[u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
            if let Some(kind) = self.fail {
                return Err(Error::from(kind));
            }
            let n = data.len().min(self.limit);
            self.output.borrow_mut().extend_from_slice(&data[..n]);
            Ok(n)
        }
    }
    #[test]
    fn protected_ring_wrap_and_wipe() {
        let mut q = ProtectedQueue::new(8);
        q.extend(b"abcdef");
        q.consume(4);
        q.extend(b"ghijkl");
        let (a, b) = q.as_slices();
        assert_eq!([a, b].concat(), b"efghijkl");
        q.consume(8);
        assert!(q.bytes.expose_secret().iter().all(|b| *b == 0));
        assert!(!format!("{q:?}").contains("abcdef"));
    }
    #[test]
    fn partial_vectored_flush_preserves_order_and_wipes() {
        let stream = Writer {
            limit: 2,
            output: RefCell::new(Vec::new()),
            fail: None,
        };
        let mut w = WriteBuffer::with_capacity(16);
        let _ = w
            .write_vectored(
                &stream,
                &[IoSlice::new(b"abc"), IoSlice::new(b"def")],
                &mut vec![],
            )
            .unwrap();
        w.flush(&stream).unwrap();
        assert_eq!(*stream.output.borrow(), b"abcdef");
        assert!(w.data_buf.bytes.expose_secret().iter().all(|b| *b == 0));
    }
    #[test]
    fn wouldblock_retains_and_fatal_error_wipes() {
        let stream = Writer {
            limit: 2,
            output: RefCell::new(Vec::new()),
            fail: Some(ErrorKind::WouldBlock),
        };
        let mut w = WriteBuffer::with_capacity(8);
        let _ = w.write(&stream, b"secret", &mut vec![]).unwrap();
        assert_eq!(w.flush(&stream).unwrap_err().kind(), ErrorKind::WouldBlock);
        assert_eq!(w.data_buf.as_slices().0, b"secret");
        let failed = Writer {
            fail: Some(ErrorKind::BrokenPipe),
            ..stream
        };
        assert_eq!(w.flush(&failed).unwrap_err().kind(), ErrorKind::BrokenPipe);
        assert!(w.data_buf.bytes.expose_secret().iter().all(|b| *b == 0));
    }
}

#[cfg(test)]
mod qv_order_tests {
    use super::*;
    use std::{
        cell::RefCell,
        io::{Error, ErrorKind, Result},
        os::fd::AsRawFd,
    };
    struct Output {
        bytes: RefCell<Vec<u8>>,
        fds: RefCell<Vec<i32>>,
    }
    impl Stream for Output {
        fn poll(&self, _: super::super::PollMode) -> Result<()> {
            Ok(())
        }
        fn read(&self, _: &mut [u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
            unreachable!()
        }
        fn write(&self, data: &[u8], fds: &mut Vec<RawFdContainer>) -> Result<usize> {
            self.fds
                .borrow_mut()
                .extend(fds.drain(..).map(|fd| fd.as_raw_fd()));
            let n = data.len().min(1);
            self.bytes.borrow_mut().extend_from_slice(&data[..n]);
            Ok(n)
        }
    }
    #[test]
    fn fd_order_and_partial_writes() {
        let out = Output {
            bytes: RefCell::new(vec![]),
            fds: RefCell::new(vec![]),
        };
        let a: RawFdContainer = std::fs::File::open("/dev/null").unwrap().into();
        let b: RawFdContainer = std::fs::File::open("/dev/null").unwrap().into();
        let expected = [a.as_raw_fd(), b.as_raw_fd()];
        let mut w = WriteBuffer::with_capacity(8);
        let _ = w.write(&out, b"ab", &mut vec![a]).unwrap();
        let _ = w.write(&out, b"cd", &mut vec![b]).unwrap();
        w.flush(&out).unwrap();
        assert_eq!(*out.bytes.borrow(), b"abcd");
        assert_eq!(*out.fds.borrow(), expected);
        assert!(w.data_buf.bytes.expose_secret().iter().all(|b| *b == 0));
    }
    struct Block;
    impl Stream for Block {
        fn poll(&self, _: super::super::PollMode) -> Result<()> {
            Ok(())
        }
        fn read(&self, _: &mut [u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
            unreachable!()
        }
        fn write(&self, _: &[u8], _: &mut Vec<RawFdContainer>) -> Result<usize> {
            Err(Error::from(ErrorKind::WouldBlock))
        }
    }
    #[test]
    fn backpressure_buffers_only_available_bytes_without_reallocation() {
        let mut w = WriteBuffer::with_capacity(8);
        let address = w.data_buf.bytes.expose_secret().as_ptr();
        assert_eq!(w.write(&Block, b"abcdef", &mut vec![]).unwrap(), 6);
        assert_eq!(w.write(&Block, b"ghijkl", &mut vec![]).unwrap(), 2);
        assert_eq!(
            w.write(&Block, b"x", &mut vec![]).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        assert_eq!(w.data_buf.as_slices().0, b"abcdefgh");
        assert_eq!(w.data_buf.bytes.expose_secret().as_ptr(), address);
    }
}
