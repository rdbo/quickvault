// SPDX-License-Identifier: AGPL-3.0-or-later

//! Terminal input (spec 0011 §3.1–3.2, §3.7; 0009 §3).
//!
//! Secrets are typed at a terminal prompt with no echo, or (the master
//! password only) read from standard input with `--password-stdin`. Prompts
//! read standard input only when it is a terminal; without one, a command
//! that needs a prompt fails with exit 2. Prompts are written to stderr.
//!
//! The prompt switches the terminal to non-canonical mode with `ECHO`,
//! `ICANON`, `ISIG` and `IEXTEN` off and discards pending input. Ctrl-C then
//! arrives as a byte and cancels; Backspace removes the last character,
//! Ctrl-U clears the line, Enter ends it, and Ctrl-D on an empty line
//! cancels. A guard restores the saved terminal state on every return path.
//! Input goes byte by byte into a locked, zeroizing buffer of fixed size,
//! so it never reallocates; input past the bound is drained to the end of
//! the line and refused (exit 9). Signals are checked between bounded polls;
//! cancellation unwinds through the terminal and alternate-screen guards.

use std::os::fd::BorrowedFd;
use std::time::Duration;

use qv_core::SecretBytes;
use rustix::termios::{LocalModes, OptionalActions, SpecialCodeIndex, Termios};
use zeroize::Zeroizing;

use crate::exit::{CliError, LIMIT, OTHER, USAGE};

/// The longest master password accepted, in bytes.
pub(crate) const MAX_PASSWORD_BYTES: usize = 1024;

/// A short answer (y/N, a recovery word, a command word).
pub(crate) const MAX_ANSWER_BYTES: usize = 64;

/// Typed input in a locked, zeroizing buffer.
pub(crate) struct Typed {
    buf: SecretBytes,
    len: usize,
}

impl Typed {
    /// The bytes typed.
    pub(crate) fn expose(&self) -> &[u8] {
        self.buf.expose_secret().get(..self.len).unwrap_or_default()
    }
}

impl core::fmt::Debug for Typed {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Typed(<redacted>)")
    }
}

/// A terminal: where prompts read and write.
#[derive(Clone, Copy)]
pub(crate) struct Tty<'a> {
    input: BorrowedFd<'a>,
    output: BorrowedFd<'a>,
}

/// Restores the saved terminal state when dropped.
struct RawGuard<'a> {
    fd: BorrowedFd<'a>,
    saved: Termios,
}

impl Drop for RawGuard<'_> {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(self.fd, OptionalActions::Now, &self.saved);
    }
}

fn io_err<E>(_: E) -> CliError {
    CliError::new(OTHER, "terminal input/output error")
}

/// Whether standard input is a terminal.
pub(crate) fn stdin_is_tty() -> bool {
    rustix::termios::isatty(rustix::stdio::stdin())
}

/// Whether standard output is a terminal.
pub(crate) fn stdout_is_tty() -> bool {
    rustix::termios::isatty(rustix::stdio::stdout())
}

/// The process's terminal (stdin for input, stderr for prompts), or exit 2
/// if standard input is not a terminal.
pub(crate) fn stdio_tty() -> Result<Tty<'static>, CliError> {
    if !stdin_is_tty() {
        return Err(CliError::new(
            USAGE,
            "this command needs a terminal to prompt on (standard input is not a terminal)",
        ));
    }
    Ok(Tty {
        input: rustix::stdio::stdin(),
        output: rustix::stdio::stderr(),
    })
}

enum Key {
    Byte(u8),
    Eof,
}

impl<'a> Tty<'a> {
    #[cfg(test)]
    pub(crate) fn new(input: BorrowedFd<'a>, output: BorrowedFd<'a>) -> Self {
        Self { input, output }
    }

    fn raw(&self) -> Result<RawGuard<'a>, CliError> {
        let saved = rustix::termios::tcgetattr(self.input).map_err(io_err)?;
        let mut t = saved.clone();
        t.local_modes -=
            LocalModes::ECHO | LocalModes::ICANON | LocalModes::ISIG | LocalModes::IEXTEN;
        t.special_codes[SpecialCodeIndex::VMIN] = 1;
        t.special_codes[SpecialCodeIndex::VTIME] = 0;
        // `Flush` also discards typed-ahead input, so a key pressed before
        // the question cannot answer it.
        rustix::termios::tcsetattr(self.input, OptionalActions::Flush, &t).map_err(io_err)?;
        Ok(RawGuard {
            fd: self.input,
            saved,
        })
    }

    /// Writes program text (labels) to the terminal.
    pub(crate) fn say(&self, s: &str) -> Result<(), CliError> {
        let mut b = s.as_bytes();
        while !b.is_empty() {
            match rustix::io::write(self.output, b) {
                Ok(0) => return Err(io_err(())),
                Ok(n) => b = b.get(n..).unwrap_or_default(),
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(io_err(e)),
            }
        }
        Ok(())
    }

    fn key(&self) -> Result<Key, CliError> {
        let mut b = Zeroizing::new([0u8; 1]);
        loop {
            readable(self.input)?;
            match rustix::io::read(self.input, &mut b[..]) {
                Ok(0) => return Ok(Key::Eof),
                Ok(_) => return Ok(Key::Byte(b[0])),
                Err(rustix::io::Errno::INTR) => {}
                Err(e) => return Err(io_err(e)),
            }
        }
    }

    /// Prompts for one line. With `echo`, typed characters are shown;
    /// without it, nothing is.
    pub(crate) fn line(&self, label: &str, max: usize, echo: bool) -> Result<Typed, CliError> {
        let guard = self.raw()?;
        self.say(label)?;
        let mut buf = SecretBytes::zeroed(max);
        let mut len = 0usize;
        let mut too_long = false;
        let result = loop {
            let Key::Byte(b) = self.key()? else {
                break Err(CliError::cancelled());
            };
            match b {
                0x03 => break Err(CliError::cancelled()),
                0x04 if len == 0 && !too_long => break Err(CliError::cancelled()),
                b'\r' | b'\n' => break Ok(()),
                0x7f | 0x08 => {
                    if too_long || len == 0 {
                        continue;
                    }
                    let bytes = buf.expose_secret_mut();
                    // Drop UTF-8 continuation bytes, then the lead byte.
                    while len > 0 && bytes.get(len - 1).is_some_and(|x| x & 0xc0 == 0x80) {
                        len -= 1;
                        bytes[len] = 0;
                    }
                    if len > 0 {
                        len -= 1;
                        bytes[len] = 0;
                    }
                    if echo {
                        self.say("\u{8} \u{8}")?;
                    }
                }
                0x15 => {
                    if echo {
                        for _ in 0..len {
                            self.say("\u{8} \u{8}")?;
                        }
                    }
                    buf.expose_secret_mut().iter_mut().for_each(|x| *x = 0);
                    len = 0;
                }
                b if b < 0x20 => {}
                b => {
                    if len >= max {
                        too_long = true;
                        continue;
                    }
                    buf.expose_secret_mut()[len] = b;
                    len += 1;
                    if echo && b.is_ascii() {
                        self.say(core::str::from_utf8(&[b]).unwrap_or_default())?;
                    }
                }
            }
        };
        drop(guard);
        self.say("\n")?;
        result?;
        if too_long {
            return Err(CliError::new(LIMIT, "input too long"));
        }
        Ok(Typed { buf, len })
    }

    /// Prompts for a secret (no echo).
    pub(crate) fn secret(&self, label: &str, max: usize) -> Result<Typed, CliError> {
        self.line(label, max, false)
    }

    /// Bounded multiline notes, with no echo. Enter preserves LF; Ctrl-D
    /// completes the input. Cancellation never returns a partial value.
    pub(crate) fn multiline(&self, label: &str, max: usize) -> Result<Typed, CliError> {
        let guard = self.raw()?;
        self.say(label)?;
        let mut buf = SecretBytes::zeroed(max);
        let mut len = 0;
        let mut too_long = false;
        loop {
            match self.key()? {
                Key::Eof | Key::Byte(0x03) => return Err(CliError::cancelled()),
                Key::Byte(0x04) => break,
                Key::Byte(b) => {
                    if len == max {
                        too_long = true;
                        continue;
                    }
                    buf.expose_secret_mut()[len] = if b == b'\r' { b'\n' } else { b };
                    len += 1;
                }
            }
        }
        drop(guard);
        self.say("\n")?;
        if too_long {
            return Err(CliError::new(LIMIT, "input too long"));
        }
        Ok(Typed { buf, len })
    }

    /// Asks a yes/no question; anything but `y`/`yes` is no.
    pub(crate) fn confirm(&self, question: &str) -> Result<bool, CliError> {
        let a = self.line(&format!("{question} [y/N] "), MAX_ANSWER_BYTES, true)?;
        Ok(matches!(
            a.expose().to_ascii_lowercase().as_slice(),
            b"y" | b"yes"
        ))
    }

    /// Waits for one key press (any key; Ctrl-C cancels).
    pub(crate) fn wait_key(&self, label: &str) -> Result<(), CliError> {
        let guard = self.raw()?;
        self.say(label)?;
        let k = self.key()?;
        drop(guard);
        match k {
            Key::Byte(0x03) | Key::Eof => Err(CliError::cancelled()),
            Key::Byte(_) => Ok(()),
        }
    }

    /// Counts down `secs` seconds on the terminal (0011 §5.4).
    pub(crate) fn countdown(&self, label: &str, secs: u64) -> Result<(), CliError> {
        for left in (1..=secs).rev() {
            self.say(&format!("\r{label} {left} s "))?;
            for _ in 0..10 {
                crate::signals::check()?;
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        self.say("\r\n")
    }
}

/// Wait for data while remaining responsive to cancellation even on a pipe.
fn readable(fd: BorrowedFd<'_>) -> Result<(), CliError> {
    loop {
        crate::signals::check()?;
        let mut fds = [rustix::event::PollFd::new(
            &fd,
            rustix::event::PollFlags::IN,
        )];
        let timeout = rustix::event::Timespec {
            tv_sec: 0,
            tv_nsec: 100_000_000,
        };
        match rustix::event::poll(&mut fds, Some(&timeout)) {
            Ok(0) | Err(rustix::io::Errno::INTR) => continue,
            Ok(_) => {
                crate::signals::check()?;
                return Ok(());
            }
            Err(e) => return Err(io_err(e)),
        }
    }
}

/// Reads the master password for `--password-stdin` (0011 §3.2): the first
/// line of standard input, without one trailing `\n` or `\r\n`. If standard
/// input is a terminal, prompts instead.
pub(crate) fn password_from_stdin(label: &str) -> Result<Typed, CliError> {
    if stdin_is_tty() {
        return stdio_tty()?.secret(label, MAX_PASSWORD_BYTES);
    }
    read_first_line(rustix::stdio::stdin(), MAX_PASSWORD_BYTES)
}

/// The first line of `fd`, at most `max` bytes after removing one trailing
/// `\n` or `\r\n`.
fn read_first_line(fd: BorrowedFd<'_>, max: usize) -> Result<Typed, CliError> {
    // Room for the content plus "\r\n".
    let mut buf = SecretBytes::zeroed(max + 2);
    let mut len = 0usize;
    let mut b = Zeroizing::new([0u8; 1]);
    let mut ended_at_lf = false;
    loop {
        readable(fd)?;
        match rustix::io::read(fd, &mut b[..]) {
            Ok(0) => break,
            Ok(_) if b[0] == b'\n' => {
                ended_at_lf = true;
                break;
            }
            Ok(_) => {
                if len > max {
                    return Err(CliError::new(
                        LIMIT,
                        "the password on standard input is too long",
                    ));
                }
                buf.expose_secret_mut()[len] = b[0];
                len += 1;
            }
            Err(rustix::io::Errno::INTR) => {}
            Err(e) => return Err(io_err(e)),
        }
    }
    if ended_at_lf
        && buf
            .expose_secret()
            .get(..len)
            .is_some_and(|s| s.ends_with(b"\r"))
    {
        len -= 1;
        buf.expose_secret_mut()[len] = 0;
    }
    if len > max {
        return Err(CliError::new(
            LIMIT,
            "the password on standard input is too long",
        ));
    }
    Ok(Typed { buf, len })
}

/// The alternate screen (0011 §3.7): entered on creation, cleared and left
/// when dropped, so what was shown does not stay in the scrollback.
pub(crate) struct AltScreen {
    _private: (),
}

/// Enter the alternate screen, home the cursor and clear it.
pub(crate) const ENTER_ALT: &str = "\u{1b}[?1049h\u{1b}[H\u{1b}[2J";
/// Clear the alternate screen and leave it.
pub(crate) const LEAVE_ALT: &str = "\u{1b}[H\u{1b}[2J\u{1b}[?1049l";

impl AltScreen {
    pub(crate) fn enter() -> Result<Self, CliError> {
        let mut o = crate::out::Out::stdout();
        o.raw(ENTER_ALT);
        o.flush()?;
        Ok(Self { _private: () })
    }
}

impl Drop for AltScreen {
    fn drop(&mut self) {
        let mut o = crate::out::Out::stdout();
        o.raw(LEAVE_ALT);
        let _ = o.flush();
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::fd::{AsFd, OwnedFd};

    use rustix::fs::{Mode, OFlags};
    use rustix::pty::OpenptFlags;

    use super::*;

    /// A PTY pair: the master (the "user") and the slave (the terminal).
    pub(crate) struct Pty {
        pub(crate) master: OwnedFd,
        pub(crate) slave: OwnedFd,
    }

    impl Pty {
        pub(crate) fn new() -> Pty {
            let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY).unwrap();
            rustix::pty::grantpt(&master).unwrap();
            rustix::pty::unlockpt(&master).unwrap();
            let name = rustix::pty::ptsname(&master, Vec::new()).unwrap();
            let slave = rustix::fs::open(
                name.as_c_str(),
                OFlags::RDWR | OFlags::NOCTTY,
                Mode::empty(),
            )
            .unwrap();
            Pty { master, slave }
        }

        pub(crate) fn tty(&self) -> Tty<'_> {
            Tty::new(self.slave.as_fd(), self.slave.as_fd())
        }

        pub(crate) fn send(&self, b: &[u8]) {
            assert_eq!(rustix::io::write(&self.master, b).unwrap(), b.len());
        }

        /// Everything the terminal printed so far (waits up to `ms`).
        pub(crate) fn drain(&self, ms: i32) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                let mut fds = [rustix::event::PollFd::new(
                    &self.master,
                    rustix::event::PollFlags::IN,
                )];
                let ts = rustix::event::Timespec {
                    tv_sec: 0,
                    tv_nsec: i64::from(ms) * 1_000_000,
                };
                if rustix::event::poll(&mut fds, Some(&ts)).unwrap() == 0 {
                    return out;
                }
                let mut b = [0u8; 4096];
                match rustix::io::read(&self.master, &mut b) {
                    Ok(0) | Err(_) => return out,
                    Ok(n) => out.extend_from_slice(&b[..n]),
                }
            }
        }

        fn echo_on(&self) -> bool {
            rustix::termios::tcgetattr(&self.slave)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        }
    }

    /// Runs `f` on the terminal on another thread while the test types.
    fn typed(
        input: &'static [u8],
        f: impl FnOnce(Tty<'_>) -> Result<Typed, CliError> + Send + 'static,
    ) -> (Result<Vec<u8>, CliError>, Vec<u8>, Pty) {
        let pty = std::sync::Arc::new(Pty::new());
        let p = pty.clone();
        let worker = std::thread::spawn(move || f(p.tty()).map(|t| t.expose().to_vec()));
        // Wait until the prompt is up (raw mode set, label written).
        let mut shown = pty.drain(500);
        pty.send(input);
        let r = worker.join().unwrap();
        shown.extend(pty.drain(100));
        let pty = std::sync::Arc::try_unwrap(pty).ok().unwrap();
        (r, shown, pty)
    }

    #[test]
    fn term_secret_prompt_does_not_echo() {
        let (r, shown, pty) = typed(b"hunter2\r", |t| t.secret("Password: ", 64));
        assert_eq!(r.unwrap(), b"hunter2");
        assert_eq!(shown, b"Password: \r\n");
        assert!(pty.echo_on(), "terminal state restored");
    }

    #[test]
    fn term_line_editing() {
        // "caf" + "é" (2 bytes), backspace removes the whole "é".
        let (r, _, _) = typed("cafe\u{301}\u{7f}\u{7f}\u{e9}!\u{8}\r".as_bytes(), |t| {
            t.secret("> ", 64)
        });
        assert_eq!(r.unwrap(), "caf\u{e9}".as_bytes());
        let (r, _, _) = typed(b"wrong\x15right\n", |t| t.secret("> ", 64));
        assert_eq!(r.unwrap(), b"right");
        let (r, _, _) = typed(b"x\x04y\r", |t| t.secret("> ", 64));
        assert_eq!(r.unwrap(), b"xy");
    }

    #[test]
    fn term_cancel_restores_the_terminal() {
        for input in [&b"abc\x03"[..], b"\x04"] {
            let input: &'static [u8] = Box::leak(input.to_vec().into_boxed_slice());
            let (r, _, pty) = typed(input, |t| t.secret("> ", 64));
            assert_eq!(r.unwrap_err(), CliError::cancelled());
            assert!(pty.echo_on());
        }
    }

    #[test]
    fn term_refuses_long_input() {
        let mut long = vec![b'a'; 70];
        long.push(b'\r');
        let input: &'static [u8] = Box::leak(long.into_boxed_slice());
        let (r, _, pty) = typed(input, |t| t.secret("> ", 64));
        assert_eq!(r.unwrap_err().code, 9);
        assert!(pty.echo_on());
    }

    #[test]
    fn term_confirm_echoes() {
        let pty = std::sync::Arc::new(Pty::new());
        let p = pty.clone();
        let w = std::thread::spawn(move || p.tty().confirm("Go?"));
        let mut shown = pty.drain(500);
        pty.send(b"Y\r");
        assert!(w.join().unwrap().unwrap());
        shown.extend(pty.drain(100));
        assert_eq!(shown, b"Go? [y/N] Y\r\n");
        let p = pty.clone();
        let w = std::thread::spawn(move || p.tty().confirm("Go?"));
        pty.drain(500);
        pty.send(b"\r");
        assert!(!w.join().unwrap().unwrap());
    }

    #[test]
    fn term_first_line_of_a_pipe() {
        let line = |input: &[u8], max: usize| {
            let (r, w) = rustix::pipe::pipe().unwrap();
            rustix::io::write(&w, input).unwrap();
            drop(w);
            read_first_line(r.as_fd(), max).map(|t| t.expose().to_vec())
        };
        assert_eq!(line(b"  spaced pw \n", 64).unwrap(), b"  spaced pw ");
        assert_eq!(line(b"crlf\r\nsecond line\n", 64).unwrap(), b"crlf");
        assert_eq!(line(b"no newline", 64).unwrap(), b"no newline");
        assert_eq!(line(b"ends in cr\r", 64).unwrap(), b"ends in cr\r");
        assert_eq!(line(b"two cr\r\r", 64).unwrap(), b"two cr\r\r");
        assert_eq!(line(b"\r", 64).unwrap(), b"\r");
        assert_eq!(line(b"two\n\n", 64).unwrap(), b"two");
        assert_eq!(line(b"cr\r\r\n", 64).unwrap(), b"cr\r");
        assert_eq!(line(b"", 64).unwrap(), b"");
        assert_eq!(line(&[b'a'; 64], 64).unwrap().len(), 64);
        assert_eq!(line(&[b'a'; 65], 64).unwrap_err().code, 9);
        let mut crlf = vec![b'a'; 64];
        crlf.extend_from_slice(b"\r\n");
        assert_eq!(line(&crlf, 64).unwrap().len(), 64);
        // At EOF the CR counts toward the bound; only CR before LF is framing.
        assert_eq!(line(&crlf[..65], 64).unwrap_err().code, 9);
        let mut at_limit = vec![b'a'; 63];
        at_limit.push(b'\r');
        assert_eq!(line(&at_limit, 64).unwrap(), at_limit);
        let mut over_limit = vec![b'a'; 65];
        over_limit.extend_from_slice(b"\r\n");
        assert_eq!(line(&over_limit, 64).unwrap_err().code, 9);
    }
}
