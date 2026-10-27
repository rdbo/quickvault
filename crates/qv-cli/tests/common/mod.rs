// SPDX-License-Identifier: AGPL-3.0-or-later

//! End-to-end harness: runs the `qvault` binary in a private home, through
//! a PTY (an interactive terminal) or through pipes.
//!
//! Child processes run one at a time (each unlock runs Argon2id with
//! 256 MiB), behind [`serial`]. Vaults for read tests are built with
//! `qv-core` in the test process, using the same anchor directory the
//! binary uses (`$XDG_STATE_HOME/quickvault/anchors`).

#![allow(dead_code)] // each test file uses a different part of the harness

use std::ffi::OsStr;
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use qv_core::{AnchorDir, Core, CoreConfig, MasterPassword, Session};
use rustix::fs::{Mode, OFlags};
use rustix::pty::OpenptFlags;

pub const PASSWORD: &str = "correct horse battery staple, but longer";

static SERIAL: Mutex<()> = Mutex::new(());

/// Serializes child processes and in-process unlocks.
pub fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|p| p.into_inner())
}

/// A private (0700) home directory with config and state directories,
/// removed on drop.
pub struct Home {
    pub root: PathBuf,
}

impl Home {
    pub fn new() -> Home {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let root = std::env::temp_dir().join(format!(
            "qv-cli-e2e-{}-{n}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        for d in ["", "config", "state", "vaults"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(d))
                .unwrap();
        }
        Home { root }
    }

    pub fn vaults(&self) -> PathBuf {
        self.root.join("vaults")
    }

    pub fn vault(&self) -> PathBuf {
        self.vaults().join("v.qvault")
    }

    pub fn anchors(&self) -> PathBuf {
        self.root.join("state").join("quickvault").join("anchors")
    }

    pub fn config_file(&self) -> PathBuf {
        self.root
            .join("config")
            .join("quickvault")
            .join("config.toml")
    }

    /// A core using this home's anchor directory.
    pub fn core(&self) -> Core {
        Core::new(CoreConfig::new(AnchorDir::open(&self.anchors()).unwrap()))
    }

    /// Creates `vault()` with [`PASSWORD`] and returns its session.
    pub fn create(&self) -> Session {
        let _s = serial();
        self.core()
            .create(&self.vault(), &pw(PASSWORD), "Test vault")
            .unwrap()
            .session
    }

    /// Unlocks `vault()` in the test process.
    pub fn unlock(&self) -> Session {
        let _s = serial();
        self.core()
            .unlock(&self.vault(), &pw(PASSWORD), None)
            .unwrap()
    }

    /// `qvault` with only this home's environment.
    pub fn qvault<I, S>(&self, args: I) -> Command
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let mut c = Command::new(env!("CARGO_BIN_EXE_qvault"));
        c.args(args)
            .env_clear()
            .env("HOME", &self.root)
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("TERM", "dumb");
        c
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

pub fn pw(s: &str) -> MasterPassword {
    MasterPassword::from_utf8(s.as_bytes()).unwrap()
}

/// The result of a piped run.
pub struct Output {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `cmd` with pipes, writing `stdin` first.
pub fn piped(mut cmd: Command, stdin: &[u8]) -> Output {
    use std::io::Write;
    let _s = serial();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let mut i = child.stdin.take().unwrap();
        let _ = i.write_all(stdin);
    }
    let out = child.wait_with_output().unwrap();
    Output {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A `qvault` process on a PTY.
pub struct Interactive {
    child: Child,
    master: OwnedFd,
    /// Everything the terminal printed so far.
    pub seen: Vec<u8>,
    _serial: MutexGuard<'static, ()>,
}

const TIMEOUT: Duration = Duration::from_secs(60);

impl Interactive {
    /// Spawns `cmd` with a PTY as stdin, stdout and stderr.
    pub fn spawn(mut cmd: Command) -> Interactive {
        let serial = serial();
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
        let child = cmd
            .stdin(Stdio::from(slave.try_clone().unwrap()))
            .stdout(Stdio::from(slave.try_clone().unwrap()))
            .stderr(Stdio::from(slave))
            .spawn()
            .unwrap();
        // The parent's copies of the slave are closed here (moved into
        // `Stdio`), so the master sees EOF/EIO once the child exits.
        Interactive {
            child,
            master,
            seen: Vec::new(),
            _serial: serial,
        }
    }

    pub fn signal(&self, signal: rustix::process::Signal) {
        let pid = rustix::process::Pid::from_raw(i32::try_from(self.child.id()).unwrap()).unwrap();
        rustix::process::kill_process(pid, signal).unwrap();
    }

    /// Keep an observation descriptor while the child exits, so tests can
    /// inspect restored terminal state. Tests close it before finish drains EOF.
    pub fn terminal_observer(&self) -> OwnedFd {
        let name = rustix::pty::ptsname(&self.master, Vec::new()).unwrap();
        rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY,
            Mode::empty(),
        )
        .unwrap()
    }

    pub fn wait_exited(&mut self) {
        let deadline = Instant::now() + TIMEOUT;
        while self.child.try_wait().unwrap().is_none() {
            self.read_some(Duration::from_millis(20));
            assert!(
                Instant::now() < deadline,
                "timed out waiting for cancelled process"
            );
        }
    }

    /// Reads what is available within `wait`; `false` once the child has
    /// closed the terminal.
    fn read_some(&mut self, wait: Duration) -> bool {
        let mut fds = [rustix::event::PollFd::new(
            &self.master,
            rustix::event::PollFlags::IN,
        )];
        let ts = rustix::event::Timespec {
            tv_sec: i64::try_from(wait.as_secs()).unwrap(),
            tv_nsec: i64::from(wait.subsec_nanos()),
        };
        match rustix::event::poll(&mut fds, Some(&ts)) {
            Ok(0) => return true,
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => return true,
            Err(e) => panic!("poll: {e}"),
        }
        let mut b = [0u8; 4096];
        match rustix::io::read(self.master.as_fd(), &mut b) {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                self.seen.extend_from_slice(&b[..n]);
                true
            }
        }
    }

    /// Waits until `needle` has been printed after position `from`; returns
    /// the position just after it.
    pub fn expect_from(&mut self, from: usize, needle: &str) -> usize {
        let deadline = Instant::now() + TIMEOUT;
        loop {
            if let Some(i) = find(&self.seen[from.min(self.seen.len())..], needle.as_bytes()) {
                return from + i + needle.len();
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {needle:?}; seen: {:?}",
                String::from_utf8_lossy(&self.seen)
            );
            if !self.read_some(Duration::from_millis(200)) {
                // Drain what is left, then one last check.
                if let Some(i) = find(&self.seen[from.min(self.seen.len())..], needle.as_bytes()) {
                    return from + i + needle.len();
                }
                panic!(
                    "the terminal closed before {needle:?}; seen: {:?}",
                    String::from_utf8_lossy(&self.seen)
                );
            }
        }
    }

    /// Waits for `needle` anywhere in the output.
    pub fn expect(&mut self, needle: &str) -> usize {
        self.expect_from(0, needle)
    }

    pub fn send(&self, b: &[u8]) {
        let mut b = b;
        while !b.is_empty() {
            let n = rustix::io::write(&self.master, b).unwrap();
            b = &b[n..];
        }
    }

    /// Sends a line (ended with Enter).
    pub fn line(&self, s: &str) {
        self.send(s.as_bytes());
        self.send(b"\r");
    }

    /// Waits for the process to exit; returns its code and all output.
    pub fn finish(mut self) -> (i32, String) {
        let deadline = Instant::now() + TIMEOUT;
        while self.read_some(Duration::from_millis(100)) {
            if let Ok(Some(_)) = self.child.try_wait() {
                // Collect what remains.
                while self.read_some(Duration::from_millis(50)) {}
                break;
            }
            assert!(Instant::now() < deadline, "timed out waiting for exit");
        }
        let status = self.child.wait().unwrap();
        (
            status.code().unwrap_or(-1),
            String::from_utf8_lossy(&self.seen).into_owned(),
        )
    }
}

impl Drop for Interactive {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Writes the config file.
pub fn write_config(home: &Home, text: &str) {
    let dir = home.config_file().parent().unwrap().to_owned();
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)
        .unwrap();
    std::fs::write(home.config_file(), text).unwrap();
}

/// The vault path as a string argument.
pub fn arg(p: &Path) -> String {
    p.to_str().unwrap().to_owned()
}
