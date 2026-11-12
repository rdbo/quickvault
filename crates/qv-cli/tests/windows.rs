// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pipe-driven checks of the Windows `qv` build (plan 0052). The PTY-based
//! end-to-end harness is Linux-only; console prompts (no echo, editing,
//! Ctrl-C) are an attended check in `plans/0052-windows-platform/
//! WINDOWS-GATES.md`. Each run gets a private `%LOCALAPPDATA%` and
//! `%APPDATA%`, so the default anchors and config are the test's own.

#![cfg(windows)]
// The helpers are test code, but clippy's `allow-*-in-tests` settings only
// cover `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::panic)]

use std::ffi::OsStr;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;

use qv_core::{AnchorDir, Core, CoreConfig, FieldKind, FieldValue, MasterPassword};

const PASSWORD: &str = "correct horse battery staple, but longer";

/// One Argon2id run (256 MiB) at a time across this binary's tests.
static SERIAL: Mutex<()> = Mutex::new(());

struct Home {
    root: PathBuf,
}

impl Home {
    fn new(tag: &str) -> Self {
        let root = std::env::temp_dir().join(format!("qv-cli-win-{}-{tag}", std::process::id()));
        for d in ["local", "roaming", "vaults"] {
            qv_core::create_private_dirs(&root.join(d)).unwrap();
        }
        Self { root }
    }

    fn vault(&self) -> PathBuf {
        self.root.join("vaults").join("v.qvault")
    }

    fn anchors(&self) -> PathBuf {
        self.root.join("local").join("QuickVault").join("anchors")
    }

    /// A vault with one login, created in this process with the anchor
    /// directory the binary will use.
    fn create(&self) {
        let _s = SERIAL.lock().unwrap();
        let core = Core::new(CoreConfig::new(AnchorDir::open(&self.anchors()).unwrap()));
        let pw = MasterPassword::from_utf8(PASSWORD.as_bytes()).unwrap();
        let s = core
            .create(&self.vault(), &pw, "Test vault")
            .unwrap()
            .session;
        let root = s.root().unwrap();
        let mut d = s.new_entry(root, "login", "GitHub").unwrap();
        d.add_field(
            "Password",
            FieldKind::Secret,
            FieldValue::text("hunter2-secret").unwrap(),
        )
        .unwrap();
        s.save_entry(d).unwrap();
    }

    fn qv<I: IntoIterator<Item = S>, S: AsRef<OsStr>>(&self, args: I) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_qv"));
        c.args(args)
            .env_clear()
            .env("LOCALAPPDATA", self.root.join("local"))
            .env("APPDATA", self.root.join("roaming"));
        // Windows processes need these to load system libraries.
        for keep in [
            "SystemRoot",
            "SYSTEMROOT",
            "windir",
            "TEMP",
            "TMP",
            "QV_WINE",
        ] {
            if let Some(v) = std::env::var_os(keep) {
                c.env(keep, v);
            }
        }
        c
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Output {
    code: i32,
    stdout: String,
    stderr: String,
}

fn piped(mut cmd: Command, stdin: &[u8]) -> Output {
    let _s = SERIAL.lock().unwrap();
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    Output {
        code: out.status.code().unwrap(),
        stdout: String::from_utf8(out.stdout).unwrap(),
        stderr: String::from_utf8(out.stderr).unwrap(),
    }
}

#[test]
fn windows_qv_runs_and_generates_without_a_vault() {
    let h = Home::new("generate");
    let out = piped(h.qv(["--version"]), b"");
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = piped(h.qv(["generate"]), b"");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.trim().len() >= 16, "{}", out.stdout);
}

#[test]
fn windows_qv_reads_a_vault_with_password_stdin() {
    let h = Home::new("read");
    h.create();
    let vault = h.vault().into_os_string();
    let ls = |input: &[u8]| {
        piped(
            h.qv([
                OsStr::new("--password-stdin"),
                OsStr::new("-v"),
                &vault,
                OsStr::new("ls"),
            ]),
            input,
        )
    };
    let out = ls(format!("{PASSWORD}\r\n").as_bytes());
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("GitHub"), "{}", out.stdout);
    assert!(!out.stdout.contains("hunter2-secret"));
    let wrong = ls(b"not the password\n");
    assert_eq!(wrong.code, 3, "{}", wrong.stderr);
    // A prompt needs a console; piped input without --password-stdin is
    // a usage error, never a read of the pipe.
    let out = piped(h.qv([OsStr::new("-v"), &vault, OsStr::new("ls")]), b"x\n");
    assert_eq!(out.code, 2, "{}", out.stderr);
}
