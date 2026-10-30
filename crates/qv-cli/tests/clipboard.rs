// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production clipboard commands run only against a private Xvfb server.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;
use common::{Home, PASSWORD, arg, pw};
use qv_core::{FieldKind, FieldValue};
use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use x11rb::{
    CURRENT_TIME, NONE,
    connection::Connection,
    protocol::{Event, xproto::*},
    rust_connection::RustConnection,
    wrapper::ConnectionExt as _,
};

struct Display {
    child: Child,
    name: String,
}
impl Display {
    fn new() -> Self {
        let bin = std::env::var_os("QV_TEST_XVFB").unwrap_or_else(|| "Xvfb".into());
        let mut child = Command::new(bin)
            .args([
                "-displayfd",
                "1",
                "-screen",
                "0",
                "800x600x24",
                "-nolisten",
                "tcp",
                "-ac",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("isolated clipboard tests require Xvfb (QV_TEST_XVFB may name it)");
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let r = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send((r, line));
        });
        let line = match rx.recv_timeout(Duration::from_secs(10)) {
            Ok((Ok(n), line)) if n > 0 => line,
            other => {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!(
                    "Xvfb startup {other:?}: {}",
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        };
        reader.join().unwrap();
        let name = format!(":{}", line.trim().parse::<u32>().unwrap());
        Self { child, name }
    }
    fn client(&self) -> Client {
        Client::new(&self.name)
    }
}
impl Drop for Display {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct Client {
    conn: RustConnection,
    window: Window,
    clipboard: Atom,
    property: Atom,
    utf8: Atom,
    incr: Atom,
}
impl Client {
    fn new(display: &str) -> Self {
        let (conn, screen) = x11rb::connect(Some(display)).unwrap();
        let window = conn.generate_id().unwrap();
        conn.create_window(
            0,
            window,
            conn.setup().roots[screen].root,
            0,
            0,
            1,
            1,
            0,
            WindowClass::INPUT_ONLY,
            0,
            &CreateWindowAux::new().event_mask(EventMask::PROPERTY_CHANGE),
        )
        .unwrap()
        .check()
        .unwrap();
        let atom = |name: &[u8]| conn.intern_atom(false, name).unwrap().reply().unwrap().atom;
        let clipboard = atom(b"CLIPBOARD");
        let property = atom(b"QV_TEST_OUTPUT");
        let utf8 = atom(b"UTF8_STRING");
        let incr = atom(b"INCR");
        Self {
            conn,
            window,
            clipboard,
            property,
            utf8,
            incr,
        }
    }
    fn atom(&self, name: &[u8]) -> Atom {
        self.conn
            .intern_atom(false, name)
            .unwrap()
            .reply()
            .unwrap()
            .atom
    }
    fn owner(&self) -> Window {
        self.conn
            .get_selection_owner(self.clipboard)
            .unwrap()
            .reply()
            .unwrap()
            .owner
    }
    fn event(&self) -> Event {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(e) = self.conn.poll_for_event().unwrap() {
                return e;
            }
            assert!(Instant::now() < end, "clipboard event timeout");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn request(&self, target: Atom) -> GetPropertyReply {
        while self.conn.poll_for_event().unwrap().is_some() {}
        self.conn
            .convert_selection(
                self.window,
                self.clipboard,
                target,
                self.property,
                CURRENT_TIME,
            )
            .unwrap()
            .check()
            .unwrap();
        loop {
            if let Event::SelectionNotify(e) = self.event() {
                assert_ne!(e.property, NONE, "selection conversion refused");
                return self
                    .conn
                    .get_property(false, self.window, self.property, AtomEnum::ANY, 0, 262_144)
                    .unwrap()
                    .reply()
                    .unwrap();
            }
        }
    }
    fn notify(&self, target: Atom) -> SelectionNotifyEvent {
        while self.conn.poll_for_event().unwrap().is_some() {}
        self.conn
            .convert_selection(
                self.window,
                self.clipboard,
                target,
                self.property,
                CURRENT_TIME,
            )
            .unwrap()
            .check()
            .unwrap();
        loop {
            if let Event::SelectionNotify(event) = self.event() {
                return event;
            }
        }
    }
    fn text(&self) -> Vec<u8> {
        let first = self.request(self.utf8);
        if first.type_ != self.incr {
            assert_eq!(first.type_, self.utf8);
            return first.value;
        }
        self.conn
            .delete_property(self.window, self.property)
            .unwrap()
            .check()
            .unwrap();
        let mut value = Vec::new();
        loop {
            if let Event::PropertyNotify(e) = self.event() {
                if e.atom != self.property || e.state != Property::NEW_VALUE {
                    continue;
                }
                let p = self
                    .conn
                    .get_property(true, self.window, self.property, AtomEnum::ANY, 0, 262_144)
                    .unwrap()
                    .reply()
                    .unwrap();
                if p.type_ != self.utf8 {
                    continue;
                }
                if p.value.is_empty() {
                    return value;
                }
                value.extend(p.value);
                assert!(value.len() <= 256 * 1024);
            }
        }
    }
    fn replace(&self) {
        self.conn
            .set_selection_owner(self.window, self.clipboard, CURRENT_TIME)
            .unwrap()
            .check()
            .unwrap();
        assert_eq!(self.owner(), self.window);
    }
}
struct Run {
    child: Child,
}
impl Run {
    fn start(home: &Home, display: &Display, args: &[&str], password: bool) -> Self {
        let mut child = home
            .qvault(args)
            .env("DISPLAY", &display.name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if password {
            child
                .stdin
                .as_mut()
                .unwrap()
                .write_all(format!("{PASSWORD}\n").as_bytes())
                .unwrap();
        }
        drop(child.stdin.take());
        Self { child }
    }
    fn ready(&mut self, c: &Client) {
        let end = Instant::now() + Duration::from_secs(10);
        while c.owner() == NONE {
            if self.child.try_wait().unwrap().is_some() {
                self.failed();
            }
            assert!(Instant::now() < end, "owner did not become ready");
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn failed(&mut self) -> ! {
        let mut stderr = String::new();
        use std::io::Read;
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        panic!("clipboard command ended early: {stderr}");
    }
    fn finish(mut self, code: i32) -> (String, String) {
        let end = Instant::now() + Duration::from_secs(10);
        while self.child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < end, "clipboard command failed to finish");
            std::thread::sleep(Duration::from_millis(10));
        }
        use std::io::Read;
        let mut stdout = String::new();
        let mut stderr = String::new();
        self.child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut stdout)
            .unwrap();
        self.child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert_eq!(self.child.wait().unwrap().code(), Some(code), "{stderr}");
        assert!(stdout.is_empty(), "copy must not print the value");
        (stdout, stderr)
    }
    fn signal(&self, signal: rustix::process::Signal) {
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(i32::try_from(self.child.id()).unwrap()).unwrap(),
            signal,
        )
        .unwrap();
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// 0012 §1: CLI argument leakage
#[test]
fn clipboard_binary_lifecycle_and_key_drop() {
    let _serial = common::serial();
    let display = Display::new();
    let c = display.client();
    let h = Home::new();
    let s = h
        .core()
        .create(&h.vault(), &pw(PASSWORD), "Clipboard test")
        .unwrap()
        .session;
    let mut draft = s.new_entry(s.root().unwrap(), "login", "Mail").unwrap();
    draft
        .add_field(
            "password",
            FieldKind::Secret,
            FieldValue::text("clipboard-marker-Δ\nsecret").unwrap(),
        )
        .unwrap();
    draft
        .add_field("empty", FieldKind::Secret, FieldValue::text("").unwrap())
        .unwrap();
    draft
        .add_field(
            "large",
            FieldKind::Secret,
            FieldValue::text(&"x".repeat(256 * 1024)).unwrap(),
        )
        .unwrap();
    draft
        .add_field(
            "OTP",
            FieldKind::Totp,
            FieldValue::text("otpauth://totp/Test?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
                .unwrap(),
        )
        .unwrap();
    let entry = s.save_entry(draft).unwrap();
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    let vault = arg(&h.vault());
    let mut run = Run::start(
        &h,
        &display,
        &[
            "--password-stdin",
            "-v",
            &vault,
            "copy",
            "Mail",
            "--timeout",
            "3",
        ],
        true,
    );
    run.ready(&c);
    let targets = c.request(c.atom(b"TARGETS"));
    let targets: Vec<_> = targets.value32().unwrap().collect();
    assert!(targets.contains(&c.atom(b"x-kde-passwordManagerHint")));
    assert!(!targets.contains(&c.atom(b"SAVE_TARGETS")));
    assert_eq!(
        c.request(c.atom(b"x-kde-passwordManagerHint")).value,
        b"secret"
    );
    assert_eq!(c.text(), "clipboard-marker-Δ\nsecret".as_bytes());
    // A second process/core can open and write while the CLI is still serving.
    let s = h.core().unlock(&h.vault(), &pw(PASSWORD), None).unwrap();
    assert_eq!(s.overview().unwrap().local_seq, seq);
    let mut d = s
        .edit_entry(
            s.find_id(&entry.id_hex(), false)
                .unwrap()
                .into_iter()
                .find_map(|h| {
                    if let qv_core::ItemHandle::Entry(e) = h {
                        Some(e)
                    } else {
                        None
                    }
                })
                .unwrap(),
        )
        .unwrap();
    d.entry_mut().title = qv_core::Text::new("Renamed").unwrap();
    s.save_entry(d).unwrap();
    drop(s);
    let (_, stderr) = run.finish(0);
    assert!(!stderr.contains("clipboard-marker"));
    assert_eq!(c.owner(), NONE);
    for field in ["empty", "large"] {
        let mut run = Run::start(
            &h,
            &display,
            &[
                "--password-stdin",
                "-v",
                &vault,
                "copy",
                "Renamed",
                field,
                "--timeout",
                "2",
            ],
            true,
        );
        run.ready(&c);
        let value = c.text();
        assert_eq!(value.len(), if field == "empty" { 0 } else { 256 * 1024 });
        run.finish(0);
        assert_eq!(c.owner(), NONE);
    }
    for signal in [
        rustix::process::Signal::INT,
        rustix::process::Signal::TERM,
        rustix::process::Signal::HUP,
    ] {
        let mut run = Run::start(
            &h,
            &display,
            &[
                "--password-stdin",
                "-v",
                &vault,
                "copy",
                "Renamed",
                "--timeout",
                "20",
            ],
            true,
        );
        run.ready(&c);
        run.signal(signal);
        run.finish(1);
        assert_eq!(c.owner(), NONE);
    }
    common::write_config(&h, "clipboard_timeout = 2\n");
    let mut run = Run::start(&h, &display, &["generate", "--copy", "--pin", "12"], false);
    run.ready(&c);
    let value = c.text();
    assert_eq!(value.len(), 12);
    assert!(value.iter().all(u8::is_ascii_digit));
    let (_, stderr) = run.finish(0);
    assert!(stderr.contains("bits"));
    assert!(!stderr.contains(std::str::from_utf8(&value).unwrap()));
    let mut run = Run::start(
        &h,
        &display,
        &[
            "--password-stdin",
            "-v",
            &vault,
            "totp",
            "Renamed",
            "--copy",
        ],
        true,
    );
    run.ready(&c);
    let value = c.text();
    assert_eq!(value.len(), 6);
    assert!(value.iter().all(u8::is_ascii_digit));
    run.finish(0);
    // Replace immediately and close to expiry. Cleanup must preserve this exact owner.
    for delay in [0, 1800] {
        let successor = display.client();
        let mut run = Run::start(&h, &display, &["generate", "--copy", "--pin", "12"], false);
        run.ready(&c);
        std::thread::sleep(Duration::from_millis(delay));
        // Store identical bytes too: cleanup must use ownership, never string equality.
        let value = c.text();
        successor
            .conn
            .change_property8(
                PropMode::REPLACE,
                successor.window,
                successor.property,
                successor.utf8,
                &value,
            )
            .unwrap()
            .check()
            .unwrap();
        successor.replace();
        run.finish(0);
        assert_eq!(successor.owner(), successor.window);
        successor
            .conn
            .destroy_window(successor.window)
            .unwrap()
            .check()
            .unwrap();
    }
}

#[test]
fn copy_preflight_rejects_before_unlock() {
    let h = Home::new();
    for args in [
        vec!["--json", "copy", "Mail"],
        vec!["--json", "generate", "--copy"],
        vec!["--json", "totp", "Mail", "--copy"],
        vec!["copy", "Mail", "--timeout", "0"],
        vec!["copy", "Mail", "--timeout", "301"],
    ] {
        let out = common::piped(h.qvault(args), b"");
        assert_eq!(out.code, 2, "{}", out.stderr);
        assert!(!out.stderr.contains("Master password"));
    }
    let out = common::piped(h.qvault(["generate", "--copy"]), b"");
    assert_eq!(out.code, 1);
    assert!(out.stdout.is_empty());
    assert!(!out.stderr.contains("panicked"));
}

#[test]
fn clipboard_incr_refusals_limits_and_expiry() {
    let _serial = common::serial();
    let display = Display::new();
    let observer = display.client();
    let h = Home::new();
    let s = h
        .core()
        .create(&h.vault(), &pw(PASSWORD), "Transfer test")
        .unwrap()
        .session;
    let mut d = s.new_entry(s.root().unwrap(), "login", "Large").unwrap();
    d.add_field(
        "payload",
        FieldKind::Secret,
        FieldValue::text(&"z".repeat(64 * 1024)).unwrap(),
    )
    .unwrap();
    d.add_field(
        "binary",
        FieldKind::Secret,
        FieldValue::bytes(&[0xff]).unwrap(),
    )
    .unwrap();
    for value in ["a", "b"] {
        d.add_field(
            "duplicate",
            FieldKind::Text,
            FieldValue::text(value).unwrap(),
        )
        .unwrap();
    }
    s.save_entry(d).unwrap();
    s.save_entry(s.new_entry(s.root().unwrap(), "note", "NoSecret").unwrap())
        .unwrap();
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    let vault = arg(&h.vault());
    for (entry, field, code) in [
        ("Large", "missing", 4),
        ("Large", "duplicate", 5),
        ("Large", "binary", 2),
        ("NoSecret", "", 4),
    ] {
        let mut args = vec!["--password-stdin", "-v", &vault, "copy", entry];
        if !field.is_empty() {
            args.push(field);
        }
        let run = Run::start(&h, &display, &args, true);
        run.finish(code);
        assert_eq!(observer.owner(), NONE);
    }
    let mut run = Run::start(
        &h,
        &display,
        &[
            "--password-stdin",
            "-v",
            &vault,
            "copy",
            "Large",
            "--timeout",
            "20",
        ],
        true,
    );
    run.ready(&observer);
    let clients: Vec<_> = (0..16).map(|_| display.client()).collect();
    for c in &clients {
        assert_eq!(c.request(c.utf8).type_, c.incr);
    }
    assert_eq!(clients[0].notify(clients[0].utf8).property, NONE); // duplicate key
    assert_eq!(
        clients[0]
            .conn
            .get_property(
                false,
                clients[0].window,
                clients[0].property,
                AtomEnum::ANY,
                0,
                4
            )
            .unwrap()
            .reply()
            .unwrap()
            .type_,
        clients[0].incr
    );
    let extra = display.client();
    assert_eq!(extra.notify(extra.utf8).property, NONE);
    assert_eq!(extra.notify(extra.atom(b"MULTIPLE")).property, NONE);
    assert_eq!(extra.notify(extra.atom(b"SAVE_TARGETS")).property, NONE);
    // Synthetic SelectionRequest/SelectionClear messages are not server ownership events.
    let owner = observer.owner();
    extra
        .conn
        .send_event(
            false,
            owner,
            EventMask::NO_EVENT,
            SelectionRequestEvent {
                response_type: SELECTION_REQUEST_EVENT,
                sequence: 0,
                time: CURRENT_TIME,
                owner,
                requestor: extra.window,
                selection: extra.clipboard,
                target: extra.utf8,
                property: extra.property,
            },
        )
        .unwrap()
        .check()
        .unwrap();
    loop {
        if let Event::SelectionNotify(e) = extra.event() {
            assert_eq!(e.property, NONE);
            break;
        }
    }
    extra
        .conn
        .send_event(
            false,
            owner,
            EventMask::NO_EVENT,
            SelectionClearEvent {
                response_type: SELECTION_CLEAR_EVENT,
                sequence: 0,
                time: CURRENT_TIME,
                owner,
                selection: extra.clipboard,
            },
        )
        .unwrap()
        .check()
        .unwrap();
    clients[0]
        .conn
        .destroy_window(clients[0].window)
        .unwrap()
        .check()
        .unwrap();
    assert_eq!(extra.request(extra.utf8).type_, extra.incr); // disappeared requestor freed a slot
    std::thread::sleep(Duration::from_millis(5200));
    assert_eq!(observer.text(), vec![b'z'; 64 * 1024]); // idle transfers released their slots
    run.signal(rustix::process::Signal::TERM);
    run.finish(1);
    assert_eq!(observer.owner(), NONE);
    let s = h.core().unlock(&h.vault(), &pw(PASSWORD), None).unwrap();
    assert_eq!(s.overview().unwrap().local_seq, seq);
}
