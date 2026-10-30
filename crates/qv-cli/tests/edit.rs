// SPDX-License-Identifier: AGPL-3.0-or-later

//! Persisted editing and rejected-operation tests through the real binary.
#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;
use common::{Home, Interactive, Output, PASSWORD, arg, piped};
use qv_core::{FieldKind, FieldValue, ItemHandle};

fn run(h: &Home, args: &[&str]) -> Output {
    let vault = arg(&h.vault());
    let mut all = vec!["--password-stdin", "-v", &vault];
    all.extend_from_slice(args);
    piped(h.qvault(all), format!("{PASSWORD}\n").as_bytes())
}
fn ok(h: &Home, args: &[&str]) {
    let o = run(h, args);
    assert_eq!(o.code, 0, "{args:?}: {}", o.stderr);
}

#[test]
fn generated_entry_edits_preserve_ids_and_rejected_updates_preserve_state() {
    let h = Home::new();
    drop(h.create());
    ok(
        &h,
        &[
            "add",
            "Mail",
            "--generate",
            "--pin",
            "12",
            "--username",
            "alice",
            "--field",
            "tag=keep",
        ],
    );
    let s = h.unlock();
    let handle = s.list(s.root().unwrap()).unwrap().entries[0].handle;
    let before = s.entry(handle).unwrap();
    let password_id = before
        .fields
        .iter()
        .find(|f| f.name.expose() == "password")
        .unwrap()
        .handle;
    let draft = s.edit_entry(handle).unwrap();
    let ids: Vec<_> = draft.entry().fields.iter().map(|f| f.id).collect();
    let value = s.reveal(password_id).unwrap();
    assert_eq!(value.expose_secret().len(), 12);
    assert!(value.expose_secret().iter().all(u8::is_ascii_digit));
    drop(value);
    drop(draft);
    drop(before);
    drop(s);
    ok(
        &h,
        &[
            "edit",
            "Mail",
            "--title",
            "Changed",
            "--username",
            "bob",
            "--protect",
            "username",
        ],
    );
    let s = h.unlock();
    let d = s
        .edit_entry(s.list(s.root().unwrap()).unwrap().entries[0].handle)
        .unwrap();
    assert_eq!(
        d.entry().fields.iter().map(|f| f.id).collect::<Vec<_>>(),
        ids
    );
    assert_eq!(
        d.entry()
            .fields
            .iter()
            .find(|f| f.name.expose() == "username")
            .unwrap()
            .value
            .expose_secret(),
        b"bob"
    );
    let seq = s.overview().unwrap().local_seq;
    drop(d);
    drop(s);
    for args in [
        vec![
            "edit",
            "Changed",
            "--username",
            "bad",
            "--unprotect",
            "username",
        ],
        vec!["edit", "Changed", "--field", "password=bad"],
        vec![
            "edit",
            "Changed",
            "--username",
            "bad",
            "--field",
            "username=again",
        ],
        vec!["edit", "Changed", "--protect", "tag", "--unprotect", "tag"],
        vec!["edit", "Changed", "--pin", "4"],
        vec!["add", "Invalid", "--generate", "--field", "password=bad"],
    ] {
        let o = run(&h, &args);
        assert_eq!(o.code, 2, "{args:?}: {}", o.stderr);
        assert!(!o.stderr.contains("password=bad"));
    }
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
    drop(s);
    ok(
        &h,
        &[
            "edit",
            "Changed",
            "--unprotect",
            "username",
            "--remove-field",
            "tag",
            "--type",
            "custom",
        ],
    );
    let s = h.unlock();
    let d = s
        .edit_entry(s.list(s.root().unwrap()).unwrap().entries[0].handle)
        .unwrap();
    assert_eq!(d.entry().type_hint.expose(), "custom");
    assert_eq!(d.entry().fields.len(), 2);
    assert!(
        !d.entry()
            .fields
            .iter()
            .find(|f| f.name.expose() == "username")
            .unwrap()
            .protected
    );
}

// 0012 §1: CLI argument leakage
#[test]
fn prompts_notes_interactive_and_cancellation() {
    let h = Home::new();
    drop(h.create());
    let vault = arg(&h.vault());
    let mut p = Interactive::spawn(h.qvault([
        "-v",
        &vault,
        "add",
        "Prompted",
        "--notes",
        "--secret-field",
        "PIN",
    ]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    let at = p.expect("PIN: ");
    p.line("hidden-pin-marker");
    p.expect_from(at, "password: ");
    p.line("hidden-password-marker");
    p.expect("Notes (Ctrl-D to finish): ");
    p.send(b"hidden-note-line1\nline2\x04");
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");
    for secret in [
        PASSWORD,
        "hidden-pin-marker",
        "hidden-password-marker",
        "hidden-note-line1",
    ] {
        assert!(!all.contains(secret));
    }
    let s = h.unlock();
    let handle = s.list(s.root().unwrap()).unwrap().entries[0].handle;
    let d = s.edit_entry(handle).unwrap();
    assert_eq!(
        d.entry().notes.as_ref().unwrap().expose(),
        "hidden-note-line1\nline2"
    );
    assert!(d.entry().fields.iter().all(|f| f.protected));
    let old_seq = s.overview().unwrap().local_seq;
    drop(d);
    drop(s);
    let mut p = Interactive::spawn(h.qvault([
        "-v", &vault, "edit", "Prompted", "-i", "--field", "password",
    ]));
    let at = p.expect("Master password: ");
    p.line(PASSWORD);
    p.expect_from(at, "password: ");
    p.line("replacement-password-marker");
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");
    assert!(!all.contains("replacement-password-marker"));
    let s = h.unlock();
    let d = s
        .edit_entry(s.list(s.root().unwrap()).unwrap().entries[0].handle)
        .unwrap();
    assert_eq!(
        d.entry()
            .fields
            .iter()
            .find(|f| f.name.expose() == "password")
            .unwrap()
            .value
            .expose_secret(),
        b"replacement-password-marker"
    );
    let seq = s.overview().unwrap().local_seq;
    assert!(seq > old_seq);
    drop(d);
    drop(s);
    let mut p = Interactive::spawn(h.qvault([
        "-v",
        &vault,
        "edit",
        "Prompted",
        "--title",
        "NeverSaved",
        "--notes",
    ]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    p.expect("Notes (Ctrl-D to finish): ");
    p.send(b"cancelled-note\x03");
    let (code, all) = p.finish();
    assert_eq!(code, 1, "{all}");
    assert!(!all.contains("cancelled-note"));
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
    assert_eq!(
        s.list(s.root().unwrap()).unwrap().entries[0].title.expose(),
        "Prompted"
    );
}

#[test]
fn prompt_preflight_and_field_name_ambiguity() {
    let h = Home::new();
    let s = h.create();
    let mut d = s
        .new_entry(s.root().unwrap(), "login", "DupFields")
        .unwrap();
    for _ in 0..2 {
        d.add_field("same", FieldKind::Text, FieldValue::text("keep").unwrap())
            .unwrap();
    }
    s.save_entry(d).unwrap();
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    for args in [
        vec!["add", "X"],
        vec!["edit", "DupFields", "--notes"],
        vec!["edit", "DupFields", "-i"],
        vec!["edit", "DupFields", "--secret-field", "password"],
    ] {
        // Empty stdin: these must fail BEFORE consuming a master password.
        let vault = arg(&h.vault());
        let mut a = vec!["--password-stdin", "-v", &vault];
        a.extend(args);
        let o = piped(h.qvault(a), b"");
        assert_eq!(o.code, 2, "{}", o.stderr);
    }
    assert_eq!(
        run(&h, &["edit", "DupFields", "--field", "same=bad"]).code,
        2
    );
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
}

#[test]
fn groups_move_delete_and_ambiguity() {
    let h = Home::new();
    drop(h.create());
    ok(&h, &["mkdir", "Work/a\\/b/c\\\\d", "-p"]);
    ok(&h, &["mkdir", "Work/a\\/b/c\\\\d", "-p"]);
    ok(&h, &["add", "Work/a\\/b/c\\\\d/Mail", "--generate"]);
    ok(&h, &["mv", "Work/a\\/b/c\\\\d/Mail", "/"]);
    assert_ne!(run(&h, &["mv", "Work", "Work/a\\/b"]).code, 0);
    assert_ne!(run(&h, &["rm", "/"]).code, 0);
    assert_ne!(run(&h, &["rm", "Work"]).code, 0);
    ok(&h, &["rm", "Work", "-r"]);
    let s = h.unlock();
    assert_eq!(s.trash().unwrap().len(), 3);
    assert_eq!(s.list(s.root().unwrap()).unwrap().entries.len(), 1);
    drop(s);
    ok(&h, &["mkdir", "Mail"]);
    assert_eq!(run(&h, &["rm", "Mail"]).code, 5); // entry and group share a name
    ok(&h, &["rm", "Mail/"]);
    let s = h.unlock();
    assert!(s.list(s.root().unwrap()).unwrap().entries[0].title.expose() == "Mail");
    let item = s.list(s.root().unwrap()).unwrap().entries[0].handle;
    let addr = format!("@{}", item.id_hex());
    drop(s);
    ok(&h, &["rm", &addr]);
    let s = h.unlock();
    assert!(
        s.trash()
            .unwrap()
            .iter()
            .any(|t| matches!(t.item, ItemHandle::Entry(_)))
    );
}

#[test]
fn signals_restore_terminal_and_never_save_partial_input() {
    use rustix::process::Signal;
    use rustix::termios::{LocalModes, tcgetattr};
    let h = Home::new();
    drop(h.create());
    let vault = arg(&h.vault());
    ok(&h, &["add", "SignalEntry", "--generate"]);
    let s = h.unlock();
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
        for stage in ["master", "password", "notes", "confirmation"] {
            let args = match stage {
                "master" => vec!["-v", &vault, "ls"],
                "password" => vec![
                    "-v",
                    &vault,
                    "edit",
                    "SignalEntry",
                    "--secret-field",
                    "password",
                ],
                "notes" => vec!["-v", &vault, "edit", "SignalEntry", "--notes"],
                _ => vec!["-v", &vault, "trash", "empty"],
            };
            let mut p = Interactive::spawn(h.qvault(args));
            let observer = p.terminal_observer();
            let at = p.expect("Master password: ");
            if stage != "master" {
                p.line(PASSWORD);
                p.expect_from(
                    at,
                    match stage {
                        "password" => "password: ",
                        "notes" => "Notes (Ctrl-D to finish): ",
                        _ => "[y/N] ",
                    },
                );
            }
            assert!(
                !tcgetattr(&observer)
                    .unwrap()
                    .local_modes
                    .contains(LocalModes::ECHO)
            );
            if stage != "confirmation" {
                p.send(b"partial-secret-marker");
            }
            p.signal(signal);
            p.wait_exited();
            let modes = tcgetattr(&observer).unwrap().local_modes;
            assert!(modes.contains(LocalModes::ECHO | LocalModes::ICANON));
            drop(observer);
            let (code, all) = p.finish();
            assert_eq!(code, 1, "{stage}: {all}");
            assert!(!all.contains("partial-secret-marker"));
        }
    }
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
}

#[test]
fn signals_clear_recovery_alternate_screen() {
    use rustix::process::Signal;
    use rustix::termios::{LocalModes, tcgetattr};
    for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
        let h = Home::new();
        let vault = arg(&h.vault());
        let mut p = Interactive::spawn(h.qvault(["init", &vault]));
        let observer = p.terminal_observer();
        let at = p.expect("Use this passphrase? [y/N] ");
        p.line("n");
        let at = p.expect_from(at, "New master password: ");
        p.line("v7#Qm!2pZr9&Lw4tX0^sK8@e");
        let at = p.expect_from(at, "Repeat the master password: ");
        p.line("v7#Qm!2pZr9&Lw4tX0^sK8@e");
        p.expect_from(at, "Press any key");
        p.signal(signal);
        p.wait_exited();
        assert!(
            tcgetattr(&observer)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO | LocalModes::ICANON)
        );
        drop(observer);
        let (code, all) = p.finish();
        assert_eq!(code, 1, "{all}");
        assert!(all.contains("\x1b[?1049h"));
        assert!(all.contains("\x1b[H\x1b[2J\x1b[?1049l"));
    }
}

#[test]
fn value_bounds_and_invalid_utf8_leave_the_entry_unchanged() {
    let h = Home::new();
    drop(h.create());
    ok(&h, &["add", "Bounded", "--generate"]);
    let s = h.unlock();
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    let vault = arg(&h.vault());
    for (option, bytes, code, prompt) in [
        (
            "--secret-field",
            vec![b'x'; 256 * 1024 + 1],
            9,
            "password: ",
        ),
        ("--notes", vec![0xff], 2, "Notes (Ctrl-D to finish): "),
    ] {
        let mut args = vec!["-v", &vault, "edit", "Bounded", option];
        if option == "--secret-field" {
            args.push("password");
        }
        let mut p = Interactive::spawn(h.qvault(args));
        let at = p.expect("Master password: ");
        p.line(PASSWORD);
        p.expect_from(at, prompt);
        p.send(&bytes);
        p.send(if option == "--notes" { b"\x04" } else { b"\r" });
        let (got, all) = p.finish();
        assert_eq!(got, code, "{all}");
    }
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
}

#[test]
fn signals_interrupt_the_weak_password_countdown() {
    use rustix::process::Signal;
    for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
        let h = Home::new();
        let vault = arg(&h.vault());
        let mut p = Interactive::spawn(h.qvault(["init", &vault, "--yes"]));
        let at = p.expect("Use this passphrase? [y/N] ");
        p.line("n");
        let at = p.expect_from(at, "New master password: ");
        p.line("weak");
        let at = p.expect_from(at, "Repeat the master password: ");
        p.line("weak");
        p.expect_from(at, "You can answer in");
        p.signal(signal);
        let (code, all) = p.finish();
        assert_eq!(code, 1, "{all}");
        assert!(!h.vault().exists());
        assert!(!all.contains("Create the vault with this weak password anyway?"));
    }
}

#[test]
fn signal_cancels_a_pending_password_pipe() {
    use rustix::process::{Pid, Signal, kill_process};
    use std::{
        process::Stdio,
        time::{Duration, Instant},
    };
    let h = Home::new();
    drop(h.create());
    let vault = arg(&h.vault());
    for (signal, number) in [(Signal::INT, 2), (Signal::TERM, 15), (Signal::HUP, 1)] {
        let _serial = common::serial();
        let mut child = h
            .qvault(["--password-stdin", "-v", &vault, "ls"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        // Synchronize on handler registration, not a guessed startup delay.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let status = std::fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
            let caught = status
                .lines()
                .find_map(|line| line.strip_prefix("SigCgt:"))
                .unwrap()
                .trim();
            if u64::from_str_radix(caught, 16).unwrap() & (1 << (number - 1)) != 0 {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(5));
        }
        let input = child.stdin.take().unwrap(); // Keep the pipe open with no bytes.
        kill_process(
            Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
            signal,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("pending pipe did not cancel");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(1));
    }
}
