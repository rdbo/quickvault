// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real binary history masking, causal restore, suppression and preflight.
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;
use common::{Home, PASSWORD, arg, piped};
use qv_core::{Extensions, Field, FieldId, FieldKind, FieldValue, RandomId, Text};

fn run(home: &Home, args: &[&str]) -> common::Output {
    let vault = arg(&home.vault());
    let mut all = vec!["--password-stdin", "-v", &vault];
    all.extend_from_slice(args);
    piped(home.qvault(all), format!("{PASSWORD}\n").as_bytes())
}
#[test]
fn history_cli_show_restore_and_purge_persist() {
    let h = Home::new();
    let s = h.create();
    let mut d = s.new_entry(s.root().unwrap(), "login", "History").unwrap();
    d.entry_mut().fields.push(Field {
        id: FieldId::generate().unwrap(),
        name: Text::new("password").unwrap(),
        kind: FieldKind::Secret,
        protected: true,
        value: FieldValue::text("historical-secret-marker").unwrap(),
        ext: Extensions::new(),
    });
    let e = s.save_entry(d).unwrap();
    let id = e.id_hex();
    let mut d = s.edit_entry(e).unwrap();
    d.entry_mut().fields[0].value = FieldValue::text("current-secret-marker").unwrap();
    s.save_entry(d).unwrap();
    let version = s.history(e).unwrap()[0].handle.version_hex();
    drop(s);
    let address = format!("@{id}");
    let out = run(&h, &["--json", "history", &address]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains(&version));
    assert!(out.stdout.contains("\"device\":null"));
    assert!(!out.stdout.contains("secret-marker"));
    let out = run(&h, &["history", "show", &address, &version]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!out.stdout.contains("historical-secret-marker"));
    let out = run(
        &h,
        &[
            "--json",
            "history",
            "show",
            &address,
            &version[..8],
            "--reveal",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("historical-secret-marker"));
    assert!(
        out.stdout
            .contains(&format!("\"version_id\":\"{version}\""))
    );
    assert_eq!(run(&h, &["restore", &address, &version]).code, 0);
    assert!(
        run(&h, &["show", &address, "--reveal"])
            .stdout
            .contains("historical-secret-marker")
    );
    let out = run(&h, &["--yes", "history", "purge", &address]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("No secure-erasure"));
    assert_eq!(
        run(&h, &["--json", "history", &address]).stdout.trim(),
        "{\"versions\":[]}"
    );
    assert_eq!(run(&h, &["history", "show", &address, &version]).code, 4);
}
#[test]
fn history_cli_preflight_before_unlock_and_scoped_absence() {
    let h = Home::new();
    for args in [
        vec!["history"],
        vec!["history", "purge", "missing"],
        vec!["--json", "restore", "missing", "abcdef"],
        vec!["--json", "history", "purge", "missing"],
        vec!["history", "show", "missing", "bad"],
    ] {
        let mut a = vec!["--password-stdin"];
        a.extend(args);
        let out = piped(h.qvault(a), b"");
        assert_eq!(out.code, 2, "{}", out.stderr);
        assert!(!out.stderr.contains("Master password"));
    }
    let s = h.create();
    let e = s
        .save_entry(s.new_entry(s.root().unwrap(), "login", "show").unwrap())
        .unwrap();
    drop(s);
    assert_eq!(
        run(
            &h,
            &["history", "show", &format!("@{}", e.id_hex()), "abcdef"]
        )
        .code,
        4
    );
}

#[test]
fn history_purge_confirmation_cancel_and_signal_preserve_history() {
    use common::Interactive;
    use rustix::process::Signal;
    let h = Home::new();
    let s = h.create();
    let e = s
        .save_entry(s.new_entry(s.root().unwrap(), "login", "History").unwrap())
        .unwrap();
    s.save_entry(s.edit_entry(e).unwrap()).unwrap();
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    let vault = arg(&h.vault());
    for signal in [
        None,
        Some(Signal::INT),
        Some(Signal::TERM),
        Some(Signal::HUP),
    ] {
        let mut p = Interactive::spawn(h.qvault(["-v", &vault, "history", "purge", "History"]));
        p.expect("Master password: ");
        p.line(PASSWORD);
        p.expect("[y/N] ");
        if let Some(signal) = signal {
            p.signal(signal);
        } else {
            p.line("n");
        }
        assert_eq!(p.finish().0, 1);
        let s = h.unlock();
        assert_eq!(s.overview().unwrap().local_seq, seq);
        let e = s.list(s.root().unwrap()).unwrap().entries[0].handle;
        assert_eq!(s.history(e).unwrap().len(), 1);
    }
}
