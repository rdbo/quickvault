// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault show`, `totp` and `generate` end to end, and the exit codes that
//! need a real vault state (6, 7).

#![cfg(any(target_os = "linux", target_os = "android"))]
// The helpers are test code, but clippy's `allow-*-in-tests` settings only
// cover `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use common::{Home, Interactive, Output, PASSWORD, arg, piped};
use qv_core::{
    Extensions, FieldKind, FieldValue, GeneratorDefaults, GeneratorSettings, PinSettings, Text,
};

/// RFC 6238's SHA-1 seed ("12345678901234567890") in base32.
const TOTP_URI: &str =
    "otpauth://totp/Test:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Test";

fn fixture() -> Home {
    let home = Home::new();
    let s = home.create();
    let root = s.root().unwrap();
    let g = s.new_group(root, "Work").unwrap();
    let work = s.save_group(g).unwrap();
    let mut d = s.new_entry(work, "login", "GitHub").unwrap();
    for (name, kind, value) in [
        ("Username", FieldKind::Text, "alice"),
        ("Password", FieldKind::Secret, "hunter2-secret"),
        ("OTP", FieldKind::Totp, TOTP_URI),
        ("Raw", FieldKind::Text, "a\u{1b}b"),
        ("Memo", FieldKind::Multiline, "line one\nline two"),
    ] {
        d.add_field(name, kind, FieldValue::text(value).unwrap())
            .unwrap();
    }
    d.entry_mut().notes = Some(Text::new("first\nPassword: fake").unwrap());
    s.save_entry(d).unwrap();
    let d = s.new_entry(work, "note", "Plain").unwrap();
    s.save_entry(d).unwrap();
    drop(s);
    home
}

fn run(home: &Home, args: &[&str]) -> Output {
    let vault = arg(&home.vault());
    let mut all = vec!["--password-stdin", "-v", &vault];
    all.extend_from_slice(args);
    piped(home.qvault(all), format!("{PASSWORD}\n").as_bytes())
}

#[test]
fn show_masks_and_reveals() {
    let home = fixture();
    let out = run(&home, &["show", "Work/GitHub"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout
            .starts_with("Title:     GitHub\nPath:      Work/GitHub\nID:        @")
    );
    assert!(out.stdout.contains("\nUsername: alice\n"));
    assert!(out.stdout.contains("\nPassword: ••••••••  (protected)\n"));
    assert!(out.stdout.contains("\nOTP: ••••••••  (protected)\n"));
    assert!(out.stdout.contains("\nRaw: a\\x1bb\n"));
    assert!(out.stdout.contains("\nMemo: line one\n  line two\n"));
    // Notes cannot fake a top-level line.
    assert!(out.stdout.contains("\nNotes:\n  first\n  Password: fake\n"));
    assert!(!out.stdout.contains("hunter2-secret"));
    assert!(!out.stdout.contains("GEZDGNBV"));

    let out = run(&home, &["show", "--reveal", "Work/GitHub"]);
    assert!(out.stdout.contains("\nPassword: hunter2-secret\n"));
    assert!(out.stdout.contains(&format!("\nOTP: {TOTP_URI}\n")));

    // --field: a protected field needs --reveal; the value is never shown.
    let out = run(&home, &["show", "--field", "Password", "Work/GitHub"]);
    assert_eq!(out.code, 1);
    assert!(out.stderr.contains("protected; add --reveal"));
    assert!(!out.stdout.contains("hunter2") && !out.stderr.contains("hunter2"));
    let out = run(
        &home,
        &["show", "--field", "Password", "--reveal", "Work/GitHub"],
    );
    assert_eq!(out.stdout, "hunter2-secret\n");
    assert_eq!(
        run(&home, &["show", "--field", "Username", "Work/GitHub"]).stdout,
        "alice\n"
    );
    assert_eq!(
        run(&home, &["show", "--field", "Nope", "Work/GitHub"]).code,
        4
    );
    // On a pipe the value is exactly as stored.
    assert_eq!(
        run(&home, &["show", "--field", "Raw", "Work/GitHub"]).stdout,
        "a\u{1b}b\n"
    );

    let out = run(&home, &["show", "--json", "Work/GitHub"]);
    assert!(
        out.stdout.contains(
            "{\"name\":\"Password\",\"kind\":\"secret\",\"protected\":true,\"value\":null}"
        )
    );
    assert!(out.stdout.contains(
        "{\"name\":\"Raw\",\"kind\":\"text\",\"protected\":false,\"value\":\"a\\u001bb\"}"
    ));
    assert!(out.stdout.contains("\"versions\":1"));
    let out = run(&home, &["show", "--json", "--reveal", "Work/GitHub"]);
    assert!(out.stdout.contains("\"value\":\"hunter2-secret\""));

    assert_eq!(run(&home, &["show", "Work/Nope"]).code, 4);
    assert_eq!(run(&home, &["show", "Work"]).code, 4);
}

#[test]
fn show_field_is_escaped_on_a_terminal() {
    let home = fixture();
    let vault = arg(&home.vault());
    let mut p =
        Interactive::spawn(home.qvault(["show", "-v", &vault, "--field", "Raw", "Work/GitHub"]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");
    assert!(all.contains("a\\x1bb"), "{all:?}");
    assert!(!all.contains("a\u{1b}b"));
    assert!(!all.contains(PASSWORD), "the password is not echoed");
}

#[test]
fn totp_prints_the_current_code() {
    let home = fixture();
    for _ in 0..3 {
        let out = run(&home, &["totp", "Work/GitHub"]);
        assert_eq!(out.code, 0, "{}", out.stderr);
        let (code, rest) = out.stdout.split_once("  (").unwrap();
        assert_eq!(code.len(), 6);
        assert!(rest.ends_with(" s left)\n"));
        // The same code from the core, unless the 30-second window rolled.
        let s = home.unlock();
        let root = s.root().unwrap();
        let work = s.list(root).unwrap().groups[0].handle;
        let e = s
            .list(work)
            .unwrap()
            .entries
            .into_iter()
            .find(|e| e.title.expose() == "GitHub")
            .unwrap();
        let field = s
            .entry(e.handle)
            .unwrap()
            .fields
            .into_iter()
            .find(|f| f.kind == FieldKind::Totp)
            .unwrap();
        let now = s.totp(field.handle).unwrap();
        let same = now.code.expose_secret() == code;
        // Release the vault lock before running qvault again.
        drop(now);
        drop(s);
        if same {
            let out = run(&home, &["totp", "--json", "Work/GitHub"]);
            assert!(out.stdout.starts_with("{\"code\":\""), "{}", out.stdout);
            assert_eq!(run(&home, &["totp", "Work/Plain"]).code, 1);
            return;
        }
    }
    panic!("the TOTP code never matched the core's");
}

#[test]
fn generate_modes_and_defaults() {
    let home = Home::new();
    let gen_ = |args: &[&str]| {
        let mut a = vec!["generate"];
        a.extend_from_slice(args);
        piped(home.qvault(a), b"")
    };
    // No vault selected: the 0010 defaults, no prompt.
    let out = gen_(&[]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout.lines().count(), 1);
    assert!(out.stdout.trim_end().len() >= 16);
    assert!(out.stderr.contains(" bits ("));
    let out = gen_(&["--pin", "6"]);
    assert_eq!(out.stdout.trim_end().len(), 6);
    assert!(out.stdout.trim_end().bytes().all(|b| b.is_ascii_digit()));
    assert!(out.stderr.contains("warning: less than 64 bits"));
    let out = gen_(&["--words", "7", "--capitalize"]);
    assert_eq!(out.code, 0);
    assert_eq!(out.stdout.trim_end().split('.').count(), 7);
    let out = gen_(&["--length", "30", "--no-symbols"]);
    assert_eq!(out.stdout.trim_end().len(), 30);
    assert!(
        out.stdout
            .trim_end()
            .bytes()
            .all(|b| b.is_ascii_alphanumeric())
    );
    let out = gen_(&["--json", "--pin", "8"]);
    assert!(out.stdout.starts_with("{\"value\":\""));
    assert!(out.stdout.contains("\"bits\":26.6,\"strength\":\"weak\"}"));
    // Invalid settings: the generator's message, nothing on stdout.
    let out = gen_(&["--length", "2"]);
    assert_eq!(out.code, 1);
    assert_eq!(out.stdout, "");
    let out = gen_(&["--words", "5", "--separator", "-"]);
    assert_eq!(out.code, 1, "{}", out.stdout);
    assert_eq!(out.stdout, "");
    // Usage errors.
    assert_eq!(gen_(&["--pin", "6", "--words", "5"]).code, 2);
    assert_eq!(gen_(&["--separator", "ab"]).code, 2);

    // A selected vault's defaults (unlocked for them).
    drop(home.create());
    let s = home.unlock();
    let mut d = s.edit_settings().unwrap();
    d.meta_mut().settings.generator = Some(GeneratorDefaults {
        settings: GeneratorSettings::Pin(PinSettings { length: 7 }),
        ext: Extensions::new(),
    });
    s.save_settings(d).unwrap();
    drop(s);
    let out = run(&home, &["generate"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(out.stdout.trim_end().len(), 7);
    // Options override them without unlocking.
    let out = piped(
        home.qvault(["generate", "-v", &arg(&home.vault()), "--pin", "4"]),
        b"",
    );
    assert_eq!(out.stdout.trim_end().len(), 4);
}

#[test]
fn exit_codes_for_vault_states() {
    let home = fixture();
    // 6: another process (here, the test) holds the vault.
    {
        let held = home.unlock();
        let out = run(&home, &["ls"]);
        assert_eq!(out.code, 6, "{}", out.stderr);
        assert!(out.stderr.contains("locked by another process"));
        drop(held);
    }
    assert_eq!(run(&home, &["ls"]).code, 0);
    // 3: a wrong password.
    let out = piped(
        home.qvault(["ls", "--password-stdin", "-v", &arg(&home.vault())]),
        b"wrong\n",
    );
    assert_eq!(out.code, 3);
    // 9: a password over 1024 bytes on stdin.
    let long = format!("{}\n", "x".repeat(1025));
    let out = piped(
        home.qvault(["ls", "--password-stdin", "-v", &arg(&home.vault())]),
        long.as_bytes(),
    );
    assert_eq!(out.code, 9);
    // 7: the anchor is gone (a copy from elsewhere, or lost state).
    for e in std::fs::read_dir(home.anchors()).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    let out = run(&home, &["ls"]);
    assert_eq!(out.code, 7, "{}", out.stderr);
    assert!(out.stderr.contains("hint: this device has no record"));
    // 7: a tampered file.
    let mut bytes = std::fs::read(home.vault()).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 0x55;
    std::fs::write(home.vault(), &bytes).unwrap();
    let out = run(&home, &["ls"]);
    assert_eq!(out.code, 7, "{}", out.stderr);
}

#[test]
fn vault_inside_the_anchor_directory_is_refused() {
    let home = fixture();
    let inside = home.anchors().join("v.qvault");
    std::fs::rename(home.vault(), &inside).unwrap();
    let out = piped(
        home.qvault(["ls", "--password-stdin", "-v", &arg(&inside)]),
        format!("{PASSWORD}\n").as_bytes(),
    );
    assert_eq!(out.code, 1, "{}", out.stderr);
    assert!(out.stderr.contains("anchor directory"));
}
