// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production protected-TTY password and recovery flows.
#![cfg(any(target_os = "linux", target_os = "android"))]
// Test-only PTY/fixture helpers fail the test on setup or protocol errors.
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;
use common::{Home, Interactive, PASSWORD, arg, piped, pw, serial};
use qv_core::RecoveryPhrase;
const NEW: &str = "s8!Qp#7mV2$xR9&kL4@zN6%wT1";

fn create(h: &Home) -> RecoveryPhrase {
    let _s = serial();
    let created = h
        .core()
        .create(&h.vault(), &pw(PASSWORD), "Credentials")
        .unwrap();
    created.session.lock();
    created.recovery_phrase
}
fn snapshot(h: &Home) {
    let o = piped(
        h.qvault(["--password-stdin", "-v", &arg(&h.vault()), "snapshot", "ls"]),
        format!("{PASSWORD}\n").as_bytes(),
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
}
fn choose(p: &mut Interactive) {
    let at = p.expect("Use this passphrase? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(NEW);
    p.expect_from(at, "Repeat the master password: ");
    p.line(NEW);
}
fn new_unlock(h: &Home) {
    let _s = serial();
    assert!(h.core().unlock(&h.vault(), &pw(NEW), None).is_ok());
    assert!(h.core().unlock(&h.vault(), &pw(PASSWORD), None).is_err());
}

#[test]
fn credentials_passwd_reauthenticates_and_yes_does_not_delete_without_consent() {
    let h = Home::new();
    let _phrase = create(&h);
    snapshot(&h);
    let snapshots = std::fs::read_dir(h.snapshots()).unwrap().count();
    let mut p = Interactive::spawn(h.qvault(["-v", &arg(&h.vault()), "--yes", "passwd"]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    choose(&mut p);
    let at = p.expect("Master password changed.");
    p.expect_from(at, "Delete these pre-change local snapshots? [y/N] ");
    p.line("n");
    let (code, text) = p.finish();
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("not cryptographic erasure"));
    assert_eq!(std::fs::read_dir(h.snapshots()).unwrap().count(), snapshots);
    new_unlock(&h);
}

#[test]
fn credentials_recovery_show_is_alternate_screen_and_reauthenticates() {
    let h = Home::new();
    let phrase = create(&h);
    let mut p = Interactive::spawn(h.qvault(["-v", &arg(&h.vault()), "recovery", "show"]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    p.expect("Press any key");
    p.send(b" ");
    let (code, text) = p.finish();
    assert_eq!(code, 0, "{text}");
    let alt = text.find("\x1b[?1049h").unwrap();
    assert!(text.contains("\x1b[?1049l"));
    for word in phrase.expose_secret().split(' ') {
        assert!(text[alt..].contains(word));
    }
    let mut p = Interactive::spawn(h.qvault(["-v", &arg(&h.vault()), "recovery", "show"]));
    p.expect("Master password: ");
    p.line("incorrect password");
    let (code, text) = p.finish();
    assert_eq!(code, 3, "{text}");
    assert!(!text.contains("\x1b[?1049h"));
}

#[test]
fn credentials_recover_missing_anchor_requires_consent_and_offers_snapshot_deletion() {
    let h = Home::new();
    let phrase = create(&h);
    for e in std::fs::read_dir(h.anchors()).unwrap() {
        std::fs::remove_file(e.unwrap().path()).unwrap();
    }
    let before = std::fs::read(h.vault()).unwrap();
    // Declining the baseline changes neither the vault nor its missing anchor.
    let mut p = Interactive::spawn(h.qvault(["recover", &arg(&h.vault())]));
    p.expect("Recovery phrase (24 words): ");
    p.line(phrase.expose_secret());
    choose(&mut p);
    p.expect("Accept this file as the new local recovery baseline? [y/N] ");
    p.line("n");
    let (code, text) = p.finish();
    assert_eq!(code, 1, "{text}");
    assert_eq!(std::fs::read(h.vault()).unwrap(), before);
    assert_eq!(std::fs::read_dir(h.anchors()).unwrap().count(), 0);
    let mut p = Interactive::spawn(h.qvault(["recover", &arg(&h.vault())]));
    p.expect("Recovery phrase (24 words): ");
    p.line(phrase.expose_secret());
    choose(&mut p);
    p.expect("Accept this file as the new local recovery baseline? [y/N] ");
    p.line("y");
    let at = p.expect("Vault recovered and master password changed.");
    p.expect_from(at, "Delete these pre-change local snapshots? [y/N] ");
    p.line("y");
    let (code, text) = p.finish();
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("does not prove it is the latest global state"));
    assert_eq!(std::fs::read_dir(h.snapshots()).unwrap().count(), 0);
    new_unlock(&h);
}

#[test]
fn credentials_recover_rejects_wrong_phrases_and_cancel_before_writes() {
    let h = Home::new();
    let _phrase = create(&h);
    let other = Home::new();
    let foreign = create(&other);
    let before = std::fs::read(h.vault()).unwrap();
    for input in ["wrong phrase", foreign.expose_secret()] {
        let mut p = Interactive::spawn(h.qvault(["recover", &arg(&h.vault())]));
        p.expect("Recovery phrase (24 words): ");
        p.line(input);
        let (code, text) = p.finish();
        assert_eq!(code, 3, "{text}");
        assert_eq!(std::fs::read(h.vault()).unwrap(), before);
    }
    let mut p = Interactive::spawn(h.qvault(["recover", &arg(&h.vault())]));
    p.expect("Recovery phrase (24 words): ");
    p.send(&[3]);
    let (code, text) = p.finish();
    assert_eq!(code, 1, "{text}");
    assert_eq!(std::fs::read(h.vault()).unwrap(), before);
}

#[test]
fn credentials_preflight_refuses_json_stdin_and_nonterminal_displays() {
    let h = Home::new();
    let _phrase = create(&h);
    for args in [
        vec!["--password-stdin", "passwd"],
        vec!["--json", "passwd"],
        vec!["--password-stdin", "recover", "v.qvault"],
        vec!["--json", "recover", "v.qvault"],
        vec!["--json", "recovery", "show"],
        vec!["recovery", "show"],
    ] {
        let out = piped(h.qvault(args), b"");
        assert_eq!(out.code, 2, "{}", out.stderr);
    }
}

#[test]
fn credentials_weak_password_delay_is_not_skipped_by_yes() {
    let h = Home::new();
    let _phrase = create(&h);
    let mut p = Interactive::spawn(h.qvault(["--yes", "-v", &arg(&h.vault()), "passwd"]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    p.expect("Use this passphrase? [y/N] ");
    p.line("n");
    p.expect("New master password: ");
    p.line("abc");
    p.expect("Repeat the master password: ");
    p.line("abc");
    let started = std::time::Instant::now();
    let at = p.expect("Create the vault with this weak password anyway? [y/N] ");
    assert!(started.elapsed() >= std::time::Duration::from_secs(4));
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(NEW);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(NEW);
    let at = p.expect_from(at, "Master password changed.");
    p.expect_from(at, "Delete these pre-change local snapshots? [y/N] ");
    p.line("n");
    let (code, text) = p.finish();
    assert_eq!(code, 0, "{text}");
    new_unlock(&h);
}

#[test]
fn credentials_rotation_marker_blocks_normal_unlock_and_phrase_recovery() {
    let h = Home::new();
    let phrase = create(&h);
    let before = std::fs::read(h.vault()).unwrap();
    let anchors: Vec<_> = std::fs::read_dir(h.anchors())
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    // An incomplete journal must stop normal opens before database ingestion.
    let marker = h.vault().with_file_name("v.qvault.qvrotate");
    std::fs::write(&marker, b"incomplete rotation intent").unwrap();
    let out = piped(
        h.qvault(["--password-stdin", "-v", &arg(&h.vault()), "ls"]),
        format!("{PASSWORD}\n").as_bytes(),
    );
    assert_eq!(out.code, 7, "{}", out.stderr);
    assert_eq!(std::fs::read(h.vault()).unwrap(), before);
    if h.snapshots().exists() {
        assert_eq!(std::fs::read_dir(h.snapshots()).unwrap().count(), 0);
    }
    let mut p = Interactive::spawn(h.qvault(["recover", &arg(&h.vault())]));
    p.expect("Recovery phrase (24 words): ");
    p.line(phrase.expose_secret());
    let (code, text) = p.finish();
    assert_eq!(code, 7, "{text}");
    for (path, bytes) in &anchors {
        assert_eq!(std::fs::read(path).unwrap(), *bytes);
    }
    // In the rename gap, an absent active name still reports integrity (7),
    // rather than NotFound (4). Store tests also check creation in this gap.
    std::fs::rename(h.vault(), h.vaults().join("old.qvault")).unwrap();
    let out = piped(h.qvault(["-v", &arg(&h.vault()), "info"]), b"");
    assert_eq!(out.code, 7, "{}", out.stderr);
    assert!(!h.vault().exists());
    for (path, bytes) in anchors {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn credentials_reserved_rotation_copy_is_never_unlocked_or_anchored() {
    let h = Home::new();
    create(&h);
    let anchors: Vec<_> = std::fs::read_dir(h.anchors())
        .unwrap()
        .map(|e| {
            let path = e.unwrap().path();
            let bytes = std::fs::read(&path).unwrap();
            (path, bytes)
        })
        .collect();
    // A valid copy under a reserved replacement name shares the anchor's
    // replica ID; an ordinary unlock must refuse it before any anchor check.
    let copy = h
        .vaults()
        .join("v.qvault.qvrotate-new-00112233445566778899aabbccddeeff");
    std::fs::copy(h.vault(), &copy).unwrap();
    let out = piped(
        h.qvault(["--password-stdin", "-v", &arg(&copy), "ls"]),
        format!("{PASSWORD}\n").as_bytes(),
    );
    assert_eq!(out.code, 7, "{}", out.stderr);
    for (path, bytes) in anchors {
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }
}
