// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault init` and `qvault info` end to end, through a PTY and pipes.

#![cfg(any(target_os = "linux", target_os = "android"))]
// The helpers are test code, but clippy's `allow-*-in-tests` settings only
// cover `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]

mod common;

use std::time::Instant;

use common::{Home, Interactive, arg, piped};

const ENTER_ALT: &str = "\u{1b}[?1049h";
const LEAVE_ALT: &str = "\u{1b}[?1049l";
const STRONG: &str = "v7#Qm!2pZr9&Lw4tX0^sK8@e";

/// The text printed outside the alternate screen, and each alternate-screen
/// part.
fn split_alt(seen: &str) -> (String, Vec<String>) {
    let mut outside = String::new();
    let mut inside = Vec::new();
    let mut rest = seen;
    while let Some(i) = rest.find(ENTER_ALT) {
        outside.push_str(&rest[..i]);
        let after = &rest[i + ENTER_ALT.len()..];
        let j = after.find(LEAVE_ALT).expect("alternate screen left");
        inside.push(after[..j].to_owned());
        rest = &after[j + LEAVE_ALT.len()..];
    }
    outside.push_str(rest);
    (outside, inside)
}

/// The 24 numbered words of a phrase display.
fn phrase_words(screen: &str) -> Vec<String> {
    let mut words = vec![String::new(); 24];
    let tokens: Vec<&str> = screen.split_whitespace().collect();
    for w in tokens.windows(2) {
        if let Some(n) = w[0].strip_suffix('.').and_then(|n| n.parse::<usize>().ok())
            && (1..=24).contains(&n)
            && w[1].chars().all(|c| c.is_ascii_lowercase())
        {
            words[n - 1] = w[1].to_owned();
        }
    }
    assert!(words.iter().all(|w| !w.is_empty()), "{screen:?}");
    words
}

/// The number asked for by the last `Word #N: ` prompt after `from`.
fn asked(p: &mut Interactive, from: usize) -> (usize, usize) {
    let end = p.expect_from(from, "Word #");
    let colon = p.expect_from(end, ": ");
    let n: usize = String::from_utf8_lossy(&p.seen[end..colon - 2])
        .parse()
        .unwrap();
    (n, colon)
}

/// Answers the suggestion with "n" and types `password` twice.
fn typed_password(p: &mut Interactive, password: &str) -> usize {
    let at = p.expect("Use this passphrase? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(password);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(password);
    at
}

fn phrase_after(p: &mut Interactive, from: usize) -> (Vec<String>, usize) {
    let at = p.expect_from(from, "Press any key when you have written them down.");
    let seen = String::from_utf8_lossy(&p.seen[from..at]).into_owned();
    let start = seen.rfind("Recovery phrase.").unwrap();
    (phrase_words(&seen[start..]), at)
}

fn confirm_all(p: &mut Interactive, words: &[String], mut at: usize) -> usize {
    for _ in 0..3 {
        let (n, next) = asked(p, at);
        p.line(&words[n - 1]);
        at = next;
    }
    p.expect_from(at, "The recovery phrase is checked.")
}

#[test]
fn init_with_the_suggested_passphrase() {
    let home = Home::new();
    let vault = home.vault();
    let mut p = Interactive::spawn(home.qvault(["init", &arg(&vault), "--name", "Mine"]));
    let at = p.expect("Use this passphrase? [y/N] ");
    let screen = String::from_utf8_lossy(&p.seen[..at]).into_owned();
    let line = screen
        .lines()
        .find(|l| l.starts_with("    ") && l.trim().contains('.'))
        .expect("suggested passphrase line");
    let suggestion = line.trim().to_owned();
    assert_eq!(suggestion.split('.').count(), 6, "{suggestion}");
    p.line("y");
    let (words, at) = phrase_after(&mut p, at);
    p.send(b" ");
    confirm_all(&mut p, &words, at);
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");
    assert!(all.contains("Created vault \"Mine\""));

    // Neither the phrase nor the suggestion is printed outside the
    // alternate screen.
    let (outside, inside) = split_alt(&all);
    assert_eq!(inside.len(), 2);
    assert!(!outside.contains(&suggestion));
    assert!(!outside.contains(&words.join(" ")));
    for (i, w) in words.iter().enumerate() {
        assert!(!outside.contains(&format!("{}. {w}", i + 1)), "{w}");
        for pair in words.windows(2) {
            assert!(!outside.contains(&format!("{} {}", pair[0], pair[1])));
        }
    }

    // The suggestion is the master password.
    let mut c = home.qvault(["info", "--full", "--password-stdin", "-v", &arg(&vault)]);
    c.current_dir(&home.root);
    let out = piped(c, format!("{suggestion}\n").as_bytes());
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(
        out.stdout.contains("name:            Mine"),
        "{}",
        out.stdout
    );
    assert!(out.stdout.contains("entries:         0"));
    // The phrase check was not skipped.
    let s = home
        .core()
        .unlock(&vault, &common::pw(&suggestion), None)
        .unwrap();
    assert!(
        s.edit_settings()
            .unwrap()
            .meta()
            .settings
            .recovery_skipped_at
            .is_none()
    );
}

#[test]
fn init_typed_password_retry_and_show_again() {
    let home = Home::new();
    let vault = home.vault();
    let mut p = Interactive::spawn(home.qvault(["init", &arg(&vault)]));
    let at = p.expect("Use this passphrase? [y/N] ");
    p.line("n");
    // Mismatched passwords ask again.
    let at = p.expect_from(at, "New master password: ");
    p.line(STRONG);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line("something else");
    let at = p.expect_from(at, "The passwords do not match; try again.");
    let at = p.expect_from(at, "New master password: ");
    p.line(STRONG);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(STRONG);
    let (words, at) = phrase_after(&mut p, at);
    p.send(b"x");
    // A wrong word, then the phrase again, then the right one.
    let (n, at) = asked(&mut p, at);
    p.line("zzzz");
    let at = p.expect_from(at, &format!("That is not word #{n}."));
    let (n2, _) = asked(&mut p, at);
    assert_eq!(n2, n);
    p.line("");
    let at = p.expect_from(at, "Show the recovery phrase again? [y/N] ");
    p.line("y");
    let (again, at) = phrase_after(&mut p, at);
    assert_eq!(again, words);
    p.send(b" ");
    let (n3, at) = asked(&mut p, at);
    assert_eq!(n3, n);
    p.line(&words[n - 1]);
    let mut at = at;
    for _ in 0..2 {
        let (k, next) = asked(&mut p, at);
        p.line(&words[k - 1]);
        at = next;
    }
    p.expect_from(at, "The recovery phrase is checked.");
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");
    // Typed secrets are not echoed.
    let (outside, _) = split_alt(&all);
    assert!(!outside.contains(STRONG));
    assert!(!outside.contains("something else"));
    home.core()
        .unlock(&vault, &common::pw(STRONG), None)
        .unwrap();
}

#[test]
fn init_skip_is_recorded() {
    let home = Home::new();
    let vault = home.vault();
    let mut p = Interactive::spawn(home.qvault(["init", &arg(&vault)]));
    let at = typed_password(&mut p, STRONG);
    let (_, at) = phrase_after(&mut p, at);
    p.send(b" ");
    let (_, at) = asked(&mut p, at);
    p.line("");
    let at = p.expect_from(at, "Show the recovery phrase again? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "Skip checking the recovery phrase? [y/N] ");
    p.line("y");
    let at = p.expect_from(at, "Skip anyway? [y/N] ");
    p.line("y");
    p.expect_from(at, "Skipped");
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");
    let s = home
        .core()
        .unlock(&vault, &common::pw(STRONG), None)
        .unwrap();
    assert!(
        s.edit_settings()
            .unwrap()
            .meta()
            .settings
            .recovery_skipped_at
            .is_some()
    );
}

#[test]
fn init_weak_password_waits_even_with_yes() {
    let home = Home::new();
    let vault = home.vault();
    let mut p = Interactive::spawn(home.qvault(["init", "--yes", &arg(&vault)]));
    let at = typed_password(&mut p, "password");
    let at = p.expect_from(at, "This password is weak and could be guessed");
    let shown = Instant::now();
    let at = p.expect_from(
        at,
        "Create the vault with this weak password anyway? [y/N] ",
    );
    assert!(
        shown.elapsed().as_secs_f64() >= 4.5,
        "{:?}",
        shown.elapsed()
    );
    p.line("n");
    let at = p.expect_from(at, "Choose a stronger password.");
    p.expect_from(at, "New master password: ");
    p.send(b"\x03");
    let (code, all) = p.finish();
    assert_eq!(code, 1, "{all}");
    assert!(all.contains("cancelled"));
    assert!(!vault.exists());
}

#[test]
fn init_refusals() {
    let home = Home::new();
    let vault = home.vault();
    // No terminal on stdin.
    let out = piped(home.qvault(["init", &arg(&vault)]), b"");
    assert_eq!(out.code, 2, "{}", out.stderr);
    assert!(!vault.exists());
    // --password-stdin is refused.
    let out = piped(
        home.qvault(["init", "--password-stdin", &arg(&vault)]),
        b"pw\n",
    );
    assert_eq!(out.code, 2);
    // A wrong extension.
    let p = Interactive::spawn(home.qvault(["init", &arg(&home.vaults().join("v.txt"))]));
    let (code, all) = p.finish();
    assert_eq!(code, 2, "{all}");
    // An existing path is left untouched.
    std::fs::write(&vault, b"not a vault").unwrap();
    let p = Interactive::spawn(home.qvault(["init", &arg(&vault)]));
    let (code, all) = p.finish();
    assert_eq!(code, 1, "{all}");
    assert!(all.contains("path already exists"));
    assert_eq!(std::fs::read(&vault).unwrap(), b"not a vault");
}

#[test]
fn info_unverified_and_full() {
    let home = Home::new();
    let vault = home.vault();
    drop(home.create());
    // No password, no terminal.
    let out = piped(home.qvault(["info", "-v", &arg(&vault)]), b"");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.starts_with("Vault header (unverified"));
    assert!(
        out.stdout
            .contains("format:          0x7fff0003 (development")
    );
    assert!(
        out.stdout
            .contains("Argon2id, 256 MiB, 3 iterations, 4 lanes")
    );
    assert!(!out.stdout.contains("Test vault"));
    // JSON.
    let out = piped(home.qvault(["info", "--json", "-v", &arg(&vault)]), b"");
    assert_eq!(out.code, 0);
    assert!(
        out.stdout
            .starts_with("{\"verified\":false,\"vault_id\":\"")
    );
    assert!(out.stdout.contains(
        "\"kdf\":{\"profile\":1,\"memory_kib\":262144,\"iterations\":3,\"parallelism\":4}"
    ));
    // --full with the password on stdin.
    let line = format!("{}\n", common::PASSWORD);
    let out = piped(
        home.qvault(["info", "--full", "--password-stdin", "-v", &arg(&vault)]),
        line.as_bytes(),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.contains("name:            Test vault"));
    let out = piped(
        home.qvault([
            "info",
            "--full",
            "--json",
            "--password-stdin",
            "-v",
            &arg(&vault),
        ]),
        line.as_bytes(),
    );
    assert!(
        out.stdout
            .contains("\"overview\":{\"name\":\"Test vault\",\"entries\":0")
    );
    // A wrong password is exit 3; no password and no terminal is exit 2.
    let out = piped(
        home.qvault(["info", "--full", "--password-stdin", "-v", &arg(&vault)]),
        b"wrong\n",
    );
    assert_eq!(out.code, 3, "{}", out.stderr);
    assert!(out.stderr.contains("wrong password"));
    let out = piped(home.qvault(["info", "--full", "-v", &arg(&vault)]), b"");
    assert_eq!(out.code, 2);
    // A missing vault is exit 4; no vault selected is exit 2.
    let out = piped(
        home.qvault(["info", "-v", &arg(&home.vaults().join("x.qvault"))]),
        b"",
    );
    assert_eq!(out.code, 4);
    let out = piped(home.qvault(["info"]), b"");
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("no vault selected"));
    // QVAULT_PATH and the config file select it too.
    let mut c = home.qvault(["info"]);
    c.env("QVAULT_PATH", &vault);
    assert_eq!(piped(c, b"").code, 0);
    common::write_config(&home, &format!("default_vault = \"{}\"\n", arg(&vault)));
    assert_eq!(piped(home.qvault(["info"]), b"").code, 0);
    common::write_config(&home, "unknown = 1\n");
    let out = piped(home.qvault(["info"]), b"");
    assert_eq!(out.code, 2);
    assert!(
        out.stderr
            .contains("config file line 1: unknown key `unknown`")
    );
}
