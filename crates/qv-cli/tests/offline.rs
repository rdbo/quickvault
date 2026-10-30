// SPDX-License-Identifier: AGPL-3.0-or-later

//! 0012 *Implicit server prerequisite* (CLI part): a vault is created,
//! unlocked, edited and recovered with its phrase with no config file, no
//! account, no server setting and an empty home, and, where `unshare -rn` works, with networking blocked
//! (a new network namespace with no interfaces). Plus a check that the CLI
//! links no networking crate. `QV_REQUIRE_NETNS=1` turns an unavailable
//! namespace into a failure instead of a skip.

#![cfg(any(target_os = "linux", target_os = "android"))]
// The helpers are test code, but clippy's `allow-*-in-tests` settings only
// cover `#[test]` functions.
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::process::Command;

use common::{Home, Interactive, arg, piped};

const PW: &str = "v7#Qm!2pZr9&Lw4tX0^sK8@e";
const NEW: &str = "s8!Qp#7mV2$xR9&kL4@zN6%wT1";

/// The 24 numbered words of the phrase display before `at`.
fn phrase(p: &Interactive, at: usize) -> String {
    let seen = String::from_utf8_lossy(&p.seen[..at]).into_owned();
    let screen = &seen[seen.rfind("Recovery phrase.").unwrap()..];
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
    words.join(" ")
}

/// `qvault` with `args`, inside `unshare -rn` when `blocked`.
fn cmd(home: &Home, blocked: bool, args: &[&str]) -> Command {
    let base = home.qvault(args);
    if !blocked {
        return base;
    }
    let mut c = Command::new("unshare");
    c.arg("-rn").arg(base.get_program()).args(base.get_args());
    c.env_clear();
    for (k, v) in base.get_envs() {
        if let Some(v) = v {
            c.env(k, v);
        }
    }
    c
}

fn flow(blocked: bool) {
    let home = Home::new();
    let vault = arg(&home.vault());
    // init on a terminal; the phrase check is skipped to keep it short.
    let mut p = Interactive::spawn(cmd(&home, blocked, &["init", &vault]));
    let at = p.expect("Use this passphrase? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(PW);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(PW);
    let at = p.expect_from(at, "Press any key");
    let words = phrase(&p, at);
    p.send(b" ");
    let at = p.expect_from(at, "Word #");
    p.line("");
    let at = p.expect_from(at, "Show the recovery phrase again? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "Skip checking the recovery phrase? [y/N] ");
    p.line("y");
    p.expect_from(at, "Skip anyway? [y/N] ");
    p.line("y");
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");

    let stdin = format!("{PW}\n");
    for args in [
        &["info", "--full"][..],
        &["ls", "-r"],
        &["search", "x"],
        &["generate", "--pin", "4"],
    ] {
        let mut a = vec!["--password-stdin", "-v", &vault];
        a.extend_from_slice(args);
        let out = piped(cmd(&home, blocked, &a), stdin.as_bytes());
        assert_eq!(out.code, 0, "{args:?}: {}", out.stderr);
    }
    for args in [
        &["mkdir", "Work/Nested", "-p"][..],
        &["add", "Work/Nested/Offline", "--generate", "--pin", "8"],
        &["edit", "Work/Nested/Offline", "--username", "offline-user"],
        &["mv", "Work/Nested/Offline", "/"],
        &["rm", "Offline"],
        &["trash", "restore", "Offline"],
        &["show", "Offline"],
    ] {
        let mut a = vec!["--password-stdin", "-v", &vault];
        a.extend_from_slice(args);
        let out = piped(cmd(&home, blocked, &a), stdin.as_bytes());
        assert_eq!(out.code, 0, "{args:?}: {}", out.stderr);
    }

    // Recovery with the phrase; the earlier commands took a snapshot.
    let mut p = Interactive::spawn(cmd(&home, blocked, &["recover", &vault]));
    p.expect("Recovery phrase (24 words): ");
    p.line(&words);
    let at = p.expect("Use this passphrase? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(NEW);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(NEW);
    let at = p.expect_from(at, "Vault recovered and master password changed.");
    p.expect_from(at, "Delete these pre-change local snapshots? [y/N] ");
    p.line("n");
    let (code, all) = p.finish();
    assert_eq!(code, 0, "{all}");
    let out = piped(
        cmd(
            &home,
            blocked,
            &["--password-stdin", "-v", &vault, "show", "Offline"],
        ),
        format!("{NEW}\n").as_bytes(),
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(!home.config_file().exists());
}

// 0012 §1: Implicit server prerequisite
#[test]
fn offline_without_any_configuration() {
    flow(false);
}

// 0012 §1: Implicit server prerequisite
/// Skipped (never counted as a pass) where `unshare -rn` is unavailable,
/// unless `QV_REQUIRE_NETNS=1` (CI) makes that a failure (plan 0024).
#[test]
fn offline_with_networking_blocked() {
    let required = std::env::var_os("QV_REQUIRE_NETNS").is_some_and(|v| v == "1");
    let unavailable = |why: String| {
        if required {
            panic!("QV_REQUIRE_NETNS=1 but unshare -rn is unavailable: {why}");
        }
        eprintln!("SKIPPED (not a pass): unshare -rn is unavailable here: {why}");
    };
    match Command::new("unshare").args(["-rn", "true"]).output() {
        Ok(o) if o.status.success() => flow(true),
        Ok(o) => unavailable(String::from_utf8_lossy(&o.stderr).trim().to_owned()),
        Err(e) => unavailable(format!("unshare not found: {e}")),
    }
}

// 0012 §1: Supply chain
#[test]
fn offline_cli_dependencies_are_fixed() {
    let manifest = include_str!("../Cargo.toml");
    let deps: Vec<&str> = manifest
        .split("\n[dependencies]\n")
        .nth(1)
        .unwrap()
        .split("\n[")
        .next()
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
        .map(|l| l.split(['.', ' ', '=']).next().unwrap())
        .collect();
    assert_eq!(
        deps,
        [
            "clap",
            "qv-core",
            "rustix",
            "signal-hook",
            "x11rb",
            "x11rb-protocol",
            "zeroize"
        ]
    );
}
