// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault recovery rotate` end to end through a PTY (plan 0023 step 8;
//! 0011 §4, §5.5, §6; 0012 §1 rows "Rotation/purge ambiguity" and
//! old-generation archives).
#![cfg(any(target_os = "linux", target_os = "android"))]
// Test-only PTY/fixture helpers fail the test on setup or protocol errors.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod common;

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};

use common::{Home, Interactive, PASSWORD, arg, piped, pw, serial};

const NEW: &str = "s8!Qp#7mV2$xR9&kL4@zN6%wT1";

fn create(h: &Home) {
    let _s = serial();
    h.core()
        .create(&h.vault(), &pw(PASSWORD), "Rotation")
        .unwrap()
        .session
        .lock();
}

/// Runs `args` with `password` on standard input.
fn run(h: &Home, password: &str, args: &[&str]) -> common::Output {
    let mut all = vec!["--password-stdin", "-v"];
    let v = arg(&h.vault());
    all.push(&v);
    all.extend_from_slice(args);
    piped(h.qvault(all), format!("{password}\n").as_bytes())
}

/// Every file under `dir`, recursively, with its bytes.
fn tree(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        if e.file_type().unwrap().is_dir() {
            out.extend(tree(&p));
        } else {
            out.push((p.clone(), std::fs::read(&p).unwrap()));
        }
    }
    out.sort();
    out
}

fn copy_tree(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let target = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            if !target.exists() {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&target)
                    .unwrap();
            }
            copy_tree(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), &target).unwrap();
        }
    }
}

fn reserved(h: &Home) -> usize {
    std::fs::read_dir(h.vaults())
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .contains(".qvrotate")
        })
        .count()
}

/// The 24 numbered words of the last phrase display before `at`.
fn phrase_words(p: &Interactive, from: usize, at: usize) -> Vec<String> {
    let seen = String::from_utf8_lossy(&p.seen[from..at]).into_owned();
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
    words
}

/// The number asked for by the next `Word #N: ` prompt after `from`.
fn asked(p: &mut Interactive, from: usize) -> (usize, usize) {
    let end = p.expect_from(from, "Word #");
    let colon = p.expect_from(end, ": ");
    let n = String::from_utf8_lossy(&p.seen[end..colon - 2])
        .parse()
        .unwrap();
    (n, colon)
}

/// Starts `recovery rotate` and answers up to the phrase display; returns
/// the words and the position after the phrase screen.
fn up_to_phrase(h: &Home, yes: bool) -> (Interactive, Vec<String>, usize) {
    let v = arg(&h.vault());
    let mut args = vec!["-v", v.as_str()];
    if yes {
        args.push("--yes");
    }
    args.extend(["recovery", "rotate"]);
    let mut p = Interactive::spawn(h.qvault(args));
    p.expect("Master password: ");
    p.line(PASSWORD);
    let at = p.expect("Type rotate to continue: ");
    p.line("rotate");
    let at = p.expect_from(at, "Use this passphrase? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(NEW);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(NEW);
    let end = p.expect_from(at, "Press any key when you have written them down.");
    let words = phrase_words(&p, at, end);
    p.send(b" ");
    (p, words, end)
}

fn confirm_words(p: &mut Interactive, words: &[String], mut at: usize) -> usize {
    for _ in 0..3 {
        let (n, next) = asked(p, at);
        p.line(&words[n - 1]);
        at = next;
    }
    p.expect_from(at, "The new recovery phrase is checked.")
}

#[test]
fn rotation_with_typed_confirmation_and_phrase_check() {
    let h = Home::new();
    create(&h);
    let ls = run(&h, PASSWORD, &["snapshot", "ls"]);
    assert_eq!(ls.code, 0, "{}", ls.stderr);
    let old_id = std::fs::read_dir(h.snapshots())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .find_map(|f| {
            f.strip_suffix(".qvsnap")
                .filter(|id| id.len() == 32)
                .map(str::to_owned)
        })
        .unwrap();
    // `--yes` does not skip the typed confirmation: the prompt still came.
    let (mut p, words, at) = up_to_phrase(&h, true);
    let at = confirm_words(&mut p, &words, at);
    p.expect_from(
        at,
        "Key rotation complete: the vault is now key generation 2.",
    );
    let (code, text) = p.finish();
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("open only with the old recovery phrase"));
    assert_eq!(reserved(&h), 0);

    assert_eq!(run(&h, NEW, &["ls"]).code, 0);
    assert_eq!(run(&h, PASSWORD, &["ls"]).code, 3);
    let info = run(&h, NEW, &["info"]);
    assert!(
        info.stdout.contains("key generation:  2"),
        "{}",
        info.stdout
    );
    // The old-generation copy is neither listed nor restored.
    let ls = run(&h, NEW, &["snapshot", "ls"]);
    assert_eq!(ls.code, 0, "{}", ls.stderr);
    assert!(!ls.stdout.contains(&old_id), "{}", ls.stdout);
    let target = h.vaults().join("restored.qvault");
    let restore = run(&h, NEW, &["snapshot", "restore", &old_id, &arg(&target)]);
    assert_eq!(restore.code, 7, "{}", restore.stderr);
    assert!(!target.exists());
    assert!(
        std::fs::read_dir(h.snapshots()).unwrap().any(|e| e
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(&old_id))
    );
}

#[test]
fn rotation_refusals_change_nothing() {
    let h = Home::new();
    create(&h);
    let vault = std::fs::read(h.vault()).unwrap();
    let anchors = tree(&h.anchors());

    // Non-interactive forms are usage errors before any prompt.
    assert_eq!(run(&h, PASSWORD, &["recovery", "rotate"]).code, 2);
    let json = piped(
        h.qvault(["--json", "-v", &arg(&h.vault()), "recovery", "rotate"]),
        b"",
    );
    assert_eq!(json.code, 2, "{}", json.stderr);
    let piped_stdin = piped(
        h.qvault(["-v", &arg(&h.vault()), "recovery", "rotate"]),
        b"",
    );
    assert_eq!(piped_stdin.code, 2, "{}", piped_stdin.stderr);

    // A wrong typed confirmation, even with --yes.
    let mut p =
        Interactive::spawn(h.qvault(["-v", &arg(&h.vault()), "--yes", "recovery", "rotate"]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    p.expect("Type rotate to continue: ");
    p.line("yes");
    let (code, text) = p.finish();
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("nothing changed"));

    // Cancelling at the phrase check.
    let (mut p, _, at) = up_to_phrase(&h, false);
    let (_, at) = asked(&mut p, at);
    p.line("");
    let at = p.expect_from(at, "Show the new recovery phrase again? [y/N] ");
    p.line("n");
    p.expect_from(at, "Cancel the key rotation? Nothing will change. [y/N] ");
    p.line("y");
    let (code, text) = p.finish();
    assert_eq!(code, 1, "{text}");
    assert!(text.contains("key rotation cancelled; nothing changed"));

    assert_eq!(std::fs::read(h.vault()).unwrap(), vault);
    assert_eq!(tree(&h.anchors()), anchors);
    assert_eq!(reserved(&h), 0);
    assert_eq!(run(&h, PASSWORD, &["ls"]).code, 0);
}

/// Resumes an interrupted rotation in `h` with `choice`.
fn resume(h: &Home, choice: &str) -> (i32, String) {
    let mut p = Interactive::spawn(h.qvault(["-v", &arg(&h.vault()), "recovery", "rotate"]));
    let at = p.expect("An interrupted key rotation was found for this vault.");
    let at = p.expect_from(at, "New master password (chosen for the rotation): ");
    p.line(NEW);
    let at = p.expect_from(at, "Previous master password: ");
    p.line(PASSWORD);
    p.expect_from(at, "Type complete or rollback: ");
    p.line(choice);
    p.finish()
}

// 0012 §1: Rotation/purge ambiguity
#[test]
fn rotation_interrupted_then_completed_or_rolled_back() {
    let h = Home::new();
    create(&h);
    // An unwritable anchor directory makes the anchor step fail after the
    // journal is published (unlock and snapshots never write anchors).
    let (mut p, words, at) = up_to_phrase(&h, false);
    std::fs::set_permissions(h.anchors(), std::fs::Permissions::from_mode(0o500)).unwrap();
    confirm_words(&mut p, &words, at);
    let (code, text) = p.finish();
    std::fs::set_permissions(h.anchors(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(code, 1, "{text}");
    assert!(
        text.contains("may be partly applied"),
        "{text} (running as root?)"
    );
    assert!(reserved(&h) > 0);

    // Ordinary access is refused with the hint.
    let ls = run(&h, PASSWORD, &["ls"]);
    assert_eq!(ls.code, 7, "{}", ls.stderr);
    assert!(
        ls.stderr.contains("interrupted key rotation"),
        "{}",
        ls.stderr
    );
    assert_eq!(run(&h, NEW, &["ls"]).code, 7);

    let rolled = Home::new();
    copy_tree(&h.root, &rolled.root);

    let (code, text) = resume(&h, "complete");
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("Key rotation complete."));
    assert_eq!(reserved(&h), 0);
    assert_eq!(run(&h, NEW, &["ls"]).code, 0);
    assert_eq!(run(&h, PASSWORD, &["ls"]).code, 3);

    let (code, text) = resume(&rolled, "rollback");
    assert_eq!(code, 0, "{text}");
    assert!(text.contains("rolled back"));
    assert_eq!(reserved(&rolled), 0);
    assert_eq!(run(&rolled, PASSWORD, &["ls"]).code, 0);
    assert_eq!(run(&rolled, NEW, &["ls"]).code, 3);
}
