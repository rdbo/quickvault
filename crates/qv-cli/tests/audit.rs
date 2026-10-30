// SPDX-License-Identifier: AGPL-3.0-or-later

//! Offline release audits through the real binary (plan 0024 steps 2–4;
//! 0012 §3: permissions, disk-full behaviour, redacted errors):
//! - every file and directory QuickVault creates is owner-only even under
//!   `umask 000` (0008 §5);
//! - writes that hit a file-size limit (`EFBIG`, the same error class as
//!   `ENOSPC`) fail closed at each write path, with the previous vault,
//!   anchor and trash intact;
//! - canary secrets never reach the output of failing commands or any
//!   file in plaintext.
//!
//! A real full-disk test needs root or a tmpfs mount; the file-size limit
//! (`prlimit --fsize`, with `SIGXFSZ` ignored) exercises the same write-error
//! paths without either.
#![cfg(any(target_os = "linux", target_os = "android"))]
// Test-only PTY/fixture helpers fail the test on setup or protocol errors.
#![allow(clippy::unwrap_used, clippy::panic, clippy::expect_used)]
mod common;

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use common::{Home, Interactive, Output, PASSWORD, arg, piped, pw, serial};
use qv_core::{FieldKind, FieldValue, ItemHandle};

const NEW: &str = "s8!Qp#7mV2$xR9&kL4@zN6%wT1";
const THIRD: &str = "h3^Tz8!Wq5#Lm1&Vr7@Kd2%Ny9";

/// `base` run through `sh -c script`, where the script ends with
/// `exec ... "$0" "$@"`. Keeps `base`'s cleared environment and directory.
fn wrapped(base: Command, script: &str) -> Command {
    let mut c = Command::new("sh");
    c.arg("-c")
        .arg(script)
        .arg(base.get_program())
        .args(base.get_args());
    c.env_clear().env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    for (k, v) in base.get_envs() {
        if let Some(v) = v {
            c.env(k, v);
        }
    }
    if let Some(d) = base.get_current_dir() {
        c.current_dir(d);
    }
    c
}

fn umask0(base: Command) -> Command {
    wrapped(base, r#"umask 000; exec "$0" "$@""#)
}

/// No file this process writes may grow past `bytes` (`EFBIG`).
fn limited(base: Command, bytes: u64) -> Command {
    wrapped(
        base,
        &format!(r#"trap "" XFSZ; exec prlimit --fsize={bytes} -- "$0" "$@""#),
    )
}

fn with_vault(h: &Home, args: &[&str]) -> Vec<String> {
    let mut all = vec![
        "--password-stdin".to_owned(),
        "-v".to_owned(),
        arg(&h.vault()),
    ];
    all.extend(args.iter().map(|a| (*a).to_owned()));
    all
}

/// Runs from the home directory: attachment sources are relative paths
/// there (an absolute path through the shared `/tmp` is refused).
fn run_as(h: &Home, wrap: impl Fn(Command) -> Command, password: &str, args: &[&str]) -> Output {
    let mut c = h.qvault(with_vault(h, args));
    c.current_dir(&h.root);
    piped(wrap(c), format!("{password}\n").as_bytes())
}

/// Every path under `dir` (lstat), recursively.
fn walk(dir: &Path) -> Vec<(PathBuf, std::fs::Metadata)> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let m = std::fs::symlink_metadata(&p).unwrap();
        if m.is_dir() {
            out.extend(walk(&p));
        }
        out.push((p, m));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Every regular file under `dir` with its bytes.
fn files(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    walk(dir)
        .into_iter()
        .filter(|(_, m)| m.is_file())
        .map(|(p, _)| {
            let b = std::fs::read(&p).unwrap();
            (p, b)
        })
        .collect()
}

/// The 24 numbered words of the last phrase display between `from` and `at`.
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

/// Answers the password chooser with `password`.
fn choose(p: &mut Interactive, from: usize, password: &str) -> usize {
    let at = p.expect_from(from, "Use this passphrase? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(password);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(password);
    at
}

/// A completed `recovery rotate` from `old` to `new`.
fn rotate(cmd: Command, old: &str, new: &str) {
    let mut p = Interactive::spawn(cmd);
    p.expect("Master password: ");
    p.line(old);
    let at = p.expect("Type rotate to continue: ");
    p.line("rotate");
    let at = choose(&mut p, at, new);
    let end = p.expect_from(at, "Press any key when you have written them down.");
    let words = phrase_words(&p, at, end);
    p.send(b" ");
    let mut at = end;
    for _ in 0..3 {
        let w = p.expect_from(at, "Word #");
        let colon = p.expect_from(w, ": ");
        let n: usize = String::from_utf8_lossy(&p.seen[w..colon - 2])
            .parse()
            .unwrap();
        p.line(&words[n - 1]);
        at = colon;
    }
    p.expect_from(at, "Key rotation complete");
    let (code, text) = p.finish();
    assert_eq!(code, 0, "{text}");
}

// ---- Step 2: modes ------------------------------------------------------

// 0012 §1: Ambiguous trust boundary
#[test]
fn audit_modes_owner_only_under_umask_000() {
    let h = Home::new();
    let vault = arg(&h.vault());

    // init on a terminal (phrase check skipped to keep it short).
    let mut p = Interactive::spawn(umask0(h.qvault(["init", &vault])));
    let at = choose(&mut p, 0, PASSWORD);
    let at = p.expect_from(at, "Press any key");
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

    // The attachment source is the test's own file, outside QuickVault's
    // directories.
    let input = h.root.join("input.bin");
    std::fs::write(&input, vec![7u8; 200_000]).unwrap();
    for args in [
        vec!["add", "Mail", "--generate"],
        vec!["attach", "add", "Mail", "input.bin"],
        vec!["rm", "Mail"],
        vec!["--yes", "trash", "empty"],
        vec!["snapshot", "ls"],
    ] {
        let o = run_as(&h, umask0, PASSWORD, &args);
        assert_eq!(o.code, 0, "{args:?}: {}", o.stderr);
    }

    let mut p = Interactive::spawn(umask0(h.qvault(["-v", &vault, "--yes", "passwd"])));
    p.expect("Master password: ");
    p.line(PASSWORD);
    let at = choose(&mut p, 0, NEW);
    let at = p.expect_from(at, "Master password changed.");
    p.expect_from(at, "Delete these pre-change local snapshots? [y/N] ");
    p.line("n");
    let (code, text) = p.finish();
    assert_eq!(code, 0, "{text}");

    rotate(
        umask0(h.qvault(["-v", &vault, "recovery", "rotate"])),
        NEW,
        THIRD,
    );

    let mut checked = 0;
    for (path, m) in walk(&h.root) {
        assert!(!m.file_type().is_symlink(), "symlink: {path:?}");
        if path == input {
            continue;
        }
        let mode = m.mode() & 0o7777;
        if m.is_dir() {
            assert_eq!(mode, 0o700, "{path:?}");
        } else {
            assert!(m.is_file(), "not a regular file: {path:?}");
            assert_eq!(mode, 0o600, "{path:?}");
            checked += 1;
        }
    }
    // The vault, its anchor, snapshots and the inventory at least.
    assert!(checked >= 4, "{checked}");
    assert!(
        walk(&h.snapshots())
            .iter()
            .any(|(p, _)| p.to_string_lossy().ends_with(".qvinv")),
        "the rotation's inventory was created"
    );
}

// ---- Step 3: write failure ----------------------------------------------

/// Byte evidence of the vault directory and the anchors.
fn evidence(h: &Home) -> Vec<(PathBuf, Vec<u8>)> {
    let mut v = files(&h.vaults());
    v.extend(files(&h.anchors()));
    v
}

/// The vault still unlocks normally (anchor verified) with `names` live.
fn intact(h: &Home, names: &[&str]) {
    let s = h.unlock();
    let mut live: Vec<String> = s
        .list(s.root().unwrap())
        .unwrap()
        .entries
        .iter()
        .map(|e| e.title.expose().to_owned())
        .collect();
    live.sort();
    assert_eq!(live, names);
    s.lock();
}

fn failed_closed(o: &Output, what: &str) {
    assert!(
        matches!(o.code, 1 | 9),
        "{what}: exit {}: {}",
        o.code,
        o.stderr
    );
    assert!(!o.stderr.contains("panicked"), "{what}: {}", o.stderr);
}

/// No `.tmp-` or rotation files beside the vault.
fn no_partial_files(h: &Home) {
    for (p, _) in walk(&h.vaults()) {
        let n = p.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !n.contains(".tmp-") && !n.contains(".qvrotate"),
            "left behind: {n}"
        );
    }
}

// 0012 §1: Snapshot disk growth
#[test]
fn audit_write_failure_fails_closed_at_every_write_path() {
    let h = Home::new();
    {
        let s = h.create();
        s.save_entry(s.new_entry(s.root().unwrap(), "login", "Keep").unwrap())
            .unwrap();
        s.lock();
    }
    let before = evidence(&h);

    // Automatic snapshot (best effort): the unlock succeeds, the copy is not
    // written and no partial archive is left.
    let o = run_as(&h, |c| limited(c, 1024), PASSWORD, &["ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("Keep"), "{}", o.stdout);
    assert!(o.stderr.to_lowercase().contains("snapshot"), "{}", o.stderr);
    if h.snapshots().exists() {
        assert!(
            files(&h.snapshots()).is_empty(),
            "{:?}",
            walk(&h.snapshots())
        );
    }
    assert_eq!(evidence(&h), before);

    // One normal run takes today's copy, so later runs skip it.
    assert_eq!(run_as(&h, |c| c, PASSWORD, &["ls"]).code, 0);
    let size = std::fs::metadata(h.vault()).unwrap().len();
    let before = evidence(&h);

    // Vault growth through an entry and through an attachment.
    // Below the kernel's 128 KiB limit for one argument.
    let big = format!("note={}", "x".repeat(120_000));
    let o = run_as(
        &h,
        |c| limited(c, size),
        PASSWORD,
        &["add", "Grow", "--generate", "--field", &big],
    );
    failed_closed(&o, "add");
    intact(&h, &["Keep"]);
    assert_eq!(evidence(&h), before);
    no_partial_files(&h);

    let input = h.root.join("input.bin");
    std::fs::write(&input, vec![3u8; 3 * 1024 * 1024]).unwrap();
    let o = run_as(
        &h,
        |c| limited(c, size + 64 * 1024),
        PASSWORD,
        &["attach", "add", "Keep", "input.bin"],
    );
    failed_closed(&o, "attach add");
    intact(&h, &["Keep"]);
    assert_eq!(evidence(&h), before);
    no_partial_files(&h);

    // The mandatory recovery copy of `trash empty` (0012 "Snapshot disk
    // growth", offline part): no copy, no deletion.
    {
        let s = h.unlock();
        let e = s.list(s.root().unwrap()).unwrap().entries[0].handle;
        s.delete(ItemHandle::Entry(e), false).unwrap();
        s.lock();
    }
    let snaps = files(&h.snapshots());
    let o = run_as(
        &h,
        |c| limited(c, 1024),
        PASSWORD,
        &["--yes", "trash", "empty"],
    );
    failed_closed(&o, "trash empty");
    {
        let s = h.unlock();
        assert_eq!(s.trash().unwrap().len(), 1);
        s.lock();
    }
    assert_eq!(files(&h.snapshots()), snaps);

    // Key rotation: its recovery copy or replacement cannot be written;
    // nothing is published and the old password still opens the vault.
    let before = evidence(&h);
    let vault = arg(&h.vault());
    let mut p = Interactive::spawn(limited(
        h.qvault(["-v", &vault, "recovery", "rotate"]),
        1024,
    ));
    p.expect("Master password: ");
    p.line(PASSWORD);
    let at = p.expect("Type rotate to continue: ");
    p.line("rotate");
    choose(&mut p, at, NEW);
    let (code, text) = p.finish();
    assert!(matches!(code, 1 | 9), "rotate: exit {code}: {text}");
    assert!(!text.contains("panicked"), "{text}");
    assert!(!text.contains("partly applied"), "{text}");
    assert_eq!(evidence(&h), before);
    no_partial_files(&h);
    intact(&h, &[]);

    // A new vault: nothing is published at the target.
    let target = h.vaults().join("new.qvault");
    let mut p = Interactive::spawn(limited(h.qvault(["init", &arg(&target)]), 4096));
    choose(&mut p, 0, PASSWORD);
    let (code, text) = p.finish();
    assert!(matches!(code, 1 | 9), "init: exit {code}: {text}");
    assert!(!text.contains("panicked"), "{text}");
    assert!(!target.exists());
    no_partial_files(&h);
}

// ---- Step 4: canaries ---------------------------------------------------

const CANARY_MASTER: &str = "qvCanaryMaster-5d1e8b40c2a7";
const CANARY_WRONG: &str = "qvCanaryWrong-91f0a3e6d4b2";
const CANARY_OLD: &str = "qvCanaryOldValue-0c6f2a9e71d3";
const CANARY_FIELD: &str = "qvCanaryField-7f3a91be5c08";
const CANARY_NEW: &str = "qvCanaryNewPassword-3b8e0d5a19c4";
const CANARIES: [&str; 5] = [
    CANARY_MASTER,
    CANARY_WRONG,
    CANARY_OLD,
    CANARY_FIELD,
    CANARY_NEW,
];

fn no_canary(what: &str, text: &str) {
    for c in CANARIES {
        assert!(!text.contains(c), "{what}: canary {c} leaked: {text}");
    }
}

// 0012 §1: Ambiguous trust boundary
// 0012 §1: CLI argument leakage
#[test]
fn audit_canary_secrets_never_reach_output_or_files() {
    let h = Home::new();
    {
        let _s = serial();
        let s = h
            .core()
            .create(&h.vault(), &pw(CANARY_MASTER), "Canaries")
            .unwrap()
            .session;
        let mut d = s.new_entry(s.root().unwrap(), "login", "Canary").unwrap();
        d.add_field(
            "password",
            FieldKind::Secret,
            FieldValue::text(CANARY_OLD).unwrap(),
        )
        .unwrap();
        let e = s.save_entry(d).unwrap();
        // The old value stays in retained history.
        let mut d = s.edit_entry(e).unwrap();
        d.entry_mut().fields[0].value = FieldValue::text(CANARY_FIELD).unwrap();
        s.save_entry(d).unwrap();
        s.lock();
    }
    // One ordinary snapshot, so archives are scanned too.
    assert_eq!(run_as(&h, |c| c, CANARY_MASTER, &["ls"]).code, 0);

    let corrupt = h.vaults().join("corrupt.qvault");
    // A clobbered SQLite magic: always read, so always refused. (A flipped
    // byte at an arbitrary offset can land in a page's unallocated gap,
    // which is never read.)
    let mut bytes = std::fs::read(h.vault()).unwrap();
    bytes[..16].fill(0x55);
    std::fs::write(&corrupt, &bytes).unwrap();
    std::fs::set_permissions(&corrupt, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::File::create(h.root.join("large.bin"))
        .unwrap()
        .set_len(10 * 1024 * 1024 + 1)
        .unwrap();
    let restored = arg(&h.vaults().join("restored.qvault"));

    let cases: Vec<(&str, Vec<String>, &str, i32)> = vec![
        ("wrong password", with_vault(&h, &["ls"]), CANARY_WRONG, 3),
        (
            "wrong password, json",
            with_vault(&h, &["--json", "show", "Canary"]),
            CANARY_WRONG,
            3,
        ),
        (
            "missing entry",
            with_vault(&h, &["show", "Missing"]),
            CANARY_MASTER,
            4,
        ),
        (
            "protected field without --reveal",
            with_vault(&h, &["show", "Canary", "--field", "password"]),
            CANARY_MASTER,
            -1,
        ),
        (
            "over-limit attachment",
            with_vault(&h, &["attach", "add", "Canary", "large.bin"]),
            CANARY_MASTER,
            9,
        ),
        (
            "unknown snapshot",
            with_vault(&h, &["snapshot", "restore", &"0".repeat(32), &restored]),
            CANARY_MASTER,
            4,
        ),
        (
            "history of a missing entry, json",
            with_vault(&h, &["--json", "history", "Missing"]),
            CANARY_MASTER,
            4,
        ),
        (
            "corrupt vault",
            vec![
                "--password-stdin".to_owned(),
                "-v".to_owned(),
                arg(&corrupt),
                "show".to_owned(),
                "Canary".to_owned(),
            ],
            CANARY_MASTER,
            -1,
        ),
    ];
    for (what, args, password, want) in cases {
        let mut c = h.qvault(&args);
        c.current_dir(&h.root);
        let o = piped(c, format!("{password}\n").as_bytes());
        assert_ne!(o.code, 0, "{what}: {}", o.stdout);
        if want >= 0 {
            assert_eq!(o.code, want, "{what}: {}", o.stderr);
        }
        no_canary(what, &o.stdout);
        no_canary(what, &o.stderr);
    }

    // A cancelled rotation, on a terminal.
    let mut p = Interactive::spawn(h.qvault(["-v", &arg(&h.vault()), "recovery", "rotate"]));
    p.expect("Master password: ");
    p.line(CANARY_MASTER);
    p.expect("Type rotate to continue: ");
    p.line("no");
    let (code, text) = p.finish();
    assert_eq!(code, 1, "{text}");
    no_canary("cancelled rotation", &text);

    // A new password typed, mismatched, then cancelled.
    let mut p = Interactive::spawn(h.qvault(["-v", &arg(&h.vault()), "passwd"]));
    p.expect("Master password: ");
    p.line(CANARY_MASTER);
    let at = p.expect("Use this passphrase? [y/N] ");
    p.line("n");
    let at = p.expect_from(at, "New master password: ");
    p.line(CANARY_NEW);
    let at = p.expect_from(at, "Repeat the master password: ");
    p.line(&format!("{CANARY_NEW}-mismatch"));
    let at = p.expect_from(at, "The passwords do not match; try again.");
    p.expect_from(at, "New master password: ");
    p.send(&[3]);
    let (code, text) = p.finish();
    assert_eq!(code, 1, "{text}");
    no_canary("cancelled password change", &text);

    // No file holds a canary in plaintext: vault pages, journals, anchors,
    // archives and anything else QuickVault wrote.
    for (path, bytes) in files(&h.root) {
        for c in CANARIES {
            assert!(
                common::find(&bytes, c.as_bytes()).is_none(),
                "canary {c} in {path:?}"
            );
        }
    }
}
