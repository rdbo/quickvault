// SPDX-License-Identifier: AGPL-3.0-or-later

//! Actual CLI import/export, consent, receipt restart and suppression behavior.
#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;
use common::{Home, Output, PASSWORD, arg, piped};

fn run(h: &Home, extra: &[&str]) -> Output {
    let vault = arg(&h.vault());
    let mut args = vec!["--password-stdin", "-v", &vault];
    args.extend_from_slice(extra);
    piped(h.qvault(args), format!("{PASSWORD}\n").as_bytes())
}

// 0012 §1: Exchange-file password guessing
#[test]
fn exchange_cli_preflight_and_explicit_backup_consent() {
    let h = Home::new();
    let dest = arg(&h.root.join("exports"));
    for extra in [
        vec!["--json", "merge", "missing"],
        vec!["--json", "snapshot", "export", &dest],
        vec!["snapshot", "export", &dest, "--self-contained"],
    ] {
        let o = run(&h, &extra);
        assert_eq!(o.code, 2, "{}", o.stderr);
        assert!(!h.root.join("exports").exists());
        assert!(o.stdout.is_empty());
    }
    let mut prompt = common::Interactive::spawn(h.qvault([
        "-v",
        &arg(&h.vault()),
        "snapshot",
        "export",
        &dest,
        "--self-contained",
    ]));
    prompt.expect("Include the password slot in this backup?");
    prompt.line("n");
    let (code, output) = prompt.finish();
    assert_eq!(code, 1, "{output}");
    assert!(!output.contains("Master password:"));
    assert!(!h.root.join("exports").exists());
    h.create().lock();
    let o = run(&h, &["--yes", "snapshot", "export", &dest]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let id = o.stdout.trim();
    assert_eq!(id.len(), 32);
    assert!(id.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(h.root.join("exports").join(format!("{id}.qvsnap")).exists());
    assert!(!o.stderr.contains("offline master-password guessing"));
    let o = run(
        &h,
        &["--yes", "snapshot", "export", &dest, "--self-contained"],
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stderr.contains("offline master-password guessing"));
    assert_eq!(
        std::fs::read_dir(h.root.join("exports")).unwrap().count(),
        2
    );
    let backup = h
        .root
        .join("exports")
        .join(format!("{}.qvsnap", o.stdout.trim()));
    let o = run(&h, &["merge", &arg(&backup)]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.stdout, "local acceptance: committed\nconflicts: 0\n");
}

// 0012 §1: Hostile files from sync folders
// 0012 §1: Deleted-entry resurrection
#[test]
fn exchange_cli_old_archive_keeps_suppression_and_receipts_survive_restart() {
    let h = Home::new();
    let s = h.create();
    let root = s.root().unwrap();
    let entry = s
        .save_entry(s.new_entry(root, "login", "archive canary").unwrap())
        .unwrap();
    let directory = h.root.join("exports");
    let old = s.export_archive(&directory, false, None).unwrap();
    let source = directory.join(format!("{}.qvsnap", old.archive_id));
    let mut draft = s.edit_entry(entry).unwrap();
    draft.entry_mut().title = qv_core::Text::new("current complete version").unwrap();
    s.save_entry(draft).unwrap();
    s.purge_history(entry).unwrap();
    let newer = s.export_archive(&directory, false, None).unwrap();
    s.lock();
    let o = run(&h, &["merge", &arg(&source)]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.stdout, "local acceptance: committed\nconflicts: 0\n");
    assert!(!o.stdout.contains("archive canary"));
    let s = h.unlock();
    let entry = match s.search("current complete version").unwrap().remove(0) {
        qv_core::SearchHit::Entry(e) => e.handle,
        _ => panic!(),
    };
    assert!(s.history(entry).unwrap().is_empty());
    s.lock();
    let o = run(&h, &["merge", &arg(&source)]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("already accepted"));
    std::fs::copy(
        directory.join(format!("{}.qvsnap", newer.archive_id)),
        &source,
    )
    .unwrap();
    let o = run(&h, &["merge", &arg(&source)]);
    assert_eq!(o.code, 7, "{}", o.stderr);
    assert!(o.stdout.is_empty());
}
