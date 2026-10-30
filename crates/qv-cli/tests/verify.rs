// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault verify` (0011 §4–5): the full report, the anchor semantics, the
//! JSON shape and the integrity exits. The vault is never repaired.
#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Home, Output, PASSWORD, arg, piped};

fn run(h: &Home, extra: &[&str]) -> Output {
    let vault = arg(&h.vault());
    let mut a = vec!["--password-stdin", "-v", &vault];
    a.extend_from_slice(extra);
    piped(h.qvault(a), format!("{PASSWORD}\n").as_bytes())
}

#[test]
fn verify_reports_every_check_group_and_never_repairs() {
    let h = Home::new();
    let s = h.create();
    let root = s.root().unwrap();
    s.save_entry(s.new_entry(root, "login", "Mail").unwrap())
        .unwrap();
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    let before = std::fs::read(h.vault()).unwrap();

    let o = run(&h, &["verify"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    // One line per check group plus a summary line.
    assert!(o.stdout.contains("objects: "), "{}", o.stdout);
    assert!(o.stdout.contains("records: "), "{}", o.stdout);
    assert!(o.stdout.contains("anchor: verified"), "{}", o.stdout);
    assert!(o.stdout.contains("summary: ok"), "{}", o.stdout);
    assert!(!o.stdout.contains(&h.root.to_string_lossy().to_string()));
    assert!(!o.stderr.contains(&h.root.to_string_lossy().to_string()));
    // Read-only: the vault file is byte-identical and the sequence unchanged.
    assert_eq!(std::fs::read(h.vault()).unwrap(), before);
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
    drop(s);

    let o = run(&h, &["--json", "verify"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    // The documented key order and types; no ID, hash, payload or path.
    let json = o.stdout.trim_end();
    assert!(json.starts_with("{\"vault_id\":\""), "{json}");
    for key in [
        "\",\"key_generation\":1,\"local_seq\":",
        ",\"anchor\":\"verified\",\"objects\":",
        ",\"records\":",
        ",\"active_heads\":",
        ",\"retained_versions\":0,\"tombstones\":0,\"total_bytes\":",
        ",\"ok\":true,\"notes\":[]}",
    ] {
        assert!(json.contains(key), "missing {key}: {json}");
    }
    assert!(!json.contains(&h.root.to_string_lossy().to_string()));
    assert!(!json.contains("path"));
}

#[test]
fn verify_missing_anchor_is_reported_and_exits_7() {
    let h = Home::new();
    let s = h.create();
    drop(s);
    for entry in std::fs::read_dir(h.anchors()).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let o = run(&h, &["verify"]);
    assert_eq!(o.code, 7, "{}", o.stderr);
    // The report exists: the objects were still checked.
    assert!(o.stdout.contains("anchor: missing"), "{}", o.stdout);
    assert!(o.stdout.contains("summary: integrity check failed"));
    assert!(o.stderr.contains("integrity check failed"));

    let o = run(&h, &["--json", "verify"]);
    assert_eq!(o.code, 7);
    assert!(o.stdout.contains("\"anchor\":\"missing\""), "{}", o.stdout);
    assert!(o.stdout.contains("\"ok\":false"));
    assert!(o.stdout.contains("\"objects\":"));
}

#[test]
fn verify_wrong_password_and_a_damaged_vault_exit_3_and_7() {
    let h = Home::new();
    let s = h.create();
    drop(s);
    let vault = arg(&h.vault());
    let o = piped(
        h.qvault(["--password-stdin", "-v", &vault, "verify"]),
        b"wrong password\n",
    );
    assert_eq!(o.code, 3, "{}", o.stderr);
    assert!(o.stdout.is_empty());

    // Truncating the vault is detected before any report is produced and
    // nothing is repaired: the file stays exactly as it was.
    let bytes = std::fs::read(h.vault()).unwrap();
    std::fs::write(h.vault(), &bytes[..bytes.len() / 2]).unwrap();
    let damaged = std::fs::read(h.vault()).unwrap();
    let o = run(&h, &["verify"]);
    assert_eq!(o.code, 7, "{} {}", o.code, o.stderr);
    assert!(!o.stdout.contains("summary:"));
    assert_eq!(std::fs::read(h.vault()).unwrap(), damaged);
}

// 0012 §1: Exchange-file password guessing
#[test]
fn exchange_file_password_guessing_a_snapshot_does_not_open_with_the_password() {
    // 0012 §1 row "Exchange-file password guessing": a local snapshot carries
    // no password slot, so the master password alone opens nothing.
    let h = Home::new();
    let s = h.create();
    drop(s);
    // The first CLI unlock takes the first-of-day ordinary snapshot.
    let o = run(&h, &["snapshot", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let snapshot = std::fs::read_dir(h.snapshots())
        .unwrap()
        .map(|e| e.unwrap().path())
        .next()
        .expect("no snapshot was written");
    // Use the snapshot as if it were a vault file next to the real one.
    let copy = h.vaults().join("copy.qvault");
    std::fs::copy(&snapshot, &copy).unwrap();
    std::fs::set_permissions(&copy, std::fs::Permissions::from_mode(0o600)).unwrap();
    let o = piped(
        h.qvault(["--password-stdin", "-v", &arg(&copy), "verify"]),
        format!("{PASSWORD}\n").as_bytes(),
    );
    assert_ne!(o.code, 0, "the snapshot opened as a vault: {}", o.stdout);
    assert_ne!(o.code, 3, "the password was accepted as a keyslot");
    assert!(o.stdout.is_empty());
    // The real vault is untouched and still verifies.
    let o = run(&h, &["verify"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
}
