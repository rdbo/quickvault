// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault snapshot ls` and the `trash empty` recovery-snapshot ordering
//! (0011 §4–5, 0007 §3).
#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;

use std::os::unix::fs::PermissionsExt;

use common::{Home, Output, PASSWORD, arg, piped};
use qv_core::{ItemHandle, Session};

fn run(h: &Home, extra: &[&str]) -> Output {
    let vault = arg(&h.vault());
    let mut a = vec!["--password-stdin", "-v", &vault];
    a.extend_from_slice(extra);
    piped(h.qvault(a), format!("{PASSWORD}\n").as_bytes())
}

fn trashed_entry(s: &Session) -> ItemHandle {
    let root = s.root().unwrap();
    let e = s.new_entry(root, "login", "Mail").unwrap();
    let e = ItemHandle::Entry(s.save_entry(e).unwrap());
    s.delete(e, false).unwrap();
    e
}

#[test]
fn snapshot_ls_lists_authenticated_local_snapshots() {
    let h = Home::new();
    let s = h.create();
    drop(s);
    // The first unlock of the day takes one ordinary snapshot.
    let o = run(&h, &["snapshot", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let lines: Vec<&str> = o.stdout.lines().collect();
    assert_eq!(lines.len(), 1, "{}", o.stdout);
    let row = lines[0];
    let id = &row[..32];
    assert!(
        id.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{row}"
    );
    assert!(row.contains("ordinary"), "{row}");
    assert!(row.contains(" bytes on disk "), "{row}");
    assert!(row.contains(" objects  "), "{row}");

    let o = run(&h, &["--json", "snapshot", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let json = o.stdout.trim_end();
    assert!(json.starts_with("{\"snapshots\":[{\"id\":\""), "{json}");
    assert!(json.contains("\"created_at\":\""), "{json}");
    assert!(json.contains("\"kind\":\"ordinary\""), "{json}");
    assert!(json.contains("\"size\":"), "{json}");
    assert!(json.contains("\"objects\":"), "{json}");
    assert!(json.contains("\"total_bytes\":"), "{json}");
    assert!(json.ends_with("}]}"), "{json}");
    assert!(!json.contains(&h.root.to_string_lossy().to_string()));

    // A second unlock inside the hour coalesces: still one snapshot.
    let o = run(&h, &["snapshot", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.stdout.lines().count(), 1, "{}", o.stdout);
}

#[test]
fn hostile_files_from_sync_folders_are_warnings_not_rows() {
    // 0012 §1 row "Hostile files from sync folders": an unauthenticatable
    // archive in the snapshot directory never becomes a row, never stops the
    // healthy ones being listed and never reaches the vault.
    let h = Home::new();
    let s = h.create();
    drop(s);
    let o = run(&h, &["snapshot", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    let healthy = o.stdout.lines().count();
    assert_eq!(healthy, 1, "{}", o.stdout);
    let dir = h.snapshots();
    // A valid snapshot name with a truncated prefix and garbage frames.
    let hostile = "0123456789abcdef0123456789abcdef.qvsnap";
    std::fs::write(
        dir.join(hostile),
        b"QVSNAP\0\x01\x00\x00\x02\x00not a header",
    )
    .unwrap();
    let o = run(&h, &["snapshot", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.stdout.lines().count(), healthy, "{}", o.stdout);
    assert!(!o.stdout.contains("0123456789abcdef"));
    assert!(
        o.stderr.contains("could not be authenticated"),
        "{}",
        o.stderr
    );
    // The vault still verifies, so no exchange byte reached SQLite.
    let o = run(&h, &["verify"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
}

#[test]
fn trash_empty_takes_a_recovery_snapshot_before_the_deletion() {
    let h = Home::new();
    let s = h.create();
    let item = trashed_entry(&s);
    let seq = s.overview().unwrap().local_seq;
    drop(s);

    let o = run(&h, &["--yes", "trash", "empty"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.is_empty(), "{}", o.stdout);
    let s = h.unlock();
    assert!(s.trash().unwrap().is_empty());
    assert_eq!(s.overview().unwrap().local_seq, seq + 1, "one purge commit");
    assert!(s.find_id(&item.id_hex(), true).unwrap().is_empty());
    drop(s);

    // After completion the copy is an ordinary snapshot, and no `recover-`
    // file is left behind (0007 §3.2).
    let o = run(&h, &["--json", "snapshot", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("\"kind\":\"ordinary\""), "{}", o.stdout);
    assert!(!o.stdout.contains("\"kind\":\"recovery\""), "{}", o.stdout);
    let names: Vec<String> = std::fs::read_dir(h.snapshots())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(
        !names.iter().any(|n| n.starts_with("recover-")),
        "{names:?}"
    );
}

#[test]
fn snapshot_disk_growth_a_snapshot_failure_aborts_the_destructive_operation() {
    // 0012 §1 row "Snapshot disk growth": the mandatory recovery copy cannot
    // be written, so the deletion is aborted with nothing purged.
    let h = Home::new();
    let s = h.create();
    trashed_entry(&s);
    let seq = s.overview().unwrap().local_seq;
    drop(s);

    // (1) An unsafe private directory is refused before anything is deleted;
    // the mode check does not depend on the process's privileges.
    let dir = h.snapshots();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
    let o = run(&h, &["--yes", "trash", "empty"]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert!(
        o.stderr.contains("no usable private snapshot directory"),
        "{}",
        o.stderr
    );
    assert!(o.stdout.is_empty());

    // (2) A directory that cannot be written is the same abort through the
    // I/O path. A process with permission-override privileges (uid 0 in a
    // user namespace, e.g. `unshare -rn`) cannot produce that failure; the
    // store's writer covers the disk-full error path separately.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let denied = std::fs::write(dir.join("probe"), b"").is_err();
    let _ = std::fs::remove_file(dir.join("probe"));
    if denied {
        let o = run(&h, &["--yes", "trash", "empty"]);
        assert_eq!(o.code, 1, "{}", o.stderr);
        assert!(o.stderr.contains("input/output"), "{}", o.stderr);
    } else {
        eprintln!(
            "note: permission-override privileges; the read-only-directory arm is covered by \
             the unsafe-directory abort above"
        );
    }
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

    // Nothing was purged and the vault did not change.
    let s = h.unlock();
    assert_eq!(s.trash().unwrap().len(), 1);
    assert_eq!(s.overview().unwrap().local_seq, seq);
}
