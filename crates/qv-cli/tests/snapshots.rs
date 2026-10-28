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

#[test]
fn snapshot_restore_creates_a_new_baseline_and_preserves_active_vault() {
    let h = Home::new();
    let s = h.create();
    let root = s.root().unwrap();
    s.save_entry(s.new_entry(root, "login", "Snapshot entry").unwrap())
        .unwrap();
    drop(s);
    let listed = run(&h, &["snapshot", "ls"]);
    assert_eq!(listed.code, 0, "{}", listed.stderr);
    let id = listed.stdout.lines().next().unwrap()[..32].to_owned();
    let before = std::fs::read(h.vault()).unwrap();
    let anchors: Vec<_> = std::fs::read_dir(h.anchors())
        .unwrap()
        .map(|e| {
            let p = e.unwrap().path();
            (p.clone(), std::fs::read(p).unwrap())
        })
        .collect();
    let target = h.vaults().join("restored.qvault");
    let path = arg(&target);
    let o = run(
        &h,
        &["snapshot", "restore", &format!("@{}", &id[..6]), &path],
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.is_empty());
    assert!(o.stderr.contains("new recovery baseline") && o.stderr.contains("may be old"));
    assert_eq!(std::fs::read(h.vault()).unwrap(), before);
    for (p, bytes) in anchors {
        assert_eq!(std::fs::read(p).unwrap(), bytes);
    }
    let o = piped(
        h.qvault(["--password-stdin", "-v", &path, "--json", "verify"]),
        format!("{PASSWORD}\n").as_bytes(),
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("\"local_seq\":1") && o.stdout.contains("\"anchor\":\"verified\""));
    let o = piped(
        h.qvault(["--password-stdin", "-v", &path, "search", "Snapshot entry"]),
        format!("{PASSWORD}\n").as_bytes(),
    );
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("Snapshot entry"));
    let target_before = std::fs::read(&target).unwrap();
    let o = run(&h, &["snapshot", "restore", &id, &path]);
    assert_eq!(o.code, 1, "{}", o.stderr);
    assert_eq!(std::fs::read(&target).unwrap(), target_before);
}

#[test]
fn snapshot_restore_preflight_and_addressing_errors() {
    use std::os::unix::fs::PermissionsExt;
    let h = Home::new();
    let s = h.create();
    drop(s);
    for args in [
        vec!["--json", "snapshot", "restore", "abcdef", "new.qvault"],
        vec!["snapshot", "restore", "invalid", "new.qvault"],
    ] {
        let mut a = vec!["--password-stdin"];
        a.extend(args);
        let o = piped(h.qvault(a), b"");
        assert_eq!(o.code, 2, "{}", o.stderr);
    }
    assert_eq!(run(&h, &["snapshot", "ls"]).code, 0);
    let target = arg(&h.vaults().join("new.qvault"));
    let o = run(&h, &["snapshot", "restore", &"f".repeat(32), &target]);
    assert_eq!(o.code, 4, "{}", o.stderr);
    let ids = [
        "abcdef00000000000000000000000000",
        "abcdef11111111111111111111111111",
    ];
    for id in ids {
        let path = h.snapshots().join(format!("{id}.qvsnap"));
        std::fs::write(&path, b"hostile archive").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let o = run(&h, &["snapshot", "restore", "abcdef", &target]);
    assert_eq!(o.code, 5, "{}", o.stderr);
    for id in ids {
        assert!(o.stderr.contains(id));
    }
    let o = run(&h, &["snapshot", "restore", ids[0], &target]);
    assert_eq!(o.code, 7, "{}", o.stderr);
    assert!(!h.vaults().join("new.qvault").exists());
}
