// SPDX-License-Identifier: AGPL-3.0-or-later

//! Trash addresses, output escaping, confirmation and tombstone persistence.
#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;
use common::{Home, Interactive, Output, PASSWORD, arg, piped};
use qv_core::{ItemHandle, Session};
fn run(h: &Home, args: &[&str]) -> Output {
    let vault = arg(&h.vault());
    let mut a = vec!["--password-stdin", "-v", &vault];
    a.extend_from_slice(args);
    piped(h.qvault(a), format!("{PASSWORD}\n").as_bytes())
}
fn entry(s: &Session, title: &str) -> ItemHandle {
    ItemHandle::Entry(
        s.save_entry(s.new_entry(s.root().unwrap(), "login", title).unwrap())
            .unwrap(),
    )
}
#[test]
fn trash_scoping_ambiguity_escaping_restore_and_permanent_deletion() {
    let h = Home::new();
    let s = h.create();
    let first = entry(&s, "Same");
    let second = entry(&s, "Same");
    let live = entry(&s, "Live");
    let hostile = entry(&s, "\x1b]52;c;data\x07");
    for item in [first, second, hostile] {
        s.delete(item, false).unwrap();
    }
    let seq = s.overview().unwrap().local_seq;
    drop(s);
    let o = run(&h, &["trash", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.contains("\\x1b]52;c;data\\x07"));
    assert!(!o.stdout.contains('\x1b'));
    assert!(!o.stdout.contains('\x07'));
    let o = run(&h, &["--json", "trash", "ls"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(o.stdout.starts_with("{\"items\":[{"));
    assert!(o.stdout.contains("\"kind\":\"entry\""));
    assert!(o.stdout.contains("\"deleted_at\":\""));
    assert!(o.stdout.contains("\\u001b"));
    assert!(!o.stdout.contains(&live.id_hex()));
    let o = run(&h, &["trash", "restore", "Same"]);
    assert_eq!(o.code, 5);
    assert!(o.stderr.contains(&first.id_hex()) && o.stderr.contains(&second.id_hex()));
    assert_eq!(
        run(&h, &["trash", "restore", &format!("@{}", live.id_hex())]).code,
        4
    );
    assert_eq!(run(&h, &["trash", "restore", "@bad"]).code, 2);
    assert_eq!(run(&h, &["trash", "empty"]).code, 2);
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
    drop(s);
    let vault = arg(&h.vault());
    let mut p = Interactive::spawn(h.qvault(["-v", &vault, "trash", "empty"]));
    p.expect("Master password: ");
    p.line(PASSWORD);
    p.expect("[y/N] ");
    p.line("n");
    assert_eq!(p.finish().0, 1);
    let s = h.unlock();
    assert_eq!(s.overview().unwrap().local_seq, seq);
    drop(s);
    assert_eq!(
        run(&h, &["trash", "restore", &format!("@{}", first.id_hex())]).code,
        0
    );
    assert_eq!(run(&h, &["--yes", "trash", "empty"]).code, 0);
    let s = h.unlock();
    assert!(s.trash().unwrap().is_empty());
    assert_eq!(s.list(s.root().unwrap()).unwrap().entries.len(), 2);
    // Permanent tombstones cannot be selected or restored as trash.
    assert!(s.find_id(&second.id_hex(), true).unwrap().is_empty());
    drop(s);
    assert_eq!(
        run(&h, &["trash", "restore", &format!("@{}", second.id_hex())]).code,
        4
    );
}
#[test]
fn group_restore_recovers_deleted_subtree() {
    let h = Home::new();
    let s = h.create();
    let root = s.root().unwrap();
    let g = s.save_group(s.new_group(root, "Work").unwrap()).unwrap();
    let e = s
        .save_entry(s.new_entry(g, "login", "Mail").unwrap())
        .unwrap();
    s.delete(ItemHandle::Group(g), true).unwrap();
    drop(s);
    assert_eq!(
        run(&h, &["trash", "restore", &format!("@{}", g.id_hex())]).code,
        0
    );
    let s = h.unlock();
    let groups = s.list(s.root().unwrap()).unwrap().groups;
    assert_eq!(groups.len(), 1);
    assert_eq!(
        s.list(groups[0].handle).unwrap().entries[0].handle.id_hex(),
        e.id_hex()
    );
    assert!(s.trash().unwrap().is_empty());
}
