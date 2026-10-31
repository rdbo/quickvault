// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real archive conflicts, safe inspection, complete selection and slot proof.
#![cfg(any(target_os = "linux", target_os = "android"))]
// Fixture assertions intentionally fail loudly; all values are test canaries.
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;
use common::{Home, Interactive, Output, PASSWORD, arg, piped, pw};
use qv_core::{ConflictDetails, FieldKind, FieldValue, RecordKind, Session};
const REMOTE: &str = "a separate remote selected-slot password";
fn run(h: &Home, extra: &[&str]) -> Output {
    let v = arg(&h.vault());
    let mut args = vec!["--password-stdin", "-v", &v];
    args.extend_from_slice(extra);
    piped(h.qvault(args), format!("{PASSWORD}\n").as_bytes())
}
fn edit(s: &Session, e: qv_core::EntryHandle, title: &str, password: &str) {
    let mut d = s.edit_entry(e).unwrap();
    d.entry_mut().title = qv_core::Text::new(title).unwrap();
    let field = d
        .entry_mut()
        .fields
        .iter_mut()
        .find(|f| f.name.expose() == "password")
        .unwrap();
    field.value = FieldValue::text(password).unwrap();
    s.save_entry(d).unwrap();
    let mut g = s.edit_group(s.root().unwrap()).unwrap();
    g.group_mut().name = qv_core::Text::new(title).unwrap();
    s.save_group(g).unwrap();
    let mut m = s.edit_settings().unwrap();
    m.meta_mut().name = qv_core::Text::new(title).unwrap();
    s.save_settings(m).unwrap();
}
fn entry(s: &Session) -> qv_core::EntryHandle {
    match s.search("initial").unwrap().remove(0) {
        qv_core::SearchHit::Entry(e) => e.handle,
        _ => panic!(),
    }
}

#[test]
fn conflicts_preflight_rejects_invalid_or_unframed_secret_requests_before_unlock() {
    let h = Home::new();
    for a in [
        vec!["conflicts", "--reveal"],
        vec!["conflicts", "@bad"],
        vec!["resolve", "@123456", "--version", "no"],
        vec!["--json", "resolve", "@123456", "--version", "123456"],
    ] {
        let o = run(&h, &a);
        assert_eq!(o.code, 2, "{}", o.stderr);
        assert!(o.stdout.is_empty());
    }
}

// 0012 §1: Mixed credentials
// 0012 §1: CLI argument leakage
#[test]
fn conflicts_cli_all_kinds_masking_selection_and_selected_slot_password_proof() {
    let h = Home::new();
    let s = h.create();
    let mut d = s.new_entry(s.root().unwrap(), "login", "initial").unwrap();
    d.add_field(
        "password",
        FieldKind::Secret,
        FieldValue::text("initial-password-canary").unwrap(),
    )
    .unwrap();
    let e = s.save_entry(d).unwrap();
    let eid = e.id_hex();
    let a = s
        .add_attachment(
            e,
            "canary.bin",
            "application/test",
            &mut &[1, 2, 3][..],
            None,
        )
        .unwrap();
    let aid = a.id_hex();
    s.lock();
    let listing = run(&h, &["snapshot", "ls"]);
    assert_eq!(listing.code, 0, "{}", listing.stderr);
    let snapshot = &listing.stdout.lines().next().unwrap()[..32];
    let branch = h.vaults().join("branch.qvault");
    let restored = run(&h, &["snapshot", "restore", snapshot, &arg(&branch)]);
    assert_eq!(restored.code, 0, "{}", restored.stderr);
    let local = h.unlock();
    let remote = {
        let _s = common::serial();
        h.core().unlock(&branch, &pw(PASSWORD), None).unwrap()
    };
    let le = entry(&local);
    let re = entry(&remote);
    local
        .remove_attachment(local.attachments(le).unwrap()[0].handle)
        .unwrap();
    let rh = remote
        .conflict_versions(remote.conflict_matches(&aid).unwrap()[0])
        .unwrap()
        .remove(0);
    remote.resolve_version(&rh, None, None).unwrap();
    edit(&local, le, "local title", "local-password-canary");
    edit(&remote, re, "remote title", "remote-password-canary");
    {
        let _s = common::serial();
        local.change_password(&pw(PASSWORD), None).unwrap();
        remote.change_password(&pw(REMOTE), None).unwrap();
    }
    let dir = h.root.join("exports");
    let file = remote.export_archive(&dir, false, None).unwrap();
    let file = dir.join(format!("{}.qvsnap", file.archive_id));
    local.lock();
    let merged = run(&h, &["merge", &arg(&file)]);
    assert_eq!(merged.code, 0, "{}", merged.stderr);
    assert!(merged.stdout.contains("conflicts: 5"));
    let rows = run(&h, &["--json", "conflicts"]);
    assert_eq!(rows.code, 0, "{}", rows.stderr);
    for kind in [
        "entry",
        "group",
        "vault_meta",
        "attachment",
        "password_keyslot",
    ] {
        assert!(
            rows.stdout.contains(&format!("\"kind\":\"{kind}\"")),
            "{}",
            rows.stdout
        );
    }
    let detail = run(&h, &["--json", "conflicts", &format!("@{eid}")]);
    assert_eq!(detail.code, 0, "{}", detail.stderr);
    assert_eq!(detail.stdout.matches("\"version_id\"").count(), 2);
    assert!(detail.stdout.contains("\"protected\":true,\"value\":null"));
    assert!(!detail.stdout.contains("local-password-canary"));
    assert!(!detail.stdout.contains("remote-password-canary"));
    let detail = run(&h, &["--json", "conflicts", &format!("@{eid}"), "--reveal"]);
    assert_eq!(detail.code, 0, "{}", detail.stderr);
    assert!(detail.stdout.contains("local-password-canary"));
    assert!(detail.stdout.contains("remote-password-canary"));
    let local = h.unlock();
    let rows = local.conflict_records().unwrap();
    let mut selected = Vec::new();
    let mut slot = None;
    for row in rows {
        let id = row.handle.id_hex();
        let r = remote.conflict_matches(&id).unwrap()[0];
        let v = remote.conflict_versions(r).unwrap().remove(0);
        if row.kind == RecordKind::PasswordKeyslot {
            slot = Some((id, v.version_hex()));
        } else {
            selected.push((row.kind, id, v.version_hex()));
        }
    }
    local.lock();
    remote.lock();
    for (_, id, version) in &selected {
        let inspect = run(&h, &["--json", "conflicts", &format!("@{id}"), "--reveal"]);
        assert_eq!(inspect.code, 0, "{}", inspect.stderr);
        let human = run(&h, &["conflicts", &format!("@{id}")]);
        assert_eq!(human.code, 0, "{}", human.stderr);
        assert!(human.stdout.contains("Version:"));
        let o = run(
            &h,
            &[
                "--yes",
                "resolve",
                &format!("@{id}"),
                "--version",
                &format!("@{version}"),
            ],
        );
        assert_eq!(o.code, 0, "{}", o.stderr);
        assert!(o.stdout.contains("local resolution: committed"));
    }
    let (slot, version) = slot.unwrap();
    let target = format!("@{slot}");
    let inspected = run(&h, &["--json", "conflicts", &target, "--reveal"]);
    assert_eq!(inspected.code, 0, "{}", inspected.stderr);
    for key in ["kdf_salt", "kek_commit", "nonce", "wrapped_vk"] {
        assert!(!inspected.stdout.contains(key));
    }
    assert!(inspected.stdout.contains("slot_id"));
    let missing_tty = run(&h, &["--yes", "resolve", &target, "--version", &version]);
    assert_eq!(missing_tty.code, 2, "{}", missing_tty.stderr);
    for (password, expected) in [("wrong selected password", 3), (REMOTE, 0)] {
        let mut p = Interactive::spawn(h.qvault([
            "-v",
            &arg(&h.vault()),
            "--yes",
            "resolve",
            &target,
            "--version",
            &version,
        ]));
        p.expect("Master password:");
        p.line(PASSWORD);
        p.expect("Selected version's master password:");
        p.line(password);
        let (code, output) = p.finish();
        assert_eq!(code, expected, "{output}");
        assert!(!output.contains(password));
        if expected == 3 {
            assert!(!output.contains("local resolution: committed"));
        } else {
            assert!(output.contains("conflicts: 0"));
        }
    }
    let _s = common::serial();
    let s = h.core().unlock(&h.vault(), &pw(REMOTE), None).unwrap();
    assert!(s.conflict_records().unwrap().is_empty());
    let e = match s
        .search("remote title")
        .unwrap()
        .into_iter()
        .find_map(|h| match h {
            qv_core::SearchHit::Entry(e) => Some(e.handle),
            _ => None,
        }) {
        Some(e) => e,
        None => panic!(),
    };
    let h = s
        .conflict_versions(s.conflict_matches(&e.id_hex()).unwrap()[0])
        .unwrap()
        .remove(0);
    let ConflictDetails::Entry { detail, .. } = s.conflict_version(&h).unwrap().details else {
        panic!()
    };
    let f = detail
        .fields
        .iter()
        .find(|f| f.name.expose() == "password")
        .unwrap();
    assert_eq!(
        s.reveal(f.handle).unwrap().expose_secret(),
        b"remote-password-canary"
    );
    assert!(s.verify(None).unwrap().ok());
}
