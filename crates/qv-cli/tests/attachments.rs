// SPDX-License-Identifier: AGPL-3.0-or-later

//! Production attachment commands, file refusal and explicit export behavior.
// Shared integration fixture helpers intentionally unwrap trusted test setup.
#![allow(clippy::unwrap_used, clippy::panic)]
mod common;
use common::{Home, PASSWORD, arg, piped};
use std::{
    os::unix::fs::{PermissionsExt, symlink},
    process::Command,
};
fn run(h: &Home, args: &[&str]) -> common::Output {
    let vault = arg(&h.vault());
    let mut all = vec!["--password-stdin", "--yes", "-v", &vault];
    all.extend_from_slice(args);
    let mut c: Command = h.qvault(all);
    c.current_dir(h.vaults());
    piped(c, format!("{PASSWORD}\n").as_bytes())
}
#[test]
fn attachment_cli_round_trip_and_safe_paths() {
    let h = Home::new();
    let s = h.create();
    s.save_entry(s.new_entry(s.root().unwrap(), "login", "Files").unwrap())
        .unwrap();
    drop(s);
    let bytes: Vec<u8> = (0..10 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    std::fs::write(h.vaults().join("input"), &bytes).unwrap();
    let out = run(
        &h,
        &[
            "attach",
            "add",
            "Files",
            "input",
            "--name",
            "../../evil\nname",
        ],
    );
    assert_eq!(out.code, 0, "{}", out.stderr);
    let id = out.stdout.trim();
    assert!(id.starts_with('@'));
    let ls = run(&h, &["--json", "attach", "ls", "Files"]);
    assert_eq!(ls.code, 0, "{}", ls.stderr);
    assert!(ls.stdout.contains("10485760"));
    assert!(ls.stdout.contains("../../evil\\nname"));
    let out = run(&h, &["attach", "save", "Files", id, "output"]);
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert!(out.stdout.is_empty());
    assert_eq!(std::fs::read(h.vaults().join("output")).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(h.vaults().join("output"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let out = run(&h, &["attach", "save", "Files", id, "output"]);
    assert_eq!(out.code, 1);
    assert_eq!(std::fs::read(h.vaults().join("output")).unwrap(), bytes);
    symlink("output", h.vaults().join("link")).unwrap();
    for path in ["link", "../outside", "/tmp/unsafe-export", "new/."] {
        assert_eq!(run(&h, &["attach", "save", "Files", id, path]).code, 1);
    }
    assert_eq!(run(&h, &["attach", "add", "Files", "link"]).code, 1);
    assert_eq!(run(&h, &["attach", "rm", "Files", id]).code, 0);
    assert_eq!(run(&h, &["attach", "save", "Files", id, "absent"]).code, 4);
    assert!(!h.vaults().join("absent").exists());
    assert_eq!(
        run(&h, &["--json", "attach", "ls", "Files"]).stdout.trim(),
        "[]"
    );
}
#[test]
fn attachment_cli_preflight_ambiguity_and_input_limits() {
    let h = Home::new();
    for args in [
        vec!["--json", "attach", "add", "Files", "missing"],
        vec!["--json", "attach", "save", "Files", "name", "out"],
        vec!["--json", "attach", "rm", "Files", "name"],
        vec!["attach", "save", "Files", "name", "out"],
        vec!["attach", "rm", "Files", "name"],
    ] {
        let mut a = vec!["--password-stdin"];
        a.extend(args);
        let out = piped(h.qvault(a), b"");
        assert_eq!(out.code, 2);
        assert!(!out.stderr.contains("Master password"));
    }
    let s = h.create();
    s.save_entry(s.new_entry(s.root().unwrap(), "login", "Files").unwrap())
        .unwrap();
    drop(s);
    std::fs::write(h.vaults().join("empty"), b"").unwrap();
    for _ in 0..2 {
        assert_eq!(run(&h, &["attach", "add", "Files", "empty"]).code, 0);
    }
    assert_eq!(
        run(&h, &["attach", "save", "Files", "empty", "out"]).code,
        5
    );
    let file = std::fs::File::create(h.vaults().join("large")).unwrap();
    file.set_len(10 * 1024 * 1024 + 1).unwrap();
    assert_eq!(run(&h, &["attach", "add", "Files", "large"]).code, 9);
    rustix::fs::mknodat(
        rustix::fs::CWD,
        h.vaults().join("fifo"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        0,
    )
    .unwrap();
    assert_eq!(run(&h, &["attach", "add", "Files", "fifo"]).code, 1);
}
