// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qv lan open|sync|join` end to end (spec 0011 *LAN command contracts*,
//! 0013; plans 0038 step 8, 0042 step 7). The other device runs in the test
//! process through qv-core. Sessions with a CLI process use this host's
//! first non-loopback address, because the CLI never allows loopback
//! endpoints (0013 §1.4); a host without one fails these tests with an
//! explicit message.
#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use common::{Home, Interactive, Output, PASSWORD, arg, piped, pw, serial};
use qv_core::{
    ApproverUi, JoinCode, JoinerUi, LanTimeouts, ListenScope, MasterPassword, Sas, Served, Session,
    SyncOptions, SyncWindowOptions,
};

fn lan_addr() -> IpAddr {
    qv_core::local_addresses()
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            panic!("the qv lan tests need a non-loopback local address on this host")
        })
}

fn run(h: &Home, extra: &[&str]) -> Output {
    let vault = arg(&h.vault());
    let mut args = vec!["--password-stdin", "-v", &vault];
    args.extend_from_slice(extra);
    piped(h.qv(args), format!("{PASSWORD}\n").as_bytes())
}

struct Yes(Option<String>);
impl ApproverUi for Yes {
    fn confirm(&mut self, sas: &str, _: &str) -> bool {
        self.0 = Some(sas.to_owned());
        true
    }
}

struct Joiner(Option<[u8; 6]>);
impl JoinerUi for Joiner {
    fn show_code(&mut self, sas: &Sas) -> bool {
        self.0 = Some(sas.digits());
        true
    }
    fn confirm_vault(&mut self, _: &[u8], _: &Sas) -> bool {
        true
    }
    fn master_password(&mut self) -> Option<MasterPassword> {
        Some(pw(PASSWORD))
    }
}

fn fast() -> LanTimeouts {
    LanTimeouts {
        message: Duration::from_secs(5),
        idle: Duration::from_secs(20),
        confirm: Duration::from_secs(60),
        connect: Duration::from_secs(5),
        probe: Duration::from_secs(1),
    }
}

fn window_options(scope: ListenScope) -> SyncWindowOptions {
    SyncWindowOptions {
        scope,
        limit: Duration::from_secs(60),
        timeouts: fast(),
        ..SyncWindowOptions::new()
    }
}

/// A's vault (created) and B as a new device joined from it, in process.
fn joined(a_home: &Home, b_home: &Home) -> (Session, Session) {
    let a = a_home.create();
    let w = a
        .open_sync_window(window_options(ListenScope::LoopbackForTests))
        .unwrap();
    let c = w.code(&[]).unwrap();
    let manual = String::from_utf8(c.manual.expose_secret().to_vec()).unwrap();
    let port = c.port;
    let b = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut Yes(None), None).unwrap());
        let _s = serial();
        let b = b_home
            .core()
            .join_new_device(
                JoinCode::from_manual(&manual).unwrap(),
                &b_home.vault(),
                SyncOptions {
                    extra_endpoints: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)],
                    allow_loopback: true,
                    timeouts: fast(),
                },
                &mut Joiner(None),
                None,
            )
            .unwrap();
        assert!(matches!(
            h.join().unwrap(),
            Served::Joined {
                peer_confirmed: true,
                ..
            }
        ));
        b
    });
    (a, b)
}

fn add_entry(s: &Session, title: &str) {
    let d = s.new_entry(s.root().unwrap(), "login", title).unwrap();
    s.save_entry(d).unwrap();
}

fn titles(s: &Session) -> Vec<String> {
    s.list(s.root().unwrap())
        .unwrap()
        .entries
        .iter()
        .map(|e| e.title.expose().to_owned())
        .collect()
}

// 0012 §1: Account-dependent LAN sync
#[test]
fn lan_cli_open_serves_one_sync_and_shows_the_code_only_on_the_alternate_screen() {
    let (a_home, b_home) = (Home::new(), Home::new());
    let (a, b) = joined(&a_home, &b_home);
    add_entry(&b, "made on b");
    a.lock();
    let ip = lan_addr();
    let mut p = Interactive::spawn(a_home.qv([
        "-v",
        &arg(&a_home.vault()),
        "lan",
        "open",
        "--minutes",
        "1",
    ]));
    p.expect("Master password:");
    p.line(PASSWORD);
    let at = p.expect("Code (type it on the other device; it works once):");
    let end = p.expect_from(at, "This device's address:");
    let shown = String::from_utf8_lossy(&p.seen[at..end]).into_owned();
    let code = shown.split_whitespace().next().unwrap().to_owned();
    assert_eq!(code.len(), 26 + 5);
    let addr_line = p.expect_from(end, &format!("{ip}:"));
    let tail = String::from_utf8_lossy(&p.seen[addr_line..]).into_owned();
    let port: u16 = tail
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap();
    let sent = b
        .sync_with_code(
            JoinCode::from_manual(&code).unwrap(),
            SyncOptions {
                extra_endpoints: vec![SocketAddr::new(ip, port)],
                timeouts: fast(),
                ..SyncOptions::default()
            },
            None,
        )
        .unwrap();
    assert_eq!(sent.local, qv_core::LocalAcceptance::Unchanged);
    let (code_exit, all) = p.finish();
    assert_eq!(code_exit, 0, "{all}");
    // A sync asks nothing on the offering device and prints the sync lines.
    assert!(!all.contains("Do both devices show"), "{all}");
    assert!(all.contains("local acceptance: committed"), "{all}");
    assert!(all.contains("conflicts: 0"), "{all}");
    assert!(all.contains("peer receipt: confirmed"), "{all}");
    // The code was shown on the alternate screen, which is left and
    // cleared before the result lines.
    let leave = all.rfind("\u{1b}[?1049l").unwrap();
    assert!(all.find(&code).unwrap() < leave);
    assert!(!all[leave..].contains(&code));
    let a = a_home.unlock();
    assert!(titles(&a).contains(&"made on b".to_owned()));
}

// 0012 §1: Account-dependent LAN sync
#[test]
fn lan_cli_sync_prompts_for_the_code_and_prints_the_sync_lines() {
    let (a_home, b_home) = (Home::new(), Home::new());
    let (a, b) = joined(&a_home, &b_home);
    add_entry(&a, "made on a");
    b.lock();
    let ip = lan_addr();
    let w = a
        .open_sync_window(window_options(ListenScope::AllInterfaces))
        .unwrap();
    let c = w.code(&[ip]).unwrap();
    let manual = String::from_utf8(c.manual.expose_secret().to_vec()).unwrap();
    let endpoint = SocketAddr::new(ip, c.port).to_string();
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut Yes(None), None).unwrap());
        let mut p = Interactive::spawn(b_home.qv([
            "-v",
            &arg(&b_home.vault()),
            "lan",
            "sync",
            "--endpoint",
            &endpoint,
        ]));
        p.expect("Master password:");
        p.line(PASSWORD);
        p.expect("Code: ");
        p.line(&manual.to_lowercase());
        let (code, out) = p.finish();
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("local acceptance: committed"), "{out}");
        assert!(out.contains("peer receipt: confirmed"), "{out}");
        // The typed code is not echoed.
        assert!(!out.to_lowercase().contains(&manual.to_lowercase()));
        assert!(matches!(h.join().unwrap(), Served::Synced(_)));
    });
    let b = b_home.unlock();
    assert!(titles(&b).contains(&"made on a".to_owned()));
}

#[test]
fn lan_cli_usage_and_exit_codes() {
    let (a_home, b_home) = (Home::new(), Home::new());
    // Usage errors (2): missing or invalid arguments, --json, the removed
    // link commands, and --password-stdin (every LAN command prompts).
    for extra in [
        vec!["lan", "sync"],
        vec!["lan", "sync", "--endpoint", "localhost:80"],
        vec!["lan", "sync", "--endpoint", "[fe80::1%2]:80"],
        vec!["--json", "lan", "sync", "--endpoint", "10.0.0.1:1"],
        vec!["lan", "sync", "--endpoint", "10.0.0.1:1"],
        vec!["lan", "open"],
        vec!["lan", "open", "--minutes", "11"],
        vec!["lan", "join", "--endpoint", "10.0.0.1:1"],
        vec!["lan", "pair", "--label", "x"],
        vec!["lan", "receive"],
        vec!["lan", "links"],
        vec!["lan", "unlink", "abcdef"],
    ] {
        let o = run(&a_home, &extra);
        assert_eq!(o.code, 2, "{extra:?}: {}", o.stderr);
        assert!(o.stdout.is_empty(), "{extra:?}");
    }
    let (a, _b) = joined(&a_home, &b_home);
    a.lock();
    // No device answers (loopback is never allowed): 10.
    let mut p = Interactive::spawn(a_home.qv([
        "-v",
        &arg(&a_home.vault()),
        "lan",
        "sync",
        "--endpoint",
        "127.0.0.1:9",
    ]));
    p.expect("Master password:");
    p.line(PASSWORD);
    p.expect("Code: ");
    p.line("AAAAA-AAAAA-AAAAA-AAAAA-AAAAA-A");
    let (code, out) = p.finish();
    assert_eq!(code, 10, "{out}");
}

#[test]
fn lan_cli_join_new_device_prompts_for_code_vault_and_password() {
    let (a_home, b_home) = (Home::new(), Home::new());
    let a = a_home.create();
    add_entry(&a, "only on a");
    let ip = lan_addr();
    let w = a
        .open_sync_window(window_options(ListenScope::AllInterfaces))
        .unwrap();
    let c = w.code(&[ip]).unwrap();
    let manual = String::from_utf8(c.manual.expose_secret().to_vec()).unwrap();
    let dest = b_home.vault();
    let endpoint = SocketAddr::new(ip, c.port).to_string();
    // An existing destination is refused before connecting.
    std::fs::write(&dest, b"x").unwrap();
    let p = Interactive::spawn(b_home.qv([
        "lan",
        "join",
        "--new",
        &arg(&dest),
        "--endpoint",
        &endpoint,
    ]));
    let (code, out) = p.finish();
    assert_eq!(code, 2, "{out}");
    std::fs::remove_file(&dest).unwrap();
    let mut yes = Yes(None);
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut yes, None).unwrap());
        let mut p = Interactive::spawn(b_home.qv([
            "lan",
            "join",
            "--new",
            &arg(&dest),
            "--endpoint",
            &endpoint,
        ]));
        p.expect("Code: ");
        p.line(&manual.to_lowercase());
        p.expect("comparison code: ");
        p.expect("Join vault \"Test vault\"? Comparison code ");
        p.line("y");
        p.expect("Master password of the joined vault: ");
        p.line("not the password");
        p.expect("Wrong password; try again");
        p.line(PASSWORD);
        let (code, out) = p.finish();
        assert_eq!(code, 0, "{out}");
        assert!(out.contains("created: "), "{out}");
        assert!(!out.contains("paired: "), "{out}");
        // The typed code is not echoed.
        assert!(!out.to_lowercase().contains(&manual.to_lowercase()));
        assert!(matches!(
            h.join().unwrap(),
            Served::Joined {
                peer_confirmed: true,
                ..
            }
        ));
    });
    assert!(yes.0.is_some(), "the offering device compared codes");
    let b = b_home.unlock();
    assert_eq!(titles(&b), ["only on a"]);
}
