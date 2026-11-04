// SPDX-License-Identifier: AGPL-3.0-or-later

//! `qvault lan` end to end (spec 0011 *LAN command contracts*, 0013; plan
//! 0038 step 8). The other device runs in the test process through
//! qv-core. Rounds between CLI processes use this host's first non-loopback
//! address, because the CLI never allows loopback endpoints (0013 §1.4); a
//! host without one fails these tests with an explicit message.
#![cfg(any(target_os = "linux", target_os = "android"))]
#![allow(clippy::unwrap_used, clippy::panic)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Stdio;
use std::time::Duration;

use common::{Home, Interactive, Output, PASSWORD, arg, piped, pw, serial};
use qv_core::{
    ApproverUi, JoinCode, JoinMode, JoinOptions, JoinerUi, LanTimeouts, ListenScope,
    MasterPassword, PairingOptions, Sas, Session,
};

fn lan_addr() -> IpAddr {
    qv_core::local_addresses()
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            panic!("the qvault lan tests need a non-loopback local address on this host")
        })
}

fn run(h: &Home, extra: &[&str]) -> Output {
    let vault = arg(&h.vault());
    let mut args = vec!["--password-stdin", "-v", &vault];
    args.extend_from_slice(extra);
    piped(h.qvault(args), format!("{PASSWORD}\n").as_bytes())
}

struct Yes(Option<String>);
impl ApproverUi for Yes {
    fn confirm(&mut self, sas: &str, _: JoinMode, _: &str) -> bool {
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

/// A's vault (created) and B as a new device paired from it, in process.
fn paired(a_home: &Home, b_home: &Home) -> (Session, Session) {
    let a = a_home.create();
    let w = a
        .open_pairing_window(PairingOptions {
            scope: ListenScope::LoopbackForTests,
            limit: Duration::from_secs(60),
            timeouts: fast(),
            ..PairingOptions::new("laptop")
        })
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
                JoinOptions {
                    extra_endpoints: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)],
                    allow_loopback: true,
                    timeouts: fast(),
                    ..JoinOptions::new("desktop")
                },
                &mut Joiner(None),
                None,
            )
            .unwrap();
        assert!(h.join().unwrap().peer_confirmed);
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
fn lan_cli_receive_and_sync_between_two_processes() {
    let (a_home, b_home) = (Home::new(), Home::new());
    let (a, b) = paired(&a_home, &b_home);
    add_entry(&a, "made on a");
    a.lock();
    b.lock();
    let ip = lan_addr();
    // B receives (no TTY needed), A syncs.
    let vault_b = arg(&b_home.vault());
    let mut receiver = b_home
        .qvault([
            "--password-stdin",
            "-v",
            &vault_b,
            "lan",
            "receive",
            "--minutes",
            "1",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let _s = serial();
        let mut i = receiver.stdin.take().unwrap();
        i.write_all(format!("{PASSWORD}\n").as_bytes()).unwrap();
    }
    let mut lines = BufReader::new(receiver.stdout.take().unwrap()).lines();
    assert_eq!(lines.next().unwrap().unwrap(), "endpoints:");
    let mut endpoint = None;
    for line in lines.by_ref() {
        let line = line.unwrap();
        if line.starts_with("waiting up to") {
            break;
        }
        let e: SocketAddr = line.trim().parse().unwrap();
        if e.ip() == ip {
            endpoint = Some(e);
        }
    }
    let endpoint = endpoint.expect("the receive window lists this host's address");
    let sent = run(
        &a_home,
        &["lan", "sync", "--endpoint", &endpoint.to_string()],
    );
    assert_eq!(sent.code, 0, "{}", sent.stderr);
    assert!(
        sent.stdout.contains("local acceptance: unchanged"),
        "{}",
        sent.stdout
    );
    assert!(
        sent.stdout.contains("peer receipt: confirmed"),
        "{}",
        sent.stdout
    );
    let rest: Vec<String> = lines.map(|l| l.unwrap()).collect();
    let status = receiver.wait().unwrap();
    assert_eq!(status.code(), Some(0));
    assert!(
        rest.iter().any(|l| l == "local acceptance: committed"),
        "{rest:?}"
    );
    assert!(rest.iter().any(|l| l == "conflicts: 0"), "{rest:?}");
    let b = b_home.unlock();
    assert!(titles(&b).contains(&"made on a".to_owned()));
}

#[test]
fn lan_cli_usage_link_selection_and_exit_codes() {
    let (a_home, b_home) = (Home::new(), Home::new());
    // Before unlock: usage errors (2).
    for extra in [
        vec!["lan", "sync"],
        vec!["lan", "sync", "--endpoint", "localhost:80"],
        vec!["lan", "sync", "--endpoint", "[fe80::1%2]:80"],
        vec!["--json", "lan", "sync", "--endpoint", "10.0.0.1:1"],
        vec!["lan", "pair", "--label", "x"],
        vec!["lan", "join", "--endpoint", "10.0.0.1:1", "--label", "x"],
        vec!["lan", "receive", "--minutes", "16"],
        vec!["lan", "sync", "--endpoint", "10.0.0.1:1", "--link", "xyz"],
    ] {
        let o = run(&a_home, &extra);
        assert_eq!(o.code, 2, "{extra:?}: {}", o.stderr);
        assert!(o.stdout.is_empty(), "{extra:?}");
    }
    let (a, b) = paired(&a_home, &b_home);
    a.lock();
    let o = run(&a_home, &["--json", "lan", "links"]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert!(
        o.stdout.starts_with("{\"links\":[{\"id\":\""),
        "{}",
        o.stdout
    );
    assert!(o.stdout.contains("\"label\":\"laptop\""), "{}", o.stdout);
    // The only link, but no device answers (loopback is never allowed): 10.
    let o = run(&a_home, &["lan", "sync", "--endpoint", "127.0.0.1:9"]);
    assert_eq!(o.code, 10, "{}", o.stderr);
    // Two links (B pairs again in link mode): ambiguous without --link (5).
    let a = a_home.unlock();
    let w = a
        .open_pairing_window(PairingOptions {
            scope: ListenScope::LoopbackForTests,
            limit: Duration::from_secs(60),
            timeouts: fast(),
            ..PairingOptions::new("again")
        })
        .unwrap();
    let c = w.code(&[]).unwrap();
    let manual = String::from_utf8(c.manual.expose_secret().to_vec()).unwrap();
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut Yes(None), None).unwrap());
        b.join_link(
            JoinCode::from_manual(&manual).unwrap(),
            JoinOptions {
                extra_endpoints: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), c.port)],
                allow_loopback: true,
                timeouts: fast(),
                ..JoinOptions::new("desktop again")
            },
            &mut Joiner(None),
            None,
        )
        .unwrap();
        h.join().unwrap();
    });
    let ids: Vec<String> = a
        .lan_links()
        .unwrap()
        .iter()
        .map(|l| l.handle.id_hex())
        .collect();
    a.lock();
    b.lock();
    assert_eq!(ids.len(), 2);
    let o = run(&a_home, &["lan", "sync", "--endpoint", "127.0.0.1:9"]);
    assert_eq!(o.code, 5, "{}", o.stderr);
    assert!(o.stderr.contains(&ids[0]) && o.stderr.contains(&ids[1]));
    // Unlink one (confirmed by --yes); the other remains.
    let o = run(&a_home, &["--yes", "lan", "unlink", &ids[0][..8]]);
    assert_eq!(o.code, 0, "{}", o.stderr);
    assert_eq!(o.stdout, format!("removed: {}\n", ids[0]));
    assert!(o.stderr.contains("not notified"));
    let o = run(&a_home, &["lan", "links"]);
    assert_eq!(o.code, 0);
    assert!(
        o.stdout.starts_with(&ids[1]) && !o.stdout.contains(&ids[0]),
        "{}",
        o.stdout
    );
    // A vault without links: 4.
    let c_home = Home::new();
    drop(c_home.create());
    let o = run(&c_home, &["lan", "sync", "--endpoint", "10.0.0.1:1"]);
    assert_eq!(o.code, 4, "{}", o.stderr);
    let o = run(&c_home, &["lan", "unlink", "abcdef"]);
    assert_eq!(o.code, 2, "--password-stdin without --yes: {}", o.stderr);
}

#[test]
fn lan_cli_pair_shows_the_code_only_on_the_alternate_screen() {
    let (a_home, b_home) = (Home::new(), Home::new());
    let (a, b) = paired(&a_home, &b_home);
    a.lock();
    let ip = lan_addr();
    let mut p = Interactive::spawn(a_home.qvault([
        "-v",
        &arg(&a_home.vault()),
        "lan",
        "pair",
        "--label",
        "tablet",
        "--minutes",
        "1",
    ]));
    p.expect("Master password:");
    p.line(PASSWORD);
    let at = p.expect("Pairing code (type it on the other device):");
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
    let mut joiner = Joiner(None);
    let joined = std::thread::scope(|s| {
        let h = s.spawn(|| {
            b.join_link(
                JoinCode::from_manual(&code).unwrap(),
                JoinOptions {
                    extra_endpoints: vec![SocketAddr::new(ip, port)],
                    timeouts: fast(),
                    ..JoinOptions::new("desktop")
                },
                &mut joiner,
                None,
            )
        });
        let asked = p.expect("Do both devices show ");
        p.line("y");
        let r = h.join().unwrap().unwrap();
        (asked, r)
    });
    let (asked, report) = joined;
    let digits = String::from_utf8(joiner.0.unwrap().to_vec()).unwrap();
    let sas = format!("{} {}", &digits[..3], &digits[3..]);
    assert!(String::from_utf8_lossy(&p.seen[asked..]).starts_with(&sas));
    let (code_exit, all) = p.finish();
    assert_eq!(code_exit, 0, "{all}");
    assert!(
        all.contains(&format!("paired: {}", report.link.id_hex())),
        "{all}"
    );
    assert!(all.contains("local acceptance: unchanged"), "{all}");
    // The code was shown on the alternate screen, which is left and
    // cleared before the result lines.
    let leave = all.rfind("\u{1b}[?1049l").unwrap();
    assert!(all.find(&code).unwrap() < leave);
    assert!(!all[leave..].contains(&code));
}

#[test]
fn lan_cli_join_new_device_prompts_for_code_vault_and_password() {
    let (a_home, b_home) = (Home::new(), Home::new());
    let a = a_home.create();
    add_entry(&a, "only on a");
    let ip = lan_addr();
    let w = a
        .open_pairing_window(PairingOptions {
            limit: Duration::from_secs(60),
            timeouts: fast(),
            ..PairingOptions::new("phone")
        })
        .unwrap();
    let c = w.code(&[ip]).unwrap();
    let manual = String::from_utf8(c.manual.expose_secret().to_vec()).unwrap();
    let dest = b_home.vault();
    let endpoint = SocketAddr::new(ip, c.port).to_string();
    // An existing destination is refused before pairing.
    std::fs::write(&dest, b"x").unwrap();
    let p = Interactive::spawn(b_home.qvault([
        "lan",
        "join",
        "--new",
        &arg(&dest),
        "--endpoint",
        &endpoint,
        "--label",
        "laptop",
    ]));
    let (code, out) = p.finish();
    assert_eq!(code, 2, "{out}");
    std::fs::remove_file(&dest).unwrap();
    let mut yes = Yes(None);
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut yes, None).unwrap());
        let mut p = Interactive::spawn(b_home.qvault([
            "lan",
            "join",
            "--new",
            &arg(&dest),
            "--endpoint",
            &endpoint,
            "--label",
            "laptop",
        ]));
        p.expect("Pairing code: ");
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
        assert!(out.contains("paired: "), "{out}");
        // The typed code is not echoed.
        assert!(!out.to_lowercase().contains(&manual.to_lowercase()));
        assert!(h.join().unwrap().peer_confirmed);
    });
    let b = b_home.unlock();
    assert_eq!(titles(&b), ["only on a"]);
    assert_eq!(b.lan_links().unwrap().len(), 1);
}
