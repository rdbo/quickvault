// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN pairing through core (plan 0037 step 7; 0013 testing rows "Generation
//! transitions", "Account-dependent LAN sync" (pairing part), "Explicit
//! initiation"; 0012 §1 "LAN discovery mistaken for trust").

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use qv_crypto::MasterPassword;
use qv_store::{AnchorDir, ArchiveScope, SnapshotDir, VaultFile};

use crate::lan::{
    ApproverUi, JoinCode, JoinMode, JoinOptions, JoinerUi, LanError, LanTimeouts, ListenScope,
    PairingOptions, Sas,
};
use crate::snapshot::SnapshotPolicy;
use crate::testutil::{Env, PASSWORD, TestDir, err, kdf, pw};
use crate::{CoreError, Session};

fn fast() -> LanTimeouts {
    LanTimeouts {
        message: Duration::from_secs(5),
        idle: Duration::from_secs(10),
        confirm: Duration::from_secs(20),
        connect: Duration::from_secs(2),
        probe: Duration::from_secs(1),
    }
}

fn options(label: &str) -> PairingOptions {
    PairingOptions {
        scope: ListenScope::LoopbackForTests,
        limit: Duration::from_secs(30),
        timeouts: fast(),
        ..PairingOptions::new(label)
    }
}

fn join_options(label: &str, port: u16) -> JoinOptions {
    JoinOptions {
        extra_endpoints: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)],
        allow_loopback: true,
        timeouts: fast(),
        ..JoinOptions::new(label)
    }
}

struct Yes(Option<String>, Option<Box<dyn FnMut() + Send>>);
impl ApproverUi for Yes {
    fn confirm(&mut self, sas: &str, _: JoinMode, name: &str) -> bool {
        assert_eq!(name, crate::testutil::NAME);
        if let Some(f) = &mut self.1 {
            f();
        }
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
    fn confirm_vault(&mut self, name: &[u8], _: &Sas) -> bool {
        assert_eq!(name, crate::testutil::NAME.as_bytes());
        true
    }
    fn master_password(&mut self) -> Option<MasterPassword> {
        Some(pw(PASSWORD))
    }
}

fn code(s: &Session, label: &str) -> (crate::PairingWindow, String, u16) {
    let w = s.open_pairing_window(options(label)).unwrap();
    let c = w.code(&[]).unwrap();
    let manual = String::from_utf8(c.manual.expose_secret().to_vec()).unwrap();
    (w, manual, c.port)
}

/// Pairs a new device from `a` into `b_env`'s directory.
fn join_new(
    a: &Session,
    b_env: &Env,
    dest: &std::path::Path,
) -> (crate::ApproveReport, Result<Session, CoreError>) {
    let (w, manual, port) = code(a, "phone");
    let mut yes = Yes(None, None);
    let mut joiner = Joiner(None);
    let core = b_env.core();
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(a, &mut yes, None));
        let joined = {
            let _k = kdf();
            core.join_new_device(
                JoinCode::from_manual(&manual).unwrap(),
                dest,
                join_options("laptop", port),
                &mut joiner,
                None,
            )
        };
        (h.join().unwrap().unwrap(), joined)
    })
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_core_new_device_joins_and_both_list_one_link() {
    let a_env = Env::new();
    let a = a_env.unlock();
    let root = a.root().unwrap();
    crate::testutil::add_entry(&a, root, "shared over the LAN");
    let b_env = Env::empty(TestDir::new());
    let dest = b_env.dir.path().join("joined.qvault");
    let (report, joined) = join_new(&a, &b_env, &dest);
    let b = joined.unwrap();
    assert_eq!(report.mode, JoinMode::NewDevice);
    assert!(report.peer_confirmed);
    let (ao, bo) = (a.overview().unwrap(), b.overview().unwrap());
    assert_eq!(ao.name.expose(), bo.name.expose());
    assert_eq!(ao.entries, bo.entries);
    let al = a.lan_links().unwrap();
    let bl = b.lan_links().unwrap();
    assert_eq!((al.len(), bl.len()), (1, 1));
    assert_eq!(al[0].label.expose(), "phone");
    assert_eq!(bl[0].label.expose(), "laptop");
    assert_eq!(al[0].handle.id_hex(), bl[0].handle.id_hex());
    assert_eq!(al[0].handle.id_hex(), report.link.id_hex());
    // Removal is local: only A's link goes.
    a.remove_lan_link(&al[0].handle).unwrap();
    assert!(a.lan_links().unwrap().is_empty());
    assert_eq!(err(a.remove_lan_link(&al[0].handle)), CoreError::NotFound);
    assert_eq!(
        err(b.remove_lan_link(&al[0].handle)),
        CoreError::StaleHandle
    );
    assert_eq!(b.lan_links().unwrap().len(), 1);
    // Removal preserves the vault's contents.
    assert_eq!(a.overview().unwrap().entries, ao.entries);
}

#[test]
fn lan_core_link_mode_between_replicas() {
    let env = Env::new();
    let a = env.unlock();
    let b_path = env.dir.path().join("b.qvault");
    a.read(|ctx| {
        let mut bytes = Vec::new();
        let now = ctx.now();
        ctx.open.vault.write_archive(&mut bytes, now, &|| false)?;
        let h = ctx.open.vault.header();
        VaultFile::create_from_archive(
            &b_path,
            &mut std::io::Cursor::new(bytes),
            ArchiveScope::new(h.vault_id, h.key_generation),
            ctx.open.vault.vault_key(),
            &AnchorDir::open(&env.anchors)?,
            &|| false,
        )?;
        Ok(())
    })
    .unwrap();
    let b = {
        let _k = kdf();
        env.core().unlock(&b_path, &pw(PASSWORD), None).unwrap()
    };
    let (w, manual, port) = code(&a, "desktop");
    let mut yes = Yes(None, None);
    let mut joiner = Joiner(None);
    let (report, link) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut yes, None));
        let link = b.join_link(
            JoinCode::from_manual(&manual).unwrap(),
            join_options("tablet", port),
            &mut joiner,
            None,
        );
        (h.join().unwrap().unwrap(), link.unwrap())
    });
    assert_eq!(report.mode, JoinMode::Link);
    assert!(report.peer_confirmed);
    assert_eq!(link.id_hex(), report.link.id_hex());
    assert_eq!(
        yes.0.unwrap().as_bytes(),
        &joiner.0.unwrap()[..],
        "both screens showed the same code"
    );
    assert_eq!(b.lan_links().unwrap()[0].label.expose(), "tablet");
}

#[test]
fn lan_core_lock_closes_the_window_without_a_link() {
    let env = Env::new();
    let a = env.unlock();
    let (w, manual, port) = code(&a, "phone");
    let b_env = Env::empty(TestDir::new());
    let dest = b_env.dir.path().join("joined.qvault");
    // The approver's session locks while the user compares the codes.
    let lock: &Session = &a;
    let comparing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let flag = comparing.clone();
    let mut yes = Yes(
        None,
        Some(Box::new(move || {
            flag.store(true, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(300));
        })),
    );
    let core = b_env.core();
    let mut joiner = Joiner(None);
    let (approved, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(lock, &mut yes, None));
        s.spawn(|| {
            while !comparing.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(10));
            }
            lock.lock();
        });
        let joined = core.join_new_device(
            JoinCode::from_manual(&manual).unwrap(),
            &dest,
            join_options("laptop", port),
            &mut joiner,
            None,
        );
        (h.join().unwrap(), joined)
    });
    assert!(matches!(
        approved.err(),
        Some(CoreError::Lan(LanError::Cancelled))
    ));
    assert!(matches!(
        joined.err(),
        Some(CoreError::Lan(LanError::PeerCancelled))
    ));
    assert!(!dest.exists());
    let a = env.unlock();
    assert!(a.lan_links().unwrap().is_empty());
}

#[test]
fn lan_core_refuses_invalid_options_and_recovery_sessions() {
    let env = Env::new();
    let s = env.unlock();
    for label in ["", "a\u{7}b"] {
        assert_eq!(
            err(s.open_pairing_window(options(label))),
            CoreError::InvalidInput
        );
    }
    let mut long = options("x");
    long.limit = Duration::from_secs(601);
    assert_eq!(err(s.open_pairing_window(long)), CoreError::InvalidInput);
    let mut slow = options("x");
    slow.timeouts.message = Duration::from_secs(11);
    assert_eq!(err(s.open_pairing_window(slow)), CoreError::InvalidInput);
    drop(s);
    // A vault opened for recovery (no anchor) cannot pair.
    std::fs::remove_dir_all(&env.anchors).unwrap();
    let (r, _) = {
        let _k = kdf();
        env.core()
            .unlock_for_recovery(&env.path, &pw(PASSWORD), None)
            .unwrap()
    };
    assert!(r.open_pairing_window(options("x")).is_err());
}

fn policy(env: &Env) -> SnapshotPolicy {
    SnapshotPolicy {
        dir: SnapshotDir::open(&env.dir.path().join("snapshots")).unwrap(),
        max_count: 48,
        max_bytes: 512 * 1024 * 1024,
        max_age_seconds: 30 * 24 * 60 * 60,
    }
}

const NEW: &str = "replacement generation passphrase for lan rotation";

#[test]
fn lan_core_rotation_drops_links_and_repairing_works() {
    let a_env = Env::new();
    let core = a_env.core_with(Some(policy(&a_env)));
    let a = {
        let _k = kdf();
        core.unlock(&a_env.path, &pw(PASSWORD), None).unwrap()
    };
    let b_env = Env::empty(TestDir::new());
    let old_copy: PathBuf = b_env.dir.path().join("old.qvault");
    let (report, joined) = join_new(&a, &b_env, &old_copy);
    let old = joined.unwrap();
    assert!(report.peer_confirmed);
    old.lock();
    let old_bytes = std::fs::read(&old_copy).unwrap();
    // The old link root of A's generation.
    let (vault, old_root) = a
        .read(|ctx| {
            let h = ctx.open.vault.header();
            Ok((
                h.vault_id,
                qv_crypto::lan::LinkRoot::derive(
                    ctx.open.vault.vault_key(),
                    h.vault_id,
                    h.key_generation,
                    h.derivation_profile,
                )
                .unwrap(),
            ))
        })
        .unwrap();
    // Rotate A (0002 §3.5).
    let mut r = {
        let _k = kdf();
        a.begin_rotation(&pw(NEW), false, None).unwrap()
    };
    for i in [3usize, 11, 20] {
        let word = r.phrase().expose_word(i).unwrap().to_owned();
        assert!(r.confirm_word(i, word.as_bytes()).unwrap());
    }
    r.install(None).unwrap();
    let a2 = {
        let _k = kdf();
        core.unlock(&a_env.path, &pw(NEW), None).unwrap()
    };
    // The replacement generation has no links (0013 §12.2).
    assert!(a2.lan_links().unwrap().is_empty());
    let (g2, new_root) = a2
        .read(|ctx| {
            let h = ctx.open.vault.header();
            Ok((
                h.key_generation,
                qv_crypto::lan::LinkRoot::derive(
                    ctx.open.vault.vault_key(),
                    h.vault_id,
                    h.key_generation,
                    h.derivation_profile,
                )
                .unwrap(),
            ))
        })
        .unwrap();
    assert_eq!(g2.0, 2);
    // An old-generation proof never verifies under the new generation.
    let proof = old_root
        .proof(&[1; 32], qv_crypto::lan::ProofRole::B, vault, g2)
        .unwrap();
    assert!(
        new_root
            .verify_proof(&[1; 32], qv_crypto::lan::ProofRole::B, vault, g2, &proof)
            .is_err()
    );
    // Re-pairing in new-device mode creates a new file; the old copy stays
    // untouched (0013 §10.6, §12.2).
    let fresh = b_env.dir.path().join("fresh.qvault");
    let (report, joined) = join_new_with(&a2, &b_env, &fresh, NEW);
    assert!(report.peer_confirmed);
    assert_eq!(joined.unwrap().lan_links().unwrap().len(), 1);
    assert_eq!(std::fs::read(&old_copy).unwrap(), old_bytes);
}

struct JoinerPw(&'static str);
impl JoinerUi for JoinerPw {
    fn show_code(&mut self, _: &Sas) -> bool {
        true
    }
    fn confirm_vault(&mut self, _: &[u8], _: &Sas) -> bool {
        true
    }
    fn master_password(&mut self) -> Option<MasterPassword> {
        Some(pw(self.0))
    }
}

fn join_new_with(
    a: &Session,
    b_env: &Env,
    dest: &std::path::Path,
    password: &'static str,
) -> (crate::ApproveReport, Result<Session, CoreError>) {
    let (w, manual, port) = code(a, "phone");
    let mut yes = Yes(None, None);
    let mut joiner = JoinerPw(password);
    let core = b_env.core();
    std::thread::scope(|s| {
        let h = s.spawn(|| w.run(a, &mut yes, None));
        let joined = {
            let _k = kdf();
            core.join_new_device(
                JoinCode::from_manual(&manual).unwrap(),
                dest,
                join_options("laptop", port),
                &mut joiner,
                None,
            )
        };
        (h.join().unwrap().unwrap(), joined)
    })
}

#[test]
fn lan_core_conflicted_keyslot_refuses_a_new_device() {
    let env = Env::new();
    let core = env.core_with(Some(policy(&env)));
    let a = {
        let _k = kdf();
        core.unlock(&env.path, &pw(PASSWORD), None).unwrap()
    };
    // A second replica changes the password concurrently, then its archive
    // merges back: two keyslot heads.
    let other = env.dir.path().join("other.qvault");
    a.read(|ctx| {
        let mut bytes = Vec::new();
        let now = ctx.now();
        ctx.open.vault.write_archive(&mut bytes, now, &|| false)?;
        let h = ctx.open.vault.header();
        VaultFile::create_from_archive(
            &other,
            &mut std::io::Cursor::new(bytes),
            ArchiveScope::new(h.vault_id, h.key_generation),
            ctx.open.vault.vault_key(),
            &AnchorDir::open(&env.anchors)?,
            &|| false,
        )?;
        Ok(())
    })
    .unwrap();
    let o = {
        let _k = kdf();
        core.unlock(&other, &pw(PASSWORD), None).unwrap()
    };
    {
        let _k = kdf();
        o.change_password(&pw("the other replica's password"), None)
            .unwrap();
        a.change_password(&pw("this replica's new password"), None)
            .unwrap();
    }
    let out = TestDir::new();
    let exported = o.export_archive(out.path(), false, None).unwrap();
    let archive = out.path().join(format!("{}.qvsnap", exported.archive_id));
    let merged = a.merge_archive(&archive, true, None).unwrap();
    assert!(merged.accepted);
    let b_env = Env::empty(TestDir::new());
    let dest = b_env.dir.path().join("joined.qvault");
    let (w, manual, port) = code(&a, "phone");
    let mut yes = Yes(None, None);
    let mut joiner = Joiner(None);
    let core_b = b_env.core();
    let (report, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut yes, None));
        let joined = core_b.join_new_device(
            JoinCode::from_manual(&manual).unwrap(),
            &dest,
            join_options("laptop", port),
            &mut joiner,
            None,
        );
        (h.join().unwrap().unwrap(), joined)
    });
    assert_eq!(err(joined), CoreError::Lan(LanError::Keyslot));
    assert!(!report.peer_confirmed);
    assert_eq!(report.failure, Some(LanError::Keyslot));
    assert!(!dest.exists());
}
