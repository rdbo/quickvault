// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN code suites (plans 0037 step 6, 0042 step 5; 0013 Testing
//! Requirements; 0012 §1 "LAN discovery mistaken for trust"). Two devices run on loopback, which
//! is enabled explicitly (0013 §1.4), with shortened time limits.

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::fs::DirBuilderExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use qv_crypto::lan::{
    PairNonce, PairingKeys, PairingSecret, ProofRoot, RecordOpener, RecordSealer, Sas,
};
use qv_crypto::{MasterPassword, SecretBytes, XWingDecapsKey};
use qv_model::{ObjectId, RandomId, Timestamp};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::{
    Done, JoinMode, ManifestPart, ObjectMsg, Outcome, PairAccept, PairGrant, PairHello, PairReveal,
    State, Want,
};
use qv_protocol::oob::decode_manual;
use qv_protocol::registry::{ErrorCode, LanProfile};
use qv_store::{AnchorDir, LanServeState, StoreError, UnlockedVault, VaultFile};

use super::steps::{check_accept, join_attempt, record_keys, th};
use super::transport::{Channel, Conn};
use super::*;

const PASSWORD: &str = "correct horse battery staple";

/// Argon2id runs. At most `QV_TEST_KDF_JOBS` (default: half the CPUs, 1–4)
/// Argon2id runs of 256 MiB at once in this test binary, which bounds memory
/// without serializing every unlock.
static KDF_SLOTS: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());

fn kdf_jobs() -> usize {
    static JOBS: OnceLock<usize> = OnceLock::new();
    *JOBS.get_or_init(|| {
        std::env::var("QV_TEST_KDF_JOBS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map_or(1, |n| n.get() / 2)
                    .clamp(1, 4)
            })
    })
}

/// Holds one KDF slot until dropped.
struct KdfSlot;

impl Drop for KdfSlot {
    fn drop(&mut self) {
        let mut used = KDF_SLOTS.0.lock().unwrap_or_else(PoisonError::into_inner);
        *used -= 1;
        KDF_SLOTS.1.notify_one();
    }
}

fn kdf() -> KdfSlot {
    let mut used = KDF_SLOTS.0.lock().unwrap_or_else(PoisonError::into_inner);
    while *used >= kdf_jobs() {
        used = KDF_SLOTS
            .1
            .wait(used)
            .unwrap_or_else(PoisonError::into_inner);
    }
    *used += 1;
    KdfSlot
}
fn pw(s: &str) -> MasterPassword {
    MasterPassword::from_utf8(s.as_bytes()).unwrap()
}

struct Dir(PathBuf);
impl Dir {
    fn new() -> Self {
        let mut name = String::from("qv-sync-test-");
        for b in qv_crypto::random_array::<8>().unwrap() {
            name.push_str(&format!("{b:02x}"));
        }
        let path = std::env::temp_dir().join(name);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn join(&self, n: &str) -> PathBuf {
        self.0.join(n)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One created vault (KDF once), copied per test with its anchors.
struct Template {
    vault: Vec<u8>,
    anchors: Vec<(std::ffi::OsString, Vec<u8>)>,
}
fn template(name: &'static str) -> &'static Template {
    static A: OnceLock<Template> = OnceLock::new();
    static B: OnceLock<Template> = OnceLock::new();
    let cell = if name == "Personal" { &A } else { &B };
    cell.get_or_init(|| {
        let d = Dir::new();
        let anchors = AnchorDir::open(&d.join("anchors")).unwrap();
        let _k = kdf();
        drop(VaultFile::create(&d.join("v.qvault"), &pw(PASSWORD), name, &anchors).unwrap());
        Template {
            vault: std::fs::read(d.join("v.qvault")).unwrap(),
            anchors: std::fs::read_dir(d.join("anchors"))
                .unwrap()
                .map(|e| {
                    let e = e.unwrap();
                    (e.file_name(), std::fs::read(e.path()).unwrap())
                })
                .collect(),
        }
    })
}

/// A device: its directory, anchors and unlocked vault.
struct Device {
    // Kept alive: dropping the directory deletes the vault.
    _dir: Dir,
    _anchors: AnchorDir,
    vault: Mutex<UnlockedVault>,
}
impl Device {
    fn from(t: &Template) -> Self {
        let dir = Dir::new();
        std::fs::write(dir.join("v.qvault"), &t.vault).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(dir.join("anchors"))
            .unwrap();
        for (n, b) in &t.anchors {
            std::fs::write(dir.join("anchors").join(n), b).unwrap();
        }
        use std::os::unix::fs::PermissionsExt;
        for p in std::fs::read_dir(dir.join("anchors")).unwrap() {
            std::fs::set_permissions(p.unwrap().path(), std::fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        std::fs::set_permissions(dir.join("v.qvault"), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let anchors = AnchorDir::open(&dir.join("anchors")).unwrap();
        let u = {
            let _k = kdf();
            VaultFile::open(&dir.join("v.qvault"))
                .unwrap()
                .unlock(&pw(PASSWORD), &anchors)
                .unwrap()
        };
        Self {
            _dir: dir,
            _anchors: anchors,
            vault: Mutex::new(u),
        }
    }
    fn personal() -> Self {
        Self::from(template("Personal"))
    }
    /// Another replica of this device's vault (same vault and generation).
    fn replica(&self) -> Self {
        let dir = Dir::new();
        let anchors = AnchorDir::open(&dir.join("anchors")).unwrap();
        let u = self.u();
        let mut bytes = Vec::new();
        drop(u);
        self.u()
            .write_archive(&mut bytes, Timestamp(1), &|| false)
            .unwrap();
        let u = self.u();
        VaultFile::create_from_archive(
            &dir.join("v.qvault"),
            &mut std::io::Cursor::new(&bytes),
            qv_store::ArchiveScope::new(u.header().vault_id, u.header().key_generation),
            u.vault_key(),
            &anchors,
            &|| false,
        )
        .unwrap();
        let v = {
            let _k = kdf();
            VaultFile::open(&dir.join("v.qvault"))
                .unwrap()
                .unlock(&pw(PASSWORD), &anchors)
                .unwrap()
        };
        Self {
            _dir: dir,
            _anchors: anchors,
            vault: Mutex::new(v),
        }
    }
    fn u(&self) -> MutexGuard<'_, UnlockedVault> {
        self.vault.lock().unwrap_or_else(PoisonError::into_inner)
    }
    /// `lan_link` rows in this file: always none (0013 §9.1).
    fn links(&self) -> usize {
        self.u().retired_lan_links()
    }
}

impl ExchangeVault for Device {
    fn scope(&self) -> Result<(qv_crypto::VaultId, qv_crypto::KeyGeneration), LanError> {
        let u = self.u();
        Ok((u.header().vault_id, u.header().key_generation))
    }
    fn serve_state(&self) -> Result<LanServeState, LanError> {
        self.u().lan_serve_state().map_err(store)
    }
    fn object(&self, state: &LanServeState, id: ObjectId) -> Result<Vec<u8>, LanError> {
        self.u()
            .lan_object_envelope(state, id)
            .map_err(|e| match e {
                StoreError::NotFound => LanError::StateChanged,
                StoreError::InvalidEdit => LanError::Protocol,
                StoreError::Integrity => LanError::Integrity,
                e => LanError::Store(e),
            })
    }
    fn stage(&self, hash: &[u8; 32], envelope: &[u8]) -> Result<qv_store::LanStaging, LanError> {
        self.u()
            .lan_stage(hash, envelope, &never)
            .map_err(LanError::from_staging)
    }
    fn stage_local(&self, staging: &mut qv_store::LanStaging) -> Result<(), LanError> {
        self.u().lan_stage_local(staging).map_err(store)
    }
    fn accept(&self, staging: qv_store::LanStaging) -> Result<Accepted, LanError> {
        let mut u = self.u();
        let mut verified = u
            .lan_finish(staging, &never)
            .map_err(LanError::from_staging)?;
        let committed = u
            .accept_lan(
                &mut verified,
                &mut |l, i, read| {
                    crate::merge(l, i, &mut |s, r, v| read(s, r, v), &never)
                        .map(|c| c.manifest().clone())
                },
                &never,
            )
            .map_err(store)?;
        let conflicts = u.manifest().records().iter().any(|r| r.heads().len() > 1);
        Ok(Accepted {
            outcome: match (committed, conflicts) {
                (false, _) => Outcome::Unchanged,
                (true, false) => Outcome::Merged,
                (true, true) => Outcome::MergedWithConflicts,
            },
            manifest_hash: u.manifest_hash(),
        })
    }
}

fn store(e: StoreError) -> LanError {
    LanError::Store(e)
}

impl ApproverVault for Device {
    fn context(&self) -> Result<ApproverContext, LanError> {
        let u = self.u();
        let h = u.header();
        Ok(ApproverContext {
            vault_id: h.vault_id,
            key_generation: h.key_generation,
            vault_name: SecretBytes::try_init(8, |b| {
                b.copy_from_slice(b"Personal");
                Ok::<(), ()>(())
            })
            .unwrap(),
            root: proof_root(&u),
        })
    }
    fn grant(&self, seal: &mut Sealer<'_>) -> Result<Vec<u8>, LanError> {
        let u = self.u();
        let h = u.header();
        seal(&grant_plaintext(
            u.vault_key(),
            h.vault_id,
            h.key_generation,
        )?)
    }
}

impl JoinerVault for Device {
    fn context(&self) -> Result<JoinerContext, LanError> {
        let u = self.u();
        let h = u.header();
        Ok(JoinerContext {
            vault_id: h.vault_id,
            key_generation: h.key_generation,
            root: proof_root(&u),
        })
    }
}

fn proof_root(u: &UnlockedVault) -> ProofRoot {
    let h = u.header();
    ProofRoot::derive(
        u.vault_key(),
        h.vault_id,
        h.key_generation,
        h.derivation_profile,
    )
    .unwrap()
}

/// The window's sync report.
fn synced(r: Result<Approved, LanError>) -> Result<RoundReport, LanError> {
    match r? {
        Approved::Synced(report) => Ok(report),
        other => panic!("not a sync: {other:?}"),
    }
}

/// The window's join outcome: whether the new device confirmed, and why not.
fn joined(r: Approved) -> (bool, Option<LanError>) {
    match r {
        Approved::Joined {
            peer_confirmed,
            failure,
        } => (peer_confirmed, failure),
        other => panic!("not a join: {other:?}"),
    }
}

fn private_dir(d: &Dir) -> PathBuf {
    let private = d.join("private");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .unwrap();
    private
}

fn fast() -> LanTimeouts {
    LanTimeouts {
        message: Duration::from_secs(5),
        idle: Duration::from_secs(10),
        confirm: Duration::from_secs(20),
        connect: Duration::from_secs(2),
        probe: Duration::from_secs(1),
    }
}

/// The approver's confirmation: an answer, and the code it saw.
struct Approve {
    answer: bool,
    seen: Option<[u8; 6]>,
    before: Option<Box<dyn FnMut() + Send>>,
}
impl Approve {
    fn yes() -> Self {
        Self {
            answer: true,
            seen: None,
            before: None,
        }
    }
}
impl Confirm for Approve {
    fn confirm(&mut self, sas: &Sas, name: &[u8]) -> bool {
        assert_eq!(name, b"Personal");
        if let Some(f) = &mut self.before {
            f();
        }
        self.seen = Some(sas.digits());
        self.answer
    }
}

/// The joiner's UI.
struct Join {
    show: bool,
    vault: bool,
    passwords: Vec<&'static str>,
    seen: Option<[u8; 6]>,
}
impl Join {
    fn yes() -> Self {
        Self {
            show: true,
            vault: true,
            passwords: vec![PASSWORD],
            seen: None,
        }
    }
}
impl JoinerUi for Join {
    fn show_code(&mut self, sas: &Sas) -> bool {
        self.seen = Some(sas.digits());
        self.show
    }
    fn confirm_vault(&mut self, name: &[u8], sas: &Sas) -> bool {
        assert_eq!(name, b"Personal");
        assert_eq!(Some(sas.digits()), self.seen);
        self.vault
    }
    fn master_password(&mut self) -> Option<MasterPassword> {
        let p = self.passwords.pop()?;
        Some(pw(p))
    }
}

fn never() -> bool {
    false
}

fn window() -> (PairingWindow, SocketAddr, String) {
    let w =
        PairingWindow::open(ListenScope::LoopbackForTests, None, Duration::from_secs(30)).unwrap();
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), w.port().unwrap());
    let code = w.manual_code().to_string();
    (w, addr, code)
}

const LOOPBACK: EndpointPolicy = EndpointPolicy {
    allow_loopback: true,
};

fn keys_of(code: &str) -> PairingKeys {
    PairingSecret::from_bytes(&*decode_manual(code).unwrap())
        .unwrap()
        .keys()
        .unwrap()
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_new_device_end_to_end() {
    let a = Device::personal();
    let b = Dir::new();
    let private = b.join("private");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .unwrap();
    let (w, _addr, code) = window();
    let qr = w.qr(&[IpAddr::V4(Ipv4Addr::LOCALHOST)]).unwrap();
    let mut approve = Approve::yes();
    let mut join = Join::yes();
    let (approved, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let joined = {
            let _k = kdf();
            join_new_device(
                JoinCode::from_qr(&qr).unwrap(),
                &[],
                LOOPBACK,
                &private,
                &mut join,
                &fast(),
                &never,
            )
        };
        (h.join().unwrap(), joined)
    });
    let (confirmed, failure) = super::tests::joined(approved.unwrap());
    let joined = joined.unwrap();
    let _ = code;
    assert!(confirmed, "{failure:?}");
    assert!(approve.seen.is_some());
    assert_eq!(approve.seen, join.seen);
    assert_eq!(joined.staging.manifest(), a.u().manifest());
    assert!(joined.vk.ct_eq(a.u().vault_key()));
    // B builds its vault (0013 §10 step 5).
    let anchors = AnchorDir::open(&b.join("anchors")).unwrap();
    let path = b.join("joined.qvault");
    VaultFile::create_from_lan(
        &path,
        joined.staging,
        joined.proof,
        &joined.vk,
        &anchors,
        &never,
    )
    .unwrap();
    let u = {
        let _k = kdf();
        VaultFile::open(&path)
            .unwrap()
            .unlock(&pw(PASSWORD), &anchors)
            .unwrap()
    };
    assert_eq!(u.manifest(), a.u().manifest());
    // Nothing about the other device is stored on either side (0013 §9.1).
    assert_eq!(u.retired_lan_links(), 0);
    assert_eq!(a.links(), 0);
}

#[test]
fn lan_enroll_sync_mode_needs_no_comparison_code_and_stores_nothing() {
    let a = Device::personal();
    let b = a.replica();
    let (w, addr, code) = window();
    let mut approve = Approve::yes();
    let (approved, ours) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let ours = sync_with_code(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &b,
            &fast(),
            &never,
        );
        (h.join().unwrap(), ours)
    });
    // The exchange (§4.8) ran: identical replicas, nothing new.
    let ours = ours.unwrap();
    let theirs = synced(approved).unwrap();
    assert_eq!(
        (ours.local, ours.peer, theirs.local, theirs.peer),
        (
            Outcome::Unchanged,
            Some(Outcome::Unchanged),
            Outcome::Unchanged,
            Some(Outcome::Unchanged)
        )
    );
    // No comparison code was shown, and no row was written.
    assert!(approve.seen.is_none());
    assert_eq!(a.links() + b.links(), 0);
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_vault_substitution_releases_nothing() {
    // Sync mode with a different vault: A refuses B's proof.
    let a = Device::personal();
    let other = Device::from(template("Other"));
    let (w, addr, code) = window();
    let mut approve = Approve::yes();
    let (sa, so) = (a.u().local_seq(), other.u().local_seq());
    let (approved, link) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let link = sync_with_code(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &other,
            &fast(),
            &never,
        );
        (h.join().unwrap(), link)
    });
    assert_eq!(approved.unwrap_err(), LanError::VaultMismatch);
    assert_eq!(link.unwrap_err(), LanError::VaultMismatch);
    assert_eq!((a.u().local_seq(), other.u().local_seq()), (sa, so));
    assert_eq!(a.links() + other.links(), 0);
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_wrong_code_gets_no_answer_and_counts() {
    let a = Device::personal();
    let (w, addr, _code) = window();
    let wrong = qv_protocol::oob::encode_manual(&[0x42; 16]).to_string();
    let mut approve = Approve::yes();
    let stop = AtomicBool::new(false);
    let cancel = || stop.load(Ordering::SeqCst);
    let (approved, link) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &cancel));
        let b = Device::personal();
        let link = sync_with_code(
            JoinCode::from_manual(&wrong).unwrap(),
            &[addr],
            LOOPBACK,
            &b,
            &fast(),
            &never,
        );
        stop.store(true, Ordering::SeqCst);
        (h.join().unwrap(), link)
    });
    assert_eq!(link.unwrap_err(), LanError::NoPeer);
    assert_eq!(approved.unwrap_err(), LanError::Cancelled);
    assert!(approve.seen.is_none());
    assert_eq!(a.links(), 0);
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_spoofed_endpoint_first_is_skipped() {
    let a = Device::personal();
    let b = a.replica();
    let (w, addr, code) = window();
    // A spoof at the first candidate endpoint: it answers with a wrong-MAC accept.
    let spoof = TcpListener::bind("127.0.0.1:0").unwrap();
    let spoof_addr = spoof.local_addr().unwrap();
    let mut approve = Approve::yes();
    let (approved, link) = std::thread::scope(|s| {
        s.spawn(|| {
            let (stream, _) = spoof.accept().unwrap();
            let mut conn = Conn::new(stream, &never).unwrap();
            conn.within(Duration::from_secs(5), None);
            let mut buf = Vec::new();
            conn.recv_frame(FramePhase::Handshake, &mut buf).unwrap();
            assert!(PairHello::decode(&buf).is_ok());
            let fake = PairAccept::encode(&[1; 32], &[2; 1120], &[3; 32]).unwrap();
            let _ = conn.send_frame(FramePhase::Handshake, &fake);
        });
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let link = sync_with_code(
            JoinCode::from_manual(&code).unwrap(),
            &[spoof_addr, addr],
            LOOPBACK,
            &b,
            &fast(),
            &never,
        );
        (h.join().unwrap(), link)
    });
    assert_eq!(link.unwrap().local, synced(approved).unwrap().local);
}

/// Sends one handshake frame to `addr` and returns whether anything came back.
fn poke(addr: SocketAddr, frame: &[u8]) -> bool {
    let stream = TcpStream::connect(addr).unwrap();
    let mut conn = Conn::new(stream, &never).unwrap();
    conn.within(Duration::from_secs(3), None);
    conn.send_frame(FramePhase::Handshake, frame).unwrap();
    let mut buf = Vec::new();
    conn.recv_frame(FramePhase::Handshake, &mut buf).is_ok()
}

fn hello_with(keys: &PairingKeys, profile: u64, pairing_id: [u8; 16], mode: u64) -> Vec<u8> {
    let (_, ek) = XWingDecapsKey::generate().unwrap();
    let commit = PairNonce::generate().unwrap().commitment().unwrap();
    let enc = |e: &mut qv_encoding::Encoder| {
        e.text("qv/lan-pair-hello/v1");
        e.uint(profile);
        e.bytes(&pairing_id);
        e.uint(mode);
        e.bytes(&commit);
        e.bytes(ek.as_bytes());
    };
    let body = qv_encoding::encode_array(|a| {
        enc(a);
        Ok(())
    })
    .unwrap();
    let mac = keys.hello_mac(&body).unwrap();
    qv_encoding::encode_array(|a| {
        enc(a);
        a.bytes(mac.as_bytes());
        Ok(())
    })
    .unwrap()
    .to_vec()
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_hostile_hellos_are_silent_and_close_the_window() {
    let a = Device::personal();
    let (w, addr, code) = window();
    let keys = keys_of(&code);
    let id = *keys.pairing_id();
    let mut approve = Approve::yes();
    let approved = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        // Profile 2, a swapped pairing ID, mode 2, a wrong MAC key, garbage
        // and an oversized frame: no reply, each counted.
        let other = PairingSecret::from_bytes(&[9; 16]).unwrap().keys().unwrap();
        let mut bad = vec![
            hello_with(&keys, 2, id, 0),
            hello_with(&keys, 1, [0; 16], 0),
            hello_with(&keys, 1, id, 2),
            hello_with(&other, 1, id, 0),
            vec![0x80],
        ];
        while bad.len() < 15 {
            bad.push(b"garbage".to_vec());
        }
        for frame in &bad {
            assert!(!poke(addr, frame));
        }
        // The 16th: an oversized length, refused before allocation.
        let mut stream = TcpStream::connect(addr).unwrap();
        use std::io::{Read, Write};
        stream.write_all(&5000u32.to_be_bytes()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut b = [0u8; 1];
        assert!(matches!(stream.read(&mut b), Ok(0) | Err(_)));
        h.join().unwrap()
    });
    assert_eq!(approved.unwrap_err(), LanError::TooManyAttempts);
    assert!(approve.seen.is_none());
    assert_eq!(a.links(), 0);
}

/// A manual joiner that pairs up to the record channel, for hostile-peer and
/// ordering tests.
struct Manual<'c> {
    ch: Channel<'c>,
    hello: Vec<u8>,
    th: [u8; 32],
}

fn manual<'c>(
    addr: SocketAddr,
    keys: &PairingKeys,
    mode: JoinMode,
    reveal: Option<[u8; 32]>,
) -> Manual<'c> {
    let nonce = PairNonce::generate().unwrap();
    let (dk, ek) = XWingDecapsKey::generate().unwrap();
    let attempt = join_attempt(keys, mode, nonce, dk, &ek).unwrap();
    let mut conn = Conn::new(TcpStream::connect(addr).unwrap(), &never).unwrap();
    conn.within(Duration::from_secs(5), None);
    conn.send_frame(FramePhase::Handshake, &attempt.hello)
        .unwrap();
    let mut buf = Vec::new();
    conn.recv_frame(FramePhase::Handshake, &mut buf).unwrap();
    let (ct, accept_hash) = check_accept(keys, &attempt.hello_hash, &buf).unwrap();
    let ss = attempt.dk.decapsulate(&ct).unwrap();
    let th = th(&attempt.hello_hash, &accept_hash).unwrap();
    let (b2a, a2b) = record_keys(keys, &ss, &th).unwrap();
    let mut ch = Channel::new(conn, RecordSealer::new(b2a), RecordOpener::new(a2b));
    if mode == JoinMode::NewDevice {
        let revealed = reveal.unwrap_or(*attempt.nonce_b.expose_secret());
        ch.send(
            &PairReveal::encode(&revealed).unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();
    }
    Manual {
        ch,
        hello: attempt.hello.to_vec(),
        th,
    }
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_raced_second_hello_aborts_without_release() {
    let a = Device::personal();
    let (w, addr, code) = window();
    let keys = keys_of(&code);
    let racer = hello_with(&keys, 1, *keys.pairing_id(), 0);
    let mut approve = Approve {
        answer: true,
        seen: None,
        before: Some(Box::new(move || {
            // Someone else who saw the code connects meanwhile.
            assert!(!poke(addr, &racer));
            std::thread::sleep(Duration::from_millis(300));
        })),
    };
    let (approved, mut m) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let m = manual(addr, &keys, JoinMode::NewDevice, None);
        (h.join().unwrap(), m)
    });
    assert_eq!(approved.unwrap_err(), LanError::CodeObserved);
    // No grant: the joiner receives `cancelled`.
    assert_eq!(
        m.ch.recv(Duration::from_secs(5), None).err(),
        Some(LanError::PeerCancelled)
    );
    assert_eq!(a.links(), 0);
}

#[test]
fn lan_enroll_identical_replayed_hello_is_refused_not_observed() {
    let a = Device::personal();
    let (w, addr, code) = window();
    let keys = keys_of(&code);
    let replay: Mutex<Vec<u8>> = Mutex::new(Vec::new());
    let mut approve = Approve::yes();
    approve.answer = false;
    let approved = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let m = manual(addr, &keys, JoinMode::NewDevice, None);
        *replay.lock().unwrap() = m.hello.clone();
        assert!(!poke(addr, &replay.lock().unwrap()));
        let r = h.join().unwrap();
        drop(m);
        r
    });
    // The pairing ends by the user's rejection, not by an observed code.
    assert_eq!(approved.unwrap_err(), LanError::Cancelled);
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_reveal_must_open_the_commitment() {
    let a = Device::personal();
    let (w, addr, code) = window();
    let keys = keys_of(&code);
    let mut approve = Approve::yes();
    let (approved, mut m) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        // A joiner revealing another nonce than it committed to.
        let m = manual(addr, &keys, JoinMode::NewDevice, Some([7; 32]));
        (h.join().unwrap(), m)
    });
    assert_eq!(approved.unwrap_err(), LanError::Protocol);
    assert!(approve.seen.is_none());
    assert_eq!(
        m.ch.recv(Duration::from_secs(5), None).err(),
        Some(LanError::Protocol)
    );
    assert_eq!(a.links(), 0);
}

#[test]
fn lan_enroll_rejections_on_either_side() {
    // A rejects the comparison code.
    let a = Device::personal();
    let b = Dir::new();
    let private = private_dir(&b);
    let (w, addr, code) = window();
    let mut approve = Approve::yes();
    approve.answer = false;
    let (approved, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let joined = join_new_device(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &private,
            &mut Join::yes(),
            &fast(),
            &never,
        );
        (h.join().unwrap(), joined)
    });
    assert_eq!(approved.unwrap_err(), LanError::Cancelled);
    assert_eq!(joined.unwrap_err(), LanError::PeerCancelled);
    // B rejects.
    let (w, addr, code) = window();
    let mut join = Join::yes();
    join.show = false;
    let mut approve = Approve::yes();
    let (approved, joined) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let joined = join_new_device(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &private,
            &mut join,
            &fast(),
            &never,
        );
        (h.join().unwrap(), joined)
    });
    assert_eq!(joined.unwrap_err(), LanError::Cancelled);
    // B cancels right after its reveal while A's user confirms. If A had
    // not granted yet, its window fails; if it had (A's user approved, which
    // is what releases VK, §4.7), A reports that the new device did not
    // finish. Nothing is stored either way.
    match approved {
        Err(_) => {}
        Ok(served) => {
            let (confirmed, failure) = super::tests::joined(served);
            assert!(!confirmed && failure.is_some());
        }
    }
    assert_eq!(a.links(), 0);
}

#[test]
fn lan_enroll_cancel_during_the_confirmation_wait_is_prompt() {
    let a = Device::personal();
    let b = Dir::new();
    let private = private_dir(&b);
    let (w, addr, code) = window();
    let stop = AtomicBool::new(false);
    let cancel = || stop.load(Ordering::SeqCst);
    let release = AtomicBool::new(false);
    let wait = &release;
    struct Slow<'r>(&'r AtomicBool);
    impl Confirm for Slow<'_> {
        fn confirm(&mut self, _: &Sas, _: &[u8]) -> bool {
            while !self.0.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
            }
            false
        }
    }
    let mut slow = Slow(wait);
    let (elapsed, link) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut slow, &fast(), &never));
        let started = Instant::now();
        s.spawn(|| {
            std::thread::sleep(Duration::from_millis(500));
            stop.store(true, Ordering::SeqCst);
        });
        let link = join_new_device(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &private,
            &mut Join::yes(),
            &fast(),
            &cancel,
        );
        let elapsed = started.elapsed();
        release.store(true, Ordering::SeqCst);
        let _ = h.join().unwrap();
        (elapsed, link)
    });
    assert_eq!(link.unwrap_err(), LanError::Cancelled);
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    assert_eq!(a.links(), 0);
}

#[test]
fn lan_enroll_exchange_refuses_bad_requests_and_tolerates_a_missing_done() {
    for case in 0..5 {
        let a = Device::personal();
        let (w, addr, code) = window();
        let keys = keys_of(&code);
        let mut approve = Approve::yes();
        let (approved, joiner_err) = std::thread::scope(|s| {
            let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
            let mut m = manual(addr, &keys, JoinMode::NewDevice, None);
            let t = Duration::from_secs(5);
            let grant = m.ch.recv(t, None).unwrap();
            let g = PairGrant::decode(grant.expose_secret()).unwrap();
            let (vault, generation) = (g.vault_id, g.key_generation);
            m.ch.send(&State::encode(&vault, generation, &[0; 32], 0).unwrap(), t)
                .unwrap();
            let state = State::decode(m.ch.recv(t, None).unwrap().expose_secret()).unwrap();
            let mut envelope = Vec::new();
            while (envelope.len() as u64) < state.manifest_length {
                let msg = m.ch.recv(t, None).unwrap();
                envelope
                    .extend_from_slice(ManifestPart::decode(msg.expose_secret()).unwrap().bytes);
            }
            let err = match case {
                // An ID outside the served manifest.
                0 => {
                    m.ch.send(&Want::encode(&[[0xee; 16]], true).unwrap(), t)
                        .unwrap();
                    m.ch.recv(t, None).err()
                }
                // A duplicate ID.
                1 => {
                    let ids = a.u().manifest().references()[0].object_id().to_bytes();
                    m.ch.send(&Want::encode(&[ids, ids], true).unwrap(), t)
                        .unwrap();
                    m.ch.recv(t, None).err()
                }
                // Everything, then no Done.
                _ => {
                    let refs: Vec<[u8; 16]> = a
                        .u()
                        .manifest()
                        .references()
                        .iter()
                        .map(|r| r.object_id().to_bytes())
                        .collect();
                    m.ch.send(&Want::encode(&refs, true).unwrap(), t).unwrap();
                    for _ in &refs {
                        ObjectMsg::decode(m.ch.recv(t, None).unwrap().expose_secret()).unwrap();
                    }
                    let want = Want::decode(m.ch.recv(t, None).unwrap().expose_secret()).unwrap();
                    assert!(want.ids.is_empty() && want.last);
                    if case == 4 {
                        // A Done that does not report receipt (§10 step 3).
                        m.ch.send(
                            &Done::encode(Outcome::Unchanged, &state.manifest_hash).unwrap(),
                            t,
                        )
                        .unwrap();
                    } else if case == 3 {
                        m.ch.send(
                            &Done::encode(Outcome::Merged, &state.manifest_hash).unwrap(),
                            t,
                        )
                        .unwrap();
                        let done =
                            Done::decode(m.ch.recv(t, None).unwrap().expose_secret()).unwrap();
                        assert_eq!(done.outcome, Outcome::Unchanged);
                    } else {
                        m.ch.conn.close();
                    }
                    None
                }
            };
            (h.join().unwrap(), err)
        });
        let (confirmed, failure) = joined(approved.unwrap());
        // Nothing about the new device is stored, before or after the grant.
        assert_eq!(a.links(), 0, "case {case}");
        match case {
            0 | 1 => {
                assert_eq!(joiner_err, Some(LanError::Protocol), "case {case}");
                assert_eq!(failure, Some(LanError::Protocol));
                assert!(!confirmed);
            }
            2 => {
                assert!(!confirmed);
                assert!(failure.is_some());
            }
            4 => {
                assert!(!confirmed);
                assert_eq!(failure, Some(LanError::Protocol));
            }
            _ => assert!(confirmed),
        }
    }
}

#[test]
fn lan_enroll_window_expires() {
    let a = Device::personal();
    let w = PairingWindow::open(
        ListenScope::LoopbackForTests,
        None,
        Duration::from_millis(300),
    )
    .unwrap();
    let started = Instant::now();
    assert_eq!(
        w.run(&a, &mut Approve::yes(), &fast(), &never).unwrap_err(),
        LanError::WindowExpired
    );
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn lan_enroll_codes_and_policies() {
    let (w, _, code) = window();
    assert_eq!(code.len(), 31);
    // A loopback window advertises only loopback; a joiner refuses loopback
    // unless enabled.
    let qr = w
        .qr(&[
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ])
        .unwrap();
    let parsed = qv_protocol::oob::decode_qr(&qr).unwrap();
    assert_eq!(parsed.endpoints.len(), 1);
    let j = JoinCode::from_qr(&qr).unwrap();
    assert!(j.candidates(&[], EndpointPolicy::default()).is_empty());
    assert_eq!(j.candidates(&[], LOOPBACK).len(), 1);
    let bad: Vec<SocketAddr> = [
        "0.0.0.0:1",
        "224.0.0.251:5353",
        "255.255.255.255:1",
        "10.0.0.1:0",
    ]
    .iter()
    .map(|s| s.parse().unwrap())
    .collect();
    // Typed endpoints replace hints, even if every typed address is rejected.
    assert!(j.candidates(&bad, LOOPBACK).is_empty());
    let typed: SocketAddr = "192.0.2.55:7777".parse().unwrap();
    assert_eq!(j.candidates(&[typed], LOOPBACK), vec![typed]);
    let many: Vec<SocketAddr> = (1..40)
        .map(|p| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), p))
        .collect();
    assert_eq!(j.candidates(&many, LOOPBACK).len(), 16);
    // An unknown profile in a QR.
    let qr2 = qv_protocol::oob::encode_qr(LanProfile::V1, &[1; 16], &[], "").unwrap();
    let mut raw = qr2.to_vec();
    let pos = raw.iter().position(|b| *b == 0x01).unwrap();
    raw[pos] = 0x02;
    assert_eq!(JoinCode::from_qr(&raw).unwrap_err(), LanError::Unsupported);
    assert_eq!(
        JoinCode::from_manual("short").unwrap_err(),
        LanError::Protocol
    );
    // Timeouts may only shrink.
    let mut t = LanTimeouts::default();
    t.validate().unwrap();
    t.message = Duration::from_secs(11);
    assert!(t.validate().is_err());
    assert_eq!(ErrorCode::from_wire(5), ErrorCode::Cancelled);
}

/// A hostile approver: pairs correctly, grants `a`'s vault, then runs
/// `script` instead of the honest exchange.
fn hostile_approver(
    a: &Device,
    script: impl FnOnce(&mut Channel<'_>, &LanServeState) + Send,
) -> LanError {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let secret = PairingSecret::generate().unwrap();
    let code = qv_protocol::oob::encode_manual(secret.expose_secret()).to_string();
    let keys = secret.keys().unwrap();
    let b = Dir::new();
    let private = b.join("private");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&private)
        .unwrap();
    std::thread::scope(|s| {
        s.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let mut conn = Conn::new(stream, &never).unwrap();
            conn.within(Duration::from_secs(5), None);
            let mut buf = Vec::new();
            conn.recv_frame(FramePhase::Handshake, &mut buf).unwrap();
            let hello = super::steps::check_hello(&keys, &buf).ok().unwrap();
            let (ss, ct) = hello.ek.encapsulate().unwrap();
            let (accept, accept_hash) =
                super::steps::accept_for(&keys, &hello.hash, &[5; 32], &ct).unwrap();
            conn.send_frame(FramePhase::Handshake, &accept).unwrap();
            let th = th(&hello.hash, &accept_hash).unwrap();
            let (b2a, a2b) = record_keys(&keys, &ss, &th).unwrap();
            let mut ch = Channel::new(conn, RecordSealer::new(a2b), RecordOpener::new(b2a));
            let t = Duration::from_secs(5);
            ch.recv(t, None).unwrap(); // reveal
            let record = a.grant(&mut |p| ch.seal(p)).unwrap();
            ch.send_sealed(&record, t).unwrap();
            let state = a.serve_state().unwrap();
            State::decode(ch.recv(t, None).unwrap().expose_secret()).unwrap();
            script(&mut ch, &state);
        });
        let mut join = Join::yes();
        join_new_device(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &private,
            &mut join,
            &fast(),
            &never,
        )
        .unwrap_err()
    })
}

fn honest_state(ch: &mut Channel<'_>, a: &Device, state: &LanServeState) {
    let h = *a.u().header();
    let len = state.envelope().len() as u64;
    ch.send(
        &State::encode(
            &h.vault_id.0,
            h.key_generation.0,
            state.manifest_hash(),
            len,
        )
        .unwrap(),
        Duration::from_secs(5),
    )
    .unwrap();
}

fn parts(ch: &mut Channel<'_>, state: &LanServeState) {
    for (i, part) in state.envelope().chunks(1 << 20).enumerate() {
        ch.send(
            &ManifestPart::encode((i << 20) as u64, part).unwrap(),
            Duration::from_secs(5),
        )
        .unwrap();
    }
}

fn wants(ch: &mut Channel<'_>) -> Vec<[u8; 16]> {
    let mut ids = Vec::new();
    loop {
        let w = Want::decode(
            ch.recv(Duration::from_secs(5), None)
                .unwrap()
                .expose_secret(),
        )
        .unwrap();
        ids.extend(w.ids);
        if w.last {
            return ids;
        }
    }
}

#[test]
fn lan_enroll_joiner_refuses_a_hostile_approver() {
    let a = Device::personal();
    let t = Duration::from_secs(5);
    // Another vault in the state than in the grant.
    let e = hostile_approver(&a, |ch, state| {
        let h = *a.u().header();
        ch.send(
            &State::encode(&[0x77; 16], h.key_generation.0, state.manifest_hash(), 10).unwrap(),
            t,
        )
        .unwrap();
    });
    assert_eq!(e, LanError::VaultMismatch);
    // A manifest above 64 MiB, refused before allocating.
    let e = hostile_approver(&a, |ch, state| {
        let h = *a.u().header();
        ch.send(
            &State::encode(
                &h.vault_id.0,
                h.key_generation.0,
                state.manifest_hash(),
                (64 << 20) + 1,
            )
            .unwrap(),
            t,
        )
        .unwrap();
    });
    assert_eq!(e, LanError::Limit);
    // A non-contiguous part.
    let e = hostile_approver(&a, |ch, state| {
        honest_state(ch, &a, state);
        ch.send(&ManifestPart::encode(1, &state.envelope()[1..]).unwrap(), t)
            .unwrap();
    });
    assert_eq!(e, LanError::Protocol);
    // A tampered manifest fails its hash.
    let e = hostile_approver(&a, |ch, state| {
        honest_state(ch, &a, state);
        let mut env = state.envelope().to_vec();
        let n = env.len() - 1;
        env[n] ^= 1;
        ch.send(&ManifestPart::encode(0, &env).unwrap(), t).unwrap();
    });
    assert_eq!(e, LanError::Integrity);
    // Objects out of request order.
    let e = hostile_approver(&a, |ch, state| {
        honest_state(ch, &a, state);
        parts(ch, state);
        let ids = wants(ch);
        let last = ObjectId::from_bytes(*ids.last().unwrap()).unwrap();
        ch.send(
            &ObjectMsg::encode(&a.object(state, last).unwrap()).unwrap(),
            t,
        )
        .unwrap();
    });
    assert_eq!(e, LanError::Protocol);
    // A request of the empty joiner.
    let e = hostile_approver(&a, |ch, state| {
        honest_state(ch, &a, state);
        parts(ch, state);
        for id in wants(ch) {
            let id = ObjectId::from_bytes(id).unwrap();
            ch.send(
                &ObjectMsg::encode(&a.object(state, id).unwrap()).unwrap(),
                t,
            )
            .unwrap();
        }
        ch.send(&Want::encode(&[[1; 16]], true).unwrap(), t)
            .unwrap();
    });
    assert_eq!(e, LanError::Protocol);
    // A `cancelled` error record instead of the state.
    let e = hostile_approver(&a, |ch, _| {
        ch.send(
            &qv_protocol::lan::ErrorMsg::encode(ErrorCode::Cancelled).unwrap(),
            t,
        )
        .unwrap();
    });
    assert_eq!(e, LanError::PeerCancelled);
}

#[path = "sync_tests.rs"]
mod sync;
