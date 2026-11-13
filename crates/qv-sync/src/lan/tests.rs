// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN code suites (plans 0037 step 6, 0042 step 5; 0013 Testing
//! Requirements; 0012 §1 "LAN discovery mistaken for trust"). Two devices run on loopback, which
//! is enabled explicitly (0013 §1.4), with shortened time limits.

#![allow(clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{Duration, Instant};

use qv_crypto::lan::{PairNonce, PairingSecret, Sas};
use qv_crypto::{MasterPassword, SecretBytes, XWingDecapsKey};
use qv_model::{ObjectId, RandomId, Timestamp};
use qv_protocol::frame::FramePhase;
use qv_protocol::lan::{Done, JoinMode, ManifestPart, ObjectMsg, Outcome, State, Want};
use qv_protocol::oob::decode_manual;
use qv_protocol::registry::{ErrorCode, LanProfile};
use qv_store::{AnchorDir, LanServeState, StoreError, UnlockedVault, VaultFile};

use super::steps_v2::{auth_transcript, check_accept, crypto_mode, join_attempt, outer_transcript};
use super::transport::{Conn, V2Channel};
use super::*;
use qv_crypto::lan::v2::{
    self as crypto, FinalEpoch, InitialEpoch, KeyAuthentication, OuterSchedule, PairingKeys,
    TrafficKeys,
};
use qv_crypto::lan_auth::{PasswordAuthClient, PasswordAuthServer};
use qv_protocol::lan::v2::{
    self as wire, AuthMode, Finished, KeyProve, KeyProved, PakeFinish, PakeResponse, PakeStart,
};

const PASSWORD: &str = "correct horse battery staple";

/// Argon2id runs. At most `QV_TEST_KDF_JOBS` (default 1)
/// Argon2id runs of 256 MiB at once in this test binary, which bounds memory
/// and keeps the machine responsive; set it higher for speed.
static KDF_SLOTS: (Mutex<usize>, Condvar) = (Mutex::new(0), Condvar::new());

/// `chmod mode`, or its Windows ACL counterpart.
fn set_mode(path: &std::path::Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(windows)]
    qv_win::fs::chmod_like(path, mode).unwrap();
}
fn kdf_jobs() -> usize {
    static JOBS: OnceLock<usize> = OnceLock::new();
    *JOBS.get_or_init(|| {
        std::env::var("QV_TEST_KDF_JOBS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|n| *n > 0)
            .unwrap_or(1)
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
        qv_store::create_private_dirs(&path).unwrap();
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
        qv_store::create_private_dirs(&dir.join("anchors")).unwrap();
        for (n, b) in &t.anchors {
            std::fs::write(dir.join("anchors").join(n), b).unwrap();
        }
        for p in std::fs::read_dir(dir.join("anchors")).unwrap() {
            set_mode(&p.unwrap().path(), 0o600);
        }
        set_mode(&dir.join("v.qvault"), 0o600);
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
        })
    }
}

struct TestAuthorization {
    descriptor: zeroize::Zeroizing<Vec<u8>>,
    record: qv_model::RecordId,
    version: qv_model::VersionId,
    object: ObjectId,
    hash: [u8; 32],
    t0: [u8; 32],
}
impl CredentialApprover for Device {
    type Authorization = TestAuthorization;
    fn authenticate_password(
        &self,
        password: MasterPassword,
        t0: &[u8; 32],
        ke1: &[u8],
    ) -> Result<(PasswordAuthServer, SecretBytes, TestAuthorization), LanError> {
        let authorization = {
            let u = self.u();
            let descriptor = u.lan_working_password_descriptor().map_err(store)?;
            let record = u.manifest().keyslot_id();
            let [head] = u.manifest().record(record).unwrap().heads() else {
                return Err(LanError::Keyslot);
            };
            TestAuthorization {
                descriptor,
                record,
                version: head.version_id(),
                object: head.object_id(),
                hash: *u.manifest().reference(head.object_id()).unwrap().sha256(),
                t0: *t0,
            }
        };
        let slot = qv_model::Keyslot::decode(&authorization.descriptor).unwrap();
        let (vault, generation) = self.scope()?;
        let unwrapped = slot
            .slot
            .unlock(&password, vault, generation)
            .map_err(|_| LanError::Store(StoreError::WrongPassword))?;
        if !unwrapped.ct_eq(self.u().vault_key()) {
            return Err(LanError::Integrity);
        }
        drop(unwrapped);
        let (server, ke2) =
            PasswordAuthServer::start(&password, t0, ke1).map_err(|_| LanError::Integrity)?;
        drop(password);
        Ok((server, ke2, authorization))
    }
    fn check_authorization(&self, a: &TestAuthorization) -> Result<(), LanError> {
        let u = self.u();
        if u.lan_working_password_descriptor()
            .map_err(store)?
            .as_slice()
            != a.descriptor.as_slice()
        {
            return Err(LanError::StateChanged);
        }
        Ok(())
    }
    fn key_auth(
        &self,
        mode: crypto::AuthMode,
        t0: [u8; 32],
    ) -> Result<KeyAuthentication, LanError> {
        KeyAuthentication::new(self.u().vault_key(), mode, t0).map_err(|_| LanError::Integrity)
    }
    fn authorized_grant(
        &self,
        a: TestAuthorization,
        sealer: &mut crypto::RecordSealer<FinalEpoch>,
    ) -> Result<SealedGrant, LanError> {
        self.check_authorization(&a)?;
        assert_eq!(
            sealer.binding(),
            (crypto::AuthMode::PasswordEnrollment, a.t0)
        );
        assert_eq!(sealer.next_sequence(), 0);
        let u = self.u();
        let h = u.header();
        let plaintext = credential_grant_plaintext(
            u.vault_key(),
            h.vault_id,
            h.key_generation,
            &a.descriptor,
            a.record,
            a.version,
            a.object,
            &a.hash,
        )?;
        Ok(SealedGrant::Ready(
            sealer.seal(plaintext.expose_secret()).unwrap(),
        ))
    }
}

impl JoinerVault for Device {
    fn key_auth(&self, t0: [u8; 32]) -> Result<KeyAuthentication, LanError> {
        CredentialApprover::key_auth(self, crypto::AuthMode::KeySync, t0)
    }
    fn context(&self) -> Result<JoinerContext, LanError> {
        let u = self.u();
        let h = u.header();
        Ok(JoinerContext {
            vault_id: h.vault_id,
            key_generation: h.key_generation,
        })
    }
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
            ..
        } => (peer_confirmed, failure),
        other => panic!("not a join: {other:?}"),
    }
}

fn private_dir(d: &Dir) -> PathBuf {
    let private = d.join("private");
    qv_store::create_private_dirs(&private).unwrap();
    private
}

fn fast() -> LanTimeouts {
    LanTimeouts {
        message: Duration::from_secs(5),
        idle: Duration::from_secs(10),
        confirm: Duration::from_secs(20),
        connect: Duration::from_secs(2),
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
    fn password(&mut self, sas: &Sas, name: &[u8], _: bool) -> Option<MasterPassword> {
        self.confirm(sas, name).then(|| pw(PASSWORD))
    }
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
    PairingKeys::new(PairingSecret::from_bytes(&*decode_manual(code).unwrap()).unwrap()).unwrap()
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_new_device_end_to_end() {
    let a = Device::personal();
    let b = Dir::new();
    let private = b.join("private");
    qv_store::create_private_dirs(&private).unwrap();
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
    VaultFile::create_from_verified_lan(
        &path,
        joined.staging,
        joined.proof,
        joined.vk,
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
    assert_eq!(approved.unwrap_err(), LanError::Integrity);
    assert_eq!(link.unwrap_err(), LanError::Timeout);
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
            assert!(wire::PairHello::decode(&buf).is_ok());
            let fake =
                qv_protocol::lan::PairAccept::encode(&[1; 32], &[2; 1120], &[3; 32]).unwrap();
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
    let Ok(stream) = TcpStream::connect_timeout(&addr, Duration::from_secs(1)) else {
        return false;
    };
    let mut conn = Conn::new(stream, &never).unwrap();
    conn.within(Duration::from_secs(3), None);
    if conn.send_frame(FramePhase::Handshake, frame).is_err() {
        return false;
    }
    let mut buf = Vec::new();
    conn.recv_frame(FramePhase::Handshake, &mut buf).is_ok()
}

fn hello_with(keys: &PairingKeys, profile: u64, pairing_id: [u8; 16], mode: u64) -> Vec<u8> {
    let (_, ek) = XWingDecapsKey::generate().unwrap();
    let commit = crypto::nonce_commitment(&PairNonce::generate().unwrap()).unwrap();
    let enc = |e: &mut qv_encoding::Encoder| {
        e.text("qv/lan-pair-hello/v2");
        e.uint(profile);
        e.bytes(&pairing_id);
        e.uint(mode);
        e.uint(u64::from(mode == 1));
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
        let other = PairingKeys::new(PairingSecret::from_bytes(&[9; 16]).unwrap()).unwrap();
        let mut bad = vec![
            hello_with(&keys, 1, id, 0),
            hello_with(&keys, 2, [0; 16], 0),
            hello_with(&keys, 2, id, 2),
            hello_with(&other, 2, id, 0),
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

/// Test-only channel adapter to script hostile traffic on either epoch. There
/// is no such union or key fallback in the product record layer.
enum TestEpoch<'c> {
    Initial(V2Channel<'c, InitialEpoch>),
    Final(V2Channel<'c>),
}
struct Channel<'c>(Option<TestEpoch<'c>>);
impl<'c> Channel<'c> {
    fn send(&mut self, msg: &[u8], t: Duration) -> Result<(), LanError> {
        match self.0.as_mut().unwrap() {
            TestEpoch::Initial(c) => c.send(msg, t),
            TestEpoch::Final(c) => c.send(msg, t),
        }
    }
    fn recv(&mut self, t: Duration, cap: Option<Instant>) -> Result<SecretBytes, LanError> {
        match self.0.as_mut().unwrap() {
            TestEpoch::Initial(c) => c.recv(t, cap),
            TestEpoch::Final(c) => c.recv(t, cap),
        }
    }
    fn finish(&mut self, keys: TrafficKeys<FinalEpoch>) {
        let Some(TestEpoch::Initial(ch)) = self.0.take() else {
            panic!("expected initial epoch")
        };
        self.0 = Some(TestEpoch::Final(ch.finish(keys).unwrap()));
    }
    fn final_channel(&mut self) -> &mut V2Channel<'c> {
        let Some(TestEpoch::Final(ch)) = self.0.as_mut() else {
            panic!("expected final epoch")
        };
        ch
    }
}
struct Manual<'c> {
    ch: Channel<'c>,
    hello: Vec<u8>,
    th: [u8; 32],
    schedule: Option<OuterSchedule>,
}
fn manual_outer<'c>(
    addr: SocketAddr,
    keys: &PairingKeys,
    mode: AuthMode,
) -> (Manual<'c>, PairNonce) {
    let nonce = PairNonce::generate().unwrap();
    let (dk, ek) = XWingDecapsKey::generate().unwrap();
    let attempt = join_attempt(keys, mode, nonce, dk, &ek).unwrap();
    let mut conn = Conn::new(TcpStream::connect(addr).unwrap(), &never).unwrap();
    conn.within(Duration::from_secs(10), None);
    conn.send_frame(FramePhase::Handshake, &attempt.hello)
        .unwrap();
    let mut buf = Vec::new();
    conn.recv_frame(FramePhase::Handshake, &mut buf).unwrap();
    let (ct, accept_hash) = check_accept(keys, mode, &attempt.hash, &buf).unwrap();
    let ss = attempt.dk.decapsulate(&ct).unwrap();
    let th = outer_transcript(mode, &attempt.hash, &accept_hash).unwrap();
    let owned = PairingKeys::new(PairingSecret::from_bytes(keys.secret().expose_secret()).unwrap())
        .unwrap();
    let (schedule, initial) = owned.begin(ss, crypto_mode(mode), th).unwrap();
    let m = Manual {
        ch: Channel(Some(TestEpoch::Initial(V2Channel::initial(
            conn,
            initial,
            crypto::Role::Joiner,
        )))),
        hello: attempt.hello.to_vec(),
        th,
        schedule: Some(schedule),
    };
    (m, attempt.nonce)
}

fn manual<'c>(
    addr: SocketAddr,
    keys: &PairingKeys,
    mode: JoinMode,
    reveal: Option<[u8; 32]>,
) -> Manual<'c> {
    let mode = if mode == JoinMode::NewDevice {
        AuthMode::PasswordEnrollment
    } else {
        AuthMode::KeySync
    };
    let (mut m, nonce) = manual_outer(addr, keys, mode);
    let th = m.th;
    if mode == AuthMode::PasswordEnrollment {
        let password = pw(PASSWORD);
        let (client, ke1) = PasswordAuthClient::start(&password, &th).unwrap();
        let r = PakeStart {
            nonce: reveal.unwrap_or(*nonce.expose_secret()),
            ke1: ke1.expose_secret().try_into().unwrap(),
        }
        .encode()
        .unwrap();
        m.ch.send(&r, Duration::from_secs(10)).unwrap();
        if reveal.is_some() {
            return m;
        }
        let s = m.ch.recv(Duration::from_secs(60), None).unwrap();
        let response = PakeResponse::decode(s.expose_secret()).unwrap();
        let (ke3, auth) = client.finish(&password, response.ke2).unwrap();
        let f = PakeFinish {
            ke3: ke3.expose_secret().try_into().unwrap(),
        }
        .encode()
        .unwrap();
        let ta = auth_transcript(mode, &th, &r, s.expose_secret(), Some(&f)).unwrap();
        m.ch.send(&f, Duration::from_secs(10)).unwrap();
        let (keys, finished) = m.schedule.take().unwrap().complete(auth, ta).unwrap();
        m.ch.finish(keys);
        m.ch.send(
            &Finished {
                mac: finished.tag().unwrap().as_bytes(),
            }
            .encode()
            .unwrap(),
            Duration::from_secs(10),
        )
        .unwrap();
        m.ch.final_channel().begin_exchange();
    }
    m
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_enroll_admission_is_closed_before_approval_and_later_connections_cannot_interrupt() {
    let a = Device::personal();
    let b = Dir::new();
    let private = private_dir(&b);
    let (w, addr, code) = window();
    let keys = keys_of(&code);
    let racer = hello_with(&keys, 2, *keys.pairing_id(), 0);
    let mut approve = Approve::yes();
    approve.before = Some(Box::new(move || {
        // Even another valid code holder cannot reach a surviving listener.
        // In parallel: Windows retries a refused loopback connect, so each
        // attempt runs its full 1 s timeout, and 22 in a row would outlast
        // the confirmation window.
        std::thread::scope(|s| {
            let closed = s.spawn(|| TcpStream::connect_timeout(&addr, Duration::from_secs(1)));
            let racer = s.spawn(|| poke(addr, &racer));
            let junk: Vec<_> = (0..20).map(|_| s.spawn(|| poke(addr, b"junk"))).collect();
            assert!(closed.join().unwrap().is_err());
            assert!(!racer.join().unwrap());
            for poke in junk {
                assert!(!poke.join().unwrap());
            }
        });
    }));
    let mut join = Join::yes();
    let (approved, received) = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut approve, &fast(), &never));
        let received = join_new_device(
            JoinCode::from_manual(&code).unwrap(),
            &[addr],
            LOOPBACK,
            &private,
            &mut join,
            &fast(),
            &never,
        );
        (h.join().unwrap(), received)
    });
    let (confirmed, failure) = joined(approved.unwrap());
    assert!(confirmed, "{failure:?}");
    assert!(received.is_ok());
    assert!(TcpStream::connect_timeout(&addr, Duration::from_secs(1)).is_err());
    assert_eq!(a.links(), 0);
}

#[test]
fn lan_enroll_identical_replayed_hello_finds_no_listener() {
    let a = Device::personal();
    let (w, addr, code) = window();
    let keys = keys_of(&code);
    let stopped = AtomicBool::new(false);
    let cancel = || stopped.load(Ordering::SeqCst);
    let approved = std::thread::scope(|s| {
        let h = s.spawn(|| w.run(&a, &mut Approve::yes(), &fast(), &cancel));
        let m = manual(addr, &keys, JoinMode::Sync, None);
        assert!(!poke(addr, &m.hello));
        assert!(TcpStream::connect(addr).is_err());
        stopped.store(true, Ordering::SeqCst);
        h.join().unwrap()
    });
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
    assert_eq!(approved.unwrap_err(), LanError::Integrity);
    assert!(approve.seen.is_none());
    assert_eq!(
        m.ch.recv(Duration::from_secs(5), None).err(),
        Some(LanError::Timeout)
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
    assert_eq!(joined.unwrap_err(), LanError::Timeout);
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
    // Without KE3/FinishedB A can never authorize a grant, even if its user
    // approves the comparison after B cancelled locally.
    assert!(approved.is_err());
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
        fn password(&mut self, sas: &Sas, name: &[u8], _: bool) -> Option<MasterPassword> {
            self.confirm(sas, name).then(|| pw(PASSWORD))
        }
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
            let g = wire::PairGrant::decode(grant.expose_secret()).unwrap();
            let (vault, generation) = (g.vault_id, g.generation);
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
                        m.ch.final_channel().conn.close();
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
    let parsed = qv_protocol::oob::decode_qr_v2(&qr).unwrap();
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
    let qr2 = qv_protocol::oob::encode_qr(LanProfile::V2, &[1; 16], &[], "").unwrap();
    let mut raw = qr2.to_vec();
    let pos = 2 + qv_protocol::oob::QR_LABEL_V2.len();
    raw[pos] = 3;
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

/// Authenticated outer acceptance for hostile-emitter scripts.
fn accept_initial<'c>(
    stream: TcpStream,
    keys: PairingKeys,
) -> (
    Channel<'c>,
    OuterSchedule,
    super::steps_v2::CheckedHello,
    [u8; 32],
) {
    let mut conn = Conn::new(stream, &never).unwrap();
    conn.within(Duration::from_secs(10), None);
    let mut buf = Vec::new();
    conn.recv_frame(FramePhase::Handshake, &mut buf).unwrap();
    let hello = super::steps_v2::check_hello(&keys, &buf).ok().unwrap();
    let (ss, ct) = hello.ek.encapsulate().unwrap();
    let (accept, hash) = super::steps_v2::accept_for(&keys, &hello, [5; 32], &ct).unwrap();
    conn.send_frame(FramePhase::Handshake, &accept).unwrap();
    let th = outer_transcript(hello.mode, &hello.hash, &hash).unwrap();
    let (schedule, keys) = keys.begin(ss, crypto_mode(hello.mode), th).unwrap();
    (
        Channel(Some(TestEpoch::Initial(V2Channel::initial(
            conn,
            keys,
            crypto::Role::Offerer,
        )))),
        schedule,
        hello,
        th,
    )
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
    let keys = PairingKeys::new(secret).unwrap();
    let b = Dir::new();
    let private = b.join("private");
    qv_store::create_private_dirs(&private).unwrap();
    std::thread::scope(|s| {
        s.spawn(|| {
            let (stream, _) = listener.accept().unwrap();
            let (mut ch, schedule, _, th) = accept_initial(stream, keys);
            let t = Duration::from_secs(10);
            let r = ch.recv(t, None).unwrap();
            let start = PakeStart::decode(r.expose_secret()).unwrap();
            let (server, ke2, authorization) = a
                .authenticate_password(pw(PASSWORD), &th, start.ke1)
                .unwrap();
            let response = PakeResponse {
                ke2: ke2.expose_secret().try_into().unwrap(),
            }
            .encode()
            .unwrap();
            ch.send(&response, t).unwrap();
            let f = ch.recv(t, None).unwrap();
            let finish = PakeFinish::decode(f.expose_secret()).unwrap();
            let auth = server.finish(finish.ke3).unwrap();
            let ta = auth_transcript(
                AuthMode::PasswordEnrollment,
                &th,
                r.expose_secret(),
                &response,
                Some(f.expose_secret()),
            )
            .unwrap();
            let (keys, finished) = schedule.complete(auth, ta).unwrap();
            ch.finish(keys);
            let message = ch.recv(t, None).unwrap();
            let done = Finished::decode(message.expose_secret()).unwrap();
            finished
                .verify(&qv_crypto::MacTag::from_bytes(*done.mac))
                .unwrap();
            let SealedGrant::Ready(record) = a
                .authorized_grant(authorization, &mut ch.final_channel().sealer)
                .unwrap()
            else {
                panic!("expected ready grant")
            };
            ch.final_channel().send_sealed(&record, t).unwrap();
            ch.final_channel().begin_exchange();
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
        ch.send(&wire::ErrorMsg::encode(ErrorCode::Cancelled).unwrap(), t)
            .unwrap();
    });
    assert_eq!(e, LanError::PeerCancelled);
}

#[path = "sync_tests.rs"]
mod sync;

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_auth_code_holder_with_a_wrong_password_cannot_forge_a_finish_or_reuse_admission() {
    let a = Device::personal();
    let (w, addr, code) = window();
    let keys = keys_of(&code);
    let (approved, observed) = std::thread::scope(|scope| {
        let h = scope.spawn(|| w.run(&a, &mut Approve::yes(), &fast(), &never));
        let (mut m, nonce) = manual_outer(addr, &keys, AuthMode::PasswordEnrollment);
        let wrong = pw("attacker supplied guess");
        let (client, ke1) = PasswordAuthClient::start(&wrong, &m.th).unwrap();
        let r = PakeStart {
            nonce: *nonce.expose_secret(),
            ke1: ke1.expose_secret().try_into().unwrap(),
        }
        .encode()
        .unwrap();
        m.ch.send(&r, Duration::from_secs(10)).unwrap();
        let s = m.ch.recv(Duration::from_secs(60), None).unwrap();
        let response = PakeResponse::decode(s.expose_secret()).unwrap();
        assert!(client.finish(&wrong, response.ke2).is_err());
        // A custom receiver can ignore its own failed password prompt, but a
        // forged KE3 still cannot authenticate to A or derive the final keys.
        m.ch.send(
            &PakeFinish { ke3: &[71; 64] }.encode().unwrap(),
            Duration::from_secs(10),
        )
        .unwrap();
        let observed = m.ch.recv(Duration::from_secs(10), None);
        (h.join().unwrap(), observed)
    });
    assert_eq!(approved.unwrap_err(), LanError::Integrity);
    assert_eq!(observed.err(), Some(LanError::Timeout));
    assert!(
        TcpStream::connect(addr).is_err(),
        "a failed credential attempt spends the code"
    );
}

// 0012 §1: LAN discovery mistaken for trust
#[test]
fn lan_auth_correct_ke3_without_valid_final_finished_releases_no_grant_or_data() {
    for omit in [false, true] {
        let a = Device::personal();
        let (w, addr, code) = window();
        let keys = keys_of(&code);
        let (approved, observed) = std::thread::scope(|scope| {
            let h = scope.spawn(|| w.run(&a, &mut Approve::yes(), &fast(), &never));
            let (mut m, nonce) = manual_outer(addr, &keys, AuthMode::PasswordEnrollment);
            let password = pw(PASSWORD);
            let (client, ke1) = PasswordAuthClient::start(&password, &m.th).unwrap();
            let r = PakeStart {
                nonce: *nonce.expose_secret(),
                ke1: ke1.expose_secret().try_into().unwrap(),
            }
            .encode()
            .unwrap();
            m.ch.send(&r, Duration::from_secs(10)).unwrap();
            let s = m.ch.recv(Duration::from_secs(60), None).unwrap();
            let response = PakeResponse::decode(s.expose_secret()).unwrap();
            let (ke3, auth) = client.finish(&password, response.ke2).unwrap();
            drop(password);
            let f = PakeFinish {
                ke3: ke3.expose_secret().try_into().unwrap(),
            }
            .encode()
            .unwrap();
            let ta = auth_transcript(
                AuthMode::PasswordEnrollment,
                &m.th,
                &r,
                s.expose_secret(),
                Some(&f),
            )
            .unwrap();
            m.ch.send(&f, Duration::from_secs(10)).unwrap();
            let (keys, finished) = m.schedule.take().unwrap().complete(auth, ta).unwrap();
            m.ch.finish(keys);
            if !omit {
                let mut mac = *finished.tag().unwrap().as_bytes();
                mac[0] ^= 1;
                m.ch.send(
                    &Finished { mac: &mac }.encode().unwrap(),
                    Duration::from_secs(10),
                )
                .unwrap();
            }
            let observed = m.ch.recv(Duration::from_secs(10), None);
            (h.join().unwrap(), observed)
        });
        assert_eq!(
            approved.unwrap_err(),
            if omit {
                LanError::Timeout
            } else {
                LanError::Integrity
            }
        );
        assert_eq!(observed.err(), Some(LanError::Timeout));
        assert!(TcpStream::connect(addr).is_err());
    }
}
