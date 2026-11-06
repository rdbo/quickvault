// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN sync in the app (0013; plans 0038 step 9, 0042 step 8), through
//! qv-core only.
//!
//! A LAN operation runs on the single vault worker and blocks there: a
//! one-use sync window, a sync from another device's code, or a new-device
//! join from the locked screen. Nothing about the other device is stored.
//! What it shows and asks lives in one [`LanRun`] in the controller state:
//! - the code (a protected copy, shown only while the window runs);
//! - endpoints and the countdown;
//! - the current question;
//! - the final outcome.
//!
//! The worker posts a question and waits on a condition variable. The
//! renderer answers through [`Controller::lan_answer`] and the other `lan_*`
//! methods, which work while the worker is busy, because the worker is
//! waiting for exactly that answer. Every wait ends on cancel and on lock
//! (lock closes the run), so no prompt outlives its session (0037 found
//! that core cannot interrupt a prompt).
//!
//! Only a listening window with no unanswered question defers idle locking,
//! until its absolute expiry. Prompts and initiated operations use the normal
//! inactivity timeout. Callback waits enforce it even without renderer polling.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::time::{Duration, Instant};

use qv_core::{
    ApproverUi, CancelToken, JoinCode, JoinerUi, ListenScope, LocalAcceptance, MasterPassword,
    PAIRING_WINDOW_MAX, Sas, SecretBytes, Served, Session, SyncOptions, SyncReport,
    SyncWindowOptions,
};
use zeroize::Zeroize;

use crate::controller::{AppError, Controller, FormEpoch, State};
use crate::workspace::{Apply, WsField, protect};

/// Which LAN operation runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LanKind {
    /// A one-use sync window: this device shows a code.
    Window,
    /// A sync with another device's code, started here.
    Sync,
    /// Joining as a new device (locked screen).
    Join,
}

/// What the running operation asks the user. Only the comparison code and
/// the vault's name are shown; nothing else from the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Question {
    /// Offering device: a new device asks to join; do both screens show `sas`?
    Approve {
        /// The comparison code, `123 456`.
        sas: String,
        /// This vault's name (escaped by the renderer).
        vault: String,
    },
    /// New device: join the vault named `vault`?
    JoinVault {
        /// The received vault's name.
        vault: String,
        /// The comparison code.
        sas: String,
    },
    /// New device: the joined vault's master password.
    Password {
        /// A previous attempt was wrong.
        retry: bool,
    },
}

/// A finished operation: fixed lines and an optional error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanDone {
    /// Result lines (fixed text and counts).
    pub lines: Vec<String>,
    /// The failure, if it failed.
    pub error: Option<AppError>,
}

#[derive(Default)]
struct Slot {
    answer: Option<bool>,
    password: Option<MasterPassword>,
    closed: bool,
}

struct Reply {
    slot: Mutex<Slot>,
    cv: Condvar,
}

/// The running (or finished) LAN operation.
pub(crate) struct LanRun {
    kind: LanKind,
    code: Option<SecretBytes>,
    qr: Option<crate::qr::Symbol>,
    endpoints: Vec<String>,
    expires: Option<Instant>,
    info: Option<String>,
    question: Option<Question>,
    done: Option<LanDone>,
    /// A password typed for [`Question::Password`], until submitted.
    typed: Option<SecretBytes>,
    reply: Arc<Reply>,
    cancel: CancelToken,
}

impl LanRun {
    fn new(kind: LanKind) -> Self {
        Self {
            kind,
            code: None,
            qr: None,
            endpoints: Vec::new(),
            expires: None,
            info: None,
            question: None,
            done: None,
            typed: None,
            reply: Arc::new(Reply {
                slot: Mutex::new(Slot::default()),
                cv: Condvar::new(),
            }),
            cancel: CancelToken::new(),
        }
    }

    /// Cancels the operation and ends every wait (lock, cancel, dismiss).
    pub(crate) fn close(&mut self) {
        self.cancel.cancel();
        let mut slot = self
            .reply
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        slot.closed = true;
        slot.password = None;
        self.reply.cv.notify_all();
        drop(slot);
        self.code = None;
        self.qr = None;
        self.typed = None;
        self.question = None;
    }

    /// Whether the operation is still running: until its outcome exists,
    /// including while a cancel takes effect.
    pub(crate) fn running(&self) -> bool {
        self.done.is_none()
    }

    /// Only bounded listeners without a pending question defer idle locking.
    pub(crate) fn defers_idle(&self) -> bool {
        self.running()
            && !self.cancel.is_cancelled()
            && self.kind == LanKind::Window
            && self.question.is_none()
            && self.expires.is_some_and(|t| Instant::now() < t)
    }

    /// Seconds left before the window closes by itself; 0 when none.
    pub(crate) fn seconds(&self) -> u64 {
        self.expires.map_or(0, |t| {
            if self.done.is_some() {
                return 0;
            }
            let left = t.saturating_duration_since(Instant::now());
            left.as_secs() + u64::from(left.subsec_nanos() > 0)
        })
    }
}

/// Renderer view of the LAN operation.
pub struct LanView {
    /// The operation.
    pub kind: LanKind,
    /// The code while the window runs (a protected copy).
    pub code: Option<SecretBytes>,
    /// The protected binary QR symbol, only while its window runs.
    pub qr: Option<crate::qr::Symbol>,
    /// This device's endpoints for the other device to type.
    pub endpoints: Vec<String>,
    /// Seconds left in the window.
    pub seconds: u64,
    /// Progress text.
    pub info: Option<String>,
    /// The question waiting for an answer.
    pub question: Option<Question>,
    /// The outcome once finished.
    pub done: Option<LanDone>,
}

/// Only tests listen on and dial loopback (0013 §1.4); the app never does.
#[cfg(test)]
pub(crate) static TEST_LOOPBACK: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn loopback() -> bool {
    #[cfg(test)]
    {
        TEST_LOOPBACK.load(std::sync::atomic::Ordering::SeqCst)
    }
    #[cfg(not(test))]
    {
        false
    }
}

fn scope() -> ListenScope {
    if loopback() {
        ListenScope::LoopbackForTests
    } else {
        ListenScope::AllInterfaces
    }
}

fn addresses() -> Vec<IpAddr> {
    if loopback() {
        vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
    } else {
        qv_core::local_addresses()
    }
}

/// The worker's side: posts what the run shows and waits for answers.
struct Bridge {
    c: Controller,
    generation: u64,
    reply: Arc<Reply>,
}

impl Bridge {
    /// Registers `run` as the current LAN operation of this lock generation.
    fn start(c: &Controller, run: LanRun) -> Result<(Self, CancelToken), AppError> {
        let mut s = c.state();
        let reply = run.reply.clone();
        let cancel = run.cancel.clone();
        if let Some(ws) = s.workspace.as_mut() {
            ws.inputs.remove(&WsField::LanCode);
            ws.inputs.remove(&WsField::LanEndpoint);
            ws.lan_scanned = false;
        }
        if let Some(mut old) = s.lan.replace(run) {
            old.close();
        }
        s.revision = s.revision.wrapping_add(1);
        Ok((
            Self {
                c: c.clone(),
                generation: s.lock_gen,
                reply,
            },
            cancel,
        ))
    }

    fn update(&self, f: impl FnOnce(&mut LanRun)) {
        let mut s = self.c.state();
        if s.lock_gen != self.generation {
            return;
        }
        if let Some(run) = s.lan.as_mut() {
            f(run);
        }
        s.revision = s.revision.wrapping_add(1);
    }

    /// Checks callback lifetime without holding the reply mutex. No network or
    /// callback event manufactures user activity while a question is pending.
    fn waiting(&self) -> bool {
        let mut s = self.c.state();
        if s.lock_gen != self.generation {
            return false;
        }
        let idle = s.active.elapsed() >= Duration::from_secs(60);
        let Some(run) = s.lan.as_mut() else {
            return false;
        };
        if run.expires.is_some_and(|t| Instant::now() >= t) {
            run.close();
            return false;
        }
        if idle {
            drop(s);
            self.c.lock();
            return false;
        }
        true
    }

    /// Posts `q` and waits until `take` yields an answer; `None` on cancel or
    /// lock.
    fn ask<T>(&self, q: Question, take: impl Fn(&mut Slot) -> Option<T>) -> Option<T> {
        {
            let mut slot = self
                .reply
                .slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            slot.answer = None;
            slot.password = None;
        }
        self.update(|r| r.question = Some(q));
        let out = self.wait(take);
        self.update(|r| {
            r.question = None;
            r.typed = None;
        });
        out
    }

    fn wait<T>(&self, take: impl Fn(&mut Slot) -> Option<T>) -> Option<T> {
        let mut slot = self
            .reply
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        loop {
            if slot.closed {
                return None;
            }
            if let Some(v) = take(&mut slot) {
                return Some(v);
            }
            let (next, _) = self
                .reply
                .cv
                .wait_timeout(slot, Duration::from_millis(250))
                .unwrap_or_else(PoisonError::into_inner);
            slot = next;
            drop(slot);
            if !self.waiting() {
                return None;
            }
            slot = self
                .reply
                .slot
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
        }
    }

    fn answer(&self, q: Question) -> bool {
        self.ask(q, |s| s.answer.take()).unwrap_or(false)
    }
}

fn grouped(digits: &[u8]) -> String {
    let d: String = digits.iter().map(|b| char::from(*b)).collect();
    match (d.get(..3), d.get(3..)) {
        (Some(a), Some(b)) => format!("{a} {b}"),
        _ => d,
    }
}

impl ApproverUi for Bridge {
    fn confirm(&mut self, sas: &str, vault_name: &str) -> bool {
        self.answer(Question::Approve {
            sas: grouped(sas.as_bytes()),
            vault: vault_name.to_owned(),
        })
    }
}

/// The new device's UI.
struct JoinBridge {
    bridge: Bridge,
    attempts: usize,
}

impl JoinerUi for JoinBridge {
    fn show_code(&mut self, sas: &Sas) -> bool {
        let sas = grouped(&sas.digits());
        self.bridge.update(|r| {
            r.info = Some(format!(
                "Comparison code {sas}: check that the other device shows the same code. Receiving the vault…"
            ))
        });
        true
    }

    fn confirm_vault(&mut self, vault_name: &[u8], sas: &Sas) -> bool {
        self.bridge.answer(Question::JoinVault {
            vault: String::from_utf8_lossy(vault_name).into_owned(),
            sas: grouped(&sas.digits()),
        })
    }

    fn master_password(&mut self) -> Option<MasterPassword> {
        let retry = self.attempts > 0;
        self.attempts += 1;
        self.bridge
            .ask(Question::Password { retry }, |s| s.password.take())
    }
}

fn round_lines(r: &SyncReport, lines: &mut Vec<String>) {
    lines.push(
        match r.local {
            LocalAcceptance::Committed => "This device accepted the other device's changes.",
            LocalAcceptance::Unchanged => "Nothing new from the other device.",
        }
        .to_owned(),
    );
    lines.push(format!("Unresolved conflicts: {}", r.conflicts));
    lines.push(
        if r.peer_confirmed {
            "The other device confirmed receipt."
        } else {
            "The other device did not confirm receipt; sync again later."
        }
        .to_owned(),
    );
}

/// Keep local acceptance visible even when completion or acknowledgement failed.
pub(crate) fn round_done(r: &SyncReport, mut lines: Vec<String>) -> LanDone {
    round_lines(r, &mut lines);
    LanDone {
        lines,
        error: r.completion_error.map(AppError::from),
    }
}

/// The finishing effect: stores the outcome, ends the run's secrets.
fn finish(generation: u64, done: LanDone) -> Apply {
    Box::new(move |s: &mut State| {
        if s.lock_gen != generation {
            return;
        }
        if let Some(run) = s.lan.as_mut() {
            run.code = None;
            run.qr = None;
            run.question = None;
            run.typed = None;
            run.expires = None;
            run.done = Some(done);
        }
        s.revision = s.revision.wrapping_add(1);
    })
}

fn outcome(result: Result<LanDone, AppError>) -> LanDone {
    match result {
        Ok(done) => done,
        Err(error) => LanDone {
            lines: Vec::new(),
            error: Some(error),
        },
    }
}

/// The code and endpoints of the Devices form, consumed by this action.
struct Inputs {
    code: SecretBytes,
    endpoints: Vec<SocketAddr>,
}

fn inputs(c: &Controller, epoch: FormEpoch) -> Result<Inputs, AppError> {
    c.with_ws(epoch, |ws, _| {
        let result = (|| {
            let v = ws.input(WsField::LanCode);
            if v.is_empty() {
                return Err(AppError::InvalidInput);
            }
            let code = protect(v)?;
            let typed = ws.text(WsField::LanEndpoint)?.to_owned();
            let endpoints = if typed.is_empty() {
                // A scanned code may carry its own candidates; a typed code
                // without an address is refused by the session (no peer).
                Vec::new()
            } else {
                vec![qv_core::parse_endpoint(&typed).map_err(|_| AppError::InvalidInput)?]
            };
            if endpoints.is_empty()
                && !qv_core::inspect_lan_qr(code.expose_secret())
                    .is_ok_and(|q| !q.endpoints.is_empty())
            {
                return Err(AppError::InvalidInput);
            }
            Ok(Inputs { code, endpoints })
        })();
        // The code and address belong to this explicit action only.
        ws.inputs.remove(&WsField::LanCode);
        ws.inputs.remove(&WsField::LanEndpoint);
        ws.lan_scanned = false;
        result
    })
    .ok_or(AppError::InvalidInput)?
}

fn join_code(code: &SecretBytes) -> Result<JoinCode, AppError> {
    if let Ok(code) = JoinCode::from_qr(code.expose_secret()) {
        return Ok(code);
    }
    let text = std::str::from_utf8(code.expose_secret()).map_err(|_| AppError::InvalidInput)?;
    JoinCode::from_manual(text).map_err(|_| AppError::InvalidInput)
}

/// Opens a one-use sync window and serves one sync or one new device.
pub(crate) fn offer(c: &Controller, epoch: FormEpoch) -> Result<(), AppError> {
    c.run_op(epoch, None, move |s, _, ctl| {
        let window = s.open_sync_window(SyncWindowOptions {
            scope: scope(),
            limit: PAIRING_WINDOW_MAX,
            ..SyncWindowOptions::new()
        })?;
        let addrs = addresses();
        let code = window.code(&addrs)?;
        let mut run = LanRun::new(LanKind::Window);
        run.qr = Some(crate::qr::encode(code.qr.expose_secret())?);
        run.code = Some(code.manual);
        run.endpoints = addrs
            .iter()
            .map(|ip| SocketAddr::new(*ip, code.port).to_string())
            .collect();
        if run.endpoints.is_empty() {
            run.info = Some(format!(
                "No local address was found. Give the other device this device's IP address with port {}.",
                code.port
            ));
        }
        run.expires = Some(window.expires_at());
        let (mut bridge, cancel) = Bridge::start(ctl, run)?;
        let generation = bridge.generation;
        let result = window
            .run(s, &mut bridge, Some(&cancel))
            .map_err(AppError::from)
            .map(|served| match served {
                Served::Synced(r) => {
                    round_done(&r, vec!["Synced with a device that holds this vault.".to_owned()])
                }
                Served::Joined {
                    peer_confirmed,
                    failure,
                } => LanDone {
                    lines: vec![
                        if peer_confirmed {
                            "A new device joined this vault."
                        } else {
                            "The new device may not have finished joining."
                        }
                        .to_owned(),
                    ],
                    error: failure.map(|e| AppError::from(qv_core::CoreError::Lan(e))),
                },
            });
        Ok(finish(generation, outcome(result)))
    })
}

/// One sync with the code in the form (0014 §6.2, §6.4).
pub(crate) fn sync(c: &Controller, epoch: FormEpoch) -> Result<(), AppError> {
    let i = inputs(c, epoch)?;
    let code = join_code(&i.code)?;
    c.run_op(epoch, None, move |s, _, ctl| {
        let (bridge, cancel) = Bridge::start(ctl, LanRun::new(LanKind::Sync))?;
        bridge.update(|r| r.info = Some("Syncing…".to_owned()));
        let result = s
            .sync_with_code(
                code,
                SyncOptions {
                    extra_endpoints: i.endpoints,
                    allow_loopback: loopback(),
                    ..SyncOptions::default()
                },
                Some(&cancel),
            )
            .map_err(AppError::from)
            .map(|r| round_done(&r, Vec::new()));
        Ok(finish(bridge.generation, outcome(result)))
    })
}

/// The new-device join of the locked screen: receives and verifies the
/// vault, asks to confirm it and for its master password, creates it at
/// `path`, and returns the unlocked session (runs on the vault worker).
pub(crate) fn join_new_device(
    c: &Controller,
    core: &qv_core::Core,
    path: &std::path::Path,
    code: &SecretBytes,
    endpoint: &[u8],
) -> Result<Session, AppError> {
    let code = join_code(code)?;
    let endpoints = if endpoint.is_empty() {
        Vec::new()
    } else {
        vec![
            std::str::from_utf8(endpoint)
                .ok()
                .and_then(|e| qv_core::parse_endpoint(e).ok())
                .ok_or(AppError::InvalidInput)?,
        ]
    };
    let (bridge, cancel) = Bridge::start(c, LanRun::new(LanKind::Join))?;
    let mut ui = JoinBridge {
        bridge,
        attempts: 0,
    };
    let session = core.join_new_device(
        code,
        path,
        SyncOptions {
            extra_endpoints: endpoints,
            allow_loopback: loopback(),
            ..SyncOptions::default()
        },
        &mut ui,
        Some(&cancel),
    );
    // The locked screen's run ends with the attempt; an error shows there.
    let mut s = c.state();
    if s.lock_gen == ui.bridge.generation
        && let Some(mut run) = s.lan.take()
    {
        run.close();
    }
    Ok(session?)
}

impl Controller {
    /// Whether the Devices form holds a scanned code (shown only as such).
    pub fn lan_scanned(&self, epoch: FormEpoch) -> bool {
        self.peek(epoch, |ws| ws.lan_scanned).unwrap_or(false)
    }

    /// The LAN operation's renderer view, for the current epoch's session or
    /// the locked screen.
    pub fn lan_view(&self, epoch: FormEpoch) -> Option<LanView> {
        let mut s = self.state();
        if s.epoch != epoch.0 {
            return None;
        }
        let run = s.lan.as_mut()?;
        if run.expires.is_some_and(|end| Instant::now() >= end) {
            run.code = None;
            run.qr = None;
            run.typed = None;
        }
        Some(LanView {
            kind: run.kind,
            code: run
                .code
                .as_ref()
                .and_then(|c| protect(c.expose_secret()).ok()),
            qr: run.qr.as_ref().and_then(|q| q.copy().ok()),
            endpoints: run.endpoints.clone(),
            seconds: run.seconds(),
            info: run.info.clone(),
            question: run.question.clone(),
            done: run.done.clone(),
        })
    }

    /// Answers the current yes/no question. Works while the worker waits for
    /// it; anything stale is ignored.
    pub fn lan_answer(&self, epoch: FormEpoch, yes: bool) {
        let mut s = self.state();
        if s.epoch != epoch.0 {
            return;
        }
        s.active = Instant::now();
        let Some(run) = s.lan.as_mut() else {
            return;
        };
        let password = match &run.question {
            Some(Question::Password { .. }) if yes => {
                let typed = run.typed.take();
                match typed.map(|t| MasterPassword::from_utf8(t.expose_secret())) {
                    Some(Ok(p)) => Some(p),
                    _ => return,
                }
            }
            Some(_) => None,
            None => return,
        };
        let mut slot = run
            .reply
            .slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        match (password, yes) {
            (Some(p), _) => slot.password = Some(p),
            (None, _) if matches!(run.question, Some(Question::Password { .. })) => {
                // Refusing the password prompt cancels the join.
                slot.closed = true;
            }
            (None, yes) => slot.answer = Some(yes),
        }
        run.reply.cv.notify_all();
    }

    /// Takes a typed password for [`Question::Password`] into protected
    /// state, clearing the framework string.
    pub fn lan_secret(&self, epoch: FormEpoch, value: &mut String) {
        {
            let mut s = self.state();
            if s.epoch == epoch.0
                && value.len() <= crate::workspace::LINE_MAX
                && let Some(run) = s.lan.as_mut()
                && matches!(run.question, Some(Question::Password { .. }))
            {
                run.typed = protect(value.as_bytes()).ok();
                s.active = Instant::now();
            }
        }
        value.zeroize();
        value.clear();
    }

    /// Cancels the running operation; it ends within ~100 ms (a window) or at
    /// its next step.
    pub fn lan_cancel(&self, epoch: FormEpoch) {
        let mut s = self.state();
        if s.epoch != epoch.0 {
            return;
        }
        s.active = Instant::now();
        if let Some(run) = s.lan.as_mut()
            && run.done.is_none()
        {
            run.close();
            run.info = Some("Cancelling…".to_owned());
            s.revision = s.revision.wrapping_add(1);
        }
    }

    /// Dismisses a finished operation's outcome.
    pub fn lan_dismiss(&self, epoch: FormEpoch) {
        let mut s = self.state();
        if s.epoch != epoch.0 {
            return;
        }
        s.active = Instant::now();
        if s.lan.as_ref().is_some_and(|r| r.done.is_some())
            && let Some(mut run) = s.lan.take()
        {
            run.close();
            s.revision = s.revision.wrapping_add(1);
        }
    }
}

/// A core peer for the synthetic Linux WebKit flow (plan 0038 step 9).
/// No production or Android build includes this fixture command.
#[cfg(all(feature = "validation", target_os = "linux"))]
pub(crate) mod fixture {
    use super::*;
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicBool, Ordering};

    static STARTED: AtomicBool = AtomicBool::new(false);
    static COMPLETE: OnceLock<bool> = OnceLock::new();

    pub(crate) fn complete() -> bool {
        COMPLETE.get() == Some(&true)
    }

    pub(crate) fn start(controller: &Controller) {
        if !controller.is_fixture() || STARTED.swap(true, Ordering::SeqCst) {
            return;
        }
        let controller = controller.clone();
        std::thread::spawn(move || {
            let result = join(&controller);
            if let Err(error) = result {
                eprintln!("synthetic LAN peer failed: {error:?}");
            }
            let ok = result.is_ok();
            let _ = COMPLETE.set(ok);
            if ok {
                progress(&controller, "Synthetic peer opened the vault.");
            }
        });
    }

    fn progress(controller: &Controller, text: &str) {
        let mut s = controller.state();
        if let Some(run) = s.lan.as_mut() {
            run.info = Some(text.to_owned());
            s.revision = s.revision.wrapping_add(1);
        }
    }

    fn join(controller: &Controller) -> Result<(), AppError> {
        let (code, endpoint, cancel, epoch) = {
            let s = controller.state();
            let run = s.lan.as_ref().ok_or(AppError::InvalidInput)?;
            if run.kind != LanKind::Window || !run.running() {
                return Err(AppError::InvalidInput);
            }
            let code = join_code(run.code.as_ref().ok_or(AppError::InvalidInput)?)?;
            let endpoint = run
                .endpoints
                .first()
                .and_then(|e| qv_core::parse_endpoint(e).ok())
                .ok_or(AppError::Unavailable)?;
            (code, endpoint, run.cancel.clone(), FormEpoch(s.epoch))
        };
        let base = controller.0.base.join("lan-peer");
        crate::controller::private_dir(&base)?;
        let peer = Controller::new(base.clone(), controller.0.services.clone())?;
        let mut ui = PeerUi {
            controller,
            epoch,
            cancel: &cancel,
            matched: false,
        };
        let session = peer.core()?.join_new_device(
            code,
            &base.join("vaults/peer.qvault"),
            SyncOptions {
                extra_endpoints: vec![endpoint],
                ..SyncOptions::default()
            },
            &mut ui,
            Some(&cancel),
        )?;
        let checked = (|| {
            let overview = session.overview()?;
            Ok::<_, AppError>(
                ui.matched && overview.name.expose() == "Synthetic vault" && overview.entries == 1,
            )
        })();
        session.lock();
        if checked? {
            Ok(())
        } else {
            Err(AppError::InvalidInput)
        }
    }

    struct PeerUi<'a> {
        controller: &'a Controller,
        epoch: FormEpoch,
        cancel: &'a CancelToken,
        matched: bool,
    }

    impl JoinerUi for PeerUi<'_> {
        fn show_code(&mut self, sas: &Sas) -> bool {
            let expected = grouped(&sas.digits());
            let end = Instant::now() + Duration::from_secs(5);
            while !self.cancel.is_cancelled() && Instant::now() < end {
                if let Some(Question::Approve { sas, .. }) = self
                    .controller
                    .lan_view(self.epoch)
                    .and_then(|v| v.question)
                {
                    self.matched = sas == expected;
                    if self.matched {
                        progress(self.controller, "Synthetic peer compared the code.");
                    }
                    return self.matched;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        }

        fn confirm_vault(&mut self, name: &[u8], _: &Sas) -> bool {
            self.matched && name == b"Synthetic vault"
        }

        fn master_password(&mut self) -> Option<MasterPassword> {
            MasterPassword::from_utf8(b"K4L!c8vP2zR9qT7W6nM5").ok()
        }
    }
}

#[cfg(test)]
mod repair_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::controller::Phase;
    use crate::workspace_tests::Env;

    // 0012 §1: LAN partial acceptance
    #[test]
    fn lan_app_wait_expires_clears_secrets_and_idle_locks_without_ui_polling() {
        for idle in [false, true] {
            let env = Env::new();
            let mut run = LanRun::new(LanKind::Window);
            run.expires = Some(Instant::now() + Duration::from_secs(60));
            run.code = Some(protect(b"synthetic pairing secret").unwrap());
            run.typed = Some(protect(b"synthetic password").unwrap());
            run.qr = Some(crate::qr::encode(b"synthetic pairing secret").unwrap());
            let (bridge, _) = Bridge::start(&env.c, run).unwrap();
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::scope(|scope| {
                let h = scope.spawn(|| {
                    tx.send(bridge.answer(Question::Approve {
                        sas: "123 456".to_owned(),
                        vault: "Synthetic vault".to_owned(),
                    }))
                    .unwrap();
                });
                let end = Instant::now() + Duration::from_secs(2);
                loop {
                    let mut s = env.c.state();
                    if s.lan.as_ref().is_some_and(|r| r.question.is_some()) {
                        if idle {
                            s.active = Instant::now() - Duration::from_secs(61);
                        } else {
                            s.lan.as_mut().unwrap().expires =
                                Some(Instant::now() - Duration::from_secs(1));
                        }
                        break;
                    }
                    drop(s);
                    if Instant::now() >= end {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                // No snapshot/render polling: the callback must stop itself.
                let result = rx.recv_timeout(Duration::from_secs(2));
                let s = env.c.state();
                let erased = s
                    .lan
                    .as_ref()
                    .is_none_or(|r| r.code.is_none() && r.typed.is_none() && r.qr.is_none());
                let stopped = s.lan.as_ref().is_none_or(|r| r.cancel.is_cancelled());
                drop(s);
                env.c.lock(); // ensure cleanup even if the regression fails
                h.join().unwrap();
                assert_eq!(result, Ok(false));
                assert!(erased && stopped);
            });
        }
    }

    #[test]
    fn lan_app_only_unexpired_listeners_without_questions_defer_idle_lock() {
        for kind in [LanKind::Window, LanKind::Sync, LanKind::Join] {
            let env = Env::new();
            let mut run = LanRun::new(kind);
            run.expires = Some(Instant::now() + Duration::from_secs(60));
            assert_eq!(run.defers_idle(), kind == LanKind::Window);
            run.question = Some(Question::Password { retry: false });
            assert!(!run.defers_idle());
            run.question = None;
            run.expires = Some(Instant::now() - Duration::from_secs(1));
            assert!(!run.defers_idle());
            Bridge::start(&env.c, run).unwrap();
            {
                let mut s = env.c.state();
                s.phase = Phase::Opening;
                s.active = Instant::now() - Duration::from_secs(61);
            }
            assert_eq!(env.c.snapshot().phase, Phase::Locked);
            assert!(env.c.state().lan.is_none());
        }
    }
}
