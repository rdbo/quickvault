// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN pairing for frontends (0013 §4, §8–10, §12; plan 0037).
//!
//! - [`Session::open_pairing_window`] then [`PairingWindow::run`]: the
//!   approving device. The window's code is shown to the user, and the
//!   call blocks until a pairing completes or the window closes.
//! - [`Core::join_new_device`]: a device without this vault pairs, receives
//!   and verifies the vault, confirms it, checks the master password,
//!   creates the vault at a new path and unlocks it (0013 §10).
//! - [`Session::join_link`]: an unlocked copy of the same vault pairs with
//!   the approver.
//! - [`Session::lan_links`] and [`Session::remove_lan_link`]: local link
//!   management (0013 §12.1).
//! - [`Session::open_receive_window`] then [`ReceiveWindow::run`], and
//!   [`Session::sync_lan`]: sync rounds between linked devices (0013 §5,
//!   §7, §8). Each side merges through the archive acceptance path and
//!   commits locally; local acceptance and peer receipt are reported
//!   separately (0005 §6.5). Before accepting, the ordinary automatic
//!   snapshot runs with its hourly coalescing (0007 §3.2).
//!
//! Nothing here starts without an explicit call (0005 §0.5). The session
//! mutex is held only for short reads and the link commit, never while
//! waiting on the network or the user. A session lock or the caller's
//! [`CancelToken`] closes a window or a join within about 100 ms, except
//! inside the frontend's own confirmation prompt, which must end itself on
//! cancel. Exit codes for [`CoreError::Lan`] are assigned with the CLI
//! commands (roadmap 2.10).

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use qv_crypto::lan::{LinkKey, LinkRoot, valid_link_label};
use qv_crypto::{KeyGeneration, MasterPassword, SecretBytes, VaultId};
use qv_model::{ObjectId, Text};
use qv_store::{LanServeState, LanStaging, StoreError, VaultFile};
use qv_sync::lan::{
    self as sync, Accepted, ApproverContext, ApproverVault, Confirm, EndpointPolicy, ExchangeVault,
    JoinerContext, JoinerVault, Outcome, ResponderVault, RoundReport, Sealer,
};

pub use qv_platform::net::local_addresses;
pub use qv_sync::lan::{
    JoinCode, JoinMode, JoinerUi, LanError, LanQrInfo, LanQrKind, LanTimeouts, ListenScope,
    PAIRING_WINDOW_MAX, RECEIVE_WINDOW_DEFAULT, RECEIVE_WINDOW_MAX, Sas, WindowEnd, parse_endpoint,
};

/// Inspect a scanned LAN code without initiating any network operation.
pub fn inspect_lan_qr(bytes: &[u8]) -> Result<LanQrInfo, CoreError> {
    sync::inspect_lan_qr(bytes).map_err(CoreError::Lan)
}

use crate::index::{Index, MAX_VIEW_BYTES};
use crate::session::SessionTag;
use crate::{CancelToken, Core, CoreError, Session};

/// Options for a pairing window.
#[derive(Clone, Debug)]
pub struct PairingOptions {
    /// This device's label for the joining device (1–64 bytes).
    pub peer_label: String,
    /// Where to listen; frontends use [`ListenScope::AllInterfaces`].
    pub scope: ListenScope,
    /// A user-chosen port, or `None` for an OS-chosen one.
    pub port: Option<u16>,
    /// The window's time limit, at most [`PAIRING_WINDOW_MAX`].
    pub limit: Duration,
    /// Protocol time limits (the defaults are the spec's).
    pub timeouts: LanTimeouts,
}

impl PairingOptions {
    /// The defaults: all interfaces, an OS-chosen port, 10 minutes.
    pub fn new(peer_label: &str) -> Self {
        Self {
            peer_label: peer_label.to_owned(),
            scope: ListenScope::AllInterfaces,
            port: None,
            limit: PAIRING_WINDOW_MAX,
            timeouts: LanTimeouts::default(),
        }
    }
}

/// Options for joining.
#[derive(Clone, Debug)]
pub struct JoinOptions {
    /// This device's label for the approving device (1–64 bytes).
    pub label: String,
    /// Endpoints typed by the user, tried after the QR's.
    pub extra_endpoints: Vec<SocketAddr>,
    /// Allow loopback endpoints (tests only, 0013 §1.4).
    pub allow_loopback: bool,
    /// Protocol time limits.
    pub timeouts: LanTimeouts,
}

impl JoinOptions {
    /// The defaults: no extra endpoints, loopback refused.
    pub fn new(label: &str) -> Self {
        Self {
            label: label.to_owned(),
            extra_endpoints: Vec::new(),
            allow_loopback: false,
            timeouts: LanTimeouts::default(),
        }
    }
}

/// A LAN link of this session's vault.
#[derive(Clone, PartialEq, Eq)]
pub struct LanLinkHandle {
    session: SessionTag,
    link_id: [u8; 16],
}

impl LanLinkHandle {
    /// The link ID as 32 lowercase hex digits.
    pub fn id_hex(&self) -> String {
        self.link_id.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// One link, for listing.
pub struct LanLinkSummary {
    /// The link.
    pub handle: LanLinkHandle,
    /// The user's label for the peer.
    pub label: Text,
    /// When the link was created (display only).
    pub created_at: qv_model::Timestamp,
}

/// What to show for an open window. `manual` and `qr` carry the pairing
/// secret: show them only on this device's screen.
pub struct PairingCode {
    /// The 26-character code in groups of five (UTF-8).
    pub manual: SecretBytes,
    /// The QR payload bytes.
    pub qr: SecretBytes,
    /// The listening port.
    pub port: u16,
}

/// A completed pairing on the approving device.
pub struct ApproveReport {
    /// The joiner's mode.
    pub mode: JoinMode,
    /// The new link.
    pub link: LanLinkHandle,
    /// Whether the other device confirmed completion; otherwise "pairing may
    /// be incomplete on the other device" (0013 §4.7). The link stays.
    pub peer_confirmed: bool,
    /// Why the transfer after the link commit failed, if it did.
    pub failure: Option<LanError>,
    /// Link mode: the sync round that followed the pairing (0013 §4.8). Its
    /// failure leaves both links; the user syncs again later.
    pub sync: Option<Result<SyncReport, CoreError>>,
}

/// A completed link-mode join.
pub struct JoinLinkReport {
    /// The new link.
    pub link: LanLinkHandle,
    /// The sync round that followed the pairing (0013 §4.8).
    pub sync: Result<SyncReport, CoreError>,
}

/// Whether this device committed anything in a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAcceptance {
    /// A merged state was committed (DB commit, then anchor).
    Committed,
    /// The peer brought nothing new; nothing was committed.
    Unchanged,
}

/// One sync round's result (0005 §6.5): local acceptance, conflicts and
/// confirmed peer receipt, reported separately.
pub struct SyncReport {
    /// The link the round used.
    pub link: LanLinkHandle,
    /// What this device committed.
    pub local: LocalAcceptance,
    /// Unresolved conflicts after the round (all record kinds).
    pub conflicts: usize,
    /// Whether the other device's `Done` arrived. Its own commit is its
    /// report, not a promise (no distributed commit).
    pub peer_confirmed: bool,
    /// A failure after the local commit, which must not hide it: an anchor
    /// completion error, or the lost acknowledgement.
    pub completion_error: Option<CoreError>,
}

/// Options for a receive window.
#[derive(Clone, Debug)]
pub struct ReceiveOptions {
    /// Where to listen; frontends use [`ListenScope::AllInterfaces`].
    pub scope: ListenScope,
    /// A user-chosen port, or `None` for an OS-chosen one.
    pub port: Option<u16>,
    /// The window's time limit, at most [`RECEIVE_WINDOW_MAX`].
    pub limit: Duration,
    /// Serve further rounds within the limit instead of closing after the
    /// first completed one.
    pub stay_open: bool,
    /// Protocol time limits.
    pub timeouts: LanTimeouts,
}

impl ReceiveOptions {
    /// The defaults: all interfaces, an OS-chosen port, 2 minutes, one round.
    pub fn new() -> Self {
        Self {
            scope: ListenScope::AllInterfaces,
            port: None,
            limit: RECEIVE_WINDOW_DEFAULT,
            stay_open: false,
            timeouts: LanTimeouts::default(),
        }
    }
}

impl Default for ReceiveOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Options for starting a round.
#[derive(Clone, Debug, Default)]
pub struct SyncOptions {
    /// Allow loopback endpoints (tests only, 0013 §1.4).
    pub allow_loopback: bool,
    /// Protocol time limits.
    pub timeouts: LanTimeouts,
}

/// What a receive window shows: its endpoints as text and as the
/// address-only code (0013 §8.5). Neither carries a secret.
pub struct ReceiveCode {
    /// The address-only QR payload; empty when no local address was given.
    pub qr: Vec<u8>,
    /// The endpoints, at most 8.
    pub endpoints: Vec<SocketAddr>,
    /// The listening port.
    pub port: u16,
}

/// Something a running receive window reports.
pub enum ReceiveEvent {
    /// A round passed the handshake and ended this way.
    Round(Result<SyncReport, CoreError>),
}

/// How a receive window ended.
pub struct ReceiveReport {
    /// Rounds that completed.
    pub rounds: usize,
    /// Why it closed.
    pub end: WindowEnd,
}

/// The approving user's decision (0013 §4.5).
pub trait ApproverUi {
    /// Shows the six-digit `sas`, the joiner's `mode` and the vault's name,
    /// and returns `true` once the user confirmed that both screens match.
    fn confirm(&mut self, sas: &str, mode: JoinMode, vault_name: &str) -> bool;
}

macro_rules! redacted {
    ($($t:ty),+) => {$(
        impl core::fmt::Debug for $t {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($t), "(<redacted>)"))
            }
        }
    )+};
}
redacted!(
    LanLinkHandle,
    LanLinkSummary,
    PairingCode,
    ApproveReport,
    PairingWindow,
    JoinLinkReport,
    SyncReport,
    ReceiveCode,
    ReceiveEvent,
    ReceiveReport,
    ReceiveWindow
);

fn label_ok(label: &str) -> Result<(), CoreError> {
    if valid_link_label(label) {
        Ok(())
    } else {
        Err(CoreError::InvalidInput)
    }
}

fn lan(e: CoreError) -> LanError {
    match e {
        CoreError::Cancelled | CoreError::SessionLocked => LanError::Cancelled,
        CoreError::Store(s) => LanError::Store(s),
        CoreError::LimitExceeded => LanError::Limit,
        CoreError::Lan(l) => l,
        _ => LanError::Store(StoreError::Internal),
    }
}

fn digits(sas: &Sas) -> String {
    sas.digits().iter().map(|d| char::from(*d)).collect()
}

/// An open pairing window bound to one session.
pub struct PairingWindow {
    inner: sync::PairingWindow,
    session: SessionTag,
    label: String,
    timeouts: LanTimeouts,
}

impl Session {
    /// Opens a pairing window for this vault (0013 §8.1). Writes must be
    /// allowed: a recovery session is refused.
    pub fn open_pairing_window(&self, options: PairingOptions) -> Result<PairingWindow, CoreError> {
        label_ok(&options.peer_label)?;
        options
            .timeouts
            .validate()
            .map_err(|_| CoreError::InvalidInput)?;
        if options.limit.is_zero() || options.limit > PAIRING_WINDOW_MAX {
            return Err(CoreError::InvalidInput);
        }
        self.writable()?;
        let inner = sync::PairingWindow::open(options.scope, options.port, options.limit)
            .map_err(CoreError::Lan)?;
        Ok(PairingWindow {
            inner,
            session: self.tag(),
            label: options.peer_label,
            timeouts: options.timeouts,
        })
    }

    /// Joins an approving device in link mode (0013 §4.8): both hold this
    /// vault and generation. Commits the link, then runs one sync round over
    /// the pairing keys.
    pub fn join_link(
        &self,
        code: JoinCode,
        options: JoinOptions,
        ui: &mut dyn JoinerUi,
        cancel: Option<&CancelToken>,
    ) -> Result<JoinLinkReport, CoreError> {
        label_ok(&options.label)?;
        self.writable()?;
        let joiner = SessionJoiner {
            session: self,
            label: &options.label,
            exchange: SessionExchange::new(self, cancel, None)?,
        };
        let cancelled =
            || self.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled);
        let joined = sync::join_link(
            code,
            &options.extra_endpoints,
            EndpointPolicy {
                allow_loopback: options.allow_loopback,
            },
            &joiner,
            ui,
            &options.timeouts,
            &cancelled,
        )
        .map_err(CoreError::Lan)?;
        let link = LanLinkHandle {
            session: self.tag(),
            link_id: joined.link_id,
        };
        let sync = match joined.round {
            Ok(round) => joiner.exchange.report(link.clone(), round),
            Err(e) => Err(CoreError::Lan(e)),
        };
        Ok(JoinLinkReport { link, sync })
    }

    /// Opens a receive window for this vault (0013 §8.1): the other device
    /// starts a round with [`Session::sync_lan`]. Writes must be allowed.
    pub fn open_receive_window(&self, options: ReceiveOptions) -> Result<ReceiveWindow, CoreError> {
        options
            .timeouts
            .validate()
            .map_err(|_| CoreError::InvalidInput)?;
        if options.limit.is_zero() || options.limit > RECEIVE_WINDOW_MAX {
            return Err(CoreError::InvalidInput);
        }
        self.writable()?;
        let inner = sync::ReceiveWindow::open(
            options.scope,
            options.port,
            options.limit,
            options.stay_open,
        )
        .map_err(CoreError::Lan)?;
        Ok(ReceiveWindow {
            inner,
            session: self.tag(),
            timeouts: options.timeouts,
        })
    }

    /// Runs one sync round as initiator with `link` against the first of
    /// `endpoints` that authenticates (0013 §5, §7). Nothing starts without
    /// this call (0005 §0.5).
    pub fn sync_lan(
        &self,
        link: &LanLinkHandle,
        endpoints: &[SocketAddr],
        options: SyncOptions,
        cancel: Option<&CancelToken>,
    ) -> Result<SyncReport, CoreError> {
        options
            .timeouts
            .validate()
            .map_err(|_| CoreError::InvalidInput)?;
        let key = self.read(|ctx| {
            ctx.own(link.session)?;
            ctx.check_cancel()?;
            if ctx.open.read_only {
                return Err(StoreError::NoAnchor.into());
            }
            ctx.open
                .vault
                .lan_link_key(&link.link_id)
                .map_err(|e| match e {
                    StoreError::NotFound => CoreError::NotFound,
                    e => e.into(),
                })
        })?;
        let exchange = SessionExchange::new(self, cancel, None)?;
        let cancelled =
            || self.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled);
        let round = sync::sync(
            &key,
            endpoints,
            EndpointPolicy {
                allow_loopback: options.allow_loopback,
            },
            &exchange,
            &options.timeouts,
            &cancelled,
        )
        .map_err(CoreError::Lan)?;
        exchange.report(link.clone(), round)
    }

    /// Refuses read-only (recovery) sessions.
    fn writable(&self) -> Result<(), CoreError> {
        self.read(|ctx| {
            ctx.check_cancel()?;
            if ctx.open.read_only {
                return Err(StoreError::NoAnchor.into());
            }
            Ok(())
        })
    }

    /// This vault's LAN links.
    pub fn lan_links(&self) -> Result<Vec<LanLinkSummary>, CoreError> {
        self.read(|ctx| {
            let tag = ctx.tag();
            ctx.open
                .vault
                .lan_links()?
                .into_iter()
                .map(|r| {
                    let label = core::str::from_utf8(r.label.expose_secret())
                        .map_err(|_| CoreError::Internal)?;
                    Ok(LanLinkSummary {
                        handle: LanLinkHandle {
                            session: tag,
                            link_id: r.link_id,
                        },
                        label: Text::new(label).map_err(|_| CoreError::Internal)?,
                        created_at: r.created_at,
                    })
                })
                .collect()
        })
    }

    /// Removes a link in one commit (0013 §12.1). The peer is
    /// not told; its next attempt fails like an unreachable device. Removal
    /// is not compromise recovery: that is rotation (§12.3).
    pub fn remove_lan_link(&self, link: &LanLinkHandle) -> Result<(), CoreError> {
        self.mutate(|ctx| {
            ctx.own(link.session)?;
            ctx.check_cancel()?;
            let mut w = ctx.open.vault.write()?;
            w.remove_lan_link(&link.link_id).map_err(|e| match e {
                StoreError::NotFound => CoreError::NotFound,
                e => e.into(),
            })?;
            w.commit()?;
            Ok(())
        })
    }
}

impl PairingWindow {
    /// The code to show: the manual code, and a QR payload naming up to
    /// eight of `local_addrs` (the frontend's interface addresses) with this
    /// window's port. Discovery is off in this phase.
    pub fn code(&self, local_addrs: &[IpAddr]) -> Result<PairingCode, CoreError> {
        let manual = self.inner.manual_code();
        let qr = self.inner.qr(local_addrs).map_err(CoreError::Lan)?;
        let copy = |b: &[u8]| {
            SecretBytes::try_init(b.len(), |o| {
                o.copy_from_slice(b);
                Ok::<(), CoreError>(())
            })
        };
        Ok(PairingCode {
            manual: copy(manual.as_bytes())?,
            qr: copy(&qr)?,
            port: self.inner.port().map_err(CoreError::Lan)?,
        })
    }

    /// When the window closes on its own.
    pub fn expires_at(&self) -> Instant {
        self.inner.expires_at()
    }

    /// Runs the window until one pairing completes or the window closes.
    pub fn run(
        self,
        session: &Session,
        ui: &mut dyn ApproverUi,
        cancel: Option<&CancelToken>,
    ) -> Result<ApproveReport, CoreError> {
        if session.tag() != self.session {
            return Err(CoreError::StaleHandle);
        }
        let approver = SessionApprover {
            session,
            label: &self.label,
            exchange: SessionExchange::new(session, cancel, Some(self.inner.expires_at()))?,
        };
        let cancelled = || {
            session.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled)
        };
        let mut confirm = UiConfirm(ui);
        let approved = self
            .inner
            .run(&approver, &mut confirm, &self.timeouts, &cancelled)
            .map_err(CoreError::Lan)?;
        let link = LanLinkHandle {
            session: self.session,
            link_id: approved.link_id,
        };
        let sync = approved.round.map(|round| match round {
            Ok(r) => approver.exchange.report(link.clone(), r),
            Err(e) => Err(CoreError::Lan(e)),
        });
        Ok(ApproveReport {
            mode: approved.mode,
            link,
            peer_confirmed: approved.peer_confirmed,
            failure: approved.failure,
            sync,
        })
    }
}

struct UiConfirm<'u>(&'u mut dyn ApproverUi);

impl Confirm for UiConfirm<'_> {
    fn confirm(&mut self, sas: &Sas, mode: JoinMode, vault_name: &[u8]) -> bool {
        let name = core::str::from_utf8(vault_name).unwrap_or("");
        self.0.confirm(&digits(sas), mode, name)
    }
}

/// What a round's acceptance left for its report.
#[derive(Default)]
struct AcceptState {
    committed: bool,
    conflicts: usize,
    completion_error: Option<CoreError>,
}

/// One vault's side of an exchange over a session (0013 §7): short `read`
/// and `mutate` calls only, never across the network.
struct SessionExchange<'s> {
    session: &'s Session,
    cancel: Option<&'s CancelToken>,
    expires: Option<Instant>,
    state: Mutex<AcceptState>,
}

impl<'s> SessionExchange<'s> {
    fn new(
        session: &'s Session,
        cancel: Option<&'s CancelToken>,
        expires: Option<Instant>,
    ) -> Result<Self, CoreError> {
        let conflicts = session.read(|ctx| {
            Ok(ctx
                .open
                .index
                .records
                .values()
                .filter(|r| r.status.conflict)
                .count())
        })?;
        Ok(Self {
            session,
            cancel,
            expires,
            state: Mutex::new(AcceptState {
                conflicts,
                ..AcceptState::default()
            }),
        })
    }

    fn cancelled(&self) -> bool {
        self.cancel.is_some_and(CancelToken::is_cancelled)
            || self.expires.is_some_and(|t| Instant::now() >= t)
    }

    /// Takes one round's acceptance, retaining metadata for an unchanged retry.
    fn take(&self) -> AcceptState {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let conflicts = state.conflicts;
        std::mem::replace(
            &mut *state,
            AcceptState {
                conflicts,
                ..AcceptState::default()
            },
        )
    }

    /// The report of a finished round.
    fn report(&self, link: LanLinkHandle, round: RoundReport) -> Result<SyncReport, CoreError> {
        let accepted = self.take();
        Ok(SyncReport {
            link,
            local: if accepted.committed {
                LocalAcceptance::Committed
            } else {
                LocalAcceptance::Unchanged
            },
            conflicts: accepted.conflicts,
            peer_confirmed: round.peer.is_some(),
            completion_error: accepted
                .completion_error
                .or(round.failure.map(CoreError::Lan)),
        })
    }
}

impl ExchangeVault for SessionExchange<'_> {
    fn scope(&self) -> Result<(VaultId, KeyGeneration), LanError> {
        self.session
            .read(|ctx| {
                let h = ctx.open.vault.header();
                Ok((h.vault_id, h.key_generation))
            })
            .map_err(lan)
    }

    fn serve_state(&self) -> Result<LanServeState, LanError> {
        self.session
            .read(|ctx| Ok(ctx.open.vault.lan_serve_state()?))
            .map_err(lan)
    }

    fn object(&self, state: &LanServeState, id: ObjectId) -> Result<Vec<u8>, LanError> {
        self.session
            .read(|ctx| {
                ctx.open.vault.lan_object_envelope(state, id).map_err(|e| {
                    CoreError::Lan(match e {
                        StoreError::NotFound => LanError::StateChanged,
                        StoreError::InvalidEdit => LanError::Protocol,
                        StoreError::Integrity => LanError::Integrity,
                        e => LanError::Store(e),
                    })
                })
            })
            .map_err(lan)
    }

    fn stage(&self, manifest_hash: &[u8; 32], envelope: &[u8]) -> Result<LanStaging, LanError> {
        self.session
            .read(|ctx| {
                let c = ctx.canceller();
                ctx.open
                    .vault
                    .lan_stage(manifest_hash, envelope, &|| {
                        c.is_cancelled() || self.cancelled()
                    })
                    .map_err(|e| CoreError::Lan(LanError::from_staging(e)))
            })
            .map_err(lan)
    }

    fn stage_local(&self, staging: &mut LanStaging) -> Result<(), LanError> {
        if self.cancelled() {
            return Err(LanError::Cancelled);
        }
        self.session
            .read(|ctx| Ok(ctx.open.vault.lan_stage_local(staging)?))
            .map_err(lan)
    }

    fn accept(&self, staging: LanStaging) -> Result<Accepted, LanError> {
        // Ordinary snapshot coalescing before a LAN merge (0007 §3.2): at
        // most one per interval; a failure does not block the merge.
        if self.cancelled() {
            return Err(LanError::Cancelled);
        }
        self.session
            .run_automatic_snapshot_cancellable(&|| self.cancelled());
        self.session
            .mutate(|ctx| {
                let c = ctx.canceller();
                let cancelled = || c.is_cancelled() || self.cancelled();
                ctx.check_cancel()?;
                if ctx.open.read_only {
                    return Err(StoreError::NoAnchor.into());
                }
                let mut verified = ctx
                    .open
                    .vault
                    .lan_finish(staging, &cancelled)
                    .map_err(|e| CoreError::Lan(LanError::from_staging(e)))?;
                let before = ctx.open.vault.local_seq();
                let mut proposed = None;
                let mut preflight_error = None;
                let result = ctx.open.vault.accept_lan(
                    &mut verified,
                    &mut |local, incoming, read| {
                        let candidate = qv_sync::merge(
                            local,
                            incoming,
                            &mut |s, r, v| read(s, r, v),
                            &cancelled,
                        )?;
                        let index = Index::from_manifest(
                            candidate.manifest(),
                            &mut |r, v| {
                                let role = candidate
                                    .manifest()
                                    .record(r)
                                    .and_then(|r| r.version(v))
                                    .ok_or(CoreError::Internal)?;
                                let source = candidate
                                    .source(role.object_id())
                                    .ok_or(CoreError::Internal)?;
                                Ok(read(source, r, v)?)
                            },
                            &cancelled,
                            MAX_VIEW_BYTES,
                        )
                        .map_err(|e| {
                            preflight_error = Some(e);
                            StoreError::Internal
                        })?;
                        proposed = Some(index);
                        Ok(candidate.manifest().clone())
                    },
                    &cancelled,
                );
                let committed = ctx.open.vault.local_seq() != before;
                if committed {
                    let Some(index) = proposed else {
                        ctx.poison = true;
                        return Err(CoreError::Internal);
                    };
                    ctx.open.index = index;
                } else if let Err(e) = result {
                    return Err(preflight_error.unwrap_or(if cancelled() {
                        CoreError::Cancelled
                    } else {
                        CoreError::Lan(match e {
                            StoreError::Integrity => LanError::Integrity,
                            StoreError::LimitExceeded => LanError::Limit,
                            StoreError::Changed | StoreError::Locked => LanError::Busy,
                            e => LanError::Store(e),
                        })
                    }));
                }
                let conflicts = ctx.open.index.records.values().any(|r| r.status.conflict);
                *self.state.lock().unwrap_or_else(PoisonError::into_inner) = AcceptState {
                    committed,
                    conflicts: ctx
                        .open
                        .index
                        .records
                        .values()
                        .filter(|r| r.status.conflict)
                        .count(),
                    completion_error: if committed {
                        result.err().map(Into::into)
                    } else {
                        None
                    },
                };
                Ok(Accepted {
                    outcome: match (committed, conflicts) {
                        (false, _) => Outcome::Unchanged,
                        (true, false) => Outcome::Merged,
                        (true, true) => Outcome::MergedWithConflicts,
                    },
                    manifest_hash: ctx.open.vault.manifest_hash(),
                })
            })
            .map_err(lan)
    }
}

/// Delegates [`ExchangeVault`] to the `exchange` field.
macro_rules! delegate_exchange {
    ($($t:ident),+) => {$(
        impl ExchangeVault for $t<'_> {
            fn scope(&self) -> Result<(VaultId, KeyGeneration), LanError> {
                self.exchange.scope()
            }
            fn serve_state(&self) -> Result<LanServeState, LanError> {
                self.exchange.serve_state()
            }
            fn object(&self, state: &LanServeState, id: ObjectId) -> Result<Vec<u8>, LanError> {
                self.exchange.object(state, id)
            }
            fn stage(&self, hash: &[u8; 32], envelope: &[u8]) -> Result<LanStaging, LanError> {
                self.exchange.stage(hash, envelope)
            }
            fn stage_local(&self, staging: &mut LanStaging) -> Result<(), LanError> {
                self.exchange.stage_local(staging)
            }
            fn accept(&self, staging: LanStaging) -> Result<Accepted, LanError> {
                self.exchange.accept(staging)
            }
        }
    )+};
}
delegate_exchange!(SessionApprover, SessionJoiner, SessionResponder);

struct SessionApprover<'s> {
    session: &'s Session,
    label: &'s str,
    exchange: SessionExchange<'s>,
}

impl ApproverVault for SessionApprover<'_> {
    fn context(&self) -> Result<ApproverContext, LanError> {
        self.session
            .read(|ctx| {
                let v = &ctx.open.vault;
                let h = v.header();
                let name = ctx
                    .open
                    .index
                    .meta()
                    .ok_or(CoreError::Internal)?
                    .name
                    .expose()
                    .as_bytes();
                Ok(ApproverContext {
                    vault_id: h.vault_id,
                    key_generation: h.key_generation,
                    vault_name: SecretBytes::try_init(name.len(), |o| {
                        o.copy_from_slice(name);
                        Ok::<(), CoreError>(())
                    })?,
                    root: LinkRoot::derive(
                        v.vault_key(),
                        h.vault_id,
                        h.key_generation,
                        h.derivation_profile,
                    )
                    .map_err(crate::error::crypto)?,
                })
            })
            .map_err(lan)
    }

    fn commit_link(&self, link_id: [u8; 16], key: &LinkKey) -> Result<(), LanError> {
        commit_link(self.session, self.label, link_id, key, &|| {
            self.exchange.cancelled()
        })
    }

    fn grant(&self, link_id: &[u8; 16], seal: &mut Sealer<'_>) -> Result<Vec<u8>, LanError> {
        // VK is encoded into a wiped buffer and sealed inside this short
        // read; the driver sends the record after it (0037 finding 4).
        self.session
            .read(|ctx| {
                if self.exchange.cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let v = &ctx.open.vault;
                let h = v.header();
                let plaintext =
                    sync::grant_plaintext(v.vault_key(), h.vault_id, h.key_generation, link_id)
                        .map_err(CoreError::Lan)?;
                seal(&plaintext).map_err(CoreError::Lan)
            })
            .map_err(lan)
    }
}

fn commit_link(
    session: &Session,
    label: &str,
    link_id: [u8; 16],
    key: &LinkKey,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), LanError> {
    session
        .mutate(|ctx| {
            ctx.check_cancel()?;
            let c = ctx.canceller();
            let stop = || c.is_cancelled() || cancelled();
            if stop() {
                return Err(CoreError::Cancelled);
            }
            let now = ctx.now();
            let before = ctx.open.vault.local_seq();
            let mut w = ctx.open.vault.write()?;
            w.add_lan_link(link_id, key, label, now)?;
            let result = w.commit_cancellable(&stop);
            if result.is_err() && ctx.open.vault.local_seq() == before && stop() {
                return Err(CoreError::Cancelled);
            }
            result?;
            Ok(())
        })
        .map_err(lan)
}

fn link_root(session: &Session) -> Result<JoinerContext, LanError> {
    session
        .read(|ctx| {
            let v = &ctx.open.vault;
            let h = v.header();
            Ok(JoinerContext {
                vault_id: h.vault_id,
                key_generation: h.key_generation,
                root: LinkRoot::derive(
                    v.vault_key(),
                    h.vault_id,
                    h.key_generation,
                    h.derivation_profile,
                )
                .map_err(crate::error::crypto)?,
            })
        })
        .map_err(lan)
}

struct SessionJoiner<'s> {
    session: &'s Session,
    label: &'s str,
    exchange: SessionExchange<'s>,
}

impl JoinerVault for SessionJoiner<'_> {
    fn context(&self) -> Result<JoinerContext, LanError> {
        link_root(self.session)
    }

    fn commit_link(&self, link_id: [u8; 16], key: &LinkKey) -> Result<(), LanError> {
        commit_link(self.session, self.label, link_id, key, &|| {
            self.exchange.cancelled()
        })
    }
}

/// A receive window's view of the session: its links and the exchange.
struct SessionResponder<'s> {
    session: &'s Session,
    exchange: SessionExchange<'s>,
}

impl ResponderVault for SessionResponder<'_> {
    fn links(&self) -> Result<Vec<([u8; 16], LinkKey)>, LanError> {
        self.session
            .read(|ctx| {
                let v = &ctx.open.vault;
                v.lan_links()?
                    .into_iter()
                    .map(|r| Ok((r.link_id, v.lan_link_key(&r.link_id)?)))
                    .collect()
            })
            .map_err(lan)
    }

    fn has_link(&self, link_id: &[u8; 16]) -> Result<bool, LanError> {
        self.session
            .read(|ctx| {
                Ok(ctx
                    .open
                    .vault
                    .lan_links()?
                    .iter()
                    .any(|r| r.link_id == *link_id))
            })
            .map_err(lan)
    }
}

/// An open receive window bound to one session (0013 §8).
pub struct ReceiveWindow {
    inner: sync::ReceiveWindow,
    session: SessionTag,
    timeouts: LanTimeouts,
}

impl ReceiveWindow {
    /// What to show: the endpoints for `local_addrs` (the frontend's
    /// addresses, e.g. [`local_addresses`]) and the address-only code.
    pub fn code(&self, local_addrs: &[IpAddr]) -> Result<ReceiveCode, CoreError> {
        let endpoints = self.inner.endpoints(local_addrs).map_err(CoreError::Lan)?;
        let qr = if endpoints.is_empty() {
            Vec::new()
        } else {
            self.inner.qr(local_addrs).map_err(CoreError::Lan)?
        };
        Ok(ReceiveCode {
            qr,
            endpoints,
            port: self.inner.port().map_err(CoreError::Lan)?,
        })
    }

    /// When the window closes on its own.
    pub fn expires_at(&self) -> Instant {
        self.inner.expires_at()
    }

    /// Runs the window until it closes. `on_event` sees each round that
    /// passed the handshake. A lock or `cancel` closes it within ~100 ms.
    pub fn run(
        self,
        session: &Session,
        on_event: &mut dyn FnMut(ReceiveEvent),
        cancel: Option<&CancelToken>,
    ) -> Result<ReceiveReport, CoreError> {
        if session.tag() != self.session {
            return Err(CoreError::StaleHandle);
        }
        let responder = SessionResponder {
            session,
            exchange: SessionExchange::new(session, cancel, Some(self.inner.expires_at()))?,
        };
        let cancelled = || {
            session.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled)
        };
        let mut rounds = 0;
        let tag = self.session;
        let end = self
            .inner
            .run(
                &responder,
                &self.timeouts,
                &cancelled,
                &mut |link_id, result| {
                    let link = LanLinkHandle {
                        session: tag,
                        link_id,
                    };
                    let report = match result {
                        Ok(round) => responder.exchange.report(link, round),
                        Err(e) => {
                            responder.exchange.take();
                            Err(CoreError::Lan(e))
                        }
                    };
                    if report.is_ok() {
                        rounds += 1;
                    }
                    on_event(ReceiveEvent::Round(report));
                },
            )
            .map_err(CoreError::Lan)?;
        Ok(ReceiveReport { rounds, end })
    }
}

impl Core {
    /// Joins an approving device as a new device (0013 §4.7, §10): pairs,
    /// receives and verifies the vault into private staging, asks the user
    /// to confirm the vault and enter its master password, creates it at the
    /// new path `destination` with the link in its first head, and unlocks
    /// it. Nothing appears at `destination` before the last step.
    pub fn join_new_device(
        &self,
        code: JoinCode,
        destination: &Path,
        options: JoinOptions,
        ui: &mut dyn JoinerUi,
        cancel: Option<&CancelToken>,
    ) -> Result<Session, CoreError> {
        label_ok(&options.label)?;
        // The same guards as `create`, before any key is received.
        self.platform_gate()?;
        self.check_anchor_location(destination)?;
        let cancelled = || cancel.is_some_and(CancelToken::is_cancelled);
        let joined = sync::join_new_device(
            code,
            &options.extra_endpoints,
            EndpointPolicy {
                allow_loopback: options.allow_loopback,
            },
            self.anchors.path(),
            ui,
            &options.timeouts,
            &cancelled,
        )
        .map_err(CoreError::Lan)?;
        let password: MasterPassword = joined.password;
        VaultFile::create_from_lan(
            destination,
            joined.staging,
            joined.proof,
            &joined.vk,
            &self.anchors,
            qv_store::NewLanLink {
                link_id: joined.link_id,
                key: &joined.link_key,
                label: &options.label,
                created_at: self.time.now(),
            },
            &cancelled,
        )?;
        self.unlock(destination, &password, cancel)
    }
}

#[cfg(test)]
mod repair_tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::testutil::{Env, add_entry, seq};

    fn stage(local: &SessionExchange<'_>, peer: &SessionExchange<'_>) -> LanStaging {
        let state = peer.serve_state().unwrap();
        let mut staging = local
            .stage(state.manifest_hash(), state.envelope())
            .unwrap();
        for (id, source) in staging.plan().to_vec() {
            match source {
                qv_store::Planned::Local => local.stage_local(&mut staging).unwrap(),
                qv_store::Planned::Peer => staging
                    .add_object(&peer.object(&state, id).unwrap())
                    .unwrap(),
            }
        }
        staging
    }

    // 0012 §1: LAN partial acceptance
    #[test]
    fn lan_core_committed_report_survives_lock_before_done() {
        let env = Env::new();
        let (a, b, link, _) = crate::lan_tests::linked_pair(&env, None);
        add_entry(&b, b.root().unwrap(), "arrived");
        let local = SessionExchange::new(&a, None, None).unwrap();
        let peer = SessionExchange::new(&b, None, None).unwrap();
        let accepted = local.accept(stage(&local, &peer)).unwrap();
        assert_eq!(accepted.outcome, Outcome::Merged);
        a.lock();
        let report = local
            .report(
                link,
                RoundReport {
                    local: accepted.outcome,
                    peer: None,
                    manifest_hash: accepted.manifest_hash,
                    failure: Some(LanError::Cancelled),
                },
            )
            .unwrap();
        assert_eq!(report.local, LocalAcceptance::Committed);
        assert!(!report.peer_confirmed);
        assert_eq!(
            report.completion_error,
            Some(CoreError::Lan(LanError::Cancelled))
        );
        assert_eq!(report.conflicts, 0);
    }

    // 0012 §1: LAN partial acceptance
    #[test]
    fn lan_core_cancel_and_expiry_before_acceptance_preserve_state() {
        let env = Env::new();
        let (a, b, _, _) = crate::lan_tests::linked_pair(&env, None);
        add_entry(&b, b.root().unwrap(), "not accepted");
        let peer = SessionExchange::new(&b, None, None).unwrap();
        let before = seq(&a);
        let token = CancelToken::new();
        let local = SessionExchange::new(&a, Some(&token), None).unwrap();
        let staged = stage(&local, &peer);
        token.cancel();
        assert_eq!(local.accept(staged), Err(LanError::Cancelled));
        assert_eq!(seq(&a), before);
        let mut local = SessionExchange::new(&a, None, None).unwrap();
        let staged = stage(&local, &peer);
        local.expires = Some(Instant::now() - Duration::from_secs(1));
        assert_eq!(local.accept(staged), Err(LanError::Cancelled));
        assert_eq!(seq(&a), before);
        let key = a
            .read(|ctx| {
                let links = ctx.open.vault.lan_links()?;
                Ok(ctx.open.vault.lan_link_key(&links[0].link_id)?)
            })
            .unwrap();
        let approver = SessionApprover {
            session: &a,
            label: "late",
            exchange: local,
        };
        assert_eq!(
            approver.commit_link([0x44; 16], &key),
            Err(LanError::Cancelled)
        );
        let mut sealed = false;
        assert_eq!(
            approver.grant(&[0x44; 16], &mut |_| {
                sealed = true;
                Ok(Vec::new())
            }),
            Err(LanError::Cancelled)
        );
        assert!(!sealed);
        assert_eq!(seq(&a), before);
    }
}
