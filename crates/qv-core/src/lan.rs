// SPDX-License-Identifier: AGPL-3.0-or-later

//! LAN sync with one-use codes for frontends (0013 §4, §7–10, §12; plans
//! 0037, 0038, 0042).
//!
//! - [`Session::open_sync_window`] then [`SyncWindow::run`]: the offering
//!   device. The window's code is shown to the user, and the call blocks
//!   until its one session ends or the window closes. A new device's hello
//!   asks the user to compare codes ([`ApproverUi`]); a sync needs no input.
//! - [`Session::sync_with_code`]: an unlocked copy of the same vault proves
//!   itself to the window and runs one sync round.
//! - [`Core::join_new_device`]: a device without this vault receives and
//!   verifies it, confirms it, checks the master password, creates the
//!   vault at a new path and unlocks it (0013 §10).
//!
//! Each side merges through the archive acceptance path and commits
//! locally; local acceptance and peer receipt are reported separately
//! (0005 §6.5). Before accepting, the ordinary automatic snapshot runs with
//! its hourly coalescing (0007 §3.2). Nothing about the other device is
//! stored (0013 §9.1).
//!
//! Nothing here starts without an explicit call (0005 §0.5). The session
//! mutex is held only for short reads and commits, never while waiting on
//! the network or the user. A session lock or the caller's
//! [`CancelToken`] closes a window, a sync or a join within about 100 ms,
//! except inside the frontend's own confirmation prompt, which must end
//! itself on cancel.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use qv_crypto::lan::ProofRoot;
use qv_crypto::{KeyGeneration, MasterPassword, SecretBytes, VaultId};
use qv_model::ObjectId;
use qv_store::{LanServeState, LanStaging, StoreError, VaultFile};
use qv_sync::lan::{
    self as sync, Accepted, Approved, ApproverContext, ApproverVault, Confirm, EndpointPolicy,
    ExchangeVault, JoinerContext, JoinerVault, Outcome, RoundReport, Sealer,
};

pub use qv_platform::net::local_addresses;
pub use qv_sync::lan::{
    JoinCode, JoinMode, JoinerUi, LanError, LanQrInfo, LanTimeouts, ListenScope,
    PAIRING_WINDOW_MAX, Sas, parse_endpoint,
};

/// Inspect a scanned LAN code without initiating any network operation.
pub fn inspect_lan_qr(bytes: &[u8]) -> Result<LanQrInfo, CoreError> {
    sync::inspect_lan_qr(bytes).map_err(CoreError::Lan)
}

use crate::index::{Index, MAX_VIEW_BYTES};
use crate::session::SessionTag;
use crate::{CancelToken, Core, CoreError, Session};

/// Options for a sync window.
#[derive(Clone, Debug)]
pub struct SyncWindowOptions {
    /// Where to listen; frontends use [`ListenScope::AllInterfaces`].
    pub scope: ListenScope,
    /// A user-chosen port, or `None` for an OS-chosen one.
    pub port: Option<u16>,
    /// The window's time limit, at most [`PAIRING_WINDOW_MAX`].
    pub limit: Duration,
    /// Protocol time limits (the defaults are the spec's).
    pub timeouts: LanTimeouts,
}

impl SyncWindowOptions {
    /// The defaults: all interfaces, an OS-chosen port, 10 minutes.
    pub fn new() -> Self {
        Self {
            scope: ListenScope::AllInterfaces,
            port: None,
            limit: PAIRING_WINDOW_MAX,
            timeouts: LanTimeouts::default(),
        }
    }
}

impl Default for SyncWindowOptions {
    fn default() -> Self {
        Self::new()
    }
}

/// Options for syncing with or joining from a code.
#[derive(Clone, Debug, Default)]
pub struct SyncOptions {
    /// Endpoints typed by the user, tried after the QR's.
    pub extra_endpoints: Vec<SocketAddr>,
    /// Allow loopback endpoints (tests only, 0013 §1.4).
    pub allow_loopback: bool,
    /// Protocol time limits.
    pub timeouts: LanTimeouts,
}

/// What to show for an open window. `manual` and `qr` carry the code's
/// secret: show them only on this device's screen.
pub struct WindowCode {
    /// The 26-character code in groups of five (UTF-8).
    pub manual: SecretBytes,
    /// The QR payload bytes.
    pub qr: SecretBytes,
    /// The listening port.
    pub port: u16,
}

/// The window's one session, on the offering device.
pub enum Served {
    /// A new device joined (0013 §4.7). Without `peer_confirmed` it may not
    /// have finished joining; `failure` says why.
    Joined {
        /// Whether the new device's `Done` arrived.
        peer_confirmed: bool,
        /// Why the transfer failed after the grant, if it did.
        failure: Option<LanError>,
    },
    /// A sync with another copy of this vault (0013 §4.8).
    Synced(SyncReport),
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

/// The offering user's decision for a new device (0013 §4.5).
pub trait ApproverUi {
    /// Shows the six-digit `sas` and the vault's name, and returns `true`
    /// once the user confirmed that both screens match.
    fn confirm(&mut self, sas: &str, vault_name: &str) -> bool;
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
redacted!(WindowCode, Served, SyncWindow, SyncReport);

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

/// An open sync window bound to one session.
pub struct SyncWindow {
    inner: sync::PairingWindow,
    session: SessionTag,
    timeouts: LanTimeouts,
}

impl Session {
    /// Opens a one-use sync window for this vault (0013 §8.1). Writes must
    /// be allowed: a recovery session is refused.
    pub fn open_sync_window(&self, options: SyncWindowOptions) -> Result<SyncWindow, CoreError> {
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
        Ok(SyncWindow {
            inner,
            session: self.tag(),
            timeouts: options.timeouts,
        })
    }

    /// Syncs once with the window that shows `code` (0013 §4.8, §7): both
    /// hold this vault and generation. Nothing starts without this call
    /// (0005 §0.5), and nothing about the other device is stored.
    pub fn sync_with_code(
        &self,
        code: JoinCode,
        options: SyncOptions,
        cancel: Option<&CancelToken>,
    ) -> Result<SyncReport, CoreError> {
        options
            .timeouts
            .validate()
            .map_err(|_| CoreError::InvalidInput)?;
        self.writable()?;
        let joiner = SessionJoiner {
            session: self,
            exchange: SessionExchange::new(self, cancel, None)?,
        };
        let cancelled =
            || self.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled);
        let round = sync::sync_with_code(
            code,
            &options.extra_endpoints,
            EndpointPolicy {
                allow_loopback: options.allow_loopback,
            },
            &joiner,
            &options.timeouts,
            &cancelled,
        )
        .map_err(CoreError::Lan)?;
        joiner.exchange.report(round)
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
}

impl SyncWindow {
    /// The code to show: the manual code, and a QR payload naming up to
    /// eight of `local_addrs` (the frontend's interface addresses) with this
    /// window's port. Discovery is off in this phase.
    pub fn code(&self, local_addrs: &[IpAddr]) -> Result<WindowCode, CoreError> {
        let manual = self.inner.manual_code();
        let qr = self.inner.qr(local_addrs).map_err(CoreError::Lan)?;
        let copy = |b: &[u8]| {
            SecretBytes::try_init(b.len(), |o| {
                o.copy_from_slice(b);
                Ok::<(), CoreError>(())
            })
        };
        Ok(WindowCode {
            manual: copy(manual.as_bytes())?,
            qr: copy(&qr)?,
            port: self.inner.port().map_err(CoreError::Lan)?,
        })
    }

    /// When the window closes on its own.
    pub fn expires_at(&self) -> Instant {
        self.inner.expires_at()
    }

    /// Runs the window until its one session ends or the window closes.
    pub fn run(
        self,
        session: &Session,
        ui: &mut dyn ApproverUi,
        cancel: Option<&CancelToken>,
    ) -> Result<Served, CoreError> {
        if session.tag() != self.session {
            return Err(CoreError::StaleHandle);
        }
        let approver = SessionApprover {
            session,
            exchange: SessionExchange::new(session, cancel, Some(self.inner.expires_at()))?,
        };
        let cancelled = || {
            session.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled)
        };
        let mut confirm = UiConfirm(ui);
        let served = self
            .inner
            .run(&approver, &mut confirm, &self.timeouts, &cancelled)
            .map_err(CoreError::Lan)?;
        Ok(match served {
            Approved::Joined {
                peer_confirmed,
                failure,
            } => Served::Joined {
                peer_confirmed,
                failure,
            },
            Approved::Synced(round) => Served::Synced(approver.exchange.report(round)?),
        })
    }
}

struct UiConfirm<'u>(&'u mut dyn ApproverUi);

impl Confirm for UiConfirm<'_> {
    fn confirm(&mut self, sas: &Sas, vault_name: &[u8]) -> bool {
        let name = core::str::from_utf8(vault_name).unwrap_or("");
        self.0.confirm(&digits(sas), name)
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
    fn report(&self, round: RoundReport) -> Result<SyncReport, CoreError> {
        let accepted = self.take();
        Ok(SyncReport {
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
delegate_exchange!(SessionApprover, SessionJoiner);

struct SessionApprover<'s> {
    session: &'s Session,
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
                    root: ProofRoot::derive(
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

    fn grant(&self, seal: &mut Sealer<'_>) -> Result<Vec<u8>, LanError> {
        // VK is encoded into a wiped buffer and sealed inside this short
        // read; the driver sends the record after it (0037 finding 4).
        self.session
            .read(|ctx| {
                if self.exchange.cancelled() {
                    return Err(CoreError::Cancelled);
                }
                let v = &ctx.open.vault;
                let h = v.header();
                let plaintext = sync::grant_plaintext(v.vault_key(), h.vault_id, h.key_generation)
                    .map_err(CoreError::Lan)?;
                seal(&plaintext).map_err(CoreError::Lan)
            })
            .map_err(lan)
    }
}

fn proof_root(session: &Session) -> Result<JoinerContext, LanError> {
    session
        .read(|ctx| {
            let v = &ctx.open.vault;
            let h = v.header();
            Ok(JoinerContext {
                vault_id: h.vault_id,
                key_generation: h.key_generation,
                root: ProofRoot::derive(
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
    exchange: SessionExchange<'s>,
}

impl JoinerVault for SessionJoiner<'_> {
    fn context(&self) -> Result<JoinerContext, LanError> {
        proof_root(self.session)
    }
}

impl Core {
    /// Joins from another device's code as a new device (0013 §4.7, §10):
    /// receives and verifies the vault into private staging, asks the user
    /// to confirm the vault and enter its master password, creates it at the
    /// new path `destination`, and unlocks it. Nothing appears at
    /// `destination` before the last step, and nothing about the other
    /// device is stored.
    pub fn join_new_device(
        &self,
        code: JoinCode,
        destination: &Path,
        options: SyncOptions,
        ui: &mut dyn JoinerUi,
        cancel: Option<&CancelToken>,
    ) -> Result<Session, CoreError> {
        options
            .timeouts
            .validate()
            .map_err(|_| CoreError::InvalidInput)?;
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
        let (a, b) = crate::lan_tests::replicas(&env);
        add_entry(&b, b.root().unwrap(), "arrived");
        let local = SessionExchange::new(&a, None, None).unwrap();
        let peer = SessionExchange::new(&b, None, None).unwrap();
        let accepted = local.accept(stage(&local, &peer)).unwrap();
        assert_eq!(accepted.outcome, Outcome::Merged);
        a.lock();
        let report = local
            .report(RoundReport {
                local: accepted.outcome,
                peer: None,
                manifest_hash: accepted.manifest_hash,
                failure: Some(LanError::Cancelled),
            })
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
        let (a, b) = crate::lan_tests::replicas(&env);
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
        let approver = SessionApprover {
            session: &a,
            exchange: local,
        };
        let mut sealed = false;
        assert_eq!(
            approver.grant(&mut |_| {
                sealed = true;
                Ok(Vec::new())
            }),
            Err(LanError::Cancelled)
        );
        assert!(!sealed);
        assert_eq!(seq(&a), before);
    }
}
