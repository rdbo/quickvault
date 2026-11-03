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
use std::time::{Duration, Instant};

use qv_crypto::lan::{LinkKey, LinkRoot, valid_link_label};
use qv_crypto::{MasterPassword, SecretBytes};
use qv_model::{ObjectId, Text};
use qv_store::{LanServeState, StoreError, VaultFile};
use qv_sync::lan::{
    self as sync, ApproverContext, ApproverVault, Confirm, EndpointPolicy, JoinerContext,
    JoinerVault,
};

pub use qv_sync::lan::{
    JoinCode, JoinMode, JoinerUi, LanError, LanTimeouts, ListenScope, PAIRING_WINDOW_MAX, Sas,
};

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
    PairingWindow
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
        self.read(|ctx| {
            ctx.check_cancel()?;
            if ctx.open.read_only {
                return Err(StoreError::NoAnchor.into());
            }
            Ok(())
        })?;
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
    /// vault and generation. Returns the committed link.
    pub fn join_link(
        &self,
        code: JoinCode,
        options: JoinOptions,
        ui: &mut dyn JoinerUi,
        cancel: Option<&CancelToken>,
    ) -> Result<LanLinkHandle, CoreError> {
        label_ok(&options.label)?;
        self.read(|ctx| {
            ctx.check_cancel()?;
            if ctx.open.read_only {
                return Err(StoreError::NoAnchor.into());
            }
            Ok(())
        })?;
        let joiner = SessionJoiner {
            session: self,
            label: &options.label,
        };
        let cancelled =
            || self.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled);
        let link_id = sync::join_link(
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
        Ok(LanLinkHandle {
            session: self.tag(),
            link_id,
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
        };
        let cancelled = || {
            session.locking.load(Ordering::SeqCst) || cancel.is_some_and(CancelToken::is_cancelled)
        };
        let mut confirm = UiConfirm(ui);
        let approved = self
            .inner
            .run(&approver, &mut confirm, &self.timeouts, &cancelled)
            .map_err(CoreError::Lan)?;
        Ok(ApproveReport {
            mode: approved.mode,
            link: LanLinkHandle {
                session: self.session,
                link_id: approved.link_id,
            },
            peer_confirmed: approved.peer_confirmed,
            failure: approved.failure,
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

struct SessionApprover<'s> {
    session: &'s Session,
    label: &'s str,
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
        self.session
            .mutate(|ctx| {
                ctx.check_cancel()?;
                let now = ctx.now();
                let mut w = ctx.open.vault.write()?;
                w.add_lan_link(link_id, key, self.label, now)?;
                w.commit()?;
                Ok(())
            })
            .map_err(lan)
    }

    fn grant(
        &self,
        link_id: &[u8; 16],
        send: &mut dyn FnMut(&[u8]) -> Result<(), LanError>,
    ) -> Result<(), LanError> {
        // VK is encoded into a wiped buffer and sealed inside this short read.
        self.session
            .read(|ctx| {
                let v = &ctx.open.vault;
                let h = v.header();
                let plaintext =
                    sync::grant_plaintext(v.vault_key(), h.vault_id, h.key_generation, link_id)
                        .map_err(CoreError::Lan)?;
                send(&plaintext).map_err(CoreError::Lan)
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
}

struct SessionJoiner<'s> {
    session: &'s Session,
    label: &'s str,
}

impl JoinerVault for SessionJoiner<'_> {
    fn context(&self) -> Result<JoinerContext, LanError> {
        self.session
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

    fn commit_link(&self, link_id: [u8; 16], key: &LinkKey) -> Result<(), LanError> {
        self.session
            .mutate(|ctx| {
                ctx.check_cancel()?;
                let now = ctx.now();
                let mut w = ctx.open.vault.write()?;
                w.add_lan_link(link_id, key, self.label, now)?;
                w.commit()?;
                Ok(())
            })
            .map_err(lan)
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
