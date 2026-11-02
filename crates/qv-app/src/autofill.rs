// SPDX-License-Identifier: AGPL-3.0-or-later

//! Autofill handoff state (0009 §4.4). A request arrives through native glue
//! while the vault is normally locked. It waits unbound (at most
//! [`REQUEST_TTL`]); unlocking binds it to that lock generation and opens the
//! autofill screen. Any later lock cancels a bound request. Values leave only
//! for an explicitly chosen candidate, through [`AutofillSink::complete`].
use crate::controller::{Controller, Phase, State};
use crate::workspace::Screen;
use qv_core::SecretBytes;
use qv_core::platform::autofill::{REQUEST_TTL, Requester, Roles};
use std::sync::OnceLock;
use std::time::Instant;

/// Native completion side; Android implements it.
pub(crate) trait AutofillSink: Send + Sync {
    /// Hand the chosen values to the waiting OS request; false if it is gone.
    fn complete(
        &self,
        native: i64,
        username: Option<&SecretBytes>,
        password: Option<&SecretBytes>,
    ) -> bool;
    /// Abandon a request; a completed result is unaffected.
    fn cancel(&self, native: i64);
}
struct NoSink;
impl AutofillSink for NoSink {
    fn complete(&self, _: i64, _: Option<&SecretBytes>, _: Option<&SecretBytes>) -> bool {
        false
    }
    fn cancel(&self, _: i64) {}
}
static SINK: OnceLock<Box<dyn AutofillSink>> = OnceLock::new();
/// Install the native sink once (Android startup or a test recorder).
#[cfg(any(test, all(feature = "desktop", target_os = "android")))]
pub(crate) fn set_sink(sink: Box<dyn AutofillSink>) {
    let _ = SINK.set(sink);
}
pub(crate) fn sink() -> &'static dyn AutofillSink {
    SINK.get().map_or(&NoSink, |s| s.as_ref())
}

/// One OS request awaiting the user's choice.
pub(crate) struct Pending {
    pub(crate) native: i64,
    pub(crate) requester: Requester,
    pub(crate) roles: Roles,
    offered: Instant,
    /// The lock generation it was bound to after unlock.
    pub(crate) bound: Option<u64>,
}
impl Pending {
    fn expired(&self) -> bool {
        self.bound.is_none() && self.offered.elapsed() >= REQUEST_TTL
    }
}

/// Requester text for the lock screen and autofill screen. Package names and
/// origins are OS/browser metadata, not vault data.
pub fn describe(requester: &Requester) -> String {
    match requester {
        Requester::App(app) => format!(
            "App {} (signing certificate verified by Android)",
            app.package.as_str()
        ),
        Requester::Web { browser, origin } => format!(
            "Website {} in {}",
            origin.display(),
            browser.package.as_str()
        ),
    }
}

/// What the autofill screen shows about the bound request.
pub struct AutofillView {
    /// Who will receive the values.
    pub label: String,
    /// The requester, for candidate queries.
    pub requester: Requester,
    /// App request: linking is possible.
    pub app: Option<(String, String)>,
}

/// Bind an unbound, unexpired request to the newly unlocked workspace.
pub(crate) fn bind(s: &mut State) {
    if s.autofill.as_ref().is_some_and(Pending::expired) {
        if let Some(old) = s.autofill.take() {
            sink().cancel(old.native);
        }
        return;
    }
    if s.phase != Phase::Unlocked {
        return;
    }
    let lock_gen = s.lock_gen;
    let Some(pending) = s.autofill.as_mut().filter(|p| p.bound.is_none()) else {
        return;
    };
    pending.bound = Some(lock_gen);
    if let Some(ws) = s.workspace.as_mut() {
        ws.go(Screen::Autofill);
        s.epoch = s.epoch.wrapping_add(1);
        s.revision = s.revision.wrapping_add(1);
    }
}

/// On every lock: a bound request is cancelled; an unbound one may wait for
/// the unlock it is asking for, until it expires.
pub(crate) fn on_lock(s: &mut State) {
    if s.autofill
        .as_ref()
        .is_some_and(|p| p.bound.is_some() || p.expired())
        && let Some(old) = s.autofill.take()
    {
        sink().cancel(old.native);
    }
}

impl Controller {
    /// A validated native request. It replaces (and cancels) any earlier one.
    #[cfg(any(test, all(feature = "desktop", target_os = "android")))]
    pub(crate) fn autofill_offer(&self, native: i64, requester: Requester, roles: Roles) {
        let mut s = self.state();
        if let Some(old) = s.autofill.take() {
            sink().cancel(old.native);
        }
        s.autofill = Some(Pending {
            native,
            requester,
            roles,
            offered: Instant::now(),
            bound: None,
        });
        bind(&mut s);
        s.revision = s.revision.wrapping_add(1);
    }
    /// Lock-screen notice for a request that still waits for unlock.
    pub fn autofill_banner(&self) -> Option<String> {
        let s = self.state();
        s.autofill
            .as_ref()
            .filter(|p| p.bound.is_none() && !p.expired())
            .map(|p| {
                format!(
                    "Autofill request: {}. Unlock to choose a login.",
                    describe(&p.requester)
                )
            })
    }
    /// The request bound to the current unlocked session.
    pub(crate) fn autofill_bound(&self) -> Option<(i64, Requester, Roles)> {
        let s = self.state();
        s.autofill
            .as_ref()
            .filter(|p| s.phase == Phase::Unlocked && p.bound == Some(s.lock_gen))
            .map(|p| (p.native, p.requester.clone(), p.roles))
    }
    /// Autofill screen data, if a request is bound to this session.
    pub fn autofill_view(&self) -> Option<AutofillView> {
        let (_, requester, _) = self.autofill_bound()?;
        let app = match &requester {
            Requester::App(app) => Some((
                app.package.as_str().to_owned(),
                app.signers
                    .digests()
                    .iter()
                    .map(|d| {
                        d[..6]
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    })
                    .collect::<Vec<_>>()
                    .join(", "),
            )),
            Requester::Web { .. } => None,
        };
        Some(AutofillView {
            label: describe(&requester),
            requester,
            app,
        })
    }
    /// Abandon the bound request and return to the vault.
    pub(crate) fn autofill_cancel(&self) {
        let mut s = self.state();
        if let Some(old) = s.autofill.take() {
            sink().cancel(old.native);
        }
        if let Some(ws) = s.workspace.as_mut()
            && ws.screen == Screen::Autofill
        {
            ws.go(Screen::Browse(None));
            s.epoch = s.epoch.wrapping_add(1);
        }
        s.revision = s.revision.wrapping_add(1);
    }
    /// The bound request was completed natively; forget it without cancelling.
    pub(crate) fn autofill_completed(s: &mut State, native: i64) {
        if s.autofill.as_ref().is_some_and(|p| p.native == native) {
            s.autofill = None;
        }
    }
    /// Whether the native autofill service is enabled for this device.
    pub fn autofill_available(&self) -> bool {
        #[cfg(all(feature = "desktop", target_os = "android"))]
        {
            crate::android::autofill_available()
        }
        #[cfg(not(all(feature = "desktop", target_os = "android")))]
        {
            false
        }
    }
}

#[cfg(test)]
impl Controller {
    /// Test-only: age a waiting request instead of sleeping for the TTL.
    pub(crate) fn age_autofill(&self, by: std::time::Duration) {
        if let Some(p) = self.state().autofill.as_mut() {
            p.offered = p.offered.checked_sub(by).unwrap_or(p.offered);
        }
    }
}
