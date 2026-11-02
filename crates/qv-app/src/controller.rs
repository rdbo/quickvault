// SPDX-License-Identifier: AGPL-3.0-or-later

//! Protected forms and epoch-scoped operations shared by Android and Linux.
use ctutils::CtEq;
use qv_core::platform::{LockEvent, PlatformServices, Watch};
use qv_core::{
    AnchorDir, CancelToken, Core, CoreConfig, CoreError, MasterPassword, PasswordVerdict,
    RecoveryPhrase, SecretBytes, Session, SnapshotDir, SnapshotPolicy,
};
use std::path::PathBuf;
use std::sync::{
    Arc, Mutex, MutexGuard,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

/// One bounded input control. Values never enter application String state.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InputField {
    /// Local vault path.
    Path,
    /// Vault name.
    Name,
    /// Master password.
    Password,
    /// Password confirmation.
    Repeat,
    /// Recovery phrase.
    Phrase,
    /// First requested recovery word.
    Word0,
    /// Second requested recovery word.
    Word1,
    /// Third requested recovery word.
    Word2,
}
impl InputField {
    fn index(self) -> usize {
        self as usize
    }
}
/// Public controller outcome without secret, path or OS payloads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppError {
    /// Existing redacted core failure.
    Core(CoreError),
    /// Invalid or oversized form input.
    InvalidInput,
    /// One operation is already running.
    Busy,
    /// Explicit acknowledgement is required.
    Consent,
    /// Weak-password cooldown and confirmation required.
    WeakPassword,
    /// Required lifecycle monitoring cannot be established.
    LockMonitoring,
    /// Private application storage could not be established.
    PrivateStorage,
    /// Another process owns this application's private state directory.
    AlreadyRunning,
    /// Required platform service is unavailable.
    Unavailable,
    /// The item has conflicting versions; choose one first.
    Conflict,
    /// The clipboard backend is unavailable on this system.
    ClipboardUnavailable,
    /// The stored value is larger than the app's edit bound; use the CLI.
    TooLargeForApp,
    /// An interrupted key rotation must be finished before unlocking.
    RotationPending,
    /// The native autofill request is no longer waiting.
    AutofillExpired,
}
impl AppError {
    /// Fixed user-facing text.
    pub fn message(self) -> &'static str {
        match self {
            Self::Core(CoreError::Store(qv_core::StoreError::WrongPassword)) => {
                "The password or recovery phrase is incorrect."
            }
            Self::Core(CoreError::Store(qv_core::StoreError::Integrity)) => {
                "The vault failed its integrity check. Keep the original and recover from a verified backup."
            }
            Self::Core(CoreError::Store(
                qv_core::StoreError::NoAnchor | qv_core::StoreError::Rollback,
            )) => {
                "The local anchor is missing or mismatched. Use explicit recovery to inspect this file."
            }
            Self::Core(CoreError::Conflict) | Self::Conflict => {
                "This item has conflicting versions. Resolve the conflict before using it here."
            }
            Self::Core(CoreError::SnapshotOverBudget { .. }) => {
                "The mandatory recovery snapshot does not fit the snapshot budget. Nothing was changed."
            }
            Self::Core(CoreError::Cancelled) => "The operation was cancelled.",
            Self::Core(_) => {
                "The vault operation could not be completed. Check protection status and the selected vault."
            }
            Self::InvalidInput => {
                "Check the input bounds, password confirmation, or recovery words."
            }
            Self::Busy => "An operation is still finishing. Please wait.",
            Self::Consent => "Acknowledge the displayed protection limits before opening a vault.",
            Self::WeakPassword => {
                "This password is weak and could be guessed by an attacker who obtains your vault file. Create the vault anyway?"
            }
            Self::LockMonitoring => {
                "OS lock and sleep monitoring is unavailable. Review the protection status before trying again."
            }
            Self::PrivateStorage => {
                "QuickVault could not establish private local storage. Check its ownership and permissions, then try again."
            }
            Self::AlreadyRunning => {
                "QuickVault is already running for this private state directory. Switch to that window, or close it before reopening."
            }
            Self::Unavailable => "Required OS protection or private storage is unavailable.",
            Self::ClipboardUnavailable => {
                "Copying is unavailable: no supported clipboard was found on this system."
            }
            Self::TooLargeForApp => {
                "This value is larger than the app can edit. View or copy it here, and edit it with the CLI."
            }
            Self::RotationPending => {
                "An interrupted key rotation was found. Finish or roll it back before unlocking."
            }
            Self::AutofillExpired => {
                "The autofill request expired or was cancelled. Start it again from the other app."
            }
        }
    }
}
impl From<CoreError> for AppError {
    fn from(e: CoreError) -> Self {
        Self::Core(e)
    }
}
/// The screen currently authorized by Rust state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// No unlocked vault.
    Locked,
    /// Awaiting weak-password confirmation.
    WeakPassword,
    /// A vault task is running.
    Opening,
    /// Awaiting recovery-word confirmation.
    Phrase,
    /// Awaiting explicit anchor baseline adoption.
    Recovery,
    /// A current vault session is ready.
    Unlocked,
    /// A prepared key rotation awaits confirmation of its new phrase. The old
    /// session is consumed; cancelling changes nothing.
    Rotation,
}
/// Foundation workflow selected on the locked screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Password unlock.
    Unlock,
    /// Create a new local vault.
    Create,
    /// Phrase or anchor recovery.
    Recover,
}
/// A current form generation; late input cannot affect a new generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FormEpoch(pub u64);
/// Redacted UI snapshot. Phrase display is a separate protected operation.
#[derive(PartialEq, Eq)]
pub struct View {
    /// Current generation.
    pub epoch: FormEpoch,
    /// Current screen.
    pub phase: Phase,
    /// Selected foundation workflow.
    pub mode: Mode,
    /// One operation may run, even if a cancelled KDF is still finishing.
    pub busy: bool,
    /// Fixed status text.
    pub status: &'static str,
    /// A data-free failure.
    pub error: Option<AppError>,
    /// Seconds remaining before weak-password confirmation is permitted.
    pub weak_seconds: u64,
    /// Requested word positions, one-based for display.
    pub positions: [usize; 3],
    /// A fair master password receives an inline warning.
    pub fair_warning: bool,
    /// A generated six-word suggestion is currently visible.
    pub suggestion_visible: bool,
    /// Current process and memory-lock hardening is reduced.
    pub reduced_process: bool,
    /// Linux OS lock/sleep notifications are unavailable; manual/idle locks work.
    pub reduced_lifecycle: bool,
    /// Workspace revision; any renderer-visible unlocked change advances it.
    pub revision: u64,
    /// Time-dependent workspace display (reveal and clipboard countdowns).
    pub live: crate::workspace::Live,
    /// The prepared rotation's new phrase is confirmed.
    pub rotation_confirmed: bool,
    /// An interrupted rotation must be finished before unlocking.
    pub resume: Option<Resume>,
    /// Baseline adoption awaits over-budget consent for this many bytes.
    pub over_budget: Option<u64>,
}
/// Core-backed foundation actions. None grants arbitrary IO or crypto access.
#[derive(Clone, Copy)]
pub enum Action {
    /// Generate an ephemeral six-word master-password suggestion.
    SuggestPassword,
    /// Create a new vault.
    Create,
    /// Confirm a weak creation password after cooldown.
    ConfirmWeak,
    /// Unlock with a password.
    Unlock,
    /// Explicit hardware-authenticated quick unlock; never a fallback.
    QuickUnlock,
    /// Open with the recovery phrase.
    Recover,
    /// Inspect a missing or mismatched anchor using a password.
    RecoverPassword,
    /// Confirm three recovery words.
    ConfirmPhrase,
    /// Record explicit phrase-confirmation skip.
    SkipPhrase,
    /// Snapshot then accept a new recovery baseline.
    AdoptBaseline,
    /// Accept the baseline after consenting to an over-budget recovery snapshot.
    AdoptBaselineOverBudget,
    /// Confirm three words of a prepared rotation's new phrase.
    ConfirmRotation,
    /// Install the confirmed rotation.
    InstallRotation,
    /// Drop the prepared rotation; nothing changes.
    CancelRotation,
    /// Finish an interrupted rotation by completing it.
    ResumeComplete,
    /// Finish an interrupted rotation by rolling it back.
    ResumeRollback,
}
/// An interrupted rotation found before unlocking, with the passwords it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Resume {
    /// The previous master password is needed.
    pub old: bool,
    /// The rotation's new master password is needed.
    pub new: bool,
}
pub(crate) struct State {
    pub(crate) epoch: u64,
    pub(crate) phase: Phase,
    mode: Mode,
    inputs: [SecretBytes; 8],
    pub(crate) cancel: CancelToken,
    pub(crate) session: Option<Arc<Session>>,
    phrase: Option<RecoveryPhrase>,
    positions: [usize; 3],
    pub(crate) error: Option<AppError>,
    pub(crate) status: &'static str,
    pub(crate) active: Instant,
    weak_until: Option<Instant>,
    fair_warning: bool,
    suggestion: Option<qv_core::Generated>,
    suggestion_until: Option<Instant>,
    /// Advanced only by a lock; worker results apply to the same generation.
    pub(crate) lock_gen: u64,
    /// A vault worker for this lock generation has not reported yet.
    pub(crate) op_running: bool,
    /// The open vault's path, for operations that reopen it (snapshot restore).
    pub(crate) vault_path: Option<PathBuf>,
    /// The vault was opened with the recovery phrase; offer a new password.
    recovered_with_phrase: bool,
    /// Unlocked screens; dropped (and its holds cancelled) on every lock.
    pub(crate) workspace: Option<crate::workspace::Workspace>,
    /// Changes whenever renderer-visible workspace state changes.
    pub(crate) revision: u64,
    /// A rotation worker consumed the session; its own lock is expected.
    pub(crate) rotating: bool,
    /// A prepared rotation awaiting phrase confirmation.
    pub(crate) rotation: Option<Box<qv_core::Rotation>>,
    rotation_confirmed: bool,
    /// An interrupted rotation for this path must be finished first.
    resume: Option<(PathBuf, Resume)>,
    /// Baseline adoption needs consent for this many over-budget bytes.
    over_budget: Option<u64>,
    /// Unverified header read before unlocking (the session then holds the file).
    pub(crate) about: Option<crate::views::AboutView>,
    /// A native autofill request (0009 §4.4); see [`crate::autofill`].
    pub(crate) autofill: Option<crate::autofill::Pending>,
}
impl State {
    fn clear_inputs(&mut self) {
        self.suggestion = None;
        self.suggestion_until = None;
        for input in &mut self.inputs {
            *input = SecretBytes::zeroed(0);
        }
    }
    pub(crate) fn invalidate(&mut self) {
        let creating = self.phase == Phase::Opening && self.status == "Creating vault…";
        let unconfirmed = self.phase == Phase::Phrase;
        let rotation = self.phase == Phase::Rotation;
        let interrupted = self.op_running;
        self.lock_gen = self.lock_gen.wrapping_add(1);
        #[cfg(all(feature = "desktop", target_os = "android"))]
        crate::android::forget_pick();
        self.op_running = false;
        self.rotating = false;
        self.rotation = None;
        self.rotation_confirmed = false;
        self.resume = None;
        self.over_budget = None;
        self.about = None;
        self.workspace = None;
        self.vault_path = None;
        self.recovered_with_phrase = false;
        self.revision = self.revision.wrapping_add(1);
        self.cancel.cancel();
        self.cancel = CancelToken::new();
        self.epoch = self.epoch.wrapping_add(1);
        self.clear_inputs();
        self.phrase = None;
        self.weak_until = None;
        self.fair_warning = false;
        if let Some(session) = self.session.take() {
            session.lock();
        }
        self.phase = Phase::Locked;
        self.mode = Mode::Unlock;
        self.status = if creating {
            "Locked. A vault created before cancellation may remain."
        } else if rotation {
            "Locked. The prepared key rotation was cancelled; nothing changed."
        } else if unconfirmed {
            "Locked before the recovery phrase was confirmed. After unlocking, use Settings → Show recovery phrase."
        } else if interrupted {
            "Locked. An operation was in progress; it may have completed."
        } else {
            "Locked"
        };
        self.error = None;
        crate::autofill::on_lock(self);
    }
}
pub(crate) struct Inner {
    pub(crate) base: PathBuf,
    pub(crate) services: Arc<dyn PlatformServices>,
    state: Mutex<State>,
    pub(crate) working: AtomicBool,
    /// Worker permits released; part of the view revision because reads that
    /// were refused while busy become available (lock-free, so a guard may be
    /// dropped while the state lock is held).
    released: AtomicU64,
    monitoring: AtomicBool,
    watch: Mutex<Option<Box<dyn Watch>>>,
    #[cfg(feature = "validation")]
    preview: AtomicBool,
    #[cfg(feature = "validation")]
    pub(crate) fixture: AtomicBool,
}
/// Shared application controller; event callbacks contain only a weak reference.
#[derive(Clone)]
pub struct Controller(pub(crate) Arc<Inner>);
impl PartialEq for Controller {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
pub(crate) struct Worker(pub(crate) Arc<Inner>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.working.store(false, Ordering::SeqCst);
        self.0.released.fetch_add(1, Ordering::SeqCst);
    }
}
enum Opened {
    Created(qv_core::Created, [usize; 3], PathBuf),
    Session(Session, PathBuf, bool, Option<crate::views::AboutView>),
    Resume(PathBuf, Resume),
}
impl Controller {
    /// Attempt lifecycle monitoring before accepting input, reporting its
    /// absence as reduced protection on Linux. Other platforms require it.
    /// `base` is a private app directory verified by platform startup.
    pub fn new(base: PathBuf, services: Arc<dyn PlatformServices>) -> Result<Self, AppError> {
        qv_core::harden();
        let inner = Arc::new(Inner {
            base,
            services,
            state: Mutex::new(State {
                epoch: 0,
                phase: Phase::Locked,
                mode: Mode::Unlock,
                inputs: std::array::from_fn(|_| SecretBytes::zeroed(0)),
                cancel: CancelToken::new(),
                session: None,
                phrase: None,
                positions: [0; 3],
                error: None,
                status: "Locked",
                active: Instant::now(),
                weak_until: None,
                fair_warning: false,
                suggestion: None,
                suggestion_until: None,
                lock_gen: 0,
                op_running: false,
                vault_path: None,
                recovered_with_phrase: false,
                workspace: None,
                revision: 0,
                rotating: false,
                rotation: None,
                rotation_confirmed: false,
                resume: None,
                over_budget: None,
                about: None,
                autofill: None,
            }),
            working: AtomicBool::new(false),
            released: AtomicU64::new(0),
            monitoring: AtomicBool::new(false),
            watch: Mutex::new(None),
            #[cfg(feature = "validation")]
            preview: AtomicBool::new(false),
            #[cfg(feature = "validation")]
            fixture: AtomicBool::new(false),
        });
        let weak = Arc::downgrade(&inner);
        let watch = inner.services.lifecycle().watch(Arc::new(move |event| {
            if let Some(inner) = weak.upgrade() {
                if event == LockEvent::ProtectionLost {
                    inner.monitoring.store(false, Ordering::SeqCst);
                }
                Controller(inner).lock();
            }
        }));
        #[cfg(target_os = "linux")]
        let watch = watch.ok();
        #[cfg(not(target_os = "linux"))]
        let watch = Some(watch.map_err(|_| AppError::LockMonitoring)?);
        inner.monitoring.store(watch.is_some(), Ordering::SeqCst);
        *inner.watch.lock().unwrap_or_else(|p| p.into_inner()) = watch;
        Ok(Self(inner))
    }
    /// Whether this controller is a synthetic read-only preview.
    #[cfg(feature = "validation")]
    pub fn is_preview(&self) -> bool {
        self.0.preview.load(Ordering::SeqCst)
    }

    /// Read-only synthetic UI preview. It cannot create or open a vault.
    #[cfg(feature = "validation")]
    pub fn preview() -> Result<Self, AppError> {
        use qv_core::platform::*;
        struct Preview;
        struct PreviewWatch;
        impl Watch for PreviewWatch {}
        impl Lifecycle for Preview {
            fn watch(&self, _: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
                Ok(Box::new(PreviewWatch))
            }
        }
        impl PlatformServices for Preview {
            fn status(&self) -> ProtectionStatus {
                ProtectionStatus {
                    storage: Evidence::Unknown,
                    swap: Evidence::Unknown,
                    hibernation: Evidence::Unknown,
                    lifecycle: false,
                    clipboard: false,
                    quick_unlock: false,
                }
            }
            fn lifecycle(&self) -> &dyn Lifecycle {
                self
            }
            fn clipboard(&self) -> &dyn Clipboard {
                &Unavailable
            }
            fn secure_input(&self) -> &dyn SecureInput {
                &Unavailable
            }
            fn keystore(&self) -> &dyn Keystore {
                &Unavailable
            }
        }
        let controller = Self::new(PathBuf::new(), Arc::new(Preview))?;
        controller.0.preview.store(true, Ordering::SeqCst);
        Ok(controller)
    }
    /// Full-flow synthetic fixture. It owns a newly created private temporary
    /// root and simulates only OS lifecycle; vault crypto/storage are real.
    #[cfg(feature = "validation")]
    pub fn validation_fixture() -> Result<Self, AppError> {
        use qv_core::platform::*;
        struct Fixture;
        struct Guard;
        impl Watch for Guard {}
        impl Lifecycle for Fixture {
            fn watch(&self, _: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
                Ok(Box::new(Guard))
            }
        }
        impl PlatformServices for Fixture {
            fn status(&self) -> ProtectionStatus {
                ProtectionStatus {
                    storage: Evidence::Unknown,
                    swap: Evidence::Unknown,
                    hibernation: Evidence::Unknown,
                    lifecycle: true,
                    clipboard: false,
                    quick_unlock: false,
                }
            }
            fn lifecycle(&self) -> &dyn Lifecycle {
                self
            }
            fn clipboard(&self) -> &dyn Clipboard {
                &Unavailable
            }
            fn secure_input(&self) -> &dyn SecureInput {
                &Unavailable
            }
            fn keystore(&self) -> &dyn Keystore {
                &Unavailable
            }
        }
        let base = std::env::current_dir()
            .map_err(|_| AppError::Unavailable)?
            .join(format!(".qv-ui-flow-{}", std::process::id()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&base).map_err(|_| AppError::Unavailable)?;
        let services: Arc<dyn PlatformServices> = Arc::new(Fixture);
        #[cfg(target_os = "linux")]
        let services: Arc<dyn PlatformServices> =
            if std::env::var_os("QV_TEST_REAL_LINUX_PLATFORM").is_some_and(|value| value == "1") {
                Arc::new(LinuxPlatform::default())
            } else {
                services
            };
        let controller = Self::new(base, services)?;
        std::fs::write(
            controller.0.base.join("source.bin"),
            b"synthetic-attachment-canary",
        )
        .map_err(|_| AppError::Unavailable)?;
        private_dir(&controller.0.base.join("exports"))?;
        controller.0.fixture.store(true, Ordering::SeqCst);
        Ok(controller)
    }
    #[cfg(feature = "validation")]
    pub(crate) fn is_fixture(&self) -> bool {
        self.0.fixture.load(Ordering::SeqCst)
    }
    #[cfg(feature = "validation")]
    pub(crate) fn finish_fixture(&self, passed: bool) -> ! {
        if !self.is_fixture() {
            std::process::exit(2)
        }
        self.lock();
        #[cfg(target_os = "linux")]
        let files_safe = qv_core::platform::files::Input::open(
            &self.0.base.join("source.bin"),
            1024,
            Arc::new(|| false),
        )
        .is_ok();
        #[cfg(not(target_os = "linux"))]
        let files_safe = false;
        let attachment_ok = !files_safe
            || std::fs::read(self.0.base.join("output.bin"))
                .is_ok_and(|b| b == b"synthetic-attachment-canary");
        let passed = passed && attachment_ok;
        let cleaned = std::fs::remove_dir_all(&self.0.base).is_ok();
        if passed && cleaned {
            println!("full UI flow passed");
            std::process::exit(0)
        }
        eprintln!("full UI flow failed (synthetic fixture)");
        std::process::exit(1)
    }
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        match self.0.state.lock() {
            Ok(s) => s,
            Err(p) => {
                let mut s = p.into_inner();
                s.invalidate();
                s.error = Some(AppError::Unavailable);
                s
            }
        }
    }
    /// Current platform protection; configuration uncertainty is never hidden.
    pub fn protection(&self) -> qv_core::platform::ProtectionStatus {
        let mut status = self.0.services.status();
        status.lifecycle &= self.0.monitoring.load(Ordering::SeqCst);
        status
    }
    /// Snapshot polls core locking as well as local inactivity, so OS callbacks
    /// and session auto-locks destroy renderer-visible state without user action.
    pub fn snapshot(&self) -> View {
        let mut s = self.state();
        let idle = if matches!(s.phase, Phase::Phrase | Phase::Rotation)
            || s.workspace
                .as_ref()
                .is_some_and(crate::workspace::Workspace::shows_phrase)
        {
            crate::workspace::PHRASE_IDLE
        } else {
            Duration::from_secs(60)
        };
        if s.active.elapsed() >= idle
            && (s.phase != Phase::Locked
                || s.inputs.iter().any(|v| !v.is_empty())
                || s.suggestion.is_some())
            || (!s.rotating && s.session.as_ref().is_some_and(|v| v.is_locked()))
        {
            s.invalidate();
        }
        let remaining = s
            .weak_until
            .map(|t| t.saturating_duration_since(Instant::now()))
            .unwrap_or_default();
        let (revision, live) = crate::workspace::live(&mut s);
        View {
            revision: revision.wrapping_add(self.0.released.load(Ordering::SeqCst)),
            live,
            epoch: FormEpoch(s.epoch),
            phase: s.phase,
            mode: s.mode,
            busy: self.0.working.load(Ordering::SeqCst),
            status: s.status,
            error: s.error,
            weak_seconds: remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0),
            positions: s.positions.map(|n| n + 1),
            reduced_process: qv_core::harden().is_reduced(),
            reduced_lifecycle: cfg!(target_os = "linux")
                && !self.0.monitoring.load(Ordering::SeqCst),
            fair_warning: s.fair_warning,
            suggestion_visible: s.suggestion.is_some()
                && s.suggestion_until.is_some_and(|t| Instant::now() < t),
            rotation_confirmed: s.rotation_confirmed,
            resume: s.resume.as_ref().map(|r| r.1),
            over_budget: s.over_budget,
        }
    }
    /// Select a workflow, clearing the old form and invalidating late events.
    pub fn select_mode(&self, epoch: FormEpoch, mode: Mode) {
        let mut s = self.state();
        if s.epoch == epoch.0 && !self.0.working.load(Ordering::SeqCst) {
            s.invalidate();
            s.mode = mode;
            s.active = Instant::now();
        }
    }
    /// Transfer bounded framework input to protected Rust storage and clear the
    /// mutable intermediary even for invalid or stale input.
    pub fn input(&self, epoch: FormEpoch, field: InputField, value: &mut String) {
        let mut s = self.state();
        let limit = if matches!(field, InputField::Path) {
            4096
        } else {
            1024
        };
        if epoch.0 == s.epoch && !self.0.working.load(Ordering::SeqCst) {
            if value.len() > limit || value.contains('\0') {
                s.clear_inputs();
                s.epoch = s.epoch.wrapping_add(1);
                s.error = Some(AppError::InvalidInput);
            } else {
                let mut protected = SecretBytes::zeroed(value.len());
                protected
                    .expose_secret_mut()
                    .copy_from_slice(value.as_bytes());
                s.inputs[field.index()] = protected;
                s.active = Instant::now();
                s.error = None;
                if matches!(field, InputField::Password | InputField::Repeat) {
                    s.weak_until = None;
                    if s.phase == Phase::WeakPassword {
                        s.phase = Phase::Locked;
                    }
                }
            }
        }
        value.zeroize();
        value.clear();
    }
    /// Copy the phrase only for the current confirmation screen. Application
    /// state never holds a plaintext String; the trusted renderer has best-effort
    /// copies that cannot be deterministically erased.
    pub fn phrase(&self, epoch: FormEpoch) -> Option<SecretBytes> {
        let s = self.state();
        if s.epoch != epoch.0 {
            return None;
        }
        let phrase = match s.phase {
            Phase::Phrase => s.phrase.as_ref()?.expose_secret().as_bytes(),
            Phase::Rotation => s.rotation.as_ref()?.phrase().expose_secret().as_bytes(),
            _ => return None,
        };
        let mut copy = SecretBytes::zeroed(phrase.len());
        copy.expose_secret_mut().copy_from_slice(phrase);
        Some(copy)
    }
    /// Short-lived generated suggestion, only after an explicit action. The
    /// protected original remains until the form ends to preserve exact entropy.
    pub fn suggestion(&self, epoch: FormEpoch) -> Option<SecretBytes> {
        let s = self.state();
        if s.epoch != epoch.0 || s.suggestion_until.is_none_or(|t| Instant::now() >= t) {
            return None;
        }
        let value = s.suggestion.as_ref()?.expose_secret().as_bytes();
        let mut out = SecretBytes::zeroed(value.len());
        out.expose_secret_mut().copy_from_slice(value);
        Some(out)
    }
    /// Cancel work, expire forms and drop keys/phrase. A running KDF keeps its
    /// single worker permit until it returns; repeated cancellation cannot fan out.
    pub fn lock(&self) {
        self.state().invalidate();
    }
    pub(crate) fn core(&self) -> Result<Core, AppError> {
        for name in ["anchors", "snapshots", "vaults"] {
            private_dir(&self.0.base.join(name))?;
        }
        let anchors = AnchorDir::open(&self.0.base.join("anchors")).map_err(CoreError::from)?;
        let snapshots =
            SnapshotDir::open(&self.0.base.join("snapshots")).map_err(CoreError::from)?;
        let core =
            Core::new(CoreConfig::new(anchors).with_snapshots(SnapshotPolicy::new(snapshots)));
        #[cfg(target_os = "linux")]
        let core = core.with_linux_platform(self.0.services.clone(), true);
        #[cfg(not(target_os = "linux"))]
        let core = core.with_platform(self.0.services.clone(), true);
        Ok(core)
    }
    /// Dispatch only an action allowed on this current Rust screen.
    pub fn submit(
        &self,
        epoch: FormEpoch,
        action: Action,
        acknowledged: bool,
    ) -> Result<(), AppError> {
        #[cfg(feature = "validation")]
        if self.0.preview.load(Ordering::SeqCst) {
            return Err(AppError::Unavailable);
        }

        if matches!(
            action,
            Action::Create
                | Action::ConfirmWeak
                | Action::Unlock
                | Action::QuickUnlock
                | Action::Recover
                | Action::RecoverPassword
        ) {
            // Re-arm the app-level subscription before each pending unlock/KDF.
            // The session's own watcher does not yet exist during that work.
            let weak = Arc::downgrade(&self.0);
            let next = self.0.services.lifecycle().watch(Arc::new(move |event| {
                if let Some(inner) = weak.upgrade() {
                    if event == LockEvent::ProtectionLost {
                        inner.monitoring.store(false, Ordering::SeqCst);
                    }
                    Controller(inner).lock();
                }
            }));
            let was_monitoring = self.0.monitoring.swap(next.is_ok(), Ordering::SeqCst);
            #[cfg(not(target_os = "linux"))]
            let missing_required = next.is_err();
            #[cfg(target_os = "linux")]
            let missing_required = false;
            let next = next.ok();
            let previous = std::mem::replace(
                &mut *self.0.watch.lock().unwrap_or_else(|p| p.into_inner()),
                next,
            );
            drop(previous);
            if missing_required || (was_monitoring && !self.0.monitoring.load(Ordering::SeqCst)) {
                // A changed capability invalidates earlier form consent. Linux
                // can retry explicitly with the reduced status now visible.
                let mut s = self.state();
                s.invalidate();
                s.error = Some(AppError::LockMonitoring);
                return Err(AppError::LockMonitoring);
            }
        }

        let mut s = self.state();
        if epoch.0 != s.epoch {
            return Err(AppError::InvalidInput);
        }
        if self.0.working.load(Ordering::SeqCst) {
            return Err(AppError::Busy);
        }
        s.active = Instant::now();
        if matches!(action, Action::SuggestPassword) {
            if s.phase != Phase::Locked {
                return Err(AppError::InvalidInput);
            }
            s.suggestion = Some(qv_core::generate(&qv_core::GeneratorSettings::Passphrase(
                qv_core::PassphraseSettings::default(),
            ))?);
            s.suggestion_until = Some(Instant::now() + Duration::from_secs(30));
            s.error = None;
            return Ok(());
        }
        if matches!(
            action,
            Action::ConfirmRotation | Action::InstallRotation | Action::CancelRotation
        ) {
            if s.phase != Phase::Rotation {
                return Err(AppError::InvalidInput);
            }
            return self.rotation_step(s, action);
        }
        if matches!(action, Action::ResumeComplete | Action::ResumeRollback) {
            if s.phase != Phase::Locked {
                return Err(AppError::InvalidInput);
            }
            return self.resume_step(s, action);
        }
        if matches!(action, Action::ConfirmPhrase) {
            if s.phase != Phase::Phrase {
                return Err(AppError::InvalidInput);
            }
            let phrase = s.phrase.as_ref().ok_or(AppError::InvalidInput)?;
            for (word, index) in [InputField::Word0, InputField::Word1, InputField::Word2]
                .into_iter()
                .zip(s.positions)
            {
                if phrase
                    .confirm_word(index, s.inputs[word.index()].expose_secret())
                    .is_err()
                {
                    s.error = Some(AppError::InvalidInput);
                    s.clear_inputs();
                    s.epoch = s.epoch.wrapping_add(1);
                    return Err(AppError::InvalidInput);
                }
            }
            s.phrase = None;
            s.clear_inputs();
            s.epoch = s.epoch.wrapping_add(1);
            s.phase = Phase::Unlocked;
            s.status = "Vault ready";
            enter_workspace(&mut s);
            return Ok(());
        }
        if matches!(
            action,
            Action::SkipPhrase | Action::AdoptBaseline | Action::AdoptBaselineOverBudget
        ) {
            if matches!(action, Action::AdoptBaselineOverBudget) && s.over_budget.is_none() {
                return Err(AppError::InvalidInput);
            }
            let allow_over = matches!(action, Action::AdoptBaselineOverBudget);
            s.over_budget = None;
            let expected = if matches!(action, Action::SkipPhrase) {
                Phase::Phrase
            } else {
                Phase::Recovery
            };
            if s.phase != expected || !acknowledged {
                return Err(AppError::Consent);
            }
            let session = s.session.clone().ok_or(AppError::InvalidInput)?;
            let token = s.cancel.clone();
            self.0.working.store(true, Ordering::SeqCst);
            let worker = Worker(self.0.clone());
            let controller = self.clone();
            s.clear_inputs();
            s.epoch = s.epoch.wrapping_add(1);
            let next = s.epoch;
            drop(s);
            std::thread::Builder::new()
                .name("qv-app-confirm".into())
                .spawn(move || {
                    let _worker = worker;
                    let mut cleanup_pending = false;
                    let result = if matches!(action, Action::SkipPhrase) {
                        session.record_recovery_skip()
                    } else {
                        session
                            .begin_destructive(allow_over, Some(&token))
                            .and_then(|copy| {
                                session.adopt_baseline()?;
                                cleanup_pending = session.finish_destructive(copy).is_err();
                                Ok(())
                            })
                    };
                    let mut s = controller.state();
                    if s.epoch == next && !token.is_cancelled() {
                        match result {
                            Ok(()) => {
                                s.phrase = None;
                                s.phase = Phase::Unlocked;
                                s.status = if cleanup_pending {
                                    "Baseline accepted; recovery snapshot cleanup is incomplete."
                                } else {
                                    "Vault ready"
                                };
                                s.error = None;
                                enter_workspace(&mut s);
                            }
                            Err(CoreError::SnapshotOverBudget { needed }) => {
                                s.over_budget = Some(needed);
                                s.error =
                                    Some(AppError::Core(CoreError::SnapshotOverBudget { needed }));
                            }
                            Err(e) => {
                                s.error = Some(e.into());
                            }
                        }
                    }
                })
                .map_err(|_| AppError::Unavailable)?;
            return Ok(());
        }
        if !matches!(s.phase, Phase::Locked | Phase::WeakPassword) {
            return Err(AppError::InvalidInput);
        }
        if !acknowledged {
            s.error = Some(AppError::Consent);
            return Err(AppError::Consent);
        }
        if matches!(action, Action::Create | Action::ConfirmWeak) {
            let passwords =
                MasterPassword::from_utf8(s.inputs[InputField::Password.index()].expose_secret())
                    .and_then(|password| {
                        MasterPassword::from_utf8(
                            s.inputs[InputField::Repeat.index()].expose_secret(),
                        )
                        .map(|repeated| (password, repeated))
                    });
            let valid = passwords.as_ref().is_ok_and(|(password, repeated)| {
                password
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(repeated.expose_secret().as_bytes())
                    .to_bool()
            });
            if !valid {
                let mode = s.mode;
                s.invalidate();
                s.mode = mode;
                s.error = Some(AppError::InvalidInput);
                return Err(AppError::InvalidInput);
            }
            let (password, _repeated) = passwords.map_err(|_| AppError::InvalidInput)?;
            let generated = s.suggestion.as_ref().is_some_and(|value| {
                value
                    .expose_secret()
                    .as_bytes()
                    .ct_eq(password.expose_secret().as_bytes())
                    .to_bool()
            });
            let verdict = if generated {
                PasswordVerdict::Accept
            } else {
                qv_core::password_strength(&password).verdict
            };
            match verdict {
                PasswordVerdict::ConfirmWeak => {
                    if !matches!(action, Action::ConfirmWeak)
                        || s.weak_until.is_none_or(|until| Instant::now() < until)
                    {
                        s.weak_until
                            .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
                        s.phase = Phase::WeakPassword;
                        s.error = Some(AppError::WeakPassword);
                        return Err(AppError::WeakPassword);
                    }
                }
                PasswordVerdict::Warn => s.fair_warning = true,
                PasswordVerdict::Accept => {}
            }
        }
        let values = std::mem::replace(
            &mut s.inputs,
            std::array::from_fn(|_| SecretBytes::zeroed(0)),
        );
        s.suggestion = None;
        s.suggestion_until = None;
        s.epoch = s.epoch.wrapping_add(1);
        let next = s.epoch;
        let token = s.cancel.clone();
        s.phase = Phase::Opening;
        s.status = if matches!(action, Action::Create | Action::ConfirmWeak) {
            "Creating vault…"
        } else {
            "Opening vault…"
        };
        s.error = None;
        self.0.working.store(true, Ordering::SeqCst);
        let worker = Worker(self.0.clone());
        let controller = self.clone();
        drop(s);
        std::thread::Builder::new()
            .name("qv-app-vault".into())
            .spawn(move || {
                let _worker = worker;
                let result = controller.open(action, &values, &token);
                controller.complete(next, &token, result);
            })
            .map_err(|_| AppError::Unavailable)?;
        Ok(())
    }
    #[cfg(feature = "desktop")]
    pub(crate) fn perform(&self, epoch: FormEpoch, action: Action, consent: bool) {
        if let Err(error) = self.submit(epoch, action, consent) {
            let mut s = self.state();
            if s.epoch == epoch.0 {
                s.error = Some(error);
            }
        }
    }
    fn open(
        &self,
        action: Action,
        values: &[SecretBytes; 8],
        token: &CancelToken,
    ) -> Result<Opened, AppError> {
        if token.is_cancelled() {
            return Err(CoreError::Cancelled.into());
        }
        let text = |field: InputField| {
            std::str::from_utf8(values[field.index()].expose_secret())
                .map_err(|_| AppError::InvalidInput)
        };
        let path = if text(InputField::Path)?.is_empty() {
            self.0.base.join("vaults/main.qvault")
        } else {
            PathBuf::from(text(InputField::Path)?)
        };
        if !path.is_absolute() {
            return Err(AppError::InvalidInput);
        }
        #[cfg(all(feature = "validation", target_os = "android"))]
        if self.is_fixture() && path != self.0.base.join("vaults/main.qvault") {
            return Err(AppError::InvalidInput);
        }
        let core = self.core()?;
        if !matches!(action, Action::Create | Action::ConfirmWeak)
            && core.rotation_pending(&path).unwrap_or(false)
        {
            let need = core.rotation_passwords(&path)?;
            return Ok(Opened::Resume(
                path,
                Resume {
                    old: need.old,
                    new: need.new,
                },
            ));
        }
        // Read the public header while the file is still free to open.
        let about = crate::views::about(&core, &path).ok();
        match action {
            Action::Create | Action::ConfirmWeak => {
                let password =
                    MasterPassword::from_utf8(values[InputField::Password.index()].expose_secret())
                        .map_err(|_| AppError::InvalidInput)?;
                let name = text(InputField::Name)?;
                let positions = qv_core::confirmation_positions()?;
                Ok(Opened::Created(
                    core.create(
                        &path,
                        &password,
                        if name.is_empty() { "My vault" } else { name },
                    )?,
                    positions,
                    path,
                ))
            }
            Action::QuickUnlock => Ok(Opened::Session(
                core.unlock_quick(&path, Some(token))?,
                path,
                false,
                about,
            )),
            Action::Unlock | Action::RecoverPassword => {
                let password =
                    MasterPassword::from_utf8(values[InputField::Password.index()].expose_secret())
                        .map_err(|_| AppError::InvalidInput)?;
                let session = if matches!(action, Action::RecoverPassword) {
                    core.unlock_for_recovery(&path, &password, Some(token))?.0
                } else {
                    core.unlock(&path, &password, Some(token))?
                };
                Ok(Opened::Session(session, path, false, about))
            }
            Action::Recover => {
                let session = core
                    .unlock_with_phrase(
                        &path,
                        values[InputField::Phrase.index()].expose_secret(),
                        Some(token),
                    )?
                    .0;
                Ok(Opened::Session(session, path, true, about))
            }
            _ => Err(AppError::InvalidInput),
        }
    }
    fn complete(&self, epoch: u64, token: &CancelToken, result: Result<Opened, AppError>) {
        let mut s = self.state();
        if s.epoch != epoch || token.is_cancelled() {
            drop(result);
            return;
        }
        match result {
            Ok(Opened::Created(created, positions, path)) => {
                s.vault_path = Some(path);
                s.session = Some(Arc::new(created.session));
                s.phrase = Some(created.recovery_phrase);
                s.positions = positions;
                s.phase = Phase::Phrase;
                s.status = "Write down your recovery phrase";
            }
            Ok(Opened::Session(session, path, phrase, about)) => {
                s.vault_path = Some(path);
                s.about = about;
                s.recovered_with_phrase = phrase;
                s.phase = if session.is_read_only().unwrap_or(true) {
                    Phase::Recovery
                } else {
                    Phase::Unlocked
                };
                s.status = if s.phase == Phase::Recovery {
                    "Recovery baseline approval required"
                } else {
                    "Vault ready"
                };
                s.session = Some(Arc::new(session));
                enter_workspace(&mut s);
                crate::autofill::bind(&mut s);
            }
            Ok(Opened::Resume(path, need)) => {
                s.phase = Phase::Locked;
                s.status = "An interrupted key rotation was found";
                s.resume = Some((path, need));
                s.error = Some(AppError::RotationPending);
            }
            Err(e) => {
                s.phase = Phase::Locked;
                s.status = "Locked";
                s.error = Some(e);
            }
        }
    }
    /// Move a prepared rotation (the session it consumed is gone) to its
    /// phrase-confirmation phase.
    pub(crate) fn enter_rotation(
        s: &mut State,
        rotation: qv_core::Rotation,
        positions: [usize; 3],
    ) {
        s.rotating = false;
        s.workspace = None;
        if let Some(session) = s.session.take() {
            session.lock();
        }
        s.clear_inputs();
        s.rotation = Some(Box::new(rotation));
        s.rotation_confirmed = false;
        s.positions = positions;
        s.phase = Phase::Rotation;
        s.epoch = s.epoch.wrapping_add(1);
        s.status = "Confirm the new recovery phrase";
        s.error = None;
        s.revision = s.revision.wrapping_add(1);
    }
    fn rotation_step(&self, mut s: MutexGuard<'_, State>, action: Action) -> Result<(), AppError> {
        match action {
            Action::CancelRotation => {
                s.invalidate();
                s.status = "Key rotation cancelled; nothing changed.";
                Ok(())
            }
            Action::ConfirmRotation => {
                let words: Vec<SecretBytes> =
                    [InputField::Word0, InputField::Word1, InputField::Word2]
                        .iter()
                        .map(|w| crate::workspace::protect(s.inputs[w.index()].expose_secret()))
                        .collect::<Result<_, _>>()?;
                let positions = s.positions;
                let rotation = s.rotation.as_mut().ok_or(AppError::InvalidInput)?;
                let mut ok = true;
                for (p, w) in positions.iter().zip(&words) {
                    ok &= rotation
                        .confirm_word(*p, w.expose_secret())
                        .unwrap_or(false);
                }
                s.clear_inputs();
                s.epoch = s.epoch.wrapping_add(1);
                s.rotation_confirmed |= ok;
                if !ok {
                    s.error = Some(AppError::InvalidInput);
                    return Err(AppError::InvalidInput);
                }
                s.error = None;
                Ok(())
            }
            _ => {
                if !s.rotation_confirmed {
                    return Err(AppError::InvalidInput);
                }
                let rotation = s.rotation.take().ok_or(AppError::InvalidInput)?;
                let token = s.cancel.clone();
                let generation = s.lock_gen;
                self.0.working.store(true, Ordering::SeqCst);
                let worker = Worker(self.0.clone());
                s.status = "Installing the key rotation…";
                drop(s);
                let controller = self.clone();
                std::thread::Builder::new()
                    .name("qv-app-rotation".into())
                    .spawn(move || {
                        let _worker = worker;
                        let outcome = rotation.install(Some(&token));
                        let mut s = controller.state();
                        if s.lock_gen != generation {
                            return;
                        }
                        let message = match &outcome {
                            Ok(done) if done.cleanup_pending => {
                                "Key rotation complete; old-generation cleanup remains. Unlock with the new master password and use the new recovery phrase."
                            }
                            Ok(_) => {
                                "Key rotation complete. Unlock with the new master password and use the new recovery phrase."
                            }
                            Err(e) if e.journal_published => {
                                "Key rotation was interrupted after it started. Unlock to finish or roll it back."
                            }
                            Err(_) => "Key rotation failed before it started; nothing changed.",
                        };
                        s.invalidate();
                        s.status = message;
                    })
                    .map_err(|_| AppError::Unavailable)?;
                Ok(())
            }
        }
    }
    fn resume_step(&self, mut s: MutexGuard<'_, State>, action: Action) -> Result<(), AppError> {
        let (path, need) = s.resume.clone().ok_or(AppError::InvalidInput)?;
        let password =
            |field: InputField, needed: bool| -> Result<Option<MasterPassword>, AppError> {
                if !needed {
                    return Ok(None);
                }
                MasterPassword::from_utf8(s.inputs[field.index()].expose_secret())
                    .map(Some)
                    .map_err(|_| AppError::InvalidInput)
            };
        let new = password(InputField::Password, need.new)?;
        let old = password(InputField::Repeat, need.old)?;
        let choice = if matches!(action, Action::ResumeComplete) {
            qv_core::RotationChoice::Complete
        } else {
            qv_core::RotationChoice::RollBack
        };
        let core = self.core()?;
        let token = s.cancel.clone();
        let generation = s.lock_gen;
        s.clear_inputs();
        s.epoch = s.epoch.wrapping_add(1);
        s.status = "Finishing the interrupted key rotation…";
        self.0.working.store(true, Ordering::SeqCst);
        let worker = Worker(self.0.clone());
        drop(s);
        let controller = self.clone();
        std::thread::Builder::new()
            .name("qv-app-resume".into())
            .spawn(move || {
                let _worker = worker;
                let result = (|| -> Result<&'static str, AppError> {
                    let t =
                        core.resume_rotation(&path, old.as_ref(), new.as_ref(), Some(&token))?;
                    drop((old, new));
                    let allowed = match t.state() {
                        qv_core::RotationState::Committed => {
                            choice == qv_core::RotationChoice::Complete
                        }
                        qv_core::RotationState::RollbackPending => {
                            choice == qv_core::RotationChoice::RollBack
                        }
                        _ => true,
                    };
                    if !allowed {
                        return Err(AppError::InvalidInput);
                    }
                    core.finish_rotation(t, choice, Some(&token))?;
                    Ok(match choice {
                        qv_core::RotationChoice::Complete => {
                            "Key rotation complete. Unlock with the new master password."
                        }
                        qv_core::RotationChoice::RollBack => {
                            "Key rotation rolled back. Unlock with the previous master password."
                        }
                    })
                })();
                let mut s = controller.state();
                if s.lock_gen != generation {
                    return;
                }
                match result {
                    Ok(message) => {
                        s.invalidate();
                        s.status = message;
                    }
                    Err(e) => {
                        s.status = "An interrupted key rotation was found";
                        s.error = Some(e);
                    }
                }
            })
            .map_err(|_| AppError::Unavailable)?;
        Ok(())
    }
}
/// Open the unlocked screens once a writable session is ready. A phrase
/// unlock first offers (never forces) a new master password, as `recover` does.
fn enter_workspace(s: &mut State) {
    if s.phase == Phase::Unlocked && s.workspace.is_none() {
        s.workspace = Some(crate::workspace::Workspace::new(s.recovered_with_phrase));
        s.revision = s.revision.wrapping_add(1);
    }
}
/// Create private application directories without changing permissions on an
/// existing path. Native guards/core perform no-follow ownership validation.
pub(crate) fn private_dir(path: &std::path::Path) -> Result<(), AppError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|_| AppError::Unavailable)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path).map_err(|_| AppError::Unavailable)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    // Tests fail loudly on fixture errors; never touch an existing user vault.
    #![allow(clippy::unwrap_used)]
    use super::*;
    use qv_core::platform::*;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    static KDF: Mutex<()> = Mutex::new(());
    const PASSWORD: &str = "K4L!c8vP2zR9qT7W6nM5";
    #[derive(Default)]
    struct Fake {
        callbacks: Arc<Mutex<std::collections::BTreeMap<u64, LockCallback>>>,
        next: AtomicU64,
        unavailable: AtomicBool,
    }
    struct Guard {
        callbacks: Arc<Mutex<std::collections::BTreeMap<u64, LockCallback>>>,
        id: u64,
    }
    impl Watch for Guard {}
    impl Drop for Guard {
        fn drop(&mut self) {
            self.callbacks.lock().unwrap().remove(&self.id);
        }
    }
    impl Lifecycle for Fake {
        fn watch(&self, callback: LockCallback) -> Result<Box<dyn Watch>, PlatformError> {
            if self.unavailable.load(Ordering::SeqCst) {
                return Err(PlatformError::Unavailable);
            }
            let id = self.next.fetch_add(1, Ordering::SeqCst);
            self.callbacks.lock().unwrap().insert(id, callback);
            Ok(Box::new(Guard {
                callbacks: self.callbacks.clone(),
                id,
            }))
        }
    }
    impl PlatformServices for Fake {
        fn status(&self) -> ProtectionStatus {
            ProtectionStatus {
                storage: Evidence::Unknown,
                swap: Evidence::Unknown,
                hibernation: Evidence::Unknown,
                lifecycle: !self.unavailable.load(Ordering::SeqCst),
                clipboard: false,
                quick_unlock: false,
            }
        }
        fn lifecycle(&self) -> &dyn Lifecycle {
            self
        }
        fn clipboard(&self) -> &dyn Clipboard {
            &Unavailable
        }
        fn secure_input(&self) -> &dyn SecureInput {
            &Unavailable
        }
        fn keystore(&self) -> &dyn Keystore {
            &Unavailable
        }
    }
    impl Fake {
        fn event(&self) {
            let callbacks = self
                .callbacks
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect::<Vec<_>>();
            for callback in callbacks {
                callback(LockEvent::ScreenLocked)
            }
        }
    }
    struct Env {
        controller: Controller,
        os: Arc<Fake>,
        dir: PathBuf,
    }
    impl Env {
        fn new() -> Self {
            Self::with_missing_monitor(false)
        }
        fn with_missing_monitor(missing: bool) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "qv-app-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            private_dir(&dir).unwrap();
            let os = Arc::new(Fake::default());
            os.unavailable.store(missing, Ordering::SeqCst);
            let controller = Controller::new(dir.clone(), os.clone()).unwrap();
            Self {
                controller,
                os,
                dir,
            }
        }
        fn fill(&self, field: InputField, value: &str) {
            let mut value = value.to_owned();
            self.controller
                .input(self.controller.snapshot().epoch, field, &mut value);
            assert!(value.is_empty());
        }
        fn wait(&self) {
            let end = Instant::now() + Duration::from_secs(45);
            while self.controller.snapshot().busy && Instant::now() < end {
                std::thread::sleep(Duration::from_millis(10))
            }
            assert!(!self.controller.snapshot().busy);
        }
        fn create(&self) {
            self.fill(InputField::Password, PASSWORD);
            self.fill(InputField::Repeat, PASSWORD);
            self.controller
                .submit(self.controller.snapshot().epoch, Action::Create, true)
                .unwrap();
            self.wait();
            assert_eq!(self.controller.snapshot().phase, Phase::Phrase);
        }
    }
    impl Drop for Env {
        fn drop(&mut self) {
            self.controller.lock();
            std::fs::remove_dir_all(&self.dir).unwrap();
        }
    }
    // 0012 §1: Ambiguous trust boundary
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_without_os_monitor_can_create_unlock_recover_and_lock() {
        let _k = KDF.lock().unwrap();
        let env = Env::with_missing_monitor(true);
        assert!(env.controller.snapshot().reduced_lifecycle);
        env.fill(InputField::Password, PASSWORD);
        env.fill(InputField::Repeat, PASSWORD);
        assert_eq!(
            env.controller
                .submit(env.controller.snapshot().epoch, Action::Create, false),
            Err(AppError::Consent)
        );
        assert!(!env.dir.join("vaults/main.qvault").exists());
        env.controller
            .submit(env.controller.snapshot().epoch, Action::Create, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Phrase);
        let phrase = env
            .controller
            .phrase(env.controller.snapshot().epoch)
            .unwrap();
        env.controller
            .submit(env.controller.snapshot().epoch, Action::SkipPhrase, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        assert!(env.controller.snapshot().reduced_lifecycle);
        env.controller.lock();
        env.fill(InputField::Password, PASSWORD);
        env.controller
            .submit(env.controller.snapshot().epoch, Action::Unlock, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        env.controller.state().active = Instant::now() - Duration::from_secs(61);
        assert_eq!(env.controller.snapshot().phase, Phase::Locked);
        env.controller
            .select_mode(env.controller.snapshot().epoch, Mode::Recover);
        env.fill(
            InputField::Phrase,
            std::str::from_utf8(phrase.expose_secret()).unwrap(),
        );
        env.controller
            .submit(env.controller.snapshot().epoch, Action::Recover, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        env.controller.lock();
        assert_eq!(env.controller.snapshot().phase, Phase::Locked);
        assert!(env.os.callbacks.lock().unwrap().is_empty());
    }
    // 0012 §1: Ambiguous trust boundary
    #[cfg(target_os = "linux")]
    #[test]
    fn controller_monitor_loss_clears_prior_consent_and_linux_startup_can_be_reduced() {
        let _k = KDF.lock().unwrap();
        let env = Env::new();
        env.os.unavailable.store(true, Ordering::SeqCst);
        let reduced = Controller::new(env.dir.clone(), env.os.clone()).unwrap();
        assert!(reduced.snapshot().reduced_lifecycle);
        assert!(!reduced.protection().lifecycle);
        env.fill(InputField::Password, PASSWORD);
        let epoch = env.controller.snapshot().epoch;
        assert_eq!(
            env.controller.submit(epoch, Action::Unlock, true),
            Err(AppError::LockMonitoring)
        );
        let view = env.controller.snapshot();
        assert_ne!(view.epoch, epoch);
        assert_eq!(view.phase, Phase::Locked);
        assert_eq!(view.error, Some(AppError::LockMonitoring));
        assert!(
            env.controller
                .state()
                .inputs
                .iter()
                .all(SecretBytes::is_empty)
        );
        assert!(!env.dir.join("vaults/main.qvault").exists());
        env.controller.select_mode(view.epoch, Mode::Create);
        env.create();
        assert!(env.controller.snapshot().reduced_lifecycle);
        env.controller.lock();
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn controller_forms_bound_stale_events_and_clear_even_rejected_intermediates() {
        let env = Env::new();
        let epoch = env.controller.snapshot().epoch;
        let mut huge = "秘密".repeat(1024);
        env.controller.input(epoch, InputField::Password, &mut huge);
        assert!(huge.is_empty());
        assert_eq!(
            env.controller.snapshot().error,
            Some(AppError::InvalidInput)
        );
        let mut late = "old-secret".to_owned();
        env.controller.input(epoch, InputField::Password, &mut late);
        assert!(late.is_empty());
        assert!(
            env.controller
                .state()
                .inputs
                .iter()
                .all(SecretBytes::is_empty)
        );
        assert_eq!(
            env.controller.submit(epoch, Action::Unlock, true),
            Err(AppError::InvalidInput)
        );
        assert_eq!(
            env.controller
                .submit(env.controller.snapshot().epoch, Action::Unlock, false),
            Err(AppError::Consent)
        );
        env.fill(InputField::Password, PASSWORD);
        env.fill(InputField::Repeat, "different");
        let epoch = env.controller.snapshot().epoch;
        assert_eq!(
            env.controller.submit(epoch, Action::Create, true),
            Err(AppError::InvalidInput)
        );
        assert_ne!(env.controller.snapshot().epoch, epoch);
        assert!(
            env.controller
                .state()
                .inputs
                .iter()
                .all(SecretBytes::is_empty)
        );
        assert!(!env.dir.join("vaults/main.qvault").exists());
    }
    // 0012 §1: Webview exposure
    #[test]
    fn controller_weak_confirmation_cannot_skip_countdown_or_keep_old_input() {
        let env = Env::new();
        env.fill(InputField::Password, "password");
        env.fill(InputField::Repeat, "password");
        let epoch = env.controller.snapshot().epoch;
        assert_eq!(
            env.controller.submit(epoch, Action::Create, true),
            Err(AppError::WeakPassword)
        );
        assert!(env.controller.snapshot().weak_seconds > 0);
        assert_eq!(
            env.controller.submit(epoch, Action::ConfirmWeak, true),
            Err(AppError::WeakPassword)
        );
        env.os.event();
        assert_eq!(env.controller.snapshot().phase, Phase::Locked);
        assert!(
            env.controller
                .state()
                .inputs
                .iter()
                .all(SecretBytes::is_empty)
        );
        assert!(!env.dir.join("vaults/main.qvault").exists());
    }
    // 0012 §1: Webview exposure
    #[test]
    fn controller_generator_display_expires_and_lock_discards_the_suggestion() {
        let env = Env::new();
        let epoch = env.controller.snapshot().epoch;
        assert!(env.controller.suggestion(epoch).is_none());
        env.controller
            .submit(epoch, Action::SuggestPassword, false)
            .unwrap();
        let value = env.controller.suggestion(epoch).unwrap();
        assert_eq!(
            std::str::from_utf8(value.expose_secret())
                .unwrap()
                .split('.')
                .count(),
            6
        );
        env.controller.state().suggestion_until = Some(Instant::now() - Duration::from_secs(1));
        assert!(env.controller.suggestion(epoch).is_none());
        env.os.event();
        assert!(env.controller.state().suggestion.is_none());
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn flows_create_confirm_wrong_password_unlock_phrase_recovery_and_os_lock() {
        let _k = KDF.lock().unwrap();
        let env = Env::new();
        env.create();
        let view = env.controller.snapshot();
        let phrase = env.controller.phrase(view.epoch).unwrap();
        let words = std::str::from_utf8(phrase.expose_secret())
            .unwrap()
            .split_whitespace()
            .collect::<Vec<_>>();
        for (field, pos) in [InputField::Word0, InputField::Word1, InputField::Word2]
            .into_iter()
            .zip(view.positions)
        {
            env.fill(field, words[pos - 1]);
        }
        env.controller
            .submit(view.epoch, Action::ConfirmPhrase, false)
            .unwrap();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        assert!(env.controller.phrase(view.epoch).is_none());
        env.os.event();
        assert_eq!(env.controller.snapshot().phase, Phase::Locked);
        env.fill(InputField::Password, "incorrect");
        env.controller
            .submit(env.controller.snapshot().epoch, Action::Unlock, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Locked);
        assert!(env.controller.snapshot().error.is_some());
        env.fill(InputField::Password, PASSWORD);
        env.controller
            .submit(env.controller.snapshot().epoch, Action::Unlock, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        env.controller.lock();
        env.fill(
            InputField::Phrase,
            std::str::from_utf8(phrase.expose_secret()).unwrap(),
        );
        env.controller
            .submit(env.controller.snapshot().epoch, Action::Recover, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        env.os.event();
        assert_eq!(env.controller.snapshot().phase, Phase::Locked);
        assert!(
            env.controller
                .state()
                .inputs
                .iter()
                .all(SecretBytes::is_empty)
        );
    }
    // 0012 §1: Whole-file rollback
    #[test]
    fn flows_missing_anchor_requires_snapshot_and_explicit_baseline_consent() {
        let _k = KDF.lock().unwrap();
        let env = Env::new();
        env.create();
        env.controller
            .submit(env.controller.snapshot().epoch, Action::SkipPhrase, true)
            .unwrap();
        env.wait();
        env.controller.lock();
        std::fs::remove_dir_all(env.dir.join("anchors")).unwrap();
        env.fill(InputField::Password, PASSWORD);
        env.controller
            .submit(
                env.controller.snapshot().epoch,
                Action::RecoverPassword,
                true,
            )
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Recovery);
        assert_eq!(
            env.controller.submit(
                env.controller.snapshot().epoch,
                Action::AdoptBaseline,
                false
            ),
            Err(AppError::Consent)
        );
        env.controller
            .submit(env.controller.snapshot().epoch, Action::AdoptBaseline, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        assert!(
            std::fs::read_dir(env.dir.join("snapshots"))
                .unwrap()
                .next()
                .is_some()
        );
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn controller_late_success_after_lock_drops_phrase_and_cannot_revive_session() {
        let _k = KDF.lock().unwrap();
        let env = Env::new();
        let token = env.controller.state().cancel.clone();
        let epoch = env.controller.snapshot().epoch.0;
        let created = env
            .controller
            .core()
            .unwrap()
            .create(
                &env.dir.join("vaults/late.qvault"),
                &MasterPassword::from_utf8(PASSWORD.as_bytes()).unwrap(),
                "late",
            )
            .unwrap();
        env.os.event();
        env.controller.complete(
            epoch,
            &token,
            Ok(Opened::Created(created, [0, 1, 2], PathBuf::new())),
        );
        let view = env.controller.snapshot();
        assert_eq!(view.phase, Phase::Locked);
        assert!(env.controller.phrase(view.epoch).is_none());
        assert!(env.controller.state().session.is_none());
        assert!(env.dir.join("vaults/late.qvault").exists());
    }
    // 0012 §1: Ambiguous trust boundary
    #[test]
    fn flows_skip_is_recorded_and_idle_expiry_clears_the_phrase() {
        let _k = KDF.lock().unwrap();
        let env = Env::new();
        env.create();
        let epoch = env.controller.snapshot().epoch;
        assert_eq!(
            env.controller.submit(epoch, Action::SkipPhrase, false),
            Err(AppError::Consent)
        );
        env.controller
            .submit(epoch, Action::SkipPhrase, true)
            .unwrap();
        env.wait();
        assert_eq!(env.controller.snapshot().phase, Phase::Unlocked);
        let session = env.controller.state().session.clone().unwrap();
        assert!(
            session
                .edit_settings()
                .unwrap()
                .meta()
                .settings
                .recovery_skipped_at
                .is_some()
        );
        env.controller.state().active = Instant::now() - Duration::from_secs(61);
        assert_eq!(env.controller.snapshot().phase, Phase::Locked);
        assert!(session.is_locked());
    }
}
