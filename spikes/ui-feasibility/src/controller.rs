// SPDX-License-Identifier: AGPL-3.0-or-later

//! Disposable fixture controller. Framework Strings enter protected containers
//! promptly; the controller makes no claim about copies inside the renderer.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use qv_core::{
    AnchorDir, CancelToken, Core, CoreConfig, CoreError, EntryHandle, FieldKind, FieldValue,
    MasterPassword, SecretText, Session, Text,
};
use zeroize::Zeroizing;

const INPUT_LIMIT: usize = 256 * 1024;

#[derive(Clone)]
pub(crate) struct Controller(Arc<Inner>);
struct Inner {
    base: PathBuf,
    state: Mutex<State>,
    notify: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}
struct State {
    epoch: u64,
    form: u64,
    cancel: CancelToken,
    session: Option<Arc<Session>>,
    password: Option<MasterPassword>,
    replacement: Option<SecretText>,
    title: Zeroizing<String>,
    title_invalid: bool,
    replacement_invalid: bool,
    rows: Vec<Row>,
    measurements: Vec<Measurement>,
    busy: bool,
    message: &'static str,
    error: Option<CoreError>,
    active: Instant,
}
#[derive(Clone)]
pub(crate) struct Measurement {
    pub(crate) ms: u128,
    pub(crate) before_kib: u64,
    pub(crate) peak_kib: u64,
    pub(crate) after_kib: u64,
}
#[derive(Clone)]
pub(crate) struct Row {
    pub(crate) handle: EntryHandle,
    pub(crate) title: Zeroizing<String>,
}
pub(crate) struct Snapshot {
    pub(crate) form: u64,
    pub(crate) busy: bool,
    pub(crate) unlocked: bool,
    pub(crate) message: &'static str,
    pub(crate) error: Option<CoreError>,
    pub(crate) rows: Vec<Row>,
    pub(crate) measurements: Vec<Measurement>,
}
impl PartialEq for Controller {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Controller {
    pub(crate) fn new(base: PathBuf) -> Self {
        Self(Arc::new(Inner {
            base,
            state: Mutex::new(State {
                epoch: 0,
                form: 0,
                cancel: CancelToken::new(),
                session: None,
                password: None,
                replacement: None,
                title: Zeroizing::new(String::new()),
                title_invalid: false,
                replacement_invalid: false,
                rows: Vec::new(),
                measurements: Vec::new(),
                busy: false,
                message: "Locked",
                error: None,
                active: Instant::now(),
            }),
            notify: Mutex::new(None),
        }))
    }
    fn state(&self) -> MutexGuard<'_, State> {
        self.0.state.lock().unwrap_or_else(|p| p.into_inner())
    }
    pub(crate) fn notify_with(&self, f: impl Fn() + Send + Sync + 'static) {
        *self.0.notify.lock().unwrap_or_else(|p| p.into_inner()) = Some(Arc::new(f));
    }
    fn notify(&self) {
        let f = self
            .0
            .notify
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(f) = f {
            f();
        }
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        let s = self.state();
        Snapshot {
            form: s.form,
            busy: s.busy,
            unlocked: s.session.is_some(),
            message: s.message,
            error: s.error,
            rows: s.rows.clone(),
            measurements: s.measurements.clone(),
        }
    }
    pub(crate) fn password(&self, form: u64, value: &str) {
        let mut s = self.state();
        if form != s.form || s.busy {
            return;
        }
        s.active = Instant::now();
        s.password = None;
        if value.len() > 1024 {
            s.message = "Password exceeds 1,024 bytes";
            return;
        }
        match MasterPassword::from_utf8(value.as_bytes()) {
            Ok(p) => s.password = Some(p),
            Err(_) => s.message = "Invalid password input",
        }
    }
    pub(crate) fn title(&self, form: u64, value: &str) {
        let mut s = self.state();
        if form != s.form || s.busy {
            return;
        }
        s.active = Instant::now();
        s.title = Zeroizing::new(String::new());
        s.title_invalid = value.len() > INPUT_LIMIT;
        if value.len() <= INPUT_LIMIT {
            s.title = Zeroizing::new(value.to_owned());
        } else {
            s.message = "Title exceeds model limit";
        }
    }
    pub(crate) fn replacement(&self, form: u64, value: &str) {
        let mut s = self.state();
        if form != s.form || s.busy {
            return;
        }
        s.active = Instant::now();
        s.replacement = None;
        s.replacement_invalid = value.len() > INPUT_LIMIT;
        if value.len() <= INPUT_LIMIT {
            s.replacement = SecretText::new(value).ok();
        } else {
            s.message = "Field exceeds model limit";
        }
    }
    pub(crate) fn lock(&self) {
        let session = {
            let mut s = self.state();
            s.cancel.cancel();
            s.epoch = s.epoch.wrapping_add(1);
            s.form = s.form.wrapping_add(1);
            s.password = None;
            s.replacement = None;
            s.title = Zeroizing::new(String::new());
            s.rows.clear();
            s.title_invalid = false;
            s.replacement_invalid = false;
            s.busy = false;
            s.message = "Locked";
            s.error = None;
            s.session.take()
        };
        if let Some(session) = session {
            session.lock();
        }
        self.notify();
    }
    pub(crate) fn idle(&self) {
        let expired = {
            let s = self.state();
            (s.session.is_some() || s.busy || s.password.is_some() || s.replacement.is_some())
                && s.active.elapsed() >= Duration::from_secs(60)
        };
        if expired {
            self.lock();
        }
    }
    fn core(&self) -> Result<Core, CoreError> {
        use std::os::unix::fs::DirBuilderExt;
        let db = self.0.base.join("active");
        let anchors = self.0.base.join("anchors");
        for dir in [&db, &anchors] {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|_| CoreError::Internal)?;
        }
        Ok(Core::new(CoreConfig::new(AnchorDir::open(&anchors)?)))
    }
    pub(crate) fn open(&self, create: bool, acknowledgement: bool) -> Option<JoinHandle<()>> {
        let (epoch, password, cancel) = {
            let mut s = self.state();
            if s.busy || s.session.is_some() {
                return None;
            }
            if !acknowledgement {
                s.message = "Acknowledge disposable fixture and OS protection limits first";
                drop(s);
                self.notify();
                return None;
            }
            let Some(p) = s.password.take() else {
                s.message = "Enter a test password";
                drop(s);
                self.notify();
                return None;
            };
            s.epoch = s.epoch.wrapping_add(1);
            s.form = s.form.wrapping_add(1);
            s.cancel = CancelToken::new();
            s.busy = true;
            s.message = "Working (full password-kdf/1)";
            s.error = None;
            s.active = Instant::now();
            (s.epoch, p, s.cancel.clone())
        };
        self.notify();
        let controller = self.clone();
        Some(std::thread::spawn(move || {
            let result = (|| {
                let core = controller.core()?;
                let file = controller.0.base.join("active/fixture.qvault");
                if create {
                    let created = core.create(&file, &password, "Disposable Dioxus fixture")?;
                    let session = Arc::new(created.session);
                    drop(created.recovery_phrase);
                    {
                        let mut s = controller.state();
                        if s.epoch != epoch || cancel.is_cancelled() {
                            drop(s);
                            session.lock();
                            return Err(CoreError::Cancelled);
                        }
                        // Publish ownership before any post-create writes so lock() can
                        // cancel the Session even while the worker is seeding the fixture.
                        s.session = Some(session.clone());
                    }
                    if cancel.is_cancelled() {
                        session.lock();
                        return Err(CoreError::Cancelled);
                    }
                    session.record_recovery_skip()?;
                    let mut draft =
                        session.new_entry(session.root()?, "login", "Shared fixture entry")?;
                    draft.add_field(
                        "password",
                        FieldKind::Secret,
                        FieldValue::text("disposable-test-value")
                            .map_err(|_| CoreError::InvalidInput)?,
                    )?;
                    session.save_entry(draft)?;
                    Ok(session)
                } else {
                    core.unlock(&file, &password, Some(&cancel)).map(Arc::new)
                }
            })();
            drop(password);
            controller.finish_open(epoch, result);
        }))
    }
    fn finish_open(&self, epoch: u64, result: Result<Arc<Session>, CoreError>) {
        let result = result.and_then(|session| {
            let listing = session.list(session.root()?)?;
            let rows = listing
                .entries
                .into_iter()
                .map(|e| Row {
                    handle: e.handle,
                    title: Zeroizing::new(e.title.expose().to_owned()),
                })
                .collect();
            Ok((session, rows))
        });
        let mut s = self.state();
        if epoch != s.epoch {
            drop(s);
            if let Ok((session, _)) = result {
                session.lock();
            }
            return;
        }
        s.busy = false;
        match result {
            Ok((session, rows)) => {
                s.session = Some(session);
                s.rows = rows;
                s.message = "Unlocked";
            }
            Err(error) => {
                s.error = Some(error);
                let pending = s.session.take();
                s.message = "Open failed (check password, file and anchor)";
                drop(s);
                if let Some(pending) = pending {
                    pending.lock();
                }
                self.notify();
                return;
            }
        }
        drop(s);
        self.notify();
    }
    /// One warmup and five bounded real-core unlocks; only numeric metrics persist.
    pub(crate) fn benchmark(&self, acknowledgement: bool) -> Option<JoinHandle<()>> {
        let (password, epoch, cancel) = {
            let mut s = self.state();
            if s.busy || s.session.is_some() || !acknowledgement {
                return None;
            }
            let password = s.password.take()?;
            s.epoch = s.epoch.wrapping_add(1);
            s.form = s.form.wrapping_add(1);
            s.cancel = CancelToken::new();
            s.busy = true;
            s.measurements.clear();
            s.message = "Benchmarking: one warmup + five full-profile unlocks";
            s.active = Instant::now();
            (password, s.epoch, s.cancel.clone())
        };
        self.notify();
        let c = self.clone();
        Some(std::thread::spawn(move || {
            let result = (|| {
                let core = c.core()?;
                let file = c.0.base.join("active/fixture.qvault");
                core.unlock(&file, &password, Some(&cancel))?.lock();
                let mut samples = Vec::with_capacity(5);
                for _ in 0..5 {
                    if cancel.is_cancelled() {
                        return Err(CoreError::Cancelled);
                    }
                    let before = rss_kib();
                    let peak = Arc::new(AtomicU64::new(before));
                    let stop = Arc::new(AtomicBool::new(false));
                    let sampler = {
                        let peak = peak.clone();
                        let stop = stop.clone();
                        std::thread::spawn(move || {
                            while !stop.load(Ordering::Acquire) {
                                peak.fetch_max(rss_kib(), Ordering::Relaxed);
                                std::thread::sleep(Duration::from_millis(25));
                            }
                        })
                    };
                    let start = Instant::now();
                    let opened = core.unlock(&file, &password, Some(&cancel));
                    let ms = start.elapsed().as_millis();
                    if let Ok(session) = &opened {
                        session.lock();
                    }
                    stop.store(true, Ordering::Release);
                    let _ = sampler.join();
                    opened?;
                    let after = rss_kib();
                    samples.push(Measurement {
                        ms,
                        before_kib: before,
                        peak_kib: peak.load(Ordering::Relaxed).max(after),
                        after_kib: after,
                    });
                }
                // Metrics contain no credential, title, ID or phone serial. A unique
                // private file avoids overwriting any previous artifact or symlink.
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let stamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| CoreError::Internal)?
                    .as_nanos();
                let mut out = std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .open(c.0.base.join(format!("metrics-{stamp}.csv")))
                    .map_err(|_| CoreError::Internal)?;
                writeln!(
                    out,
                    "sample,unlock_ms,rss_before_kib,rss_peak_25ms_kib,rss_after_kib"
                )
                .map_err(|_| CoreError::Internal)?;
                for (i, m) in samples.iter().enumerate() {
                    writeln!(
                        out,
                        "{},{},{},{},{}",
                        i + 1,
                        m.ms,
                        m.before_kib,
                        m.peak_kib,
                        m.after_kib
                    )
                    .map_err(|_| CoreError::Internal)?;
                }
                Ok(samples)
            })();
            let mut s = c.state();
            if s.epoch != epoch {
                return;
            }
            s.busy = false;
            match result {
                Ok(samples) => {
                    s.measurements = samples;
                    s.message = "Benchmark complete (RSS sampled every 25 ms)";
                }
                Err(error) => {
                    s.error = Some(error);
                    s.message = "Benchmark failed or cancelled";
                }
            }
            drop(s);
            c.notify();
        }))
    }
    pub(crate) fn save(&self, handle: EntryHandle) -> Option<JoinHandle<()>> {
        let (session, epoch, title, replacement) = {
            let mut s = self.state();
            if s.busy || s.title_invalid || s.replacement_invalid {
                return None;
            }
            let session = s.session.as_ref()?.clone();
            if !s.rows.iter().any(|r| r.handle == handle) {
                return None;
            }
            let title = std::mem::replace(&mut s.title, Zeroizing::new(String::new()));
            let replacement = s.replacement.take();
            s.busy = true;
            s.form = s.form.wrapping_add(1);
            s.active = Instant::now();
            (session, s.epoch, title, replacement)
        };
        let controller = self.clone();
        self.notify();
        Some(std::thread::spawn(move || {
            let result = (|| {
                let mut draft = session.edit_entry(handle)?;
                if !title.is_empty() {
                    draft.entry_mut().title =
                        Text::new(&title).map_err(|_| CoreError::InvalidInput)?;
                }
                if let Some(value) = replacement.filter(|v| !v.expose_secret().is_empty()) {
                    let field = draft
                        .entry_mut()
                        .fields
                        .iter_mut()
                        .find(|f| f.kind == FieldKind::Secret)
                        .ok_or(CoreError::NotFound)?;
                    field.value = FieldValue::Text(value);
                }
                session.save_entry(draft)?;
                session.list(session.root()?)
            })();
            let mut s = controller.state();
            if s.epoch != epoch {
                return;
            }
            s.busy = false;
            match result {
                Ok(listing) => {
                    s.rows = listing
                        .entries
                        .into_iter()
                        .map(|e| Row {
                            handle: e.handle,
                            title: Zeroizing::new(e.title.expose().to_owned()),
                        })
                        .collect();
                    s.message = "Saved locally";
                }
                Err(_) => s.message = "Save failed; reopen to inspect durable state",
            }
            drop(s);
            controller.notify();
        }))
    }
}

fn rss_kib() -> u64 {
    // Only this process; 0 records an unavailable /proc counter, never a claim
    // of zero consumption. Neither /proc contents nor private input is logged.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines().find_map(|line| {
                line.strip_prefix("VmRSS:")?
                    .split_whitespace()
                    .next()?
                    .parse()
                    .ok()
            })
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Controller {
        let p = std::env::temp_dir().join(format!(
            "qv-dioxus-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        Controller::new(p)
    }
    #[test]
    fn persist_edit_reopen_and_boundaries() {
        let c = fixture();
        c.password(c.snapshot().form, "test-only fixture password");
        assert!(c.open(true, false).is_none());
        c.open(true, true).unwrap().join().unwrap();
        assert!(c.snapshot().unlocked);
        let handle = c.snapshot().rows[0].handle;
        c.title(c.snapshot().form, &"x".repeat(INPUT_LIMIT + 1));
        assert!(c.save(handle).is_none());
        c.title(c.snapshot().form, "<script>literal fixture title</script>");
        c.replacement(c.snapshot().form, &"x".repeat(INPUT_LIMIT + 1));
        assert!(c.save(handle).is_none());
        c.replacement(c.snapshot().form, "replacement-test-marker");
        c.save(handle).unwrap().join().unwrap();
        c.lock();
        assert!(!c.snapshot().unlocked && c.snapshot().rows.is_empty());
        c.password(c.snapshot().form, &"a".repeat(1025));
        assert!(c.open(false, true).is_none());
        c.password(c.snapshot().form, "wrong");
        c.open(false, true).unwrap().join().unwrap();
        assert!(!c.snapshot().unlocked);
        c.password(c.snapshot().form, "test-only fixture password");
        c.open(false, true).unwrap().join().unwrap();
        assert_eq!(
            c.snapshot().rows[0].title.as_str(),
            "<script>literal fixture title</script>"
        );
        let session = c.state().session.as_ref().unwrap().clone();
        let detail = session.entry(c.snapshot().rows[0].handle).unwrap();
        assert_eq!(
            session
                .reveal(detail.fields[0].handle)
                .unwrap()
                .expose_secret(),
            b"replacement-test-marker"
        );
        drop(detail);
        drop(session);
        c.lock();
        std::fs::remove_dir_all(&c.0.base).unwrap();
    }
    #[test]
    fn late_unlock_cannot_revive_and_idle_clears_input() {
        let c = fixture();
        c.password(c.snapshot().form, "test-only fixture password");
        c.open(true, true).unwrap().join().unwrap();
        c.lock();
        let epoch = c.state().epoch;
        let session = c
            .core()
            .unwrap()
            .unlock(
                &c.0.base.join("active/fixture.qvault"),
                &MasterPassword::from_utf8(b"test-only fixture password").unwrap(),
                None,
            )
            .unwrap();
        let old_form = c.snapshot().form;
        c.lock();
        c.password(old_form, "stale-input-event");
        assert!(c.state().password.is_none());
        c.finish_open(epoch, Ok(Arc::new(session)));
        assert!(!c.snapshot().unlocked && c.snapshot().rows.is_empty());
        c.password(c.snapshot().form, "pending-test-input");
        c.state().active = Instant::now() - Duration::from_secs(61);
        c.idle();
        assert!(c.state().password.is_none());
        let form = c.snapshot().form;
        c.idle();
        c.idle();
        assert_eq!(
            c.snapshot().form,
            form,
            "already-locked idle must not churn forms"
        );
        std::fs::remove_dir_all(&c.0.base).unwrap();
    }
}
