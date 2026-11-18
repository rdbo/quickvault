// SPDX-License-Identifier: AGPL-3.0-or-later

//! The backend behind the one `qv` command: every request is checked here as
//! if a compromised page sent it (plan 0070). Rust handles never leave this
//! module; the page gets random references that a lock clears (0008 §4.1).
use qv_core::platform::PlatformServices;
use qv_core::{
    AnchorDir, CancelToken, Core, CoreConfig, CoreError, EntryHandle, FieldHandle, FieldKind,
    FieldValue, GroupHandle, MasterPassword, PageLimit, SearchHit, SecretBytes, Session,
    StoreError, Text,
};
use qv_proto_api::{
    Answer, EntryView, Envelope, Event, FieldView, MediaView, REVEAL_MS, Ref, Reply, Request, Row,
    Sample, Secret, UiError,
};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// The synthetic vault's password. The prototype holds no real data, so the
/// lock screen shows it.
pub const DEMO_PASSWORD: &str = "prototype";
/// The inactivity lock (0009 §1.8, 1.1.1).
pub const IDLE: Duration = Duration::from_secs(5 * 60);
/// How long a copied value stays on the clipboard.
pub const CLIPBOARD_FOR: Duration = Duration::from_secs(30);
/// At most this many references per session; more fails closed.
const MAX_REFS: usize = 16_384;
/// At most this many open previews.
const MAX_MEDIA: usize = 4;

/// Sends an event to the page.
pub type Emit = Arc<dyn Fn(Event) + Send + Sync>;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Target {
    Group(GroupHandle),
    Entry(EntryHandle),
    Field(FieldHandle),
}

/// The shared backend state.
pub struct Backend {
    core: Core,
    services: Arc<dyn PlatformServices>,
    vault: PathBuf,
    session: Option<Arc<Session>>,
    generation: u64,
    refs: HashMap<Ref, Target>,
    issued: HashMap<Target, Ref>,
    reveals: Vec<(Ref, Instant)>,
    media: HashMap<Ref, Sample>,
    clip: Option<CancelToken>,
    last_active: Instant,
    idle: Duration,
    platform: &'static str,
    emit: Emit,
}

/// The backend behind a mutex, as Tauri state.
#[derive(Clone)]
pub struct Shared(pub Arc<Mutex<Backend>>);

impl Shared {
    /// The backend; a poisoned lock is taken over (the state is replaced on
    /// the next lock anyway).
    pub fn get(&self) -> MutexGuard<'_, Backend> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn core_error(e: CoreError) -> UiError {
    match e {
        CoreError::Store(StoreError::WrongPassword) => UiError::WrongPassword,
        CoreError::SessionLocked => UiError::Locked,
        CoreError::StaleHandle | CoreError::NotFound => UiError::NotFound,
        _ => UiError::Unavailable,
    }
}

fn text(t: &Text) -> String {
    t.expose().to_owned()
}

fn value_bytes(v: &FieldValue) -> &[u8] {
    v.expose_secret()
}

/// Creates the synthetic vault with one group and two entries.
fn create_demo(core: &Core, path: &Path) -> Result<(), UiError> {
    let password =
        MasterPassword::from_utf8(DEMO_PASSWORD.as_bytes()).map_err(|_| UiError::Unavailable)?;
    let created = core
        .create(path, &password, "Prototype")
        .map_err(core_error)?;
    let s = created.session;
    let root = s.root().map_err(core_error)?;
    let group = s
        .save_group(s.new_group(root, "Websites").map_err(core_error)?)
        .map_err(core_error)?;
    let _ = s.save_group(s.new_group(root, "Banking").map_err(core_error)?);
    let mut d = s
        .new_entry(group, "login", "Example login")
        .map_err(core_error)?;
    let field = |v: &str| FieldValue::text(v).map_err(|_| UiError::Unavailable);
    d.add_field("username", FieldKind::Text, field("demo@example.org")?)
        .map_err(core_error)?;
    d.add_field(
        "password",
        FieldKind::Secret,
        field("correct horse battery staple")?,
    )
    .map_err(core_error)?;
    d.add_field("website", FieldKind::Url, field("https://example.org")?)
        .map_err(core_error)?;
    d.entry_mut().notes =
        Some(Text::new("Synthetic entry for the prototype.").map_err(|_| UiError::Unavailable)?);
    s.save_entry(d).map_err(core_error)?;
    let d = s
        .new_entry(group, "login", "Second login")
        .map_err(core_error)?;
    s.save_entry(d).map_err(core_error)?;
    s.lock();
    Ok(())
}

impl Backend {
    /// Opens the core in `base`, creating the synthetic vault on first run.
    pub fn open(
        base: &Path,
        services: Arc<dyn PlatformServices>,
        emit: Emit,
        idle: Duration,
    ) -> Result<Self, UiError> {
        qv_core::create_private_dirs(base).map_err(|_| UiError::Unavailable)?;
        let anchors = AnchorDir::open(&base.join("anchors")).map_err(|_| UiError::Unavailable)?;
        let core = Core::new(CoreConfig::new(anchors));
        // The prototype's vault is synthetic, so reduced protection is
        // acknowledged up front (the real app asks, 0009 §1.8).
        #[cfg(target_os = "linux")]
        let core = core.with_linux_platform(services.clone(), true);
        #[cfg(not(target_os = "linux"))]
        let core = core.with_platform(services.clone(), true);
        let vaults = base.join("vaults");
        qv_core::create_private_dirs(&vaults).map_err(|_| UiError::Unavailable)?;
        let vault = vaults.join("Prototype.qvault");
        if std::fs::symlink_metadata(&vault).is_err() {
            create_demo(&core, &vault)?;
        }
        Ok(Self {
            core,
            services,
            vault,
            session: None,
            generation: 1,
            refs: HashMap::new(),
            issued: HashMap::new(),
            reveals: Vec::new(),
            media: HashMap::new(),
            clip: None,
            last_active: Instant::now(),
            idle,
            platform: if cfg!(target_os = "android") {
                "android"
            } else if cfg!(windows) {
                "windows"
            } else {
                "linux"
            },
            emit,
        })
    }

    /// The current lock generation.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether a vault is open.
    pub fn unlocked(&self) -> bool {
        self.session.is_some()
    }

    /// Decodes and answers one raw request body.
    pub fn handle(&mut self, body: &[u8]) -> Answer {
        let reply = match qv_proto_api::decode(body) {
            Ok(envelope) => self.answer(envelope),
            Err(e) => Reply::Error(e),
        };
        Answer {
            generation: self.generation,
            reply,
        }
    }

    fn answer(
        &mut self,
        Envelope {
            generation,
            request,
        }: Envelope,
    ) -> Reply {
        // Status is how a page learns the generation; everything else from
        // an older generation is a late request from before a lock.
        if !matches!(request, Request::Status) && generation != self.generation {
            return Reply::Error(UiError::Stale);
        }
        self.last_active = Instant::now();
        match self.dispatch(request) {
            Ok(reply) => reply,
            Err(e) => Reply::Error(e),
        }
    }

    fn dispatch(&mut self, request: Request) -> Result<Reply, UiError> {
        match request {
            Request::Status => Ok(Reply::Status {
                unlocked: self.unlocked(),
                platform: self.platform.to_owned(),
                hint: DEMO_PASSWORD.to_owned(),
            }),
            Request::Active => Ok(Reply::Ok),
            Request::Unlock { password } => self.unlock(&password),
            Request::Lock => {
                self.lock();
                Ok(Reply::Ok)
            }
            Request::Groups => self.groups(),
            Request::Entries { group } => self.entries(group),
            Request::Entry { entry } => self.entry(entry),
            Request::Reveal { field } => self.reveal(field),
            Request::Copy { field } => self.copy(field),
            Request::OpenMedia { sample } => self.open_media(sample),
            Request::CloseMedia { media } => {
                self.media.remove(&media);
                Ok(Reply::Ok)
            }
            Request::BackAtRoot => {
                #[cfg(target_os = "android")]
                crate::android::back_at_root();
                Ok(Reply::Ok)
            }
        }
    }

    fn session(&self) -> Result<Arc<Session>, UiError> {
        self.session.clone().ok_or(UiError::Locked)
    }

    fn issue(&mut self, target: Target) -> Result<Ref, UiError> {
        if let Some(r) = self.issued.get(&target) {
            return Ok(*r);
        }
        if self.refs.len() >= MAX_REFS {
            return Err(UiError::Unavailable);
        }
        let r = random_ref()?;
        self.refs.insert(r, target);
        self.issued.insert(target, r);
        Ok(r)
    }

    fn unlock(&mut self, password: &Secret) -> Result<Reply, UiError> {
        if self.session.is_some() {
            return Ok(Reply::Ok);
        }
        let password =
            MasterPassword::from_utf8(password.expose()).map_err(|_| UiError::WrongPassword)?;
        let session = self
            .core
            .unlock(&self.vault, &password, None)
            .map_err(core_error)?;
        self.session = Some(Arc::new(session));
        self.last_active = Instant::now();
        Ok(Reply::Ok)
    }

    /// Locks, clears every reference, reveal and preview token, cancels the
    /// clipboard hold and tells the page. Locking twice is a no-op.
    pub fn lock(&mut self) {
        let Some(session) = self.session.take() else {
            return;
        };
        session.lock();
        self.refs.clear();
        self.issued.clear();
        self.reveals.clear();
        self.media.clear();
        if let Some(clip) = self.clip.take() {
            clip.cancel();
        }
        self.generation = self.generation.wrapping_add(1);
        (self.emit)(Event::Locked {
            generation: self.generation,
        });
    }

    /// Runs the timers: reveal expiry, the inactivity lock and locks the
    /// platform made (screen lock, background expiry).
    pub fn tick(&mut self, now: Instant) {
        let emit = self.emit.clone();
        self.reveals.retain(|(field, at)| {
            let keep = now.duration_since(*at) < Duration::from_millis(u64::from(REVEAL_MS));
            if !keep {
                emit(Event::RevealExpired { field: *field });
            }
            keep
        });
        let platform_locked = self.session.as_ref().is_some_and(|s| s.is_locked());
        if platform_locked || now.duration_since(self.last_active) >= self.idle {
            self.lock();
        }
    }

    fn groups(&mut self) -> Result<Reply, UiError> {
        let s = self.session()?;
        let root = s.root().map_err(core_error)?;
        let page = s
            .groups_page(Some(root), "", None, limit()?, &CancelToken::new())
            .map_err(core_error)?;
        let mut rows = Vec::with_capacity(page.items.len());
        for g in page.items {
            rows.push(Row {
                id: self.issue(Target::Group(g.handle))?,
                name: text(&g.name),
            });
        }
        Ok(Reply::Groups(rows))
    }

    fn target(&self, r: Ref) -> Result<Target, UiError> {
        self.refs.get(&r).copied().ok_or(UiError::NotFound)
    }

    fn entries(&mut self, group: Ref) -> Result<Reply, UiError> {
        let s = self.session()?;
        let Target::Group(group) = self.target(group)? else {
            return Err(UiError::NotFound);
        };
        let page = s
            .browse_items_page(group, "", None, limit()?, &CancelToken::new())
            .map_err(core_error)?;
        let mut rows = Vec::new();
        for hit in page.items {
            if let SearchHit::Entry(e) = hit {
                rows.push(Row {
                    id: self.issue(Target::Entry(e.handle))?,
                    name: text(&e.title),
                });
            }
        }
        Ok(Reply::Entries(rows))
    }

    fn entry(&mut self, entry: Ref) -> Result<Reply, UiError> {
        let s = self.session()?;
        let Target::Entry(entry) = self.target(entry)? else {
            return Err(UiError::NotFound);
        };
        let detail = s.entry(entry).map_err(core_error)?;
        let mut fields = Vec::with_capacity(detail.fields.len());
        for f in detail.fields {
            let value = match (&f.value, f.protected) {
                (Some(v), false) => Some(String::from_utf8_lossy(value_bytes(v)).into_owned()),
                _ => None,
            };
            fields.push(FieldView {
                id: self.issue(Target::Field(f.handle))?,
                name: text(&f.name),
                protected: f.protected,
                value,
            });
        }
        Ok(Reply::Entry(EntryView {
            title: text(&detail.title),
            fields,
            notes: detail.notes.as_ref().map(text).unwrap_or_default(),
        }))
    }

    fn field_value(&self, field: Ref) -> Result<(Arc<Session>, FieldValue), UiError> {
        let s = self.session()?;
        let Target::Field(handle) = self.target(field)? else {
            return Err(UiError::NotFound);
        };
        let value = s.reveal(handle).map_err(core_error)?;
        Ok((s, value))
    }

    fn reveal(&mut self, field: Ref) -> Result<Reply, UiError> {
        let (_, value) = self.field_value(field)?;
        let value = Secret::new(value_bytes(&value))?;
        self.reveals.retain(|(f, _)| *f != field);
        self.reveals.push((field, Instant::now()));
        Ok(Reply::Revealed {
            field,
            value,
            expires_ms: REVEAL_MS,
        })
    }

    /// Rust → OS: the value never passes through the page. The hold runs on
    /// its own thread and ends on expiry, replacement, cancel or lock.
    fn copy(&mut self, field: Ref) -> Result<Reply, UiError> {
        let (session, value) = self.field_value(field)?;
        let bytes = value_bytes(&value);
        let secret = SecretBytes::try_init(bytes.len(), |out| {
            out.copy_from_slice(bytes);
            Ok::<(), CoreError>(())
        })
        .map_err(core_error)?;
        drop(value);
        let cancel = CancelToken::new();
        if let Some(old) = self.clip.replace(cancel.clone()) {
            old.cancel();
        }
        let services = self.services.clone();
        let emit = self.emit.clone();
        std::thread::Builder::new()
            .name("qv-proto-clipboard".into())
            .spawn(move || {
                let mut progress = |seconds: u64| {
                    emit(Event::Clipboard { seconds });
                    Ok(())
                };
                let _ = session.hold_clipboard(
                    services.clipboard(),
                    secret,
                    CLIPBOARD_FOR,
                    Some(&cancel),
                    &mut progress,
                );
                emit(Event::Clipboard { seconds: 0 });
            })
            .map_err(|_| UiError::Unavailable)?;
        Ok(Reply::Ok)
    }

    fn open_media(&mut self, sample: Sample) -> Result<Reply, UiError> {
        self.session()?;
        if self.media.len() >= MAX_MEDIA {
            return Err(UiError::Unavailable);
        }
        let token = random_ref()?;
        self.media.insert(token, sample);
        let (bytes, mime) = crate::media::sample(sample);
        Ok(Reply::Media(MediaView {
            media: token,
            url: crate::media::url(&token),
            mime: mime.to_owned(),
            size: u64::try_from(bytes.len()).map_err(|_| UiError::Unavailable)?,
        }))
    }

    /// The sample a live preview token names.
    pub fn media(&self, token: &Ref) -> Option<Sample> {
        self.session.as_ref()?;
        self.media.get(token).copied()
    }
}

/// One page of rows (the prototype shows the first page only).
fn limit() -> Result<PageLimit, UiError> {
    Ok(PageLimit::default())
}

/// 128 random bits from the OS.
pub fn random_ref() -> Result<Ref, UiError> {
    let mut r = [0u8; 16];
    getrandom::fill(&mut r).map_err(|_| UiError::Unavailable)?;
    Ok(Ref(r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use qv_proto_api::MAX_REQUEST;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct Env {
        _dir: TempDir,
        backend: Backend,
        events: Arc<Mutex<Vec<Event>>>,
    }

    /// A private directory, removed on drop.
    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    static NEXT: AtomicU64 = AtomicU64::new(0);

    /// The suite shares one synthetic vault (one Argon2id create); each test
    /// copies it, as AGENTS.md asks. Paths are relative to the package
    /// directory (the test's working directory): the 0011 §4 ancestor-owner
    /// check may refuse an absolute path whose ancestors another user owns.
    fn fixture_base() -> PathBuf {
        static ONCE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        ONCE.get_or_init(|| {
            let base = PathBuf::from("../target/qv-proto-tests")
                .join(format!("fixture-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&base);
            let backend = Backend::open(&base, services(), Arc::new(|_| {}), IDLE).unwrap();
            drop(backend);
            base
        })
        .clone()
    }

    fn services() -> Arc<dyn PlatformServices> {
        #[cfg(target_os = "linux")]
        {
            Arc::new(qv_core::platform::LinuxPlatform::default())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Arc::new(qv_core::platform::AndroidPlatform::default())
        }
    }

    fn copy_dir(from: &Path, to: &Path) {
        qv_core::create_private_dirs(to).unwrap();
        for e in std::fs::read_dir(from).unwrap() {
            let e = e.unwrap();
            let target = to.join(e.file_name());
            if e.file_type().unwrap().is_dir() {
                copy_dir(&e.path(), &target);
            } else {
                std::fs::copy(e.path(), &target).unwrap();
            }
        }
    }

    fn env_with(idle: Duration) -> Env {
        let base = fixture_base();
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir = base.with_file_name(format!("qv-proto-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        copy_dir(&base, &dir);
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let backend = Backend::open(
            &dir,
            services(),
            Arc::new(move |e| sink.lock().unwrap().push(e)),
            idle,
        )
        .unwrap();
        Env {
            _dir: TempDir(dir),
            backend,
            events,
        }
    }

    fn env() -> Env {
        env_with(IDLE)
    }

    impl Env {
        fn ask(&mut self, request: serde_json::Value) -> Answer {
            let g = self.backend.generation();
            self.ask_at(g, request)
        }
        fn ask_at(&mut self, generation: u64, request: serde_json::Value) -> Answer {
            let body = serde_json::json!({ "generation": generation, "request": request });
            self.backend.handle(body.to_string().as_bytes())
        }
        fn unlock(&mut self) {
            let pw: Vec<u8> = DEMO_PASSWORD.bytes().collect();
            let a = self.ask(serde_json::json!({ "unlock": { "password": pw } }));
            assert!(matches!(a.reply, Reply::Ok), "{:?}", a.reply);
        }
        fn first_entry(&mut self) -> (Ref, EntryView) {
            let groups = match self.ask(serde_json::json!("groups")).reply {
                Reply::Groups(groups) => groups,
                other => panic!("groups: {other:?}"),
            };
            let web = groups.iter().find(|g| g.name == "Websites").unwrap();
            let Reply::Entries(entries) = self
                .ask(serde_json::json!({ "entries": { "group": web.id.hex() } }))
                .reply
            else {
                panic!("entries");
            };
            let e = entries.iter().find(|e| e.name == "Example login").unwrap();
            let Reply::Entry(view) = self
                .ask(serde_json::json!({ "entry": { "entry": e.id.hex() } }))
                .reply
            else {
                panic!("entry");
            };
            (e.id, view)
        }
    }

    fn error(a: &Answer) -> Option<UiError> {
        match a.reply {
            Reply::Error(e) => Some(e),
            _ => None,
        }
    }

    #[test]
    fn unlock_browse_and_reveal() {
        let mut env = env();
        let wrong: Vec<u8> = b"nope".to_vec();
        let a = env.ask(serde_json::json!({ "unlock": { "password": wrong } }));
        assert_eq!(error(&a), Some(UiError::WrongPassword));
        env.unlock();
        let (_, view) = env.first_entry();
        let pw = view.fields.iter().find(|f| f.name == "password").unwrap();
        assert!(pw.protected && pw.value.is_none());
        let user = view.fields.iter().find(|f| f.name == "username").unwrap();
        assert_eq!(user.value.as_deref(), Some("demo@example.org"));
        let a = env.ask(serde_json::json!({ "reveal": { "field": pw.id.hex() } }));
        let Reply::Revealed {
            value, expires_ms, ..
        } = a.reply
        else {
            panic!("reveal");
        };
        assert_eq!(value.expose(), b"correct horse battery staple");
        assert_eq!(expires_ms, REVEAL_MS);
    }

    #[test]
    fn oversized_and_malformed_bodies_fail_closed() {
        let mut env = env();
        let big = vec![b' '; MAX_REQUEST + 1];
        assert_eq!(error(&env.backend.handle(&big)), Some(UiError::TooLarge));
        assert_eq!(
            error(&env.backend.handle(br#"{"generation":1,"request":"rm_rf"}"#)),
            Some(UiError::Malformed)
        );
        assert_eq!(
            error(
                &env.backend
                    .handle(br#"{"generation":1,"request":"groups","x":0}"#)
            ),
            Some(UiError::Malformed)
        );
        // Locked: nothing to read.
        assert_eq!(
            error(&env.ask(serde_json::json!("groups"))),
            Some(UiError::Locked)
        );
    }

    #[test]
    fn a_lock_expires_references_and_old_generations() {
        let mut env = env();
        env.unlock();
        let before = env.backend.generation();
        let (entry, _) = env.first_entry();
        env.backend.lock();
        assert_eq!(
            env.events.lock().unwrap().last(),
            Some(&Event::Locked {
                generation: before + 1
            })
        );
        // A late request from before the lock is refused as stale …
        let late = env.ask_at(
            before,
            serde_json::json!({ "entry": { "entry": entry.hex() } }),
        );
        assert_eq!(error(&late), Some(UiError::Stale));
        assert_eq!(late.generation, before + 1);
        // … and after unlocking again the old reference names nothing.
        env.unlock();
        let a = env.ask(serde_json::json!({ "entry": { "entry": entry.hex() } }));
        assert_eq!(error(&a), Some(UiError::NotFound));
        // A reference of the wrong kind is refused too.
        let a = env.ask(serde_json::json!({ "entries": { "group": entry.hex() } }));
        assert_eq!(error(&a), Some(UiError::NotFound));
    }

    #[test]
    fn idle_locks_and_activity_defers_it() {
        let mut env = env_with(Duration::from_millis(400));
        env.unlock();
        let start = Instant::now();
        env.backend.tick(start + Duration::from_millis(100));
        assert!(env.backend.unlocked());
        // Activity resets the timer.
        std::thread::sleep(Duration::from_millis(250));
        assert!(matches!(
            env.ask(serde_json::json!("active")).reply,
            Reply::Ok
        ));
        env.backend
            .tick(Instant::now() + Duration::from_millis(300));
        assert!(env.backend.unlocked());
        env.backend
            .tick(Instant::now() + Duration::from_millis(450));
        assert!(!env.backend.unlocked());
    }

    #[test]
    fn reveals_expire_and_media_tokens_revoke() {
        let mut env = env();
        env.unlock();
        let (_, view) = env.first_entry();
        let pw = view
            .fields
            .iter()
            .find(|f| f.name == "password")
            .unwrap()
            .id;
        env.ask(serde_json::json!({ "reveal": { "field": pw.hex() } }));
        env.backend
            .tick(Instant::now() + Duration::from_millis(u64::from(REVEAL_MS) + 1));
        assert!(
            env.events
                .lock()
                .unwrap()
                .contains(&Event::RevealExpired { field: pw })
        );
        let Reply::Media(m) = env
            .ask(serde_json::json!({ "open_media": { "sample": "video" } }))
            .reply
        else {
            panic!("media");
        };
        assert_eq!(env.backend.media(&m.media), Some(Sample::Video));
        env.ask(serde_json::json!({ "close_media": { "media": m.media.hex() } }));
        assert_eq!(env.backend.media(&m.media), None);
        let Reply::Media(m) = env
            .ask(serde_json::json!({ "open_media": { "sample": "wav" } }))
            .reply
        else {
            panic!("media");
        };
        env.backend.lock();
        assert_eq!(env.backend.media(&m.media), None);
    }
}
