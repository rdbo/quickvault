// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test fixtures: private temporary directories, a serialized KDF, a fixed
//! clock, and one fixture vault per test binary that each test copies.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError};

use qv_crypto::MasterPassword;
use qv_model::Timestamp;
use qv_store::{AnchorDir, SnapshotDir};

use crate::{Core, CoreConfig, Session, SnapshotPolicy, TimeSource};

pub(crate) const PASSWORD: &str = "correct horse battery staple";
pub(crate) const NAME: &str = "Personal";

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
pub(crate) struct KdfSlot;

impl Drop for KdfSlot {
    fn drop(&mut self) {
        let mut used = KDF_SLOTS.0.lock().unwrap_or_else(PoisonError::into_inner);
        *used -= 1;
        KDF_SLOTS.1.notify_one();
    }
}

pub(crate) fn kdf() -> KdfSlot {
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

/// `chmod mode`, or its Windows ACL counterpart (`qv_win::fs::chmod_like`).
pub(crate) fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(windows)]
    qv_win::fs::chmod_like(path, mode).unwrap();
}

/// Wine keeps a deleted name listed while a handle is open (NTFS removes
/// it); checks of that skip there. The runner sets `QV_WINE=1`.
pub(crate) fn wine_keeps_deleted_names() -> bool {
    let wine = cfg!(windows) && std::env::var_os("QV_WINE").is_some();
    if wine {
        eprintln!("skipped under Wine: deleted names linger while open");
    }
    wine
}

/// Wine does not enforce a DACL that removes the owner's write right; the
/// test runner sets `QV_WINE=1` (never set on Windows).
pub(crate) fn wine_ignores_read_only_dacl() -> bool {
    let wine = cfg!(windows) && std::env::var_os("QV_WINE").is_some();
    if wine {
        eprintln!("skipped under Wine: read-only DACL not enforced");
    }
    wine
}

pub(crate) fn pw(s: &str) -> MasterPassword {
    MasterPassword::from_utf8(s.as_bytes()).unwrap()
}

/// A settable clock.
pub(crate) struct FixedTime(pub(crate) AtomicI64);

impl FixedTime {
    pub(crate) fn set(&self, ms: i64) {
        self.0.store(ms, Ordering::SeqCst);
    }
}

impl TimeSource for FixedTime {
    fn now(&self) -> Timestamp {
        Timestamp(self.0.load(Ordering::SeqCst))
    }
}

/// A fresh 0700 directory under the system temp dir, removed on drop.
pub(crate) struct TestDir(PathBuf);

impl TestDir {
    pub(crate) fn new() -> Self {
        let mut name = String::from("qv-core-test-");
        for b in qv_crypto::random_array::<8>().unwrap() {
            name.push_str(&format!("{b:02x}"));
        }
        let path = std::env::temp_dir().join(name);
        qv_store::create_private_dirs(&path).unwrap();
        Self(path)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    vault: Vec<u8>,
    anchors: Vec<(std::ffi::OsString, Vec<u8>)>,
}

fn fixture() -> &'static Fixture {
    static F: OnceLock<Fixture> = OnceLock::new();
    F.get_or_init(|| {
        let d = TestDir::new();
        let env = Env::empty(d);
        let created = {
            let _k = kdf();
            env.core().create(&env.path, &pw(PASSWORD), NAME).unwrap()
        };
        created.session.lock();
        let anchors = std::fs::read_dir(&env.anchors)
            .unwrap()
            .map(|e| {
                let e = e.unwrap();
                (e.file_name(), std::fs::read(e.path()).unwrap())
            })
            .collect();
        Fixture {
            vault: std::fs::read(&env.path).unwrap(),
            anchors,
        }
    })
}

/// A vault path, its anchor directory and a fixed clock.
pub(crate) struct Env {
    pub(crate) dir: TestDir,
    pub(crate) path: PathBuf,
    pub(crate) anchors: PathBuf,
    pub(crate) time: Arc<FixedTime>,
}

impl Env {
    /// An empty directory (no vault yet).
    pub(crate) fn empty(dir: TestDir) -> Env {
        let path = dir.path().join("v.qvault");
        let anchors = dir.path().join("anchors");
        Env {
            dir,
            path,
            anchors,
            // Starts at the real time: the store stamps control records with
            // the system clock.
            time: Arc::new(FixedTime(AtomicI64::new(crate::SystemTime.now().0))),
        }
    }

    /// A copy of the fixture vault and its anchor.
    pub(crate) fn new() -> Env {
        let env = Env::empty(TestDir::new());
        let f = fixture();
        std::fs::write(&env.path, &f.vault).unwrap();
        set_mode(&env.path, 0o600);
        qv_store::create_private_dirs(&env.anchors).unwrap();
        for (name, bytes) in &f.anchors {
            let p = env.anchors.join(name);
            std::fs::write(&p, bytes).unwrap();
            set_mode(&p, 0o600);
        }
        env
    }

    pub(crate) fn core(&self) -> Core {
        let anchors = AnchorDir::open(&self.anchors).unwrap();
        Core::new(CoreConfig {
            anchors,
            time: self.time.clone(),
            snapshots: None,
        })
    }

    /// A core with the given clock and snapshot policy.
    pub(crate) fn core_with(&self, snapshots: Option<SnapshotPolicy>) -> Core {
        let anchors = AnchorDir::open(&self.anchors).unwrap();
        Core::new(CoreConfig {
            anchors,
            time: self.time.clone(),
            snapshots,
        })
    }

    /// A snapshot policy in the test directory's `snapshots/`.
    pub(crate) fn snapshot_policy(&self) -> SnapshotPolicy {
        SnapshotPolicy::new(SnapshotDir::open(&self.dir.path().join("snapshots")).unwrap())
    }

    /// Unlocks the vault with a snapshot policy (the KDF serialized).
    pub(crate) fn unlock_with(&self, policy: Option<SnapshotPolicy>) -> Session {
        let core = self.core_with(policy);
        let _k = kdf();
        core.unlock(&self.path, &pw(PASSWORD), None).unwrap()
    }

    /// Unlocks the vault (the KDF serialized).
    pub(crate) fn unlock(&self) -> Session {
        let core = self.core();
        let _k = kdf();
        core.unlock(&self.path, &pw(PASSWORD), None).unwrap()
    }
}

/// The error of a result that must fail.
pub(crate) fn err<T>(r: Result<T, crate::CoreError>) -> crate::CoreError {
    match r {
        Ok(_) => panic!("unexpectedly succeeded"),
        Err(e) => e,
    }
}

/// Exercise the production copy/authorize/mutate/complete flow. Callers must
/// configure a real SnapshotPolicy; this helper grants no test-only bypass.
pub(crate) fn destructive<T>(
    s: &Session,
    f: impl FnOnce() -> Result<T, crate::CoreError>,
) -> Result<T, crate::CoreError> {
    let copy = s.begin_destructive(false, None)?;
    let result = f();
    let finished = s.finish_destructive(copy);
    let value = result?;
    finished?;
    Ok(value)
}

/// The store's commit sequence number.
pub(crate) fn seq(s: &Session) -> u64 {
    s.overview().unwrap().local_seq
}

/// A new group under `parent`.
pub(crate) fn add_group(s: &Session, parent: crate::GroupHandle, name: &str) -> crate::GroupHandle {
    let d = s.new_group(parent, name).unwrap();
    s.save_group(d).unwrap()
}

/// A new login entry with a username, a protected password, a URL, a
/// multiline memo and notes.
pub(crate) fn add_entry(s: &Session, group: crate::GroupHandle, title: &str) -> crate::EntryHandle {
    use qv_model::{FieldKind, FieldValue, Text};
    let mut d = s.new_entry(group, "login", title).unwrap();
    d.add_field(
        "Username",
        FieldKind::Text,
        FieldValue::text("alice").unwrap(),
    )
    .unwrap();
    d.add_field(
        "Password",
        FieldKind::Secret,
        FieldValue::text("hunter2").unwrap(),
    )
    .unwrap();
    d.add_field(
        "URL",
        FieldKind::Url,
        FieldValue::text("https://github.com/login").unwrap(),
    )
    .unwrap();
    d.add_field(
        "Memo",
        FieldKind::Multiline,
        FieldValue::text("memo text").unwrap(),
    )
    .unwrap();
    d.entry_mut().notes = Some(Text::new("xyzzy notes").unwrap());
    s.save_entry(d).unwrap()
}
