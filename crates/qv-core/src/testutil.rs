// SPDX-License-Identifier: AGPL-3.0-or-later

//! Test fixtures: private temporary directories, a serialized KDF, a fixed
//! clock, and one fixture vault per test binary that each test copies.

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use qv_crypto::MasterPassword;
use qv_model::Timestamp;
use qv_store::{AnchorDir, SnapshotDir};

use crate::{Core, CoreConfig, Session, SnapshotPolicy, TimeSource};

pub(crate) const PASSWORD: &str = "correct horse battery staple";
pub(crate) const NAME: &str = "Personal";

static KDF: Mutex<()> = Mutex::new(());

/// Serializes Argon2id runs (256 MiB each).
pub(crate) fn kdf() -> MutexGuard<'static, ()> {
    KDF.lock().unwrap_or_else(|p| p.into_inner())
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
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
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
        std::fs::set_permissions(&env.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&env.anchors)
            .unwrap();
        for (name, bytes) in &f.anchors {
            let p = env.anchors.join(name);
            std::fs::write(&p, bytes).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
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
