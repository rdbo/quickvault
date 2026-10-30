// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rotation installation and restart evidence (plan 0023 steps 1–4; 0012 §1
//! rows "Rotation/purge ambiguity" (interrupted rotation), "Migration
//! coupling" (data part), "Whole-file rollback" and "Hostile SQLite/CBOR"
//! (journal file)). Every transition ends with exactly one generation
//! openable, its anchor verified and its logical state equal to the source.

use std::path::{Path, PathBuf};

use qv_crypto::{KeyGeneration, RecordId, VaultKey};
use qv_model::Timestamp;

use super::platform::{Leftover, Paths, classify};
use super::*;
use crate::crash::{CrashPoint, test as crash};
use crate::fs::test_dir::{TestDir, write_file};
use crate::vault::tests::{PASSWORD, err, kdf, pw, unlock};
use crate::{
    AnchorDir, AnchorStatus, Manifest, PreparedRotation, RotationJournal, RotationJournalBody,
    SnapshotDir, SnapshotInventory, SnapshotKind, StoreError, UnlockedVault, VaultFile,
};

const NEW: &str = "replacement generation passphrase for installation tests";
const NAME: &str = "v.qvault";

/// A vault directory, its anchor directory and its snapshot directory.
struct Env {
    vault: TestDir,
    _a: TestDir,
    _s: TestDir,
    anchors: AnchorDir,
    snaps: SnapshotDir,
}

impl Env {
    fn path(&self) -> PathBuf {
        self.vault.join(NAME)
    }

    /// The three directories as the crash harness copies them.
    fn dirs(&self) -> [(PathBuf, &'static str); 3] {
        [
            (self.vault.path().to_owned(), "vault"),
            (self.anchors.path().to_owned(), "anchors"),
            (self.snaps.path().to_owned(), "snapshots"),
        ]
    }

    fn arm(&self, point: CrashPoint, to: &TestDir) {
        let dirs = self.dirs();
        let refs: Vec<(&Path, &str)> = dirs.iter().map(|(p, l)| (p.as_path(), *l)).collect();
        crash::arm_dirs(point, &refs, to.path());
    }

    /// Byte evidence of every file in the three directories.
    fn evidence(&self) -> Vec<(PathBuf, Vec<u8>)> {
        let mut rows = Vec::new();
        for (dir, _) in self.dirs() {
            for e in std::fs::read_dir(&dir).unwrap() {
                let path = e.unwrap().path();
                if path.is_file() {
                    rows.push((path.clone(), std::fs::read(&path).unwrap()));
                }
            }
        }
        rows.sort();
        rows
    }

    fn vault_names(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(self.vault.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    fn inventory_exists(&self, u: &UnlockedVault, g: u32) -> bool {
        self.snaps
            .path()
            .join(crate::snapshot_inventory::file_name(
                u.header().vault_id,
                KeyGeneration(g),
            ))
            .exists()
    }

    /// A copy of the three directories made by the crash harness in `at`.
    fn from_crash(at: &TestDir) -> Env {
        let root = TestDir::new();
        let vault = TestDir::new();
        copy_into(&at.path().join("vault"), vault.path());
        let a = root;
        let anchors = a.subdir("anchors", 0o700);
        copy_into(&at.path().join("anchors"), &anchors);
        let s = TestDir::new();
        let snaps = s.subdir("snapshots", 0o700);
        copy_into(&at.path().join("snapshots"), &snaps);
        Env {
            vault,
            anchors: AnchorDir::open(&anchors).unwrap(),
            snaps: SnapshotDir::open(&snaps).unwrap(),
            _a: a,
            _s: s,
        }
    }

    /// An independent copy of this environment.
    fn duplicate(&self) -> Env {
        let at = TestDir::new();
        for (dir, label) in self.dirs() {
            let to = at.subdir(label, 0o700);
            copy_into(&dir, &to);
        }
        Env::from_crash(&at)
    }
}

fn copy_into(from: &Path, to: &Path) {
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
        }
    }
}

/// The shared fixture with history and a multi-chunk attachment, plus a
/// snapshot directory and an ordinary snapshot of generation 1.
fn env() -> (Env, UnlockedVault) {
    let (vault, a, mut u, _) = crate::verify_tests::setup();
    let s = TestDir::new();
    let snaps = SnapshotDir::open(&s.join("snapshots")).unwrap();
    snaps
        .publish(
            &mut u,
            SnapshotKind::Ordinary,
            Timestamp(1_700_000_000_000),
            &|| false,
        )
        .unwrap();
    let anchors = u.anchors.clone();
    (
        Env {
            vault,
            _a: a,
            _s: s,
            anchors,
            snaps,
        },
        u,
    )
}

fn bytes16(hex: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

/// The logical state, keyslot excluded: records, heads, history, floors.
type Logical = Vec<(
    RecordId,
    Vec<(qv_model::VersionId, qv_model::Clock)>,
    Vec<qv_model::VersionId>,
    String,
)>;

fn logical(m: &Manifest) -> Logical {
    m.records()
        .iter()
        .filter(|r| r.record_id() != m.keyslot_id())
        .map(|r| {
            (
                r.record_id(),
                r.heads()
                    .iter()
                    .map(|h| (h.version_id(), h.clock().clone()))
                    .collect(),
                r.history().iter().map(|h| h.version_id()).collect(),
                format!("{:?}", r.floor().clock()),
            )
        })
        .collect()
}

/// Everything an installation needs: the recovery snapshot (pinned by the
/// caller in core), the prepared replacement and its inventory.
struct Ready {
    prepared: PreparedRotation,
    inventory: SnapshotInventory,
    snapshot: [u8; 16],
    source: Logical,
    generation: u32,
}

fn ready(e: &Env, mut u: UnlockedVault) -> Ready {
    let snapshot = bytes16(
        e.snaps
            .publish(
                &mut u,
                SnapshotKind::Recovery,
                Timestamp(1_700_000_100_000),
                &|| false,
            )
            .unwrap()
            .archive_id(),
    );
    let source = logical(u.manifest());
    let generation = u.header().key_generation.0;
    let prepared = {
        let _k = kdf();
        u.prepare_rotation(&pw(NEW), &|| false).unwrap()
    };
    let inventory = e.snaps.prepare_inventory(&prepared, &|| false).unwrap();
    Ready {
        prepared,
        inventory,
        snapshot,
        source,
        generation,
    }
}

fn install(e: &Env, r: Ready) -> Result<Installed, InstallError> {
    r.prepared
        .install(&e.snaps, &r.inventory, r.snapshot, &|| false)
}

/// Exactly the new generation is active and anchored, with no siblings.
fn assert_new(e: &Env, source: &Logical, generation: u32) {
    assert_eq!(e.vault_names(), vec![NAME.to_owned()]);
    assert!(!rotation_pending(&e.path()).unwrap());
    assert_eq!(
        err(unlock(&e.path(), &e.anchors, PASSWORD)),
        StoreError::WrongPassword
    );
    let u = unlock(&e.path(), &e.anchors, NEW).unwrap();
    assert_eq!(u.header().key_generation.0, generation + 1);
    assert_eq!(&logical(u.manifest()), source);
    u.verify_all(&|| false).unwrap();
    assert!(e.inventory_exists(&u, generation + 1));
    assert!(!e.inventory_exists(&u, generation));
    let inv = e.snaps.inventory(&u).unwrap().unwrap();
    assert!(!inv.rows().is_empty());
}

/// Exactly the old generation is active and anchored, with no siblings.
fn assert_old(e: &Env, source: &Logical, generation: u32) {
    assert_eq!(e.vault_names(), vec![NAME.to_owned()]);
    assert!(!rotation_pending(&e.path()).unwrap());
    assert_eq!(
        err(unlock(&e.path(), &e.anchors, NEW)),
        StoreError::WrongPassword
    );
    let u = unlock(&e.path(), &e.anchors, PASSWORD).unwrap();
    assert_eq!(u.header().key_generation.0, generation);
    assert_eq!(&logical(u.manifest()), source);
    assert!(!e.inventory_exists(&u, generation + 1));
}

fn open(e: &Env) -> Result<InterruptedRotation, StoreError> {
    let _k = kdf();
    InterruptedRotation::open(
        &e.path(),
        &e.anchors,
        Some(&pw(PASSWORD)),
        Some(&pw(NEW)),
        &|| false,
    )
}

/// Stops an installation at `point` and returns the on-disk copy.
fn crashed_at(point: CrashPoint) -> (Env, Logical, u32) {
    let (e, u) = env();
    let r = ready(&e, u);
    let (source, generation) = (r.source.clone(), r.generation);
    let at = TestDir::new();
    e.arm(point, &at);
    let _ = install(&e, r);
    assert!(!crash::disarm(), "{point:?} never fired");
    (Env::from_crash(&at), source, generation)
}

// ---- Step 1: primitives -------------------------------------------------

#[test]
fn rotation_install_primitives_names_and_leftover_patterns() {
    let s = [0xab; 16];
    let p = Paths::of(Path::new("/d/v.qvault"), &s);
    let hex = "ab".repeat(16);
    assert_eq!(p.marker, Path::new("/d/v.qvault.qvrotate"));
    assert_eq!(
        p.old,
        PathBuf::from(format!("/d/v.qvault.qvrotate-old-{hex}"))
    );
    assert_eq!(
        p.new,
        PathBuf::from(format!("/d/v.qvault.qvrotate-new-{hex}"))
    );
    let v = b"v.qvault";
    let t = "0123456789abcdef";
    let cases: [(String, Option<Leftover>); 11] = [
        (
            format!("v.qvault.qvrotate-new-{hex}"),
            Some(Leftover::Removable),
        ),
        (
            format!("v.qvault.qvrotate-new-{hex}-journal"),
            Some(Leftover::Removable),
        ),
        (
            format!(".v.qvault.qvrotate-new-{hex}.tmp-{t}"),
            Some(Leftover::Removable),
        ),
        (
            format!(".v.qvault.qvrotate-new-{hex}.tmp-{t}-journal"),
            Some(Leftover::Removable),
        ),
        (
            format!(".v.qvault.qvrotate.tmp-{t}"),
            Some(Leftover::Removable),
        ),
        (format!("v.qvault.qvrotate-old-{hex}"), Some(Leftover::Old)),
        ("v.qvault.qvrotate".to_owned(), None),
        ("v.qvault".to_owned(), None),
        (format!("v.qvault.qvrotate-new-{}", "AB".repeat(16)), None),
        (format!("w.qvault.qvrotate-new-{hex}"), None),
        (format!("v.qvault.qvrotate-new-{hex}x"), None),
    ];
    for (name, want) in cases {
        assert_eq!(classify(v, name.as_bytes()), want, "{name}");
    }
}

#[test]
fn rotation_install_primitives_leftovers_removed_old_kept() {
    let (e, u) = env();
    let hex = "cd".repeat(16);
    let t = "0123456789abcdef";
    let removable = [
        format!("v.qvault.qvrotate-new-{hex}"),
        format!("v.qvault.qvrotate-new-{hex}-journal"),
        format!(".v.qvault.qvrotate-new-{hex}.tmp-{t}"),
        format!(".v.qvault.qvrotate.tmp-{t}"),
    ];
    for n in &removable {
        write_file(&e.vault.join(n), b"x", 0o600);
    }
    let kept = [
        format!("v.qvault.qvrotate-old-{hex}"),
        format!("w.qvault.qvrotate-new-{hex}"),
        "notes.txt".to_owned(),
    ];
    for n in &kept {
        write_file(&e.vault.join(n), b"y", 0o600);
    }
    let next = e.snaps.path().join(crate::snapshot_inventory::file_name(
        u.header().vault_id,
        KeyGeneration(2),
    ));
    write_file(&next, b"unused", 0o600);
    let found = u.remove_rotation_leftovers(&e.snaps).unwrap();
    assert_eq!(
        found,
        Leftovers {
            removed: 5,
            retained_old: 1
        }
    );
    let mut want: Vec<String> = kept.to_vec();
    want.push(NAME.to_owned());
    want.sort();
    assert_eq!(e.vault_names(), want);
    assert!(!next.exists());

    // A symlink matching a pattern is refused, never followed.
    std::os::unix::fs::symlink(
        e.vault.join("notes.txt"),
        e.vault.join(&format!("v.qvault.qvrotate-new-{hex}")),
    )
    .unwrap();
    assert_eq!(
        err(u.remove_rotation_leftovers(&e.snaps)),
        StoreError::UnsafeFile
    );
    assert!(e.vault.join("notes.txt").exists());
    std::fs::remove_file(e.vault.join(&format!("v.qvault.qvrotate-new-{hex}"))).unwrap();

    // Never while a marker exists.
    write_file(&crate::rotation_guard::marker(&e.path()), b"", 0o600);
    assert!(rotation_pending(&e.path()).unwrap());
    let before = e.evidence();
    assert_eq!(
        err(u.remove_rotation_leftovers(&e.snaps)),
        StoreError::Integrity
    );
    assert_eq!(e.evidence(), before);
}

#[test]
fn rotation_install_primitives_transition_role_and_marker_reads() {
    let (e, u) = env();
    drop(u);
    // A transition copy is verified but never written or adopted.
    let lock = crate::fs::open_existing(&e.path()).unwrap();
    let file =
        VaultFile::open_locked_as(&e.path(), lock, crate::vault::FileRole::Transition).unwrap();
    let vk = {
        let _k = kdf();
        crate::slot::password_slot(&file.slots)
            .unwrap()
            .keyslot
            .slot
            .unlock(
                &pw(PASSWORD),
                file.header.vault_id,
                file.header.key_generation,
            )
            .unwrap()
    };
    let mut t = file.finish_candidate(vk, &e.anchors).unwrap();
    assert_eq!(err(t.write().map(|_| ())), StoreError::Integrity);
    assert_eq!(err(t.adopt_baseline()), StoreError::Integrity);
    drop(t);

    // Marker reads: symlink, directory, group-readable, oversized, garbage.
    let marker = crate::rotation_guard::marker(&e.path());
    let open =
        || InterruptedRotation::open(&e.path(), &e.anchors, None, None, &|| false).map(|_| ());
    std::os::unix::fs::symlink(e.path(), &marker).unwrap();
    assert_eq!(err(open()), StoreError::UnsafeFile);
    std::fs::remove_file(&marker).unwrap();
    std::fs::create_dir(&marker).unwrap();
    assert!(matches!(
        err(open()),
        StoreError::UnsafeFile | StoreError::Io
    ));
    std::fs::remove_dir(&marker).unwrap();
    write_file(&marker, b"\xa0", 0o644);
    assert_eq!(err(open()), StoreError::UnsafeFile);
    write_file(
        &marker,
        &vec![0u8; crate::MAX_ROTATION_JOURNAL_BYTES + 1],
        0o600,
    );
    assert_eq!(err(open()), StoreError::Integrity);
    write_file(&marker, b"not cbor", 0o600);
    assert_eq!(err(open()), StoreError::Integrity);
    // A marker held by another opener is Locked.
    let held = crate::fs::open_existing(&marker).unwrap();
    assert_eq!(err(open()), StoreError::Locked);
    drop(held);
    // The ordinary open refuses throughout; the vault stays intact.
    assert_eq!(err(VaultFile::open(&e.path())), StoreError::Integrity);
}

// ---- Step 2: installation ------------------------------------------------

#[test]
fn rotation_install_publishes_the_new_generation() {
    let (e, u) = env();
    let r = ready(&e, u);
    let (source, generation, snapshot) = (r.source.clone(), r.generation, r.snapshot);
    let done = install(&e, r).unwrap();
    assert_eq!(done.new_generation.0, generation + 1);
    assert!(!done.cleanup_pending);
    assert_new(&e, &source, generation);
    // The recovery snapshot of the old generation is carried and counted.
    let u = unlock(&e.path(), &e.anchors, NEW).unwrap();
    let inv = e.snaps.inventory(&u).unwrap().unwrap();
    assert!(inv.rows().iter().any(|r| r.archive_id == snapshot));
    assert_eq!(inv.rows().len(), 2);
    assert_eq!(u.state.head.local_seq, {
        let a = e
            .anchors
            .load(&u.state.replica.replica_id)
            .unwrap()
            .unwrap();
        a.local_seq
    });
}

#[test]
fn rotation_install_refuses_changed_state_before_publication() {
    // The anchor changed under the prepared rotation.
    let (e, u) = env();
    let r = ready(&e, u);
    let replica = r.prepared.source.state.replica.replica_id;
    let mut anchor = e.anchors.load(&replica).unwrap().unwrap();
    anchor.local_seq += 7;
    e.anchors.store(&replica, &anchor).unwrap();
    let before = e.evidence();
    let failed = install(&e, r).unwrap_err();
    assert_eq!(failed.error, StoreError::Rollback);
    assert!(!failed.journal_published);
    // Only the private candidate disappeared.
    let after = e.evidence();
    assert!(after.iter().all(|x| before.contains(x)));
    assert!(!rotation_pending(&e.path()).unwrap());
    assert_eq!(e.vault_names(), vec![NAME.to_owned()]);

    // A marker that appeared meanwhile.
    let (e, u) = env();
    let r = ready(&e, u);
    write_file(&crate::rotation_guard::marker(&e.path()), b"", 0o600);
    let failed = install(&e, r).unwrap_err();
    assert_eq!(failed.error, StoreError::Integrity);
    assert!(!failed.journal_published);

    // Cancellation before the journal: nothing published.
    let (e, u) = env();
    let r = ready(&e, u);
    let failed = r
        .prepared
        .install(&e.snaps, &r.inventory, r.snapshot, &|| true)
        .unwrap_err();
    assert_eq!(failed.error, StoreError::Io);
    assert!(!failed.journal_published);
    assert_eq!(e.vault_names(), vec![NAME.to_owned()]);
    let u = unlock(&e.path(), &e.anchors, PASSWORD).unwrap();
    assert!(!e.inventory_exists(&u, 2));
}

#[test]
fn rotation_install_reports_cleanup_pending_after_the_anchor() {
    for point in [
        CrashPoint::RotationAnchored,
        CrashPoint::RotationOldRemoved,
        CrashPoint::RotationInventoryRetired,
    ] {
        let (e, u) = env();
        let r = ready(&e, u);
        let at = TestDir::new();
        e.arm(point, &at);
        let done = install(&e, r).unwrap();
        assert!(done.cleanup_pending, "{point:?}");
        // The live directories are committed: a restart finishes cleanup
        // with the new password alone.
        let need = needed_passwords(&e.path(), &e.anchors).unwrap();
        assert_eq!(
            need,
            NeededPasswords {
                old: false,
                new: true
            }
        );
        let t = {
            let _k = kdf();
            InterruptedRotation::open(&e.path(), &e.anchors, None, Some(&pw(NEW)), &|| false)
                .unwrap()
        };
        assert_eq!(t.state(), RotationState::Committed);
        t.finish(RotationChoice::Complete, &e.snaps, &|| false)
            .unwrap();
        assert_eq!(e.vault_names(), vec![NAME.to_owned()]);
        unlock(&e.path(), &e.anchors, NEW).unwrap();
    }
}

// ---- Step 3: restart -----------------------------------------------------

/// A copy's VK, recovered through its phrase (test-only path to the key).
fn vk_of(path: &Path, password: &str, anchors: &AnchorDir) -> VaultKey {
    let _k = kdf();
    let lock = crate::fs::open_existing(path).unwrap();
    let f = VaultFile::open_locked_as(path, lock, crate::vault::FileRole::Transition).unwrap();
    let vk = crate::slot::password_slot(&f.slots)
        .unwrap()
        .keyslot
        .slot
        .unlock(&pw(password), f.header.vault_id, f.header.key_generation)
        .unwrap();
    let u = f.finish_candidate(vk, anchors).unwrap();
    let phrase = u.recovery_phrase(&pw(password)).unwrap();
    let words: Vec<&str> = (0..24).map(|i| phrase.expose_word(i).unwrap()).collect();
    VaultKey::from_recovery_phrase(words.join(" ").as_bytes()).unwrap()
}

#[test]
fn rotation_resume_classifies_and_finishes_each_state() {
    for (point, state) in [
        (
            CrashPoint::RotationJournalPublished,
            RotationState::CandidateReady,
        ),
        (
            CrashPoint::RotationActiveRetired,
            RotationState::ActiveRetired,
        ),
        (CrashPoint::RotationInstalled, RotationState::AnchorPending),
        (CrashPoint::RotationAnchored, RotationState::Committed),
    ] {
        let (e, source, g) = crashed_at(point);
        assert!(rotation_pending(&e.path()).unwrap());
        assert!(matches!(
            err(unlock(&e.path(), &e.anchors, PASSWORD)),
            StoreError::Integrity | StoreError::NotFound | StoreError::Io
        ));
        let rolled = e.duplicate();
        let t = open(&e).unwrap();
        assert_eq!(t.state(), state, "{point:?}");
        assert_eq!(t.old_generation().0, g);
        assert_eq!(t.new_generation().0, g + 1);
        t.finish(RotationChoice::Complete, &e.snaps, &|| false)
            .unwrap();
        assert_new(&e, &source, g);

        let t = open(&rolled).unwrap();
        if state == RotationState::Committed {
            let before = rolled.evidence();
            assert_eq!(
                err(t.finish(RotationChoice::RollBack, &rolled.snaps, &|| false)),
                StoreError::Integrity
            );
            assert_eq!(rolled.evidence(), before);
        } else {
            t.finish(RotationChoice::RollBack, &rolled.snaps, &|| false)
                .unwrap();
            assert_old(&rolled, &source, g);
            // The recovery snapshot survives, unpinned, for ordinary policy.
            assert!(std::fs::read_dir(rolled.snaps.path()).unwrap().any(|x| {
                x.unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("recover-")
            }));
        }
    }
}

#[test]
fn rotation_resume_needs_the_right_passwords() {
    let (e, _, _) = crashed_at(CrashPoint::RotationInstalled);
    assert_eq!(
        needed_passwords(&e.path(), &e.anchors).unwrap(),
        NeededPasswords {
            old: true,
            new: true
        }
    );
    let before = e.evidence();
    let try_open = |old: Option<&str>, new: Option<&str>| {
        let _k = kdf();
        InterruptedRotation::open(
            &e.path(),
            &e.anchors,
            old.map(pw).as_ref(),
            new.map(pw).as_ref(),
            &|| false,
        )
        .map(|_| ())
    };
    assert_eq!(
        err(try_open(Some(PASSWORD), Some(PASSWORD))),
        StoreError::WrongPassword
    );
    assert_eq!(
        err(try_open(Some(NEW), Some(NEW))),
        StoreError::WrongPassword
    );
    assert_eq!(err(try_open(None, Some(NEW))), StoreError::Integrity);
    assert_eq!(err(try_open(Some(PASSWORD), None)), StoreError::Integrity);
    assert_eq!(e.evidence(), before);
}

#[test]
fn rotation_resume_rollback_pending_and_missing_candidate() {
    // A rollback interrupted after removing the candidate.
    let (e, _, _) = crashed_at(CrashPoint::RotationJournalPublished);
    let t = open(&e).unwrap();
    let at = TestDir::new();
    e.arm(CrashPoint::RollbackCandidateRemoved, &at);
    let _ = t.finish(RotationChoice::RollBack, &e.snaps, &|| false);
    assert!(!crash::disarm());
    let c = Env::from_crash(&at);
    assert_eq!(
        needed_passwords(&c.path(), &c.anchors).unwrap(),
        NeededPasswords {
            old: true,
            new: false
        }
    );
    let t = {
        let _k = kdf();
        InterruptedRotation::open(&c.path(), &c.anchors, Some(&pw(PASSWORD)), None, &|| false)
            .unwrap()
    };
    assert_eq!(t.state(), RotationState::RollbackPending);
    let before = c.evidence();
    assert_eq!(
        err(t.finish(RotationChoice::Complete, &c.snaps, &|| false)),
        StoreError::Integrity
    );
    assert_eq!(c.evidence(), before);
    let t = {
        let _k = kdf();
        InterruptedRotation::open(&c.path(), &c.anchors, Some(&pw(PASSWORD)), None, &|| false)
            .unwrap()
    };
    t.finish(RotationChoice::RollBack, &c.snaps, &|| false)
        .unwrap();
    assert!(!rotation_pending(&c.path()).unwrap());
    unlock(&c.path(), &c.anchors, PASSWORD).unwrap();
}

#[test]
fn rotation_resume_refuses_hostile_journals_copies_and_anchors() {
    let (base, _, _) = crashed_at(CrashPoint::RotationInstalled);
    let marker = crate::rotation_guard::marker(&base.path());
    let journal = RotationJournal::decode(&std::fs::read(&marker).unwrap()).unwrap();
    let b = journal.body();
    let (paths_old, paths_new) = {
        let p = Paths::of(&base.path(), &b.suffix);
        (p.old, p.new)
    };
    let body = |suffix: [u8; 16]| RotationJournalBody {
        operation_id: b.operation_id,
        vault_id: b.vault_id,
        replica_id: b.replica_id,
        old_generation: b.old_generation,
        new_generation: b.new_generation,
        old_sequence: b.old_sequence,
        new_sequence: b.new_sequence,
        old_digest: b.old_digest,
        new_digest: b.new_digest,
        suffix,
        snapshot_id: b.snapshot_id,
        inventory_digest: b.inventory_digest,
    };
    let old_vk = vk_of(&paths_old, PASSWORD, &base.anchors);
    let new_vk = vk_of(&base.path(), NEW, &base.anchors);

    type Tamper = Box<dyn Fn(&Env)>;
    let replica = b.replica_id;
    let rewrite = |bytes: Vec<u8>| -> Tamper {
        Box::new(move |e: &Env| {
            write_file(&crate::rotation_guard::marker(&e.path()), &bytes, 0o600);
        })
    };
    let wrong_new = RotationJournal::sign(body(b.suffix), &old_vk, &VaultKey::generate().unwrap())
        .unwrap()
        .encode()
        .unwrap();
    let wrong_old = RotationJournal::sign(body(b.suffix), &VaultKey::generate().unwrap(), &new_vk)
        .unwrap()
        .encode()
        .unwrap();
    let mut flipped = std::fs::read(&marker).unwrap();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    let old_name = paths_old.file_name().unwrap().to_str().unwrap().to_owned();
    let new_name = paths_new.file_name().unwrap().to_str().unwrap().to_owned();
    let cases: Vec<(&str, Tamper, StoreError)> = vec![
        (
            "new MAC from another key",
            rewrite(wrong_new),
            StoreError::Integrity,
        ),
        (
            "old MAC from another key",
            rewrite(wrong_old),
            StoreError::Integrity,
        ),
        ("flipped MAC bit", rewrite(flipped), StoreError::Integrity),
        (
            "anchor at neither head",
            Box::new(move |e: &Env| {
                let mut a = e.anchors.load(&replica).unwrap().unwrap();
                a.local_digest = [7; 32];
                e.anchors.store(&replica, &a).unwrap();
            }),
            StoreError::Integrity,
        ),
        (
            "missing anchor",
            Box::new(|e: &Env| {
                for x in std::fs::read_dir(e.anchors.path()).unwrap() {
                    std::fs::remove_file(x.unwrap().path()).unwrap();
                }
            }),
            StoreError::NoAnchor,
        ),
        (
            "old copy replaced by the new one",
            Box::new(move |e: &Env| {
                std::fs::copy(e.path(), e.vault.join(&old_name)).unwrap();
            }),
            StoreError::Integrity,
        ),
        (
            "an extra candidate",
            Box::new(move |e: &Env| {
                std::fs::copy(e.path(), e.vault.join(&new_name)).unwrap();
            }),
            StoreError::Integrity,
        ),
        (
            "active missing with only the old copy",
            Box::new(|e: &Env| std::fs::remove_file(e.path()).unwrap()),
            StoreError::Integrity,
        ),
    ];
    for (name, tamper, want) in cases {
        let e = base.duplicate();
        tamper(&e);
        let before = e.evidence();
        assert_eq!(err(open(&e).map(|_| ())), want, "{name}");
        assert_eq!(e.evidence(), before, "{name}");
    }

    // A candidate from another rotation of the same vault: its head digest
    // differs from the journal's.
    let (other, _, _) = crashed_at(CrashPoint::RotationJournalPublished);
    let e = crashed_at(CrashPoint::RotationJournalPublished).0;
    let mine = {
        let j = RotationJournal::decode(
            &std::fs::read(crate::rotation_guard::marker(&e.path())).unwrap(),
        )
        .unwrap();
        Paths::of(&e.path(), &j.body().suffix).new
    };
    let theirs = {
        let j = RotationJournal::decode(
            &std::fs::read(crate::rotation_guard::marker(&other.path())).unwrap(),
        )
        .unwrap();
        Paths::of(&other.path(), &j.body().suffix).new
    };
    std::fs::copy(&theirs, &mine).unwrap();
    let before = e.evidence();
    assert_eq!(err(open(&e).map(|_| ())), StoreError::Integrity);
    assert_eq!(e.evidence(), before);
}

/// The suffix of the journal at `e`.
fn suffix_of(e: &Env) -> [u8; 16] {
    let marker = crate::rotation_guard::marker(&e.path());
    RotationJournal::decode(&std::fs::read(marker).unwrap())
        .unwrap()
        .body()
        .suffix
}

#[test]
fn rotation_resume_refuses_swapped_suffix_foreign_journal_and_stale_old_copy() {
    // A swapped suffix with the siblings renamed to match: names line up,
    // but neither journal MAC covers the new suffix.
    let e = crashed_at(CrashPoint::RotationInstalled).0;
    let marker = crate::rotation_guard::marker(&e.path());
    let bytes = std::fs::read(&marker).unwrap();
    let suffix = suffix_of(&e);
    let swapped = [0x5a; 16];
    let at: Vec<usize> = bytes
        .windows(16)
        .enumerate()
        .filter(|(_, w)| *w == suffix)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(at.len(), 1);
    let mut forged = bytes.clone();
    forged[at[0]..at[0] + 16].copy_from_slice(&swapped);
    assert_eq!(
        RotationJournal::decode(&forged).unwrap().body().suffix,
        swapped
    );
    write_file(&marker, &forged, 0o600);
    std::fs::rename(
        Paths::of(&e.path(), &suffix).old,
        Paths::of(&e.path(), &swapped).old,
    )
    .unwrap();
    let before = e.evidence();
    assert_eq!(err(open(&e).map(|_| ())), StoreError::Integrity);
    assert_eq!(e.evidence(), before);

    // Another vault's journal: no copy has its vault ID.
    let e = crashed_at(CrashPoint::RotationJournalPublished).0;
    let other = crashed_at(CrashPoint::RotationJournalPublished).0;
    write_file(
        &crate::rotation_guard::marker(&e.path()),
        &std::fs::read(crate::rotation_guard::marker(&other.path())).unwrap(),
        0o600,
    );
    let before = e.evidence();
    assert_eq!(err(open(&e).map(|_| ())), StoreError::Integrity);
    assert_eq!(e.evidence(), before);

    // A stale old copy: the same vault and password one commit earlier, so
    // its head is not the journal's old head.
    let (e, mut u) = env();
    let stale = std::fs::read(e.path()).unwrap();
    crate::vault::tests::edit(
        &mut u,
        <RecordId as qv_model::RandomId>::generate().unwrap(),
        "later",
    );
    let r = ready(&e, u);
    let at = TestDir::new();
    e.arm(CrashPoint::RotationInstalled, &at);
    let _ = install(&e, r);
    assert!(!crash::disarm());
    let c = Env::from_crash(&at);
    write_file(&Paths::of(&c.path(), &suffix_of(&c)).old, &stale, 0o600);
    let before = c.evidence();
    assert_eq!(err(open(&c).map(|_| ())), StoreError::Integrity);
    assert_eq!(c.evidence(), before);
}

// ---- Step 4: crash matrix ------------------------------------------------

/// What a crash copy at `point` must recover to, for both choices.
fn recover_both(e: Env, source: &Logical, g: u32, point: CrashPoint) {
    if !rotation_pending(&e.path()).unwrap() {
        // Before the journal: the old vault opens ordinarily; after its
        // removal: the new one does.
        if let Ok(u) = unlock(&e.path(), &e.anchors, PASSWORD) {
            assert_eq!(&logical(u.manifest()), source, "{point:?}");
            u.remove_rotation_leftovers(&e.snaps).unwrap();
            drop(u);
            assert_old(&e, source, g);
        } else {
            assert_new(&e, source, g);
        }
        return;
    }
    assert!(VaultFile::open(&e.path()).is_err(), "{point:?}");
    let rolled = e.duplicate();
    let t = open(&e).unwrap();
    let committed = t.state() == RotationState::Committed;
    t.finish(RotationChoice::Complete, &e.snaps, &|| false)
        .unwrap();
    assert_new(&e, source, g);
    let t = open(&rolled).unwrap();
    if committed {
        assert_eq!(
            err(t.finish(RotationChoice::RollBack, &rolled.snaps, &|| false)),
            StoreError::Integrity
        );
    } else {
        t.finish(RotationChoice::RollBack, &rolled.snaps, &|| false)
            .unwrap();
        assert_old(&rolled, source, g);
    }
}

// 0012 §1: Rotation/purge ambiguity
#[test]
fn rotation_crash_at_every_installation_step() {
    for point in [
        CrashPoint::RotationCandidateNamed,
        CrashPoint::RotationInventoryPublished,
        CrashPoint::RotationJournalPublished,
        CrashPoint::RotationActiveRetired,
        CrashPoint::RotationInstalled,
        CrashPoint::AnchorTempWritten,
        CrashPoint::AnchorReplaced,
        CrashPoint::RotationAnchored,
        CrashPoint::RotationOldRemoved,
        CrashPoint::RotationInventoryRetired,
        CrashPoint::RotationJournalRemoved,
    ] {
        let (e, source, g) = crashed_at(point);
        recover_both(e, &source, g, point);
    }
}

// 0012 §1: Rotation/purge ambiguity
#[test]
fn rotation_crash_while_completing_after_a_restart() {
    for point in [
        CrashPoint::RotationActiveRetired,
        CrashPoint::RotationInstalled,
        CrashPoint::AnchorTempWritten,
        CrashPoint::AnchorReplaced,
        CrashPoint::RotationAnchored,
        CrashPoint::RotationOldRemoved,
        CrashPoint::RotationInventoryRetired,
        CrashPoint::RotationJournalRemoved,
    ] {
        let (e, source, g) = crashed_at(CrashPoint::RotationJournalPublished);
        let t = open(&e).unwrap();
        let at = TestDir::new();
        e.arm(point, &at);
        let _ = t.finish(RotationChoice::Complete, &e.snaps, &|| false);
        assert!(!crash::disarm(), "{point:?} never fired");
        recover_both(Env::from_crash(&at), &source, g, point);
    }
}

// 0012 §1: Rotation/purge ambiguity
#[test]
fn rotation_crash_while_rolling_back_after_a_restart() {
    for point in [
        CrashPoint::RollbackNewRetired,
        CrashPoint::RollbackOldRestored,
        CrashPoint::RollbackCandidateRemoved,
        CrashPoint::RollbackInventoryRemoved,
        CrashPoint::RotationJournalRemoved,
    ] {
        let (e, source, g) = crashed_at(CrashPoint::RotationInstalled);
        let t = open(&e).unwrap();
        let at = TestDir::new();
        e.arm(point, &at);
        let _ = t.finish(RotationChoice::RollBack, &e.snaps, &|| false);
        assert!(!crash::disarm(), "{point:?} never fired");
        let c = Env::from_crash(&at);
        if !rotation_pending(&c.path()).unwrap() {
            assert_old(&c, &source, g);
            continue;
        }
        // Finishing a started rollback again (a rollback never commits the
        // new generation, so Complete is offered only while the candidate
        // exists).
        let need = needed_passwords(&c.path(), &c.anchors).unwrap();
        let t = {
            let _k = kdf();
            InterruptedRotation::open(
                &c.path(),
                &c.anchors,
                Some(&pw(PASSWORD)),
                need.new.then(|| pw(NEW)).as_ref(),
                &|| false,
            )
            .unwrap()
        };
        assert_ne!(t.state(), RotationState::Committed, "{point:?}");
        t.finish(RotationChoice::RollBack, &c.snaps, &|| false)
            .unwrap();
        assert_old(&c, &source, g);
    }
}

#[test]
fn rotation_crash_matrix_debug_is_redacted() {
    let (e, _, _) = crashed_at(CrashPoint::RotationJournalPublished);
    let t = open(&e).unwrap();
    assert_eq!(format!("{t:?}"), "InterruptedRotation(<redacted>)");
    let failed = InstallError {
        error: StoreError::Io,
        journal_published: true,
    };
    assert!(!format!("{failed:?}").contains('/'));
    let _ = AnchorStatus::Verified;
}
