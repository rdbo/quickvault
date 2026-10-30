// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unlock and resource-budget benchmark (plan 0024; 0002 §1.3, 0004 §4).
//!
//! ```text
//! budget_bench generate <dir> <P0|P1|P2|P3>   # host: builds <dir>/vault/v.qvault
//! budget_bench measure  <dir> [samples]       # Linux or Android: prints CSV
//! ```
//!
//! `generate` writes a disposable vault through the store's public `Write`
//! API in batches (a frontend would commit one edit at a time), then runs a
//! full verification. `measure` runs one warm-up and `samples` (default 5)
//! measured samples. Each sample is a fresh child process, so its peak
//! resident set (`VmHWM`) is its own:
//! - `Core::unlock`: the full password-kdf/1 run, the header MAC, unlock
//!   verification, the anchor check and the metadata views;
//! - `Session::verify`: the full integrity pass;
//! - one ordinary edit through core (a new version of the first entry), with
//!   its manifest, local head and anchor step;
//! - then the session is locked.
//!
//! The password is a development constant stored in `<dir>/password` (0600),
//! never on the command line. Generated vaults hold synthetic data only.
//! The output is one CSV row per sample:
//! `profile,unlock_ms,verify_ms,write_ms,peak_rss_kib,file_bytes`.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Instant;

use qv_core::{AnchorDir, Core, CoreConfig, MasterPassword};
use qv_crypto::RecordId;
use qv_model::{
    Clock, Entry, Extensions, Field, FieldId, FieldKind, FieldValue, Payload, RandomId, RecordBody,
    RecordVersion, Text, Timestamp, VersionId,
};
use qv_store::VaultFile;

type R<T> = Result<T, String>;

const PASSWORD: &[u8] = b"budget benchmark development passphrase, not a secret";
const BATCH: usize = 1_000;

fn err<E: core::fmt::Debug>(what: &'static str) -> impl FnOnce(E) -> String {
    move |e| format!("{what}: {e:?}")
}

fn password() -> R<MasterPassword> {
    MasterPassword::from_utf8(PASSWORD).map_err(err("password"))
}

/// The vault, anchor and password paths of a benchmark directory.
struct Layout {
    vault: PathBuf,
    anchors: PathBuf,
    password: PathBuf,
}

impl Layout {
    fn of(dir: &Path) -> Layout {
        Layout {
            vault: dir.join("vault").join("v.qvault"),
            anchors: dir.join("anchors"),
            password: dir.join("password"),
        }
    }
}

fn private_dir(p: &Path) -> R<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(p)
        .map_err(err("create directory"))
}

/// What one profile contains.
struct Profile {
    records: usize,
    versions: usize,
    attachments: usize,
    attachment_bytes: usize,
}

fn profile(name: &str) -> R<Profile> {
    Ok(match name {
        "P0" => Profile {
            records: 0,
            versions: 0,
            attachments: 0,
            attachment_bytes: 0,
        },
        "P1" => Profile {
            records: 1_000,
            versions: 4,
            attachments: 20,
            attachment_bytes: 1024 * 1024,
        },
        // The root group, keyslot and settings records count toward the
        // 50,000-record budget (0004 §4.1): 49,997 entries reach it exactly.
        "P2" => Profile {
            records: 50_000 - 3,
            versions: 4,
            attachments: 0,
            attachment_bytes: 0,
        },
        // Padded chunk ciphertext (0002 §3, PADME) makes a 10 MiB attachment
        // about 10.3 MiB of the 1 GiB total-ciphertext budget: 99 fit, the
        // 100th is LimitExceeded.
        "P3" => Profile {
            records: 1,
            versions: 1,
            attachments: 99,
            attachment_bytes: 10 * 1024 * 1024,
        },
        _ => return Err(format!("unknown profile {name}")),
    })
}

fn text(s: &str) -> R<Text> {
    Text::new(s).map_err(err("text"))
}

/// One live entry version of `record` with a username and a protected
/// password field.
fn entry_version(
    root: RecordId,
    w: &mut qv_store::Write<'_>,
    record: RecordId,
    n: usize,
    round: usize,
) -> R<RecordVersion> {
    let counter = w.reserve_counter().map_err(err("counter"))?;
    let clock =
        Clock::for_edit(&w.head_clocks(record), w.writer_id(), counter).map_err(err("clock"))?;
    let field = |name: &str, kind, value: String| -> R<Field> {
        Ok(Field {
            id: FieldId::generate().map_err(err("field id"))?,
            name: text(name)?,
            kind,
            protected: kind == FieldKind::Secret,
            value: FieldValue::text(&value).map_err(err("field value"))?,
            ext: Extensions::new(),
        })
    };
    Ok(RecordVersion {
        version_id: VersionId::generate().map_err(err("version id"))?,
        clock,
        modified_at: Timestamp(1_700_000_000_000 + round as i64),
        body: RecordBody::Live(Payload::Entry(Entry {
            group: root,
            type_hint: text("login")?,
            title: text(&format!("Entry {n:05}"))?,
            fields: vec![
                field("username", FieldKind::Text, format!("user{n}@example.org"))?,
                field(
                    "password",
                    FieldKind::Secret,
                    format!("synthetic-{n}-{round}-0123456789abcdef"),
                )?,
            ],
            notes: None,
            icon: None,
            expires_at: None,
            created_at: Timestamp(1_700_000_000_000),
            modified_at: Timestamp(1_700_000_000_000 + round as i64),
            deleted_at: None,
            ext: Extensions::new(),
        })),
        ext: Extensions::new(),
    })
}

/// Deterministic, incompressible-enough attachment bytes.
struct Pattern {
    left: usize,
    state: u64,
}

impl std::io::Read for Pattern {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = buf.len().min(self.left);
        for b in buf.iter_mut().take(n) {
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *b = (self.state >> 56) as u8;
        }
        self.left -= n;
        Ok(n)
    }
}

fn generate(dir: &Path, name: &str) -> R<()> {
    let p = profile(name)?;
    let l = Layout::of(dir);
    private_dir(l.vault.parent().ok_or("vault path")?)?;
    private_dir(&l.anchors)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&l.password)
        .map_err(err("password file"))?;
    f.write_all(PASSWORD).map_err(err("password file"))?;
    let anchors = AnchorDir::open(&l.anchors).map_err(err("anchors"))?;
    let started = Instant::now();
    let mut vault =
        VaultFile::create(&l.vault, &password()?, "Benchmark", &anchors).map_err(err("create"))?;
    let ids: Vec<RecordId> = (0..p.records)
        .map(|_| <RecordId as RandomId>::generate().map_err(err("record id")))
        .collect::<R<_>>()?;
    for round in 0..p.versions {
        for (b, chunk) in ids.chunks(BATCH).enumerate() {
            let root = vault.manifest().root_group_id();
            let mut w = vault.write().map_err(err("write"))?;
            for (i, id) in chunk.iter().enumerate() {
                let v = entry_version(root, &mut w, *id, b * BATCH + i, round)?;
                w.put_local(*id, v).map_err(err("put"))?;
            }
            w.commit().map_err(|e| {
                format!(
                    "commit of records {}..{} in round {} of {}: {e:?}",
                    b * BATCH,
                    b * BATCH + chunk.len(),
                    round + 1,
                    p.versions
                )
            })?;
        }
        eprintln!("{name}: round {} of {} written", round + 1, p.versions);
    }
    let owner = ids.first().copied();
    for a in 0..p.attachments {
        let entry = owner.ok_or("attachments need an entry")?;
        let id = <RecordId as RandomId>::generate().map_err(err("attachment id"))?;
        let mut w = vault.write().map_err(err("write"))?;
        let mut source = Pattern {
            left: p.attachment_bytes,
            state: a as u64 + 1,
        };
        let staged = w
            .stage_attachment(id, &mut source, &|| false)
            .map_err(|e| format!("staging attachment {} of {}: {e:?}", a + 1, p.attachments))?;
        let meta = staged.into_meta(
            entry,
            text(&format!("a{a}.bin"))?,
            text("application/octet-stream")?,
        );
        let counter = w.reserve_counter().map_err(err("counter"))?;
        let clock =
            Clock::for_edit(&w.head_clocks(id), w.writer_id(), counter).map_err(err("clock"))?;
        let version = RecordVersion {
            version_id: VersionId::generate().map_err(err("version id"))?,
            clock,
            modified_at: Timestamp(1_700_000_000_000),
            body: RecordBody::Live(Payload::AttachmentMeta(meta)),
            ext: Extensions::new(),
        };
        w.put_local(id, version).map_err(err("put"))?;
        w.commit().map_err(err("commit"))?;
    }
    let counts = vault.verify_all(&|| false).map_err(err("verify"))?;
    drop(vault);
    let size = std::fs::metadata(&l.vault).map_err(err("stat"))?.len();
    eprintln!(
        "{name}: generated {size} bytes in {:.1} s; {counts:?}",
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// The peak resident set of this process, from `/proc/self/status`.
fn peak_rss_kib() -> R<u64> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(err("status"))?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().strip_suffix("kB"))
        .and_then(|v| v.trim().parse().ok())
        .ok_or_else(|| "no VmHWM".to_owned())
}

/// One sample in this process: the CSV row without the profile name.
fn sample(dir: &Path) -> R<String> {
    let l = Layout::of(dir);
    let stored = std::fs::read(&l.password).map_err(err("password file"))?;
    if stored != PASSWORD {
        return Err("unexpected password file".to_owned());
    }
    let core = Core::new(CoreConfig::new(
        AnchorDir::open(&l.anchors).map_err(err("anchors"))?,
    ));
    let t = Instant::now();
    let session = core
        .unlock(&l.vault, &password()?, None)
        .map_err(err("unlock"))?;
    let unlock_ms = t.elapsed().as_secs_f64() * 1000.0;
    let t = Instant::now();
    session.verify(None).map_err(err("verify"))?;
    let verify_ms = t.elapsed().as_secs_f64() * 1000.0;
    // One ordinary edit: a new version of the first entry (a new entry in an
    // empty vault), committed with its manifest and anchor step.
    let t = Instant::now();
    let root = session.root().map_err(err("root"))?;
    let first = session
        .list(root)
        .map_err(err("list"))?
        .entries
        .first()
        .map(|e| e.handle);
    let draft = match first {
        Some(entry) => {
            let mut d = session.edit_entry(entry).map_err(err("edit"))?;
            d.entry_mut().title = text("Edited by the benchmark")?;
            d
        }
        None => session
            .new_entry(root, "login", "Written by the benchmark")
            .map_err(err("new entry"))?,
    };
    session.save_entry(draft).map_err(err("save"))?;
    let write_ms = t.elapsed().as_secs_f64() * 1000.0;
    session.lock();
    let size = std::fs::metadata(&l.vault).map_err(err("stat"))?.len();
    Ok(format!(
        "{unlock_ms:.1},{verify_ms:.1},{write_ms:.1},{},{size}",
        peak_rss_kib()?
    ))
}

fn measure(dir: &Path, samples: usize) -> R<()> {
    let name = dir
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("directory name")?
        .to_owned();
    let exe = std::env::current_exe().map_err(err("current exe"))?;
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "profile,unlock_ms,verify_ms,write_ms,peak_rss_kib,file_bytes"
    )
    .map_err(err("stdout"))?;
    for i in 0..=samples {
        let o = Command::new(&exe)
            .arg("sample")
            .arg(dir)
            .output()
            .map_err(err("spawn"))?;
        if !o.status.success() {
            return Err(format!(
                "sample failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        // Sample 0 is the warm-up.
        if i > 0 {
            let row = String::from_utf8_lossy(&o.stdout);
            writeln!(out, "{name},{}", row.trim()).map_err(err("stdout"))?;
        }
    }
    Ok(())
}

fn run() -> R<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["generate", dir, name] => generate(Path::new(dir), name),
        ["measure", dir] => measure(Path::new(dir), 5),
        ["measure", dir, n] => measure(Path::new(dir), n.parse().map_err(err("samples"))?),
        ["sample", dir] => {
            let row = sample(Path::new(dir))?;
            writeln!(std::io::stdout(), "{row}").map_err(err("stdout"))
        }
        _ => Err(
            "usage: budget_bench generate <dir> <P0|P1|P2|P3> | measure <dir> [samples]".to_owned(),
        ),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "budget_bench: {e}");
            ExitCode::FAILURE
        }
    }
}
