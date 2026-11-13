# Plan 0052 — Windows platform and release (roadmap 3.1)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — Windows CI run, attended checklist and fresh review pending | 2026-11-12 | 2026-11-12 (owner request "execute the Windows phases"; design owner-delegated, standing 2026-11-02) | 0009 §2, §5 (amended, Draft); 0004 §1.1, §1.3; 0008 §1.2–1.4, §3, §5; 0002 §5.2; 0011 §3; 0012 §3 |

## Intent

The owner asked for the Windows phases to run now ("I want you to execute the
Windows phases", 2026-11-12) and to use best judgement without questions.
Roadmap phase 3.1 brings the existing CLI (`qv`) and the shared Dioxus app
(`quickvault`) to Windows with real OS adapters and file-safety rules
equivalent to the Linux ones. It also adds a Windows CI target, packaging and
a manual gate checklist. Features that cannot be validated stay disabled.

## Scope

**In scope:**
- A Windows-only OS binding crate `qv-win`. It is the only crate that uses
  `unsafe`, and it exposes small safe wrappers.
- `qv-store` on Windows: ACL-based owner-only checks, the parent-directory
  rule, reparse-point refusal, file identity, the process lock, no-replace and
  replace renames, durable flushes, directory locks, sidecar checks, default
  directories and location warnings. Every store module then compiles and
  runs on Windows (today it gets the fail-closed `unsupported` API).
- `qv-core`, `qv-sync`, `qv-crypto`: enable the Windows paths (LAN windows,
  exchange, error mapping); Windows process-hardening status.
- `qv-platform`: `WindowsPlatform` with WTS session/sleep notifications, a
  Win32 clipboard with history/cloud exclusion, the single-instance lock,
  no-follow explicit user files and native open/save dialogs. Protection
  status is reported honestly; quick unlock is unavailable.
- `qv-cli`: Windows console secret input (no echo), clipboard, default
  config path, signals. Portable tests run on Windows.
- `qv-app`: desktop build on Windows (WebView2), Windows platform wiring,
  default directories, file dialogs, prefs file privacy.
- CI: a `windows-latest` job (fmt, Clippy, tests). Packaging: a release zip
  with `SHA256SUMS`. Docs, specs and the gate checklist.

**Out of scope:**
- A Windows quick-unlock backend (Windows Hello / TPM). 0002 §5.2 needs a
  specified and tested envelope first, and none is validated here, so quick
  unlock stays unavailable on Windows (0009 §5).
- Autofill on Windows: no desktop autofill exists on any platform (0009 OQ2).
- Authenticode signing: needs the owner's certificate. Unsigned artifacts are
  a recorded release blocker.
- Windows on arm64, MSI/MSIX installers, winget: later.
- Milestone 2's open items (2.10a acceptance, 2.11 evidence, the D12 review)
  stay open. This phase runs before them on the owner's explicit request.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Owner-only files, private directory, no symlinks, no replacement | 0004 §1.1, §1.3 | Accepted | "equivalent ACLs elsewhere"; Windows mapping in 0009 §5.1 |
| Lock on screen lock/sleep (WTS) | 0009 §5; 0008 §1.4 | Draft (D5 go-ahead) | Required on Windows; failure blocks unlock |
| Reduced-protection acknowledgement | 0008 §1.3 | Draft (D5) | Storage, swap and hibernation evidence is Unknown on Windows |
| Clipboard flags and owned clear | 0008 §3 | Draft (D5) | Windows exclusion formats |
| Quick unlock disabled without a validated backend | 0002 §5.2; 0009 §5 | Accepted / Draft | |
| No-echo TTY prompts | 0009 §3; 0011 §3 | Draft / Accepted | Windows console |
| Release gates | 0012 §3 | Accepted | CI plus a manual checklist |

**Spec changes required:** 0009 §5.1 "Windows profile" (Draft spec,
amendment owner-delegated, step 1). It covers the ACL mapping, lifecycle
signals, clipboard formats, default locations, the Windows baseline and the
disabled features. Changelog line plus the `specs/README.md` index note. No
Accepted spec changes.

## Decisions needed

None open. Each choice below was delegated by the owner (standing,
2026-11-02, and "do the best judgement", 2026-11-12):

1. **Order.** Run 3.1 before 2.10a acceptance and 2.11. The owner asked for
   it explicitly. Milestone 2 evidence stays open; nothing in 3.1 depends on
   it.
2. **`unsafe` boundary.** A new crate `qv-win` (Windows-only, empty
   elsewhere) on `windows-sys` 0.61.2. That crate is already in `Cargo.lock`
   and already exempted in `supply-chain/config.toml`, so no new third-party
   crate is added. `unsafe` is allowed only there. Every block carries
   `// SAFETY:`, enforced by `clippy::undocumented_unsafe_blocks = deny`.
   All other crates keep `unsafe_code = forbid`.
   *Rejected:*
   - the `windows` crate: its calls are equally unsafe, and it is heavier;
   - ACL wrapper crates: unmaintained, and more security-relevant code;
   - running `icacls`: localized, fragile output;
   - leaving Windows on `unsupported`: the phase requires it.
3. **ACL mapping of 0004 §1.1** (trusted SIDs are the current user,
   LocalSystem and BUILTIN\Administrators, the Windows counterparts of root):
   - **Vault file** (any vault-adjacent private file):
     - a regular file, not a reparse point;
     - owned by the current user;
     - a DACL is present (a NULL DACL fails);
     - every effective allow ACE names a trusted SID;
     - an unknown ACE type fails closed.
   - **Parent directory:** owned by a trusted SID, and no allow ACE grants
     write-class rights (add file or subdirectory, delete child, delete,
     write DAC or owner, generic write or all) to another SID.
   - **Private directory** (anchors, snapshots, state): the same rule as the
     parent directory, plus no reparse point, and owned by the user.
   - **Creation:** new files and directories get a protected DACL with one
     full-control ACE for the user. The owner is set to the user.
4. **File identity and locks.**
   - Identity: the volume serial plus the 128-bit file ID
     (`FileIdInfo`).
   - Process lock: an exclusive non-blocking `LockFileEx` on one byte at
     offset `0x7FFF_FFFF_FFFF_FF00`. That is far beyond SQLite's lock bytes,
     and Windows locks are mandatory, so it must never cover data.
   - Opaque files: a shared lock on the same byte.
   - Our handles share read, write and delete. They never request DELETE
     access, so SQLite can still open the file.
   - Directory lock: a named mutex
     `Local\QuickVault-dir-<volume serial>-<file id>` (blocking; a mutex
     abandoned by a dead process counts as acquired). The guard is `!Send`.
     *Rejected:* lock files, because they clutter user folders.
5. **Durability and renames.**
   - Files: `FlushFileBuffers`.
   - No-replace rename: `MoveFileExW(MOVEFILE_WRITE_THROUGH)`, which fails on
     an existing target.
   - Anchor replacement: `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`.
   - Directory sync: a documented no-op. NTFS journals metadata, and the
     renames are write-through.
   - Windows cannot rename a file SQLite holds open. `VaultFile::relocate`
     (rotation install) closes the connection, renames under the retained
     lock handle, then reopens and re-hardens the connection and rechecks
     identity. Any failure is an error, never a weaker fallback.
6. **Lifecycle.** A hidden top-level window on its own thread receives:
   - `WTSRegisterSessionNotification(NOTIFY_FOR_THIS_SESSION)`:
     - `WTS_SESSION_LOCK` → `ScreenLocked`;
     - console or remote disconnect → `ScreenLocked`;
     - logoff → `ProtectionLost`;
   - `WM_POWERBROADCAST/PBT_APMSUSPEND` → `PreparingForSleep`;
   - `WM_ENDSESSION` → `ProtectionLost`.

   The initial state comes from `WTSQuerySessionInformationW(WTSSessionInfoEx)`
   after registration: locked → `ScreenLocked`. A thread or registration
   failure → `ProtectionLost` and lifecycle unavailable. Windows uses
   `with_platform` (lifecycle required), so a failed watcher blocks unlock.
   Linux's optional rule (0009 §5) does not extend to Windows.
7. **Clipboard.**
   - Content: `CF_UNICODETEXT`, plus `ExcludeClipboardContentFromMonitorProcessing`,
     `CanIncludeInClipboardHistory` = 0 and `CanUploadToCloudClipboard` = 0.
   - Ownership: the sequence number recorded after `SetClipboardData`.
   - Replacement (the sequence changes) → `ClipboardReplaced`. Like Android,
     Windows cannot confirm consumption.
   - Expiry: if the clipboard is still ours, zero the global memory, then
     `EmptyClipboard`. It never clears a successor.
   - Buffers: the UTF-16 staging buffer is a `SecretBytes`.
   - Limit: values are capped at 256 KiB, as on X11.
8. **Protection status.**
   - Storage, swap and hibernation evidence: `Unknown`. BitLocker or
     page-file status needs admin rights or WMI, so the reduced-protection
     acknowledgement is required, as on Linux without evidence.
   - Process hardening: `Unsupported` for core dumps and debugger attach,
     which is surfaced. A same-user debugger cannot be prevented, and WER
     opt-out writes persistent registry state.
   - Memory locking: `VirtualLock` through `region` (already used).
9. **Locations** (device-local, never roaming):
   - `%LOCALAPPDATA%\QuickVault\{vaults,anchors,snapshots,state}`;
   - CLI config `%APPDATA%\QuickVault\config.toml`.

   The variables must be absolute. Location warnings:
   - `GetDriveTypeW` remote → network;
   - removable or CD-ROM → removable;
   - the existing sync-folder names and markers.
10. **Dialogs.** `GetOpenFileNameW`/`GetSaveFileNameW` (flat comdlg32 API,
    Explorer style, no COM vtables, which `windows-sys` lacks). The selected
    path then goes through the no-follow file checks.
11. **Baseline and toolchain.**
    - Windows 10 22H2 or Windows 11, x86_64, WebView2 Evergreen runtime
      (preinstalled on supported Windows).
    - Release and CI target: `x86_64-pc-windows-msvc`. Local cross-checks use
      `x86_64-pc-windows-gnu` (mingw-w64) with tests under Wine.
    - Wine is development evidence only. It is not Windows ACL or session
      semantics, and not release evidence.
12. **Packaging.** `crates/qv-app/scripts/package-windows.ps1` builds both
    binaries in release mode into `quickvault-<version>-windows-x86_64.zip`
    with `SHA256SUMS` and the licence. It is unsigned until the owner supplies
    a certificate, which is a release blocker. CI uploads the zip as a
    workflow artifact.

## Design

**Components touched:**
- `qv-win` (new, bottom level, no qv dependency). Trust boundary: trusted
  client code; it is the only place with raw OS calls.
- `qv-store` `fs`: becomes `fs/mod.rs`, which picks `fs/unix.rs` or
  `fs/windows.rs` behind the same crate-private API.
- `qv-platform` `windows` module; qv-core/cli/app wiring. Frontends still
  reach the store only through `qv-core`.

**Interfaces (qv-win, all safe):**

```rust
pub struct FileId { pub volume: u64, pub id: u128 }
pub enum Kind { File, Dir, Reparse, Other }
pub struct Handle(std::fs::File);                 // owns a HANDLE via std
pub fn open(path: &Path, access: Access, create: Create, dir: bool) -> io::Result<File>;
pub fn kind_nofollow(path: &Path) -> io::Result<Kind>; // FILE_FLAG_OPEN_REPARSE_POINT
pub fn kind_of(file: &File) -> io::Result<Kind>;
pub fn file_id(file: &File) -> io::Result<FileId>;
pub fn try_lock(file: &File, exclusive: bool) -> io::Result<bool>; // false = busy
pub fn unlock(file: &File) -> io::Result<()>;
pub fn flush(file: &File) -> io::Result<()>;
pub fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()>;
pub fn rename_replace(from: &Path, to: &Path) -> io::Result<()>;
pub enum Privacy { OwnerOnly, NoForeignWrite }
pub fn check_private(file: &File, rule: Privacy, owner_user: bool) -> io::Result<bool>;
pub fn create_private_file(path: &Path) -> io::Result<File>; // CREATE_NEW, protected DACL
pub fn create_private_dir(path: &Path) -> io::Result<()>;
pub fn set_owner_only(path: &Path) -> io::Result<()>;      // tests and repair-free fixtures
pub fn grant_everyone(path: &Path, write: bool) -> io::Result<()>; // test fixtures
pub struct NamedLock(..);  pub fn named_lock(name: &str) -> io::Result<NamedLock>; // !Send
pub enum Drive { Fixed, Remote, Removable, Unknown }
pub fn drive_type(path: &Path) -> Drive;
pub mod session;   // SessionWatcher::start(cb) -> io::Result<SessionWatcher>; events enum
pub mod clipboard; // Owner::set(&[u16]) -> Result<Owned>; Owned::state(); Owned::clear_if_owned()
pub mod console;   // RawConsole::enter() -> guard; read_char(timeout) -> Option<char>
pub mod dialog;    // open_file(title, filter) / save_file(title, name) -> Option<PathBuf>
```

**Data and control flow:** Write ordering is unchanged; only primitives change.
- Create: temp `CREATE_NEW` + DACL → SQLite builds, closes → flush → anchor →
  `rename_noreplace` (write-through) → reopen.
- Anchor: temp → flush → re-read → `rename_replace` (write-through).
- Rotation `relocate`: close conn → `rename_noreplace` → reopen hardened →
  identity check.
- Crash points stay where they are; tests run on Windows.

**Secrets and hostile input:**
- The clipboard staging and console input buffers are `SecretBytes` and
  bounded (256 KiB for the clipboard; the CLI's existing caps for input).
- The console reads one UTF-16 unit at a time into the fixed buffer, so it
  never reallocates.
- OS copies (the clipboard global memory after handover, console history) are
  documented best-effort limits. Console line editing is ours (no
  `ENABLE_LINE_INPUT`), so conhost keeps no history of secret lines.
- Hostile files: ACL and identity checks run before SQLite opens anything,
  as on Linux.

**Errors:** `io::Error` raw OS codes map to the existing redacted
`StoreError`/`PlatformError` variants:
- `ERROR_FILE_NOT_FOUND`/`PATH_NOT_FOUND` → `NotFound`;
- `ALREADY_EXISTS`/`FILE_EXISTS` → `Exists`;
- `LOCK_VIOLATION`/`SHARING_VIOLATION` → `Locked`;
- `DISK_FULL`/`HANDLE_DISK_FULL` → `StorageCapacity`;
- `CANT_ACCESS_FILE`/reparse → `UnsafeFile`;
- anything else → `Io`.

No path or OS message is included.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| windows-sys 0.61.2 (features only, already locked) | Win32 FFI declarations for qv-win | `windows` crate; hand-written `extern` blocks (more unsafe surface) | Existing exemption (plan 0030, recorded debt); Microsoft-maintained; no Cargo.lock package added |

## Steps

### Step 1 — Spec and plan

- [x] **Do:** Add 0009 §5.1 "Windows profile" (decisions 3–11) + Changelog;
  `specs/README.md` note; plan index row; roadmap revision entry.
- **Files:** `specs/0009-clients-and-platforms.md`, `specs/README.md`,
  `plans/README.md`, `plans/0002-roadmap/PLAN.md`.
- **Done when:** the text matches the decisions; Draft status kept.
- **Verify:** `sh scripts/check-spdx.sh`.

### Step 2 — qv-win crate

- [x] **Do:** Create `crates/qv-win` (`#![cfg(windows)]` body; explicit lints
  equal to the workspace's except `unsafe_code = "allow"`, plus
  `clippy::undocumented_unsafe_blocks`, `unsafe_op_in_unsafe_fn`,
  `clippy::multiple_unsafe_ops_per_block` denied). Implement the interface
  above with unit tests: ACL classification (owner-only and Everyone-read
  fixtures), lock contention between two handles, no-replace rename on an
  existing target, reparse detection (symlink, needs privilege, which CI has),
  named-lock exclusion across threads, drive type of the temp dir, and the
  clipboard and session watcher smoke tests.
- **Files:** `crates/qv-win/**`, root `Cargo.toml` (workspace dep).
- **Done when:** it cross-checks with Clippy and its tests pass under Wine. On
  Linux it is an empty crate.
- **Verify:** `cargo clippy -p qv-win --target x86_64-pc-windows-gnu --all-targets -- -D warnings`;
  `cargo test -p qv-win --target x86_64-pc-windows-gnu` (Wine runner).

### Step 3 — qv-store file layer on Windows

- [x] **Do:** Move `fs.rs` to `fs/unix.rs` and write `fs/windows.rs` with the
  same crate-private API.
  - Add portable helpers that replace the direct `rustix` uses elsewhere:
    - `fs::probe(path) -> Result<Option<Probe>>` (exists or not, regular,
      owner-only);
    - `fs::sync_file(&File)`;
    - `fs::create_private_dir`;
    - `fs::fs_warnings(&File)`.
  - Add a Windows `os_err` next to `errno_err`.
  - Change every `any(target_os = "linux", target_os = "android")` store gate
    to `any(target_os = "linux", target_os = "android", windows)`.
  - Make `relocate` reopen the connection on Windows.
  - Anchor default dir under `%LOCALAPPDATA%`.
  - Make the test fixtures portable: `write_file(path, bytes, mode)` and
    `subdir(name, mode)` map group/other bits to an Everyone ACE on Windows.
  - Mark tests that depend on Unix-only facts (FIFOs, `/proc`, uid 0, raw
    mode bits) `#[cfg(unix)]`, and give the security-relevant ones a Windows
    counterpart (foreign ACE, reparse point, lock, replacement).
- **Files:** `crates/qv-store/src/**`, `crates/qv-store/Cargo.toml`.
- **Done when:** Linux tests are unchanged and green, and the Windows
  cross-check and the Wine test run of qv-store are green.
- **Verify:** `cargo test --locked -p qv-store`; the Windows commands with
  `-p qv-store`.

### Step 4 — core, sync, crypto on Windows

- [x] **Do:**
  - Enable the qv-sync and qv-core Windows paths (`exchange`, the error
    mapping, LAN).
  - Add `Core::with_windows_platform`, which is `with_platform` with
    lifecycle required, so it is equivalent to calling `with_platform`;
    document that.
  - Snapshot default dir.
  - Gate Unix-only tests.
- **Files:** `crates/qv-core/src/**`, `crates/qv-sync/src/**`, `crates/qv-crypto/src/**`.
- **Done when:** the Windows check and the Wine tests of these crates pass,
  and Linux is unchanged.
- **Verify:** `cargo test --locked -p qv-core -p qv-sync -p qv-crypto` plus the Windows equivalents.

### Step 5 — qv-platform Windows adapters

- [x] **Do:** Add `windows` module:
  - `WindowsPlatform` (status per decision 8);
  - `WtsLifecycle` (decision 6);
  - `WinClipboard` (decision 7, `hold` loop with a 250 ms poll of the
    sequence number and cancellation);
  - `InstanceLock` (an exclusive lock on `instance.lock` in an owner-only
    directory, no reparse);
  - `files` (no-follow explicit read and create-new write, mirroring the
    Linux `files` API);
  - `dialog` re-exports;
  - `net` enabled on Windows.
- **Files:** `crates/qv-platform/**`.
- **Done when:** the unit tests (status, an injected watcher callback, the
  clipboard set/replace/clear-if-owned sequence, the instance lock contention,
  file refusal of reparse and foreign ACL) pass under Wine where Wine
  implements the API. The session tests are smoke tests: real lock events
  are a manual gate.
- **Verify:** the Windows commands with `-p qv-platform`.

### Step 6 — CLI on Windows

- [x] **Do:** Split `term.rs` behind a backend:
  - Unix: rustix termios (unchanged);
  - Windows: `qv_win::console` with the same `Tty` API (no echo, editing keys,
    Ctrl-C/Ctrl-D cancel, deadline and cancel polling, bounded buffer).

  Then:
  - `--password-stdin` on Windows reads the stdin handle;
  - clipboard → `WinClipboard`;
  - config path per decision 9;
  - signals: SIGINT and SIGTERM (no SIGHUP);
  - the 0011 §4 ancestor rule uses the ACL parent rule on Windows;
  - portable integration tests run on Windows, and pty-driven ones stay
    `cfg(unix)`.
- **Files:** `crates/qv-cli/**`.
- **Done when:** Linux is unchanged, the Windows build and Clippy pass, and
  the portable tests pass under Wine.
- **Verify:** `cargo test --locked -p qv-cli`; the Windows equivalents.

### Step 7 — App on Windows

- [x] **Do:**
  - Desktop runtime: `WindowsPlatform`, the instance lock under
    `%LOCALAPPDATA%\QuickVault\state`, default vault folder.
  - Documents: Windows dialogs + `files`.
  - Prefs privacy: an ACL-private file.
  - Gate Linux-only validation helpers.
  - Ensure the vendored dioxus-desktop compiles for Windows (no patch
    expected).
- **Files:** `crates/qv-app/src/**`, `crates/qv-app/Cargo.toml` (description).
- **Done when:** `cargo clippy -p qv-app --features desktop --target x86_64-pc-windows-gnu`
  is clean, and the app's non-GUI tests pass under Wine.
- **Verify:** the Windows commands with `-p qv-app --features desktop`.

### Step 8 — CI and packaging

- [x] **Do:** Add a `windows` job on `windows-latest` (pinned actions as in the
  existing jobs):
  - toolchain;
  - `cargo fmt --check`;
  - `cargo clippy --all-targets --locked -- -D warnings`;
  - `cargo clippy -p qv-app --features desktop`;
  - `cargo test --locked`;
  - `package-windows.ps1`;
  - upload the zip artifact.

  Write `crates/qv-app/scripts/package-windows.ps1`.
- **Files:** `.github/workflows/ci.yml`, `crates/qv-app/scripts/package-windows.ps1`.
- **Done when:** the YAML parses, the script is reviewed, and the SPDX header
  is present.
- **Verify:** `python3 -c 'import yaml'` if available, else a careful read;
  `sh scripts/check-spdx.sh`.

### Step 9 — Gate checklist, docs, final gates

- [x] **Do:**
  - Write `plans/0052-windows-platform/WINDOWS-GATES.md`: the manual checklist
    for a real Windows 10/11 machine (lock and sleep events, clipboard
    history and cloud exclusion, ACLs of created files, dialogs, WebView2
    CSP/IPC boundary, secret-input cleanup limits, reduced-protection
    disclosure).
  - Update `ARCHITECTURE.md` §3 (qv-win, the platform row) and §6.
  - `CHANGELOG.md`; `AGENTS.md` (the unsafe exception is qv-win only);
    `.agents/README.md` if needed.
  - Roadmap log.
  - Run all gates on Linux plus the Windows cross-checks and the Wine tests.
- **Files:** as listed.
- **Done when:** gates pass; the checklist exists with every item marked
  pending.
- **Verify:** all `AGENTS.md` gates; Windows cross-commands.

## Test plan

- Final verification: all `AGENTS.md` gates on Linux, plus the following
  Windows commands (gnu target; Wine runner for tests):
  - `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings`;
  - `cargo clippy -p qv-app --features desktop --target x86_64-pc-windows-gnu -- -D warnings`;
  - `cargo test --workspace --target x86_64-pc-windows-gnu`.

  Real Windows evidence comes from the CI job (MSVC) and the manual
  checklist.
- Unit tests: qv-win ACL/lock/rename/identity; store fixtures portable.
- Rejection tests on Windows:
  - foreign-SID ACEs on the vault, the parent and the anchor dir;
  - reparse points at the vault, anchor and snapshot paths;
  - a second-process lock;
  - path replacement;
  - `-wal`/`-shm` sidecars;
  - a foreign `-journal`;
  - stale temps.
- Crash tests: the existing crash-point suite runs on Windows.
- 0012 §1 rows: the existing tagged tests now also run on Windows. No new row
  names.

## Risks and stop conditions

- Wine diverges from Windows for ACLs, sessions and the clipboard. Tests that
  only fail under Wine because of a Wine gap are marked with
  `QV_WINE=1`-gated skips that print why. They are never skipped on real
  Windows (CI).
- If SQLite cannot reopen after `relocate`, stop: rotation must not continue
  with a closed connection.
- If an ACL rule would refuse ordinary user folders (for example
  `Documents`), record it and fix the rule rather than weaken the vault-file
  rule.
- No security claim from cross-compilation or CI alone (0012 §3).

## Documentation

- [ ] `CHANGELOG.md` — Unreleased: Windows support (CLI and app), CI,
  packaging.
- [ ] `ARCHITECTURE.md` — §3 rows (qv-win; qv-platform and qv-store Windows),
  §6 technology row.
- [ ] Specs — 0009 §5.1 + Changelog; `specs/README.md` note.
- [ ] `AGENTS.md` — `unsafe` only in `qv-win`, with SAFETY comments; Windows
  cross-check commands.
- [ ] `plans/README.md` — index row; roadmap revision and log.

## Revisions

- 2026-11-12 (during implementation, owner-delegated; each change is
  recorded in the execution log):
  - **Rules.** The trusted principals now include TrustedInstaller, which
    owns `C:\`. Every rule accepts any trusted owner, because SQLite's own
    journal may be owned by Administrators for an elevated user.
  - **Rule set.** The ACL rules are `OwnerOnly`, `NoForeignWrite`,
    `VaultParent` and `NoForeignReplace`.
    - `VaultParent` also refuses foreign ACEs that new files would inherit,
      because SQLite creates `-journal` with inherited security. It applies
      to vault parents and private directories.
    - `NoForeignReplace` is for the ancestors of explicit user files, so
      that `C:\`'s "create folders" right for Authenticated Users does not
      refuse every path.
  - **SQLite and renames.** Windows also refuses to remove or rename a file
    while SQLite holds it.
    - `VaultFile::into_lock` closes the connection and keeps the lock.
      Restore publication and rotation cleanup/rollback use it.
    - `PreparedRotation::install` binds `_cleanup` first, so an early return
      closes the replacement's connection before the file is removed.
  - **Removal.** Store removals use POSIX-semantics deletion by handle
    (`qv_win::fs::remove_nofollow`), so names disappear at once like
    `unlink`.
  - **Receipt names.** Archive receipt names keep the stored `/`-separated
    form: `/C:/…` and `/UNC/server/share/…`.
  - **New public helper.** `qv_store::create_private_dirs` is re-exported by
    qv-core. Frontends and tests create owner-only folders through it.
- 2026-11-13 (first CI `windows` run, owner-delegated): **LAN listeners.**
  `PairingWindow::open` kept only the first socket that bound, `[::]`. That
  socket is dual stack on Linux but IPv6-only on Windows, so a QR's IPv4
  endpoints were refused and `lan_app_scanned_codes_start_the_join_and_the_sync`
  timed out. `endpoint::listen` now binds `[::]`, then `0.0.0.0` on the same
  port (that bind fails harmlessly where `[::]` is dual stack); the acceptor
  polls every listener and drops them all on admission. This restores the
  dual-stack intent of plan 0037 decision 7 and covers Linux `bindv6only`.
  It is transport only: no wire, crypto or spec change.

## Execution log

- 2026-11-12: Steps 1–8 implemented.
  - **Step 1, spec and plan.** 0009 §5.1 Windows profile (Draft) with
    Changelog; specs index note; plan index row; roadmap revision entry.
  - **Step 2, qv-win.** The crate covers:
    - pure security-descriptor parsing and the rules, with unit tests that
      run on Linux too;
    - the FFI modules `fs`, `sync`, `session`, `clipboard`, `console` and
      `dialog`.

    Its lints deny `unsafe` outside the FFI modules, and
    `undocumented_unsafe_blocks` and `multiple_unsafe_ops_per_block` are
    denied.
  - **Step 3, store.**
    - `fs_windows.rs` and `incoming_path_windows.rs`.
    - Portable `fs::{entry, sync_file, create_private_dir_all, remove_file}`
      and `LockedFile::write_all` replace the direct `rustix` calls outside
      `fs`.
    - Every store module is enabled on Windows; `unsupported.rs` remains
      only for other targets.
    - `relocate` reopens the connection, re-hardens it and compares the
      header after a close-rename.
    - Tests use portable `test_dir::{set_mode, has_mode, symlink}`.
    - `tests/lock.rs` and `tests/tamper.rs` are ported through
      `tests/common`.
  - **Step 4, core/sync/crypto.**
    - Windows paths are enabled.
    - Test fixtures are portable (`create_private_dirs`, `set_mode`).
    - The quick-unlock tests remain Linux-only: their synthetic platform
      has no lifecycle, which only Linux's optional rule accepts.
    - `budget_bench` compiles everywhere.
  - **Step 5, platform.** The `windows` module (`WindowsPlatform`,
    `WtsLifecycle`, `WinClipboard`, `InstanceLock`, `pick`) and
    `files_windows.rs`.
  - **Step 6, CLI.**
    - `term.rs`: a Windows console backend for the shared line editor, plus
      an unbuffered `--password-stdin` read.
    - `out.rs` writes straight to the handle (`WriteConsoleW` for a
      console); the virtual-terminal mode is enabled for the alternate
      screen.
    - Clipboard backend selection, no SIGHUP on Windows, and the
      `%APPDATA%` config path.
    - The PTY end-to-end tests stay Linux-only, and two ungated test files
      got the gate. New `tests/windows.rs` pipe smoke tests.
  - **Step 7, app.**
    - Picker, file and runtime gates widened to Windows, with a
      `documents::Pick` alias (portal or Windows dialogs).
    - `desktop_setup` with `WindowsPlatform` and the
      `%LOCALAPPDATA%\QuickVault\state` instance lock.
    - Default vault folder `%LOCALAPPDATA%\QuickVault\vaults`.
    - Windows file-name rules and messages; private folders through
      `create_private_dirs`.
  - **Step 8, CI and packaging.** The `windows` CI job, with
    upload-artifact v7.0.2 pinned by SHA (released 2026-10-07);
    `package-windows.ps1`; the SPDX checker now covers `*.ps1`, with a
    rejection test.
  - **Wine findings** (development harness only; they do not affect
    Windows behaviour):
    - ACLs are stored as Unix modes.
    - There is no inheritance.
    - A POSIX-deleted name stays listed while the creating handle is open.
    - Read-only DACLs are not enforced.
    - `FileIdInfo` reports volume serial 0 on some handles. Identity
      therefore takes the serial from `GetFileInformationByHandle` and
      compares against the identity recorded at lease time.

    The runner uses `umask 077`, and named assertions skip only under
    `QV_WINE=1`.
  - **Found, not fixed.** The vendored dioxus-desktop has two Windows-only
    warnings (unused import, unused `show_toast`). It is vendored upstream
    code and not a product lint failure; no vendor patch was made for it.

- 2026-11-12: Plan written and approved. The owner asked for the Windows
  phases and delegated all decisions. The tree held the uncommitted roadmap
  renumbering (plan-only). The owner asked not to be questioned, so this
  phase continues on that tree. The 2.10a / 0040–0051 fresh reviews are still
  pending and were not run: the owner's explicit request names Windows, and
  those reviews are recorded in their own plans.

- 2026-11-12 (stopped at the usage limit; step 9 not finished).
  - **Results so far.**
    - qv-win, qv-store (with its integration tests), qv-platform, qv-crypto,
      qv-protocol, qv-model and qv-encoding pass under Wine.
    - qv-core and qv-sync pass under Wine after two Wine-only skips.
    - Windows Clippy is clean for the workspace and for the desktop app.
    - Both Windows executables link (gnu).
    - Linux Clippy is clean.
    - `cargo vet --locked` and `check-supply-chain.py` pass.
  - **`cargo deny`.** It failed on the new RUSTSEC-2026-0486 (rustix 1.1.5
    xattr functions, unused by QuickVault). rustix was moved to 1.1.6 in the
    workspace pin, Cargo.lock, fuzz/Cargo.lock and the vet exemption.
    deny and vet have NOT been rerun after that move.
  - **Bug fixed.** The app's vault list accepted only paths starting with
    `/`, so Windows paths were dropped. It now uses `Path::is_absolute`.
  - **Remaining.**
    - Rerun deny and vet; rerun the full Linux gates (the full Linux test
      run was in progress: Xvfb had been truncated by a full /tmp, and the
      CLI dependency-pin test was updated).
    - Port the Unix path literals in the qv-app vaults/workspace tests and
      the qv-cli config/select tests to Windows (they fail under Wine).
    - Investigate the app's `protection_ack_needed` test under Windows.
    - Rerun the Wine runs of qv-cli and qv-app.
    - Run `cargo fmt`.
    - Finish step 9's checks, then the roadmap tick/log, plans/README status.

- 2026-11-12: Resumed and finished step 9.
  - **Fixes:**
    - Windows path literals in the qv-cli config/select tests.
    - The Unix-path vault-list tests are `cfg(unix)`, plus a new Windows
      drive/UNC test.
    - The app phone-model test acknowledges protection when the host cannot
      harden the process (Windows).
    - The `desktop_setup` rename in two runtime tests.
    - The CLI dependency-pin test now pins the common, Unix and Windows
      tables exactly.
  - **Final evidence**, on the final tree unless noted:
    - SPDX (with the `.ps1` rejection test), matrix and `cargo fmt --check`
      pass.
    - `cargo clippy --all-targets --locked -D warnings` is clean on Linux,
      and on the Windows gnu cross target for the workspace and for qv-app
      `desktop`. Linux qv-app `validation` Clippy is clean.
    - `cargo test --locked` on Linux (private Xvfb): 1018 passed, 0 failed.
      The run started before the last fix, the two `desktop`-only runtime
      test calls covered by the next item.
    - `cargo test -p qv-app --features validation`: 102 + 3 real-engine
      flows pass.
    - `cargo deny check` (product, plus fuzz advisories/bans/sources),
      `cargo vet --locked` and `check-supply-chain.py` pass after rustix
      1.1.6.
    - Wine (development evidence only), every workspace crate: pass,
      including the qv-cli `tests/windows.rs` smoke tests of the real
      `qv.exe`.
    - The gnu cross build links `quickvault.exe` and `qv.exe`.
  - **Pending:**
    - The first CI `windows` run (MSVC, real Windows).
    - Every attended item in WINDOWS-GATES.md.
    - Authenticode signing (the owner's certificate).
    - The fresh-context review (quickvault-reviewer).
