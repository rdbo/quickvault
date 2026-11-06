# Plan 0041 — Vault list, default folder and name-only create

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — fresh review and owner acceptance pending | 2026-11-06 | 2026-11-06 (owner: "the vault redesign should come now"; decisions A and import-in-place by the owner 2026-11-05, the rest owner-delegated) | 0009 §1.8 (amended here); 0011 §4 path rules (unchanged) |

## Intent

The owner found vaults confusing during plan 0040 acceptance:
- the first vault was "this device's vault" whatever its name;
- a second vault needed a file path;
- nothing remembered either vault.

They asked for:
1. a default folder, so creating a vault needs only a name;
2. showing where each vault is stored;
3. a changeable default folder;
4. importing vaults from other folders;
5. remembered vaults.

## Scope

**In scope:**
- Spec 0009 §1.8 amendment: vault names visible as file names (owner
  decision A), and a vault-list file.
- A bounded vault-list file in the app's private directory: the default
  folder and remembered vault paths.
- The default folder, scanned for vaults.
- Name-only create.
- Import in place through the existing picker.
- "Remove from list".
- The lock-screen vault switcher, with names and locations.
- Settings rows for this vault's file and the default folder.
- Tests and flows.

**Out of scope:**
- Moving, renaming or deleting vault files.
- Renaming a file when the vault's internal name changes.
- Android folder choice and import: Android keeps its private folder.
- A vault-name hint on the create screen (the owner: "goes without saying").
- Any vault, crypto, storage-format, protocol or sync change.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Vault file path rules (absolute, no-follow, ownership) | 0011 §4, 0008 §5 | Accepted / Draft | Unchanged; every listed path is re-checked when opened |
| App preferences and files without typed paths | 0009 §1.8 | Draft (owner-approved for the app) | Amended in step 1 |
| Vault metadata name is encrypted | 0003 §3, 0008 §1.2 | Accepted / Draft | Unchanged; the *file name* is the visible name (owner decision A) |

**Spec changes required:** 0009 §1.8 (step 1):
- "Vault names" becomes "Vault list": names are file names and may show
  before unlock; the list file is bounded and private.
- The preferences bullet keeps its "no vault path" rule; paths live only in
  the vault-list file.

## Decisions needed

None. Recorded decisions:

- **V1 (owner, 2026-11-05):** vault names are not secret. A vault's visible
  name is its file name without `.qvault`. It shows on the lock screen.
- **V2 (owner, 2026-11-05):** import references the file where it is, with
  no copy.
- **V3 (owner-delegated):** the default folder.
  - Linux: `$XDG_DATA_HOME/quickvault/vaults`, if that is absolute, else
    `~/.local/share/quickvault/vaults`.
  - Android and validation fixtures: the app's private `vaults/` directory.
  - It is created mode 0700 on first use and can be changed on Linux.
  - The old `…/state/quickvault/vaults/main.qvault` is listed in place,
    shown as "main". It is never moved.
- **V4 (owner-delegated):** the name becomes the file name.
  - Trimmed, 1–64 characters.
  - Refused: `/`, `\`, NUL, control characters, a leading `.`, and `.`/`..`.
  - An existing file is refused with "A vault with this name is already
    there"; the store's create-new refusal is kept.
  - The name is also the vault's internal (encrypted) name.
- **V5 (owner-delegated):** the list.
  - It contains remembered paths plus the `*.qvault` regular files directly
    in the default folder: at most 64 scanned, no recursion, no links.
  - Most recently opened first, then by name.
  - A path is remembered when it is created, opened or picked.
  - A missing file shows "Not found here" and can be removed from the list.
  - Vaults in the default folder cannot be removed (they are found again).
- **V6 (owner-delegated):** the selection.
  - The selected vault is controller state that survives form resets and
    lock. It starts as the most recent existing vault.
  - Unlock and recover use it. A typed or picked path (the fallback field)
    still wins, as today.
- **V7 (owner-delegated):** Join creates `Joined vault.qvault` in the default
  folder, or `Joined vault 2.qvault` and so on if taken.

## Design

**Components touched:**
- `crates/qv-app`:
  - new `src/vaults.rs`;
  - `controller.rs` (selection, open-path resolution, remembering);
  - `ui/mod.rs` (locked screens);
  - `ui/pages.rs` (Settings);
  - `lan.rs` (join path);
  - flows.

No core, store, crypto or platform change. The portal `Pick::Folder` already
exists.

**Vault-list file** `vault-list` in the private app directory (beside the private `vaults/` folder), next to
`preferences`:
- UTF-8 lines: `folder <abs path>` (at most one; Linux only) and
  `vault <abs path>` (at most 64, most recent first).
- At most 64 KiB in total; each path at most 4096 bytes, absolute, no NUL or
  line break.
- `vault` paths end in `.qvault`.
- Unknown or malformed lines are ignored.
- A non-regular file or an over-size file reads as empty.
- Writes go to a fresh 0600 temporary file, renamed into place (as
  `prefs::save`).
- Write failures never block opening; they show an error and continue.

```rust
// src/vaults.rs
pub struct VaultList { folder: Option<PathBuf>, recent: Vec<PathBuf> }
impl VaultList {
    pub fn parse(bytes: &[u8]) -> Self; pub fn encode(&self) -> String;
    pub fn load(base: &Path) -> Self; pub fn save(&self, base: &Path) -> io::Result<()>;
    pub fn remember(&mut self, path: &Path); pub fn forget(&mut self, path: &Path);
}
pub fn default_folder(base: &Path, chosen: Option<&Path>) -> PathBuf;
pub fn file_name(name: &str) -> Result<String, AppError>;          // V4
pub struct Listed { pub path: PathBuf, pub name: String, pub place: String,
                    pub exists: bool, pub in_folder: bool }
pub fn listed(base: &Path, list: &VaultList) -> Vec<Listed>;         // V5
pub fn shown_place(dir: &Path) -> String;                            // "~/…"
// Controller
pub fn vaults(&self) -> Vec<Listed>; pub fn selected_vault(&self) -> Option<Listed>;
pub fn select_vault(&self, epoch: FormEpoch, path: &Path);
pub fn forget_vault(&self, epoch: FormEpoch, path: &Path);
pub fn set_default_folder(&self, path: &Path) -> Result<(), AppError>;
pub fn default_folder(&self) -> PathBuf;
```

**Secrets and hostile input:**
- Paths are not secrets (V1), but they never go into logs or errors.
- Listed paths are re-validated by core at open (0011 §4: no-follow,
  ownership).
- Scanning uses `symlink_metadata` and skips anything that is not a regular
  file.
- Names and places render only as text nodes.

**Errors:** new `AppError::VaultName` ("Use a name of 1–64 characters, without
/ or \\, that does not start with a dot.") and `AppError::VaultExists`. The
store's `Exists` maps to `VaultExists` on create.

**Dependencies:** none.

## Steps

### Step 1 — Spec 0009 §1.8
- [x] Do: replace "Vault names" with "Vault list" (V1–V7); keep
  preferences free of paths; add a Changelog line; index note.
- Verify: `git diff --check`.

### Step 2 — `src/vaults.rs`
- [x] Do: the list file, default folder, name rules, scan and display.
  Tests:
  - parse bounds, malformed lines and round trip;
  - a linked or non-regular file reads as empty;
  - writes are 0600;
  - remember/forget order and the 64-entry cap;
  - name rules;
  - the scan ignores links, directories and non-`.qvault` files;
  - legacy `main.qvault` is listed;
  - de-duplication.
- Verify: `cargo test --locked -p qv-app vaults`.

### Step 3 — Controller
- [x] Do: the selection (V6); open-path resolution (typed path, else for
  create default folder + name, else the selection); remembering on
  successful create/unlock/recover and on pick; forget; set the default
  folder; join path (V7); error mapping.
  Tests:
  - create two vaults by name only;
  - both listed;
  - lock and unlock the second through the selection;
  - a duplicate name is refused without touching the file;
  - a bad name is refused;
  - picking an outside file lists it;
  - forgetting a missing file;
  - the default folder change lists the new folder;
  - the selection survives lock.
- Verify: `cargo test --locked -p qv-app`.

### Step 4 — Screens
- [x] Do:
  - Lock-screen switcher: the selected name; its place under it; a menu with
    every listed vault (name, place, check), then "Open a vault file…",
    Create, Join, Recover.
  - Create: name only, with "Saves to ~/…/vaults · Change". Change offers
    "Choose a folder…" (sets the default folder) and "Save somewhere else…"
    (the existing save picker).
  - Missing-file state with "Remove from list".
  - Settings → Vault: "This vault" (file and folder) and "Default folder"
    (Change, Linux).
  - Welcome stays the first-run screen when no vault is listed.
- Verify: validation Clippy; real input under Xvfb.

### Step 5 — Flows, docs, gates
- [x] Do: update `flow.js` and Android `flows.js` for name-only create and
  the switcher, keeping every assertion. Update the CHANGELOG, the
  `qv-app` README, the plan index and the log.
- Verify: all `AGENTS.md` gates, plus Android Clippy.

## Test plan

- Final verification: all `AGENTS.md` gates on the final tree.
- Rejection paths:
  - over-size, linked or malformed list files;
  - bad and duplicate names;
  - a missing listed file;
  - a stale epoch for select/forget.
- 0012 §1 rows: none new. The existing GUI and unlock rows keep passing.

## Risks and stop conditions

- Stop if a listed path would bypass core's open checks, or if any change in
  core, store or format seems needed.
- Fixtures must stay inside their private root: on validation builds the
  default folder is the private `vaults/`.
- A vault in the old private directory must keep opening.

## Documentation

- [x] `CHANGELOG.md`
- [x] Spec 0009 §1.8 + Changelog; `specs/README.md` note
- [x] `crates/qv-app/README.md`
- [x] `plans/README.md` row
- [x] `ARCHITECTURE.md`: no component change (an app module only)

## Revisions

None.

## Execution log

- 2026-11-06: Plan written and approved on the owner's request; decisions
  V1–V2 are the owner's (2026-11-05), V3–V7 owner-delegated. The owner has
  neither elogind nor logind, so screen-lock detection is correctly reported
  unavailable on their system (plan 0040 log).
- 2026-11-06: Steps 1–5.
  - **Code:**
    - `src/vaults.rs`: the list file, default folder, name rules, scan and
      display.
    - `prefs::{read_private, write_private}`, shared with the preferences.
    - `Controller`: `vaults`, `selected_vault`, `select_vault`,
      `forget_vault`, `import_vault`, `set_default_folder`, `default_folder`
      and `open_vault`.
    - `open()` resolves paths per V6 and V7. Successful create and unlock
      remember and select the vault.
    - New errors: `VaultName`, `VaultExists`, `VaultMissing`.
    - The pickers gain `PathFor::{Import, Folder}`.
    - Locked screens: an anchored switcher listing the vaults; "Saves in … ·
      Change" on create; a missing-file banner with "Remove from list"; Esc
      closes menus.
    - Settings: the vault file and the folder for new vaults.
  - **Deviations:**
    - The list file is named `vault-list`, not `vaults`: it sits beside the
      private `vaults/` folder, and the first attempt failed to save into
      that name (caught by the new test).
    - Creating with an empty name still uses "My vault", for the existing
      tests; the screen always asks for a name.
    - The Android validation fixture check now accepts any file in the
      private `vaults/` folder, not only `main.qvault`.
  - **Tests:**
    - 5 unit tests in `vaults.rs`;
    - `vaults_are_created_by_name_listed_selected_and_imported_in_place`,
      covering name-only create, duplicate and bad names, selection across
      lock, refusal of unlisted paths, import, missing files and forget,
      restart, and the default folder rules.
  - **Real input under Xvfb (desktop build, no validation):**
    - the old `main.qvault` was listed in place;
    - "Work" was created by name into the default folder and remembered;
    - after lock, the switcher listed both, most recent first;
    - selecting "main" unlocked it;
    - Settings showed both rows.

    The portal is absent under Xvfb, so the typed fallback appeared and the
    folder and save pickers could not be exercised.
  - **Found, not fixed:**
    - The old vault's file name ("main") differs from its internal name
      ("Test"); renaming files is out of scope.
    - Write failures of the list are not shown after open (the vault still
      opens).
    - A picker error can stay visible on the next create step.
