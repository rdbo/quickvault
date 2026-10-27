# Plan 0011 — CLI foundation, vault and read commands (phase 1.10a)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-26 | 2026-10-26 | 0011 §1–3, §4 (Vault: `init`, `info`; Browsing; `generate`), §5–6; 0009 §3; 0010 §3–4; 0002 §3.1, §4.2; 0008 §1, §3; 0012 §1 |

## Intent

Roadmap 0002 phase 1.10, first half. Create `qv-cli` (`qvault`): the command
tree, vault selection and config, secret-safe terminal input, escaped output
and JSON, exit codes, a PTY test harness, and the commands that create,
inspect and read a vault: `init`, `info`, `ls`, `search`, `show`, `totp` and
`generate`. The second half (1.10b) adds editing, the trash and the
clipboard on this foundation.

## Scope

**In scope:**
- Small hooks below the CLI, each needed by a 1.10a command:
  - `qv-crypto`: `MasterPassword::expose_secret` (the NFC text, for the
    strength estimate) and `PasswordKdfProfile::argon2_params` (for `info`);
  - `qv-store`: `VaultFile::header`, `VaultFile::schema_version` and
    `VaultFile::password_kdf` (unverified, for `info`);
  - `qv-model`: settings key 3, the recorded recovery-phrase skip (D-5), and
    the fix for review 0010 finding 1 (new generator defaults replace a
    key-2 value this version can't read);
  - `qv-core`: `harden`, `Core::inspect`, `password_strength` (zxcvbn,
    0010 §3.2, §4.2), `confirmation_positions`, handle IDs and
    `Session::find_id`, `Session::record_recovery_skip`, and refusing an
    anchor directory that holds the vault (review 0009 finding 2).
- New crate `qv-cli`, binary `qvault`:
  - global options `--vault/-v`, `--password-stdin`, `--json`, `--yes`;
  - config file (strict TOML subset) and vault selection (0011 §1.2–1.3);
  - terminal I/O: TTY detection, no-echo prompt, `--password-stdin`
    reader, alternate screen, y/N confirmation;
  - an output writer that keeps vault text in zeroizing buffers and writes
    it straight to the file descriptor, control-character escaping, a JSON
    writer and timestamp formatting;
  - addressing: paths with `\/` escapes, `@id` prefixes, ambiguity (exit 5);
  - commands `init`, `info [--full]`, `ls [<group>] [-r]`, `search`,
    `show [--reveal] [--field]`, `totp`, `generate`;
  - the exit-code mapping (0011 §6) and redacted error messages;
  - end-to-end tests through a PTY and pipes.

**Out of scope (phase 1.10b, next session):**
- `add`, `edit`, `mv`, `mkdir`, `rm`, `trash ls|restore|empty`; the notes
  prompt and `-i`.
- `copy`, `totp --copy`, `generate --copy` (arboard), the countdown, signal
  handling with terminal restore on SIGTERM/SIGHUP (signal-hook), and the
  `clipboard_timeout` setting (it is parsed and validated here but not used).

**Out of scope (other phases):** `passwd`, `recover`, `recovery show|rotate`
(1.14–1.15), `verify` (1.13), history and snapshots (1.12–1.13), attachment
commands (1.11), conflicts and sync (milestones 2–3), colour output, shell
completion.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Binary `qvault` built with clap; crate `qv-cli` | 0011 §1.1 | Accepted | clap builder API |
| Vault selection order, exit 2 if none | 0011 §1.2 | Accepted | |
| Config file location and keys; no secrets | 0011 §1.3 | Accepted | Strict TOML subset (*Design*) |
| Per-command unlock, zeroize, exit; `info` unverified | 0011 §1.4, 0009 §3 | Accepted / Draft (D5) | |
| Lock held only while running; exit 6 if locked | 0011 §1.5 | Accepted | `StoreError::Locked` |
| Paths, `\/`, `@id` prefixes ≥ 6 hex, ambiguity exit 5, trash not matched | 0011 §2 | Accepted | See *Readings* |
| No secrets in argv or environment; `-i`; notes prompted | 0011 §3.1 | Accepted | Notes and `-i` are 1.10b |
| `--password-stdin` rules | 0011 §3.2 | Accepted | |
| Protected values masked unless `--reveal` | 0011 §3.3, 0009 §3 | Accepted | |
| No `$EDITOR`, no plaintext temp files | 0011 §3.4 | Accepted | |
| Core dumps disabled at start; memory hygiene | 0011 §3.5, 0008 §1.1 | Accepted / Draft (D5) | `qv_core::harden` first thing |
| Recovery phrase on the alternate screen | 0011 §3.7 | Accepted | |
| Phrase: confirmation or explicit recorded skip | 0002 §4.2 | Accepted | Where it is recorded: D-5 |
| NFC master password | 0002 §3.1 | Accepted | Already in `MasterPassword` |
| `init`, `info`, `ls`, `search`, `show`, `totp`, `generate` | 0011 §4 | Accepted | `--copy` variants are 1.10b |
| Human output, no colour unless TTY and no `NO_COLOR` | 0011 §5.1 | Accepted | No colour is emitted in 1.10 |
| `--json`, protected → `null` + `"protected": true` | 0011 §5.2 | Accepted | |
| Errors on stderr, no secrets; escape control/ANSI/OSC; JSON escaping | 0011 §5.3 | Accepted | |
| Weak master password: warning, 5 s wait, `[y/N]`, `--yes` does not skip | 0011 §5.4, 0010 §4.2 | Accepted | `init` only in 1.10a |
| Exit codes | 0011 §6 | Accepted | |
| Exact entropy for generated values; zxcvbn for typed passwords; labels | 0010 §3.1–3.3 | Accepted | |
| Warn below 64 bits; suggest a 6-word passphrase for the master password | 0010 §4.1–4.2 | Accepted | |
| Generator defaults per vault, overridable | 0010 §5.1 | Accepted | |
| Generated values are secrets; no generator history | 0010 §6 | Accepted | |
| Clipboard, logs, temp files | 0008 §3 | Draft (D5) | Logs/temp files here; clipboard 1.10b |
| Anchor not next to the vault | 0005 §5.4 | Draft (D5) | Review 0009 finding 2 |

**Spec changes required:** 0010 §3.2 (D-7, the zxcvbn ceiling; step 2). Otherwise none, unless the owner picks option B or C in
D-5 and wants the location written into 0002 §4.2. With option A (vault
setting), settings key 3 is a development registry value like keys 0–2; the
1.16 format freeze records it.

## Decisions needed

The plan needs the owner because of D-1 to D-4 (new dependencies outside the
roadmap candidate table, and a licence outside the allow-list), D-5 (a spec
point that doesn't say where a skip is recorded) and D-6 (a deviation from
the roadmap phase entry). D-3 and D-4 are for 1.10b. They are asked now so
that 1.10b can run under standing approval.

1. **D-1 — `zxcvbn` for user-typed passwords** (0010 §3.2 requires it; the
   roadmap revision of 2026-10-25 reserved owner approval). `zxcvbn 3.1.1`
   (2026-04-24, MIT), `default-features = false`, in `qv-core` so the app
   shares it. It adds 15 crates, all MIT/Apache-2.0/Unlicense-or-MIT:
   `fancy-regex`, `regex`, `regex-automata`, `aho-corasick`, `memchr`,
   `bit-set`, `bit-vec`, `itertools`, `either`, `lazy_static`, `time`,
   `time-core`, `deranged`, `num-conv`, `powerfmt` (`regex-syntax` is
   already in the tree). Cost: zxcvbn copies the password into ordinary
   `String`s (lowercasing, l33t substitution, matches) that are never
   zeroized, a library intermediate that 0008 §1.1 says to audit. We'd
   document it as reduced hygiene for the estimate. Alternatives: none meets
   0010 §3.2 without a spec change. Recommendation: approve.
   Blocks: steps 2, 6. Resolution: owner accepted the recommendation on 2026-10-26.
2. **D-2 — `clap 4.6.7`, builder API only** (candidate table). It is listed
   here only because the derive API would add `syn`, `quote`,
   `proc-macro2` and `heck`, and the builder API avoids all four.
   `default-features = false`, features `std`, `help`, `usage`,
   `error-context`: `clap`, `clap_builder`, `clap_lex`, `anstyle`
   (MIT/Apache-2.0). Recommendation: approve as described.
   Blocks: step 3. Resolution: owner accepted the recommendation on 2026-10-26.
3. **D-3 (1.10b) — `signal-hook 0.4.5`** (2026-10-04, MIT/Apache-2.0;
   adds `signal-hook-registry`; `libc` and `errno` are already in the
   tree). `copy` must clear the clipboard on SIGINT, SIGTERM and SIGHUP
   (0011 §3.6), and prompts must restore the terminal. With
   `unsafe_code = "forbid"` we cannot install handlers ourselves.
   `signal_hook::flag::register` is a safe API. Alternative: `ctrlc` with
   `termination` (pulls in `nix`; one callback, no per-signal flags).
   Recommendation: approve `signal-hook`, `default-features = false`.
   Blocks: 1.10b. Resolution: owner accepted the recommendation on 2026-10-26.
4. **D-4 (1.10b) — `arboard 3.6.1` and its licences** (candidate table; 3.7.0
   is from 2026-10-15, under two weeks old). With `default-features =
   false` (no image support) the Linux tree is `x11rb`, `x11rb-protocol`,
   `gethostname` (Apache-2.0), `parking_lot`, `parking_lot_core`,
   `lock_api`, `scopeguard`, `log` and `percent-encoding`. The checks I
   ran: Linux `exclude_from_history()` sets `x-kde-passwordManagerHint`,
   and with that hint arboard doesn't hand the value to a clipboard manager
   when it exits. `wl-clipboard-rs` writes no temp files. X11 `clear()`
   drops ownership even when another app owns the clipboard, so 1.10b must
   check ownership itself first. **Licence:** the Windows backend's
   `clipboard-win` and `error-code` are `BSL-1.0`. That licence is outside
   the allow-list, and `cargo deny` checks every target. Options:
   (a) per-crate `[[licenses.exceptions]]` for those two crates (BSL-1.0 is
   OSI-approved and permissive; Windows is milestone 4 anyway);
   (b) limit `cargo deny`'s graph to Linux/Android targets until milestone
   4; (c) allow `BSL-1.0` everywhere. Recommendation: (a). **Wayland:**
   X11 only for now (works on Wayland desktops through XWayland). Native
   `wayland-data-control` adds `wl-clipboard-rs`, `wayland-*`,
   `tree_magic_mini` and more, and can come with the platform adapters (2.3).
   Recommendation: X11 only. Blocks: 1.10b. Resolution: owner accepted the recommendation on 2026-10-26.
5. **D-5 — Where the "explicit recorded skip" of the recovery-phrase
   confirmation is recorded** (0002 §4.2 says it is recorded but not where).
   Options: (A) a synced, encrypted vault setting
   `recovery_skipped_at: Timestamp` at settings key 3, so every client can
   remind the user later, cleared once the phrase is confirmed (`recovery
   show`, 1.14); (B) local-only state in the `replica` row (needs a schema
   change); (C) not persisted: the typed acknowledgement is the record.
   Recommendation: A. It's cheap, needs no schema change, and lets the app
   show a reminder. Blocks: steps 1, 2, 6. Resolution: owner accepted the recommendation on 2026-10-26.
6. **D-6 — Split phase 1.10 into 1.10a (this plan) and 1.10b** (editing,
   trash, clipboard). The full entry is about 17 steps, past the roadmap's
   8–10-step session limit. 1.10b depends on 1.10a and needs D-3 and D-4. A
   dated *Revisions* entry in the roadmap records the split when it's
   approved. Recommendation: approve. Blocks: everything. Resolution: owner accepted the recommendation on 2026-10-26.

7. **D-7 — zxcvbn's 64-bit ceiling** (found in step 2). zxcvbn 3.1.1 never
   estimates above 64 bits, so 0010 §4.2's ≥ 70-bit Accept tier was
   unreachable. Options: (A) an estimate at the ceiling counts as Strong
   (0010 §3.2 amendment); (B) lower the typed-password threshold to 64 bits;
   (C) keep it, so every typed master password warns. Recommendation: A.
   Blocks: step 2. Resolution: owner accepted A on 2026-10-26; 0010 §3.2
   amended in step 2.

**Not needed for 1.10, raised for the owner:** 0011 has no command that
accepts a vault whose anchor is missing or mismatched. That happens when a
vault is copied to a new machine or the state directory is lost. 0005 §5.4
requires an explicit recovery, and `qv-core` already has
`unlock_for_recovery` and `adopt_baseline`, but such a vault currently
always exits 7. Recommendation: amend 0011 in phase 1.13 or 1.14 (for
example `qvault adopt`, which shows what is known and requires typed
confirmation). Until then, the 1.10a error message names the situation.

**Readings** (from the specs; listed for the reviewer):
- **Prompts read from standard input only when it is a terminal.** Without
  a TTY on stdin, a command that needs a prompt fails with exit 2. The one
  exception is the master password with `--password-stdin` (0011 §3.2,
  0009 §3: "from the TTY"). Prompts are written to stderr. Reading fd 0
  means the PTY tests need no controlling terminal.
- **The prompt runs in non-canonical mode** with ECHO and ISIG off. That
  way Ctrl-C arrives as a byte, and the prompt restores the terminal and
  exits with "cancelled" (exit 1) instead of leaving echo off. Backspace and
  Ctrl-U edit; Enter ends; EOF (Ctrl-D) on an empty line cancels. Termios is
  restored on every return path. SIGTERM and SIGHUP during a prompt are not
  handled until 1.10b (D-3).
- **`init` needs a TTY on stdin and stdout** (the phrase must use the
  alternate screen, 0011 §3.7). `--password-stdin` with `init` is exit 2.
- **Master-password suggestion** (0010 §4.2): `init` first shows a
  generated 6-word passphrase on the alternate screen and asks
  "Use this passphrase? [y/N]". On "y" it becomes the password. Otherwise the
  user types a password twice, and the zxcvbn verdict applies: Fair prints a
  warning; Weak prints the warning, waits 5 s with a countdown, then asks
  `Create the vault with this weak password anyway? [y/N]`. `--yes` doesn't
  skip this (0011 §5.4).
- **Confirmation:** after the phrase is shown (alternate screen, cleared
  after a keypress), the user types 3 words at random distinct positions.
  `RecoveryPhrase::confirm_word` checks each in constant time. On a
  mismatch the user can retry, type `show` to see the phrase again, or type
  `skip`. A skip shows a warning, needs a `y` confirmation, and is then
  recorded (D-5). If `create` fails after the file exists (review 0008
  finding 4), the message says that a vault file may exist at the path.
- **`show --field <name>`** prints only the value. It is escaped when stdout
  is a terminal and verbatim otherwise (scripts get the exact bytes). A
  protected field still needs `--reveal`.
- **Conflicted entries:** `show` displays the representative and notes how
  many versions exist. `show --field` and `totp` need a version choice, so
  they exit 8 (0005 §2.3; no CLI choice exists until milestone 2).
- **`generate`:** the value goes to stdout. Entropy, label and the below-64-bit
  warning (0010 §4.1) go to stderr. If any generator flag is given, the
  flags alone decide the settings, starting from the 0010 defaults for the
  chosen mode. Without flags, a vault selected by 0011 §1.2 is unlocked and
  its defaults are used; with no vault, the 0010 defaults apply.
- **`ls` columns:** the username is the first listed field named
  `username`, `user`, `login` or `email` (case-insensitive), else the first
  `email`-kind field. The URL is the first `url`-kind field. These are
  template conventions (0003 §5.2), not rules. Recovered items (0003 §4.2)
  are listed after the root's contents under `Recovered items:`, with their
  `@id`.
- **Path escaping:** `\/` is a slash in a name and `\\` a backslash. Any
  other `\x` is a usage error (exit 2). Output paths use the same escaping,
  so they can be pasted back.
- **Escaping** (0011 §5.3): C0 controls, DEL and C1 controls are printed as
  `\xNN` / `\u{NN}`, and so are the Unicode bidirectional controls
  (U+202A–U+202E, U+2066–U+2069, U+200E–U+200F, U+061C), which can disguise
  text. Backslash is printed as `\\`. This applies to every human-readable
  vault value and every error.
- **Input bounds:** a master password at the prompt or on stdin is at most
  1,024 bytes (above that: exit 9, "too long"). The config file is at most
  64 KiB. A search query is at most `MAX_QUERY_BYTES` (core).

## Design

**Components touched:** `qv-crypto` and `qv-store` (two read-only
accessors each), `qv-model` (settings key 3, key-2 fix), `qv-core`
(frontend-facing additions, zxcvbn), new `qv-cli` (frontend; depends only on
`qv-core`, `clap`, `rustix` and `zeroize`, per `ARCHITECTURE.md` §3). No
`unsafe`. The CLI has no network dependency.

**Lower-crate hooks (step 1).**
- `qv_crypto::MasterPassword::expose_secret(&self) -> &str`: the NFC text
  (already valid UTF-8).
- `qv_crypto::PasswordKdfProfile::argon2_params(self) -> Argon2Params
  { memory_kib: u32, iterations: u32, parallelism: u32 }` (public, `Copy`,
  `Debug`), from the same table as the crate-private `params`.
- `qv_store::VaultFile::{header(&self) -> &Header, schema_version(&self) ->
  u32, password_kdf(&self) -> PasswordKdfProfile}`. These are unverified:
  nothing here is MAC-checked before unlock, and the docs say so.
- `qv_model::Settings::recovery_skipped_at: Option<Timestamp>` at key 3
  (if D-5 = A; uint ms like other timestamps). The encoder skips an `ext`
  entry whose key a known field already writes. So when `generator` is
  `Some`, a raw key 2 in `ext` is dropped (review 0010 finding 1). The
  same rule covers key 3.

**qv-core additions (step 2):**

```rust
/// Hardens the process once (no core dumps, no debugger attach) and returns
/// the protection report; `Core::new` uses the same once-cell.
pub fn harden() -> Protection;

pub struct VaultInfo {                 // unverified header data (0011 `info`)
    pub vault_id: String,              // lowercase hex
    pub schema_version: u32,
    pub key_generation: u32,
    pub data_profile: u16, pub derivation_profile: u16, pub mac_profile: u16,
    pub min_data_profile: u16, pub min_derivation_profile: u16,
    pub kdf_profile: u16, pub kdf: Argon2Params,
    pub warnings: LocationWarnings,
}
impl Core { pub fn inspect(&self, path: &Path) -> Result<VaultInfo, CoreError>; }

pub enum PasswordVerdict { Accept, Warn, ConfirmWeak }   // 0010 §4.2
pub struct PasswordCheck { pub bits: f64, pub strength: Strength, pub verdict: PasswordVerdict }
/// zxcvbn estimate: bits = guesses_log10 · log2(10); labels per 0010 §3.3.
pub fn password_strength(password: &MasterPassword) -> PasswordCheck;

/// Three distinct random word positions (0-based) for the phrase check.
pub fn confirmation_positions() -> Result<[usize; 3], CoreError>;

impl EntryHandle { pub fn id_hex(&self) -> String; }   // 32 lowercase hex
impl GroupHandle { pub fn id_hex(&self) -> String; }
impl ItemHandle  { pub fn id_hex(&self) -> String; }
impl Session {
    /// Live (or, with `in_trash`, trashed) entries and groups whose ID starts
    /// with `prefix` (6–32 hex digits, any case; else InvalidInput).
    pub fn find_id(&self, prefix: &str, in_trash: bool) -> Result<Vec<ItemHandle>, CoreError>;
    /// Records an explicit skip of the phrase confirmation (D-5).
    pub fn record_recovery_skip(&self) -> Result<(), CoreError>;
}
pub enum CoreError { /* … */ AnchorLocation /* exit 1 */ }
// Re-export qv_crypto::{SecretBytes, Argon2Params} and qv_crypto::PasswordKdfProfile.
```

`Core::create`, `unlock` and `unlock_for_recovery` refuse with
`AnchorLocation` when the vault's parent directory (canonicalized) equals the
anchor directory or lies inside it. An anchor that is copied or restored
together with the vault detects nothing (review 0009 finding 2). The check
runs before the KDF.

**qv-cli modules:**

| Module | Content |
|--------|---------|
| `main.rs` | `harden()`, then `cli::run(std::env::args_os())` → `ExitCode` |
| `cli.rs` | clap command tree (builder), global options, dispatch |
| `config.rs` | strict TOML-subset parser, `Config { default_vault, clipboard_timeout, color }` |
| `select.rs` | vault selection (0011 §1.2), anchor dir, `Core` construction |
| `term.rs` | `isatty`, prompt (non-canonical, no echo, ISIG off), `--password-stdin` reader, alternate screen, keypress, y/N |
| `out.rs` | `Out`: zeroizing buffer flushed straight to fd 1/2 via `rustix::io::write`; escaping; timestamps (UTC, RFC 3339, civil-from-days) |
| `json.rs` | minimal JSON writer into an `Out` (objects, arrays, strings with JSON escaping, numbers, bools, null); the schemas are documented in its module docs |
| `address.rs` | path parsing (`\/`, `\\`), resolution by walking `list`, `@id` via `find_id`, `Resolved::{One, Many}` → exit 5 listing matches |
| `exit.rs` | `CliError` → exit code and fixed message, from `CoreError`/`StoreError` per 0011 §6 |
| `cmd/{init,info,ls,search,show,totp,generate}.rs` | the commands |

The binary is the only target. Unit tests sit inside the modules, and
end-to-end tests are in `tests/` (`env!("CARGO_BIN_EXE_qvault")`).

**Config (strict TOML subset).** File:
`$XDG_CONFIG_HOME/quickvault/config.toml` (only if `XDG_CONFIG_HOME` is
absolute), else `$HOME/.config/quickvault/config.toml`. A missing file means
an empty config. At most 64 KiB, UTF-8. Accepted lines: blank lines,
`# comments`, and `key = value` with a basic string (escapes `\" \\ \n \t
\uXXXX \UXXXXXXXX`), a literal string `'…'`, a decimal integer or
`true`/`false`, with an optional trailing comment. Keys: `default_vault`
(string, absolute path), `clipboard_timeout` (integer 1–300),
`color` (`"auto"` or `"never"`). Anything else (tables, arrays, dotted or
duplicate keys, unknown keys) is a config error: exit 2, naming the line
number and key, never the value. Every file this subset accepts is valid
TOML with the same meaning.

**Terminal input.** `term::prompt_secret(label) -> Result<SecretBytes,
CliError>` (`SecretBytes` is qv-crypto's locked buffer, re-exported by
qv-core):
- refuse if fd 0 is not a TTY (exit 2);
- save the termios state, clear `ECHO`, `ICANON` and `ISIG` (`VMIN` 1,
  `VTIME` 0), write the label to stderr;
- read one byte at a time into a pre-allocated `SecretBytes::zeroed(1024 + 4)`
  (never grows). Backspace (`0x7f`/`0x08`) removes the last UTF-8 scalar;
  Ctrl-U clears; `\r`/`\n` ends; Ctrl-C cancels; Ctrl-D on an empty buffer
  cancels. Past 1,024 bytes the input is drained to the newline and the
  call fails with "too long" (exit 9);
- restore termios on every path (a guard type whose `Drop` restores), then
  write `\n` to stderr.

`term::read_password_stdin()` reads fd 0 byte by byte until `\n` or EOF into
the same kind of buffer. It removes one trailing `\n` or `\r\n` and nothing
else. If fd 0 is a TTY, it falls back to `prompt_secret`.
`MasterPassword::from_utf8` takes the buffer; invalid UTF-8 is exit 1
("the password is not valid UTF-8").

**Output.** Every byte of vault text (titles, names, values, notes,
revealed secrets, generated values, codes) goes through `Out`. `Out` builds
the escaped (or JSON-escaped) form in a `Zeroizing<Vec<u8>>` with capacity
reserved up front, so it never reallocates for one value, and writes it with
`rustix::io::write` to fd 1. std's `Stdout` buffer is never used for vault
text. Non-vault text (labels, help) may use std. Errors use `Out` on fd 2.
clap's own help and usage output goes through clap.

**Exit codes (`exit.rs`):** `StoreError::WrongPassword` and
`CryptoError::WrongPhrase` → 3; `NotFound` (store, core) → 4; ambiguity → 5;
`Locked`, `Replaced`, `Changed`, `CoreError::StaleHandle` → 6; `Integrity`,
`Rollback`, `NoAnchor` → 7, with a hint for the last two (see the note
under *Decisions needed*); `CoreError::Conflict` → 8; `LimitExceeded` (store,
core) and input over a bound → 9; usage, no vault, config error and missing
TTY → 2; everything else → 1. clap errors map to 2, and `--help`/`--version`
to 0. A unit test covers every row.

**`info`.** `Core::inspect` takes no password. It prints the vault ID,
schema (format) version, key generation, profiles and KDF parameters, under
a heading that says they are unverified. Location warnings go to stderr.
`--full` also prompts, unlocks and prints the name, entry and group counts,
items in trash, conflicts and last change (`Session::overview`).

**`ls`, `search`, `show`, `totp`.** Each unlocks, resolves the address,
reads through core views, writes through `Out` and drops the session (lock)
before exit. Paths for output come from one walk of the tree from the root
(`list` recursively, bounded by the index). `show` prints title, path,
type, the fields in order (`••••••••` for protected values unless
`--reveal`), notes, and created/modified/expiry times in UTC. For a
conflicted entry it adds a line saying how many versions exist. `totp`
uses the entry's first `totp`-kind field and prints the code and
`(Ns left)`.

**JSON (0011 §5.2).** `ls` → `{"groups":[{"id","path","name"}],
"entries":[{"id","path","title","type","username","url"}],
"recovered":[…]}`; `search` → `{"hits":[{"kind":"group"|"entry",…}]}`; `show`
→ `{"id","path","title","type","notes","created","modified","expires",
"conflict_versions","fields":[{"name","kind","protected","value"}]}` where a
protected value is `null` without `--reveal`; `totp` → `{"code",
"seconds_remaining"}`; `info` → the `VaultInfo` fields (plus `"verified":
false`), and `--full` adds an `"overview"` object; `generate` →
`{"value","bits","strength"}`. Timestamps are RFC 3339 UTC strings. The
module docs of `json.rs` are the documented schema.

**Secrets and hostile input.**
- Secrets in the CLI: master password (`SecretBytes` → `MasterPassword`),
  recovery phrase (`RecoveryPhrase`), typed confirmation words
  (`SecretBytes`), revealed values (`FieldValue`), generated values
  (`Generated`), TOTP codes (`OtpCode`). None of these types implements
  `Display`. They go to the terminal only through `Out`, and are dropped
  before exit.
- No option accepts a secret value. A test walks the clap tree and asserts
  this: no option named or described like a password, secret, phrase or
  note takes a value. `QVAULT_PATH` is the only environment variable read
  besides `HOME`, `XDG_*` and `NO_COLOR`.
- Vault text is authenticated but can be authored by any VK holder, and it
  reaches the terminal only escaped (or JSON-escaped).
- Config, arguments and stdin are bounded before allocation (*Readings*).
- No temp files and no `$EDITOR` (0011 §3.4). Protection status is printed
  as a warning on stderr when reduced (0008 §1.1).
- zxcvbn's internal copies (D-1) are documented in `password_strength`'s docs.

**Errors:** `CliError { code: u8, message: &'static str, detail: Option<Escaped> }`,
where the detail is non-secret context such as an ambiguous path's matches,
a config line number or a file path, printed escaped. No error carries a
secret or a vault value other than the matches of an ambiguous address, which
the user typed.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| `clap =4.6.7` (+ `clap_builder`, `clap_lex`, `anstyle`) | 0011 §1.1 | derive API (adds `syn`, `quote`, `proc-macro2`, `heck`) | Widely used, maintained; no imported vet audit expected → exemptions |
| `zxcvbn =3.1.1` (+ 15, D-1) | 0010 §3.2 | none without a spec change | MIT; maintained (2026-04); exemptions |
| `rustix` (existing) + features `termios`, `stdio`; dev: `pty`, `fs`, `event` | termios, isatty, direct fd writes; PTY tests | `rpassword` (opens `/dev/tty`, returns plain `String`s); `nix` | already vetted in the tree |
| `zeroize` (existing) | zeroizing output buffers | — | already in the tree |

Not used: `serde`/`serde_json` (own JSON writer, so secrets never pass
through serde buffers), `toml` (strict subset parser, 3 keys), `chrono`/`time`
in the CLI (civil-from-days for UTC). Every new crate is at least two weeks
old. `cargo deny check` and `cargo vet` run in step 9.

## Steps

### Step 1 — Lower-crate hooks

- [x] **Do:** Add `MasterPassword::expose_secret`,
  `PasswordKdfProfile::argon2_params` + `Argon2Params`,
  `VaultFile::{header, schema_version, password_kdf}`, and (D-5 = A)
  `Settings::recovery_skipped_at` at key 3. Make the vault-meta encoder skip
  an `ext` entry whose key a known settings field writes (review 0010
  finding 1). Update the module docs (`vault_meta.rs` key table, `vault.rs`
  "unverified").
- **Files:** `crates/qv-crypto/src/{password,profile,lib}.rs`,
  `crates/qv-store/src/vault.rs`, `crates/qv-model/src/payload/vault_meta.rs`.
- **Done when:** unit tests: `expose_secret` returns the NFC form of a
  decomposed input; `argon2_params(V1)` = (262144, 3, 4); a fixture's
  `header`/`schema_version`/`password_kdf` read without a password; key 3
  round-trips byte-identically and is absent when `None`; a vault meta with
  an unreadable raw key 2 and a new `generator` encodes to a single key 2
  (the new value) and decodes back; the existing unknown-key tests still
  pass unchanged.
- **Verify:** `cargo test --locked -p qv-crypto -p qv-store -p qv-model`.

### Step 2 — qv-core additions

- [x] **Do:** `harden` (shared once-cell with `Core::new`), `Core::inspect`
  + `VaultInfo`, `password_strength` + `PasswordCheck`/`PasswordVerdict`
  (zxcvbn; document its non-zeroized copies), `confirmation_positions`,
  `id_hex` on handles, `Session::find_id`, `Session::record_recovery_skip`
  (a settings edit through the existing `commit`), `CoreError::AnchorLocation`
  and the check in `create`/`unlock`/`unlock_for_recovery`; re-exports. Add
  `zxcvbn` to `[workspace.dependencies]`.
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/qv-core/Cargo.toml`,
  `crates/qv-core/src/{lib,setup,session,views,settings,error}.rs`, new
  `crates/qv-core/src/strength.rs`.
- **Done when:** unit tests: `harden` twice returns the same process result;
  `inspect` on a fixture needs no password and matches the header;
  `password_strength`: `"password"` → `ConfirmWeak`, a 6-word generated
  passphrase → `Accept`, a value in 50–69 bits → `Warn` (pick a fixed
  test string and pin its zxcvbn score), and the label thresholds match
  0010 §3.3; `confirmation_positions` are distinct and < 24 over 1,000
  draws; `find_id`: a unique 6-hex prefix finds one item, a 5-hex or non-hex
  prefix is `InvalidInput`, trashed items appear only with `in_trash`,
  finally deleted ones never; `record_recovery_skip` survives a reopen;
  a vault whose directory is the anchor directory (or inside it) is
  `AnchorLocation` on create and unlock, before any KDF (timed or checked by
  `local_seq`/no file created); `CoreError` strings fixed.
- **Verify:** `cargo test --locked -p qv-core`.

### Step 3 — qv-cli skeleton: command tree, config, selection, exit codes

- [x] **Do:** Create `crates/qv-cli` (`[[bin]] name = "qvault"`, workspace
  lints) with `main.rs`, `cli.rs` (the full 1.10a tree with global options;
  command bodies return "not implemented" until their step, exit 1),
  `config.rs`, `select.rs`, `exit.rs`. `main` calls `qv_core::harden()`
  before parsing arguments and warns on stderr if protection is reduced.
- **Files:** `Cargo.toml` (workspace `clap`), `Cargo.lock`,
  `crates/qv-cli/{Cargo.toml,src/main.rs,src/cli.rs,src/config.rs,src/select.rs,src/exit.rs}`.
- **Done when:** unit tests: config accepts every subset form and rejects
  tables, arrays, dotted/duplicate/unknown keys, a relative `default_vault`,
  `clipboard_timeout` 0 and 301, a bad escape, more than 64 KiB, and invalid
  UTF-8, each with exit 2 and the line number without the value; selection
  order `--vault` > `QVAULT_PATH` > `default_vault`, and none → exit 2
  (selection takes the environment as a parameter, so tests don't mutate
  the process environment); the exit-code table, one assertion per row; the
  argv test (no secret-taking option); `--help` and `--version` exit 0, an
  unknown flag exits 2.
- **Verify:** `cargo test --locked -p qv-cli -- config select exit cli`.

### Step 4 — Terminal I/O and output

- [x] **Do:** `term.rs` and `out.rs` per *Design*, `json.rs`, and timestamp
  formatting. Add the rustix features. Write the PTY test harness in
  `crates/qv-cli/tests/common/mod.rs`: open a PTY pair (rustix `pty`), spawn
  the binary with the slave as stdin/stdout/stderr (or pipes), send input,
  read output with `poll` timeouts (30 s), wait for the exit status; private
  temp dirs (0700) with `HOME`, `XDG_CONFIG_HOME` and `XDG_STATE_HOME` set
  inside them; a process-wide mutex that serializes KDF-running children.
  The binary gets no test-only subcommand: terminal code is tested here by
  unit tests on a PTY opened in the test process, and through real commands
  from step 6 on.
- **Files:** `crates/qv-cli/src/{term,out,json}.rs`, `crates/qv-cli/Cargo.toml`,
  `crates/qv-cli/tests/common/mod.rs`.
- **Done when:** unit tests (PTY opened in-process): the prompt doesn't echo
  (nothing read back from the master side), handles backspace across a
  multi-byte scalar, Ctrl-U, Ctrl-C (cancel, termios restored: `ECHO` set
  again) and Ctrl-D, refuses past 1,024 bytes; `read_password_stdin` strips
  exactly one `\n` / `\r\n` and keeps spaces, and reads only the first line;
  escaping covers ESC/CSI/OSC sequences, C1, DEL, tab, bidi controls and
  backslash, and leaves other non-ASCII text alone; JSON escaping per RFC
  8259 (controls as `\u00XX`, quotes, backslash, valid UTF-8 kept); timestamps
  match known values (epoch, a leap day, 9999-12-31, negative → before 1970);
  `Out` never reallocates for a value it reserved (capacity assertion).
- **Verify:** `cargo test --locked -p qv-cli -- term out json`.

### Step 5 — Addressing

- [x] **Do:** `address.rs`: parse paths (`\/`, `\\`, empty segments are a
  usage error, a trailing `/` names a group), resolve against the tree
  (live items only; a last segment matching several entries, or an entry
  and a group where the command takes either, is ambiguous), `@id` through
  `Session::find_id`, and the ambiguity report (exit 5, matches with
  `@id` and escaped paths on stderr).
- **Files:** `crates/qv-cli/src/address.rs`.
- **Done when:** unit tests (against a vault built through `qv-core` in the
  test): nested paths, escaped slash and backslash, duplicate titles → exit
  5 listing both IDs, `@` with a 6-hex unique prefix, a too-short prefix →
  exit 2, an unknown path → 4, a trashed item not found by path or ID → 4,
  a group path where an entry is required → 4.
- **Verify:** `cargo test --locked -p qv-cli -- address`.

### Step 6 — `init` and `info`

- [x] **Do:** `cmd/init.rs` per *Readings* (suggestion on the alternate
  screen, two prompts, the zxcvbn verdict flow with the 5 s wait, create,
  phrase on the alternate screen with keypress, three-word confirmation with
  retry/`show`/`skip`, skip recorded, the "may exist" message on a failure
  after the file exists, `AnchorLocation` message). `cmd/info.rs` (header
  and `--full`, JSON).
- **Files:** `crates/qv-cli/src/cmd/{mod,init,info}.rs`,
  `crates/qv-cli/tests/init_info.rs`.
- **Done when:** end-to-end (PTY): `init` with the suggestion accepted
  creates a vault that `info --full` opens with that passphrase (the test
  reads it from the alternate screen); `init` with a typed strong password
  and correct confirmation words; a wrong word, then `show`, then the right
  word; `skip` is recorded (visible through `qv-core` in the test); a weak
  password waits ≥ 5 s before the question (measured) even with `--yes`, and
  "N" creates nothing; mismatched passwords re-prompt; the recovery phrase
  never appears outside the alternate screen (the captured output is
  split at the `smcup`/`rmcup` sequences, and nothing outside them contains
  any of the 24 words); `init` with stdin not a TTY → exit 2; an existing
  path → error, file untouched; `info` with no TTY and no password prints
  the unverified header; `info --full` with `--password-stdin` (pipe) works
  and a wrong password exits 3.
- **Verify:** `cargo test --locked -p qv-cli --test init_info`.

### Step 7 — `ls` and `search`

- [x] **Do:** `cmd/ls.rs` (`-r`, recovered items, columns per *Readings*,
  JSON) and `cmd/search.rs` (JSON).
- **Files:** `crates/qv-cli/src/cmd/{ls,search}.rs`, `crates/qv-cli/tests/browse.rs`.
- **Done when:** end-to-end with `--password-stdin` (pipes; vaults built
  through `qv-core` in the test): `ls`, `ls Group`, `ls -r` order and paths,
  recovered items; `search` hits on titles, group names, usernames and URLs,
  not on protected values or notes; a title containing ESC, OSC 52, CSI, C1
  and U+202E prints escaped in `ls`, `search` and the ambiguity error; JSON
  output parses (checked with a minimal test-side parser or exact strings)
  and contains no raw control characters; exit 4 for an unknown group.
- **Verify:** `cargo test --locked -p qv-cli --test browse`.

### Step 8 — `show`, `totp` and `generate`

- [x] **Do:** `cmd/show.rs`, `cmd/totp.rs`, `cmd/generate.rs` per *Design*
  and *Readings* (generator flags of 0011 §4, vault defaults, stderr
  entropy/label/warning, JSON).
- **Files:** `crates/qv-cli/src/cmd/{show,totp,generate}.rs`,
  `crates/qv-cli/tests/show_generate.rs`.
- **Done when:** end-to-end: `show` masks protected values and `--reveal`
  prints them; `--field` with and without `--reveal` (protected → exit 1
  with a message, no value); `--field` escaped on a PTY and verbatim on a
  pipe; JSON with `"value": null, "protected": true`; `totp` prints the RFC
  6238 code for the current time (the test computes it with the same seed)
  and the seconds left; `totp` on an entry without a TOTP field → exit 1;
  `generate` defaults, each mode, an invalid combination → exit 1 with the
  generator's message and no output on stdout, a short setting warns on
  stderr, vault defaults used without flags when `--vault` is given,
  `--json`; exit 6 while a test-held session keeps the vault locked;
  exit 7 after the anchor is deleted (with the hint); exit 8 is covered by
  the mapping test, since no 1.10a vault can hold a conflict (logged).
- **Verify:** `cargo test --locked -p qv-cli --test show_generate`.

### Step 9 — 0012 rows, documentation and gates

- [x] **Do:** Add the offline test: `init` → `info --full` → `ls` → `show`
  with no config and empty `HOME`, run under `unshare -rn` when that works
  (the test logs a skip otherwise). Add a test that reads
  `crates/qv-cli/Cargo.toml` and asserts that its direct dependencies are
  exactly `qv-core`, `clap`, `rustix` and `zeroize`, so no networking crate
  can be added unnoticed.
  Update the docs (below). Run every gate, plus `cargo deny check` and
  `cargo vet` with the new exemptions.
- **Files:** `crates/qv-cli/tests/offline.rs`, `supply-chain/config.toml`,
  `deny.toml` (no change expected for 1.10a), `ARCHITECTURE.md`,
  `AGENTS.md`, `CHANGELOG.md`, `plans/0002-roadmap/PLAN.md`,
  `plans/README.md`, this plan.
- **Done when:** all gates green; deny and vet green; the qv-cli suite takes
  at most about 120 s in the debug profile (log the time; if it's slower,
  share fixtures across tests, without dropping rejection tests).
- **Verify:** `sh scripts/check-spdx.sh && cargo fmt --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --locked`;
  `cargo deny check`; `cargo vet` (scratch `CARGO_HOME`).

## Test plan

- Unit and property tests: config parser (accept/reject table), escaping
  (a property test: the escaped form contains no byte < 0x20, no 0x7f and no
  C1/bidi scalar, and it round-trips through an unescape helper in the
  test), JSON writer, timestamps, addressing, exit mapping, zxcvbn verdicts,
  `find_id`.
- Rejection, malformed-input and crash-path tests: every refused input
  asserts its exact exit code and, where vault state could change, that
  `local_seq` is unchanged. Prompt cancel paths restore termios. A
  `create` failure after the rename is reported (simulated by making the
  anchor directory read-only after the vault directory check, as the
  qv-store tests do).
- Vectors: RFC 6238 through `totp`; none for formats (unstable until 1.16).
- 0012 §1 matrix rows: **CLI argument leakage** (no secret-taking option;
  passwords only from the TTY or `--password-stdin`; the notes and clipboard
  parts follow in 1.10b); **Implicit server prerequisite** (CLI part: create,
  unlock and read with no config, no account and networking blocked where
  `unshare` allows; edit follows in 1.10b).

## Risks and stop conditions

- **Decisions:** don't start steps 1–2 or 6 before D-1, D-5 and D-6 are
  resolved, or step 3 before D-2. If the owner rejects zxcvbn, stop: `init`
  can't meet 0010 §4.2 without it.
- **Library copies:** if zxcvbn or clap turn out to log or panic with the
  input (check their error paths), stop and report. Never pass a secret to
  clap. Secrets are never arguments, so this should not happen.
- **PTY flakiness:** if the PTY tests are unreliable in CI (timing, `TERM`),
  fix the harness (longer timeouts, explicit `TERM=dumb` in the child's
  environment) rather than weakening the assertions. If the alternate-screen
  check can't be made reliable, stop and ask.
- **`unshare`:** never require privileges. If `unshare -rn` is unavailable,
  skip that test with a logged reason; do not count it as a pass in the
  0012 row.
- **Scope:** no editing, trash or clipboard code here (1.10b). If a 1.10a
  command seems to need one, stop.
- **Store/core changes** beyond step 1–2's list: stop. In particular,
  don't add a recovery/adopt command (raised under *Decisions needed*).
- No `unsafe`, no `$EDITOR`, no temp files, no `println!` of vault text
  (clippy `print_stdout` may be denied in `qv-cli` to enforce `Out`).

## Documentation

- [x] `CHANGELOG.md` — Unreleased: `qv-cli` (`qvault`) with `init`, `info`,
  `ls`, `search`, `show`, `totp`, `generate`; the core and lower-crate hooks;
  review 0010 finding 1 fixed; review 0009 finding 2 handled.
- [x] `ARCHITECTURE.md` — §3 "Implemented so far" gains `qv-cli`; §6 notes
  the CLI dependencies (clap, zxcvbn).
- [x] Specs — 0010 §3.2 and its Changelog (D-7); otherwise no change.
- [x] `AGENTS.md` — "Current state" gains `qv-cli`.
- [x] `crates/qv-cli` module docs, including the JSON schema in `json.rs`.
- [x] `plans/README.md` — index row; `plans/0002-roadmap/PLAN.md` —
  *Revisions* (split into 1.10a/1.10b, D-1–D-6 resolutions, development
  value: settings key 3), tick 1.10a, *Execution log*.

## Revisions

- 2026-10-26: D-7 added (zxcvbn's 64-bit ceiling) and resolved by the owner (option A); 0010 §3.2 amended.
- 2026-10-26: Approved by the owner (not standing approval: new dependencies, D-5 and the split). D-1 to D-6 accepted as recommended: `zxcvbn`, clap builder API, `signal-hook` (1.10b), `arboard 3.6.1` X11-only with per-crate BSL-1.0 exceptions (1.10b), recovery skip as vault setting key 3, split into 1.10a/1.10b.


- 2026-10-26: Owner authorized fixing review findings 1–2 in this session.
  Architect revision: resume the existing phase; no spec, public API, format,
  dependency or resource-policy change. Step 4 follows 0011 §3.2 exactly.
  Step 7 uses iterative traversal and component storage instead of recursive
  calls or retaining full ancestor prefixes (0011 §2, §4–5; 0008 §1 under D5).
  `Paths` stores an arena of zeroizing escaped components with parent indices
  plus an item-to-index map; `get` returns one owned zeroizing path assembled
  iteratively with precomputed capacity. Indices avoid recursive destruction.
  Listing/search flush human rows and JSON objects incrementally through Out;
  Json gains a private flush forwarding method preserving separator state.
  Output order, schemas, escaping and errors stay the same. An I/O error can
  leave a partial stream, as with existing descriptor writes. No new byte or
  depth cutoff is introduced. No unresolved decision is needed.

### Review remediation (owner approved 2026-10-26)

- [x] **R1 — Exact stdin line endings.** Track LF consumption; strip CR only
  before LF. Keep the existing 1,024-byte bound. Add EOF-CR, repeated CR,
  CRLF and exact/over-limit tests. Files: `src/term.rs` under `crates/qv-cli`.
  Done when the previous failing EOF-CR assertion passes and overlong EOF
  input ending in CR is refused. Verify: `cargo test --locked -p qv-cli term_first_line`.
- [x] **R2 — Iterative traversal and shared prefixes.** Replace collect's
  recursive calls with heap frames (child iterator plus pending entries),
  preserving preorder groups and postorder entries. Use the arena described
  above for paths; adjust ls/search/show and ambiguity formatting callers.
  Flush output per row/object; propagate I/O errors. Files: qv-cli
  `src/{address,json}.rs`, `src/cmd/{ls,search,show}.rs`, `tests/browse.rs`.
  Done when 50,000 synthetic levels traverse and drop without recursion,
  deep path storage grows with components, and branching order plus escaping,
  human/JSON output and missing/recovered paths retain regression coverage.
  Use production traversal with a synthetic listing source to avoid 50,000
  durable core writes; existing persisted-vault e2e tests cover integration.
  Verify: `cargo test --locked -p qv-cli`.
- [x] **R3 — Gates and handoff.** Update CHANGELOG, this plan, review follow-up,
  plan index and roadmap log. Run SPDX, fmt, Clippy and full locked tests.
  No dependency change, so deny/vet are not required anew. Inspect the final
  diff under reviewer role; leave phase Implemented for a fresh-context
  approval and preserve the historical Changes requested review. Do not start
  the next phase or alter the owner's staged changes.

## Execution log

- 2026-10-26: Approved by the owner; status In progress.
- 2026-10-26: Step 1 done. `MasterPassword::expose_secret`; `Argon2Params` + `PasswordKdfProfile::argon2_params`, which the crate-private `params` now reads, so there is one table; `VaultFile::{header, schema_version, password_kdf}` (also stubbed in `unsupported.rs`). `password_kdf` returns `Result` (the slot lookup can fail in principle; `open` already checked it), a small deviation from the sketch. `Settings::recovery_skipped_at` at key 3 (D-5 = A); the encoder skips a kept `ext` entry at a key a known field writes (review 0010 finding 1). Tests: NFC text exposed; V1 parameters; unverified header equals the unlocked one; key 3 round trip and malformed value; a new generator replaces an unreadable key 2 and encodes exactly like a vault that only had the new one.
- 2026-10-26: Step 2 mostly written (harden, inspect, AnchorLocation, id_hex, find_id, record_recovery_skip, strength), with one addition outside the step's list: `qv_store::AnchorDir::path` (read-only, needed for the planned anchor-location check). `deranged` pinned to 0.5.8 (0.5.9 is under two weeks old). The lockfile also gains zxcvbn's wasm32-only dependencies (chrono, wasm-bindgen, web-sys and their trees, about 33 crates) that never build for our targets; the host graph is the planned 15. **Blocked:** zxcvbn 3.1.1 counts guesses in a saturating `u64`, so no estimate exceeds 64 bits (`scoring.rs:152`, `lib.rs:335` asserts `guesses == u64::MAX`). With 0010 §3.3/§4.2, a typed master password can therefore never be Strong (≥ 70 bits): every one gets at least the Fair warning. Also, a random 6-word passphrase scores Fair (dictionary words), so the plan's *Done when* expectation for it was wrong (generated values use their exact entropy and never go to zxcvbn). Asked the owner.
- 2026-10-26: Owner accepted D-7 option A: an estimate at zxcvbn's ceiling (`guesses == u64::MAX`) counts as Strong. 0010 §3.2 and its Changelog amended. Status In progress again.
- 2026-10-26: Step 2 done. `harden` (once-cell, shared with `Core::new`), `Core::inspect` + `VaultInfo`, `CoreError::AnchorLocation` checked before the store opens the file in `create`, `unlock` and `unlock_for_recovery` (canonicalized parent vs anchor directory; `AnchorDir::path` made public, replacing a test-only copy), `id_hex` on the handles, `Session::find_id`, `Session::record_recovery_skip`, `strength.rs` (`password_strength` with the D-7 ceiling rule, `confirmation_positions` by rejection sampling), re-exports (`SecretBytes`, `Argon2Params`, `CryptoError`, `PHRASE_WORDS`). Tests: harden once; inspect equals the authenticated header and needs no password; anchor-location refusals on create (nothing written) and unlock (before the KDF: a wrong password still gives `AnchorLocation`); find_id (prefix lengths, case, trash scope, purged never); the skip survives a reopen; strength verdicts and thresholds; confirmation positions distinct and covering all 24. Deviation from *Done when*: "a 6-word generated passphrase → Accept" does not hold for zxcvbn (it scores Fair); the strong case uses a fixed 24-character string at the 64-bit ceiling, and the Fair case `plumb-tiger-velvet-31` (58 bits; `Tr0ub4dour&3` is 24 bits). Found, not fixed: zxcvbn puts `correct horse battery staple` at its 64-bit ceiling, so under D-7 that famous phrase counts as Strong. This is zxcvbn's model (four dictionary words), not something core can correct without its own estimator; noted for the reviewer and owner.
- 2026-10-26: Step 3 done. `qv-cli` with `[[bin]] qvault`; `clap 4.6.7` builder API (the lockfile gained exactly `clap`, `clap_builder`, `clap_lex`, `anstyle`, all at least two weeks old). `cli.rs` (the 1.10a tree, global `--vault/-v`, `--password-stdin`, `--json`, `--yes`; help text with the argv and scrollback notes), `config.rs` (strict TOML subset, 64 KiB, unknown/duplicate keys refused with the line number and never the value), `select.rs` (selection with the environment passed in; `--vault` never reads the config), `exit.rs` (one test row per exit code; hints for `NoAnchor`, `Rollback`, `Locked`, `Conflict`, `AnchorLocation`). `main` hardens before parsing and warns on reduced protection, and `run` warns at the end if memory locking failed. `#![deny(clippy::print_stdout, clippy::print_stderr)]` outside tests keeps vault text off std's buffers. clap's own help and usage errors go through clap (exit 0 and 2).
- 2026-10-26: Step 4 done. `out.rs` (`Out`: a zeroizing buffer that grows by copying and wiping, written with `write(2)`; escaping per the module docs; `multiline` indents continuation lines; `path` for path-escaped strings; `json_str`; RFC 3339 via civil-from-days), `json.rs` (writer + documented schemas), `term.rs` (raw-mode prompt with the guard, `confirm`, `wait_key`, `countdown`, `password_from_stdin`, `AltScreen`). The in-process PTY tests cover no echo, multi-byte backspace, Ctrl-U, Ctrl-C and Ctrl-D with termios restored, the length bound, echoed y/N, and the stdin first-line rules. The e2e harness is `tests/common/mod.rs` (private home, PTY and pipe runners, one child at a time). The escaping property test checks that the output has no control or bidi scalar; the planned unescape round trip was not written, because the exact expected strings in the unit tests pin the format.
- 2026-10-26: Step 5 done. `address.rs`: path parsing (leading `/` optional, empty path = root, `\/` and `\\` only), resolution by name per level with ambiguity at any level (exit 5 listing `@id`, kind and path), `@id` through `find_id` (a bad prefix is exit 2), `Paths::walk` for display paths. Tests on a vault built with `qv-core` in the test.
- 2026-10-26: Step 6 done. `cmd/init.rs` and `cmd/info.rs` per *Readings*, with one deviation: the confirmation offers its options (show the phrase again, skip) after an **empty line**, not after typing `show` or `skip`. `skip` is itself a BIP-39 word, so a typed command would be ambiguous with a correct answer. Typed recovery words are not echoed (0011 §3.1). An accepted suggestion is judged by its exact entropy, never by zxcvbn (D-7 note). `qv-core` re-exports `VAULT_EXTENSION`. E2E (PTY): suggestion accepted and used as the password; neither the suggestion nor the phrase appears outside the alternate screens (no numbered word, no consecutive pair, no full phrase); typed password with a mismatch, a wrong word, the phrase shown again, then right words; skip recorded in the vault settings; a weak password waits ≥ 4.5 s measured between the warning and the question even with `--yes`, "n" asks again, Ctrl-C cancels with nothing created; refusals (no TTY, `--password-stdin`, extension, existing file untouched). `info`: unverified header without a password or TTY, JSON, `--full` with `--password-stdin`, wrong password exit 3, missing vault 4, no selection 2, selection by `QVAULT_PATH` and `default_vault`, a config error 2 with the line number.
- 2026-10-26: Step 7 done. `cmd/ls.rs` (full paths; with `-r`, each subgroup's contents follow it, then the group's own entries; recovered items under the root listing with a 12-hex `@id`; a `(conflicting versions)` marker), `cmd/search.rs` (an empty query is exit 2, over 1,024 bytes exit 9). The JSON entry object gained `conflict`, and a search entry hit is `{"kind": "entry", "entry": …}`; `json.rs` documents both. E2E: listing order, columns, `-r`, recovered items, duplicate group names → exit 5 with both IDs, `@id` prefix, a hostile title (OSC 52, CSI, C1, U+202E) escaped in human and JSON output with no raw control character, protected values and notes never listed or found.
- 2026-10-26: Step 8 done. `cmd/show.rs` (mask, `--reveal`, `--field` escaped on a PTY and verbatim on a pipe, multi-line values and notes indented so they can't fake lines, JSON, `versions`), `cmd/totp.rs`, `cmd/generate.rs` (mode from the options, mixed modes exit 2, vault defaults only without options). E2E: all of the step's *Done when*; exit 6 with a session held by the test, 3 for a wrong password, 9 for a 1,025-byte password on stdin, 7 after the anchor is deleted (with the hint) and after a flipped byte; `AnchorLocation` through the CLI (exit 1). The TOTP code is compared with the core's for the same window instead of a hard-coded RFC vector, because the CLI uses the system clock (the RFC vector itself is tested in `qv-core`/`qv-model`). Exit 8 is covered only by the mapping test: no 1.10a vault can hold a conflict.
- 2026-10-26: Step 9 done; plan `Implemented`. `tests/offline.rs`: init → `info --full`, `ls -r`, `search`, `generate` with no config and an empty home (passes); the same under `unshare -rn` **skipped here, not a pass** (`unshare: unshare failed: No space left on device`: no user namespaces in this sandbox; it runs where they are available, e.g. CI runners that allow them); the direct dependencies of `qv-cli` are pinned to `clap`, `qv-core`, `rustix`, `zeroize` by a test. Docs: `CHANGELOG.md`, `ARCHITECTURE.md` §3 and §6, `AGENTS.md`, spec 0010 §3.2 (D-7), module docs (JSON schema in `json.rs`). Gates: SPDX, `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked` (453 passed, 0 failed, 2 ignored; the qv-cli suite is 41 tests in about 32 s), `cargo deny check` (advisories, bans, licenses, sources ok; a duplicate-`syn` warning from zxcvbn's wasm32-only tree), `cargo vet` (27 fully audited, 6 partially audited, 75 exempted; `imports.lock` now records the imported audits that cover some new crates), `cargo fetch --locked` on the fuzz workspace.
  Found, not fixed: (1) zxcvbn rates `correct horse battery staple` at its 64-bit ceiling, so under D-7 it counts as Strong; core can't correct zxcvbn's model without its own estimator. (2) Generated passphrases typed back by hand score Fair (only an accepted suggestion uses the exact entropy). (3) arboard is not in yet; `copy`, `totp --copy` and `generate --copy` are 1.10b, which also adds SIGTERM/SIGHUP terminal restore. (4) No colour output; the `color` setting is validated only. (5) `clipboard_timeout` and `--yes` are parsed but unused until 1.10b. (6) The planned unescape round-trip property was replaced by exact expected strings plus a no-control-character property. (7) A vault whose anchor is missing still has no CLI recovery command (raised under *Decisions needed*).

- 2026-10-26: Fresh-session review: **Changes requested**; see [REVIEW.md](REVIEW.md). EOF-terminated stdin strips a password's final CR contrary to 0011 §3.2 (reproduced with a temporary pipe-test assertion); recursive `ls -r` uses depth-dependent stack space over a model allowing 50,000 groups (static finding). No production fix applied. Status remains Implemented. Roadmap session protocol step 2 stops the next phase pending resolution.
- 2026-10-26: Reviewer final gates: SPDX, fmt, Clippy, tests (453 passed, 2 ignored), deny (temporary advisory-cache path only) and vet passed. Details and logs in REVIEW.md. Networking-blocked scenario remains skipped, not passed.

- 2026-10-26: Owner requested fixes; resumed In progress under the remediation revision. Existing staged review records are preserved; changes are added without staging or committing.
- 2026-10-26: R1 implemented: CR is removed only when LF ended the first line;
  EOF-CR and exact/over-limit CR cases are permanent regression assertions.
  R2 implemented: explicit listing frames, parent-index component arena,
  on-demand zeroizing paths, incremental human/JSON output and propagated
  flush failures. Tests cover 50,000 synthetic levels including drop,
  persisted branching order, non-recursive traversal and loader errors,
  exact multi-object JSON and `/dev/full` I/O errors. No new resource-policy
  limit or dependency. Final gates pending.
- 2026-10-26: R3 complete; status Implemented (fixes await fresh-context
  review). Final gates passed: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`
  (456 passed, 0 failed, 2 ignored). Full logs:
  `/tmp/qv-fix-spdx.log`, `/tmp/qv-fix-final-fmt.log`,
  `/tmp/qv-fix-final-clippy.log`, `/tmp/qv-fix-final-test.log`.
  Focused CLI suite: 44 passed, with the usual environment-dependent offline
  networking scenario skipped internally (not counted as isolation evidence);
  `unshare -rn true` still fails with `No space left on device`
  (`/tmp/qv-fix-unshare.log`). Dependencies and lockfile unchanged, so no new
  deny/vet run required. Reviewer-role diff inspection checked LF/EOF/limit
  branches, traversal order and drop, component/path zeroization, JSON state
  across flushes and I/O error propagation; it found no further changes
  needed in this remediation. This is not fresh-context phase approval.
  Existing staged review records were not staged over or committed; all
  implementation changes remain unstaged for owner review/commit.

- 2026-10-26: Fresh-context remediation review approved; see REVIEW.md. Both
  findings resolved without further code changes. Independent SPDX, fmt,
  Clippy and locked tests passed (456 passed, 2 ignored). No dependency
  changes in the remediation. Network isolation remains unverified here.
