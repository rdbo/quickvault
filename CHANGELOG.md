# Changelog

Repository-level changes: code, tooling, docs and spec milestones. Normative
spec amendments are also recorded in each spec's own *Changelog* section; this
file summarizes them. Loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are ISO 8601. Newest first within each section.

## Unreleased

### Added

- 2026-10-29: Rotation foundation (plan 0021, phase 1.15a): bounded canonical
  journal metadata with independent old/new generation MACs, strict rejection
  tests and a journal fuzz target. Existing `.qvrotate` intent markers block
  ordinary open/create/restore and mutation paths without adopting an anchor.
  No production marker writer or `recovery rotate` command yet; replacement,
  durable recovery and snapshot accounting follow in phase 1.15b. Owner-approved
  0002 amendment defers offline recovery public-key derivation until needed.

- 2026-10-29: Fresh-context review of phase 1.14 (plan 0020): Approved with
  minor fixes to its stale plan status. No blocking product finding; independent
  required gates pass with private Xvfb. Network isolation unavailable.

- 2026-10-29: `qvault passwd`, `recovery show` and `recover <existing.qvault>`
  (plan 0020, phase 1.14). Password replacement atomically updates the complete
  slot, encrypted keyslot record and header MAC through the existing transaction
  and anchor path, preserving VK, generation and application object ciphertext.
  Recovery-phrase redisplay reauthenticates and uses the terminal alternate
  screen. Phrase recovery of a missing/mismatched anchor requires explicit
  baseline consent and a verified recovery copy. After a successful password
  change, the CLI names pre-change snapshots and offers deletion only after
  separate confirmation; old slots and independent copies remain effective.
  No new dependency, profile, format or schema. Standalone phrase/archive import
  and generation rotation are not included.

- 2026-10-29: Correct slot-bearing snapshot restore to return integrity exit 7
  as specified, with a production CLI regression preserving source and anchors
  (plan 0019 review remediation). Other unsupported archive features retain
  their existing classification.

- 2026-10-28: Independent review of snapshot restore (plan 0019) requests a
  correction: selected slot-bearing archives are refused with exit 1 instead
  of the specified exit 7. Phase 1.14 awaits correction and review; no product
  behavior change in this review session.

- 2026-10-28: `qvault snapshot restore <id> <new-path>` restores a local archive
  into a new private vault with fresh replica, writer and external anchor
  state (plan 0019, phase 1.13b). It preserves archived records, history,
  suppression floors and attachments, leaves the active vault and its anchor
  unchanged, and uses the password current when the snapshot was made.
  Full or unambiguous six-or-more-hex IDs (optional `@`) are supported;
  existing targets are refused. The explicit recovery baseline does not prove
  global freshness. Automatic pruning waits until restore succeeds, and
  signal cancellation is checked between bounded units of work. No dependency,
  schema or format change.

### Fixed

- 2026-10-28: Authenticate archive records, retained history and attachment
  chunks before publication or delivery to import code. Reject nonce-only
  corruption and contradictory reference digests, and preserve existing
  snapshots when a replacement cannot be verified (plan 0018 review fixes).
  Verification uses bounded seek passes over ciphertext without plaintext
  staging; the archive format is unchanged.

### Added

- 2026-10-28: Local snapshot policy, `qvault snapshot ls`, `qvault verify` and
  the mandatory recovery snapshot of `trash empty` (plan 0018 steps 7–10,
  phase 1.13a; 0007 §3, 0011 §4). With a configured private snapshot
  directory, an unlock may write one ordinary archive per hour and one on the
  first unlock of a UTC day, decided from authenticated archive headers only:
  no marker or settings row and no vault write on a read command. Budgets are
  30 days, 48 ordinary snapshots and 512 MiB, pruned oldest first; a recovery
  copy pinned by an in-progress destructive operation is never pruned and a
  `recover-` file left by a crash is reclassified before pruning. `trash empty`
  writes and verifies a recovery copy before its purge commits: a copy that
  cannot be written aborts the deletion with nothing purged, and exceeding the
  ordinary budget requires explicit approval (exit 9 when declined). `verify`
  is a read-only full re-hash/authentication pass that reports object/record/
  head/history/tombstone counts, the local sequence and the anchor comparison
  (`verified|advanced|missing|mismatch`) as human lines or documented JSON.
  `snapshot ls` authenticates every header with the vault key and lists only
  same-vault, same-generation archives newest first; unauthenticatable files
  are stderr warnings, never rows. Snapshot files carry no password slot, and
  snapshot failures or budget skips are warnings that never fail the command.
  Limits: `verify` never repairs (the remedy is a snapshot restore, 1.13b), a
  failed verify is not proof of erasure, and archives elsewhere on other media
  remain outside application control. No dependency, schema, MSRV or format
  change.

- 2026-10-28: `qv-store` archives and `verify` (0004 §6, §3.6; plan 0018 steps
  3–6): the bounded archive header codec and `u32be` framing, the writer that
  streams only verified objects to a temp file and checks each object's
  profile, length and SHA-256 against its reference first, the publish
  protocol (temp → re-read and verify with the reader → `fsync` →
  `RENAME_NOREPLACE` → directory `fsync`), the 0004 §6.3 reader, the private
  local-snapshot directory, the full `verify` pass and the `archive_read` fuzz
  target with its CI step. No dependency, schema, MSRV or frozen format change.

### Changed

- 2026-10-28: Owner-approved 0011 snapshot/`verify` contract (plan 0018, owner
  decision D1): `verify` reports counts, anchor status and fixed-label notes and
  never repairs; `snapshot ls` lists only authenticated same-vault,
  same-generation snapshots; archive IDs are scoped and prefix-addressable; and
  `trash empty` must write and verify a recovery snapshot before it commits.

- 2026-10-27: 0007 §3 amended per owner decision D6: a local snapshot carries
  no password slot and opens with the vault key of the same vault ID and
  generation or the recovery phrase; the new §3.5 requires a password change to
  offer (never to claim erasure of) the pre-change snapshots, and OQ1 is
  resolved. No archive format value changes (plan 0018).

- 2026-10-27: Owner-approved history/restore/purge CLI contract added for
  roadmap phase 1.12: scoped historical version IDs, explicit conflict restore
  consent, protected historical display and local suppression limits (plan 0017).

- 2026-10-27: Use the existing reviewed constant-time implementation for
  confidential attachment-content hash comparisons during staging and reading;
  test rejected digests at first, middle and last byte positions (plan 0016
  review remediation). No format or dependency change.

- 2026-10-27: Fresh-context review approved phase 1.10c (plan 0015), including
  independent maintained-transport and private-Xvfb checks. Owner approved
  plan 0016 and its concrete attachment CLI spec amendment.

- 2026-10-27: Fresh-context review approved phase 1.10b (plan 0014), with
  independent gates passing and no code fixes. The owner approved plan 0015's
  clipboard design and incoming-allocation correction, with continuing authority
  for necessary correctness fixes within that implementation.

- 2026-10-27: Fresh-context review approved phase 1.9's disposable Dioxus
  feasibility scope (plan 0013); root/spike gates pass. Prepared plan 0014
  for remaining CLI editing/trash/signals, with an owner decision pending on
  separating clipboard integration because of dependency buffer/ownership gaps.

- 2026-10-26: Owner selected standard Dioxus webview input for the shared UI.
  Specs 0008/0009 now require bounded input and best-effort cleanup, with
  framework/OS copy limits stated; native dialogs, a fork or a custom engine
  are not required solely for deterministic wiping. D8 resolved; plan 0013
  revised and approved. Related 0002/0012 cross-references, architecture and
  agent guidance updated; core secret handling and release controls retained.

- 2026-10-26: Fresh-context review approved the CLI EOF-CR and deep-listing
  fixes (plan 0011); phase 1.10a is Reviewed.

- 2026-10-26: Fixed CLI password input dropping a final carriage return at EOF.
  Deep listings now traverse iteratively, share path components and flush
  output incrementally; listing order and human/JSON formats are preserved.

- 2026-10-26: Agent guidance now loads spec/layout navigation on demand in
  `.agents/README.md` and uses the architecture and plans index for current
  implementation status. Skills describe targeted roadmap reading, focused
  step verification and full final gates with preserved exit status; review
  checks remain independent. Shorter skill descriptions reduce discovery
  context. Spec/security requirements, approval rules and required gates are
  retained; the specs index no longer calls the repository specification-only.

### Added

- 2026-10-27: Entry history, explicit historical display/reveal, restore as a
  fresh causal edit and confirmed local history purge (plan 0017, phase 1.12).
  Retention targets ten versions under monotonic suppression and existing
  budgets; no active head/conflict/tombstone is pruned. New CLI `history`,
  `history show`, `restore` and `history purge` support scoped historical IDs,
  masked output and explicit conflict-restoration consent. Purge keeps current
  heads but suppresses them if later dominated; snapshots, unseen concurrent
  history and independent copies may remain. No secure-erasure claim.

- 2026-10-27: Streaming attachments through qv-core and `qvault attach
  add|ls|save|rm` (plan 0016, phase 1.11). Imports up to 10 MiB use protected
  chunk buffers, authenticated ordered chunks and complete SHA-256/length
  checks within the existing transaction/anchor path. Metadata hashes now
  zeroize on drop and rejected decode. Listing supports JSON; plaintext save
  requires explicit consent and a new owner-only path, with no overwrite,
  symlink traversal, temporary plaintext or automatic file opening. Removal
  confirms permanent causal deletion and prunes by references. Failed/crashed
  exports can leave incomplete plaintext; independent copies are not erased.

- 2026-10-27: CLI `copy`, `totp --copy` and `generate --copy` (plan 0015,
  phase 1.10c). The private X11 adapter uses sensitive hints, a foreground
  timeout/countdown and signal cleanup after dropping vault keys/metadata.
  Window/connection release preserves a newer owner; INCR transfers and I/O
  have explicit budgets. Maintained x11rb source protects outgoing buffers and
  checks incoming lengths before allocation. Provenance/header-checker rules,
  two documented vet exemptions and isolated-Xvfb CI tests accompany it.
  Native Wayland requires XWayland; clipboard managers/recipients may retain
  copies despite hints and timeout. No secure-erasure claim.

- 2026-10-27: CLI entry editing (`add`, `edit`), groups/moves/deletion
  (`mkdir [-p]`, `mv`, `rm [-r]`) and `trash ls|restore|empty` (plan 0014,
  phase 1.10b). Notes and protected fields use bounded no-echo prompts;
  `-i` prompts field values, and stdin/password prompt conflicts fail before
  unlocking. SIGINT/TERM/HUP cancel input/countdowns and restore terminal and
  recovery alternate-screen state. Core drafts preserve untouched data; trash
  empty confirms unless `--yes`. Clipboard commands remain phase 1.10c.


- 2026-10-26: Isolated non-production Dioxus spike source and protected fixture
  controller (plan 0013). Linux create/edit/reopen, input cleanup and five
  full-profile unlock samples validated; arm64 APK built with minimum Android 10, backups off and
  no personal-data permissions. Dioxus loopback IPC requires Android
  INTERNET permission (also capable of remote networking). Device validation
  now passes on the connected phone, including persistence/background lock and
  screenshot blocking; five unlock samples measure 852–881 ms (median 865 ms).
  Fixed required loopback packaging policy and canonical app-private paths while
  retaining storage checks. Four approved spike-only advisory exceptions and an isolated vet baseline retain root policy.

- 2026-10-26: Plan 0013 for phase 1.9 Android/Linux feasibility, with verified
  physical-device prerequisites and explicit phone-operation boundaries.
  The initial native-input proposal was replaced by the owner's Dioxus input
  decision; no spike app has been installed yet.

- 2026-10-26: Withdrew unapproved CLI plan 0012 after the owner corrected
  phase selection to the unfinished Android/Linux feasibility phase 1.9.
  No CLI scope or behavior changed.

- 2026-10-26: `scripts/setup-android.sh`: installs the Android command-line
  tools (checksum-pinned), platform 35, build-tools 35.0.0, NDK r27
  (27.3.13750724) and the Rust Android targets; `--print-env` prints the
  variables for Android builds (minimum API 29). The SDK goes to
  `$HOME/Android/Sdk`, or to the git-ignored `.android-sdk/` when `$HOME` is
  read-only.

- 2026-10-26: Spec 0009 §2: the supported Android baseline (arm64, Android
  10+, at least 4 GB RAM) is the target of the 0002 §1.3 KDF budgets; no named
  benchmark devices (roadmap D7, owner decision).

- 2026-10-26: CLI foundation, vault and read commands (roadmap phase
  1.10a, plan 0011). New crate `qv-cli`, binary `qvault`: `init` (a
  suggested 6-word passphrase, the zxcvbn verdict with the 5-second weak
  password confirmation, the recovery phrase on the alternate screen, a
  three-word check or a recorded skip), `info` (the unverified header without
  a password; `--full` unlocks), `ls`, `search`, `show` (masked unless
  `--reveal`; `--field` for scripts), `totp` and `generate`. Vault selection
  by `--vault`, `QVAULT_PATH` or the config file (a strict TOML subset);
  `--password-stdin`; `--json`; no-echo prompts with the terminal state
  always restored; all vault text escaped (ANSI/OSC, C1, bidi controls) and
  written from zeroizing buffers; exit codes per 0011 §6; PTY end-to-end
  tests. `qv-core` gains the header view, the zxcvbn master-password
  estimate, the recovery-phrase confirmation positions and recorded skip,
  `@id` lookup, and refuses a vault stored inside the anchor directory
  (review of plan 0009). `qv-model` stores the skip at settings key 3, and
  new generator defaults replace an unreadable stored value (review of plan
  0010). Spec 0010 §3.2: a zxcvbn estimate at its 64-bit ceiling counts as
  Strong. New dependencies: `clap` (builder API) and `zxcvbn`.

- 2026-10-26: `qv-core` sessions and vault operations (roadmap phase 1.8,
  plan 0010). New crate `qv-core`, the single entry point for frontends:
  `Core` hardens the process and reports reduced protection, creates vaults
  (returning the recovery phrase once) and unlocks them, including the
  read-only recovery unlock with `adopt_baseline`. A `Session` serializes
  calls, and `lock` cancels running work, drops and zeroizes the vault, keys
  and views, and is final; handles carry a random session tag. The metadata
  index (64 MiB budget) keeps only non-protected metadata; protected values
  and notes are decrypted on demand (`entry`, `reveal`, `totp`, drafts).
  Search covers titles, group names and non-protected text, URL and e-mail
  fields, with no search index. Listings follow the repaired group tree,
  with recovered items. Edits, moves and settings go through drafts that
  carry their base version, as causal versions committed by the store's one
  transaction. Conflicts are shown, and their records refused for changes
  until phase 2.2. The trash: a group is deleted with its contents in one
  transaction and restored with what was deleted with it; final deletion is
  explicit, leaves a tombstone, drops history, advances the floor and
  tombstones the entry's attachments; an expiry report lists what the
  retention period offers and flags clock anomalies. `qv-store`: a final
  tombstone drops the record's history and advances its floor; manifest
  types print a redacted `Debug` (review of plan 0009). `qv-model`: password
  generator defaults in vault settings (key 2).

- 2026-10-26: Objects, manifests, local head, anchor and the write path
  (roadmap phase 1.7, plan 0009). `qv-store` now stores records as
  encrypted immutable objects whose plaintext envelope holds only object ID,
  key generation, profile, nonce and ciphertext; the encrypted manifest
  (heads, history, floors, chunk lists, sorted references, configuration
  digest, the three control records) with its envelope hash and reference
  digest, validated and bounded before allocation; the authenticated local
  head; per-replica external anchors in a private state directory; and
  writer IDs with counter reservations in a local-only `replica` row. `create`
  writes the vault metadata, root group and password-keyslot records;
  `unlock` verifies the head, manifest, every referenced object row and
  every head (0004 §3.6) and compares the head with its anchor (0005 §5.4),
  failing closed on a missing or mismatched anchor, with
  `unlock_for_recovery` + `adopt_baseline` as the explicit recovery. All
  writes go through one mutation transaction (head re-read inside
  `BEGIN IMMEDIATE`, objects, manifest, head, counters, prune, durable
  commit, anchor, report), checked at every ordering point by a test-only
  crash-injection harness. New errors `Rollback`, `NoAnchor`, `Changed`,
  `InvalidEdit`; a full disk is no longer reported as the size budget.
  Development schema 2. New `manifest_decode` fuzz target, run in CI. The
  generated worst-case manifest at every budget is 50.0 MiB, inside the
  64 MiB limit. `qv-crypto`: the `local-state` key MACs; `qv-model`: public
  clock codec. Spec 0004 amended (below).

- 2026-10-26: Vault file: hardened SQLite, schema, header and keyslots
  (roadmap phase 1.6, plan 0008). New crate `qv-store`: owner-only vault
  files (symlinks, nonregular files, unsafe modes and unsafe parent
  directories refused), a `flock` process lock, file-identity tracking and
  sync-folder/network/removable location warnings; SQLite opened with every
  0004 §1.2 setting read back (defensive mode, no triggers/views/extensions,
  limits, an execution-step budget, a 2 GiB size cap), bounded
  `quick_check` and exact-schema validation; the header and the local
  password slot under the header MAC; atomic `create` (temp file and
  no-replace rename) and `open` → `unlock` to VK, with wrong password and
  integrity failures kept distinct. Formats are development values until
  phase 1.16. New dependency `rusqlite` with bundled SQLite 3.53.2, whose
  compile options `.cargo/config.toml` trims (no FTS, R-Tree, dbstat, JSON,
  extension loading or URI filenames; checked by a test); `rustix` gains its
  `fs` feature. New `vault_open` fuzz target, run in CI, plus tamper and
  second-process lock suites. `qv-model` gains a public keyslot-descriptor
  codec.

- 2026-10-26: Data model, version vectors and merge (roadmap phase 1.5,
  plan 0007). New crate `qv-model`: random UUIDv4 IDs (validated on decode),
  the record-version plaintext and the five payload kinds (vault metadata
  with settings, groups, entries with typed fields, attachment metadata, the
  password keyslot) as canonical CBOR with an integer-key registry
  (development values until the 1.16 format freeze), unknown-key
  preservation and 0004 §4.1 budgets checked before allocation; version
  vectors with the sorted-pair wire form, join and edit clocks; the
  maximal-version merge with its integrity checks, head limit, live/trash
  representatives and record status; history floors as data; the
  deterministic group-tree projection with a recovered-items view; and
  `otpauth://totp` parsing with RFC 6238 codes. `qv-crypto` gains `hotp`
  (RFC 4226 over the pinned HMAC crates; RFC 4226 and RFC 6238 vectors) and
  the new dependency `sha1`. Property tests cover merge commutativity,
  associativity and idempotence over generated histories and the 0012 rows
  for old-date edits, mixed credentials and deleted-entry resurrection. New
  `record_decode` fuzz target with a canonical round-trip oracle, run in CI.

- 2026-10-25: Recovery phrase and password generator (roadmap phase 1.4,
  plan 0006). `qv-crypto` encodes VK as 24 BIP-39 English words (entropy
  encoding only, not the wallet seed) and decodes it back with
  constant-time word lookups and checksum checks; `RecoveryPhrase::confirm_word`
  supports confirmation at vault creation. Trezor BIP-39 vectors pass. The
  spec 0010 generator covers random characters, passphrases (EFF large list)
  and PINs. Every setting is validated before any randomness is used,
  selection is unbiased rejection sampling, `require_each_class` regenerates
  whole passwords (at most 10,000 attempts) and never patches them, and
  entropy, strength labels and the 64-bit warning are exact. Deterministic
  chi-square tests cover every sampling path. Both word lists are embedded
  byte for byte, and their SHA-256 is checked at first use and in tests
  (sources and licences in `crates/qv-crypto/data/README.md`; `.gitattributes`
  keeps their line endings). New `CryptoError::WrongPhrase` (exit code 3).
  New direct dependency `ctutils` (already in the build via `hmac`), approved
  by the owner instead of `subtle`, whose `BSD-3-Clause` licence is outside the
  allow-list. `zxcvbn` estimates for typed passwords come with the CLI
  (phase 1.10).

- 2026-10-25: Review fix (plan 0005): other crates could read raw AEAD/MAC
  key bytes through the sealed key-use traits; the accessors now require a
  crate-private token, with compile-fail tests.

- 2026-10-25: Crypto profiles and key hierarchy (roadmap phase 1.3, plan
  0005): `qv-crypto` gains the profile registry (one type per namespace;
  unknown IDs fail closed; explicit transitions), password-kdf/1 (Argon2id
  over the NFC master password), the KEK and its constant-time commitment,
  password slots that report only "wrong password" (with a
  partitioning-oracle test), HKDF-SHA-512 purpose keys for all nine labels
  as purpose-typed keys, per-record and per-attachment keys, stored-data/1
  (XChaCha20-Poly1305 with canonical Padmé framing and budgets checked
  before decryption), MAC/1, object-hash/1 and the redacted `CryptoError`.
  Upstream known-answer vectors: RFC 4231, Wycheproof HKDF-SHA-512, FIPS
  180-4, draft-irtf-cfrg-xchacha-03 and RFC 9106. Development-only
  QuickVault vectors are cross-checked by a stdlib Python script and by
  OpenSSL's Argon2id. New dependencies: `chacha20poly1305`, `argon2`, `hkdf`,
  `hmac`, `sha2` and `unicode-normalization`; `deny.toml` now allows
  `Unicode-3.0` (Unicode data tables), approved by the owner.

- 2026-10-25: Canonical CBOR (roadmap phase 1.2, plan 0004): new crate
  `qv-encoding` implementing the spec 0004 §3.1 profile of RFC 8949
  deterministic CBOR. It validates the whole input without allocating before
  any typed read, and rejects every noncanonical form, tags, floats, other
  simple values, invalid UTF-8, non-integer, duplicate or misordered map keys,
  nesting deeper than 32 and lengths beyond the input. The encoder can only
  emit canonical items (sorted maps, exact counts) and wipes its buffers.
  `RawValue` preserves unknown map entries byte for byte, and `encode_array`
  builds AAD/info/transcripts. Property tests (`proptest`, dev-only) and a
  `cbor_decode` fuzz target (`fuzz/`, cargo-fuzz) with a new CI job.

- 2026-10-25: Cargo workspace and tooling (roadmap phase 1.1, plan 0003):
  pinned Rust 1.98.1, workspace lints (no `unsafe`, no `unwrap`/`expect`
  outside tests), `cargo deny` and `cargo vet` configuration, SPDX header
  check, GitHub Actions CI. New crate `qv-crypto` with zeroizing, page-locked,
  unprintable and non-cloneable secret buffers (`SecretBytes`, `SecretArray`),
  reduced-protection reporting when locking fails, core-dump/debugger-attach
  hardening on Linux/Android, and a fail-closed OS RNG.

- 2026-10-25: Development roadmap (`plans/0002-roadmap/`): 37 phases across
  the four milestones of `ARCHITECTURE.md` §7, one phase per session. Records
  the owner's decisions on toolchain/MSRV, CI, SPDX headers, workspace layout,
  go-ahead for the Draft sections milestone 1 needs, snapshot password slots
  and CLI attachment commands.

- 2026-10-16: Agent workflow. `AGENTS.md` (with `CLAUDE.md` symlink), skills in
  `.agents/skills/` (`quickvault-thinker`, `quickvault-architect`,
  `quickvault-developer`, `quickvault-reviewer`) symlinked from `.claude/skills`,
  the `plans/` directory, this changelog, and search guards (`.ignore`,
  `.gitignore`, `.claude/settings.json`).

### Fixed

- 2026-10-26: `qv-store`'s `adopt_baseline` now retries a pending anchor
  update before it commits, as every other write does (review of plan 0009).
  Before, a recovery after a failed anchor write could leave the database
  two commits ahead of its anchor, so the next open reported a rollback.

- 2026-10-26: `qv-store` no longer lets a file planted next to the vault
  rewrite it before validation (review of plan 0008). SQLite rolled back a
  hot `<vault>-journal` and replayed a `<vault>-wal` before any check ran;
  a crafted 512-byte journal truncated the vault, and a WAL changed it on
  disk. A `-journal` must now be owner-only like the vault, and a `-wal` or
  `-shm` is refused. The parent directory must be writable by no one but
  the owner (0004 §1.1): the sticky-bit exception is gone, and group write
  is allowed only for Android's per-app `0771` directory.

- 2026-10-26: `qv-model` no longer encodes a record whose embedded
  `qv-crypto` ID (root group, group parent, entry group, attachment entry,
  slot ID) lacks the UUIDv4 bits, which decode would reject (review of
  plan 0007).

### Specs

- 2026-10-26: 0004 §4.1/§4.2: an aggregate budget of 1,048,576 clock
  components per manifest, so that the worst-case manifest fits the 64 MiB
  limit (256 writers per clock over 250,000 objects did not); history yields
  to it. 0004 §2: the local-only `replica` row (writer state and the
  anchor's name). Owner-approved with plan 0009.

- 2026-10-24: Prioritize Android alongside Linux before the optional server;
  retain iOS as later work. Specify shared cross-platform app/UI code, isolated
  OS adapters and early Android/Linux framework validation. Preserve Dioxus as
  the planned framework, the open renderer decision and existing security gates.

- 2026-10-24: Follow-up direction: start both LAN and remote sync with manual
  user initiation. Remove automatic unlock/edit/timer triggers, defer background
  scheduling/retries, and align client/CLI requirements and acceptance criteria.

- 2026-10-24: Refocus QuickVault on complete offline use with two independent
  optional sync modes: direct account-free LAN peer sync and account-based
  remote server sync. Align architecture, roadmap, threat model, key rotation,
  storage, history, clients, CLI and separate validation gates; retain existing
  merge/crypto guarantees and record unresolved LAN protocol decisions.
  Document the amendment and review in `plans/0001-offline-first-sync/`.

- 2026-10-14 – 2026-10-15: Initial specs 0001–0012 and `ARCHITECTURE.md`, then
  amendments from a security review. See each spec's *Changelog*.
