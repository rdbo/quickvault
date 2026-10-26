# Changelog

Repository-level changes: code, tooling, docs and spec milestones. Normative
spec amendments are also recorded in each spec's own *Changelog* section; this
file summarizes them. Loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are ISO 8601. Newest first within each section.

## Unreleased

### Added

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

### Specs

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
