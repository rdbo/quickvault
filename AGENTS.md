# AGENTS.md

Instructions for AI agents (and humans) working in this repository.
`CLAUDE.md` is a symlink to this file; edit this file only.

## What this repository is

QuickVault is an offline-first, end-to-end encrypted password manager with
optional sync, written in stable Rust (AGPL-3.0-or-later). Development is
**spec-first**: the specs in `specs/` are normative and code implements them.

**Current state:** early implementation (roadmap 0002). The Cargo workspace,
CI and supply-chain tooling exist; `qv-encoding` has the canonical CBOR codec;
`qv-crypto` has protected memory, process hardening, the OS RNG, the profile
registry, the symmetric primitives, the key hierarchy, the recovery phrase,
the password generator and HOTP; `qv-model` has the records, version vectors,
merge, group-tree projection and TOTP; `qv-store` has the hardened vault
file, its header and keyslots, creation and unlock. Most specs
are not implemented yet. `tests/` is an empty placeholder. Do not assume code
exists; check with `git ls-files <path>`.

## Ground rules

1. **Specs are normative.** Behaviour changes start with a spec change.
   Status meanings are in `specs/README.md`: implement `Accepted` specs;
   `Draft`/`Exploratory` behaviour needs the owner's explicit go-ahead.
2. **Don't decide open questions for the owner.** Undecided points stay listed
   under a spec's *Open Questions* (or as an `Exploratory` spec) with your
   recommendation, until the owner confirms. Current owner-level open decisions
   are listed at the end of `ARCHITECTURE.md`.
3. **Plan before non-trivial code.** Work flows through the skills below and
   is recorded in `plans/`.
4. **Document every change** (see *Documentation duties*).
5. **Security claims must be honest.** Writing a spec or test is not evidence
   that something is secure; see `specs/0012-security-validation.md`.

## Context budget: read only what you need

This repo is small but dense, and future builds will add large trees. Keep
token use proportional to the task:

- **No recursive sweeps of the repo root.** Avoid `grep -r . `, `find .`,
  `ls -R`, `**/*` globs and "read every spec to get context". Use
  `git ls-files [path]` for inventory and the topic map below to pick files.
- **Outline first, then read a section.** For a spec:
  `grep -n '^#' specs/0005-synchronization.md` and then read only the line
  range of the section you need.
- **Scope every search** to a file or directory you've already picked, e.g.
  `grep -n 'tombstone' specs/0005-*.md specs/0007-*.md`.
- **Overview = `ARCHITECTURE.md` + `specs/README.md`.** Start there; don't open
  specs you don't need.
- **Never read:** `LICENSE` (it's AGPL-3.0-or-later; nothing else in it matters),
  `.git/`, `target/`. Read `Cargo.lock` only for dependency review.
  `.ignore` keeps ripgrep-based search out of `LICENSE`, and `.gitignore` covers
  `target/`.
- **Trim command output**: pipe long build/test output through `tail`/`grep`.
- **Don't spawn search subagents** for this repo; direct, targeted reads are cheaper.

## Topic map

| Topic | Where |
|-------|-------|
| Goals, components, trust boundaries, flows, tech stack, phases | `ARCHITECTURE.md` |
| Spec index, statuses, process, spec template | `specs/README.md` |
| Assets, adversaries, out of scope, security goals, accepted leakage | `0001` threat model |
| Crypto profiles §1, migration §2, key hierarchy / password slots §3, recovery phrase §4, quick unlock §5, hybrid KEM/signatures §6, general rules §7, unlock §8 | `0002` cryptography |
| Identifiers, records, vault metadata, groups, entries, attachments, tags | `0003` data model |
| Vault files §1, SQLite schema §2, encoding/encryption §3, resource budgets §4, unlock & writes §5, archive format §6 | `0004` local storage |
| Offline-first modes §0, versions/causality §1, merge §2, remote server sync §3, file exchange §4, manifests/checkpoints/anchors §5, direct LAN sync §6 | `0005` synchronization |
| Admission, auth, key custody, OPAQUE, server identity, registration, login, adding a device (pairing), recovery, password change, revocation | `0006` server auth |
| Entry history §1, trash §2, local snapshots §3, server retention §4 | `0007` history & backups |
| Memory §1, timing §2, OS leaks §3, webview boundary §4, local files & testing §5 | `0008` memory & side channels |
| Clients, platform priority, CLI scope, mobile autofill, desktop | `0009` clients & platforms |
| Randomness, modes, strength, warnings, settings, secret handling | `0010` password generator |
| CLI general, addressing, secret-handling rules, commands, output, exit codes | `0011` CLI |
| Validation matrix §1, acceptance scenarios §2, release gates & supply chain §3 | `0012` security validation |

## Repository layout

| Path | Purpose |
|------|---------|
| `ARCHITECTURE.md` | High-level design; kept in sync with specs and code structure |
| `specs/` | Normative RFC-style specs (`NNNN-title.md`, numbers never reused) |
| `plans/` | Implementation plans and reviews (`NNNN-slug/PLAN.md`, `REVIEW.md`) |
| `CHANGELOG.md` | Repository-level change log |
| `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `clippy.toml` | Virtual workspace, lockfile, pinned toolchain, clippy test exemptions |
| `.cargo/config.toml` | Build environment: compile options of the bundled SQLite (checked by a `qv-store` test) |
| `crates/<name>/` | Workspace crates (`ARCHITECTURE.md` §3) |
| `deny.toml`, `supply-chain/` | `cargo deny` policy and `cargo vet` audits/exemptions |
| `fuzz/` | cargo-fuzz targets; own workspace and lockfile, outside the shipped workspace; pinned nightly in CI |
| `scripts/` | Repository checks (`check-spdx.sh`) |
| `.github/workflows/` | CI (gates, supply chain, fuzzing), actions pinned by SHA |
| `.agents/skills/` | Agent skills (source of truth) |
| `.claude/skills` | Symlink to `../.agents/skills` for Claude Code |
| `tests/` | Placeholder for future integration tests |

## Agent workflow and skills

Skills live in `.agents/skills/<name>/SKILL.md`. Typical flow:

```
quickvault-thinker  → idea explored; outcome recorded as Exploratory spec / Open Question
quickvault-architect → plans/NNNN-slug/PLAN.md (status Proposed → owner approves)
quickvault-developer → implements the plan, keeps its execution log (→ Implemented)
quickvault-reviewer  → REVIEW.md, minor fixes, escalates the rest (→ Reviewed)
```

Skip stages when they add nothing: a typo fix needs no plan, and a settled idea
needs no thinker. Anything touching cryptography, storage or wire formats,
protocols or secret handling always goes through architect → developer → reviewer.

**Roadmap:** development follows `plans/0002-roadmap/PLAN.md`, one phase per
fresh session started with "next phase". Follow its *Session protocol*: review
the previous phase, plan the current one, approve it under the standing
approval rule (stop for the owner only on the listed conditions), implement,
then update the roadmap. **Never commit, push or branch: the owner commits.**
If the previous phase is still uncommitted, ask the owner to commit it first.

## Documentation duties

| When you… | Update |
|-----------|--------|
| Change normative behaviour | The spec's text **and** its *Changelog*; status if it changed; `specs/README.md` index |
| Add/rename/split a component, crate or trust boundary | `ARCHITECTURE.md` §3 (and the diagram if affected) |
| Change tech choices or phases | `ARCHITECTURE.md` §6 / §7 |
| Finish any user-visible or repo-level change | `CHANGELOG.md` under *Unreleased* |
| Fully implement a spec | Set its status to `Implemented` (only when the code matches it fully) |
| Change agent workflow, layout or conventions | This file, and the affected skill |

## Engineering conventions

Applies once code exists (from the specs and `ARCHITECTURE.md`):

- Stable Rust. Create crates from `ARCHITECTURE.md` §3 only when an interface
  needs them — no empty scaffolding.
- Dependency direction: frontends → `qv-core`; crypto and model never depend on
  frontends.
- Gates for every change: `sh scripts/check-spdx.sh`, `cargo fmt --check`,
  `cargo clippy --all-targets --locked -- -D warnings`, `cargo test --locked`.
  Commit `Cargo.lock`. Crates opt into the workspace lints (`[lints] workspace = true`):
  `unsafe_code` is forbidden and `unwrap`/`expect`/`panic!` are denied outside tests.
- Secrets live only in `qv_crypto::{SecretBytes, SecretArray}`; access is via
  `expose_secret*`. Lock and hardening failures are status values that callers
  must surface, not errors to swallow.
- Dependency changes: justify in the plan, run `cargo deny` and `cargo vet`
  (0012 §3), keep security-critical crates to a reviewed minimum.
- Never implement cryptographic primitives; use reviewed crates pinned to the
  profiles in 0002.
- Secrets: zeroize, no `Debug`/`Display`, never in logs, errors, panics or argv
  (0008, 0011 §3). Untrusted input: bounded before allocation, authenticated
  before parsing (0004 §4, §6). No `unwrap`/`expect` on untrusted data.
- `unsafe` only when a plan allows it, with a `// SAFETY:` comment.
- Commit messages: short, lowercase, imperative (`add sync spec`), matching history.

Owner decisions (2026-10-25, roadmap 0002 D1–D4):

- Toolchain pinned to Rust `1.98.1` in `rust-toolchain.toml`; that is the MSRV.
  Bump it deliberately in its own commit.
- CI: GitHub Actions running the gates above plus `cargo deny`/`cargo vet`;
  actions pinned by commit SHA.
- Every source file starts with `// SPDX-License-Identifier: AGPL-3.0-or-later`
  (checked in CI).
- Virtual workspace with crates under `crates/<name>/`; bounded deterministic
  CBOR lives in its own bottom-level crate `qv-encoding`.
