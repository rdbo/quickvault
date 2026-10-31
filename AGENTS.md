# AGENTS.md

Instructions for agents and humans. `CLAUDE.md` links here; edit this file only.
QuickVault is an offline-first, end-to-end encrypted password manager with
optional sync, stable Rust, AGPL-3.0-or-later. **Specs are normative.**

## Non-negotiable rules

- Behaviour changes start with a spec amendment. Implement `Accepted` specs;
  `Draft`/`Exploratory` behaviour requires the owner's explicit go-ahead.
  Status meanings: `specs/README.md`; roadmap approvals may cover named sections.
- Do not decide open questions for the owner. Keep recommendations in spec
  *Open Questions* or an `Exploratory` spec until confirmed. Owner-level open
  decisions are at the end of `ARCHITECTURE.md` and in the active plan/roadmap.
- Plan before non-trivial code; record work in `plans/`. Cryptography, storage
  or wire formats, protocols and secret handling always require
  architect → developer → reviewer. A typo or local doc wording fix needs no plan.
- Document every change (table below). Never claim a spec or passing tests prove
  security; follow `specs/0012-security-validation.md`.
- **Never commit, push or branch: the owner commits.**

## Load context by task

This is early implementation, not all specs are implemented. Use
`ARCHITECTURE.md` §3 for components/current implementation, `plans/README.md`
for plan status, and `git ls-files <path>` to confirm code exists.

- Read the skill for your current role under `.agents/skills/`: unsettled idea
  → `quickvault-thinker`; plan/design → `quickvault-architect`; execute/resume
  → `quickvault-developer`; review/audit → `quickvault-reviewer`.
  Skip stages that add nothing; a settled idea needs no thinker.
- Use [.agents/README.md](.agents/README.md) **when needed** for task entry
  points, spec topic map, layout and roadmap reading instructions. Read the
  actual requirements, relevant Open Questions and owner decisions before
  acting; navigation and summaries do not replace them.
- Read only relevant architecture/spec sections. Outline with
  `rg -n '^#{1,4} ' <file>`, then read selected ranges. Widen to callers,
  cross-references and tests as needed to establish correctness.
- Scope searches to selected files/directories. Use `git ls-files <path>`
  and `rg`; no recursive root sweeps (`find .`, `ls -R`, `grep -r .`, `**/*`).
  Do not reload unchanged material already in context or spawn search subagents.
- Never read `LICENSE`, `.git/`, `target/` or `.android-sdk/`. Read `Cargo.lock`
  only for dependency review. Batch independent reads; keep output bounded.
- Keep full build/test output in a temporary log and show a short summary or
  failure excerpt. Preserve the command's exit status (e.g. Bash `pipefail`
  when piping to `tail`); truncated output must not hide failures.

## Roadmap sessions

Development follows `plans/0002-roadmap/PLAN.md`, one phase per fresh session
started with “next phase”. Its **Session protocol** governs: check the tree,
review the previous phase unless already Reviewed, plan the current phase,
apply standing approval only when no listed stop condition applies, implement,
then update the roadmap. If the previous phase is uncommitted, ask the owner
to commit it first. Preserve the fresh-context review requirement for
implementation; spec-only or plan-only work needs no separate review session.
Keep implementation steps inside the phase plan. Do not create more phase
suffixes solely for step count or context size; use the execution log to
continue the approved phase. Split only at a concrete delivery boundary or
blocking owner decision, with a stated reason. Explicit owner continuation
requests override the named intermediate commit/session boundary.

## Documentation duties

| Change | Update |
|--------|--------|
| Normative behaviour | Spec text + Changelog, status if changed; `specs/README.md` index |
| Component/crate/trust boundary added, renamed or split | `ARCHITECTURE.md` §3 and diagram if affected |
| Technology or phases | `ARCHITECTURE.md` §6 / §7 |
| User-visible or repo-level change | `CHANGELOG.md` under Unreleased |
| Spec fully implemented | Status `Implemented` only when code matches it fully |
| Agent workflow/layout/conventions | `AGENTS.md`, affected skill; `.agents/README.md` if navigation changes |

## Engineering and verification

- Stable Rust; MSRV pinned to **1.98.1** in `rust-toolchain.toml` (owner D1).
  Bump deliberately in its own commit. Virtual workspace, `crates/<name>/`;
  create crates from architecture §3 only when an interface needs them.
  Bounded deterministic CBOR is bottom-level `qv-encoding` (D4).
- Frontends → `qv-core`; crypto/model never depend on frontends.
- **Required gates for every change:** `sh scripts/check-spdx.sh`,
  `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
  `cargo test --locked`. Run focused checks while editing, then all gates on
  the final tree before handoff. Repeat affected checks after further edits;
  old logs are not current evidence. Do not weaken tests to save tokens.
- Tests that cover a 0012 §1 offline row carry `// 0012 §1: <exact row>`
  above their attributes; `sh scripts/check-matrix.sh` (CI) checks the rows
  in `tests/matrix-offline.txt`. Pre-1.0, formats stay volatile: no freeze
  until the owner says so.
- Dependency changes: justify in the plan, run `cargo deny check` and
  `cargo vet --locked` (0012 §3), retain `Cargo.lock` changes for owner commit,
  minimize security-critical crates. CI uses GitHub Actions, actions pinned
  by SHA, with gates plus deny/vet (D2).
- Every source starts with `// SPDX-License-Identifier: AGPL-3.0-or-later`
  (shell scripts use `#`, after the shebang); CI checks headers (D3).
  The sole approved vendored exception is `third-party/x11rb` 0.13.2 (plan
  0015): retain upstream licenses/headers/lints, exclude it from the product
  workspace and validate package identity/provenance in the header checker.
  QuickVault adapter code still follows all product header/lint rules. Review
  the local vendor patch as maintained application code; run its focused tests.
- Crates opt into workspace lints (`[lints] workspace = true`): `unsafe_code`
  forbidden; `unwrap`/`expect`/`panic!` denied outside tests. `unsafe` requires
  plan permission and a `// SAFETY:` comment.
- Application-controlled Rust secrets live in `qv_crypto::{SecretBytes,
  SecretArray}`, accessed via `expose_secret*`; zeroize, no secret-bearing
  `Debug`/`Display`, logs, errors, panics or argv (0008, 0011 §3). Dioxus input
  and framework/OS intermediates follow 0008 §1.1/§4.4: bound input, promptly
  convert to protected Rust containers, clear controls/state, and document
  best-effort cleanup limits. Framework copies alone do not require native
  dialogs or a custom engine. Surface lock/hardening failure status values.
- Never implement crypto primitives; use reviewed crates pinned to 0002
  profiles. Bound untrusted input before allocating, authenticate before parsing
  (0004 §4, §6); no `unwrap`/`expect` on untrusted data.
- Commit message convention for the owner: short, lowercase, imperative.
