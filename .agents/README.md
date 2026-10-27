# Agent navigation

Read this file when you need task routing, the spec topic map, repository
layout or roadmap navigation.
[AGENTS.md](../AGENTS.md) holds the mandatory rules; this file is navigation,
not a replacement for specs, plans or source code.

## Task entry points

| Task | Read first | Then read |
|------|------------|-----------|
| Small doc/tooling correction | Requested files and their diff | Relevant conventions; no product-spec tour |
| Explore an undecided idea | `quickvault-thinker/SKILL.md` | Related spec sections and Open Questions |
| Plan settled work | `quickvault-architect/SKILL.md` | Plans index, architecture sections and related specs |
| Implement/resume a plan | `quickvault-developer/SKILL.md` | Active plan in full, cited specs and named source files |
| Review work | `quickvault-reviewer/SKILL.md` | Plan, diff, related code and specs |
| “next phase” | Plans index, roadmap Session protocol | Previous phase plan/review and current phase dependencies |

Skill paths above are under `.agents/skills/`. Load only the role you are
performing; load the next skill when changing roles. Use the named plan when
provided; the roadmap itself is not an implementation plan.

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
| `scripts/` | Repository checks (`check-spdx.sh`); Android SDK/NDK and Rust Android targets setup (`setup-android.sh`, versions pinned inside) |
| `third-party/` | Approved vendor provenance and patch maintenance; only x11rb 0.13.2 is authorized (plan 0015) |
| `.github/workflows/` | CI (gates, supply chain, fuzzing), actions pinned by SHA |
| `.agents/skills/` | Agent skills (source of truth) |
| `.claude/skills` | Symlink to `../.agents/skills` for Claude Code |
| `spikes/ui-feasibility/` | Isolated non-production Dioxus prototype; separate lockfile/policy; status and gaps in plan 0013 |
| `tests/` | Placeholder for future integration tests |

## Efficient reading without losing evidence

- Treat indexes as routing aids. Read the actual spec requirements, status,
  relevant Open Questions and recorded owner decisions before designing,
  implementing or reviewing behaviour. Follow cross-references that affect it.
- For architecture context, pick the needed sections: §3 boundaries, §6
  technology, §7 delivery/open decisions. A workflow-only task does not need
  the whole architecture or any unrelated product spec.
- Read an active implementation plan fully once, including revisions and log.
  While executing, revisit the current step and relevant design constraints;
  re-read changed sections after edits or a handoff. Do not repeatedly reload
  unchanged files already in context.
- For roadmap work, outline `plans/0002-roadmap/PLAN.md` first. Read Session
  protocol, Spec basis, Decisions needed, Design, Risks and stop conditions,
  and Revisions, plus the selected phase and its prerequisites. Locate phase
  checkboxes with a scoped search. Read relevant log entries for handoff;
  unrelated future phase bodies and old logs need not be loaded.
- Start code discovery with `git ls-files crates/<name>` and scoped `rg` for
  symbols. Read the implementation and relevant callers/tests, widening the
  search when evidence shows another dependency. A path list is not a code
  review, and a summary is not evidence that requirements are satisfied.
- Batch independent reads/searches into one tool call, with output small
  enough to avoid truncation. If output truncates, narrow the query and read
  the missing part. Prefer headings and ranges over whole large documents.
- Keep durable handoffs in the existing plan log: completed work, unresolved
  issues, next step, and verification commands/results. Link to source sections
  instead of copying specs, diffs or test output into new context summaries.
  Recheck current files and status after resuming; old results are historical.
