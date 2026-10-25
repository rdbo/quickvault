# Changelog

Repository-level changes: code, tooling, docs and spec milestones. Normative
spec amendments are also recorded in each spec's own *Changelog* section; this
file summarizes them. Loosely follows [Keep a Changelog](https://keepachangelog.com/).
Dates are ISO 8601. Newest first within each section.

## Unreleased

### Added

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
