# Plans

Implementation plans written by the `quickvault-architect` skill, executed by
`quickvault-developer` and reviewed by `quickvault-reviewer`. Plans are kept
after completion as the record of *how* and *why* something was built; specs
remain the record of *what* the system must do.

## Layout

```
plans/
  NNNN-short-slug/
    PLAN.md     # the plan, plus the developer's execution log
    REVIEW.md   # written by the reviewer
```

Numbers are four digits, increase by one, and are never reused. Find the next one
with `ls plans/`.

## Status lifecycle

Set in the table at the top of `PLAN.md`.

| Status | Meaning | Set by |
|--------|---------|--------|
| `Proposed` | Written, awaiting owner approval | architect |
| `Approved` | Owner agreed; ready to implement | owner (or developer, recording the owner's go-ahead) |
| `In progress` | Being implemented | developer |
| `Blocked` | Stopped on a question for the owner; see execution log | developer |
| `Implemented` | All steps done and verified | developer |
| `Reviewed` | Reviewer approved (possibly with minor fixes) | reviewer |
| `Abandoned` | Not pursued; keep the file and say why | anyone, with owner agreement |

A review that requests changes leaves the status at `Implemented` with a note,
and the developer continues. A re-plan creates a revision section in the same
plan, or a new plan that names the one it supersedes.

## Index

| # | Title | Status |
|---|-------|--------|
| [0001](0001-offline-first-sync/PLAN.md) | Offline-first sync direction (spec amendment) | Reviewed |
| [0002](0002-roadmap/PLAN.md) | Development roadmap (phases to v1 milestones) | Approved |
| [0003](0003-workspace-bootstrap/PLAN.md) | Workspace bootstrap and protected memory (roadmap 1.1) | Reviewed |
| [0004](0004-canonical-cbor/PLAN.md) | Bounded deterministic CBOR, `qv-encoding` (roadmap 1.2) | Reviewed |
| [0005](0005-crypto-key-hierarchy/PLAN.md) | Crypto profiles, symmetric primitives and key hierarchy (roadmap 1.3) | Reviewed |
| [0006](0006-recovery-phrase-generator/PLAN.md) | Recovery phrase and password generator (roadmap 1.4) | Reviewed |
| [0007](0007-data-model-merge/PLAN.md) | Data model, version vectors and merge, `qv-model` (roadmap 1.5) | Reviewed |
| [0008](0008-vault-file-sqlite/PLAN.md) | Vault file: hardened SQLite, schema, header and keyslots, `qv-store` (roadmap 1.6) | Reviewed |
| [0009](0009-objects-manifest-anchor/PLAN.md) | Objects, manifests, local head, anchor and the write path, `qv-store` (roadmap 1.7) | Reviewed |
| [0010](0010-core-sessions/PLAN.md) | qv-core sessions and vault operations, `qv-core` (roadmap 1.8) | Reviewed |
| [0011](0011-cli-foundation-read/PLAN.md) | CLI foundation, vault and read commands, `qv-cli` (roadmap 1.10a) | Reviewed |
| [0012](0012-cli-edit-trash/PLAN.md) | CLI editing, trash and signal cleanup (proposed phase 1.10b revision) | Abandoned — wrong phase selection; owner directed phase 1.9 |
| [0013](0013-ui-feasibility/PLAN.md) | Android/Linux shared-UI feasibility (roadmap 1.9) | Reviewed |
| [0014](0014-cli-edit-trash/PLAN.md) | CLI editing, trash and signal cleanup (roadmap 1.10b) | Reviewed |
| [0015](0015-cli-clipboard/PLAN.md) | CLI clipboard: direct X11 adapter and protected transport (roadmap 1.10c) | Reviewed |
| [0016](0016-attachments/PLAN.md) | Streaming attachments and CLI file operations (roadmap 1.11) | Reviewed |
| [0017](0017-entry-history/PLAN.md) | Entry history, restore and purge (roadmap 1.12) | Reviewed |
| [0018](0018-archives-snapshots-verify/PLAN.md) | Archives, local snapshots and `verify` (roadmap 1.13a) | Implemented |
