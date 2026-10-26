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
| [0008](0008-vault-file-sqlite/PLAN.md) | Vault file: hardened SQLite, schema, header and keyslots, `qv-store` (roadmap 1.6) | Implemented |
