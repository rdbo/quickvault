# Review — Plan 0021: Rotation journal and open safeguards (roadmap 1.15a)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-29 | `git show 9c25a6a` (parent `acc1021`) |

## Summary

Fresh-context review of committed phase 1.15a. Checked the bounded journal
codec, its canonical MAC transcript and independent old/new local-state MACs,
the `.qvrotate` marker guard and where it is placed on open, unlock, create,
restore, read and write paths, the rejection and race tests, the independent
Python vector, the fuzz target and CI wiring, and the narrow 0002 §3.5.1
amendment. The code matches the revised 1.15a scope and does not go beyond it:
nothing in production writes a marker, and no API installs a replacement or
adopts an anchor. No defects found. Required gates pass.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 — D1/spec amendment | yes | Amendment text matches D1 A word for word; 0002 Changelog and specs index updated. |
| 2 — Journal codec/MACs | yes | 4096-byte cap is checked before decoding; strict canonical map 0–14; fixed lengths; UUIDv4 checks; checked +1 increments; `verify_mac` is constant-time; Debug is redacted. |
| 3 — Guards | yes | `lstat` without following, before and after the inode lock and before `open_connection`; identity is rechecked before SQLite; `check_identity` covers `begin_read`, `BEGIN IMMEDIATE`, pre-COMMIT, pending-anchor retry, attachments, phrase display; create/restore check before input/anchor/publish. |
| 4 — Fuzzing | yes | Fuzz target and CI step present. Fuzz fmt and locked build pass here; the 60 s campaign was not repeated (developer log: 179,938 runs, clean, no ASan). |
| 5 — Docs/gates | yes | CHANGELOG, ARCHITECTURE §3/§7, roadmap split, index. |

Out-of-scope changes: none. The commit also contains the 0020 review record
from the previous session; it is documentation only.

## Findings

None that block approval. Design notes for the 1.15b architect, not defects
in 1.15a:

1. **Marker-blocked identity checks also block the installer's own session.**
   `VaultFile::check_identity` (`crates/qv-store/src/vault.rs:481`) now refuses
   whenever the marker exists. 1.15b must therefore finish every read from the
   source through ordinary APIs before it publishes the journal, or use a
   dedicated internal path that is bound to the journal. It must not weaken
   the guard.
2. **The marker is a sibling of the path, so hard-link aliases do not see it.**
   `open_existing` does not check the link count. During installation the
   per-inode lock serializes aliases. After the anchor advances, an alias of
   the old inode fails the anchor comparison. 1.15b should keep holding both
   inode locks until the anchor is durable, as its design already says, and
   test an alias of the old inode after the transition.

## Fixes applied by reviewer

None.

## Gates

Run on the clean committed tree `9c25a6a`. Logs are in the session scratchpad
`r21/`.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass with private Xvfb (Alpine package extracted into scratchpad, `QV_TEST_XVFB`): 603 passed, 0 failed, 2 pre-existing ignored, 34 groups |
| `python3 -I crates/qv-store/tests/vectors/rotation_journal.py` | pass |
| `cargo fmt --check --manifest-path fuzz/Cargo.toml`; locked fuzz build | pass |
| `cargo deny check`, `cargo vet --locked` | not required; no dependency inputs changed |

`unshare -rn true` fails with `No space left on device`, so network-isolated
runs were not available and are not counted as a pass. This review makes no
security-proof, audit or rotation-completion claim.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 rotation foundation, §7 split)
- [x] Spec statuses and Changelogs (0002 stays Accepted; amendment logged)
- [x] Plan ticks, execution log, plans/README.md row (now Reviewed)

## Escalations for the owner

None.
