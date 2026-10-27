# Review — Plan 0016: Attachments

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved after owner-requested remediation | 2026-10-27 | `git diff HEAD^ HEAD` at `b42c5ed`, plus uncommitted remediation |

## Summary

Initial fresh-context review found non-constant-time confidential content-hash
comparisons and blocked Rust tooling. Both findings are now resolved by the
owner-requested remediation, and the resumed review's required gates pass.
The attachment phase is approved; no product code was changed in the reviewer
role. Approval is not a security proof or a new-session audit of the fix.

## Remediation and resumed review (2026-10-27)

The owner explicitly requested fixing both findings, finishing review and
starting the next phase without an intervening commit. The architect revised
plan 0016 and the developer added `SecretArray::ct_eq`, delegating to pinned
ctutils CtEq on fixed-length slices. Both confidential digest call sites now
use it. The helper tests every differing byte; store tests reject first,
middle and final-byte mismatches while retaining rollback/integrity assertions.
The resumed reviewer inspected this diff and the complete attachment paths;
no reviewer product edits were made. This is a continued fresh-context review,
not a claim that the newly written fix received a new-session independent audit.

Missing Cargo/Clippy components were removed/re-added with rustup's component
manager; Cargo and rustc now report 1.98.1. No MSRV or dependency changes.
Developer final gates pass (490 passed, 2 ignored). Reviewer SPDX, fmt, Clippy
and separate full workspace test reruns pass (490 passed, 0 failed, 2 ignored,
including doctests and all three private-Xvfb clipboard integration tests).
Production offline tests pass (3), including a blocked network namespace;
`unshare -rn cargo test --locked -p qv-cli --test attachments` also passes (2),
including the real 10 MiB add/list/save/remove flow. No personal display,
clipboard or phone access. Tests do not establish security proof.

## Plan conformance

The implementation includes the approved CLI amendment, fixed chunk framing,
streaming store/core operations, safe explicit-file helpers and cross-layer tests.
Reviewed the new attachment modules, crypto/model changes, transaction staging,
core commit/session changes, CLI dispatch and attachment tests against the plan
and relevant 0003 §6, 0004 §3–5, 0008 §1–2/§5 and 0011 attachment requirements.
Completion of all claimed acceptance evidence is not independently established;
the gates below could not execute. No approval is inferred from developer logs.

## Initial findings (resolved)

1. **[medium] Confidential content hashes use ordinary equality** —
   `crates/qv-store/src/attachment.rs:146` and
   `crates/qv-store/src/write.rs:370`.
   Complete-content verification compares the calculated plaintext SHA-256 with
   confidential metadata using ordinary array equality. Staging validation also
   compares the same confidential digest using ordinary equality. These
   comparisons do not provide the constant-time contract required by 0008 §2;
   the phase itself correctly treats this digest as confidential elsewhere.
   Use a reviewed constant-time comparison path for both checks, preserving
   existing mismatch errors and rollback behavior. Retain wrong-hash rejection
   tests and exercise mismatches at multiple digest positions. This is a
   requirement violation, not a demonstrated practical timing exploit.
   **Action: escalated, then fixed under the owner-authorized architect/developer
   remediation above; reviewed and resolved.**

2. **[blocking verification] Pinned Rust toolchain cannot run Cargo** —
   `rust-toolchain.toml:2`.
   Initial `cargo fmt --check` attempted toolchain installation and failed with
   a `bin/cargo` component conflict. Subsequent fmt, Clippy and test attempts
   report that the Cargo binary is not applicable to
   `1.98.1-x86_64-unknown-linux-musl`. This is an environment blocker, not a
   source-code test failure. Restore the pinned toolchain without changing MSRV
   or substituting a different compiler, then rerun all required gates and the
   remaining review. **Resolved with rustup-managed component reinstall and
   successful pinned-toolchain gates.**

## Fixes applied by reviewer

None. Only review/handoff documentation changed.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | Pass |
| `cargo fmt --check` | Pass after toolchain repair |
| `cargo clippy --all-targets --locked -- -D warnings` | Pass after toolchain repair |
| `cargo test --locked` | Pass; 490 passed, 0 failed, 2 ignored |
| `cargo deny check` / `cargo vet --locked` | Not required by this phase: no dependency or lockfile changes |

Initial failures remain in `/tmp/opencode/qv17-review/{spdx,fmt,fmt-retry,clippy,test}.log`.
Successful resumed reviewer outputs are `reviewer-{spdx,fmt,clippy,test}.log` in
the same directory; focused offline/attachment runs have separate reviewer logs.
Xvfb path: `/tmp/opencode/qv17-review/xvfb/usr/bin/Xvfb`, with its extracted
`usr/lib` in LD_LIBRARY_PATH; packages are disposable test tooling, not product
dependencies. Historical phase test passes were not reused as current evidence.

## Documentation

The committed phase includes CHANGELOG, architecture, normative CLI amendment
and plan/roadmap records. No spec status was promoted to Implemented. The plan
and index are now Reviewed; remediation also has a CHANGELOG entry.

## Escalations for the owner

None outstanding for this review. Original findings are retained above as the
audit trail. Source same-size concurrent edits and export crash leftovers remain
explicitly documented limits, not erasure/atomic-completion promises. No commit,
push or branch; owner explicitly authorized starting phase 1.12 in this session
after remediation/review, without the intervening phase commit.
