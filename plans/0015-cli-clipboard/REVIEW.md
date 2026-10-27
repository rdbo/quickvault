# Review — Plan 0015: CLI clipboard

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-27 | Clipboard-scoped changes in `981c39d..6721feb`; clean starting tree |

## Summary

The private X11 owner implements the approved clipboard scope, with vault
sessions dropped before serving, protected outgoing transport storage, bounded
incoming traffic and ownership-safe window destruction. Independent gates and
private-Xvfb tests pass. No blocking finding or code fix; these checks do not
establish security or production platform validation.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Narrow vendor exception and checker rejection fixtures |
| 2 | yes | Archive identity, exact source differences and transport tests checked |
| 3 | yes | Local Unix transport; cancellation/deadlines, INCR and transfer limits |
| 4 | yes | Copy modes, preflight, default/named fields and destruction scopes |
| 5 | yes | Production binary exercised against private Xvfb |
| 6 | yes | Documentation and independent final gates |

Reviewed the adapter, Stream, command integration, config/flags, tests, CI,
dependency/policy changes and vendor conventions. The commit also contains
previously reviewed phases 1.9/1.10b; those are not newly approved by this review.
No out-of-scope clipboard change found.

## Findings

None requiring correction or escalation.

The borrowed ChangeProperty path retains payload slices through request
serialization, vectored-write slice advancement and DefaultStream sendmsg.
The maintained protected ring handles the library-owned outgoing copy;
consumption/error paths wipe storage and drop uses SecretBytes cleanup.
The header guard precedes the protocol reader's resize, and the Stream's
independent lifetime budget bounds eager packet accumulation. Setup validates
the requested screen before the adapter indexes it. Request/event filtering,
transfer cap/idle expiry, deadline cancellation and window-only cleanup were
checked against the plan. No unconditional clearing or manager handover exists.

Downloaded the versioned archive to `/tmp/qv16-review/x11rb.crate` and verified
SHA-256 `9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414`.
Byte comparison of non-license upstream files confirms exactly the documented
source changes: Cargo.toml, packet_reader.rs and write_buffer.rs. Cargo.lock is
the documented local test lockfile; registry VCS metadata is omitted.
License contents were not read. Provenance checks are not dependency audits.

## Fixes applied by reviewer

None. Only review/status documentation changed.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `sh scripts/test-check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 474 passed, 2 ignored, 0 failed, including doctests |
| `cargo deny --locked --config /tmp/qv16-deny.toml check` | pass: advisories, bans, licenses, sources |
| `cargo vet --locked` | pass: 27 fully audited, 6 partially audited, 79 exempted |
| Locked vendor `--lib rust_connection` tests | pass: 12, including memory-limited hostile-length child |
| rustfmt of both patched vendor Rust files | pass |

Complete outputs: `/tmp/qv16-review-{spdx,checker,fmt,clippy,test,deny,vet,vendor,vendor-fmt}.log`.
Deny 0.20.2 and vet 0.10.3 were installed under `/tmp/qv16-tools`.
The temporary deny config changes only the advisory database location; vet uses
`XDG_CACHE_HOME=/tmp/qv16-cache`. Policies/assertions were not weakened.
Xvfb and runtime packages were fetched/extracted under `/tmp/qv16-xvfb`, without
system installation. The full test command used
`QV_TEST_XVFB=/tmp/qv16-xvfb/usr/bin/Xvfb LD_LIBRARY_PATH=/tmp/qv16-xvfb/usr/lib`.
All three clipboard integration tests passed; no user display/clipboard access.

Network namespace isolation is still unavailable: `unshare -rn true` exits 1
with “No space left on device” (`/tmp/qv16-review-netns.log`). The ordinary
offline flow passes; the blocked-network scenario is unavailable, not validated.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md private adapter and maintained dependency
- [x] Spec statuses unchanged; no normative amendment in this phase
- [x] Plan, execution log and index updated to Reviewed

## Escalations for the owner

None. Native Wayland/other OS backends, recipient/manager erasure, actual-platform
release evidence and unavailable namespace isolation remain recorded limitations.
