# Review — Plan 0037: LAN pairing, link storage and new-device initialization (roadmap 2.9)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-11-03 | `bfdcfdf..1d8e470` (owner commits `d6e4017` "phase 2.9", `5ca6f64` "no remembering without identity", `1d8e470` "update") |

## Summary

Phase 2.9 delivers what the plan describes:
- the 0013 §4 pairing key schedule in `qv-crypto::lan`;
- typed pairing and exchange codecs plus the out-of-band QR and manual code
  in `qv-protocol`;
- head-bound `lan_link` storage (format `0x7FFF0004`) and new-device staging
  and creation through the 1.13b restore path in `qv-store`;
- the pairing window and both joiner modes over TCP in `qv-sync::lan`;
- the core API.

Every label and derivation matches 0013 §4.1–4.8 as written. Comparisons
are constant time, and the hello checks run in the §4.3 order. Nothing is
sent before the hello MAC, and nothing is decapsulated before the accept
MAC. Peer bytes reach SQLite only after the full archive authentication. The
hint removal (owner decision 2026-11-03) is applied consistently across
code, 0004 and 0013.

One low finding was fixed: `Core::join_new_device` skipped the platform and
anchor-location guards that `Core::create` applies. The remaining findings
are low-severity hardening and UX items for phase 2.10, which reuses this
exchange code.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 Spec clarifications | yes | 0013 §1.3/§7.1/§8.3 and 0004 §2.4 with Changelog lines; statuses unchanged (Accepted). The 2026-11-03 hint removal is in both specs and the index note |
| 2 qv-crypto key schedule | yes | Labels, IKM order (`ss ‖ P`, `K_lan ‖ ss`), salts and info arrays checked against §4. No new public `RecordKey` constructor. `test-vectors` is enabled only through qv-sync's dev-dependencies |
| 3 qv-protocol | yes | Exact shapes, generation `1..=u32::MAX`, bounded arrays; base32 decode enforces 26 symbols and zero pad bits. `ErrorMsg::peek` replaces `Received::decode` (logged) |
| 4 qv-store link state | yes | Shape checks before values, the digest bound to head key 8, re-read in `Write` begin, crash point `LanLinksWritten`; empty digest on create, restore and rotation |
| 5 Staging and creation | yes | Envelope bounded, hashed, then authenticated; per-object reference checks before writing; `read_archive` on finish; the proof must equal the staged slot body; the conflicted-keyslot test moved to core (logged) |
| 6 qv-sync | yes | 15 `lan_enroll_*` tests. The plan's "missing object row on A → `state_changed`" case has no test (finding 5) |
| 7 qv-core | yes | Non-Linux stubs dropped (logged, nothing builds there before milestone 4). Reviewer fix below |
| 8 Vectors | yes | Rust regeneration test and `crosscheck_lan.py` (OK, rerun here) |
| 9 Fuzz and CI | yes | `lan_oob` added to `ci.yml` and `fuzz-extended.yml`; `lan_message` runs the typed decoders |
| 10 Documentation | yes | ARCHITECTURE §3/§6, CHANGELOG (format bump stated), roadmap, index |

Out-of-scope changes: none. Commit `bfdcfdf`'s change of the 0036
`FrameTooLarge` wire mapping belongs to the 0036 review and is recorded
there.

## Findings

1. **[low] New-device join skipped the creation guards** —
   `crates/qv-core/src/lan.rs:527`.
   `Core::create` checks `platform_gate()` (unacknowledged reduced hardening)
   and `check_anchor_location()` before creating a vault, but
   `join_new_device` did neither. Two consequences:
   - a destination inside the anchor directory was created and anchored,
     and then the final `unlock` failed with `AnchorLocation`, leaving a
     vault where `create` refuses to put one;
   - with reduced hardening and no acknowledgement, VK was received before
     the gate refused the unlock.

   Action: fixed by the reviewer. Both guards now run before any network
   activity, with a test.
2. **[low] An authenticated joiner can keep the serving loop open
   indefinitely** — `crates/qv-sync/src/lan/exchange.rs:85`.
   A's `Want` loop accepts any number of empty `Want(last = false)`
   messages. Each one only resets the 60 s idle limit, and the window's time
   limit no longer applies after the grant. Only a peer that knows `P` and
   whose code the user confirmed can do this, and cancel or lock still ends
   it. Phase 2.10 reuses this loop for the general exchange. It should bound
   the number of `Want` messages (for example, refuse an empty non-final
   `Want`, or cap the count at ⌈250,000 / 4,096⌉ + 1). The cap would be a
   0013 §7.4 clarification. Action: carried to 2.10.
3. **[low] A ignores the outcome in B's `Done`** —
   `crates/qv-sync/src/lan/exchange.rs:109`. §10 step 3 says B sends
   outcome 1. A checks the hash but accepts any outcome. This is harmless
   for pairing, but the general exchange in 2.10 should validate it.
   Action: carried to 2.10.
4. **[low] The grant is sent while the session mutex is held** —
   `crates/qv-core/src/lan.rs:444`. `SessionApprover::grant` seals and
   sends the record inside `session.read`. The send is a single small
   record, bounded by the 10 s message limit. Still, the module docs say the
   mutex is never held while waiting on the network. 2.10 can seal inside
   the read and send after it. Action: carried to 2.10.
5. **[low] Test gap: a missing object row maps to `state_changed`** —
   `crates/qv-core/src/lan.rs:460`. Step 6 planned this test. The store test
   covers `NotFound` from `lan_object_envelope`, but the core mapping to
   `StateChanged` and the wire code are untested. Action: carried to 2.10
   (exchange tests).
6. **[low] Connection attempts cannot be cancelled promptly** —
   `crates/qv-sync/src/lan/joiner.rs:161`. `TcpStream::connect_timeout`
   blocks for up to the 10 s connect limit per candidate before
   cancellation is checked. Decision 5's "about 100 ms" holds for reads and
   writes only. Action: carried to 2.10, which adds initiation with up to 16
   candidates.
7. **[info, for D12] Second-hello detection during the checking phase** —
   `crates/qv-sync/src/lan/approver.rs:274`. While the first connection's
   hello is still being read (up to 10 s), other connections close unread,
   as 0013 §8.3 requires. An observer of the code whose hello lands first
   can therefore get the real joiner dropped without triggering
   `CodeObserved`. The SAS comparison stays the protection: the real joiner
   shows an error, not a code. This is spec-conformant; it is noted for the
   D12 protocol reviewer.
8. **[info] A new-device destination that already exists is reported late.**
   `create_from_lan` returns `Exists` only after the transfer and the
   password prompt. The 2.10 CLI and app should check the destination
   before pairing.

## Fixes applied by reviewer

- `crates/qv-core/src/lan.rs:527` — `join_new_device` runs `platform_gate()`
  and `check_anchor_location(destination)` first, as `create` does.
  `check_anchor_location` became `pub(crate)` (`crates/qv-core/src/setup.rs:227`).
  This is a local fix with the intent stated by `create`. It changes no
  format, protocol or public API.
- `crates/qv-core/src/lan_tests.rs` —
  `lan_core_new_device_refuses_an_anchor_directory_destination_before_pairing`:
  `AnchorLocation`, nothing at the destination, and the endpoint never
  contacted. Without the fix the call reaches the network and fails
  differently.

## Gates

Run on the reviewed tree (the commits above plus the reviewer fix), private
Xvfb.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 830 passed, 0 failed, 2 ignored (pre-existing) |
| `python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py` | OK |
| `cargo deny check` / `cargo vet --locked` | not rerun: the lockfile change in `bfdcfdf..1d8e470` is only the `qv-sync` → `qv-protocol`/`zeroize` edges between existing packages; no package was added or changed |

Before the fix, the committed tree `1d8e470` passed every gate above:
`cargo test --locked` gave 829 passed, 0 failed, 2 ignored (pre-existing).

## Documentation

- [x] CHANGELOG.md (2.9 entry, format bump, hint removal)
- [x] ARCHITECTURE.md (§3 rows, 2.9 paragraph, §6 LAN row)
- [x] Spec statuses and Changelogs (0013, 0004 Accepted; Changelog lines present)
- [x] Plan ticks, execution log, plans/README.md row (updated by this review)

## Escalations for the owner

None. Findings 2–6 are carried into phase 2.10's plan. Finding 7 is a note
for the D12 reviewer, not a defect.
