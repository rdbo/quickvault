# Review — Plan 0036: Protocol foundation and X-Wing (roadmap 2.8)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-11-02 | `bfdcfdf` (owner commit titled "phase 2.9"; it holds the phase 2.8 work) against `87f1267` |

## Summary

Phase 2.8 delivers what the plan describes:
- the key-free `qv-protocol` crate (bounded frames, label/arity registry,
  exact-shape reader/writer, profile/feature/error registry);
- X-Wing draft-11 through `libcrux-kem` 0.0.10 behind a small wrapper in
  `qv-crypto`;
- the 0013 §6 record layer;
- the `lan_message` fuzz target.

The code is small and careful. Bounds come before allocation and errors carry
no data. Secrets live in locked containers, and the libcrux erasure limits are
documented. The deviations (hybrid signature deferred to 3.3, the
`deny.toml` entries for never-compiled tooling, typed array readers) are logged
in the plan and the roadmap. One low finding, fixed: oversized frames were
mapped to a wire error code although 0013 §1.3 says the connection just closes.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 Dependency and skeletons | yes | `libcrux-kem =0.0.10` (std only); deny entries scoped by version with reasons; 36 vet exemptions labelled as audit debt |
| 2 X-Wing wrapper and vectors | yes | All three draft-11 vectors pass through the production wrapper, which also confirms the derand seed order. Covered: wrong lengths and missing halves, the coefficient ≥ q key check, implicit rejection, low-order X25519 and redaction |
| 3 Record layer | yes | Nonce/AAD rebuilt from the spec text in the test; replay, reorder, gap, tamper, truncation and wrong key all poison; 2³² limit |
| 4 qv-protocol | yes | Interface revisions (`Label::parse`, typed array readers) logged; no-allocation oversize check; proptest no-panic |
| 5 Fuzz and CI | yes | Target registered in `ci.yml` and `fuzz-extended.yml`; fuzz lockfile only gained packages |
| 6 Documentation | yes | ARCHITECTURE §3/§6, CHANGELOG, roadmap Revision/tick/log, index |

Out-of-scope changes: the same commit carries the 0034/0035 review fixes
(Android autofill handoff, empty fields, 0009 §4.4 lifetimes, a qv-store
Android cast). Those were reviewed in the 0034/0035 reviews and are not
re-reviewed here.

## Findings

1. **[low] Oversized frames mapped to a wire error** —
   `crates/qv-protocol/src/error.rs:36`.
   `ProtocolError::wire_code` returned `Some(Protocol)` for `FrameTooLarge`.
   0013 §1.3 says a larger length "closes the connection before any
   allocation", so an authenticated caller following the mapping would have
   sent an error record first. Nothing calls it yet (2.9 is the first caller).
   Action: fixed by reviewer (`FrameTooLarge` → `None`, with a test assertion).

Checked and fine:
- **X-Wing:**
  - every libcrux error is `Integrity`, wrong lengths are `LimitExceeded`,
    and nothing is partially returned;
  - the private-key seed copy is wiped on every path, including decapsulation
    failure;
  - `Ss::encode` output is wiped.
- **Record layer:**
  - the sequence number advances only on success;
  - a failed seal wipes the buffer;
  - the opener checks the length before `SecretBytes::try_init`, and
    plaintext comes back only in locked memory.
- **Frames:**
  - the header loop never reads past 4 bytes and the body uses `read_exact`
    (no read-ahead);
  - `try_reserve_exact` runs only after the bound check;
  - `buf` is cleared on every error.
- **Messages:**
  - `Decoder::new` validates the whole canonical input before any typed read;
  - arity is checked after the label;
  - `body_without_last` re-encodes validated raw items, which is exact for
    canonical CBOR.
- **Debug output:** no secret-bearing `Debug` impls, and no
  `unwrap`/`expect` outside tests.

## Fixes applied by reviewer

- `crates/qv-protocol/src/error.rs:33`: `FrameTooLarge` has no wire code
  (0013 §1.3). Local API semantics with no caller yet, and the spec states the
  exact behaviour.
- `crates/qv-protocol/src/registry.rs:121`: test asserts the new mapping.

## Gates

Run on the committed tree `bfdcfdf` (the tree was clean), then the focused
checks again after the fix:

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh`, `sh scripts/check-matrix.sh` | pass |
| `cargo fmt --check` | pass (also after the fix) |
| `cargo clippy --all-targets --locked -- -D warnings` | pass; after the fix `-p qv-protocol` passes |
| `cargo test --locked` | 781 passed, 0 failed, 2 ignored (private Xvfb from the sandbox notes). After the fix, `-p qv-protocol` passes 12/12 |
| `cargo deny check` | pass (advisories, bans, licenses, sources) |
| `cargo vet --locked` | pass (94 fully audited, 11 partially, 457 exempted) |

The first test run without Xvfb failed only the two isolated X11 clipboard
tests, which require it by design. The rerun with the private Xvfb passed. The
full workspace gates are repeated on the final phase 2.9 tree; see plan 0037.

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 rows, §6 LAN row)
- [x] Spec statuses and Changelogs: no spec change (0013 stays Accepted, not
  Implemented)
- [x] Plan ticks, execution log, plans/README.md row (updated to Reviewed)

## Escalations for the owner

None. Standing items, unchanged by this review:
- **D12 (independent protocol review)** remains pending and blocks only the
  2.11 release evidence.
- **libcrux has no independent audit** of the composition crate, and its
  intermediates are not zeroized. Both are documented; no audit is claimed.
