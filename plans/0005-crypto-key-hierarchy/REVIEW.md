# Review — Plan 0005: Crypto profiles, symmetric primitives and key hierarchy

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-25 | commit `29c8581` ("phase 1.3") |

## Summary

`qv-crypto` now has the symmetric half of spec 0002, as planned: the profile
registry, password-kdf/1 with NFC, the KEK with its constant-time commitment,
password slots, the nine purpose-typed keys, record and attachment keys,
stored-data/1 with canonical Padmé framing, MAC/1, object-hash/1 and
`CryptoError`. Labels, salts and AAD/info arrays match 0002 §3.1–3.3 and §3.6
exactly, and are cross-checked by an independent stdlib script plus OpenSSL's
Argon2id. The logged deviations are justified and some make the work stronger
than planned: Python is the vector source, OpenSSL computes the Argon2 vector,
and `mac` returns `Result`. One real secret-handling gap was found and fixed:
the sealed key-use traits let any other crate read raw key bytes.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | Pins as planned; 19 vet exemptions recorded honestly; `Unicode-3.0` approved by the owner |
| 2 | yes | Upstream vectors carry source lines; XChaCha §A.3.1 and RFC 9106 §5.3 tags checked against the published values |
| 3 | yes | Padmé formula correct; framing checks happen after authentication; budget checked before allocation (proved with a tag-invalid input) |
| 4 | yes | Typed purposes; compile-fail doctests each have a passing twin. Gap: see finding 1 |
| 5 | yes | Exact V1 parameters; own Argon2 memory wiped on every path; exhaustive NFC 3× bound; 0.48 s full-profile test |
| 6 | yes | Order KEK → commitment (constant time) → wrap key → AEAD; the partitioning test shows the AEAD alone would open under B |
| 7 | yes | `crosscheck.py` exits 0 here (re-run by the reviewer) |
| 8 | yes | Crate docs, CHANGELOG, ARCHITECTURE §3, AGENTS current state, roadmap tick and log |

Out-of-scope changes: the `memory.rs` test lock became a crate-wide
`#[cfg(test)]` `RwLock` (test-only, logged and justified). The CI
`cargo fetch --locked` step for `fuzz/` belongs to the plan 0004 review fix,
committed with this phase.

## Findings

1. **[medium] Sealed key-use traits exposed raw key bytes to other crates** —
   `crates/qv-crypto/src/keys.rs:100-123`
   `AeadKey: sealed::AeadKeyBytes` and `MacKey: sealed::MacKeyBytes` had
   methods `aead_key(&self)` / `mac_key(&self) -> &[u8; 32]`. The module was
   `pub(crate)`, so the traits could not be named, but the methods were still
   callable through a generic bound. A reviewer probe outside the crate,
   `fn leak<K: qv_crypto::AeadKey>(k: &K) -> [u8; 32] { *k.aead_key() }`,
   compiled and printed the bytes of a manifest key. The `MacKey` version did
   the same for a header-MAC key. That bypasses the `expose_secret*` access
   rule (`AGENTS.md`) and lets callers copy keys into unprotected memory
   (0008 §1.1). It is not exploitable by an outside attacker; it is an API
   hole in the trusted client.
   Fix: both methods now take a `sealed::Token`. It is a zero-sized type with
   a private field, and only the crate-private `TOKEN` const can build it, so
   no other crate can obtain one in safe code. Two `compile_fail` doctests
   (AEAD and MAC) with a passing twin pin this. The probe now fails with
   E0061. No format, label or behaviour change.
   Action: fixed by the reviewer and highlighted here (secret-handling code).
2. **[low] VK copied through a possible stack temporary in `wrap_vk`** —
   `crates/qv-crypto/src/slot.rs:80`
   `*b = *vk.expose_secret()` copied the array by value. It is now
   `b.copy_from_slice(vk.expose_secret())`, the same form as `open_with_kek`.
   Action: fixed by the reviewer.
3. **[low] No upper bound on the master-password length** —
   `crates/qv-crypto/src/password.rs` (`MasterPassword::from_utf8`)
   It allocates `3 × len` of locked memory. That fails safely (memory locking
   reports reduced protection and multiplication overflow is
   `LimitExceeded`), but huge input means a huge allocation. The frontends
   bound their input (0011 §3 TTY reading), and phase 1.10 should set the
   limit. Not a defect in this phase.
   Action: noted for 1.10.
4. **[note] stored-data AAD is the caller's job** — `stored_data.rs`
   `seal`/`open` take the profile but do not add it to the AAD. 0002 §7.2
   requires the profiles, vault, generation and IDs in every AAD. Phase 1.7
   builds the record, chunk and manifest AAD and must include
   `stored_data_profile` there. This is in the plan's scope split.
   Action: noted for 1.7.

The plan's own notes for later phases still apply: the local-state key is
specified for both AEAD and MAC (owner's call before 1.7); the Padmé ceiling
under the 1 MiB budget is 1 MiB − 16 KiB − 4 bytes; Argon2 lanes run
sequentially (1.9/1.16); the new RustCrypto majors have no imported audits.

## Fixes applied by reviewer

- `crates/qv-crypto/src/keys.rs` — `sealed::Token`/`TOKEN`; the
  `aead_key`/`mac_key` accessors take the token; three new doctests (two
  `compile_fail`, one positive). Minor because it changes no format, label or
  primitive, the plan sketch never meant the accessors to be public, and no
  crate depends on them yet.
- `crates/qv-crypto/src/stored_data.rs` — call sites pass `TOKEN`.
- `crates/qv-crypto/src/slot.rs:80` — `copy_from_slice` instead of an array copy by value.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass: 140 passed, 0 failed, 1 ignored (the stored-data vector generator) |
| `cargo deny check` (deps changed) | pass (advisories, bans, licenses, sources ok) |
| `cargo vet --locked` | pass (12 fully audited, 33 exempted) |
| `python3 -I crates/qv-crypto/tests/vectors/crosscheck.py` | pass (4 files ok) |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 "Implemented so far")
- [x] Spec statuses and Changelogs (no change; 0002 stays Accepted, not fully implemented)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None blocking. Finding 1 was a secret-handling issue and is highlighted
above even though it is fixed.
