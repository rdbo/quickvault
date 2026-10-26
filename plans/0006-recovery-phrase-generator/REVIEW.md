# Review — Plan 0006: Recovery phrase and password generator

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-26 | commit `74048a7` ("phase 1.4"), phase 1.4 files |

## Summary

`qv-crypto` now has the 0002 §4.1 recovery phrase (VK ↔ 24 BIP-39 English
words, entropy encoding only) and the 0010 generator (characters, passphrase,
PIN), both following the plan's design. The phrase decoder scans all 2,048
entries per word with `ctutils` and branches once on "all found and checksum
valid". The generator validates every setting before touching the RNG, uses
correct rejection sampling (`min = 2^32 mod n`), regenerates whole passwords
for `require_each_class` and computes exact entropy by inclusion–exclusion.
The tests are real: exact error variants, zero-RNG-use proofs, the exact
10,000-attempt bound, deterministic chi-square tests with a working
modulo-bias control. The only fix was a formatting nit.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | `sha256sum` of both data files matches the pinned and published hashes (re-run by the reviewer); strict parsers; `.gitattributes` deviation logged and sound |
| 2 | yes | `ctutils` instead of `subtle` (owner decision B, recorded under *Revisions*). The vector file matches Trezor `vectors.json` exactly (all eight 256-bit English entries; re-checked by the reviewer against a fresh download) |
| 3 | yes | Validation order and variants as planned; separator forbidden set derived from the embedded list |
| 4 | yes | `RandomSource` is crate-private, test RNGs only under `#[cfg(test)]` (0010 §1.3) |
| 5 | yes | Chi-square at z = 5, fixed seeds; the control rejects `byte % 94`; the developer's mutation check is logged |
| 6 | yes | Crate docs, CHANGELOG, ARCHITECTURE §3, AGENTS, roadmap tick/log/revisions |

Out-of-scope changes: the same commit also carries the plan 0005 review fix
(`keys.rs` access token, `stored_data.rs`, `slot.rs`), already recorded in
plan 0005's REVIEW.md. `.gitattributes` is new (logged in step 1).

## Findings

No correctness, spec or security defects found. Checked in particular:

- 11-bit packing: 24 × 11 = 264 bits; `group(23)` reads bytes 31..34 of the
  35-byte buffer with shift 8; the checksum is byte 32 and the two padding
  bytes stay zero (tested).
- Phrase input: no allocation; more than 24 words fail at the 25th slot;
  every failure is `WrongPhrase`; all secret buffers are `SecretArray` or
  `Zeroizing` and wiped on every path.
- 0010 §2.2.3: the output is injective (separator absent from all output
  words, digit only at a word end, capitalization of lowercase words), so the
  `w·log2 7776 + log2(10w)` formula is exact.
- `char_entropy` cannot reach a non-positive fraction for valid settings
  (the minimum length is 8, at most 4 classes).
- Strength boundaries on real numbers (`< 50`, `< 70`, `< 90`) are the plan's
  stated reading of the 0010 §3.3 integer table, not a silent decision.

Known limitations, documented in the plan's log and the crate docs, and
consistent with 0001's scope: generator table lookups are secret-indexed;
joining phrase words of different lengths is not constant time.

## Fixes applied by reviewer

- `CHANGELOG.md:30` — added the missing blank line between the plan 0005
  review-fix entry and the next entry, like the rest of the list.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (182 passed, 1 ignored: the plan 0005 vector generator) |
| `cargo deny check` (if deps changed) | not re-run: no package added to `Cargo.lock` (only the `qv-crypto → ctutils` edge); the developer's run is logged |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 "Implemented so far")
- [x] Spec statuses and Changelogs (no change; 0002 and 0010 stay Accepted, not fully implemented)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None. Carried forward (already in the plan's log): qv-core (1.8) re-exports
the phrase and generator API and stores generator defaults; `zxcvbn`
(0010 §3.2/§4.2) needs owner approval in phase 1.10.
