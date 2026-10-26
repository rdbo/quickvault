# Review — Plan 0007: Data model, version vectors and merge

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-10-26 | commit `ee48464` ("phase 1.5") |

## Summary

The new crate `qv-model` matches the plan: IDs, text and secret types, clocks,
the record envelope and all five payload kinds with the development registry,
the maximal-version merge with representatives and status, history floors, the
group-tree projection and TOTP. `qv-crypto` gains `hotp`, and there is a new
`record_decode` fuzz target. The code is small, strict and bounded. The merge
argument (descending counter sum, heads only grow) holds, and the property
tests check it against a brute-force maximal set. I found one low-severity
gap: the claim that the model never writes what it would reject does not hold
for IDs. It is not blocking, and I recorded it for phase 1.6/1.7.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 | yes | IDs, `Text`/`SecretText`/`FieldValue`/`Extensions`, errors; compile-fail doctests |
| 2 | yes | `Clock`, `Causality`, `join`, `for_edit`, wire form; proptests |
| 3 | yes | Envelope, vault meta, settings, keyslot; key 5 decoded with the kind from key 0 (sorted first) |
| 4 | yes | Group, entry/field, attachment; mutation/arbitrary-input proptests |
| 5 | yes | `merge`, `merge_record`, `Merged`, `HistoryFloor` |
| 6 | yes | Honest-history generator, brute-force oracle, the four scenarios |
| 7 | yes | Iterative projection; 50,000-deep chain and 50,000-cycle tests |
| 8 | yes | `hotp`, RFC 4226/6238 vectors parsed from fetched RFC texts; `sha1` exempted in vet |
| 9 | yes | Fuzz target and CI step |
| 10 | yes | Docs and gates |

Out-of-scope changes: none. Deviations logged: the RFC 6238 errata citation
was dropped (no erratum number verified), which is honest and fine.

## Findings

1. **[low] The v4 invariant does not hold for the four IDs from `qv-crypto`,
   so `encode` can write a record that `decode` rejects.**
   `crates/qv-model/src/ids.rs:7` (docs: "That is a type invariant") and
   `crates/qv-crypto/src/ids.rs:12-24` (`VaultId`, `SlotId`, `RecordId`,
   `AttachmentId` have `pub [u8; 16]` fields). Any caller can build
   `RecordId([0; 16])`. `put_id` (`crates/qv-model/src/codec.rs:94`) writes it,
   while `read_id` rejects it as `Malformed`. A group `parent`, an entry
   `group`, `root_group`, an attachment `entry` or a keyslot `slot_id` built
   this way encodes fine, but after a write the version cannot be read back.
   This contradicts the plan's "`encode` applies the same budgets and fails
   with the same variants" and 0003 §1.1's intent. The model's own four ID
   types are not affected (private fields). Nothing builds these IDs outside
   tests yet. Two fixes are possible, and choosing between them is a design
   choice, so I did not apply either: (a) make the `qv-crypto` ID fields
   private with a validated constructor (a qv-crypto API change), or (b) have
   `RecordVersion::check` validate every embedded crypto ID on encode.
   Recommendation: (b) in phase 1.6 or 1.7, the first phase that builds vault,
   slot and record IDs from storage, plus a test where a non-v4 `RecordId`
   fails `encode`.
   Action: escalated as non-blocking; carried forward to the 1.6 plan.

2. **[info] Readings to confirm when consumers arrive.** The developer's
   "Found, not fixed" items in the plan's execution log are accurate, and I
   agree with them: settings values clamped at use (1.7/1.12); merge against
   retained history so that duplicate-clock detection sees dominated versions
   (1.7); 1.8 decides how the live view shows records that are both `live` and
   `in_trash`. One more for 1.7/1.8: root undeletability (0003 §2.3) depends on
   the manifest role, so the model only provides `check_root`. The write path
   must call it for the root on every write and every merge result.
   Action: none now.

3. **[info] `crates/qv-model/proptest-regressions/merge.txt`** holds two seeds
   from the developer's deliberate mutation check (ascending sort). Against
   the correct code they are extra regression cases that pass. Keeping them
   is harmless.

## Fixes applied by reviewer

None.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass (all suites ok, 1 ignored: plan 0005 vector generator) |
| `cargo deny check` (deps changed: `sha1`) | pass (advisories, bans, licenses, sources) |
| `cargo vet --locked` | pass (12 fully audited, 34 exempted) |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md (§3 "Implemented so far" gains `qv-model`)
- [x] Spec statuses and Changelogs (no spec change; 0003/0007 stay Accepted, 0005 Draft, correctly)
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

None blocking. Finding 1 is carried into the phase 1.6 plan as a small step.
