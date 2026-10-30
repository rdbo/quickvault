# Review — Plan 0022: Verified rotation replacement and snapshot inventory

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes | 2026-10-30 | `git show 5fe3495` (phase 1.15b), plus the reviewer fixes below |

## Summary

Phase 1.15b builds the private replacement of the next key generation and
the per-generation snapshot inventory, as planned. `prepare_rotation` checks
its preconditions before any KDF or file work. It authenticates the whole
source, reencrypts every record and chunk under fresh object IDs with version
IDs, clocks, floors and conflicts preserved, and adds one causal keyslot edit.
It then reopens the persisted file hardened as a never-writable,
never-anchored Candidate and compares it fully with the source. Nothing is
published. The inventory codec is bounded, canonical and MAC'd, and its
directory operations never turn a row into a path. The code is careful and
matches the plan. The fixes were two misplaced doc comments and two test
cases that step 4 listed but that were missing.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 Reserved names | yes | `rotation_guard::check` covers open, open_locked, create, restore and `check_identity`. A Candidate skips only the name test. Every write path goes through `begin()`, which refuses a Candidate. |
| 2 Creation helper, build | yes | Restore's DB body moved unchanged into `creation::write_database`, which now writes the slot kind from the slot (`PASSWORD_SLOT` = 0 as before). |
| 3 Persisted verification | yes | Slot unlocked from the persisted bytes. Header MAC checked under both keys. `finish_candidate` never touches anchors. Manifest, digest, replica and head are compared, then a full `verify_all` and a per-version logical and content comparison. |
| 4 Evidence | partial → yes after fixes | Missing before the fixes: the anchor-Mismatch refusal and preservation of unknown extension fields. Added by the reviewer (see below). The listed "attachment history versions" case cannot occur: content is staged once per new record and `Manifest::validate` uses each chunk reference once, so an attachment record never has a chunk-bearing history version. The developer did not log that omission. |
| 5 Codec, vector, fuzz | yes | `Decoder::new` validates canonical form, key order and duplicates before field parsing. Size cap before decode; row bound before allocation. |
| 6 Directory operations | yes | Build rules 1–4 as specified; a g-authenticated row supersedes a carried row. |
| 7 Docs and gates | yes | |

Out-of-scope changes: none. The logged deviations (no `check_identity` case
for an ordinary session at a reserved path, the bijection correction, test
hooks, and the 4097-row bound tested with a well-formed array) are justified.

## Findings

1. **[low] Planned replacement evidence missing** —
   `crates/qv-store/src/rotation_tests.rs`. Step 4 listed an anchor Mismatch
   refusal and unknown extension fields. Only Missing (NoAnchor) was tested,
   and the fixture had no extensions. `compare()` covers extensions by
   construction (full canonical-encoding digests), but the plan's *Done
   when* asked for the cases. The step-4 "attachment history versions" case
   is unreachable (see Plan conformance). Action: fixed by the reviewer
   (two tests added).
2. **[low] Two doc comments attached to the wrong items** —
   `crates/qv-store/src/vault.rs` (`finish_unlock`'s doc on `path()`) and
   `crates/qv-store/src/manifest.rs` (`replace_heads`'s doc merged into
   `remapped`). The inserted functions landed between a doc comment and its
   item. Action: fixed by the reviewer.
3. **[note] The new slot keeps the source slot's KDF/wrap profiles** —
   `crates/qv-store/src/rotation.rs:253`. The plan said "the profiles of the
   current registry". The developer logged this deviation, and the two are
   identical today (V1 only). 0002 §3.5 sets no rule. When a second profile
   exists (1.16 or later), whoever adds it should decide whether rotation
   also upgrades the KDF profile. This is not decided here. No action.
4. **[note] Inventory hashing is path-based** —
   `crates/qv-store/src/snapshot_inventory.rs:396–399, 505–508`. The header
   check, the hash and the removal each reopen the file by name. Only a
   process with write access to the owner-only snapshot directory can swap
   files in between. Removal still needs an exact hash and size match, so
   the worst case is deleting a file that already has an inventoried hash.
   This fits the 0008 §5 local-attacker model. No action.

No security finding in cryptographic, secret-handling, parsing or storage
code. Checked:
- secrets stay in qv-crypto containers; `PreparedRotation` Debug is redacted
  and the inventory types print counts only;
- comparisons are constant-time (MAC verify, content hashes, file hashes);
- no new primitive; purpose keys and labels follow the existing journal
  construction;
- Candidate sessions are refused by `begin` and `finish_pending_anchor`;
- object-ID collisions fail closed as `Rng`;
- the source, its sidecars and the anchors stay byte-identical in every test
  path;
- no `unsafe`, dependency, schema or profile change.

## Fixes applied by reviewer

- `crates/qv-store/src/rotation_tests.rs`: added
  `rotation_replacement_refuses_a_mismatched_anchor` (an anchor two commits
  behind; `unlock_for_recovery` reports Mismatch; `prepare_rotation` is
  `Rollback`; vault and anchors byte-identical) and
  `rotation_replacement_preserves_unknown_extension_fields` (an unknown
  envelope key, built by decoding, survives into the replacement with equal
  content; byte-identical evidence). Test-only; it specifies behaviour the
  plan already required.
- `crates/qv-store/src/vault.rs`, `crates/qv-store/src/manifest.rs`: moved
  the two doc comments back to `finish_unlock` and `replace_heads`. Doc-only.

## Gates

Run on the final reviewed tree after the fixes. The committed tree also passed every gate before the fixes (619 passed). Logs are in the session
scratchpad `rev22/`.

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `cargo fmt --check` | pass |
| `cargo clippy --all-targets --locked -- -D warnings` | pass |
| `cargo test --locked` | pass with private Xvfb (Alpine package extracted into the scratchpad, `QV_TEST_XVFB`): 621 passed, 0 failed, 2 pre-existing ignored, 34 groups. The first final run had one failure: `clipboard_binary_lifecycle_and_key_drop` hit its 10 s Xvfb startup timeout (environment load; no qv-cli change). The clipboard test alone and a full rerun then passed. Recorded, not hidden. |
| `cargo deny check` / `cargo vet --locked` | n/a (no dependency change) |

Network namespace isolation is not available in this environment and is not
counted as a pass.

## Documentation

- [x] CHANGELOG.md (1.15b entry present; review entry added)
- [x] ARCHITECTURE.md §3 rotation paragraph, §7 split note
- [x] Spec statuses and Changelogs (no normative change; 0002 stays Accepted)
- [x] Plan ticks, execution log, plans/README.md row (now Reviewed)

## Escalations for the owner

None. Note 3 (the KDF profile of a rotated slot) is for whoever adds a
second password-KDF profile to decide.
