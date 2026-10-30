# Report — Plan 0024: Offline hardening evidence (roadmap 1.16)

Evidence collected on 2026-10-30. **The owner has decided there is no format
freeze before 1.0**, so nothing here freezes, tunes or promises a format.
The numbers describe today's development formats and profiles. This report
is not proof of security (0012 *Security Considerations*).

## 1. Offline matrix rows

`tests/matrix-offline.txt` lists the 23 rows of 0012 §1 that apply to the
offline Linux CLI. `sh scripts/check-matrix.sh` (also run in CI) checks
that each row has at least one test tagged `// 0012 §1: <row>`, and that
every tag names a real row and sits on a `#[test]` function. `cargo test`
supplies the "passing" half. For each row, only the offline part is
covered. Exchange (2.2), LAN, server and GUI parts belong to those
releases' gates.

| Row (0012 §1) | Tagged tests |
|---|---|
| Implicit server prerequisite | `offline_without_any_configuration` (qv-cli); `offline_with_networking_blocked` (qv-cli); `offline_lifecycle` (qv-core) |
| Old-date concurrent edits | `scenario_old_date_concurrent_edit_survives` (qv-model) |
| Order-dependent merges | `merge_is_permutation_invariant` (qv-model); `merge_regrouping_converges` (qv-model); `merge_ignores_duplicate_delivery` (qv-model) |
| Whole-file rollback | `rollback_two_commits_ahead` (qv-store); `rollback_fork_and_old_copy` (qv-store); `verify_rejects_missing_short_long_flipped_and_substituted_objects` (qv-store) |
| Live SQLite copying | `live_sqlite_copying_snapshots_never_copy_or_write_the_vault` (qv-core); `archive_writer_aborts_on_a_corrupt_object_with_nothing_published` (qv-store); `live_sqlite_copying_archive_is_built_from_verified_objects` (qv-store); `archive_during_a_concurrent_writer_is_safe` (qv-store); `snapshot_publish_crash_points_leave_no_partial_archive` (qv-store) |
| Swap/hibernation leaks | `memory_lock_failure_under_real_limit_is_reported` (qv-crypto); `process_hardening_applies_and_is_idempotent` (qv-crypto); `process_hardening_reports_unsupported` (qv-crypto) |
| Unpinned crypto | `kat_rfc4231_hmac_sha512` (qv-crypto); `kat_mac1_truncates_rfc4231_style_outputs` (qv-crypto); `kat_wycheproof_hkdf_sha512` (qv-crypto); `kat_sha256` (qv-crypto); `kat_xchacha20poly1305_draft_a_3_1` (qv-crypto); `kat_dev_keys_match_the_independent_python_values` (qv-crypto); `kat_dev_stored_data` (qv-crypto); `password_rfc9106_argon2id_through_the_pinned_crate` (qv-crypto); `password_kdf_v1_full_profile_matches_openssl` (qv-crypto); `slot_unknown_profiles_fail_at_parse_time` (qv-crypto) |
| Hostile SQLite/CBOR | `head_rejects_reserved_indefinite_and_truncated` (qv-encoding); `manifest_key_rejections` (qv-store); `rotation_journal_rejects_bad_shape_versions_and_unbounded_lengths` (qv-store); `snapshot_inventory_rejects_bad_shape_bounds_and_rows` (qv-store); `tamper_schema_changes_are_refused` (qv-store); `tamper_pages_and_files_are_refused` (qv-store); `tamper_planted_sidecars_are_refused` (qv-store) |
| Deleted-entry resurrection | `scenario_deleted_entry_stays_deleted` (qv-model) |
| Self-referential/incomplete commitments | `archive_rejects_wrong_reference_digest_before_sink` (qv-store); `manifest_structure_rejections` (qv-store); `verify_rejects_a_truncated_history_version` (qv-store); `verify_rejects_a_corrupt_attachment_chunk` (qv-store) |
| Rotation/purge ambiguity | `rotation_interrupted_then_completed_or_rolled_back` (qv-cli); `history_purge_crash_boundaries_preserve_heads_and_atomic_floor` (qv-store); `rotation_crash_at_every_installation_step` (qv-store); `rotation_crash_while_completing_after_a_restart` (qv-store); `rotation_crash_while_rolling_back_after_a_restart` (qv-store) |
| Migration coupling | `rotate_full_lifecycle_through_core` (qv-core); `credentials_rewrap_preserves_objects_and_phrase_and_reauthenticates_current_slot` (qv-store) |
| Mixed credentials | `scenario_mixed_credentials_stay_whole` (qv-model) |
| Snapshot disk growth | `audit_write_failure_fails_closed_at_every_write_path` (qv-cli); `snapshot_disk_growth_a_snapshot_failure_aborts_the_destructive_operation` (qv-cli); `snapshot_disk_growth_a_full_disk_aborts_the_mandatory_copy` (qv-core) |
| Impossible generator | `generator_infeasible_character_settings` (qv-crypto); `generator_too_few_positions` (qv-crypto); `generator_require_each_class_exhausts_without_patching` (qv-crypto) |
| Ambiguous trust boundary | `audit_modes_owner_only_under_umask_000` (qv-cli); `audit_canary_secrets_never_reach_output_or_files` (qv-cli); `keys_debug_is_redacted` (qv-crypto); `memory_debug_is_redacted` (qv-crypto); `password_debug_is_redacted` (qv-crypto); `vault_unlocked_debug_is_redacted` (qv-store) |
| Hostile files from sync folders | `hostile_files_from_sync_folders_are_warnings_not_rows` (qv-cli); `hostile_archive_files_are_rejected_before_any_sqlite_call` (qv-store) |
| Exchange-file password guessing | `exchange_file_password_guessing_a_snapshot_does_not_open_with_the_password` (qv-cli); `exchange_file_password_guessing_archives_carry_no_slot` (qv-store) |
| Password-slot partitioning oracle | `slot_partitioning_oracle_is_rejected_before_decryption` (qv-crypto) |
| Anchor crash windows | `crash_every_mutation_point` (qv-store); `crash_every_create_point` (qv-store) |
| CLI argument leakage | `audit_canary_secrets_never_reach_output_or_files` (qv-cli); `clipboard_binary_lifecycle_and_key_drop` (qv-cli); `prompts_notes_interactive_and_cancellation` (qv-cli) |
| Budget inconsistency | `manifest_worst_case_fits_the_limit` (qv-store) |
| Supply chain | `offline_cli_dependencies_are_fixed` (qv-cli) |

"Ambiguous trust boundary" and "Supply chain" are review rows: their tags
sit on the closest automated checks, and §5 and §6 hold the review.

The CLI flow covers create, unlock, read, edit and phrase recovery (`recover`, added in review: the row names recovery). **Not a pass here:** `offline_with_networking_blocked` skips in this
sandbox, because `unshare -rn` fails ("No space left on device"). CI now
enables user namespaces and sets `QV_REQUIRE_NETNS=1`, so the test must
pass there. The owner needs to check that CI result (no `gh` in this
environment).

## 2. Audits (`crates/qv-cli/tests/audit.rs`)

| Audit | Result |
|-------|--------|
| Modes under `umask 000`: `init`, `add`, `attach add`, `rm`, `trash empty`, `snapshot ls`, `passwd`, `recovery rotate` | Pass: every file 0600, every directory 0700, no symlinks. A scratch `chmod 0644` made it fail. |
| Write failure (`prlimit --fsize`, `SIGXFSZ` ignored; `EFBIG` maps like `ENOSPC`) | Pass. Automatic snapshot: a warning (exit 0), no archive left. `add` and `attach add`: exit 1/9, vault, anchor and directory byte-identical. `trash empty`: refused before deleting. `recovery rotate`: nothing published, old password works. `init`: nothing at the target. |
| Canary secrets in output and files | Pass: 5 canaries (the new-password canary was added in review), 8 failing commands plus a cancelled rotation and a cancelled password change with a mismatched new password. No canary in stdout or stderr, and none in any file (vault pages, journals, anchors, archives). Phrase words are random dictionary words and cannot serve as canaries. |

Limits:
- A real full disk needs root or a tmpfs mount, so the file-size limit
  stands in for it.
- The rotation case cannot separate failing at the recovery copy from
  failing at the replacement.
- No tested command spawns a helper process.

Investigated, not a finding: one flipped byte at a vault's midpoint still
opened. It hit the unallocated gap of an index page, which SQLite never
reads. QuickVault authenticates content, not page slack.

## 3. Fuzzing

Local runs on the pinned nightly (`nightly-2026-10-01`, cargo-fuzz 0.13.2),
30 minutes per target. Because the host is musl, they ran with
`-s none -use_cmp=0`, that is **without AddressSanitizer**. Summaries are in
`evidence/fuzz-*.txt`.

| Target | Runs | Final coverage (cov / ft) | Findings |
|--------|------|---------------------------|----------|
| cbor_decode | 124,179,865 | 305 / 2072 | none |
| record_decode | 1,543,653,147 | 778 / 1269 | none |
| manifest_decode | 873,045,361 | 298 / 649 | none |
| vault_open (unseeded) | 39,197,940 | 277 / 354 | none |
| vault_open (seeded with 2 real vaults) | 17,463,179 | 663 / 1035 | none |
| archive_read | 58,612,712 | 1023 / 2082 | none |
| rotation_journal | 86,526,267 | 405 / 925 | none |
| snapshot_inventory | 292,469,502 | 419 / 867 | none |

Observations:
- **The runs were longer than this stage needs.** Most targets stopped
  finding new paths within minutes (for example, cbor_decode was already
  at 305 after 8 minutes). Ongoing fuzzing is now the per-push 60 s CI
  runs plus the new weekly `fuzz-extended` workflow (30 minutes per target
  with ASan on glibc). The owner reads its results.
- **`vault_open` got weak coverage from random bytes** (277): they rarely
  form a valid SQLite file. Seeding it with real vaults more than doubled
  coverage (663). Done afterwards with the owner's go-ahead: the target now
  builds a real vault once per process. Odd-first-byte inputs patch,
  truncate or extend that vault; even ones stay raw bytes. A 2-minute run
  from an empty corpus was clean. Its coverage of 2297 also counts the
  one-time vault creation, so it is not comparable with the numbers above.
- The nightly reports a deprecation in `qv-store/src/sqlite.rs`
  (`fetch_update` → `try_update`). Stable 1.98.1 is unaffected; no action.

## 4. Benchmarks

The `budget_bench` example (`crates/qv-core/examples/`) generates
disposable vaults through the store's batched writes. It then measures each
sample in a fresh process:
- `Core::unlock` (the full password-kdf/1 run, header MAC, unlock
  verification, anchor, views);
- `Session::verify`;
- one ordinary edit through core.

Host: AMD Ryzen 9 9900X, 8 vCPUs available, release build, vaults on tmpfs
(so write timings exclude real `fsync` cost). Median of 5 samples after
one warm-up, with the range in brackets. Peak RSS is `VmHWM`. CSVs are in
`evidence/linux-*.csv`.

| Profile | Content | File | Unlock ms | Verify ms | Edit ms | Peak RSS |
|---------|---------|------|-----------|-----------|---------|----------|
| P0 | empty | 36 KiB | 332.6 (330.2–343.5) | 0.1 | 0.3 | 260 MiB |
| P1 | 1,000 entries × 4 versions, 20 × 1 MiB attachments | 24 MiB | 375.9 (371.9–378.3) | 116.3 | 47.2 | 262 MiB |
| P2 | 49,997 entries × 4 versions (50,000 records, 199,991 objects: the record cap) | 117 MiB | 2388.9 (2376.2–2418.6) | 2619.7 | 2551.3 | 262 MiB |
| P3 | 99 × 10 MiB attachments (1,021.5 of 1,024 MiB referenced ciphertext) | 1.03 GiB | 488.4 (487.1–497.8) | 3592.4 | 13.2 | 262 MiB |

Reading:
- **KDF.** Unlock of an empty vault is about 0.33 s here. On the owner's
  arm64 phone (phase 1.9) it was 0.865 s median, within 0002 §1.3's
  ~1 s target. Android measurement of these profiles is deferred with the
  freeze (owner decision).
- **Memory.** Peak RSS is about 260 MiB in every profile: the 256 MiB
  Argon2id buffer dominates, and even the largest manifest stays below it.
  This fits the ≥ 4 GB Android baseline.
- **Budgets are enforced, not just declared.** The record cap counts the
  three control records: a 50,000th entry is refused (LimitExceeded at
  commit). Padded chunk ciphertext makes a 10 MiB attachment about
  10.3 MiB of the 1 GiB budget, so the 100th is refused at staging. Both
  refusals left the vault intact. These were errors in the profile
  definitions, corrected and logged, not budget inconsistencies.
- **Write cost grows with the vault (input for the architecture review).**
  Every commit rewrites and re-encrypts the whole manifest. At the record
  cap, one edit takes about 2.5 s on this host, and unlock and verify
  about 2.4–2.6 s. A phone is likely 2–3 times slower. Typical vaults (P1)
  are far below that. This is a property of the single-manifest design
  (0004 §5.2), recorded for D13 and not changed here.

## 5. Secret-bearing types (Debug review)

Hand-written redacted `Debug` covers every secret container:
- qv-crypto: `SecretBytes`, `SecretArray<N>`, `MasterPassword`, `VaultKey`,
  `DataKey`, `RecoveryPhrase`, `OtpCode`, `Generated`, `MacTag`,
  `ContentHasher`;
- qv-model: `SecretText`, `FieldValue`, `Text`, `Extensions`, `Totp`;
- qv-encoding: `RawValue`;
- qv-store: `UnlockedVault`, `VaultFile`, `Write`, `StagedAttachment`,
  `ObjectEnvelope`, `PreparedRotation`, `InterruptedRotation`,
  `SnapshotInventory`, the archive types;
- qv-core: `Session`, `EntryDraft`, `GroupDraft`, `SettingsDraft`,
  `Rotation`, `Created`, `RecoverySnapshot` and the summaries;
- qv-cli: `Typed`.

Derived `Debug` in qv-crypto appears only on settings, IDs, profiles,
hardening status and errors. No plaintext allocation outside these
containers was found in this review. It is a review, not a proof.

## 6. Supply chain

- `cargo deny check`: advisories, bans, licenses and sources ok.
- `cargo vet --locked`: succeeded: 27 fully audited, 6 partially audited,
  **79 exempted**.
- Most security-critical crates are **exemptions** (trusted, with no
  recorded audit): `argon2`, `chacha20poly1305`, `poly1305`, `hkdf`, `hmac`,
  `sha2`, `blake2`, `ctutils`, `getrandom`, `rusqlite`, `libsqlite3-sys`.
  0012 §3 asks for these to be kept to a reviewed minimum and their audit
  status recorded: this is that record.
- Release artifact signing, checksums and reproducible builds do not exist
  yet. They belong to the pre-1.0 release step.

## 7. Known limitations (recorded, not decided)

- `qvault info` shows no rotation hint while a rotation is pending (1.15c).
- A generation ≥ 2 vault without its snapshot inventory reports a failed
  snapshot status on every unlock (fail-closed, 1.15c).
- Rolling back an interrupted rotation before commit needs the new
  password too (0023 review, note 5).
- Core takes the rotation's recovery snapshot just before freezing writes;
  a concurrent frontend could slip one write in between (0023 review,
  note 4).
- A damaged `-old-` sibling blocks cleanup of a committed rotation (0023
  review, note 6).

## 8. For the pre-1.0 release step (not scheduled)

- the 0012 §3 freeze and golden vectors, with the worst-case manifest;
- supported-device KDF and budget benchmarks with this tool;
- closing 0002 OQ1 and 0004 OQ1;
- audits or a recorded review of the exempted security-critical crates;
- release signing, checksums and reproducible builds;
- a decision on the known limitations above.
