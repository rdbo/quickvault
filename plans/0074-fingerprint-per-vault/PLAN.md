# Plan 0074 — Fingerprint unlock for every vault, not one per device

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — gates pass; phone check (two vaults, a finger) and fresh-context review pending | 2026-11-20 | 2026-11-20 (owner: "I can only enable fingerprint for one vault at a time???"; design delegated, standing 2026-11-02) | 0002 §5.1, §5.4; 0009 §1.8 |

## Intent

The device keeps one quick-unlock enrollment. Enrolling a second vault moves
the fingerprint key to it, and turning it off in one vault's Settings stops
the offer for every vault. Plan 0072 recorded this limit in 0009 §1.8 as a
rule when fixing the Settings text, and the owner did not know it. Nothing
in 0002 §5 requires it. Let every vault on the device have its own
fingerprint unlock, independent of the others.

## Findings

1. The limit is in Rust: `AndroidKeystore` holds `Mutex<Option<Slot>>`;
   the `quick-unlock` state file (`QVQU`, version 1) holds one record;
   `Keystore::{binding, policy, invalidate}` take no vault; `enroll`
   destroys the old slot first.
2. Native keys are already one per enrollment: the alias is a random
   16-byte handle in the envelope header, each with its own enrollment time
   (`born`). Only `retain` keeps one envelope at startup and deletes every
   other QuickVault key.
3. The AAD binds vault ID, key generation, password-keyslot version and the
   envelope header (`qv/android-quick/v1`), so envelopes stay per vault as
   they are; the envelope format is unchanged.
4. The state and preferences files are app-local device state, outside the
   frozen 1.0 formats (0015 "Out of scope"), and fail safe to defaults.
5. The `quick=off` preference is device-wide: it is set by turning
   fingerprint unlock off in Settings and blocks the offer for every vault.

## Decisions (owner-delegated, standing 2026-11-02)

- D1 One enrollment per vault ID, at most 16 on a device (bounded state).
  Enrolling a vault replaces only its own enrollment. A 17th is refused
  with a message to turn one off first; no enrollment is ever moved or
  evicted silently.
- D2 Each enrollment is independent: its own hardware key, policy
  (fingerprint, or the labeled PIN opt-in), seven-day age and three failed
  attempts (0002 §5.4, now per enrolled vault). Turning it off, a password
  change, a rotation, an expiry or a failure limit removes only that
  vault's enrollment. Device-wide events still remove them all: a new boot,
  a clock that went backwards, unreadable or unknown state, and a backend
  that is no longer validated. A new fingerprint enrolled in Android
  invalidates every key; each enrollment is removed at its next use.
  The OS biometric lockout is device-wide and bounds guesses across
  vaults.
- D3 State file version 2: the version-1 header fields per record, up to 16
  records, read whole and bounded before allocation. A version-1 file is
  read as one record, so the current enrollment survives the update. Any
  malformed file is cleared and every handle destroyed, as today.
- D4 Native `retain` takes the list of live envelopes and deletes every
  other QuickVault key. All live envelopes share the install's device ID;
  an envelope with another device ID is dropped.
- D5 UI: Settings shows and changes this vault's fingerprint unlock only.
  The "on for another vault" banner and "Use fingerprint for this vault"
  (plan 0072 D7) go away. After a password unlock the offer comes when this
  vault has no enrollment and fingerprint unlock is not turned off for it.
  The locked screen prompts for the selected vault when it has one (as
  today, judged from the header).
- D6 "Turned off" becomes per vault: `quick-off=<vault ID hex>` lines in
  the preferences file, at most 64. The old device-wide `quick=off` line is
  dropped when read, so each vault can be offered again once.
- D7 Removing a vault from this device's list removes its enrollment.

## Steps

1. Specs: 0002 §5.1 (one enrollment per vault), §5.4 (attempts and age per
   enrolled vault; device-wide invalidation); 0009 §1.8 (replace the
   one-enrollment rule). Changelogs.
2. qv-platform: `Keystore` methods take a vault ID (`binding(vault)`,
   `policy(vault)`, `invalidate(vault)`, plus `invalidate_all`);
   `AndroidKeystore` keeps a bounded map of slots; state version 2 with
   version-1 reading; per-slot attempts, persisted before each prompt;
   `retain` with every live envelope. Tests: the existing policy tests per
   slot, independence (a failure limit or invalidation of one keeps the
   other), the 16 limit, version-1 migration, malformed and oversized
   version-2 files, a boot change clearing all.
3. Android native: `qvQuickRetain` takes an array of envelopes.
4. qv-core: `quick_enrolled`, `quick_ready_for`, `invalidate_quick` by the
   session's vault; tests.
5. qv-app: remove `QuickHolder`; per-vault offer and preferences; Settings
   text; removing a vault drops its enrollment; tests.
6. CHANGELOG, gates (with Android Clippy), APK, phone check of two vaults
   with fingerprints (owner), fresh-context review.

## Test plan

Workspace gates; app Clippy and tests with `desktop` and `validation`;
Android Clippy for `mobile` and `mobile,validation`; the real-engine flow;
phone: enroll two vaults, unlock each with a fingerprint, turn one off and
check the other still works (owner, a finger is needed).

## Risks and stop conditions

- Secret handling and key management: the fresh-context review is required
  before release.
- Stop if the native keystore cannot keep several keys with per-use
  authentication on the owner's phone.

## Execution log

- 2026-11-20: plan written from the owner's report and a read of
  `qv-platform` quick unlock, the native keystore, `qv-core` quick unlock
  and the app's offer, Settings and preferences.
- 2026-11-20 (steps 1–6): specs amended. qv-platform: `Keystore`
  `binding`/`policy`/`invalidate` take a vault ID, plus `invalidate_all`;
  `AndroidKeystore` keeps up to `MAX_SLOTS` (16) slots, each with its own
  attempts, age and serial; state version 2 (a count, then the version-1
  record fields per vault), version 1 read as one record and rewritten;
  a record past its age is dropped alone, anything else malformed clears
  all. `retain` takes every live envelope (native `qvQuickKeep` per
  envelope, then `qvQuickSweep`). qv-core: `quick_ready_for`,
  `quick_enrolled`, `quick_policy`, `invalidate_quick` per vault;
  `Core::quick_ready` is replaced by `quick_kept` (did the last attempt end
  its vault's enrollment) and `forget_quick` (unless a listed copy is the
  same vault). App: `QuickHolder` and the Settings banner/move removed;
  the offer needs no enrollment for this vault and no `quick-off` mark for
  it in the vault list (the `quick=off` preference is dropped); removing a
  vault from the list ends its enrollment; the 17th enrollment shows
  `QUICK_LIMIT`. Tests: platform
  `each_vault_keeps_its_own_enrollment_attempts_and_age`,
  `a_restart_drops_expired_records_alone_and_a_new_boot_drops_all`,
  `a_device_keeps_at_most_sixteen_enrolled_vaults`, the malformed-file test
  for version 2 and version-1 reading; core
  `dismissal_keeps_the_enrollment_and_each_vault_has_its_own`; app
  `quick_unlock_is_offered_after_a_password_unlock_and_prompts_on_return_only`
  (two vaults, turning one off, removing one), the vault-list and
  preferences tests. All gates pass (1,390 tests); Android Clippy for
  `mobile` and `mobile,validation`. Installed on the owner's Android test
  phone (isolated copy).
