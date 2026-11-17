# Plans

Implementation plans written by the `quickvault-architect` skill, executed by
`quickvault-developer` and reviewed by `quickvault-reviewer`. Plans are kept
after completion as the record of *how* and *why* something was built; specs
remain the record of *what* the system must do.

## Layout

```
plans/
  NNNN-short-slug/
    PLAN.md     # the plan, plus the developer's execution log
    REVIEW.md   # written by the reviewer
```

Numbers are four digits, increase by one, and are never reused. Find the next one
with `ls plans/`.

## Status lifecycle

Set in the table at the top of `PLAN.md`.

| Status | Meaning | Set by |
|--------|---------|--------|
| `Proposed` | Written, awaiting owner approval | architect |
| `Approved` | Owner agreed; ready to implement | owner (or developer, recording the owner's go-ahead) |
| `In progress` | Being implemented | developer |
| `Blocked` | Stopped on a question for the owner; see execution log | developer |
| `Implemented` | All steps done and verified | developer |
| `Reviewed` | Reviewer approved (possibly with minor fixes) | reviewer |
| `Abandoned` | Not pursued; keep the file and say why | anyone, with owner agreement |

A review that requests changes leaves the status at `Implemented` with a note,
and the developer continues. A re-plan creates a revision section in the same
plan, or a new plan that names the one it supersedes.

## Index

| # | Title | Status |
|---|-------|--------|
| [0001](0001-offline-first-sync/PLAN.md) | Offline-first sync direction (spec amendment) | Reviewed |
| [0002](0002-roadmap/PLAN.md) | Development roadmap (phases to v1 milestones) | Approved |
| [0003](0003-workspace-bootstrap/PLAN.md) | Workspace bootstrap and protected memory (roadmap 1.1) | Reviewed |
| [0004](0004-canonical-cbor/PLAN.md) | Bounded deterministic CBOR, `qv-encoding` (roadmap 1.2) | Reviewed |
| [0005](0005-crypto-key-hierarchy/PLAN.md) | Crypto profiles, symmetric primitives and key hierarchy (roadmap 1.3) | Reviewed |
| [0006](0006-recovery-phrase-generator/PLAN.md) | Recovery phrase and password generator (roadmap 1.4) | Reviewed |
| [0007](0007-data-model-merge/PLAN.md) | Data model, version vectors and merge, `qv-model` (roadmap 1.5) | Reviewed |
| [0008](0008-vault-file-sqlite/PLAN.md) | Vault file: hardened SQLite, schema, header and keyslots, `qv-store` (roadmap 1.6) | Reviewed |
| [0009](0009-objects-manifest-anchor/PLAN.md) | Objects, manifests, local head, anchor and the write path, `qv-store` (roadmap 1.7) | Reviewed |
| [0010](0010-core-sessions/PLAN.md) | qv-core sessions and vault operations, `qv-core` (roadmap 1.8) | Reviewed |
| [0011](0011-cli-foundation-read/PLAN.md) | CLI foundation, vault and read commands, `qv-cli` (roadmap 1.10a) | Reviewed |
| [0012](0012-cli-edit-trash/PLAN.md) | CLI editing, trash and signal cleanup (proposed phase 1.10b revision) | Abandoned — wrong phase selection; owner directed phase 1.9 |
| [0013](0013-ui-feasibility/PLAN.md) | Android/Linux shared-UI feasibility (roadmap 1.9) | Reviewed |
| [0014](0014-cli-edit-trash/PLAN.md) | CLI editing, trash and signal cleanup (roadmap 1.10b) | Reviewed |
| [0015](0015-cli-clipboard/PLAN.md) | CLI clipboard: direct X11 adapter and protected transport (roadmap 1.10c) | Reviewed |
| [0016](0016-attachments/PLAN.md) | Streaming attachments and CLI file operations (roadmap 1.11) | Reviewed |
| [0017](0017-entry-history/PLAN.md) | Entry history, restore and purge (roadmap 1.12) | Reviewed |
| [0018](0018-archives-snapshots-verify/PLAN.md) | Archives, local snapshots and `verify` (roadmap 1.13a) | Reviewed |
| [0019](0019-snapshot-restore/PLAN.md) | Restore a local snapshot to a new vault (roadmap 1.13b) | Reviewed |
| [0020](0020-password-recovery/PLAN.md) | Password change and recovery flows (roadmap 1.14) | Reviewed |
| [0021](0021-offline-key-rotation/PLAN.md) | Rotation journal and open safeguards (roadmap 1.15a) | Reviewed |
| [0022](0022-rotation-replacement/PLAN.md) | Verified rotation replacement and snapshot inventory (roadmap 1.15b) | Reviewed |
| [0023](0023-rotation-install/PLAN.md) | Rotation installation, restart and `recovery rotate` (roadmap 1.15c) | Reviewed |
| [0024](0024-offline-release-evidence/PLAN.md) | Offline hardening evidence (roadmap 1.16) | Reviewed |
| [0025](0025-lan-protocol-spec/PLAN.md) | LAN sync protocol spec 0013 (roadmap 2.1) | Reviewed (0013 Accepted) |
| [0026](0026-conflicts-archive-exchange/PLAN.md) | Verified archive input and merge candidates (roadmap 2.2a) | Reviewed |
| [0027](0027-archive-receipt-state/PLAN.md) | Archive receipts and atomic incoming acceptance (roadmap 2.2b) | Reviewed |
| [0028](0028-archive-exchange-commands/PLAN.md) | Conflict resolution and archive exchange (roadmap 2.2c) | Reviewed — publication reporting repaired and verified |
| [0029](0029-linux-platform/PLAN.md) | Platform traits and Linux adapters (roadmap 2.3) | Reviewed |
| [0030](0030-app-foundation/PLAN.md) | Shared app foundation and webview security boundary (roadmap 2.4) | Reviewed — startup error category repaired; 2.5 follow-ups recorded |
| [0031](0031-app-vault-workflows/PLAN.md) | App vault workflows (roadmap 2.5) | Reviewed — 2026-11-02 repairs confirmed in the 0033 fresh review |
| [0032](0032-remove-vendored-forks/PLAN.md) | Remove vendored forks except dioxus-desktop | Reviewed |
| [0033](0033-android-quick-unlock/PLAN.md) | Android quick unlock (roadmap 2.6) | Reviewed — unvalidated devices disabled; device matrix incomplete |
| [0034](0034-android-autofill/PLAN.md) | Android autofill (roadmap 2.7) | Reviewed — reviewer fixed cold-start handoff and empty-field fills; device round trip pending; gate closed |
| [0035](0035-android-single-runtime/PLAN.md) | Android: one Rust runtime per process; single build project dir | Reviewed |
| [0036](0036-protocol-foundation/PLAN.md) | Protocol foundation and X-Wing, `qv-protocol` (roadmap 2.8) | Reviewed — reviewer fixed the oversized-frame wire code |
| [0037](0037-lan-pairing/PLAN.md) | LAN pairing, link storage and new-device initialization (roadmap 2.9) | Reviewed — reviewer added the creation guards to new-device join |
| [0038](0038-lan-exchange/PLAN.md) | LAN sessions, exchange, CLI and app (roadmap 2.10) | Reviewed — repairs approved; remaining attended testing carried to 0039 step 6 |
| [0039](0039-lan-qr/PLAN.md) | LAN QR display and Android camera scanning (roadmap 2.10b) | Reviewed — approved with two test-only fixes; native/optical phone checks pass; live peer/offline checks carried to 2.11 |
| [0040](0040-app-design/PLAN.md) | App design: application look and feel (roadmap 2.10a) | Implemented — new UI from the approved prototype; fresh review, phone run and owner acceptance pending |
| [0041](0041-vault-list/PLAN.md) | Vault list, default folder and name-only create (owner follow-up to 2.10a) | Implemented — fresh review and owner acceptance pending |
| [0042](0042-lan-one-scan-sync/PLAN.md) | One-scan LAN sync, no device links (owner direction; spec 0014) | Implemented — fresh review, phone run and D12 pending |
| [0043](0043-owner-polish/PLAN.md) | Page fade, title-bar icon contrast, protection chip, `qv` binary (owner follow-ups) | Implemented — fresh review pending |
| [0044](0044-owner-feedback-batch/PLAN.md) | List selection, sync receipt, conflict compare, in-app attachment previews, Android shell (owner feedback batch) | Implemented — fresh review and device check pending |
| [0045](0045-owner-feedback-android/PLAN.md) | Fingerprint first (persistent quick unlock), protection levels, Android long press, conflicts, Devices, fade, focus (owner feedback) | Implemented — fresh review and device check pending (quick-unlock policy partially reviewed 2026-11-14; remaining code findings repaired in 0065) |
| [0046](0046-audit-remediation/PLAN.md) | Security assessment: initial fixes and full findings disposition | Reviewed — initial code batch only; LAN v2/v3 design changes requested, v3 resolutions proposed and awaiting review; remaining assessment work open |
| [0047](0047-audit-policy-and-lan-auth/PLAN.md) | Large-vault views, filesystem policy and authenticated LAN enrollment | Reviewed — LAN/2, bounded pages and SQLite repair implemented; final gates pass; release/device evidence continues in0048 |
| [0048](0048-security-release-validation/PLAN.md) | Security release validation and large-vault qualification | Blocked — phone boundary/QR/regular-UI checks and Class3 repeat pass; first hardware failure, full app/LAN evidence and independent review remain open |
| [0049](0049-android-vault-file-picker/PLAN.md) | Android vault-file picker and verified local import | In progress — review code findings repaired in 0065; current APK build passes; real-phone qualification pending |
| [0050](0050-complete-audit-remediation/PLAN.md) | Complete remaining security assessment repairs | In progress — review code findings repaired in 0065; Linux media flows pass; isolated Android media qualification awaits phone |
| [0051](0051-list-swap-other-type/PLAN.md) | No list flicker on filter change; fixed item types with Other (owner request) | Implemented — fresh review pending |
| [0052](0052-windows-platform/PLAN.md) | Windows platform and release (roadmap 3.1) | Implemented — Windows CI run, attended gate checklist and fresh review pending (qv-win clipboard partially reviewed 2026-11-14; exclusion ordering repaired in 0065) |
| [0053](0053-performance/PLAN.md) | Performance: unlock, paged views, search and bulk changes (owner request) | Reviewed — approved 2026-11-14; phone run pending (0056 step 5) |
| [0054](0054-selection-motion-type-tiles/PLAN.md) | Selection motion, type tiles, quieter file cards, stable selection rows, new logo (owner request) | Implemented — fresh review and owner acceptance pending |
| [0055](0055-wayland-clipboard/PLAN.md) | Clipboard on Wayland: GTK in the app, data-control in the CLI (owner bug report) | Reviewed — approved 2026-11-14; remaining lows repaired in 0065; owner Wayland check pending (0056 step 5) |
| [0056](0056-release-1-0/PLAN.md) | Release 1.0: readiness checklist, cleanup, fast tests, focused reviews (owner request) | In progress — review repairs/LAN source review in 0065; native Windows, device/qualification and release gates remain |
| [0057](0057-video-preview/PLAN.md) | Video preview: playback stalls, player size, first frame before play (owner bug report) | Implemented — seek after end verified; fresh-context review pending |
| [0058](0058-picker-inactivity/PLAN.md) | File picking and playback: picker inactivity, shared input folders, playing preview (owner bug reports) | Implemented — APK build, phone check and fresh-context review pending |
| [0059](0059-sizes-and-snapshots/PLAN.md) | Larger vaults and files, snapshots inside the vault, buffered playback (owner request) | Reviewed 2026-11-16 — remaining rollback/downgrade/crash tests added in 0065; phone and native Windows checks pending |
| [0060](0060-snapshot-space-and-compaction/PLAN.md) | Snapshot space from free room, deleting snapshots, vault compaction (owner request) | Reviewed 2026-11-16 — remaining code findings repaired in 0065; locked replacement requires native Windows validation; phone check pending |
| [0061](0061-audio-levels/PLAN.md) | Audio preview bars: rest until Play, follow the sound on Android (owner request) | Implemented — full gates, phone check and fresh-context review pending; native levels proposed |
| [0062](0062-phone-and-sync-polish/PLAN.md) | Phone and sync polish: Back closes the sync window, connected state, receipt after Resolve, keyboard and tab bar, red snapshot delete, smooth copy bar, LAN address order (owner QA) | Implemented — phone check and fresh-context review pending |
| [0063](0063-phone-groups-and-last-view/PLAN.md) | Groups on the phone; the last group per vault, sealed per device (owner request) | Reviewed 2026-11-16 — remaining view-tag finding repaired in 0065; phone check pending |
| [0064](0064-format-freeze/PLAN.md) | Format freeze for 1.0: format registry, golden vectors, phone KDF benchmark (plan 0056 step 7) | Reviewed 2026-11-16 — golden restore/schema/generation coverage completed in 0065; phone KDF qualification pending |
| [0065](0065-release-review-repairs/PLAN.md) | Complete 1.0 review repairs and review LAN/2 | Implemented — code repairs and LAN source review complete; local gates pass; fresh review/native Windows/device release evidence pending |
| [0066](0066-alpine-edge-package/PLAN.md) | Separate Alpine 3.22 and Edge release packages with install checks | Implemented — local gates and workflow lint pass; clean-container CI and fresh review pending |
| [0067](0067-windows-webview-startup/PLAN.md) | Windows WebView2 startup origins | Implemented — origin tests pass; Wine hang also reproduces in a plain WebView2 host; fresh review and native Windows startup retest pending |
| [0068](0068-phone-ui-polish/PLAN.md) | Phone UI polish and a stuck scan panel (owner QA) | Implemented — gates pass; phone check and fresh-context review pending |
| [0069](0069-phone-owner-report/PLAN.md) | Phone owner report: update version code, background lock at the inactivity limit (5 min), screen freeze after a quick app switch (numbered UI batches), paste, groups by name, copy notices | Implemented — gates pass; phone check and fresh-context review pending |
