# QuickVault Specifications

QuickVault is developed spec-first. Specs are **normative**: code implements
what they say, and behaviour changes start with a spec change.

## Index

Plan 0053 (2026-11-13, owner-delegated) amends 0004 §7.2/§7.3 and 0008
§2/§6 for performance: unlock verification feeds the index, text-free match
sets and a separately evicted label tier speed up paged views. No format,
budget, ordering or status change.

Plan 0049's Android system-picker implementation uses explicit private-copy
import under 0009 §1.8 and 0004 §5.4: bounded raw ciphertext staging, full
authentication/verification, fresh local identity and no provider write-back.
Linux import continues to reference the selected file. The named Draft client
section is implemented under the owner's execution instruction; whole-spec
statuses and independent device/release validation requirements are unchanged.
0007 §3.2 distinguishes this independent new-path creation from a destructive
import into an existing vault; the latter still requires its recovery copy.

Plan0050 tracks all fifteen remaining assessment repairs under the owner's
2026-11-09 instruction and delegated correctness decisions. The first amendment
requires a bounded immutable read-only schema probe before mutable SQLite
hardening (0004 §1.2), distinct durable/capacity/damaged-anchor reporting
(0004 §5, 0011 §6), independent-anchor warnings (0004 §1.1), causal admission
that retains room for the local resolver (0005 §1.2), and explicit encrypted
deletion identities (0003 §4/§5, 0007 §2.1). This is implementation work, not
release approval.

The same plan specifies accurate clipboard replacement reporting (0008 §3,
0011 §3.6) and shared display-only escapes for bidi/invisible controls without
changing editor or stored values (0009 §1, 0011 §5).
It also specifies core-enforced recovery-copy authorization and cooperative
file leases (0004 §6, 0007 §3.2), protected ranged media with separate loopback
capabilities and exact CSP bounds (0003 §6.4, 0008 §4, 0009 §1.8), and explicit
loading before large/unmeasured image decoding. Actual device validation remains
separate from these contracts and local test results.

Audit remediation (plan 0046, 2026-11-08) clarifies 0011 §3.1's terminal
protection through command exit and 0013 §1.4's shared endpoint classification.
The three policy discussions now have owner-selected directions recorded in
[plan 0047](../plans/0047-audit-policy-and-lan-auth/PLAN.md): bounded cache/paged
views, no persistent filesystem binding, and ephemeral v4 LAN authentication
with listener closure. Owner approved implementation on 2026-11-09. Normative amendments are in
0013 §15, 0014 §10, 0002 §9, 0003 §8 and 0004 §7, with corresponding
threat/input/validation text. Runtime LAN/2, verified password/phrase enrollment
and bounded frontend pages are implemented; final local gates pass. Independent
review and target qualification continue in proposed plan0048. The discovered SQLite advisory is repaired by upgrading the pinned engine,
with no vault/wire format change or advisory suppression. The named
0008 §6/0009 §7 sections are approved without promoting their full Draft specs.

0014 (accepted by the owner 2026-11-06, plan 0042) replaces 0013's stored
device links with one-use sync codes; its amendments are applied to 0013,
0002, 0004, 0005, 0009, 0011 and 0012.

0009 §1.8 specifies the owner-delegated app shell, preferences and item
editor profile (2026-11-05, plan 0040), approved for implementation. 0003 §5.5
adds the app colour token in the existing `icon` text. Its vault-list bullet (plan
0041) covers name-only create, import in place and the lock screen's copy of
vault names. The owner's 2026-11-06 amendment (plan 0043) shows the locked
screen's protection chip only while an acknowledgement is pending.

0011 §1.1 names the binary `qv` (owner, 2026-11-06, plan 0043).

0009 §1.8 adds item list actions, the sync receipt, the conflict comparison,
attachment previews and the Android shell, and 0003 §6.4 allows memory-only
in-app previews of sniffed types (owner, 2026-11-07, plan 0044).

0009 §1.8 lists fixed item types with Other and Wi-Fi and swaps list pages
without blanking; 0003 §5.1 shows non-standard hints as Other (owner,
2026-11-11, plan 0051).

0009 §1.4 makes Windows delivery phase 3 and the optional remote service
phase 4 (owner, 2026-11-12, roadmap 0002).

0009 §5.1 adds the Windows profile: ACL owner-only rules, required WTS
lifecycle, clipboard exclusion and disabled quick unlock (owner-delegated,
2026-11-12, plan 0052).

0009 §1.8 puts quick unlock first, grades protection as levels and adds
Android evidence, long-press selection and conflict links; 0002 §5.4 lets
boot-bound quick-unlock state survive app restarts (owner, 2026-11-07, plan
0045).

0009 §1.7 specifies the owner-delegated bounded Android LAN QR camera profile
(2026-11-03, plan 0039), approved for implementation; camera scanning is on
by default in ordinary packages (owner, 2026-11-07, plan 0043). Its overall
Draft status and actual-device release requirements are unchanged.

Owner-approved 2026-11-01 amendment to Draft 0008 §1.4 and 0009 §5: Linux
OS lock/sleep monitoring is optional and disclosed when unavailable; manual
and inactivity locking remain active. Reduced-protection acknowledgement still
applies. Android lifecycle requirements remain unchanged. Approved for current
phase 2.4 implementation; neither spec's overall status is promoted.

| # | Title | Status |
|---|-------|--------|
| [0001](0001-threat-model.md) | Threat Model | Accepted |
| [0002](0002-cryptography.md) | Cryptography and Key Hierarchy | Accepted |
| [0003](0003-data-model.md) | Data Model | Accepted |
| [0004](0004-local-storage.md) | Local Storage (Vault File) | Accepted |
| [0005](0005-synchronization.md) | Synchronization and Conflict Resolution (LAN and Remote) | Draft |
| [0006](0006-server-authentication.md) | Server Accounts, Authentication and Device Enrollment | Draft |
| [0007](0007-history-and-backups.md) | History and Backups | Accepted |
| [0008](0008-memory-and-side-channels.md) | Memory Hygiene and Side Channels | Draft |
| [0009](0009-clients-and-platforms.md) | Clients and Platforms | Draft |
| [0010](0010-password-generator.md) | Password Generator | Accepted |
| [0011](0011-cli.md) | Command-Line Interface | Accepted |
| [0012](0012-security-validation.md) | Security Validation and Release Gates | Accepted |
| [0013](0013-lan-sync-protocol.md) | Direct LAN Sync Protocol | Accepted |
| [0014](0014-lan-one-scan-sync.md) | One-Scan LAN Sync (no device links) | Accepted |

0004 §6.2 and 0011 §4 specify the delegated archive merge/export contracts and
explicit self-contained backup slots (2026-10-31, plan 0028).

0004 §3.4.1 and 0007 also specify permanent tombstone role markers and
indefinite covered-history retention (combined 2.2b, owner-directed plan 0027).

0004 §2.3 and 0005 §4/§5.4 include the owner-approved local archive receipt
contract (2026-10-30, plan 0027; delegation in 0026): bounded confidential paths,
complete-stream digests, sealed singleton state and authenticated-head binding.
Combined 2.2b implements atomic storage acceptance and receipts through the
existing Write/anchor path, with source paths bound to verified capabilities.

0002 includes the owner-approved offline rotation amendment of 2026-10-29
(plan 0021 D1 A): recovery public-key derivation may wait until sync needs it;
the independently derived signing seeds still change with VK.

0011 includes the owner-approved attachment CLI amendment of 2026-10-27
(plan 0016): explicit file import/export and confirmed permanent removal.
0011 also includes the owner-approved history/restore/purge CLI amendment of
2026-10-27 (plan 0017): scoped historical IDs, explicit conflict restoration
and local suppression limits. 0007 includes the owner-approved D6 amendment of
2026-10-27 (plan 0018): local snapshots carry no password slot, open with the
vault key or the recovery phrase, and a password change offers to delete the
snapshots created before it. 0011 includes the owner-approved snapshot/`verify`
CLI amendment of 2026-10-28 (plan 0018): the full integrity report with anchor
status, authenticated local-snapshot listing, scoped archive IDs and the
mandatory recovery snapshot before bulk deletion.

The 2026-10-24 direction amendment makes local vault use independent of accounts
and network access, with two optional sync modes: direct account-free LAN sync
and account-based remote server sync. Either mode, both or neither may be used
on a vault. 0005 defines their shared causal merge and separate lifecycle state;
0006 applies only to the remote mode. Archive exchange remains a backup/import/
export utility. Initial LAN and remote sync is manually initiated; automatic
sync and background retries are deferred. LAN discovery, enrollment, sessions,
peer-state persistence, listening lifecycle and peer removal remain explicit
Open Questions; this amendment does not select a wire protocol or promote any
Draft spec to Accepted.

0013 (Accepted 2026-10-30, owner-delegated) specifies that LAN protocol: discovery only during
explicit windows, out-of-band pairing into pairwise generation-bound link
keys, an X-Wing session handshake, the exchange and peer state. Its
amendments to 0001, 0002, 0004 and 0005 are applied. Acceptance does not
authorize a LAN release: the 0012 §3 gate, including independent review,
still applies. Plan 0037 (2026-11-02, owner-delegated) adds implementation
clarifications to 0013 §1.3, §7.1 and §8.3, and the development
`lan_link` layout to 0004 §2.4. On 2026-11-03 the owner removed remembered
endpoints (`lan_hint`) from 0013 §9.2: there is no device identity to remember
them for. Plan 0038 (2026-11-03, owner-delegated) adds the
address-only receive-window code (0013 §8.5), the initiator's single-link
rule (§5.1) and the `Want` count bound (§7.4), and specifies the `qv lan`
commands and exit code 10 in 0011.

The Android-priority follow-up brings Android and Linux into initial shared-core
and UI validation, with usable offline apps before the remote server. iOS stays
a later target. 0009 requires shared cross-platform app/UI code with isolated
OS adapters. On 2026-10-26 the owner selected Dioxus with standard webview
input and bounded cleanup claims (0008 §1.1/§4.4; 0009 §6). The renderer
choice is resolved; framework/OS copies do not require native secret dialogs
or a custom engine. Platform input cleanup, keystore, lifecycle, active-content
and autofill validation still apply. Related amendments update 0002's recovery
cross-reference and 0012's evidence requirements; spec statuses are unchanged.

The 2026-10-15 amendments replace HLC/field merging, active-file sync and
unconditional freshness claims. The follow-up security review replaces SQLite
exports with authenticated archives, removes server-visible record linkage,
simplifies anchors and remote acceptance, and hardens pairing and password
slots. Accepted designs still require their applicable
validation gates before release; specification acceptance is not an audit.

Implementation is partial; see [ARCHITECTURE.md §3](../ARCHITECTURE.md#3-components-and-trust-boundaries)
and the [plans index](../plans/README.md) for current coverage. Validation
scenarios are acceptance criteria, not evidence of completed validation.

## Process

- **File naming:** `NNNN-short-title.md`, numbers never reused.
- **Status lifecycle:**
  - `Exploratory`: options are being compared; nothing is decided.
  - `Draft`: a concrete proposal; may still change.
  - `Accepted`: agreed; implementation may start. Changes need an amendment
    noted in the spec's *Changelog*.
  - `Implemented`: matches the code.
  - `Superseded by NNNN`: replaced.
- **Normative language:** the key words MUST, MUST NOT, SHOULD, SHOULD NOT and
  MAY are used as described in RFC 2119 / RFC 8174.
- **Every spec has:** a metadata header, Summary, Specification, Security
  Considerations, Open Questions and Changelog.
- **Implementation** of accepted specs is planned and reviewed in
  [plans/](../plans/README.md); see [AGENTS.md](../AGENTS.md).

## Template

```markdown
# NNNN — Title

| Status | Created | Depends on |
|--------|---------|------------|
| Draft  | YYYY-MM-DD | 000X |

## Summary
## Motivation
## Specification
## Security Considerations
## Open Questions
## Changelog
```

0028 completion specifies all-kind conflict inspection/resolution, mandatory selected-slot proof, and working-source-slot fallback for local snapshot recovery (0004 §6.2, 0011 §4; 2026-10-31).
