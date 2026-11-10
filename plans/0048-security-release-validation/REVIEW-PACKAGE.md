# LAN/2 review package

Prepared 2026-11-09 against commit
`ee0cafdd56af1b9593445cb632f0f1be3e7e101a` (Rust 1.98.1).
No reviewer has been engaged and no material has been sent externally.

## Verdict and scope

**D12: pending independent review; LAN release remains blocked.** This package
prepares that review. The implementing agent's 0047 review, component audits,
development dependency exemptions and passing tests do not supply that verdict.
The server composition is outside this package and needs its own D12 review.

The current protocol is [0013 §15](../../specs/0013-lan-sync-protocol.md#15-credential-authenticated-lan-profile-0047-owner-approved-2026-11-09).
It supersedes the historical LAN/1 text and contradictory 0014 text. Read it
with [0012 §3–4](../../specs/0012-security-validation.md#3-release-gates),
the [implementation contract](../0047-audit-policy-and-lan-auth/LAN-CONTRACT.md)
and [local evidence](../0047-audit-policy-and-lan-auth/LAN-VALIDATION.md).
The exploratory diagrams under 0046 are design history, not this contract.

## Exact baseline

[source-baseline.sha256](evidence/source-baseline.sha256) identifies 110 files:
the protocol, crypto, sync, core authorization, storage/publication, frontend
integration, fixtures, dependency policy and prior evidence. It is a scoped
review inventory; the commit identifies the complete product source, including
callers not in the inventory. Verify from the repository root:

```sh
sha256sum -c plans/0048-security-release-validation/evidence/source-baseline.sha256
```

The package contains public source and synthetic vector material only. A later
code/dependency change needs a new baseline and review of its impact. Reports
must identify the actual commit, configuration and any differences they cover.
Do not attach personal vaults, credentials, device keys or unredacted captures.

## Review questions and trace

| Question | Primary sources | Required analysis |
|----------|-----------------|-------------------|
| Fixed engine and ephemeral registration | `qv-crypto/src/lan_auth{,_engine}.rs`; `qv-core/src/lan_auth.rs` | Verify A's exact working slot/head before local registration; fixed Ristretto255/TripleDh/SHA512, explicit 256 MiB/t3/p4 Argon2id, identities/context and message widths; no stored/imported verifier |
| Randomness and cleanup | Same crypto wrappers; `qv-crypto/src/memory.rs` | Review latched fallible RNG, termination poison and discard of every poisoned output; zeroizing KSF blocks and inter-flight state; dependency-private hash/OPRF/HMAC scratch limits |
| Outer and final composition | `qv-crypto/src/lan_v2.rs`; `qv-protocol/src/lan_v2.rs`; `qv-sync/src/lan/steps_v2.rs` | Review X-Wing/P/Z mixing, canonical J/T0/TA, role/intent/method/direction separation, record AAD/counters and permanent epoch transitions; no classical-to-PQ authentication inference |
| Password confirmation and grant | `qv-sync/src/lan/{approver,joiner}.rs`; core authorization | KE3 then final FinishedB before any grant; exact snapshot/policy/lock/deadline/sealer check and one seal under mutex; no mutex-held KDF/network/UI wait; receiver slot unwrap and VK equality before bulk |
| Independent VK proof | Crypto v2 and sync approver/joiner | PB before identity/PA, no grant/password gate, final B State before A data, enrollment versus existing-copy scope binding |
| Spent admission and deadlines | `qv-sync/src/lan/{window,approver,transport,joiner}.rs` | Listener closure/join and queued-stream disposal before credential work; no retry/reopening; one absolute deadline across prompts, KDF and publication; per-state idle bounds |
| Publication and outcomes | `qv-store/src/{lan_staging,lan_store,acceptance}.rs`; `qv-core/src/lan.rs` | Authenticate and bound all staging; private source/method capability and unique password head; preflight before no-replace publication; fresh local identity/anchor; preserve durable files after cancellation; distinguish disclosure, receipt, commit and publication |
| Hostile input and trust boundaries | Protocol frames/codecs; storage/model callers; app LAN | Bounds before allocation, authentication before payload parsing, unknown profiles fail closed, stale UI replies, secret-input clearing, no raw-key frontend publication capability |

Review tests as evidence of intended boundaries, not substitutes for analysis.
Include custom peers that skip every UI check, weak/incorrect credentials,
reflection/replay/context substitution, grant/password-change races, omitted or
modified FinishedB, lifecycle cancellation and post-publication/anchor faults.
The named regression inventory is in the 0047 local evidence linked above.

## Vectors and their limits

[LAN-V2.md](../../crates/qv-crypto/tests/vectors/LAN-V2.md) records generator
versions, upstream commit and source hashes. The Python/library-derived key and
wire fixtures cross-check encodings and schedules. Wire OPAQUE/slot fields are
synthetic shapes, not an end-to-end PAKE transcript. The pinned upstream OPAQUE
component fixture uses **Identity KSF for that component test only**; production
uses the separately tested explicit Argon2 suite. Neither fixture is independent
analysis of the QuickVault composition or complete error-transition coverage.

## Requested report

Record reviewer identity and independence, source/configuration scope,
techniques and exclusions, findings with severity and reproduction, and the
precise release verdict. For each issue, separate a demonstrated flaw from an
unproved assumption or missing evidence. Track repairs under an approved
spec/plan amendment, rerun affected evidence and obtain the reviewer's actual
retest disposition. Do not mark D12 complete with this checklist.

Owner selection of reviewer, spending and permitted material sharing remain
required before engagement. No external contact is authorized by preparation.
