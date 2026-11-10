# LAN contract — plan 0047

Normative byte/state registry: [0013 §15](../../specs/0013-lan-sync-protocol.md#15-credential-authenticated-lan-profile-0047-owner-approved-2026-11-09).
Owner approved implementation on 2026-11-09. This checklist is implementation
and review evidence, not a second protocol definition.

| Boundary | Exact rule / evidence required |
|----------|--------------------------------|
| Profiles | lan/2 only; lan-pake/1 for password; no legacy grant |
| Method/intent | password/enroll, key/enroll, key/sync; hello and accept bind both |
| Engine | opaque-ke 4.0.1 Ristretto255/TripleDh/SHA-512; KE1 96, KE2 320, KE3 64, Z 64; compiled serializer assertions pass |
| Stretching | Explicit Argon2id v1.3, 262144 KiB/t3/p4, 64 bytes, zero salt16; no engine defaults |
| RNG | Fallible OS source; centralized failure rejection and every-draw injection tests pass |
| Secrets | Protected inter-flight states and outputs; wiped KSF blocks; dependency-private scratch limits in DEPENDENCIES.md |
| Admission | Close every listener/advertisement after valid hello, before auth |
| Password transition | KE3 last epoch0; FinishedB first B epoch1; grant first A epoch1 |
| Key transition | PA last epoch0; State first B epoch1; no A epoch1 before verified State |
| Transcript | Exact complete canonical messages, T0/TA and J per §15; no variable concatenation |
| Grant | Snapshot check and one seal under session mutex; completed seal counts disclosed |
| Public descriptor | Defined keys0–6 only; 171 bytes, asserted by canonical codec test |
| Enrollment | Full private staging; grant descriptor/head binding or key-route capability; preflight before publish |
| Deadlines | Original A expiry; one B 10min deadline before first attempt, all waits/work included |
| Reporting | Distinguish seal/disclosure, receipt, local commit, publication and anchor |
| Release | External D12 composition review and target evidence remain open |

Review before crypto implementation: check this registry against the pinned
serializers, normative requirements, engine KSF/context/identities, RNG failure
behavior and secret lifetimes. Record findings in REVIEW.md; do not mark this
gate complete from this checklist alone. The registry is now implemented in qv-crypto/qv-protocol/qv-sync, with core
policy and frontend integration. Local review and evidence are recorded in
REVIEW.md and LAN-VALIDATION.md; external D12 remains open.
