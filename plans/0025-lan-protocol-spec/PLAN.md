# Plan 0025 — LAN sync protocol spec (roadmap 2.1)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-30 | 2026-10-30 (owner delegated D10: "whatever you think is best") | 0005 §6, OQ3–OQ6; 0001; 0002 §1, §3, §6; 0004 §2, §4; 0012 §3 (LAN gate) |

## Intent

Write the direct LAN sync protocol as a new `Draft` spec, so that milestone 2
can implement it once the owner accepts it. This phase resolves D10 (0005
OQ3–OQ6) as the owner delegated. It is spec-only: no code.

## Scope

**In scope:**
- spec `0013-lan-sync-protocol.md` (`Draft`):
  - discovery and addressing;
  - pairing, with optional new-device key transfer;
  - pairwise link keys;
  - the session handshake and record layer;
  - exchange messages, bounds and errors;
  - peer-state storage and rollback binding;
  - the receive window;
  - removal and generation transitions;
  - new-device initialization and crash ordering;
- the exact text of the amendments to the `Accepted` specs 0002 and 0004
  (and the 0001 leakage sentence), applied only when the owner accepts 0013;
- direct pointer edits to `Draft` 0005 (§5.4, §6.7, OQ3–OQ6);
- the `specs/README.md` index, `ARCHITECTURE.md` §3/§5/§6 and its open
  decisions;
- the D12 review request text.

**Out of scope:**
- code, crates and dependencies (phases 2.8–2.10 choose them, including an
  mDNS crate and X-Wing's crate);
- the CLI and app commands: the 0011 amendment comes with phase 2.10;
- interoperability vectors (0012 §3 requires them before release; they are
  generated with the implementation);
- D11 (0006 OQ2). The LAN design does not depend on it.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| LAN requirements | 0005 §6.1–6.7 | Draft | 0013 must satisfy every MUST |
| Threat model (T3 MITM, spoofed discovery; T5 hostile peer; T7) | 0001 | Accepted | |
| Profiles, purpose keys, rotation invalidates LAN approvals | 0002 §1, §3.3, §3.5.5–6, §6.1 | Accepted | Amendments are listed in 0013 |
| Peer-state schema deferred to 0005 §6 | 0004 §2 | Accepted | Amendment listed in 0013 |
| Budgets | 0004 §4 | Accepted | Reused |
| LAN gate | 0012 §3 | Accepted | Unchanged |

**Spec changes required:** a new spec 0013 (`Draft`); pointer edits to 0005
(`Draft`). Amendments to 0001, 0002 and 0004 are written out in 0013 §13 and
applied only on the owner's acceptance of 0013.

## Decisions needed

1. **D10 (0005 OQ3–OQ6).** The owner delegated it on 2026-10-30. Resolved as:
   - **OQ3:** endpoints come from the pairing QR or from manual entry
     (IP literal and port). DNS-SD discovery runs only while a receive
     window is open, with a random per-window instance name and no vault
     metadata. Every address is untrusted.
   - **OQ4:** an out-of-band pairing (QR or a 26-character code holding a
     128-bit secret, plus a committed comparison code) creates a
     **pairwise link key** per peer and generation. Only existing profiles
     are used: X-Wing draft-11, HKDF-SHA-512, MAC/1 and XChaCha20-Poly1305.
     Sessions authenticate with the link key and use a fresh X-Wing
     ephemeral each time. There are no device signing identities.
   - **OQ5:** an explicit, time-boxed receive window per unlocked vault,
     one session at a time; no background service.
   - **OQ6:** removal is local per link. Links are bound to the key
     generation (rotation drops all of them). Compromise means rotation
     plus fresh pairing.

   Rejected:
   - per-device signature identities: more composition, and ML-DSA arrives
     earlier;
   - a credential derived only from VK: any VK holder could then sync
     without approval, against 0005 §6.2;
   - TLS with pinned certificates: classical authentication would still
     need a hybrid signature on top.

   Blocks: nothing further. Resolution: delegated to and chosen by the
   session on 2026-10-30. Spec 0013 stays `Draft` until the owner accepts
   it.
2. **D12 (independent protocol review).** It remains pending with the
   owner. This plan only drafts the request.

## Design

**Components touched:** specs and docs only. The protocol lives in
`qv-protocol` (wire types, 2.8) and `qv-sync` (exchange, 2.10). Peer state
is stored in `qv-store` through the 1.7 write path.

**Protocol shape** (normative detail in 0013):
- **Transport:** TCP. Frames are a `u32` big-endian length plus a body.
  Pre-authentication frames are at most 4 KiB; authenticated records at
  most 1 MiB plus 64 bytes.
- **Pairing:** `PairHello` (committed B nonce, B's ephemeral X-Wing key, MAC
  with a key from the pairing secret), then `PairAccept` (A's nonce,
  ciphertext, MAC), then B's encrypted nonce reveal.
  - Both devices show a 6-digit code over the full transcript; A requires
    the user to confirm it before releasing anything.
  - In new-device mode A then sends a `Grant` (VK, vault ID, generation,
    profiles). In link mode both sides prove the same VK and generation
    with a key-confirmation MAC instead.
  - The link key is derived from the pairing secret, the KEM secret, the
    transcript and the new `lan-link` purpose key of the generation.
- **Session:** `SyncHello` with no identifier, which the responder
  trial-verifies against at most 64 links; then `SyncAccept` with an X-Wing
  ciphertext; then per-direction keys and AEAD records with counter
  nonces.
- **Exchange:** the state message, then both manifests, object requests and
  verified streaming. Each side merges through `qv-sync` and commits through
  the 1.7 path, then sends `Done`.
- **Peer state:** a local-only `lan_link` table, encrypted under
  `local-state`. A `lan_links_digest` in the local head binds the link set
  against row rollback.

**Secrets and hostile input:**
- The pairing secret, link keys, the KEM secret and session keys live in
  protected containers and are erased at the end of the window or session.
- Every bound is checked before allocation.
- Unauthenticated peers get no error oracle: the connection just closes.

**Errors:** in-session error codes are enumerated in 0013. Frontends map
them to 0011 exit codes in 2.10.

**Dependencies:** None (spec only).

## Steps

### Step 1 — Record D10

- [x] **Do:** the D10 resolution in roadmap 0002 *Decisions needed* and
  above.
- **Files:** `plans/0002-roadmap/PLAN.md`, this plan.
- **Done when:** D10 has a dated resolution naming 0013.
- **Verify:** `git diff --check`.

### Step 2 — Write 0013

- [x] **Do:** the spec, sections §1–§13 as in *Design*, with byte-level
  CBOR layouts, labels, bounds, state machines and error transitions.
  Mark it `Draft`. Every 0005 §6 MUST is traced in a coverage table.
- **Files:** `specs/0013-lan-sync-protocol.md`.
- **Done when:** every 0005 §6.1–6.7 requirement and every 0012 §3 LAN item
  maps to a section.
- **Verify:** `rg -n '^#{1,4} ' specs/0013-lan-sync-protocol.md`.

### Step 3 — Pointers and index

- [x] **Do:** in 0005, add a §6.7 pointer and mark OQ3–OQ6 as proposed in
  0013, with a Changelog line. Add the 0013 row to `specs/README.md`.
- **Files:** `specs/0005-synchronization.md`, `specs/README.md`.
- **Done when:** no remaining text says the LAN protocol is unselected
  without naming 0013.
- **Verify:** `rg -n 'OQ3|0013' specs/0005-synchronization.md specs/README.md`.

### Step 4 — Architecture and roadmap docs

- [x] **Do:** `ARCHITECTURE.md`:
  - §3 qv-protocol/qv-sync wording;
  - §5 LAN flow;
  - §6 technology row;
  - the open-decisions paragraph.

  Also `CHANGELOG.md`, and draft the D12 review request here.
- **Files:** `ARCHITECTURE.md`, `CHANGELOG.md`, this plan.
- **Done when:** the docs name 0013 as the Draft LAN protocol.
- **Verify:** `sh scripts/check-spdx.sh`; `git diff --check`.

### Step 5 — Spec self-check

- [x] **Do:** a `quickvault-reviewer` pass over 0013 against 0001, 0002,
  0005 §6 and 0012 §3. It runs in the same session, so it is not
  independent; the next session repeats it with fresh context.
- **Files:** `plans/0025-lan-protocol-spec/REVIEW.md`.
- **Done when:** findings are fixed or listed.
- **Verify:** the review file.

## Test plan

- No code. Gates: `sh scripts/check-spdx.sh` and `git diff --check` (the
  Rust gates are unaffected; they are not rerun unless code changes).
- 0012 §3 LAN items each map to a 0013 section (coverage table).
- Vectors: none. They are listed as a release requirement in 0013 §12.

## Risks and stop conditions

- If a 0005 §6 MUST cannot be met without a new primitive or profile family
  beyond `lan/1`, stop and ask.
- The amendments to `Accepted` specs are not applied without the owner's
  acceptance.
- Never claim the composition is secure; the D12 review is required.

## Documentation

- [x] `CHANGELOG.md`: Unreleased: Draft LAN protocol spec 0013.
- [x] `ARCHITECTURE.md`: §3, §5, §6 and open decisions.
- [x] Specs: new 0013; 0005 pointers and Changelog; `specs/README.md` index.
- [x] `AGENTS.md`: no change.

## D12 review request (draft for the owner to send)

> QuickVault, an AGPL offline-first password manager, asks for an
> independent review of its direct LAN sync protocol, spec
> `specs/0013-lan-sync-protocol.md` (Draft, 2026-10-30). Scope:
> - the pairing composition: a 128-bit out-of-band secret, X-Wing
>   draft-11 key encapsulation, a commit-then-reveal comparison code and
>   vault-key transfer;
> - the pairwise link-key derivation;
> - the session handshake (link-key MACs plus an ephemeral X-Wing exchange,
>   key confirmation);
> - the counter-nonce XChaCha20-Poly1305 record layer;
> - the lifecycle of ephemeral secrets and the error/abort transitions.
>
> Primitives are pinned in `specs/0002-cryptography.md`; the threat model is
> `specs/0001-threat-model.md`. We want confirmation or refutation of the
> properties claimed in 0013 §5.4 and the Security Considerations, plus any
> attacks on context binding, reflection, replay, comparison-code grinding
> or partial acceptance. Interoperability vectors follow with the
> implementation (roadmap 2.8–2.10).

## Revisions

None.

## Execution log

2026-10-30: The owner answered "whatever you think is best" to the D10
options. Session choice: pairwise link keys (better than the three OQ4
options first shown: per-peer approval and blocking with only symmetric,
PQ-safe authentication), QR/manual endpoints plus window-only discovery,
explicit receive windows and local, generation-bound removal. The plan
amends specs; the owner's delegation covers the D10 choice and drafting
0013. Accepting 0013 and applying its listed amendments to 0001, 0002 and
0004 remains the owner's call.

2026-10-30: Steps 2–5 done.
- 0013 was written as Draft (§1–§14).
- 0005 now points §6.7 and OQ3–OQ6 to 0013 (proposed resolution, OQ7) and
  has a Changelog line; the spec index has a 0013 row.
- `ARCHITECTURE.md` §5, §6, the server-revocation paragraph and the open
  decisions are updated; so is the CHANGELOG; the D12 request is drafted
  above.
- Self-check (REVIEW.md, same session, not independent): four fixes, the
  main one being B's confirmation before joining in new-device mode.
- SPDX passes and `git diff --check` is clean.

Plan status Implemented. The 0001, 0002 and 0004 amendments are not
applied (0013 §13). Next: owner acceptance, then D12.

2026-10-30: Owner direction: plans and specs need no separate review
session; only implementation does. The in-session check (REVIEW.md) is the
review of this spec-only plan. Status Reviewed. 0013 still awaits the
owner's acceptance and D12.

2026-10-30: The owner delegated acceptance ("whatever you feel is best").
0013 is now Accepted, and its §13 amendments to 0001, 0002, 0004 and 0005
are applied with Changelog lines. The roadmap ticks phase 2.1. The D12
request is still unsent (owner action; it blocks only the LAN release).
