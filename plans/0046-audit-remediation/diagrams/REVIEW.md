# Follow-up review — exploratory LAN authentication v2

| Verdict | Reviewed | Scope |
|---------|----------|-------|
| Changes requested | 2026-11-08 | Staged diagram/analysis follow-up to plan 0046; no production implementation |

## Summary

V2 makes useful progress: it locates proposed PAKE state inside the encrypted
keyslot record, gates the password-mode grant on KE3, and reuses key-possession
authentication for recovery. However, parts of its adversary analysis are
incorrect and the diagram omits an explicit owner-selected requirement.
Correct these before treating v2 as the basis for an implementation plan.

This review does not reject OPAQUE as a candidate, approve a cryptographic
composition, or change the initial code batch's Reviewed status. The proposed
record-key combiner, credential lifecycle and classical-authentication exception
still need a specification and independent review under 0012 §3.

## Inputs and conformance

- Reviewed the staged `ANALYSIS.md`, both Mermaid sources, render configuration,
  README, exports, Changelog and plan additions against the conversation and
  relevant sections of 0002, 0003, 0005, 0006, 0013 and 0014.
- No Rust, dependency, application configuration or normative spec changes are
  present in the reviewed staged set. The staged audit symlink is unchanged.
- The owner's explicit artifact-only verification direction applies: no Cargo
  commands were run for this documentation review.

## Findings

These are findings in an exploratory design and its explanation, not newly
demonstrated vulnerabilities in shipped code.

### R1 — Medium: server-state disclosure is incorrectly equated with client authentication

Location: `ANALYSIS.md:30` (F2), also the comparison at `ANALYSIS.md:89`.

Disclosure of OPAQUE server setup/registration does not by itself demonstrate
how to produce the legitimate client's KE3 without recovering its credential.
OPAQUE-3DH's client computation still requires its password-recovered private
key. Server-state compromise does permit offline password guessing; claiming
immediate VK release requires another demonstrated attack. If registration
replacement is intended, that is a separate integrity failure, not disclosure
alone. See [RFC 9807 §6.4.3](https://www.rfc-editor.org/rfc/rfc9807.html#section-6.4.3)
and [§10.11](https://www.rfc-editor.org/rfc/rfc9807.html#section-10.11).

Separately, the stolen-local-vault row cannot simply say "Nothing": its existing
password slot is already an offline guessing target (0002 §3.2, `PasswordSlot`
documentation). Encrypting the PAKE record does not remove that attack surface.

Requested change: retain the encrypted-state recommendation, correct F2 and
the affected table rows, and distinguish immediate authentication, offline
guessing and unauthenticated replacement. Remove conclusions built on the
unsupported immediate-bypass claim.

### R2 — Medium: the quantum exposure is incorrectly bounded by the live window

Location: `ANALYSIS.md:69`–`71`; the table at `ANALYSIS.md:86` only describes an
attacker who already has a quantum computer.

A code holder can participate and retain inner PAKE messages during the live
window, then analyze them after it closes. The future attacker need not possess
a quantum computer during that window. Distinguish this from passive outer
traffic capture: a successful hybrid transport can hide the inner messages
from an outsider, but not from a participating endpoint. The possible later
loss of a long-lived password is a different outcome from obtaining VK during
that expired session; a failed exchange that never sent a grant does not
retroactively contain one. The draft discussion of
[retroactive password recovery](https://datatracker.ietf.org/doc/html/draft-vos-cfrg-pqpake-03#section-11.3)
supports treating time of collection and time of analysis separately; it is
research context, not validation of this proposed composition.

Requested change: add the recorded-failed-attempt case, correct the time-window
argument and state the lifetime of the proposed classical exception accurately.
An OPAQUE recommendation may still be justified, but not by that argument.

### R3 — Medium: v2 does not carry forward explicit listener closure

Location: `lan-auth-v2.mmd:16`; `ANALYSIS.md:42` calls the single-session behavior
unchanged, and its amendment list omits the relevant §8.3 listener exception.

"One valid hello per window" does not mean "stop listening after accepting that
hello." The current 0013 §8.3 deliberately keeps probing additional connections
and is the mechanism involved in QV-005/006. The owner selected consuming the
code and closing the listener after the first valid code-authenticated attempt;
the original diagram explicitly records that action. V2 leaves it unspecified.

Requested change: put code consumption/listener closure in v2 immediately after
all hello checks succeed, and explicitly supersede second-hello probing for the
accepted session in the proposed §4.3/§8 amendments. Retain timeouts, lock and
cancel behavior for the established connection. This is a missing documented
requirement, not evidence that any new production code is defective.

### R4 — Low: new responder metadata disclosure is not equivalent to the old direction

Location: `ANALYSIS.md:98`–`102`; `lan-auth-v2.mmd:39`.

In the current VK-proof flow, an initiator supplies the vault ID/generation and
the responder checks it before replying. In v2, a code holder can instead ask
the responder to reveal its vault ID/generation before proving VK. Disclosure
in the opposite role does not establish permission for this new interaction.

Requested change: mark this as a proposed leakage-policy choice for the owner,
not already "Accepted leakage." Either justify it explicitly or distinguish
the restore bootstrap from ordinary existing-copy sync, as the analysis itself
suggests. This review does not choose that policy.

### R5 — Low: post-grant key confirmation is dismissed too broadly

Location: `ANALYSIS.md:31` (F3).

A MAC under a freshly delivered key is key confirmation; it does not establish
that the recipient knew the password before delivery. The original diagram
already says its MAC proves key possession, not which credential produced it.
V2 can reasonably remove an additional acknowledgement if its authenticated
grant, exchange and consistency checks supply the required confirmation, but
"proves nothing" conflates different guarantees.

Requested change: explain the narrower guarantee and why v2 no longer needs a
separate confirmation round. Do not treat that round as password authentication.

## Other implementation prerequisites

- Storing setup/registration with the keyslot is a plausible reuse of an atomic
  record, not zero-cost lifecycle support. Define registration validation,
  identity/context binding, recovery, slot selection/conflicts, credential
  replacement and creation/migration atomically with the matching descriptor.
- Before implementing the `k1`→`k2` switch, specify exact domain-separated
  derivation/encoding, per-direction switch points, strict phase decoding and
  old-key rejection. Resetting counters requires distinct new keys. The diagram's
  formula is a proposed composition, not an already-reviewed consequence of
  using HKDF or the account PAKE profile.
- Pin the actual crate/version before using an audit as dependency evidence.
  The published `opaque-ke` README says its June 2021 audit covered v0.5.0 and
  fixes landed in v1.2.0; that does not establish coverage of a future selected
  version. [Upstream audit statement](https://github.com/meta/opaque-ke#audit)
- Refusing legacy grant labels is useful, but the exact LAN profile/mode
  discrimination and absence of automatic downgrade need an explicit design.
- The F10 slot check establishes consistency with the typed password. It does
  not alone establish the intended vault's origin if an attacker already knows
  that password and can construct another consistent vault.

## Minor fix applied

`README.md` now distinguishes v1's grant-envelope/key-confirmation notation from
v2's PAKE-confirmed record-key proposal. Its unqualified claim that both routes
prove VK possession before transfer described v1, not the revised password path.
No cryptographic proposal, Mermaid source, export, accepted spec or dependency
was changed by the reviewer.

## Verification

| Check | Result |
|-------|--------|
| Mermaid rendering of both source versions | pass, local Mermaid CLI 12.0.0 |
| Checked-in SVG text vs fresh source renders | pass for both versions |
| PNG signature, chunk bounds and CRC checks | pass for both exports; v2 also visually inspected |
| Render configuration JSON and review/README local links | pass |
| Analysis, source, SVG, PNG and layout vs their staged versions | unchanged |
| `sh scripts/check-spdx.sh` | pass |
| `git diff --check HEAD` | pass |
| Cargo / dependency gates | not run; documentation-only scope, owner's explicit artifact-verification direction |

Rendering logs and scratch SVGs are under `/tmp/qv-auth-followup-47f96rxh/`;
the review and all user-facing artifacts are in this repository. No Cargo
commands, dependency changes, commits or staging operations were performed.

## Outcome

Return the analysis and v2 diagram for the corrections above, then use
quickvault-architect to specify the selected protocol before implementation.
The central direction remains password authentication before a VK grant, no
VK grant for a key-holding receiver, and one accepted connection per code.
