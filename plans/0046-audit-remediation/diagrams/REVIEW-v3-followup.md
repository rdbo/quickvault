# Follow-up review — exploratory LAN enrollment v3

| Verdict | Reviewed | Scope |
|---------|----------|-------|
| Changes requested — design and review only | 2026-11-08 | `DESIGN-v3.md`, `lan-auth-v3.mmd`, and the simplifications in `REVIEW-v3.md`; relevant current storage, credential and LAN paths |

## Summary

No credential-check bypass was demonstrated in the v3 construction during this
review. Its central rules remain appropriate: consume the code and close the
listener, authenticate before granting VK, bind authentication to the session,
and grant no key to a receiver that already holds it. This is another review of
an exploratory construction, not an independent cryptographic audit or an
approval to implement or release it.

The earlier simplification review contains useful recommendations, but its
claim that every guarantee remains identical is too strong. Three design gaps
and one guarantee clarification need attention before a concrete protocol and
implementation plan. No security-sensitive design change was applied here.

## Findings

### F1 — Medium: the secret-state migration must exclude older readers

Location: `DESIGN-v3.md:74` (different types/encoders),
`REVIEW-v3.md:195` (encoder split prerequisite).

The proposed encoder split fixes new code. It does not stop an older binary
from decoding a new encrypted record's authentication state as an unknown
extension and copying it to the clear local slot during restore. Current
`crates/qv-model/src/payload/keyslot.rs:95` preserves unknown fields and its
encoder writes them back; `crates/qv-store/src/restore.rs:153` encodes the record
and lines 161–165 install those bytes in the local slot table.

This is conditional on retaining a representation that those readers accept;
v3 has not chosen the new physical representation. No current authentication
state leak is demonstrated because the proposed state does not yet exist.
However, a new LAN profile alone cannot exclude old file/archive readers.

**Required direction:** make the storage migration explicitly incompatible
where necessary, so every affected old open/restore/import path rejects the
new representation before copying secret fields. Specify this together with
the encoder separation. The header already has a fail-closed development
format (`crates/qv-store/src/header.rs:33` and `:138`); select the exact gates
for files, archives and merge paths in the storage amendment. Include an
old-reader rejection fixture and a new-reader test proving that secret fields
never enter local-slot serialization. Pre-1.0 format volatility permits this
change; it does not itself make old readers reject a new record.

Action: escalated as a migration requirement.

### F2 — Medium: “no worse than the password slot” needs a concrete KDF comparison

Location: `DESIGN-v3.md:51`, `REVIEW-v3.md:104`.

V3 requires a fixed reviewed authentication KDF but leaves its parameters
unselected. The previous review nevertheless calls leaked authentication state
“no worse than” the existing password slot. That comparison is not established:
the state creates another password-guessing target, and a cheaper stretching
profile could make recovering the same password substantially easier. Keeping
the state VK-encrypted limits exposure but does not justify that claim after
the very disclosure being analyzed. Leaked server state also supports emitter
impersonation under the component's model, as v3 itself acknowledges.

**Required direction:** specify and assess the actual authentication KDF and
offline guessing path against QuickVault's password-wrapping profile, including
future upgrades and retained older credentials. Require an explicit supported
cost floor and forbid silent library defaults. Do not equate using Argon2 in
both places with equal resistance. This does not authorize executing work
factors supplied by the peer.

The implementation's own [versioned KSF documentation](https://docs.rs/opaque-ke/4.0.1/opaque_ke/#custom-ksf-and-parameters)
confirms that stretching parameters are configurable and determine offline
guessing resistance; it does not establish our eventual profile's cost.

Action: escalated; no weaker KDF or actual regression was demonstrated because
no profile has been selected or implemented.

### F3 — Medium: credential rechecking needs a defined atomic grant boundary

Location: `DESIGN-v3.md:136` and `:255`.

“Recheck before a grant” and “an uncompleted grant based on the old state
aborts” leave the critical concurrency boundary unspecified. A separate
snapshot check followed by grant construction permits this ordering: check the
old head, commit a password change, then seal a grant authorized by the old
authentication. There is also a distinction between a sealed record and one
already written to the socket.

The existing adapter makes that distinction concrete:
`crates/qv-core/src/lan.rs:629` seals inside a short session read, then its
caller sends outside it. Waiting on the network under the session mutex would
conflict with the current lock/cancellation architecture.

**Required direction:** define the grant authorization point and perform the
snapshot comparison, session/generation validation and grant sealing against
one consistent protected state. Specify cancellation and queued-record handling
around that point without holding a session lock across network I/O. Tests
must exercise a password change or lock between authentication and sealing,
and cancellation after sealing but before send. Do not promise revocation of
key material already transmitted.

Action: escalated as an implementation-contract gap, not a demonstrated race
in implemented v3 code.

### F4 — Low: removing Finished changes which key is explicitly confirmed

Location: `REVIEW-v3.md:64` and `:180`.

The password engine confirms its own session secret. It does not confirm the
application's `HKDF(ss || P || Z, TA)` traffic keys. With v3's Finished pair,
A receives a valid record under those final keys before sending the grant.
In the proposed simplification, the grant is A's first final-key record; A
has not yet received such a record from B. Thus “the same check ... with
nothing released before it” is inaccurate for that explicit confirmation
property. The commitment-removal discussion also incorrectly calls the grant
v3's first epoch-1 record: v3 sends Finished first.

This is not an identified password bypass or evidence that the simpler flow
exposes a decryptable VK to someone without credentials. Authentication still
precedes the grant, and a mismatched traffic key makes that grant unreadable.
The simpler exchange may be acceptable, but it deliberately replaces explicit
pre-grant confirmation of the combined keys with confirmation through later
application records. State and review that choice instead of treating the two
state machines as identical.

Action: escalated as a correction to the prior review's rationale; Finished
messages were neither removed nor added by this review.

## Disposition of the other simplifications

| Prior item | Follow-up assessment |
|------------|----------------------|
| V1: remove C/R | Reasonable candidate. No independent protection against selecting a wrong vault with the same password was established. Carry identity under authenticated final keys; retain exact session/context binding. |
| V3: fold acknowledgements into exchange start | Reasonable if B's first accepted application message occurs after every required check and covers the intended state. Specify the transition and resulting failure reporting. |
| V4: combine Reveal and KE1 | Reasonable subject to bounded buffering, checking the commitment and retaining approval before any password-dependent response. This changes input timing/latency, not the credential gate. |
| V5: prefer augmented authentication | Failure containment is a useful product rationale. Qualify the leaked-state comparison as F2. The exact comparative quantum operation counts are not established by this review; do not treat them as measured attack costs for an unselected suite. |
| V6: separate MAC and schedule outputs | Sensible domain separation. No concrete attack on the existing symbolic Z reuse was demonstrated. |
| V7: remove credential epoch | A stable slot/registration identity may suffice. Keep the live record-head snapshot separate from the identifier used at registration; a later record version is not automatically an interchangeable registration identifier. |
| V8: separate cache work | Agree. Keep the selected 1 GiB ciphertext budget and track the 64 MiB cache redesign separately. Recovery-capable publication remains an integration prerequisite. |

## Plan conformance and fixes

The requested follow-up is complete. Reviewed the construction and prior review
against relevant 0002, 0008, 0012 and 0013 requirements, then followed the actual
slot encoder, restore, password-change, rotation and grant paths. Normative
specs remain unchanged; differences proposed by this exploratory design are
not silently approved as implemented behavior.

Only this report, review navigation, the plan log/index and changelog were
changed. Previous designs, reviews, Mermaid sources and exports were preserved.
No production, protocol or dependency changes or staging operations were made.

## Verification

- Read-only source tracing; no v3 implementation or execution attack test.
- `sh scripts/check-spdx.sh`: pass.
- `git diff --check HEAD`: pass.
- Changed Markdown links: checked locally, pass.
- No Cargo commands: documentation-only review, following the owner's earlier
  instruction about this scope. No dependency change, so deny/vet not run.

These checks do not establish cryptographic security.

## Next design work

Refine the candidate with an incompatible secret-state migration, an assessed
authentication KDF profile and an explicit atomic grant authorization boundary.
Then specify the chosen confirmation/acknowledgement state machine and its
failure behavior. These are inputs to the architect stage before production
implementation, not a request for the owner to settle cryptographic details.
