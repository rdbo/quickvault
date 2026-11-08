# QuickVault LAN enrollment — product-specific candidate v3

**Status: Exploratory, 2026-11-08.** Requested by the owner after the v2
review. This is a construction to analyze, not an accepted spec, implemented
feature, completed cryptographic analysis or security certification. Earlier
diagrams and their reviews remain historical proposals. Conformance to an
external document is not an acceptance criterion for this design.

The [follow-up review](REVIEW-v3-followup.md) identified migration, KDF and
grant-authorization gaps. Section 13 records proposed resolutions, requested
by the owner; they remain exploratory and have not received a follow-up verdict.

## 1. What this construction must accomplish

- Knowing the one-use code must not by itself yield VK or vault objects.
- A new receiver must complete password authentication before VK delivery,
  or independently obtain VK from its recovery words/existing unlocked copy.
- A failed password attempt must not give a classical attacker a portable
  offline password test. A fake emitter must not collect such a test from an
  honest receiver either.
- The first valid code-authenticated hello consumes the code and closes the
  listener. The accepted connection has its own bounded remaining lifetime;
  there is no competing-hello monitor to exhaust or keep polling.
- All authentication is bound to one connection, method and protocol version.
  An authenticated grant must open the intended context and match the password
  the receiver entered before bulk transfer or local publication.
- Preserve hybrid confidentiality for the transport. Keep separate, explicit
  assumptions for the password-authentication component; do not infer that
  protecting outer traffic makes every inner mechanism post-quantum.

An attacker already possessing VK can decrypt/forge same-generation data.
Malware controlling an unlocked endpoint is not stopped by this protocol.
Neither a MAC nor a password can establish which physical device a human meant
to approve without the intended source being identified through the user flow.

## 2. Product facts used by the construction

A is an explicitly selected, unlocked vault. B is an existing unlocked copy,
or a new installation with the password or recovery words. There is no account,
remote server, permanent peer identity or stored link. Recovery words directly
encode the 256-bit VK. Password changes replace its wrapping, not VK.

A retains VK, not the user's password-derived master key. Password enrollment
therefore needs credential state provisioned locally when the correct password
is available. Recovery and already-unlocked sync do not need that state.

The password authentication engine must use a reviewed implementation as a
component inside this QuickVault protocol. The concrete candidate is the
OPAQUE engine already investigated, rather than a new low-entropy password
proof invented from HMAC. Its role is to produce a mutually authenticated secret
`Z` without transmitting the password or giving an unsuccessful peer a reusable
offline test under its computational assumptions. The engine's serialized
messages are opaque fields of our own bounded messages.

Trusted registration and receiver input use the same existing password byte
bound and NFC normalization as vault unlock. The password-engine KDF is its own
fixed, reviewed local profile; it does not replace or reuse the vault wrapping
key as an authentication secret. Do not use a demonstration/no-work KDF or let
a peer request arbitrary parameters. Unknown profiles fail before KDF work.
The proposed initial cost and upgrade rules are in §13.2.

This candidate chooses that component for those properties and implementation
availability, not because its containing application must copy another
protocol's enrollment flow. No crate/version has been added or approved here.
The [upstream implementation](https://github.com/meta/opaque-ke) and its
[application API](https://docs.rs/opaque-ke/latest/opaque_ke/) are implementation
evidence, not proof of this composition. A historical audit is not evidence
that every later version or custom integration was covered.

## 3. State and storage boundaries

The encrypted password control record would contain an atomic pair:

1. The selected portable password-slot descriptor.
2. Secret password-authentication setup and registration state, its own profile,
   and a fresh credential epoch created when that password is registered.

The public local slot and secret control record must have **different types and
encoders**. The local slot exports only explicitly allowed password-wrapper
fields. Unknown encrypted-record extensions must never be copied into it.
The new representation must also exclude older readers, as specified in §13.1.

This is necessary for this repository, not just abstract hygiene:
`qv-model/src/payload/keyslot.rs` currently defines one map for both forms.
`qv-store/src/restore.rs` reads a decrypted keyslot record, calls `slot.encode()`
and places those bytes in `StoredSlot`. Simply adding secret setup to that map
or its extensions would make this restore path export it into the clear local
table. The proposal requires replacing that coupling before adding secret state.
There is no existing secret setup in that map today, so this is a prospective
implementation hazard, not a newly demonstrated current leak.

All application-owned passwords, setup state, temporary decoded records, key
material and authentication buffers use the existing protected/zeroizing Rust
containers. No secret-bearing Debug, errors, logs or argv. GUI/library/OS copies
retain the existing documented best-effort cleanup limits.

## 4. Message and key conventions

`P` is the random one-use code. `ss` is the X-Wing shared secret. `J` denotes a
new, explicitly incompatible LAN profile, to be assigned in a spec amendment.
`H` is SHA-256, MAC is the existing HMAC-SHA-512/32-byte-tag profile, and
extract/expand are HKDF-SHA-512. Record keys are 32 bytes and use the existing
authenticated-encryption primitive. These are building blocks, not new primitives.

Every transcript is a domain-separated deterministic CBOR array. `||` is used
only for fixed-length secret inputs from a selected fixed profile. Never splice
variable-length fields together without their encoding. All message tags,
directional key labels and context domains below are proposal names, not
registered wire strings or a substitute for an exact byte-level specification.

The outer transcript `T0` commits to J, the method, the exact accepted hello and
accept, ephemeral KEM material and nonces. Epoch-0 directional keys derive from
`HKDF-Extract(T0, ss || P)` under distinct sender/receiver labels. These protect
credential authentication, not a pre-authentication grant.
All fresh randomness comes from the existing OS RNG, and RNG failure aborts.

## 5. Common admission

1. A creates P, shows its code and starts a bounded window. Nothing starts in
   the background. B chooses `password` or `key` in its initial authenticated
   hello. Unknown/legacy profiles and methods are rejected, with no fallback.
2. Bound and validate the hello, check its code MAC before KEM work, then check
   its public key. On the first fully valid hello, consume P and **close every
   listening socket** before proceeding with that connection. Retain P only as
   protected key-schedule input for the active session until its scheduled wipe.
3. Establish the hybrid epoch-0 record keys and T0. For password enrollment,
   retain the committed comparison-code check and source-side approval before
   any password-authentication reply. A negative answer aborts.

Unauthenticated failures before acceptance retain a bounded admission budget.
Once accepted, exactly one credential attempt is permitted. A typo, malformed
message or failed proof ends the connection. Another attempt is a new explicit
window with a new code, not a retry on the old session.

## 6. Password method

A requires one unambiguous, validated password control record whose slot matches
its working local slot and policy. A conflict, missing setup or inconsistent
record refuses password enrollment; it never silently creates replacement state
from an untrusted client's registration.

A captures an immutable authentication snapshot including the selected record
head, credential epoch and generation. Recheck it before a grant: if password
credentials or generation changed, or the session locked/cancelled, abort.
Do not mix registration state from one version with a slot from another.
The snapshot comparison and grant sealing form one atomic authorization step
under the existing session mutex (§13.3); a separate earlier check is insufficient.

A creates a fresh random 32-byte value R and a context commitment:

`C = H(CBOR([context-domain, R, vault_id, generation, credential_epoch, slot_id]))`.

A sends only C and the fixed password-authentication profile under epoch 0.
It does not send the password slot, commitment-to-KEK, setup state, vault name,
vault ID or key generation before authentication. R is revealed only later.
The randomized commitment binds the eventual grant without exposing the stable
vault identifiers at this point.

B enters its password locally. Both run the password authentication engine with
context bound to `[J, T0, password-method, auth_profile, C]` and distinct fixed
client/server role identities. The server's internal credential identifier is
bound to its selected vault/generation/slot/epoch; registration uses those same
role identities. B need not know that internal identifier or the secret setup.

B verifies the emitter-side authentication before producing its final reply.
A verifies the receiver's final reply. Only successful completion produces Z
and permits the session to advance. No application-defined password MAC is
sent as a substitute for this exchange.

The complete engine messages, context and T0 enter the authenticated transcript
`TA`. C is opened and checked when the grant arrives, before accepting its
identity or slot. The exact engine integration and this hiding/binding context
choice require composition review; they are not assumed secure merely because
each constituent is reviewed.

## 7. Key method: recovery words or existing unlocked copy

B already has VK, so A never sends it one. To avoid the new responder-ID leak
identified in v2, B first proves key possession **without asking A for stable
vault metadata**:

- Derive a session-specific bootstrap secret Z from VK and T0 with a dedicated
  `key-authentication` purpose. This is a high-entropy VK proof, not a proof
  keyed by a human password.
- B sends `MAC(Z, CBOR([receiver-ready, J, T0]))` under epoch 0.
- A verifies before sending its identity. On success it sends M containing
  vault ID/generation and its distinct role-bound MAC over T0 and H(M).
- B verifies that response; an existing copy also checks M against its known
  vault/generation. A phrase-based receiver adopts the authenticated identity.
  B returns a distinct acknowledgement bound to H(M), which A verifies.

TA commits to this complete exchange, including M. Domain labels must separate
the two role proofs and acknowledgement. A wrong key/generation aborts; no
proof is silently retried under other stored keys.

This is a proposed replacement for the existing ID-dependent bootstrap proof,
not a claim that the existing wire format already supports it.

## 8. The authenticated record-key transition

After successful password authentication or mutual VK authentication:

`root1 = HKDF-Extract(salt = TA, IKM = ss || P || Z)`.

Derive independent epoch-1 keys with labels binding J, the method, TA, epoch 1,
and each direction. Epoch-0 labels are distinct. Transcript hashes include the
complete canonical authentication messages, not just an informal summary.

B switches after sending its last required epoch-0 authentication record. A
switches only after verifying that record. A sends `FinishedA` as its first
epoch-1 record; B verifies and returns `FinishedB` as its first epoch-1 record.
A verifies it before a grant or object transfer. Both Finished messages commit
to J, method, TA and the appropriate role. No epoch-0 records are accepted after
the switch; no trial-decrypt fallback, in-place retry or counter reset under an
old key is permitted. Counters start at zero only for the distinct new keys.
Frame/AAD and state-machine details must make those boundaries unambiguous.
Both Finished messages are retained in this candidate (§13.4).

This makes credential authentication part of the keys protecting subsequent
traffic. It is a candidate composition requiring analysis, not an assertion
that concatenating secrets automatically provides a proven hybrid guarantee.

## 9. Grant, transfer and local creation

Password method only: A sends an epoch-1 grant containing VK, R, the committed
identity/epoch/slot fields, the selected **public** slot descriptor and the
selected encrypted-record head identity. It never exports the secret setup
outside its VK-encrypted record as part of this grant.

B checks C's opening and all identity/profile/slot bindings, unwraps the public
slot with the password it entered and compares the result with the granted VK
in constant time. This check occurs **before bulk transfer**, allowing the raw
password and temporary master/wrapping keys to be wiped promptly instead of
retained while up to 1 GiB transfers. B acknowledges the authenticated grant.
This is consistency checking, not the emitter's credential-authentication gate;
that gate already ran before the grant.

Key method: no grant, password slot or password prompt is needed to authenticate
the network peer. Both sides already hold VK.

Only then does the complete bounded ciphertext exchange run. Verify its
commitments, objects, selected control-record/descriptor consistency and model
limits before publication. Keep the existing 1 GiB referenced-ciphertext budget.
Bound the text cache through eviction/batched reads, not by rejecting a vault
whose total searchable text exceeds 64 MiB. The backend must support that policy
before this design can promise larger searchable-text capacity. For a new vault,
require confirmation of the received vault name and destination before publication;
never accept a partial vault or feed exchanged SQLite into the store. Existing
copy sync keeps its merge/snapshot/anchor rules. New local creation uses fresh
replica/writer/anchor state and reports durable outcomes accurately.

A phrase-only receiver must not be forced through a second master-password
gate after authentication. Local creation needs an explicit recovery-capable
API/session path; it preserves authenticated password records and does not
silently reset the shared password. Creating/resetting a password or enabling
quick unlock remains a separate explicit operation. That persistence interface
is an implementation prerequisite, not already implemented behavior.

## 10. Credential lifecycle

- **Creation/setup:** register locally on the trusted device while the validated
  password is available. Verify its local slot first. Never accept bootstrap
  registration from an unauthenticated peer.
- **Password change:** generate a new credential epoch and state for the new
  password; atomically replace it with its matching slot record. Preserve the
  store's commit/anchor ordering. No half-updated or silently stale verifier.
  Authentication against the old state cannot authorize a grant after the
  replacement commits. A grant already authorized and sealed is treated as
  disclosed for revocation purposes, even if delivery is unconfirmed (§13.3).
  Compromise recovery still needs VK rotation rather than a promise that a
  password change or cancellation erases a peer's key.
- **Conflicts:** retain the working local unlock slot. Do not auto-select a
  conflicting password credential for enrollment. Key-authenticated sync may
  still exchange conflicts so they can be resolved.
- **Existing vaults:** explicit setup on a trusted password unlock or trusted
  password reauthentication. Missing state disables only password enrollment;
  it must not break ordinary offline unlock or key-authenticated sync/recovery.
- **Rotation/recovery:** VK rotation rebuilds and rebinds state to the new
  generation. A password reset uses the password-change transition, not an
  unauthenticated registration shortcut. Old copied credentials cannot be
  retroactively erased; their exact capabilities must be documented.

## 11. Attack worksheet

| Attacker/action | Required result / reasoning to verify |
|-----------------|----------------------------------------|
| Records traffic, without code or either credential | Hybrid transport hides authentication and payloads while its assumptions hold. |
| Has code, no password/VK, accepted by mistake | One password-engine attempt; no grant, object stream, public slot or application password proof on failure. |
| Fake emitter solicits a real user's password | The engine must authenticate its responder before the client's final proof; no reusable offline test under the engine's assumptions. Human confirmation and vault-name checks remain part of intended-device selection. |
| Relays authentication between two different sessions | T0/context binding changes TA and epoch-1 keys; cross-session proofs and Finished messages must fail. |
| Reflects a proof back to its sender | Role/purpose separation rejects it. |
| Changes password/key method, profile, commitment or identity opening | Transcript, engine authentication, commitment or record authentication must reject it. |
| Floods connections after the valid hello | Listener is already closed. No monitor/failure-counter interaction can disable authentication. |
| Replays old traffic at a key switch or reconnect | Fresh transcript/keys, strict epoch state and monotonic counters reject it. |
| Has an old-generation VK | Key proof fails against current VK; no automatic generation downgrade. |
| Steals a local vault file | Its existing password slot already permits offline guessing. Keeping authentication state encrypted does not remove that fact. |
| Gets password-authentication server state | Enables offline guessing/server impersonation under the engine's model, not automatically a legitimate client proof. Confidentiality and authenticated registration replacement are separate requirements. |
| Records an inner password exchange as an active code holder | Treat later cryptanalysis separately from the short window. The selected classical password engine does not promise post-quantum credential hiding; a failed session contains no retroactive VK grant. |
| Changes an authenticated received vault before local publication | Object commitments and model validation reject it; cache policy is preflighted first. |

One rejected shortcut was exercised with synthetic data: a fake emitter chooses
a public salt/challenge and receives `HMAC(KDF(password), transcript)` from B.
It can recognize the correct candidate from a small offline dictionary without
another connection. Increasing KDF cost slows that attack; it does not remove
the target. This is an executable counterexample to the shortcut, not a test
or proof of this candidate.

Likewise, sending a password-wrapped VK before authentication exports an offline
target. Sending the password itself through an untrusted endpoint's encrypted
channel exposes it to that endpoint. Neither satisfies the chosen contract.

## 12. Evidence required before implementation

This document selects a product-specific structure, not a safe-to-ship byte
protocol. Require a reviewed profile/engine version and its actual audit scope,
an exact bounded message/encoding/AAD registry, state-machine and replay review,
secret-lifetime review, transactional credential migration, and adversarial
tests against each row above. Check the new key schedule and key transition
independently rather than attributing their security to the component library.

All required Accepted-spec amendments and a concrete implementation plan come
before production changes. No old code-only VK grant is retained as a fallback.
No production code, dependency, accepted spec or persistent user data is changed
by this exploratory document.

## 13. Proposed resolutions to the follow-up review

These are concrete design recommendations, not implementation changes or a
claim that the review findings have been independently closed. The existing
sequence diagram still shows the selected flow, including both Finished
messages; these refinements specify its storage and authorization boundaries.

### 13.1. F1: incompatible storage migration and explicit public-slot export

Use distinct model types for `PublicPasswordSlot` and `PasswordControlV2`.
The latter contains the public descriptor and protected authentication state;
it has no generic conversion to a clear local slot. Only an explicit
`public_descriptor()` projection can feed the local-slot encoder or a grant.
The public encoder allows exactly its defined fields, with no copied extension
map. These names describe proposed interfaces, not existing Rust APIs.

Make the new control payload structurally incompatible with the old bare-slot
map, rather than hiding setup state in optional extensions. A tagged container
with the descriptor and protected setup as separate members provides that
boundary. The precise bounded encoding is assigned in the spec amendment.
Old keyslot decoders must reject the entire payload instead of round-tripping
unknown secret fields.

Also introduce new development file and archive format versions and the new
LAN profile J. Check them at every entry point: local open, restore, ordinary
and self-contained archive import, and LAN exchange. Required configuration
must survive export and merge; never emit a legacy container containing the
new credential representation. Do not silently strip authentication state to
make a legacy export. Structural rejection supplements the container gates.

New software may read the old format through an explicit migration path. It
must complete the format upgrade before persisting authentication state.
Prepare and verify a private replacement, then publish through the existing
durable replacement/anchor process; specify its crash recovery before coding.
Keep VK unchanged for this format migration. Existing offline unlock and
key-authenticated operation remain possible without provisioned password auth.
Pre-upgrade backups remain old copies; the migration cannot revoke them.

**User-visible consequence:** older apps cannot open upgraded vaults or read
new-format archives. This is an intentional compatibility break. The UI must
explain it before an existing vault is upgraded.

Required evidence: old-reader rejection fixtures for both the new containers
and extracted control payload; projection tests with injected secret/unknown
fields; migration crash points; restore/import/export tests proving that
neither setup bytes nor their extensions enter the clear local-slot table.

### 13.2. F2: an explicit authentication KDF profile

For the initial candidate, use Argon2id v1.3 with **256 MiB, t=3, p=4** as
the authentication engine's stretching step. This starts from the current
vault-wrapping profile's work parameters. Use the reviewed engine's configured
Argon2 adapter on its OPRF-derived input; do not substitute MK/KEK, invent a
password prehash or silently accept the library's defaults. The selected suite
fixes the output size and adapter semantics. Each registration uses fresh
random secret setup and the same validated normalized password as its slot.

Assign a separate immutable authentication-profile ID with exact parameters.
J admits only supported, assessed authentication/wrapping-profile pairs.
Unknown or disallowed pairs fail before work; no peer-supplied tuning knobs.
If a later wrapping profile raises the supported cost floor, either re-register
and atomically publish the matching authentication state during trusted
password reauthentication, or disable password enrollment until that upgrade
can happen. Do not keep enrolling through a weaker state by silent fallback.
Registration needs the password; VK alone cannot perform this upgrade.

This is a defensible starting cost, not proof of equivalent attack resistance.
Before acceptance, trace a leaked-state offline guess through the exact pinned
suite, verify that every candidate requiring password validation incurs the
intended stretching work, and compare that path with the wrapping-slot guess.
Benchmark both on supported devices. The component exposes configurable
[KSF parameters](https://docs.rs/opaque-ke/4.0.1/opaque_ke/#custom-ksf-and-parameters);
our adapter configuration and its review remain necessary.

Perform authentication stretching and the later slot check sequentially,
releasing scratch memory between them: this adds KDF latency but does not
require two simultaneous 256 MiB scratch allocations for one enrollment.
Enforce the app's KDF concurrency budget across local operations. A target
that cannot run the chosen profile must report that limitation without
silently reducing its cost. The parameters remain subject to the existing
pre-release device benchmarking requirement.

Older copied slots, authentication records and backups retain their original
guessing cost. Upgrading the current profile cannot erase those targets or
strengthen a password already recovered from one of them.

### 13.3. F3: one atomic authorization step, with an honest revocation boundary

Capture an immutable authentication handle when the exchange starts: session
tag, vault ID/generation, selected slot ID, credential identity and exact
control-record head. Do not give the transport an independently reusable VK
or permission to construct its own grant.

After authentication and FinishedB, call one session operation that:

1. Takes the existing session mutex for a short local operation.
2. Rechecks the handle against the current unlocked state, exact credential
   head, generation, policy, expiry and cancellation/lock flags.
3. Constructs the grant from that same state and seals it once under the
   authenticated session's final send key/counter.
4. Checks cancellation again before returning the sealed record, discarding
   it and aborting the connection if cancellation was observed.

Password changes and grant creation serialize on that mutex. If the password
change commits first, the handle is stale and no grant is returned. If grant
creation completes first, it was authorized against the then-current password.
Never rewind a consumed record counter or reuse that grant on another session.

Send outside the session mutex, with a final cancellation check before the
first write. Invalidation closes the connection and discards pending output
where possible. A cancellation observed after sealing ends the connection;
it does not retry the grant. Avoid holding a lock while awaiting the network.

**Disclosure boundary:** once authorization and sealing complete, conservatively
treat the key as disclosed for revocation decisions. Socket buffers and partial
writes make reliable recall impossible. A password change or lock racing after
that point may stop transmission, but cannot promise to do so. Report an
authorized but unconfirmed transfer accordingly. This explicitly replaces the
earlier ambiguous promise that every "uncompleted" grant can be revoked.

Required tests cover both mutex orderings, lock/cancel during sealing, sealed
but unsent cancellation, partial writes, disconnects and durable password-change
failures. None may cause a second grant, counter reuse or a false claim that
key disclosure was reversed.

### 13.4. F4: retain explicit confirmation of the combined traffic keys

Keep FinishedA and FinishedB under distinct final directional keys, bound to
the full transcript and roles. A accepts FinishedB before the atomic grant
operation. This preserves explicit evidence that B derived the final composed
keys, rather than relying on the later application exchange to discover a
mismatch. It costs two small records and one round trip on the LAN.

Removing that pair could be analyzed as an optimization later, but provides
little product benefit compared with KDF work and bulk transfer. Keep the
current flow while resolving storage and credential-lifecycle integration.
Other message-count simplifications remain recommendations for separate
analysis; they are not silently applied here.
