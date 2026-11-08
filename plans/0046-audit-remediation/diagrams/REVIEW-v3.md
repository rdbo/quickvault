# Review — exploratory LAN enrollment v3

| Verdict | Reviewed | Scope |
|---------|----------|-------|
| Sound direction, simplify before specifying | 2026-11-08 | `DESIGN-v3.md`, `lan-auth-v3.mmd`; no production code |

Judged by one test, at the owner's direction: does each part protect *this*
product against a real attacker? Conformance to external documents is not a
criterion. This review is not a security proof (0012).

## Summary

v3 fixes everything the v2 review raised (R1–R5): listener closure after the
first valid hello, the harvest-now/analyze-later case, no responder metadata
before proof, and accurate wording on key confirmation. It also finds a real
repository hazard. Its key method is better than v2's.

It has, however, gained ceremony that costs round trips and spec surface
without stopping any attacker. Removing that ceremony takes the password path
from nine messages to four, and the key path from five to two. The guarantees
stay the same (§2).

## 1. What v3 gets right (keep)

- **One accepted connection, one attempt.** The code is consumed and every
  listener closed on the first fully valid hello. This removes the QV-005/006
  monitor surface instead of patching it.
- **Key method sends nothing before proof.** B proves VK with a key derived
  from VK and T0, so no vault ID is needed first. A reveals the identity only
  after verifying. This fixes the leak in v2 properly.
- **Separate encoders (§3).** Verified: `qv-store/src/restore.rs:153` encodes
  the decrypted keyslot record payload, including its `ext` unknown keys
  (`qv-model/src/payload/keyslot.rs:35`), and stores those bytes as the
  cleartext local slot. Any secret added to that record or its extensions
  would be written to disk in the clear. This is a hard prerequisite.
- **Slot check before bulk transfer.** B wipes the password and its derived
  keys before receiving up to 1 GiB, instead of holding them for the whole
  transfer. This fits our product well.
- **The rejected HMAC shortcut** is shown with a working counterexample: a fake
  emitter turns `HMAC(KDF(password), transcript)` into an offline test. That
  is why a real PAKE is necessary here, whatever any RFC says.
- No legacy fallback, and exactly one attempt per code.

## 2. Findings

### V1 — Medium (complexity): the context commitment `C`/`R` stops no attacker

A sends `C = H(R, vault_id, generation, epoch, slot_id)` before
authentication and opens it in the grant. But:
- B cannot check `C` until the grant arrives. The grant is the first
  epoch-1 record, and its AEAD already authenticates those same fields under
  keys bound to TA, from a peer that has already passed the PAKE.
- It does not help in the one real misbinding case: the same password used
  in two vaults, and B scans the wrong vault's code. The PAKE and the slot
  check both pass, and only B's vault-name confirmation catches it. `C`
  changes nothing there.
- A's internal consistency (registration and slot from one record version)
  is A's own invariant. B's slot check catches any mismatch anyway.

**Change:** drop `C`, `R` and the "profile" message. The profile is fixed by
`J`; unknown values fail at the hello. Nothing identity-related is sent before
authentication, and the identity travels in the grant.

### V2 — Medium (complexity): `FinishedA`/`FinishedB` repeat confirmations already made

- Password method: the engine is already mutually confirming. B checks A's
  authentication inside KE2 before it sends KE3, and A checks KE3 before
  anything else.
- Key method: `proof_B` and `proof_A` are already mutual proofs bound to the
  transcript.
- In both cases, a peer with different epoch-1 keys fails the AEAD on the
  first epoch-1 record anyway.

The Finished pair costs a full round trip and two more labels for nothing.

**Change:** remove both. The rule becomes: A's first epoch-1 record is the
grant (password method); B's first epoch-1 record is its exchange start (key
method).

### V3 — Low (complexity): `GrantAccepted` and the key-method acknowledgement are redundant

- B is already the exchange initiator (0013 §7). Its first exchange message,
  sent after the grant checks, *is* the acceptance.
- In the key method, TA includes `M`. If B had seen a different `M`, its
  epoch-1 keys would differ, and its first record would fail. A separate
  acknowledgement bound to `H(M)` adds nothing.

**Change:** remove both.

### V4 — Low (UX and latency): approval ordering costs a round trip

KE1 is blinded and reveals nothing about the password. B can send `Reveal`
and `KE1` together. A holds KE1 and answers with KE2 only after its user
approves the codes. The guarantee is the same (no password-dependent reply
before approval), with one message fewer. Also, B's user types the password
while the codes are being compared, rather than afterwards.

### V5 — Low (rationale): justify the PAKE choice by our product, not availability

§2 picks the engine for "properties and implementation availability". The
reason specific to our product is stronger and belongs in the design:
- While A's state stays VK-encrypted, an augmented PAKE buys nothing over a
  balanced one, because only VK holders can read that state.
- The difference shows if the state **escapes** VK encryption, which is
  exactly the §3 hazard. Leaked OPAQUE server state allows only offline
  guessing, which is no worse than the password slot already in every vault
  file. A leaked balanced-PAKE secret would let a file thief who also sees a
  code take VK **without the password**.
- The cost to record is quantum: a code holder who records a failed attempt
  and later gets a quantum computer needs one discrete log against OPAQUE,
  then Argon2id work per guess. Against CPace it needs one discrete log per
  guess. Either way the exposure is the long-lived password, not VK.

Recommendation: keep the augmented engine for that failure-containment
reason, and record the trade-off.

### V6 — Low (precision): one key, two jobs, in the key method

In the key method, `Z` is both the MAC key for the proofs and the input to
`root1`. Derive two outputs from VK under distinct labels (`key-auth-mac`,
`key-auth-schedule`). The password method already has this right: the engine
outputs a session key, and the MACs are inside the engine.

### V7 — Low (precision): "credential epoch" duplicates identifiers we already have

The registration and the slot live in one record version. That version ID
already names the exact credential, and a password change also produces a new
`slot_id`. A's snapshot check can therefore be: "abort if the vault locks or
any commit changes the keyslot record head during the session". No new epoch
field is needed.

### V8 — Scope: storage items do not belong in the authentication design

§9's text-cache eviction and "not rejecting vaults over 64 MiB of searchable
text" is a separate assessment item about storage capacity. Leaving it here
makes the authentication protocol wait on a backend change. Move it to its own
plan step. The recovery-capable creation path, which publishes without forcing
a password reset, is needed regardless, so track it as a prerequisite and not
as protocol text.

## 3. Simplified flow (v3 with V1–V7 applied)

Common, unchanged from v3: QR `P` → Hello (method, `commit_B`, `ek_B`, code
MAC) → A checks the MAC, then the key, consumes the code and **closes all
listeners** → Accept → T0 and epoch-0 keys.

**Password method** (4 messages, then the exchange):
1. B → `Reveal + KE1`, with the engine context bound to `J`, T0 and the method.
2. Both show the committed code. A's user approves. A → `KE2`.
3. B opens the envelope (failure means a wrong password or a fake emitter, so
   abort) → `KE3`. B switches to epoch 1.
4. A checks KE3, checks that the vault is still unlocked and the keyslot head
   unchanged, and switches. A → `Grant {VK, vault_id, generation,
   record version, public slot}` as its first epoch-1 record.
5. B unwraps the slot with the typed password and compares it with VK in
   constant time. B wipes the password and keys, confirms the vault name,
   then sends its exchange start (which serves as acceptance).

**Key method** (2 messages, then the exchange):
1. B → `proof_B = MAC(Z_mac, ["b", J, T0])`.
2. A checks it. A → `M {vault_id, generation}` and
   `proof_A = MAC(Z_mac, ["a", J, T0, H(M)])`. A switches.
3. B checks `proof_A` (and checks `M` against its copy, if it has one) and
   switches. B's exchange start is its first epoch-1 record.

Epoch-1 keys: `root1 = HKDF-Extract(TA, ss ‖ P ‖ Z_ks)`, with
`TA = H(T0, every authentication message)`. Counters restart only under the
new keys.

| | v3 | Simplified |
|-|----|------------|
| Password path, after accept | 9 messages (≈ 4½ round trips) | 4 messages (2 round trips) |
| Key path, after accept | 5 messages | 2 messages |
| New labels and message types | C, profile, FinishedA/B, GrantAccepted, ack | none of those |

Every row of v3's attack worksheet (§11) still holds:
- **Relay and reflection** fail through T0/TA binding and role labels.
- **Method, profile or identity tampering** fails through the hello MAC
  (method), `J` (profile) and epoch-1 AEAD (identity).
- **A wrong key** fails on the first epoch-1 record instead of on a Finished
  message. That is the same check one message later, with nothing released
  before it.

## 4. Notes on my v2 (superseded by v3)

The v2 review was right on these points:
- **F2 overstated the risk for OPAQUE.** Leaked server state allows offline
  guessing and impersonating A, not B. The password-free takeover I described
  applies only to a balanced PAKE secret. That is now the basis of V5.
- **"Stolen file: nothing"** was wrong. The file's slot is already an offline
  target.
- **The quantum window** must count recording during the session and analysis
  later.
- **Listener closure** was missing.
- **The `vk`-mode context-first message** was a new leak. v3's key method
  removes it.

## 5. Before an implementation plan

- The encoder split (§1) lands first, with a test that a record extension
  never reaches the local slot table.
- Pick and pin the engine crate version and check its actual audit scope, then
  check licences against `deny.toml` and run `cargo deny` and `cargo vet`.
- Write the 0013 amendment as a `Draft`, with exact labels, encodings, epoch
  boundaries and the attack rows above as Testing Requirements. Then get the
  independent 0012 §3 review.
