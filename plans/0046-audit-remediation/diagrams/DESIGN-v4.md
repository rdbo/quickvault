# QuickVault LAN enrollment — candidate v4 (no stored credential state)

**Status: Exploratory, 2026-11-08.** Not a spec, not implemented, not reviewed
under 0012 §3, and not evidence of security. The only test applied is fitness
for this product against the attackers in v3 §11. v4 starts from
[DESIGN-v3.md](DESIGN-v3.md) and its [follow-up review](REVIEW-v3-followup.md).
v3 sections not replaced here (§1 goals, §3 secret-handling rules, §4
conventions, §11 worksheet and rejected shortcuts, §12 evidence) still apply.

## 1. Review of v3 after §13

v3 §13 answers the follow-up findings correctly. But the answers show how
much the stored password-authentication state costs:

| Cost of persisting that state | Where |
|-------------------------------|-------|
| A new file format, a new archive format and a structurally new keyslot payload, so older apps cannot copy secret fields into the clear slot table | §13.1, follow-up F1 |
| An **intentional compatibility break**: older apps can no longer open upgraded vaults or archives, plus a crash-safe migration | §13.1 |
| A second stored offline-guessing target, whose KDF floor must be maintained, upgraded and compared with the slot forever | §13.2, follow-up F2 |
| Registration at setup, on password change, on profile upgrade and on rotation, plus conflict selection and stale-state rules | §10 |
| A grant authorization that must be serialized against password-change commits | §13.3, follow-up F3 |

All of that exists for one reason: A must check a password it does not keep.
But in this flow **A's user is already at A**. They must look at A's screen,
compare the code and approve. If they also type the vault password there, A
can build the credential for this one session and throw it away afterwards.
Nothing is stored, so none of the rows above exists.

Other v3 points, agreed by both reviews and applied here:
- **The context commitment `C`/`R` is dropped.** It stops no attacker. The
  identity travels in the grant, under final keys.
- **`GrantAccepted` and the key-method acknowledgement are dropped.** B's first
  final-key record covers them.
- **Reveal and KE1 are sent together.** A answers only after its user approves.
- **The key method derives separate MAC and key-schedule secrets** from VK.
- **The follow-up's F4 is right:** explicit confirmation of the combined
  final keys before the grant is worth having. v4 keeps it without the
  round trip: `FinishedB` travels in the same flight as KE3, and `FinishedA`
  is unnecessary (§4).

## 2. The one change: the password is typed on both devices

**Password mode, on A:** after the hello says `password`, A's approval screen
shows the comparison code **and a vault-password field**. The approval *is*
typing the password and confirming. A then:
1. checks the password against its working local slot (the existing unlock
   check: Argon2id, then `kek_commit` in constant time). A wrong password
   lets the user retype on A only. B is not involved, the code is not
   consumed again and B gets no guess;
2. requires a unique, non-conflicted keyslot record that matches that slot
   (the existing `keyslot` rule);
3. creates fresh **ephemeral** password-engine server setup and registration
   from that password, in protected memory, and wipes the password;
4. answers KE1.

The registration lives only in the session. It is erased when the session
ends, whether by success, abort, lock or timeout.

Product fit:
- **No persistent state**, so v3 §3's encoder split, §10's lifecycle, §13.1's
  format break and migration, §13.2's stored-target comparison and most of
  §13.3 disappear. Existing vaults gain password enrollment with no
  migration. Older apps are unaffected.
- **It works on every device**, including those unlocked by fingerprint,
  without first provisioning state through a password unlock.
- **The credential is always the current password.** A password change on
  another device that A has not yet adopted leaves A authenticating the
  password its own file still opens. The old password and physical access
  already open that file, so this adds nothing new.
- **The price:** the user types the vault password on A as well as on B, once
  per new device, and A runs two Argon2id passes (about 2 s on the target
  phone). A one-time join is where this cost matters least.

Rejected alternatives:
- **v3's stored state:** everything in §1's table.
- **Keeping the registration in memory from the last password unlock:** it
  needs the password itself while unlocked, or a password-equivalent kept for
  the whole unlocked session, and it still fails after a fingerprint unlock.
- **A balanced PAKE over a KEK-derived secret:** once nothing is stored, the
  augmented engine's leak-containment advantage is gone. A balanced PAKE would
  then be simpler: one Argon2id per side, and the quantum-annoying property.
  It stays rejected only because no reviewed Rust implementation is known, and
  the project rule forbids hand-built primitives. Revisit if one appears. The
  message flow below does not change.

## 3. Engine and KDF

The engine is the reviewed OPAQUE-3DH implementation (ristretto255,
SHA-512), used as a component. Its messages are opaque, bounded fields inside
our records:
- engine context = `CBOR([J, "password", T0])`;
- fixed client and server role identities;
- one fixed credential identifier.

Stretching uses Argon2id with the vault-wrapping work parameters (v3 §13.2:
256 MiB, t=3, p=4) under its own profile ID, which `J` fixes. There are no
peer-supplied parameters, and a profile that cannot run fails before any work.

Because the registration exists only during a live session, the only offline
path left is the follow-up's harvest case. A code holder whom A approved
records a failed run and later breaks the group, for example with a quantum
computer. It must still pay one Argon2id with these parameters per guess, and
it recovers the password, not VK. Document this as the classical exception for
LAN password mode.

## 4. Flow

### Common

QR `P` → Hello `(J, method, commit_B, ek_B, MAC_P)` → A checks the size,
shape, `J` and the MAC, then the key. On the first fully valid hello it
**consumes `P` and closes every listener** → Accept `(nonce_A, ct, MAC_P)` →
`T0`, and epoch-0 keys from `HKDF-Extract(T0, ss ‖ P)`.

**Rule for both methods:** A sends no epoch-1 record until it has
authenticated one epoch-1 record from B.

### Password method (4 flights, then the exchange)

1. B → `Reveal(nonce_B) + KE1`. B's user types the password while the
   codes are compared.
2. Both show the committed code. On A, the user approves by typing the vault
   password (§2). A → `KE2`.
3. B runs the engine finish. A failure means a wrong password or a fake
   emitter, so B aborts. On success B gets `Z` and computes
   `TA = H(T0, Reveal, KE1, KE2, KE3)` and `root1 = HKDF-Extract(TA, ss ‖ P ‖ Z)`.
   B → `KE3` (epoch 0) **and** `FinishedB = MAC(fin_b, [J, "b", TA])` as its
   first epoch-1 record, in one flight.
4. A checks KE3 (which gives `Z`), derives the same keys and checks
   `FinishedB`. Then one atomic session operation (v3 §13.3, simplified):
   - check the vault is unlocked, the session not cancelled, and the keyslot
     head the same as at step 2;
   - seal `Grant {vault_id, key_generation, VK, public slot descriptor}`
     once, as A's first epoch-1 record;
   - send it outside the lock.
5. B opens the grant, which confirms A's keys to B. B unwraps the public slot
   with the typed password and compares the result with VK in constant time.
   B wipes the password and its derived keys, then confirms the vault name.
   B's exchange start is its acceptance.

Once sealed, the grant counts as disclosed (v3 §13.3). It is never resent or
resealed.

### Key method: recovery words or an existing copy (2 flights, then the exchange)

1. B → `proof_B = MAC(z_mac, [J, "b", T0])`, where
   `z_mac = HKDF(VK, T0, ["qv/lan-key-auth/v1", "mac"])`.
2. A checks it and only then sends `M {vault_id, key_generation}` and
   `proof_A = MAC(z_mac, [J, "a", T0, H(M)])`, then switches to
   `root1 = HKDF-Extract(TA, ss ‖ P ‖ z_ks)`, with
   `z_ks = HKDF(VK, T0, ["qv/lan-key-auth/v1", "schedule"])` and
   `TA = H(T0, proof_B, M, proof_A)`.
3. B checks `proof_A`. A copy also checks `M` against its own vault; a
   phrase-restore adopts `M`. B switches, and its exchange start is its first
   epoch-1 record. That satisfies the rule above before A sends any vault
   data. VK never crosses the network.

### Messages after accept

| | v3 | v4 |
|-|----|----|
| Password | Reveal, C+profile, KE1, KE2, KE3, FinishedA, FinishedB, Grant, GrantAccepted: 9 messages, about 4½ round trips | Reveal+KE1, KE2, KE3+FinishedB, Grant: 4 flights, 2 round trips |
| Key | proof_B, M+proof_A, ack, FinishedA, FinishedB: 5 | proof_B, M+proof_A: 2 |
| Explicit confirmation of the final keys before VK leaves A | yes (FinishedB) | yes (FinishedB) |

## 5. Attack check (v3 §11 rows that change)

| Attacker | v4 result |
|----------|-----------|
| Has the code and races or is approved by mistake, without the password | One engine attempt per code. A also needs its own user to type the correct password before it answers. No grant, slot or offline test |
| Fake emitter | Without the password it cannot build a registration that opens B's envelope, so B aborts after KE2. It learns a blinded KE1 only |
| Relay between two sessions | Different `T0`, so KE2's authentication fails on B, or KE3 fails on A |
| Steals the vault file | Unchanged: the slot was already an offline target. Nothing new is stored |
| Gets "server state" | It exists only inside a live session on an unlocked A. Anyone who can read it there can also read VK |
| Old app reads a new vault | Nothing new is stored, so nothing can leak in clear |
| Password change during a session | Detected because the keyslot head changed at step 4, so abort. After sealing, it counts as disclosed |
| Same password in two vaults, wrong code scanned | The engine and the slot check both pass. B's vault-name confirmation is the defence, as in every version |
| Knows the password and has the code | Still needs A's user to compare the codes and approve. The insider case is unchanged |

## 6. Independent hardening, not a blocker

The follow-up's F1 hazard is real today, independent of LAN.
`Keyslot::decode` keeps unknown `ext` keys, and `restore.rs:153`–`165`
installs the record bytes, extensions included, as the cleartext local slot.
Any future field added to the encrypted keyslot record would land on disk in
the clear on that path. v4 adds no such field. Even so, the local-slot
encoder should write only the defined descriptor fields, with a test, in its
own small change. The LAN fill comparison at line 156 must then compare the
projected bytes.

## 7. Spec work on acceptance

- **0013:** a new profile `J`; §4.3 methods; §4.5 limited to password mode
  with A's password approval; §4.7 replaced by §4 above; §4.8 replaced by the
  key method; §8.3 listener closure after the first valid hello; §10 step 4
  becomes B's pre-transfer slot check.
- **0002:** a `lan-pake/1` profile row and the `lan-key-auth` labels.
- **0001 SG6:** the LAN password mode's classical exception (§3).
- **0009 and 0014:** A's approval screen takes the vault password; B's prompt
  moves before the transfer.
- **0012 §3:** tests for every §5 row, and for A sending no epoch-1 record
  before `FinishedB`/the exchange start.
- **No storage-format change.**
