# LAN join authentication: analysis of `lan-auth` and revised `lan-auth-v2`

Exploratory, 2026-11-08. Not a spec, not reviewed, not evidence of security
(0012). Normative behaviour changes only through a 0013 amendment.

## 1. The defect being fixed

0013 §4.7 (new-device mode) sends `["qv/lan-pair-grant/v1", vault_id,
key_generation, vk]` once the comparison code is confirmed on A. Up to that
point B has only shown it holds the one-use code `P`. The master-password
check in §10 step 4 runs on B after B already has VK and every object. It
is a client-side UI step, not a protocol gate: a modified client skips it.
So VK goes to whoever holds `P` and gets A's user to tap "codes match". The
committed comparison code stops MITM grinding, but it cannot stop a user who
taps without comparing, or a racer whose code happens to be the one A shows.

Requirement: **A releases VK only to a peer that has shown, in this
session, that it knows the vault password. A peer that fails must not get an
offline password-guessing target.** A peer that already holds VK (its own
copy or the recovery phrase) proves VK instead, and VK is never sent.

## 2. Findings on the proposed diagram (`lan-auth.mmd`)

The direction is right: a PAKE gates the grant, and the recovery route sends
no VK. These problems remain.

| # | Finding | Effect | Fix in v2 |
|---|---------|--------|-----------|
| F1 | Left open: who creates the PAKE server state, where it is stored, and what happens on password change or migration | The design cannot be specified | Store the OPAQUE server setup and registration inside the existing **VK-encrypted keyslot record**. 0002 §2.1 already writes that record atomically whenever the password slot changes, on a device where the password is typed. 0005 §2.6 already syncs it and handles its conflicts, so password change and conflict handling come at no extra cost |
| F2 | The state's location is not given. If it went into the **cleartext local keyslot table** (0004 §2) or anywhere readable without VK, then a stolen file + an observed code + one approval would yield VK *without the password* | Weaker than both today's design and SG3 | State it explicitly: the state is only ever inside the VK-encrypted record, and never in the local cleartext slot |
| F3 | Stage 3 (the VK-possession proof) also runs on the password route, right after A has sent VK | Proves nothing: B echoes back a key it just received. It adds two messages and a false sense of assurance | The password route ends at KE3 plus the grant. VK proofs exist only on the VK route |
| F4 | A separate inner grant envelope (`K_grant`, random nonce, `AEAD_Seal(VK)`) inside the record layer | A new envelope format and nonce rule. It protects only the grant, not the exchange that follows | Fold the PAKE key into the record keys: `k2 = HKDF(ss ‖ P ‖ K, th2)`. The grant and the whole exchange then depend on X-Wing, `P` and the password proof together. There is no new envelope |
| F5 | The "bootstrap context" offers "allowed methods/profiles" plus a "fresh challenge", and B answers with a separate method-selection round | Negotiation creates a downgrade surface. The challenge duplicates `th`, which already contains fresh `nonce_A`, `ek_B` and `ct`. One extra round trip | The method is the hello's existing `mode` field (MAC'd by `P`). Profiles are fixed by `lan_profile`. No challenge |
| F6 | The recovery route is drawn as a new third path | It is exactly sync mode for a B whose local manifest is empty | Merge them: `mode = vk` covers "has a copy" and "has the recovery phrase" |
| F7 | It is unclear whether A's comparison-code approval comes before the PAKE | If the PAKE ran first, every code holder would get an online password guess without the user's approval | v2: reveal, code, A confirms, *then* context and PAKE |
| F8 | The online-guess budget is not stated | Retries inside one session would multiply guesses per observed code | Exactly one PAKE per window. Any failure aborts the window, and a new attempt needs a new code (a new user action) |
| F9 | Post-quantum is not addressed for an **active** attacker who holds `P` | That attacker is an endpoint, so the outer X-Wing layer gives no protection. VK then rests on OPAQUE (classical) plus the password. One discrete-log solve on an OPRF evaluation recovers the OPRF key, which turns the attack into offline guessing at Argon2id cost (OPAQUE is not "quantum-annoying") | Document it as a classical exception, like account OPAQUE in SG6/0006. It is still strictly better than today, where that attacker gets VK with no guessing at all (§4) |
| F10 | B does not check that the VK it received matches the vault's password slot | A peer that forges KE2 (for example after an F9-style key recovery) could hand B a VK and vault of its choosing | B publishes only if the received keyslot record unwraps to the granted VK under the password the user typed. This is §10 step 4, reused as a consistency check |

## 3. Revised flow (`lan-auth-v2.mmd`)

Unchanged from 0013: the code `P`, hello, accept, `th`, `k1`, record layer,
exchange, staging, and one session per window. Changes:

1. **Two modes** in the hello: `vk` (B holds VK: a synced copy or a recovery
   phrase) and `password` (B has only the vault password).
2. **`vk` mode:** A sends `[vault_id, key_generation]`. B checks them (a copy)
   or adopts them (a phrase). Then come today's §4.8 proofs (B first, A replies
   only after verifying), then the exchange. VK never crosses the network.
3. **`password` mode:** reveal → committed code → A confirms → context →
   OPAQUE KE1/KE2/KE3 with `context = H(th, vault_id, key_generation)` →
   A verifies KE3 → record keys switch to `k2 = HKDF(ss ‖ P ‖ K, th2)` →
   grant → exchange → B's consistency check and vault-name confirmation →
   publish.
4. **PAKE suite:** RFC 9807 OPAQUE-3DH with the same primitives and Argon2id
   KSF as 0006 `account-auth/1`, under its own context label
   (`qv/lan-pake/v1`). Reusing the profile already pinned in 0006 means no
   new primitive choice.

### Why OPAQUE and not a balanced PAKE

The augmented property is useless here: the server state is readable only
by VK holders, who need no password. A balanced PAKE over a VK-encrypted
verifier (CPace) would be simpler: two messages, one less long-term key. It
is also quantum-annoying, so a quantum attacker must solve one discrete log
per password guess, not one in total. Against that, OPAQUE has a profile
already pinned in 0006 and a maintained Rust implementation with a published
audit (`opaque-ke`). CPace has neither. The project rule is reviewed crates
and no hand-built primitives, and the gap between the two only matters to
an active quantum attacker standing on the LAN during a 10-minute window
with the code. So OPAQUE is the recommendation. Revisit if a reviewed CPace
implementation appears.

## 4. Adversary comparison

`P` = has the one-use code (saw the QR, or raced). "Approval" = A's user
confirms the comparison code. Rows assume the attacker does **not** know the
password unless stated.

| Adversary | Today (0013) | Proposed (`lan-auth`) | Revised (v2) |
|-----------|--------------|-----------------------|--------------|
| Passive, no `P` | Safe | Safe | Safe |
| Passive with `P`, including recorded traffic + a later quantum computer | Safe (X-Wing) | Safe | Safe; the grant also depends on `P` and K |
| Active with `P`, user rejects the code mismatch | Safe | Safe | Safe |
| Active with `P`, **user approves blindly / racer wins** | **Gets VK** | One online guess; F2 risk if the state's location is wrong | One online guess per code; no offline target |
| Same, attacker has a quantum computer | Gets VK | Offline Argon2id guessing (F9) | Same as proposed; documented exception |
| MITM with `P` on both legs | Stopped by the code only | PAKE bound to CTX | PAKE bound to `th`, which differs per leg; both legs fail even without the code |
| Fake QR (victim B scans an attacker's window) | B's name and password checks stop the join, after B has received the attacker's data | OPAQUE envelope fails on B; no guess for the attacker unless its vault uses a guessed password | Same, plus F10 |
| Stolen vault file + `P` + approval | Gets VK | Gets VK if F2 goes wrong | Nothing: the OPAQUE state needs VK to read |
| Knows the password + has `P` + approval | Gets VK | Gets VK | Gets VK (an insider; the code remains the only check) |
| Holds VK + `P` | Syncs (conceded in 0001/0014) | Same | Same |

The revised design is no worse than today in every row, and fixes the row
the owner raised.

## 5. Costs and residual items

- **Metadata:** in `vk` mode A now sends `vault_id` and `key_generation`
  before B proves. Today B sends the same pair to its peer before A proves,
  so a code holder can already see it in the other direction. Accepted
  leakage, or keep B-first for copies and send the context only for
  phrase-restores, at the price of a third mode.
- **Comparison code kept.** With the PAKE it only protects against an
  attacker who knows *both* the password and `P`. Removing it would simplify
  the UI and remove the reveal and commit, but it is not free, so v2 keeps it.
  This is the owner's choice.
- **One attempt per code.** A typo on B means scanning a new code. Allowing
  retries within a window means more guesses per observed code.
- **Migration:** existing keyslot records have no OPAQUE state. Add it on the
  next password unlock, or ask for the password on A when a password-mode
  window opens and the state is missing (check it against the slot's
  `kek_commit`, then write a new record version). Pre-1.0, no compatibility
  path.
- **Dependency:** `opaque-ke` (and `voprf`, `curve25519-dalek`) are not in
  `Cargo.lock` yet. They need a licence check against `deny.toml`, then
  `cargo deny` and `cargo vet` (0012 §3).
- **Malicious A:** gets at most one online guess of B's password, and only by
  registering a guessed password in its own vault.

## 6. Spec text this would need (on acceptance)

- 0013 §4.3 modes; §4.5 limited to password mode; §4.7 replaced (PAKE, `k2`,
  grant); §4.8 context first and recovery-phrase B; §10 step 4 becomes the
  F10 consistency check; new labels (`qv/lan-pake/v1`, `qv/lan-pair-key/v2`,
  `qv/lan-pair-grant/v2`); old grant label refused.
- 0002 §3.2 and 0003 §2.3: the keyslot record payload gains the OPAQUE server
  setup and registration; a new `lan-pake/1` profile row.
- 0001 SG6: LAN password-mode PAKE as a documented classical exception
  against an active code holder.
- 0012 §3: LAN gate rows for one-guess-per-code, no offline target, KE3
  before grant, and the F10 check.
- 0014 Security Considerations: new-device mode strength.
