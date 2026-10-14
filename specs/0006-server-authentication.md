# 0006 — Server Accounts, Authentication and Device Enrollment

| Status | Created | Depends on |
|--------|---------|------------|
| Draft | 2026-10-14 | 0001, 0002 |

## Summary

This spec covers three separate problems:

1. **Admission:** who may create an account and store data at all, so the
   server can't be abused as free file storage (§Admission control).
2. **Authentication and authorization:** proving that a request comes from
   the owner of an account, and that the account owns the vault it touches
   (§Options).
3. **Key transport:** how a new device gets VK (Option C).

## Admission control

The server cannot inspect ciphertext, so it can never tell a real vault from
arbitrary bytes. Abuse is prevented by **who may upload** and **how much**,
not by looking at the content.

### Registration modes (server configuration)

| Mode | Use case | How |
|------|----------|-----|
| `closed` | personal / family server | Accounts only created by the admin (CLI on the server) |
| `invite` | small groups | Admin or existing users generate single-use, expiring invite tokens; registration requires one |
| `open` | hosted service | Anyone may register; MUST sign in with an external identity provider (OAuth 2.0 / OpenID Connect) **and** solve a proof-of-work challenge |

The server MUST default to `closed`. Other modes MUST be enabled explicitly
in the server configuration.

In `open` mode (deferred, see §Phasing):
- **External identity instead of email verification:** sign-up requires an
  OpenID Connect login (e.g. Google, GitHub, configurable providers). The
  server never sends email. The provider is used only to gate admission: it
  never takes part in vault encryption or device authentication, and it
  learns only that the user has a QuickVault account.
- **Proof of work:** registration requires solving a server-issued,
  single-use, expiring, memory-hard challenge (Argon2id-based). Default
  difficulty targets roughly 10 s on a mid-range phone; configurable.

### Quotas (all modes)

- Max vaults per account, max total bytes per account (**including** old
  versions kept in the server log, 0007 §3.3), max history size per vault,
  max record size, max attachment size (0003 §6.3), max records per vault,
  upload rate limits.
- All quotas MUST be configurable by the server admin (global defaults,
  optionally per account). Default values are deferred to the server
  configuration spec.
- Requests over quota are rejected before the body is stored.

### Why this is enough

- **No public download:** data can only be read by authenticated devices of
  the account that owns it. There are no shareable links, so the server can't
  serve files to anyone else. That makes it useless for distributing files,
  which is what file-hosting abuse wants.
- A legitimate account can still put arbitrary bytes in its quota. That's
  true of any cloud storage and is acceptable.

## Authentication vs. "HMAC over something"

"This vault belongs to this person" is two steps:

1. **Authentication:** the request comes from account X (one of its devices).
2. **Authorization:** the server keeps an access list `vault_id → owner
   account` and only lets X's sessions read or write X's vaults. This is
   a plain database check; no crypto is needed once (1) holds.

The question is how to do (1). A **MAC (e.g. HMAC)** needs the verifier to
hold the same key as the signer. If the server can check the HMAC, the server
stores that key, and anyone who steals the server database can forge requests.
If the key comes from the password, they can also try to crack it. That is
Option A below.

A **signature** separates the two: the device keeps the private key, the
server stores only the public key. A stolen server database lets nobody
impersonate the user. That is Option C. HMACs still have their place
*inside* the vault (integrity between the user's own devices, 0005 §5.2), where
the verifier knows the key anyway.

## Requirements

- R1. Multiple users per server, multiple vaults per user, self-hosted or hosted.
- R2. The server never receives the master password, VK, or anything that
  allows decrypting vault data.
- R3. The server MUST NOT store anything that allows guessing the vault
  master password offline. In particular, the `password` keyslot is never
  uploaded (§Key custody).
- R4. An attacker who learns *only* the account password SHOULD NOT be able to
  download ciphertext (keeps them from starting an offline attack).
- R5. Asymmetric crypto MUST be hybrid classical + PQ (0002 §6).
- R6. Online guessing is rate-limited; account existence is not revealed
  (no user enumeration through responses or timing).

## What the attacker wants

| Attacker | Goal | Main defence |
|----------|------|--------------|
| T2 server DB thief | Crack the password offline from stored auth data | Don't store a password-equivalent (B, C) |
| T2 malicious operator | Trick the client into revealing key material | Client never sends keys; enrollment verified out-of-band |
| T3 MITM | Steal session or credentials, harvest-now-decrypt-later | TLS 1.3 hybrid + app-level hybrid KEM for key transport |
| T4 online guesser | Guess the account password | Rate limiting, device-bound auth (C) |
| Phisher | Get the user to log in on a fake server | PAKE doesn't reveal the password to a fake server (B) |

## Options

### Option A — Derived auth token (Bitwarden-style)

Client derives `auth_key = HKDF(MK, "qv/auth")` and sends a hash of it; the
server stores `Argon2id(auth_hash, server_salt)`.

- ✅ Simple, well understood.
- ❌ A server DB thief can run an offline dictionary attack on the master password
  (at Argon2id cost). It also requires the account password to be the same as, or
  derived from, the vault password.
- ❌ A fake/phishing server receives a password-derived value.

### Option B — OPAQUE (asymmetric PAKE, RFC 9807)

The client and server run a protocol in which the server never sees the
password or a value derived from it in a guessable form. Crate: `opaque-ke`.

- ✅ Server DB theft still allows offline guessing only *after* the theft (no
  precomputation), and a fake server learns nothing useful.
- ✅ Produces a shared session key → can bind the session.
- ❌ Not post-quantum (based on OPRF over elliptic curves). The danger is
  limited: a future quantum attacker with recorded transcripts could mount an
  offline guessing attack on the account password, not decrypt the vault.
- ❌ More complex; must use the configuration from the RFC exactly.

### Option C — Device enrollment ("pre-established handshake")

Each device generates a **hybrid identity key pair** (Ed25519 + ML-DSA-65 for
signing, X-Wing for KEM). The server only accepts requests signed by an
enrolled device (challenge–response for each session).

New device enrollment:
1. New device generates keys, shows a short code / QR with its public key
   fingerprint.
2. An already-enrolled device scans/enters it, signs an approval, and
   encapsulates VK to the new device's X-Wing public key.
3. Server relays the approval and the encapsulated VK; it can't read them.
4. The first device of an account is enrolled during account creation.
   If every device is lost: re-enroll with the **recovery phrase**
   (§Key custody).

- ✅ Meets R4: password alone downloads nothing. Fully hybrid PQ (R5).
- ✅ Matches the "client and server do a handshake before syncing" idea.
- ✅ Also solves *key transport*: VK reaches new devices end-to-end encrypted.
- ❌ Adding a device needs an existing device or the recovery phrase.
- ❌ Requires a device-management UI (list, revoke).

### Option D — Combination ✅ chosen

- **C** for everything sync-related: device identity, sessions, VK transport.
- **B (OPAQUE)** as the account password for account-level actions (web
  account page, billing on a hosted service, emergency device revocation).
- A device revocation stops future sessions; it does not erase data already
  on that device. Afterwards the user SHOULD rotate VK (0002 §3.5).

## Decision

**Option D is adopted:** signed device enrollment (C) authenticates all
sync traffic and transports VK; OPAQUE (B) protects the account password used
for account-level actions. Options A and B-alone are rejected.

## Key custody

Where copies of VK exist, and in what form:

| Keyslot | Stored on | Uploaded to server? | Why |
|---------|-----------|---------------------|-----|
| `password` (VK wrapped by Argon2id(master password)) | each device, locally | **Never** | It's the only copy an attacker could attack by guessing a human-chosen password |
| `quick-unlock:<device>` | that device only | Never | Device-bound |
| Device enrollment (VK encapsulated to a new device's X-Wing key) | server, temporarily | Yes, as a relay | Only the target device can open it; deleted once delivered |

The recovery phrase is VK itself (0002 §4) and exists only where the user
wrote it down. The server never receives the phrase or any copy of VK.

Consequence: a stolen server database contains only ciphertext encrypted
under random 256-bit keys. **There is nothing to brute-force.**

### Adding a device

1. **From an existing device (normal case):** device-to-device transfer as in
   Option C. The user confirms the short code on both devices.
2. **From the recovery phrase (all devices lost):**
   1. Log in with the account password (OPAQUE).
   2. Enter the vault's recovery phrase, which decodes to VK.
   3. Prove it to the server: the client derives a hybrid signing key pair
      from VK (HKDF seed, label `qv/v1/vault-recovery-sign`) and signs the
      enrollment. The server verifies it against the vault's public
      recovery key, stored when the vault was first uploaded. This keeps R4:
      the account password alone downloads nothing.
   4. The server sends the vault's encrypted records; the client decrypts
      them with VK.
   5. The user sets the master password for this device, which creates a new
      local `password` keyslot.

Losing all devices **and** the recovery phrase means the data is gone, even
though the server still has the ciphertext (0001 SG8).

### Master password changes

Because `password` keyslots are local, each device holds its own. A change
on one device does not reach the others by itself.

1. The changing device writes a synced **password-change record**, encrypted
   with VK like any other record. It contains the new `password` keyslot
   (new salt, VK wrapped by the new KEK) and an increasing epoch number.
2. This does not break R3: the record is encrypted under VK, so cracking the
   password from it would require VK first, and VK already gives everything.
   The server sees one more opaque record.
3. Another device keeps unlocking with the **old** password while it is
   offline. After it next syncs (unlocked), it replaces its local keyslot with
   the one from the record. From then on only the new password works there.
   The user doesn't have to type the new password on each device.
4. Quick-unlock keyslots on all devices are invalidated (0002 §5.3).

Accepted risk: a device that never syncs keeps accepting the old password.
An attacker would need that device's vault file anyway.

### File-based sync

A `.qvault` file contains the `password` keyslot. Syncing it with Dropbox,
Syncthing etc. gives that provider something to guess against (same as
KeePass). Clients MUST mention this when the user sets up file-based sync.

## Account password

The account password (username + password, OPAQUE) MUST be a **separate
secret** from any vault master password. Clients MUST NOT derive one from the
other. A breach of the server or of the account password therefore never
touches anything tied to vault encryption.

The account password is needed only for: creating the account, enrolling the
first device, account settings, and emergency device revocation. Day-to-day
sync uses device keys only.

## Server identity

Each server has a long-term **hybrid identity key pair** (Ed25519 + ML-DSA-65),
separate from its TLS certificate.

1. **Trust on first use:** on first connection the client receives the server
   identity public key and pins it for that server URL.
2. **Verification words:** client and server admin both display a fingerprint
   of the key as a short sequence of words (e.g. 6 words from a fixed list,
   ~66 bits), like a safety number in an encrypted messenger. The server shows
   it with `qv-server fingerprint`. The user compares them; the client records
   whether the key was verified.
3. **Channel binding:** at session start the server signs the TLS exporter
   value (RFC 5705/8446 §7.5) with its identity key. A MITM with a different
   TLS certificate, even one trusted by the system CA store, fails this check.
   The system CA store is therefore not relied upon.
4. **Planned rotation:** a new identity key is signed by the old one; clients
   accept it automatically and show a notice.
5. **Unexplained change:** if the pinned key changes without a valid rotation
   signature, the client MUST stop syncing and show a blocking warning until
   the user verifies the new words.

### If the server identity key is stolen

An attacker with the key and a network position can impersonate the server.

| They can | They cannot |
|----------|-------------|
| See metadata (who syncs, when, sizes) | Decrypt any vault (all records are E2E encrypted) |
| Serve old data or withhold new data (rollback/freeze; detected by 0005 §5) | Obtain VK: it only travels device-to-device, and enrollment is confirmed by the user between their own devices |
| Make sync fail (denial of service) | Learn the account password (OPAQUE does not reveal it, even to the real server) |
| | Reuse device-signed requests (each is bound to its session) |

So server-key theft is a **metadata and availability** problem, not a
confidentiality one. The device-to-device enrollment code (Option C step 1–2)
is the check that keeps vaults end-to-end protected even then.

Mitigations: the identity key is encrypted at rest (optionally kept in a
TPM/HSM); compromise rotation per point 5; optionally later an offline root
key that signs short-lived online keys.

## Sessions

*The question:* after a device has proved who it is, how does each following
request prove it comes from that same device? A plain random token
("bearer token", like a browser cookie) works for whoever holds it, so
stealing it from memory, a log or a proxy is enough to impersonate the device.

Proposal:
1. **Session start:** the device signs `server challenge ‖ TLS exporter value`
   with its hybrid device key. The server verifies the signature against the
   enrolled public key and returns a random 32-byte **session secret** and a
   session ID.
2. **Each request** carries the session ID, a timestamp, a counter and
   `HMAC(session secret, method ‖ path ‖ body hash ‖ timestamp ‖ counter)`.
   The server rejects stale timestamps and repeated counters.
3. Session secrets live only in memory on both sides, expire after 15 minutes
   of inactivity or 12 hours absolute, and are dropped when the vault locks.
   A new session is started automatically by signing again with the device
   key; the user never sees this.

### What expires, and when

| Credential | Expires | User action needed |
|------------|---------|--------------------|
| Session secret | 15 min idle / 12 h absolute / on lock | None (automatic) |
| Device enrollment | When revoked, or after **180 days** without any sync (configurable by the server admin) | Re-enroll from another device or with the recovery phrase |
| Account-password session (account settings, revocation) | 5 minutes | Re-enter account password |

This avoids a large post-quantum signature on every request while keeping
sessions bound to a device and a connection. Since the session secret is
created by the server and short-lived, a MAC is the right tool here (see
"Authentication vs. HMAC" above).

## Phasing

| Phase | Included |
|-------|----------|
| v1 | Username + password (OPAQUE), device enrollment, sessions, server identity (TOFU + words), `closed` registration, configurable quotas |
| Later | `invite` mode |
| Hosted service | `open` mode: OpenID Connect sign-up + proof of work |

## Transport

- TLS 1.3 only, hybrid `X25519MLKEM768` key exchange (rustls supports it).
- App-level: VK and other key material are transported only inside X-Wing
  encapsulations between devices, never through the TLS layer alone.

## Server-side hardening (applies to all options)

- Rate limiting per account and per IP; exponential backoff.
- Constant-shape responses for unknown accounts (OPAQUE supports fake records
  for non-existent users).
- Audit log of enrollments/revocations visible to the user.

## Open Questions

1. Fingerprint encoding: word list (BIP-39 English?) and number of words.
2. Proof-of-work exact parameters (deferred to the hosted-service phase).
3. Which OpenID Connect providers to support (deferred).

Next step: write a concrete protocol spec (messages, state machines,
endpoints) for enrollment, sessions and revocation.

## Changelog

- 2026-10-14: Initial exploratory version.
- 2026-10-14: Split into admission / authentication / key transport; added
  registration modes and quotas; explained MAC vs. signature.
- 2026-10-14: Adopted option D; `closed` registration by default; `open`
  mode requires email verification + proof of work; quotas configurable.
  Status → Draft.
- 2026-10-14: Account password separate from vault password; server identity
  via TOFU + verification words + TLS channel binding; session proposal;
  `open` mode uses OpenID Connect instead of email; v1 is username + password.
- 2026-10-14: Key custody: `password` keyslot never leaves the device;
  `recovery` keyslot stored on the server; recovery-phrase device enrollment.
- 2026-10-14: Expiry table accepted.
- 2026-10-14: Session design accepted, expiry proposal; password change via
  a VK-encrypted keyslot record.
- 2026-10-14: Recovery phrase is VK itself; no recovery keyslot anywhere.
  The server stores only a public recovery verification key per vault.
