# 0006 — Server Accounts, Authentication and Device Enrollment

| Status | Created | Depends on |
|--------|---------|------------|
| Draft | 2026-10-14 | 0001, 0002 |

## Summary

Devices authenticate sync access with hybrid signatures. A separate OPAQUE
account password controls account administration. Pairing authenticates both
devices out of band and transfers vault keys using a complete signed KEM/
encryption envelope. Device grants are scoped to vault and key generation.

## Specification

### Admission control

v1 supports **closed** registration only. An admin creates a pending username
and a random 128-bit registration code, stored hashed, single-use, expiring
after 24 hours. Deliver URL, code and server identity fingerprint out of band.
Consume the code atomically with registration. Invite and hosted/open admission
require separate specifications; OIDC and proof of work are not v1 dependencies.

Apply per-account/IP request limits and configurable account/vault quotas:
current objects, retained history, staging, record count, bytes, attachment size,
device count and uploads. Enforce body limits before allocation/storage; reject
over-budget requests without partial publication. Client safety budgets (0004)
remain independent. Use SQLite for the first self-hosted server; Postgres support
is deferred until the transaction/retention behavior is tested on SQLite.

### Authentication and authorization

A device is an account identity plus a set of per-vault grants
`(vault_id, key_generation, role)`. v1 role is owner on granted vaults; no sharing
between users. An account session may administer or revoke devices but MUST NOT
download vault objects, enroll an unrestricted sync device, or obtain VK.
Recovery of one vault grants access to that vault only, not all account vaults.

Each request checks account status, device revocation/authentication generation,
grant and requested vault/generation. A generation change invalidates old grants.
A malicious server can bypass its own access controls, but does not learn keys;
client cryptographic trust never comes from the server's device list alone.

### Key custody

| Material | Device storage | Server storage |
|----------|----------------|----------------|
| VK | Wrapped password/platform slots | No plaintext VK |
| Password slot | Local slot; inside encrypted keyslot record | Only VK-encrypted record |
| Quick-unlock slot | Device-bound, excluded from exports | Never |
| Signing private keys | Encrypted device bundle; see below | Never |
| Pairing decapsulation key | Ephemeral in protected memory | Never |
| Pairing transfer | Pending ciphertext until delivered/expired | Encrypted relay, maximum ten minutes |

Device signing bundles are sealed by an authenticated OS wrapper or wrapped
under a designated local vault's device-storage key, with account/device IDs
as authenticated context. The device's unlock policy must release both halves
before signing; no plaintext private-key file or automatic unprotected fallback.
Registration before any vault exists requires an authenticated OS wrapper or
an explicitly chosen local device password using password-kdf/1. Rewrap after
the designated vault rotates and wipe plaintext on lock. Restoring an exported
vault never restores signing identity. Ordinary local offline use needs no
device signing identity.

Pairing uses a fresh X-Wing key pair per ticket, not a long-lived device KEM key.
Erase its private key and P after delivery, cancellation or expiry; never persist
them in backup/state restoration. App restart cancels pairing. Long-term signing
key compromise therefore does not decrypt recorded pairing transfers.

There is no **vault-master-password verifier** in the server DB. This guarantee
does not apply to the separate account password: OPAQUE server compromise allows
offline guessing. Explicit file exports contain an attackable password slot.

### Account password and OPAQUE profile

The account password is a separate secret from vault passwords; clients MUST
NOT derive one from the other. Require a strong generated suggestion (0010).
OPAQUE does not enforce that humans never reuse passwords; explain the separation
and never claim that reuse preserves this boundary.

Account-auth/1 is RFC 9807 OPAQUE-3DH with ristretto255-SHA512 OPRF and group,
HKDF-SHA-512, HMAC-SHA-512, SHA-512, and application-selected Argon2id KSF:
v=0x13, m=262144 KiB, t=3, p=4, output 64 bytes, salt=16 zero bytes, no
secret/associated-data parameters. The OPRF provides the per-credential salt.
Context is canonical CBOR of
`["qv/account-auth/v1", server_identity_fingerprint, account_auth_profile]`.
Credential/client identity is the canonical username's UTF-8 bytes; server
identity is its full application-key fingerprint. Username canonicalization is
ASCII lowercase with a fixed [a-z0-9._-] alphabet and length 1–64; reject other
forms rather than applying locale-dependent transformations.

Pin this application profile; never use a crate's identity KSF or allow the
server to negotiate weaker work factors. Keep OPRF seed in secret server
configuration, separate from the records DB; database-plus-seed compromise
permits offline guessing as described in
[RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html#section-10.11).
Use the RFC's fake-record path for unknown users, equivalent work classes,
rate limits and generic errors. The server necessarily knows which accounts
exist. OPAQUE is a documented classical exception to hybrid vault-key transport.

### Server identity

TLS 1.3 uses hybrid X25519MLKEM768. Disable 0-RTT for authenticated operations.
qv-server terminates this TLS connection; proxies may forward opaque TCP but
MUST NOT substitute client-supplied exporter headers.

The application server identity is a separate Ed25519 + ML-DSA-65 public-key
pair. Its fingerprint is SHA-256 of canonical
`["qv/server-key/v1", signature_profile, ed25519_public, mldsa_public]`, displayed
as the full grouped hexadecimal digest or a QR code. Registration requires
comparison with the admin's out-of-band fingerprint. Pairing obtains it from
the approving device's QR. TOFU without verification is explicitly unverified;
do not describe it as protection from first-contact MITM.

Export 32 bytes using TLS exporter label `EXPORTER-QuickVault-v1`, empty context.
The server signs canonical
`["qv/server-channel/v1", protocol_version, server_fingerprint, exporter]`
with both identity keys; verify the pinned fingerprint and both signatures before
registration, account login or device session creation. Standard certificate/
hostname validation remains enabled unless the user explicitly configured a
pinned self-hosted certificate. An unexplained application-key change stops
sync. Planned rotation binds old/new keys and monotonic identity generation
in an old-key-signed transcript; a stolen old key cannot authenticate recovery
from its own compromise, so that recovery needs a new out-of-band comparison.

### Registration

1. Verify server identity, code and canonical username. Generate signing keys
   and securely store the device bundle before finalizing registration.
2. Run OPAQUE registration bound to one random 128-bit transaction ID, username,
   initial device public keys, server identity and TLS exporter; expires in five
   minutes. Bind the final submission to this stored transaction, not a caller-
   supplied replacement device key.
3. Verify initial device proof of possession: hybrid signature over canonical
   `["qv/register/v1", transaction_id, account_id, username, device_id,
   device_public_keys, server_fingerprint, exporter]`.
4. In one transaction store OPAQUE record, enroll device, consume code and mark
   transaction complete. Repeating the same operation returns its stored result;
   replacing the username, keys or body is rejected. The first device has no
   vault grants until creating a vault.

### Uploading a vault

An unlocked device with an account device session creates a vault using its
random vault ID, generation, hybrid recovery public keys, initial checkpoint
and object references. Require recent account login, device signature and
recovery-key proof over the same complete create-vault transcript including
account ID and operation ID. Atomically assign ownership, grant the creating
device and publish the initial verified state. Subsequent changes use 0005.

### Logging in

#### Device session

1. Request a challenge for an account/device. Return a random 32-byte nonce
   associated with device, connection exporter and transaction ID, valid for
   60 seconds. Unknown/revoked failures have the same shape and work class.
2. The device signs canonical
   `["qv/device-session/v1", server_fingerprint, account_id, device_id,
   transaction_id, challenge, exporter, authentication_generation]`.
3. Verify both signatures, transaction/connection, enrollment and expiry;
   consume the challenge exactly once before issuing a random 32-byte opaque
   session token. Store only its hash with scopes and authentication generation.
4. Use this token as an Authorization bearer on that same TLS connection.
   Recheck revocation and grants on **every** request. A reconnect creates a
   new session. TLS protects the complete method, path, query, body and response;
   there is no custom per-request HMAC/counter protocol.
5. Tokens remain in memory, never URLs/logs/config. Expire after 15 minutes idle,
   twelve hours absolute, lock, TLS close, revocation or generation invalidation.

#### Account login

Run OPAQUE KE1/KE2/KE3 with the pinned profile, server identity and connection.
Release a five-minute, administration-only opaque session after verifying KE3.
Bind it to the same TLS exporter/connection, as for device sessions. Failed
attempts do not disclose whether username or password was incorrect. Password
change re-registers through an authenticated account session and invalidates all
account sessions; it cannot change vault keyslots.

### Adding a device

1. A starts from an unlocked vault and device session. The user selects the
   vaults/generations to grant. Server creates a random single-use ticket,
   account-bound, ten-minute expiry. A generates random 128-bit pairing secret P.
2. A displays a QR containing protocol/enrollment profile, URL, server fingerprint,
   account ID, ticket ID/expiry and A's complete signing-key fingerprint plus P.
   Manual pairing encodes the same bytes; P is never sent separately to the
   server. A fingerprint here is SHA-256 of canonical profile/public-key tuple.
3. B verifies QR expiry and server fingerprint, generates its hybrid signing
   identity plus fresh ephemeral X-Wing keys, and sends canonical request Q:
   `["qv/pair-request/v1", server_fingerprint, account_id, ticket_id,
   expiry, A_fingerprint, B_device_id, B_signing_keys, B_ephemeral_kem_key]`,
   a hybrid B proof-of-possession signature over Q, and HMAC-SHA-512/32(P, Q).
4. A checks exact ticket/context, both B signatures, MAC and public-key validity,
   displays the selected grant list, and obtains explicit user approval.
5. A creates context T containing Q, A's signing public keys, the selected vault/
   generation list and checkpoint IDs. Encapsulate to B's ephemeral X-Wing key:
   `(enc, shared_secret) = XWing.Encapsulate(B_key)`.
   Derive 32-byte transport key using HKDF-SHA-512 with IKM=shared_secret,
   salt=SHA256(canonical T), info=`"qv/pair-transfer/v1"`.
   Encrypt payload with XChaCha20-Poly1305, fresh nonce, AAD=canonical
   `["qv/pair-transfer/v1", T, enc]`.
   Payload carries VKs, vault/control-record IDs, generations, portable profiles
   and A's verified checkpoints. A signs canonical
   `["qv/pair-approval/v1", T, enc, nonce, ciphertext]` with both signing keys,
   and MACs the complete approval plus signatures under P.
6. Server verifies A's current enrollment/grants, B's proof, ticket/expiry and
   immutable approval body. Atomically consume ticket, enroll B and install only
   approved per-vault generation grants. Repeated identical approval is
   idempotent; a different body for a consumed ticket fails.
7. B independently validates T against Q/QR, A's public-key fingerprint,
   signatures and P MAC; decapsulates and authenticates payload; checks exact
   grant list/generation/checkpoints. Server assertions are insufficient.
   Pull and verify from those checkpoints before exposing data. Adopt only a
   unique verified password keyslot record; a conflict needs explicit resolution.
8. B acknowledges by signing approval hash; server deletes relay ciphertext.
   Both devices erase P, shared secret/transport key and B's ephemeral private
   key. Expiry/cancellation also erases local secrets and relay data.

Every received array has exact field order and bounded types; no omitted context
or variable-length string concatenation. Wrong ticket/account/server/recipient/
profile, replay and modified ciphertext MUST fail. This composition needs the
release validation in 0012; selecting reviewed primitives is not a protocol audit.

### Recovery (all devices lost)

Account login permits listing only vault IDs, generations and recovery public
keys needed for recovery, not encrypted manifests/objects or password slots.
Account login alone provides no ciphertext access. For each vault being
recovered, decode its phrase to VK and derive the independent hybrid recovery
keys (0002). Issue a random single-use 60-second challenge tied to account session,
connection, vault ID and current generation. The recovery signature covers
`["qv/recover/v1", server_fingerprint, account_id, vault_id, key_generation,
transaction_id, challenge, exporter, new_device_id, new_signing_keys]`.
Verify against stored recovery public keys, consume challenge, enroll the device
and grant **only that vault/generation**, atomically and idempotently.
With no trusted checkpoint, mark the initial state as an unverified freshness
baseline. Verify manifest integrity regardless. Adopt the password slot or create
a new one after explicit user choice. Losing the account password too requires
a separately specified admin reset; a recovery phrase is not an account reset.

### Master password changes

Create a new salt/slot and encrypted keyslot-record version as one local
transaction with updated header MAC and manifest. Other devices may use their
old password offline. On verified sync adopt a unique descendant keyslot
atomically, update the local header MAC and invalidate quick unlock.
A concurrent keyslot conflict preserves the working local password slot and
requires user resolution; configuration candidates remain encrypted in the
record. Pending local slot changes do not participate in verification of the
remote manifest. Never combine salt, KDF profile or wrapped VK from different
versions. A compromised old slot requires VK rotation for future-data protection.

### Revocation, sessions and expiry

Revocation is one transaction: mark the device revoked, increase its
authentication generation, revoke all associated sessions/grants and pending
tickets/transfers, and append an audit event. Check session generation on every
read and immediately before a write commits. Cancel active streams and prevent
later chunks/publications after revocation; bytes already delivered cannot be
recalled. All sessions, including already-open sessions, become unusable.
A session that raced revocation may only finish if its authorization/publication
linearized before revocation; no later state may be committed.

Device enrollment expires after 180 days without sync (admin-configurable).
Expiration uses the same invalidation path. It is not tombstone garbage
collection. A revoked holder of VK retains already obtained data and forging
ability for that generation; rotate VK and reapprove trusted devices.
An honest server keeps audit events for grant/enrollment/revocation/rotation;
a malicious server can hide its own audit history, so it is not an independent
transparency witness.

## Security Considerations

Account compromise can deny service through administrative actions but does not
alone reveal VK. Server compromise permits account-password guessing and fork/
freeze attacks within 0005's documented limits. Rate-limit expensive operations
and bound challenges/tickets/staging. Authentication policy never substitutes
for client verification of vault contents or out-of-band key distribution.

## Open Questions

1. Hosted admission and Postgres are deferred. These are not substitutes for
   client resource budgets or the release gates in 0012.

## Changelog

- 2026-10-14: Device enrollment plus separate OPAQUE account password adopted.
- 2026-10-15: Pin OPAQUE profile; replace per-request HMAC with TLS-bound opaque
  sessions; invalidate active sessions on revocation; define scoped grants,
  encrypted signing storage, ephemeral authenticated key transport, checkpoint
  handoff and strict recovery/rotation context. Defer hosted admission/second DB.
