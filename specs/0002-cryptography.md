# 0002 — Cryptography and Key Hierarchy

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0001 |

## Summary

Defines immutable profiles per cryptographic purpose, the vault key hierarchy,
recovery, platform wrapping, and migration. Key transport is a complete
authenticated KEM/encryption protocol (0006), not bare encapsulation of a key.

## Specification

### 1. Profiles

1.1. Profile IDs are `u16` **within a purpose namespace**. KDF, stored-data,
password-wrapping, platform-wrapping, signature, enrollment and account-auth
profiles evolve independently. Every envelope names all relevant profiles;
unknown IDs fail closed. Published profiles are immutable. A KDF increase does
not migrate record encryption, signatures or TLS.

1.2. Initial profiles:

| Namespace / ID | Definition |
|----------------|------------|
| password-kdf / 1 | Argon2id v1.3; 256 MiB, t=3, p=4, 32-byte output, random 32-byte salt |
| stored-data / 1 | XChaCha20-Poly1305, 32-byte keys, random 24-byte nonce, 16-byte tag |
| password-wrap / 1 | XChaCha20-Poly1305 with password KEK |
| derivation / 1 | HKDF-SHA-512; canonical domain/context encoding (§3) |
| MAC / 1 | HMAC-SHA-512 truncated to its first 32 bytes (not HMAC-SHA-512/256) |
| object-hash / 1 | SHA-256 for immutable-object hashes and checkpoint IDs |
| signature / 1 | Ed25519 plus ML-DSA-65; both verify the identical canonical transcript |
| enrollment / 1 | X-Wing draft-11, HKDF-SHA-512, XChaCha20-Poly1305 plus transcript signatures (0006) |
| account-auth / 1 | RFC 9807 application profile in 0006 |
| platform-wrap | Backend-specific mechanisms in §5, distinct from password wrapping |

1.3. Password-kdf/1 is a candidate until benchmarked before the first release.
It MUST meet the 64 MiB hard floor and target about one second on a supported
mid-range Android device (at most two seconds on the supported low-end target).
If the candidate changes before publication, update the profile and vectors
together; after publication introduce a new profile. No arbitrary parameters
from an untrusted file are executed. Do not publish unsupported attacker-rate
estimates as security guarantees.

1.4. The authenticated header and portable manifest configuration carry minimum
accepted profiles per purpose. Password-KDF/wrapping policy travels atomically
with its encrypted keyslot descriptor, separately from data-profile minima;
pending/conflicted password changes cannot silently invalidate a working slot.
Reject retired profiles for writing; explicit
read-only migration may allow them. There is no numeric ordering across
namespaces; allowed transitions are an explicit registry, not `new_id > old_id`.

### 2. Migration rules

2.1. KDF/password-wrap migration creates a new password slot and encrypted
keyslot record atomically. It does not change VK or stored data. Adoption on
other devices follows 0006 and must preserve a working slot on conflict.

2.2. Stored-data migration creates a new key generation and new VK using §3.5.
Reencrypt all retained objects and rebuild manifests/checkpoints while keeping
logical version IDs and clocks. This avoids silently mutating immutable objects
in a generation. An old-generation peer cannot automatically merge its data.

2.3. Persist accepted generation/profile minima with the external anchor.
A header MAC cannot detect wholesale replacement by an older valid file.
Restore is an explicit workflow, not an exception hidden in normal unlock.

### 3. Key hierarchy

3.1. Normalize master-password text to NFC. Derive MK with the selected fixed
Argon2id profile; MK is never stored. Each vault has an independent password
and salt. Derive KEK with HKDF-SHA-512, IKM=MK, salt=vault ID, 32-byte output,
and info=canonical CBOR `["qv/kek/v1", password_kdf_profile]`.

3.2. VK is 32 random bytes generated at vault creation. Password wrapping uses
a fresh nonce and AAD
`["qv/password-slot/v1", vault_id, key_generation, slot_id,
password_kdf_profile, kdf_salt, password_wrap_profile]`.
Platform slots use §5. There is no recovery keyslot: the recovery phrase is VK.
The password slot leaves a device only in a VK-encrypted keyslot record or an
explicit self-contained file export (0006).

3.3. Purpose keys use HKDF-SHA-512 with IKM=VK, salt=vault ID, 32-byte output,
and info=canonical CBOR
`["qv/purpose/v1", purpose_label, key_generation, derivation_profile]`.

| Purpose label | Use |
|---------------|-----|
| record | Root for per-record keys |
| attachment | Root for per-attachment keys |
| header-mac | Authenticate local header and slots |
| manifest | Encrypt portable manifests |
| state-commit | Remote checkpoint MACs |
| local-state | Encrypt sync/outbox state and MAC anchor transitions |
| device-storage | Wrap local device signing bundles when bound to this vault |
| recovery-ed25519 | Independent Ed25519 recovery-key seed |
| recovery-mldsa65 | Independent ML-DSA-65 recovery-key seed |

Labels are never reused. Algorithm-specific seeds are separate derivations;
do not reuse one signature algorithm's seed for another.

3.4. A master-password change replaces the slot, not VK. A copied old slot
still yields the same VK after successful guessing and can decrypt later
same-generation data. Password change and deletion of local snapshots do not
revoke an attacker's copy. Suspected key/password compromise requires rotation
and replacement of external credentials whose old values may already be known.

3.5. **VK rotation and compromise recovery:**

1. Freeze ordinary writes on the initiating trusted device, resolve control
   conflicts, and take a local recovery snapshot. Generate new VK, generation
   number (previous + 1), recovery phrase, password slot and recovery public keys.
2. Build a private replacement DB containing all active versions, unresolved
   conflicts, chosen retained history and chunks, permanent tombstones and
   suppression frontiers. Reencrypt under new keys, preserve logical clocks/IDs,
   and verify the full manifest. Require confirmation of the new phrase (or an
   explicit recovery warning) and a successful replacement-password unlock before
   publication. No plaintext or unwrapped new VK is journaled.
3. For a synced vault require recent account authentication and the initiating
   enrolled device's hybrid signature over old checkpoint, new generation,
   new recovery public keys and new checkpoint. Compare-and-swap the server
   generation, recovery keys and full reference set as one publication.
   Retire pending old-generation publications/grants and install only the
   initiating device's new-generation grant. An ambiguous outcome
   is queried by operation ID; do not resume old-generation writes blindly.
4. Locally install the verified replacement with a durable recovery journal
   recording old/new complete anchors, authenticated with both generations'
   local-state keys, never plaintext keys. Advance the external
   anchor before reporting success. Restart resumes or rolls back only through
   this journal and the server publication status; retain the old DB until the
   transition is confirmed. Recovery may require unlocking both retained copies
   with their respective credentials; never guess that a server timeout means
   rollback succeeded. This dual-authenticated journal authorizes the generation
   change instead of an ordinary same-generation anchor update. An offline vault
   skips only the server step.
5. Invalidate every old quick slot and per-vault device grant. Reapprove each
   remaining device through a fresh out-of-band pairing (0006). Authenticate the
   generation and approving device independently of old VK. NEVER wrap new VK
   solely with old VK or automatically send it to the server's device list.
   Update other remotes explicitly; they have separate checkpoint chains.
6. Old-generation peers stop normal sync. Salvaging their offline edits requires
   separately unlocking a private old copy and explicit user-selected import as
   new edits under the current generation; never replay old control records or
   replace new generation keys. New recovery phrases replace old phrases.

A server may retain old ciphertext and a thief may retain old keys. Rotation
protects the new generation, not the secrecy of historical copies. If account
or device signing keys were also compromised, replace those credentials and
server trust before distributing new VK. Missing trusted device approval uses
recovery plus out-of-band verification; no automatic old-key-only transition.

3.6. Derive record keys from the record purpose key with HKDF-SHA-512,
salt=vault ID, 32-byte output, info=`["qv/record-key/v1", record_id]`.
Attachment keys use the attachment purpose key and
`["qv/attachment-key/v1", attachment_id]`. Per-record keys do not allow
individual cryptographic erasure while VK remains available.

### 4. Recovery phrase

4.1. Encode VK's 256 bits plus BIP-39 checksum as 24 English words.
This is mnemonic **entropy encoding**, not the BIP-39 PBKDF2 wallet seed
function. Decode directly to VK. No optional extra mnemonic passphrase in v1.

4.2. Show at creation; require confirmation or an explicit recorded skip.
Never log, persist plaintext or send it to the server. Redisplay only after
master-password reauthentication; follow native secret-input/display rules.
Rotation generates a new phrase; the operation may take significant time for
history/attachments and MUST be resumable rather than promising a fixed duration.

4.3. A phrase decrypts a matching vault file without its password. Recovering
only from the server also needs the account login (0006); a phrase alone is not
an account credential. With no local copy or enrolled device, a master password
alone cannot bootstrap server recovery, because no password verifier/slot is
stored there in attackable form.

### 5. Quick unlock and platform wrapping

5.1. Opt-in, device-local. Store a versioned backend envelope identifying its
algorithm, keystore key handle, authenticated vault ID/generation and access
policy. It is not required to implement XChaCha inside secure hardware.

5.2. Android profile uses a generated nonexportable AES-256-GCM keystore key
with authentication required for each operation; prefer StrongBox when available.
Use provider-generated nonrepeating encryption IVs, bind vault/generation/device
as AAD, and validate security level. Apple/Windows backends must use documented
authenticated keychain/enclave or OS-protected wrapping; specify and test each
backend envelope before enabling it. A generic Secret Service entry is not
evidence of per-operation authentication or hardware nonexportability.
Unsupported backends disable quick unlock; no silent weaker fallback.

5.3. Exportable fallback keys require explicit reduced-protection opt-in and
OS authentication before release. Exclude every quick slot, key handle and
device-bound secret from exports, cloud backup and sync. Hardware-bound storage
and exported keychain storage must not be presented as equivalent protections.

5.4. Require the master password after reboot, seven-day maximum age by default,
three failed attempts, password change, rotation or loss of trusted local
policy state. Keep policy state outside the replaceable vault and bind it to
generation. Destroy old slots/handles after invalidation.

### 6. Hybrid asymmetric cryptography

6.1. X-Wing is pinned to
[draft-connolly-cfrg-xwing-kem-11](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html).
Its combiner is
`SHA3-256(ss_MLKEM || ss_X25519 || ct_X25519 || pk_X25519 || XWingLabel)`,
with label hex `5c2e2f2f5e5c`. Use the exact draft's validation, key encoding
and known-answer tests; a newer draft requires a new enrollment profile.
Do not implement the combiner by composing unreviewed primitive calls.

6.2. A hybrid signature requires both Ed25519 and ML-DSA-65 over the same
canonical CBOR array beginning with a purpose/version string. Require exact
key/signature lengths and reject missing halves or unknown profiles.
Account OPAQUE and ordinary TLS certificates are explicit classical exceptions;
vault key transfer and device/server application identities remain hybrid.

6.3. Transport requires TLS 1.3 and hybrid X25519MLKEM768; abort unsupported
negotiation for account/enrollment traffic rather than silently falling back.
TLS protects metadata, sessions and OPAQUE exchanges; vault encryption remains
independent. Never put VK in plaintext inside a TLS-only transfer.

### 7. General rules

7.1. Stored-data and password-wrap XChaCha nonces are random 24-byte OS CSPRNG
values. Do not reuse key/nonce pairs. Platform GCM nonce policy is backend-specific
(§5), not the XChaCha rule. RNG failure aborts operations.

7.2. All AAD/transcripts use canonical CBOR arrays with purpose, vault,
generation, IDs and relevant profiles. Authenticate the entire header and exact
local keyslot set after obtaining VK; enforce profile bounds before the KDF.
Header MAC covers canonical header fields excluding its MAC plus slots sorted
by slot ID. Portable configuration excludes quick slots (0004).

7.3. Use constant-time MAC/tag comparisons and reviewed crypto implementations.
Crate popularity is not evidence of an audit: record versions, provenance,
applicable audits and known-answer results before release. No custom primitives.
The enrollment composition itself requires review and negative tests (0012).

### 8. Unlock

Unlock is local: validate file/profile limits, unwrap VK, verify header MAC,
manifest/completeness and external anchor, then expose metadata and handles.
Protected values remain encrypted when idle. Failed password unwrap reports
only wrong password; authenticated-structure or rollback failures are integrity
errors and must not be mislabeled as a password typo. See 0004 and 0008.

## Security Considerations

Neither strong primitives nor MACs establish freshness. Historical copies and
OS memory persistence remain relevant even after password changes. Account
password guessing and device compromise are separate from vault encryption.

## Open Questions

1. Benchmark password-kdf/1 before publication.
2. Implement and validate platform-wrap backends per target; disable unavailable
   mechanisms rather than relying on an unverified portability assumption.

## Changelog

- 2026-10-14: Initial accepted key hierarchy and recovery design.
- 2026-10-15: Amendment: independent profile namespaces, pinned X-Wing and MAC
  definitions, full generation rotation lifecycle, platform-specific wrapping,
  stable logical versions, explicit key derivation and realistic unlock guarantees.
