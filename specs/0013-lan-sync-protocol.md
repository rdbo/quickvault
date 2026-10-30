# 0013 — Direct LAN Sync Protocol

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-30 | 0001, 0002, 0004, 0005 §6 |

## Summary

Account-free synchronization between two devices on the same network:
- **Discovery:** endpoints come from a pairing QR, manual entry or DNS-SD
  advertisements made only while a user-opened window is open. No address
  is trusted.
- **Pairing:** an out-of-band pairing (QR, or a 26-character code with a
  128-bit secret, plus a committed six-digit comparison code) creates a
  **pairwise link key** for one peer, one vault and one key generation. In
  new-device mode it also transfers VK.
- **Sessions:** each session authenticates with the link key and gets
  forward secrecy and hybrid post-quantum confidentiality from a fresh
  X-Wing exchange.
- **Exchange:** peers trade complete encrypted manifests and the immutable
  objects the other lacks. Each side verifies them, merges under 0005 §2 and
  commits locally under 0004 §5 and 0005 §5.4.
- **Removal:** local, per link. Rotation drops every link; compromise
  recovery is rotation plus re-pairing.

This spec resolves 0005 Open Questions 3–6 (roadmap D10, delegated by the
owner on 2026-10-30; acceptance also delegated the same day). It uses only primitives already
pinned in 0002. It is a composition that still needs the independent
review required by 0012 §3; an accepted spec is not a security proof, and
no LAN release is authorized before that gate.

## Motivation

0005 §6 sets the requirements for LAN sync: approved peers, authenticated
out-of-band enrollment, a reviewed session, complete-manifest acceptance and
local durable commits. It deliberately selects no wire protocol (§6.7).
Milestone 2 needs a protocol that:
- works with no server, account or Internet;
- stays small enough to review;
- keeps vault-key transfer hybrid post-quantum (SG6);
- satisfies 0002 §3.5.5: rotation invalidates LAN approvals.

**Alternatives considered (D10):**
- *Per-device hybrid signature identities* (as in 0006): allow blocking one
  device, but add the most composition and need ML-DSA in milestone 2.
- *A credential derived only from VK:* the simplest, but every VK holder
  (a restored phrase, a stolen unlocked file) could then sync without any
  approval. That contradicts 0005 §6.2.
- *TLS 1.3 with pinned self-signed certificates* (as in Syncthing): reuses a
  reviewed record layer. But certificate authentication is classical, so it
  would still need a hybrid application signature bound to the channel,
  and VK transfer would still need its own X-Wing envelope (0002 §6.3).

Pairwise link keys give per-peer approval and local blocking. Their
authentication is symmetric, so quantum attacks don't break it. They use
only existing profiles.

## Specification

### 1. Profiles, notation and transport

1.1. **Profile.** `lan / 1` is a new purpose namespace (see the 0002
amendment in §13):
- the KEM is X-Wing draft-11 (0002 §6.1): encapsulation key 1216 bytes,
  ciphertext 1120 bytes, shared secret 32 bytes;
- key derivation uses HKDF-SHA-512 and authentication MAC/1 (HMAC-SHA-512
  truncated to 32 bytes);
- records use XChaCha20-Poly1305 with the counter nonces of §6;
- transcript hashes use SHA-256.

An unknown or unsupported `lan` profile fails closed: before authentication
by closing the connection, afterwards with error `unsupported` (§11).

1.2. **Encoding.** Every message is a canonical CBOR array (0004 §3.1) whose
first element is its label string. `bstr(n)` is a byte string of exactly `n`
bytes, `uint` an unsigned integer of at most 64 bits, and `bool` the CBOR
simple value `true` or `false`. Decoders reject
any other shape, extra elements, noncanonical encodings and unknown labels.
`H(x)` is SHA-256 of the canonical encoding of `x`. Every key derivation
below is

```
HKDF-SHA-512(IKM, salt, info = canonical CBOR array, L)
```

`L` is 32 unless stated otherwise, and `‖` is byte concatenation of
fixed-length values only. HKDF salts are byte strings. Where a salt is
written as an array, the salt is `H(array)`. The pairing ID's empty salt is
the zero-length string.

1.3. **Transport.** A single TCP connection, IPv4 or IPv6. Each frame is a
`u32` big-endian length followed by that many body bytes:
- before the session keys exist, a frame body is at most 4096 bytes;
- afterwards, at most 1,052,672 bytes (1 MiB plus 4 KiB).

A larger length closes the connection before any allocation. A peer
reads at most one frame ahead. Time limits: 10 s per handshake message,
60 s idle during an exchange, and the window limits in §8.

1.4. **Addresses.** An endpoint is an IP literal (4 or 16 bytes) and a
port. v1 does not resolve hostnames, so manual entry leaks nothing to
DNS. Loopback endpoints are allowed only for tests and must be enabled
explicitly.

### 2. Roles and states

- *Approving device* **A**: has the vault unlocked and opens a pairing
  window.
- *Joining device* **B**: scans or types the pairing code. It joins in
  **new-device** mode (it has no copy of this vault and generation) or
  **link** mode (it already holds the same vault and generation, unlocked).
- *Initiator* **I** and *responder* **R** in a sync session: R has an open
  receive window; I connects. Roles never affect the merge result
  (0005 §6.1).

Each window or session is a state machine. Any message other than the next
expected one, a failed check, a timeout, a lock or a cancellation moves it
to **Aborted**:
- erase every ephemeral secret (§9.4);
- discard staged data;
- keep accepted local state unchanged;
- close the connection.

Committed local state stays committed (0005 §6.5).

### 3. Discovery and addressing

3.1. Endpoints come only from:
- the pairing QR (§4.2);
- manual entry;
- the link's remembered endpoint hints (§9.2);
- DNS-SD results collected during an explicit user action.

All of them are untrusted hints (0005 §6.2). Authentication comes only from
§4 and §5.

3.2. **Advertising** runs only while a pairing or receive window is open
(§8). It is off when the user disables discovery, which must be possible
on every platform, and then manual entry still works.
- Service type: `_qvault._tcp.local`.
- Instance name: `qv-` plus 16 lowercase hex digits, random per window.
- TXT record: `v=1`. Pairing windows add `p=` plus 8 hex digits of
  `HKDF(IKM=P, salt=pairing_id, info=["qv/lan-pair-tag/v1"], L=4)`,
  which lets the joining device pick the right advertisement.

Advertisements carry no vault ID, generation, device name, user name or
other A2 data. Where the platform lets the application choose the mDNS host
label, it MUST use a random per-window label. Otherwise the OS host name is
accepted leakage, documented per platform (0009). Advertising stops when
the window closes.

3.3. **Browsing** runs only during an explicit pair or sync action, for at
most 3 s. It keeps at most 16 candidate endpoints. The initiator tries the
candidates one at a time and stops at the first authenticated session. A
wrong responder gets one hello, which holds no identifier and nothing
reusable (§5.1).

3.4. **Android** (0009): resolve discovered or QR-named services through
the platform's service-discovery API where possible. It grants
per-service access without the broad local-network permission. Request
the local-network permission only when the user enters an endpoint by hand
or the platform requires it, with an explanation, and never at start-up.

### 4. Pairing

4.1. **Opening.** A opens a pairing window for one unlocked vault (§8.1).
It generates:
- the pairing secret `P`: 16 random bytes;
- `pairing_id = HKDF(IKM=P, salt=empty, info=["qv/lan-pair-id/v1"], L=16)`;
- `K_hello = HKDF(P, pairing_id, ["qv/lan-pair-mac/v1", "hello"])`;
- `K_accept = HKDF(P, pairing_id, ["qv/lan-pair-mac/v1", "accept"])`.

4.2. **Out-of-band code.** A shows:
- **QR:** `["qv/lan-pair-qr/v1", lan_profile: uint, P: bstr(16),
  endpoints: [ [addr: bstr(4)|bstr(16), port: uint] ]` with 0–8 entries,
  `instance: tstr]`. `instance` is the window's DNS-SD instance name, or
  empty when discovery is off.
- **Manual code:** `P` in RFC 4648 base32 without padding (26 characters),
  shown in groups of five. Input ignores case, spaces and `-`. The endpoint
  is typed separately or found through the `p=` tag.

`P` never travels over the network. A wrong code fails the MAC; there is no
other check.

4.3. **PairHello (B → A, cleartext frame).** B generates `nonce_B`
(32 random bytes) and a fresh X-Wing key pair `(dk_B, ek_B)`.

```
body   = ["qv/lan-pair-hello/v1", lan_profile: uint, pairing_id: bstr(16),
          mode: uint (0 = new device, 1 = link), commit_B: bstr(32),
          ek_B: bstr(1216)]
commit_B = H(["qv/lan-pair-commit/v1", nonce_B])
hello    = body ++ [MAC/1(K_hello, canonical(body))]      (one 7-element array)
```

A checks, in this order: the frame length, the exact shape, the profile,
`pairing_id` (window match), the MAC in constant time and the X-Wing key
validity. On any failure A closes the connection, sends nothing and counts
the failure (§8.3).

A accepts **one** valid hello per window. A second valid hello with
different bytes aborts the window and warns the user that the code may have
been observed. An identical repeat on a new connection is also refused
(single use).

4.4. **PairAccept (A → B, cleartext frame).** A computes
`(ct, ss) = X-Wing.Encaps(ek_B)` and draws `nonce_A` (32 random bytes).

```
body   = ["qv/lan-pair-accept/v1", nonce_A: bstr(32), ct: bstr(1120)]
accept = body ++ [MAC/1(K_accept, canonical(["qv/lan-pair-accept/v1",
                    H(hello), nonce_A, ct]))]
th     = H(["qv/lan-pair-th/v1", H(hello), H(accept)])
k_b2a  = HKDF(ss ‖ P, th, ["qv/lan-pair-key/v1", "b2a"])
k_a2b  = HKDF(ss ‖ P, th, ["qv/lan-pair-key/v1", "a2b"])
```

B verifies the MAC in constant time and decapsulates. From here both
directions use the §6 record layer with these keys.

4.5. **Reveal and comparison code.**
- B sends `["qv/lan-pair-reveal/v1", nonce_B: bstr(32)]`, and A checks it
  against `commit_B`.
- Both compute `SAS = (u32be(first 4 bytes of
  H(["qv/lan-pair-sas/v1", th, nonce_B]))) mod 1,000,000` and show it as
  six digits.

B committed to `nonce_B` before seeing `nonce_A`, and A fixed `nonce_A`
before seeing `nonce_B`. A man in the middle who knows `P` therefore cannot
search for keys or nonces that make both screens show the same code; one
attempt matches with probability 10⁻⁶. This prevents the truncated-code
grinding of CVE-2025-32898.

A shows the code with B's requested mode and the vault's name. A releases
nothing until the user confirms that both codes match. A mismatch or a
cancellation aborts on both sides.

4.6. **Link derivation.** A draws `link_id` (16 random bytes).
`K_lan = HKDF(VK, vault_id, ["qv/purpose/v1", "lan-link", key_generation,
derivation_profile])` is the new purpose key (0002 §3.3, amended in §13).
Then:

```
link_key = HKDF(K_lan ‖ ss,
                ["qv/lan-link-salt/v1", th, nonce_B, link_id],
                ["qv/lan-link/v1", vault_id, key_generation, link_id])
```

Binding to `K_lan` makes a link usable only by holders of this
generation's VK, and makes every link invalid after rotation.

4.7. **New-device mode.** After confirmation, A commits its link row (§9.1).
It then sends
`["qv/lan-pair-grant/v1", vault_id: bstr(16), key_generation: uint,
vk: bstr(32), link_id: bstr(16)]`.

B derives `K_lan` and `link_key`. The connection then runs one exchange
(§7), with B as initiator and A as responder, over the pairing keys
(`k_b2a` as `k_i2r`, `k_a2b` as `k_r2i`, with their sequence numbers
continuing). B starts empty: it sends the state message with an empty
manifest and requests everything. B then initializes the vault under §10.

A reports "paired" only after B's `Done`. If B never sends it, A reports
"pairing may be incomplete on the other device" and keeps the link. Nobody
else can derive that key, so the leftover link is harmless; the user can
remove it.

4.8. **Link mode.** After confirmation, B (which has the vault unlocked)
sends
`["qv/lan-pair-prove/v1", vault_id, key_generation, proof_B]`, where
`proof_B = MAC/1(K_lan, canonical(["qv/lan-pair-prove/v1", th, "b",
vault_id, key_generation]))`.

A checks:
- the vault ID and generation against the window's vault;
- `proof_B` in constant time, with its own `K_lan`.

A mismatch sends error `vault_mismatch` and aborts; nothing is stored.

A then commits its link row (§9.1) and sends
`["qv/lan-pair-proved/v1", link_id, proof_A]`, with `proof_A` defined in the
same way with role `"a"`. B verifies it and commits its own row. B sends
`["qv/lan-pair-done/v1"]` after its commit is durable. The connection then
runs one ordinary exchange (§7) over the pairing keys, with B as
initiator, as in §4.7. A failure of that exchange leaves both links in
place; the user syncs again later.

VK never crosses the network in link mode.

4.9. Pairing transfers no endpoint authority and no checkpoint. LAN
pairing establishes no server base (0005 §6.4).

### 5. Session handshake

5.1. **SyncHello (I → R, cleartext frame).** I draws `nonce_I` (32 bytes)
and a fresh X-Wing key pair `(dk_I, ek_I)`.

```
K_i   = HKDF(link_key, empty, ["qv/lan-auth/v1", "i"])
K_r   = HKDF(link_key, empty, ["qv/lan-auth/v1", "r"])
body  = ["qv/lan-hello/v1", lan_profile: uint, nonce_I: bstr(32), ek_I: bstr(1216)]
hello = body ++ [MAC/1(K_i, canonical(body))]
```

The hello carries **no link or vault identifier**. R evaluates the tag
against every link of the window's vault (at most 64, §9.1). It SHOULD
check all of them rather than stopping at the first match, and compare
each tag in constant time.
- No match: R closes the connection, sends nothing and counts a failure.
- A `nonce_I` already seen in this window: R refuses the hello.

R performs no KEM operation before a tag verifies, so an unauthenticated
peer cannot make R do expensive work.

5.2. **SyncAccept (R → I, cleartext frame).** R computes
`(ct, ss) = X-Wing.Encaps(ek_I)` and draws `nonce_R`.

```
body   = ["qv/lan-accept/v1", nonce_R: bstr(32), ct: bstr(1120)]
accept = body ++ [MAC/1(K_r, canonical(["qv/lan-accept/v1", H(hello), nonce_R, ct]))]
th     = H(["qv/lan-th/v1", H(hello), H(accept)])
k_i2r  = HKDF(ss ‖ link_key, th, ["qv/lan-session/v1", "i2r"])
k_r2i  = HKDF(ss ‖ link_key, th, ["qv/lan-session/v1", "r2i"])
```

I verifies the tag in constant time, which authenticates R freshly, since
`H(hello)` covers `nonce_I`. I then decapsulates and erases `dk_I` and `ss`.

5.3. **Confirm.** I's first record (§6) is `["qv/lan-confirm/v1", th]`.
R accepts nothing else before it. A valid confirm proves that I holds
`dk_I`, so a replayed hello can never get past this step. R then erases
`ss`.

5.4. **Properties claimed** (the review in 0012 §3 must confirm them):
- mutual authentication by the link key;
- the session key depends on a fresh hybrid KEM secret, so recorded
  traffic stays confidential if the link key or VK leaks later, and
  breaking only one half of X-Wing does not expose it;
- the separate `"i"`/`"r"` and `"i2r"`/`"r2i"` labels prevent reflection;
- every handshake field is bound into `th`.

Not claimed: protection against a party that holds the link key (it also
holds VK, 0001); hiding traffic patterns.

### 6. Record layer

6.1. Each direction has its own key (`k_a2b`/`k_b2a` or `k_i2r`/`k_r2i`) and
a 64-bit sequence number that starts at 0 and is never sent. A record is
one frame whose body is

```
XChaCha20-Poly1305(key, nonce = 16 zero bytes ‖ u64be(seq),
                   aad = canonical(["qv/lan-record/v1", seq]),
                   plaintext = canonical message)
```

The receiver decrypts with the sequence number it expects next. A failed
tag, a gap, a reordering or a replay aborts the session. Keys are unique
per session and direction, so counter nonces never repeat. A direction
that reaches 2³² records aborts.

6.2. A record's plaintext is one message of at most 1,048,576 + 1,024
bytes. The decoder bounds every length field before allocating
(0004 §4).

### 7. Exchange

7.1. **Turn order.** Strictly alternating, which makes the state machine
easy to bound:

```
I: State   R: State
I: Manifest*   R: Manifest*
I: Want*   R: Object*      (R serves I's requests)
R: Want*   I: Object*      (I serves R's requests)
each side: verify → merge → commit (§7.6)
I: Done    R: Done
```

If both states name the same `manifest_hash`, both send `Done` with
outcome 0 straight after the state messages.

7.2. **State.** `["qv/lan-state/v1", vault_id: bstr(16), key_generation:
uint, manifest_hash: bstr(32), manifest_length: uint, features: [uint]]`.
- A joining new device sends an all-zero hash and length 0, then no
  manifest parts and an empty final `Want` reply set. This is valid only
  in the exchange that follows a new-device grant (§4.7). Anywhere else,
  length 0 is `protocol`.
- A vault ID or generation that differs from the receiver's sends error
  `vault_mismatch` and aborts. Generations are never merged automatically
  (0005 §6.4).
- An unknown feature in `features` is required: the receiver sends
  `unsupported` and aborts. v1 sends `[]`.
- A manifest length above 64 MiB is answered with `limit` before any
  allocation.

7.3. **Manifest.** `["qv/lan-manifest/v1", offset: uint, bytes: bstr]`,
with at most 1 MiB per part. Parts are contiguous from offset 0, and their
total equals `manifest_length`. The bytes are the manifest envelope exactly
as in an archive frame (0004 §6.1). The receiver:
1. checks `SHA-256 = manifest_hash`;
2. decrypts with the manifest key and AAD (0004 §3.4);
3. validates the manifest and every budget (0004 §4.1–4.2, 0005 §5.1)
   before parsing any object.

Each side's manifest is the state it named in its state message, and it
serves objects from a consistent read of that state. If it
can no longer do so, it sends `state_changed`, the round aborts and the
user can retry.

7.4. **Want.** `["qv/lan-want/v1", ids: [bstr(16)], last: bool]`, with at
most 4,096 IDs per message. The receiver requests exactly the referenced
objects it does not hold with an identical reference
`[object_id, data_profile, ciphertext_length, SHA-256]`.
- A local object with the same ID but a different reference is an
  integrity error. The round aborts with `integrity`, and the user sees
  substitution evidence.
- Totals stay within 250,000 objects and 2 GiB of staging (0004 §4.1,
  §4.3).
- The sender refuses an ID that is not in the manifest it sent
  (`protocol`).

7.5. **Object.** `["qv/lan-object/v1", envelope: bstr]`. Objects arrive in
request order, one per record. The receiver:
- checks the envelope's object ID against the next requested ID;
- checks the length and SHA-256 against the manifest reference **before**
  AEAD;
- then verifies the AEAD and stages the object (0004 §3.6).

Objects are streamed to private staging, never accumulated in memory
beyond one record. An unrequested, duplicated or out-of-order object is
`protocol`.

7.6. **Accept and commit.** With every reference verified, the receiver:
1. merges the peer's manifest into a local candidate under 0005 §2. It
   keeps local heads, tombstones and suppression floors, and lets no
   version resurrect.
2. commits the candidate through the single local write path:
   DB commit, then anchor, then report (0004 §5, 0005 §5.4).

If a budget is exceeded, the merge aborts without changing accepted state
(0005 §2.2). A local edit committed during the round is part of the base
of that merge. The merge never stalls or overwrites it.

7.7. **Done.** `["qv/lan-done/v1", outcome: uint (0 unchanged, 1 merged,
2 merged with conflicts), manifest_hash: bstr(32)]`. `manifest_hash` is
the sender's new local manifest.
- Frontends report local acceptance and confirmed peer receipt separately
  (0005 §6.5).
- A local commit survives a lost `Done`.
- Repeating a round is idempotent: versions are deduplicated by version
  ID.

7.8. **Never sent:**
- the SQLite file;
- device-local quick slots;
- anchors, local heads, replica rows and LAN tables;
- server sync state (0005 §6.3).

A LAN round never changes `sync_state`, server checkpoints or the outbox
(0005 §0.3, §6.6).

### 8. Windows (listening lifecycle)

8.1. **Opening.** A pairing window or a receive window opens only through
an explicit user action, for one unlocked vault. Nothing opens one
automatically (0005 §0.5). While the window is open:
- a TCP listener runs on an OS-chosen port, or one the user chooses;
- advertising runs (§3.2) unless discovery is off;
- the UI shows that the device is reachable and how long remains.

8.2. **Closing.** A window closes at the earliest of these:
- its time limit: pairing 10 minutes; receive 2 minutes by default,
  at most 15 minutes;
- an explicit cancel, a lock, process exit, or the app leaving the
  foreground on mobile;
- a pairing completing or aborting;
- for a receive window, the first completed session, unless the user
  asked to stay open for further sessions within the limit;
- 16 failed pre-authentication attempts (§8.3).

There is no background service and no retry after the window closes
(0005 §0.5). Closing stops the listener and the advertising, and erases
the window's secrets.

8.3. **Abuse limits.**
- One session at a time; other connections close immediately, unanswered.
- 16 failed hellos or pairing hellos close the window, and the user is
  told "unexpected connection attempts".
- Handshake time limits are in §1.3.

8.4. **Initiating.** A sync session also starts only through an explicit
user action. The action may retry within itself (bounded, while unlocked),
but nothing is scheduled afterwards (0005 §0.5). Both vaults must be
unlocked (0005 §6.1).

### 9. Peer state

9.1. **`lan_link`** is a local-only table, at most 64 rows per vault:

| Column | Contents |
|--------|----------|
| `link_id` | `bstr(16)`, primary key |
| `key_generation` | the generation the link is bound to |
| `sealed` | XChaCha20-Poly1305 under the `local-state` purpose key, random nonce, AAD `["qv/lan-link-row/v1", vault_id, key_generation, link_id]`, plaintext `[link_key: bstr(32), label: tstr (≤ 64 bytes, user-chosen), created_at: uint]` |

Every insertion or removal is one commit through the ordinary write path.
The commit writes a new local head whose `lan_links_digest` is
`H(["qv/lan-links/v1", sorted [link_id, SHA-256(sealed)]])` (amendment to
0005 §5.4 and 0004 §2, see §13). On open:
- rows that do not match the head's digest are an integrity error,
  handled like a local head mismatch;
- removed rows cannot be planted back without moving the head, which the
  anchor catches.

9.2. **`lan_hint`** holds unauthenticated convenience data, local-only
and not in the digest: per `link_id`, sealed the same way with label
`"qv/lan-hint/v1"`, up to 4 last-seen endpoints and the time of the last
successful session. Losing it or rolling it back costs only convenience.
A hint is never trusted.

9.3. Both tables are excluded from manifests, archives, snapshots and
restores (0004 §3.5, 0007). A restored or rotated vault starts with no
links.

9.4. **Ephemeral secrets** are `P`, `K_hello`, `K_accept`, `dk_*`, `ss`,
nonces before reveal, the pairing and session keys, and decrypted
`link_key`s. They are held in `qv_crypto` protected containers
(0008 §1), are never logged, and are erased on completion, abort, lock
or window close. Lock invalidates staged-response handles (0005 §6.5).

### 10. New-device initialization

B in new-device mode must not expose data before acceptance. Order:
1. Receive the grant and the full exchange into private staging. Verify
   the manifest and every object (§7.3–7.5).
2. Find the unique verified password keyslot record. If it is missing or
   conflicted, abort with `keyslot` and tell the user to resolve it on A
   (0005 §2.6).
3. Send `Done` with outcome 1 and A's manifest hash. Here `Done` reports
   receipt, not a commit (contrast §7.7); A reports "paired, the other
   device is finishing". The connection may then
   close; B's remaining steps are local.
4. Show the received vault's name and the pairing's comparison code, and
   require the user's confirmation that this is the vault to join. This
   stops a victim who scanned an attacker's code from silently joining the
   attacker's vault (as in 0006 step 3). Then ask the user for the vault's
   master password and verify it against
   the keyslot record before publishing anything.
5. Build the new vault file:
   - a fresh replica and writer ID;
   - the adopted password slot;
   - the merged objects and manifest;
   - the `lan_link` row, in the first local head.

   Write it as a private temporary file, verify it, fsync it and publish
   it by no-replace rename (the 1.13b restore path, 0004 §5). Then create
   the anchor, then report. A leftover temporary file after a crash is
   removed on the next attempt. Nothing appears at the destination path
   before step 5 completes.
6. If B holds an older generation of the same vault, that file stays
   untouched and private. Salvaging its edits follows 0002 §3.5.6.

### 11. Errors

After the session keys exist, an error is the record
`["qv/lan-error/v1", code: uint]`, followed by Aborted. Codes:

| Code | Name | Meaning |
|------|------|---------|
| 1 | `vault_mismatch` | Different vault ID or generation, or a failed link-mode proof |
| 2 | `unsupported` | Unknown profile or required feature |
| 3 | `limit` | A 0004 budget would be exceeded |
| 4 | `integrity` | Manifest, object or reference verification failed |
| 5 | `cancelled` | User cancel, lock or window close |
| 6 | `busy` | The vault is locked for writing (e.g. rotation in progress) |
| 7 | `state_changed` | The sender can no longer serve its named state |
| 8 | `keyslot` | No unique verified keyslot record for a new device |
| 9 | `protocol` | Unexpected message or field |

Before authentication nothing is sent: failures look identical to a closed
port. Unknown codes are treated as `protocol`. Frontends map the codes onto
0011 exit codes when the CLI commands are specified (roadmap 2.10).

### 12. Generation transitions and removal

12.1. **Removing a link** is a local commit that deletes the row and hint.
The peer is not notified. Its next hello fails authentication and looks
like an unreachable peer, so I's frontend says: "no linked device
answered; it may have removed this link or rotated the vault key". A
removed peer that holds VK can still read its own copy and forge
same-generation state (0001). Removal only stops this device from
exchanging with it.

12.2. **Rotation** (0002 §3.5):
- the replacement vault has no `lan_link` rows;
- `K_lan` changes with the generation, so every old link key is
  unusable;
- each remaining device re-pairs in new-device mode, which creates a new
  vault file for the new generation (§10.6);
- old-generation peers stop normal sync: their hellos fail.

This meets 0002 §3.5.5, because approval is authenticated by a fresh
out-of-band pairing that does not depend on old VK.

12.3. **Suspected compromise** of a linked device is handled by rotation
plus re-pairing of the trusted devices. Local removal alone is not
compromise recovery.

### 13. Amendments to other specs (applied 2026-10-30)

These edits were applied on acceptance, each with a Changelog line in its
spec.

1. **0002 §1.2**, new table row:
   `lan / 1 | X-Wing draft-11, HKDF-SHA-512, MAC/1, XChaCha20-Poly1305 with
   per-direction counter nonces, SHA-256 transcripts (0013)`.
2. **0002 §3.3**, new purpose label:
   `lan-link | Root of pairwise LAN link keys (0013 §4.6)`.
3. **0002 §3.5**, the final paragraph ("For LAN peers, propagation …")
   becomes: "LAN peer approvals are pairwise link keys bound to one key
   generation (0013 §9, §12). A rotated vault has no links and old link
   keys fail authentication. Each remaining device re-pairs through 0013
   §4 in new-device mode. Removal is local and is not compromise
   recovery."
4. **0004 §2**:
   - new rows `lan_link` and `lan_hint` (0013 §9), both "local-only; never
     in archives or sync";
   - the `local_head` row gains `lan_links_digest`;
   - the sentence "the local-only peer authorization/session-state schema
     remains to be specified …" becomes a reference to 0013 §9.
5. **0005 §5.4**: the local head gains `lan_links_digest` (0013 §9.1).
   §6.7 and Open Questions 3–6 point to 0013 as resolved.
6. **0001 *Accepted leakage***: "Exact advertisements and enrollment
   metadata remain to be specified in 0005" becomes "Advertisements and
   pairing metadata are specified in 0013 §3–§4".

### 14. Coverage of 0005 §6

| 0005 requirement | Where |
|------------------|-------|
| §6.1: no server or account; both vaults unlocked; no primary; roles do not affect the merge | §2, §7.1, §8.4 |
| §6.2: discovery is not trust; explicit out-of-band approval binding peers, vault, generation and profile; no reuse of 0006 transcripts | §3.1, §4 (own labels; binds `th`, mode, vault and generation) |
| §6.3: authenticated, confidential, integrity- and replay-protected session; complete manifest before merge; budgets; no SQLite or local-only data; fail closed | §5, §6, §7.3–7.5, §7.8, §1.1 |
| §6.4: snapshot as merge input; no cross-generation merge; no server base | §7.2, §7.6, §4.9 |
| §6.5: local commit/anchor; lock cancels; idempotent retry; acceptance reported separately | §2, §7.6–7.7, §9.4 |
| §6.6: no server checkpoint or publication | §7.8 |
| §6.7 and OQ3–OQ6 | §3, §4–§6, §8, §9, §12 |

## Security Considerations

- **The pairing secret** has 128 bits. Offline search against an observed
  hello or accept MAC is infeasible. Observing the QR is the realistic
  threat; the single-hello rule and the committed comparison code (§4.3,
  §4.5) cover it. A user who confirms codes without comparing them is
  the residual risk, as in 0006.
- **Link keys** need `K_lan`, so a stolen locked device yields nothing
  usable without VK. Every party holding a link key also holds VK, and
  0001 already concedes everything to such a party.
- **Post-quantum.** Authentication is symmetric (MAC/1). Confidentiality
  and VK transfer use hybrid X-Wing (SG6). Session keys also mix in the
  link key, or `P` during pairing.
- **Denial of service** is limited to the windows: they are short,
  explicit and abort after 16 failures. No KEM or KDF work happens before
  a MAC check.
- **Metadata.** Network observers see addresses, timing, frame sizes (which
  approximate the manifest size and object counts) and, during windows,
  an advertisement with no vault data (accepted leakage, 0001). There is no
  traffic hiding.
- **Hostile authenticated peers** (T5) are bounded exactly like archives:
  authenticate, then bound, then verify each object before AEAD, and never
  accept partially.
- **Not reviewed.** The composition (pairing, link derivation, handshake,
  record layer, secret lifecycle) has had no independent review. The 0012
  §3 LAN gate, including the review (roadmap D12) and interoperability
  vectors, must pass before any LAN release.

## Testing Requirements

Release evidence for the 0012 §3 LAN gate and the 0012 §1 LAN rows:

| Requirement | Evidence |
|-------------|----------|
| Byte-level interoperability | Vectors for every message, key derivation, transcript and error record (§4–§7, §11), produced by the implementation and checked independently |
| LAN discovery mistaken for trust | Spoofed advertisements and endpoints, and a raced or second pairing hello: no key release, no state change |
| Context substitution | A swapped vault ID, generation, profile, mode, `link_id` or role label; a reflected hello; a replayed hello or confirm: all fail |
| Comparison-code grinding | A man in the middle who knows `P` cannot force equal codes (a test of the ordering) |
| Hostile unauthenticated peers | Oversized frames, garbage, slow peers: bounded memory and time, no reply before authentication |
| LAN partial acceptance | Interrupt, lock, duplicate and retry at every message boundary and at the commit/anchor crash points; local edits and anchor preserved, no partial manifest |
| Peer state rollback | A removed row planted back, or a modified row, is detected (§9.1) |
| Generation transitions | Links fail after rotation; re-pairing in new-device mode works; the old copy stays untouched |
| Account-dependent LAN sync | LAN-only operation without Internet, account or server; either side initiates |
| Mixed-mode state confusion | A LAN round never touches `sync_state` or checkpoints |
| Explicit initiation | No window or session without a user action; nothing resumes afterwards |
| Discovery privacy | Advertisements contain only §3.2 fields; nothing outside a window |
| Fuzzing | Every pre-authentication and authenticated message decoder (roadmap 2.9–2.10) |

## Open Questions

1. **Window defaults** (receive 2 minutes, at most 15; one session unless
   kept open) are sane defaults to revisit after user testing.
2. **Incremental exchange.** Every round sends the full manifest (up to
   64 MiB). Manifest diffs or paging would follow 0005 OQ2 and are
   deferred until benchmarks call for them.
3. **Several vaults per window or session.** v1 handles one vault per window
   and per session. A device can still hold links for several vaults.

## Changelog

- 2026-10-30: Accepted (owner-delegated). The §13 amendments to 0001, 0002, 0004 and 0005 are applied. Release still requires the 0012 §3 LAN gate, including the D12 independent review and interoperability vectors.
- 2026-10-30: Initial Draft (roadmap phase 2.1, plan 0025):
  - proposes the resolution of 0005 OQ3–OQ6 (D10, delegated by the
    owner): QR or manual endpoints with window-only discovery, pairwise
    generation-bound link keys from an out-of-band pairing with a
    committed comparison code, explicit time-boxed windows, and local
    removal with rotation for compromise;
  - lists the amendments to 0001, 0002, 0004 and 0005 that are applied on
    acceptance.
