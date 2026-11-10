# 0014 — One-Scan LAN Sync (no device links)

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-11-06 | 0013, 0005 §6, 0002 §3.3 and §3.5 |

## Summary

**0047 amendment (2026-11-09):** §10 applies the credential-authenticated
lan/2 flow in 0013 §15. The older handshake descriptions here are historical;
password enrollment prompts on both devices and key/phrase enrollment transfers
no VK. Nothing adds persistent credentials or changes file/archive formats.

Owner direction, 2026-11-06: "Not sure I see the point in pairing devices
when there is no identity. Maybe scanning = 1 sync only, and thats it."

This spec replaces 0013's stored pairwise links with a one-use code:
- **One window, one use.** A device with the vault unlocked opens a *sync
  window*. It shows a QR (and the 0013 §4.2 manual code with its address).
  The window serves exactly one session, then closes.
- **Sync mode** (replaces 0013 link mode and the §5 session handshake):
  the other device scans or types the code, and both run 0013's pairing
  hello and accept. Each side then proves it holds this vault and
  generation's key with a MAC bound to the transcript. Then they run one
  exchange (0013 §7). There is no comparison code, and nothing is stored
  about the other device.
- **New-device mode** keeps the comparison code and the join confirmation
  (0013 §4.5, §4.7, §10), because it hands over VK. It stores no link
  either.
- **Removed:** link keys, the `lan_link` rows' use, the §5 SyncHello
  session, receive windows and their address-only QR (§8.5), the linked
  device list, link labels and link removal.

Accepted by the owner on 2026-11-06 ("Accepted, go ahead"). The §9
amendments are applied to 0013, 0002, 0004, 0005, 0009, 0011 and 0012;
0013 is the normative text, and this spec records the change and its
rationale.

## Motivation

What a 0013 link provides today:
- it proves, at each later sync, that the user approved this peer once
  (0005 §6.2);
- it lets one device stop syncing with one other device (local removal).

What it costs:
- a secret per peer stored in every vault file (`lan_link`, its head digest);
- a second handshake (§5), a second window kind (receive) and a second QR
  kind (address-only);
- link names, a device list and a removal flow, for devices that have no
  identity (0013 §9.2: "v1 has no device identity");
- every sync still needs a user action on both devices: a receive window on
  one and the address typed or scanned on the other.

0013's *Alternatives considered* rejected "a credential derived only from
VK" because any VK holder could then sync without approval. This design
does not rely on VK alone. Each session needs:
1. the one-time secret `P`, shown only by a window the user opened on an
   unlocked device (that is the approval, given again for each session);
2. proof of this generation's VK, bound to the session transcript.

A party with only `P` (someone who saw the QR) learns nothing and cannot
sync. A party with only VK (a restored phrase, a stolen unlocked file)
cannot connect without a window's `P`. Per-session approval replaces stored
approval, so there is nothing left to revoke except by rotation, which
0013 §12.3 already requires for compromise.

Lost: blocking one device while still syncing with others. Without device
identity it was only local, and after compromise it needed rotation anyway.

## Specification

### 1. Roles and windows

1.1. The *offering device* **A** has the vault unlocked and opens a sync
window (0013 §8.1, renamed). It generates `P` and the keys of 0013 §4.1
unchanged, and shows the 0013 §4.2 QR and manual code unchanged.

1.2. The *joining device* **B** scans or types the code. It chooses
**sync** mode (it holds this vault, unlocked) or **new-device** mode (it
has no copy). The window accepts either; A learns the mode from the hello.

1.3. A sync window closes at the earliest of:
- 10 minutes (0013 OQ1 still governs this default);
- cancel, lock, process exit, or the app leaving the foreground on mobile;
- the end of its one session, completed or aborted;
- 16 failed pre-authentication attempts (0013 §8.3, unchanged).

There is no receive window and no "stay open" option. Nothing opens a
window or starts a session without a user action (0005 §0.5).

### 2. Sync mode

2.1. **Hello and accept.** 0013 §4.3–§4.4 unchanged, with `mode = 1`,
renamed from "link" to "sync". The single-hello rule and the second-hello
abort (0013 §4.3, §8.3) apply unchanged.

2.2. **No reveal, no comparison code.** In sync mode B does not send
`PairReveal` and neither side computes or shows the comparison code.
`commit_B` is still sent in the hello (the hello shape is shared by both
modes) and is not opened. The transcript `th` is 0013 §4.4's.

2.3. **Proofs.** The vault proof key replaces the link root:

```
K_proof = HKDF(VK, vault_id, ["qv/purpose/v1", "lan-proof", key_generation,
                               derivation_profile])
proof_X = MAC/1(K_proof, canonical(["qv/lan-pair-prove/v1", th, role_X,
                                     vault_id, key_generation]))
```

with `role_X` the text `"b"` or `"a"`.

Order:
1. B's first record is `["qv/lan-pair-prove/v1", vault_id: bstr(16),
   key_generation: uint, proof_B: bstr(32)]` (0013 §4.8, unchanged).
2. A checks the vault ID and generation against the window's vault, then
   `proof_B` in constant time. On any mismatch A sends `vault_mismatch`
   and aborts. **A sends nothing derived from `K_proof` before `proof_B`
   verifies.**
3. A sends `["qv/lan-pair-proved/v1", proof_A: bstr(32)]` (the `link_id`
   element is removed).
4. B verifies `proof_A` in constant time. On mismatch it sends
   `vault_mismatch` and aborts. B sends no exchange message before it
   verifies.
5. One exchange (0013 §7) follows over the pairing keys, B as initiator
   with `k_b2a` as `k_i2r` and `k_a2b` as `k_r2i`, sequence numbers
   continuing. Its commits, reports and failure handling are 0013 §7
   unchanged. `PairDone` is not sent in sync mode.

2.4. Nothing is stored about the peer: no row, label, address or key.
Each device's report says only that it synced with a device holding this
vault (local acceptance, conflicts, peer receipt; 0005 §6.5).

2.5. **Generations.** An old-generation copy fails step 2 or 4 with
`vault_mismatch`. Its frontend says the other device has a different key
generation and offers new-device mode (0002 §3.5.5, 0013 §12.2).

### 3. New-device mode

0013 §4.5, §4.7 and §10 unchanged, except:
- the grant is `["qv/lan-pair-grant/v1", vault_id, key_generation, vk]`
  (no `link_id`);
- A commits nothing before or after the grant; it reports "joined" after
  B's `Done`, or "the other device may not have finished" without it;
- §10 step 5 writes no `lan_link` row;
- the comparison code on both devices, A's explicit confirmation and B's
  confirmation of the vault name (0013 §10 step 4) remain mandatory.

### 4. Removed from 0013

- §4.6 link derivation, `link_key` and the `lan-link` purpose (replaced by
  `lan-proof`, §2.3).
- §4.8 link rows and their commits (the proofs move to §2.3).
- §5 (SyncHello, SyncAccept, Confirm and the `qv/lan-hello`, `qv/lan-accept`,
  `qv/lan-th`, `qv/lan-session`, `qv/lan-auth`, `qv/lan-confirm` labels).
- §8.5 receive-window code (`qv/lan-addr-qr/v1`). A decoder treats it as an
  unknown label.
- §9.1's use of `lan_link` (see §5 below), §12.1 link removal.
- Receive windows in §8.1–§8.2.

Kept unchanged: §1, §3 (with the pairing QR as the only QR), §4.1–§4.5 for
both modes, §6, §7, §8.3–§8.4, §9.2–§9.4 (ephemeral secrets now include
`K_proof`), §10, §11 (`vault_mismatch` now also means a failed sync-mode
proof), §12.2–§12.3.

### 5. Stored state

The vault format does not change. `lan_link` and the local head's
`lan_links_digest` (0004 §2, 0005 §5.4) remain so that existing development
files still open and verify. From now on:
- every commit writes the empty row set: it deletes all `lan_link` rows and
  sets `lan_links_digest` to the empty-set digest;
- open still checks the rows against the head digest (0013 §9.1);
- new-device creation, restore and rotation write no rows.

Rows left in an older file are never read for authentication and disappear
at that vault's next commit. Both structures are removed at the next format
change (pre-1.0, no freeze).

### 6. App (amends 0009 §1.7 and the Sync screen)

6.1. **Offering:** the Sync screen (named Devices before 2026-11-07) offers "Sync with another device".
It opens a window and shows the QR, the manual code, the endpoints and the
remaining time. A new-device hello shows the comparison code with the
vault name and asks for confirmation. A sync-mode session needs no input on
A. A shows the result, then the window is closed.

6.2. **Scanning to sync** (an unlocked vault, Sync screen): the scan is
the user's explicit action. If the QR carries endpoints, the sync starts at
once with them. If it carries none, the form shows that the code came from
the QR ("✓ Code from QR"; the code itself is never rendered) and asks for
the address; "Sync" starts it.

6.3. **Joining** (locked screen, "Join from another device"): a scan with
endpoints connects at once and goes straight to the comparison step. A
scan without endpoints behaves like §6.2. VK is released only after A's
confirmation, and nothing is published before B's confirmation and
password check (0013 §10).

6.4. **Typing** stays available everywhere: the manual code (secret input)
and the address, then Sync or Join. Scanned endpoints are hints only and
grant no trust (0013 §3.1). A manually typed address replaces scanned ones.

6.5. Scanned and typed codes stay in protected Rust containers; no code
reaches the renderer (0008 §1.1, 0009 §1.7). Endpoints are not secret and
may be shown.

6.6. **Camera frames:** a frame without a decodable code, or with more than
one code, is skipped and the scan continues within its 30-second limit. A
decoded payload that fails 0013 validation (wrong label, profile, size or
endpoint) ends the scan with an error.

### 7. CLI (amends 0011's LAN command contracts)

- `qv lan open [--port <n>] [--minutes <1-10>]`: unlock, open a sync
  window, and show the manual code, endpoints and time left on the
  alternate screen. A new-device hello asks the 0011 comparison question
  (`Do both devices show <code>? [y/N]`). It prints the sync lines (sync
  mode) or `joined` and the peer receipt (new-device mode). Exit 10 if
  the window closes without a session.
- `qv lan sync --endpoint <ip:port> [--endpoint …]`: prompt for the
  code (no echo), unlock, run one sync-mode session, print the sync lines.
- `qv lan join --endpoint <ip:port> [--endpoint …] --new <path>`:
  new-device mode as today, without `--label` or `paired:` output.
- `lan pair`, `lan receive`, `lan links` and `lan unlink` are removed.

The code stays out of argv and the environment; endpoints may appear in
argv; `--json` is rejected before unlock (0011, unchanged).

### 8. Errors

0013 §11 codes unchanged. Frontend messages:
- `vault_mismatch` in sync mode: "The other device has a different vault
  or key generation."
- a refused connection, or a window that already served its session: "No
  device answered with this code. Open a new code on the other device."

### 9. Amendments to apply on acceptance

Each with a Changelog line in its spec:
1. **0013:** apply §1–§5 and §8 here: rewrite §2, §4.5–§4.9, §8, §9.1,
   §10 step 5, §11 (`vault_mismatch` meaning), §12, §14, the Summary,
   *Security Considerations* and *Testing Requirements*; delete §5 and
   §8.5 and renumber; OQ1 refers to the sync window only.
2. **0002 §3.3:** the purpose label `lan-link` becomes `lan-proof`, "VK
   possession proofs for one LAN session (0013)". **§3.5:** "LAN sessions
   need a fresh code from an unlocked device and a proof of the current
   generation's VK; old-generation copies fail it and join again in
   new-device mode (0013 §12). No LAN approval is stored."
3. **0004 §2:** `lan_link` and `lan_links_digest` are kept for format
   compatibility and are always empty after a commit (§5 here).
4. **0005 §5.4:** the same note for `lan_links_digest`. **§6.2:** the
   approval is a one-use code shown by an unlocked device plus a
   transcript-bound VK proof, given for each session; no stored pairing.
5. **0009 §1.7:** replace "Scanning fills a selected Join/Link/Sync form
   and MUST NOT start a network operation" with §6.2–§6.6 here; drop the
   address-only payload.
6. **0011:** replace the LAN command contracts with §7 here; drop exit
   codes 4/5 for links.
7. **0012 §1:** "Account-dependent LAN sync": "sync two same-network
   devices with a one-use code" in place of "link". "Server revocation
   overclaim": drop "test selected LAN peer-removal policy separately"
   (there is no LAN peer state).

### 10. Credential-authenticated one-scan amendment (0047)

0013 §15 supersedes this spec's lan/1 handshake, proof, listener-monitor and
post-transfer password language. Use lan/2 exclusively with separate method
and intent: password/enroll, key/enroll (recovery words), key/sync (unlocked
copy). The first valid code-authenticated hello closes all admission and spends
the code; the accepted session retains the original absolute expiry. No
second-hello detector, retry, persistent verifier or storage migration is added.

Password enrollment prompts on both devices; A verifies locally and approves
the comparison before sending its ephemeral password-engine response. A sends
VK only after B proves credentials and confirms the final channel. B verifies
the public slot before transfer, then wipes password keys. Phrase enrollment
proves independently held VK, transfers no key and needs no password/reset.
Existing-copy sync remains password-free. Full private staging, received-name/
destination confirmation and source-bound preflight precede publication.
Both peers need software implementing the new profile; do not fall back.

All CLI/app prompt cleanup, bounded deadlines and precise disclosure/receipt/
local-outcome requirements in 0013 §15, 0009 §7 and 0011 §7 apply. The existing
command names, code-input confidentiality and endpoint replacement rules remain.

## Security Considerations

- Approval is one explicit window on an unlocked device, with an original
  absolute lifetime of at most 10 minutes. The first valid code-authenticated
  hello closes admission before credential work; no competing-hello detector
  survives. A code holder can deny service by taking that one admission.
- The code alone never authorizes a key grant or vault transfer. Password
  enrollment requires the selected vault's password on both devices, successful
  ephemeral password authentication and verified FinishedB before A seals a
  grant. Completed sealing counts as possible disclosure even if delivery is
  unknown. The receiver verifies the granted slot against its password before
  bulk transfer and the staged record before publication.
- Key routes require an independently obtained VK. B proves first; A reveals
  its identity and role-bound proof only after verification. Each proof binds
  the method, intent and outer transcript. A verifies B's first final-key State
  before returning final-key data. Credential failures close silently.
- A VK holder who observes the code can take the admitted session. The threat
  model already concedes same-generation data to a VK holder; rotation is the
  recovery. The intended receiver then needs a fresh window.
- X-Wing supplies hybrid outer confidentiality. The password engine uses
  classical Ristretto authentication; it is not claimed to be post-quantum.
  The final schedule mixes the outer secret, pairing secret and independent
  credential secret. SG6's limits and 0013 §15 apply.
- No registration, verifier, link key or peer authorization is stored.
  D12 independent composition review, dependency review and target evidence
  remain release gates; implementation tests do not prove security.

## Testing Requirements

In addition to 0013's current rows:

| Requirement | Evidence |
|-------------|----------|
| Key proof binding | Wrong VK, vault ID/generation, role, method or transcript fails before exchange or commit |
| Proof ordering | No A identity/proof before valid PB; no A final-key data before valid B State |
| Password ordering | No grant after missing/invalid KE3 or FinishedB; no code-only or legacy grant path |
| Relay | Captured proofs or records fail with distinct T0/TA, mode, role or epoch |
| Raced code | First valid hello closes every listener before approval; later connections cannot interrupt the admitted stream |
| One use | Completion, credential failure, cancellation and expiry never reopen admission |
| No peer state | Sync/join leave no peer authorization; historical link rows clear on the next ordinary commit |
| Removed messages | Old profiles, QR labels and credential-free handshake/grant shapes are refused |
| Generation | Old-generation copies fail; authenticated enrollment of the new generation works |
| Interop vectors | Independent v2 schedule/record/wire vectors and pinned password-component fixtures, with explicit suite limits |
| App | Protected instance-bound prompts, cleanup on cancel/lock, accurate receipt/publication reporting; no code in the DOM |

## Open Questions

1. **Sync window default** (10 minutes, one session): carried from 0013
   OQ1, to revisit after user testing.

## Changelog

- 2026-11-09: Reconcile security/testing requirements with §15 credential authentication and single admission; preserve historical v1 descriptions above.
- 2026-11-09: Apply owner-approved ephemeral credential authentication and one admitted connection.

- 2026-11-07: §6: the Devices screen is called Sync; no behaviour change
  (owner, plan 0045).
- 2026-11-06: Accepted by the owner. §9 amendments applied (plan 0042 step 1).
- 2026-11-06: Initial Draft (owner direction). Replaces 0013 links,
  sessions and receive windows with one-use sync windows and
  transcript-bound VK proofs; new-device mode keeps its comparison code.
  Lists the amendments applied on acceptance.
