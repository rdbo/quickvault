# 0001 — Threat Model

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | — |

## Summary

Defines protected assets, adversaries, operating-system prerequisites and the
limits of integrity/freshness guarantees. Every other spec is judged against
this document; valid encryption alone is not proof of freshness or availability.
The model covers standalone offline vaults, direct LAN peers and optional
account-based remote sync. Accounts and server availability are not prerequisites
for local or LAN operation.

## Specification

### Assets

| ID | Asset | Notes |
|----|-------|-------|
| A1 | Passwords, notes, attachments and TOTP seeds | Confidential |
| A2 | Titles, usernames, URLs and group structure | Confidential even when UI-visible |
| A3 | Master password, VK and derived keys | Compromise exposes vault data |
| A4 | Recovery phrase | Encodes VK |
| A5 | Vault integrity and remembered checkpoints | Subject to explicit rollback/fork limits |
| A6 | Availability, retained history and backups | Requires independent copies |
| A7 | Usage metadata | Accepted leakage below |

### Adversaries in scope

| ID | Adversary | Capabilities |
|----|-----------|-------------|
| T1 | Device thief | Locked/powered-off device; full disk image including swap, hibernation, temporary files and old SQLite pages |
| T2 | Compromised server/operator | Read/write server code, DB and responses; forge server-side authorization, reorder/drop/replay/withhold data and isolate device histories |
| T3 | Network attacker | Passive recording including future quantum analysis; active MITM on LAN or remote links, spoofed discovery and peer endpoints |
| T4 | Online guesser | API access, credential guessing and account enumeration |
| T5 | Malicious file/peer | Crafted SQLite, ciphertext, CBOR, old snapshots or protocol messages |
| T6 | Side-channel observer | Timing, clipboard history, screenshots, keyboard learning |
| T7 | Future cryptanalysis | Weakening of a classical or PQ component |
| T8 | Supply-chain tampering | Malicious or compromised dependency, build input or release artifact |

### Prerequisites and limits

T1 protection against plaintext persisted by the OS requires protected storage,
swap and hibernation whose keys are unavailable in the relevant device state
(0008). Screen lock alone is not proof. Unsupported/unverifiable configurations
must be reported as reduced protection and require explicit acknowledgement.
Zeroizing RAM and locking selected pages do not erase previous OS copies.

Rollback detection requires a remembered anchor/checkpoint outside the vault
file and its archives. Restoring both vault and external state can defeat it. A
malicious server may freeze a device at its last valid checkpoint or maintain
isolated valid forks. Detection requires cross-device checkpoint comparison or
an independent witness; v1 does not promise automatic global freshness/fork
detection. A new recovery without a trusted checkpoint has an unverified
baseline.

A local network is untrusted. Discovering a device does not
authorize it for a vault or permit key transfer. Approved peers holding VK can
decrypt and forge that generation's vault contents; server revocation does not
remove their LAN access or erase their copies. Compromise recovery requires
rotation and fresh approval under 0002, even for LAN-only vaults.

Malicious SQLite/CBOR/rendering inputs are in scope even while the vault is
unlocked. Excluding malware does not exclude remote code execution introduced
through the application's own parsers or UI.

### Out of scope

- Malware independently running as the user while unlocked.
- A compromised OS, firmware or hardware.
- An attacker already holding the master password or recovery phrase; compromise
  recovery still follows the operational rotation requirements in 0002.
- Physical/EM side channels beyond memory hygiene's stated mitigations.
- Server denial of service prevention. Clients still bound hostile resource use
  and detect missing referenced data; cryptography cannot restore deleted data.

### Security goals

- **SG1 Confidentiality:** A1/A2 remain confidential against T1–T5 under the
  prerequisites above, apart from accepted leakage.
- **SG2 Integrity:** reject forged/substituted objects and incomplete manifests
  before acceptance; do not silently omit failed records. This does not imply
  that every valid old snapshot or isolated fork can be identified.
- **SG3 Guessing resistance:** local file master-password guesses cost the fixed
  password KDF. The server has no vault-password verifier. A compromised OPAQUE
  server can guess the separate account password offline; online APIs rate-limit
  attempts on an honest server.
- **SG4 Rollback awareness:** detect regression against an intact remembered
  manifest/checkpoint and detect incompatible histories when compared (0005).
- **SG5 Crypto agility:** replace independent purpose profiles through explicit
  migrations, without conflating KDF, storage and authentication changes.
- **SG6 Hybrid vault transport:** breaking only one half of the hybrid key
  transport/application signatures does not expose VK. OPAQUE and ordinary TLS
  certificates are documented classical exceptions; account compromise alone
  does not grant VK.
- **SG7 No silent conflict loss:** preserve concurrent complete versions and
  deletion knowledge; retained history follows bounded policy (0007).
- **SG8 Intentional unrecoverability:** no project/server backdoor. Access needs
  a usable wrapped key plus its unlock method, recovery phrase plus data, or
  approved key transfer. Server-only recovery additionally needs account access.
- **SG9 No server vault-password verifier:** never upload a password keyslot
  except under VK encryption. Exchange archives carry no password slot either;
  only an explicitly self-contained backup exposes a guessing target to
  whoever holds it.
- **SG10 Release integrity:** releases come from locked, reviewed dependencies
  and verifiable signed artifacts (0012 §3). This reduces, but cannot remove,
  T8 risk; a compromised maintainer signing key is outside what users can
  detect without reproducible builds.

### Accepted leakage

The server learns account IDs, vault/device counts, random object IDs,
liveness/retention changes, padded sizes, timing, key generations, IP addresses
and grants. It does not learn which objects belong to the same record,
attachment or history (0004 §2.2). File-sync providers see archive sizes,
vault ID, generation and creation times; a wrapped password slot only in an
explicitly self-contained backup. No ORAM or traffic-hiding promise.
Views containing titles/usernames/URLs are confidential A2 data, not public data.

On LAN, network observers can see communicating addresses, connection timing
and traffic sizes; enabled discovery may also expose service presence. Advertisements
and pairing metadata are specified in 0013 §3–§4; they MUST NOT expose vault secrets or confidential A2 metadata. An approved peer
receives the shared vault's contents and authenticated causal metadata. LAN
sync makes no traffic-hiding or protection-from-an-approved-VK-holder claim.

## Security Considerations

Claims must preserve these conditions in product text and tests. A successful
sync does not establish global freshness; encryption does not guarantee
availability or secure erasure. Compromise recovery and session revocation are
separate lifecycle operations, not consequences of changing a password.

## Open Questions

None in this model. Platform verification and independent protocol review are
required implementation evidence under 0012.

## Changelog

- 2026-10-30: Owner-delegated acceptance of 0013 (roadmap D10, plan 0025): LAN advertisement and pairing metadata now point to 0013.
- 2026-10-24: Cover direct LAN sync and standalone use explicitly; reject
  network presence as trust, distinguish server revocation from LAN/key access,
  and document LAN traffic/discovery leakage.
- 2026-10-14: Initial accepted threat model; added SG9.
- 2026-10-15: Amendment: conditional OS persistence guarantees; honest limits
  for rollback, freeze, forks and availability; distinguish account guessing
  from vault-password verification and document reference-list leakage.
- 2026-10-15: Security review: add T8/SG10 supply chain; no record linkage in
  server-visible routing data; exchange archives carry no password slot.
