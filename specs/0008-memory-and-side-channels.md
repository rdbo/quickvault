# 0008 — Memory Hygiene and Side Channels

| Status | Created | Depends on |
|--------|---------|------------|
| Draft | 2026-10-14 | 0001, 0002 |

## Summary

Minimize plaintext lifetime and copies, prevent application-created plaintext
files, and state the OS protections required against a locked-device disk image.
UI handles minimize exposure; they are not isolation from compromised frontend code.

## Specification

### 1. Memory and locked-device protection

1.1. Keys, passwords, plaintext payloads, metadata and serialization/normalization
buffers use zeroizing allocations with redacted Debug/Display. Audit library
intermediates, error paths, panics, cloning and reallocation; a final SecretBox
does not erase preceding copies. Core dumps and debugger attachment MUST be
disabled where supported before reading secrets; report unsupported protection.

1.2. Lock keys and short-lived protected-value buffers before filling them,
through a small reviewed memory module. Prefer no-access/guarded allocations
where supported. A locking failure MUST be surfaced as reduced protection,
never merely buried in logs. Do not claim that zeroizing RAM erases swap.
Keep protected values encrypted when idle. Wipe decrypted record buffers after
building metadata views or completing an edit; do not build a plaintext password
search index. Metadata is confidential even when marked non-protected.

1.3. The locked-device full-disk-image guarantee requires encrypted OS storage,
swap and hibernation with keys unavailable to the thief in the relevant locked
or powered-off state. Memory locking alone does not protect hibernation or
garbage-collected webview copies. Detect/report known configuration gaps; where
the platform cannot establish these prerequisites, require explicit reduced-
protection acknowledgement before persistent secret use and expose that mode
in security settings. Do not infer that a screen lock necessarily seals all
disk-encryption keys. This limitation is part of 0001, not an unlocked-malware
exception.

1.4. Lock on inactivity, OS screen lock/sleep, and mobile background expiry.
Cancel in-flight operations, invalidate session-scoped handles and network
credentials, close authenticated TLS connections, clear clipboard if still
owned, zeroize keys/metadata/buffers and
destroy revealed UI state. Late responses must not repopulate a locked session.
Do not persist plaintext for OS state restoration, search indexing, recent
documents, accessibility caches or crash restoration.

### 2. Timing

Use constant-time cryptographic comparisons and implementations. Unknown
account/device failures must match existing-credential failures in shape and
work class with rate limits and fake OPAQUE records. Do not claim the server
cannot distinguish its own registered account database. Vault search is local;
network content is not generated from protected-value searches.

### 3. OS leaks

| Channel | Rule |
|---------|------|
| Clipboard | Use sensitive/no-history flags, clear after 20 seconds only if still owned; flags cannot force all clipboard managers to comply |
| Screenshots/recents | Android FLAG_SECURE; hide previews where supported; no universal desktop screenshot-prevention claim |
| Keyboard | Password/no-learning input types; native secure input for master password, recovery phrase and edited protected values |
| Logs/crash reports | No plaintext, keys, recovery phrases, tokens or secret-bearing URLs; redact at type boundaries |
| Temp files | No plaintext; explicit plaintext export is a separately confirmed operation to a user-selected path |
| Autofill | Match verified app identity/web origin, not display labels or URL substrings; require choosing conflicted credentials |

### 4. Frontend boundary and webview contract

4.1. The trusted client includes Rust crypto/model/store/sync code, platform
adapters and any frontend that handles secret input or can request reveal.
qv-core owns authorization/session policy, not every allocation of plaintext.
Handles are scoped to one unlocked session and unforgeable outside its bridge;
they expire on lock. They reduce copies but do not prevent malicious UI code
from invoking an allowed reveal operation.

4.2. Bundle all executable UI assets locally. Enforce restrictive CSP with no
remote scripts, eval or inline executable code. Block navigation, frames,
popups and remote subresources; no remote favicon fetching. Render vault text
as escaped text, never raw HTML or executable markdown. Permit explicit http/
https external links only after parsing; reject javascript/data/file and
unregistered custom schemes. External pages never receive the privileged bridge.

4.3. Bridge methods are allowlisted, typed, bounded and checked in Rust for
current session, vault, field and operation. Never expose arbitrary filesystem,
shell, SQL, network or crypto functions. Protected reveal requires an explicit
UI action, expires after 30 seconds and is cleared on lock. Copy/autofill goes
Rust directly to the OS. A compromised authorized webview remains a compromise
of the trusted client; do not advertise handles as an XSS defense.

4.4. GUI master password/recovery/protected-value editing uses native secure-input
controls owned by the platform layer; the CLI uses non-echoing OS TTY input.
The webview receives completion/cancel
signals, not input text. Native reveal is preferred; if the supported frontend
cannot provide secure input, that path MUST NOT ship with a stronger memory
claim. Native controls also require zeroizing bridge buffers and OS protection;
they cannot promise immunity to a compromised OS.

### 5. Local files and testing

Private app state, signing bundles and anchors use owner-only permissions and
atomic durable updates. Symlink/path replacement must not redirect writes.
Test lock during sync/reveal/autofill, all secret-input error paths, redacted
logging, malicious HTML/URLs, blocked navigation/bridge access, swap/hibernation
configuration reporting and clipboard ownership races on each supported target.

## Security Considerations

Best-effort UI/OS cleanup is not proof of physical erasure. The locked-device
guarantee is conditional on §1.3; unlocked malware and a compromised OS remain
out of scope. Remotely supplied parser/rendering inputs remain in scope.

## Open Questions

1. Validate native input and OS protection detection per supported platform.
   Unsupported protection must be visible and cannot silently inherit claims.

## Changelog

- 2026-10-14: Initial memory/webview proposal.
- 2026-10-15: Specify OS prerequisites, lazy protected-value handling, native
  input, mandatory webview/bridge hardening and lock-time operation cancellation.
