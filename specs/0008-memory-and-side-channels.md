# 0008 — Memory Hygiene and Side Channels

| Status | Created | Depends on |
|--------|---------|------------|
| Draft | 2026-10-14 | 0001, 0002 |

## Summary

Minimize plaintext lifetime and copies, prevent application-created plaintext
files, and state the OS protections required against a locked-device disk image.
UI handles minimize exposure; they are not isolation from compromised frontend
code.

## Specification

### 1. Memory and locked-device protection

1.1. Application-controlled Rust keys, passwords, plaintext payloads, metadata
and serialization/normalization buffers use zeroizing allocations with redacted
Debug/Display. GUI input MAY use ordinary Dioxus/webview controls and their
framework event/bridge buffers. Bound input, minimize copies and lifetime,
transfer secrets to protected Rust containers promptly, and clear controls and
application state after use and on lock. Never log or persist these values.

Framework, web-engine, input-method and OS intermediates may retain copies that
application code cannot deterministically wipe. Document these limits; neither
native widgets nor webview controls establish complete memory erasure. Residual
framework copies alone do not require native dialogs, a framework fork or a
custom engine. Audit library intermediates, error paths, panics, cloning and
reallocation in proportion to the threats in 0001; a final SecretBox does not
erase preceding copies. Arbitrary access to an unlocked process compromises
its active secrets and is not prevented by zeroization. Residual data after
lock, dumps and OS persistence still warrant best-effort cleanup and the OS
prerequisites in §1.3. Core dumps and debugger attachment MUST be disabled where
supported before reading secrets; report unsupported protection.

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

1.4. Manual locking and the application inactivity timeout MUST work without
OS lifecycle services. Lock on OS screen lock/sleep when the platform provides
usable notifications, and on mobile background expiry. On Linux, automatic
OS lock/sleep notification support is an optional detected capability, not a
prerequisite for local vault use. If unavailable, show that limitation clearly
before persistent use and while unlocked; retain §1.3's explicit reduced-
protection acknowledgement. Do not advertise OS-triggered locking as active.
Absence of logind, a portal interface or a compositor integration MUST NOT by
itself prevent Linux creation, unlock or recovery. Android's required lifecycle
and secure-window checks remain in force.

Loss of an installed watcher locks existing sessions and clears pending work;
a subsequent explicit Linux open may proceed with the unavailable capability
disclosed. Successful notifications always lock; foreground/resume never unlocks.
On every lock, cancel in-flight operations, invalidate session-scoped handles and network
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
Performance paths (caches, match sets, case folding, staged writes) add no
secret-dependent comparison or early exit on keys, MACs, fingerprints or
protected values; their timing may depend only on non-protected text and the
query, as matching already does.

### 3. OS leaks

| Channel | Rule |
|---------|------|
| Clipboard | Use sensitive/no-history flags, clear after 20 seconds only if still owned; flags cannot force all clipboard managers to comply |
| Screenshots/recents | Android FLAG_SECURE; hide previews where supported; no universal desktop screenshot-prevention claim |
| Keyboard | Password/no-learning hints where supported; masked Dioxus/webview secret inputs are permitted; clear controls after use and on lock, with framework/OS memory limits documented |
| Logs/crash reports | No plaintext, keys, recovery phrases, tokens or secret-bearing URLs; redact at type boundaries |
| Temp files | No plaintext; explicit plaintext export is a separately confirmed operation to a user-selected path |
| Autofill | Match verified app identity/web origin, not display labels or URL substrings; require choosing conflicted credentials |

When clipboard ownership is replaced before completed delivery is established,
report `ClipboardReplaced`, separately from ordinary expiry and cancellation.
For X11, count only a successful text-property/notify delivery or the successful
INCR terminator after all data acknowledgements; metadata requests do not count.
With the GTK backend (the desktop app on Wayland), count a text-target request
answered through GTK as delivery; GTK does not report whether the requester
read the data. With Wayland data-control (the CLI, and the app without GTK),
count a text-type request whose whole value was written to the requester's
descriptor. The password-manager hint target does not count for either.
Android cannot confirm consumption and reports observed replacement explicitly.
Expiry means the value was offered for that interval, not proof of a paste.
Cleanup must never clear a successor's selection.

### 4. Frontend boundary and webview contract

Preview transport follows 0003 §6.4: protected per-range buffers, a Weak session
binding, no detached vault key or plaintext response Vec, and revocation on
close/navigation/lock. Do not hold a session lock during socket writes. In-flight
kernel/renderer copies cannot be recalled or deterministically wiped. Loopback
capabilities never enter logs and are separate from edit-transport credentials.
These bounds constrain application-owned buffers, not total renderer/GPU RSS.

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

4.4. Use the shared Dioxus UI and its standard webview controls for GUI master
password/recovery/protected-value input. Secrets may cross the framework's local
input/event bridge into Rust. Apply §1.1's input bounds, prompt conversion,
no-log/no-persistence rules and best-effort cleanup. Do not retain protected
values in long-lived frontend state or send keys to the renderer. Mask secret
input, use password/no-learning hints where available, clear inputs on
submit/cancel/lock and discard late events/results from an old session. The
CLI continues to use non-echoing OS TTY input.

Dioxus and the web engine are part of the trusted client, not a secret-isolation
boundary. Do not claim that clearing the DOM, dropping Rust state, forcing GC
or choosing native controls guarantees erasure of all copies. Native adapters
remain appropriate for actual OS functions such as clipboard, keystore,
biometrics, lifecycle and autofill; a separate native input dialog is not
required merely because UI frameworks copy data.

### 5. Local files and testing

Private app state, signing bundles and anchors use owner-only permissions and
atomic durable updates. Symlink/path replacement must not redirect writes.
Test lock during sync/reveal/autofill, all secret-input error paths, redacted
logging, malicious HTML/URLs, blocked navigation/bridge access, swap/hibernation
configuration reporting and clipboard ownership races on each supported target.

### 6. LAN credential and paged-view lifetimes (0047)

The owner approved implementation of this section and its references to
§1/§4 for 0047 on 2026-11-09; the rest of this spec remains Draft.

LAN application-owned setup, registration, login, RNG-adapter state and outputs
are protected, redacted and zeroizing; audit dependency scratch separately.
A's typed password and derived wrapping keys are wiped after local verification
and ephemeral registration; B's after authenticating the grant/slot, before
bulk transfer. Phrase/existing-key enrollment has no password gate. Cancel,
lock and expiry destroy pending credentials and invalidate late prompt answers.
Do not promise interruption inside an uninterruptible Argon2 call or complete
erasure of library/framework/OS copies. RNG failure releases no message and
uses no panic, zero seed or weaker fallback.

Confidential metadata uses 0004 §7's evictable cache and bounded view pages.
Zeroize query/sort/cursor/cache/page buffers, the label tier, case-folding
scratch and 0004 §7.3 match sets when discarded; include allocated text
capacity and normalization copies in accounting. Protected values/notes
remain outside searching. No persistent plaintext search index or temporary
plaintext file is permitted.

## Security Considerations

Best-effort UI/OS cleanup is not proof of physical erasure. The locked-device
guarantee is conditional on §1.3; unlocked malware and a compromised OS remain
out of scope. Remotely supplied parser/rendering inputs remain in scope.

## Open Questions

1. Validate input cleanup, lifecycle and OS protection reporting per supported
   platform, recording framework-managed memory limitations.
2. **Resolved 2026-10-26 (owner):** use Dioxus with its standard webview UI and
   input controls. A native-input workaround, Dioxus fork or custom engine is
   not required for deterministic framework-memory wiping. Platform validation
   and the active-content/bridge requirements remain; this decision is not
   evidence that they pass.

## Changelog

- 2026-11-13: §3 adds the delivery rules for the GTK clipboard (the desktop
  app on Wayland) and Wayland data-control (the CLI) (plan 0055, owner
  request; details owner-delegated under the standing 2026-11-02
  delegation).
- 2026-11-13: §2 bars secret-dependent timing in performance paths; §6 adds
  the label tier, folding scratch and match sets to the zeroized buffers
  (plan 0053, owner-delegated under the standing 2026-11-02 delegation).
- 2026-11-10: Define bounded protected preview streaming and capability/session
  lifetimes, including explicit renderer/kernel/GPU cleanup limits (plan0050).
- 2026-11-09: Report clipboard replacement before confirmed delivery separately
  from expiry/cancel, tracking direct and INCR completion (T3-03, plan0050).
- 2026-11-09: Record owner-approved LAN/paging secret lifetimes and explicit cleanup limits.

- 2026-11-01: Owner directs optional Linux OS lock/sleep monitoring. Preserve
  manual/idle locking, clear unavailable-capability reporting and reduced-
  protection acknowledgement; watcher loss locks current sessions but does not
  permanently bar subsequent Linux opens. Android requirements unchanged.

- 2026-10-26: Owner selected stock Dioxus/webview input. Replace mandatory native
  secret dialogs with bounded input and best-effort cleanup; distinguish controlled
  Rust buffers from framework/OS copies and avoid complete-erasure claims.
  Retain OS prerequisites, lifecycle, no-log/persistence and active-content rules.

- 2026-10-24: Move renderer/framework evaluation to early Android/Linux work
  in phase 1 to reflect mobile priority and shared UI intent; preserve native
  secure-input requirements and leave the framework decision open.
- 2026-10-14: Initial memory/webview proposal.
- 2026-10-15: Specify OS prerequisites, lazy protected-value handling, native
  input, mandatory webview/bridge hardening and lock-time operation cancellation.
