# Local completion check — plan0050

2026-11-10. Developer's local check, with no reviewer agent or independent
assessment. The owner requested a quick local check and delegated correctness
decisions. No external reviewer was contacted.

**Status: qualification remains open.** Source repairs cover the fifteen tracked
implementation areas. Android media playback has not been executed because no
phone is connected. The plan stays In progress; tests alone do not close the
independent composition/dependency/device gates in0048.

The local pass follows the changed call chains for non-mutating SQLite opening,
post-durable errors/index repair, finite clock admission, deletion identity,
destructive-copy authorization, cross-process file leases and cleanup,
clipboard delivery, display/editor separation and preview source/transport/UI.
Contracts precede behavior changes; no crypto primitive, eligibility budget,
causal truncation, detached preview key or new production dependency was added.

Corrections from this pass:

- Preserve private parent-directory aliases when acquiring directory flocks;
  the earlier extra no-follow flag would have changed the owner's QV-013 policy.
  Explicit snapshot/anchor-root checks retain their existing policy.
- Escape omitted vault locations, autofill rows and editor display mirrors;
  retain raw editable controls and stored/copied values.
- Carry capacity classification through platform output creation/fsync and
  frontend adapters; provider failures without a usable errno remain generic.
- Revoke hidden/late-inserted preview sources through the existing bounded
  typed UI event as well as resetting renderer media. Avoid sending that event
  when there is no viewer on the locked screen.
- Preserve existing imported delta-audit bases rather than deleting apparently
  stale versions and breaking real audit paths. Exemption debt remains explicit.
- Correct obsolete test setup, without removing assertions: mandatory copies,
  a genuine empty-attachment content hash and explicit private Xvfb selection.

File-lifetime check: handles release their file Arc before their lease token;
the last token closes the registry's descriptor under its mutex. A dead Weak
still in the registry fails Locked. SQLite-capable descriptors are not cloned
or reopened by cleanup; opaque readers share positioned I/O with independent
cursors. Producers retain flock through publication/fsync, and recovery entries
carry a private exclusive lease until their pin is released. Child-process and
actual SQLite-lock tests exercise these invariants.

Preview boundaries: exact capability paths/numeric Host, bounded initial
headers/connections, strict single ranges and416, separate websocket credentials,
exact listener CSP, protected chunks and Weak Session authorization. Actual
GTK/WebKit playback/seeking/consent and close/lock refusal pass. Decoder/kernel/
GPU residual memory remains best effort, and the failed native attempts are
recorded in VALIDATION.md. Android compilation cannot substitute for device tests.

Final gate results and exact commands are in [VALIDATION.md](VALIDATION.md).
Final-tree gates pass:1,000 workspace tests,0 failures,6 intentional ignores;
Clippy including the desktop/validation app, fmt, SPDX, matrix, deny/vet,
locked fuzz build and the dependency baseline check. The maintained vendor
checks pass13 and standard real-engine checks pass3. Final native media passes
twice with a controlled private desktop runtime, without claiming physical audio
or Android compatibility. No commit, branch or push was made.
