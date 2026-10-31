# Linux lifecycle and protection validation

## Automated evidence

`cargo test --locked -p qv-platform` uses a private dbus-daemon to exercise the
production logind setup, typed dispatch and shutdown against test objects:
Lock, PrepareForSleep(true), owner loss and dropping an idle subscription.
It also checks sender/session/type filtering and bounded stalled authentication.
These fixtures do not prove that a particular desktop emits the expected
signals. Core platform tests inject lifecycle callbacks and establish session
locking, stale capability refusal, watcher release, late-event handling and
cancellation of a session-bound clipboard without holding the session mutex.
CLI clipboard tests use private Xvfb to exercise the shared production engine's
ownership, bounded INCR transfer/refusal, expiry and key-drop behavior.

## Real desktop procedure (not executed in this container)

This container has no real logind-managed graphical login session or suspend
hardware. Record the desktop/compositor, systemd/logind version, display backend
and result when running these checks on a supported Linux desktop. Phase 2.4's
app must configure LinuxPlatform and the core protection acknowledgement before
using persistent secrets, retain its instance guard and destroy revealed UI
state whenever a bound session locks.

1. Construct core with LinuxPlatform and without reduced-protection consent.
   Confirm its reported storage/key-custody uncertainty is visible and persistent
   create/unlock is refused. Explicitly acknowledge reduced protection, unlock
   a disposable vault and check the reported lifecycle status after attachment. Missing lifecycle
   monitoring must still refuse the configured session even after reduced
   persistence protection is acknowledged.
2. Request a real session lock through the desktop's screen locker or
   `loginctl lock-session`. Confirm the bound Session is locked, previously
   obtained handles refuse reads/reveal and the UI destroys plaintext views.
   Unlocking the desktop must not unlock or repopulate that vault session.
3. Unlock a fresh vault session, own the clipboard through its session-bound
   API, then lock the screen. Confirm ownership ends and buffers are released.
   Repeat after another application takes ownership; its selection must survive.
4. Unlock a fresh session and request suspend/hibernate using ordinary OS UI.
   Confirm PrepareForSleep(true) locks it; resume(false) must not reopen it.
   The delay inhibitor is released only after the lock callback, but logind's
   maximum delay and OS scheduling bound its guarantee. Do not infer that screen
   lock or successful suspend erases disk-encryption keys.
5. Start a second instance using the same private instance-lock directory.
   Confirm acquisition is Busy; after the first guard exits acquisition succeeds
   without deleting/replacing the lock file. An unsafe directory or symlink
   component must reject rather than create another independent lock.
6. Verify persistence reporting with swap disabled, active swap and hibernation
   configured; unreadable/malformed configuration must stay Unknown. Even an
   encrypted device name does not establish locked-state key unavailability.
   Quick unlock remains unavailable; wrap/unwrap fail closed.

No real-desktop success is claimed here. The reduced mode is required because
Linux configuration probes cannot establish storage/swap/hibernation key custody.
Wayland clipboard has no implementation in this phase and fails unavailable
when a supported local X11 connection cannot be acquired. Clipboard hints cannot
force managers to comply, and OS/X server copies are outside deterministic wiping.

The platform phase supplies lifecycle services and bound vault sessions; pending
frontend unlock tasks, externally held protected views and rotation confirmation
artifacts must also be cancelled/dropped by the production app on lifecycle
changes. They are not a claim of complete erasure from framework/OS memory.
No production GUI is created here; D13 still gates phase 2.4.
