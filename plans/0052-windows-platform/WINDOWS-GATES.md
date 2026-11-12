# Windows gate checklist (plan 0052, roadmap 3.1)

0012 §3 per-platform gates for the Windows release. Cross-compilation, Wine
runs and CI are development evidence. They do not establish the rows marked
**attended**, which need a real Windows 10 22H2 or Windows 11 x86_64 machine
and a person. Every item starts **pending**. Record the date, the Windows
build and the result next to each item. Use the owner's test machine and
synthetic vaults only.

## Automated (CI `windows` job, MSVC)

| # | Check | Evidence | Status |
|---|-------|----------|--------|
| A1 | fmt, Clippy (workspace and desktop app) with `-D warnings` | CI log | pending (first CI run) |
| A2 | `cargo test --locked` on Windows, including the store ACL, reparse, lock, rename and crash-point tests, the qv-win FFI tests and the `qv` pipe smoke tests | CI log | pending |
| A3 | Unsigned release zip with `SHA256SUMS` built and uploaded | CI artifact | pending |

## Attended

| # | Check | Spec | How | Status |
|---|-------|------|-----|--------|
| W1 | New vault, anchors, snapshots and state are owner-only: the DACL is protected, has one ACE for the user, and inherits to the folder's files | 0004 §1.1; 0009 §5.1 | `icacls "%LOCALAPPDATA%\QuickVault" /T` after creating a vault in the app and with `qv init` | pending |
| W2 | A vault in a folder that grants Users or Everyone write, or that new files would inherit read from, is refused; `Documents` and `%LOCALAPPDATA%` work | 0004 §1.1 | Make a shared test folder with `icacls`; try `qv -v` there | pending |
| W3 | A symlink or junction at the vault path, its journal or the anchor folder is refused | 0004 §1.1 | `mklink`, then open | pending |
| W4 | A second app instance reports "already running"; a second `qv` on an open vault exits 6 (locked) | 0004 §1.3 | Two windows / two consoles | pending |
| W5 | Win+L locks the app; sleep and hibernate lock it; RDP disconnect locks it; a session locked before unlock locks at once | 0008 §1.4; 0009 §5.1 | Unlock, then lock the screen, sleep, disconnect | pending |
| W6 | The app refuses to unlock if the watcher cannot start (no false "monitored" claim) | 0009 §5 | Check the protection status in Settings | pending |
| W7 | Copied values do not appear in clipboard history (Win+V) or the cloud clipboard, clear after the timeout only if still ours, and a later copy by another app is never cleared | 0008 §3 | Enable clipboard history; copy a password; copy something else from Notepad during the hold | pending |
| W8 | `qv` prompts do not echo; Backspace, Ctrl-U, Enter, Ctrl-C and Ctrl-D behave as on Linux; the console history (F7, Up arrow) has no secret | 0009 §3; 0011 §3 | `qv init` and `qv show --reveal` in conhost and Windows Terminal | pending |
| W9 | The recovery phrase screen uses the alternate screen and leaves no scrollback | 0011 §3.7 | `qv init`, then scroll back | pending |
| W10 | Open, save and folder dialogs work; the chosen files are not in Recent; a dialog cancel changes nothing | 0009 §1.8 | Attachments, archives, the vault folder | pending |
| W11 | WebView2 boundary: strict CSP, one navigation, bounded IPC, no devtools, dropped files and external links refused | 0008 §4 | Run the boundary harness checks by hand (drag a file, try a link) | pending |
| W12 | Secret-input cleanup limits match the documented WebView2/framework copy limits; lock clears the controls | 0008 §1.1 | Type and lock; inspect the UI state after unlock | pending |
| W13 | The reduced-protection notice appears before first persistent use and in Settings (storage, swap and hibernation unknown; core dumps and debugger not disabled) | 0008 §1.2–1.3 | First run | pending |
| W14 | Quick unlock is not offered | 0002 §5.2 | Settings | pending |
| W15 | LAN sync to the Linux or Android build works both ways with a one-use code; Windows Firewall shows a prompt and works after allowing the private network | 0013/0014 | `qv lan open` / app Devices | pending |
| W16 | Vault on a USB stick (FAT/exFAT) or network share: refused or warned as specified, never opened unprotected | 0004 §1.1 | Plug in a stick, try a vault there | pending |
| W17 | Release artifacts are Authenticode-signed and the checksums are published | 0012 §3 | Owner's certificate | pending (no certificate yet) |
| W18 | The app's own title bar works on Windows: drag to move, edge resize, minimize, maximize, close, Snap, high-DPI scaling and the light/dark theme | 0009 §1.8 | Use the window on a 100% and a 150% display | pending |

## Known limitations to record with the release

- Storage, swap and hibernation protection are not detected (BitLocker and
  page-file status need admin queries). The reduced-protection
  acknowledgement always applies on Windows.
- Core dumps (WER) and same-user debugger attachment cannot be disabled
  without persistent registry changes. This is reported as unsupported.
- Windows cannot confirm that a paste happened, so a clipboard replacement
  is always reported as replaced (as on Android).
- FAT/exFAT drives have no ACLs. Vaults, and user files opened through the
  attachment path rules, are refused there.
- The `\\?\` path and NTFS case-insensitivity make archive receipt names
  case-preserving. A differently cased path to the same archive is merged
  again, which is idempotent.
- Wine is not Windows: it maps ACLs to Unix modes, has no ACL inheritance,
  keeps POSIX-deleted names listed while a handle is open, and ignores
  read-only DACLs. Tests skip only those assertions when `QV_WINE=1`.
