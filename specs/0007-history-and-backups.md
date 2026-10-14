# 0007 — History and Backups

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0004, 0005 |

## Summary

Two layers protect against accidental loss:
1. **Entry history and trash:** fine-grained, inside the vault, synced.
2. **Vault snapshots:** whole-vault copies, local and/or on the server.

## Specification

### 1. Entry history

1.1. Every overwritten record version goes to `record_history` (0004),
including versions that lost a sync conflict (flagged `conflict`).

1.2. Retention per record: keep the last **N** versions (vault setting,
default 10). Versions flagged `conflict` are kept for at least 30 days
regardless of N.

1.3. Restoring a version creates a *new* version with that content (history is
never rewritten), so the restore itself syncs like any edit.

1.4. History is synced: other devices receive previous versions as part of
sync, so restoring works on any device.

### 2. Trash

2.1. Deleting an entry or group sets `deleted_at` (soft delete); it shows up
in the trash.

2.2. After the trash retention period (default 30 days) the client writes a
tombstone and purges payload and history.

2.3. Tombstones are kept for 180 days so that a device that was offline for a
long time does not resurrect the item.

### 3. Vault snapshots

A snapshot is a consistent copy of the vault file (SQLite backup API). Because
the file is already encrypted, snapshots need no extra encryption, and they
open with the master password valid **at the time of the snapshot**.

3.1. **Local snapshots are event-driven, not periodic** (the app may not be
running). A snapshot is taken before: a sync or file merge that changes data,
a suite migration, an import, VK rotation, and bulk deletions (e.g. deleting
a group with entries). Additionally at most one per day on first unlock.

3.1.1. Local snapshots are stored in the app's data directory (not next to
the vault), so file-sync tools don't pick them up.

3.1.2. The retention policy (§3.3) only decides which **existing** snapshots
to delete as they age. It needs no background process: pruning runs whenever
a snapshot is taken.

3.2. Server-side: the append-only log (0005 §3.1) is itself a history:
every old version of every record stays there until it is cleaned up.

3.3. **Retention: age-based.**

- **Local:** snapshots older than the retention period are deleted. Default
  **30 days**, configurable in the client settings, including "keep forever".
  There is **no size cap** on local snapshots: disk usage on the user's own
  device is the user's choice.
- **Server:** record versions older than the retention period are deleted
  from the log. Default **30 days**, set **only by the server admin**; users
  cannot extend it. The **current** version of every record and the current
  state commitment (0005 §5.2) are never deleted, however old.
- **Server size cap:** old versions count toward the account's storage quota
  (0006 §Quotas). In addition, the admin can set a maximum history size per
  vault. When a vault exceeds either limit, the server deletes its oldest
  non-current versions first, before the retention period is over. If the
  *current* data alone exceeds the quota, new writes are rejected; current
  data is never deleted to make room. This keeps history from becoming a
  way around the quotas (0006 §Admission control).
- Cleanup runs when a snapshot is taken (client) or on a periodic job
  (server). It never needs the app to be running in the background.
- Independent of this: per-entry history (§1, last N versions) and
  tombstones (§2.3, 180 days) follow their own rules.

## Security Considerations

- History keeps old secrets around (e.g. a replaced password). Users MUST be
  able to purge history for an entry ("shred") and for the whole vault.
- Old snapshots contain keyslots for old master passwords. After a password
  change because the old one leaked, the user SHOULD be offered to delete old
  snapshots (or rotate VK, 0002 §3.5).

## Open Questions

None currently.

## Changelog

- 2026-10-14: Initial draft.
- 2026-10-14: Local snapshots are event-driven and live in the app data
  directory.
- 2026-10-14: Retention is age-based: 30 days by default, configurable on
  client and server (replaces the tiered proposal).
- 2026-10-14: No local size cap; local retention may be unlimited. Server
  retention admin-only, history counts toward quota, per-vault history cap.
  Status → Accepted.
