# 0007 — History and Backups

| Status | Created | Depends on |
|--------|---------|------------|
| Accepted | 2026-10-14 | 0004, 0005 |

## Summary

History, trash and independent consistent snapshots reduce data-loss risk.
Unresolved conflicts and permanent deletion knowledge are not expiring history.
Purging retained payloads is not cryptographic erasure of external copies.

## Specification

### 1. Entry history and suppression

1.1. Dominated complete versions become history. Keep the last N (default 10)
by deterministic (modified_at, version_id) order, subject to resource budgets.
Unresolved heads remain active and MUST NOT be pruned, including during rotation.
Dates do not establish causality or override suppression rules.

1.2. Each record retains a monotonic `history_floor` version vector in the
manifest. Merge floors componentwise by maximum. A historical version whose
clock is at most the floor is suppressed, even if reintroduced by an old peer.
The floor does not hide active heads or remove permanent tombstones.
Missing floor metadata means zero only for a genuinely new record, not when
a reference to existing suppression metadata is missing or fails verification.

1.3. Pruning may advance per-writer floor components only when all historical
versions covered by that advance are eligible for removal. If a retained version
would also be covered, leave that component unchanged. N is a retention target,
not permission to forget causal/suppression metadata or silently lose a conflict.
Write floor/reference changes in the same manifest transaction before deleting
unreferenced payloads. Recheck floors when merging imported historical objects.

1.4. Explicit history purge advances the floor to the join of all known active
head clocks, drops covered historical payloads and publishes the new manifest.
If those heads later become history they are also covered. Explain this boundary
to the user. Concurrent unseen versions are preserved and can need a later purge.
Purging must not resolve a conflict or delete its active versions implicitly.

1.5. Restore creates a new version covering all known heads, with explicit
resolution if needed. A restored historical value is an intentional new edit,
not reactivation of a suppressed version ID. Available history is synchronized
as authenticated references; it is not assumed present merely because the server
once received it. The current manifest declares exact retained references.

### 2. Trash

2.1. Soft deletion sets deleted_at as a causal edit. Default trash retention
is 30 days, measured by client policy; clock anomalies require confirmation
before destructive expiry. Bulk deletion of a group applies explicit entry/
group edits in one transaction, rather than silently hiding inaccessible children.

2.2. Final deletion removes secret payload/history and installs a minimal causal
tombstone; owned attachment metadata receives tombstones in the same transaction.
Release chunks only when no retained reference needs them. Retain each tombstone's
ID, version and clock **indefinitely**. Old covered edits
stay deleted after years offline. Concurrent deletion/edit is a visible conflict
in trash until explicit resolution (0005). Deletion knowledge is included in
snapshots, rotation, manifests and the resource budget.

### 3. Local snapshots

3.1. Snapshots are archives (0004 §6) written from verified local objects.
They never contain device-local quick slots, signing keys, session tokens,
sync state or external anchors. Local snapshots are self-contained archives:
they carry the password slot valid at their creation and open with that
password or the recovery phrase (see Open Questions). Store in a private
application directory, outside exchange directories.

3.2. Take a recovery snapshot before explicit file imports, whole-state recovery,
profile/generation migrations and bulk deletion; at most one ordinary snapshot
per hour plus one on first unlock each day. Normal server causal merges use
ordinary snapshot coalescing, not a full mandatory copy on every poll. Local
edits between snapshots still have record history. Mandatory pre-operation
recovery snapshots may bypass the hourly interval. Only one serialized recovery
operation may pin a snapshot; after confirmed completion its copy becomes an
ordinary snapshot subject to count/byte pruning.

3.3. Defaults are 30 days, at most 48 ordinary snapshots and a 512 MiB aggregate
budget per vault. Prune oldest ordinary snapshots to fit count/bytes; configurable
larger budgets require explicit user choice. Never silently delete a recovery
snapshot protecting an in-progress operation. If the new snapshot cannot fit,
abort that destructive operation and report required space; do not continue
without its recovery copy. One necessary recovery copy may exceed the ordinary
budget with explicit user approval or a user-selected alternate location.

3.4. Restore writes a new path, preserving the active vault and its external
anchor. Opening a restored copy is an explicit recovery baseline, and subsequent
merge with an existing device preserves that device's deletion/suppression
knowledge. A restore never proves that the snapshot is the latest global state.

### 4. Server retention and purge acknowledgements

4.1. The current checkpoint's manifest and every referenced object are pinned,
including retained history, unresolved versions, tombstones and chunks. An honest
server MUST NOT prune these to satisfy an admin history policy. A lower server
retention/quota requires a client-produced manifest explicitly releasing eligible
history; otherwise reject new writes or request client cleanup. Never silently
invalidate a published manifest.

4.2. Default unreferenced-object retention is 30 days; quotas may shorten it.
An authenticated explicit purge requests immediate logical removal of released
objects, after checking that no pinned state references them. Publish references
and the purge result atomically/idempotently. The server cannot inspect
encrypted timestamps/deletion flags
to implement client retention policy on its own.

4.3. Clients track remote purge acknowledgement and local snapshot status.
Offline devices and exported/backed-up copies may retain secrets; show these
limits. Other clients apply suppression floors before importing old histories.
No mechanism can force a malicious server, independent backup or departed device
to erase a retained copy.

## Security Considerations

The CLI calls this operation history purge, not secure shred. Derived record
keys remain reconstructible from VK, and SSD/copy-on-write storage can retain
old ciphertext. Secure erasure cannot be claimed. A leaked old password slot
can still reveal same-generation VK; offer generation rotation for future-data
protection, and separately identify remaining local snapshots (0002).

## Testing Requirements

Test suppression after old-backup import, years-old deleted entries, resolution
after delete/edit races, preservation of every unresolved head, snapshot
count/bytes and disk-full failures, and server GC against the complete current
reference set. Purge acknowledgements must not imply independent copies vanished.

## Open Questions

1. **Password slots in local snapshots.** A self-contained snapshot keeps
   opening with the password current at its creation, so after a password
   change made *because the old password leaked*, up to 30 days of snapshots
   still yield VK to a thief holding that old password. Alternative: local
   snapshots carry no slot (like exchange archives) and open with the active
   vault's VK or the recovery phrase; cost: if the active vault's keyslot is
   lost and the recovery phrase is unavailable, snapshots are unusable.
   Recommendation: no slot by default, plus offering to delete pre-change
   snapshots on password change. Undecided.

## Changelog

- 2026-10-14: Initial accepted history/trash/snapshot policy.
- 2026-10-15: Amendment: permanent tombstones, monotonic history suppression,
  bounded/coalesced snapshots and reference-based server retention. Define purge
  propagation and avoid claims of cryptographic erasure.
- 2026-10-15: Security review amendment: snapshots use the authenticated
  archive format instead of SQLite backup copies; no checkpoint-chain retention.
