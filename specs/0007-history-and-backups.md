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
sync state or external anchors. By default a local snapshot carries **no
password slot** (0004 §6.4; roadmap 0002 decision D6): it opens only with the
vault key of the same vault ID and key generation — i.e. from the active
vault that wrote it, or any other replica holding that key — or with the
recovery phrase. An archive that gives a file-sync provider, a backup thief
or a copy on a shared medium nothing to attack offline MUST NOT be weakened
for convenience: no slot is added unless the user explicitly chooses a
self-contained archive (0004 §6.4). Store snapshots in a private application
directory, outside exchange directories.

3.2. Take a recovery snapshot before explicit file imports, whole-state recovery,
profile/generation migrations and bulk deletion; at most one ordinary snapshot
per hour plus one on first unlock each day. Normal LAN and server causal merges
use ordinary snapshot coalescing, not a full mandatory copy on every poll. Local
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

3.5. **Password changes and existing snapshots.** Changing the master
password (0002 §3.4) leaves the vault key and key generation unchanged, so
snapshots taken before the change remain decryptable with that key. Because
the old password may be the reason for the change, the frontend MUST, after a
successful password change, offer to delete the snapshots created before it,
naming how many exist. It MUST delete them only on explicit confirmation, and
it MUST NOT describe the result as cryptographic erasure: copies held
elsewhere, on other media or by other devices are unaffected (§4.3), and a
party that obtains the vault key from an old vault-file copy or an old keyslot
can still open them. Declining the offer keeps them under the ordinary
snapshot budgets (§3.2–3.3).

### 4. Server retention and purge acknowledgements

This section applies only to configured remote server sync. Offline and LAN-only
vaults require no server purge acknowledgement. Local history suppression and
snapshot budgets apply in every mode; LAN peers merge suppression frontiers
under 0005 and may retain independent copies. A peer's receipt is not a server
purge acknowledgement and does not prove erasure.

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

1. **Password slots in local snapshots.** *Resolved 2026-10-25 (owner decision
   D6, roadmap 0002): no password slot by default. On password change, offer to
   delete pre-change snapshots (§3.1, §3.5). Self-contained archives remain an
   explicit, warned user choice (0004 §6.4).*

## Changelog

- 2026-10-27: Resolve OQ1 per owner decision D6. Local snapshots carry no
  password slot and open with the vault key or the recovery phrase; add §3.5
  (offer to delete pre-change snapshots on password change) and the
  private-directory requirement (plan 0018).
- 2026-10-24: Apply ordinary snapshot coalescing to LAN and server merges;
  scope server retention/purge acknowledgements to optional remote sync and
  preserve suppression/independent-copy limits for LAN-only use.
- 2026-10-14: Initial accepted history/trash/snapshot policy.
- 2026-10-15: Amendment: permanent tombstones, monotonic history suppression,
  bounded/coalesced snapshots and reference-based server retention. Define purge
  propagation and avoid claims of cryptographic erasure.
- 2026-10-15: Security review amendment: snapshots use the authenticated
  archive format instead of SQLite backup copies; no checkpoint-chain retention.
