# Review — Plan 0025: LAN sync protocol spec (roadmap 2.1)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved with minor fixes (in-session check; owner direction: no separate session for spec-only work) | 2026-10-30 | Uncommitted: `specs/0013-lan-sync-protocol.md`, 0005 pointers, `specs/README.md`, `ARCHITECTURE.md`, `CHANGELOG.md` |

## Summary

0013 specifies the whole LAN protocol at the message level:
- discovery during explicit windows only;
- pairing, with a committed comparison code and new-device or link mode;
- pairwise link keys bound to `K_lan` and the generation;
- the X-Wing session handshake and the counter-nonce record layer;
- the alternating full-manifest exchange through the single local write
  path;
- peer state bound into the local head, windows, errors, removal and
  rotation.

Every MUST in 0005 §6.1–6.7 and every 0012 §3 LAN item maps to a section
(0013 §14 and *Testing Requirements*). This check ran in the session that wrote
the spec. Per the owner's direction it needs no separate review session.
The external D12 review still applies before release.

## Plan conformance

| Step | Done | Notes |
|------|------|-------|
| 1 Record D10 | yes | Roadmap D10 and plan 0025 |
| 2 Write 0013 | yes | §1–§14, Draft |
| 3 Pointers and index | yes | 0005 §6.7, OQ7 and Changelog; `specs/README.md` |
| 4 Architecture and docs | yes | §5 LAN flow, §6 row, server-revocation paragraph, open decisions; CHANGELOG; D12 request in the plan |
| 5 Self-check | yes | This file |

Out-of-scope changes: none. Accepted specs 0001, 0002 and 0004 are
unchanged; their amendments are written out in 0013 §13.

## Findings

1. **[medium] A new device could silently join an attacker's vault** —
   `specs/0013-lan-sync-protocol.md` §10. Someone who shows a victim their
   own pairing code can push the victim's device into new-device mode. The
   victim might then store secrets in a vault the attacker holds (0006 step
   3 guards against the same thing). Fixed: before publishing, B shows the
   received vault's name and the comparison code and requires the user's
   confirmation.
2. **[low] Wrong size claim** — §3.3 stated a 1,248-byte hello, but the
   encoded size is larger. Fixed: the text no longer gives a size.
3. **[low] `bool` undefined** — §1.2 now defines it as CBOR `true`/`false`,
   which `qv-encoding` accepts.
4. **[low] Ambiguous sentence** — §7.3 on which side serves which state.
   Fixed.

Checked, no finding:
- **Comparison-code grinding** (§4.5). Walked through a man in the middle
  who knows `P`. B commits to its nonce before seeing A's; A's nonce
  follows a fixed hello; the single-hello rule leaves one attempt.
- **Replay and reflection.** A hello replayed in the same window is
  refused; one replayed later dies at `Confirm`. The `"i"`/`"r"` labels
  differ.
- **No KEM work before a MAC check** on either listener.
- **Link mode never sends VK**, and a link is unusable without `K_lan`.
- **Rotation drops links**, consistent with 0002 §3.5.5.

## Gates

| Check | Result |
|-------|--------|
| `sh scripts/check-spdx.sh` | pass |
| `git diff --check` | clean |
| Rust gates | n/a: no code changed after the 0024 review's final gate run |

## Documentation

- [x] CHANGELOG.md
- [x] ARCHITECTURE.md §5, §6 and open decisions
- [x] Specs: 0013 (Draft), 0005 pointers and Changelog, README index
- [x] Plan ticks, execution log, plans/README.md row

## Escalations for the owner

- **Accept 0013, or ask for changes.** Acceptance also applies the §13
  amendments to 0001, 0002, 0004 and 0005.
- **D12:** choose and engage the independent protocol reviewer. The request
  text is in plan 0025.
