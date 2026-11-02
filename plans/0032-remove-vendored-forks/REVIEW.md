# Review — Plan 0032: Remove vendored forks

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Approved | 2026-11-02 | `2c993c6..da6f1f3`, checked on committed `1a40186` before subsequent phase work |

## Summary and conformance

The five forks were replaced with the same published versions, leaving only
the owner-authorized hardened dioxus-desktop. The removed x11rb framing limit
is implemented in the product transport before bytes are returned to x11rb;
its zeroizing write ring is explicitly dropped/documented as authorized.
Package policy, provenance, advisory/license exceptions and audit debt match
the plan; there is no new unapproved vendor exception.

## Findings

None in this scoped change. The earlier 0031 app findings are recorded in that
plan and are not waived by this verdict. This is not a security audit or a
release verdict. The ignored glib advisory and vet exemptions remain debt.

## Evidence

Read the BoundedStream/Framing implementation and tests, including fragmented
setup/packets, exact packet cap and oversized reply/GenericEvent. Compared it
with the restored x11rb-protocol 0.13.2 packet reader: that reader grows its
packet buffer only after receiving all 32 header bytes, which the guard checks
before returning. Lifetime read/deadline/cancellation/descriptor checks remain.
The independent full locked suite on `1a40186` passed 741 tests, two existing
ignored, including real private-Xvfb clipboard tests. SPDX/fixtures/matrix/fmt,
workspace and app-validation Clippy, app unit+engine tests (25), and vendor
focused tests (5) passed. Deny passed with the documented exceptions; vet
passed (93 fully audited, 11 partially audited, 421 exempted).

The dioxus archive hash is the README's
`236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d`.
Compared retained files against that archive; documented patch areas and
upstream license files match the expected scope. Reviewed the 0031 additions
to the existing hardened patch and ran its focused tests. Exact logs are under
`/tmp/qv-next-phase/` (temporary). Phase-0033 changes made afterward have their
own final-tree verification and require their normal later fresh review.

## Fixes and documentation

No product fix. Updated the plan/index to Reviewed and recorded this scoped
review. No commit, push or branch. Owner explicitly authorized continuing on
the staged tree while fixing 0031 and implementing phase 2.6.
