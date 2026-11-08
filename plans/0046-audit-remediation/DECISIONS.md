# Policies to discuss before the next repair batch

The owner explicitly requested discussion of these three policies on 2026-11-08.
None of the options below has been implemented or accepted by silence.

## The 64 MiB index-text budget

The constant is `qv-core/src/index.rs::MAX_VIEW_BYTES`: 67,108,864 bytes of
retained UTF-8 text after unlock. It counts entry titles/type hints/icons,
group names/icons/order strings, vault names and the names/values of searchable
non-protected text, URL and email fields. It does not count passwords,
protected fields, notes or attachment bodies. Non-protected metadata remains
confidential: the index is cleared when the session locks.

It is neither a vault-file size limit nor a limit on total process memory.
The index's maps, clocks, identifiers, temporary decoding and password KDF
require additional memory. A vault with many small fields can fit while one
with a few hundred very large searchable fields may exhaust this budget.

The bound prevents a key-holding peer or an unusually large vault from making
the app retain arbitrary amounts of plaintext in RAM, especially on phones.
Raising it has a memory/performance cost; removing it is not a sound repair.
The value is local policy, not a cryptographic parameter or a new file format.

Important qualification to the report: stock local edits and archive/LAN merges
already check the candidate index before committing. The bundled reproducer
explicitly raises the constant in a custom authoring build, then tries to open
the result with the default build. This demonstrates the undocumented limit and
missing larger-policy/recovery path; it does not demonstrate a stock CLI edit
crossing the bound. Code inspection also found new-device join publishes before
the final unlock/index build; a repaired policy should preflight before that
publication too. That additional ordering observation has not been reproduced
with an oversized peer fixture.

| Option | Consequence |
|--------|-------------|
| Keep 64 MiB default; add an explicit larger local budget | Preserves phone defaults and provides an escape for compatible but larger vaults. Needs core/CLI/app settings, a clear budget-specific error and consistent preflight for every creation/acceptance path. |
| Raise the default | Allows larger indexes everywhere, with more RAM use. Still needs a documented limit and recovery policy at the next boundary. |
| Retain only a bounded working set and search on demand | Makes the index less dependent on total searchable text, at the cost of more decryptions and search latency. This changes the index/search architecture and needs a separate design. |

Recommendation: the first option. Agree the policy before choosing allowed
override values or a UI. A larger budget must be explicit and bounded, and
must not allow a write the same selected policy cannot reopen. Recovery must
preserve authenticated/causal data, not silently drop records or fields.

## Replacing a vault's parent directory

The immediate parent can be private while its own directory entry is writable
by someone through a higher ancestor. An attacker can rename that parent and
put a different victim-owned vault directory at the original path. Checking
the final file with no-follow flags does not detect that history.

Holding a directory descriptor protects operations from a swap while the
process runs. It does not prove that the directory at startup is the one the
user used last time. The latter needs a trust policy or persistent identity.

| Option | Consequence |
|--------|-------------|
| Require a trusted ancestor chain | Avoids binding vaults to an inode and preserves ordinary moves between safe locations. Must precisely handle ownership, writable groups, ACL/platform limits, symlinks and sticky shared directories. A blanket writable-ancestor check would reject `/tmp` locations too. |
| Remember directory identity with the external anchor | Detects substitution before startup, but legitimate moves/restores and inode replacement require a relocation/recovery flow. Changes persistent local state and its crash ordering; device/inode is not a portable identity. |
| Pin the directory only for the open operation | Useful race hardening, but deliberately does not close the demonstrated pre-start substitution. Must not be presented as the complete fix. |

Recommendation: design trusted-location checks plus descriptor pinning first,
unless portable vault relocation should explicitly require a recovery action.
The threat model already treats a compromised filesystem as a limited-trust
environment; the chosen behavior must state that limit without claiming an
inode defeats a malicious filesystem.

## A spent LAN failure budget during an accepted session

The window closes its acceptor after 16 failed connections. Today, an accepted
session may continue after that, losing the only detector for a second valid
hello. A second distinct valid hello requires possession of the one-use code;
unauthenticated junk alone must not gain a key. The reported defect removes a
warning/protocol safeguard, not the comparison-code approval requirement.

| Option | Consequence |
|--------|-------------|
| Close the whole window/session when the budget is spent | Simple, bounded interpretation of the existing close-window rule. Any nearby peer can interrupt a legitimate session with enough junk connections. |
| Close admission but retain a separately bounded detector during the accepted session | Avoids immediate interruption by junk, but must define detector capacity, deadlines and overload behavior. Otherwise exhaustion merely disables the detector again. |

Recommendation: whole-window closure is the simplest defensible initial
policy, provided interruption is accepted. Keep second-hello checks alive
through transfer and final reporting. If keys have already been granted they
cannot be taken back; if local data already committed it cannot be rolled
back by reporting an abort. Report the observation and completed local outcome
together. The detector's shorter probe timeout, session teardown and total
joining deadline should be specified consistently in the same batch.
