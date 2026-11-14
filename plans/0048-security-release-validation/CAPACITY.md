# Bulk mutation capacity

2026-11-09. Local measurements and design recommendation, with no selected
memory target or authorized mutation-architecture change.

## Reproduce

The disposable `capacity-harness.rs` and `measure-capacity.py` were removed
in the 2026-11-14 cleanup; they are in git history before that commit. Their
maintained successor is `scripts/perf/` (plan 0053, derived from this
harness). The original commands were:

```sh
python3 plans/0048-security-release-validation/measure-capacity.py
# Exact preparation checkpoint in a disposable core source copy:
python3 plans/0048-security-release-validation/measure-capacity.py --instrument-preparation
```

Requires Linux `/proc`, Python 3.11+, the pinned Rust toolchain and cached
product dependencies. The script creates a 0700 temporary directory under
`/var/tmp`, prints its path, and retains per-command logs and fixtures there.
It copies the checked-in [capacity harness](capacity-harness.rs) to a disposable
standalone package. Registry versions/checksums must be a subset of the product
lockfile before compiling; no new dependency baseline is allowed. It propagates
the product SQLite flags, uses the stock optimized release profile and runs
focused Clippy. Product files and personal vaults are never edited by the tool.

Three source fixtures contain 30, 90 or 180 entries, with three searchable
256 KiB fields each, under one group. All are authored through core save APIs
and completely verified. Each measured operation gets its own filesystem copy
and fresh process/password unlock. There is no snapshot policy or GUI engine.
Complete bounded paging gathers handles; page payloads and cursors then drop.
Each run checks integrity and the expected zero or one local commit afterward.

`search` traverses all entry hits; `prepare` holds every public `EntryDraft`
without saving; `batch` sets icons in one batch; `recursive` deletes the group
and all entries in one transaction. A separate sampler observes current RSS
every 2 ms only during each stage. Reported peaks can miss shorter transients;
RSS includes allocator/SQLite/stack/scratch costs and is not an owned-byte count.
The process-wide high-water mark separately includes the earlier 256 MiB KDF.

Held drafts are a **preparation proxy**: both `edit_entry` and production
mutation preparation use `load_entry`, retaining decoded entry bodies. Draft
wrappers and lifetimes differ from private `Vec<Change>` preparation. The proxy
does not measure an instrumented internal production preparation interval or
prove the exact allocation count. Actual batch/recursive peaks cover their
whole operation, including preparation, encryption, transaction and index work.

The optional instrumented run copies core sources into the temporary package
and resolves inherited manifest/lint values explicitly. Its sole runtime
source change is [preparation-trace.patch](evidence/preparation-trace.patch): a
count/RSS checkpoint at entry to `commit`, with the complete `Vec<Change>`
still alive, before opening the storage write. It logs no payload or secret.
The marker is enabled only for samples, not fixture generation. Product source
remains byte-identical; this is instrumented evidence, not an unmodified
binary's exact timing. The checkpoint can miss earlier decoding transients.

The retained patch uses zero context (`git apply --check --unidiff-zero`);
the baseline source hashes identify its input. This avoids trailing-space
context lines in the committed evidence without changing the instrumentation.

## Observed host results

Same host/toolchain as [large-vault evidence](LARGE-VAULT-VALIDATION.md).
The initial run overlapped other host checks; timings are single observations,
not a latency acceptance baseline. Raw stage counters are retained under
`evidence/capacity/`.

| Searchable values | Pre-operation RSS | Complete search | Search peak RSS | Held drafts RSS | Batch peak RSS / time | Recursive peak RSS / time |
|-------------------|-------------------|-----------------|-----------------|-----------------|-----------------------|---------------------------|
| 22.5 MiB / 30 rows | ~29.1 MiB | 10 ms | 31.2 MiB | 52.4 MiB | 55.4 MiB / 298 ms | 54.7 MiB / 302 ms |
| 67.5 MiB / 90 rows | ~71.1 MiB | 588 ms | 74.2 MiB | 141.0 MiB | 143.9 MiB / 909 ms | 143.3 MiB / 904 ms |
| 135 MiB / 180 rows | ~71.2 MiB | 19,020 ms | 75.0 MiB | 211.0 MiB | 212.9 MiB / 2,022 ms | 212.9 MiB / 1,877 ms |

At 180 rows, ordinary paged residency stays near the 90-row observation while
held payload and mutation memory grows. KDF high-water RSS (~262 MiB) hides
this growth if only whole-process peak is examined. The larger search also
costs substantially more CPU/I/O: bounded selection rescans/decrypts uncached
metadata across pages. This warrants separate workload investigation, not a
claim that arbitrary text volume has constant latency.

The instrumented repeat confirms actual preparation residency:

| Rows | Prepared batch changes / RSS | Prepared recursive changes / RSS | Sampled batch / recursive peak RSS |
|------|------------------------------|----------------------------------|------------------------------------|
| 30 | 30 / 53,656 KiB | 31 / 53,672 KiB | 56,012 / 55,256 KiB |
| 90 | 90 / 144,380 KiB | 91 / 144,368 KiB | 146,724 / 146,736 KiB |
| 180 | 180 / 216,028 KiB | 181 / 215,972 KiB | 218,436 / 218,380 KiB |

The extra recursive change is the containing group. Each operation completed
one commit and passed post-operation integrity/count checks. Raw counters are
in `evidence/capacity-instrumented/`. The held-draft proxy and real vectors agree
closely for these fixtures; that is not a bound on all maximal/conflicted rows.

## Source and transaction trace

In `qv-core/src/edit.rs`, `subtree` collects compact IDs. `set_deleted` and
`edit_entries` then decode and retain changed entry/group bodies in
`Vec<Change>` before calling `commit`. The batch API caps handles at 4096;
recursive deletion follows the structural subtree and is not limited by that
batch-handle cap. Existing model/record/ciphertext limits still apply.

`commit_with` consumes changes, encodes/decodes each version for the compact
candidate index and stages encrypted objects with `Write::put_local`. The
storage write owns a candidate manifest and metadata, not a retained plaintext
vector of all bodies. It inserts encrypted objects inside one SQLite
transaction. Candidate index/budgets and cancellation are checked before
commit; history retention, manifest/head/counters and object-reference updates
commit atomically before the external anchor. Dropping an unfinished Write
rolls back. A durable commit followed by anchor failure remains durable and
must be reported as such. View-cache accounting does not cover the caller's
prepared payload vector, encryption scratch, SQLite or KDF.

## Options for the owner

| Approach | Memory and operational tradeoff |
|----------|---------------------------------|
| Keep current preparation | No migration; present atomicity and cancellation behavior; decoded payload memory scales with affected data |
| Stage changed records one at a time in the existing transaction | Retain compact selected IDs/preconditions and one decoded payload at a time; can preserve a single commit, but needs design/review of borrow structure, index preflight, rollback, cancellation and longer transaction lifetime |
| Two-pass validated preparation | First retain compact IDs/base identities and validate scope; then decode/stage one record at a time under the same mutation authority; more reads and explicit stale-base checks, still one commit |
| Encrypted private staging | Can bound payload residency, but adds temporary-object/key/cleanup/disk-full/crash complexity; plaintext spill is forbidden |
| Commit in chunks | Would change all-or-nothing behavior and cancellation outcomes; not equivalent to the current operation and not authorized |

Recommendation: if a tighter mutation-memory target is wanted, first design
sequential staging in one transaction, retaining only compact preconditions and
candidate metadata. Measure structural/SQLite/encryption costs as well as the
payload vector; do not promise a 64 MiB process bound. Do not introduce a new
vault-eligibility cap or silently split commits to meet a target.

The owner still selects whether this work is needed and the supported-target
memory/latency goals. Representative conflicted/maximal-payload workloads and
continuous allocation profiling remain open. No architecture or
behavior change was implemented by this measurement work.
