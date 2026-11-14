# Review — Plan 0049: Android vault-file picker and verified import (partial)

| Verdict | Reviewed | Diff reviewed |
|---------|----------|---------------|
| Partial — not a verdict on the whole plan | 2026-11-14 | commit `d4ce6ab`: `crates/qv-store/src/vault_import.rs` |

## Summary

Plan 0056 (1.0 preparation) asked for focused reviews of the riskiest
unreviewed code. This covers the store side of importing an untrusted
user-selected document: bounded staging, authentication and publication.
`qv-core/src/vault_import.rs`, the app controller, the Kotlin document glue
and the device qualification remain; the plan stays `In progress`.

## Findings

Checked: staging writes only ciphertext into a leased private temporary,
reads at most `MAX_DB_BYTES` plus one probe byte and refuses more without
writing it; every failure drops the lease before the staging guard reaps
unleased temporaries (test `vault_import_bounds_actual_bytes_and_cleans_failed_staging`);
a wrong password keeps the same candidate and its lock, so the provider is
never reread; the full `verify_all` pass and the keyslot-descriptor
cross-check run before a `VerifiedVaultImport` exists; publication goes
through the ordinary verified archive restore path with a fresh writer,
replica, head and anchor, and a post-publication failure is reported as
`PublicationIncomplete`, never as a clean failure.

1. **[low] A cancellation or integrity failure after the password consumes
   the candidate** — `crates/qv-store/src/vault_import.rs:107`. After
   `held.take()`, a failing `finish_unlock`/`verify_all` drops the file, so a
   retry needs the document picked again. Fails safe. Action: recorded.
2. **[low] Cancellation is reported as `StoreError::Io`** — `check_cancel`.
   Callers must check their own cancel token to tell a cancel from an I/O
   failure; core does (`qv-core` maps by token). Action: recorded.

No critical, high or medium findings in the reviewed file.

## Fixes applied by reviewer

None.

## Gates

See plan 0056's execution log for the 2026-11-14 tree.

## Escalations for the owner

None blocking. The real-phone picker qualification is plan 0056 step 5.
