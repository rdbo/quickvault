# Dioxus spike dependency disposition

The owner's Dioxus selection is retained. The isolated lockfile records the
actual graph; root Cargo.lock and the root dependency policy/audit store are
unchanged. Direct crates: dioxus 0.7.3 (minimal), dioxus-desktop 0.7.3
(tokio_runtime, no devtools), existing qv-core path/version and zeroize 1.9.1.
The desktop runtime feature is required by unconditional upstream edits.rs calls.
Internal Dioxus semver dependencies resolve to 0.7.10 where applicable.

The isolated deny.toml adds version-scoped license exceptions only for standard
Dioxus transitives: BSD-3-Clause, ISC, MPL-2.0, Zlib and the target-lexicon
Apache-2.0 WITH LLVM-exception expression. These are not global root allowances.
Four advisory exceptions are scoped to this disposable spike under owner-resolved
plan decision D3. No unsafe lint exception, fork or custom engine was introduced.

## Advisory disposition (D3 resolved 2026-10-26)

| Package | Advisory | Observation / residual work |
|---------|----------|-------------------------------|
| glib 0.18.5 | [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html) | VariantStrIter unsound out-pointer handling; patched >=0.20.0, beyond GTK 0.18 binding family. Scoped ignore; no whole-program reachability proof. |
| rand 0.7.3 | [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097.html) | Requires log/thread_rng and a reentrant custom logger. Locked rand 0.7.3 features inspected: alloc/default/getrandom/getrandom_package/libc/rand_pcg/small_rng/std, without log. This narrows applicability but is not a blanket future exception. |
| fxhash 0.2.1 | [RUSTSEC-2025-0057](https://rustsec.org/advisories/RUSTSEC-2025-0057.html) | Unmaintained dependency in stock framework tree; no exploit claimed merely from maintenance status. |
| proc-macro-error 1.0.4 | [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html) | Unmaintained macro dependency; not a claim of exposed runtime secret code. |

Dioxus desktop 0.7.10 source also declares Wry 0.53.5. A patch bump alone does
not establish a fixed GTK graph. This does not mean Dioxus is rejected or every
version/backend has the same issue. Four explicit IDs and reasons are recorded in the isolated deny.toml. Production
gates remain strict; these exceptions must not be carried into a release silently.

## Vet coverage and checks

The initial check against a temporary copy of the root store found 396 missing
coverage entries. Imported audit evidence and regenerated minimal exemptions are
retained in the isolated `supply-chain/` store. The resulting locked check passes:
**89 fully audited, 47 partially audited, 356 exempted**. Exemptions establish the
initial disposable-framework baseline; they are not independent audits. Root
records remain unchanged (27 fully audited, 6 partially audited, 75 exempted).

Isolated deny passes with the four approved exceptions and version-scoped license
exceptions. Logs: `/tmp/qv-ui-deny.log`, `/tmp/qv-ui-vet.log`; graph metadata:
`/tmp/qv-dioxus-metadata.json`. The deny run uses a temporary copy of the spike
policy adding only a writable advisory-cache path. The retained spike vet store
is used by its normal locked command. Passing checks do not establish security.

A scoped source search for `array_iter_str`/`VariantStrIter` in the resolved
glib/gio/gtk/gdk/muda/rfd/Wry/Tao/Dioxus desktop/core/asset-resolver source found
references only within glib's implementation/examples/tests. This supports
further reachability review but is not a whole-program proof of unreachability. The exception is explicitly a spike risk acceptance. Log: `/tmp/qv-ui-glib-callsite-check.log`.
