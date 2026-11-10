# Exact dependency baseline

2026-11-10. QV-012 maintenance repairs; independent audit debt remains.

The product retains rusqlite0.41.0/libsqlite3-sys0.39.1. Fuzz's older SQLite
and newer transitive resolutions are reconciled using the product lockfile as
the resolver seed. Its only additional registry packages are libfuzzer-sys0.4.13,
arbitrary1.5.0 and jobserver0.1.35. They are fuzz tooling, not new product
dependencies. All shared package versions and checksums match the product.

Six exemptions are absent from both compiled trees: futures-task0.3.21,
futures-util0.3.21, itertools0.10.3, once_cell1.12.0,
wasm-bindgen-macro0.2.99 and wasm-bindgen-shared0.2.100. They are necessary
**bases of existing imported delta-audit chains**, rather than obsolete entries.
Removing them made locked vet report the six corresponding current versions as
unvetted. Retain the original versions/criteria and explain this in their notes;
do not invent replacement full audits or silently exempt the current tips.
The corresponding delta records are in supply-chain/imports.lock under Mozilla,
Bytecode Alliance and ISRG imports. Vet checks the full criterion paths; the
baseline checker only permits these named bases when an imported delta actually
references them. Their unaudited starting versions remain explicit debt.

Security-critical
exemptions now name their actual role and the remaining independent review
requirement; prior approval/evidence notes are retained. No audit record or new
exemption is created. `cargo vet` passing through exemptions does not establish
that a dependency or its composition was independently reviewed.

The desktop build consumes the unchanged prebuilt JS from the verified
dioxus-desktop0.7.10 archive, removing its ambient Bun invocation and build-only
lazy-js-bundle edge. Other upstream dependencies may still use lazy-js-bundle;
this repair concerns the maintained desktop package. Exact hashes and future
artifact-update requirements are in [third-party maintenance](../../third-party/README.md).

CI checks shared lock versions/checksums, stale exemptions and both retained
JS/TS hashes with `python3 scripts/check-supply-chain.py`. This is hygiene and
provenance checking, not an audit. See [0048 dependency review debt](../0048-security-release-validation/DEPENDENCY-REVIEW.md)
for release requirements. Final deny/vet/build results are recorded separately
in this plan's validation record.
