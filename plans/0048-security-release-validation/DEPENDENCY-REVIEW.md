# Dependency review evidence

2026-11-09; baseline commit `ee0cafdd56af1b9593445cb632f0f1be3e7e101a`.

## Exact scope and debt

[dependency-baseline.tsv](evidence/dependency-baseline.tsv) records the exact
22 registry package versions/checksums added or updated in 0047: the 20-package
authentication family and rusqlite 0.41.0/libsqlite3-sys 0.39.1. Every version
still has an explicit development exemption in `supply-chain/config.toml`.
The `safe-to-deploy` criterion on an **exemption is not an audit**. No review
certification, trusted publisher delegation or new exemption was added here.

[crypto-features.txt](evidence/crypto-features.txt) and
[bigint-reverse-features.txt](evidence/bigint-reverse-features.txt) are fresh
locked Cargo feature traces. Paths, package hashes and selected arithmetic/
scratch analysis are in [0047's dependency evidence](../0047-audit-policy-and-lan-auth/DEPENDENCIES.md).
The source inventory binds these policy and implementation inputs.

## Primary-source check

The pinned [opaque-ke 4.0.1 README](https://raw.githubusercontent.com/meta/opaque-ke/v4.0.1/README.md)
describes the 2021 NCC review of 0.5.0 and fixes through 1.2.0. That report
does not cover 4.0.1 or QuickVault's ephemeral-registration composition.
No exact-version composition report was obtained during this preparation.

[RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html)
still describes timing-variable integer operations; patched versions start at
0.7.6. The current 0.5.5 exception depends on the fixed suite using dalek
arithmetic and only the byte-oriented XMD expansion from elliptic-curve.
It is a reachability-based exception, not a repair or a timing proof. Review
that assumption again if features, suite, callers or dependencies change.

The [SQLite advisory source](https://raw.githubusercontent.com/RustSec/advisory-db/main/crates/libsqlite3-sys/RUSTSEC-2026-0459.md)
identifies bundled libsqlite3-sys 0.39.1 as SQLite 3.54.1, containing the WAL
page-size disclosure repair. The [rusqlite release](https://github.com/rusqlite/rusqlite/releases/tag/v0.41.0)
provides the version/API change context. This confirms the published repair
boundary; it does not audit the new bindings or bundled C source.

## Current policy checks

Fresh CI-pinned cargo-deny 0.20.2 and cargo-vet 0.10.3 both pass.
Locked vet reports 94 fully audited, 11 partially audited and 480 exempted
packages across the workspace, matching the historical development baseline.
This is a policy classification, not 22 newly completed audits.

The first deny invocation failed because the Cargo home advisory cache is
read-only. A temporary exact copy of `deny.toml`, adding only
`advisories.db-path = "/tmp/qv-0048-advisory-dbs"`, passes all four checks.
No ignore/license/source policy or repository supply-chain file changed.
Logs: `/tmp/qv-0048-evidence/{deny,deny-writable-cache,vet}.log`.

## Release disposition

Genuine review of the new family and SQLite delta remains open. An auditor
must identify the reviewed version or exact base-to-target delta, configuration,
criteria, report and exclusions. Only genuine matching evidence belongs in
`supply-chain/audits.toml` or imports. Refreshing policy checks, downloading
upstream reports or this inventory cannot retire the unaudited debt by itself.
