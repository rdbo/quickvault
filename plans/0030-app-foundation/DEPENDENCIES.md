# App foundation dependency gate — 2026-10-31

This records the initial prerequisite assessment and its subsequent disposition.
It is not a security audit. The sections through Candidate license allowances
describe the 2026-10-31 probe; the final disposition below supersedes its blocked
status. D1 and D2 are approved under owner delegation.

## Actual checks and scope

A temporary standalone manifest under `/tmp/qv30-dependency-probe` selected
Dioxus/desktop 0.7.10, the approved direct serde/JSON/URL/zeroize versions,
current qv-core and the existing maintained x11rb patch. `cargo deny` used the
unchanged root deny.toml and a refreshed advisory database; `cargo vet` used a
copy of the root supply-chain store with existing locked imports. The root
Cargo.lock and supply-chain store were preserved.

A second probe changed only the approved desktop package's `image` dependency
to disable default codecs and enable PNG, which is sufficient for its bundled
window icon. This removes the paste advisory and unnecessary image-codec graph.
It also pinned qv-core's path dependency version to remove the probe's wildcard
error. This experiment was under /tmp, not a product-source patch.

Trimmed graph: 523 package records, including 397 external records absent from
the current root lockfile. The exact candidate lock hash and all 395 uncovered
name/version/criteria tuples are in [UNVETTED.json](UNVETTED.json). This is a
probe result under current imports, not a final dependency selection or a
request to certify those packages as audited. No new exemption was added.

## Gate results

| Check | Result |
|-------|--------|
| Initial dependency deny | Fail: advisories, licenses; probe-only path-version wildcard |
| Trimmed dependency deny | Fail: four advisories and 16 license entries; bans and sources pass |
| Candidate graph vet with copied locked root store | Fail: 395 uncovered package versions |
| Current product graph | Unchanged; the prior independent root gates remain applicable |

Logs: `/tmp/qv30-inspect/dependency-deny.log`,
`dependency-deny-trimmed.log`, `dependency-vet.json`, `licenses.json`,
`rand-features-all.log`. Each failure exit was retained.

## Remaining advisories and paths

| Advisory | Exact package | Dependency path / assessment |
|----------|---------------|------------------------------|
| RUSTSEC-2024-0429 | glib 0.18.5 | Desktop → tao/wry → GTK 0.18 → glib 0.18.5. Unsound VariantStrIter output pointer; fixed upstream in glib >=0.20, outside GTK 0.18's compatible API range. Cached source confirms the affected `&p` argument. |
| RUSTSEC-2024-0370 | proc-macro-error 1.0.4 | glib-macros 0.18.5 and gtk3-macros 0.18.2 build dependencies; unmaintained. |
| RUSTSEC-2025-0057 | fxhash 0.2.1 | Android wry → kuchikiki → selectors 0.24; unmaintained. |
| RUSTSEC-2026-0097 | rand 0.7.3 | Same selectors → phf/phf_codegen 0.8 chain. Advisory requires the log/thread_rng combination plus reentrant custom logging. Probe features do not enable rand's log feature; this does not make the package pass the repository's no-ignore gate. |

The glib upgrade cannot be forced by a compatible lockfile update: GTK's
0.18 types/APIs are used throughout the current Linux backend. The desktop
package alone cannot backport glib's code or replace selectors/macro dependencies.
The old spike's advisory/license exemptions are explicitly limited to synthetic
feasibility data and were not copied to production.

Primary references, checked 2026-10-31:
[RustSec GLib advisory](https://rustsec.org/advisories/RUSTSEC-2024-0429.html),
[upstream fix](https://github.com/gtk-rs/gtk-rs-core/pull/1343),
[RustSec rand advisory](https://rustsec.org/advisories/RUSTSEC-2026-0097.html).
The unmaintained advisories and paths were read from the current deny output.

## Recommended remediation authority (D2)

Keep production advisories denied, with no new advisory ignores. Authorize
narrow maintained patches for these additional exact packages:

- glib 0.18.5: backport the upstream mutable-output-pointer fix and its focused
  regression evidence; retain upstream unsafe blocks and licenses, add no new
  unsafe operation. This is a correctness backport, not an API/crypto change.
- glib-macros 0.18.5 and gtk3-macros 0.18.2: replace the unmaintained diagnostic
  helper with a maintained compatible helper, adapting only diagnostics/tests.
- selectors 0.24.0: replace fxhash with maintained rustc-hash and update the
  paired phf runtime/code generator to a maintained compatible release. Check
  parser/generator behavior on Android and run upstream focused tests.

Those are candidate remediation directions, not verified drop-in replacements.
Within the expanded scope, select compatible helper versions, retain provenance
and review each exact patch before use. Stop if remediation needs a different
architecture, cryptographic change, a further unsafe operation or an advisory
exception. Do not claim that changing a Cargo source identity alone fixes an
advisory: keep the known issue and regression proof in the provenance record.

Also authorize package/version-scoped compatible license allowances below and
a documented development vet baseline after graph minimization and checking
available imported audits. Any remaining exemption must name the exact package,
version and missing criterion with an audit-debt note; no blanket publisher
trust, fabricated certification or release/security approval. UNVETTED.json is
an explicit upper candidate list for this probe, not an automatic exemption
list. New helper versions must be recorded in the final dependency assessment.

Alternatives are to wait for upstream Linux/Android integration fixes, or
explicitly accept scoped advisory risk. Neither was chosen by the agent;
the recommendation is source remediation while preserving the advisory gate.

## Candidate license allowances

These are metadata-derived license identifiers. Use precise
package/version exceptions rather than broadening the global license list.
Versions removed during minimization need no exception.

| Package | Version | License expression |
|---------|---------|--------------------|
| const_format | 0.2.37 | Zlib |
| const_format_proc_macros | 0.2.37 | Zlib |
| cssparser | 0.29.6 | MPL-2.0 |
| cssparser-macros | 0.6.1 | MPL-2.0 |
| dtoa-short | 0.3.5 | MPL-2.0 |
| konst | 0.2.20 | Zlib |
| konst_macro_rules | 0.2.19 | Zlib |
| libloading | 0.7.4 | ISC |
| libloading | 0.8.9 | ISC |
| option-ext | 0.2.0 | MPL-2.0 |
| rustls-webpki | 0.103.16 | ISC |
| selectors | 0.24.0 | MPL-2.0 |
| slotmap | 1.1.1 | Zlib |
| subtle | 2.6.1 | BSD-3-Clause |
| target-lexicon | 0.12.16 | Apache-2.0 WITH LLVM-exception |
| untrusted | 0.9.0 | ISC |

## Final disposition — 2026-11-01

Owner delegated choices and tradeoffs. Chosen: five narrow source snapshots
instead of advisory ignores or a renderer replacement. Exact provenance,
patches and focused test commands are in [third-party/README.md](../../third-party/README.md).
GLib retains its compatible GTK API with the mutable output-pointer backport.
Both diagnostic macro packages select proc-macro-error3 3.1.1; error2 was
rejected because it is also unmaintained. selectors uses rustc-hash 2.1.1 and
paired phf/phf_codegen 0.11.3. Desktop enables only PNG codecs. This trades
ongoing patch maintenance for retaining the selected shared UI and unchanged
advisory policy. No product unsafe operation or crypto/format change was added.

qv-app directly uses qv-core, ctutils, zeroize and optional exact Dioxus/desktop
0.7.10. JSON/URL parsing remains inside the maintained integration rather than
unused direct app dependencies. Default workspace tests remain headless; the
validation feature and dedicated CI job exercise the actual webview. An isolated
third-party workspace runs upstream regressions without adding those packages
to the product workspace.

`deny.toml` has 15 exact compatible package/version license allowances from the
candidate table; selectors is local and retains MPL-2.0. No advisory ignore was
added. `cargo deny check` passes advisories, bans, licenses and sources. Local
source identity alone is not proof of remediation: review the actual GLib fix
and maintained patch against its archive and exercise its optimized iterator tests.

Imported audit coverage was refreshed with `cargo vet regenerate imports`.
The final config has 410 exact version exemption entries (previously 109): 302
added and getrandom 0.4.3 removed because imported coverage now suffices.
[UNVETTED.json](UNVETTED.json) records 306 missing-coverage entries at assessment:
302 new exemptions plus four existing ones (phf/phf_generator/phf_shared 0.11.3
and toml_edit 0.20.2). The final locked vet run passes with 93 fully audited,
11 partially audited and 404 exempted packages in the selected graph. Config
entries and selected graph counts differ because some exemptions are unused.
Exemptions carry development audit-debt notes; they are not audit attestations,
publisher trust or release/security approval. No spike exemptions were copied
as production advisory waivers.

Current evidence and remaining platform limitations are in [VALIDATION.md](VALIDATION.md).
