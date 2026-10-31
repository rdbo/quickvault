# Phase 2.3 dependency record

The owner delegated the platform dependency choice and necessary implementation
on 2026-10-31. This record describes the resulting **development baseline**, not
an audit, a security certification or release approval (0012 §3).

## Selection and provenance

Pinned `zbus = 6.2.0` supplies typed, authenticated system D-Bus calls and signal
subscriptions. Its Rust MSRV is 1.89, within the repository's 1.98.1 toolchain.
The originally proposed 5.19.0 graph was rejected after current deny checks
reported RUSTSEC-2026-0370/0371/0372: its standalone zvariant/zbus_names/derive
crates are unmaintained after merging into zbus 6. No advisory ignore was added.
The downloaded 6.2.0 package sources and Cargo manifests were used for API and
feature verification; documentation URLs were unavailable through the browser
in this environment. Advisory details came from the freshly fetched RustSec
advisory database and cargo-deny output.

zbus is Linux-only. Production features are default-rt and proxy; service is a dev-only feature
for the private-bus integration fixture. No production object server is created.
Explicit async-io 2.6.0 and futures-lite 2.6.1 edges reuse runtime packages to
bound setup and shutdown with timer races. No network sync, listener or external
process is started by constructing core. The logind adapter uses only the fixed
local system-bus Unix endpoint; no secret is passed to D-Bus. Tests use a private
D-Bus daemon via an internal builder and never lock the real desktop.

Alternatives: hand-written D-Bus framing/command-output parsing would add a new
parser/authentication contract; C libdbus bindings add a native dependency and
FFI boundary. Neither improves the reuse of a maintained typed Rust client.
The selected dependency is not a crypto or key-storage backend.

Cargo.lock retains registry identities and hashes. Comparing parsed package
records against HEAD found no existing external record removed or changed by
the root dependency addition. The final root graph adds 26 external packages: two with imported audit
coverage (parking and hex), plus the 24 audit-debt entries below.
Existing rustix/X11/zeroize versions remain pinned. The application-maintained
x11rb patch is reused without source changes and is tested separately; its
explicit vet audit-as-crates-io=false records that upstream registry audits do
not cover the local application patch. The isolated UI spike also selects that
patch now that its core dependency includes platform; it must not silently use
the unpatched registry clipboard implementation.

## Audit disposition

The existing six audit imports were refreshed without changing their criteria
or adding blanket publisher trust. Current imports do not cover these 24 exact
versions to the required criteria. They have explicit version-scoped exemptions
with notes in supply-chain/config.toml, as audit debt under the owner's delegated
dependency baseline. None was certified as audited. Existing exemptions were
preserved. Vet passes with 29 fully audited, 6 partially audited and 103 exempted
packages (79 previous + 24 new). Imported coverage is evidence about the stated
packages/criteria, not a claim that all QuickVault dependencies are audited.

| Package | Version |
|---------|---------|
| async-io | 2.6.0 |
| async-trait | 0.1.92 |
| concurrent-queue | 2.5.0 |
| crossbeam-utils | 0.8.23 |
| endi | 1.1.1 |
| fastrand | 2.5.0 |
| futures-io | 0.3.34 |
| futures-lite | 2.6.1 |
| hermit-abi | 0.5.3 |
| memoffset | 0.9.1 |
| ordered-stream | 0.2.0 |
| polling | 3.11.0 |
| serde | 1.0.229 |
| serde_repr | 0.1.21 |
| socket2 | 0.6.5 |
| tempfile | 3.27.0 |
| uds_windows | 1.2.1 |
| uuid | 1.29.0 |
| winnow | 1.0.4 |
| zbus | 6.2.0 |
| zbus_macros | 6.2.0 |
| zbus_utils | 6.1.0 |
| zcheapstr | 1.2.0 |
| zruntime | 0.2.2 |

Cross-target entries are retained because Cargo locks and vet inspect the full
supported graph; they do not imply a Windows adapter has been implemented.
The ordinary deny policy remains unchanged: advisories/bans/licenses/sources
must pass. Remaining audit debt must be assessed as part of future release
evidence; this phase does not authorize a release.
