# Plan 0049 validation — 2026-11-11

Source implementation and local qualification only. Tests/builds are not a
security certification, fresh-context review or evidence of phone execution.
No personal vault, device install, commit, branch or push was involved.

## Implementation and scope

Android's welcome/locked/switcher actions select a SAF document, stage bounded
ciphertext, then require a password, unused local filename and explicit
private-copy/new-baseline acknowledgement. The provider document is never
written. Linux keeps its original-file behavior; both switchers expose opening.

Core/store own opaque capabilities, full verification and index preflight.
Publication streams a verified archive through existing fresh-local creation,
with a new writer/replica/head/anchor and no overwrite. Current password/control
binding prevents silently installing another password. Staging uses the existing
inode/directory leases; cleanup cannot close a live SQLite descriptor or reclaim
another producer. Wrong passwords/pre-publication errors retain a reusable
candidate. Post-publication cancellation/failure retains the created file and
cannot return a late unlocked session. No dependency, primitive, unsafe code,
vault/archive/wire format or budget changed.

The native adapter binds results and cleanup to their request IDs. Metadata
queries happen outside the cancellation monitor, then recheck the active ID;
locking cannot be undone by a late provider query. After staging, the URI is
cleared while a metadata-only ID preserves foreground-return deferral.

## Local results

| Check | Result |
|-------|--------|
| SPDX, fmt, offline matrix | Pass |
| Locked all-target workspace Clippy (`-D warnings`) | Pass |
| Desktop/validation app all-target Clippy | Pass; retained upstream vendor warnings do not alter product lint rules |
| Android arm64 release/mobile library Clippy | Pass |
| Focused store/core/app import regressions | 11 pass |
| Locked workspace tests | Final tree: 1,011 pass, zero failures, seven intentional ignored tests across 48 groups; the near-budget case additionally passes when explicitly invoked |
| Stock large-text lifecycle plus import after rotation | Pass: all >64 MiB searchable text remains searchable; imported sequence starts at 1 |
| Explicit near-budget import qualification | Pass: 990 MiB attachment plaintext, 1,071,078,080 referenced ciphertext bytes (99.752% of the unchanged budget), 1,106,436,096 physical SQLite bytes |
| Near-budget stream/reopen properties | Actual source bytes consumed; read requests <=65,536 bytes; all 99 attachments retained and fully verified after publication/reopen; hundredth attachment rejected without advancing source head |
| Ordinary Android app + instrumentation | Build pass without validation features; test provider absent from the main APK |
| Isolated regular-UI provider package | Build/native-identity/manifest checks pass; final hashes below |
| Android provider runtime / attended system picker | **Not run:** no connected device |
| Required fresh-context implementation review | **Pending:** this developer session does not supply it |

The near-budget test is intentionally separate from the normal parallel suite
because it writes several GiB. It was explicitly executed on private disk-backed
storage under the ignored app build directory, then removed. It is not merely
manifest arithmetic, sparse preallocation or a skipped claim. The first attempted
1,000-MiB plaintext fixture exceeded the existing padded-ciphertext limit; the
corrected fixture uses the same 99-attachment sizing as 0048 P3, keeps every limit
unchanged and explicitly tests rejection of the hundredth attachment.

## Commands and logs

Use the documented optimized test environment (no KDF cost change):

```sh
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1
export QV_TEST_KDF_JOBS=2
export QV_TEST_XVFB=/tmp/qv-0049-checks.8d00rw/xorg/Xvfb
sh scripts/check-spdx.sh
cargo fmt --check
sh scripts/check-matrix.sh
cargo clippy --all-targets --locked -- -D warnings
cargo clippy --locked -p qv-app --features desktop,validation --all-targets -- -D warnings
cargo test --locked
```

Run the heavy qualification separately in a new private directory on a filesystem
with at least 6 GiB free (several copies coexist during verification/publication):

```sh
qv_capacity_tmp=$(mktemp -d "$PWD/crates/qv-app/dist/qv-import-capacity.XXXXXX")
TMPDIR="$qv_capacity_tmp" QV_TEST_KDF_JOBS=1 cargo test --locked -p qv-core \
  vault_import_near_budget_streams_actual_bytes_and_reopens -- --ignored --nocapture
rmdir "$qv_capacity_tmp"
```

Full logs are `/tmp/qv-0049-{spdx,fmt,matrix,clippy,desktop-clippy,workspace-tests}.log`;
focused evidence is `/tmp/qv-0049-import-tests.log`; the complete near-budget
run is `/tmp/qv-0049-capacity-test.log` (250.55 s). The refused initial oversized
fixture is retained as `/tmp/qv-0049-capacity-overbudget-fixture.log`. Initial
new-test signature/assertion and Clippy issues were corrected; no existing tests
or limits were relaxed. A workspace run was interrupted while finishing the
unsupported-platform stubs; subsequent complete runs pass.

Android builds use the existing pinned SDK/NDK, JDK21 and Dioxus0.7.10:

```sh
eval "$(sh scripts/setup-android.sh --print-env)"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export QV_DX=$PWD/crates/qv-app/dist/.build-cache/dx-0.7.10/bin/dx
cargo clippy --release --locked -p qv-app --features mobile \
  --target aarch64-linux-android --lib -- -D warnings
QV_APP_DEVICE_VALIDATION=0 QV_APP_MEDIA_VALIDATION=0 sh crates/qv-app/scripts/build-android.sh
python3 crates/qv-app/scripts/package-isolated-android.py --uid org.quickvault.validation49
```

(The plan-local `package-android.py` was replaced by this generic packager on
2026-11-14; outputs are now `quickvault-validation49-{debug,tests}.apk`, not
`quickvault-import49-*`.)

Logs: `/tmp/qv-0049-android-{clippy,build,package}.log`. The packager checks app/test
IDs and target, API29 baseline, provider authority and absence from the main APK,
and byte-identical native libraries against the ordinary APK. It never installs.

Final APK SHA-256:

| Artifact | SHA-256 |
|----------|---------|
| `crates/qv-app/dist/quickvault-debug.apk` | `91e7986d03cfc0d2c7834e6d2617e1dc5b03ea4ccc88389e10a019124171f4f8` |
| `crates/qv-app/dist/quickvault-import49-debug.apk` | `38854e3c2b453f6a2980c08470f186ec8b4049e780ae07e2e1fbb4f09c5c3647` |
| `crates/qv-app/dist/quickvault-import49-tests.apk` | `ff215f78404b4eec98abeada3ee9d40d421d3232f234818ce252fa937e34f93c` |

The final APK/project verification log is in
`/var/tmp/qv-0049-android-twvftyer/build.log`. Python packager syntax, shell
syntax and `git diff --check` also pass. No Rust/source inputs changed after
the final gate run; subsequent edits only record these Markdown results.

## Device continuation

The fixture provider/test is packaged only in the test APK and accepts the
disposable `org.quickvault.validation49` UID. Run only the isolated pair; never
install a test build over the owner's ordinary application. The test requires
fresh isolated app state and creates its own closed synthetic vault through the
ordinary name/password UI. It disables optional quick unlock only in that fresh
UID's ordinary preferences to avoid conflating this test with 0048's attended
Class3/keystore matrix. KDF, protection acknowledgement and other requirements
remain unchanged.

```sh
adb install -r -t crates/qv-app/dist/quickvault-validation49-debug.apk
adb install -r -t crates/qv-app/dist/quickvault-validation49-tests.apk
adb shell am instrument -w -r \
  -e class org.quickvault.app.VaultImportTest \
  org.quickvault.validation49.test/android.test.InstrumentationTestRunner
```

The real `content:` fixture covers unknown sizes, pipes/short reads, refusal,
permission denial, malformed/truncated bytes, background cancellation, stale
cleanup/results, wrong-password retry without rereading the provider, consent,
editable private copy, source digest and durable reopen. Compilation is not
runtime evidence. Separately perform an attended Downloads/system-picker run
from a closed/exported synthetic vault and record device/build identities,
source before/after digest, copy notice, search/edit/lock/reopen and cancellation.
Phone large-data/provider qualification and fresh-context review remain open.
0048's independent review, D12, keystore and other release gates remain separate.
