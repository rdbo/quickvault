# Plan0050 validation — 2026-11-10

Local repair evidence only. Tests, exemptions and specification conformance do
not prove security or satisfy0048's independent review/device release gates.
No personal vault, reviewer contact, commit, branch or push was involved.

## Reproducible environment

Alpine edge, pinned Rust1.98.1. Build/test profile overrides used consistently:

```sh
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1
export QV_TEST_KDF_JOBS=2
export QV_TEST_XVFB=/tmp/qv-0050-xorg/Xvfb
```

The default image lacks Xvfb. Fetch/extract Alpine's xvfb21.1.25-r0 package
and dependencies into a private temporary tree, and point QV_TEST_XVFB to a
wrapper selecting that binary and its library directory. No system package or
personal display was modified. `run-media.py` creates its own display and cwd,
samples only its child process tree and removes its owned synthetic fixtures.
Use `--private-runtime` to provide a disposable D-Bus/PipeWire session and null
audio sink. It requires dbus-daemon, pipewire, pipewire-pulse, wireplumber and
pactl, redirects runtime/state/cache/config into its owned directory, and stops
its own services afterward. This tests decoded playback/seek, not physical
speaker output. It does not configure the normal desktop session.

## Results

| Check | Outcome / evidence |
|-------|--------------------|
| Required workspace gates | Pass:1,000 tests,0 failures,6 intentional ignored tests across48 test groups; fmt/SPDX/matrix/Clippy pass. Logs `/tmp/qv-0050-final-tree-{tests,clippy,fmt,spdx,matrix}.log` |
| Desktop/validation app all-target Clippy | Pass; `/tmp/qv-0050-final-tree-app-clippy.log` |
| Locked fuzz build, all eleven bins | Pass on final tree, `/tmp/qv-0050-final-tree-fuzz.log` |
| Shared dependency/checksum/exemption/artifact check | Pass: `python3 scripts/check-supply-chain.py` |
| Deny0.20.2 product | Pass: advisories, bans, licenses, sources; `/tmp/qv-0050-deny-tempdb2.log` |
| Deny0.20.2 fuzz | Pass: advisories, bans, sources; `/tmp/qv-0050-deny-fuzz.log` |
| Vet0.10.3 locked | Pass:94 fully audited,11 partially audited,480 exempted; `/tmp/qv-0050-vet-final.log`. Exempted does not mean audited. |
| Maintained vendor transport/boundary tests |13 pass; `/tmp/qv-0050-vendor-final.log` |
| Standard real GTK/WebKit tests |3 pass: local flow, real Linux services, active-content/privileged-route refusal; `/tmp/qv-0050-engine-final.log` |
| Native media | Pass twice on final native binary with private D-Bus/PipeWire/null-sink runtime; `/tmp/qv-0050-native-private-{runtime,repeat}/native.log`. |
| Android media APK and instrumentation | Final-tree build/package pass; `/tmp/qv-0050-final-tree-android-{build,package}.log`. Device test **not run**: `adb devices` lists none. |

Deny used an exact temporary copy of deny.toml with only advisory `db-path`
set to `/tmp/qv-0050-advisory-dbs`; the default cache is read-only. Policy is
unchanged. The CI-pinned tools were installed only under `/tmp/qv-0050-tools`.
The downloaded cargo-deny release checksum matched its official published
checksum. cargo-vet0.10.3 was built with `cargo install --locked`.

## Regression coverage

- Foreign SQLite WAL/hot-journal/hardlink probes preserve bytes; legitimate own
  crash recovery remains in the store matrix.
- Typed durable/anchor-pending results retain the committed index and survive
  late cancellation; configured budgets remain distinct from capacity errors.
- Full clock unions include the actual local resolving writer. Independent
  same-time deletes retain distinct operation IDs; missing legacy IDs never
  timestamp-match other children.
- Core destructive calls refuse missing, stale, foreign or damaged recovery
  authorization unchanged. A pin is invalid after a mutation. Ordinary writable
  sessions cannot adopt a baseline. Late-lock completion remains truthful.
- Separate child processes prove live recovery copies cannot be renamed or
  pruned, and live temporary producers cannot be reclaimed. Killing the producer
  permits cleanup. A raw SQLite child probe proves cleanup/failed alias opens
  do not drop the live process's SQLite POSIX lock. Parent-alias regression
  preserves the previously permitted private-directory policy.
- Range tests cover unaligned two-chunk reads, exact EOF, overflow/oversize,
  cancellation and damaged touched ciphertext. Source tests cover consent,
  revocation of cloned sources and locked sessions. Prefix tests retain a
  fixed-size buffer while consuming a synthetic1 GiB stream; the real10 MiB
  attachment eligibility limit is unchanged.
- X11 tests exercise actual private-server ownership/direct/INCR completion;
  display/editor tests preserve exact stored values while showing dangerous
  controls visibly. Real engine tests include the ordinary lifecycle flow.

## Native media and memory interpretation

The media driver creates a fresh encrypted vault containing an8 MiB generated
silent WAV and checked-in synthetic MP4/PNG fixtures. It verifies playback and
seek in audio/video, small-image rendering, the5000×4000 image's explicit-load
panel without an image element, close/reset, lock/reset and rejected new requests
using old capabilities. No URL/content is logged; stages and failure facts are
fixed numeric metadata. WAV generation and app range delivery are bounded.

Final controlled-runtime runs had summed process-tree RSS peaks748576 KiB and
685584 KiB. Earlier successful unsessioned runs peaked703072 KiB and686484 KiB. This includes application/WebKit processes and setup KDF memory;
it is **not** a claim that media plaintext occupies that amount, a renderer/GPU
memory ceiling or a guarantee of erased decoded buffers. Application-owned
prefix/range bounds are verified separately. Large-image consent avoids the
implicit80 MB RGBA lower-bound decode; ordinary audio/video use preload none.

Failed attempts are retained as evidence, not hidden: the original cleanup
assertion incorrectly required empty currentSrc. Native facts showed paused,
detached, no src, ready/network reset; WHATWG HTML issue10410 documents stale
currentSrc reporting. The assertion now checks actual decoder/network state and
new revoked-capability refusal. A subsequent run timed out at stage4; the driver
now uses a monotonic deadline and avoids the Audio constructor's implicit load
followed by a redundant explicit load. Two unsessioned runs passed, but a later
final-binary run also stalled at stage2 before playback. `pactl info` showed no
running audio service. The controlled private desktop runtime then passed twice
without a product change. This suggests the headless media-runtime setup was a
factor; it does not establish deterministic engine behavior, physical audio
output or erasure of engine-owned memory. Failed logs remain at
`/tmp/qv-0050-native-{facts,final,final-tree}/native.log`.

Two initial full-gate attempts stopped on setup/fixture errors: Xvfb was not
selected for CLI clipboard tests, and a CLI integration fixture directly called
history purge without a recovery policy. A core trash fixture also had an
invalid all-zero empty-content hash. Tests now use real verified recovery copies
and a correct empty-content hash; original state assertions are retained.

To repeat native media on the current tree:

```sh
cargo build --locked -p qv-app --features validation --bin qv-flow-harness
python3 plans/0050-complete-audit-remediation/run-media.py --private-runtime \
  --binary target/debug/qv-flow-harness --output /tmp/qv-0050-media-new-run
```

## Android continuation

```sh
eval "$(sh scripts/setup-android.sh --print-env)"
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export QV_DX=$PWD/crates/qv-app/dist/.build-cache/dx-0.7.10/bin/dx
QV_APP_DEVICE_VALIDATION=1 QV_APP_MEDIA_VALIDATION=1 \
  sh crates/qv-app/scripts/build-android.sh
python3 crates/qv-app/scripts/package-isolated-android.py --baseline validation \
  --uid org.quickvault.validation50
```

(The plan-local `package-media-android.py` was replaced by this generic
packager on 2026-11-14; outputs are now `quickvault-validation50-{debug,tests}.apk`.)

The packager builds only, checks identical native bytes, application/test IDs
and instrumentation target, and emits a disposable `org.quickvault.validation50`
pair. Never install the baseline `org.quickvault.app` validation APK over the
owner's ordinary app. When the phone returns, install only that isolated pair
and run `org.quickvault.app.MediaTest#testSyntheticMediaPlaybackSeekConsentAndRevocation`
through `org.quickvault.validation50.test/android.test.InstrumentationTestRunner`.
The test requires a fresh isolated fixture and uses only a fixed PASS/FAIL marker.
It is media compatibility evidence, not a hardware-keystore or independent audit.
Remove only the isolated packages afterward. No Android mixed-content policy
was weakened to infer compatibility; actual playback is still unverified.

The final isolated app APK is
`/var/tmp/qv-0050-android-q14lo8pu/project/app/build/outputs/apk/debug/app-debug.apk`,
SHA-256 `ff11459e55d1d568d291b592ec20b5687689229028f4eeaef82c60f9e9f8cd66`.
Its instrumentation APK is
`/var/tmp/qv-0050-android-q14lo8pu/project/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk`,
SHA-256 `d8925a14e72483439a48cc1fac8a7a4afa75cabd2d0891ce822487d08845f0a2`.
Temporary artifacts may be cleared; rebuild with the commands above if absent.
