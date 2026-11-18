# Tauri 2 + Leptos prototype (plan 0070, phase A)

A go/no-go prototype for moving the app UI from Dioxus to Tauri 2 and a
Leptos page, fully in process: no servers, no listening sockets. It is not
the product. It has its own Cargo workspace and lockfile, is excluded from
the product workspace, and opens only a synthetic vault (password
`prototype`, shown on its lock screen). Results: `plans/0070-tauri-leptos-ui/VALIDATION.md`.

| Path | What |
|------|------|
| `api/` | `qv-proto-api`: request, reply and event types; the bounded decode |
| `app/` | `qv-proto-app`: Tauri backend, the `qv` command, the `qvmedia` scheme, Android JNI glue |
| `ui/` | `qv-proto-ui`: the Leptos page (wasm32), with the app's `app.css` and `app.js` |
| `ui/static/player.js` | the app's `player.js`, changed to fetch media in 64 KiB ranges (see its "Plan 0070" notes) |
| `app/gen/android/` | Tauri's Android project; `MainActivity.kt` adapted from the app's |
| `app/fixtures/tone.m4a` | 20 s, 440 Hz synthetic AAC tone (below) |

## Build

Tools, pinned: Rust 1.98.1 with `wasm32-unknown-unknown`, `wasm-bindgen-cli`
0.2.129 and, for Android, `tauri-cli` 2.12.4 (each with `cargo install
--locked --version …`). Use low priority and two jobs; the target directory
grows by several GB per profile.

```sh
cd prototypes/tauri-leptos
sh build-ui.sh -j 2                      # the page, into ui/dist
CARGO_INCREMENTAL=0 cargo build -j 2 --locked -p qv-proto-app
./target/debug/qv-proto                  # Linux
CARGO_INCREMENTAL=0 cargo test -j 2 --locked
```

Debug builds only: `QV_PROTO_DATA=<relative dir>` moves the data directory,
`QV_PROTO_IDLE_MS` shortens the inactivity lock, `QV_PROTO_PROBE=<file.js>`
runs a test script in the page and prints titles starting with `PROBE `,
and `QV_PROTO_TRACE=1` prints each media request's range and status.

Android (debug key, application ID `org.quickvault.prototype`, installs
beside the real app):

```sh
eval "$(sh ../../scripts/setup-android.sh --print-env)"
export NDK_HOME=$ANDROID_NDK_HOME JAVA_HOME=/usr/lib/jvm/java-21-openjdk
export ANDROID_USER_HOME=$PWD/target/android-user CARGO_PROFILE_DEV_OPT_LEVEL=3 CARGO_PROFILE_DEV_DEBUG=0
cd app && cargo tauri android build --debug --target aarch64 --apk --ci
adb install gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk
```

The Android project uses the shipped app's toolchain (AGP 8.7.0, Gradle
9.1.0, compile and target SDK 35, minimum SDK 29) instead of the template's
AGP 9.3.1, which needs build tools 36.

## Fixture

`app/fixtures/tone.m4a`, made with FFmpeg 9.0.2:
`ffmpeg -f lavfi -i "sine=frequency=440:sample_rate=44100:duration=20,volume=0.2" -c:a aac -b:a 64k -movflags +faststart -map_metadata -1 -fflags +bitexact -flags:a +bitexact tone.m4a`.
SHA-256 `ff1c1998822bcf414f8a3dead03f09d1ba7195f358e81af385a6225384bc0138`.
The video samples are the app's own fixtures (`crates/qv-app/tests/fixtures`);
the WAV is generated at runtime.
