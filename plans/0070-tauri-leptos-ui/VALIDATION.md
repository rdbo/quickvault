# Plan 0070 phase A — validation

Prototype: `prototypes/tauri-leptos/` (README there). Tauri 2.12.5, Leptos
0.8.23, wasm-bindgen 0.2.129, Rust 1.98.1. Linux runs: musl host,
WebKitGTK 2.48.7, private Xvfb with software rendering, debug builds.
Android: debug APK for arm64, built, not yet installed (no phone attached).

**Status: Linux passes; the go/no-go waits for the phone checklist below.**
Tests and these checks do not establish security (0012).

## Automated results (Linux)

| Step | Check | Result |
|------|-------|--------|
| A1 | Prototype builds for the host and wasm32; product `cargo metadata --locked` unchanged, `Cargo.lock` untouched | pass |
| A1 | `cargo deny check licenses` against the repo `deny.toml` | 8 crates outside the allow-list (below) |
| A2 | `cargo test --locked` in the prototype (17 tests: bounds, unknown fields/ops, duplicate keys, oversized secret, stale reference after lock, wrong-kind reference, old-generation request, idle lock and deferral, reveal expiry, media tokens revoked on close and lock, ranges, `416`/`404`/`405`/`403`, navigation allowlist) | pass |
| A2 | `cargo clippy --all-targets --locked -- -D warnings` (host), page for `wasm32-unknown-unknown`, backend for `aarch64-linux-android`; `cargo fmt --check` | pass |
| A2 | Real window: typed unlock, groups, entries, entry, Reveal, value masked again after 30 s, Copy through Rust with the clipboard countdown event, Lock clears the screen and inputs | pass (screenshots during the run) |
| A3 | CSP and bridge probe (below) | pass |
| A3 | No listening sockets (below) | pass |
| A4 | Idle lock with a 3 s test limit: activity reports keep it open, then it locks about 2.2 s after the last report; inputs cleared | pass |
| A6 | Mode B (`player.js` chunks) plays and seeks all five samples | pass |
| A6 | Mode A (`<video src="qvmedia://…">`) | fails on WebKitGTK: WEBKIT.md W13 |
| A7 | No media file in the WebKit processes' descriptors during playback | pass (only `memfd:WebKitSharedMemory`) |

### CSP and bridge probe (A3)

A script run in the page (debug-only `QV_PROTO_PROBE`) tried each of these;
every one was refused, and each CSP refusal raised a
`securitypolicyviolation`:

- `eval`, `new Function`, an inline `<script>`, a remote `<script src>`
- `fetch` to a remote URL and to `http://127.0.0.1:9/`, a remote image, a remote iframe
- `window.open`, and `location.href` to a remote page (the navigation guard kept `tauri://localhost`)
- Tauri commands not granted: `plugin:fs|read_file`, `plugin:window|close`, `plugin:event|emit`, an unknown command

The `qv` command answered raw bytes. Document CSP as served (Linux):

```
default-src 'none'; script-src 'self' 'wasm-unsafe-eval' <4 sha256 hashes>;
style-src 'self'; img-src 'self'; font-src 'self';
media-src 'self' qvmedia: http://qvmedia.localhost blob:;
connect-src 'self' ipc: http://ipc.localhost qvmedia: http://qvmedia.localhost;
object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'
```

The four hashes are Tauri's: it hashes every bundled `.js` file (our own
`app.js`, `boot.js`, `player.js`, the wasm-bindgen glue) into `script-src`.
That admits only those exact contents, which `'self'` already allows; phase B
decides whether to turn it off (`dangerousDisableAssetCspModification`).

### No listening sockets (A3)

The app hardens itself (non-dumpable), so even the same user cannot list its
descriptors; the check therefore compares the network namespace's listening
TCP, UDP and unix sockets before launch and after unlock, with media played.
A positive control (a Python listener on loopback) showed up in the same
comparison.

- New TCP/UDP listeners: **none**.
- New unix listeners: 4, each traced by inode to its owner: Xvfb (2), the
  D-Bus session bus that GLib autolaunched because the sandbox has none,
  and the AT-SPI accessibility bus. None belongs to the app, its
  `WebKitNetworkProcess` or `WebKitWebProcess`.
- The WebKit processes held only connected unix sockets (their IPC with the app).

### Media (A6)

`QV_PROTO_TRACE` showed every response at most 64 KiB, with no `416` or
`404` in normal playback. Seeks are by the player's slider.

| Sample | Mode A (src) | Mode B (chunks) |
|--------|--------------|-----------------|
| Short MP4 video, 4 s | `NotSupportedError` | plays; seek; MSE |
| Long MP4 video, 100 s, index at end | `NotSupportedError` | plays; seek to 70 s plays on; MSE |
| Long-GOP MP4, 12 s | `NotSupportedError` | plays; seek to 9 s; MSE |
| MP4 audio (AAC tone), 20 s | `NotSupportedError` | plays; seek to 15 s; MSE |
| WAV, 5 s | `NotSupportedError` | plays; seek; whole-file blob |

`player.js` needed one change: it asks for a whole range in one request (up
to 32 MiB) and rejected the scheme's shorter answers, so the prototype's copy
fetches in 64 KiB requests (`fetchRange`, `loadWhole`). Rust never holds more
than one 64 KiB piece of plaintext per request; the page assembles the range,
as it did before.

### Measurements (A7)

| What | Result |
|------|--------|
| Start to a drawn lock screen (includes creating the synthetic vault) | 0.69 s and 0.84 s; one run 6.4 s (outlier, not investigated) |
| Unlock (Argon2id, 256 MiB) to the groups list | 0.42–0.44 s |
| Memory after unlock (debug build) | app 207 MB, WebKitNetworkProcess 131 MB, WebKitWebProcess 248 MB |
| Page | 421 KB wasm (size profile) + 38 KB glue; `app.css`, `app.js`, `player.js` unchanged except `player.js` above |
| Android debug APK (Rust at opt-level 3, no debug info) | 30.5 MB of content: Rust library 15.4 MB, unminified dex 13 MB |

Not compared side by side with 1.1.1: that needs a second full build of the
shipped app. The phone's startup and memory are owner checks (nice to have).

## Licences (A1)

`cargo deny check licenses` with the repo `deny.toml` rejects 8 crates. All
licences are permissive; none can be avoided by turning off a feature:

| Crate | Licence | From | Product precedent |
|-------|---------|------|-------------------|
| cssparser 0.37.0, 0.38.0; cssparser-macros 0.7.1; selectors 0.38.0, 0.41.0 | MPL-2.0 | tauri-utils, build time (HTML handling) | same crates, older versions, plan 0030 |
| foldhash 0.2.0 | Zlib | tauri-utils (`dom_query`) | Zlib exceptions, plan 0030 |
| xxhash-rust 0.8.21 | BSL-1.0 | leptos → server_fn (always on) | none: new licence |
| base16 0.2.1 | CC0-1.0 | leptos → wasm_split_macros, build time | none: new licence |

Phase B adds exact-version exceptions with this table as the review; BSL-1.0
and CC0-1.0 are new licence kinds for the project. Full `cargo deny check`
(advisories, bans, sources) and `cargo vet` are phase B.

## Phone checklist (owner)

Install beside the real app (different ID, debug key):
`adb install prototypes/tauri-leptos/app/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk`.
The vault is synthetic: password `prototype`.

| # | Check | How | Result |
|---|-------|-----|--------|
| 1 | Unlock by typing with Gboard | type `prototype` in the password field | pending |
| 2 | Paste | long press in "Text field" and "Notes" → Paste | pending |
| 3 | Keyboard does not cover the focused field | focus Notes near the bottom | pending |
| 4 | Leave and return 20 times quickly, once during an unlock | recents/home and back | pending: no freeze, no delay, still unlocked |
| 5 | Screen lock locks at once; recents thumbnail blank | power button; recents | pending |
| 6 | Copy reaches the clipboard and clears after 30 s | Copy on the password; paste elsewhere | pending (the JNI `qvCopy` proof, A5) |
| 7 | Media: each sample in A and in B, play and seek | the Media card | pending; record which mode works |
| 8 | Back closes the open panel; at the root, twice leaves | system Back | pending |

Nice to have: TalkBack reads the lock screen; startup and memory compared with 1.1.1.

**Go** when 1–8 pass. A failure goes to the owner with the options (plan
stop conditions).

## Deviations from the plan (delegated)

- **Enums are externally tagged** (`{"unlock":{…}}`), not `tag = "op"`: serde
  decodes internally tagged enums through an untyped buffer, which would copy
  a password outside the zeroizing `Secret`. Secrets travel as arrays of byte
  values, so decoding leaves no unwiped copy from growth or unescaping.
- **No Trunk:** `build-ui.sh` runs cargo and wasm-bindgen 0.2.129. Trunk's
  output loads the wasm through an inline script, which the CSP forbids
  (0008 §4.2), and it is one tool fewer.
- **Synthetic vault created at first run** (one Argon2id create) instead of a
  copied fixture file; tests copy one vault per run.
- **`player.js`:** 64 KiB range fetching (above). **New fixture:** `tone.m4a`,
  as the app's fixtures carry audio at 1% amplitude.
- **Direct dependencies already in the lock:** `getrandom` 0.4.3 (references),
  and `jni` 0.21.1 on Android (wry's version; wry no longer re-exports it).
- **Android toolchain:** AGP 8.7.0 and Gradle 9.1.0 (the shipped app's), SDK
  35, minimum SDK 29; Tauri's own Android library is built against SDK 35.
- **Prototype profiles:** the product's dev overrides (crypto crates at
  opt-level 3); tests share the dev build, unlike the product (disk); a
  size-optimized `wasm` profile for the page.

## Found, for phase B

- **Android bridge bound:** on Android, Tauri's IPC uses `postMessage`; Tauri
  parses its JSON envelope (serde_json, depth-limited) before the command
  runs, so our 64 KiB check applies to the request bytes after that parse.
  Linux and Windows deliver the raw body. Spec 0008 §4.3 wording to settle.
- **Framework copies:** the raw request body and the encoded reply are owned
  by Tauri and are not wiped (0008 §4.4 best effort, as with wry today).
- **Android WebView settings:** the prototype applies the app's settings
  except `domStorageEnabled = false` and `mediaPlaybackRequiresUserGesture`,
  and keeps Tauri's `WebChromeClient` (permission and file-chooser refusal to
  be re-added in Tauri's terms).
- **CSP hashes** added by Tauri (above).
- **Mode A on Linux** (W13): Linux keeps mode B, as planned.
- `autocorrect="off"` is not a Leptos attribute method; set it with a
  generic attribute in phase D.
