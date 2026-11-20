# Plan 0071 — dependency record

Decision basis: owner decision 2026-11-17 (Tauri 2 + Leptos, plan 0070),
delegated choices under the standing delegation of 2026-11-02. Licences were
checked against `deny.toml` when the prototype was planned (plan 0070
VALIDATION.md); this file records what the product tree now contains.

## Direct dependencies added

| Crate | Version | Where | Why |
|-------|---------|-------|-----|
| tauri | =2.12.5, `default-features = false`, `wry` | qv-app (`desktop`) | Window, webview, the one IPC command, the in-process `qvmedia` scheme |
| tauri-runtime | =2.12.3 | qv-app (`desktop`) | `ResizeDirection` for the title bar's edge handles (not re-exported by tauri) |
| tauri-build | =2.7.4 | qv-app build script | Embeds the page and generates the command manifest and capabilities |
| jni | =0.21.1, no default features | qv-app (Android) | The JNI calls `android.rs` makes on the activity (previously through Dioxus) |
| serde, serde_json | =1.0.229, =1.0.154 | qv-ui-api, qv-app, qv-ui | Strict decoding of requests (`deny_unknown_fields`) and frame encoding |
| leptos | =0.8.23, `csr` only | qv-ui (wasm32) | The page |
| wasm-bindgen, wasm-bindgen-futures, js-sys, web-sys | =0.2.129, =0.4.79, =0.3.106, =0.3.106 | qv-ui (wasm32) | Browser bindings; `wasm-bindgen-cli` 0.2.129 must match |

`getrandom` and `zeroize` were already workspace dependencies.

Tools (not in the lockfile): tauri-cli 2.12.4 (Android packaging) and
wasm-bindgen-cli 0.2.129 (`crates/qv-ui/setup-tools.sh`), both pinned in CI.

Android build: the Tauri project in `crates/qv-app/gen/android` carries the
Gradle wrapper jar from Tauri's template, SHA-256
`497c8c2a7e5031f6aa847f88104aa80a93532ec32ee17bdb8d1d2f67a194a9c7`, which is
Gradle's published wrapper checksum for 9.6.1 (checked against
services.gradle.org). It downloads Gradle 9.1.0, now pinned by
`distributionSha256Sum` (Gradle's published SHA-256 for
`gradle-9.1.0-bin.zip`). AGP 8.7.0, as the Dioxus build used.

## Removed

Dioxus 0.7.10 and its tree, the vendored `third-party/dioxus-desktop`, and the
Dioxus CLI. `cargo vet regenerate exemptions` dropped 158 exemptions that no
longer match the tree (the Dioxus crates, muda/global-hotkey, libxdo,
appindicator, image decoding, the older wry/webkit2gtk and others).

## Licences (`deny.toml`, exact versions)

- MPL-2.0: `cssparser` 0.37.0 and 0.38.0, `cssparser-macros` 0.7.1,
  `selectors` 0.38.0 and 0.41.0 — Servo's CSS crates under `dom_query`, which
  tauri-utils uses at build time and wry for HTML handling.
- Zlib: `foldhash` 0.2.0 (dom_query).
- BSL-1.0: `xxhash-rust` 0.8.21 (Leptos `server_fn`, compiled though the page
  uses no server functions).
- CC0-1.0: `base16` 0.2.1 (Leptos wasm-split macro helper).

All are compatible with distribution under AGPL-3.0-or-later. Exceptions for
crates that left the tree (selectors 0.24, cssparser 0.29, libloading 0.7,
rustls-webpki, untrusted) were removed.

## Advisories

- RUSTSEC-2024-0436 `paste` (unmaintained, no vulnerability): a compile-time
  macro helper of Leptos. Ignored with that reason.
- RUSTSEC-2026-0543 `chrono` (unmaintained, no vulnerability): a newly
  published advisory, not introduced here. zxcvbn 3.1.1 depends on chrono only
  for `target_arch = "wasm32"`, and QuickVault never builds `qv-core` for
  wasm32 (`qv-ui` does not depend on it), so it never ships. Ignored with that
  reason; it applies to 1.1.1 as well.
- The glib 0.18 advisories stay: Tauri's GTK3 stack pins glib 0.18 as Dioxus's
  did. The fxhash and rand 0.7 ignores were removed (no longer in the tree).

## cargo vet

204 exact-version development exemptions were added for the Tauri and Leptos
trees, each noted "Plan 0071 … not an audit; review remains release debt under
specs/0012 section 3". `cargo vet --locked`: 74 fully audited, 8 partially
audited, 526 exempted. The fuzz lockfile was re-resolved for `jni` (the fuzz
workspace depends on qv-app) and `bytes` pinned to the product's 1.12.1, so
`scripts/check-supply-chain.py` passes.

## Security-relevant notes

- tauri's default features are off: no `compression`, no plugins. The only
  capability (`capabilities/main.json`) grants the app's own `qv` command.
- No server feature of Leptos is enabled (`csr` only); `server_fn` is compiled
  as part of the crate but no server function exists and nothing listens.
- The page has no access to vault data beyond what a frame shows; see the
  0008 §4 amendment and `ARCHITECTURE.md` §3.
