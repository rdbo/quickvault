# Known WebKitGTK limits

The Linux app renders in WebKitGTK 4.1 (2.48 when these were found) through
Tauri 2 (wry; plan 0071; the vendored dioxus-desktop until 1.2.0). Android
uses the Chromium WebView and Windows
uses WebView2; the entries below are WebKitGTK-only unless they say otherwise.

Each entry records what goes wrong, what QuickVault does about it, and what
to do if the engine or UI framework changes. None has been reported upstream
yet.

## When the framework or engine changes

Before a framework, webview or major UI change, go through every entry:

1. Re-test the symptom on the new engine with the entry's check.
2. If it is gone, remove the response (the code listed) and any Linux-only
   split, and update the spec and plan text the entry names.
3. If it remains, keep the response and carry the entry over.

Entries marked **Security** protect plaintext. Keep their protection until
the new engine is shown not to need it.

Whenever a new WebKitGTK bug, workaround or limit is found, add an entry here
(`AGENTS.md`, documentation duties).

## Entries

### W1. Playing media is buffered to disk (Security)

- **Symptom:** media played from an HTTP URL is buffered to an unlinked
  `WebKit-Media-*` file in `/var/tmp`, so decrypted attachment plaintext
  reaches the disk.
- **Response:** on Linux, previews play from renderer memory instead: MP4 as
  Media Source Extensions fragments rewritten from its own sample tables,
  other formats as a whole in-memory blob. Non-MP4 Linux previews are capped
  at 256 MiB (`PreviewTooLarge`). The CSP adds `blob:` to media-src and the
  `qvmedia` origin to connect-src.
  The fetch must send the explicit app origin (`tauri://localhost` on Linux,
  `src/bridge/media.rs`); an opaque `null` origin receives no CORS grant.
  Rechecked with WebKitGTK in plan 0065 (Dioxus) and plan 0071 (Tauri); do
  not broaden that grant to every opaque document.
- **Code:** `assets/player.js` (header, `loadBlob`, the MP4 fragmenter),
  the Linux branches of the viewer in `crates/qv-ui/src/items.rs`, the bound
  in `src/preview.rs`.
- **Docs:** 0003 §6.4, 0009 §1.8; plans 0057, 0059.
- **Check:** `run-media.py --check-media-files` (crates/qv-app README).
- **On change:** if the new engine streams HTTP media without a disk buffer
  (sample its descriptors, as the check does), Linux can use `src` like
  Windows and Android. The memory playback, the MP4 fragmenter and the
  256 MiB bound can then go. W2–W5 exist only because of this path.
  Recheck custom-scheme Origin serialization and actual memory playback too.

### W2. Blob playback of MP4

- **Symptom:** blob playback cannot play an MP4 whose index (`moov`) is at
  the end, and a replay after the end sticks.
- **Response:** MP4 streams through MSE (W1) instead of a blob.
- **Code:** `assets/player.js` (`streamMp4`, `playFromMemory`).
- **Docs:** plans 0057, 0059.
- **On change:** drops out with W1.

### W3. Slow sources and metadata preload stall

- **Symptom:** WebKit throttles a slow range source by cancelling and
  re-requesting ranges (33–47 requests for one file) and stalls at about
  0.1 s. With `preload="metadata"`, playback also stalled at about 6 s in 5
  of 8 runs, even from a plain local server.
- **Response:** ranges arrive fast enough: dev builds optimize the crypto
  crates, and a range read stops at a 64 KiB chunk boundary. Video uses
  `preload="auto"`.
- **Code:** dev profile overrides in the workspace `Cargo.toml`,
  `src/preview.rs` (range reads), `crates/qv-ui/src/items.rs` (preload
  attributes).
- **Docs:** plan 0057 *Diagnosis*.
- **On change:** re-test `preload="metadata"`; it would avoid loading video
  before Play.

### W4. Replay after the end skips video

- **Symptom:** WebKitGTK's retained MSE decoder can skip the first group of
  pictures on replay after the end.
- **Response:** replay, and a backward seek after the end, rebuild the
  MediaSource from the still-live preview route instead of seeking the
  ended source.
- **Code:** `assets/player.js` (`toggle`, the seek `change` handler).
- **Docs:** 0003 §6.4 ("explicit replay or backward seek after the end"),
  plan 0057.
- **On change:** if the new engine replays correctly, use an ordinary
  `currentTime = 0`.

### W5. MSE buffer faults

- **Symptom:** the decoder presents no frames after its buffer is emptied
  and refilled. A seek made before any media data buffers nothing. A seek
  into a gap at the start stalls.
- **Response:** a seek outside the buffered data rebuilds the MediaSource at
  the target. The start position is set after the first window, one second
  early (B-frames). The fragmenter starts each track at 0, so an edit
  list's few milliseconds of encoder delay are not applied.
- **Code:** `assets/player.js` (`restart`, `streamMp4`, `fragmentMp4`).
- **Docs:** plan 0059 (step 8).
- **On change:** drops out with W1; otherwise re-test seeks outside the
  buffer by counting presented frames.

### W6. Native video full screen draws black

- **Symptom:** the element's own full screen shows a black picture.
- **Response:** WebKit full screen is disabled; the video button makes the
  whole window full screen instead.
- **Code:** `set_enable_fullscreen(false)` in `src/bridge/webkit.rs`; the
  viewer's full-screen button in `crates/qv-ui/src/items.rs`.
- **Docs:** 0009 §1.8, plan 0057.
- **On change:** use element full screen, as Android already does.

### W7. Web Audio routing drops and delays sound

- **Symptom:** an `AudioContext` starts only inside a user gesture, and an
  element routed into a suspended context refuses to play. Routing a media
  element through `MediaElementAudioSourceNode` skips about 1 s of sound
  when routing starts and adds about 0.8 s of silence after each unpause.
  Routing before the first play gives mostly silence. Suspending and
  resuming the context leaves an MSE source silent until the next seek.
- **Response:** Linux does not route. The audio card's bars loop while
  playing instead of following the sound; Android routes.
- **Code:** `routeAudio` in `assets/player.js` (only CORS sources route).
- **Docs:** 0003 §6.4, 0009 §1.8, plan 0061, `CHANGELOG.md`.
- **Check:** record the audio sink's monitor while a chirp plays and decode
  the heard position from its pitch (plan 0061). Reading levels or
  `currentTime` alone hid the fault.
- **On change:** if the heard output stays continuous, let blob/MSE sources
  route and the bars follow the sound on Linux.

### W8. Stale `currentSrc`

- **Symptom:** after `src` is removed, WebKit keeps reporting the old
  `currentSrc` (WHATWG html issue 10410).
- **Response:** tests check the actual reset states and refuse a closed
  route, instead of reading `currentSrc` as evidence of playback.
- **Docs:** plan 0050 (execution log, 2026-11-10).
- **On change:** nothing to remove. Keep the tests engine-neutral.

### W9. Clicking a button does not focus it

- **Symptom:** WebKit does not focus buttons on click, so keys reach a pane
  only while focus is already inside it.
- **Response:** Escape and similar shortcuts live at the root, with the list
  selection in `Workspace::selection`.
- **Docs:** plan 0044 (step 4).
- **On change:** keep. The root shortcuts work on every engine.

### W10. Blur layer teardown repaints (unconfirmed)

- **Symptom:** removing a `backdrop-filter` blur layer can repaint the page
  under it. Not confirmed on the owner's machine.
- **Response:** the preview backdrop is plain and near-opaque.
- **Docs:** plan 0044.
- **On change:** blur can be tried again, watching for flicker.

### W11. Mute takes effect late without a PulseAudio server

- **Symptom:** the sound continues for about 0.5 s after mute (about 0.2 s
  late on unmute), while pause is instant. Seen on a desktop running native
  PipeWire without `pipewire-pulse`, where mpv (native PipeWire output)
  mutes instantly.
- **Cause (reproduced):** WebKit's `autoaudiosink` tries `pulsesink` and,
  with no PulseAudio server, falls back to `alsasink` (into PipeWire through
  the ALSA plugin). Mute is applied ahead of ALSA's larger output buffer;
  pause stops the output itself. Private-session probe, heard position
  decoded from a recorded chirp: no PulseAudio server, mute pressed at
  2.00 s, sound until 2.3 s; with `pipewire-pulse` (`pulsesink`), or with
  `pipewiresink` forced, within 0.1 s, for both MP3 blob and M4A MSE
  playback.
- **Response:** none in the app. Running `pipewire-pulse` makes WebKit use
  `pulsesink`; the owner confirmed mute is then immediate. An app-wide
  `GST_PLUGIN_FEATURE_RANK=pipewiresink:MAX` would prefer PipeWire's own
  sink, whose upstream rank is deliberately low; not adopted without a
  full media qualification.
- **Docs:** `CHANGELOG.md` (2026-11-15).
- **On change:** check mute against pause with no PulseAudio server.

### W12. Caps Lock indicator in password fields

- **Symptom:** WebKitGTK draws a black up-arrow inside a focused password
  field while Caps Lock is on, out of place on the dark theme and absent
  on the other engines.
- **Response:** hidden with `::-webkit-caps-lock-indicator`; `app.js`
  tracks Caps Lock from key and pointer events and the app shows its own
  hint (a "Caps Lock" pill in the unlock field, "Caps Lock is on" under form
  fields) on every platform with a hardware keyboard.
- **Docs:** plan 0062, `CHANGELOG.md`.
- **On change:** keep the app's hint; drop the WebKit rule if unused.

### W13. Media elements cannot load a custom URI scheme

- **Symptom:** an `<audio>`/`<video>` whose `src` is an app-registered
  scheme (the plan 0070 prototype's `qvmedia://localhost/<token>`, served by
  Tauri's in-process scheme handler) fails at once with `NotSupportedError`
  (`MediaError` code 4). The engine makes one ranged request (`bytes=0-1445`,
  no Origin) and then gives up, for MP4 video, MP4 audio and WAV alike.
  `fetch()` from the page to the same URL works. Found with WebKitGTK 2.48.7
  in the plan 0070 prototype; it applies to the app since plan 0071 moved
  previews to the same scheme.
- **Response:** none needed: Linux already plays previews from renderer
  memory (W1), and that path fetches through the scheme (64 KiB per request,
  as the scheme answers) and works.
- **Code:** `assets/player.js` (`fetchRange`, `loadWhole`).
- **Docs:** plan 0070 (step A6, `VALIDATION.md`), plan 0071.
- **On change:** if a later engine plays custom-scheme `src`, it still
  needs W1's disk check before Linux may use it.

## Testing method

Real-engine checks run on a private X server, with a private D-Bus and
PipeWire session and a null sink (`run-media.py --private-runtime`), with and
without `--compositing`. Media checks count presented frames
(`requestVideoFrameCallback` / `getVideoPlaybackQuality`), never only
`currentTime`, and audio checks record the sink (W7).

Related, not WebKit: the Wayland clipboard goes through GTK (plan 0055); a
framework change must re-check it too.
