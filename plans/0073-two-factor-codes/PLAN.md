# Plan 0073 — Two-factor codes people can find: setup sheet, scan, setup key, visible code

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Implemented — gates pass; phone scan check and fresh-context review pending | 2026-11-19 | 2026-11-19 (owner: "find a more reasonable approach, UX wise"; design delegated, standing 2026-11-02) | 0003 §5.4, 0009 §1.8 (entry editor and view), 0008 §1.1 |

## Intent

TOTP has worked since phase 1.5 (model, CLI, app), yet the owner, who
created the app, did not know it existed (2026-11-19). Today:

- the only way in is "Add a field", then the "Two-factor code" chip or the
  "One-time code" kind, and the field asks for an `otpauth://` link, which
  sites rarely show (they show a QR code and, under "can't scan?", a setup
  key);
- the entry view hides the code behind "Show code" with the 30-second
  reveal timer, not the code's own period.

Make two-factor codes a first-class part of a login, set up the way sites
present them, without changing the stored format.

## Findings

1. Storage is a `totp` field holding an `otpauth://totp/…` URI (0003
   §5.4); `qv_model::Totp::parse` accepts `otpauth://totp/?secret=KEY`
   with an empty label, so a setup key needs no format change (formats are
   frozen at 1.0).
2. The Android camera scan (`android::capture_qr`, decoded in Rust by
   `qr.rs`, bounded by `MAX_PAYLOAD`) serves only the LAN join and sync
   (`QrTarget`). An `otpauth://` QR is plain text in byte mode, which the
   same decoder returns.
3. `Session::totp` already returns the code and the seconds remaining.
4. Desktop has no camera path; the QR shows on the same screen as the site.

## Decisions (owner-delegated, standing 2026-11-02)

- D1 Where it lives. A login's editor shows a **Two-factor code** row
  under its fields, whether or not it is set up: "Set up" when empty, the
  live code with "Replace" when set (the field menu removes it). Other types reach the
  same row through "Add a field" → "Two-factor code" (the chip and the
  kind open the setup sheet instead of a raw value field). A login without
  a code shows nothing extra in the view.
- D2 The setup sheet: the steps the site shows, in its words.
  - "Scan the QR code" first where a camera scan exists (Android); it
    fills the sheet.
  - "Or enter the setup key": one input that takes the base32 key as
    sites print it (spaces, dashes, any case) or a pasted `otpauth://`
    link; Rust tells which.
  - Once the input is valid, the sheet shows the **current code** and its
    countdown, because sites finish setup by asking for one. Rust checks
    the input once typing pauses (the 400 ms pause of plan 0072), never per
    keystroke, and the page gets only "valid/invalid", the code and the
    seconds.
  - "More options" (closed by default, key only): digits 6/7/8, period
    30/60 s, algorithm SHA-1/SHA-256/SHA-512. A link carries its own.
  - "Add" stores `otpauth://totp/?secret=KEY[&digits=…][&period=…]
    [&algorithm=…]` built in Rust from the normalized key, or the link as
    given after it parses. Nothing else changes in the entry.
- D3 The start step recognizes a pasted `otpauth://` link as a login with
  a two-factor code: the issuer becomes the name and the account the
  username (both from the link's label/issuer, editable).
- D4 Viewing: a login's two-factor code shows **without a reveal tap**,
  grouped ("123 456"), with a ring for the code's own period; tapping it
  copies, as today. The setup key and link are never shown in the view; in
  the editor they stay a protected value behind its reveal. 0003 §5.4 is
  amended: `protected` covers the stored URI; the current code is derived,
  short-lived and shown while the entry is open. The page receives a new
  code each period and drops it on close, lock and hide, like other
  revealed values (0008 §1.1, best effort).
- D5 Not in this plan: reading a QR code on desktop (from the screen, a
  pasted screenshot or an image file), HOTP, Steam codes, importing from
  other authenticator apps. Recorded as follow-ups.

## Steps

1. Specs: 0003 §5.4 (code display; setup key stored as a URI), 0009 §1.8
   (the editor row, the sheet, the start-step link, the view), 0008 §1.1
   (the code in the page each period), with changelogs.
2. Rust: setup-key normalization and URI building next to `Totp::parse`
   (qv-model), with tests (spaces/dashes/case, padding, invalid
   characters, bounds, round trip through `parse`, RFC 6238 vectors).
3. Workspace: setup state (input, options, preview), the check on pause,
   add/replace/remove, the QR target `Totp` on Android; cleanup on close,
   lock and hide; tests.
4. Frame/API and page: the editor row, the sheet, the start-step
   recognition, the view's visible code with its ring; CSS.
5. Validation flow: set up from a key and from a link in the real
   WebKitGTK harness; the code shown matches RFC 6238 for the test key.
6. CHANGELOG, gates, execution log; phone check of the scan (owner).

## Test plan

Workspace gates; page Clippy for wasm32; app Clippy and tests with
`desktop` and `validation`; Android Clippy; the real-engine flow; phone
scan of a site QR by the owner.

## Risks and stop conditions

- Secret handling (setup key input, scan payload, codes in the page) needs
  the fresh-context review before release.
- Stop if a site's QR uses a form the parser refuses for a reason that
  would need a format change (for example a new URI scheme).

## Execution log

- 2026-11-19: plan written from the owner's report and a read of the
  editor, item view, `qr.rs`, `android.rs` scan and `qv_model::totp`.
- 2026-11-20 (steps 1–5): specs 0003 §5.4, 0008 §4.3, 0009 §1.8 amended
  (D1–D4). qv-model `Setup::from_input` (key as sites print it, or a link
  kept as given) and `link_names`, re-exported by qv-core with `Totp`,
  `KeyOptions` and `OtpAlgorithm`; `TotpNow` gains the period. App: the
  workspace's `TotpSheet` and input `TotpInput` (protected, 8 KiB bound),
  actions `TotpOpen`/`TotpCheck`/`TotpOptions`/`TotpAdd`/`TotpClose`; the
  link goes into the form as a protected replacement, so saving is
  unchanged. "Add a field" with the code kind or the "Two-factor code"
  name opens the sheet instead of adding an empty field. The start box
  takes a pasted link (`Start::Totp`). The QR target `Totp`: a scanned
  `otpauth://` link fills the sheet and is added at once; anything else is
  refused in the sheet and not kept. The camera decoder now accepts a UTF-8
  ECI header (some sites' links); other declared encodings are still
  refused and sync codes keep their own validation. The entry view and the
  editor compute codes in Rust each frame; `Live.code_tick` rebuilds frames
  once a second only while an entry or the sheet is open, and the page
  keeps codes in their own signal so the entry body is not rebuilt per
  tick (no flicker). The scan panel names the site's QR code.
- Found while testing (fixed): the page's 400 ms pause helper called
  `ui()` from a timer, outside any reactive owner, so `expect_context`
  panicked and nothing was sent. Plan 0072's live password meter therefore
  never updated in the app (its Rust tests drive the action directly). The
  helper now takes the page handle when the input is built. The real-engine
  flow now checks the meter (stage 21) and the two-factor setup (stages
  41–48).
- Tests: qv-model `setup_keys_as_sites_print_them`,
  `setup_links_are_kept_as_given_and_named`; qr
  `qr_utf8_marked_text_is_read_and_other_encodings_refused`; editor
  `a_login_sets_up_its_two_factor_code_from_a_setup_key`,
  `a_pasted_two_factor_link_starts_a_login_with_its_code`,
  `adding_a_two_factor_field_opens_its_setup_and_a_lock_drops_it`,
  `a_scanned_two_factor_link_is_added_and_other_codes_are_not_kept`.
  Follow-ups (D5): desktop QR from the screen or an image, HOTP, Steam,
  imports from other authenticator apps.
- 2026-11-20 (owner): the "More options" choices showed the arrow cursor
  and didn't change on hover, unlike the "More options" toggle above them,
  so they didn't look like buttons. Choice buttons (`.ie-seg`, which the
  editor's security choice also uses) now show the pointer cursor and a
  hover border.
- 2026-11-20 (owner): a row's right-click menu and copy menu list its
  two-factor code (`MenuField.code`; the page sends the existing
  `CopyKey::Totp`, so Rust copies the current code); a field that cannot
  make codes is left out. Spec 0009 §1.8 amended; the real-engine flow's
  stage 55 checks the menu item.
