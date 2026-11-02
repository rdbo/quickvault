# Plan 0034 — Android autofill (roadmap 2.7)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Approved | 2026-11-02 | 2026-11-02 | 0009 §4 (amended here); 0008 §3, §4; 0002 §5; 0003 §5; 0012 §3 |

## Intent

Let QuickVault fill logins in other Android apps and trusted browsers. A fill
happens only for a verified app signing identity or an exact web origin, and
only after the user unlocks in the shared Dioxus app and explicitly chooses a
credential. Keep the feature disabled on unvalidated devices, as for quick
unlock in 2.6.

## Scope

**In scope:**
- Spec amendment: 0009 §4.4, the Android autofill profile (identity formats,
  trusted browsers, handoff channel, gating).
- `qv-platform::autofill`: bounded request identity, stored-identity parsing,
  exact matching and an empty trusted-browser allowlist.
- `qv-core` candidate enumeration, explicit fill values and app linking through
  the existing edit path.
- Kotlin glue: `QvAutofillService`, non-exported `AutofillAuthActivity`, an
  in-process request registry, manifest/res entries and build-script copying.
- Rust Android bridge: polling, bounded fetch, completion/cancel.
- App state and the shared autofill screen.
- Host tests, instrumentation and VALIDATION.md.
- Carry-over 0033 REVIEW finding 1: do not hold the quick-unlock policy mutex
  across the native prompt.

**Out of scope:**
- Digital Asset Links (needs a network fetch; see decision 2).
- Save requests (`onSaveRequest`) and inline keyboard suggestions.
- Credential Manager provider, iOS, Linux/desktop autofill.
- A fill that skips the main app's unlock/choice screen.
- Partial-origin matching (subdomain, eTLD+1).
- Any vault format change, dependency, `unsafe` or new primitive.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Rust-owned matching/fill; thin OS glue | 0009 §4.2 | Draft | go-ahead delegated (decision 1) |
| Handoff to main-app unlock; authenticated scoped channel; verified identity; conflicted choice | 0009 §4.3 | Draft | same |
| Android identity formats, trusted browsers, gate | 0009 §4.4 (new) | Draft | amended in step 1 |
| Match verified identity, not labels/substrings; choose conflicted credentials | 0008 §3 Autofill row | Accepted (D5) | |
| Secret containers and webview/framework limits | 0008 §1.1, §4.4 | Accepted | |
| Entry fields/kinds; templates are UI conventions | 0003 §5, §5.2 | Accepted | identities are `url` fields, no model change |
| Validate verified autofill matching per platform; keep unvalidated disabled | 0012 §3 | Accepted | |

**Spec changes required:** 0009 §4.4 plus a Changelog line, and an Android note
on Open Question 2 (step 1). 0009 stays Draft. No other spec changes.

## Decisions needed

None pending. All were chosen under the owner's standing delegation of
2026-11-02 ("dont ask me to approve stuff, just pick whatever is the best
option"). That delegation also covers the roadmap stop conditions this plan
triggers: a spec amendment, a Draft spec and a deviation from the phase entry.

1. **Implement Draft 0009 §4.** Chosen: yes, with the §4.4 amendment as
   normative text. Rejected: waiting for owner acceptance (delegated).
2. **Digital Asset Links.** Chosen: defer. DAL needs fetching
   `https://<domain>/.well-known/assetlinks.json`, which is a remote-network
   feature in an offline-first app whose `INTERNET` permission exists only for
   renderer loopback. A hostile network could also influence the fetched
   association. Instead:
   - app requests match explicit, user-linked package + signing-certificate
     identities, verified via PackageManager;
   - web requests match exact origins reported by allowlisted browsers.

   Rejected: (a) DAL fetch now (network feature, threat-model change);
   (b) `DomainVerificationManager` (reports only the caller's own package state).
   Logged as a roadmap Revision.
3. **Web origin trust.** A web domain in a `ViewNode` is whatever the requesting
   app claims. Chosen: trust it only from allowlisted browsers, pinned by
   package plus the exact signing-certificate SHA-256 set. The compiled
   allowlist starts **empty**. Entries are added only from digests read on a
   validation device and recorded in VALIDATION.md, never from memory or
   documentation. Rejected: trusting any app's web domain (spoofable by any
   WebView); a user-editable browser list (extra persistent state; later).
4. **Origin matching.** Chosen: exact `(scheme, host, port)`, scheme `https` or
   `http` matched exactly, ASCII hostnames only. Rejected:
   - subdomain/eTLD+1 matching (needs a Public Suffix List dependency, widens trust);
   - IDN conversion (dependency);
   - IPv6 literals (rare; parser surface).
5. **App identity storage.** Chosen: a `url`-kind field with value
   `androidapp://<package>#sha256=<hex>[,<hex>…]`, a client convention under
   0003 §5.2, created by an explicit, confirmed "link this app" action that uses
   OS-verified values. An identity without a digest set never matches.
   Rejected: a new record type or setting (model change); package-only matching
   (spoofable by sideloading).
6. **Handoff channel.** Chosen: one in-process Kotlin registry holding a single
   pending request with a 128-bit random token and 120-second TTL. Pieces:
   - immutable explicit PendingIntent to a **non-exported** `AutofillAuthActivity`;
   - Rust polls the registry in-process;
   - the result is written back to the registry and consumed once by the auth
     activity, which re-verifies the requester's signing digests before
     building the Dataset.

   Rejected: intent extras carrying identity or results (forgeable, since
   MainActivity is exported); a second Dioxus activity instance (breaks the
   single Rust bridge).
7. **MainActivity launch mode.** Chosen: `singleTask`, so the handoff can never
   create a second Rust-bridged activity. Existing PlatformTest/QuickUnlock
   instrumentation must still pass.
8. **Fill-value selection.** Chosen, deterministically:
   - username = first field whose name ASCII-case-insensitively equals
     `username`, `user name`, `email`, `e-mail` or `login`, else the first
     `email` kind, else the first `text` kind;
   - password = first field named `password`, else the first `secret` kind.

   Only roles the request contains are filled. Rejected: heuristics on titles.
9. **Mutex carry-over (0033 REVIEW 1).** Chosen: reserve the attempt, copy the
   envelope, release the mutex for the native call, then reacquire and account
   only if the same enrollment (a slot serial) is still present. Otherwise
   discard the plaintext and return `Cancelled`.

## Design

**Components touched:**
- `qv-platform` (`autofill`, `quick_unlock`): trusted Rust policy.
- `qv-core` (`autofill`): session reads plus the existing edit path.
- `qv-app` (`android.rs`, `controller.rs`, `autofill.rs`, `ui/autofill.rs`): app
  trust boundary.
- Kotlin glue (`android/AutofillService.kt`, `android/AutofillAuthActivity.kt`,
  `android/res/xml/autofill_service.xml`, manifest): OS entry points; no matching
  logic.
- `scripts/build-android.sh`: packaging.

**Interfaces (sketch):**

```rust
// qv-platform/src/autofill.rs
pub const MAX_PACKAGE: usize = 255;      // [A-Za-z0-9_.], ≥2 segments
pub const MAX_SIGNERS: usize = 8;        // SHA-256 digests, 32 bytes each
pub const MAX_HOST: usize = 253;         // labels 1..=63, [a-z0-9-], no edge '-'
pub const MAX_IDENTITY_FIELD: usize = 1024; // stored url value considered at all
pub const MAX_FILL_VALUE: usize = 8 * 1024;
pub const REQUEST_TTL: Duration = Duration::from_secs(120);

#[derive(Clone, PartialEq, Eq)] pub struct PackageName(String); // validated
#[derive(Clone, PartialEq, Eq)] pub struct SignerSet(Vec<[u8; 32]>); // sorted, dedup, 1..=8
#[derive(Clone, Copy, PartialEq, Eq)] pub enum Scheme { Https, Http }
#[derive(Clone, PartialEq, Eq)] pub struct Origin { scheme: Scheme, host: String, port: u16 }
pub struct AppIdentity { pub package: PackageName, pub signers: SignerSet }
pub struct TrustedBrowser { pub package: &'static str, pub signers: &'static [[u8; 32]] }
pub const TRUSTED_BROWSERS: &[TrustedBrowser] = &[]; // device-validated only

/// OS-verified requester plus an optional browser-claimed origin.
pub struct FillRequest { pub app: AppIdentity, pub web: Option<Origin>, pub roles: Roles }
#[derive(Clone, Copy)] pub struct Roles { pub username: bool, pub password: bool }
pub enum Requester { App(AppIdentity), Web { browser: AppIdentity, origin: Origin } }
pub enum StoredIdentity { App(AppIdentity), Web(Origin) }

impl Origin { pub fn parse_stored(url: &[u8]) -> Option<Origin>; // https?://host[:port][/path…]
              pub fn from_request(scheme: &str, host: &str, port: Option<u16>) -> Option<Origin>; }
impl StoredIdentity { pub fn parse(url: &[u8]) -> Option<StoredIdentity>; } // androidapp:// or http(s)://
impl FillRequest {
    pub fn new(package: &str, signers: &[[u8; 32]], web_scheme: Option<&str>,
               web_host: Option<&str>, roles: Roles) -> Result<Self, PlatformError>;
    /// Web only when `app` is a trusted browser (exact package + signer set);
    /// an untrusted app's claimed origin is ignored, never "best effort".
    pub fn requester(&self, trusted: &[TrustedBrowser]) -> Requester;
}
pub fn matches(requester: &Requester, stored: &StoredIdentity) -> bool; // exact only

// qv-core/src/autofill.rs
pub struct FillCandidate { pub entry: EntryHandle, pub version: VersionHandle,
    pub title: Text, pub username: Option<Text>, pub conflicted: bool } // redacted Debug
pub struct FillValues { pub username: Option<SecretBytes>, pub password: Option<SecretBytes> }
impl Session {
    /// Live (not trashed) entries whose url fields match. A conflicted entry
    /// yields one candidate per head and is flagged; no default is chosen.
    pub fn autofill_candidates(&self, request: &Requester) -> Result<Vec<FillCandidate>, CoreError>;
    /// Re-checks that this exact head still matches before decrypting values.
    pub fn autofill_values(&self, request: &Requester, c: &FillCandidate, roles: Roles)
        -> Result<FillValues, CoreError>;
    /// Adds `androidapp://…` through edit_entry/add_field/save_entry; App only.
    pub fn link_app(&self, entry: EntryHandle, app: &AppIdentity) -> Result<EntryHandle, CoreError>;
}
```

`autofill_candidates` refuses (`NotAllowed`) on read-only sessions only for
`link_app`. Reads are allowed on read-only sessions. Rotation-pending or
locking sessions follow existing `read`/`mutate` checks.

**Data and control flow:**

1. `QvAutofillService.onFillRequest` (Kotlin), in order:
   - Gate: `AutofillGate.enabled` false (normal builds; fingerprint allowlist
     empty) → `onSuccess(null)`.
   - Read `activityComponent.packageName` from the **last** fill context (set
     by the system, not the app). Skip our own package.
   - Signing digests: `PackageManager.getPackageInfo(pkg, GET_SIGNING_CERTIFICATES)`
     → `signingInfo.apkContentsSigners` (multiple signers: all of them) →
     SHA-256 each. Bound to 8; on failure, `onSuccess(null)`.
   - Traverse at most 512 nodes, depth 64, and collect the first username and
     first password `AutofillId`. Detection uses `autofillHints`
     (`username`/`emailAddress`/`password`) or password `inputType`
     variations. The first non-null `webDomain`/`webScheme` (API 28+) of a
     detected node gives the claimed origin; `webScheme == null` → no origin.
   - No detected field → `onSuccess(null)`.
   - Register `PendingRequest{token(16 random bytes), id(Long), package,
     digests, scheme, host, port, ids, created=elapsedRealtime}`. This replaces
     any previous request; the old one is cancelled and its result zeroed.
   - Respond with `FillResponse.setAuthentication(ids, intentSender,
     presentation)`. The `PendingIntent.getActivity` targets
     `AutofillAuthActivity` explicitly with `FLAG_IMMUTABLE |
     FLAG_CANCEL_CURRENT`; its only extra is the token. The presentation is the
     fixed text "Unlock QuickVault to fill" (no titles, usernames or counts).
     No `SaveInfo`.
2. `AutofillAuthActivity` (non-exported, translucent, no UI):
   - `onCreate`: token must equal the registered one, not expired and not yet
     claimed; otherwise `RESULT_CANCELED`/finish. Mark it claimed (one-shot),
     then start MainActivity with the launcher intent plus `NEW_TASK`. No
     request data travels in that intent.
   - Its first `onResume` after the launch reads the registry: if
     `state == Completed` for this token, it re-reads the requester's signing
     digests (they must equal the registered set) and builds a `Dataset` with
     `AutofillValue.forText` only for the registered ids and returned roles.
     Then `setResult(RESULT_OK, EXTRA_AUTHENTICATION_RESULT)`, zero the byte
     arrays and finish. Anything else → cancel the request, `RESULT_CANCELED`,
     finish.
3. Rust polling thread (existing 100 ms loop in `android.rs`):
   - `qvAutofillPending()` returns a new claimed request id or 0. Fetch it with
     bounded getters, then `FillRequest::new(...)`; invalid → `qvAutofillCancel(id)`.
   - Deliver to `Controller::autofill_offer(request, id)`, which replaces any
     unbound request.
   - An unbound request survives locks until `REQUEST_TTL`, since it usually
     arrives while locked; no vault data is involved before unlock.
   - On unlock with an unbound, unexpired request, the workspace opens
     `Screen::Autofill`, binding the request to the current `lock_gen`.
   - `State::invalidate` (any lock, background expiry, screen-off, protection
     loss) drops a **bound** request and calls `qvAutofillCancel`.
4. Autofill screen (shared Dioxus):
   - Shows the requester (package, plus origin and browser for web), labelled
     "verified signer".
   - Lists candidates: title and non-protected username. Conflicted entries
     list each head separately and require choosing one; there is no
     preselection.
   - **Fill** → `autofill_values` on the worker → `qvAutofillComplete(id,
     user, pass)` → `Completed` result in the registry → `moveTaskToBack(true)`.
     The vault then locks by the normal background rule.
   - **Cancel** → `qvAutofillCancel`.
   - For app requests with no match: "Link this app to an entry…" → existing
     search picker → `ConfirmKind::LinkApp`, warning "QuickVault cannot tell
     whether this app belongs to the service; link only an app you trust", with
     package and digest prefixes shown → `link_app` → candidates refresh → an
     explicit Fill is still required.
5. Every action is epoch- and lock_gen-checked. A late worker result after a
   lock is dropped (existing `run_op`), and the request is cancelled.

`link_app` is the only write. It uses the existing `save_entry`
transaction/anchor ordering (0004 §5, 0005 §5.4); no new write path.

**Secrets and hostile input:**
- The request is untrusted until validated in Rust:
  - package charset/length;
  - signer count 1..=8, exactly 32-byte digests (Kotlin passes `n*32` bytes;
    Rust checks the length before copying);
  - host charset/labels/length and port 1..=65535.
- Stored url values longer than `MAX_IDENTITY_FIELD` are ignored.
  `androidapp` parsing requires the exact `#sha256=` form: lowercase hex,
  64 characters per digest, comma separated, at most 8. Anything else is
  `None` (never matches).
- `http(s)` parsing rejects userinfo (`@` before the path), empty or non-ASCII
  hosts, trailing dots, percent-encoding in the host and bad ports. Lowercase
  ASCII hosts; default ports 443/80.
- Fill values are `SecretBytes`, bounded at `MAX_FILL_VALUE` (larger →
  `InvalidInput`, nothing filled). They cross JNI as byte arrays; Kotlin zeroes
  its arrays after building the `Dataset`. `AutofillValue`/`String` and
  framework or target-app copies are best-effort limits (0008 §4.4), documented
  in the README.
- Nothing secret is in the FillResponse presentation, logs, exceptions or
  intents. Titles/usernames appear only inside the FLAG_SECURE app.
- Matching never inspects titles, labels, activity names or URL substrings.

**Errors:** fixed `PlatformError`/`CoreError` categories. The UI shows "No
matching entry for this verified identity", "Autofill request expired" and
"Autofill cancelled because the vault locked". Kotlin never logs exception
messages.

**Mutex carry-over:** add a `serial: u64` to `Slot`, incremented per
enrollment. `unlock_bound`:
1. Lock, validate, `failures += 1`, copy the envelope into a new `SecretBytes`,
   unlock.
2. `backend.open(...)`.
3. Relock. If the slot is absent or its serial differs, drop the plaintext and
   return `Cancelled`. Otherwise apply the existing success/failure/destroy
   rules.

`binding()` then never waits for a prompt.

**Dependencies:** none. SHA-256 of certificates uses Android `MessageDigest` in
the glue. Rust compares digests only.

## Steps

### Step 1 — Spec amendment 0009 §4.4 and roadmap record
- [x] **Do:** Add 0009 §4.4 "Android profile" stating:
  - the `androidapp://<package>#sha256=…` and exact `http(s)` origin
    conventions;
  - app identity = system activity package + full current signer set;
  - web origins trusted only from allowlisted browsers pinned by signer set,
    with the allowlist populated only from device-validated digests;
  - no partial or subdomain matching; DAL deferred (network);
  - the non-exported, one-shot, TTL-bounded handoff with re-verification;
  - explicit choice, including conflicted heads; a bound request is cancelled
    by lock;
  - disabled unless the device is validated.

  Add an Android note under Open Question 2 and a Changelog line ("owner
  standing delegation 2026-11-02"). Update the `specs/README.md` index row if
  it carries a summary. Add a dated roadmap Revision covering the DAL deferral
  and the spec amendment.
- **Files:** `specs/0009-clients-and-platforms.md`, `specs/README.md`, `plans/0002-roadmap/PLAN.md`.
- **Done when:** the spec text covers every behaviour in this plan's Design; status stays Draft.
- **Verify:** `sh scripts/check-spdx.sh` (docs only).

### Step 2 — Quick-unlock mutex carry-over
- [x] **Do:** Implement the serial-based release/reacquire in
  `AndroidKeystore::unlock_bound` as designed. Add tests with a blocking fake
  backend (a channel-gated `open`):
  - `binding()` returns while `open` is blocked;
  - `invalidate()` or a re-`enroll` during `open` makes the result `Cancelled`,
    discards it and does not touch the new slot's failure count;
  - the three-failure and permanent-loss rules are unchanged.
- **Files:** `crates/qv-platform/src/quick_unlock.rs`.
- **Done when:** the new and existing quick tests pass; no new public API.
- **Verify:** `cargo test --locked -p qv-platform quick`; `cargo test --locked -p qv-core quick`.

### Step 3 — Platform identity parsing and matching
- [x] **Do:** Create `qv-platform::autofill` per the sketch, re-exported via
  `qv-core::platform`. Tests:
  - exact origin match;
  - subdomain, parent-domain, `bank.com.evil.com`, `evilbank.com` and
    `bank.com@evil.com` all refused;
  - scheme/port mismatch, default-port equivalence and case normalization;
  - non-ASCII, trailing-dot and percent-host refusals;
  - custom schemes (`bank://`, `android-app://`, `intent://`) never parse;
  - `androidapp` without a digest, with uppercase hex, with a bad digest length
    or more than 8 digests → `None`;
  - same package with a different signer set, or a subset/superset → no match;
  - an untrusted app claiming an origin → `Requester::App`, so stored web
    identities never match;
  - a trusted browser with an exact signer set → `Web`;
  - every `FillRequest::new` bound.

  Tag the spoofing tests `// 0012 §1: Hardware assumptions` only if
  `check-matrix` accepts them; otherwise leave them untagged (there is no
  autofill row in `tests/matrix-offline.txt`).
- **Files:** `crates/qv-platform/src/{lib,autofill}.rs`, `crates/qv-core/src/platform.rs`.
- **Done when:** label, substring and custom-scheme spoof cases are refused in
  host tests; the allowlist is empty.
- **Verify:** `cargo test --locked -p qv-platform autofill`.

### Step 4 — Core candidates, values and app linking
- [x] **Do:** `qv-core/src/autofill.rs` per the sketch:
  - iterate live entries (exclude trash/deleted), parse each `url` field with
    `StoredIdentity::parse` and match;
  - conflicted entries → one candidate per head with an entry payload, flagged;
  - `autofill_values` re-reads that head and re-matches before the
    decrypt/reveal of the selected fields (decision 8), `StaleHandle` if the
    head changed;
  - `link_app` uses the draft/add_field/save_entry path with field name
    "Android app", kind `url`, unprotected.

  Tests on a real test vault:
  - match/no-match, trash exclusion;
  - conflict yields two candidates and values come from the chosen head only;
  - the stale head is refused;
  - the link round trip then matches; read-only session `link_app` refused;
  - lock during the call → `Cancelled`/locked;
  - values bounded; redacted `Debug`.
- **Files:** `crates/qv-core/src/{lib,autofill}.rs`.
- **Done when:** the tests above pass; no new store API.
- **Verify:** `cargo test --locked -p qv-core autofill`.

### Step 5 — Kotlin glue and packaging
- [x] **Do:** Add the following, matching the existing MainActivity style
  (SPDX header, fixed failure categories, no logging of values):
  - `android/AutofillService.kt`: `QvAutofillService` and a process singleton
    `AutofillRegistry` (synchronized; one request; token, TTL, states
    Pending/Claimed/Completed/Cancelled; results zeroed on replace, cancel or
    consume);
  - `android/AutofillAuthActivity.kt`;
  - `android/res/xml/autofill_service.xml` (no settings activity);
  - an `AutofillGate.kt` generated by the build script, with
    `VALIDATION = QV_APP_DEVICE_VALIDATION` and the fingerprint allowlist empty.

  Manifest:
  - the service with `android:permission="android.permission.BIND_AUTOFILL_SERVICE"`,
    `exported="true"` (required by the system binding), the
    `android.service.autofill.AutofillService` intent filter and meta-data;
  - the auth activity `exported="false"`, `excludeFromRecents`,
    `noHistory="false"`, translucent theme;
  - MainActivity `launchMode="singleTask"`.

  MainActivity methods: `qvAutofillPending()`, `qvAutofillPackage(id)`,
  `qvAutofillSigners(id)` (n×32 bytes), `qvAutofillScheme(id)`,
  `qvAutofillHost(id)`, `qvAutofillPort(id)`, `qvAutofillRoles(id)`,
  `qvAutofillComplete(id, user: ByteArray?, pass: ByteArray?)` (bounded at
  8 KiB, then `moveTaskToBack(true)`), `qvAutofillCancel(id)`,
  `qvOwnSigners()` (validation positive path) and
  `qvOpenAutofillSettings()` (`ACTION_REQUEST_SET_AUTOFILL_SERVICE`).

  `build-android.sh`: copy the two Kotlin files and generated gate into
  `app/src/main/kotlin/dev/dioxus/main/`, and the XML into
  `app/src/main/res/xml/`. Extend the existing badging/permission inspection to
  assert the service permission, the non-exported auth activity and no new
  `uses-permission` (in particular no `QUERY_ALL_PACKAGES`). If package
  visibility blocks `getPackageInfo` for the requester on API 30+, add a
  minimal `<queries>` entry only if strictly required, record it, and never
  add `QUERY_ALL_PACKAGES`.
- **Files:** `crates/qv-app/android/{AutofillService.kt,AutofillAuthActivity.kt,res/xml/autofill_service.xml,AndroidManifest.xml,MainActivity.kt}`, `crates/qv-app/scripts/build-android.sh`.
- **Done when:** the APK builds and the inspection asserts pass; normal builds
  answer every request with null.
- **Verify:** `sh crates/qv-app/scripts/build-android.sh` (pinned dx/JDK/SDK as in 0033 VALIDATION.md).

### Step 6 — Rust bridge, app state and shared screen
- [x] **Do:**
  - `android.rs`: poll `qvAutofillPending` in the existing loop, then fetch,
    validate and offer.
  - Validation build only: treat a request from the instrumentation package
    whose signers equal `qvOwnSigners()` as a trusted browser
    (`#[cfg(feature = "validation")]`), with fixture-vault path restriction
    unchanged.
  - `autofill.rs` (app): request state with bound/unbound, TTL and lock_gen.
  - `Controller::autofill_offer`; `State::invalidate` drops bound requests and
    cancels natively; the unlock path opens `Screen::Autofill`.
  - `ui/autofill.rs`: the screen per the Design flow, plus a Settings row with
    availability and an "Open Android autofill settings" button.
  - New `ConfirmKind::LinkApp` text; worker operations via `run_op`.

  Linux has no autofill: the screen is unreachable and status shows
  unavailable.

  Controller tests with an injected request:
  - a request while locked is kept and opens the screen after unlock;
  - expiry;
  - manual lock after binding cancels;
  - stale epoch;
  - a conflicted candidate requires a version (no default);
  - an untrusted-origin request lists no web entries;
  - link needs confirmation, then still needs Fill;
  - completion payload bounded;
  - a late result after a lock is dropped.
- **Files:** `crates/qv-app/src/{android,autofill,controller,workspace,ops,views}.rs`, `crates/qv-app/src/ui/{mod,workspace,autofill}.rs`, `crates/qv-app/src/workspace_tests.rs`.
- **Done when:** app tests pass; Android arm64 Clippy passes; no secret enters UI events.
- **Verify:** `cargo test --locked -p qv-app`; `cargo test --locked -p qv-app --features validation`; Android arm64 Clippy as in 0033.

### Step 7 — Instrumentation and device evidence
- [x] **Do:** Add `android/tests/AutofillTest.java`, run in the validation
  build. The test activity hosts username/password EditTexts, an activity label
  "QuickVault Bank" and a WebView loading local HTML via
  `loadDataWithBaseURL("https://bank.example/", …)`. The test selects QuickVault
  as the autofill service via `adb shell settings put secure autofill_service
  …` in the runner instructions. Cases, driven through the shared app with DOM
  helpers:
  - native fields with no link → the screen lists no candidates although an
    entry is titled "QuickVault Bank" (label spoof);
  - after linking → explicit Fill fills both fields;
  - WebView origins `https://bank.example.evil.test`, `https://evilbank.example`,
    `bank://login` and `http://bank.example` against a stored
    `https://bank.example` → no web candidates;
  - the exact origin through the validation trusted-browser path → fill;
  - a conflicted entry needs a version choice;
  - a lock during the bound request → the target stays empty;
  - an expired token → RESULT_CANCELED.

  Record results in `plans/0034-android-autofill/VALIDATION.md`, with passed
  and pending rows kept separate as in 0033. Run on the POCO X7 Pro when it is
  connected. If no device is available, leave the rows explicitly pending; do
  not invent evidence.
- **Files:** `crates/qv-app/android/tests/{AutofillTest.java,AndroidManifest.xml}`, `crates/qv-app/scripts/build-android.sh`, `plans/0034-android-autofill/VALIDATION.md`.
- **Done when:** the instrumentation APK builds; device results are recorded or explicitly pending.
- **Verify:** the APK build plus `adb shell am instrument -w -e class org.quickvault.app.AutofillTest org.quickvault.app.test/android.test.InstrumentationTestRunner` when a device is present.

### Step 8 — Documentation
- [x] **Do:** Update:
  - `ARCHITECTURE.md` §3: the qv-platform row (autofill matching), the Android
    paragraph and the diagram ("future autofill" → gated autofill);
  - `CHANGELOG.md` Unreleased;
  - the app README: autofill limits and copies, the empty allowlists and how
    to enable the service;
  - plan index and roadmap tick/log.
- **Files:** as listed.
- **Done when:** the documentation duties table is satisfied.
- **Verify:** `sh scripts/check-spdx.sh`.

## Test plan

- Final verification: all `AGENTS.md` gates on the final tree, plus app
  validation tests/Clippy, the vendor hardened tests (unchanged vendor source;
  rerun as a regression), Android arm64 Clippy, and the APK build with
  inspection. No dependency change, so `cargo deny`/`cargo vet` run only if
  `Cargo.lock` changes (it must not).
- Unit tests: origin/identity parsers, matcher, bounds and allowlist behaviour;
  core candidates and values; mutex serial semantics.
- Rejection tests: every spoof class in steps 3 and 7; oversized
  package/signers/host/values; malformed digests; stale heads; expired/replaced
  tokens; locked sessions.
- Vectors: none (no cryptography).
- 0012 §1 rows: no dedicated autofill row exists. Evidence feeds 0012 §3
  "verified autofill matching" for release 2.11. The quick-unlock carry-over
  keeps "Hardware assumptions" tests green.

## Risks and stop conditions

- Stop if verifying identity would require `QUERY_ALL_PACKAGES`, a network
  fetch, a new dependency or `unsafe`.
- Stop if the system does not populate `activityComponent` reliably, or if the
  handoff cannot be kept non-exported and one-shot. Record and keep autofill
  disabled; never fall back to label or URL-substring matching.
- Never add allowlist entries (devices or browsers) without digests observed on
  a device and recorded in VALIDATION.md.
- If `singleTask` breaks existing instrumentation, record it and revise the
  plan (e.g. reorder-to-front intent flags) rather than allowing a second
  activity.
- Missing hardware leaves step 7 pending, as in 0033. Continue host work;
  device enablement stays closed.

## Documentation

- [ ] `CHANGELOG.md` — Unreleased entry
- [ ] `ARCHITECTURE.md` — §3 qv-platform row, Android paragraph, diagram
- [ ] Specs — 0009 §4.4, OQ2 note, Changelog; `specs/README.md` row if needed; status stays Draft
- [ ] `AGENTS.md` — no change

## Revisions

- 2026-11-02 (developer, packaging fact): the Dioxus CLI's own Gradle build
  compiles only the configured `MainActivity.kt` and resolves manifest
  resources before the build script copies anything. The autofill Kotlin
  (`QvAutofillService`, `AutofillAuthActivity`, `AutofillRegistry`,
  `AutofillIdentity`, `AutofillGate`) therefore lives in `MainActivity.kt`,
  following the quick-unlock precedent. The optional `android.autofill`
  meta-data/XML is dropped (it only names a settings activity, and there is
  none). The build script flips `AutofillGate.VALIDATION` only in the copied
  validation project. The autofill screen lives in `ui/workspace.rs` to reuse
  its private `act`/`Input` helpers, not in a new `ui/autofill.rs`. The design
  is unchanged.

## Execution log

- 2026-11-02: Planned after the fresh-context 0033 review (Approved; one low
  finding carried as step 2). The roadmap stop conditions this plan triggers
  (Draft 0009 §4, spec amendment, DAL deviation) are resolved under the owner's
  standing delegation of 2026-11-02. Approved: standing approval, roadmap 0002,
  plus owner standing delegation. No dependency or `unsafe`.

- 2026-11-02: Steps 1–4 implemented. 0009 §4.4/OQ2/Changelog and roadmap
  Revision added. Quick-unlock slot serial: mutex released across native open;
  new blocking-backend test (readiness during prompt, re-enroll/invalidate
  discard late results) plus the existing quick tests pass (platform 3, core 1).
  `qv-platform::autofill` parsers/matcher: 5 tests pass (substring, subdomain,
  userinfo, custom-scheme, IDN/percent/IPv6, signer subset/superset, untrusted
  WebView origin claims, bounds). `qv-core::autofill`: 3 tests pass (titles
  never match; values only for the chosen conflict head; stale head refused;
  trash excluded; link idempotent and refused on conflicted/locked). Platform
  and core Clippy and fmt clean. Deviation: the request has no port parameter
  (Android reports none), so requests use the default port and stored
  non-default ports never match web requests. This is stricter than the sketch.

- 2026-11-02: Steps 5–8 implemented.
  - Kotlin glue as revised: field detection only, OS-reported package, signer
    SHA-256 set, generic dataset authentication.
  - Registry: one request, 16-byte token, 120 s pending / 10 min total; results
    zeroed; cancel never revokes a COMPLETED result.
  - Non-exported handoff activity: claim once, re-verify signers, fill only
    registered ids.
  - Rust bridge: bounded poll/fetch, `FillRequest` validation, validation-only
    own-package trusted-browser path.
  - App: request state survives locks until bound (TTL); bound requests are
    cancelled by lock; autofill screen with per-head candidates, confirmed
    linking, explicit Fill; lock-screen and workspace banners; Settings row.
  - Request ports: see the steps 1–4 log (no request port parameter).
  - Instrumentation: `AutofillTest` (in-process handoff, wrong/replayed token,
    label spoof, link confirmation, explicit fill, lock cancellation).

  Builds: normal and validation APKs plus instrumentation build; manifest
  checks pass (non-exported handoff, system-only binding, `singleTask`, no new
  permission). The generated gate is false in normal builds and true only in
  the validation build. Android arm64 Clippy passes for `mobile` and
  `validation`.

  Final gates on this tree:
  - SPDX + fixtures, matrix, fmt, workspace Clippy pass;
  - `cargo test --locked` **759 passed, 0 failed, 2 ignored** (private Xvfb
    via `QV_TEST_XVFB`);
  - app validation Clippy and **31** tests pass;
  - vendor hardened **6** pass;
  - `Cargo.lock` unchanged, so deny/vet were not rerun.

  Device: `adb devices` empty, so every VALIDATION.md device row is pending;
  no device or browser is enabled.

  Found, not fixed: each Android build still creates a new
  `dist/android-project-*` directory (owner will handle the build-output
  pile-up separately).

- 2026-11-02 (phone connected, POCO X7 Pro, Android 15):
  - `AutofillTest` passes on the validation build with all seven stages (label
    spoof refused, link confirmation, explicit fill, lock cancellation,
    wrong/replayed token refused).
  - `PlatformTest` passes on the normal build with `singleTask` (64.697 s).
    The normal build is reinstalled.
  - Harness-only fixes: a JSON-string assertion; MIUI blocks app self-starts
    from the background (MIUIOP 10021), so the test now waits for the activity
    and the runner starts it from adb shell. The op was temporarily allowed and
    restored to `ignore`.

  Found, not fixed (pre-existing, outside this plan's files): a second
  `MainActivity` in a live process aborts in `ndk-context` (`previous.is_none()`
  from wry's `WryActivity_create`): the Rust runtime initializes once per
  process. Normal launches avoid it because Android starts a fresh process, but
  backing out of QuickVault while the autofill service keeps the process
  cached, then starting another handoff, would crash. The crash fails closed:
  no session or values are released.

  Recommended next plan: on final destroy (`isFinishing &&
  !isChangingConfigurations`), lock and end the process so the next launch is
  fresh, with an instrumentation-aware exception or a per-method runner;
  alternatively fix context release upstream in wry, which would be a new
  vendor fork and needs the owner. Autofill stays gated, so no device is
  exposed. Remaining attended rows: framework round trip from a foreign app
  and WebView origin claims.

- 2026-11-02: The `ndk-context` re-creation finding is fixed by plan 0035 and
  verified on the device (Back/reopen and dark-mode toggle). The VALIDATION.md
  "known failure" row is resolved.
