# Plan 0038 — LAN sessions, exchange, CLI and app (roadmap 2.10)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-11-03 | 2026-11-03 | 0013 §1–8, §11–12 (amended in step 1); 0011 §1, §3, §4, §6 (amended in step 1); 0005 §0.5, §6; 0004 §5–6; 0007 §3.2; 0008 §1, §4; 0009 §1; 0012 §1 |

## Intent

Make two devices that share a LAN link actually synchronize. Either device
opens a receive window; the other starts a round. Both end with the same
merged vault, committed through the local write path, and nothing ever
starts without a user action. The CLI and the app gain the LAN commands and
screens, pairing included, so the 2.9 core becomes usable.

## Scope

**In scope:**
- **Spec amendments (step 1):**
  - 0013: the address-only receive-window code (owner decision 2026-11-03);
    the initiator's link choice; the `Want` count bound (review 0037,
    finding 2);
  - 0011: `qvault lan …` syntax, behaviour and output, and exit code 10
    with the LAN error mapping.
- **qv-crypto:** the 0013 §5 session key schedule (`K_i`, `K_r` and the
  `k_i2r`/`k_r2i` session keys).
- **qv-protocol:** the `SyncHello`, `SyncAccept` and `Confirm` codecs, and
  the address-only QR codec.
- **qv-store:**
  - staging a peer's state against an existing vault: a plan of local and
    peer objects, local copies, and the full archive authentication;
  - LAN acceptance through the existing incoming-acceptance path, without
    filename receipts. A result equal to the local manifest commits
    nothing.
- **qv-sync::lan:**
  - the §5 handshake for both roles;
  - the general §7 exchange (both directions, merge through a vault trait);
  - receive windows (§8: one session at a time, 16 failures, nonce replay
    set, time limit, optional stay-open);
  - the initiator, with candidates tried one at a time and connection
    attempts cancellable within about 100 ms;
  - the exchange after link-mode pairing (§4.8);
  - the 0037 review carry-overs (findings 2–6).
- **qv-platform:** local interface-address discovery for QR and endpoint
  display, with std only (route probes; no new dependency).
- **qv-core:**
  - `Session::open_receive_window`, `ReceiveWindow::{code, run}` and
    `Session::sync_lan`, with exchange reports;
  - the link-mode follow-up exchange in `PairingWindow::run` and
    `Session::join_link`;
  - ordinary snapshot coalescing before LAN acceptance (0007 §3.2);
  - `local_addresses()`.
- **qv-cli:** `qvault lan pair|join|receive|sync|links|unlink` per amended
  0011, with the exit-code mapping.
- **qv-app:**
  - a *Devices* pane for an unlocked vault: list and remove links, pair a
    device, link an existing copy, receive, and sync with a link;
  - *Join from another device* on the locked screen (new device);
  - code display as text (manual code and endpoints), SAS confirmation
    prompts, progress, cancel, and closing on lock and on background.
- Development vectors for §5 and the address QR, with the Python crosscheck
  extended; fuzzing of the new decoders.

**Out of scope:**
- **QR rendering and camera scanning** → new roadmap phase **2.10b** (see
  Decisions 2). Core returns both QR payloads; frontends show the manual
  code and the endpoints as text.
- DNS-SD advertising and browsing (owner decision 2026-11-03: stays
  deferred; windows keep discovery off).
- Visual redesign (phase 2.10a).
- Automatic or background sync (0005 §0.5).
- Mixed LAN and remote sync (milestone 3).

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Session handshake, link-key auth, no KEM before the tag, nonce replay, confirm | 0013 §5 | Accepted | step 1 adds the initiator's link choice |
| Record layer | 0013 §6 | Accepted (implemented 2.8) | |
| Exchange turns, State/Manifest/Want/Object/Done, accept and commit | 0013 §7.1–7.8 | Accepted | step 1 bounds the `Want` count |
| Windows and abuse limits, explicit initiation | 0013 §8; 0005 §0.5 | Accepted / Draft (roadmap-approved phase entry) | 0005 §6 is the phase entry's spec, resolved by 0013 |
| Address-only receive-window code | 0013 §3.1, new §8.5 | Accepted (amended step 1) | owner decision 2026-11-03 |
| Exchange after link-mode pairing | 0013 §4.8 | Accepted | |
| Errors on the wire; exit codes | 0013 §11; 0011 §6 | Accepted (0011 amended step 1) | |
| Local commit, anchor, crash ordering | 0004 §5; 0005 §5.4, §6.5 | Accepted / D5 | reuses `accept_incoming` |
| Snapshots before merges | 0007 §3.2 | Accepted | LAN merges use ordinary coalescing, not a mandatory recovery copy |
| No secret in argv/env; prompts; alternate screen | 0011 §3 | Accepted | the pairing code is a displayed secret like the recovery phrase |
| Frontends through core; app input rules | 0009 §1; 0008 §1, §4 | Accepted / Draft (D5, D13 go-ahead) | |
| Matrix rows | 0012 §1 | Accepted | Account-dependent LAN sync, LAN partial acceptance, LAN discovery mistaken for trust (sessions), Unrequested synchronization (LAN) via 0013 "Explicit initiation" |

**Spec changes required (step 1):** these are owner-delegated, standing
2026-11-02. The 0013 QR amendment is also owner-directed (2026-11-03). Each
gets a Changelog line.
- **0013:**
  - new §8.5 (address-only QR and its text form);
  - §3.1 points to §8.5;
  - §5.1: the initiator uses exactly one link per attempt;
  - §7.4: an empty `Want` must be final, and at most 62 `Want` messages
    are allowed per turn.
- **0011:**
  - the §4 *Sync and later* `qvault lan …` row becomes the exact command
    contract;
  - §6 gains code 10;
  - §3.2 notes that LAN prompts are refused with `--password-stdin`.

## Decisions needed

None pending. Each choice below is delegated by the owner (standing,
2026-11-02: "dont ask me to approve stuff, just pick whatever is the best
option").

1. **Initiator link choice (0013 §5.1 gap).** The hello carries no link ID,
   and the initiator may hold several links for one vault.
   - Chosen: the initiator uses one link per attempt: the one the user
     selected, or the vault's only link. Frontends name links by label.
   - Rejected: trying every link in turn. Each wrong tag counts as a failed
     attempt at the responder (16 close the window), so a vault with many
     links would close windows. It also tells the responder how many links
     the initiator holds.
   - Rejected: a link selector in the address QR. It would make windows
     linkable, against the owner's unlinkability direction.
2. **QR rendering and scanning move to a new phase 2.10b.**
   - Displaying a QR needs an encoder dependency (`qrcodegen`).
   - Scanning needs a camera path. Android has no system QR decoder without
     Play Services, so that means a capture intent plus a decoder crate,
     and the desktop usually has no camera. Scanning is validated on
     devices only.

   That is a separate delivery boundary: new dependencies, a new
   permission or intent, and attended device evidence. It is not a split
   for size. In 2.10 both QR payloads exist in core and are specified, and
   the frontends offer the owner's "typing as the fallback" path (manual
   code and `address:port`).
   - Rejected: rendering the QR without scanning. It would add a dependency
     with no in-app consumer.
   - Rejected: scanning in 2.10. It would block the whole phase on device
     validation.
3. **Interface addresses without a dependency.**
   - Chosen: `qv_platform::net::local_addresses()` uses route probes. An
     unconnected UDP socket is `connect`ed (this sends no packet) to fixed
     destinations, and its `local_addr()` is read. IPv4 destinations:
     `10.255.255.254`, `172.31.255.254`, `192.168.255.254`, `100.127.255.254`,
     `192.0.2.1`. IPv6 destinations: `fd00::1`, `2001:db8::1`.
   - The result is deduplicated and filtered through the §1.4 rules, minus
     loopback and link-local (QR endpoints carry no scope ID). At most 8
     are returned.
   - Probe failures are skipped, and an empty result means "type the
     address".
   - Rejected: the `if-addrs` crate (a new dependency with `unsafe`
     `getifaddrs`); parsing `/proc/net` (unreadable for apps since
     Android 10); JNI `NetworkInterface` (Android-only glue).
4. **Exit code 10, "LAN peer unavailable".** 0011 §6 has no code for an
   unreachable or refusing peer. Mapping:

   | Code | LAN errors |
   |------|------------|
   | 10 | `NoPeer`, `Timeout`, `PeerCancelled`, `CodeObserved`, `TooManyAttempts`, `WindowExpired`, `VaultMismatch`, `Io` |
   | 7 | `Integrity`, `Protocol` |
   | 8 | `Keyslot` |
   | 9 | `Limit` |
   | 6 | `Busy`, `StateChanged` |
   | 1 | `Cancelled` (as other CLI cancellations), `Unsupported` |
   | the existing store mapping | `Store(e)` |

   - Rejected: folding everything into 1, which leaves scripts unable to
     tell "nobody answered" from a bug.
5. **The receiving side reuses the archive path.** The peer's manifest and
   objects are staged into a private, unlinked, complete archive:
   - peer references this vault holds with an identical reference are
     copied from local rows;
   - the others are requested;
   - the archive is authenticated with `read_archive`;
   - the result is accepted through the existing `accept_incoming`
     transaction, generalized over its input, with no receipt for LAN.

   A candidate equal to the local manifest commits nothing (outcome 0).
   - Rejected: a second merge/commit path (0002 roadmap invariant).
6. **Snapshots.** Before LAN acceptance, core runs the ordinary automatic
   snapshot, which applies the hourly coalescing (0007 §3.2). A missing
   policy or a snapshot failure does not block the merge. 0007 requires a
   mandatory copy only for explicit imports and recovery.
7. **Receive windows.**
   - Default limit 2 minutes, at most 15 (0013 §8.2). `stay_open = false`
     closes the window after the first completed round.
   - An authenticated round that aborts leaves the window open within its
     limit. It is not a failed attempt, since the peer authenticated.
   - Pre-authentication failures count toward 16: shape, profile, no tag
     match, a replayed `nonce_I`, a removed link, a bad confirm.
   - Link keys are read once when the window opens and kept as
     `SessionAuth` values until it closes. A tag match is rechecked against
     the current links before accepting, so a link removed while the window
     is open stops working at once.
8. **The pairing code in the CLI** is shown like the recovery phrase: on the
   alternate screen, cleared when the command ends. `pair` and `join` need
   a TTY and refuse `--password-stdin` (exit 2). `join` reads the code with
   the no-echo prompt.
9. **Mobile foreground.** On Android, the existing lifecycle lock (pause
   locks the session, 0009) closes any window through the session lock. If
   a configuration does not lock on pause, the app cancels the window's
   token on pause instead (0013 §8.2).
10. **Initiator connect cancellation (0037 finding 6).** Each connection
    attempt runs `TcpStream::connect_timeout` on a short-lived helper
    thread. The caller polls the result and the cancel check every 100 ms
    and abandons the thread on cancel; the thread ends within the 10 s
    connect limit. No new dependency, no `unsafe`.

## Design

**Components touched** (trust boundary):
- qv-crypto `lan.rs` (trusted crypto);
- qv-protocol `lan.rs` and `oob.rs` (key-free, hostile-input codecs);
- qv-store `lan_staging.rs`, `incoming.rs`, `acceptance.rs` and
  `lan_store.rs` (trusted; peer bytes only after authentication);
- qv-sync `lan/*` (trusted orchestration of hostile peer input);
- qv-platform `net.rs` (OS adapter; addresses are untrusted hints);
- qv-core `lan.rs`;
- the qv-cli and qv-app frontends, through core only;
- `fuzz/`.

LAN code stays Linux/Android only, as in 2.9.

**Interfaces** (the signatures are the contract; private helpers are free):

```rust
// ---- qv-crypto/src/lan.rs ----
/// K_i and K_r of one link (0013 §5.1): HKDF(link_key, salt = empty,
/// ["qv/lan-auth/v1", "i"|"r"]). Redacted Debug, no Clone.
pub struct SessionAuth { i: SecretArray<32>, r: SecretArray<32> }
impl LinkKey { pub fn session_auth(&self) -> Result<SessionAuth, CryptoError>; }
impl SessionAuth {
    pub fn hello_mac(&self, body: &[u8]) -> Result<MacTag, CryptoError>;              // K_i
    pub fn verify_hello(&self, body: &[u8], tag: &MacTag) -> Result<(), CryptoError>;  // CT
    pub fn accept_mac(&self, transcript: &[u8]) -> Result<MacTag, CryptoError>;        // K_r
    pub fn verify_accept(&self, transcript: &[u8], tag: &MacTag) -> Result<(), CryptoError>;
}
/// (k_i2r, k_r2i) = HKDF(ss ‖ link_key, th, ["qv/lan-session/v1", "i2r"|"r2i"]).
pub fn session_record_keys(ss: &XWingSharedSecret, link: &LinkKey, th: &[u8; 32])
    -> Result<(RecordKey, RecordKey), CryptoError>;
// vectors module: + session_auth(k) -> ([u8;32],[u8;32])
```

```rust
// ---- qv-protocol/src/lan.rs ----
pub struct SyncHello<'a> { pub profile: u64, pub nonce_i: [u8; 32], pub ek: &'a [u8; 1216], pub mac: [u8; 32] }
// body(profile, nonce_i, ek), encode(.., mac), decode (exact shape; profile raw)
pub struct SyncAccept<'a> { pub nonce_r: [u8; 32], pub ct: &'a [u8; 1120], pub mac: [u8; 32] }
// transcript(hello_hash, nonce_r, ct) = canonical ["qv/lan-accept/v1", H(hello), nonce_R, ct]; encode; decode
pub fn session_th_input(hello_hash: &[u8; 32], accept_hash: &[u8; 32]) -> Result<Zeroizing<Vec<u8>>, ProtocolError>;
//   canonical ["qv/lan-th/v1", H(hello), H(accept)]
pub struct Confirm { pub th: [u8; 32] }  // ["qv/lan-confirm/v1", th]; encode/decode
pub const MAX_WANT_MESSAGES: usize = 62;  // ⌈250,000 / 4,096⌉ (0013 §7.4 amended)

// ---- qv-protocol/src/oob.rs ----
pub const ADDR_QR_LABEL: &str = "qv/lan-addr-qr/v1";
pub struct AddrQr { pub profile: u64, pub endpoints: Vec<WireEndpoint> /* 1..=8 */ }
pub fn encode_addr_qr(profile: LanProfile, endpoints: &[WireEndpoint]) -> Result<Vec<u8>, ProtocolError>;
pub fn decode_addr_qr(bytes: &[u8]) -> Result<AddrQr, ProtocolError>;   // ≤ 1024 bytes, canonical, exact
/// "a.b.c.d:port" or "[v6]:port"; IP literals only, port 1..=65535, ≤ 64 bytes.
pub fn parse_endpoint(text: &str) -> Result<WireEndpoint, ProtocolError>;
pub fn format_endpoint(e: &WireEndpoint) -> String;
```

```rust
// ---- qv-store (Linux/Android) ----
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Planned { Local, Peer }
impl LanStaging {
    /// Every peer reference in archive order with its source; new-device
    /// staging plans every object as Peer.
    pub fn plan(&self) -> &[(ObjectId, Planned)];
    /// The Peer IDs in order (what to put in `Want`s).
    pub fn requested(&self) -> Vec<ObjectId>;
    /// The source of the next object to append, or None when complete.
    pub fn next(&self) -> Option<Planned>;
    // add_object(envelope) stays: it appends the next planned object (Peer).
}
impl UnlockedVault {
    /// Staging of a peer's state for merge (0013 §7.3–7.5). Checks, in this
    /// order: envelope length ≤ MAX_ARCHIVE_MANIFEST_FRAME; SHA-256 =
    /// manifest_hash (Integrity); envelope generation and profile; manifest
    /// AEAD/decode/validate under this vault's VK; configuration digest
    /// equal to this vault's (Unsupported otherwise); budgets (count ≤
    /// MAX_OBJECTS, total ≤ MAX_ARCHIVE_TOTAL_LENGTH, LimitExceeded). Then it
    /// plans each reference: identical to this vault's reference →
    /// Local; same ID, different reference → Integrity (substitution
    /// evidence, §7.4); absent → Peer. Finally it writes the prefix, a
    /// header MAC'd under VK and the manifest frame into an unlinked file in
    /// `private_dir` (checked private).
    pub fn lan_stage(&self, private_dir: &Path, manifest_hash: &[u8; 32], envelope: &[u8],
                     cancelled: &dyn Fn() -> bool) -> Result<LanStaging, StoreError>;
    /// Appends the next planned Local object from this vault's row; the
    /// row is rechecked against the reference (NotFound if it is gone).
    pub fn lan_stage_local(&self, staging: &mut LanStaging) -> Result<(), StoreError>;
    /// Full authentication of a complete staging under this vault's VK.
    pub fn lan_finish(&self, staging: LanStaging, cancelled: &dyn Fn() -> bool)
        -> Result<VerifiedLanStaging, StoreError>;
    /// accept_incoming for LAN: no receipt. Returns Ok(false), with no
    /// commit, when the built candidate equals the current manifest.
    pub fn accept_lan(&mut self, staging: &mut VerifiedLanStaging,
                      build: &mut impl FnMut(&Manifest, &Manifest, &mut IncomingRead<'_>) -> Result<Manifest, StoreError>,
                      cancelled: &dyn Fn() -> bool) -> Result<bool, StoreError>;
    /// The current manifest hash (for Done).
    pub fn manifest_hash(&self) -> [u8; 32];
}
// Internally: VerifiedIncoming and VerifiedLanStaging share one private
// `StagedArchive { file, opened }` with read_version/read_object;
// accept_incoming and accept_lan share one body over an input that
// optionally carries the receipt (path + digest). No second copy.
```

```rust
// ---- qv-sync/src/lan/ ----
/// What one vault offers an exchange (qv-core implements it over a session
/// with short calls; VK never leaves the session).
pub trait ExchangeVault: Sync {
    fn serve_state(&self) -> Result<LanServeState, LanError>;
    fn object(&self, state: &LanServeState, id: ObjectId) -> Result<Vec<u8>, LanError>;
    fn stage(&self, manifest_hash: &[u8; 32], envelope: &[u8]) -> Result<LanStaging, LanError>;
    fn stage_local(&self, staging: &mut LanStaging) -> Result<(), LanError>;
    /// Finish (full authentication), merge, commit; Done's outcome and hash.
    fn accept(&self, staging: LanStaging) -> Result<Accepted, LanError>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted { pub outcome: Outcome, pub manifest_hash: [u8; 32] }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role { Initiator, Responder }
/// One round's result (0005 §6.5: local acceptance separate from peer receipt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoundReport { pub local: Outcome, pub peer: Option<Outcome>, pub manifest_hash: [u8; 32] }
pub(crate) fn exchange(ch: &mut Channel<'_>, role: Role, vault: &dyn ExchangeVault,
                       id: VaultId, generation: KeyGeneration, t: &LanTimeouts) -> Result<RoundReport, LanError>;

/// The links a responder checks: (link_id, auth) for every link of the vault.
pub trait ResponderVault: ExchangeVault {
    fn context(&self) -> Result<(VaultId, KeyGeneration), LanError>;
    fn links(&self) -> Result<Vec<([u8; 16], LinkKey)>, LanError>;   // ≤ 64
    fn has_link(&self, link_id: &[u8; 16]) -> Result<bool, LanError>;
}
pub struct ReceiveWindow { /* listener, scope, expires, stay_open */ }
impl ReceiveWindow {
    pub fn open(scope: ListenScope, port: Option<u16>, limit: Duration /* ≤ 15 min */,
                stay_open: bool) -> Result<Self, LanError>;
    pub fn port(&self) -> Result<u16, LanError>;
    pub fn qr(&self, addrs: &[IpAddr]) -> Result<Vec<u8>, LanError>;        // address-only, ≥ 1 endpoint
    pub fn endpoints(&self, addrs: &[IpAddr]) -> Result<Vec<SocketAddr>, LanError>;
    pub fn expires_at(&self) -> Instant;
    /// Runs until closed. `on_round` sees each completed round (link ID and
    /// report); a round's failure is reported with Err and the window stays
    /// open within its limit.
    pub fn run(self, vault: &dyn ResponderVault, timeouts: &LanTimeouts,
               cancelled: &(dyn Fn() -> bool + Sync),
               on_round: &mut dyn FnMut([u8; 16], Result<RoundReport, LanError>)) -> WindowEnd;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowEnd { Completed, Expired, Cancelled, TooManyAttempts, Io }

pub trait InitiatorVault: ExchangeVault { fn context(&self) -> Result<(VaultId, KeyGeneration), LanError>; }
/// §5 + §7 as the initiator with `link`.
pub fn sync(link: &LinkKey, endpoints: &[SocketAddr], policy: EndpointPolicy, vault: &dyn InitiatorVault,
            timeouts: &LanTimeouts, cancelled: &(dyn Fn() -> bool + Sync)) -> Result<RoundReport, LanError>;
// Pairing: ApproverVault and JoinerVault gain `ExchangeVault` as a
// supertrait; Approved gains `round: Option<Result<RoundReport, LanError>>`
// (link mode only); join_link returns `JoinedLink { link_id, round: Result<RoundReport, LanError> }`.
```

```rust
// ---- qv-platform/src/net.rs (Linux/Android) ----
/// Up to 8 local unicast addresses for display (decision 3); empty when none
/// is found. Never trusted.
pub fn local_addresses() -> Vec<IpAddr>;
```

```rust
// ---- qv-core/src/lan.rs (additions) ----
pub use qv_platform::net::local_addresses;
pub struct ReceiveOptions { pub scope: ListenScope, pub port: Option<u16>, pub limit: Duration,
                            pub stay_open: bool, pub timeouts: LanTimeouts }   // new(): all interfaces, 2 min
pub struct SyncOptions { pub allow_loopback: bool /* tests */, pub timeouts: LanTimeouts }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAcceptance { Committed, Unchanged }
pub struct SyncReport { pub link: LanLinkHandle, pub local: LocalAcceptance, pub conflicts: usize,
                        pub peer_confirmed: bool, pub completion_error: Option<CoreError> }  // redacted Debug
pub struct ReceiveCode { pub qr: Vec<u8>, pub endpoints: Vec<SocketAddr>, pub port: u16 }
pub enum ReceiveEvent { Round(Result<SyncReport, CoreError>) }
pub struct ReceiveReport { pub rounds: usize, pub end: WindowEnd }
impl Session {
    pub fn open_receive_window(&self, options: ReceiveOptions) -> Result<ReceiveWindow, CoreError>;
    pub fn sync_lan(&self, link: &LanLinkHandle, endpoints: &[SocketAddr], options: SyncOptions,
                    cancel: Option<&CancelToken>) -> Result<SyncReport, CoreError>;
    pub fn join_link(&self, …) -> Result<JoinLinkReport, CoreError>;   // changed return type
}
pub struct JoinLinkReport { pub link: LanLinkHandle, pub sync: Result<SyncReport, CoreError> }
impl ReceiveWindow {
    pub fn code(&self, local_addrs: &[IpAddr]) -> Result<ReceiveCode, CoreError>;
    pub fn expires_at(&self) -> Instant;
    pub fn run(self, session: &Session, on_event: &mut dyn FnMut(ReceiveEvent),
               cancel: Option<&CancelToken>) -> Result<ReceiveReport, CoreError>;
}
// ApproveReport gains `sync: Option<Result<SyncReport, CoreError>>` (link mode).
```

**Data and control flow.**

*Handshake (§5), responder R per connection:*
1. Read one handshake frame (message limit).
2. Decode `SyncHello` (exact shape), then check the profile.
3. Compute the tag under **every** window link's `K_i` and compare each in
   constant time, without stopping at the first match.
4. Refuse a `nonce_I` already seen in this window.
5. Recheck that the matched link still exists (`has_link`).
6. Only then `XWingEncapsKey::from_bytes`.

Any failure closes the connection, sends nothing and counts one attempt.
After that:
- encapsulate, draw `nonce_R`, send `SyncAccept`;
- `th` from H(hello) and H(accept);
- `(k_i2r, k_r2i)` from `ss ‖ link_key`;
- open I's first record, which must be `Confirm(th)` (constant-time
  compare; anything else counts as a failure and closes without a reply);
- erase `ss`, then run the exchange as responder.

*Initiator I:* draw a fresh `nonce_I` and X-Wing pair for each candidate
(at most 16, deduplicated and policy-filtered):
- connect (cancellable, decision 10), send the hello, read the accept
  (message limit);
- a bad accept MAC or a closed connection moves on to the next candidate;
- the first valid accept authenticates R. Later failures abort.

Then decapsulate (failure → `Integrity`), derive `th` and the keys, erase
`dk_I` and `ss`, send `Confirm`, and run the exchange as initiator.

*Exchange (§7.1).* Turns, with each side's own state `S` taken from
`serve_state` once at the start:
1. I sends `State(S_I)`; R checks the vault and generation
   (`vault_mismatch`), the features (`unsupported`), then length 0 →
   `protocol` and above 64 MiB → `limit`, before allocating.
2. R sends `State(S_R)`; I applies the same checks.
3. Equal manifest hashes: I sends `Done(0, h)`, R sends `Done(0, h)`; both
   report `Unchanged` with `peer = Some(Unchanged)`. Done.
4. I sends its manifest parts (≤ 1 MiB each, contiguous); R receives them
   into a buffer reserved once at the announced length.
5. R sends its manifest parts; I receives them.
6. Each side calls `stage(peer_hash, peer_envelope)`, which yields its
   plan.
7. I sends `Want`s for its Peer IDs. R validates them (each ID in R's
   served state, no duplicates, ≤ 4,096 per message, ≤ 62 messages, an
   empty `Want` only as the last, total ≤ 250,000; else `protocol`).
8. R sends one `Object` per request, in order. In parallel, I walks its
   plan: Local entries go to `stage_local`, Peer entries read the next
   `Object` into `add_object`. Each object's ID, length and SHA-256 are
   checked against the reference before writing (§7.5).
9. The same with roles swapped: R's `Want`s, I's `Object`s.
10. Each side calls `accept(staging)`: finish, merge through
    `qv_sync::merge`, commit through `accept_lan` (DB commit → anchor), or
    no commit if unchanged.
11. I sends `Done(outcome_I, h_I')`. R reads it, then sends
    `Done(outcome_R, h_R')`, and I reads that. Each `Done` is
    shape-checked; its outcome is only reported.

Failure semantics:
- A failure before `accept` commits nothing: staging is an unlinked file,
  dropped on abort.
- A failure after this side's commit keeps the commit and reports it, with
  `peer = None` (§7.7: a lost `Done` keeps the local commit).
- Retrying is idempotent: versions deduplicate, and the second round
  reaches step 3.

Serving uses the state named in step 1. A missing row is `state_changed`;
a hash mismatch is `integrity`.

*Pairing follow-up (§4.8).* After `PairDone`, B runs the exchange as I and
A as R, on the same channel with the pairing keys (`k_b2a` = i2r, `k_a2b` =
r2i, sequence numbers continuing). A failure leaves both links and is
reported separately from the pairing result.

*Store acceptance.* `accept_lan` runs the `accept_incoming` body without
receipts:
- configuration and reference identity checks;
- the transaction-local candidate build and `validate_projection`;
- object inserts, crash point `ObjectsWritten`, `verify_candidate`;
- `Write::commit_cancellable`, whose order is objects → manifest → head →
  `COMMIT` → anchor.

When `candidate == local manifest`, it returns `Ok(false)` before writing
and drops the write without advancing any sequence. Core then rebuilds the
`Index` from the candidate exactly as `merge_archive` does, and counts the
conflicts from it.

*Windows.* A shared acceptor helper is used by pairing and receive windows
(no second copy of the poll loop). A receive window has no probe
exception: while a session runs, other connections close at once,
unanswered. The window closes:
- at its limit;
- on cancel or lock;
- at 16 failed attempts;
- after the first completed round, unless `stay_open`.

**Secrets and hostile input.**
- **Protected containers:**
  - `SessionAuth`, the session `RecordKey`s and `ss`/`dk_I` (the existing
    X-Wing types) use `SecretArray`;
  - decrypted `LinkKey`s live in `SecretArray` and are dropped when the
    window or round ends (§9.4);
  - the CLI's typed pairing code goes into `Zeroizing` buffers and then
    `JoinCode`;
  - the app's code input follows 0008 §1.1/§4.4 (bounded at 64 bytes,
    converted promptly, control state cleared).
- **No KEM work, decryption or derivation per peer** before the hello tag
  verifies. The only derivations before that are the window's own
  `SessionAuth` values, computed when the window opens.
- **Bounds:** frames are 4096 bytes before keys and the session bound
  after. Manifest length is checked before reserving. `Want` counts and IDs
  are bounded. Staging budgets are checked before writing. Every object is
  checked against its reference before it is written. Full AEAD and role
  authentication run before any SQLite insert.
- **Endpoints and the address QR carry no secret.** They may appear in
  argv, output and logs. The pairing code (`P`) never does (0011 §3).
- No secret in errors, `LanError`, reports' `Debug`, logs or argv. No
  `unwrap`/`expect` on peer data, no `unsafe`.

**Errors.** The wire mapping is the 2.9 table, plus:
- staging Integrity (substitution) → `integrity`;
- a bad `Want` → `protocol`;
- `Changed`/`Locked` during accept → `busy`.

Core wraps `LanError` as `CoreError::Lan`. The CLI uses decision 4. App
messages are fixed text per `LanError` (the existing `Display` strings).

**Dependencies:** none new. qv-platform uses `std::net` only.

## Steps

### Step 1 — Spec amendments

- [x] **Do:**
  - **0013:**
    - new §8.5 *Receive-window code*:
      - the QR array `["qv/lan-addr-qr/v1", lan_profile: uint, endpoints:
        [[addr: bstr(4)|bstr(16), port: uint]] (1–8)]`, canonical, at most
        1024 bytes;
      - the text form `a.b.c.d:port` / `[v6]:port`;
      - it carries no secret and no vault, link or device data; it is a
        §3.1 hint; decoders apply §1.4; link-local addresses are not
        listed;
    - §3.1's bullet points to §8.5;
    - §5.1 adds: "I uses one link per attempt: the link the user selected
      for this action, or the vault's only link. It does not try other
      links against the same window.";
    - §7.4 adds: "An empty `Want` must have `last = true`. A side sends at
      most 62 `Want` messages per turn. Anything else is `protocol`.";
    - Changelog entry.
  - **0011:**
    - replace the `qvault lan …` row with a pointer to a new *LAN command
      contracts* block. It gives the syntax for `pair`, `join`, `receive`,
      `sync`, `links` and `unlink` as in this plan's CLI step, with
      prompts, TTY rules, output lines and exit codes;
    - §6 gains row 10;
    - §3.2 gains the note on LAN prompts and `--password-stdin`;
    - Changelog entry.
  - `specs/README.md`: one-line notes.
- **Files:** `specs/0013-lan-sync-protocol.md`, `specs/0011-cli.md`, `specs/README.md`.
- **Done when:** the text states exactly the behaviour of this plan's
  decisions and steps; statuses unchanged (Accepted).
- **Verify:** `rg -n 'lan-addr-qr|62 .Want|one link per attempt|^\| 10 ' specs/`.

### Step 2 — qv-crypto session keys

- [x] **Do:** `SessionAuth`, `LinkKey::session_auth` and
  `session_record_keys` as specified; extend `vectors`. Tests:
  - each value against an independent in-test HKDF/HMAC over hand-built
    CBOR;
  - `i`/`r` and `i2r`/`r2i` separation (a swapped label fails);
  - another link key or `th` changes every value;
  - redacted `Debug`.
- **Files:** `crates/qv-crypto/src/lan.rs`.
- **Done when:** the tests pass; no new public `RecordKey` constructor.
- **Verify:** `cargo test --locked -p qv-crypto lan`.

### Step 3 — qv-protocol codecs

- [x] **Do:** `SyncHello`, `SyncAccept`, `session_th_input`, `Confirm`,
  `MAX_WANT_MESSAGES`, the address QR codec, `parse_endpoint` and
  `format_endpoint`. Tests:
  - round trips; wrong label or arity; wrong lengths;
  - address QR: 0 or 9 endpoints, a 5-byte address, port 0, a bad label,
    trailing bytes, oversize;
  - endpoint text: hostnames, a missing port, port 0/65536, a zone ID,
    whitespace and > 64 bytes are refused;
  - proptest no-panic for the new decoders.
- **Files:** `crates/qv-protocol/src/{lan.rs,oob.rs}`.
- **Done when:** the tests pass; still only qv-encoding as a qv dependency.
- **Verify:** `cargo test --locked -p qv-protocol`.

### Step 4 — qv-store merge staging and LAN acceptance

- [x] **Do:**
  - the `Planned` plan in `LanStaging`, with `begin` planning every object
    as Peer;
  - `UnlockedVault::{lan_stage, lan_stage_local, lan_finish, accept_lan,
    manifest_hash}`;
  - the shared `StagedArchive` under `VerifiedIncoming` and
    `VerifiedLanStaging`;
  - the shared acceptance body with an optional receipt.

  Existing archive and incoming tests must still pass unchanged. New
  tests:
  - two diverged replicas: staging of each other's state, with plans that
    mark common objects Local, then finish and `accept_lan`; both end
    with equal manifests;
  - an identical peer state → `Ok(false)` and no `local_seq` change;
  - a substituted reference (same ID, other bytes) → `Integrity` at
    `lan_stage`;
  - a foreign configuration → `Unsupported`;
  - over-budget → `LimitExceeded` before any write;
  - a local row deleted after planning → `NotFound` at `lan_stage_local`;
  - crash points `ObjectsWritten`, `HeadWritten` and `Committed` during
    `accept_lan` reopen to old or new with the anchor consistent;
  - no receipt is written for LAN (the receipt digest is unchanged).
- **Files:** `crates/qv-store/src/{lan_staging.rs,incoming.rs,acceptance.rs,lib.rs}`, `crates/qv-store/src/lan_staging_tests.rs`.
- **Done when:** all qv-store tests pass.
- **Verify:** `cargo test --locked -p qv-store`.

### Step 5 — qv-sync handshake, exchange, windows, initiator

- [x] **Do:**
  - `lan/session.rs`: the handshake steps, pure, as for pairing;
  - `lan/exchange.rs`: the general exchange. Generalize the 2.9 new-device
    serve/receive onto it where they coincide, but keep the new-device
    specifics (an empty joiner, `Done(Merged)` meaning receipt);
  - `lan/window.rs`: the shared acceptor;
  - `lan/receiver.rs` (`ReceiveWindow`) and `lan/initiator.rs` (`sync`);
  - the link-mode follow-up exchange;
  - the review carry-overs:
    - the bounded `Want` loop in both serve paths;
    - `Done` outcome 1 checked in the new-device serve (`protocol`
      otherwise);
    - cancellable connect for both joiners and the initiator.

  Tests (`lan_sync_*` and the existing `lan_enroll_*`, loopback, short
  timeouts, real `UnlockedVault` replicas):
  - **0012 §1 Account-dependent LAN sync** (loopback part; the attended
    run is in the test plan): diverged edits on both sides converge to
    equal manifests whichever side initiates; tag it;
  - **0012 §1 LAN partial acceptance:**
    - interrupt (close) after the states, mid-manifest, mid-objects of
      each turn, and before each `Done`: no state change before
      acceptance, the commit kept after it;
    - a retry then completes or reports `Unchanged`;
    - lock or cancel mid-round → `Cancelled` with no change;
    - a duplicate (replayed) hello → refused;
  - **0012 §1 LAN discovery mistaken for trust (sessions):**
    - a wrong link → no reply, counted;
    - a hello under a removed link → refused;
    - a replayed `nonce_I` → refused;
    - a spoof endpoint first → skipped;
    - a reflected accept (R's MAC under `K_i`) → refused;
    - a missing or wrong `Confirm` → closed without reply;
    - a different vault or generation in `State` → `VaultMismatch`;
  - exchange negatives:
    - `Want` IDs outside the state, duplicates, an empty non-final `Want`,
      63 messages → `protocol`;
    - an unrequested or out-of-order `Object` → `protocol`;
    - a substituted object → `integrity`;
    - over 64 MiB → `limit` before allocation;
    - non-contiguous parts → `protocol`;
    - a missing row on the server → `state_changed` (0037 finding 5);
  - windows: 16 failures close; expiry; `stay_open` serves two rounds;
    another connection during a session closes unanswered;
  - link-mode pairing now syncs (both manifests equal); a follow-up
    failure keeps the links;
  - cancel during a connect attempt to a blackhole address returns within
    1 s (use a non-routable `192.0.2.1` candidate; if the sandbox refuses
    it at once, assert the cancel path through a listener that never
    accepts).
- **Files:** `crates/qv-sync/src/lan/{mod.rs,session.rs,exchange.rs,window.rs,receiver.rs,initiator.rs,approver.rs,joiner.rs,transport.rs,tests.rs}` (and a new `sync_tests.rs` if `tests.rs` grows too large).
- **Done when:** `cargo test --locked -p qv-sync lan` passes, three times in a row.
- **Verify:** `cargo test --locked -p qv-sync lan`; `cargo clippy --locked -p qv-sync --all-targets -- -D warnings`.

### Step 6 — qv-platform addresses and qv-core API

- [x] **Do:**
  - `qv-platform/src/net.rs` (decision 3), with unit tests for the filter
    (loopback, link-local, multicast and unspecified dropped; deduped; at
    most 8);
  - qv-core:
    - `ReceiveWindow`, `sync_lan`, `SyncReport` and `JoinLinkReport`;
    - `ApproveReport.sync`;
    - the `ExchangeVault`/`ResponderVault`/`InitiatorVault` impls over
      `Session`: short `read`/`mutate` calls; `accept` inside one
      `mutate` with `qv_sync::merge` and the `Index` rebuild as in
      `merge_archive`; the ordinary automatic snapshot before it;
    - the review carry-over: the grant is sealed inside `read` and sent
      after it (0037 finding 4).

  Tests (`lan_core_*`; two cores, loopback):
  - diverged edits sync both directions to equal overviews;
  - conflicts surface as conflicts;
  - a lock during the round → `Cancelled`, no change, window closed;
  - removing a link stops a window from accepting it;
  - a read-only (recovery) session refuses to receive and to sync;
  - `sync_lan` with a stale handle → `StaleHandle`;
  - rotation: the replacement has no links, and old-link sync fails as
    `NoPeer`;
  - the ordinary snapshot runs at most once per interval;
  - `Debug` of every report is redacted.
- **Files:** `crates/qv-platform/src/{lib.rs,net.rs}`, `crates/qv-core/src/{lan.rs,lan_tests.rs,lib.rs}`.
- **Done when:** the tests pass.
- **Verify:** `cargo test --locked -p qv-platform net`; `cargo test --locked -p qv-core lan`.

### Step 7 — Vectors and fuzzing

- [x] **Do:**
  - extend `qv-sync::lan::vectors` and `qv-dev-lan-pairing.txt` with one
    deterministic session handshake: link key `0x66`×32, `nonce_I`
    `0x77`×32, `nonce_R` `0x88`×32, X-Wing draft-11 vector 1;
  - list `K_i`, `K_r`, the hello body, the hello, H(hello), the accept
    transcript, the accept, H(accept), `th`, `k_i2r`, `k_r2i` and the
    confirm plaintext;
  - add the address QR for `[192.0.2.10:7777, [2001:db8::10]:7777]`;
  - extend `crosscheck_lan.py` to recompute them;
  - fuzz: `lan_message` gets the new typed decoders; `lan_oob` gets
    `decode_addr_qr` and `parse_endpoint`, with round trips.
- **Files:** `crates/qv-sync/src/lan/vectors.rs`, `crates/qv-sync/tests/vectors/{qv-dev-lan-pairing.txt,crosscheck_lan.py}`, `fuzz/fuzz_targets/{lan_message.rs,lan_oob.rs}`.
- **Done when:** the Rust vector test passes, the Python check prints OK,
  and both fuzz targets run 60 s clean.
- **Verify:** `cargo test --locked -p qv-sync lan_vectors`; `python3 -I crates/qv-sync/tests/vectors/crosscheck_lan.py`; `cargo +nightly-2026-10-01 fuzz run -s none <target> -- -max_total_time=60 -use_cmp=0`.

### Step 8 — CLI `qvault lan`

- [x] **Do:** `crates/qv-cli/src/cmd/lan.rs` and the clap definitions:
  - **`pair --label <name> [--port <n>] [--minutes <1-10>]`:**
    - unlock; stdin and stdout must be TTYs, and `--password-stdin` is
      refused (exit 2);
    - on the alternate screen: the manual code, the endpoints (from
      `local_addresses()` and the port) and the time limit;
    - on a hello: the SAS, the mode, the escaped vault name, and the prompt
      `Do both devices show <123 456>? [y/N]`;
    - after leaving the alternate screen, print `paired: <link-id>`,
      `peer receipt: confirmed|unconfirmed` and, for link mode, the sync
      lines.
  - **`join --endpoint <ip:port>... --label <name> [--new <path>]`:**
    - the code comes from a no-echo prompt; TTY required;
    - link mode on the selected vault: show `comparison code: <123 456>`
      and ask to confirm that both screens match; then the sync lines;
    - `--new`: the path must not exist (checked before pairing, exit 2 if
      it does). Show the code during the transfer, then ask `Join vault
      "<name>"? Comparison code <123 456> [y/N]`, then the master password
      prompt (retried on a wrong password), then
      `created: <path>`.
  - **`receive [--port <n>] [--minutes <1-15>] [--stay]`:**
    - print the endpoints and the time limit;
    - per round, the sync lines;
    - exit 0 after at least one completed round. Expiry with none is
      exit 10.
  - **`sync --endpoint <ip:port>... [--link <6-32 hex>]`:**
    - the link is the only link or the prefix match: none → 4; several
      without `--link` → 5, listing the matches.
  - **`links [--json]`:** the ID, escaped label and creation time. JSON:
    `{"links":[{"id":hex,"label":str,"created_at":ms}]}`.
  - **`unlink <6-32 hex> [--yes]`:** confirm, `removed: <id>`, and a note
    that the other device is not notified.
  - **Sync lines:** `local acceptance: committed|unchanged`, `conflicts: N`,
    `peer receipt: confirmed|unconfirmed`. A durable commit followed by a
    later failure prints the lines first, then the error.
  - `--json` is refused on every interactive subcommand (exit 2).
  - SIGINT/SIGTERM and the session lock cancel through the existing signal
    token.
  - The exit mapping follows decision 4 in `exit.rs`.

  Integration tests:
  - two vault directories, one `receive` and one `sync` process, over the
    first non-loopback local address. If none exists, the test fails with
    an explicit message, never a silent pass;
  - usage errors;
  - `links`/`unlink`;
  - `--password-stdin` refusal;
  - no code in argv (the code is supplied through the TTY harness
    already used by the credential tests);
  - exit codes 4, 5 and 10.
- **Files:** `crates/qv-cli/src/{cli.rs,exit.rs,cmd/mod.rs,cmd/lan.rs,term.rs}`, `crates/qv-cli/tests/lan.rs`.
- **Done when:** the tests pass; `qvault lan --help` matches 0011.
- **Verify:** `cargo test --locked -p qv-cli lan`.

### Step 9 — App Devices pane and join

- [x] **Do:** shared Dioxus screens through core only.
  - **Devices pane** in Settings: the link list (label and date), *Remove*
    (with confirmation), *Pair a device*, *Link an existing copy*,
    *Receive* and *Sync with …* (the link plus a typed endpoint).
  - **Pairing window:** the manual code (protected display, cleared on
    close), endpoints, the countdown and *Cancel*; then a SAS modal with
    the code, mode and vault name, *Codes match* / *Cancel*.
  - **Join from another device** on the locked screen: code, endpoint and
    label inputs (bounded; code at most 64 bytes), plus the destination
    (Linux path input, Android app-private default). Then the code shown
    during the transfer, the vault-name confirmation and the master
    password; ends unlocked.
  - **Blocking callbacks:**
    - `ApproverUi`/`JoinerUi` run on the operation thread. They post a
      prompt state and wait on a condvar for the user's answer or for
      cancel or lock;
    - every prompt ends on cancel (0037 found that core cannot interrupt
      a prompt);
    - a window or round started from the app ends on lock and on Android
      pause (decision 9).
  - **Outcome text:** local acceptance and peer receipt separately, plus
    the conflicts count.

  Tests:
  - workspace tests for the new actions and states (prompt answer,
    cancel, lock while waiting, busy refusal, input bounds and cleanup);
  - one real-engine flow on Linux that pairs two app controllers over
    loopback in validation builds. If the harness cannot host two
    controllers, pair against a core window in the same process instead.
- **Files:** `crates/qv-app/src/{controller.rs,workspace.rs,ops.rs,views.rs,ui/workspace.rs,ui/mod.rs,workspace_tests.rs,bin/flow.js}` (as needed).
- **Done when:** app tests and validation-feature tests pass. Android arm64
  Clippy passes for `mobile` and `mobile,validation`. The APK builds.
- **Verify:** `cargo test --locked -p qv-app`; `cargo test --locked -p qv-app --features validation`; Android Clippy per the 0037 test plan.

### Step 10 — Documentation and roadmap

- [x] **Do:**
  - `ARCHITECTURE.md` §3 rows (qv-sync, qv-platform, qv-core, qv-cli,
    qv-app) and the 2.10 paragraph;
  - `CHANGELOG.md` Unreleased;
  - the roadmap: tick 2.10, add the plan link, add a Revisions entry for
    phase 2.10b (decision 2) with its phase entry, and an execution log
    entry;
  - the `plans/README.md` row.
- **Files:** as listed.
- **Done when:** the documentation-duties table is satisfied.
- **Verify:** `sh scripts/check-spdx.sh`.

## Test plan

- **Final verification:**
  - all `AGENTS.md` gates on the final tree (SPDX, matrix, fmt, workspace
    Clippy, `cargo test --locked` with private Xvfb);
  - app validation tests;
  - Android arm64 Clippy for both feature sets and an APK build;
  - fuzz smoke for `lan_message` and `lan_oob`;
  - the Python crosscheck;
  - `cargo deny`/`vet` only if `Cargo.lock` changes. It must not, since
    there is no new dependency.
- **Unit and property tests:** steps 2–4, with proptest no-panic for every
  new decoder.
- **Rejection and crash paths:** steps 4–6 (staging refusals, acceptance
  crash points, interruption at every turn).
- **Vectors:** the step 7 development vectors with the independent Python
  check (0013 Testing: byte-level interoperability; not final).
- **0012 §1 rows:**
  - *Account-dependent LAN sync*: loopback convergence tests (steps 5–6),
    the CLI two-process test over a LAN address (step 8), and an
    **attended run**. The attended run is a Linux CLI plus the phone app,
    with the router's Internet uplink disconnected (or the phone in
    airplane mode with Wi-Fi on), pairing and syncing from either side.
    It is recorded as pending until the owner runs it;
  - *LAN partial acceptance*: steps 4–5;
  - *LAN discovery mistaken for trust*: step 5's session tests;
  - *Unrequested synchronization (LAN)*: tests that unlock, edit and
    window close start no connection (a listener that must see none).

  The offline matrix list is unchanged.

## Risks and stop conditions

- **Stop if:**
  - a 0013 requirement cannot be met as written apart from the step 1
    amendments (for example, the turn order or "no KEM before the tag");
  - `accept_incoming` cannot be generalized without weakening a check or
    adding a second commit path;
  - prompt cancellation cannot be made prompt with the 100 ms slices;
  - the app's single-operation model cannot host a blocking round with
    prompts without a redesign of the controller.
- **Never:**
  - start a round or window without a user action;
  - send before the tag or accept MAC verifies;
  - insert peer bytes into SQLite before full verification;
  - put the pairing code in argv, env, logs or `Debug`.
- **Device evidence:** the attended two-device run needs the owner's
  phone. Without it, the phase stays unticked, as in 2.6/2.7.
- **Not a security proof:** no D12 review yet; no LAN release.

## Documentation

- [x] `CHANGELOG.md`: Unreleased entry (LAN sync usable from the CLI and the
  app; exit code 10; QR scanning in 2.10b)
- [x] `ARCHITECTURE.md`: §3 rows and the 2.10 paragraph; §6 LAN row
  (addresses from route probes)
- [x] Specs: 0013 §3.1/§5.1/§7.4/§8.5 and 0011 §3.2/§4/§6, with Changelog
  lines and `specs/README.md` notes; statuses unchanged
- [x] `AGENTS.md`: no change
- [x] Roadmap 0002: plan link, 2.10b Revisions entry and phase entry,
  execution log; `plans/README.md` row
- [x] Roadmap 0002: tick reviewed 2.10 implementation; owner moved its
  remaining attended offline Linux/phone run to plan 0039 step 6

## Revisions

- 2026-11-03 (during implementation; details in the log):
  - `ExchangeVault::scope` replaces the sketched `InitiatorVault` and
    `ResponderVault::context`;
  - `UnlockedVault::lan_stage` stages in the vault's own anchor directory
    and takes no directory;
  - `RoundReport.failure` and `ReceiveWindow::run`'s `Result`;
  - the app's idle lock skips a running LAN operation (decision 9
    extended);
  - the real-engine flow covers one controller (the Devices screen and a
    cancelled pairing window), while the headless tests pair two
    controllers.

## Execution log

- 2026-11-03: Planned in the next-phase session after the fresh-context
  review of 0037 (Approved with minor fixes). Approved under the roadmap's
  standing approval together with the owner's standing delegation
  (2026-11-02). The delegation covers:
  - the 0013/0011 amendments (the 0013 QR amendment is also owner-directed,
    2026-11-03);
  - the 2.10b split (decision 2);
  - the no-dependency address discovery (decision 3).

  No new dependency, no `unsafe`.

- 2026-11-03: Step 1 done. 0013 gains §8.5 (the address-only code and its
  text form), the §3.1 pointer, the §5.1 single-link rule and the §7.4
  `Want` bounds. 0011 gains the LAN command contracts, the sync lines, the
  §3.2 `--password-stdin` note and exit code 10 with the LAN mapping. Both
  have Changelog lines (owner-delegated), and `specs/README.md` has a note.
  Statuses unchanged.

- 2026-11-03: Step 2 done. `LinkKey::session_auth`, `SessionAuth`
  (hello/accept MAC and verify) and `session_record_keys`; `vectors` gains
  `session_auth` and `link_key_from` (test/test-vectors only). The new test
  recomputes every value with direct HKDF/HMAC over hand-built CBOR, checks
  the `i`/`r` reflection refusal, and confirms that each input changes both
  record keys. `cargo test -p qv-crypto lan`: 10 passed.

- 2026-11-03: Step 3 done. `SyncHello`, `SyncAccept`, `session_th_input`,
  `Confirm` and `MAX_WANT_MESSAGES` in `lan.rs`. In `oob.rs`:
  `encode_addr_qr`/`decode_addr_qr`, `parse_endpoint`/`format_endpoint`,
  and a shared endpoint reader/writer that the pairing QR now uses too.
  Tests cover hand-built spec bytes, shape and range refusals (zone IDs,
  hostnames, ports, lengths) and proptest no-panic for the new decoders.
  `cargo test -p qv-protocol`: 26 passed.

- 2026-11-03: Step 4 done.
  - `LanStaging` now carries a plan of `(ObjectId, Planned::{Local, Peer})`.
    `begin` (new device) plans every object as Peer; `wanted()` became
    `requested()`.
  - `UnlockedVault::{lan_stage, lan_stage_local, lan_finish, accept_lan,
    manifest_hash}`. A shared private `StagedArchive` sits under
    `VerifiedIncoming` and `VerifiedLanStaging`. `accept_incoming` and
    `accept_lan` share one body (`accept_staged`) with an optional receipt.
    Without a receipt, a candidate equal to the current manifest returns
    `false` and commits nothing.
  - `lan_object_envelope` and the local copies share `local_envelope`.
  - New tests:
    - merge staging plans the common objects as Local and requests only
      the new ones; acceptance writes no receipt;
    - the same state twice, or the vault's own state, commits nothing;
    - a substituted reference → `Integrity` before staging;
    - a vanished local row → `NotFound`; a peer object in a local slot is
      refused;
    - the crash matrix (`Begun` … `AnchorReplaced`) reopens to old or new.
  - Not tested: "foreign configuration → Unsupported". With one registered
    profile no other configuration digest can be built; the check stays,
    shared with new-device staging.
  - `cargo test -p qv-store`: 239 passed.

- 2026-11-03: Step 5 done.
  - New modules:
    - `session.rs`: pure §5 steps;
    - `window.rs`: the acceptor, moved out of `approver.rs` and shared;
    - `receiver.rs`: `ReceiveWindow`, `ResponderVault`, `WindowEnd`;
    - `initiator.rs`: `sync`.
  - The general `exchange` lives in `exchange.rs`. The new-device
    serve/receive now use its shared turn helpers: the bounded `Want`
    loop (≤ 62 messages, no empty non-final `Want`), and B's `Done`
    outcome checked as 1.
  - Interface details beyond the sketch:
    - `ExchangeVault::scope` replaces the planned `InitiatorVault` and
      `ResponderVault::context`;
    - `RoundReport.failure` records a failure after this side's commit;
    - `ReceiveWindow::run` returns `Result<WindowEnd, LanError>`;
    - `ApproverVault::grant` returns the sealed record, and the driver
      sends it after the call (0037 finding 4);
    - `Approved.round` and `JoinedLink` carry the §4.8 follow-up exchange.
  - Connection attempts use `transport::connect`, a cancellable helper
    thread (decision 10), for joiners and initiators.
  - The `Confirm` check is a plain comparison: `th` is computed from
    cleartext messages and is not secret.
  - Found and fixed during the step: a cancel or lock took effect only
    when socket I/O blocked, so a fast loopback round could complete after
    a cancel. `Conn` and `Channel::send` now check the cancel before every
    frame, and before sealing, so no sequence number is skipped. Abort
    records bypass the check, so the peer still learns `cancelled`.
  - New `lan_sync_*` tests (11):
    - convergence from either initiator, an idempotent retry, conflicts;
    - responder failure while serving and a cancel mid-round, with nothing
      accepted;
    - a responder failing at acceptance, with the initiator's commit kept
      and receipt unconfirmed; then the retry completes the other side;
    - wrong link, replayed hello, wrong confirm, a link removed while the
      window is open;
    - spoofed and reflecting responders skipped;
    - responder refusals: vault mismatch, > 64 MiB, length 0, an unknown
      ID, an empty non-final `Want`, a 63rd `Want`;
    - window failures, expiry, stay-open with an extra connection dropped;
    - cancel during a connect attempt.

    The new-device exchange test gained a `Done(Unchanged)` refusal.
  - `cargo test -p qv-sync lan`: 27 passed, three runs in a row. qv-sync
    Clippy is clean.

- 2026-11-03: Step 6 done.
  - `qv_platform::net::local_addresses` uses route probes (decision 3);
    two tests (the filter, and bounded and showable results on this host).
  - qv-core:
    - `Session::{open_receive_window, sync_lan}`, `ReceiveWindow::{code,
      expires_at, run}`;
    - `ReceiveOptions`, `SyncOptions`, `SyncReport`, `LocalAcceptance`,
      `ReceiveCode`, `ReceiveEvent`, `ReceiveReport`, `JoinLinkReport`,
      `ApproveReport.sync`, all with redacted `Debug`;
    - `local_addresses` and the window constants re-exported.
  - One `SessionExchange` serves the approver, joiner and responder
    adapters through a delegation macro.
  - Its `accept` runs the ordinary automatic snapshot, then one `mutate`:
    `lan_finish`, `accept_lan` with `qv_sync::merge`, and the `Index`
    rebuild as in `merge_archive`. A completion error after a commit is
    kept for the report.
  - The grant is sealed inside the session read and sent after it (0037
    finding 4).
  - Deviation: `UnlockedVault::lan_stage` takes no directory and stages in
    the vault's own private anchor directory, as new-device staging does.
    A session exposes no other private directory, and passing the anchor
    path through core would only duplicate it.
  - `LanError::from_staging` became public for core's mapping.
  - Tests (`lan_core_*`, 4 new, 11 in total):
    - convergence both ways;
    - an unchanged round;
    - a conflict reported on both sides;
    - a removed link → `NoPeer`;
    - a lock closes the window within 2 s;
    - `StaleHandle`;
    - an over-limit window;
    - a recovery session refused for both receiving and syncing;
    - the ordinary snapshot added only after the interval passed.
  - The link-mode test also checks the follow-up round.
  - Not separately tested: "old-link sync after rotation → NoPeer". The
    rotated replacement has no links (already tested), so its window
    refuses every tag, the same path as the removed-link test.
  - Workspace Clippy is clean.

- 2026-11-03: Step 7 done.
  - The vectors file gained the §5 session handshake (link key `0x66`×32,
    `nonce_I` `0x77`×32, `nonce_R` `0x88`×32, X-Wing draft-11 vector 1)
    and the address QR. `crosscheck_lan.py` recomputes them: "OK: 34
    values recomputed independently". The Rust vector test passes, and a
    second render is identical.
  - Fuzzing:
    - `lan_message` also runs `SyncHello`, `SyncAccept` and `Confirm`;
    - `lan_oob` gained `decode_addr_qr` and `parse_endpoint` with round
      trips (the first byte now selects one of four decoders).
  - Local runs (nightly-2026-10-01, cargo-fuzz 0.13.2, `-s none`,
    `-use_cmp=0`, 60 s): `lan_message` 4,461,700 runs, `lan_oob`
    68,168,420 runs, no crash. The fuzz lockfile is unchanged.

- 2026-11-03: Step 8 done. `crates/qv-cli/src/cmd/lan.rs` implements the
  amended 0011 contracts.
  - `pair`: alternate-screen code and endpoints; SAS confirmation on the
    TTY.
  - `join`: hidden code prompt; link mode, or `--new` with the destination
    checked before pairing, vault confirmation and password retry.
  - `receive`: endpoints and per-round lines; exit 10 without a round.
  - `sync`: link selection with exit 4 or 5.
  - `links` (with `--json`) and `unlink` (confirmation or `--yes`).
  - `exit.rs` maps every `LanError` (decision 4), with a test row for each.
  - `qv_core::parse_endpoint` (re-exported from qv-sync) parses
    endpoints, so the CLI depends only on qv-core.
  - `tests/lan.rs`, 4 tests:
    - two CLI processes over this host's LAN address (B `receive`, A
      `sync`; B commits A's entry, A unchanged, peer receipt confirmed);
    - usage refusals before unlock and exit codes 2, 4, 5, 10;
    - links JSON, unlink;
    - interactive `pair`: the code appears only before the alternate
      screen is left, and both sides confirm the same SAS;
    - interactive `join --new`: an existing destination → 2, a lowercase
      code accepted, the code not echoed, a wrong password retried.
  - `cargo test -p qv-cli`: 100 passed. qv-cli Clippy is clean.

- 2026-11-03: Step 9 done. `crates/qv-app/src/lan.rs`:
  - One `LanRun` in the controller state carries the kind, a protected copy
    of the pairing code, endpoints, the countdown, the current `Question`
    and the outcome. Every lock closes it (cancel token plus the end of
    every wait).
  - A worker-side `Bridge` implements `ApproverUi`/`JoinerUi`: it posts a
    question and waits on a condvar. The renderer calls
    `lan_answer`/`lan_secret`/`lan_cancel`/`lan_dismiss`, which work while
    the single worker is busy, because it is waiting for exactly that
    answer.
  - Workspace: `Screen::Devices`, `WsField::{LanCode, LanEndpoint,
    LanLabel}`, `WsAction::{LanPair, LanReceive, LanSync, LanLink,
    LanRemove}` and `ConfirmKind::RemoveLink`.
  - Locked screen: `Mode::Join`, `Action::JoinDevice` and three new inputs.
    The new-device join runs on the vault worker and ends unlocked.
  - UI:
    - the Devices screen;
    - a `LanPanel` with the code, endpoints, countdown, the
      compare/join/password dialogs and Cancel/Dismiss, shown while busy
      and on the locked screen;
    - the Join tab.
  - Deviation (decision 9): the 60-second idle lock skips a running LAN
    operation. Found in self-review: otherwise a pairing window waiting for
    a hello would lock after a minute. The window's own limit bounds it.
    Android's background expiry still locks, which closes it.
  - Loopback is used only under `cfg(test)` (`TEST_LOOPBACK`).
  - Tests (`lan_app_*`, 3):
    - a new-device join through the locked screen, with matching codes on
      both screens, a wrong password retried and the framework string
      cleared; then a sync both ways through the Devices screen, and a
      remove with its confirmation;
    - cancel ends a pairing window within 3 s and removes the code; a
      waiting window survives the idle lock; lock ends a receive window;
      bad inputs are refused;
    - a join refused by the approver creates nothing.
  - The real-engine flow (`flow.js`, stage 64) opens Devices, shows a
    pairing code, checks that navigation is disabled during the window,
    cancels and dismisses. Forcing that stage to fail fails the engine
    test, so it runs.
  - Not done: a real-engine flow pairing two app controllers. The harness
    hosts one controller, and the app never dials loopback outside tests.
    The headless tests above pair two real controllers instead.
  - `cargo test -p qv-app`: 30 passed; with `validation`: 34 passed;
    `--test engine`: 3 passed. App and validation Clippy are clean, and
    Android arm64 Clippy passes for `mobile` and `mobile,validation`.

- 2026-11-03: Step 10 done:
  - ARCHITECTURE §3: the qv-crypto, qv-store, qv-protocol, qv-sync,
    qv-core, qv-platform and qv-cli/qv-app rows, the 2.10 paragraph and
    the trust note; §6: the LAN row;
  - CHANGELOG: an Unreleased entry;
  - roadmap: the 2.10 plan link, the new phase 2.10b entry, 2.10a now
    depending on 2.10b, and a Revisions entry;
  - specs: done in step 1.

- 2026-11-03: All steps done; status Implemented. Final verification:
  - Full gates on the tree after step 10 (private Xvfb): SPDX, matrix,
    fmt and workspace Clippy pass; `cargo test --locked`: 862 passed,
    0 failed, 2 ignored (pre-existing); `crosscheck_lan.py` OK.
  - After that run only qv-app changed: the idle-lock exemption, found in
    self-review, and its test. A first version ended the exemption at
    cancel, and the new test caught the idle lock firing before the
    outcome; fixed by counting a run as running until its outcome exists,
    with cancel and dismiss counting as activity. Rerun on the final tree:
    - fmt, workspace Clippy and app-validation Clippy pass;
    - `cargo test -p qv-app`: 30 passed; with `validation`: 34 passed;
      `lan_app_*` twice;
    - SPDX and matrix pass;
    - Android arm64 Clippy (`mobile`, `mobile,validation`; app, core,
      sync, store, crypto, protocol, platform) passes;
    - the APK builds (Dioxus CLI 0.7.10, SHA-256
      `f97b1cdba21ea3b248acd06bd49f1e072ef7e1d2f7017755e1c329c8ab49e036`;
      built only, not installed);
    - the real-engine tests (`--features validation --test engine`, 3)
      passed before the idle change, which touches no rendering.
  - Fuzz smoke (step 7): `lan_message` and `lan_oob`, 60 s each, clean.
  - `Cargo.lock` and `fuzz/Cargo.lock` are unchanged, so deny/vet are not
    rerun (no dependency change).
  - **Pending, attended:** the 0012 §1 "Account-dependent LAN sync"
    two-device run. The Linux CLI or app and the phone app pair and sync
    from either side, with the router's Internet uplink disconnected or
    the phone in airplane mode with Wi-Fi on. This needs the owner's phone
    and network, so the roadmap box for 2.10 stays unticked.
  - Found, not fixed:
    - a cancel that lands between sealing the grant and sending it makes
      the peer see `integrity` instead of `cancelled`. The window is tiny,
      and the round aborts either way;
    - the app shows the pairing code and endpoints as text only until
      2.10b renders the QR codes.

  No commit, push or branch.


- 2026-11-03: Fresh-context next-phase review of committed `92aa8c4`:
  **Re-plan needed**; see REVIEW.md. Blocking findings: unbounded app prompt
  waits suppress idle locking, active receive exchanges outlive window expiry,
  app completion errors are discarded, and lock can hide a durable acceptance
  report. Two temporary diagnostics reproduced the expiry defects and were
  removed; no product change retained. Status remains Implemented per reviewer
  workflow, not Reviewed. Phase 2.10b must wait for the repair and validation.
  SPDX/matrix/fmt/Clippy pass. Workspace tests fail at two CLI clipboard tests
  because Xvfb is absent. No phone is attached; attended validation is pending.

  Review verification completed: focused tests for crypto, protocol, store,
  sync, core and platform plus CLI LAN integration pass (see REVIEW.md for
  totals); Python independently recomputes 34 vector values. Final SPDX,
  matrix, fmt and workspace Clippy checks pass after diagnostic sources were
  removed. Full workspace tests remain failed due to missing Xvfb; no test
  was weakened or skipped to claim a passing gate. Retained changes are
  review documentation only, including CHANGELOG and roadmap/index notes.


## Repair revision — 2026-11-03

Owner authorization: “do whatever you think is best” after the blocking review.
This authorizes revising and repairing 0038 on the present tree without another
commit or approval boundary. No new dependency, unsafe, format or crypto change.
The completed steps above remain historical. Review findings 1–4 are the scope.

Requirements: Accepted 0013 §1.3, §7.6–7.7, §8.2; 0004 §5; roadmap-approved
0005 §6.5 and 0008 §1.4. No spec amendment is required: these repairs enforce
existing lifetime and reporting contracts. The previous idle exemption is
narrowed: only a listening Pair/Receive run with a future absolute expiry and
no pending question can defer inactivity. Prompts, joins and initiated sync use
the normal 60-second inactivity timeout; callbacks enforce it even if rendering
stops. Expiry closes the run and erases its code and typed password.

### Repair A — Transport and acceptance lifetime

- [x] **Do:** add an optional persistent absolute cap to private `Conn`, set
  once for pairing and receive connections (including probes), and clamp every
  subsequent message deadline to it. Check deadline/cancel before every actual
  socket read/write, including immediately successful operations. Acceptor
  threads own their listeners so expiry drops the listener independently of
  local processing or frontend callbacks. Core `SessionExchange` stores the
  caller cancel token and optional window expiry, and combines them with the
  session canceller throughout staging completion, merge and commit. Snapshot
  coalescing receives the same cancellation/expiry predicate through a private
  helper in `qv-core/src/snapshot.rs`; acceptance rechecks expiry after it.
  Preserve objects → manifest → head → COMMIT → anchor ordering and durable
  reports if expiry/cancel happens after commit. No public signature changes.
- **Files:** `crates/qv-sync/src/lan/{transport,receiver,approver,sync_tests,tests}.rs`,
  `crates/qv-core/src/{lan,lan_tests,snapshot}.rs`.
- **Done when:** an authenticated peer cannot resume after expiry; ready I/O
  cannot bypass deadlines; cancelled/expired acceptance commits nothing before
  its commit boundary. Expiry drops the listener; pairing follow-up shares cap.
- **Verify:** `cargo test --locked -p qv-sync lan`; `cargo test --locked -p qv-core lan`.

### Repair B — Reports survive lock and app errors remain visible

- [x] **Do:** save conflict count and completion state within core acceptance;
  capture the initial count when constructing the exchange for equal-state
  rounds. `report` uses saved metadata only, with no session read. Make app
  round rendering build `LanDone` with both lines and `completion_error`,
  including receive and pairing follow-up; retain pairing transfer failures.
- **Files:** `crates/qv-core/src/{lan,lan_tests}.rs`,
  `crates/qv-app/src/{lan,lan_tests}.rs`.
- **Done when:** lock between commit and reporting preserves local acceptance;
  app shows committed result plus completion failure rather than success alone.
- **Verify:** focused core/app regression tests, then package test suites.

### Repair C — Bounded frontend prompts and idle exemption

- [x] **Do:** remove automatic keep-alive activity updates from callback waits.
  Poll run expiry and real inactivity while waiting (drop the reply mutex
  before touching controller state); expiry closes and clears the run, idle
  locks the controller. Only future-expiry listeners with no question defer
  inactivity; never Sync/Link/Join or an unanswered prompt. Tests use synthetic
  expired Instants instead of waiting minutes. Add regressions for prompt
  expiry/idle, clearing secrets, sync idle locking, and existing cancellation.
- **Files:** `crates/qv-app/src/{lan,controller,lan_tests}.rs`.
- **Done when:** no pending callback outlives its run expiry or idle timeout,
  regardless of UI polling; cancellation remains prompt and deadlock-free.
- **Verify:** `cargo test --locked -p qv-app`; validation-feature tests when the
  environment can build desktop dependencies.

### Repair D — Verification and records

- [x] **Do:** run all AGENTS gates on final source, app validation/real-engine
  and Android checks where available; resolve missing Xvfb using an isolated
  test dependency setup if possible. Record environmental blockers accurately.
  Update CHANGELOG, roadmap, index and this log; append repair evidence to the
  review without converting it into a fresh-context approval. Phase 2.10 stays
  unticked until attended offline LAN evidence is supplied. No D12 release claim.
- **Files:** plan/review, `plans/{README.md,0002-roadmap/PLAN.md}`, `CHANGELOG.md`,
  `ARCHITECTURE.md` (existing LAN paragraph).
- **Done when:** all available checks pass and limitations are explicit; repair
  status is Implemented, awaiting fresh-context review and device evidence.
- **Verify:** SPDX, matrix, fmt, workspace Clippy, `cargo test --locked`; no
  dependency change, so no deny/vet requirement.

Stop only for a new unresolved security/design issue outside these choices.

- Repair implementation refinement, 2026-11-03 (owner-delegated): the CLI
  approver's TTY wait has the same window-expiry gap as the app callback.
  Include `crates/qv-cli/src/{term.rs,cmd/lan.rs}` in repair A/C, adding an
  optional absolute deadline to private Tty prompts and bounding the pair
  approver by the window's expiry. This enforces the existing 0013 §8.2
  contract; no command, exit-code, wire or public API change. Add a PTY
  timeout/restoration test and rerun CLI checks and final gates.


- 2026-11-03: Repairs A–C implemented under the owner's delegation. The
  transport carries an absolute cap across handshake, exchange and abort
  attempts, checks ready reads/writes as well as timeout retries, and drops
  each listener on its acceptor thread's exit. Worker disconnect races now
  preserve the expiry/cancel classification. Core propagates token/expiry
  through staging, snapshot copying and acceptance, retaining commit ordering.
  Report metadata survives lock; the app retains completion errors and local
  acceptance lines, including pairing follow-up. Callback waits no longer
  refresh inactivity; they check expiry and idle without renderer polling.
  Only a future-expiry listener without a question defers idle lock.

  Added regressions cover ready I/O after deadline reset; authenticated
  receive expiry and listener closure; core cancellation/expiry before
  acceptance; an actual commit followed by lock before reporting; prompt
  expiry/idle secret cleanup without UI polling; idle exemptions by operation
  kind; app completion-error lines; and CLI PTY deadline/restoration.
  Focused results: qv-sync LAN 29 pass, core LAN 13 pass, app 32 pass.
  App validation (33 unit checks plus three real-engine flows) passes; final reruns
  after the CLI/prompt refinement are recorded below. Android arm64 Clippy
  passes for mobile and mobile,validation (existing upstream vendor warnings
  unchanged). APK build refuses available dx 0.8.0-alpha.0: pinned 0.7.10
  is required. No phone connected; attended evidence remains pending.

  Verification setup: fetched signed Alpine xvfb packages with `apk fetch`,
  extracted to `/tmp/qv-xvfb-root` without system installation, and selected
  its executable through `QV_TEST_XVFB`. This resolves the initial review's
  missing-Xvfb failure without skipping tests. Installed the pinned
  toolchain's Android std target for cross-checking; no repo dependency,
  lockfile, compiler pin or vendor patch changed.

  Final lifetime audit also applies the same predicate to pairing-link
  `commit_cancellable` and grant construction, so a deadline crossing after
  proof verification cannot commit a link or encode a grant. The existing
  core cancellation/expiry regression now covers these paths and asserts
  no sequence advance and no grant-sealer invocation.

  The CLI approver's bounded TTY also polls the session lock predicate;
  a separate PTY regression checks cancellation and terminal restoration.
  This completes the existing frontend callback cancellation contract as
  part of the authorized lifetime repair, with no global signal mutation.


  The default-parallel final-tree workspace run hit an unchanged platform
  test failure: `linux::instance::tests::instance_contention_release_and_unsafe_paths`
  returned Busy at the immediate post-drop reacquisition (instance.rs:91).
  It passes in isolation without changes. A possible explanation is transient
  flock inheritance by a concurrent test's fork-before-exec child; this is
  an inference, not established root cause. Preserve this failure in
  `/tmp/qv-0038-repair-complete-gates.log`; do not weaken the assertion or
  silently label the parallel gate passed. Final full rerun uses
  `RUST_TEST_THREADS=1` to isolate test subprocess activity, with every test
  and assertion retained. This does not claim parallel-test stability.
  The final CLI package run passes all 102 tests; app validation passes
  33 unit tests and three real-engine flows; Android arm64 Clippy passes
  both feature sets after the core link-commit refinement.


- 2026-11-03: Repair D complete; status Implemented. Final verification:
  - SPDX, matrix, fmt and workspace Clippy pass.
  - `RUST_TEST_THREADS=1 QV_TEST_XVFB=/tmp/qv-xvfb-root/usr/bin/Xvfb cargo test --locked`:
    870 passed, 0 failed, 2 pre-existing ignored. Every test/fixture
    assertion is retained. The default-parallel instance-lock failure above
    remains an explicit test-isolation limitation, not a repaired production
    defect or a claimed passing parallel run.
  - Final CLI package run: 102 passed. Final app validation: 33 unit tests
    plus 3 real-engine flows passed. Android arm64 Clippy passes for both
    mobile and mobile,validation after the last core changes.
  - Python vector crosscheck: 34 values independently recomputed, OK.
  - No dependency/lockfile changes; deny/vet not applicable.
  - APK packaging refused the available dx 0.8.0-alpha.0; pinned 0.7.10
    is required. `adb devices` is empty. APK and attended offline-LAN
    evidence are not claimed; phase 2.10 stays unticked and 2.10b has not begun.
  - Fresh-context review is still required. This developer repair supplement
    does not approve its own implementation; REVIEW.md retains its original
    verdict and adds the implementation/verification evidence.

  Final logs: `/tmp/qv-0038-repair-serial-gates.log`,
  `/tmp/qv-0038-repair-cli-final.log`,
  `/tmp/qv-0038-repair-complete-validation.log`,
  `/tmp/qv-0038-repair-complete-android.log`,
  `/tmp/qv-0038-repair-apk.log`. Earlier full runs were superseded during
  iteration; only the final-tree serialized run supplies the passing full
  gate evidence. No commit, push, branch or staging change.

### Fresh-review verification repair — 2026-11-03

Owner authorization: the current “next phase” request delegates architectural
choices without another approval. Complete step 9's existing core-peer fallback
instead of treating the cancelled-window engine flow as completed pairing.
This adds validation-only fixture code, with no production behaviour, dependency,
wire, storage or cryptographic change.

- [x] **Do:** extend the Linux synthetic WebKit flow to start a core new-device
  joiner only after an explicit fixture event in an already-open pairing window.
  The peer checks the same SAS as the real controller's approval question;
  JavaScript clicks the rendered approval button and checks the confirmed
  outcome and cleared code. Verify the peer's vault name/link and lock it;
  require successful peer completion before the fixture can pass. Keep the
  existing cancel/cleanup assertions. Use only synthetic secrets and a newly
  owned private fixture directory; cancellation follows the window token.
- **Files:** `crates/qv-app/src/{lan.rs,controller.rs,ui/mod.rs,bin/flow.js}`;
  review, execution log, changelog and roadmap/index notes.
- **Done when:** both synthetic and real-Linux WebKit flows complete pairing
  through the rendered approval control, and cancellation still clears it.
- **Verify:** `cargo test --locked -p qv-app --features validation --test engine`;
  validation Clippy; final required gates. Reuse this session's full workspace
  test result for unchanged default-feature sources; rerun affected checks
  after edits. Do not repeat historical fuzz or expensive unchanged KDF suites.

The attended Linux/phone run remains required by this plan and the roadmap.
No device is currently attached; neither an engine test nor an APK build is
substituted for that evidence. Do not tick 2.10 or start 2.10b without it.

- 2026-11-03: Fresh-context review of clean committed `138bdde` completed:
  **Approved with minor fixes**, status Reviewed (see REVIEW.md). All four
  original findings are closed. The remaining step-9 engine fallback now
  completes a pairing through the rendered comparison-code button against a
  real core joiner, checks the same SAS and confirmed receipt, clears the
  displayed code/SAS and verifies that the peer opened the transferred vault.
  The old cancellation assertions remain. Fixture code is restricted to Linux
  validation builds and an explicitly started synthetic flow; no production,
  protocol, storage, dependency or vendor change.

  Verification:
  - One full serialized workspace run: 870 passed, 0 failed, 2 pre-existing
    ignored (`RUST_TEST_THREADS=1 QV_TEST_XVFB=/tmp/qv-0038-review-xvfb/root/usr/bin/Xvfb cargo test --locked`).
    Runtime reported by suites totals about 11 minutes. It began before the
    validation-only fixture addition; unaffected crate results are retained.
  - After the addition: current app library tests 32 passed; validation engine
    tests 3 passed, including both synthetic-OS and real-Linux pairing flows.
    Workspace and validation Clippy, SPDX, matrix, fmt and diff checks pass.
    The independent Python crosscheck recomputes all 34 vector values.
  - Early engine runs failed on the synthetic peer's unsupported `.qv` suffix;
    corrected to `.qvault`, with all transfer/open assertions preserved. Those
    failure logs are superseded only for the affected flow by the final passing
    engine run. No unchanged fuzz campaign or second full KDF/rotation suite.
  - The pinned Dioxus 0.7.10 CLI is available through an isolated `/tmp` runtime;
    official release archive digest checked. The initial loader wrapper could
    not support the CLI's Rust self-invocation; setting the temporary binary's
    ELF interpreter/RPATH resolves it without changing repository dependencies
    or the system installation. Final Android packaging passes (app/test APKs).
    Product APK SHA-256:
    `5dbba78f1190ab283ef15c36f1b3e4a873cc4e2691dece09096e62728f01b9ef`.
    No device install; subsequent source changes are Linux validation-only.
  - `adb devices` is empty. The attended offline Linux/phone pairing and
    both-direction sync run remains pending; roadmap 2.10 stays unticked and
    2.10b has not started. D12 independent review remains a release requirement.

  Final logs: `/tmp/qv-0038-fresh-review-tests.log`,
  `/tmp/qv-0038-fresh-review-app-final.log`,
  `/tmp/qv-0038-fresh-review-engine-final.log`,
  `/tmp/qv-0038-fresh-review-clippy.log`,
  `/tmp/qv-0038-fresh-review-validation-clippy.log`,
  `/tmp/qv-0038-fresh-review-checks.log`,
  `/tmp/qv-0038-fresh-review-apk-final.log`. No commit, push, branch or staging
  change. This review and passing tests do not establish protocol security.

## Owner continuation — 2026-11-03

Owner: “Do 2.10b, and add the remaining testing of 2.10 at the end of 2.10b.
I dont have time now”. This supersedes the earlier instruction to wait before
2.10b: carry the attended offline Linux/phone checks to plan 0039 step 6.
Implementation review stays Reviewed; no attended pass, phase tick or release
approval is inferred. Current staged work is explicitly authorized to continue.

- Follow-up bookkeeping: roadmap 2.10 is now ticked for its reviewed
  implementation because its remaining attended criterion was transferred,
  explicitly, to 0039 step 6. This supersedes earlier unticked-phase notes;
  the attended result remains pending and is not retroactively called passed.
