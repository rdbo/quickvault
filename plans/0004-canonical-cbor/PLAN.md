# Plan 0004 — Bounded deterministic CBOR (`qv-encoding`)

| Status | Created | Approved | Specs |
|--------|---------|----------|-------|
| Reviewed | 2026-10-25 | 2026-10-25 | 0004 §3.1, §4.1; 0002 §7.2; 0008 §1.1; 0012 §1 |

## Intent

Roadmap 0002 phase 1.2. Create the bottom-level crate `qv-encoding` (D4): a
strict codec for the RFC 8949 core-deterministic CBOR profile that every
QuickVault payload, AAD, HKDF info and transcript uses. Decoding treats its
input as hostile: it validates the whole item, without allocating, before any
typed read. Encoding can only produce canonical output. Unknown map entries
can be carried through a rewrite byte for byte. A fuzz target runs in CI.

## Scope

**In scope:**
- `crates/qv-encoding`: validator, borrowing pull decoder, `RawValue` for
  unknown entries, encoder with sorted maps, `encode_array` for AAD/info/transcripts.
- Rejection tests for every noncanonical form in RFC 8949 §4.2 plus the
  profile's own rejections. Round-trip and oracle property tests (`proptest`).
- `fuzz/` (cargo-fuzz, outside the workspace) with target `cbor_decode`, plus a CI job.

**Out of scope:**
- Typed records, payload schemas, field budgets (4,096 fields, 256 KiB per
  field), and "unknown required feature fails closed". These are model rules
  for qv-model (phase 1.5), built on this API.
- A generic owned `Value` tree. It would multiply memory on a 64 MiB manifest.
  Tests and the fuzz target define their own.
- AAD/info contents (labels, field order). Phase 1.3 defines them in qv-crypto
  using `encode_array`.
- Streaming decode of inputs larger than RAM. Every bounded object (≤ 64 MiB
  manifest) is decoded from an in-memory, already authenticated buffer.

## Spec basis

| Behaviour | Spec | Spec status | Notes |
|-----------|------|-------------|-------|
| Core deterministic CBOR: shortest form, definite lengths, sorted integer keys, valid UTF-8, no floats/tags/duplicates, reject noncanonical | 0004 §3.1 | Accepted | Key order = bytewise lexicographic order of the encoded keys (RFC 8949 §4.2.1) |
| Preserve unknown optional keys within budgets | 0004 §3.1, 0003 §2.2 | Accepted | Codec supplies `RawValue`; the model decides what is optional |
| Transcripts use exact canonical bytes | 0004 §3.1, 0002 §7.2 | Accepted | `encode_array` |
| Nesting ≤ 32; bounds before allocation | 0004 §4.1 | Accepted | |
| Serialization buffers are zeroizing | 0008 §1.1 | Draft (D5 go-ahead) | Encoder wipes on growth and drop |
| Hostile CBOR fuzzed | 0012 §1 ("Hostile SQLite/CBOR") | Accepted | Before-authentication half; after-auth fuzzing comes with the record parsers |

**Spec changes required:** None.

## Decisions needed

None. D4 placed the codec in `qv-encoding`. The candidate table in roadmap 0002
lists `proptest` and `cargo-fuzz` (which brings `libfuzzer-sys`) for this phase.
No `unsafe` is needed. Three design choices follow directly from the specs and
are recorded here, not left open:

- **Simple values.** `false`, `true` and `null` are accepted, because 0003 has
  `bool` fields and a `null` root parent. Every other major-type-7 item
  (undefined, unassigned simple values, floats, `break` outside a container)
  is rejected, because the spec names no use for them and fail-closed is the rule.
- **Map keys.** Validation accepts any CBOR integer key (major type 0 or 1),
  exactly as 0004 §3.1 says. The typed API reads and writes keys as `i64`. A
  key outside `i64` validates, but a typed `int()` read of it returns
  `OutOfRange`. The model therefore rejects such a record at read time; it
  never misreads it.
- **The fuzz crate is excluded from the shipped workspace.** `libfuzzer-sys` is
  `(MIT OR Apache-2.0) AND NCSA`, and the shipped allow-list must not grow for a
  CI-only tool. `fuzz/` keeps its own `Cargo.lock`. CI runs
  `cargo deny check advisories bans sources` on it, but not `licenses` or
  `cargo vet`. This is recorded honestly in the docs; nothing in `fuzz/` ships.

## Design

**Components touched:** a new crate, `qv-encoding`, which is a hostile-input
parser at the bottom of the graph. It depends on no qv crate; its only
dependency is `zeroize`. A new `fuzz/` dev crate. The CI workflow. Nothing
depends on `qv-encoding` yet (qv-crypto from 1.3, qv-model from 1.5).

**Profile (what "canonical" means here):**

| Item | Accepted | Rejected (error) |
|------|----------|------------------|
| Head | additional info 0–27, argument in its shortest form | 28–30 (`ReservedAdditionalInfo`); 31 (`IndefiniteLength`); longer than needed (`NonShortestArgument`) |
| Major 0/1 | full range, uint and negative | — |
| Major 2 | definite byte string, length ≤ remaining input | indefinite; length > remaining (`LengthExceedsInput`) |
| Major 3 | definite text, valid UTF-8 (no NFC check) | invalid UTF-8 (`InvalidUtf8`) |
| Major 4 | definite array, count ≤ remaining bytes | indefinite; count > remaining |
| Major 5 | definite map, 2·count ≤ remaining; integer keys only; strictly ascending by encoded key bytes | non-integer key (`NonIntegerKey`); equal key (`DuplicateKey`); descending key (`UnorderedKeys`) |
| Major 6 | — | any tag (`Tag`) |
| Major 7 | `0xf4` false, `0xf5` true, `0xf6` null | `0xf9`–`0xfb` (`Float`); everything else (`UnsupportedSimple`) |
| Nesting | depth ≤ 32 | 33+ (`DepthExceeded`) |
| Top level | exactly one item, no trailing bytes | `Truncated`, `TrailingBytes` |

**Depth** counts containers: a top-level scalar has depth 0, `[]` has depth 1,
and 32 nested arrays are accepted while 33 are rejected. A map value nests one
level below its map, and a map key, being an integer, adds no depth.

**Key order** compares the encoded key slices bytewise (RFC 8949 §4.2.1). So
every unsigned key sorts before every negative key, and `24` (`18 18`) sorts
before `-1` (`20`). Length-first ordering (§4.2.3) would order these the
other way, and the tests pin that difference.

**Interfaces:**

```rust
// crates/qv-encoding/src/lib.rs re-exports all of these.
pub const MAX_DEPTH: usize = 32;

/// Item kind at the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind { Uint, Negative, Bytes, Text, Array, Map, Bool, Null }

/// Why input was rejected. Carries no input bytes, offsets or lengths
/// (decoded plaintext may be secret; an offset can reveal a field length).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    Truncated, TrailingBytes, ReservedAdditionalInfo, IndefiniteLength,
    NonShortestArgument, LengthExceedsInput, InvalidUtf8, Tag, Float,
    UnsupportedSimple, DepthExceeded, NonIntegerKey, DuplicateKey, UnorderedKeys,
    // typed reads on validated input:
    UnexpectedType, OutOfRange, Unconsumed,
}
impl fmt::Display for DecodeError { /* fixed string per variant */ }
impl std::error::Error for DecodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError { DepthExceeded, DuplicateKey, ItemCount }
// Display + Error likewise.

/// Checks that `input` is exactly one canonical item. No heap allocation;
/// O(input.len()); iterative, with a fixed `[Frame; MAX_DEPTH]` stack.
pub fn validate(input: &[u8]) -> Result<(), DecodeError>;

/// Cursor over one validated item. Borrows; copies nothing.
pub struct Decoder<'a> { input: &'a [u8], pos: usize }
impl<'a> Decoder<'a> {
    /// Runs `validate` on all of `input`, then positions at its start.
    pub fn new(input: &'a [u8]) -> Result<Self, DecodeError>;
    pub fn peek_kind(&self) -> Result<Kind, DecodeError>;
    pub fn uint(&mut self) -> Result<u64, DecodeError>;
    /// Raw negative: the value is -1 - n.
    pub fn negative(&mut self) -> Result<u64, DecodeError>;
    /// Uint or negative within i64; otherwise OutOfRange. Map keys use this.
    pub fn int(&mut self) -> Result<i64, DecodeError>;
    pub fn bytes(&mut self) -> Result<&'a [u8], DecodeError>;
    pub fn text(&mut self) -> Result<&'a str, DecodeError>;
    pub fn bool(&mut self) -> Result<bool, DecodeError>;
    pub fn null(&mut self) -> Result<(), DecodeError>;
    /// Consumes a null and returns true, or returns false and consumes nothing.
    pub fn try_null(&mut self) -> Result<bool, DecodeError>;
    /// Header only. The count is ≤ the remaining input bytes, but callers must
    /// still apply their model budget before allocating from it.
    pub fn array(&mut self) -> Result<u64, DecodeError>;
    /// Header only. The caller then reads `count` (key, value) pairs.
    pub fn map(&mut self) -> Result<u64, DecodeError>;
    pub fn skip(&mut self) -> Result<(), DecodeError>;
    /// The exact bytes of the next complete item.
    pub fn raw_item(&mut self) -> Result<&'a [u8], DecodeError>;
    /// The next item, copied into an owned, zeroize-on-drop RawValue.
    pub fn raw_value(&mut self) -> Result<RawValue, DecodeError>;
    pub fn is_finished(&self) -> bool;
    /// Err(Unconsumed) unless the whole item was read.
    pub fn finish(self) -> Result<(), DecodeError>;
}

/// One canonical item kept verbatim (unknown map entries). Not Clone (it may
/// hold secrets); Debug is `RawValue(<redacted>)`; zeroized on drop.
pub struct RawValue { bytes: Box<[u8]>, depth: u8 }
impl RawValue {
    pub fn from_canonical(bytes: &[u8]) -> Result<Self, DecodeError>; // validates
    pub fn as_bytes(&self) -> &[u8];
    pub fn decoder(&self) -> Decoder<'_>; // no re-validation
}

/// Builds exactly one canonical item. Owns its buffer: it grows the buffer
/// itself (allocate new, copy, zeroize old), so Vec never reallocates and
/// leaves an unwiped copy behind. It zeroizes on drop.
pub struct Encoder { buf: Vec<u8>, items: u64, depth: usize }
impl Encoder {
    pub fn new() -> Self;
    pub fn uint(&mut self, v: u64);
    pub fn negative(&mut self, n: u64); // encodes -1 - n
    pub fn int(&mut self, v: i64);
    pub fn bytes(&mut self, v: &[u8]);
    pub fn text(&mut self, v: &str);
    pub fn bool(&mut self, v: bool);
    pub fn null(&mut self);
    pub fn raw(&mut self, v: &RawValue) -> Result<(), EncodeError>; // depth check
    /// `f` writes the items into a child encoder; the header is written with
    /// the exact count afterwards, so the count can't be wrong.
    pub fn array(&mut self, f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>)
        -> Result<(), EncodeError>;
    /// Entries in any order; emitted sorted by encoded key; duplicates → DuplicateKey.
    pub fn map(&mut self, f: impl FnOnce(&mut MapEncoder) -> Result<(), EncodeError>)
        -> Result<(), EncodeError>;
    /// Err(ItemCount) unless exactly one top-level item was written.
    pub fn finish(self) -> Result<Zeroizing<Vec<u8>>, EncodeError>;
}
impl Default for Encoder { /* new() */ }

pub struct MapEncoder { /* Vec<(encoded key bytes, Encoder)> */ }
impl MapEncoder {
    /// `f` must write exactly one item (else ItemCount).
    pub fn entry(&mut self, key: i64, f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>)
        -> Result<(), EncodeError>;
    pub fn raw_entry(&mut self, key: i64, v: &RawValue) -> Result<(), EncodeError>;
}

/// AAD / HKDF info / transcript builder: one canonical array.
/// `encode_array(|a| { a.text("qv/kek/v1"); a.uint(profile); Ok(()) })`
pub fn encode_array(f: impl FnOnce(&mut Encoder) -> Result<(), EncodeError>)
    -> Result<Zeroizing<Vec<u8>>, EncodeError>;
```

The developer may add private helpers. The developer must not widen the
public API beyond this sketch without logging the change. Small ergonomic
additions on the same types, such as `Encoder::with_capacity`, count as
widening and need a log entry.

**Module layout:** `lib.rs` (crate docs: profile table, trust boundary,
"validate before typed reads", what it does not do), `error.rs`, `head.rs`
(read/write one head: major type plus shortest-form argument; shared by
everything), `validate.rs`, `decode.rs`, `raw.rs`, `encode.rs`.

**Data and control flow:** `Decoder::new` always runs `validate` first. Typed
reads then walk input that is already known to be canonical. Each read still
bounds-checks and returns `Err`, never panics, so a `Decoder` built from
`RawValue::decoder` or a wrong call sequence can't cause UB or a panic; it only
returns `UnexpectedType`/`Truncated`. The validator's frame stack holds, per
open container: items remaining, whether it is a map, whether a key is
expected next, and the previous key's byte range. Key comparison is
`input[prev] < input[cur]` on slices of at most 9 bytes.

**Secrets and hostile input:**
- Hostile input: every length and count is checked against the remaining
  input before it is used. The validator allocates nothing. The decoder
  allocates only in `raw_value`, bounded by the item's validated size.
  Validation work is linear in the input. There is no recursion on input data
  (the encoder recurses only through caller closures, bounded by `MAX_DEPTH`).
- Secrets: decoded strings are borrowed from the caller's buffer (a
  `SecretBytes` in later phases), so no copy is made. `RawValue`, `Encoder`
  and `MapEncoder` buffers are zeroized on drop, and `Encoder` growth wipes the
  old buffer. `finish` returns `Zeroizing<Vec<u8>>`; callers that need locked
  memory move it with `SecretBytes::take_from` (phase 1.3+). The crate is
  honest that Vec-backed buffers are not page-locked; locking stays qv-crypto's
  job, and qv-encoding must not depend on it (D4).
- Errors carry no data (see `DecodeError`). There is no `Debug` on anything
  that holds content, apart from the redacted `RawValue`.

**Errors:** `DecodeError` and `EncodeError` as above. Phase 1.3's redacted
taxonomy maps every `DecodeError` on authenticated data to "integrity error".
That mapping is not done here.

**Dependencies:**

| Crate | Why | Alternatives | Review / audit status |
|-------|-----|--------------|-----------------------|
| `zeroize` =1.9.1 (`alloc`; already in the workspace) | Wipe encoder/raw buffers (0008 §1.1) | Volatile writes by hand (a home-made primitive) | Already vetted (imports) |
| `proptest` (latest 1.x, exact pin; `default-features = false`, `features = ["std"]`), **dev-dependency** | Round-trip and oracle property tests (roadmap Done when) | Hand-written random loops (weaker shrinking); `quickcheck` | Widely used; expect `cargo vet` exemptions for it and its rand stack (`safe-to-run`, since dev-only). Licenses MIT/Apache-2.0 |
| `libfuzzer-sys` (via `cargo fuzz init`, exact pin), **`fuzz/` only** | Fuzz target | `afl` (heavier setup) | rust-fuzz; not shipped; deny advisories/bans/sources only (see *Decisions needed*) |
| `cargo-fuzz` (exact version), **CI tool** | Builds/runs the target | — | Installed with `--locked` |

Own codec vs `minicbor` plus a canonical-check layer: the roadmap leaves this
to the architect. **Own codec.** We would need to reimplement every
canonical check (shortest form, key order, duplicates, depth before
allocation) on top of minicbor anyway. The encoder side would still need
sorting and zeroizing. The format surface here is about 400 lines. CBOR is
an encoding, not a cryptographic primitive, so the "no home-made primitives"
rule doesn't apply. One fewer security-critical dependency fits 0012 §3.

## Steps

### Step 1 — Crate skeleton, errors and heads

- [x] **Do:** Create `crates/qv-encoding` (lib; `[lints] workspace = true`;
  dependency `zeroize.workspace = true`). Write `lib.rs` crate docs (profile
  table, depth and key-order rules, trust boundary), `error.rs` (both enums,
  Display strings, `Error` impls) and `head.rs` (private
  `read_head(input, pos) -> Result<(major, arg, len), DecodeError>`, which
  enforces reserved/indefinite/shortest rules, and
  `write_head(buf, major, arg)` for shortest form). Unit tests for `head`:
  each boundary (23/24, 255/256, 65535/65536, 2³²−1/2³², u64::MAX) encodes to
  the RFC 8949 Appendix A bytes. Non-shortest forms at every width are
  rejected, and so are additional info 28/29/30 and a truncated argument.
- **Files:** `crates/qv-encoding/{Cargo.toml,src/lib.rs,src/error.rs,src/head.rs}`, `Cargo.lock`.
- **Done when:** the head tests pass; there is no `unwrap` outside tests.
- **Verify:** `cargo test --locked -p qv-encoding head`

### Step 2 — Validator and the rejection suite

- [x] **Do:** Implement `validate` as designed (iterative, fixed stack, no
  heap). Add `crates/qv-encoding/tests/reject.rs`, with one test per row of the
  profile table and these exact cases:
  - Non-shortest argument for each of major types 0, 1, 2, 3, 4 and 5, at each width (24/25/26/27).
  - Indefinite byte string, text string, array and map. A `0xff` break at
    top level and inside a definite array.
  - Tags: `c0`–`d7`, `d8 xx` and bignums `c2`/`c3`. Floats: `f9`, `fa`, `fb`
    (including a half-float 0.0). `f7` (undefined), `e0`, `f3`, `f8 20`, `fc`–`fe`.
  - Invalid UTF-8: an overlong `c0 80`, a lone surrogate `ed a0 80`,
    truncated multibyte, `ff`. Valid multibyte text is accepted.
  - Map: text key, bytes key, array key, bool key. A duplicate key (`{1:0,1:0}`).
    Descending order (`{2:0,1:0}`). `[24, -1]` order accepted and `[-1, 24]`
    rejected (bytewise vs length-first).
  - Depth: 32 nested arrays accepted, 33 rejected. 32 levels of maps/arrays
    mixed accepted, 33 rejected.
  - Lengths: a byte string, array and map claiming `u64::MAX` or
    remaining+1 → `LengthExceedsInput` (no allocation happens: the validator
    has none). Truncated inside an item → `Truncated`. Empty input →
    `Truncated`. Two top-level items → `TrailingBytes`.
  - Accept: `00`, `20`, `40`, `60`, `80`, `a0`, `f4`, `f5`, `f6`, and the
    largest uint/negative.
  Each rejection test asserts the **exact** `DecodeError` variant.
- **Files:** `crates/qv-encoding/src/validate.rs`, `lib.rs`, `crates/qv-encoding/tests/reject.rs`.
- **Done when:** every case passes with its expected variant, and
  `validate` contains no `Vec`/`Box`/`String`.
- **Verify:** `cargo test --locked -p qv-encoding --test reject`; `grep -nE 'Vec|Box|String|vec!' crates/qv-encoding/src/validate.rs` finds nothing outside `#[cfg(test)]`.

### Step 3 — Decoder and RawValue

- [x] **Do:** Implement `Decoder` and `RawValue` as designed. Unit tests:
  - typed reads of each kind; `UnexpectedType` on a mismatch; `int()`
    `OutOfRange` for `u64::MAX` and `-2⁶⁴`;
  - `try_null`; `skip` and `raw_item` over nested containers return the exact sub-slice;
  - `finish` → `Unconsumed` when items are left;
  - `RawValue::from_canonical` rejects noncanonical input; its Debug is
    `RawValue(<redacted>)` with no length or content;
  - a `RawValue::decoder()` round trip.
  Add one integration test, `tests/unknown_keys.rs`. It decodes a map with
  known keys 1 and 3 and unknown keys 2, 7 and -1 (unknowns kept as
  `(i64, RawValue)`), changes key 1's value, and re-encodes through
  `MapEncoder::raw_entry` (after Step 4; leave this test until then, or
  write it in Step 4). The output equals the expected canonical bytes, with
  the unknown values unchanged byte for byte.
- **Files:** `crates/qv-encoding/src/{decode.rs,raw.rs,lib.rs}`.
- **Done when:** tests pass. `RawValue` has no `Clone` (add a
  `compile_fail,E0599` doctest paired with a passing one).
- **Verify:** `cargo test --locked -p qv-encoding decode raw && cargo test --locked -p qv-encoding --doc`

### Step 4 — Encoder, MapEncoder and `encode_array`

- [x] **Do:** Implement as designed. All writes go through one private
  `reserve(n)` that grows by doubling into a new `Vec`, copies, then
  `zeroize`s the old buffer (`Vec<u8>::zeroize` also clears spare capacity).
  `extend_from_slice` is called only after `reserve`, so Vec never
  reallocates on its own; add a debug assertion that capacity is unchanged
  across the write. `Drop` zeroizes. Unit tests:
  - Appendix A vectors for ints, strings, arrays and maps.
  - Map entries inserted out of order come out sorted, unsigned keys before
    negative ones. A duplicate gives `DuplicateKey`.
  - An entry closure that writes 0 or 2 items gives `ItemCount`.
  - `finish` with 0 or 2 items gives `ItemCount`.
  - 32 nested `array` calls succeed and 33 give `DepthExceeded`; a `raw` at
    depth that would exceed 32 also gives `DepthExceeded`.
  - Growth past the initial capacity produces correct output.
  - `encode_array` of `["qv/kek/v1", 1]` equals the hand-computed bytes.
  - Every encoder output passes `validate`.
  Then write `tests/unknown_keys.rs` (from Step 3).
- **Files:** `crates/qv-encoding/src/{encode.rs,lib.rs}`, `crates/qv-encoding/tests/unknown_keys.rs`.
- **Done when:** tests pass; no `unwrap`/`expect`/indexing panics outside tests.
- **Verify:** `cargo test --locked -p qv-encoding`

### Step 5 — Property tests and supply chain

- [x] **Do:** Add `proptest` as a dev-dependency (exact pin, in
  `[workspace.dependencies]`). In `tests/roundtrip.rs`, define a test-only
  `Value` tree and a strategy (depth ≤ 6, bounded sizes, all eight kinds, maps
  with random `i64` keys with duplicates removed). Properties:
  1. `encode(v)` passes `validate`, and `decode(encode(v)) == v` (with maps
     compared as sorted).
  2. **Oracle:** for arbitrary bytes `b` (`vec(any::<u8>(), 0..512)`), if
     `validate(b)` is Ok then walking it with the typed API and re-encoding
     gives exactly `b`. A huge key outside `i64` falls back to `raw`.
  3. **Mutation:** for a valid `encode(v)`, flipping one byte, truncating, or
     appending a byte either gives Err or (if it is still valid) satisfies property 2.
  4. **Determinism:** two `Value`s that differ only in map insertion order encode identically.
  Then run `cargo deny check` and `cargo vet`. Add `cargo vet` exemptions for
  the new crates (criteria `safe-to-run`, dev-only). Write no audits.
  Re-run `cargo vet prune` after `cargo vet regenerate imports`.
- **Files:** `Cargo.toml`, `Cargo.lock`, `crates/qv-encoding/Cargo.toml`, `crates/qv-encoding/tests/roundtrip.rs`, `supply-chain/*`.
- **Done when:** properties pass at the default 256 cases. `cargo deny check`
  and `cargo vet --locked` pass. The execution log lists every new transitive
  crate and exemption.
- **Verify:** `cargo test --locked -p qv-encoding --test roundtrip && cargo deny check && cargo vet --locked`

### Step 6 — Fuzz target and CI job

- [x] **Do:**
  - `cargo fuzz init` in the repo root (or write the equivalent by hand),
    giving `fuzz/Cargo.toml` (package `qv-encoding-fuzz`, `publish = false`,
    its own `[workspace]`, `cargo-fuzz = true` metadata), target
    `fuzz_targets/cbor_decode.rs` and `fuzz/.gitignore` (`target`, `corpus`,
    `artifacts`, `coverage`). Add `exclude = ["fuzz"]` to the root workspace.
    Pin `libfuzzer-sys` exactly and commit `fuzz/Cargo.lock`. SPDX headers on the `.rs` files.
  - The target: run `validate`. If Ok, apply the oracle walk from Step 5
    property 2 (its own small walker; assert identity) and check that
    `RawValue::from_canonical` agrees with `validate`. If Err, check that
    `Decoder::new` returns the same error.
  - CI: a new job `fuzz` (ubuntu-latest, same checkout pin). It installs a
    pinned nightly (`rustup toolchain install nightly-YYYY-MM-DD --profile minimal`;
    choose a nightly at least 2 weeks old and record it). It installs
    `cargo-fuzz` with `cargo install --locked --version <exact>`, runs
    `cargo fmt --check --manifest-path fuzz/Cargo.toml`, and then runs
    `cargo +nightly-YYYY-MM-DD fuzz run cbor_decode -- -max_total_time=60`.
    In the `supply-chain` job, add
    `cargo deny --manifest-path fuzz/Cargo.toml check advisories bans sources`.
  - Run it locally. This host is Alpine/musl, where libFuzzer and ASan may not
    build. Try `cargo +nightly fuzz run cbor_decode -s none -- -max_total_time=60`
    (with `CARGO_HOME` in the scratchpad if needed). If it can't build here,
    record the exact error. The proptest oracle (Step 5) is then the local
    evidence, and the CI job's first run is pending the owner's push. Do not
    weaken or drop the CI job.
- **Files:** `fuzz/Cargo.toml`, `fuzz/Cargo.lock`, `fuzz/.gitignore`, `fuzz/fuzz_targets/cbor_decode.rs`, `Cargo.toml`, `.github/workflows/ci.yml`.
- **Done when:** the target builds (CI, and locally if possible). The
  workflow's new commands pass locally except where the musl limitation is
  logged. The root gates are unaffected by `fuzz/`.
- **Verify:** `sh scripts/check-spdx.sh`; the root standard gates; `cargo deny --manifest-path fuzz/Cargo.toml check advisories bans sources`; the local fuzz attempt above.

### Step 7 — Documentation

- [x] **Do:** Update the files under *Documentation*. Set this plan to `Implemented`.
- **Files:** see *Documentation*.
- **Done when:** the docs match the tree.
- **Verify:** `git status --short` shows only the intended files; full gates once more.

## Test plan

- **Unit and property tests:** head boundaries and Appendix A vectors; typed
  decoder reads; encoder sorting, counts and depth; proptest round trip,
  oracle identity, mutation and determinism.
- **Rejection, malformed-input and crash-path tests:** `tests/reject.rs`
  covers every RFC 8949 §4.2 noncanonical form (non-shortest arguments,
  indefinite lengths, key order including the length-first trap), plus tags,
  floats, simple values, UTF-8, duplicates, depth 33, oversized lengths,
  truncation and trailing bytes, each with its exact error. The `cbor_decode`
  fuzz target runs in CI.
- **Vectors:** RFC 8949 Appendix A, for the subset in the profile. No
  QuickVault format vectors (unstable until 1.16).
- **0012 §1 matrix rows addressed:** "Hostile SQLite/CBOR": the CBOR half
  (malformed lengths and nesting; fuzz before authentication). Partial,
  because fuzzing after authentication of record/manifest parsers comes with
  1.5–1.7.

## Risks and stop conditions

- If `proptest` with `default-features = false, features = ["std"]` pulls in
  a crate with a license outside the allow-list, or an advisory with no clean
  fix, stop and ask. Do not widen `deny.toml` or add an `ignore`.
- If cargo-fuzz requires `fuzz/` to be a workspace member, or forces a
  change to the root `deny.toml`/`supply-chain/`, stop and ask.
- If a design rule above turns out to conflict with RFC 8949 §4.2.1 for
  integer keys, stop and ask. Don't silently switch the key order.
- If the public API needs to grow beyond the sketch (for example a
  `Value` type), log it and justify it. Anything that changes the profile
  table needs the owner.
- Never weaken a rejection test to make it pass. An exact error variant is part of the test.

## Documentation

- [x] `CHANGELOG.md` — Unreleased/Added: `qv-encoding` canonical CBOR codec, fuzz target and CI job
- [x] `ARCHITECTURE.md` — §3: a component row for `qv-encoding` (bounded deterministic CBOR; hostile-input parser; no qv deps), and add it to "Implemented so far"
- [x] Specs — no change. 0004 stays Accepted (not fully implemented)
- [x] `AGENTS.md` — layout table: `fuzz/` (cargo-fuzz targets, outside the workspace, nightly in CI); *Current state* mentions `qv-encoding`
- [x] `plans/README.md` — index row; roadmap 0002: tick 1.2, plan number, execution log; its *Documentation* item for the §3 `qv-encoding` row

## Revisions

None.

## Execution log

- 2026-10-25: Approved (standing approval, roadmap 0002): no open decisions, no spec amendment, dependencies from the candidate table only (`proptest`, `cargo-fuzz`/`libfuzzer-sys`), no `unsafe`, matches phase 1.2.
- 2026-10-25: Steps 1–4 done. Files: `crates/qv-encoding/src/{lib,error,head,validate,decode,raw,encode}.rs`,
  `tests/{reject,unknown_keys}.rs`. Only `zeroize` (workspace) as a dependency.
  Head-level rules apply to every major type: tags fail as `Tag` whatever
  their argument; `0xfc`–`0xfe` fail as `ReservedAdditionalInfo` (the head
  rule comes before the simple-value rule); `0xff` (a stray break) fails as
  `UnsupportedSimple`, not `IndefiniteLength`, since it is a major-type-7
  item, not an indefinite container. Deviation (process): steps 1–3 left
  `dead_code` lints on helpers that step 4 uses, so clippy was green from
  step 4 on; tests were green after every step. Deviation (strengthening):
  `Decoder` has no `Debug` (not stated in the plan; it borrows possibly secret
  input). `text()` re-checks UTF-8 and leaves the cursor in place on failure,
  so a `Decoder` over `RawValue::decoder()` input cannot return unchecked
  text. The public API matches the sketch; `RawValue::depth` is crate-private.
  Tests: 19 unit, 14 rejection (every variant asserted exactly), 1
  unknown-keys round trip, 5 doctests (2 `compile_fail` with codes E0599 and
  E0369 + paired positives, 1 `encode_array` example). `validate.rs` has no
  `Vec`/`Box`/`String`.
- 2026-10-25: Step 5 done. `proptest =1.12.0` (`default-features = false`,
  `std`) as a dev-dependency. New transitive crates (dev-only): autocfg 1.5.1,
  chacha20 0.10.2, core_detect 1.0.0, cpufeatures 0.3.1, num-traits 0.2.19,
  rand 0.10.3, rand_core 0.10.1, rand_xorshift 0.5.0, regex-syntax 0.8.11,
  unarray 0.1.4. `getrandom` resolves to the existing 0.4.3. `cargo deny
  check` ok (licenses unchanged). `cargo vet`: imports cover all but four;
  new `safe-to-run` exemptions for autocfg 1.5.1, proptest 1.12.0,
  rand_xorshift 0.5.0 and regex-syntax 0.8.11. No audits written; no
  publisher `trust` entries added (cargo vet suggested trusting cuviper and
  BurntSushi, as isrg/mozilla/bytecode-alliance do; that is a policy choice
  left to the owner). Result: 10 fully audited, 14 exempted. `cargo vet
  prune` changed nothing. Four properties pass at 256 cases each:
  round trip, oracle on arbitrary bytes, mutation (flip/truncate/append),
  and map-order independence. Deviation: `tests/roundtrip.rs` carries a
  file-level `#![allow(clippy::unwrap_used, clippy::panic)]` with a comment,
  because clippy's `allow-*-in-tests` covers only `#[test]` functions, not
  helper functions in an integration test.
- 2026-10-25: Step 6 done. `fuzz/` written by hand in the `cargo fuzz init`
  layout (package `qv-encoding-fuzz`, own `[workspace]`, `libfuzzer-sys
  =0.4.13`, 13 locked packages); root `Cargo.toml` has `exclude = ["fuzz"]`.
  Deviation: the path dependency on `qv-encoding` carries `version = "=0.0.0"`,
  because cargo-deny's `wildcards = "deny"` treats a versionless path
  dependency as a wildcard; this keeps `deny.toml` unchanged. Tools:
  cargo-fuzz 0.13.2, nightly `nightly-2026-10-01` (rustc 1.101.0-nightly
  2026-09-30), installed via a scratch `CARGO_HOME` because `~/.cargo/bin` is
  read-only here. CI: the new `fuzz` job (pinned nightly, cargo-fuzz
  `--locked --version 0.13.2`, fmt check of the fuzz crate, 60 s run), and
  `cargo deny --manifest-path fuzz/Cargo.toml check advisories bans sources`
  in `supply-chain`. Locally (Alpine/musl, `-s none`): the default run
  crashed in libFuzzer itself. gdb shows a SIGSEGV in libFuzzer's `memmem`
  interceptor (`FuzzerInterceptors.cpp:215`, a null real-function pointer
  reached from `Mutate_AddWordFromTORC`), with no QuickVault frame on the
  stack. The input it recorded (empty) passes when replayed. With
  `-use_cmp=0` (local workaround only, not in CI): **2,589,332 runs in 61 s,
  no crash, 332 edges**. The CI job runs on glibc with the default ASan; its
  first hosted run is pending the owner's push. Local checks: fmt of the fuzz
  crate ok; fuzz-crate deny (advisories, bans, sources) ok; root gates
  unaffected.
- 2026-10-25: Step 7 done; plan `Implemented`. Docs: `CHANGELOG.md`,
  `ARCHITECTURE.md` §3 (row and "Implemented so far"), `AGENTS.md` (current
  state; layout rows for `fuzz/` and CI), roadmap 0002 (1.2 ticked, §3
  documentation item ticked, log). Specs unchanged: 0004 stays Accepted, not
  fully implemented. Final gates: SPDX ok; fmt ok (root and fuzz crate);
  clippy `-D warnings` clean; `cargo test --locked` 75 passed, 0 failed;
  `cargo deny check` ok; fuzz-crate deny (advisories, bans, sources) ok;
  `cargo vet --locked` ok (10 audited, 14 exempted).
  Found, not fixed: (1) `cargo fuzz run` has no `--locked` flag, so CI relies
  on the committed `fuzz/Cargo.lock` without enforcing it. (2) cargo vet's
  suggested publisher trust (cuviper, BurntSushi) is an owner policy choice.
  (3) Locally on musl the fuzzer needs `-use_cmp=0` (libFuzzer interceptor
  bug); CI is unaffected.
- 2026-10-25: Reviewed ([REVIEW.md](REVIEW.md)): Approved with minor fixes. The reviewer added a `cargo fetch --locked` step for `fuzz/Cargo.lock` to the CI fuzz job. Two low findings are noted and need no change. Status `Reviewed`.
