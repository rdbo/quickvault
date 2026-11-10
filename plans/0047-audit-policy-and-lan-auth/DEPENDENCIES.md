# LAN engine readiness — plan 0047

2026-11-09. Production wrappers and LAN/2 integration now exist; readiness
conditions were reviewed before integration. This document retains the initial
failed checks as history. It is not a component/composition certification.

**Current state:** production engine/runtime integration and host/Android suite
checks are complete. The owner approved the additional SQLite advisory repair;
rusqlite0.41.0/libsqlite3-sys0.39.1 (SQLite3.54.1) are now pinned. Fresh deny and
locked vet pass. Final full workspace/native and all-target lint checks after the upgrade pass.
The fixed-suite timing exception and exact development-only vet baseline remain
unaudited debt, not certification. D12/device and genuine dependency review
remain release gates. Historical failed checks below are retained as history.

## Selected package and integration

`opaque-ke =4.0.1` with defaults disabled, `ristretto255` and `argon2` only.
Bridge aliases: `argon2-opaque =0.5.3` (alloc + zeroize), `sha2-opaque =0.10.9`
(defaults off). The package re-exports its compatible rand and generic-array;
no separate RNG implementation or change to existing QuickVault profiles.
Package MSRV is 1.85; host build on the pinned 1.98.1 passed. The Android arm64 target was subsequently installed; selected-suite all-target
checks pass, as recorded in the adapter checkpoint below. This is compilation,
not physical-device evidence.

The declared MIT/Apache license of opaque-ke does not cover every dependency:
curve25519-dalek 4.1.3 is BSD-3-Clause, handled by an exact-package license
exception in deny.toml after the gate identified it. No broad license allowlist
change was made. The full feature tree is in the temporary
check log; no serde/std/alternative curve feature is requested on opaque-ke.
The dependency family adds the following exact registry packages:

| Package | Version | Registry SHA-256 |
|---------|---------|-----------------|
| argon2 | 0.5.3 | `3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072` |
| base16ct | 0.2.0 | `4c7f02d4ea65f2c1853089ffd8d2787bdbc63de2f0d29dedbcf8ccdfa0ccd4cf` |
| blake2 | 0.10.6 | `46502ad458c9a52b69d4d4d32775c788b7a1b85e8bc9d482d92250fc0e3f8efe` |
| const-oid | 0.9.6 | `c2459377285ad874054d797f3ccebf984978aa39129f6eafde5cdc8315b612f8` |
| crypto-bigint | 0.5.5 | `0dc92fb57ca44df6db8059111ab3af99a63d5d0f8375d9972e319a379c6bab76` |
| curve25519-dalek | 4.1.3 | `97fb8b7c4503de7d6ae7b42ab72a5a59857b4c937ec27a3d4539dba95b5ab2be` |
| curve25519-dalek-derive | 0.1.1 | `f46882e17999c6cc590af592290432be3bce0428cb0d5f8b6715e4dc7b383eb3` |
| der | 0.7.10 | `e7c1832837b905bbfb5101e07cc24c8deddf52f93225eee6ead5f4d63d53ddcb` |
| derive-where | 1.7.0 | `2e2b94854e8576378ccda7c8de8a66ed8b4e8acbd2c50ec3418ea6c8aaf4b567` |
| elliptic-curve | 0.13.8 | `b5e6043086bf7973472e0c7dff2142ea0b680d30e18d9cc40f267efbf222bd47` |
| ff | 0.13.1 | `c0b50bfb653653f9ca9095b427bed08ab8d75a137839d9ad64eb11810d5b6393` |
| fiat-crypto | 0.2.9 | `28dea519a9695b9977216879a3ebfddf92f1c08c05d984f8996aecd6ecdc811d` |
| group | 0.13.0 | `f0f9ef7462f7c099f518d754361858f86d8a07af53ba9af0fe635bbccb151a63` |
| hkdf | 0.12.4 | `7b5f8eb2ad728638ea2c7d47a21db23b7b58a72ed6a38256b8a1849f15fbbdf7` |
| hmac | 0.12.1 | `6c49c37c09c17a53d937dfbb742eb3a961d65a994e6bcdcf37e7399d0cc8ab5e` |
| opaque-ke | 4.0.1 | `ded22991b43cd15561b62b2e1cf9ace1344a8534eebec96202d5c96a77a6616a` |
| password-hash | 0.5.0 | `346f04948ba92c43e8469c1ee6736c7563d71012b17d40745260fe106aac2166` |
| sec1 | 0.7.3 | `d3e97a565f76233a6003f9f5c54be1d9c5bdfa3eccfb189469f11ec4901c47dc` |
| voprf | 0.5.0 | `28f59c30c76e2fea54cdece6a054e2662feffa7ab19658a7887524265ee39470` |
| zeroize_derive | 1.5.0 | `3c50655cbb0fe3fc43170059e702f1ce5e19b84cec58dc87b037a09935c2f328` |

## Source/API evidence

Downloaded crate bytes for opaque-ke have the lockfile checksum above.
The selected OPRF/AKE suite uses dalek Ristretto/Scalar arithmetic.
`messages.rs` defines KE1 as group element32 + nonce32 + public key32 =96;
KE2 as evaluated element32 + masking nonce32 + masked response128 + AKE128
=320; KE3 is the SHA-512 MAC64. A compiled qv-crypto profile test asserts all
three serializer lengths and constructs the explicit 262144 KiB/t3/p4,
64-byte Argon2 parameters. Public slot projection is separately tested as171.

Use fixed engine role identities/context from 0013 §15; parameters must be
passed explicitly both at local registration and client finishing. Upstream
Argon2 defaults/Identity do not satisfy this contract. Its Ksf trait permits a
small adapter invoking the reviewed Argon2 with caller-owned, zeroizing blocks;
do not use the upstream convenience KSF if it leaves scratch unwiped.

The infallible rand0.8 RngCore interface needs a checked adapter. Selected
scalar generation retries zero scalars. A naive zero-on-error adapter can hang;
no adapter is implemented or approved yet. Failure must prevent all output,
without panic, a zero seed or weaker generator. Its source/test proof is an
outstanding gate, not implied by successful dependency compilation.

Upstream setup/registration/login/key states derive ZeroizeOnDrop, but not all
hash/HMAC/OPRF scratch does. `opaque.rs:get_password_derived_key` uses ordinary
GenericArray outputs/HKDF state; `key_exchange/shared.rs:DerivedKeys` has raw
hash outputs; the digest0.10/hash/HMAC family lacks modern blanket zeroization.
Outer wrappers cannot erase these private intermediates. Review/document these
best-effort limits under 0008 §1.1 before asserting cleanup; no complete-erasure
or memory-locking guarantee for dependency-owned states has been established.

Upstream's 2021 NCC audit concerns older versions (0.5.0 / fixes through1.2.0),
not 4.0.1 or this product-specific composition. D12 remains an external release
gate. No audit certification or supply-chain exemption has been created.

## Current advisory and reachability trace

cargo-deny reports [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387)
on crypto-bigint0.5.5. Fixed versions start at0.7.6; the 0.13 elliptic-curve
family requires0.5, so an ordinary compatible update cannot select the fix.
Dependency path is opaque-ke/voprf → elliptic-curve0.13.8 → crypto-bigint0.5.5.

Selected AKE `key_exchange/group/ristretto255.rs` uses dalek point/scalar
compression, multiplication, inversion and random-scalar reduction directly.
Selected OPRF `voprf/src/group/ristretto.rs` also uses dalek; its use of
elliptic-curve is the generic hash-to-curve XMD byte expander, not integer/field
arithmetic. `typenum::U256` in generic hash bounds is a type-level length,
not crypto-bigint::U256. The generic elliptic-curve group adapters are present
in the package but are not the selected ciphersuite. This suggests the flagged
integer operations are outside this suite; no runtime advisory waiver or claim
of whole-package safety has been made. Recheck the complete path/feature tree
and compiled selected instantiations before any narrowly scoped exception.
The owner was asked about exception versus changing the engine on2026-11-09;
that choice is resolved below; the exact unused-code advisory exception is now in deny.toml.

## Initial gate results (historical)

- qv-crypto dependency build and feature-tree check: passed.
- Serializer/parameter candidate test: passed in component test run.
- cargo-deny0.20.2: **failed**, new timing advisory. The initial check also
  flagged the dalek BSD license; an exact-package license exception resolves
  that policy entry without suppressing advisories.
  Original cargo home is read-only; rerun used an exact temporary copy of
  deny.toml changing only advisory DB location to /tmp/qv-0047-advisory-dbs.
  No policy was weakened. Full output: /tmp/qv-0047-deny.log.
- cargo-vet0.10.3 --locked: **failed**,20 new packages lack safe-to-deploy
  evidence in the locked imports. No exemptions were added. A temporary store
  refreshed public imports: still17 missing (estimated108159 lines of review).
  That experiment did not alter repository supply-chain files. Logs:
  /tmp/qv-0047-vet.log and /tmp/qv-0047-vet-online.log.
- Android/KDF timing/device and new composition vectors: not run.

CI-pinned tools were absent; installed into /tmp/qv-0047-tools. Direct vet
invocation requires `CARGO=/home/user/.cargo/bin/cargo cargo-vet vet --locked`.
Read-only cache also makes vet suggest panic here; ordinary locked check works.
Do not turn incomplete review into safe-to-deploy certifications to pass a gate.

## Initial required resolution (subsequently addressed below)

Resolve the advisory/engine choice and obtain genuine supply-chain evidence for
the pinned family (or revise engine/dependency design). Review RNG and secret
adapters before step4. These gates do not prevent the independent public-slot
hardening or large-vault design work. Authentication implementation is pending.

## Owner disposition and completed selected-path trace

2026-11-09: owner prefers an easy beneficial security improvement, otherwise
retain/document instead of a change with no security benefit. Retaining the
fixed suite is supported by the selected paths: the XMD implementation in
elliptic-curve/src/hash2curve/hash2field/expand_msg/xmd.rs hashes byte slices,
XORs fixed hash outputs and maintains public length counters. Its ExpandMsg/
Expander traits operate on bytes; no crypto-bigint arithmetic appears there.
Both OPRF hash-to-scalar/point and AKE scalar multiplication/inversion route to
dalek. The generic Weierstrass group adapters are not the fixed ciphersuite.
Serializer assertions and profile typing bind that selected suite; there is
no peer-controlled group selection. No current secret reaches the operations
named in RUSTSEC-2026-0387 through this suite. An incompatible bigint-family
upgrade would not improve those selected operations.

Added a documented advisory exception on this basis, conditional on the exact
suite/feature/reverse-dependency trace. The advisory policy schema scopes by
advisory ID; its reason records the exact current dependency and usage scope.
Re-review it if any suite, feature or dependency path changes. This is neither
a repair of crypto-bigint nor an assertion that its generic arithmetic is safe.
No vet exemption or audit certification was added; that gate remains unresolved.
Earlier failed-gate entries above remain the record of discovery, not current
claims that an owner decision is still missing.

## Development baseline authorization

After the separate question offering exact-version development exemptions or
waiting for review records, the owner replied “contineu”. Implementation takes
that as approval for the proposed development baseline. All20 exact package
versions above now have explicit exemptions in supply-chain/config.toml. They
are **unaudited debt**, not reviewed/audited packages and not release approval.
The older gate failures above remain discovery history. Genuine dependency
review and D12 composition review remain required before LAN release. No local
certifications, author trust delegations or blanket version ranges were added.

## Adapter readiness checkpoint

At the readiness checkpoint, `qv-crypto/src/lan_auth_engine.rs` fixed the actual suite to
Ristretto255/TripleDh/SHA512 and provides these reviewed adapter choices before
production integration:

- **RNG:** direct fallible OS calls, without a seeded replacement generator.
  The infallible trait latches the first error, wipes any partial fill and
  supplies ff termination poison only inside the discarded engine operation.
  This is not accepted entropy: the wrapper must reject the entire operation
  before any message/state/key escapes. Selected random-scalar reduction of
  ff is nonzero; the selected seed-based scalar derivation also accepts the
  fixed ff seed. This prevents the zero-scalar retry hang of a zero-on-error
  adapter. The failure test reaches both paths and setup/client KE1, and the
  real-registration test injects partial failure at every KE2 draw. Wrapper
  integration must centralize the check, not rely on frontends remembering it.
- **KSF:** explicit Argon2id v1.3,262144 KiB/t3/p4, output64, zero16 salt.
  Reject any other KSF input/output width. Input is zeroizing; application
  output uses SecretArray64; the dependency's typed256 MiB block vector has
  a zeroizing guard across success/error/unwind. As with the existing KDF,
  this scratch is too large to lock. No unsafe cast, primitive or default
  Argon2/identity configuration is used.
- **Lifetimes:** serialize inter-flight setup/registration/login state into
  protected SecretBytes; deserialize only during the operation, then promptly
  destroy typed state. OprfSeed and PrivateKey own zeroizing fields; registration
  and login states derive ZeroizeOnDrop. Raw session/export GenericArray outputs
  do not provide the application boundary: production wrappers must copy into
  protected storage and wipe every handed-back copy, including poisoned/error
  paths. Library-private hash/HMAC/OPRF intermediates retain the previously
  documented best-effort limits; serialization cannot erase them.
- **Scope:** selected TripleDh KE3 does not consume its RNG argument. No engine
  RNG-failure path may send output, even where the component reports success.
  Upstream seed-key derivation contains a library unwrap; the selected ff
  failure poison is tested valid for that path rather than causing its error
  to unwind. This is fixed-suite evidence, not a guarantee for other engines.

Checks passed: host candidate RNG and real-KDF/context/rejection tests;
`cargo check --locked -p qv-crypto --target aarch64-linux-android` and
`cargo check --locked -p qv-crypto --all-targets --target aarch64-linux-android`.
The latter initially hit disk exhaustion, then passed after removing only this
session's generated release artifacts. Android compilation is not device/KDF
latency or lifecycle evidence. Production `lan_auth.rs` now uses the adapter with a centralized latched-RNG
check; all one-shot outputs and inter-flight states use protected containers.
Failure injection covers every selected operation draw. See LAN-VALIDATION.md.

The engine-readiness cargo-deny check passed with the documented fixed-suite
advisory exception; final fresh deny passes after the owner-approved SQLite repair below.
Current locked vet passes with the owner-approved development exemptions
(94 fully audited,11 partially audited,480 exempted overall); this is a policy
check, not20 new audits. D12 and genuine new-family review remain release gates.

## Owner-approved SQLite advisory repair

The final fresh database scan found RUSTSEC-2026-0459 in the pre-existing
SQLite3.53.2. It describes process-memory disclosure from a crafted database
with a mismatched WAL page size. Existing pre-open WAL/SHM refusal mitigates the
route but was not used as an advisory waiver. On2026-11-09 the owner explicitly
instructed “Fix it” and requested completion without further scope expansion.

Only two existing packages changed; no new package/features:

| Package | Version | Registry SHA-256 |
|---------|---------|-----------------|
| rusqlite |0.41.0 | `9c026b4444579e8d754556c6c75d040d69c4a44283cdb648ab8a8d5965c2cfa8` |
| libsqlite3-sys |0.39.1 | `14a5f01b87b92705d07b433c06f96cbc764637d81a0bffb5734ce17cf0f9a2b3` |

The bundled engine is SQLite3.54.1, above the advisory's fixed3.54.0 boundary.
Upstream release/API notes identify mutable callback installation; the private
store harden helper and callers now use `&mut Connection` for the progress
budget callback. The existing compiled-version assertion is updated, and every
trimmed compile-option assertion remains. No file/archive schema, public core
API, SQLite feature or transaction/anchor ordering changes.

The existing exact-version development exemptions for these two packages were
carried forward with explicit unaudited-debt notes. This is not new audit evidence
or an expansion to arbitrary versions. cargo-deny and locked cargo-vet pass
(94 fully audited,11 partially audited,480 exempted overall). Source/release
references: [upstream release](https://github.com/rusqlite/rusqlite/releases/tag/v0.41.0)
and [RustSec record](https://raw.githubusercontent.com/RustSec/advisory-db/main/crates/libsqlite3-sys/RUSTSEC-2026-0459.md).
