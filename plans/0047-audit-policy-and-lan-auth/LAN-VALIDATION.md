# LAN/2 local validation and D12 review package

2026-11-09. Implementation evidence for plan0047, assembled locally; no external
review request was sent. This is the same implementing agent's source review,
not independent cryptanalysis or a claim that tests prove security.

## Implemented boundary

Only lan/2 is admitted. The first complete valid code-MAC hello consumes the
code, stops/joins the sole listener owner and clears displayed admission codes
before KEM/credential work. Discovery remains off. Wrong-code attempts count
only before admission, up to16. Credential failure never reopens the code.

Password enrollment uses password input on both devices and a fresh, local
OPAQUE registration created only after A verifies its working vault password.
No registration/verifier is persisted or accepted from the receiver. Exact
Ristretto255/TripleDh/SHA512 suite, identities, contexts and Argon2 cost are
fixed by0013 §15 and DEPENDENCIES.md. X-Wing supplies the outer hybrid secret;
the password component's authentication is classical. No full post-quantum
password-authentication claim is made.

Typed initial/final channels enforce the KE3 boundary. A verifies KE3 and B's
first final-key FinishedB before its first final-key grant. Core atomically
checks the session, exact password-head/descriptor snapshot, policy, deadline,
cancel/lock flags and sealer binding/sequence before sealing once. A completed
seal means possible disclosure even if the frame is subsequently discarded.
B verifies the granted slot against its password and VK before bulk transfer.
Both passwords and derived password keys are discarded before transfer.

Phrase enrollment and existing-copy sync derive independent proof and schedule
secrets from an independently obtained VK. B proves first; A's identity/proof
follow only after verification. A accepts B's final-key State under credential
frame/time bounds before sending final-key data. These routes grant no VK.

The receiver fully authenticates private staging, binds its unique password
head to the password grant when applicable, and preflights the structural index
before no-replace publication. A source-bound private capability prevents
substitution by another staging object. Phrase enrollment preserves the shared
password. Fresh replica/anchor state is local. Post-publication failure or
cancellation retains the file, drops the new session and reports that a file
was created. Source receipt means complete transfer, not receiver publication.

## Local attack and regression evidence

| Boundary | Evidence in current sources |
|----------|-----------------------------|
| Custom code holder skips its own prompt | sync `lan_auth_code_holder_with_a_wrong_password_cannot_forge_a_finish_or_reuse_admission`: forged KE3 gets silence, no grant, no reopened listener |
| Final confirmation | sync `lan_auth_correct_ke3_without_valid_final_finished_releases_no_grant_or_data`: correct KE3 plus absent or modified FinishedB produces no final grant/data |
| Fake emitter / wrong identity | crypto password-response mutation/context tests; sync hostile-approver and vault-substitution tests; receiver slot unwrap/VK comparison |
| Role/method/session/epoch confusion | crypto v2 proof and channel tests reject reflection, replay, changed context, old epoch and exhausted counters; protocol malformed-mode/shape/property tests |
| Admission races | real loopback tests verify listener closure before approval, later connections cannot interrupt, replay finds no listener, invalid hello floods remain silent |
| Slot races and locking | four core grant tests cover password change before seal, seal before password change, wrong local password/pre-cancel, and lock/cancel after seal with disclosure preserved |
| Deadlines | absolute Conn cap survives epoch/exchange transition; original B deadline is forwarded before prompting and checked after work; expired/cancelled startup never prompts; authenticated expiry and candidate-cancel tests |
| Bulk/staging | hostile state/want/object tests, missing Done/retry tests; unique head/descriptor/object/hash binding and separate-staging substitution tests |
| Publication and reporting | injected post-rename fault keeps an openable anchored file; core cancellation barriers after publication and after platform binding return no Session while retaining a writable file |
| UI secrets / late work | instance-bound prompt tests, cancellation cleanup, locked-action reporting; real GTK/WebKit enrollment and boundary flows |
| Complete large transfer | stock67.5 MiB searchable-text fixture exercises both credential routes, reopens and traverses every search result |
| Offline / both directions | existing-copy sync loopback tests converge from either side, retain no peer/account state and do not touch remote checkpoints |

These are deterministic/local tests, not every possible network scheduling,
crash, relay or malicious component behavior. Continuous fuzz campaigns,
physical device lifecycle checks and independent composition analysis remain
separate evidence. Invalid FinishedB tests include omission and mutation;
record-layer replay rejection is tested separately rather than claiming a
single end-to-end test for every combination.

## Independent and component fixtures

See [vector provenance](../../crates/qv-crypto/tests/vectors/LAN-V2.md).
Python cryptography/cbor2/libsodium generators independently derive the three
mode contexts, outer/final keys, FinishedB, key proofs, commitments, comparison
codes, AAD and record ciphertext. The canonical wire fixtures include synthetic
OPAQUE bytes and a synthetic slot descriptor: they verify codec/transcript
composition, not a successful end-to-end PAKE transcript. The driver matches
these independently generated transcript bytes.

The upstream pinned opaque-ke4.0.1 Ristretto serialized component fixture uses
its test-only Identity KSF. It checks interoperability with that published
component; it does not replace the separate real-Argon2 wrapper round trips and
negative tests. Production never selects Identity or a peer-chosen KDF profile.
Exact upstream commit, source checksum, package hashes and regeneration commands
are retained beside the fixtures.

## Reproduction and check records

Host: Rust1.98.1, x86_64-unknown-linux-musl. Host disk exhaustion required this
session's temporary target directory; no product limit or assertion was lowered:

```sh
export CARGO_TARGET_DIR=/tmp/qv-0047-build
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
export QV_TEST_KDF_JOBS=2
sh scripts/check-spdx.sh
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --locked
# After correcting only the new store boundary-test assertion:
cargo test --locked -p qv-store -p qv-sync
cargo test --locked --doc
sh scripts/check-matrix.sh
cargo check --locked -p qv-crypto --all-targets --target aarch64-linux-android
RUST_TEST_THREADS=1 cargo test --locked -p qv-app --features validation
cargo deny check
cargo vet --locked
```

Native tests used the temporary Xvfb wrapper selected by QV_TEST_XVFB, with the
installed GTK/WebKit libraries. The passing native checkpoint contains94 app
unit tests and all3 real-window tests, including source password approval and
verified peer-open completion. Final post-publication-fix reruns are recorded in
REVIEW.md. Full-run core136, crypto133 (plus1 existing ignored), model79 and
protocol29 tests pass. The new store boundary fixture initially asserted budget
validation at the raw encoder instead of decode/seal; its corrected focused
test passes. The original failed command remains in the execution log. A subsequent complete
final workspace run after the SQLite fix passes, as recorded below. The Android command is a cross-compilation check, not an APK build or
an actual phone run. No device was accessed.

cargo-deny0.20.2 used repository policy with only its cache location redirected
to writable temporary storage. It now passes after the owner-approved upgrade
to rusqlite0.41.0/libsqlite3-sys0.39.1 (SQLite3.54.1), repairing RUSTSEC-2026-0459.
The existing WAL/SHM refusal and trimmed compile options are preserved and
checked. Locked vet0.10.3 passes with explicit exact development exemptions:
94 fully audited,11 partially audited,480 exempted overall. These are policy
classifications, not new audits.

The complete final `cargo test --locked` run after the SQLite change exits0;
main units include136 core,133 crypto (+1 existing ignored),79 model,29 protocol,
235 store and46 sync. All integration/doctests pass. Native94+3 and all-target
clippy also pass. Final invocation adds these temporary build-only settings:

```sh
export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_TEST_OPT_LEVEL=1
export CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=true CARGO_PROFILE_TEST_DEBUG_ASSERTIONS=true
export CARGO_PROFILE_DEV_OVERFLOW_CHECKS=true CARGO_PROFILE_TEST_OVERFLOW_CHECKS=true
```

No repository profile, assertion, KDF or test coverage is reduced. See REVIEW.md
for the earlier failed fixture assertion and final successful command. The
follow-up [0048](../0048-security-release-validation/PLAN.md) carries the open
release/qualification work below; it is Proposed, not started.

## Open release gates and review questions

- D12: independently assess this exact ephemeral-registration/outer-secret/
  credential-secret composition, role/intent identity binding, KE3→FinishedB→
  grant ordering and key-route State confirmation. Passing vectors is insufficient.
- Genuine dependency review of the20 exact additions. Recheck the narrowly
  traced crypto-bigint timing exception if the fixed suite/features/path change.
- Physical Android and Linux interactive tests in both enrollment directions:
  prompt/background/lock lifecycle, source biometric-unlocked state, cancellation,
  large transfer, adverse network and disk/anchor failures. Linux real-window
  tests and synthetic keystore fixtures do not stand in for these device cases.
- Target KDF latency/peak memory and representative large-vault workloads.
  Retain the selected cost pending evidence; no promise about phone latency.
- Dependency-private OPRF/HMAC/hash scratch and OS/framework copies have
  best-effort cleanup limits. Application inter-flight states/output are protected,
  the Argon2 block arena is wiped, and RNG failure prevents every output from
  escaping, but complete erasure is not established.
