# Large-vault qualification evidence

2026-11-09; product source/dependency baseline
`ee0cafdd56af1b9593445cb632f0f1be3e7e101a`. These are synthetic development
measurements, with no owner-selected latency/RSS threshold or representative
conflicted workload. They do not constitute release qualification.

## Host and build

Alpine Linux / x86_64-unknown-linux-musl, Linux 7.3.1-0-sigma, Ryzen 9 9900X
(12 cores / 24 threads), 14.7 GiB RAM and swap enabled. Rust/Cargo 1.98.1.
The benchmark uses the stock optimized release profile, final pinned
dependencies and the forced SQLite flags in `.cargo/config.toml`. No production
limit, KDF parameter or compile flag was reduced. Core measurements exclude
Dioxus/WebKit and platform-service integration.

```sh
cargo build --release --locked -p qv-core --example budget_bench
# Use a fresh owner-only directory; repeat for P0, P1, P2, P3.
target/release/examples/budget_bench generate "$work/P3" P3
target/release/examples/budget_bench measure "$work/P3" 3
```

The generator creates private vault/anchor directories and a 0600 synthetic
password file; the password is never an argument. It fully verifies each
generated vault. Measurement uses one warm-up and three samples, each in a new
child process. Each sample unlocks, fully verifies, commits one ordinary edit,
then locks. Samples therefore advance the first entry's history; they are not
bit-identical copies. Peak RSS comes from the child, not the build command.
These are warm-filesystem observations, not cold-cache or statistical claims.

## Existing profile datasets

| Profile | Authored contents | Generation verification |
|---------|-------------------|-------------------------|
| P0 | Empty ordinary vault (control records only) | Complete verification passed |
| P1 | 1,000 entries, four versions each, twenty 1 MiB attachments | Complete verification passed |
| P2 | 49,997 entries plus three control records, four versions per entry | 50,000 records, 199,991 objects, 149,991 retained versions; complete verification passed |
| P3 | One entry plus ninety-nine actual 10 MiB attachments | 103 records, 15,943 objects, 1,071,077,760 referenced ciphertext bytes; complete verification passed |

P3 fills **99.752% of the 1 GiB referenced-ciphertext budget** with physically
stored encrypted objects. Its SQLite file is 1,106,440,192 bytes at generation;
file size includes database overhead and is distinct from the ciphertext
budget. This is a populated near-limit vault, not manifest arithmetic. It is
attachment-heavy, with only one searchable entry; it does not establish the
performance of near-limit searchable text, conflicts or GUI memory.

The first host timing series ran while build/test work was also active. Retain
it as preliminary evidence, not an isolated latency baseline. A final series
and the device measurements follow. No repository build/test was active during
the final host timing series; ambient desktop/OS load and clocks were not fixed.

Medians of three measured samples (milliseconds); RSS is the largest child
process high-water mark in those samples, in KiB:

| Profile | Host unlock | Host verify | Host edit | Host peak RSS | Phone unlock | Phone verify | Phone edit | Phone peak RSS |
|---------|-------------|-------------|-----------|---------------|--------------|--------------|------------|----------------|
| P0 | 460.3 | 0.1 | 0.4 | 265,880 | 931.0 | 0.4 | 20.3 | 268,928 |
| P1 | 544.2 | 139.9 | 56.8 | 267,976 | 1,177.8 | 436.3 | 216.8 | 270,720 |
| P2 | 4,690.8 | 3,105.7 | 3,255.7 | 268,144 | 16,124.5 | 11,742.1 | 11,951.0 | 325,748 |
| P3 | 673.8 | 3,932.7 | 14.9 | 267,756 | 1,496.1 | 12,885.4 | 76.1 | 270,968 |

Raw rows are `evidence/P*-measure-final.log` and
`evidence/phone-P*-measure-private.log`. Original generation counts above
precede the benchmark's ordinary edits. Phone runs used the snapshots of all
four host fixtures after the initial host series, before the final host series.

Phone: POCO X7 Pro / 2412DPC0AG, Android 15/API 35, arm64-v8a. The same
`budget_bench` was cross-built with Rust 1.98.1, release/locked, target
`aarch64-linux-android`, NDK 27.3.13750724 and the repository's Android API29
linker/SQLite settings. ADB pushed it and the fixtures into a freshly created
0700 `/data/local/tmp/qv-0048.*` directory. ADB changed file permissions to
0666, so the first P0 attempt correctly failed `Store(UnsafeFile)`. Restoring
owner-only file/directory modes inside this disposable subtree allowed every
profile to pass. No storage protection was relaxed.

Each phone measurement command was:

```text
adb shell <private-root>/budget_bench measure <private-root>/P0 3
```

Repeat for P1/P2/P3. These are real physical-device core/KDF/SQLite measurements
under the shell UID, with no app UI or keystore backend. P0 is a small-vault
full unlock timing, not an isolated LAN-authentication KDF timing. Host and
phone use different filesystems; phone editing/fsync costs are visible. No
claim of phone-app RSS, biometric behavior or LAN transfer follows from them.

## Stock searchable-text lifecycle

Fresh final-dependency optimized run:

```sh
QV_TEST_KDF_JOBS=2 cargo test --release --locked -p qv-core large_vault_stock -- --nocapture
```

Passed: 90 entries, three 256 KiB searchable values each (67.5 MiB total), all
90 hits across 45 bounded pages, edit, archive export/import, snapshot restore,
phrase unlock, rotation, password and key LAN enrollment/reopen, and synthetic
keystore open. Complete fixture duration: 34.67 s. Observed authoring 0.614 s,
password open 2.167 s, complete search 0.626 s, password enrollment/reopen
6.428 s, key enrollment/reopen 4.386 s, synthetic quick open/search 1.540 s.
Process high-water RSS reached 341,228 KiB. Other host checks were running;
these are individual functional-run observations. Synthetic quick unlock and
same-host loopback LAN do not establish physical biometric/interoperability
evidence. The fixed cache accounting assertions remained enabled.

## Separate mutation costs and remaining scope

The unmodified public-API capacity harness was also cross-built release/locked
for Android and run under the same private shell UID. It authored and verified
fresh searchable-text fixtures on the phone, then measured complete paged
traversal/search and lock, with integrity and unchanged-commit-count checks:

| Phone fixture | Password open | Complete paged handle traversal | Complete search | Search sampled RSS peak |
|---------------|---------------|---------------------------------|-----------------|-------------------------|
| 90 rows / 67.5 MiB values | 4.003 s | 2.160 s | 2.204 s | 79,416 KiB |
| 180 rows / 135 MiB values | 7.576 s | 70.585 s | 70.895 s | 79,440 KiB |

Both pass; raw `evidence/phone-capacity-*-{generate,search}.log` files retain
every stage, including the process high-water RSS of 270,848 KiB. These are
single homogeneous ASCII runs, not a distribution or a GUI measurement.
The sharp latency increase beyond cache residency is a recorded performance
finding. No latency target, text eligibility cap or alternative index was
selected. The device's disposable benchmark subtree is removed after recording
the results; source/commands remain reproducible.

[CAPACITY.md](CAPACITY.md) separates paged reads, held decoded-draft preparation
and actual atomic batch/recursive mutations on 22.5, 67.5 and 135 MiB
searchable-text fixtures. The cache ceiling is not a process-RSS ceiling.

Remaining qualification includes owner-selected representative/conflicted
datasets, actual app process memory and lifecycle, both physical LAN enrollment
directions/methods, adverse-network/publication outcomes, physical biometric
source behavior and the supported-target acceptance criteria. Record phone
core benchmarks separately from app/device tests in [DEVICE-VALIDATION.md](DEVICE-VALIDATION.md).
