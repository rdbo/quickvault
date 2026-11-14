#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build and run the disposable plan 0053 performance harness with exact product dependencies."""

import argparse
import os
from pathlib import Path
import json
import statistics
import shutil
import subprocess
import tempfile
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-only", action="store_true")
parser.add_argument("--samples", type=int, default=3)
parser.add_argument("--rows", default="30,90,180")
parser.add_argument("--label", default="run", help="name for the summary file")
parser.add_argument("--source-root", type=Path,
                    help="measure another checkout (e.g. a `git archive` of the baseline); "
                         "it builds in a private target directory")
args = parser.parse_args()
source = Path(__file__).resolve().parent
repo = (args.source_root or source.parents[1]).resolve()
work = Path(tempfile.mkdtemp(prefix="qv-0053-perf-", dir="/var/tmp"))
print(f"Private synthetic work and logs: {work}", flush=True)
scratch = work / "tool"
(scratch / "src").mkdir(parents=True)
shutil.copyfile(source / "perf-harness.rs", scratch / "src/main.rs")
core_path = repo / "crates/qv-core"
members = ''
(scratch / "Cargo.toml").write_text(
    '[package]\nname = "qv-perf-measurement"\nversion = "0.0.0"\n'
    'edition = "2024"\nlicense = "AGPL-3.0-or-later"\n[workspace]\n' + members +
    f'[dependencies]\nqv-core = {{ path = "{core_path}" }}\n'
    'zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }\n'
    '[lints.rust]\nunsafe_code = "forbid"\n[lints.clippy]\n'
    'unwrap_used = "deny"\nexpect_used = "deny"\npanic = "deny"\n'
)
shutil.copyfile(repo / "Cargo.lock", scratch / "Cargo.lock")
env = os.environ.copy()
target = work / "target" if args.source_root else repo / "target"
env["CARGO_TARGET_DIR"] = str(target)
for key, value in tomllib.loads((repo / ".cargo/config.toml").read_text())["env"].items():
    env[key] = value["value"]


def run(name, command):
    with (work / f"{name}.log").open("w") as log:
        result = subprocess.run(command, cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT)
    print(f"{name}: exit {result.returncode}", flush=True)
    if result.returncode:
        raise SystemExit(f"Failed: {work / f'{name}.log'}")


# Minimal re-resolution retains compatible product lock versions. Do not use
# generate-lockfile, which can choose newer cached transitive packages.
manifest = str(scratch / "Cargo.toml")
run("metadata", ["cargo", "metadata", "--offline", "--format-version", "1",
                 "--filter-platform", "x86_64-unknown-linux-musl", "--manifest-path", manifest])


def registry_packages(lockfile):
    return {(p["name"], p["version"], p.get("checksum"))
            for p in tomllib.loads(lockfile.read_text())["package"] if "source" in p}


if not registry_packages(scratch / "Cargo.lock") <= registry_packages(repo / "Cargo.lock"):
    raise SystemExit("Measurement dependency drift; refusing to build")
run("build", ["cargo", "build", "--release", "--locked", "--manifest-path", manifest])
run("clippy", ["cargo", "clippy", "--release", "--locked", "--manifest-path", manifest,
               "--", "-D", "warnings"])
if args.build_only:
    raise SystemExit(0)
exe = str(target / "release/qv-perf-measurement")
OPERATIONS = ["search", "fieldsearch", "refine", "kinds", "batch", "recursive"]
results = {}
for rows in [int(r) for r in args.rows.split(",")]:
    fixture = work / f"rows-{rows}"
    run(f"{rows}-generate", [exe, "generate", str(fixture), str(rows)])
    for operation in OPERATIONS:
        for n in range(args.samples):
            sample = work / f"rows-{rows}-{operation}"
            shutil.copytree(fixture, sample)
            name = f"{rows}-{operation}-{n}"
            run(name, [exe, "sample", str(sample), operation])
            # Fixture copies are large: keep only the logs.
            shutil.rmtree(sample)
            for line in (work / f"{name}.log").read_text().splitlines():
                parts = line.split(",")
                if len(parts) == 6 and parts[0] != "stage":
                    stage = parts[0]
                    key = f"{rows}/{operation if stage == operation else stage}"
                    before, peak = int(parts[2]), int(parts[4])
                    results.setdefault(key, []).append((float(parts[1]), peak - before, peak))
    shutil.rmtree(fixture)
summary = {key: {"median_ms": round(statistics.median(v[0] for v in values), 1),
                 "median_growth_kib": int(statistics.median(v[1] for v in values)),
                 "median_peak_kib": int(statistics.median(v[2] for v in values)),
                 "samples": len(values)}
           for key, values in sorted(results.items())}
out = work / f"summary-{args.label}.json"
out.write_text(json.dumps(summary, indent=1) + "\n")
for key, value in summary.items():
    print(f"{key}: {value}")
print(f"Summary: {out}")
