#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build and run the disposable capacity harness with exact product dependencies."""

import argparse
import difflib
import os
from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile
import tomllib

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--build-only", action="store_true")
parser.add_argument("--instrument-preparation", action="store_true",
                    help="trace prepared Vec<Change> RSS in a disposable core copy")
args = parser.parse_args()
source = Path(__file__).resolve().parent
repo = source.parents[1]
work = Path(tempfile.mkdtemp(prefix="qv-0048-capacity-", dir="/var/tmp"))
print(f"Private synthetic work and logs: {work}", flush=True)
scratch = work / "tool"
(scratch / "src").mkdir(parents=True)
shutil.copyfile(source / "capacity-harness.rs", scratch / "src/main.rs")
core_path = repo / "crates/qv-core"
if args.instrument_preparation:
    core_path = scratch / "instrumented-core"
    shutil.copytree(repo / "crates/qv-core/src", core_path / "src")
    workspace = tomllib.loads((repo / "Cargo.toml").read_text())
    manifest_text = (repo / "crates/qv-core/Cargo.toml").read_text()

    def literal(value):
        if isinstance(value, dict):
            return "{ " + ", ".join(f"{key} = {literal(item)}" for key, item in value.items()) + " }"
        return json.dumps(value)

    for key, value in workspace["workspace"]["package"].items():
        manifest_text = re.sub(rf"^{re.escape(key)}\.workspace = true$",
                               lambda _: f"{key} = {literal(value)}", manifest_text, flags=re.M)
    manifest_text = re.sub(r'\[dev-dependencies\]\n.*?(?=\n\[)', '', manifest_text, flags=re.S)
    for key, value in workspace["workspace"]["dependencies"].items():
        if isinstance(value, dict) and "path" in value:
            value = {**value, "path": str(repo / value["path"])}
        manifest_text = manifest_text.replace(f"{key}.workspace = true", f"{key} = {literal(value)}")
    lints = "\n".join(f"[lints.{kind}]\n" + "\n".join(f"{key} = {literal(value)}"
                        for key, value in values.items())
                      for kind, values in workspace["workspace"]["lints"].items())
    manifest_text = manifest_text.replace("[lints]\nworkspace = true", lints)
    (core_path / "Cargo.toml").write_text(manifest_text)
    edit = core_path / "src/edit.rs"
    marker = '    if changes.is_empty() {\n'
    trace = '''    if std::env::var_os("QV_CAPACITY_TRACE").is_some() {
        let rss = std::fs::read_to_string("/proc/self/status").ok()
            .and_then(|status| status.lines().find_map(|line| line.strip_prefix("VmRSS:")
                .and_then(|value| value.split_whitespace().next()?.parse::<u64>().ok())));
        eprintln!("prepared_changes,{},{rss:?}", changes.len());
    }
'''
    original = edit.read_text()
    if original.count(marker) != 1:
        raise SystemExit("Preparation trace insertion point changed; review before instrumenting")
    edit.write_text(original.replace(marker, trace + marker))
    (work / "preparation-trace.patch").write_text("".join(difflib.unified_diff(
        original.splitlines(keepends=True), edit.read_text().splitlines(keepends=True),
        fromfile="a/crates/qv-core/src/edit.rs", tofile="b/crates/qv-core/src/edit.rs", n=0)))
    # The copy is a workspace member; original product source remains untouched.
    members = 'members = ["instrumented-core"]\n'
else:
    members = ''
(scratch / "Cargo.toml").write_text(
    '[package]\nname = "qv-capacity-measurement"\nversion = "0.0.0"\n'
    'edition = "2024"\nlicense = "AGPL-3.0-or-later"\n[workspace]\n' + members +
    f'[dependencies]\nqv-core = {{ path = "{core_path}" }}\n'
    'zeroize = { version = "=1.9.1", default-features = false, features = ["alloc"] }\n'
    '[lints.rust]\nunsafe_code = "forbid"\n[lints.clippy]\n'
    'unwrap_used = "deny"\nexpect_used = "deny"\npanic = "deny"\n'
)
shutil.copyfile(repo / "Cargo.lock", scratch / "Cargo.lock")
env = os.environ.copy()
env["CARGO_TARGET_DIR"] = str(repo / "target")
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
exe = str(repo / "target/release/qv-capacity-measurement")
for rows in [30, 90, 180]:
    fixture = work / f"rows-{rows}"
    run(f"{rows}-generate", [exe, "generate", str(fixture), str(rows)])
    for operation in ["search", "prepare", "batch", "recursive"]:
        sample = work / f"rows-{rows}-{operation}"
        shutil.copytree(fixture, sample)
        if args.instrument_preparation:
            env["QV_CAPACITY_TRACE"] = "1"
        run(f"{rows}-{operation}", [exe, "sample", str(sample), operation])
        env.pop("QV_CAPACITY_TRACE", None)
