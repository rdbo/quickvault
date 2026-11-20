#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Check exact lockfile and exemption hygiene."""
from pathlib import Path
import sys
import tomllib

root = Path(__file__).resolve().parent.parent


def packages(path):
    return {(p["name"], p["version"]): p.get("checksum")
            for p in tomllib.loads((root / path).read_text())["package"] if "source" in p}


product, fuzz = packages("Cargo.lock"), packages("fuzz/Cargo.lock")
product_names = {name for name, _ in product}
errors = []
for key, checksum in fuzz.items():
    if key[0] in product_names and (key not in product or product[key] != checksum):
        errors.append(f"fuzz/product resolution drift: {key[0]} {key[1]}")
config = tomllib.loads((root / "supply-chain/config.toml").read_text())
# These absent versions are necessary roots of existing imported delta-audit
# chains, not stale entries. cargo vet verifies complete criterion coverage.
delta_bases = {("futures-task", "0.3.21"), ("futures-util", "0.3.21"),
               ("itertools", "0.10.3"), ("once_cell", "1.12.0"),
               ("wasm-bindgen-macro", "0.2.99"), ("wasm-bindgen-shared", "0.2.100")}
imports = tomllib.loads((root / "supply-chain/imports.lock").read_text())
for name, entries in config.get("exemptions", {}).items():
    for entry in entries:
        if (name, entry["version"]) not in product.keys() | fuzz.keys():
            base = (name, entry["version"])
            referenced = any(entry["version"] in audit.get("delta", "").split(" -> ")
                             for source in imports.get("audits", {}).values()
                             for audit in source.get("audits", {}).get(name, []))
            if base not in delta_bases or not referenced or "delta-audit base" not in entry.get("notes", ""):
                errors.append(f"stale exemption: {name} {entry['version']}")
if errors:
    print("\n".join(errors), file=sys.stderr)
    raise SystemExit(1)
print("supply-chain baseline: shared resolution and exemptions match")
