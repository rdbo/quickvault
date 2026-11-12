#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks that every Rust source starts with the SPDX header and every shell
# or PowerShell script carries it on its first or second line (after a
# shebang). Covers tracked and untracked, non-ignored files, so it also
# works before a commit.
# The exact owner-approved vendor package retains upstream headers (plan 0030).

set -eu

rs_header='// SPDX-License-Identifier: AGPL-3.0-or-later'
sh_header='# SPDX-License-Identifier: AGPL-3.0-or-later'
missing=$(mktemp)
trap 'rm -f "$missing"' EXIT

approved_vendor() {
    case "$1" in
    third-party/dioxus-desktop/*) vendor_dir=third-party/dioxus-desktop; vendor_name=dioxus-desktop; vendor_version=0.7.10; vendor_hash=236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d ;;
    *) return 1 ;;
    esac
    [ -f "$vendor_dir/Cargo.toml" ] &&
    [ -f "$vendor_dir/UPSTREAM.sha256" ] &&
    [ "$(cat "$vendor_dir/UPSTREAM.sha256")" = "$vendor_hash" ] &&
    awk -v name="$vendor_name" -v version="$vendor_version" '
        /^\[package\]$/ { package_section = 1; next }
        /^\[/ { package_section = 0 }
        package_section && $0 == "name = \"" name "\"" { name_ok = 1 }
        package_section && $0 == "version = \"" version "\"" { version_ok = 1 }
        END { exit !(name_ok && version_ok) }
    ' "$vendor_dir/Cargo.toml"
}

files=$(git ls-files --cached --others --exclude-standard -- '*.rs' '*.sh' '*.ps1') || {
    echo 'cannot list source files for SPDX check' >&2
    exit 1
}
printf '%s\n' "$files" |
while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in
    third-party/*)
        if approved_vendor "$f"; then
            continue
        fi
        echo "invalid vendor identity metadata: $f" | tee -a "$missing"
        continue ;;
    *.rs) [ "$(sed -n 1p "$f")" = "$rs_header" ] && continue ;;
    *.sh|*.ps1) { [ "$(sed -n 1p "$f")" = "$sh_header" ] || [ "$(sed -n 2p "$f")" = "$sh_header" ]; } && continue ;;
    esac
    echo "missing SPDX header: $f" | tee -a "$missing"
done

[ ! -s "$missing" ]
