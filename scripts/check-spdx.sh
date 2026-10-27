#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks that every Rust source starts with the SPDX header and every shell
# script carries it on its first or second line (after a shebang). Covers
# tracked and untracked, non-ignored files, so it also works before a commit.
# Only the owner-approved x11rb vendor package retains upstream headers.

set -eu

rs_header='// SPDX-License-Identifier: AGPL-3.0-or-later'
sh_header='# SPDX-License-Identifier: AGPL-3.0-or-later'
missing=$(mktemp)
trap 'rm -f "$missing"' EXIT

approved_vendor() {
    [ -f third-party/x11rb/Cargo.toml ] &&
    [ -f third-party/x11rb/UPSTREAM.sha256 ] &&
    [ "$(cat third-party/x11rb/UPSTREAM.sha256)" = \
      '9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414' ] &&
    awk '
        /^\[package\]$/ { package_section = 1; next }
        /^\[/ { package_section = 0 }
        package_section && $0 == "name = \"x11rb\"" { name_ok = 1 }
        package_section && $0 == "version = \"0.13.2\"" { version_ok = 1 }
        END { exit !(name_ok && version_ok) }
    ' third-party/x11rb/Cargo.toml
}

git ls-files --cached --others --exclude-standard -- '*.rs' '*.sh' |
while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in
    third-party/x11rb/*)
        if approved_vendor; then
            continue
        fi
        echo "invalid x11rb vendor identity/provenance: $f" | tee -a "$missing"
        continue ;;
    *.rs) [ "$(sed -n 1p "$f")" = "$rs_header" ] && continue ;;
    *.sh) { [ "$(sed -n 1p "$f")" = "$sh_header" ] || [ "$(sed -n 2p "$f")" = "$sh_header" ]; } && continue ;;
    esac
    echo "missing SPDX header: $f" | tee -a "$missing"
done

[ ! -s "$missing" ]
