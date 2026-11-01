#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks that every Rust source starts with the SPDX header and every shell
# script carries it on its first or second line (after a shebang). Covers
# tracked and untracked, non-ignored files, so it also works before a commit.
# Exact owner-approved vendor packages retain upstream headers (plans 0015/0030).

set -eu

rs_header='// SPDX-License-Identifier: AGPL-3.0-or-later'
sh_header='# SPDX-License-Identifier: AGPL-3.0-or-later'
missing=$(mktemp)
trap 'rm -f "$missing"' EXIT

approved_vendor() {
    case "$1" in
    third-party/x11rb/*) vendor_dir=third-party/x11rb; vendor_name=x11rb; vendor_version=0.13.2; vendor_hash=9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414 ;;
    third-party/dioxus-desktop/*) vendor_dir=third-party/dioxus-desktop; vendor_name=dioxus-desktop; vendor_version=0.7.10; vendor_hash=236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d ;;
    third-party/glib/*) vendor_dir=third-party/glib; vendor_name=glib; vendor_version=0.18.5; vendor_hash=233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5 ;;
    third-party/glib-macros/*) vendor_dir=third-party/glib-macros; vendor_name=glib-macros; vendor_version=0.18.5; vendor_hash=0bb0228f477c0900c880fd78c8759b95c7636dbd7842707f49e132378aa2acdc ;;
    third-party/gtk3-macros/*) vendor_dir=third-party/gtk3-macros; vendor_name=gtk3-macros; vendor_version=0.18.2; vendor_hash=52ff3c5b21f14f0736fed6dcfc0bfb4225ebf5725f3c0209edeec181e4d73e9d ;;
    third-party/selectors/*) vendor_dir=third-party/selectors; vendor_name=selectors; vendor_version=0.24.0; vendor_hash=0c37578180969d00692904465fb7f6b3d50b9a2b952b87c23d0e2e5cb5013416 ;;
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

git ls-files --cached --others --exclude-standard -- '*.rs' '*.sh' |
while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in
    third-party/*)
        if approved_vendor "$f"; then
            continue
        fi
        echo "invalid vendor identity/provenance: $f" | tee -a "$missing"
        continue ;;
    *.rs) [ "$(sed -n 1p "$f")" = "$rs_header" ] && continue ;;
    *.sh) { [ "$(sed -n 1p "$f")" = "$sh_header" ] || [ "$(sed -n 2p "$f")" = "$sh_header" ]; } && continue ;;
    esac
    echo "missing SPDX header: $f" | tee -a "$missing"
done

[ ! -s "$missing" ]
