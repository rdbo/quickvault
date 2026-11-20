#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks that every Rust source starts with the SPDX header and every shell
# or PowerShell script carries it on its first or second line (after a
# shebang). Covers tracked and untracked, non-ignored files, so it also
# works before a commit.
# No vendored sources are approved any more: the last one, dioxus-desktop,
# left with the Dioxus renderer (plan 0071).

set -eu

rs_header='// SPDX-License-Identifier: AGPL-3.0-or-later'
sh_header='# SPDX-License-Identifier: AGPL-3.0-or-later'
missing=$(mktemp)
trap 'rm -f "$missing"' EXIT

files=$(git ls-files --cached --others --exclude-standard -- '*.rs' '*.sh' '*.ps1') || {
    echo 'cannot list source files for SPDX check' >&2
    exit 1
}
printf '%s\n' "$files" |
while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in
    third-party/*)
        echo "unapproved vendored source: $f" | tee -a "$missing"
        continue ;;
    *.rs) [ "$(sed -n 1p "$f")" = "$rs_header" ] && continue ;;
    *.sh|*.ps1) { [ "$(sed -n 1p "$f")" = "$sh_header" ] || [ "$(sed -n 2p "$f")" = "$sh_header" ]; } && continue ;;
    esac
    echo "missing SPDX header: $f" | tee -a "$missing"
done

[ ! -s "$missing" ]
