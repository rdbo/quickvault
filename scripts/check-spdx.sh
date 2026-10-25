#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Checks that every Rust source starts with the SPDX header and every shell
# script carries it on its first or second line (after a shebang). Covers
# tracked and untracked, non-ignored files, so it also works before a commit.

set -eu

rs_header='// SPDX-License-Identifier: AGPL-3.0-or-later'
sh_header='# SPDX-License-Identifier: AGPL-3.0-or-later'
missing=$(mktemp)
trap 'rm -f "$missing"' EXIT

git ls-files --cached --others --exclude-standard -- '*.rs' '*.sh' |
while IFS= read -r f; do
    [ -f "$f" ] || continue
    case "$f" in
    *.rs) [ "$(sed -n 1p "$f")" = "$rs_header" ] && continue ;;
    *.sh) { [ "$(sed -n 1p "$f")" = "$sh_header" ] || [ "$(sed -n 2p "$f")" = "$sh_header" ]; } && continue ;;
    esac
    echo "missing SPDX header: $f" | tee -a "$missing"
done

[ ! -s "$missing" ]
