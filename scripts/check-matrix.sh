#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Offline release matrix check (spec 0012 §1, §3; plan 0024).
#
# Every row listed in tests/matrix-offline.txt must have at least one test
# tagged with a line `// 0012 §1: <exact row name>` directly above the
# test's attributes (only comments and attributes may come between the tag
# and the `fn`, and one of the attributes must be `#[test]`). A tag must
# name a row of the 0012 §1 table. This checks naming only; `cargo test`
# checks that the tagged tests pass.
set -eu

cd "$(dirname "$0")/.."
list=tests/matrix-offline.txt
spec=specs/0012-security-validation.md
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Row names of the 0012 §1 table: the first cell of each body row.
awk '
  /^### 1\./ { inside = 1; next }
  /^### /    { inside = 0 }
  inside && /^\| / && !/^\| Finding / && !/^\|-/ {
    split($0, cell, "|"); name = cell[2]
    gsub(/^ +| +$/, "", name); print name
  }
' "$spec" | sort -u > "$tmp/spec-rows"

grep -v '^#' "$list" | sed '/^[[:space:]]*$/d' > "$tmp/wanted"

status=0
while IFS= read -r row; do
  if ! grep -Fxq -- "$row" "$tmp/spec-rows"; then
    echo "matrix list: not a 0012 §1 row: $row" >&2
    status=1
  fi
done < "$tmp/wanted"

# Tags, each checked to sit on a #[test] function: "row<TAB>file:line".
git ls-files 'crates/*.rs' | while IFS= read -r file; do
  awk -v file="$file" '
    function flush(ok) {
      for (i = 1; i <= n; i++) {
        if (ok) printf "%s\t%s:%d\n", tag[i], file, at[i]
        else printf "misplaced tag (not on a #[test] fn): %s:%d\n", file, at[i] > "/dev/stderr"
      }
      n = 0; seen_test = 0
    }
    {
      line = $0; sub(/^[ \t]+/, "", line)
      if (line ~ /^\/\/ 0012 §1: /) {
        sub(/^\/\/ 0012 §1: /, "", line); sub(/[ \t]+$/, "", line)
        n++; tag[n] = line; at[n] = NR; next
      }
      if (n == 0) next
      if (line ~ /^#\[test\]/) { seen_test = 1; next }
      if (line ~ /^(\/\/|#\[)/) next
      flush(seen_test && line ~ /(^|[ \t])fn /)
    }
    END { if (n > 0) flush(0) }
  ' "$file"
done > "$tmp/tags" 2> "$tmp/misplaced"

if [ -s "$tmp/misplaced" ]; then
  cat "$tmp/misplaced" >&2
  status=1
fi

cut -f1 "$tmp/tags" | sort -u > "$tmp/tagged"
while IFS= read -r row; do
  if ! grep -Fxq -- "$row" "$tmp/spec-rows"; then
    echo "unknown row in a tag: $row" >&2
    grep -F -- "$row	" "$tmp/tags" | cut -f2 | sed 's/^/  at /' >&2
    status=1
  fi
done < "$tmp/tagged"

while IFS= read -r row; do
  count=$(cut -f1 "$tmp/tags" | grep -Fxc -- "$row" || true)
  printf '%3d  %s\n' "$count" "$row"
  if [ "$count" -eq 0 ]; then
    echo "matrix: no tagged test for offline row: $row" >&2
    status=1
  fi
done < "$tmp/wanted"

exit "$status"
