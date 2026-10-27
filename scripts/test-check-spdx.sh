#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Exercise checker rejection without changing the real repository index/tree.
set -eu

checker=$(pwd)/scripts/check-spdx.sh
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/third-party/x11rb" "$fixture/third-party/other"
cat > "$fixture/bin/git" <<'EOF'
#!/bin/sh
printf '%s\n' "$QV_SPDX_TEST_FILES"
EOF
chmod +x "$fixture/bin/git"
PATH=$fixture/bin:$PATH
export PATH
cd "$fixture"

check() {
    expected=$1
    QV_SPDX_TEST_FILES=$2
    export QV_SPDX_TEST_FILES
    if sh "$checker" > result.log 2>&1; then
        actual=0
    else
        actual=1
    fi
    if [ "$actual" != "$expected" ]; then
        cat result.log
        echo "unexpected checker result: expected $expected, got $actual"
        exit 1
    fi
}

printf 'fn main() {}\n' > product.rs
check 1 product.rs
printf '// SPDX-License-Identifier: AGPL-3.0-or-later\n' > product.rs
check 0 product.rs
printf '// Upstream header\n' > third-party/x11rb/lib.rs
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
printf '%s\n' 9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414 > third-party/x11rb/UPSTREAM.sha256
check 0 third-party/x11rb/lib.rs
printf '[package]\nname = "other"\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0.13.3"\n[dependencies.protocol]\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0x13x2"\n' > third-party/x11rb/Cargo.toml
check 1 third-party/x11rb/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0.13.2"\n' > third-party/x11rb/Cargo.toml
printf 'wrong-hash\n' > third-party/x11rb/UPSTREAM.sha256
check 1 third-party/x11rb/lib.rs
printf '// Upstream header\n' > third-party/other/lib.rs
check 1 third-party/other/lib.rs
printf 'fn main() {}\n' > product.rs
check 1 product.rs
printf 'SPDX checker rejection tests passed\n'
