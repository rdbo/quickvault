#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Exercise checker rejection without changing the real repository index/tree.
set -eu

checker=$(pwd)/scripts/check-spdx.sh
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
mkdir -p "$fixture/bin" "$fixture/third-party/dioxus-desktop" "$fixture/third-party/other"
cat > "$fixture/bin/git" <<'EOF'
#!/bin/sh
[ "${QV_SPDX_TEST_GIT_FAIL:-0}" = 0 ] || exit 1
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
printf 'Write-Output 1\n' > package.ps1
check 1 package.ps1
printf '# SPDX-License-Identifier: AGPL-3.0-or-later\nWrite-Output 1\n' > package.ps1
check 0 package.ps1
printf '// SPDX-License-Identifier: AGPL-3.0-or-later\n' > product.rs
check 0 product.rs
# A failed file listing must not look like an empty successful scan.
QV_SPDX_TEST_GIT_FAIL=1
export QV_SPDX_TEST_GIT_FAIL
check 1 product.rs
QV_SPDX_TEST_GIT_FAIL=0
export QV_SPDX_TEST_GIT_FAIL
printf '// Upstream header\n' > third-party/dioxus-desktop/lib.rs
check 1 third-party/dioxus-desktop/lib.rs
printf '[package]\nname = "dioxus-desktop"\nversion = "0.7.10"\n' > third-party/dioxus-desktop/Cargo.toml
printf '%s\n' 236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d > third-party/dioxus-desktop/UPSTREAM.sha256
check 0 third-party/dioxus-desktop/lib.rs
printf '[package]\nname = "other"\nversion = "0.7.10"\n' > third-party/dioxus-desktop/Cargo.toml
check 1 third-party/dioxus-desktop/lib.rs
printf '[package]\nname = "dioxus-desktop"\nversion = "0.7.11"\n[dependencies.core]\nversion = "0.7.10"\n' > third-party/dioxus-desktop/Cargo.toml
check 1 third-party/dioxus-desktop/lib.rs
printf '[package]\nname = "x11rb"\nversion = "0x13x2"\n' > third-party/dioxus-desktop/Cargo.toml
check 1 third-party/dioxus-desktop/lib.rs
printf '[package]\nname = "dioxus-desktop"\nversion = "0.7.10"\n' > third-party/dioxus-desktop/Cargo.toml
printf 'wrong-hash\n' > third-party/dioxus-desktop/UPSTREAM.sha256
check 1 third-party/dioxus-desktop/lib.rs
printf '// Upstream header\n' > third-party/other/lib.rs
check 1 third-party/other/lib.rs
printf 'fn main() {}\n' > product.rs
check 1 product.rs
printf 'Write-Output 1\n' > package.ps1
check 1 package.ps1
printf '# SPDX-License-Identifier: AGPL-3.0-or-later\nWrite-Output 1\n' > package.ps1
check 0 package.ps1
mkdir -p third-party/dioxus-desktop
printf '// Upstream header\n' > third-party/dioxus-desktop/lib.rs
printf '[package]\nname = "dioxus-desktop"\nversion = "0.7.10"\n' > third-party/dioxus-desktop/Cargo.toml
printf '236deb81f1a04de704fb80cf7838c65607441c76914de2e036709540c540a39d\n' > third-party/dioxus-desktop/UPSTREAM.sha256
check 0 third-party/dioxus-desktop/lib.rs
printf 'wrong-hash\n' > third-party/dioxus-desktop/UPSTREAM.sha256
check 1 third-party/dioxus-desktop/lib.rs
# Packages removed by plan 0032 are no longer exempt, even with their former
# exact identity and upstream hash.
for removed in \
    "x11rb 0.13.2 9993aa5be5a26815fe2c3eacfc1fde061fc1a1f094bf1ad2a18bf9c495dd7414" \
    "glib 0.18.5 233daaf6e83ae6a12a52055f568f9d7cf4671dabb78ff9560ab6da230ce00ee5" \
    "glib-macros 0.18.5 0bb0228f477c0900c880fd78c8759b95c7636dbd7842707f49e132378aa2acdc" \
    "gtk3-macros 0.18.2 52ff3c5b21f14f0736fed6dcfc0bfb4225ebf5725f3c0209edeec181e4d73e9d" \
    "selectors 0.24.0 0c37578180969d00692904465fb7f6b3d50b9a2b952b87c23d0e2e5cb5013416"; do
    set -- $removed
    mkdir -p "third-party/$1"
    printf '// Upstream header\n' > "third-party/$1/lib.rs"
    printf '[package]\nname = "%s"\nversion = "%s"\n' "$1" "$2" > "third-party/$1/Cargo.toml"
    printf '%s\n' "$3" > "third-party/$1/UPSTREAM.sha256"
    check 1 "third-party/$1/lib.rs"
done
printf 'SPDX checker rejection tests passed\n'
