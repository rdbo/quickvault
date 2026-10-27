#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build and inspect only; this script never connects to or installs on a phone.
set -eu
spike_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$spike_dir"
qv_dx=${QV_DX:-dx}
case "$("$qv_dx" --version)" in
    'dioxus 0.7.3'*) ;;
    *) echo 'Use the pinned Dioxus CLI 0.7.3 (QV_DX selects its path).' >&2; exit 1 ;;
esac
: "${ANDROID_HOME:?Source scripts/setup-android.sh --print-env first}"
: "${JAVA_HOME:?Select a supported JDK (validated with JDK 21)}"
"$qv_dx" build --platform android --target aarch64-linux-android --release \
    --features mobile --cargo-args=--locked
# Dioxus 0.7.3 uses android_min_sdk_version for native linking but hardcodes
# minSdk=24 in Gradle. Copy its generated package and enforce the baseline in
# the APK as well, without patching the framework or its registry source.
qv_project=$(python3 - <<'PY'
from pathlib import Path
import shutil,time
root=Path.cwd()
source=root/'target/dx/qv-ui-feasibility/release/android/app'
destination=root/'dist'/f'android-project-{time.time_ns()}'
shutil.copytree(source,destination,ignore=shutil.ignore_patterns('build','.gradle'))
p=destination/'app/build.gradle.kts'
s=p.read_text()
if s.count('minSdk = 24')!=1:
    raise SystemExit('Unexpected upstream minSdk template; review it before packaging')
p.write_text(s.replace('minSdk = 24','minSdk = 29',1))
# Preserve the framework's required loopback transport exception, explicitly
# disallowing cleartext to remote hosts. The custom manifest references it.
shutil.copyfile(root/'android/network_security_config.xml',
                destination/'app/src/main/res/xml/network_security_config.xml')
print(destination)
PY
)
sh "$qv_project/gradlew" -p "$qv_project" :app:assembleDebug --no-daemon
cp "$qv_project/app/build/outputs/apk/debug/app-debug.apk" dist/qv-ui-feasibility-debug.apk
"$ANDROID_HOME/build-tools/34.0.0/aapt" dump badging dist/qv-ui-feasibility-debug.apk > dist/apk-badging.txt
"$ANDROID_HOME/build-tools/34.0.0/aapt" dump permissions dist/qv-ui-feasibility-debug.apk > dist/apk-permissions.txt
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
import hashlib
badging=Path('dist/apk-badging.txt').read_text()
permissions=Path('dist/apk-permissions.txt').read_text()
if "package: name='org.quickvault.feasibility'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit('Unexpected package or minimum SDK')
for line in permissions.splitlines():
    if line.startswith('uses-permission:') and not any(allowed in line for allowed in (
        "name='org.quickvault.feasibility.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'",
        "name='android.permission.INTERNET'",  # Dioxus loopback UI transport
    )):
        raise SystemExit('Unexpected requested permission; inspect before installing')
manifest=ET.parse('android/AndroidManifest.xml')
ns='{http://schemas.android.com/apk/res/android}'
app=manifest.find('application')
if app is None or app.get(ns+'allowBackup')!='false':
    raise SystemExit('Backup policy is not disabled')
p=Path('dist/qv-ui-feasibility-debug.apk')
print('APK SHA-256:',hashlib.sha256(p.read_bytes()).hexdigest())
print('Built only. Inspect the final manifest/signature before any device install.')
PY
