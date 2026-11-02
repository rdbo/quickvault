#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Build and inspect only; this script never connects to or installs on a phone.
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$app_dir"
# Keep tooling caches and the debug signing key out of read-only user homes.
qv_cache=${QV_APP_BUILD_CACHE:-$app_dir/dist/.build-cache}
mkdir -p "$qv_cache"
export DX_HOME=${DX_HOME:-$qv_cache/dx}
export GRADLE_USER_HOME=${GRADLE_USER_HOME:-$qv_cache/gradle}
export ANDROID_USER_HOME=${QV_ANDROID_USER_HOME:-$qv_cache/android-user}
qv_dx=${QV_DX:-dx}
case "$("$qv_dx" --version)" in
    'dioxus 0.7.10'*) ;;
    *) echo 'Use the pinned Dioxus CLI 0.7.10 (QV_DX selects its path).' >&2; exit 1 ;;
esac
: "${ANDROID_HOME:?Source scripts/setup-android.sh --print-env first}"
: "${JAVA_HOME:?Select a supported JDK (validated with JDK 21)}"
qv_features=mobile
qv_artifact=quickvault
if [ "${QV_APP_DEVICE_VALIDATION:-0}" = 1 ]; then
    qv_features=mobile,validation
    qv_artifact=quickvault-validation
fi
export QV_APP_BUILT_APK="dist/$qv_artifact-debug.apk"
"$qv_dx" build --platform android --target aarch64-linux-android --release \
    --features "$qv_features" --package qv-app --bin quickvault --cargo-args=--locked
# Dioxus 0.7.10 uses android_min_sdk_version for native linking but hardcodes
# minSdk=24 in Gradle. Copy its generated package and enforce the baseline in
# the APK as well, without patching the framework or its registry source.
qv_project=$(python3 - <<'PY'
from pathlib import Path
import shutil,time,re
root=Path.cwd()
source=root.parent.parent/'target/dx/quickvault/release/android/app'
destination=root/'dist'/f'android-project-{time.time_ns()}'
shutil.copytree(source,destination,ignore=shutil.ignore_patterns('build','.gradle'))
p=destination/'app/build.gradle.kts'
s=p.read_text()
if len(re.findall(r"minSdk = (?:24|29)\b",s))!=1:
    raise SystemExit('Unexpected upstream minSdk template; review it before packaging')
s=re.sub(r'minSdk = (?:24|29)\b','minSdk = 29',s,count=1)
s=s.replace('android {','android {\n    useLibrary("android.test.runner")\n    useLibrary("android.test.base")\n    useLibrary("android.test.mock")',1)
s=s.replace('defaultConfig {','defaultConfig {\n        testInstrumentationRunner = "android.test.InstrumentationTestRunner"',1)
p.write_text(s)
tests=destination/'app/src/androidTest/java/org/quickvault/app'
tests.mkdir(parents=True)
shutil.copyfile(root/'android/tests/PlatformTest.java',tests/'PlatformTest.java')
shutil.copyfile(root/'android/tests/QuickUnlockTest.java',tests/'QuickUnlockTest.java')
shutil.copyfile(root/'android/tests/QuickUnlockUiTest.java',tests/'QuickUnlockUiTest.java')
fixture_assets=destination/'app/src/androidTest/assets'
fixture_assets.mkdir(parents=True)
shutil.copyfile(root/'android/tests/flows.js',fixture_assets/'flows.js')
shutil.copyfile(root/'android/tests/AndroidManifest.xml',destination/'app/src/androidTest/AndroidManifest.xml')
# Preserve the framework's required loopback transport exception, explicitly
# disallowing cleartext to remote hosts. The custom manifest references it.
shutil.copyfile(root/'android/network_security_config.xml',
                destination/'app/src/main/res/xml/network_security_config.xml')
print(destination)
PY
)
sh "$qv_project/gradlew" -p "$qv_project" :app:assembleDebug :app:assembleDebugAndroidTest --no-daemon
cp "$qv_project/app/build/outputs/apk/debug/app-debug.apk" "dist/$qv_artifact-debug.apk"
cp "$qv_project/app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk" "dist/$qv_artifact-tests.apk"
"$ANDROID_HOME/build-tools/35.0.0/aapt" dump badging "dist/$qv_artifact-debug.apk" > dist/apk-badging.txt
"$ANDROID_HOME/build-tools/35.0.0/aapt" dump permissions "dist/$qv_artifact-debug.apk" > dist/apk-permissions.txt
python3 - <<'PY'
from pathlib import Path
import xml.etree.ElementTree as ET
import hashlib,os
badging=Path('dist/apk-badging.txt').read_text()
permissions=Path('dist/apk-permissions.txt').read_text()
if "package: name='org.quickvault.app'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit('Unexpected package or minimum SDK')
for line in permissions.splitlines():
    if line.startswith('uses-permission:') and not any(allowed in line for allowed in (
        "name='org.quickvault.app.DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION'",
        "name='android.permission.USE_BIOMETRIC'",
        "name='android.permission.INTERNET'",  # Dioxus loopback UI transport
    )):
        raise SystemExit('Unexpected requested permission; inspect before installing')
manifest=ET.parse('android/AndroidManifest.xml')
ns='{http://schemas.android.com/apk/res/android}'
app=manifest.find('application')
if app is None or app.get(ns+'allowBackup')!='false':
    raise SystemExit('Backup policy is not disabled')
p=Path(os.environ['QV_APP_BUILT_APK'])
print('APK SHA-256:',hashlib.sha256(p.read_bytes()).hexdigest())
print('Built only. Inspect the final manifest/signature before any device install.')
PY
