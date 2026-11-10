#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Repackage the freshly built media validation APK under a disposable UID.

Build only. Never installs or touches a connected phone or personal vault.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

repo = Path(__file__).resolve().parents[2]
app = repo / "crates/qv-app"
baseline = app / "dist/quickvault-validation-debug.apk"
if not baseline.is_file():
    raise SystemExit("First build with QV_APP_DEVICE_VALIDATION=1 QV_APP_MEDIA_VALIDATION=1")
work = Path(tempfile.mkdtemp(prefix="qv-0050-android-", dir="/var/tmp"))
project = work / "project"
shutil.copytree(app / "dist/android-project", project,
                ignore=shutil.ignore_patterns("build", ".gradle"))
build = project / "app/build.gradle.kts"
text = build.read_text()
old = 'applicationId = "org.quickvault.app"'
if text.count(old) != 1:
    raise SystemExit("Unexpected application ID template")
build.write_text(text.replace(old, 'applicationId = "org.quickvault.validation50"'))
tests = project / "app/src/androidTest/java/org/quickvault/app"
for path in tests.glob("*.java"):
    path.write_text(path.read_text().replace('"org.quickvault.app"', '"org.quickvault.validation50"'))
env = dict(os.environ, GRADLE_USER_HOME=str(app / "dist/.build-cache/gradle"),
           ANDROID_USER_HOME=str(app / "dist/.build-cache/android-user"))
with (work / "build.log").open("w") as log:
    result = subprocess.run(["sh", str(project / "gradlew"), "-p", str(project),
                             ":app:assembleDebug", ":app:assembleDebugAndroidTest", "--no-daemon"],
                            cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT)
if result.returncode:
    raise SystemExit(f"Build failed: {work / 'build.log'}")
apk = project / "app/build/outputs/apk/debug/app-debug.apk"
test_apk = project / "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"


def native_hashes(path):
    with zipfile.ZipFile(path) as archive:
        return {name: hashlib.sha256(archive.read(name)).hexdigest()
                for name in archive.namelist() if name.startswith("lib/") and name.endswith(".so")}


native = native_hashes(apk)
if not native or native != native_hashes(baseline):
    raise SystemExit("Native library differs from the selected baseline APK")
aapt = str(Path(env["ANDROID_HOME"]) / "build-tools/35.0.0/aapt")
badging = subprocess.check_output([aapt, "dump", "badging", str(apk)], text=True)
if "package: name='org.quickvault.validation50'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit("Unexpected package identity/baseline")
test_manifest = subprocess.check_output([aapt, "dump", "xmltree", str(test_apk), "AndroidManifest.xml"], text=True)
if 'package="org.quickvault.validation50.test"' not in test_manifest or 'android:targetPackage(0x01010021)="org.quickvault.validation50"' not in test_manifest:
    raise SystemExit("Unexpected instrumentation package/target")
(work / "apk-badging.txt").write_text(badging)
for path in [apk, test_apk]:
    with path.open("rb") as data:
        print(hashlib.file_digest(data, "sha256").hexdigest(), path, flush=True)
print("Native bytes match media validation baseline; no install performed.", flush=True)
