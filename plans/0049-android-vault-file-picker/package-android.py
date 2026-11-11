#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build an isolated regular-UI import qualification package; never install it."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

repo = Path(__file__).resolve().parents[2]
app = repo / "crates/qv-app"
baseline = app / "dist/quickvault-debug.apk"
if not baseline.is_file():
    raise SystemExit("Build the ordinary Android APK first (no validation features)")
work = Path(tempfile.mkdtemp(prefix="qv-0049-android-", dir="/var/tmp"))
project = work / "project"
shutil.copytree(app / "dist/android-project", project,
                ignore=shutil.ignore_patterns("build", ".gradle"))
build = project / "app/build.gradle.kts"
source = build.read_text()
old = 'applicationId = "org.quickvault.app"'
if source.count(old) != 1:
    raise SystemExit("Unexpected application ID template")
build.write_text(source.replace(old, 'applicationId = "org.quickvault.validation49"'))
for path in (project / "app/src/androidTest/java/org/quickvault/app").glob("*.java"):
    path.write_text(path.read_text().replace('"org.quickvault.app"', '"org.quickvault.validation49"'))
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
    raise SystemExit("Native libraries differ from the ordinary APK")
aapt = str(Path(env["ANDROID_HOME"]) / "build-tools/35.0.0/aapt")
badging = subprocess.check_output([aapt, "dump", "badging", str(apk)], text=True)
if "package: name='org.quickvault.validation49'" not in badging or "sdkVersion:'29'" not in badging:
    raise SystemExit("Unexpected app identity/API baseline")
manifest = subprocess.check_output([aapt, "dump", "xmltree", str(test_apk), "AndroidManifest.xml"], text=True)
if 'package="org.quickvault.validation49.test"' not in manifest or 'android:targetPackage(0x01010021)="org.quickvault.validation49"' not in manifest:
    raise SystemExit("Unexpected instrumentation identity/target")
if 'org.quickvault.validation49.test.vault-import' not in manifest:
    raise SystemExit("Unexpected fixture-provider authority")
main_manifest = subprocess.check_output([aapt, "dump", "xmltree", str(apk), "AndroidManifest.xml"], text=True)
if "VaultImportProvider" in main_manifest:
    raise SystemExit("Test provider leaked into the product APK")
(work / "app-badging.txt").write_text(badging)
(work / "test-manifest.txt").write_text(manifest)
for built, name in [(apk, "quickvault-import49-debug.apk"), (test_apk, "quickvault-import49-tests.apk")]:
    destination = app / "dist" / name
    shutil.copyfile(built, destination)
    with destination.open("rb") as data:
        print(hashlib.file_digest(data, "sha256").hexdigest(), destination, flush=True)
print("Native bytes match the ordinary app; no install performed.", work, flush=True)
