#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Install the built debug packages without clearing data, then test fresh
# synthetic vaults. Use the host's working ADB server; never replace it here.
set -eu
app_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
export QV_ANDROID_APP_DIR="$app_dir"
python3 - <<'PY'
import os
import hashlib
import shlex
from pathlib import Path
import subprocess
import sys
import tempfile
import time

adb = os.environ.get('QV_ADB', 'adb')
app = Path(os.environ['QV_ANDROID_APP_DIR'])
logs = Path(tempfile.mkdtemp(prefix='qv-android-tests-'))
print('Synthetic device test logs:', logs, flush=True)
devices = subprocess.check_output([adb, 'devices'], text=True, timeout=10)
rows = [row.split() for row in devices.splitlines()[1:] if row.strip()]
if len(rows) != 1 or rows[0][1] != 'device':
    sys.exit('Exactly one authorized test device is required.')
variant = 'quickvault-validation' if os.environ.get('QV_APP_DEVICE_VALIDATION') == '1' else 'quickvault'
for name, package in [(variant + '-debug.apk', 'org.quickvault.app'),
                      (variant + '-tests.apk', 'org.quickvault.app.test')]:
    apk = app / 'dist' / name
    if not apk.is_file():
        sys.exit('Build the app and instrumentation APKs first.')
    # Avoid needless reinstalls and OEM install prompts when bytes match.
    local_hash = hashlib.file_digest(apk.open('rb'), 'sha256').hexdigest()
    location = subprocess.check_output([adb, 'shell', 'pm path ' + shlex.quote(package)],
                                       text=True, timeout=10).strip()
    if location.startswith('package:') and '\n' not in location:
        installed = subprocess.check_output([
            adb, 'shell', 'sha256sum ' + shlex.quote(location[len('package:'):]),
        ], text=True, timeout=10).split()
        if installed and installed[0] == local_hash:
            print('Already installed with matching SHA-256:', name, flush=True)
            continue
    with (logs / (name + '.install.log')).open('w') as output:
        subprocess.run([adb, 'install', '-r', str(apk)], stdout=output,
                       stderr=subprocess.STDOUT, timeout=90, check=True)
test_class = os.environ.get('QV_ANDROID_TEST_CLASS', 'org.quickvault.app.PlatformTest')
if test_class not in ('org.quickvault.app.PlatformTest', 'org.quickvault.app.QrTest'):
    sys.exit('Unsupported explicit instrumentation class.')
test_args = []
for option, argument in [('QV_ANDROID_QR_CAMERA', 'qv_camera'), ('QV_ANDROID_QR_OPTICS', 'qv_optics')]:
    if os.environ.get(option) != '1':
        continue
    if test_class != 'org.quickvault.app.QrTest' or os.environ.get('QV_APP_DEVICE_VALIDATION') != '1':
        sys.exit('Live camera checks require explicit QrTest and validation packaging.')
    test_args.extend(['-e', argument, 'true'])
log = logs / 'instrumentation.log'
with log.open('w') as output:
    runner = subprocess.Popen([
        adb, 'shell', 'am', 'instrument', '-w', '-e', 'class',
        test_class, *test_args,
        'org.quickvault.app.test/android.test.InstrumentationTestRunner',
    ], stdout=output, stderr=subprocess.STDOUT)
    try:
        # Select the exact test class to avoid slow whole-package discovery.
        # Explicit foreground launch handles OEM background-launch restrictions.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and runner.poll() is None:
            if test_class.rsplit('.', 1)[-1] + ':' in log.read_text():
                break
            time.sleep(.1)
        if runner.poll() is None:
            with (logs / 'launch.log').open('w') as launch:
                subprocess.run([
                    adb, 'shell', 'am', 'start', '-W', '-n',
                    'org.quickvault.app/dev.dioxus.main.MainActivity',
                ], stdout=launch, stderr=subprocess.STDOUT, timeout=15, check=True)
        runner.wait(timeout=210)
    except BaseException:
        runner.terminate()
        runner.wait()
        raise
result = log.read_text()
print(result[-5000:])
# adb can return success even when instrumentation fails; inspect test status.
sys.exit(0 if runner.returncode == 0 and 'OK (1 test)' in result else 1)
PY
