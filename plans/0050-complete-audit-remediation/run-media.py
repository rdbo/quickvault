# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run only synthetic native media fixtures on a private X server."""
import argparse
import os
from pathlib import Path
import select
import signal
import subprocess
import tempfile
import time


def rss_tree(pid, seen=None):
    seen = set() if seen is None else seen
    if pid in seen or len(seen) >= 128:
        return []
    seen.add(pid)
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        rss = int(next(row.split()[1] for row in status.splitlines() if row.startswith("VmRSS:")))
        children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
    except (FileNotFoundError, ProcessLookupError, StopIteration, PermissionError):
        return []
    return [(pid, rss)] + [row for child in children for row in rss_tree(int(child), seen)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--private-runtime", action="store_true",
                        help="provide a private D-Bus/PipeWire session and null audio sink")
    args = parser.parse_args()
    args.output.mkdir(mode=0o700, parents=True, exist_ok=True)
    binary = args.binary.resolve()
    xvfb = os.environ.get("QV_TEST_XVFB", "Xvfb")
    app = None
    services = []
    with tempfile.TemporaryDirectory(prefix="qv-0050-media-") as working:
        with (args.output / "xvfb.log").open("w") as xlog, (args.output / "native.log").open("w") as log:
            display_server = subprocess.Popen(
                [xvfb, "-displayfd", "1", "-screen", "0", "1280x1000x24", "-nolisten", "tcp", "-ac"],
                stdout=subprocess.PIPE, stderr=xlog,
            )
            try:
                if not select.select([display_server.stdout], [], [], 5)[0]:
                    raise RuntimeError("private display startup deadline")
                number = display_server.stdout.readline().decode().strip()
                if not number.isdecimal():
                    raise RuntimeError("private display startup failed; inspect xvfb.log")
                env = dict(os.environ, DISPLAY=":" + number,
                           WEBKIT_DISABLE_COMPOSITING_MODE="1", QV_TEST_MEDIA_FLOW="1")
                if args.private_runtime:
                    for name, variable in [("runtime", "XDG_RUNTIME_DIR"),
                                           ("state", "XDG_STATE_HOME"),
                                           ("cache", "XDG_CACHE_HOME"),
                                           ("config", "XDG_CONFIG_HOME")]:
                        path = Path(working) / name
                        path.mkdir(mode=0o700)
                        env[variable] = str(path)
                    address = Path(working) / "bus-address"
                    with address.open("w") as fd, (args.output / "services.log").open("w") as service_log:
                        services.append(subprocess.Popen(
                            ["dbus-daemon", "--session", "--nofork", f"--print-address={fd.fileno()}"],
                            pass_fds=(fd.fileno(),), env=env, stdout=service_log,
                            stderr=service_log, start_new_session=True))
                        end = time.monotonic() + 5
                        while address.stat().st_size == 0 and time.monotonic() < end:
                            time.sleep(0.05)
                        if not 0 < address.stat().st_size < 4096:
                            raise RuntimeError("private session startup deadline")
                        env["DBUS_SESSION_BUS_ADDRESS"] = address.read_text().strip()
                        env["PULSE_SERVER"] = "unix:" + env["XDG_RUNTIME_DIR"] + "/pulse/native"
                        env["PULSE_SINK"] = "qv_synthetic"
                        for command in ["pipewire", "pipewire-pulse", "wireplumber"]:
                            services.append(subprocess.Popen(
                                [command], env=env, stdout=service_log, stderr=service_log,
                                start_new_session=True))
                        end, ready = time.monotonic() + 10, False
                        while not ready and time.monotonic() < end:
                            ready = subprocess.run(["pactl", "info"], env=env,
                                                   stdout=subprocess.DEVNULL,
                                                   stderr=subprocess.DEVNULL, timeout=2).returncode == 0
                            if not ready:
                                time.sleep(0.1)
                        if not ready:
                            raise RuntimeError("private audio startup deadline")
                        subprocess.run(["pactl", "load-module", "module-null-sink",
                                        "sink_name=qv_synthetic",
                                        "sink_properties=device.description=QuickVaultSynthetic"],
                                       env=env, stdout=service_log, stderr=service_log,
                                       check=True, timeout=5)
                app = subprocess.Popen([str(binary)], cwd=working, env=env,
                                       stdout=log, stderr=log, start_new_session=True)
                start, peak = time.monotonic(), 0
                with (args.output / "rss.log").open("w") as stats:
                    while app.poll() is None and time.monotonic() - start < 180:
                        rows = rss_tree(app.pid)
                        total = sum(rss for _, rss in rows)
                        peak = max(peak, total)
                        stats.write(f"{time.monotonic()-start:.1f}s total_kib={total} processes={rows}\n")
                        stats.flush()
                        time.sleep(0.5)
                if app.poll() is None:
                    os.killpg(app.pid, signal.SIGTERM)
                    app.wait(timeout=5)
                    code = 124
                else:
                    code = app.returncode
                print(f"native media exit={code}; peak summed process RSS={peak} KiB", flush=True)
                return code
            finally:
                if app:
                    try:
                        os.killpg(app.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                for service in reversed(services):
                    try:
                        os.killpg(service.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        service.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(service.pid, signal.SIGKILL)
                        service.wait()
                display_server.terminate()
                try:
                    display_server.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    display_server.kill()
                    display_server.wait()


if __name__ == "__main__":
    raise SystemExit(main())
