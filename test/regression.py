#!/usr/bin/env python3
"""Runs the test suites side by side and prints how long each one took.

    test/regression.py            everything
    test/regression.py --fast     everything except the virtual machines
    test/regression.py unit e2e-debian
    test/regression.py --list     the suites as JSON, which is what the CI runs
    test/regression.py --no-prep  skip the build, for a checkout that has it

A suite that fails or hangs only ends itself. Logs go to REGRESSION_LOGS, by
default ~/.cache/hauswart-regression. Everything is built first, because a build
during the tests would pull the dashboard away from under them.
"""
import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, f"{ROOT}/test")

import e2e  # noqa: E402
import vm  # noqa: E402

VERSION = os.environ.get("VERSION", "0.1.0")
LOGS = os.environ.get("REGRESSION_LOGS", os.path.expanduser("~/.cache/hauswart-regression"))
TMP = os.environ.get("E2E_TMP", f"{LOGS}/tmp")  # /tmp is often too small for disk images
MAX_VMS = int(os.environ.get("REGRESSION_VMS", "4"))
MAX_CONTAINERS = int(os.environ.get("REGRESSION_CONTAINERS", "6"))
TIMEOUT = 3600  # the slowest suite took about 30 minutes

FIRST_PORT = 18500  # the test defaults and the fixed ports of notify are below
SSH_STEP = 20  # wider than the range of SSH ports in test/vm.py


class Suite:
    def __init__(self, name, command, pool, shared=False, cwd=ROOT):
        self.name, self.command, self.pool, self.shared, self.cwd = name, command, pool, shared, cwd
        self.status, self.seconds, self.summary = "not run", 0.0, ""


def suites(fast):
    found = [
        Suite("unit", ["make", "test"], "work"),
        Suite("gui", ["make", "test-gui"], "work"),
        Suite("types", ["npx", "tsc", "--noEmit", "-p", "."], "work", cwd=f"{ROOT}/web"),
        Suite("passkeys", ["node", "test/passkeys.mjs"], "work"),
        Suite("packages", ["python3", "test/packages.py"], "containers"),
        Suite("authentik", ["python3", "test/authentik.py"], "containers", shared=True),
    ]
    for distro in e2e.DISTROS:
        found.append(Suite(f"e2e-{distro}", ["python3", "test/e2e.py", distro, f"journal-{distro}", f"policy-{distro}"], "containers"))
    for name in ("systemd", "signing", "socket", "renewal", "notify"):
        found.append(Suite(f"e2e-{name}", ["python3", "test/e2e.py", name], "containers"))
    if not fast:
        # Directory tests use the fixed ports and names of Authentik.
        for name in vm.TESTS:
            found.append(Suite(f"vm-{name}", ["python3", "test/vm.py", name], "vms", shared=name.startswith("directory")))
    return found


def environment(index):
    return {
        **os.environ, "VERSION": VERSION, "E2E_TMP": TMP,
        "E2E_PORT": str(FIRST_PORT + index), "VM_PORT": str(FIRST_PORT + index),
        "E2E_PREFIX": f"hauswart-r{index}", "E2E_SUFFIX": f"-r{index}",
        "VM_SSH_OFFSET": str(index * SSH_STEP),
    }


running, running_lock = set(), threading.Lock()


def stop(process):
    """Ends the suite with everything it started, such as its virtual machine."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(20)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run(suite, index):
    started = time.monotonic()
    path = f"{LOGS}/{suite.name}.log"
    with open(path, "w") as log:
        process = subprocess.Popen(suite.command, cwd=suite.cwd, env=environment(index), stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True)
        with running_lock:
            running.add(process)
        try:
            process.wait(TIMEOUT)
            suite.status = "ok" if process.returncode == 0 else "FAILED"
        except subprocess.TimeoutExpired:
            stop(process)
            suite.status = "TIMEOUT"
        with running_lock:
            running.discard(process)
    suite.seconds = time.monotonic() - started
    with open(path, errors="replace") as log:
        lines = [line.strip() for line in log if "checks passed" in line]
    suite.summary = lines[-1] if lines else ""
    print(f"{suite.status:8}{suite.seconds / 60:6.1f} min  {suite.name}  {suite.summary}", flush=True)


def run_all(chosen):
    pools = {"work": threading.Semaphore(4), "containers": threading.Semaphore(MAX_CONTAINERS),
             "vms": threading.Semaphore(MAX_VMS)}
    shared = threading.Lock()

    def worker(suite, index):
        # The lock comes first, so that a waiting suite holds no place in a pool.
        if suite.shared:
            shared.acquire()
        try:
            with pools[suite.pool]:
                run(suite, index)
        except Exception as error:  # noqa: BLE001 - one suite must not end the others
            suite.status, suite.summary = "FAILED", str(error)
            print(f"FAILED  {suite.name}: {error}", flush=True)
        finally:
            if suite.shared:
                shared.release()

    threads = [threading.Thread(target=worker, args=(suite, index), daemon=True) for index, suite in enumerate(chosen)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def prepare(chosen):
    if any(s.name in ("packages", "passkeys", "vm-desktop") or s.name.startswith("vm-gui") for s in chosen):
        print("building everything", flush=True)
        with open(f"{LOGS}/build.log", "w") as log:
            if subprocess.run(["make", "packages", f"VERSION={VERSION}"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode:
                sys.exit(f"the build failed, see {LOGS}/build.log")
    if any(s.pool == "vms" for s in chosen):
        print("fetching images", flush=True)
        with open(f"{LOGS}/images.log", "w") as log:
            if subprocess.run(["python3", "test/vm.py", "images"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode:
                sys.exit(f"fetching images failed, see {LOGS}/images.log")


def main():
    parser = argparse.ArgumentParser(description="Runs the test suites side by side.")
    parser.add_argument("--fast", action="store_true", help="leave out the virtual machines")
    parser.add_argument("--list", action="store_true", help="print the suites as JSON")
    parser.add_argument("--no-prep", action="store_true", help="skip the build and the images")
    parser.add_argument("names", nargs="*")
    args = parser.parse_args()

    available = suites(args.fast and not args.names)
    if args.list:
        print(json.dumps([s.name for s in available]))
        return
    unknown = set(args.names) - {s.name for s in available}
    if unknown:
        sys.exit(f"unknown suites: {', '.join(sorted(unknown))}")
    chosen = [s for s in available if not args.names or s.name in args.names]

    os.makedirs(TMP, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)

    def interrupted(*_):
        with running_lock:
            for process in running:
                stop(process)
        sys.exit("interrupted")

    signal.signal(signal.SIGINT, interrupted)
    signal.signal(signal.SIGTERM, interrupted)

    started = time.monotonic()
    if not args.no_prep:
        prepare(chosen)
    run_all(chosen)

    print(f"\n{'suite':24}{'result':10}{'minutes':>8}")
    for suite in sorted(chosen, key=lambda s: -s.seconds):
        print(f"{suite.name:24}{suite.status:10}{suite.seconds / 60:8.1f}  {suite.summary}")
    bad = [s.name for s in chosen if s.status != "ok"]
    print(f"\n{len(chosen) - len(bad)}/{len(chosen)} suites passed in {(time.monotonic() - started) / 60:.1f} minutes, logs in {LOGS}")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
