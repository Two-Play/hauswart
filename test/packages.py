#!/usr/bin/env python3
"""Installs the built packages on fresh systems with a real systemd.

Run "make packages" first. Everything happens inside throwaway containers.
Usage: test/packages.py [rpm deb tarball]
"""
import json
import os
import shlex
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION = os.environ.get("VERSION", "0.1.0")
URL = "https://localhost:8443"
SUFFIX = os.environ.get("E2E_SUFFIX", "")  # to run next to another test run
CA = "/var/lib/hauswart-server/pki/ca.pem"

FEDORA = """FROM registry.fedoraproject.org/fedora:44
RUN dnf5 install -y systemd curl && dnf5 clean all
"""
DEBIAN = """FROM docker.io/library/debian:stable
RUN apt-get update && apt-get install -y systemd systemd-sysv curl ca-certificates
"""

TARGETS = {
    "rpm": (FEDORA, f"dnf5 install -y /pkgs/hauswart-server-{VERSION}-1.x86_64.rpm /pkgs/hauswart-agent-{VERSION}-1.x86_64.rpm "
                    f"/pkgs/hauswart-tray-{VERSION}-1.x86_64.rpm /pkgs/hauswart-admin-gui-{VERSION}-1.x86_64.rpm",
            "dnf5 remove -y hauswart-agent"),
    "deb": (DEBIAN, f"apt-get install -y /pkgs/hauswart-server_{VERSION}_amd64.deb /pkgs/hauswart-agent_{VERSION}_amd64.deb "
                    f"/pkgs/hauswart-tray_{VERSION}_amd64.deb /pkgs/hauswart-admin-gui_{VERSION}_amd64.deb",
            "apt-get remove -y hauswart-agent"),
    "tarball": (DEBIAN, f"cd /tmp && tar xzf /pkgs/hauswart-{VERSION}-linux-amd64.tar.gz && hauswart-{VERSION}/install.sh server && hauswart-{VERSION}/install.sh agent",
                None),
}

results = []


def check(target, name, ok, detail=""):
    results.append((target, name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail[-500:]}" if detail and not ok else ""), flush=True)


def run(*argv, input=None, timeout=600):
    return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)


def test(target):
    containerfile, install, remove = TARGETS[target]
    print(f"\n== {target}", flush=True)
    image = f"localhost/hauswart-pkg-{target}{SUFFIX}"
    built = run("podman", "build", "-q", "-t", image, "-", input=containerfile)
    if built.returncode != 0:
        check(target, "image builds", False, built.stderr)
        return
    container = f"hauswart-pkg-{target}{SUFFIX}"
    run("podman", "rm", "-f", container)
    # systemd needs these to set up the service sandbox. Rootless, they stay
    # inside the container's user namespace.
    started = run("podman", "run", "-d", "--name", container, "--systemd=always", "--cap-add=SYS_ADMIN",
                  "--security-opt", "unmask=ALL", "--security-opt", "label=disable",
                  "-v", f"{ROOT}/dist:/pkgs:ro,Z", image, "/sbin/init")
    if started.returncode != 0:
        check(target, "container starts", False, started.stderr)
        return

    def inside(cmd, timeout=300):
        return run("podman", "exec", container, "sh", "-c", cmd, timeout=timeout)

    def call(method, path, body=None):
        cmd = f"curl -s --cacert {CA} -b /tmp/jar -c /tmp/jar -H 'X-Hauswart: 1' -X {method} {URL}{path}"
        if body is not None:
            cmd += " -H 'Content-Type: application/json' -d " + shlex.quote(json.dumps(body))
        out = inside(cmd).stdout
        return json.loads(out) if out else None

    try:
        inside("systemctl is-system-running --wait")
        if target != "rpm":
            inside("apt-get update")

        done = inside(install)
        check(target, "installs", done.returncode == 0, done.stdout + done.stderr)
        check(target, "no service started by the package", inside("systemctl is-active hauswart-server").returncode != 0)

        check(target, "default config in place", inside("test -f /etc/hauswart/server.env").returncode == 0)
        notify = inside("stat -c '%a %U' /etc/hauswart/notify.env").stdout.strip()
        check(target, "notification credentials are private", notify == "600 hauswart", notify)

        enabled = inside("systemctl enable --now hauswart-server")
        check(target, "server enables", enabled.returncode == 0, enabled.stderr)
        for _ in range(30):
            if inside(f"curl -s -o /dev/null --cacert {CA} {URL}/healthz").returncode == 0:
                break
            time.sleep(1)
        check(target, "server is active", inside("systemctl is-active hauswart-server").returncode == 0,
              inside("journalctl -u hauswart-server --no-pager | tail -15").stdout)

        # 0100007F:20FB is 127.0.0.1:8443 in /proc/net/tcp, state 0A is listening.
        listeners = inside("awk '$4 == \"0A\" && $2 ~ /:20FB$/ {print $2}' /proc/net/tcp /proc/net/tcp6").stdout.split()
        check(target, "default config listens on loopback only", listeners == ["0100007F:20FB"], str(listeners))

        owner = inside("stat -c %U /proc/$(systemctl show -p MainPID --value hauswart-server)").stdout.strip()
        check(target, "server does not run as root", owner not in ("", "root"), owner)

        password = inside("cat /var/lib/hauswart-server/initial-admin-password").stdout.strip()
        check(target, "initial password file exists", len(password) == 24)
        mode = inside("stat -c %a /var/lib/hauswart-server/initial-admin-password").stdout.strip()
        check(target, "initial password file is private", mode == "600", mode)
        journal = inside("journalctl -u hauswart-server --no-pager").stdout
        check(target, "notification file is accepted", "admin notifications are off" not in journal, journal[-400:])
        check(target, "password stays out of the journal", password and password not in journal)

        user = call("POST", "/api/login", {"username": "admin", "password": password})
        check(target, "login", user and user.get("role") == "admin", str(user))
        command = call("POST", "/api/enroll-tokens")["command"].replace("sudo ", "", 1)
        enrolled = inside(command)
        check(target, "agent enrolls", enrolled.returncode == 0, enrolled.stderr)
        trusted = inside(f"curl -s -o /dev/null {URL}/healthz")
        check(target, "enrollment adds the CA to the system store", trusted.returncode == 0, str(trusted.returncode))
        if target != "rpm":
            policies = inside("test -s /etc/firefox/policies/policies.json && test -s /etc/chromium/policies/managed/hauswart-server.json")
            check(target, "browser policies written", policies.returncode == 0)
        enabled = inside("systemctl enable --now hauswart-agent")
        check(target, "agent enables", enabled.returncode == 0, enabled.stderr)

        device = None
        for _ in range(20):
            devices = call("GET", "/api/devices")
            device = next((d for d in devices if d["report"].get("distro")), None)
            if device:
                break
            time.sleep(1)
        check(target, "agent reports", device, inside("journalctl -u hauswart-agent --no-pager | tail -15").stdout)
        if not device:
            return

        created = call("POST", f"/api/devices/{device['id']}/tasks", {"type": "pkg.install", "payload": {"packages": ["tree"]}})
        status = None
        for _ in range(120):
            tasks = call("GET", "/api/tasks")
            status = next(t for t in tasks if t["id"] == created["id"])["status"]
            if status in ("done", "failed"):
                break
            time.sleep(1)
        check(target, "task runs through the service", status == "done" and inside("command -v tree").returncode == 0, str(status))

        restarted = inside("systemctl restart hauswart-server")
        time.sleep(2)
        check(target, "server survives a restart", restarted.returncode == 0 and inside("systemctl is-active hauswart-server").returncode == 0)

        # Disaster recovery: lose everything except the backup.
        made = inside("hauswart-server backup -out /root/backup.tar.gz")
        check(target, "backup while the server runs", made.returncode == 0, made.stderr)
        mode = inside("stat -c %a /root/backup.tar.gz").stdout.strip()
        check(target, "backup is private", mode == "600", mode)
        inside("systemctl stop hauswart-server hauswart-agent && rm -rf /var/lib/hauswart-server/*")
        check(target, "data is gone", inside("test -e /var/lib/hauswart-server/hauswart.db").returncode != 0)
        restored = inside("hauswart-server restore -in /root/backup.tar.gz && chown -R hauswart:hauswart /var/lib/hauswart-server/")
        check(target, "restore", restored.returncode == 0, restored.stderr)
        inside("systemctl start hauswart-server hauswart-agent")
        for _ in range(30):
            if inside(f"curl -s -o /dev/null --cacert {CA} {URL}/healthz").returncode == 0:
                break
            time.sleep(1)
        user = call("POST", "/api/login", {"username": "admin", "password": password})
        check(target, "login after restore", user and user.get("role") == "admin", str(user))
        created = call("POST", f"/api/devices/{device['id']}/tasks", {"type": "pkg.remove", "payload": {"packages": ["tree"]}})
        status = None
        for _ in range(60):
            tasks = call("GET", "/api/tasks")
            status = next(t for t in tasks if t["id"] == created["id"])["status"]
            if status in ("done", "failed"):
                break
            time.sleep(1)
        check(target, "enrolled device keeps working after restore", status == "done", str(status))

        if remove:
            removed = inside(remove)
            check(target, "removes cleanly", removed.returncode == 0, removed.stderr)
            check(target, "removal stops the agent", inside("systemctl is-active hauswart-agent").returncode != 0)
    except Exception as err:  # keep testing the other targets
        check(target, "no crash", False, repr(err))
    finally:
        run("podman", "rm", "-f", container)


def main():
    for target in sys.argv[1:] or list(TARGETS):
        test(target)
    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    for target, name, _ in failed:
        print(f"  FAILED {target}: {name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
