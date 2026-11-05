#!/usr/bin/env python3
"""End-to-end test: real server on the host, real agents as root in containers.

Everything privileged happens inside throwaway containers; the host is never
touched. Usage: test/e2e.py [fedora debian arch opensuse systemd]
"""
import http.cookiejar
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

PORT = 18443
URL = f"https://localhost:{PORT}"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DISTROS = {
    "fedora": ("registry.fedoraproject.org/fedora:44", "dnf5 install -y sudo shadow-utils ca-certificates", "tree"),
    "debian": ("docker.io/library/debian:stable", "apt-get update && apt-get install -y sudo ca-certificates", "tree"),
    "arch": ("docker.io/library/archlinux:latest", "pacman -Sy --noconfirm sudo ca-certificates", "tree"),
    "opensuse": ("registry.opensuse.org/opensuse/tumbleweed:latest", "zypper --non-interactive install sudo shadow ca-certificates", "tree"),
}


class Client:
    def __init__(self, ca_file):
        ctx = ssl.create_default_context(cafile=ca_file)
        jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=ctx),
            urllib.request.HTTPCookieProcessor(jar),
        )

    def call(self, method, path, body=None):
        req = urllib.request.Request(
            URL + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json", "X-Hauswart": "1"},
        )
        try:
            with self.opener.open(req, timeout=40) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as err:
            raw = err.read()
            return err.code, json.loads(raw) if raw else None


results = []


def check(distro, name, ok, detail=""):
    results.append((distro, name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {detail[-400:]}" if detail and not ok else ""), flush=True)


def sh(*argv, check_rc=True, timeout=600):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check_rc and proc.returncode != 0:
        raise RuntimeError(f"{argv}: {proc.stdout}{proc.stderr}")
    return proc


def run_task(admin, device, task_type, payload, wait=300):
    """Creates a task and waits for its final state."""
    code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": task_type, "payload": payload})
    if code != 201:
        return {"status": "rejected", "output": str(out)}
    return wait_task(admin, out["id"], wait)


def wait_task(admin, task_id, wait=300):
    deadline = time.time() + wait
    while time.time() < deadline:
        _, tasks = admin.call("GET", "/api/tasks")
        task = next(t for t in tasks if t["id"] == task_id)
        if task["status"] in ("done", "failed"):
            return task
        time.sleep(1)
    return {"status": "timeout", "output": ""}


def test_distro(name, admin, agent_bin, ca_pem):
    image, setup, package = DISTROS[name]
    print(f"\n== {name} ({image})", flush=True)
    container = f"hauswart-e2e-{name}"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", image, "sleep", "1800", timeout=600)

    def inside(cmd, check_rc=False, timeout=600):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=check_rc, timeout=timeout)

    try:
        inside(setup, check_rc=True)

        _, enroll = admin.call("POST", "/api/enroll-tokens")
        command = enroll["command"].replace("sudo ", "", 1)
        check(name, "enrollment", inside(command).returncode == 0)

        bad = re.sub(r"--ca-fingerprint \w+", "--ca-fingerprint " + "0" * 64, command)
        check(name, "wrong CA fingerprint refused", inside(bad + " --dir /tmp/x").returncode != 0)
        check(name, "enroll token is single use", inside(command + " --dir /tmp/y").returncode != 0)

        sh("podman", "exec", "-d", container, "sh", "-c", "hauswart-agent run >/var/log/agent.log 2>&1")

        device = None
        deadline = time.time() + 20
        while time.time() < deadline and not device:
            _, devices = admin.call("GET", "/api/devices")
            hostname = inside("hostname || cat /etc/hostname").stdout.strip()
            live = [d for d in devices if not d["revoked"] and d["report"].get("distro") and d["id"] not in seen]
            if live:
                device = live[0]
            time.sleep(1)
        check(name, "report arrives", device, hostname)
        if not device:
            return
        seen.add(device["id"])
        report = device["report"]
        check(name, "report has metrics", report["mem_total"] > 0 and report["disk_total"] > 0 and report["cpus"] > 0)
        print(f"       distro={report['distro']!r} backends={report['backends']}", flush=True)
        id_ = device["id"]

        task = run_task(admin, id_, "pkg.install", {"packages": [package]})
        check(name, "pkg.install", task["status"] == "done", task["output"])
        check(name, "package really installed", inside(f"command -v {package}").returncode == 0)

        task = run_task(admin, id_, "pkg.remove", {"packages": [package]})
        check(name, "pkg.remove", task["status"] == "done", task["output"])
        check(name, "package really removed", inside(f"command -v {package}").returncode != 0)

        task = run_task(admin, id_, "pkg.upgrade", {}, wait=580)
        check(name, "pkg.upgrade", task["status"] == "done", task["output"])

        task = run_task(admin, id_, "user.create", {"user": "anna", "full_name": "Anna Test"})
        check(name, "user.create", task["status"] == "done", task["output"])
        check(name, "user exists", inside("id anna").returncode == 0)

        code, started = admin.call("POST", f"/api/devices/{id_}/start-password", {"user": "anna"})
        check(name, "start password created", code == 201, str(started))
        task = wait_task(admin, started["id"])
        check(name, "user.passwd", task["status"] == "done", task["output"])
        shadow = inside("getent shadow anna").stdout.strip().split(":")
        fields = shadow[1].split("$")
        expected = sh("openssl", "passwd", "-6", "-salt", fields[-2], started["password"]).stdout.strip()
        # openssl leaves out a rounds prefix, so compare salt and digest.
        check(name, "shadow hash matches the password", expected.split("$")[-1] == fields[-1])
        check(name, "password change forced at first login", shadow[2] == "0", shadow[2])

        task = run_task(admin, id_, "ca.install", {"name": "family", "pem": ca_pem})
        check(name, "ca.install", task["status"] == "done", task["output"])
        store = "/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ca-certificates/extracted/tls-ca-bundle.pem"
        body = "".join(ca_pem.strip().splitlines()[1:3])
        flat = f"for f in {store}; do [ -f $f ] && tr -d '\\n' < $f | grep -qF '{body}' && exit 0; done; exit 1"
        check(name, "CA in system trust bundle", inside(flat).returncode == 0)

        task = run_task(admin, id_, "file.put", {"path": "/etc/hauswart.d/app.conf", "content": "a=1\n", "mode": "0640"})
        check(name, "file.put allowed", task["status"] == "done", task["output"])
        check(name, "file content and mode", inside("[ \"$(stat -c %a /etc/hauswart.d/app.conf)\" = 640 ] && grep -q a=1 /etc/hauswart.d/app.conf").returncode == 0)
        task = run_task(admin, id_, "file.put", {"path": "/etc/sudoers.d/evil", "content": "anna ALL=(ALL) NOPASSWD: ALL\n"})
        check(name, "file.put to sudoers refused", task["status"] == "failed" and inside("test -e /etc/sudoers.d/evil").returncode != 0, task["output"])

        expires = (datetime.now(timezone.utc) + timedelta(seconds=20)).isoformat()
        task = run_task(admin, id_, "sudo.grant", {"user": "anna", "expires_at": expires})
        check(name, "sudo.grant", task["status"] == "done", task["output"])
        listing = inside("sudo -l -U anna").stdout
        check(name, "sudo really effective", "(ALL : ALL) ALL" in listing, listing)
        time.sleep(40)
        listing = inside("sudo -l -U anna").stdout
        check(name, "sudo expires by itself", "(ALL : ALL) ALL" not in listing and inside("test -e /etc/sudoers.d/hauswart-anna").returncode != 0, listing)

        task = run_task(admin, id_, "user.lock", {"user": "anna"})
        check(name, "user.lock", task["status"] == "done", task["output"])
        check(name, "account really locked", inside("passwd -S anna 2>/dev/null | grep -Eq ' (L|LK) |locked'; [ $? = 0 ] || grep -q '^anna:!' /etc/shadow").returncode == 0)
        task = run_task(admin, id_, "user.lock", {"user": "root"})
        check(name, "locking root refused", task["status"] == "rejected", task["output"])

        task = run_task(admin, id_, "limit.set", {"user": "anna", "cpu_percent": 150, "memory_mb": 2048})
        wrote = inside("grep -q 'CPUQuota=150%' /etc/systemd/system/user-*.slice.d/50-hauswart.conf").returncode == 0
        check(name, "limit.set writes the slice drop-in", wrote, task["output"])

        code, _ = admin.call("POST", f"/api/devices/{id_}/revoke")
        check(name, "revoke", code == 204)
        time.sleep(3)
        log = inside("sleep 30; tail -5 /var/log/agent.log").stdout
        check(name, "revoked agent is shut out", "status 403" in log, log)
    except Exception as err:  # keep testing the other distributions
        check(name, "no crash", False, str(err))
        print(inside("tail -20 /var/log/agent.log 2>/dev/null").stdout)
    finally:
        sh("podman", "rm", "-f", container, check_rc=False)


SYSTEMD_IMAGE = "localhost/hauswart-e2e-systemd"
SYSTEMD_CONTAINERFILE = """FROM registry.fedoraproject.org/fedora:44
RUN dnf5 install -y systemd sudo shadow-utils && dnf5 clean all
"""
MEMORY_HOG = "head -c 300M /dev/zero | tail >/dev/null"


def test_systemd(admin, agent_bin):
    """Proves that limit.set takes effect, which needs a real systemd."""
    name = "systemd"
    print(f"\n== {name} (Fedora with systemd as PID 1)", flush=True)
    subprocess.run(["podman", "build", "-q", "-t", SYSTEMD_IMAGE, "-"],
                   input=SYSTEMD_CONTAINERFILE, text=True, check=True, capture_output=True, timeout=600)
    container = "hauswart-e2e-systemd"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--systemd=always", "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", SYSTEMD_IMAGE, "/sbin/init")

    def inside(cmd, timeout=120):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=False, timeout=timeout)

    try:
        inside("systemctl is-system-running --wait")
        inside("useradd anna")
        uid = inside("id -u anna").stdout.strip()
        slice_ = f"user-{uid}.slice"
        # A process already running in the slice, as for someone who is logged
        # in: the limit has to reach a live cgroup, not only future ones.
        running = inside(f"systemd-run --quiet --unit=logged-in --slice={slice_} sleep 600")
        check(name, "user session running", running.returncode == 0, running.stderr)

        _, enroll = admin.call("POST", "/api/enroll-tokens")
        check(name, "enrollment", inside(enroll["command"].replace("sudo ", "", 1)).returncode == 0)
        sh("podman", "exec", "-d", container, "sh", "-c", "hauswart-agent run >/var/log/agent.log 2>&1")

        device = None
        deadline = time.time() + 20
        while time.time() < deadline and not device:
            _, devices = admin.call("GET", "/api/devices")
            live = [d for d in devices if not d["revoked"] and d["report"].get("distro") and d["id"] not in seen]
            device = live[0] if live else None
            time.sleep(1)
        check(name, "report arrives", device)
        if not device:
            return
        seen.add(device["id"])

        task = run_task(admin, device["id"], "limit.set", {"user": "anna", "cpu_percent": 150, "memory_mb": 64})
        check(name, "limit.set", task["status"] == "done", task["output"])

        shown = inside(f"systemctl show -p MemoryMax -p CPUQuotaPerSecUSec {slice_}").stdout
        check(name, "systemd reports the limits", "MemoryMax=67108864" in shown and "CPUQuotaPerSecUSec=1.5" in shown, shown)

        cgroup = f"/sys/fs/cgroup/user.slice/{slice_}"
        memory_max = inside(f"cat {cgroup}/memory.max").stdout.strip()
        cpu_max = inside(f"cat {cgroup}/cpu.max").stdout.strip()
        check(name, "cgroup carries the limits on a running slice",
              memory_max == "67108864" and cpu_max.startswith("150000 "), f"{memory_max} / {cpu_max}")

        run = "systemd-run --quiet --wait -p MemorySwapMax=0 --slice={} sh -c '" + MEMORY_HOG + "'"
        check(name, "control: process runs outside the limit", inside(run.format("system.slice")).returncode == 0)
        limited = inside(run.format(slice_))
        check(name, "process over the limit is killed", limited.returncode != 0, limited.stdout + limited.stderr)
    except Exception as err:
        check(name, "no crash", False, str(err))
        print(inside("tail -20 /var/log/agent.log 2>/dev/null").stdout)
    finally:
        sh("podman", "rm", "-f", container, check_rc=False)


RENEWAL_VALIDITY = 90


def test_renewal(admin, agent_bin):
    """Runs an agent past the expiry of its first certificate."""
    name = "renewal"
    print(f"\n== {name} (certificates valid for {RENEWAL_VALIDITY}s)", flush=True)
    container = "hauswart-e2e-renewal"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", DISTROS["fedora"][0], "sleep", "1200")

    def inside(cmd):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=False, timeout=120)

    def start_agent():
        sh("podman", "exec", "-d", container, "sh", "-c",
           "echo $$ >/run/agent.pid; exec hauswart-agent run >>/var/log/agent.log 2>&1")

    def enroll():
        _, token = admin.call("POST", "/api/enroll-tokens")
        return inside(token["command"].replace("sudo ", "", 1))

    def wait_device():
        deadline = time.time() + 20
        while time.time() < deadline:
            _, devices = admin.call("GET", "/api/devices")
            live = [d for d in devices if not d["revoked"] and d["report"].get("distro") and d["id"] not in seen]
            if live:
                seen.add(live[0]["id"])
                return live[0]["id"]
            time.sleep(1)
        return None

    def digest(path):
        return inside(f"sha256sum {path}").stdout.split()[0]

    cert, key = "/var/lib/hauswart/agent.pem", "/var/lib/hauswart/agent-key.pem"
    try:
        check(name, "enrollment", enroll().returncode == 0)
        start_agent()
        device = wait_device()
        check(name, "report arrives", device)
        first_cert, first_key = digest(cert), digest(key)

        time.sleep(RENEWAL_VALIDITY + 25)  # past the expiry of the first certificate
        check(name, "certificate was replaced", digest(cert) != first_cert)
        check(name, "private key stayed", digest(key) == first_key)
        log = inside("cat /var/log/agent.log").stdout
        check(name, "renewed without a restart", "certificate renewed" in log, log)
        path = {"path": "/etc/hauswart.d/after-expiry", "content": "x"}
        task = run_task(admin, device, "file.put", path, wait=30)
        check(name, "works after the first certificate expired", task["status"] == "done", task["output"])
        _, audit = admin.call("GET", "/api/audit")
        check(name, "renewal is in the audit log", any(e["action"] == "device.renewed" for e in audit))

        inside("kill $(cat /run/agent.pid)")
        start_agent()
        task = run_task(admin, device, "file.put", path, wait=30)
        check(name, "renewed certificate survives an agent restart", task["status"] == "done", task["output"])

        # Switched off for longer than the certificate lives.
        inside("kill $(cat /run/agent.pid); : >/var/log/agent.log")
        time.sleep(RENEWAL_VALIDITY + 10)
        start_agent()
        time.sleep(5)
        log = inside("cat /var/log/agent.log").stdout
        check(name, "expired device is refused, visibly", "poll failed" in log, log)
        inside("kill $(cat /run/agent.pid)")
        check(name, "enrolling again recovers the device", enroll().returncode == 0)
        start_agent()
        check(name, "recovered device reports", wait_device())
    except Exception as err:
        check(name, "no crash", False, str(err))
        print(inside("tail -20 /var/log/agent.log").stdout)
    finally:
        sh("podman", "rm", "-f", container, check_rc=False)


seen = set()


def main():
    # Short lifetimes apply to the whole server, so this runs on its own.
    names = sys.argv[1:] or [*DISTROS, "systemd"]
    extra_args = ["-device-cert-validity", f"{RENEWAL_VALIDITY}s"] if names == ["renewal"] else []
    work = tempfile.mkdtemp(prefix="hauswart-e2e-", dir=os.environ.get("E2E_TMP"))
    server_bin, agent_bin = f"{work}/server", f"{work}/agent"
    env = {**os.environ, "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-o", server_bin, "./cmd/hauswart-server"], cwd=ROOT, env=env, check=True)
    subprocess.run(["go", "build", "-o", agent_bin, "./cmd/hauswart-agent"], cwd=ROOT, env=env, check=True)

    log_path = f"{work}/server.log"
    with open(log_path, "w") as log:
        server = subprocess.Popen(
            [server_bin, "-addr", f"127.0.0.1:{PORT}", "-data", f"{work}/data", "-url", URL, *extra_args],
            stderr=log, stdout=log)
    try:
        password = None
        for _ in range(50):
            if "listening" in open(log_path).read():
                password = open(f"{work}/data/initial-admin-password").read().strip()
                break
            time.sleep(0.2)
        if not password:
            raise SystemExit("server did not start:\n" + open(log_path).read())

        ca_file = f"{work}/data/pki/ca.pem"
        admin = Client(ca_file)
        code, _ = admin.call("POST", "/api/login", {"username": "admin", "password": password})
        assert code == 200, code
        ca_pem = open(ca_file).read()
        for name in names:
            if name == "systemd":
                test_systemd(admin, agent_bin)
            elif name == "renewal":
                test_renewal(admin, agent_bin)
            else:
                test_distro(name, admin, agent_bin, ca_pem)
    finally:
        server.terminate()
        server.wait()
        shutil.rmtree(work, ignore_errors=True)

    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    for distro, name, _ in failed:
        print(f"  FAILED {distro}: {name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
