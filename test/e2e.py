#!/usr/bin/env python3
"""End-to-end test: real server on the host, real agents as root in containers.

Everything privileged happens inside throwaway containers; the host is never
touched. Usage: test/e2e.py [fedora debian arch opensuse systemd signing notify renewal
journal-fedora journal-debian journal-arch journal-opensuse]

E2E_PORT, E2E_PREFIX and E2E_SUFFIX keep parallel runs apart.
"""
import base64
import http.cookiejar
import json
import os
import re
import shutil
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

PORT = int(os.environ.get("E2E_PORT", "18443"))
PREFIX = os.environ.get("E2E_PREFIX", "hauswart-e2e")
SUFFIX = os.environ.get("E2E_SUFFIX", "")
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
    container = f"{PREFIX}-{name}"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", image, "sleep", "3000", timeout=600)

    def inside(cmd, check_rc=False, timeout=600):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=check_rc, timeout=timeout)

    try:
        inside(setup, check_rc=True)
        if PENDING_SETUP[name]:
            inside(PENDING_SETUP[name], check_rc=True)
        sync_before = inside(ARCH_SYNC_DB).stdout

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

        test_update_status(name, admin, id_, inside, sync_before)

        code, samples = admin.call("GET", f"/api/devices/{id_}/history")
        check(name, "resource history has the report", code == 200 and samples and samples[0]["mem_total"] > 0, str(samples))
        expires_in = datetime.fromisoformat(report["cert_expires"]) - datetime.now(timezone.utc)
        check(name, "certificate expiry is reported", expires_in > timedelta(days=700), str(expires_in))
        check(name, "a new certificate raises no warning", not any(w["code"] == "cert_expiring" for w in device.get("warnings", [])))

        task = run_task(admin, id_, "logs.fetch", {})
        data = task_data(admin, task)
        check(name, "logs.fetch without a journal", task["status"] == "done" and data.get("available") is False, str(task))

        task = run_task(admin, id_, "pkg.install", {"packages": [package]})
        check(name, "pkg.install", task["status"] == "done", task["output"])
        check(name, "package really installed", inside(f"command -v {package}").returncode == 0)
        def in_inventory():
            return package in inventory_names(admin, id_)
        check(name, "the inventory lists what the system has", wait_for(lambda: len(inventory_names(admin, id_)) > 20, 150), str(inventory_names(admin, id_))[:200])
        check(name, "a new package reaches the inventory", wait_for(in_inventory, 150), str(inventory_names(admin, id_))[:200])

        task = run_task(admin, id_, "pkg.remove", {"packages": [package]})
        check(name, "pkg.remove", task["status"] == "done", task["output"])
        check(name, "package really removed", inside(f"command -v {package}").returncode != 0)
        check(name, "and leaves the inventory", wait_for(lambda: not in_inventory(), 150), str(inventory_names(admin, id_))[:200])

        # A kernel directory that is not the running kernel's means a new kernel
        # was installed, which is what a reboot is for.
        inside("mkdir -p /usr/lib/modules/0.0.0-hauswart-test")
        task = run_task(admin, id_, "pkg.upgrade", {}, wait=580)
        check(name, "pkg.upgrade", task["status"] == "done", task["output"])
        updates = wait_report(admin, id_, lambda r: r.get("updates", {}).get("pending") == 0 and r["updates"]["reboot"] == "required", 240)
        check(name, "no updates pending after pkg.upgrade", updates, str(last_report(admin, id_).get("updates")))

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

        test_rights(name, admin, id_, inside)

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


def last_report(admin, device):
    _, devices = admin.call("GET", "/api/devices")
    return next((d["report"] for d in devices if d["id"] == device), {})


def wait_report(admin, device, condition, wait=150):
    """Agents report once a minute."""
    deadline = time.time() + wait
    while time.time() < deadline:
        report = last_report(admin, device)
        if condition(report):
            return report
        time.sleep(2)
    return None


def wait_for(condition, wait=150, step=3):
    deadline = time.time() + wait
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(step)
    return False


def inventory_names(admin, device):
    code, entry = admin.call("GET", f"/api/inventory/{device}")
    return [p["name"] for p in entry.get("packages", [])] if code == 200 else []


def task_data(admin, task):
    """The structured result, which task lists leave out for logs."""
    code, full = admin.call("GET", f"/api/tasks/{task['id']}/data") if "id" in task else (0, None)
    return full.get("data", {}) if code == 200 else {}


# Puts a real pending update in place where the image is up to date. An older
# version comes from the repositories on Fedora. On Debian, the package database
# is told so, which apt then fixes for real.
PENDING_SETUP = {
    "fedora": "dnf5 downgrade -y tzdata",
    "debian": "sed -i '/^Package: ca-certificates$/,/^$/ s/^Version: .*/Version: 20000101/' /var/lib/dpkg/status",
    "arch": "",
    "opensuse": "",
}
# What the package manager says itself, to compare with. Arch needs no number:
# checking must not touch the real sync databases, which ARCH_SYNC_DB shows.
PENDING_COUNT = {
    "fedora": "dnf5 repoquery --upgrades --quiet --qf '%{name}.%{arch}\\n' | sort -u | wc -l",
    "debian": "apt-get -s upgrade | grep -c '^Inst '",
    "arch": "",
    "opensuse": "zypper --non-interactive list-updates | grep -c '^v '",
}
ARCH_SYNC_DB = "ls -l --time-style=full-iso /var/lib/pacman/sync 2>/dev/null"


def test_update_status(name, admin, device, inside, sync_before):
    report = wait_report(admin, device, lambda r: r.get("updates", {}).get("checked_at"), 240)
    check(name, "update status arrives", report, str(last_report(admin, device).get("updates")))
    if not report:
        return
    updates = report["updates"]
    print(f"       updates={updates['pending']} reboot={updates['reboot']} error={updates.get('error')!r}", flush=True)
    check(name, "update check succeeds", not updates.get("error"), updates.get("error", ""))
    check(name, "updates are pending", updates["pending"] > 0 and updates["packages"], str(updates))
    check(name, "reboot state is a known value", updates["reboot"] in ("required", "not_required", "unknown"), updates["reboot"])
    if PENDING_COUNT[name]:
        expected = inside(PENDING_COUNT[name]).stdout.strip()
        check(name, "count matches the package manager", expected == str(updates["pending"]), f"{expected} != {updates['pending']}")
    check(name, "real package databases untouched", inside(ARCH_SYNC_DB).stdout == sync_before)


def test_rights(name, admin, device, inside):
    created = inside("groupadd -f docker && useradd -m -G docker ben")
    check(name, "second account prepared", created.returncode == 0, created.stderr)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
    task = run_task(admin, device, "sudo.grant", {"user": "anna", "expires_at": expires})
    check(name, "sudo.grant for the overview", task["status"] == "done", task["output"])

    def accounts(report):
        return {a["name"]: a for a in report.get("accounts") or []}

    def granted(report):
        found = accounts(report)
        return "ben" in found and "(ALL : ALL) ALL" in found.get("anna", {}).get("sudo", [])

    report = wait_report(admin, device, granted)
    check(name, "rights overview shows the grant", report, str(accounts(last_report(admin, device))))
    if not report:
        return
    found = accounts(report)
    anna, ben = found["anna"], found["ben"]
    check(name, "running grant has its expiry", anna.get("grant_expires"), str(anna))
    check(name, "own group is listed", "anna" in anna["groups"] or anna["groups"], str(anna))
    check(name, "UID is the real one", str(anna["uid"]) == inside("id -u anna").stdout.strip(), str(anna))
    check(name, "group equal to root is marked", ben.get("privileged") == ["docker"] and "docker" in ben["groups"], str(ben))
    # openSUSE lets everyone use sudo with the root password by default.
    allowed = "is not allowed" not in inside("sudo -l -U ben").stdout
    check(name, "sudo rights match what sudo says", bool(ben.get("sudo")) == allowed and not ben.get("sudo_unknown"), str(ben))
    check(name, "no grant without a grant", not ben.get("grant_expires"), str(ben))
    check(name, "system accounts stay out", not {"root", "daemon", "nobody"} & set(found), str(sorted(found)))

    task = run_task(admin, device, "sudo.revoke", {"user": "anna"})
    check(name, "sudo.revoke", task["status"] == "done", task["output"])
    gone = wait_report(admin, device, lambda r: "anna" in accounts(r) and not granted(r) and not accounts(r)["anna"].get("grant_expires"))
    check(name, "rights overview shows the end of the grant", gone, str(accounts(last_report(admin, device))))


JOURNAL_IMAGES = {
    "fedora": ("FROM registry.fedoraproject.org/fedora:44\n"
               "RUN dnf5 install -y systemd sudo shadow-utils && dnf5 clean all\n", "/sbin/init"),
    "debian": ("FROM docker.io/library/debian:stable\n"
               "RUN apt-get update && apt-get install -y systemd systemd-sysv dbus sudo ca-certificates\n", "/sbin/init"),
    # The image has no machine ID, and what fails without one or in a container
    # takes the system bus with it.
    "arch": ("FROM docker.io/library/archlinux:latest\n"
             "RUN pacman -Sy --noconfirm sudo ca-certificates && systemd-machine-id-setup && "
             "systemctl mask systemd-firstboot.service systemd-homed.service systemd-resolved.service\n",
             "/usr/lib/systemd/systemd"),
    "opensuse": ("FROM registry.opensuse.org/opensuse/tumbleweed:latest\n"
                 "RUN zypper --non-interactive install systemd dbus-1-daemon sudo shadow ca-certificates\n", "/usr/lib/systemd/systemd"),
}


def test_journal(distro, admin, agent_bin):
    """Proves that logs.fetch shows the system and nothing from users.

    Runs against a volatile journal, where user messages share the system's
    file, and a persistent one, where they have files of their own. Each marker
    is first shown to be in the journal, so a miss really means filtered.
    """
    name = f"journal-{distro}"
    print(f"\n== {name} (systemd as PID 1, real journal)", flush=True)
    containerfile, init = JOURNAL_IMAGES[distro]
    image = f"localhost/hauswart-e2e-journal-{distro}"
    built = subprocess.run(["podman", "build", "-q", "-t", image, "-"],
                           input=containerfile, text=True, capture_output=True, timeout=900)
    check(name, "image builds", built.returncode == 0, built.stderr)
    if built.returncode != 0:
        return
    container = f"{PREFIX}-{name}"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--systemd=always", "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", image, init)

    def inside(cmd, timeout=120):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=False, timeout=timeout)

    def in_journal(marker):
        # Whole lines only: systemd also logs the command that held the marker.
        return inside(f"journalctl --no-pager -o cat | grep -qx {marker}").returncode == 0

    def journald(storage):
        inside("mkdir -p /etc/systemd/journald.conf.d && "
               f"printf '[Journal]\\nStorage={storage}\\n' >/etc/systemd/journald.conf.d/test.conf && "
               "systemctl restart systemd-journald")

    def emit(round_):
        """Writes one system message and one per way a user's message can arrive.

        A message through a pipe can lose its metadata, because the sender ends
        before journald looks at it. That is the point of those variants.
        """
        system = f"SYSTEMMARKER{round_}"
        as_service = "sh -c 'echo \"<4>{}\"; sleep 1'"
        through_pipe = "sh -c 'echo {} | systemd-cat -p warning'"
        run = "systemd-run --quiet --wait"
        ways = {
            f"USERPIPE{round_}": f"{run} --uid=anna {through_pipe}",
            f"USEROUTPUT{round_}": f"{run} --uid=anna {as_service}",
            f"USERSERVICE{round_}": f"{run} --uid=anna --pipe --setenv=XDG_RUNTIME_DIR=/run/user/{uid} {run} --user {as_service}",
            f"ROOTOUTPUT{round_}": f"{run} --slice=user-{uid}.slice {as_service}",
            f"ROOTPIPE{round_}": f"{run} --slice=user-{uid}.slice {through_pipe}",
        }
        inside(f"{run} {as_service.format(system)}")
        for marker, command in ways.items():
            inside(command.format(marker))
        time.sleep(2)
        return system, list(ways)

    def verify(label, system, private, withheld):
        check(name, f"{label}: system marker is in the journal", in_journal(system))
        for marker in private:
            check(name, f"{label}: control, {marker} is in the journal", in_journal(marker))
        task = run_task(admin, device["id"], "logs.fetch", {"lines": 500})
        check(name, f"{label}: logs.fetch", task["status"] == "done", task["output"])
        data = task_data(admin, task)
        raw = json.dumps(data)
        check(name, f"{label}: journal is available", data.get("available") is True, raw[:300])
        check(name, f"{label}: system message is shown", system in raw, raw[-300:])
        for marker in private:
            check(name, f"{label}: NO user journal: {marker} left out", marker not in raw, raw[-300:])
        check(name, f"{label}: left out entries are counted", data.get("withheld", 0) >= withheld, str(data.get("withheld")))
        _, tasks = admin.call("GET", "/api/tasks")
        check(name, f"{label}: logs stay out of the task list", system not in json.dumps(tasks))
        return data

    try:
        inside("systemctl is-system-running --wait")
        inside("useradd -m anna && loginctl enable-linger anna")
        uid = inside("id -u anna").stdout.strip()
        inside("systemctl start user@$(id -u anna).service")

        _, enroll = admin.call("POST", "/api/enroll-tokens")
        check(name, "enrollment", inside(enroll["command"].replace("sudo ", "", 1)).returncode == 0)
        # The same name as the real unit, so the agent's messages are found the
        # same way as on a device with the package installed.
        started = inside("systemd-run --quiet --unit=hauswart-agent.service /usr/local/bin/hauswart-agent run")
        check(name, "agent runs as a unit", started.returncode == 0, started.stderr)

        device = None
        deadline = time.time() + 30
        while time.time() < deadline and not device:
            _, devices = admin.call("GET", "/api/devices")
            live = [d for d in devices if not d["revoked"] and d["report"].get("distro") and d["id"] not in seen]
            device = live[0] if live else None
            time.sleep(1)
        check(name, "report arrives", device)
        if not device:
            return
        seen.add(device["id"])

        journald("volatile")
        check(name, "journal is volatile", inside("ls /run/log/journal/*/system.journal").returncode == 0)
        system, private = emit("A")
        verify("volatile journal", system, private, len(private))
        shown = inside("journalctl --system --priority=warning --no-pager -o cat | grep -cx 'USER.*A'").stdout.strip()
        print(f"       user messages that --system alone would have shown: {shown}", flush=True)

        journald("persistent")
        inside("journalctl --flush")
        system, private = emit("B")
        check(name, "user has a journal file of their own", inside(f"ls /var/log/journal/*/user-{uid}.journal").returncode == 0,
              inside("ls -R /var/log/journal").stdout)
        # Messages of the user's own UID are in that file, which is not read at
        # all. What runs as root in a session stays in the system's file.
        data = verify("persistent journal", system, private, 2)

        check(name, "agent unit is in the result", any("running task" in e["message"] for e in data["agent"]), json.dumps(data["agent"])[-300:])
        check(name, "system part holds warnings and worse only", all(e["priority"] <= 4 for e in data["system"]), json.dumps(data["system"])[:300])

        inside("systemd-run --quiet --wait sh -c 'for i in 1 2 3 4 5 6 7 8; do echo \"<4>filler$i\"; done; sleep 1'")
        task = run_task(admin, device["id"], "logs.fetch", {"lines": 3})
        data = task_data(admin, task)
        check(name, "length is limited", len(data.get("system", [])) == 3 and len(data.get("agent", [])) <= 3, str(data)[:300])
        check(name, "the newest entries are kept", data.get("system", [{}])[-1].get("message") == "filler8", str(data.get("system")))
        code, out = admin.call("POST", f"/api/devices/{device['id']}/tasks", {"type": "logs.fetch", "payload": {"lines": 501}})
        check(name, "more than the limit is refused", code == 400, str(out))
    except Exception as err:
        check(name, "no crash", False, repr(err))
        print(inside("journalctl -u hauswart-agent.service --no-pager | tail -20").stdout)
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
    container = f"{PREFIX}-systemd"
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


class Admin:
    """The hauswart-admin tool with a real ssh-agent."""

    def __init__(self, work, binary):
        self.binary = binary
        # Unix sockets allow only short paths, which the work directory may not be.
        self.socket_dir = tempfile.mkdtemp(prefix="hw-", dir=os.environ.get("XDG_RUNTIME_DIR"))
        socket = f"{self.socket_dir}/agent"
        self.env = {**os.environ, "HAUSWART_ADMIN_DIR": f"{work}/admin", "SSH_AUTH_SOCK": socket}
        self.keys = []
        self.ssh_agent = subprocess.Popen(["ssh-agent", "-D", "-a", socket], stdout=subprocess.DEVNULL)
        for key in ("primary", "offline", "next"):
            sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{work}/{key}")
            self.keys.append(f"{work}/{key}")
        for _ in range(50):
            if os.path.exists(socket):
                break
            time.sleep(0.1)
        subprocess.run(["ssh-add", "-q", f"{work}/primary"], env=self.env, check=True)

    def run(self, *args, input=None):
        return subprocess.run([self.binary, *args], input=input, env=self.env, capture_output=True, text=True, timeout=120)

    def close(self):
        self.ssh_agent.terminate()
        shutil.rmtree(self.socket_dir, ignore_errors=True)


def test_signing(admin, agent_bin, work, password, admin_bin, ca_pem):
    """A compromised server is simulated by writing to its database directly."""
    name = "signing"
    print(f"\n== {name} (real ssh-agent, tasks written straight into the database)", flush=True)
    container = f"{PREFIX}-signing{SUFFIX}"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", DISTROS["fedora"][0], "sleep", "1500")
    tool = Admin(work, admin_bin)
    db_path = f"{work}/data/hauswart.db"

    def inside(cmd):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=False, timeout=300)

    def start_agent():
        sh("podman", "exec", "-d", container, "sh", "-c",
           "echo $$ >/run/agent.pid; exec hauswart-agent run >>/var/log/agent.log 2>&1")

    def attack(device, task_type, payload, signed=""):
        """What an attacker with full control of the server can do."""
        task_id = f"attack-{time.time_ns()}"
        with sqlite3.connect(db_path, timeout=10) as db:
            db.execute("INSERT INTO tasks (id, device_id, type, payload, status, signed, created_by, created_at) "
                       "VALUES (?,?,?,?,'pending',?,'attacker',?)",
                       (task_id, device, task_type, json.dumps(payload), signed, int(time.time())))
        return wait_task(admin, task_id, 45)

    def captured_signature(device, payload):
        """Pauses the agent to read a signed task the way the server sees it."""
        inside("kill -STOP $(cat /run/agent.pid)")
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "pkg.install", "payload": payload})
        assert code == 201, out
        tool.run("approve", input="y\n")
        with sqlite3.connect(db_path, timeout=10) as db:
            signed = db.execute("SELECT signed FROM tasks WHERE id = ?", (out["id"],)).fetchone()[0]
        inside("kill -CONT $(cat /run/agent.pid)")
        wait_task(admin, out["id"], 120)
        return signed

    try:
        inside("dnf5 install -y sudo shadow-utils procps-ng && useradd anna")
        fingerprint = re.search(r"--ca-fingerprint (\w+)", admin.call("POST", "/api/enroll-tokens")[1]["command"]).group(1)
        done = tool.run("login", "--server", URL, "--ca-fingerprint", "0" * 64, "--user", "admin", input=password + "\n")
        check(name, "login refuses a wrong CA", done.returncode != 0)
        done = tool.run("login", "--server", URL, "--ca-fingerprint", fingerprint, "--user", "admin", input=password + "\n")
        check(name, "login", done.returncode == 0, done.stderr)

        tool.run("keys", "add", f"{work}/primary.pub")
        check(name, "one key is not enough", tool.run("enroll-command").returncode != 0)
        tool.run("keys", "add", f"{work}/offline.pub")
        command = tool.run("enroll-command").stdout.strip()
        check(name, "enroll command pins both keys", command.count("--signing-key") == 2, command)
        enrolled = inside(command.replace("sudo ", "", 1))
        check(name, "enrollment", enrolled.returncode == 0, enrolled.stderr)
        device = re.search(r"Device ID: (\w+)", enrolled.stdout).group(1)
        start_agent()
        deadline = time.time() + 20
        report = {}
        while time.time() < deadline and not report.get("protected"):
            _, devices = admin.call("GET", "/api/devices")
            report = next((d["report"] for d in devices if d["id"] == device), {})
            time.sleep(1)
        check(name, "device reports protection", report.get("protected"), str(report))

        # A hacked server trying the ways to root.
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        task = attack(device, "sudo.grant", {"user": "anna", "expires_at": expires})
        check(name, "ATTACK unsigned sudo refused", task["status"] == "failed" and "signature" in task["output"], task["output"])
        check(name, "no sudo rule appeared", inside("test -e /etc/sudoers.d/hauswart-anna").returncode != 0)
        hash_ = sh("openssl", "passwd", "-6", "attacker").stdout.strip()
        task = attack(device, "user.passwd", {"user": "anna", "hash": hash_})
        check(name, "ATTACK unsigned password refused", task["status"] == "failed", task["output"])
        task = attack(device, "pkg.install", {"packages": ["nmap"]})
        check(name, "ATTACK unsigned package refused", task["status"] == "failed" and inside("command -v nmap").returncode != 0, task["output"])
        task = attack(device, "ca.install", {"name": "evil", "pem": ca_pem})
        check(name, "ATTACK unsigned CA refused", task["status"] == "failed", task["output"])
        task = attack(device, "keys.set", {"keys": [open(f"{work}/next.pub").read().strip()]})
        check(name, "ATTACK unsigned key swap refused", task["status"] == "failed", task["output"])
        check(name, "pinned keys unchanged", open(f"{work}/next.pub").read().split()[1] not in inside("cat /var/lib/hauswart/agent.json").stdout)

        # The new actions, each without a signature.
        valid = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        inside("groupadd media")
        for task_type, payload in (
            ("power.reboot", {"delay_minutes": 1, "expires_at": valid}),
            ("power.shutdown", {"delay_minutes": 1, "expires_at": valid}),
            ("notify.send", {"message": "Your password expired, call 555-1234", "expires_at": valid}),
            ("group.add", {"user": "anna", "group": "media"}),
            ("group.remove", {"user": "anna", "group": "media"}),
        ):
            task = attack(device, task_type, payload)
            check(name, f"ATTACK unsigned {task_type} refused",
                  task["status"] == "failed" and "signature" in task["output"], task["output"])
        check(name, "no group change happened", "media" not in inside("id -nG anna").stdout)
        task = attack(device, "group.add", {"user": "anna", "group": "wheel"})
        check(name, "ATTACK unsigned wheel refused", task["status"] == "failed", task["output"])
        check(name, "not in wheel", "wheel" not in inside("id -nG anna").stdout)

        # The normal way.
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "pkg.install", "payload": {"packages": ["tree"]}})
        _, tasks = admin.call("GET", "/api/tasks")
        status = next(t for t in tasks if t["id"] == out["id"])["status"]
        check(name, "dashboard task waits for a signature", status == "signing", status)
        skipped = tool.run("approve", input="y\n")
        check(name, "an unnamed device cannot be signed for", "no name here" in skipped.stdout, skipped.stdout + skipped.stderr)
        tool.run("name", device, "test-laptop")
        shown = tool.run("approve", input="n\n")
        check(name, "approve shows device and packages",
              "Install packages as root: tree" in shown.stdout and "test-laptop" in shown.stdout, shown.stdout + shown.stderr)
        check(name, "saying no leaves it queued", next(t for t in admin.call("GET", "/api/tasks")[1] if t["id"] == out["id"])["status"] == "signing")
        signed = tool.run("approve", input="y\n")
        check(name, "approve signs", "Signed." in signed.stdout, signed.stdout + signed.stderr)
        task = wait_task(admin, out["id"], 120)
        check(name, "signed task runs", task["status"] == "done" and inside("command -v tree").returncode == 0, task["output"])

        # Attacks with a real signature.
        captured = captured_signature(device, {"packages": ["vim-minimal"]})
        check(name, "signature captured", captured != "")
        task = attack(device, "pkg.install", {"packages": ["nmap"]}, captured)
        check(name, "ATTACK replay refused", task["status"] == "failed" and "counter" in task["output"], task["output"])
        envelope = json.loads(captured)
        raw = base64.b64decode(envelope["envelope"]).replace(b"vim-minimal", b"nmap")
        envelope["envelope"] = base64.b64encode(raw).decode()
        task = attack(device, "pkg.install", {"packages": ["nmap"]}, json.dumps(envelope))
        check(name, "ATTACK changed envelope refused", task["status"] == "failed", task["output"])
        check(name, "nmap never arrived", inside("command -v nmap").returncode != 0)

        # A real signature on one thing must not carry another.
        task = attack(device, "power.reboot", {"delay_minutes": 1, "expires_at": valid}, captured)
        check(name, "ATTACK signed package as a reboot refused", task["status"] == "failed", task["output"])

        # Signed actions take the normal way, and the tool says what they do.
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "group.add", "payload": {"user": "anna", "group": "media"}})
        shown = tool.run("approve", input="y\n")
        check(name, "approve spells out the group", "ADD Linux user anna to group media" in shown.stdout, shown.stdout + shown.stderr)
        task = wait_task(admin, out["id"], 45)
        check(name, "signed group.add works", task["status"] == "done" and "media" in inside("id -nG anna").stdout, task["output"])
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "group.remove", "payload": {"user": "anna", "group": "media"}})
        tool.run("approve", input="y\n")
        task = wait_task(admin, out["id"], 45)
        check(name, "signed group.remove works", task["status"] == "done" and "media" not in inside("id -nG anna").stdout, task["output"])
        for group in ("wheel", "sudo", "docker"):
            code, _ = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "group.add", "payload": {"user": "anna", "group": group}})
            check(name, f"dashboard refuses {group}", code == 400, str(code))
        inside("groupadd family; echo '%family ALL=(ALL) ALL' >/etc/sudoers.d/family; chmod 440 /etc/sudoers.d/family")
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "group.add", "payload": {"user": "anna", "group": "family"}})
        tool.run("approve", input="y\n")
        task = wait_task(admin, out["id"], 45)
        check(name, "a group with sudo rights is refused, even signed", task["status"] == "failed" and "family" not in inside("id -nG anna").stdout, task["output"])
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "notify.send", "payload": {"message": "Essen ist fertig", "expires_at": valid}})
        shown = tool.run("approve", input="n\n")
        check(name, "approve shows the popup text", 'titled "Hauswart"' in shown.stdout and "Essen ist fertig" in shown.stdout, shown.stdout + shown.stderr)
        tool.run("approve", input="r\n")
        task = run_task(admin, device, "power.cancel", {}, wait=45)
        check(name, "power.cancel needs no signature", task["status"] in ("done", "failed") and "signature" not in task["output"], task["output"])

        # Reject, and a task that needs no signature.
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "pkg.install", "payload": {"packages": ["nmap"]}})
        tool.run("approve", input="r\n")
        check(name, "rejecting closes the task", next(t for t in admin.call("GET", "/api/tasks")[1] if t["id"] == out["id"])["status"] == "failed")
        task = run_task(admin, device, "sudo.revoke", {"user": "anna"}, wait=45)
        check(name, "sudo.revoke needs no signature", task["status"] == "done", task["output"])
        task = run_task(admin, device, "logs.fetch", {}, wait=45)
        check(name, "logs.fetch needs no signature", task["status"] == "done", task["output"])
        task = attack(device, "logs.fetch", {"unit": "sshd.service"})
        check(name, "ATTACK logs of a chosen unit refused", task["status"] == "failed", task["output"])
        task = attack(device, "logs.fetch", {"lines": 100000})
        check(name, "ATTACK unlimited logs refused", task["status"] == "failed", task["output"])

        # Sudo and the start password.
        code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": "sudo.grant", "payload": {"user": "anna", "expires_at": expires}})
        shown = tool.run("approve", input="y\n")
        check(name, "full root is spelled out", "FULL ROOT" in shown.stdout, shown.stdout)
        wait_task(admin, out["id"], 45)
        check(name, "signed sudo works", "(ALL : ALL) ALL" in inside("sudo -l -U anna").stdout)
        code, _ = admin.call("POST", f"/api/devices/{device}/start-password", {"user": "anna"})
        check(name, "server cannot make a password here", code == 409, str(code))
        made = tool.run("start-password", "--device", device, "--user", "anna")
        check(name, "admin tool sets a start password", made.returncode == 0, made.stderr)
        secret = re.search(r"for anna: (\w+)", made.stdout).group(1)
        time.sleep(8)
        shadow = inside("getent shadow anna").stdout.strip().split(":")
        fields = shadow[1].split("$")
        expected = sh("openssl", "passwd", "-6", "-salt", fields[-2], secret).stdout.strip()
        check(name, "password in shadow matches", expected.split("$")[-1] == fields[-1], shadow[1])
        _, tasks = admin.call("GET", "/api/tasks")
        _, audit = admin.call("GET", "/api/audit")
        check(name, "hash reaches neither log", fields[-1] not in json.dumps(tasks) + json.dumps(audit))

        # Rotation, then the second key.
        tool.run("keys", "add", f"{work}/next.pub")
        check(name, "rotate-keys", tool.run("rotate-keys", "--device", device).returncode == 0)
        time.sleep(8)
        check(name, "new key is pinned", open(f"{work}/next.pub").read().split()[1] in inside("cat /var/lib/hauswart/agent.json").stdout)

        # Lost state must stop the agent, not reset it.
        inside("kill $(cat /run/agent.pid); rm /var/lib/hauswart/guard.json; : >/var/log/agent.log")
        start_agent()
        time.sleep(3)
        log = inside("cat /var/log/agent.log").stdout
        check(name, "lost signing state stops the agent", "signing state" in log and inside("kill -0 $(cat /run/agent.pid)").returncode != 0, log)

        # Protecting an already enrolled device.
        _, token = admin.call("POST", "/api/enroll-tokens")
        check(name, "plain enrollment", inside(token["command"].replace("sudo ", "", 1) + " --dir /var/lib/h2").returncode == 0)
        trust = tool.run("trust-command").stdout.strip().replace("sudo ", "", 1)
        check(name, "trust-key protects later", inside(trust + " --dir /var/lib/h2").returncode == 0)
        check(name, "trust-key works only once", inside(trust + " --dir /var/lib/h2").returncode != 0)
    except Exception as err:
        check(name, "no crash", False, repr(err))
        print(inside("tail -20 /var/log/agent.log").stdout)
    finally:
        tool.close()
        sh("podman", "rm", "-f", container, check_rc=False)


def test_socket(admin, agent_bin):
    """Everyone on a device talks to the agent as root runs it, and sees only themselves."""
    name = "socket"
    print(f"\n== {name} (two people at the socket of a real agent)", flush=True)
    container = f"{PREFIX}-socket{SUFFIX}"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", DISTROS["fedora"][0], "sleep", "600")

    def inside(cmd):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=False, timeout=300)

    def as_user(user, path, body=None):
        send = f"-X POST -d '{body}'" if body else ""
        return inside(f"runuser -u {user} -- curl -s -o /dev/stdout -w ' %{{http_code}}' --unix-socket /run/hauswart/user.sock {send} http://agent{path}")

    try:
        inside(DISTROS["fedora"][1] + " util-linux curl && useradd anna && useradd ben")
        _, enroll = admin.call("POST", "/api/enroll-tokens")
        enrolled = inside(enroll["command"].replace("sudo ", "", 1))
        check(name, "enrollment", enrolled.returncode == 0, enrolled.stderr)
        device = re.search(r"Device ID: (\w+)", enrolled.stdout).group(1)
        seen.add(device)
        sh("podman", "exec", "-d", container, "sh", "-c", "hauswart-agent run >/var/log/agent.log 2>&1")
        time.sleep(3)
        check(name, "the socket is there", inside("test -S /run/hauswart/user.sock").returncode == 0, inside("tail -5 /var/log/agent.log").stdout)

        anna, ben = as_user("anna", "/status"), as_user("ben", "/status")
        check(name, "anna is anna", '"user":"anna"' in anna.stdout and " 200" in anna.stdout, anna.stdout + anna.stderr)
        check(name, "ben is ben", '"user":"ben"' in ben.stdout, ben.stdout)

        code, out = admin.call("POST", "/api/users", {"username": "anna-socket", "linux_user": "anna", "password": "long enough password", "role": "member"})
        check(name, "account for anna", code == 201, str(out))
        account = next(u for u in admin.call("GET", "/api/users")[1] if u["username"] == "anna-socket")
        admin.call("PUT", f"/api/users/{account['id']}/devices", {"devices": [device]})

        sent = as_user("anna", "/request", '{"kind":"software","detail":"vim","reason":"school"}')
        check(name, "a request goes out", sent.stdout.strip().endswith("201"), sent.stdout)
        _, requests = admin.call("GET", "/api/requests")
        filed = [r for r in requests if r["detail"] == "vim" and r["device_id"] == device]
        check(name, "and arrives as anna's", len(filed) == 1 and filed[0]["username"] == "anna-socket", str(requests))

        forged = as_user("ben", "/request", '{"kind":"software","detail":"vim","user":"anna"}')
        check(name, "ATTACK ben cannot speak for anna", forged.stdout.strip().endswith("400"), forged.stdout)
        unknown = as_user("ben", "/request", '{"kind":"software","detail":"vim"}')
        check(name, "someone without an account gets nowhere", not unknown.stdout.strip().endswith("201"), unknown.stdout)
    finally:
        sh("podman", "rm", "-f", container, check_rc=False)


POLICY_FILE = "/etc/hauswart.d/policy-test"


def test_policy(distro, admin, agent_bin, work, password, admin_bin, ca_pem, stop_server, restart_server):
    """The whole way of a policy, on a real package manager. Stopping the server
    shows that a device keeps its state on its own."""
    name = f"policy-{distro}"
    image, setup, package = DISTROS[distro]
    print(f"\n== {name} ({image})", flush=True)
    container = f"{PREFIX}-{name}{SUFFIX}"
    sh("podman", "rm", "-f", container, check_rc=False)
    sh("podman", "run", "-d", "--name", container, "--network", "host",
       "-v", f"{agent_bin}:/usr/local/bin/hauswart-agent:ro,Z", image, "sleep", "1500", timeout=600)
    home = f"{work}/{name}"
    os.makedirs(home)
    tool = Admin(home, admin_bin)
    db_path = f"{work}/data/hauswart.db"

    def inside(cmd, timeout=600):
        return sh("podman", "exec", container, "sh", "-c", cmd, check_rc=False, timeout=timeout)

    def start_agent():
        sh("podman", "exec", "-d", container, "sh", "-c",
           "echo $$ >/run/agent.pid; exec hauswart-agent run >>/var/log/agent.log 2>&1")

    def attack(device, payload, signed=""):
        task_id = f"attack-{time.time_ns()}"
        with sqlite3.connect(db_path, timeout=10) as db:
            db.execute("INSERT INTO tasks (id, device_id, type, payload, status, signed, created_by, created_at) "
                       "VALUES (?,?,?,?,'pending',?,'attacker',?)",
                       (task_id, device, "policy.set", json.dumps(payload), signed, int(time.time())))
        return wait_task(admin, task_id, 45)

    def until(condition, wait=180):
        deadline = time.time() + wait
        while time.time() < deadline:
            if condition():
                return True
            time.sleep(2)
        return False

    def installed(pkg):
        query = {"fedora": f"rpm -q {pkg}", "opensuse": f"rpm -q {pkg}", "arch": f"pacman -Q {pkg}",
                 "debian": f"dpkg-query -W -f='${{db:Status-Status}}' {pkg} | grep -qx installed"}[distro]
        return inside(query).returncode == 0

    def ca_files():
        # Plain ls, as not every image has find.
        dirs = ("/etc/pki/ca-trust/source/anchors", "/etc/ca-certificates/trust-source/anchors",
                "/etc/pki/trust/anchors", "/usr/local/share/ca-certificates")
        return inside("ls " + " ".join(f"{d}/hauswart-home.crt" for d in dirs) + " 2>/dev/null").stdout.split()

    def state():
        _, view = admin.call("GET", f"/api/groups/{group}/policy")
        return next(d for d in view["devices"] if d["id"] == device)

    try:
        inside(setup)
        install = {"fedora": "dnf5 install -y nano", "opensuse": "zypper --non-interactive install nano",
                   "arch": "pacman -S --noconfirm nano", "debian": "apt-get install -y nano"}[distro]
        check(name, "forbidden package is there at first", inside(install).returncode == 0 and installed("nano"))

        fingerprint = re.search(r"--ca-fingerprint (\w+)", admin.call("POST", "/api/enroll-tokens")[1]["command"]).group(1)
        tool.run("login", "--server", URL, "--ca-fingerprint", fingerprint, "--user", "admin", input=password + "\n")
        tool.run("keys", "add", f"{home}/primary.pub")
        tool.run("keys", "add", f"{home}/offline.pub")
        enrolled = inside(tool.run("enroll-command").stdout.strip().replace("sudo ", "", 1))
        check(name, "enrollment", enrolled.returncode == 0, enrolled.stderr)
        device = re.search(r"Device ID: (\w+)", enrolled.stdout).group(1)
        seen.add(device)  # later tests look for the newest device they have not seen
        start_agent()
        report = wait_report(admin, device, lambda r: r.get("protected"), 30)
        check(name, "device reports protection", report.get("protected"), str(report))
        tool.run("name", device, f"{distro}-laptop")

        code, out = admin.call("POST", "/api/groups", {"name": name})
        check(name, "group created", code == 201, out)
        group = out["id"]
        admin.call("PUT", f"/api/groups/{group}/devices", {"devices": [device]})

        policy = {
            "required_packages": [package],
            "forbidden_packages": ["nano"],
            "files": [{"path": POLICY_FILE, "content": "wanted\n", "mode": "0640"}],
            "cas": [{"name": "home", "pem": ca_pem}],
        }
        code, out = admin.call("PUT", f"/api/groups/{group}/policy", policy)
        check(name, "policy saved", code == 204, out)
        check(name, "it waits for a signature", state()["state"] == "signature", str(state()))
        check(name, "nothing changed before the signature", installed("nano") and not installed(package))

        task = attack(device, policy)
        check(name, "ATTACK unsigned policy refused", task["status"] == "failed" and "signature" in task["output"], task["output"])
        check(name, "the unsigned policy did nothing", installed("nano"))

        shown = tool.run("approve", input="n\n")
        check(name, "approve shows the rules",
              f"required package {package}" in shown.stdout and "forbidden package nano" in shown.stdout
              and "TRUSTED CA home" in shown.stdout and "wanted" in shown.stdout, shown.stdout + shown.stderr)
        check(name, "the first policy is all new", "all of it is new" in shown.stdout, shown.stdout)
        # The agent pauses, so that the signature can be read the way a server
        # sees it. It is gone from the database once the task has run.
        inside("kill -STOP $(cat /run/agent.pid)")
        signed = tool.run("approve", input="y\n")
        check(name, "approve signs", "Signed." in signed.stdout, signed.stdout + signed.stderr)
        with sqlite3.connect(db_path, timeout=10) as db:
            # A waiting long poll may have claimed it already, for the paused agent.
            captured = db.execute("SELECT signed FROM tasks WHERE type = 'policy.set' AND status IN ('pending','running') "
                                  "AND signed != '' AND device_id = ?", (device,)).fetchone()[0]
        inside("kill -CONT $(cat /run/agent.pid)")

        check(name, "required package arrives", until(lambda: installed(package)))
        check(name, "forbidden package goes", until(lambda: not installed("nano")))
        check(name, "file arrives", until(lambda: inside(f"cat {POLICY_FILE}").stdout == "wanted\n"))
        check(name, "file has its mode", inside(f"stat -c %a {POLICY_FILE}").stdout.strip() == "640")
        check(name, "CA is in the trust store", until(lambda: ca_files()), inside("cat /var/log/agent.log | tail -5").stdout)
        print(f"       CA files: {ca_files()}", flush=True)
        check(name, "the dashboard says up to date", until(lambda: state()["state"] == "current"), str(state()))

        task = attack(device, policy, captured)
        check(name, "ATTACK replayed policy refused", task["status"] == "failed" and "counter" in task["output"], task["output"])
        document = json.loads(captured)
        envelope = json.loads(base64.b64decode(document["envelope"]))
        envelope["payload"]["required_packages"] = ["nano"]
        envelope["payload"]["forbidden_packages"] = []
        document["envelope"] = base64.b64encode(json.dumps(envelope).encode()).decode()
        task = attack(device, policy, json.dumps(document))
        check(name, "ATTACK changed policy refused", task["status"] == "failed" and "signature" in task["output"], task["output"])

        # The device is on its own from here on.
        stop_server()
        inside(f"kill $(cat /run/agent.pid); echo changed >{POLICY_FILE}; chmod 666 {POLICY_FILE}")
        sh("podman", "exec", container, "sh", "-c", install, check_rc=False, timeout=600)
        check(name, "drift is real", installed("nano") and inside(f"cat {POLICY_FILE}").stdout == "changed\n")
        start_agent()
        check(name, "offline: file restored", until(lambda: inside(f"cat {POLICY_FILE}").stdout == "wanted\n", 60))
        check(name, "offline: mode restored", inside(f"stat -c %a {POLICY_FILE}").stdout.strip() == "640")
        check(name, "offline: forbidden package removed", until(lambda: not installed("nano"), 120))
        restart_server()
        admin.call("POST", "/api/login", {"username": "admin", "password": password})
        report = wait_report(admin, device, lambda r: "policy" in r and r["policy"].get("corrected"), 90)
        check(name, "the report says what was corrected",
              any(POLICY_FILE in item for item in report.get("policy", {}).get("corrected", [])), str(report.get("policy")))

        policy["required_packages"] = [package, "hw-no-such-package"]
        admin.call("PUT", f"/api/groups/{group}/policy", policy)
        shown = tool.run("approve", input="y\n")
        check(name, "the diff shows the change",
              "+ required package hw-no-such-package" in shown.stdout and "- " not in shown.stdout.split("Changes since")[1].split("Sign?")[0],
              shown.stdout)
        check(name, "an impossible rule shows as a deviation",
              until(lambda: state()["state"] == "deviation" and "hw-no-such-package" in str(state()["deviations"]), 150), str(state()))

        admin.call("PUT", f"/api/groups/{group}/devices", {"devices": []})
        shown = tool.run("approve", input="y\n")
        check(name, "leaving the group needs a signature too", "REMOVE THE POLICY" in shown.stdout, shown.stdout + shown.stderr)
        check(name, "the CA is no longer trusted", until(lambda: len(ca_files()) == 0))
        check(name, "what the policy installed stays", installed(package))
        report = wait_report(admin, device, lambda r: "policy" not in r, 90)
        check(name, "no policy in the report any more", "policy" not in report, str(report.get("policy")))
    finally:
        tool.close()
        sh("podman", "rm", "-f", container, check_rc=False)


NTFY_IMAGE = "docker.io/binwiederhier/ntfy:latest"
MAILPIT_IMAGE = "docker.io/axllent/mailpit:latest"
NTFY_PORT, SMTP_PORT, MAILPIT_PORT = 18481, 18482, 18483
SERVICE_IP = "127.0.0.2"  # the server's own names are refused for services


def test_notify(admin, work, restart_server):
    """Real ntfy and mail servers, on TLS with certificates from Hauswart."""
    name = "notify"
    print(f"\n== {name} (ntfy and Mailpit in containers, TLS from a service certificate)", flush=True)
    containers = ("hauswart-e2e-ntfy" + SUFFIX, "hauswart-e2e-mail" + SUFFIX)
    for container in containers:
        sh("podman", "rm", "-f", container, check_rc=False)

    def fetch(url, token=None):
        ctx = ssl.create_default_context(cafile=f"{work}/service/ca.pem")
        req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"} if token else {})
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            return resp.read().decode()

    try:
        # A service certificate, used by real TLS servers.
        code, out = admin.call("POST", "/api/certificates", {"names": ["google.com"]})
        check(name, "certificate outside the CA refused", code == 400 and out["code"] == "cert_outside_ca", str(out))
        code, out = admin.call("POST", "/api/certificates", {"names": ["localhost"]})
        check(name, "certificate for the server itself refused", code == 400 and out["code"] == "cert_server_name", str(out))
        code, issued = admin.call("POST", "/api/certificates", {"names": [SERVICE_IP, "nas.home.test"], "days": 30})
        check(name, "service certificate issued", code == 201, str(issued))
        service = f"{work}/service"
        os.makedirs(service, mode=0o755)
        for file, field in (("cert.pem", "cert"), ("key.pem", "key"), ("ca.pem", "ca")):
            with open(f"{service}/{file}", "w") as f:
                f.write(issued[field])
            os.chmod(f"{service}/{file}", 0o644)  # read by the container's user
        _, listed = admin.call("GET", "/api/certificates")
        check(name, "listed with its expiry", any(c["serial"] == issued["serial"] and c["not_after"] == issued["not_after"] for c in listed), str(listed))
        check(name, "key is not in the list", issued["key"].split("\n")[1] not in json.dumps(listed))
        _, audit = admin.call("GET", "/api/audit")
        entry = next((e for e in audit if e["action"] == "certificate.issued"), None)
        check(name, "in the audit log", entry and issued["serial"] in entry["detail"], str(entry))
        check(name, "key is not in the audit log", issued["key"].split("\n")[1] not in json.dumps(audit))
        stored = sh("sh", "-c", f"grep -rlF '{issued['key'].splitlines()[1]}' {work}/data", check_rc=False).stdout
        check(name, "key is nowhere in the data directory", stored == "", stored)

        with open(f"{service}/mail-users", "w") as f:
            f.write("hauswart:mail-secret\n")
        os.chmod(f"{service}/mail-users", 0o644)
        sh("podman", "run", "-d", "--name", containers[0], "--network", "host", "-v", f"{service}:/tls:ro,z",
           "-e", "NTFY_BASE_URL=https://" + SERVICE_IP, "-e", f"NTFY_LISTEN_HTTP=-", "-e", f"NTFY_LISTEN_HTTPS={SERVICE_IP}:{NTFY_PORT}",
           "-e", "NTFY_KEY_FILE=/tls/key.pem", "-e", "NTFY_CERT_FILE=/tls/cert.pem",
           "-e", "NTFY_AUTH_FILE=/tmp/auth.db", "-e", "NTFY_AUTH_DEFAULT_ACCESS=deny-all",
           "-e", "NTFY_CACHE_FILE=/tmp/cache.db", NTFY_IMAGE, "serve", timeout=300)
        sh("podman", "run", "-d", "--name", containers[1], "--network", "host", "-v", f"{service}:/tls:ro,z",
           MAILPIT_IMAGE, "--smtp", f"{SERVICE_IP}:{SMTP_PORT}", "--listen", f"{SERVICE_IP}:{MAILPIT_PORT}",
           "--smtp-tls-cert", "/tls/cert.pem", "--smtp-tls-key", "/tls/key.pem", "--smtp-require-starttls",
           "--smtp-auth-file", "/tls/mail-users", timeout=300)
        time.sleep(3)
        made = sh("podman", "exec", "-e", "NTFY_PASSWORD=ntfy-secret-1", containers[0], "ntfy", "user", "add", "--role=admin", "hauswart", check_rc=False)
        check(name, "ntfy user created", made.returncode == 0, made.stdout + made.stderr)
        created = sh("podman", "exec", containers[0], "ntfy", "token", "add", "hauswart", check_rc=False)
        token = re.search(r"tk_\w+", created.stdout + created.stderr)
        check(name, "ntfy token created", token, created.stdout + created.stderr)
        token = token.group(0)

        env_path = f"{work}/notify.env"
        topic = "hauswart-topic-" + os.urandom(8).hex()
        with open(env_path, "w") as f:
            f.write(f"NTFY_URL=https://{SERVICE_IP}:{NTFY_PORT}/{topic}\nNTFY_TOKEN={token}\n"
                    f"SMTP_HOST={SERVICE_IP}\nSMTP_PORT={SMTP_PORT}\nSMTP_USER=hauswart\nSMTP_PASSWORD=mail-secret\n"
                    "SMTP_FROM=Hauswart <hauswart@home.test>\nSMTP_TO=admin@home.test\n")
        os.chmod(env_path, 0o600)
        restart_server()

        # A member files a request from a device with a hostile hostname.
        device = "notify-device"
        with sqlite3.connect(f"{work}/data/hauswart.db", timeout=10) as db:
            db.execute("INSERT INTO devices (id, hostname, cert_serial, enrolled_at) VALUES (?,?,'x',?)",
                       (device, "küche\nBcc: evil@example.org http://phish.example", int(time.time())))
        code, _ = admin.call("POST", "/api/users", {"username": "mia", "password": "member password", "role": "member", "linux_user": "mia"})
        check(name, "member created", code == 201, str(code))
        _, users = admin.call("GET", "/api/users")
        mia = next(u for u in users if u["username"] == "mia")
        code, _ = admin.call("PUT", f"/api/users/{mia['id']}/devices", {"devices": [device]})
        check(name, "device assigned to the member", code == 204, str(code))
        member = Client(f"{work}/data/pki/ca.pem")
        member.call("POST", "/api/login", {"username": "mia", "password": "member password"})
        started = time.time()
        code, out = member.call("POST", "/api/requests", {"device_id": device, "kind": "software", "detail": "secretpackage", "reason": "my password is hunter2"})
        took = time.time() - started
        check(name, "request filed", code == 201, str(out))
        check(name, "the request does not wait for delivery", took < 1, f"{took:.2f}s")

        message = ""
        deadline = time.time() + 30
        while time.time() < deadline and not message:
            message = fetch(f"https://{SERVICE_IP}:{NTFY_PORT}/{topic}/json?poll=1", token)
            time.sleep(1)
        check(name, "ntfy got the message", "mia asks for software" in message, message)
        mails = []
        while time.time() < deadline and not mails:
            mails = json.loads(fetch(f"http://{SERVICE_IP}:{MAILPIT_PORT}/api/v1/messages"))["messages"]
            time.sleep(1)
        check(name, "mail arrived over STARTTLS with a login", len(mails) == 1, str(mails))
        mail = fetch(f"http://{SERVICE_IP}:{MAILPIT_PORT}/api/v1/message/{mails[0]['ID']}/raw") if mails else ""
        check(name, "mail has the text and fixed subject", "mia asks for software" in mail and "Subject: New request in Hauswart" in mail, mail)
        everything = message + mail
        for leak in ("secretpackage", "hunter2", "ntfy-secret", "mail-secret", token):
            check(name, f"no {leak[:8]}... in the messages", leak not in everything)
        check(name, "hostile hostname adds no header or link", "Bcc" not in mail.split("\r\n\r\n")[0] and "http://phish" not in everything, mail)
        server_log = open(f"{work}/server.log").read()
        check(name, "no secret in the server log", not any(s in server_log for s in ("mail-secret", token, topic)))

        # A dead channel must not slow anybody down.
        for container in containers[:2]:
            sh("podman", "rm", "-f", container, check_rc=False)
        started = time.time()
        code, _ = member.call("POST", "/api/requests", {"device_id": device, "kind": "flatpak", "detail": "org.gnome.Chess", "reason": ""})
        took = time.time() - started
        check(name, "a request still goes through quickly with both servers gone", code == 201 and took < 1, f"{code} {took:.2f}s")
        time.sleep(2)
        log = open(f"{work}/server.log").read()
        check(name, "the failure is logged without the topic", "sending a notification failed" in log and topic not in log, log[-400:])

        os.chmod(env_path, 0o644)
        restart_server()
        log = open(f"{work}/server.log").read()
        check(name, "a file others can read is not used", "admin notifications are off" in log and "must be 0600" in log, log[-400:])
    except Exception as err:
        check(name, "no crash", False, repr(err))
        for container in containers:
            print(sh("podman", "logs", "--tail", "15", container, check_rc=False).stderr)
    finally:
        for container in containers:
            sh("podman", "rm", "-f", container, check_rc=False)


RENEWAL_VALIDITY = 90


def test_renewal(admin, agent_bin):
    """Runs an agent past the expiry of its first certificate."""
    name = "renewal"
    print(f"\n== {name} (certificates valid for {RENEWAL_VALIDITY}s)", flush=True)
    container = f"{PREFIX}-renewal"
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
        _, devices = admin.call("GET", "/api/devices")
        warnings = next(d for d in devices if d["id"] == device).get("warnings", [])
        check(name, "soon expiring certificate is flagged", any(w["code"] == "cert_expiring" for w in warnings), str(warnings))

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
    names = sys.argv[1:] or [*DISTROS, *(f"journal-{d}" for d in DISTROS), *(f"policy-{d}" for d in DISTROS), "systemd", "signing", "socket"]
    extra_args = ["-device-cert-validity", f"{RENEWAL_VALIDITY}s"] if names == ["renewal"] else []
    if names == ["notify"]:  # the CA scope is fixed when the CA is made
        extra_args = ["-ca-scope", "home.test,127.0.0.0/8"]
    work = tempfile.mkdtemp(prefix="hauswart-e2e-", dir=os.environ.get("E2E_TMP"))
    server_bin, agent_bin = f"{work}/server", f"{work}/agent"
    env = {**os.environ, "CGO_ENABLED": "0"}
    subprocess.run(["go", "build", "-o", server_bin, "./cmd/hauswart-server"], cwd=ROOT, env=env, check=True)
    subprocess.run(["go", "build", "-o", agent_bin, "./cmd/hauswart-agent"], cwd=ROOT, env=env, check=True)
    admin_bin = f"{work}/admin-tool"
    subprocess.run(["go", "build", "-o", admin_bin, "./cmd/hauswart-admin"], cwd=ROOT, env=env, check=True)

    log_path = f"{work}/server.log"

    def start_server():
        with open(log_path, "a") as log:
            return subprocess.Popen(
                [server_bin, "-addr", f"127.0.0.1:{PORT}", "-data", f"{work}/data", "-url", URL,
                 "-notify-env", f"{work}/notify.env", *extra_args],
                stderr=log, stdout=log)

    server = start_server()

    def stop_server():
        server.terminate()
        server.wait()

    def restart_server():
        nonlocal server
        server.terminate()
        server.wait()
        before = open(log_path).read().count("listening")
        server = start_server()
        for _ in range(50):
            if open(log_path).read().count("listening") > before:
                return
            time.sleep(0.2)
        raise RuntimeError("server did not come back")

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
            elif name == "notify":
                test_notify(admin, work, restart_server)
            elif name == "socket":
                test_socket(admin, agent_bin)
            elif name == "signing":
                test_signing(admin, agent_bin, work, password, admin_bin, ca_pem)
            elif name.startswith("journal-"):
                test_journal(name.removeprefix("journal-"), admin, agent_bin)
            elif name.startswith("policy-"):
                test_policy(name.removeprefix("policy-"), admin, agent_bin, work, password, admin_bin, ca_pem, stop_server, restart_server)
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
