#!/usr/bin/env python3
"""Runs what containers cannot, in real virtual machines: Flatpak, rpm-ostree,
real reboots and popups in a real desktop session.

The server runs on the host. Guests reach it through QEMU's user networking at
10.0.2.2, so this needs no root and touches nothing on the host but a cache
directory. Usage: test/vm.py [flatpak atomic ubuntu power desktop]
"""
import hashlib
import json
import lzma
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import browsers  # noqa: E402
import e2e  # noqa: E402

PORT = int(os.environ.get("VM_PORT", "18450"))
GUEST_URL = f"https://10.0.2.2:{PORT}"
ROOT = e2e.ROOT
CACHE = os.environ.get("VM_CACHE", os.path.expanduser("~/.cache/hauswart-vm"))

CLOUD_DIR = "https://download.fedoraproject.org/pub/fedora/linux/releases/44/Cloud/x86_64/images/"
CLOUD_IMAGE = "Fedora-Cloud-Base-Generic-44-1.7.x86_64.qcow2"
STREAM = "https://builds.coreos.fedoraproject.org/streams/stable.json"

# Small app on the freedesktop runtime.
FLATPAK_APP = "io.mpv.Mpv"

results = []


def check(group, name, ok, detail=""):
    results.append((group, name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {str(detail)[-600:]}" if detail and not ok else ""), flush=True)


def fetch(url, path):
    if os.path.exists(path):
        return
    print(f"downloading {url}", flush=True)
    with urllib.request.urlopen(url) as resp, open(path + ".part", "wb") as out:
        shutil.copyfileobj(resp, out)
    os.rename(path + ".part", path)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cloud_image():
    path = f"{CACHE}/{CLOUD_IMAGE}"
    fetch(CLOUD_DIR + CLOUD_IMAGE, path)
    listing = urllib.request.urlopen(CLOUD_DIR).read().decode()
    name = re.search(r'Fedora-Cloud-44-[^"<>]*CHECKSUM', listing).group(0)
    sums = urllib.request.urlopen(CLOUD_DIR + name).read().decode()
    want = re.search(rf"SHA256 \({re.escape(CLOUD_IMAGE)}\) = (\w+)", sums).group(1)
    if sha256(path) != want:
        os.remove(path)
        sys.exit("cloud image checksum mismatch")
    return path


def coreos_image():
    stream = json.load(urllib.request.urlopen(STREAM))
    disk = stream["architectures"]["x86_64"]["artifacts"]["qemu"]["formats"]["qcow2.xz"]["disk"]
    packed = f"{CACHE}/{os.path.basename(disk['location'])}"
    path = packed.removesuffix(".xz")
    if not os.path.exists(path):
        fetch(disk["location"], packed)
        if sha256(packed) != disk["sha256"]:
            os.remove(packed)
            sys.exit("CoreOS image checksum mismatch")
        with lzma.open(packed) as src, open(path, "wb") as out:
            shutil.copyfileobj(src, out)
    return path


def ubuntu_image():
    base = "https://cloud-images.ubuntu.com/releases/noble/release/"
    name = "ubuntu-24.04-server-cloudimg-amd64.img"
    path = f"{CACHE}/{name}"
    fetch(base + name, path)
    sums = urllib.request.urlopen(base + "SHA256SUMS").read().decode()
    want = re.search(rf"(\w+) \*{re.escape(name)}", sums).group(1)
    if sha256(path) != want:
        os.remove(path)
        sys.exit("Ubuntu image checksum mismatch")
    return path


class VM:
    def __init__(self, work, name, image, user, ssh_port, extra):
        self.user = user
        self.port = ssh_port
        self.key = f"{work}/id"
        self.log = f"{work}/{name}.log"
        disk = f"{work}/{name}.qcow2"
        subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, disk, "30G"], check=True)
        self.process = subprocess.Popen(
            ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "4096", "-smp", "4",
             "-display", "none", "-serial", f"file:{self.log}",
             "-drive", f"file={disk},if=virtio",
             "-nic", f"user,model=virtio,hostfwd=tcp:127.0.0.1:{ssh_port}-:22", *extra])

    def ssh(self, cmd, timeout=1800):
        argv = ["ssh", "-i", self.key, "-p", str(self.port), "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-o", "ConnectTimeout=5",
                f"{self.user}@127.0.0.1", "sudo sh -s"]
        return subprocess.run(argv, input=cmd, capture_output=True, text=True, timeout=timeout)

    def wait_ssh(self):
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                if self.ssh("true", timeout=15).returncode == 0:
                    return True
            except subprocess.TimeoutExpired:
                pass
            time.sleep(3)
        return False

    def copy(self, src, dst):
        subprocess.run(["scp", "-q", "-i", self.key, "-P", str(self.port), "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                        src, f"{self.user}@127.0.0.1:{dst}"], check=True)

    def stop(self):
        self.process.terminate()
        self.process.wait()


def start_agent(vm, admin, agent_bin, work):
    """Enrolls the agent in the guest and returns its device ID."""
    vm.copy(agent_bin, "/tmp/hauswart-agent")
    # /tmp can be mounted noexec, and SELinux wants a binary below /usr/local.
    vm.ssh("install -m755 /tmp/hauswart-agent /usr/local/bin/hauswart-agent")
    _, token = admin.call("POST", "/api/enroll-tokens")
    enrolled = vm.ssh(token["command"].replace("sudo ", "", 1).replace("hauswart-agent", "/usr/local/bin/hauswart-agent", 1))
    if enrolled.returncode != 0:
        raise RuntimeError(enrolled.stdout + enrolled.stderr)
    started = vm.ssh("systemd-run --unit=hauswart-agent /usr/local/bin/hauswart-agent run")
    if started.returncode != 0:
        raise RuntimeError(started.stderr)
    deadline = time.time() + 30
    while time.time() < deadline:
        _, devices = admin.call("GET", "/api/devices")
        live = [d for d in devices if d["report"].get("distro") and d["id"] not in e2e.seen]
        if live:
            e2e.seen.add(live[0]["id"])
            print(f"       {live[0]['report']['distro']} backends={live[0]['report']['backends']}", flush=True)
            return live[0]["id"]
        time.sleep(1)
    raise RuntimeError("no report: " + vm.ssh("journalctl -u hauswart-agent --no-pager | tail -20").stdout)


def test_flatpak(admin, agent_bin, work, public_key):
    group = "flatpak"
    print("\n== flatpak (Fedora Cloud 44 VM)", flush=True)
    seed = f"{work}/seed"
    os.makedirs(seed)
    with open(f"{seed}/user-data", "w") as f:
        f.write(f"#cloud-config\nusers:\n  - name: fedora\n    sudo: ALL=(ALL) NOPASSWD:ALL\n"
                f"    ssh_authorized_keys:\n      - {public_key}\n")
    with open(f"{seed}/meta-data", "w") as f:
        f.write("instance-id: hauswart\nlocal-hostname: flatpak-vm\n")
    subprocess.run(["xorrisofs", "-quiet", "-output", f"{work}/seed.iso", "-volid", "cidata", "-joliet", "-rock", seed], check=True)
    vm = VM(work, "flatpak", cloud_image(), "fedora", 2231,
            ["-drive", f"file={work}/seed.iso,media=cdrom,readonly=on"])
    try:
        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read())
        installed = vm.ssh("dnf5 install -y flatpak")
        check(group, "flatpak available", installed.returncode == 0, installed.stderr)
        check(group, "no Flathub remote yet", "flathub" not in vm.ssh("flatpak remotes --system").stdout)
        device = start_agent(vm, admin, agent_bin, work)
        task = e2e.run_task(admin, device, "flatpak.install", {"packages": [FLATPAK_APP]}, wait=1500)
        check(group, "flatpak.install", task["status"] == "done", task["output"])
        check(group, "app really installed", FLATPAK_APP in vm.ssh("flatpak list --system --app --columns=application").stdout)
        task = e2e.run_task(admin, device, "flatpak.install", {"packages": [FLATPAK_APP]}, wait=120)
        check(group, "installing again is harmless", task["status"] == "done", task["output"])
    finally:
        vm.stop()


def test_ubuntu(admin, agent_bin, work, public_key):
    """Measures browser trust on Ubuntu, where the browsers are snaps."""
    group = "ubuntu"
    print("\n== ubuntu (Ubuntu 24.04 VM, Firefox and Chromium as snaps)", flush=True)
    seed = f"{work}/seed-ubuntu"
    os.makedirs(seed)
    with open(f"{seed}/user-data", "w") as f:
        f.write(f"#cloud-config\nusers:\n  - name: ubuntu\n    sudo: ALL=(ALL) NOPASSWD:ALL\n"
                f"    shell: /bin/bash\n    ssh_authorized_keys:\n      - {public_key}\n")
    with open(f"{seed}/meta-data", "w") as f:
        f.write("instance-id: hauswart-ubuntu\nlocal-hostname: ubuntu-vm\n")
    subprocess.run(["xorrisofs", "-quiet", "-output", f"{work}/seed-ubuntu.iso", "-volid", "cidata", "-joliet", "-rock", seed], check=True)
    vm = VM(work, "ubuntu", ubuntu_image(), "ubuntu", 2233,
            ["-drive", f"file={work}/seed-ubuntu.iso,media=cdrom,readonly=on"])

    as_user = "sudo -iu ubuntu env XDG_RUNTIME_DIR=/run/user/1000 "
    commands = {
        "firefox": as_user + "sh -c 'rm -rf ~/snap/firefox/common/p; mkdir -p ~/snap/firefox/common/p; timeout 120 "
                   "/snap/bin/firefox --headless --no-remote --profile ~/snap/firefox/common/p --screenshot ~/snap/firefox/common/s.png https://localhost:9443/'",
        "chromium": as_user + "sh -c 'rm -rf ~/snap/chromium/common/p; timeout 120 /snap/bin/chromium --headless --no-sandbox "
                    "--disable-gpu --user-data-dir=$HOME/snap/chromium/common/p --dump-dom https://localhost:9443/'",
    }

    def reached(browser, url="https://localhost:9443/"):
        vm.ssh(": >/tmp/server.log")
        result = vm.ssh(commands[browser].replace("https://localhost:9443/", url), timeout=200)
        hit = "REQUEST" in vm.ssh("cat /tmp/server.log").stdout
        if not hit:
            print(f"       {browser} {url}: rc={result.returncode} {(result.stdout + result.stderr)[-300:]!r}", flush=True)
        return hit

    try:
        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        vm.ssh("cloud-init status --wait; loginctl enable-linger ubuntu")
        print("       network:", vm.ssh("getent hosts api.snapcraft.io; curl -s -o /dev/null -m 20 -w '%{http_code} %{time_total}s' https://api.snapcraft.io/; echo").stdout.strip(), flush=True)
        print("       seeded:", vm.ssh("timeout 120 snap wait system seed.loaded; echo rc=$?; snap changes | tail -4").stdout.strip(), flush=True)
        # --no-wait and a limit, so that a stuck store shows why instead of hanging.
        for snap in ("firefox", "chromium"):
            vm.ssh(f"snap install --no-wait {snap}")
            deadline = time.time() + 600
            while time.time() < deadline and vm.ssh(f"snap list {snap}").returncode != 0:
                if "Error" in vm.ssh("snap changes").stdout:
                    break
                time.sleep(15)
            vm.ssh("snap watch --last=install")
            listed = vm.ssh(f"snap list {snap}")
            check(group, f"{snap} snap installed", listed.returncode == 0,
                  listed.stderr + vm.ssh("snap changes; snap tasks --last=install | tail -12").stdout)
        setup = vm.ssh(browsers.SETUP)
        check(group, "test server prepared", setup.returncode == 0, setup.stderr)
        # systemd-run, because a background process would keep the SSH session open.
        vm.ssh("systemd-run --unit=tls-test sh -c 'python3 -u /srv/tls/server.py >/tmp/server.log 2>&1'; sleep 2; chmod 666 /tmp/server.log")

        for browser in commands:
            check(group, f"{browser} runs (positive control)", reached(browser, "http://localhost:9080/"))
        for browser in commands:
            check(group, f"{browser} blocks without the CA", not reached(browser))
        vm.ssh("cp /srv/tls/ca.pem /usr/local/share/ca-certificates/hauswart-family.crt && update-ca-certificates")
        for browser in commands:
            print(f"       {browser} with system store only: {reached(browser)}", flush=True)
        vm.ssh(browsers.POLICY_UBUNTU)
        for browser in commands:
            check(group, f"{browser} trusts the CA through a policy", reached(browser))
    finally:
        vm.stop()


def test_atomic(admin, agent_bin, work, public_key):
    group = "atomic"
    print("\n== atomic (Fedora CoreOS VM)", flush=True)
    ignition = {
        "ignition": {"version": "3.4.0"},
        "passwd": {"users": [{"name": "core", "sshAuthorizedKeys": [public_key]}]},
        # Automatic updates would compete with the test for the rpm-ostree lock.
        "systemd": {"units": [{"name": "zincati.service", "mask": True}]},
    }
    with open(f"{work}/config.ign", "w") as f:
        json.dump(ignition, f)
    vm = VM(work, "atomic", coreos_image(), "core", 2232,
            ["-fw_cfg", f"name=opt/com.coreos/config,file={work}/config.ign"])
    try:
        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        device = start_agent(vm, admin, agent_bin, work)

        task = e2e.run_task(admin, device, "pkg.install", {"packages": ["tree"]}, wait=900)
        check(group, "pkg.install", task["status"] == "done", task["output"])
        status = vm.ssh("rpm-ostree status --json").stdout
        check(group, "package layered in a deployment", '"tree"' in status, status)
        check(group, "usable without a reboot", vm.ssh("command -v tree").returncode == 0)

        task = e2e.run_task(admin, device, "pkg.install", {"packages": ["tree"]}, wait=300)
        check(group, "installing again is harmless", task["status"] == "done", task["output"])

        vm.ssh("systemctl reboot", timeout=30)
        time.sleep(10)
        check(group, "VM comes back after a reboot", vm.wait_ssh())
        check(group, "package survives the reboot", vm.ssh("command -v tree").returncode == 0)
        vm.ssh("systemd-run --unit=hauswart-agent /usr/local/bin/hauswart-agent run")

        task = e2e.run_task(admin, device, "pkg.remove", {"packages": ["tree"]}, wait=600)
        check(group, "pkg.remove", task["status"] == "done", task["output"])

        task = e2e.run_task(admin, device, "pkg.upgrade", {}, wait=1200)
        check(group, "pkg.upgrade", task["status"] == "done", task["output"])
    finally:
        vm.stop()


def cloud_seed(work, name, public_key):
    """Writes the cloud-init disk for a Fedora Cloud VM and returns its QEMU arguments."""
    seed = f"{work}/seed-{name}"
    os.makedirs(seed)
    with open(f"{seed}/user-data", "w") as f:
        f.write(f"#cloud-config\nusers:\n  - name: fedora\n    sudo: ALL=(ALL) NOPASSWD:ALL\n"
                f"    ssh_authorized_keys:\n      - {public_key}\n")
    with open(f"{seed}/meta-data", "w") as f:
        f.write(f"instance-id: hauswart-{name}\nlocal-hostname: {name}-vm\n")
    subprocess.run(["xorrisofs", "-quiet", "-output", f"{seed}.iso", "-volid", "cidata", "-joliet", "-rock", seed], check=True)
    return ["-drive", f"file={seed}.iso,media=cdrom,readonly=on"]


signing = None


def signing_tool(admin, work):
    """The hauswart-admin tool with a real ssh-agent, logged in once."""
    global signing
    if signing:
        return signing
    signing = e2e.Admin(work, f"{work}/admin-tool")
    command = admin.call("POST", "/api/enroll-tokens")[1]["command"]
    fingerprint = re.search(r"--ca-fingerprint (\w+)", command).group(1)
    done = signing.run("login", "--server", e2e.URL, "--ca-fingerprint", fingerprint, "--user", "admin",
                       input=open(f"{work}/data/initial-admin-password").read())
    if done.returncode != 0:
        raise RuntimeError(done.stderr)
    signing.run("keys", "add", f"{work}/primary.pub", f"{work}/offline.pub")
    return signing


def protected_agent(vm, admin, tool, agent_bin, name):
    """Installs the agent the way the packages do and pins signing keys. Only a
    real service comes back after a reboot."""
    vm.copy(agent_bin, "/tmp/hauswart-agent")
    vm.copy(f"{ROOT}/packaging/systemd/hauswart-agent.service", "/tmp/hauswart-agent.service")
    vm.ssh("install -m755 /tmp/hauswart-agent /usr/bin/hauswart-agent && "
           "install -m644 /tmp/hauswart-agent.service /usr/lib/systemd/system/hauswart-agent.service && "
           "restorecon /usr/bin/hauswart-agent /usr/lib/systemd/system/hauswart-agent.service; systemctl daemon-reload")
    command = tool.run("enroll-command").stdout.strip().replace("sudo ", "", 1).replace(e2e.URL, GUEST_URL)
    enrolled = vm.ssh(command)
    if enrolled.returncode != 0:
        raise RuntimeError(enrolled.stdout + enrolled.stderr)
    device = re.search(r"Device ID: (\w+)", enrolled.stdout).group(1)
    tool.run("name", device, name)
    started = vm.ssh("systemctl enable --now hauswart-agent")
    if started.returncode != 0:
        raise RuntimeError(started.stderr)
    deadline = time.time() + 60
    while time.time() < deadline:
        if report_of(admin, device).get("protected"):
            return device
        time.sleep(1)
    raise RuntimeError("no report: " + vm.ssh("journalctl -u hauswart-agent --no-pager | tail -20").stdout)


def report_of(admin, device):
    _, devices = admin.call("GET", "/api/devices")
    return next((d["report"] for d in devices if d["id"] == device), {})


def signed_task(admin, tool, device, task_type, payload, wait=60):
    code, out = admin.call("POST", f"/api/devices/{device}/tasks", {"type": task_type, "payload": payload})
    if code != 201:
        return {"id": "", "status": "rejected", "output": str(out)}, ""
    shown = tool.run("approve", input="y\n")
    task = e2e.wait_task(admin, out["id"], wait)
    return task, shown.stdout


def attack(admin, work, device, task_type, payload, signed=""):
    """A compromised server, which writes to its database directly."""
    task_id = f"attack-{time.time_ns()}"
    with sqlite3.connect(f"{work}/data/hauswart.db", timeout=10) as db:
        db.execute("INSERT INTO tasks (id, device_id, type, payload, status, signed, created_by, created_at) "
                   "VALUES (?,?,?,?,'pending',?,'attacker',?)",
                   (task_id, device, task_type, json.dumps(payload), signed, int(time.time())))
    return e2e.wait_task(admin, task_id, 60)


def valid_for(minutes=30):
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes)).isoformat()


def test_power(admin, agent_bin, work, public_key):
    """Signed reboot and shutdown of a protected device, on a real kernel."""
    group = "power"
    print("\n== power (Fedora Cloud 44 VM, protected device, agent as a service)", flush=True)
    tool = signing_tool(admin, work)
    vm = VM(work, "power", cloud_image(), "fedora", 2234, cloud_seed(work, "power", public_key))

    def boot_id():
        return vm.ssh("cat /proc/sys/kernel/random/boot_id").stdout.strip()

    def scheduled():
        return vm.ssh("cat /run/systemd/shutdown/scheduled 2>/dev/null").stdout

    try:
        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        vm.ssh("cloud-init status --wait; useradd anna; groupadd media")
        device = protected_agent(vm, admin, tool, agent_bin, "power-vm")
        first_boot = boot_id()

        for task_type in ("power.reboot", "power.shutdown"):
            task = attack(admin, work, device, task_type, {"delay_minutes": 1, "expires_at": valid_for()})
            check(group, f"ATTACK unsigned {task_type} refused", task["status"] == "failed" and "signature" in task["output"], task["output"])
        check(group, "nothing was scheduled", scheduled() == "")

        # Ten minutes, because logind stops new logins, and with them this
        # test's SSH, for the last five.
        task, shown = signed_task(admin, tool, device, "power.reboot",
                                  {"delay_minutes": 10, "message": "Kernel-Update", "expires_at": valid_for()})
        check(group, "approve spells out the restart", "RESTART THIS DEVICE in 10 minute(s)" in shown and "Kernel-Update" in shown, shown)
        check(group, "signed reboot is scheduled", task["status"] == "done" and "restart scheduled in 10" in task["output"], task["output"])
        pending = scheduled()
        check(group, "logind holds the reboot", "MODE=reboot" in pending, pending)
        check(group, "the warning carries the fixed prefix and the text",
              "Hauswart: this device will restart in 10 minute(s). Kernel-Update" in pending.replace("\\x20", " "), pending)
        task = e2e.run_task(admin, device, "power.cancel", {}, wait=60)
        check(group, "cancel works without a signature", task["status"] == "done" and "cancelled" in task["output"], task["output"])
        check(group, "the reboot is gone", scheduled() == "")
        task = e2e.run_task(admin, device, "power.cancel", {}, wait=60)
        check(group, "cancelling again says so", "nothing was scheduled" in task["output"], task["output"])

        # A short delay that really runs out, cancelled in time.
        task, _ = signed_task(admin, tool, device, "power.reboot", {"delay_minutes": 1, "expires_at": valid_for()})
        check(group, "reboot in a minute is scheduled", task["status"] == "done", task["output"])
        task = e2e.run_task(admin, device, "power.cancel", {}, wait=30)
        check(group, "cancelled in time", "cancelled" in task["output"], task["output"])
        time.sleep(75)
        check(group, "no reboot happened after the minute", boot_id() == first_boot)

        # The server forgets a signature once the task is done, so an attacker
        # has to catch it on the way. The paused agent gives the time for that.
        vm.ssh("systemctl kill -s STOP hauswart-agent")
        code, out = admin.call("POST", f"/api/devices/{device}/tasks",
                               {"type": "power.reboot", "payload": {"delay_minutes": 1, "expires_at": valid_for()}})
        tool.run("approve", input="y\n")
        with sqlite3.connect(f"{work}/data/hauswart.db", timeout=10) as db:
            captured = db.execute("SELECT signed FROM tasks WHERE id = ?", (out["id"],)).fetchone()[0]
        check(group, "signature captured", captured != "")
        vm.ssh("systemctl kill -s CONT hauswart-agent")
        task = e2e.wait_task(admin, out["id"], 60)
        check(group, "agent reports before it goes down", task["status"] == "done", task["output"])
        down = False
        deadline = time.time() + 150
        while time.time() < deadline and not down:
            try:
                down = vm.ssh("true", timeout=8).returncode != 0
            except subprocess.TimeoutExpired:
                down = True
            time.sleep(3)
        check(group, "device goes down", down)
        time.sleep(10)
        check(group, "VM comes back", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        second_boot = boot_id()
        check(group, "it really restarted", second_boot and second_boot != first_boot, second_boot)
        running = vm.ssh("systemctl is-active hauswart-agent").stdout.strip()
        check(group, "agent service is back", running == "active",
              running + vm.ssh("journalctl -u hauswart-agent -b --no-pager | tail -20").stdout)
        deadline = time.time() + 120
        report = {}
        while time.time() < deadline:
            report = report_of(admin, device)
            if report.get("uptime_s", 1 << 30) < 300:
                break
            time.sleep(2)
        check(group, "agent reports again after the reboot", report.get("uptime_s", 1 << 30) < 300, str(report))

        task = attack(admin, work, device, "power.reboot", {}, captured)
        check(group, "ATTACK replay of the signed reboot refused after the restart",
              task["status"] == "failed" and "counter" in task["output"], task["output"])
        check(group, "the replay scheduled nothing", scheduled() == "")
        task, _ = signed_task(admin, tool, device, "group.add", {"user": "anna", "group": "media"})
        check(group, "signed tasks still work after the reboot", task["status"] == "done", task["output"])

        task, shown = signed_task(admin, tool, device, "power.shutdown", {"delay_minutes": 1, "expires_at": valid_for()})
        check(group, "approve spells out the shutdown", "SHUT DOWN THIS DEVICE" in shown, shown)
        check(group, "signed shutdown is scheduled", task["status"] == "done", task["output"])
        try:
            code = vm.process.wait(timeout=180)
        except subprocess.TimeoutExpired:
            code = None
        check(group, "the machine powers off", code == 0, str(code))
    finally:
        vm.stop()


GDM_CONFIG = """[daemon]
AutomaticLoginEnable=True
AutomaticLogin=anna
"""
GNOME_PACKAGES = "gdm gnome-shell gnome-session-wayland-session gnome-settings-daemon mesa-dri-drivers dbus-tools kernel-modules"


def screendump(monitor, path):
    """Saves what the VM's screen shows, through the QEMU monitor."""
    with socket.socket(socket.AF_UNIX) as conn:
        conn.connect(monitor)
        conn.sendall(f"screendump {path} -f png\n".encode())
        time.sleep(0.5)
    deadline = time.time() + 5
    while time.time() < deadline and not os.path.exists(path):
        time.sleep(0.1)


def clear_banner(monitor):
    """GNOME keeps a banner up while nobody touches the machine, and queues what
    comes next. A few key presses count as somebody being there."""
    for _ in range(12):
        with socket.socket(socket.AF_UNIX) as conn:
            conn.connect(monitor)
            conn.sendall(b"sendkey shift\n")
            time.sleep(0.2)
        time.sleep(1)


def test_desktop(admin, agent_bin, work, public_key):
    """Popups in a real GNOME session on Wayland, on a protected device."""
    group = "desktop"
    print("\n== desktop (Fedora Cloud 44 VM with GNOME on Wayland, automatic login)", flush=True)
    tool = signing_tool(admin, work)
    shots = os.environ.get("VM_SHOTS", work)
    os.makedirs(shots, exist_ok=True)
    monitor = f"{work}/monitor"
    vm = VM(work, "desktop", cloud_image(), "fedora", 2235,
            [*cloud_seed(work, "desktop", public_key), "-vga", "virtio",
             "-monitor", f"unix:{monitor},server,nowait"])
    bus = "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u anna)/bus"

    def monitor_log():
        return vm.ssh("cat /tmp/notifications.log").stdout

    try:
        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        vm.ssh("cloud-init status --wait; useradd anna")
        installed = vm.ssh(f"dnf5 install -y --setopt=install_weak_deps=False {GNOME_PACKAGES}", timeout=1500)
        check(group, "GNOME installed", installed.returncode == 0, installed.stderr[-800:])
        vm.ssh(f"cat >/etc/gdm/custom.conf <<'CONF'\n{GDM_CONFIG}CONF\nsystemctl set-default graphical.target; systemctl enable gdm")
        vm.ssh("systemctl reboot", timeout=30)
        time.sleep(15)
        check(group, "VM comes back with a desktop", vm.wait_ssh())
        session = ""
        deadline = time.time() + 180
        while time.time() < deadline and "Type=wayland" not in session:
            sessions = vm.ssh("loginctl list-sessions --no-legend | awk '$3 == \"anna\" {print $1}'").stdout.split()
            session = vm.ssh("".join(f"loginctl show-session {s} -p Type -p Class -p State; " for s in sessions)).stdout
            time.sleep(3)
        check(group, "anna has a Wayland session", "Type=wayland" in session,
              session + vm.ssh("loginctl list-sessions; journalctl -b -u gdm --no-pager | tail -15").stdout)
        time.sleep(20)  # the shell needs a moment before it owns the service
        owner = vm.ssh(f"runuser -u anna -- env {bus} busctl --user status org.freedesktop.Notifications | grep -E '^(Comm|Exe)='").stdout
        # GNOME answers through a small gjs service, which passes it to the shell.
        check(group, "GNOME runs the notification service", "gnome-shell" in owner or "Comm=gjs" in owner, owner)

        device = protected_agent(vm, admin, tool, agent_bin, "desktop-vm")
        vm.ssh(f"systemd-run --unit=notifications --uid=anna --setenv={bus.replace('$(id -u anna)', vm.ssh('id -u anna').stdout.strip())} "
               "sh -c \"exec dbus-monitor --session \\\"interface='org.freedesktop.Notifications',member='Notify'\\\" >/tmp/notifications.log\"")
        time.sleep(2)
        screendump(monitor, f"{shots}/desktop-before.png")

        task = attack(admin, work, device, "notify.send", {"message": "Your password expired", "expires_at": valid_for()})
        check(group, "ATTACK unsigned popup refused", task["status"] == "failed" and "signature" in task["output"], task["output"])
        check(group, "and nothing was shown", "password expired" not in monitor_log())

        text = 'Abendessen um 18 Uhr <b>heute</b> & "pünktlich"'
        task, shown = signed_task(admin, tool, device, "notify.send", {"message": text, "expires_at": valid_for()})
        screendump(monitor, f"{shots}/desktop-popup.png")
        check(group, "approve shows title and text", 'titled "Hauswart"' in shown and text in shown, shown)
        check(group, "popup task reports anna", task["status"] == "done" and "popup shown to anna" in task["output"], task["output"])
        log = monitor_log()
        check(group, "notification reached the session bus", "Abendessen um 18 Uhr" in log, log)
        check(group, "markup arrives escaped", "&lt;b&gt;heute&lt;/b&gt; &amp;" in log and "<b>" not in log, log)
        check(group, "title and app are fixed", log.count('string "Hauswart"') >= 2, log)
        before = open(f"{shots}/desktop-before.png", "rb").read()
        after = open(f"{shots}/desktop-popup.png", "rb").read()
        check(group, "the screen changed", before != after)

        task, _ = signed_task(admin, tool, device, "notify.send", {"message": "-h --help", "user": "anna", "expires_at": valid_for()})
        check(group, "a text like an option is only text", task["status"] == "done" and "-h --help" in monitor_log(), task["output"])
        task, _ = signed_task(admin, tool, device, "notify.send", {"message": "Hallo", "user": "fedora", "expires_at": valid_for()})
        check(group, "a user without a desktop is reported", task["status"] == "failed" and "nobody" in task["output"], task["output"])

        clear_banner(monitor)
        screendump(monitor, f"{shots}/desktop-clear.png")
        clear = open(f"{shots}/desktop-clear.png", "rb").read()
        check(group, "the first banner went away", clear != after)
        task, _ = signed_task(admin, tool, device, "power.reboot", {"delay_minutes": 10, "expires_at": valid_for()})
        time.sleep(2)
        screendump(monitor, f"{shots}/desktop-reboot-warning.png")
        check(group, "reboot warns the desktop", "popup shown to anna" in task["output"] and "will restart in 10 minute" in monitor_log(), task["output"])
        warning = open(f"{shots}/desktop-reboot-warning.png", "rb").read()
        check(group, "the warning is on the screen", warning not in (clear, after))
        task = e2e.run_task(admin, device, "power.cancel", {}, wait=60)
        screendump(monitor, f"{shots}/desktop-cancelled.png")
        check(group, "cancelling tells the desktop", "popup shown to anna" in task["output"] and "was cancelled" in monitor_log(), task["output"])
    finally:
        vm.stop()


def main():
    names = sys.argv[1:] or ["flatpak", "atomic", "ubuntu", "power", "desktop"]
    os.makedirs(CACHE, exist_ok=True)
    work = tempfile.mkdtemp(prefix="hauswart-vm-", dir=os.environ.get("E2E_TMP"))
    env = {**os.environ, "CGO_ENABLED": "0"}
    for binary in ("server", "agent"):
        subprocess.run(["go", "build", "-o", f"{work}/{binary}", f"./cmd/hauswart-{binary}"], cwd=ROOT, env=env, check=True)
    subprocess.run(["go", "build", "-o", f"{work}/admin-tool", "./cmd/hauswart-admin"], cwd=ROOT, env=env, check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{work}/id"], check=True)
    public_key = open(f"{work}/id.pub").read().strip()

    e2e.URL = f"https://localhost:{PORT}"
    log_path = f"{work}/server.log"
    with open(log_path, "w") as log:
        server = subprocess.Popen(
            [f"{work}/server", "-addr", f"127.0.0.1:{PORT}", "-data", f"{work}/data", "-url", GUEST_URL],
            stderr=log, stdout=log)
    try:
        for _ in range(50):
            if "listening" in open(log_path).read():
                break
            time.sleep(0.2)
        password = open(f"{work}/data/initial-admin-password").read().strip()
        admin = e2e.Client(f"{work}/data/pki/ca.pem")
        code, _ = admin.call("POST", "/api/login", {"username": "admin", "password": password})
        assert code == 200, code
        for name in names:
            tests = {"flatpak": test_flatpak, "atomic": test_atomic, "ubuntu": test_ubuntu,
                     "power": test_power, "desktop": test_desktop}
            tests[name](admin, f"{work}/agent", work, public_key)
    finally:
        if signing:
            signing.close()
        server.terminate()
        server.wait()
        shutil.rmtree(work, ignore_errors=True)

    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    for group, name, _ in failed:
        print(f"  FAILED {group}: {name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
