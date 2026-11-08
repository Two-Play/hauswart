#!/usr/bin/env python3
"""Runs what containers cannot, in real virtual machines: Flatpak, rpm-ostree,
real reboots and popups in a real desktop session.

The server runs on the host. Guests reach it through QEMU's user networking at
10.0.2.2, so this needs no root and touches nothing on the host but a cache
directory. Usage: test/vm.py [flatpak atomic ubuntu power desktop screentime kde atomic-policy directory directory-debian gui-kde gui-gnome apps-kde apps-gnome apps-debian]
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
import authentik  # noqa: E402
import browsers  # noqa: E402
import e2e  # noqa: E402

PORT = int(os.environ.get("VM_PORT", "18450"))
# Added to every SSH port, so that tests can run next to each other.
SSH_OFFSET = int(os.environ.get("VM_SSH_OFFSET", "0"))
LDAPS_PORT = 16636
CLOUD_PORT, CLOUD_HTTP_PORT = 16443, 18080
NEXTCLOUD_IMAGE = "docker.io/library/nextcloud:stable-apache"
GUEST_URL = f"https://10.0.2.2:{PORT}"
ROOT = e2e.ROOT
CACHE = os.environ.get("VM_CACHE", os.path.expanduser("~/.cache/hauswart-vm"))

STREAM_BUILDS = "https://builds.coreos.fedoraproject.org/prod/streams/stable/builds"
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
    part = f"{path}.{os.getpid()}.part"  # another run may fetch the same file
    with urllib.request.urlopen(url) as resp, open(part, "wb") as out:
        shutil.copyfileobj(resp, out)
    os.rename(part, path)


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


def previous_coreos_image():
    """The build before the current one, so that a real update is pending."""
    builds = f"{STREAM_BUILDS}/builds.json"
    build = json.load(urllib.request.urlopen(builds))["builds"][1]["id"]
    meta = json.load(urllib.request.urlopen(f"{STREAM_BUILDS}/{build}/x86_64/meta.json"))
    disk = meta["images"]["qemu"]
    packed = f"{CACHE}/{disk['path']}"
    path = packed.removesuffix(".xz")
    if not os.path.exists(path):
        fetch(f"{STREAM_BUILDS}/{build}/x86_64/{disk['path']}", packed)
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


def debian_image():
    # Not the genericcloud image: its kernel has no SMB client.
    base = "https://cloud.debian.org/images/cloud/trixie/latest/"
    name = "debian-13-generic-amd64.qcow2"
    path = f"{CACHE}/{name}"
    fetch(base + name, path)
    sums = urllib.request.urlopen(base + "SHA512SUMS").read().decode()
    want = re.search(rf"(\w+)\s+{re.escape(name)}", sums).group(1)
    digest = hashlib.sha512()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != want:
        os.remove(path)
        sys.exit("Debian image checksum mismatch")
    return path


class VM:
    def __init__(self, work, name, image, user, ssh_port, extra, display="none"):
        self.user = user
        ssh_port += SSH_OFFSET
        self.port = ssh_port
        self.key = f"{work}/id"
        self.log = f"{work}/{name}.log"
        disk = f"{work}/{name}.qcow2"
        if not os.path.exists(disk):  # the playground keeps its disk between runs
            subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", image, disk, "30G"], check=True)
        self.process = subprocess.Popen(
            ["qemu-system-x86_64", "-enable-kvm", "-cpu", "host", "-m", "4096", "-smp", "4",
             "-display", display, "-serial", f"file:{self.log}",
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
        check(group, "the Flatpak is in the inventory", wait_for(lambda: FLATPAK_APP in e2e.inventory_names(admin, device), 150))
    finally:
        vm.stop()


def test_inventory(admin, agent_bin, work, public_key):
    group = "inventory"
    print("\n== inventory (Fedora Cloud 44 VM with made-up hardware)", flush=True)
    smbios = "type=1,manufacturer=Hauswart Test,product=Box 7,serial=HW-0042"
    vm = VM(work, group, cloud_image(), "fedora", 2247, [*cloud_seed(work, group, public_key), "-smbios", smbios])
    try:
        check(group, "VM boots", vm.wait_ssh())
        vm.ssh("dnf5 install -y firewalld; systemctl disable --now firewalld", timeout=600)
        device = start_agent(vm, admin, agent_bin, work)

        def entry():
            return admin.call("GET", f"/api/inventory/{device}")[1]
        check(group, "the inventory arrives", wait_for(lambda: entry().get("inventory"), 150), str(entry())[:300])
        inventory = entry()["inventory"]
        hardware = inventory["hardware"]
        check(group, "the hardware is the real one", (hardware.get("vendor"), hardware.get("model"), hardware.get("serial")) == ("Hauswart Test", "Box 7", "HW-0042"), str(hardware))
        check(group, "the processor is named", hardware.get("cpu"), str(hardware))
        check(group, "the disk is there", any(d["size"] > 10 << 30 for d in inventory.get("disks", [])), str(inventory.get("disks")))
        cards = inventory.get("network", [])
        check(group, "the network card is there", any(c.get("mac", "").startswith("52:54:00") and "10.0.2.15" in c.get("addresses", []) for c in cards), str(cards))
        check(group, "without a policy too, the disk counts as unencrypted", inventory["security"].get("disk_encryption") == "off", str(inventory["security"]))
        check(group, "a stopped firewall shows as off", inventory["security"].get("firewall") == "off", str(inventory["security"]))
        check(group, "and asking does not start it", vm.ssh("systemctl is-active firewalld").stdout.strip() != "active")
        count = int(vm.ssh("rpm -qa | sort -u | wc -l").stdout.strip())
        check(group, "the whole package list arrives", abs(inventory["package_count"] - count) < 5, f'{inventory["package_count"]} of {count}')
        check(group, "and says how fresh it is", inventory.get("updated_at", 0) > 0, str(inventory)[:200])

        csv_data = vm_csv(admin)
        check(group, "the export has the serial number", "HW-0042" in csv_data, csv_data[:300])
    finally:
        vm.stop()


def vm_csv(admin):
    with admin.opener.open(f"{e2e.URL}/api/inventory.csv", timeout=40) as response:
        return response.read().decode()


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
    vm = VM(work, "atomic", previous_coreos_image(), "core", 2232,
            ["-fw_cfg", f"name=opt/com.coreos/config,file={work}/config.ign"])
    try:
        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        device = start_agent(vm, admin, agent_bin, work)

        report = e2e.wait_report(admin, device, lambda r: "updates" in r, 420)
        updates = (report or {}).get("updates", {})
        print(f"       updates={updates}", flush=True)
        check(group, "update check on rpm-ostree", updates.get("checked_at") and not updates.get("error"), str(updates))
        check(group, "booted deployment needs no reboot", updates.get("reboot") == "not_required", str(updates))
        check(group, "newer image counts as pending", updates.get("pending") == 1 and updates.get("packages"), str(updates))

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
        report = e2e.wait_report(admin, device, lambda r: r.get("updates", {}).get("reboot") == "required", 420)
        check(group, "staged deployment asks for a reboot", report, str(e2e.last_report(admin, device).get("updates")))
        check(group, "nothing pending after the upgrade", report and report["updates"]["pending"] == 0, str(report))
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


# A hand picked set starts a session that is not a working desktop.
KDE_PACKAGES = "@kde-desktop mesa-dri-drivers dbus-tools kernel-modules"
SDDM_CONFIG = """[Autologin]
User=anna
Session=plasma
"""


def desktop_session(vm, group, kde):
    """Brings up a real desktop with automatic login for anna."""
    check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
    vm.ssh("cloud-init status --wait; useradd anna")
    packages = KDE_PACKAGES if kde else GNOME_PACKAGES
    weak = "" if kde else "--setopt=install_weak_deps=False"
    installed = vm.ssh(f"dnf5 install -y {weak} {packages} firewalld", timeout=2400)
    check(group, "desktop installed", installed.returncode == 0, installed.stderr[-800:])
    if kde:
        vm.ssh(f"mkdir -p /etc/sddm.conf.d; cat >/etc/sddm.conf.d/autologin.conf <<'CONF'\n{SDDM_CONFIG}CONF\n"
               "systemctl set-default graphical.target")
        # Fedora starts a first run wizard under its own user, and its own login
        # manager, instead of the configured automatic login.
        vm.ssh("dnf5 remove -y plasma-setup; dnf5 install -y sddm; systemctl disable plasmalogin; systemctl enable --force sddm", timeout=600)
    else:
        vm.ssh(f"cat >/etc/gdm/custom.conf <<'CONF'\n{GDM_CONFIG}CONF\nsystemctl set-default graphical.target; systemctl enable gdm")
    vm.ssh("systemctl disable --now firewalld")
    vm.ssh("systemctl reboot", timeout=30)
    time.sleep(15)
    check(group, "VM comes back with a desktop", vm.wait_ssh())
    return "sddm" if kde else "gdm"


def graphical_session(vm):
    """The ID of anna's graphical session, or an empty string."""
    ids = vm.ssh("loginctl list-sessions --no-legend | awk '$3 == \"anna\" {print $1}'").stdout.split()
    for session in ids:
        shown = vm.ssh(f"loginctl show-session {session} -p Type").stdout
        if "wayland" in shown or "x11" in shown:
            return session
    return ""


def midday():
    """A fixed zone where it is around noon, so that no test reaches midnight."""
    now = datetime.now(timezone.utc)
    hours = 12 - now.hour
    if hours > 12:
        hours -= 24
    # The sign of these names is the other way around.
    return f"Etc/GMT{-hours:+d}" if hours else "UTC", now + timedelta(hours=hours)


def wait_for(condition, wait=180, step=3):
    deadline = time.time() + wait
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(step)
    return False


def test_atomic_policy(admin, agent_bin, work, public_key):
    """A policy on rpm-ostree: layering a package and an update window."""
    group = "atomic-policy"
    print("\n== atomic-policy (Fedora CoreOS VM)", flush=True)
    tool = signing_tool(admin, work)
    ignition = {
        "ignition": {"version": "3.4.0"},
        "passwd": {"users": [{"name": "core", "sshAuthorizedKeys": [public_key]}]},
        "systemd": {"units": [{"name": "zincati.service", "mask": True}]},
    }
    with open(f"{work}/config-policy.ign", "w") as f:
        json.dump(ignition, f)
    vm = VM(work, group, previous_coreos_image(), "core", 2238,
            ["-fw_cfg", f"name=opt/com.coreos/config,file={work}/config-policy.ign"])
    try:
        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        vm.copy(agent_bin, "/tmp/hauswart-agent")
        vm.ssh("install -m755 /tmp/hauswart-agent /usr/local/bin/hauswart-agent")
        command = tool.run("enroll-command").stdout.strip().replace("sudo ", "", 1).replace(e2e.URL, GUEST_URL)
        command = command.replace("hauswart-agent", "/usr/local/bin/hauswart-agent", 1)
        enrolled = vm.ssh(command)
        check(group, "enrollment", enrolled.returncode == 0, enrolled.stdout + enrolled.stderr)
        device = re.search(r"Device ID: (\w+)", enrolled.stdout).group(1)
        tool.run("name", device, group)
        vm.ssh("systemd-run --unit=hauswart-agent /usr/local/bin/hauswart-agent run")
        check(group, "device reports protection", wait_for(lambda: report_of(admin, device).get("protected"), 60, 1))
        report = e2e.wait_report(admin, device, lambda r: r.get("updates", {}).get("pending"), 420)
        check(group, "a newer image is pending", report, str(report_of(admin, device).get("updates")))

        code, out = admin.call("POST", "/api/groups", {"name": group})
        path = f"/api/groups/{out['id']}"
        admin.call("PUT", f"{path}/devices", {"devices": [device]})
        zone, now = midday()
        window = {"days": [now.strftime("%a").lower()], "start": "00:00", "end": "24:00"}
        policy = {"required_packages": ["tree"], "time_zone": zone, "updates": {"window": window, "reboot": "never"}}
        code, out = admin.call("PUT", f"{path}/policy", policy)
        check(group, "policy saved", code == 204, out)
        shown = tool.run("approve", input="y\n")
        check(group, "approve signs", "Signed." in shown.stdout, shown.stdout + shown.stderr)

        check(group, "required package is layered", wait_for(lambda: vm.ssh("command -v tree").returncode == 0, 900, 10),
              vm.ssh("journalctl -u hauswart-agent --no-pager | tail -20").stdout)
        report = e2e.wait_report(admin, device, lambda r: r.get("updates", {}).get("reboot") == "required", 1200)
        check(group, "the window stages the update", report, str(report_of(admin, device).get("updates")))
        check(group, "the rule keeps the device from rebooting", vm.ssh("test -e /run/systemd/shutdown/scheduled").returncode != 0)

        def state():
            view = admin.call("GET", f"{path}/policy")[1]
            return view["devices"][0]
        check(group, "the dashboard says up to date", wait_for(lambda: state()["state"] == "current", 150), str(state()))
    finally:
        vm.stop()


def sh_logs():
    return subprocess.run(["podman", "logs", "--tail", "12", authentik.CONTAINERS[3]], capture_output=True, text=True).stderr[-1800:]


def test_directory(admin, agent_bin, work, public_key, debian=False):
    """Accounts from a real Authentik log in on a real device, also offline."""
    group = "directory-debian" if debian else "directory"
    print(f"\n== {group} ({'Debian 13' if debian else 'Fedora Cloud 44'} VM, SSSD, Authentik {authentik.VERSION} LDAP outpost)", flush=True)
    tool = signing_tool(admin, work)
    stack = authentik.Authentik()
    proxy = None
    vm = VM(work, group, debian_image() if debian else cloud_image(), "fedora", 2239, cloud_seed(work, group, public_key))
    password = authentik.PASSWORD

    def pam(user, secret):
        return vm.ssh(f"printf '%s\\n' '{secret}' | pamtester login {user} authenticate")

    def start_proxy():
        return subprocess.Popen(["socat", f"OPENSSL-LISTEN:{LDAPS_PORT},reuseaddr,fork,cert={work}/ldap.pem,key={work}/ldap.key,verify=0",
                                 f"TCP:127.0.0.1:{authentik.LDAP_PORT}"], stderr=subprocess.DEVNULL)

    try:
        stack.start()
        check(group, "Authentik is up", True)
        base_dn = stack.ldap_outpost()
        admins = stack.pk("core/groups/", "authentik Admins")
        stack.user("ldapreader", [admins])
        stack.user("lena")
        stack.user("fedora")  # named like the local account with sudo
        # A CA of its own, as the one of the Hauswart server must not vouch for this.
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30", "-subj", "/CN=ldap.home.test",
                        "-addext", "subjectAltName=DNS:ldap.home.test", "-addext", "basicConstraints=critical,CA:TRUE",
                        "-keyout", f"{work}/ldap.key", "-out", f"{work}/ldap.pem"], check=True, capture_output=True)
        proxy = start_proxy()

        check(group, "VM boots", vm.wait_ssh(), open(vm.log, errors="replace").read()[-1500:])
        vm.ssh("cloud-init status --wait; echo '10.0.2.2 ldap.home.test' >>/etc/hosts")
        # The lists go again afterwards: a fresh device has none, and the agent has to cope.
        installed = vm.ssh("apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q pamtester sudo && rm -rf /var/lib/apt/lists/*"
                           if debian else "dnf5 install -y pamtester authselect", timeout=900)
        check(group, "test tools installed", installed.returncode == 0, installed.stderr[-500:])
        device = protected_agent(vm, admin, tool, agent_bin, group)

        code, out = admin.call("POST", "/api/groups", {"name": group})
        path = f"/api/groups/{out['id']}"
        admin.call("PUT", f"{path}/devices", {"devices": [device]})
        ca = open(f"{work}/data/pki/ca.pem").read()
        policy = {
            "cas": [{"name": "home", "pem": ca}],
            "directory": {"uri": f"ldaps://ldap.home.test:{LDAPS_PORT}", "base_dn": base_dn,
                          "bind_dn": f"cn=ldapreader,ou=users,{base_dn}", "bind_password": password,
                          "ca": open(f"{work}/ldap.pem").read()},
        }
        code, out = admin.call("PUT", f"{path}/policy", policy)
        check(group, "policy saved", code == 204, out)
        shown = tool.run("approve", input="y\n")
        check(group, "the directory is shown before signing", "ACCOUNTS FROM ldaps://ldap.home.test" in shown.stdout, shown.stdout + shown.stderr)
        check(group, "and its password is not", password not in shown.stdout, shown.stdout)

        def state():
            return admin.call("GET", f"{path}/policy")[1]["devices"][0]
        applied = wait_for(lambda: state()["state"] == "current" and state().get("checks", {}).get("directory") == "on", 240, 5)
        print("       " + str(state())[:700], flush=True)
        check(group, "the device applies it", applied, vm.ssh("journalctl -u hauswart-agent --no-pager | tail -5").stdout)
        known = wait_for(lambda: vm.ssh("getent passwd lena").returncode == 0, 60)
        if not known:
            print(vm.ssh(f"echo | timeout 10 openssl s_client -connect ldap.home.test:{LDAPS_PORT} 2>&1 | grep -E 'Verif|verify|CONNECTED|errno|alert' | head -8; " +
                         ("apt-get install -q -y ldap-utils >/dev/null 2>&1; " if debian else "dnf5 install -q -y openldap-clients >/dev/null 2>&1; ") +
                         f"LDAPTLS_REQCERT=demand ldapsearch -LLL -H ldaps://ldap.home.test:{LDAPS_PORT} -x -D 'cn=ldapreader,ou=users,{base_dn}' "
                         f"-w '{password}' -b '{base_dn}' '(cn=lena)' 2>&1 | head -30; "
                         "grep -E '\\(0x00[1-8]0\\)' /var/log/sssd/sssd_hauswart.log | cut -c1-220 | tail -25").stdout[-5000:], flush=True)
            print(sh_logs(), flush=True)
        check(group, "a directory account is known", known)
        print("       " + vm.ssh("getent passwd lena").stdout.strip(), flush=True)
        check(group, "the password from Authentik works", pam("lena", password).returncode == 0,
              pam("lena", password).stderr + vm.ssh("tail -15 /var/log/sssd/sssd_hauswart.log").stdout)
        check(group, "a wrong password does not", pam("lena", "wrong-password").returncode != 0)
        check(group, "ATTACK a directory account named like a local one gets nothing", pam("fedora", password).returncode != 0,
              pam("fedora", password).stdout + vm.ssh("grep filter_users /etc/sssd/conf.d/hauswart.conf").stdout)
        check(group, "the local account keeps its own ID", vm.ssh("id -u fedora").stdout.strip() == "1000", vm.ssh("getent passwd fedora").stdout)
        check(group, "the local account still works", vm.ssh("id -un").stdout.strip() == "root" or vm.ssh("true").returncode == 0)

        task, _ = signed_task(admin, tool, device, "sudo.grant", {"user": "lena", "expires_at": valid_for(30)})
        check(group, "the agent knows directory accounts", task["status"] == "done", task["output"])
        task = e2e.run_task(admin, device, "sudo.revoke", {"user": "lena"}, wait=60)
        check(group, "and can take the right back", task["status"] == "done", task["output"])

        # A share with the same password, and one that is out of reach.
        prepared = vm.ssh(("DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends samba sssd-tools; " if debian else
                           "dnf5 install -y samba kernel-modules-core-$(uname -r) && setenforce 0; ") + "modprobe cifs; "
                          "mkdir -p /srv/family && echo hello >/srv/family/hello.txt && chown -R lena /srv/family && "
                          "printf '[family]\\npath = /srv/family\\nread only = no\\n' >>/etc/samba/smb.conf && "
                          f"printf '%s\\n%s\\n' '{password}' '{password}' | smbpasswd -s -a lena && systemctl restart {'smbd' if debian else 'smb'} && "
                          "sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* ; "
                          "printf 'PasswordAuthentication yes\\nKbdInteractiveAuthentication yes\\n' >/etc/ssh/sshd_config.d/00-test.conf; systemctl restart ssh || systemctl restart sshd", timeout=900)
        check(group, "Samba runs", prepared.returncode == 0, prepared.stdout[-400:] + prepared.stderr[-400:])
        policy["mounts"] = [{"server": "127.0.0.1", "share": "family", "folder": "Family"}]
        admin.call("PUT", f"{path}/policy", policy)
        tool.run("approve", input="y\n")
        check(group, "the share is set up", wait_for(lambda: state()["state"] == "current" and "family" in vm.ssh("cat /etc/security/pam_mount.conf.xml").stdout
                       and vm.ssh("grep -q pam_mount /etc/pam.d/common-auth || grep -q pam_mount /etc/pam.d/password-auth").returncode == 0, 300, 5),
              str(state()) + vm.ssh("ls -la /etc/security/pam_mount.conf.xml").stdout)
        askpass = f"{work}/askpass"
        with open(askpass, "w") as f:
            f.write(f"#!/bin/sh\necho '{password}'\n")
        os.chmod(askpass, 0o700)

        def as_lena(command):
            return subprocess.run(["ssh", "-p", str(vm.port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                                   "-o", "PreferredAuthentications=password,keyboard-interactive", "lena@127.0.0.1", command],
                                  env={**os.environ, "SSH_ASKPASS": askpass, "SSH_ASKPASS_REQUIRE": "force"},
                                  capture_output=True, text=True, timeout=120)
        login = as_lena("pwd; cat /media/lena-Family/hello.txt; grep -c cifs /proc/mounts")
        print("       " + login.stdout.replace("\n", " | "), flush=True)
        if "/home/lena" not in login.stdout:
            print(vm.ssh("journalctl -u ssh -u sshd --no-pager | tail -14 | cut -c1-200; sshd -T | grep -iE '^(passwordauth|kbdinter|usepam|maxauth)'; "
                         "ls /etc/ssh/sshd_config.d/; grep -v '^#' /etc/pam.d/sshd | grep -v '^$' | head -20").stdout, flush=True)
        check(group, "the home directory appears", "/home/lena" in login.stdout, login.stderr[-300:])
        if "hello" not in login.stdout:
            print(vm.ssh("grep -n 'pam_mount\\|pam_sss\\|pam_unix' /etc/pam.d/password-auth /etc/pam.d/common-auth /etc/pam.d/common-session; cat /etc/security/pam_mount.conf.xml | tail -6; "
                         "journalctl -b --no-pager | grep -iE 'pam_mount|cifs|mount\\.' | grep -v AUDIT | tail -14; modprobe cifs; lsmod | grep -c cifs; "
                         "testparm -s 2>/dev/null | tail -5").stdout[-2500:], flush=True)
        check(group, "the share is there after login", "hello" in login.stdout)
        check(group, "the mount point is out of the user's reach", vm.ssh("stat -c %U /media").stdout.strip() == "root")
        check(group, "the password is in no file", vm.ssh(f"grep -rl '{password}' /etc/security /home 2>/dev/null").stdout.strip() == "")

        policy["mounts"].append({"server": "10.255.255.1", "share": "away", "folder": "Away"})
        admin.call("PUT", f"{path}/policy", policy)
        tool.run("approve", input="y\n")
        wait_for(lambda: "10.255.255.1" in vm.ssh("cat /etc/security/pam_mount.conf.xml").stdout, 120, 5)
        started = time.time()
        login = as_lena("echo logged-in")
        took = time.time() - started
        check(group, "a share out of reach does not block the login", "logged-in" in login.stdout and took < 30, f"{took:.0f}s {login.stderr}")
        print(f"       login with a share out of reach took {took:.0f}s", flush=True)

        # Nextcloud as a drive, with the password only in a keyring.
        code, issued = admin.call("POST", "/api/certificates", {"names": ["cloud.home.test"], "days": 30})
        check(group, "certificate for Nextcloud", code == 201, str(issued))
        for file, field in (("cloud.pem", "cert"), ("cloud.key", "key")):
            with open(f"{work}/{file}", "w") as f:
                f.write(issued[field])
        subprocess.run(["podman", "rm", "-f", "hw-nextcloud"], capture_output=True)
        subprocess.run(["podman", "run", "-d", "--name", "hw-nextcloud", "-p", f"127.0.0.1:{CLOUD_HTTP_PORT}:80",
                        "-e", "SQLITE_DATABASE=nextcloud", "-e", "NEXTCLOUD_ADMIN_USER=lena", "-e", f"NEXTCLOUD_ADMIN_PASSWORD={password}",
                        "-e", "NEXTCLOUD_TRUSTED_DOMAINS=cloud.home.test 127.0.0.1", NEXTCLOUD_IMAGE], capture_output=True, check=True)
        cloud_proxy = subprocess.Popen(["socat", f"OPENSSL-LISTEN:{CLOUD_PORT},reuseaddr,fork,cert={work}/cloud.pem,key={work}/cloud.key,verify=0",
                                        f"TCP:127.0.0.1:{CLOUD_HTTP_PORT}"], stderr=subprocess.DEVNULL)

        def cloud_ready():
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{CLOUD_HTTP_PORT}/status.php", timeout=5) as resp:
                    return json.load(resp).get("installed")
            except (OSError, ValueError):
                return False
        check(group, "Nextcloud runs", wait_for(cloud_ready, 240, 5))
        vm.ssh("echo '10.0.2.2 cloud.home.test' >>/etc/hosts; " + ("DEBIAN_FRONTEND=noninteractive apt-get install -y -q gnome-keyring dbus-daemon"
                                                                    if debian else "dnf5 install -y gnome-keyring dbus-daemon"), timeout=600)
        policy["nextcloud"] = {"url": f"https://cloud.home.test:{CLOUD_PORT}", "mode": "drive"}
        admin.call("PUT", f"{path}/policy", policy)
        tool.run("approve", input="y\n")
        check(group, "the drive is set up", wait_for(lambda: vm.ssh("test -x /usr/local/libexec/hauswart-nextcloud-drive && command -v rclone").returncode == 0, 300, 5), str(state()))
        drive = as_lena(f"""dbus-run-session -- sh -c '
            printf %s "{password}" | gnome-keyring-daemon --unlock --components=secrets >/dev/null; sleep 1
            printf %s "{password}" | secret-tool store --label=Nextcloud service hauswart-nextcloud
            /usr/local/libexec/hauswart-nextcloud-drive &
            for i in $(seq 40); do grep -q rclone /proc/mounts && break; sleep 1; done; sleep 2
            ls ~/Nextcloud; grep -c rclone /proc/mounts; ps -eo args | grep -c "[w]ebdav-pass"
            fusermount3 -u ~/Nextcloud'""")
        print("       " + drive.stdout.replace("\n", " | ")[:300], flush=True)
        check(group, "the files of Nextcloud are in the drive", "Documents" in drive.stdout or "Readme.md" in drive.stdout, drive.stdout + drive.stderr)
        check(group, "the password is in no process list", password not in vm.ssh("ps -eo args").stdout)
        cloud_proxy.terminate()
        subprocess.run(["podman", "rm", "-f", "hw-nextcloud"], capture_output=True)

        # The laptop leaves home.
        proxy.terminate()
        proxy.wait()
        proxy = None
        vm.ssh("sss_cache -E; systemctl restart sssd; sleep 8")
        check(group, "offline: the directory is gone", vm.ssh(f"timeout 5 bash -c '</dev/tcp/ldap.home.test/{LDAPS_PORT}'").returncode != 0)
        check(group, "offline: the account is still known", vm.ssh("getent passwd lena").returncode == 0)
        started = time.time()
        check(group, "offline: the password still works", pam("lena", password).returncode == 0,
              pam("lena", password).stderr + vm.ssh("tail -15 /var/log/sssd/sssd_hauswart.log").stdout)
        took = time.time() - started
        check(group, "offline: and quickly", took < 15, f"{took:.0f}s")
        check(group, "offline: a wrong password does not", pam("lena", "wrong-password").returncode != 0)
        proxy = start_proxy()

        # A child renames their account to get out of a rule.
        policy.update({"time_zone": "UTC", "screen_time": [{"user": "lena", "windows": []}]})
        admin.call("PUT", f"{path}/policy", policy)
        tool.run("approve", input="y\n")
        check(group, "the screen time rule arrives", wait_for(lambda: "screen_uids" in vm.ssh("cat /var/lib/hauswart/policy-state.json").stdout, 90, 3),
              vm.ssh("cat /var/lib/hauswart/policy-state.json").stdout)
        # The same for application rules, which also have to work with such an account.
        policy["apps"] = [{"user": "lena", "block_downloads": True, "flatpaks": {"mode": "allow", "apps": []}}]
        admin.call("PUT", f"{path}/policy", policy)
        tool.run("approve", input="y\n")
        vm.ssh("cp /usr/bin/true /tmp/lenas; chmod 755 /tmp/lenas")
        check(group, "an application rule holds for a directory account",
              wait_for(lambda: vm.ssh("cd /tmp; runuser -u lena -- /tmp/lenas").returncode != 0, 420, 5),
              vm.ssh("journalctl -u hauswart-agent -u fapolicyd --no-pager | tail -8 | cut -c1-200").stdout)
        check(group, "root is not affected", vm.ssh("/tmp/lenas").returncode == 0)
        lena_uid = vm.ssh("id -u lena").stdout.strip()

        def app_filter():
            return vm.ssh(f"busctl --system get-property org.freedesktop.Accounts /org/freedesktop/Accounts/User{lena_uid} "
                          "com.endlessm.ParentalControls.AppFilter AppFilter").stdout.strip()
        check(group, "and so does the Flatpak filter", wait_for(lambda: app_filter().startswith("(bas) true"), 120, 5),
              app_filter() + vm.ssh("journalctl -u hauswart-agent --no-pager | tail -5 | cut -c1-240").stdout)
        lena_id = stack.pk("core/users/", "lena", key="username")
        stack.api("PATCH", f"core/users/{lena_id}/", {"username": "free-at-last"})
        vm.ssh("sss_cache -E; systemctl restart sssd; sleep 3")
        check(group, "the device knows the new name", vm.ssh("getent passwd free-at-last").returncode == 0,
              vm.ssh("getent passwd free-at-last; tail -5 /var/log/sssd/sssd_hauswart.log").stdout)
        check(group, "ATTACK the new name does not lead out of the application rule",
              vm.ssh("cd /tmp; runuser -u free-at-last -- /tmp/lenas").returncode != 0)
        child = subprocess.Popen(["ssh", "-p", str(vm.port), "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                                  "-o", "PreferredAuthentications=password,keyboard-interactive", "free-at-last@127.0.0.1", "sleep 300"],
                                 env={**os.environ, "SSH_ASKPASS": askpass, "SSH_ASKPASS_REQUIRE": "force"},
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Logins run into the agent within seconds, often before the command starts,
        # so what counts is that it acted on the new name and that nothing is left.
        def ended():
            return "ending the sessions of a user outside their screen time\" user=free-at-last" in \
                vm.ssh("journalctl -u hauswart-agent --no-pager | tail -30").stdout
        check(group, "the agent acts on the new name", wait_for(ended, 90, 2),
              vm.ssh("loginctl list-sessions; journalctl -u hauswart-agent --no-pager | tail -6").stdout)
        check(group, "ATTACK the new name does not lead out of the rule",
              wait_for(lambda: vm.ssh("pgrep -x -u free-at-last sleep").returncode != 0, 30, 1) and child.poll() is not None or
              vm.ssh("pgrep -x -u free-at-last sleep").returncode != 0,
              vm.ssh("loginctl list-sessions; ps -u free-at-last").stdout)
        child.kill()

        admin.call("PUT", f"{path}/devices", {"devices": []})
        tool.run("approve", input="y\n")
        check(group, "leaving the group removes the service password",
              wait_for(lambda: vm.ssh("test -e /etc/sssd/conf.d/hauswart.conf").returncode != 0, 120))
        check(group, "and nobody is locked out", vm.ssh("true").returncode == 0)
    finally:
        if proxy:
            proxy.terminate()
        stack.stop()
        vm.stop()


def test_directory_debian(admin, agent_bin, work, public_key):
    test_directory(admin, agent_bin, work, public_key, debian=True)


def test_screentime(admin, agent_bin, work, public_key, kde=False):
    """A real session runs out of time on a protected device, and the security
    rules meet a real firewall and a real desktop."""
    group = "kde" if kde else "screentime"
    print(f"\n== {group} (Fedora Cloud 44 VM, {'Plasma' if kde else 'GNOME'}, automatic login)", flush=True)
    tool = signing_tool(admin, work)
    vm = VM(work, group, cloud_image(), "fedora", 2237 if kde else 2236,
            [*cloud_seed(work, group, public_key), "-vga", "virtio"])

    def notifications():
        return vm.ssh("cat /tmp/notifications.log").stdout

    try:
        manager = desktop_session(vm, group, kde)
        check(group, "anna has a graphical session", wait_for(lambda: graphical_session(vm)),
              vm.ssh(f"loginctl list-sessions; journalctl -b -u {manager} --no-pager | tail -15").stdout)
        time.sleep(20)  # the shell needs a moment before it owns the service
        uid = vm.ssh("id -u anna").stdout.strip()
        device = protected_agent(vm, admin, tool, agent_bin, group)
        bus = f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus"
        vm.ssh(f"systemd-run --unit=notifications --uid=anna --setenv={bus} "
               "sh -c \"exec dbus-monitor --session \\\"interface='org.freedesktop.Notifications',member='Notify'\\\" >/tmp/notifications.log\"")

        code, out = admin.call("POST", "/api/groups", {"name": group})
        check(group, "group created", code == 201, out)
        path = f"/api/groups/{out['id']}"
        admin.call("PUT", f"{path}/devices", {"devices": [device]})
        zone, now = midday()
        end = (now + timedelta(minutes=4)).strftime("%H:%M")
        today = now.strftime("%a").lower()
        policy = {
            "security": {"firewall": True, "disk_encryption": True, "screen_lock": True},
            "time_zone": zone,
            "language": "de",
            "screen_time": [{"user": "anna", "windows": [{"days": [today], "start": "00:00", "end": end}]}],
        }
        code, out = admin.call("PUT", f"{path}/policy", policy)
        check(group, "policy saved", code == 204, out)

        task = attack(admin, work, device, "screen.extend", {"user": "anna", "until": valid_for(60)})
        check(group, "ATTACK unsigned extension refused", task["status"] == "failed" and "signature" in task["output"], task["output"])

        shown = tool.run("approve", input="y\n")
        check(group, "the rule is shown before signing", f"user anna may be logged in: {today} 00:00-{end}" in shown.stdout, shown.stdout + shown.stderr)

        check(group, "firewall comes on", wait_for(lambda: vm.ssh("systemctl is-active firewalld").stdout.strip() == "active", 60))
        check(group, "warning in the chosen language", wait_for(lambda: "Bildschirmzeit" in notifications(), 60), notifications())

        report = {}

        def checks_arrived():
            nonlocal report
            report = report_of(admin, device).get("policy", {})
            return report.get("checks", {}).get("firewall") == "on"
        check(group, "the report has the checks", wait_for(checks_arrived, 150), str(report))
        check(group, "the cloud image counts as unencrypted", report["checks"].get("disk_encryption") == "off", str(report))
        session = graphical_session(vm)
        print(vm.ssh(f"loginctl show-session {session} -p Desktop -p Type -p Class -p State -p Remote; "
                     f"runuser -u anna -- env {bus} gsettings get org.gnome.desktop.screensaver lock-enabled 2>&1; "
                     f"runuser -u anna -- env {bus} gsettings get org.gnome.desktop.session idle-delay 2>&1; "
                     f"runuser -u anna -- env {bus} busctl --user status org.freedesktop.Notifications 2>&1 | grep -E '^(Comm|Exe)=';"
                     "ps -u anna -o comm= | sort -u | tr '\\n' ' '; echo").stdout, flush=True)
        check(group, "a real session has a screen lock", report["checks"].get("screen_lock") == "on", str(report))

        check(group, "last warning", wait_for(lambda: "Noch 1 Minute" in notifications(), 240), notifications())
        session = graphical_session(vm)
        check(group, "the session is locked at the end",
              wait_for(lambda: "LockedHint=yes" in vm.ssh(f"loginctl show-session {session} -p LockedHint").stdout, 120, 2),
              vm.ssh(f"loginctl show-session {session}").stdout)
        check(group, "the user is told", "vorbei" in notifications(), notifications())
        check(group, "the session ends a minute later", wait_for(lambda: not graphical_session(vm), 100, 2),
              vm.ssh("loginctl list-sessions").stdout)

        vm.ssh(f"systemctl restart {manager}", timeout=60)
        appeared = wait_for(lambda: graphical_session(vm), 90, 1)
        ended = wait_for(lambda: not graphical_session(vm), 40, 1)
        check(group, "a new login appears", appeared, vm.ssh(f"loginctl list-sessions; systemctl status {manager} --no-pager | tail").stdout)
        check(group, "and ends within seconds", ended, vm.ssh("loginctl list-sessions").stdout)

        until = (datetime.now(timezone.utc) + timedelta(minutes=10))
        task, shown = signed_task(admin, tool, device, "screen.extend", {"user": "anna", "until": until.isoformat()})
        check(group, "the extension is shown", "Let anna stay logged in" in shown, shown)
        check(group, "the extension runs", task["status"] == "done", task["output"])
        vm.ssh(f"systemctl restart {manager}", timeout=60)
        check(group, "with an extension the session comes back", wait_for(lambda: graphical_session(vm), 90, 2),
              vm.ssh("loginctl list-sessions").stdout)
        time.sleep(40)
        check(group, "and it stays", graphical_session(vm), vm.ssh("loginctl list-sessions").stdout)

        if kde:
            vm.ssh("mkdir -p /home/anna/.config; printf '[Daemon]\\nAutolock=false\\n' >/home/anna/.config/kscreenlockerrc; "
                   "chown -R anna: /home/anna/.config; systemctl restart hauswart-agent")

            def lock_off():
                return report_of(admin, device).get("policy", {}).get("checks", {}).get("screen_lock") == "off"
            check(group, "Plasma without a lock is reported", wait_for(lock_off, 150), str(report_of(admin, device).get("policy")))

        vm.ssh("systemctl stop firewalld; systemctl restart hauswart-agent")
        check(group, "a stopped firewall comes back",
              wait_for(lambda: vm.ssh("systemctl is-active firewalld").stdout.strip() == "active", 60))
    finally:
        vm.stop()


def test_kde(admin, agent_bin, work, public_key):
    test_screentime(admin, agent_bin, work, public_key, kde=True)


def test_apps(admin, agent_bin, work, public_key, desktop="kde"):
    """Rules per person: one person is stopped, another on the same device is not."""
    group = f"apps-{desktop}"
    print(f"\n== {group} (real fapolicyd and Flatpak)", flush=True)
    debian = desktop == "debian"
    tool = signing_tool(admin, work)
    extra = [] if debian else ["-vga", "virtio"]
    vm = VM(work, group, debian_image() if debian else cloud_image(), "fedora", 2243, [*cloud_seed(work, group, public_key), *extra])

    def as_user(user, command):
        return vm.ssh(f"cd /tmp; runuser -u {user} -- {command}")

    def blocked(result):
        return result.returncode != 0

    def denied(result):
        # A file that is not there fails as well, and proves nothing.
        output = result.stdout + result.stderr
        return blocked(result) and "No such file" not in output and "not found" not in output

    try:
        if debian:
            check(group, "VM boots", vm.wait_ssh())
            vm.ssh("cloud-init status --wait; useradd -m anna")
            manager = ""
        else:
            manager = desktop_session(vm, group, desktop == "kde")
            check(group, "anna has a graphical session", wait_for(lambda: graphical_session(vm)))
        install = ("apt-get update -q && DEBIAN_FRONTEND=noninteractive apt-get install -y -q flatpak python3" if debian
                   else "dnf5 install -y flatpak python3")
        check(group, "Flatpak installed", vm.ssh(install, timeout=900).returncode == 0)
        pulled = vm.ssh("flatpak remote-add --system --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo; "
                        f"flatpak install --system --noninteractive -y flathub {FLATPAK_APP}", timeout=1800)
        check(group, "a Flatpak is there", pulled.returncode == 0, pulled.stdout[-300:] + pulled.stderr[-300:])
        vm.ssh(r"""useradd -m ben
for u in anna ben; do cp /usr/bin/true /home/$u/mytrue; chown $u /home/$u/mytrue
  printf '#!/bin/sh\necho ran\n' >/home/$u/s.sh; chmod 755 /home/$u/s.sh; chown $u /home/$u/s.sh
  printf '#!/usr/bin/python3\nprint("ran")\n' >/home/$u/p.py; chown $u /home/$u/p.py; done
for p in okapp badapp forbidden; do cp /usr/bin/true /usr/bin/hw-$p; done
cat >/usr/local/bin/hw-namespace <<'PY'
import os, sys
os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
print("unshared", flush=True)
os.execv(sys.argv[1], ["x"])
PY
cat >/usr/local/bin/hw-escape <<'PY'
import ctypes, os, shutil, sys
uid, gid = os.getuid(), os.getgid()
os.unshare(os.CLONE_NEWUSER | os.CLONE_NEWNS)
open("/proc/self/setgroups", "w").write("deny")
open("/proc/self/uid_map", "w").write(f"0 {uid} 1")
open("/proc/self/gid_map", "w").write(f"0 {gid} 1")
assert ctypes.CDLL(None).mount(b"x", b"/mnt", b"tmpfs", 0, None) == 0
shutil.copy(sys.argv[1], "/mnt/x")
os.chmod("/mnt/x", 0o755)
print("mounted", flush=True)
os.execv("/mnt/x", ["x", "-version"])
PY
for p in okapp badapp; do printf '[Desktop Entry]\nType=Application\nName=%s\nExec=hw-%s\n' $p $p >/usr/share/applications/hw-$p.desktop; done""")
        device = protected_agent(vm, admin, tool, agent_bin, group)
        code, out = admin.call("POST", "/api/groups", {"name": group})
        path = f"/api/groups/{out['id']}"
        admin.call("PUT", f"{path}/devices", {"devices": [device]})
        policy = {"apps": [{"user": "anna", "strict": True, "allowed_apps": ["hw-okapp"], "forbidden_programs": ["/usr/bin/hw-forbidden"]}]}
        code, out = admin.call("PUT", f"{path}/policy", policy)
        check(group, "policy saved", code == 204, out)
        shown = tool.run("approve", input="y\n")
        check(group, "the rule is shown before signing", "user anna may ONLY start these applications from the menu: hw-okapp" in shown.stdout, shown.stdout + shown.stderr)

        def state():
            return admin.call("GET", f"{path}/policy")[1]["devices"][0]
        applied = wait_for(lambda: vm.ssh("systemctl is-active fapolicyd").stdout.strip() == "active" and state()["state"] in ("current", "deviation"), 420, 5)
        print("       " + str(state())[:500], flush=True)
        check(group, "the device applies it", applied, vm.ssh("journalctl -u hauswart-agent -u fapolicyd --no-pager | tail -8 | cut -c1-200").stdout)
        check(group, "the applications reach the dashboard", any(a["id"] == "hw-badapp" for a in state().get("apps", [])), str(state())[:300])

        if not debian:
            vm.ssh("systemctl reboot", timeout=30)
            time.sleep(15)
            check(group, "VM comes back", vm.wait_ssh())
            check(group, "the session of the child starts under the rules", wait_for(lambda: graphical_session(vm)),
                  vm.ssh(f"journalctl -b -u {manager} --no-pager | tail -10; loginctl list-sessions").stdout)
            time.sleep(25)
            shell = "plasmashell" if desktop == "kde" else "gnome-shell"
            check(group, "and the desktop runs", vm.ssh(f"pgrep -x -u anna {shell}").returncode == 0,
                  vm.ssh("ps -u anna -o comm= | sort -u | tr '\\n' ' '; journalctl -b -u fapolicyd --no-pager | tail -5").stdout)
            check(group, "the rules are on after the reboot", vm.ssh("systemctl is-active fapolicyd").stdout.strip() == "active")

        # After the reboot, as neither of these two would survive it.
        vm.ssh("cp /usr/bin/true /tmp/annas; chmod 755 /tmp/annas; mkdir -p /run/media/stick; "
               "mount -t tmpfs stick /run/media/stick; cp /usr/bin/true /run/media/stick/mytrue")
        loader = "/lib64/ld-linux-x86-64.so.2"
        for label, command in (("a program from home", "/home/anna/mytrue"), ("a program from /tmp", "/tmp/annas"),
                               ("through the loader", f"{loader} /home/anna/mytrue"), ("a script", "/home/anna/s.sh"),
                               ("a script through sh", "sh /home/anna/s.sh"), ("a script through python", "python3 /home/anna/p.py"),
                               ("a forbidden program", "/usr/bin/hw-forbidden"), ("an application not on the list", "/usr/bin/hw-badapp"),
                               ("a forbidden program through the loader", f"{loader} /usr/bin/hw-forbidden"),
                               ("a program on a stick", "/run/media/stick/mytrue"),
                               ("a new mount namespace", "unshare -Urm /home/anna/mytrue"),
                               ("a sandbox of bubblewrap", "bwrap --dev-bind / / /home/anna/mytrue")):
            result = as_user("anna", command)
            check(group, f"ATTACK {label}", denied(result), result.stdout + result.stderr)
        result = as_user("anna", "python3 /usr/local/bin/hw-namespace /home/anna/mytrue")
        check(group, "ATTACK a namespace from Python", denied(result) and "unshared" in result.stdout, result.stdout + result.stderr)
        result = as_user("ben", "python3 /usr/local/bin/hw-namespace /home/ben/mytrue")
        check(group, "and that way works for someone without the rule, so the rule stopped it", not blocked(result), result.stdout + result.stderr)
        result = as_user("ben", "/run/media/stick/mytrue")
        check(group, "someone without the rule may: a program on a stick", not blocked(result), result.stdout + result.stderr)
        # A known limit, see docs/security.md. Measured, so that the text stays true.
        for kind, program in (("dynamic", "/usr/bin/true"), ("static", "/usr/bin/hauswart-agent")):
            escape = as_user("anna", f"python3 /usr/local/bin/hw-escape {program}")
            print(f"       LIMIT a {kind} program on a file system of their own: rc={escape.returncode} {(escape.stdout + escape.stderr)[-120:].strip()}", flush=True)
        vm.ssh("cp /lib/x86_64-linux-gnu/libz.so.1 /home/anna/x.so 2>/dev/null || cp /usr/lib64/libz.so.1 /home/anna/x.so; chown anna /home/anna/x.so")
        preload = vm.ssh("cd /tmp; runuser -u anna -- env LD_PRELOAD=/home/anna/x.so /usr/bin/id 2>&1")
        check(group, "ATTACK a library from home", "cannot be preloaded" in preload.stdout or preload.returncode != 0, preload.stdout)
        check(group, "the allowed application starts", not blocked(as_user("anna", "/usr/bin/hw-okapp")))
        check(group, "helpers keep working", not blocked(as_user("anna", "/usr/bin/id")))
        for label, command in (("a program from home", "/home/ben/mytrue"), ("a script", "/home/ben/s.sh"),
                               ("a forbidden program", "/usr/bin/hw-forbidden"), ("an application not on the list", "/usr/bin/hw-badapp")):
            check(group, f"someone without the rule may: {label}", not blocked(as_user("ben", command)))

        run = f"env HOME=/home/%s flatpak run --command=true {FLATPAK_APP}"
        denied = vm.ssh(f"cd /tmp; runuser -u anna -- {run % 'anna'} 2>&1")
        print("       " + denied.stdout[-200:].strip().replace("\n", " "), flush=True)
        check(group, "ATTACK a Flatpak not on the list", denied.returncode != 0 and "not allowed" in denied.stdout, denied.stdout[-300:])
        ben = vm.ssh(f"cd /tmp; runuser -u ben -- {run % 'ben'} 2>&1")
        check(group, "someone without the rule may use the Flatpak", "not allowed" not in ben.stdout, ben.stdout[-300:])

        policy["apps"][0]["flatpaks"] = {"mode": "allow", "apps": [FLATPAK_APP]}
        admin.call("PUT", f"{path}/policy", policy)
        tool.run("approve", input="y\n")
        allowed = wait_for(lambda: "not allowed" not in vm.ssh(f"cd /tmp; runuser -u anna -- {run % 'anna'} 2>&1").stdout, 90, 5)
        check(group, "the Flatpak works once it is on the list", allowed, vm.ssh(f"cd /tmp; runuser -u anna -- {run % 'anna'} 2>&1").stdout[-300:])

        vm.ssh("systemctl stop fapolicyd; systemctl restart hauswart-agent")
        check(group, "a stopped service comes back", wait_for(lambda: vm.ssh("systemctl is-active fapolicyd").stdout.strip() == "active", 60))
        check(group, "and the rule holds again", wait_for(lambda: blocked(as_user("anna", "/home/anna/mytrue")), 20, 2))

        admin.call("PUT", f"{path}/devices", {"devices": []})
        tool.run("approve", input="y\n")
        check(group, "without the policy the child is free again", wait_for(lambda: not blocked(as_user("anna", "/home/anna/mytrue")), 90, 3))
        check(group, "and the service is off", vm.ssh("systemctl is-enabled fapolicyd").stdout.strip() != "enabled")
    finally:
        vm.stop()


def test_apps_gnome(admin, agent_bin, work, public_key):
    test_apps(admin, agent_bin, work, public_key, "gnome")


def test_apps_debian(admin, agent_bin, work, public_key):
    test_apps(admin, agent_bin, work, public_key, "debian")


def test_gui(admin, agent_bin, work, public_key, kde=True):
    """The packaged desktop app in a real session, started the way it is at login."""
    group = "gui-kde" if kde else "gui-gnome"
    print(f"\n== {group} (Fedora Cloud 44 VM, the package hauswart-tray)", flush=True)
    package = f"{ROOT}/dist/hauswart-tray-0.1.0-1.x86_64.rpm"
    if not os.path.exists(package):
        sys.exit("run make packages first")
    tool = signing_tool(admin, work)
    shots = os.environ.get("VM_SHOTS", work)
    os.makedirs(shots, exist_ok=True)
    monitor = f"{work}/monitor-{group}"
    vm = VM(work, group, cloud_image(), "fedora", 2240, [*cloud_seed(work, group, public_key), "-vga", "virtio",
                                                         "-monitor", f"unix:{monitor},server,nowait"])

    def user(command):
        uid = vm.ssh("id -u anna").stdout.strip()
        return vm.ssh(f"runuser -u anna -- env XDG_RUNTIME_DIR=/run/user/{uid} DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus {command}")

    try:
        manager = desktop_session(vm, group, kde)
        check(group, "anna has a graphical session", wait_for(lambda: graphical_session(vm)),
              vm.ssh(f"journalctl -b -u {manager} --no-pager | tail -15").stdout)
        device = protected_agent(vm, admin, tool, agent_bin, group)
        vm.copy(package, "/tmp/tray.rpm")
        installed = vm.ssh("dnf5 install -y /tmp/tray.rpm", timeout=600)
        check(group, "the package installs", installed.returncode == 0, installed.stderr[-400:])
        check(group, "nothing is missing", "not found" not in vm.ssh("ldd /usr/bin/hauswart-tray").stdout)

        code, out = admin.call("POST", "/api/groups", {"name": group})
        path = f"/api/groups/{out['id']}"
        admin.call("PUT", f"{path}/devices", {"devices": [device]})
        zone, now = midday()
        policy = {"time_zone": zone, "language": "de",
                  "screen_time": [{"user": "anna", "windows": [{"days": [now.strftime("%a").lower()], "start": "00:00", "end": "23:30"}]}]}
        admin.call("PUT", f"{path}/policy", policy)
        tool.run("approve", input="y\n")
        check(group, "the rule arrives", wait_for(lambda: "screen_time" in vm.ssh("cat /var/lib/hauswart/policy.json").stdout, 90))

        vm.ssh("systemctl reboot", timeout=30)
        time.sleep(15)
        check(group, "VM comes back", vm.wait_ssh())
        check(group, "anna has a session again", wait_for(lambda: graphical_session(vm)))
        check(group, "the app starts at login", wait_for(lambda: vm.ssh("pgrep -x -u anna hauswart-tray").returncode == 0, 90, 2),
              vm.ssh("ls -la /etc/xdg/autostart | head; journalctl -b --no-pager | grep -i hauswart-tray | tail -5").stdout)
        time.sleep(20)  # the desktop needs a moment to draw it
        screendump(monitor, f"{shots}/{group}-tray.png")
        if kde:
            items = user("busctl --user get-property org.kde.StatusNotifierWatcher /StatusNotifierWatcher org.kde.StatusNotifierWatcher RegisteredStatusNotifierItems").stdout
            names = re.findall(r'"(:[0-9.]+)/', items)
            owners = [user(f"busctl --user status {name}").stdout for name in names]
            check(group, "the tray symbol is registered", any("hauswart-tray" in owner for owner in owners), items)

        answer = user("curl -s --unix-socket /run/hauswart/user.sock http://agent/status").stdout
        print("       " + answer[:200], flush=True)
        check(group, "anna's app can ask the agent", '"user":"anna"' in answer and '"allowed":true' in answer, answer)

        before = open(f"{shots}/{group}-tray.png", "rb").read()
        second = user("hauswart-tray")
        check(group, "a second start ends at once", second.returncode == 0, second.stderr)
        time.sleep(5)
        screendump(monitor, f"{shots}/{group}-window.png")
        check(group, "and opens the window of the first", open(f"{shots}/{group}-window.png", "rb").read() != before)
        check(group, "there is still one app", vm.ssh("pgrep -c -x -u anna hauswart-tray").stdout.strip() == "1")
    finally:
        vm.stop()


def test_gui_gnome(admin, agent_bin, work, public_key):
    test_gui(admin, agent_bin, work, public_key, kde=False)


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

        # Blocking access: a blocked screen comes back locked, refused logins end the session.
        def anna_session():
            return vm.ssh("loginctl list-sessions --no-legend | awk '$3 == \"anna\" {print $1}' | while read s; do "
                          "loginctl show-session $s -p Type --value | grep -q wayland && echo $s; done").stdout.split()

        def locked(session):
            return vm.ssh(f"loginctl show-session {session} -p LockedHint --value").stdout.strip() == "yes"

        def wait_for(condition, seconds):
            deadline = time.time() + seconds
            while time.time() < deadline:
                if condition():
                    return True
                time.sleep(2)
            return condition()

        sessions = anna_session()
        check(group, "anna still has her session", len(sessions) == 1, str(sessions))
        task, shown = signed_task(admin, tool, device, "access.set", {"mode": "screen", "users": ["anna"]})
        check(group, "approve says the screen is blocked", "BLOCK THE SCREEN of Linux user(s) anna" in shown, shown)
        check(group, "the screen block is in force", task["status"] == "done", task["output"])
        check(group, "anna's screen is locked", wait_for(lambda: locked(sessions[0]), 30))
        screendump(monitor, f"{shots}/desktop-blocked.png")
        check(group, "and she is told", "blocks the screen" in monitor_log(), monitor_log()[-800:])
        vm.ssh(f"loginctl unlock-session {sessions[0]}")
        check(group, "unlocked, it is locked again", wait_for(lambda: locked(sessions[0]), 20))
        task, _ = signed_task(admin, tool, device, "access.set", {"mode": "open"})
        vm.ssh(f"loginctl unlock-session {sessions[0]}")
        time.sleep(12)
        check(group, "opened, it stays unlocked", task["status"] == "done" and not locked(sessions[0]), task["output"])

        task, _ = signed_task(admin, tool, device, "access.set", {"mode": "login", "users": ["anna"], "until": valid_for()})
        check(group, "logins refused for anna", task["status"] == "done", task["output"])
        check(group, "she is warned", wait_for(lambda: "Your session ends at" in monitor_log(), 20), monitor_log()[-800:])
        check(group, "after a minute her session ends", wait_for(lambda: sessions[0] not in anna_session(), 120), str(anna_session()))
        check(group, "and a new one does not last", wait_for(lambda: anna_session() == [], 60), str(anna_session()))
        task, _ = signed_task(admin, tool, device, "access.set", {"mode": "open"})
        check(group, "access open again", task["status"] == "done", task["output"])

        # The full-screen notice: a console of its own, back in front within seconds.
        vm.copy(f"{ROOT}/dist/hauswart-blocker", "/tmp/hauswart-blocker")
        vm.ssh("install -m755 /tmp/hauswart-blocker /usr/bin/hauswart-blocker && restorecon /usr/bin/hauswart-blocker")
        check(group, "anna is back", wait_for(lambda: len(anna_session()) == 1, 120), str(anna_session()))

        def front():
            return vm.ssh("cat /sys/class/tty/tty0/active").stdout.strip()
        before = front()
        task, shown = signed_task(admin, tool, device, "access.set", {"mode": "fullscreen", "message": "Abendessen um 18 Uhr"}, wait=600)
        check(group, "approve says the screen is covered", "COVER THE SCREEN" in shown and "Abendessen um 18 Uhr" in shown, shown)
        check(group, "the full-screen block is in force", task["status"] == "done", task["output"])
        check(group, "it is in front on its own console", wait_for(lambda: front() == "tty9", 60),
              front() + vm.ssh("systemctl status hauswart-block --no-pager | tail -15").stdout)
        check(group, "it belongs to the system, not to anna",
              vm.ssh("systemctl show hauswart-block -p User --value").stdout.strip() == "hauswart-block")
        time.sleep(5)
        screendump(monitor, f"{shots}/desktop-fullscreen.png")
        vm.ssh("chvt 2")
        check(group, "switching away comes back", wait_for(lambda: front() == "tty9", 20), front())
        task, _ = signed_task(admin, tool, device, "access.set", {"mode": "open"})
        check(group, "opened, the block is gone", wait_for(lambda: vm.ssh("systemctl is-active hauswart-block").returncode != 0, 20))
        check(group, "and the console from before is in front", wait_for(lambda: front() == before, 20), front() + " " + before)
    finally:
        vm.stop()


TESTS = ["flatpak", "atomic", "ubuntu", "inventory", "power", "desktop", "screentime", "kde", "atomic-policy", "directory", "directory-debian", "gui-kde", "gui-gnome", "apps-kde", "apps-gnome", "apps-debian"]


def main():
    names = sys.argv[1:] or TESTS
    if names == ["images"]:  # so that parallel runs do not fetch them all at once
        os.makedirs(CACHE, exist_ok=True)
        for image in (cloud_image, previous_coreos_image, ubuntu_image, debian_image):
            image()
        return
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
            [f"{work}/server", "-addr", f"127.0.0.1:{PORT}", "-data", f"{work}/data", "-url", GUEST_URL, "-ca-scope", "home.test"],
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
            tests = {"flatpak": test_flatpak, "atomic": test_atomic, "ubuntu": test_ubuntu, "inventory": test_inventory,
                     "power": test_power, "desktop": test_desktop, "screentime": test_screentime, "kde": test_kde,
                     "atomic-policy": test_atomic_policy, "directory": test_directory,
                     "directory-debian": test_directory_debian, "gui-kde": test_gui, "gui-gnome": test_gui_gnome,
                     "apps-kde": test_apps, "apps-gnome": test_apps_gnome, "apps-debian": test_apps_debian}
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
