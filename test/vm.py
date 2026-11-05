#!/usr/bin/env python3
"""Runs what containers cannot: Flatpak and rpm-ostree, in real virtual machines.

The server runs on the host. Guests reach it through QEMU's user networking at
10.0.2.2, so this needs no root and touches nothing on the host but a cache
directory. Usage: test/vm.py [flatpak atomic]
"""
import hashlib
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402

PORT = 18450
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


def main():
    names = sys.argv[1:] or ["flatpak", "atomic"]
    os.makedirs(CACHE, exist_ok=True)
    work = tempfile.mkdtemp(prefix="hauswart-vm-", dir=os.environ.get("E2E_TMP"))
    env = {**os.environ, "CGO_ENABLED": "0"}
    for binary in ("server", "agent"):
        subprocess.run(["go", "build", "-o", f"{work}/{binary}", f"./cmd/hauswart-{binary}"], cwd=ROOT, env=env, check=True)
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
            {"flatpak": test_flatpak, "atomic": test_atomic}[name](admin, f"{work}/agent", work, public_key)
    finally:
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
