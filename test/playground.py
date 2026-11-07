#!/usr/bin/env python3
"""A server and a desktop VM to try Hauswart by hand. Nothing is cleaned up.

    test/playground.py          GNOME
    test/playground.py --kde    Plasma

The first run installs the desktop, which takes 10 to 20 minutes. Later runs
start from the same disk and server data in PLAYGROUND_DIR, by default
~/.cache/hauswart-playground. Delete that folder to start over. Ctrl+C or closing
the VM window shuts everything down.

Needs KVM, QEMU and `make packages`.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time

PORT = int(os.environ.get("PLAYGROUND_PORT", "18600"))
os.environ["VM_PORT"] = str(PORT)  # read by vm.py on import
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, f"{ROOT}/test")

import e2e  # noqa: E402
import vm  # noqa: E402

HOME = os.environ.get("PLAYGROUND_DIR", os.path.expanduser("~/.cache/hauswart-playground"))
VERSION = os.environ.get("VERSION", "0.1.0")
SSH_PORT = 2250
NAME = "playground"
PERSON, PERSON_PASSWORD = "anna", "anna"


class Signer:
    """hauswart-admin with its own ssh-agent. Unlike the one of the tests, it keeps
    its keys between runs."""

    def __init__(self, binary):
        self.binary = binary
        self.socket_dir = tempfile.mkdtemp(prefix="hw-", dir=os.environ.get("XDG_RUNTIME_DIR"))
        self.socket = f"{self.socket_dir}/agent"
        self.env = {**os.environ, "HAUSWART_ADMIN_DIR": f"{HOME}/admin", "SSH_AUTH_SOCK": self.socket}
        self.ssh_agent = subprocess.Popen(["ssh-agent", "-D", "-a", self.socket], stdout=subprocess.DEVNULL)
        for key in ("primary", "offline"):
            if not os.path.exists(f"{HOME}/{key}"):
                subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{HOME}/{key}"], check=True)
        for _ in range(50):
            if os.path.exists(self.socket):
                break
            time.sleep(0.1)
        subprocess.run(["ssh-add", "-q", f"{HOME}/primary"], env=self.env, check=True)

    def run(self, *args, input=None):
        return subprocess.run([self.binary, *args], input=input, env=self.env, capture_output=True, text=True, timeout=120)

    def close(self):
        self.ssh_agent.terminate()
        subprocess.run(["rm", "-f", self.socket])
        os.rmdir(self.socket_dir)


def build():
    os.makedirs(f"{HOME}/bin", exist_ok=True)
    env = {**os.environ, "CGO_ENABLED": "0"}
    for binary in ("server", "agent", "admin"):
        subprocess.run(["go", "build", "-o", f"{HOME}/bin/hauswart-{binary}", f"./cmd/hauswart-{binary}"],
                       cwd=ROOT, env=env, check=True)
    tray = f"{ROOT}/dist/hauswart-tray-{VERSION}-1.x86_64.rpm"
    if not os.path.exists(tray):
        sys.exit("the desktop app is missing, run make packages first")
    return tray


def start_server():
    log = open(f"{HOME}/server.log", "a")
    before = open(f"{HOME}/server.log").read().count("listening")
    server = subprocess.Popen([f"{HOME}/bin/hauswart-server", "-addr", f"127.0.0.1:{PORT}", "-data", f"{HOME}/data",
                               "-url", vm.GUEST_URL, "-notify-env", f"{HOME}/notify.env", "-oidc-env", f"{HOME}/oidc.env"],
                              stdout=log, stderr=log)
    for _ in range(100):
        if open(f"{HOME}/server.log").read().count("listening") > before:
            return server
        if server.poll() is not None:
            break
        time.sleep(0.2)
    sys.exit("the server did not start:\n" + open(f"{HOME}/server.log").read()[-2000:])


def password():
    return open(f"{HOME}/data/initial-admin-password").read().strip()


def first_run(machine, signer, tray, kde, state):
    admin = e2e.Client(f"{HOME}/data/pki/ca.pem")
    code, _ = admin.call("POST", "/api/login", {"username": "admin", "password": password()})
    if code != 200:
        sys.exit(f"login failed: {code}")
    command = admin.call("POST", "/api/enroll-tokens")[1]["command"]
    fingerprint = re.search(r"--ca-fingerprint (\w+)", command).group(1)
    done = signer.run("login", "--server", e2e.URL, "--ca-fingerprint", fingerprint, "--user", "admin", input=password())
    if done.returncode != 0:
        sys.exit(done.stderr)
    signer.run("keys", "add", f"{HOME}/primary.pub", f"{HOME}/offline.pub")
    state["fingerprint"] = fingerprint

    print("installing the desktop, this takes a while", flush=True)
    vm.desktop_session(machine, NAME, kde)
    machine.ssh(f"echo '{PERSON}:{PERSON_PASSWORD}' | chpasswd")
    device = vm.protected_agent(machine, admin, signer, f"{HOME}/bin/hauswart-agent", f"{NAME}-vm")
    machine.copy(tray, "/tmp/tray.rpm")
    installed = machine.ssh("dnf5 install -y /tmp/tray.rpm", timeout=600)
    if installed.returncode != 0:
        sys.exit("the desktop app did not install:\n" + installed.stderr[-800:])
    # The app starts at login, and anna is already logged in.
    machine.ssh("systemctl restart display-manager", timeout=60)
    state["device"] = device


def explain(signer, machine):
    admin = f"{HOME}/bin/hauswart-admin"
    print(f"""
Hauswart is running. Your data stays in {HOME}.

  Dashboard     https://localhost:{PORT}  as admin, password {password()}
                The browser warns once: Hauswart has its own CA, in {HOME}/data/pki/ca.pem.
  Desktop       the VM window, logged in as {PERSON} with the password {PERSON_PASSWORD}
  The device    is protected: policies and app rules need your signature.

  Sign tasks in a second terminal:
    export HAUSWART_ADMIN_DIR={HOME}/admin SSH_AUTH_SOCK={signer.socket}
    {admin} approve
  or the admin app instead of approve: {ROOT}/dist/hauswart-admin-gui

  Root shell in the VM:
    ssh -i {HOME}/id -p {machine.port} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null fedora@127.0.0.1

Ctrl+C here, or closing the VM window, shuts everything down.""", flush=True)


def main():
    parser = argparse.ArgumentParser(description="A server and a desktop VM to try Hauswart by hand.")
    parser.add_argument("--kde", action="store_true", help="Plasma instead of GNOME, only on the first run")
    args = parser.parse_args()

    os.makedirs(HOME, exist_ok=True)
    state_file = f"{HOME}/state.json"
    state = json.load(open(state_file)) if os.path.exists(state_file) else {}
    if state and args.kde != state.get("kde"):
        print(f"keeping the desktop of the first run, delete {HOME} to change it", flush=True)
    kde = state.get("kde", args.kde)

    tray = build()
    if not os.path.exists(f"{HOME}/id"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{HOME}/id"], check=True)
    e2e.URL = f"https://localhost:{PORT}"
    server = start_server()
    signer = Signer(f"{HOME}/bin/hauswart-admin")
    seed = f"{HOME}/seed-{NAME}.iso"
    seed_args = ["-drive", f"file={seed},media=cdrom,readonly=on"] if os.path.exists(seed) else \
        vm.cloud_seed(HOME, NAME, open(f"{HOME}/id.pub").read().strip())
    machine = vm.VM(HOME, NAME, vm.cloud_image(), "fedora", SSH_PORT - vm.SSH_OFFSET, [*seed_args, "-vga", "virtio"],
                    display="gtk")
    try:
        if not state.get("device"):
            state["kde"] = kde
            first_run(machine, signer, tray, kde, state)
            json.dump(state, open(state_file, "w"))
        elif not machine.wait_ssh():
            sys.exit(f"the VM did not come up, see {machine.log}")
        # The login of the tool may have run out since the last time.
        if signer.run("devices").returncode != 0:
            signer.run("login", "--server", e2e.URL, "--ca-fingerprint", state["fingerprint"], "--user", "admin",
                       input=password())
        explain(signer, machine)
        machine.process.wait()
    except KeyboardInterrupt:
        print("\nshutting down", flush=True)
        try:
            machine.ssh("systemctl poweroff", timeout=20)
            machine.process.wait(60)
        except subprocess.TimeoutExpired:
            machine.stop()
    finally:
        if machine.process.poll() is None:
            machine.stop()
        server.terminate()
        server.wait()
        signer.close()


if __name__ == "__main__":
    main()
