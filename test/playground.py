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
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time

PORT = int(os.environ.get("PLAYGROUND_PORT", "18600"))
PLAIN_PORT = PORT + 1  # the dashboard without TLS, so the browser has nothing to warn about
os.environ["VM_PORT"] = str(PORT)  # read by vm.py on import
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, f"{ROOT}/test")

import e2e  # noqa: E402
import vm  # noqa: E402

# A DNS name, because passkeys refuse bare addresses. Browsers send *.localhost to
# this machine by themselves, and the VM gets the name in /etc/hosts.
HOST = os.environ.get("PLAYGROUND_HOST", "hauswart.localhost")
URL = f"https://{HOST}:{PORT}"
vm.GUEST_URL = URL

HOME = os.environ.get("PLAYGROUND_DIR", os.path.expanduser("~/.cache/hauswart-playground"))
VERSION = os.environ.get("VERSION", "0.1.0")
SSH_PORT = int(os.environ.get("PLAYGROUND_SSH_PORT", "2250"))
# gtk shows the VM in a window, none runs it without one, as for a test.
DISPLAY = os.environ.get("PLAYGROUND_DISPLAY", "gtk")
NAME = "playground"
PERSON, PERSON_PASSWORD = "anna", "anna"
PERSON_WEB_PASSWORD = "anna-password"  # the dashboard wants at least 10 characters


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
    # The desktop apps are built apart, so they can lag behind. An old admin app
    # refuses to sign what it does not know, an old tray misses new notices.
    changed = subprocess.run(["git", "log", "-1", "--format=%ct", "--", "gui", "internal/api", "internal/admintool"],
                             cwd=ROOT, capture_output=True, text=True).stdout.strip()
    for app in (tray, f"{ROOT}/dist/hauswart-admin-gui"):
        if changed and os.path.exists(app) and os.path.getmtime(app) < int(changed):
            print(f"WARNING: {os.path.basename(app)} is older than the code it is built from, run make packages", flush=True)
    return tray


def start_server():
    log = open(f"{HOME}/server.log", "a")
    before = open(f"{HOME}/server.log").read().count("listening")
    server = subprocess.Popen([f"{HOME}/bin/hauswart-server", "-addr", f"127.0.0.1:{PORT}", "-data", f"{HOME}/data",
                               "-url", URL, "-hosts", "localhost,127.0.0.1", "-dev-http", f"127.0.0.1:{PLAIN_PORT}", "-notify-env", f"{HOME}/notify.env", "-oidc-env", f"{HOME}/oidc.env"],
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


def login():
    admin = e2e.Client(f"{HOME}/data/pki/ca.pem")
    code, _ = admin.call("POST", "/api/login", {"username": "admin", "password": password()})
    if code != 200:
        sys.exit(f"login failed: {code}")
    return admin


def ensure_person(device):
    """Gives anna a Hauswart account for her Linux account, so the desktop app on
    the VM can file requests. Runs on every start to repair older playgrounds."""
    admin = login()
    account = next((u for u in admin.call("GET", "/api/users")[1] if u["username"] == PERSON), None)
    if account is None:
        code, body = admin.call("POST", "/api/users", {"username": PERSON, "linux_user": PERSON,
                                                       "password": PERSON_WEB_PASSWORD, "role": "member"})
        if code != 201:
            sys.exit(f"could not add {PERSON}: {code} {body}")
        account = next(u for u in admin.call("GET", "/api/users")[1] if u["username"] == PERSON)
    code, body = admin.call("PUT", f"/api/users/{account['id']}/devices", {"devices": [device]})
    if code not in (200, 204):
        sys.exit(f"could not assign the device to {PERSON}: {code} {body}")


def ensure_terminal(machine, kde):
    """The desktop comes without weak dependencies, and so without a terminal. You
    want one to try sudo as anna. Runs on every start to repair older playgrounds."""
    terminal = "konsole" if kde else "ptyxis"
    if machine.ssh(f"rpm -q {terminal}").returncode != 0:
        print(f"installing {terminal}, a terminal for the desktop", flush=True)
        installed = machine.ssh(f"dnf5 install -y {terminal}", timeout=600)
        if installed.returncode != 0:
            sys.exit(f"{terminal} did not install:\n" + installed.stderr[-800:])


def digest(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def update_device(machine, tray, state):
    """Brings the agent and the desktop app of the VM up to what was just built,
    so a later run shows the code of now. The desktop app starts at login, so a
    new one logs anna out once."""
    agent = f"{HOME}/bin/hauswart-agent"
    if state.get("agent") != digest(agent):
        print("updating the agent in the VM", flush=True)
        machine.copy(agent, "/tmp/hauswart-agent")
        machine.ssh("install -m755 /tmp/hauswart-agent /usr/bin/hauswart-agent && restorecon /usr/bin/hauswart-agent && "
                    "systemctl restart hauswart-agent", timeout=60)
        state["agent"] = digest(agent)
    if state.get("tray") != digest(tray):
        print("updating the desktop app in the VM, anna logs in again", flush=True)
        machine.copy(tray, "/tmp/tray.rpm")
        installed = machine.ssh("rpm -U --replacepkgs --force /tmp/tray.rpm", timeout=600)
        if installed.returncode != 0:
            sys.exit("the desktop app did not install:\n" + installed.stderr[-800:])
        machine.ssh("systemctl restart display-manager", timeout=60)
        state["tray"] = digest(tray)


def connect_tool(signer, state):
    """Logs the signing tool in to a new server and gives it the keys."""
    admin = login()
    command = admin.call("POST", "/api/enroll-tokens")[1]["command"]
    fingerprint = re.search(r"--ca-fingerprint (\w+)", command).group(1)
    done = signer.run("login", "--server", e2e.URL, "--ca-fingerprint", fingerprint, "--user", "admin", input=password())
    if done.returncode != 0:
        sys.exit(done.stderr)
    signer.run("keys", "add", f"{HOME}/primary.pub", f"{HOME}/offline.pub")
    state["fingerprint"] = fingerprint
    return admin


def ensure_host(machine):
    """Lets the VM find the server by its name, through the gateway of QEMU."""
    machine.ssh(f"grep -q ' {HOST}$' /etc/hosts || echo '10.0.2.2 {HOST}' >>/etc/hosts")


def enroll_again(machine, signer, state):
    """Enrolls the VM with a new server and keeps its desktop: playgrounds from
    before the server had a name need a new CA for it."""
    print(f"enrolling the VM again, now with {URL}", flush=True)
    admin = connect_tool(signer, state)
    ensure_host(machine)
    machine.ssh("systemctl disable --now hauswart-agent; rm -rf /var/lib/hauswart.old; "
                "mv /var/lib/hauswart /var/lib/hauswart.old; mkdir -p /var/lib/hauswart")
    state["device"] = vm.protected_agent(machine, admin, signer, f"{HOME}/bin/hauswart-agent", f"{NAME}-vm")
    state.pop("agent", None)


def first_run(machine, signer, tray, kde, state):
    admin = connect_tool(signer, state)

    print("installing the desktop, this takes a while", flush=True)
    vm.desktop_session(machine, NAME, kde)
    machine.ssh(f"echo '{PERSON}:{PERSON_PASSWORD}' | chpasswd")
    ensure_host(machine)
    device = vm.protected_agent(machine, admin, signer, f"{HOME}/bin/hauswart-agent", f"{NAME}-vm")
    machine.copy(tray, "/tmp/tray.rpm")
    installed = machine.ssh("dnf5 install -y /tmp/tray.rpm", timeout=600)
    if installed.returncode != 0:
        sys.exit("the desktop app did not install:\n" + installed.stderr[-800:])
    # The app starts at login, and anna is already logged in.
    machine.ssh("systemctl restart display-manager", timeout=60)
    state["device"] = device
    state["agent"], state["tray"] = digest(f"{HOME}/bin/hauswart-agent"), digest(tray)


def explain(signer, machine, device_id):
    admin = f"{HOME}/bin/hauswart-admin"
    print(f"""
Hauswart is running. Your data stays in {HOME}.

  Dashboard     http://127.0.0.1:{PLAIN_PORT}  as admin, password {password()}
                With passkeys: {URL}, after `make playground-trust`
                once, which puts the playground CA into your browsers.
  Desktop       the VM window, logged in as {PERSON} with the password {PERSON_PASSWORD}
                {PERSON} has a Hauswart account as well, password {PERSON_WEB_PASSWORD}
  The device    is protected: policies and app rules need your signature.

  Sign tasks in a second terminal:
    export HAUSWART_ADMIN_DIR={HOME}/admin SSH_AUTH_SOCK={signer.socket}
    {admin} approve
  or the admin app instead of approve: {ROOT}/dist/hauswart-admin-gui
  `approve --all` signs everything that waits after one question.

  Approve with a passkey instead, also from a phone:
    1. make playground-trust, then open {URL} and log in
    2. Approvals, Add passkey
    3. {admin} passkeys list
       {admin} passkeys pin --device {device_id} --passkey N

  Live terminal on the VM: Terminal on the device card, with your passkey
    pinned as above, or without one:
    {admin} terminal --device {device_id}

  Boot proof: Details of the device, tab Boot. The VM has a TPM and Secure Boot;
    change the kernel parameters to see an alarm after a restart:
    sudo grubby --update-kernel=ALL --args=hauswart-test && sudo reboot

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

    with socket.socket() as probe:
        if probe.connect_ex(("127.0.0.1", PORT)) == 0:
            sys.exit(f"something already listens on port {PORT}, probably a playground that is still running")
    tray = build()
    if not os.path.exists(f"{HOME}/id"):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", f"{HOME}/id"], check=True)
    e2e.URL = URL
    if state.get("device") and state.get("host") != HOST:
        # The CA of the old server cannot vouch for the name, so the server
        # starts over. The VM keeps its desktop and is enrolled again.
        stamp = time.strftime("%Y%m%d-%H%M%S")
        for old in ("data", "admin"):
            if os.path.exists(f"{HOME}/{old}"):
                os.rename(f"{HOME}/{old}", f"{HOME}/{old}-before-{stamp}")
        state["reenroll"] = True
        state.pop("device")
    state["host"] = HOST
    server = start_server()
    signer = Signer(f"{HOME}/bin/hauswart-admin")
    seed = f"{HOME}/seed-{NAME}.iso"
    seed_args = ["-drive", f"file={seed},media=cdrom,readonly=on"] if os.path.exists(seed) else \
        vm.cloud_seed(HOME, NAME, open(f"{HOME}/id.pub").read().strip())
    # A TPM and Secure Boot, so that the device proves how it starts. They stay
    # between runs like the disk; an older playground gets them on its next start.
    machine_args = []
    if vm.tpm_available():
        machine_args = vm.tpm_machine(HOME, NAME, keep=True)
    else:
        print("no swtpm or OVMF with Secure Boot here, so the VM has no TPM: sudo dnf install swtpm edk2-ovmf", flush=True)
    machine = vm.VM(HOME, NAME, vm.cloud_image(), "fedora", SSH_PORT - vm.SSH_OFFSET,
                    [*seed_args, "-vga", "virtio", *machine_args], display=DISPLAY)
    try:
        if state.get("reenroll"):
            if not machine.wait_ssh():
                sys.exit(f"the VM did not come up, see {machine.log}")
            enroll_again(machine, signer, state)
            state.pop("reenroll")
            json.dump(state, open(state_file, "w"))
        elif not state.get("device"):
            state["kde"] = kde
            first_run(machine, signer, tray, kde, state)
            json.dump(state, open(state_file, "w"))
        elif not machine.wait_ssh():
            sys.exit(f"the VM did not come up, see {machine.log}")
        ensure_host(machine)
        ensure_person(state["device"])
        ensure_terminal(machine, kde)
        update_device(machine, tray, state)
        json.dump(state, open(state_file, "w"))
        # The login of the tool may have run out since the last time.
        if signer.run("devices").returncode != 0:
            signer.run("login", "--server", e2e.URL, "--ca-fingerprint", state["fingerprint"], "--user", "admin",
                       input=password())
        explain(signer, machine, state["device"])
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
