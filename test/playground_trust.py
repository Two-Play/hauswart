#!/usr/bin/env python3
"""Puts the CA of the playground into the certificate stores of your browsers,
for your account only, so that passkeys work on the playground dashboard.

    test/playground_trust.py           add it, after asking
    test/playground_trust.py --remove  take it out again

Chrome, Chromium and Firefox keep their own stores, which certutil from nss-tools
edits. Close the browsers first, and open them again afterwards.
"""
import argparse
import glob
import os
import shutil
import subprocess
import sys

HOME = os.environ.get("PLAYGROUND_DIR", os.path.expanduser("~/.cache/hauswart-playground"))
CA = f"{HOME}/data/pki/ca.pem"
NICKNAME = "Hauswart Playground"


def stores():
    """The NSS databases of the browsers of this account."""
    home = os.path.expanduser("~")
    found = []
    if os.path.exists(f"{home}/.pki/nssdb/cert9.db"):
        found.append(("Chrome and Chromium", f"{home}/.pki/nssdb"))
    for pattern, name in (
        (f"{home}/.mozilla/firefox/*/cert9.db", "Firefox"),
        (f"{home}/.var/app/org.mozilla.firefox/.mozilla/firefox/*/cert9.db", "Firefox (Flatpak)"),
        (f"{home}/.var/app/org.chromium.Chromium/.pki/nssdb/cert9.db", "Chromium (Flatpak)"),
        (f"{home}/.var/app/com.google.Chrome/.pki/nssdb/cert9.db", "Chrome (Flatpak)"),
    ):
        for db in sorted(glob.glob(pattern)):
            found.append((f"{name}, {os.path.basename(os.path.dirname(db))}", os.path.dirname(db)))
    return found


def main():
    parser = argparse.ArgumentParser(description="Trust the playground CA in your browsers.")
    parser.add_argument("--remove", action="store_true", help="take the CA out again")
    args = parser.parse_args()
    if not shutil.which("certutil"):
        sys.exit("certutil is missing: sudo dnf install nss-tools, or sudo apt install libnss3-tools")
    if not args.remove and not os.path.exists(CA):
        sys.exit(f"no playground CA in {CA}, start the playground once first")
    found = stores()
    if not found:
        sys.exit("no browser store found. Start the browser once, then try again.")
    verb = "Remove" if args.remove else "Add"
    print(f"{verb} the CA {'from' if args.remove else 'to'} these stores?")
    for name, path in found:
        print(f"  {name}: {path}")
    if not args.remove:
        fingerprint = subprocess.run(["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", CA],
                                     capture_output=True, text=True).stdout.strip()
        print(f"The CA: {fingerprint}")
        print("It can only vouch for the names in its scope, which the playground chose.")
    if input("[y/N] ").strip().lower() != "y":
        return
    for name, path in found:
        if args.remove:
            command = ["certutil", "-D", "-n", NICKNAME, "-d", f"sql:{path}"]
        else:
            command = ["certutil", "-A", "-n", NICKNAME, "-t", "C,,", "-i", CA, "-d", f"sql:{path}"]
        result = subprocess.run(command, capture_output=True, text=True)
        print(f"  {name}: {'done' if result.returncode == 0 else result.stderr.strip()}")
    print("Open the browsers again for it to take effect.")


if __name__ == "__main__":
    main()
