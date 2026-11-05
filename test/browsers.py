#!/usr/bin/env python3
"""Measures whether browsers trust a CA from the system store.

A browser that rejects the certificate aborts the TLS handshake and never sends
an HTTP request, so the test server's log is an objective answer. Everything
happens inside a throwaway container. Usage: test/browsers.py [fedora debian]
"""
import subprocess
import sys

CONTAINER = "hauswart-browsers"

FIREFOX = ("rm -rf /tmp/ff && mkdir /tmp/ff && timeout 60 {binary} --headless --no-remote --profile /tmp/ff "
           "--screenshot /tmp/shot.png https://localhost:9443/")
CHROME = ("rm -rf /tmp/cr && timeout 60 {binary} --headless --no-sandbox --disable-gpu "
          "--user-data-dir=/tmp/cr --dump-dom https://localhost:9443/")

TARGETS = {
    "fedora": {
        "containerfile": """FROM registry.fedoraproject.org/fedora:44
RUN dnf5 install -y firefox chromium python3 openssl shadow-utils ca-certificates \\
    https://dl.google.com/linux/direct/google-chrome-stable_current_x86_64.rpm && dnf5 clean all
RUN useradd anna
""",
        "trust": "cp /srv/tls/ca.pem /etc/pki/ca-trust/source/anchors/hauswart-family.crt && update-ca-trust extract",
        "browsers": {
            "firefox": FIREFOX.format(binary="firefox"),
            "chromium": CHROME.format(binary="chromium-browser"),
            "chrome": CHROME.format(binary="google-chrome"),
        },
    },
    "debian": {
        "containerfile": """FROM docker.io/library/debian:stable
RUN apt-get update && apt-get install -y firefox-esr chromium python3 openssl ca-certificates
RUN useradd -m anna
""",
        "trust": "cp /srv/tls/ca.pem /usr/local/share/ca-certificates/hauswart-family.crt && update-ca-certificates",
        # The system store is not enough here, so this is what the agent adds.
        "policy": r"""
mkdir -p /etc/firefox/policies /etc/chromium/policies/managed
printf '{"policies":{"Certificates":{"Install":["/usr/local/share/ca-certificates/hauswart-family.crt"]}}}' >/etc/firefox/policies/policies.json
b64=$(grep -v CERTIFICATE /srv/tls/ca.pem | tr -d '
')
printf '{"CACertificates":["%s"]}' "$b64" >/etc/chromium/policies/managed/hauswart.json
""",
        "browsers": {
            "firefox": FIREFOX.format(binary="firefox-esr"),
            "chromium": CHROME.format(binary="chromium"),
        },
    },
}

# The CA and the certificate the same way Hauswart makes them: EC P-256.
SETUP = r"""
set -e
mkdir -p /srv/tls && cd /srv/tls
openssl ecparam -genkey -name prime256v1 -noout -out ca-key.pem
openssl req -x509 -new -key ca-key.pem -subj "/O=Hauswart/CN=Hauswart Root CA" -days 3650 \
    -addext basicConstraints=critical,CA:TRUE,pathlen:0 -addext keyUsage=critical,keyCertSign,cRLSign \
    -addext "nameConstraints=critical,permitted;DNS:localhost,permitted;IP:127.0.0.1/255.255.255.255" -out ca.pem
openssl ecparam -genkey -name prime256v1 -noout -out key.pem
openssl req -new -key key.pem -subj "/CN=hauswart-server" -out req.pem
printf 'subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\n' >ext
openssl x509 -req -in req.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 700 -extfile ext -out cert.pem
# What an attacker with the CA key would do: a certificate for a foreign name.
sed 's/DNS:localhost/DNS:flathub.example/' ext >ext-foreign
openssl x509 -req -in req.pem -CA ca.pem -CAkey ca-key.pem -CAcreateserial -days 700 -extfile ext-foreign -out foreign.pem
echo '127.0.0.1 flathub.example' >>/etc/hosts
cat >server.py <<'EOF'
import http.server, ssl, threading
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        print("REQUEST", self.headers.get("User-Agent"), flush=True)
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(b"<title>ok</title>trusted")
    def log_message(self, *args): pass
def serve(port, cert):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, "/srv/tls/key.pem")
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
threading.Thread(target=serve, args=(9444, "/srv/tls/foreign.pem"), daemon=True).start()
# Plain HTTP as a positive control: it shows that a browser runs at all, so that
# no request on the TLS ports really means a refused certificate.
plain = http.server.ThreadingHTTPServer(("127.0.0.1", 9080), Handler)
threading.Thread(target=plain.serve_forever, daemon=True).start()
serve(9443, "/srv/tls/cert.pem")
EOF
"""

# Snaps read only certain paths, so everything goes below the policy directories.
POLICY_UBUNTU = r"""
mkdir -p /etc/firefox/policies /var/snap/chromium/current/policies/managed
cp /srv/tls/ca.pem /etc/firefox/policies/hauswart.crt
printf '{"policies":{"Certificates":{"Install":["/etc/firefox/policies/hauswart.crt"]}}}' >/etc/firefox/policies/policies.json
b64=$(grep -v CERTIFICATE /srv/tls/ca.pem | tr -d '\n')
printf '{"CACertificates":["%s"]}' "$b64" >/var/snap/chromium/current/policies/managed/hauswart.json
"""


def run(*argv, input=None, timeout=900):
    return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)


def inside(cmd, user="root", timeout=120):
    return run("podman", "exec", "-u", user, CONTAINER, "sh", "-c", cmd, timeout=timeout)


def reached(command):
    """Runs a browser as a normal user and reports whether a request arrived."""
    inside(": >/tmp/server.log")
    inside(command, user="anna")
    return "REQUEST" in inside("cat /tmp/server.log").stdout


def measure(name, target):
    image = f"localhost/hauswart-browsers-{name}"
    built = run("podman", "build", "-q", "-t", image, "-", input=target["containerfile"])
    if built.returncode != 0:
        sys.exit(built.stderr)
    run("podman", "rm", "-f", CONTAINER)
    run("podman", "run", "-d", "--name", CONTAINER, image, "sleep", "1200")
    try:
        setup = inside(SETUP)
        if setup.returncode != 0:
            sys.exit(setup.stderr)
        run("podman", "exec", "-d", CONTAINER, "sh", "-c", "python3 -u /srv/tls/server.py >/tmp/server.log 2>&1")
        inside("sleep 1; chmod 666 /tmp/server.log")

        browsers = target["browsers"]
        before = {b: reached(c) for b, c in browsers.items()}
        trusted = inside(target["trust"])
        if trusted.returncode != 0:
            sys.exit(trusted.stderr)
        after = {b: reached(c) for b, c in browsers.items()}
        policy = {}
        if "policy" in target:
            setup_policy = inside(target["policy"])
            if setup_policy.returncode != 0:
                sys.exit(setup_policy.stderr)
            policy = {b: reached(c) for b, c in browsers.items()}
            after = policy
        foreign = {b: reached(c.replace("localhost:9443", "flathub.example:9444")) for b, c in browsers.items()}
        for browser in browsers:
            print(f"{name}/{browser}: without CA reached={before[browser]}, with CA reached={after[browser]}, "
                  f"foreign name reached={foreign[browser]}", flush=True)
        return not any(before.values()) and all(after.values()) and not any(foreign.values())
    finally:
        run("podman", "rm", "-f", CONTAINER)


def main():
    results = [measure(name, TARGETS[name]) for name in sys.argv[1:] or list(TARGETS)]
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
