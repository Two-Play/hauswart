#!/usr/bin/env python3
"""Runs the login through a real Authentik in containers, because a fake provider
only proves what its author believed. Usage: test/authentik.py [login]
"""
import http.cookiejar
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e  # noqa: E402
from e2e import ROOT, sh  # noqa: E402

VERSION = os.environ.get("AUTHENTIK_VERSION", "2026.8.5")
SERVER_IMAGE = f"ghcr.io/goauthentik/server:{VERSION}"
LDAP_IMAGE = f"ghcr.io/goauthentik/ldap:{VERSION}"
POSTGRES_IMAGE = "docker.io/library/postgres:16-alpine"
HOST = "127.0.0.2"
# In front of Authentik sits what a home usually has there, a TLS proxy.
NAME = "auth.localhost"
HTTP_PORT, HTTPS_PORT, INNER_HTTPS_PORT, DB_PORT = 19000, 19443, 19543, 15432
LDAP_PORT = 13389
PORT = int(os.environ.get("AUTH_PORT", "18460"))
URL = f"https://localhost:{PORT}"
TOKEN = "e2e-bootstrap-token-" + "x" * 20
PASSWORD = "Family-Secret-1"
CONTAINERS = ("hw-auth-db", "hw-auth-server", "hw-auth-worker", "hw-auth-ldap")

results = []


def check(group, name, ok, detail=""):
    results.append((group, name, bool(ok)))
    mark = "ok  " if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f"  -- {str(detail)[-900:]}" if detail and not ok else ""), flush=True)


class Authentik:
    """A running Authentik, set up through its API."""

    def __init__(self):
        self.base = f"http://{HOST}:{HTTP_PORT}"

    def start(self):
        for name in CONTAINERS:
            sh("podman", "rm", "-f", name, check_rc=False)
        sh("podman", "run", "-d", "--name", CONTAINERS[0], "--network", "host",
           "-e", "POSTGRES_PASSWORD=db-secret", "-e", "POSTGRES_USER=authentik", "-e", "POSTGRES_DB=authentik",
           "-e", f"PGPORT={DB_PORT}", POSTGRES_IMAGE)
        settings = ["-e", "AUTHENTIK_SECRET_KEY=" + "k" * 60,
                    "-e", "AUTHENTIK_POSTGRESQL__HOST=127.0.0.1", "-e", f"AUTHENTIK_POSTGRESQL__PORT={DB_PORT}",
                    "-e", "AUTHENTIK_POSTGRESQL__USER=authentik", "-e", "AUTHENTIK_POSTGRESQL__NAME=authentik",
                    "-e", "AUTHENTIK_POSTGRESQL__PASSWORD=db-secret",
                    "-e", f"AUTHENTIK_LISTEN__HTTP=0.0.0.0:{HTTP_PORT}", "-e", f"AUTHENTIK_LISTEN__HTTPS=0.0.0.0:{INNER_HTTPS_PORT}",
                    "-e", "AUTHENTIK_LISTEN__METRICS=127.0.0.1:19300", "-e", "AUTHENTIK_LISTEN__LDAP=0.0.0.0:13389",
                    "-e", f"AUTHENTIK_BOOTSTRAP_TOKEN={TOKEN}", "-e", f"AUTHENTIK_BOOTSTRAP_PASSWORD={PASSWORD}",
                    "-e", "AUTHENTIK_ERROR_REPORTING__ENABLED=false", "-e", "AUTHENTIK_DISABLE_UPDATE_CHECK=true"]
        time.sleep(4)
        sh("podman", "run", "-d", "--name", CONTAINERS[1], "--network", "host", *settings, SERVER_IMAGE, "server")
        # On the host network the worker would fight the server for its ports.
        sh("podman", "run", "-d", "--name", CONTAINERS[2], "--network", "host", *settings,
           "-e", "AUTHENTIK_LISTEN__METRICS=127.0.0.1:19301", "-e", "AUTHENTIK_LISTEN__HTTP=127.0.0.1:19001",
           "-e", "AUTHENTIK_LISTEN__HTTPS=127.0.0.1:19444", SERVER_IMAGE, "worker")
        deadline = time.time() + 300
        while time.time() < deadline:
            try:
                self.api("GET", "core/users/me/")
                # Flows come from blueprints, which the worker applies a bit later.
                ready = (self.pk("flows/instances/", "default-provider-authorization-implicit-consent", key="slug")
                         and self.pk("flows/instances/", "default-provider-invalidation-flow", key="slug")
                         and self.pk("flows/instances/", "default-authentication-flow", key="slug")
                         and self.pk("crypto/certificatekeypairs/", "authentik Self-signed Certificate")
                         and self.api("GET", "core/brands/")["results"] and len(self.scopes()) == 3)
                if ready:
                    return
            except (OSError, RuntimeError, IndexError):
                pass
            time.sleep(3)
        raise RuntimeError("Authentik did not start:\n" + sh("podman", "logs", "--tail", "30", CONTAINERS[1], check_rc=False).stdout)

    def stop(self):
        for name in CONTAINERS:
            sh("podman", "rm", "-f", name, check_rc=False)

    def api(self, method, path, body=None):
        request = urllib.request.Request(f"{self.base}/api/v3/{path}", method=method,
                                         data=json.dumps(body).encode() if body is not None else None)
        request.add_header("Authorization", f"Bearer {TOKEN}")
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as err:
            raise RuntimeError(f"{method} {path}: {err.code} {err.read()[:400]}") from None
        return json.loads(raw) if raw else None

    def pk(self, path, value, key="name", field="pk"):
        results_ = self.api("GET", f"{path}?{key}={urllib.parse.quote(value)}")["results"]
        return results_[0][field] if results_ else None

    def group(self, name):
        return self.api("POST", "core/groups/", {"name": name})["pk"]

    def user(self, username, groups=()):
        user = self.api("POST", "core/users/", {"username": username, "name": username, "groups": list(groups), "type": "internal"})
        self.api("POST", f"core/users/{user['pk']}/set_password/", {"password": PASSWORD})
        return user

    def scopes(self):
        found = self.api("GET", "propertymappings/provider/scope/?page_size=100")["results"]
        wanted = {f"goauthentik.io/providers/oauth2/scope-{s}" for s in ("openid", "email", "profile")}
        return [m["pk"] for m in found if m.get("managed") in wanted]

    def ldap_outpost(self):
        """Starts the outpost and returns the base DN. It speaks plain LDAP on the
        host, and a TLS proxy goes in front of it."""
        base_dn = "dc=ldap,dc=goauthentik,dc=io"
        flow = self.pk("flows/instances/", "default-authentication-flow", key="slug")
        provider = self.api("POST", "providers/ldap/", {
            "name": "ldap", "authorization_flow": flow, "base_dn": base_dn, "bind_mode": "direct", "search_mode": "direct",
            "invalidation_flow": self.pk("flows/instances/", "default-invalidation-flow", key="slug"),
        })
        self.api("POST", "core/applications/", {"name": "LDAP", "slug": "ldap", "provider": provider["pk"]})
        outpost = self.api("POST", "outposts/instances/", {
            "name": "ldap", "type": "ldap", "providers": [provider["pk"]],
            "config": {"authentik_host": self.base, "authentik_host_insecure": True},
        })
        key = self.api("GET", f"core/tokens/{outpost['token_identifier']}/view_key/")["key"]
        sh("podman", "run", "-d", "--name", CONTAINERS[3], "--network", "host",
           "-e", f"AUTHENTIK_HOST={self.base}", "-e", f"AUTHENTIK_TOKEN={key}", "-e", "AUTHENTIK_INSECURE=true",
           "-e", f"AUTHENTIK_LISTEN__LDAP=127.0.0.1:{LDAP_PORT}", "-e", "AUTHENTIK_LISTEN__LDAPS=127.0.0.1:13636",
           "-e", "AUTHENTIK_LISTEN__METRICS=127.0.0.1:19302", "-e", "AUTHENTIK_LISTEN__HTTP=127.0.0.1:19002", LDAP_IMAGE)
        return base_dn

    def oidc_application(self, redirect):
        signing = self.pk("crypto/certificatekeypairs/", "authentik Self-signed Certificate")
        provider = self.api("POST", "providers/oauth2/", {
            "name": "hauswart", "client_type": "confidential", "client_id": "hauswart", "client_secret": "client-secret",
            "authorization_flow": self.pk("flows/instances/", "default-provider-authorization-implicit-consent", key="slug"),
            "invalidation_flow": self.pk("flows/instances/", "default-provider-invalidation-flow", key="slug"),
            "redirect_uris": [{"matching_mode": "strict", "url": redirect}],
            "signing_key": signing, "property_mappings": self.scopes(), "grant_types": ["authorization_code"],
        })
        self.api("POST", "core/applications/", {"name": "Hauswart", "slug": "hauswart", "provider": provider["pk"]})


def tls_proxy(cert_file, key_file):
    """Serves a certificate of the Hauswart CA in front of Authentik. It passes
    TLS on to TLS, so that Authentik knows that the request came over https."""
    return [subprocess.Popen(["socat", f"OPENSSL-LISTEN:{HTTPS_PORT},{family},reuseaddr,fork,cert={cert_file},key={key_file},verify=0",
                              f"OPENSSL:{HOST}:{INNER_HTTPS_PORT},verify=0"], stderr=subprocess.DEVNULL)
            for family in ("pf=ip4,bind=127.0.0.1", "pf=ip6,bind=[::1]")]


class Browser:
    """Walks through Authentik's flows the way its login page does."""

    def __init__(self, ca_file):
        self.jar = http.cookiejar.CookieJar()
        context = ssl.create_default_context(cafile=ca_file)
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar),
                                                  urllib.request.HTTPSHandler(context=context))

    def get(self, url):
        with self.opener.open(url, timeout=30) as resp:
            return resp.geturl(), resp.read()

    def flow(self, url, base, username):
        """url is a page of a flow. Returns where the flow leads."""
        parsed = urllib.parse.urlparse(url)
        slug = parsed.path.rstrip("/").split("/")[-1]
        executor = f"{base}/api/v3/flows/executor/{slug}/?query={urllib.parse.quote(parsed.query)}"
        _, raw = self.get(executor)
        challenge = json.loads(raw)
        for _ in range(10):
            component = challenge.get("component")
            if component == "xak-flow-redirect":
                return urllib.parse.urljoin(base, challenge["to"])
            answer = {"ak-stage-identification": {"uid_field": username},
                      "ak-stage-password": {"password": PASSWORD}}.get(component)
            if answer is None:
                raise RuntimeError(f"unexpected step {component}: {challenge}")
            csrf = next((c.value for c in self.jar if c.name == "authentik_csrf"), "")
            request = urllib.request.Request(executor, data=json.dumps({"component": component, **answer}).encode(), method="POST")
            request.add_header("Content-Type", "application/json")
            request.add_header("X-authentik-CSRF", csrf)
            with self.opener.open(request, timeout=30) as resp:
                challenge = json.loads(resp.read())
        raise RuntimeError("the flow does not end")

    def login(self, username, base):
        url, _ = self.get(f"{URL}/auth/oidc/start")
        for _ in range(6):
            if url.startswith(URL):
                return url
            if "/if/flow/" in url:
                url, _ = self.get(self.flow(url, base, username))
            else:
                raise RuntimeError(f"lost at {url}")
        raise RuntimeError("the login does not end")

    def hauswart(self, path):
        request = urllib.request.Request(URL + path)
        try:
            with self.opener.open(request, timeout=30) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as err:
            return err.code, None


def start_server(work, env_file=""):
    binary = f"{work}/server"
    if not os.path.exists(binary):
        subprocess.run(["go", "build", "-o", binary, "./cmd/hauswart-server"], cwd=ROOT,
                       env={**os.environ, "CGO_ENABLED": "0"}, check=True)
    log = open(f"{work}/server.log", "a")
    server = subprocess.Popen([binary, "-addr", f"127.0.0.1:{PORT}", "-data", f"{work}/data", "-url", URL,
                               "-ca-scope", "home.test,127.0.0.0/8", "-oidc-env", env_file or f"{work}/none"],
                              stderr=log, stdout=log)
    before = time.time()
    while time.time() - before < 10:
        if "listening" in open(f"{work}/server.log").read().rsplit("hauswart", 1)[-1] or os.path.exists(f"{work}/data/hauswart.db"):
            time.sleep(1)
            return server
        time.sleep(0.2)
    raise RuntimeError("server did not start")


def test_login(work):
    group = "login"
    print(f"\n== login (Authentik {VERSION} in containers)", flush=True)
    e2e.URL = URL
    e2e.PORT = PORT
    server = start_server(work)
    auth = Authentik()
    proxies = []
    try:
        password = open(f"{work}/data/initial-admin-password").read().strip()
        ca = f"{work}/data/pki/ca.pem"
        admin = e2e.Client(ca)
        code, _ = admin.call("POST", "/api/login", {"username": "admin", "password": password})
        check(group, "local admin logs in", code == 200)
        code, issued = admin.call("POST", "/api/certificates", {"names": [NAME], "days": 30})
        check(group, "service certificate for Authentik", code == 201, str(issued))

        auth.start()
        check(group, "Authentik is up", True)
        for file, field in (("service.pem", "cert"), ("service.key", "key")):
            with open(f"{work}/{file}", "w") as f:
                f.write(issued[field])
        proxies += tls_proxy(f"{work}/service.pem", f"{work}/service.key")
        auth.oidc_application(f"{URL}/auth/oidc/callback")
        admins = auth.group("family-admins")
        parents = auth.group("family-parents")
        auth.user("lena", [admins])
        auth.user("paul", [parents])
        kid = auth.user("mia")
        auth.user("admin2")

        base = f"https://{NAME}:{HTTPS_PORT}"
        env_file = f"{work}/oidc.env"
        with open(env_file, "w") as f:
            f.write(f"OIDC_ISSUER={base}/application/o/hauswart/\nOIDC_CLIENT_ID=hauswart\nOIDC_CLIENT_SECRET=client-secret\n"
                    f"OIDC_ADMIN_GROUP=family-admins\nOIDC_PARENT_GROUP=family-parents\n"
                    f"AUTHENTIK_URL={base}\nAUTHENTIK_TOKEN={TOKEN}\n")
        os.chmod(env_file, 0o600)
        server.terminate()
        server.wait()
        server = start_server(work, env_file)
        check(group, "the server enabled the login", "login through Authentik is on" in open(f"{work}/server.log").read(),
              open(f"{work}/server.log").read())

        for name, role in (("lena", "admin"), ("paul", "parent"), ("mia", "member")):
            browser = Browser(ca)
            landed = browser.login(name, base)
            check(group, f"{name} comes back without an error", "login_error" not in landed,
                  landed + open(f"{work}/server.log").read()[-700:])
            code, me = browser.hauswart("/api/me")
            check(group, f"{name} is logged in as {role}", code == 200 and me["role"] == role and me["source"] == "authentik", str(me))

        code, _ = admin.call("POST", "/api/login", {"username": "admin", "password": password})
        check(group, "the local admin still logs in", code == 200)

        # The sync has to find the same people the logins created, by subject.
        auth.user("nora", [parents])
        paul_id = auth.pk("core/users/", "paul", key="username")
        auth.api("PATCH", f"core/users/{paul_id}/", {"is_active": False})
        server.terminate()
        server.wait()
        server = start_server(work, env_file)
        time.sleep(3)
        admin = e2e.Client(ca)
        admin.call("POST", "/api/login", {"username": "admin", "password": password})
        _, users = admin.call("GET", "/api/users")
        by_name = {u["username"]: u for u in users}
        check(group, "the sync brings in someone who never logged in", by_name.get("nora", {}).get("role") == "parent", str(users))
        check(group, "the sync knows who already logged in", sum(u["username"] == "lena" for u in users) == 1 and by_name["lena"]["role"] == "admin", str(users))
        check(group, "a deactivated account is disabled", by_name["paul"].get("disabled"), str(users))
        check(group, "service accounts stay out", not any(u["username"].startswith("ak-") for u in users), str(users))
        check(group, "local accounts stay as they are", by_name["admin"]["role"] == "admin" and not by_name["admin"].get("disabled"), str(users))

        auth.api("PATCH", f"core/users/{kid['pk']}/", {"username": "mia-renamed-Bad Name"})
        browser = Browser(ca)
        landed = browser.login("mia-renamed-Bad Name", base)
        check(group, "a name that cannot be a Linux account is refused", "login_error=oidc_bad_name" in landed, landed)
    finally:
        if os.environ.get("AUTH_DEBUG"):
            print(sh("podman", "logs", "--tail", "400", CONTAINERS[1], check_rc=False).stderr)
        for proxy in proxies:
            proxy.terminate()
        server.terminate()
        server.wait()
        auth.stop()


def main():
    work = tempfile.mkdtemp(prefix="hw-auth-", dir=os.environ.get("E2E_TMP"))
    try:
        for name in sys.argv[1:] or ["login"]:
            {"login": test_login}[name](work)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    failed = [r for r in results if not r[2]]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    for group, name, _ in failed:
        print(f"  FAILED {group}: {name}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
