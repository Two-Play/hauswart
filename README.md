# Hauswart

Hauswart manages the Linux computers of a household from one web dashboard.
Family members request software or temporary sudo rights, and an admin approves
them with a click. It is built for Fedora and works on other distributions.

**Status: early and not yet used on real hardware.** Everything below is tested
in containers, not on physical machines or over a real VPN. See
[Limitations](#limitations).

## Features

- Web dashboard in English and German, with device health at a glance
- Requests for software and sudo, approved by an admin
- Temporary sudo that ends on time, even if the server is unreachable
- Package install, removal and system update through dnf, apt, zypper and pacman
- Deployment of configuration files and CA certificates
- Linux users: create, lock, and set a start password that must be changed
- CPU and memory limits per user
- Built-in certificate authority with automatic certificate renewal
- Audit log of every action
- Backup and restore

Remote desktop access is planned but not built yet.

## How it works

A server runs at home. An agent on every device connects outwards to it, so
devices need no open ports. Agents authenticate with client certificates from
the server's own CA, and they carry out a fixed set of task types instead of
arbitrary commands.

- [Architecture](docs/architecture.md)
- [Security model](docs/security.md), including what it does not protect against
- [Operating Hauswart](docs/operations.md): installation, VPN, backups

## Quick start

You need Go, Node.js and `rpmbuild`.

```bash
make packages
sudo dnf install ./dist/hauswart-server-0.1.0-1.x86_64.rpm
sudo systemctl enable --now hauswart-server
sudo cat /var/lib/hauswart-server/initial-admin-password
```

The dashboard is now on `https://localhost:8443`. To use it from other devices,
follow [Operating Hauswart](docs/operations.md).

## Development

```bash
make build
dist/hauswart-server -data /tmp/hauswart -dev-http 127.0.0.1:8080
```

`-dev-http` serves the dashboard without TLS on a loopback address. For the
frontend alone, use `npm run dev` in `web/`. It does not proxy the API.

| Command | Checks |
| --- | --- |
| `make test` | `go vet` and unit tests |
| `make e2e` | Real agents as root in Fedora, Debian, Arch and openSUSE containers, resource limits under systemd, and certificate renewal |
| `make test-packages` | RPM, `.deb` and tarball on fresh systems with systemd, including a disaster recovery |
| `test/browsers.py` | Whether real browsers trust the CA. It reports a failure for Debian, which is a known gap |

The privileged tests run inside throwaway containers and need Podman.

## Limitations

- Not yet tried on real hardware or over a real VPN.
- `flatpak.install` and the `rpm-ostree` backend have never been executed.
- On Debian, browsers ignore the system store, so the CA has to be imported by
  hand. Flatpak browsers are not measured.
- A compromised server can reach root on the devices. See
  [the security model](docs/security.md).
- Only `amd64` packages are built.
