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
- Package install, removal and system update through dnf, apt, zypper, pacman
  and rpm-ostree, and Flatpak installs from Flathub
- Deployment of configuration files and CA certificates
- Linux users: create, lock, set a start password that must be changed, and
  change group memberships
- Restart and shutdown with a warning and a way to cancel
- Messages to family members as a popup on their desktop
- CPU and memory limits per user
- Built-in certificate authority with automatic certificate renewal, and
  certificates for home services
- Notifications to admins about new requests, through ntfy or email
- Tasks signed on your own computer, so a hacked server alone cannot reach root
  on protected devices
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
| `make e2e` | Real agents as root in Fedora, Debian, Arch and openSUSE containers, resource limits under systemd, certificate renewal, and real ntfy and mail servers |
| `make test-packages` | RPM, `.deb` and tarball on fresh systems with systemd, including a disaster recovery |
| `make test-vm` | Flatpak, `rpm-ostree`, real reboots and popups in a GNOME session, in real virtual machines. Needs KVM and downloads about 1.5 GB of images, plus GNOME inside a VM |
| `test/browsers.py` | Whether real browsers trust the CA. It reports a failure for Debian, which is a known gap |

The privileged tests run inside throwaway containers and need Podman.

## License

GNU Affero General Public License, version 3 only (`AGPL-3.0-only`). See
[LICENSE](LICENSE).

## Limitations

- Not yet tried on real hardware or over a real VPN.
- Popups are tested in GNOME on Wayland only. Other desktops should work, but
  are not tested.
- Atomic Fedora is tested on CoreOS, not on Silverblue or Kinoite, and Flatpak
  installs are tested on a server image, without starting the app.
- On Debian, browsers ignore the system store, so the CA has to be imported by
  hand. Flatpak browsers are not measured.
- Only devices with pinned signing keys are protected against a compromised
  server. See [the security model](docs/security.md).
- Only `amd64` packages are built.
