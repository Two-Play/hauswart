# Hauswart

[![CI](https://github.com/Two-Play/hauswart/actions/workflows/ci.yml/badge.svg)](https://github.com/Two-Play/hauswart/actions/workflows/ci.yml)

Hauswart manages the Linux computers of a household, a small office or a shared
PC from one web dashboard. People request software or temporary sudo rights, and
an admin approves them with a click. It is built for Fedora and works on other distributions.

**Status: early and not yet used on real hardware.** Everything below is tested
in containers and virtual machines, not on physical machines or over a real VPN. See
[Limitations](#limitations).

## Features

- Web dashboard in English and German, with device health at a glance
- Details per device: seven days of resource history, pending updates and
  reboots, accounts with their groups and sudo rights, and system logs without
  anything from users
- Warnings for a nearly full disk and a soon expiring device certificate
- Requests for software and sudo, approved by an admin, or by rules per group
- Search with suggestions for packages and Flatpaks, from the devices' repositories and Flathub
- Temporary sudo that ends on time, even if the server is unreachable
- Package install, removal and system update through dnf, apt, zypper, pacman
  and rpm-ostree, and Flatpak installs from Flathub
- Deployment of configuration files and CA certificates
- Linux users: create, lock, set a start password that must be changed, and
  change group memberships
- Restart and shutdown with a warning and a way to cancel
- Messages to people as a popup on their desktop
- CPU and memory limits per user
- Built-in certificate authority with automatic certificate renewal, and
  certificates for home services
- Notifications to admins about new requests, through ntfy or email
- Tasks signed on your own computer, so a hacked server alone cannot reach root
  on protected devices
- Optional approval with a passkey from a browser or phone, limited per device
  to a list of task types and weaker than a signature
- Roles for admins, approvers who decide requests, and members with their own devices
- Signed policies per group that devices enforce on their own, also without the
  server: required and forbidden software, files, CAs, updates in a maintenance
  window, firewall, and reports on disk encryption and the screen lock
- Screen time per user with warnings, and more time for today from a phone
- Dashboard login through Authentik, with roles from its groups and a sync of its
  accounts
- Linux login with Authentik accounts on Fedora and Debian, also offline, with SMB
  shares at login and Nextcloud as a sync client or network drive
- Application rules per person: no downloaded programs, forbidden programs, Flatpak
  lists, and a strict list of what may run. Others on the device stay free
- A desktop app for everyone with their screen time, shares and requests, and one
  for admins to review and sign tasks
- An inventory of all devices with hardware, software, network and security state, your own
  details such as location and warranty, a search for software across devices and a CSV export
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
git clone https://github.com/Two-Play/hauswart.git
cd hauswart
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

To try everything by hand, `make playground` starts a server and a protected Fedora VM
with a desktop and the desktop app, in its own window. Add `ARGS=--kde` for Plasma. The
first run takes 10 to 20 minutes, later runs start from the same state. It prints the
dashboard address, the password and how to sign tasks. It needs KVM, QEMU and
`make packages`, and keeps its data in `~/.cache/hauswart-playground`.

| Command | Checks |
| --- | --- |
| `make regression` | All suites below at once, with a table of how long each took. `make regression-fast` leaves out the virtual machines |
| `make test` | `go vet` and unit tests |
| `make test-gui` | The desktop apps, clicked through without a screen. Needs the headers of Fyne, or use `make gui` to build in a container |
| `make e2e` | Real agents as root in Fedora, Debian, Arch and openSUSE containers, the same four with a real journal, resource limits under systemd, certificate renewal, signed tasks against a simulated hacked server, and admin notifications |
| `make test-packages` | RPM, `.deb` and tarball on fresh systems with systemd, including a disaster recovery |
| `make test-vm` | Flatpak, `rpm-ostree`, the inventory with made-up hardware, real reboots, popups and screen time in GNOME and Plasma sessions, and the login with a real Authentik, Samba and Nextcloud, in real virtual machines. Needs KVM and Podman, and downloads several GB |
| `test/authentik.py` | The dashboard login and the sync of accounts against a real Authentik in containers |
| `node test/passkeys.mjs` | The passkey flow in Chromium with a virtual authenticator, including what a hacked server tries. Needs `make build` |
| `test/browsers.py` | Whether real browsers trust the CA. It reports a failure for Debian, which is a known gap |

The privileged tests run inside throwaway containers and need Podman.

GitHub runs the same suites on every pull request, and the virtual machines on pull
requests to `main`. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GNU Affero General Public License, version 3 only (`AGPL-3.0-only`). See
[LICENSE](LICENSE).

## Limitations

- Not yet tried on real hardware or over a real VPN.
- Popups use the standard notification service of the desktop, so any desktop with
  one should work, but only GNOME and Plasma on Wayland are tested. So is screen time.
  The check of the screen lock knows only these two.
- The login with directory accounts, shares and the Nextcloud drive are tested on
  Fedora and Debian, in virtual machines. The Nextcloud sync client is not tried.
- Atomic Fedora is tested on CoreOS, not on Silverblue or Kinoite, and Flatpak
  installs are tested on a server image, without starting the app.
- On Debian, browsers ignore the system store, so the CA has to be imported by
  hand. Flatpak browsers are not measured.
- Only devices with pinned signing keys are protected against a compromised
  server. See [the security model](docs/security.md).
- Passkeys are tested with a virtual authenticator only, not on real phones or
  security keys.
- Only `amd64` packages are built.
- The update check for classic `dnf` is written for it but only tested with `dnf5`.
