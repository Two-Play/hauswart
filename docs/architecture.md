# Architecture

## Overview

```text
 Browser ──HTTPS, session cookie──┐
                                  ▼
                        ┌───────────────────┐
                        │  hauswart-server  │  dashboard, API, CA
                        │  SQLite           │  unprivileged user
                        └───────────────────┘
                                  ▲
 hauswart-agent ──HTTPS, mTLS─────┘  outbound only, root, one per device
```

The server and the agent are single static Go binaries. Everything
distribution specific lives in `internal/agent/platform.go`, so supporting
another distribution means adding a package backend or a trust store layout
there.

| Path | Purpose |
| --- | --- |
| `cmd/hauswart-server`, `cmd/hauswart-agent` | Entry points |
| `internal/api` | Wire types, task validation, error codes |
| `internal/server` | HTTP API and the approval workflow |
| `internal/store` | SQLite and schema migrations |
| `internal/pki` | Certificate authority |
| `internal/agent` | Enrollment, connection, task execution |
| `internal/backup` | Backup and restore |
| `internal/notify` | Notifications to admins through ntfy and email |
| `internal/sign` | Signatures for tasks |
| `cmd/hauswart-admin` | Signing tool for the admin's computer |
| `web` | React and Mantine dashboard, embedded into the server binary |
| `packaging` | systemd units, RPM spec, `.deb` build |
| `test` | End-to-end, package and browser tests |

## Enrollment

1. The admin creates a command in the dashboard. It holds a one-time token,
   valid for an hour, and the SHA-256 fingerprint of the CA.
2. The agent fetches the CA over an unverified connection and accepts it only
   if the fingerprint matches. From here on, it pins that CA.
3. The agent creates its key, which never leaves the device, and sends a CSR
   with the token.
4. The server consumes the token and signs a certificate. The common name is the
   device ID, a hash of the public key, which the agent checks.
5. The agent adds the CA to the system store, so browsers on the device trust
   the dashboard where the distribution allows it.

## Connection

Agents open every connection themselves:

- Long poll for tasks (`GET /agent/tasks`), waiting up to 25 seconds
- Report of health and inventory every minute (`POST /agent/report`)
- Task results (`POST /agent/tasks/{id}/result`)

Browsers and agents share one TLS port. A client certificate is optional at the
TLS layer, and agent routes reject requests without a verified one. On each
request, the server also checks the certificate serial against the device
record, because TLS alone would keep accepting the valid certificate of a
revoked device.

## Tasks

The agent runs only these task types:

| Type | Effect |
| --- | --- |
| `pkg.install`, `pkg.remove`, `pkg.upgrade` | Package manager of the device |
| `flatpak.install` | System-wide Flatpak from Flathub |
| `file.put` | Writes a file below the locally allowed paths |
| `ca.install` | Adds a CA to the system store |
| `sudo.grant`, `sudo.revoke` | Temporary sudoers rule, 24 hours at most |
| `user.create`, `user.lock`, `user.unlock` | Linux accounts |
| `user.passwd` | Start password from a hash, to be changed at first login |
| `keys.set` | Replaces the pinned signing keys, needs a signature |
| `limit.set` | CPU and memory limits through a systemd slice drop-in |
| `logs.fetch` | Reads the journal, see [Insight into devices](#insight-into-devices) |
| `power.reboot`, `power.shutdown` | Scheduled through `shutdown`, at least one minute ahead |
| `power.cancel` | Cancels a scheduled reboot or shutdown |
| `notify.send` | Popup in running desktop sessions |
| `group.add`, `group.remove` | Membership in ordinary Linux groups |

`api.Validate` checks every task on the server for early feedback, and again on
the agent, which is the actual enforcement boundary.

A task goes from `pending` to `running` when an agent claims it, then to `done`
or `failed`. A task without a result after 45 minutes becomes `failed`. It is
not retried, because whether it ran is unknown.

## Signed tasks

A device with pinned keys runs a task only with a valid signature, except
`sudo.revoke`, `pkg.upgrade`, `logs.fetch` and `power.cancel`. The keys live in `agent.json` and the server has
no way to change them: they come from the enroll command or `trust-key`, and
later only from a signed `keys.set`.

`hauswart-admin` signs through the ssh-agent, using the SSHSIG layout with a
namespace and SHA-512. Only Ed25519 keys are accepted, as software or FIDO keys.

The signed envelope holds the type, payload, device ID, a counter and an expiry.
`internal/agent/guard.go` verifies the signature before parsing anything, then
checks the device, the expiry and that the counter is above the highest one seen.
It stores the counter durably before the task runs, and rebuilds the task from
the envelope, so nothing the server added survives. A clock far behind the last
seen time is refused, because it could revive expired tasks. If the state file is
gone, the agent does not start.

Tasks for a protected device wait in status `signing`. The tool fetches them,
decodes and shows them, and signs its own encoding, never bytes from the server.
Password hashes and key lists are made by the tool itself and refused from the
queue.

## Power actions

A reboot or shutdown goes through `shutdown`, so logind holds it, warns terminals
and stops new logins for the last five minutes. Desktops see none of that, so the
agent also shows a popup, which is best effort: the device goes down as ordered
even if nobody is logged in. The delay is at least a minute, which also lets the
agent report the result before it goes down.

Power tasks and messages carry an expiry of at most 24 hours, and the dashboard
sets one hour. The agent refuses them later, and a signature ends with them. This
way nobody can hold back a signed reboot, and a device that was switched off does
not restart right after it comes back. The counter of a signed task is stored
before the task runs, so a reboot cannot repeat after the restart.

## Desktop messages

The agent asks logind for sessions of type `x11` or `wayland`, leaving out the
login screen, remote sessions and system accounts. For each person, it calls the
standard notification service on their session bus through `busctl`, which comes
with systemd, running as that user.

Title and app name are always `Hauswart`. The message is a single line, its
markup is escaped, and control and invisible format characters are refused, so
it cannot pose as the system or look different from what the admin signed. A
task fails if nobody saw the message.

## Requests

A member files a request for software, a Flatpak or sudo. Nothing reaches the
device until an admin approves it, which creates the task. A single conditional
update decides a request, so a double click cannot create two tasks. The expiry
of a sudo grant counts from the approval.

A new request notifies admins through ntfy, email or both, if
`/etc/hauswart/notify.env` configures them. A queue and one background worker do
the sending with three attempts, so a dead mail server never holds up a request.
The queue lives in memory, and at most 30 messages go out per hour, because
members can file requests at any rate. What is lost that way still shows in the
dashboard. A message says who asked for which kind of thing on which device, and
leaves out the details and the reason, which are free text.

## Temporary sudo

sudoers has no expiry of its own. The agent writes a rule to
`/etc/sudoers.d/hauswart-<user>` after checking it with `visudo`, and records the
expiry in `grants.json`. It checks every 15 seconds and at start, without needing
the server, so a grant also ends on time on a disconnected device or after a
reboot.

## Insight into devices

Everything here only reads. It is for admins, and members see none of it.

### Logs

`logs.fetch` takes a number of lines and nothing else, so the server cannot choose
what the agent reads. The agent runs `journalctl --system` twice: for
`hauswart-agent.service` at every priority, and for all messages from warning up.
At most 500 entries and 256 KiB per part come back, as a structured result.

`--system` is not enough to keep users out. It skips the files of users, but a
volatile journal or `SplitMode=none` keeps everything in the system's file. The
agent therefore reads JSON and drops an entry in `internal/agent/logs.go` if it

- comes from a UID of 1000 or above, or names one in another field
- comes from a user's service manager
- ran in a `user-*.slice`, which covers root through sudo in a session
- has no slice at all, because the sender ended before journald could look at it

The result counts what was left out. It stays out of task lists and is fetched
through `GET /api/tasks/{id}/data`. The server deletes it after an hour.

### Rights overview

Every report lists the accounts with a UID of 1000 or above, except `nobody`, with
their groups, the groups that amount to root, and running grants. Sudo rights come
from `sudo -l -U`, because only sudo knows what rules, aliases and groups add up
to. Each question lands in the system log, so the agent asks again only if the
account files or sudoers changed, and at least every hour. Only local accounts
appear, not those from a directory service.

### Update status

The agent checks at start, every six hours, and after every package task, and
retries after 30 minutes if a check failed. A check and a package task never run
at once, because package managers refuse that. The report carries the last result
and the error of a failed check.

| Backend | Pending updates | Reboot needed |
| --- | --- | --- |
| dnf, dnf5 | `repoquery --upgrades` | `needs-restarting --reboothint` |
| apt | `apt-get update`, then a simulated upgrade | `/run/reboot-required` |
| zypper | `list-updates` | `needs-rebooting` |
| pacman | `pacman -Sy` on a copy in `/var/cache/hauswart/pacman` | Kernels only |
| rpm-ostree | `upgrade --preview` | Newest deployment is not the booted one |

On every backend, a running kernel that is gone or older than an installed one
also counts as a reason. The answer is "unknown" if nothing gives one, for example
in a container. pacman gets a copy because refreshing the real databases without
upgrading would set up a partial upgrade.

A system that follows a container image, like Fedora CoreOS, knows no package list
before the upgrade, so the new image counts as one update, named by its version.

### Resource history

The server keeps load, memory and disk per device for seven days in
`device_samples`, at most one row per device and minute, so a device cannot fill
the database. `GET /api/devices/{id}/history` returns averages over 5 minutes for
a day and over 30 minutes for longer.

`GET /api/devices` adds warnings for admins when it is called: a disk at 90 percent
or more, and a certificate with less than 30 days left. The expiry comes from the
certificate the device connected with, not from what it claims, and the warning
also appears for a device that went quiet.

## Certificates

The CA is valid for ten years, and device and server certificates for two.

An agent renews once a third of the lifetime is left. The server records the new
serial next to the current one and accepts both until the device uses the new
certificate. A lost response therefore cannot lock a device out. The agent keeps
its private key, so the swap is a single atomic rename, and it takes effect at
the next TLS handshake without a restart.

Service certificates for home services come from the same CA. The server makes
the key, hands it out once and keeps only the serial, names and expiry, which the
dashboard lists. A certificate is valid for 397 days at most, serves TLS only, and
is issued only for names inside the CA's constraints. Wildcards and the server's
own names are refused, and a CA without constraints issues none at all.

## Data

The server keeps everything in its data directory, by default
`/var/lib/hauswart-server`: `hauswart.db` and the `pki` directory. Schema changes
are appended to `migrations` in `internal/store/store.go` and tracked through
`PRAGMA user_version`, so an old database or backup upgrades when it is opened.

The agent keeps its state in `/var/lib/hauswart`.

## Dashboard

The dashboard is a React application using Mantine, built by Vite and embedded
through `go:embed`. It needs no separate deployment.

Mantine injects style tags at runtime. Instead of allowing inline styles, the
server replaces a placeholder in `index.html` with a nonce that is new on every
request and allows only that nonce in the Content Security Policy.

Errors carry a stable code. The English text in `internal/api/errors.go` is a
fallback, and the dashboard shows the translation from `web/src/locales`. A test
fails if a code lacks a translation.
