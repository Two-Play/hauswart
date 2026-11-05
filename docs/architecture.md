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

`api.Validate` checks every task on the server for early feedback, and again on
the agent, which is the actual enforcement boundary.

A task goes from `pending` to `running` when an agent claims it, then to `done`
or `failed`. A task without a result after 45 minutes becomes `failed`. It is
not retried, because whether it ran is unknown.

## Signed tasks

A device with pinned keys runs a task only with a valid signature, except
`sudo.revoke` and `pkg.upgrade`. The keys live in `agent.json` and the server has
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

## Requests

A member files a request for software, a Flatpak or sudo. Nothing reaches the
device until an admin approves it, which creates the task. A single conditional
update decides a request, so a double click cannot create two tasks. The expiry
of a sudo grant counts from the approval.

## Temporary sudo

sudoers has no expiry of its own. The agent writes a rule to
`/etc/sudoers.d/hauswart-<user>` after checking it with `visudo`, and records the
expiry in `grants.json`. It checks every 15 seconds and at start, without needing
the server, so a grant also ends on time on a disconnected device or after a
reboot.

## Certificates

The CA is valid for ten years, and device and server certificates for two.

An agent renews once a third of the lifetime is left. The server records the new
serial next to the current one and accepts both until the device uses the new
certificate. A lost response therefore cannot lock a device out. The agent keeps
its private key, so the swap is a single atomic rename, and it takes effect at
the next TLS handshake without a restart.

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
