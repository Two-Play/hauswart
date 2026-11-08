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
| `internal/sign` | Signatures and passkey assertions for tasks |
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
| `keys.set` | Replaces the pinned signing keys and passkeys, needs a signature |
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

The tool continues from its own counter, or from the device's report when that is
higher. The report comes through the server, so the tool refuses one more than
`maxCounterJump` ahead, and it never lets the counter wrap.

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

## Passkey approvals

A passkey approves a task in the browser, without the signing tool. It is weaker,
see [the security model](security.md), so it runs alongside signatures and shares
only the envelope with them.

1. An approver or admin registers a passkey in the dashboard. On the server, that is
   only a candidate and means nothing to any device.
2. `hauswart-admin passkeys pin` signs a `keys.set` holding the keys and the
   passkeys with their RP ID, origin and expiry. The agent stores them in
   `agent.json`. `keys.set` replaces both lists, and `admin.json` remembers what
   was pinned. There is no other way onto a device.
3. For a task in status `signing`, the server allocates a passkey counter and builds
   the same envelope as for a signature. The dashboard decodes it, shows it, computes
   the challenge itself, `SHA-256("hauswart-task-passkey@v1\0" || envelope)`, and
   asks for the passkey.
4. The server checks the assertion against the approver's own passkey, for early
   feedback only, and releases the task.
5. `internal/sign/passkey.go` checks the signature before parsing anything, then
   type, challenge, origin, RP ID, and the flags for presence and verification. The
   guard then checks device, expiry, the local list and the counter, and rebuilds
   the task from the envelope.

`guard.json` holds a separate counter for passkeys. The server picks this one, so
sharing the signing counter would let one approval stop all signed tasks. A jump
limit protects the passkey counter in the same way. Tasks with a passkey reach the
device in counter order. If one overtakes another, the server asks for a new
approval instead of sending a task the device would refuse.

`passkey_types` in `agent.json` lists the task types a passkey may approve on this
device. Missing means the default, an empty list means none. The agent reads it at
start, no task changes it, and `keys.set` leaves it alone. It can only narrow
`DefaultPasskeyTypes` in `internal/api/passkeys.go`, which is also the ceiling.

## Policies

A policy is the state a device keeps on its own: required and forbidden packages
and Flatpaks, files, CAs, a maintenance window, security rules and screen time.

Groups hold policies, and devices receive one document. `api.MergePolicies` builds
it from the policies of a device's groups: lists add up, and the stricter security
rule wins. Anything else that disagrees, such as a package that is both required
and forbidden, is a conflict. A device with a conflict receives nothing and keeps
what it has, until an admin settles it.

The merge runs on the server, and that needs no trust: an admin signs the result.
`policy.set` and `policy.clear` are signed tasks that a passkey can never approve,
and a device without pinned keys refuses both. Every change of a policy or of a
group's members queues them for the devices it touches, replacing what nobody
signed yet. `hauswart-admin approve` shows the whole policy, compares it with the
last one signed from that computer, and offers to sign identical policies for
several devices at once.

The agent stores the policy in `policy.json` and works from it alone:

- `PolicyEngine.Enforce` runs at start, after a new policy and every 15 minutes.
  One entry that fails costs only that entry. Only a second look at the device
  counts as success, because a package manager can succeed and change nothing.
- Files stay bound to the allowed paths of the device. A CA leaves the trust store
  with the policy, and everything else stays when an entry is dropped.
- Updates run once per maintenance window, and a window a device missed is not made
  up for. The start is stored first, so that a reboot in the window cannot repeat
  the run.
- An unreadable `policy.json` is reported and changes nothing, because treating it
  like no policy would remove CAs.

The report carries the hash, what differs, what was corrected and the results of
the checks. The server compares the hash with the merge to show each device's state.

### Screen time

`PolicyEngine.ScreenLoop` looks at `loginctl` every 15 seconds. Someone inside
their time gets warnings 15, 5 and 1 minutes before the end. At the end the session
locks, and a minute later `loginctl terminate-user` ends it. Someone who logs in
outside their time is out at the next check, without a warning or a grace period,
so that logging in again earns nothing. Rules are written with names, and the agent
keeps the user ID behind each name, as a directory account can be renamed.

There are no PAM changes on purpose: a mistake there locks everyone out, and this
works the same for accounts that come from elsewhere later. The time zone is part
of the policy, so that changing the zone of a device moves nothing.

`screen.extend` gives more time for today. It holds a moment and not a duration, so
that a late task gives no more than was meant. A passkey may approve it, and the
agent limits it to four hours and to midnight.

## Accounts from Authentik

The dashboard speaks OIDC with Authentik, with PKCE, a nonce and a state that is tied
to the browser by a cookie. An account is matched by its subject, and a name that
already belongs to a local account is refused. `syncDirectory` reads Authentik's API
every 5 minutes, and an account that disappeared there is disabled here.

On devices, a policy can hold a `DirectoryRule`. The agent installs sssd, writes
`/etc/sssd/conf.d/hauswart.conf` and selects the matching PAM setup: `authselect` on
Fedora, `pam-auth-update` on Debian. Other systems report a deviation, because
changing PAM by hand can lock everyone out. Shares use pam_mount. Fedora dropped the
authselect feature for it, so the agent keeps a custom profile based on `sssd`.

The agent is a static binary, and Go's `os/user` only reads `/etc/passwd` then. So
`lookupUser` asks `getent` for accounts it does not find.

## Desktop apps

The apps have a Go module of their own in `gui/`, built with [Fyne](https://fyne.io).
Fyne needs CGO and links against graphics libraries, and the server, the agent and the
admin tool stay static this way. `packaging/build-gui.sh` builds them on Debian, as what
is built against a newer glibc does not start on an older one.

`hauswart-tray` asks the agent over a Unix socket. `hauswart-admin-gui` uses
`internal/admintool` like the command line tool, so both show the same text and sign
through the same code.

## Roles

| Role | May do |
| --- | --- |
| `admin` | Everything |
| `approver` | Decide requests of others, approve listed tasks with a passkey |
| `member` | File requests for the devices assigned to them |

A member sees only assigned devices. A device enrolled later is assigned to nobody
until an admin does it. The update to these roles assigns all existing devices to
existing members, so nothing disappears for them.

## Requests

A member files a request for software, a Flatpak, sudo or screen time. Nothing
reaches the device until an admin or approver approves it, or an approval rule
does, which creates the task. A single conditional update decides a request, so a
double click cannot create two tasks. The expiry of a sudo grant counts from the
approval.

### Approval rules

Approval rules say who decides a request. They exist once for all devices and
once per group, and they set a mode for each kind of request:

| Mode | Effect |
| --- | --- |
| `auto` | Approved when it is filed |
| `approver` | An admin or approver decides, the default |
| `admin` | Only an admin decides |
| `blocked` | Refused when it is filed |

A group leaves a kind open to use the rule for all devices. For a device in
several groups, the strictest mode wins, so no group can loosen what another
group or the default made strict. On top, lists of packages and Flatpaks are
approved at once, but only for a kind that an approver decides, only when every
package of the request is on a list, and never when the policy of the device
forbids one. sudo cannot be `auto`.

The rules stay on the server and are not part of the signed policy. They take the
place of the approver, never of the signature: on a protected device, an
automatically approved task still waits in the signing queue. An approval checks
the rules again, since they may have changed since the request was filed.

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
