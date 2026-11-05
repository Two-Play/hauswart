# Security model

Hauswart gives one server control over the computers of a household. This
document says what that means, what is defended, and where the limits are.

## The most important point

**Without signing keys, the server is as sensitive as root on every device.**
Protect your devices by pinning signing keys, as described in
[Operating Hauswart](operations.md). Everything below distinguishes between
protected devices and the others.

## What an attacker can do

### With control of the server, on a protected device

The attacker controls the binary, the database, the CA key and the dashboard
code, and can still:

- **Withhold tasks**, and show false results or a fake dashboard. A task marked
  done in the dashboard is only a claim of the server.
- **Trigger `pkg.upgrade`**, which installs what the device's own repositories
  offer, `sudo.revoke`, which only takes rights away, and `power.cancel`, which
  stops a scheduled restart, even one the admin signed.
- **Refuse or delay** anything, including signed tasks.
- **Read** device reports and the audit log, and change the log.
- **Trick the admin.** `hauswart-admin approve` shows what it signs, but a task
  can look legitimate. Read before you sign.
- **Hold back a signed reboot or message** until it expires, which is at most 24
  hours and by default an hour after it was created.
- **Issue service certificates** and read the notification credentials, see
  [Service certificates](#service-certificates) and
  [Notifications](#notifications).

The attacker **cannot** grant sudo, install packages, deploy files or CAs, change
passwords, groups or the pinned keys, restart or shut down a device, or show
popups. The agent refuses these without a valid
signature, and `test/e2e.py signing` proves it by writing such tasks straight
into the database.

### With control of the server, on an unprotected device

- **Reach root.** There is no task that runs a command, but the path exists: set
  a start password for an account, grant it sudo, log in.
- Install, remove and update packages from the repositories a device has
  configured. Packages run their install scripts as root.
- Add a CA to the system store, and so intercept TLS traffic.
- Lock accounts, set resource limits and add accounts to ordinary groups.
- Restart or shut down devices, again and again if it wants to, and show popups.

Even here, the attacker cannot directly run an arbitrary command through the
agent, write files outside the allowed paths, or target `root` and other system
accounts below UID 1000.

### With the signing key

**A signing key is root on every protected device.** Keep it apart from
everything else:

- Use a dedicated key, not the one you log in with. Prefer FIDO
  (`ed25519-sk`), which needs a touch for every signature, or add it with
  `ssh-add -c`, which asks each time.
- Never forward the ssh-agent to another machine.
- Protect the computer you sign on first, because an unprotected laptop gives a
  hacked server root there, and with it the key.
- Keep the second key offline.

### With the CA key

New CAs are limited by name constraints to the addresses of your home network.
With the key, an attacker can impersonate the Hauswart server and your home
services, but not other websites: real browsers refuse such certificates, which
`test/browsers.py` proves. Impersonating the server to an agent gains nothing
beyond control of the server itself.

### With control of a device

- Act as that one device: send false reports and results for its own tasks.
- See only tasks addressed to it.
- Renew only its own certificate.

It cannot read other devices' data or act as another device. Revoking it locks
it out at once.

### With a member account

- See device names, and file requests.
- See only their own requests.
- Not create tasks, see device details, or reach admin functions.

### Desktop messages

A popup always carries the title `Hauswart`, so it cannot pose as the system. It
can still lie: whoever is allowed to send one can write "call this number". Family
members should know that Hauswart never asks for a password.

### Linux groups

`wheel`, `sudo`, `docker` and other groups that amount to root are refused, for
adding and removing, on the server and on the agent, even with a signature. The
agent also refuses a group with GID 0 and any group that `sudoers` mentions on that
device. It does not know other local grants, such as polkit rules or a socket
someone gave to a group, so **the admin who signs still has to know what a group
can do**. Membership takes effect at the next login, and removal does not end
sessions that are already running.

### Service certificates

Every device trusts the CA, so a service key lets its holder impersonate that one
name in the household. This is why names stay inside the CA's constraints, and why
the server's own names are refused: a NAS with that key could otherwise collect
dashboard passwords. Issuing needs no signature, because the CA key is on the
server, and an attacker with the server can issue on their own anyway. Certificates
cannot be revoked yet: a stolen key stays usable until it expires. Choose a short
validity for anything exposed.

### Notifications

The credentials are in `/etc/hauswart/notify.env`, which the server refuses to use
if others can read it. The server has to read them to send, so an attacker with
the server has them too. **Use a dedicated mail account and an ntfy token limited
to one topic**, not your own login. They are not in backups, which cover only the
data directory.

Messages hold a user name, a device name, the kind of request and the dashboard
address, and no details or free text, because they leave the house when ntfy or
mail run elsewhere. A device name comes from the device and is cleaned, so that it
adds no lines, headers or links. With `SMTP_TLS=starttls`, mail is not sent if the
server offers no STARTTLS, so nobody in between can downgrade the connection.

### During a sudo grant

**A sudo grant is full root for its duration, and root can outlast the grant.**
The expiry removes the Hauswart rule, but it cannot undo what someone does while
they have root, such as adding their own rule. The feature protects against
accidents and keeps honest use limited in time. It does not protect against a
family member who sets out to keep root. Grants limited to specific commands are
safer, but the task supports that through the API only, not yet in the dashboard.
Many commands also allow escaping to a shell.

## Defences

| Area | Measure |
| --- | --- |
| Protected devices | Tasks signed by a pinned Ed25519 key, bound to the device, with a counter against replay and an expiry |
| Signing tool | Decodes, shows and re-encodes tasks itself, strips control characters, makes passwords and enroll commands locally |
| CA | Name constrained to the home network |
| Agent authentication | mTLS with a client certificate per device, serial checked on every request |
| First contact | One-time token, CA pinned by fingerprint |
| Device identity | Derived from the device's public key, checked by the agent |
| Input to root | Validated on the agent: strict names, no options, paths or URLs as package names |
| Privileged groups | `wheel`, `sudo`, `docker` and similar are refused in `user.create`, `group.add` and `group.remove`, as are groups with GID 0 or a rule in `sudoers` |
| Power actions | Signed, at least a minute of warning, expire within 24 hours |
| Desktop messages | Signed, fixed title, one line, markup escaped, no invisible characters |
| Service certificates | Inside the CA's constraints, TLS servers only, key not stored |
| Notifications | Credentials in a private file, background delivery, no details in messages, no secrets in logs |
| File deployment | Allowed paths are set on the device, symlinks are not followed |
| Sudoers | Checked by `visudo` before activation, 24 hours at most |
| Passwords | bcrypt, at least 10 characters, lockout after 5 failures per address |
| Sessions | Random tokens stored hashed, `HttpOnly`, `Secure` and `SameSite=Strict` cookies, 12 hours |
| CSRF | SameSite cookies and a required custom header |
| Browser | Strict CSP without `unsafe-inline`, no `innerHTML`, device data treated as untrusted |
| Start passwords | Generated by the server, shown once, sent only as a hash through stdin, removed after use |
| Server process | Unprivileged user in a systemd sandbox |
| Transport | TLS 1.3 only |

## Known weaknesses

- **The CA key is an unencrypted file** in the server's data directory and in
  every backup. Protect backups accordingly.
- **Enrollment trusts the command you paste.** Build it with
  `hauswart-admin enroll-command`, not from the dashboard, for a protected device.
- **The dashboard is not protected by signatures.** A hacked server can show
  anything there and capture dashboard passwords.
- **Lost signing state stops the agent on purpose.** Enroll the device again.
- **The enrollment command contains a token.** It may land in the shell history.
  It works once and for one hour, so the exposure is small.
- **The first admin password** sits in a file until you delete it. It stops
  mattering once you change it.
- **A pending start password** exists as a hash in the database until the device
  picks up the task. SHA-512 crypt is much weaker against guessing than bcrypt,
  but the password is random with 80 bits of entropy. A signed one also sits in
  the task's envelope until then.
- **The login lockout is per address** and held in memory, so a restart clears
  it. There is no two-factor login.
- **A signed restart can lose work.** The warning reaches running desktops and
  terminals, but nothing stops the restart if someone has unsaved work. It can
  also interrupt a running package task.
- **The audit log** lives in the same database an attacker on the server controls.
- **Packages are not signed.** Install them only from your own build.
- **The agent runs as root without a sandbox**, because changing the system is
  its purpose.
- **Revoking a device** ends its access, but does not undo anything on it. A
  `sudo` rule granted before stays until it expires, as long as the agent runs.
- **The development listener** `-dev-http` has no TLS. It accepts only loopback
  addresses. Do not use it in operation.

## Reporting a problem

This is a private project. Open a ticket in the `HAUS` Jira project.
