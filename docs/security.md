# Security model

Hauswart gives one server control over the computers of a household or a small office. This
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
- **Read** device reports and the audit log, and change the log. Reports name the
  accounts of a device with their groups and sudo rights.
- **Fetch logs**, because `logs.fetch` needs no signature. That means the Hauswart
  agent's log and system messages from warning up, not more. The text of a system
  message can still hold a username or a path, as described under
  [Known weaknesses](#known-weaknesses).
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

**This holds for packages only as long as no passkey is pinned.** With a passkey,
see [the next section](#with-control-of-the-server-on-a-device-with-pinned-passkeys).
Sudo, CAs, passwords, keys and files stay out of reach either way.

### With control of the server, on a device with pinned passkeys

Passkeys are the optional way to approve tasks without the CLI, for example from a
phone. They are **weaker than `hauswart-admin`, and that is a deliberate trade**.
The CLI decodes and shows a task on your own computer, and the server has no part
in what you read. A passkey approval happens on a page the server delivers, so a
hacked server can:

- **Show one task and have another confirmed.** The authenticator signs a hash,
  and it cannot show you what the hash stands for. The dialog says what the server
  wants it to say.
- **Collect several touches.** A fake "failed, try again" gets another approval
  each time, for any device the passkey is pinned on. Touching for someone else's PC
  can approve something for your laptop.
- **Pick the expiry and the counter**, within the limits below.

What a touch can reach is limited by the device, not by the server, and only to
the types in its local list. By default those are `pkg.install`, `pkg.remove`,
`pkg.upgrade`, `flatpak.install`, `power.reboot`, `power.shutdown`, `power.cancel`
and `notify.send`.

**Do not read that list as harmless.** With one touch, a hacked server can:

- Install any package from the repositories of the device. Packages run scripts
  as root, and some start services that trust the network.
- Remove any package, including the agent, the firewall or the kernel. Some package
  managers also read a name as a pattern, so one name can match many packages.
- Install any Flatpak from Flathub with the permissions it asks for, without a
  prompt. Anyone can publish there, subject to Flathub's review. On the computer
  you sign on, an app with access to the ssh-agent reaches your signing key, which
  is root on all protected devices. **Never pin a passkey on that computer.**
- Reboot or shut down the device, and show a false notification on it.

If that is too much for a device, narrow its list. See
[Operating Hauswart](operations.md#approve-with-a-passkey).

Whatever a passkey approves, these limits are checked on the device:

- `sudo.*`, `ca.install`, `user.*`, `keys.set`, `file.put` and `limit.set` are
  refused, even if the local list names them. New task types stay CLI only until
  someone adds them to the ceiling in `internal/api/passkeys.go`.
- An approval is valid for 24 hours at most, whatever its envelope says. It has to
  name a random value the device changes every 12 hours, so approvals cannot be
  collected in advance for later use.
- A device runs at most 20 passkey approvals within any 24 hours.
- A device has to be online for a passkey approval, because the value comes from
  its latest report.
- Each passkey pin ends after 180 days, unless `hauswart-admin` renews it.
- What the agent ran on a passkey approval is in the device's own journal, with the
  name of the passkey and the payload. That is the record to trust, not the
  server's audit log.

`test/passkeys.mjs` proves this in a real browser with a virtual authenticator,
by writing assertions straight into the database.

**Pinning trusts the server at that moment, and this cannot be fixed.** Registering
a passkey happens on a page from the server, so a server that is already hacked can
swap in a key of its own. Nothing tells you: any fingerprint you could compare comes
from the same server. `hauswart-admin` then pins the attacker's key, and the attacker
approves listed tasks without any touch, as often as the limits above allow. The
pin stays after the server is cleaned up, until it expires or you remove it.

So pin only while you trust the server, and **after any incident on the server,
remove all passkeys from all devices and register them again.**

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

### With a stolen phone or security key

Passkeys need the screen lock or PIN of the authenticator on every use, and the
device refuses an approval without that. Whoever knows the phone's PIN and has a
dashboard session can approve listed tasks. That includes a member who knows an
approver's PIN.

- **Removing a lost passkey takes `hauswart-admin`**, because only a signed
  `keys.set` reaches the device. Deleting it in the dashboard does nothing there.
- A hacked server can withhold that `keys.set`. Then only the expiry of the pin
  ends it, or root on the device.
- `admin.json` remembers what is pinned, per computer. `rotate-keys` from an older
  copy brings back a removed passkey, so it shows the list and asks.
- **Synced passkeys** live in the account of the passkey provider, such as Apple,
  Google or a password manager. Whoever takes over that account has the passkey.
  Hauswart does not tell them apart from passkeys on one device. A security key
  with a PIN avoids this.
- Changing someone's role in the dashboard does not unpin their passkey.

### With the CA key

New CAs are limited by name constraints to the addresses of your home network.
With the key, an attacker can impersonate the Hauswart server and your home
services, but not other websites: real browsers refuse such certificates, which
`test/browsers.py` proves. Impersonating the server to an agent gains nothing
beyond control of the server itself.

### Policies

A policy is signed like any other task, and a passkey cannot approve one, so a
hacked server cannot change or remove one. Its limits:

- **A server decides when a policy arrives.** It can hold back a new one, and it can
  deliver an older signed one that has not expired yet, up to 30 days after signing,
  as long as nothing newer reached the device. A device shows what it has in its
  report, but a hacked server can fake the dashboard.
- **A policy repeats itself.** What you sign, a device applies again and again. So a
  CA or a package in a policy is a decision for as long as the policy lasts, and
  removing a package by hand does not last.
- **A forbidden package can take others with it.** Package managers remove what
  depends on it. Hauswart refuses to forbid packages a device cannot do without, but
  that list is short. Read the diff before you sign.
- **The merge happens on the server,** so review what `approve` shows and not what
  the dashboard says the groups contain.

### Screen time

Screen time is meant for people who have no root rights. Its limits:

- **Anyone with sudo can get around all of it,** by stopping the agent or changing
  the clock. That includes a running sudo grant from Hauswart.
- **It controls sessions, not apps or websites.** Forbidding a package works for
  classic packages. A Flatpak in a home directory, a portable program or a web app
  remains possible during allowed times.
- **It needs the agent.** There are no PAM rules behind it. Up to 15 seconds in a
  session outside the allowed time remain possible.
- **The clock is the device's.** Changing the time zone does not help, but changing
  the time does, for whoever has the right to. Check that the people it limits do not.
- **An extension by passkey can be abused by a hacked server** like any passkey
  approval, for up to four hours until midnight, within the daily limit of approvals.

### With control of Authentik

Whoever controls Authentik can log in to the dashboard as anyone, and give themselves
the admin role. That is the same as a stolen admin password: **it does not reach
protected devices**, because signatures come from your own computer. Passkeys do not
help such an attacker either, but a passkey you registered earlier can be talked into
an approval, as described above.

An account is matched by its subject and never by its name, so a new account called
`admin` in Authentik gets no access to the local `admin`. Keep the local admin's
password: it works without Authentik. The client secret and the API token are in
`/etc/hauswart/oidc.env`, and a hacked server has them.

### Directory login

A policy with a directory makes Authentik decide who can log in on a device, so:

- **Whoever controls Authentik can log in on these devices** as any of its accounts,
  or create new ones. An account that has sudo there gives them root on that device.
  Signed tasks stay out of their reach, but they would be on the device itself.
- **The reading account's password is on every device and on the server.** A hacked
  server or any root user can read it. It can see names and groups of everyone.
- **Offline, a device trusts its cache without an end.** A password changed in
  Authentik still opens a laptop that has not been online since, and so does an
  account that was deleted there. There is no way to reach a lost laptop that stays
  offline, so disk encryption matters on those.
- **Only the CA in the policy vouches for the directory,** and it must not be the
  Hauswart CA. With that one, a hacked server could pose as the directory and log in
  as anyone, sudo included.
- **Local accounts are shielded by name.** The list comes from the device at every
  check, so a new local account is exposed for up to 15 minutes to a directory
  account of the same name.
- **Shares get the login password** in the moment of the login, as the login does.
  It is kept in memory by pam_mount and is written nowhere.

### The socket of the agent

The agent runs as root and answers everyone on the device on `/run/hauswart/user.sock`.
Who is asking comes from the kernel, so nobody can speak for someone else. It tells
people about themselves, and it passes on requests, at most 10 an hour per person.
A hacked device can make up requests in the name of anyone who may use it, and
someone still has to approve them.

The history on the socket shows each person their own requests and the changes
that concern them or the whole device. A device learns the state of its requests,
with the Linux user, the kind and the detail, but never the reason, because whoever
controls the device can read it.

### The admin app

`hauswart-admin-gui` runs no server and opens no port. It shows what the command line
shows, through the same code, and reads a task again right before it signs: a task
that changed since it was on the screen is refused. Whatever runs as you can still
ask your ssh-agent to sign, with either tool. Use a security key, or `ssh-add -c`, to
have a say in that.

### Application rules

Rules for a person work in the kernel, through fapolicyd, by user ID. They hold for
programs, and they end where a program that is allowed runs what it is given:

- **Interpreters.** Scripts in a home folder are stopped by their type, which fapolicyd
  takes from the first line. A script without one, or `python3 < file`, gets past.
  Forbid the interpreter too, if that matters.
- **Code typed into an interpreter is not a file.** `python3 -c` runs what it is given.
  Python can also make its own mount namespace with a file system nothing watches. An
  ordinary program fails there, as the loader is caught, but a statically linked one
  runs: the VM tests measure this. It takes code and such a program, and the only way
  to stop it is to forbid the interpreter, if nothing the person needs depends on it.
  Namespaces cannot be turned off for one person, and Flatpak needs them.
- **Bubblewrap and FUSE.** Flatpaks need them, so a person who may use a Flatpak can call
  them too, and with bubblewrap also start the files of another Flatpak. Without Flatpaks
  a strict rule blocks them, and some desktops then show no previews of images. `unshare`
  and `nsenter` are always blocked.
- **Network shares are not watched.** A server that hangs would hold up every program on
  the device. Shares from a policy are mounted `noexec`, others are not covered.
- **Web apps** run in the browser. A rule cannot see them.
- **A strict rule is about applications with a launcher.** A desktop needs hundreds of
  helpers, so what has no launcher stays available, and an application installed just
  now stays open until the next check, up to 15 minutes later. It stops what the launcher
  starts, which can be a small script in front of the real program. A launcher that goes
  through `sh` or `python3` blocks nothing, and a program no rule can be written for, as
  its path has a space, shows as a deviation.
- **Flatpak lists name the stable branch.** Anything else counts as not listed.
- **Anyone with sudo can get around all of it,** and a stopped service stops nothing:
  that shows as a deviation, and the next check starts it again.

### With control of a device

- Act as that one device: send false reports and results for its own tasks.
- See only tasks addressed to it.
- Renew only its own certificate.

It cannot read other devices' data or act as another device. Revoking it locks
it out at once.

### With a member account

- See the names of the devices assigned to them, and file requests for those.
- See only their own requests.
- Not create tasks, see device details, or reach admin functions.

### Desktop messages

A popup always carries the title `Hauswart`, so it cannot pose as the system. It
can still lie: whoever is allowed to send one can write "call this number". Everyone
should know that Hauswart never asks for a password.

A hacked server can suspend a device. That ends sudo grants and stops requests,
and nothing more.

A full-screen notice runs under its own system account with a PAM service that lets
only systemd start it, as root does. It takes no input, and the text and picture
it shows are those someone signed, so it cannot pose as anything but what the admin
wrote. A hacked server can still write any text on an unprotected device.

Blocking access is a signed task on a protected device, opening included, so a
hacked server can neither lock people out nor let them back in. On an unprotected
device it can do both. A block for the whole device also locks out local admins,
and only root and the end of the block get around it. If `access.json` is broken,
the agent refuses logins until access is set again, rather than opening what was
blocked.

A signed Flatpak install also installs the package `flatpak` where it is missing,
from the device's own repositories. Approving a Flatpak means the device needs what
runs it.

Popups about changes come from fixed texts on the device. A package or group name is
the only part from outside, and it is escaped. A hacked server can claim that a
request was denied or approved without doing it, which confuses but grants nothing:
what a device does still needs a task, and on a protected device a signature.

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
name on your network. This is why names stay inside the CA's constraints, and why
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
### With an approver account

- See all device names and all requests, and approve or deny requests.
- Approve queued tasks with their own passkey, on devices where it is pinned.
- Not create tasks, see device details, or reach admin functions.
- Not approve their own requests, or those for their own Linux user.

**Approving is more than it sounds.** On an unprotected device, approving a sudo
request creates the grant at once. Two approvers can therefore give each other sudo
there, and an approver can approve a sudo request for a member account they control.
Protect a device, and sudo needs `hauswart-admin` no matter who approves.

Roles are checks of the server. They mean nothing against a hacked server, where
only what is pinned on a device still holds. The same goes for approval rules: they
can approve a request without anyone looking, but on a protected device the task
still needs a signature.

### During a sudo grant

**A sudo grant is full root for its duration, and root can outlast the grant.**
The expiry removes the Hauswart rule, but it cannot undo what someone does while
they have root, such as adding their own rule. The feature protects against
accidents and keeps honest use limited in time. It does not protect against
someone who sets out to keep root. Grants limited to specific commands are
safer, but the task supports that through the API only, not yet in the dashboard.
Many commands also allow escaping to a shell.

### Registering passkeys

The server does not inspect the key behind a registration. An approver, or someone
with the server, can register a key held by a script that claims user presence and
verification. **`hauswart-admin passkeys pin` is the decision:** pin only keys you
registered yourself, on a device you can see. Whether a pinned passkey really asks
for a PIN is up to that passkey, not to Hauswart.

## Defences

| Area | Measure |
| --- | --- |
| Protected devices | Tasks signed by a pinned Ed25519 key, bound to the device, with a counter against replay and an expiry |
| Passkey approvals | Verified by the agent against passkeys pinned through a signed `keys.set`: signature, RP ID, exact origin, user presence and verification, a hash of the envelope as challenge. Local list of task types below a fixed ceiling, own counter, 24 hours, 20 per day |
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
| Logs | No unit, path or filter from the server, length limited, messages of users dropped on the device, gone from the server after an hour |
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
- **Passkeys are weaker than signatures**, and a swapped pin stays unnoticed. See
  [above](#with-control-of-the-server-on-a-device-with-pinned-passkeys).
- **A bad counter from the server** can still upset `hauswart-admin`, which trusts
  the reported counter of a device when it is higher than its own.
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
- **Logs hold what system services write.** Messages of users and their sessions
  stay on the device, but a system service can mention a username, a hostname or a
  path in its own message, and the kernel can name a program that crashed. Hauswart
  does not read the text of messages. Fetching logs is recorded in the audit log.
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

## Package search

Search fields in the dashboard and the desktop app suggest names. For packages, each
device sends the names of all packages its repositories offer, once a day and only
when they changed. The server keeps one copy per list, checks that the list is what
its hash says, and a device can only point itself at a list. For Flatpaks, the
server asks Flathub. Only the search term leaves the server, and answers are cached
for an hour. Start the server with `-flathub-search=false` to keep searches at home;
Flatpak searches then only find what devices have installed.

Suggestions are a help to type a name and never decide anything. A hacked device can
put names into its own list, which shows up in searches for that device and for
groups it belongs to.

## The inventory

Serial numbers, MAC addresses and lists of software are personal data once a device
belongs to someone, as are the names you add yourself. They stay on the server and in
its backups, only admins can see them, and devices are never deleted, so neither are
they. The inventory only reads, and changes nothing on a device. What a device reports
is unproven, so it should not decide anything. A hacked device can use it against
whoever reads it, which is why text is limited, and why a CSV export neutralises formulas.
Do not turn that off when you import the file.

## Reporting a problem

This is a private project. Open a ticket in the `HAUS` Jira project.
