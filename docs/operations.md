# Operating Hauswart

The server runs on one machine on site, at home or in the office. Devices reach it
through a VPN, both on site and on the road, so it never needs a port on the
internet.

## Install the server

```bash
make packages
sudo dnf install ./dist/hauswart-server-0.1.0-1.x86_64.rpm
```

On Debian-based systems use the `.deb`. For other distributions, unpack the
tarball and run `sudo ./install.sh server`.

The package does not start the service. Set the address first, as described
below, then run:

```bash
sudo systemctl enable --now hauswart-server
sudo cat /var/lib/hauswart-server/initial-admin-password
```

Sign in as `admin` with that password and change it right away. The file is
readable only by the service account and root, and you can delete it afterwards.

## Bind the server to the VPN

The server listens only where `/etc/hauswart/server.env` says. The default is
`127.0.0.1`, which is safe but reachable from nowhere else.

```bash
HAUSWART_ARGS=-addr 10.8.0.1:8443 -url https://10.8.0.1:8443
```

- `-addr` is the address the server binds to. Use the VPN address of the
  server, never `:8443` or `0.0.0.0:8443`.
- `-url` is what devices connect to. Its host name goes into the TLS
  certificate, and the certificate is reissued when that changes.
- `-hosts` adds more names or addresses to the certificate.
- `-ca-scope` lists domains and CIDR ranges the CA may ever issue for, for
  example `-ca-scope home.arpa,10.8.0.0/24`.

**Decide on the scope before the first start.** The CA is limited to these names
and to the server's own addresses, so a stolen CA key cannot impersonate other
websites to your devices. The limit is part of the CA and cannot change later. A
new scope means a new CA, and every device has to be enrolled again.

After a change, run `sudo systemctl restart hauswart-server`.

If the VPN comes up after the server, binding fails and systemd retries every
five seconds until the address exists.

### WireGuard

Example for the server at home, in `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <server private key>

[Peer]
# One block per device
PublicKey = <device public key>
AllowedIPs = 10.8.0.2/32
```

Each device gets a matching configuration with its own address and
`AllowedIPs = 10.8.0.0/24`, so that only Hauswart traffic uses the tunnel.
Forward UDP port 51820 on your router to the server. That is the only port open
to the internet.

```bash
sudo systemctl enable --now wg-quick@wg0
```

On Fedora, open the WireGuard port and allow Hauswart on the tunnel only. The
`internal` zone applies to `wg0` and to nothing else:

```bash
sudo firewall-cmd --permanent --add-port=51820/udp
sudo firewall-cmd --permanent --zone=internal --add-interface=wg0
sudo firewall-cmd --permanent --zone=internal --add-port=8443/tcp
sudo firewall-cmd --reload
```

### Tailscale

Tailscale needs no router configuration. Install it on the server and on every
device, then find the server's address:

```bash
tailscale ip -4
```

Use that address for `-addr`. For `-url` you can use the same address or the
MagicDNS name, for example `https://hauswart.tailnet-name.ts.net:8443`, with
`-hosts` listing the other one.

Restrict access in the Tailscale ACLs to your own devices.

## Add a device

```bash
sudo dnf install ./dist/hauswart-agent-0.1.0-1.x86_64.rpm
```

In the dashboard, choose **Add device**, run the shown command on the device,
then start the service:

```bash
sudo systemctl enable --now hauswart-agent
```

The agent only connects outwards, so a device needs no open port.

Enrollment also adds the Hauswart CA to the system store of the device.

On atomic systems such as Silverblue, Kinoite and CoreOS, Hauswart uses
`rpm-ostree`. Installed packages are usable right away. Removing a package and
system updates take effect after the next reboot, and Hauswart does not reboot a
device by itself.

## Suspend or remove a device

**Suspend** holds a device back for a while, for example while it is lent out. It
keeps reporting, so the dashboard still shows it, but:

- It runs no tasks. They wait until you resume it.
- Nobody can file requests for it, and open requests cannot be approved.
- Running sudo grants end, and everyone at the device gets a notice. People go on
  working as before.

**Resume** undoes all of that.

**Remove** is final. The device loses access at once and comes back only by
enrolling it again, as a new device.

## Block access to a device

Suspending changes what Hauswart does. To change what people at a device can do,
run **Block access** on it:

| Mode | What happens |
| --- | --- |
| Block the screen | Sessions are locked, and locked again within seconds whenever someone unlocks them. Work stays open. |
| Full-screen notice | Your text and picture cover the screen, and the sessions behind are locked. Nobody at the device can close it, and work stays open. |
| Refuse logins | Running sessions get a minute's warning, then they end, and unsaved work is lost. New logins are refused. |
| Open access again | Lifts the block. |

- **Who:** It applies to the Linux users you name, or to every ordinary account if you
  name none. System accounts and root are never affected.
- **Local admins:** Without names, local admins are locked out as well. Keep root over
  SSH, or give the block an end.
- **How:**
  - For the whole device, logins are refused through `/run/nologin`, which
    `pam_nologin` honours on Fedora and Debian.
  - For single people, any session they start ends at once.
- **End:** A block can end after some hours, at most 30 days. The device keeps to
  the end without the server, and a restart keeps the block.
- **Signatures:** On a protected device, every mode needs a signature, opening
  included.
- **Full-screen notice:**
  - It needs the package `hauswart-tray` on the device. The agent installs the kiosk
    compositor `cage` itself.
  - It runs as the system account `hauswart-block` on console 9. Whoever switches
    away to a session it is about gets it back within seconds, while others can
    reach the login screen.
  - For single people it shows while their session is in front.
  - It ends with the agent, so a stopped or removed agent leaves no block behind.
  - The picture is a PNG or JPEG of at most 512 KB and 4096 by 4096 pixels, and
    travels in the signed task.

## Protect devices with signatures

Without this, whoever controls the server can reach root on your devices. With
it, tasks need a signature made on your own computer. Do this on the computer
you sign on first.

The price: on a protected device, the dashboard only queues tasks. You confirm
them with `hauswart-admin approve`, which does not work from a phone. For a part of
the tasks, [a passkey](#approve-with-a-passkey) can do that, at a lower level of
security.

Create two dedicated keys. Keep the second one offline, for example on a USB
stick. It is your way back if you lose the first.

```bash
sudo dnf install ./dist/hauswart-admin-0.1.0-1.x86_64.rpm
ssh-keygen -t ed25519-sk -f ~/.ssh/hauswart
ssh-keygen -t ed25519 -f /run/media/usb/hauswart-offline
ssh-add -c ~/.ssh/hauswart
```

Without a FIDO key, use `-t ed25519` for the first key as well.

Log in with the fingerprint from the server log, and pin both keys:

```bash
hauswart-admin login --server https://10.8.0.1:8443 --ca-fingerprint <fingerprint>
hauswart-admin keys add ~/.ssh/hauswart.pub /run/media/usb/hauswart-offline.pub
```

For a new device, use the command from this tool instead of the dashboard, so
that the server has no say in what you paste as root:

```bash
hauswart-admin enroll-command
```

To protect a device that is already enrolled, run the output of
`hauswart-admin trust-command` on it and restart the agent.

Enrollment prints the device ID. Compare it, then name the device. The tool
refuses to sign for a device without a name, because the names the server shows
are not trustworthy.

```bash
hauswart-admin devices
hauswart-admin name <device-id> laptop-anna
```

Daily use:

```bash
hauswart-admin approve
hauswart-admin approve --all
hauswart-admin start-password --device <device-id> --user anna
```

`approve --all` shows every waiting task in full and then asks once. The admin app
does the same with **Sign everything**. A security key still wants a touch per
task, because each task carries a signature of its own.

`approve` shows each task in full. Read it, especially what it says about root.
Start passwords can only come from this tool on a protected device.

To replace a key, add the new one with `keys add`, remove the old one from the
`keys` list in the tool's `admin.json`, and run `rotate-keys` for each device
while you still hold a working key. Signed tasks expire after 30 days, so a device
that stays off longer needs a new one.

The counter of each device lives in `admin.json`. If a second computer signs too,
or you restore an old copy, the tool catches up from the device's report, up to
about a million ahead. It refuses anything beyond that, because the report passes
through the server and could be false. If the device really is that far ahead,
copy its counter from your newest `admin.json`.

If you lose every key, or a device loses `/var/lib/hauswart/guard.json`, that
device refuses work until you enroll it again. That is deliberate: a state that
can be reset could be replayed.

## Approve with a passkey

`hauswart-admin approve` does not work from a phone. A passkey does, for tasks that
stay within a list on each device. **It is weaker than signing:** read
[what a hacked server can do with it](security.md#with-control-of-the-server-on-a-device-with-pinned-passkeys)
before you pin one. Signing keeps working as before, and everything outside the
list stays with `hauswart-admin`.

### What it needs

**A DNS name.** WebAuthn does not work with a bare IP address, so
`-url https://10.8.0.1:8443` is not enough. Use a name that resolves to the VPN
address on all your devices, for example `https://hauswart.home.arpa:8443` through
the DNS server of your VPN, or the MagicDNS name of Tailscale.

The name has to be within the scope of the CA, which cannot change later. It is
when it is the host in `-url` or `-hosts` at the first start, or below a domain in
`-ca-scope`. A server set up with addresses only needs a new CA, and every device
has to be enrolled again.

The passkey belongs to that exact name and port. If you change `-url` later, all
passkeys have to be registered and pinned again.

**A browser that trusts the CA.** WebAuthn refuses a page with a certificate
warning, so accepting the warning does not help. On a computer, see
[Browser trust](#browser-trust). A phone is not enrolled, so it needs the CA by hand.
Download `https://<server>:8443/ca.pem` on the phone and compare the fingerprint
with the one in the server log:

- **Android:** Settings, Security and privacy, More security settings, Encryption
  and credentials, Install a certificate, CA certificate. The wording differs
  between makers.
- **iPhone and iPad:** open the file and install the profile in Settings. Then
  turn it on under General, About, Certificate Trust Settings. Without this second
  step, it does not count.

A CA on a phone can only ever vouch for the names in its scope, so a stolen CA key
reaches no other websites from there.

### Register and pin

1. Sign in to the dashboard as an approver or admin, and open **Approvals**. Choose
   **Add passkey** on the phone or computer that will approve. Do not do this while
   you have any doubt about the server.
2. On the computer you sign on, pin it on each device where it should work:

   ```bash
   hauswart-admin passkeys list
   hauswart-admin passkeys pin --device ID --passkey N
   ```

   The tool shows the resulting list and asks before it signs. A passkey is refused
   if it belongs to another server than the one you logged in to.

Pins end after 180 days. `hauswart-admin passkeys renew --device ID` extends them
from what this computer remembers, without asking the server. To remove a passkey
that was lost, or all of them after trouble with the server:

```bash
hauswart-admin passkeys unpin --device ID --name phone
hauswart-admin passkeys unpin --device ID
```

The device has to be online to receive the change. Check its journal before you
rely on it, because a hacked server can withhold the task.

### Limit what a passkey may approve

`pkg.upgrade` and `power.cancel` run without any approval, so this list does not
restrict them. Each device has its own list in `/var/lib/hauswart/agent.json`, which the server
cannot change:

```json
"passkey_types": ["pkg.upgrade", "notify.send"]
```

Removing `pkg.remove` and `flatpak.install` is a sensible first step. An empty list
turns passkeys off on that device. Restart the agent after a change. Types beyond
the default stay refused, so the list can only get shorter. The default is
`pkg.install`, `pkg.remove`, `pkg.upgrade`, `flatpak.install`, `power.reboot`,
`power.shutdown`, `power.cancel`, `notify.send`, `screen.extend` and `access.set`.
A block approved with a passkey must end within 24 hours. A device keeps the list it
was enrolled with, so add newer types to its file to approve them with a passkey.

To see what passkeys approved on a device:

```bash
journalctl -u hauswart-agent --grep 'approved by passkey'
```

## Roles

Under **Users**, every account has a role:

| Role | For | May do |
| --- | --- | --- |
| Admin | You | Everything |
| Approver | Someone who decides, but does not administer, such as a parent or a team lead | See all devices and requests, decide requests of others, approve tasks with a passkey |
| Member | Everyone else | File requests for the devices assigned to them |

Assign devices to members in the same table. A new device is assigned to nobody at
first, and a member without devices sees none.

## Approval rules

Under **Groups**, **Approval rules for all devices** decide who answers requests,
and each group can make them stricter. For each kind of request, choose:

- **Approve automatically**: the request is approved when it is filed.
- **Approver decides**: an admin or approver decides. This is the default.
- **Only an admin decides**: approvers see the request, but cannot decide it.
- **Not allowed**: the request is refused when it is filed.

Packages and Flatpaks on the lists of automatic apps are installed without asking,
as long as an approver decides their kind and the policy does not forbid them.
Where groups disagree, the strictest rule wins. sudo always needs a person. On a
protected device, an automatic approval still waits for a signature.

Once approved, a request shows how its task went: waiting for a signature,
running, done or failed. For a failure, admins and approvers also see what the
device said. Members see only that it failed.

A device without Flatpak, such as a minimal desktop, gets the package `flatpak`
from its package manager before the first Flatpak is installed. GNOME and Plasma
read the folder of Flatpak apps at login only, so everyone logged in is told that
new apps show in the menu after the next login.

## Browser trust

Whether a browser honours the system store depends on the distribution. This is
measured by `test/browsers.py`:

| Distribution | Browser | CA from the system store |
| --- | --- | --- |
| Fedora 44 | Firefox (RPM) | trusted |
| Fedora 44 | Chromium (RPM) | trusted |
| Fedora 44 | Google Chrome | trusted |
| Debian 13 | Firefox ESR | not trusted |
| Debian 13 | Chromium | not trusted |
| Arch | Firefox | trusted |
| Arch | Chromium | trusted |
| openSUSE Tumbleweed | Firefox | not trusted |
| openSUSE Tumbleweed | Chromium | not trusted |

| Fedora 44 | Firefox (Flatpak from Flathub) | not trusted |

Where the store is not trusted, as on Debian and openSUSE, the agent adds the CA
through the policies of Firefox and Chromium, which the same test shows to work.

Firefox from Flathub runs in a sandbox and trusts neither the system store nor the
policies in `/etc/firefox`, and a policy in its `systemconfig` extension did not
help in a measurement either. Import the CA by hand there, as described below.
Chromium from Flathub is not measured yet.

Where the store is not used, and on computers that are not enrolled, import the
CA by hand. Download it from `https://<server>:8443/ca.pem`. Accept the warning
for this one download, and compare the SHA-256 fingerprint with the one in the
server log before you trust the file.

- **Firefox:** Settings, Privacy & Security, Certificates, View Certificates,
  Authorities, Import. Tick "Trust this CA to identify websites".
- **Chromium and Chrome:** Settings, Privacy and security, Security, Manage
  certificates, Authorities or Local certificates, Import.

Files can be deployed only below `/etc/hauswart.d` by default. To allow more,
edit `allowed_paths` in `/var/lib/hauswart/agent.json` on that device and
restart the agent. Think before widening it: a path from which the system
executes files gives the server root on that device.

## Look into a device

**Details** on a device shows:

- **Resources:** disk, memory and load of the last 24 hours or 7 days. A gap means
  the device was off.
- **Updates:** what is pending and whether a reboot is needed. Devices check a few
  times a day and after every package task. Whether a reboot is needed can read
  "unknown", which is normal in a container. On Arch and Debian only a new kernel
  counts, unless a package left `/run/reboot-required`.
- **Accounts and rights:** accounts from UID 1000, their groups, sudo rights and
  running grants. Groups in red amount to root. On openSUSE, every account shows
  a sudo rule, because its default rule lets anyone who knows the root password
  use sudo.
- **Logs:** fetched when you ask, from a device that is online. You see the
  Hauswart agent and system messages from warning up. Messages of users stay on
  the device, and the server deletes fetched logs after an hour. A device without
  a journal says so.

The device card warns when a disk is at least 90 percent full and when a device
certificate has less than 30 days left. An agent renews long before that, so this
means the device has been off for months or cannot reach the server. See
[Certificates](#certificates).

## Prove how a device started

A device with a TPM 2.0 proves how it started, through measured boot. The agent
registers the TPM with the server on its own, then sends a proof when it starts and
every six hours: the TPM signs what the firmware recorded on the way, the boot loaders,
the Secure Boot keys and the kernel parameters, together with a fresh value from the
server, so an old proof cannot be replayed.

The first proof is the boot to compare with. **Details** of a device, tab **Boot**,
shows it next to the last one. What differs stays there until you accept it:

- **Alarm**, with a notification and a red mark on the card: Secure Boot was
  switched off, its keys changed, the kernel parameters changed (such as
  `init=/bin/bash`), the device came with another TPM, or a proof did not check out.
- **Note**: the firmware changed, as after a BIOS update, the list of revoked boot
  loaders grew, or, with Secure Boot off, another boot loader started.
- Updates of the kernel, grub and shim while Secure Boot is on raise nothing:
  Secure Boot checked their signature.

A device that reports but has sent no proof for three days gets a warning. Nothing
stops a device on its own; you decide. Accept a boot once you know where a change came
from, with **Accept this boot**.

Devices without a TPM, or with the TPM switched off in the firmware, show nothing
here. Without Secure Boot, a device can still prove its firmware and kernel
parameters, but not which boot loader and kernel started.

**Another TPM** shows when the mainboard was replaced, the TPM cleared in the firmware,
or the files of the agent copied to another computer. Its proofs count once you accept
it, and the next one becomes the boot to compare with.

## Keep an inventory

**Inventory** in the dashboard lists every device, for admins only. A device sends its
hardware, installed packages, system-wide Flatpaks, network cards and security state
at start, every six hours and after a package task. Flatpaks a person installed for
themselves and snaps are not listed. All of it comes from the device, so a hacked device
can lie. It is as old as the time shown in the details, usually up to six hours, and
longer for a device that was off. If a device cannot list its packages, the last list stays.

The security state covers disk encryption, screen lock and firewall, and whether the
device has a TPM 2.0, whether it starts with Secure Boot, and the Host Security ID of
fwupd if that is installed (`fwupdmgr security`, from HSI:0 for unprotected firmware to
HSI:4; a `!` means a runtime problem). A device without a TPM 2.0 or Secure Boot gets a
note that it cannot prove how it started, not a warning: older PCs often have neither
switched on, and the firmware settings usually can.

Open a device to add what only you know: inventory number, person, location, purchase
date, warranty and a note. A warranty shows a warning from 30 days before its end until
30 days after. **Software** finds a package across all active devices, with its
versions. A revoked device keeps its details, marked as such.

**Export CSV** gives one line per device, and the audit log records it. A value that a
spreadsheet would read as a formula starts with `'` and every field is quoted, as a
device picks its own name. Excel with German settings may show all of a line in one column
at first. Import the file with a comma as separator.
Devices without an agent, such as printers, are not listed.

## Certificates

Device certificates last two years. Agents renew theirs on their own once a
third of the lifetime is left, without a restart, and keep their private key.
There is nothing to do as long as a device comes online at least once in those
last eight months.

A device that stays off for longer has an expired certificate and is refused.
Its log shows `poll failed`. To bring it back, create a new command with
**Add device** and run it on that device. It then appears as a new device, and
you can revoke the old entry.

The server's own certificate also lasts two years. It is replaced at a service
start once less than 30 days are left, so restart the server at least once a
year, which any system update with a reboot does. The CA lasts ten years.

### Service certificates

To run a home service on trusted HTTPS, open **Certificates** in the dashboard and
enter its host names or IP addresses. They have to be inside the scope chosen with
`-ca-scope`, and they cannot be names of the Hauswart server. A CA that was created
without constraints issues no service certificates.

**Copy the private key at once.** It is shown only in that dialog and stored
nowhere. If it is lost, issue a new certificate. The dashboard lists everything
issued with its expiry, and turns red 30 days before the end. Renewal is manual,
and the limit is 397 days.

## Restart and shut down devices

Choose **Restart device** or **Shut down device** in the action dialog of a device,
with the minutes of warning. Terminals and desktops see the warning, and new
logins stop for the last five minutes. On a protected device, sign it with
`hauswart-admin approve`, which has to happen within the hour.

**Cancel restart or shutdown** stops it. It needs no signature, so it works quickly.
On GNOME, the warning stays on the screen until someone closes it, and the message
about the cancellation appears after that.

Agents come back on their own, as long as the service is enabled.

## Live terminal

**Terminal** on the card of a protected device opens a shell on it in the dashboard,
as root or as one of its people, for at most 240 minutes. Your own passkey approves
each session, and it has to be pinned on the device like any other: see
[Approve with a passkey](#approve-with-a-passkey). Without a passkey, or from a
terminal, the admin tool does the same with a signature:

```sh
hauswart-admin terminal --device ID                       # as root
hauswart-admin terminal --device ID --user anna --minutes 30
```

The device connects to the server for the session, the server passes everything on
between it and your browser, and nothing needs a port on the device. A session ends
when the shell ends, when nobody types for 15 minutes, when its time is up, or a
minute after you closed the window. An approval that has not started a session within
15 minutes lapses.

People at the device are told: a notification when it starts and when it ends, and
the desktop app shows who works on the device and until when, for as long as it
runs. The audit log has the start and the end with who, as whom and how long; the
device's own log has them with the passkey that approved it. What you type and see
is recorded nowhere.

Only the admin who asked for a session can open it, and approvers cannot approve one.
Unprotected devices have no live terminal, because nothing but the server would
decide who gets a shell.

### Warning about a server on the internet

Hauswart is meant for the local network, or for a VPN. The dashboard warns admins
when the server listens on a public address, or when a request came from one, which
usually means a forwarded port on the router. It does not ask a service on the
internet, which would learn about your server. If the public address is meant to be
there, as with some VPNs, start the server with `-allow-public`.

## Send a message to a desktop

**Send desktop message** shows a popup titled `Hauswart` to everyone logged in to a
desktop, or to one Linux user. The task fails if no session took it, which is not
the same as someone reading it: GNOME shows one banner at a time and keeps it up
until the user is active. A device that is off or offline for more than an hour
does not show it later. The fixed warnings about restarts are in English.

## Keep devices in a defined state

A policy belongs to a group and applies to its members, which need pinned signing
keys. Under **Groups**, choose **Create policy** on a group. Nothing changes on a
device until you sign:

```bash
hauswart-admin approve
```

`approve` shows the whole policy and what changed since you last signed for that
device. The last signed policies stay on your computer, in `policies` next to
`admin.json`. If the same policy waits for several devices, `a` signs it for all of
them.

The group page shows where each device stands:

| State | Meaning |
| --- | --- |
| Up to date | The device has this policy and nothing differs. |
| Waiting for signature | Run `hauswart-admin approve`. |
| On its way | Signed, the device has not picked it up yet. |
| Not up to date | The device has something else, for example after a rejected signature. Save the policy again. |
| Deviation | The device has the policy, but could not do all of it. The reason is listed. |
| Contradiction | The groups of this device disagree. The device keeps what it has until you change one of them. |
| No signing keys | Pin signing keys on this device first. |

A device applies a policy at start, right after receiving it and every 15 minutes,
with or without the server.

A device in several groups gets all their rules. Lists add up, and the stricter
security rule wins.

When an entry leaves a policy, packages and files stay on the device. CAs are
removed. Removing a device from its group needs a signature as well.

A CA in a policy takes over a CA of the same name that was installed by hand, and
leaves with the policy.

A device can stay **Not up to date** after you rejected a signature, or when the
signed task expired or failed. Saving the policy again queues it anew.

### Updates

With a maintenance window, a device installs updates once per window, in the time
zone of the policy or else its own. A device that was off for a window waits for the
next one. With the restart rule, it restarts in the window if an update needs that,
after a warning of 10 minutes.

### Security rules

- **Firewall:** firewalld or ufw is kept on. If neither is installed, this shows as
  a deviation. Add `firewalld` to the required packages to fix that.
- **Disk encryption and screen lock** are only checked. Neither can be forced on a
  running system. The screen lock can only be seen in a running GNOME or Plasma
  session, and otherwise says unknown.

### Screen time

Each rule names a Linux user and their times per day. A day without a time means no
session on that day. Warnings come 15, 5 and 1 minutes before the end. At the end
the session locks, and a minute later it ends. **Unsaved work is lost then.**

A rule can also have **minutes per day**. The device counts the time someone's
session is in front, locked or not, because a session can claim to be locked, and the session ends when the minutes are used up or the time
window closes, whichever comes first. A rule with minutes and no windows allows any
time of the day. The count starts over at midnight in the policy's time zone.

The page **Screen time** shows the rules of all groups by person, and saves them in
the policy of each group.

To give someone more time today, choose **Extend screen time** on the device. This
is possible with a passkey, at most four hours ahead and until midnight.

Policies with screen time need a time zone. The dashboard fills in that of your
browser, and warnings use the language you were using when you saved.

## Log in through Authentik

Accounts can come from [Authentik](https://goauthentik.io). The local admin stays as
an emergency access for when Authentik is away, so keep its password.

In Authentik, create an **OAuth2/OpenID provider** and an application for it:

- Client type: confidential.
- Redirect URI, strict: `https://hauswart.example/auth/oidc/callback`, with the name
  from `-url`.
- Grant types: authorization code.
- Signing key: choose one. Hauswart refuses tokens that are only signed with the
  client secret.
- Subject mode: leave the default, the hashed user ID. The sync of accounts relies on it.
- Scopes: `openid`, `profile` and `email`.

Then write `/etc/hauswart/oidc.env` with mode 0600:

```bash
OIDC_ISSUER=https://auth.example/application/o/hauswart/
OIDC_CLIENT_ID=...
OIDC_CLIENT_SECRET=...
OIDC_ADMIN_GROUP=hauswart-admins
OIDC_APPROVER_GROUP=hauswart-approvers
# The old name OIDC_PARENT_GROUP still works.
# Optional: only these people may log in.
OIDC_ALLOWED_GROUP=hauswart-users
# Optional: a certificate from elsewhere. The Hauswart CA is always trusted.
OIDC_CA_FILE=/etc/hauswart/authentik-ca.pem
# Optional: bring all accounts over every 5 minutes, and end access for those who
# are gone. The token needs read access to users.
AUTHENTIK_URL=https://auth.example
AUTHENTIK_TOKEN=...
```

Restart the server. The login page then offers **Log in with Authentik**.

Roles come from the groups, at every login and sync. Such accounts cannot be changed
in Hauswart, and they have no password here. The name becomes the Linux account, so
it has to be one: lower case, without spaces. An account of the same name that was
created here stays separate, and that person cannot log in through Authentik until
one of the two is renamed.

Without `AUTHENTIK_TOKEN`, an account only appears at its first login, and someone
you deactivate stays logged in for up to 12 hours.

### Log in on devices with Authentik accounts

A policy can let accounts from the LDAP outpost of Authentik log in on Fedora and
Debian. Local accounts go on working. After one online login, a laptop also accepts
the password without a connection, and it keeps doing so.

In Authentik:

1. Create an **LDAP provider** with the default authentication flow as its bind
   flow, and an application for it. The bind flow must not ask for a second factor.
2. Deploy an **LDAP outpost** for it. It needs TLS, and Hauswart refuses plain LDAP.
   Its certificate must come from a CA of its own, such as Authentik's, and **not
   from the Hauswart CA**: a hacked server holds that one and could pose as the
   directory. `hauswart-admin approve` warns about this.
3. Create a service account for reading, and give it the right to search the
   directory.

In the policy of a group, fill in **Accounts from a directory**:

| Field | Example |
| --- | --- |
| Address | `ldaps://auth.example:6636` |
| Base DN | `dc=ldap,dc=goauthentik,dc=io` |
| Reading account | `cn=ldapreader,ou=users,dc=ldap,dc=goauthentik,dc=io` |
| CA | The certificate of the CA that signed the outpost's certificate |

The password of the reading account ends up on the server and on every device of the
group, so that account must be able to do nothing but read.

On a device with SELinux, the agent allows the port of the address for sssd. PAM
stays as it is when the policy ends: without a domain, it does no harm.

Screen time and sudo grants work for these accounts as well. Their IDs start at 2000.

An account named like a local one on a device cannot log in there: local accounts
stay local.

A screen time rule follows the account, and not only its name: a device remembers the
ID the first time it sees the name, so renaming the account in Authentik leads
nowhere. That needs the device to have seen the name once, which it does as soon as it
has the policy and can reach the directory.

### Shares

**Shares** in a policy appear in `/media` at login, as `lena-Family` for the folder
`Family`, with the login password, so nothing about them is stored. Programs cannot run from
a share. File managers list
them there. They are not in the home directory on purpose: the mount runs as root, and
a user could put a link there. The share has to know the same password, and that is
why this needs the directory login. Local accounts get no shares. A share out of reach
adds at most 8 seconds to a login.

If the password changes in Authentik, a laptop that was offline knows the old one
until it has logged in once on site.

### Nextcloud

Each person logs in to Nextcloud for themselves, so no policy holds a password.

- **Sync client:** installs the client, starts it at login and points it at your
  server.
- **Network drive:** mounts the files in `~/Nextcloud` without a copy. Everyone creates
  an app password in Nextcloud once, and stores it in their keyring:

  ```bash
  secret-tool store --label=Nextcloud service hauswart-nextcloud
  ```

  At the next login the drive is there. On a laptop without a connection it stays
  away and tries again, every minute.


### Wi-Fi and printers

**Wi-Fi** in a policy lists networks with a password, WPA2 or WPA3 Personal, hidden
or not. The agent writes a NetworkManager connection per network to
`/etc/NetworkManager/system-connections`, readable by root only, and removes its
own when a network leaves the policy. Connections that were there before stay. The
password is in the policy, so admins see it in the dashboard; the signing tool shows
only its length.

**Printers** need an address such as `ipp://drucker.local/ipp/print` and no driver:
the printer has to speak IPP Everywhere, as most printers since 2012 do. The agent
sets up a CUPS queue `hauswart-<name>` for everyone on the device, makes one of them
the default if you choose, and removes its own queues that leave the policy.

A device without NetworkManager or CUPS shows that as a deviation, and admins hear
about it once.
## Desktop apps

**`hauswart-tray`** is for everyone on a device. It shows the screen time left and the
connected shares, files requests, and takes the Nextcloud app password, which it
keeps in the keyring. Install the package `hauswart-tray` on a device, or put it into
the required packages of a policy. It starts at login.

KDE shows it in the system tray. GNOME has no tray without an extension, so open
**Hauswart** from the app menu there. Warnings arrive as notifications either way.

A request needs a Hauswart account whose Linux user is the person at the device.

### What people at a device are told

The agent shows a popup when Hauswart changes something for someone, and the
**History** tab of the desktop app lists the same, with the person's own requests:

| Change | Who sees it |
| --- | --- |
| Their request waits for a signature, was denied, is done, or failed | whoever filed it |
| sudo granted or taken back, ends in 5 minutes, ended | the person |
| Account locked, unlocked, new password, group added or removed | the person |
| Software installed, removed, updated, or a failed change | everyone at a desktop |
| New or removed rules of the device | everyone at a desktop |

Popups use the language of the policy, the history that of the desktop. They
need a desktop with a notification service, which GNOME and Plasma have, and they
work without the desktop app. While someone is at a desktop, the agent asks the
server every minute how the requests of the device stand. A device keeps the last
200 changes, and requests of the last 30 days.

**`hauswart-admin-gui`** does on your own computer what `hauswart-admin approve` does in
a terminal, from the package `hauswart-admin-gui`. Log in once with `hauswart-admin
login`, and pin keys there as well. Keys stay in your ssh-agent, so a security key
asks for its touch as usual.

The apps are built apart from everything else, as they link against graphics
libraries:

```bash
make gui
```

### Application rules

Under **Applications** in a policy, each Linux user gets rules of their own, and
everyone else on the device stays free:

- **No programs from home or temporary folders** stops what someone downloads.
- **Forbidden programs** stops single programs for this person, by full path.
- **Only allow the applications below** is the strict rule. The list offers what the
  devices of the group have. Everything else with a launcher is blocked, new
  applications included, and only the listed Flatpaks run.
- **Flatpaks** can be limited on their own, to a list or by exceptions.

A device installs `fapolicyd` and `malcontent` for this. The rules that come with
`fapolicyd` would apply to everyone, so they are set aside, and they come back when the
last rule ends. Fedora and Debian are tested, with GNOME and Plasma.

A rule that cannot be applied shows as a deviation, and the device goes on working.

## Package search

Fields for packages and Flatpaks in the dashboard and in the desktop app suggest names
while you type. Packages come from the repositories of the devices, which each agent
lists once a day. A device that was just enrolled finds only what is installed until
then. Flatpaks come from Flathub, through the server: only the search term goes
there. To turn that off, add `-flathub-search=false` to `HAUSWART_ARGS` in
`/etc/hauswart/server.env`.

## Notifications for admins

Hauswart tells admins through ntfy, mail or both:

- **New request:** who asks for what kind of thing, on which device.
- **Failed task:** of any kind, with the device and, for a request, who asked. What
  the device said stays in the dashboard, under **Tasks**.
- **New deviation from a policy:** a device that cannot reach its policy, such as a
  Flatpak that does not install. A deviation is told once, not with every report,
  and what the device put right itself is not told at all.

The dashboard counts the same at **Tasks**, for the failures of the last day, and at
**Groups**, for devices that differ from their policy.

To turn notifications on, edit `/etc/hauswart/notify.env`. Everything is off until
you do. Either channel works alone.

```bash
NTFY_URL=https://ntfy.example.org/a-long-random-topic
NTFY_TOKEN=tk_...
SMTP_HOST=mail.example.org
SMTP_PORT=587
SMTP_TLS=starttls
SMTP_USER=hauswart@example.org
SMTP_PASSWORD=...
SMTP_FROM=Hauswart <hauswart@example.org>
SMTP_TO=admin@example.org, second-admin@example.org
```

- The file must keep mode `0600` and belong to the `hauswart` user, as installed.
  With other modes, the server does not use it and logs why.
- `SMTP_TLS` is `starttls`, `tls` for port 465, or `none`. A password needs TLS,
  and so does an ntfy token, except on the same machine.
- The Hauswart CA is trusted in addition to the system's, so a mail or ntfy server
  with a service certificate works.
- Use a mail account and an ntfy token only for this. The ntfy topic works like a
  password, so make it long and random.

Run `sudo systemctl restart hauswart-server`, and look for
`admin notifications are on` in the log. Failed attempts show up there too.

The file is not part of backups, so keep the credentials somewhere else as well.

## Back up

```bash
sudo hauswart-server backup -out /root/hauswart-$(date +%F).tar.gz
```

This works while the server runs. The archive holds the database and the
certificate authority.

**Treat the archive like a password.** It contains the CA private key, so
whoever has it can impersonate your server to your devices. It is created
readable only by its owner. Encrypt it before it leaves the machine:

```bash
gpg --symmetric hauswart-2026-11-05.tar.gz
```

Devices do not need a backup. They hold only their own certificate and can be
enrolled again.

## Restore

Restore refuses to overwrite an existing database, so stop the service and
clear the directory first:

```bash
sudo systemctl stop hauswart-server
sudo rm -rf /var/lib/hauswart-server/*
sudo hauswart-server restore -in /root/hauswart-2026-11-05.tar.gz
sudo chown -R hauswart:hauswart /var/lib/hauswart-server/
sudo systemctl start hauswart-server
```

Enrolled devices keep working, because the CA is the same. Without a backup, the
CA is lost and every device has to be enrolled again.

Devices send their inventory again within six hours, so it catches up by itself.

## Development

For local work, `-dev-http 127.0.0.1:8080` additionally serves the dashboard
without TLS. It accepts only loopback addresses. Agents always use TLS.
