# Operating Hauswart at home

The server runs on one machine at home. Devices reach it through a VPN, both at
home and on the road, so it never needs a port on the internet.

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

Restrict access in the Tailscale ACLs to the devices of your household.

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

Not measured: Flatpak browsers, Arch and openSUSE. Flatpak apps run in a sandbox
and may not see the system store.

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

## Development

For local work, `-dev-http 127.0.0.1:8080` additionally serves the dashboard
without TLS. It accepts only loopback addresses. Agents always use TLS.
