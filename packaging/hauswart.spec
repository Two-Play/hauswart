# Packages the binaries from dist/, built by "make build". Go binaries carry
# their own build info, so the usual debuginfo and strip steps are skipped.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

Name:           hauswart
Version:        %{hw_version}
Release:        1
Summary:        Linux management for small groups
License:        AGPL-3.0-only
ExclusiveArch:  x86_64

%description
Hauswart manages Linux devices of a household or small office from a web dashboard.

%package server
Summary:        Hauswart management server with web dashboard

%description server
Server and web dashboard of Hauswart.

%package agent
Summary:        Hauswart management agent

%description agent
Agent that runs on every managed device.

%package admin
Summary:        Hauswart admin tool for signing tasks

%description admin
Runs on the admin's own computer and signs tasks for protected devices.

%package tray
Summary:        Hauswart desktop app for members
Recommends:     libsecret

%description tray
Shows the screen time left and what is connected, and files requests.

%package admin-gui
Summary:        Hauswart desktop app for reviewing and signing tasks

%description admin-gui
The window for what hauswart-admin approve does in a terminal.

%install
install -Dm755 %{hw_root}/dist/hauswart-server %{buildroot}/usr/bin/hauswart-server
install -Dm755 %{hw_root}/dist/hauswart-agent %{buildroot}/usr/bin/hauswart-agent
install -Dm755 %{hw_root}/dist/hauswart-admin %{buildroot}/usr/bin/hauswart-admin
install -Dm755 %{hw_root}/dist/hauswart-tray %{buildroot}/usr/bin/hauswart-tray
install -Dm755 %{hw_root}/dist/hauswart-admin-gui %{buildroot}/usr/bin/hauswart-admin-gui
install -Dm644 %{hw_root}/packaging/desktop/hauswart-tray.desktop %{buildroot}/usr/share/applications/hauswart-tray.desktop
install -Dm644 %{hw_root}/packaging/desktop/hauswart-admin-gui.desktop %{buildroot}/usr/share/applications/hauswart-admin-gui.desktop
install -Dm644 %{hw_root}/packaging/desktop/hauswart-tray-autostart.desktop %{buildroot}/etc/xdg/autostart/hauswart-tray.desktop
install -Dm644 %{hw_root}/packaging/desktop/hauswart.svg %{buildroot}/usr/share/icons/hicolor/scalable/apps/hauswart.svg
install -Dm644 %{hw_root}/packaging/systemd/hauswart-server.service %{buildroot}/usr/lib/systemd/system/hauswart-server.service
install -Dm644 %{hw_root}/packaging/systemd/hauswart-agent.service %{buildroot}/usr/lib/systemd/system/hauswart-agent.service
install -Dm644 %{hw_root}/packaging/server.env %{buildroot}/etc/hauswart/server.env
install -Dm600 %{hw_root}/packaging/notify.env %{buildroot}/etc/hauswart/notify.env
install -Dm644 %{hw_root}/packaging/hauswart.sysusers %{buildroot}/usr/lib/sysusers.d/hauswart.conf

# Neither package restarts its service: a running agent may be the very
# process that is installing this update.
%post server
systemd-sysusers hauswart.conf || :
chown hauswart:hauswart /etc/hauswart/notify.env || :
[ -d /run/systemd/system ] && systemctl daemon-reload || :

%post agent
[ -d /run/systemd/system ] && systemctl daemon-reload || :

# $1 is 0 on a real removal and 1 on an upgrade.
%preun server
if [ "$1" = 0 ] && [ -d /run/systemd/system ]; then
	systemctl disable --now hauswart-server.service || :
fi

%preun agent
if [ "$1" = 0 ] && [ -d /run/systemd/system ]; then
	systemctl disable --now hauswart-agent.service || :
fi

%files server
/usr/bin/hauswart-server
/usr/lib/systemd/system/hauswart-server.service
/usr/lib/sysusers.d/hauswart.conf
%dir /etc/hauswart
%config(noreplace) /etc/hauswart/server.env
%attr(0600,root,root) %config(noreplace) %verify(not user group) /etc/hauswart/notify.env

%files admin
/usr/bin/hauswart-admin

%files agent
/usr/bin/hauswart-agent
/usr/lib/systemd/system/hauswart-agent.service

%files tray
/usr/bin/hauswart-tray
/usr/share/applications/hauswart-tray.desktop
/etc/xdg/autostart/hauswart-tray.desktop
/usr/share/icons/hicolor/scalable/apps/hauswart.svg

%files admin-gui
/usr/bin/hauswart-admin-gui
/usr/share/applications/hauswart-admin-gui.desktop
