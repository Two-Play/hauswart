# Packages the binaries from dist/, built by "make build". Go binaries carry
# their own build info, so the usual debuginfo and strip steps are skipped.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none

Name:           hauswart
Version:        %{hw_version}
Release:        1
Summary:        Linux management for families
License:        MIT
ExclusiveArch:  x86_64

%description
Hauswart manages Linux devices of a household from a web dashboard.

%package server
Summary:        Hauswart management server with web dashboard

%description server
Server and web dashboard of Hauswart.

%package agent
Summary:        Hauswart management agent

%description agent
Agent that runs on every managed device.

%install
install -Dm755 %{hw_root}/dist/hauswart-server %{buildroot}/usr/bin/hauswart-server
install -Dm755 %{hw_root}/dist/hauswart-agent %{buildroot}/usr/bin/hauswart-agent
install -Dm644 %{hw_root}/packaging/systemd/hauswart-server.service %{buildroot}/usr/lib/systemd/system/hauswart-server.service
install -Dm644 %{hw_root}/packaging/systemd/hauswart-agent.service %{buildroot}/usr/lib/systemd/system/hauswart-agent.service
install -Dm644 %{hw_root}/packaging/server.env %{buildroot}/etc/hauswart/server.env
install -Dm644 %{hw_root}/packaging/hauswart.sysusers %{buildroot}/usr/lib/sysusers.d/hauswart.conf

# Neither package restarts its service: a running agent may be the very
# process that is installing this update.
%post server
systemd-sysusers hauswart.conf || :
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

%files agent
/usr/bin/hauswart-agent
/usr/lib/systemd/system/hauswart-agent.service
