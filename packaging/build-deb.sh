#!/bin/sh
# Builds a .deb with ar and tar, so that packaging on Fedora needs no Debian
# tools. Usage: packaging/build-deb.sh server|agent|admin|tray|admin-gui VERSION
set -eu

component=$1
version=$2
root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/data/usr/bin" "$work/data/usr/lib/systemd/system" "$work/control"

install -m755 "dist/hauswart-$component" "$work/data/usr/bin/"
case $component in
server | agent)
	install -m644 "packaging/systemd/hauswart-$component.service" "$work/data/usr/lib/systemd/system/"
	;;
tray)
	install -Dm644 packaging/desktop/hauswart-tray.desktop "$work/data/usr/share/applications/hauswart-tray.desktop"
	install -Dm644 packaging/desktop/hauswart-tray-autostart.desktop "$work/data/etc/xdg/autostart/hauswart-tray.desktop"
	install -Dm644 packaging/desktop/hauswart.svg "$work/data/usr/share/icons/hicolor/scalable/apps/hauswart.svg"
	install -m755 dist/hauswart-blocker "$work/data/usr/bin/"
	;;
admin-gui)
	install -Dm644 packaging/desktop/hauswart-admin-gui.desktop "$work/data/usr/share/applications/hauswart-admin-gui.desktop"
	;;
esac
if [ "$component" = server ]; then
	mkdir -p "$work/data/etc/hauswart" "$work/data/usr/lib/sysusers.d"
	install -m644 packaging/server.env "$work/data/etc/hauswart/"
	install -m600 packaging/notify.env "$work/data/etc/hauswart/"
	install -m644 packaging/hauswart.sysusers "$work/data/usr/lib/sysusers.d/hauswart.conf"
	printf '%s\n' /etc/hauswart/server.env /etc/hauswart/notify.env >"$work/control/conffiles"
fi

cat >"$work/control/control" <<CONTROL
Package: hauswart-$component
Version: $version
Architecture: amd64
Maintainer: Hauswart <noreply@localhost>
Section: admin
Priority: optional
Description: Linux management for small groups ($component)
CONTROL
case $component in
tray | admin-gui)
	echo "Depends: libgl1, libx11-6, libxcursor1, libxrandr2, libxinerama1, libxi6, libxxf86vm1, libwayland-client0" >>"$work/control/control"
	;;
esac
if [ "$component" = tray ]; then
	echo "Recommends: libsecret-tools" >>"$work/control/control"
fi
if [ "$component" = server ] || [ "$component" = agent ]; then
	install -m755 packaging/deb/postinst "$work/control/postinst"
	sed "s/@COMPONENT@/$component/" packaging/deb/prerm >"$work/control/prerm"
	chmod 755 "$work/control/prerm"
fi

echo 2.0 >"$work/debian-binary"
tar --owner=0 --group=0 -czf "$work/control.tar.gz" -C "$work/control" .
tar --owner=0 --group=0 -czf "$work/data.tar.gz" -C "$work/data" .
target="$root/dist/hauswart-${component}_${version}_amd64.deb"
rm -f "$target"
cd "$work"
ar rc "$target" debian-binary control.tar.gz data.tar.gz
