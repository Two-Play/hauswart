#!/bin/sh
# Installs Hauswart from the tarball on systems without rpm or dpkg packages.
# Usage: sudo ./install.sh agent|server|admin
set -eu

component=${1:-}
case "$component" in
	agent | server) ;;
	admin)
		cd "$(dirname "$0")"
		install -Dm755 hauswart-admin /usr/bin/hauswart-admin
		echo "Installed hauswart-admin."
		exit 0
		;;
	*)
		echo "usage: $0 agent|server|admin" >&2
		exit 2
		;;
esac
cd "$(dirname "$0")"

install -Dm755 "hauswart-$component" "/usr/bin/hauswart-$component"
install -Dm644 "hauswart-$component.service" "/usr/lib/systemd/system/hauswart-$component.service"
if [ "$component" = server ]; then
	install -Dm644 hauswart.sysusers /usr/lib/sysusers.d/hauswart.conf
	systemd-sysusers hauswart.conf
	if [ ! -e /etc/hauswart/server.env ]; then
		install -Dm644 server.env /etc/hauswart/server.env
	fi
	if [ ! -e /etc/hauswart/notify.env ]; then
		install -Dm600 -o hauswart -g hauswart notify.env /etc/hauswart/notify.env
	fi
fi
systemctl daemon-reload
echo "Installed hauswart-$component."
