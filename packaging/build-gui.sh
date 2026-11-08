#!/bin/sh
# Builds the desktop apps in a Debian container. Unlike the other binaries they
# link against the system's graphics libraries, and what is built on a newer glibc
# does not start on an older one. hauswart-blocker speaks Wayland only, because it
# runs in the kiosk compositor cage. Usage: packaging/build-gui.sh VERSION
set -eu

version=$1
root=$(go env GOROOT)
cache=$(go env GOMODCACHE)
image=localhost/hauswart-gui-build
podman build -q -t "$image" - >/dev/null <<'CONTAINERFILE'
FROM docker.io/library/debian:stable
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev pkg-config libgl1-mesa-dev xorg-dev libwayland-dev libxkbcommon-dev ca-certificates
CONTAINERFILE
mkdir -p dist
# Without labels: the Go installation belongs to the system and must not be relabeled.
podman run --rm --security-opt label=disable -v "$PWD:/src" -v "$root:/goroot:ro" -v "$cache:/gomod:ro" \
	-e GOROOT=/goroot -e GOMODCACHE=/gomod -e GOCACHE=/tmp/cache -e GOFLAGS=-mod=mod -e GOPROXY=off -e GOTOOLCHAIN=local \
	-e CGO_ENABLED=1 -w /src/gui "$image" sh -c "
		/goroot/bin/go build -ldflags '-s -w -X github.com/Two-Play/hauswart/internal/agent.Version=$version' -o ../dist/hauswart-tray ./cmd/hauswart-tray &&
		/goroot/bin/go build -ldflags '-s -w' -o ../dist/hauswart-admin-gui ./cmd/hauswart-admin-gui &&
		/goroot/bin/go build -tags wayland -ldflags '-s -w' -o ../dist/hauswart-blocker ./cmd/hauswart-blocker"
