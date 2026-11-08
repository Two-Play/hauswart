package agent

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

const (
	inventoryInterval = 6 * time.Hour
	inventoryRetry    = 10 * time.Minute
	inventoryTick     = time.Minute
	inventoryTimeout  = 5 * time.Minute
	dmiDir            = "/sys/class/dmi/id"
	sectorSize        = 512
	minMACBytes       = 6
)

// eMMC lists parts of itself as devices.
var notADisk = regexp.MustCompile(`boot[0-9]+$|rpmb$`)

// Manufacturers leave these in fields they did not fill.
var dmiPlaceholders = []string{"to be filled by o.e.m.", "default string", "not specified", "system serial number",
	"system product name", "system manufacturer", "none", "n/a", "unknown", "0"}

const maxHardwareText = 200

func inventoryText(s string) string { return api.CleanText(s, maxHardwareText) }

func (e *Executor) dmi(name string) string {
	raw, err := os.ReadFile(e.path(dmiDir + "/" + name))
	if err != nil {
		return ""
	}
	value := inventoryText(string(raw))
	if slices.Contains(dmiPlaceholders, strings.ToLower(value)) {
		return ""
	}
	return value
}

func (e *Executor) hardware() api.Hardware {
	return api.Hardware{
		Vendor: e.dmi("sys_vendor"),
		Model:  e.dmi("product_name"),
		Serial: e.dmi("product_serial"),
		BIOS:   e.dmi("bios_version"),
		CPU:    e.cpuName(),
	}
}

func (e *Executor) cpuName() string {
	raw, err := os.ReadFile(e.path("/proc/cpuinfo"))
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(raw)) {
		key, value, found := strings.Cut(line, ":")
		if found && strings.TrimSpace(key) == "model name" {
			return inventoryText(value)
		}
	}
	return ""
}

// disks lists built-in disks. Sticks come and go, and would change the inventory
// each time.
func (e *Executor) disks() []api.Disk {
	entries, err := filepath.Glob(e.path("/sys/block/*"))
	if err != nil {
		return nil
	}
	read := func(dir, file string) string {
		raw, _ := os.ReadFile(filepath.Join(dir, file))
		return inventoryText(string(raw))
	}
	var disks []api.Disk
	for _, dir := range entries {
		name := filepath.Base(dir)
		sectors, _ := strconv.ParseUint(read(dir, "size"), 10, 64)
		if sectors == 0 || read(dir, "removable") == "1" || notADisk.MatchString(name) {
			continue
		}
		// Only hardware has a device behind it, not loop, zram or a mapper.
		if _, err := os.Stat(filepath.Join(dir, "device")); err != nil {
			continue
		}
		// An external disk does not call itself removable.
		if real, err := filepath.EvalSymlinks(dir); err == nil && strings.Contains(real, "/usb") {
			continue
		}
		model := read(dir, "device/model")
		if model == "" {
			model = read(dir, "device/name") // eMMC
		}
		disks = append(disks, api.Disk{Name: inventoryText(name), Model: model,
			Size: sectors * sectorSize, Rotational: read(dir, "queue/rotational") == "1"})
	}
	return disks[:min(len(disks), 32)]
}

// network lists real cards. A virtual one has no device behind it, which leaves out
// loopback, bridges, containers and tunnels.
func (e *Executor) network() []api.NetworkCard {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var cards []api.NetworkCard
	for _, nic := range interfaces {
		if _, err := os.Stat(e.path("/sys/class/net/" + nic.Name + "/device")); err != nil {
			continue
		}
		card := api.NetworkCard{Name: inventoryText(nic.Name)}
		if len(nic.HardwareAddr) >= minMACBytes {
			card.MAC = nic.HardwareAddr.String()
		}
		addresses, _ := nic.Addrs()
		for _, address := range addresses[:min(len(addresses), 16)] {
			if ip, _, err := net.ParseCIDR(address.String()); err == nil {
				card.Addresses = append(card.Addresses, ip.String())
			}
		}
		cards = append(cards, card)
	}
	return cards[:min(len(cards), 32)]
}

// dpkgStates are what dpkg can say about a package, and whether it is there.
var dpkgStates = map[string]bool{"installed": true, "half-configured": true, "unpacked": true, "half-installed": true,
	"triggers-awaited": true, "triggers-pending": true, "not-installed": false, "config-files": false}

// parseInstalled reads "name version", or "state name version" from dpkg, which also
// keeps what was removed. Errors end up in the same output, so a line has to look
// like a package. The keys of rpm count as packages there, but are none.
func parseInstalled(out string) []api.Package {
	var found []api.Package
	for line := range strings.Lines(out) {
		fields := strings.Fields(line)
		there, state := false, false
		if len(fields) > 0 {
			there, state = dpkgStates[fields[0]]
		}
		if state && !there {
			continue
		}
		if state {
			fields = fields[1:]
		}
		if len(fields) != 2 || !api.ValidPackage(fields[0]) || !strings.ContainsAny(fields[1], "0123456789") || fields[0] == "gpg-pubkey" {
			continue
		}
		found = append(found, api.Package{Kind: api.PackageSystem, Name: inventoryText(fields[0]), Version: inventoryText(fields[1])})
	}
	return found
}

func parseFlatpaks(out string) []api.Package {
	var found []api.Package
	for line := range strings.Lines(out) {
		id, version, _ := strings.Cut(strings.TrimRight(line, "\n"), "\t")
		if api.ValidAppID(id) && strings.Contains(id, ".") {
			found = append(found, api.Package{Kind: api.PackageFlatpak, Name: id, Version: inventoryText(version)})
		}
	}
	return found
}

// software lists what is installed, sorted. The last value says that a list failed,
// which says nothing about what is there.
func (e *Executor) software(ctx context.Context) (found []api.Package, truncated bool, err error) {
	if backend := e.Platform.Backend; backend != nil && backend.List != nil {
		out, err := e.Run(ctx, backend.List[0], backend.List[1:]...)
		if err != nil {
			return nil, false, err
		}
		found = parseInstalled(out)
	}
	if e.Platform.Flatpak || e.Has != nil && e.Has("flatpak") {
		out, err := e.Run(ctx, "flatpak", "list", "--system", "--app", "--columns=application,version")
		if err != nil {
			return nil, false, err
		}
		found = append(found, parseFlatpaks(out)...)
	}
	slices.SortFunc(found, func(a, b api.Package) int {
		return strings.Compare(a.Kind+" "+a.Name+" "+a.Version, b.Kind+" "+b.Name+" "+b.Version)
	})
	found = slices.Compact(found)
	size := 0
	for i, pkg := range found {
		size += len(pkg.Name) + len(pkg.Version) + api.PackageOverhead
		if i == api.MaxInventoryPackages || size > api.MaxInventoryPackageBytes {
			return found[:i], true, nil
		}
	}
	return found, false, nil
}

// firewallState only asks, unlike enforceFirewall. Having no known firewall says
// nothing, as nftables can be set up by hand.
func (e *Executor) firewallState(ctx context.Context) string {
	firewall := e.Platform.Firewall
	if firewall == "" && e.Has != nil {
		firewall = detectFirewall(e.Has)
	}
	switch firewall {
	case firewallD:
		// Without the daemon the tool says "FirewallD is not running".
		out, _ := e.Run(ctx, "firewall-cmd", "--state")
		switch state := strings.TrimSpace(out); {
		case state == "running":
			return api.CheckOn
		case strings.HasSuffix(state, "not running"):
			return api.CheckOff
		}
		return api.CheckUnknown
	case firewallUFW:
		out, err := e.Run(ctx, "ufw", "status")
		if err != nil {
			return api.CheckUnknown
		}
		if strings.Contains(out, "Status: active") {
			return api.CheckOn
		}
		return api.CheckOff
	}
	return api.CheckUnknown
}

func (e *Executor) collectInventory(ctx context.Context, log *slog.Logger) api.Inventory {
	ctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	lock, _ := e.screenLock(ctx)
	packages, truncated, err := e.software(ctx)
	if err != nil {
		log.Warn("listing the installed software failed", "err", err)
	}
	return api.Inventory{
		Hardware: e.hardware(),
		Disks:    e.disks(),
		Network:  e.network(),
		Security: api.SecurityState{DiskEncryption: e.diskEncryption(ctx), ScreenLock: lock, Firewall: e.firewallState(ctx),
			TPM: e.tpmState(), SecureBoot: e.secureBootState(), HSI: e.hsiLevel(ctx)},
		Packages: packages, Truncated: truncated, KeepPackages: err != nil,
	}
}

func (e *Executor) inventoryDue() bool {
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	return e.insight.inventoryStale
}

// inventoryStarted comes before the collecting, so that a package task which ends
// in the middle of it asks for another round.
func (e *Executor) inventoryStarted() {
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	e.insight.inventoryStale = false
}

// sendInventory checks first, as the server would refuse the whole of it.
func sendInventory(inventory api.Inventory, post func(api.Inventory) error) error {
	if err := inventory.Check(); err != nil {
		return err
	}
	return post(inventory)
}

// inventoryLoop runs at start, every few hours and after a package task. It sends
// each time, so that a restored server catches up, and the server sorts out what
// changed.
func (a *Agent) inventoryLoop(ctx context.Context) {
	next := time.Now()
	ticker := time.NewTicker(inventoryTick)
	defer ticker.Stop()
	for {
		if a.exec.inventoryDue() || !time.Now().Before(next) {
			a.exec.inventoryStarted()
			err := sendInventory(a.exec.collectInventory(ctx, a.log), func(inventory api.Inventory) error {
				return a.post(ctx, "/agent/inventory", inventory)
			})
			next = time.Now().Add(inventoryInterval)
			if err != nil && !errors.Is(err, context.Canceled) {
				a.log.Warn("sending the inventory failed", "err", err)
				next = time.Now().Add(inventoryRetry)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
