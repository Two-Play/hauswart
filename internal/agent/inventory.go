package agent

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
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
)

// Manufacturers leave these in fields they did not fill.
var dmiPlaceholders = []string{"to be filled by o.e.m.", "default string", "not specified", "system serial number",
	"system product name", "system manufacturer", "none", "n/a", "unknown", "0"}

func inventoryText(s string) string {
	return clip(strings.TrimSpace(cleanText(strings.ToValidUTF8(s, ""))), 200)
}

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
		if sectors == 0 || read(dir, "removable") == "1" {
			continue
		}
		// Only hardware has a device behind it, not loop, zram or a mapper.
		if _, err := os.Stat(filepath.Join(dir, "device")); err != nil {
			continue
		}
		disks = append(disks, api.Disk{Name: inventoryText(name), Model: read(dir, "device/model"),
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
		card := api.NetworkCard{Name: inventoryText(nic.Name), MAC: nic.HardwareAddr.String()}
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

// parseInstalled reads "name version", or "status name version" from dpkg, which
// also keeps what was removed. Anything else on a line is no package.
func parseInstalled(out string) []api.Package {
	var found []api.Package
	for line := range strings.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == "installed" {
			fields = fields[1:]
		}
		if len(fields) == 2 {
			found = append(found, api.Package{Kind: api.PackageSystem, Name: inventoryText(fields[0]), Version: inventoryText(fields[1])})
		}
	}
	return found
}

func parseFlatpaks(out string) []api.Package {
	var found []api.Package
	for line := range strings.Lines(out) {
		id, version, _ := strings.Cut(strings.TrimRight(line, "\n"), "\t")
		if api.ValidAppID(id) {
			found = append(found, api.Package{Kind: api.PackageFlatpak, Name: id, Version: inventoryText(version)})
		}
	}
	return found
}

// software is sorted, so that the same packages give the same hash.
func (e *Executor) software(ctx context.Context) ([]api.Package, bool) {
	var found []api.Package
	if backend := e.Platform.Backend; backend != nil && backend.List != nil {
		if out, err := e.Run(ctx, backend.List[0], backend.List[1:]...); err == nil {
			found = parseInstalled(out)
		}
	}
	if e.Platform.Flatpak || e.Has != nil && e.Has("flatpak") {
		if out, err := e.Run(ctx, "flatpak", "list", "--system", "--app", "--columns=application,version"); err == nil {
			found = append(found, parseFlatpaks(out)...)
		}
	}
	slices.SortFunc(found, func(a, b api.Package) int {
		return strings.Compare(a.Kind+" "+a.Name+" "+a.Version, b.Kind+" "+b.Name+" "+b.Version)
	})
	found = slices.Compact(found)
	if len(found) > api.MaxInventoryPackages {
		return found[:api.MaxInventoryPackages], true
	}
	return found, false
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
		if out, err := e.Run(ctx, "firewall-cmd", "--state"); err == nil && strings.TrimSpace(out) == "running" {
			return api.CheckOn
		}
		return api.CheckOff
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

func (e *Executor) collectInventory(ctx context.Context) api.Inventory {
	ctx, cancel := context.WithTimeout(ctx, inventoryTimeout)
	defer cancel()
	lock, _ := e.screenLock(ctx)
	packages, truncated := e.software(ctx)
	return api.Inventory{
		Hardware: e.hardware(),
		Disks:    e.disks(),
		Network:  e.network(),
		Security: api.SecurityState{DiskEncryption: e.diskEncryption(ctx), ScreenLock: lock, Firewall: e.firewallState(ctx)},
		Packages: packages, Truncated: truncated,
	}
}

func (e *Executor) inventoryDue() bool {
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	return e.insight.inventoryStale
}

func (e *Executor) inventoryTaken(at time.Time) {
	e.insight.mu.Lock()
	defer e.insight.mu.Unlock()
	e.insight.inventoryStale = false
	e.insight.inventoryAt = &at
}

// sendInventory sends what changed since the last time, and returns the new hash.
func sendInventory(inventory api.Inventory, sent string, post func(api.Inventory) error) (string, error) {
	raw, err := json.Marshal(inventory)
	if err != nil {
		return sent, err
	}
	hash := sha256.Sum256(raw)
	sum := string(hash[:])
	if sum == sent {
		return sent, nil
	}
	if err := post(inventory); err != nil {
		return sent, err
	}
	return sum, nil
}

// inventoryLoop runs at start, every few hours and after a package task. Only a
// change goes out, as most of the time there is none.
func (a *Agent) inventoryLoop(ctx context.Context) {
	sent := ""
	next := time.Now()
	ticker := time.NewTicker(inventoryTick)
	defer ticker.Stop()
	for {
		if a.exec.inventoryDue() || !time.Now().Before(next) {
			var err error
			sent, err = sendInventory(a.exec.collectInventory(ctx), sent, func(inventory api.Inventory) error {
				return a.post(ctx, "/agent/inventory", inventory)
			})
			switch {
			case err == nil:
				a.exec.inventoryTaken(time.Now().UTC())
				next = time.Now().Add(inventoryInterval)
			case !errors.Is(err, context.Canceled):
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
