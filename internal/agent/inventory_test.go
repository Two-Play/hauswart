package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for path, text := range files {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHardware(t *testing.T) {
	e := &Executor{Root: t.TempDir()}
	writeFiles(t, e.Root, map[string]string{
		dmiDir + "/sys_vendor":     "LENOVO\n",
		dmiDir + "/product_name":   "To Be Filled By O.E.M.\n",
		dmiDir + "/product_serial": "PF1\x00ABC\n",
		dmiDir + "/bios_version":   "N3AET\n",
		"/proc/cpuinfo":            "processor : 0\nmodel name\t: AMD Ryzen 7\nprocessor : 1\nmodel name\t: AMD Ryzen 7\n",
	})
	got := e.hardware()
	want := api.Hardware{Vendor: "LENOVO", Serial: "PF1 ABC", BIOS: "N3AET", CPU: "AMD Ryzen 7"}
	if got != want {
		t.Fatalf("got %+v", got)
	}
	if err := (api.Inventory{Hardware: got}).Check(); err != nil {
		t.Fatal(err)
	}
}

func TestHardwareOfAContainerIsEmpty(t *testing.T) {
	e := &Executor{Root: t.TempDir()}
	if got := e.hardware(); got != (api.Hardware{}) {
		t.Fatalf("got %+v", got)
	}
}

func TestDisksLeaveOutWhatIsNoBuiltInDisk(t *testing.T) {
	e := &Executor{Root: t.TempDir()}
	writeFiles(t, e.Root, map[string]string{
		"/sys/block/nvme0n1/size":             "2000\n",
		"/sys/block/nvme0n1/removable":        "0\n",
		"/sys/block/nvme0n1/device/model":     "Samsung SSD\n",
		"/sys/block/nvme0n1/queue/rotational": "0\n",
		"/sys/block/sda/size":                 "4000\n",
		"/sys/block/sda/removable":            "0\n",
		"/sys/block/sda/device/model":         "WD Red\n",
		"/sys/block/sda/queue/rotational":     "1\n",
		"/sys/block/sdb/size":                 "100\n",
		"/sys/block/sdb/removable":            "1\n",
		"/sys/block/sdb/device/model":         "Stick\n",
		"/sys/block/loop0/size":               "100\n",
		"/sys/block/sr0/size":                 "0\n",
	})
	got := e.disks()
	if len(got) != 2 || got[0] != (api.Disk{Name: "nvme0n1", Model: "Samsung SSD", Size: 2000 * sectorSize}) ||
		got[1] != (api.Disk{Name: "sda", Model: "WD Red", Size: 4000 * sectorSize, Rotational: true}) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseInstalled(t *testing.T) {
	got := parseInstalled("bash 5.2-1\ninstalled vim 2:9.1\nconfig-files old 1.0\nwarning: something odd went wrong here\n")
	want := []api.Package{{Kind: api.PackageSystem, Name: "bash", Version: "5.2-1"}, {Kind: api.PackageSystem, Name: "vim", Version: "2:9.1"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestParseFlatpaks(t *testing.T) {
	got := parseFlatpaks("org.gnome.Calculator\t46.1\nio.mpv.Mpv\t\nnot an id\t1\n")
	want := []api.Package{{Kind: api.PackageFlatpak, Name: "org.gnome.Calculator", Version: "46.1"}, {Kind: api.PackageFlatpak, Name: "io.mpv.Mpv"}}
	if !slices.Equal(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestEveryBackendCanListPackages(t *testing.T) {
	for _, tool := range []string{"dnf5", "dnf", "apt-get", "zypper", "pacman"} {
		backend := detectBackend(func(name string) bool { return name == tool }, false)
		if backend == nil || len(backend.List) == 0 {
			t.Errorf("%s: %+v", tool, backend)
		}
	}
	if backend := detectBackend(func(name string) bool { return name == "rpm-ostree" }, true); len(backend.List) == 0 {
		t.Error("rpm-ostree")
	}
}

func TestSoftwareIsSortedAndLimited(t *testing.T) {
	var lines strings.Builder
	for i := range api.MaxInventoryPackages + 5 {
		fmt.Fprintf(&lines, "p%d 1\n", i)
	}
	e := &Executor{Platform: Platform{Backend: &Backend{List: []string{"list"}}}}
	e.Run = func(context.Context, string, ...string) (string, error) { return lines.String(), nil }
	got, truncated := e.software(context.Background())
	if len(got) != api.MaxInventoryPackages || !truncated {
		t.Fatalf("%d %v", len(got), truncated)
	}
	if !slices.IsSortedFunc(got, func(a, b api.Package) int { return strings.Compare(a.Name, b.Name) }) {
		t.Fatal("not sorted")
	}
}

// Reading the state must not start anything, that is what a policy is for.
func TestFirewallIsOnlyAskedAbout(t *testing.T) {
	var calls []string
	e := &Executor{Platform: Platform{Firewall: firewallD}}
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "not running\n", errors.New("exit status 252")
	}
	if got := e.firewallState(context.Background()); got != api.CheckOff {
		t.Fatal(got)
	}
	if !slices.Equal(calls, []string{"firewall-cmd --state"}) {
		t.Fatalf("got %v", calls)
	}
	e.Platform.Firewall = firewallUFW
	e.Run = func(context.Context, string, ...string) (string, error) { return "Status: active\n", nil }
	if got := e.firewallState(context.Background()); got != api.CheckOn {
		t.Fatal(got)
	}
	e.Platform.Firewall = ""
	if got := e.firewallState(context.Background()); got != api.CheckUnknown {
		t.Fatal(got)
	}
}

func TestOnlyAChangeIsSent(t *testing.T) {
	sends := 0
	post := func(api.Inventory) error { sends++; return nil }
	inventory := api.Inventory{Hardware: api.Hardware{Model: "x"}}
	sent, err := sendInventory(inventory, "", post)
	if err != nil {
		t.Fatal(err)
	}
	if sent, err = sendInventory(inventory, sent, post); err != nil || sends != 1 {
		t.Fatalf("%d %v", sends, err)
	}
	inventory.Hardware.Model = "y"
	if _, err = sendInventory(inventory, sent, post); err != nil || sends != 2 {
		t.Fatalf("%d %v", sends, err)
	}
}

func TestAFailedSendIsTriedAgain(t *testing.T) {
	inventory := api.Inventory{Hardware: api.Hardware{Model: "x"}}
	sent, err := sendInventory(inventory, "", func(api.Inventory) error { return errors.New("down") })
	if err == nil || sent != "" {
		t.Fatalf("%q %v", sent, err)
	}
}

func TestAPackageTaskAsksForANewInventory(t *testing.T) {
	e := &Executor{}
	e.lockPackages()()
	if !e.inventoryDue() {
		t.Fatal("not due")
	}
	e.inventoryTaken(time.Now())
	if e.inventoryDue() || e.insight.inventoryAt == nil {
		t.Fatal("not taken")
	}
}
