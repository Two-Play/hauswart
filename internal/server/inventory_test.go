package server

import (
	"encoding/csv"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
)

func init() { minInventoryGap = 0 }

func sampleInventory() api.Inventory {
	return api.Inventory{
		Hardware: api.Hardware{Vendor: "LENOVO", Model: "T14", Serial: "PF1", CPU: "AMD"},
		Disks:    []api.Disk{{Name: "nvme0n1", Size: 1000}},
		Network:  []api.NetworkCard{{Name: "enp1s0", MAC: "52:54:00:12:34:56", Addresses: []string{"10.0.0.5"}}},
		Security: api.SecurityState{DiskEncryption: api.CheckOn, ScreenLock: api.CheckUnknown, Firewall: api.CheckOff},
		Packages: []api.Package{{Kind: api.PackageSystem, Name: "firefox", Version: "140"}, {Kind: api.PackageFlatpak, Name: "org.gnome.Calculator", Version: "46"}},
	}
}

func inventoryOf(t *testing.T, e *env, c *http.Client) []inventoryDevice {
	t.Helper()
	code, data := e.do(c, "GET", "/api/inventory", nil)
	if code != http.StatusOK {
		t.Fatalf("got %d %s", code, data)
	}
	var list []inventoryDevice
	if err := json.Unmarshal(data, &list); err != nil {
		t.Fatal(err)
	}
	return list
}

func TestInventoryArrives(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	if code, data := e.do(agent, "POST", "/agent/inventory", sampleInventory()); code != http.StatusNoContent {
		t.Fatalf("got %d %s", code, data)
	}
	admin := e.login("admin")
	list := inventoryOf(t, e, admin)
	if len(list) != 1 || list[0].Inventory == nil || list[0].Inventory.Hardware.Serial != "PF1" || list[0].Inventory.PackageCount != 2 || len(list[0].Packages) != 0 {
		t.Fatalf("got %+v", list)
	}
	code, data := e.do(admin, "GET", "/api/inventory/"+id, nil)
	var one inventoryDevice
	if code != http.StatusOK || json.Unmarshal(data, &one) != nil || len(one.Packages) != 2 {
		t.Fatalf("got %d %s", code, data)
	}

	// The next one replaces it, so that removed software does not stay behind.
	next := sampleInventory()
	next.Packages = next.Packages[:1]
	e.do(agent, "POST", "/agent/inventory", next)
	if got := inventoryOf(t, e, admin)[0].Inventory.PackageCount; got != 1 {
		t.Fatalf("got %d", got)
	}
}

// A list that failed on the device must not read as an empty device.
func TestFailedListKeepsThePackages(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.do(agent, "POST", "/agent/inventory", sampleInventory())
	failed := sampleInventory()
	failed.Packages, failed.KeepPackages, failed.Hardware.Model = nil, true, "new"
	if code, data := e.do(agent, "POST", "/agent/inventory", failed); code != http.StatusNoContent {
		t.Fatalf("got %d %s", code, data)
	}
	admin := e.login("admin")
	entry := inventoryOf(t, e, admin)[0]
	if entry.Inventory.PackageCount != 2 || entry.Inventory.Hardware.Model != "new" {
		t.Fatalf("got %+v", entry.Inventory)
	}
	_, data := e.do(admin, "GET", "/api/inventory/"+id, nil)
	if !strings.Contains(string(data), "firefox") {
		t.Fatalf("got %s", data)
	}
	// And the next good list still counts, also if it is the one from before.
	e.do(agent, "POST", "/agent/inventory", sampleInventory())
	if got := inventoryOf(t, e, admin)[0].Inventory.PackageCount; got != 2 {
		t.Fatalf("got %d", got)
	}
}

func TestADeviceCannotKeepTheServerBusy(t *testing.T) {
	e := setup(t)
	_, agent := e.enroll()
	minInventoryGap = time.Hour
	t.Cleanup(func() { minInventoryGap = 0 })
	if code, data := e.do(agent, "POST", "/agent/inventory", sampleInventory()); code != http.StatusNoContent {
		t.Fatalf("got %d %s", code, data)
	}
	if code, _ := e.do(agent, "POST", "/agent/inventory", sampleInventory()); code != http.StatusTooManyRequests {
		t.Fatalf("got %d", code)
	}
}

func TestReportTextIsLimited(t *testing.T) {
	e := setup(t)
	_, agent := e.enroll()
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: "a\nb\u202e" + strings.Repeat("x", 1<<20), Kernel: strings.Repeat("y", 1<<20)})
	entry := inventoryOf(t, e, e.login("admin"))[0]
	if len(entry.Hostname) > 300 || len(entry.Kernel) > 300 || strings.ContainsAny(entry.Hostname, "\n\u202e") {
		t.Fatalf("got %d %d", len(entry.Hostname), len(entry.Kernel))
	}
}

func TestInventoryIsForAdmins(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.do(agent, "POST", "/agent/inventory", sampleInventory())
	e.addUser("paul", "", "parent")
	e.assign("anna", id)
	for _, name := range []string{"anna", "paul"} {
		c := e.login(name)
		for _, path := range []string{"/api/inventory", "/api/inventory.csv", "/api/inventory/software?q=firefox", "/api/inventory/" + id} {
			if code, _ := e.do(c, "GET", path, nil); code != http.StatusForbidden {
				t.Errorf("%s %s: got %d", name, path, code)
			}
		}
		if code, _ := e.do(c, "PUT", "/api/inventory/"+id+"/asset", api.Asset{Tag: "x"}); code != http.StatusForbidden {
			t.Errorf("%s: got %d", name, code)
		}
	}
}

func TestOnlyADeviceWritesItsInventory(t *testing.T) {
	e := setup(t)
	if code, _ := e.do(e.login("admin"), "POST", "/agent/inventory", sampleInventory()); code == http.StatusNoContent {
		t.Fatal("a person wrote the inventory of a device")
	}
	first, agent := e.enroll()
	second, other := e.enroll()
	e.do(agent, "POST", "/agent/inventory", sampleInventory())
	changed := sampleInventory()
	changed.Hardware.Serial = "OTHER"
	e.do(other, "POST", "/agent/inventory", changed)
	for _, entry := range inventoryOf(t, e, e.login("admin")) {
		if want := map[string]string{first: "PF1", second: "OTHER"}[entry.ID]; entry.Inventory.Hardware.Serial != want {
			t.Fatalf("%s: got %s", entry.ID, entry.Inventory.Hardware.Serial)
		}
	}
}

func TestBadInventoryIsRefused(t *testing.T) {
	e := setup(t)
	_, agent := e.enroll()
	for name, change := range map[string]func(*api.Inventory){
		"long text":     func(i *api.Inventory) { i.Hardware.Model = strings.Repeat("x", 1000) },
		"line break":    func(i *api.Inventory) { i.Hardware.Serial = "a\nb" },
		"bad mac":       func(i *api.Inventory) { i.Network[0].MAC = "<script>" },
		"bad address":   func(i *api.Inventory) { i.Network[0].Addresses = []string{"nowhere"} },
		"bad state":     func(i *api.Inventory) { i.Security.Firewall = "maybe" },
		"bad kind":      func(i *api.Inventory) { i.Packages[0].Kind = "x" },
		"empty package": func(i *api.Inventory) { i.Packages[0].Name = "" },
		"too many": func(i *api.Inventory) {
			i.Packages = make([]api.Package, api.MaxInventoryPackages+1)
			for n := range i.Packages {
				i.Packages[n] = api.Package{Kind: api.PackageSystem, Name: "a"}
			}
		},
	} {
		inventory := sampleInventory()
		change(&inventory)
		if code, _ := e.do(agent, "POST", "/agent/inventory", inventory); code < 400 {
			t.Errorf("%s: got %d", name, code)
		}
	}
}

func TestSoftwareSearch(t *testing.T) {
	e := setup(t)
	_, first := e.enroll()
	_, second := e.enroll()
	e.do(first, "POST", "/agent/inventory", sampleInventory())
	older := sampleInventory()
	older.Packages[0].Version = "128"
	e.do(second, "POST", "/agent/inventory", older)
	admin := e.login("admin")
	code, data := e.do(admin, "GET", "/api/inventory/software?q=fire", nil)
	var result struct {
		Entries []struct {
			Version string
			Devices []struct{ ID string }
		}
	}
	if code != http.StatusOK || json.Unmarshal(data, &result) != nil || len(result.Entries) != 2 || result.Entries[0].Version != "128" {
		t.Fatalf("got %d %s", code, data)
	}
	// A wildcard is a character like any other here.
	code, data = e.do(admin, "GET", "/api/inventory/software?q=%25%25", nil)
	if code != http.StatusOK || strings.Contains(string(data), "firefox") {
		t.Fatalf("got %d %s", code, data)
	}
}

func TestAssets(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop"})
	admin := e.login("admin")
	soon := time.Now().UTC().Add(10 * 24 * time.Hour).Format(time.DateOnly)
	asset := api.Asset{Tag: "INV-1", Person: "Lena", Location: "Büro", Purchased: "2025-01-02", WarrantyUntil: soon, Note: "Zwei\nZeilen"}
	if code, data := e.do(admin, "PUT", "/api/inventory/"+id+"/asset", asset); code != http.StatusNoContent {
		t.Fatalf("got %d %s", code, data)
	}
	entry := inventoryOf(t, e, admin)[0]
	if entry.Asset != asset || len(entry.Warnings) != 1 || entry.Warnings[0].Code != api.WarnWarrantyEnding {
		t.Fatalf("got %+v", entry)
	}
	if warnings := devices(t, e, admin)[0].Warnings; len(warnings) != 1 {
		t.Fatalf("got %+v", warnings)
	}
	for name, bad := range map[string]api.Asset{
		"long":     {Tag: strings.Repeat("x", 500)},
		"line":     {Person: "a\nb"},
		"bad date": {Purchased: "morgen"},
	} {
		if code, _ := e.do(admin, "PUT", "/api/inventory/"+id+"/asset", bad); code != http.StatusBadRequest {
			t.Errorf("%s: got %d", name, code)
		}
	}
	if code, _ := e.do(admin, "PUT", "/api/inventory/nobody/asset", asset); code != http.StatusNotFound {
		t.Fatalf("got %d", code)
	}
}

// The data of a device outlives it, as the hardware is still there.
func TestRevokedDevicesStayInTheInventory(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.do(agent, "POST", "/agent/inventory", sampleInventory())
	admin := e.login("admin")
	e.do(admin, "PUT", "/api/inventory/"+id+"/asset", api.Asset{Tag: "INV-1"})
	if code, data := e.do(admin, "POST", "/api/devices/"+id+"/revoke", nil); code >= 300 {
		t.Fatalf("got %d %s", code, data)
	}
	entry := inventoryOf(t, e, admin)[0]
	if !entry.Revoked || entry.Asset.Tag != "INV-1" || entry.Inventory == nil {
		t.Fatalf("got %+v", entry)
	}
	if code, _ := e.do(agent, "POST", "/agent/inventory", sampleInventory()); code != http.StatusForbidden {
		t.Fatalf("got %d", code)
	}
}

func TestCSVCannotCarryFormulas(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: `=cmd|' /C calc'!A0`, Kernel: `pc;=cmd|' /C calc'!A0;x`, Distro: "＝1+1"})
	inventory := sampleInventory()
	inventory.Hardware.Model = "@SUM(1+1)"
	inventory.Hardware.Vendor = `-2+3,"x"`
	inventory.Hardware.BIOS = " =1+1"
	e.do(agent, "POST", "/agent/inventory", inventory)
	admin := e.login("admin")
	e.do(admin, "PUT", "/api/inventory/"+id+"/asset", api.Asset{Note: "+1\nzweite Zeile"})
	code, data := e.do(admin, "GET", "/api/inventory.csv", nil)
	if code != http.StatusOK || !strings.HasPrefix(string(data), "\xef\xbb\xbf") {
		t.Fatalf("got %d %q", code, data)
	}
	rows, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\xef\xbb\xbf"))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || len(rows[1]) != len(inventoryColumns) {
		t.Fatalf("got %v", rows)
	}
	for i, value := range rows[1] {
		if trimmed := strings.TrimSpace(value); trimmed != "" && strings.ContainsRune(formulaStarts, []rune(trimmed)[0]) {
			t.Errorf("%s: %q", inventoryColumns[i], value)
		}
	}
	// Read with a semicolon as a German spreadsheet does, nothing may start a cell.
	for _, line := range strings.Split(string(data), "\r\n") {
		german := csv.NewReader(strings.NewReader(line))
		german.Comma, german.LazyQuotes, german.FieldsPerRecord = ';', true, -1
		cells, _ := german.Read()
		for _, cell := range cells[min(1, len(cells)):] {
			t.Errorf("a semicolon started a cell: %q", cell)
		}
	}
	got := map[string]string{}
	for i, name := range inventoryColumns {
		got[name] = rows[1][i]
	}
	if got["hostname"] != `'=cmd|' /C calc'!A0` || got["vendor"] != `'-2+3,"x"` || got["note"] != "'+1\nzweite Zeile" || got["serial"] != "PF1" {
		t.Fatalf("got %v", got)
	}
}
