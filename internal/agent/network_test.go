package agent

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestWifiFilesFollowThePolicy(t *testing.T) {
	pe, _ := newEngine(t)
	e := pe.exec
	var reloads int
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		if name == "nmcli" {
			reloads++
		}
		return "", nil
	}
	dir := e.path(nmConnections)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(dir, "Home.nmconnection")
	os.WriteFile(foreign, []byte("mine"), 0o600)

	office := api.WifiRule{SSID: "Büro\n[evil]", Password: `pa\ss=word"1`, Security: "wpa3", Hidden: true}
	var o outcome
	pe.enforceWifi(context.Background(), []api.WifiRule{office}, &o)
	file := filepath.Join(dir, wifiFile(office.SSID))
	raw, err := os.ReadFile(file)
	if err != nil || len(o.deviations) != 0 {
		t.Fatalf("%v %+v", err, o.deviations)
	}
	text := string(raw)
	for _, want := range []string{"ssid=Büro\\n[evil]\n", "key-mgmt=sae\n", "hidden=true\n", `psk=pa\\ss=word"1` + "\n"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, "\n[evil]") {
		t.Fatal("a line break in the SSID opened a section")
	}
	if info, _ := os.Stat(file); info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", info.Mode())
	}
	if reloads != 1 {
		t.Fatalf("%d reloads", reloads)
	}

	// Unchanged, nothing happens; gone from the policy, the file goes, the foreign one stays.
	o = outcome{}
	pe.enforceWifi(context.Background(), []api.WifiRule{office}, &o)
	if reloads != 1 || len(o.corrected) != 0 {
		t.Fatalf("rewrote an unchanged network: %d %v", reloads, o.corrected)
	}
	pe.enforceWifi(context.Background(), nil, &outcome{})
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Fatal("the network stayed")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("a foreign connection went")
	}
}

func TestWifiWithoutNetworkManagerIsADeviation(t *testing.T) {
	pe, _ := newEngine(t)
	pe.exec.Has = func(string) bool { return false }
	var o outcome
	pe.enforceWifi(context.Background(), []api.WifiRule{{SSID: "Büro", Password: "12345678"}}, &o)
	if len(o.deviations) != 1 || o.deviations[0].Kind != deviationWifi {
		t.Fatalf("got %+v", o.deviations)
	}
}

func TestPrintersFollowThePolicy(t *testing.T) {
	pe, _ := newEngine(t)
	e := pe.exec
	e.Has = func(string) bool { return true }
	queues := map[string]string{"Office": "ipp://other/ipp/print", "hauswart-old": "ipp://gone/ipp/print"}
	current := ""
	var calls []string
	e.Run = func(_ context.Context, name string, args ...string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		switch {
		case name == "lpstat" && args[0] == "-v":
			var out strings.Builder
			for q, uri := range queues {
				out.WriteString("device for " + q + ": " + uri + "\n")
			}
			return out.String(), nil
		case name == "lpstat" && args[0] == "-d":
			return "system default destination: " + current + "\n", nil
		case name == "lpadmin" && args[0] == "-p":
			queues[args[1]] = args[4]
		case name == "lpadmin" && args[0] == "-d":
			current = args[1]
		case name == "lpadmin" && args[0] == "-x":
			delete(queues, args[1])
		}
		return "", nil
	}
	printers := []api.PrinterRule{{Name: "flur", URI: "ipp://drucker.local/ipp/print", Default: true}}
	pe.enforcePrinters(context.Background(), printers, &outcome{})
	if queues["hauswart-flur"] != "ipp://drucker.local/ipp/print" || current != "hauswart-flur" {
		t.Fatalf("queues %v, default %s", queues, current)
	}
	if _, ok := queues["hauswart-old"]; ok {
		t.Fatal("an old queue of ours stayed")
	}
	if _, ok := queues["Office"]; !ok {
		t.Fatal("a foreign queue went")
	}
	if !slices.Contains(calls, "lpadmin -p hauswart-flur -E -v ipp://drucker.local/ipp/print -m everywhere") {
		t.Fatalf("got %v", calls)
	}
	calls = nil
	pe.enforcePrinters(context.Background(), printers, &outcome{})
	for _, call := range calls {
		if strings.HasPrefix(call, "lpadmin") {
			t.Fatalf("changed what was right: %v", calls)
		}
	}
}

func TestNetworkRulesAreChecked(t *testing.T) {
	for name, p := range map[string]api.Policy{
		"short password":  {Wifi: []api.WifiRule{{SSID: "a", Password: "short"}}},
		"long ssid":       {Wifi: []api.WifiRule{{SSID: strings.Repeat("x", 33), Password: "12345678"}}},
		"wep":             {Wifi: []api.WifiRule{{SSID: "a", Password: "12345678", Security: "wep"}}},
		"http printer":    {Printers: []api.PrinterRule{{Name: "a", URI: "http://drucker/"}}},
		"shell in a uri":  {Printers: []api.PrinterRule{{Name: "a", URI: "ipp://drucker/;rm -rf"}}},
		"two defaults":    {Printers: []api.PrinterRule{{Name: "a", URI: "ipp://a/", Default: true}, {Name: "b", URI: "ipp://b/", Default: true}}},
		"same name twice": {Printers: []api.PrinterRule{{Name: "a", URI: "ipp://a/"}, {Name: "a", URI: "ipp://b/"}}},
	} {
		if err := api.Validate(api.TaskPolicySet, payload(t, p)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
