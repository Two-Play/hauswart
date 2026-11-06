package main

import (
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/philippe/hauswart/internal/api"
)

func caPEM(content string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(content)}))
}

func fullPolicy() api.Policy {
	window := api.Window{Days: []string{"mon", "tue"}, Start: "15:00", End: "19:00"}
	return api.Policy{
		RequiredPackages:  []string{"vim"},
		ForbiddenPackages: []string{"steam"},
		RequiredFlatpaks:  []string{"org.gnome.Calculator"},
		ForbiddenFlatpaks: []string{"com.valvesoftware.Steam"},
		Files:             []api.FilePutPayload{{Path: "/etc/hauswart.d/a", Content: "secret\x1b[2Kline"}},
		CAs:               []api.CAInstallPayload{{Name: "home", PEM: caPEM("data")}},
		Updates:           &api.UpdateRule{Window: api.Window{Days: []string{"sat"}, Start: "02:00", End: "04:00"}, Reboot: api.RebootWindow},
		Security:          &api.SecurityRule{Firewall: true, DiskEncryption: true, ScreenLock: true},
		TimeZone:          "Europe/Berlin",
		ScreenTime:        []api.ScreenTimeRule{{User: "anna", Windows: []api.Window{window}}, {User: "ben"}},
		Language:          "de",
		Directory:         &api.DirectoryRule{URI: "ldaps://auth.example", BaseDN: "dc=ldap", BindDN: "cn=reader", BindPassword: "secret", CA: caPEM("directory")},
		Mounts:            []api.MountRule{{Server: "nas.home", Share: "family", Folder: "Family"}},
		Nextcloud:         &api.NextcloudRule{URL: "https://cloud.home", Mode: api.NextcloudDrive},
	}
}

func TestReviewShowsTheWholePolicy(t *testing.T) {
	text, _, err := review(api.TaskPolicySet, mustJSON(t, fullPolicy()))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"required package vim", "forbidden package steam", "required Flatpak org.gnome.Calculator",
		"forbidden Flatpak com.valvesoftware.Steam", "file /etc/hauswart.d/a", "TRUSTED CA home",
		"3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7", "automatic updates sat 02:00-04:00, reboot: window",
		"firewall enforced", "disk encryption checked", "screen lock checked", "time zone Europe/Berlin",
		"user anna may be logged in: mon,tue 15:00-19:00", "user ben may be logged in: NEVER",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("no %q in %q", want, text)
		}
	}
	if strings.ContainsRune(text, 0x1b) {
		t.Fatal("an escape from a file reached the terminal")
	}
}

// Every field of a policy has to show. A rule that is missing here would be
// signed without anyone having seen it.
func TestEveryPolicyChangeShowsAsAChange(t *testing.T) {
	changes := map[string]func(*api.Policy){
		"required package":  func(p *api.Policy) { p.RequiredPackages = []string{"nano"} },
		"forbidden package": func(p *api.Policy) { p.ForbiddenPackages = []string{"nano"} },
		"required flatpak":  func(p *api.Policy) { p.RequiredFlatpaks = []string{"org.x"} },
		"forbidden flatpak": func(p *api.Policy) { p.ForbiddenFlatpaks = []string{"org.x"} },
		"file content":      func(p *api.Policy) { p.Files[0].Content = "other" },
		"file mode":         func(p *api.Policy) { p.Files[0].Mode = "0600" },
		"file path":         func(p *api.Policy) { p.Files[0].Path = "/etc/hauswart.d/b" },
		"CA":                func(p *api.Policy) { p.CAs[0].PEM = caPEM("other") },
		"update days":       func(p *api.Policy) { p.Updates.Window.Days = []string{"sun"} },
		"update reboot":     func(p *api.Policy) { p.Updates.Reboot = api.RebootNever },
		"no updates":        func(p *api.Policy) { p.Updates = nil },
		"firewall":          func(p *api.Policy) { p.Security.Firewall = false },
		"encryption":        func(p *api.Policy) { p.Security.DiskEncryption = false },
		"lock":              func(p *api.Policy) { p.Security.ScreenLock = false },
		"zone":              func(p *api.Policy) { p.TimeZone = "UTC" },
		"window":            func(p *api.Policy) { p.ScreenTime[0].Windows[0].End = "20:00" },
		"rule gone":         func(p *api.Policy) { p.ScreenTime = p.ScreenTime[:1] },
		"language":          func(p *api.Policy) { p.Language = "en" },
		"directory uri":     func(p *api.Policy) { p.Directory.URI = "ldaps://evil.example" },
		"directory base":    func(p *api.Policy) { p.Directory.BaseDN = "dc=evil" },
		"directory bind":    func(p *api.Policy) { p.Directory.BindDN = "cn=evil" },
		"directory secret":  func(p *api.Policy) { p.Directory.BindPassword = "other" },
		"directory CA":      func(p *api.Policy) { p.Directory.CA = caPEM("evil") },
		"no directory":      func(p *api.Policy) { p.Directory = nil },
		"share server":      func(p *api.Policy) { p.Mounts[0].Server = "evil.example" },
		"share name":        func(p *api.Policy) { p.Mounts[0].Share = "other" },
		"share folder":      func(p *api.Policy) { p.Mounts[0].Folder = "Other" },
		"nextcloud url":     func(p *api.Policy) { p.Nextcloud.URL = "https://evil.example" },
		"nextcloud mode":    func(p *api.Policy) { p.Nextcloud.Mode = api.NextcloudClient },
	}
	for name, change := range changes {
		before, after := fullPolicy(), fullPolicy()
		// Windows share no memory between the two copies.
		change(&after)
		if text := diffPolicies(before, after); !strings.Contains(text, "Changes since") {
			t.Errorf("%s: %s", name, text)
		}
	}
	if text := diffPolicies(fullPolicy(), fullPolicy()); !strings.Contains(text, "Nothing changed") {
		t.Errorf("got %s", text)
	}
}

func TestDiffMarksAddedAndRemoved(t *testing.T) {
	text := diffPolicies(api.Policy{RequiredPackages: []string{"vim"}}, api.Policy{RequiredPackages: []string{"nano"}})
	if !strings.Contains(text, "- required package vim") || !strings.Contains(text, "+ required package nano") {
		t.Fatalf("got %s", text)
	}
}

func TestReviewOfClearSaysWhatEnds(t *testing.T) {
	text, payload, err := review(api.TaskPolicyClear, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "REMOVE THE POLICY") || !strings.Contains(text, "parental controls") || string(payload) != "{}" {
		t.Fatalf("%q %q", text, payload)
	}
}

func TestReviewRefusesABadPolicy(t *testing.T) {
	if _, _, err := review(api.TaskPolicySet, []byte(`{"forbidden_packages":["hauswart-agent"]}`)); err == nil {
		t.Fatal("offered to forbid the agent")
	}
	if _, _, err := review(api.TaskPolicySet, []byte(`{"hidden":1}`)); err == nil {
		t.Fatal("accepted an unknown field")
	}
}

func TestLastSignedPolicyStaysLocal(t *testing.T) {
	t.Setenv("HAUSWART_ADMIN_DIR", t.TempDir())
	_, payload, err := review(api.TaskPolicySet, mustJSON(t, api.Policy{RequiredPackages: []string{"vim"}}))
	if err != nil {
		t.Fatal(err)
	}
	if got := policyChanges("abc", api.TaskPolicySet, payload); !strings.Contains(got, "all of it is new") {
		t.Fatalf("got %s", got)
	}
	if err := rememberPolicy("abc", api.TaskPolicySet, payload); err != nil {
		t.Fatal(err)
	}
	path, _ := policyPath("abc")
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("%v, %v", info, err)
	}
	if got := policyChanges("abc", api.TaskPolicySet, payload); !strings.Contains(got, "Nothing changed") {
		t.Fatalf("got %s", got)
	}
	if got := policyChanges("abc", api.TaskPolicyClear, []byte(`{}`)); !strings.Contains(got, "- required package vim") {
		t.Fatalf("got %s", got)
	}
	if err := rememberPolicy("abc", api.TaskPolicyClear, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("kept a policy that ended")
	}
}

func TestDeviceIDCannotLeaveThePolicyDirectory(t *testing.T) {
	t.Setenv("HAUSWART_ADMIN_DIR", t.TempDir())
	for _, id := range []string{"../evil", "a/b", "", ".."} {
		if _, err := policyPath(id); err == nil {
			t.Errorf("accepted %q", id)
		}
	}
	if path, err := policyPath("abc"); err != nil || filepath.Base(path) != "abc.json" {
		t.Fatalf("%q, %v", path, err)
	}
}

// A hacked server puts a harmless device first, so that the admin sees no change.
func TestAllForAllShowsWhatEndsOnEachDevice(t *testing.T) {
	t.Setenv("HAUSWART_ADMIN_DIR", t.TempDir())
	harmless := mustJSON(t, api.Policy{RequiredPackages: []string{"vim"}})
	_, payload, err := review(api.TaskPolicySet, harmless)
	if err != nil {
		t.Fatal(err)
	}
	_, kids, err := review(api.TaskPolicySet, mustJSON(t, api.Policy{TimeZone: "UTC", ScreenTime: []api.ScreenTimeRule{{User: "anna"}}}))
	if err != nil {
		t.Fatal(err)
	}
	if err := rememberPolicy("parents", api.TaskPolicySet, payload); err != nil {
		t.Fatal(err)
	}
	if err := rememberPolicy("kid", api.TaskPolicySet, kids); err != nil {
		t.Fatal(err)
	}
	cfg := &config{Devices: map[string]*device{"parents": {Name: "parents"}, "kid": {Name: "kid-pc"}}}
	got := identicalPolicies(cfg, []queued{{DeviceID: "kid", Type: api.TaskPolicySet, Payload: harmless}}, policyFingerprint(api.TaskPolicySet, payload))
	if len(got) != 1 || !strings.Contains(got[0], "- user anna may be logged in") {
		t.Fatalf("got %v", got)
	}
}

func TestIdenticalPoliciesNeedALocalName(t *testing.T) {
	t.Setenv("HAUSWART_ADMIN_DIR", t.TempDir())
	raw := mustJSON(t, api.Policy{RequiredPackages: []string{"vim"}})
	_, payload, err := review(api.TaskPolicySet, raw)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config{Devices: map[string]*device{"a": {Name: "laptop"}, "b": {}}}
	queue := []queued{
		{DeviceID: "a", Type: api.TaskPolicySet, Payload: raw},
		{DeviceID: "b", Type: api.TaskPolicySet, Payload: raw},
		{DeviceID: "c", Type: api.TaskPolicySet, Payload: raw},
		{DeviceID: "a", Type: api.TaskPolicyClear, Payload: []byte(`{}`)},
	}
	got := identicalPolicies(cfg, queue, policyFingerprint(api.TaskPolicySet, payload))
	if len(got) != 1 || !strings.Contains(got[0], "On laptop:") {
		t.Fatalf("got %v", got)
	}
}

func TestWarnsAboutTheServersOwnCA(t *testing.T) {
	policy := fullPolicy()
	payload := mustJSON(t, policy)
	if got := policyWarning(&config{CA: caPEM("server")}, api.TaskPolicySet, payload); got != "" {
		t.Fatalf("got %q", got)
	}
	if got := policyWarning(&config{CA: policy.Directory.CA}, api.TaskPolicySet, payload); !strings.Contains(got, "WARNING") {
		t.Fatalf("got %q", got)
	}
}
