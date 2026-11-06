package api

import (
	"encoding/json"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
	"time"
)

func testCA(content string) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte(content)}))
}

func TestCheckPolicyAcceptsAFullPolicy(t *testing.T) {
	p := Policy{
		RequiredPackages:  []string{"vim"},
		ForbiddenPackages: []string{"telnet"},
		RequiredFlatpaks:  []string{"org.mozilla.firefox"},
		Files:             []FilePutPayload{{Path: "/etc/hauswart.d/a", Content: "x", Mode: "0644"}},
		CAs:               []CAInstallPayload{{Name: "home", PEM: testCA("a")}},
		Updates:           &UpdateRule{Window: Window{Days: []string{"sat"}, Start: "02:00", End: "04:00"}, Reboot: RebootWindow},
		Security:          &SecurityRule{Firewall: true},
		TimeZone:          "Europe/Berlin",
		ScreenTime:        []ScreenTimeRule{{User: "anna", Windows: []Window{{Days: []string{"mon"}, Start: "15:00", End: "24:00"}}}},
	}
	if err := CheckPolicy(p); err != nil {
		t.Fatal(err)
	}
}

func TestCheckPolicyRefuses(t *testing.T) {
	window := Window{Days: []string{"mon"}, Start: "15:00", End: "19:00"}
	screen := func(w Window) []ScreenTimeRule { return []ScreenTimeRule{{User: "anna", Windows: []Window{w}}} }
	cases := map[string]struct {
		policy Policy
		code   string
	}{
		"bad package":        {Policy{RequiredPackages: []string{"-x"}}, ErrInvalidPackage},
		"forbid agent":       {Policy{ForbiddenPackages: []string{"hauswart-agent"}}, ErrPackageProtected},
		"forbid kernel":      {Policy{ForbiddenPackages: []string{"kernel-core"}}, ErrPackageProtected},
		"forbid sudo":        {Policy{ForbiddenPackages: []string{"SUDO"}}, ErrPackageProtected},
		"relative path":      {Policy{Files: []FilePutPayload{{Path: "etc/x"}}}, ErrInvalidPath},
		"two certificates":   {Policy{CAs: []CAInstallPayload{{Name: "a", PEM: testCA("a") + testCA("b")}}}, ErrNotPEM},
		"bad zone":           {Policy{TimeZone: "Mars/Base"}, ErrInvalidTimeZone},
		"local zone":         {Policy{TimeZone: "Local"}, ErrInvalidTimeZone},
		"screen, no zone":    {Policy{ScreenTime: screen(window)}, ErrInvalidTimeZone},
		"root":               {Policy{TimeZone: "UTC", ScreenTime: []ScreenTimeRule{{User: "root"}}}, ErrInvalidUser},
		"bad day":            {Policy{TimeZone: "UTC", ScreenTime: screen(Window{Days: []string{"x"}, Start: "01:00", End: "02:00"})}, ErrInvalidWindow},
		"no days":            {Policy{TimeZone: "UTC", ScreenTime: screen(Window{Start: "01:00", End: "02:00"})}, ErrInvalidWindow},
		"end before start":   {Policy{TimeZone: "UTC", ScreenTime: screen(Window{Days: []string{"mon"}, Start: "20:00", End: "19:00"})}, ErrInvalidWindow},
		"bad clock":          {Policy{TimeZone: "UTC", ScreenTime: screen(Window{Days: []string{"mon"}, Start: "1:00", End: "25:00"})}, ErrInvalidWindow},
		"bad reboot":         {Policy{Updates: &UpdateRule{Window: window, Reboot: "always"}}, ErrInvalidReboot},
		"required+forbidden": {Policy{RequiredPackages: []string{"vim"}, ForbiddenPackages: []string{"vim"}}, ErrPolicyConflict},
		"plain ldap":         {Policy{Directory: &DirectoryRule{URI: "ldap://a", BaseDN: "dc=a", BindDN: "cn=b", BindPassword: "c", CA: testCA("a")}}, ErrInvalidDirectory},
		"line in dn":         {Policy{Directory: &DirectoryRule{URI: "ldaps://a", BaseDN: "dc=a\nldap_tls_reqcert=never", BindDN: "cn=b", BindPassword: "c", CA: testCA("a")}}, ErrInvalidDirectory},
		"line in password":   {Policy{Directory: &DirectoryRule{URI: "ldaps://a", BaseDN: "dc=a", BindDN: "cn=b", BindPassword: "c\nx=y", CA: testCA("a")}}, ErrInvalidDirectory},
		"no password":        {Policy{Directory: &DirectoryRule{URI: "ldaps://a", BaseDN: "dc=a", BindDN: "cn=b"}}, ErrInvalidDirectory},
		"share with xml":     {Policy{Mounts: []MountRule{{Server: "nas", Share: `a"><volume`, Folder: "x"}}}, ErrInvalidMount},
		"share leaves home":  {Policy{Mounts: []MountRule{{Server: "nas", Share: "a", Folder: "../etc"}}}, ErrInvalidMount},
		"hidden folder":      {Policy{Mounts: []MountRule{{Server: "nas", Share: "a", Folder: ".ssh"}}}, ErrInvalidMount},
		"bad server":         {Policy{Mounts: []MountRule{{Server: "-o evil", Share: "a", Folder: "x"}}}, ErrInvalidMount},
		"plain nextcloud":    {Policy{Nextcloud: &NextcloudRule{URL: "http://a", Mode: NextcloudClient}}, ErrInvalidMount},
		"nextcloud mode":     {Policy{Nextcloud: &NextcloudRule{URL: "https://a", Mode: "x"}}, ErrInvalidMount},
		"unclean path":       {Policy{Files: []FilePutPayload{{Path: "/etc//x"}}}, ErrInvalidPath},
		"reserved CA":        {Policy{CAs: []CAInstallPayload{{Name: "server", PEM: testCA("a")}}}, ErrInvalidCAName},
		"same path twice":    {Policy{Files: []FilePutPayload{{Path: "/a", Content: "1"}, {Path: "/a", Content: "2"}}}, ErrPolicyConflict},
		"same file twice":    {Policy{Files: []FilePutPayload{{Path: "/a"}, {Path: "/a"}}}, ErrPolicyConflict},
		"too many packages":  {Policy{RequiredPackages: slices.Repeat([]string{"vim"}, maxPolicyPackages+1)}, ErrPolicyTooLarge},
		"too large":          {Policy{Files: []FilePutPayload{{Path: "/a", Content: strings.Repeat("x", maxPolicyBytes)}}}, ErrPolicyTooLarge},
	}
	for name, c := range cases {
		err := CheckPolicy(c.policy)
		apiErr, ok := err.(*Error)
		if !ok || apiErr.Code != c.code {
			t.Errorf("%s: got %v, want %s", name, err, c.code)
		}
	}
}

func TestPolicyTaskNeedsASignatureAndNoPasskey(t *testing.T) {
	for _, taskType := range []string{TaskPolicySet, TaskPolicyClear} {
		if !NeedsSignature(taskType) {
			t.Errorf("%s runs unsigned", taskType)
		}
		if PasskeyEligible(taskType) {
			t.Errorf("a passkey can approve %s", taskType)
		}
	}
}

func TestValidateRefusesUnknownPolicyFields(t *testing.T) {
	if err := Validate(TaskPolicySet, json.RawMessage(`{"required_packages":["vim"],"hidden":1}`)); err == nil {
		t.Fatal("accepted an unknown field")
	}
}

func TestMergeAddsUp(t *testing.T) {
	merged, conflicts := MergePolicies(map[string]Policy{
		"all":  {RequiredPackages: []string{"vim", "git"}, CAs: []CAInstallPayload{{Name: "home", PEM: "p"}}, Security: &SecurityRule{Firewall: true}},
		"kids": {RequiredPackages: []string{"vim", "gcompris"}, ForbiddenPackages: []string{"steam"}, CAs: []CAInstallPayload{{Name: "home", PEM: "p"}}, Security: &SecurityRule{ScreenLock: true}, TimeZone: "UTC"},
	})
	if len(conflicts) > 0 {
		t.Fatalf("%+v", conflicts)
	}
	if !slices.Equal(merged.RequiredPackages, []string{"gcompris", "git", "vim"}) {
		t.Errorf("got %v", merged.RequiredPackages)
	}
	if len(merged.CAs) != 1 || merged.TimeZone != "UTC" || merged.ForbiddenPackages[0] != "steam" {
		t.Errorf("got %+v", merged)
	}
	if !merged.Security.Firewall || !merged.Security.ScreenLock {
		t.Errorf("the stricter rule did not win: %+v", merged.Security)
	}
}

func TestMergeNamesEveryConflict(t *testing.T) {
	window := Window{Days: []string{"mon"}, Start: "01:00", End: "02:00"}
	other := Window{Days: []string{"tue"}, Start: "01:00", End: "02:00"}
	a := Policy{
		RequiredPackages: []string{"vim"},
		RequiredFlatpaks: []string{"org.a"},
		Files:            []FilePutPayload{{Path: "/a", Content: "1"}},
		CAs:              []CAInstallPayload{{Name: "c", PEM: "1"}},
		Updates:          &UpdateRule{Window: window, Reboot: RebootNever},
		TimeZone:         "UTC",
		ScreenTime:       []ScreenTimeRule{{User: "anna", Windows: []Window{window}}},
	}
	b := Policy{
		ForbiddenPackages: []string{"vim"},
		ForbiddenFlatpaks: []string{"org.a"},
		Files:             []FilePutPayload{{Path: "/a", Content: "2"}},
		CAs:               []CAInstallPayload{{Name: "c", PEM: "2"}},
		Updates:           &UpdateRule{Window: other, Reboot: RebootNever},
		TimeZone:          "Europe/Berlin",
		ScreenTime:        []ScreenTimeRule{{User: "anna", Windows: []Window{other}}},
	}
	_, conflicts := MergePolicies(map[string]Policy{"a": a, "b": b})
	var items []string
	for _, c := range conflicts {
		items = append(items, c.Item)
		if !slices.Equal(c.Groups, []string{"a", "b"}) {
			t.Errorf("%s: groups %v", c.Item, c.Groups)
		}
	}
	want := []string{"CA c", "file /a", "flatpak org.a", "package vim", "screen time of anna", "time zone", "update rule"}
	if !slices.Equal(items, want) {
		t.Fatalf("got %v", items)
	}
}

func TestMergeIsStable(t *testing.T) {
	groups := map[string]Policy{
		"b": {RequiredPackages: []string{"z", "a"}, Files: []FilePutPayload{{Path: "/z"}, {Path: "/a"}}},
		"a": {RequiredPackages: []string{"m"}},
	}
	first, _ := MergePolicies(groups)
	for range 20 {
		next, _ := MergePolicies(groups)
		if next.Hash() != first.Hash() {
			t.Fatal("the same groups gave different hashes")
		}
	}
	if first.Files[0].Path != "/a" {
		t.Fatalf("got %+v", first.Files)
	}
}

func TestEmptyMergeIsZero(t *testing.T) {
	merged, _ := MergePolicies(map[string]Policy{"a": {}, "b": {RequiredPackages: []string{}}})
	if !merged.IsZero() {
		t.Fatalf("got %+v", merged)
	}
	if (Policy{RequiredPackages: []string{"vim"}}).IsZero() {
		t.Fatal("a policy with content counts as empty")
	}
}

func TestHashSurvivesAnEncodingRoundTrip(t *testing.T) {
	p := Policy{RequiredPackages: []string{"vim"}, Security: &SecurityRule{Firewall: true}}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var back Policy
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Hash() != p.Hash() {
		t.Fatal("agent and admin tool would disagree")
	}
}

func TestWindowBounds(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	w := Window{Days: []string{"sun"}, Start: "15:00", End: "24:00"}
	inside := time.Date(2026, 11, 8, 23, 59, 0, 0, berlin) // a Sunday
	if !w.Contains(inside) {
		t.Error("23:59 is inside a window that runs to the end of the day")
	}
	if w.Contains(time.Date(2026, 11, 9, 0, 0, 0, 0, berlin)) {
		t.Error("midnight belongs to the next day")
	}
	if w.Contains(time.Date(2026, 11, 8, 14, 59, 0, 0, berlin)) {
		t.Error("before the start")
	}
	if !w.Contains(time.Date(2026, 11, 8, 15, 0, 0, 0, berlin)) {
		t.Error("the start belongs to the window")
	}
	if (Window{Days: []string{"sat"}, Start: "15:00", End: "19:00"}).Contains(inside) {
		t.Error("wrong day")
	}
}

// On the day clocks change, a window follows the wall clock.
func TestWindowFollowsTheWallClockOverDaylightSaving(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Fatal(err)
	}
	w := Window{Days: []string{"sun"}, Start: "01:00", End: "05:00"}
	day := time.Date(2026, 3, 29, 12, 0, 0, 0, berlin) // clocks go forward at 02:00
	_, end, _ := w.Bounds(day.Add(-8 * time.Hour))
	if end.Hour() != 5 {
		t.Fatalf("got %v", end)
	}
	if !w.Contains(time.Date(2026, 3, 29, 4, 30, 0, 0, berlin)) {
		t.Fatal("04:30 is inside")
	}
}
