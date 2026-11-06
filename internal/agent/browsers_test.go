package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/pki"
)

func testCert(t *testing.T) string {
	t.Helper()
	ca, err := pki.LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return string(ca.CertPEM)
}

func TestFirefoxPolicyKeepsForeignSettings(t *testing.T) {
	e, _ := newExecutor(t)
	dir := e.path(firefoxPolicyDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := `{"policies":{"DisableTelemetry":true,"Certificates":{"Install":["/other.crt"]}}}`
	if err := os.WriteFile(filepath.Join(dir, "policies.json"), []byte(existing), 0o644); err != nil {
		t.Fatal(err)
	}
	for range 2 { // running twice must not add the certificate twice
		if err := e.firefoxPolicy("family", testCert(t)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(filepath.Join(dir, "policies.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Policies struct {
			DisableTelemetry bool
			Certificates     struct{ Install []string }
		} `json:"policies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if !doc.Policies.DisableTelemetry {
		t.Error("foreign setting lost")
	}
	want := []string{"/other.crt", firefoxPolicyDir + "/hauswart-family.crt"}
	if !slices.Equal(doc.Policies.Certificates.Install, want) {
		t.Errorf("got %v", doc.Policies.Certificates.Install)
	}
}

func TestFirefoxPolicyLeavesBrokenFileAlone(t *testing.T) {
	e, _ := newExecutor(t)
	dir := e.path(firefoxPolicyDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "policies.json")
	if err := os.WriteFile(file, []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := e.firefoxPolicy("family", testCert(t)); err == nil {
		t.Fatal("overwrote a file it could not read")
	}
	if raw, _ := os.ReadFile(file); string(raw) != "{broken" {
		t.Fatal("file changed")
	}
}

func TestChromiumPolicyHoldsTheCertificate(t *testing.T) {
	e, _ := newExecutor(t)
	cert := testCert(t)
	if err := e.chromiumPolicies("family", cert); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.path("/etc/chromium/policies/managed/hauswart-family.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ CACertificates []string }
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(cert))
	if len(doc.CACertificates) != 1 || doc.CACertificates[0] != base64.StdEncoding.EncodeToString(block.Bytes) {
		t.Fatalf("got %s", raw)
	}
	if _, err := os.Stat(e.path("/etc/opt/chrome/policies/managed/hauswart-family.json")); err != nil {
		t.Error("no policy for Chrome")
	}
	if _, err := os.Stat(e.path("/var/snap")); err == nil {
		t.Error("created a snap directory without the snap")
	}
}

func TestBrowserPoliciesOnlyWhereMeasured(t *testing.T) {
	for _, withBrowsers := range []bool{false, true} {
		e, _ := newExecutor(t)
		e.Platform.Trust = &Trust{Dir: "/anchors", Update: []string{"update"}, Browsers: withBrowsers}
		res := e.Execute(context.Background(), task(t, api.TaskCAInstall, api.CAInstallPayload{Name: "family", PEM: testCert(t)}))
		if !res.OK {
			t.Fatal(res.Output)
		}
		_, err := os.Stat(e.path(firefoxPolicyDir))
		if (err == nil) != withBrowsers {
			t.Errorf("Browsers=%v: policy dir %v", withBrowsers, err)
		}
	}
}
