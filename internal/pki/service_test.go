package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func scopedCA(t *testing.T, scope ...string) *CA {
	t.Helper()
	ca, err := LoadOrCreate(t.TempDir(), scope...)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestServiceCertWorksForItsName(t *testing.T) {
	ca := scopedCA(t, "home.lan", "10.8.0.0/24")
	cert, err := ca.IssueService([]string{"nas.home.lan", "10.8.0.5"}, 90*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert.CertPEM, cert.KeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"nas.home.lan", "10.8.0.5"} {
		opts := x509.VerifyOptions{Roots: ca.Pool(), DNSName: name}
		if _, err := leaf.Verify(opts); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	if leaf.Subject.CommonName != "nas.home.lan" || leaf.IsCA {
		t.Errorf("got CN %q, CA %v", leaf.Subject.CommonName, leaf.IsCA)
	}
	if got := time.Until(leaf.NotAfter); got < 89*24*time.Hour || got > 91*24*time.Hour {
		t.Errorf("validity %v", got)
	}
	if _, ok := pair.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Errorf("key is %T", pair.PrivateKey)
	}
}

func TestServiceCertCannotActAsADevice(t *testing.T) {
	ca := scopedCA(t, "home.lan")
	cert, err := ca.IssueService([]string{"nas.home.lan"}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := ParseCert(cert.CertPEM)
	if err != nil {
		t.Fatal(err)
	}
	opts := x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if _, err := leaf.Verify(opts); err == nil {
		t.Fatal("service certificate works as a client certificate")
	}
}

func TestServiceCertStaysInsideTheConstraints(t *testing.T) {
	ca := scopedCA(t, "home.lan", "10.8.0.0/24")
	for _, name := range []string{"google.com", "home.lan.evil.com", "evilhome.lan", "10.9.0.1", "invalid", "x.invalid", "192.0.2.0"} {
		_, err := ca.IssueService([]string{"nas.home.lan", name}, time.Hour)
		var outside *OutsideError
		if !errors.As(err, &outside) || outside.Name != name {
			t.Errorf("%s: got %v", name, err)
		}
	}
}

func TestPlaceholdersAreNotPermitted(t *testing.T) {
	ca := scopedCA(t, "home.lan") // gets the placeholder IP
	if _, err := ca.IssueService([]string{"192.0.2.0"}, time.Hour); err == nil {
		t.Error("issued for the placeholder address")
	}
	ca = scopedCA(t, "10.0.0.0/8") // gets the placeholder domain
	if _, err := ca.IssueService([]string{"invalid"}, time.Hour); err == nil {
		t.Error("issued for the placeholder domain")
	}
}

func TestUnconstrainedCAIssuesNothing(t *testing.T) {
	ca := scopedCA(t)
	if _, err := ca.IssueService([]string{"nas.home.lan"}, time.Hour); !errors.Is(err, ErrNotConstrained) {
		t.Fatalf("got %v", err)
	}
}

func TestServiceValidityIsCapped(t *testing.T) {
	ca := scopedCA(t, "home.lan")
	cert, err := ca.IssueService([]string{"nas.home.lan"}, 10*365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(cert.NotAfter) > MaxServiceValidity {
		t.Fatalf("valid until %v", cert.NotAfter)
	}
}

func TestServiceKeyIsNotWrittenToDisk(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, "home.lan")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.IssueService([]string{"nas.home.lan"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(cert.KeyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("key is %q", cert.KeyPEM)
	}
	assertNotOnDisk(t, dir, block.Bytes)
}

func assertNotOnDisk(t *testing.T, dir string, secret []byte) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(raw, secret) || bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString(secret)[:40])) {
			t.Errorf("key found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
