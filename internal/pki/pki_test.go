package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newCSR(t *testing.T, commonName string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: commonName}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func TestCAPersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatal("CA changed across restart, every enrolled device would be cut off")
	}
}

func TestCAKeyIsPrivate(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadOrCreate(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode %v", info.Mode().Perm())
	}
}

func TestSignDeviceSetsIdentityItself(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	certPEM, serial, err := ca.SignDevice(newCSR(t, "someone-else"), "device-1")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Subject.CommonName != "device-1" {
		t.Fatalf("CN %q taken from the CSR", cert.Subject.CommonName)
	}
	if cert.SerialNumber.Text(16) != serial {
		t.Fatal("returned serial does not match the certificate")
	}
	if cert.IsCA {
		t.Fatal("device certificate is a CA")
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		t.Fatalf("not valid for client auth: %v", err)
	}
	_, err = cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	if err == nil {
		t.Fatal("device certificate can impersonate the server")
	}
}

func TestDeviceValidityOverride(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca.DeviceValidity = 80 * time.Second
	certPEM, _, err := ca.SignDevice(newCSR(t, "x"), "d")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ParseCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != 100*time.Second {
		t.Fatalf("lifetime %v", got)
	}
}

func TestSignDeviceRejectsBadCSR(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ca.SignDevice([]byte("not pem"), "d"); err == nil {
		t.Fatal("accepted garbage")
	}
	csr := newCSR(t, "x")
	block, _ := pem.Decode(csr)
	block.Bytes[len(block.Bytes)-1] ^= 0xff
	if _, _, err := ca.SignDevice(pem.EncodeToMemory(block), "d"); err == nil {
		t.Fatal("accepted a CSR with a broken signature")
	}
}

func TestServerCertCoversHosts(t *testing.T) {
	ca, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ca.ServerCert([]string{"hauswart.home", "10.0.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"hauswart.home", "10.0.0.2"} {
		if err := cert.VerifyHostname(host); err != nil {
			t.Error(err)
		}
	}
	if err := cert.VerifyHostname("other.home"); err == nil {
		t.Error("certificate covers an unrelated host")
	}
}

func TestServerCertSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	first, err := ca.ServerCert([]string{"hauswart.home"})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := restarted.ServerCert([]string{"hauswart.home"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Fatal("certificate changed across restart")
	}
	third, err := restarted.ServerCert([]string{"hauswart.home", "new.home"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first.Certificate[0], third.Certificate[0]) {
		t.Fatal("kept a certificate that does not cover a new host")
	}
	info, err := os.Stat(filepath.Join(dir, serverKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("server key mode %v", info.Mode().Perm())
	}
}
