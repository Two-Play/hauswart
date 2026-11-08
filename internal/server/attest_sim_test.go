//go:build cgo

// The TPM simulator is C code, so these tests need cgo.

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/Two-Play/hauswart/internal/agent"
	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/pki"
)

// simChannel lets go-attestation talk to the simulator.
type simChannel struct{ *simulator.Simulator }

func (simChannel) MeasurementLog() ([]byte, error) { return nil, os.ErrNotExist }

// bootedTPM is a simulated TPM whose PCRs hold what the event log says, as
// after a real boot. seed picks the TPM: another seed, another EK.
func bootedTPM(t *testing.T, seed int64, eventLog []byte) *attest.TPM {
	t.Helper()
	sim, err := simulator.GetWithFixedSeedInsecure(seed)
	if err != nil {
		t.Fatal(err)
	}
	log, err := attest.ParseEventLog(eventLog)
	if err != nil {
		t.Fatal(err)
	}
	for _, bank := range []struct {
		hash attest.HashAlg
		alg  tpm2.Algorithm
	}{{attest.HashSHA1, tpm2.AlgSHA1}, {attest.HashSHA256, tpm2.AlgSHA256}} {
		for _, e := range log.Events(bank.hash) {
			if err := tpm2.PCRExtend(sim, tpmutil.Handle(e.Index), bank.alg, e.Digest, ""); err != nil {
				t.Fatal(err)
			}
		}
	}
	tpm, err := attest.OpenTPM(&attest.OpenConfig{CommandChannel: simChannel{sim}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tpm.Close() })
	return tpm
}

func eventLog(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *env) bootStatus(admin *http.Client, device string) api.BootStatus {
	e.t.Helper()
	code, data := e.do(admin, "GET", "/api/devices/"+device+"/boot", nil)
	if code != http.StatusOK {
		e.t.Fatalf("boot status: %d %s", code, data)
	}
	var status api.BootStatus
	json.Unmarshal(data, &status)
	return status
}

func TestAttestationEndToEnd(t *testing.T) {
	e := setup(t)
	device, client := e.enroll()
	if code, _ := e.do(client, "POST", "/agent/report", api.Report{Hostname: "laptop"}); code != http.StatusNoContent {
		t.Fatalf("report: %d", code)
	}
	admin := e.login("admin")
	dir := t.TempDir()
	log := eventLog(t, "ubuntu-no-secure-boot.eventlog")
	tpm := bootedTPM(t, 1, log)
	at := &agent.Attestor{Client: client, Server: e.ts.URL, Dir: dir, EventLog: log}
	ctx := context.Background()

	if err := at.Prove(ctx, tpm); err != nil {
		t.Fatal(err)
	}
	status := e.bootStatus(admin, device)
	if !status.Registered || status.Baseline == nil || status.LastAt == nil || len(status.Changes) != 0 {
		t.Fatalf("after the first quote: %+v", status)
	}
	if status.Baseline.SecureBoot || !strings.Contains(status.Baseline.CommandLine, "root=PARTUUID=") ||
		strings.Contains(status.Baseline.CommandLine, "vmlinuz") || status.Baseline.Firmware == "" {
		t.Fatalf("boot state: %+v", status.Baseline)
	}
	if _, err := os.Stat(filepath.Join(dir, "agent-ak.json")); err != nil {
		t.Fatal("the attestation key was not kept")
	}

	// The same boot again: nothing to tell, and no new registration.
	if err := at.Prove(ctx, tpm); err != nil {
		t.Fatal(err)
	}
	if status := e.bootStatus(admin, device); len(status.Changes) != 0 {
		t.Fatalf("the same boot changed: %+v", status.Changes)
	}
	audit, _ := e.store.ListAudit(ctx, 50)
	registered := 0
	for _, entry := range audit {
		if entry.Action == "tpm.registered" {
			registered++
		}
	}
	if registered != 1 {
		t.Fatalf("registered %d times", registered)
	}

	// A device that lies about its PCRs is caught by the quote.
	var nonce api.TPMNonce
	_, data := e.do(client, "POST", "/agent/tpm/nonce", struct{}{})
	json.Unmarshal(data, &nonce)
	ak, _ := os.ReadFile(filepath.Join(dir, "agent-ak.json"))
	var stored struct{ Blob, Public []byte }
	json.Unmarshal(ak, &stored)
	loaded, err := tpm.LoadAK(stored.Blob)
	if err != nil {
		t.Fatal(err)
	}
	platform, err := tpm.AttestPlatform(loaded, nonce.Nonce, &attest.PlatformAttestConfig{EventLog: log})
	if err != nil {
		t.Fatal(err)
	}
	lie := api.TPMQuote{AKPublic: stored.Public, EventLog: log}
	for _, q := range platform.Quotes {
		lie.Quotes = append(lie.Quotes, api.TPMQuoteSig{Quote: q.Quote, Signature: q.Signature})
	}
	for _, p := range platform.PCRs {
		digest := append([]byte(nil), p.Digest...)
		if p.Index == 8 {
			digest[0] ^= 1
		}
		lie.PCRs = append(lie.PCRs, api.TPMPCR{Index: p.Index, Digest: digest, Hash: uint(p.DigestAlg)})
	}
	if code, data := e.do(client, "POST", "/agent/tpm/quote", lie); code != http.StatusBadRequest {
		t.Fatalf("a lie: %d %s", code, data)
	}
	// The nonce is gone with it: an old quote does not come back either.
	if code, _ := e.do(client, "POST", "/agent/tpm/quote", lie); code != http.StatusConflict {
		t.Fatalf("a quote without a nonce: %d", code)
	}
	status = e.bootStatus(admin, device)
	if len(status.Changes) != 1 || status.Changes[0].Kind != api.BootQuote || !status.Changes[0].Alarm {
		t.Fatalf("after a lie: %+v", status.Changes)
	}
	code, data := e.do(admin, "GET", "/api/devices", nil)
	if !strings.Contains(string(data), api.WarnBootChanged) {
		t.Fatalf("no warning on the card: %d %s", code, data)
	}
	if code, _ := e.do(admin, "POST", "/api/devices/"+device+"/boot/accept", nil); code != http.StatusNoContent {
		t.Fatalf("accept: %d", code)
	}
	if status := e.bootStatus(admin, device); len(status.Changes) != 0 {
		t.Fatalf("after accepting: %+v", status.Changes)
	}
	loaded.Close(tpm)
}

func TestAnotherTPMWaitsForAnAdmin(t *testing.T) {
	e := setup(t)
	device, client := e.enroll()
	admin := e.login("admin")
	dir := t.TempDir()
	log := eventLog(t, "ubuntu-no-secure-boot.eventlog")
	ctx := context.Background()

	first := bootedTPM(t, 1, log)
	if err := (&agent.Attestor{Client: client, Server: e.ts.URL, Dir: dir, EventLog: log}).Prove(ctx, first); err != nil {
		t.Fatal(err)
	}
	first.Close()
	// The mainboard was swapped, or the agent's files were copied elsewhere.
	other := bootedTPM(t, 2, log)
	os.Remove(filepath.Join(dir, "agent-ak.json"))
	err := (&agent.Attestor{Client: client, Server: e.ts.URL, Dir: dir, EventLog: log}).Prove(ctx, other)
	if err == nil {
		t.Fatal("the other TPM's quote counted")
	}
	status := e.bootStatus(admin, device)
	if status.OtherTPM == "" || status.OtherTPM == status.EK || len(status.Changes) != 1 || status.Changes[0].Kind != api.BootTPM {
		t.Fatalf("other TPM: %+v", status)
	}
	if code, _ := e.do(admin, "POST", "/api/devices/"+device+"/boot/accept", nil); code != http.StatusNoContent {
		t.Fatalf("accept: %d", code)
	}
	// The key was dropped after the refusal; the next round registers it again
	// and the accepted TPM's quotes count.
	if err := (&agent.Attestor{Client: client, Server: e.ts.URL, Dir: dir, EventLog: log}).Prove(ctx, other); err != nil {
		t.Fatal(err)
	}
	status = e.bootStatus(admin, device)
	if status.OtherTPM != "" || status.Baseline == nil || len(status.Changes) != 0 {
		t.Fatalf("after accepting the other TPM: %+v", status)
	}
}

func TestSecureBootIsRead(t *testing.T) {
	e := setup(t)
	_, client := e.enroll()
	log := eventLog(t, "secure-boot.eventlog")
	tpm := bootedTPM(t, 1, log)
	if err := (&agent.Attestor{Client: client, Server: e.ts.URL, Dir: t.TempDir(), EventLog: log}).Prove(context.Background(), tpm); err != nil {
		t.Fatal(err)
	}
	records, _ := e.store.TPMs(context.Background())
	for _, rec := range records {
		if rec.Baseline == nil || !rec.Baseline.SecureBoot || rec.Baseline.SecureBootKeys == "" {
			t.Fatalf("secure boot: %+v", rec.Baseline)
		}
	}
}

// tpmClient is a device client whose TLS key is in the TPM.
func (e *env) tpmClient(t *testing.T, tpm *attest.TPM, blob []byte, certPEM string) *http.Client {
	t.Helper()
	key, err := tpm.LoadKey(blob)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { key.Close() })
	private, err := key.Private(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.ParseCert([]byte(certPEM))
	if err != nil {
		t.Fatal(err)
	}
	return e.client(tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: private, Leaf: leaf})
}

func TestKeyMovesIntoTheTPM(t *testing.T) {
	e := setup(t)
	device, fileClient := e.enroll()
	log := eventLog(t, "ubuntu-no-secure-boot.eventlog")
	tpm := bootedTPM(t, 1, log)
	at := &agent.Attestor{Client: fileClient, Server: e.ts.URL, Dir: t.TempDir(), EventLog: log}
	ctx := context.Background()
	if err := at.Prove(ctx, tpm); err != nil {
		t.Fatal(err)
	}
	blob, certPEM, public, err := at.CertifiedKey(ctx, tpm)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := pki.ParseCert([]byte(certPEM))
	if leaf.Subject.CommonName != device {
		t.Fatalf("certificate for %s", leaf.Subject.CommonName)
	}
	if derived, _ := pki.DeviceID(public); derived == device {
		t.Fatal("the TPM key is the file key")
	}

	// A TLS handshake signed in the TPM, which makes the new certificate the
	// device's and ends the old one.
	tpmClient := e.tpmClient(t, tpm, blob, certPEM)
	if code, data := e.do(tpmClient, "POST", "/agent/report", api.Report{Hostname: "laptop"}); code != http.StatusNoContent {
		t.Fatalf("report with the TPM key: %d %s", code, data)
	}
	if code, _ := e.do(fileClient, "POST", "/agent/report", api.Report{Hostname: "laptop"}); code != http.StatusForbidden {
		t.Fatalf("the file key still works: %d", code)
	}

	// Renewal keeps the TPM key and the ID.
	key, _ := tpm.LoadKey(blob)
	defer key.Close()
	private, _ := key.Private(key.Public())
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if code, data := e.do(tpmClient, "POST", "/agent/renew", api.RenewRequest{CSR: csr}); code != http.StatusOK {
		t.Fatalf("renew with the TPM key: %d %s", code, data)
	}
	status := e.bootStatus(e.login("admin"), device)
	if !status.KeyInTPM {
		t.Fatal("the dashboard does not know the key is in the TPM")
	}
}

func TestOnlyCertifiedTPMKeysGetACertificate(t *testing.T) {
	e := setup(t)
	_, client := e.enroll()
	log := eventLog(t, "ubuntu-no-secure-boot.eventlog")
	tpm := bootedTPM(t, 1, log)
	dir := t.TempDir()
	at := &agent.Attestor{Client: client, Server: e.ts.URL, Dir: dir, EventLog: log}
	if err := at.Prove(context.Background(), tpm); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "agent-ak.json"))
	var stored struct{ Blob []byte }
	json.Unmarshal(raw, &stored)
	ak, err := tpm.LoadAK(stored.Blob)
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close(tpm)
	key, err := tpm.NewKey(ak, &attest.KeyConfig{Algorithm: attest.ECDSA, Size: 256})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()
	params := key.CertificationParameters()

	// A key in a file, with the certification of a key in the TPM.
	file, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, file)
	swapped := api.TPMRekey{CSR: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})),
		Public: params.Public, CreateData: params.CreateData, CreateAttestation: params.CreateAttestation, CreateSignature: params.CreateSignature}
	if code, data := e.do(client, "POST", "/agent/tpm/rekey", swapped); code != http.StatusBadRequest {
		t.Fatalf("a file key passed: %d %s", code, data)
	}
	// A certification whose signature does not hold.
	private, _ := key.Private(key.Public())
	der, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, private)
	forged := swapped
	forged.CSR = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	forged.CreateSignature = append([]byte(nil), params.CreateSignature...)
	forged.CreateSignature[len(forged.CreateSignature)-1] ^= 1
	if code, data := e.do(client, "POST", "/agent/tpm/rekey", forged); code != http.StatusBadRequest {
		t.Fatalf("a forged certification passed: %d %s", code, data)
	}
	// A device without a registered TPM gets nothing.
	_, other := e.enroll()
	if code, _ := e.do(other, "POST", "/agent/tpm/rekey", forged); code != http.StatusConflict {
		t.Fatalf("an unregistered device: %d", code)
	}
}
