//go:build cgo

// The TPM simulator is C code, so these tests need cgo.

package server

import (
	"context"
	"encoding/json"
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
