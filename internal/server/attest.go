package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/legacy/tpm2"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/notify"
	"github.com/Two-Play/hauswart/internal/pki"
	"github.com/Two-Play/hauswart/internal/store"
)

const (
	// tpmChallengeTTL is how long a device has to answer an activation.
	tpmChallengeTTL = 10 * time.Minute
	// tpmNonceTTL is how long a nonce waits for its quote.
	tpmNonceTTL = 5 * time.Minute
	// attestationOverdue is when a device that reports but sends no quote
	// gets a warning. It quotes every few hours.
	attestationOverdue = 3 * 24 * time.Hour
	// recentlySeen is how fresh a report must be for a missing quote to count.
	recentlySeen = time.Hour
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("POST /agent/tpm/register", s.agent(s.handleTPMRegister))
		mux.Handle("POST /agent/tpm/activate", s.agent(s.handleTPMActivate))
		mux.Handle("POST /agent/tpm/nonce", s.agent(s.handleTPMNonce))
		mux.Handle("POST /agent/tpm/quote", s.agent(s.handleTPMQuote))
		mux.Handle("POST /agent/tpm/rekey", s.agent(s.handleTPMRekey))
		mux.Handle("GET /api/devices/{id}/boot", s.admin(s.handleBootStatus))
		mux.Handle("POST /api/devices/{id}/boot/accept", s.admin(s.handleBootAccept))
	})
}

// tpmState holds what waits for a device's next step, in memory: a restart
// only means that the device starts that step again.
type tpmState struct {
	mu      sync.Mutex
	pending map[string]tpmPending
	nonces  map[string]tpmNonce
	// records keeps the read-modify-write of a device's record one at a time.
	records sync.Mutex
}

type tpmPending struct {
	secret   []byte
	ek       string
	akPublic []byte
	until    time.Time
}

type tpmNonce struct {
	nonce []byte
	until time.Time
}

// ekFingerprint names a TPM by its endorsement key.
func ekFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// handleTPMRegister starts the activation of an attestation key: the challenge
// can only be read by the TPM that holds both the EK and the AK.
func (s *Server) handleTPMRegister(w http.ResponseWriter, r *http.Request, device string) {
	var in api.TPMRegistration
	if !readJSON(w, r, &in) {
		return
	}
	for _, blob := range [][]byte{in.EKPublic, in.AKPublic, in.CreateData, in.CreateAttestation, in.CreateSignature} {
		if len(blob) == 0 || len(blob) > api.MaxTPMBlob {
			fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "size")
			return
		}
	}
	ek, err := x509.ParsePKIXPublicKey(in.EKPublic)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "endorsement key")
		return
	}
	params := attest.ActivationParameters{EK: ek, AK: attest.AttestationParameters{
		Public: in.AKPublic, CreateData: in.CreateData, CreateAttestation: in.CreateAttestation, CreateSignature: in.CreateSignature,
	}}
	secret, challenge, err := params.Generate()
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "attestation key")
		return
	}
	s.tpm.mu.Lock()
	if s.tpm.pending == nil {
		s.tpm.pending = map[string]tpmPending{}
	}
	s.tpm.pending[device] = tpmPending{secret: secret, ek: ekFingerprint(in.EKPublic), akPublic: in.AKPublic,
		until: time.Now().Add(tpmChallengeTTL)}
	s.tpm.mu.Unlock()
	writeJSON(w, http.StatusOK, api.TPMChallenge{Credential: challenge.Credential, Secret: challenge.Secret})
}

// handleTPMActivate trusts the attestation key once the device read the
// challenge. The first TPM of a device is trusted as it comes; another one
// waits for an admin.
func (s *Server) handleTPMActivate(w http.ResponseWriter, r *http.Request, device string) {
	var in api.TPMActivation
	if !readJSON(w, r, &in) {
		return
	}
	s.tpm.mu.Lock()
	pending, ok := s.tpm.pending[device]
	delete(s.tpm.pending, device)
	s.tpm.mu.Unlock()
	if !ok || time.Now().After(pending.until) || subtle.ConstantTimeCompare(pending.secret, in.Secret) != 1 {
		fail(w, http.StatusForbidden, api.ErrTPMChallenge)
		return
	}
	s.tpm.records.Lock()
	defer s.tpm.records.Unlock()
	rec, err := s.store.TPM(r.Context(), device)
	switch {
	case errors.Is(err, store.ErrNotFound):
		rec = store.TPMRecord{EK: pending.ek, AKPublic: pending.akPublic}
		s.audit(r, device, "tpm.registered", pending.ek)
	case err != nil:
		s.internal(w, err)
		return
	case rec.EK == pending.ek:
		// The same TPM with a new key, such as after the agent was installed again.
		rec.AKPublic = pending.akPublic
		s.audit(r, device, "tpm.key_renewed", pending.ek)
	default:
		rec.PendingEK, rec.PendingAK = pending.ek, pending.akPublic
		s.addBootChanges(r.Context(), device, &rec, []string{api.BootTPM})
		s.audit(r, device, "tpm.other_tpm", pending.ek)
	}
	if err := s.store.SaveTPM(r.Context(), device, rec); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleTPMNonce(w http.ResponseWriter, _ *http.Request, device string) {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	s.tpm.mu.Lock()
	if s.tpm.nonces == nil {
		s.tpm.nonces = map[string]tpmNonce{}
	}
	s.tpm.nonces[device] = tpmNonce{nonce: nonce, until: time.Now().Add(tpmNonceTTL)}
	s.tpm.mu.Unlock()
	writeJSON(w, http.StatusOK, api.TPMNonce{Nonce: nonce})
}

// handleTPMQuote checks a quote and the event log behind it, and compares the
// boot it describes with the one an admin accepted.
func (s *Server) handleTPMQuote(w http.ResponseWriter, r *http.Request, device string) {
	var in api.TPMQuote
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.EventLog) > api.MaxEventLog || len(in.Quotes) == 0 || len(in.Quotes) > api.MaxTPMQuotes ||
		len(in.PCRs) == 0 || len(in.PCRs) > api.MaxTPMPCRs {
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "size")
		return
	}
	s.tpm.mu.Lock()
	nonce, ok := s.tpm.nonces[device]
	delete(s.tpm.nonces, device)
	s.tpm.mu.Unlock()
	if !ok || time.Now().After(nonce.until) {
		fail(w, http.StatusConflict, api.ErrTPMChallenge)
		return
	}

	s.tpm.records.Lock()
	defer s.tpm.records.Unlock()
	rec, err := s.store.TPM(r.Context(), device)
	if errors.Is(err, store.ErrNotFound) || (err == nil && !bytes.Equal(rec.AKPublic, in.AKPublic)) {
		// Not a key the server trusts, such as one of another TPM that waits
		// for an admin. The device registers again later.
		fail(w, http.StatusConflict, api.ErrTPMUnknown)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	state, err := verifyQuote(rec.AKPublic, in, nonce.nonce)
	if err != nil {
		s.log.Warn("a quote did not verify", "device", device, "err", err)
		s.addBootChanges(r.Context(), device, &rec, []string{api.BootQuote})
		if err := s.store.SaveTPM(r.Context(), device, rec); err != nil {
			s.log.Error("saving the TPM record failed", "device", device, "err", err)
		}
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "quote")
		return
	}
	rec.Current, rec.LastAt = &state, time.Now()
	if rec.Baseline == nil {
		baseline := state
		rec.Baseline = &baseline
		s.audit(r, device, "tpm.baseline", "")
	} else {
		if state.SecureBoot {
			// Updates of shim, grub and the kernel are signed, and Secure Boot
			// checked them.
			rec.Baseline.Bootloaders = state.Bootloaders
		}
		s.addBootChanges(r.Context(), device, &rec, api.CompareBoot(*rec.Baseline, state))
	}
	if err := s.store.SaveTPM(r.Context(), device, rec); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// verifyQuote checks the quotes against the trusted key and the nonce, and the
// event log against the quoted PCRs, and reads the boot from what checked out.
func verifyQuote(akPublic []byte, in api.TPMQuote, nonce []byte) (api.BootState, error) {
	ak, err := attest.ParseAKPublic(akPublic)
	if err != nil {
		return api.BootState{}, err
	}
	quotes := make([]attest.Quote, 0, len(in.Quotes))
	for _, q := range in.Quotes {
		quotes = append(quotes, attest.Quote{Quote: q.Quote, Signature: q.Signature})
	}
	pcrs := make([]attest.PCR, 0, len(in.PCRs))
	for _, p := range in.PCRs {
		hash := crypto.Hash(p.Hash)
		if hash != crypto.SHA1 && hash != crypto.SHA256 && hash != crypto.SHA384 && hash != crypto.SHA512 {
			return api.BootState{}, fmt.Errorf("PCR bank %d", p.Hash)
		}
		pcrs = append(pcrs, attest.PCR{Index: p.Index, Digest: p.Digest, DigestAlg: hash})
	}
	if err := ak.VerifyAll(quotes, pcrs, nonce); err != nil {
		return api.BootState{}, err
	}
	log, err := attest.ParseEventLog(in.EventLog)
	if err != nil {
		return api.BootState{}, err
	}
	events, err := log.Verify(pcrs)
	if err != nil {
		return api.BootState{}, err
	}
	return readBootState(events, pcrs), nil
}

// addBootChanges notes what differs and tells admins about what is new.
// Changes stay until an admin accepts the boot, even if they went away.
func (s *Server) addBootChanges(ctx context.Context, device string, rec *store.TPMRecord, kinds []string) {
	var fresh []string
	for _, kind := range kinds {
		known := false
		for _, c := range rec.Changes {
			known = known || c.Kind == kind
		}
		if !known {
			rec.Changes = append(rec.Changes, api.BootChange{Kind: kind, Alarm: api.BootAlarm(kind), At: time.Now()})
			fresh = append(fresh, kind)
		}
	}
	if len(fresh) == 0 || s.notifier == nil {
		return
	}
	hostname := device
	if report, err := s.store.DeviceReport(ctx, device); err == nil && report != nil && report.Hostname != "" {
		hostname = report.Hostname
	}
	what := "started differently than accepted"
	for _, kind := range fresh {
		if api.BootAlarm(kind) {
			what = "ALARM: started differently than accepted"
		}
	}
	s.notifier.SendAs(notify.SubjectAttention, fmt.Sprintf("%s %s: %s.\nSee Devices in the dashboard: %s",
		plainName(hostname), what, strings.Join(fresh, ", "), s.publicURL))
}

func (s *Server) handleBootStatus(w http.ResponseWriter, r *http.Request, _ store.User) {
	rec, err := s.store.TPM(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusOK, api.BootStatus{Changes: []api.BootChange{}})
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	status := api.BootStatus{Registered: true, EK: rec.EK, Baseline: rec.Baseline, Current: rec.Current,
		Changes: rec.Changes, OtherTPM: rec.PendingEK, KeyInTPM: rec.TLSKey != ""}
	if status.Changes == nil {
		status.Changes = []api.BootChange{}
	}
	if !rec.LastAt.IsZero() {
		status.LastAt = &rec.LastAt
	}
	writeJSON(w, http.StatusOK, status)
}

// handleBootAccept takes the current boot as the one to compare with, or the
// other TPM as the device's own.
func (s *Server) handleBootAccept(w http.ResponseWriter, r *http.Request, u store.User) {
	device := r.PathValue("id")
	s.tpm.records.Lock()
	defer s.tpm.records.Unlock()
	rec, err := s.store.TPM(r.Context(), device)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrTPMUnknown)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if rec.PendingEK != "" {
		rec.EK, rec.AKPublic = rec.PendingEK, rec.PendingAK
		rec.PendingEK, rec.PendingAK = "", nil
		// The next quote of the new TPM sets the boot to compare with.
		rec.Baseline, rec.Current, rec.LastAt = nil, nil, time.Time{}
	} else if rec.Current != nil {
		current := *rec.Current
		rec.Baseline = &current
	}
	rec.Changes = nil
	if err := s.store.SaveTPM(r.Context(), device, rec); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "tpm.accepted", device)
	w.WriteHeader(http.StatusNoContent)
}

// bootWarnings says what an admin should look at in a device's boot.
func bootWarnings(d store.Device, rec *store.TPMRecord, now time.Time) []api.Warning {
	if rec == nil || d.Revoked {
		return nil
	}
	var warnings []api.Warning
	alarms := 0
	for _, c := range rec.Changes {
		if c.Alarm {
			alarms++
		}
	}
	if alarms > 0 {
		warnings = append(warnings, api.Warning{Code: api.WarnBootChanged, Value: alarms})
	}
	seen := time.Unix(d.LastSeen, 0)
	if !rec.LastAt.IsZero() && now.Sub(seen) < recentlySeen && now.Sub(rec.LastAt) > attestationOverdue {
		warnings = append(warnings, api.Warning{Code: api.WarnAttestationMissing, Value: int(now.Sub(rec.LastAt) / (24 * time.Hour))})
	}
	return warnings
}

// keyFingerprint names a public key by its PKIX encoding.
func keyFingerprint(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// handleTPMRekey issues a certificate for a TLS key that the device's trusted
// AK certified as made in the TPM and bound to it. The device keeps its ID,
// and from then on its identity cannot be copied with its files.
func (s *Server) handleTPMRekey(w http.ResponseWriter, r *http.Request, device string) {
	var in api.TPMRekey
	if !readJSON(w, r, &in) {
		return
	}
	// The certification needs no creation data, which the TPM may leave out.
	for _, blob := range [][]byte{in.Public, in.CreateAttestation, in.CreateSignature} {
		if len(blob) == 0 || len(blob) > api.MaxTPMBlob {
			fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "size")
			return
		}
	}
	if len(in.CreateData) > api.MaxTPMBlob {
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "size")
		return
	}
	s.tpm.records.Lock()
	defer s.tpm.records.Unlock()
	rec, err := s.store.TPM(r.Context(), device)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusConflict, api.ErrTPMUnknown)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if rec.PendingEK != "" {
		// Another TPM waits for an admin; it must not get a key before.
		fail(w, http.StatusConflict, api.ErrTPMUnknown)
		return
	}
	ak, err := attest.ParseAKPublic(rec.AKPublic)
	if err != nil {
		s.internal(w, err)
		return
	}
	params := attest.CertificationParameters{Public: in.Public, CreateData: in.CreateData,
		CreateAttestation: in.CreateAttestation, CreateSignature: in.CreateSignature}
	if err := params.Verify(attest.VerifyOpts{Public: ak.Public, Hash: ak.Hash}); err != nil {
		s.log.Warn("a TPM key certification did not verify", "device", device, "err", err)
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "certification")
		return
	}
	certified, err := tpm2.DecodePublic(in.Public)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "key")
		return
	}
	key, err := certified.Key()
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidTPM, "key")
		return
	}
	csr, err := pki.ParseCSR([]byte(in.CSR))
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidCSR)
		return
	}
	want, err1 := keyFingerprint(key)
	got, err2 := keyFingerprint(csr.PublicKey)
	if err1 != nil || err2 != nil || want != got {
		fail(w, http.StatusBadRequest, api.ErrInvalidCSR)
		return
	}
	cert, serial, err := s.ca.SignDeviceAs(csr, device)
	if err != nil {
		s.internal(w, err)
		return
	}
	rec.TLSKey = got
	if err := s.store.SaveTPM(r.Context(), device, rec); err != nil {
		s.internal(w, err)
		return
	}
	if err := s.store.SetNextSerial(r.Context(), device, serial); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, "agent:"+device, "tpm.key", serial)
	writeJSON(w, http.StatusOK, api.RenewResponse{Cert: string(cert)})
}
