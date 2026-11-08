package server

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
	"github.com/Two-Play/hauswart/internal/store"
)

const (
	registrationTTL = 5 * time.Minute
	// passkeyEnvelopeLifetime stays below the limit on the device, and a short
	// value leaves a hacked server less time to sit on an approval.
	passkeyEnvelopeLifetime = 12 * time.Hour
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/passkeys", s.approver(s.handlePasskeys))
		mux.Handle("POST /api/passkeys/options", s.approver(s.handlePasskeyOptions))
		mux.Handle("POST /api/passkeys", s.approver(s.handleRegisterPasskey))
		mux.Handle("DELETE /api/passkeys/{id}", s.approver(s.handleDeletePasskey))
		mux.Handle("GET /api/approvals", s.approver(s.handleApprovals))
		mux.Handle("POST /api/tasks/{id}/passkey-challenge", s.approver(s.handlePasskeyChallenge))
		mux.Handle("POST /api/tasks/{id}/passkey-approval", s.approver(s.handlePasskeyApproval))
	})
}

// registration is a challenge that waits for the browser.
type registration struct {
	challenge []byte
	expires   time.Time
}

// relyingParty derives the WebAuthn identity from the public URL. An address
// cannot be a relying party, so a server reached by IP has no passkeys.
func (s *Server) relyingParty() (id, origin string, ok bool) {
	u, err := url.Parse(s.publicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || net.ParseIP(u.Hostname()) != nil {
		return "", "", false
	}
	return u.Hostname(), s.publicURL, true
}

// ownerFilter is 0 for an admin, who sees all passkeys.
func ownerFilter(u store.User) int64 {
	if u.Role == store.RoleAdmin {
		return 0
	}
	return u.ID
}

func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request, u store.User) {
	passkeys, err := s.store.ListPasskeys(r.Context(), ownerFilter(u))
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, passkeys)
}

func (s *Server) handlePasskeyOptions(w http.ResponseWriter, r *http.Request, u store.User) {
	rpID, _, ok := s.relyingParty()
	if !ok {
		fail(w, http.StatusConflict, api.ErrNoPasskeyHost)
		return
	}
	challenge := []byte(store.RandomToken())
	s.mu.Lock()
	s.registrations[u.ID] = registration{challenge: challenge, expires: time.Now().Add(registrationTTL)}
	s.mu.Unlock()
	existing, err := s.store.ListPasskeys(r.Context(), u.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	exclude := make([][]byte, 0, len(existing))
	for _, p := range existing {
		exclude = append(exclude, p.CredentialID)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge": challenge,
		"rp_id":     rpID,
		"user_id":   []byte(strconv.FormatInt(u.ID, 10)),
		"username":  u.Username,
		"exclude":   exclude,
	})
}

// handleRegisterPasskey stores a candidate. The checks here only serve an honest
// server: what counts is what the admin pins later.
func (s *Server) handleRegisterPasskey(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Name           string `json:"name"`
		CredentialID   []byte `json:"credential_id"`
		PublicKey      []byte `json:"public_key"`
		ClientDataJSON []byte `json:"client_data_json"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	rpID, origin, ok := s.relyingParty()
	if !ok {
		fail(w, http.StatusConflict, api.ErrNoPasskeyHost)
		return
	}
	s.mu.Lock()
	open, found := s.registrations[u.ID]
	delete(s.registrations, u.ID)
	s.mu.Unlock()
	var client struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if !found || time.Now().After(open.expires) || json.Unmarshal(in.ClientDataJSON, &client) != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidPasskey)
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(client.Challenge)
	if err != nil || !bytes.Equal(challenge, open.challenge) || client.Type != "webauthn.create" || client.Origin != origin {
		fail(w, http.StatusBadRequest, api.ErrInvalidPasskey)
		return
	}
	passkey := sign.Passkey{
		Name: in.Name, CredentialID: in.CredentialID, PublicKey: in.PublicKey,
		RPID: rpID, Origin: origin, NotAfter: time.Now().Add(time.Hour),
	}
	if err := sign.ValidPasskey(passkey); err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidPasskey)
		return
	}
	id, err := s.store.CreatePasskey(r.Context(), u.ID, passkey)
	if err != nil {
		fail(w, http.StatusConflict, api.ErrInvalidPasskey)
		return
	}
	s.audit(r, u.Username, "passkey.registered", in.Name)
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request, u store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidPasskey)
		return
	}
	err = s.store.DeletePasskey(r.Context(), id, ownerFilter(u))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrInvalidPasskey)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "passkey.deleted", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleApprovals(w http.ResponseWriter, r *http.Request, _ store.User) {
	queue, err := s.store.PasskeyQueue(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	types, err := s.store.PasskeyTypes(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	// Approvers see only what a passkey may approve; the rest is for signing.
	queue = slices.DeleteFunc(queue, func(w store.WaitingRow) bool { return !slices.Contains(types, w.Type) })
	writeJSON(w, http.StatusOK, queue)
}

// usableOn returns the approver's passkeys a device says it has pinned. What the
// device reports is a hint for the dashboard, it decides by itself anyway.
func usableOn(report *api.Report, passkeys []store.PasskeyRow) [][]byte {
	usable := [][]byte{}
	for _, p := range passkeys {
		if slices.Contains(report.Passkeys, base64.RawURLEncoding.EncodeToString(p.CredentialID)) {
			usable = append(usable, p.CredentialID)
		}
	}
	return usable
}

// handlePasskeyChallenge prepares what the approver confirms. Only types that a
// passkey can approve get here: the answer holds the payload, which an approver may
// not read for anything else.
func (s *Server) handlePasskeyChallenge(w http.ResponseWriter, r *http.Request, u store.User) {
	task, err := s.store.WaitingTask(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusConflict, api.ErrNotWaiting)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	allowed, err := s.passkeyAllowed(r.Context(), task.Type)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !allowed {
		fail(w, http.StatusConflict, api.ErrNotForPasskey, task.Type)
		return
	}
	if task.Type == api.TaskTerminalOpen && task.CreatedBy != u.Username {
		// A shell is for the admin who opens it, and no one approves it for them.
		fail(w, http.StatusForbidden, api.ErrAdminOnly)
		return
	}
	// The device checks this as well; asking here saves a touch that would fail.
	if err := api.PasskeyLimits(task.Type, task.Payload, time.Now()); err != nil {
		failErr(w, http.StatusConflict, err)
		return
	}
	rpID, _, ok := s.relyingParty()
	if !ok {
		fail(w, http.StatusConflict, api.ErrNoPasskeyHost)
		return
	}
	report, err := s.store.DeviceReport(r.Context(), task.DeviceID)
	if err != nil {
		s.internal(w, err)
		return
	}
	passkeys, err := s.store.ListPasskeys(r.Context(), u.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	credentials := usableOn(report, passkeys)
	if len(credentials) == 0 {
		fail(w, http.StatusConflict, api.ErrPasskeyNotPinned)
		return
	}
	if report.PasskeyFreshness == "" {
		fail(w, http.StatusConflict, api.ErrPasskeyNotPinned)
		return
	}
	envelope := task.Envelope()
	if !envelopeUsable(envelope, report.PasskeyFreshness, task.Type) {
		counter, err := s.store.NextPasskeyCounter(r.Context(), task.DeviceID, report.PasskeyCounter)
		if err != nil {
			s.internal(w, err)
			return
		}
		envelope, err = json.Marshal(sign.Envelope{
			Type:      task.Type,
			Payload:   task.Payload,
			DeviceID:  task.DeviceID,
			Counter:   counter,
			NotAfter:  time.Now().Add(envelopeLifetime(task.Type)).UTC(),
			Freshness: report.PasskeyFreshness,
		})
		if err != nil {
			s.internal(w, err)
			return
		}
		if err := s.store.SetPasskeyEnvelope(r.Context(), task.ID, envelope, counter); err != nil {
			fail(w, http.StatusConflict, api.ErrNotWaiting)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"envelope":    envelope,
		"credentials": credentials,
		"rp_id":       rpID,
		"hostname":    task.Hostname,
	})
}

// envelopeUsable says whether a prepared envelope can be shown again. One with
// less than a twelfth of its lifetime left is replaced.
func envelopeUsable(raw []byte, freshness, taskType string) bool {
	var env sign.Envelope
	if len(raw) == 0 || json.Unmarshal(raw, &env) != nil {
		return false
	}
	return env.Freshness == freshness && time.Until(env.NotAfter) > envelopeLifetime(taskType)/12
}

// envelopeLifetime is how long an approval holds: a live terminal must start
// within minutes, everything else within hours.
func envelopeLifetime(taskType string) time.Duration {
	if window := api.ApprovalWindow(taskType); window > 0 {
		return window * 2 / 3
	}
	return passkeyEnvelopeLifetime
}

// handlePasskeyApproval checks the assertion for early feedback and an honest
// audit log, then passes it on. The device checks it again and alone decides.
func (s *Server) handlePasskeyApproval(w http.ResponseWriter, r *http.Request, u store.User) {
	var in sign.Assertion
	if !readJSON(w, r, &in) {
		return
	}
	task, err := s.store.WaitingTask(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && len(task.Envelope()) == 0) {
		fail(w, http.StatusConflict, api.ErrNotWaiting)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	own, err := s.store.ListPasskeys(r.Context(), u.ID)
	if err != nil {
		s.internal(w, err)
		return
	}
	pins := make([]sign.Passkey, 0, len(own))
	for _, p := range own {
		pins = append(pins, sign.Passkey{
			Name: p.Name, CredentialID: p.CredentialID, PublicKey: p.PublicKey,
			RPID: p.RPID, Origin: p.Origin, NotAfter: time.Now().Add(time.Hour),
		})
	}
	signed := sign.Signed{Envelope: task.Envelope(), Passkey: &in}
	_, used, err := sign.VerifyPasskey(signed, pins, time.Now())
	if err != nil {
		s.log.Warn("passkey approval refused", "task", task.ID, "user", u.Username, "err", err)
		fail(w, http.StatusForbidden, api.ErrPasskeyRefused)
		return
	}
	device, err := s.store.ReleasePasskeyTask(r.Context(), task.ID, signed)
	switch {
	case errors.Is(err, store.ErrStale):
		fail(w, http.StatusConflict, api.ErrPasskeyRetry)
		return
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusConflict, api.ErrNotWaiting)
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "task.passkey_approved", task.ID+" "+used.Name)
	s.wake(device)
	w.WriteHeader(http.StatusNoContent)
}
