package server

import (
	"bytes"
	"context"
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

// pinnedDevice is a protected device that says a passkey is pinned on it.
type pinnedDevice struct {
	ID       string `json:"id"`
	Hostname string `json:"hostname"`
}

// passkeyEntry is a passkey with where it can approve something.
type passkeyEntry struct {
	store.PasskeyRow
	// PinnedOn are the protected devices whose last report names the passkey.
	// Only a pin through a signed keys.set gets it there.
	PinnedOn []pinnedDevice `json:"pinned_on"`
}

func (s *Server) handlePasskeys(w http.ResponseWriter, r *http.Request, u store.User) {
	passkeys, err := s.store.ListPasskeys(r.Context(), ownerFilter(u))
	if err != nil {
		s.internal(w, err)
		return
	}
	devices, err := s.store.ListDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	entries := make([]passkeyEntry, 0, len(passkeys))
	for _, p := range passkeys {
		entry := passkeyEntry{PasskeyRow: p, PinnedOn: []pinnedDevice{}}
		id := base64.RawURLEncoding.EncodeToString(p.CredentialID)
		for _, d := range devices {
			if !d.Revoked && d.Report != nil && d.Report.Protected && slices.Contains(d.Report.Passkeys, id) {
				entry.PinnedOn = append(entry.PinnedOn, pinnedDevice{ID: d.ID, Hostname: d.Hostname})
			}
		}
		entries = append(entries, entry)
	}
	writeJSON(w, http.StatusOK, entries)
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

// refusal is why a passkey cannot approve a task, as the answer says it.
type refusal struct {
	status int
	err    error
}

// prepared is a waiting task with the envelope a passkey confirms, and the
// approver's passkeys that its device has pinned.
type prepared struct {
	task        store.WaitingRow
	envelope    []byte
	credentials [][]byte
}

// preparePasskey checks that a passkey of the approver can approve a task, and
// makes or reuses its envelope. A single approval and a batch go through here
// alike, so a batch gets nothing past the checks of one.
func (s *Server) preparePasskey(ctx context.Context, u store.User, id string) (prepared, *refusal) {
	task, err := s.store.WaitingTask(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return prepared{}, &refusal{http.StatusConflict, api.Fail(api.ErrNotWaiting)}
	}
	if err != nil {
		return prepared{}, &refusal{http.StatusInternalServerError, err}
	}
	allowed, err := s.passkeyAllowed(ctx, task.Type)
	if err != nil {
		return prepared{}, &refusal{http.StatusInternalServerError, err}
	}
	if !allowed {
		return prepared{}, &refusal{http.StatusConflict, api.Fail(api.ErrNotForPasskey, task.Type)}
	}
	if task.Type == api.TaskTerminalOpen && task.CreatedBy != u.Username {
		// A shell is for the admin who opens it, and no one approves it for them.
		return prepared{}, &refusal{http.StatusForbidden, api.Fail(api.ErrAdminOnly)}
	}
	// The device checks this as well; asking here saves a touch that would fail.
	if err := api.PasskeyLimits(task.Type, task.Payload, time.Now()); err != nil {
		return prepared{}, &refusal{http.StatusConflict, err}
	}
	report, err := s.store.DeviceReport(ctx, task.DeviceID)
	if err != nil {
		return prepared{}, &refusal{http.StatusInternalServerError, err}
	}
	passkeys, err := s.store.ListPasskeys(ctx, u.ID)
	if err != nil {
		return prepared{}, &refusal{http.StatusInternalServerError, err}
	}
	credentials := usableOn(report, passkeys)
	if len(credentials) == 0 || report.PasskeyFreshness == "" {
		return prepared{}, &refusal{http.StatusConflict, api.Fail(api.ErrPasskeyNotPinned)}
	}
	envelope := task.Envelope()
	if !envelopeUsable(envelope, report.PasskeyFreshness, task.Type) {
		counter, err := s.store.NextPasskeyCounter(ctx, task.DeviceID, report.PasskeyCounter)
		if err != nil {
			return prepared{}, &refusal{http.StatusInternalServerError, err}
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
			return prepared{}, &refusal{http.StatusInternalServerError, err}
		}
		if err := s.store.SetPasskeyEnvelope(ctx, task.ID, envelope, counter); err != nil {
			return prepared{}, &refusal{http.StatusConflict, api.Fail(api.ErrNotWaiting)}
		}
	}
	return prepared{task: task, envelope: envelope, credentials: credentials}, nil
}

// refuse answers with a refusal.
func (s *Server) refuse(w http.ResponseWriter, r *refusal) {
	if r.status == http.StatusInternalServerError {
		s.internal(w, r.err)
		return
	}
	failErr(w, r.status, r.err)
}

// handlePasskeyChallenge prepares what the approver confirms. Only types that a
// passkey can approve get here: the answer holds the payload, which an approver may
// not read for anything else.
func (s *Server) handlePasskeyChallenge(w http.ResponseWriter, r *http.Request, u store.User) {
	rpID, _, ok := s.relyingParty()
	if !ok {
		fail(w, http.StatusConflict, api.ErrNoPasskeyHost)
		return
	}
	p, refused := s.preparePasskey(r.Context(), u, r.PathValue("id"))
	if refused != nil {
		s.refuse(w, refused)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"envelope":    p.envelope,
		"credentials": p.credentials,
		"rp_id":       rpID,
		"hostname":    p.task.Hostname,
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

// approverPins are the approver's passkeys as a device would pin them, for
// checking an assertion before it goes on.
func (s *Server) approverPins(ctx context.Context, u store.User) ([]sign.Passkey, error) {
	own, err := s.store.ListPasskeys(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	pins := make([]sign.Passkey, 0, len(own))
	for _, p := range own {
		pins = append(pins, sign.Passkey{
			Name: p.Name, CredentialID: p.CredentialID, PublicKey: p.PublicKey,
			RPID: p.RPID, Origin: p.Origin, NotAfter: time.Now().Add(time.Hour),
		})
	}
	return pins, nil
}

// releasePasskey checks an approval and passes the task on to its device.
func (s *Server) releasePasskey(ctx context.Context, u store.User, task store.WaitingRow, signed sign.Signed, pins []sign.Passkey) (sign.Passkey, *refusal) {
	_, used, err := sign.VerifyPasskey(signed, pins, time.Now())
	if err != nil {
		s.log.Warn("passkey approval refused", "task", task.ID, "user", u.Username, "err", err)
		return sign.Passkey{}, &refusal{http.StatusForbidden, api.Fail(api.ErrPasskeyRefused)}
	}
	_, err = s.store.ReleasePasskeyTask(ctx, task.ID, signed)
	switch {
	case errors.Is(err, store.ErrStale):
		return sign.Passkey{}, &refusal{http.StatusConflict, api.Fail(api.ErrPasskeyRetry)}
	case errors.Is(err, store.ErrNotFound):
		return sign.Passkey{}, &refusal{http.StatusConflict, api.Fail(api.ErrNotWaiting)}
	case err != nil:
		return sign.Passkey{}, &refusal{http.StatusInternalServerError, err}
	}
	return used, nil
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
	pins, err := s.approverPins(r.Context(), u)
	if err != nil {
		s.internal(w, err)
		return
	}
	signed := sign.Signed{Envelope: task.Envelope(), Passkey: &in}
	used, refused := s.releasePasskey(r.Context(), u, task, signed, pins)
	if refused != nil {
		s.refuse(w, refused)
		return
	}
	device := task.DeviceID
	s.audit(r, u.Username, "task.passkey_approved", task.ID+" "+used.Name)
	s.wake(device)
	w.WriteHeader(http.StatusNoContent)
}
