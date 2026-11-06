package server

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.HandleFunc("GET /ca.pem", s.handleCA)
		mux.HandleFunc("POST /agent/enroll", s.handleEnroll)
		mux.Handle("POST /agent/report", s.agent(s.handleReport))
		mux.Handle("POST /agent/inventory", s.agent(s.handleAgentInventory))
		mux.Handle("POST /agent/renew", s.agent(s.handleRenew))
		mux.Handle("GET /agent/tasks", s.agent(s.handlePoll))
		mux.Handle("POST /agent/tasks/{id}/result", s.agent(s.handleResult))
	})
}

type deviceHandler func(http.ResponseWriter, *http.Request, string)

func (s *Server) agent(next deviceHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			fail(w, http.StatusUnauthorized, api.ErrClientCertRequired)
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		id := leaf.Subject.CommonName
		ok, err := s.store.DeviceAuthorized(r.Context(), id, leaf.SerialNumber.Text(16))
		if err != nil {
			s.internal(w, err)
			return
		}
		if !ok {
			fail(w, http.StatusForbidden, api.ErrDeviceRefused)
			return
		}
		next(w, r, id)
	})
}

func (s *Server) handleCA(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(s.ca.CertPEM)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var in api.EnrollRequest
	if !readJSON(w, r, &in) {
		return
	}
	ok, err := s.store.ConsumeEnrollToken(r.Context(), in.Token)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !ok {
		fail(w, http.StatusForbidden, api.ErrEnrollTokenInvalid)
		return
	}
	cert, id, serial, err := s.ca.SignDevice([]byte(in.CSR))
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidCSR)
		return
	}
	hostname := in.Hostname
	if len(hostname) > 253 {
		hostname = hostname[:253]
	}
	if err := s.store.CreateDevice(r.Context(), id, hostname, serial); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, "agent:"+id, "device.enrolled", hostname)
	writeJSON(w, http.StatusOK, api.EnrollResponse{DeviceID: id, Cert: string(cert)})
}

// --- agent ---

// handleRenew issues a new certificate to an authenticated device. Identity
// comes from the current certificate, so a device can only renew itself.
func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request, id string) {
	var in api.RenewRequest
	if !readJSON(w, r, &in) {
		return
	}
	cert, csrID, serial, err := s.ca.SignDevice([]byte(in.CSR))
	if err != nil || csrID != id {
		// Identity is the key, so a renewal must keep it.
		fail(w, http.StatusBadRequest, api.ErrInvalidCSR)
		return
	}
	if err := s.store.SetNextSerial(r.Context(), id, serial); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, "agent:"+id, "device.renewed", serial)
	writeJSON(w, http.StatusOK, api.RenewResponse{Cert: string(cert)})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request, id string) {
	var rep api.Report
	if !readJSON(w, r, &rep) {
		return
	}
	rep.Clean()
	s.recordInsight(r, id, &rep)
	before, err := s.store.DeviceReport(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := s.store.SaveReport(r.Context(), id, rep); err != nil {
		s.internal(w, err)
		return
	}
	// A device that just became protected can receive its policy from now on.
	if rep.Protected && !before.Protected {
		if err := s.syncPolicies(r, "agent:"+id, []string{id}); err != nil {
			s.internal(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePoll is a long poll: it returns a task as soon as one exists, or 204
// when the wait runs out.
func (s *Server) handlePoll(w http.ResponseWriter, r *http.Request, id string) {
	wait := maxPollWait
	if v, err := strconv.Atoi(r.URL.Query().Get("wait")); err == nil && v >= 0 && time.Duration(v)*time.Second < wait {
		wait = time.Duration(v) * time.Second
	}
	if err := s.store.TouchDevice(r.Context(), id); err != nil {
		s.internal(w, err)
		return
	}
	wake := s.waiter(id)
	timeout := time.After(wait)
	for {
		task, err := s.store.ClaimTask(r.Context(), id)
		if err != nil {
			s.internal(w, err)
			return
		}
		if task != nil {
			writeJSON(w, http.StatusOK, task)
			return
		}
		select {
		case <-wake:
		case <-timeout:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (s *Server) waiter(id string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.waiters[id]
	if !ok {
		ch = make(chan struct{}, 1)
		s.waiters[id] = ch
	}
	return ch
}

func (s *Server) wake(id string) {
	select {
	case s.waiter(id) <- struct{}{}:
	default:
	}
}

func (s *Server) handleResult(w http.ResponseWriter, r *http.Request, id string) {
	var res api.TaskResult
	if !readJSON(w, r, &res) {
		return
	}
	err := s.store.FinishTask(r.Context(), id, r.PathValue("id"), res)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchTask)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
