package server

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/devices", s.user(s.handleDevices))
		mux.Handle("POST /api/enroll-tokens", s.admin(s.handleEnrollToken))
		mux.Handle("POST /api/devices/{id}/revoke", s.admin(s.handleRevoke))
	})
}

// --- devices and tasks ---

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request, u store.User) {
	devices, err := s.store.ListDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	if u.Role == store.RoleMember {
		assigned, err := s.store.UserDevices(r.Context(), u.ID)
		if err != nil {
			s.internal(w, err)
			return
		}
		devices = slices.DeleteFunc(devices, func(d store.Device) bool { return !slices.Contains(assigned, d.ID) })
	}
	for i := range devices {
		if u.Role == store.RoleAdmin {
			devices[i].Warnings = deviceWarnings(devices[i])
		} else {
			// They only need something to pick from when filing a request.
			devices[i].Report = nil
		}
	}
	writeJSON(w, http.StatusOK, devices)
}

func (s *Server) handleEnrollToken(w http.ResponseWriter, r *http.Request, u store.User) {
	token, err := s.store.CreateEnrollToken(r.Context(), enrollTokenTTL)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "enroll_token.created", "")
	writeJSON(w, http.StatusCreated, map[string]string{
		"token": token,
		"command": fmt.Sprintf("sudo hauswart-agent enroll --server %s --token %s --ca-fingerprint %s",
			s.publicURL, token, s.ca.Fingerprint()),
	})
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request, u store.User) {
	id := r.PathValue("id")
	err := s.store.RevokeDevice(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchDevice)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "device.revoked", id)
	w.WriteHeader(http.StatusNoContent)
}
