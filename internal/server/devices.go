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
		mux.Handle("POST /api/devices/{id}/suspend", s.admin(s.handleSuspend(true)))
		mux.Handle("POST /api/devices/{id}/resume", s.admin(s.handleSuspend(false)))
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
	assets := map[string]api.Asset{}
	tpms := map[string]store.TPMRecord{}
	if u.Role == store.RoleAdmin {
		if assets, err = s.store.Assets(r.Context()); err != nil {
			s.internal(w, err)
			return
		}
		if tpms, err = s.store.TPMs(r.Context()); err != nil {
			s.internal(w, err)
			return
		}
	}
	for i := range devices {
		if u.Role == store.RoleAdmin {
			devices[i].Warnings = deviceWarnings(devices[i], assets[devices[i].ID], tpmOf(tpms, devices[i].ID))
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

// handleSuspend holds a device back or lets it go on. Its tasks wait meanwhile.
func (s *Server) handleSuspend(suspend bool) userHandler {
	return func(w http.ResponseWriter, r *http.Request, u store.User) {
		id := r.PathValue("id")
		err := s.store.SuspendDevice(r.Context(), id, suspend)
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusNotFound, api.ErrNoSuchDevice)
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		action := "device.resumed"
		if suspend {
			action = "device.suspended"
		}
		s.audit(r, u.Username, action, id)
		s.wake(id)
		w.WriteHeader(http.StatusNoContent)
	}
}

// refuseSuspended answers for a suspended device and says whether it did.
func (s *Server) refuseSuspended(w http.ResponseWriter, r *http.Request, device string, status int) bool {
	suspended, err := s.store.DeviceSuspended(r.Context(), device)
	if err != nil {
		s.internal(w, err)
		return true
	}
	if suspended {
		fail(w, status, api.ErrDeviceSuspended)
	}
	return suspended
}
