package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/requests", s.user(s.handleListRequests))
		mux.Handle("POST /api/requests", s.user(s.handleCreateRequest))
		mux.Handle("POST /api/requests/{id}/approve", s.approver(s.handleApprove))
		mux.Handle("POST /api/requests/{id}/deny", s.approver(s.handleDeny))
	})
}

// --- requests ---

func (s *Server) handleListRequests(w http.ResponseWriter, r *http.Request, u store.User) {
	var filter int64
	if u.Role == store.RoleMember {
		filter = u.ID
	}
	requests, err := s.store.ListRequests(r.Context(), filter)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, requests)
}

func (s *Server) handleCreateRequest(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		DeviceID string `json:"device_id"`
		Kind     string `json:"kind"`
		Detail   string `json:"detail"`
		Reason   string `json:"reason"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	// Validate now, so a bad request fails for the person filing it rather
	// than for the admin approving it.
	if _, _, err := requestTask(in.Kind, in.Detail, u.LinuxUser); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	allowed, err := s.store.DeviceAllowed(r.Context(), u.ID, in.DeviceID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !allowed {
		fail(w, http.StatusForbidden, api.ErrDeviceNotAssigned)
		return
	}
	id, err := s.store.CreateRequest(r.Context(), u.ID, in.DeviceID, in.Kind, in.Detail, in.Reason)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrNoSuchDevice)
		return
	}
	s.audit(r, u.Username, "request.created", in.Kind+" "+in.Detail)
	s.notifyRequest(r.Context(), id)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// requestTask converts a request into the task it causes once approved. A
// sudo grant's expiry counts from this call, so from approval when approving.
func requestTask(kind, detail, linuxUser string) (string, []byte, error) {
	var taskType string
	var payload any
	switch kind {
	case "software", "flatpak":
		taskType = api.TaskPkgInstall
		if kind == "flatpak" {
			taskType = api.TaskFlatpakInstall
		}
		payload = api.PackagesPayload{Packages: strings.Fields(detail)}
	case "sudo":
		minutes, err := strconv.Atoi(strings.TrimSpace(detail))
		if err != nil || minutes < 1 || minutes > maxSudoMinutes {
			return "", nil, api.Fail(api.ErrInvalidDuration, strconv.Itoa(maxSudoMinutes))
		}
		taskType = api.TaskSudoGrant
		payload = api.SudoGrantPayload{User: linuxUser, ExpiresAt: time.Now().Add(time.Duration(minutes) * time.Minute)}
	default:
		return "", nil, api.Fail(api.ErrUnknownRequestKind, kind)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", nil, err
	}
	if err := api.Validate(taskType, raw); err != nil {
		return "", nil, err
	}
	return taskType, raw, nil
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request, u store.User) {
	req, err := s.store.GetRequest(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchRequest)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	// A sudo grant goes to the Linux user, and two accounts can share one, so the
	// account alone is not enough. Otherwise a parent could give themselves root
	// on an unprotected device, which is more than approving.
	if u.Role != store.RoleAdmin && (req.UserID == u.ID || req.LinuxUser == u.LinuxUser) {
		fail(w, http.StatusForbidden, api.ErrOwnRequest)
		return
	}
	// The request may be older than the decision to take the device away.
	allowed, err := s.store.DeviceAllowed(r.Context(), req.UserID, req.DeviceID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !allowed {
		fail(w, http.StatusConflict, api.ErrDeviceNotAssigned)
		return
	}
	taskType, payload, err := requestTask(req.Kind, req.Detail, req.LinuxUser)
	if err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	won, err := s.store.DecideRequest(r.Context(), req.ID, "approved", u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !won {
		fail(w, http.StatusConflict, api.ErrRequestDecided)
		return
	}
	if _, err := s.enqueue(r, req.DeviceID, taskType, payload, u.Username); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDeny(w http.ResponseWriter, r *http.Request, u store.User) {
	id := r.PathValue("id")
	won, err := s.store.DecideRequest(r.Context(), id, "denied", u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !won {
		fail(w, http.StatusConflict, api.ErrRequestDecided)
		return
	}
	s.audit(r, u.Username, "request.denied", id)
	w.WriteHeader(http.StatusNoContent)
}
