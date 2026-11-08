package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/GehirnInc/crypt/sha512_crypt"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("POST /api/devices/{id}/tasks", s.admin(s.handleCreateTask))
		mux.Handle("POST /api/devices/{id}/start-password", s.admin(s.handleStartPassword))
		mux.Handle("POST /api/devices/{id}/signed-tasks", s.admin(s.handleCreateSignedTask))
		mux.Handle("GET /api/signing", s.admin(s.handleSigningQueue))
		mux.Handle("POST /api/tasks/{id}/signature", s.admin(s.handleSignature))
		mux.Handle("POST /api/tasks/{id}/reject", s.approver(s.handleReject))
		mux.Handle("GET /api/tasks", s.admin(s.handleTasks))
		mux.Handle("GET /api/attention", s.admin(s.handleAttention))
	})
}

func (s *Server) handleCreateTask(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage(`{}`)
	}
	if in.Type == api.TaskUserPassword || in.Type == api.TaskKeysSet {
		// Only their own routes may create these: the start-password route
		// keeps the hash out of the audit log, and keys need a signature.
		fail(w, http.StatusBadRequest, api.ErrUseStartPassword)
		return
	}
	if err := api.Validate(in.Type, in.Payload); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	id, err := s.enqueue(r, r.PathValue("id"), in.Type, in.Payload, u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

// handleStartPassword creates a random password, sends only its hash to the
// device and returns the password exactly once. It is stored nowhere.
func (s *Server) handleStartPassword(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		User string `json:"user"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	deviceID := r.PathValue("id")
	protected, err := s.store.DeviceProtected(r.Context(), deviceID)
	if err != nil {
		s.internal(w, err)
		return
	}
	if protected {
		// A server-made hash would defeat the point of the signature.
		fail(w, http.StatusConflict, api.ErrUseAdminTool)
		return
	}
	password := store.RandomToken()[:startPasswordLen]
	hash, err := sha512_crypt.New().Generate([]byte(password), nil)
	if err != nil {
		s.internal(w, err)
		return
	}
	payload, err := json.Marshal(api.PasswordPayload{User: in.User, Hash: hash})
	if err != nil {
		s.internal(w, err)
		return
	}
	if err := api.Validate(api.TaskUserPassword, payload); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	id, err := s.store.CreateTask(r.Context(), deviceID, api.TaskUserPassword, payload, u.Username)
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "task."+api.TaskUserPassword, deviceID+" "+in.User)
	s.wake(deviceID)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "password": password})
}

// enqueue hands a task to its device, or queues it for a signature if the
// device demands one. The server cannot skip that: the device would refuse.
func (s *Server) enqueue(r *http.Request, deviceID, taskType string, payload []byte, actor string) (string, error) {
	return s.enqueueFor(r, deviceID, taskType, payload, actor, "")
}

// enqueueFor is enqueue for the task of a request, which it links before the
// device can see the task.
func (s *Server) enqueueFor(r *http.Request, deviceID, taskType string, payload []byte, actor, requestID string) (string, error) {
	protected, err := s.store.DeviceProtected(r.Context(), deviceID)
	if err != nil {
		return "", err
	}
	signing := protected && api.NeedsSignature(taskType)
	// Task and link go in together, so that a device polling in between never
	// gets a task without its request.
	id, err := s.store.CreateLinkedTask(r.Context(), deviceID, taskType, payload, actor, signing, requestID)
	if err != nil {
		return "", err
	}
	s.audit(r, actor, "task."+taskType, deviceID+" "+string(payload))
	s.wake(deviceID)
	return id, nil
}

func (s *Server) handleSigningQueue(w http.ResponseWriter, r *http.Request, _ store.User) {
	tasks, err := s.store.SigningQueue(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (s *Server) handleSignature(w http.ResponseWriter, r *http.Request, u store.User) {
	var in sign.Signed
	if !readJSON(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	device, err := s.store.AttachSignature(r.Context(), id, in)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusConflict, api.ErrNotWaiting)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "task.signed", id)
	s.wake(device)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReject(w http.ResponseWriter, r *http.Request, u store.User) {
	id := r.PathValue("id")
	if u.Role != store.RoleAdmin {
		// Approvers only ever see the types they can approve.
		task, err := s.store.WaitingTask(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			fail(w, http.StatusConflict, api.ErrNotWaiting)
			return
		}
		if err != nil {
			s.internal(w, err)
			return
		}
		if !api.PasskeyEligible(task.Type) {
			fail(w, http.StatusForbidden, api.ErrAdminOnly)
			return
		}
	}
	err := s.store.RejectTask(r.Context(), id, u.Username)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusConflict, api.ErrNotWaiting)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "task.rejected", id)
	w.WriteHeader(http.StatusNoContent)
}

// handleCreateSignedTask takes tasks the admin tool made and signed by itself,
// such as start passwords. Only the type goes into the audit log, because the
// envelope may hold a password hash.
func (s *Server) handleCreateSignedTask(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Type   string      `json:"type"`
		Signed sign.Signed `json:"signed"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	device := r.PathValue("id")
	id, err := s.store.CreateSignedTask(r.Context(), device, in.Type, in.Signed, u.Username)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrNoSuchDevice)
		return
	}
	s.audit(r, u.Username, "task."+in.Type, device)
	s.wake(device)
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
}

func (s *Server) handleTasks(w http.ResponseWriter, r *http.Request, _ store.User) {
	tasks, err := s.store.ListTasks(r.Context(), listLimit)
	if err != nil {
		s.internal(w, err)
		return
	}
	for i := range tasks {
		if tasks[i].Type == api.TaskUserPassword {
			tasks[i].Payload = json.RawMessage(`{}`)
		}
		if tasks[i].Type == api.TaskLogsFetch {
			tasks[i].Data = nil // large, and fetched one at a time
		}
	}
	writeJSON(w, http.StatusOK, tasks)
}

// handleAttention counts what an admin should look at: tasks that failed in the
// last day, and devices that differ from their policy.
func (s *Server) handleAttention(w http.ResponseWriter, r *http.Request, _ store.User) {
	failed, err := s.store.FailedTasksSince(r.Context(), time.Now().Add(-24*time.Hour))
	if err != nil {
		s.internal(w, err)
		return
	}
	devices, err := s.store.ListDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	tpms, err := s.store.TPMs(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	deviating, booting := 0, 0
	for _, d := range devices {
		if !d.Revoked && d.Report != nil && d.Report.Policy != nil && len(d.Report.Policy.Deviations) > 0 {
			deviating++
		}
		if len(bootWarnings(d, tpmOf(tpms, d.ID), time.Now())) > 0 {
			booting++
		}
	}
	writeJSON(w, http.StatusOK, map[string]int{"failed_tasks": failed, "deviating_devices": deviating, "boot_alarms": booting})
}
