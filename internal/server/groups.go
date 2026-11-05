package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/groups", s.admin(s.handleGroups))
		mux.Handle("POST /api/groups", s.admin(s.handleCreateGroup))
		mux.Handle("DELETE /api/groups/{id}", s.admin(s.handleDeleteGroup))
		mux.Handle("PUT /api/groups/{id}/devices", s.admin(s.handleSetGroupDevices))
		mux.Handle("POST /api/groups/{id}/tasks", s.admin(s.handleGroupTask))
	})
}

// groupTaskTypes are the only tasks that go to a whole group. Anything that
// grants rights or trust has to be decided device by device.
var groupTaskTypes = map[string]bool{
	api.TaskPkgInstall:     true,
	api.TaskPkgRemove:      true,
	api.TaskPkgUpgrade:     true,
	api.TaskFlatpakInstall: true,
}

func (s *Server) handleGroups(w http.ResponseWriter, r *http.Request, _ store.User) {
	groups, err := s.store.ListGroups(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, groups)
}

func (s *Server) handleCreateGroup(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Name string `json:"name"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !api.ValidGroupName(in.Name) {
		fail(w, http.StatusBadRequest, api.ErrInvalidGroupName)
		return
	}
	id, err := s.store.CreateGroup(r.Context(), in.Name)
	if errors.Is(err, store.ErrGroupExists) {
		fail(w, http.StatusConflict, api.ErrGroupExists)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "group.created", in.Name)
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func groupID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusNotFound, api.ErrNoSuchGroup)
		return 0, false
	}
	return id, true
}

func (s *Server) handleDeleteGroup(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	err := s.store.DeleteGroup(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchGroup)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "group.deleted", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetGroupDevices(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	var in struct {
		Devices []string `json:"devices"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	err := s.store.SetGroupDevices(r.Context(), id, in.Devices)
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchGroup)
		return
	}
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrNoSuchDevice)
		return
	}
	s.audit(r, u.Username, "group.devices", r.PathValue("id"))
	w.WriteHeader(http.StatusNoContent)
}

// handleGroupTask creates one task per device. An offline device gets its task
// when it returns, and a protected one waits for a signature like any other.
func (s *Server) handleGroupTask(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	var in struct {
		Type    string          `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if !groupTaskTypes[in.Type] {
		fail(w, http.StatusBadRequest, api.ErrNotForGroups, in.Type)
		return
	}
	if len(in.Payload) == 0 {
		in.Payload = json.RawMessage(`{}`)
	}
	if err := api.Validate(in.Type, in.Payload); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	devices, err := s.store.GroupDevices(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	created := make([]string, 0, len(devices))
	for _, device := range devices {
		task, err := s.enqueue(r, device, in.Type, in.Payload, u.Username)
		if err != nil {
			s.internal(w, err)
			return
		}
		created = append(created, task)
	}
	writeJSON(w, http.StatusCreated, map[string][]string{"tasks": created})
}
