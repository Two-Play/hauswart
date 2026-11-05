package server

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/philippe/hauswart/internal/api"
	"github.com/philippe/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/users", s.admin(s.handleUsers))
		mux.Handle("POST /api/users", s.admin(s.handleCreateUser))
		mux.Handle("DELETE /api/users/{id}", s.admin(s.handleDeleteUser))
		mux.Handle("GET /api/audit", s.admin(s.handleAudit))
	})
}

// --- users and audit ---

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request, _ store.User) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, users)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request, u store.User) {
	var in struct {
		Username  string `json:"username"`
		LinuxUser string `json:"linux_user"`
		Password  string `json:"password"`
		Role      string `json:"role"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.LinuxUser == "" {
		in.LinuxUser = in.Username
	}
	if !api.ValidUser(in.Username) || !api.ValidUser(in.LinuxUser) {
		fail(w, http.StatusBadRequest, api.ErrInvalidUsername)
		return
	}
	if in.Role != "admin" && in.Role != "member" {
		fail(w, http.StatusBadRequest, api.ErrInvalidRole)
		return
	}
	if len(in.Password) < minPasswordLen {
		fail(w, http.StatusBadRequest, api.ErrPasswordTooShort, strconv.Itoa(minPasswordLen))
		return
	}
	hash, err := HashPassword(in.Password)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrPasswordTooLong)
		return
	}
	if _, err := s.store.CreateUser(r.Context(), in.Username, in.LinuxUser, hash, in.Role); err != nil {
		fail(w, http.StatusConflict, api.ErrUsernameTaken)
		return
	}
	s.audit(r, u.Username, "user.created", in.Username+" ("+in.Role+")")
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request, u store.User) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidUserID)
		return
	}
	switch err := s.store.DeleteUser(r.Context(), id); {
	case errors.Is(err, store.ErrNotFound):
		fail(w, http.StatusNotFound, api.ErrNoSuchUser)
	case errors.Is(err, store.ErrLastAdmin):
		fail(w, http.StatusConflict, api.ErrLastAdmin)
	case err != nil:
		s.internal(w, err)
	default:
		s.audit(r, u.Username, "user.deleted", r.PathValue("id"))
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request, _ store.User) {
	entries, err := s.store.ListAudit(r.Context(), listLimit)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, entries)
}
