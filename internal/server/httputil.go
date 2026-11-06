package server

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Two-Play/hauswart/internal/api"
)

// --- helpers ---

func (s *Server) audit(r *http.Request, actor, action, detail string) {
	if err := s.store.Audit(r.Context(), actor, action, detail); err != nil {
		s.log.Error("audit write failed", "err", err, "action", action)
	}
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.log.Error("request failed", "err", err)
	fail(w, http.StatusInternalServerError, api.ErrInternal)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidJSON)
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code string, value ...string) {
	e := api.Fail(code, value...)
	writeJSON(w, status, map[string]string{"error": e.Error(), "code": e.Code, "value": e.Value})
}

// failErr reports a validation error with its code.
func failErr(w http.ResponseWriter, status int, err error) {
	var e *api.Error
	if errors.As(err, &e) {
		fail(w, status, e.Code, e.Value)
		return
	}
	fail(w, status, api.ErrInvalidPayload, err.Error())
}
