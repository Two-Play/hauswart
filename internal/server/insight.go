package server

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

const (
	defaultHistoryHours = 24
	maxHistoryHours     = int(store.SampleRetention / time.Hour)
	// About 300 points in either range, enough for a chart and far less than
	// a value per minute.
	shortHistoryStep = 5 * time.Minute
	longHistoryStep  = 30 * time.Minute
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/devices/{id}/history", s.admin(s.handleHistory))
		mux.Handle("GET /api/tasks/{id}/data", s.admin(s.handleTaskData))
	})
}

// recordInsight adds what the server knows better than the device, and keeps
// the values for the history. A failure here must not cost the report.
func (s *Server) recordInsight(r *http.Request, id string, rep *api.Report) {
	expires := r.TLS.VerifiedChains[0][0].NotAfter
	rep.CertExpires = &expires
	if err := s.store.AddSample(r.Context(), id, time.Now(), *rep); err != nil {
		s.log.Error("saving resource history failed", "device", id, "err", err)
	}
}

func deviceWarnings(d store.Device, asset api.Asset) []api.Warning {
	if d.Revoked || d.Report == nil {
		return nil
	}
	warnings := d.Report.Warnings(time.Now())
	if warning := asset.Warning(time.Now()); warning != nil {
		warnings = append(warnings, *warning)
	}
	return warnings
}

func (s *Server) handleHistory(w http.ResponseWriter, r *http.Request, _ store.User) {
	hours := defaultHistoryHours
	if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v > 0 && v <= maxHistoryHours {
		hours = v
	}
	step := shortHistoryStep
	if hours > defaultHistoryHours {
		step = longHistoryStep
	}
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	samples, err := s.store.History(r.Context(), r.PathValue("id"), since, step)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, samples)
}

// handleTaskData returns one task with its result. Lists leave out results that
// are large, and logs vanish from the database after a while.
func (s *Server) handleTaskData(w http.ResponseWriter, r *http.Request, _ store.User) {
	task, err := s.store.GetTask(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, api.ErrNoSuchTask)
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if task.Type == api.TaskUserPassword {
		task.Payload = []byte(`{}`)
	}
	writeJSON(w, http.StatusOK, task)
}
