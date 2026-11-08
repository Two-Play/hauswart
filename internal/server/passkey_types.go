package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/passkey-types", s.approver(s.handlePasskeyTypes))
		mux.Handle("PUT /api/passkey-types", s.admin(s.handleSetPasskeyTypes))
	})
}

// passkeyTypesView is the setting with how far the protected devices are.
type passkeyTypesView struct {
	Types []string `json:"types"`
	// Chosen says that an admin set the list; before, devices keep theirs.
	Chosen bool `json:"chosen"`
	// Capable is everything a passkey could ever approve; the rest always
	// needs a signature.
	Capable []string `json:"capable"`
	// Devices counts the protected devices by what they have.
	Devices struct {
		Applied int `json:"applied"`
		Waiting int `json:"waiting"`
		Total   int `json:"total"`
	} `json:"devices"`
}

func (s *Server) handlePasskeyTypes(w http.ResponseWriter, r *http.Request, _ store.User) {
	types, chosen, err := s.store.ChosenPasskeyTypes(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	view := passkeyTypesView{Types: types, Chosen: chosen, Capable: api.PasskeyCapable}
	devices, err := s.store.ListDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	for _, d := range devices {
		if d.Revoked || d.Report == nil || !d.Report.Protected {
			continue
		}
		view.Devices.Total++
		if slices.Equal(api.SortedTypes(d.Report.PasskeyTypes), types) {
			view.Devices.Applied++
			continue
		}
		if waiting, err := s.store.LatestTask(r.Context(), d.ID, api.TaskPasskeyTypes, "signing"); err == nil && waiting != nil {
			view.Devices.Waiting++
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// handleSetPasskeyTypes saves the choice and queues it for every protected
// device, where it waits for a signature. Until then the devices keep what
// they have.
func (s *Server) handleSetPasskeyTypes(w http.ResponseWriter, r *http.Request, u store.User) {
	var in api.PasskeyTypesPayload
	if !readJSON(w, r, &in) {
		return
	}
	if in.Types == nil {
		in.Types = []string{}
	}
	raw, _ := json.Marshal(in)
	if err := api.Validate(api.TaskPasskeyTypes, raw); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	if err := s.store.SetPasskeyTypes(r.Context(), in.Types, u.Username); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "passkey_types.set", strings.Join(api.SortedTypes(in.Types), ","))
	devices, err := s.store.ListDevices(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	for _, d := range devices {
		if d.Revoked {
			continue
		}
		if err := s.syncPasskeyTypes(r, u.Username, d.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.internal(w, err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// syncPasskeyTypes compares what a protected device lets a passkey approve
// with the admins' choice, and queues the choice for a signature if they
// differ. Like syncPolicy, it counts what is signed and on its way first.
func (s *Server) syncPasskeyTypes(r *http.Request, actor, device string) error {
	s.passkeyTypesMu.Lock()
	defer s.passkeyTypesMu.Unlock()
	ctx := r.Context()
	report, err := s.store.DeviceReport(ctx, device)
	if err != nil {
		return err
	}
	if report == nil || !report.Protected {
		return s.store.DropWaitingTasks(ctx, device, api.TaskPasskeyTypes)
	}
	types, chosen, err := s.store.ChosenPasskeyTypes(ctx)
	if err != nil {
		return err
	}
	if !chosen {
		return nil
	}
	payload, err := json.Marshal(api.PasskeyTypesPayload{Types: types})
	if err != nil {
		return err
	}
	settled, err := s.passkeyTypesSettled(ctx, device, report, types, string(payload))
	if err != nil || settled {
		if err == nil {
			err = s.store.DropWaitingTasks(ctx, device, api.TaskPasskeyTypes)
		}
		return err
	}
	waiting, err := s.store.LatestTask(ctx, device, api.TaskPasskeyTypes, "signing")
	if err != nil {
		return err
	}
	if waiting != nil && waiting.Payload == string(payload) {
		return nil
	}
	if err := s.store.DropWaitingTasks(ctx, device, api.TaskPasskeyTypes); err != nil {
		return err
	}
	if _, err := s.store.CreateSigningTask(ctx, device, api.TaskPasskeyTypes, payload, actor); err != nil {
		return err
	}
	s.audit(r, actor, "task."+api.TaskPasskeyTypes, device+" "+strings.Join(types, ","))
	return nil
}

// passkeyTypesSettled says whether the device ends up with the choice without
// another signature: through a task on its way, one it just finished, or
// because it has the list already.
func (s *Server) passkeyTypesSettled(ctx context.Context, device string, report *api.Report, types []string, payload string) (bool, error) {
	signed, err := s.store.LatestTask(ctx, device, api.TaskPasskeyTypes, "pending", "running")
	if err != nil {
		return false, err
	}
	if signed != nil {
		return signed.Payload == payload, nil
	}
	if slices.Equal(api.SortedTypes(report.PasskeyTypes), types) {
		return true, nil
	}
	done, err := s.store.LatestTask(ctx, device, api.TaskPasskeyTypes, "done")
	if err != nil {
		return false, err
	}
	// The report may be older than the task the device just finished.
	return done != nil && done.Payload == payload && report.PasskeyTypes == nil, nil
}

// passkeyAllowed says whether the admins let a passkey approve a type. The
// device checks its own list; asking here spares a touch that would fail.
func (s *Server) passkeyAllowed(ctx context.Context, taskType string) (bool, error) {
	if !api.PasskeyEligible(taskType) {
		return false, nil
	}
	types, err := s.store.PasskeyTypes(ctx)
	if err != nil {
		return false, err
	}
	return slices.Contains(types, taskType), nil
}
