package server

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/groups/{id}/policy", s.admin(s.handleGroupPolicy))
		mux.Handle("PUT /api/groups/{id}/policy", s.admin(s.handleSetGroupPolicy))
	})
}

// How a device stands with the policies of its groups.
const (
	policyNone        = "none"
	policyCurrent     = "current"
	policySignature   = "signature"
	policyPending     = "pending"
	policyOutdated    = "outdated"
	policyDeviation   = "deviation"
	policyConflict    = "conflict"
	policyUnprotected = "unprotected"
)

type devicePolicy struct {
	ID         string                `json:"id"`
	State      string                `json:"state"`
	Conflicts  []api.PolicyConflict  `json:"conflicts,omitempty"`
	Deviations []api.PolicyDeviation `json:"deviations,omitempty"`
	Corrected  []string              `json:"corrected,omitempty"`
	Checks     map[string]string     `json:"checks,omitempty"`
	Apps       []api.AppEntry        `json:"apps,omitempty"`
	CheckedAt  time.Time             `json:"checked_at,omitzero"`
}

func (s *Server) handleGroupPolicy(w http.ResponseWriter, r *http.Request, _ store.User) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	policy, err := s.store.GroupPolicy(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	members, err := s.store.GroupDevices(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	devices := make([]devicePolicy, 0, len(members))
	for _, member := range members {
		state, err := s.policyState(r.Context(), member)
		if err != nil {
			s.internal(w, err)
			return
		}
		devices = append(devices, state)
	}
	writeJSON(w, http.StatusOK, map[string]any{"policy": policy, "devices": devices})
}

// handleSetGroupPolicy stores a group's policy, and an empty one ends it. Only
// signatures make it real, so this queues what the members have to change.
func (s *Server) handleSetGroupPolicy(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	var raw json.RawMessage
	if !readJSON(w, r, &raw) {
		return
	}
	if err := api.Validate(api.TaskPolicySet, raw); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return
	}
	var policy api.Policy
	if err := json.Unmarshal(raw, &policy); err != nil {
		fail(w, http.StatusBadRequest, api.ErrInvalidJSON)
		return
	}
	members, err := s.store.GroupDevices(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	if policy.IsZero() {
		err = s.store.DeleteGroupPolicy(r.Context(), id)
	} else {
		var document []byte
		if document, err = json.Marshal(policy); err == nil {
			err = s.store.SetGroupPolicy(r.Context(), id, document, u.Username)
		}
	}
	if err != nil {
		// A group that does not exist fails on the foreign key.
		fail(w, http.StatusNotFound, api.ErrNoSuchGroup)
		return
	}
	s.audit(r, u.Username, "group.policy", r.PathValue("id")+" "+policy.Hash())
	if err := s.syncPolicies(r, u.Username, members); err != nil {
		s.internal(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// effectivePolicy merges what the groups of a device ask for.
func (s *Server) effectivePolicy(ctx context.Context, device string) (api.Policy, []api.PolicyConflict, error) {
	policies, err := s.store.DevicePolicies(ctx, device)
	if err != nil {
		return api.Policy{}, nil, err
	}
	merged, conflicts := api.MergePolicies(policies)
	// Each group can be fine and the sum too large, which no admin tool would
	// sign. Saying so here beats waiting for a signature forever.
	if err := api.CheckPolicy(merged); err != nil && len(conflicts) == 0 {
		conflicts = []api.PolicyConflict{{Item: err.Error(), Groups: slices.Sorted(maps.Keys(policies))}}
	}
	return merged, conflicts, nil
}

// syncPolicies queues what the given devices need after a change. A device that
// appears twice is handled once.
func (s *Server) syncPolicies(r *http.Request, actor string, devices []string) error {
	// Two requests at once would each see no task and each create one.
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	devices = slices.Clone(devices)
	slices.Sort(devices)
	for _, device := range slices.Compact(devices) {
		err := s.syncPolicy(r, actor, device)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// syncPolicy compares what a device should have with what it has and what is on
// its way. It never makes anything happen on a device by itself: each result
// waits in the signing queue, and a hacked server gets no further than that.
func (s *Server) syncPolicy(r *http.Request, actor, device string) error {
	ctx := r.Context()
	report, err := s.store.DeviceReport(ctx, device)
	if err != nil {
		return err
	}
	effective, conflicts, err := s.effectivePolicy(ctx, device)
	if err != nil {
		return err
	}
	// The device keeps what it has until the admin settles the contradiction.
	if !report.Protected || len(conflicts) > 0 {
		return s.store.DropWaitingPolicyTasks(ctx, device)
	}
	taskType, payload := api.TaskPolicySet, []byte(nil)
	if effective.IsZero() {
		taskType, payload = api.TaskPolicyClear, []byte(`{}`)
	} else if payload, err = json.Marshal(effective); err != nil {
		return err
	}
	matches := func(t *store.PolicyTask) bool {
		return t != nil && t.Type == taskType && t.Payload == string(payload)
	}

	// Where the device ends up without another signature: at what is on its
	// way, or else at what it has.
	signed, err := s.store.SignedPolicyTask(ctx, device)
	if err != nil {
		return err
	}
	settled := matches(signed)
	// A policy task the device finished says what it has, even before its next
	// report: emptying a policy right after it arrived must still end it.
	var done *store.PolicyTask
	if signed == nil {
		if done, err = s.store.DonePolicyTask(ctx, device); err != nil {
			return err
		}
		settled = matches(done)
	}
	if signed == nil && done == nil {
		current := ""
		if report.Policy != nil {
			current = report.Policy.Hash
		}
		settled = (taskType == api.TaskPolicyClear && current == "") ||
			(taskType == api.TaskPolicySet && current == effective.Hash())
	}
	if settled {
		return s.store.DropWaitingPolicyTasks(ctx, device)
	}

	waiting, err := s.store.WaitingPolicyTask(ctx, device)
	if err != nil {
		return err
	}
	if matches(waiting) {
		return nil
	}
	if err := s.store.DropWaitingPolicyTasks(ctx, device); err != nil {
		return err
	}
	if _, err := s.store.CreateSigningTask(ctx, device, taskType, payload, actor); err != nil {
		return err
	}
	// The content can be large and holds files, so the log gets the hash.
	s.audit(r, actor, "task."+taskType, device+" "+effective.Hash())
	return nil
}

func (s *Server) policyState(ctx context.Context, device string) (devicePolicy, error) {
	state := devicePolicy{ID: device}
	report, err := s.store.DeviceReport(ctx, device)
	if err != nil {
		return state, err
	}
	effective, conflicts, err := s.effectivePolicy(ctx, device)
	if err != nil {
		return state, err
	}
	open, err := s.store.OpenPolicyTask(ctx, device)
	if err != nil {
		return state, err
	}
	current := ""
	if report.Policy != nil {
		current = report.Policy.Hash
		state.Deviations = report.Policy.Deviations
		state.Corrected = report.Policy.Corrected
		state.Checks = report.Policy.Checks
		state.CheckedAt = report.Policy.CheckedAt
	}
	// Also without a policy: the first rule needs something to choose from.
	state.Apps = report.Apps
	want := ""
	if !effective.IsZero() {
		want = effective.Hash()
	}
	state.Conflicts = conflicts
	switch {
	case len(conflicts) > 0:
		state.State = policyConflict
	case !report.Protected:
		state.State = policyUnprotected
		if want == "" {
			state.State = policyNone
		}
	case open != nil && open.Status == "signing":
		state.State = policySignature
	case open != nil:
		state.State = policyPending
	case current != want:
		state.State = policyOutdated
	case len(state.Deviations) > 0:
		state.State = policyDeviation
	case want == "":
		state.State = policyNone
	default:
		state.State = policyCurrent
	}
	return state, nil
}
