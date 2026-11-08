package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

func init() {
	addRoutes(func(s *Server, mux *http.ServeMux) {
		mux.Handle("GET /api/approval-rules", s.admin(s.handleDefaultApprovals))
		mux.Handle("PUT /api/approval-rules", s.admin(s.handleSetDefaultApprovals))
		mux.Handle("GET /api/groups/{id}/approval-rules", s.admin(s.handleGroupApprovals))
		mux.Handle("PUT /api/groups/{id}/approval-rules", s.admin(s.handleSetGroupApprovals))
	})
}

func (s *Server) handleDefaultApprovals(w http.ResponseWriter, r *http.Request, _ store.User) {
	rules, err := s.store.DefaultApprovals(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleSetDefaultApprovals(w http.ResponseWriter, r *http.Request, u store.User) {
	rules, ok := readApprovalRules(w, r)
	if !ok {
		return
	}
	if err := s.store.SetDefaultApprovals(r.Context(), rules, u.Username); err != nil {
		s.internal(w, err)
		return
	}
	s.audit(r, u.Username, "approvals.default", approvalSummary(rules))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGroupApprovals(w http.ResponseWriter, r *http.Request, _ store.User) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	rules, err := s.store.GroupApprovals(r.Context(), id)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, rules)
}

func (s *Server) handleSetGroupApprovals(w http.ResponseWriter, r *http.Request, u store.User) {
	id, ok := groupID(w, r)
	if !ok {
		return
	}
	rules, ok := readApprovalRules(w, r)
	if !ok {
		return
	}
	err := s.store.SetGroupApprovals(r.Context(), id, rules, u.Username)
	if err != nil {
		// A group that does not exist fails on the foreign key, or is not found.
		if !errors.Is(err, store.ErrNotFound) {
			s.log.Warn("approval rules not stored", "group", id, "err", err)
		}
		fail(w, http.StatusNotFound, api.ErrNoSuchGroup)
		return
	}
	s.audit(r, u.Username, "group.approvals", r.PathValue("id")+" "+approvalSummary(rules))
	w.WriteHeader(http.StatusNoContent)
}

func readApprovalRules(w http.ResponseWriter, r *http.Request) (api.ApprovalRules, bool) {
	var rules api.ApprovalRules
	if !readJSON(w, r, &rules) {
		return rules, false
	}
	if err := api.CheckApprovalRules(rules); err != nil {
		failErr(w, http.StatusBadRequest, err)
		return rules, false
	}
	return rules, true
}

// approvalSummary is what the audit log keeps of a change.
func approvalSummary(rules api.ApprovalRules) string {
	raw, _ := json.Marshal(rules)
	return string(raw)
}

// deviceApprovals merges the rules that decide requests for a device.
func (s *Server) deviceApprovals(ctx context.Context, device string) (api.ApprovalRules, error) {
	defaults, err := s.store.DefaultApprovals(ctx)
	if err != nil {
		return api.ApprovalRules{}, err
	}
	groups, err := s.store.DeviceApprovals(ctx, device)
	if err != nil {
		return api.ApprovalRules{}, err
	}
	return api.MergeApprovalRules(defaults, groups), nil
}

// requestMode says who decides a request for a device. What the policy of the
// device forbids is never approved automatically.
func (s *Server) requestMode(ctx context.Context, device, kind, detail string) (string, error) {
	rules, err := s.deviceApprovals(ctx, device)
	if err != nil {
		return "", err
	}
	policy, _, err := s.effectivePolicy(ctx, device)
	if err != nil {
		return "", err
	}
	return rules.Decide(kind, detail, policy), nil
}
