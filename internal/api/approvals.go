package api

import (
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Who decides a request. The modes are ordered from loose to strict.
const (
	// ApprovalAuto approves without anyone looking.
	ApprovalAuto = "auto"
	// ApprovalApprover leaves it to an admin or an approver, as before rules.
	ApprovalApprover = "approver"
	// ApprovalAdmin leaves it to an admin.
	ApprovalAdmin = "admin"
	// ApprovalBlocked refuses the request when it is filed.
	ApprovalBlocked = "blocked"
)

// Kinds of requests, as people file them.
const (
	RequestSoftware = "software"
	RequestFlatpak  = "flatpak"
	RequestSudo     = "sudo"
)

// DecidedAutomatically is who decided a request that a rule approved.
const DecidedAutomatically = "auto"

var approvalRank = map[string]int{ApprovalAuto: 0, ApprovalApprover: 1, ApprovalAdmin: 2, ApprovalBlocked: 3}

// ApprovalRules say who decides the requests for the devices of a group. They
// stay on the server: a device never sees them, and they decide nothing a
// signature would otherwise decide.
type ApprovalRules struct {
	// Kinds maps a request kind to a mode. A missing kind uses the default rules,
	// and without those an approver decides.
	Kinds map[string]string `json:"kinds,omitempty"`
	// AutoPackages and AutoFlatpaks are approved at once, even when an approver
	// decides the rest of their kind.
	AutoPackages []string `json:"auto_packages,omitempty"`
	AutoFlatpaks []string `json:"auto_flatpaks,omitempty"`
}

// IsZero says whether the rules change nothing.
func (r ApprovalRules) IsZero() bool {
	return len(r.Kinds) == 0 && len(r.AutoPackages) == 0 && len(r.AutoFlatpaks) == 0
}

// CheckApprovalRules refuses rules that make no sense or go too far.
func CheckApprovalRules(r ApprovalRules) error {
	for kind, mode := range r.Kinds {
		if !slices.Contains(requestKinds, kind) {
			return Fail(ErrUnknownRequestKind, kind)
		}
		if _, ok := approvalRank[mode]; !ok {
			return Fail(ErrInvalidApprovalMode, mode)
		}
		// Root without anyone looking is more than a rule should give.
		if kind == RequestSudo && mode == ApprovalAuto {
			return Fail(ErrInvalidApprovalMode, kind+" "+mode)
		}
	}
	for _, list := range [][]string{r.AutoPackages, r.AutoFlatpaks} {
		if len(list) > maxPolicyPackages {
			return Fail(ErrApprovalsTooLarge, strconv.Itoa(maxPolicyPackages))
		}
		for _, name := range list {
			if !ValidPackage(name) {
				return Fail(ErrInvalidPackage, name)
			}
		}
	}
	return nil
}

// MergeApprovalRules builds the rules of a device from the defaults and the
// rules of its groups. Each group's mode for a kind is its own or the default,
// and the strictest one wins: a group that wants an admin to look must not be
// overruled by another group. The lists of automatic apps add up.
func MergeApprovalRules(defaults ApprovalRules, groups []ApprovalRules) ApprovalRules {
	out := ApprovalRules{Kinds: map[string]string{}}
	for _, kind := range requestKinds {
		base := defaults.Kinds[kind]
		if base == "" {
			base = ApprovalApprover
		}
		mode := base
		if len(groups) > 0 {
			mode = ""
			for _, group := range groups {
				next := group.Kinds[kind]
				if next == "" {
					next = base
				}
				if mode == "" || approvalRank[next] > approvalRank[mode] {
					mode = next
				}
			}
		}
		out.Kinds[kind] = mode
	}
	packages, flatpaks := map[string]bool{}, map[string]bool{}
	for _, rules := range append([]ApprovalRules{defaults}, groups...) {
		for _, name := range rules.AutoPackages {
			packages[name] = true
		}
		for _, name := range rules.AutoFlatpaks {
			flatpaks[name] = true
		}
	}
	out.AutoPackages = slices.Sorted(maps.Keys(packages))
	out.AutoFlatpaks = slices.Sorted(maps.Keys(flatpaks))
	return out
}

// Mode is who decides a request of this kind, without looking at its detail.
func (r ApprovalRules) Mode(kind string) string {
	if mode := r.Kinds[kind]; mode != "" {
		return mode
	}
	return ApprovalApprover
}

// Decide says who decides a request. The lists of automatic apps only lift a
// kind that an approver decides, and only when every package of the request is
// on them. Nothing forbidden by the policy of the device is ever approved
// automatically, so that a rule cannot undo a policy.
func (r ApprovalRules) Decide(kind, detail string, policy Policy) string {
	mode := r.Mode(kind)
	var auto, forbidden []string
	switch kind {
	case RequestSoftware:
		auto, forbidden = r.AutoPackages, policy.ForbiddenPackages
	case RequestFlatpak:
		auto, forbidden = r.AutoFlatpaks, policy.ForbiddenFlatpaks
	default:
		return mode
	}
	names := strings.Fields(detail)
	for _, name := range names {
		if slices.Contains(forbidden, name) {
			if mode == ApprovalAuto {
				return ApprovalApprover
			}
			return mode
		}
	}
	if mode != ApprovalApprover || len(names) == 0 {
		return mode
	}
	for _, name := range names {
		if !slices.Contains(auto, name) {
			return mode
		}
	}
	return ApprovalAuto
}
