package api

import (
	"errors"
	"slices"
	"testing"
)

func TestCheckApprovalRules(t *testing.T) {
	for name, tc := range map[string]struct {
		rules ApprovalRules
		code  string
	}{
		"empty":         {ApprovalRules{}, ""},
		"valid":         {ApprovalRules{Kinds: map[string]string{"software": "auto", "sudo": "admin"}, AutoFlatpaks: []string{"org.kde.kate"}}, ""},
		"unknown kind":  {ApprovalRules{Kinds: map[string]string{"root": "auto"}}, ErrUnknownRequestKind},
		"unknown mode":  {ApprovalRules{Kinds: map[string]string{"software": "maybe"}}, ErrInvalidApprovalMode},
		"auto sudo":     {ApprovalRules{Kinds: map[string]string{"sudo": "auto"}}, ErrInvalidApprovalMode},
		"bad package":   {ApprovalRules{AutoPackages: []string{"--evil"}}, ErrInvalidPackage},
		"too many apps": {ApprovalRules{AutoPackages: slices.Repeat([]string{"vim"}, maxPolicyPackages+1)}, ErrApprovalsTooLarge},
	} {
		err := CheckApprovalRules(tc.rules)
		var apiErr *Error
		switch {
		case tc.code == "" && err != nil:
			t.Errorf("%s: %v", name, err)
		case tc.code != "" && (!errors.As(err, &apiErr) || apiErr.Code != tc.code):
			t.Errorf("%s: got %v, want %s", name, err, tc.code)
		}
	}
}

func TestMergeApprovalRulesStrictestWins(t *testing.T) {
	defaults := ApprovalRules{Kinds: map[string]string{"screen": "auto"}, AutoPackages: []string{"vim"}}
	office := ApprovalRules{Kinds: map[string]string{"software": "auto"}, AutoFlatpaks: []string{"org.kde.kate"}}
	strict := ApprovalRules{Kinds: map[string]string{"software": "admin", "flatpak": "blocked"}}

	merged := MergeApprovalRules(defaults, []ApprovalRules{office, strict})
	want := map[string]string{"software": "admin", "flatpak": "blocked", "sudo": "approver", "screen": "auto"}
	for kind, mode := range want {
		if merged.Kinds[kind] != mode {
			t.Errorf("%s: got %s, want %s", kind, merged.Kinds[kind], mode)
		}
	}
	if !slices.Equal(merged.AutoPackages, []string{"vim"}) || !slices.Equal(merged.AutoFlatpaks, []string{"org.kde.kate"}) {
		t.Errorf("lists: %+v", merged)
	}
}

// A group without its own mode counts with the default, so a loose group does
// not loosen a strict default either.
func TestMergeApprovalRulesGroupWithoutModeUsesDefault(t *testing.T) {
	defaults := ApprovalRules{Kinds: map[string]string{"software": "admin"}}
	loose := ApprovalRules{Kinds: map[string]string{"software": "auto"}}
	merged := MergeApprovalRules(defaults, []ApprovalRules{loose, {}})
	if merged.Kinds["software"] != "admin" {
		t.Fatalf("got %s", merged.Kinds["software"])
	}
	if merged := MergeApprovalRules(ApprovalRules{}, nil); merged.Kinds["sudo"] != "approver" {
		t.Fatalf("no rules at all: %+v", merged)
	}
}

func TestDecide(t *testing.T) {
	rules := ApprovalRules{
		Kinds:        map[string]string{"software": "approver", "flatpak": "auto", "sudo": "admin"},
		AutoPackages: []string{"vim", "htop"},
	}
	policy := Policy{ForbiddenPackages: []string{"steam"}, ForbiddenFlatpaks: []string{"com.valvesoftware.Steam"}}
	for _, tc := range []struct{ kind, detail, want string }{
		{"software", "vim", ApprovalAuto},
		{"software", "vim htop", ApprovalAuto},
		{"software", "vim gimp", ApprovalApprover},
		{"software", "steam", ApprovalApprover},
		{"flatpak", "org.kde.kate", ApprovalAuto},
		{"flatpak", "com.valvesoftware.Steam", ApprovalApprover},
		{"sudo", "30", ApprovalAdmin},
		{"screen", "30", ApprovalApprover},
	} {
		if got := rules.Decide(tc.kind, tc.detail, policy); got != tc.want {
			t.Errorf("%s %s: got %s, want %s", tc.kind, tc.detail, got, tc.want)
		}
	}
	// An admin-only kind stays with the admin, even for listed apps.
	strict := ApprovalRules{Kinds: map[string]string{"software": "admin"}, AutoPackages: []string{"vim"}}
	if got := strict.Decide("software", "vim", Policy{}); got != ApprovalAdmin {
		t.Errorf("admin kind: got %s", got)
	}
}
