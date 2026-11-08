package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

func putApprovals(t *testing.T, e *env, admin *http.Client, path string, rules api.ApprovalRules) {
	t.Helper()
	if code, data := e.do(admin, "PUT", path, rules); code != http.StatusNoContent {
		t.Fatalf("put %s: %d %s", path, code, data)
	}
}

// file files a request and returns its answer.
func file(t *testing.T, e *env, c *http.Client, device, kind, detail string) (int, map[string]string) {
	t.Helper()
	code, data := e.do(c, "POST", "/api/requests", map[string]string{"device_id": device, "kind": kind, "detail": detail})
	var out map[string]string
	json.Unmarshal(data, &out)
	return code, out
}

func TestWithoutRulesAnApproverDecides(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.assign("anna", id)
	code, out := file(t, e, e.login("anna"), id, "software", "vim")
	if code != http.StatusCreated || out["status"] != "open" {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("task without approval: %d", code)
	}
}

func TestListedPackageIsApprovedAtOnce(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.assign("anna", id)
	admin := e.login("admin")
	group := newGroup(t, e, admin, id)
	putApprovals(t, e, admin, group+"/approval-rules", api.ApprovalRules{AutoPackages: []string{"vim"}})
	anna := e.login("anna")

	code, out := file(t, e, anna, id, "software", "vim")
	if code != http.StatusCreated || out["status"] != "approved" {
		t.Fatalf("%d %v", code, out)
	}
	code, data := e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusOK || !strings.Contains(string(data), "vim") {
		t.Fatalf("no task: %d %s", code, data)
	}
	_, data = e.do(admin, "GET", "/api/requests", nil)
	if !strings.Contains(string(data), `"decided_by":"auto"`) {
		t.Fatalf("got %s", data)
	}

	// A package that is not on the list still waits.
	if _, out := file(t, e, anna, id, "software", "vim gimp"); out["status"] != "open" {
		t.Fatalf("got %v", out)
	}
}

func TestForbiddenPackageIsNeverApprovedAutomatically(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	e.assign("anna", id)
	admin := e.login("admin")
	group := newGroup(t, e, admin, id)
	putPolicy(t, e, admin, group, api.Policy{ForbiddenPackages: []string{"steam"}})
	putApprovals(t, e, admin, group+"/approval-rules", api.ApprovalRules{
		Kinds: map[string]string{"software": "auto"}, AutoPackages: []string{"steam"}})
	if _, out := file(t, e, e.login("anna"), id, "software", "steam"); out["status"] != "open" {
		t.Fatalf("got %v", out)
	}
}

func TestBlockedKindIsRefused(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	e.assign("anna", id)
	admin := e.login("admin")
	putApprovals(t, e, admin, "/api/approval-rules", api.ApprovalRules{Kinds: map[string]string{"sudo": "blocked"}})
	code, data := e.do(e.login("anna"), "POST", "/api/requests", map[string]string{"device_id": id, "kind": "sudo", "detail": "30"})
	if code != http.StatusForbidden || !strings.Contains(string(data), api.ErrRequestBlocked) {
		t.Fatalf("%d %s", code, data)
	}
}

func TestAdminOnlyKind(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	e.assign("anna", id)
	e.addUser("mia", "mia", store.RoleApprover)
	admin := e.login("admin")
	group := newGroup(t, e, admin, id)
	putApprovals(t, e, admin, group+"/approval-rules", api.ApprovalRules{Kinds: map[string]string{"software": "admin"}})

	request := e.request(e.login("anna"), id, "software", "vim")
	approver := e.login("mia")
	_, data := e.do(approver, "GET", "/api/requests", nil)
	if !strings.Contains(string(data), `"mode":"admin"`) {
		t.Fatalf("list does not say who decides: %s", data)
	}
	if code, data := e.do(approver, "POST", "/api/requests/"+request+"/approve", nil); code != http.StatusForbidden ||
		!strings.Contains(string(data), api.ErrAdminDecides) {
		t.Fatalf("approver approved: %d %s", code, data)
	}
	if code, data := e.do(admin, "POST", "/api/requests/"+request+"/approve", nil); code != http.StatusNoContent {
		t.Fatalf("admin: %d %s", code, data)
	}
}

// The rule takes the approver's part, never the signature's.
func TestAutomaticApprovalStillWaitsForSignature(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	protect(t, e, agent)
	e.assign("anna", id)
	admin := e.login("admin")
	putApprovals(t, e, admin, "/api/approval-rules", api.ApprovalRules{AutoFlatpaks: []string{"org.kde.kate"}})

	if _, out := file(t, e, e.login("anna"), id, "flatpak", "org.kde.kate"); out["status"] != "approved" {
		t.Fatalf("got %v", out)
	}
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("delivered without a signature: %d", code)
	}
	if queue := queueOf(t, e, admin); len(queue) != 1 || queue[0].Type != api.TaskFlatpakInstall {
		t.Fatalf("got %+v", queue)
	}
}

func TestApprovalRulesAreChecked(t *testing.T) {
	e := setup(t)
	admin := e.login("admin")
	group := newGroup(t, e, admin)
	for _, rules := range []api.ApprovalRules{
		{Kinds: map[string]string{"sudo": "auto"}},
		{Kinds: map[string]string{"software": "sometimes"}},
		{AutoPackages: []string{"--evil"}},
	} {
		if code, _ := e.do(admin, "PUT", group+"/approval-rules", rules); code != http.StatusBadRequest {
			t.Errorf("%+v: %d", rules, code)
		}
	}
	if code, _ := e.do(admin, "PUT", "/api/groups/999/approval-rules", api.ApprovalRules{AutoPackages: []string{"vim"}}); code != http.StatusNotFound {
		t.Errorf("unknown group: %d", code)
	}
	e.addUser("mia", "mia", store.RoleApprover)
	if code, _ := e.do(e.login("mia"), "PUT", "/api/approval-rules", api.ApprovalRules{}); code != http.StatusForbidden {
		t.Errorf("approver changed rules: %d", code)
	}

	putApprovals(t, e, admin, group+"/approval-rules", api.ApprovalRules{AutoPackages: []string{"vim"}})
	_, data := e.do(admin, "GET", group+"/approval-rules", nil)
	if !strings.Contains(string(data), "vim") {
		t.Fatalf("got %s", data)
	}
	putApprovals(t, e, admin, group+"/approval-rules", api.ApprovalRules{})
	_, data = e.do(admin, "GET", group+"/approval-rules", nil)
	if strings.Contains(string(data), "vim") {
		t.Fatalf("not removed: %s", data)
	}
}
