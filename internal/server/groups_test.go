package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/philippe/hauswart/internal/api"
)

func newGroup(t *testing.T, e *env, admin *http.Client, devices ...string) string {
	t.Helper()
	code, data := e.do(admin, "POST", "/api/groups", map[string]string{"name": "laptops"})
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, data)
	}
	var out struct{ ID int64 }
	json.Unmarshal(data, &out)
	path := fmt.Sprintf("/api/groups/%d", out.ID)
	if code, data := e.do(admin, "PUT", path+"/devices", map[string][]string{"devices": devices}); code != http.StatusNoContent {
		t.Fatalf("members: %d %s", code, data)
	}
	return path
}

func TestGroupTaskReachesEveryMember(t *testing.T) {
	e := setup(t)
	first, firstAgent := e.enroll()
	second, secondAgent := e.enroll()
	_, outsider := e.enroll()
	admin := e.login("admin")
	path := newGroup(t, e, admin, first, second)

	in := map[string]any{"type": api.TaskPkgInstall, "payload": api.PackagesPayload{Packages: []string{"vim"}}}
	if code, data := e.do(admin, "POST", path+"/tasks", in); code != http.StatusCreated {
		t.Fatalf("task: %d %s", code, data)
	}
	for _, agent := range []*http.Client{firstAgent, secondAgent} {
		if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusOK {
			t.Fatalf("member got nothing: %d", code)
		}
	}
	if code, _ := e.do(outsider, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("outsider got a task: %d", code)
	}
}

func TestGroupTaskWaitsForSignatureOnProtectedDevice(t *testing.T) {
	e := setup(t)
	protected, protectedAgent := e.enroll()
	open, openAgent := e.enroll()
	protect(t, e, protectedAgent)
	admin := e.login("admin")
	path := newGroup(t, e, admin, protected, open)

	in := map[string]any{"type": api.TaskPkgInstall, "payload": api.PackagesPayload{Packages: []string{"vim"}}}
	e.do(admin, "POST", path+"/tasks", in)
	if code, _ := e.do(protectedAgent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("protected device got an unsigned task: %d", code)
	}
	if code, _ := e.do(openAgent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusOK {
		t.Fatalf("open device: %d", code)
	}
}

func TestRightsAndTrustNeverGoToAGroup(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	for _, taskType := range []string{api.TaskSudoGrant, api.TaskCAInstall, api.TaskUserPassword, api.TaskFilePut, api.TaskKeysSet, api.TaskUserCreate} {
		code, data := e.do(admin, "POST", path+"/tasks", map[string]any{"type": taskType, "payload": map[string]any{}})
		if code != http.StatusBadRequest || !strings.Contains(string(data), api.ErrNotForGroups) {
			t.Errorf("%s: %d %s", taskType, code, data)
		}
	}
}

func TestGroupsAreAdminOnly(t *testing.T) {
	e := setup(t)
	member := e.login("anna")
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/groups"},
		{"POST", "/api/groups"},
		{"DELETE", "/api/groups/1"},
		{"PUT", "/api/groups/1/devices"},
		{"POST", "/api/groups/1/tasks"},
	} {
		if code, _ := e.do(member, route.method, route.path, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s %s: %d", route.method, route.path, code)
		}
	}
}
