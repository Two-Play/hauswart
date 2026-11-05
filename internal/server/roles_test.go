package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/philippe/hauswart/internal/store"
)

// assign gives a member a device, as an admin would.
func (e *env) assign(name string, devices ...string) {
	e.t.Helper()
	u, err := e.store.UserByName(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.store.SetUserDevices(context.Background(), u.ID, devices); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) addUser(name, linuxUser, role string) {
	e.t.Helper()
	hash, err := HashPassword(testPassword)
	if err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.store.CreateUser(context.Background(), name, linuxUser, hash, role); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) request(c *http.Client, device, kind, detail string) string {
	e.t.Helper()
	code, data := e.do(c, "POST", "/api/requests", map[string]string{"device_id": device, "kind": kind, "detail": detail})
	if code != http.StatusCreated {
		e.t.Fatalf("request: %d %s", code, data)
	}
	var out struct{ ID string }
	json.Unmarshal(data, &out)
	return out.ID
}

func TestMemberSeesOnlyAssignedDevices(t *testing.T) {
	e := setup(t)
	mine, _ := e.enroll()
	other, _ := e.enroll()
	e.assign("anna", mine)
	anna := e.login("anna")

	_, data := e.do(anna, "GET", "/api/devices", nil)
	if !strings.Contains(string(data), mine) || strings.Contains(string(data), other) {
		t.Fatalf("got %s", data)
	}
	if code, _ := e.do(anna, "POST", "/api/requests", map[string]string{"device_id": other, "kind": "software", "detail": "vim"}); code != http.StatusForbidden {
		t.Fatalf("request for a foreign device: %d", code)
	}
}

func TestMemberWithoutAssignmentSeesNothing(t *testing.T) {
	e := setup(t)
	e.enroll()
	_, data := e.do(e.login("anna"), "GET", "/api/devices", nil)
	if strings.TrimSpace(string(data)) != "[]" {
		t.Fatalf("got %s", data)
	}
}

func TestApprovalRechecksAssignment(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	e.assign("anna", id)
	request := e.request(e.login("anna"), id, "software", "vim")
	e.assign("anna")
	if code, _ := e.do(e.login("admin"), "POST", "/api/requests/"+request+"/approve", nil); code != http.StatusConflict {
		t.Fatalf("approved for a device taken away: %d", code)
	}
}

func TestParentMayApproveButNotStartAnything(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.assign("anna", id)
	e.addUser("mama", "mama", store.RoleParent)
	parent := e.login("mama")

	if code, _ := e.do(parent, "GET", "/api/devices", nil); code != http.StatusOK {
		t.Fatalf("devices: %d", code)
	}
	request := e.request(e.login("anna"), id, "software", "vim")
	_, data := e.do(parent, "GET", "/api/requests", nil)
	if !strings.Contains(string(data), request) {
		t.Fatalf("parent does not see the request: %s", data)
	}
	if code, data := e.do(parent, "POST", "/api/requests/"+request+"/approve", nil); code != http.StatusNoContent {
		t.Fatalf("approve: %d %s", code, data)
	}
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusOK {
		t.Fatalf("task missing: %d", code)
	}

	routes := []struct{ method, path string }{
		{"POST", "/api/enroll-tokens"},
		{"POST", "/api/devices/" + id + "/tasks"},
		{"POST", "/api/devices/" + id + "/start-password"},
		{"POST", "/api/devices/" + id + "/signed-tasks"},
		{"POST", "/api/devices/" + id + "/revoke"},
		{"GET", "/api/tasks"},
		{"GET", "/api/signing"},
		{"POST", "/api/tasks/x/signature"},
		{"GET", "/api/users"},
		{"POST", "/api/users"},
		{"PUT", "/api/users/1/role"},
		{"PUT", "/api/users/1/devices"},
		{"GET", "/api/groups"},
		{"GET", "/api/audit"},
	}
	for _, r := range routes {
		if code, _ := e.do(parent, r.method, r.path, map[string]any{}); code != http.StatusForbidden {
			t.Errorf("%s %s: %d", r.method, r.path, code)
		}
	}
}

// Without this, a parent could give themselves root on an unprotected device.
func TestParentCannotApproveOwnRequest(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	e.addUser("mama", "mama", store.RoleParent)
	e.addUser("mama2", "mama", store.RoleParent)
	request := e.request(e.login("mama"), id, "sudo", "30")
	if code, _ := e.do(e.login("mama"), "POST", "/api/requests/"+request+"/approve", nil); code != http.StatusForbidden {
		t.Fatalf("own request: %d", code)
	}
	// A second account on the same Linux user is the same person to sudo.
	if code, _ := e.do(e.login("mama2"), "POST", "/api/requests/"+request+"/approve", nil); code != http.StatusForbidden {
		t.Fatalf("same Linux user: %d", code)
	}
	if code, _ := e.do(e.login("admin"), "POST", "/api/requests/"+request+"/approve", nil); code != http.StatusNoContent {
		t.Fatalf("admin: %d", code)
	}
}

func TestAdminManagesRolesAndAssignments(t *testing.T) {
	e := setup(t)
	id, _ := e.enroll()
	admin := e.login("admin")
	anna, err := e.store.UserByName(context.Background(), "anna")
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/users/%d", anna.ID)

	if code, data := e.do(admin, "PUT", path+"/devices", map[string][]string{"devices": {id}}); code != http.StatusNoContent {
		t.Fatalf("assign: %d %s", code, data)
	}
	if _, data := e.do(admin, "GET", path+"/devices", nil); !strings.Contains(string(data), id) {
		t.Fatalf("got %s", data)
	}
	if code, _ := e.do(admin, "PUT", path+"/devices", map[string][]string{"devices": {"nope"}}); code != http.StatusBadRequest {
		t.Fatalf("unknown device: %d", code)
	}
	if _, data := e.do(admin, "GET", path+"/devices", nil); !strings.Contains(string(data), id) {
		t.Fatalf("failed change was not undone: %s", data)
	}
	if code, _ := e.do(admin, "PUT", path+"/role", map[string]string{"role": store.RoleParent}); code != http.StatusNoContent {
		t.Fatalf("role: %d", code)
	}
	if code, _ := e.do(admin, "PUT", path+"/role", map[string]string{"role": "owner"}); code != http.StatusBadRequest {
		t.Fatalf("unknown role: %d", code)
	}
	if code, _ := e.do(admin, "POST", "/api/users", map[string]string{
		"username": "papa", "password": testPassword, "role": store.RoleParent,
	}); code != http.StatusCreated {
		t.Fatalf("create parent: %d", code)
	}
}

func TestLastAdminCannotBeDemoted(t *testing.T) {
	e := setup(t)
	admin := e.login("admin")
	u, err := e.store.UserByName(context.Background(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/users/%d/role", u.ID)
	if code, _ := e.do(admin, "PUT", path, map[string]string{"role": store.RoleMember}); code != http.StatusConflict {
		t.Fatalf("got %d", code)
	}
	if code, _ := e.do(admin, "PUT", path, map[string]string{"role": store.RoleAdmin}); code != http.StatusNoContent {
		t.Fatalf("keeping the role: %d", code)
	}
}
