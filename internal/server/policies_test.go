package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/sign"
)

type policyView struct {
	Policy  *api.Policy
	Devices []devicePolicy
}

func groupPolicy(t *testing.T, e *env, admin *http.Client, path string) policyView {
	t.Helper()
	code, data := e.do(admin, "GET", path+"/policy", nil)
	if code != http.StatusOK {
		t.Fatalf("get: %d %s", code, data)
	}
	var view policyView
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func putPolicy(t *testing.T, e *env, admin *http.Client, path string, p api.Policy) {
	t.Helper()
	if code, data := e.do(admin, "PUT", path+"/policy", p); code != http.StatusNoContent {
		t.Fatalf("put: %d %s", code, data)
	}
}

func queueOf(t *testing.T, e *env, admin *http.Client) []struct {
	ID       string          `json:"id"`
	DeviceID string          `json:"device_id"`
	Type     string          `json:"type"`
	Payload  json.RawMessage `json:"payload"`
} {
	t.Helper()
	code, data := e.do(admin, "GET", "/api/signing", nil)
	if code != http.StatusOK {
		t.Fatalf("queue: %d %s", code, data)
	}
	var queue []struct {
		ID       string          `json:"id"`
		DeviceID string          `json:"device_id"`
		Type     string          `json:"type"`
		Payload  json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &queue); err != nil {
		t.Fatal(err)
	}
	return queue
}

func report(t *testing.T, e *env, agent *http.Client, r api.Report) {
	t.Helper()
	if code, data := e.do(agent, "POST", "/agent/report", r); code != http.StatusNoContent {
		t.Fatalf("report: %d %s", code, data)
	}
}

func protectedDevice(t *testing.T, e *env) (string, *http.Client) {
	t.Helper()
	id, agent := e.enroll()
	protect(t, e, agent)
	return id, agent
}

func TestPolicyWaitsForASignatureOnEveryMember(t *testing.T) {
	e := setup(t)
	first, firstAgent := protectedDevice(t, e)
	second, _ := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, first, second)

	policy := api.Policy{RequiredPackages: []string{"vim"}}
	putPolicy(t, e, admin, path, policy)

	queue := queueOf(t, e, admin)
	if len(queue) != 2 || queue[0].Type != api.TaskPolicySet {
		t.Fatalf("got %+v", queue)
	}
	// Nothing reaches a device before the signature.
	if code, _ := e.do(firstAgent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusNoContent {
		t.Fatalf("the device got a task: %d", code)
	}
	view := groupPolicy(t, e, admin, path)
	if view.Policy == nil || len(view.Devices) != 2 || view.Devices[0].State != policySignature {
		t.Fatalf("got %+v", view)
	}

	// Saving the same again adds nothing, and a new version replaces the old.
	putPolicy(t, e, admin, path, policy)
	if got := len(queueOf(t, e, admin)); got != 2 {
		t.Fatalf("queue grew to %d", got)
	}
	putPolicy(t, e, admin, path, api.Policy{RequiredPackages: []string{"nano"}})
	queue = queueOf(t, e, admin)
	if len(queue) != 2 || !strings.Contains(string(queue[0].Payload), "nano") {
		t.Fatalf("got %+v", queue)
	}
}

func TestDeviceThatHasThePolicyGetsNoTask(t *testing.T) {
	e := setup(t)
	id, agent := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	policy := api.Policy{RequiredPackages: []string{"vim"}}
	report(t, e, agent, api.Report{Protected: true, Policy: &api.PolicyStatus{Hash: policy.Hash()}})

	putPolicy(t, e, admin, path, policy)
	if queue := queueOf(t, e, admin); len(queue) != 0 {
		t.Fatalf("got %+v", queue)
	}
	if got := groupPolicy(t, e, admin, path).Devices[0].State; got != policyCurrent {
		t.Fatalf("got %s", got)
	}

	report(t, e, agent, api.Report{Protected: true, Policy: &api.PolicyStatus{
		Hash:       policy.Hash(),
		Deviations: []api.PolicyDeviation{{Kind: "package", Item: "vim"}},
		Checks:     map[string]string{"screen_lock": "on"},
	}})
	state := groupPolicy(t, e, admin, path).Devices[0]
	if state.State != policyDeviation || state.Checks["screen_lock"] != "on" {
		t.Fatalf("got %+v", state)
	}
}

func TestGroupsMergeIntoOnePolicyPerDevice(t *testing.T) {
	e := setup(t)
	id, _ := protectedDevice(t, e)
	admin := e.login("admin")
	everyone := newGroup(t, e, admin, id)
	putPolicy(t, e, admin, everyone, api.Policy{RequiredPackages: []string{"vim"}})

	code, data := e.do(admin, "POST", "/api/groups", map[string]string{"name": "kids"})
	if code != http.StatusCreated {
		t.Fatalf("%d %s", code, data)
	}
	var out struct{ ID int64 }
	json.Unmarshal(data, &out)
	kids := fmt.Sprintf("/api/groups/%d", out.ID)
	putPolicy(t, e, admin, kids, api.Policy{ForbiddenPackages: []string{"steam"}})
	if code, data := e.do(admin, "PUT", kids+"/devices", map[string][]string{"devices": {id}}); code != http.StatusNoContent {
		t.Fatalf("%d %s", code, data)
	}

	queue := queueOf(t, e, admin)
	if len(queue) != 1 {
		t.Fatalf("got %+v", queue)
	}
	var merged api.Policy
	if err := json.Unmarshal(queue[0].Payload, &merged); err != nil {
		t.Fatal(err)
	}
	if merged.RequiredPackages[0] != "vim" || merged.ForbiddenPackages[0] != "steam" {
		t.Fatalf("got %+v", merged)
	}

	// A contradiction stops everything for that device and says where it is.
	putPolicy(t, e, admin, kids, api.Policy{ForbiddenPackages: []string{"vim"}})
	if queue := queueOf(t, e, admin); len(queue) != 0 {
		t.Fatalf("got %+v", queue)
	}
	state := groupPolicy(t, e, admin, kids).Devices[0]
	if state.State != policyConflict || state.Conflicts[0].Item != "package vim" || len(state.Conflicts[0].Groups) != 2 {
		t.Fatalf("got %+v", state)
	}
}

func TestLeavingTheGroupEndsThePolicy(t *testing.T) {
	e := setup(t)
	id, agent := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	policy := api.Policy{RequiredPackages: []string{"vim"}}
	report(t, e, agent, api.Report{Protected: true, Policy: &api.PolicyStatus{Hash: policy.Hash()}})
	putPolicy(t, e, admin, path, policy)

	if code, data := e.do(admin, "PUT", path+"/devices", map[string][]string{"devices": {}}); code != http.StatusNoContent {
		t.Fatalf("%d %s", code, data)
	}
	queue := queueOf(t, e, admin)
	if len(queue) != 1 || queue[0].Type != api.TaskPolicyClear {
		t.Fatalf("got %+v", queue)
	}
}

func TestDeletingTheGroupEndsThePolicy(t *testing.T) {
	e := setup(t)
	id, agent := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	policy := api.Policy{RequiredPackages: []string{"vim"}}
	report(t, e, agent, api.Report{Protected: true, Policy: &api.PolicyStatus{Hash: policy.Hash()}})
	putPolicy(t, e, admin, path, policy)

	if code, data := e.do(admin, "DELETE", path, nil); code != http.StatusNoContent {
		t.Fatalf("%d %s", code, data)
	}
	if queue := queueOf(t, e, admin); len(queue) != 1 || queue[0].Type != api.TaskPolicyClear {
		t.Fatalf("got %+v", queue)
	}
}

func TestEmptyPolicyEndsItAndADeviceWithoutOneNeedsNothing(t *testing.T) {
	e := setup(t)
	id, _ := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	putPolicy(t, e, admin, path, api.Policy{RequiredPackages: []string{"vim"}})
	putPolicy(t, e, admin, path, api.Policy{})
	// Never signed, never there: the waiting task goes and nothing replaces it.
	if queue := queueOf(t, e, admin); len(queue) != 0 {
		t.Fatalf("got %+v", queue)
	}
	if view := groupPolicy(t, e, admin, path); view.Policy != nil || view.Devices[0].State != policyNone {
		t.Fatalf("got %+v", view)
	}
}

func TestUnprotectedDeviceWaitsUntilItIsProtected(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	putPolicy(t, e, admin, path, api.Policy{RequiredPackages: []string{"vim"}})
	if queue := queueOf(t, e, admin); len(queue) != 0 {
		t.Fatalf("got %+v", queue)
	}
	if got := groupPolicy(t, e, admin, path).Devices[0].State; got != policyUnprotected {
		t.Fatalf("got %s", got)
	}
	report(t, e, agent, api.Report{Protected: true})
	if queue := queueOf(t, e, admin); len(queue) != 1 {
		t.Fatalf("got %+v", queue)
	}
	// Later reports leave a task that someone rejected alone.
	report(t, e, agent, api.Report{Protected: true})
	if queue := queueOf(t, e, admin); len(queue) != 1 {
		t.Fatalf("got %+v", queue)
	}
}

func TestPolicyRoutes(t *testing.T) {
	e := setup(t)
	id, _ := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)

	if code, data := e.do(admin, "PUT", path+"/policy", api.Policy{ForbiddenPackages: []string{"sudo"}}); code != http.StatusBadRequest || !strings.Contains(string(data), api.ErrPackageProtected) {
		t.Fatalf("%d %s", code, data)
	}
	if code, data := e.do(admin, "PUT", path+"/policy", map[string]any{"hidden": 1}); code != http.StatusBadRequest {
		t.Fatalf("%d %s", code, data)
	}
	if code, _ := e.do(admin, "PUT", "/api/groups/999/policy", api.Policy{RequiredPackages: []string{"vim"}}); code != http.StatusNotFound {
		t.Fatalf("got %d", code)
	}
	member := e.login("anna")
	if code, _ := e.do(member, "GET", path+"/policy", nil); code != http.StatusForbidden {
		t.Fatalf("got %d", code)
	}
	if code, _ := e.do(member, "PUT", path+"/policy", api.Policy{}); code != http.StatusForbidden {
		t.Fatalf("got %d", code)
	}
}

// File contents can be anything, so they stay out of the audit log.
func TestAuditHoldsTheHashNotTheContent(t *testing.T) {
	e := setup(t)
	id, _ := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	putPolicy(t, e, admin, path, api.Policy{Files: []api.FilePutPayload{{Path: "/etc/hauswart.d/a", Content: "topsecret"}}})
	_, data := e.do(admin, "GET", "/api/audit", nil)
	if strings.Contains(string(data), "topsecret") {
		t.Fatalf("got %s", data)
	}
}

// What is signed and on its way will arrive, whatever else was decided since.
func TestRevertBehindASignedTaskGetsItsOwnTask(t *testing.T) {
	e := setup(t)
	id, agent := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	original := api.Policy{RequiredPackages: []string{"vim"}}
	report(t, e, agent, api.Report{Protected: true, Policy: &api.PolicyStatus{Hash: original.Hash()}})

	putPolicy(t, e, admin, path, api.Policy{RequiredPackages: []string{"nano"}})
	queue := queueOf(t, e, admin)
	if len(queue) != 1 {
		t.Fatalf("got %+v", queue)
	}
	if code, data := e.do(admin, "POST", "/api/tasks/"+queue[0].ID+"/signature", sign.Signed{Envelope: []byte("x")}); code >= 300 {
		t.Fatalf("%d %s", code, data)
	}
	putPolicy(t, e, admin, path, api.Policy{RequiredPackages: []string{"less"}})
	putPolicy(t, e, admin, path, original)
	queue = queueOf(t, e, admin)
	if len(queue) != 1 || !strings.Contains(string(queue[0].Payload), "vim") {
		t.Fatalf("the signed task would undo the revert: %+v", queue)
	}

	// Going back to what is on its way needs no second signature.
	putPolicy(t, e, admin, path, api.Policy{RequiredPackages: []string{"nano"}})
	if queue := queueOf(t, e, admin); len(queue) != 0 {
		t.Fatalf("got %+v", queue)
	}
}

func TestMergeThatGrowsTooLargeIsNamed(t *testing.T) {
	e := setup(t)
	id, _ := protectedDevice(t, e)
	admin := e.login("admin")
	first := newGroup(t, e, admin, id)
	code, data := e.do(admin, "POST", "/api/groups", map[string]string{"name": "more"})
	if code != http.StatusCreated {
		t.Fatalf("%d %s", code, data)
	}
	var out struct{ ID int64 }
	json.Unmarshal(data, &out)
	second := fmt.Sprintf("/api/groups/%d", out.ID)
	e.do(admin, "PUT", second+"/devices", map[string][]string{"devices": {id}})

	names := func(prefix string) []string {
		list := make([]string, 150)
		for i := range list {
			list[i] = fmt.Sprintf("%s%d", prefix, i)
		}
		return list
	}
	putPolicy(t, e, admin, first, api.Policy{RequiredPackages: names("a")})
	putPolicy(t, e, admin, second, api.Policy{RequiredPackages: names("b")})
	if queue := queueOf(t, e, admin); len(queue) != 0 {
		t.Fatalf("queued what cannot be signed: %d", len(queue))
	}
	if state := groupPolicy(t, e, admin, first).Devices[0]; state.State != policyConflict {
		t.Fatalf("got %+v", state)
	}
}

func TestRequestFromADevice(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	admin := e.login("admin")
	if code, data := e.do(agent, "POST", "/agent/requests", api.DeviceRequest{User: "nobody", UserRequest: api.UserRequest{Kind: "software", Detail: "vim"}}); code != http.StatusNotFound {
		t.Fatalf("%d %s", code, data)
	}
	// anna is a member, and this device is not hers yet.
	in := api.DeviceRequest{User: "anna", UserRequest: api.UserRequest{Kind: api.RequestScreen, Detail: "30", Reason: "homework"}}
	if code, data := e.do(agent, "POST", "/agent/requests", in); code != http.StatusForbidden {
		t.Fatalf("%d %s", code, data)
	}
	users, _ := e.store.ListUsers(context.Background())
	var anna int64
	for _, u := range users {
		if u.Username == "anna" {
			anna = u.ID
		}
	}
	if err := e.store.SetUserDevices(context.Background(), anna, []string{id}); err != nil {
		t.Fatal(err)
	}
	if code, data := e.do(agent, "POST", "/agent/requests", in); code != http.StatusCreated {
		t.Fatalf("%d %s", code, data)
	}
	_, data := e.do(admin, "GET", "/api/requests", nil)
	if !strings.Contains(string(data), `"kind":"screen"`) {
		t.Fatalf("got %s", data)
	}
	var requests []struct{ ID string }
	json.Unmarshal(data, &requests)
	if code, data := e.do(admin, "POST", "/api/requests/"+requests[0].ID+"/approve", nil); code != http.StatusNoContent {
		t.Fatalf("%d %s", code, data)
	}
	_, data = e.do(admin, "GET", "/api/tasks", nil)
	if !strings.Contains(string(data), api.TaskScreenExtend) {
		t.Fatalf("got %s", data)
	}
	// The device learns how the request stands, and the task says where it came from.
	code, data := e.do(agent, "GET", "/agent/requests", nil)
	var states []api.RequestState
	if code != http.StatusOK || json.Unmarshal(data, &states) != nil || len(states) != 1 ||
		states[0].State != api.RequestRunning || states[0].User != "anna" || strings.Contains(string(data), "homework") {
		t.Fatalf("%d %s", code, data)
	}
	code, data = e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	var task api.Task
	if code != http.StatusOK || json.Unmarshal(data, &task) != nil || task.Request != requests[0].ID {
		t.Fatalf("%d %s", code, data)
	}
	e.do(agent, "POST", "/agent/tasks/"+task.ID+"/result", api.TaskResult{OK: true})
	_, data = e.do(agent, "GET", "/agent/requests", nil)
	if !strings.Contains(string(data), `"state":"done"`) {
		t.Fatalf("got %s", data)
	}
	if code, _ := e.do(e.client(), "GET", "/agent/requests", nil); code != http.StatusUnauthorized {
		t.Fatalf("got %d", code)
	}

	for name, bad := range map[string]api.DeviceRequest{
		"too long a stay": {User: "anna", UserRequest: api.UserRequest{Kind: api.RequestScreen, Detail: "9999"}},
		"unknown kind":    {User: "anna", UserRequest: api.UserRequest{Kind: "shell", Detail: "x"}},
	} {
		if code, data := e.do(agent, "POST", "/agent/requests", bad); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, data)
		}
	}
	if code, _ := e.do(e.client(), "POST", "/agent/requests", in); code != http.StatusUnauthorized {
		t.Fatalf("got %d", code)
	}
}

func TestSharedLinuxAccountIsNotGuessed(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	ctx := context.Background()
	hash, _ := HashPassword(testPassword)
	if _, err := e.store.CreateUser(ctx, "approver", "anna", hash, "approver"); err != nil {
		t.Fatal(err)
	}
	in := api.DeviceRequest{User: "anna", UserRequest: api.UserRequest{Kind: "sudo", Detail: "30"}}
	// anna is a member without this device, so only the parent is left.
	if code, data := e.do(agent, "POST", "/agent/requests", in); code != http.StatusCreated {
		t.Fatalf("%d %s", code, data)
	}
	users, _ := e.store.ListUsers(ctx)
	for _, u := range users {
		if u.Username == "anna" {
			if err := e.store.SetUserDevices(ctx, u.ID, []string{id}); err != nil {
				t.Fatal(err)
			}
		}
	}
	code, data := e.do(agent, "POST", "/agent/requests", in)
	if code != http.StatusConflict || !strings.Contains(string(data), api.ErrSharedAccount) {
		t.Fatalf("%d %s", code, data)
	}
}

func TestEmptyingAPolicyWithNetworksEndsIt(t *testing.T) {
	e := setup(t)
	id, agent := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	policy := api.Policy{Wifi: []api.WifiRule{{SSID: "Büro", Password: "very secret pw", Security: "wpa3"}},
		Printers: []api.PrinterRule{{Name: "flur", URI: "ipp://localhost:18631/ipp/print", Default: true}}}
	putPolicy(t, e, admin, path, policy)
	report(t, e, agent, api.Report{Hostname: "laptop", Protected: true, Policy: &api.PolicyStatus{Hash: policy.Hash()}})
	putPolicy(t, e, admin, path, api.Policy{})
	if queue := queueOf(t, e, admin); len(queue) != 1 || queue[0].Type != api.TaskPolicyClear {
		t.Fatalf("got %+v", queue)
	}
}

// The device finished the policy, but has not reported since. Emptying the
// policy then must still end it on the device.
func TestEmptyingBeforeTheNextReportEndsThePolicy(t *testing.T) {
	e := setup(t)
	id, agent := protectedDevice(t, e)
	admin := e.login("admin")
	path := newGroup(t, e, admin, id)
	report(t, e, agent, api.Report{Hostname: "laptop", Protected: true})
	putPolicy(t, e, admin, path, api.Policy{RequiredPackages: []string{"vim"}})
	db, err := sql.Open("sqlite", e.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE tasks SET status = 'done' WHERE type = ?`, api.TaskPolicySet); err != nil {
		t.Fatal(err)
	}
	putPolicy(t, e, admin, path, api.Policy{})
	if queue := queueOf(t, e, admin); len(queue) != 1 || queue[0].Type != api.TaskPolicyClear {
		t.Fatalf("got %+v", queue)
	}
}
