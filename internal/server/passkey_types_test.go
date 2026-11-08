package server

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func (e *env) signingTasks(taskType string) []api.Task {
	e.t.Helper()
	_, data := e.do(e.login("admin"), "GET", "/api/signing", nil)
	var queue []api.Task
	json.Unmarshal(data, &queue)
	return slices.DeleteFunc(queue, func(t api.Task) bool { return t.Type != taskType })
}

func TestPasskeyTypesWaitForASignature(t *testing.T) {
	e := setup(t)
	protected, agent := e.enroll()
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop", Protected: true, PasskeyTypes: api.DefaultPasskeyTypes})
	_, open := e.enroll()
	e.do(open, "POST", "/agent/report", api.Report{Hostname: "kitchen"})
	admin := e.login("admin")

	// Before an admin chooses, devices keep what they have.
	if got := e.signingTasks(api.TaskPasskeyTypes); len(got) != 0 {
		t.Fatalf("queued without a choice: %+v", got)
	}
	_, data := e.do(admin, "GET", "/api/passkey-types", nil)
	if !strings.Contains(string(data), `"chosen":false`) || !strings.Contains(string(data), api.TaskTerminalOpen) {
		t.Fatalf("view: %s", data)
	}

	if code, data := e.do(admin, "PUT", "/api/passkey-types", api.PasskeyTypesPayload{Types: []string{"sudo.grant"}}); code != http.StatusBadRequest {
		t.Fatalf("sudo for a passkey: %d %s", code, data)
	}
	choice := api.PasskeyTypesPayload{Types: []string{api.TaskPkgInstall, "power.reboot"}}
	if code, data := e.do(admin, "PUT", "/api/passkey-types", choice); code != http.StatusNoContent {
		t.Fatalf("set: %d %s", code, data)
	}
	queued := e.signingTasks(api.TaskPasskeyTypes)
	if len(queued) != 1 || queued[0].ID == "" {
		t.Fatalf("queued: %+v", queued)
	}
	var payload api.PasskeyTypesPayload
	json.Unmarshal(queued[0].Payload, &payload)
	if !slices.Equal(payload.Types, []string{api.TaskPkgInstall, "power.reboot"}) {
		t.Fatalf("payload %s", queued[0].Payload)
	}
	tasks, _ := e.store.ListTasks(context.Background(), 50)
	for _, task := range tasks {
		if task.Type == api.TaskPasskeyTypes && task.DeviceID != protected {
			t.Fatal("an unprotected device got the list")
		}
	}

	// A second report or the same choice again does not queue it twice.
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop", Protected: true, PasskeyTypes: api.DefaultPasskeyTypes})
	e.do(admin, "PUT", "/api/passkey-types", choice)
	if got := e.signingTasks(api.TaskPasskeyTypes); len(got) != 1 {
		t.Fatalf("queued twice: %d", len(got))
	}

	// Once the device has the list, nothing waits any more.
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop", Protected: true, PasskeyTypes: choice.Types})
	if got := e.signingTasks(api.TaskPasskeyTypes); len(got) != 0 {
		t.Fatalf("still waiting: %+v", got)
	}
	_, data = e.do(admin, "GET", "/api/passkey-types", nil)
	if !strings.Contains(string(data), `"applied":1`) || !strings.Contains(string(data), `"total":1`) {
		t.Fatalf("view: %s", data)
	}
}

func TestPasskeyRefusedForTypesTheAdminsTookAway(t *testing.T) {
	p := setupPasskey(t)
	task := p.queue(p.device, api.TaskPkgInstall, vim)
	admin := p.login("admin")
	if code, _ := p.do(admin, "PUT", "/api/passkey-types", api.PasskeyTypesPayload{Types: []string{"power.reboot"}}); code != http.StatusNoContent {
		t.Fatal("set")
	}
	_, data := p.do(p.parent, "GET", "/api/approvals", nil)
	if strings.Contains(string(data), task) {
		t.Fatalf("still offered to approvers: %s", data)
	}
	if code, _ := p.do(p.parent, "POST", "/api/tasks/"+task+"/passkey-challenge", nil); code != http.StatusConflict {
		t.Fatalf("challenge: %d", code)
	}
}

func TestPasskeyTypesAreNeverApprovedByPasskey(t *testing.T) {
	if api.PasskeyEligible(api.TaskPasskeyTypes) {
		t.Fatal("a passkey could widen its own reach")
	}
}
