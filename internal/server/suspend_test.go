package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
)

func TestSuspendedDeviceWaits(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.assign("anna", id)
	admin, anna := e.login("admin"), e.login("anna")
	code, open := file(t, e, anna, id, "software", "vim")
	if code != http.StatusCreated {
		t.Fatalf("%d %v", code, open)
	}
	if code, _ := e.do(anna, "POST", "/api/devices/"+id+"/suspend", nil); code != http.StatusForbidden {
		t.Fatalf("a member suspended a device: %d", code)
	}
	if code, data := e.do(admin, "POST", "/api/devices/"+id+"/suspend", nil); code != http.StatusNoContent {
		t.Fatalf("%d %s", code, data)
	}
	e.do(admin, "POST", "/api/devices/"+id+"/tasks", map[string]any{"type": api.TaskPkgUpgrade, "payload": map[string]any{}})

	code, data := e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusLocked || !strings.Contains(string(data), api.ErrDeviceSuspended) {
		t.Fatalf("%d %s", code, data)
	}
	if code, data := e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop"}); code != http.StatusNoContent {
		t.Fatalf("a suspended device cannot report: %d %s", code, data)
	}
	in := api.DeviceRequest{User: "anna", UserRequest: api.UserRequest{Kind: "software", Detail: "git"}}
	if code, data := e.do(agent, "POST", "/agent/requests", in); code != http.StatusLocked || !strings.Contains(string(data), api.ErrDeviceSuspended) {
		t.Fatalf("%d %s", code, data)
	}
	if code, out := file(t, e, anna, id, "software", "git"); code != http.StatusConflict {
		t.Fatalf("%d %v", code, out)
	}
	if code, data := e.do(admin, "POST", "/api/requests/"+open["id"]+"/approve", nil); code != http.StatusConflict {
		t.Fatalf("%d %s", code, data)
	}
	_, data = e.do(admin, "GET", "/api/devices", nil)
	var devices []struct{ Suspended bool }
	if json.Unmarshal(data, &devices); len(devices) != 1 || !devices[0].Suspended {
		t.Fatalf("got %s", data)
	}

	// Back again, the task that waited comes first.
	if code, _ := e.do(admin, "POST", "/api/devices/"+id+"/resume", nil); code != http.StatusNoContent {
		t.Fatalf("got %d", code)
	}
	code, data = e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	if code != http.StatusOK || !strings.Contains(string(data), api.TaskPkgUpgrade) {
		t.Fatalf("%d %s", code, data)
	}

	// Removing stays final.
	e.do(admin, "POST", "/api/devices/"+id+"/revoke", nil)
	if code, _ := e.do(admin, "POST", "/api/devices/"+id+"/resume", nil); code != http.StatusNotFound {
		t.Fatalf("a removed device came back: %d", code)
	}
	if code, _ := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusForbidden {
		t.Fatalf("got %d", code)
	}
}
