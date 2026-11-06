package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

func devices(t *testing.T, e *env, c *http.Client) []store.Device {
	t.Helper()
	code, data := e.do(c, "GET", "/api/devices", nil)
	if code != http.StatusOK {
		t.Fatalf("devices: %d %s", code, data)
	}
	var out []store.Device
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestReportCarriesTheRealCertificateExpiry(t *testing.T) {
	e := setup(t)
	_, agent := e.enroll()
	claimed := time.Now().Add(100 * 365 * 24 * time.Hour)
	report := api.Report{Hostname: "laptop", Insight: api.Insight{CertExpires: &claimed}}
	if code, data := e.do(agent, "POST", "/agent/report", report); code != http.StatusNoContent {
		t.Fatalf("got %d %s", code, data)
	}
	got := devices(t, e, e.login("admin"))[0].Report.CertExpires
	if got == nil || got.After(time.Now().Add(3*365*24*time.Hour)) || got.Before(time.Now()) {
		t.Errorf("got %v", got)
	}
}

func TestWarningsAreForAdmins(t *testing.T) {
	e := setup(t)
	_, agent := e.enroll()
	report := api.Report{DiskTotal: 100, DiskUsed: 95, Insight: api.Insight{
		Accounts: []api.Account{{Name: "anna", UID: 1000, Sudo: []string{"(ALL) ALL"}}},
		Updates:  &api.UpdateStatus{Pending: 2},
	}}
	e.do(agent, "POST", "/agent/report", report)

	warnings := devices(t, e, e.login("admin"))[0].Warnings
	if len(warnings) != 1 || warnings[0] != (api.Warning{Code: api.WarnDiskFull, Value: 95}) {
		t.Errorf("got %v", warnings)
	}
	_, data := e.do(e.login("anna"), "GET", "/api/devices", nil)
	for _, secret := range []string{"anna", "pending", "warnings", "disk_full"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("member sees %s: %s", secret, data)
		}
	}
}

func TestRevokedDeviceRaisesNoWarnings(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.do(agent, "POST", "/agent/report", api.Report{DiskTotal: 100, DiskUsed: 95})
	admin := e.login("admin")
	e.do(admin, "POST", "/api/devices/"+id+"/revoke", nil)
	if warnings := devices(t, e, admin)[0].Warnings; len(warnings) != 0 {
		t.Errorf("got %v", warnings)
	}
}

func TestHistory(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	e.do(agent, "POST", "/agent/report", api.Report{MemUsed: 7, MemTotal: 10, DiskUsed: 1, DiskTotal: 2, Load1: 0.5})
	admin := e.login("admin")
	for _, query := range []string{"", "?hours=24", "?hours=168", "?hours=99999", "?hours=x"} {
		code, data := e.do(admin, "GET", "/api/devices/"+id+"/history"+query, nil)
		var samples []store.Sample
		if err := json.Unmarshal(data, &samples); err != nil {
			t.Fatal(err)
		}
		if code != http.StatusOK || len(samples) != 1 || samples[0].MemUsed != 7 {
			t.Errorf("%q: %d %s", query, code, data)
		}
	}
	if code, data := e.do(admin, "GET", "/api/devices/unknown/history", nil); code != http.StatusOK || strings.TrimSpace(string(data)) != "[]" {
		t.Errorf("got %d %s", code, data)
	}
	if code, _ := e.do(e.login("anna"), "GET", "/api/devices/"+id+"/history", nil); code != http.StatusForbidden {
		t.Errorf("member got %d", code)
	}
}

func fetchLogs(t *testing.T, e *env, admin, agent *http.Client, id string) string {
	t.Helper()
	code, data := e.do(admin, "POST", "/api/devices/"+id+"/tasks", map[string]any{"type": api.TaskLogsFetch, "payload": map[string]int{"lines": 10}})
	if code != http.StatusCreated {
		t.Fatalf("got %d %s", code, data)
	}
	var created struct{ ID string }
	if err := json.Unmarshal(data, &created); err != nil {
		t.Fatal(err)
	}
	if code, data := e.do(agent, "GET", "/agent/tasks?wait=0", nil); code != http.StatusOK {
		t.Fatalf("poll: %d %s", code, data)
	}
	result := api.TaskResult{OK: true, Output: "1 entry", Data: json.RawMessage(`{"available":true,"system":[{"message":"disk error"}]}`)}
	if code, data := e.do(agent, "POST", "/agent/tasks/"+created.ID+"/result", result); code != http.StatusNoContent {
		t.Fatalf("result: %d %s", code, data)
	}
	return created.ID
}

func TestLogsComeOneAtATime(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	admin := e.login("admin")
	task := fetchLogs(t, e, admin, agent, id)

	if _, data := e.do(admin, "GET", "/api/tasks", nil); strings.Contains(string(data), "disk error") {
		t.Errorf("logs in the task list: %s", data)
	}
	code, data := e.do(admin, "GET", "/api/tasks/"+task+"/data", nil)
	if code != http.StatusOK || !strings.Contains(string(data), "disk error") {
		t.Errorf("got %d %s", code, data)
	}
	if code, _ := e.do(e.login("anna"), "GET", "/api/tasks/"+task+"/data", nil); code != http.StatusForbidden {
		t.Errorf("member got %d", code)
	}
	if code, _ := e.do(admin, "GET", "/api/tasks/nope/data", nil); code != http.StatusNotFound {
		t.Errorf("unknown task got %d", code)
	}
	if _, audit := e.do(admin, "GET", "/api/audit", nil); strings.Contains(string(audit), "disk error") {
		t.Errorf("logs in the audit log: %s", audit)
	}
}

func TestLogsNeedNoSignatureOnAProtectedDevice(t *testing.T) {
	e := setup(t)
	id, agent := e.enroll()
	protect(t, e, agent)
	fetchLogs(t, e, e.login("admin"), agent, id)
}

func TestLogsCannotGoToAGroup(t *testing.T) {
	e := setup(t)
	admin := e.login("admin")
	_, data := e.do(admin, "POST", "/api/groups", map[string]string{"name": "all"})
	var group struct{ ID int64 }
	if err := json.Unmarshal(data, &group); err != nil {
		t.Fatal(err)
	}
	code, _ := e.do(admin, "POST", fmt.Sprintf("/api/groups/%d/tasks", group.ID), map[string]any{"type": api.TaskLogsFetch})
	if code != http.StatusBadRequest {
		t.Errorf("got %d", code)
	}
}
