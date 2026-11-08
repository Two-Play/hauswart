package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/notify"
)

// heard keeps what the server would send to admins.
type heard struct {
	mu   sync.Mutex
	sent []string
}

func (h *heard) Send(message string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sent = append(h.sent, message)
}

func (h *heard) SendAs(_ notify.Subject, message string) { h.Send(message) }

func (h *heard) take() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	sent := h.sent
	h.sent = nil
	return sent
}

func TestFailedTasksAreTold(t *testing.T) {
	e := setup(t)
	h := &heard{}
	e.server.notifier = h
	id, agent := e.enroll()
	e.assign("anna", id)
	admin, anna := e.login("admin"), e.login("anna")
	e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop\nCall 0800"})

	_, filed := file(t, e, anna, id, "flatpak", "org.mozilla.firefox")
	e.do(admin, "POST", "/api/requests/"+filed["id"]+"/approve", nil)
	h.take() // the notice of the new request
	_, data := e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	var task api.Task
	json.Unmarshal(data, &task)
	e.do(agent, "POST", "/agent/tasks/"+task.ID+"/result", api.TaskResult{OK: false, Output: "flatpak is not installed, secret detail"})
	sent := h.take()
	if len(sent) != 1 || !strings.Contains(sent[0], "flatpak.install failed on laptop_Call_0800, asked for by anna") ||
		strings.Contains(sent[0], "secret") {
		t.Fatalf("got %q", sent)
	}

	e.do(admin, "POST", "/api/devices/"+id+"/tasks", map[string]any{"type": api.TaskPkgUpgrade, "payload": map[string]any{}})
	_, data = e.do(agent, "GET", "/agent/tasks?wait=0", nil)
	json.Unmarshal(data, &task)
	e.do(agent, "POST", "/agent/tasks/"+task.ID+"/result", api.TaskResult{OK: true})
	if sent := h.take(); len(sent) != 0 {
		t.Fatalf("a success was told: %q", sent)
	}

	_, data = e.do(admin, "GET", "/api/attention", nil)
	if !strings.Contains(string(data), `"failed_tasks":1`) {
		t.Fatalf("got %s", data)
	}
	if code, _ := e.do(anna, "GET", "/api/attention", nil); code != http.StatusForbidden {
		t.Fatalf("a member sees the counts: %d", code)
	}
}

func TestNewDeviationsAreToldOnce(t *testing.T) {
	e := setup(t)
	h := &heard{}
	e.server.notifier = h
	_, agent := e.enroll()
	report := func(deviations ...api.PolicyDeviation) {
		e.do(agent, "POST", "/agent/report", api.Report{Hostname: "laptop", Policy: &api.PolicyStatus{Deviations: deviations}})
	}
	firefox := api.PolicyDeviation{Kind: "flatpak", Item: "org.mozilla.firefox", Detail: "flatpak is not installed"}
	report(firefox)
	if sent := h.take(); len(sent) != 1 || !strings.Contains(sent[0], "laptop differs from its policy: flatpak org.mozilla.firefox") {
		t.Fatalf("got %q", sent)
	}
	report(firefox)
	if sent := h.take(); len(sent) != 0 {
		t.Fatalf("told again: %q", sent)
	}
	report(firefox, api.PolicyDeviation{Kind: "package", Item: "vim"})
	if sent := h.take(); len(sent) != 1 || !strings.Contains(sent[0], "package vim") || strings.Contains(sent[0], "firefox") {
		t.Fatalf("got %q", sent)
	}
	_, data := e.do(e.login("admin"), "GET", "/api/attention", nil)
	if !strings.Contains(string(data), `"deviating_devices":1`) {
		t.Fatalf("got %s", data)
	}
}
