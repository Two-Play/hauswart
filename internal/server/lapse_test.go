package server

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Two-Play/hauswart/internal/api"
	"github.com/Two-Play/hauswart/internal/store"
)

// Waiting tasks say when they lapse, and the janitor closes them then, with a
// line in the audit log.
func TestWaitingTasksLapse(t *testing.T) {
	e := setup(t)
	device, agent := e.enroll()
	e.addUser("mama", "mama", store.RoleApprover)
	e.reportPins(agent, 0)
	id := e.queue(device, api.TaskPowerReboot, map[string]any{"delay_minutes": 1, "expires_at": time.Now().Add(time.Hour)})

	_, data := e.do(e.login("mama"), "GET", "/api/approvals", nil)
	var waiting []struct {
		ID        string `json:"id"`
		CreatedAt int64  `json:"created_at"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &waiting); err != nil || len(waiting) != 1 || waiting[0].ID != id {
		t.Fatalf("%s", data)
	}
	if got := waiting[0].ExpiresAt - waiting[0].CreatedAt; got != int64((2 * time.Hour).Seconds()) {
		t.Fatalf("lapses after %ds", got)
	}

	e.server.lapseWaiting(context.Background(), time.Now().Add(3*time.Hour))
	if _, data := e.do(e.login("mama"), "GET", "/api/approvals", nil); string(data) != "[]\n" && string(data) != "[]" {
		t.Fatalf("still waiting: %s", data)
	}
	task, err := e.store.GetTask(context.Background(), id)
	if err != nil || task.Output != api.TaskLapsed {
		t.Fatalf("%+v, %v", task, err)
	}
	entries, err := e.store.ListAudit(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range entries {
		found = found || (a.Action == "task.lapsed" && a.Actor == "server")
	}
	if !found {
		t.Fatalf("no audit entry: %+v", entries)
	}
}
